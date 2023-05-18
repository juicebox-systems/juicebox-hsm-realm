use async_trait::async_trait;
use clap::Parser;
use std::cmp::min;
use std::ffi::CString;
use std::fmt::Display;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::time::Instant;
use tracing::{debug, info, instrument, warn};

use agent_core::Agent;
use entrust_api::{NvRamState, StartRequest, StartResponse, Ticket};
use entrust_nfast::{
    find_key, Cmd_ClearUnitEx, Cmd_CreateBuffer, Cmd_CreateSEEWorld,
    Cmd_CreateSEEWorld_Args_flags_EnableDebug, Cmd_Destroy, Cmd_GetTicket, Cmd_LoadBuffer,
    Cmd_LoadBuffer_Args_flags_Final, Cmd_NoOp, Cmd_SEEJob, Cmd_SetSEEMachine, Cmd_TraceSEEWorld,
    M_ByteBlock, M_Cmd_ClearUnitEx_Args, M_Cmd_CreateBuffer_Args, M_Cmd_CreateSEEWorld_Args,
    M_Cmd_LoadBuffer_Args, M_Cmd_NoOp_Args, M_Cmd_SEEJob_Args, M_Cmd_SetSEEMachine_Args,
    M_Cmd_TraceSEEWorld_Args, M_Command, M_KeyID, M_Status, M_Word, ModuleMode_Default,
    NFKM_cmd_loadblob, NFastApp_Connect, NFastApp_Connection, NFastApp_ConnectionFlags_Privileged,
    NFastApp_Disconnect, NFastConn, NFastError, Reply, SEEInitStatus_OK, Status_OK,
    Status_ObjectInUse, Status_SEEWorldFailed, TicketDestination_AnySEEWorld,
};
use loam_mvp::clap_parsers::parse_duration;
use loam_mvp::future_task::FutureTasks;
use loam_mvp::google_auth;
use loam_mvp::logging;
use loam_mvp::realm::hsm::client::{HsmClient, HsmRpcError, Transport};
use loam_mvp::realm::store::bigtable::BigTableArgs;
use loam_sdk_core::marshalling::{self, DeserializationError, SerializationError};

#[derive(Parser)]
#[command(about = "A host agent for use with an Entrust nCipherXC HSM")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8082)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the agent in logging [default: agent{listen}].
    #[arg(short, long)]
    name: Option<String>,

    /// The HSM module to work with. (The default of 1 is fine unless there are
    /// multiple HSMs in a host).
    #[arg(short, long, default_value_t = 1)]
    module: u8,

    /// Enable collection of the debugging output from the HSM trace buffer.
    /// This requires the Security World to have been created with the `dseeall`
    /// feature enabled.
    #[arg(short, long, default_value_t = false)]
    trace: bool,

    /// The name of the file containing the signed SEEMachine image (in SAR
    /// format). Is used to set the SEEMachine image in order to start or
    /// restart the SEE World.
    #[arg(short, long)]
    image: PathBuf,

    /// The name of the file containing the signed userdata file. Should be
    /// signed with the same 'seeinteg' key that the see machine image was
    /// signed with. The data in this file isn't used, but the signed file is
    /// needed for the ACLs that restrict access to a SEEMachine to work.
    #[arg(short, long)]
    userdata: PathBuf,

    /// HSM Metrics reporting interval in milliseconds [default: no reporting]
    #[arg(long, value_parser=parse_duration)]
    metrics: Option<Duration>,

    /// Reinitialize the NVRAM state back to blank, effectively making a new HSM.
    #[arg(long, default_value_t = false)]
    reinitialize: bool,
}

#[tokio::main]
async fn main() {
    logging::configure("entrust-agent");

    let mut shutdown_tasks = FutureTasks::new();
    let mut shutdown_tasks_clone = shutdown_tasks.clone();
    let rt = Handle::try_current().unwrap();

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        rt.block_on(async { shutdown_tasks_clone.join_all().await });
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("agent{}", args.listen));

    let auth_manager = if args.bigtable.needs_auth() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };
    let store = args
        .bigtable
        .connect_data(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable");

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager)
        .await
        .expect("Unable to connect to Bigtable admin");

    let hsm_t = EntrustSeeTransport::new(
        args.module,
        args.trace,
        args.image,
        args.userdata,
        args.reinitialize,
    );
    let hsm = HsmClient::new(hsm_t, name.clone(), args.metrics);

    let agent = Agent::new(name, hsm, store, store_admin);
    let agent_clone = agent.clone();
    shutdown_tasks.add(Box::pin(async move {
        agent_clone.shutdown(Duration::from_secs(10)).await;
    }));

    let (url, join_handle) = agent
        .listen(args.listen)
        .await
        .expect("failed to listen for connections");
    info!(url = %url, "Agent started");
    join_handle.await.unwrap();
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}

#[derive(Debug)]
pub enum SeeError {
    // These are agent side marshalling errors.
    Serialization(SerializationError),
    Deserialization(DeserializationError),
    // An NFast API or CMD transact failed.
    NFast(NFastError),
    // The HSM process crashed or was otherwise terminated.
    SeeWorldFailed,
    // HSM Side marshalling errors
    HsmMarshallingError,
}

impl Display for SeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeeError::Serialization(err) => write!(f, "Serialization error: {:?}", err),
            SeeError::Deserialization(err) => write!(f, "Deserialization error: {:?}", err),
            SeeError::NFast(err) => write!(f, "NFastError: {}", err),
            SeeError::SeeWorldFailed => write!(f, "SEEWorld failed"),
            SeeError::HsmMarshallingError => {
                write!(f, "HSM Failed to marshal a request or response")
            }
        }
    }
}

impl From<DeserializationError> for SeeError {
    fn from(v: DeserializationError) -> Self {
        Self::Deserialization(v)
    }
}

impl From<SerializationError> for SeeError {
    fn from(v: SerializationError) -> Self {
        Self::Serialization(v)
    }
}

impl From<HsmRpcError> for SeeError {
    fn from(_v: HsmRpcError) -> Self {
        Self::HsmMarshallingError
    }
}

impl From<NFastError> for SeeError {
    fn from(v: NFastError) -> Self {
        Self::NFast(v)
    }
}

#[derive(Debug)]
struct EntrustSeeTransport(Arc<Mutex<TransportInner>>);
impl EntrustSeeTransport {
    fn new(
        module: u8,
        tracing: bool,
        see_machine: PathBuf,
        userdata: PathBuf,
        reinit_nvram: bool,
    ) -> Self {
        Self(Arc::new(Mutex::new(TransportInner {
            tracing,
            module,
            see_machine,
            userdata,
            conn: NFastConn::new(),
            world_id: None,
            nvram: if reinit_nvram {
                NvRamState::Reinitialize
            } else {
                NvRamState::LastWritten
            },
        })))
    }
}

#[derive(Debug)]
struct TransportInner {
    tracing: bool,
    module: u8,
    see_machine: PathBuf,
    userdata: PathBuf,
    conn: NFastConn,
    world_id: Option<M_KeyID>,
    nvram: NvRamState,
}

unsafe impl Send for TransportInner {}

#[async_trait]
impl Transport for EntrustSeeTransport {
    type Error = SeeError;

    async fn send_rpc_msg(&self, msg_name: &str, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        self.0.lock().unwrap().send_rpc_msg(msg_name, msg)
    }
}

impl TransportInner {
    #[instrument(level = "trace", skip(self, msg))]
    fn send_rpc_msg(&mut self, msg_name: &str, msg: Vec<u8>) -> Result<Vec<u8>, SeeError> {
        unsafe {
            self.connect()?;
        }
        let start = Instant::now();
        let resp_vec = self.transact_seejob(msg)?;
        debug!(dur=?start.elapsed(), req=msg_name, "Entrust HSM request transacted");
        Ok(resp_vec)
    }

    unsafe fn connect(&mut self) -> Result<(), SeeError> {
        self.conn.connect()?;
        if self.world_id.is_none() {
            self.world_id = Some(self.start_seeworld()?);

            self.start_hsmcore();
        }
        Ok(())
    }

    fn start_hsmcore(&mut self) {
        // Collect up all the key tickets we need.
        let comm_private_key = self.ticket_for_key("simple", "jbox-noise", KeyHalf::Private);
        let comm_public_key = self.ticket_for_key("simple", "jbox-noise", KeyHalf::Public);
        let mac_key = self.ticket_for_key("simple", "jbox-mac", KeyHalf::Private);
        let record_key = self.ticket_for_key("simple", "jbox-record", KeyHalf::Private);

        // send a StartRequest Job to get HSMCore running.
        let start = StartRequest {
            tree_overlay_size: 511,
            max_sessions: 511,
            comm_private_key,
            comm_public_key,
            mac_key,
            record_key,
            nvram: self.nvram,
        };
        let start_msg = marshalling::to_vec(&start).expect("Failed to serialize StartRequest");
        let resp_bytes = self
            .transact_seejob(start_msg)
            .expect("StartRequest to HSM failed");

        // Check the response.
        let start_rep: StartResponse = marshalling::from_slice(&resp_bytes)
            .expect("Failed to deserialize response from StartRequest job");
        match start_rep {
            StartResponse::Ok => {
                info!("HSMCore started and ready for work")
            }
            StartResponse::PersistenceError(msg) => {
                panic!("HSMCore failed to start due to persistence error: {msg}")
            }
            StartResponse::WorldSigner(err) => {
                panic!("HSMCore failed to start due to code signing related issue: {err:?}")
            }
            StartResponse::InvalidTicket(k, status) => {
                panic!(
                    "HSMCore failed to start due to invalid ticket for key {k:?} with error {}",
                    NFastError::Api(status)
                )
            }
            StartResponse::InvalidKeyLength {
                role,
                expecting,
                actual,
            } => {
                panic!("HSMCore failed to start due to key {role:?} having unexpected length of {actual} when it should be {expecting}")
            }
        }
    }

    fn transact_seejob(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>, SeeError> {
        let mut cmd = M_Command::new(Cmd_SEEJob);
        cmd.args.seejob = M_Cmd_SEEJob_Args {
            worldid: self
                .world_id
                .expect("SEEWorld should have already been started"),
            seeargs: M_ByteBlock {
                len: data.len() as M_Word,
                ptr: data.as_mut_ptr(),
            },
        };
        let rep = self.transact(&mut cmd)?;
        let resp = unsafe { rep.reply.seejob.seereply.as_slice().to_vec() };
        self.collect_trace_buffer();
        Ok(resp)
    }

    // If there's a problem generating a ticket for a key, then we can't start
    // the hsmcore, and retrying is highly unlikely to work. So this panics on
    // all the error conditions.
    fn ticket_for_key(&mut self, app: &str, ident: &str, half: KeyHalf) -> Ticket {
        debug!(?app, ?ident, "Trying to find key in security world");

        let key = match find_key(&self.conn, app, ident) {
            Err(err) => panic!("Error looking for key {app},{ident} in the security world {err}"),
            Ok(None) => panic!("Unable to find key {app},{ident} in the security world"),
            Ok(Some(key)) => key,
        };
        let mut key_id: M_KeyID = 0;
        let for_str = CString::new("ticket for key for use by hsmcore").unwrap();
        let rc = unsafe {
            NFKM_cmd_loadblob(
                self.conn.app,
                self.conn.conn,
                self.module.into(),
                match half {
                    KeyHalf::Public => &key.pubblob,
                    KeyHalf::Private => &key.privblob,
                },
                0,
                &mut key_id,
                for_str.as_ptr(),
                null_mut(),
            )
        };
        if rc != 0 {
            panic!(
                "failed to NFKM_cmd_loadblob for {app},{ident}, error: {}",
                NFastError::Api(rc)
            )
        }
        /* Get key ticket */
        let mut cmd = M_Command::new(Cmd_GetTicket);
        cmd.args.getticket.obj = key_id;
        cmd.args.getticket.dest = TicketDestination_AnySEEWorld;
        let reply = self.transact(&mut cmd).unwrap_or_else(|err| {
            panic!("Cmd_GetTicket failed for key {app},{ident}, error: {err}")
        });

        let ticket = unsafe { reply.reply.getticket.ticket.as_slice().to_vec() };
        debug!(?app, ?ident, "Generated key ticket");
        Ticket(ticket)
    }

    unsafe fn start_seeworld(&mut self) -> Result<M_KeyID, SeeError> {
        // Load the SEEMachine image
        let data = fs::read(&self.see_machine).unwrap_or_else(|err| {
            panic!(
                "Failed to load see machine image file {}: {err}",
                self.see_machine.display()
            )
        });
        let image_buffer = self.load_buffer(data)?;
        let mut cmd = M_Command::new(Cmd_SetSEEMachine);
        cmd.args.setseemachine = M_Cmd_SetSEEMachine_Args {
            flags: 0,
            buffer: image_buffer,
        };
        self.transact(&mut cmd)?;

        let user_data = fs::read(&self.userdata).unwrap_or_else(|err| {
            panic!(
                "Failed to load userdata file {}: {err}",
                self.userdata.display()
            )
        });
        let user_data_buffer = self.load_buffer(user_data)?;

        let mut cmd = M_Command::new(Cmd_CreateSEEWorld);
        cmd.args.createseeworld = M_Cmd_CreateSEEWorld_Args {
            flags: if self.tracing {
                Cmd_CreateSEEWorld_Args_flags_EnableDebug
            } else {
                0
            },
            buffer: user_data_buffer,
        };
        match self.transact(&mut cmd) {
            Err(e) => Err(e),
            Ok(reply) => {
                // for CreateSEEWorld we also need to check the initStatus.
                let init = reply.reply.createseeworld.initstatus;
                if init != SEEInitStatus_OK {
                    warn!(
                        initstatus = init,
                        "SEE Machine failed to initialize during CreateSEEWorld"
                    );
                    Err(SeeError::SeeWorldFailed)
                } else {
                    info!("Successfully started SEEWorld");
                    Ok(reply.reply.createseeworld.worldid)
                }
            }
        }
    }

    /// Create's a HSM buffer and loads the supplied userdata into it. Returns the buffer id.
    fn load_buffer(&mut self, mut userdata: Vec<u8>) -> Result<M_KeyID, SeeError> {
        // This function takes a Vec<u8> for userdata to ensure its on the heap, as required
        // by the transact calls for Cmd_LoadBuffer.
        let buffer_id = {
            let mut cmd = M_Command::new(Cmd_CreateBuffer);
            cmd.args.createbuffer = M_Cmd_CreateBuffer_Args {
                module: self.module as M_Word,
                flags: 0,
                size: userdata.len() as M_Word,
                params: null_mut(),
            };
            let rep = self.transact(&mut cmd)?;
            unsafe { rep.reply.createbuffer.id }
        };

        const WRITE_BLOCK_SIZE: usize = 4096;
        // togo is a &mut because we need to use as_mut_ptr() in the M_ByteBlock
        let mut togo: &mut [u8] = &mut userdata;
        while !togo.is_empty() {
            let n = min(togo.len(), WRITE_BLOCK_SIZE);
            let mut cmd = M_Command::new(Cmd_LoadBuffer);
            cmd.args.loadbuffer = M_Cmd_LoadBuffer_Args {
                id: buffer_id,
                flags: if n == togo.len() {
                    Cmd_LoadBuffer_Args_flags_Final
                } else {
                    0
                },
                chunk: M_ByteBlock {
                    len: n as M_Word,
                    ptr: togo.as_mut_ptr(),
                },
                flashsegment: null_mut(),
            };
            self.transact(&mut cmd)?;
            togo = &mut togo[n..];
        }
        Ok(buffer_id)
    }

    /// If tracing is enabled, will collect any data from the HSM trace buffer and log it.
    fn collect_trace_buffer(&mut self) {
        if !self.tracing || self.world_id.is_none() {
            return;
        }
        let mut cmd = M_Command::new(Cmd_TraceSEEWorld);
        cmd.args.traceseeworld = M_Cmd_TraceSEEWorld_Args {
            worldid: self.world_id.unwrap(),
        };
        match self.transact(&mut cmd) {
            Err(e) => {
                warn!(err=?e, "error trying to collect trace data");
            }
            Ok(reply) => unsafe {
                let tr = &reply.reply.traceseeworld;
                let str = String::from_utf8_lossy(tr.data.as_slice());
                let trimmed = str.trim_end_matches(&[' ', '\r', '\n', '\0']);
                if !trimmed.is_empty() {
                    info!(flags=?tr.flags, len=?tr.data.len, "HSM: {trimmed}");
                }
            },
        }
    }

    fn transact(&mut self, cmd: &mut M_Command) -> Result<Reply, SeeError> {
        self.transact_on_conn(self.conn.conn, cmd)
    }

    fn transact_on_conn(
        &mut self,
        conn: NFastApp_Connection,
        cmd: &mut M_Command,
    ) -> Result<Reply, SeeError> {
        let res = unsafe { self.conn.transact_on_conn(conn, cmd) };
        if let Err(NFastError::Transact(status)) = res {
            if cmd.cmd != Cmd_TraceSEEWorld {
                self.collect_trace_buffer();
            }
            if status == Status_SEEWorldFailed || status == Status_ObjectInUse {
                // try restarting the SEE world
                self.restart_world();
                return Err(SeeError::SeeWorldFailed);
            }
        }
        Ok(res?)
    }

    /// Restarts the SEEWorld after its failed. We first attempt a restart by destroying the current one
    /// and then starting it again. If that fails, we do a more extensive reset using a clear command
    /// which should work but takes a lot of time.
    fn restart_world(&mut self) {
        if self.world_id.is_some() {
            warn!("SEEWorld failed, attempting restart");
            let mut cmd = M_Command::new(Cmd_Destroy);
            cmd.args.destroy.key = self.world_id.unwrap();
            if self.transact(&mut cmd).is_ok() {
                self.world_id = None;
                if unsafe { self.connect() }.is_ok() {
                    return;
                }
            }
            warn!("Failed to restart SEEWorld, trying harder");
        }
        self.try_clear();
    }

    /// If the SEEWorld crashes or is terminated by the HSM, transact will return Status_SEEWorldFailed.
    /// If a graceful recovery doesn't work, then this more aggressive one should do it.
    /// Recovering from this involves
    ///     * Getting a privileged connection.
    ///     * Issuing a clear command (equiv to noopclearfail -c)
    ///     * Loading the HSM image. (or having the hardserver configured to auto load the image)
    ///     * Finally creating a new SEEWorld.
    fn try_clear(&mut self) {
        self.world_id = None;
        warn!("Attempting to clear & restart SEEWorld");
        let mut priv_conn: NFastApp_Connection = null_mut();
        unsafe {
            let rc = NFastApp_Connect(
                self.conn.app,
                &mut priv_conn,
                NFastApp_ConnectionFlags_Privileged,
                null_mut(),
            ) as M_Status;
            if rc != Status_OK {
                panic!("Connect for privileged connection failed with code {rc}. Unable to recover crashed SEEWorld.");
            }
        }
        // issue the clear command
        let mut cmd = M_Command::new(Cmd_ClearUnitEx);
        cmd.args.clearunitex = M_Cmd_ClearUnitEx_Args {
            flags: 0,
            module: self.module as M_Word,
            mode: ModuleMode_Default,
        };
        let reply = self.transact_on_conn(priv_conn, &mut cmd);
        match reply {
            Err(e) => {
                panic!("The SEEWorld crashed, and the attempt the clear the HSM so it can be restarted failed with error {e:?}");
            }
            Ok(_r) => {
                info!("Clear successfully issued, waiting on it to finish.");
                // Clear takes a while we'll wait on a no-op for it to finish.
                let mut cmd = M_Command::new(Cmd_NoOp);
                cmd.args.noop = M_Cmd_NoOp_Args {
                    module: self.module as M_Word,
                };
                match self.transact_on_conn(priv_conn, &mut cmd) {
                    Err(e) => {
                        panic!(
                                "The SEEWorld crashed, and a No-op after performing a clear failed with error {e:?}"
                            );
                    }
                    Ok(_reply) => {
                        info!("Clear successfully completed. Attempting to restart SEEWorld");
                        if let Err(e) = unsafe { self.connect() } {
                            panic!("Restarting SEEWorld after previous crash has failed: {e:?}");
                        }
                    }
                }
            }
        }
        unsafe {
            NFastApp_Disconnect(priv_conn, null_mut());
        }
    }
}

enum KeyHalf {
    Public,
    Private,
}
