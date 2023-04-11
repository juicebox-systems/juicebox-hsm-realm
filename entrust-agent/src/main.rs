use async_trait::async_trait;
use clap::Parser;
use core::slice;
use loam_sdk_core::marshalling::{DeserializationError, SerializationError};
use nfastapp::{
    Cmd_ClearUnitEx, Cmd_CreateBuffer, Cmd_CreateSEEWorld,
    Cmd_CreateSEEWorld_Args_flags_EnableDebug, Cmd_Destroy, Cmd_ErrorReturn, Cmd_LoadBuffer,
    Cmd_LoadBuffer_Args_flags_Final, Cmd_NoOp, Cmd_SEEJob, Cmd_SetSEEMachine, Cmd_TraceSEEWorld,
    M_ByteBlock, M_Cmd, M_Cmd_ClearUnitEx_Args, M_Cmd_CreateBuffer_Args, M_Cmd_CreateSEEWorld_Args,
    M_Cmd_LoadBuffer_Args, M_Cmd_NoOp_Args, M_Cmd_SEEJob_Args, M_Cmd_SetSEEMachine_Args,
    M_Cmd_TraceSEEWorld_Args, M_Command, M_KeyID, M_Reply, M_Status, M_Word, ModuleMode_Default,
    NFastApp_Connect, NFastApp_Connection, NFastApp_ConnectionFlags_Privileged,
    NFastApp_Disconnect, NFastApp_Free_Reply, NFastApp_Init, NFastApp_Transact, NFast_AppHandle,
    SEEInitStatus_OK, Status_OK, Status_ObjectInUse, Status_SEEWorldFailed,
};
use std::cmp::min;
use std::fs;
use std::net::SocketAddr;
use std::ops::Deref;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, info, instrument, warn};

use loam_mvp::clap_parsers::parse_duration;
use loam_mvp::google_auth;
use loam_mvp::logging;
use loam_mvp::realm::agent::Agent;
use loam_mvp::realm::hsm::client::{HsmClient, HsmRpcError, Transport};
use loam_mvp::realm::store::bigtable::BigTableArgs;

mod nfastapp;

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

    /// The name of the file containing the SEEMachine image (in SAR format). Is
    /// used to set the SEEMachine image in order to start or restart the SEE
    /// World. If not set the hardserver should be configured to auto load the
    /// relevant image. See section 6.3 of the Developer_CodeSafe_Guide
    #[arg(long)]
    image: Option<String>,

    /// HSM Metrics reporting interval in milliseconds [default: no reporting]
    #[arg(long, value_parser=parse_duration)]
    metrics: Option<Duration>,
}

#[tokio::main]
async fn main() {
    logging::configure("entrust-agent");

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
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

    let hsm_t = EntrustSeeTransport::new(args.module, args.trace, args.image);
    let hsm = HsmClient::new(hsm_t, name.clone(), args.metrics);
    let agent = Agent::new(name, hsm, store, store_admin);
    let (url, join_handle) = agent.listen(args.listen).await.expect("TODO");
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
    // An NFast API call returned an error.
    NFastError(M_Status),
    // A SEEJob transaction returned an error.
    CmdErrorReturn(M_Status),
    // The HSM process crashed or was otherwise terminated.
    SeeWorldFailed,
    // HSM Side marshalling errors
    HsmMarshallingError,
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

#[derive(Debug)]
struct EntrustSeeTransport(Arc<Mutex<TransportInner>>);
impl EntrustSeeTransport {
    fn new(module: u8, tracing: bool, seemachine: Option<String>) -> Self {
        Self(Arc::new(Mutex::new(TransportInner {
            tracing,
            module,
            see_machine: seemachine,
            app: null_mut(),
            conn: null_mut(),
            world_id: None,
        })))
    }
}

#[derive(Debug)]
struct TransportInner {
    tracing: bool,
    module: u8,
    see_machine: Option<String>,
    app: NFast_AppHandle,
    conn: NFastApp_Connection,
    world_id: Option<M_KeyID>,
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
    fn send_rpc_msg(&mut self, msg_name: &str, mut msg: Vec<u8>) -> Result<Vec<u8>, SeeError> {
        unsafe {
            self.connect()?;

            let mut cmd = M_Command::new(Cmd_SEEJob);
            cmd.args.seejob = M_Cmd_SEEJob_Args {
                worldid: self.world_id.expect("connect() sets the world_id"),
                seeargs: M_ByteBlock {
                    len: msg.len() as M_Word,
                    ptr: msg.as_mut_ptr(),
                },
            };
            let start = Instant::now();
            let reply = self.transact(&mut cmd)?;
            debug!(dur=?start.elapsed(), req=msg_name, "Entrust HSM request transacted");

            let resp_vec = reply.reply.seejob.seereply.as_slice().to_vec();
            self.collect_trace_buffer();
            Ok(resp_vec)
        }
    }

    unsafe fn connect(&mut self) -> Result<(), SeeError> {
        if self.app.is_null() {
            let rc = NFastApp_Init(&mut self.app, None, None, None, null_mut());
            let rc = rc as M_Status;
            if rc != Status_OK {
                return Err(SeeError::NFastError(rc));
            }
        }
        if self.conn.is_null() {
            let rc = NFastApp_Connect(self.app, &mut self.conn, 0, null_mut());
            let rc = rc as M_Status;
            if rc != Status_OK {
                return Err(SeeError::NFastError(rc));
            }
        }
        if self.world_id.is_none() {
            self.world_id = Some(self.start_seeworld()?);
        }
        Ok(())
    }

    unsafe fn start_seeworld(&mut self) -> Result<M_KeyID, SeeError> {
        if let Some(image) = &self.see_machine {
            // Load the SEEMachine image if one was specified
            let data = fs::read(image).expect("TODO");
            let buffer_id = self.load_buffer(data)?;
            let mut cmd = M_Command::new(Cmd_SetSEEMachine);
            cmd.args.setseemachine = M_Cmd_SetSEEMachine_Args {
                flags: 0,
                buffer: buffer_id,
            };
            self.transact(&mut cmd)?;
        }

        // a valid, dummy userdata section (taken from the hello world example)
        let user_data = [
            0x0Cu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x4C, 0xA2, 0xD7, 0x63, 0x1E, 0xEC, 0xA9, 0x5E, 0xD2, 0xDE, 0xA6, 0xAC,
            0x75, 0x88, 0xED, 0x32, 0x76, 0xD2, 0x41, 0x4E,
        ];
        let buffer_id = self.load_buffer(user_data.to_vec())?;

        let mut cmd = M_Command::new(Cmd_CreateSEEWorld);
        cmd.args.createseeworld = M_Cmd_CreateSEEWorld_Args {
            flags: if self.tracing {
                Cmd_CreateSEEWorld_Args_flags_EnableDebug
            } else {
                0
            },
            buffer: buffer_id,
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
        self.transact_on_conn(self.conn, cmd)
    }

    fn transact_on_conn(
        &mut self,
        conn: NFastApp_Connection,
        cmd: &mut M_Command,
    ) -> Result<Reply, SeeError> {
        let rc;
        let mut rep = M_Reply::default();
        unsafe {
            rc = NFastApp_Transact(conn, null_mut(), cmd, &mut rep, null_mut());
        }
        let rc = rc as M_Status;
        if rc != Status_OK {
            warn!(cmd=?cmd.cmd, ?rc, "NFastApp_Transact returned error");
            return Err(SeeError::NFastError(rc));
        }
        if rep.cmd == Cmd_ErrorReturn {
            warn!(cmd=?cmd.cmd, ?rep, "NFastApp_Transact returned ErrorReturn");
            if cmd.cmd != Cmd_TraceSEEWorld {
                self.collect_trace_buffer();
            }
            if rep.status == Status_SEEWorldFailed || rep.status == Status_ObjectInUse {
                // try restarting the SEE world
                self.restart_world();
                return Err(SeeError::SeeWorldFailed);
            }
            return Err(SeeError::CmdErrorReturn(rep.status));
        }
        Ok(Reply {
            app: self.app,
            inner: rep,
        })
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
                self.app,
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

#[derive(Debug)]
struct Reply {
    app: NFast_AppHandle,
    inner: M_Reply,
}

impl Drop for Reply {
    fn drop(&mut self) {
        unsafe {
            NFastApp_Free_Reply(self.app, null_mut(), null_mut(), &mut self.inner);
        }
    }
}

impl Deref for Reply {
    type Target = M_Reply;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl M_ByteBlock {
    pub unsafe fn as_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.ptr, self.len as usize)
    }
}

impl M_Command {
    pub fn new(cmd: M_Cmd) -> Self {
        Self {
            cmd,
            ..Self::default()
        }
    }
}
