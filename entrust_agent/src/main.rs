use clap::Args;
use core::slice;
use std::cmp::min;
use std::ffi::CString;
use std::fmt::Display;
use std::iter::zip;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;
use std::{fs, thread};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use agent_core::hsm::Transport;
use agent_core::service::{AgentArgs, HsmTransportConstructor};
use entrust_api::{NvRamState, SEEJobResponseType, StartRequest, StartResponse, Ticket};
use entrust_nfast::{
    find_key, lookup_name_no_default, Cmd_ClearUnitEx, Cmd_CreateBuffer, Cmd_CreateSEEWorld,
    Cmd_CreateSEEWorld_Args_flags_EnableDebug, Cmd_Destroy, Cmd_GetTicket, Cmd_LoadBuffer,
    Cmd_LoadBuffer_Args_flags_Final, Cmd_NoOp, Cmd_SEEJob, Cmd_SetSEEMachine, Cmd_StatGetValues,
    Cmd_TraceSEEWorld, ConnectionFlags, M_ByteBlock, M_Cmd_ClearUnitEx_Args,
    M_Cmd_CreateBuffer_Args, M_Cmd_CreateSEEWorld_Args, M_Cmd_LoadBuffer_Args, M_Cmd_NoOp_Args,
    M_Cmd_SEEJob_Args, M_Cmd_SetSEEMachine_Args, M_Cmd_TraceSEEWorld_Args, M_Command, M_KeyID,
    M_Word, ModuleMode_Default, NFKM_cmd_loadblob, NF_StatID_enumtable, NFastConn, NFastError,
    Reply, SEEInitStatus_OK, StatInfo_flags_Counter, StatInfo_flags_Fraction,
    StatInfo_flags_IPAddress, StatInfo_flags_String, StatNodeTag_ModuleEnvStats,
    StatNodeTag_PerModule, Status_ObjectInUse, Status_SEEWorldFailed,
    TicketDestination_AnySEEWorld,
};
use juicebox_marshalling::{self as marshalling, DeserializationError, SerializationError};
use observability::{metrics, metrics_tag as tag};
use retry_loop::AttemptError;
use service_core::future_task::FutureTask;

/// A host agent for use with an Entrust nCipherXC HSM.
#[derive(Clone, Debug, Args)]
struct EntrustArgs {
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

    /// Reinitialize the NVRAM state back to blank, effectively making a new HSM.
    #[arg(long, default_value_t = false)]
    reinitialize: bool,

    /// Number of worker threads to use for the entrust transport.
    #[arg(long, default_value_t = 32)]
    transport_threads: u8,
}

impl EntrustArgs {
    fn nvram_state(&self) -> NvRamState {
        if self.reinitialize {
            NvRamState::Reinitialize
        } else {
            NvRamState::LastWritten
        }
    }
}

#[tokio::main]
async fn main() {
    let handle =
        agent_core::service::main("entrust_agent", build_info::get!(), &mut EntrustConstructor)
            .await;
    handle.await.unwrap();
}

struct EntrustConstructor;

impl HsmTransportConstructor<EntrustArgs, EntrustSeeTransport> for EntrustConstructor {
    async fn construct(
        &mut self,
        args: &AgentArgs<EntrustArgs>,
        metrics: &metrics::Client,
    ) -> (EntrustSeeTransport, Option<FutureTask<()>>) {
        (
            EntrustSeeTransport::new(args.service.clone(), metrics.clone()),
            None,
        )
    }
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
    HsmMarshallingError(String),
}

impl Display for SeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeeError::Serialization(err) => write!(f, "Serialization error: {:?}", err),
            SeeError::Deserialization(err) => write!(f, "Deserialization error: {:?}", err),
            SeeError::NFast(err) => write!(f, "NFastError: {}", err),
            SeeError::SeeWorldFailed => write!(f, "SEEWorld failed"),
            SeeError::HsmMarshallingError(msg) => {
                write!(f, "HSM Marshalling Error: {msg}")
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

impl From<NFastError> for SeeError {
    fn from(v: NFastError) -> Self {
        Self::NFast(v)
    }
}

impl From<SeeError> for AttemptError<SeeError> {
    fn from(error: SeeError) -> Self {
        match error {
            SeeError::Serialization(_) => AttemptError::Fatal {
                error,
                tags: vec![tag!("kind": "serialization")],
            },
            SeeError::Deserialization(_) => AttemptError::Fatal {
                error,
                tags: vec![tag!("kind": "deserialization")],
            },
            SeeError::NFast(_) => AttemptError::Fatal {
                error,
                tags: vec![tag!("kind": "nfast")],
            },
            SeeError::SeeWorldFailed => {
                // A retry might succeed after this restarts the world.
                AttemptError::Retryable {
                    error,
                    tags: vec![tag!("kind": "nfast")],
                }
            }
            SeeError::HsmMarshallingError(_) => AttemptError::Fatal {
                error,
                tags: vec![tag!("kind": "hsm_marshalling")],
            },
        }
    }
}

#[derive(Debug)]
struct EntrustSeeTransport(async_channel::Sender<WorkerRequest>);

impl EntrustSeeTransport {
    fn new(args: EntrustArgs, metrics: metrics::Client) -> Self {
        let (sender, receiver) = async_channel::bounded(128);

        let metrics_clone = metrics.clone();
        std::thread::spawn(move || collect_entrust_stats(args.module, metrics_clone));
        let conn =
            NFastConn::new(ConnectionFlags::NONE).expect("Failed to connect to Entrust Hardserver");
        let num_threads = args.transport_threads;
        let start = SEEWorldStarter {
            args,
            conn,
            metrics,
        };
        let world = unsafe { start.connect().expect("Failed to start SEEWorld") };
        for _ in 0..num_threads {
            let another_conn = world.additional_conn().unwrap();
            let another_rec = receiver.clone();
            thread::spawn(move || another_conn.run_worker(another_rec));
        }
        Self(sender)
    }
}

fn collect_entrust_stats(module: u8, mut metrics: metrics::Client) {
    let interval = Duration::from_secs(1);
    let conn =
        NFastConn::new(ConnectionFlags::NONE).expect("failed to connect to Entrust Hardserver");
    loop {
        if let Err(err) = collect_entrust_stats_inner(module, &conn, &mut metrics) {
            warn!(?err, "failed to collect stats from HSM");
        }
        std::thread::sleep(interval);
    }
}

const ALL_STATINFO_FLAG_BITS: u32 = 0b00111111;

fn collect_entrust_stats_inner(
    module: u8,
    conn: &NFastConn,
    metrics: &mut metrics::Client,
) -> Result<(), SeeError> {
    // see /opt/nfast/c/csd/examples/nfuser/stattree.c for the entrust example on reading stats.
    let mut stat_path = [
        StatNodeTag_PerModule,
        module as u32,
        StatNodeTag_ModuleEnvStats,
    ];
    let mut cmd = M_Command::new(Cmd_StatGetValues);
    cmd.args.statgetvalues.n_path_tags = stat_path.len() as i32;
    cmd.args.statgetvalues.path_tags = stat_path.as_mut_ptr();

    unsafe {
        let reply = conn.transact(&mut cmd)?;
        let statv = &reply.reply.statgetvalues;
        let stat_infos = slice::from_raw_parts(statv.statinfos, statv.n_statinfos as usize);
        let values = slice::from_raw_parts(statv.values, statv.n_values as usize);

        for (stat_info, value) in zip(stat_infos, values.iter().copied()) {
            if stat_info.flags & (StatInfo_flags_String | StatInfo_flags_IPAddress) != 0 {
                continue;
            }
            let metric_name = match lookup_name_no_default(stat_info.id, &NF_StatID_enumtable) {
                None => continue,
                Some(name) => format!("entrust.stat.module.{}", name),
            };

            if stat_info.flags & StatInfo_flags_Counter != 0 {
                metrics.count(metric_name, value as i64, metrics::NO_TAGS);
            } else if stat_info.flags & StatInfo_flags_Fraction != 0 {
                let (int, frac) = (value >> 16, ((value & 0xFFFF) * 100) >> 16);
                let result = (int as f32) + ((frac as f32) / 100.0);
                metrics.gauge(metric_name, result, metrics::NO_TAGS);
            } else if stat_info.flags & !ALL_STATINFO_FLAG_BITS == 0 {
                metrics.gauge(metric_name, value, metrics::NO_TAGS);
            } else {
                warn!(?metric_name, ?stat_info.flags, "ignoring metric with unknown flags set (probably a new metric type)");
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct WorkerRequest {
    msg_name: &'static str,
    msg: Vec<u8>,
    respond_to: oneshot::Sender<WorkerResult>,
}
type WorkerResult = Result<Vec<u8>, SeeError>;

impl WorkerRequest {
    fn new(
        msg_name: &'static str,
        msg: Vec<u8>,
        respond_to: oneshot::Sender<WorkerResult>,
    ) -> Self {
        Self {
            msg_name,
            msg,
            respond_to,
        }
    }
}

#[derive(Debug)]
struct SEEWorldStarter {
    args: EntrustArgs,
    conn: NFastConn,
    metrics: metrics::Client,
}

#[derive(Debug)]
struct SEEWorldConn {
    module: u8,
    conn: NFastConn,
    tracing: bool,
    world_id: M_KeyID,
    metrics: metrics::Client,
}

unsafe impl Send for SEEWorldConn {}

impl Transport for EntrustSeeTransport {
    type FatalError = SeeError;
    type RetryableError = SeeError;

    async fn send_rpc_msg(
        &self,
        msg_name: &'static str,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, AttemptError<SeeError>> {
        let (sender, receiver) = oneshot::channel();
        self.0
            .send(WorkerRequest::new(msg_name, msg, sender))
            .await
            .expect("HSM Transport worker task appears to be gone");
        receiver.await.unwrap().map_err(AttemptError::from)
    }
}

impl SEEWorldConn {
    fn run_worker(&self, receiver: async_channel::Receiver<WorkerRequest>) {
        while let Ok(work) = receiver.recv_blocking() {
            let result = self.send_hsm_msg(work.msg_name, work.msg);
            _ = work.respond_to.send(result);
        }
        info!("entrust transport worker thread stopping");
    }

    fn additional_conn(&self) -> Result<SEEWorldConn, NFastError> {
        Ok(SEEWorldConn {
            module: self.module,
            conn: self.conn.additional(ConnectionFlags::NONE)?,
            tracing: self.tracing,
            world_id: self.world_id,
            metrics: self.metrics.clone(),
        })
    }

    fn send_hsm_msg(&self, msg_name: &str, msg: Vec<u8>) -> Result<Vec<u8>, SeeError> {
        let start = Instant::now();
        let req_len = msg.len();
        let resp_vec = self.transact_seejob(msg)?;
        let elapsed = start.elapsed();
        let tag = tag!(?msg_name);
        self.metrics.timing("entrust.seejob.time", elapsed, [&tag]);
        self.metrics
            .distribution("entrust.seejob.request.bytes", req_len, [&tag]);
        self.metrics
            .distribution("entrust.seejob.response.bytes", resp_vec.len(), [&tag]);

        Ok(resp_vec)
    }
}

impl SEEWorldStarter {
    unsafe fn connect(self) -> Result<SEEWorldConn, SeeError> {
        let world_id = match self.start_seeworld() {
            Ok(id) => id,
            Err(e) => {
                let perform_clear = match e {
                    SeeError::SeeWorldFailed => true,
                    SeeError::NFast(NFastError::Transact(status))
                        if status == Status_ObjectInUse =>
                    {
                        true
                    }
                    _ => false,
                };
                if !perform_clear {
                    return Err(e);
                }
                self.try_clear();
                self.start_seeworld()?
            }
        };
        let conn = SEEWorldConn {
            conn: self.conn,
            tracing: self.args.trace,
            world_id,
            metrics: self.metrics,
            module: self.args.module,
        };
        conn.start_hsmcore(self.args.nvram_state());
        Ok(conn)
    }
}

impl SEEWorldConn {
    fn start_hsmcore(&self, nvram: NvRamState) {
        // Collect up all the key tickets we need.
        let comm_private_key = self.ticket_for_key("simple", "jbox-noise", KeyHalf::Private);
        let comm_public_key = self.ticket_for_key("simple", "jbox-noise", KeyHalf::Public);
        let mac_key = self.ticket_for_key("simple", "jbox-mac", KeyHalf::Private);
        let record_key = self.ticket_for_key("simple", "jbox-record", KeyHalf::Private);

        // send a StartRequest Job to get HSMCore running.
        let start = StartRequest {
            tree_overlay_size: 511,
            // This is large enough that a malicious client can't churn the
            // entire cache faster than a different client can get their
            // register/recover completed. It takes ~2ms for the HSM to complete
            // a Noise handshake, no session can be evicted within 8192 * 2 /
            // 1000 = 16.384 seconds of its creation.
            max_sessions: 8192,
            comm_private_key,
            comm_public_key,
            mac_key,
            record_key,
            nvram,
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

    fn transact_seejob(&self, mut data: Vec<u8>) -> Result<Vec<u8>, SeeError> {
        let mut cmd = M_Command::new(Cmd_SEEJob);
        cmd.args.seejob = M_Cmd_SEEJob_Args {
            worldid: self.world_id,
            seeargs: M_ByteBlock::from_vec(&mut data),
        };
        let reply = self.transact(&mut cmd)?;
        let mut data = unsafe { reply.reply.seejob.seereply.as_slice().to_vec() };
        let result = match SEEJobResponseType::from_byte(
            data.pop()
                .expect("SEEJob responses should always include the type trailer byte"),
        ) {
            Ok(SEEJobResponseType::JobResult) => Ok(data),
            Ok(SEEJobResponseType::JobResultWithIdleTime) => {
                assert!(data.len() >= 4);
                let idle_bytes = data.split_off(data.len() - 4);
                let idle = u32::from_be_bytes(idle_bytes.try_into().unwrap());
                self.metrics.timing(
                    "entrust.idle_time",
                    Duration::from_nanos(idle.into()),
                    metrics::NO_TAGS,
                );
                Ok(data)
            }
            Ok(SEEJobResponseType::PanicMessage) => {
                panic!("HSM panicked: {}\n", String::from_utf8_lossy(&data));
            }
            Ok(SEEJobResponseType::MarshallingError) => {
                let msg = String::from_utf8_lossy(&data).to_string();
                Err(SeeError::HsmMarshallingError(msg))
            }
            Err(msg) => Err(SeeError::Deserialization(DeserializationError(msg))),
        };
        if self.tracing {
            self.collect_trace_buffer();
        }
        result
    }

    // If there's a problem generating a ticket for a key, then we can't start
    // the hsmcore, and retrying is highly unlikely to work. So this panics on
    // all the error conditions.
    fn ticket_for_key(&self, app: &str, ident: &str, half: KeyHalf) -> Ticket {
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
}

impl SEEWorldStarter {
    unsafe fn start_seeworld(&self) -> Result<M_KeyID, SeeError> {
        // Load the SEEMachine image
        let data = fs::read(&self.args.image).unwrap_or_else(|err| {
            panic!(
                "Failed to load see machine image file {}: {err}",
                self.args.image.display()
            )
        });
        let image_buffer = self.load_buffer(data)?;
        let mut cmd = M_Command::new(Cmd_SetSEEMachine);
        cmd.args.setseemachine = M_Cmd_SetSEEMachine_Args {
            flags: 0,
            buffer: image_buffer,
        };
        self.conn.transact(&mut cmd)?;

        let user_data = fs::read(&self.args.userdata).unwrap_or_else(|err| {
            panic!(
                "Failed to load userdata file {}: {err}",
                self.args.userdata.display()
            )
        });
        let user_data_buffer = self.load_buffer(user_data)?;

        let mut cmd = M_Command::new(Cmd_CreateSEEWorld);
        cmd.args.createseeworld = M_Cmd_CreateSEEWorld_Args {
            flags: if self.args.trace {
                Cmd_CreateSEEWorld_Args_flags_EnableDebug
            } else {
                0
            },
            buffer: user_data_buffer,
        };
        let reply = self.conn.transact(&mut cmd)?;
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

    /// Create's a HSM buffer and loads the supplied userdata into it. Returns the buffer id.
    fn load_buffer(&self, mut userdata: Vec<u8>) -> Result<M_KeyID, SeeError> {
        // This function takes a Vec<u8> for userdata to ensure its on the heap, as required
        // by the transact calls for Cmd_LoadBuffer.
        let buffer_id = {
            let mut cmd = M_Command::new(Cmd_CreateBuffer);
            cmd.args.createbuffer = M_Cmd_CreateBuffer_Args {
                module: self.args.module as M_Word,
                flags: 0,
                size: userdata.len() as M_Word,
                params: null_mut(),
            };
            unsafe {
                let rep = self.conn.transact(&mut cmd)?;
                rep.reply.createbuffer.id
            }
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
            unsafe { self.conn.transact(&mut cmd)? };
            togo = &mut togo[n..];
        }
        Ok(buffer_id)
    }
}

impl SEEWorldConn {
    /// Collect any data from the HSM trace buffer and log it.
    fn collect_trace_buffer(&self) {
        assert!(self.tracing);
        let mut cmd = M_Command::new(Cmd_TraceSEEWorld);
        cmd.args.traceseeworld = M_Cmd_TraceSEEWorld_Args {
            worldid: self.world_id,
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

    fn transact(&self, cmd: &mut M_Command) -> Result<Reply, SeeError> {
        let res = unsafe { self.conn.transact(cmd) };
        if let Err(NFastError::Transact(status)) = res {
            if cmd.cmd != Cmd_TraceSEEWorld && self.tracing {
                self.collect_trace_buffer();
            }
            if status == Status_SEEWorldFailed || status == Status_ObjectInUse {
                // Attempt to gracefully cleanup so that things restart cleanly.
                let mut cmd = M_Command::new(Cmd_Destroy);
                cmd.args.destroy.key = self.world_id;
                if let Err(err) = unsafe { self.conn.transact(&mut cmd) } {
                    warn!(?err, "attempt to close the SEEWorld failed");
                }
                // Because of the role clocks it's not safe to restart the
                // SEEWorld without restarting the agent.
                panic!(
                    "The SEEWorld crashed while transacting a request (err={})",
                    NFastError::Transact(status)
                );
            }
        }
        Ok(res?)
    }
}

impl SEEWorldStarter {
    /// If the SEEWorld fails to start, it's usually because the SEEWorld
    /// previously crashed or was terminated by the HSM and it didn't get
    /// cleaned up.
    ///
    /// SEEWorldConn attempts to gracefully clean up, but if that doesn't work
    /// then this more aggressive one should do it.
    ///
    /// Recovering from this involves:
    /// * Getting a privileged connection.
    /// * Issuing a clear command (equiv to noopclearfail -c)
    ///
    /// This requires that the user account running the service is a member
    /// of the 'nfast' group.
    ///
    /// This panics if its unable to successfully perform the clear
    fn try_clear(&self) {
        warn!("Attempting to clear SEEWorld");
        let priv_conn = NFastConn::new(ConnectionFlags::NONE.with_privileged()).expect(
            "Connect for privileged connection failed. Unable to recover from crashed SEEWorld",
        );

        // issue the clear command
        let mut cmd = M_Command::new(Cmd_ClearUnitEx);
        cmd.args.clearunitex = M_Cmd_ClearUnitEx_Args {
            flags: 0,
            module: self.args.module as M_Word,
            mode: ModuleMode_Default,
        };
        let reply = unsafe { priv_conn.transact(&mut cmd) };
        match reply {
            Err(e) => {
                panic!(
                    "The attempt the clear the HSM so it can be restarted failed with error {e:?}"
                );
            }
            Ok(_r) => {
                info!("Clear successfully issued, waiting on it to finish.");
                // Clear takes a while we'll wait on a no-op for it to finish.
                let mut cmd = M_Command::new(Cmd_NoOp);
                cmd.args.noop = M_Cmd_NoOp_Args {
                    module: self.args.module as M_Word,
                };
                match unsafe { priv_conn.transact(&mut cmd) } {
                    Err(e) => {
                        panic!(
                            "Performing a No-op after performing a clear failed with error {e:?}"
                        );
                    }
                    Ok(_reply) => {
                        info!("Clear successfully completed.");
                    }
                }
            }
        }
    }
}

enum KeyHalf {
    Public,
    Private,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::service::AgentArgs;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["../usage.txt"].assert_eq(
            &AgentArgs::<EntrustArgs>::command()
                .try_get_matches_from(["agent", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
