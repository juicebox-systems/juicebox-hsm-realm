#![cfg_attr(target_os = "ncipherxc", no_std)]
#![cfg_attr(target_os = "ncipherxc", feature(lang_items))]

#[cfg(target_os = "ncipherxc")]
mod ncipherxc;

mod platform;
mod seelib;

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicU32, Ordering};
use marshalling::to_be4;
use x25519_dalek as x25519;

use entrust_api::{KeyRole, SEEJobResponseType, StartRequest, StartResponse, Ticket};
use hsm_core::hsm::{
    mac::MacKey, Hsm, HsmOptions, MetricsReporting, RealmKeys, RecordEncryptionKey,
};
use juicebox_marshalling as marshalling;
use platform::{register_global_rng, transact, NCipher, SeeError};
use seelib::{
    Cmd_Export, Cmd_RedeemTicket, M_ByteBlock, M_Command, M_Hash, M_Status, M_Word,
    SEElib_AwaitJobEx, SEElib_InitComplete, SEElib_ReturnJob, Status_BufferFull,
    SEELIB_JOB_REQUEUE,
};

// We'll refuse SEEJobs that are larger than this.
const MAX_JOB_SIZE_BYTES: usize = 1024 * 1024;

// Set to the tag of the SEEJob when a SEEJob is being processed. Used by the
// panic handler to return a panic message to the agent. 0 means no active job.
static ACTIVE_JOB_TAG: AtomicU32 = AtomicU32::new(0);

#[no_mangle]
pub extern "C" fn rust_main() -> isize {
    let mut buf = vec![0; 32 * 1024];
    unsafe {
        SEElib_InitComplete(0);
    }

    // Register a global random number generator (used for randomized hash
    // tables). This can be done early since the RNG doesn't depend on the rest
    // of the platform being initialized.
    register_global_rng();

    #[cfg(not(target_os = "ncipherxc"))]
    std::panic::set_hook(Box::new(|info| {
        println!("{}", info);
        let tag = ACTIVE_JOB_TAG.load(Ordering::Relaxed);
        if tag != 0 {
            let data = info.to_string().into_bytes();
            return_job(tag, data, SEEJobResponseType::PanicMessage);
        }
        std::process::abort();
    }));

    // We process start jobs until we get a successful HSM instance, then start
    // handling application requests.
    let hsm = process_start_jobs(&mut buf);
    process_hsm_jobs(hsm, &mut buf);
    unreachable!()
}

fn process_start_jobs(buf: &mut Vec<u8>) -> Hsm<NCipher> {
    loop {
        let (tag, job_len) = await_job(buf);

        let req: Result<StartRequest, _> = marshalling::from_slice(&buf[..job_len]);
        match req {
            Ok(req) => {
                let (hsm, resp) = match start_hsm(req) {
                    Ok(hsm) => (Some(hsm), StartResponse::Ok),
                    Err(res) => (None, res),
                };
                let data = marshalling::to_vec(&resp).unwrap();
                return_job(tag, data, SEEJobResponseType::JobResult);
                if let Some(started_hsm) = hsm {
                    return started_hsm;
                }
                // Its exceedingly unlikely that another StartRequest will
                // succeed. However we keep looping trying start requests
                // because we don't want this SEEWorld process to exit on its
                // own. If it did that would end with the the hard server
                // treating it as crashed, which can be very slow to recover
                // from. The agent though will panic on the failed StartRequest
                // which'll have the hard server shutdown the SEEWorld.
            }
            Err(err) => {
                // We couldn't deserialize the StartRequest we got
                return_job(
                    tag,
                    err.to_string().into_bytes(),
                    SEEJobResponseType::MarshallingError,
                );
            }
        }
    }
}

fn start_hsm(req: StartRequest) -> Result<Hsm<NCipher>, StartResponse> {
    let platform = NCipher::new()?;

    let comm_private_key = x25519::StaticSecret::from(redeem_ticket(
        KeyRole::CommunicationPrivateKey,
        req.comm_private_key,
        platform.world_signer,
    )?);

    let comm_public_key = x25519::PublicKey::from(redeem_ticket(
        KeyRole::CommunicationPublicKey,
        req.comm_public_key,
        platform.world_signer,
    )?);

    let record_key = RecordEncryptionKey::from(redeem_ticket(
        KeyRole::RecordKey,
        req.record_key,
        platform.world_signer,
    )?);

    let mac_key = MacKey::from(redeem_ticket(
        KeyRole::MacKey,
        req.mac_key,
        platform.world_signer,
    )?);

    let keys = RealmKeys {
        communication: (comm_private_key, comm_public_key),
        record: record_key,
        mac: mac_key,
    };

    if req.nvram == entrust_api::NvRamState::Reinitialize {
        use hsm_core::hal::NVRam;
        platform.write(Vec::new()).map_err(|err| {
            StartResponse::PersistenceError(format!("error while re-initializing NVRAM: {:?}", err))
        })?;
    }

    let metrics = if cfg!(feature = "insecure") {
        MetricsReporting::Enabled
    } else {
        MetricsReporting::Disabled
    };

    Hsm::new(
        HsmOptions {
            name: String::from("entrust"),
            tree_overlay_size: req.tree_overlay_size,
            max_sessions: req.max_sessions,
            metrics,
        },
        platform,
        keys,
    )
    .map_err(|err| StartResponse::PersistenceError(format!("{:?}", err)))
}

fn process_hsm_jobs(mut hsm: Hsm<NCipher>, buf: &mut Vec<u8>) {
    //println!("entrust-hsm init complete, ready for jobs");
    loop {
        let start = if cfg!(feature = "insecure") {
            platform::now()
        } else {
            None
        };
        let (tag, job_len) = await_job(buf);
        let idle = start.and_then(platform::elapsed);

        let result = hsm.handle_request(&buf[..job_len]);
        match result {
            Ok(mut data) => {
                let t = match idle {
                    None => SEEJobResponseType::JobResult,
                    Some(nanos) => {
                        let idle_bytes = to_be4(nanos.0);
                        data.extend(idle_bytes);
                        SEEJobResponseType::JobResultWithIdleTime
                    }
                };
                return_job(tag, data, t);
            }
            Err(err) => {
                return_job(
                    tag,
                    err.to_string().into_bytes(),
                    SEEJobResponseType::MarshallingError,
                );
            }
        };
    }
}

// Waits for a job and returns its tag and len. buf will be expanded if the job
// is larger than the current capacity of buf.
fn await_job(buf: &mut Vec<u8>) -> (M_Word, usize) {
    let mut tag: M_Word = 0;
    loop {
        let mut len = buf.len() as M_Word;
        let flags = if buf.len() == MAX_JOB_SIZE_BYTES {
            // Without requeue jobs larger than the available buffer size get
            // outright rejected.
            0
        } else {
            SEELIB_JOB_REQUEUE
        };
        let rc = unsafe { SEElib_AwaitJobEx(&mut tag, buf.as_mut_ptr(), &mut len, flags) };
        let rc = rc as M_Status;
        if rc == Status_BufferFull {
            buf.resize(min(len as usize, MAX_JOB_SIZE_BYTES), 0);
            continue;
        }
        // Everything is executed on the same one thread, so Ordering::Relaxed is
        // fine. The only reason its an atomic is to keep the borrow checker happy.
        ACTIVE_JOB_TAG.store(tag, Ordering::Relaxed);
        return (tag, len as usize);
    }
}

fn return_job(tag: M_Word, mut data: Vec<u8>, response_type: SEEJobResponseType) {
    ACTIVE_JOB_TAG.store(0, Ordering::Relaxed);
    data.push(response_type.as_byte());
    unsafe { SEElib_ReturnJob(tag, data.as_ptr(), data.len() as M_Word) };
}

// Redeem a ticket for a keyId, then export the key to get its actual bytes.
fn redeem_ticket<const N: usize>(
    key_role: KeyRole,
    mut ticket: Ticket,
    world_signer: M_Hash,
) -> Result<[u8; N], StartResponse> {
    let err_mapper = |err: SeeError| StartResponse::InvalidTicket(key_role, err.status());

    let mut cmd = M_Command::new(Cmd_RedeemTicket);
    cmd.args.redeemticket.ticket = M_ByteBlock::from_vec(&mut ticket.0);
    let reply = transact(&mut cmd, Some(world_signer)).map_err(err_mapper)?;
    let key_id = unsafe { reply.reply.redeemticket.obj };

    let mut cmd = M_Command::new(Cmd_Export);
    cmd.args.export.key = key_id;
    let reply = transact(&mut cmd, Some(world_signer)).map_err(err_mapper)?;

    let key = unsafe { reply.reply.export.data.data.random.k.as_slice() };
    if key.len() != N {
        return Err(StartResponse::InvalidKeyLength {
            role: key_role,
            expecting: N,
            actual: key.len(),
        });
    }
    let mut res = [0u8; N];
    res.copy_from_slice(key);
    Ok(res)
}
