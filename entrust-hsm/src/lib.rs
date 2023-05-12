#![cfg_attr(target_os = "ncipherxc", no_std)]
#![cfg_attr(target_os = "ncipherxc", feature(lang_items))]

#[cfg(target_os = "ncipherxc")]
mod ncipherxc;

mod platform;
mod seelib;

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use x25519_dalek as x25519;

use entrust_api::{KeyRole, StartRequest, StartResponse, Ticket};
use hsmcore::hsm::{Hsm, HsmOptions, MacKey, RealmKeys, RecordEncryptionKey};
use loam_sdk_core::marshalling;
use platform::{transact, NCipher, SeeError};
use seelib::{
    Cmd_Export, Cmd_RedeemTicket, M_ByteBlock, M_Command, M_Hash, M_Status, M_Word,
    SEElib_AwaitJobEx, SEElib_InitComplete, SEElib_ReturnJob, Status_BufferFull,
    SEELIB_JOB_REQUEUE,
};

#[no_mangle]
pub extern "C" fn rust_main() -> isize {
    let mut buf = vec![0; 32 * 1024];
    unsafe {
        SEElib_InitComplete(0);
    }

    // We process start jobs until we get a successful HSM instance, then start
    // handling application requests.
    let hsm = process_start_jobs(&mut buf);
    process_hsm_jobs(hsm, &mut buf);
    unreachable!()
}

fn process_start_jobs(buf: &mut Vec<u8>) -> Hsm<NCipher> {
    loop {
        let (tag, job) = await_job(buf);

        let req: Result<StartRequest, _> = marshalling::from_slice(job);
        match req {
            Ok(req) => {
                let (hsm, resp) = match start_hsm(req) {
                    Ok(hsm) => (Some(hsm), StartResponse::Ok),
                    Err(res) => (None, res),
                };
                let data = marshalling::to_vec(&resp).unwrap();
                unsafe { SEElib_ReturnJob(tag, data.as_ptr(), data.len() as M_Word) };
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
            Err(_) => {
                // We couldn't deserialize the StartRequest we got
                unsafe { SEElib_ReturnJob(tag, buf.as_ptr(), 0) };
            }
        }
    }
}

fn start_hsm(req: StartRequest) -> Result<Hsm<NCipher>, StartResponse> {
    let platform = NCipher::new()?;

    let comm_private_key: [u8; 32] = redeem_ticket(
        KeyRole::CommunicationPrivateKey,
        req.comm_private_key,
        platform.world_signer,
    )?;

    let comm_public_key: [u8; 32] = redeem_ticket(
        KeyRole::CommunicationPublicKey,
        req.comm_public_key,
        platform.world_signer,
    )?;

    let record_key: [u8; 32] =
        redeem_ticket(KeyRole::RecordKey, req.record_key, platform.world_signer)?;

    let mac_key: [u8; 64] = redeem_ticket(KeyRole::MacKey, req.mac_key, platform.world_signer)?;

    let keys = RealmKeys {
        communication: (
            x25519::StaticSecret::from(comm_private_key),
            x25519::PublicKey::from(comm_public_key),
        ),
        record: RecordEncryptionKey::from(record_key),
        mac: MacKey::from(mac_key),
    };

    Hsm::new(
        HsmOptions {
            name: String::from("entrust"),
            tree_overlay_size: req.tree_overlay_size,
            max_sessions: req.max_sessions,
        },
        platform,
        keys,
    )
    .map_err(|err| StartResponse::PersistenceError(format!("{:?}", err)))
}

fn process_hsm_jobs(mut hsm: Hsm<NCipher>, buf: &mut Vec<u8>) {
    //println!("entrust-hsm init complete, ready for jobs");
    loop {
        let (tag, job) = await_job(buf);
        let result = hsm.handle_request(job);
        match result {
            Ok(data) => {
                //println!("success, returning {} bytes", data.len());
                unsafe { SEElib_ReturnJob(tag, data.as_ptr(), data.len() as u32) }
            }
            Err(_e) => {
                // There are no valid responses that are empty. We use an empty response to signal
                // a marshalling failure.
                //println!("failed with marshalling error {:?}", _e);
                unsafe { SEElib_ReturnJob(tag, buf.as_ptr(), 0) }
            }
        };
    }
}

// Waits for a job and returns its tag and data. buf will be expanded if the job
// is larger than the current capacity of buf.
fn await_job(buf: &mut Vec<u8>) -> (M_Word, &[u8]) {
    let mut tag: M_Word = 0;
    loop {
        let mut len = buf.len() as M_Word;
        let rc =
            unsafe { SEElib_AwaitJobEx(&mut tag, buf.as_mut_ptr(), &mut len, SEELIB_JOB_REQUEUE) };
        let rc = rc as M_Status;
        if rc == Status_BufferFull {
            buf.resize(len as usize, 0);
            continue;
        }
        return (tag, &buf[..(len as usize)]);
    }
}

// Redeem a ticket for a keyId, then export the key to get its actual bytes.
fn redeem_ticket<const N: usize>(
    key_role: KeyRole,
    mut ticket: Ticket,
    world_signer: M_Hash,
) -> Result<[u8; N], StartResponse> {
    let mut cmd = M_Command::new(Cmd_RedeemTicket);
    cmd.args.redeemticket.ticket = M_ByteBlock::from_vec(&mut ticket.0);

    let err_mapper = |err: SeeError| StartResponse::InvalidTicket(key_role, err.status());

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
