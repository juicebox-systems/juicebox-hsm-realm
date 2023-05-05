#![cfg_attr(target_os = "ncipherxc", no_std)]
#![cfg_attr(target_os = "ncipherxc", feature(lang_items))]

#[cfg(target_os = "ncipherxc")]
mod ncipherxc;

mod platform;
mod seelib;

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};

use entrust_api::{
    EntrustRequest, InitializeRequest, InitializeResponse, StartRequest, StartResponse,
};
use hsmcore::hsm::{Hsm, HsmOptions, RealmKey};
use loam_sdk_core::marshalling;
use platform::NCipher;
use seelib::{
    M_Status, M_Word, SEElib_AwaitJobEx, SEElib_InitComplete, SEElib_ReturnJob, Status_BufferFull,
    SEELIB_JOB_REQUEUE,
};

#[no_mangle]
pub extern "C" fn rust_main() -> isize {
    let mut buf = vec![0; 32 * 1024];
    unsafe {
        SEElib_InitComplete(0);
    }

    // We process control jobs until we get a StartRequest, when we then
    // load the HSM instance and start handling application requests.
    let hsm = process_control_jobs(&mut buf);
    process_hsm_jobs(hsm, &mut buf);
    unreachable!()
}

fn process_control_jobs(buf: &mut Vec<u8>) -> Hsm<NCipher> {
    loop {
        let (tag, job) = await_job(buf);

        let req: Result<EntrustRequest, _> = marshalling::from_slice(job);
        match req {
            Ok(EntrustRequest::Initialize(req)) => {
                let res = initialize_hsm(req);
                let data = marshalling::to_vec(&res).unwrap();
                unsafe { SEElib_ReturnJob(tag, data.as_ptr(), data.len() as M_Word) };
            }
            Ok(EntrustRequest::Start(req)) => {
                let (hsm, res) = start_hsm(req);
                let data = marshalling::to_vec(&res).unwrap();
                unsafe { SEElib_ReturnJob(tag, data.as_ptr(), data.len() as M_Word) };
                if let Some(started_hsm) = hsm {
                    return started_hsm;
                }
            }
            Err(_) => {
                unsafe { SEElib_ReturnJob(tag, buf.as_ptr(), 0) };
            }
        }
    }
}

fn initialize_hsm(_req: InitializeRequest) -> InitializeResponse {
    // // redeem our tickets for keyIds.
    // let k = export_key(req.hmac_key_ticket);

    InitializeResponse::Ok
}

fn start_hsm(req: StartRequest) -> (Option<Hsm<NCipher>>, StartResponse) {
    match Hsm::new(
        HsmOptions {
            name: String::from("entrust"),
            tree_overlay_size: req.tree_overlay_size,
            max_sessions: req.max_sessions,
        },
        NCipher,
        RealmKey::derive_from("010203".as_bytes()),
    ) {
        Ok(hsm) => (Some(hsm), StartResponse::Ok),
        Err(err) => (None, StartResponse::PersistenceError(format!("{:?}", err))),
    }
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
