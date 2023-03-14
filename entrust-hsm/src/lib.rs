#![cfg_attr(target_os = "ncipherxc", no_std)]
#![cfg_attr(target_os = "ncipherxc", feature(lang_items))]

#[cfg(target_os = "ncipherxc")]
mod ncipherxc;

mod seelib;

extern crate alloc;

use alloc::{boxed::Box, string::String, vec};
use core::slice;
use hsmcore::{
    hsm::{Hsm, HsmOptions, RealmKey},
    rand::GetRandom,
};
use seelib::{
    Cmd_GenerateRandom, M_ByteBlock, M_Cmd_GenerateRandom_Args, M_Command, M_Reply, M_Status,
    M_Word, SEElib_AwaitJobEx, SEElib_FreeReply, SEElib_InitComplete, SEElib_ReturnJob,
    SEElib_Transact, Status_BufferFull, Status_OK, SEELIB_JOB_REQUEUE,
};

#[no_mangle]
pub extern "C" fn rust_main() -> isize {
    let mut hsm = Hsm::new(
        HsmOptions {
            name: String::from("entrust"),
            rng: Box::new(NFastRng),
            tree_overlay_size: 511,
        },
        RealmKey::derive_from("010203".as_bytes()),
    );
    let mut buf = vec![0; 32 * 1024];
    let mut tag: M_Word = 0;
    let mut len: M_Word;
    unsafe {
        SEElib_InitComplete(0);
    }
    //println!("entrust-hsm init complete, ready for jobs");
    loop {
        len = buf.len() as M_Word;
        let rc: i32;
        unsafe {
            rc = SEElib_AwaitJobEx(&mut tag, buf.as_mut_ptr(), &mut len, SEELIB_JOB_REQUEUE);
        }
        let rc = rc as M_Status;
        if rc == Status_BufferFull {
            buf.resize(len as usize, 0);
            continue;
        }
        if rc == Status_OK {
            let result = hsm.handle_request(&buf[..len as usize]);
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
        } else {
            // println!("AwaitJobEx returned unexpected error {}", rc);
        }
    }
}

struct NFastRng;

impl GetRandom for NFastRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut cmd = M_Command {
            cmd: Cmd_GenerateRandom,
            ..M_Command::default()
        };
        cmd.args.generaterandom = M_Cmd_GenerateRandom_Args {
            lenbytes: dest.len() as M_Word,
        };
        unsafe {
            let mut reply = M_Reply::default();
            let rc = SEElib_Transact(&mut cmd, &mut reply);
            assert_eq!(0, rc);
            assert_eq!(cmd.cmd, reply.cmd);
            let d = reply.reply.generaterandom.data.as_slice();
            dest.copy_from_slice(d);
            SEElib_FreeReply(&mut reply);
        }
    }
}

impl M_ByteBlock {
    pub unsafe fn as_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.ptr, self.len as usize)
    }
}
