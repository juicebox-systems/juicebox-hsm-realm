#![cfg_attr(target_os = "ncipherxc", no_std)]
#![cfg_attr(target_os = "ncipherxc", feature(lang_items))]

#[cfg(target_os = "ncipherxc")]
mod ncipherxc;

mod seelib;

extern crate alloc;

use alloc::{string::String, vec};
use core::{slice, time::Duration};
use hsmcore::{
    hal::Clock,
    hsm::{Hsm, HsmOptions, RealmKey},
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
            tree_overlay_size: 511,
        },
        NCipher,
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

struct NCipher;

impl rand_core::CryptoRng for NCipher {}

// TODO: This RNG is slow, so we should be using it to seed another one
// instead.
impl rand_core::RngCore for NCipher {
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

    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl M_ByteBlock {
    pub unsafe fn as_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.ptr, self.len as usize)
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
#[repr(C)]
struct TimeSpec {
    sec: i32,
    nsec: i32,
}

type ClockId = isize;
const CLOCK_MONOTONIC: ClockId = 1;

extern "C" {
    fn clock_gettime(c: ClockId, tm: *mut TimeSpec) -> isize;
}

impl Clock for NCipher {
    type Instant = TimeSpec;

    fn now(&self) -> Option<TimeSpec> {
        let mut tm = TimeSpec::default();
        unsafe {
            match clock_gettime(CLOCK_MONOTONIC, &mut tm) {
                0 => Some(tm),
                _ => None,
            }
        }
    }

    fn elapsed(&self, start: TimeSpec) -> Option<Duration> {
        let end = self.now()?;
        timespec_elapsed(&start, &end)
    }
}

#[allow(clippy::manual_range_contains)] // clippy thinks (0..1_000_000_000).contains(&nsec) is clearer. clippy is nuts.
fn timespec_elapsed(start: &TimeSpec, end: &TimeSpec) -> Option<Duration> {
    if end < start {
        return None;
    }
    let mut sec = end.sec - start.sec;
    let mut nsec = end.nsec - start.nsec;
    if nsec < 0 {
        sec -= 1;
        nsec += 1_000_000_000;
    }
    assert!(sec >= 0);
    assert!(nsec >= 0 && nsec < 1_000_000_000);
    Some(Duration::new(sec as u64, nsec as u32))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn elapsed_zero() {
        let s = TimeSpec {
            sec: 123,
            nsec: 4_444_000,
        };
        assert_eq!(Some(Duration::ZERO), timespec_elapsed(&s, &s))
    }

    #[test]
    fn elapsed() {
        let s = TimeSpec {
            sec: 4,
            nsec: 10_000,
        };
        let e = TimeSpec {
            sec: 4,
            nsec: 100_000,
        };
        assert_eq!(
            Some(Duration::from_nanos(100_000 - 10_000)),
            timespec_elapsed(&s, &e)
        );

        let e = TimeSpec {
            sec: 6,
            nsec: 100_000,
        };
        assert_eq!(Some(Duration::new(2, 90_000)), timespec_elapsed(&s, &e));
    }

    #[test]
    fn elapsed_nsec_rollover() {
        let s = TimeSpec {
            sec: 10,
            nsec: 900_000_000,
        };
        let e = TimeSpec { sec: 11, nsec: 50 };
        assert_eq!(
            Some(Duration::from_nanos(100_000_050)),
            timespec_elapsed(&s, &e)
        );
    }

    #[test]
    fn end_lt_start() {
        let s = TimeSpec { sec: 5, nsec: 5000 };
        let e = TimeSpec { sec: 5, nsec: 4999 };
        assert!(timespec_elapsed(&s, &e).is_none());

        let s = TimeSpec { sec: 5, nsec: 5000 };
        let e = TimeSpec { sec: 4, nsec: 9000 };
        assert!(timespec_elapsed(&s, &e).is_none());
    }
}
