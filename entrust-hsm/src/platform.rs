use alloc::{format, vec::Vec};
use core::{
    num::NonZeroU32,
    ops::{Deref, Sub},
    slice,
};
use rand_core::Error;

use super::seelib::{
    CertType_SEECert, Cmd_GenerateRandom, Cmd_GetWorldSigners, Cmd_NVMemOp,
    Command_flags_certs_present, M_ByteBlock, M_Certificate, M_CertificateList, M_Cmd, M_Command,
    M_FileID, M_KeyHash, M_NVMemOpType_Write_OpVal, M_Reply, M_Status, M_Word, NVMemOpType_Read,
    NVMemOpType_Write, SEElib_FreeReply, SEElib_Transact, Status_OK,
};
use entrust_api::WorldSignerError;
use hsmcore::hal::{Clock, IOError, NVRam, Nanos, MAX_NVRAM_SIZE};

/// NCipher implements the Platform trait, which provides platform specific
/// functionality to the hsmcore library.
#[derive(Clone)]
pub struct NCipher {
    // The hash of the key used to sign the SEEMachine/Userdata. We need this
    // when accessing resources that are restricted to the signing key. This
    // needs making into a Certificate to make the calls, but we can't keep it
    // as a certificate here because a certificate contains raw pointers, which
    // makes it problematic.
    world_cert_key: M_KeyHash,
}

impl NCipher {
    pub fn new() -> Result<NCipher, WorldSignerError> {
        let mut cmd = M_Command::new(Cmd_GetWorldSigners);
        let reply = transact(&mut cmd, None)
            .map_err(|e| WorldSignerError::FailedToLoad { status: e.status() })?;
        match unsafe { reply.reply.getworldsigners.n_sigs } {
            0 => Err(WorldSignerError::NoWorldSigner),
            1 => Ok(NCipher {
                world_cert_key: unsafe { (*reply.reply.getworldsigners.sigs).hash },
            }),
            _ => Err(WorldSignerError::TooManyWorldSigners),
        }
    }
}

impl rand_core::CryptoRng for NCipher {}

// TODO: This RNG is slow, so we should be using it to seed another one
// instead.
impl rand_core::RngCore for NCipher {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap()
    }

    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let mut cmd = M_Command::new(Cmd_GenerateRandom);
        cmd.args.generaterandom.lenbytes = dest.len() as M_Word;
        let reply = transact(&mut cmd, None).map_err(|err| {
            rand_core::Error::from(NonZeroU32::new(Error::CUSTOM_START + err.status()).unwrap())
        })?;
        unsafe {
            let d = reply.reply.generaterandom.data.as_slice();
            dest.copy_from_slice(d);
        }
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
pub struct TimeSpec {
    sec: i32,
    nsec: i32,
}
impl Sub for TimeSpec {
    type Output = Nanos;

    #[allow(clippy::manual_range_contains)] // clippy thinks (0..1_000_000_000).contains(&nsec) is clearer. clippy is nuts.
    fn sub(self, rhs: Self) -> Self::Output {
        if rhs > self {
            Nanos(0)
        } else {
            let mut sec = self.sec - rhs.sec;
            let mut nsec = self.nsec - rhs.nsec;
            if nsec < 0 {
                sec -= 1;
                nsec += 1_000_000_000;
            }
            assert!(sec >= 0);
            assert!(nsec >= 0 && nsec < 1_000_000_000);
            let nanos = (sec as u32)
                .saturating_mul(1_000_000_000)
                .saturating_add(nsec as u32);
            Nanos(nanos)
        }
    }
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

    fn elapsed(&self, start: TimeSpec) -> Option<Nanos> {
        Some(self.now()? - start)
    }
}

const NVRAM_FILENAME: M_FileID = M_FileID {
    // state
    bytes: [b's', b't', b'a', b't', b'e', 0, 0, 0, 0, 0, 0],
};

const NCIPHER_NVRAM_LEN: usize = 4096;
const NVRAM_LEN_OFFSET: usize = NCIPHER_NVRAM_LEN - 4;

impl NVRam for NCipher {
    // The admin needs to allocate an nvram area called 'state' with a size of
    // 4096 bytes. The nvram-sw tool can do this.
    // /opt/nfast/bin/nvram-sw --alloc -b 4096 -n state
    //
    // For production we need something that will correctly set the acl on this
    // nvram file. See the entrust_init tool.
    //
    // read will always return the full 4096 bytes, and writes need to send a
    // full 4096 bytes. The last 4 bytes hold the size of the data that was
    // written. This is extracted during read to correctly size the returned
    // data.

    fn read(&self) -> Result<Vec<u8>, IOError> {
        let mut cmd = M_Command::new(Cmd_NVMemOp);
        cmd.args.nvmemop.op = NVMemOpType_Read;
        cmd.args.nvmemop.name = NVRAM_FILENAME;

        let reply = transact(&mut cmd, Some(self.world_cert_key))
            .map_err(|err| IOError(format!("SEElib_Transact for NVMemOp read failed: {err:?}")))?;

        let mut data = unsafe { reply.reply.nvmemop.res.read.data.as_slice().to_vec() };
        // The first read after the NVRam entry was initialized will be
        // all zeros. Which conveniently says the length is zero.
        if data.len() != NCIPHER_NVRAM_LEN {
            return Err(IOError(format!(
                "data read from NVRam is wrong size, should be {NCIPHER_NVRAM_LEN} bytes, but was {}",
                data.len()
            )));
        }
        let len = u32::from_be_bytes(
            data[NVRAM_LEN_OFFSET..NVRAM_LEN_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        data.truncate(len as usize);
        Ok(data)
    }

    fn write(&self, mut data: Vec<u8>) -> Result<(), IOError> {
        if data.len() > MAX_NVRAM_SIZE {
            return Err(IOError(format!(
                "data with {} bytes is larger than allowed maximum of {MAX_NVRAM_SIZE}",
                data.len()
            )));
        }
        let len = (data.len() as u32).to_be_bytes();
        data.resize(NVRAM_LEN_OFFSET, 0);
        data.extend(&len);

        let mut cmd = M_Command::new(Cmd_NVMemOp);
        cmd.args.nvmemop.op = NVMemOpType_Write;
        cmd.args.nvmemop.name = NVRAM_FILENAME;
        cmd.args.nvmemop.val.write = M_NVMemOpType_Write_OpVal {
            data: M_ByteBlock {
                len: data.len() as M_Word,
                ptr: data.as_mut_ptr(),
            },
        };

        transact(&mut cmd, Some(self.world_cert_key))
            .map_err(|err| IOError(format!("NVMemOp write failed: {err:?}")))?;
        Ok(())
    }
}

impl M_Command {
    fn new(cmd: M_Cmd) -> Self {
        M_Command {
            cmd,
            ..M_Command::default()
        }
    }
}

// Execute a command with the HSM module and wait for the response. Optionally
// include a certificate list for the supplied world signer, so that the request
// inherits permissions associated to the world signers key. (like ACL entries).
fn transact(cmd: &mut M_Command, signer: Option<M_KeyHash>) -> Result<Reply, SeeError> {
    let mut cert = M_Certificate::default();
    let mut certs = M_CertificateList {
        n_certs: 0,
        certs: &mut cert,
    };
    if let Some(hash) = signer {
        cert.keyhash = hash;
        cert.type_ = CertType_SEECert;
        certs.n_certs = 1;
        cmd.certs = &mut certs;
        cmd.flags |= Command_flags_certs_present;
    }
    let mut reply = M_Reply::default();
    let rc = unsafe { SEElib_Transact(cmd, &mut reply) };
    if rc != 0 {
        return Err(SeeError::Api(rc as M_Status));
    }
    if reply.status != Status_OK {
        return Err(SeeError::Transact(reply.status));
    }
    // We don't call SEElib_FreeCommand() because we're using rust's memory
    // management for building the M_Commands. But as the replies are built by
    // the Entrust code, we do need to ensure that SEElib_FreeReply does get
    // called on those. The reply wrapper used here will call FreeReply when
    // dropped.
    Ok(Reply { inner: reply })
}

#[derive(Debug)]
enum SeeError {
    // A C API call returned an error.
    Api(M_Status),
    // A Command was transacted and returned an error.
    Transact(M_Status),
}

impl SeeError {
    fn status(&self) -> M_Status {
        match self {
            SeeError::Api(status) => *status,
            SeeError::Transact(status) => *status,
        }
    }
}

struct Reply {
    inner: M_Reply,
}

impl Drop for Reply {
    fn drop(&mut self) {
        unsafe {
            SEElib_FreeReply(&mut self.inner);
        }
    }
}

impl Deref for Reply {
    type Target = M_Reply;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
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
        assert_eq!(Nanos::ZERO, s - s)
    }

    #[test]
    fn elapsed() {
        let s = TimeSpec {
            sec: i32::MAX,
            nsec: 10_000,
        };
        let e = TimeSpec {
            sec: i32::MAX,
            nsec: 100_000,
        };
        assert_eq!(Nanos(100_000 - 10_000), e - s);

        let s = TimeSpec {
            sec: 4,
            nsec: 10_000,
        };
        let e = TimeSpec {
            sec: 6,
            nsec: 100_000,
        };
        assert_eq!(Nanos(2_000_090_000), e - s);
    }

    #[test]
    fn elapsed_nsec_rollover() {
        let s = TimeSpec {
            sec: 10,
            nsec: 900_000_000,
        };
        let e = TimeSpec { sec: 11, nsec: 50 };
        assert_eq!(Nanos(100_000_050), e - s);
    }

    #[test]
    fn end_lt_start() {
        let s = TimeSpec { sec: 5, nsec: 5000 };
        let e = TimeSpec { sec: 5, nsec: 4999 };
        assert_eq!(Nanos::ZERO, e - s);

        let s = TimeSpec { sec: 5, nsec: 5000 };
        let e = TimeSpec { sec: 4, nsec: 9000 };
        assert_eq!(Nanos::ZERO, e - s);
    }

    #[test]
    fn saturates() {
        let s = TimeSpec { sec: 5, nsec: 0 };
        let e = TimeSpec { sec: 1000, nsec: 0 };
        assert_eq!(Nanos::MAX, e - s);

        let e = TimeSpec {
            sec: i32::MAX,
            nsec: 999_999_999,
        };
        assert_eq!(Nanos::MAX, e - s);
    }
}
