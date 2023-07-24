use alloc::{format, vec::Vec};
use core::{
    cmp::min,
    ops::{Deref, Sub},
    slice,
};
use juicebox_sdk_core::types::to_be4;

use super::seelib::{
    CertType_SEECert, Cmd_GenerateRandom, Cmd_GetWorldSigners, Cmd_NVMemOp,
    Command_flags_certs_present, M_ByteBlock, M_Certificate, M_CertificateList, M_Cmd, M_Command,
    M_FileID, M_KeyHash, M_NVMemOpType_Write_OpVal, M_Reply, M_Status, M_Word, NVMemOpType_Read,
    NVMemOpType_Write, SEElib_FreeReply, SEElib_Transact, Status_OK,
};
use entrust_api::WorldSignerError;
use hsm_api::rpc::Nanos;
use hsm_core::hal::{Clock, IOError, NVRam, MAX_NVRAM_SIZE};

/// NCipher implements the Platform trait, which provides platform specific
/// functionality to the hsmcore library.
#[derive(Clone)]
pub struct NCipher {
    // The hash of the key used to sign the SEEMachine/Userdata. We need this
    // when accessing resources that are restricted to the signing key. This
    // needs making into a Certificate to make the calls, but we can't keep it
    // as a certificate here because a certificate contains raw pointers, which
    // makes it problematic.
    pub world_signer: M_KeyHash,
    rng: BlockRng<NCipherRngFiller>,
}

impl NCipher {
    pub fn new() -> Result<NCipher, WorldSignerError> {
        let mut cmd = M_Command::new(Cmd_GetWorldSigners);
        let reply = transact(&mut cmd, None)
            .map_err(|e| WorldSignerError::FailedToLoad { status: e.status() })?;
        match unsafe { reply.reply.getworldsigners.n_sigs } {
            0 => Err(WorldSignerError::NoWorldSigner),
            1 => Ok(NCipher {
                world_signer: unsafe { (*reply.reply.getworldsigners.sigs).hash },
                rng: new_rng(),
            }),
            _ => Err(WorldSignerError::TooManyWorldSigners),
        }
    }
}

pub fn register_global_rng() {
    hsm_core::hash::set_global_rng_owned(new_rng());
}

fn new_rng() -> BlockRng<NCipherRngFiller> {
    // This doesn't use a full 8192 byte block in case the hsm side has the
    // same issue as the host API with larger responses where they go
    // exceptionally slow.
    BlockRng::new(8000, NCipherRngFiller)
}

struct BlockRng<F> {
    buf: Vec<u8>,
    size: usize,
    filler: F,
}

trait BlockRngFiller {
    fn fill(&mut self, buff: &mut Vec<u8>);
}

// Platform gets cloned on every request. We need to safely impl Clone but its
// exceedingly unlikely that the cloned platform actually calls the rng so we
// want clone to be cheap and only do the allocation/fill when it needs to.
impl<F: BlockRngFiller + Clone> Clone for BlockRng<F> {
    fn clone(&self) -> Self {
        Self::new(self.size, self.filler.clone())
    }
}

impl<F: BlockRngFiller> BlockRng<F> {
    fn new(block_size: usize, filler: F) -> Self {
        Self {
            buf: Vec::new(),
            size: block_size,
            filler,
        }
    }
}

impl<F: BlockRngFiller> rand_core::RngCore for BlockRng<F> {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap()
    }

    fn try_fill_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), rand_core::Error> {
        while !dest.is_empty() {
            if self.buf.is_empty() {
                self.buf.resize(self.size, 0);
                self.filler.fill(&mut self.buf);
            }
            let chunk = min(dest.len(), self.buf.len());
            dest[..chunk].copy_from_slice(self.buf.drain(self.buf.len() - chunk..).as_slice());
            dest = &mut dest[chunk..];
        }
        Ok(())
    }
}

#[derive(Clone)]
struct NCipherRngFiller;

impl BlockRngFiller for NCipherRngFiller {
    fn fill(&mut self, buff: &mut Vec<u8>) {
        let mut cmd = M_Command::new(Cmd_GenerateRandom);
        cmd.args.generaterandom.lenbytes = buff.len() as M_Word;
        let reply = transact(&mut cmd, None).unwrap();
        unsafe {
            assert_eq!(buff.len() as u32, reply.reply.generaterandom.data.len);
            buff.copy_from_slice(reply.reply.generaterandom.data.as_slice());
        }
    }
}

impl rand_core::CryptoRng for BlockRng<NCipherRngFiller> {}

impl rand_core::CryptoRng for NCipher {}

impl rand_core::RngCore for NCipher {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl M_ByteBlock {
    pub unsafe fn as_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.ptr, self.len as usize)
    }
    pub fn from_vec(v: &mut Vec<u8>) -> Self {
        M_ByteBlock {
            len: v.len() as M_Word,
            ptr: v.as_mut_ptr(),
        }
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
    bytes: *b"state\0\0\0\0\0\0",
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

        let reply = transact(&mut cmd, Some(self.world_signer))
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
        let len = usize::try_from(u32::from_be_bytes(
            data[NVRAM_LEN_OFFSET..NVRAM_LEN_OFFSET + 4]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        if len > MAX_NVRAM_SIZE {
            return Err(IOError(format!("indicated length of stored data was {len} which is larger than the allowed maximum of {MAX_NVRAM_SIZE}")));
        }

        data.truncate(len);
        Ok(data)
    }

    fn write(&self, mut data: Vec<u8>) -> Result<(), IOError> {
        if data.len() > MAX_NVRAM_SIZE {
            return Err(IOError(format!(
                "data with {} bytes is larger than allowed maximum of {MAX_NVRAM_SIZE}",
                data.len()
            )));
        }
        data.resize(NVRAM_LEN_OFFSET, 0);
        data.extend(&to_be4(data.len()));

        let mut cmd = M_Command::new(Cmd_NVMemOp);
        cmd.args.nvmemop.op = NVMemOpType_Write;
        cmd.args.nvmemop.name = NVRAM_FILENAME;
        cmd.args.nvmemop.val.write = M_NVMemOpType_Write_OpVal {
            data: M_ByteBlock {
                len: data.len() as M_Word,
                ptr: data.as_mut_ptr(),
            },
        };

        transact(&mut cmd, Some(self.world_signer))
            .map_err(|err| IOError(format!("NVMemOp write failed: {err:?}")))?;
        Ok(())
    }
}

impl M_Command {
    pub fn new(cmd: M_Cmd) -> Self {
        M_Command {
            cmd,
            ..M_Command::default()
        }
    }
}

// Execute a command with the HSM module and wait for the response. Optionally
// include a certificate list for the supplied world signer, so that the request
// inherits permissions associated to the world signers key. (like ACL entries).
pub fn transact(cmd: &mut M_Command, signer: Option<M_KeyHash>) -> Result<Reply, SeeError> {
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
pub enum SeeError {
    // A C API call returned an error.
    Api(M_Status),
    // A Command was transacted and returned an error.
    Transact(M_Status),
}

impl SeeError {
    pub fn status(&self) -> M_Status {
        match self {
            SeeError::Api(status) => *status,
            SeeError::Transact(status) => *status,
        }
    }
}

pub struct Reply {
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
mod tests {
    use rand_core::RngCore;

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

    #[derive(Clone)]
    struct TestFiller {
        fills: usize,
    }
    impl BlockRngFiller for TestFiller {
        fn fill(&mut self, buff: &mut Vec<u8>) {
            assert_eq!(16, buff.len());
            for (i, x) in buff.iter_mut().enumerate() {
                *x = u8::try_from(i + 1).unwrap();
            }
            self.fills += 1;
        }
    }

    #[test]
    fn block_rng() {
        let filler = TestFiller { fills: 0 };
        let mut rng = BlockRng::new(16, filler);
        // new should be cheap, the buffer should be an empty vec
        assert!(rng.buf.is_empty());
        assert_eq!(16, rng.size);
        // Getting some random data should cause the buffer to be created & filled.
        assert_ne!(0, rng.next_u32());
        assert_eq!(12, rng.buf.len());
        assert_eq!(1, rng.filler.fills);
        // Should be able to get more bytes than are in the buffer.
        let mut bytes: [u8; 69] = [0; 69];
        rng.fill_bytes(&mut bytes);
        assert!(bytes.iter().all(|v| *v != 0));
        assert_eq!(5, rng.filler.fills);
        assert!(rng.buf.len() < 8); // ensure next_u64 will need to refill the buffer
        assert_ne!(0, rng.next_u64());
        assert_eq!(6, rng.filler.fills);
    }

    #[test]
    fn block_rng_clone() {
        let filler = TestFiller { fills: 0 };
        let mut rng = BlockRng::new(16, filler);
        assert_ne!(0, rng.next_u32());
        let mut rng2 = rng.clone();
        assert!(rng2.buf.is_empty());
        assert_ne!(rng.next_u32(), rng2.next_u32());
        assert_eq!(rng.filler.fills + 1, rng2.filler.fills);
    }
}
