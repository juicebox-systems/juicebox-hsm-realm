use std::slice;

mod nfastapp;
pub use nfastapp::*;

impl M_ByteBlock {
    /// # Safety
    ///
    /// Assumes the M_ByteBlock correctly points to allocated memory.
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
