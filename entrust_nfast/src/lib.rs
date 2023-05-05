use std::{ops::Deref, ptr::null_mut, slice};

mod nfastapp;
pub use nfastapp::*;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct NFastConn {
    pub app: NFast_AppHandle,
    pub conn: NFastApp_Connection,
}

impl NFastConn {
    pub fn new() -> Self {
        Self {
            app: null_mut(),
            conn: null_mut(),
        }
    }

    pub unsafe fn connect(&mut self) -> Result<(), NFastError> {
        if self.app.is_null() {
            let rc = NFastApp_Init(&mut self.app, None, None, None, null_mut());
            let rc = rc as M_Status;
            if rc != Status_OK {
                return Err(NFastError::Api(rc));
            }
        }
        if self.conn.is_null() {
            let rc = NFastApp_Connect(self.app, &mut self.conn, 0, null_mut());
            let rc = rc as M_Status;
            if rc != Status_OK {
                return Err(NFastError::Api(rc));
            }
        }
        Ok(())
    }

    pub fn transact(&mut self, cmd: &mut M_Command) -> Result<Reply, NFastError> {
        self.transact_on_conn(self.conn, cmd)
    }

    pub fn transact_on_conn(
        &mut self,
        conn: NFastApp_Connection,
        cmd: &mut M_Command,
    ) -> Result<Reply, NFastError> {
        let mut rep = M_Reply::default();
        let rc = unsafe { NFastApp_Transact(conn, null_mut(), cmd, &mut rep, null_mut()) };
        let rc = rc as M_Status;
        if rc != Status_OK {
            warn!(cmd=?cmd.cmd, ?rc, "NFastApp_Transact returned error");
            return Err(NFastError::Api(rc));
        }
        if rep.cmd == Cmd_ErrorReturn {
            warn!(cmd=?cmd.cmd, ?rep, "NFastApp_Transact returned ErrorReturn");
            return Err(NFastError::Transact(rep.status));
        }
        Ok(Reply {
            app: self.app,
            inner: rep,
        })
    }
}

#[derive(Debug)]
pub enum NFastError {
    // An NFast API call returned an error.
    Api(M_Status),
    // A Transact returned an error.
    Transact(M_Status),
}

#[derive(Debug)]
pub struct Reply {
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
