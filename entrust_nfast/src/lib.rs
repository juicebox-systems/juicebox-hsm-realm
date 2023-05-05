use std::{borrow::Cow, ffi::CStr, fmt::Display, ops::Deref, ptr::null_mut, slice};
use thiserror::Error;
use tracing::warn;

mod nfastapp;
pub use nfastapp::*;

#[derive(Clone, Debug)]
pub struct NFastConn {
    pub app: NFast_AppHandle,
    pub conn: NFastApp_Connection,
}

impl Default for NFastConn {
    fn default() -> Self {
        Self::new()
    }
}

impl NFastConn {
    pub fn new() -> Self {
        Self {
            app: null_mut(),
            conn: null_mut(),
        }
    }

    /// Initialize the NFast API and connect to the local hardserver. Does nothing if already connected.
    /// # Safety
    /// Is calling into the NFast C API, who known what happens in there.
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

    /// Transact the Cmd with NFast. Will connect to the hard server if not
    /// already connected.
    /// # Safety
    /// Is calling into the NFast C API, who known what happens in there.
    pub unsafe fn transact(&mut self, cmd: &mut M_Command) -> Result<Reply, NFastError> {
        self.connect()?;
        self.transact_on_conn(self.conn, cmd)
    }

    /// Transact the Cmd with NFast on the supplied connection. The connection
    /// must of been obtained from this NFastConn's app handle. connect() must
    /// of already been called.
    /// # Safety
    /// Is calling into the NFast C API, who known what happens in there.
    pub unsafe fn transact_on_conn(
        &mut self,
        conn: NFastApp_Connection,
        cmd: &mut M_Command,
    ) -> Result<Reply, NFastError> {
        assert!(!self.app.is_null());
        assert!(!conn.is_null());
        let mut rep = M_Reply::default();
        let rc = NFastApp_Transact(conn, null_mut(), cmd, &mut rep, null_mut());
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

#[derive(Debug, Error)]
pub enum NFastError {
    /// An NFast API call returned an error.
    Api(M_Status),
    /// A Transact returned an error.
    Transact(M_Status),
}

impl Display for NFastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn lookup<'a>(status: M_Status) -> Cow<'a, str> {
            enum_name(status, unsafe { &NF_Status_enumtable })
        }
        match self {
            Self::Api(status) => {
                write!(f, "Api Error {} ({})", lookup(*status), *status)
            }
            Self::Transact(status) => {
                write!(f, "Transact Error {} ({})", lookup(*status), *status)
            }
        }
    }
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

pub fn enum_name(val: u32, table: &[M_ValInfo]) -> Cow<'_, str> {
    let cstr = unsafe { NF_Lookup(val, table.as_ptr()) };
    if cstr.is_null() {
        Cow::Owned(format!("[Unknown:{}]", val))
    } else {
        let cstr = unsafe { CStr::from_ptr(cstr) };
        String::from_utf8_lossy(cstr.to_bytes())
    }
}
