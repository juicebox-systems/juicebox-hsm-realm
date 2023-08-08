use std::{
    borrow::Cow,
    ffi::{CStr, CString},
    fmt::Display,
    ops::Deref,
    ptr::null_mut,
    slice,
};
use thiserror::Error;
use tracing::{debug, warn};

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
            lookup_name(status, unsafe { &NF_Status_enumtable })
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

    pub fn from_vec(v: &mut Vec<u8>) -> M_ByteBlock {
        M_ByteBlock {
            len: v.len() as M_Word,
            ptr: v.as_mut_ptr(),
        }
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

// Look for a key in the security world.
pub fn find_key(
    conn: &NFastConn,
    app: &str,
    ident: &str,
) -> Result<Option<SecurityWorldKey>, NFastError> {
    let app_cstr = CString::new(app).unwrap();
    let ident_cstr = CString::new(ident).unwrap();
    let keyid = NFKM_KeyIdent {
        appname: app_cstr.as_ptr() as *mut i8,
        ident: ident_cstr.as_ptr() as *mut i8,
    };

    let mut key: *mut NFKM_Key = null_mut();
    let rc = unsafe { NFKM_findkey(conn.app, keyid, &mut key, null_mut()) };
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }
    if key.is_null() {
        debug!(?app, ?ident, "no key found");
        return Ok(None);
    }
    debug!(?app, ?ident, key_hash=%unsafe{(*key).hash}, "found key");
    Ok(Some(SecurityWorldKey {
        conn: conn.clone(),
        inner: key,
    }))
}

pub struct SecurityWorldKey {
    conn: NFastConn,
    inner: *mut NFKM_Key,
}
impl Drop for SecurityWorldKey {
    fn drop(&mut self) {
        unsafe { NFKM_freekey(self.conn.app, self.inner, null_mut()) };
    }
}
impl Deref for SecurityWorldKey {
    type Target = NFKM_Key;

    fn deref(&self) -> &Self::Target {
        unsafe { &(*self.inner) }
    }
}

pub fn lookup_name(val: u32, table: &[M_ValInfo]) -> Cow<'_, str> {
    lookup_name_no_default(val, table).unwrap_or_else(|| Cow::Owned(format!("[Unknown:{}]", val)))
}

pub fn lookup_name_no_default(val: u32, table: &[M_ValInfo]) -> Option<Cow<'_, str>> {
    let cstr = unsafe { NF_Lookup(val, table.as_ptr()) };
    if cstr.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(cstr) };
        Some(String::from_utf8_lossy(cstr.to_bytes()))
    }
}

pub fn flag_names(val: u32, max: u32, table: &[M_ValInfo]) -> Vec<Cow<'_, str>> {
    let mut m: u32 = 1;
    let mut res = Vec::new();
    while m <= max {
        if m & val != 0 {
            res.push(lookup_name(m, table));
        }
        m <<= 1;
    }
    res
}

#[allow(non_upper_case_globals)]
impl Display for M_ACL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "ACL containing {} Permission Group{}",
            self.n_groups,
            if self.n_groups != 1 { "s" } else { "" }
        )?;
        unsafe {
            for (idx, g) in slice::from_raw_parts(self.groups, self.n_groups as usize)
                .iter()
                .enumerate()
            {
                writeln!(f, "Permission Group {}:", idx + 1)?;
                if !g.certmech.is_null() {
                    writeln!(f, "\tRequires Cert: {}", *g.certmech)?;
                }
                if !g.certifier.is_null() {
                    writeln!(f, "\tRequires Certifier: {}", *g.certifier)?;
                }
                if !g.moduleserial.is_null() {
                    writeln!(f, "\tRequires Module ESN: {}", *g.moduleserial)?;
                }
                if g.flags != 0 {
                    writeln!(
                        f,
                        "\tFlags: {}",
                        m_permissiongroup_names(g.flags).join(", ")
                    )?;
                }
                for l in slice::from_raw_parts(g.limits, g.n_limits as usize) {
                    write!(f, "\tUse Limit: ")?;
                    match l.type_ {
                        UseLim_Global => writeln!(f, "Global: {}", l.details.global),
                        UseLim_AuthOld => writeln!(f, "AuthOld"),
                        UseLim_Time => writeln!(f, "Time {:?}", l.details.time),
                        UseLim_NonVolatile => {
                            writeln!(f, "NonVolatile {:?}", l.details.nonvolatile)
                        }
                        UseLim_Auth => writeln!(f, "Auth {:?}", l.details.auth),
                        x => writeln!(f, "Limit {x}"),
                    }?;
                }
                for a in slice::from_raw_parts(g.actions, g.n_actions as usize) {
                    write!(f, "\tAction: ")?;
                    match a.type_ {
                        Act_NoAction => writeln!(f, "NoAction"),
                        Act_OpPermissions => {
                            writeln!(f, "OpPermissions: {}", a.details.oppermissions)
                        }
                        Act_MakeBlob => writeln!(f, "MakeBlob: {}", a.details.makeblob),
                        Act_MakeArchiveBlob => {
                            writeln!(f, "MakeArchiveBlob {}", a.details.makearchiveblob)
                        }
                        Act_NSOPermissions => {
                            writeln!(f, "NSOPermissions {:?}", a.details.nsopermissions)
                        }
                        Act_DeriveKey => writeln!(f, "DeriveKey {:?}", a.details.derivekey),
                        Act_NVMemOpPerms => {
                            writeln!(f, "NVMemOpPerms {}", a.details.nvmemopperms)
                        }
                        Act_FeatureEnable => {
                            writeln!(f, "FeatureEnable {:?}", a.details.featureenable)
                        }
                        Act_NVMemUseLimit => {
                            writeln!(f, "NVMemUseLimit {:?}", a.details.nvmemuselimit)
                        }
                        Act_SendShare => writeln!(f, "SendShare {:?}", a.details.sendshare),
                        Act_ReadShare => writeln!(f, "ReadShare {:?}", a.details.readshare),
                        Act_StaticFeatureEnable => {
                            writeln!(f, "StaticFeatureEnable {:?}", a.details.staticfeatureenable)
                        }
                        Act_UserAction => writeln!(f, "UserAction {:?}", a.details.useraction),
                        Act_FileCopy => writeln!(f, "FileCopy {}", a.details.filecopy),
                        Act_DeriveKeyEx => writeln!(f, "DeriveKeyEx {:?}", a.details.derivekeyex),
                        Act_SendKey => writeln!(f, "SendKey {:?}", a.details.sendkey),
                        x => writeln!(f, "Act: {}", x),
                    }?;
                }
                f.write_str("\n")?;
            }
        }
        Ok(())
    }
}

pub fn m_permissiongroup_names(f: M_PermissionGroup_flags) -> Vec<Cow<'static, str>> {
    flag_names(f, PermissionGroup_flags__allflags, unsafe {
        &NF_PermissionGroup_flags_table
    })
}

impl Display for M_Act_OpPermissions_Details {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            &flag_names(
                self.perms,
                Act_OpPermissions_Details_perms__allflags,
                unsafe { &NF_Act_OpPermissions_Details_perms_table },
            )
            .join(", "),
        )
    }
}

impl Display for M_Act_MakeBlob_Details {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.flags != 0 {
            write!(
                f,
                "Flags: {}",
                flag_names(self.flags, Act_MakeBlob_Details_flags__allflags, unsafe {
                    &NF_Act_MakeBlob_Details_flags_table
                })
                .join(", ")
            )?;
        }
        if !self.kmhash.is_null() {
            write!(f, " kmhash: {}", unsafe { *self.kmhash })?;
        }
        if !self.kthash.is_null() {
            write!(f, " kthash: {}", unsafe { *self.kthash })?;
        }
        if !self.ktparams.is_null() {
            write!(f, "ktparams: {:?}", unsafe { *self.ktparams })?;
        }
        if !self.blobfile.is_null() {
            write!(f, " blobfile: {:?}", unsafe { *self.blobfile })?;
        }
        Ok(())
    }
}

impl Display for M_Act_MakeArchiveBlob_Details {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.flags != 0 {
            write!(
                f,
                "Flags: {}",
                flag_names(self.flags, Act_MakeBlob_Details_flags__allflags, unsafe {
                    &NF_Act_MakeArchiveBlob_Details_flags_table
                })
                .join(", ")
            )?;
        }
        write!(f, " mechanism: {}", m_mech_name(self.mech))?;
        if !self.kahash.is_null() {
            write!(f, " kahash: {}", unsafe { *self.kahash })?;
        }
        if !self.blobfile.is_null() {
            write!(f, " blobfile: {:?}", unsafe { *self.blobfile })?;
        }
        Ok(())
    }
}

impl Display for M_Act_NVMemOpPerms_Details {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "perms: {}",
            flag_names(
                self.perms,
                Act_NVMemOpPerms_Details_perms__allflags,
                unsafe { &NF_Act_NVMemOpPerms_Details_perms_table }
            )
            .join(", ")
        )?;
        if !self.subrange.is_null() {
            write!(f, " subrange: {}", unsafe { *self.subrange })?;
        }
        if !self.exactrange.is_null() {
            write!(f, " extract range: {}", unsafe { *self.exactrange })?;
        }
        if !self.incdeclimit.is_null() {
            write!(f, " inc/decl limit: {}", unsafe { *self.incdeclimit })?;
        }
        Ok(())
    }
}

impl Display for M_Act_FileCopy_Details {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.flags != 0 {
            write!(
                f,
                "flags: {} ",
                flag_names(self.flags, Act_FileCopy_Details_flags__allflags, unsafe {
                    &NF_Act_FileCopy_Details_flags_table
                })
                .join(", ")
            )?;
        }
        write!(
            f,
            "from: {} ",
            flag_names(self.from, FileDeviceFlags__allflags, unsafe {
                &NF_FileDeviceFlags_table
            })
            .join(", ")
        )?;
        write!(
            f,
            "to: {}",
            flag_names(self.to, FileDeviceFlags__allflags, unsafe {
                &NF_FileDeviceFlags_table
            })
            .join(", ")
        )
    }
}

impl Display for M_NVMemRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..={}", self.first, self.last)
    }
}

impl Display for M_UseLim_Global_Details {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "max: {} id: {}", self.max, self.id)
    }
}

impl Display for M_KeyHashAndMech {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "hash: {} mechanism: {}",
            self.hash,
            m_mech_name(self.mech)
        )
    }
}

pub fn m_mech_name(m: M_Mech) -> Cow<'static, str> {
    unsafe { lookup_name(m, &NF_Mech_enumtable) }
}

impl Display for M_Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enc = hex::encode(unsafe { &self.bytes });
        f.write_str(&enc)
    }
}

impl Display for M_ASCIIString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cstr = unsafe { CStr::from_ptr(self.ptr) };
        let str = String::from_utf8_lossy(cstr.to_bytes());
        write!(f, "{}", str)
    }
}
