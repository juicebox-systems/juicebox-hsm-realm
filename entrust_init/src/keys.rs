use anyhow::{anyhow, Context};
use std::ffi::{c_void, CString};
use std::fmt::Display;
use std::ptr::null_mut;

use entrust_nfast::{
    find_key, Act_OpPermissions_Details_perms_ExportAsPlain,
    Act_OpPermissions_Details_perms_ReduceACL, Cmd_GenerateKey, Cmd_GenerateKeyPair,
    Cmd_GenerateKeyPair_Args_flags_Certify, Cmd_GenerateKeyPair_Reply_flags_certpriv_present,
    Cmd_GenerateKey_Args_flags_Certify, Cmd_GenerateKey_Reply_flags_cert_present, Cmd_GetACL,
    KeyType_Random, KeyType_X25519Private, Key_flags_ProtectionCardSet, Key_flags_ProtectionModule,
    Key_flags_RecoveryDisabled, M_Cmd_GenerateKeyPair_Args, M_Cmd_GenerateKey_Args, M_Command,
    M_Hash, M_KeyGenParams, M_KeyID, M_KeyType_Random_GenParams, M_KeyType__GenParams,
    M_ModuleCert, M_ModuleID, NFKM_Key, NFKM_MakeACLParams, NFKM_MakeBlobsParams, NFKM_ModuleInfo,
    NFKM_NKF_PublicKey, NFKM_NKF_SEEAppKey, NFKM_WorldInfo, NFKM_cmd_loadblob,
    NFKM_newkey_makeaclx, NFKM_newkey_makeblobsx, NFKM_newkey_writecert, NFKM_recordkey,
    NFastApp_FreeACL, NFastConn, NFastError, NFast_AppHandle, RQCard, RQCard_init,
    RQCard_logic_ocs_specific, RQCard_ui_default, RQCard_whichmodule_anyone, M_ACL,
};

#[derive(clap::Args)]
pub struct KeyArgs {
    /// The name of the key to generate for calculating MACs.
    #[arg(long, value_name = "KEYNAME", default_value = "jbox-mac")]
    mac: String,

    /// The name of the key pair to generate for communication.
    #[arg(long, value_name = "KEYNAME", default_value = "jbox-noise")]
    noise: String,

    /// The name of the key to generate for encrypting/decrypting user records.
    #[arg(long, value_name = "KEYNAME", default_value = "jbox-record")]
    record: String,
}

impl KeyArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_key_name(&self.mac, "mac")?;
        self.validate_key_name(&self.noise, "noise")?;
        self.validate_key_name(&self.record, "record")
    }

    pub fn validate_key_name(&self, value: &str, arg_name: &str) -> anyhow::Result<()> {
        if value.is_empty() {
            return Err(anyhow!("key name for {arg_name} can't be empty"));
        }
        if !value.is_ascii() {
            return Err(anyhow!("key name for {arg_name} must be ascii"));
        }
        if value.contains('_') {
            return Err(anyhow!("key name for {arg_name} can't contain _"));
        }
        Ok(())
    }
}

pub fn command_keys(
    conn: NFastConn,
    module: M_ModuleID,
    world: *mut NFKM_WorldInfo,
    signing_key_hash: M_Hash,
    args: &KeyArgs,
) -> anyhow::Result<()> {
    let mut creator = KeyCreator::new(conn, module, world, signing_key_hash)?;

    creator.create_symmetric_key("simple", &args.mac, 64)?;
    creator.create_symmetric_key("simple", &args.record, 32)?;
    creator.create_x25519_keypair("simple", &args.noise)
}

struct KeyCreator {
    conn: NFastConn,
    world: *mut NFKM_WorldInfo,
    signing_key_hash: M_Hash,
    module_info: *mut NFKM_ModuleInfo,
    module: M_ModuleID,
}

impl KeyCreator {
    fn new(
        conn: NFastConn,
        module: M_ModuleID,
        world: *mut NFKM_WorldInfo,
        signing_key_hash: M_Hash,
    ) -> anyhow::Result<Self> {
        let mut module_info: *mut NFKM_ModuleInfo = null_mut();
        unsafe {
            for i in 0..(*world).n_modules as usize {
                let m = *(*world).modules.add(i);
                if (*m).module == module {
                    module_info = m;
                    break;
                }
            }
        }
        if module_info.is_null() {
            return Err(anyhow!(
                "module {module} does not appear to be in the security world"
            ));
        }
        Ok(KeyCreator {
            conn,
            world,
            signing_key_hash,
            module_info,
            module,
        })
    }

    // Creates a symmetrical key in the security world. Much of this code is
    // based on the code in the doc "Tutorial nShield nCore Developer
    // 12.80.pdf".
    //
    // Will not overwrite an existing key with the same app & ident.
    fn create_symmetric_key(
        &mut self,
        app: &str,
        ident: &str,
        size_bytes: usize,
    ) -> anyhow::Result<()> {
        // see if it already exists. The security world will let you overwrite
        // the existing keys, so we need to be careful to not do that.
        if self.check_exists(app, ident)? {
            return Ok(());
        }

        let acl = create_private_key_acl(&self.conn, self.world, self.signing_key_hash)?;
        let mut cmd = M_Command::new(Cmd_GenerateKey);
        cmd.args.generatekey = M_Cmd_GenerateKey_Args {
            flags: Cmd_GenerateKey_Args_flags_Certify,
            module: self.module,
            params: M_KeyGenParams {
                type_: KeyType_Random,
                params: M_KeyType__GenParams {
                    random: M_KeyType_Random_GenParams {
                        lenbytes: size_bytes.try_into().unwrap(),
                    },
                },
            },
            acl: acl.inner,
            appdata: null_mut(),
        };

        println!("Creating key {app},{ident} with {acl}");

        let reply = unsafe {
            self.conn
                .transact(&mut cmd)
                .context("Failed to generate key")?
        };

        let key_id = unsafe { reply.reply.generatekey.key };
        let key_gen_cert = unsafe {
            if reply.reply.generatekey.flags & Cmd_GenerateKey_Reply_flags_cert_present != 0 {
                reply.reply.generatekey.cert
            } else {
                null_mut()
            }
        };
        self.add_key_to_security_world(app, ident, key_id, None, key_gen_cert)
    }

    // Creates a x25519 key pair in the security world. Much of this code
    // is based on the code in the doc "Tutorial nShield nCore Developer
    // 12.80.pdf".
    //
    // Will not overwrite an existing key with the same app & ident.
    fn create_x25519_keypair(&mut self, app: &str, ident: &str) -> anyhow::Result<()> {
        // see if it already exists. The security world will let you overwrite
        // the existing keys, so we need to be careful to not do that.
        if self.check_exists(app, ident)? {
            return Ok(());
        }

        let priv_acl = create_private_key_acl(&self.conn, self.world, self.signing_key_hash)?;
        let pub_acl = create_public_key_acl(&self.conn, self.world)?;

        let mut cmd = M_Command::new(Cmd_GenerateKeyPair);
        cmd.args.generatekeypair = M_Cmd_GenerateKeyPair_Args {
            flags: Cmd_GenerateKeyPair_Args_flags_Certify,
            module: unsafe { (*self.module_info).module },
            params: M_KeyGenParams {
                type_: KeyType_X25519Private,
                params: M_KeyType__GenParams {
                    // Many of the key types re-use the random field in the params union.
                    random: M_KeyType_Random_GenParams { lenbytes: 32 },
                },
            },
            aclpriv: priv_acl.inner,
            aclpub: pub_acl.inner,
            appdatapriv: null_mut(),
            appdatapub: null_mut(),
        };

        println!("Creating key {app},{ident} with {priv_acl}");

        let reply = unsafe {
            self.conn
                .transact(&mut cmd)
                .context("Failed to generate key")?
        };

        let key_private = unsafe { reply.reply.generatekeypair.keypriv };
        let key_public = unsafe { reply.reply.generatekeypair.keypub };
        let key_gen_cert = unsafe {
            if reply.reply.generatekeypair.flags & Cmd_GenerateKeyPair_Reply_flags_certpriv_present
                != 0
            {
                reply.reply.generatekeypair.certpriv
            } else {
                null_mut()
            }
        };
        self.add_key_to_security_world(app, ident, key_private, Some(key_public), key_gen_cert)
    }

    // Adds a key or key pair that has already been created in a HSM Module to the security world.
    fn add_key_to_security_world(
        &self,
        app: &str,
        ident: &str,
        key_private: M_KeyID,
        key_public: Option<M_KeyID>,
        key_gen_cert: *mut M_ModuleCert,
    ) -> anyhow::Result<()> {
        let mut keyinfo = NFKM_Key::default();
        let appname = CString::new(app).unwrap();
        let ident = CString::new(ident).unwrap();

        keyinfo.flags = Key_flags_RecoveryDisabled | Key_flags_ProtectionModule;
        keyinfo.v = 8;
        keyinfo.appname = appname.as_ptr() as *mut i8;
        keyinfo.ident = ident.as_ptr() as *mut i8;
        keyinfo.gentime = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap();

        let make_blob_params = NFKM_MakeBlobsParams {
            f: keyinfo.flags,
            kpriv: key_private,
            kpub: key_public.unwrap_or_default(),
            ..NFKM_MakeBlobsParams::default()
        };
        unsafe {
            let rc = NFKM_newkey_makeblobsx(
                self.conn.app,
                self.conn.conn,
                self.world,
                &make_blob_params,
                &mut keyinfo,
                null_mut(),
            );
            if rc != 0 {
                return Err(NFastError::Api(rc))
                    .context("While making blobs to store key in the security world");
            }

            if !key_gen_cert.is_null() {
                let rc = NFKM_newkey_writecert(
                    self.conn.app,
                    self.conn.conn,
                    self.module_info,
                    make_blob_params.kpriv,
                    key_gen_cert,
                    &mut keyinfo,
                    null_mut(),
                );
                if rc != 0 {
                    return Err(NFastError::Api(rc)).context("While calling NFKM_newkey_writecert");
                }
            }

            // We've created the blobs and related items, we can save the key to the security world.
            let rc = NFKM_recordkey(self.conn.app, &mut keyinfo, null_mut());
            if rc != 0 {
                return Err(NFastError::Api(rc)).context("Recording key in the security world");
            }
        }
        Ok(())
    }

    // If the specified key already exists, it will print its acl and return true.
    fn check_exists(&mut self, app: &str, ident: &str) -> anyhow::Result<bool> {
        match load_private_key_blob(&mut self.conn, self.module, self.world, app, ident)
            .with_context(|| format!("Error while looking for key {app},{ident}"))?
        {
            None => Ok(false),
            Some(key_id) => {
                print!("Key {app},{ident} already exists");

                let mut cmd = M_Command::new(Cmd_GetACL);
                cmd.args.getacl.key = key_id;
                let rep = unsafe { self.conn.transact(&mut cmd) }
                    .context("Loading ACL of existing key")?;
                unsafe { println!(" with {}", rep.reply.getacl.acl) };
                Ok(true)
            }
        }
    }
}

// Creates an ACL suitable for a private key. Only code signed by the supplied
// signing key hash will be able to access the key data.
//
// See /opt/nfast/document/ncore/html/a00001.html for details on ACL
// construction.
fn create_private_key_acl(
    conn: &NFastConn,
    world: *mut NFKM_WorldInfo,
    signing_key_hash: M_Hash,
) -> anyhow::Result<Acl> {
    let params = NFKM_MakeACLParams {
        f: Key_flags_RecoveryDisabled | Key_flags_ProtectionModule | NFKM_NKF_SEEAppKey,
        op_base: Act_OpPermissions_Details_perms_ExportAsPlain,
        op_bic: Act_OpPermissions_Details_perms_ReduceACL,
        seeinteg: &signing_key_hash,
        ..NFKM_MakeACLParams::default()
    };
    let mut acl = M_ACL::default();
    let rc =
        unsafe { NFKM_newkey_makeaclx(conn.app, conn.conn, world, &params, &mut acl, null_mut()) };
    if rc != 0 {
        return Err(anyhow!(
            "NFKM_newkey_makeaclx failed with error: {}",
            NFastError::Api(rc)
        ));
    }
    // The generated ACL is fine other than the permissions for the admin which are way too permissive.
    // In our case we can just remove those all together.
    unsafe {
        // the admin group is the only one with a certifier set. Its always the last group
        assert!(!(*acl.groups.add(acl.n_groups as usize - 1))
            .certifier
            .is_null());
        acl.n_groups -= 1;
    }
    Ok(Acl {
        app: conn.app,
        inner: acl,
    })
}

// Creates an ACL suitable for a public key.
fn create_public_key_acl(conn: &NFastConn, world: *mut NFKM_WorldInfo) -> anyhow::Result<Acl> {
    let params = NFKM_MakeACLParams {
        f: Key_flags_RecoveryDisabled | Key_flags_ProtectionModule | NFKM_NKF_PublicKey,
        op_bic: Act_OpPermissions_Details_perms_ReduceACL,
        ..NFKM_MakeACLParams::default()
    };
    let mut acl = M_ACL::default();
    let rc =
        unsafe { NFKM_newkey_makeaclx(conn.app, conn.conn, world, &params, &mut acl, null_mut()) };
    if rc != 0 {
        return Err(anyhow!(
            "NFKM_newkey_makeaclx failed with error: {}",
            NFastError::Api(rc)
        ));
    }
    Ok(Acl {
        app: conn.app,
        inner: acl,
    })
}

struct Acl {
    app: NFast_AppHandle,
    inner: M_ACL,
}

impl Display for Acl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl Drop for Acl {
    fn drop(&mut self) {
        unsafe { NFastApp_FreeACL(self.app, null_mut(), null_mut(), &mut self.inner) };
    }
}

// Looks for the named key in the security world, loads the blob and returns its KeyID.
/// Will prompt the user to insert the OCS cards if the key is protected by an OCS.
pub fn load_private_key_blob(
    conn: &mut NFastConn,
    module: M_ModuleID,
    world: *mut NFKM_WorldInfo,
    app: &str,
    ident: &str,
) -> anyhow::Result<Option<M_KeyID>> {
    match find_key(conn, app, ident)
        .with_context(|| format!("find_key failed for {app},{ident}"))?
    {
        None => Ok(None),
        Some(key) => {
            let mut module = module;
            let mut ltid: M_KeyID = 0;
            if key.flags & Key_flags_ProtectionCardSet != 0 {
                (module, ltid) = get_ocs_ltid(conn, world, key.cardset)?;
            };

            let mut key_id: M_KeyID = 0;
            let whatfor = CString::new("private key").unwrap();
            let rc = unsafe {
                NFKM_cmd_loadblob(
                    conn.app,
                    conn.conn,
                    module,
                    &key.privblob,
                    ltid,
                    &mut key_id,
                    whatfor.as_ptr(),
                    null_mut(),
                )
            };
            if rc != 0 {
                return Err(anyhow!("NFKM_cmd_loadblob failed {}", NFastError::Api(rc)));
            }
            Ok(Some(key_id))
        }
    }
}

// Prompt the user to insert the OCS cardset so that we can load a key blob.
pub fn get_ocs_ltid(
    conn: &mut NFastConn,
    world: *mut NFKM_WorldInfo,
    cardset: M_Hash,
) -> Result<(M_ModuleID, M_KeyID), NFastError> {
    let mut rqcard = RQCard::default();
    unsafe {
        let rc = RQCard_init(&mut rqcard, conn.app, conn.conn, world, null_mut());
        if rc != 0 {
            return Err(NFastError::Api(rc));
        }
        let rc = RQCard_ui_default(&mut rqcard);
        if rc != 0 {
            return Err(NFastError::Api(rc));
        }
        let desc = CString::new("Load OCS to access key").unwrap();
        let rc = RQCard_logic_ocs_specific(&mut rqcard, &cardset, desc.as_ptr());
        if rc != 0 {
            return Err(NFastError::Api(rc));
        }
        let mut module_id: M_ModuleID = 1;
        let mut ltid: M_KeyID = 0;
        let ltid_ptr: *mut c_void = &mut ltid as *mut _ as *mut c_void;
        let rc = RQCard_whichmodule_anyone(&mut rqcard, &mut module_id, ltid_ptr);
        if rc != 0 {
            return Err(NFastError::Api(rc));
        }

        let rc = (*rqcard.uf).eventloop.unwrap()(&mut rqcard);
        if rc != 0 {
            return Err(NFastError::Api(rc));
        }
        Ok((module_id, ltid))
    }
}
