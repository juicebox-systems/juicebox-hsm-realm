use anyhow::{anyhow, Context};
use std::{
    ffi::{c_int, c_void, CString},
    ptr::null_mut,
};

use entrust_nfast::{
    Act_NVMemOpPerms, Act_NVMemOpPerms_Details_perms_GetACL, Act_NVMemOpPerms_Details_perms_Read,
    Act_NVMemOpPerms_Details_perms_Write, CertType_SigningKey, Cmd_NVMemAlloc, Cmd_NVMemOp,
    Command_flags_certs_present, KeyMgmtEntType_CertDelgNVbNSO, M_Act_NVMemOpPerms_Details,
    M_Act__Details, M_Action, M_CertType_SigningKey_CertBody, M_CertType__CertBody, M_Certificate,
    M_CertificateList, M_Cmd_NVMemAlloc_Args, M_Command, M_FileID, M_FileInfo, M_Hash,
    M_KeyHashAndMech, M_KeyID, M_ModuleID, M_PermissionGroup, M_Word, Mech_Any,
    NFKM_LoadAdminKeysHandle, NFKM_WorldInfo, NFKM_cert_setdelg, NFKM_loadadminkeys_stealkey,
    NFastConn, NFastError, NVMemOpType_GetACL, PermissionGroup_flags_certmech_present, RQCard,
    RQCard_init, RQCard_logic_loadadmin, RQCard_ui_default, RQCard_whichmodule_anyone,
    Status_AlreadyExists, M_ACL, NFKM_KNV,
};

#[derive(clap::Args)]
pub struct NVRamArgs {
    /// The name of the file to create in NVRam. max length 11 characters.
    #[arg(long, default_value = "state")]
    name: String,

    /// The size (in bytes) of the file to create in NVRam.
    #[arg(long, default_value_t = 4096)]
    size: M_Word,
}

impl NVRamArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            return Err(anyhow!("NVRam file name can't be empty"));
        }
        if self.name.len() > 11 {
            return Err(anyhow!(
                "NVRam file name can't be longer than 11 characters"
            ));
        }
        if !self.name.is_ascii() {
            return Err(anyhow!("NVRam file name should be ASCII"));
        }
        if self.size == 0 {
            return Err(anyhow!("NVRam file size can't be zero"));
        }
        Ok(())
    }
}

pub fn command_nvram(
    conn: &mut NFastConn,
    module: M_ModuleID,
    world: *mut NFKM_WorldInfo,
    signing_key_hash: M_Hash,
    args: &NVRamArgs,
) -> anyhow::Result<()> {
    let admin_certs = unsafe {
        read_nvram_admin_delegation_key(conn, world, module)
            .context("Loading NVRAM admin key from admin cards")?
    };

    alloc_nvram(
        conn,
        module,
        admin_certs,
        signing_key_hash,
        &args.name,
        args.size,
    )
    .context("Allocating NVRAM file in HSM module")?;
    Ok(())
}

// Get the KNV delegation key from the ACS. This is needed to perform the alloc NVRAM operation.
//
// See get_admin_key in /opt/nfast/c/csd/examples/csee/utils/hostside/cardset.c
// and /opt/nfast/c/csd/examples/csee/tickets/hostside/hosttickets.c for entrust examples
// of similar operations.
unsafe fn read_nvram_admin_delegation_key(
    conn: &NFastConn,
    world: *mut NFKM_WorldInfo,
    module: M_ModuleID,
) -> Result<[M_Certificate; 2], NFastError> {
    // Setup RQCard so that it can prompt the user to insert the ACS cards if needed.
    let mut rqcard = RQCard::default();
    let rc = RQCard_init(&mut rqcard, conn.app, conn.conn, world, null_mut());
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }
    let rc = RQCard_ui_default(&mut rqcard);
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }

    let cstr_prompt = CString::new("Load admin cards to create NVRam file").unwrap();
    let tokens = [NFKM_KNV as i32, -1];
    let rc = RQCard_logic_loadadmin(&mut rqcard, tokens.as_ptr(), cstr_prompt.as_ptr());
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }

    let mut module = module;
    let mut lakh: NFKM_LoadAdminKeysHandle = null_mut();
    let lakh_ptr: *mut c_void = &mut lakh as *mut _ as *mut c_void;
    let rc = RQCard_whichmodule_anyone(&mut rqcard, &mut module, lakh_ptr);
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }

    // This runs the UI (which is a commandline UI) for getting the admin cards
    // loaded. When it returns 'lakh_ptr' was updated to the resulting handle.
    // We can then use that handle to get the actual key id and build the
    // certificate list.
    let rc = (*rqcard.uf).eventloop.unwrap()(&mut rqcard);
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }

    let mut key_id: M_KeyID = 0;
    let rc = NFKM_loadadminkeys_stealkey(lakh, NFKM_KNV as c_int, &mut key_id);
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }

    // We've read the NVRAM delegation key from the admin cards. Now we can
    // build a certificate list to attach that admin rights to the NVRAM
    // allocation call.
    let mut certs = [
        M_Certificate {
            keyhash: (*world).hknv,
            type_: CertType_SigningKey,
            body: M_CertType__CertBody {
                signingkey: M_CertType_SigningKey_CertBody { key: key_id },
            },
        },
        M_Certificate::default(),
    ];

    let rc = NFKM_cert_setdelg(
        conn.app,
        world,
        &mut certs[1],
        KeyMgmtEntType_CertDelgNVbNSO,
        null_mut(),
    );
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }
    Ok(certs)
}

#[allow(non_upper_case_globals)]
fn alloc_nvram(
    conn: &mut NFastConn,
    module: M_ModuleID,
    mut admin_certs: [M_Certificate; 2],
    signing_key_hash: M_Hash,
    name: &str,
    size: M_Word,
) -> anyhow::Result<()> {
    // Build the ACL we want to put on the NVRAM file.

    // Anyone can read the ACL.
    let mut actions_any = [M_Action {
        type_: Act_NVMemOpPerms,
        details: M_Act__Details {
            nvmemopperms: M_Act_NVMemOpPerms_Details {
                perms: Act_NVMemOpPerms_Details_perms_GetACL,
                subrange: null_mut(),
                exactrange: null_mut(),
                incdeclimit: null_mut(),
            },
        },
    }];

    // the SEE machine can read/write/getACL
    // Note that no one has rights to delete the file or edit the ACL.
    let mut actions_see = [M_Action {
        type_: Act_NVMemOpPerms,
        details: M_Act__Details {
            nvmemopperms: M_Act_NVMemOpPerms_Details {
                perms: Act_NVMemOpPerms_Details_perms_Read
                    | Act_NVMemOpPerms_Details_perms_Write
                    | Act_NVMemOpPerms_Details_perms_GetACL,
                subrange: null_mut(),
                exactrange: null_mut(),
                incdeclimit: null_mut(),
            },
        },
    }];
    let mut see_cert = M_KeyHashAndMech {
        hash: signing_key_hash,
        mech: Mech_Any,
    };

    let mut perms = [
        M_PermissionGroup {
            flags: 0,
            n_limits: 0,
            limits: null_mut(),
            n_actions: actions_any.len() as c_int,
            actions: actions_any.as_mut_ptr(),
            certifier: null_mut(),
            certmech: null_mut(),
            moduleserial: null_mut(),
        },
        M_PermissionGroup {
            flags: PermissionGroup_flags_certmech_present,
            n_limits: 0,
            limits: null_mut(),
            n_actions: actions_see.len() as c_int,
            actions: actions_see.as_mut_ptr(),
            certifier: null_mut(),
            certmech: &mut see_cert,
            moduleserial: null_mut(),
        },
    ];

    let acl = M_ACL {
        n_groups: perms.len() as c_int,
        groups: perms.as_mut_ptr(),
    };

    let mut cmd = M_Command::new(Cmd_NVMemAlloc);
    cmd.args.nvmemalloc = M_Cmd_NVMemAlloc_Args {
        module,
        flags: 0,
        info: M_FileInfo {
            flags: 0,
            length: size,
            id: file_id(name),
        },
        acl,
    };
    let mut certs = M_CertificateList {
        n_certs: admin_certs.len() as c_int,
        certs: admin_certs.as_mut_ptr(),
    };
    cmd.certs = &mut certs;
    cmd.flags = Command_flags_certs_present;

    match unsafe { conn.transact(&mut cmd) } {
        Err(NFastError::Transact(Status_AlreadyExists)) => {
            print!("NVRam file '{name}' already exists");

            // get the ACL and show it
            let mut cmd = M_Command::new(Cmd_NVMemOp);
            cmd.args.nvmemop.module = module;
            cmd.args.nvmemop.name = file_id(name);
            cmd.args.nvmemop.op = NVMemOpType_GetACL;
            let rep =
                unsafe { conn.transact(&mut cmd) }.context("reading ACL on existing NVRam file")?;
            let acl = unsafe { rep.reply.nvmemop.res.getacl.acl };
            println!(" with {}", acl);
            Ok(())
        }
        Err(err) => Err(err).context("Trying to create NVRam file"),
        Ok(_) => {
            println!("created NVRam file with name '{name}', size {size} bytes and {acl}");
            Ok(())
        }
    }
}

fn file_id(n: &str) -> M_FileID {
    let mut id = M_FileID::default();
    let src = n.as_bytes();
    let len = src.len();
    unsafe { id.bytes[..len].copy_from_slice(src) };
    id
}
