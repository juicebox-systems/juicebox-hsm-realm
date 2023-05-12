use anyhow::{anyhow, Context};

use super::keys::load_private_key_blob;
use entrust_nfast::{Cmd_GetACL, M_Command, M_ModuleID, NFKM_WorldInfo, NFastConn};

pub fn validate_args(app: &str, ident: &str) -> anyhow::Result<()> {
    validate_arg(app, "app")?;
    validate_arg(ident, "ident")
}

fn validate_arg(value: &str, name: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        return Err(anyhow!("{name} can't be empty"));
    }
    if !value.is_ascii() {
        return Err(anyhow!("{name} must be ascii"));
    }
    Ok(())
}

pub fn command_acl(
    mut conn: NFastConn,
    module: M_ModuleID,
    world: *mut NFKM_WorldInfo,
    app: &str,
    ident: &str,
) -> anyhow::Result<()> {
    match load_private_key_blob(&mut conn, module, world, app, ident)? {
        None => println!("Key {app},{ident} doesn't exist."),
        Some(key_id) => {
            let mut cmd = M_Command::new(Cmd_GetACL);
            cmd.args.getacl.key = key_id;
            let rep = unsafe { conn.transact(&mut cmd) }.context("Loading ACL of existing key")?;
            unsafe { println!("key {app},{ident} exists with {}", rep.reply.getacl.acl) };
        }
    }
    Ok(())
}
