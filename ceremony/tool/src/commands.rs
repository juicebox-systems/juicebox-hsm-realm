//! Things this tool can do.

use clap::{self, command, Subcommand};

pub mod bip39;
pub mod build;
pub mod computer;
pub mod feature;
pub mod firmware;
pub mod hsm;
pub mod meta;
pub mod realm;
pub mod realm_dvd;
pub mod sign;
pub mod smartcard;
pub mod vendor;

use super::{Context, Error};

/// A [`clap::Subcommand`] representing all the things this tool can do.
#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(subcommand)]
    Bip39(bip39::Command),

    Build(build::Args),

    #[command(subcommand)]
    Computer(computer::Command),

    #[command(subcommand)]
    Feature(feature::Command),

    #[command(subcommand)]
    Firmware(firmware::Command),

    #[command(subcommand)]
    Hsm(hsm::Command),

    #[command(subcommand)]
    Meta(meta::Command),

    #[command(subcommand)]
    Realm(realm::Command),

    #[command(subcommand)]
    RealmDvd(realm_dvd::Command),

    #[command(subcommand)]
    Sign(sign::Command),

    #[command(subcommand)]
    Smartcard(smartcard::Command),

    #[command(subcommand)]
    Vendor(vendor::Command),
}

/// Run the given command.
pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match &command {
        Command::Bip39(command) => bip39::run(command, context),
        Command::Build(args) => build::run(args, context),
        Command::Computer(command) => computer::run(command, context),
        Command::Feature(command) => feature::run(command, context),
        Command::Firmware(command) => firmware::run(command, context),
        Command::Hsm(command) => hsm::run(command, context),
        Command::Meta(command) => meta::run(command, context),
        Command::Realm(command) => realm::run(command, context),
        Command::RealmDvd(command) => realm_dvd::run(command, context),
        Command::Sign(command) => sign::run(command, context),
        Command::Smartcard(command) => smartcard::run(command, context),
        Command::Vendor(command) => vendor::run(command, context),
    }
}
