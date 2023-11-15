use clap::{self, Subcommand, ValueEnum};

use crate::{join_path, join_paths, Context, Error, Paths, Process, Sha256Sum};

/// Load vendor-supplied software and artifacts.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Mount, unpack, and install components from the boot DVD.
    Install {
        /// Directory containing zipped ISO images. This is only used if the
        /// images aren't loopback-mounted already.
        #[arg(
            long,
            value_name = "DIR",
            alias = "zip-dir",
            default_value_t = Paths::get().vendor_iso_zip_dir.clone(),
        )]
        zips_dir: String,

        #[arg(required(true))]
        components: Vec<Component>,
    },

    /// Mount the vendor's zipped ISO images on the filesystem.
    Mount {
        /// Directory containing zipped ISO images.
        #[arg(
            long,
            value_name = "DIR",
            alias = "zip-dir",
            default_value_t = Paths::get().vendor_iso_zip_dir.clone(),
        )]
        zips_dir: String,

        #[arg(required(true))]
        discs: Vec<Disc>,
    },

    /// Unmount the vendor's zipped ISO images.
    #[clap(alias = "umount")]
    Unmount {
        #[arg(required(true))]
        discs: Vec<Disc>,
    },
}

/// A thing that can be installed.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Component {
    /// Headers and libraries used to build code to run on HSMs.
    #[clap(alias = "code-safe")]
    Codesafe,

    /// Drivers, daemons, and programs to access HSMs.
    #[clap(name = "secworld", alias = "sec-world")]
    SecWorld,
}

/// A vendor provided `.iso.zip` disc archive.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Disc {
    /// Headers and libraries used to build code to run on HSMs.
    #[clap(alias = "code-safe")]
    Codesafe,

    /// Low-level vendor-signed firmware for HSMs.
    Firmware,

    /// Drivers, daemons, and programs to access HSMs.
    #[clap(name = "secworld", alias = "sec-world")]
    SecWorld,
}

impl Disc {
    fn long_name(&self) -> &'static str {
        match self {
            Self::Codesafe => "Codesafe_Lin64-13.4.3",
            Self::Firmware => "nShield_HSM_Firmware-13.4.4",
            Self::SecWorld => "SecWorld_Lin64-13.4.4",
        }
    }

    fn iso_name(&self) -> String {
        format!("{}.iso", self.long_name())
    }

    fn iso_path(&self, context: &Context) -> String {
        join_path(&context.paths.vendor_iso_dir, &self.iso_name())
    }

    pub(crate) fn iso_zip_name(&self) -> &'static str {
        match self {
            Self::Codesafe => "CODESAFE.ZIP",
            Self::Firmware => "FIRMWARE.ZIP",
            Self::SecWorld => "SECWORLD.ZIP",
        }
    }

    pub(crate) fn iso_zip_hash(&self) -> Sha256Sum {
        Sha256Sum::from_hex(match self {
            Self::Codesafe => "7d6eaff0548d90143d35834f1ea1cf092321e9003e10e14895a01a6f412adadb",
            Self::Firmware => "035dd8b9841d965c8f048c357ab25e1bf7c11afaa5d616482f1b2a1f8590fdc8",
            Self::SecWorld => "d05e958b19b26ac4b984cc8e5950c8baa1cd72f1efb7ede2141317b130cb89e7",
        })
        .unwrap()
    }

    fn mount_path(&self, context: &Context) -> String {
        self.mount_path_with_parent(&context.paths.vendor_iso_mount_parent)
    }

    pub(crate) fn mount_path_with_parent(&self, run_dir: &str) -> String {
        join_path(run_dir, self.long_name())
    }
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::Install {
            zips_dir,
            components,
        } => {
            for component in components {
                install(*component, zips_dir, context)?;
            }
            Ok(())
        }

        Command::Mount { zips_dir, discs } => {
            for disc in discs {
                let mount_path = disc.mount_path(context);
                if context.is_mounted(&mount_path)? && !context.common_args.dry_run {
                    println!("Disc was already mounted at {mount_path:?}");
                } else {
                    mount(*disc, zips_dir, context)?;
                }
            }
            Ok(())
        }

        Command::Unmount { discs } => {
            for disc in discs {
                let mount_path = disc.mount_path(context);
                if context.is_mounted(&mount_path)? || context.common_args.dry_run {
                    unmount(*disc, context)?;
                } else {
                    println!("Disc was not mounted at {:?}", disc.mount_path(context));
                }
            }
            Ok(())
        }
    }
}

fn install(component: Component, zips_dir: &str, context: &Context) -> Result<(), Error> {
    let disc = match component {
        Component::Codesafe => Disc::Codesafe,
        Component::SecWorld => Disc::SecWorld,
    };

    let mount_path = disc.mount_path(context);
    let already_mounted = context.is_mounted(&mount_path)? && !context.common_args.dry_run;

    if already_mounted {
        println!("Disc was already mounted at {mount_path:?}");
    } else {
        mount(disc, zips_dir, context)?;
    }

    match component {
        Component::Codesafe => {
            untar_into_root(&join_path(&mount_path, "linux/amd64/csd.tar.gz"), context)?;
        }

        Component::SecWorld => {
            for file in ["ctd", "ctls", "hwsp"] {
                untar_into_root(
                    &join_paths(&[&mount_path, "linux/amd64", &format!("{file}.tar.gz")]),
                    context,
                )?;
            }

            let driver_dir = join_path(&context.paths.nfast_dir, "driver");
            context.exec(Process::new("./configure", &[]).dir(&driver_dir))?;
            context.exec(Process::new("make", &["install"]).dir(&driver_dir))?;

            context.exec(Process::new("/opt/nfast/sbin/install", &[]))?;
        }
    }

    if !already_mounted {
        unmount(disc, context)?;
    }

    Ok(())
}

fn untar_into_root(tar_file: &str, context: &Context) -> Result<(), Error> {
    context.exec(Process::new("tar", &["-xf", tar_file]).dir("/"))
}

fn mount(disc: Disc, zips_dir: &str, context: &Context) -> Result<(), Error> {
    context.exec(
        Process::new(
            "unzip",
            &[
                "-o",
                context.check_file_digest(
                    &join_path(zips_dir, disc.iso_zip_name()),
                    &disc.iso_zip_hash(),
                )?,
                disc.iso_name().as_str(),
            ],
        )
        .dir(&context.paths.vendor_iso_dir),
    )?;

    context.mount_readonly(&disc.iso_path(context), &disc.mount_path(context))
}

fn unmount(disc: Disc, context: &Context) -> Result<(), Error> {
    context.unmount(&disc.mount_path(context))?;
    context.remove_file(&disc.iso_path(context))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso_zip_hashes_well_formed() {
        Disc::Codesafe.iso_zip_hash();
        Disc::Firmware.iso_zip_hash();
        Disc::SecWorld.iso_zip_hash();
    }
}
