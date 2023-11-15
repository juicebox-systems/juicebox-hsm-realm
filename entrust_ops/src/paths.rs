//! Module to deal with filesystem paths.
//!
//! #### Note
//!
//! This program stores all paths as UTF-8 strings so they can be printed
//! conveniently (typically as `Debug` so special characters are escaped). The
//! `camino` crate would be nicer but probably isn't worth adding a dependency
//! here.

use std::env;
use std::sync::OnceLock;

use crate::commands::vendor::Disc as EntrustDisc;

/// Private global used to access the [`Paths`] singleton, even before `main`
/// runs.
///
/// This is normally accessed through [`crate::Context::paths`] or, if that's
/// not yet available, through [`Paths::get`].
static PATHS: OnceLock<Paths> = OnceLock::new();

/// Well-known filesystem paths.
///
/// A singleton value is normally accessed through [`crate::Context::paths`]
/// or, if that's not yet available, through [`Paths::get`].
#[derive(Debug)]
pub struct Paths {
    /// The path to the device representing the DVD burner: `/dev/sr0`.
    pub dvd_device: String,

    /// The path where the `entrust_init` program will be built or placed. This
    /// file may not exist yet.
    pub entrust_init: String,

    /// The path to the latest Solo XC firmware file, once the vendor's
    /// firmware `.iso.zip` is extracted and mounted.
    pub firmware_file: String,

    /// The path to the `juicebox-hsm-realm` source code directory.
    pub juicebox_hsm_realm_dir: String,

    /// The path to the directory where the realm DVD is mounted (the mountpoint).
    /// The directory may not exist yet.
    pub mount_dir: String,

    /// The path to the directory containing the vendor's installed files:
    /// `/opt/nfast`.
    pub nfast_dir: String,

    /// The path to the directory containing most of the vendor's executables:
    /// `/opt/nfast/bin`.
    pub nfast_bin: String,

    /// The path to the ISO file that is created when preparing to burn the
    /// realm DVD. This file may not exist yet.
    pub realm_iso: String,

    /// The path to the directory containing the signed archive files (SAR
    /// files), as well as the unsigned ELF and userdata input files. The
    /// directory and files may not exist yet.
    pub signing_dir: String,

    /// The path to the directory where the vendor's ISO files are extracted.
    pub vendor_iso_dir: String,

    /// The path to the directory containing the mountpoints for the vendor's
    /// ISO files. The directory may not exist yet.
    pub vendor_iso_mount_parent: String,

    /// The path to the directory containing the the vendor's `.iso.zip` files
    /// (with shortened filenames). This assumes the Windows partition is
    /// already mounted at `/run/win` containing these files.
    pub vendor_iso_zip_dir: String,

    /// The path to the directory containing key blobs and other files related
    /// to the current Security World: `/opt/nfast/kmdata/local`.
    pub world_dir: String,
}

impl Paths {
    /// Returns a handle to the [`Paths`] singleton.
    ///
    /// Callers should prefer [`crate::Context::paths`] where possible.
    pub fn get() -> &'static Self {
        PATHS.get_or_init(|| {
            let home = env::var("HOME").expect("failed to read $HOME");
            let juicebox_hsm_realm_dir = join_path(&home, "juicebox-hsm-realm");
            let nfast_dir = String::from("/opt/nfast");
            let vendor_iso_mount_parent = String::from("/run/ceremony");

            Self {
                dvd_device: String::from("/dev/sr0"),
                entrust_init: join_path(&juicebox_hsm_realm_dir, "target/release/entrust_init"),
                firmware_file: join_path(
                    &EntrustDisc::Firmware.mount_path_with_parent(&vendor_iso_mount_parent),
                    "firmware/SoloXC/latest/soloxc-13-3-1-vsn37.nff",
                ),
                juicebox_hsm_realm_dir: juicebox_hsm_realm_dir.clone(),
                mount_dir: String::from("/run/dvd"),
                nfast_bin: join_path(&nfast_dir, "bin"),
                nfast_dir: nfast_dir.clone(),
                realm_iso: join_path(&home, "realm.iso"),
                signing_dir: join_path(
                    &juicebox_hsm_realm_dir,
                    "target/powerpc-unknown-linux-gnu/release",
                ),
                vendor_iso_dir: home.clone(),
                vendor_iso_mount_parent,
                vendor_iso_zip_dir: String::from("/run/win/Users/defaultuser0"),
                world_dir: join_path(&nfast_dir, "kmdata/local"),
            }
        })
    }
}

/// Returns two filesystem path components combined together.
///
/// `child` must be a relative path.
pub fn join_path(parent: &str, child: &str) -> String {
    join_paths(&[parent, child])
}

/// Returns multiple filesystem path components combined together.
///
/// Every component but the first must be a relative path.
pub fn join_paths(paths: &[&str]) -> String {
    let (first, rest) = paths.split_first().expect("need at least 1 path to join");
    let mut joined = std::path::PathBuf::from(first);
    for path in rest {
        let path = std::path::Path::new(path);
        assert!(!path.has_root(), "refuse to join to absolute paths");
        joined.push(path);
    }
    // The input was UTF-8 so the result should also be UTF-8.
    joined
        .into_os_string()
        .into_string()
        .expect("invalid UTF-8")
}
