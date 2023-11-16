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
    /// The path where the `entrust_init` program will be built or placed. This
    /// file may not exist yet.
    pub entrust_init: String,

    /// The path to the directory containing the vendor's installed files:
    /// `/opt/nfast`.
    pub nfast_dir: String,

    /// The path to the directory containing most of the vendor's executables:
    /// `/opt/nfast/bin`.
    pub nfast_bin: String,

    /// The path to the directory containing the signed archive files (SAR
    /// files), as well as the unsigned ELF and userdata input files. The
    /// directory and files may not exist yet.
    pub signing_dir: String,

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
            let nfast_dir = String::from("/opt/nfast");

            let program_dir_std: std::path::PathBuf = env::current_exe()
                .expect("failed to get path of current executable")
                .parent()
                .expect("failed to get parent directory of current executable")
                .to_owned();
            let program_dir: &str = program_dir_std
                .to_str()
                .expect("current executable path contains invalid UTF-8");

            let entrust_init =
                env::var("ENTRUST_INIT").unwrap_or_else(|_| join_path(program_dir, "entrust_init"));

            let signing_dir = env::var("SIGNING_DIR").unwrap_or_else(|_| {
                let relative = |mode| {
                    program_dir_std
                        .parent()
                        .unwrap()
                        .join("powerpc-unknown-linux-gnu")
                        .join(mode)
                        .into_os_string()
                        .into_string()
                        .expect("current working directory is invalid UTF-8")
                };
                if std::path::Path::ends_with(&program_dir_std, "target/release") {
                    relative("release")
                } else if std::path::Path::ends_with(&program_dir_std, "target/debug") {
                    relative("debug")
                } else {
                    // This is not a very good default, but the user may not be
                    // doing anything needing a signing dir.
                    String::from("/could not determine/path to signing dir")
                }
            });

            Self {
                entrust_init,
                nfast_bin: join_path(&nfast_dir, "bin"),
                nfast_dir: nfast_dir.clone(),
                signing_dir,
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
