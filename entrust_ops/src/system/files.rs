//! File operations.

use std::fmt;
use std::fs::{self, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use super::Context;
use crate::Error;

/// Common file permissions.
///
/// ### Note
///
/// We don't really care about users and groups, since this program runs
/// as root.
#[repr(u32)]
#[derive(Clone, Copy)]
#[allow(unused, clippy::upper_case_acronyms)]
pub enum FileMode {
    /// Read-only (`0o444`).
    R = file_modes::R,
    /// Read and write (`0o666`).
    RW = file_modes::R | file_modes::W,
    /// Read, write, and execute (`0o777`).
    RWX = file_modes::R | file_modes::W | file_modes::X,
    /// Read and execute (`0o555`).
    RX = file_modes::R | file_modes::X,
}

impl fmt::Debug for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0o{:03o}", *self as u32)
    }
}

/// Defines low-level file permissions in octal that can be OR-ed together.
mod file_modes {
    pub const R: u32 = 0o444;
    pub const W: u32 = 0o222;
    pub const X: u32 = 0o111;
}

/// Like [`std::fs::DirEntry`] but assumes UTF-8 filenames and gets file
/// metadata. This simplifies error handling. See [`Context::list_dir`].
#[allow(unused)]
pub struct DirEntry {
    pub filename: String,
    pub metadata: Metadata,
}

/// File operations.
///
/// These respect dry runs and generally give better error messages than
/// [`std::fs`].
impl Context {
    /// Returns the given path if the file is readable, or an I/O error
    /// otherwise.
    ///
    /// For dry runs, always returns the given path.
    pub(crate) fn check_file_readable<'a>(&self, path: &'a str) -> Result<&'a str, Error> {
        if self.common_args.dry_run {
            println!("Not checking if {path:?} file is readable because --dry-run");
        } else {
            fs::File::open(path)
                .and_then(|file| -> Result<Option<u8>, io::Error> {
                    file.bytes().next().transpose()
                })
                .map_err(|err| Error::new(format!("failed to read {path:?} file: {err}")))?;
        }
        Ok(path)
    }

    /// Creates the directory `path` and any ancestors.
    ///
    /// It is not an error if `path` or its ancestors already exist.
    #[allow(unused)]
    pub(crate) fn create_dir_all(&self, path: &str) -> Result<(), Error> {
        if self.common_args.dry_run {
            println!("Not creating {path:?} dir and its parents because --dry-run");
            Ok(())
        } else {
            fs::create_dir_all(path).map_err(|err| {
                Error::new(format!(
                    "failed to create {path:?} dir or its parents: {err}"
                ))
            })
        }
    }

    /// Creates a file at `path` with the given `contents` and `mode`.
    ///
    /// The parent directory must already exist.
    pub(crate) fn create_file(
        &self,
        path: &str,
        contents: &[u8],
        mode: FileMode,
    ) -> Result<(), Error> {
        if self.common_args.dry_run {
            println!("Not creating {path:?} file with mode {mode:?} because --dry-run");
            Ok(())
        } else {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode as u32)
                .open(path)
                .map_err(|err| Error::new(format!("failed to create {path:?} file: {err}")))?;
            file.write_all(contents).map_err(|err| {
                Error::new(format!("failed to write contents to {path:?} file: {err}"))
            })
        }
    }

    /// Returns the entries within an existing directory, sorted by filename.
    ///
    /// Returns an error if any of the filenames contain invalid UTF-8.
    ///
    /// For dry runs, returns an empty result.
    #[allow(unused)]
    pub(crate) fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>, Error> {
        if self.common_args.dry_run {
            println!("Not listing {path:?} dir because --dry-run");
            return Ok(Vec::new());
        }

        let list_error =
            |err| Error::new(format!("failed to list contents of {path:?} dir: {err}"));

        let mut entries: Vec<DirEntry> = fs::read_dir(path)
            .map_err(list_error)?
            .map(|entry| -> Result<DirEntry, Error> {
                let entry: fs::DirEntry = entry.map_err(list_error)?;
                let filename = entry.file_name().into_string().map_err(|non_utf8| {
                    Error::new(format!(
                        "filename in {path:?} dir contains invalid UTF-8: {non_utf8:?}"
                    ))
                })?;
                let metadata = entry.metadata().map_err(|err| {
                    Error::new(format!(
                        "failed to get metadata for {filename:?} in {path:?} dir: {err}"
                    ))
                })?;
                Ok(DirEntry { filename, metadata })
            })
            .collect::<Result<_, _>>()?;

        entries.sort_by(|a, b| a.filename.cmp(&b.filename));
        Ok(entries)
    }

    /// Returns the contents of the given file.
    ///
    /// For dry runs, returns an empty result.
    pub(crate) fn read(&self, path: &str) -> Result<Vec<u8>, Error> {
        if self.common_args.dry_run {
            println!("Not reading {path:?} file because --dry-run");
            Ok(Vec::new())
        } else {
            fs::read(path).map_err(|err| Error::new(format!("failed to read {path:?} file: {err}")))
        }
    }

    /// Removes a directory, which must be empty.
    ///
    /// It is not an error if the directory or one of its ancestors does not
    /// exist.
    #[allow(unused)]
    pub(crate) fn remove_dir_only(&self, path: &str) -> Result<(), Error> {
        if self.common_args.dry_run {
            println!("Not removing {path:?} because --dry-run");
        } else {
            match fs::remove_dir(path) {
                Ok(()) => {
                    println!("Deleted {path:?} dir");
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    // nothing to do
                }
                Err(err) => {
                    return Err(Error::new(format!("failed to delete {path:?} dir: {err}")));
                }
            }
        }
        Ok(())
    }

    /// Removes a file.
    ///
    /// It is not an error if the file or one of its ancestors does not exist.
    pub(crate) fn remove_file(&self, path: &str) -> Result<(), Error> {
        if self.common_args.dry_run {
            println!("Not removing {path:?} because --dry-run");
        } else {
            match fs::remove_file(path) {
                Ok(()) => {
                    println!("Deleted {path:?} file");
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    // nothing to do
                }
                Err(err) => {
                    return Err(Error::new(format!("failed to delete {path:?} file: {err}")));
                }
            }
        }
        Ok(())
    }
}
