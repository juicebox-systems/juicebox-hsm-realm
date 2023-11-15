//! Filesystem mounting.

use super::{Context, Process};
use crate::Error;

/// Filesystem mounting.
///
/// These respect dry runs.
impl Context {
    /// Returns true if a filesystem is mounted on exactly the given path,
    /// false otherwise.
    ///
    /// For dry runs, this always returns true.
    pub(crate) fn is_mounted(&self, mount_path: &str) -> Result<bool, Error> {
        self.exec_ok(Process::new("findmnt", &["--mountpoint", mount_path]))
    }

    /// Mounts the filesystem at a device on the given path, in read-only mode.
    ///
    /// This creates the directory at `mount_path` and any ancestors if needed.
    pub(crate) fn mount_readonly(&self, device_path: &str, mount_path: &str) -> Result<(), Error> {
        if self.common_args.dry_run {
            println!("Not creating {mount_path:?} because --dry-run");
        } else {
            self.create_dir_all(mount_path)?;
        }

        self.exec(Process::new(
            "mount",
            &["-o", "ro", device_path, mount_path],
        ))
    }

    /// Unmounts the filesystem that's mounted at the given path.
    ///
    /// After unmounting, this removes the directory at `mount_path`, which
    /// must be empty.
    pub(crate) fn unmount(&self, mount_path: &str) -> Result<(), Error> {
        self.exec(Process::new("umount", &[mount_path]))?;
        self.remove_dir_only(mount_path)
    }
}
