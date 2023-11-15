//! Spawning child processes.

use std::process;
use std::time::SystemTime;

use crate::{Context, Error};

/// Describes a child process to be spawned.
///
/// The process can be spawned with [`Context::exec`] or [`Context::exec_ok`].
///
/// This is similar to but simplified compared to [`std::process::Command`].
#[derive(Debug)]
pub struct Process<'a> {
    /// The program to execute.
    program: &'a str,
    /// Its arguments, not including the program name.
    args: &'a [&'a str],
    /// If `Some`, a path to an existing directory to use as the working
    /// directory for the program. If `None`, use the parent's working
    /// directory.
    dir: Option<&'a str>,
}

impl<'a> Process<'a> {
    /// Build a description of a new child process.
    pub fn new(program: &'a str, args: &'a [&str]) -> Self {
        Self {
            program,
            args,
            dir: None,
        }
    }

    /// Sets the child process's working directory. Otherwise, the parent's
    /// working directory is used.
    pub fn dir(mut self, dir: &'a str) -> Self {
        assert!(self.dir.is_none());
        self.dir = Some(dir);
        self
    }

    fn command(&self) -> process::Command {
        let mut command = process::Command::new(self.program);
        command.args(self.args);
        if let Some(dir) = self.dir {
            command.current_dir(dir);
        }
        command
    }
}

/// Child processes.
///
/// These respect dry runs.
impl Context {
    /// Runs the given command and waits for it to complete.
    ///
    /// Returns an error if the command does not exit with a 0 status.
    ///
    /// The child stdin, stdout, and stderr are inherited.
    ///
    /// For dry runs, the command is not executed.
    pub(crate) fn exec(&self, process: Process) -> Result<(), Error> {
        if self.common_args.dry_run {
            println!("Not running because --dry-run:");
        }
        println!("Spawning {:#?}", process);

        if !self.common_args.dry_run {
            let start = SystemTime::now();

            process
                .command()
                .status()
                .map_err(Error::from)
                .and_then(|status| {
                    if status.success() {
                        Ok(())
                    } else {
                        Err(Error::new("non-zero exit status (or signal)"))
                    }
                })
                .map_err(|err| Error::new(format!("failed to run {process:?}: {err}")))?;

            println!(
                "time elapsed: {:0.01} seconds",
                match start.elapsed() {
                    Ok(duration) => duration.as_secs_f32(),
                    Err(_) => f32::NAN,
                },
            );
        }

        Ok(())
    }

    /// Runs the given command and waits for it to complete.
    ///
    /// Returns true if the command exited with a 0 status, false if it exited
    /// with a non-zero status, or an error otherwise.
    ///
    /// The child stdin, stdout, and stderr are inherited.
    ///
    /// For dry runs, the command is not executed and `Ok(true)` is returned.
    pub(crate) fn exec_ok(&self, process: Process) -> Result<bool, Error> {
        if self.common_args.dry_run {
            println!("Not running because --dry-run:");
        }
        println!("Spawning {:#?}", process);

        if self.common_args.dry_run {
            Ok(true)
        } else {
            let status = process
                .command()
                .status()
                .map_err(|err| Error::new(format!("failed to run {process:?}: {err}")))?;
            Ok(status.success())
        }
    }
}
