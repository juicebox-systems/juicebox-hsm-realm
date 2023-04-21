use libc::pid_t;
use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::io;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Clone, Default)]
pub struct ProcessGroup(Arc<Mutex<Vec<ProcessKiller>>>);

impl ProcessGroup {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    pub fn spawn(&mut self, command: &mut Command) {
        match command.spawn() {
            Ok(child) => self.0.lock().unwrap().push(ProcessKiller(child)),
            Err(e) => panic!("failed to spawn command: {e}"),
        }
    }

    pub fn kill(&mut self) {
        let children = self.0.lock().unwrap().split_off(0);
        info!("waiting for {} child processes to exit", children.len());
        for mut child in children.into_iter().rev() {
            if let Err(e) = child.kill() {
                warn!(?e, "failed to kill child process");
            }
        }
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill();
    }
}

pub struct ProcessKiller(Child);

impl ProcessKiller {
    pub fn kill(&mut self) -> io::Result<ExitStatus> {
        match kill(Pid::from_raw(self.0.id() as pid_t), Signal::SIGTERM) {
            Ok(()) => {
                for _ in 0..1000 {
                    if let Some(status) = self.0.try_wait().transpose() {
                        return status;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Err(e) if e == Errno::ESRCH => {
                // this error seems to indicate success?
                return self.0.wait();
            }
            Err(e) => {
                warn!(?e, pid = self.0.id(), "sending SIGTERM failed");
            }
        }

        self.0.kill()?;
        self.0.wait()
    }
}

impl Drop for ProcessKiller {
    fn drop(&mut self) {
        // Err is deliberately ignored.
        if self.kill().is_err() {};
    }
}
