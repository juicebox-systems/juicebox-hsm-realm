use std::io;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[derive(Clone)]
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
        for mut child in children {
            if let Err(e) = child.kill() {
                warn!(?e, "failed to kill child process");
            }
        }
    }
}

pub struct ProcessKiller(Child);

impl ProcessKiller {
    pub fn kill(&mut self) -> io::Result<ExitStatus> {
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
