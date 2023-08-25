use std::time::Duration;

use observability::logging;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::future_task::FutureTasks;

// Registers a termination handler. The returned FutureTasks instance can be used
// to add additional tasks needed to be run during shutdown.
pub fn install_termination_handler(shutdown_timeout: Duration) -> FutureTasks<()> {
    let mut shutdown_tasks = FutureTasks::<()>::new();
    let shutdown_tasks2 = shutdown_tasks.clone();

    tokio::spawn(async move {
        let mut sig_quit = signal(SignalKind::quit()).unwrap();
        let mut sig_term = signal(SignalKind::terminate()).unwrap();
        let mut sig_int = signal(SignalKind::interrupt()).unwrap();
        tokio::select! {
            _ = sig_quit.recv() => {},
            _ = sig_term.recv() => {},
            _ = sig_int.recv() => {}
        };

        info!(pid = std::process::id(), "received termination signal");
        if timeout(shutdown_timeout, shutdown_tasks.join_all())
            .await
            .is_err()
        {
            warn!("Timed out waiting for shutdown tasks to complete");
        }

        // There's an issue with the open telemetry tracer where if you
        // try and shut it down (which is what flush does) from a tokio
        // task, it will block forever. Shutting it down from a real thread
        // works fine. (or at least doesn't block forever)
        // https://github.com/open-telemetry/opentelemetry-rust/issues/868
        let flush_handle = std::thread::spawn(|| {
            debug!("about to flush/close trace provider");
            logging::flush();
            debug!("finished flushing/closing trace provider");
        });
        flush_handle.join().unwrap();

        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    });
    shutdown_tasks2
}
