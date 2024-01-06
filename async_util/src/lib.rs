use pin_project::{pin_project, pinned_drop};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::task::{JoinError, JoinHandle};

/// Similar to a [`tokio::task::JoinHandle`] but aborts the task when dropped.
///
/// Like a [`JoinHandle`], this implements [`Future`], returning the async
/// result.
///
/// Compared to [`tokio::task::JoinSet`], this is a bit more convenient/obvious
/// for a single task.
#[derive(Debug)]
#[pin_project(PinnedDrop)]
pub struct ScopedTask<T>(#[pin] JoinHandle<T>);

impl<T> ScopedTask<T> {
    /// Wrapper around [`tokio::spawn`] that returns a [`ScopedTask`].
    #[track_caller]
    pub fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        Self(tokio::spawn(future))
    }

    pub fn new(handle: JoinHandle<T>) -> Self {
        Self(handle)
    }

    pub fn abort(&self) {
        self.0.abort();
    }

    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}

#[pinned_drop]
impl<T> PinnedDrop for ScopedTask<T> {
    fn drop(self: Pin<&mut Self>) {
        self.abort()
    }
}

impl<T> Future for ScopedTask<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().0.poll(cx)
    }
}
