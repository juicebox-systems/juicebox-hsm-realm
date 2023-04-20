use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures::{future::join_all, Future};

pub type FutureTask<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Clone, Default)]
pub struct FutureTasks<T>(Arc<Mutex<Vec<FutureTask<T>>>>);

impl<T> FutureTasks<T> {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    pub fn add(&mut self, task: FutureTask<T>) {
        self.0.lock().unwrap().push(task);
    }

    pub fn take(&mut self) -> Vec<FutureTask<T>> {
        self.0.lock().unwrap().split_off(0)
    }

    pub async fn join_all(&mut self) -> Vec<T> {
        let tasks = self.take();
        join_all(tasks).await
    }
}
