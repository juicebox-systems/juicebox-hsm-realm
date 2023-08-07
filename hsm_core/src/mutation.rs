use core::ops::{Deref, DerefMut};

pub(crate) trait OnMutationFinished<T> {
    fn finished(&mut self, t: &T);
}

/// MutationTracker wraps a value and tracks mutations. When the mutation is
/// complete a callback is executed. This uses Guards that trigger the callback
/// when they're dropped, similar to how Mutex works.
pub(crate) struct MutationTracker<T, F: OnMutationFinished<T>> {
    value: T,
    on_finished: F,
}

impl<T, F: OnMutationFinished<T>> MutationTracker<T, F> {
    pub fn new(value: T, on_finished: F) -> Self {
        Self { value, on_finished }
    }
    pub fn mutate(&mut self) -> MutationGuard<'_, T, F> {
        MutationGuard { inner: self }
    }
}

impl<T, F: OnMutationFinished<T>> Deref for MutationTracker<T, F> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

pub(crate) struct MutationGuard<'a, T, F: OnMutationFinished<T>> {
    inner: &'a mut MutationTracker<T, F>,
}

impl<'a, T, F: OnMutationFinished<T>> Deref for MutationGuard<'a, T, F> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.value
    }
}

impl<'a, T, F: OnMutationFinished<T>> DerefMut for MutationGuard<'a, T, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.value
    }
}

impl<'a, T, F: OnMutationFinished<T>> Drop for MutationGuard<'a, T, F> {
    fn drop(&mut self) {
        self.inner.on_finished.finished(&self.inner.value);
    }
}
