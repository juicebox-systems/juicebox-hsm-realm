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

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use std::sync::Mutex;

    use super::{MutationTracker, OnMutationFinished};

    #[test]
    fn on_finished() {
        struct F(Arc<Mutex<i64>>);
        impl OnMutationFinished<i64> for F {
            fn finished(&mut self, t: &i64) {
                *self.0.lock().unwrap() = *t;
            }
        }

        let cb = Arc::new(Mutex::new(0));
        let mut t = MutationTracker::new(1, F(cb.clone()));

        *t.mutate() = 44;
        assert_eq!(44, *cb.lock().unwrap());
        {
            // the callback shouldn't be called until the guard is dropped
            let mut g = t.mutate();
            assert_eq!(44, *cb.lock().unwrap());
            *g = 66;
            assert_eq!(44, *cb.lock().unwrap());
        }
        assert_eq!(66, *cb.lock().unwrap());
    }
}
