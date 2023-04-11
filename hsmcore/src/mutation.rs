use core::ops::{Deref, DerefMut};

/// MutationTracker wraps a value and tracks mutations. When the mutation is
/// complete a callback is executed. This uses Guards that trigger the callback
/// when they're dropped, similar to have Mutex works.
pub struct MutationTracker<T> {
    value: T,
    dirty: bool,
}

impl<T> MutationTracker<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            dirty: false,
        }
    }
    pub fn mutate(&mut self) -> MutationGuard<'_, T> {
        MutationGuard { inner: self }
    }
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }
}

impl<T> Deref for MutationTracker<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

pub struct MutationGuard<'a, T> {
    inner: &'a mut MutationTracker<T>,
}

impl<'a, T> MutationGuard<'a, T> {
    // Generally deref_mut will do the right thing, but there are occasions
    // where it gets confused, and explicitly having the guard and then a
    // as_mut() from that will fix that.
    pub fn as_mut(&mut self) -> &mut T {
        &mut self.inner.value
    }
}

impl<'a, T> Deref for MutationGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.value
    }
}

impl<'a, T> DerefMut for MutationGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.value
    }
}

impl<'a, T> Drop for MutationGuard<'a, T> {
    fn drop(&mut self) {
        self.inner.dirty = true;
    }
}
