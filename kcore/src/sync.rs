// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lock for shared kernel data (spec 8.1). One CPU and interrupts
//! masked inside the kernel mean it is never contended; taking it twice is
//! a bug and panics. Multi-core support changes only the inside of this type.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct Lock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only through a guard, and the flag makes the
// guard exclusive.
unsafe impl<T: Send> Sync for Lock<T> {}

impl<T> Lock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> LockGuard<'_, T> {
        if self.locked.swap(true, Ordering::Acquire) {
            panic!("kernel lock re-entered");
        }
        LockGuard {
            lock: self,
            _not_auto: PhantomData,
        }
    }
}

/// Access to a locked value; dropping the guard unlocks. A shared guard
/// hands out `&T`, so the guard is `Sync` only when `T` is:
///
/// ```compile_fail,E0277
/// fn shared<T: Sync>() {}
/// shared::<kcore::sync::LockGuard<'static, core::cell::Cell<u8>>>();
/// ```
pub struct LockGuard<'a, T> {
    lock: &'a Lock<T>,
    /// Turns off the automatic `Send` and `Sync`: they would follow
    /// `&Lock<T>` and make the guard `Sync` for every `T: Send`.
    _not_auto: PhantomData<*mut T>,
}

// SAFETY: moving the guard moves exclusive access to the value, as moving a
// `&mut T` does.
unsafe impl<T: Send> Send for LockGuard<'_, T> {}

// SAFETY: through a shared guard other threads reach only `&T`.
unsafe impl<T: Sync> Sync for LockGuard<'_, T> {}

impl<T> Deref for LockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: this guard is the only one.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for LockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this guard is the only one.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for LockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_gives_access_and_keeps_changes() {
        let l = Lock::new(1);
        *l.lock() += 1;
        assert_eq!(*l.lock(), 2);
    }

    #[test]
    fn lock_is_free_again_after_the_guard_drops() {
        let l = Lock::new(0);
        {
            let _g = l.lock();
        }
        let _g = l.lock();
    }

    #[test]
    fn guard_is_send_and_sync_as_a_mut_reference_would_be() {
        fn send<T: Send>() {}
        fn sync<T: Sync>() {}
        send::<LockGuard<'static, u32>>();
        sync::<LockGuard<'static, u32>>();
        send::<LockGuard<'static, core::cell::Cell<u8>>>();
    }

    #[test]
    #[should_panic(expected = "kernel lock re-entered")]
    fn taking_the_lock_twice_panics() {
        let l = Lock::new(0);
        let _a = l.lock();
        let _b = l.lock();
    }
}
