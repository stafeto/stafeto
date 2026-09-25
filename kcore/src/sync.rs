// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lock for shared kernel data (spec 8.1). One CPU and interrupts
//! masked inside the kernel mean it is never contended; taking it twice is
//! a bug and panics. Multi-core support changes only the inside of this type.
//! Data that is set once and then only read needs no lock: `SetOnce`.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

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

const EMPTY: u8 = 0;
const SETTING: u8 = 1;
const READY: u8 = 2;

/// A value set once and read ever after, such as what the boot learns: it
/// lives in static data, because the kernel stack starts over on every
/// entry from EL0 (spec 8.1). A second `set` fails and hands its value back.
pub struct SetOnce<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the value is written once, before READY is published, and after
// that only read: sharing hands out `&T` (T: Sync), and the value may come
// from another thread than the readers' (T: Send).
unsafe impl<T: Send + Sync> Sync for SetOnce<T> {}

impl<T> SetOnce<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Stores `value` and returns a reference to it; gives `value` back
    /// when a value is already set or being set.
    pub fn set(&self, value: T) -> Result<&T, T> {
        if self
            .state
            .compare_exchange(EMPTY, SETTING, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(value);
        }
        // SAFETY: the exchange made this call the only writer, and readers
        // wait for READY.
        let stored = unsafe { (*self.value.get()).write(value) };
        self.state.store(READY, Ordering::Release);
        Ok(stored)
    }

    pub fn get(&self) -> Option<&T> {
        // SAFETY: READY is published only after the value is written, and
        // nothing writes it again.
        (self.state.load(Ordering::Acquire) == READY)
            .then(|| unsafe { (*self.value.get()).assume_init_ref() })
    }
}

impl<T> Default for SetOnce<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for SetOnce<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == READY {
            // SAFETY: READY means the value was written, and it drops once.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
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

    #[test]
    fn set_once_is_empty_until_set() {
        let once: SetOnce<u32> = SetOnce::new();
        assert_eq!(once.get(), None);
        assert_eq!(once.set(5), Ok(&5));
        assert_eq!(once.get(), Some(&5));
    }

    #[test]
    fn second_set_hands_its_value_back() {
        let once = SetOnce::new();
        assert!(once.set(1).is_ok());
        assert_eq!(once.set(2), Err(2));
        assert_eq!(once.get(), Some(&1));
    }

    #[test]
    fn set_once_drops_its_value() {
        let value = std::rc::Rc::new(());
        {
            let once = SetOnce::new();
            assert!(once.set(value.clone()).is_ok());
            assert_eq!(std::rc::Rc::strong_count(&value), 2);
        }
        assert_eq!(std::rc::Rc::strong_count(&value), 1);
    }
}
