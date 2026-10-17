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
#[cfg(any(not(target_os = "none"), feature = "atomic-locks"))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};

pub struct Lock<T> {
    #[cfg(any(not(target_os = "none"), feature = "atomic-locks"))]
    locked: AtomicBool,
    #[cfg(all(target_os = "none", not(feature = "atomic-locks")))]
    locked: UnsafeCell<bool>,
    value: UnsafeCell<T>,
}

// SAFETY: host locks use an atomic flag. The target_os=none kernel runs on
// one core with interrupts masked while it holds a lock; its flag also
// rejects a second guard in that serial execution.
unsafe impl<T: Send> Sync for Lock<T> {}

impl<T> Lock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            #[cfg(any(not(target_os = "none"), feature = "atomic-locks"))]
            locked: AtomicBool::new(false),
            #[cfg(all(target_os = "none", not(feature = "atomic-locks")))]
            locked: UnsafeCell::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> LockGuard<'_, T> {
        #[cfg(any(not(target_os = "none"), feature = "atomic-locks"))]
        let was_locked = self.locked.swap(true, Ordering::Acquire);
        #[cfg(all(target_os = "none", not(feature = "atomic-locks")))]
        let was_locked = unsafe {
            // SAFETY: the single core and masked interrupts serialize this
            // read and write, and no guard may be borrowed simultaneously.
            let flag = &mut *self.locked.get();
            let old = *flag;
            *flag = true;
            old
        };
        if was_locked {
            panic!("kernel lock re-entered");
        }
        LockGuard {
            lock: self,
            _not_auto: PhantomData,
        }
    }

    /// The value's address, for the one reader that may not wait for the
    /// lock: the kernel's panic, which reads what a holder it interrupted
    /// may have left half written, and never returns to that holder.
    pub fn as_ptr(&self) -> *const T {
        self.value.get()
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
        #[cfg(any(not(target_os = "none"), feature = "atomic-locks"))]
        self.lock.locked.store(false, Ordering::Release);
        #[cfg(all(target_os = "none", not(feature = "atomic-locks")))]
        unsafe {
            // SAFETY: this guard is the only one on the single core.
            *self.lock.locked.get() = false;
        }
    }
}

/// A ticket lock, without data: a CPU takes the next ticket and waits until
/// the lock serves it, so the CPUs go in the order they came and none waits
/// for more than the sections of the CPUs ahead of it. The wait on AArch64
/// is `sevl; wfe; ldaxrh`: the holder's `stlrh` to the served number clears
/// the waiter's exclusive monitor, which wakes it (Arm ARM B2.9.2). The
/// holder masks interrupts (spec 8.1), so no section is preempted.
pub struct Ticket {
    next: AtomicU16,
    serving: AtomicU16,
}

impl Ticket {
    pub const fn new() -> Self {
        Self {
            next: AtomicU16::new(0),
            serving: AtomicU16::new(0),
        }
    }

    /// Waits for the lock and returns the ticket that `unlock` takes back.
    #[inline(always)]
    pub fn lock(&self) -> u16 {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        self.wait(ticket);
        ticket
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    #[inline(always)]
    fn wait(&self, ticket: u16) {
        // SAFETY: loads a halfword of the lock; `ldaxrh` acquires it, and the
        // monitor it arms lets the `stlrh` of `unlock` wake the `wfe`.
        unsafe {
            core::arch::asm!(
                // Served already: no wait, the common case.
                "ldaxrh {s:w}, [{p}]",
                "cmp {s:w}, {t:w}",
                "b.eq 3f",
                "sevl",
                "2:",
                "wfe",
                "ldaxrh {s:w}, [{p}]",
                "cmp {s:w}, {t:w}",
                "b.ne 2b",
                "3:",
                p = in(reg) self.serving.as_ptr(),
                t = in(reg) u32::from(ticket),
                s = out(reg) _,
                options(nostack),
            );
        }
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    #[inline(always)]
    fn wait(&self, ticket: u16) {
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
    }

    /// Serves the next ticket: the `stlrh` that wakes the waiters.
    #[inline(always)]
    pub fn unlock(&self, ticket: u16) {
        self.serving
            .store(ticket.wrapping_add(1), Ordering::Release);
    }

    /// Serves the next ticket for the holder, which has not kept its own:
    /// while the lock is held the number served is the holder's ticket.
    #[inline(always)]
    pub fn unlock_held(&self) {
        let ticket = self.serving.load(Ordering::Relaxed);
        self.serving
            .store(ticket.wrapping_add(1), Ordering::Release);
    }

    /// Whether no CPU holds or awaits the lock.
    pub fn is_free(&self) -> bool {
        self.next.load(Ordering::Relaxed) == self.serving.load(Ordering::Relaxed)
    }
}

impl Default for Ticket {
    fn default() -> Self {
        Self::new()
    }
}

const EMPTY: u8 = 0;
const SETTING: u8 = 1;
const READY: u8 = 2;

/// A count of things the whole system holds, bounded by a maximum that no
/// race may pass: `take` checks the bound and counts in one step, so two
/// cores that each see room for one more cannot both take it.
pub struct Budget(AtomicU32);

impl Budget {
    pub const fn new() -> Self {
        Budget(AtomicU32::new(0))
    }

    /// Counts one more unless `max` are counted already; false then.
    pub fn take(&self, max: u32) -> bool {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < max).then_some(n + 1)
            })
            .is_ok()
    }

    /// Gives back one that `take` counted.
    pub fn give(&self) {
        let before = self.0.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(before != 0, "a budget gave back more than it took");
    }

    /// The count now.
    pub fn count(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// Eight threads race for 1 000 places each; none is taken past the
    /// bound, and every place goes to exactly one thread.
    #[test]
    fn budget_never_passes_its_bound_under_a_race() {
        const MAX: u32 = 1_000;
        let budget = Budget::new();
        let won: u32 = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let mut won = 0;
                        for _ in 0..MAX {
                            if budget.take(MAX) {
                                won += 1;
                            }
                            std::thread::yield_now();
                        }
                        won
                    })
                })
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).sum()
        });
        assert_eq!(won, MAX);
        assert_eq!(budget.count(), MAX);
        assert!(!budget.take(MAX));
        budget.give();
        assert!(budget.take(MAX), "a place given back was not free again");
    }

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

    /// Eight threads add to a plain counter under the lock, across the wrap
    /// of the 16-bit ticket: no addition is lost.
    #[test]
    fn ticket_lock_excludes_across_the_wrap() {
        struct Shared(core::cell::UnsafeCell<u64>);
        // SAFETY: the test touches the cell only under the lock.
        unsafe impl Sync for Shared {}
        impl Shared {
            /// # Safety
            /// The lock is held.
            unsafe fn add(&self) {
                // SAFETY: the caller holds the lock.
                unsafe { *self.0.get() += 1 };
            }
        }
        let lock = Ticket::new();
        lock.next.store(u16::MAX - 100, Ordering::Relaxed);
        lock.serving.store(u16::MAX - 100, Ordering::Relaxed);
        let shared = Shared(core::cell::UnsafeCell::new(0));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..2_000 {
                        let t = lock.lock();
                        // SAFETY: the lock is held.
                        unsafe { shared.add() };
                        lock.unlock(t);
                    }
                });
            }
        });
        // SAFETY: the threads are done.
        assert_eq!(unsafe { *shared.0.get() }, 16_000);
        assert!(lock.is_free());
    }

    /// The lock serves tickets in the order they were taken.
    #[test]
    fn ticket_lock_serves_in_order() {
        let lock = Ticket::new();
        let first = lock.lock();
        let order = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            let (lock, order) = (&lock, &order);
            for id in 0..3u32 {
                scope.spawn(move || {
                    let t = lock.lock();
                    order.lock().unwrap().push(id);
                    lock.unlock(t);
                });
                // The next thread starts after this one took its ticket.
                while lock.next.load(Ordering::Relaxed) != 2 + id as u16 {
                    std::thread::yield_now();
                }
            }
            lock.unlock(first);
        });
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2]);
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
