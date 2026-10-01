// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer's temporary process-private mutex over waits by address
//! (posix-sync, spec 2, 3.4), until relibc's mutex replaces it (5a').
//! The word: 0 free, 1 held, 2 held with waiters; taking a free mutex and
//! giving one up without waiters make no call of the kernel. The owner's
//! pthread number serves the recursive and error-checking kinds. Waiters
//! wake by level, first come first among equals; a waiter whose level
//! changes while it waits keeps its place until inheritance comes (5h).

use crate::{constants::*, tls};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use posix_sync::{CLOCK_MONOTONIC, futex_wait, futex_wake};
use posix_time::Deadline;

const MAGIC: u64 = 0x5354_4d58_0000_0000;
const ATTR_MAGIC: u64 = 0x5354_4d41_5454_5231;
const FREE: u32 = 0;
const HELD: u32 = 1;
const CONTENDED: u32 = 2;

#[repr(C)]
pub struct Mutex {
    metadata: AtomicU64,
    owner: AtomicU64,
    count: AtomicU64,
    word: AtomicU32,
    reserved: u32,
}
impl Mutex {
    pub const fn new() -> Self {
        Self::with_kind(PTHREAD_MUTEX_DEFAULT)
    }
    const fn with_kind(kind: i32) -> Self {
        Self {
            metadata: AtomicU64::new(MAGIC | kind as u64),
            owner: AtomicU64::new(0),
            count: AtomicU64::new(0),
            word: AtomicU32::new(FREE),
            reserved: 0,
        }
    }
    fn kind(&self) -> Result<i32, i32> {
        let metadata = self.metadata.load(Ordering::Relaxed);
        let kind = (metadata & 0xffff_ffff) as i32;
        if metadata & 0xffff_ffff_0000_0000 != MAGIC || !valid_kind(kind) {
            return Err(EINVAL);
        }
        Ok(kind)
    }
    /// The word waiters wait on, for the probes.
    pub fn word(&self) -> &AtomicU32 {
        &self.word
    }
}
impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Attributes {
    magic: u64,
    kind: i32,
    reserved: u32,
}
impl Attributes {
    fn valid(&self) -> bool {
        self.magic == ATTR_MAGIC && self.reserved == 0 && valid_kind(self.kind)
    }
}
const _: () = {
    assert!(core::mem::size_of::<Mutex>() == 32);
    assert!(core::mem::align_of::<Mutex>() == 8);
    assert!(core::mem::size_of::<Attributes>() == 16);
    assert!(core::mem::align_of::<Attributes>() == 8);
};
fn valid_kind(kind: i32) -> bool {
    matches!(
        kind,
        PTHREAD_MUTEX_NORMAL
            | PTHREAD_MUTEX_ERRORCHECK
            | PTHREAD_MUTEX_RECURSIVE
            | PTHREAD_MUTEX_DEFAULT
    )
}
fn valid_address(address: u64) -> bool {
    address != 0 && address.is_multiple_of(core::mem::align_of::<Mutex>() as u64)
}

/// The monotonic instant of an absolute deadline on `deadline.clock`; for
/// CLOCK_REALTIME through the clock service now, rechecked after it passed.
pub(crate) fn monotonic_target(deadline: Deadline) -> Result<u64, i32> {
    let target = if deadline.clock == proto_clock::REALTIME {
        let (time, mono) = crate::clock::realtime_anchor()?;
        deadline.value() - time + i128::from(mono)
    } else {
        deadline.value()
    };
    Ok(target.clamp(0, i128::from(u64::MAX)) as u64)
}

/// Whether an absolute deadline passed on its own clock.
pub(crate) fn passed(deadline: Deadline) -> Result<bool, i32> {
    if deadline.clock == proto_clock::REALTIME {
        let (time, _) = crate::clock::realtime_anchor()?;
        return Ok(deadline.value() <= time);
    }
    Ok(deadline.value() <= i128::from(rt::time::ticks_to_ns(rt::time::now())))
}

/// Takes `mutex` for the calling thread: at once, or after waiting until
/// `deadline` (none: for good). `try_only` never waits.
unsafe fn acquire(
    mutex: *mut Mutex,
    try_only: bool,
    deadline: Option<(i32, posix_types::Timespec)>,
) -> i32 {
    if !valid_address(mutex as u64) {
        return EINVAL;
    }
    // SAFETY: the caller supplies a live initialized mutex.
    let mutex = unsafe { &*mutex };
    let kind = match mutex.kind() {
        Ok(kind) => kind,
        Err(error) => return error,
    };
    let me = tls::thread_id();
    if mutex
        .word
        .compare_exchange(FREE, HELD, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        mutex.owner.store(me, Ordering::Relaxed);
        mutex.count.store(1, Ordering::Relaxed);
        return 0;
    }
    if mutex.owner.load(Ordering::Relaxed) == me {
        match kind {
            PTHREAD_MUTEX_RECURSIVE => {
                let count = mutex.count.load(Ordering::Relaxed);
                if count == u64::from(u32::MAX) {
                    return EAGAIN;
                }
                mutex.count.store(count + 1, Ordering::Relaxed);
                return 0;
            }
            _ if try_only => return EBUSY,
            PTHREAD_MUTEX_ERRORCHECK => return EDEADLK,
            // A normal mutex taken twice by its owner waits for good.
            _ => {}
        }
    }
    if try_only {
        return EBUSY;
    }
    let deadline = match deadline {
        None => None,
        Some((clock, at)) => match Deadline::new(clock as u32, at.tv_sec, at.tv_nsec) {
            Ok(deadline) => Some(deadline),
            Err(_) => return EINVAL,
        },
    };
    let mut target = match deadline.map(monotonic_target).transpose() {
        Ok(target) => target,
        Err(error) => return error,
    };
    loop {
        if mutex.word.swap(CONTENDED, Ordering::Acquire) == FREE {
            mutex.owner.store(me, Ordering::Relaxed);
            mutex.count.store(1, Ordering::Relaxed);
            return 0;
        }
        match futex_wait(&mutex.word, CONTENDED, CLOCK_MONOTONIC, target) {
            Err(ETIMEDOUT) => {
                let deadline = deadline.expect("a timed wait");
                match passed(deadline) {
                    Ok(true) => return ETIMEDOUT,
                    // The calendar moved back: wait for its new instant.
                    Ok(false) => match monotonic_target(deadline) {
                        Ok(next) => target = Some(next),
                        Err(error) => return error,
                    },
                    Err(error) => return error,
                }
            }
            Err(error) if error != EAGAIN => return error,
            _ => {}
        }
    }
}

/// # Safety
/// mutex is writable and exclusively owned for initialization; attr is null or
/// points to an initialized attribute object. A live mutex must not be reinitialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(mutex: *mut Mutex, attr: *const Attributes) -> i32 {
    if !valid_address(mutex as u64) {
        return EINVAL;
    }
    let kind = if attr.is_null() {
        PTHREAD_MUTEX_DEFAULT
    } else {
        let attr = unsafe { &*attr };
        if !attr.valid() {
            return EINVAL;
        }
        attr.kind
    };
    unsafe { mutex.write(Mutex::with_kind(kind)) };
    0
}

/// # Safety
/// mutex points to a live initialized mutex, and remains valid through return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut Mutex) -> i32 {
    unsafe { acquire(mutex, false, None) }
}
/// # Safety
/// As for pthread_mutex_lock.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut Mutex) -> i32 {
    unsafe { acquire(mutex, true, None) }
}
/// # Safety
/// As for pthread_mutex_lock; deadline supplies one readable aligned Timespec.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_timedlock(
    mutex: *mut Mutex,
    deadline: *const posix_types::Timespec,
) -> i32 {
    unsafe { pthread_mutex_clocklock(mutex, crate::clock::CLOCK_REALTIME, deadline) }
}
/// # Safety
/// As for pthread_mutex_timedlock. A deadline on CLOCK_REALTIME becomes a
/// monotonic instant, checked again on the calendar once it passed. This
/// function is not a cancellation point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_clocklock(
    mutex: *mut Mutex,
    clock: i32,
    deadline: *const posix_types::Timespec,
) -> i32 {
    if !matches!(
        clock,
        crate::clock::CLOCK_REALTIME | crate::clock::CLOCK_MONOTONIC
    ) || deadline.is_null()
    {
        return EINVAL;
    }
    // SAFETY: the caller supplies one readable Timespec; invalid nanoseconds are
    // checked only when ownership cannot be acquired immediately.
    let deadline = unsafe { deadline.read() };
    unsafe { acquire(mutex, false, Some((clock, deadline))) }
}
/// # Safety
/// As for pthread_mutex_lock. The owner's Release publishes protected writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut Mutex) -> i32 {
    if !valid_address(mutex as u64) {
        return EINVAL;
    }
    let mutex = unsafe { &*mutex };
    if let Err(error) = mutex.kind() {
        return error;
    }
    if mutex.word.load(Ordering::Relaxed) == FREE
        || mutex.owner.load(Ordering::Relaxed) != tls::thread_id()
    {
        return EPERM;
    }
    let count = mutex.count.load(Ordering::Relaxed);
    if count > 1 {
        mutex.count.store(count - 1, Ordering::Relaxed);
        return 0;
    }
    mutex.count.store(0, Ordering::Relaxed);
    mutex.owner.store(0, Ordering::Relaxed);
    if mutex.word.swap(FREE, Ordering::Release) == CONTENDED {
        futex_wake(&mutex.word, 1);
    }
    0
}
/// # Safety
/// mutex is live, and no other thread is using it or can start a new operation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut Mutex) -> i32 {
    if !valid_address(mutex as u64) {
        return EINVAL;
    }
    let mutex = unsafe { &*mutex };
    if let Err(error) = mutex.kind() {
        return error;
    }
    if mutex.word.load(Ordering::Acquire) != FREE {
        return EBUSY;
    }
    mutex.metadata.store(0, Ordering::Relaxed);
    0
}

/// # Safety
/// attr points to writable storage exclusively owned by this caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut Attributes) -> i32 {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe {
        attr.write(Attributes {
            magic: ATTR_MAGIC,
            kind: PTHREAD_MUTEX_DEFAULT,
            reserved: 0,
        })
    };
    0
}
/// # Safety
/// attr is initialized and exclusively owned by this caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_destroy(attr: *mut Attributes) -> i32 {
    if attr.is_null() || !unsafe { &*attr }.valid() {
        return EINVAL;
    }
    unsafe { (*attr).magic = 0 };
    0
}
/// # Safety
/// attr is initialized; kind points to writable storage, disjoint from attr.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_gettype(attr: *const Attributes, kind: *mut i32) -> i32 {
    if attr.is_null() || kind.is_null() || !unsafe { &*attr }.valid() {
        return EINVAL;
    }
    unsafe { *kind = (*attr).kind };
    0
}
/// # Safety
/// attr is initialized and exclusively owned by this caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_settype(attr: *mut Attributes, kind: i32) -> i32 {
    if attr.is_null() || !valid_kind(kind) || !unsafe { &*attr }.valid() {
        return EINVAL;
    }
    unsafe { (*attr).kind = kind };
    0
}

/// The count of a recursive mutex the calling thread holds, for the probes.
///
/// # Safety
/// The calling thread owns this recursive mutex exclusively.
pub unsafe fn probe_recursion(mutex: *mut Mutex, count: u32) {
    let object = unsafe { &*mutex };
    assert_eq!(object.owner.load(Ordering::Relaxed), tls::thread_id());
    assert_eq!(object.kind(), Ok(PTHREAD_MUTEX_RECURSIVE));
    assert!(count != 0);
    object.count.store(u64::from(count), Ordering::Relaxed);
}
