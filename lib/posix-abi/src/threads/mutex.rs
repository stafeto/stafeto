// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process-private stalled mutexes, serialized by the existing pthread owner.
//! Application Release publication and ownership Acquire carry protected writes.

use super::{Registry, request, respond};
use crate::{constants::*, tls};
use core::sync::atomic::{AtomicU64, Ordering};
use posix_time::Deadline;
use rt::sys;

pub(super) const LOCK: u64 = 18;
pub(super) const TRY: u64 = 19;
pub(super) const UNLOCK: u64 = 20;
pub(super) const DESTROY: u64 = 21;
pub(super) const TIMED: u64 = 23;
const MAGIC: u64 = 0x5354_4d58_0000_0000;
const ATTR_MAGIC: u64 = 0x5354_4d41_5454_5231;

#[repr(C)]
pub struct Mutex {
    metadata: AtomicU64,
    owner: AtomicU64,
    count: AtomicU64,
    publication: AtomicU64,
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
            publication: AtomicU64::new(0),
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

pub(super) struct Waiting {
    address: u64,
    nonce: u64,
    token: sys::Token,
    op: u64,
    deadline: Option<Deadline>,
}
impl Registry {
    pub(super) fn mutex_lock(&mut self, caller: usize, words: [u64; 8], token: sys::Token) {
        // A retry replaces an interrupted token. A granted wait has already
        // been cleared and its nonce hits the shared reply cache instead.
        #[cfg(feature = "transport-probe")]
        if self
            .entry(caller)
            .mutex_waiting
            .as_ref()
            .is_some_and(|w| w.nonce == words[2])
            && RETRY_TARGET
                .compare_exchange(words[1], 0, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            let gate = rt::handle::Handle::<rt::handle::Channel>::borrowed(rt::abi::Handle(
                RETRY_GATE.load(Ordering::Relaxed),
            ));
            super::probe_park(&gate);
        }
        if let Some(waiting) = self.entry_mut(caller).mutex_waiting.as_mut()
            && waiting.nonce == words[2]
        {
            waiting.token = token;
            return;
        }
        self.entry_mut(caller).mutex_waiting = None;
        let result = (|| {
            if !valid_address(words[3]) {
                return Err(EINVAL);
            }
            // SAFETY: the C call retains its initialized object until returned;
            // init/destroy concurrently with a locking call is undefined.
            let mutex = unsafe { &*(words[3] as *const Mutex) };
            let kind = mutex.kind()?;
            let owner = mutex.owner.load(Ordering::Acquire);
            if owner == 0 {
                mutex.count.store(1, Ordering::Relaxed);
                mutex.owner.store(words[1], Ordering::Release);
                return Ok(false);
            }
            if owner == words[1] && kind == PTHREAD_MUTEX_RECURSIVE {
                let count = mutex.count.load(Ordering::Relaxed);
                if count == u64::from(u32::MAX) {
                    return Err(EAGAIN);
                }
                mutex.count.store(count + 1, Ordering::Relaxed);
                return Ok(false);
            }
            if words[0] == TRY {
                return Err(EBUSY);
            }
            if owner == words[1] && kind == PTHREAD_MUTEX_ERRORCHECK {
                return Err(EDEADLK);
            }
            Ok(true)
        })();
        if result == Ok(true) {
            let deadline = if words[0] == TIMED {
                match Deadline::new(words[4] as u32, words[5] as i64, words[6] as i64) {
                    Ok(deadline) => Some(deadline),
                    Err(_) => {
                        let answer = self.cache(caller, words[2], Err(EINVAL), words[0]);
                        respond(token, answer);
                        return;
                    }
                }
            } else {
                None
            };
            // Flush existing calendar intervals before adding a new wait. Its
            // first observation starts at registration, excluding earlier peaks.
            if deadline.is_some_and(|d| d.clock == proto_clock::REALTIME) {
                self.deadlines(true);
            }
            self.entry_mut(caller).mutex_waiting = Some(Waiting {
                address: words[3],
                nonce: words[2],
                token,
                op: words[0],
                deadline,
            });
        } else {
            let answer = self.cache(caller, words[2], result.map(|_| 0), words[0]);
            respond(token, answer);
        }
    }
    /// Expire in the original clock and choose the next representable wake.
    /// Rechecking after every timer/clock notice rejects stale timer deliveries.
    pub(super) fn wait_deadlines(&mut self) -> Option<u64> {
        self.deadlines(false)
    }
    pub(super) fn deadlines(&mut self, force: bool) -> Option<u64> {
        let realtime = self.entries.iter().flatten().any(|e| {
            e.sleep_waiting
                .as_ref()
                .is_some_and(|w| w.deadline.calendar())
                || e.mutex_waiting
                    .as_ref()
                    .and_then(|w| w.deadline)
                    .is_some_and(|d| d.clock == proto_clock::REALTIME)
        });
        let observation = if realtime || force {
            crate::clock::observation().ok()
        } else {
            None
        };
        let now = rt::time::ticks_to_ns(rt::time::now());
        let mut next: Option<u64> = None;
        for index in 0..self.entries.len() {
            let Some(deadline) = self.entries[index]
                .as_ref()
                .and_then(|e| e.mutex_waiting.as_ref())
                .and_then(|w| w.deadline)
            else {
                continue;
            };
            let target = deadline.target(observation.map(|o| o.anchor));
            let error = match deadline.expired(now, observation) {
                Err(_) => Some(EIO),
                Ok(true) => Some(ETIMEDOUT),
                Ok(false) => {
                    let target = target.expect("validated deadline clock");
                    if let Ok(when) = u64::try_from(target) {
                        next = Some(next.map_or(when, |v| v.min(when)));
                    }
                    None
                }
            };
            if let Some(error) = error {
                let waiting = self
                    .entry_mut(index)
                    .mutex_waiting
                    .take()
                    .expect("expired mutex wait");
                let answer = self.cache(index, waiting.nonce, Err(error), waiting.op);
                respond(waiting.token, answer);
            }
        }
        self.sleep_deadlines(now, observation)
            .into_iter()
            .chain(next)
            .chain(self.signal_deadlines(now))
            .min()
    }
    fn mutex_next(&self, address: u64) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let entry = entry.as_ref()?;
                let wait = entry
                    .mutex_waiting
                    .as_ref()
                    .filter(|w| w.address == address)?;
                let priority = sys::thread_info(entry.native.as_ref().expect("live mutex waiter"))
                    .expect("mutex waiter priority")
                    .priority;
                Some((index, priority, wait.nonce))
            })
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.2.cmp(&a.2)))
            .map(|candidate| candidate.0)
    }
    pub(super) fn mutex_perform(&mut self, words: [u64; 8]) -> Result<u64, i32> {
        self.wait_deadlines();
        if !valid_address(words[3]) {
            return Err(EINVAL);
        }
        // SAFETY: the caller retains its initialized object; every waiter also
        // keeps its locking call live until its saved terminal answer returns.
        let mutex = unsafe { &*(words[3] as *const Mutex) };
        mutex.kind()?;
        match words[0] {
            DESTROY => {
                if mutex.owner.load(Ordering::Acquire) != 0 || self.mutex_next(words[3]).is_some() {
                    return Err(EBUSY);
                }
                mutex.metadata.store(0, Ordering::Relaxed);
            }
            UNLOCK => {
                if mutex.owner.load(Ordering::Acquire) != words[1] {
                    return Err(EPERM);
                }
                // RMW reads the current publication and acquires the writes of
                // this owner's Release, without depending on IPC as a fence.
                assert_eq!(mutex.publication.fetch_add(0, Ordering::Acquire), words[4]);
                let count = mutex.count.load(Ordering::Relaxed);
                assert!(count > 0, "owned mutex lock count");
                if count > 1 {
                    mutex.count.store(count - 1, Ordering::Relaxed);
                } else if let Some(next) = self.mutex_next(words[3]) {
                    let waiting = self
                        .entry_mut(next)
                        .mutex_waiting
                        .take()
                        .expect("selected mutex waiter");
                    mutex.owner.store(self.entry(next).id, Ordering::Release);
                    let answer = self.cache(next, waiting.nonce, Ok(0), waiting.op);
                    respond(waiting.token, answer);
                } else {
                    mutex.count.store(0, Ordering::Relaxed);
                    mutex.owner.store(0, Ordering::Release);
                }
            }
            _ => return Err(EINVAL),
        }
        Ok(0)
    }
}

/// # Safety
/// mutex is writable and exclusively owned for initialization; attr is null or
/// points to an initialized attribute object. A live mutex must not be reinitialized.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
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
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut Mutex) -> i32 {
    unsafe { acquire(mutex, LOCK) }
}
/// # Safety
/// As for pthread_mutex_lock.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut Mutex) -> i32 {
    unsafe { acquire(mutex, TRY) }
}
/// # Safety
/// As for pthread_mutex_lock; deadline supplies one readable aligned Timespec.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_timedlock(
    mutex: *mut Mutex,
    deadline: *const posix_types::Timespec,
) -> i32 {
    unsafe { pthread_mutex_clocklock(mutex, crate::clock::CLOCK_REALTIME, deadline) }
}
/// # Safety
/// As for pthread_mutex_timedlock. The original absolute deadline is retained
/// across IPC interruption. This function is not a deferred cancellation point.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
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
    unsafe {
        acquire_args(
            mutex,
            TIMED,
            [
                mutex as u64,
                clock as u64,
                deadline.tv_sec as u64,
                deadline.tv_nsec as u64,
                0,
            ],
        )
    }
}
unsafe fn acquire(mutex: *mut Mutex, op: u64) -> i32 {
    unsafe { acquire_args(mutex, op, [mutex as u64, 0, 0, 0, 0]) }
}
unsafe fn acquire_args(mutex: *mut Mutex, op: u64, arguments: [u64; 5]) -> i32 {
    match request(op, arguments) {
        Ok(_) => {
            // SAFETY: a successful owner request validated the live object.
            // An Acquire RMW reads the latest ownership modification even
            // when this same pthread ID owned the mutex in an earlier cycle.
            let id = tls::thread_id();
            unsafe { &*mutex }
                .owner
                .compare_exchange(id, id, Ordering::Acquire, Ordering::Relaxed)
                .expect("published mutex ownership");
            0
        }
        Err(error) => error,
    }
}
/// # Safety
/// As for pthread_mutex_lock. The current owner publishes protected writes.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut Mutex) -> i32 {
    if !valid_address(mutex as u64) || super::current_launch().is_none() {
        return EINVAL;
    }
    let mutex_ref = unsafe { &*mutex };
    if let Err(error) = mutex_ref.kind() {
        return error;
    }
    if mutex_ref.owner.load(Ordering::Acquire) != tls::thread_id() {
        return EPERM;
    }
    let epoch = mutex_ref
        .publication
        .fetch_add(1, Ordering::Release)
        .wrapping_add(1);
    request(UNLOCK, [mutex as u64, epoch, 0, 0, 0]).map_or_else(|e| e, |_| 0)
}
/// # Safety
/// mutex is live, and no other thread is using it or can start a new operation.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut Mutex) -> i32 {
    request(DESTROY, [mutex as u64, 0, 0, 0, 0]).map_or_else(|e| e, |_| 0)
}

/// # Safety
/// attr points to writable storage exclusively owned by this caller.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
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
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_destroy(attr: *mut Attributes) -> i32 {
    if attr.is_null() || !unsafe { &*attr }.valid() {
        return EINVAL;
    }
    unsafe { (*attr).magic = 0 };
    0
}
/// # Safety
/// attr is initialized; kind points to writable storage, disjoint from attr.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_gettype(attr: *const Attributes, kind: *mut i32) -> i32 {
    if attr.is_null() || kind.is_null() || !unsafe { &*attr }.valid() {
        return EINVAL;
    }
    unsafe { *kind = (*attr).kind };
    0
}
/// # Safety
/// attr is initialized and exclusively owned by this caller.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_settype(attr: *mut Attributes, kind: i32) -> i32 {
    if attr.is_null() || !valid_kind(kind) || !unsafe { &*attr }.valid() {
        return EINVAL;
    }
    unsafe { (*attr).kind = kind };
    0
}

#[cfg(feature = "transport-probe")]
pub fn probe_interrupt_replies() {
    super::INTERRUPT_REPLIES.fetch_or(
        (1 << LOCK) | (1 << TRY) | (1 << UNLOCK) | (1 << DESTROY),
        Ordering::AcqRel,
    );
}
#[cfg(feature = "transport-probe")]
pub fn probe_waiting(thread: u64) -> Result<bool, i32> {
    request(22, [thread, 0, 0, 0, 0]).map(|value| value != 0)
}
/// # Safety
/// The calling thread owns this recursive mutex exclusively.
#[cfg(feature = "transport-probe")]
pub unsafe fn probe_recursion(mutex: *mut Mutex, count: u32) {
    let object = unsafe { &*mutex };
    assert_eq!(object.owner.load(Ordering::Acquire), tls::thread_id());
    assert_eq!(object.kind(), Ok(PTHREAD_MUTEX_RECURSIVE));
    assert!(count != 0);
    object.count.store(u64::from(count), Ordering::Relaxed);
}

#[cfg(feature = "transport-probe")]
pub fn probe_interrupt_timed_reply() {
    super::INTERRUPT_REPLIES.fetch_or(1 << TIMED, Ordering::AcqRel);
}

#[cfg(feature = "transport-probe")]
static RETRY_GATE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
static RETRY_TARGET: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
pub fn probe_gate_retry(gate: &rt::handle::Handle<rt::handle::Channel>, thread: u64) {
    RETRY_GATE.store(gate.raw().0, Ordering::Relaxed);
    RETRY_TARGET.store(thread, Ordering::Release);
}
