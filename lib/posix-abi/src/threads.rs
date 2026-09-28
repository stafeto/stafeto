// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial managed pthread lifecycle. One IPC owner retains native handles,
//! stack mappings and join results. ELF TLS, signal inheritance, cleanup
//! handlers for thread-specific data and scheduler attributes remain work.

pub mod cancel;

use crate::{allocation, constants::*, tls};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use rt::{
    Stack,
    abi::{Access, Error, Policy, ThreadState},
    handle::{Channel, Handle, Thread, Timer},
    sys,
};

const CAPACITY: usize = 32;
const PAGE: usize = 4096;
const STACK_BASE: usize = 0x3000_0000;
const STRIDE: usize = 0x10_0000;
const DEFAULT_STACK: usize = 65536;
const CREATE: u64 = 1;
const EXIT: u64 = 2;
const JOIN: u64 = 3;
const JOIN_ACK: u64 = 4;
const DETACH: u64 = 5;
const CANCEL: u64 = 7;
const JOIN_ABANDON: u64 = 8;
const ATTR_MAGIC: u64 = 0x5054_4852_4154_5431;

type Start = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Attributes {
    magic: u64,
    stack_size: usize,
    guard_size: usize,
    detached: i32,
    reserved: u32,
}

impl Attributes {
    fn defaults() -> Self {
        Self {
            magic: ATTR_MAGIC,
            stack_size: DEFAULT_STACK,
            guard_size: PAGE,
            detached: PTHREAD_CREATE_JOINABLE,
            reserved: 0,
        }
    }
    fn valid(&self) -> bool {
        self.magic == ATTR_MAGIC
            && self.reserved == 0
            && matches!(
                self.detached,
                PTHREAD_CREATE_JOINABLE | PTHREAD_CREATE_DETACHED
            )
            && self.stack_size >= PTHREAD_STACK_MIN as usize
            && rounded(self.stack_size)
                .zip(rounded(self.guard_size))
                .is_some_and(|(stack, guard)| stack.checked_add(guard).is_some_and(|n| n <= STRIDE))
    }
}

const _: () = {
    assert!(core::mem::size_of::<Attributes>() == 32);
    assert!(core::mem::align_of::<Attributes>() == 8);
};

fn rounded(size: usize) -> Option<usize> {
    size.checked_add(PAGE - 1).map(|n| n & !(PAGE - 1))
}

struct Once<T>(UnsafeCell<Option<T>>);
// SAFETY: startup publishes the immutable channel once. The main handle is
// consumed only by the single owner after publication.
unsafe impl<T: Send> Sync for Once<T> {}
static CHANNEL: Once<Handle<Channel>> = Once(UnsafeCell::new(None));
static MAIN: Once<Handle<Thread>> = Once(UnsafeCell::new(None));
static REAPER: Once<Handle<Timer>> = Once(UnsafeCell::new(None));
static READY: AtomicBool = AtomicBool::new(false);
static OWNER_STACK: Stack<32768> = Stack::new();
#[cfg(feature = "transport-probe")]
static INTERRUPT_REPLIES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
static CANCEL_JOIN_REPLY: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "transport-probe")]
static OWNER_NATIVE: Once<Handle<Thread>> = Once(UnsafeCell::new(None));
#[cfg(feature = "transport-probe")]
static WAKE_RETRIES: AtomicU64 = AtomicU64::new(0);
static NONCE: AtomicU64 = AtomicU64::new(1);

struct Launch {
    id: AtomicU64,
    callback: AtomicU64,
    argument: AtomicU64,
    floating: AtomicU64,
    completed: AtomicBool,
    cancel: cancel::State,
}
static LAUNCH: [Launch; CAPACITY] = [const {
    Launch {
        id: AtomicU64::new(0),
        callback: AtomicU64::new(0),
        argument: AtomicU64::new(0),
        floating: AtomicU64::new(0),
        completed: AtomicBool::new(false),
        cancel: cancel::State::new(),
    }
}; CAPACITY];

fn channel() -> &'static Handle<Channel> {
    // SAFETY: successful startup publishes this immutable handle.
    unsafe {
        (*CHANNEL.0.get())
            .as_ref()
            .expect("thread owner initialized")
    }
}

/// Initialize once after the heap and file owner, before entering C main.
///
/// # Safety
/// Startup owns exclusive initialization. 0xf00000, message pages starting
/// at 0x2000000 and stack reservations 0x30000000..0x32000000 are unused.
/// The supplied handle owns the calling main thread.
pub unsafe fn init(main: Handle<Thread>) -> Result<(), Error> {
    if READY.load(Ordering::Acquire) {
        return Err(Error::BadState);
    }
    let endpoint = sys::channel_create(1)?;
    // Reserve the timer before clients can exhaust the process memory quota.
    // Initial pthreads all inherit main's scheduling policy and base priority.
    let timer = sys::timer_create(&endpoint, sys::thread_info(&main)?.base)?;
    unsafe {
        *CHANNEL.0.get() = Some(endpoint);
        *MAIN.0.get() = Some(main);
        *REAPER.0.get() = Some(timer);
    }
    LAUNCH[0].id.store(1, Ordering::Release);
    let result = (|| {
        let thread = unsafe {
            sys::thread_create(
                allocation::process(),
                owner,
                OWNER_STACK.top(),
                0,
                1,
                Policy::Fifo,
                0xf00000,
            )
        }?;
        READY.store(true, Ordering::Release);
        sys::thread_start(&thread)?;
        #[cfg(feature = "transport-probe")]
        unsafe {
            *OWNER_NATIVE.0.get() = Some(thread);
        }
        Ok(())
    })();
    if result.is_err() {
        READY.store(false, Ordering::Release);
        unsafe {
            *CHANNEL.0.get() = None;
            *MAIN.0.get() = None;
            *REAPER.0.get() = None;
        }
    }
    result
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Live,
    Exiting,
    Ended,
}
#[derive(Clone, Copy)]
struct Cached {
    nonce: u64,
    status: i32,
    value: u64,
}
struct Waiting {
    caller: u64,
    nonce: u64,
    token: Option<sys::Token>,
}
struct Entry {
    id: u64,
    native: Option<Handle<Thread>>,
    mapping: Option<(usize, usize)>,
    phase: Phase,
    detached: bool,
    value: u64,
    waiting: Option<Waiting>,
    cached: Option<Cached>,
    woken_epoch: u64,
}
impl Entry {
    fn new(
        id: u64,
        native: Handle<Thread>,
        mapping: Option<(usize, usize)>,
        detached: bool,
    ) -> Self {
        Self {
            id,
            native: Some(native),
            mapping,
            phase: Phase::Live,
            detached,
            value: 0,
            waiting: None,
            cached: None,
            woken_epoch: 0,
        }
    }
}
struct Registry {
    entries: [Option<Entry>; CAPACITY],
    next_id: u64,
}
impl Registry {
    fn find(&self, id: u64) -> Result<usize, i32> {
        self.entries
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.id == id))
            .ok_or(ESRCH)
    }
    fn entry(&self, index: usize) -> &Entry {
        self.entries[index].as_ref().expect("live entry")
    }
    fn entry_mut(&mut self, index: usize) -> &mut Entry {
        self.entries[index].as_mut().expect("live entry")
    }
    fn cache(&mut self, caller: usize, nonce: u64, result: Result<u64, i32>, _op: u64) -> Cached {
        let (status, value) = match result {
            Ok(value) => (0, value),
            Err(status) => (status, 0),
        };
        let answer = Cached {
            nonce,
            status,
            value,
        };
        self.entry_mut(caller).cached = Some(answer);
        #[cfg(feature = "transport-probe")]
        if _op == JOIN && CANCEL_JOIN_REPLY.swap(false, Ordering::AcqRel) {
            LAUNCH[caller].cancel.pending.store(true, Ordering::SeqCst);
            sys::thread_interrupt(
                self.entry(caller)
                    .native
                    .as_ref()
                    .expect("cancelled reply caller"),
            )
            .expect("interrupt cancelled join result");
        }
        #[cfg(feature = "transport-probe")]
        if _op < 64 && INTERRUPT_REPLIES.fetch_and(!(1 << _op), Ordering::AcqRel) & (1 << _op) != 0
        {
            sys::thread_interrupt(self.entry(caller).native.as_ref().expect("probe caller"))
                .expect("interrupt cached pthread reply");
        }
        answer
    }
    fn create(&mut self, caller: usize, words: [u64; 8]) -> Result<u64, i32> {
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(EAGAIN)?;
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(EAGAIN)?;
        let attr = Attributes {
            magic: ATTR_MAGIC,
            stack_size: words[5] as usize,
            guard_size: (words[6] >> 1) as usize,
            detached: (words[6] & 1) as i32,
            reserved: 0,
        };
        if words[3] == 0 || !attr.valid() {
            return Err(EINVAL);
        }
        let parent =
            sys::thread_info(self.entry(caller).native.as_ref().ok_or(ESRCH)?).map_err(|_| EIO)?;
        let policy = parent.policy.ok_or(EIO)?;
        let length = rounded(attr.stack_size).ok_or(EINVAL)?;
        let address = STACK_BASE + slot * STRIDE + rounded(attr.guard_size).ok_or(EINVAL)?;
        let memory = sys::mem_create(length as u64).map_err(|_| EAGAIN)?;
        sys::mem_map(
            allocation::process(),
            &memory,
            0,
            length as u64,
            address,
            Access::ReadWrite,
        )
        .map_err(|_| EAGAIN)?;
        LAUNCH[slot].callback.store(words[3], Ordering::Relaxed);
        LAUNCH[slot].argument.store(words[4], Ordering::Relaxed);
        LAUNCH[slot].floating.store(words[7], Ordering::Relaxed);
        LAUNCH[slot].completed.store(false, Ordering::Relaxed);
        LAUNCH[slot].cancel.reset();
        LAUNCH[slot].id.store(id, Ordering::Release);
        // SAFETY: this slot owns the new stack until its native thread has ended.
        let native = unsafe {
            sys::thread_create(
                allocation::process(),
                trampoline,
                address + length,
                slot as u64,
                parent.base,
                policy,
                0x2000000 + slot * PAGE,
            )
        };
        let native = match native {
            Ok(native) => native,
            Err(_) => {
                unsafe { sys::mem_unmap(allocation::process(), address, length as u64) }
                    .expect("failed-create stack removal");
                return Err(EAGAIN);
            }
        };
        self.entries[slot] = Some(Entry::new(
            id,
            native,
            Some((address, length)),
            attr.detached != 0,
        ));
        // Install ownership before a successful start can run the callback.
        if sys::thread_start(self.entry(slot).native.as_ref().expect("new native thread")).is_err()
        {
            // The failed start leaves the thread stopped; release its handle
            // before removing the stack it cannot execute on.
            self.entries[slot] = None;
            unsafe { sys::mem_unmap(allocation::process(), address, length as u64) }
                .expect("failed-start stack removal");
            return Err(EAGAIN);
        }
        self.next_id = next;
        Ok(id)
    }
    fn reap(&mut self) {
        for (index, launch) in LAUNCH.iter().enumerate() {
            let Some(entry) = self.entries[index].as_mut() else {
                continue;
            };
            if entry.phase != Phase::Exiting {
                continue;
            }
            if sys::thread_info(entry.native.as_ref().expect("exiting native handle"))
                .expect("owned thread information")
                .state
                != ThreadState::Ended
            {
                continue;
            }
            assert!(
                launch.completed.load(Ordering::Acquire),
                "published pthread completion"
            );
            if let Some((address, length)) = entry.mapping.take() {
                // SAFETY: the kernel confirms this thread will never execute again.
                unsafe { sys::mem_unmap(allocation::process(), address, length as u64) }
                    .expect("ended pthread stack removal");
            }
            entry.native = None;
            entry.phase = Phase::Ended;
            if entry.detached {
                self.entries[index] = None;
            }
        }
        for index in 0..CAPACITY {
            let Some(entry) = self.entries[index].as_ref() else {
                continue;
            };
            if entry.phase != Phase::Ended {
                continue;
            }
            let Some(waiting) = entry.waiting.as_ref() else {
                continue;
            };
            let caller_id = waiting.caller;
            let nonce = waiting.nonce;
            let value = entry.value;
            let token = self
                .entry_mut(index)
                .waiting
                .as_mut()
                .expect("join claim")
                .token
                .take();
            if let Some(token) = token {
                let caller = self.find(caller_id).expect("live joiner");
                let answer = self.cache(caller, nonce, Ok(value), JOIN);
                respond(token, answer);
            }
        }
    }
    fn join(&mut self, caller: usize, words: [u64; 8], token: sys::Token) {
        let result = (|| {
            let target = self.find(words[3])?;
            if target == caller {
                return Err(EDEADLK);
            }
            let entry = self.entry(target);
            if entry.detached
                || entry
                    .waiting
                    .as_ref()
                    .is_some_and(|w| w.caller != words[1] || w.nonce != words[2])
            {
                return Err(EINVAL);
            }
            Ok(target)
        })();
        match result {
            Ok(target) => {
                self.entry_mut(target).waiting = Some(Waiting {
                    caller: words[1],
                    nonce: words[2],
                    token: Some(token),
                });
            }
            Err(status) => {
                let answer = self.cache(caller, words[2], Err(status), JOIN);
                respond(token, answer);
            }
        }
    }
    fn wake_needed(&self, index: usize) -> bool {
        let Some(entry) = self.entries[index].as_ref() else {
            return false;
        };
        let state = &LAUNCH[index].cancel;
        let epoch = state.active.load(Ordering::SeqCst);
        entry.phase == Phase::Live
            && state.pending.load(Ordering::SeqCst)
            && state.enabled.load(Ordering::SeqCst)
            && epoch != 0
            && epoch != entry.woken_epoch
    }
    fn wake_cancelled(&mut self) {
        for (index, launch) in LAUNCH.iter().enumerate() {
            if !self.wake_needed(index) {
                continue;
            }
            let epoch = launch.cancel.active.load(Ordering::SeqCst);
            match sys::thread_interrupt(
                self.entry(index)
                    .native
                    .as_ref()
                    .expect("live cancellation target"),
            ) {
                Ok(()) => {
                    self.entry_mut(index).woken_epoch = epoch;
                }
                Err(Error::BadState) => {
                    // The point may be about to enter IPC.
                    #[cfg(feature = "transport-probe")]
                    WAKE_RETRIES.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => panic!("owned pthread interruption: {error:?}"),
            }
        }
    }
    fn perform(&mut self, caller: usize, words: [u64; 8]) -> Result<u64, i32> {
        match words[0] {
            CREATE => self.create(caller, words),
            EXIT => {
                // Defensively remove claims still owned by an exiting thread.
                for target in self.entries.iter_mut().flatten() {
                    if target
                        .waiting
                        .as_ref()
                        .is_some_and(|w| w.caller == words[1])
                    {
                        target.waiting = None;
                    }
                }
                let entry = self.entry_mut(caller);
                entry.phase = Phase::Exiting;
                entry.value = words[3];
                // Application threads determine process lifetime; internal owners remain live.
                if self
                    .entries
                    .iter()
                    .flatten()
                    .all(|e| e.phase != Phase::Live)
                {
                    sys::process_exit(0);
                }
                Ok(0)
            }
            JOIN_ACK => {
                let target = self.find(words[3])?;
                let entry = self.entry(target);
                if entry.phase != Phase::Ended
                    || !entry.waiting.as_ref().is_some_and(|w| w.caller == words[1])
                {
                    return Err(EINVAL);
                }
                self.entries[target] = None;
                Ok(0)
            }
            CANCEL => {
                let index = self.find(words[3])?;
                if self.entry(index).phase == Phase::Live {
                    LAUNCH[index].cancel.pending.store(true, Ordering::SeqCst);
                    self.wake_cancelled();
                }
                Ok(0)
            }
            JOIN_ABANDON => {
                if let Ok(target) = self.find(words[3])
                    && self
                        .entry(target)
                        .waiting
                        .as_ref()
                        .is_some_and(|w| w.caller == words[1])
                {
                    self.entry_mut(target).waiting = None;
                }
                Ok(0)
            }
            DETACH => {
                let target = self.find(words[3])?;
                let entry = self.entry_mut(target);
                if entry.detached || entry.waiting.is_some() {
                    return Err(EINVAL);
                }
                entry.detached = true;
                if entry.phase == Phase::Ended {
                    self.entries[target] = None;
                }
                Ok(0)
            }
            #[cfg(feature = "transport-probe")]
            6 => {
                let index = self.find(words[3])?;
                Ok(self.entry(index).native.as_ref().ok_or(ESRCH)?.raw().0)
            }
            _ => Err(EINVAL),
        }
    }
}

fn respond(token: sys::Token, answer: Cached) {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&(answer.status as u64).to_le_bytes());
    bytes[8..].copy_from_slice(&answer.value.to_le_bytes());
    // An interrupted client's cached answer survives this rejected reply.
    let _ = token.reply(&bytes);
}

extern "C" fn owner(_: u64) -> ! {
    assert!(READY.load(Ordering::Acquire), "published thread owner");
    let mut registry = Registry {
        entries: core::array::from_fn(|_| None),
        next_id: 2,
    };
    // SAFETY: startup handed main exclusively to this owner.
    let main = unsafe { (*MAIN.0.get()).take().expect("initial main handle") };
    registry.entries[0] = Some(Entry::new(1, main, None, false));
    // SAFETY: startup transferred the reserved timer to this sole owner.
    let timer = unsafe { (*REAPER.0.get()).take().expect("initial reap timer") };
    let mut armed = false;
    loop {
        registry.reap();
        registry.wake_cancelled();
        if registry
            .entries
            .iter()
            .flatten()
            .any(|e| e.phase == Phase::Exiting)
            || (0..CAPACITY).any(|index| registry.wake_needed(index))
        {
            if !armed {
                sys::timer_set(
                    &timer,
                    sys::clock_now()
                        .expect("pthread clock")
                        .saturating_add(1_000_000),
                )
                .expect("pthread timer arm");
                armed = true;
            }
        } else if armed {
            sys::timer_cancel(&timer).expect("pthread timer cancel");
            armed = false;
        }
        let (len, words, token, handles) = match sys::receive(channel()) {
            Ok(sys::Received::Message {
                len,
                words,
                token,
                handles,
                ..
            }) => (len, words, token, handles),
            Ok(sys::Received::Notification {
                source: rt::abi::Source::Timer,
                ..
            }) => {
                armed = false;
                continue;
            }
            _ => continue,
        };
        drop(handles);
        let caller = match registry.find(words[1]) {
            Ok(caller) if len == 64 && words[2] != 0 => caller,
            _ => {
                respond(
                    token,
                    Cached {
                        nonce: 0,
                        status: EINVAL,
                        value: 0,
                    },
                );
                continue;
            }
        };
        if let Some(answer) = registry
            .entry(caller)
            .cached
            .filter(|c| c.nonce == words[2])
        {
            respond(token, answer);
        } else if words[0] == JOIN {
            registry.join(caller, words, token);
        } else {
            let result = registry.perform(caller, words);
            let answer = registry.cache(caller, words[2], result, words[0]);
            respond(token, answer);
        }
    }
}

extern "C" fn trampoline(slot: u64) -> ! {
    let launch = &LAUNCH[slot as usize];
    let id = launch.id.load(Ordering::Acquire);
    // SAFETY: pthread_create supplied a live C function pointer; this slot cannot
    // be reused until this native thread is confirmed ended.
    let callback: Start =
        unsafe { core::mem::transmute(launch.callback.load(Ordering::Relaxed) as usize) };
    let argument = launch.argument.load(Ordering::Relaxed) as *mut c_void;
    let floating = launch.floating.load(Ordering::Relaxed);
    // SAFETY: EL0 owns its FP environment. Restore the creator's control and
    // status registers before entering any user callback.
    unsafe {
        core::arch::asm!("msr fpcr, {control}", "msr fpsr, {status}",
            control = in(reg) floating & 0xffff_ffff,
            status = in(reg) floating >> 32,
            options(nomem, nostack, preserves_flags));
    }
    tls::with_thread(id, || {
        let value = unsafe { callback(argument) };
        // SAFETY: the current thread is managed and has an initialized scope.
        unsafe { pthread_exit(value) }
    })
}

fn request(op: u64, arguments: [u64; 5]) -> Result<u64, i32> {
    if !READY.load(Ordering::Acquire) || tls::thread_id() == 0 {
        return Err(EINVAL);
    }
    let nonce = NONCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| EAGAIN)?;
    let words = [
        op,
        tls::thread_id(),
        nonce,
        arguments[0],
        arguments[1],
        arguments[2],
        arguments[3],
        arguments[4],
    ];
    let mut bytes = [0; 64];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    loop {
        match sys::send(channel(), &bytes) {
            Err(Error::Interrupted) if op == JOIN && cancel::requested() => return Err(ECANCELED),
            Err(Error::Interrupted) => continue,
            Err(_) => return Err(EIO),
            Ok(reply) if reply.len == 16 => {
                if reply.words[0] != 0 {
                    return Err(reply.words[0] as i32);
                }
                return Ok(reply.words[1]);
            }
            _ => return Err(EIO),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_self() -> u64 {
    tls::thread_id()
}
#[unsafe(no_mangle)]
pub extern "C" fn pthread_equal(first: u64, second: u64) -> i32 {
    i32::from(first == second)
}

/// # Safety
/// out is writable, attr is null or initialized, and callback/argument remain
/// valid for the child. The calling thread is managed by this process runtime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    out: *mut u64,
    attr: *const Attributes,
    callback: Option<Start>,
    argument: *mut c_void,
) -> i32 {
    if out.is_null() || callback.is_none() {
        return EINVAL;
    }
    let attributes = if attr.is_null() {
        Attributes::defaults()
    } else {
        unsafe { *attr }
    };
    if !attributes.valid() {
        return EINVAL;
    }
    let control: u64;
    let status: u64;
    // SAFETY: read only the calling thread's current FP environment.
    unsafe {
        core::arch::asm!("mrs {control}, fpcr", "mrs {status}, fpsr",
            control = out(reg) control, status = out(reg) status,
            options(nomem, nostack, preserves_flags));
    }
    match request(
        CREATE,
        [
            callback.expect("checked callback") as *const () as u64,
            argument as u64,
            attributes.stack_size as u64,
            ((attributes.guard_size as u64) << 1) | attributes.detached as u64,
            control | (status << 32),
        ],
    ) {
        Ok(id) => {
            unsafe { out.write(id) };
            0
        }
        Err(status) => status,
    }
}

/// # Safety
/// The caller is managed; out is null or writable for one returned pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(thread: u64, out: *mut *mut c_void) -> i32 {
    let point = cancel::Point::begin();
    let result = request(JOIN, [thread, 0, 0, 0, 0]);
    if point.requested() {
        // Undo the claim even if JOIN was interrupted before acceptance or
        // after a completed target produced its retained value.
        request(JOIN_ABANDON, [thread, 0, 0, 0, 0]).expect("cancelled join claim release");
        point.finish();
        unreachable!("accepted join cancellation");
    }
    // An accepted result wins cancellation arriving after this point. ACK
    // retries are internal bookkeeping and cannot introduce a new point.
    point.end();
    match result {
        Ok(value) => {
            let launch = LAUNCH
                .iter()
                .find(|launch| launch.id.load(Ordering::Acquire) == thread)
                .expect("join result retains launch slot");
            assert!(
                launch.completed.load(Ordering::Acquire),
                "joined completion"
            );
            if !out.is_null() {
                unsafe { out.write(value as *mut c_void) };
            }
            request(JOIN_ACK, [thread, 0, 0, 0, 0]).map_or_else(|e| e, |_| 0)
        }
        Err(status) => status,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_cancel(thread: u64) -> i32 {
    request(CANCEL, [thread, 0, 0, 0, 0]).map_or_else(|e| e, |_| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_detach(thread: u64) -> i32 {
    request(DETACH, [thread, 0, 0, 0, 0]).map_or_else(|e| e, |_| 0)
}

/// # Safety
/// The current thread is managed and has its initialized POSIX scope.
/// Registered cleanup nodes remain live. Thread-specific destructors remain work.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_exit(value: *mut c_void) -> ! {
    unsafe { cancel::exit_cleanup() };
    let id = tls::thread_id();
    let launch = LAUNCH
        .iter()
        .find(|launch| launch.id.load(Ordering::Acquire) == id && id != 0)
        .expect("managed pthread completion slot");
    launch.completed.store(true, Ordering::Release);
    request(EXIT, [value as u64, 0, 0, 0, 0]).expect("managed pthread exit");
    sys::thread_exit()
}

/// # Safety
/// attr points to writable storage for a new attribute object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut Attributes) -> i32 {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe { attr.write(Attributes::defaults()) };
    0
}
/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut Attributes) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { (*attr).magic = 0 };
    0
}

/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstacksize(attr: *mut Attributes, size: usize) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    let mut copy = unsafe { *attr };
    copy.stack_size = size;
    if !copy.valid() {
        return EINVAL;
    }
    unsafe { attr.write(copy) };
    0
}
/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setguardsize(attr: *mut Attributes, size: usize) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    let mut copy = unsafe { *attr };
    copy.guard_size = size;
    if !copy.valid() {
        return EINVAL;
    }
    unsafe { attr.write(copy) };
    0
}
/// # Safety
/// attr is initialized writable attribute storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setdetachstate(attr: *mut Attributes, state: i32) -> i32 {
    if attr.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    let mut copy = unsafe { *attr };
    copy.detached = state;
    if !copy.valid() {
        return EINVAL;
    }
    unsafe { attr.write(copy) };
    0
}
/// # Safety
/// attr is initialized readable storage, and out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstacksize(
    attr: *const Attributes,
    out: *mut usize,
) -> i32 {
    if attr.is_null() || out.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { out.write((*attr).stack_size) };
    0
}
/// # Safety
/// attr is initialized readable storage, and out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getguardsize(
    attr: *const Attributes,
    out: *mut usize,
) -> i32 {
    if attr.is_null() || out.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { out.write((*attr).guard_size) };
    0
}
/// # Safety
/// attr is initialized readable storage, and out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getdetachstate(
    attr: *const Attributes,
    out: *mut i32,
) -> i32 {
    if attr.is_null() || out.is_null() || !unsafe { (*attr).valid() } {
        return EINVAL;
    }
    unsafe { out.write((*attr).detached) };
    0
}

/// Interrupt accepted replies after storing the actual operation result. Each
/// selected operation fires once; this is excluded from the public sysroot.
#[cfg(feature = "transport-probe")]
pub fn probe_interrupt_replies(create: bool, join: bool, acknowledge: bool) {
    INTERRUPT_REPLIES.store(
        (u64::from(create) << CREATE)
            | (u64::from(join) << JOIN)
            | (u64::from(acknowledge) << JOIN_ACK),
        Ordering::Release,
    );
}

/// # Safety
/// The ID names a live managed thread that remains live while its borrowed
/// handle is used. For tests only: arbitrary native thread termination would
/// bypass the pthread lifecycle protocol.
#[cfg(feature = "transport-probe")]
pub unsafe fn probe_native(thread: u64) -> Result<core::mem::ManuallyDrop<Handle<Thread>>, i32> {
    request(6, [thread, 0, 0, 0, 0]).map(|raw| Handle::borrowed(rt::abi::Handle(raw)))
}

fn current_launch() -> Option<&'static Launch> {
    let id = tls::thread_id();
    (id != 0)
        .then(|| {
            LAUNCH
                .iter()
                .find(|launch| launch.id.load(Ordering::Acquire) == id)
        })
        .flatten()
}

/// Test the real window before IPC entry; the closure's resources are dropped
/// before its cancellation boundary. Excluded from the regular sysroot.
#[cfg(feature = "transport-probe")]
pub fn probe_cancel_window(run: impl FnOnce()) {
    let point = cancel::Point::begin();
    run();
    point.finish();
}

/// Cancel once after JOIN produced a retained result, before its delivery.
#[cfg(feature = "transport-probe")]
pub fn probe_cancel_join_reply() {
    CANCEL_JOIN_REPLY.store(true, Ordering::Release);
}

/// Confirm a live thread is inside the console phase of read.
#[cfg(feature = "transport-probe")]
pub fn probe_console_waiting(id: u64) -> bool {
    LAUNCH
        .iter()
        .find(|launch| launch.id.load(Ordering::Acquire) == id)
        .is_some_and(|launch| {
            launch.cancel.console.load(Ordering::Acquire)
                && launch.cancel.active.load(Ordering::SeqCst) != 0
        })
}

/// Temporarily schedule the owner ahead of a probe's low-priority target.
/// The regular sysroot has no extra native-owner handle.
#[cfg(feature = "transport-probe")]
pub fn probe_owner_priority(priority: u8) {
    let thread = unsafe {
        (*OWNER_NATIVE.0.get())
            .as_ref()
            .expect("probe owner handle")
    };
    sys::thread_set_priority(thread, priority, Policy::Fifo).expect("probe owner priority");
}
#[cfg(feature = "transport-probe")]
pub fn probe_wake_retries() -> u64 {
    WAKE_RETRIES.load(Ordering::Acquire)
}
