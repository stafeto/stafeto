// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process heap owned by an IPC worker at the process ceiling. Requests
//! serialize allocation; the worker never calls exported allocation APIs.
//! This does not establish a bounded real-time allocator.

use crate::{constants::*, fail};
use core::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use posix_heap::{Allocator, Error, FUNDAMENTAL_ALIGNMENT};
use rt::{
    Stack,
    abi::Policy,
    handle::{Channel, Handle, Process},
    sys,
};

const BASE: usize = 0x1000_0000;
const LIMIT: usize = 0x2000_0000;
const PAGE: usize = 4096;
const CHUNK: usize = 65536;
const ALLOC: u64 = 1;
const REALLOC: u64 = 2;
const FREE: u64 = 3;
const ZERO: u64 = 4;
const ACK: u64 = 5;
mod replies;
static NEXT: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "transport-probe")]
static UPCALL_OPS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
static NATIVE_TARGET: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
static ACK_TARGET: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
static ACK_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
static REJECT_NEW: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "transport-probe")]
static WORKER: AtomicU64 = AtomicU64::new(0);

struct Config {
    process: Handle<Process>,
    channel: Handle<Channel>,
}
struct Once(UnsafeCell<Option<Config>>);
// SAFETY: startup writes once before starting the worker; config is immutable
// thereafter. READY publishes it to clients; the worker starts after that write.
unsafe impl Sync for Once {}
static CONFIG: Once = Once(UnsafeCell::new(None));
static READY: AtomicBool = AtomicBool::new(false);
static STACK: Stack<16384> = Stack::new();

/// Initialize once during single-threaded startup, before any allocation call.
/// The process heap reserves BASE..LIMIT; 0xa00000 is the worker message buffer.
///
/// # Safety
/// Called while startup has exclusive heap initialization access, before any
/// client thread uses allocation. Other runtime owners do not use this heap.
/// The reserved heap and worker message ranges must be unused.
pub unsafe fn init(process: Handle<Process>) -> Result<(), rt::abi::Error> {
    if READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    let settings = Config {
        process,
        channel: sys::channel_create(1)?,
    };
    // SAFETY: startup has exclusive access; no worker/client exists yet.
    unsafe { *CONFIG.0.get() = Some(settings) };
    let result = (|| {
        // SAFETY: this stack is used once; the message page is outside image segments.
        let thread = unsafe {
            sys::thread_create(
                &config().process,
                worker,
                STACK.top(),
                0,
                crate::ceiling()?,
                Policy::Fifo,
                0xa00000,
            )
        }?;
        READY.store(true, Ordering::Release);
        sys::thread_start(&thread)?;
        #[cfg(feature = "transport-probe")]
        WORKER.store(thread.into_raw().0, Ordering::Release);
        Ok(())
    })();
    if result.is_err() {
        READY.store(false, Ordering::Release);
        // SAFETY: thread creation/start failed, so no worker can access the config.
        unsafe { *CONFIG.0.get() = None };
        return result;
    }
    Ok(())
}

fn config() -> &'static Config {
    // SAFETY: called after successful startup or by the worker it created.
    unsafe { (*CONFIG.0.get()).as_ref().expect("heap worker initialized") }
}

fn grow(heap: &mut Allocator, needed: usize, alignment: usize) -> Result<(), Error> {
    let length = needed
        .checked_add(alignment)
        .ok_or(Error::NoMemory)?
        .max(CHUNK)
        .checked_add(PAGE - 1)
        .ok_or(Error::NoMemory)?
        & !(PAGE - 1);
    let address = BASE.checked_add(heap.committed()).ok_or(Error::NoMemory)?;
    if address.checked_add(length).is_none_or(|end| end > LIMIT) {
        return Err(Error::NoMemory);
    }
    let memory = sys::mem_create(length as u64).map_err(|_| Error::NoMemory)?;
    sys::mem_map(
        &config().process,
        &memory,
        0,
        length as u64,
        address,
        rt::abi::Access::ReadWrite,
    )
    .map_err(|_| Error::NoMemory)?;
    // SAFETY: mapping committed a disjoint contiguous range exclusively to heap.
    unsafe {
        if heap.committed() == 0 {
            heap.init(address as *mut u8, length);
        } else {
            heap.extend(length);
        }
    }
    Ok(())
}

fn allocate(heap: &mut Allocator, size: usize, alignment: usize) -> Result<NonNull<u8>, Error> {
    let needed = Allocator::required(size, alignment)?;
    if let Ok(pointer) = heap.allocate(size, alignment) {
        return Ok(pointer);
    }
    grow(heap, needed, alignment)?;
    heap.allocate(size, alignment)
}

fn perform(heap: &mut Allocator, words: [u64; 8]) -> Result<usize, Error> {
    let size = words[1] as usize;
    let alignment = words[2] as usize;
    let pointer = words[3] as *mut u8;
    match words[0] {
        ALLOC | ZERO => {
            let result = allocate(heap, size, alignment)?;
            if words[0] == ZERO {
                // SAFETY: result owns at least size writable bytes.
                unsafe { result.as_ptr().write_bytes(0, size) };
            }
            Ok(result.as_ptr() as usize)
        }
        REALLOC => {
            let Some(pointer) = NonNull::new(pointer) else {
                return allocate(heap, size, FUNDAMENTAL_ALIGNMENT).map(|p| p.as_ptr() as usize);
            };
            // SAFETY: realloc callers supply a live allocation from this heap.
            match unsafe { heap.reallocate(pointer, size) } {
                Ok(result) => Ok(result.as_ptr() as usize),
                Err(Error::NoMemory) => {
                    let alignment = unsafe { Allocator::alignment(pointer) };
                    grow(heap, Allocator::required(size, alignment)?, alignment)?;
                    unsafe { heap.reallocate(pointer, size) }.map(|p| p.as_ptr() as usize)
                }
                Err(error) => Err(error),
            }
        }
        FREE => {
            if let Some(pointer) = NonNull::new(pointer) {
                // SAFETY: free callers supply a uniquely live allocation from this heap.
                unsafe { heap.deallocate(pointer) };
            }
            Ok(0)
        }
        _ => Err(Error::InvalidAlignment),
    }
}

extern "C" fn worker(_: u64) -> ! {
    assert!(READY.load(Ordering::Acquire), "published heap owner");
    let mut heap = Allocator::new();
    let mut journal = replies::Journal::new();
    loop {
        let Ok(sys::Received::Message {
            len,
            words,
            token,
            handles,
            ..
        }) = sys::receive(&config().channel)
        else {
            continue;
        };
        drop(handles);
        #[cfg(feature = "transport-probe")]
        if len == 40 && words[0] == 6 {
            let (used, committed) = journal.stats();
            let mut bytes = [0; 32];
            for (i, value) in [used, committed, heap.used(), heap.committed()]
                .iter()
                .enumerate()
            {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&(*value as u64).to_le_bytes());
            }
            let _ = token.reply(&bytes);
            continue;
        }
        let nonce = words[4];
        let args = [words[0], words[1], words[2], words[3]];
        let (status, value) = if len != 40 || nonce == 0 {
            (EINVAL, 0)
        } else if words[0] == ACK {
            journal.ack(nonce);
            #[cfg(feature = "transport-probe")]
            {
                let target = ACK_TARGET.swap(0, Ordering::AcqRel);
                if target != 0 {
                    let native = Handle::borrowed(rt::abi::Handle(target));
                    sys::thread_interrupt(&native).expect("heap ACK caller");
                    ACK_INTERRUPTS.fetch_add(1, Ordering::Release);
                }
            }
            (0, 0)
        } else if let Some(answer) = journal.ready(nonce, args) {
            answer
        } else {
            match journal.reserve(nonce, args) {
                Err(code) => (code, 0),
                Ok(record) => {
                    let answer = match perform(&mut heap, words) {
                        Ok(value) => (0, value),
                        Err(Error::NoMemory) => (ENOMEM, 0),
                        Err(Error::InvalidAlignment) => (EINVAL, 0),
                    };
                    journal.complete(record, answer);
                    #[cfg(feature = "transport-probe")]
                    if UPCALL_OPS.fetch_and(!(1 << words[0]), Ordering::AcqRel) & (1 << words[0])
                        != 0
                    {
                        let native = Handle::borrowed(rt::abi::Handle(
                            NATIVE_TARGET.load(Ordering::Acquire),
                        ));
                        sys::thread_upcall_request(&native).expect("heap caller after commit");
                    }
                    answer
                }
            }
        };
        let mut reply = [0; 16];
        reply[..8].copy_from_slice(&(status as u64).to_le_bytes());
        reply[8..].copy_from_slice(&(value as u64).to_le_bytes());
        let _ = token.reply(&reply);
    }
}

fn request(op: u64, size: usize, alignment: usize, pointer: *mut u8) -> Result<*mut u8, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(ENOMEM);
    }
    let nonce = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| ENOMEM)?;
    let bytes = packet([op, size as u64, alignment as u64, pointer as u64, nonce]);
    let result = call(&bytes)?;
    let answer = if result.0 == 0 {
        Ok(result.1 as *mut u8)
    } else {
        Err(result.0)
    };
    let ack = call(&packet([ACK, 0, 0, 0, nonce]))?;
    if ack != (0, 0) {
        return Err(ENOMEM);
    }
    answer
}
fn packet(words: [u64; 5]) -> [u8; 40] {
    let mut bytes = [0; 40];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn call(bytes: &[u8; 40]) -> Result<(i32, usize), i32> {
    loop {
        let reply = match sys::send(&config().channel, bytes) {
            Err(rt::abi::Error::Interrupted) => continue,
            result => result.map_err(|_| ENOMEM)?,
        };
        if reply.len != 16 || !reply.handles.is_empty() {
            return Err(ENOMEM);
        }
        return Ok((reply.words[0] as i32, reply.words[1] as usize));
    }
}
/// The base priority of the live heap worker.
#[cfg(feature = "transport-probe")]
pub fn probe_worker_base() -> u8 {
    let raw = rt::abi::Handle(WORKER.load(Ordering::Acquire));
    let thread = Handle::<rt::handle::Thread>::borrowed(raw);
    sys::thread_info(&thread).expect("heap worker info").base
}
#[cfg(feature = "transport-probe")]
pub fn probe_upcall(thread: &Handle<rt::handle::Thread>, op: u64) {
    assert!((ALLOC..=ZERO).contains(&op));
    NATIVE_TARGET.store(thread.raw().0, Ordering::Release);
    UPCALL_OPS.fetch_or(1 << op, Ordering::Release);
}
#[cfg(feature = "transport-probe")]
pub fn probe_ack_interrupt(thread: &Handle<rt::handle::Thread>) {
    ACK_TARGET.store(thread.raw().0, Ordering::Release);
}
#[cfg(feature = "transport-probe")]
pub fn probe_ack_interrupts() -> u64 {
    ACK_INTERRUPTS.load(Ordering::Acquire)
}
#[cfg(feature = "transport-probe")]
pub fn probe_reject_new(reject: bool) {
    REJECT_NEW.store(reject, Ordering::Release);
}
#[cfg(feature = "transport-probe")]
pub fn probe_call(args: [u64; 4], nonce: u64) -> Result<(i32, usize), i32> {
    call(&packet([args[0], args[1], args[2], args[3], nonce]))
}
#[cfg(feature = "transport-probe")]
pub fn probe_ack(nonce: u64) -> Result<(i32, usize), i32> {
    call(&packet([ACK, 0, 0, 0, nonce]))
}
#[cfg(feature = "transport-probe")]
pub fn probe_stats() -> (u64, u64, u64, u64) {
    loop {
        let reply = match sys::send(&config().channel, &packet([6, 0, 0, 0, 0])) {
            Err(rt::abi::Error::Interrupted) => continue,
            result => result.expect("heap diagnostic query"),
        };
        assert_eq!(reply.len, 32);
        return (
            reply.words[0],
            reply.words[1],
            reply.words[2],
            reply.words[3],
        );
    }
}

fn returned(result: Result<*mut u8, i32>) -> *mut u8 {
    result.unwrap_or_else(|code| {
        fail(code);
        ptr::null_mut()
    })
}

/// # Safety
/// This thread has an initialized errno scope and the process heap is initialized.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    returned(request(ALLOC, size, FUNDAMENTAL_ALIGNMENT, ptr::null_mut()))
}

/// # Safety
/// Same initialization contract as malloc.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut u8 {
    let Some(size) = count.checked_mul(size) else {
        return returned(Err(ENOMEM));
    };
    returned(request(ZERO, size, FUNDAMENTAL_ALIGNMENT, ptr::null_mut()))
}

/// # Safety
/// pointer is null or a live allocation from this process heap, with no
/// overlapping accesses; the initialization contract of malloc also applies.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn realloc(pointer: *mut u8, size: usize) -> *mut u8 {
    returned(request(REALLOC, size, 0, pointer))
}

/// # Safety
/// Same contract as realloc. Multiplication failure preserves the allocation.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn reallocarray(pointer: *mut u8, count: usize, size: usize) -> *mut u8 {
    let Some(size) = count.checked_mul(size) else {
        return returned(Err(ENOMEM));
    };
    unsafe { realloc(pointer, size) }
}

/// # Safety
/// pointer is null or a uniquely live allocation from this process heap.
/// Free preserves errno, including for a null pointer.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn free(pointer: *mut u8) {
    if !pointer.is_null() {
        let _ = request(FREE, 0, 0, pointer);
    }
}

/// # Safety
/// Same initialization contract as malloc. alignment is a nonzero power of two
/// and size is a multiple of alignment; invalid values report EINVAL.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut u8 {
    if !alignment.is_power_of_two() || !size.is_multiple_of(alignment) {
        return returned(Err(EINVAL));
    }
    returned(request(ALLOC, size, alignment, ptr::null_mut()))
}

/// # Safety
/// out is writable/aligned for one pointer, and malloc's initialization holds.
/// Failure preserves out and errno; the result is an error number directly.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_memalign(out: *mut *mut u8, alignment: usize, size: usize) -> i32 {
    if out.is_null() {
        return EFAULT;
    }
    if alignment < core::mem::size_of::<usize>() || !alignment.is_power_of_two() {
        return EINVAL;
    }
    match request(ALLOC, size, alignment, ptr::null_mut()) {
        Ok(pointer) => {
            unsafe { out.write(pointer) };
            0
        }
        Err(code) => code,
    }
}

/// Borrow the process handle kept alive by the initialized heap owner.
pub(crate) fn process() -> &'static Handle<Process> {
    assert!(READY.load(Ordering::Acquire), "published heap process");
    &config().process
}
