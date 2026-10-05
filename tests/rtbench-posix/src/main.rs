// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! rtbench 2: the scenarios are C through pthread and POSIX (rtbench.c),
//! started by the Rust POSIX startup (posix-crt) with standard input from
//! the service `uart`, which in the image of the benchmark is the test
//! service of long operations (tests/svc, `long.rs`). This file is the
//! platform part the C program calls by name `rtbench_*`: the length of the
//! run, the count of kernel calls (rt, feature `count-calls`), the level
//! of the calling thread, the empty round trip through rt::service and the
//! output through the console, which the console's driver shows. With
//! another libc only this part changes.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicBool, Ordering};
use proto_wire::{Header, Writer};
use rt::handle::{Channel, Handle};
use rt::sys;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// The seconds of rounds the run makes, from the build (`RTBENCH_SECONDS`,
/// which xtask sets); without it, one round.
const SECONDS: u64 = match option_env!("RTBENCH_SECONDS") {
    Some(text) => parse(text),
    None => 0,
};

const fn parse(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let mut value = 0u64;
    let mut index = 0;
    while index < bytes.len() {
        assert!(bytes[index].is_ascii_digit(), "RTBENCH_SECONDS is a number");
        value = value * 10 + (bytes[index] - b'0') as u64;
        index += 1;
    }
    value
}

#[unsafe(no_mangle)]
pub extern "C" fn rtbench_seconds() -> u64 {
    SECONDS
}

/// The kernel calls of the process so far: of all its threads, the
/// helper threads of the POSIX layer among them.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_calls() -> u64 {
    sys::calls()
}

/// The calls the counter sees for one `yield`: 1 when it counts each call
/// once. The counter is the process's: a helper thread of the layer that
/// wakes during one try adds its calls, so the least of eight tries counts.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_counter_check() -> u64 {
    (0..8)
        .map(|_| {
            let before = sys::calls();
            if sys::yield_now().is_err() {
                return u64::MAX;
            }
            sys::calls() - before
        })
        .min()
        .unwrap_or(u64::MAX)
}

/// The calling thread to kernel level `level` under FIFO: 0, or the
/// error number.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_level(level: c_int) -> c_int {
    let Ok(level) = u8::try_from(level) else {
        return posix_abi::constants::EINVAL;
    };
    posix_abi::threads::set_level(level).map_or_else(|error| error, |()| 0)
}

struct Session(UnsafeCell<Option<Handle<Channel>>>);
// SAFETY: only the main thread of the benchmark pings (rtbench.c, S9),
// after it connected once.
unsafe impl Sync for Session {}
static PING: Session = Session(UnsafeCell::new(None));
static CONNECTED: AtomicBool = AtomicBool::new(false);
/// PING of the service of long operations (tests/svc, long.rs).
const PING_METHOD: u16 = 16;

/// One empty round trip to the service of long operations through its
/// loop (rt::service::run): 0, or -1 when it failed.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_ping() -> c_int {
    // SAFETY: one thread pings, so no other borrow of the session exists.
    let session = unsafe { &mut *PING.0.get() };
    if !CONNECTED.load(Ordering::Relaxed) {
        let parent = Handle::<Channel>::borrowed(abi::START_CHANNEL);
        match rt::service::connect(&parent, "bench-uart") {
            Ok(channel) => *session = Some(channel),
            Err(_) => return -1,
        }
        CONNECTED.store(true, Ordering::Relaxed);
    }
    let Some(channel) = session.as_ref() else {
        return -1;
    };
    let mut w = Writer::new();
    if Header::new(PING_METHOD, proto_uart::VERSION)
        .write(&mut w)
        .is_err()
    {
        return -1;
    }
    match sys::send(channel, w.as_bytes()) {
        Ok(reply) if reply.len == proto_wire::HEADER_LEN && reply.words[0] as u32 == 0 => 0,
        _ => -1,
    }
}

/// ROUNDS of the load (tests/rtbench-load).
const ROUNDS_METHOD: u16 = 1;

/// The rounds the hostile load made so far: u64::MAX once one failed, and
/// u64::MAX - 1 when it does not answer.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_load_rounds() -> u64 {
    const SILENT: u64 = u64::MAX - 1;
    let parent = Handle::<Channel>::borrowed(abi::START_CHANNEL);
    let Ok(load) = rt::service::connect(&parent, "rtbench-load") else {
        return SILENT;
    };
    let mut w = Writer::new();
    if Header::new(ROUNDS_METHOD, 1).write(&mut w).is_err() {
        return SILENT;
    }
    match sys::send(&load, w.as_bytes()) {
        Ok(reply) if reply.len == 12 && reply.words[0] as u32 == 0 => {
            (reply.words[0] >> 32) | (reply.words[1] << 32)
        }
        _ => SILENT,
    }
}

/// Wait by address of the layer (posix-sync) while `*word == value`: 0
/// woken, or the error number. With relibc this is `Pal::futex_wait`.
///
/// # Safety
/// `word` is a live aligned word.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtbench_futex_wait(word: *const u32, value: u32) -> c_int {
    // SAFETY: the caller's promise; the word is used atomically.
    let word = unsafe { &*word.cast::<core::sync::atomic::AtomicU32>() };
    match posix_sync::futex_wait(word, value, posix_sync::CLOCK_MONOTONIC, None) {
        Ok(_) => 0,
        Err(error) => error,
    }
}

/// Wakes up to `count` waiters on `word`: how many.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_futex_wake(word: *const u32, count: u32) -> u32 {
    posix_sync::futex_wake(word.cast(), count)
}

/// A word of `words` (`count` of them) in the bucket of `word` other than
/// itself, or null.
///
/// # Safety
/// `words` names `count` words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtbench_neighbour(
    word: *const u32,
    words: *const u32,
    count: usize,
) -> *const u32 {
    let wanted = posix_sync::bucket_of(word.cast());
    (0..count)
        // SAFETY: the caller's promise.
        .map(|index| unsafe { words.add(index) })
        .find(|&other| other != word && posix_sync::bucket_of(other.cast()) == wanted)
        .unwrap_or(core::ptr::null())
}

/// Writes `length` bytes at `text` to the console.
///
/// # Safety
/// `text` points to `length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtbench_say(text: *const c_char, length: usize) {
    // SAFETY: the caller's promise.
    let bytes = unsafe { core::slice::from_raw_parts(text.cast::<u8>(), length) };
    let _ = rt::console::write(bytes);
}

/// Preserve the original long-operation UART for S5/S6 before any file opens.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_io_init() -> c_int {
    let parent = posix_crt::parent();
    let (Ok(ram), Ok(uart), Ok(pipe)) = (
        rt::service::connect(&parent, "ramfs"),
        rt::service::connect(&parent, "bench-uart"),
        rt::service::connect(&parent, "pipe"),
    ) else {
        return -1;
    };
    let startup = posix_fs::StartupFiles::from_sessions(ram, Some(uart), Some(pipe), None);
    let Some(identity) = posix_abi::process::identity() else {
        return -1;
    };
    if startup.bind(identity).is_err() {
        return -1;
    }
    match posix_abi::shared::with_files(|files| Ok(files.replace_initial_transports(startup))) {
        Ok(Ok(old)) => {
            drop(old);
            0
        }
        // Both transport sets are returned out of FILES_LOCK before any Drop.
        Ok(Err((_, incoming))) => {
            drop(incoming);
            -1
        }
        Err(_) => -1,
    }
}

/// TTY is attached only while the new scenarios run; existing fds survive.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_terminals(enabled: c_int) -> c_int {
    let terminal = match enabled {
        0 => None,
        1 => match rt::service::connect(&posix_crt::parent(), "tty") {
            Ok(terminal) => Some(terminal),
            Err(_) => return -1,
        },
        _ => return -1,
    };
    posix_abi::shared::with_files(|files| {
        files.set_terminal(terminal);
        Ok(())
    })
    .map_or(-1, |()| 0)
}

const NATIVE_AT: usize = 0x6000_0000;
const NATIVE_BUFFERS_AT: usize = 0x7000_0000;
const PAGE: usize = 4096;
const NATIVE_MAX: usize = abi::MAX_THREADS as usize;
static NATIVE_READY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static NATIVE_RESUMED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

struct Native {
    thread: Handle<rt::handle::Thread>,
    channel: Handle<Channel>,
}
struct Population {
    // The mapping and its handles live until this spawned process exits.
    _memory: Handle<rt::handle::Memory>,
    list: [Option<Native>; NATIVE_MAX],
    count: usize,
}
struct NativePopulation(UnsafeCell<Option<Population>>);
// SAFETY: only the main thread of role stop128 accesses the population.
// Workers access their borrowed channel and the separate atomic counters.
unsafe impl Sync for NativePopulation {}
static NATIVE: NativePopulation = NativePopulation(UnsafeCell::new(None));

extern "C" fn native_wait(raw: u64) -> ! {
    let channel = Handle::<Channel>::borrowed(abi::Handle(raw));
    NATIVE_READY.fetch_add(1, Ordering::Release);
    loop {
        match sys::receive(&channel) {
            Ok(sys::Received::Notification { bits, .. }) if bits & 1 != 0 => {
                NATIVE_RESUMED.fetch_add(1, Ordering::Release);
            }
            Ok(_) | Err(abi::Error::Interrupted) => {}
            Err(_) => sys::process_exit(71),
        }
    }
}

/// Fill this child's remaining kernel places, including any existing helpers.
/// LimitReached is accepted only with spare handle entries, after all created
/// threads have started and reached Receiving. Its kernel limit is 128.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_threads128() -> c_int {
    let process = posix_abi::allocation::process();
    // SAFETY: role stop128 calls this once on its only application thread.
    let saved = unsafe { &mut *NATIVE.0.get() };
    if saved.is_some() {
        return -1;
    }
    let Ok(memory) = sys::mem_create((NATIVE_MAX * PAGE) as u64) else {
        return -1;
    };
    if sys::mem_map(
        process,
        &memory,
        0,
        (NATIVE_MAX * PAGE) as u64,
        NATIVE_AT,
        abi::Access::ReadWrite,
    )
    .is_err()
    {
        return -1;
    }
    let mut population = Population {
        _memory: memory,
        list: core::array::from_fn(|_| None),
        count: 0,
    };
    for index in 0..NATIVE_MAX {
        let Ok(channel) = sys::channel_create(31) else {
            return -1;
        };
        let Ok(handles) = sys::process_handles(process) else {
            return -1;
        };
        if handles.live + handles.retired + 1 >= handles.limit {
            return -1;
        }
        let stack = NATIVE_AT + (index + 1) * PAGE;
        let buffer = NATIVE_BUFFERS_AT + index * PAGE;
        // SAFETY: each worker has its own mapped stack and a fresh unmapped
        // IPC page. The kernel maps that page; both live until process exit.
        let made = unsafe {
            sys::thread_create(
                process,
                native_wait,
                stack,
                channel.raw().0,
                31,
                abi::Policy::Fifo,
                buffer,
            )
        };
        let thread = match made {
            Err(abi::Error::LimitReached) if population.count > 0 => {
                if NATIVE_READY.load(Ordering::Acquire) as usize != population.count {
                    return -1;
                }
                *saved = Some(population);
                return NATIVE_MAX as c_int;
            }
            Ok(thread) => thread,
            Err(_) => return -1,
        };
        if sys::thread_start(&thread).is_err()
            || !matches!(sys::thread_info(&thread), Ok(info) if info.state == abi::ThreadState::Receiving)
        {
            return -1;
        }
        population.list[index] = Some(Native { thread, channel });
        population.count += 1;
    }
    -1
}

/// After CONT, every created thread receives a notice and executes again.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_resumed128() -> c_int {
    // SAFETY: only the child main calls this; population stays immutable.
    let Some(population) = (unsafe { &*NATIVE.0.get() }).as_ref() else {
        return -1;
    };
    NATIVE_RESUMED.store(0, Ordering::Release);
    for worker in population.list.iter().flatten() {
        if sys::notify(&worker.channel, 1).is_err()
            || !matches!(sys::thread_info(&worker.thread), Ok(info) if info.state == abi::ThreadState::Receiving)
        {
            return -1;
        }
    }
    if NATIVE_RESUMED.load(Ordering::Acquire) as usize == population.count {
        128
    } else {
        -1
    }
}

/// Native workers counted during setup, before the parent starts timing.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_native_count() -> c_int {
    // SAFETY: only role stop128 main accesses this immutable population.
    unsafe { &*NATIVE.0.get() }
        .as_ref()
        .map_or(-1, |p| p.count as c_int)
}
