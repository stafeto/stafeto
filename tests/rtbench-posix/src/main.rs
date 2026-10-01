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
const PING_METHOD: u16 = 7;

/// One empty round trip to the service of long operations through its
/// loop (rt::service::run): 0, or -1 when it failed.
#[unsafe(no_mangle)]
pub extern "C" fn rtbench_ping() -> c_int {
    // SAFETY: one thread pings, so no other borrow of the session exists.
    let session = unsafe { &mut *PING.0.get() };
    if !CONNECTED.load(Ordering::Relaxed) {
        let parent = Handle::<Channel>::borrowed(abi::START_CHANNEL);
        match rt::service::connect(&parent, "uart") {
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
