// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A reply lost to a signal costs a repeat, and the repeat gives the same result.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use posix_abi::lock_fields::Flock;

static LOSE: AtomicBool = AtomicBool::new(false);
static LOST: AtomicUsize = AtomicUsize::new(0);

fn hook() -> bool {
    let lose = LOSE.swap(false, Ordering::SeqCst);
    if lose {
        LOST.fetch_add(1, Ordering::SeqCst);
    }
    lose
}
fn request(
    fd: i32,
    command: i32,
    kind: i16,
    start: i64,
    length: i64,
) -> (Result<i32, i32>, [u8; 32]) {
    let mut words = [u64::from_ne_bytes([0xa5; 8]); 4];
    let pointer = words.as_mut_ptr().cast::<u8>();
    // SAFETY: the aligned local array owns a complete AArch64 flock invocation.
    let outcome = unsafe {
        let flock = &mut *pointer.cast::<Flock>();
        flock.kind = kind;
        flock.whence = 0;
        flock.start = start;
        flock.length = length;
        flock.pid = 0;
        posix_abi::file_lock(fd, command, pointer)
    };
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    (outcome, bytes)
}
fn lost_once(fd: i32, command: i32, kind: i16, start: i64, length: i64) -> (Result<i32, i32>, [u8; 32]) {
    LOSE.store(true, Ordering::SeqCst);
    let before = LOST.load(Ordering::SeqCst);
    let answer = request(fd, command, kind, start, length);
    LOSE.store(false, Ordering::SeqCst);
    if LOST.load(Ordering::SeqCst) != before + 1 {
        return (Err(-1), [0; 32]);
    }
    answer
}
fn full_blocker(bytes: &[u8; 32]) -> bool {
    i16::from_ne_bytes(bytes[..2].try_into().unwrap()) == 0
        && i16::from_ne_bytes(bytes[2..4].try_into().unwrap()) == 0
        && i64::from_ne_bytes(bytes[8..16].try_into().unwrap()) == 117
        && i64::from_ne_bytes(bytes[16..24].try_into().unwrap()) == 0
        && i32::from_ne_bytes(bytes[24..28].try_into().unwrap()) == -1
        && bytes[4..8] == [0xa5; 4]
        && bytes[28..32] == [0xa5; 4]
}
fn idle() -> bool {
    posix_abi::shared::with_files(|files| Ok(files.no_lock_command())).unwrap_or(false)
}
fn run(fd: i32) -> Result<(), i32> {
    if request(fd, 37, 2, 0, 0).0 != Ok(0) {
        return Err(-1);
    }
    if request(fd, 37, 0, 117, 0).0 != Ok(0) {
        return Err(-2);
    }
    for _ in 0..8 {
        // A lost GET reply: the repeat returns the whole blocker.
        let (result, bytes) = lost_once(fd, 5, 1, 0, 0);
        if result != Ok(0) || !full_blocker(&bytes) || !idle() {
            return Err(-3);
        }
        // A lost SET reply: the repeat changes nothing more and succeeds.
        if lost_once(fd, 6, 1, 20, 5).0 != Ok(0) || !idle() {
            return Err(-4);
        }
        let (result, bytes) = request(fd, 36, 1, 20, 5);
        if result != Ok(0)
            || i16::from_ne_bytes(bytes[..2].try_into().unwrap()) != 1
            || i32::from_ne_bytes(bytes[24..28].try_into().unwrap()) <= 0
        {
            return Err(-5);
        }
        // A lost unlock reply.
        if lost_once(fd, 6, 2, 20, 5).0 != Ok(0) || !idle() {
            return Err(-6);
        }
    }
    // A refusal repeats as a refusal.
    let (result, _) = lost_once(-1, 5, 1, 0, 0);
    if result != Err(posix_abi::constants::EBADF) {
        return Err(-7);
    }
    if request(fd, 37, 2, 0, 0).0 != Ok(0) {
        return Err(-8);
    }
    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn lock_driver_receipts(fd: i32) -> i32 {
    let began = rt::time::now();
    posix_abi::probe_lock_hook(Some(hook));
    let result = run(fd);
    posix_abi::probe_lock_hook(None);
    if result.is_ok() {
        rt::println!(
            "posix-procs: public lock replies lost to a signal repeat with the same result ok ticks={}",
            rt::time::now().saturating_sub(began)
        );
    }
    result.map_or_else(|code| code, |()| 0)
}
