// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real public requests keep exact keys across lost replies and numeric close.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use posix_abi::{LockProbe, constants::EBADF, lock_fields::Flock};
use posix_fs::change::ControlToken;

const LOSS_START: u8 = 1;
const LOSS_QUERY: u8 = 2;
const LOSS_RELEASE: u8 = 3;
const CLOSE_START: u8 = 4;
const CLOSE_RELEASE: u8 = 5;
static MODE: AtomicU8 = AtomicU8::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static BAD_KEYS: AtomicUsize = AtomicUsize::new(0);
static COUNTS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static LOST: AtomicBool = AtomicBool::new(false);
static CLOSED: AtomicBool = AtomicBool::new(false);
static CLOSE_ERROR: AtomicI32 = AtomicI32::new(0);
static NUMBER: AtomicI32 = AtomicI32::new(-1);

fn index(stage: LockProbe) -> usize {
    match stage {
        LockProbe::Start => 0,
        LockProbe::Query => 1,
        LockProbe::Cancel => 2,
        LockProbe::Release => 3,
    }
}
fn hook(stage: LockProbe, token: ControlToken) -> bool {
    let count = index(stage);
    COUNTS[count].fetch_add(1, Ordering::SeqCst);
    if GENERATION
        .compare_exchange(0, token.generation(), Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        SLOT.store(token.slot(), Ordering::SeqCst);
    } else if GENERATION.load(Ordering::SeqCst) != token.generation()
        || SLOT.load(Ordering::SeqCst) != token.slot()
    {
        BAD_KEYS.fetch_add(1, Ordering::SeqCst);
    }
    let mode = MODE.load(Ordering::SeqCst);
    let close_here = mode == CLOSE_START && stage == LockProbe::Start
        || mode == CLOSE_RELEASE && stage == LockProbe::Release;
    if close_here
        && !CLOSED.swap(true, Ordering::SeqCst)
        && let Err(errno) = posix_abi::close(NUMBER.load(Ordering::SeqCst))
    {
        CLOSE_ERROR.store(errno, Ordering::SeqCst);
    }
    let lose_here = mode == LOSS_START && stage == LockProbe::Start
        || mode == LOSS_QUERY && stage == LockProbe::Query
        || mode == LOSS_RELEASE && stage == LockProbe::Release
        || mode == CLOSE_START && stage == LockProbe::Cancel;
    lose_here && !LOST.swap(true, Ordering::SeqCst)
}
fn begin(mode: u8, fd: i32) {
    MODE.store(mode, Ordering::SeqCst);
    GENERATION.store(0, Ordering::SeqCst);
    SLOT.store(usize::MAX, Ordering::SeqCst);
    BAD_KEYS.store(0, Ordering::SeqCst);
    for count in &COUNTS {
        count.store(0, Ordering::SeqCst);
    }
    LOST.store(false, Ordering::SeqCst);
    CLOSED.store(false, Ordering::SeqCst);
    CLOSE_ERROR.store(0, Ordering::SeqCst);
    NUMBER.store(fd, Ordering::SeqCst);
    posix_abi::probe_lock_hook(Some(hook));
}
fn end() -> bool {
    posix_abi::probe_lock_hook(None);
    GENERATION.load(Ordering::SeqCst) != 0 && BAD_KEYS.load(Ordering::SeqCst) == 0
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
fn full_blocker(bytes: &[u8; 32]) -> bool {
    i16::from_ne_bytes(bytes[..2].try_into().unwrap()) == 0
        && i16::from_ne_bytes(bytes[2..4].try_into().unwrap()) == 0
        && i64::from_ne_bytes(bytes[8..16].try_into().unwrap()) == 117
        && i64::from_ne_bytes(bytes[16..24].try_into().unwrap()) == 0
        && i32::from_ne_bytes(bytes[24..28].try_into().unwrap()) == -1
        && bytes[4..8] == [0xa5; 4]
        && bytes[28..32] == [0xa5; 4]
}
fn run(fd: i32) -> Result<(), i32> {
    if request(fd, 37, 2, 0, 0).0 != Ok(0) {
        return Err(-1);
    }
    if request(fd, 37, 0, 117, 0).0 != Ok(0) {
        return Err(-2);
    }
    // More than the sixteen paid Control places must remain available after each ack.
    for mode in [LOSS_START, LOSS_QUERY, LOSS_RELEASE] {
        for _ in 0..8 {
            begin(mode, fd);
            let (result, bytes) = request(fd, 5, 1, 0, 0);
            let stable = end();
            if result != Ok(0) || !full_blocker(&bytes) || !stable || !LOST.load(Ordering::SeqCst) {
                return Err(-10 - i32::from(mode));
            }
            let target = match mode {
                LOSS_START => 0,
                LOSS_QUERY => 1,
                _ => 3,
            };
            if COUNTS[target].load(Ordering::SeqCst) < 2 {
                return Err(-20 - i32::from(mode));
            }
        }
    }
    if request(fd, 37, 2, 0, 0).0 != Ok(0) {
        return Err(-30);
    }
    for _ in 0..20 {
        let alias = posix_abi::dup(fd).map_err(|_| -31)?;
        begin(CLOSE_START, alias);
        let (result, _) = request(alias, 37, 0, 123, 1);
        let stable = end();
        // Close may order after the effect; the genuine canonical result decides.
        if !matches!(result, Ok(0) | Err(EBADF))
            || !stable
            || !CLOSED.load(Ordering::SeqCst)
            || CLOSE_ERROR.load(Ordering::SeqCst) != 0
            || !LOST.load(Ordering::SeqCst)
            || COUNTS[2].load(Ordering::SeqCst) < 2
        {
            return Err(-32);
        }
        let reused = posix_abi::dup(fd).map_err(|_| -33)?;
        if reused != alias {
            return Err(-34);
        }
        let (result, _) = request(reused, 37, 2, 0, 0);
        if result != Ok(0) {
            return Err(-35);
        }
        posix_abi::close(reused).map_err(|_| -36)?;
    }
    let alias = posix_abi::dup(fd).map_err(|_| -40)?;
    begin(CLOSE_RELEASE, alias);
    let (result, bytes) = request(alias, 37, 0, 137, 1);
    let stable = end();
    if result != Ok(0)
        || !stable
        || !CLOSED.load(Ordering::SeqCst)
        || CLOSE_ERROR.load(Ordering::SeqCst) != 0
    {
        return Err(-41);
    }
    let (second, original) = request(fd, 37, 0, 137, 1);
    if second != Ok(0) || bytes != original {
        return Err(-42);
    }
    if request(fd, 37, 2, 0, 0).0 != Ok(0) {
        return Err(-43);
    }
    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn lock_driver_receipts(fd: i32) -> i32 {
    let began = rt::time::now();
    let result = run(fd);
    posix_abi::probe_lock_hook(None);
    if result.is_ok() {
        rt::println!(
            "posix-procs: public lock reply loss, exact keys, full GET receipt, numeric close and reuse ok ticks={}",
            rt::time::now().saturating_sub(began)
        );
    }
    result.map_or_else(|code| code, |()| 0)
}
