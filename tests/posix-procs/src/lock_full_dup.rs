// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Synchronous scalar snapshots preserve ordinary replacement ownership.
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use posix_fs::{RamTarget, Target};
static SEEN: AtomicU32 = AtomicU32::new(0);
static EVENT: [AtomicU64; 10] = [const { AtomicU64::new(0) }; 10];
fn packed(target: RamTarget) -> u64 {
    u64::from(target.fd() | (target.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT))
}
fn sample(files: &posix_fs::PosixFs, fd: u32) -> Result<[u64; 4], i32> {
    let entry = files.lock_source(fd).map_err(|_| -1)?;
    let Target::Ram(target) = files.target(fd).map_err(|_| -1)? else {
        return Err(-1);
    };
    Ok([
        u64::from(fd),
        entry.generation(),
        packed(target),
        target.generation(),
    ])
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_dup_sample(fd: u32, output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    match posix_abi::shared::with_files(|files| sample(files, fd)) {
        Ok(words) => {
            // SAFETY: the caller supplies four synchronous output cells.
            unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, 4) };
            0
        }
        Err(_) => -1,
    }
}
fn close(phase: posix_abi::CloseProbe, token: posix_fs::closing::CloseToken) -> bool {
    if phase != posix_abi::CloseProbe::Event {
        return false;
    }
    let result = posix_abi::shared::with_files(|files| {
        let snapshot = files.close_snapshot(token).map_err(|_| -1)?;
        let Target::Ram(old) = snapshot.backend else {
            return Err(-1);
        };
        let (next_packed, next_generation, flags) = match snapshot.replacement {
            Some((Target::Ram(next), flags)) => (
                packed(next),
                next.generation(),
                u64::from(flags.close_on_exec) | (u64::from(flags.close_on_fork) << 1),
            ),
            None => (0, 0, 0),
            _ => return Err(-1),
        };
        Ok([
            u64::from(snapshot.entry.fd),
            snapshot.entry.generation(),
            packed(old),
            old.generation(),
            next_packed,
            next_generation,
            flags,
            u64::from(snapshot.last_alias),
            token.slot() as u64,
            token.generation(),
        ])
    });
    match result {
        Ok(words) => {
            let seen = SEEN.load(Ordering::Acquire);
            if seen == 0 {
                for (place, word) in EVENT.iter().zip(words) {
                    place.store(word, Ordering::Relaxed);
                }
                SEEN.store(1, Ordering::Release);
            } else if seen != 1
                || EVENT
                    .iter()
                    .zip(words)
                    .any(|(place, word)| place.load(Ordering::Relaxed) != word)
            {
                SEEN.store(u32::MAX, Ordering::Release);
            }
        }
        Err(_) => SEEN.store(u32::MAX, Ordering::Release),
    }
    false
}
#[unsafe(no_mangle)]
pub extern "C" fn full_dup_arm() {
    SEEN.store(0, Ordering::Release);
    posix_abi::probe_close_hook(Some(close));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_dup_event(output: *mut u64) -> i32 {
    posix_abi::probe_close_hook(None);
    if output.is_null() || SEEN.load(Ordering::Acquire) != 1 {
        return -1;
    }
    for (index, place) in EVENT.iter().enumerate() {
        // SAFETY: the caller supplies ten output cells, without retained pointers.
        unsafe { output.add(index).write(place.load(Ordering::Relaxed)) };
    }
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn full_dup_no_event() -> i32 {
    posix_abi::probe_close_hook(None);
    if SEEN.load(Ordering::Acquire) == 0 {
        0
    } else {
        -1
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_dup_check(
    before: *const u64,
    after: *const u64,
    event: *const u64,
    last: u32,
) -> i32 {
    if before.is_null() || after.is_null() || event.is_null() || last > 1 {
        return -1;
    }
    // SAFETY: C supplies complete arrays throughout this synchronous comparison.
    let (before, after, event) = unsafe {
        (
            &*before.cast::<[u64; 12]>(),
            &*after.cast::<[u64; 12]>(),
            &*event.cast::<[u64; 10]>(),
        )
    };
    if super::lock_full_dup_wire::replacement(before, after, event, last == 1) {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn full_dup_key_valid(slot: u64, generation: u64) -> i32 {
    if super::lock_full_dup_wire::key(slot, generation) {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_dup_unchanged(
    before: *const u64,
    after: *const u64,
    source: i32,
    target: i32,
    next_source: i32,
    next_target: i32,
) -> i32 {
    if before.is_null() || after.is_null() {
        return -1;
    }
    // SAFETY: C retains both complete arrays during this synchronous call.
    let (before, after) = unsafe { (&*before.cast::<[u64; 12]>(), &*after.cast::<[u64; 12]>()) };
    if super::lock_full_dup_wire::unchanged(
        before,
        after,
        [source, target],
        [next_source, next_target],
    ) {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn full_dup_inodes(expected: u64, source: u64, target: u64) -> i32 {
    if super::lock_full_dup_wire::inodes(expected, source, target) {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_dup_effect(pages: *const u64, expected: *const u64) -> i32 {
    if pages.is_null() || expected.is_null() {
        return -1;
    }
    // SAFETY: C retains twenty complete telemetry pages and four expected cells.
    let (pages, expected) = unsafe {
        (
            &*pages.cast::<[[u64; 6]; 20]>(),
            &*expected.cast::<[u64; 4]>(),
        )
    };
    if super::lock_full_dup_wire::effect(pages, expected) {
        0
    } else {
        -1
    }
}
