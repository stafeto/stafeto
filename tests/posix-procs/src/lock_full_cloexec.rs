// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Old-image observers copy exact journal scalars before acknowledgement.
use super::lock_full_cloexec_wire::{self as wire, Outcome};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
static ARMED: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicBool = AtomicBool::new(false);
static RECORDS: [AtomicU64; 48] = [const { AtomicU64::new(0) }; 48];
unsafe extern "C" {
    fn full_cloexec_public(fd: u32) -> i32;
}
fn observe(token: posix_fs::closing::CloseToken, kind: Outcome) -> bool {
    let sampled = posix_abi::shared::with_files(|files| {
        let s = files.close_snapshot(token).map_err(|_| -1)?;
        let posix_fs::Target::Ram(target) = s.backend else {
            return Err(-1);
        };
        if s.replacement.is_some() {
            return Err(-1);
        }
        Ok([
            u64::from(s.entry.fd),
            s.entry.generation(),
            u64::from(target.fd() | target.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT),
            target.generation(),
            token.slot() as u64,
            token.generation(),
            u64::from(s.last_alias),
        ])
    });
    let Ok(sample) = sampled else {
        FAILED.store(true, Ordering::Release);
        return false;
    };
    for index in 0..ARMED.load(Ordering::Acquire) as usize {
        let other = [
            RECORDS[index * 24].load(Ordering::Acquire),
            RECORDS[index * 24 + 4].load(Ordering::Acquire),
            RECORDS[index * 24 + 5].load(Ordering::Acquire),
        ];
        if !wire::independent_key(sample[0], sample[4], sample[5], other) {
            FAILED.store(true, Ordering::Release);
            return false;
        }
    }
    for index in 0..ARMED.load(Ordering::Acquire) as usize {
        let cells = &RECORDS[index * 24..index * 24 + 24];
        if cells[0].load(Ordering::Relaxed) != sample[0] {
            continue;
        }
        let mut record = core::array::from_fn(|i| cells[i].load(Ordering::Relaxed));
        match wire::observe(&mut record, sample, kind) {
            Ok(drop_reply) => {
                for (cell, word) in cells.iter().zip(record) {
                    cell.store(word, Ordering::Release);
                }
                return drop_reply;
            }
            Err(()) => {
                FAILED.store(true, Ordering::Release);
                return false;
            }
        }
    }
    FAILED.store(true, Ordering::Release);
    false
}
fn attempt(phase: posix_abi::CloseProbe, token: posix_fs::closing::CloseToken) -> bool {
    let kind = match phase {
        posix_abi::CloseProbe::Event => Outcome::Attempt,
        posix_abi::CloseProbe::Physical => Outcome::Physical,
    };
    observe(token, kind)
}
fn accepted(token: posix_fs::closing::CloseToken) -> bool {
    observe(token, Outcome::Accepted)
}
fn public(fd: u32) -> bool {
    if FAILED.load(Ordering::Acquire) {
        return false;
    }
    // SAFETY: this fixture callback accepts one scalar and retains no pointers.
    unsafe { full_cloexec_public(fd) == 0 }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_cloexec_arm(state: *const u64) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: C supplies its complete static state during the stopped exec phase.
    let s = unsafe { core::slice::from_raw_parts(state, 352) };
    if !(3..=5).contains(&s[2]) {
        return -1;
    }
    for i in 0..wire::count(s[2]) {
        let at = wire::offset(i + 1).unwrap();
        for (cell, word) in RECORDS[i * 24..i * 24 + 24].iter().zip(&s[at..at + 24]) {
            cell.store(*word, Ordering::Relaxed);
        }
    }
    FAILED.store(false, Ordering::Release);
    ARMED.store(wire::count(s[2]) as u32, Ordering::Release);
    posix_abi::probe_close_hook(Some(attempt));
    posix_abi::probe_close_accepted(Some(accepted));
    posix_abi::process::probe_exec_close(Some(public));
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_cloexec_snapshot(fd: u32, output: *mut u64) -> i32 {
    if output.is_null() || FAILED.load(Ordering::Acquire) {
        return -1;
    }
    for i in 0..ARMED.load(Ordering::Acquire) as usize {
        if RECORDS[i * 24].load(Ordering::Acquire) == u64::from(fd) {
            for j in 0..24 {
                // SAFETY: C supplies twenty-four synchronous scalar output cells.
                unsafe {
                    output
                        .add(j)
                        .write(RECORDS[i * 24 + j].load(Ordering::Acquire));
                }
            }
            return 0;
        }
    }
    -1
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_cloexec_valid(
    s: *const u64,
    expected: *const u64,
    stage: u32,
    n: u32,
    profile: u64,
) -> i32 {
    if s.is_null() || expected.is_null() {
        return -1;
    }
    // SAFETY: C owns the complete static state and the independent eighty-word snapshot.
    let (s, e) = unsafe {
        (
            core::slice::from_raw_parts(s, 352),
            core::slice::from_raw_parts(expected, 80),
        )
    };
    let good = match stage {
        1 => wire::initial(s, s[3]),
        5 => wire::initial(s, s[3]) && wire::permitted_header(s),
        2 => wire::old_header(s, &e[..32]) && wire::receipt(s, e, n as usize),
        3 => wire::old_header(s, &e[..32]) && wire::acknowledged(s, e, n as usize, profile),
        4 => wire::new_identity(s, e, profile),
        _ => false,
    };
    if good { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_cloexec_receipts_same(
    state: *const u64,
    receipts: *const u64,
) -> i32 {
    if state.is_null() || receipts.is_null() {
        return -1;
    }
    // SAFETY: C retains both complete static arrays through the fresh-image handshake.
    let (s, r) = unsafe {
        (
            core::slice::from_raw_parts(state, 352),
            core::slice::from_raw_parts(receipts, 48),
        )
    };
    if wire::same_receipts(s, r) { 0 } else { -1 }
}
#[unsafe(no_mangle)]
pub extern "C" fn full_cloexec_pending(marker: u64, wanted: u64, previous: u64) -> i32 {
    match wire::pending(marker, wanted, previous) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(()) => -1,
    }
}
