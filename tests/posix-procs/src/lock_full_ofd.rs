// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Scalar observations accompany a genuine ordinary Read hold, never replace it.
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use posix_fs::{RamTarget, Target};
static FD: AtomicU32 = AtomicU32::new(u32::MAX);
static PACKED: AtomicU32 = AtomicU32::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static ENTRY: AtomicU64 = AtomicU64::new(0);
static REPLAY: AtomicU32 = AtomicU32::new(0);
static KEY_SLOT: AtomicU32 = AtomicU32::new(0);
static KEY_GENERATION: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" {
    fn full_ofd_window();
}
fn window() {
    posix_abi::shared::probe_window(None);
    // SAFETY: the isolated C fixture owns synchronous static metadata; no pointer is retained.
    unsafe { full_ofd_window() };
}
#[unsafe(no_mangle)]
pub extern "C" fn full_ofd_arm(fd: u32) -> i32 {
    let result = posix_abi::shared::with_files(|files| {
        let Target::Ram(target) = files.target(fd).map_err(|_| -1)? else {
            return Err(-1);
        };
        let entry = files.lock_source(fd).map_err(|_| -1)?;
        FD.store(fd, Ordering::Relaxed);
        PACKED.store(
            target.fd() | (target.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT),
            Ordering::Relaxed,
        );
        ENTRY.store(entry.generation(), Ordering::Relaxed);
        GENERATION.store(target.generation(), Ordering::Release);
        Ok(())
    });
    if result.is_err() {
        return -1;
    }
    posix_abi::shared::probe_window(Some(window));
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_ofd_local_state(output: *mut u64) -> i32 {
    if output.is_null() {
        return -1;
    }
    let generation = GENERATION.load(Ordering::Acquire);
    let packed = PACKED.load(Ordering::Relaxed);
    let Ok(target) = RamTarget::from_prepared(rt::fs::PreparedOpen {
        fd: packed & proto_fs::OPEN_FD_MASK,
        slot: (packed & proto_fs::OPEN_DESCRIPTION_MASK) >> proto_fs::OPEN_DESCRIPTION_SHIFT,
        generation,
        random: false,
    }) else {
        return -1;
    };
    let result = posix_abi::shared::with_files(|files| {
        let original_live = files
            .lock_source(FD.load(Ordering::Relaxed))
            .is_ok_and(|entry| entry.generation() == ENTRY.load(Ordering::Relaxed))
            && files.target(FD.load(Ordering::Relaxed)).ok() == Some(Target::Ram(target));
        Ok(files.io_loan_state(Target::Ram(target)).map_or(
            [0, 0, 0, u64::from(original_live)],
            |(count, closed, released)| {
                [
                    1,
                    u64::from(count),
                    u64::from(closed) | (u64::from(released) << 1),
                    u64::from(original_live),
                ]
            },
        ))
    });
    match result {
        Ok(words) => {
            // SAFETY: C supplies exactly four cells for this synchronous observation.
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
    let previous = REPLAY.fetch_add(1, Ordering::AcqRel);
    if previous == 0 {
        KEY_SLOT.store(token.slot() as u32, Ordering::Relaxed);
        KEY_GENERATION.store(token.generation(), Ordering::Release);
        return true;
    }
    if previous != 1
        || KEY_SLOT.load(Ordering::Relaxed) != token.slot() as u32
        || KEY_GENERATION.load(Ordering::Acquire) != token.generation()
    {
        REPLAY.store(u32::MAX, Ordering::Release);
    }
    posix_abi::probe_close_hook(None);
    false
}
#[unsafe(no_mangle)]
pub extern "C" fn full_ofd_replay_arm() {
    REPLAY.store(0, Ordering::Release);
    posix_abi::probe_close_hook(Some(close));
}
#[unsafe(no_mangle)]
pub extern "C" fn full_ofd_replay_ok() -> i32 {
    if REPLAY.load(Ordering::Acquire) == 2
        && (proto_fs::CloseKey {
            slot: KEY_SLOT.load(Ordering::Relaxed),
            generation: KEY_GENERATION.load(Ordering::Acquire),
        })
        .validate()
        .is_ok()
    {
        0
    } else {
        -1
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn full_ofd_counts(
    fd: u32,
    cookie: u64,
    epoch: u64,
    packed: u32,
    generation: u64,
    output: *mut u64,
) -> i32 {
    if output.is_null() {
        return -1;
    }
    let result = posix_abi::shared::held(fd, |transport, target| {
        let Target::Ram(source) = target else {
            return Err(-2);
        };
        let mut w = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff1, proto_fs::VERSION)
            .write(&mut w)
            .map_err(|_| -3)?;
        w.u32(7)
            .and_then(|()| w.u64(cookie))
            .and_then(|()| w.u64(epoch))
            .and_then(|()| {
                w.u32(source.fd() | (source.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT))
            })
            .and_then(|()| w.u64(source.generation()))
            .and_then(|()| {
                w.u32(
                    (packed & proto_fs::OPEN_DESCRIPTION_MASK) >> proto_fs::OPEN_DESCRIPTION_SHIFT,
                )
            })
            .and_then(|()| w.u64(generation))
            .map_err(|_| -4)?;
        let files = transport.files();
        let reply = rt::fs::Files::send_on(files.sessions().0, w.as_bytes()).map_err(|_| -5)?;
        if !reply.handles.is_empty() || reply.len > rt::abi::INLINE_MAX {
            return Err(-6);
        }
        let inline = rt::abi::inline_bytes(&reply.words);
        if reply.len == 8 {
            let mut r = proto_wire::Reader::new(&inline[..reply.len]);
            let status = r.u32().map_err(|_| -7)?;
            if r.u32().map_err(|_| -7)? != 0 || status == 0 || status > i32::MAX as u32 {
                return Err(-7);
            }
            r.finish().map_err(|_| -7)?;
            return Err(-(status as i32));
        }
        let words = super::lock_full_wire::reply(&inline[..reply.len], cookie, Some(epoch))
            .map_err(|_| -8)?;
        if words[1] > 1
            || (words[1] == 0 && words[2..].iter().any(|word| *word != 0))
            || (words[1] == 1
                && (words[2] == 0
                    || words[3] > words[2]
                    || words[4]
                        != u64::from(
                            (packed & proto_fs::OPEN_DESCRIPTION_MASK)
                                >> proto_fs::OPEN_DESCRIPTION_SHIFT,
                        )
                    || words[5] != generation))
        {
            return Err(-8);
        }
        Ok(words)
    });
    match result {
        Ok(words) => {
            // SAFETY: C supplies six cells for this call; no caller pointer survives it.
            unsafe { core::ptr::copy_nonoverlapping(words.as_ptr(), output, 6) };
            0
        }
        Err(error) => error,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn full_ofd_description_slot(packed: u32) -> u32 {
    (packed & proto_fs::OPEN_DESCRIPTION_MASK) >> proto_fs::OPEN_DESCRIPTION_SHIFT
}
