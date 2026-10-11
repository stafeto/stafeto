// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine signal and thread departure interrupt a registered public lock operation.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use posix_abi::LockProbe;
use posix_fs::change::ControlToken;

static ARMED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU32 = AtomicU32::new(0);
static SEEN: AtomicU32 = AtomicU32::new(0);
static QUERY_ERROR: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" {
    fn lock_probe_signal();
    fn lock_probe_signal_async();
    fn lock_probe_exit();
}
// Synchronous Start is already Complete. The fixture explicitly makes a real
// Query before its signal, without fabricating a queued response in the driver.
fn query(token: ControlToken) -> Result<(), i32> {
    let transport = posix_abi::shared::with_files(|files| Ok(files.transport())).map_err(|_| -1)?;
    let mut request = [0; 20];
    request[..8].copy_from_slice(&proto_fs::Method::LockQuery.header().bytes());
    request[8..12].copy_from_slice(&(token.slot() as u32).to_le_bytes());
    request[12..].copy_from_slice(&token.generation().to_le_bytes());
    let _scope = rt::upcall::defer_entries().map_err(|_| -3)?;
    let response = rt::sys::send(transport.files().sessions().0, &request).map_err(|_| -4)?;
    if !response.handles.is_empty() || response.len > rt::abi::INLINE_MAX {
        return Err(-5);
    }
    let bytes = rt::abi::inline_bytes(&response.words);
    let reply = proto_fs::LockReply::read(proto_wire::Reader::new(&bytes[..response.len]))
        .map_err(|_| -6)?;
    if reply.phase != proto_fs::LockPhase::Complete || reply.result != 0 {
        return Err(-7);
    }
    Ok(())
}
fn hook(phase: LockProbe, token: ControlToken) -> bool {
    let mode = MODE.load(Ordering::Acquire);
    let expected = match mode {
        6 | 8 => LockProbe::Release,
        _ => LockProbe::Start,
    };
    if phase == expected && ARMED.swap(false, Ordering::AcqRel) {
        if matches!(mode, 5 | 7) {
            QUERY_ERROR.store(query(token).err().unwrap_or(0), Ordering::Release);
        }
        SEEN.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the dedicated C fixture supplies these genuine lifecycle actions.
        unsafe {
            if mode == 3 || mode == 9 {
                lock_probe_exit();
            } else if mode == 4 {
                lock_probe_signal_async();
            } else {
                lock_probe_signal();
            }
        }
    }
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn lock_driver_signal_arm(mode: u32) {
    SEEN.store(0, Ordering::Release);
    QUERY_ERROR.store(0, Ordering::Release);
    MODE.store(mode, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    posix_abi::probe_lock_hook(Some(hook));
}
#[unsafe(no_mangle)]
pub extern "C" fn lock_driver_signal_disarm() -> u32 {
    posix_abi::probe_lock_hook(None);
    ARMED.store(false, Ordering::Release);
    if QUERY_ERROR.load(Ordering::Acquire) == 0 {
        SEEN.load(Ordering::Acquire)
    } else {
        2
    }
}
