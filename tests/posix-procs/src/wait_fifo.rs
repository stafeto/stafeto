// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Exact public WAIT receipts and notifications from two genuine workers.
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use posix_abi::WaitProbe;
use proto_wire::Reader;
static ARMED: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
static SLOTS: [AtomicU32; 2] = [const { AtomicU32::new(u32::MAX) }; 2];
static GENERATIONS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
unsafe extern "C" {
    fn wait_fifo_index() -> u32;
    fn wait_fifo_ready(index: u32);
}
fn hook(phase: WaitProbe, key: proto_fs::WaitKey) -> bool {
    // SAFETY: the C fixture's TLS index is private to each worker.
    let index = unsafe { wait_fifo_index() }.wrapping_sub(1) as usize;
    if phase == WaitProbe::Receive && index < 2 && ARMED[index].swap(false, Ordering::AcqRel) {
        SLOTS[index].store(key.slot, Ordering::Release);
        GENERATIONS[index].store(key.generation, Ordering::Release);
        // SAFETY: no native ownership or FILES_LOCK is held at this hook.
        unsafe { wait_fifo_ready(index as u32 + 1) };
    }
    false
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_fifo_hooks_begin() {
    for i in 0..2 {
        SLOTS[i].store(u32::MAX, Ordering::Release);
        GENERATIONS[i].store(0, Ordering::Release);
        ARMED[i].store(true, Ordering::Release);
    }
    posix_abi::probe_wait_hook(Some(hook));
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_fifo_hooks_end() {
    posix_abi::probe_wait_hook(None);
}
fn call(bytes: &[u8]) -> Result<([u8; 128], usize), i32> {
    let transport = posix_abi::shared::with_files(|f| Ok(f.transport())).map_err(|_| -1)?;
    let _scope = rt::upcall::defer_entries().map_err(|_| -2)?;
    let response = rt::sys::send(transport.files().sessions().0, bytes).map_err(|_| -3)?;
    if !response.handles.is_empty() || response.len > 128 {
        return Err(-4);
    }
    let mut buffer = [0; 128];
    let len = response.len;
    buffer[..len].copy_from_slice(response.bytes(&mut [0; rt::abi::MESSAGE_MAX]));
    Ok((buffer, len))
}
/// A genuine public Query observes the two retained keys before any unlock.
/// The Receive hook already proves Arm and a Sleeping reply were accepted.
#[unsafe(no_mangle)]
pub extern "C" fn wait_fifo_pending(index: u32) -> i32 {
    let result = (|| {
        let index = index.checked_sub(1).filter(|i| *i < 2).ok_or(-5)? as usize;
        let slot = SLOTS[index].load(Ordering::Acquire);
        let generation = GENERATIONS[index].load(Ordering::Acquire);
        if slot >= proto_fs::WAIT_KEY_PLACES as u32 || generation == 0 {
            return Err(-6);
        }
        let other = 1 - index;
        if slot == SLOTS[other].load(Ordering::Acquire)
            && generation == GENERATIONS[other].load(Ordering::Acquire)
        {
            return Err(-7);
        }
        let mut packet = [0; 20];
        packet[..8].copy_from_slice(&proto_fs::Method::WaitQuery.header().bytes());
        packet[8..12].copy_from_slice(&slot.to_le_bytes());
        packet[12..20].copy_from_slice(&generation.to_le_bytes());
        let (bytes, len) = call(&packet)?;
        let reply = proto_fs::WaitReply::read(Reader::new(&bytes[..len])).map_err(|_| -8)?;
        if reply.phase != proto_fs::WaitPhase::Sleeping || reply.result != 0 {
            return Err(-9);
        }
        rt::println!(
            "posix-procs: FIFO public WAIT {}/{} sleeping",
            slot,
            generation
        );
        Ok(())
    })();
    result.err().unwrap_or(0)
}
