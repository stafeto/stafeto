// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//! Real server gate observation and exact keys from two genuine WAIT workers.
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use posix_abi::WaitProbe;
use posix_fs::{Target, wait::WaitToken};
use proto_wire::{Header, Reader};
static ARMED: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
static SLOTS: [AtomicU32; 2] = [const { AtomicU32::new(u32::MAX) }; 2];
static GENERATIONS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
unsafe extern "C" {
    fn wait_fifo_index() -> u32;
    fn wait_fifo_ready(index: u32);
}
fn hook(phase: WaitProbe, token: WaitToken) -> bool {
    // SAFETY: the C fixture's TLS index is private to each worker.
    let index = unsafe { wait_fifo_index() }.wrapping_sub(1) as usize;
    if phase == WaitProbe::Receive && index < 2 && ARMED[index].swap(false, Ordering::AcqRel) {
        SLOTS[index].store(token.slot() as u32, Ordering::Release);
        GENERATIONS[index].store(token.generation(), Ordering::Release);
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
#[unsafe(no_mangle)]
pub extern "C" fn wait_fifo_arm(fd: i32, holder: u32, nonce: u64) -> i32 {
    let result = (|| {
        let backend = posix_abi::shared::with_files(|f| {
            match f
                .target(fd as u32)
                .map_err(|_| posix_abi::constants::EBADF)?
            {
                Target::Ram(b) => Ok(b),
                _ => Err(posix_abi::constants::EBADF),
            }
        })
        .map_err(|_| -5)?;
        let mut packet = [0; 36];
        packet[..8].copy_from_slice(
            &Header {
                method: 0xfff2,
                version: proto_fs::VERSION,
            }
            .bytes(),
        );
        packet[8..12].copy_from_slice(&1u32.to_le_bytes());
        packet[12..20].copy_from_slice(&nonce.to_le_bytes());
        packet[20..24].copy_from_slice(
            &(backend.fd() | backend.description_slot() << proto_fs::OPEN_DESCRIPTION_SHIFT)
                .to_le_bytes(),
        );
        packet[24..32].copy_from_slice(&backend.generation().to_le_bytes());
        packet[32..36].copy_from_slice(&holder.to_le_bytes());
        for _ in 0..1024 {
            let (bytes, len) = call(&packet)?;
            if len != 8 {
                return Err(-6);
            }
            let status = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            if status == 0 && bytes[4..8] == [0; 4] {
                return Ok(());
            }
            if status != proto_fs::RESOLVING {
                return Err(-7);
            }
            let _ = rt::sys::yield_now();
        }
        Err(-8)
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_fifo_selected(nonce: u64, index: u32) -> i32 {
    let result = (|| {
        let index = index.checked_sub(1).filter(|i| *i < 2).ok_or(-9)? as usize;
        let mut packet = [0; 20];
        packet[..8].copy_from_slice(
            &Header {
                method: 0xfff2,
                version: proto_fs::VERSION,
            }
            .bytes(),
        );
        packet[8..12].copy_from_slice(&2u32.to_le_bytes());
        packet[12..20].copy_from_slice(&nonce.to_le_bytes());
        let (bytes, len) = call(&packet)?;
        let mut reader = Reader::new(&bytes[..len]);
        if reader.u32().map_err(|_| -10)? != 0
            || reader.u32().map_err(|_| -11)? != 4
            || reader.u64().map_err(|_| -12)? != nonce
        {
            return Err(-13);
        }
        let visited = reader.u32().map_err(|_| -14)?;
        if reader.u32().map_err(|_| -15)? != 0 {
            return Err(-16);
        }
        let owner = reader.u64().map_err(|_| -17)?;
        let control_slot = reader.u32().map_err(|_| -18)?;
        let control_gen = reader.u64().map_err(|_| -19)?;
        let registration = reader.u32().map_err(|_| -20)?;
        let wait_owner = reader.u64().map_err(|_| -21)?;
        let wait_slot = reader.u32().map_err(|_| -22)?;
        let wait_gen = reader.u64().map_err(|_| -23)?;
        reader.finish().map_err(|_| -24)?;
        if owner == 0
            || owner != wait_owner
            || !(32..48).contains(&control_slot)
            || control_gen == 0
            || registration >= 16
            || wait_slot != SLOTS[index].load(Ordering::Acquire)
            || wait_gen == 0
            || wait_gen != GENERATIONS[index].load(Ordering::Acquire)
            || visited == 0
            || visited > 4096
        {
            return Err(-25);
        }
        rt::println!(
            "posix-procs: FIFO nonce {} Control {}/{} WAIT {}/{} visits {}",
            nonce,
            control_slot,
            control_gen,
            wait_slot,
            wait_gen,
            visited
        );
        Ok(())
    })();
    result.err().unwrap_or(0)
}
