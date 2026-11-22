// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The windows the sessions gave the service (WINDOW): one memory object of `WINDOW_BYTES` for a
//! session, whose handle the worker keeps until the session goes, executes a new image (UNBIND) or
//! gives another window. The worker maps one cell of it for the time of one job at `WINDOW_AT` and
//! unmaps it when the job is done: 64 sessions with windows would otherwise hold 64 of the 128
//! mappings of the service and the page tables of 8 MiB of other processes' memory.

use datafs::server::SESSIONS;
use proto_data::{CELL_BYTES, WINDOW_BYTES};
use rt::abi::Access;
use rt::handle::{Handle, Memory, Process};
use rt::sys;

/// Where the worker maps a cell: the worker's own area, after the page of the clock and the page of
/// the generations (`0x58_3000_0000` and `0x58_3000_1000`), clear of the buffer of the disk service
/// and of the stack. A cell is at most `CELL_BYTES`.
pub const WINDOW_AT: usize = 0x58_4000_0000;

const PAGE: usize = 4096;

/// The windows, by the label of the session.
pub struct Windows {
    slots: [Option<(u64, Handle<Memory>)>; SESSIONS],
}

impl Windows {
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; SESSIONS],
        }
    }

    /// Keeps `window` for the session `label`; the window it gave before closes with its handle.
    /// False when no slot is free (the slots are as many as the sessions, so a session has one).
    pub fn put(&mut self, label: u64, window: Handle<Memory>) -> bool {
        let at = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|(l, _)| *l == label))
            .or_else(|| self.slots.iter().position(Option::is_none));
        match at {
            Some(i) => {
                self.slots[i] = Some((label, window));
                true
            }
            None => false,
        }
    }

    pub fn get(&self, label: u64) -> Option<&Handle<Memory>> {
        self.slots
            .iter()
            .flatten()
            .find(|(l, _)| *l == label)
            .map(|(_, h)| h)
    }

    /// The session went, or has run a new image: its handle closes and the pages go back to the
    /// process that made the window.
    pub fn remove(&mut self, label: u64) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|(l, _)| *l == label) {
                *slot = None;
            }
        }
    }
}

impl Default for Windows {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether the service takes `memory` as a window: exactly `WINDOW_BYTES` and mappable read-write
/// (the object's rights are not in `memory_info`; a handle without MAP_READ and MAP_WRITE fails the
/// map, and so does a size the object does not have). The first page is mapped and unmapped again.
pub fn acceptable(process: &Handle<Process>, memory: &Handle<Memory>) -> bool {
    match sys::memory_info(memory) {
        Ok(info) if info.size == WINDOW_BYTES as u64 => {}
        _ => return false,
    }
    if sys::mem_map(
        process,
        memory,
        0,
        PAGE as u64,
        WINDOW_AT,
        Access::ReadWrite,
    )
    .is_err()
    {
        return false;
    }
    // SAFETY: the page was mapped by the call above and nothing uses it.
    let _ = unsafe { sys::mem_unmap(process, WINDOW_AT, PAGE as u64) };
    true
}

/// The longest map and unmap of a cell so far, in ticks, under the feature `steps`: a longer one
/// says so, `datafs: cell map longest N ticks` and `datafs: cell unmap longest N ticks`, which the
/// probe of the service judges against term B (a cell is 16 pages, one chunk of the kernel's
/// `mem_map` and `mem_unmap`).
#[cfg(feature = "steps")]
fn longest(slot: &core::sync::atomic::AtomicU64, what: &str, from: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let took = rt::time::now().saturating_sub(from);
    if took > slot.load(Relaxed) {
        slot.store(took, Relaxed);
        rt::println!("datafs: cell {what} longest {took} ticks");
    }
}

#[cfg(feature = "steps")]
static LONGEST_MAP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "steps")]
static LONGEST_UNMAP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Maps the first `count` bytes of cell `cell` (rounded up to pages) at `WINDOW_AT`: read only when
/// the job writes the file, read-write when it reads the file. The bytes mapped, for `unmap`.
pub fn map(
    process: &Handle<Process>,
    window: &Handle<Memory>,
    cell: u32,
    count: usize,
    reading_file: bool,
) -> Result<u64, abi::Error> {
    let len = count.div_ceil(PAGE).max(1) * PAGE;
    debug_assert!(len <= CELL_BYTES && cell < 2);
    let access = if reading_file {
        Access::ReadWrite
    } else {
        Access::Read
    };
    #[cfg(feature = "steps")]
    let from = rt::time::now();
    sys::mem_map(
        process,
        window,
        cell as u64 * CELL_BYTES as u64,
        len as u64,
        WINDOW_AT,
        access,
    )?;
    #[cfg(feature = "steps")]
    longest(&LONGEST_MAP, "map", from);
    Ok(len as u64)
}

/// Unmaps what `map` mapped.
pub fn unmap(process: &Handle<Process>, len: u64) {
    #[cfg(feature = "steps")]
    let from = rt::time::now();
    // SAFETY: the job that used the cell is over; the slices it made are gone.
    if unsafe { sys::mem_unmap(process, WINDOW_AT, len) }.is_err() {
        rt::println!("datafs: a cell of a window did not unmap");
    }
    #[cfg(feature = "steps")]
    longest(&LONGEST_UNMAP, "unmap", from);
}
