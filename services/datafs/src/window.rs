// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The windows the sessions gave the service (WINDOW): one memory object of `WINDOW_BYTES` for a
//! session, whose handle the worker keeps until the session goes, executes a new image (UNBIND) or
//! gives another window. The worker maps one cell of it for the time of one job at `WINDOW_AT` and
//! unmaps it when the job is done: 64 sessions with windows would otherwise hold 64 of the 128
//! mappings of the service and the page tables of 8 MiB of other processes' memory.

#[cfg(feature = "steps")]
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
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
/// `mem_map` and `mem_unmap`). The rest of the line says what the call was (`pages P, N-th, access
/// A`), so that a long one can be told from the usual ones (the first map of a run builds the
/// page-table pages of the mapping).
#[cfg(feature = "steps")]
fn longest(
    (slot, calls, buckets): (&AtomicU64, &AtomicU64, &Buckets),
    what: &str,
    from: Began,
    (pages, access): (u64, &str),
    process: &Handle<Process>,
) {
    let nth = calls.fetch_add(1, Relaxed) + 1;
    let took = rt::time::now().saturating_sub(from.at);
    // The wall time of a call counts a preemption (by the loop or by a higher level) in it. A call
    // that no step of the loop started or ended in, judged by the kernel ticks of the process,
    // is the call with no preemption by the loop; its figure is the one the probe judges.
    let kernel = sys::process_times(process).map_or(0, |t| t.1);
    if from.events == rt::service::loop_events() && from.kernel != 0 && kernel != 0 {
        quiet(what, kernel.saturating_sub(from.kernel), nth);
    }
    buckets.note(took);
    if took > slot.load(Relaxed) {
        slot.store(took, Relaxed);
        rt::println!(
            "datafs: cell {what} longest {took} ticks (pages {pages}, call {nth}, access {access})"
        );
    }
}

/// What a call of `map` or `unmap` starts from: the clock, the loop's steps and the kernel ticks of
/// the process.
#[cfg(feature = "steps")]
struct Began {
    at: u64,
    events: u64,
    kernel: u64,
}

#[cfg(feature = "steps")]
impl Began {
    fn now(process: &Handle<Process>) -> Began {
        let events = rt::service::loop_events();
        let kernel = sys::process_times(process).map_or(0, |t| t.1);
        Began {
            at: rt::time::now(),
            events,
            kernel,
        }
    }
}

#[cfg(feature = "steps")]
static QUIET_LONGEST: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
#[cfg(feature = "steps")]
static QUIET_CALLS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// A call with no step of the loop in it took `ticks` of kernel time of the process: a longer one
/// than before says so, `datafs: cell map quiet longest N ticks (quiet calls Q, call N-th)`.
#[cfg(feature = "steps")]
fn quiet(what: &str, ticks: u64, nth: u64) {
    let at = usize::from(what == "unmap");
    let calls = QUIET_CALLS[at].fetch_add(1, Relaxed) + 1;
    if ticks > QUIET_LONGEST[at].load(Relaxed) {
        QUIET_LONGEST[at].store(ticks, Relaxed);
        rt::println!(
            "datafs: cell {what} quiet longest {ticks} ticks (quiet calls {calls}, call {nth})"
        );
    }
}

/// How many calls took each length, in ticks: up to 4,500, 6,000, 8,000, 12,000, 16,000, 20,410 (term
/// B) and longer. The longest call alone cannot say whether a long one is usual: the histogram does.
#[cfg(feature = "steps")]
pub struct Buckets([AtomicU64; 7]);

#[cfg(feature = "steps")]
const BUCKET_UPTO: [u64; 6] = [4_500, 6_000, 8_000, 12_000, 16_000, 20_410];

#[cfg(feature = "steps")]
impl Buckets {
    const fn new() -> Buckets {
        Buckets([const { AtomicU64::new(0) }; 7])
    }

    fn note(&self, ticks: u64) {
        let at = BUCKET_UPTO
            .iter()
            .position(|&limit| ticks <= limit)
            .unwrap_or(BUCKET_UPTO.len());
        self.0[at].fetch_add(1, Relaxed);
    }
}

#[cfg(feature = "steps")]
static MAP_TICKS: Buckets = Buckets::new();
#[cfg(feature = "steps")]
static UNMAP_TICKS: Buckets = Buckets::new();

/// The histograms of the maps and unmaps that changed since the last report: `datafs: cell map ticks
/// <=4500 N <=6000 N ... <=20410 N more N`.
#[cfg(feature = "steps")]
pub fn report() {
    static SAID: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    for (i, (what, buckets)) in [("map", &MAP_TICKS), ("unmap", &UNMAP_TICKS)]
        .into_iter()
        .enumerate()
    {
        let total: u64 = buckets.0.iter().map(|b| b.load(Relaxed)).sum();
        if total == 0 || SAID[i].swap(total, Relaxed) == total {
            continue;
        }
        let n = |at: usize| buckets.0[at].load(Relaxed);
        rt::println!(
            "datafs: cell {what} ticks <=4500 {} <=6000 {} <=8000 {} <=12000 {} <=16000 {} <=20410 {} more {}",
            n(0),
            n(1),
            n(2),
            n(3),
            n(4),
            n(5),
            n(6)
        );
    }
}

#[cfg(feature = "steps")]
static LONGEST_MAP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "steps")]
static LONGEST_UNMAP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "steps")]
static MAPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "steps")]
static UNMAPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The deliberate break `break-datafs-cell-kept`: the length of the cell the last job left mapped
/// (0 for none), which the next map unmaps first.
#[cfg(feature = "break-datafs-cell-kept")]
static KEPT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
    #[cfg(feature = "break-datafs-cell-kept")]
    {
        let kept = KEPT.swap(0, core::sync::atomic::Ordering::Relaxed);
        if kept != 0 {
            // SAFETY: the job that left the cell mapped is over.
            let _ = unsafe { sys::mem_unmap(process, WINDOW_AT, kept) };
        }
    }
    #[cfg(feature = "steps")]
    let from = Began::now(process);
    sys::mem_map(
        process,
        window,
        cell as u64 * CELL_BYTES as u64,
        len as u64,
        WINDOW_AT,
        access,
    )?;
    #[cfg(feature = "steps")]
    longest(
        (&LONGEST_MAP, &MAPS, &MAP_TICKS),
        "map",
        from,
        (
            len as u64 / PAGE as u64,
            if reading_file { "rw" } else { "r" },
        ),
        process,
    );
    Ok(len as u64)
}

/// Unmaps what `map` mapped.
pub fn unmap(process: &Handle<Process>, len: u64) {
    #[cfg(feature = "break-datafs-cell-kept")]
    if cfg!(feature = "break-datafs-cell-kept") {
        KEPT.store(len, core::sync::atomic::Ordering::Relaxed);
        return;
    }
    #[cfg(feature = "steps")]
    let from = Began::now(process);
    // SAFETY: the job that used the cell is over; the slices it made are gone.
    if unsafe { sys::mem_unmap(process, WINDOW_AT, len) }.is_err() {
        rt::println!("datafs: a cell of a window did not unmap");
    }
    #[cfg(feature = "steps")]
    longest(
        (&LONGEST_UNMAP, &UNMAPS, &UNMAP_TICKS),
        "unmap",
        from,
        (len / PAGE as u64, "-"),
        process,
    );
}
