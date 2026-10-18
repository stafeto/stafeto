// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The counters of SMP stage 6 (feature `smp-measure`, xtask smp-measure):
//! for each CPU, the time its entries from EL0 spent in the kernel, the
//! longest of them (the blocking a high-priority thread meets, OBJ waits
//! included), and the waits for `OBJ`. A program resets them and has the
//! kernel print them with two writes to the debug resource
//! (`smp-measure reset`, `smp-measure report`), so that a number covers one
//! storm of calls alone. Ticks of the counter, instructions under `-icount`.

use crate::arch::cpu;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// CPUs the table has rows for.
const CPUS: usize = 8;

/// The numbers of one CPU, written by that CPU alone.
struct Row {
    /// The counter at the entry from EL0 the CPU is in, 0 outside one.
    entered: AtomicU64,
    entries: AtomicU64,
    kernel: AtomicU64,
    longest: AtomicU64,
    acquires: AtomicU64,
    wait: AtomicU64,
    longest_wait: AtomicU64,
}

impl Row {
    const fn new() -> Self {
        Self {
            entered: AtomicU64::new(0),
            entries: AtomicU64::new(0),
            kernel: AtomicU64::new(0),
            longest: AtomicU64::new(0),
            acquires: AtomicU64::new(0),
            wait: AtomicU64::new(0),
            longest_wait: AtomicU64::new(0),
        }
    }

    fn clear(&self) {
        for word in [
            &self.entries,
            &self.kernel,
            &self.longest,
            &self.acquires,
            &self.wait,
            &self.longest_wait,
        ] {
            word.store(0, Relaxed);
        }
    }
}

static ROWS: [Row; CPUS] = [const { Row::new() }; CPUS];

fn row() -> &'static Row {
    &ROWS[cpu::this().index().min(CPUS - 1)]
}

/// An entry from EL0 at `now` (`thread::user_ran`).
pub fn entered(now: u64) {
    row().entered.store(now, Relaxed);
}

/// The way out to EL0 at `now` (`thread::user_resumes`): the entry ends.
pub fn resumed(now: u64) {
    let row = row();
    let since = row.entered.swap(0, Relaxed);
    if since != 0 {
        let took = now.wrapping_sub(since);
        row.entries.fetch_add(1, Relaxed);
        row.kernel.fetch_add(took, Relaxed);
        if took > row.longest.load(Relaxed) {
            row.longest.store(took, Relaxed);
        }
    }
}

/// A CPU waited `ticks` for `OBJ` (`obj::acquire`).
pub fn waited(ticks: u64) {
    let row = row();
    row.acquires.fetch_add(1, Relaxed);
    row.wait.fetch_add(ticks, Relaxed);
    if ticks > row.longest_wait.load(Relaxed) {
        row.longest_wait.store(ticks, Relaxed);
    }
}

/// Starts a new count.
pub fn reset() {
    for row in &ROWS {
        row.clear();
    }
    crate::obj::reset_holds();
    crate::obj::reset_stretches();
}

/// Prints the count, a line for each CPU that entered the kernel.
pub fn report() {
    kprintln!("smp-measure counter {} Hz", crate::arch::timer::frequency());
    for (i, row) in ROWS.iter().enumerate() {
        let entries = row.entries.load(Relaxed);
        if entries == 0 {
            continue;
        }
        kprintln!(
            "smp-measure cpu {i}: entries {entries}, kernel {} ticks, longest entry {}, OBJ taken {} times, wait {} ticks, longest wait {}",
            row.kernel.load(Relaxed),
            row.longest.load(Relaxed),
            row.acquires.load(Relaxed),
            row.wait.load(Relaxed),
            row.longest_wait.load(Relaxed),
        );
    }
    let (held, kind) = crate::obj::longest_hold();
    kprintln!("smp-measure OBJ longest hold {held} ticks (kind {kind})");
    let stretches = crate::obj::stretches_by_takes();
    let most = stretches
        .iter()
        .rposition(|&(took, _)| took != 0)
        .unwrap_or(0);
    kprintln!(
        "smp-measure OBJ takes in a stretch {most}={}",
        stretches[most].0
    );
}
