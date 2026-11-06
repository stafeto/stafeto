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
    /// The idle poll (idle.rs): windows that ended with an interrupt or a
    /// bell, windows that ran out, ticks in windows, the window now, bells
    /// this CPU rang that needed no SGI, and those that did.
    hits: AtomicU64,
    naps: AtomicU64,
    misses: AtomicU64,
    polled: AtomicU64,
    window: AtomicU64,
    saved: AtomicU64,
    sent: AtomicU64,
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
            hits: AtomicU64::new(0),
            naps: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            polled: AtomicU64::new(0),
            window: AtomicU64::new(0),
            saved: AtomicU64::new(0),
            sent: AtomicU64::new(0),
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
            &self.hits,
            &self.naps,
            &self.misses,
            &self.polled,
            &self.saved,
            &self.sent,
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

/// The idle loop slept: with a `window` of poll in ticks (0 for none), the
/// window ended with an interrupt or a bell (`hit`), and the whole wait took
/// `ticks`.
pub fn polled(window: u64, hit: bool, ticks: u64) {
    let row = row();
    row.window.store(window, Relaxed);
    if window == 0 {
        row.naps.fetch_add(1, Relaxed);
    } else {
        row.polled.fetch_add(ticks.min(window), Relaxed);
        let which = if hit { &row.hits } else { &row.misses };
        which.fetch_add(1, Relaxed);
    }
}

/// The counter at the last periodic print of the poll counters.
static LAST_PRINT: AtomicU64 = AtomicU64::new(0);

/// CPU 0 prints the counters of the poll every 5 s, so that a run on a
/// machine that cannot send the request to report (VZ) shows them in the
/// kernel log: the counts are since the start of the kernel.
pub fn periodic(now: u64) {
    if cpu::this().index() != 0 {
        return;
    }
    let last = LAST_PRINT.load(Relaxed);
    if now.wrapping_sub(last) > 5 * crate::arch::timer::frequency() {
        LAST_PRINT.store(now, Relaxed);
        kprintln!(
            "smp-measure poll at {} s",
            now / crate::arch::timer::frequency()
        );
        report_poll();
    }
}

/// This CPU rang another one; `sgi` when the SGI went too.
pub fn rang(sgi: bool) {
    let which = if sgi { &row().sent } else { &row().saved };
    which.fetch_add(1, Relaxed);
}

/// Starts a new count.
pub fn reset() {
    for row in &ROWS {
        row.clear();
    }
    crate::obj::reset_holds();
    crate::obj::reset_stretches();
}

/// Prints the counters of the idle poll, a line for each CPU that polled or
/// rang.
pub fn report_poll() {
    for (i, row) in ROWS.iter().enumerate() {
        let rings = row.saved.load(Relaxed) + row.sent.load(Relaxed);
        if rings + row.hits.load(Relaxed) + row.misses.load(Relaxed) + row.naps.load(Relaxed) != 0 {
            kprintln!(
                "smp-measure poll cpu {i}: windows hit {}, missed {}, sleeps without a window {}, {} ticks polled, window {} ticks, bells without SGI {}, with SGI {}",
                row.hits.load(Relaxed),
                row.misses.load(Relaxed),
                row.naps.load(Relaxed),
                row.polled.load(Relaxed),
                row.window.load(Relaxed),
                row.saved.load(Relaxed),
                row.sent.load(Relaxed),
            );
        }
    }
}

/// Prints the count, a line for each CPU that entered the kernel.
pub fn report() {
    kprintln!("smp-measure counter {} Hz", crate::arch::timer::frequency());
    report_poll();
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
