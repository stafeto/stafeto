// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The counters of the profile of the service (the feature `profile`, which
//! only the images of the measurement turn on): what a request costs the
//! service by parts. Each counter is a relaxed atomic that only grows; once a
//! second the service prints the lines `net: profile ...` with the change of
//! each counter since the line before (the maxima are the largest value so
//! far). Without the feature every function here is empty and costs no
//! instruction at its call sites.
//!
//! The counters: the steps by kind (`step_*`), the line's interrupts (`irq`),
//! the service's notifications to itself (`told`, and `refused` for those the
//! kernel refused), the doorbells rung per queue and the ones the device
//! suppressed (`bell_*`, `skipped`), the frames of the wire (`frames_*`), the
//! checksum work (`sum_n` frames and `sum_bytes` bytes, made on sending and
//! verified on receiving), the copies between a cell of a shared buffer and
//! the socket's queue (`copy_n`, `copy_bytes`), the requests by method (`calls`,
//! and the line `net: profile calls`) with the ticks of the counter they took
//! (`call_ticks`), and the probe of the cost of the device's exits: the ticks
//! around one doorbell (`ring_*`), around the read of the interrupt status
//! (`isr_*`) and around the reopening of the line (`reopen_*`).

use core::fmt::{self, Write};

macro_rules! counters {
    ($($name:ident = $text:literal),* $(,)?) => {
        /// A counter of the profile.
        #[derive(Clone, Copy)]
        #[repr(usize)]
        #[allow(clippy::enum_variant_names)]
        pub enum Counter { $($name),* }
        /// The names of the counters, in the order of the lines.
        pub const NAMES: &[&str] = &[$($text),*];
    };
}

counters! {
    StepRx = "step_rx",
    StepTx = "step_tx",
    StepWake = "step_wake",
    StepCleanup = "step_cleanup",
    StepSweep = "step_sweep",
    StepResolv = "step_resolv",
    StepRx1 = "step_rx1",
    StepReturn = "step_return",
    StepTimer = "step_timer",
    Irq = "irq",
    Told = "told",
    Refused = "refused",
    BellRx = "bell_rx",
    BellTx = "bell_tx",
    Skipped = "skipped",
    FramesRx = "frames_rx",
    FramesTx = "frames_tx",
    SumN = "sum_n",
    SumBytes = "sum_bytes",
    CopyN = "copy_n",
    CopyBytes = "copy_bytes",
    Calls = "calls",
    CallTicks = "call_ticks",
    RingN = "ring_n",
    RingTicks = "ring_ticks",
    IsrN = "isr_n",
    IsrTicks = "isr_ticks",
    ReopenN = "reopen_n",
    ReopenTicks = "reopen_ticks",
    // The maxima: the counters from here on are not differences.
    RingMax = "ring_max",
    IsrMax = "isr_max",
    ReopenMax = "reopen_max",
    CallMax = "call_max",
}

/// The counters that are sums; the rest are maxima.
pub const SUMS: usize = Counter::RingMax as usize;
const COUNTERS: usize = NAMES.len();
/// The methods of proto_net are below this number.
pub const METHODS: usize = 64;

/// The values of every counter at one moment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Snapshot {
    pub counters: [u64; COUNTERS],
    pub calls: [u64; METHODS],
}

impl Snapshot {
    pub const ZERO: Snapshot = Snapshot {
        counters: [0; COUNTERS],
        calls: [0; METHODS],
    };
}

/// The line of the counters between `before` and `now`, second `second` of
/// the service: `net: profile t <second> <name> <change> ...`.
pub fn counters_line(
    out: &mut impl Write,
    second: u64,
    before: &Snapshot,
    now: &Snapshot,
) -> fmt::Result {
    write!(out, "net: profile t {second}")?;
    for (i, name) in NAMES.iter().enumerate() {
        let value = if i < SUMS {
            now.counters[i].wrapping_sub(before.counters[i])
        } else {
            now.counters[i]
        };
        write!(out, " {name} {value}")?;
    }
    Ok(())
}

/// The line of the requests by method between `before` and `now`: `net:
/// profile calls t <second> <method>:<count> ...` for the methods that came.
pub fn calls_line(
    out: &mut impl Write,
    second: u64,
    before: &Snapshot,
    now: &Snapshot,
) -> fmt::Result {
    write!(out, "net: profile calls t {second}")?;
    for method in 0..METHODS {
        let change = now.calls[method].wrapping_sub(before.calls[method]);
        if change != 0 {
            write!(out, " {method}:{change}")?;
        }
    }
    Ok(())
}

#[cfg(feature = "profile")]
mod on {
    use super::{COUNTERS, Counter, METHODS, Snapshot};
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

    static COUNTS: [AtomicU64; COUNTERS] = [const { AtomicU64::new(0) }; COUNTERS];
    static CALLS: [AtomicU64; METHODS] = [const { AtomicU64::new(0) }; METHODS];

    /// The counter of the clock, for the probes of cost (zero on the host).
    #[inline(always)]
    pub fn now() -> u64 {
        #[cfg(target_os = "none")]
        {
            rt::time::now()
        }
        #[cfg(not(target_os = "none"))]
        {
            0
        }
    }

    #[inline(always)]
    pub fn add(counter: Counter, n: u64) {
        COUNTS[counter as usize].fetch_add(n, Relaxed);
    }

    #[inline(always)]
    pub fn count(counter: Counter) {
        add(counter, 1);
    }

    #[inline(always)]
    pub fn max(counter: Counter, value: u64) {
        COUNTS[counter as usize].fetch_max(value, Relaxed);
    }

    /// One use of a device's exit that began at `began` (from `now`): its
    /// count, its ticks and its largest.
    #[inline(always)]
    pub fn timed(n: Counter, ticks: Counter, largest: Counter, began: u64) {
        let spent = now().saturating_sub(began);
        count(n);
        add(ticks, spent);
        max(largest, spent);
    }

    /// A request of `method` that took `began` to now.
    #[inline(always)]
    pub fn call(method: u16, began: u64) {
        let spent = now().saturating_sub(began);
        count(Counter::Calls);
        add(Counter::CallTicks, spent);
        max(Counter::CallMax, spent);
        CALLS[usize::from(method) % METHODS].fetch_add(1, Relaxed);
    }

    pub fn snapshot() -> Snapshot {
        let mut out = Snapshot::ZERO;
        for (to, from) in out.counters.iter_mut().zip(&COUNTS) {
            *to = from.load(Relaxed);
        }
        for (to, from) in out.calls.iter_mut().zip(&CALLS) {
            *to = from.load(Relaxed);
        }
        out
    }
}

#[cfg(not(feature = "profile"))]
mod off {
    use super::{Counter, Snapshot};

    #[inline(always)]
    pub fn now() -> u64 {
        0
    }
    #[inline(always)]
    pub fn add(_: Counter, _: u64) {}
    #[inline(always)]
    pub fn count(_: Counter) {}
    #[inline(always)]
    pub fn max(_: Counter, _: u64) {}
    #[inline(always)]
    pub fn timed(_: Counter, _: Counter, _: Counter, _: u64) {}
    #[inline(always)]
    pub fn call(_: u16, _: u64) {}
    #[inline(always)]
    pub fn snapshot() -> Snapshot {
        Snapshot::ZERO
    }
}

#[cfg(not(feature = "profile"))]
pub use off::*;
#[cfg(feature = "profile")]
pub use on::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn text(f: impl FnOnce(&mut String) -> fmt::Result) -> String {
        let mut out = String::new();
        f(&mut out).unwrap();
        out
    }

    #[test]
    fn every_counter_has_a_name_and_the_maxima_come_last() {
        assert_eq!(NAMES.len(), COUNTERS);
        assert_eq!(NAMES[SUMS], "ring_max");
        assert_eq!(NAMES[Counter::CallMax as usize], "call_max");
        assert_eq!(COUNTERS, Counter::CallMax as usize + 1);
    }

    #[test]
    fn a_line_has_the_change_of_a_sum_and_the_value_of_a_maximum() {
        let mut before = Snapshot::ZERO;
        let mut now = Snapshot::ZERO;
        before.counters[Counter::StepRx as usize] = 10;
        now.counters[Counter::StepRx as usize] = 25;
        before.counters[Counter::RingMax as usize] = 700;
        now.counters[Counter::RingMax as usize] = 900;
        let line = text(|o| counters_line(o, 7, &before, &now));
        assert!(line.starts_with("net: profile t 7 step_rx 15 step_tx 0 "));
        assert!(line.contains(" ring_max 900 "));
    }

    #[test]
    fn the_calls_line_names_the_methods_that_came() {
        let before = Snapshot::ZERO;
        let mut now = Snapshot::ZERO;
        now.calls[5] = 3;
        now.calls[21] = 1;
        assert_eq!(
            text(|o| calls_line(o, 2, &before, &now)),
            "net: profile calls t 2 5:3 21:1"
        );
        assert_eq!(
            text(|o| calls_line(o, 3, &now, &now)),
            "net: profile calls t 3"
        );
    }

    #[cfg(feature = "profile")]
    #[test]
    fn the_counters_add_and_keep_the_largest() {
        let before = snapshot();
        add(Counter::SumBytes, 1500);
        count(Counter::SumN);
        max(Counter::RingMax, 5);
        max(Counter::RingMax, 3);
        call(5, 0);
        let now = snapshot();
        assert!(
            now.counters[Counter::SumBytes as usize]
                >= before.counters[Counter::SumBytes as usize] + 1500
        );
        assert!(now.counters[Counter::RingMax as usize] >= 5);
        assert!(now.calls[5] > before.calls[5]);
    }

    #[cfg(not(feature = "profile"))]
    #[test]
    fn without_the_feature_nothing_is_counted() {
        add(Counter::SumBytes, 1500);
        call(5, 0);
        assert_eq!(snapshot(), Snapshot::ZERO);
    }
}
