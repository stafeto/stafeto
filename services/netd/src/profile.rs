// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The counters of the profile of the service (the feature `profile`, which
//! only the images of the measurement turn on): what a request costs the
//! service by parts. Each counter is a relaxed atomic that only grows; once a
//! `posix-net stat` the service prints the totals as records `net: prof <id>
//! <name> <value> ...` (the counters, and `c<method> <count>` for the methods
//! that came), of at most 63 bytes each so that a record is one write of the
//! console and comes whole whatever else is printing; a reader takes the
//! records of one `<id>` and subtracts the totals of the snapshot before a run
//! from those after it. The maxima are the largest value since the snapshot
//! before. Without the feature every function here is empty and costs no
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
//! (`isr_*`) and around the reopening of the line (`reopen_*`). The time the
//! service itself ran (`ran_ticks`, its thread's own time, which the kernel
//! counts apart from the time of others), the ticks of the steps by kind
//! (`step_rx_ticks`, `step_tx_ticks`, `step_other_ticks`) and of the
//! checksums (`sum_ticks`) give the parts of the time of a request.

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
    SumTicks = "sum_ticks",
    StepRxTicks = "step_rx_ticks",
    StepTxTicks = "step_tx_ticks",
    StepOtherTicks = "step_other_ticks",
    Ran = "ran_ticks",
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

/// The most a record is: the console takes 64 bytes in one write, the line
/// feed among them.
pub const RECORD_MAX: usize = 63;

/// A text of fixed size that refuses what does not fit whole.
struct Fixed<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Fixed<N> {
    const fn new() -> Self {
        Fixed {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        // Only `write_str` fills it, with whole strings.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> Write for Fixed<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        if end > N {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The records of snapshot `id`: `net: prof <id> <name> <value> ...`, each
/// handed to `emit` without its line feed, as many pairs as fit in
/// `RECORD_MAX` bytes. Every counter is in, and the methods that came as
/// `c<method>`.
pub fn records(id: u64, now: &Snapshot, mut emit: impl FnMut(&str)) {
    let mut record = Fixed::<RECORD_MAX>::new();
    let mut pairs = 0;
    let mut put = |name: &dyn fmt::Display, value: u64, record: &mut Fixed<RECORD_MAX>| {
        let mut pair = Fixed::<48>::new();
        let _ = write!(pair, " {name} {value}");
        if record.len + pair.len > RECORD_MAX && pairs != 0 {
            emit(record.as_str());
            *record = Fixed::new();
            pairs = 0;
        }
        if pairs == 0 {
            let _ = write!(record, "net: prof {id}");
        }
        let _ = record.write_str(pair.as_str());
        pairs += 1;
    };
    for (i, name) in NAMES.iter().enumerate() {
        put(name, now.counters[i], &mut record);
    }
    for (method, count) in now.calls.iter().enumerate() {
        if *count != 0 {
            put(&format_args!("c{method}"), *count, &mut record);
        }
    }
    if pairs != 0 {
        emit(record.as_str());
    }
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

    /// Sets a counter to a value read elsewhere (the service's own time).
    pub fn store(counter: Counter, value: u64) {
        COUNTS[counter as usize].store(value, Relaxed);
    }

    /// The number of the next snapshot.
    pub fn next_id() -> u64 {
        static ID: AtomicU64 = AtomicU64::new(0);
        ID.fetch_add(1, Relaxed) + 1
    }

    /// Starts the maxima anew, so that those of the next snapshot are the
    /// largest since this one.
    pub fn take_maxima() {
        for counter in &COUNTS[super::SUMS..] {
            counter.store(0, Relaxed);
        }
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
    pub fn store(_: Counter, _: u64) {}
    #[inline(always)]
    pub fn next_id() -> u64 {
        0
    }
    #[inline(always)]
    pub fn take_maxima() {}
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

    fn all(snapshot: &Snapshot) -> Vec<String> {
        let mut out = Vec::new();
        records(7, snapshot, |r| out.push(r.to_owned()));
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
    fn a_record_is_whole_and_fits_one_write_of_the_console() {
        // The largest values and every method: the records still fit.
        let full = Snapshot {
            counters: [u64::MAX; COUNTERS],
            calls: [u64::MAX; METHODS],
        };
        let records = all(&full);
        let mut seen = 0;
        for r in &records {
            assert!(r.len() <= RECORD_MAX, "{r}");
            let words: Vec<&str> = r.split(' ').collect();
            assert_eq!(&words[..3], ["net:", "prof", "7"], "{r}");
            // Pairs of a name and a number, nothing cut.
            assert_eq!(words.len() % 2, 1, "{r}");
            for pair in words[3..].chunks(2) {
                assert_eq!(pair[1], u64::MAX.to_string(), "{r}");
                seen += 1;
            }
        }
        assert_eq!(seen, COUNTERS + METHODS);
        // The records of the counters carry every name once, in order.
        let names: Vec<&str> = records
            .iter()
            .flat_map(|r| r.split(' ').skip(3).step_by(2))
            .take(COUNTERS)
            .collect();
        assert_eq!(names, NAMES);
    }

    #[test]
    fn only_the_methods_that_came_are_named() {
        let mut now = Snapshot::ZERO;
        now.counters[Counter::StepRx as usize] = 15;
        now.calls[5] = 3;
        now.calls[21] = 1;
        let text = all(&now).join("\n");
        assert!(text.contains(" step_rx 15 "));
        assert!(text.contains(" c5 3"));
        assert!(text.contains(" c21 1"));
        assert!(!text.contains(" c6 "));
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
