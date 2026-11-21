// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the quiet probe of the log's wake keeps (feature `quiet-probe` of the
//! program, xtask `log-quiet`): the driver counts its wake-ups and the overruns
//! of its budget, and after the quiet window writes lines of its own into the
//! kernel log at the spacing of its heartbeat, one at a time, and measures the
//! time from the write of each (the record's time) to its take. The pure part
//! is here, for the host tests.

/// The text every line the driver writes for the latency begins with.
pub const LINE: &[u8] = b"uart: latency probe line ";

/// The safety ticks of the quiet window: the driver counts from the first one
/// to the one 10 s later (xtask), and writes its lines after the 12th.
pub const QUIET_TICKS: u32 = 12;

/// The lines the driver writes for the latency.
pub const LINES: usize = 100;

/// Whether `text` is one of the latency lines.
pub fn is_line(text: &[u8]) -> bool {
    text.starts_with(LINE)
}

/// The latency of the lines the driver wrote: the time from the write of each
/// to its take, in microseconds.
#[derive(Clone, Copy, Debug)]
pub struct Latency {
    micros: [u32; LINES],
    taken: usize,
    written: usize,
}

impl Latency {
    pub const fn new() -> Latency {
        Latency {
            micros: [0; LINES],
            taken: 0,
            written: 0,
        }
    }

    /// Whether the driver writes a line now: the quiet window is over
    /// (`ticks` safety ticks passed) and the lines are not all written.
    pub fn writes(&self, ticks: u32) -> bool {
        ticks >= QUIET_TICKS && self.written < LINES
    }

    /// A line was written: its number.
    pub fn written(&mut self) -> usize {
        self.written += 1;
        self.written
    }

    /// A line was taken `micros` after its write.
    pub fn taken(&mut self, micros: u64) {
        if let Some(slot) = self.micros.get_mut(self.taken) {
            *slot = u32::try_from(micros).unwrap_or(u32::MAX);
            self.taken += 1;
        }
    }

    /// The lines taken.
    pub fn lines(&self) -> usize {
        self.taken
    }

    /// The longest latency, and the 99th percentile (the smallest value that
    /// 99 % of the lines are within), in microseconds.
    pub fn longest_and_p99(&self) -> (u32, u32) {
        let mut sorted = self.micros;
        let n = self.taken;
        sorted[..n].sort_unstable();
        match n {
            0 => (0, 0),
            _ => (sorted[n - 1], sorted[(n * 99).div_ceil(100) - 1]),
        }
    }
}

impl Default for Latency {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_longest_and_the_99th_percentile_of_the_lines_taken() {
        let mut l = Latency::new();
        assert_eq!(l.longest_and_p99(), (0, 0));
        for us in 1..=100 {
            l.taken(us);
        }
        assert_eq!(l.lines(), LINES);
        // Only LINES are kept: 1..=100, and the 99th of them is 99.
        assert_eq!(l.longest_and_p99(), (100, 99));
        let mut m = Latency::new();
        for us in [10, 20, 30, 5000] {
            m.taken(us);
        }
        assert_eq!(m.longest_and_p99(), (5000, 5000));
        let mut k = Latency::new();
        for _ in 0..99 {
            k.taken(100);
        }
        k.taken(900);
        assert_eq!(k.longest_and_p99(), (900, 100));
    }

    #[test]
    fn the_lines_are_written_after_the_quiet_window_and_no_more_than_the_limit() {
        let mut l = Latency::new();
        assert!(!l.writes(QUIET_TICKS - 1));
        assert!(l.writes(QUIET_TICKS));
        for n in 1..=LINES {
            assert_eq!(l.written(), n);
        }
        assert!(!l.writes(QUIET_TICKS + 100));
        assert!(is_line(b"uart: latency probe line 7\n"));
        assert!(!is_line(b"uart: pl011 at"));
    }
}
