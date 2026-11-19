// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lines the conductor prints and the arithmetic they need: the counters
//! a phase read from the service, their increments between two reads, and the
//! share of the CPU the loop of the CPU load got.

use core::fmt::{self, Write};

use crate::phases::Phase;

/// The counters of the service as a phase read them (the fields of its
/// statistics that the line names), in the units of the line: microseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub releases: u32,
    pub frames: u32,
    pub direct: u32,
    pub late: u32,
    pub skipped: u32,
    pub failed: u32,
    pub capped: u32,
    pub wakeups: u32,
    pub take_max_us: u32,
    pub compose_max_us: u32,
    pub device_max_us: u32,
    pub frame_max_us: u32,
    pub band_max_us: u32,
}

impl Counters {
    /// The counts since an earlier read (the maxima are the later read's:
    /// each is the largest since the last reset).
    pub fn since(&self, before: &Counters) -> Counters {
        Counters {
            releases: self.releases.wrapping_sub(before.releases),
            frames: self.frames.wrapping_sub(before.frames),
            direct: self.direct.wrapping_sub(before.direct),
            late: self.late.wrapping_sub(before.late),
            skipped: self.skipped.wrapping_sub(before.skipped),
            failed: self.failed.wrapping_sub(before.failed),
            capped: self.capped.wrapping_sub(before.capped),
            wakeups: self.wakeups.wrapping_sub(before.wakeups),
            ..*self
        }
    }
}

/// The line of a phase.
pub struct PhaseLine<'a>(pub Phase, pub &'a Counters);

impl fmt::Display for PhaseLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self.1;
        write!(
            f,
            "frame-load: phase {} frames {} late {} skipped {} failed {} capped {} wakeups {} take-max-us {} compose-max-us {} device-max-us {} frame-max-us {} band-max-us {} releases {} direct {}",
            self.0.name(),
            c.frames,
            c.late,
            c.skipped,
            c.failed,
            c.capped,
            c.wakeups,
            c.take_max_us,
            c.compose_max_us,
            c.device_max_us,
            c.frame_max_us,
            c.band_max_us,
            c.releases,
            c.direct
        )
    }
}

/// The histogram of the frame time of a phase: 33 bins.
pub struct HistLine<'a>(pub Phase, pub &'a [u32; 33]);

impl fmt::Display for HistLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "frame-load: hist {}", self.0.name())?;
        for bin in self.1 {
            write!(f, " {bin}")?;
        }
        Ok(())
    }
}

/// The bands the service put together in a phase (the counter of DESCRIBE).
pub struct BandsLine(pub Phase, pub u32);

impl fmt::Display for BandsLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "frame-load: bands {} {}", self.0.name(), self.1)
    }
}

/// One window's counters in a phase, as the service's statistics give them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowCounters {
    pub id: u32,
    pub interval: u32,
    pub posts: u32,
    pub taken: u32,
    pub replaced: u32,
    pub late: u32,
    pub missed: u32,
    pub late_max_us: u32,
}

/// The line of a window in a phase.
pub struct WindowLine<'a>(pub Phase, pub &'a WindowCounters);

impl fmt::Display for WindowLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let w = self.1;
        write!(
            f,
            "frame-load: window {} id {} interval {} posts {} taken {} replaced {} late {} missed {} late-max-us {}",
            self.0.name(),
            w.id,
            w.interval,
            w.posts,
            w.taken,
            w.replaced,
            w.late,
            w.missed,
            w.late_max_us
        )
    }
}

/// The line of the CPU load: the loops a second it made in a phase.
pub struct CpuLine(pub Phase, pub u64);

impl fmt::Display for CpuLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "frame-load: cpu {} loops-per-s {}",
            self.0.name(),
            self.1
        )
    }
}

/// The loops a second: `loops` made in `elapsed_ns`.
pub const fn loops_per_second(loops: u64, elapsed_ns: u64) -> u64 {
    if elapsed_ns == 0 {
        return 0;
    }
    ((loops as u128 * 1_000_000_000) / elapsed_ns as u128) as u64
}

/// The share of the CPU the loop got in a phase against what it makes alone,
/// in parts per million (1 000 000 is the whole CPU).
pub const fn cpu_share_ppm(loops_per_s: u64, alone_per_s: u64) -> u64 {
    if alone_per_s == 0 {
        return 0;
    }
    ((loops_per_s as u128 * 1_000_000) / alone_per_s as u128) as u64
}

/// A line into a buffer, for a console that takes bytes.
pub fn render<const N: usize>(line: &dyn fmt::Display) -> ([u8; N], usize) {
    struct Out<const N: usize>([u8; N], usize);
    impl<const N: usize> Write for Out<N> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let room = N - self.1;
            let n = s.len().min(room);
            self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
            self.1 += n;
            if n < s.len() { Err(fmt::Error) } else { Ok(()) }
        }
    }
    let mut out = Out::<N>([0; N], 0);
    let _ = write!(out, "{line}");
    (out.0, out.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters() -> Counters {
        Counters {
            releases: 240,
            frames: 240,
            direct: 0,
            late: 0,
            skipped: 0,
            failed: 0,
            capped: 0,
            wakeups: 240,
            take_max_us: 410,
            compose_max_us: 2950,
            device_max_us: 120,
            frame_max_us: 3070,
            band_max_us: 260,
        }
    }

    #[test]
    fn the_phase_line_is_the_one_the_probe_reads() {
        let c = counters();
        assert_eq!(
            PhaseLine(Phase::Net, &c).to_string(),
            "frame-load: phase net frames 240 late 0 skipped 0 failed 0 capped 0 wakeups 240 take-max-us 410 compose-max-us 2950 device-max-us 120 frame-max-us 3070 band-max-us 260 releases 240 direct 0"
        );
    }

    #[test]
    fn the_window_and_bands_lines_are_the_ones_the_probe_reads() {
        let w = WindowCounters {
            id: 1,
            interval: 1,
            posts: 241,
            taken: 240,
            replaced: 0,
            late: 0,
            missed: 0,
            late_max_us: 0,
        };
        assert_eq!(
            WindowLine(Phase::Net, &w).to_string(),
            "frame-load: window net id 1 interval 1 posts 241 taken 240 replaced 0 late 0 missed 0 late-max-us 0"
        );
        assert_eq!(
            BandsLine(Phase::Full, 9120).to_string(),
            "frame-load: bands full 9120"
        );
    }

    #[test]
    fn the_hist_line_has_the_33_bins() {
        let mut bins = [0u32; 33];
        bins[1] = 212;
        bins[2] = 26;
        let line = HistLine(Phase::Net, &bins).to_string();
        assert!(line.starts_with("frame-load: hist net 0 212 26 0"));
        assert_eq!(line.split_whitespace().count(), 3 + 33);
    }

    #[test]
    fn counts_are_increments_and_maxima_stay() {
        let before = Counters {
            frames: 100,
            late: 1,
            frame_max_us: 9000,
            ..Counters::default()
        };
        let after = Counters {
            frames: 340,
            late: 1,
            frame_max_us: 3070,
            ..Counters::default()
        };
        let d = after.since(&before);
        assert_eq!((d.frames, d.late, d.frame_max_us), (240, 0, 3070));
        // A counter that wrapped between the reads still gives the increment.
        let wrapped = Counters {
            frames: 5,
            ..Counters::default()
        }
        .since(&Counters {
            frames: u32::MAX - 4,
            ..Counters::default()
        });
        assert_eq!(wrapped.frames, 10);
    }

    #[test]
    fn loops_and_shares() {
        assert_eq!(loops_per_second(812_345, 1_000_000_000), 812_345);
        assert_eq!(loops_per_second(500, 500_000_000), 1000);
        assert_eq!(loops_per_second(5, 0), 0);
        assert_eq!(cpu_share_ppm(190_000, 1_000_000), 190_000);
        assert_eq!(cpu_share_ppm(5, 0), 0);
    }

    #[test]
    fn a_line_renders_into_a_buffer() {
        let (bytes, n) = render::<64>(&CpuLine(Phase::Stress, 812_345));
        assert_eq!(&bytes[..n], b"frame-load: cpu stress loops-per-s 812345");
    }
}
