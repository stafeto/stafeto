// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The quiet probe of the kernel log's wake (`cargo xtask log-quiet [icount|tcg]`,
//! kernel/src/log.rs, services/uart): the boot image with the console driver built
//! with the feature `quiet-probe` and the shell, which waits for input, so the
//! system is idle once it is up. At each safety tick (each second) the driver says
//! how many times it woke for the log's notification and its timer, how many
//! times its budget ran out, and, from the 13th tick on, the latency of the
//! lines it writes into the kernel log itself, one at each heartbeat, at least
//! 250 ms apart, so that each of them finds the driver asleep: the time from the
//! write of a line (the record's time) to its take. The verdict:
//!
//! 1. In the window of 10 s from the first tick the driver woke at most
//!    `WAKEUPS_MAX` times (the 10 safety ticks and a reserve) and its budget ran
//!    out never under -icount; under TCG, whose clock is the host's, no more often than the
//!    heartbeat and the safety tick come, none for the kernel's notifications or the drain.
//!    The boot's own overruns lie before the window.
//! 2. The driver says no `log wake missed` line (every run of xtask fails on one).
//! 3. Under -icount the longest latency of a line is below `LATENCY_MAX_US`, the
//!    period of the drain and a step; under TCG, whose clock is the host's, it is
//!    printed alone. The 99th percentile is printed in both.
//!
//! The heartbeat of the driver (each 250 ms, init's watchdog) wakes it four times
//! a second as well; the driver counts only what its log work does, and the
//! heartbeat is reported in the output.

use std::time::Duration;

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, SHELL_STACK_SIZE, UART_STACK_SIZE, Variant, build,
    build_boot_image, probe_command, qemu,
};

const PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &[]),
    ("uart", "uart", UART_STACK_SIZE, &["crash", "quiet-probe"]),
    ("shell", "shell", SHELL_STACK_SIZE, &[]),
];

/// The most times the driver may wake for its log in the window: the 10 safety
/// ticks, and a reserve of 2.
pub const WAKEUPS_MAX: u64 = 12;
/// The longest latency of a line under -icount, in microseconds: the period of
/// the drain (2 500) and the step that takes the line.
pub const LATENCY_MAX_US: u64 = 5_000;
/// The period of the driver's heartbeat in init's table (services/init/src/table/normal.rs).
const HEARTBEAT_MS: u64 = 250;
/// The lines the driver writes (uart::probe::LINES): the run ends with the
/// line that says it took them all.
const LINES: u64 = 100;
const TIMEOUT: Duration = Duration::from_secs(900);

/// What the driver says: after the window of 10 s, one line with its wake-ups and the overruns of
/// its budget since the first safety tick (`uart: quiet window wakeups W overruns O ms T`), and
/// once all its latency lines are taken, one with their latency (`uart: quiet latency max A us p99
/// B us lines K`). The driver prints nothing before the window is over, so that its own lines
/// (the transmit interrupts and the drain that follow) are not counted in it.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct Said {
    pub wakeups: u64,
    pub overruns: u64,
    pub window_ms: u64,
    pub longest_us: u64,
    pub p99_us: u64,
    pub lines: u64,
    /// The overruns of the window by the reason of the wake-up they came in: the heartbeat to
    /// init, the kernel's notification of a record, the safety tick, a tick of the drain, the
    /// rest.
    pub reasons: [u64; 5],
}

/// The numbers of `line` after `head`, at the places of `shape` (`None` for a number).
fn numbers(line: &str, head: &str, shape: &[Option<&str>]) -> Option<Vec<u64>> {
    let rest = line.split_once(head)?.1;
    let t: Vec<&str> = rest.split_whitespace().collect();
    if t.len() < shape.len() {
        return None;
    }
    let mut out = Vec::new();
    for (word, shape) in t.iter().zip(shape) {
        match shape {
            Some(w) if w == word => {}
            Some(_) => return None,
            None => out.push(word.parse().ok()?),
        }
    }
    Some(out)
}

/// What the lines of the run say; `None` for a window or a latency line that did not come.
pub fn parse(lines: &[String]) -> (Option<Said>, bool) {
    let mut said = Said::default();
    let (mut window, mut latency) = (false, false);
    for l in lines {
        if let Some(n) = numbers(
            l,
            "uart: quiet window wakeups ",
            &[None, Some("overruns"), None, Some("ms"), None],
        ) {
            (said.wakeups, said.overruns, said.window_ms) = (n[0], n[1], n[2]);
            window = true;
        } else if let Some(n) = numbers(
            l,
            "uart: quiet reasons beat ",
            &[
                None,
                Some("log"),
                None,
                Some("safe"),
                None,
                Some("drain"),
                None,
                Some("other"),
                None,
            ],
        ) {
            said.reasons = [n[0], n[1], n[2], n[3], n[4]];
        } else if let Some(n) = numbers(
            l,
            "uart: quiet latency max ",
            &[
                None,
                Some("us"),
                Some("p99"),
                None,
                Some("us"),
                Some("lines"),
                None,
            ],
        ) {
            (said.longest_us, said.p99_us, said.lines) = (n[0], n[1], n[2]);
            latency = true;
        }
    }
    (window.then_some(said), latency)
}

/// What a run measured.
pub type Report = Said;

/// The verdict on what a run said (`icount`: the clock is the guest's).
pub fn verdict(said: Option<Said>, latency: bool, icount: bool) -> Result<Report, String> {
    let said = said.ok_or("the driver said nothing of the window of 10 s")?;
    if said.overruns > (u64::MAX / 2) {
        return Err("the driver could not read the overruns of its budget".into());
    }
    if said.window_ms < 9_000 {
        return Err(format!(
            "the window was {} ms, 10 000 expected",
            said.window_ms
        ));
    }
    if said.wakeups > WAKEUPS_MAX {
        return Err(format!(
            "the driver woke {} times in {} ms, at most {WAKEUPS_MAX} expected",
            said.wakeups, said.window_ms
        ));
    }
    // Under -icount none at all. Under TCG the clock is the host's: the step of the driver's
    // heartbeat (a request to init each 250 ms, which init's table sets, no work of the log) and
    // its safety tick (about 110 us under -icount, close to the budget of 150 us) run the budget
    // out about once each, and the overruns of the other wake-ups, the kernel's notifications
    // and the drain, never. The driver counts each overrun by the reason of the wake-up before
    // the count that showed it (the kernel counts it up to a period of 10 ms after the step),
    // so a heartbeat and a safety tick within one period are counted together: the sum of the
    // two is what the probe bounds, by the heartbeats and the ticks of the window.
    let [beat, log, safe, drain, other] = said.reasons;
    let allowed = if icount {
        0
    } else {
        said.window_ms / HEARTBEAT_MS + said.window_ms / 1000 + 4
    };
    if log + drain + other != 0 || beat + safe > allowed || (icount && said.overruns != 0) {
        return Err(format!(
            "the budget of the driver ran out in the window of 10 s: {} times in all, by the heartbeat {beat} and the safety tick {safe} (at most {allowed} together), by the kernel's notification {log}, the drain {drain}, the rest {other} (none expected)",
            said.overruns
        ));
    }
    if !latency || said.lines < LINES {
        return Err(format!(
            "the driver took {} of its {LINES} latency lines",
            said.lines
        ));
    }
    if icount && said.longest_us > LATENCY_MAX_US {
        return Err(format!(
            "a line waited {} us for the driver, more than {LATENCY_MAX_US}",
            said.longest_us
        ));
    }
    Ok(said)
}

/// One run: `icount` under QEMU's -icount, otherwise under TCG alone.
fn probe(icount: bool) -> Result<Report, String> {
    let image = build_boot_image("boot-log-quiet.img", &PROGRAMS, BOOT_PROFILE)?;
    let (mut cmd, _kernel) = probe_command(&image, false)?;
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let outcome = qemu::on_cpus(1, || qemu::run_until(cmd, TIMEOUT, Some(" lines 100")))?;
    if outcome.timed_out || !outcome.stopped_on_marker {
        return Err(format!(
            "the probe did not finish: {:?}",
            outcome.lines.last()
        ));
    }
    let (said, latency) = parse(&outcome.lines);
    verdict(said, latency, icount)
}

/// The kernel tests of the log's wake and the kernels built to break them
/// (`cargo xtask log-wake-break`, part of `budget-breaks`): with the rings left out of the
/// `irq_ack` of the log's binding, a record that waits for the first `irq_ack` is never
/// posted, and the writer on CPU 1 that races the arming loses a wake; with the post made in
/// the call that claimed it, the call takes `OBJ` twice. Each must fail its tests.
pub fn breaks() -> Result<(), String> {
    for (variant, tests, what) in [
        (
            Variant::LogWakeBreakTest,
            &["log_wake_posts_once_for_each_arming"][..],
            "an irq_ack that looks at no ring",
        ),
        (
            Variant::LogWakeBreakEl0,
            &["log_wake_a_writer_on_another_cpu_loses_no_wake"][..],
            "an irq_ack that looks at no ring, against a writer on CPU 1",
        ),
        (
            Variant::LogPostInCallBreakTest,
            &["log_wake_post_is_a_turn_of_its_own"][..],
            "a post made in the call that claimed it",
        ),
    ] {
        let a = build(variant)?;
        // The writer test needs a second CPU.
        let o = qemu::on_cpus(2, || {
            let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
            cmd.args(qemu::HEADLESS);
            qemu::run_until(cmd, Duration::from_secs(300), None)
        })?;
        let report = qemu::parse_report(&o.lines);
        for test in tests {
            if !report.failed.iter().any(|(name, _)| name == test) {
                return Err(format!("the kernel with {what} passed {test}"));
            }
            println!("log-wake-break: a kernel with {what} fails {test}");
        }
    }
    Ok(())
}

/// `cargo xtask log-quiet [icount|tcg]`.
pub fn run(args: &[String]) -> Result<(), String> {
    let icount = match args.first().map(String::as_str) {
        None | Some("icount") => true,
        Some("tcg") => false,
        Some(other) => return Err(format!("log-quiet: `{other}`, expected icount or tcg")),
    };
    let r = probe(icount).map_err(|e| format!("log-quiet: {e}"))?;
    let mode = if icount { "icount" } else { "tcg" };
    println!(
        "log-quiet {mode}: {} wake-ups and {} overruns of the budget in {} ms (at most {WAKEUPS_MAX}; no overruns under icount, under tcg only the heartbeats and the safety ticks, at most one each); latency of a line after its write: max {} us, p99 {} us over {} lines",
        r.wakeups, r.overruns, r.window_ms, r.longest_us, r.p99_us, r.lines
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(w: u64, o: u64, ms: u64, max: u64, n: u64) -> Vec<String> {
        vec![
            "uart: pl011 at 0x9000000, line 33".to_owned(),
            format!("uart: quiet reasons beat {o} log 0 safe 0 drain 0 other 0"),
            format!("uart: quiet window wakeups {w} overruns {o} ms {ms}"),
            format!(
                "uart: quiet latency max {max} us p99 {} us lines {n}",
                max / 2
            ),
        ]
    }

    fn judged(lines: &[String], icount: bool) -> Result<Report, String> {
        let (said, latency) = parse(lines);
        verdict(said, latency, icount)
    }

    #[test]
    fn ten_ticks_and_no_overrun_pass() {
        let r = judged(&run(10, 0, 10_000, 90, 100), true).unwrap();
        assert_eq!((r.wakeups, r.overruns, r.lines), (10, 0, 100));
        assert_eq!((r.longest_us, r.p99_us), (90, 45));
    }

    #[test]
    fn a_driver_that_wakes_every_20_ms_fails_the_window() {
        let e = judged(&run(500, 0, 10_000, 90, 100), true).unwrap_err();
        assert!(e.contains("woke 500 times"), "{e}");
    }

    #[test]
    fn an_overrun_in_the_window_fails_it() {
        let e = judged(&run(10, 1, 10_000, 90, 100), true).unwrap_err();
        assert!(e.contains("1 times in all"), "{e}");
        let e = judged(&run(10, u64::MAX, 10_000, 90, 100), true).unwrap_err();
        assert!(e.contains("could not read"), "{e}");
    }

    #[test]
    fn under_tcg_only_the_heartbeats_may_overrun() {
        // 40 overruns of the heartbeat pass under TCG and fail under icount.
        let beat = run(10, 40, 10_000, 90, 100);
        assert!(judged(&run(10, 50, 10_000, 90, 100), false).is_ok());
        assert!(judged(&beat, false).is_ok());
        assert!(judged(&beat, true).is_err());
        // One of the log's own fails under TCG too, whatever the heartbeats are.
        let mut log = run(10, 40, 10_000, 90, 100);
        log[1] = "uart: quiet reasons beat 39 log 1 safe 0 drain 0 other 0".to_owned();
        let e = judged(&log, false).unwrap_err();
        assert!(e.contains("notification 1"), "{e}");
        // More than the heartbeats that came also fails.
        assert!(judged(&run(10, 70, 10_000, 90, 100), false).is_err());
    }

    #[test]
    fn a_slow_line_fails_under_icount_only() {
        let lines = run(10, 0, 10_000, 9_000, 100);
        assert!(judged(&lines, true).unwrap_err().contains("9000 us"));
        assert!(judged(&lines, false).is_ok());
    }

    #[test]
    fn a_run_without_its_lines_or_its_window_fails() {
        assert!(
            judged(&run(10, 0, 10_000, 90, 40), true)
                .unwrap_err()
                .contains("40 of its 100")
        );
        assert!(judged(&run(10, 0, 3_000, 90, 100), true).is_err());
        assert!(judged(&[], true).is_err());
        assert!(judged(&run(10, 0, 10_000, 90, 100)[..2], true).is_err());
    }
}
