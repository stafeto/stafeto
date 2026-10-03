// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! rtbench 2: the real-time scenarios of a POSIX program
//! (tests/rtbench-posix) beside a hostile load (tests/rtbench-load), on
//! HVF and Apple VZ for N minutes at the same time
//! (`cargo xtask rtbench --minutes N [--serial]`), or
//! one round on QEMU TCG in `ci` (`short`). Each run writes
//! `target/measure/rtbench-<machine>.txt`: the commit, the host's `uptime`
//! before and after, and a row for each scenario with n, min, p50, p99,
//! max and the histogram by powers of two in nanoseconds; next to it the
//! whole output of the machine (`.log`).

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::{
    BOOT_PROFILE, ImageProgram, RTBENCH_POSIX_PROGRAMS, RTBENCH_POSIX_VZ_PROGRAMS, Variant, build,
    hvf_host, qemu, target_dir, vz, write_boot_image_with,
};

/// The rows of a run, in its order: each comes once, as numbers or as
/// `none` with the reason the layer has no such operation yet.
pub const ROWS: [&str; 43] = [
    "s1_mutex_alone",
    "s2_futex_wake_idle",
    "s3_mutex_rival_10",
    "s3_mutex_rival_20",
    "s3_mutex_rival_30",
    "s4_malloc_free_64",
    "s4_malloc_free_4k",
    "s4_dup_close",
    "s5_kill_sleeping",
    "s5_kill_reading",
    "s5_kill_busy_25",
    "s6_read_ready",
    "s7_sleep_abs_1ms",
    "s8_futex_pair",
    "s8_futex_bucket_neighbour",
    "s9_service_round_trip",
    "s10_kill_process_sleeping",
    "s10_kill_process_busy_25",
    "s11_waitpid_zombie",
    "s11_exit_to_waitpid",
    "s12_killpg_group_32",
    "s13_spawn_to_main",
    "s14_exec_to_main",
    "s15_fork_to_child",
    "s15_fork_heap_1m",
    "s15_fork_heap_8m",
    "s16_fork_exec_waitpid",
    "s17_fork_sleepers_1",
    "s17_fork_sleepers_8",
    "s17_fork_sleepers_32",
    "s17_fork_sleepers_63",
    "s17_fork_spinners_1",
    "s17_fork_spinners_8",
    "s17_fork_spinners_32",
    "s17_fork_spinners_63",
    "s18_exec_spinners_1",
    "s18_exec_spinners_8",
    "s18_exec_spinners_32",
    "s18_exec_spinners_63",
    "timer_1ms",
    "inheritance_chain",
    "s7_missed",
    "load_rounds",
];

/// The time a round may take at most, on TCG too.
const ROUND: Duration = Duration::from_secs(120);

/// A row with numbers: nanoseconds, `calls` the kernel calls over the n
/// samples where the row counts them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Numbers {
    pub n: u64,
    pub min: u64,
    pub p50: u64,
    pub p99: u64,
    pub max: u64,
    pub calls: Option<u64>,
    pub histogram: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Row {
    Numbers(Numbers),
    None(String),
    Count(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub hz: u64,
    pub rounds: u64,
    pub rows: Vec<(&'static str, Row)>,
}

fn field(words: &[&str], key: &str, line: &str) -> Result<u64, String> {
    words
        .iter()
        .find_map(|w| w.strip_prefix(key))
        .ok_or_else(|| format!("no {key} in {line:?}"))?
        .parse()
        .map_err(|e| format!("bad {key} in {line:?}: {e}"))
}

fn numbers(words: &[&str], line: &str) -> Result<Numbers, String> {
    let histogram = words
        .iter()
        .find_map(|w| w.strip_prefix("h="))
        .ok_or_else(|| format!("no histogram in {line:?}"))?
        .split(',')
        .map(|c| {
            c.parse()
                .map_err(|e| format!("bad histogram in {line:?}: {e}"))
        })
        .collect::<Result<Vec<u64>, String>>()?;
    let row = Numbers {
        n: field(words, "n=", line)?,
        min: field(words, "min=", line)?,
        p50: field(words, "p50=", line)?,
        p99: field(words, "p99=", line)?,
        max: field(words, "max=", line)?,
        calls: words
            .iter()
            .any(|w| w.starts_with("calls="))
            .then(|| field(words, "calls=", line))
            .transpose()?,
        histogram,
    };
    if row.n == 0 {
        return Err(format!("no samples: {line}"));
    }
    if row.histogram.iter().sum::<u64>() != row.n {
        return Err(format!("the histogram does not sum to n: {line}"));
    }
    if !(row.min <= row.p50 && row.p50 <= row.p99 && row.p99 <= row.max) {
        return Err(format!("min, p50, p99, max out of order: {line}"));
    }
    Ok(row)
}

/// The run in `lines`: its start, the check of the counter of calls (one
/// call for one `yield`), each row of ROWS once, and its end.
pub fn parse(lines: &[String]) -> Result<Run, String> {
    if let Some(failed) = lines.iter().find(|l| l.starts_with("RTB2 FAIL")) {
        return Err(format!("the benchmark failed: {failed}"));
    }
    // Rows taken without the hostile load compare nothing.
    if let Some(failed) = lines
        .iter()
        .find(|l| l.contains("rtbench-load: failed") || l.contains("init: rtbench-load ended"))
    {
        return Err(format!("the load stopped: {failed}"));
    }
    let start = lines
        .iter()
        .find(|l| l.starts_with("RTB2 START "))
        .ok_or("no RTB2 START")?;
    let hz = field(&start.split_whitespace().collect::<Vec<_>>(), "hz=", start)?;
    match lines.iter().find(|l| l.starts_with("RTB2 calls yield=")) {
        Some(l) if l == "RTB2 calls yield=1" => {}
        Some(l) => return Err(format!("the counter of calls is wrong: {l}")),
        None => return Err("no check of the counter of calls".into()),
    }
    let done = lines
        .iter()
        .find(|l| l.starts_with("RTB2 DONE "))
        .ok_or("no RTB2 DONE")?;
    let rounds = field(
        &done.split_whitespace().collect::<Vec<_>>(),
        "rounds=",
        done,
    )?;
    let mut rows = Vec::new();
    for name in ROWS {
        let prefix = format!("RTB2 {name} ");
        let found: Vec<_> = lines.iter().filter(|l| l.starts_with(&prefix)).collect();
        let line = match found.as_slice() {
            [line] => *line,
            [] => return Err(format!("no row {name}")),
            _ => return Err(format!("row {name} comes {} times", found.len())),
        };
        let words: Vec<_> = line.split_whitespace().skip(2).collect();
        let row = match words.as_slice() {
            ["none", why @ ..] if !why.is_empty() => Row::None(why.join(" ")),
            [count] => Row::Count(
                count
                    .parse()
                    .map_err(|e| format!("bad count in {line:?}: {e}"))?,
            ),
            _ => Row::Numbers(numbers(&words, line)?),
        };
        rows.push((name, row));
    }
    match rows.last() {
        Some(("load_rounds", Row::Count(n))) if *n > 0 && *n < u64::MAX - 1 => {}
        other => return Err(format!("the load made no rounds: {other:?}")),
    }
    Ok(Run { hz, rounds, rows })
}

/// The text of the file of a run.
pub fn file(machine: &str, commit: &str, seconds: u64, uptime: [&str; 2], run: &Run) -> String {
    let mut text = format!(
        "rtbench 2 on {machine}\ncommit {commit}\nseconds {seconds}, rounds {}, counter {} Hz (a tick is {:.1} ns)\nuptime before: {}\nuptime after: {}\n\n",
        run.rounds,
        run.hz,
        1e9 / run.hz as f64,
        uptime[0],
        uptime[1]
    );
    text += "row n min p50 p99 max (ns) calls/op | histogram: samples in [2^i, 2^(i+1)) ns from i = 0\n";
    for (name, row) in &run.rows {
        match row {
            Row::Numbers(r) => {
                let calls = r
                    .calls
                    .map_or("-".to_owned(), |c| format!("{:.2}", c as f64 / r.n as f64));
                let histogram: Vec<_> = r.histogram.iter().map(u64::to_string).collect();
                text += &format!(
                    "{name} {} {} {} {} {} {calls} | {}\n",
                    r.n,
                    r.min,
                    r.p50,
                    r.p99,
                    r.max,
                    histogram.join(",")
                );
            }
            Row::None(why) => text += &format!("{name} none: {why}\n"),
            Row::Count(count) => text += &format!("{name} {count}\n"),
        }
    }
    text
}

fn output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

pub fn commit() -> String {
    let hash = output("git", &["rev-parse", "--short", "HEAD"]);
    let dirty = !output("git", &["status", "--porcelain", "--untracked-files=no"]).is_empty();
    if dirty {
        format!("{hash}+changes")
    } else {
        hash
    }
}

/// The boot image of the benchmark for a run of `seconds`, the length
/// built into the program (`RTBENCH_SECONDS`).
fn image(name: &str, programs: &[ImageProgram], seconds: u64) -> Result<PathBuf, String> {
    write_boot_image_with(
        name,
        programs,
        BOOT_PROFILE,
        &[("RTBENCH_SECONDS", &seconds.to_string())],
    )
}

/// One run of `cmd` for `seconds`, its file and log under target/measure
/// as `machine`; the parsed run.
fn measure(cmd: Command, machine: &str, seconds: u64) -> Result<Run, String> {
    println!("rtbench 2: {machine}, {seconds} s");
    let before = output("uptime", &[]);
    let timeout = Duration::from_secs(seconds) + ROUND * 2;
    // The end of the program, after its last row or its failure.
    let outcome = qemu::run_until(cmd, timeout, Some("init: rtbench-posix ended"))?;
    let after = output("uptime", &[]);
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let log = dir.join(format!("rtbench-{machine}.log"));
    std::fs::write(&log, outcome.lines.join("\n") + "\n")
        .map_err(|e| format!("{}: {e}", log.display()))?;
    if !outcome.stopped_on_marker {
        return Err(format!(
            "{machine} did not finish (log {}): {:?}",
            log.display(),
            outcome.lines.last()
        ));
    }
    if let Some(panic) = outcome.lines.iter().find(|l| l.contains("KERNEL PANIC")) {
        return Err(format!("the kernel panicked: {panic}"));
    }
    let run = parse(&outcome.lines).map_err(|e| format!("{e} (log {})", log.display()))?;
    let path = dir.join(format!("rtbench-{machine}.txt"));
    let text = file(machine, &commit(), seconds, [&before, &after], &run);
    std::fs::write(&path, &text).map_err(|e| format!("{}: {e}", path.display()))?;
    print!("{text}");
    println!("rtbench 2: {} and {}", path.display(), log.display());
    Ok(run)
}

/// How `rtbench --minutes N` places its two runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placing {
    /// HVF, then VZ (`--serial`).
    Serial,
    /// Both at once, the default: the host has cores for two guests, and
    /// the report of each run says how loaded it was (the uptime before
    /// and after). Two runs of 2 minutes each way (notes/parallel-guests.md)
    /// kept the p99 and the maximum of the main rows within the spread of
    /// two serial runs.
    Concurrent,
}

/// `cargo xtask rtbench --minutes N`: N minutes on HVF and on VZ, at the
/// same time unless `placing` says otherwise.
pub fn run(minutes: u64, placing: Placing) -> Result<(), String> {
    hvf_host().map_err(|why| format!("rtbench 2 runs on HVF and VZ: {why}"))?;
    let seconds = minutes * 60;
    let kernel = build(Variant::Normal)?;
    let image_qemu = image("rtbench-posix.img", &RTBENCH_POSIX_PROGRAMS, seconds)?;
    let image_vz = image("rtbench-posix-vz.img", &RTBENCH_POSIX_VZ_PROGRAMS, seconds)?;
    let mut hvf = qemu::command(&qemu::HVF_V3, &kernel.image, Some(&image_qemu));
    hvf.args(qemu::HEADLESS);
    let vz = vz::command(&kernel.image, &image_vz)?;
    match placing {
        Placing::Serial => {
            measure(hvf, "hvf", seconds)?;
            vz::stop_hint(measure(vz, "vz", seconds))?;
        }
        Placing::Concurrent => {
            // Each run keeps its output, shown whole once both ended.
            let ((hvf, hvf_out), (vz, vz_out)) = std::thread::scope(|scope| {
                let hvf = scope.spawn(|| crate::out::capture(1, || measure(hvf, "hvf", seconds)));
                let vz = scope
                    .spawn(|| crate::out::capture(2, || vz::stop_hint(measure(vz, "vz", seconds))));
                (
                    hvf.join().expect("the HVF run does not panic"),
                    vz.join().expect("the VZ run does not panic"),
                )
            });
            print!("{hvf_out}{vz_out}");
            hvf?;
            vz?;
        }
    }
    Ok(())
}

/// One round on QEMU TCG (`ci`): the scenarios run and their rows are
/// whole; its numbers compare nothing.
pub fn short() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = image("rtbench-posix-short.img", &RTBENCH_POSIX_PROGRAMS, 0)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    measure(cmd, "tcg", 0).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines() -> Vec<String> {
        let mut lines = vec![
            "RTB2 START hz=24000000 seconds=0".to_owned(),
            "RTB2 calls yield=1".to_owned(),
            "RTB2 round 1".to_owned(),
        ];
        for name in ROWS {
            lines.push(match name {
                "s2_futex_wake_idle" => format!("RTB2 {name} none no futex yet"),
                "s7_missed" => format!("RTB2 {name} 0"),
                "load_rounds" => format!("RTB2 {name} 17"),
                "s1_mutex_alone" => {
                    format!("RTB2 {name} n=3 min=1 p50=2 p99=5 max=5 calls=12 h=1,1,1")
                }
                _ => format!("RTB2 {name} n=3 min=1 p50=2 p99=5 max=5 h=1,1,1"),
            });
        }
        lines.push("RTB2 DONE rounds=1".to_owned());
        lines
    }

    #[test]
    fn a_whole_run_parses_and_writes_every_row() {
        let run = parse(&lines()).unwrap();
        assert_eq!(run.rows.len(), ROWS.len());
        assert_eq!(run.rounds, 1);
        let Row::Numbers(s1) = &run.rows[0].1 else {
            panic!("s1 has numbers");
        };
        assert_eq!(s1.calls, Some(12));
        assert_eq!(s1.histogram, [1, 1, 1]);
        let text = file("tcg", "abc", 0, ["u0", "u1"], &run);
        assert!(text.contains("s1_mutex_alone 3 1 2 5 5 4.00 | 1,1,1\n"));
        assert!(text.contains("s2_futex_wake_idle none: no futex yet\n"));
        assert!(text.contains("uptime before: u0\nuptime after: u1\n"));
    }

    #[test]
    fn a_load_that_stopped_or_made_no_rounds_fails_the_run() {
        let mut lines = lines();
        lines.insert(
            3,
            "rtbench-load: failed after 3 rounds: NoMemory".to_owned(),
        );
        assert!(parse(&lines).unwrap_err().starts_with("the load stopped"));
        let mut lines = self::lines();
        lines.insert(
            3,
            "init: rtbench-load ended: exit code 1, not restarted".to_owned(),
        );
        assert!(parse(&lines).unwrap_err().starts_with("the load stopped"));
        for rounds in ["0", "18446744073709551615"] {
            let lines: Vec<_> = self::lines()
                .into_iter()
                .map(|l| {
                    if l.starts_with("RTB2 load_rounds ") {
                        format!("RTB2 load_rounds {rounds}")
                    } else {
                        l
                    }
                })
                .collect();
            assert!(
                parse(&lines)
                    .unwrap_err()
                    .starts_with("the load made no rounds")
            );
        }
    }

    #[test]
    fn a_missing_row_fails_the_run() {
        let lines: Vec<_> = lines()
            .into_iter()
            .filter(|l| !l.starts_with("RTB2 s6_read_ready "))
            .collect();
        assert_eq!(parse(&lines).unwrap_err(), "no row s6_read_ready");
    }

    #[test]
    fn a_histogram_that_does_not_sum_to_n_fails_the_run() {
        let mut lines = lines();
        let at = lines
            .iter()
            .position(|l| l.starts_with("RTB2 s3_mutex_rival_30 "))
            .unwrap();
        lines[at] = "RTB2 s3_mutex_rival_30 n=3 min=1 p50=2 p99=5 max=5 h=1,1".to_owned();
        assert!(
            parse(&lines)
                .unwrap_err()
                .starts_with("the histogram does not sum to n")
        );
    }

    #[test]
    fn a_counter_that_counts_twice_or_a_failure_fails_the_run() {
        let mut lines = lines();
        lines[1] = "RTB2 calls yield=2".to_owned();
        assert!(
            parse(&lines)
                .unwrap_err()
                .starts_with("the counter of calls")
        );
        let mut lines = self::lines();
        lines.insert(3, "RTB2 FAIL S5 read 4".to_owned());
        assert!(
            parse(&lines)
                .unwrap_err()
                .starts_with("the benchmark failed")
        );
        let mut lines = self::lines();
        lines.pop();
        assert_eq!(parse(&lines).unwrap_err(), "no RTB2 DONE");
    }
}
