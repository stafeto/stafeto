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
    BOOT_PROFILE, ImageProgram, RTBENCH_POSIX_PROGRAMS, RTBENCH_POSIX_VZ_PROGRAMS, S5_ICOUNT_MAX,
    S5_ICOUNT_SLACK, Variant, build, guard_lower_hint, guard_margin, hvf_host, qemu, target_dir,
    vz, write_boot_image_with,
};

/// The rows of a run, in its order: each comes once, as numbers or as
/// `none` with the reason the layer has no such operation yet.
pub const ROWS: [&str; 56] = [
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
    "s19_pipe_ping_pong",
    "s20_pipe_1m_w512",
    "s20_pipe_1m_w4k",
    "s22_ls_etc_cat",
    "s23_getentropy_32",
    "s24_getentropy_256",
    "s25_urandom_4k",
    "s26_pty_echo_byte",
    "s27_pty_ctrl_c_idle",
    "s27_pty_ctrl_c_busy_25",
    "s28_stop_threads_128",
    "s28_cont_threads_128",
    "s29_pipe_write_to_poll",
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
        if (name.starts_with("s26_")
            || name.starts_with("s27_")
            || name.starts_with("s28_")
            || name.starts_with("s29_"))
            && !matches!(row, Row::Numbers(_))
        {
            return Err(format!("required scenario has no measurements: {name}"));
        }
        rows.push((name, row));
    }
    let readiness: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("RTB2 S28 ready "))
        .collect();
    if readiness.len() as u64 != rounds {
        return Err("S28 readiness must confirm each round".into());
    }
    for line in readiness {
        let words: Vec<_> = line.split_whitespace().collect();
        let total = field(&words, "kernel_threads=", line)?;
        let native = field(&words, "native_threads=", line)?;
        let existing = field(&words, "existing_threads=", line)?;
        if total != 128
            || native == 0
            || existing == 0
            || native.checked_add(existing) != Some(total)
        {
            return Err(format!("S28 thread count is wrong: {line}"));
        }
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
    measure_lines(cmd, machine, seconds).map(|(run, _)| run)
}

/// `measure` with the lines of the machine's output.
fn measure_lines(cmd: Command, machine: &str, seconds: u64) -> Result<(Run, Vec<String>), String> {
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
    Ok((run, outcome.lines))
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
    // The `ls` and `cat` of S22 are BusyBox's.
    crate::relibc()?;
    crate::busybox_build()?;
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

/// How `rtbench --short` runs its round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Short {
    /// On TCG at its own speed: the rows are whole, the numbers compare
    /// nothing.
    Plain,
    /// Under -icount (`ci`): a tick is an instruction, and the path of
    /// `pthread_kill` (S5) stays under `S5_ICOUNT_MAX`.
    Icount,
    /// Under -icount with the marks of posix-abi along that path: the
    /// segments are printed and the guard is not checked (the marks add
    /// instructions).
    Marks,
}

/// The instructions of the three rows of S5: the `min` of each, in ticks of
/// the counter, which under -icount are instructions.
fn s5_ticks(run: &Run) -> Result<Vec<u64>, String> {
    S5_ROWS
        .iter()
        .map(|name| match run.rows.iter().find(|(n, _)| n == name) {
            // The file keeps nanoseconds: a tick is 1e9 / hz of them.
            Some((_, Row::Numbers(r))) => {
                Ok((u128::from(r.min) * u128::from(run.hz) + 500_000_000) as u64 / 1_000_000_000)
            }
            _ => Err(format!("no numbers for {name}")),
        })
        .collect()
}

const S5_ROWS: [&str; 3] = ["s5_kill_sleeping", "s5_kill_reading", "s5_kill_busy_25"];

/// The room the S5 rows of an -icount run leave under `max` (the least of
/// the three), or the error that names the row past it.
fn s5_room(run: &Run, max: u64) -> Result<u64, String> {
    let ticks = s5_ticks(run)?;
    let mut room = u64::MAX;
    for name in S5_ROWS {
        room = room.min(guard_margin(
            "S5 under icount",
            &S5_ROWS,
            &ticks,
            name,
            max,
        )?);
    }
    Ok(room)
}

/// The lines `MARKS a b c d e f g h` that posix-abi prints (feature
/// `rtbench-marks`): the counter ticks and kernel calls of the segments
/// `kill_relibc_thread` to the request, the request to `dispatch`,
/// `dispatch` to `deliver`, `deliver` to the handler.
/// The rows of the three scenarios come in turn, `size` each; the first
/// signal of each is a warm-up. Returns the median of each scenario.
fn marks_summary(lines: &[String]) -> Result<Vec<String>, String> {
    let rows: Vec<Vec<i64>> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("MARKS "))
        .map(|l| l.split_whitespace().map(|w| w.parse::<i64>()).collect())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("bad MARKS line: {e}"))?;
    let size = rows.len() / S5_ROWS.len();
    if size < 2 || rows.iter().any(|r| r.len() != 8) {
        return Err(format!(
            "{} MARKS lines do not make three scenarios",
            rows.len()
        ));
    }
    let mut out = Vec::new();
    for (g, name) in S5_ROWS.iter().enumerate() {
        let part = &rows[g * size + 1..(g + 1) * size];
        let med: Vec<i64> = (0..8)
            .map(|i| {
                let mut column: Vec<i64> = part.iter().map(|r| r[i]).collect();
                column.sort_unstable();
                column[column.len() / 2]
            })
            .collect();
        out.push(format!(
            "{name} ({} signals): kill_relibc_thread to request {}/{}, request to dispatch {}/{}, dispatch to deliver {}/{}, deliver to handler {}/{} (ticks/kernel calls)",
            part.len(), med[0], med[1], med[2], med[3], med[4], med[5], med[6], med[7]
        ));
    }
    Ok(out)
}

/// `cargo xtask rtbench --short [--icount [--marks]]`: one round on QEMU
/// TCG (`ci`); the scenarios run and their rows are whole.
pub fn short(how: Short) -> Result<(), String> {
    crate::relibc()?;
    crate::busybox_build()?;
    let kernel = build(Variant::Normal)?;
    let mut programs = RTBENCH_POSIX_PROGRAMS;
    if how == Short::Marks {
        let at = programs
            .iter()
            .position(|p| p.1 == "rtbench-posix")
            .ok_or("no rtbench-posix in the image")?;
        programs[at].3 = &["rtbench-marks"];
    }
    let image = image("rtbench-posix-short.img", &programs, 0)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    if how == Short::Plain {
        return measure(cmd, "tcg", 0).map(drop);
    }
    cmd.args(qemu::ICOUNT);
    let (run, lines) = measure_lines(cmd, "icount", 0)?;
    if how == Short::Marks {
        for line in marks_summary(&lines)? {
            println!("{line}");
        }
        return Ok(());
    }
    let room = s5_room(&run, S5_ICOUNT_MAX)?;
    println!(
        "S5 instructions under icount: {} of S5_ICOUNT_MAX {S5_ICOUNT_MAX}, room {room}",
        s5_ticks(&run)?
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    );
    if let Some(hint) = guard_lower_hint("S5_ICOUNT_MAX", room, S5_ICOUNT_SLACK, S5_ICOUNT_MAX) {
        println!("{hint}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines() -> Vec<String> {
        let mut lines = vec![
            "RTB2 START hz=24000000 seconds=0".to_owned(),
            "RTB2 calls yield=1".to_owned(),
            "RTB2 round 1".to_owned(),
            "RTB2 S28 ready kernel_threads=128 native_threads=127 existing_threads=1".to_owned(),
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
    fn required_terminal_rows_and_exact_thread_count_are_enforced() {
        for name in ROWS.iter().filter(|name| {
            name.starts_with("s26_")
                || name.starts_with("s27_")
                || name.starts_with("s28_")
                || name.starts_with("s29_")
        }) {
            let mut lines = self::lines();
            let at = lines
                .iter()
                .position(|l| l.starts_with(&format!("RTB2 {name} ")))
                .unwrap();
            lines[at] = format!("RTB2 {name} none unsupported");
            assert!(parse(&lines).unwrap_err().contains("required scenario"));
        }
        let mut lines = self::lines();
        let at = lines
            .iter()
            .position(|l| l.starts_with("RTB2 S28 ready "))
            .unwrap();
        lines[at] =
            "RTB2 S28 ready kernel_threads=127 native_threads=126 existing_threads=1".into();
        assert!(parse(&lines).unwrap_err().contains("thread count"));
        lines.remove(at);
        assert!(parse(&lines).unwrap_err().contains("each round"));
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

    fn run_with_s5(min_ns: u64) -> Run {
        let mut lines = lines();
        lines[0] = "RTB2 START hz=62500000 seconds=0".to_owned();
        for name in S5_ROWS {
            let at = lines
                .iter()
                .position(|l| l.starts_with(&format!("RTB2 {name} ")))
                .unwrap();
            lines[at] =
                format!("RTB2 {name} n=3 min={min_ns} p50={min_ns} p99={min_ns} max={min_ns} h=3");
        }
        parse(&lines).unwrap()
    }

    /// 16 ns a tick under -icount: 2 772 instructions are 44 352 ns.
    #[test]
    fn the_guard_of_s5_holds_at_its_number_and_fires_one_over() {
        let at = run_with_s5(S5_ICOUNT_MAX * 16);
        assert_eq!(s5_ticks(&at).unwrap(), [S5_ICOUNT_MAX; 3]);
        assert_eq!(s5_room(&at, S5_ICOUNT_MAX), Ok(0));
        let head = run_with_s5(2_756 * 16);
        assert_eq!(s5_room(&head, S5_ICOUNT_MAX), Ok(16));
        let over = run_with_s5((S5_ICOUNT_MAX + 1) * 16);
        let error = s5_room(&over, S5_ICOUNT_MAX).unwrap_err();
        assert!(
            error.contains("s5_kill_sleeping=2773") && error.contains("1 past its guard 2772"),
            "{error}"
        );
        // One row alone over the number fires too.
        let mut one = run_with_s5(2_756 * 16);
        let at = one
            .rows
            .iter()
            .position(|(n, _)| *n == "s5_kill_busy_25")
            .unwrap();
        if let Row::Numbers(r) = &mut one.rows[at].1 {
            r.min = 2_790 * 16;
        }
        assert!(
            s5_room(&one, S5_ICOUNT_MAX)
                .unwrap_err()
                .contains("s5_kill_busy_25=2790")
        );
    }

    #[test]
    fn marks_give_the_median_of_each_scenario_without_its_warm_up() {
        let mut lines = vec!["noise".to_owned()];
        for scenario in 0..3 {
            // The warm-up is far off; the others are 100, 101, 102.
            lines.push("MARKS 9999 9 9999 9 9999 9 9999 9".to_owned());
            for i in 0..3 {
                let t = 100 + i + scenario * 10;
                lines.push(format!("MARKS {t} 1 {t} 0 {t} 1 {t} 0"));
            }
        }
        let out = marks_summary(&lines).unwrap();
        assert_eq!(out.len(), 3);
        assert!(out[0].contains("to request 101/1, request to dispatch 101/0"));
        assert!(
            out[2].contains("dispatch to deliver 121/1, deliver to handler 121/0"),
            "{}",
            out[2]
        );
        assert!(marks_summary(&lines[..3]).is_err());
    }
}
