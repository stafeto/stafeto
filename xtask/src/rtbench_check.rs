// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask rtbench-check [--same-guest OLD=NEW]... <session>...`: the acceptance of epoch 2 for
//! the path of `pthread_kill` and of a signal of the process, read from the
//! files of several sessions of `rtbench --minutes N --serial`. A session
//! is a directory with the file `order` (`base-first` or `head-first`: which
//! of its two runs came first; the check compares it with the `uptime before`
//! lines of the runs) and the directories `base` and `head`, each
//! with `rtbench-hvf.txt` and `rtbench-vz.txt` (rtbench2.rs, `file`). The
//! sessions are listed in the order they were made and alternate in their
//! `order`, so that a drift of the host over the hours does not favour one
//! commit. The rules, on each machine:
//!
//! - at least `MIN_SESSIONS` sessions, alternating in order;
//! - the three rows `s5_*`, the p50 in ticks of the counter (the file keeps
//!   nanoseconds, and a cell of the histogram is a whole number of ticks):
//!   p50 of the head at most `S5_P50_MAX_TICKS` in every session, which holds
//!   the drift of the base between epochs, and the median over the sessions
//!   of the difference of the p50s (head minus base of the same session) at
//!   most `S5_P50_DELTA_MAX_TICKS`, which catches the growth from one
//!   change; the median over the sessions of the difference of the p99s
//!   (head minus base of the same session, each p99 first turned into whole
//!   ticks of the counter of its own session) at most `P99_DELTA_MAX_TICKS`;
//! - the two rows `s10_*`: the median over the sessions of the ratio of the
//!   p50 of the head to the p50 of the base at most `S10_P50_PERCENT` over
//!   100.
//!
//! `--same-guest OLD=NEW` declares that the guest code of commit OLD is that of
//! NEW (a commit that changed only the host's tools, as `git diff` over the
//! guest's directories shows): a file that names OLD counts as NEW, and the
//! header of the table says so. With it the archive of a run
//! (`reports/raw/<head>/.../sN`) repeats the check as it was made.
//!
//! The median of the paired differences takes out the drift of the host
//! between sessions and the lone tails of a cell: the p99 of 11 900 samples
//! is its 119th from the top, and the same commit moves it by up to 96 ns
//! (two to three ticks) from one session to the next. Rows of S15 and S28
//! are printed without a limit. The table goes to the output; the error
//! names every row that is over.

use std::collections::BTreeMap;
use std::path::Path;

/// The sessions a machine needs before its comparison counts.
pub const MIN_SESSIONS: usize = 4;
/// The most the p50 of the path of `pthread_kill` may have, in ticks of the
/// counter: the median p50 of the base is 13 ticks, and 10 % over it is 14.3,
/// whole 14 (583 ns, the cell 591). A tick is the unit of the measure (the
/// difference of two reads of the counter, one tick either way); the
/// histogram cell [528, 543] holds exactly 13 ticks, so a limit in
/// nanoseconds sat inside the noise of the base.
pub const S5_P50_MAX_TICKS: u64 = 14;
/// The most the median over the sessions of the p50 of the head minus the
/// p50 of the base of the same session may be, in ticks (7.7 % of 13).
pub const S5_P50_DELTA_MAX_TICKS: i64 = 1;
/// The most the median of the differences of the p99, head minus base, may be,
/// in ticks of the counter (83 ns at 24 MHz). Each p99 is turned into whole
/// ticks by the frequency of its own session before the subtraction, as the
/// p50 is, so that the limit is the number of the acceptance and does not
/// depend on the rounding of a conversion to nanoseconds.
pub const P99_DELTA_MAX_TICKS: i64 = 2;
/// The median ratio of the p50 of a signal of the process to the base's may
/// be this many percent.
pub const S10_P50_PERCENT: u64 = 110;
/// The rows with a limit, and the rows printed beside them.
const S5_ROWS: [&str; 3] = ["s5_kill_sleeping", "s5_kill_reading", "s5_kill_busy_25"];
const S10_ROWS: [&str; 2] = ["s10_kill_process_sleeping", "s10_kill_process_busy_25"];
const RECORDED_ROWS: [&str; 5] = [
    "s15_fork_to_child",
    "s15_fork_heap_1m",
    "s15_fork_heap_8m",
    "s28_stop_threads_128",
    "s28_cont_threads_128",
];
const MACHINES: [&str; 2] = ["hvf", "vz"];

/// What a file of a run says about a row, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Figures {
    n: u64,
    p50: u64,
    p99: u64,
}

/// A time in nanoseconds as whole ticks of a counter of `hz`.
fn ticks(ns: u64, hz: u64) -> i64 {
    ((u128::from(ns) * u128::from(hz) + 500_000_000) / 1_000_000_000) as i64
}

#[derive(Debug)]
struct Measured {
    commit: String,
    seconds: u64,
    /// The frequency of the counter, from the line `counter N Hz`.
    hz: u64,
    /// The host's uptime at the start of the run, in minutes.
    before: u64,
    rows: BTreeMap<String, Figures>,
}

/// The minutes of the uptime in a line of `uptime`: `... up 35 days, 9:58,
/// 2 users`, `up 35 days, 11 hrs, 2 users`, `up 12 mins, 1 user`.
fn uptime_minutes(line: &str) -> Option<u64> {
    let after = line.split_once(" up ")?.1;
    let mut minutes = 0;
    let mut seen = false;
    for part in after.split(',') {
        let part = part.trim();
        if part.contains("user") {
            break;
        }
        if let Some((hours, mins)) = part.split_once(':') {
            minutes += hours.trim().parse::<u64>().ok()? * 60 + mins.trim().parse::<u64>().ok()?;
        } else {
            let (count, unit) = part.split_once(' ')?;
            let count: u64 = count.parse().ok()?;
            minutes += count
                * match unit.trim() {
                    "day" | "days" => 24 * 60,
                    "hr" | "hrs" => 60,
                    "min" | "mins" => 1,
                    "sec" | "secs" => 0,
                    _ => return None,
                };
        }
        seen = true;
    }
    seen.then_some(minutes)
}

/// The file of a run as `rtbench2::file` writes it.
fn parse_file(text: &str) -> Result<Measured, String> {
    let mut commit = None;
    let mut seconds = None;
    let mut hz = None;
    let mut before = None;
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("uptime before:") {
            before = Some(uptime_minutes(rest).ok_or_else(|| format!("uptime line {rest:?}"))?);
        } else if let Some(rest) = line.strip_prefix("commit ") {
            commit = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("seconds ") {
            seconds = rest
                .split(',')
                .next()
                .and_then(|s| s.trim().parse::<u64>().ok());
            hz = rest
                .split_once("counter ")
                .and_then(|(_, tail)| tail.split_whitespace().next())
                .and_then(|word| word.parse::<u64>().ok());
        } else if let Some((left, _)) = line.split_once(" | ") {
            let words: Vec<_> = left.split_whitespace().collect();
            // name n min p50 p99 max calls
            if let [name, n, _min, p50, p99, _max, _calls] = words.as_slice()
                && let (Ok(n), Ok(p50), Ok(p99)) = (n.parse(), p50.parse(), p99.parse())
            {
                rows.insert((*name).to_owned(), Figures { n, p50, p99 });
            }
        }
    }
    Ok(Measured {
        commit: commit.ok_or("no commit line")?,
        seconds: seconds.ok_or("no seconds line")?,
        hz: hz.filter(|hz| *hz > 0).ok_or("no counter frequency")?,
        before: before.ok_or("no uptime before line")?,
        rows,
    })
}

fn row<'a>(run: &'a Measured, name: &str, what: &str) -> Result<&'a Figures, String> {
    run.rows
        .get(name)
        .filter(|f| f.n > 0)
        .ok_or_else(|| format!("{what} has no numbers for {name}"))
}

/// One session on one machine: which run came first, and the two files.
struct Session<'a> {
    base_first: bool,
    base: &'a str,
    head: &'a str,
}

/// Twice the median, so that the middle of an even count stays whole.
fn median_x2(values: &[i64]) -> i64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    if n % 2 == 1 {
        2 * sorted[n / 2]
    } else {
        sorted[n / 2 - 1] + sorted[n / 2]
    }
}

fn median_f64(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// A median written as the integer it is, or with `.5`.
fn show_x2(x2: i64) -> String {
    if x2 % 2 == 0 {
        (x2 / 2).to_string()
    } else {
        format!("{}.5", x2.div_euclid(2))
    }
}

fn list(values: &[i64]) -> String {
    let words: Vec<_> = values.iter().map(|v| format!("{v:+}")).collect();
    words.join(" ")
}

/// The comparison of one machine over its sessions: its table, and the rows
/// that are over.
fn compare(
    machine: &str,
    sessions: &[Session],
    same_guest: &[(String, String)],
) -> Result<(String, Vec<String>), String> {
    let canon = |commit: &str| {
        same_guest
            .iter()
            .find(|(old, _)| old == commit)
            .map_or(commit.to_owned(), |(_, new)| new.clone())
    };
    if sessions.len() < MIN_SESSIONS {
        return Err(format!(
            "{machine}: need {MIN_SESSIONS} sessions, have {}",
            sessions.len()
        ));
    }
    if sessions
        .windows(2)
        .any(|pair| pair[0].base_first == pair[1].base_first)
    {
        return Err(format!(
            "{machine}: the sessions must alternate in order (base first, head first)"
        ));
    }
    let mut pairs = Vec::new();
    for (i, session) in sessions.iter().enumerate() {
        let n = i + 1;
        let base =
            parse_file(session.base).map_err(|e| format!("{machine} session {n} base: {e}"))?;
        let head =
            parse_file(session.head).map_err(|e| format!("{machine} session {n} head: {e}"))?;
        if base.seconds != head.seconds {
            return Err(format!(
                "{machine} session {n}: the runs differ in length ({} s and {} s)",
                base.seconds, head.seconds
            ));
        }
        // The file `order` says which run came first; the host's uptime at
        // the start of each run says it too.
        let (first, second) = if session.base_first {
            (&base, &head)
        } else {
            (&head, &base)
        };
        if first.before >= second.before {
            return Err(format!(
                "{machine} session {n}: the order says {} first, but the uptime before of the runs is {} min (base) and {} min (head)",
                if session.base_first { "base" } else { "head" },
                base.before,
                head.before
            ));
        }
        pairs.push((base, head));
    }
    // The sessions come in the order they were made.
    for (i, pair) in pairs.windows(2).enumerate() {
        let last = pair[0].0.before.max(pair[0].1.before);
        let first = pair[1].0.before.min(pair[1].1.before);
        if first <= last {
            return Err(format!(
                "{machine}: session {} starts at uptime {first} min, not after session {} (last start {last} min)",
                i + 2,
                i + 1
            ));
        }
    }
    let (base0, head0) = &pairs[0];
    for (i, (base, head)) in pairs.iter().enumerate() {
        if canon(&base.commit) != canon(&base0.commit)
            || canon(&head.commit) != canon(&head0.commit)
            || base.seconds != base0.seconds
        {
            return Err(format!(
                "{machine} session {}: commits {} and {} (or the length) differ from session 1 ({} and {})",
                i + 1,
                base.commit,
                head.commit,
                base0.commit,
                head0.commit
            ));
        }
    }
    let mut table = format!(
        "{machine}: base {} and head {}, {} s, {} sessions\n",
        canon(&base0.commit),
        canon(&head0.commit),
        base0.seconds,
        pairs.len()
    );
    for (old, new) in same_guest {
        table += &format!("same guest: {old}={new} (declared)\n");
    }
    let mut over = Vec::new();
    for name in S5_ROWS {
        let mut head_p50 = Vec::new();
        let mut p50_deltas = Vec::new();
        let mut deltas = Vec::new();
        for (base, head) in &pairs {
            let (b, h) = (row(base, name, "base")?, row(head, name, "head")?);
            let head_ticks = ticks(h.p50, head.hz);
            head_p50.push(head_ticks);
            p50_deltas.push(head_ticks - ticks(b.p50, base.hz));
            deltas.push(ticks(h.p99, head.hz) - ticks(b.p99, base.hz));
        }
        let median = median_x2(&deltas);
        let p50_median = median_x2(&p50_deltas);
        let mut broken = Vec::new();
        for (i, p50) in head_p50.iter().enumerate() {
            if *p50 > S5_P50_MAX_TICKS as i64 {
                broken.push(format!(
                    "p50 {p50} ticks over {S5_P50_MAX_TICKS} in session {}",
                    i + 1
                ));
            }
        }
        if p50_median > 2 * S5_P50_DELTA_MAX_TICKS {
            broken.push(format!(
                "median p50 difference {} ticks over {S5_P50_DELTA_MAX_TICKS}",
                show_x2(p50_median)
            ));
        }
        if median > 2 * P99_DELTA_MAX_TICKS {
            broken.push(format!(
                "median p99 difference {} ticks over {P99_DELTA_MAX_TICKS}",
                show_x2(median)
            ));
        }
        if !broken.is_empty() {
            over.push(format!("{machine} {name}: {}", broken.join(", ")));
        }
        table += &format!(
            "{name:<28} head p50 {} ticks, minus base [{}] median {}  p99 head minus base [{}] median {}  limit: p50 <= {S5_P50_MAX_TICKS}, p50 median <= {S5_P50_DELTA_MAX_TICKS}, p99 median <= {P99_DELTA_MAX_TICKS}\n",
            list(&head_p50).replace('+', ""),
            list(&p50_deltas),
            show_x2(p50_median),
            list(&deltas),
            show_x2(median)
        );
    }
    for name in S10_ROWS {
        let mut ratios = Vec::new();
        for (base, head) in &pairs {
            let (b, h) = (row(base, name, "base")?, row(head, name, "head")?);
            ratios.push(h.p50 as f64 / b.p50 as f64);
        }
        let median = median_f64(&ratios);
        let limit = S10_P50_PERCENT as f64 / 100.0;
        if median > limit + 1e-9 {
            over.push(format!(
                "{machine} {name}: median p50 ratio {median:.3} over {limit:.2}"
            ));
        }
        let words: Vec<_> = ratios.iter().map(|r| format!("{r:.3}")).collect();
        table += &format!(
            "{name:<28} p50 head/base [{}] median {median:.3}  limit: median <= {limit:.2}\n",
            words.join(" ")
        );
    }
    for name in RECORDED_ROWS {
        let mut figures = Vec::new();
        for (base, head) in &pairs {
            figures.push((row(base, name, "base")?, row(head, name, "head")?));
        }
        let med = |pick: &dyn Fn(&(&Figures, &Figures)) -> u64| {
            show_x2(median_x2(
                &figures.iter().map(|f| pick(f) as i64).collect::<Vec<_>>(),
            ))
        };
        table += &format!(
            "{name:<28} median p50 {} to {}, p99 {} to {}  limit: none\n",
            med(&|f| f.0.p50),
            med(&|f| f.1.p50),
            med(&|f| f.0.p99),
            med(&|f| f.1.p99)
        );
    }
    Ok((table, over))
}

/// The tables and the verdict for the texts of the files, the sessions of
/// each machine in the order they were made.
fn check_texts(
    machines: &[(&str, Vec<Session>)],
    same_guest: &[(String, String)],
) -> Result<String, String> {
    let mut report = String::new();
    let mut over = Vec::new();
    for (machine, sessions) in machines {
        let (table, rows) = compare(machine, sessions, same_guest)?;
        report += &table;
        report.push('\n');
        over.extend(rows);
    }
    if over.is_empty() {
        Ok(report)
    } else {
        print!("{report}");
        Err(format!("over the limit: {}", over.join("; ")))
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: rtbench-check [--same-guest OLD=NEW]... <session directory>...";
    let mut same_guest = Vec::new();
    let mut dirs = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if word == "--same-guest" {
            let pair = words.next().ok_or(usage)?;
            let (old, new) = pair.split_once('=').ok_or(usage)?;
            same_guest.push((old.to_owned(), new.to_owned()));
        } else {
            dirs.push(word);
        }
    }
    if dirs.is_empty() {
        return Err(usage.to_owned());
    }
    let read = |path: std::path::PathBuf| {
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    // texts[session] = (base_first, [(machine, base, head)])
    let mut texts = Vec::new();
    for dir in dirs.iter().copied() {
        let dir = Path::new(dir);
        let order = read(dir.join("order"))?;
        let base_first = match order.trim() {
            "base-first" => true,
            "head-first" => false,
            other => return Err(format!("{}: order {other:?}", dir.display())),
        };
        let mut files = Vec::new();
        for machine in MACHINES {
            let name = format!("rtbench-{machine}.txt");
            files.push((
                machine,
                read(dir.join("base").join(&name))?,
                read(dir.join("head").join(&name))?,
            ));
        }
        texts.push((base_first, files));
    }
    let machines: Vec<_> = MACHINES
        .iter()
        .enumerate()
        .map(|(m, machine)| {
            let sessions = texts
                .iter()
                .map(|(base_first, files)| Session {
                    base_first: *base_first,
                    base: files[m].1.as_str(),
                    head: files[m].2.as_str(),
                })
                .collect();
            (*machine, sessions)
        })
        .collect();
    print!("{}", check_texts(&machines, &same_guest)?);
    println!(
        "rtbench-check: within the limits on hvf and vz over {} sessions",
        dirs.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file with the figures of a run: the s5 rows, the s10 rows and the
    /// rows without a limit.
    fn file(commit: &str, seconds: u64, s5: [(u64, u64); 3], s10: [(u64, u64); 2]) -> String {
        let mut text = format!(
            "rtbench 2 on hvf\ncommit {commit}\nseconds {seconds}, rounds 12, counter 24000000 Hz (a tick is 41.7 ns)\nuptime before: x\nuptime after: y\n\nrow n min p50 p99 max (ns) calls/op | histogram\n"
        );
        for (name, (p50, p99)) in S5_ROWS.into_iter().zip(s5) {
            text += &format!("{name} 100 1 {p50} {p99} {p99} - | 1,2\n");
        }
        for (name, (p50, p99)) in S10_ROWS.into_iter().zip(s10) {
            text += &format!("{name} 50 1 {p50} {p99} {p99} - | 1,2\n");
        }
        for name in RECORDED_ROWS {
            text += &format!("{name} 10 1 5000 9000 9000 - | 1,2\n");
        }
        text
    }

    fn base() -> String {
        file(
            "4f3c7d0",
            600,
            [(503, tick_ns(24)), (503, tick_ns(19)), (503, tick_ns(17))],
            [(1983, 7000), (1695, 7000)],
        )
    }

    /// Nanoseconds of a whole number of ticks of the 24 MHz counter, which
    /// `ticks` turns back into the same number.
    fn tick_ns(ticks: u64) -> u64 {
        (ticks * 1_000_000_000 + 12_000_000) / 24_000_000
    }

    /// A head with the figures of the base plus `delta` ticks on every p99 of S5
    /// and `p50` on every p50 of S5, S10 as the base times `ratio` percent.
    fn head(delta: [u64; 3], p50: u64, ratio: u64) -> String {
        file(
            "abc",
            600,
            [
                (p50, tick_ns(24 + delta[0])),
                (p50, tick_ns(19 + delta[1])),
                (p50, tick_ns(17 + delta[2])),
            ],
            [(1983 * ratio / 100, 7000), (1695 * ratio / 100, 7000)],
        )
    }

    /// The text of a run that started when the host had been up `minutes`.
    fn timed(text: &str, minutes: u64) -> String {
        text.replace(
            "uptime before: x",
            &format!("uptime before: 1:00  up {minutes} mins, 1 user, load averages: 1"),
        )
    }

    /// Four sessions alternating in order, one head each: (base first, base
    /// text, head text), ten minutes between the two runs and an hour
    /// between sessions.
    fn four(heads: &[String; 4]) -> Vec<(bool, String, String)> {
        heads
            .iter()
            .enumerate()
            .map(|(i, head)| {
                let start = 100 + 60 * i as u64;
                let base_first = i % 2 == 0;
                let (b, h) = if base_first {
                    (start, start + 10)
                } else {
                    (start + 10, start)
                };
                (base_first, timed(&base(), b), timed(head, h))
            })
            .collect()
    }

    fn sessions(owned: &[(bool, String, String)]) -> Vec<Session<'_>> {
        owned
            .iter()
            .map(|(base_first, base, head)| Session {
                base_first: *base_first,
                base,
                head,
            })
            .collect()
    }

    fn check(heads: &[String; 4]) -> Result<String, String> {
        let owned = four(heads);
        check_texts(&[("hvf", sessions(&owned)), ("vz", sessions(&owned))], &[])
    }

    #[test]
    fn a_head_within_the_limits_passes() {
        let ok = head([2, 2, 2], 543, 110);
        let report = check(&[ok.clone(), ok.clone(), ok.clone(), ok]).unwrap();
        assert!(report.contains("s5_kill_busy_25"), "{report}");
        assert!(report.contains("s15_fork_heap_8m"), "{report}");
    }

    /// One noisy cell and the median passes: the differences 4, 1, 1, 1 ticks
    /// (HVF `reading`) have the median 1.
    #[test]
    fn a_noisy_cell_with_a_passing_median_passes() {
        let heads = [
            head([0, 4, 0], 503, 100),
            head([0, 1, 0], 503, 100),
            head([0, 1, 0], 503, 100),
            head([0, 1, 0], 503, 100),
        ];
        let report = check(&heads).unwrap();
        assert!(report.contains("[+4 +1 +1 +1] median 1"), "{report}");
    }

    /// A shift in three of four sessions fails whatever the fourth does.
    #[test]
    fn a_median_over_the_slack_fails() {
        let heads = [
            head([0, 3, 0], 503, 100),
            head([0, 3, 0], 503, 100),
            head([0, 3, 0], 503, 100),
            head([0, 0, 0], 503, 100),
        ];
        let error = check(&heads).unwrap_err();
        assert!(
            error.contains("s5_kill_reading: median p99 difference 3 ticks over 2"),
            "{error}"
        );
        // The middle of an even count: 3 and 2 give 2.5.
        let heads = [
            head([0, 3, 0], 503, 100),
            head([0, 2, 0], 503, 100),
            head([0, 8, 0], 503, 100),
            head([0, 0, 0], 503, 100),
        ];
        assert!(check(&heads).unwrap_err().contains("2.5 ticks over 2"));
        // Two ticks in every session stay within the limit.
        let heads = [
            head([0, 2, 0], 503, 100),
            head([0, 2, 0], 503, 100),
            head([0, 2, 0], 503, 100),
            head([0, 2, 0], 503, 100),
        ];
        check(&heads).unwrap();
    }

    /// Sessions with the given orders, the uptimes following the orders.
    fn ordered(base_first: &[bool]) -> Vec<(bool, String, String)> {
        let ok = head([0, 0, 0], 503, 100);
        base_first
            .iter()
            .enumerate()
            .map(|(i, &first)| {
                let start = 100 + 60 * i as u64;
                let (b, h) = if first {
                    (start, start + 10)
                } else {
                    (start + 10, start)
                };
                (first, timed(&base(), b), timed(&ok, h))
            })
            .collect()
    }

    #[test]
    fn fewer_than_four_sessions_or_a_fixed_order_fail() {
        let three = ordered(&[true, false, true]);
        assert!(
            check_texts(&[("hvf", sessions(&three))], &[])
                .unwrap_err()
                .contains("need 4 sessions, have 3")
        );
        let same = ordered(&[true, true, true, true]);
        assert!(
            check_texts(&[("hvf", sessions(&same))], &[])
                .unwrap_err()
                .contains("must alternate")
        );
        let two_and_two = ordered(&[true, true, false, false]);
        assert!(
            check_texts(&[("hvf", sessions(&two_and_two))], &[])
                .unwrap_err()
                .contains("must alternate")
        );
    }

    /// The file `order` has to agree with the uptimes of the runs, and the
    /// sessions with each other.
    #[test]
    fn an_order_that_the_uptimes_contradict_fails() {
        let mut owned = ordered(&[true, false, true, false]);
        assert!(check_texts(&[("hvf", sessions(&owned))], &[]).is_ok());
        // Every file `order` says the opposite of what happened.
        for session in &mut owned {
            session.0 = !session.0;
        }
        let error = check_texts(&[("hvf", sessions(&owned))], &[]).unwrap_err();
        assert!(
            error.contains("session 1: the order says head first"),
            "{error}"
        );
        // Sessions out of their time order.
        let mut owned = ordered(&[true, false, true, false]);
        owned.swap(1, 3);
        owned[1].0 = false;
        owned[3].0 = false;
        let error = check_texts(&[("hvf", sessions(&owned))], &[]).unwrap_err();
        assert!(error.contains("not after session"), "{error}");
    }

    /// A file that names an OLD commit counts as NEW when declared, and the
    /// header says so; undeclared, the sessions differ.
    #[test]
    fn a_declared_same_guest_joins_the_commits_of_the_sessions() {
        let ok = head([0, 0, 0], 503, 100);
        let old = ok.replace("commit abc", "commit old");
        let owned = four(&[old.clone(), old, ok.clone(), ok]);
        let machines = [("hvf", sessions(&owned))];
        assert!(
            check_texts(&machines, &[])
                .unwrap_err()
                .contains("differ from session 1")
        );
        let report = check_texts(&machines, &[("old".to_owned(), "abc".to_owned())]).unwrap();
        assert!(report.contains("head abc, 600 s, 4 sessions"), "{report}");
        assert!(
            report.contains("same guest: old=abc (declared)"),
            "{report}"
        );
    }

    /// The p50 takes the values of the cells 463, 503, 543, 591, 639 (11 to
    /// 15 ticks): 591 is 14 ticks and within the limit in any session, 639
    /// is over; one session a tick above the base leaves the median in.
    #[test]
    fn the_p50_is_judged_in_ticks_of_the_counter() {
        assert_eq!(ticks(463, 24_000_000), 11);
        assert_eq!(ticks(503, 24_000_000), 12);
        assert_eq!(ticks(543, 24_000_000), 13);
        assert_eq!(ticks(591, 24_000_000), 14);
        assert_eq!(ticks(639, 24_000_000), 15);
        let heads = [
            head([0, 0, 0], 591, 100),
            head([0, 0, 0], 503, 100),
            head([0, 0, 0], 543, 100),
            head([0, 0, 0], 503, 100),
        ];
        check(&heads).unwrap();
        // A file without the frequency of the counter has no ticks.
        let broken = timed(&base(), 100).replace("counter 24000000 Hz", "counter ? Hz");
        assert!(parse_file(&broken).unwrap_err().contains("frequency"));
    }

    #[test]
    fn the_uptime_lines_of_the_host_parse() {
        let at = |line| uptime_minutes(line);
        assert_eq!(
            at(" 2:24  up 35 days,  9:58, 2 users, load averages: 2,85"),
            Some(35 * 1440 + 9 * 60 + 58)
        );
        assert_eq!(
            at(" 3:27  up 35 days, 11 hrs, 2 users"),
            Some(35 * 1440 + 11 * 60)
        );
        assert_eq!(at(" 3:27  up 12 mins, 1 user"), Some(12));
        assert_eq!(at(" 3:27  up 1 day, 3 mins, 1 user"), Some(1440 + 3));
        assert_eq!(at("x"), None);
    }

    #[test]
    fn each_rule_names_its_row() {
        let cases = [
            (
                "p50 of s5 in one session",
                [
                    head([0, 0, 0], 503, 100),
                    head([0, 0, 0], 639, 100),
                    head([0, 0, 0], 503, 100),
                    head([0, 0, 0], 503, 100),
                ],
                "s5_kill_sleeping: p50 15 ticks over 14 in session 2",
            ),
            (
                "median p50 of s5 against the base",
                [
                    head([0, 0, 0], 591, 100),
                    head([0, 0, 0], 591, 100),
                    head([0, 0, 0], 591, 100),
                    head([0, 0, 0], 503, 100),
                ],
                "s5_kill_busy_25: median p50 difference 2 ticks over 1",
            ),
            (
                "p99 of s5",
                [
                    head([0, 0, 3], 503, 100),
                    head([0, 0, 3], 503, 100),
                    head([0, 0, 3], 503, 100),
                    head([0, 0, 3], 503, 100),
                ],
                "s5_kill_busy_25: median p99 difference 3 ticks",
            ),
            (
                "p50 of s10",
                [
                    head([0, 0, 0], 503, 112),
                    head([0, 0, 0], 503, 112),
                    head([0, 0, 0], 503, 112),
                    head([0, 0, 0], 503, 100),
                ],
                "median p50 ratio 1.",
            ),
        ];
        for (what, heads, text) in cases {
            let error = check(&heads).unwrap_err();
            assert!(error.contains(text), "{what}: {error}");
        }
        // One session of four over on S10 leaves the median in the limits.
        let heads = [
            head([0, 0, 0], 503, 150),
            head([0, 0, 0], 503, 100),
            head([0, 0, 0], 503, 100),
            head([0, 0, 0], 503, 100),
        ];
        check(&heads).unwrap();
    }

    #[test]
    fn runs_of_different_length_or_without_a_row_do_not_compare() {
        let short = file(
            "abc",
            60,
            [(500, 1000), (500, 800), (420, 700)],
            [(1983, 7000), (1695, 7000)],
        );
        let ok = head([0, 0, 0], 503, 100);
        let heads = [short, ok.clone(), ok.clone(), ok.clone()];
        assert!(check(&heads).unwrap_err().contains("differ in length"));
        let missing = ok.replace("s10_kill_process_busy_25", "s10_other");
        let heads = [missing, ok.clone(), ok.clone(), ok.clone()];
        assert!(
            check(&heads)
                .unwrap_err()
                .contains("s10_kill_process_busy_25")
        );
        // Another commit in one session.
        let other = ok.replace("commit abc", "commit def");
        let heads = [other, ok.clone(), ok.clone(), ok];
        assert!(check(&heads).unwrap_err().contains("differ from session 1"));
    }

    /// The limits are the numbers of the acceptance.
    #[test]
    fn the_limits_are_those_of_the_acceptance() {
        assert_eq!(S5_P50_MAX_TICKS, 14);
        assert_eq!(S5_P50_DELTA_MAX_TICKS, 1);
        assert_eq!(P99_DELTA_MAX_TICKS, 2);
        assert_eq!(S10_P50_PERCENT, 110);
        assert_eq!(MIN_SESSIONS, 4);
    }

    #[test]
    fn medians_of_odd_and_even_counts() {
        assert_eq!(median_x2(&[3, 1, 2]), 4);
        assert_eq!(median_x2(&[4, 1, 2, 9]), 6);
        assert_eq!(show_x2(6), "3");
        assert_eq!(show_x2(7), "3.5");
        assert_eq!(show_x2(-3), "-2.5");
    }
}
