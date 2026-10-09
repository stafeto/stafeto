// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask rtbench-check <session>...`: the acceptance of epoch 2 for
//! the path of `pthread_kill` and of a signal of the process, read from the
//! files of several sessions of `rtbench --minutes N --serial`. A session
//! is a directory with the file `order` (`base-first` or `head-first`: which
//! of its two runs came first) and the directories `base` and `head`, each
//! with `rtbench-hvf.txt` and `rtbench-vz.txt` (rtbench2.rs, `file`). The
//! sessions are listed in the order they were made and alternate in their
//! `order`, so that a drift of the host over the hours does not favour one
//! commit. The rules, on each machine:
//!
//! - at least `MIN_SESSIONS` sessions, alternating in order;
//! - the three rows `s5_*`: p50 of the head at most `S5_P50_MAX_NS` in every
//!   session; the median over the sessions of the difference of the p99s
//!   (head minus base of the same session) at most `P99_SLACK_NS`, two ticks
//!   of the counter;
//! - the two rows `s10_*`: the median over the sessions of the ratio of the
//!   p50 of the head to the p50 of the base at most `S10_P50_PERCENT` over
//!   100.
//!
//! The median of the paired differences takes out the drift of the host
//! between sessions and the lone tails of a cell: the p99 of 11 900 samples
//! is its 119th from the top, and the same commit moves it by up to 96 ns
//! from one session to the next, more than the slack. Rows of S15 and S28
//! are printed without a limit. The table goes to the output; the error
//! names every row that is over.

use std::collections::BTreeMap;
use std::path::Path;

/// The sessions a machine needs before its comparison counts.
pub const MIN_SESSIONS: usize = 4;
/// The most the p50 of the path of `pthread_kill` may have, in nanoseconds: the
/// p50 of the base commit with room, from the acceptance of epoch 2.
pub const S5_P50_MAX_NS: u64 = 543;
/// Two ticks of the counter (83 ns at 24 MHz): the most the median of the
/// differences of the p99 may be.
pub const P99_SLACK_NS: u64 = 83;
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

#[derive(Debug)]
struct Measured {
    commit: String,
    seconds: u64,
    rows: BTreeMap<String, Figures>,
}

/// The file of a run as `rtbench2::file` writes it.
fn parse_file(text: &str) -> Result<Measured, String> {
    let mut commit = None;
    let mut seconds = None;
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("commit ") {
            commit = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("seconds ") {
            seconds = rest
                .split(',')
                .next()
                .and_then(|s| s.trim().parse::<u64>().ok());
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
fn compare(machine: &str, sessions: &[Session]) -> Result<(String, Vec<String>), String> {
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
        pairs.push((base, head));
    }
    let (base0, head0) = &pairs[0];
    for (i, (base, head)) in pairs.iter().enumerate() {
        if base.commit != base0.commit
            || head.commit != head0.commit
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
        base0.commit,
        head0.commit,
        base0.seconds,
        pairs.len()
    );
    let mut over = Vec::new();
    for name in S5_ROWS {
        let mut head_p50 = Vec::new();
        let mut deltas = Vec::new();
        for (base, head) in &pairs {
            let (b, h) = (row(base, name, "base")?, row(head, name, "head")?);
            head_p50.push(h.p50 as i64);
            deltas.push(h.p99 as i64 - b.p99 as i64);
        }
        let median = median_x2(&deltas);
        let mut broken = Vec::new();
        for (i, p50) in head_p50.iter().enumerate() {
            if *p50 > S5_P50_MAX_NS as i64 {
                broken.push(format!(
                    "p50 {p50} over {S5_P50_MAX_NS} in session {}",
                    i + 1
                ));
            }
        }
        if median > 2 * P99_SLACK_NS as i64 {
            broken.push(format!(
                "median p99 difference {} over {P99_SLACK_NS}",
                show_x2(median)
            ));
        }
        if !broken.is_empty() {
            over.push(format!("{machine} {name}: {}", broken.join(", ")));
        }
        table += &format!(
            "{name:<28} head p50 {}  p99 head minus base [{}] median {}  limit: p50 <= {S5_P50_MAX_NS}, median <= {P99_SLACK_NS}\n",
            list(&head_p50).replace('+', ""),
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
fn check_texts(machines: &[(&str, Vec<Session>)]) -> Result<String, String> {
    let mut report = String::new();
    let mut over = Vec::new();
    for (machine, sessions) in machines {
        let (table, rows) = compare(machine, sessions)?;
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
    if args.is_empty() {
        return Err("usage: rtbench-check <session directory>...".to_owned());
    }
    let read = |path: std::path::PathBuf| {
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    // texts[session] = (base_first, [(machine, base, head)])
    let mut texts = Vec::new();
    for dir in args {
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
    print!("{}", check_texts(&machines)?);
    println!(
        "rtbench-check: within the limits on hvf and vz over {} sessions",
        args.len()
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
            [(503, 1000), (503, 800), (423, 700)],
            [(1983, 7000), (1695, 7000)],
        )
    }

    /// A head with the figures of the base plus `delta` on every p99 of S5
    /// and `p50` on every p50 of S5, S10 as the base times `ratio` percent.
    fn head(delta: [u64; 3], p50: u64, ratio: u64) -> String {
        file(
            "abc",
            600,
            [
                (p50, 1000 + delta[0]),
                (p50, 800 + delta[1]),
                (p50, 700 + delta[2]),
            ],
            [(1983 * ratio / 100, 7000), (1695 * ratio / 100, 7000)],
        )
    }

    /// Four sessions alternating in order, one head each.
    fn four(heads: &[String; 4]) -> Vec<Session<'_>> {
        static BASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let base = BASE.get_or_init(base).as_str();
        heads
            .iter()
            .enumerate()
            .map(|(i, head)| Session {
                base_first: i % 2 == 0,
                base,
                head,
            })
            .collect()
    }

    fn check(heads: &[String; 4]) -> Result<String, String> {
        check_texts(&[("hvf", four(heads)), ("vz", four(heads))])
    }

    #[test]
    fn a_head_within_the_limits_passes() {
        let ok = head([83, 83, 83], 543, 110);
        let report = check(&[ok.clone(), ok.clone(), ok.clone(), ok]).unwrap();
        assert!(report.contains("s5_kill_busy_25"), "{report}");
        assert!(report.contains("s15_fork_heap_8m"), "{report}");
    }

    /// One noisy cell and the median passes: the differences 176, 32, 48, 48
    /// of the review (HVF `reading`) have the median 48.
    #[test]
    fn a_noisy_cell_with_a_passing_median_passes() {
        let heads = [
            head([0, 176, 0], 503, 100),
            head([0, 32, 0], 503, 100),
            head([0, 48, 0], 503, 100),
            head([0, 48, 0], 503, 100),
        ];
        let report = check(&heads).unwrap();
        assert!(report.contains("[+176 +32 +48 +48] median 48"), "{report}");
    }

    /// A shift in three of four sessions fails whatever the fourth does.
    #[test]
    fn a_median_over_the_slack_fails() {
        let heads = [
            head([0, 90, 0], 503, 100),
            head([0, 90, 0], 503, 100),
            head([0, 90, 0], 503, 100),
            head([0, 0, 0], 503, 100),
        ];
        let error = check(&heads).unwrap_err();
        assert!(
            error.contains("s5_kill_reading: median p99 difference 90 over 83"),
            "{error}"
        );
        // The middle of an even count: 84 and 83 give 83.5.
        let heads = [
            head([0, 84, 0], 503, 100),
            head([0, 83, 0], 503, 100),
            head([0, 200, 0], 503, 100),
            head([0, 0, 0], 503, 100),
        ];
        assert!(check(&heads).unwrap_err().contains("83.5 over 83"));
    }

    #[test]
    fn fewer_than_four_sessions_or_a_fixed_order_fail() {
        let ok = head([0, 0, 0], 503, 100);
        let base = base();
        let session = |base_first| Session {
            base_first,
            base: &base,
            head: &ok,
        };
        let three = vec![session(true), session(false), session(true)];
        assert!(
            check_texts(&[("hvf", three)])
                .unwrap_err()
                .contains("need 4 sessions, have 3")
        );
        let same = vec![session(true), session(true), session(true), session(true)];
        assert!(
            check_texts(&[("hvf", same)])
                .unwrap_err()
                .contains("must alternate")
        );
        let two_and_two = vec![session(true), session(true), session(false), session(false)];
        assert!(
            check_texts(&[("hvf", two_and_two)])
                .unwrap_err()
                .contains("must alternate")
        );
    }

    #[test]
    fn each_rule_names_its_row() {
        let cases = [
            (
                "p50 of s5 in one session",
                [
                    head([0, 0, 0], 503, 100),
                    head([0, 0, 0], 544, 100),
                    head([0, 0, 0], 503, 100),
                    head([0, 0, 0], 503, 100),
                ],
                "s5_kill_sleeping: p50 544 over 543 in session 2",
            ),
            (
                "p99 of s5",
                [
                    head([0, 0, 90], 503, 100),
                    head([0, 0, 90], 503, 100),
                    head([0, 0, 90], 503, 100),
                    head([0, 0, 90], 503, 100),
                ],
                "s5_kill_busy_25: median p99 difference 90",
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
        assert_eq!(S5_P50_MAX_NS, 543);
        assert_eq!(P99_SLACK_NS, 83);
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
