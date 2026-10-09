// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask rtbench-check <base> <head>`: the acceptance of epoch 2 for
//! the path of `pthread_kill` and of a signal of the process, read from the
//! files of two `rtbench --minutes N --serial` runs made one after the
//! other in one session. Each argument is a directory with
//! `rtbench-hvf.txt` and `rtbench-vz.txt` (rtbench2.rs, `file`). The rules,
//! on each machine:
//!
//! - the three rows `s5_*`: p50 at most `S5_P50_MAX_NS`; p99 at most the
//!   p99 of the base plus `P99_SLACK_NS` (two ticks of the counter);
//! - the two rows `s10_*`: p50 at most the p50 of the base plus
//!   `S10_P50_PERCENT` over 100.
//!
//! Rows of S15 and S28 are printed without a limit. The table of the
//! comparison goes to the output; the error names every row that is over.

use std::collections::BTreeMap;
use std::path::Path;

/// The most the p50 of the path of `pthread_kill` may have, in nanoseconds: the
/// p50 of the base commit with room, from the acceptance of epoch 2.
pub const S5_P50_MAX_NS: u64 = 543;
/// Two ticks of the counter (83 ns at 24 MHz) over the base's p99.
pub const P99_SLACK_NS: u64 = 83;
/// The p50 of a signal of the process may be this many percent of the
/// base's.
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

/// The comparison of one machine: its table, and the rows that are over.
fn compare(
    machine: &str,
    base: &Measured,
    head: &Measured,
) -> Result<(String, Vec<String>), String> {
    if base.seconds != head.seconds {
        return Err(format!(
            "{machine}: the runs differ in length ({} s and {} s)",
            base.seconds, head.seconds
        ));
    }
    let mut table = format!(
        "{machine}: base {} and head {}, {} s\n{:<28} {:>9} {:>9} {:>9} {:>9}  limit\n",
        base.commit,
        head.commit,
        base.seconds,
        "row",
        "base p50",
        "base p99",
        "head p50",
        "head p99"
    );
    let mut over = Vec::new();
    for name in S5_ROWS.into_iter().chain(S10_ROWS).chain(RECORDED_ROWS) {
        let (b, h) = (row(base, name, "base")?, row(head, name, "head")?);
        let limit = if S5_ROWS.contains(&name) {
            let p99_max = b.p99 + P99_SLACK_NS;
            let mut broken = Vec::new();
            if h.p50 > S5_P50_MAX_NS {
                broken.push(format!("p50 {} over {S5_P50_MAX_NS}", h.p50));
            }
            if h.p99 > p99_max {
                broken.push(format!("p99 {} over {p99_max}", h.p99));
            }
            if !broken.is_empty() {
                over.push(format!("{machine} {name}: {}", broken.join(", ")));
            }
            format!("p50 <= {S5_P50_MAX_NS}, p99 <= {p99_max}")
        } else if S10_ROWS.contains(&name) {
            // Integer arithmetic: h.p50 <= b.p50 * 110 / 100.
            if h.p50 * 100 > b.p50 * S10_P50_PERCENT {
                over.push(format!(
                    "{machine} {name}: p50 {} over {} percent of {}",
                    h.p50, S10_P50_PERCENT, b.p50
                ));
            }
            format!("p50 <= {}", b.p50 * S10_P50_PERCENT / 100)
        } else {
            "none".to_owned()
        };
        table += &format!(
            "{name:<28} {:>9} {:>9} {:>9} {:>9}  {limit}\n",
            b.p50, b.p99, h.p50, h.p99
        );
    }
    Ok((table, over))
}

/// The tables and the verdict for the texts of the files, one pair for each
/// machine.
fn check_texts(pairs: &[(&str, &str, &str)]) -> Result<String, String> {
    let mut report = String::new();
    let mut over = Vec::new();
    for (machine, base, head) in pairs {
        let (base, head) = (
            parse_file(base).map_err(|e| format!("{machine} base: {e}"))?,
            parse_file(head).map_err(|e| format!("{machine} head: {e}"))?,
        );
        let (table, rows) = compare(machine, &base, &head)?;
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
    let [base, head] = args else {
        return Err("usage: rtbench-check <base directory> <head directory>".to_owned());
    };
    let read = |dir: &str, machine: &str| {
        let path = Path::new(dir).join(format!("rtbench-{machine}.txt"));
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let mut texts = Vec::new();
    for machine in MACHINES {
        texts.push((machine, read(base, machine)?, read(head, machine)?));
    }
    let pairs: Vec<_> = texts
        .iter()
        .map(|(machine, base, head)| (*machine, base.as_str(), head.as_str()))
        .collect();
    print!("{}", check_texts(&pairs)?);
    println!("rtbench-check: within the limits on hvf and vz");
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

    #[test]
    fn a_head_within_the_limits_passes() {
        let head = file(
            "abc",
            600,
            [(543, 1083), (520, 883), (500, 783)],
            [(2181, 9000), (1864, 8000)],
        );
        let report = check_texts(&[("hvf", &base(), &head), ("vz", &base(), &head)]).unwrap();
        assert!(report.contains("s5_kill_busy_25"), "{report}");
        assert!(report.contains("s15_fork_heap_8m"), "{report}");
    }

    #[test]
    fn each_rule_names_its_row() {
        let ok5 = [(500, 1000), (500, 800), (420, 700)];
        let ok10 = [(1983, 7000), (1695, 7000)];
        type S5 = [(u64, u64); 3];
        type S10 = [(u64, u64); 2];
        let cases: [(&str, S5, S10, &str); 4] = [
            (
                "p50 of s5",
                [(544, 1000), (500, 800), (420, 700)],
                ok10,
                "s5_kill_sleeping",
            ),
            (
                "p99 of s5",
                [(500, 1000), (500, 800), (420, 784)],
                ok10,
                "s5_kill_busy_25",
            ),
            (
                "p50 of s10",
                ok5,
                [(1983, 7000), (1865, 7000)],
                "s10_kill_process_busy_25",
            ),
            (
                "p50 of s10 sleeping",
                ok5,
                [(2182, 7000), (1695, 7000)],
                "s10_kill_process_sleeping",
            ),
        ];
        for (what, s5, s10, name) in cases {
            let head = file("abc", 600, s5, s10);
            let error = check_texts(&[("hvf", &base(), &head)]).unwrap_err();
            assert!(error.contains(name), "{what}: {error}");
        }
    }

    #[test]
    fn runs_of_different_length_or_without_a_row_do_not_compare() {
        let ok5 = [(500, 1000), (500, 800), (420, 700)];
        let ok10 = [(1983, 7000), (1695, 7000)];
        let short = file("abc", 60, ok5, ok10);
        assert!(
            check_texts(&[("hvf", &base(), &short)])
                .unwrap_err()
                .contains("differ in length")
        );
        let missing = base().replace("s10_kill_process_busy_25", "s10_other");
        assert!(
            check_texts(&[("hvf", &base(), &missing)])
                .unwrap_err()
                .contains("s10_kill_process_busy_25")
        );
    }

    /// The limit on the p50 of S5 is the number of the acceptance.
    #[test]
    fn the_limit_of_s5_is_543_ns() {
        assert_eq!(S5_P50_MAX_NS, 543);
        assert_eq!(P99_SLACK_NS, 83);
        assert_eq!(S10_P50_PERCENT, 110);
    }
}
