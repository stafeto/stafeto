// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask smp-measure [tcg|hvf|hvf2] [RUNS]`: the numbers of SMP
//! stage 6 on 2 and on 4 CPUs. The test init of the kernel built with
//! `smp-measure` runs its rows (tests/init/src/smp.rs, `stage_6_measures`):
//! a request to a thread on another CPU (S5x) with the target waiting in
//! WFI and with a lower thread on its CPU, a call to a service on this CPU
//! and on another, and under a storm of calls from the other CPUs the
//! request to a thread of this one (S5) and a local call. The kernel
//! counts, for each storm, the time of the entries into it, the longest
//! entry (B_N seen), the waits for OBJ and the longest hold of OBJ
//! (kernel/src/smpm.rs). The table goes to the output and to
//! `target/measure/smp-<mode>.txt`; `rule` says whether the decision's rule
//! asks for the finer locks.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::{
    BOOT_PROFILE, OBJ_HOLD_MAX, S5_ICOUNT_MAX, TEST_PROFILE, TEST_PROGRAMS, TEST_TIMEOUT, Variant,
    build, build_boot_image, hvf_host, qemu, run_until, target_dir,
};

/// The CPU counts of the table.
const CPUS: [usize; 2] = [2, 4];

/// One row of a run: what the test init printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub median: u64,
    pub p99: u64,
    pub longest: u64,
}

/// What the kernel counted in one storm.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counted {
    /// Kernel time, longest entry, OBJ taken, wait, longest wait: for each CPU.
    pub cpus: Vec<[u64; 5]>,
    pub longest_hold: u64,
}

/// The rows of a run, each storm row with what the kernel counted for it.
pub fn parse(lines: &[String]) -> (Vec<Row>, Vec<Counted>) {
    let mut rows = Vec::new();
    let mut storms = Vec::new();
    let mut pending = Counted::default();
    for line in lines {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("smp measure: ") {
            let Some((name, numbers)) = rest.split_once(": median ") else {
                continue;
            };
            let number = |after: &str| -> u64 {
                numbers
                    .split(after)
                    .nth(1)
                    .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0)
            };
            rows.push(Row {
                name: name.to_owned(),
                median: numbers
                    .split(' ')
                    .next()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0),
                p99: number("p99 "),
                longest: number("longest "),
            });
            if name.contains("under a storm") {
                storms.push(std::mem::take(&mut pending));
            }
        } else if let Some(rest) = line.strip_prefix("smp-measure cpu ") {
            // `2: entries 5, kernel 100 ticks, longest entry 9, OBJ taken 4 times,
            // wait 3 ticks, longest wait 2`
            let words: Vec<&str> = rest
                .split(|c: char| !c.is_ascii_digit())
                .filter(|w| !w.is_empty())
                .collect();
            let n: Vec<u64> = words.iter().filter_map(|w| w.parse().ok()).collect();
            if n.len() == 7 {
                let at = n[0] as usize;
                if pending.cpus.len() <= at {
                    pending.cpus.resize(at + 1, [0; 5]);
                }
                pending.cpus[at] = [n[2], n[3], n[4], n[5], n[6]];
            }
        } else if let Some(rest) = line.strip_prefix("smp-measure OBJ longest hold ") {
            pending.longest_hold = rest
                .split(' ')
                .next()
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
        }
    }
    (rows, storms)
}

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v.get(v.len() / 2).copied().unwrap_or(0)
}

/// The share of the kernel time that went into waits for OBJ, in percent
/// with one decimal (tenths), over all the CPUs of the storms.
pub fn wait_share_tenths(storms: &[&Counted]) -> u64 {
    let (mut wait, mut kernel) = (0u64, 0u64);
    for s in storms {
        for c in &s.cpus {
            kernel += c[0];
            wait += c[3];
        }
    }
    (wait * 1000).checked_div(kernel).unwrap_or(0)
}

/// The decision's rule for the finer locks: the wait for OBJ is above 10 %
/// of the kernel time, or its longest is above (N-1) times the longest hold
/// seen in the same runs. The decision counts the hold in instructions
/// (OBJ_HOLD_MAX); the counters of a run count ticks of the counter, in which
/// a hold is what it took on that host, a host's preemption of the holder
/// included, so that the bound is made of the holds of the runs themselves.
pub fn needs_finer_locks(share_tenths: u64, longest_wait: u64, hold: u64, cpus: usize) -> bool {
    share_tenths > 100 || longest_wait > (cpus as u64 - 1) * hold
}

fn one_run(mode: &str, cpus: usize) -> Result<(Vec<Row>, Vec<Counted>), String> {
    let a = build(Variant::SmpMeasure)?;
    let image = build_boot_image("boot-test.img", &TEST_PROGRAMS, TEST_PROFILE)?;
    let machine = match mode {
        "hvf" => &qemu::HVF_V3,
        "hvf2" => &qemu::HVF_V2,
        _ => &qemu::VIRT,
    };
    let mut cmd = qemu::command(machine, &a.image, Some(&image));
    cmd.args(["-smp", &cpus.to_string()]);
    cmd.args(qemu::HEADLESS);
    let o = run_until(cmd, TEST_TIMEOUT, None, &a.elf)?;
    let (rows, storms) = parse(&o.lines);
    if rows.len() != 6 || storms.len() != 2 {
        return Err(format!(
            "the test init printed {} rows and {} storms of 6 and 2 (the lines: {:?})",
            rows.len(),
            storms.len(),
            o.lines
                .iter()
                .filter(|l| l.starts_with("smp measure") || l.starts_with("smp-measure"))
                .collect::<Vec<_>>()
        ));
    }
    let _ = BOOT_PROFILE;
    Ok((rows, storms))
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mode = args.first().map_or("tcg", String::as_str);
    if !["tcg", "hvf", "hvf2"].contains(&mode) {
        return Err("usage: smp-measure [tcg|hvf|hvf2] [RUNS]".into());
    }
    let runs: usize = args
        .get(1)
        .map_or(Ok(3), |r| r.parse())
        .map_err(|_| "RUNS is a number")?;
    if mode.starts_with("hvf")
        && let Err(why) = hvf_host()
    {
        println!("smp-measure: HVF skipped: {why}");
        return Ok(());
    }
    let mut report = String::new();
    let _ = writeln!(
        report,
        "smp-measure {mode}, {runs} runs of each (ticks of the counter, 62.5 MHz: 16 ns)"
    );
    for cpus in CPUS {
        let mut by_row: BTreeMap<String, Vec<Row>> = BTreeMap::new();
        let mut storms = Vec::new();
        for _ in 0..runs {
            let (rows, s) = one_run(mode, cpus)?;
            for r in rows {
                by_row.entry(r.name.clone()).or_default().push(r);
            }
            storms.extend(s);
        }
        let _ = writeln!(report, "{cpus} CPUs:");
        for (name, rows) in &by_row {
            let _ = writeln!(
                report,
                "  {name}: median {}, p99 {}, longest {}",
                median(rows.iter().map(|r| r.median).collect()),
                median(rows.iter().map(|r| r.p99).collect()),
                rows.iter().map(|r| r.longest).max().unwrap_or(0)
            );
        }
        let refs: Vec<&Counted> = storms.iter().collect();
        let share = wait_share_tenths(&refs);
        let longest_entry = storms
            .iter()
            .flat_map(|s| s.cpus.iter().map(|c| c[1]))
            .max()
            .unwrap_or(0);
        let entry_cpu0 = storms
            .iter()
            .filter_map(|s| s.cpus.first().map(|c| c[1]))
            .max()
            .unwrap_or(0);
        let longest_wait = storms
            .iter()
            .flat_map(|s| s.cpus.iter().map(|c| c[4]))
            .max()
            .unwrap_or(0);
        let hold = storms.iter().map(|s| s.longest_hold).max().unwrap_or(0);
        let bound = (cpus as u64 - 1) * hold;
        let instructions = (cpus as u64 - 1) * OBJ_HOLD_MAX;
        let _ = writeln!(
            report,
            "  under the storms: longest entry {longest_entry} (CPU 0: {entry_cpu0}), longest OBJ hold {hold}, longest OBJ wait {longest_wait} (bound {bound} = (N-1) * the longest hold), wait share of the kernel time {}.{} %",
            share / 10,
            share % 10
        );
        let _ = writeln!(
            report,
            "  in instructions (icount): S5_N bound {} = S5_ICOUNT_MAX {S5_ICOUNT_MAX} + (N-1) * OBJ_HOLD_MAX {OBJ_HOLD_MAX}",
            S5_ICOUNT_MAX + instructions
        );
        let _ = writeln!(
            report,
            "  rule: {}",
            if needs_finer_locks(share, longest_wait, hold, cpus) {
                "the wait for OBJ asks for the finer locks"
            } else {
                "the wait for OBJ stays under the rule: one lock stays"
            }
        );
    }
    print!("{report}");
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(format!("smp-{mode}.txt")), &report).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| (*l).to_owned()).collect()
    }

    #[test]
    fn rows_and_storms_are_read_from_the_output() {
        let out = lines(&[
            "smp measure: S5x target waiting, its CPU idle: median 246 ticks, p99 368, longest 380 of 200 (counter 62500000 Hz)",
            "smp-measure counter 62500000 Hz",
            "smp-measure cpu 0: entries 10, kernel 1000 ticks, longest entry 300, OBJ taken 40 times, wait 100 ticks, longest wait 50",
            "smp-measure cpu 2: entries 5, kernel 3000 ticks, longest entry 900, OBJ taken 50 times, wait 400 ticks, longest wait 70",
            "smp-measure OBJ longest hold 60 ticks (kind 33)",
            "smp measure: S5 on this CPU under a storm of the others: median 21, p99 51, longest 271 of 200 (counter 62500000 Hz)",
        ]);
        let (rows, storms) = parse(&out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].median, 246);
        assert_eq!(rows[0].p99, 368);
        assert_eq!(rows[0].longest, 380);
        assert_eq!(storms.len(), 1);
        assert_eq!(storms[0].cpus[2], [3000, 900, 50, 400, 70]);
        assert_eq!(storms[0].longest_hold, 60);
        // 500 ticks of 4000 in the kernel waited: 12.5 %.
        assert_eq!(wait_share_tenths(&[&storms[0]]), 125);
    }

    #[test]
    fn the_rule_of_the_finer_locks() {
        // Over 10 % of the kernel time.
        assert!(needs_finer_locks(101, 10, 100, 4));
        assert!(!needs_finer_locks(100, 10, 100, 4));
        // The longest wait over (N-1) holds.
        assert!(needs_finer_locks(10, 301, 100, 4));
        assert!(!needs_finer_locks(10, 300, 100, 4));
        assert!(needs_finer_locks(10, 101, 100, 2));
    }
}
