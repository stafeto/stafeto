// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Compare the same EL0 RTOS workloads on TCG, HVF and Apple VZ.

use std::path::Path;
use std::time::Duration;

use crate::{BOOT_PROFILE, RTBENCH_PROGRAMS, Variant, build, build_boot_image, hvf_host, qemu, vz};

const TIMEOUT: Duration = Duration::from_secs(90);
const NAMES: [&str; 6] = [
    "baseline",
    "cooperative",
    "preemptive",
    "messages",
    "synchronization",
    "allocation",
];

#[derive(Clone, Copy, Default)]
struct Wake {
    p99_us: u64,
    max_ns: u64,
    missed: u64,
}

#[derive(Clone, Copy, Default)]
struct ResultRow {
    rates: [u64; 6],
    wakes: [Wake; 2],
}

fn number(line: &str, key: &str) -> Result<u64, String> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(key))
        .ok_or_else(|| format!("missing {key} in {line:?}"))?
        .parse()
        .map_err(|e| format!("bad {key} in {line:?}: {e}"))
}

fn parse(lines: &[String]) -> Result<ResultRow, String> {
    if !lines.iter().any(|line| line.starts_with("RTBENCH START "))
        || !lines.iter().any(|line| line == "RTBENCH DONE")
    {
        return Err(format!("incomplete RTOS benchmark: {:?}", lines.last()));
    }
    let mut result = ResultRow::default();
    for (index, name) in NAMES.iter().enumerate() {
        let prefix = format!("RTBENCH {name} ");
        let line = lines
            .iter()
            .find(|line| line.starts_with(&prefix))
            .ok_or_else(|| format!("missing {prefix:?}"))?;
        let ops = number(line, "ops=")?;
        let ns = number(line, "ns=")?;
        if ns == 0 || ops == 0 {
            return Err(format!("empty workload {name}: {line}"));
        }
        if *name == "preemptive" && number(line, "handled=")? != ops {
            return Err(format!("notifications were lost: {line}"));
        }
        result.rates[index] = ((ops as u128 * 1_000_000_000) / ns as u128) as u64;
    }
    for (index, name) in ["timer_idle", "timer_load"].iter().enumerate() {
        let prefix = format!("RTBENCH {name} ");
        let line = lines
            .iter()
            .find(|line| line.starts_with(&prefix))
            .ok_or_else(|| format!("missing {prefix:?}"))?;
        if number(line, "n=")? != 1000 {
            return Err(format!("short timer run: {line}"));
        }
        result.wakes[index] = Wake {
            p99_us: number(line, "p99us=")?,
            max_ns: number(line, "maxns=")?,
            missed: number(line, "missed=")?,
        };
    }
    Ok(result)
}

fn measure(cmd: std::process::Command, machine: &str) -> Result<ResultRow, String> {
    println!("rtbench: {machine}");
    let outcome = qemu::run_until(cmd, TIMEOUT, Some("RTBENCH DONE"))?;
    if outcome.timed_out || !outcome.stopped_on_marker {
        return Err(format!(
            "{machine} did not finish: {:?}",
            outcome.lines.last()
        ));
    }
    parse(&outcome.lines)
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn report(machine: &str, rows: &[ResultRow]) {
    println!("{machine}: median operations/s over {} runs", rows.len());
    for (index, name) in NAMES.iter().enumerate() {
        let mut values: Vec<_> = rows.iter().map(|row| row.rates[index]).collect();
        println!("  {name:12} {}", median(&mut values));
    }
    for (index, name) in ["timer idle", "timer load"].iter().enumerate() {
        let mut p99: Vec<_> = rows.iter().map(|row| row.wakes[index].p99_us).collect();
        let maximum = rows
            .iter()
            .map(|row| row.wakes[index].max_ns)
            .max()
            .unwrap();
        let missed: u64 = rows.iter().map(|row| row.wakes[index].missed).sum();
        println!(
            "  {name:12} p99={} us, worst={} ns, missed={missed}",
            median(&mut p99),
            maximum
        );
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let repeats = match args {
        [] => 3,
        [flag, count] if flag == "--repeats" => count
            .parse::<usize>()
            .ok()
            .filter(|&count| (1..=20).contains(&count))
            .ok_or("rtbench --repeats expects 1..=20")?,
        _ => return Err("usage: cargo xtask rtbench [--repeats N]".into()),
    };
    let image = build_boot_image("rtbench.img", &RTBENCH_PROGRAMS, BOOT_PROFILE)?;
    let normal = build(Variant::Normal)?;
    let mut machines = vec![("QEMU TCG", &qemu::VIRT_V3)];
    let native = hvf_host().is_ok();
    if native {
        machines.push(("QEMU HVF", &qemu::HVF_V3));
    }
    for (name, machine) in machines {
        let mut rows = Vec::new();
        for _ in 0..repeats {
            let mut cmd = qemu::command(machine, &normal.image, Some(&image));
            cmd.args(qemu::HEADLESS);
            rows.push(measure(cmd, name)?);
        }
        report(name, &rows);
    }
    if native {
        let runner = vz::runner()?;
        let vz = build(Variant::Vz)?;
        let mut rows = Vec::new();
        for _ in 0..repeats {
            let mut cmd = std::process::Command::new(&runner);
            cmd.arg(Path::new(&vz.image)).arg(Path::new(&image));
            rows.push(measure(cmd, "Apple VZ")?);
        }
        report("Apple VZ", &rows);
    } else {
        println!("rtbench: HVF and Apple VZ require an Apple Silicon Mac");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_run_has_every_workload_and_timer_result() {
        let lines = [
            "RTBENCH START hz=24000000",
            "RTBENCH baseline ops=100 ns=1000000000",
            "RTBENCH cooperative ops=100 ns=1000000000 min=20 max=20",
            "RTBENCH preemptive ops=100 ns=1000000000 handled=100",
            "RTBENCH messages ops=100 ns=1000000000",
            "RTBENCH synchronization ops=100 ns=1000000000",
            "RTBENCH allocation ops=100 ns=1000000000",
            "RTBENCH timer_idle n=1000 p50us=1 p99us=10 maxns=20000 missed=0",
            "RTBENCH timer_load n=1000 p50us=2 p99us=20 maxns=30000 missed=1",
            "RTBENCH DONE",
        ]
        .map(str::to_owned);
        let result = parse(&lines).unwrap();
        assert_eq!(result.rates, [100; 6]);
        assert_eq!(result.wakes[1].missed, 1);
        assert_eq!(result.wakes[0].p99_us, 10);
    }

    #[test]
    fn incomplete_or_inconsistent_run_is_rejected() {
        let mut lines = [
            "RTBENCH START hz=24000000",
            "RTBENCH baseline ops=100 ns=1000000000",
            "RTBENCH cooperative ops=100 ns=1000000000",
            "RTBENCH preemptive ops=100 ns=1000000000 handled=99",
            "RTBENCH messages ops=100 ns=1000000000",
            "RTBENCH synchronization ops=100 ns=1000000000",
            "RTBENCH allocation ops=100 ns=1000000000",
            "RTBENCH timer_idle n=1000 p99us=10 maxns=20000 missed=0",
            "RTBENCH timer_load n=1000 p99us=20 maxns=30000 missed=0",
            "RTBENCH DONE",
        ]
        .map(str::to_owned);
        assert!(parse(&lines).is_err());
        lines[3] = "RTBENCH preemptive ops=100 ns=1000000000 handled=100".into();
        lines[9] = "KERNEL PANIC".into();
        assert!(parse(&lines).is_err());
    }
}
