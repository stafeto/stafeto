// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Durable measurements from successful QEMU runs (spec 15.3).

use crate::qemu::Machine;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock, PoisonError};

#[derive(Default)]
struct Report {
    accel: String,
    runs: usize,
    frequency: Option<String>,
    lines: Vec<String>,
}

static REPORTS: OnceLock<Mutex<BTreeMap<String, Report>>> = OnceLock::new();

fn reports() -> &'static Mutex<BTreeMap<String, Report>> {
    REPORTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn measured_line(line: &str) -> bool {
    [
        "counter ticks of 10000 turns:",
        "normal build ticks:",
        "log ticks:",
        "ipc round trip ticks:",
        "ipc round trip longest ticks:",
        "memory portions ticks:",
        "timer portions ticks:",
        "interrupt path ticks:",
        "device window ticks:",
        "KERNEL_STATS:",
        "call maximum ticks:",
        "fp switch ticks:",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

/// Keeps the lines of a run only after its existing verdict has passed.
pub fn record(machine: &Machine, lines: &[String]) {
    let mut all = reports().lock().unwrap_or_else(PoisonError::into_inner);
    let report = all.entry(machine.name.to_owned()).or_default();
    report.accel = machine.accel.to_owned();
    report.runs += 1;
    for line in lines {
        if let Some(hz) = line.strip_prefix("timer      ") {
            report.frequency = Some(hz.to_owned());
        }
        if measured_line(line) {
            report.lines.push(line.clone());
        }
    }
}

fn command_line(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    Ok(stdout.lines().next().unwrap_or_default().to_owned())
}

fn file_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .to_lowercase()
}

fn series(lines: &[String], row: &str) -> Option<(usize, u64, u64, u64)> {
    let mut values: Vec<u64> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("ipc round trip ticks: "))
        .filter_map(|rows| {
            rows.split_whitespace().find_map(|item| {
                item.strip_prefix(row)
                    .and_then(|s| s.strip_prefix('='))
                    .and_then(|s| s.parse().ok())
            })
        })
        .collect();
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some((
        values.len(),
        values[0],
        values[values.len() / 2],
        values[values.len() - 1],
    ))
}

fn content(
    name: &str,
    report: &Report,
    commit: &str,
    qemu: &str,
    kernel: u64,
    boot: u64,
) -> String {
    let mut text = format!(
        "machine: {name}\ncommit: {commit}\naccelerator: {}\nqemu: {qemu}\ncounter frequency: {}\nruns: {}\nkernel image bytes: {kernel}\nboot image bytes: {boot}\n",
        report.accel,
        report.frequency.as_deref().unwrap_or("not reported"),
        report.runs,
    );
    if report.accel.starts_with("hvf") {
        for row in ["fast", "slow"] {
            if let Some((count, min, median, max)) = series(&report.lines, row) {
                text.push_str(&format!(
                    "{row} ticks: samples={count} min={min} median={median} max={max}\n"
                ));
            }
        }
    }
    for line in &report.lines {
        text.push_str(line);
        text.push('\n');
    }
    text
}

/// Writes all complete machine reports by renaming files in their target
/// directory. A failed run never reaches this function.
pub fn write_all(target: &Path, kernel: u64, boot: u64) -> Result<(), String> {
    let commit = command_line("git", &["rev-parse", "HEAD"])?;
    let qemu = command_line("qemu-system-aarch64", &["--version"])?;
    let dir = target.join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let all = reports().lock().unwrap_or_else(PoisonError::into_inner);
    for (name, report) in all.iter() {
        let final_path = dir.join(format!("{}.txt", file_name(name)));
        let pending = dir.join(format!(".{}.pending", file_name(name)));
        std::fs::write(
            &pending,
            content(name, report, &commit, &qemu, kernel, boot),
        )
        .map_err(|e| format!("{}: {e}", pending.display()))?;
        std::fs::rename(&pending, &final_path)
            .map_err(|e| format!("{} -> {}: {e}", pending.display(), final_path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_keeps_only_measurement_rows_and_sanitizes_machine_name() {
        let report = Report {
            accel: "tcg".into(),
            runs: 2,
            frequency: Some("62500000 Hz".into()),
            lines: [
                "normal build ticks: null=271",
                "ipc round trip ticks: fast=1",
            ]
            .map(str::to_owned)
            .to_vec(),
        };
        assert_eq!(file_name("EL2 GICv3"), "el2-gicv3");
        let text = content("EL2 GICv3", &report, "abc", "QEMU 11", 10, 20);
        assert!(text.contains("commit: abc\naccelerator: tcg\nqemu: QEMU 11\n"));
        assert!(text.contains("counter frequency: 62500000 Hz\nruns: 2\n"));
        assert!(text.contains("kernel image bytes: 10\nboot image bytes: 20\n"));
        assert!(text.ends_with("normal build ticks: null=271\nipc round trip ticks: fast=1\n"));
        assert!(measured_line("memory portions ticks: create=1"));
        assert!(!measured_line("TEST sample ok"));
        let lines = [
            "ipc round trip ticks: null=1 fast=30 slow=60",
            "ipc round trip ticks: null=1 fast=10 slow=40",
            "ipc round trip ticks: null=1 fast=20 slow=50",
        ]
        .map(str::to_owned);
        assert_eq!(series(&lines, "fast"), Some((3, 10, 20, 30)));
        assert_eq!(series(&lines, "slow"), Some((3, 40, 50, 60)));
    }
}
