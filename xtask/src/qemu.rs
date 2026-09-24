// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Running QEMU with a deadline and judging its console output.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Console on stdio, no window, no monitor: for runs whose output is parsed.
pub const HEADLESS: &[&str] = &["-display", "none", "-serial", "stdio", "-monitor", "none"];

pub fn args(kernel: &Path, boot_image: Option<&Path>) -> Vec<String> {
    let mut a: Vec<String> = ["-machine", "virt,gic-version=2", "-cpu", "cortex-a72", "-m", "512M", "-kernel"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    a.push(kernel.display().to_string());
    if let Some(b) = boot_image {
        a.push("-initrd".into());
        a.push(b.display().to_string());
    }
    a
}

pub fn command(kernel: &Path, boot_image: Option<&Path>) -> Command {
    let mut c = Command::new("qemu-system-aarch64");
    c.args(args(kernel, boot_image));
    c
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub lines: Vec<String>,
    pub status: Option<ExitStatus>,
    pub timed_out: bool,
    pub stopped_on_marker: bool,
}

/// Runs `cmd`, echoing and collecting its stdout lines. Kills it when a line
/// contains `stop_marker` or when `timeout` passes.
pub fn run_until(mut cmd: Command, timeout: Duration, stop_marker: Option<&str>) -> Result<Outcome, String> {
    let mut child = cmd.stdout(Stdio::piped()).spawn().map_err(|e| format!("{cmd:?}: {e}"))?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // Read raw bytes and decode lossily: a stray non-UTF-8 byte in the
        // child's output must not end the reader early (BufRead::lines()
        // would return an Err for such a line and stop there).
        let mut reader = BufReader::new(stdout);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    if buf.last() == Some(&b'\n') {
                        buf.pop();
                    }
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let deadline = Instant::now() + timeout;
    let mut lines = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => {
                println!("{line}");
                let line = line.trim_end_matches('\r').to_string();
                let hit = stop_marker.is_some_and(|m| line.contains(m));
                lines.push(line);
                if hit {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(Outcome { lines, status: None, timed_out: false, stopped_on_marker: true });
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // The reader thread exited (EOF or a read error), but the
                // child process may still be running: poll instead of a
                // blocking wait so the deadline still applies.
                loop {
                    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                        return Ok(Outcome { lines, status: Some(status), timed_out: false, stopped_on_marker: false });
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(Outcome { lines, status: None, timed_out: true, stopped_on_marker: false });
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Outcome { lines, status: None, timed_out: true, stopped_on_marker: false });
        }
    }
}

fn tail(lines: &[String]) -> &[String] {
    &lines[lines.len().saturating_sub(10)..]
}

/// The machine must print `line` and then power off by itself with status 0.
pub fn expect_clean_exit_with(o: &Outcome, line: &str) -> Result<(), String> {
    if o.timed_out {
        return Err(format!("QEMU did not finish in time; last lines: {:?}", tail(&o.lines)));
    }
    if !o.lines.iter().any(|l| l == line) {
        return Err(format!("kernel never printed {line:?}; last lines: {:?}", tail(&o.lines)));
    }
    match o.status {
        Some(s) if s.success() => Ok(()),
        other => Err(format!("QEMU exit status {other:?}")),
    }
}

/// Some line must contain `marker`.
pub fn expect_marker(o: &Outcome, marker: &str) -> Result<(), String> {
    if o.lines.iter().any(|l| l.contains(marker)) {
        Ok(())
    } else {
        Err(format!("kernel never printed {marker:?}; last lines: {:?}", tail(&o.lines)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn args_select_the_spec_machine_and_boot_image() {
        let a = args(Path::new("k.img"), Some(Path::new("b.img")));
        let joined = a.join(" ");
        assert!(joined.contains("-machine virt,gic-version=2"));
        assert!(joined.contains("-cpu cortex-a72"));
        assert!(joined.contains("-m 512M"));
        assert!(joined.contains("-kernel k.img"));
        assert!(joined.contains("-initrd b.img"));
        assert!(!args(Path::new("k.elf"), None).join(" ").contains("-initrd"));
    }

    #[test]
    fn collects_output_of_a_finished_process() {
        let o = run_until(sh("echo one; echo two"), Duration::from_secs(5), None).unwrap();
        assert!(!o.timed_out && !o.stopped_on_marker);
        assert_eq!(o.lines, ["one", "two"]);
        assert!(o.status.unwrap().success());
    }

    #[test]
    fn kills_a_process_that_outlives_the_deadline() {
        let start = Instant::now();
        let o = run_until(sh("echo started; sleep 10"), Duration::from_millis(300), None).unwrap();
        assert!(o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(expect_clean_exit_with(&o, "started").is_err());
    }

    #[test]
    fn stops_on_the_marker() {
        let start = Instant::now();
        let o = run_until(sh("echo booting; echo 'KERNEL PANIC: no device tree'; sleep 10"), Duration::from_secs(20), Some("no device tree")).unwrap();
        assert!(o.stopped_on_marker && !o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(expect_marker(&o, "no device tree").is_ok());
    }

    #[test]
    fn clean_exit_needs_the_line_and_status_zero() {
        let ok = Outcome { lines: vec!["boot complete".into()], status: Some(ExitStatus::from_raw(0)), timed_out: false, stopped_on_marker: false };
        assert!(expect_clean_exit_with(&ok, "boot complete").is_ok());
        let missing = Outcome { lines: vec!["booting".into()], ..ok.clone() };
        assert!(expect_clean_exit_with(&missing, "boot complete").is_err());
        let failed = Outcome { status: Some(ExitStatus::from_raw(1 << 8)), ..ok.clone() };
        assert!(expect_clean_exit_with(&failed, "boot complete").is_err());
    }

    #[test]
    fn survives_non_utf8_output() {
        let start = Instant::now();
        let o = run_until(sh("printf 'bad \\377 byte\\n'; echo after; sleep 10"), Duration::from_millis(300), None).unwrap();
        assert!(o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(o.lines.iter().any(|l| l.starts_with("bad ")));
        assert!(o.lines.iter().any(|l| l == "after"));
    }

    #[test]
    fn marker_must_appear() {
        let o = Outcome { lines: vec!["booting".into()], status: None, timed_out: true, stopped_on_marker: false };
        assert!(expect_marker(&o, "no device tree").is_err());
    }
}
