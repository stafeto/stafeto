// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Running QEMU with a deadline and judging its console output.

use std::io::{BufRead, BufReader};
use std::ops::Range;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Console on stdio, no window, no monitor: for runs whose output is parsed.
pub const HEADLESS: &[&str] = &["-display", "none", "-serial", "stdio", "-monitor", "none"];

/// Virtual time counts instructions, one per 2^4 ns, which at the 62.5 MHz
/// of the counter is one per tick; with `sleep=off` it jumps to the next
/// timer deadline while the CPU sleeps in `wfi`. Every run of a kernel
/// then sees the same times, whatever the host does. An idle kernel with
/// no deadline stops time and hangs.
pub const ICOUNT: &[&str] = &["-icount", "shift=4,sleep=off"];

/// A QEMU machine type with its options, and a CPU model.
pub struct Machine {
    pub machine: &'static str,
    pub cpu: &'static str,
    pub memory: &'static str,
}

/// The machine of the spec: the kernel is entered at EL1, PSCI goes through HVC.
pub const VIRT: Machine = Machine {
    machine: "virt,gic-version=2",
    cpu: "cortex-a72",
    memory: "512M",
};

/// The kernel is entered at EL2, as on the PinePhone's Cortex-A53; PSCI then
/// goes through SMC.
pub const VIRT_EL2: Machine = Machine {
    machine: "virt,gic-version=2,virtualization=on",
    cpu: "cortex-a53",
    memory: "512M",
};

/// The spec machine with 2 GiB and the PinePhone's Cortex-A53: RAM spans
/// two GiBs, and the second one is not in the boot page tables. The A53
/// reports a VIPT instruction cache, so the kernel tests take that path of
/// the cache maintenance too; the kernel is entered at EL1 and PSCI goes
/// through HVC, as on VIRT.
pub const VIRT_2G: Machine = Machine {
    machine: "virt,gic-version=2",
    cpu: "cortex-a53",
    memory: "2G",
};

pub fn args(m: &Machine, kernel: &Path, boot_image: Option<&Path>) -> Vec<String> {
    let mut a: Vec<String> = [
        "-machine", m.machine, "-cpu", m.cpu, "-m", m.memory, "-kernel",
    ]
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

pub fn command(m: &Machine, kernel: &Path, boot_image: Option<&Path>) -> Command {
    let mut c = Command::new("qemu-system-aarch64");
    c.args(args(m, kernel, boot_image));
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
/// contains `stop_marker` or when `timeout` passes. The child gets /dev/null
/// as stdin: with `-serial stdio` QEMU puts a terminal on stdin into raw mode
/// and a killed QEMU cannot restore it.
pub fn run_until(
    mut cmd: Command,
    timeout: Duration,
    stop_marker: Option<&str>,
) -> Result<Outcome, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd:?}: {e}"))?;
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
                    return Ok(Outcome {
                        lines,
                        status: None,
                        timed_out: false,
                        stopped_on_marker: true,
                    });
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // The reader thread exited (EOF or a read error), but the
                // child process may still be running: poll instead of a
                // blocking wait so the deadline still applies.
                loop {
                    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                        return Ok(Outcome {
                            lines,
                            status: Some(status),
                            timed_out: false,
                            stopped_on_marker: false,
                        });
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(Outcome {
                            lines,
                            status: None,
                            timed_out: true,
                            stopped_on_marker: false,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Outcome {
                lines,
                status: None,
                timed_out: true,
                stopped_on_marker: false,
            });
        }
    }
}

fn tail(lines: &[String]) -> &[String] {
    &lines[lines.len().saturating_sub(10)..]
}

/// The machine must print `line` and then power off by itself with status 0.
pub fn expect_clean_exit_with(o: &Outcome, line: &str) -> Result<(), String> {
    if o.timed_out {
        return Err(format!(
            "QEMU did not finish in time; last lines: {:?}",
            tail(&o.lines)
        ));
    }
    if !o.lines.iter().any(|l| l == line) {
        return Err(format!(
            "kernel never printed {line:?}; last lines: {:?}",
            tail(&o.lines)
        ));
    }
    match o.status {
        Some(s) if s.success() => Ok(()),
        other => Err(format!("QEMU exit status {other:?}")),
    }
}

/// Some line must be `line`, whole.
pub fn expect_line(o: &Outcome, line: &str) -> Result<(), String> {
    if o.lines.iter().any(|l| l == line) {
        Ok(())
    } else {
        Err(format!(
            "no line is {line:?}; last lines: {:?}",
            tail(&o.lines)
        ))
    }
}

/// Some line must contain `marker`.
pub fn expect_marker(o: &Outcome, marker: &str) -> Result<(), String> {
    if o.lines.iter().any(|l| l.contains(marker)) {
        Ok(())
    } else {
        Err(format!(
            "kernel never printed {marker:?}; last lines: {:?}",
            tail(&o.lines)
        ))
    }
}

/// The first number after `prefix` on the first line that contains it,
/// anywhere in the line.
pub fn number_after(lines: &[String], prefix: &str) -> Option<u64> {
    let rest = lines
        .iter()
        .find_map(|l| l.find(prefix).map(|i| &l[i + prefix.len()..]))?;
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// The hex value starting at `line[at + 2..]` (right after a `0x`).
fn hex_at(line: &str, at: usize) -> Option<u64> {
    let digits: String = line[at + 2..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    u64::from_str_radix(&digits, 16).ok()
}

/// The address after `ELR=0x` on the kernel's panic line, if any.
fn elr_in_panic(lines: &[String]) -> Option<u64> {
    let line = lines.iter().find(|l| l.contains("ELR=0x"))?;
    hex_at(line, line.find("ELR=0x")? + "ELR=".len())
}

/// Addresses on backtrace frame lines (`kcore::backtrace`'s `  #N  0x...`).
fn backtrace_addresses(lines: &[String]) -> Vec<u64> {
    lines
        .iter()
        .filter(|l| l.trim_start().starts_with('#'))
        .filter_map(|l| l.find("0x").and_then(|at| hex_at(l, at)))
        .collect()
}

/// The backtrace must name the interrupted instruction (its `ELR`) and at
/// least one caller above it: proof that exception entry recorded a frame
/// linking the fault into the backtrace, not just the panic handler's own
/// frames (which a backtrace prints regardless of that record).
pub fn backtrace_names_the_fault(lines: &[String]) -> Result<(), String> {
    let elr = elr_in_panic(lines).ok_or("no panic line with ELR=0x...")?;
    let frames = backtrace_addresses(lines);
    let at = frames
        .iter()
        .position(|&a| a == elr)
        .ok_or_else(|| format!("ELR {elr:#x} is not in the backtrace: {frames:#x?}"))?;
    if at + 1 >= frames.len() {
        return Err(format!("ELR {elr:#x} is the last frame in the backtrace"));
    }
    Ok(())
}

/// The address range of the function `name` in `llvm-nm -C --print-size`
/// output (lines of address, size, type and name).
pub fn symbol_range(nm: &str, name: &str) -> Option<Range<u64>> {
    nm.lines().find_map(|l| {
        let mut f = l.splitn(4, ' ');
        let (addr, size, _kind, sym) = (f.next()?, f.next()?, f.next()?, f.next()?);
        if sym != name {
            return None;
        }
        let addr = u64::from_str_radix(addr, 16).ok()?;
        Some(addr..addr + u64::from_str_radix(size, 16).ok()?)
    })
}

/// The report of a stack overflow in the recursive function `f`: the
/// panic line's ELR lies in `f`, and the backtrace shows the ELR and, above
/// it, more frames of `f`. Those frames come from the kernel stack, while the
/// report runs on the emergency stack: proof that the walk crossed over.
pub fn overflow_report_names(lines: &[String], f: Range<u64>) -> Result<(), String> {
    let elr = elr_in_panic(lines).ok_or("no panic line with ELR=0x...")?;
    if !f.contains(&elr) {
        return Err(format!("ELR {elr:#x} is outside the recursion {f:#x?}"));
    }
    let frames = backtrace_addresses(lines);
    let at = frames
        .iter()
        .position(|&a| a == elr)
        .ok_or_else(|| format!("ELR {elr:#x} is not in the backtrace: {frames:#x?}"))?;
    if !frames[at + 1..].iter().any(|a| f.contains(a)) {
        return Err(format!(
            "the backtrace has no frames of the recursion above the ELR: {frames:#x?}"
        ));
    }
    Ok(())
}

/// QEMU must have finished before the deadline.
pub fn expect_not_timed_out(o: &Outcome) -> Result<(), String> {
    if o.timed_out {
        Err(format!(
            "QEMU did not finish in time; last lines: {:?}",
            tail(&o.lines)
        ))
    } else {
        Ok(())
    }
}

/// The machine must power itself off before the deadline, with status 0.
pub fn expect_powered_off(o: &Outcome) -> Result<(), String> {
    expect_not_timed_out(o)?;
    match o.status {
        Some(s) if s.success() => Ok(()),
        other => Err(format!("QEMU exit status {other:?}")),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TestReport {
    pub passed: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// Failures the run counted itself (`failed=<n>`).
    pub done: Option<u32>,
    /// Tests the run says it has (`total=<n>`), when it says so.
    pub total: Option<u32>,
}

/// Reads `TEST <name> ok`, `TEST <name> FAIL <why>` and
/// `TESTS DONE [total=<n>] failed=<n>` lines.
pub fn parse_report(lines: &[String]) -> TestReport {
    let mut r = TestReport {
        passed: Vec::new(),
        failed: Vec::new(),
        done: None,
        total: None,
    };
    for line in lines {
        if let Some(rest) = line.strip_prefix("TEST ") {
            let mut parts = rest.splitn(3, ' ');
            let name = parts.next().unwrap_or_default().to_string();
            match parts.next() {
                Some("ok") => r.passed.push(name),
                Some("FAIL") => r
                    .failed
                    .push((name, parts.next().unwrap_or_default().to_string())),
                _ => {}
            }
        } else if let Some(rest) = line.strip_prefix("TESTS DONE ") {
            for field in rest.split_whitespace() {
                if let Some(n) = field.strip_prefix("total=") {
                    r.total = n.parse().ok();
                } else if let Some(n) = field.strip_prefix("failed=") {
                    r.done = n.parse().ok();
                }
            }
        }
    }
    r
}

/// A run of tests in QEMU finished in time with status 0, some tests
/// passed, none failed, and the run said so.
pub fn verdict(o: &Outcome, r: &TestReport) -> Result<(), String> {
    if o.timed_out {
        return Err(format!(
            "QEMU did not finish in time; last lines: {:?}",
            tail(&o.lines)
        ));
    }
    if !r.failed.is_empty() {
        return Err(format!("{} test(s) failed: {:?}", r.failed.len(), r.failed));
    }
    match r.done {
        Some(0) => {}
        Some(n) => return Err(format!("the run reported {n} failed test(s)")),
        None => {
            return Err(format!(
                "no TESTS DONE line; last lines: {:?}",
                tail(&o.lines)
            ));
        }
    }
    if r.passed.is_empty() {
        return Err("no tests ran".into());
    }
    match o.status {
        Some(s) if s.success() => Ok(()),
        other => Err(format!("QEMU exit status {other:?}")),
    }
}

/// As `verdict`, for a run that counts its tests: it prints
/// `TESTS DONE total=<n> ...`, and each of the n passed once. A test line
/// that went missing in the output fails the run.
pub fn counted_verdict(o: &Outcome, r: &TestReport) -> Result<(), String> {
    verdict(o, r)?;
    let total = r.total.ok_or("the run never said how many tests it has")?;
    let mut names = r.passed.clone();
    names.sort();
    names.dedup();
    if names.len() != r.passed.len() {
        return Err(format!("a test passed twice: {:?}", r.passed));
    }
    if r.passed.len() != total as usize {
        return Err(format!(
            "{} of {total} tests reported: {:?}",
            r.passed.len(),
            r.passed
        ));
    }
    Ok(())
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
        let a = args(&VIRT, Path::new("k.img"), Some(Path::new("b.img")));
        let joined = a.join(" ");
        assert!(joined.contains("-machine virt,gic-version=2"));
        assert!(!joined.contains("virtualization"));
        assert!(joined.contains("-cpu cortex-a72"));
        assert!(joined.contains("-m 512M"));
        assert!(joined.contains("-kernel k.img"));
        assert!(joined.contains("-initrd b.img"));
        assert!(
            !args(&VIRT, Path::new("k.elf"), None)
                .join(" ")
                .contains("-initrd")
        );
    }

    #[test]
    fn two_gib_machine_asks_for_2g() {
        let joined = args(&VIRT_2G, Path::new("k.img"), None).join(" ");
        assert!(joined.contains("-m 2G"));
        assert!(joined.contains("-cpu cortex-a53"));
        assert!(!joined.contains("virtualization"));
    }

    #[test]
    fn number_after_reads_the_first_number() {
        let l = lines(&["boot", "frames     1987 MiB free"]);
        assert_eq!(number_after(&l, "frames "), Some(1987));
    }

    #[test]
    fn number_after_finds_the_prefix_inside_a_line() {
        let l = lines(&["[0.1] frames     12 MiB free"]);
        assert_eq!(number_after(&l, "frames "), Some(12));
    }

    #[test]
    fn number_after_needs_the_prefix_and_a_number() {
        assert_eq!(number_after(&lines(&["boot"]), "frames "), None);
        assert_eq!(number_after(&lines(&["frames none"]), "frames "), None);
    }

    #[test]
    fn backtrace_names_the_fault_accepts_the_elr_with_a_caller_above_it() {
        let l = lines(&[
            "unexpected exception EL1h sync: unknown or undefined instruction (EC 0x0) ESR=0x2000000 ELR=0xffffffffc00017c0 FAR=0x0",
            "backtrace (look up: lldb -b -o 'image lookup -a ADDR' target/stafeto-probe.elf):",
            "  #0  0xffffffffc0001204",
            "  #4  0xffffffffc00017c0",
            "  #5  0xffffffffc0002378",
        ]);
        assert!(backtrace_names_the_fault(&l).is_ok());
    }

    #[test]
    fn backtrace_names_the_fault_rejects_a_missing_elr() {
        let l = lines(&[
            "unexpected exception EL1h sync: ... ELR=0xffffffffc00017c0 FAR=0x0",
            "backtrace (look up: ...):",
            "  #0  0xffffffffc0001204",
            "  #1  0xffffffffc0002438",
        ]);
        assert!(backtrace_names_the_fault(&l).is_err());
    }

    #[test]
    fn backtrace_names_the_fault_rejects_the_elr_as_the_last_frame() {
        let l = lines(&[
            "unexpected exception EL1h sync: ... ELR=0xffffffffc00017c0 FAR=0x0",
            "backtrace (look up: ...):",
            "  #0  0xffffffffc0001204",
            "  #4  0xffffffffc00017c0",
        ]);
        assert!(backtrace_names_the_fault(&l).is_err());
    }

    const NM: &str = "\
ffffffffc0003a0c 0000000000000014 t kernel::arch::aarch64::probe::recurse
ffffffffc00042f0 0000000000000438 T handle_exception
ffffffffc0009000 T __text_end
";

    #[test]
    fn powered_off_needs_an_exit_in_time_with_status_zero() {
        let off = Outcome {
            lines: vec![],
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        };
        assert!(expect_powered_off(&off).is_ok());
        let failed = Outcome {
            status: Some(ExitStatus::from_raw(1 << 8)),
            ..off.clone()
        };
        assert!(expect_powered_off(&failed).is_err());
        let hung = Outcome {
            status: None,
            timed_out: true,
            ..off
        };
        assert!(expect_powered_off(&hung).is_err());
    }

    #[test]
    fn symbol_range_reads_address_and_size() {
        assert_eq!(
            symbol_range(NM, "handle_exception"),
            Some(0xffff_ffff_c000_42f0..0xffff_ffff_c000_4728)
        );
    }

    #[test]
    fn symbol_range_needs_the_whole_name_and_a_size() {
        assert_eq!(symbol_range(NM, "recurse"), None);
        assert_eq!(symbol_range(NM, "__text_end"), None);
        assert_eq!(symbol_range(NM, "kernel_main"), None);
    }

    const RECURSE: std::ops::Range<u64> = 0xffff_ffff_c000_3a0c..0xffff_ffff_c000_3a20;

    fn overflow_report(elr: &str, frames: &[&str]) -> Vec<String> {
        let mut l = vec![
            "kernel stack overflow: no room for the trap frame at SP 0xffffffffc001fef0"
                .to_string(),
            format!(
                "unexpected exception EL1h sync: data abort in the kernel (EC 0x25) ESR=0x96000047 ELR={elr} FAR=0xffffffffc001ff70"
            ),
            "backtrace (look up: lldb -b -o 'image lookup -a ADDR' target/stafeto-overflow.elf):"
                .to_string(),
        ];
        l.extend(
            frames
                .iter()
                .enumerate()
                .map(|(i, f)| format!("  #{i:<2} {f}")),
        );
        l
    }

    #[test]
    fn overflow_report_accepts_the_elr_in_the_recursion_with_more_of_it_above() {
        let l = overflow_report(
            "0xffffffffc0003a10",
            &[
                "0xffffffffc0004400",
                "0xffffffffc0003a10",
                "0xffffffffc0003a18",
            ],
        );
        assert!(overflow_report_names(&l, RECURSE).is_ok());
    }

    #[test]
    fn overflow_report_rejects_an_elr_outside_the_recursion() {
        let l = overflow_report(
            "0xffffffffc0004400",
            &["0xffffffffc0004400", "0xffffffffc0003a18"],
        );
        assert!(overflow_report_names(&l, RECURSE).is_err());
    }

    #[test]
    fn overflow_report_rejects_an_elr_missing_from_the_backtrace() {
        let l = overflow_report("0xffffffffc0003a10", &["0xffffffffc0003a18"]);
        assert!(overflow_report_names(&l, RECURSE).is_err());
    }

    #[test]
    fn overflow_report_rejects_a_backtrace_that_stops_at_the_elr() {
        let l = overflow_report(
            "0xffffffffc0003a10",
            &[
                "0xffffffffc0004400",
                "0xffffffffc0003a10",
                "0xffffffffc0004800",
            ],
        );
        assert!(overflow_report_names(&l, RECURSE).is_err());
    }

    #[test]
    fn el2_args_turn_on_virtualization_on_a_cortex_a53() {
        let a = args(&VIRT_EL2, Path::new("k.img"), Some(Path::new("b.img")));
        let joined = a.join(" ");
        assert!(joined.contains("-machine virt,gic-version=2,virtualization=on"));
        assert!(joined.contains("-cpu cortex-a53"));
        assert!(joined.contains("-m 512M"));
        assert!(joined.contains("-kernel k.img"));
        assert!(joined.contains("-initrd b.img"));
    }

    #[test]
    fn collects_output_of_a_finished_process() {
        let o = run_until(sh("echo one; echo two"), Duration::from_secs(5), None).unwrap();
        assert!(!o.timed_out && !o.stopped_on_marker);
        assert_eq!(o.lines, ["one", "two"]);
        assert!(o.status.unwrap().success());
    }

    #[test]
    fn child_stdin_is_the_null_device() {
        // QEMU's `-serial stdio` puts a terminal on its stdin into raw mode,
        // and a killed QEMU never restores it, so the child must not inherit
        // the caller's stdin. This catches a regression whenever the test
        // runner's own stdin is not /dev/null, as in a terminal.
        let o = run_until(
            sh("if [ /dev/stdin -ef /dev/null ]; then echo null; else echo inherited; fi"),
            Duration::from_secs(5),
            None,
        )
        .unwrap();
        assert_eq!(o.lines, ["null"]);
    }

    #[test]
    fn kills_a_process_that_outlives_the_deadline() {
        let start = Instant::now();
        let o = run_until(
            sh("echo started; sleep 10"),
            Duration::from_millis(300),
            None,
        )
        .unwrap();
        assert!(o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(expect_clean_exit_with(&o, "started").is_err());
    }

    #[test]
    fn stops_on_the_marker() {
        let start = Instant::now();
        let o = run_until(
            sh("echo booting; echo 'KERNEL PANIC: no device tree'; sleep 10"),
            Duration::from_secs(20),
            Some("no device tree"),
        )
        .unwrap();
        assert!(o.stopped_on_marker && !o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(expect_marker(&o, "no device tree").is_ok());
    }

    #[test]
    fn clean_exit_needs_the_line_and_status_zero() {
        let ok = Outcome {
            lines: vec!["boot complete".into()],
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        };
        assert!(expect_clean_exit_with(&ok, "boot complete").is_ok());
        let missing = Outcome {
            lines: vec!["booting".into()],
            ..ok.clone()
        };
        assert!(expect_clean_exit_with(&missing, "boot complete").is_err());
        let failed = Outcome {
            status: Some(ExitStatus::from_raw(1 << 8)),
            ..ok.clone()
        };
        assert!(expect_clean_exit_with(&failed, "boot complete").is_err());
    }

    #[test]
    fn survives_non_utf8_output() {
        let start = Instant::now();
        let o = run_until(
            sh("printf 'bad \\377 byte\\n'; echo after; sleep 10"),
            Duration::from_millis(300),
            None,
        )
        .unwrap();
        assert!(o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(o.lines.iter().any(|l| l.starts_with("bad ")));
        assert!(o.lines.iter().any(|l| l == "after"));
    }

    #[test]
    fn marker_must_appear() {
        let o = Outcome {
            lines: vec!["booting".into()],
            status: None,
            timed_out: true,
            stopped_on_marker: false,
        };
        assert!(expect_marker(&o, "no device tree").is_err());
    }

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn report_collects_passes_failures_and_total() {
        let r = parse_report(&lines(&[
            "stafeto 0.1.0 booting",
            "TEST a ok",
            "TEST b FAIL memory is not 512 MiB",
            "TESTS DONE failed=1",
        ]));
        assert_eq!(r.passed, ["a"]);
        assert_eq!(
            r.failed,
            [("b".to_string(), "memory is not 512 MiB".to_string())]
        );
        assert_eq!(r.done, Some(1));
    }

    #[test]
    fn verdict_accepts_a_clean_run() {
        let o = Outcome {
            lines: lines(&["TEST a ok", "TESTS DONE failed=0"]),
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        };
        assert!(verdict(&o, &parse_report(&o.lines)).is_ok());
    }

    #[test]
    fn verdict_rejects_failures_hangs_crashes_and_empty_runs() {
        let base = Outcome {
            lines: vec![],
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        };
        let with = |l: &[&str]| Outcome {
            lines: lines(l),
            ..base.clone()
        };
        let failed = with(&["TEST a FAIL x", "TESTS DONE failed=1"]);
        assert!(verdict(&failed, &parse_report(&failed.lines)).is_err());
        let hung = Outcome {
            timed_out: true,
            status: None,
            ..with(&["TEST a ok"])
        };
        assert!(verdict(&hung, &parse_report(&hung.lines)).is_err());
        let crashed = with(&["TEST a ok", "KERNEL PANIC: boom"]);
        assert!(verdict(&crashed, &parse_report(&crashed.lines)).is_err());
        let empty = with(&["TESTS DONE failed=0"]);
        assert!(verdict(&empty, &parse_report(&empty.lines)).is_err());
        let bad_status = Outcome {
            status: Some(ExitStatus::from_raw(1 << 8)),
            ..with(&["TEST a ok", "TESTS DONE failed=0"])
        };
        assert!(verdict(&bad_status, &parse_report(&bad_status.lines)).is_err());
    }

    fn finished(l: &[&str]) -> Outcome {
        Outcome {
            lines: lines(l),
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        }
    }

    #[test]
    fn report_reads_the_total_of_a_counted_run() {
        let r = parse_report(&lines(&["TEST a ok", "TESTS DONE total=2 failed=1"]));
        assert_eq!((r.total, r.done), (Some(2), Some(1)));
        let uncounted = parse_report(&lines(&["TESTS DONE failed=0"]));
        assert_eq!((uncounted.total, uncounted.done), (None, Some(0)));
    }

    #[test]
    fn counted_verdict_needs_every_test_once() {
        let clean = finished(&["TEST a ok", "TEST b ok", "TESTS DONE total=2 failed=0"]);
        assert!(counted_verdict(&clean, &parse_report(&clean.lines)).is_ok());
        let lost = finished(&["TEST a ok", "TESTS DONE total=2 failed=0"]);
        assert!(counted_verdict(&lost, &parse_report(&lost.lines)).is_err());
        let twice = finished(&["TEST a ok", "TEST a ok", "TESTS DONE total=2 failed=0"]);
        assert!(counted_verdict(&twice, &parse_report(&twice.lines)).is_err());
        let uncounted = finished(&["TEST a ok", "TESTS DONE failed=0"]);
        assert!(counted_verdict(&uncounted, &parse_report(&uncounted.lines)).is_err());
        let failed = finished(&["TEST a ok", "TEST b FAIL x", "TESTS DONE total=2 failed=1"]);
        assert!(counted_verdict(&failed, &parse_report(&failed.lines)).is_err());
    }

    #[test]
    fn a_line_must_match_whole() {
        let o = finished(&["TEST a ok", "\u{0}debug_write stops at its length###"]);
        assert!(expect_line(&o, "TEST a ok").is_ok());
        assert!(expect_line(&o, "TEST a").is_err());
        assert!(expect_line(&o, "debug_write stops at its length").is_err());
    }
}
