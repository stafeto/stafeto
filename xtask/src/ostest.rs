// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask os-test`: the io and malloc suites of os-test
//! (tools/build-os-test.py) on relibc, one test a boot of QEMU (init has
//! no order among its programs). A test's outcome is what os-test's
//! misc/run.sh writes: its output, then `exit: N` when the output is empty
//! or the status is 2 or more; it passes when one of its expectations
//! (<suite>.expect/<test>.*) is that text. A test that needs fork, exec or
//! pipes is UNSUPPORTED and does not run. The table goes to
//! target/measure/os-test.txt.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{BOOT_PROFILE, ImageProgram, Variant, build, qemu, target_dir, write_boot_image_with};

/// The image of one test: the RAM files, the process and clock services and
/// the test under the name `os-test`.
const PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", crate::INIT_STACK_SIZE, &["table-os-test"]),
    ("ramfs", "ramfs", crate::SVC_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("os-test", "os-test-probe", crate::POSIX_STACK_SIZE, &[]),
];

/// The end of a test in the log, before its status.
const ENDED: &str = "init: os-test ended: exit code ";
/// The time a test may take on TCG, its boot included.
const TIMEOUT: Duration = Duration::from_secs(60);

/// The result of a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Unsupported,
}

impl Verdict {
    fn name(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Unsupported => "UNSUPPORTED",
        }
    }
}

/// The outcome text of the test whose boot printed `lines`: the lines it
/// wrote (the services' and init's own lines left out) and `exit: N` as
/// misc/run.sh adds it. An error when the log has no end of the test: a
/// test without its result line counts for nothing.
pub fn outcome(lines: &[String]) -> Result<String, String> {
    let end = lines
        .iter()
        .position(|line| line.starts_with(ENDED))
        .ok_or("the test printed no result line (init saw no end of it)")?;
    let code: i64 = lines[end][ENDED.len()..]
        .split(',')
        .next()
        .and_then(|code| code.trim().parse().ok())
        .ok_or_else(|| format!("no status in {:?}", lines[end]))?;
    let start = lines
        .iter()
        .position(|line| line == "init: services started")
        .map_or(0, |at| at + 1);
    let service = |line: &str| {
        line.starts_with("init: ")
            || line.starts_with("ramfs: ")
            || line.starts_with("posix-process: ")
            || line.starts_with("clock: ")
    };
    let mut text = String::new();
    for line in lines[start.min(end)..end].iter() {
        let line = line.trim_end_matches('\r');
        if !service(line) {
            text.push_str(line);
            text.push('\n');
        }
    }
    if text.is_empty() || code >= 2 {
        text.push_str(&format!("exit: {code}\n"));
    }
    Ok(text)
}

/// Whether `outcome` is one of the expectations of `test` in `expect`
/// (`<test>.<anything>`, as os-test's misc/html.c reads them).
pub fn expected(expect: &Path, test: &str, outcome: &str) -> Result<bool, String> {
    let entries = std::fs::read_dir(expect).map_err(|e| format!("{}: {e}", expect.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name
            .strip_prefix(test)
            .is_some_and(|rest| rest.starts_with('.'))
            && !name[test.len() + 1..].starts_with("unknown.")
            && std::fs::read_to_string(&path).is_ok_and(|text| text == outcome)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the test's source needs what stafeto has not yet: processes,
/// programs, pipes.
fn needs_processes(source: &str) -> bool {
    [
        "fork(",
        "execv",
        "execl",
        "pipe(",
        "waitpid(",
        "posix_spawn",
    ]
    .iter()
    .any(|call| source.contains(call))
}

/// The time `ci` gives the suites (about 70 s on TCG for 56 boots).
const BUDGET: Duration = Duration::from_secs(300);

/// The suites within BUDGET, for `ci`.
pub fn run_in_budget() -> Result<(), String> {
    let start = std::time::Instant::now();
    run()?;
    let took = start.elapsed();
    if took > BUDGET {
        return Err(format!(
            "os-test took {} s, over its {} s",
            took.as_secs(),
            BUDGET.as_secs()
        ));
    }
    println!(
        "os-test: {} s of its {} s",
        took.as_secs(),
        BUDGET.as_secs()
    );
    Ok(())
}

pub fn run() -> Result<(), String> {
    crate::relibc()?;
    crate::run_cmd(
        std::process::Command::new("python3").arg(crate::root().join("tools/build-os-test.py")),
    )?;
    let work = target_dir().join("os-test");
    let list = std::fs::read_to_string(work.join("tests.txt"))
        .map_err(|e| format!("os-test list: {e}"))?;
    let kernel = build(Variant::Normal)?;
    let mut rows = Vec::new();
    for line in list.lines() {
        let (name, built) = line.split_once(' ').ok_or("a bad line of tests.txt")?;
        let (suite, test) = name.split_once('/').ok_or("a test without its suite")?;
        let source_path = work.join("source").join(suite).join(format!("{test}.c"));
        let source = std::fs::read_to_string(&source_path)
            .map_err(|e| format!("{}: {e}", source_path.display()))?;
        let (verdict, text) = if needs_processes(&source) {
            (Verdict::Unsupported, "needs fork, exec or pipes".to_owned())
        } else {
            let text = match built.strip_prefix('!') {
                // A test that did not compile: os-test's outcome for it.
                Some(failed) => format!("{failed}\n"),
                None => {
                    let image = write_boot_image_with(
                        "boot-os-test.img",
                        &PROGRAMS,
                        BOOT_PROFILE,
                        &[("STAFETO_OS_TEST_OBJECT", built)],
                    )?;
                    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
                    cmd.args(qemu::HEADLESS);
                    let run = qemu::run_until(cmd, TIMEOUT, Some(ENDED))?;
                    outcome(&run.lines).map_err(|e| format!("{name}: {e}"))?
                }
            };
            let expect = work.join("source").join(format!("{suite}.expect"));
            let verdict = if expected(&expect, test, &text)? {
                Verdict::Pass
            } else {
                Verdict::Fail
            };
            (verdict, text)
        };
        println!("os-test {name}: {} ({})", verdict.name(), first_line(&text));
        rows.push((name.to_owned(), verdict, text));
    }
    let path = write(&rows)?;
    println!("os-test: {}", score(&rows));
    println!("os-test table: {}", path.display());
    Ok(())
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("")
}

/// `PASS n, FAIL n, UNSUPPORTED n of n`.
fn score(rows: &[(String, Verdict, String)]) -> String {
    let count = |v| rows.iter().filter(|row| row.1 == v).count();
    format!(
        "PASS {}, FAIL {}, UNSUPPORTED {} of {}",
        count(Verdict::Pass),
        count(Verdict::Fail),
        count(Verdict::Unsupported),
        rows.len()
    )
}

/// target/measure/os-test.txt: the score and a row a test.
fn write(rows: &[(String, Verdict, String)]) -> Result<PathBuf, String> {
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut text = format!(
        "os-test io and malloc on relibc (commit {}): {}\n\n| test | result | outcome |\n|---|---|---|\n",
        crate::rtbench2::commit(),
        score(rows)
    );
    for (name, verdict, outcome) in rows {
        text.push_str(&format!(
            "| {name} | {} | {} |\n",
            verdict.name(),
            outcome.trim_end().replace('\n', "; ")
        ));
    }
    let path = dir.join("os-test.txt");
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|line| (*line).to_owned()).collect()
    }

    /// The test's own lines between init's start of the services and its
    /// end, `exit: N` for an empty output or a status of 2 or more.
    #[test]
    fn outcome_is_what_run_sh_writes() {
        let log = lines(&[
            "boot complete",
            "init: services started",
            "ramfs: ready",
            "open: EISDIR\r",
            "init: os-test ended: exit code 1, not restarted",
        ]);
        assert_eq!(outcome(&log).unwrap(), "open: EISDIR\n");
        let silent = lines(&[
            "init: services started",
            "init: os-test ended: exit code 0, not restarted",
        ]);
        assert_eq!(outcome(&silent).unwrap(), "exit: 0\n");
        let aborted = lines(&[
            "init: services started",
            "NULL",
            "init: os-test ended: exit code 134, not restarted",
        ]);
        assert_eq!(outcome(&aborted).unwrap(), "NULL\nexit: 134\n");
    }

    /// A log without the end of the test is refused, never scored.
    #[test]
    fn a_test_without_its_result_line_is_refused() {
        let log = lines(&["init: services started", "open: EISDIR"]);
        assert!(outcome(&log).is_err());
        let garbled = lines(&["init: os-test ended: exit code ?, not restarted"]);
        assert!(outcome(&garbled).is_err());
    }

    #[test]
    fn processes_are_unsupported() {
        assert!(needs_processes("pid_t child = fork();"));
        assert!(!needs_processes("int fd = open(path, O_RDWR);"));
    }
}
