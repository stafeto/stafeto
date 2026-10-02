// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask os-test`: the io and malloc suites of os-test
//! (tools/build-os-test.py) on relibc, one test a boot of QEMU (init has
//! no order among its programs). A test's outcome is what os-test's
//! misc/run.sh writes: its output, then `exit: N` when the output is empty
//! or the status is 2 or more; it passes when one of its expectations
//! (<suite>.expect/<test>.*) is that text. A test that needs fork, exec or
//! pipes is UNSUPPORTED and does not run. A test that faults, is killed
//! or gives no end within its time FAILs, and the run goes on. The table
//! goes to target/measure/os-test.txt; `ci` fails when a test of
//! tests/os-test/pass.txt does not pass.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

/// The end of a test in the log, before how it ended.
const ENDED: &str = "init: os-test ended: ";
/// How a test ended with a status, after ENDED.
const EXIT_CODE: &str = "exit code ";
/// How a POSIX test ended by a signal, after ENDED: `signal N (NAME)`.
const SIGNAL: &str = "signal ";
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

/// The end of a test as its boot's log tells it.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// It exited: what misc/run.sh writes, which its expectations judge.
    Exited(String),
    /// It faulted, was killed or gave no end: a FAIL whatever it wrote.
    Failed(String),
}

/// The end of the test whose boot printed `lines`. For an exit, the lines
/// it wrote (the services' and init's own lines left out) and `exit: N`
/// as misc/run.sh adds it; a death by signal N is the shell's status 128 +
/// N, as run.sh sees it; for a fault or a kill, its lines and `exit:
/// signal` with init's reason; a log without the end of the test is a
/// FAIL `timeout`.
pub fn outcome(lines: &[String]) -> Ended {
    let Some(end) = lines.iter().position(|line| line.starts_with(ENDED)) else {
        return Ended::Failed("timeout: no end of the test\n".to_owned());
    };
    let how = lines[end][ENDED.len()..].trim_end_matches('\r');
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
    let signal = how
        .strip_prefix(SIGNAL)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse::<i64>().ok());
    if let Some(n) = signal {
        text.push_str(&format!("exit: {}\n", 128 + n));
        return Ended::Exited(text);
    }
    let Some(status) = how.strip_prefix(EXIT_CODE) else {
        let reason = how.split(',').next().unwrap_or(how);
        text.push_str(&format!("exit: signal ({reason})\n"));
        return Ended::Failed(text);
    };
    let Some(code) = status
        .split(',')
        .next()
        .and_then(|code| code.trim().parse::<i64>().ok())
    else {
        return Ended::Failed(format!("no status in {how:?}\n"));
    };
    if text.is_empty() || code >= 2 {
        text.push_str(&format!("exit: {code}\n"));
    }
    Ended::Exited(text)
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

/// The tests that pass on stafeto: `ci` fails when one of them does not.
const PASSING: &str = "tests/os-test/pass.txt";

/// The name of os-test's licence (ISC) in an image with a test.
pub const LICENCE: &str = "OS-TEST-LICENSE";

/// os-test's LICENSE (tools/build-os-test.py fetches the source).
pub fn licence() -> Result<Vec<u8>, String> {
    let path = target_dir().join("os-test/source/LICENSE");
    std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The suites within BUDGET (`cargo xtask os-test`, `ci`): the run stops once the budget is
/// spent, and the tests of PASSING pass.
pub fn run_in_budget() -> Result<(), String> {
    let start = Instant::now();
    let rows = suites(start + BUDGET)?;
    let took = start.elapsed();
    println!(
        "os-test: {} s of its {} s",
        took.as_secs(),
        BUDGET.as_secs()
    );
    let path = crate::root().join(PASSING);
    let list = std::fs::read_to_string(&path).map_err(|e| format!("{PASSING}: {e}"))?;
    let (lost, new) = compare(&list, &rows);
    for name in &new {
        println!("os-test {name} passes and is not in {PASSING}");
    }
    if lost.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "os-test: {} of {PASSING} no longer pass: {}",
            lost.len(),
            lost.join(", ")
        ))
    }
}

/// The tests of `list` (one name a line, `#` for a comment) that do not
/// pass in `rows`, and the passing tests that `list` lacks.
fn compare(list: &str, rows: &[(String, Verdict, String)]) -> (Vec<String>, Vec<String>) {
    let listed: Vec<&str> = list
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let passes = |name: &str| {
        rows.iter()
            .any(|(row, verdict, _)| row == name && *verdict == Verdict::Pass)
    };
    let lost = listed
        .iter()
        .filter(|name| !passes(name))
        .map(|name| (*name).to_owned())
        .collect();
    let new = rows
        .iter()
        .filter(|(row, verdict, _)| *verdict == Verdict::Pass && !listed.contains(&row.as_str()))
        .map(|(row, _, _)| row.clone())
        .collect();
    (lost, new)
}

/// The suites, a row a test; an error once `deadline` passes.
fn suites(deadline: Instant) -> Result<Vec<(String, Verdict, String)>, String> {
    crate::relibc()?;
    crate::run_cmd(
        std::process::Command::new("python3").arg(crate::root().join("tools/build-os-test.py")),
    )?;
    let work = target_dir().join("os-test");
    let list = std::fs::read_to_string(work.join("tests.txt"))
        .map_err(|e| format!("os-test list: {e}"))?;
    let kernel = build(Variant::Normal)?;
    let mut rows = Vec::new();
    let mut licensed = false;
    for line in list.lines() {
        let (name, built) = line.split_once(' ').ok_or("a bad line of tests.txt")?;
        let (suite, test) = name.split_once('/').ok_or("a test without its suite")?;
        let source_path = work.join("source").join(suite).join(format!("{test}.c"));
        let source = std::fs::read_to_string(&source_path)
            .map_err(|e| format!("{}: {e}", source_path.display()))?;
        let (verdict, text) = if needs_processes(&source) {
            (Verdict::Unsupported, "needs fork, exec or pipes".to_owned())
        } else {
            let ended = match built.strip_prefix('!') {
                // A test that did not compile: os-test's outcome for it.
                Some(failed) => Ended::Exited(format!("{failed}\n")),
                None => {
                    let left = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|left| !left.is_zero())
                        .ok_or_else(|| {
                            format!("os-test spent its {} s before {name}", BUDGET.as_secs())
                        })?;
                    let image = write_boot_image_with(
                        "boot-os-test.img",
                        &PROGRAMS,
                        BOOT_PROFILE,
                        &[("STAFETO_OS_TEST_OBJECT", built)],
                    )?;
                    if !licensed {
                        carries_licence(&image)?;
                        licensed = true;
                    }
                    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
                    cmd.args(qemu::HEADLESS);
                    let run = qemu::run_until(cmd, left.min(TIMEOUT), Some(ENDED))?;
                    outcome(&run.lines)
                }
            };
            match ended {
                Ended::Exited(text) => {
                    let expect = work.join("source").join(format!("{suite}.expect"));
                    if expected(&expect, test, &text)? {
                        (Verdict::Pass, text)
                    } else {
                        (Verdict::Fail, text)
                    }
                }
                Ended::Failed(text) => (Verdict::Fail, text),
            }
        };
        println!("os-test {name}: {} ({})", verdict.name(), first_line(&text));
        rows.push((name.to_owned(), verdict, text));
    }
    let path = write(&rows)?;
    println!("os-test: {}", score(&rows));
    println!("os-test table: {}", path.display());
    Ok(rows)
}

/// Fails unless the boot image at `path` carries os-test's licence.
fn carries_licence(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let licence = licence()?;
    if image
        .files()
        .any(|file| file.name == LICENCE && file.data == licence.as_slice())
    {
        Ok(())
    } else {
        Err(format!("{} carries no {LICENCE}", path.display()))
    }
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
        assert_eq!(outcome(&log), Ended::Exited("open: EISDIR\n".to_owned()));
        let silent = lines(&[
            "init: services started",
            "init: os-test ended: exit code 0, not restarted",
        ]);
        assert_eq!(outcome(&silent), Ended::Exited("exit: 0\n".to_owned()));
        let aborted = lines(&[
            "init: services started",
            "NULL",
            "init: os-test ended: exit code 134, not restarted",
        ]);
        assert_eq!(
            outcome(&aborted),
            Ended::Exited("NULL\nexit: 134\n".to_owned())
        );
        // A death by a signal, as init tells it of a POSIX process: the
        // shell's status 128 + N.
        let signaled = lines(&[
            "init: services started",
            "NULL",
            "init: os-test ended: signal 6 (SIGABRT), not restarted",
        ]);
        assert_eq!(
            outcome(&signaled),
            Ended::Exited("NULL\nexit: 134\n".to_owned())
        );
    }

    /// A fault, a kill, a garbled status and a log without the end of the
    /// test are FAILs, never scored by the expectations.
    #[test]
    fn a_test_without_an_exit_fails() {
        let fault = lines(&[
            "init: services started",
            "partial",
            "init: os-test ended: fault ESR=0x92000046 FAR=0x0 ELR=0x200000, not restarted",
        ]);
        assert_eq!(
            outcome(&fault),
            Ended::Failed(
                "partial\nexit: signal (fault ESR=0x92000046 FAR=0x0 ELR=0x200000)\n".to_owned()
            )
        );
        let killed = lines(&["init: os-test ended: killed, not restarted"]);
        assert_eq!(
            outcome(&killed),
            Ended::Failed("exit: signal (killed)\n".to_owned())
        );
        let log = lines(&["init: services started", "open: EISDIR"]);
        assert!(matches!(outcome(&log), Ended::Failed(text) if text.starts_with("timeout")));
        let garbled = lines(&["init: os-test ended: exit code ?, not restarted"]);
        assert!(matches!(outcome(&garbled), Ended::Failed(_)));
    }

    /// `ci` names each test of the list that no longer passes, and the
    /// passing tests the list lacks.
    #[test]
    fn the_list_of_passing_tests_holds() {
        let row = |name: &str, verdict| (name.to_owned(), verdict, String::new());
        let rows = [
            row("io/a", Verdict::Pass),
            row("io/b", Verdict::Fail),
            row("io/c", Verdict::Pass),
        ];
        let (lost, new) = compare("# comment\nio/a\nio/b\n\nio/d\n", &rows);
        assert_eq!(lost, ["io/b", "io/d"]);
        assert_eq!(new, ["io/c"]);
        assert_eq!(compare("io/a\nio/c\n", &rows), (vec![], vec![]));
    }

    #[test]
    fn processes_are_unsupported() {
        assert!(needs_processes("pid_t child = fork();"));
        assert!(!needs_processes("int fd = open(path, O_RDWR);"));
    }
}
