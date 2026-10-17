// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask open-posix`: the Open POSIX Test Suite of LTP
//! (tools/build-open-posix.py) on relibc, in batches of one boot each, the
//! way `os-test --full-basic` runs the basic corpus (ostest/full.rs): the
//! tests are compiled and linked on the host, a batch of them is the files
//! of one boot's RAM service, and the runner of os-test (tests/os-test-run)
//! starts each with a time limit and marks its output.
//!
//! The outcome of a test is the suite's own: PASS, FAIL, UNRESOLVED,
//! UNSUPPORTED and UNTESTED by the exit status 0, 1, 2, 4 and 5; a
//! compilation that failed is BUILD, a link that failed LINK, a test the
//! runner killed or one that held the guest still TIMEOUT; SCRIPT and ARGS
//! are the tests the suite runs from a shell script or with arguments from
//! a file, which this run does not start. A test that was only to compile
//! (`-buildonly`) passes when it does. The table goes to
//! target/measure/open-posix.tsv; the run fails when a test of
//! tests/open-posix/pass.txt does not pass.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::ostest::{self, Ended, ProbeLink};
use crate::{Variant, build, llvm_tool, rootfs, target_dir};

/// The tests that pass: the run fails when one of them does not.
const PASSING: &str = "tests/open-posix/pass.txt";
/// The name of the suite's licence in an image.
const LICENCE: &str = "OPEN-POSIX-COPYING";
/// A batch of tests, as in the full basic run: the RAM service keeps half
/// its storage free for the tests' own files.
const BATCH_TESTS: usize = 48;
const BATCH_BYTES: usize = 8 * 1024 * 1024;
const BATCH_ENTRIES: usize = 900;
/// The time a conformance test may take (ms), and a functional or stress one.
/// Tests of timers and clocks sleep for half a minute in all (timer_settime
/// 1-2 runs 27 s), so the limit is far above the common case.
const LIMIT_MS: u64 = 60_000;
const LONG_LIMIT_MS: u64 = 120_000;
/// How many times a batch is started again after a hang of the guest.
const RESTARTS: usize = 8;

/// A row of tests.tsv.
struct Test {
    name: String,
    kind: String,
    object: String,
    detail: String,
}

/// A row of the result table: the name, the outcome, the phase and a line
/// that says why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub result: &'static str,
    pub phase: &'static str,
    pub detail: String,
}

/// Tests that sleep for minutes by their design: timer_settime 5-3 sets
/// thirty timers in the past and sleeps 5 s after each.
const SLOW: [&str; 1] = ["conformance/interfaces/timer_settime/5-3"];

fn limit_of(name: &str) -> u64 {
    if SLOW.contains(&name) {
        return 240_000;
    }
    if name.starts_with("conformance/") {
        LIMIT_MS
    } else {
        LONG_LIMIT_MS
    }
}

fn one_line(text: &str, bound: usize) -> String {
    let mut line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.len() > bound {
        let mut at = bound;
        while !line.is_char_boundary(at) {
            at -= 1;
        }
        line.truncate(at);
    }
    line
}

/// The outcome of a test that ended as `ended` says.
pub fn classify(ended: Ended) -> (&'static str, String) {
    match ended {
        Ended::Exited(text, code) => {
            let said = one_line(
                text.strip_suffix(&format!("exit: {code}\n"))
                    .unwrap_or(&text),
                300,
            );
            let result = match code {
                0 => "PASS",
                1 => "FAIL",
                2 => "UNRESOLVED",
                4 => "UNSUPPORTED",
                5 => "UNTESTED",
                _ => "FAIL",
            };
            let how = match code {
                0 | 1 | 2 | 4 | 5 => String::new(),
                c if c >= 128 => format!("signal {} ", c - 128),
                c => format!("exit {c} "),
            };
            (result, format!("{how}{said}").trim_end().to_owned())
        }
        Ended::Failed(text) => {
            let said = one_line(&text, 300);
            if said.contains("exit: timeout") {
                (
                    "TIMEOUT",
                    said.replace("exit: timeout", "").trim().to_owned(),
                )
            } else {
                ("FAIL", said)
            }
        }
    }
}

/// The names of the symbols the native linker could not find, from its
/// diagnostics.
fn undefined_symbols(error: &str) -> String {
    let mut names = BTreeSet::new();
    for line in error.lines() {
        if let Some((_, name)) = line.split_once("undefined symbol: ") {
            names.insert(name.trim().to_owned());
        }
    }
    if names.is_empty() {
        one_line(error, 200)
    } else {
        names.into_iter().collect::<Vec<_>>().join(",")
    }
}

fn tests_of(work: &Path) -> Result<Vec<Test>, String> {
    let text = std::fs::read_to_string(work.join("tests.tsv"))
        .map_err(|e| format!("open-posix list: {e}"))?;
    text.lines()
        .map(|line| {
            let mut fields = line.splitn(4, '\t');
            let mut next = || fields.next().map(str::to_owned);
            match (next(), next(), next(), next()) {
                (Some(name), Some(kind), Some(object), Some(detail)) => Ok(Test {
                    name,
                    kind,
                    object,
                    detail,
                }),
                _ => Err(format!("a bad line of tests.tsv: {line}")),
            }
        })
        .collect()
}

/// Names in `list` (`#` for a comment) whose row is not PASS, and the PASS
/// rows `list` lacks.
pub fn compare(list: &str, rows: &[Row]) -> (Vec<String>, Vec<String>) {
    let listed: BTreeSet<&str> = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let passing: BTreeSet<&str> = rows
        .iter()
        .filter(|r| r.result == "PASS")
        .map(|r| r.name.as_str())
        .collect();
    (
        listed
            .difference(&passing)
            .map(|s| (*s).to_owned())
            .collect(),
        passing
            .difference(&listed)
            .map(|s| (*s).to_owned())
            .collect(),
    )
}

fn entries(names: &[&str]) -> usize {
    let mut directories = BTreeSet::new();
    for name in names {
        for (at, _) in name.match_indices('/') {
            directories.insert(&name[..at]);
        }
    }
    names.len() + directories.len() + 32
}

/// Whether one more test fits in a batch of `names` and `bytes`.
fn fits(names: &[&str], bytes: usize, name: &str, size: usize) -> bool {
    names.len() < BATCH_TESTS && bytes + size <= BATCH_BYTES && {
        let mut all = names.to_vec();
        all.push(name);
        entries(&all) <= BATCH_ENTRIES
    }
}

/// Whether the runner went through its whole list: a test that ends the
/// runner early (by a signal to its group, say) leaves the rest unstarted.
fn batch_finished(log: &str) -> bool {
    log.lines().any(|l| l == "os-test-run: done")
        && log
            .lines()
            .any(|l| l == "init: os-test-run ended: exit code 0, not restarted")
}

fn write_rows(rows: &[Row]) -> Result<(), String> {
    let mut ordered = rows.to_vec();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut text = "test\tresult\tphase\tdetail\n".to_owned();
    for row in ordered {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            row.name,
            row.result,
            row.phase,
            row.detail.replace(['\t', '\n', '\r'], " ")
        ));
    }
    std::fs::write(dir.join("open-posix.tsv"), text).map_err(|e| e.to_string())
}

/// A test linked into an ELF file, or the row that says why not.
type Linked = Result<Vec<u8>, Row>;

fn link_all(
    link: &ProbeLink,
    work: &Path,
    common: &str,
    tests: &[&Test],
) -> Result<Vec<Linked>, String> {
    let objdump = llvm_tool("llvm-objdump")?;
    let objcopy = llvm_tool("llvm-objcopy")?;
    let link_dir = work.join("link");
    let next = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<Result<Linked, String>>>> =
        Mutex::new((0..tests.len()).map(|_| None).collect());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let at = next.fetch_add(1, Ordering::SeqCst);
                    let Some(test) = tests.get(at) else { break };
                    let one = || -> Result<Linked, String> {
                        let scratch = link_dir.join(format!("test-{at}"));
                        let elf = link_dir.join(format!("test-{at}.elf"));
                        let linked = link.link_objects(&[&test.object, common], &scratch, &elf);
                        let _ = std::fs::remove_dir_all(&scratch);
                        if let Err(error) = linked {
                            if error.starts_with("native linker exited ") {
                                return Ok(Err(Row {
                                    name: test.name.clone(),
                                    result: "LINK",
                                    phase: "LINK",
                                    detail: undefined_symbols(&error),
                                }));
                            }
                            return Err(format!("link infrastructure for {}: {error}", test.name));
                        }
                        crate::disasm::erratum_835769(&elf, &objdump)?;
                        crate::disasm::erratum_843419(&elf)?;
                        let stripped = link_dir.join(format!("test-{at}.stripped"));
                        crate::run_cmd(
                            Command::new(&objcopy)
                                .arg("--strip-all")
                                .arg(&elf)
                                .arg(&stripped),
                        )?;
                        let bytes = std::fs::read(&stripped).map_err(|e| e.to_string())?;
                        for path in [&elf, &stripped] {
                            std::fs::remove_file(path).map_err(|e| e.to_string())?;
                        }
                        Ok(Ok(bytes))
                    };
                    slots.lock().unwrap_or_else(PoisonError::into_inner)[at] = Some(one());
                }
            });
        }
    });
    slots
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .into_iter()
        .map(|slot| slot.ok_or_else(|| "a test was not linked".to_owned())?)
        .collect()
}

fn bytes_of(batch: &[(String, Vec<u8>)]) -> usize {
    batch.iter().map(|t| t.1.len()).sum()
}

/// The rows of the `tests` (name, ELF bytes) run in as many boots of one
/// batch as a hang of the guest takes: a test that began and did not end
/// while the batch did is TIMEOUT, and the tests after it go to a new boot.
fn run_batch(
    kernel: &crate::Artifacts,
    number: usize,
    mut tests: Vec<(String, Vec<u8>)>,
) -> (Vec<Row>, Vec<String>) {
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    for attempt in 0..=RESTARTS {
        if tests.is_empty() {
            break;
        }
        let limits: Vec<u64> = tests.iter().map(|t| limit_of(&t.0)).collect();
        let budget = limits.iter().sum::<u64>() / 1000 + 180;
        let image = format!("open-posix-{number}-{attempt}.img");
        let log = match ostest::boot(
            kernel,
            &image,
            rootfs::open_posix(&tests, &limits),
            Duration::from_secs(budget),
        ) {
            Ok((log, _)) => log,
            Err(error) => {
                problems.push(format!("batch {number}: {error}"));
                String::new()
            }
        };
        let finished = batch_finished(&log);
        let before = rows.len();
        let mut left = Vec::new();
        for (name, elf) in tests {
            match ostest::outcome(&log, &name) {
                Ended::Failed(text) if text.contains("did not start") => {
                    if finished {
                        rows.push(Row {
                            name,
                            result: "FAIL",
                            phase: "RUNTIME",
                            detail: "the runner did not start the test".into(),
                        });
                    } else {
                        left.push((name, elf));
                    }
                }
                Ended::Failed(text) if text.contains("no end of the test") => {
                    // It began and the runner never said how it ended: the
                    // guest held still (or the runner was lost) with it.
                    rows.push(Row {
                        name,
                        result: "TIMEOUT",
                        phase: "RUNTIME",
                        detail: "no end mark: the guest held still or the test ended the runner"
                            .into(),
                    });
                }
                ended => {
                    let (result, detail) = classify(ended);
                    println!("open-posix {name}: {result} ({})", one_line(&detail, 80));
                    rows.push(Row {
                        name,
                        result,
                        phase: "RUNTIME",
                        detail,
                    });
                }
            }
        }
        tests = left;
        if finished || rows.len() == before {
            break;
        }
    }
    if !tests.is_empty() && rows.is_empty() {
        problems.push(format!("batch {number} never ran a test"));
    }
    for (name, _) in tests {
        rows.push(Row {
            name,
            result: "TIMEOUT",
            phase: "RUNTIME",
            detail: "the batch gave up after restarts".into(),
        });
    }
    (rows, problems)
}

/// What a run covers.
pub enum Select {
    /// The tests of PASSING, all of which must pass.
    Pinned,
    /// Every test.
    Full,
    /// The tests whose name starts with this text (to look at a failure;
    /// PASSING is not enforced).
    Prefix(String),
}

/// The run of the tests `select` names.
pub fn run(select: Select, jobs: usize) -> Result<(), String> {
    let pinned = matches!(select, Select::Pinned);
    let wanted_name = |name: &str, listed: &BTreeSet<&str>| match &select {
        Select::Pinned => listed.contains(name),
        Select::Full => true,
        Select::Prefix(prefix) => name.starts_with(prefix.as_str()),
    };
    let begun = Instant::now();
    crate::relibc()?;
    crate::busybox_build()?;
    crate::run_cmd(Command::new("python3").arg(crate::root().join("tools/build-open-posix.py")))?;
    let work = target_dir().join("open-posix");
    ostest::use_licence(LICENCE, work.join("source/COPYING"));
    let list = std::fs::read_to_string(crate::root().join(PASSING))
        .map_err(|e| format!("{PASSING}: {e}"))?;
    let listed: BTreeSet<&str> = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let all = tests_of(&work)?;
    let mut rows = Vec::new();
    let mut to_run = Vec::new();
    let mut scripts: Vec<(String, Vec<u8>)> = Vec::new();
    for test in &all {
        if !wanted_name(&test.name, &listed) {
            continue;
        }
        let row = |result, phase, detail: &str| Row {
            name: test.name.clone(),
            result,
            phase,
            detail: detail.to_owned(),
        };
        match (test.kind.as_str(), test.object.as_str()) {
            ("SCRIPT", _) => {
                let path = work.join("source").join(format!("{}.sh", test.name));
                match std::fs::read(&path) {
                    Ok(bytes) => scripts.push((test.name.clone(), bytes)),
                    Err(e) => rows.push(row("SCRIPT", "SKIP", &format!("{}: {e}", path.display()))),
                }
            }
            ("ARGS", _) => rows.push(row("ARGS", "SKIP", "started with arguments from a file")),
            (_, "!compile") => rows.push(row("BUILD", "COMPILE", &test.detail)),
            ("BUILDONLY", _) => rows.push(row("PASS", "COMPILE", "compiled")),
            _ => to_run.push(test),
        }
    }
    let bootstrap = work.join("empty-main.o");
    crate::run_cmd(
        Command::new("python3")
            .arg(crate::root().join("tools/check-os-test-headers.py"))
            .arg("--bootstrap")
            .arg(&bootstrap),
    )?;
    let link = ProbeLink::new(&bootstrap.display().to_string(), &work.join("probe"))?;
    let common = std::fs::read_to_string(work.join("common.txt")).map_err(|e| e.to_string())?;
    let linked = link_all(&link, &work, common.trim(), &to_run)?;
    let mut batches: Vec<Vec<(String, Vec<u8>)>> = Vec::new();
    let mut current: Vec<(String, Vec<u8>)> = Vec::new();
    let mut bytes = 0;
    for (test, result) in to_run.iter().zip(linked) {
        match result {
            Err(row) => rows.push(row),
            Ok(elf) => {
                let names: Vec<&str> = current.iter().map(|t| t.0.as_str()).collect();
                if !fits(&names, bytes, &test.name, elf.len()) && !current.is_empty() {
                    batches.push(std::mem::take(&mut current));
                    bytes = 0;
                }
                bytes += elf.len();
                current.push((test.name.clone(), elf));
            }
        }
    }
    // The suite's shell scripts run from the image under its ash, which
    // the "#!/bin/sh" line names.
    for (name, bytes) in scripts {
        let names: Vec<&str> = current.iter().map(|t| t.0.as_str()).collect();
        if !fits(&names, bytes_of(&current), &name, bytes.len()) && !current.is_empty() {
            batches.push(std::mem::take(&mut current));
        }
        current.push((name, bytes));
    }
    if !current.is_empty() {
        batches.push(current);
    }
    write_rows(&rows)?;
    println!(
        "open-posix: {} tests, {} batches, built in {:.1}s",
        all.len(),
        batches.len(),
        begun.elapsed().as_secs_f64()
    );
    let kernel = build(Variant::Normal)?;
    let rows = Arc::new(Mutex::new(rows));
    let problems = Arc::new(Mutex::new(Vec::new()));
    let mut boots = Vec::new();
    for (number, tests) in batches.into_iter().enumerate() {
        let kernel = kernel.clone();
        let rows = Arc::clone(&rows);
        let problems = Arc::clone(&problems);
        boots.push(crate::jobs::job(
            &format!("open-posix {number}"),
            move || {
                let (done, trouble) = run_batch(&kernel, number, tests);
                problems
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend(trouble);
                let mut rows = rows.lock().unwrap_or_else(PoisonError::into_inner);
                rows.extend(done);
                write_rows(&rows)
            },
        ));
    }
    crate::jobs::run_all(boots, jobs)?;
    let rows = rows.lock().unwrap_or_else(PoisonError::into_inner);
    let names: BTreeSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    let wanted = all.iter().filter(|t| wanted_name(&t.name, &listed)).count();
    if rows.len() != wanted || names.len() != wanted {
        return Err(format!(
            "open-posix: {} rows ({} distinct) for {wanted} tests",
            rows.len(),
            names.len()
        ));
    }
    write_rows(&rows)?;
    let (lost, new) = compare(&list, &rows);
    let partial = matches!(select, Select::Prefix(_));
    if !pinned && !partial {
        for name in &new {
            println!("open-posix {name} passes and is not in {PASSING}");
        }
    }
    let count = |what: &str| rows.iter().filter(|r| r.result == what).count();
    println!(
        "open-posix: {} PASS, {} FAIL, {} UNRESOLVED, {} UNSUPPORTED, {} UNTESTED, {} BUILD, {} LINK, {} TIMEOUT, {} SCRIPT, {} ARGS of {}, {:.1}s",
        count("PASS"),
        count("FAIL"),
        count("UNRESOLVED"),
        count("UNSUPPORTED"),
        count("UNTESTED"),
        count("BUILD"),
        count("LINK"),
        count("TIMEOUT"),
        count("SCRIPT"),
        count("ARGS"),
        rows.len(),
        begun.elapsed().as_secs_f64()
    );
    let problems = problems.lock().unwrap_or_else(PoisonError::into_inner);
    if !problems.is_empty() {
        return Err(format!("open-posix boot trouble: {}", problems.join("; ")));
    }
    if !lost.is_empty() && !partial {
        return Err(format!(
            "open-posix: {} of {PASSING} no longer pass: {}",
            lost.len(),
            lost.join(", ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, result: &'static str) -> Row {
        Row {
            name: name.to_owned(),
            result,
            phase: "RUNTIME",
            detail: String::new(),
        }
    }

    #[test]
    fn exit_statuses_are_the_suites_outcomes() {
        let exited = |text: &str, code| classify(Ended::Exited(text.to_owned(), code));
        assert_eq!(exited("Test PASSED\n", 0).0, "PASS");
        assert_eq!(exited("Test FAILED\n", 1), ("FAIL", "Test FAILED".into()));
        assert_eq!(exited("x\n", 2).0, "UNRESOLVED");
        assert_eq!(exited("x\n", 4).0, "UNSUPPORTED");
        assert_eq!(exited("x\n", 5).0, "UNTESTED");
        assert_eq!(exited("exit: 3\n", 3), ("FAIL", "exit 3".into()));
        assert_eq!(exited("exit: 139\n", 139), ("FAIL", "signal 11".into()));
        assert_eq!(
            classify(Ended::Failed("exit: timeout\n".into())).0,
            "TIMEOUT"
        );
        assert_eq!(
            classify(Ended::Failed("exit: error spawn 2\n".into())).0,
            "FAIL"
        );
    }

    #[test]
    fn a_listed_test_that_does_not_pass_is_lost() {
        let rows = [row("a/1", "PASS"), row("a/2", "FAIL"), row("a/3", "PASS")];
        let (lost, new) = compare("# c\na/1\na/2\na/gone\n", &rows);
        assert_eq!(lost, ["a/2", "a/gone"]);
        assert_eq!(new, ["a/3"]);
        assert_eq!(compare("a/1\na/3\n", &rows), (vec![], vec![]));
    }

    #[test]
    fn undefined_symbols_are_named_once() {
        let text = "ld.lld: error: undefined symbol: mq_open\n>>> x\nld.lld: error: undefined symbol: mq_open\nld.lld: error: undefined symbol: aio_read\n";
        assert_eq!(undefined_symbols(text), "aio_read,mq_open");
    }

    #[test]
    fn batches_are_bounded_by_tests_bytes_and_entries() {
        let names: Vec<String> = (0..BATCH_TESTS).map(|n| format!("c/i/t{n}/1-1")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        assert!(!fits(&refs, 0, "c/i/x/1-1", 1));
        assert!(fits(&refs[..2], 0, "c/i/x/1-1", 1));
        assert!(fits(&refs[..2], BATCH_BYTES - 1, "c/i/x/1-1", 1));
        assert!(!fits(&refs[..2], BATCH_BYTES, "c/i/x/1-1", 1));
    }

    #[test]
    fn limits_follow_the_section() {
        assert_eq!(limit_of("conformance/interfaces/fork/1-1"), LIMIT_MS);
        assert_eq!(limit_of("stress/threads/x"), LONG_LIMIT_MS);
        assert_eq!(limit_of("functional/timers/x"), LONG_LIMIT_MS);
    }

    #[test]
    fn the_list_of_passes_is_sorted() {
        let text = std::fs::read_to_string(crate::root().join(PASSING)).unwrap();
        let names: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(names.iter().all(|n| n.contains('/')));
    }
}
