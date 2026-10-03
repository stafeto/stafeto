// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask os-test`: the io, malloc, process, signal and pty suites of
//! os-test and the tests of its basic suite that start programs (spawn,
//! exec, fork; tools/build-os-test.py) on relibc. The tests of a suite are files of one boot's RAM service, and
//! the runner (tests/os-test-run) starts each as misc/run.sh does and marks
//! its output (`@@os-test begin NAME`, `@@os-test end NAME exit N`); `ci`
//! reads a test's outcome between the marks: what misc/run.sh writes, its
//! output, then `exit: N` when the output is empty or the status is 2 or
//! more. A test passes when one of its expectations
//! (<suite>.expect/<test>.*) is that text; a test of the basic suite, which
//! has none, when the outcome is `exit: 0`. The bounded readiness groups
//! basic/poll, basic/sys_select, signal/ppoll and pty run explicitly (5f). A test that faults, is killed or gives
//! no end within the runner's 10 s FAILs, and the run goes on. The
//! table goes to target/measure/os-test.txt; `ci` fails when a test of
//! tests/os-test/pass.txt does not pass. `cargo xtask os-test --one NAME`
//! runs one test in a boot of its own and shows its log, to look at a
//! failure.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::jobs::Job;
use crate::{
    BOOT_PROFILE, BUILD_LOCK, ImageProgram, PROGRAM_TARGET, Variant, build, cargo, cargo_output,
    llvm_tool, qemu, rootfs, target_dir, write_boot_image_files,
};

/// The image of a suite: the RAM files with the tests, pipes, the console
/// and terminal, process and clock services, the loader and the runner.
const PROGRAMS: [ImageProgram; 11] = [
    ("init", "init", crate::INIT_STACK_SIZE, &["table-os-test"]),
    ("uart", "uart", crate::UART_STACK_SIZE, &[]),
    ("tty", "tty", crate::TTY_STACK_SIZE, &[]),
    ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", crate::PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("os-test-run", "os-test-run", crate::POSIX_STACK_SIZE, &[]),
    ("loader", "loader", 0, &[]),
    (
        "virtio-rng",
        "virtio-rng",
        crate::entropy::RNG_STACK_SIZE,
        &[],
    ),
    (
        "entropy",
        "entropy",
        crate::entropy::ENTROPY_STACK_SIZE,
        &[],
    ),
];

/// The end of the runner in the log, when it ended.
const ENDED: &str = "init: os-test-run ended";
/// The marks of the runner (tests/os-test-run/run.c).
const BEGIN: &str = "@@os-test begin ";
const END: &str = "@@os-test end ";
/// How a POSIX test ended by a signal, after the mark: `signal N`.
const SIGNAL: &str = "signal ";
/// How a test ended with a status, after the mark.
const EXIT_CODE: &str = "exit ";
/// The time a suite may take on TCG, its boot included.
const TIMEOUT: Duration = Duration::from_secs(600);

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

/// The end of a test as the runner's marks tell it.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// It exited: what misc/run.sh writes, which its expectations judge.
    Exited(String),
    /// It faulted, was killed or gave no end: a FAIL whatever it wrote.
    Failed(String),
}

/// The end of the test `name` in `log`, the lines of a boot joined: the
/// output between its marks (the services' and the kernel's own lines left
/// out) and `exit: N` as misc/run.sh adds it, for an empty output or a
/// status of 2 or more; a death by signal N is the shell's status 128 + N,
/// as run.sh sees it; no mark of the start or the end, a timeout the runner
/// killed and a failure of the runner are FAILs.
pub fn outcome(log: &str, name: &str) -> Ended {
    let begin = format!("{BEGIN}{name}\n");
    let Some(at) = log.find(&begin) else {
        return Ended::Failed("timeout: the test did not start\n".to_owned());
    };
    let rest = &log[at + begin.len()..];
    let mark = format!("{END}{name} ");
    let Some(end) = rest.find(&mark) else {
        return Ended::Failed("timeout: no end of the test\n".to_owned());
    };
    let how = rest[end + mark.len()..].lines().next().unwrap_or("");
    let service = |line: &str| {
        line.starts_with("init: ")
            || line.starts_with("ramfs: ")
            || line.starts_with("pipe: ")
            || line.starts_with("tty: ")
            || line.starts_with("virtio-rng: ")
            || line.starts_with("entropy: ")
            || line.starts_with("posix-process: ")
            || line.starts_with("clock: ")
            || line.starts_with("process fault: ")
    };
    let mut text = String::new();
    for line in rest[..end].split_inclusive('\n') {
        if !(line.ends_with('\n') && service(line)) {
            text.push_str(line);
        }
    }
    let code = if let Some(n) = how.strip_prefix(SIGNAL).and_then(|n| n.parse::<i64>().ok()) {
        128 + n
    } else if let Some(code) = how
        .strip_prefix(EXIT_CODE)
        .and_then(|c| c.trim().parse::<i64>().ok())
    {
        code
    } else {
        text.push_str(&format!("exit: {how}\n"));
        return Ended::Failed(text);
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

/// Finds readiness calls, including ppoll and pselect.
fn needs_poll(source: &str) -> bool {
    ["poll(", "select("]
        .iter()
        .any(|call| source.contains(call))
}

/// Readiness coverage is enabled explicitly for the accepted groups.
fn readiness_group(name: &str) -> bool {
    name.starts_with("basic/poll/")
        || name.starts_with("basic/sys_select/")
        || name.starts_with("signal/ppoll-")
        || name.starts_with("pty/")
}

/// The time `ci` gives the boots of the suites, counted from the first
/// one's start: about 230 s on TCG since the suites of `fork` (5d), up to
/// 241 s seen, with room for the variance of a loaded host.
const BUDGET: Duration = Duration::from_secs(420);

/// The tests that pass on stafeto: `ci` fails when one of them does not.
const PASSING: &str = "tests/os-test/pass.txt";

/// The name of os-test's licence (ISC) in an image with a test.
pub const LICENCE: &str = "OS-TEST-LICENSE";

/// os-test's LICENSE (tools/build-os-test.py fetches the source).
pub fn licence() -> Result<Vec<u8>, String> {
    let path = target_dir().join("os-test/source/LICENSE");
    std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The suites within BUDGET (`cargo xtask os-test`), `jobs` boots at a
/// time: the run stops once the budget is spent, and the tests of PASSING
/// pass.
pub fn run_in_budget(jobs: usize) -> Result<(), String> {
    let (list, plan) = plan()?;
    crate::jobs::run_all(list, jobs)?;
    crate::jobs::run_all(vec![runner_check_job()], 1)?;
    finish(plan)
}

/// The rows of a run of the suites: a place for each test, filled as its
/// job ends.
type Rows = Arc<Mutex<Vec<Option<Row>>>>;

/// A test's name, its verdict and its outcome.
type Row = (String, Verdict, String);

/// The suites as a job for each test, and what `finish` needs.
pub struct Plan {
    rows: Rows,
    /// The start of the first test's job: the budget counts from it.
    started: Arc<OnceLock<Instant>>,
    /// Selected directory; a full CI run has no filter.
    suite: Option<String>,
}

/// The suites as jobs (a boot a suite, the tests started from files), after
/// the build of os-test's tests. `ci` puts them among its own jobs.
pub fn plan() -> Result<(Vec<Job>, Plan), String> {
    plan_suite(None)
}

/// Select a whole directory with the regular runner and retained PASS gate.
pub fn run_suite(suite: &str, jobs: usize) -> Result<(), String> {
    let (list, plan) = plan_suite(Some(suite))?;
    crate::jobs::run_all(list, jobs)?;
    finish(plan)
}

fn in_suite(name: &str, suite: &str) -> bool {
    name.strip_prefix(suite)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn select_suite(tests: Vec<Test>, suite: &str) -> Result<Vec<Test>, String> {
    let selected: Vec<_> = tests
        .into_iter()
        .filter(|t| in_suite(&t.name, suite))
        .collect();
    if selected.is_empty() {
        Err(format!("unknown or empty os-test suite: {suite}"))
    } else {
        Ok(selected)
    }
}

fn plan_suite(suite: Option<&str>) -> Result<(Vec<Job>, Plan), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        crate::relibc()?;
    }
    let mut compile = Command::new("python3");
    compile.arg(crate::root().join("tools/build-os-test.py"));
    if let Some(suite) = suite {
        compile.args(["--suite", suite]);
    }
    crate::run_cmd(&mut compile)?;
    let work = target_dir().join("os-test");
    let tests = tests_of(&work)?;
    let tests = match suite {
        Some(suite) => select_suite(tests, suite)?,
        None => tests,
    };
    let kernel = build(Variant::Normal)?;
    let mut places: Vec<Option<Row>> = Vec::new();
    for test in &tests {
        let source = source_of(&work, test)?;
        places.push(if needs_poll(&source) && !readiness_group(&test.name) {
            Some((
                test.name.clone(),
                Verdict::Unsupported,
                "readiness test awaits explicit coverage".to_owned(),
            ))
        } else if let Some(failed) = test.built.strip_prefix('!') {
            // A test that did not compile: os-test's outcome for it.
            let text = format!("{failed}\n");
            let verdict = if passes(&work, test, &text)? {
                Verdict::Pass
            } else {
                Verdict::Fail
            };
            Some((test.name.clone(), verdict, text))
        } else {
            None
        });
    }
    let rows: Rows = Arc::new(Mutex::new(places));
    let started = Arc::new(OnceLock::new());
    let jobs = suite_jobs(&work, tests, &kernel, &rows, &started)?;
    Ok((
        jobs,
        Plan {
            rows,
            started,
            suite: suite.map(str::to_owned),
        },
    ))
}

/// The end of a run of the suites: the table, the score and the list of
/// the tests that pass.
pub fn finish(plan: Plan) -> Result<(), String> {
    let rows: Vec<Row> = plan
        .rows
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .flatten()
        .cloned()
        .collect();
    let path = write(&rows, plan.suite.as_deref())?;
    println!("os-test: {}", score(&rows));
    println!("os-test table: {}", path.display());
    let took = plan.started.get().map_or(Duration::ZERO, Instant::elapsed);
    println!(
        "os-test boots: {} s of its {} s",
        took.as_secs(),
        BUDGET.as_secs()
    );
    let path = crate::root().join(PASSING);
    let list = std::fs::read_to_string(&path).map_err(|e| format!("{PASSING}: {e}"))?;
    let list = match plan.suite.as_deref() {
        Some(suite) => list
            .lines()
            .filter(|name| in_suite(name.trim(), suite))
            .collect::<Vec<_>>()
            .join("\n"),
        None => list,
    };
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
fn compare(list: &str, rows: &[Row]) -> (Vec<String>, Vec<String>) {
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

/// A test `suite/test` of tests.txt: its name, the object it was
/// compiled to or the outcome of its compilation's failure, and the part
/// of the source tree its source and expectations are in.
struct Test {
    name: String,
    /// The suite of the name: `io`, `malloc`, `process`, `signal` or `basic`.
    suite: String,
    /// The name without the suite.
    test: String,
    built: String,
}

/// The tests of `work`/tests.txt in order.
fn tests_of(work: &Path) -> Result<Vec<Test>, String> {
    let list = std::fs::read_to_string(work.join("tests.txt"))
        .map_err(|e| format!("os-test list: {e}"))?;
    list.lines()
        .map(|line| {
            let (name, built) = line.split_once(' ').ok_or("a bad line of tests.txt")?;
            let (suite, test) = name.split_once('/').ok_or("a test without its suite")?;
            Ok(Test {
                name: name.to_owned(),
                suite: suite.to_owned(),
                test: test.to_owned(),
                built: built.to_owned(),
            })
        })
        .collect()
}

/// The source of `test`.
fn source_of(work: &Path, test: &Test) -> Result<String, String> {
    let path = work
        .join("source")
        .join(&test.suite)
        .join(format!("{}.c", test.test));
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Whether `text`, the outcome of `test`, is one of its expectations: of
/// the suite's `.expect` directory, or `exit: 0` for the basic suite,
/// which has none.
fn passes(work: &Path, test: &Test, text: &str) -> Result<bool, String> {
    let expect = work.join("source").join(format!("{}.expect", test.suite));
    if test.suite == "basic" && !expect.exists() {
        return Ok(text == "exit: 0\n");
    }
    // The expectations of a test of basic/<part>/<name> do not exist; the
    // others are named by the test alone.
    expected(&expect, &test.test, text)
}

/// The ELF file of `test`, its object linked with the layer and relibc
/// into the program os-test-probe, stripped of what the image does not
/// need, `elfs`/`<name>` kept beside it.
fn test_elf(test: &Test, object: &str, elfs: &Path) -> Result<Vec<u8>, String> {
    // The build and the copy of its output go together: another build in
    // between would leave its own file at the path every build shares.
    let _building = BUILD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut cmd = cargo();
    cmd.env("STAFETO_OS_TEST_OBJECT", object)
        .arg("build")
        .args(BOOT_PROFILE.args())
        .args(["--target", PROGRAM_TARGET, "--package", "os-test-probe"]);
    crate::run_cmd(&mut cmd)?;
    let built = cargo_output(&target_dir(), PROGRAM_TARGET, BOOT_PROFILE, "os-test-probe");
    crate::disasm::erratum_835769(&built, &llvm_tool("llvm-objdump")?)?;
    let kept = elfs.join(test.name.replace('/', "__"));
    crate::run_cmd(
        Command::new(llvm_tool("llvm-objcopy")?)
            .arg("--strip-all")
            .arg(&built)
            .arg(&kept),
    )?;
    std::fs::read(&kept).map_err(|e| format!("{}: {e}", kept.display()))
}

/// The runner's boot of an image with `files`, its log joined into one
/// text and as lines; an error when the image does not carry the licence.
fn boot(
    kernel: &crate::Artifacts,
    image: &str,
    files: Vec<rootfs::RootFile>,
    timeout: Duration,
) -> Result<(String, Vec<String>), String> {
    let image = write_boot_image_files(image, &PROGRAMS, BOOT_PROFILE, &[], files)?;
    carries_licence(&image)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let run = qemu::run_until(cmd, timeout, Some(ENDED))?;
    let log = run
        .lines
        .iter()
        .map(|line| line.trim_end_matches('\r'))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    Ok((log, run.lines))
}

/// The check of the runner: a test that never ends gets SIGKILL after the
/// time the list gives it (a second here) and the run goes on with the
/// next, which exits with 7.
fn runner_check(kernel: &crate::Artifacts) -> Result<(), String> {
    let (log, _) = boot(
        kernel,
        "os-test-check.img",
        rootfs::runner_check(),
        Duration::from_secs(60),
    )?;
    match outcome(&log, "check/hang") {
        Ended::Failed(text) if text.contains("timeout") => {}
        other => return Err(format!("the runner did not kill a hung test: {other:?}")),
    }
    match outcome(&log, "check/quick") {
        Ended::Exited(text) if text == "exit: 7\n" => {}
        other => return Err(format!("the runner did not go on after a kill: {other:?}")),
    }
    println!("os-test runner check passed");
    Ok(())
}

/// The suites as jobs, a boot for each: the rows of its tests go into
/// `rows` when its job ends. The tests that need poll or select, or did not
/// compile, get their rows before any boot.
fn suite_jobs(
    work: &Path,
    tests: Vec<Test>,
    kernel: &crate::Artifacts,
    rows: &Rows,
    started: &Arc<OnceLock<Instant>>,
) -> Result<Vec<Job>, String> {
    let tests = Arc::new(tests);
    let mut suites: Vec<String> = Vec::new();
    for test in tests.iter() {
        if !suites.contains(&test.suite) {
            suites.push(test.suite.clone());
        }
    }
    let mut jobs = Vec::new();
    for suite in suites {
        let (work, tests, kernel) = (work.to_path_buf(), Arc::clone(&tests), kernel.clone());
        let (rows, started) = (Arc::clone(rows), Arc::clone(started));
        jobs.push(crate::jobs::job(&format!("os-test {suite}"), move || {
            let deadline = *started.get_or_init(Instant::now) + BUDGET;
            let left = |what: &str| {
                deadline
                    .checked_duration_since(Instant::now())
                    .filter(|left| !left.is_zero())
                    .ok_or_else(|| format!("os-test spent its {} s {what}", BUDGET.as_secs()))
            };
            let elfs = work.join("elfs");
            std::fs::create_dir_all(&elfs).map_err(|e| format!("{}: {e}", elfs.display()))?;
            let mut files = Vec::new();
            let mut places = Vec::new();
            for (place, test) in tests.iter().enumerate() {
                let empty = rows.lock().unwrap_or_else(PoisonError::into_inner)[place].is_none();
                if test.suite == suite && empty {
                    left(&format!("before {}", test.name))?;
                    files.push((test.name.clone(), test_elf(test, &test.built, &elfs)?));
                    places.push(place);
                }
            }
            if files.is_empty() {
                return Ok(());
            }
            let image = format!("os-test-{suite}.img");
            let (log, _) = boot(
                &kernel,
                &image,
                rootfs::os_test(&files),
                left(&format!("in {suite}"))?.min(TIMEOUT),
            )?;
            for place in places {
                let test = &tests[place];
                let (verdict, text) = match outcome(&log, &test.name) {
                    Ended::Exited(text) if passes(&work, test, &text)? => (Verdict::Pass, text),
                    Ended::Exited(text) | Ended::Failed(text) => (Verdict::Fail, text),
                };
                println!(
                    "os-test {}: {} ({})",
                    test.name,
                    verdict.name(),
                    first_line(&text)
                );
                rows.lock().unwrap_or_else(PoisonError::into_inner)[place] =
                    Some((test.name.clone(), verdict, text));
            }
            Ok(())
        }));
    }
    Ok(jobs)
}

/// The check of the runner as a job for the serial set: it reads the host's
/// time (a hung test is killed after a second).
pub fn runner_check_job() -> Job {
    crate::jobs::job("os-test runner check", || {
        if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
            crate::relibc()?;
        }
        runner_check(&build(Variant::Normal)?)
    })
}

/// `cargo xtask os-test --one NAME`: the test `NAME` alone in a boot of
/// its own, with the whole log of the boot.
pub fn run_one(name: &str) -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        crate::relibc()?;
    }
    crate::run_cmd(
        std::process::Command::new("python3").arg(crate::root().join("tools/build-os-test.py")),
    )?;
    let work = target_dir().join("os-test");
    let elfs = work.join("elfs");
    std::fs::create_dir_all(&elfs).map_err(|e| format!("{}: {e}", elfs.display()))?;
    let tests = tests_of(&work)?;
    let test = tests
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| format!("no test {name} in tests.txt"))?;
    if test.built.starts_with('!') {
        return Err(format!("{name} did not compile: {}", test.built));
    }
    let kernel = build(Variant::Normal)?;
    let file = (test.name.clone(), test_elf(test, &test.built, &elfs)?);
    let (log, _) = boot(
        &kernel,
        "os-test-one.img",
        rootfs::os_test(&[file]),
        TIMEOUT,
    )?;
    println!("{log}");
    let (verdict, text) = match outcome(&log, name) {
        Ended::Exited(text) if passes(&work, test, &text)? => (Verdict::Pass, text),
        Ended::Exited(text) | Ended::Failed(text) => (Verdict::Fail, text),
    };
    println!("os-test {name}: {}\n{text}", verdict.name());
    Ok(())
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
fn score(rows: &[Row]) -> String {
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
fn write(rows: &[Row], suite: Option<&str>) -> Result<PathBuf, String> {
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut text = format!(
        "os-test io, malloc, process, signal, pty and basic tests on relibc (commit {}): {}\n\n| test | result | outcome |\n|---|---|---|\n",
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
    let filename = suite.map_or_else(
        || "os-test.txt".to_owned(),
        |suite| format!("os-test-{}.txt", suite.replace('/', "-")),
    );
    let path = dir.join(filename);
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boot's log: the services' lines around the runner's marks.
    fn log(text: &[&str]) -> String {
        text.join("\n") + "\n"
    }

    /// The test's own lines between its marks, `exit: N` for an empty
    /// output or a status of 2 or more.
    #[test]
    fn outcome_is_what_run_sh_writes() {
        let log = log(&[
            "boot complete",
            "init: services started",
            "ramfs: ready",
            "@@os-test begin io/open",
            "pipe: ready",
            "tty: ready",
            "virtio-rng: ready",
            "entropy: seeded from the device",
            "open: EISDIR",
            "@@os-test end io/open exit 1",
            "@@os-test begin io/silent",
            "@@os-test end io/silent exit 0",
            "@@os-test begin io/aborted",
            "NULL",
            "@@os-test end io/aborted exit 134",
        ]);
        assert_eq!(
            outcome(&log, "io/open"),
            Ended::Exited("open: EISDIR\n".to_owned())
        );
        assert_eq!(
            outcome(&log, "io/silent"),
            Ended::Exited("exit: 0\n".to_owned())
        );
        assert_eq!(
            outcome(&log, "io/aborted"),
            Ended::Exited("NULL\nexit: 134\n".to_owned())
        );
    }

    /// Output with no newline before the end mark is the output as it is;
    /// a death by a signal is the shell's status 128 + N; the lines of the
    /// services and the kernel's fault line are not the test's.
    #[test]
    fn marks_leave_the_output_as_it_was() {
        let log = log(&[
            "@@os-test begin signal/raise",
            "SIGUSR1@@os-test end signal/raise exit 0",
            "@@os-test begin signal/fault",
            "partial",
            "process fault: data abort from EL0 (EC 0x24) ESR=0x92000006 FAR=0x0 ELR=0x22f244",
            "clock: tick",
            "@@os-test end signal/fault signal 11",
        ]);
        assert_eq!(
            outcome(&log, "signal/raise"),
            Ended::Exited("SIGUSR1".to_owned())
        );
        assert_eq!(
            outcome(&log, "signal/fault"),
            Ended::Exited("partial\nexit: 139\n".to_owned())
        );
    }

    /// A timeout the runner killed, a failure of the runner, a test that
    /// did not start and a log without the end of the test are FAILs,
    /// never scored by the expectations; the names of tests that begin
    /// alike are told apart.
    #[test]
    fn a_test_without_an_exit_fails() {
        let log = log(&[
            "@@os-test begin io/hung",
            "partial",
            "@@os-test end io/hung timeout",
            "@@os-test begin io/hung-twice",
            "@@os-test begin io/refused",
            "@@os-test end io/refused error spawn 2",
        ]);
        assert_eq!(
            outcome(&log, "io/hung"),
            Ended::Failed("partial\nexit: timeout\n".to_owned())
        );
        assert!(matches!(
            outcome(&log, "io/hung-twice"),
            Ended::Failed(text) if text.starts_with("timeout")
        ));
        assert_eq!(
            outcome(&log, "io/refused"),
            Ended::Failed("exit: error spawn 2\n".to_owned())
        );
        assert!(matches!(
            outcome(&log, "io/none"),
            Ended::Failed(text) if text.starts_with("timeout")
        ));
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
    fn suite_selection_preserves_directory_boundaries_and_rejects_empty() {
        let tests = |names: &[&str]| {
            names
                .iter()
                .map(|name| Test {
                    name: (*name).to_owned(),
                    suite: "unused".to_owned(),
                    test: "unused".to_owned(),
                    built: "object".to_owned(),
                })
                .collect()
        };
        let selected = select_suite(
            tests(&[
                "pty/a",
                "pty-other/b",
                "basic/termios/a",
                "basic/termios-extra/b",
            ]),
            "pty",
        )
        .unwrap();
        assert_eq!(
            selected.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["pty/a"]
        );
        let selected = select_suite(
            tests(&["basic/termios/a", "basic/termios-extra/b"]),
            "basic/termios",
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        assert!(select_suite(tests(&["pty-other/a"]), "pty").is_err());
        assert!(select_suite(tests(&[]), "basic/termios").is_err());
    }

    #[test]
    fn readiness_calls_and_explicit_groups() {
        assert!(readiness_group("basic/poll/poll"));
        assert!(readiness_group("basic/sys_select/select"));
        assert!(readiness_group("signal/ppoll-block-raise"));
        assert!(readiness_group("pty/pty-poll"));
        assert!(readiness_group("pty/pty-hup-poll"));
        assert!(!readiness_group("signal/other-poll"));
        assert!(needs_poll("int n = poll(fds, 1, 0);"));
        assert!(needs_poll("int n = ppoll(fds, 1, NULL, NULL);"));
        assert!(needs_poll("int n = select(1, &set, NULL, NULL, &tv);"));
        assert!(needs_poll(
            "int n = pselect(1, &set, NULL, NULL, NULL, NULL);"
        ));
        assert!(!needs_poll("int fd = open(path, O_RDWR);"));
        // Programs started from files run (5c), fork (5d) and pipes (5e).
        assert!(!needs_poll("execlp(argv[0], argv[0], \"2\", NULL);"));
        assert!(!needs_poll("pid_t child = fork();"));
        assert!(!needs_poll("if (pipe(fds) < 0)"));
        assert!(!needs_poll("if (pipe2(fds, O_CLOEXEC) < 0)"));
        assert!(!needs_poll(
            "posix_spawn(&pid, program, NULL, NULL, argv, environ);"
        ));
    }
}
