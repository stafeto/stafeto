// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dEQP-EGL module of VK-GL-CTS (tests/deqp, built by tools/build-deqp.py)
//! in the image of the POSIX probes. The runner lists the cases of the groups
//! it was asked for (one run of the program in `stdout-caselist` mode), splits
//! them into batches of `BATCH`, and runs each batch as one start of the
//! program: the batch is the case list file `/etc/deqp.args` names, the log
//! goes to the standard output (the program opens /dev/stdout as a copy of
//! descriptor 1), and `parse_qpa` reads it. A process that dies in the
//! middle of a batch (a crash, a hang the timeout ends) loses the case it was
//! running, which is recorded as `Crash`; the cases after it go back to the
//! list and run in the next start (`settle`).

mod baseline;
mod reference;

pub use baseline::{
    Baseline, Departure, Module, SETS, SMOKE_EXCLUDED, Set, compare, load_baseline,
    parse_departures, parse_smoke, passes, select_smoke, sets_of,
};
pub use reference::reference;

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, PIPE_STACK_SIZE, RAMFS_STACK_SIZE, Variant, build,
    qemu, rootfs, run_until, write_boot_image_files,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// The cases of one start of the program.
pub const BATCH: usize = 200;
/// The stack of the program's main thread: the framework recurses, and so
/// does the GLSL compiler of Mesa.
const DEQP_STACK_SIZE: u32 = 1024 * 1024;
/// The longest a start of the program may take.
const TIMEOUT: Duration = Duration::from_secs(1800);
const ENDED: &str = "init: deqp ended";
/// Where the data files of a module (the shader tests of the GLSL
/// conformance, textures) are in the image: the argument `--deqp-archive-dir`.
const DATA_DIR: &str = "/data";

/// The files of the baselines of Linux, the departures and the smoke list.
fn baseline_dir() -> PathBuf {
    crate::root().join("tests/deqp/baseline")
}

fn departures_file() -> PathBuf {
    crate::root().join("tests/deqp/departures.txt")
}

fn smoke_file() -> PathBuf {
    crate::root().join("tests/deqp/smoke.txt")
}

/// The lines of /etc/deqp.args of the image the next build makes.
static ARGS: Mutex<String> = Mutex::new(String::new());

/// The contents of /etc/deqp.args, for the image `boot-deqp.img` (rootfs.rs).
pub fn args_bytes() -> &'static [u8] {
    let text = ARGS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Box::leak(text.into_bytes().into_boxed_slice())
}

/// The case list file of a batch: its name in the image.
pub const CASE_FILE: &str = "/etc/deqp.cases";

/// The bytes of the case list file of the image.
pub fn cases_bytes() -> &'static [u8] {
    let text = CASES.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Box::leak(text.into_bytes().into_boxed_slice())
}

static CASES: Mutex<String> = Mutex::new(String::new());

/// The image of the probe: the services of the POSIX process probe and the
/// program of a module of the suite, which the image calls `deqp`.
pub const fn programs(module: Module) -> [ImageProgram; 9] {
    [
        ("init", "init", INIT_STACK_SIZE, &["table-deqp"]),
        ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
        ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
        (
            "posix-process-service",
            "posix-process-service",
            64 * 1024,
            &[],
        ),
        ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
        ("deqp", module.package(), DEQP_STACK_SIZE, &[]),
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
    ]
}

/// The image of dEQP-EGL (the lists the checks of the images walk).
#[cfg(test)]
pub const PROGRAMS: [ImageProgram; 9] = programs(Module::Egl);
/// The images of the other modules.
#[cfg(test)]
pub const PROGRAMS_GLES2: [ImageProgram; 9] = programs(Module::Gles2);
#[cfg(test)]
pub const PROGRAMS_GLES3: [ImageProgram; 9] = programs(Module::Gles3);
#[cfg(test)]
pub const PROGRAMS_GLES31: [ImageProgram; 9] = programs(Module::Gles31);

/// The result of one case: its path and the status code of the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseResult {
    pub name: String,
    pub status: String,
}

/// What a log holds: the cases that have a result, the case the log began
/// and never ended (the process died in it), and whether the session ended.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub results: Vec<CaseResult>,
    pub open: Option<String>,
    pub ended: bool,
}

/// The value of `StatusCode="..."` of the last `<Result` element of a line.
fn status_code(line: &str) -> Option<String> {
    let at = line.rfind("<Result StatusCode=\"")? + "<Result StatusCode=\"".len();
    let rest = &line[at..];
    Some(rest[..rest.find('"')?].to_owned())
}

/// The results of a log of the framework (the console of a batch, the lines
/// of the `qpa` format mixed with whatever else the program printed). A case
/// is `#beginTestCaseResult NAME`, the XML of its result with the last
/// `<Result StatusCode="...">`, and `#endTestCaseResult`; a case the process
/// ended with `#terminateTestCaseResult WHY` has the status WHY; a case with
/// no end before the next begin or the end of the log is `open`.
pub fn parse_qpa(lines: &[String]) -> Parsed {
    let mut parsed = Parsed::default();
    let mut current: Option<(String, Option<String>)> = None;
    for line in lines {
        if let Some(at) = line.find("#beginTestCaseResult ") {
            if let Some((name, _)) = current.take() {
                // The previous case never ended and a new one began: the
                // process was restarted by something else than this runner.
                parsed.results.push(CaseResult {
                    name,
                    status: "Crash".to_owned(),
                });
            }
            let name = line[at + "#beginTestCaseResult ".len()..].trim().to_owned();
            current = Some((name, None));
        } else if let Some(at) = line.find("#terminateTestCaseResult") {
            if let Some((name, _)) = current.take() {
                let why = line[at + "#terminateTestCaseResult".len()..].trim();
                parsed.results.push(CaseResult {
                    name,
                    status: if why.is_empty() { "Crash" } else { why }.to_owned(),
                });
            }
        } else if line.contains("#endTestCaseResult") {
            if let Some((name, status)) = current.take() {
                parsed.results.push(CaseResult {
                    name,
                    status: status.unwrap_or_else(|| "InternalError".to_owned()),
                });
            }
        } else if line.contains("#endSession") {
            parsed.ended = true;
        } else if let Some((_, status)) = current.as_mut()
            && let Some(code) = status_code(line)
        {
            *status = Some(code);
        }
    }
    parsed.open = current.map(|(name, _)| name);
    parsed
}

/// What a batch settled: the results it produced, and the cases to run again.
#[derive(Debug, PartialEq, Eq)]
pub struct Settled {
    pub results: Vec<CaseResult>,
    pub requeue: Vec<String>,
}

/// The results of a batch and the cases it leaves. A case that has a result
/// is done. The case the process died in has the result `Crash` and is not
/// run again. Every other case of the batch goes back to the list. A batch
/// that settled no case at all (the program died before its first) is an
/// error: running the same cases again would never end.
pub fn settle(batch: &[String], parsed: &Parsed) -> Result<Settled, String> {
    let in_batch: HashSet<&str> = batch.iter().map(String::as_str).collect();
    let mut results: Vec<CaseResult> = parsed
        .results
        .iter()
        .filter(|r| in_batch.contains(r.name.as_str()))
        .cloned()
        .collect();
    if let Some(open) = &parsed.open
        && in_batch.contains(open.as_str())
        && !results.iter().any(|r| &r.name == open)
    {
        results.push(CaseResult {
            name: open.clone(),
            status: "Crash".to_owned(),
        });
    }
    let done: HashSet<&str> = results.iter().map(|r| r.name.as_str()).collect();
    let requeue: Vec<String> = batch
        .iter()
        .filter(|n| !done.contains(n.as_str()))
        .cloned()
        .collect();
    if results.is_empty() {
        return Err(format!(
            "the program settled none of the {} cases of the batch (it died before the first: {:?})",
            batch.len(),
            batch.first()
        ));
    }
    Ok(Settled { results, requeue })
}

/// The names of the cases of a `stdout-caselist` run: the lines `TEST: NAME`.
pub fn parse_caselist(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| l.find("TEST: ").map(|at| l[at + 6..].trim().to_owned()))
        .filter(|n| n.starts_with("dEQP-"))
        .collect()
}

/// The counts of a set of results.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub pass: usize,
    pub fail: usize,
    pub not_supported: usize,
    pub other: usize,
}

/// Pass counts the warnings of quality and compatibility as dEQP does; fail
/// counts every status that is neither a pass nor NotSupported or Waiver.
pub fn tally(results: &[CaseResult]) -> Tally {
    let mut t = Tally::default();
    for r in results {
        match r.status.as_str() {
            "Pass" | "QualityWarning" | "CompatibilityWarning" => t.pass += 1,
            "NotSupported" => t.not_supported += 1,
            "Waiver" => t.other += 1,
            _ => t.fail += 1,
        }
    }
    t
}

/// The arguments of the program for a run: one per line.
fn args_text(module: Module, extra: &[&str]) -> String {
    let mut args = vec![
        "--deqp-log-filename=/dev/stdout".to_owned(),
        "--deqp-log-flush=enable".to_owned(),
        "--deqp-watchdog=disable".to_owned(),
    ];
    if module != Module::Egl {
        args.push(format!("--deqp-archive-dir={DATA_DIR}"));
    }
    args.extend(module.arguments().iter().map(|s| (*s).to_owned()));
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args.join("\n") + "\n"
}

/// The directory of the data files of a module in the build of dEQP.
fn data_source(module: Module) -> PathBuf {
    let name = module.name();
    crate::root()
        .join("target/deqp/build/modules")
        .join(name)
        .join(name)
}

/// The files of the directory `from` (and its directories) as files of the
/// image under `to`, in order.
fn files_under(from: &Path, to: &str, out: &mut Vec<rootfs::RootFile>) -> Result<(), String> {
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let mut entries: Vec<_> = std::fs::read_dir(from)
        .map_err(|e| format!("{}: {e}", from.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", from.display()))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = leak(format!("{to}/{name}"));
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        if kind.is_dir() {
            out.push(rootfs::RootFile {
                path,
                mode: 0o755,
                uid: 0,
                gid: 0,
                source: None,
            });
            files_under(&entry.path(), path, out)?;
        } else if kind.is_file() {
            let bytes = std::fs::read(entry.path())
                .map_err(|e| format!("{}: {e}", entry.path().display()))?;
            // The name of the file in the image: at most 32 bytes, unique.
            let file = leak(format!("dq{}", out.len()));
            out.push(rootfs::RootFile {
                path,
                mode: 0o644,
                uid: 0,
                gid: 0,
                source: Some(rootfs::Source::Bytes(
                    file,
                    Box::leak(bytes.into_boxed_slice()),
                )),
            });
        }
    }
    Ok(())
}

/// The data files of a module as files of the image: the shader tests of the
/// GLSL conformance and the images of the texture tests, under `DATA_DIR`.
fn data_files(module: Module) -> Result<Vec<rootfs::RootFile>, String> {
    if module == Module::Egl {
        return Ok(Vec::new());
    }
    let to: &'static str = Box::leak(format!("{DATA_DIR}/{}", module.name()).into_boxed_str());
    let mut files = vec![
        rootfs::RootFile {
            path: DATA_DIR,
            mode: 0o755,
            uid: 0,
            gid: 0,
            source: None,
        },
        rootfs::RootFile {
            path: to,
            mode: 0o755,
            uid: 0,
            gid: 0,
            source: None,
        },
    ];
    files_under(&data_source(module), to, &mut files)?;
    Ok(files)
}

/// One start of the program of a module with these arguments (and the case
/// file, when given); the lines of the console.
fn start(
    machine: &qemu::Machine,
    module: Module,
    args: &[&str],
    cases: &[String],
) -> Result<Vec<String>, String> {
    *ARGS.lock().unwrap_or_else(|e| e.into_inner()) = args_text(module, args);
    *CASES.lock().unwrap_or_else(|e| e.into_inner()) = cases.join("\n") + "\n";
    crate::deqp()?;
    let kernel = build(Variant::Normal)?;
    // Written afresh every time: the files of the image (the arguments, the case
    // list) change from start to start, and `build_boot_image` keeps the first.
    let image = write_boot_image_files(
        "boot-deqp.img",
        &programs(module),
        BOOT_PROFILE,
        &[],
        data_files(module)?,
    )?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let outcome = run_until(cmd, TIMEOUT, Some(ENDED), &kernel.elf)?;
    Ok(outcome.lines)
}

/// The cases of a set: the baseline's, when there is one (it holds every case
/// of the set on Linux); else one start of the program in the mode that lists
/// them.
fn list_cases(
    machine: &qemu::Machine,
    set: &Set,
    baseline: Option<&Baseline>,
) -> Result<Vec<String>, String> {
    if let Some(baseline) = baseline {
        return Ok(baseline.cases.keys().cloned().collect());
    }
    // The list of the pinned release does not change: it is kept next to its
    // source in target/deqp-src (delete the file to list again).
    let kept = crate::root()
        .join("target/deqp-src")
        .join(format!("cases-{}.txt", set.name));
    if let Ok(text) = std::fs::read_to_string(&kept) {
        let cases: Vec<String> = text.lines().map(str::to_owned).collect();
        if !cases.is_empty() {
            return Ok(cases);
        }
    }
    let pattern = format!("--deqp-case={}", set.patterns.join(","));
    let lines = start(
        machine,
        set.module,
        &["--deqp-runmode=stdout-caselist", pattern.as_str()],
        &[],
    )?;
    let cases = parse_caselist(&lines);
    if cases.is_empty() {
        return Err("the program listed no case".to_owned());
    }
    // Best effort: a list that is not kept is made again.
    let _ = std::fs::write(&kept, cases.join("\n") + "\n");
    Ok(cases)
}

/// Runs the cases in batches, restarting the program after a batch it did
/// not finish; the result of every case.
pub fn run_cases(
    machine: &qemu::Machine,
    module: Module,
    cases: Vec<String>,
) -> Result<Vec<CaseResult>, String> {
    let mut pending = cases;
    let mut results = Vec::new();
    while !pending.is_empty() {
        let take = pending.len().min(BATCH);
        let batch: Vec<String> = pending.drain(..take).collect();
        let option = format!("--deqp-caselist-file={CASE_FILE}");
        let lines = start(machine, module, &[option.as_str()], &batch)?;
        let settled = settle(&batch, &parse_qpa(&lines))?;
        println!(
            "deqp: batch of {}: {} settled, {} left for another start",
            batch.len(),
            settled.results.len(),
            settled.requeue.len()
        );
        results.extend(settled.results);
        // What the batch left goes in front, in order.
        let rest = std::mem::take(&mut pending);
        pending = settled.requeue;
        pending.extend(rest);
    }
    Ok(results)
}

/// The departures of `tests/deqp/departures.txt` (none when the file is not
/// there yet).
fn load_departures() -> Result<Vec<Departure>, String> {
    let path = departures_file();
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_departures(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Prints the comparison of a run with its baseline; an error when it found
/// a regression, a stale departure or a case the baseline does not know.
fn report(label: &str, c: &baseline::Comparison, provisional: bool) -> Result<(), String> {
    println!(
        "deqp: {label}: {} cases against the baseline of Linux{}, {} departures used",
        c.checked,
        if provisional { " (provisional)" } else { "" },
        c.departed.len()
    );
    for (case, step) in &c.departed {
        println!("deqp: departure {case} (returned by {step})");
    }
    for line in &c.regressions {
        println!("deqp: REGRESSION {line}");
    }
    for case in &c.stale {
        println!("deqp: STALE departure of {case}: it passes, drop the line");
    }
    for case in &c.unknown {
        println!("deqp: UNKNOWN to the baseline: {case}");
    }
    if c.is_ok() {
        return Ok(());
    }
    Err(format!(
        "{label}: {} regressions, {} stale departures, {} cases the baseline does not know",
        c.regressions.len(),
        c.stale.len(),
        c.unknown.len()
    ))
}

fn print_tally(label: &str, machine: &qemu::Machine, results: &[CaseResult]) {
    let t = tally(results);
    println!(
        "{label} on {}: {} cases, {} pass, {} fail, {} not supported, {} other",
        machine.name,
        results.len(),
        t.pass,
        t.fail,
        t.not_supported,
        t.other
    );
}

/// The sets of `cargo xtask deqp` with no argument: the two groups of the
/// first probe of dEQP-EGL.
const DEFAULT_SETS: [&str; 2] = ["egl.info", "egl.context"];

/// `cargo xtask deqp [SET | MODULE | all | smoke | smoke-select]...`: the
/// sets in the guest, one start of the program of the module after another,
/// each compared with its baseline of Linux and the departures. `smoke` runs
/// the cases of `tests/deqp/smoke.txt` (the job `deqp-smoke` of ci).
pub fn probe(machine: &qemu::Machine, words: &[String]) -> Result<(), String> {
    let words: Vec<String> = if words.is_empty() {
        DEFAULT_SETS.iter().map(|s| (*s).to_owned()).collect()
    } else {
        words.to_vec()
    };
    let mut failed = Vec::new();
    for word in &words {
        let outcome = match word.as_str() {
            "smoke" => smoke(machine),
            "smoke-select" => smoke_select(),
            _ => sets_of(word).and_then(|sets| {
                let mut worst = Ok(());
                for set in sets {
                    if let Err(e) = run_set(machine, set) {
                        worst = Err(e);
                    }
                }
                worst
            }),
        };
        if let Err(e) = outcome {
            failed.push(e);
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// One set in the guest.
fn run_set(machine: &qemu::Machine, set: &Set) -> Result<(), String> {
    let baseline = load_baseline(&baseline_dir(), set)?;
    let cases = list_cases(machine, set, baseline.as_ref())?;
    println!(
        "deqp: set {}: {} cases in {}",
        set.name,
        cases.len(),
        set.patterns.join(", ")
    );
    let started = std::time::Instant::now();
    let results = run_cases(machine, set.module, cases.clone())?;
    println!(
        "deqp: set {}: {} cases in {} s",
        set.name,
        results.len(),
        started.elapsed().as_secs()
    );
    for r in &results {
        println!("deqp: {} {}", r.status, r.name);
    }
    print_tally(&format!("deqp set {}", set.name), machine, &results);
    let missing: Vec<&String> = cases
        .iter()
        .filter(|c| !results.iter().any(|r| &r.name == *c))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "{} cases have no result: {missing:?}",
            missing.len()
        ));
    }
    match baseline {
        Some(b) => report(
            &format!("set {}", set.name),
            &compare(&b.cases, &cases, &results, &load_departures()?),
            b.provisional,
        ),
        None => {
            println!(
                "deqp: set {}: no baseline in tests/deqp/baseline, nothing to compare with",
                set.name
            );
            Ok(())
        }
    }
}

/// All the baselines of the sets that exist, as one map of case to status.
fn all_baselines() -> Result<(BTreeMap<String, String>, bool), String> {
    let mut all = BTreeMap::new();
    let mut provisional = false;
    for set in SETS {
        if let Some(b) = load_baseline(&baseline_dir(), set)? {
            provisional |= b.provisional;
            for (case, status) in b.cases {
                if all.insert(case.clone(), status).is_some() {
                    return Err(format!("{case} is in the baselines of two sets"));
                }
            }
        }
    }
    Ok((all, provisional))
}

/// The cases of `tests/deqp/smoke.txt`.
fn smoke_cases() -> Result<Vec<String>, String> {
    let path = smoke_file();
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(parse_smoke(&text))
}

/// `deqp-smoke`: the cases of the smoke list, every one that passes on Linux
/// must pass here.
pub fn smoke(machine: &qemu::Machine) -> Result<(), String> {
    let cases = smoke_cases()?;
    if cases.is_empty() {
        return Err("tests/deqp/smoke.txt lists no case".to_owned());
    }
    let (linux, provisional) = all_baselines()?;
    let mut results = Vec::new();
    for module in Module::ALL {
        let mine: Vec<String> = cases
            .iter()
            .filter(|c| Module::of_case(c) == Some(module))
            .cloned()
            .collect();
        if mine.is_empty() {
            continue;
        }
        let started = std::time::Instant::now();
        let done = run_cases(machine, module, mine)?;
        println!(
            "deqp: smoke {}: {} cases in {} s",
            module.name(),
            done.len(),
            started.elapsed().as_secs()
        );
        results.extend(done);
    }
    for r in &results {
        println!("deqp: {} {}", r.status, r.name);
    }
    print_tally("deqp-smoke", machine, &results);
    report(
        "smoke",
        &compare(&linux, &cases, &results, &load_departures()?),
        provisional,
    )
}

/// `cargo xtask deqp smoke-select`: the cases the smoke list would hold, from
/// the passing cases of the baselines of the sets that give cases to it.
fn smoke_select() -> Result<(), String> {
    let mut passing = BTreeSet::new();
    for set in SETS.iter().filter(|s| s.smoke) {
        if let Some(b) = load_baseline(&baseline_dir(), set)? {
            passing.extend(
                b.cases
                    .into_iter()
                    .filter(|(case, status)| {
                        passes(status) && !SMOKE_EXCLUDED.contains(&case.as_str())
                    })
                    .map(|(case, _)| case),
            );
        }
    }
    let picked = select_smoke(&passing, SMOKE_MOST);
    println!(
        "# {} cases, one of each group of the passing cases of the baselines",
        picked.len()
    );
    for case in picked {
        println!("{case}");
    }
    Ok(())
}

/// The most cases of the smoke list (the plan asks for 150 to 250).
const SMOKE_MOST: usize = 250;

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_owned).collect()
    }

    /// A log of a batch of six cases: three passed, one is NotSupported, the
    /// fifth began and the process died (no end, no end of session), the sixth
    /// never began. The console lines of the framework are mixed in.
    const CRASHED: &str = "\
Writing test log into /dev/stdout
#sessionInfo releaseName 3.2.14
#beginSession
Test case 'dEQP-EGL.info.version'..
#beginTestCaseResult dEQP-EGL.info.version
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<TestCaseResult Version=\"0.3.4\" CasePath=\"dEQP-EGL.info.version\" CaseType=\"Self-contained\">
 <Text>EGL 1.5</Text>
 <Result StatusCode=\"Pass\">Pass</Result>
</TestCaseResult>
#endTestCaseResult
  Pass (Pass)
#beginTestCaseResult dEQP-EGL.info.vendor
<TestCaseResult Version=\"0.3.4\" CasePath=\"dEQP-EGL.info.vendor\" CaseType=\"Self-contained\">
 <Result StatusCode=\"QualityWarning\">Quality</Result>
</TestCaseResult>
#endTestCaseResult
#beginTestCaseResult dEQP-EGL.info.client_extensions
<TestCaseResult Version=\"0.3.4\" CasePath=\"dEQP-EGL.info.client_extensions\" CaseType=\"Self-contained\">
 <Result StatusCode=\"Pass\">Pass</Result>
</TestCaseResult>
#endTestCaseResult
#beginTestCaseResult dEQP-EGL.functional.create_context.rgba8888_window
<TestCaseResult Version=\"0.3.4\" CasePath=\"dEQP-EGL.functional.create_context.rgba8888_window\" CaseType=\"Self-contained\">
 <Result StatusCode=\"NotSupported\">No matching config</Result>
</TestCaseResult>
#endTestCaseResult
#beginTestCaseResult dEQP-EGL.functional.create_context.rgb565_window
<TestCaseResult Version=\"0.3.4\" CasePath=\"dEQP-EGL.functional.create_context.rgb565_window\" CaseType=\"Self-contained\">
 <Text>making the context
init: deqp-egl ended: signal 11, not restarted
";

    fn batch() -> Vec<String> {
        [
            "dEQP-EGL.info.version",
            "dEQP-EGL.info.vendor",
            "dEQP-EGL.info.client_extensions",
            "dEQP-EGL.functional.create_context.rgba8888_window",
            "dEQP-EGL.functional.create_context.rgb565_window",
            "dEQP-EGL.functional.create_context.rgb888_window",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    #[test]
    fn a_log_with_a_crash_in_the_middle_of_a_batch() {
        let parsed = parse_qpa(&lines(CRASHED));
        assert_eq!(parsed.results.len(), 4);
        assert_eq!(parsed.results[1].status, "QualityWarning");
        assert_eq!(parsed.results[3].status, "NotSupported");
        assert_eq!(
            parsed.open.as_deref(),
            Some("dEQP-EGL.functional.create_context.rgb565_window")
        );
        assert!(!parsed.ended);
        let settled = settle(&batch(), &parsed).unwrap();
        // The crashed case has its result and the case after it is run again.
        assert_eq!(settled.results.len(), 5);
        assert_eq!(settled.results[4].status, "Crash");
        assert_eq!(
            settled.requeue,
            ["dEQP-EGL.functional.create_context.rgb888_window"]
        );
        // Every case of the batch is accounted for: a result or the list.
        assert_eq!(settled.results.len() + settled.requeue.len(), batch().len());
    }

    /// The console of a real batch of 27 cases (the groups `info` and
    /// `create_context`) on stafeto in QEMU, as xtask read it.
    const RECORDED: &str = include_str!("../../tests/deqp/recorded/egl-batch.log");

    fn recorded_cases() -> Vec<String> {
        parse_qpa(&lines(RECORDED))
            .results
            .into_iter()
            .map(|r| r.name)
            .collect()
    }

    /// The recorded log cut where a process that died would have left it:
    /// the case `name` began, wrote a line of its result, and nothing more.
    fn crashed_in(name: &str) -> Vec<String> {
        let all = lines(RECORDED);
        let begin = all
            .iter()
            .position(|l| l.ends_with(&format!("#beginTestCaseResult {name}")))
            .unwrap();
        let mut cut = all[..begin + 3].to_vec();
        cut.push("init: deqp-egl ended: signal 11, not restarted".to_owned());
        cut
    }

    #[test]
    fn the_recorded_batch_has_twenty_seven_results() {
        let parsed = parse_qpa(&lines(RECORDED));
        assert!(parsed.ended);
        assert_eq!(parsed.open, None);
        assert_eq!(parsed.results.len(), 27);
        let t = tally(&parsed.results);
        assert_eq!((t.pass, t.fail, t.not_supported, t.other), (12, 0, 15, 0));
        assert_eq!(parsed.results[0].name, "dEQP-EGL.info.version");
        assert_eq!(parsed.results[0].status, "Pass");
        assert_eq!(parsed.results[5].status, "NotSupported");
        let batch = recorded_cases();
        let settled = settle(&batch, &parsed).unwrap();
        assert!(settled.requeue.is_empty());
    }

    #[test]
    fn the_recorded_batch_cut_in_a_case_loses_no_case() {
        let batch = recorded_cases();
        let name = "dEQP-EGL.functional.create_context.rgba4444_depth_stencil";
        let at = batch.iter().position(|n| n == name).unwrap();
        let parsed = parse_qpa(&crashed_in(name));
        assert!(!parsed.ended);
        assert_eq!(parsed.open.as_deref(), Some(name));
        assert_eq!(parsed.results.len(), at);
        let settled = settle(&batch, &parsed).unwrap();
        // The cases before it keep their results, it is a Crash, and every
        // case after it is left for the next start.
        assert_eq!(settled.results.len(), at + 1);
        assert_eq!(settled.results[at].status, "Crash");
        assert_eq!(settled.requeue, batch[at + 1..].to_vec());
        assert_eq!(settled.results.len() + settled.requeue.len(), batch.len());
        // The next start settles the rest: nothing is run twice, nothing is lost.
        let next = settle(&settled.requeue, &parse_qpa(&lines(RECORDED))).unwrap();
        assert!(next.requeue.is_empty());
        let mut names: Vec<&str> = settled
            .results
            .iter()
            .chain(&next.results)
            .map(|r| r.name.as_str())
            .collect();
        names.sort_unstable();
        let mut want: Vec<&str> = batch.iter().map(String::as_str).collect();
        want.sort_unstable();
        assert_eq!(names, want);
    }

    #[test]
    fn a_batch_that_ended_leaves_nothing() {
        let text = "\
#beginSession
#beginTestCaseResult dEQP-EGL.info.version
 <Result StatusCode=\"Pass\">Pass</Result>
#endTestCaseResult
#beginTestCaseResult dEQP-EGL.info.vendor
 <Result StatusCode=\"Fail\">no</Result>
#endTestCaseResult
#endSession
";
        let parsed = parse_qpa(&lines(text));
        assert!(parsed.ended);
        assert_eq!(parsed.open, None);
        let two: Vec<String> = batch().into_iter().take(2).collect();
        let settled = settle(&two, &parsed).unwrap();
        assert!(settled.requeue.is_empty());
        let t = tally(&settled.results);
        assert_eq!((t.pass, t.fail, t.not_supported), (1, 1, 0));
    }

    #[test]
    fn a_terminated_case_has_the_status_of_the_log() {
        let text = "\
#beginTestCaseResult dEQP-EGL.info.version
#terminateTestCaseResult Timeout
";
        let parsed = parse_qpa(&lines(text));
        assert_eq!(parsed.results[0].status, "Timeout");
        assert_eq!(parsed.open, None);
    }

    #[test]
    fn a_program_that_died_before_its_first_case_is_an_error() {
        let parsed = parse_qpa(&lines("init: deqp-egl ended: signal 11, not restarted\n"));
        assert!(settle(&batch(), &parsed).is_err());
    }

    #[test]
    fn cases_outside_the_batch_are_ignored() {
        let text = "\
#beginTestCaseResult dEQP-EGL.other.case
 <Result StatusCode=\"Pass\">Pass</Result>
#endTestCaseResult
#beginTestCaseResult dEQP-EGL.info.version
 <Result StatusCode=\"Pass\">Pass</Result>
#endTestCaseResult
";
        let settled = settle(&batch(), &parse_qpa(&lines(text))).unwrap();
        assert_eq!(settled.results.len(), 1);
        assert_eq!(settled.requeue.len(), batch().len() - 1);
    }

    #[test]
    fn the_case_list_is_the_test_lines() {
        let listed = parse_caselist(&lines(
            "GROUP: dEQP-EGL.info\nTEST: dEQP-EGL.info.version\nTEST: dEQP-EGL.info.vendor\nfoo\n",
        ));
        assert_eq!(listed, ["dEQP-EGL.info.version", "dEQP-EGL.info.vendor"]);
    }

    #[test]
    fn the_arguments_are_one_a_line() {
        let option = format!("--deqp-caselist-file={CASE_FILE}");
        let text = args_text(Module::Egl, &[option.as_str()]);
        assert!(text.ends_with(&format!("{option}\n")));
        assert!(text.lines().all(|l| l.starts_with("--deqp-")));
    }

    /// The files of tests/deqp: the baselines of Linux, the smoke list and the
    /// departures agree with each other and with the sets of the runner.
    #[test]
    fn the_files_of_the_comparison_agree() {
        let mut linux = BTreeMap::new();
        for set in SETS {
            if let Some(b) = load_baseline(&baseline_dir(), set).unwrap() {
                for case in b.cases.keys() {
                    assert!(
                        set.patterns.iter().any(|p| {
                            let prefix = p.strip_suffix('*').unwrap_or(p);
                            case.starts_with(prefix)
                        }),
                        "{case} is not in the patterns of {}",
                        set.name
                    );
                }
                linux.extend(b.cases);
            }
        }
        let smoke = smoke_cases().unwrap();
        assert!(
            (150..=250).contains(&smoke.len()),
            "{} smoke cases",
            smoke.len()
        );
        assert!(smoke.iter().all(|c| !SMOKE_EXCLUDED.contains(&c.as_str())));
        let unique: BTreeSet<&String> = smoke.iter().collect();
        assert_eq!(unique.len(), smoke.len(), "a case twice in smoke.txt");
        for case in &smoke {
            let status = linux
                .get(case)
                .unwrap_or_else(|| panic!("{case}: no baseline"));
            assert!(passes(status), "{case} is {status} on Linux");
        }
        for d in load_departures().unwrap() {
            if d.pattern.contains('*') {
                assert!(
                    linux.keys().any(|c| baseline::glob(&d.pattern, c)),
                    "{} matches no case of the baselines",
                    d.pattern
                );
            } else {
                let status = linux
                    .get(&d.pattern)
                    .unwrap_or_else(|| panic!("{}: no baseline", d.pattern));
                assert!(
                    passes(status),
                    "{} is {status} on Linux: no departure",
                    d.pattern
                );
            }
        }
    }
}
