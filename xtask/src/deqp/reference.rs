// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask deqp-reference SET...`: the baseline of dEQP on Linux (plan
//! G8, 7.3). The same Mesa and the same VK-GL-CTS as the guest has are built
//! for the machine (`tools/build-deqp-reference.py`), the cases of the sets
//! run in batches as the guest runs them (`parse_qpa`, `settle`), and the
//! status of every case goes to `target/deqp-reference/baseline/<set>.txt` and
//! into the log between two marker lines, where it can be copied from. It runs
//! on arm64 Linux only (a runner of probe.yml).

use super::baseline::{Module, Set, Target, format_baseline, sets_of};
use super::{BATCH, CaseResult, parse_caselist, parse_qpa, settle, tally};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The longest a start of a program of dEQP may take.
const BATCH_TIMEOUT: Duration = Duration::from_secs(25 * 60);
/// The X server of the target `x11_egl`.
const DISPLAY: &str = ":99";

fn work() -> PathBuf {
    crate::root().join("target/deqp-reference")
}

/// The packages the build and the runs need on an Ubuntu runner (on top of the
/// ones of the setup of ci): the headers of X11 and XCB for the EGL platform
/// of Mesa and the target `x11_egl`, and the X server of the runs.
const APT_PACKAGES: &[&str] = &[
    "cmake",
    "xvfb",
    "libx11-dev",
    "libxext-dev",
    "libx11-xcb-dev",
    "libxcb1-dev",
    "libxcb-dri3-dev",
    "libxcb-present-dev",
    "libxcb-xfixes0-dev",
    "libxcb-shm0-dev",
    "libxcb-sync-dev",
    "libxcb-randr0-dev",
    "libxshmfence-dev",
    "libxrandr-dev",
    "libxfixes-dev",
];

fn install_packages() -> Result<(), String> {
    let wanted = std::env::var("DEQP_REFERENCE_APT").is_ok_and(|v| v == "1")
        || std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");
    if !wanted {
        return Ok(());
    }
    let sudo = Command::new("sudo")
        .arg("true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    let mut apt = if sudo {
        let mut c = Command::new("sudo");
        c.arg("apt-get");
        c
    } else {
        Command::new("apt-get")
    };
    apt.args(["install", "-y", "--no-install-recommends"])
        .args(APT_PACKAGES);
    crate::run_cmd(&mut apt)
}

/// What the build script wrote: the versions in the header of a baseline.
fn versions() -> Result<String, String> {
    let path = work().join("versions.txt");
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The binary of a module in the tree of a target and the directory it runs
/// in (its data files are there).
fn binary(target: Target, module: Module) -> (PathBuf, PathBuf) {
    let dir = work()
        .join(format!("cts-{}", target.cmake_name()))
        .join("modules")
        .join(module.name());
    (dir.join(module.package()), dir)
}

/// The directory of `libEGL.so` in the install prefix of Mesa for a target
/// (the prefix has `lib` or `lib/<triplet>`).
fn mesa_lib(target: Target) -> Result<PathBuf, String> {
    let variant = if target == Target::X11Egl {
        "x11"
    } else {
        "surfaceless"
    };
    let prefix = work().join(format!("mesa-{variant}")).join("prefix");
    let mut candidates = vec![prefix.join("lib")];
    if let Ok(entries) = std::fs::read_dir(prefix.join("lib")) {
        let mut triplets: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        triplets.sort();
        candidates.extend(triplets);
    }
    candidates
        .into_iter()
        .find(|dir| dir.join("libEGL.so").exists() || dir.join("libEGL.so.1").exists())
        .ok_or_else(|| format!("no libEGL.so under {}", prefix.display()))
}

/// The environment of a run of a module: Mesa's libraries, the platform of
/// EGL, and the X display for the target of X11.
fn environment(target: Target) -> Result<Vec<(&'static str, String)>, String> {
    let lib = mesa_lib(target)?;
    let mut env = vec![
        ("LD_LIBRARY_PATH", lib.display().to_string()),
        ("MESA_SHADER_CACHE_DISABLE", "true".to_owned()),
        ("LIBGL_ALWAYS_SOFTWARE", "true".to_owned()),
    ];
    if target == Target::X11Egl {
        env.push(("EGL_PLATFORM", "x11".to_owned()));
        env.push(("DISPLAY", DISPLAY.to_owned()));
    } else {
        env.push(("EGL_PLATFORM", "surfaceless".to_owned()));
    }
    Ok(env)
}

/// Runs a command to its end or kills it at the deadline; the text of its
/// standard output. The log of the framework goes to a file the arguments
/// name, so the standard output holds the case list or the console only.
fn run_limited(mut cmd: Command, limit: Duration) -> Result<String, String> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("{cmd:?}: {e}"))?;
    let started = Instant::now();
    // The output is read by a thread so a full pipe never stops the program.
    let mut out = child.stdout.take().ok_or("no standard output")?;
    let reader = std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = std::io::Read::read_to_end(&mut out, &mut text);
        text
    });
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(_) => break,
            None if started.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                println!("deqp-reference: killed a start after {} s", limit.as_secs());
                break;
            }
            None => std::thread::sleep(Duration::from_millis(500)),
        }
    }
    let bytes = reader.join().map_err(|_| "the reader of the output died")?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The X server of the target `x11_egl`, stopped when the value goes.
struct XServer(Child);

impl XServer {
    fn start() -> Result<XServer, String> {
        let child = Command::new("Xvfb")
            .args([DISPLAY, "-screen", "0", "1280x1024x24", "-nolisten", "tcp"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Xvfb: {e}"))?;
        let socket = Path::new("/tmp/.X11-unix/X99");
        for _ in 0..50 {
            if socket.exists() {
                return Ok(XServer(child));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let mut server = XServer(child);
        let _ = server.0.kill();
        Err("Xvfb did not make its socket".to_owned())
    }
}

impl Drop for XServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The cases of a set on this machine: one start of the module's program that
/// lists them.
fn list(set: &Set, env: &[(&str, String)]) -> Result<Vec<String>, String> {
    let (program, dir) = binary(set.target, set.module);
    let mut cmd = Command::new(&program);
    cmd.current_dir(&dir)
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .arg("--deqp-runmode=stdout-caselist")
        .arg("--deqp-log-filename=/dev/null")
        .args(set.module.arguments())
        .arg(format!("--deqp-case={}", set.patterns.join(",")));
    let text = run_limited(cmd, BATCH_TIMEOUT)?;
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let cases = parse_caselist(&lines);
    if cases.is_empty() {
        return Err(format!("{} lists no case", set.name));
    }
    Ok(cases)
}

/// The cases in batches, one start each, as the guest runs them; the status of
/// every case.
fn run_set(
    set: &Set,
    cases: Vec<String>,
    env: &[(&str, String)],
) -> Result<Vec<CaseResult>, String> {
    let (program, dir) = binary(set.target, set.module);
    let scratch = work().join("run");
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let list_file = scratch.join("cases.txt");
    let log_file = scratch.join("log.qpa");
    let mut pending = cases;
    let mut results = Vec::new();
    while !pending.is_empty() {
        let take = pending.len().min(BATCH);
        let batch: Vec<String> = pending.drain(..take).collect();
        std::fs::write(&list_file, batch.join("\n") + "\n").map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&log_file);
        let mut cmd = Command::new(&program);
        cmd.current_dir(&dir)
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .arg(format!("--deqp-caselist-file={}", list_file.display()))
            .arg(format!("--deqp-log-filename={}", log_file.display()))
            .arg("--deqp-log-flush=enable")
            .arg("--deqp-watchdog=disable")
            .args(set.module.arguments());
        run_limited(cmd, BATCH_TIMEOUT)?;
        let log = std::fs::read_to_string(&log_file).unwrap_or_default();
        let lines: Vec<String> = log.lines().map(str::to_owned).collect();
        let settled = settle(&batch, &parse_qpa(&lines))?;
        println!(
            "deqp-reference: {}: batch of {}: {} settled, {} left for another start",
            set.name,
            batch.len(),
            settled.results.len(),
            settled.requeue.len()
        );
        results.extend(settled.results);
        let rest = std::mem::take(&mut pending);
        pending = settled.requeue;
        pending.extend(rest);
    }
    Ok(results)
}

/// The lines at the head of a baseline file.
fn header(
    set: &Set,
    note: Option<&str>,
    seconds: u64,
    results: &[CaseResult],
) -> Result<Vec<String>, String> {
    let t = tally(results);
    let mut lines = Vec::new();
    if let Some(note) = note {
        lines.push(format!("provisional: {note}"));
    }
    lines.push(format!(
        "dEQP baseline of the set {} (cargo xtask deqp-reference {})",
        set.name, set.name
    ));
    lines.push(format!(
        "module {}, platform {}, patterns {}",
        set.module.package(),
        set.target.cmake_name(),
        set.patterns.join(" ")
    ));
    for line in versions()?.lines() {
        lines.push(line.to_owned());
    }
    let uname = Command::new("uname").arg("-srm").output().ok();
    if let Some(out) = uname {
        lines.push(format!(
            "machine {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ));
    }
    lines.push(format!("arguments {}", set.module.arguments().join(" ")));
    lines.push(format!(
        "{} cases: {} pass, {} fail, {} not supported, {} other, in {seconds} s",
        results.len(),
        t.pass,
        t.fail,
        t.not_supported,
        t.other
    ));
    Ok(lines)
}

/// What the command line holds: the sets and the options.
pub struct Plan {
    pub sets: Vec<&'static Set>,
    /// Skip the build (the trees of an earlier run are there).
    pub no_build: bool,
    /// Copy the files into `tests/deqp/baseline` too.
    pub write: bool,
    /// The text of a `provisional:` line, when the run is not a probe of a runner.
    pub note: Option<String>,
}

pub fn parse_plan(words: &[String]) -> Result<Plan, String> {
    let mut plan = Plan {
        sets: Vec::new(),
        no_build: false,
        write: false,
        note: None,
    };
    let mut words = words.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--no-build" => plan.no_build = true,
            "--write" => plan.write = true,
            "--provisional" => {
                plan.note = Some(
                    words
                        .next()
                        .ok_or("--provisional takes the text of a line")?
                        .replace('_', " "),
                );
            }
            other => {
                for set in sets_of(other)? {
                    if !plan.sets.iter().any(|s| s.name == set.name) {
                        plan.sets.push(set);
                    }
                }
            }
        }
    }
    if plan.sets.is_empty() {
        return Err(
            "name the sets to run: cargo xtask deqp-reference egl.info gles2.basic ...".to_owned(),
        );
    }
    Ok(plan)
}

/// The arguments of the build script: `TARGET:MODULE,MODULE` for each target
/// the sets need.
fn build_arguments(sets: &[&Set]) -> Vec<String> {
    let mut args = Vec::new();
    for target in [Target::Surfaceless, Target::Nullws, Target::X11Egl] {
        let mut modules: Vec<&str> = Vec::new();
        for set in sets.iter().filter(|s| s.target == target) {
            if !modules.contains(&set.module.name()) {
                modules.push(set.module.name());
            }
        }
        if !modules.is_empty() {
            args.push(format!("{}:{}", target.cmake_name(), modules.join(",")));
        }
    }
    args
}

pub fn reference(words: &[String]) -> Result<(), String> {
    if !(cfg!(target_os = "linux") && cfg!(target_arch = "aarch64")) {
        return Err(
            "deqp-reference runs on arm64 Linux only (probe.yml: command=deqp-reference SET)"
                .to_owned(),
        );
    }
    let plan = parse_plan(words)?;
    install_packages()?;
    let out = work().join("baseline");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    // A target that does not build costs its sets, and the others still run.
    let mut failures: Vec<String> = Vec::new();
    let mut built: Vec<Target> = Vec::new();
    for argument in build_arguments(&plan.sets) {
        let target = argument.split(':').next().unwrap_or_default().to_owned();
        let kind = [Target::Surfaceless, Target::Nullws, Target::X11Egl]
            .into_iter()
            .find(|t| t.cmake_name() == target);
        let Some(kind) = kind else { continue };
        if plan.no_build {
            built.push(kind);
            continue;
        }
        let mut script = crate::build_script(crate::root().join("tools/build-deqp-reference.py"));
        script.arg(&argument);
        match crate::run_cmd(&mut script) {
            Ok(()) => built.push(kind),
            Err(e) => failures.push(format!("the build of {argument}: {e}")),
        }
    }
    let wants_x11 = plan.sets.iter().any(|s| s.target == Target::X11Egl);
    let _server = if wants_x11 && built.contains(&Target::X11Egl) {
        Some(XServer::start()?)
    } else {
        None
    };
    for set in &plan.sets {
        if !built.contains(&set.target) {
            failures.push(format!(
                "{}: its platform {} did not build",
                set.name,
                set.target.cmake_name()
            ));
            continue;
        }
        match one_set(set, &plan, &out) {
            Ok(()) => {}
            Err(e) => failures.push(format!("{}: {e}", set.name)),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn one_set(set: &Set, plan: &Plan, out: &Path) -> Result<(), String> {
    let env = environment(set.target)?;
    let started = Instant::now();
    let cases = list(set, &env)?;
    println!("deqp-reference: {}: {} cases", set.name, cases.len());
    let results = run_set(set, cases, &env)?;
    let seconds = started.elapsed().as_secs();
    let text = format_baseline(
        &header(set, plan.note.as_deref(), seconds, &results)?,
        &results,
    );
    let file = out.join(format!("{}.txt", set.name));
    std::fs::write(&file, &text).map_err(|e| format!("{}: {e}", file.display()))?;
    if plan.write {
        let kept = crate::root()
            .join("tests/deqp/baseline")
            .join(format!("{}.txt", set.name));
        std::fs::create_dir_all(kept.parent().unwrap_or(Path::new(".")))
            .map_err(|e| e.to_string())?;
        std::fs::write(&kept, &text).map_err(|e| format!("{}: {e}", kept.display()))?;
    }
    // The file in the log, between two lines to cut it out by.
    println!("==== BEGIN tests/deqp/baseline/{}.txt ====", set.name);
    print!("{text}");
    println!("==== END tests/deqp/baseline/{}.txt ====", set.name);
    println!(
        "deqp-reference: {}: {} cases in {seconds} s",
        set.name,
        results.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_plan_takes_sets_modules_and_options() {
        let plan = parse_plan(&words(&["--write", "egl.info", "gles3", "egl.info"])).unwrap();
        assert!(plan.write && !plan.no_build);
        let names: Vec<&str> = plan.sets.iter().map(|s| s.name).collect();
        assert_eq!(names[0], "egl.info");
        assert!(names.contains(&"gles3.basic"));
        assert_eq!(names.iter().filter(|n| **n == "egl.info").count(), 1);
        let plan = parse_plan(&words(&[
            "--provisional",
            "made_in_a_container",
            "egl.info",
        ]))
        .unwrap();
        assert_eq!(plan.note.as_deref(), Some("made in a container"));
        assert!(parse_plan(&words(&[])).is_err());
        assert!(parse_plan(&words(&["--write"])).is_err());
        assert!(parse_plan(&words(&["nope"])).is_err());
    }

    #[test]
    fn the_build_gets_each_target_with_its_modules() {
        let plan = parse_plan(&words(&["egl", "gles2.basic", "gles3.basic"])).unwrap();
        assert_eq!(
            build_arguments(&plan.sets),
            ["surfaceless:gles2,gles3", "nullws:egl", "x11_egl:egl"]
        );
        let plan = parse_plan(&words(&["egl.info"])).unwrap();
        assert_eq!(build_arguments(&plan.sets), ["nullws:egl"]);
    }
}
