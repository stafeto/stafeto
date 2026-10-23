// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask ci`: the checks of a change, run to the end and reported
//! together.
//!
//! The checks are steps. Every step runs even when an earlier one failed,
//! except a step whose builds failed: that one is skipped and says which
//! step it waited for. The run ends with a summary of the steps (outcome,
//! time, first line of the reason) and fails when any step failed.
//!
//! `--group NAME` runs one part of the steps, so that the jobs of a CI
//! workflow can run the parts on machines of their own; no `--group` runs
//! them all. Every guest probe belongs to exactly one group (a test
//! checks that the groups together are the whole list). The `build` group
//! builds what the other groups need and the others rebuild nothing that
//! it left up to date.

use std::process::Command;
use std::time::{Duration, Instant};

use super::{Variant, jobs};

/// Groups of the guest probes, equal in expected time.
const GUEST_GROUPS: usize = 3;
/// Parts of the Open POSIX run, equal in expected time.
const OPEN_POSIX_PARTS: usize = 3;

/// The groups, in the order of a run without `--group`.
pub fn groups() -> Vec<String> {
    let mut all: Vec<String> = ["build", "host", "kernel", "os-test"]
        .map(str::to_owned)
        .to_vec();
    all.extend((1..=OPEN_POSIX_PARTS).map(|n| format!("open-posix-{n}")));
    all.extend((1..=GUEST_GROUPS).map(|n| format!("guests-{n}")));
    all
}

const RELIBC: &str = "relibc";
const BASE: &str = "BusyBox and base packages";
const ADDONS: &str = "add-on packages";
const KERNELS: &str = "kernel images";
const IMAGES: &str = "boot images";
const OS_TEST_OBJECTS: &str = "os-test objects";
const OPEN_POSIX_OBJECTS: &str = "Open POSIX objects";

/// What every boot needs built.
const BOOT_NEEDS: [&str; 5] = [RELIBC, BASE, ADDONS, KERNELS, IMAGES];

struct Step {
    name: String,
    group: String,
    needs: Vec<&'static str>,
    run: Box<dyn FnOnce() -> Result<(), String>>,
}

fn step(
    group: &str,
    name: &str,
    needs: &[&'static str],
    run: impl FnOnce() -> Result<(), String> + 'static,
) -> Step {
    Step {
        name: name.to_owned(),
        group: group.to_owned(),
        needs: needs.to_vec(),
        run: Box::new(run),
    }
}

/// The lints of `ci_lints`: each one runs, the failed ones are named at the
/// end.
#[derive(Default)]
pub struct Lints {
    total: usize,
    failed: Vec<String>,
}

impl Lints {
    pub fn lint(&mut self, cmd: &mut Command) {
        let args: Vec<String> = cmd
            .get_args()
            .take_while(|a| *a != "--")
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let mut label = args.join(" ");
        if label.len() > 90 {
            label.truncate(label.floor_char_boundary(90));
            label.push_str("...");
        }
        self.total += 1;
        if let Err(e) = super::run_cmd(cmd) {
            println!("== FAILED lint: {label}: {e}");
            self.failed.push(label);
        }
    }

    pub fn finish(self) -> Result<(), String> {
        if self.failed.is_empty() {
            return Ok(());
        }
        Err(format!(
            "{} of {} lints failed: {}",
            self.failed.len(),
            self.total,
            self.failed.join("; ")
        ))
    }
}

/// The jobs of the boots that are not os-test's, split by their group:
/// the quick checks of the kernel and the images, and the probes of the
/// services and of the POSIX layer, shared by `GUEST_GROUPS` groups.
struct Split {
    kernel: Vec<String>,
    guests: Vec<Vec<String>>,
}

/// Expected seconds of the probes, from a run on the CI machine. A probe
/// not in the table counts as `DEFAULT_WEIGHT`.
const WEIGHTS: &[(&str, u32)] = &[
    ("ext4ro", 2),
    ("ramfs", 10),
    ("posix-abi", 26),
    ("posix-orphans", 11),
    ("posix-threads", 63),
    ("posix-cancel-input", 28),
    ("posix-shared", 15),
    ("posix-input", 19),
    ("posix-interrupt", 14),
    ("posix-tty", 22),
    ("posix-tty-control-steps", 29),
    ("relibc-hello", 23),
    ("relibc-threads", 23),
    ("posix-files", 29),
    ("posix-files steps", 31),
    ("posix-procs", 69),
    ("posix-procs EL2", 52),
    ("posix-map EL2", 14),
    ("posix-interrupt EL2", 10),
    ("posix-spawn-churn", 43),
    ("posix-map", 10),
    ("posix-resources", 14),
    ("posix-sync", 10),
    ("posix-math", 10),
    ("posix-park", 15),
    ("posix-fifo", 26),
    ("posix-fifo steps", 33),
    ("posix-lifetimes", 41),
    ("posix-lock-ring", 26),
    ("posix-lock-core", 11),
    ("posix-lock-pages", 25),
    ("posix-lock-queue-core", 24),
    ("posix-jobs", 18),
    ("loader-channels", 19),
    ("posix-poll", 26),
    ("posix-sock", 25),
    ("posix-sock-steps", 11),
    ("posix-ipc", 12),
    ("posix-ipc-steps", 12),
    ("posix-pty", 12),
    ("posix-pty-steps", 18),
    ("busybox", 17),
    ("ash", 17),
    ("ash-dialog", 80),
    ("nano-dialog", 22),
    ("htop-dialog", 3),
    ("cpus-dialog smp 1", 20),
    ("cpus-dialog smp 4", 30),
    ("ncdu-dialog", 3),
    ("ash-shell-exit", 1),
    ("bash-shell-exit", 5),
    ("bash-dialog", 41),
    ("ls", 8),
    ("rtbench-short", 49),
    ("boot 512M GICv2", 1),
    ("boot 512M GICv3", 1),
    ("boot EL2 GICv2", 1),
    ("boot EL2 GICv3", 1),
    ("boot 2G", 1),
    ("smp 4 GICv2", 2),
    ("smp 4 GICv3", 2),
    ("smp 4 EL2 GICv2", 2),
    ("smp 4 EL2 GICv3", 2),
    ("smp 4 CPU_ON refused", 2),
    ("smp 4 window", 2),
    ("posix-threads smp 4", 40),
    ("posix-procs smp 4", 60),
    ("relibc-hello smp 4", 5),
    ("relibc-threads smp 4", 15),
    ("posix-sync smp 4", 6),
    ("posix-lock-core smp 4", 10),
    ("posix-lock-queue-core smp 4", 10),
    ("ramfs smp 4", 5),
    ("smp 4 asid", 10),
    ("smp 4 probes GICv2", 25),
    ("smp 4 probes GICv3", 25),
    ("smp 4 probes EL2 GICv2", 25),
    ("smp 4 probes EL2 GICv3", 25),
    ("smp 4 checks", 25),
    ("console dialog 512M", 2),
    ("trace dialog 512M", 4),
    ("console dialog GICv3", 6),
    ("bad boot images", 1),
    ("init fault", 1),
    ("panic log", 1),
    ("fault report", 4),
    ("stack overflow", 9),
    ("test build symbols", 4),
    ("strict panic", 5),
    ("no u128 division", 4),
    ("shipping init", 1),
    ("init tests 512M icount", 2),
    ("init tests 2G icount", 2),
    ("service tests 512M", 3),
    ("service tests GICv3", 3),
    ("bad tables", 1),
    ("kernel tests 512M", 1),
    ("kernel tests 2G", 1),
    ("kernel tests GICv3", 1),
    ("kernel tests EL2", 1),
    ("kernel tests smp 4", 2),
    ("kernel tests 512M icount", 1),
    ("kernel tests 2G icount", 1),
    ("tty", 10),
    ("entropy", 6),
    ("posix-random", 19),
];
const DEFAULT_WEIGHT: u32 = 20;

/// The probes that take a few seconds each: boots of the kernel's own
/// tests, of the images and of their faults.
const KERNEL_PREFIXES: &[&str] = &[
    "boot ",
    "smp ",
    "console dialog",
    "trace dialog",
    "bad ",
    "init fault",
    "panic log",
    "fault report",
    "stack overflow",
    "test build symbols",
    "strict panic",
    "no u128 division",
    "shipping init",
    "init tests",
    "service tests",
    "kernel tests",
];

fn weight(name: &str) -> u32 {
    WEIGHTS
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(DEFAULT_WEIGHT, |(_, w)| *w)
}

/// The names of the boots of `ci` outside os-test, in their order, split:
/// longest first into the group with the least expected time.
fn split(names: &[String]) -> Split {
    let (kernel, rest): (Vec<&String>, Vec<&String>) = names
        .iter()
        .partition(|n| KERNEL_PREFIXES.iter().any(|p| n.starts_with(p)));
    let mut by_weight = rest.clone();
    by_weight.sort_by_key(|n| (std::cmp::Reverse(weight(n)), (*n).clone()));
    let mut load = [0u32; GUEST_GROUPS];
    let mut guests: Vec<Vec<String>> = vec![Vec::new(); GUEST_GROUPS];
    for name in by_weight {
        let at = (0..GUEST_GROUPS).min_by_key(|&g| (load[g], g)).unwrap_or(0);
        load[at] += weight(name);
        guests[at].push(name.clone());
    }
    // Inside a group the probes keep the order of the list.
    for group in &mut guests {
        group.sort_by_key(|n| rest.iter().position(|r| *r == n));
    }
    Split {
        kernel: kernel.into_iter().cloned().collect(),
        guests,
    }
}

/// The names of the probes of the kernel group.
pub fn kernel_boot_names() -> Vec<String> {
    split(&all_boot_names()).kernel
}

fn all_boot_names() -> Vec<String> {
    super::boot_jobs(Vec::new())
        .iter()
        .map(|j| j.name().to_owned())
        .collect()
}

fn only(list: Vec<jobs::Job>, names: &[String]) -> Vec<jobs::Job> {
    list.into_iter()
        .filter(|j| names.iter().any(|n| n == j.name()))
        .collect()
}

fn all_steps(njobs: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    // What the other groups need, built once.
    steps.push(step("build", RELIBC, &[], super::relibc));
    steps.push(step("build", BASE, &[RELIBC], super::busybox_build));
    steps.push(step("build", ADDONS, &[RELIBC, BASE], super::nano_build));
    steps.push(step("build", KERNELS, &[], || {
        for variant in [
            Variant::Normal,
            Variant::Test,
            Variant::TestEl0,
            Variant::TestIcount,
            Variant::TestIcountEl0,
        ] {
            super::build(variant)?;
        }
        Ok(())
    }));
    steps.push(step("build", IMAGES, &[], || {
        super::build_boot_image("boot-test.img", &super::TEST_PROGRAMS, super::TEST_PROFILE)?;
        super::build_boot_image("boot-svc.img", &super::SVC_PROGRAMS, super::TEST_PROFILE)?;
        Ok(())
    }));
    steps.push(step("build", OS_TEST_OBJECTS, &[RELIBC, BASE], || {
        for extra in [None, Some("--full-basic")] {
            let mut cmd = Command::new("python3");
            cmd.arg(super::root().join("tools/build-os-test.py"));
            cmd.args(extra);
            super::run_cmd(&mut cmd)?;
        }
        Ok(())
    }));
    steps.push(step("build", OPEN_POSIX_OBJECTS, &[RELIBC, BASE], || {
        super::run_cmd(Command::new("python3").arg(super::root().join("tools/build-open-posix.py")))
    }));

    // The checks that read the repository and run on the host.
    steps.push(step("host", "packages check", &[], super::packages::check));
    steps.push(step("host", "licences", &[RELIBC], || {
        super::run_cmd(Command::new("python3").arg(super::root().join("tools/check-licenses.py")))
    }));
    steps.push(step(
        "host",
        "no transport-probe feature",
        &[],
        super::no_transport_probe,
    ));
    steps.push(step("host", "counter read sites", &[], || {
        super::disasm::check_counter_read_sites(&super::root())
    }));
    steps.push(step("host", "layer C names", &[], super::layer_c_names));
    steps.push(step("host", "no Cyrillic", &[], || {
        super::cyrillic::check(&super::root())
    }));
    steps.push(step("host", "fmt", &[], || {
        super::run_cmd(super::cargo().args(["fmt", "--all", "--check"]))
    }));
    steps.push(step("host", "clippy", &[], super::ci_lints));
    steps.push(step("host", "host tests", &[], super::host_tests));
    steps.push(step("host", "kernel stack depth", &[], || {
        super::wcet::run(&["stack".to_owned()])
    }));
    steps.push(step("host", "shipping disassembly", &[KERNELS], || {
        let a = super::build(Variant::Normal)?;
        let objdump = super::llvm_tool("llvm-objdump")?;
        super::disasm::shipping(&a.elf, &objdump)?;
        super::disasm::smp_order(&a.elf, &objdump)
    }));

    // Boots.
    let names = all_boot_names();
    let Split { kernel, guests } = split(&names);
    steps.push(step(
        "kernel",
        "kernel and image boots",
        &BOOT_NEEDS,
        move || jobs::run_all(only(super::boot_jobs(Vec::new()), &kernel), njobs),
    ));
    // Checks that read the host's time on TCG run alone, after the rest.
    steps.push(step("kernel", "timing boots", &BOOT_NEEDS, || {
        jobs::run_all(super::timing_jobs(), 1)
    }));
    // Every take of OBJ in the kernel is a place on the list (obj_sites.rs).
    steps.push(step("kernel", "obj lock sites", &[], || {
        super::obj_sites::check(&super::root())
    }));
    steps.push(step(
        "kernel",
        "trace plugin",
        &BOOT_NEEDS,
        super::wcet::smoke,
    ));
    // Prints the computed bound against the measure of each call; it fails
    // only when the analysis itself breaks (an annotation names no function,
    // a call has no entry), and never on a number.
    steps.push(step("kernel", "wcet bound", &BOOT_NEEDS, || {
        super::wcet::run(&["bound".to_owned()])
    }));
    steps.push(step(
        "kernel",
        "measures",
        &BOOT_NEEDS,
        super::write_measures,
    ));
    for (n, names) in guests.into_iter().enumerate() {
        let group = format!("guests-{}", n + 1);
        let probes = format!("guest probes {}", n + 1);
        steps.push(step(&group, &probes, &BOOT_NEEDS, move || {
            jobs::run_all(only(super::boot_jobs(Vec::new()), &names), njobs)
        }));
        steps.push(step(&group, "measures", &BOOT_NEEDS, super::write_measures));
    }

    // os-test: a boot a suite, and the complete basic suite.
    let os_needs = [RELIBC, BASE, ADDONS, KERNELS, IMAGES, OS_TEST_OBJECTS];
    steps.push(step("os-test", "os-test suites", &os_needs, move || {
        let (list, plan) = super::ostest::plan()?;
        jobs::run_all(list, njobs)?;
        super::ostest::finish(plan)
    }));
    steps.push(step(
        "os-test",
        "os-test full basic",
        &os_needs,
        move || super::ostest::run_full_basic(njobs),
    ));
    steps.push(step(
        "os-test",
        "measures",
        &os_needs,
        super::write_measures,
    ));

    // The tests of the Open POSIX Test Suite that pass still pass
    // (tests/open-posix/pass.txt), in parts.
    let op_needs = [RELIBC, BASE, KERNELS, OPEN_POSIX_OBJECTS];
    for n in 0..OPEN_POSIX_PARTS {
        let group = format!("open-posix-{}", n + 1);
        steps.push(step(&group, "Open POSIX tests", &op_needs, move || {
            super::openposix::run_part(
                super::openposix::Select::Pinned,
                njobs,
                Some((n, OPEN_POSIX_PARTS)),
            )
        }));
    }
    steps
}

/// The steps of `group` and the steps they need, in the order of the list;
/// all the steps for no group.
fn select(steps: Vec<Step>, group: Option<&str>) -> Vec<Step> {
    let Some(group) = group else { return steps };
    let mut wanted: Vec<String> = steps
        .iter()
        .filter(|s| s.group == group)
        .map(|s| s.name.clone())
        .collect();
    loop {
        let more: Vec<String> = steps
            .iter()
            .filter(|s| wanted.contains(&s.name))
            .flat_map(|s| s.needs.iter())
            .filter(|n| !wanted.iter().any(|w| w == **n))
            .map(|n| (*n).to_owned())
            .collect();
        if more.is_empty() {
            break;
        }
        wanted.extend(more);
    }
    steps
        .into_iter()
        .filter(|s| s.group == group || (s.group == "build" && wanted.contains(&s.name)))
        .collect()
}

enum Outcome {
    Ok,
    Failed(String),
    Skipped(&'static str),
}

struct Report {
    name: String,
    outcome: Outcome,
    took: Duration,
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

fn execute(steps: Vec<Step>) -> Vec<Report> {
    let mut reports: Vec<Report> = Vec::new();
    for step in steps {
        let blocked = step.needs.iter().find(|need| {
            reports
                .iter()
                .any(|r| r.name == **need && !matches!(r.outcome, Outcome::Ok))
        });
        println!("== step: {}", step.name);
        if let Some(need) = blocked {
            println!("== skipped: {} (skipped because of {need})", step.name);
            reports.push(Report {
                name: step.name,
                outcome: Outcome::Skipped(need),
                took: Duration::ZERO,
            });
            continue;
        }
        let began = Instant::now();
        let result = (step.run)();
        let took = began.elapsed();
        let outcome = match result {
            Ok(()) => Outcome::Ok,
            Err(e) => Outcome::Failed(e),
        };
        match &outcome {
            Outcome::Failed(e) => println!(
                "== step FAILED: {} ({:.0} s): {e}",
                step.name,
                took.as_secs_f64()
            ),
            _ => println!("== step ok: {} ({:.0} s)", step.name, took.as_secs_f64()),
        }
        reports.push(Report {
            name: step.name,
            outcome,
            took,
        });
    }
    reports
}

fn summary(label: &str, reports: &[Report]) -> String {
    let mut text = format!("ci summary ({label}):\n");
    for r in reports {
        let line = match &r.outcome {
            Outcome::Ok => format!("  ok       {:>6.0} s  {}", r.took.as_secs_f64(), r.name),
            Outcome::Failed(e) => format!(
                "  FAILED   {:>6.0} s  {}: {}",
                r.took.as_secs_f64(),
                r.name,
                first_line(e)
            ),
            Outcome::Skipped(need) => {
                format!(
                    "  skipped  {:>8}  {} (skipped because of {need})",
                    "", r.name
                )
            }
        };
        text.push_str(&line);
        text.push('\n');
    }
    text
}

struct Options {
    jobs: usize,
    group: Option<String>,
    list: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let usage = "usage: cargo xtask ci [--jobs N] [--group NAME | --list-groups]";
    let mut options = Options {
        jobs: jobs::default_jobs(),
        group: None,
        list: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--jobs" => {
                options.jobs = args
                    .next()
                    .and_then(|n| n.parse::<usize>().ok())
                    .filter(|&n| n >= 1)
                    .ok_or("ci --jobs expects a number from 1")?;
            }
            "--group" => options.group = Some(args.next().ok_or(usage)?.clone()),
            "--list-groups" => options.list = true,
            _ => return Err(usage.to_owned()),
        }
    }
    Ok(options)
}

pub fn run(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    let known = groups();
    if options.list {
        for group in &known {
            println!("{group}");
        }
        return Ok(());
    }
    if let Some(group) = &options.group
        && !known.contains(group)
    {
        return Err(format!(
            "unknown group {group}; the groups: {}",
            known.join(", ")
        ));
    }
    jobs::keep_going(true);
    let label = options.group.clone().unwrap_or_else(|| "all".to_owned());
    let began = Instant::now();
    let steps = select(all_steps(options.jobs), options.group.as_deref());
    let reports = execute(steps);
    let mut text = summary(&label, &reports);
    text.push_str(&format!("  total {:.0} s\n", began.elapsed().as_secs_f64()));
    println!("{text}");
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            let _ = writeln!(file, "### {label}\n```\n{text}```");
        }
    }
    let failed: Vec<&Report> = reports
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Failed(_)))
        .collect();
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        for r in &failed {
            if let Outcome::Failed(e) = &r.outcome {
                println!("::error title=ci {label}: {}::{}", r.name, first_line(e));
            }
        }
    }
    let skipped = reports
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Skipped(_)))
        .count();
    if failed.is_empty() && skipped == 0 {
        println!("all checks passed");
        return Ok(());
    }
    Err(format!(
        "{} of {} steps failed, {skipped} skipped: {}",
        failed.len(),
        reports.len(),
        failed
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Every boot outside os-test is in exactly one group.
    #[test]
    fn the_groups_are_the_whole_list_of_probes() {
        let names = all_boot_names();
        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "a probe is named twice");
        let Split { kernel, guests } = split(&names);
        assert!(!kernel.is_empty());
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for name in kernel.iter().chain(guests.iter().flatten()) {
            *seen.entry(name.clone()).or_default() += 1;
        }
        for name in &names {
            assert_eq!(seen.get(name), Some(&1), "{name} is not in one group");
        }
        assert_eq!(seen.len(), names.len());
        for (n, group) in guests.iter().enumerate() {
            assert!(!group.is_empty(), "guests-{} is empty", n + 1);
        }
        // The jobs built from the groups are the jobs of the list.
        let built: usize = (0..guests.len())
            .map(|n| only(super::super::boot_jobs(Vec::new()), &guests[n]).len())
            .sum::<usize>()
            + only(super::super::boot_jobs(Vec::new()), &kernel).len();
        assert_eq!(built, names.len());
    }

    /// The groups are close in expected time.
    #[test]
    fn the_guest_groups_are_balanced() {
        let Split { guests, .. } = split(&all_boot_names());
        let loads: Vec<u32> = guests
            .iter()
            .map(|g| g.iter().map(|n| weight(n)).sum())
            .collect();
        let (low, high) = (loads.iter().min().unwrap(), loads.iter().max().unwrap());
        assert!(*high * 10 <= *low * 11 + 100, "{loads:?}");
    }

    /// The timing boots and the os-test boots are not among the probes
    /// the groups split.
    #[test]
    fn the_groups_have_steps_and_a_workflow_job_each() {
        let steps = all_steps(1);
        let workflow =
            std::fs::read_to_string(super::super::root().join(".github/workflows/ci.yml"))
                .expect("the workflow");
        for group in groups() {
            assert!(
                steps.iter().any(|s| s.group == group),
                "{group} has no step"
            );
            if group != "build" {
                assert!(
                    workflow.contains(&format!("- {group}\n")),
                    "{group} is not in the matrix of the workflow"
                );
            }
        }
        let names: Vec<&str> = steps.iter().map(|s| s.group.as_str()).collect();
        for name in names {
            assert!(groups().iter().any(|g| g == name), "{name} is not listed");
        }
    }

    #[test]
    fn a_step_after_a_failed_build_is_skipped() {
        let steps = vec![
            step("a", "build", &[], || Err("broken\nmore".to_owned())),
            step("a", "use", &["build"], || Ok(())),
            step("a", "other", &[], || Ok(())),
        ];
        let reports = execute(steps);
        assert!(matches!(reports[0].outcome, Outcome::Failed(_)));
        assert!(matches!(reports[1].outcome, Outcome::Skipped("build")));
        assert!(matches!(reports[2].outcome, Outcome::Ok));
        let text = summary("t", &reports);
        assert!(text.contains("skipped because of build"));
        assert!(text.contains("build: broken"));
        assert!(!text.contains("more"));
    }

    #[test]
    fn a_group_brings_the_steps_it_needs() {
        let steps = select(all_steps(1), Some("open-posix-1"));
        let names: Vec<&str> = steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                RELIBC,
                BASE,
                KERNELS,
                OPEN_POSIX_OBJECTS,
                "Open POSIX tests"
            ]
        );
    }
}
