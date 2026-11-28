// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask layer-posix [breaks]`: the POSIX layer on the layered root (tests/layer-posix) on
//! QEMU's `virt` with a virtio disk that holds a data volume made offline
//! (`data_image::make_layer_posix_volume`: the live layer 00 with marks of deletion, names that
//! shadow lower ones, an opaque directory, files of another owner and closed directories, a
//! directory whose first sixteen lower names the layer hides). The image has the RAM files (the
//! lower set of the probe: `boot-layer-posix.img`, with the programs the probe starts), the process,
//! clock and pipe services, the disk service of the volume, the data file service, the layer service
//! and the probe, a POSIX process of the root whose layer sends every path of the root but the
//! pass-through names to the layer service (the feature `layer`). The probe prints a line for each
//! check (`layer-posix: <check> ok`) and ends with `layer-posix: checks passed`.
//!
//! `ash` runs the shell of the layered root (`boot-layer-ash.img`, the same volume and lower set
//! without the programs of the C probe): BusyBox's `ash` with a script of `ls -la /etc`, reads of
//! names of the layers, a listing in which the layer hides lower names, a directory of the lower set
//! alone, a write below `/tmp` and a write the root refuses (tests/busybox, feature `ash-layer`).
//!
//! `breaks` builds the probe's layer with each deliberate break (no path routed to the layer
//! service, no session for a child) and runs the probe against it: the probe must fail, and the
//! check each break is meant for must be one of the failures.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, Variant, build, qemu, run_until,
    write_boot_image_files,
};
use std::path::PathBuf;

const PREFIX: &str = "layer-posix: ";
const ENDS: &str = "init: layer-posix ended: ";
const PASSED: &str = "layer-posix: checks passed";
const IMAGE: &str = "boot-layer-posix.img";

/// The image is written under one name (the files of its lower set are the ones `rootfs::files_of`
/// lists for the name), and the jobs of one `xtask ci` run side by side in a process, so the write is
/// done one at a time and each run boots from a copy of its own.
static IMAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A number no other run of this process has.
fn seq() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

const ASH_IMAGE: &str = "boot-layer-ash.img";
const ASH_ENDS: &str = "init: busybox-probe ended: ";

/// The size of the disk file: the layout takes 1 MiB for the table, `store` half of the rest, and the
/// data partition of 31 MiB holds the volume of the probe.
const DISK_BYTES: u64 = 64 << 20;

/// The longest a boot may take: the start of the volume, the index and 24 checks with their forks.
const LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

/// The checks of the probe, in the order it runs them: the line of each is `layer-posix: <check> ok`.
pub const CHECKS: [&str; 31] = [
    "a file of the layer of the user is read",
    "a lower file is read",
    "a name of the layer shadows the lower one",
    "the names the layer deletes are gone",
    "stat of paths and the layered device",
    "access and readlink",
    "a merged directory is listed once",
    "a lower directory is listed",
    "a listing goes on over empty replies",
    "an opaque directory lists its own names",
    "paths against a merged directory",
    "paths against a lower directory",
    "the pass-through names are the services' own",
    "a path out of a pass-through directory is the root's",
    "a link below a pass-through directory is routed through the layer",
    "chdir and fchdir",
    "realpath",
    "a forked child shares the directory description",
    "a spawned program keeps the directory description",
    "an exec keeps the directory description",
    "programs of the layers",
    "a forked child binds its own identity",
    "rights of another user",
    "writes to the lower set are refused",
    "the attributes of descriptions are kept",
    "a lower link leads through the merged view",
    "descriptions keep the device across fork and exec",
    "a description of the service has no path after exec",
    "a set-ID program is given the service's session",
    "a set-ID program keeps the genuine session and binds it",
    "the directory of the layers is hidden from programs",
];

/// The deliberate breaks, the program each is a feature of and the check each one fails.
pub const BREAKS: [(&str, &str, &str); 6] = [
    (
        "break-layer-route",
        "layer-posix",
        "a file of the layer of the user is read",
    ),
    (
        "break-layer-clone",
        "layer-posix",
        "a forked child shares the directory description",
    ),
    // The file service expands a link that reaches the root from a descriptor itself, and its write
    // guard is off.
    (
        "break-layered-guard",
        "ramfs",
        "a link below a pass-through directory is routed through the layer",
    ),
    (
        "break-layer-fd-guard",
        "layer-posix",
        "the attributes of descriptions are kept",
    ),
    (
        "break-layer-unverified",
        "loader",
        "a set-ID program is given the service's session",
    ),
    // The data file service shows `/.layers` to every session, so a program sees the layers.
    (
        "break-datafs-layers-visible",
        "datafsd",
        "the directory of the layers is hidden from programs",
    ),
];

const PASSED_WRITE: &str = "layer-posix: write checks passed";
const PASSED_REREAD: &str = "layer-posix: reread checks passed";

/// The checks of the write phase (`cargo xtask layer-posix write`): the changes of names on the
/// layer, in the order the probe runs them.
pub const WRITE_CHECKS: [&str; 13] = [
    "a file is created and written",
    "a file of the layer is rewritten",
    "directories are made and removed",
    "names are deleted from the layer and from the lower set",
    "directories are removed and made again opaque",
    "an opaque directory removed or moved stays removed",
    "names are renamed inside the layer",
    "symbolic links of the layer",
    "hard links, reserved names and long paths",
    "the rights of another user on the layer",
    "a sticky directory is kept",
    "a program of the lower set is not written",
    "changes against descriptions",
];

/// The checks of the second boot of the write probe, on the disk the first one left.
pub const REREAD_CHECKS: [&str; 5] = [
    "the names made are kept",
    "the names deleted stay deleted",
    "a directory made over a removed one is opaque",
    "the links are kept",
    "the numbers go on and the owners are kept",
];

/// The breaks of the layer service the write probe must catch: the feature, the phase whose probe
/// must fail (the second boot reads what the first left) and the check that must be one of the
/// failures.
pub const WRITE_BREAKS: [(&str, bool, &str); 2] = [
    // The sticky bit of a directory is not looked at by a removal or a rename.
    ("break-layerd-sticky", false, "a sticky directory is kept"),
    // The mark of the deletion of a lower name is not written to the volume: the index hides the
    // name until the service starts again.
    (
        "break-layerd-no-mark",
        true,
        "the names deleted stay deleted",
    ),
];

/// The features each program of the image is built with.
#[derive(Clone, Copy, Default)]
struct Build {
    probe: &'static [&'static str],
    ramfs: &'static [&'static str],
    loader: &'static [&'static str],
    layerd: &'static [&'static str],
    datafs: &'static [&'static str],
}

/// The image's programs; the probe is built with `probe` features, the RAM file service with
/// `ramfs` features, the loader with `loader` features and the layer service with `layerd`.
fn programs(build: Build) -> Vec<ImageProgram> {
    let Build {
        probe,
        ramfs,
        loader,
        layerd,
        datafs,
    } = build;
    vec![
        ("init", "init", INIT_STACK_SIZE, &["table-layer-posix"][..]),
        ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, ramfs),
        (
            "posix-process-service",
            "posix-process-service",
            64 * 1024,
            &[],
        ),
        ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
        ("pipe", "pipe", crate::PIPE_STACK_SIZE, &[]),
        ("loader", "loader", 0, loader),
        (
            "virtio-blk",
            "virtio-blk",
            crate::blk_probe::BLK_STACK_SIZE,
            &[],
        ),
        ("datafsd", "datafsd", 32 * 1024, datafs),
        ("layerd", "layerd", crate::LAYERD_STACK_SIZE, layerd),
        (
            "layer-posix",
            "layer-posix-probe",
            crate::POSIX_STACK_SIZE,
            probe,
        ),
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

/// The programs of the plain image, for the check of the stacks of every list of programs.
#[cfg(test)]
pub fn plain_programs() -> Vec<ImageProgram> {
    programs(Build::default())
}

/// The disk of the run: a file of the process's name, removed at the end.
struct Disk(PathBuf);

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => probe(machine),
        Some("breaks") if args.len() == 1 => breaks(machine),
        Some("ash") if args.len() == 1 => ash(machine),
        Some("write") if args.len() == 1 => write(machine),
        Some("write") if args.len() == 2 && args[1] == "breaks" => write_breaks(machine),
        Some("copy") if args.len() == 1 => copy(machine),
        Some("copy") if args.len() == 2 && args[1] == "breaks" => copy_breaks(machine),
        Some("copy") if args.len() == 2 && args[1] == "race" => copy_race(machine),
        Some("copy") if args.len() == 2 && args[1] == "full" => copy_full(machine),
        Some(other) => Err(format!(
            "layer-posix [breaks | ash | write [breaks] | copy [breaks | race | full]]: unknown argument {other}"
        )),
    }
}

/// The image of the shell: the C probe's services with BusyBox's probe in its place.
fn ash_programs() -> Vec<ImageProgram> {
    let mut list = programs(Build::default());
    list[0].3 = &["table-layer-ash"];
    let at = list
        .iter()
        .position(|p| p.0 == "layer-posix")
        .expect("the probe is in the image");
    list[at] = (
        "busybox-probe",
        "busybox-probe",
        crate::POSIX_STACK_SIZE,
        &["ash-layer"],
    );
    list
}

/// The programs of the image of the shell, for the check of the stacks.
#[cfg(test)]
pub fn plain_ash_programs() -> Vec<ImageProgram> {
    ash_programs()
}

/// The shell on the layered root: its output is the script's, in order.
pub fn ash(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    crate::busybox_build()?;
    let kernel = build(Variant::Normal)?;
    // The shell's own program is a file of the lower set too: the write the script makes to it is
    // refused (a program is never copied up), where a write to a data file would be copied.
    let program = crate::rootfs::RootFile {
        path: "/bin/busybox-probe",
        mode: 0o755,
        uid: 0,
        gid: 0,
        source: Some(crate::rootfs::Source::Elf("busybox-probe")),
    };
    let image =
        write_boot_image_files(ASH_IMAGE, &ash_programs(), BOOT_PROFILE, &[], vec![program])?;
    let disk =
        Disk(std::env::temp_dir().join(format!("stafeto-layer-ash-{}.img", std::process::id())));
    crate::data_image::make_layer_posix_volume(&disk.0, DISK_BYTES)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let started = std::time::Instant::now();
    let output = run_until(cmd, LIMIT, Some(ASH_ENDS), &kernel.elf)?;
    registered(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: busybox-probe ended: exit code 0, not restarted",
    )?;
    read_ash(&output.lines)?;
    println!(
        "layer-posix ash on {}: the shell on the layered root in {} s: ok",
        machine.name,
        started.elapsed().as_secs()
    );
    Ok(())
}

/// The last word of a line of a long listing.
fn last_word(line: &str) -> &str {
    line.split_whitespace().last().unwrap_or("")
}

/// The output of the script of the shell (tests/busybox, `ASH_LAYER_SCRIPT`) after
/// `layer-shell-ready`: the long listing of `/etc` (BusyBox's `ls` of this build prints the mode,
/// the links, the size and the name, in the reverse of the order the directory gives them) with the
/// names of the layer of the user and of the lower set and the sizes of the layer's files, then the
/// lines of the rest of the script, in order (`ls -1` of `/many` is in the same reverse order).
pub fn read_ash(lines: &[String]) -> Result<(), String> {
    let at = lines
        .iter()
        .position(|l| l == "layer-shell-ready")
        .ok_or_else(|| {
            format!(
                "no layer-shell-ready; last lines: {:?}",
                &lines[lines.len().saturating_sub(8)..]
            )
        })?;
    let rest = &lines[at + 1..];
    let end = rest
        .iter()
        .position(|l| l == "lower of etc")
        .ok_or("no line of the file layer-lower after the listing")?;
    let listing = &rest[..end];
    let find = |name: &str| listing.iter().find(|l| last_word(l) == name);
    let wanted = [
        ("layer-own", "-rw-r-----", "25"),
        ("layer-note", "-rw-r--r--", "11"),
        ("layer-world", "-rw-r--r--", "13"),
        ("layer-secret", "-rw-------", "7"),
        ("layer-lower", "-rw-r--r--", "13"),
        (".", "drwxr-xr-x", "0"),
        ("..", "drwxr-xr-x", "0"),
    ];
    for (name, mode, size) in wanted {
        match find(name) {
            Some(line)
                if line.starts_with(mode) && line.split_whitespace().nth(2) == Some(size) => {}
            other => {
                return Err(format!(
                    "the long listing has no {name:?} of mode {mode} and size {size}: {other:?}"
                ));
            }
        }
    }
    // Each name once: the layer of the user and the lower set do not list one twice.
    for (name, _, _) in wanted {
        if listing.iter().filter(|l| last_word(l) == name).count() != 1 {
            return Err(format!("the listing has {name:?} not once: {listing:?}"));
        }
    }
    if find("layer-hidden").is_some() {
        return Err("the listing shows layer-hidden, which the layer deletes".to_owned());
    }
    // The listings of `ls -1` come in the order the build's `ls` makes of them, so each is a set.
    let got = &rest[end..];
    let fixed = [
        "lower of etc",
        "owned bytes of the layer",
        "upper shadow",
        "hidden-gone",
    ];
    let sets: [&[&str]; 2] = [&["f16", "f17", "f18", "f19", "own"], &["a", "b", "c"]];
    let tail = ["a", "tmp-bytes"];
    let want = fixed.len() + sets[0].len() + sets[1].len() + tail.len();
    let mut at = 0;
    let mut ok = got.len() >= want && got[..fixed.len()].iter().zip(fixed).all(|(l, w)| l == w);
    at += fixed.len();
    for set in sets {
        if !ok {
            break;
        }
        let mut have: Vec<&str> = got[at..at + set.len()].iter().map(String::as_str).collect();
        have.sort_unstable();
        let mut wanted = set.to_vec();
        wanted.sort_unstable();
        ok = have == wanted;
        at += set.len();
    }
    ok = ok
        && got[at..at + tail.len()]
            .iter()
            .zip(tail)
            .all(|(l, w)| l == w);
    if !ok {
        return Err(format!(
            "the lines after the listing are not the script's ({fixed:?}, {sets:?}, {tail:?}): {got:?}"
        ));
    }
    let after = &got[..want];
    // The write and the `mv` of the program are refused, and the program is there.
    let mut rest = got[after.len()..].iter();
    for wanted in ["write-refused", "mv-refused", "moved-none", "program-kept"] {
        if !rest.any(|l| l == wanted) {
            return Err(format!(
                "the shell did not say {wanted:?} after the listing: {:?}",
                &got[after.len()..]
            ));
        }
    }
    Ok(())
}

/// A disk for a run: the volume of the probe, made offline.
fn new_disk() -> Result<Disk, String> {
    let disk = Disk(std::env::temp_dir().join(format!(
        "stafeto-layer-posix-{}-{}.img",
        std::process::id(),
        seq()
    )));
    crate::data_image::make_layer_posix_volume(&disk.0, DISK_BYTES)?;
    Ok(disk)
}

/// One boot with the programs built as `build` says, on a disk of its own; the lines of the
/// console.
fn boot(machine: &qemu::Machine, with: Build) -> Result<(qemu::Outcome, u64), String> {
    boot_on(machine, with, &new_disk()?)
}

/// One boot on `disk`: the second boot of the write probe reads what the first left on it.
fn boot_on(
    machine: &qemu::Machine,
    with: Build,
    disk: &Disk,
) -> Result<(qemu::Outcome, u64), String> {
    boot_with(machine, with, disk, Vec::new(), LIMIT)
}

/// `boot_on` with files besides the lower set of the image and the longest the boot may take.
fn boot_with(
    machine: &qemu::Machine,
    with: Build,
    disk: &Disk,
    extra: Vec<crate::rootfs::RootFile>,
    limit: std::time::Duration,
) -> Result<(qemu::Outcome, u64), String> {
    boot_until(machine, with, disk, extra, limit, &[], ENDS)
}

/// `boot_with` for a build that takes `env` and a run that stops on the line `stop`.
fn boot_until(
    machine: &qemu::Machine,
    with: Build,
    disk: &Disk,
    extra: Vec<crate::rootfs::RootFile>,
    limit: std::time::Duration,
    env: &[(&str, &str)],
    stop: &str,
) -> Result<(qemu::Outcome, u64), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = {
        let _writing = IMAGE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let made = write_boot_image_files(IMAGE, &programs(with), BOOT_PROFILE, env, extra)?;
        let own = made.with_file_name(format!(
            "boot-layer-posix-run-{}-{}.img",
            std::process::id(),
            seq()
        ));
        std::fs::copy(&made, &own).map_err(|e| format!("{}: {e}", own.display()))?;
        own
    };
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let started = std::time::Instant::now();
    let output = run_until(cmd, limit, Some(stop), &kernel.elf);
    // The image is this run's alone.
    let _ = std::fs::remove_file(&image);
    Ok((output?, started.elapsed().as_secs()))
}

/// The lines of the probe, text after the prefix.
fn mine(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .filter_map(|l| l.find(PREFIX).map(|at| &l[at + PREFIX.len()..]))
        .collect()
}

/// The root of the layer service is registered, or the probe could not have taken it.
fn registered(lines: &[String]) -> Result<(), String> {
    if lines.iter().any(|l| {
        l.contains("layerd: root registered with the process service")
            || l.contains("layerd: root registered after ")
    }) {
        return Ok(());
    }
    Err(format!(
        "the layer service did not say its root is registered: {:?}",
        lines
            .iter()
            .filter(|l| l.contains("layerd:"))
            .collect::<Vec<_>>()
    ))
}

/// Each check has exactly one line `ok`, in the order of `CHECKS`; no line says a check failed; the
/// line of the end comes once, after every check.
pub fn read_lines(lines: &[String]) -> Result<(), String> {
    read_checks(lines, &CHECKS, PASSED)
}

/// `read_lines` for the checks `checks` and the line of the end `passed`.
fn read_checks(lines: &[String], checks: &[&str], passed: &str) -> Result<(), String> {
    registered(lines)?;
    let mine = mine(lines);
    if let Some(bad) = mine
        .iter()
        .find(|l| l.contains("FAILED") || l.contains("checks failed") || l.contains("check failed"))
    {
        return Err(format!("layer-posix: {bad}"));
    }
    let mut next = 0;
    let mut ended = false;
    for line in &mine {
        if *line == &passed[PREFIX.len()..] {
            if next != checks.len() {
                return Err(format!("the end after {next} of {} checks", checks.len()));
            }
            ended = true;
            continue;
        }
        let Some(name) = line.strip_suffix(" ok") else {
            continue;
        };
        if ended {
            return Err(format!("a line after the end: {line:?}"));
        }
        match checks.get(next) {
            Some(expected) if *expected == name => next += 1,
            Some(expected) => {
                return Err(format!(
                    "the check {name:?} came where {expected:?} was due"
                ));
            }
            None => return Err(format!("an extra check line {line:?}")),
        }
    }
    if !ended {
        return Err(format!(
            "the probe said {next} of {} checks and no end",
            checks.len()
        ));
    }
    Ok(())
}

pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let (output, seconds) = boot(machine, Build::default())?;
    read_lines(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-posix on {}: {} checks of the POSIX layer on the layered root in {} s: ok",
        machine.name,
        CHECKS.len(),
        seconds
    );
    Ok(())
}

/// Each break, one boot each: the probe must fail and name the check the break is for.
pub fn breaks(machine: &qemu::Machine) -> Result<(), String> {
    for (feature, program, check) in BREAKS {
        let features: &'static [&'static str] = Box::leak(vec![feature].into_boxed_slice());
        let build = match program {
            "ramfs" => Build {
                ramfs: features,
                ..Build::default()
            },
            "loader" => Build {
                loader: features,
                ..Build::default()
            },
            "datafsd" => Build {
                datafs: features,
                ..Build::default()
            },
            _ => Build {
                probe: features,
                ..Build::default()
            },
        };
        let (output, seconds) = boot(machine, build)?;
        let mine = mine(&output.lines);
        if mine.iter().any(|l| *l == &PASSED[PREFIX.len()..]) {
            return Err(format!(
                "layer-posix breaks: {feature} did not fail the probe"
            ));
        }
        let failed: Vec<&&str> = mine.iter().filter(|l| l.contains(" FAILED")).collect();
        let wanted = format!("{check} FAILED");
        if !failed.iter().any(|l| l.starts_with(&wanted)) {
            return Err(format!(
                "layer-posix breaks: {feature} did not fail {check:?}; the checks that failed: {failed:?}"
            ));
        }
        println!("layer-posix breaks: {feature} is caught by {check:?} (in {seconds} s)");
    }
    Ok(())
}

const WRITE_PROBE: &[&str] = &["phase-write"];
const REREAD_PROBE: &[&str] = &["phase-reread"];

/// The write probe: the changes of names on the layer in one boot, and a second boot on the same disk
/// that reads what the first left (the names, the marks, the opaque directory, the links, the
/// numbers).
pub fn write(machine: &qemu::Machine) -> Result<(), String> {
    let disk = new_disk()?;
    let (first, first_seconds) = boot_on(
        machine,
        Build {
            probe: WRITE_PROBE,
            ..Build::default()
        },
        &disk,
    )?;
    read_checks(&first.lines, &WRITE_CHECKS, PASSED_WRITE)?;
    qemu::expect_stopped_on(
        &first,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    let (second, second_seconds) = boot_on(
        machine,
        Build {
            probe: REREAD_PROBE,
            ..Build::default()
        },
        &disk,
    )?;
    read_checks(&second.lines, &REREAD_CHECKS, PASSED_REREAD)?;
    qemu::expect_stopped_on(
        &second,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-posix write on {}: {} checks of the changes in {first_seconds} s, {} checks of the names they left on a second boot in {second_seconds} s: ok",
        machine.name,
        WRITE_CHECKS.len(),
        REREAD_CHECKS.len(),
    );
    Ok(())
}

/// Each break of the layer service, with the boots it needs: the probe must fail and name the check
/// the break is for.
pub fn write_breaks(machine: &qemu::Machine) -> Result<(), String> {
    for (feature, reread, check) in WRITE_BREAKS {
        let layerd: &'static [&'static str] = Box::leak(vec![feature].into_boxed_slice());
        let disk = new_disk()?;
        let write_build = Build {
            probe: WRITE_PROBE,
            layerd,
            ..Build::default()
        };
        let (mut output, mut seconds) = boot_on(machine, write_build, &disk)?;
        if reread {
            // The first boot must pass (the break shows only after the service starts again).
            read_checks(&output.lines, &WRITE_CHECKS, PASSED_WRITE)?;
            let build = Build {
                probe: REREAD_PROBE,
                layerd,
                ..Build::default()
            };
            let (second, more) = boot_on(machine, build, &disk)?;
            (output, seconds) = (second, seconds + more);
        }
        let passed = if reread { PASSED_REREAD } else { PASSED_WRITE };
        let mine = mine(&output.lines);
        if mine.iter().any(|l| *l == &passed[PREFIX.len()..]) {
            return Err(format!(
                "layer-posix write breaks: {feature} did not fail the probe"
            ));
        }
        let failed: Vec<&&str> = mine.iter().filter(|l| l.contains(" FAILED")).collect();
        let wanted = format!("{check} FAILED");
        if !failed.iter().any(|l| l.starts_with(&wanted)) {
            return Err(format!(
                "layer-posix write breaks: {feature} did not fail {check:?}; the checks that failed: {failed:?}"
            ));
        }
        println!("layer-posix write breaks: {feature} is caught by {check:?} (in {seconds} s)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------- copy

const PASSED_COPY: &str = "layer-posix: copy checks passed";
const PASSED_COPY_REREAD: &str = "layer-posix: copy reread checks passed";

/// The checks of the copy phase (`cargo xtask layer-posix copy`): a lower file is copied up when it
/// is written, in the order the probe runs them.
pub const COPY_CHECKS: [&str; 14] = [
    "a lower file that is written is copied up",
    "the copy keeps the owner, the mode, the times and the number",
    "a cut open makes an empty copy with the lower attributes",
    "chmod, chown, utimensat and truncate of a lower file copy it up",
    "chmod, chown and utimensat of a lower directory keep its number",
    "lchown of a lower link copies the link",
    "a lower program is never copied up and still runs",
    "a read open copies nothing",
    "a user without write rights is refused and nothing is copied",
    "two writers of one file make one copy",
    "a signal during the wait of a copy is EINTR without SA_RESTART",
    "a signal during the wait of a copy goes on with SA_RESTART",
    "the numbers of the copies are kept",
    "a lower file and a lower link are renamed after their copy with a mark on the old name",
];

/// The check of the second boot of the copy probe, on the disk the first one left.
pub const COPY_REREAD_CHECKS: [&str; 1] = ["the copies are the layer's with the numbers they had"];

/// The breaks of the copy up the probe must catch: the feature of the layer service and the checks
/// that must be among the failures.
pub const COPY_BREAKS: [(&str, &[&str]); 4] = [
    // The copy and the directories of its path take numbers of the counter: `st_ino` changes.
    (
        "break-layerd-copy-counter-ino",
        &["a lower file that is written is copied up"],
    ),
    // The copy keeps the owner, mode and times the volume gave it.
    (
        "break-layerd-copy-attrs",
        &["the copy keeps the owner, the mode, the times and the number"],
    ),
    // A program is copied like any file.
    (
        "break-layerd-copy-elf",
        &["a lower program is never copied up and still runs"],
    ),
    // The rename of a lower file leaves the old name unmarked: the lower name shows again.
    (
        "break-layerd-rename-no-mark",
        &["a lower file and a lower link are renamed after their copy with a mark on the old name"],
    ),
];

/// The copies of the whole run: the files of the checks that copy (nine of the probe, the two of two
/// signals and the two files of the renames), and the five writes and the two renames of a program
/// that begin a copy the worker refuses. The link of a rename is copied in the job: no copy of the table.
const COPIES_RESERVED: u32 = 19;
const COPIES_MADE_VISIBLE: u32 = 12;
const COPIES_FAILED: u32 = 7;

const COPY_PROBE: &[&str] = &["phase-copy"];
/// The layer service of the copy probe tells the counters of its copies.
const COPY_LAYERD: &[&str] = &["probe-copies"];
const COPY_REREAD_PROBE: &[&str] = &["phase-copyreread"];

/// The size of the disk of the copy probe: the data partition holds the copies (35 MiB of files
/// above all) and the rest of the volume.
const COPY_DISK_BYTES: u64 = 192 << 20;
/// The longest a boot of the copy probe may take: 35 MiB are copied through the window of a service
/// under emulation.
const COPY_LIMIT: std::time::Duration = std::time::Duration::from_secs(900);
/// The bytes of the lower files of 16 MiB and of 3 MiB (`BIG_BYTE` of the probe).
const BIG_BYTES: usize = 16 << 20;
const TWO_BYTES: usize = 3 << 20;

/// The byte `i` of the big lower files: what the probe compares (`BIG_BYTE` of layer.c).
fn big_byte(i: usize) -> u8 {
    ((i.wrapping_mul(7) + (i >> 12)) | 1) as u8
}

fn big(len: usize) -> &'static [u8] {
    Box::leak(
        (0..len)
            .map(big_byte)
            .collect::<Vec<u8>>()
            .into_boxed_slice(),
    )
}

/// The files of the lower set the copy probe writes (besides those of the image): the directory
/// `/copyup`, with files of other owners and modes, a directory, links, files of 16 and 3 MiB, and
/// the names the renames take.
pub fn copy_lower_files() -> Vec<crate::rootfs::RootFile> {
    use crate::rootfs::{RootFile, Source};
    let of = |path: &'static str, mode: u32, (uid, gid): (u32, u32), source: Source| RootFile {
        path,
        mode,
        uid,
        gid,
        source: Some(source),
    };
    let bytes = |name: &'static str, text: &'static [u8]| Source::Bytes(name, text);
    let dir = |path: &'static str, mode: u32, (uid, gid): (u32, u32)| RootFile {
        path,
        mode,
        uid,
        gid,
        source: None,
    };
    let user = (1000, 100);
    vec![
        dir("/copyup", 0o755, (0, 0)),
        of(
            "/copyup/append",
            0o640,
            user,
            bytes("lp-copy-append", b"lower line\n"),
        ),
        of(
            "/copyup/attrs",
            0o751,
            (1001, 102),
            bytes("lp-copy-attrs", b"attrs bytes\n"),
        ),
        of(
            "/copyup/big1",
            0o644,
            (0, 0),
            Source::Bytes("lp-copy-big1", big(BIG_BYTES)),
        ),
        of(
            "/copyup/big2",
            0o644,
            (0, 0),
            Source::Bytes("lp-copy-big2", big(BIG_BYTES)),
        ),
        of(
            "/copyup/chmod",
            0o644,
            user,
            bytes("lp-copy-chmod", b"chmod me\n"),
        ),
        of(
            "/copyup/chown",
            0o644,
            user,
            bytes("lp-copy-chown", b"chown me\n"),
        ),
        dir("/copyup/dir", 0o750, user),
        of(
            "/copyup/dir/in",
            0o644,
            (0, 0),
            bytes("lp-copy-dir-in", b"inside\n"),
        ),
        of(
            "/copyup/link",
            bootimg::rootfs::SYMLINK_MODE,
            (0, 0),
            Source::Link("append"),
        ),
        of(
            "/copyup/read",
            0o644,
            (0, 0),
            bytes("lp-copy-read", b"read only\n"),
        ),
        of(
            "/copyup/rn-file",
            0o640,
            user,
            bytes("lp-copy-rn-file", b"rename me\n"),
        ),
        of(
            "/copyup/rn-link",
            bootimg::rootfs::SYMLINK_MODE,
            (0, 0),
            Source::Link("rn-file"),
        ),
        of(
            "/copyup/rn-move",
            0o644,
            (0, 0),
            bytes("lp-copy-rn-move", b"move me\n"),
        ),
        of(
            "/copyup/trunc",
            0o600,
            user,
            bytes("lp-copy-trunc", b"to be cut\n"),
        ),
        of(
            "/copyup/trunc2",
            0o644,
            (0, 0),
            bytes("lp-copy-trunc2", b"truncate me\n"),
        ),
        of(
            "/copyup/two",
            0o644,
            (0, 0),
            Source::Bytes("lp-copy-two", big(TWO_BYTES)),
        ),
        of(
            "/copyup/utime",
            0o644,
            (0, 0),
            bytes("lp-copy-utime", b"utime\n"),
        ),
    ]
}

/// The counters of the last line of the layer service about its copies at or before `at` of the
/// console: reserved, made visible, dropped, failed.
fn copy_counts(lines: &[String], at: usize) -> Option<[u32; 4]> {
    lines[..at].iter().rev().find_map(|l| {
        let rest = l.split_once("layerd: copies ")?.1;
        let rest = rest.split_once(": ")?.1;
        let mut numbers = rest
            .split(", ")
            .map(|part| part.split_whitespace().next()?.parse().ok());
        Some([
            numbers.next()??,
            numbers.next()??,
            numbers.next()??,
            numbers.next()??,
        ])
    })
}

/// The place of the line the probe says as a marker.
fn marker(lines: &[String], name: &str) -> Result<usize, String> {
    let wanted = format!("{PREFIX}marker {name}");
    lines
        .iter()
        .position(|l| l.ends_with(&wanted))
        .ok_or_else(|| format!("the probe said no marker {name:?}"))
}

/// What the lines of the layer service say of the copies: a read open reserves none, two writers
/// reserve one, and the run ends with the counts the checks make; the start of each boot found
/// `work/` empty.
pub fn read_copy_counts(lines: &[String]) -> Result<(), String> {
    let counts = |name: &str| -> Result<[u32; 4], String> {
        let at = marker(lines, name)?;
        Ok(copy_counts(lines, at).unwrap_or([0; 4]))
    };
    let (begin, end) = (counts("read-begin")?, counts("read-end")?);
    if begin != end {
        return Err(format!(
            "a read open changed the copies of the service: {begin:?} before, {end:?} after"
        ));
    }
    let (begin, end) = (counts("deny-begin")?, counts("deny-end")?);
    if begin != end {
        return Err(format!(
            "a user without the right to write made a copy: {begin:?} before, {end:?} after"
        ));
    }
    let (begin, end) = (counts("two-begin")?, counts("two-end")?);
    if end[0] != begin[0] + 1 {
        return Err(format!(
            "two writers of one file made {} copies ({begin:?} before, {end:?} after)",
            end[1].saturating_sub(begin[0])
        ));
    }
    let last = copy_counts(lines, lines.len()).ok_or("the layer service said nothing of copies")?;
    if last != [COPIES_RESERVED, COPIES_MADE_VISIBLE, 0, COPIES_FAILED] {
        return Err(format!(
            "the copies at the end are {last:?} (reserved, made visible, dropped, failed), {:?} were due",
            [COPIES_RESERVED, COPIES_MADE_VISIBLE, 0, COPIES_FAILED]
        ));
    }
    Ok(())
}

/// The start of a boot found `work/` empty.
fn read_work_empty(lines: &[String]) -> Result<(), String> {
    if lines
        .iter()
        .any(|l| l.contains("layerd: work/ is empty at the start"))
    {
        return Ok(());
    }
    Err(format!(
        "the layer service did not find work/ empty at its start: {:?}",
        lines
            .iter()
            .filter(|l| l.contains("layerd: work/"))
            .collect::<Vec<_>>()
    ))
}

/// The copy probe: a lower file is copied up when it is written (one boot), and a second boot on the
/// disk reads the copies, their numbers and what they hold, and finds `work/` empty.
pub fn copy(machine: &qemu::Machine) -> Result<(), String> {
    let disk = copy_disk()?;
    let (first, first_seconds) = boot_with(
        machine,
        Build {
            probe: COPY_PROBE,
            layerd: COPY_LAYERD,
            ..Build::default()
        },
        &disk,
        copy_lower_files(),
        COPY_LIMIT,
    )?;
    read_checks(&first.lines, &COPY_CHECKS, PASSED_COPY)?;
    read_work_empty(&first.lines)?;
    read_copy_counts(&first.lines)?;
    qemu::expect_stopped_on(
        &first,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    let (second, second_seconds) = boot_with(
        machine,
        Build {
            probe: COPY_REREAD_PROBE,
            layerd: COPY_LAYERD,
            ..Build::default()
        },
        &disk,
        copy_lower_files(),
        COPY_LIMIT,
    )?;
    read_checks(&second.lines, &COPY_REREAD_CHECKS, PASSED_COPY_REREAD)?;
    read_work_empty(&second.lines)?;
    qemu::expect_stopped_on(
        &second,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-posix copy on {}: {} checks of the copy up in {first_seconds} s, {} check of the copies on a second boot in {second_seconds} s: ok",
        machine.name,
        COPY_CHECKS.len(),
        COPY_REREAD_CHECKS.len(),
    );
    Ok(())
}

fn copy_disk() -> Result<Disk, String> {
    let disk = Disk(std::env::temp_dir().join(format!(
        "stafeto-layer-posix-copy-{}-{}.img",
        std::process::id(),
        seq()
    )));
    crate::data_image::make_layer_posix_volume(&disk.0, COPY_DISK_BYTES)?;
    Ok(disk)
}

/// Each break of the copy up, one boot each: the probe must fail and name the checks the break is
/// for.
pub fn copy_breaks(machine: &qemu::Machine) -> Result<(), String> {
    for (feature, checks) in COPY_BREAKS {
        let layerd: &'static [&'static str] =
            Box::leak(vec!["probe-copies", feature].into_boxed_slice());
        let disk = copy_disk()?;
        let (output, seconds) = boot_with(
            machine,
            Build {
                probe: COPY_PROBE,
                layerd,
                ..Build::default()
            },
            &disk,
            copy_lower_files(),
            COPY_LIMIT,
        )?;
        let mine = mine(&output.lines);
        if mine.iter().any(|l| *l == &PASSED_COPY[PREFIX.len()..]) {
            return Err(format!(
                "layer-posix copy breaks: {feature} did not fail the probe"
            ));
        }
        let failed: Vec<&&str> = mine.iter().filter(|l| l.contains(" FAILED")).collect();
        for check in checks {
            let wanted = format!("{check} FAILED");
            if !failed.iter().any(|l| l.starts_with(&wanted)) {
                return Err(format!(
                    "layer-posix copy breaks: {feature} did not fail {check:?}; the checks that failed: {failed:?}"
                ));
            }
        }
        println!("layer-posix copy breaks: {feature} is caught by {checks:?} (in {seconds} s)");
    }
    Ok(())
}

// ------------------------------------------------------------------ races, full volume and cut

const PASSED_RACE: &str = "layer-posix: copy race checks passed";
const PASSED_FULL: &str = "layer-posix: copy full checks passed";
const PASSED_FULL_REREAD: &str = "layer-posix: copy full reread checks passed";
const PASSED_CUT: &str = "layer-posix: cut verify checks passed";

/// The checks of the race probe (`cargo xtask layer-posix copy race`): names that change while the
/// copy of a rename goes on, in the order the probe runs them.
pub const RACE_CHECKS: [&str; 4] = [
    "a name deleted during the copy of a rename stays deleted",
    "a name made during the copy of a rename is the one that moves",
    "two renames of one file make one move",
    "more files than places for copies are all copied",
];

/// The checks of the probe of the volume too small for a copy (`cargo xtask layer-posix copy full`),
/// and of the boot after it.
pub const FULL_CHECKS: [&str; 2] = [
    "a copy without space is ENOSPC for every waiter and for a rename",
    "the lower file is whole after a copy without space",
];
pub const FULL_REREAD_CHECKS: [&str; 1] = ["the lower file is whole and the copy is tried again"];

/// The checks of the verification after a cut (`cargo xtask layer-cut copy`).
pub const CUT_CHECKS: [&str; 3] = [
    "the copied file is whole with the lower attributes",
    "the renamed file has the old name or the new, never both and never torn",
    "the rename that was cut goes through when it is asked again",
];

const RACE_BYTES: usize = 3 << 20;
const SMALL_BYTES: usize = 1 << 20;
const FULL_BYTES: usize = 20 << 20;
const CUT_BYTES: usize = 200 << 10;
/// The disk of the probe of the full volume: the data partition is about 16 MiB.
const FULL_DISK_BYTES: u64 = 34 << 20;
const RACE_DISK_BYTES: u64 = 128 << 20;
/// The disk of the cut probe: the copies are 200 KiB.
const CUT_DISK_BYTES: u64 = 64 << 20;
/// The files of the race probe that more than fill the table of copies.
const RACE_MORE: [&str; 14] = [
    "/race/f00",
    "/race/f01",
    "/race/f02",
    "/race/f03",
    "/race/f04",
    "/race/f05",
    "/race/f06",
    "/race/f07",
    "/race/f08",
    "/race/f09",
    "/race/f10",
    "/race/f11",
    "/race/f12",
    "/race/f13",
];

fn pattern_file(
    path: &'static str,
    mode: u32,
    owner: (u32, u32),
    name: &'static str,
    bytes: &'static [u8],
) -> crate::rootfs::RootFile {
    crate::rootfs::RootFile {
        path,
        mode,
        uid: owner.0,
        gid: owner.1,
        source: Some(crate::rootfs::Source::Bytes(name, bytes)),
    }
}

fn directory(path: &'static str) -> crate::rootfs::RootFile {
    crate::rootfs::RootFile {
        path,
        mode: 0o755,
        uid: 0,
        gid: 0,
        source: None,
    }
}

/// The lower files of the race probe: three of 3 MiB to rename and fourteen of 1 MiB to write.
pub fn race_lower_files() -> Vec<crate::rootfs::RootFile> {
    let (large, small) = (big(RACE_BYTES), big(SMALL_BYTES));
    let mut files = vec![
        directory("/race"),
        pattern_file("/race/rc-a", 0o644, (0, 0), "lp-race-a", large),
        pattern_file("/race/rc-b", 0o644, (0, 0), "lp-race-b", large),
        pattern_file("/race/rc-c", 0o644, (0, 0), "lp-race-c", large),
    ];
    for path in RACE_MORE {
        files.push(pattern_file(path, 0o644, (0, 0), "lp-race-f", small));
    }
    files
}

/// The lower file of the probe of the full volume: 20 MiB on a volume of 16 MiB.
pub fn full_lower_files() -> Vec<crate::rootfs::RootFile> {
    vec![
        directory("/full"),
        pattern_file("/full/big", 0o644, (0, 0), "lp-full-big", big(FULL_BYTES)),
    ]
}

/// The lower files of the cut probe: a file to copy up and a file to rename, with owners and modes of
/// their own.
pub fn cut_lower_files() -> Vec<crate::rootfs::RootFile> {
    let bytes = big(CUT_BYTES);
    vec![
        directory("/cutup"),
        pattern_file("/cutup/a", 0o640, (1000, 100), "lp-cut-a", bytes),
        pattern_file("/cutup/b", 0o600, (1001, 101), "lp-cut-b", bytes),
    ]
}

fn small_disk(name: &str, bytes: u64) -> Result<Disk, String> {
    let disk = Disk(std::env::temp_dir().join(format!(
        "stafeto-layer-posix-{name}-{}-{}.img",
        std::process::id(),
        seq()
    )));
    crate::data_image::make_layer_posix_volume(&disk.0, bytes)?;
    Ok(disk)
}

/// Names that change during the copy of a rename: a name deleted, a name made, two renames of one
/// file, and more files than places in the table of copies.
pub fn copy_race(machine: &qemu::Machine) -> Result<(), String> {
    let disk = small_disk("race", RACE_DISK_BYTES)?;
    let (output, seconds) = boot_with(
        machine,
        Build {
            probe: &["phase-copyrace"],
            ..Build::default()
        },
        &disk,
        race_lower_files(),
        COPY_LIMIT,
    )?;
    read_checks(&output.lines, &RACE_CHECKS, PASSED_RACE)?;
    read_work_empty(&output.lines)?;
    qemu::expect_stopped_on(
        &output,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-posix copy race on {}: {} checks of names that change during a copy in {seconds} s: ok",
        machine.name,
        RACE_CHECKS.len()
    );
    Ok(())
}

/// A copy on a volume that is too small: ENOSPC for every waiter, the lower file whole, and a second
/// boot that finds `work/` empty (the copy left nothing).
pub fn copy_full(machine: &qemu::Machine) -> Result<(), String> {
    let disk = small_disk("full", FULL_DISK_BYTES)?;
    let (first, first_seconds) = boot_with(
        machine,
        Build {
            probe: &["phase-copyfull"],
            ..Build::default()
        },
        &disk,
        full_lower_files(),
        COPY_LIMIT,
    )?;
    read_checks(&first.lines, &FULL_CHECKS, PASSED_FULL)?;
    qemu::expect_stopped_on(
        &first,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    let (second, second_seconds) = boot_with(
        machine,
        Build {
            probe: &["phase-copyfullreread"],
            ..Build::default()
        },
        &disk,
        full_lower_files(),
        COPY_LIMIT,
    )?;
    read_checks(&second.lines, &FULL_REREAD_CHECKS, PASSED_FULL_REREAD)?;
    read_work_empty(&second.lines)?;
    qemu::expect_stopped_on(
        &second,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-posix copy full on {}: ENOSPC for the waiters of a copy of 20 MiB on 16 MiB in {first_seconds} s, the lower file whole and work/ empty on a second boot in {second_seconds} s: ok",
        machine.name
    );
    Ok(())
}

/// The points of the cut: the number, what has happened, whether the cut leaves a file in `work/` (the
/// points before the rename of the copy into the layer do), and whether the rename of `/cutup/b` is
/// done (the name found after the cut is the new one). Points 1 to 4 fire in the open of `/cutup/a`,
/// before the probe has begun the rename, so `/cutup/b` has its old name there; point 5 leaves the
/// copy under the old name (its mark is written, the move is not), and point 6 the new name.
pub const CUT_POINTS: [(u8, &str, bool, bool); 6] = [
    (1, "the file in work/ is made, no byte in it", true, false),
    (
        2,
        "the first cell of the file in work/ is written",
        true,
        false,
    ),
    (3, "the file in work/ is whole and closed", true, false),
    (4, "the copy is renamed into the layer", false, false),
    (5, "the old name of the rename is marked", false, false),
    (6, "the volume has the new name of the rename", false, true),
];

/// The names the probe found after a cut, from its line `cut found the old name N, the new name M`.
pub fn cut_found(lines: &[String]) -> Result<(bool, bool), String> {
    lines
        .iter()
        .find_map(|l| {
            let rest = l.split_once("cut found the old name ")?.1;
            let (old, new) = rest.split_once(", the new name ")?;
            Some((old.trim() == "1", new.trim() == "1"))
        })
        .ok_or_else(|| "the probe did not say which names it found".to_owned())
}

/// How many names `work/` held at the start of a boot, from the line of the layer service.
pub fn work_held(lines: &[String]) -> Result<usize, String> {
    if lines
        .iter()
        .any(|l| l.contains("layerd: work/ is empty at the start"))
    {
        return Ok(0);
    }
    lines
        .iter()
        .find_map(|l| {
            l.split_once("layerd: work/ held ")?
                .1
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .ok_or_else(|| "the layer service said nothing of work/ at its start".to_owned())
}

/// One point of the cut: the service stops at the point and the machine is killed, then the same disk
/// is started again with the verification.
fn cut_point(
    machine: &qemu::Machine,
    point: u8,
    what: &str,
    leaves: bool,
    moved: bool,
) -> Result<(), String> {
    let disk = small_disk(&format!("cut{point}"), CUT_DISK_BYTES)?;
    let at = point.to_string();
    let marker = format!("layerd: cut point {point}");
    let (cut, cut_seconds) = boot_until(
        machine,
        Build {
            probe: &["phase-cut"],
            layerd: &["probe-cut"],
            ..Build::default()
        },
        &disk,
        cut_lower_files(),
        LIMIT,
        &[("STAFETO_LAYERD_CUT_AT", &at)],
        &marker,
    )?;
    if !cut.stopped_on_marker {
        return Err(format!(
            "layer-cut {point}: the service never said {marker:?}: {:?}",
            cut.lines
                .iter()
                .filter(|l| l.contains("layer-posix:") || l.contains("layerd:"))
                .collect::<Vec<_>>()
        ));
    }
    let (verify, verify_seconds) = boot_until(
        machine,
        Build {
            probe: &["phase-cutverify"],
            ..Build::default()
        },
        &disk,
        cut_lower_files(),
        LIMIT,
        &[],
        ENDS,
    )
    .map_err(|e| format!("layer-cut {point}: {e}"))?;
    read_checks(&verify.lines, &CUT_CHECKS, PASSED_CUT)
        .map_err(|e| format!("layer-cut {point} ({what}): {e}"))?;
    let found = cut_found(&verify.lines)?;
    if found != (!moved, moved) {
        return Err(format!(
            "layer-cut {point} ({what}): the probe found (old name, new name) {found:?}, {:?} were due",
            (!moved, moved)
        ));
    }
    let held = work_held(&verify.lines)?;
    if (held > 0) != leaves {
        return Err(format!(
            "layer-cut {point} ({what}): work/ held {held} names at the start of the next boot, {} were due",
            if leaves { "some" } else { "none" }
        ));
    }
    qemu::expect_stopped_on(
        &verify,
        "init: layer-posix ended: exit code 0, not restarted",
    )?;
    println!(
        "layer-cut copy {point}: cut when {what} ({cut_seconds} s), the old file or the new after it ({verify_seconds} s), work/ held {held}: ok"
    );
    Ok(())
}

/// `cargo xtask layer-cut copy [point]`: the power cut during a copy up and between the steps of the
/// rename of a lower file.
pub fn cut_command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args {
        [what] if what == "copy" => {
            for (point, what, leaves, moved) in CUT_POINTS {
                cut_point(machine, point, what, leaves, moved)?;
            }
            Ok(())
        }
        [what, point] if what == "copy" => {
            let point: u8 = point
                .parse()
                .map_err(|_| format!("layer-cut copy: {point} is not a point"))?;
            let (_, what, leaves, moved) = CUT_POINTS
                .iter()
                .copied()
                .find(|(p, _, _, _)| *p == point)
                .ok_or_else(|| format!("layer-cut copy: no point {point}"))?;
            cut_point(machine, point, what, leaves, moved)
        }
        _ => Err("layer-cut copy [point 1 to 6]".to_owned()),
    }
}

/// The break of the cut probe: the worker makes the copy at its final name, so a cut leaves a partial
/// file under the name.
pub const CUT_BREAK: (&str, u8) = ("break-layerd-copy-rename-open", 2);

/// `cargo xtask layer-cut breaks`: the break that makes the copy visible before its end must fail the
/// verification of a cut in the middle of the copy.
pub fn cut_breaks(machine: &qemu::Machine) -> Result<(), String> {
    let (feature, point) = CUT_BREAK;
    let disk = small_disk("cutbreak", CUT_DISK_BYTES)?;
    let at = point.to_string();
    let marker = format!("layerd: cut point {point}");
    let layerd: &'static [&'static str] = Box::leak(vec!["probe-cut", feature].into_boxed_slice());
    let (cut, _) = boot_until(
        machine,
        Build {
            probe: &["phase-cut"],
            layerd,
            ..Build::default()
        },
        &disk,
        cut_lower_files(),
        LIMIT,
        &[("STAFETO_LAYERD_CUT_AT", &at)],
        &marker,
    )?;
    if !cut.stopped_on_marker {
        return Err(format!(
            "layer-cut breaks: {feature}: no cut at point {point}"
        ));
    }
    let (verify, seconds) = boot_until(
        machine,
        Build {
            probe: &["phase-cutverify"],
            layerd,
            ..Build::default()
        },
        &disk,
        cut_lower_files(),
        LIMIT,
        &[],
        ENDS,
    )?;
    let mine = mine(&verify.lines);
    if mine.iter().any(|l| *l == &PASSED_CUT[PREFIX.len()..]) {
        return Err(format!(
            "layer-cut breaks: {feature} did not fail the verification"
        ));
    }
    let wanted = format!("{} FAILED", CUT_CHECKS[0]);
    if !mine.iter().any(|l| l.starts_with(&wanted)) {
        return Err(format!(
            "layer-cut breaks: {feature} did not fail {:?}; the lines: {mine:?}",
            CUT_CHECKS[0]
        ));
    }
    println!(
        "layer-cut breaks: {feature} is caught by {:?} after a cut at point {point} (in {seconds} s)",
        CUT_CHECKS[0]
    );
    Ok(())
}

pub fn cut(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("breaks") if args.len() == 1 => cut_breaks(machine),
        _ => cut_command(args, machine),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(names: &[&str]) -> Vec<String> {
        let mut v = vec!["layerd: root registered with the process service".to_owned()];
        v.extend(names.iter().map(|n| format!("{PREFIX}{n}")));
        v
    }

    fn all_ok() -> Vec<String> {
        let mut names: Vec<String> = CHECKS.iter().map(|c| format!("{c} ok")).collect();
        names.push(PASSED[PREFIX.len()..].to_owned());
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        lines(&refs)
    }

    #[test]
    fn a_run_with_every_check_in_order_and_the_end_passes() {
        assert_eq!(read_lines(&all_ok()), Ok(()));
    }

    #[test]
    fn a_failed_check_a_missing_check_or_a_missing_end_fails() {
        let mut v = all_ok();
        v.insert(3, format!("{PREFIX}a lower file is read FAILED"));
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.insert(3, format!("{PREFIX}check failed at line 9: x (errno 2)"));
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.remove(4);
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.pop();
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.swap(2, 3);
        assert!(read_lines(&v).is_err());
        let mut v = all_ok();
        v.remove(0);
        assert!(read_lines(&v).is_err(), "no root registered");
    }

    #[test]
    fn the_output_of_the_shell_is_read_line_by_line() {
        let long = |mode: &str, size: &str, name: &str| format!("{mode}    1 {size:>9} {name}");
        let mut lines: Vec<String> = vec![
            "layer-shell-ready".into(),
            "datafs: first walk made by a request, 32 blocks used".into(),
        ];
        lines.push(long("-rw-------", "80", "shadow"));
        lines.push(long("-rw-r-----", "25", "layer-own"));
        lines.push(long("-rw-r--r--", "11", "layer-note"));
        lines.push(long("-rw-r--r--", "13", "layer-world"));
        lines.push(long("-rw-------", "7", "layer-secret"));
        lines.push(long("-rw-r--r--", "13", "layer-lower"));
        lines.push(long("drwxr-xr-x", "0", ".."));
        lines.push(long("drwxr-xr-x", "0", "."));
        for l in [
            "lower of etc",
            "owned bytes of the layer",
            "upper shadow",
            "hidden-gone",
            "f19",
            "f18",
            "f17",
            "f16",
            "own",
            "c",
            "b",
            "a",
            "a",
            "tmp-bytes",
            "ash: can't create /bin/busybox-probe: Read-only file system",
            "write-refused",
            "mv-refused",
            "moved-none",
            "program-kept",
        ] {
            lines.push(l.to_owned());
        }
        assert_eq!(read_ash(&lines), Ok(()));
        // The deleted name in the listing, a name twice, a missing name, a size that is not the
        // layer's, a lower name that stayed hidden, and a write that went through each fail it.
        let mut bad = lines.clone();
        bad.insert(3, long("-rw-r--r--", "20", "layer-hidden"));
        assert!(read_ash(&bad).is_err());
        let mut bad = lines.clone();
        bad.insert(3, long("-rw-r--r--", "13", "layer-lower"));
        assert!(read_ash(&bad).is_err());
        let mut bad = lines.clone();
        bad.remove(4);
        assert!(read_ash(&bad).is_err());
        let mut bad = lines.clone();
        bad[3] = long("-rw-r-----", "99", "layer-own");
        assert!(read_ash(&bad).is_err());
        let mut bad = lines.clone();
        bad.retain(|l| l != "f17");
        assert!(read_ash(&bad).is_err());
        let mut bad = lines.clone();
        bad.retain(|l| l != "write-refused");
        assert!(read_ash(&bad).is_err());
        assert!(read_ash(&lines[1..]).is_err());
    }

    #[test]
    fn jobs_that_run_side_by_side_never_share_a_disk() {
        // The jobs of one `xtask ci` run in threads of one process: the name of the
        // disk of a run is its own (a shared disk made QEMU fail to get its write lock).
        let names: Vec<(String, std::path::PathBuf)> = std::thread::scope(|scope| {
            let runs: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let disk = new_disk().unwrap();
                        (format!("{}", seq()), disk.0.clone())
                    })
                })
                .collect();
            runs.into_iter().map(|run| run.join().unwrap()).collect()
        });
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                assert_ne!(a.0, b.0);
                assert_ne!(a.1, b.1);
            }
        }
    }

    #[test]
    fn every_break_names_a_check_of_the_probe() {
        for (feature, program, check) in BREAKS {
            assert!(CHECKS.contains(&check), "{feature}");
            assert!(feature.starts_with("break-layer") || feature == "break-datafs-layers-visible");
            assert!(
                ["layer-posix", "ramfs", "loader", "datafsd"].contains(&program),
                "{feature}"
            );
        }
        // The checks of the file are the checks of the C program, each once.
        let source = include_str!("../../tests/layer-posix/layer.c");
        for check in CHECKS
            .iter()
            .chain(&WRITE_CHECKS)
            .chain(&REREAD_CHECKS)
            .chain(&COPY_CHECKS)
            .chain(&COPY_REREAD_CHECKS)
            .chain(&RACE_CHECKS)
            .chain(&FULL_CHECKS)
            .chain(&FULL_REREAD_CHECKS)
            .chain(&CUT_CHECKS)
        {
            let quoted = format!("run_check(\"{check}\"");
            assert_eq!(source.matches(&quoted).count(), 1, "{check}");
        }
        assert_eq!(
            source.matches("run_check(\"").count(),
            CHECKS.len()
                + WRITE_CHECKS.len()
                + REREAD_CHECKS.len()
                + COPY_CHECKS.len()
                + COPY_REREAD_CHECKS.len()
                + RACE_CHECKS.len()
                + FULL_CHECKS.len()
                + FULL_REREAD_CHECKS.len()
                + CUT_CHECKS.len()
        );
        // The breaks of the copy probe name checks of its phase.
        for (feature, checks) in COPY_BREAKS {
            assert!(
                feature.starts_with("break-layerd-copy-")
                    || feature.starts_with("break-layerd-rename-"),
                "{feature}"
            );
            for check in checks {
                assert!(COPY_CHECKS.contains(check), "{feature}: {check}");
            }
        }
        // The cut points are numbered as the service numbers them, and the break of the cut probe
        // names the first check of the verification.
        let points: Vec<u8> = CUT_POINTS.iter().map(|p| p.0).collect();
        assert_eq!(points, [1, 2, 3, 4, 5, 6]);
        assert!(CUT_POINTS.iter().filter(|p| p.2).count() == 3);
        assert_eq!(CUT_POINTS.iter().filter(|p| p.3).count(), 1);
        assert_eq!(
            cut_found(&["layer-posix: cut found the old name 0, the new name 1".to_owned()]),
            Ok((false, true))
        );
        assert!(CUT_BREAK.0.starts_with("break-layerd-copy-"));
        // The breaks of the write probe name a check of its phase.
        for (feature, reread, check) in WRITE_BREAKS {
            let checks: &[&str] = if reread {
                &REREAD_CHECKS
            } else {
                &WRITE_CHECKS
            };
            assert!(checks.contains(&check), "{feature}");
            assert!(feature.starts_with("break-layerd-"));
        }
    }

    fn copy_lines(read: [u32; 2], two: [u32; 2], last: [u32; 4]) -> Vec<String> {
        let line = |what: &str, c: [u32; 4]| {
            format!(
                "layerd: copies {what}: {} reserved, {} made visible, {} dropped, {} failed",
                c[0], c[1], c[2], c[3]
            )
        };
        let mark = |name: &str| format!("{PREFIX}marker {name}");
        vec![
            line("queued", [3, 2, 0, 0]),
            mark("read-begin"),
            line("over", [read[0], 2, 0, 0]),
            mark("read-end"),
            mark("deny-begin"),
            mark("deny-end"),
            line("queued", [two[0], 2, 0, 0]),
            mark("two-begin"),
            line("queued", [two[1], 2, 0, 0]),
            mark("two-end"),
            line("over", last),
        ]
    }

    #[test]
    fn the_counts_of_the_copies_say_a_read_made_none_and_two_writers_made_one() {
        let last = [COPIES_RESERVED, COPIES_MADE_VISIBLE, 0, COPIES_FAILED];
        assert_eq!(read_copy_counts(&copy_lines([3, 3], [4, 5], last)), Ok(()));
        // A read that reserved a copy, and two writers that reserved two, fail it.
        let err = read_copy_counts(&copy_lines([4, 0], [4, 5], last)).unwrap_err();
        assert!(err.contains("read open"), "{err}");
        let err = read_copy_counts(&copy_lines([3, 3], [4, 6], last)).unwrap_err();
        assert!(err.contains("two writers"), "{err}");
        // Two writers that made none are no better.
        assert!(read_copy_counts(&copy_lines([3, 3], [4, 4], last)).is_err());
        // The end of the run is the count of the checks.
        assert!(read_copy_counts(&copy_lines([3, 3], [4, 5], [14, 10, 0, 5])).is_err());
        assert!(read_copy_counts(&copy_lines([3, 3], [4, 5], [15, 9, 1, 5])).is_err());
        // No marker is no proof.
        assert!(read_copy_counts(&[]).is_err());
    }

    #[test]
    fn the_lower_files_of_the_copy_probe_are_in_ascending_order_and_have_the_sizes_the_probe_says()
    {
        let files = copy_lower_files();
        let paths: Vec<&str> = files.iter().map(|f| f.path).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        assert_eq!(paths.first(), Some(&"/copyup"));
        // The file names of the sources of one image are all different and short.
        let mut names: Vec<String> = files
            .iter()
            .filter_map(|f| f.source.as_ref().map(crate::rootfs::Source::file_name))
            .collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        assert!(names.iter().all(|n| n.len() <= bootimg::NAME_MAX));
        // The bytes of the big file are the ones layer.c compares: the first byte and one past the
        // middle.
        assert_eq!(big_byte(0), 1);
        let source = include_str!("../../tests/layer-posix/layer.c");
        assert!(source.contains("#define BIG_BYTES (16UL << 20)"));
        assert!(source.contains("#define TWO_BYTES (3UL << 20)"));
        assert!(source.contains("(unsigned char)(((i) * 7 + ((i) >> 12)) | 1)"));
        assert_eq!(BIG_BYTES, 16 << 20);
        assert_eq!(TWO_BYTES, 3 << 20);
        assert_eq!(big_byte(4096), ((4096 * 7 + 1) | 1) as u8);
    }

    #[test]
    fn the_image_has_the_layer_service_after_the_data_service_and_before_the_probe() {
        let p = plain_programs();
        let at = |name: &str| p.iter().position(|x| x.0 == name).unwrap();
        assert!(at("datafsd") < at("layerd") && at("layerd") < at("layer-posix"));
    }
}
