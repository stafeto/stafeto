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
    "the lower set is not written",
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
        Some(other) => Err(format!(
            "layer-posix [breaks | ash | write [breaks]]: unknown argument {other}"
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
    let image = write_boot_image_files(ASH_IMAGE, &ash_programs(), BOOT_PROFILE, &[], Vec::new())?;
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
    if !got[after.len()..].iter().any(|l| l == "write-refused") {
        return Err(format!(
            "the shell wrote below the layers: {:?}",
            &got[after.len()..]
        ));
    }
    Ok(())
}

/// A disk for a run: the volume of the probe, made offline.
fn new_disk() -> Result<Disk, String> {
    let disk =
        Disk(std::env::temp_dir().join(format!("stafeto-layer-posix-{}.img", std::process::id())));
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
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = write_boot_image_files(IMAGE, &programs(with), BOOT_PROFILE, &[], Vec::new())?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    let started = std::time::Instant::now();
    let output = run_until(cmd, LIMIT, Some(ENDS), &kernel.elf)?;
    Ok((output, started.elapsed().as_secs()))
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
            "ash: can't create /etc/layer-lower: Read-only file system",
            "write-refused",
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
        for check in CHECKS.iter().chain(&WRITE_CHECKS).chain(&REREAD_CHECKS) {
            let quoted = format!("run_check(\"{check}\"");
            assert_eq!(source.matches(&quoted).count(), 1, "{check}");
        }
        assert_eq!(
            source.matches("run_check(\"").count(),
            CHECKS.len() + WRITE_CHECKS.len() + REREAD_CHECKS.len()
        );
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

    #[test]
    fn the_image_has_the_layer_service_after_the_data_service_and_before_the_probe() {
        let p = plain_programs();
        let at = |name: &str| p.iter().position(|x| x.0 == name).unwrap();
        assert!(at("datafsd") < at("layerd") && at("layerd") < at("layer-posix"));
    }
}
