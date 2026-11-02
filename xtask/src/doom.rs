// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The games image (`boot-doom.img`): the shell's image with Doomgeneric
//! (`/bin/doom`) and the Freedoom data (`/games/freedoom1.wad`), and the
//! probe `doom-headless`, which plays the demo of Freedoom from ash without a
//! screen: `doom -iwad /games/freedoom1.wad -timedemo demo1 -nodraw`.

use super::*;
use std::time::Instant;

/// The image of the games.
const IMAGE: &str = "boot-doom.img";
/// The WAD's name in the image and the licence files it carries.
const WAD: &str = "freedoom1.wad";
/// Doomgeneric's and Freedoom's licences and the notes of their sources in
/// an image.
const DOOM_LICENSE: &str = "DOOM-LICENSE";
const DOOM_SOURCE: &str = "DOOM-SOURCE";
const FREEDOOM_LICENSE: &str = "FREEDOOM-LICENSE";
const FREEDOOM_SOURCE: &str = "FREEDOOM-SOURCE";
/// How long the demo may take: Doom plays it as fast as the machine goes,
/// and a slow runner is some ten times slower than a quiet Mac.
const TIMEDEMO: Duration = Duration::from_secs(300);
/// The line of Doom's report, which it prints as its error and leaves with.
const REPORT: &str = "timed ";

/// The programs of the games image: those of the shell image, with the
/// table of init that gives the launcher the quota of Doom, and Doom.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let packages =
            packages::of_image(IMAGE).unwrap_or_else(|e| panic!("the games image: {e}"));
        let mut programs = SHELL_SERVICES.to_vec();
        programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-doom"]);
        for program in packages.iter().filter_map(|p| p.program.as_deref()) {
            let entry = PACKAGE_PROGRAMS
                .iter()
                .find(|p| p.0 == program)
                .unwrap_or_else(|| panic!("no build of the program {program} (PACKAGE_PROGRAMS)"));
            programs.push(*entry);
        }
        programs.extend(SHELL_SERVICES_LAST);
        programs
    })
}

/// The scripts of the games built, once in a run of xtask: Doomgeneric and
/// Freedoom come after the add-ons the image holds with them.
pub fn build_games() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    packages_built(packages::Kind::Game)
}

/// The licence texts of Doomgeneric and Freedoom and the notes of their
/// exact sources: (Doomgeneric's licence, its note, Freedoom's licence, its
/// note).
pub fn doom_terms() -> Result<(Vec<u8>, String, Vec<u8>, String), String> {
    let doom = packages::value("doomgeneric", "version")?;
    let doom_sha256 = packages::value("doomgeneric", "sha256")?;
    let doom_url = packages::value("doomgeneric", "url")?;
    let freedoom = packages::value("freedoom", "version")?;
    let freedoom_sha256 = packages::value("freedoom", "sha256")?;
    let freedoom_url = packages::value("freedoom", "url")?;
    let read = |path: PathBuf| std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()));
    let doom_licence = read(target_dir().join(format!("doomgeneric/doomgeneric-{doom}/LICENSE")))?;
    let freedoom_licence = read(target_dir().join(format!("freedoom/freedoom-{freedoom}/COPYING.txt")))?;
    let relibc = script_value("tools/build-relibc.py", "COMMIT")?;
    let doom_note = format!(
        "doom holds Doomgeneric, commit {doom} of https://github.com/ozkl/doomgeneric,\n\
         the Doom source port with a small platform interface; the Doom source is\n\
         Copyright (C) id Software, Inc. and the contributors of Chocolate Doom.\n\
         Licensed under GPLv2 or later (DOOM-LICENSE).\n\n\
         Its source: {doom_url}\n\
         (SHA-256 {doom_sha256}), built unchanged by tools/build-doomgeneric.py\n\
         with the platform file ports/doomgeneric/doomgeneric_stafeto.c\n\
         of https://github.com/stafeto/stafeto at commit {}; linked with relibc\n\
         https://github.com/stafeto/relibc at commit {relibc}\n\
         (THIRD-PARTY-NOTICES).\n",
        rtbench2::commit()
    );
    let freedoom_note = format!(
        "/games/{WAD} is the Phase 1 WAD of Freedoom {freedoom}, Copyright (C) the\n\
         Freedoom project contributors. Licensed under the BSD 3-clause licence\n\
         (FREEDOOM-LICENSE, the COPYING.txt of the release).\n\n\
         Its source: {freedoom_url}\n\
         (SHA-256 {freedoom_sha256}), put in the image unchanged by\n\
         tools/build-freedoom.py.\n"
    );
    Ok((doom_licence, doom_note, freedoom_licence, freedoom_note))
}

/// The files of the games' terms for an image whose programs include Doom:
/// the names and the bytes, to go in the image's list.
pub fn terms_files() -> Result<[(&'static str, Vec<u8>); 4], String> {
    let (doom_licence, doom_note, freedoom_licence, freedoom_note) = doom_terms()?;
    Ok([
        (DOOM_LICENSE, doom_licence),
        (DOOM_SOURCE, doom_note.into_bytes()),
        (FREEDOOM_LICENSE, freedoom_licence),
        (FREEDOOM_SOURCE, freedoom_note.into_bytes()),
    ])
}

/// Fails unless the boot image at `path` carries the terms of the games and
/// the WAD that `tools/build-freedoom.py` unpacked, whole.
fn image_has_doom_terms(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let version = packages::value("freedoom", "version")?;
    let wad_path = target_dir().join(format!("freedoom/freedoom-{version}/{WAD}"));
    let wad = std::fs::read(&wad_path).map_err(|e| format!("{}: {e}", wad_path.display()))?;
    let carries = |name: &str, check: &dyn Fn(&[u8]) -> bool| {
        image
            .files()
            .any(|file| file.name == name && check(file.data))
    };
    let mentions = |data: &[u8], text: &str| data.windows(text.len()).any(|w| w == text.as_bytes());
    let (licence, _, freedoom_licence, _) = doom_terms()?;
    let doom = packages::value("doomgeneric", "version")?;
    if !wad.is_empty()
        && carries(WAD, &|data| data == wad.as_slice())
        && carries(DOOM_LICENSE, &|data| data == licence.as_slice())
        && carries(DOOM_SOURCE, &|data| mentions(data, &doom) && mentions(data, "GPLv2"))
        && carries(FREEDOOM_LICENSE, &|data| data == freedoom_licence.as_slice())
        && carries(FREEDOOM_SOURCE, &|data| mentions(data, &version))
    {
        Ok(())
    } else {
        Err(format!(
            "{} carries no whole WAD or no terms of the games",
            path.display()
        ))
    }
}

/// The number after `timed ` in the report `timed N gametics in M realtics`
/// and the one after `gametics in `.
fn report_numbers(line: &str) -> Option<(u64, u64)> {
    let rest = line.split(REPORT).nth(1)?;
    let (tics, rest) = rest.split_once(" gametics in ")?;
    let (real, _) = rest.split_once(" realtics")?;
    Some((tics.trim().parse().ok()?, real.trim().parse().ok()?))
}

/// `cargo xtask doom-headless [MACHINE]`: Doom plays the demo of Freedoom
/// from ash on a machine with no screen.
pub fn doom_headless(machine: &'static qemu::Machine) -> Result<(), String> {
    build_games()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    image_has_doom_terms(&image)?;
    packages::check()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // The WAD is a file of the image.
        run.send(&format!("ls -l /games/{WAD}"))?;
        run.expect_line(
            "the WAD in /games",
            |l| l.contains(&format!("/games/{WAD}")) && l.starts_with('-'),
            DIALOG_STEP,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        run.send(&format!(
            "doom -iwad /games/{WAD} -timedemo demo1 -nodraw"
        ))?;
        run.expect("W_Init: Init WADfiles.", DIALOG_STEP)?;
        run.expect("ST_Init", TIMEDEMO)?;
        let report = run.expect_line(
            "the report of the demo",
            |l| report_numbers(l).is_some(),
            TIMEDEMO,
        )?;
        let (tics, real) = report_numbers(&report).unwrap_or_default();
        if tics == 0 {
            return Err(format!("the demo played no tics: {report}"));
        }
        // Doom left, and ash prompts again.
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo ash-is-back")?;
        run.expect_line("ash after Doom", |l| l == "ash-is-back", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        println!(
            "doom-headless: {tics} gametics in {real} realtics, {:.1} s from the command to the prompt",
            started.elapsed().as_secs_f64()
        );
        // Ctrl-D on an empty line ends ash.
        run.type_raw(b"\x04")?;
        run.expect(
            "init: busybox-probe ended: exit code 0, not restarted",
            DIALOG_STEP,
        )
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("I/O error")
    }) {
        return Err("the games image faulted".into());
    }
    let size = |program: &str| -> Result<u64, String> {
        let elf = image_elf(&target_dir(), IMAGE, program);
        std::fs::metadata(&elf)
            .map(|m| m.len())
            .map_err(|e| format!("{}: {e}", elf.display()))
    };
    let image_size = std::fs::metadata(&image)
        .map(|m| m.len())
        .map_err(|e| format!("{}: {e}", image.display()))?;
    println!(
        "doom-headless passed: doom {} bytes, WAD {} bytes, image {} bytes",
        size("doom")?,
        freedoom_size()?,
        image_size
    );
    Ok(())
}

/// The size of the WAD in the image.
fn freedoom_size() -> Result<u64, String> {
    let version = packages::value("freedoom", "version")?;
    let path = target_dir().join(format!("freedoom/freedoom-{version}/{WAD}"));
    std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_of_the_demo_reads() {
        assert_eq!(
            report_numbers("Error: timed 2154 gametics in 612 realtics"),
            Some((2154, 612))
        );
        assert_eq!(report_numbers("timed 0 gametics in 0 realtics"), Some((0, 0)));
        assert_eq!(report_numbers("W_Init: Init WADfiles."), None);
        assert_eq!(report_numbers("timed N gametics in M realtics"), None);
    }

    #[test]
    fn the_games_image_runs_doom_on_the_table_of_its_quota() {
        let doom = programs().iter().find(|p| p.0 == "init").unwrap();
        assert_eq!(doom.3, &["table-doom"]);
        assert!(programs().iter().any(|p| p.0 == "doom" && p.3.contains(&"dynamic")));
        assert!(shell_programs().iter().all(|p| p.0 != "doom"));
    }
}
