// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The games image (`boot-doom.img`): the shell's image with Doomgeneric
//! (`/bin/doom`), the Freedoom data (`/games/freedoom1.wad`) and the services
//! of the screen and the keys (virtio-gpu, virtio-input). Three commands
//! run it:
//!
//! - `doom-headless`, which plays the demo of Freedoom from ash with a screen
//!   nobody looks at: `doom -iwad /games/freedoom1.wad -timedemo demo1
//!   -nodraw`;
//! - `doom-probe` (spec 3, 9.2), the probe of the goal: Doom from ash opens
//!   the first level, takes keys, and ash prompts again after it;
//! - `doom`, which opens the window of QEMU for a person to play in.

use super::*;
use crate::gpu_probe::{self, Scratch};
use crate::monitor::{Monitor, Ppm};
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
/// table of init that gives the launcher the quota of Doom, the services of
/// the screen and the keys, and Doom. The display service is built without
/// the method CRASH, which only the images of the probes have.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| image_programs(&[]))
}

/// The programs of the image of the measures (`boot-doom-steps.img`): the
/// games image whose services of the screen and the keys count their steps.
pub fn steps_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| image_programs(&["steps"]))
}

/// The programs of the games image, the services of the screen and the keys
/// built with `features` besides (the image of the measures counts their
/// steps).
fn image_programs(features: &'static [&'static str]) -> Vec<ImageProgram> {
    let packages = packages::of_image(IMAGE).unwrap_or_else(|e| panic!("the games image: {e}"));
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
    programs.push((
        "virtio-input",
        "virtio-input",
        input_probe::INPUT_STACK_SIZE,
        features,
    ));
    programs.push((
        "virtio-gpu",
        "virtio-gpu",
        gpu_probe::GPU_STACK_SIZE,
        features,
    ));
    programs
}

/// The scripts of the games built, once in a run of xtask: Doomgeneric and
/// Freedoom come after the add-ons the image holds with them.
pub fn build_games() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    packages_built(&[packages::Group::Game])
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
    let doom_licence = crate::notices::licence_text("doomgeneric")?;
    let freedoom_licence = crate::notices::licence_text("freedoom")?;
    let relibc = script_value("tools/build-relibc.py", "COMMIT")?;
    let doom_note = format!(
        "doom holds Doomgeneric, commit {doom} of https://github.com/ozkl/doomgeneric,\n\
         the Doom source port with a small platform interface; the Doom source is\n\
         Copyright (C) id Software, Inc. and the contributors of Chocolate Doom.\n\
         Licensed under GPLv2 or later (DOOM-LICENSE).\n\n\
         Its source: {doom_url}\n\
         (SHA-256 {doom_sha256}), built unchanged by tools/build-doomgeneric.py\n\
         with the platform files ports/doomgeneric/doomgeneric_stafeto.c and keys.c\n\
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
        && carries(DOOM_SOURCE, &|data| {
            mentions(data, &doom) && mentions(data, "GPLv2")
        })
        && carries(FREEDOOM_LICENSE, &|data| {
            data == freedoom_licence.as_slice()
        })
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
    cmd.args(qemu::GPU);
    cmd.args(qemu::KEYBOARD);
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
        run.send(&format!("doom -iwad /games/{WAD} -timedemo demo1 -nodraw"))?;
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
        // Doom left through I_Error with 255, and ash prompts again.
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo rc=$?")?;
        run.expect_line("the exit code of Doom", |l| l == "rc=255", DIALOG_STEP)?;
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

/// The line of the title screen: Doom prints it when the first frame of
/// the title is on the screen, with the CRC-32 of its red, green and blue
/// bytes.
const TITLE: &str = "doom: title crc32 ";
/// The line of the first level (episode 1, map 1).
const LEVEL: &str = "doom: level 1 1";
/// The command the probe types.
const LAUNCH: &str = "doom -iwad /games/freedoom1.wad";
/// Between two keys the probe sends: the machine under TCG needs the time
/// to draw the menu.
const KEY_PAUSE: Duration = Duration::from_millis(500);
/// How long the title may take to come after the command: Doom reads the
/// WAD's directory and the lumps it needs, on a slow runner.
const TITLE_WITHIN: Duration = Duration::from_secs(45);
/// The whole probe may take this long (spec 3, 9.2); a slow runner that
/// takes more fails the probe instead of eating the reserve of the job.
const PROBE_WITHIN: Duration = Duration::from_secs(180);
/// How long the first level may take to come after the last key of the menu.
const LEVEL_WITHIN: Duration = Duration::from_secs(30);
/// The colours a level's picture has at least (a blank or banded screen
/// has few).
const COLOURS_MIN: usize = 64;
/// The share of points, in thousandths, in which the picture after a turn
/// differs from the one before: a turn changes almost the whole view, the
/// animated floors of E1M1 without input about 5 %.
const TURN_MIN: usize = 300;

/// The title screen: the size of the screen.
fn check_size(shot: &Ppm, what: &str) -> Result<(), String> {
    if (shot.width, shot.height) == (640, 400) {
        Ok(())
    } else {
        Err(format!(
            "{what}: the screenshot is {}x{}, 640x400 expected",
            shot.width, shot.height
        ))
    }
}

/// The picture of the first level: the screen's size and not fewer than
/// COLOURS_MIN colours.
fn check_level(shot: &Ppm) -> Result<usize, String> {
    check_size(shot, "the level")?;
    let colours = shot.colours();
    if colours < COLOURS_MIN {
        return Err(format!(
            "the level's picture has {colours} colours, {COLOURS_MIN} expected"
        ));
    }
    Ok(colours)
}

/// The picture after the turn against the one before: they differ in
/// TURN_MIN thousandths of the points at least. The share is the result.
fn check_turn(before: &Ppm, after: &Ppm) -> Result<usize, String> {
    check_size(after, "the turn")?;
    let differs = after.differs_from(before);
    if differs < TURN_MIN {
        return Err(format!(
            "after the turn the picture differs in {differs} thousandths of the points, {TURN_MIN} expected"
        ));
    }
    Ok(differs)
}

/// The whole probe within PROBE_WITHIN.
fn check_time(took: Duration, machine: &str) -> Result<(), String> {
    if took > PROBE_WITHIN {
        return Err(format!(
            "doom-probe on {machine}: {:.0} s, {} s expected at most",
            took.as_secs_f64(),
            PROBE_WITHIN.as_secs()
        ));
    }
    Ok(())
}

/// The lines of a finished run that say the image faulted.
fn faulted(lines: &[String]) -> Option<&String> {
    lines.iter().find(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("I/O error")
    })
}

/// The command line of a run with a screen nobody looks at, a serial line on
/// stdio and the monitor on the socket of `scratch`.
fn probe_command(
    machine: &qemu::Machine,
    kernel: &Path,
    image: &Path,
    scratch: &Scratch,
) -> Command {
    let mut cmd = qemu::command(machine, kernel, Some(image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(qemu::GPU);
    cmd.args(qemu::KEYBOARD);
    cmd
}

/// What the probe measured on the way.
struct Seen {
    /// Seconds from the command to the title, and to the first level.
    title: f64,
    level: f64,
    /// The colours of the level's picture and the share of points the turn
    /// changed, in thousandths.
    colours: usize,
    turned: usize,
}

/// Follows the run through steps 1 to 6 of spec 3, 9.2.
fn drive(run: &mut qemu::Run, scratch: &Scratch) -> Result<Seen, String> {
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let picture = scratch.picture();
    run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
    run.expect("# ", DIALOG_STEP)?;
    // 1 and 2: the title screen is on the screen as the guest drew it.
    run.send(LAUNCH)?;
    let began = Instant::now();
    let line = run.expect_line("the title screen", |l| l.contains(TITLE), TITLE_WITHIN)?;
    let title = began.elapsed().as_secs_f64();
    gpu_probe::compare(&mut monitor, &picture, &line, TITLE)?;
    // 3: the menu, New Game, the episode, the skill: the first level.
    let menu = Instant::now();
    std::thread::sleep(KEY_PAUSE);
    monitor.sendkeys(&["ret", "ret", "ret", "ret"], KEY_PAUSE)?;
    run.expect_line("the first level", |l| l.contains(LEVEL), LEVEL_WITHIN)?;
    let level = menu.elapsed().as_secs_f64();
    std::thread::sleep(Duration::from_secs(2));
    let before = monitor.screendump(&picture)?;
    let colours = check_level(&before)?;
    // 4: a turn, the key held for a second, changes the view.
    monitor.sendkey("left", Some(1000))?;
    std::thread::sleep(Duration::from_millis(2500));
    let after = monitor.screendump(&picture)?;
    let turned = check_turn(&before, &after)?;
    // 5: the menu, the cursor from New Game to Quit Game, the question
    // answered, ash again and Doom's code 0.
    monitor.sendkey("esc", None)?;
    std::thread::sleep(KEY_PAUSE);
    monitor.sendkeys(&["up", "ret", "y"], KEY_PAUSE)?;
    run.expect(gpu_probe::RELEASED, DIALOG_STEP * 3)?;
    run.send("echo rc=$?")?;
    run.expect_line("the exit code of Doom", |l| l == "rc=0", DIALOG_STEP)?;
    // 6: Doom again in the background holds the screen: a second one cannot
    // open it, says so and leaves with code 1. Then Doom in the foreground,
    // and Ctrl-C into the terminal gives the prompt and the screen back.
    run.expect("# ", DIALOG_STEP)?;
    run.send(&format!("{LAUNCH} &"))?;
    run.send("P=$!")?;
    run.expect_line(
        "the title screen of the first",
        |l| l.contains(TITLE),
        TITLE_WITHIN,
    )?;
    run.send(&format!("{LAUNCH}; echo busy=$?"))?;
    run.expect_line(
        "the refusal of a second Doom",
        |l| l == "busy=1",
        DIALOG_STEP * 3,
    )?;
    run.send("kill $P")?;
    run.expect(gpu_probe::RELEASED, DIALOG_STEP * 3)?;
    run.send("echo again")?;
    run.expect_line("ash after the kill", |l| l == "again", DIALOG_STEP)?;
    run.expect("# ", DIALOG_STEP)?;
    run.send(LAUNCH)?;
    run.expect_line(
        "the title screen again",
        |l| l.contains(TITLE),
        TITLE_WITHIN,
    )?;
    run.type_raw(b"\x03")?;
    run.expect(gpu_probe::RELEASED, DIALOG_STEP * 3)?;
    run.send("echo ash-is-back")?;
    run.expect_line("ash after Ctrl-C", |l| l == "ash-is-back", DIALOG_STEP)?;
    Ok(Seen {
        title,
        level,
        colours,
        turned,
    })
}

/// `cargo xtask doom-probe [MACHINE]` (spec 3, 9.2): the goal. From ash,
/// `doom -iwad /games/freedoom1.wad` shows the title screen (the screenshot
/// of QEMU has the CRC the guest computed), takes the keys of the menu to
/// the first level, which a turn changes, and leaves through the menu with
/// code 0 and the prompt of ash; a second run ends by Ctrl-C and ash
/// prompts again.
pub fn doom_probe(machine: &'static qemu::Machine) -> Result<(), String> {
    build_games()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    image_has_doom_terms(&image)?;
    packages::check()?;
    let scratch = Scratch::new()?;
    let cmd = probe_command(machine, &kernel.image, &image, &scratch);
    // The time of the probe is that of the machine, not of the build.
    let began = Instant::now();
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let driven = drive(&mut run, &scratch);
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    let seen = driven.map_err(|e| format!("doom-probe on {}: {e}", machine.name))?;
    check_time(began.elapsed(), machine.name)?;
    if let Some(line) = faulted(&output.lines) {
        return Err(format!(
            "doom-probe on {}: the games image faulted: {line}",
            machine.name
        ));
    }
    let released = output
        .lines
        .iter()
        .filter(|l| l.as_str() == gpu_probe::RELEASED)
        .count();
    if released != 3 {
        return Err(format!(
            "doom-probe on {}: the screen went back {released} times, 3 expected",
            machine.name
        ));
    }
    println!(
        "doom-probe on {}: the title screen matched QEMU's screenshot ({:.1} s), the menu led to E1M1 in {:.1} s ({} colours), a turn changed {:.1} % of the points, the menu left with code 0, a second Doom was refused with 1, Ctrl-C left too; {:.0} s in all",
        machine.name,
        seen.title,
        seen.level,
        seen.colours,
        seen.turned as f64 / 10.0,
        began.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The machine a person plays on: `--machine hvf` (Apple's Hypervisor, the
/// fast one on a Mac), `--machine tcg` (QEMU's own emulation, the default),
/// or the name of a machine of `qemu::MACHINES`.
fn player_machine(args: &[String]) -> Result<&'static qemu::Machine, String> {
    match args {
        [] => Ok(&qemu::VIRT),
        [flag, name] if flag == "--machine" => match name.as_str() {
            "hvf" => Ok(&qemu::HVF_V3),
            "tcg" => Ok(&qemu::VIRT),
            other => qemu::machine(Some(&other.to_owned())),
        },
        _ => Err(format!("unknown arguments of doom: {args:?}\n\n{USAGE}")),
    }
}

/// `cargo xtask doom [--machine hvf]`: QEMU with the window of the screen
/// (cocoa on a Mac) and the console on the terminal, to play by hand. The
/// terminal is ash: `doom -iwad /games/freedoom1.wad` opens the game in the
/// window, which takes the keys while Doom owns the screen. Ctrl-A X in the
/// terminal quits QEMU.
pub fn doom_window(args: &[String]) -> Result<(), String> {
    let machine = player_machine(args)?;
    if machine.is_hvf() {
        hvf_host().map_err(|why| {
            format!(
                "--machine hvf needs macOS on Apple Silicon with the Hypervisor framework: {why}"
            )
        })?;
    }
    build_games()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    image_has_doom_terms(&image)?;
    packages::check()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    if cfg!(target_os = "macos") {
        cmd.args(["-display", "cocoa"]);
    }
    // The console on the terminal with Ctrl-A X to quit, as the interactive
    // ash has it; Ctrl-C reaches the guest.
    cmd.args([
        "-chardev",
        "stdio,id=console,mux=on,signal=off",
        "-serial",
        "chardev:console",
        "-mon",
        "chardev=console,mode=readline",
    ]);
    cmd.args(qemu::GPU);
    cmd.args(qemu::KEYBOARD);
    println!(
        "doom on {}: at the prompt of ash type `doom -iwad /games/{WAD}`; the game opens in the window, which takes the keys (arrows, Ctrl fire, Space use, Shift run, Esc menu); Ctrl-C in the terminal ends Doom; Ctrl-A X quits QEMU",
        machine.name
    );
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status()
        .map_err(|e| format!("{cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU exited with {status}"))
    }
}

/// The tags of the lines of steps of the display and the input service.
const GPU_TAG: &str = "12";
const INPUT_TAG: &str = "13";

/// The frames a second of a timed demo: its game tics over its real tics
/// (35 a second).
fn frames_per_second(tics: u64, real: u64) -> f64 {
    if real == 0 {
        return 0.0;
    }
    tics as f64 * 35.0 / real as f64
}

/// `cargo xtask doom-measure [MACHINE]` (part 5 of the stage): the numbers
/// of Doom with the screen. A run with the screen shows how much memory the
/// process has at the title and on the first level (`/proc/PID/status`), and
/// plays the demo with the screen, `-timedemo demo1`, for its frames a
/// second. On a machine under emulation a second run, under -icount with
/// the services counting their steps, measures the longest steps of the
/// display and the input service while Doom plays the same keys as the
/// probe; they are held to 0.9 of term B.
pub fn doom_measure(machine: &'static qemu::Machine) -> Result<(), String> {
    build_games()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let cmd = probe_command(machine, &kernel.image, &image, &scratch);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let measured = (|| {
        let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // In the background, so that ash answers while Doom runs.
        run.send(&format!("{LAUNCH} &"))?;
        run.send("P=$!")?;
        run.expect_line("the title", |l| l.contains(TITLE), TITLE_WITHIN)?;
        let mut memory = Vec::new();
        let mut read = |run: &mut qemu::Run, when: &str| -> Result<(), String> {
            run.send(
                "echo mem $(awk '$1==\"VmSize:\"||$1==\"VmRSS:\"{printf \"%s \",$2}' /proc/$P/status) $(cat /proc/$P/statm)",
            )?;
            let line = run.expect_line("the memory", |l| l.starts_with("mem "), DIALOG_STEP)?;
            memory.push(format!("{when}: {}", line.trim_start_matches("mem ")));
            Ok(())
        };
        read(&mut run, "title")?;
        std::thread::sleep(KEY_PAUSE);
        monitor.sendkeys(&["ret", "ret", "ret", "ret"], KEY_PAUSE)?;
        run.expect_line("the first level", |l| l.contains(LEVEL), LEVEL_WITHIN)?;
        std::thread::sleep(Duration::from_secs(2));
        read(&mut run, "E1M1")?;
        run.send("kill $P")?;
        run.expect(gpu_probe::RELEASED, DIALOG_STEP * 3)?;
        // The demo with the screen.
        run.send(&format!("{LAUNCH} -timedemo demo1"))?;
        let report = run.expect_line(
            "the report of the demo",
            |l| report_numbers(l).is_some(),
            TIMEDEMO,
        )?;
        let (tics, real) = report_numbers(&report).unwrap_or_default();
        Ok::<_, String>((memory, tics, real))
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    let (memory, tics, real) =
        measured.map_err(|e| format!("doom-measure on {}: {e}", machine.name))?;
    println!(
        "doom-measure on {}: {:.1} frames a second ({tics} game tics in {real} real tics of 1/35 s); memory of the process (VmSize kB, VmRSS kB, statm pages): {}",
        machine.name,
        frames_per_second(tics, real),
        memory.join("; ")
    );
    if machine.is_hvf() {
        return Ok(());
    }
    steps(machine)
}

/// The keys of the probe for a machine that runs at the pace of its
/// instruction count (-icount): no screenshots, long waits, the same keys.
fn drive_slowly(run: &mut qemu::Run, scratch: &Scratch) -> Result<(), String> {
    const SLOW: Duration = Duration::from_secs(900);
    const PAUSE: Duration = Duration::from_secs(3);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    run.expect(SERVICES_STARTED, SLOW)?;
    run.expect("# ", SLOW)?;
    run.send(LAUNCH)?;
    run.expect_line("the title screen", |l| l.contains(TITLE), SLOW)?;
    std::thread::sleep(PAUSE);
    monitor.sendkeys(&["ret", "ret", "ret", "ret"], PAUSE)?;
    run.expect_line("the first level", |l| l.contains(LEVEL), SLOW)?;
    std::thread::sleep(PAUSE);
    monitor.sendkey("left", Some(1000))?;
    std::thread::sleep(PAUSE);
    monitor.sendkey("esc", None)?;
    std::thread::sleep(PAUSE);
    monitor.sendkeys(&["up", "ret", "y"], PAUSE)?;
    run.expect(gpu_probe::RELEASED, SLOW)?;
    Ok(())
}

/// The run under -icount that counts the steps of the two services.
fn steps(machine: &'static qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let programs = steps_programs();
    let image = build_boot_image("boot-doom-steps.img", programs, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = probe_command(machine, &kernel.image, &image, &scratch);
    cmd.args(qemu::ICOUNT);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let driven = drive_slowly(&mut run, &scratch);
    let output = run.stop();
    driven.map_err(|e| format!("doom steps under -icount: {e}"))?;
    let mut text = Vec::new();
    for (name, tag) in [("display", GPU_TAG), ("input", INPUT_TAG)] {
        let rows = longest_steps(&output.lines, tag);
        if rows.is_empty() {
            return Err(format!("doom steps: no step of the {name} service"));
        }
        if let Some(row) = rows.iter().find(|r| r.1 > gpu_probe::STEP_MAX) {
            return Err(format!(
                "doom steps: a step of the {name} service past 0.9 of term B ({}): {row:?}",
                gpu_probe::STEP_MAX
            ));
        }
        let rows: Vec<_> = rows
            .iter()
            .map(|(kind, ticks, detail)| format!("kind {kind} {ticks} (detail {detail})"))
            .collect();
        text.push(format!("{name}: {}", rows.join(", ")));
    }
    println!(
        "doom steps on {}: the longest steps under -icount, ticks (0.9 of term B {}): {}",
        machine.name,
        gpu_probe::STEP_MAX,
        text.join("; ")
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
        assert_eq!(
            report_numbers("timed 0 gametics in 0 realtics"),
            Some((0, 0))
        );
        assert_eq!(report_numbers("W_Init: Init WADfiles."), None);
        assert_eq!(report_numbers("timed N gametics in M realtics"), None);
    }

    #[test]
    fn the_games_image_runs_doom_on_the_table_of_its_quota() {
        let doom = programs().iter().find(|p| p.0 == "init").unwrap();
        assert_eq!(doom.3, &["table-doom"]);
        assert!(
            programs()
                .iter()
                .any(|p| p.0 == "doom" && p.3.contains(&"dynamic"))
        );
        assert!(shell_programs().iter().all(|p| p.0 != "doom"));
    }

    /// The games image has the services of the screen and the keys, and the
    /// display service has no method CRASH (only the images of the probes
    /// build it in: a client could end the screen of a player).
    #[test]
    fn the_games_image_has_the_screen_services_built_without_crash() {
        let gpu = programs().iter().find(|p| p.0 == "virtio-gpu").unwrap();
        assert!(!gpu.3.contains(&"crash"), "{:?}", gpu.3);
        assert!(gpu.3.is_empty());
        let input = programs().iter().find(|p| p.0 == "virtio-input").unwrap();
        assert!(input.3.is_empty());
        // The probes' images build it with the method, so the check above
        // tells the two apart.
        assert!(crate::gpu_probe::PROGRAMS[1].3.contains(&"crash"));
        // The image of the measures counts steps and has no CRASH either.
        let counting = image_programs(&["steps"]);
        let gpu = counting.iter().find(|p| p.0 == "virtio-gpu").unwrap();
        assert_eq!(gpu.3, &["steps"]);
    }

    fn picture(width: usize, height: usize, point: impl Fn(usize) -> [u8; 3]) -> Ppm {
        let rgb = (0..width * height).flat_map(point).collect();
        Ppm { width, height, rgb }
    }

    #[test]
    fn a_level_picture_needs_the_screens_size_and_colours() {
        let many = picture(640, 400, |i| [(i % 100) as u8, 0, 0]);
        assert_eq!(check_level(&many), Ok(100));
        let few = picture(640, 400, |i| [(i % 10) as u8, 0, 0]);
        assert!(check_level(&few).unwrap_err().contains("10 colours"));
        let small = picture(320, 200, |i| [(i % 100) as u8, 0, 0]);
        assert!(check_level(&small).unwrap_err().contains("320x200"));
    }

    #[test]
    fn a_turn_changes_the_view_in_three_tenths_of_the_points() {
        let before = picture(640, 400, |i| [(i % 256) as u8, 1, 1]);
        let turned = picture(640, 400, |i| [(i % 256) as u8, 2, 1]);
        assert_eq!(check_turn(&before, &turned), Ok(1000));
        assert!(
            check_turn(&before, &before)
                .unwrap_err()
                .contains("0 thousandths")
        );
        // An animation of the floors: 5 % of the points.
        let floors = picture(640, 400, |i| {
            [(i % 256) as u8, if i % 20 == 0 { 2 } else { 1 }, 1]
        });
        assert!(check_turn(&before, &floors).is_err());
        // 29 % fails, 30 % passes.
        let share = |percent: usize| {
            picture(640, 400, |i| {
                [(i % 256) as u8, if i % 100 < percent { 2 } else { 1 }, 1]
            })
        };
        assert!(check_turn(&before, &share(29)).is_err());
        assert_eq!(check_turn(&before, &share(30)), Ok(300));
    }

    #[test]
    fn the_frames_a_second_come_from_the_tics_of_the_demo() {
        assert_eq!(frames_per_second(2154, 2154), 35.0);
        assert_eq!(frames_per_second(350, 700), 17.5);
        assert_eq!(frames_per_second(10, 0), 0.0);
    }

    #[test]
    fn a_probe_past_its_time_fails() {
        assert!(check_time(Duration::from_secs(180), "m").is_ok());
        assert!(
            check_time(Duration::from_secs(181), "m")
                .unwrap_err()
                .contains("181 s")
        );
    }

    #[test]
    fn a_fault_in_the_output_is_found() {
        let ok = vec!["doom: level 1 1".to_owned()];
        assert!(faulted(&ok).is_none());
        let bad = vec!["x".to_owned(), "process fault: doom".to_owned()];
        assert_eq!(faulted(&bad).unwrap(), "process fault: doom");
    }

    #[test]
    fn the_player_names_a_machine() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(player_machine(&[]).unwrap().name, qemu::VIRT.name);
        assert_eq!(
            player_machine(&args(&["--machine", "hvf"])).unwrap().name,
            qemu::HVF_V3.name
        );
        assert_eq!(
            player_machine(&args(&["--machine", "tcg"])).unwrap().name,
            qemu::VIRT.name
        );
        assert!(player_machine(&args(&["--machine", "nonsense"])).is_err());
        assert!(player_machine(&args(&["--hvf"])).is_err());
    }

    /// The table of keys (ports/doomgeneric/keys.c) is C that the host
    /// compiles with its own tests: Linux key codes into Doom's keys.
    #[test]
    fn the_table_of_keys_passes_its_c_tests() {
        let dir = root().join("ports/doomgeneric");
        let out = std::env::temp_dir().join(format!("stafeto-keys-test-{}", std::process::id()));
        let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let mut cc = Command::new(&compiler);
        cc.args(["-std=c11", "-Wall", "-Werror", "-I"])
            .arg(&dir)
            .arg("-o")
            .arg(&out)
            .arg(dir.join("keys.c"))
            .arg(dir.join("keys_test.c"));
        let built = cc.output().unwrap_or_else(|e| {
            panic!("the C compiler {compiler:?} (CC, cc by default) does not run: {e}; install one to test the table of keys")
        });
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let ran = Command::new(&out).output().expect("the test runs");
        let _ = std::fs::remove_file(&out);
        let said = String::from_utf8_lossy(&ran.stdout);
        assert!(ran.status.success(), "{said}");
        assert_eq!(said.trim(), "keys: ok");
    }
}
