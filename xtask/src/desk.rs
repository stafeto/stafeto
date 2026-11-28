// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the manager's calls (`cargo xtask desk-probe --api`): the image
//! of the desk (`table::desk`), with the keyboard and the tablet on transports of
//! their own (15 and 6), runs the C probe of `<stafeto/manager.h>` as the record
//! `desk` (tests/posix-manager). The probe subscribes, starts a client, frames its
//! window with a window of its own, moves the pair, resizes the client, asks it to
//! close, and checks that the child of the manager is refused. Its lines are the
//! checks; xtask reads the guest's `input at X Y` line and then presses a key with
//! the monitor of QEMU and moves and clicks the tablet through QMP, at that point
//! of the screen: the window with the focus must get them (the client says so by
//! changing its title, which the manager reads).

use std::time::Duration;

use crate::focus_probe::Qmp;
use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, Variant, build,
    build_boot_image, comp_probe, input_probe, qemu,
};

/// The desk image's programs: the services of the POSIX programs, the display
/// driver, the input driver (one program, a record for each of the keyboard and
/// the tablet), the compositor and the probe.
pub const PROGRAMS: [ImageProgram; 12] = [
    ("init", "init", INIT_STACK_SIZE, &["table-desk"]),
    ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("pipe", "pipe", crate::PIPE_STACK_SIZE, &[]),
    ("loader", "loader", 0, &[]),
    ("virtio-gpu", "virtio-gpu", gpu_probe::GPU_STACK_SIZE, &[]),
    (
        "virtio-input",
        "virtio-input",
        input_probe::INPUT_STACK_SIZE,
        &[],
    ),
    ("compositor", "compositor", comp_probe::COMP_STACK_SIZE, &[]),
    (
        "posix-manager",
        "posix-manager-probe",
        POSIX_STACK_SIZE,
        &[],
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
];

/// The lines of the probe, each a check that passed and each said once.
const LINES: [&str; 11] = [
    "posix-manager: a call before the subscription is EBADF, a second subscription EBUSY, an id that names no window EINVAL",
    "posix-manager: a child of the manager is refused with EPERM",
    "posix-manager: the client's window is created and the manager gives it the focus",
    "posix-manager: the title and the kind of the program come by INFO",
    "posix-manager: a frame of the manager's own is linked, and the pair moves as one",
    "posix-manager: a move that would put the frame off the screen is refused and nothing moves",
    "posix-manager: the key and the pointer reached the window with the focus",
    "posix-manager: CONFIGURE got RESIZED and the frame follows the size",
    "posix-manager: the frame is hidden and shown with its window",
    "posix-manager: close asks the client, whose window goes, and the frame is hidden",
    "posix-manager: client ok",
];

/// The start of the line that tells the host where to press and move.
const INPUT: &str = "posix-manager: input at ";
const OK: &str = "posix-manager: ok";
const ENDED: &str = "init: desk ended: exit code 0, not restarted";

/// The line of each input driver about its device, as far as the status: the
/// keyboard on transport 15 and the tablet on transport 6.
const KEYBOARD_LINE: &str = "virtio-input: virtio-mmio at 0xa001e00, line 63, status 0x0";
const TABLET_LINE: &str = "virtio-input: virtio-mmio at 0xa000c00, line 54, status 0x0";

/// The size of the screen the tablet's axes are scaled to.
const SCREEN: (u32, u32) = (640, 400);

/// The lines that end the probe in failure: a check that failed, and the
/// manager ending with a code other than 0.
fn failure(line: &str) -> Option<String> {
    let failed = line.starts_with("posix-manager: check failed")
        || (line.starts_with("init: desk ended: ") && line != ENDED);
    failed.then(|| line.to_owned())
}

/// The point of the guest's `input at X Y` line.
fn input_point(line: &str) -> Result<(u32, u32), String> {
    let rest = line
        .strip_prefix(INPUT)
        .ok_or_else(|| format!("{line:?} is no input line"))?;
    let mut numbers = rest.split_whitespace().map(str::parse::<u32>);
    match (numbers.next(), numbers.next(), numbers.next()) {
        (Some(Ok(x)), Some(Ok(y)), None) if x < SCREEN.0 && y < SCREEN.1 => Ok((x, y)),
        _ => Err(format!("{line:?} has no point inside the screen")),
    }
}

/// Follows the run: the guest asks for input, xtask gives it, the manager ends.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<(u32, u32), String> {
    const WITHIN: Duration = Duration::from_secs(120);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let mut qmp = Qmp::connect(
        &scratch.socket().with_file_name("qmp.sock"),
        Duration::from_secs(20),
    )?;
    let line = run.expect_line(
        INPUT,
        |l| l.starts_with(INPUT) || failure(l).is_some(),
        WITHIN,
    )?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    let point = input_point(&line)?;
    // The key goes to the keyboard (transport 15) and reaches the window with
    // the focus; then the tablet (transport 6) moves into the window and its
    // button goes down and up there.
    monitor.sendkey("a", Some(100))?;
    std::thread::sleep(Duration::from_millis(300));
    qmp.move_to(point.0, point.1, SCREEN.0, SCREEN.1)?;
    std::thread::sleep(Duration::from_millis(300));
    qmp.left_button(true)?;
    std::thread::sleep(Duration::from_millis(300));
    qmp.left_button(false)?;
    let line = run.expect_line(ENDED, |l| l == ENDED || failure(l).is_some(), WITHIN)?;
    match failure(&line) {
        Some(failed) => Err(failed),
        None => Ok(point),
    }
}

/// Judges the lines of a run: no check failed, both input drivers found their
/// devices, each line of the probe came once, and the manager said `ok`.
fn verdict(lines: &[String]) -> Result<(), String> {
    if let Some(failed) = lines.iter().find_map(|l| failure(l)) {
        return Err(failed);
    }
    for marker in LINES.iter().chain(&[OK, KEYBOARD_LINE, TABLET_LINE]) {
        let found = lines.iter().filter(|l| l.as_str() == *marker).count();
        if found != 1 {
            return Err(format!("{found} lines {marker:?}, 1 expected"));
        }
    }
    let inputs = lines.iter().filter(|l| l.starts_with(INPUT)).count();
    if inputs != 1 {
        return Err(format!("{inputs} lines {INPUT:?}, 1 expected"));
    }
    Ok(())
}

/// `cargo xtask desk-probe --api` and its boot in `test`.
pub fn api(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-desk.img", &PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(["-qmp"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().with_file_name("qmp.sock").display()
    ));
    cmd.args(qemu::GPU);
    cmd.args(qemu::KEYBOARD);
    cmd.args(qemu::DESK_TABLET);
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    let point = driven.map_err(|e| format!("desk-probe on {}: {e}", machine.name))?;
    verdict(&outcome.lines).map_err(|e| format!("desk-probe on {}: {e}", machine.name))?;
    println!(
        "desk-probe on {}: the manager of the C library subscribed, saw the client's window and gave it the focus, read its title and kind by INFO, framed it with a window of its own and moved the pair as one (a move that would put the frame off the screen moved nothing), resized it by CONFIGURE and heard RESIZED, hid and showed the pair, and asked it to close; the child of the manager was refused with EPERM; the key and the tablet's click at {point:?} reached the window with the focus through the keyboard on transport 15 and the tablet on transport 6: ok",
        machine.name
    );
    Ok(())
}

/// `cargo xtask desk-probe [--api]`.
pub fn command(args: &[String], machine: &qemu::Machine) -> Result<(), String> {
    match args {
        [flag] if flag == "--api" => api(machine),
        _ => Err("desk-probe --api (the probe of the desk itself comes with the manager of steps 5 and 6)".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Vec<String> {
        let mut lines: Vec<String> = LINES.iter().map(|l| (*l).to_owned()).collect();
        lines.extend([
            format!("{INPUT}200 120"),
            OK.to_owned(),
            KEYBOARD_LINE.to_owned(),
            TABLET_LINE.to_owned(),
        ]);
        lines
    }

    #[test]
    fn a_run_with_every_line_once_passes() {
        assert_eq!(verdict(&run()), Ok(()));
    }

    #[test]
    fn a_missing_repeated_or_failed_line_is_named() {
        let mut lines = run();
        lines.retain(|l| l != KEYBOARD_LINE);
        assert!(verdict(&lines).unwrap_err().contains("0 lines"));
        let mut lines = run();
        lines.push(LINES[3].to_owned());
        assert!(verdict(&lines).unwrap_err().contains("2 lines"));
        let mut lines = run();
        lines.retain(|l| l != TABLET_LINE);
        assert!(verdict(&lines).unwrap_err().contains("0 lines"));
        let mut lines = run();
        lines.push("posix-manager: check failed at line 9: x (errno 1)".to_owned());
        assert!(verdict(&lines).unwrap_err().contains("check failed"));
        let mut lines = run();
        lines.push("init: desk ended: exit code 20, not restarted".to_owned());
        assert!(verdict(&lines).unwrap_err().contains("exit code 20"));
    }

    #[test]
    fn the_input_line_names_a_point_inside_the_screen() {
        assert_eq!(
            input_point("posix-manager: input at 200 120"),
            Ok((200, 120))
        );
        assert!(input_point("posix-manager: input at 640 120").is_err());
        assert!(input_point("posix-manager: input at 2 x").is_err());
        assert!(input_point("posix-manager: input at 2 3 4").is_err());
        assert!(input_point("other").is_err());
    }

    /// The header compiles under every mode a program may use, with the layout
    /// assertions on, together with `<stafeto/window.h>` that it includes, and a
    /// wrong layout does not compile. Skipped when no clang is found (as the test
    /// of the window header in `posix_window.rs`).
    #[test]
    fn the_header_compiles_in_every_standard() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let include = root.join("lib/posix-crt/window");
        let tool = |name: &str| {
            let brew = std::path::PathBuf::from("/opt/homebrew/opt/llvm/bin").join(name);
            if brew.exists() { brew } else { name.into() }
        };
        let compile =
            |program: &str, std: &str, lang: &str, source: &str, include: &std::path::Path| {
                let mut child = Command::new(tool(program))
                    .args([
                        "--target=aarch64-linux-gnu",
                        "-pedantic-errors",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                    ])
                    .args(["-fsyntax-only", "-x", lang, &format!("-std={std}")])
                    .arg("-I")
                    .arg(include)
                    .arg("-")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .ok()?;
                child.stdin.take()?.write_all(source.as_bytes()).ok()?;
                Some(child.wait().ok()?.success())
            };
        let source = "#include <stafeto/manager.h>\n#include <stafeto/manager.h>\nint main(void) { return STAFETO_MANAGER_WINDOWS_MAX; }\n";
        if compile("clang", "c11", "c", source, &include).is_none() {
            eprintln!("no clang: the header's standards are not tried");
            return;
        }
        for std in ["c99", "c11", "c17"] {
            assert_eq!(
                compile("clang", std, "c", source, &include),
                Some(true),
                "{std}"
            );
        }
        for std in ["c++98", "c++11", "c++17"] {
            assert_eq!(
                compile("clang++", std, "c++", source, &include),
                Some(true),
                "{std}"
            );
        }
        // A wrong size is refused in the old mode and the new one.
        let dir =
            std::env::temp_dir().join(format!("stafeto-manager-header-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("stafeto")).unwrap();
        std::fs::copy(
            include.join("stafeto/window.h"),
            dir.join("stafeto/window.h"),
        )
        .unwrap();
        let text = std::fs::read_to_string(include.join("stafeto/manager.h")).unwrap();
        let wrong = text.replace(
            "stafeto_manager_info) == 144",
            "stafeto_manager_info) == 145",
        );
        assert_ne!(text, wrong);
        std::fs::write(dir.join("stafeto/manager.h"), wrong).unwrap();
        for (program, std, lang) in [
            ("clang", "c99", "c"),
            ("clang", "c11", "c"),
            ("clang++", "c++98", "c++"),
            ("clang++", "c++17", "c++"),
        ] {
            assert_eq!(
                compile(program, std, lang, source, &dir),
                Some(false),
                "{std}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_end_with_code_zero_is_no_failure() {
        assert!(failure(ENDED).is_none());
        assert!(failure("init: desk ended: exit code 21, not restarted").is_some());
        assert!(failure("posix-manager: a child of the manager is refused with EPERM").is_none());
    }
}
