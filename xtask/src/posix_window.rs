// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the window library (tests/posix-window, the functions of
//! `<stafeto/window.h>` in a static program) on QEMU's virtio-gpu-device:
//! the services of the POSIX probes, the display driver, the compositor and
//! the probe, which starts its own file once. The copy that can fork makes a
//! window of 200 by 100 points with two buffers, posts a pattern, a second
//! buffer with one rectangle changed and the first again with five
//! rectangles that merge into their bounding box, and prints the CRC-32 of
//! the screen it should show after each frame. While the probe waits after a
//! line, xtask asks the monitor of QEMU for a `screendump` and takes the
//! CRC-32 of the colours (`comp-probe`'s way): the two are equal, so the
//! window library's buffers, the compositor's frame and the driver's show
//! agree. The other checks (the bits that free the buffers, the events, the
//! child that has no window, the signal that ends a wait, the close) are the
//! probe's lines.

use std::time::Duration;

use crate::gpu_probe::{self, Scratch};
use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, Variant, build,
    build_boot_image, qemu,
};

/// The probe's image: the services of the POSIX probes, the driver, the
/// compositor and the probe.
pub const PROGRAMS: [ImageProgram; 11] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-window"]),
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
        "compositor",
        "compositor",
        crate::comp_probe::COMP_STACK_SIZE,
        &[],
    ),
    ("posix-window", "posix-window-probe", POSIX_STACK_SIZE, &[]),
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

/// The lines with a CRC the screenshots are compared with, in order.
const SHOTS: [&str; 3] = [
    "posix-window: window crc ",
    "posix-window: partial crc ",
    "posix-window: merged crc ",
];

/// The lines of the probe, each a check that passed.
const LINES: [&str; 8] = [
    "posix-window: the screen is described, no window yet, and bad arguments leave nothing",
    "posix-window: a window of 200 by 100 with two zeroed buffers, a second open is EBUSY",
    "posix-window: post refuses a wrong buffer, window or rectangle, and a buffer that is out",
    "posix-window: the frame is shown and its bit frees the replaced buffer",
    "posix-window: five rectangles merge into their bounding box",
    "posix-window: the events are the focus events only and the ring is empty after",
    "posix-window: a forked child has no window, and a signal ends a wait with EINTR",
    "posix-window: close ends the window, and a new one opens",
];

const ENDED: &str = "init: posix-window ended: exit code 0, not restarted";

/// The lines that end the probe in failure: a check that failed, and the
/// probe's process ending with a code other than 0.
fn failure(line: &str) -> Option<String> {
    let failed = line.starts_with("posix-window: check failed")
        || (line.starts_with("init: posix-window ended: ") && line != ENDED);
    failed.then(|| line.to_owned())
}

/// Follows the run: the three screenshots against the guest's CRC lines,
/// then the end of the probe. The CRC-32 of each screenshot.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<[u32; 3], String> {
    const WITHIN: Duration = Duration::from_secs(120);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    let mut shots = [0; 3];
    for (shot, prefix) in shots.iter_mut().zip(SHOTS) {
        // A check that failed or an end with another code ends the probe: no
        // CRC line will come, and the wait for it would run to the end of the
        // time.
        let line = run.expect_line(
            prefix,
            |l| l.contains(prefix) || failure(l).is_some(),
            WITHIN,
        )?;
        if let Some(failed) = failure(&line) {
            return Err(failed);
        }
        *shot = gpu_probe::compare_shot(&mut monitor, &scratch.picture(), &line, prefix)?;
    }
    let line = run.expect_line(ENDED, |l| l == ENDED || failure(l).is_some(), WITHIN)?;
    if let Some(failed) = failure(&line) {
        return Err(failed);
    }
    Ok(shots)
}

/// Judges the lines of a run and the CRC-32 of the three screenshots: no
/// check failed, each line of the probe came once, the screenshot after the
/// merged post is the first one again (the first buffer's top byte is 0xFF
/// and the screen ignores it), and the one after the second buffer differs.
fn verdict(lines: &[String], shots: [u32; 3]) -> Result<(), String> {
    if let Some(failed) = lines
        .iter()
        .find(|l| l.starts_with("posix-window: check failed"))
    {
        return Err(failed.clone());
    }
    for marker in LINES.iter().chain(&["posix-window: ok"]) {
        let found = lines.iter().filter(|l| l.as_str() == *marker).count();
        if found != 1 {
            return Err(format!("{found} lines {marker:?}, 1 expected"));
        }
    }
    if shots[0] != shots[2] {
        return Err(format!(
            "the merged post did not bring the first picture back: screenshots {:08x} and {:08x}",
            shots[0], shots[2]
        ));
    }
    if shots[0] == shots[1] {
        return Err("the screen did not change with the second buffer".into());
    }
    Ok(())
}

/// `cargo xtask posix-window` and its boot in `test`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-posix-window.img", &PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(qemu::GPU);
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    let shots = driven.map_err(|e| format!("posix-window on {}: {e}", machine.name))?;
    verdict(&outcome.lines, shots).map_err(|e| format!("posix-window on {}: {e}", machine.name))?;
    println!(
        "posix-window on {}: a window of the C library with two buffers matched QEMU's screenshot for the first frame, a rectangle of the second buffer and the merge of five rectangles; the bits freed the buffers, the child had no window, a signal ended the wait, close and a new window: ok",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Vec<String> {
        let mut lines: Vec<String> = LINES.iter().map(|l| (*l).to_owned()).collect();
        lines.push("posix-window: ok".to_owned());
        lines
    }

    #[test]
    fn a_run_whose_merge_restores_the_first_screenshot_passes() {
        assert_eq!(
            verdict(&run(), [0x0a0b_0c0d, 0x1122_3344, 0x0a0b_0c0d]),
            Ok(())
        );
    }

    #[test]
    fn a_failed_check_or_an_end_with_another_code_stops_the_wait() {
        assert!(failure("posix-window: check failed at line 355: x (errno 4)").is_some());
        assert!(failure("init: posix-window ended: exit code 20, not restarted").is_some());
        assert!(failure(ENDED).is_none());
        assert!(failure("posix-window: window crc 79c130d2").is_none());
    }

    #[test]
    fn the_verdict_names_what_is_wrong() {
        let err = verdict(&run(), [1, 2, 3]).unwrap_err();
        assert!(err.contains("merged"), "{err}");
        let err = verdict(&run(), [1, 1, 1]).unwrap_err();
        assert!(err.contains("did not change"), "{err}");
        let mut lines = run();
        lines.remove(0);
        assert!(verdict(&lines, [1, 2, 1]).unwrap_err().contains("expected"));
        let mut lines = run();
        lines.push("posix-window: check failed at line 9: x (errno 1)".to_owned());
        assert!(
            verdict(&lines, [1, 2, 1])
                .unwrap_err()
                .contains("check failed")
        );
    }

    /// The header compiles under every mode a program may use, with the
    /// layout assertions on (`_Static_assert`, `static_assert`, or the
    /// array of size -1 before C11 and C++11), and a wrong layout does not
    /// compile. By hand:
    /// `clang --target=aarch64-linux-gnu -std=c99 -pedantic-errors -Wall -Wextra -Werror
    ///  -fsyntax-only -x c -I lib/posix-crt/window -` with `#include <stafeto/window.h>`,
    /// and `clang++ ... -std=c++98 ... -x c++`. Skipped when no clang is found (the
    /// host job of ci has one, as `cargo xtask abi` needs it).
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
        let source = "#include <stafeto/window.h>\n#include <stafeto/window.h>\nint main(void) { return 0; }\n";
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
            std::env::temp_dir().join(format!("stafeto-window-header-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("stafeto")).unwrap();
        let text = std::fs::read_to_string(include.join("stafeto/window.h")).unwrap();
        let wrong = text.replace("stafeto_screen) == 32", "stafeto_screen) == 33");
        assert_ne!(text, wrong);
        std::fs::write(dir.join("stafeto/window.h"), wrong).unwrap();
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
}
