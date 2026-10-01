// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Run an arm64 Image on Apple's Virtualization.framework: the kernel
//! that ships, which has no build of its own for VZ, with a boot image
//! whose init starts the Virtio console's driver (services/virtio-console).
//! VZ gives the machine no PL011: what the kernel says goes into its log,
//! which the driver shows; a kernel panic shows nothing there and powers
//! the machine off, and the runner says "guest stopped" (`stop_hint`).
//! The same kernel under HVF (`cargo xtask hvf`, `cargo xtask run --hvf`)
//! shows the panic. VZ restarts the machine at PSCI SYSTEM_RESET with its
//! RAM cleared, so the kernel log does not outlive a panic there either.

use std::path::Path;
use std::process::Command;

use std::time::Duration;

use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, CRASHING, DIALOG_STEP, PROMPT, RECONNECTED, SHELL_CONNECTED,
    VZ_EARLY_PROGRAMS, VZ_PROGRAMS, VZ_WATCH_PROGRAMS, Variant, build, build_boot_image, qemu,
    root, run_cmd, target_dir,
};

/// The line of the Virtio console's driver at its start: device 5 of bus
/// 0, INTA through `interrupt-map` at INTID 69, and the command word 0 it
/// found, at the machine's start and after init stopped the function of
/// the instance before.
pub const DRIVER_LINE: &str = "virtio-console: 1af4:1043 at 0x40028000, line 69, command 0x0";

/// Init's line once the device of the crashed driver stayed silent
/// (feature `dma-watch`).
const UNCHANGED: &str = "init: uart DMA memory unchanged for 300 ms after its stop";

/// What the runner says when the machine powered itself off.
const STOPPED: &str = "guest stopped";

/// The hint a failed run on VZ gets when the machine stopped before the
/// end of its steps: on VZ the kernel has no port, so a panic or init's
/// end shows nothing; the same kernel image shows it under HVF.
pub const HINT: &str = "the machine powered off before the end: on Apple VZ a kernel panic or the end of init shows nothing; run the same kernel under HVF (cargo xtask run --hvf, cargo xtask hvf) to see it";

/// `result` of a run on VZ: a failure whose output shows the machine
/// stopped (STOPPED) gets HINT.
pub fn stop_hint<T>(result: Result<T, String>) -> Result<T, String> {
    result.map_err(|e| {
        if e.contains(STOPPED) {
            format!("{e}\n{HINT}")
        } else {
            e
        }
    })
}

pub fn runner() -> Result<std::path::PathBuf, String> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err("Virtualization.framework requires an Apple silicon Mac".into());
    }
    let root = root();
    let binary = target_dir().join("vz-run");
    run_cmd(
        Command::new("swiftc")
            .arg(root.join("tools/vz-run.swift"))
            .args(["-o"])
            .arg(&binary),
    )?;
    run_cmd(
        Command::new("codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg(root.join("tools/vz-entitlements.plist"))
            .arg(&binary),
    )?;
    Ok(binary)
}

/// The command that boots `kernel` with the boot image `boot` on VZ.
pub fn command(kernel: &Path, boot: &Path) -> Result<Command, String> {
    let mut cmd = Command::new(runner()?);
    cmd.arg(kernel).arg(boot);
    Ok(cmd)
}

/// The kernel image and the boot image of VZ, and a line of the report
/// with the kernel's size: the build that ships (spec 3.4).
fn images() -> Result<(crate::Artifacts, std::path::PathBuf), String> {
    let kernel = build(Variant::Normal)?;
    let boot = build_boot_image("boot-vz.img", &VZ_PROGRAMS, BOOT_PROFILE)?;
    let bytes = std::fs::metadata(&kernel.image)
        .map_err(|e| format!("{}: {e}", kernel.image.display()))?
        .len();
    println!("VZ kernel image: the build that ships, {bytes} bytes");
    Ok((kernel, boot))
}

/// `cargo xtask vz`: the shell on the terminal.
pub fn run() -> Result<(), String> {
    let (kernel, boot) = images()?;
    let status = command(&kernel.image, &boot)?
        .status()
        .map_err(|e| format!("vz-run: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("vz-run exited with {status}"))
    }
}

/// `cargo xtask console-restart-vz` (spec 13.5; spec 2, section 4): the
/// driver starts and the shell connects; `echo` goes through the
/// interrupt; `crash uart` ends the driver with a fault, and init resets
/// the device and clears its command word (Record::quiesce), then reads
/// the old DMA object for 300 ms (feature `dma-watch`) while xtask types
/// into the console: init says the object stayed unchanged, so the device
/// wrote no frame after its stop. Then the new instance finds the
/// function stopped (DRIVER_LINE once more), the shell connects again,
/// and `echo` shows input still comes through the interrupt.
pub fn console_restart() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let boot = build_boot_image("boot-vz-watch.img", &VZ_WATCH_PROGRAMS, BOOT_PROFILE)?;
    let mut run = qemu::Run::start(command(&kernel.image, &boot)?, qemu::Input::Pipe)?;
    let result = (|| {
        let whole = |line: &'static str| move |l: &str| l == line;
        run.expect_line(DRIVER_LINE, whole(DRIVER_LINE), BOOT_TIMEOUT)?;
        run.expect_line(SHELL_CONNECTED, whole(SHELL_CONNECTED), DIALOG_STEP)?;
        run.expect(PROMPT, DIALOG_STEP)?;
        run.send("echo before the crash")?;
        run.expect_line("before the crash", whole("before the crash"), DIALOG_STEP)?;
        run.expect(PROMPT, DIALOG_STEP)?;
        run.send("crash uart")?;
        run.expect_line(CRASHING, whole(CRASHING), DIALOG_STEP)?;
        // Input while init watches the old object: the device would write
        // it into the receive buffer the dead driver left it.
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            run.send("x")?;
        }
        run.expect_line(RECONNECTED, whole(RECONNECTED), DIALOG_STEP)?;
        run.expect_seen(UNCHANGED, DIALOG_STEP)?;
        let starts = run.lines().iter().filter(|l| *l == DRIVER_LINE).count();
        if starts != 2 {
            return Err(format!("{starts} lines {DRIVER_LINE:?}, two expected"));
        }
        run.expect(PROMPT, DIALOG_STEP)?;
        run.send("echo after the crash")?;
        run.expect_line("after the crash", whole("after the crash"), DIALOG_STEP)?;
        run.expect(PROMPT, DIALOG_STEP)
    })();
    run.stop();
    stop_hint(result).map_err(|e| format!("console restart on VZ: {e}"))?;
    println!("console restart on VZ: ok");
    Ok(())
}

/// `cargo xtask console-early-exit-vz` (spec 2, section 4): the first
/// instance of the driver ends after it wrote BAR 1, with decoding off, so
/// BAR 0 reads 0xff and drops writes; init skips the reset through BAR 0
/// (Write::only_if), clears the command word and starts the driver again,
/// which comes up, and the shell connects and answers `echo`.
pub fn console_early_exit() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let boot = build_boot_image("boot-vz-early.img", &VZ_EARLY_PROGRAMS, BOOT_PROFILE)?;
    let mut run = qemu::Run::start(command(&kernel.image, &boot)?, qemu::Input::Pipe)?;
    let result = (|| {
        let whole = |line: &'static str| move |l: &str| l == line;
        run.expect_line(DRIVER_LINE, whole(DRIVER_LINE), BOOT_TIMEOUT)?;
        run.expect_line(SHELL_CONNECTED, whole(SHELL_CONNECTED), DIALOG_STEP)?;
        run.expect(PROMPT, DIALOG_STEP)?;
        run.expect_seen(EARLY_END, DIALOG_STEP)?;
        run.send("echo after the early end")?;
        run.expect_line(
            "after the early end",
            whole("after the early end"),
            DIALOG_STEP,
        )?;
        run.expect(PROMPT, DIALOG_STEP)
    })();
    run.stop();
    stop_hint(result).map_err(|e| format!("early end on VZ: {e}"))?;
    println!("early end of the console's driver on VZ: ok");
    Ok(())
}

/// Init's line of the end of the first instance of `exit-before-decoding`.
const EARLY_END: &str = "init: uart ended: exit code 8; restarts in 100 ms";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_that_stopped_gets_the_hint() {
        let stopped: Result<(), String> = Err(
            "the output ended before x; last lines: [\"guest stopped: the kernel powered off\"]"
                .into(),
        );
        assert!(stop_hint(stopped).unwrap_err().ends_with(HINT));
        let timed_out: Result<(), String> = Err("timed out waiting for x".into());
        assert_eq!(stop_hint(timed_out), Err("timed out waiting for x".into()));
        assert_eq!(stop_hint(Ok(1)), Ok(1));
    }
}
