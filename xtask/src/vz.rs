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
    BOOT_PROFILE, BOOT_TIMEOUT, CRASHING, DIALOG_STEP, POSIX_TTY_VZ_PROGRAMS, PROMPT, RECONNECTED,
    SHELL_CONNECTED, VZ_EARLY_PROGRAMS, VZ_PROGRAMS, VZ_WATCH_PROGRAMS, Variant, build,
    build_boot_image, qemu, root, run_cmd, target_dir,
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

/// The keys of `vz-run` a run sets beyond the images; a key left out keeps
/// the runner's default (one processor, 512 MiB, no network device).
#[derive(Clone, Copy, Default)]
pub struct Machine {
    pub cpus: Option<usize>,
    pub memory_mib: Option<u64>,
    /// The Virtio network devices on the NAT, 0 to 2.
    pub net: usize,
    /// The fifth byte of the MAC addresses (`--mac-suffix`); 0 is the
    /// runner's default and leaves the key out.
    pub mac_suffix: u8,
}

/// The MAC address of network device `device` (0 or 1) of a guest run with
/// `suffix`, as `vz-run` sets it.
pub fn mac(suffix: u8, device: usize) -> String {
    format!("02:73:74:66:{suffix:02x}:{:02x}", device + 1)
}

/// The suffix a run with network devices holds while it lives: the lock on
/// its file is released when the process ends, however it ends.
pub struct Suffix {
    pub value: u8,
    _lock: std::fs::File,
}

/// The suffixes in the keys `--mac-suffix` of the `vz-run` processes in
/// `ps` output (`pid command` lines); a runner without the key holds 0.
pub fn suffixes_in(ps: &str) -> Vec<u8> {
    let mut found = Vec::new();
    for line in ps.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(command) = words.get(1) else {
            continue;
        };
        if !(command.ends_with("/vz-run") || *command == "vz-run") {
            continue;
        }
        let key = words.iter().position(|w| *w == "--mac-suffix");
        found.push(
            key.and_then(|at| words.get(at + 1))
                .and_then(|w| w.parse().ok())
                .unwrap_or(0),
        );
    }
    found
}

/// Claims the lowest free suffix from 1 up: one no other xtask run holds
/// (a lock file per suffix in the temporary directory) and no running
/// `vz-run` has in its key, so that guests side by side have MAC addresses
/// of their own and so leases of their own on the NAT. A runner started by
/// hand without the key holds 0, which is never claimed.
pub fn claim_suffix() -> Result<Suffix, String> {
    let directory = std::env::temp_dir().join("stafeto-vz-mac");
    std::fs::create_dir_all(&directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    let ps = Command::new("ps")
        .args(["-Ao", "pid,command"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let running = suffixes_in(&ps);
    for value in 1..=u8::MAX {
        if running.contains(&value) {
            continue;
        }
        let path = directory.join(value.to_string());
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        match file.try_lock() {
            Ok(()) => return Ok(Suffix { value, _lock: file }),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("{}: {e}", path.display()));
            }
        }
    }
    Err("no free MAC suffix for a guest of vz-run".into())
}

/// The arguments of `vz-run` for `machine`, before the two images.
pub fn machine_arguments(machine: Machine) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(cpus) = machine.cpus {
        args.extend(["--cpus".to_string(), cpus.to_string()]);
    }
    if let Some(memory) = machine.memory_mib {
        args.extend(["--memory".to_string(), memory.to_string()]);
    }
    if machine.net > 0 {
        args.extend(["--net".to_string(), machine.net.to_string()]);
    }
    if machine.mac_suffix > 0 {
        args.extend(["--mac-suffix".to_string(), machine.mac_suffix.to_string()]);
    }
    args
}

/// The command that boots `kernel` with the boot image `boot` on VZ on
/// `machine`.
pub fn command_on(kernel: &Path, boot: &Path, machine: Machine) -> Result<Command, String> {
    let mut cmd = Command::new(runner()?);
    cmd.args(machine_arguments(machine)).arg(kernel).arg(boot);
    Ok(cmd)
}

/// The command that boots `kernel` with the boot image `boot` on VZ.
pub fn command(kernel: &Path, boot: &Path) -> Result<Command, String> {
    command_on(kernel, boot, Machine::default())
}

/// `command` for a machine with `cpus` processors.
pub fn command_cpus(kernel: &Path, boot: &Path, cpus: usize) -> Result<Command, String> {
    let machine = Machine {
        cpus: Some(cpus),
        ..Machine::default()
    };
    command_on(kernel, boot, machine)
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

/// `cargo xtask smp-vz` (SMP stage 2): the machine has four processors; the
/// kernel's log, which the Virtio console's driver shows, has the line of
/// each CPU (MPIDR, EL1, its timer) and the line of the SGI probe, and the
/// shell connects.
pub fn smp_boot() -> Result<(), String> {
    let (kernel, boot) = images()?;
    let mut run = qemu::Run::start(
        command_cpus(&kernel.image, &boot, crate::SMP_CPUS)?,
        qemu::Input::Pipe,
    )?;
    let result = (|| {
        let whole = |line: &'static str| move |l: &str| l == line;
        run.expect_line(SHELL_CONNECTED, whole(SHELL_CONNECTED), BOOT_TIMEOUT)?;
        crate::smp_report(run.lines(), crate::SMP_CPUS)
    })();
    run.stop();
    stop_hint(result).map_err(|e| format!("SMP boot on VZ: {e}"))?;
    println!("smp boot on VZ with {} CPUs: ok", crate::SMP_CPUS);
    Ok(())
}

/// `cargo xtask smp-asid-vz` (SMP stage 5): `smp_boot` with the kernel of 3-bit
/// ASIDs, then the UART driver crashes and restarts four times: the boot and
/// each new driver take an ASID of the 7, so that a new generation begins over
/// four processors; the shell still answers. VZ shows no output of the test
/// init, so the probes of `smp_asid` do not run here; the kernel's log shows
/// the generations that began.
pub fn smp_asid() -> Result<(), String> {
    let kernel = build(Variant::AsidProbe3)?;
    let boot = build_boot_image("boot-vz.img", &VZ_PROGRAMS, BOOT_PROFILE)?;
    let mut run = qemu::Run::start(
        command_cpus(&kernel.image, &boot, crate::SMP_CPUS)?,
        qemu::Input::Pipe,
    )?;
    let result = (|| {
        let whole = |line: &'static str| move |l: &str| l == line;
        run.expect_line(SHELL_CONNECTED, whole(SHELL_CONNECTED), BOOT_TIMEOUT)?;
        crate::smp_report(run.lines(), crate::SMP_CPUS)?;
        run.expect(PROMPT, DIALOG_STEP)?;
        for _ in 0..4 {
            run.send("crash uart")?;
            run.expect_line(CRASHING, whole(CRASHING), DIALOG_STEP)?;
            run.expect_seen(RECONNECTED, DIALOG_STEP)?;
            run.expect(PROMPT, DIALOG_STEP)?;
        }
        run.send("echo after the generations")?;
        run.expect_line(
            "after the generations",
            whole("after the generations"),
            DIALOG_STEP,
        )
    })();
    let seen: Vec<String> = run
        .lines()
        .iter()
        .filter(|l| l.starts_with("smp asid  generation "))
        .cloned()
        .collect();
    run.stop();
    stop_hint(result).map_err(|e| format!("SMP ASID probe on VZ: {e}"))?;
    println!(
        "smp asid on VZ with {} CPUs: ok; generations seen in the log: {seen:?}",
        crate::SMP_CPUS
    );
    Ok(())
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

/// `cargo xtask clock-vz` (stafeto-design#380): VZ has no PL031, so the
/// runner writes the time it is given (`--time`) into the file `boot-time`
/// of a copy of the boot image, and the clock service starts there. The
/// time is a day before the host's, so that neither the default of the
/// service (2026-01-01) nor the host's time passes for it.
pub fn clock() -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let boot = build_boot_image(
        "boot-posix-tty-vz.img",
        &POSIX_TTY_VZ_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let seconds = rtc::FLOOR + 40 * 86_400 + 12_345;
    let mut cmd = Command::new(runner()?);
    cmd.args(["--time", &seconds.to_string()])
        .arg(&kernel.image)
        .arg(&boot);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let line = format!("clock: ready (started at {seconds} from the boot image)");
    let result = run.expect(&line, BOOT_TIMEOUT);
    run.stop();
    stop_hint(result).map_err(|e| format!("clock on VZ: {e}"))?;
    println!("clock on VZ: started at {seconds}, the time the runner wrote: ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_machine_keys_of_the_runner_are_set_only_when_asked_for() {
        assert!(machine_arguments(Machine::default()).is_empty());
        let machine = Machine {
            cpus: Some(4),
            memory_mib: Some(1024),
            net: 2,
            mac_suffix: 7,
        };
        assert_eq!(
            machine_arguments(machine),
            [
                "--cpus",
                "4",
                "--memory",
                "1024",
                "--net",
                "2",
                "--mac-suffix",
                "7"
            ]
        );
        let net = Machine {
            net: 1,
            ..Machine::default()
        };
        assert_eq!(machine_arguments(net), ["--net", "1"]);
    }

    #[test]
    fn the_macs_carry_the_suffix_and_the_device() {
        assert_eq!(mac(0, 0), "02:73:74:66:00:01");
        assert_eq!(mac(0x1a, 1), "02:73:74:66:1a:02");
    }

    #[test]
    fn the_suffixes_of_running_runners_are_read_from_ps() {
        let ps = "  PID COMMAND\n 11 /x/target/vz-run --net 2 --mac-suffix 3 k b\n 12 vz-run --net 1 k b\n 13 /bin/sh -c vz-run --mac-suffix 9\n 14 qemu-system-aarch64 -m 1\n";
        assert_eq!(suffixes_in(ps), [3, 0]);
    }

    #[test]
    fn two_claims_get_different_suffixes() {
        let a = claim_suffix().unwrap();
        let b = claim_suffix().unwrap();
        assert_ne!(a.value, b.value);
    }

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
