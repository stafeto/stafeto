// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probes of the source of entropy (step 5e'): the driver of the
//! Virtio entropy device (services/virtio-rng) on QEMU's virtio-mmio, under
//! HVF and on the Virtio PCI of Apple VZ. The probe (tests/entropy) takes
//! two fills of 64 bytes, which differ and are not all zero, crashes the
//! driver, and fills once more from the driver init started again; the
//! new instance's line shows the device's status 0, so init reset the
//! device before it let the old DMA object go (on VZ init also watches the
//! old object for 300 ms, feature `dma-watch`). Under -icount the driver
//! prints each new longest step of its loop, and every one stays under
//! term B.

use std::time::Duration;

use crate::{
    BOOT_PROFILE, CHILD_STACK_SIZE, INIT_STACK_SIZE, ImageProgram, RAM_STEP_MAX, UART_STACK_SIZE,
    Variant, build, build_boot_image, longest_steps, qemu, run_until, vz,
};

/// The stack of the entropy device's driver: its loop's table of sessions
/// and the driver's fills.
const RNG_STACK_SIZE: u32 = 32 * 1024;

/// The probe's image on QEMU: the driver with CRASH and the count of its
/// steps (feature `steps`, which prints only under the tag it asks for).
pub const PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-entropy"]),
    (
        "virtio-rng",
        "virtio-rng",
        RNG_STACK_SIZE,
        &["crash", "steps"],
    ),
    ("entropy-probe", "entropy-probe", CHILD_STACK_SIZE, &[]),
];

/// The probe's image on VZ: the console's driver shows the lines, and init
/// watches the old DMA object of the driver that ended.
pub const VZ_PROGRAMS: [ImageProgram; 4] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-entropy-vz", "dma-watch"],
    ),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("virtio-rng", "virtio-rng", RNG_STACK_SIZE, &["crash"]),
    ("entropy-probe", "entropy-probe", CHILD_STACK_SIZE, &[]),
];

/// The driver's line at each start: the transport or the function, its
/// line, and the device's status as the driver found it, before its own
/// reset: 0 at the machine's start and after init stopped the device.
pub const DRIVER_LINE: &str = "virtio-rng: virtio-mmio at 0xa003e00, line 79, status 0x0";
pub const DRIVER_LINE_VZ: &str = "virtio-rng: 1af4:1044 at 0x40030000, line 70, status 0x0";

const TWO_FILLS: &str = "entropy-probe: two fills of 64 bytes differ, none all zero";
const AFTER_RESTART: &str = "entropy-probe: a fill after the restart";
const OK: &str = "entropy-probe: ok";
const ENDED: &str = "init: entropy-probe ended: exit code 0, not restarted";
/// Init's line once the device of the crashed driver stayed silent.
const UNCHANGED: &str = "init: rng DMA memory unchanged for 300 ms after its stop";

/// The tag of the driver's lines of steps (rt::service::report_steps).
const RNG_TAG: &str = "10";
/// The kinds of the driver's steps: FILL_START, FILL_TAKE, and its own
/// step of the interrupt (rt::service::step_own); the kind 64 holds the
/// heartbeat, a send to init and its reply.
const RNG_STEP_KINDS: [(usize, &str); 3] = [(1, "FillStart"), (2, "FillTake"), (65, "interrupt")];

/// What a run of the probe printed, judged: the driver started twice, each
/// time with the device's status 0 (`driver`), the fills came before and
/// after the restart, and the probe ended well.
pub fn verdict(lines: &[String], driver: &str) -> Result<(), String> {
    let starts = lines.iter().filter(|l| l.as_str() == driver).count();
    if starts != 2 {
        let found: Vec<_> = lines
            .iter()
            .filter(|l| l.starts_with("virtio-rng: "))
            .collect();
        return Err(format!(
            "{starts} lines {driver:?}, two expected: {found:?}"
        ));
    }
    for marker in [TWO_FILLS, AFTER_RESTART] {
        if !lines.iter().any(|l| l.starts_with(marker)) {
            return Err(format!("no line {marker:?}"));
        }
    }
    if !lines.iter().any(|l| l == OK) {
        let failed = lines
            .iter()
            .find(|l| l.starts_with("entropy-probe: failed"));
        return Err(format!("the probe did not end well: {failed:?}"));
    }
    Ok(())
}

/// The longest step of each kind of the driver's loop, from the lines of a
/// run under -icount: every kind of RNG_STEP_KINDS came and stayed under
/// term B. Gives the rows.
pub fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = longest_steps(lines, RNG_TAG);
    for (kind, name) in RNG_STEP_KINDS {
        let ticks = rows.iter().find(|(k, ..)| *k == kind).map_or(0, |r| r.1);
        if ticks == 0 || ticks > RAM_STEP_MAX {
            return Err(format!(
                "the driver of the entropy device: {name} took {ticks} ticks, past {RAM_STEP_MAX} or none: {rows:?}"
            ));
        }
    }
    Ok(rows)
}

/// `cargo xtask entropy` and its boot in `test`: the probe on `machine`,
/// under -icount on QEMU's own emulation, where the steps are measured.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-entropy.img", &PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let icount = !machine.is_hvf();
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let output = run_until(cmd, crate::BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    verdict(&output.lines, DRIVER_LINE).map_err(|e| format!("entropy on {}: {e}", machine.name))?;
    if icount {
        let rows = steps_verdict(&output.lines)?;
        let text: Vec<_> = rows
            .iter()
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect();
        println!(
            "entropy on {}: the driver's longest steps under -icount, ticks: {} (term B {RAM_STEP_MAX})",
            machine.name,
            text.join(", ")
        );
    }
    println!(
        "entropy on {}: fills before and after a restart of the driver, the device reset: ok",
        machine.name
    );
    Ok(())
}

/// `cargo xtask entropy-vz`: the probe on Apple VZ, where the driver goes
/// through the Virtio PCI function, and init watches the old DMA object.
pub fn probe_vz() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let boot = build_boot_image("boot-entropy-vz.img", &VZ_PROGRAMS, BOOT_PROFILE)?;
    let mut run = qemu::Run::start(vz::command(&kernel.image, &boot)?, qemu::Input::Pipe)?;
    let result = run
        .expect_seen(ENDED, crate::BOOT_TIMEOUT)
        .and_then(|()| run.expect_seen(UNCHANGED, Duration::from_secs(1)));
    let outcome = run.stop();
    vz::stop_hint(result.and_then(|()| verdict(&outcome.lines, DRIVER_LINE_VZ)))
        .map_err(|e| format!("entropy on VZ: {e}"))?;
    println!(
        "entropy on VZ: fills before and after a restart of the driver, the device reset and silent: ok"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| l.to_string()).collect()
    }

    const GOOD: [&str; 6] = [
        DRIVER_LINE,
        "entropy-probe: two fills of 64 bytes differ, none all zero (1, 2)",
        "entropy-probe: crashing rng",
        DRIVER_LINE,
        "entropy-probe: a fill after the restart (3)",
        OK,
    ];

    #[test]
    fn a_good_run_passes() {
        assert_eq!(verdict(&lines(&GOOD), DRIVER_LINE), Ok(()));
    }

    #[test]
    fn a_restart_that_finds_the_device_running_fails() {
        // Without init's reset the new instance finds the old status.
        let mut run = GOOD;
        run[3] = "virtio-rng: virtio-mmio at 0xa003e00, line 79, status 0xf";
        assert!(verdict(&lines(&run), DRIVER_LINE).is_err());
        // One start alone, or no fill after it.
        let run = [GOOD[0], GOOD[1], GOOD[2], GOOD[5]];
        assert!(verdict(&lines(&run), DRIVER_LINE).is_err());
        let run = [GOOD[0], GOOD[1], GOOD[2], GOOD[3], GOOD[5]];
        assert!(verdict(&lines(&run), DRIVER_LINE).is_err());
        let run = [GOOD[0], GOOD[1], GOOD[2], GOOD[3], GOOD[4]];
        assert!(verdict(&lines(&run), DRIVER_LINE).is_err());
    }

    #[test]
    fn every_kind_of_step_must_come_under_term_b() {
        let step = |kind: usize, ticks: u64| {
            format!("service step: 10 kind {kind} {ticks} ticks detail 0")
        };
        let good = vec![
            step(1, 900),
            step(2, 1500),
            step(65, 3000),
            step(64, 90_000),
        ];
        assert_eq!(steps_verdict(&good).map(|r| r.len()), Ok(4));
        let long = vec![step(1, 900), step(2, 1500), step(65, RAM_STEP_MAX + 1)];
        assert!(steps_verdict(&long).is_err());
        let missing = vec![step(1, 900), step(65, 3000)];
        assert!(steps_verdict(&missing).is_err());
    }
}
