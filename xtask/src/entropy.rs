// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probes of the source of entropy (step 5e'): the driver of the
//! Virtio entropy device (services/virtio-rng) on QEMU's virtio-mmio, under
//! HVF and on the Virtio PCI of Apple VZ, and the entropy service
//! (services/entropy) it feeds. The probe (tests/entropy) takes a key of
//! the service, waiting for the device's first bytes, and 16 more at once;
//! takes two fills of 64 bytes, which differ and are not all zero; crashes
//! the driver, takes 32 keys at once while init restarts it, and fills once
//! more from the new instance, whose line shows the device's status 0, so
//! init reset the device before it let the old DMA object go (on VZ init
//! also watches the old object for 300 ms, feature `dma-watch`). A second
//! client's key differs from the first's; on QEMU it takes one more key
//! after 61 s, past the service's reseed through the new driver. Under
//! -icount the driver and the service print each new longest step of their
//! loops, and every one stays under term B.

use std::time::Duration;

use crate::{
    BOOT_PROFILE, CHILD_STACK_SIZE, INIT_STACK_SIZE, ImageProgram, RAM_STEP_MAX, UART_STACK_SIZE,
    Variant, build, build_boot_image, longest_steps, qemu, run_until, vz,
};

/// The stack of the entropy device's driver: its loop's table of sessions
/// and the driver's fills.
const RNG_STACK_SIZE: u32 = 32 * 1024;

/// The stack of the entropy service's loop: the service with the table of
/// the clones it gave (8 KiB); its table of sessions lies in its data.
const ENTROPY_STACK_SIZE: u32 = 32 * 1024;

/// The probe's image on QEMU: the driver with CRASH, the service with the
/// line of each reseed, both with the count of their steps (feature
/// `steps`, which prints only under the tag each asks for).
pub const PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-entropy"]),
    (
        "virtio-rng",
        "virtio-rng",
        RNG_STACK_SIZE,
        &["crash", "steps"],
    ),
    ("entropy-probe", "entropy-probe", CHILD_STACK_SIZE, &[]),
    (
        "entropy",
        "entropy",
        ENTROPY_STACK_SIZE,
        &["steps", "report"],
    ),
];

/// The probe's image on VZ: the console's driver shows the lines, and init
/// watches the old DMA object of the driver that ended.
pub const VZ_PROGRAMS: [ImageProgram; 5] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-entropy-vz", "dma-watch"],
    ),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("virtio-rng", "virtio-rng", RNG_STACK_SIZE, &["crash"]),
    ("entropy-probe", "entropy-probe", CHILD_STACK_SIZE, &[]),
    ("entropy", "entropy", ENTROPY_STACK_SIZE, &["report"]),
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
const ENDED_B: &str = "init: entropy-probe-b ended: exit code 0, not restarted";
const B_ENDS: &str = "init: entropy-probe-b ended: ";
const KEY: &str = "entropy-probe: key ";
const AT_ONCE: &str = "entropy-probe: 16 seeds at once, all distinct";
const FLAG: &str = "entropy-probe: an unknown flag is refused";
const DURING_RESTART: &str = "entropy-probe: 32 seeds while the driver restarts";
const LATER: &str = "entropy-probe: a seed after 61 s";
const SEEDED: &str = "entropy: seeded from the device";
const RESEEDED: &str = "entropy: reseeded from the device";
/// Init's line once the device of the crashed driver stayed silent.
const UNCHANGED: &str = "init: rng DMA memory unchanged for 300 ms after its stop";

/// The tags of the driver's and of the service's lines of steps
/// (rt::service::report_steps).
const RNG_TAG: &str = "10";
const ENTROPY_TAG: &str = "11";
/// The kinds of the driver's steps: FILL_START, FILL_TAKE, and its own
/// step of the interrupt (rt::service::step_own); the kind 64 holds the
/// heartbeat, a send to init and its reply.
const RNG_STEP_KINDS: [(usize, &str); 3] = [(1, "FillStart"), (2, "FillTake"), (65, "interrupt")];
/// The kinds of the service's steps that must come: SEED and its own step
/// of the feeder's bytes (a seed or a reseed, and the seeds that waited
/// told). SEED_TAKE comes only when a client asked before the first bytes,
/// and is checked when it came.
const ENTROPY_STEP_KINDS: [(usize, &str); 2] = [(5, "Seed"), (65, "the feeder's bytes")];

/// What a run of the probe printed, judged: the driver started twice, each
/// time with the device's status 0 (`driver`), the fills came before and
/// after the restart; the service was seeded once and gave the two
/// clients two keys that differ, and keys at once, during the restart too;
/// with `reseed`, it reseeded and gave a key after it; both clients ended
/// well.
pub fn verdict(lines: &[String], driver: &str, reseed: bool) -> Result<(), String> {
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
    let count = |marker: &str| lines.iter().filter(|l| l.starts_with(marker)).count();
    let mut wanted = vec![
        (TWO_FILLS, 1),
        (AFTER_RESTART, 1),
        (DURING_RESTART, 1),
        (SEEDED, 1),
        (AT_ONCE, 2),
        (FLAG, 2),
        (OK, 2),
    ];
    if reseed {
        wanted.push((LATER, 1));
    }
    for (marker, n) in wanted {
        if count(marker) != n {
            let failed = lines
                .iter()
                .find(|l| l.starts_with("entropy-probe: failed"));
            return Err(format!(
                "{} lines {marker:?}, {n} expected; a failure: {failed:?}",
                count(marker)
            ));
        }
    }
    if reseed && count(RESEEDED) == 0 {
        return Err("the service never reseeded".into());
    }
    let keys: Vec<_> = lines.iter().filter_map(|l| l.strip_prefix(KEY)).collect();
    if keys.len() != 2 || keys[0] == keys[1] || keys.iter().any(|k| k.len() != 64) {
        return Err(format!("the keys of the two clients: {keys:?}"));
    }
    Ok(())
}

/// The longest step of each kind of a loop: (kind, ticks, detail).
type Rows = Vec<(usize, u64, u64)>;

/// The longest step of each kind of the loop of `tag`, from the lines of a
/// run under -icount: every kind of `kinds` came, and every kind but the
/// heartbeat (64) stayed under term B. Gives the rows.
fn loop_steps(
    lines: &[String],
    tag: &str,
    kinds: &[(usize, &str)],
    who: &str,
) -> Result<Rows, String> {
    let rows = longest_steps(lines, tag);
    for &(kind, name) in kinds {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("{who}: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.0 != 64 && r.1 > RAM_STEP_MAX) {
        return Err(format!("{who}: a step past term B {RAM_STEP_MAX}: {row:?}"));
    }
    Ok(rows)
}

/// The steps of the driver and of the service (loop_steps).
pub fn steps_verdict(lines: &[String]) -> Result<[Rows; 2], String> {
    Ok([
        loop_steps(
            lines,
            RNG_TAG,
            &RNG_STEP_KINDS,
            "the entropy device's driver",
        )?,
        loop_steps(
            lines,
            ENTROPY_TAG,
            &ENTROPY_STEP_KINDS,
            "the entropy service",
        )?,
    ])
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
    // The second client ends last: it waits 61 s, virtual time under
    // -icount, which jumps while every thread sleeps.
    let timeout = crate::BOOT_TIMEOUT
        + if icount {
            Duration::ZERO
        } else {
            Duration::from_secs(61)
        };
    // The run stops at the second client's end, whatever its code.
    let output = run_until(cmd, timeout, Some(B_ENDS), &kernel.elf)?;
    verdict(&output.lines, DRIVER_LINE, true)
        .map_err(|e| format!("entropy on {}: {e}", machine.name))?;
    qemu::expect_stopped_on(&output, ENDED_B)?;
    qemu::expect_marker(&output, ENDED)?;
    if icount {
        let [rng, service] = steps_verdict(&output.lines)?;
        let text = |rows: &[(usize, u64, u64)]| {
            let rows: Vec<_> = rows
                .iter()
                .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
                .collect();
            rows.join(", ")
        };
        println!(
            "entropy on {}: the longest steps under -icount, ticks (term B {RAM_STEP_MAX}): driver {}; service {}",
            machine.name,
            text(&rng),
            text(&service)
        );
    }
    println!(
        "entropy on {}: keys of two clients, keys during a restart of the driver, a reseed, fills, the device reset: ok",
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
        .and_then(|()| run.expect_seen(ENDED_B, crate::BOOT_TIMEOUT))
        .and_then(|()| run.expect_seen(UNCHANGED, Duration::from_secs(1)));
    let outcome = run.stop();
    vz::stop_hint(result.and_then(|()| verdict(&outcome.lines, DRIVER_LINE_VZ, false)))
        .map_err(|e| format!("entropy on VZ: {e}"))?;
    println!(
        "entropy on VZ: keys of two clients, keys during a restart of the driver, fills, the device reset and silent: ok"
    );
    Ok(())
}

/// The C probe of the layer's generator (tests/posix-random): the POSIX
/// services, the loader, the entropy device's driver and service, and the
/// probe, which starts its own file once.
pub const RANDOM_PROGRAMS: [ImageProgram; 9] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-random"]),
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
    ("virtio-rng", "virtio-rng", RNG_STACK_SIZE, &[]),
    ("entropy", "entropy", ENTROPY_STACK_SIZE, &[]),
    (
        "posix-random",
        "posix-random-probe",
        crate::POSIX_STACK_SIZE,
        &[],
    ),
];

/// The lines of the C probe, each a check that passed.
const RANDOM_LINES: [&str; 5] = [
    "posix-random: getentropy gave 256 bytes twice, they differ",
    "posix-random: getentropy of 257 bytes gave EINVAL",
    "posix-random: getrandom: GRND_NONBLOCK and GRND_RANDOM give every byte, bad flags EINVAL",
    "posix-random: after fork the child's bytes differ from the parent's",
    "posix-random: ok",
];

/// `cargo xtask posix-random` and its boot in `test`: getentropy and
/// getrandom from C on relibc, and a forked child's bytes, on `machine`.
pub fn random_probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-posix-random.img", &RANDOM_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    const ENDS: &str = "init: posix-random ended: ";
    let output = run_until(cmd, crate::BOOT_TIMEOUT, Some(ENDS), &kernel.elf)?;
    for line in RANDOM_LINES {
        qemu::expect_marker(&output, line)?;
    }
    qemu::expect_stopped_on(
        &output,
        "init: posix-random ended: exit code 0, not restarted",
    )?;
    println!(
        "posix-random on {}: getentropy, getrandom and fork: ok",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| l.to_string()).collect()
    }

    const A: &str =
        "entropy-probe: key 0101010101010101010101010101010101010101010101010101010101010101";
    const B: &str =
        "entropy-probe: key 0202020202020202020202020202020202020202020202020202020202020202";

    const GOOD: [&str; 18] = [
        DRIVER_LINE,
        SEEDED,
        A,
        AT_ONCE,
        FLAG,
        B,
        AT_ONCE,
        FLAG,
        "entropy-probe: two fills of 64 bytes differ, none all zero (1, 2)",
        "entropy-probe: crashing rng",
        DURING_RESTART,
        DRIVER_LINE,
        "entropy-probe: a fill after the restart (3)",
        OK,
        "entropy: reseeded from the device (1)",
        LATER,
        OK,
        ENDED_B,
    ];

    #[test]
    fn a_good_run_passes() {
        assert_eq!(verdict(&lines(&GOOD), DRIVER_LINE, true), Ok(()));
        // On VZ the second client takes no key after the reseed.
        let vz: Vec<_> = GOOD.iter().filter(|l| **l != LATER).copied().collect();
        assert_eq!(verdict(&lines(&vz), DRIVER_LINE, false), Ok(()));
        assert!(verdict(&lines(&vz), DRIVER_LINE, true).is_err());
    }

    /// The run without the line at `i`, or with `with` there.
    fn without(i: usize) -> Vec<String> {
        lines(&GOOD)
            .into_iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(_, l)| l)
            .collect()
    }

    fn with(i: usize, with: &str) -> Vec<String> {
        let mut run = lines(&GOOD);
        run[i] = with.to_owned();
        run
    }

    #[test]
    fn the_service_must_give_two_clients_two_keys_and_keys_at_once() {
        assert!(verdict(&with(5, A), DRIVER_LINE, true).is_err());
        assert!(verdict(&with(5, "entropy-probe: key 02"), DRIVER_LINE, true).is_err());
        for i in [1, 2, 3, 4, 10, 14, 15, 16] {
            assert!(verdict(&without(i), DRIVER_LINE, true).is_err(), "line {i}");
        }
    }

    #[test]
    fn a_restart_that_finds_the_device_running_fails() {
        // Without init's reset the new instance finds the old status.
        let mut run = GOOD;
        run[11] = "virtio-rng: virtio-mmio at 0xa003e00, line 79, status 0xf";
        assert!(verdict(&lines(&run), DRIVER_LINE, true).is_err());
        // One start alone, no fills, or no fill after the restart.
        for i in [11, 8, 12] {
            assert!(verdict(&without(i), DRIVER_LINE, true).is_err(), "line {i}");
        }
    }

    #[test]
    fn every_kind_of_step_must_come_under_term_b() {
        let step = |tag: u8, kind: usize, ticks: u64| {
            format!("service step: {tag} kind {kind} {ticks} ticks detail 0")
        };
        let good = vec![
            step(10, 1, 900),
            step(10, 2, 1500),
            step(10, 65, 3000),
            step(10, 64, 90_000),
            step(11, 5, 1200),
            step(11, 65, 2000),
        ];
        assert_eq!(
            steps_verdict(&good).map(|[a, b]| (a.len(), b.len())),
            Ok((4, 2))
        );
        // A SEED_TAKE past term B fails, though it need not come.
        let mut long = good.clone();
        long.push(step(11, 6, RAM_STEP_MAX + 1));
        assert!(steps_verdict(&long).is_err());
        let mut long = good.clone();
        long.push(step(10, 65, RAM_STEP_MAX + 1));
        assert!(steps_verdict(&long).is_err());
        for i in [0, 1, 2, 4, 5] {
            let mut missing = good.clone();
            missing.remove(i);
            assert!(steps_verdict(&missing).is_err(), "row {i}");
        }
    }
}
