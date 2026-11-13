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
pub const RNG_STACK_SIZE: u32 = 32 * 1024;

/// The stack of the entropy service's loop: the service with the table of
/// the clones it gave (8 KiB); its table of sessions lies in its data.
pub const ENTROPY_STACK_SIZE: u32 = 32 * 1024;

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
        &["steps", "report", "slow-start"],
    ),
];

/// The image of the boot seed with no device (`cargo xtask entropy-seed`):
/// init gives the entropy service the page of the seed, no driver is
/// started, and the service, built with CRASH, is ended by the probe once.
pub const SEED_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-entropy-seed"]),
    ("entropy-probe", "entropy-probe", CHILD_STACK_SIZE, &[]),
    (
        "entropy",
        "entropy",
        ENTROPY_STACK_SIZE,
        &["crash", "report"],
    ),
];

/// The same image with a service that never reads the page.
pub const SEED_BREAK_PROGRAMS: [ImageProgram; 3] = [
    SEED_PROGRAMS[0],
    SEED_PROGRAMS[1],
    (
        "entropy",
        "entropy",
        ENTROPY_STACK_SIZE,
        &["crash", "report", "break-seed-page"],
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
const WAITED: &str = "entropy-probe: 32 seeds waited for the first bytes, 32 told";
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
/// The kinds of the service's steps that must come: SEED, SEED_TAKE of
/// the seeds that waited for the first bytes (the service's build
/// `slow-start`), and its own steps: the feeder's bytes (a seed or a
/// reseed) and each part of the seeds that waited, told.
const ENTROPY_STEP_KINDS: [(usize, &str); 4] = [
    (5, "Seed"),
    (6, "SeedTake"),
    (8, "Clone, the table of clones full"),
    (65, "the feeder's bytes and the tells"),
];
/// The line of the probe's role `x` (QEMU): CLONE with the service's
/// table of live clones full, so the measured CLONE (kind 8) is its
/// longest. It takes the same ticks with any number of live clones.
const CLONES_FULL: &str = "entropy-probe: the service's table of clones is full: 320 clones";

/// What a run of the probe printed, judged: the driver started twice, each
/// time with the device's status 0 (`driver`), the fills came before and
/// after the restart; the service was seeded once and gave the two
/// clients two keys that differ, and keys at once, during the restart too;
/// with `reseed` (the QEMU image, whose service starts late), 32 seeds of
/// each client, the service's 64 places, waited for the first bytes and were told, and the service
/// reseeded and gave a key after it; both clients ended well.
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
        wanted.push((WAITED, 2));
        wanted.push((CLONES_FULL, 1));
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

/// The CLONE of the entropy service with its table of 320 clones full, in
/// ticks: 5551 measured, where a walk of the table took 12 560. A client
/// that is no clone makes the step walk the table of roots (32 entries,
/// about 200 ticks more), so the bound sits above that and far below the
/// walk of the table, so that a return to a walk fails.
const CLONE_FULL_MAX: u64 = 6_500;

/// The longest step of each kind of the loop of `tag`, from the lines of a
/// run under -icount: every kind of `kinds` came, and every kind stayed
/// under term B, the heartbeat too (it counts its own part only). Gives
/// the rows.
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
    if let Some(row) = rows.iter().find(|r| r.1 > RAM_STEP_MAX) {
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
    .and_then(|rows| {
        let clone = rows[1].iter().find(|r| r.0 == 8).map_or(0, |r| r.1);
        if clone > CLONE_FULL_MAX {
            return Err(format!(
                "the entropy service: CLONE with the table full took {clone} ticks, past {CLONE_FULL_MAX}"
            ));
        }
        Ok(rows)
    })
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
        crate::check_waits(&output.lines, &["10", "11"], "entropy")?;
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

/// The line of an instance seeded from the page of the boot seed (the
/// bytes are not printed), and of one with no source at all.
const BOOT_PAGE: &str = "entropy: seeded from the boot page (32 bytes)";
const NO_SOURCE: &str = "entropy: no source on this boot; keys wait";
const KEYS_AFTER: &str = "entropy-probe: 32 keys from the service after its restart";

/// What the run of the image of the boot seed printed, judged: both
/// instances (before and after the CRASH) seeded from the page with 32
/// bytes, the keys came at once, new after the restart, no line says the
/// device or `no source`, and the probe ended well.
pub fn seed_verdict(lines: &[String]) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.starts_with(marker)).count();
    for (marker, n) in [
        (BOOT_PAGE, 2),
        (AT_ONCE, 1),
        (FLAG, 1),
        (KEYS_AFTER, 1),
        (OK, 1),
        (NO_SOURCE, 0),
        (SEEDED, 0),
    ] {
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
    let keys: Vec<_> = lines.iter().filter_map(|l| l.strip_prefix(KEY)).collect();
    if keys.len() != 1 || keys[0].len() != 64 {
        return Err(format!("the key of the probe: {keys:?}"));
    }
    Ok(())
}

/// `cargo xtask entropy-seed`: the image with no device of random bytes
/// and the page of the boot seed that QEMU's tree gives (the kernel takes
/// `/chosen/rng-seed`, init gives the page to the service). The service
/// seeds from it before it serves; the probe ends it with CRASH, and the
/// instance init starts seeds from the key the first one left in the page,
/// so that its keys come at once and differ from every key before. The
/// break, a service that never reads the page, finds no source, says so,
/// and the probe waits for its first key until the run is cut.
pub fn seed_probe() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-entropy-seed.img", &SEED_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let output = run_until(cmd, crate::BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    seed_verdict(&output.lines).map_err(|e| format!("entropy-seed: {e}"))?;
    println!(
        "entropy-seed: seeded from the boot page with no device, keys at once, and again after a restart of the service: ok"
    );
    let image = build_boot_image(
        "boot-entropy-seed-break.img",
        &SEED_BREAK_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let output = run_until(cmd, Duration::from_secs(10), Some(ENDED), &kernel.elf)?;
    let said = output.lines.iter().any(|l| l.starts_with(NO_SOURCE));
    if output.stopped_on_marker || !output.timed_out || !said {
        return Err(format!(
            "the break (the service ignores the page) was not caught: ended {}, timed out {}, line {said}",
            output.stopped_on_marker, output.timed_out
        ));
    }
    println!("entropy-seed: the break that ignores the page is caught: no source, the probe waits");
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
pub const fn random_programs(
    pipe: &'static [&'static str],
    loader: &'static [&'static str],
) -> [ImageProgram; 9] {
    [
        ("init", "init", INIT_STACK_SIZE, &["table-posix-random"]),
        ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]),
        (
            "posix-process-service",
            "posix-process-service",
            64 * 1024,
            &[],
        ),
        ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
        ("pipe", "pipe", crate::PIPE_STACK_SIZE, pipe),
        ("loader", "loader", 0, loader),
        ("virtio-rng", "virtio-rng", RNG_STACK_SIZE, &[]),
        // The first fill waits 500 ms: the probe meets the wait for it.
        ("entropy", "entropy", ENTROPY_STACK_SIZE, &["slow-start"]),
        (
            "posix-random",
            "posix-random-probe",
            crate::POSIX_STACK_SIZE,
            &[],
        ),
    ]
}

/// The probe's image with the steps of the pipe service counted.
static RANDOM_PROGRAMS: [ImageProgram; 9] = random_programs(&[], &[]);
static RANDOM_PROGRAMS_STEPS: [ImageProgram; 9] = random_programs(&["steps"], &[]);
/// The same with a loader that gives AT_RANDOM as zeros (feature `break-at-random`).
static RANDOM_BREAK_PROGRAMS: [ImageProgram; 9] = random_programs(&[], &["break-at-random"]);

/// The lines of the C probe, each a check that passed.
const RANDOM_LINES: [&str; 26] = [
    "posix-random: the start waited for the first seed, so getrandom with GRND_NONBLOCK gave every byte in main",
    "posix-random: getentropy with another inside a handler",
    "posix-random: a pipe read went on after another inside a handler",
    "posix-random: arc4random gave its word in a thread that got a signal",
    "posix-random: getentropy gave its bytes in a thread that was asked to cancel",
    "posix-random: cancellation left the calls of getentropy bounded",
    "posix-random: two threads read 4096 bytes of /dev/urandom at once, all different",
    "posix-random: getentropy gave 256 bytes twice, they differ",
    "posix-random: getentropy of 257 bytes gave EINVAL",
    "posix-random: getrandom: GRND_NONBLOCK and GRND_RANDOM give every byte, bad flags EINVAL",
    "posix-random: after fork the child's bytes differ from the parent's",
    "posix-random: /dev/urandom and /dev/random are character devices that give 4096 bytes each, all different",
    "posix-random: writes to the devices are accepted",
    "posix-random: a dup of a device reads",
    "posix-random: arc4random, arc4random_buf and arc4random_uniform",
    "posix-random: mkstemp gave",
    "posix-random: a device descriptor crosses posix_spawn, FD_CLOEXEC closes it",
    "posix-random: a device descriptor crosses fork, the bytes of parent and child differ",
    "posix-random: AT_RANDOM gave 16 bytes to each of two programs, they differ and are not zero",
    "posix-random: the stack canary differs in each of three programs, is not zero and has a zero low byte",
    "posix-random: without entropy mkstemp, mkostemp, mkdtemp, mktemp, tmpnam, tempnam and shmget of a new segment failed with ENOSYS and left no name",
    "posix-random: a lookup without entropy failed with EAI_SYSTEM and ENOSYS",
    "posix-random: a set-ID program takes its entropy session from the service, and a forged one gets no request",
    "posix-random: a set-ID program has AT_RANDOM from its verified session",
    "posix-random: a set-ID program takes its pipe session from the service, and a forged one gets no request",
    "posix-random: ok",
];

/// `cargo xtask posix-random` and its boot in `test`: getentropy and
/// getrandom from C on relibc, and a forked child's bytes, on `machine`.
pub fn random_probe(machine: &qemu::Machine) -> Result<(), String> {
    random_run(machine, false).map(drop)
}

/// `cargo xtask posix-random-steps`: the same probe under -icount with the
/// pipe service's steps counted; VerifySession (kind 46, which the set-ID
/// starts of the probe send it) stays under 0.9 of term B.
pub fn random_steps() -> Result<(), String> {
    let lines = random_run(&qemu::VIRT, true)?;
    let rows = longest_steps(&lines, "4");
    let Some(row) = rows.iter().find(|r| r.0 == 46) else {
        return Err(format!(
            "the pipe service ran no VerifySession step: {rows:?}"
        ));
    };
    println!(
        "pipe service VerifySession: {} ticks, detail {}, B {}",
        row.1,
        row.2,
        crate::TERM_B
    );
    if row.1 > crate::TERM_B * 9 / 10 {
        return Err(format!("VerifySession: a step past 0.9 of B: {row:?}"));
    }
    Ok(())
}

/// The probe's image with the network service, and with its steps counted.
const fn random_net_programs(
    table: &'static [&'static str],
    netd: &'static [&'static str],
) -> [ImageProgram; 10] {
    let base = random_programs(&[], &[]);
    [
        ("init", "init", INIT_STACK_SIZE, table),
        base[1],
        base[2],
        base[3],
        base[4],
        base[5],
        base[6],
        base[7],
        base[8],
        ("netd", "netd", crate::net_probe::NETD_STACK_SIZE, netd),
    ]
}
static RANDOM_NET_PROGRAMS: [ImageProgram; 10] =
    random_net_programs(&["table-posix-random-net"], &[]);
static RANDOM_NET_PROGRAMS_STEPS: [ImageProgram; 10] =
    random_net_programs(&["table-posix-random-net"], &["steps"]);
/// With two stack instances of the service (the image runs on two CPUs).
static RANDOM_NET2_PROGRAMS: [ImageProgram; 10] =
    random_net_programs(&["table-posix-random-net2"], &["instances-2"]);
static RANDOM_NET2_PROGRAMS_STEPS: [ImageProgram; 10] =
    random_net_programs(&["table-posix-random-net2"], &["instances-2", "steps"]);

/// The lines of the C probe's role `net`, each a check that passed.
const RANDOM_NET_LINES: [&str; 3] = [
    "posix-random: a set-ID program takes its net session from the service, and a forged one gets no request",
    "posix-random: a set-ID program keeps the socket it inherited with its net session",
    "posix-random: net ok",
];

/// The lines of the role `net2`.
const RANDOM_NET2_LINES: [&str; 3] = [
    "posix-random: the net session is homed on the second instance (CPU 1)",
    "posix-random: a set-ID program keeps a socket of a session homed on the second instance",
    "posix-random: net2 ok",
];

/// The tag of the network service's lines of steps, and the kind of VerifySession.
const NETD_TAG: &str = "14";
const NETD_VERIFY_KIND: usize = 43;

/// `cargo xtask posix-random-net`: the sessions of a set-ID program with the network service
/// (tests/posix-random, role `net`): the image of the probe of getentropy with the network
/// service on QEMU's user network. With `steps` the same under -icount with the service counting
/// its steps: VerifySession (kind 43) and every other kind stay under the bound
/// (`net_probe::STEP_MAX`), and the kinds above the margin are named.
pub fn random_net(steps: bool) -> Result<(), String> {
    random_net_run(steps, false)
}

/// `cargo xtask posix-random-net-two`: the same with two stack instances of the network
/// service on two CPUs (role `net2`): the probe's process is homed on the second instance, and
/// the set-ID program it starts keeps the socket it inherits, which the first instance's check
/// forwards to the instance that holds it. With `steps` under -icount, naming the VerifySession
/// steps of both instances.
pub fn random_net_two(steps: bool) -> Result<(), String> {
    qemu::on_cpus(2, || random_net_run(steps, true))
}

fn random_net_run(steps: bool, two: bool) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let programs: &[ImageProgram] = match (two, steps) {
        (false, false) => &RANDOM_NET_PROGRAMS,
        (false, true) => &RANDOM_NET_PROGRAMS_STEPS,
        (true, false) => &RANDOM_NET2_PROGRAMS,
        (true, true) => &RANDOM_NET2_PROGRAMS_STEPS,
    };
    let name = if two {
        "boot-posix-random-net2.img"
    } else {
        "boot-posix-random-net.img"
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    // Under -icount the counter holds the instructions of all the CPUs, so a step of one
    // instance of two comes out in millions: the steps of two instances are read on the
    // generic timer (the host's noise is in them).
    if steps && !two {
        cmd.args(qemu::ICOUNT);
    }
    const ENDS: &str = "init: posix-random ended: ";
    let timeout = crate::BOOT_TIMEOUT * if steps { 20 } else { 2 };
    let output = run_until(cmd, timeout, Some(ENDS), &kernel.elf)?;
    let lines: &[&str] = if two {
        &RANDOM_NET2_LINES
    } else {
        &RANDOM_NET_LINES
    };
    for line in lines {
        qemu::expect_marker(&output, line)?;
    }
    qemu::expect_stopped_on(
        &output,
        "init: posix-random ended: exit code 0, not restarted",
    )?;
    if steps {
        let mut rows = longest_steps(&output.lines, NETD_TAG);
        let Some(verify) = rows.iter().find(|r| r.0 == NETD_VERIFY_KIND).copied() else {
            return Err(format!(
                "the network service ran no VerifySession step: {rows:?}"
            ));
        };
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        let table: Vec<_> = rows
            .iter()
            .take(4)
            .map(|(kind, ticks, _)| format!("kind {kind} {ticks}"))
            .collect();
        println!(
            "net service VerifySession: {} ticks, detail {}; the longest steps: {} (margin {}, bound {})",
            verify.1,
            verify.2,
            table.join(", "),
            crate::net_probe::STEP_MARGIN,
            crate::net_probe::STEP_MAX
        );
        if two {
            let all: Vec<_> = output
                .lines
                .iter()
                .filter(|l| l.starts_with("service step: 14 kind 43 "))
                .map(|l| l.split_whitespace().nth(5).unwrap_or("?"))
                .collect();
            println!(
                "net service VerifySession steps of both instances, in order of the new longest: {all:?}"
            );
        }
        // The timer's ticks of the two-CPU run are no instruction counts: no bound applies.
        if two {
            println!("posix-random-net-two: step ticks are the generic timer's, no bound applies");
        } else if let Some(row) = rows.iter().find(|r| r.1 > crate::net_probe::STEP_MAX) {
            return Err(format!(
                "the network service: a step past the bound: {row:?}"
            ));
        }
        if !two && verify.1 > crate::net_probe::STEP_MARGIN {
            return Err(format!("VerifySession: a step past the margin: {verify:?}"));
        }
    }
    println!(
        "posix-random-net{}: a set-ID program takes its net session from the service, keeps an inherited socket: ok",
        if two { "-two" } else { "" }
    );
    Ok(())
}

/// `cargo xtask random-breaks`: the probe of AT_RANDOM with a loader that
/// gives zeros fails (the probe's check of the bytes; its exit code 20), and
/// no line `posix-random: ok` comes.
pub fn random_breaks() -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-posix-random-break.img",
        &RANDOM_BREAK_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let output = run_until(
        cmd,
        crate::BOOT_TIMEOUT,
        Some("init: posix-random ended: "),
        &kernel.elf,
    )?;
    qemu::expect_marker(&output, "init: posix-random ended: exit code 20")?;
    if output.lines.iter().any(|l| l == "posix-random: ok") {
        return Err("the loader that gives zeros passed the probe".into());
    }
    qemu::expect_marker(&output, "check failed at line")?;
    println!("random-breaks: a loader that gives AT_RANDOM as zeros is caught");
    Ok(())
}

fn random_run(machine: &qemu::Machine, steps: bool) -> Result<Vec<String>, String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let programs: &[ImageProgram] = if steps {
        &RANDOM_PROGRAMS_STEPS
    } else {
        &RANDOM_PROGRAMS
    };
    let image = build_boot_image("boot-posix-random.img", programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    if steps {
        cmd.args(qemu::ICOUNT);
    }
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
    Ok(output.lines)
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

    const GOOD: [&str; 21] = [
        DRIVER_LINE,
        SEEDED,
        WAITED,
        WAITED,
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
        CLONES_FULL,
        OK,
        ENDED_B,
    ];

    #[test]
    fn a_good_run_passes() {
        assert_eq!(verdict(&lines(&GOOD), DRIVER_LINE, true), Ok(()));
        // On VZ the second client takes no key after the reseed.
        let vz: Vec<_> = GOOD
            .iter()
            .filter(|l| **l != LATER && **l != WAITED && **l != CLONES_FULL)
            .copied()
            .collect();
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
        assert!(verdict(&with(7, A), DRIVER_LINE, true).is_err());
        assert!(verdict(&with(7, "entropy-probe: key 02"), DRIVER_LINE, true).is_err());
        for i in [1, 2, 4, 5, 6, 12, 16, 17, 18, 19] {
            assert!(verdict(&without(i), DRIVER_LINE, true).is_err(), "line {i}");
        }
    }

    #[test]
    fn a_restart_that_finds_the_device_running_fails() {
        // Without init's reset the new instance finds the old status.
        let mut run = GOOD;
        run[13] = "virtio-rng: virtio-mmio at 0xa003e00, line 79, status 0xf";
        assert!(verdict(&lines(&run), DRIVER_LINE, true).is_err());
        // One start alone, no fills, or no fill after the restart.
        for i in [13, 10, 14] {
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
            step(10, 64, 1_100),
            step(11, 5, 1200),
            step(11, 6, 1300),
            step(11, 8, 5600),
            step(11, 65, 2000),
        ];
        assert_eq!(
            steps_verdict(&good).map(|[a, b]| (a.len(), b.len())),
            Ok((4, 4))
        );
        let mut long = good.clone();
        long.push(step(11, 6, RAM_STEP_MAX + 1));
        assert!(steps_verdict(&long).is_err());
        let mut long = good.clone();
        long.push(step(11, 8, CLONE_FULL_MAX + 1));
        assert!(
            steps_verdict(&long).is_err(),
            "a CLONE that walks the table"
        );
        let mut long = good.clone();
        long.push(step(10, 65, RAM_STEP_MAX + 1));
        assert!(steps_verdict(&long).is_err());
        // The heartbeat counts its own part only, and is bound like the rest.
        let mut long = good.clone();
        long.push(step(10, 64, RAM_STEP_MAX + 1));
        assert!(steps_verdict(&long).is_err(), "a heartbeat past term B");
        for i in [0, 1, 2, 4, 5, 6, 7] {
            let mut missing = good.clone();
            missing.remove(i);
            assert!(steps_verdict(&missing).is_err(), "row {i}");
        }
    }
}
