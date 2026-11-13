// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the display service's place in a process (tests/
//! posix-display; sub-project 3, part 3a; spec 3, 3.8 and 7.3) on QEMU's
//! virtio-gpu-device: the session the start gives, the CLONE of it for a
//! forked child, a spawned program and the program a child execs, the
//! display piece of the memory map (not copied by `fork`, refused by
//! `munmap` and `mprotect`, gone with `exec`), and the price of the session
//! in a fork, which the probe prints from the call of fork with and without
//! it.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, Variant, build, build_boot_image, qemu, run_until,
};

/// The probe's image: the services of the POSIX probes, the display
/// service and the probe, which starts its own file once.
pub const PROGRAMS: [ImageProgram; 10] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-display"]),
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
    (
        "virtio-gpu",
        "virtio-gpu",
        crate::gpu_probe::GPU_STACK_SIZE,
        &[],
    ),
    (
        "posix-display",
        "posix-display-probe",
        crate::POSIX_STACK_SIZE,
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

/// The lines of the C probe, each a check that passed.
const LINES: [&str; 9] = [
    "posix-display: the start gave a session that answers a CLONE",
    "posix-display: the buffer is the display piece, one for a process",
    "posix-display: munmap, mprotect and MAP_FIXED over the piece are EINVAL, the piece is as it was",
    "posix-display: a forked child has a session of its own that answers a CLONE, and no piece",
    "posix-display: the child's read at the parent's buffer is SIGSEGV, the parent's pieces are intact",
    "posix-display: a spawned program has a session of its own",
    "posix-display: a set-ID program gets no session",
    "posix-display: exec takes the child's piece away and keeps its session",
    "posix-display: the piece goes with its unmap, a second one can be mapped",
];

const PRICE: &str = "posix-display: fork with the session ";

/// The mean times in ns of the call of fork with the session, without it
/// and of a CLONE alone, from the probe's line.
pub fn price(lines: &[String]) -> Result<(u64, u64, u64), String> {
    let line = lines
        .iter()
        .find_map(|l| l.strip_prefix(PRICE))
        .ok_or("no line of the price of the session in a fork")?;
    let (with, rest) = line
        .split_once(" ns, without it ")
        .ok_or_else(|| format!("the price line {line:?}"))?;
    let (without, clone) = rest
        .split_once(" ns, a CLONE alone ")
        .ok_or_else(|| format!("the price line {line:?}"))?;
    let clone = clone.trim_end_matches(" ns");
    let number = |s: &str| s.parse::<u64>().map_err(|e| format!("{s:?}: {e}"));
    Ok((number(with)?, number(without)?, number(clone)?))
}

/// `cargo xtask posix-display` and its boot in `test`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-posix-display.img", &PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::GPU);
    const ENDS: &str = "init: posix-display ended: ";
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 2, Some(ENDS), &kernel.elf)?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("posix-display: check failed"))
    {
        return Err(failed.clone());
    }
    for line in LINES {
        qemu::expect_marker(&output, line)?;
    }
    qemu::expect_marker(&output, "posix-display: ok")?;
    qemu::expect_stopped_on(
        &output,
        "init: posix-display ended: exit code 0, not restarted",
    )?;
    let (with, without, clone) = price(&output.lines)?;
    println!(
        "posix-display on {}: the session in fork, spawn and exec, the display piece: ok; the call of fork {with} ns with the session, {without} ns without it, a CLONE alone {clone} ns",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_price_is_read_from_its_line() {
        let lines = vec![
            "other".to_owned(),
            format!("{PRICE}1234 ns, without it 1100 ns, a CLONE alone 90 ns"),
        ];
        assert_eq!(price(&lines), Ok((1234, 1100, 90)));
        assert!(price(&lines[..1]).is_err());
        let bad = vec![format!("{PRICE}12 ns, without it 5 ns")];
        assert!(price(&bad).is_err());
    }
}
