// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask pkg-slot`: the place `Packages` of the start area (tests/pkg-slot; sub-project 5,
//! part 3b; pk3-design R13, R17) on QEMU's `virt` with the disk and package services: the session
//! the start gives, the CLONE of it for a forked child, a spawned program and the program a child
//! execs, a set-ID program that gets none, the right of the superuser alone to begin an
//! installation (NOT_ALLOWED through the session of the place), and the price of the session in a
//! fork, which the probe prints from the call of fork with and without it.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, Variant, build, build_boot_image, qemu, run_until,
};

/// The probe's image: the services of the store probe (the disk and package services too), and the
/// probe, which starts its own file once.
pub const PROGRAMS: [ImageProgram; 12] = [
    ("init", "init", INIT_STACK_SIZE, &["table-pkg-slot"]),
    ("uart", "uart", crate::UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", crate::PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "virtio-blk",
        "virtio-blk",
        crate::blk_probe::BLK_STACK_SIZE,
        &[],
    ),
    ("pkgd", "pkgd", crate::store_probe::PKGD_STACK_SIZE, &[]),
    ("pkg-slot", "pkg-slot-probe", crate::POSIX_STACK_SIZE, &[]),
    ("loader", "loader", 0, &[]),
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
const LINES: [&str; 7] = [
    "pkg-slot: the start gave a session that answers a LIST and a CLONE",
    "pkg-slot: a forked child has a session of its own that answers, the parent's answers after the child ended",
    "pkg-slot: a spawned program has a session of its own",
    "pkg-slot: a set-ID program gets no session",
    "pkg-slot: exec keeps the session, and the parent's answers after the program ended",
    "pkg-slot: INSTALL_BEGIN is NOT_ALLOWED for a process that is not the superuser, and taken from the superuser",
    "pkg-slot: BUFFER of a process that is user 1000 is BUSY when the places for any session are in use, the superuser still has one",
];

const PRICE: &str = "pkg-slot: fork with the session ";

/// The mean times in ns of the call of fork with the session, without it and of a CLONE alone,
/// from the probe's line.
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

/// `cargo xtask pkg-slot` and its boot in `test`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-pkg-slot.img", &PROGRAMS, BOOT_PROFILE)?;
    let disk = crate::store_probe::Disk::new("pkg-slot");
    crate::store_probe::write_disk(&disk, None)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&disk.0, None));
    const ENDS: &str = "init: pkg-slot ended: ";
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 4, Some(ENDS), &kernel.elf)?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("pkg-slot: check failed"))
    {
        return Err(failed.clone());
    }
    for line in LINES {
        qemu::expect_marker(&output, line)?;
    }
    qemu::expect_marker(&output, "pkg-slot: ok")?;
    qemu::expect_stopped_on(&output, "init: pkg-slot ended: exit code 0, not restarted")?;
    let (with, without, clone) = price(&output.lines)?;
    println!(
        "pkg-slot on {}: the session in fork, spawn and exec, none for a set-ID program, NOT_ALLOWED for a process that is not the superuser: ok; the call of fork {with} ns with the session, {without} ns without it, a CLONE alone {clone} ns",
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
