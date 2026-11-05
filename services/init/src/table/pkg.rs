// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables of the package stages on QEMU's `virt` machine: the walk of
//! bus 0 (tests/pci-walk), which measures the host bridge, the disk's
//! function and its BAR before a driver relies on them, and the disk
//! service (services/virtio-blk) with its probe (tests/blk-probe).
//!
//! The disk is the Virtio PCI function at device 1 of bus 0 (xtask's
//! `qemu::store`): the page of its configuration in ECAM, BAR 4 of 16 KiB at
//! the start of the 32-bit window, which the driver measures and sets, and
//! INTA, INTID 36 by the swizzle of the tree's `interrupt-map`
//! (virtio_pci::qemu). The device masters the bus with no SMMU (spec 9): the
//! driver is trusted, and init stops the device before the DMA object of an
//! instance that ended goes, with the Virtio reset while the function
//! decodes its BAR, then the command word 0.

use super::{Binding, Dma, GENERAL_CPUS, Gate, Kind, Record, Restart, Shares, Window, Write};
use crate::PAGE;
use crate::watch::Watch;
use virtio_pci::qemu;

const MS: u64 = 1_000_000;

/// The walk of bus 0 (tests/pci-walk): one window over the ECAM of bus 0,
/// 32 devices of 32 KiB. The program ends by itself; it needs no binding
/// and no DMA.
pub const PCI_WALK_QEMU: Record = Record {
    windows: &[Window {
        name: "ecam",
        base: virtio_pci::qemu::ECAM,
        len: 0x10_0000,
        duplicate: false,
    }],
    ..super::vz::PCI_WALK
};

/// The image of the walk: the PL011's driver for the lines and the walk.
pub const PCI_WALK_QEMU_TABLE: &[Record] = &[super::normal::TABLE[0], PCI_WALK_QEMU];

/// `device_status` of the Virtio common configuration at the start of
/// BAR 4, the command word of the function and its bit of decoding.
const DEVICE_STATUS: u64 = 0x14;
const COMMAND: u64 = 4;
const MEMORY: u32 = 1 << 1;
/// The machine kind of the driver's arguments: QEMU's `virt`.
const MACHINE_QEMU: u64 = 1;

/// The own arguments of the disk driver after the DMA object's physical
/// address: the function's page of configuration and the machine kind.
const BLK_ARGS: [u8; 16] = {
    let mut args = [0; 16];
    let (function, machine) = (
        qemu::DISK_FUNCTION.to_le_bytes(),
        MACHINE_QEMU.to_le_bytes(),
    );
    let mut i = 0;
    while i < 8 {
        args[i] = function[i];
        args[8 + i] = machine[i];
        i += 1;
    }
    args
};

/// The disk service, level 39: not below its client, `pkgd` (whose ceiling
/// stays at 38 or less), above the network service and the entropy driver,
/// below the services it never calls. Its steps stay under 0.9 of term B,
/// and no more than five requests are with the device.
pub const BLK: Record = Record {
    name: "blk",
    program: "virtio-blk",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 39,
    ceiling: 39,
    // Beyond the mappings, the client's buffer of 16 pages and the BAR's 4
    // need page tables.
    quota: 64 * PAGE,
    handle_limit: 32,
    restart: Restart::Always,
    console: true,
    log: false,
    trace: false,
    windows: &[
        Window {
            name: "ecam",
            base: qemu::DISK_FUNCTION,
            len: PAGE,
            duplicate: false,
        },
        Window {
            name: "bar",
            base: qemu::DISK.bar,
            len: qemu::DISK.len,
            duplicate: false,
        },
    ],
    bindings: &[Binding {
        name: "irq",
        line: qemu::DISK_LINE,
        edge: false,
    }],
    connects: &[],
    args: &BLK_ARGS,
    // The queue's two pages, the headers, and four cells of 16 KiB
    // (virtio_blk::dma): 32 pages, a power of two.
    dma: &[Dma {
        name: "dma",
        size: 32 * PAGE,
        uncached: true,
        duplicate: false,
    }],
    // As the console on VZ: the Virtio reset while the function decodes
    // its BAR, then the command word 0, which stops its bus mastering.
    quiesce: &[
        Write {
            window: "bar",
            offset: DEVICE_STATUS,
            bits: 8,
            value: 0,
            settled: 0xFF,
            only_if: Some(Gate {
                window: "ecam",
                offset: COMMAND,
                bits: MEMORY,
            }),
        },
        Write {
            window: "ecam",
            offset: COMMAND,
            bits: 32,
            value: 0,
            settled: 0xFFFF,
            only_if: None,
        },
    ],
    trusted: true,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
};

/// The probe of the disk (tests/blk-probe): a client of the service, at 30.
/// It picks its mode from sector 0 of the disk: a pattern and a flush, the
/// check of the pattern with a restart of the service, or the faults the
/// host injects.
pub const BLK_PROBE: Record = Record {
    name: "blk-probe",
    program: "blk-probe",
    kind: Kind::Client,
    priority: 30,
    ceiling: 30,
    quota: 32 * PAGE,
    handle_limit: 32,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["blk"],
    args: &[],
    dma: &[],
    quiesce: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
};

/// The image of the disk probe: the PL011's driver, the disk service and
/// its client.
pub const BLK_PROBE_TABLE: &[Record] = &[super::normal::TABLE[0], BLK, BLK_PROBE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_disk_record_is_where_the_machine_puts_the_disk() {
        assert_eq!(BLK.windows[0].base, 0x3f00_8000);
        assert_eq!(BLK.windows[0].len, PAGE);
        assert_eq!(BLK.windows[1].base, qemu::DISK.bar);
        assert_eq!(BLK.windows[1].len, 0x4000);
        assert_eq!(BLK.bindings[0].line, 36);
        assert!(!BLK.bindings[0].edge);
        assert_eq!(BLK.args[..8], qemu::DISK_FUNCTION.to_le_bytes());
        assert_eq!(BLK.args[8..], 1u64.to_le_bytes());
        assert_eq!(BLK.dma[0].size, 32 * PAGE);
        assert!(BLK.dma[0].uncached && BLK.trusted);
    }

    #[test]
    fn the_disk_windows_cross_no_other_window_of_its_table() {
        for (i, a) in BLK_PROBE_TABLE.iter().enumerate() {
            for b in &BLK_PROBE_TABLE[i + 1..] {
                for wa in a.windows {
                    for wb in b.windows {
                        assert!(
                            wa.base + wa.len <= wb.base || wb.base + wb.len <= wa.base,
                            "{} and {} overlap",
                            wa.name,
                            wb.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn init_stops_the_device_with_the_reset_and_the_command_word() {
        let [reset, command] = BLK.quiesce else {
            panic!("two writes expected");
        };
        assert_eq!((reset.window, reset.offset, reset.bits), ("bar", 0x14, 8));
        assert_eq!(reset.value, 0);
        let gate = reset.only_if.expect("the reset waits for decoding");
        assert_eq!((gate.window, gate.offset, gate.bits), ("ecam", 4, 2));
        assert_eq!(
            (command.window, command.offset, command.bits),
            ("ecam", 4, 32)
        );
        assert_eq!(command.value, 0);
        assert!(command.only_if.is_none());
    }

    #[test]
    fn the_probe_is_no_higher_than_the_service() {
        const { assert!(BLK_PROBE.ceiling <= BLK.priority) };
        assert_eq!(BLK_PROBE.connects, &[BLK.name]);
    }
}
