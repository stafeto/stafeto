// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables of the boot images of Apple's Virtualization.framework (spec
//! 13.4, 13.5): the driver of the Virtio PCI console under the name of the
//! console's driver, `uart`, with the protocol of the PL011's driver, so
//! that the shell and the POSIX probes connect as on QEMU; then the shell
//! (`TABLE`), the POSIX services and probe (`POSIX_ABI_TABLE`) or the RAM
//! file service and a probe of console input (`BUSYBOX_DIALOG_TABLE`), or
//! rtbench (`RTBENCH_TABLE`).
//!
//! VZ gives the console device 5 of bus 0 whatever else the machine has
//! (checked with an entropy device and a memory balloon added; the driver
//! checks the function's ID before it writes there), and the tree's
//! `interrupt-map` routes INTA of device N to SPI 0x20 + N, level: INTID
//! 64 + N. The device masters the bus with no SMMU (spec 9): the driver is
//! trusted, and init resets the device and clears its command word before
//! the DMA object of an instance that ended goes.

use super::{Binding, Dma, Kind, Record, Restart, Window, Write};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The PCI device of the console on bus 0.
const DEVICE: u64 = 5;
/// The page of its function 0 in ECAM, from `reg` of the tree's `pci`.
const FUNCTION: u64 = 0x4000_0000 + (DEVICE << 15);
/// INTA of the device through `interrupt-map`.
const LINE: u32 = 64 + DEVICE as u32;
/// BAR 0, at the start of the host bridge's 64-bit window (`ranges`),
/// where the driver puts it (virtio_console::pci).
const BAR: u64 = 0x1_0000_0000;

/// The driver of the console (services/virtio-console).
pub const CONSOLE: Record = Record {
    name: "uart",
    program: "virtio-console",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 60,
    ceiling: 60,
    quota: 64 * PAGE,
    handle_limit: 32,
    restart: Restart::Always,
    console: true,
    log: true,
    trace: false,
    windows: &[
        Window {
            name: "ecam",
            base: FUNCTION,
            len: PAGE,
        },
        Window {
            name: "bar",
            base: BAR,
            len: 16 * PAGE,
        },
    ],
    bindings: &[Binding {
        name: "irq",
        line: LINE,
        edge: false,
    }],
    connects: &[],
    args: &FUNCTION.to_le_bytes(),
    dma: &[Dma {
        name: "dma",
        size: 16 * PAGE,
        uncached: true,
    }],
    // A Virtio reset through `device_status` (the common configuration
    // at the start of BAR 0), which reads 0 once done, then the command
    // byte 0: VZ keeps a device's DMA going with bus mastering off alone.
    quiesce: &[
        Write {
            window: "bar",
            offset: 0x14,
            bits: 8,
            value: 0,
            settled: 0xFF,
        },
        // The command word; its status half reads back what it holds. VZ
        // stops the machine at a byte write to the configuration space.
        Write {
            window: "ecam",
            offset: 4,
            bits: 32,
            value: 0,
            settled: 0xFFFF,
        },
    ],
    trusted: true,
};

pub const TABLE: &[Record] = &[
    CONSOLE,
    Record {
        connects: &["uart"],
        ..super::normal::TABLE[1]
    },
];

/// The POSIX services and probe of `ramfs::POSIX_ABI_TABLE`, the probe
/// reading the console through the driver.
pub const POSIX_ABI_TABLE: &[Record] = &[
    CONSOLE,
    super::ramfs::POSIX_ABI_TABLE[0],
    super::ramfs::POSIX_ABI_TABLE[1],
    super::ramfs::POSIX_ABI_TABLE[2],
    super::ramfs::POSIX_ABI_TABLE[3],
    Record {
        connects: &["ramfs", "clock", "clock-peer", "posix", "uart"],
        ..super::ramfs::POSIX_ABI_TABLE[4]
    },
];

/// The RAM file service and a probe that reads the console, as
/// `ramfs::BUSYBOX_DIALOG_TABLE` on QEMU.
pub const BUSYBOX_DIALOG_TABLE: &[Record] = &[
    CONSOLE,
    super::ramfs::TABLE[0],
    super::ramfs::BUSYBOX_DIALOG_TABLE[2],
];

/// rtbench as a client beside the driver, which shows its lines: its main
/// thread at 20, its workers up to 30 (tests/rtbench), the driver at 60
/// above them all with its timer of 50 ms.
pub const RTBENCH_TABLE: &[Record] = &[
    CONSOLE,
    Record {
        name: "rtbench",
        program: "rtbench",
        priority: 20,
        ceiling: 30,
        quota: 1024 * PAGE,
        handle_limit: 64,
        restart: Restart::Never,
        trace: false,
        ..super::normal::TABLE[1]
    },
];
