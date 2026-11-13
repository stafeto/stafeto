// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The display service (services/virtio-gpu) and the images of its probe
//! (tests/gpu-probe): `GPU` on QEMU's virtio-mmio, for the images that
//! show a screen.
//!
//! QEMU's `virt` has 32 virtio-mmio transports of 0x200 bytes from
//! 0xa000000, transport i at SPI 16 + i (INTID 48 + i). Init gives no two
//! windows the same page (spec 9), and the page of transports 24 to 31
//! (0xa003000) is the entropy driver's, so the device sits on transport
//! 23, the one at 0xa002e00 on its own page, INTID 71: xtask puts the
//! device there (`-device virtio-gpu-device,bus=virtio-mmio-bus.23`,
//! qemu::GPU). Empty transports on the same page read as a device with ID
//! 0; the driver checks the magic and the ID at its address before it
//! writes.
//!
//! The service holds two DMA objects: `dma` (16 pages, uncached: the
//! queue, then the commands and their answers) and `fb` (a megabyte of
//! cached memory: the screen's buffer, which the owner of the screen
//! maps), the second with DUPLICATE so that the owner gets a copy with
//! MAP_READ and MAP_WRITE only. The device masters the bus with no SMMU
//! (spec 9): the driver is trusted, and init stops the device before the
//! objects of an instance that ended go: Status 0, which reads 0 once the
//! reset is done.
//!
//! Level 33 (spec 3, section 4): above the processes of POSIX, whose
//! ceilings stay at 31 in the tables, and below the services at 40 and
//! above, which never call it.

use super::{Binding, Dma, GENERAL_CPUS, Kind, Record, Restart, Shares, Window, Write};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The virtio-mmio transport of the device on QEMU and its line.
pub const TRANSPORT: u64 = 0x0a00_2e00;
pub const LINE: u32 = 48 + 23;
/// `Status` of a virtio-mmio transport (Virtio 1.2, 4.2.2).
const MMIO_STATUS: u64 = 0x70;

/// The objects of an instance: the queue and the commands, and the buffer
/// of the screen.
pub const DMA: &[Dma] = &[
    Dma {
        name: "dma",
        size: 16 * PAGE,
        uncached: true,
        duplicate: false,
    },
    Dma {
        name: "fb",
        size: 256 * PAGE,
        uncached: false,
        duplicate: true,
    },
];

/// The display service.
pub const GPU: Record = Record {
    name: "gpu",
    program: "virtio-gpu",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 33,
    ceiling: 33,
    quota: 96 * PAGE,
    handle_limit: 64,
    restart: Restart::Always,
    console: true,
    log: false,
    trace: false,
    windows: &[Window {
        name: "mmio",
        base: TRANSPORT & !(PAGE - 1),
        len: PAGE,
        duplicate: false,
        at: crate::table::At::Fixed,
    }],
    bindings: &[Binding {
        name: "irq",
        line: LINE,
        edge: false,
        of: None,
    }],
    connects: &[],
    args: &TRANSPORT.to_le_bytes(),
    dma: DMA,
    // A write of 0 to Status resets the device; it reads 0 once done.
    quiesce: &[Write {
        window: "mmio",
        offset: (TRANSPORT & (PAGE - 1)) + MMIO_STATUS,
        bits: 32,
        value: 0,
        settled: 0xFFFF_FFFF,
        only_if: None,
        confirm: None,
    }],
    trusted: true,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
};

/// The first probe, the owner (role `o`): opens the screen, draws and
/// shows, refuses a second owner, and ends holding the screen.
const PROBE: Record = Record {
    name: "gpu-probe",
    program: "gpu-probe",
    kind: Kind::Client,
    priority: 30,
    ceiling: 30,
    quota: 96 * PAGE,
    handle_limit: 32,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["gpu"],
    args: b"o",
    dma: &[],
    quiesce: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
};

/// The second probe (role `s`): takes the screen once the first ended,
/// finds the buffer cleared, closes the screen and finds the buffer
/// cleared again, kills the service and opens the screen of the new
/// instance.
const PROBE_B: Record = Record {
    name: "gpu-probe-b",
    args: b"s",
    ..PROBE
};

/// The probe's image on QEMU.
pub const TABLE: &[Record] = &[GPU, PROBE, PROBE_B];
