// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the Virtio entropy device (services/virtio-rng), the
//! entropy service (services/entropy) and the images of their probe
//! (tests/entropy): `RNG` on QEMU's virtio-mmio, `RNG_VZ` on the Virtio PCI
//! of Apple VZ, `ENTROPY` on both. The service holds no window and no DMA;
//! its feeder is the driver's client, and every POSIX process may be the
//! service's.
//!
//! QEMU's `virt` has 32 virtio-mmio transports of 0x200 bytes from
//! 0xa000000, transport i at SPI 16 + i (INTID 48 + i), and puts the first
//! `-device` on the last of them: xtask gives every run one
//! `virtio-rng-device` (qemu::args), which lands on transport 31 at
//! 0xa003e00, INTID 79 (QEMU 11.1, `info qtree` and the tree of
//! `dumpdtb`); the driver checks the magic and the device ID there before
//! it writes. VZ puts the entropy device at device 6 of bus 0, after the
//! console, INTA at INTID 70 (a walk of the bus, tools/vz-run.swift); the
//! driver checks the function's ID first.
//!
//! The device masters the bus with no SMMU (spec 9): the driver is
//! trusted, and init stops the device before the DMA object of an
//! instance that ended goes: Status 0 on virtio-mmio, which reads 0 once
//! the reset is done; on VZ the Virtio reset and the command word 0, as
//! for the console (vz.rs).

use super::{Binding, Dma, Gate, Kind, Record, Restart, Window, Write};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The virtio-mmio transport of the device on QEMU and its line.
const TRANSPORT: u64 = 0x0a00_3e00;
const MMIO_LINE: u32 = 48 + 31;
/// `Status` of a virtio-mmio transport (Virtio 1.2, 4.2.2).
const MMIO_STATUS: u64 = 0x70;
/// The PCI device of the entropy device on VZ's bus 0, the page of its
/// function 0 in ECAM, and INTA through `interrupt-map`.
const DEVICE: u64 = 6;
const FUNCTION: u64 = 0x4000_0000 + (DEVICE << 15);
const PCI_LINE: u32 = 64 + DEVICE as u32;
/// BAR 0, where the driver puts it (virtio_rng::PLACE), 32 KiB.
const BAR: u64 = 0x1_0001_0000;
/// `device_status` of the Virtio common configuration at the start of
/// BAR 0, the command word of the function and its bit of decoding.
const DEVICE_STATUS: u64 = 0x14;
const COMMAND: u64 = 4;
const MEMORY: u32 = 1 << 1;
/// The DMA object of an instance: the queue's two pages and the bounce
/// page (virtio_rng::dma), four pages, a power of two.
const DMA: &[Dma] = &[Dma {
    name: "dma",
    size: 4 * PAGE,
    uncached: true,
}];

/// The driver on QEMU: level 45, above the entropy service, its client.
pub const RNG: Record = Record {
    name: "rng",
    program: "virtio-rng",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 45,
    ceiling: 45,
    quota: 48 * PAGE,
    handle_limit: 32,
    restart: Restart::Always,
    console: true,
    log: false,
    trace: false,
    windows: &[Window {
        name: "mmio",
        base: TRANSPORT & !(PAGE - 1),
        len: PAGE,
    }],
    bindings: &[Binding {
        name: "irq",
        line: MMIO_LINE,
        edge: false,
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
    }],
    trusted: true,
    root: false,
};

/// The driver on VZ.
pub const RNG_VZ: Record = Record {
    windows: &[
        Window {
            name: "ecam",
            base: FUNCTION,
            len: PAGE,
        },
        Window {
            name: "bar",
            base: BAR,
            len: 8 * PAGE,
        },
    ],
    bindings: &[Binding {
        name: "irq",
        line: PCI_LINE,
        edge: false,
    }],
    args: &FUNCTION.to_le_bytes(),
    // As for the console: the Virtio reset while the function decodes its
    // BARs, then the command word 0.
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
    ..RNG
};

/// The entropy service: level 44, under its driver and above every POSIX
/// process (whose ceilings stay at 39 or below).
pub const ENTROPY: Record = Record {
    name: "entropy",
    program: "entropy",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 44,
    ceiling: 44,
    quota: 64 * PAGE,
    // A handle for each of the 64 seeds that may wait (the copy each
    // brings), beside the service's own.
    handle_limit: 96,
    restart: Restart::Always,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["rng"],
    args: &[],
    dma: &[],
    quiesce: &[],
    trusted: false,
    root: false,
};

/// The probe: seeds that wait for the first bytes, a seed and the seeds at
/// once, two fills, CRASH with seeds while the driver restarts and a fill
/// after it (roles `psfc`; `sfc` on VZ, whose service starts at once).
const PROBE: Record = Record {
    name: "entropy-probe",
    program: "entropy-probe",
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
    connects: &["rng", "entropy"],
    args: b"psfc",
    dma: &[],
    quiesce: &[],
    trusted: false,
    root: false,
};

/// A second client of the service: its key differs from the first's; on
/// QEMU it seeds again after the service's reseed (roles `psw`).
const PROBE_B: Record = Record {
    name: "entropy-probe-b",
    connects: &["entropy"],
    args: b"psw",
    ..PROBE
};

/// The probe's image on QEMU.
pub const TABLE: &[Record] = &[RNG, ENTROPY, PROBE, PROBE_B];

/// The probe's image on VZ, with the console's driver for the console;
/// the second client does not wait for the reseed.
pub const VZ_TABLE: &[Record] = &[
    super::vz::CONSOLE,
    RNG_VZ,
    ENTROPY,
    Record {
        args: b"sfc",
        ..PROBE
    },
    Record {
        args: b"s",
        ..PROBE_B
    },
];
