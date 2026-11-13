// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The input service (services/virtio-input) and the image of its probe
//! (tests/input-probe): `INPUT` on QEMU's virtio-mmio, for the images that
//! take keys.
//!
//! The device sits on transport 15, the one at 0xa001e00 on the page
//! 0xa001000, INTID 63: xtask puts it there (`-device
//! virtio-keyboard-device,bus=virtio-mmio-bus.15`, qemu::KEYBOARD). The
//! page is shared with transports 8 to 14, empty ones that read as a
//! device with ID 0, and with no other window of the tables (the display
//! service has 0xa002000, the entropy driver 0xa003000); the driver checks
//! the magic and the ID at its address before it writes.
//!
//! The service holds one DMA object, `dma` (4 pages, uncached: the event
//! queue and the buffers of 64 events). Its sessions come from `connects`:
//! the display service is the one record that names `input` there (in the
//! images that have a screen), and the service lets only that session
//! GRANT and REVOKE. In the image of the probe the probe stands in for the
//! display service in the first part and the display service itself is in
//! the table for the second.
//!
//! Level 34 (spec 3, section 4): above the display service (33), its only
//! client, and below the services at 40 and above, which never call it.

use super::gpu;
use super::{Binding, Dma, GENERAL_CPUS, Kind, Record, Restart, Shares, Window, Write};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The virtio-mmio transport of the device on QEMU and its line.
pub const TRANSPORT: u64 = 0x0a00_1e00;
pub const LINE: u32 = 48 + 15;
/// `Status` of a virtio-mmio transport (Virtio 1.2, 4.2.2).
const MMIO_STATUS: u64 = 0x70;

/// The object of an instance: the event queue and its buffers.
pub const DMA: &[Dma] = &[Dma {
    name: "dma",
    size: 4 * PAGE,
    uncached: true,
    duplicate: false,
}];

/// The input service.
pub const INPUT: Record = Record {
    name: "input",
    program: "virtio-input",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 34,
    ceiling: 34,
    quota: 64 * PAGE,
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
    start: &[],
    release: &[],
    trusted: true,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
};

/// The display service as the images that take keys have it: its session
/// with the input service is the one that may grant the focus.
pub const GPU: Record = Record {
    connects: &["input"],
    ..gpu::GPU
};

/// The probe (role `g`): stands in for the display service with its own
/// session of the input service, then asks the display service for the
/// screen, whose owner has the focus.
const PROBE: Record = Record {
    name: "input-probe",
    program: "input-probe",
    kind: Kind::Client,
    priority: 30,
    ceiling: 30,
    quota: 96 * PAGE,
    handle_limit: 48,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["input", "gpu"],
    args: b"g",
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
};

/// A program the table gives no connection to the input service (role
/// `x`): init refuses its CONNECT.
const STRANGER: Record = Record {
    name: "input-probe-x",
    connects: &[],
    args: b"x",
    ..PROBE
};

/// The probe's image on QEMU.
pub const TABLE: &[Record] = &[INPUT, GPU, PROBE, STRANGER];
