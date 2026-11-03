// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The network service (services/netd) and the images of its probe
//! (tests/net-probe): `NETD` on QEMU's virtio-mmio, for the images that
//! have a network.
//!
//! QEMU's `virt` has 32 virtio-mmio transports of 0x200 bytes from
//! 0xa000000, transport i at SPI 16 + i (INTID 48 + i). The device sits on
//! transport 7, the one at 0xa000e00 on the page 0xa000000, INTID 55: xtask
//! puts it there (`-device virtio-net-device,bus=virtio-mmio-bus.7`,
//! qemu::net). The page is shared with the empty transports 0 to 6, which
//! read as devices with ID 0, and with no other window of the tables (the
//! input service has 0xa001000); the driver checks the magic and the ID at
//! its address before it writes.
//!
//! The service holds two DMA objects: `dma` (8 pages, uncached: the pages
//! of the two queues) and `net` (a megabyte of cached memory: 512 buffers
//! of 2 KiB for the frames). The device masters the bus with no SMMU (spec
//! 9): the service is trusted, and init stops the device before the objects
//! of an instance that ended go: Status 0, which reads 0 once the reset is
//! done.
//!
//! The service connects to the entropy service (the key of the stack) and
//! to the RAM file service (`/etc/netd.conf`, with the boot profile
//! `BOOT_PROFILE_CLIENTS` names). Level 35: below both, above the
//! processes of POSIX, whose ceilings stay at 31 in the tables.

use super::{
    BOOT_PROFILE_CLIENTS, Binding, Dma, Kind, NET_SERVICE, NETD_CPUS, Record, Restart, Shares,
    Window, Write,
};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The virtio-mmio transport of the device on QEMU and its line.
pub const TRANSPORT: u64 = 0x0a00_0e00;
pub const LINE: u32 = 48 + 7;
/// `Status` of a virtio-mmio transport (Virtio 1.2, 4.2.2).
const MMIO_STATUS: u64 = 0x70;

/// The objects of an instance: the queues' pages, and the buffers.
pub const DMA: &[Dma] = &[
    Dma {
        name: "dma",
        size: 8 * PAGE,
        uncached: true,
        duplicate: false,
    },
    Dma {
        name: "net",
        size: 256 * PAGE,
        uncached: false,
        duplicate: false,
    },
];

/// The network service.
pub const NETD: Record = Record {
    name: NET_SERVICE,
    program: "netd",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 35,
    ceiling: 35,
    // Measured: the probe's runs pass with 24 pages and fail with 16 (the
    // pages the service touches: the stack, the table of the files read at
    // the start, the data); 64 leave the code paths of this stage room.
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
    }],
    bindings: &[Binding {
        name: "irq",
        line: LINE,
        edge: false,
    }],
    connects: &["entropy", "ramfs"],
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
    shares: Shares::CREATOR,
    cpus: NETD_CPUS,
};

/// The probe (tests/net-probe, roles `c` and `k`): the interface's address
/// and 300 pings of the gateway, then CRASH of the service and the same
/// again through a new session.
pub const PROBE: Record = Record {
    name: "net-probe",
    program: "net-probe",
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
    connects: &[NET_SERVICE],
    args: b"ck",
    dma: &[],
    quiesce: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: super::GENERAL_CPUS,
};

// NET_TABLE copies the records of the shell's table by number: a table that
// grows would lose its new record in the image with the network.
const _: () = assert!(super::ramfs::BUSYBOX_DIALOG_TABLE.len() == 9);

/// The image of the shell with the network service. The shell's programs
/// have no session with it yet (the place `Net` of a later stage).
pub const NET_TABLE: &[Record] = &[
    super::ramfs::BUSYBOX_DIALOG_TABLE[0],
    super::ramfs::BUSYBOX_DIALOG_TABLE[1],
    super::ramfs::BUSYBOX_DIALOG_TABLE[2],
    super::ramfs::BUSYBOX_DIALOG_TABLE[3],
    super::ramfs::BUSYBOX_DIALOG_TABLE[4],
    super::ramfs::BUSYBOX_DIALOG_TABLE[5],
    super::ramfs::BUSYBOX_DIALOG_TABLE[6],
    super::ramfs::BUSYBOX_DIALOG_TABLE[7],
    super::ramfs::BUSYBOX_DIALOG_TABLE[8],
    NETD,
];

/// The images of the probe, which differ in the files of the RAM service
/// and in the features of the service: the RAM files, the entropy device's
/// driver and service, the network service and the probe.
pub const NET_PROBE_TABLE: &[Record] = &[
    super::ramfs::RAM_LEGACY,
    super::entropy::RNG,
    super::entropy::ENTROPY,
    NETD,
    PROBE,
];

// The profile of the boot files goes to the network service.
const _: () = {
    let mut found = false;
    let mut i = 0;
    while i < BOOT_PROFILE_CLIENTS.len() {
        found |= str_eq(BOOT_PROFILE_CLIENTS[i], NET_SERVICE);
        i += 1;
    }
    assert!(found);
};

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
