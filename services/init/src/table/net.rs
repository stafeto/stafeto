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

/// The network service (the same record in the image of the shell and in the
/// images of the probe: its `.bss` is the same in both).
pub const NETD: Record = Record {
    name: NET_SERVICE,
    program: "netd",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 35,
    ceiling: 35,
    // The worst case, by the formula of the stage (reports/2026-11-04-net-p1a):
    // the pages of `.data` and `.bss` of the release build (the pool of
    // buffers is 2 048 of them), the whole stack of 32 pages and 16 for the
    // rest. `.bss` 8 922 225 bytes = 2 178 pages, `.data` none: 2 178 + 32 +
    // 16. The kernel does not charge the pages of `.bss` to the quota in the
    // probe's runs (the table filled to 256 places passes with 32 pages and
    // fails to start with 24, where the page tables of the mappings do not
    // fit), so the number is a bound that the measurement does not reach.
    quota: 2226 * PAGE,
    // 128 operations' handles of notification, the notary session, the page
    // of generations, and a reserve.
    handle_limit: 192,
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

/// The roles of the probe (tests/net-probe): `c` the interface's address and
/// 300 pings of the gateway, `b` the registry of ports and the sessions, `sN`
/// N places of the table at once (the digits are N) and 50 pings, `e` the
/// rates of the loopback, `f` the full batch of a step after a hold of the
/// service, `a` every group of sockets with work at once, `w` sixteen
/// operations told by one datagram, `i` 150 s of idle, `l` a queue of 16 with
/// blocking ACCEPT and WATCH, `r` the timers, `k` CRASH of the service and the same as `c`
/// through a new session. The images of the measurement of the steps
/// (`net-sockets-N`) run `s` at 8, 64 and 256 places; the others at the
/// limit of the sockets the service serves (netd::places::SOCKETS_LIMIT,
/// which a test of xtask compares with the number here).
pub const ROLES: &[u8] = if cfg!(feature = "net-sockets-8") {
    b"cs8k"
} else if cfg!(feature = "net-sockets-64") {
    b"cs64k"
} else if cfg!(feature = "net-sockets-256") {
    b"cs256k"
} else if cfg!(feature = "net-echo") {
    b"cek"
} else if cfg!(feature = "net-full-batch") {
    b"cfk"
} else if cfg!(feature = "net-all-groups") {
    b"cak"
} else if cfg!(feature = "net-wakes") {
    b"cwk"
} else if cfg!(feature = "net-idle") {
    b"cik"
} else if cfg!(feature = "net-listen") {
    b"clk"
} else if cfg!(feature = "net-timers") {
    b"crk"
} else {
    b"cbs256k"
};

/// The probe (tests/net-probe).
pub const PROBE: Record = Record {
    name: "net-probe",
    program: "net-probe",
    kind: Kind::Client,
    priority: 30,
    ceiling: 30,
    quota: 64 * PAGE,
    handle_limit: 64,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &[NET_SERVICE],
    args: ROLES,
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

/// The CPUs of the services and the probe in the images of the measurement of
/// the steps (`net-alone`): the network service has CPU 0 to itself, so that
/// the longest step it measures holds no time of another process (the
/// preemption of a service by others belongs to the analysis of response
/// time). The image runs on two CPUs. The measurement does not use it: under
/// -icount the counter holds the instructions of all the CPUs.
const OTHERS_CPUS: u8 = 0b0010;

const fn on(r: Record, cpus: u8) -> Record {
    Record { cpus, ..r }
}

/// The images of the probe, which differ in the files of the RAM service
/// and in the features of the service: the RAM files, the entropy device's
/// driver and service, the network service and the probe.
pub const NET_PROBE_TABLE: &[Record] = if cfg!(feature = "net-alone") {
    &[
        super::ramfs::RAM_LEGACY,
        on(super::entropy::RNG, OTHERS_CPUS),
        on(super::entropy::ENTROPY, OTHERS_CPUS),
        NETD,
        on(PROBE, OTHERS_CPUS),
    ]
} else {
    &[
        super::ramfs::RAM_LEGACY,
        super::entropy::RNG,
        super::entropy::ENTROPY,
        NETD,
        PROBE,
    ]
};

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
