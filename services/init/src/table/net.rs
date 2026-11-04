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
//! On Apple VZ the device is a Virtio PCI function: `NETD_VZ` (and
//! `NETD_VZ2` with a second network device) hold the windows `ecam` (the
//! pages of the functions, device 1 and 2 of bus 0) and `bar` (their BARs
//! 0), and the bindings of INTA, INTID 64 + the device (the numbers are
//! those of `cargo xtask pci-walk-vz`; services/netd/src/pci.rs holds the
//! same, and a test of this crate compares them). The device masters the
//! bus with no SMMU, so init stops it as the console and the entropy
//! device (vz.rs): the Virtio reset through `device_status` at the start
//! of BAR 0 while the function decodes its BARs, then the command word 0.
//!
//! The service connects to the entropy service (the key of the stack) and
//! to the RAM file service (`/etc/netd.conf`, with the boot profile
//! `BOOT_PROFILE_CLIENTS` names). Level 35: below both, above the
//! processes of POSIX, whose ceilings stay at 31 in the tables.

use super::{
    BOOT_PROFILE_CLIENTS, Binding, Dma, Gate, Kind, NET_SERVICE, NETD_CPUS, Record, Restart,
    Shares, Window, Write,
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
    // rest. `.bss` 9 156 865 bytes = 2 236 pages (the second device's
    // interface, queues and books are in it), `.data` none: 2 236 + 32 + 16.
    // The kernel does not charge the pages of `.bss` to the quota in the
    // probe's runs (the table filled to 256 places passes with 32 pages and
    // fails to start with 24, where the page tables of the mappings do not
    // fit), so the number is a bound that the measurement does not reach.
    quota: 2284 * PAGE,
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

/// The PCI devices of the network on VZ's bus 0 (services/netd/src/pci.rs).
const VZ_DEVICE: [u64; 2] = [1, 2];
const VZ_ECAM: u64 = 0x4000_0000;
/// BAR 0 of the first device and the bytes of each BAR 0.
const VZ_BAR: u64 = 0x1_0002_0000;
const VZ_BAR_LEN: u64 = 0x1_0000;
/// `device_status` of the Virtio common configuration, the command word
/// of the function and its bit of memory decoding.
const DEVICE_STATUS: u64 = 0x14;
const COMMAND: u64 = 4;
const MEMORY: u32 = 1 << 1;

/// The page of the function of device `i` in ECAM, and where it lies inside
/// the window `ecam`, which starts at the page of device 0.
const fn vz_function(i: usize) -> u64 {
    VZ_ECAM + (VZ_DEVICE[i] << 15)
}

const fn vz_ecam_offset(i: usize) -> u64 {
    vz_function(i) - vz_function(0)
}

const fn vz_bar_offset(i: usize) -> u64 {
    i as u64 * VZ_BAR_LEN
}

/// The arguments of the record after the objects' addresses: the function
/// of each device, 0 for a device the record has not.
const fn vz_args<const N: usize>() -> [u8; 16] {
    let mut args = [0u8; 16];
    let mut i = 0;
    while i < N {
        let word = vz_function(i).to_le_bytes();
        let mut b = 0;
        while b < 8 {
            args[8 * i + b] = word[b];
            b += 1;
        }
        i += 1;
    }
    args
}

/// The stop of device `i` of the record: the Virtio reset through BAR 0,
/// while the function decodes its BARs (`Write::only_if`), and then the
/// command word 0 (VZ stops the machine at a byte write to the
/// configuration space; the word's status half reads back what it holds).
const fn vz_stop(i: usize) -> [Write; 2] {
    [
        Write {
            window: "bar",
            offset: vz_bar_offset(i) + DEVICE_STATUS,
            bits: 8,
            value: 0,
            settled: 0xFF,
            only_if: Some(Gate {
                window: "ecam",
                offset: vz_ecam_offset(i) + COMMAND,
                bits: MEMORY,
            }),
        },
        Write {
            window: "ecam",
            offset: vz_ecam_offset(i) + COMMAND,
            bits: 32,
            value: 0,
            settled: 0xFFFF,
            only_if: None,
        },
    ]
}

static VZ_ARGS: [u8; 16] = vz_args::<1>();
static VZ_STOP: [Write; 2] = vz_stop(0);
static VZ2_ARGS: [u8; 16] = vz_args::<2>();
static VZ2_STOP: [Write; 4] = {
    let (a, b) = (vz_stop(0), vz_stop(1));
    [a[0], a[1], b[0], b[1]]
};

/// The objects of an instance with two devices: each of the first's two
/// objects twice as big, the second device taking the second half of each
/// (`MAX_DMA` is two objects; the second device's own objects come with
/// the claim of it, a later stage). `net` is 2 MiB, under the 4 MiB a
/// contiguous object may be.
pub const DMA_TWO: &[Dma] = &[
    Dma {
        name: "dma",
        size: 16 * PAGE,
        uncached: true,
        duplicate: false,
    },
    Dma {
        name: "net",
        size: 512 * PAGE,
        uncached: false,
        duplicate: false,
    },
];

/// The service on VZ with the first network device: INTA of device 1 at
/// INTID 65.
pub const NETD_VZ: Record = Record {
    windows: &[
        Window {
            name: "ecam",
            base: VZ_ECAM + (VZ_DEVICE[0] << 15),
            len: super::PAGE,
        },
        Window {
            name: "bar",
            base: VZ_BAR,
            len: VZ_BAR_LEN,
        },
    ],
    bindings: &[Binding {
        name: "irq",
        line: 64 + VZ_DEVICE[0] as u32,
        edge: false,
    }],
    args: &VZ_ARGS,
    quiesce: &VZ_STOP,
    ..NETD
};

/// The service on VZ with both network devices: the windows hold the pages
/// of the functions of devices 1 and 2 and their BARs, INTA of device 2 is
/// INTID 66, and init stops both devices.
pub const NETD_VZ2: Record = Record {
    windows: &[
        Window {
            name: "ecam",
            base: VZ_ECAM + (VZ_DEVICE[0] << 15),
            len: vz_function(1) + super::PAGE - vz_function(0),
        },
        Window {
            name: "bar",
            base: VZ_BAR,
            len: 2 * VZ_BAR_LEN,
        },
    ],
    bindings: &[
        Binding {
            name: "irq",
            line: 64 + VZ_DEVICE[0] as u32,
            edge: false,
        },
        Binding {
            name: "irq1",
            line: 64 + VZ_DEVICE[1] as u32,
            edge: false,
        },
    ],
    args: &VZ2_ARGS,
    quiesce: &VZ2_STOP,
    dma: DMA_TWO,
    ..NETD
};

/// The second virtio-mmio transport of QEMU's `virt` for the image of two
/// devices (`-device virtio-net-device,bus=virtio-mmio-bus.14`): transport
/// 14 at 0xa001c00 on the page 0xa001000, INTID 62.
pub const TRANSPORT1: u64 = 0x0a00_1c00;
pub const LINE1: u32 = 48 + 14;

const fn mmio_args() -> [u8; 16] {
    let (a, b) = (TRANSPORT.to_le_bytes(), TRANSPORT1.to_le_bytes());
    let mut args = [0u8; 16];
    let mut i = 0;
    while i < 8 {
        args[i] = a[i];
        args[8 + i] = b[i];
        i += 1;
    }
    args
}

static MMIO2_ARGS: [u8; 16] = mmio_args();

/// The service with both network devices on QEMU: the Status of each
/// transport written 0 once an instance ended.
pub const NETD_TWO: Record = Record {
    windows: &[
        Window {
            name: "mmio",
            base: TRANSPORT & !(PAGE - 1),
            len: PAGE,
        },
        Window {
            name: "mmio1",
            base: TRANSPORT1 & !(PAGE - 1),
            len: PAGE,
        },
    ],
    bindings: &[
        Binding {
            name: "irq",
            line: LINE,
            edge: false,
        },
        Binding {
            name: "irq1",
            line: LINE1,
            edge: false,
        },
    ],
    args: &MMIO2_ARGS,
    quiesce: &[
        Write {
            window: "mmio",
            offset: (TRANSPORT & (PAGE - 1)) + MMIO_STATUS,
            bits: 32,
            value: 0,
            settled: 0xFFFF_FFFF,
            only_if: None,
        },
        Write {
            window: "mmio1",
            offset: (TRANSPORT1 & (PAGE - 1)) + MMIO_STATUS,
            bits: 32,
            value: 0,
            settled: 0xFFFF_FFFF,
            only_if: None,
        },
    ],
    dma: DMA_TWO,
    ..NETD
};

/// The roles of the probe (tests/net-probe): `c` the interface's address and
/// 300 pings of the gateway, `b` the registry of ports and the sessions, `sN`
/// N places of the table at once (the digits are N) and 50 pings, `e` the
/// rates of the loopback, `f` the full batch of a step after a hold of the
/// service, `a` every group of sockets with work at once, `w` sixteen and
/// then 128 operations told by one datagram, `i` 150 s of idle, `l` a queue of
/// 16 with blocking ACCEPT and WATCH, `r` the timers, `u` echo requests that
/// fill a frame, `k` CRASH of the service and the same as `c` through a new
/// session. The images of the measurement of the steps (`net-sockets-N`) run
/// `s` at 8, 64 and 256 places; the others at the limit of the sockets the
/// service serves (netd::places::SOCKETS_LIMIT, which a test of xtask
/// compares with the number here).
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
} else if cfg!(feature = "net-wire") {
    b"cuk"
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
const _: () = assert!(str_eq(
    super::ramfs::BUSYBOX_DIALOG_TABLE[5].program,
    "ash-launcher"
));
const _: () = assert!(str_eq(
    super::ramfs::BUSYBOX_DIALOG_TABLE[2].program,
    super::ramfs::POSIX_ABI_TABLE[1].program
));

/// The launcher of the shell with a session with the network service: the
/// shell and its commands get the same (the launcher's connections are the
/// shell's).
const NET_LAUNCHER: Record = Record {
    connects: &[
        "ramfs",
        "tty",
        "pipe",
        "clock",
        "posix",
        "entropy",
        NET_SERVICE,
    ],
    ..super::ramfs::BUSYBOX_DIALOG_TABLE[5]
};

/// The process service of the image with the network: the pool of the
/// shell's image and ten more quotas of a command. `httpd` forks a child for
/// each connection, and the eight simultaneous requests of `net-curl` make
/// eight children over the shell, the server and the launcher.
const NET_PROCESS_SERVICE: Record = Record {
    quota: super::ramfs::POSIX_ABI_TABLE[1].quota
        + super::ramfs::BUSYBOX_DIALOG_POOL
        + 10 * super::ramfs::BUSYBOX_DIALOG_QUOTA,
    ..super::ramfs::BUSYBOX_DIALOG_TABLE[2]
};

/// The image of the shell with the network service: the shell's programs
/// have a session with it (the place `Net`), and `httpd` serves from it.
pub const NET_TABLE: &[Record] = &[
    super::ramfs::BUSYBOX_DIALOG_TABLE[0],
    super::ramfs::BUSYBOX_DIALOG_TABLE[1],
    NET_PROCESS_SERVICE,
    super::ramfs::BUSYBOX_DIALOG_TABLE[3],
    super::ramfs::BUSYBOX_DIALOG_TABLE[4],
    NET_LAUNCHER,
    super::ramfs::BUSYBOX_DIALOG_TABLE[6],
    super::ramfs::BUSYBOX_DIALOG_TABLE[7],
    super::ramfs::BUSYBOX_DIALOG_TABLE[8],
    NETD,
];

/// The image of the shell with the network service on VZ (`cargo xtask net
/// --machine vz`): the console's driver in place of the PL011's, the
/// shell's table as `vz::BUSYBOX_DIALOG_TABLE` has it (the clock without a
/// PL031: the time `vz-run` writes into the image), the entropy device's
/// driver of VZ for the key of the stack, and `NETD_VZ`.
pub const NET_VZ_TABLE: &[Record] = &[
    super::vz::CONSOLE,
    super::ramfs::RAM_FIFO_CLOCKED,
    NET_PROCESS_SERVICE,
    super::ramfs::POSIX_ABI_TABLE[2],
    super::ramfs::PIPE,
    NET_LAUNCHER,
    super::ramfs::TTY,
    super::entropy::RNG_VZ,
    super::entropy::ENTROPY,
    NETD_VZ,
];

/// The image of the shell on VZ with both network devices.
pub const NET_VZ2_TABLE: &[Record] = &[
    NET_VZ_TABLE[0],
    NET_VZ_TABLE[1],
    NET_VZ_TABLE[2],
    NET_VZ_TABLE[3],
    NET_VZ_TABLE[4],
    NET_VZ_TABLE[5],
    NET_VZ_TABLE[6],
    NET_VZ_TABLE[7],
    NET_VZ_TABLE[8],
    NETD_VZ2,
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

/// The probe's image with both network devices on QEMU (role `c` and
/// `k`): the lease of each and their first interrupts are what the run of
/// xtask looks for.
pub const NET_PROBE_TWO_TABLE: &[Record] = &[
    super::ramfs::RAM_LEGACY,
    super::entropy::RNG,
    super::entropy::ENTROPY,
    NETD_TWO,
    Record {
        args: b"ck",
        ..PROBE
    },
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
