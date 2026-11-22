// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables of the package stages on QEMU's `virt` machine: the walk of
//! bus 0 (tests/pci-walk), which measures the host bridge, the disk's
//! function and its BAR before a driver relies on them, and the disk
//! service (services/virtio-blk) with its probe (tests/blk-probe), and the package service
//! (services/pkgd) with its probe (tests/store-probe).
//!
//! The disk is the Virtio PCI function at device 1 of bus 0 (xtask's
//! `qemu::store`): the page of its configuration in ECAM, BAR 4 of 16 KiB at
//! the start of the 32-bit window, which the driver measures and sets, and
//! INTA, INTID 36 by the swizzle of the tree's `interrupt-map`
//! (virtio_pci::qemu). The device masters the bus with no SMMU (spec 9): the
//! driver is trusted, and init stops the device before the DMA object of an
//! instance that ended goes, with the Virtio reset while the function
//! decodes its BAR, then the command word 0.

use super::{
    At, Binding, Budget, Confirm, Dma, GENERAL_CPUS, Gate, Kind, Record, Restart, Shares, Wait,
    Window, Write,
};
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
        at: crate::table::At::Fixed,
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
            at: crate::table::At::Fixed,
        },
        Window {
            name: "bar",
            base: qemu::DISK.bar,
            len: qemu::DISK.len,
            duplicate: false,
            at: crate::table::At::Fixed,
        },
    ],
    bindings: &[Binding {
        name: "irq",
        line: qemu::DISK_LINE,
        edge: false,
        of: None,
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
            confirm: None,
        },
        Write {
            window: "ecam",
            offset: COMMAND,
            bits: 32,
            value: 0,
            settled: 0xFFFF,
            only_if: None,
            confirm: None,
        },
    ],
    start: &[],
    release: &[],
    trusted: true,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The bytes of the store of an image with no disk: 256 MiB, the object of the memory disk.
pub const MEMORY_STORE_BYTES: u64 = 256 << 20;

/// The own arguments of the memory disk: the size of its object in bytes.
const MEMBLK_ARGS: [u8; 8] = MEMORY_STORE_BYTES.to_le_bytes();

/// The disk service over a memory object (services/mem-blk), under the name and at the level of
/// the Virtio driver, so `pkgd` finds it the same way. It needs no window, no binding and no
/// DMA. Its quota is the pages of the object and 2 048 for their list, the mappings and the
/// client's buffer. It never restarts: a new instance would show a running `pkgd` an empty
/// disk.
pub const MEMBLK: Record = Record {
    program: "mem-blk",
    quota: (MEMORY_STORE_BYTES / PAGE + 2_048) * PAGE,
    restart: Restart::Never,
    windows: &[],
    bindings: &[],
    args: &MEMBLK_ARGS,
    dma: &[],
    quiesce: &[],
    trusted: false,
    ..BLK
};

/// The PCI id of the NVMe controller of QEMU (`-device nvme`): Red Hat's vendor id and device
/// 0x0010.
pub const QEMU_NVME_ID: u32 = 0x1b36_0010;
/// The bytes of BAR 0 the NVMe service maps: the registers and the doorbells, the MSI-X table
/// and its pending bits lie in the first 16 KiB on EBS and on QEMU.
const NVME_BAR_LEN: u64 = 4 * PAGE;
/// `CC` and `CSTS` of the controller (NVM Express Base Specification, the controller
/// properties) and the bits the stop uses.
const NVME_CC: u64 = 0x14;
const NVME_CSTS: u64 = 0x1c;
/// `CC` as the library programs it (`nvme::regs::cc_enable`: enabled, 64-byte submission and
/// 16-byte completion entries) with a normal shutdown asked for (SHN = 01).
const NVME_CC_SHUTDOWN: u32 = 1 | 6 << 16 | 4 << 20 | 1 << 14;
/// `CSTS.RDY`, and `CSTS.SHST` (bits 3:2) at 10, the shutdown processing complete.
const NVME_RDY: u32 = 1;
const NVME_SHST_MASK: u32 = 0b11 << 2;
const NVME_SHST_COMPLETE: u32 = 0b10 << 2;
/// The stop of the controller, in the order of the specification: a normal shutdown (the
/// controller flushes what it holds and says so in `CSTS.SHST`), written only while the
/// controller is ready, then `CC` 0 (the controller stops its DMA, which `CSTS.RDY` 0 says).
/// When a confirmation fails, init keeps the DMA objects and marks the record broken.
static NVME_STOP: [Write; 2] = [
    Write {
        window: "bar",
        offset: NVME_CC,
        bits: 32,
        value: NVME_CC_SHUTDOWN,
        settled: 0,
        only_if: Some(Gate {
            window: "bar",
            offset: NVME_CSTS,
            bits: NVME_RDY,
        }),
        confirm: Some(Confirm {
            window: "bar",
            offset: NVME_CSTS,
            mask: NVME_SHST_MASK,
            value: NVME_SHST_COMPLETE,
        }),
    },
    Write {
        window: "bar",
        offset: NVME_CC,
        bits: 32,
        value: 0,
        settled: 0,
        only_if: None,
        confirm: Some(Confirm {
            window: "bar",
            offset: NVME_CSTS,
            mask: NVME_RDY,
            value: 0,
        }),
    },
];
/// The command word of the function goes to 0 after the stop (bus mastering and memory
/// decoding off, through the page of its configuration), also when a step of the stop did not
/// confirm.
static NVME_RELEASE: [Write; 1] = [Write {
    window: "ecam",
    offset: 4,
    bits: 32,
    value: 0,
    settled: 0xFFFF,
    only_if: None,
    confirm: None,
}];
/// The command word the start writes: memory decoding, bus mastering and INTx off (`pci::enable`),
/// before each load of the service.
const NVME_COMMAND: u32 = pci::MEMORY | pci::BUS_MASTER | pci::INTX_DISABLE;
static NVME_START: [Write; 1] = [Write {
    window: "ecam",
    offset: 4,
    bits: 32,
    value: NVME_COMMAND,
    settled: NVME_COMMAND,
    only_if: None,
    confirm: None,
}];
/// The memory of the controller: the queues, the lists of PRPs and the buffer of Identify in
/// one uncached object of 32 KiB (`nvme::MEM_BYTES`), and the four cells of 16 KiB, cached (the
/// DMA is coherent on EC2 and under QEMU). The controller addresses both as the physical
/// addresses init gives the service, `nvme` first.
const NVME_DMA: &[Dma] = &[
    Dma {
        name: "nvme",
        size: 8 * PAGE,
        uncached: true,
        duplicate: false,
    },
    Dma {
        name: "cells",
        size: 16 * PAGE,
        uncached: false,
        duplicate: false,
    },
];
/// The two MSI-X vectors of the function: 0 for the admin queue, 1 for the I/O pair. Each is an
/// event of the function's MSI device, bound with the label of its binding.
const NVME_QEMU_BINDINGS: &[Binding] = &[
    Binding::msi_of("irq0", QEMU_NVME_ID, 1, 0),
    Binding::msi_of("irq1", QEMU_NVME_ID, 1, 1),
];
const NVME_QEMU_WINDOWS: &[Window] = &[
    Window {
        name: "bar",
        base: 0,
        len: NVME_BAR_LEN,
        duplicate: false,
        at: At::Bar {
            id: QEMU_NVME_ID,
            index: 1,
            bar: 0,
        },
    },
    Window {
        name: "ecam",
        base: 0,
        len: PAGE,
        duplicate: false,
        at: At::Config {
            id: QEMU_NVME_ID,
            index: 1,
        },
    },
];
/// The budget of the request thread: 100 us of each 10 ms (1 % of CPU 0), at 32 once spent.
/// A request takes one copy of a cell (about 5 us on t4g) and a doorbell, so about 15 commands
/// fit one period, 24 MiB/s, which the store and the keys of the system never come near; the
/// polling of the queue while a command is out (500 us) is counted in it.
pub const NVME_BUDGETS: &[Budget] = &[Budget {
    name: "serve",
    cpu: 0,
    c_ns: 100_000,
    t_ns: 10 * MS,
    low: super::ramfs::SERVICE_LOW,
}];

/// The disk service over the second NVMe controller of QEMU's machine with edk2 (the data disk
/// beside the ESP's: `xtask nvme-persist`), under the name and at the level of the Virtio
/// driver, so `pkgd` finds it the same way. The function is found by its PCI id and index,
/// the walk of the platform gives its BAR as the firmware set it. The DMA of the device is
/// coherent, and init stops the controller before it lets the objects go. Beyond the
/// mappings, the client's buffer of 16 pages and the BAR's 4 need page tables.
pub const NVME_QEMU_BLK: Record = Record {
    program: "nvme-blk",
    quota: 96 * PAGE,
    windows: NVME_QEMU_WINDOWS,
    bindings: NVME_QEMU_BINDINGS,
    args: &[],
    dma: NVME_DMA,
    quiesce: &NVME_STOP,
    start: &NVME_START,
    release: &NVME_RELEASE,
    budgets: NVME_BUDGETS,
    free: super::ramfs::SERVICE_FREE,
    ..BLK
};

/// The own arguments of the data volume of QEMU's machine (`nvme-blk`, after the addresses of the DMA
/// objects): the kind 1 (the serial number of Identify Controller) and the serial of the disk
/// that `xtask nvme-persist` gives the second controller (`serial=stafeto-data`). The service serves
/// a controller with another serial number never: the ESP's is `stafeto-esp`.
const NVME_QEMU_DATA_WANT: &[u8] = b"\x01stafeto-data";

/// The data volume of QEMU's machine with edk2: the NVMe disk service under the name `datadisk`,
/// which `datafs` connects to, with the check of the volume's identity (the serial number). The record
/// is optional on this platform: a machine without the controller has no `datadisk`, and `datafs`
/// serves nothing (`not mounted`).
pub const NVME_QEMU_DATA: Record = Record {
    name: "datadisk",
    args: NVME_QEMU_DATA_WANT,
    ..NVME_QEMU_BLK
};

/// The data volume that the Virtio disk of QEMU's `virt` gives, under the name `datadisk`.
pub const BLK_DATADISK: Record = Record {
    name: "datadisk",
    ..BLK
};

/// The platform of QEMU's `virt` with `highmem-ecam=off` under edk2 (the machines of
/// `xtask efi`): the ECAM of the machine below 4 GiB, buses 0 to 15, the walk over bus 0, which
/// holds every function.
pub const QEMU_PLATFORM: crate::resolve::Platform = crate::resolve::Platform {
    ecam: pci::Ecam {
        base: qemu::ECAM,
        first_bus: 0,
        last_bus: 15,
    },
    scan_last_bus: 0,
    io_shift: 0,
    optional: &["datadisk"],
};

/// The disk service of the probe of the package service: the Virtio disk, or with the feature
/// `nvme-store` the NVMe disk (`cargo xtask nvme-persist`).
pub const PROBE_BLK: Record = if cfg!(feature = "nvme-store") {
    NVME_QEMU_BLK
} else {
    BLK
};

/// The disk service of the images with a package service: the Virtio disk, or with the feature
/// `memory-store` the memory disk (`cargo xtask pkg-probe memory`).
pub const STORE_BLK: Record = if cfg!(feature = "memory-store") {
    MEMBLK
} else {
    BLK
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
    // The shared buffer of 16 pages is its own object, mapped in both.
    quota: 64 * PAGE,
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
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The image of the disk probe: the PL011's driver, the disk service and
/// its client.
pub const BLK_PROBE_TABLE: &[Record] = &[super::normal::TABLE[0], BLK, BLK_PROBE];

/// The budgets of the data file service. `serve` is the request thread's: 100 us of each 10 ms
/// (1 % of CPU 0), at 32 once spent. A request is a copy of at most 1 KiB into a job and a reply.
/// `work` is the worker thread's, which does the jobs on the volume at 30: 3 ms of each 10 ms (30 %
/// of CPU 1), at 1 once spent, below every program of POSIX. It stands on CPU 1 because the budgets
/// of CPU 0 already take 74.5 % of the 75 % the table allows on EC2 (the admission check refuses
/// 30 % more there); the service puts the worker thread on CPU 1 when it has the budget, and a
/// machine with one CPU gets no `work` budget (init gives a budget only to an instance whose mask
/// holds its CPU), so the worker stays on the CPU of the loop with no budget. The budget does not bound the length of
/// a job: a job of seconds (a walk, an RMDIR in a large volume, a long listing) waits for the disk
/// nearly all the time, and a wait spends nothing. It bounds the share of the CPU the worker takes
/// from the programs below 30 in the spans where it computes (the checksums of littlefs over blocks
/// in its cache, the compaction of a pair of metadata blocks, a walk over blocks already read): 30 %
/// at 30, and what is left of the period only when nothing else wants the CPU.
pub const DATAFS_BUDGETS: &[Budget] = &[
    Budget {
        name: "serve",
        cpu: 0,
        c_ns: 100_000,
        t_ns: 10 * MS,
        low: super::ramfs::SERVICE_LOW,
    },
    Budget {
        name: "work",
        cpu: 1,
        c_ns: 3 * MS,
        t_ns: 10 * MS,
        low: 1,
    },
];

/// The data file service (services/datafs): the files of `/data` on the data partition of the disk
/// service. Its request thread works at 36 under a budget, above the clients of POSIX (ceiling 31) and
/// below the disk service (39) whose client its worker is, at 30. Its quota is the worker's stack, the
/// disk buffer and the pages of the volume's memory with room over. The allocator's window (one bit for
/// each block, 128 KiB for a volume of 4 GiB, 32 pages) is in the volume's memory, which is a static of
/// the program: init pays for it as a segment at the load (`quota::need_pages` counts the segments of
/// the program besides the quota), so the quota stays at 512 pages. It connects to the disk service and restarts: a new
/// instance mounts the volume again, and a client opens its files again. A service that ends twice in a
/// row with the stuck exit (6, no disk call completed for 20 s with a job waiting) is marked broken: a
/// restart would mount the same volume again and wait on it again, for ever (stafeto#443).
pub const DATAFS: Record = Record {
    name: "datafs",
    program: "datafsd",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 36,
    ceiling: 36,
    quota: 512 * PAGE,
    // The handles the service holds at most: 64 windows (one for each session, until it goes),
    // 64 copies of identity sessions (one for each bound session), 32 identity handles of SESSION
    // requests that wait for a job (`admit::WAITING_MAX`), 24 handles in the jobs in flight (a queued
    // WINDOW, an identity session or a handle for a reply: `admit::JOBS`), and about 40 of its own
    // (the channels, the notifications, the timers, the budgets, the buffer of the disk service and
    // the pages of the clock and of the generations): 224, and a limit of 256.
    handle_limit: 256,
    restart: Restart::Always,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["datadisk"],
    args: &[],
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
    budgets: DATAFS_BUDGETS,
    free: super::ramfs::SERVICE_FREE,
    broken_after: Some((6, 2)),
};

/// The data file service in the tables that have the clock service: it also connects to `clock`, whose
/// page of CLOCK_REALTIME stamps the times of files. The tables of the probes of the volume have no
/// clock service and keep `DATAFS`, whose times the service stamps from its own count. Its identity
/// questions go to the process service through the notary session init gives a service of `VOUCHERS`
/// that asks for `posix` by name (`connects` has no `posix`: a record that connects to it is a POSIX
/// process, and a notary session goes to no such record).
pub const DATAFS_CLOCKED: Record = Record {
    connects: &["datadisk", "clock"],
    ..DATAFS
};

/// The probe of the data file service (tests/data-probe): a client at 30 with a session of the
/// service by name. It starts when the service said READY, the volume mounted or not.
pub const DATA_PROBE: Record = Record {
    name: "data-probe",
    program: "data-probe",
    kind: Kind::Client,
    priority: 30,
    ceiling: 30,
    // The window of the version 4 series (32 pages) beside the probe's own.
    quota: 112 * PAGE,
    handle_limit: 32,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["datafs"],
    args: &[],
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[Wait {
        service: "datafs",
        deadline_ms: 30_000,
    }],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The image of the data probe: the PL011's driver, the disk service, the data file service and the
/// probe.
pub const DATA_PROBE_TABLE: &[Record] =
    &[super::normal::TABLE[0], BLK_DATADISK, DATAFS, DATA_PROBE];

/// The host key service (services/datakey): a client of `datafs` and of the file service that
/// puts the SSH host key of the volume into `/etc/dropbear` and says READY, and keeps a new key on
/// the volume. It is a service for init (READY and the heartbeat, one a second while it waits for
/// the key of the boot script) and ends once it has done. It follows `datafs` in the table, its first
/// request waits for the end of the start of `datafs`, the volume mounted or not, and it works at 30
/// like the other clients of the volume. Its start (the format of a blank volume may be what it waits
/// for) is watched for 30 s.
pub const DATAKEY: Record = Record {
    name: "datakey",
    program: "datakey",
    kind: Kind::Service(Watch {
        period_ns: 1000 * MS,
        deadline_ns: 30_000 * MS,
    }),
    priority: 30,
    ceiling: 30,
    quota: 128 * PAGE,
    handle_limit: 64,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["datafs", "ramfs"],
    args: &[],
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    // No wait: a request to `datafs` is answered once its start is over, the volume mounted or not,
    // and the POSIX launcher may wait for this service (a waited service has no waits of its own).
    waits: &[],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The probe of the host key service (tests/datakey-probe): the boot script of Dropbear without the
/// shell. Its session with `datakey` (the service registers once it has put the key it found into
/// the file service) holds it back until then; it keeps or makes the key in `/etc/dropbear`.
pub const DATAKEY_PROBE: Record = Record {
    name: "datakey-probe",
    program: "datakey-probe",
    kind: Kind::Client,
    priority: 29,
    ceiling: 29,
    quota: 64 * PAGE,
    handle_limit: 32,
    connects: &["ramfs", "datakey"],
    waits: &[],
    ..DATA_PROBE
};

/// The image of the host key probe on the NVMe data disk of QEMU's machine with edk2
/// (`cargo xtask nvme-persist key`): the PL011's driver, the file service, the NVMe disk service, the
/// data file service, the host key service and the probe.
pub const DATAKEY_PROBE_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    super::ramfs::RAM_LEGACY,
    NVME_QEMU_DATA,
    DATAFS,
    DATAKEY,
    DATAKEY_PROBE,
];

/// The image of the disk probe over the NVMe disk of QEMU's machine with edk2
/// (`cargo xtask nvme-persist blk-probe`): the PL011's driver, the NVMe disk service under the name
/// `blk`, which the probe connects to, and the probe.
pub const BLK_PROBE_NVME_TABLE: &[Record] = &[super::normal::TABLE[0], NVME_QEMU_BLK, BLK_PROBE];

/// The package service (pk3-design R2, R5, R15): level 32 for its main thread, below the
/// disk (39) and the file service (48) it calls and above no one it serves but the
/// processes of POSIX (ceiling 31). Its quota is the 16,384 pages of the objects of the
/// packages and 512 of its own. It never restarts: its layers stay in the file service
/// when it ends, and a new instance could not take them over (R12). It connects to the
/// disk and to the file service (the layer session by the name `ramfs/layers`, which init
/// gives a layer client); init gives it the boot image and a notary session of the
/// process service without a record of its own.
pub const PKGD: Record = Record {
    name: "pkgd",
    program: "pkgd",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 32,
    ceiling: 32,
    quota: 16_896 * PAGE,
    handle_limit: 512,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["blk", "ramfs"],
    args: &[],
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The probe of the package service (tests/store-probe): the first POSIX process, root,
/// with a session of the package service by name. It starts the program of a package
/// from the disk, so it has the quota of a child of its own.
pub const STORE_PROBE: Record = Record {
    name: "store-probe",
    program: "store-probe",
    args: b"store-probe\0",
    connects: &["ramfs", "clock", "posix", "pkgd", "entropy"],
    root: true,
    quota: super::ramfs::PROCS_QUOTA,
    ..super::ramfs::POSIX
};

/// The image of the store probe: the PL011's driver, the file service, the process, clock
/// and pipe services, the disk and package services and the probe.
pub const STORE_PROBE_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    super::ramfs::RAM_FIFO_CLOCKED,
    Record {
        quota: super::ramfs::POSIX_ABI_TABLE[1].quota + 3 * super::ramfs::PROCS_QUOTA,
        ..super::ramfs::POSIX_ABI_TABLE[1]
    },
    super::ramfs::CLOCK_RTC,
    super::ramfs::PIPE,
    PROBE_BLK,
    PKGD,
    STORE_PROBE,
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The probe of the place `Packages` (tests/pkg-slot): the first POSIX process, root, with a
/// session of the package service by name; its copy forks, spawns and execs.
pub const PKG_SLOT: Record = Record {
    name: "pkg-slot",
    program: "pkg-slot",
    args: b"pkg-slot\0",
    connects: &["ramfs", "pipe", "clock", "posix", "pkgd", "entropy"],
    quota: super::ramfs::PROCS_QUOTA,
    // The disk of the probe is empty: the service formats it before it answers, and the
    // probe starts when it said READY.
    waits: &[Wait {
        service: "pkgd",
        deadline_ms: 30_000,
    }],
    ..STORE_PROBE
};

/// The image of the probe of the place `Packages`: the store probe's services and the probe.
pub const PKG_SLOT_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    STORE_PROBE_TABLE[1],
    STORE_PROBE_TABLE[2],
    STORE_PROBE_TABLE[3],
    STORE_PROBE_TABLE[4],
    BLK,
    PKGD,
    PKG_SLOT,
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The client of the wait probe (xtask init-wait): the program of the store probe, whose
/// file `/test/mode` says `wait` (it prints the time it started and ends), waiting 3 s for
/// the package service's READY.
pub const INIT_WAIT_CLIENT: Record = Record {
    name: "init-wait",
    waits: &[Wait {
        service: "pkgd",
        deadline_ms: 3_000,
    }],
    ..STORE_PROBE
};

/// The image of the wait probe: the store probe's, the client at the end.
pub const INIT_WAIT_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    STORE_PROBE_TABLE[1],
    STORE_PROBE_TABLE[2],
    STORE_PROBE_TABLE[3],
    STORE_PROBE_TABLE[4],
    BLK,
    PKGD,
    INIT_WAIT_CLIENT,
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

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
    fn the_memory_disk_is_the_disk_service_with_no_device_and_an_object_of_256_mib() {
        assert_eq!(MEMBLK.name, "blk");
        assert_eq!(MEMBLK.program, "mem-blk");
        assert_eq!(MEMBLK.args, &(256u64 << 20).to_le_bytes());
        assert!(MEMBLK.windows.is_empty() && MEMBLK.bindings.is_empty() && MEMBLK.dma.is_empty());
        assert!(MEMBLK.quiesce.is_empty() && !MEMBLK.trusted);
        assert_eq!(MEMBLK.restart, Restart::Never);
        const { assert!(MEMBLK.quota >= MEMORY_STORE_BYTES) };
        // The level of the driver: above the package service, which calls it.
        assert_eq!((MEMBLK.priority, MEMBLK.ceiling), (39, 39));
        const { assert!(PKGD.ceiling <= MEMBLK.priority) };
        // The store probe's table with the memory disk as its `blk` is a good table.
        let table: Vec<Record> = STORE_PROBE_TABLE
            .iter()
            .map(|r| if r.name == "blk" { MEMBLK } else { *r })
            .collect();
        assert!(crate::table::check(&table).is_ok());
    }

    #[test]
    fn the_host_key_image_is_a_good_table_and_its_service_waits_for_no_one() {
        crate::table::check(DATAKEY_PROBE_TABLE).unwrap();
        // The launcher of a POSIX image may wait for it: a waited service has no waits of its own.
        assert!(DATAKEY.waits.is_empty());
        // The clients of the volume stay below the service that holds it (36).
        const { assert!(DATAKEY.ceiling < DATAFS.priority) };
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
    fn the_package_service_is_below_the_disk_above_its_clients_and_its_table_is_whole() {
        const { assert!(PKGD.priority <= BLK.priority && PKGD.ceiling <= BLK.priority) };
        assert_eq!((PKGD.priority, PKGD.ceiling), (32, 32));
        for client in STORE_PROBE_TABLE
            .iter()
            .filter(|r| r.connects.contains(&"pkgd"))
        {
            assert!(
                client.ceiling <= PKGD.priority,
                "{} is above pkgd",
                client.name
            );
        }
        assert_eq!(PKGD.quota, (16_384 + 512) * PAGE);
        assert_eq!(PKGD.restart, Restart::Never);
        assert_eq!(PKGD.connects, &["blk", "ramfs"]);
        assert!(!PKGD.is_posix() && !PKGD.trusted && PKGD.dma.is_empty());
        assert!(crate::table::check(STORE_PROBE_TABLE).is_ok());
        assert!(STORE_PROBE.is_posix() && STORE_PROBE.root);
        // The tables of the probes of the wait and of the place Packages: the store probe's
        // services, a client that waits 3 s for pkgd, a POSIX process with its session.
        assert!(crate::table::check(INIT_WAIT_TABLE).is_ok());
        assert!(crate::table::check(PKG_SLOT_TABLE).is_ok());
        assert_eq!(
            INIT_WAIT_CLIENT.waits,
            &[Wait {
                service: "pkgd",
                deadline_ms: 3_000
            }]
        );
        assert!(PKG_SLOT.is_posix() && PKG_SLOT.root && PKG_SLOT.connects.contains(&"pkgd"));
        assert_eq!(PKG_SLOT.waits.len(), 1);
    }

    #[test]
    fn init_gives_pkgd_the_layer_session_the_notary_and_the_image() {
        assert!(crate::table::LAYER_CLIENTS.contains(&"pkgd"));
        assert!(crate::table::VOUCHERS.contains(&"pkgd"));
        assert!(!crate::table::SET_ID_VOUCHERS.contains(&"pkgd"));
        assert!(crate::table::layer_grant(
            &PKGD,
            crate::table::RAM_LAYERS.as_bytes()
        ));
        assert!(!crate::table::layer_grant(
            &STORE_PROBE,
            crate::table::RAM_LAYERS.as_bytes()
        ));
        assert_eq!(crate::table::PACKAGE_SERVICE, "pkgd");
    }

    #[test]
    fn the_probe_is_no_higher_than_the_service() {
        const { assert!(BLK_PROBE.ceiling <= BLK.priority) };
        assert_eq!(BLK_PROBE.connects, &[BLK.name]);
    }

    /// QEMU's machine under edk2: the host bridge, the ESP's NVMe at 00:01.0 and the data
    /// disk's at 00:04.0, each with a 64-bit BAR of 16 KiB above 4 GiB.
    fn qemu_with_two_disks() -> pci::fake::Fake {
        let mut f = pci::fake::Fake::default();
        f.function(pci::Address::new(0, 0, 0), 0x1b36, 0x0008, 0x060000, false);
        f.function(pci::Address::new(0, 1, 0), 0x1b36, 0x0010, 0x010802, false);
        f.mem64(pci::Address::new(0, 1, 0), 0, 0x80_0000_0000, 0x4000);
        f.function(pci::Address::new(0, 4, 0), 0x1b36, 0x0010, 0x010802, false);
        f.mem64(pci::Address::new(0, 4, 0), 0, 0x80_0001_0000, 0x4000);
        f
    }

    fn resolved(table: &[Record]) -> Vec<Record> {
        let mut config = qemu_with_two_disks();
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        crate::resolve::resolve(table, &QEMU_PLATFORM, &mut config, store)
            .unwrap()
            .table
            .to_vec()
    }

    #[test]
    fn the_nvme_disk_is_the_disk_service_at_the_level_of_the_virtio_driver() {
        let r = NVME_QEMU_BLK;
        assert_eq!((r.name, r.program), ("blk", "nvme-blk"));
        assert_eq!((r.priority, r.ceiling), (39, 39));
        const { assert!(PKGD.ceiling <= NVME_QEMU_BLK.priority) };
        assert_eq!(r.restart, Restart::Always);
        assert!(r.trusted && r.connects.is_empty() && r.args.is_empty());
        // The queues' object uncached (8 pages, nvme::MEM_BYTES), the four cells cached.
        let dma: Vec<_> = r.dma.iter().map(|d| (d.name, d.size, d.uncached)).collect();
        assert_eq!(dma, [("nvme", 8 * PAGE, true), ("cells", 16 * PAGE, false)]);
        assert_eq!(r.dma[0].size, nvme::device::MEM_BYTES as u64);
        assert_eq!(r.dma[1].size, nvme::device::CELLS_BYTES as u64);
        // The window of BAR 0 holds the MSI-X table and its pending bits (offsets 0x2000 and
        // 0x3000 on EBS).
        assert_eq!(r.windows[0].len, 4 * PAGE);
        // Vector 0 for the admin queue, 1 for the pair, the second function of the id.
        assert_eq!(
            r.bindings
                .iter()
                .map(|b| (b.name, b.of))
                .collect::<Vec<_>>(),
            [
                ("irq0", Some((QEMU_NVME_ID, 1))),
                ("irq1", Some((QEMU_NVME_ID, 1)))
            ]
        );
        assert_eq!(QEMU_NVME_ID, 0x1b36_0010);
    }

    #[test]
    fn the_nvme_disk_is_stopped_by_a_shutdown_then_cc_zero_and_the_command_word_goes_to_zero() {
        let [shutdown, disable] = NVME_QEMU_BLK.quiesce else {
            panic!("two writes expected");
        };
        // The value is the library's CC with SHN = 01.
        assert_eq!(
            shutdown.value,
            nvme::regs::cc_enable() | nvme::regs::CC_SHN_NORMAL
        );
        assert_eq!((shutdown.offset, u64::from(nvme::regs::CC)), (0x14, 0x14));
        // It goes while the controller is ready, and its confirmation is SHST = 10.
        let gate = shutdown
            .only_if
            .expect("only a controller that runs is told to shut down");
        assert_eq!(
            (gate.window, gate.offset, gate.bits),
            ("bar", u64::from(nvme::regs::CSTS), nvme::regs::CSTS_RDY)
        );
        let confirm = shutdown.confirm.unwrap();
        assert_eq!(
            (confirm.offset, confirm.mask, confirm.value),
            (
                u64::from(nvme::regs::CSTS),
                nvme::regs::CSTS_SHST_MASK,
                nvme::regs::CSTS_SHST_COMPLETE << nvme::regs::CSTS_SHST_SHIFT
            )
        );
        // Then CC = 0, confirmed by RDY = 0.
        assert_eq!((disable.offset, disable.value), (0x14, 0));
        let confirm = disable.confirm.unwrap();
        assert_eq!((confirm.offset, confirm.mask, confirm.value), (0x1c, 1, 0));
        // The command word: 0 after, memory decoding and bus mastering before.
        assert_eq!(NVME_QEMU_BLK.release[0].value, 0);
        assert_eq!(NVME_QEMU_BLK.start[0].value, 0x0406);
    }

    #[test]
    fn the_nvme_record_finds_the_second_controller_its_bar_and_its_two_vectors() {
        let table: Vec<Record> = STORE_PROBE_TABLE
            .iter()
            .map(|r| if r.name == "blk" { NVME_QEMU_BLK } else { *r })
            .collect();
        let found = resolved(&table);
        let blk = found.iter().find(|r| r.name == "blk").unwrap();
        // The function at 00:04.0 (RID 0x20); the ESP's controller at 00:01.0 (RID 0x08) is index 0.
        let bar = blk.windows.iter().find(|w| w.name == "bar").unwrap();
        assert_eq!((bar.base, bar.len), (0x80_0001_0000, 4 * PAGE));
        let ecam = blk.windows.iter().find(|w| w.name == "ecam").unwrap();
        assert_eq!(ecam.base, QEMU_PLATFORM.ecam.base + (4 << 15));
        let events: Vec<_> = blk.bindings.iter().map(|b| b.event()).collect();
        assert_eq!(events, [Some((0x20, 0)), Some((0x20, 1))]);
        assert_eq!(crate::table::msi_events(blk, 0x20), 2);
        assert!(crate::table::check(&found).is_ok());
    }

    #[test]
    fn the_budgets_of_cpu_zero_with_the_nvme_service_stay_in_the_room_of_the_shell_image() {
        // The shell image's budgets on CPU 0 (the network service 60 %, the three services 8 %,
        // the console driver 1.5 %) and the NVMe service's 1 %, with the reserve of 3 % for the
        // process service and the package service: 73.5 % of the 75 % the table allows.
        let table: Vec<Record> = super::super::base::BASE_TABLE
            .iter()
            .map(|r| if r.name == "blk" { NVME_QEMU_BLK } else { *r })
            .collect();
        let on_zero: u64 = table
            .iter()
            .flat_map(|r| r.budgets.iter())
            .filter(|b| b.cpu == 0)
            .map(Budget::share_ppm)
            .sum();
        assert_eq!(NVME_BUDGETS[0].share_ppm(), 10_000);
        assert_eq!(
            on_zero + crate::table::CPU0_RESERVE_PPM,
            if super::super::ramfs::RAM_BUDGET_ON {
                735_000
            } else {
                685_000
            }
        );
        assert!(on_zero + crate::table::CPU0_RESERVE_PPM <= crate::table::BUDGET_SHARE_MAX_PPM);
        // The table passes the check (the admission of every CPU, `free` below the level).
        let found = resolved(&table);
        assert!(crate::table::check(&found).is_ok());
        let blk = found.iter().find(|r| r.name == "blk").unwrap();
        assert_eq!(blk.free, super::super::ramfs::SERVICE_FREE);
        assert!(blk.free < blk.priority && !blk.budgets.is_empty());
        // The budget has the name the service binds, and the level it works at once spent.
        assert_eq!(NVME_BUDGETS[0].name, "serve");
        assert_eq!(NVME_BUDGETS[0].low, super::super::ramfs::SERVICE_LOW);
    }

    #[test]
    fn a_table_with_the_nvme_disk_left_without_its_second_controller_is_refused() {
        let mut config = pci::fake::Fake::default();
        config.function(pci::Address::new(0, 1, 0), 0x1b36, 0x0010, 0x010802, false);
        config.mem64(pci::Address::new(0, 1, 0), 0, 0x80_0000_0000, 0x4000);
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        let table: Vec<Record> = STORE_PROBE_TABLE
            .iter()
            .map(|r| if r.name == "blk" { NVME_QEMU_BLK } else { *r })
            .collect();
        let refused = crate::resolve::resolve(&table, &QEMU_PLATFORM, &mut config, store);
        assert!(matches!(
            refused,
            Err(crate::resolve::Refusal {
                record: "blk",
                cause: crate::resolve::Cause::NoFunction { index: 1, .. },
                ..
            })
        ));
    }

    #[test]
    fn the_data_volume_is_the_optional_record_datadisk_that_datafs_connects_to() {
        assert_eq!(NVME_QEMU_DATA.name, "datadisk");
        assert_eq!(NVME_QEMU_DATA.program, "nvme-blk");
        assert_eq!(BLK_DATADISK.name, "datadisk");
        assert_eq!(DATAFS.connects, &["datadisk"]);
        // The stuck exit (services/datafs `STUCK`, 6) twice in a row marks the service broken, and
        // no other record has such a rule: a restart of the stuck volume would only repeat it.
        assert_eq!(DATAFS.broken_after, Some((6, 2)));
        for table in [
            crate::table::aws::TABLE,
            crate::table::aws::QEMU_TABLE,
            DATA_PROBE_TABLE,
        ] {
            for record in table.iter().filter(|r| r.name != "datafs") {
                assert_eq!(record.broken_after, None, "{}", record.name);
            }
        }
        // The allocator's window of 32 pages is a segment of the program, paid at load; the quota does not hold it.
        assert_eq!(DATAFS.quota, 512 * PAGE);
        assert_eq!(DATAKEY_PROBE_TABLE[2].name, "datadisk");
        assert!(DATA_PROBE_TABLE.iter().any(|r| r.name == "datadisk"));
        assert!(DATA_PROBE_TABLE.iter().all(|r| r.name != "blk"));
        assert!(QEMU_PLATFORM.optional.contains(&"datadisk"));
        // The identity wanted comes in the own arguments: the kind 1 (serial) and the value that
        // `xtask nvme-persist` gives the second controller.
        assert_eq!(NVME_QEMU_DATA.args, b"\x01stafeto-data");
        assert!(NVME_QEMU_BLK.args.is_empty());
    }

    #[test]
    fn without_a_data_controller_the_table_goes_on_with_datafs_and_no_datadisk() {
        // A machine with the ESP's controller alone: index 1 of the id is not there.
        let mut config = pci::fake::Fake::default();
        config.function(pci::Address::new(0, 0, 0), 0x1b36, 0x0008, 0x060000, false);
        config.function(pci::Address::new(0, 1, 0), 0x1b36, 0x0010, 0x010802, false);
        config.mem64(pci::Address::new(0, 1, 0), 0, 0x80_0000_0000, 0x4000);
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        let found =
            crate::resolve::resolve(DATAKEY_PROBE_TABLE, &QEMU_PLATFORM, &mut config, store)
                .unwrap();
        assert_eq!(found.skipped[0].unwrap().record, "datadisk");
        assert!(found.table.iter().all(|r| r.name != "datadisk"));
        let datafs = found.table.iter().find(|r| r.name == "datafs").unwrap();
        assert!(datafs.connects.is_empty());
        assert!(crate::table::check(found.table).is_ok());
    }

    #[test]
    fn with_the_data_controller_the_table_keeps_datadisk() {
        let found = resolved(DATAKEY_PROBE_TABLE);
        let datadisk = found.iter().find(|r| r.name == "datadisk").unwrap();
        assert_eq!(datadisk.windows.len(), 2);
        let datafs = found.iter().find(|r| r.name == "datafs").unwrap();
        assert_eq!(datafs.connects, &["datadisk"]);
        assert!(crate::table::check(&found).is_ok());
    }
}
