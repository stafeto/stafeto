// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! RAM file service and its guest probe in a dedicated boot image.

use super::{Kind, Record, Restart};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;

pub const TABLE: &[Record] = &[
    Record {
        name: "ramfs",
        program: "ramfs",
        kind: Kind::Service(Watch {
            period_ns: 250 * MS,
            deadline_ns: 1000 * MS,
        }),
        priority: 40,
        ceiling: 40,
        quota: 32 * PAGE,
        handle_limit: 32,
        restart: Restart::Always,
        console: true,
        log: false,
        trace: false,
        windows: &[],
        bindings: &[],
        connects: &[],
        args: &[],
        dma: &[],
        quiesce: &[],
        trusted: false,
        root: false,
        on_demand: false,
    },
    Record {
        name: "ramfs-probe",
        program: "ramfs-probe",
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
        connects: &["ramfs"],
        args: &[],
        dma: &[],
        quiesce: &[],
        trusted: false,
        root: false,
        on_demand: false,
    },
];

/// A POSIX process: main at the probe's level, the ceiling one above it,
/// where the holders of the locks of `posix-abi` (buckets, heap, files,
/// threads, actions) run, so an application thread at main's level never
/// delays them. BusyBox shares the record and its ceiling.
const POSIX: Record = Record {
    ceiling: TABLE[1].priority + 1,
    ..TABLE[1]
};

/// BusyBox, or a probe in its place, with the RAM files and the process
/// and clock services a program on relibc starts with.
pub const BUSYBOX_TABLE: &[Record] = &[
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "busybox-probe",
        program: "busybox-probe",
        connects: &["ramfs", "clock", "posix"],
        quota: 512 * PAGE,
        // The first POSIX process: root, so ash prompts with `#`.
        root: true,
        ..POSIX
    },
];

/// BUSYBOX_TABLE with the console's driver, which the program reads.
pub const BUSYBOX_DIALOG_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        connects: &["ramfs", "uart", "clock", "posix"],
        ..BUSYBOX_TABLE[3]
    },
];

/// The probes of console input and interruption (posix-threads with
/// cancel-input, posix-shared): the console's driver, the RAM files, the
/// process and clock services, and the probe under the name
/// `posix-probe`.
pub const POSIX_DIALOG_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "posix-probe",
        program: "posix-probe",
        connects: &["ramfs", "uart", "clock", "posix"],
        quota: 512 * PAGE,
        ..POSIX
    },
];

pub const POSIX_ABI_TABLE: &[Record] = &[
    TABLE[0],
    Record {
        name: "posix",
        program: "posix-process-service",
        // Its own, and the eight objects of the pages of its records
        // (32 pages each); what its POSIX records take init adds.
        quota: 640 * PAGE,
        // A process handle for each of its 256 records.
        handle_limit: 1024,
        restart: Restart::Never,
        ..TABLE[0]
    },
    Record {
        name: "clock",
        program: "posix-clock-service",
        quota: 64 * PAGE,
        restart: Restart::Never,
        ..TABLE[0]
    },
    Record {
        name: "clock-peer",
        program: "posix-clock-peer",
        quota: 64 * PAGE,
        connects: &["clock", "posix"],
        restart: Restart::Never,
        ..TABLE[0]
    },
    Record {
        name: "posix-abi-probe",
        program: "posix-abi-probe",
        args: b"posix-abi-probe\0argument\0",
        connects: &["ramfs", "clock", "clock-peer", "posix", "long"],
        quota: 2048 * PAGE,
        // Each pthread holds five handles: its thread, its own copy with
        // MANAGE, its channel, its timer (posix-sync) and its exit channel;
        // two more while set_level makes the new channel and timer. 63
        // pthreads take 315 besides main's and the layer's.
        handle_limit: 512,
        root: true,
        ..POSIX
    },
    // The service of long operations in two steps (tests/svc, role `l`)
    // for the probe of reads in two steps; at 50, above the clock service,
    // so that what the clock tells it (STORM) runs it before the clock's
    // reply.
    Record {
        name: "long",
        priority: 50,
        ceiling: 50,
        ..LONG
    },
    // A POSIX process that gives the clock peer its session with the
    // process service and ends (tests/svc, role `t`): the probe of the
    // credentials sees its record go with it.
    Record {
        name: "posix-sender",
        program: "svc",
        args: b"t",
        connects: &["clock-peer", "clock", "posix"],
        quota: 16 * PAGE,
        handle_limit: 16,
        ..POSIX
    },
];

/// The first C program on relibc (5a′): the RAM files, the process and
/// clock services, and the program.
pub const RELIBC_TABLE: &[Record] = &[
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "relibc-hello",
        program: "relibc-hello",
        args: b"relibc-hello\0",
        connects: &["ramfs", "clock", "posix"],
        quota: 512 * PAGE,
        ..POSIX
    },
    // The same program ending by abort, a failed assert and a panic of
    // relibc: each ends with status 134.
    Record {
        name: "relibc-abort",
        args: b"relibc-hello\0abort\0",
        ..RELIBC_HELLO
    },
    Record {
        name: "relibc-assert",
        args: b"relibc-hello\0assert\0",
        ..RELIBC_HELLO
    },
    Record {
        name: "relibc-panic",
        args: b"relibc-hello\0panic\0",
        ..RELIBC_HELLO
    },
];

/// The probe of POSIX processes (tests/posix-procs, 5b): the RAM files,
/// the process and clock services, the probe, and the records it spawns,
/// which start on demand: a child that says its parent, one that sleeps,
/// one whose 32 MiB stack its 15 pages of quota cannot map, so that its
/// load fails (the image gives `posix-procs-big` that stack), one that
/// ends 300 ms after its start, one that exits with 7, one that faults,
/// one that spawns the next, which waits to be an orphan, one that blocks
/// every signal and spins, one that exits with 42 from its handler of
/// SIGUSR1, a second sleeper, and one that calls setsid and setpgid.
pub const POSIX_PROCS_TABLE: &[Record] = &[
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "posix-procs",
        program: "posix-procs",
        args: b"posix-procs\0",
        root: true,
        ..PROCS_CHILD
    },
    Record {
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-sleeper",
        args: b"posix-procs\0sleep\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-big",
        program: "posix-procs-big",
        quota: super::MIN_QUOTA,
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-nap",
        args: b"posix-procs\0nap\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-exit7",
        args: b"posix-procs\0exit7\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-segv",
        args: b"posix-procs\0segv\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-middle",
        args: b"posix-procs\0middle\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-orphan",
        args: b"posix-procs\0orphan\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    // It spins: below the probe, which runs FIFO at its own level.
    Record {
        name: "procs-block",
        args: b"posix-procs\0block\0",
        priority: 20,
        ceiling: 21,
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-catch",
        args: b"posix-procs\0catch\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-sleep2",
        args: b"posix-procs\0sleep2\0",
        on_demand: true,
        ..PROCS_CHILD
    },
    Record {
        name: "procs-ids",
        args: b"posix-procs\0ids\0",
        on_demand: true,
        ..PROCS_CHILD
    },
];

/// The child of the probe of POSIX processes.
const PROCS_CHILD: Record = Record {
    name: "procs-child",
    program: "posix-procs",
    args: b"posix-procs\0child\0",
    connects: &["ramfs", "clock", "posix"],
    quota: 512 * PAGE,
    ..POSIX
};

/// One test of os-test a boot (cargo xtask os-test): the RAM files, the
/// process and clock services, and the test, under the name `os-test`.
pub const OS_TEST_TABLE: &[Record] = &[
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "os-test",
        program: "os-test",
        args: b"os-test\0",
        ..RELIBC_HELLO
    },
];

/// relibc-hello's record, for the records of its other runs.
const RELIBC_HELLO: Record = Record {
    name: "relibc-hello",
    program: "relibc-hello",
    args: b"relibc-hello\0",
    connects: &["ramfs", "clock", "posix"],
    quota: 512 * PAGE,
    ..POSIX
};

/// The threads of relibc (5a′): as RELIBC_TABLE, with room for 64
/// threads (four handles each, their stacks and TCBs).
pub const RELIBC_THREADS_TABLE: &[Record] = &[
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "relibc-threads",
        program: "relibc-threads",
        args: b"relibc-threads\0",
        quota: 4096 * PAGE,
        handle_limit: 512,
        // It sets the clock, which only an effective UID of 0 may.
        root: true,
        ..RELIBC_TABLE[3]
    },
];

/// The service of long operations of rtbench 2 (tests/svc, role `l`)
/// under the name of the console's driver: standard input of the
/// benchmark reads from it. Above the benchmark's ceiling, as a service.
pub const LONG: Record = Record {
    name: "uart",
    program: "svc",
    quota: 16 * PAGE,
    handle_limit: 16,
    restart: Restart::Never,
    args: b"l",
    ..TABLE[0]
};

/// The hostile load of rtbench 2 (tests/rtbench-load): a service whose
/// worker at level 5 makes and kills processes of 128 threads and large
/// memory objects; the benchmark asks it for its rounds at its end.
pub const LOAD: Record = Record {
    name: "rtbench-load",
    program: "rtbench-load",
    quota: 2048 * PAGE,
    handle_limit: 32,
    restart: Restart::Never,
    connects: &[],
    ..TABLE[0]
};

/// rtbench 2 (tests/rtbench-posix): a POSIX process with main at 30, its
/// threads from 10 to 30 under the ceiling 31 of the layer's helpers.
pub const RTBENCH: Record = Record {
    name: "rtbench-posix",
    program: "rtbench-posix",
    args: b"rtbench-posix\0",
    connects: &["ramfs", "clock", "posix", "uart", "rtbench-load"],
    quota: 2048 * PAGE,
    handle_limit: 512,
    root: true,
    ..POSIX
};

/// The image of rtbench 2 on QEMU: the PL011's driver under another name,
/// for the console alone, the RAM files, the process and clock services,
/// the service of long operations, the load and the benchmark.
pub const RTBENCH_POSIX_TABLE: &[Record] = &[
    Record {
        name: "console",
        ..super::normal::TABLE[0]
    },
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    LONG,
    LOAD,
    RTBENCH,
    RTBENCH_CHILDREN[0],
    RTBENCH_CHILDREN[1],
    RTBENCH_CHILDREN[2],
    RTBENCH_CHILDREN[3],
    RTBENCH_CHILDREN[4],
    RTBENCH_CHILDREN[5],
    RTBENCH_CHILDREN[6],
    RTBENCH_CHILDREN[7],
    RTBENCH_CHILDREN[8],
];

/// The children of rtbench 2 (S10 to S13), which start on demand.
pub const RTBENCH_CHILDREN: [Record; 9] = [
    Record {
        name: "rtbench-target",
        args: b"rtbench-posix\0target\0",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-quick",
        args: b"rtbench-posix\0quick\0",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-exiter",
        args: b"rtbench-posix\0exiter\0",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-wait1",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-wait2",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-wait3",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-wait4",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-wait5",
        ..RTBENCH_CHILD
    },
    Record {
        name: "rtbench-wait6",
        ..RTBENCH_CHILD
    },
];

/// A child of rtbench 2 (S10 to S13), which starts on demand: the
/// benchmark under a role named by its first argument. The table holds
/// 16 records, so a group of seven (`target` and the six `wait`) is the
/// largest one the benchmark can start.
pub const RTBENCH_CHILD: Record = Record {
    name: "rtbench-wait1",
    program: "rtbench-posix",
    args: b"rtbench-posix\0wait\0",
    connects: &["ramfs", "clock", "posix", "uart"],
    quota: 512 * PAGE,
    on_demand: true,
    ..POSIX
};
