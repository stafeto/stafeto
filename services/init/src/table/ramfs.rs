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
        // 4096 data pages + 650 metadata/PT_LOAD data pages + 27 code/rodata
        // pages (26 ordinary, 27 instrumented) + 12 stack + 128 reserve,
        // measured from RAM ELF segments and the printed table byte count.
        quota: (4096 + 650 + 27 + 12 + 128) * PAGE,
        handle_limit: 512,
        restart: Restart::Never,
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
    },
];

/// A POSIX process: main at the probe's level, the ceiling one above it,
/// where the holders of the locks of `posix-abi` (buckets, heap, files,
/// threads, actions) run, so an application thread at main's level never
/// delays them. BusyBox shares the record and its ceiling. The room for
/// handles holds the layer's memory map, one handle for each object of the
/// process's memory (at most 128), beside those of its threads and files; a
/// table grows by chunks only as far as the process uses it.
const POSIX: Record = Record {
    ceiling: TABLE[1].priority + 1,
    handle_limit: 512,
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

/// The dialog: the console's driver, the RAM files, the process and clock
/// services and the launcher (the program of `busybox-probe`, whose
/// argument `ash-launch` makes it start `/bin/ash` from its file, 5d). The
/// shell is a child, and so is each command it forks: the pool of the
/// process service holds the quota of five more processes of the
/// launcher's size (the shell, the three of a pipeline of three, and a
/// nested shell's command), and the reserve of its loaders. The pipe service (5e)
/// serves the shell's pipelines, the terminal service (5f) its console.
pub const BUSYBOX_DIALOG_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TABLE[0],
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 5 * DIALOG_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        args: b"ash-launch\0",
        connects: &["ramfs", "tty", "pipe", "clock", "posix", "entropy"],
        quota: DIALOG_QUOTA,
        ..BUSYBOX_TABLE[3]
    },
    TTY,
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The quota of the launcher, which the shell and its children get too.
const DIALOG_QUOTA: u64 = 512 * PAGE;

/// The probe of the terminal in C (tests/posix-tty, xtask posix-tty): the
/// console's driver, the terminal service, the RAM files, the process,
/// clock and pipe services, and the probe, which forks a child of its own
/// size. Eighteen child quotas hold run, the session leader and sixteen
/// live members for the terminal-signal walk. Spawn and exec run separately.
pub const POSIX_TTY_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TABLE[0],
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 18 * DIALOG_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        name: "posix-tty",
        program: "posix-tty",
        args: b"posix-tty\0",
        connects: &["ramfs", "tty", "pipe", "clock", "posix"],
        quota: DIALOG_QUOTA,
        root: true,
        ..POSIX
    },
    TTY,
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
        // Diagnostic writers exercise the fixed root-owned /tmp/probe node.
        root: true,
        ..POSIX
    },
];

/// The authentic identity and bounded file proof fixture, before public mutation APIs.
pub const POSIX_FILES_TABLE: &[Record] = &[
    TABLE[0],
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "posix-files",
        program: "posix-files",
        args: b"posix-files\0",
        connects: &["ramfs", "clock", "posix"],
        quota: 2048 * PAGE,
        root: true,
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
        // Loader roots, obtained at startup and narrowed for each loader.
        connects: &["ramfs", "clock"],
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
        root: true,
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

/// The pipe service (5e), beside the RAM file service at its level: its
/// segments, a stack of 32 KiB, the 64 rings of 4 KiB and the tables of
/// its 320 sessions, 256 births and 128 long operations in `.bss`; a
/// handle for each long operation that waits.
pub const PIPE: Record = Record {
    name: "pipe",
    program: "pipe",
    quota: 160 * PAGE,
    handle_limit: 192,
    restart: Restart::Never,
    ..TABLE[0]
};

/// The probe of POSIX processes (tests/posix-procs): the RAM files, the
/// pipes, the process and clock services and the probe, whose children
/// start from files (5c): the table has the pool for 33 of them and holds
/// no record of theirs.
pub const POSIX_PROCS_TABLE: &[Record] = &[
    TABLE[0],
    Record {
        // The pool of the children from files (5c): 32 of the probe's
        // quota at once and one that fails its load, with the service's
        // reserve (posix_process_service::loaders::RESERVE).
        quota: POSIX_ABI_TABLE[1].quota + 33 * PROCS_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        name: "posix-procs",
        program: "posix-procs",
        args: b"posix-procs\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy"],
        root: true,
        // A child from a file gets its parent's quota: room for BusyBox.
        quota: PROCS_QUOTA,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The probe of the longest step of the process service (tests/posix-procs
/// in the steps mode, xtask process-steps), with the entropy device's
/// driver and the entropy service at their levels 37 and 36, below the
/// services at 40 it measures. The pool for the crowd of
/// children it starts from files, each with the probe's quota, and one
/// more for the child that execs among them.
pub const POSIX_STEPS_TABLE: &[Record] = &[
    // Room for the crowd's descriptions in the RAM file service.
    Record {
        quota: TABLE[0].quota,
        ..TABLE[0]
    },
    Record {
        quota: POSIX_ABI_TABLE[1].quota + (STEPS_CHILDREN + 2) * STEPS_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    Record {
        quota: 192 * PAGE,
        ..POSIX_ABI_TABLE[2]
    },
    PIPE,
    Record {
        name: "posix-procs",
        program: "posix-procs",
        args: b"posix-procs\0steps\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy"],
        root: true,
        quota: STEPS_QUOTA,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The children of the steps probe: its 7 branches with their leaves, 32
/// each, and 24 of its own (tests/posix-procs STEPS_BRANCHES).
const STEPS_CHILDREN: u64 = 7 * 32 + 24;

/// The steps probe and each spawned child: the enlarged image plus its
/// checked 64 KiB malloc, including the allocator mapping and alignment.
const STEPS_QUOTA: u64 = (256 + 16) * PAGE;

/// The quota of the probe of POSIX processes, which each child it spawns
/// from a file gets too (5c), with 16 pages for the enlarged signal layer
/// while the fork probe still allocates its additional 1 MiB.
const PROCS_QUOTA: u64 = (512 + 16) * PAGE;

/// The runner of os-test (cargo xtask os-test, tests/os-test-run): the RAM
/// files with the tests of the image, the terminal, process and clock services, and
/// the runner, whose children are the tests, started from their files
/// (5c), one at a time, with room for one more for the exec of a test
/// that execs, for the processes of a test of groups (a test, its unreaped
/// child, a grandchild and another child) and for the three that the tests
/// of an emptied group leave alive for good: their child holds both ends of
/// its pipe and reads one (5e).
pub const OS_TEST_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TTY,
    TABLE[0],
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 10 * OS_TEST_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        name: "os-test-run",
        program: "os-test-run",
        args: b"os-test-run\0",
        connects: &["ramfs", "tty", "pipe", "clock", "posix", "entropy"],
        root: true,
        quota: OS_TEST_QUOTA,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The quota of the runner of os-test, which each test it starts gets too.
const OS_TEST_QUOTA: u64 = 512 * PAGE;

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
    connects: &[
        "ramfs",
        "clock",
        "posix",
        "pipe",
        "bench-uart",
        "tty",
        "rtbench-load",
        "entropy",
    ],
    // Room for a heap of 8 MiB, which a child of fork copies (S15).
    quota: 3072 * PAGE,
    handle_limit: 512,
    root: true,
    ..POSIX
};

/// The image of rtbench 2 on QEMU: the PL011's driver under another name,
/// for the console alone, the RAM files, the process and clock services,
/// the service of long operations, the load and the benchmark, whose
/// children (S10 to S13) are files of the image started from the loader.
pub const RTBENCH_POSIX_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TABLE[0],
    RTBENCH_POOL,
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        name: "bench-uart",
        ..LONG
    },
    TTY,
    LOAD,
    RTBENCH,
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The process service of rtbench 2: the pool for the children the
/// benchmark starts from files (5c), which get the benchmark's quota: 32
/// at once (S12, a group of 32) and one that fails its load, with the
/// service's reserve (posix_process_service::loaders::RESERVE).
pub const RTBENCH_POOL: Record = Record {
    quota: POSIX_ABI_TABLE[1].quota + 33 * RTBENCH.quota + 384 * PAGE,
    ..POSIX_ABI_TABLE[1]
};

/// The terminal service (5f): the console as a terminal over the
/// console's driver, at 50, below the driver and above the POSIX
/// processes; its segments, a stack of 32 KiB, its 320 sessions, 128 long
/// operations and the console's discipline in `.bss`; a handle for each
/// long operation that waits.
pub const TTY: Record = Record {
    name: "tty",
    program: "tty",
    priority: 50,
    ceiling: 50,
    // PT_LOAD 84 pages + stack 8 + generations 1; reserve 35 pages.
    quota: 128 * PAGE,
    handle_limit: 192,
    restart: Restart::Never,
    connects: &["uart"],
    ..TABLE[0]
};

/// The probe of the terminal service (tests/tty, xtask tty): the console's
/// driver, the service and the probe, a client of it.
pub const TTY_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TTY,
    Record {
        name: "tty-probe",
        program: "tty-probe",
        connects: &["tty"],
        ..TABLE[1]
    },
];

/// The measure of the terminal service's steps (xtask tty, under
/// -icount): the probe's program as a quiet driver under the driver's
/// name (its role `S`, no device, no interrupt), the service, and the
/// probe in its role `s`, which feeds the driver its input.
pub const TTY_STEPS_TABLE: &[Record] = &[
    Record {
        program: "tty-probe",
        windows: &[],
        bindings: &[],
        log: false,
        args: b"S",
        restart: Restart::Never,
        ..super::normal::TABLE[0]
    },
    TTY,
    Record {
        args: b"s",
        connects: &["tty", "uart"],
        // A handle for each clone of its chain (tests/tty steps.rs).
        handle_limit: 320,
        quota: 64 * PAGE,
        ..TTY_TABLE[2]
    },
];

/// The probe of getentropy and getrandom (tests/posix-random, step 5e'):
/// the RAM files, the process and clock services, the pipe service, the
/// entropy device's driver and the entropy service; the probe starts its
/// own file once, whose copy forks.
pub const POSIX_RANDOM_TABLE: &[Record] = &[
    TABLE[0],
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 3 * PROCS_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    super::entropy::RNG,
    super::entropy::ENTROPY,
    Record {
        name: "posix-random",
        program: "posix-random",
        args: b"posix-random\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy"],
        root: true,
        quota: PROCS_QUOTA,
        ..POSIX
    },
];

/// Functional loader channel probe with the process probe's ordinary image.
pub const LOADER_CHANNELS_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TTY,
    POSIX_PROCS_TABLE[0],
    POSIX_PROCS_TABLE[1],
    POSIX_PROCS_TABLE[2],
    POSIX_PROCS_TABLE[3],
    Record {
        args: b"posix-procs\0loaderchannels\0",
        connects: &["ramfs", "tty", "pipe", "clock", "posix", "entropy"],
        ..POSIX_PROCS_TABLE[4]
    },
    POSIX_PROCS_TABLE[5],
    POSIX_PROCS_TABLE[6],
];

/// The readiness probe uses the loader probe's ordinary services and pool.
pub const POSIX_POLL_TABLE: &[Record] = &[
    LOADER_CHANNELS_TABLE[0],
    LOADER_CHANNELS_TABLE[1],
    LOADER_CHANNELS_TABLE[2],
    LOADER_CHANNELS_TABLE[3],
    LOADER_CHANNELS_TABLE[4],
    LOADER_CHANNELS_TABLE[5],
    Record {
        name: "posix-poll",
        program: "posix-poll",
        args: b"posix-poll\0",
        ..LOADER_CHANNELS_TABLE[6]
    },
    LOADER_CHANNELS_TABLE[7],
    LOADER_CHANNELS_TABLE[8],
];

/// Functional PTY probe with the process probe's ordinary services.
pub const POSIX_PTY_TABLE: &[Record] = &[
    LOADER_CHANNELS_TABLE[0],
    LOADER_CHANNELS_TABLE[1],
    LOADER_CHANNELS_TABLE[2],
    LOADER_CHANNELS_TABLE[3],
    LOADER_CHANNELS_TABLE[4],
    LOADER_CHANNELS_TABLE[5],
    Record {
        name: "posix-pty",
        program: "posix-pty",
        args: b"posix-pty\0",
        ..LOADER_CHANNELS_TABLE[6]
    },
    LOADER_CHANNELS_TABLE[7],
    LOADER_CHANNELS_TABLE[8],
];
