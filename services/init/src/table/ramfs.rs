// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! RAM file service and its guest probe in a dedicated boot image.

use super::{ALL_CPUS, GENERAL_CPUS, Kind, POSIX_SHARES, Record, Restart, Shares, Window};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;

/// The pages of the service's tables and of its writable data. The layers (pk1-design R2) add
/// 336 pages to the tables (the `tables=` figure of the release build went from 7 688 784 to
/// 9 061 368 bytes, 335.1 pages: `State` holds 6 400 places of the image with their names and
/// the tables of 64 layers), 160 to the page tables of the mappings of layers (a layer of
/// 28.8 MB is 7 040 pages) and 5 to the thread that maps (stack and message buffer).
const TABLES: u64 = 915 + 392 + 336 + 160 + 5;

/// The level of the file, pipe and clock services.
pub const SERVICE_LEVEL: u8 = 48;
/// The level of the process service, the highest of the POSIX services.
pub const PROCESS_LEVEL: u8 = 52;

const RAM_BASE: Record = Record {
    name: "ramfs",
    program: "ramfs",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    // Spec 2, 2: the levels of the services, above every POSIX process
    // (ceilings up to 39): the process service 52, the terminal 50, the
    // files and the pipes 48, the clock 48 (the file service is its
    // client, so rule 6.6 puts the clock no lower than the files).
    priority: SERVICE_LEVEL,
    ceiling: SERVICE_LEVEL,
    // Checked standalone RAM adds measured readonly and code pages.
    // Backing, stack and runtime allowance retain their existing sizes.
    // The tables: 915 pages, and 392 for the sessions of 1 072 places, the table of 8 192
    // descriptions and the pool of 320 tables of numbers (stafeto-design#578). The `tables=`
    // figure of the line `ramfs: storage pages=4096 tables=...` went from 6 083 504 to
    // 7 688 784 bytes in the release build (+1 605 280, 392 pages) and from 6 381 488 to
    // 7 734 864 in the build with checks (+1 353 376, 331 pages). The quota takes the
    // larger of the two.
    quota: if cfg!(all(debug_assertions, feature = "table-ramfs")) {
        (4096 + TABLES + 11 + 34 + 12 + 128) * PAGE
    } else {
        (4096 + TABLES + 9 + 33 + 12 + 128) * PAGE
    },
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
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
};

/// Standalone RAM probes use an explicit deterministic source.
pub const RAM_LEGACY: Record = Record {
    args: proto_fs::RAM_TIME_LEGACY,
    ..RAM_BASE
};

/// POSIX RAM starts after Clock and requires its realtime page.
pub const RAM_CLOCKED: Record = Record {
    args: proto_fs::RAM_TIME_CLOCKED,
    connects: &["clock"],
    ..RAM_BASE
};

/// RAM connects to the named-pipe broker before it starts serving.
pub const RAM_FIFO_CLOCKED: Record = Record {
    connects: &["clock", "pipe"],
    ..RAM_CLOCKED
};

pub const TABLE: &[Record] = &[
    RAM_LEGACY,
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
        start: &[],
        release: &[],
        trusted: false,
        root: false,
        shares: Shares::CREATOR,
        cpus: GENERAL_CPUS,
        waits: &[],
    },
];

/// The layer probe (tests/layer-probe, xtask layer-probe): the RAM files with the clock, the
/// process service, the POSIX program that reads a layer (`layer-user`) and the native
/// leader that attaches and detaches layers through its layer session and the boot profile.
/// The leader reads the package files of its tests from the files of the image; its level is
/// the level the mapping thread of the RAM service works at.
pub const LAYER_PROBE_TABLE: &[Record] = &[
    RAM_CLOCKED,
    // The program of a layer runs as a child of `layer-user` with its quota: a pool for the
    // few at once (a reader that starts one for each pass over a file, and one that waits).
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 6 * 1024 * PAGE + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    Record {
        name: "layer-probe",
        program: "layer-probe",
        connects: &["ramfs"],
        // The big layer of 32 MiB and the layer being read.
        quota: 12288 * PAGE,
        ..TABLE[1]
    },
    Record {
        name: "layer-user",
        program: "layer-user",
        args: b"layer-user\0",
        connects: &["ramfs", "clock", "posix", "entropy"],
        quota: 1024 * PAGE,
        root: true,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// A POSIX process: main at the probe's level, the ceiling one above it,
/// where the holders of the locks of `posix-abi` (buckets, heap, files,
/// threads, actions) run, so an application thread at main's level never
/// delays them. BusyBox shares the record and its ceiling. The room for
/// handles holds the layer's memory map, one handle for each object of the
/// process's memory (at most 128), beside those of its threads and files; a
/// table grows by chunks only as far as the process uses it.
pub(super) const POSIX: Record = Record {
    ceiling: TABLE[1].priority + 1,
    handle_limit: 512,
    // The images of these tables have no tasks of realtime: the four CPUs
    // are the load of the tests, which would lose CPUs 2 and 3 with the
    // CPUs of the services. The images of the shell keep GENERAL_CPUS
    // (BUSYBOX_DIALOG_TABLE).
    cpus: ALL_CPUS,
    ..TABLE[1]
};

/// BusyBox, or a probe in its place, with the RAM files and the process
/// and clock services a program on relibc starts with.
pub const BUSYBOX_TABLE: &[Record] = &[
    RAM_CLOCKED,
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "busybox-probe",
        program: "busybox-probe",
        connects: &["ramfs", "clock", "posix", "entropy"],
        quota: 512 * PAGE,
        // The first POSIX process: root, so ash prompts with `#`.
        root: true,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The dialog: the console's driver, the RAM files, the process and clock
/// services and the launcher (the program `ash-launcher`, which starts
/// `/bin/busybox` as the getty of `/bin/ash` from its file, 5d). The
/// shell is a child, and so is each command it forks: the pool of the
/// process service holds the processes of the shell, of a pipeline of
/// three, of a nested shell's command and of the failed attempts of a
/// search through PATH, which wait to be reclaimed, and the reserve of
/// its loaders (BUSYBOX_DIALOG_POOL). The pipe service (5e)
/// serves the shell's pipelines, the terminal service (5f) its console.
pub const BUSYBOX_DIALOG_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + BUSYBOX_DIALOG_POOL,
        ..POSIX_ABI_TABLE[1]
    },
    CLOCK_RTC,
    PIPE,
    Record {
        program: "ash-launcher",
        args: b"ash-launch\0",
        connects: &["ramfs", "tty", "pipe", "clock", "posix", "entropy"],
        quota: BUSYBOX_DIALOG_QUOTA,
        // The shell and its commands run on the CPUs of the services.
        cpus: GENERAL_CPUS,
        ..BUSYBOX_TABLE[3]
    },
    TTY,
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The page of the PL031 of QEMU `virt` (rtc::PL031_BASE): the clock
/// service reads the time of the host there when it starts.
const RTC: Window = Window {
    name: "rtc",
    base: 0x0901_0000,
    len: PAGE,
    duplicate: false,
    at: crate::table::At::Fixed,
};

/// The clock service with the window over the PL031, for the machines that
/// have one (QEMU `virt`, HVF).
pub const CLOCK_RTC: Record = Record {
    windows: &[RTC],
    ..POSIX_ABI_TABLE[2]
};

/// The quota of the launcher, which the shell and its children get too.
const DIALOG_QUOTA: u64 = 512 * PAGE;

/// The quota of the launcher of the dialog with the big BusyBox, which the
/// shell and its children get too. The image of the utilities feature is
/// 3.2 MB, with the ready-made utilities (tools/build-ready-utils.py) in it;
/// the dialog needs 803 pages of it at most (803 passes, 800 does not,
/// bisected on ash-dialog). GNU bash (tools/build-bash.py) is a program of
/// 2.98 MB whose heap grows by doubling chunks up to 512 KiB, and a child of
/// the shell gets the shell's quota: bash-dialog passes with 1 050 pages and
/// fails with 1 000 (bisected), and 1 160 pages leave 10.5%.
pub(super) const BUSYBOX_DIALOG_QUOTA: u64 = 1160 * PAGE;

/// What the process service adds to its own quota for the dialog: the
/// children of the shell, the failed attempts of a search through PATH
/// (forty searches with three misses each run in the dialog) and the reserve
/// of the loaders. The bash dialog holds a shell, its pipelines of three
/// stages (each stage a copy of bash until it execs) and a command
/// substitution, each with the quota above, less the pages of bash's code
/// and read-only data for a copy of the shell (a child of fork shares them
/// with its parent and does not pay for them, spec 2, 3.12.2): with 1 160
/// pages of quota it passes with 9 560 pages and fails with 9 500 (bisected
/// on bash-dialog with BusyBox, bash, nano, htop and ncdu linked against
/// libc.so: every process pays for its own data of libc.so; with the
/// programs static it passed with 8 750 pages and failed with 8 625, and
/// before the table of images 9 375 passed and 9 250 did not); 10 520 pages
/// leave 10.0%.
pub(super) const BUSYBOX_DIALOG_POOL: u64 = 10520 * PAGE;

/// The probe of the terminal in C (tests/posix-tty, xtask posix-tty): the
/// console's driver, the terminal service, the RAM files, the process,
/// clock and pipe services, and the probe, which forks a child of its own
/// size. Seventy-two child quotas hold run, the session leader and the
/// sixty-four live members of the largest crowd for the terminal-signal walk.
/// Spawn and exec run separately.
pub const POSIX_TTY_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 72 * DIALOG_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        name: "posix-tty",
        program: "posix-tty",
        args: b"posix-tty\0",
        connects: &["ramfs", "tty", "pipe", "clock", "posix", "entropy"],
        quota: DIALOG_QUOTA,
        root: true,
        ..POSIX
    },
    TTY,
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The probes of console input and interruption (posix-threads with
/// cancel-input, posix-shared): the console's driver, the RAM files, the
/// process and clock services, and the probe under the name
/// `posix-probe`.
pub const POSIX_DIALOG_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    RAM_CLOCKED,
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "posix-probe",
        program: "posix-probe",
        connects: &["ramfs", "uart", "clock", "posix", "entropy"],
        quota: 512 * PAGE,
        // Diagnostic writers exercise the fixed root-owned /tmp/probe node.
        root: true,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

#[cfg(not(feature = "data-carrier-probe"))]
const RAM_POSIX_FILES: Record = RAM_CLOCKED;
#[cfg(feature = "data-carrier-probe")]
const RAM_POSIX_FILES: Record = Record {
    // The steps,auth-probe ELF maps 10 RO + 36 RX + 925 RW pages.
    // Data pages, stack and allowance are paid separately in this fixture.
    quota: (4096 + 971 + 12 + 128) * PAGE,
    ..RAM_CLOCKED
};

/// The authentic identity and bounded file proof fixture, before public mutation APIs.
#[cfg(not(any(feature = "ramfs-cleanup", feature = "loader-abort")))]
pub const POSIX_FILES_TABLE: &[Record] = &[
    RAM_POSIX_FILES,
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "posix-files",
        program: "posix-files",
        args: b"posix-files\0",
        connects: &["ramfs", "clock", "posix", "entropy"],
        quota: 2048 * PAGE,
        root: true,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// Genuine uncommitted exec attempts with one pending image at a time.
#[cfg(all(feature = "loader-abort", not(feature = "loader-info")))]
const RAM_LOADER_INFO: Record = RAM_CLOCKED;
#[cfg(feature = "loader-info")]
const RAM_LOADER_INFO: Record = Record {
    // This diagnostic ELF maps 9 RO + 31 RX + 920 RW pages.
    // The fixed data pool, stack and runtime allowance are paid separately.
    quota: (4096 + 960 + 12 + 128) * PAGE,
    ..RAM_CLOCKED
};

#[cfg(feature = "loader-abort")]
pub const POSIX_FILES_TABLE: &[Record] = &[
    RAM_LOADER_INFO,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 2048 * PAGE + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    Record {
        name: "posix-files",
        program: "posix-files",
        args: b"posix-files\0",
        connects: &["ramfs", "clock", "posix", "entropy"],
        quota: 2048 * PAGE,
        root: true,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// Owner and retained foreign session holder for the unfinished-binding fixture.
#[cfg(feature = "ramfs-cleanup")]
pub const POSIX_FILES_TABLE: &[Record] = &[
    Record {
        priority: 40,
        ceiling: 40,
        ..RAM_CLOCKED
    },
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 4096 * PAGE + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    Record {
        name: "posix-files",
        program: "posix-files",
        args: b"posix-files\0",
        connects: &["ramfs", "clock", "posix", "entropy", "ramfs-holder"],
        priority: 30,
        ceiling: 31,
        quota: 2048 * PAGE,
        root: true,
        ..POSIX
    },
    Record {
        name: "ramfs-holder",
        program: "ramfs-holder",
        priority: 35,
        ceiling: 40,
        quota: 64 * PAGE,
        ..RAM_BASE
    },
    Record {
        name: "ramfs-owner-0",
        args: b"posix-files\00\0",
        program: "posix-files",
        connects: &["ramfs", "clock", "posix", "entropy", "ramfs-holder"],
        priority: 30,
        ceiling: 31,
        quota: 2048 * PAGE,
        root: false,
        ..POSIX
    },
    Record {
        name: "ramfs-owner-1",
        args: b"posix-files\01\0",
        program: "posix-files",
        connects: &["ramfs", "clock", "posix", "entropy", "ramfs-holder"],
        priority: 30,
        ceiling: 31,
        quota: 2048 * PAGE,
        root: false,
        ..POSIX
    },
    Record {
        name: "ramfs-owner-2",
        args: b"posix-files\02\0",
        program: "posix-files",
        connects: &["ramfs", "clock", "posix", "entropy", "ramfs-holder"],
        priority: 30,
        ceiling: 31,
        quota: 2048 * PAGE,
        root: false,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

pub const POSIX_ABI_TABLE: &[Record] = &[
    RAM_CLOCKED,
    Record {
        name: "posix",
        program: "posix-process-service",
        priority: PROCESS_LEVEL,
        ceiling: PROCESS_LEVEL,
        // Its own, and the eight objects of the pages of its records
        // (32 pages each); what its POSIX records take init adds.
        quota: 640 * PAGE,
        // A process handle for each of its 256 records.
        handle_limit: 1024,
        restart: Restart::Never,
        // Loader roots, obtained at startup and narrowed for each loader.
        connects: &["ramfs", "clock"],
        // Every POSIX process pays from its share and runs on its CPUs
        // (kernel spec 7.5, 8): all of them, so that it can give a process
        // the CPUs of its record.
        shares: POSIX_SHARES,
        cpus: ALL_CPUS,
        ..RAM_BASE
    },
    Record {
        name: "clock",
        program: "posix-clock-service",
        connects: &[],
        quota: 64 * PAGE,
        restart: Restart::Never,
        ..RAM_BASE
    },
    Record {
        name: "clock-peer",
        program: "posix-clock-peer",
        quota: 64 * PAGE,
        connects: &["clock", "posix"],
        restart: Restart::Never,
        ..RAM_BASE
    },
    Record {
        name: "posix-abi-probe",
        program: "posix-abi-probe",
        args: b"posix-abi-probe\0argument\0",
        connects: &["ramfs", "clock", "clock-peer", "posix", "long", "entropy"],
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
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The first C program on relibc (5a′): the RAM files, the process and
/// clock services, and the program.
pub const RELIBC_TABLE: &[Record] = &[
    RAM_CLOCKED,
    POSIX_ABI_TABLE[1],
    POSIX_ABI_TABLE[2],
    Record {
        name: "relibc-hello",
        program: "relibc-hello",
        root: true,
        args: b"relibc-hello\0",
        connects: &["ramfs", "clock", "posix", "entropy"],
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
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The pipe service (5e), beside the RAM file service at its level: its
/// segments, a stack of 32 KiB, the 64 rings of 4 KiB and the tables of
/// its 320 sessions, 256 births and 128 long operations in `.bss`; a
/// handle for each long operation that waits and for each pass of a socket
/// of the network service that a message holds (32 at most). 224 covers those
/// two; the identity session each caller of the IPC calls leaves (up to 320),
/// the tickets of named objects and the file service's notification take the
/// rest of the table, whose end the kernel answers with LIMIT_REACHED to the
/// sender (a pass then does not arrive).
pub const PIPE: Record = Record {
    name: "pipe",
    program: "pipe",
    quota: 160 * PAGE,
    handle_limit: 224,
    restart: Restart::Never,
    ..RAM_BASE
};

/// The probe of POSIX processes (tests/posix-procs): the RAM files, the
/// pipes, the process and clock services and the probe, whose children
/// start from files (5c): the table has the pool for 33 of them and holds
/// no record of theirs.
pub const POSIX_PROCS_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
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

/// The grants of the probe of the big room (`posix-map big`): the children
/// of fork of `/bin/procs-child` started by the probe's record hold two
/// places of 256 MiB, above the 64 MiB from which a process may grow its
/// room, down to the depth 2 (the child and its own child of fork). The
/// second line names a copy the probe makes at `/tmp/procs-mode`, to see
/// that the loader gives the path to the service only for a file of UID 0
/// that the group and the others cannot write.
pub const MAP_BIG_GRANTS: &[u8] =
    b"grant map-big program=/bin/procs-child under=posix-procs memory=256M places=2 depth=2\n\
grant map-mode program=/tmp/procs-mode under=posix-procs memory=80M places=1 depth=1\n";

/// The pages of the places of the grants above, set apart in the pool.
const MAP_BIG_PAGES: u64 = 2 * 65_536 + 20_480;

/// The probe of the big room and of the grant of quota (tests/posix-map,
/// the argument `big`): the table of POSIX_PROCS_TABLE with the grant above
/// and the pages of its places in the pool of the service. The probe itself
/// and its children of spawn have the quota of a command. The guest has
/// 1 GiB.
pub const POSIX_MAP_BIG_TABLE: &[Record] = &[
    POSIX_PROCS_TABLE[0],
    Record {
        quota: POSIX_PROCS_TABLE[1].quota + MAP_BIG_PAGES * PAGE,
        args: MAP_BIG_GRANTS,
        ..POSIX_PROCS_TABLE[1]
    },
    POSIX_PROCS_TABLE[2],
    POSIX_PROCS_TABLE[3],
    Record {
        args: b"posix-procs\0big\0",
        ..POSIX_PROCS_TABLE[4]
    },
    POSIX_PROCS_TABLE[5],
    POSIX_PROCS_TABLE[6],
];

/// The share of thread numbers the process service has in the probe of
/// shares: few enough for a probe to use up in a moment (kernel spec 7.5).
pub const SHARES_PROBE_THREADS: u32 = 24;

/// The probe of the shares of the process service (tests/posix-procs, the
/// role `shares`, #354): the table of POSIX_PROCS_TABLE with a share of
/// SHARES_PROBE_THREADS thread numbers for the service. The probe makes
/// threads until pthread_create says EAGAIN, finds fork and posix_spawn
/// refused with EAGAIN while it holds them and a file of the RAM service
/// still read, and finds fork working after its threads ended.
pub const POSIX_SHARES_TABLE: &[Record] = &[
    POSIX_PROCS_TABLE[0],
    Record {
        shares: Shares {
            threads: SHARES_PROBE_THREADS,
            timers: POSIX_SHARES.timers,
        },
        ..POSIX_PROCS_TABLE[1]
    },
    POSIX_PROCS_TABLE[2],
    POSIX_PROCS_TABLE[3],
    Record {
        args: b"posix-procs\0shares-main\0",
        // The CPUs of the services: the probe finds that its children of
        // fork keep them though the process service has every CPU.
        cpus: GENERAL_CPUS,
        ..POSIX_PROCS_TABLE[4]
    },
    POSIX_PROCS_TABLE[5],
    POSIX_PROCS_TABLE[6],
];

/// The probe of the longest step of the process service (tests/posix-procs
/// in the steps mode, xtask process-steps), with the entropy device's
/// driver and the entropy service at their levels 37 and 36, below the
/// services at 40 it measures. The pool for the crowd of
/// children it starts from files, each with the probe's quota, and one
/// more for the child that execs among them.
pub const STEPS_GRANTS: &[u8] =
    b"grant steps program=/bin/steps-grant under=ramfs memory=64M places=1 depth=1\n";
const STEPS_GRANT_PAGES: u64 = 16_384;

pub const POSIX_STEPS_TABLE: &[Record] = &[
    // Room for the crowd's descriptions in the RAM file service.
    Record {
        quota: RAM_FIFO_CLOCKED.quota,
        ..RAM_FIFO_CLOCKED
    },
    Record {
        quota: POSIX_ABI_TABLE[1].quota
            + (STEPS_CHILDREN + 2) * STEPS_QUOTA
            + 384 * PAGE
            + STEPS_GRANT_PAGES * PAGE,
        // A grant no program of the image uses: the steps of fork, spawn and
        // exec are measured with the reserve and the counter of places there.
        args: STEPS_GRANTS,
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
    // An initial process has its own expenditure root for 500-name publication.
    Record {
        name: "names-rival",
        program: "posix-procs",
        args: b"posix-procs\0bounds-fill\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy"],
        root: false,
        quota: STEPS_QUOTA,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The children of the steps probe: its 7 branches with their leaves, 32
/// each, and 24 of its own (tests/posix-procs STEPS_BRANCHES).
const STEPS_CHILDREN: u64 = 7 * 32 + 24;

/// The steps probe and each spawned child retain at most 477 pages with
/// all seven 64 KiB workers, including allocator mapping and alignment
/// (measured on the part that added the memory map's tables, the shared
/// memory and the files of mappings: 459 pages on main before it, of which
/// the program's image grew by 5 pages and the layer's by 8). The probe
/// requires 10% reserve; 528 pages leave 10.2%. The utilities part (the
/// layer's /proc, the registry of open streams, the utmpx, syslog and
/// getlogin code) added 3 pages to the 474: 477 measured, and 532 pages leave
/// 10.3%. The priority probe of the steps (two threads of the spawners, the
/// semaphores, the offsets of the asks) added 5: 482 measured, and 540 pages
/// leave 10.7%. Goal I (64 signals with their tables of claims, the queue
/// of the library's timers, the claims of the memory limits) added 12: 494
/// measured. The guard of a stack is a hole that takes no frame; each stack
/// is an object of its own and the workload measured 496: 552 pages left
/// 10.1%, under one page to the probe's 90% (#300). With 576 pages and the
/// relibc of #432 the workload measures 499: 13.4% left, 19 pages to 90%,
/// near the cost of a thread of the volley (20 pages). The steps probe
/// reserves 250 of them on the 2 GiB machine, 24 MiB more. The sockets of the
/// network service (the layer's `net.rs`, the session in fork and spawn)
/// added 22: 521 measured, and 608 pages leave 14.3%, 26 pages to 90%. The
/// relibc that takes its stack canary from AT_RANDOM (stafeto-design#697) grew
/// the probe by one page: 548 measured against 547 before, one page over 90%
/// of 608 (547.2). With 640 pages the 548 leave 14.4%, 28 pages to 90%.
const STEPS_QUOTA: u64 = 640 * PAGE;

/// The probe and each child it spawns inherit this budget. The slow 1 MiB
/// allocator growth retained 572 charged pages when it was set to 704. The
/// layer and relibc grew since: main measured 633 pages of the slow growth
/// and 631 of the forked child, under one page to the probe's 90% of 704,
/// and the relibc of #432 (one write a message, pin-5f477a7f) 635 and 633
/// with 736 pages: 13.7% left, 27 pages to 90%. Step 6, part 1 (the memory
/// streams without a file, the probes of relibc in the image, 64 descriptions
/// of poll) measured 651 and 649 pages: 11 to 90% of 736. With 768 pages 90% is
/// 691, 40 pages away, about two threads of a volley. The room that grows
/// and the search by words (P6b-4a) added 10: 692 measured, and 800 pages
/// leave 14.3% with 28 pages to 90%.
pub(super) const PROCS_QUOTA: u64 = 800 * PAGE;

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
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 32 * OS_TEST_QUOTA + 384 * PAGE,
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
        // 35 and a ceiling of 36, as high as the entropy service allows: the
        // 32 real-time priorities of the tests are the levels 4 to 35, and
        // SCHED_OTHER stands below them at 3.
        priority: 35,
        ceiling: 36,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The quota of the runner of os-test, which each test it starts gets too.
/// 1,280 pages (it was 610: tests of Open POSIX start 30 threads, each with a
/// stack of 64 KiB, and the thread tests of Open POSIX that run longer than
/// the heap allows end in EAGAIN or OOM below that). The 610 pages were measured on the whole of basic and Open POSIX (bisected on the
/// quota with the tests that passed before): 554 pages pass and 553 do not,
/// the tightest being pthread_cond_wait/2-2, pthread_cond_timedwait/2-4 and
/// 2-7 (a stack is mapped for each thread, one after the other) and
/// basic/time/strftime_l (a second chunk of heap); 610 leave 10.1%. The
/// quota was 544 before the calls of message queues, semaphores and segments
/// and the checks of the pages of a segment, which the programs that use
/// semaphores carry, and 512 before the files, shared memory and the
/// rendezvous of the process service. 1,312 since the layer carries the path
/// of the shared buffer with the network service in every program (two pages
/// more of a static test): mmap/1-2 maps 4 MiB of shared memory, which its own
/// quota pays for, and failed with ENOMEM at 1,280.
const OS_TEST_QUOTA: u64 = 1312 * PAGE;

/// relibc-hello's record, for the records of its other runs.
const RELIBC_HELLO: Record = Record {
    name: "relibc-hello",
    program: "relibc-hello",
    args: b"relibc-hello\0",
    connects: &["ramfs", "clock", "posix", "entropy"],
    quota: 512 * PAGE,
    ..POSIX
};

/// The threads of relibc (5a′): as RELIBC_TABLE, with room for 64
/// threads (four handles each, their stacks and TCBs).
pub const RELIBC_THREADS_TABLE: &[Record] = &[
    RAM_CLOCKED,
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
    super::entropy::RNG,
    super::entropy::ENTROPY,
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
    ..RAM_BASE
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
    ..RAM_BASE
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
    RAM_FIFO_CLOCKED,
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
    ..RAM_BASE
};

// The loop of the process service works at this level while walks of the
// terminal are queued (TtySignal): below the terminal service, so that the
// terminal runs ahead of the walk. Spec 2, 2.
const _: () = assert!(PROCESS_LEVEL - proto_process::TTY_STEP_BELOW < TTY.priority);

// The thread of the process service that takes the sessions of EntropyRejoin
// from the entropy service's root works at the entropy service's level, so
// that the loop of the process service never waits for it (spec 2, 2).
const _: () = assert!(super::entropy::ENTROPY.priority == proto_process::REJOIN_LEVEL);

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
    RAM_FIFO_CLOCKED,
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

/// The probe of the restart of the entropy service (tests/posix-random, role
/// `restart`, `cargo xtask posix-random-restart`): the table of the probe of
/// getentropy, whose service is built with CRASH and starts at once from
/// the boot seed.
pub const POSIX_RANDOM_RESTART_TABLE: &[Record] = &[
    POSIX_RANDOM_TABLE[0],
    POSIX_RANDOM_TABLE[1],
    POSIX_RANDOM_TABLE[2],
    POSIX_RANDOM_TABLE[3],
    POSIX_RANDOM_TABLE[4],
    POSIX_RANDOM_TABLE[5],
    Record {
        args: b"posix-random\0restart\0",
        ..POSIX_RANDOM_TABLE[6]
    },
];

/// The probe of EntropyRejoin (tests/posix-random, role `rejoin`, `cargo xtask
/// posix-random-restart`): the table of the probe of the restart with the
/// room of the processes it keeps alive at once (a spawned program, an
/// unseeded one, a forked child and its own child, then a program born after
/// the restart).
pub const POSIX_RANDOM_REJOIN_TABLE: &[Record] = &[
    POSIX_RANDOM_TABLE[0],
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 7 * PROCS_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_RANDOM_TABLE[2],
    POSIX_RANDOM_TABLE[3],
    POSIX_RANDOM_TABLE[4],
    POSIX_RANDOM_TABLE[5],
    Record {
        args: b"posix-random\0rejoin\0",
        ..POSIX_RANDOM_TABLE[6]
    },
];

/// The probe of the limit of EntropyRejoin (tests/posix-random, role `limit`):
/// four programs that outlive the old instance and a set-ID one.
pub const POSIX_RANDOM_LIMIT_TABLE: &[Record] = &[
    POSIX_RANDOM_REJOIN_TABLE[0],
    POSIX_RANDOM_REJOIN_TABLE[1],
    POSIX_RANDOM_REJOIN_TABLE[2],
    POSIX_RANDOM_REJOIN_TABLE[3],
    POSIX_RANDOM_REJOIN_TABLE[4],
    POSIX_RANDOM_REJOIN_TABLE[5],
    Record {
        args: b"posix-random\0limit\0",
        ..POSIX_RANDOM_TABLE[6]
    },
];

/// The probe of the display service's place in a process (tests/
/// posix-display, sub-project 3 part 3a): the RAM files, the process and
/// clock services, the pipe service and the display service (level 33,
/// above the processes of POSIX; QEMU has its device on, and the probe never
/// opens the screen: it asks for sessions only). The probe
/// starts its own file once, whose copy forks, spawns and execs.
pub const POSIX_DISPLAY_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 3 * PROCS_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    super::gpu::GPU,
    Record {
        name: "posix-display",
        program: "posix-display",
        args: b"posix-display\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy", "gpu"],
        root: true,
        quota: PROCS_QUOTA,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
];

/// The probe of the screen and the keys on libc.so (tests/display-run and
/// tests/posix-so/dyn/display-probe.c, sub-project 3 part 3b): the RAM
/// files, the process and clock services, the pipe service, the input
/// service and the display service (which may grant the focus). The first
/// launcher has a session with the display service and runs the C probe's
/// whole sequence; the second has none (its `connects` lack `gpu`) and runs
/// the role of an image without a display service.
pub const DISPLAY_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 5 * PROCS_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    super::input::INPUT,
    super::input::GPU,
    Record {
        name: "display-run",
        program: "display-run",
        args: b"display-run\0run\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy", "gpu"],
        root: true,
        quota: PROCS_QUOTA,
        ..POSIX
    },
    Record {
        name: "display-run-b",
        program: "display-run",
        args: b"display-run\0nogpu\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy"],
        root: false,
        quota: PROCS_QUOTA,
        ..POSIX
    },
    super::entropy::RNG,
    super::entropy::ENTROPY,
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

/// The socket probe uses the loader probe's ordinary services and pool.
pub const POSIX_SOCK_TABLE: &[Record] = &[
    LOADER_CHANNELS_TABLE[0],
    LOADER_CHANNELS_TABLE[1],
    LOADER_CHANNELS_TABLE[2],
    LOADER_CHANNELS_TABLE[3],
    LOADER_CHANNELS_TABLE[4],
    LOADER_CHANNELS_TABLE[5],
    Record {
        name: "posix-sock",
        program: "posix-sock",
        args: b"posix-sock\0",
        ..LOADER_CHANNELS_TABLE[6]
    },
    LOADER_CHANNELS_TABLE[7],
    LOADER_CHANNELS_TABLE[8],
];

/// The probe of message queues, semaphores and shared memory uses the loader probe's ordinary services and pool.
pub const POSIX_IPC_TABLE: &[Record] = &[
    LOADER_CHANNELS_TABLE[0],
    LOADER_CHANNELS_TABLE[1],
    LOADER_CHANNELS_TABLE[2],
    LOADER_CHANNELS_TABLE[3],
    LOADER_CHANNELS_TABLE[4],
    LOADER_CHANNELS_TABLE[5],
    Record {
        name: "posix-ipc",
        program: "posix-ipc",
        args: b"posix-ipc\0",
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
