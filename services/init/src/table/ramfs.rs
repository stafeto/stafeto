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
/// room for the helper threads of `posix-abi`: its thread owner, heap and
/// file workers and sleep timer run at the ceiling, so an application
/// thread at main's level never delays them. Programs on `posix-bridge`
/// (`cprobe`, `busybox-probe`) have no such threads and leave it empty.
const POSIX: Record = Record {
    ceiling: TABLE[1].priority + 1,
    ..TABLE[1]
};

pub const CPROBE_TABLE: &[Record] = &[
    TABLE[0],
    Record {
        name: "cprobe",
        program: "cprobe",
        quota: 512 * PAGE,
        ..POSIX
    },
];

pub const BUSYBOX_TABLE: &[Record] = &[
    TABLE[0],
    Record {
        name: "busybox-probe",
        program: "busybox-probe",
        quota: 512 * PAGE,
        ..POSIX
    },
];

pub const BUSYBOX_DIALOG_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    TABLE[0],
    Record {
        connects: &["ramfs", "uart"],
        ..BUSYBOX_TABLE[1]
    },
];

pub const POSIX_ABI_TABLE: &[Record] = &[
    TABLE[0],
    Record {
        name: "posix",
        program: "posix-process-service",
        quota: 256 * PAGE,
        // A process handle for each of its 256 records, and a session of
        // each besides in the probe of its bound (transport-probe).
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
        connects: &["ramfs", "clock", "clock-peer", "posix"],
        quota: 2048 * PAGE,
        handle_limit: 128,
        root: true,
        ..POSIX
    },
];
