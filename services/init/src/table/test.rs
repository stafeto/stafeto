// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the image of init's tests (feature `table-test`, spec
//! 15.2): every record runs the program `svc` (tests/svc), whose role the
//! first byte of its own arguments names: `e` echo, `d` device, `c`
//! checker. Byte 1 of the arguments of an echo, `g`, makes it wait at the
//! gate of `echo` before its REGISTER. Services send a heartbeat
//! every 20 ms; the client `checker` runs the tests and prints their
//! lines.

use super::{Binding, Kind, Record, Restart, Window};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The heartbeat and the watchdog of most services.
const WATCH: Watch = Watch {
    period_ns: 20 * MS,
    deadline_ns: 100 * MS,
};

/// An echo service at `level`, its priority and ceiling, with `watch` and
/// the own arguments `args`.
const fn echo(name: &'static str, level: u8, watch: Watch, args: &'static [u8]) -> Record {
    Record {
        name,
        program: "svc",
        kind: Kind::Service(watch),
        priority: level,
        ceiling: level,
        quota: 32 * PAGE,
        handle_limit: 32,
        restart: Restart::Always,
        console: false,
        windows: &[],
        bindings: &[],
        connects: &[],
        args,
    }
}

pub const TABLE: &[Record] = &[
    echo("echo", 40, WATCH, b"e"),
    // Registers once the checker opened the gate of `echo`, with a
    // watchdog of 1 s.
    Record {
        connects: &["echo"],
        ..echo(
            "slow",
            40,
            Watch {
                period_ns: 20 * MS,
                deadline_ns: 1000 * MS,
            },
            b"eg",
        )
    },
    // The PL031 of QEMU's virt machine and its shared line 34.
    Record {
        windows: &[Window {
            name: "rtc",
            base: 0x0901_0000,
            len: PAGE,
        }],
        bindings: &[Binding {
            name: "rtc-irq",
            line: 34,
            edge: false,
        }],
        ..echo("device", 40, WATCH, b"d")
    },
    Record {
        kind: Kind::Client,
        restart: Restart::Never,
        console: true,
        quota: 64 * PAGE,
        handle_limit: 64,
        connects: &["echo", "slow", "device"],
        ..echo("checker", 30, WATCH, b"c")
    },
    // Known to the table, but not among the connections of `checker`.
    echo("private", 20, WATCH, b"e"),
];
