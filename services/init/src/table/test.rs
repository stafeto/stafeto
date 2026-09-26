// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the image of init's tests (feature `table-test`, spec
//! 15.2): every record runs the program `svc` (tests/svc), whose role the
//! first byte of its own arguments names: `e` echo, `d` device, `x` crash,
//! `s` silent, `k` sink, `m` mute, `c` checker. Byte 1 of the arguments of
//! an echo, `g`, makes it wait at the gate of `echo` before its REGISTER;
//! byte 1 of a silent is the ceiling it raises itself to when it hangs.
//! Services send a heartbeat every 20 ms; the client `checker` runs the
//! tests, prints their lines, and ends: its policy is never.

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
    // Marks the session that greets it and, when it goes, asks init for its
    // STATS: the level init's worker runs a kill at (kill_runs_above...).
    echo("sink", 40, WATCH, b"k"),
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
    // Fails right after its start: broken after five failures.
    echo("crash", 35, WATCH, b"x"),
    // Connects to sink; on HANG it raises itself to its ceiling (32) and
    // spins, so its heartbeat stops and the watchdog restarts it.
    Record {
        ceiling: 32,
        kind: Kind::Service(Watch {
            period_ns: 20 * MS,
            deadline_ns: 300 * MS,
        }),
        connects: &["sink"],
        ..echo("silent", 30, WATCH, b"s\x20")
    },
    // Never registers, and its HEARTBEAT gets BAD_STATE: the watchdog from
    // its start restarts it until it is broken.
    echo("mute", 30, WATCH, b"m"),
    Record {
        kind: Kind::Client,
        restart: Restart::Never,
        console: true,
        quota: 64 * PAGE,
        handle_limit: 64,
        connects: &["sink", "echo", "slow", "device", "crash", "silent", "mute"],
        ..echo("checker", 30, WATCH, b"c")
    },
    // Known to the table, but not among the connections of `checker`.
    echo("private", 20, WATCH, b"e"),
    // A quota of 1 TiB, more than init has: its start waits.
    Record {
        quota: 1 << 40,
        ..echo("hog", 20, WATCH, b"e")
    },
];
