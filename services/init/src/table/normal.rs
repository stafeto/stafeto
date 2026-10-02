// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the boot image that ships (spec 13.4): the driver of the
//! PL011, the console's port (services/uart), and the shell (apps/shell),
//! its one client.

use super::{Binding, Kind, Record, Restart, Window};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The PL011 of QEMU's virt machine and its shared line (spec 9, 13.5).
const PL011: u64 = 0x0900_0000;
const PL011_LINE: u32 = 33;

pub const TABLE: &[Record] = &[
    // The window over the port takes it from the kernel (spec 3.2); the
    // driver reads the kernel log with `log` and prints the window's base,
    // its own arguments, low byte first.
    Record {
        name: "uart",
        program: "uart",
        kind: Kind::Service(Watch {
            period_ns: 250 * MS,
            deadline_ns: 1000 * MS,
        }),
        priority: 60,
        ceiling: 60,
        quota: 32 * PAGE,
        handle_limit: 32,
        restart: Restart::Always,
        console: true,
        log: true,
        trace: false,
        windows: &[Window {
            name: "regs",
            base: PL011,
            len: PAGE,
        }],
        bindings: &[Binding {
            name: "irq",
            line: PL011_LINE,
            edge: false,
        }],
        connects: &[],
        args: &PL011.to_le_bytes(),
        dma: &[],
        quiesce: &[],
        trusted: false,
        root: false,
        on_demand: false,
    },
    // No heartbeat: it waits for input and has no periodic work (spec
    // 13.6); the console only for the message of its panic.
    Record {
        name: "shell",
        program: "shell",
        kind: Kind::Client,
        priority: 30,
        ceiling: 30,
        quota: 32 * PAGE,
        handle_limit: 32,
        restart: Restart::Always,
        console: true,
        log: false,
        trace: true,
        windows: &[],
        bindings: &[],
        connects: &["uart"],
        args: &[],
        dma: &[],
        quiesce: &[],
        trusted: false,
        root: false,
        on_demand: false,
    },
];
