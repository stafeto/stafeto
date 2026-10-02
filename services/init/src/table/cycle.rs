// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A table init refuses (feature `table-cycle`, spec 15.2): two services
//! that connect to each other.

use super::{Kind, Record, Restart};
use crate::PAGE;
use crate::watch::Watch;

const fn service(name: &'static str, connects: &'static [&'static str]) -> Record {
    Record {
        name,
        program: "svc",
        kind: Kind::Service(Watch {
            period_ns: 20_000_000,
            deadline_ns: 100_000_000,
        }),
        priority: 40,
        ceiling: 40,
        quota: 32 * PAGE,
        handle_limit: 32,
        restart: Restart::Always,
        console: false,
        log: false,
        trace: false,
        windows: &[],
        bindings: &[],
        connects,
        args: b"e",
        dma: &[],
        quiesce: &[],
        trusted: false,
        root: false,
        on_demand: false,
    }
}

pub const TABLE: &[Record] = &[service("a", &["b"]), service("b", &["a"])];
