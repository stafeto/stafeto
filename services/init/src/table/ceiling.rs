// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A table init refuses (feature `table-ceiling`, spec 15.2): a client
//! whose ceiling, 50, is above the service it connects to, at 40.

use super::{Kind, Record, Restart};
use crate::PAGE;
use crate::watch::Watch;

pub const TABLE: &[Record] = &[
    Record {
        name: "low",
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
        windows: &[],
        bindings: &[],
        connects: &[],
        args: b"e",
    },
    Record {
        name: "high",
        program: "svc",
        kind: Kind::Client,
        priority: 50,
        ceiling: 50,
        quota: 32 * PAGE,
        handle_limit: 32,
        restart: Restart::Never,
        console: false,
        windows: &[],
        bindings: &[],
        connects: &["low"],
        args: b"c",
    },
];
