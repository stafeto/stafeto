// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the probe of the overruns in the journal (feature
//! `table-budget-journal`, xtask `budget-journal`): one client, `burner`
//! (tests/svc, role `b`), with two budgets on CPU 0 of 1 ms for each 10 ms.
//! Its thread under `hog` works without a pause, so the budget runs out in
//! every period; its thread under `quiet` works 100 us of each 10 ms and
//! never runs out.

use super::{Budget, GENERAL_CPUS, Kind, Record, Restart, Shares};
use crate::PAGE;

const MS: u64 = 1_000_000;

pub const TABLE: &[Record] = &[Record {
    name: "burner",
    program: "svc",
    kind: Kind::Client,
    priority: 30,
    ceiling: 30,
    quota: 64 * PAGE,
    handle_limit: 64,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &[],
    args: b"b",
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
    budgets: &[
        Budget {
            name: "hog",
            cpu: 0,
            c_ns: MS,
            t_ns: 10 * MS,
            low: 1,
        },
        Budget {
            name: "quiet",
            cpu: 0,
            c_ns: 2 * MS,
            t_ns: 10 * MS,
            low: 1,
        },
    ],
}];
