// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! First shell on Apple's Virtio PCI console.

use super::{Kind, Record, Restart};
use crate::PAGE;

pub const TABLE: &[Record] = &[Record {
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
    connects: &[],
    args: &[],
}];
