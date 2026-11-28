// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the probe of the window library (tests/posix-window, the C
//! functions of `<stafeto/window.h>` in a static program): the services of
//! the POSIX probes, the display driver, the compositor (under the name
//! `gpu`, which the probe's place `Display` meets) and the probe, which
//! starts its own file once, and whose copy makes a window, forks and closes
//! it. The tables of `posix-display` and `comp` made one.

use super::ramfs::{PIPE, POSIX, POSIX_ABI_TABLE, PROCS_QUOTA, RAM_FIFO_CLOCKED};
use super::{Record, comp, entropy};
use crate::PAGE;

/// The pages of the window buffers the probe has open at once. The rule: for
/// each window, the buffers times ceil(stride times lines / 4096) pages; a
/// resizable XRGB8888 window of 640 by 400 is 250 pages a buffer (two buffers,
/// 500) and the small windows of the probe add about 40. Both the probe's
/// record and the POSIX service's record carry it.
const WINDOW_PAGES: u64 = 540;

pub const TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 3 * PROCS_QUOTA + (384 + WINDOW_PAGES) * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    comp::DISPLAY,
    comp::COMPOSITOR,
    Record {
        name: "posix-window",
        program: "posix-window",
        args: b"posix-window\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy", "gpu"],
        root: true,
        quota: PROCS_QUOTA + WINDOW_PAGES * PAGE,
        ..POSIX
    },
    entropy::RNG,
    entropy::ENTROPY,
];
