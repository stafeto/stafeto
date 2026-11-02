// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the games image (`boot-doom.img`, xtask doom-headless):
//! the dialog of the shell (`ramfs::BUSYBOX_DIALOG_TABLE`) with a bigger
//! quota for the launcher, which the shell and its children get too. Doom
//! keeps its zone of 6 MiB (`DEFAULT_RAM` of Doomgeneric) and the 3 MB of
//! its program in memory, and the shell's 1 160 pages hold neither. A child
//! of the shell gets the shell's quota, so the pool of the process service
//! is counted again from 3 072 pages as `BUSYBOX_DIALOG_POOL` is from 1 160:
//! that one holds 9 children of the dialog (10 520 pages), this one
//! four and a half (13 824 pages), half of them, which the shell, Doom and
//! the few commands between them fit in.

use super::Record;
use super::ramfs::{BUSYBOX_DIALOG_TABLE, POSIX_ABI_TABLE};
use crate::PAGE;

/// The quota of the launcher, and of the shell and Doom under it.
pub const QUOTA: u64 = 3072 * PAGE;

/// What the process service adds to its own quota: four and a half quotas
/// of a child.
const POOL: u64 = QUOTA / 2 * 9;

/// The table of the shell's dialog with the quota of Doom.
pub const TABLE: &[Record] = &[
    BUSYBOX_DIALOG_TABLE[0],
    BUSYBOX_DIALOG_TABLE[1],
    Record {
        quota: POSIX_ABI_TABLE[1].quota + POOL,
        ..BUSYBOX_DIALOG_TABLE[2]
    },
    BUSYBOX_DIALOG_TABLE[3],
    BUSYBOX_DIALOG_TABLE[4],
    Record {
        quota: QUOTA,
        ..BUSYBOX_DIALOG_TABLE[5]
    },
    BUSYBOX_DIALOG_TABLE[6],
    BUSYBOX_DIALOG_TABLE[7],
    BUSYBOX_DIALOG_TABLE[8],
];
