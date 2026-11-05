// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the base image and the full image (`boot-base.img`,
//! `boot-full.img`, xtask `image base` and `image full`): the shell's dialog
//! with the screen and the keys of the games table (`doom::TABLE`) and the
//! network service (`net::NETD`). The launcher connects to both the display
//! service and the network service, so the shell and its commands reach the
//! screen and the network, and has the larger quota of the two tables
//! (`NET_COMMAND_QUOTA`); the process service has the pool of the network
//! image. The services of the disk and of packages come in the stages that
//! make them (spec 5).

use super::doom;
use super::net::{NET_COMMAND_QUOTA, NET_PROCESS_SERVICE, NETD};
use super::{NET_SERVICE, Record};

// BASE_TABLE copies the records of the games table by number.
const _: () = assert!(doom::TABLE.len() == 11);

const fn at_least(a: u64, b: u64) -> u64 {
    if a > b { a } else { b }
}

/// What the launcher connects to: the games table's, and the network
/// service.
const LAUNCHER_CONNECTS: &[&str] = &[
    "ramfs",
    "tty",
    "pipe",
    "clock",
    "posix",
    "entropy",
    "gpu",
    NET_SERVICE,
];

/// The launcher of the games table with the network service too, under the
/// larger of the two quotas of a command.
pub const LAUNCHER: Record = Record {
    quota: at_least(doom::QUOTA, NET_COMMAND_QUOTA),
    connects: LAUNCHER_CONNECTS,
    ..doom::TABLE[5]
};

/// The table of the base and the full image.
pub const BASE_TABLE: &[Record] = &[
    doom::TABLE[0],
    doom::TABLE[1],
    NET_PROCESS_SERVICE,
    doom::TABLE[3],
    doom::TABLE[4],
    LAUNCHER,
    doom::TABLE[6],
    doom::TABLE[7],
    doom::TABLE[8],
    doom::TABLE[9],
    doom::TABLE[10],
    NETD,
];
