// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the base image and the full image (`boot-base.img`,
//! `boot-full.img`, xtask `image base` and `image full`): the shell's dialog
//! with the screen and the keys of the games table (`doom::TABLE`) and the
//! network service (`net::NETD`). The launcher connects to both the display
//! service and the network service, so the shell and its commands reach the
//! screen and the network, and has the larger quota of the two tables
//! (`NET_COMMAND_QUOTA`) and waits for the package service to say READY before
//! it starts the shell; the process service has the pool of the network
//! image. The disk service and the package service close the table.

use super::doom;
use super::net::{NET_COMMAND_QUOTA, NET_PROCESS_SERVICE, NETD};
use super::pkg::{BLK, PKGD};
use super::{NET_SERVICE, Record, Wait};

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
    "pkgd",
];

/// How long the launcher waits for the package service to say READY
/// (spec 5, section 4): the service reads the disk, checks the signature and
/// the hash of each package and attaches its layer, a few seconds with Doom
/// on it; past this the shell starts without waiting (`init: pkgd not ready
/// after 30 s`).
pub const PKGD_READY_MS: u32 = 30_000;

/// The launcher of the games table with the network service too, under the
/// larger of the two quotas of a command.
pub const LAUNCHER: Record = Record {
    quota: at_least(doom::QUOTA, NET_COMMAND_QUOTA),
    connects: LAUNCHER_CONNECTS,
    waits: &[Wait {
        service: "pkgd",
        deadline_ms: PKGD_READY_MS,
    }],
    ..doom::TABLE[5]
};

/// The command quotas of the pool of the process service of the base and the
/// full image: the network image's sixteen less two, which the package service
/// takes (its 16 896 pages of quota, the disk service's 64 and the table
/// itself are out of init's 127 789 pages on 512 MiB). Nothing of the shell,
/// `httpd` or a reload of nginx (nine processes, 30 440 pages) needs more than
/// the 14 x 4 096 pages left.
pub const COMMAND_QUOTAS: u64 = 14;

/// The process service of the base and the full image: the pool of the
/// network image with `COMMAND_QUOTAS` quotas of a command.
pub const BASE_PROCESS_SERVICE: Record = Record {
    quota: super::ramfs::POSIX_ABI_TABLE[1].quota
        + super::ramfs::BUSYBOX_DIALOG_POOL
        + COMMAND_QUOTAS * NET_COMMAND_QUOTA,
    ..NET_PROCESS_SERVICE
};

/// The table of the base and the full image.
///
/// What init has free after the services started (the line `init: free pages`,
/// kept from 16 384 by `cargo xtask pkg-identity`): `boot-base.img` 26 843 pages of
/// 127 972 on 512 MiB; `boot-full.img` 15 837 of 116 988 on 512 MiB, because its container
/// of 54 MB leaves the memory of init about 11 000 pages smaller than the base image's, and the
/// pool of the process service (16 quotas of 4 096 pages) stays; so the full image runs on 1 GiB
/// (xtask `base_image::machine`), where the number is the one in docs/packages.md. The disk
/// and package services come out of the same number.
pub const BASE_TABLE: &[Record] = &[
    doom::TABLE[0],
    doom::TABLE[1],
    BASE_PROCESS_SERVICE,
    doom::TABLE[3],
    doom::TABLE[4],
    LAUNCHER,
    doom::TABLE[6],
    doom::TABLE[7],
    doom::TABLE[8],
    doom::TABLE[9],
    doom::TABLE[10],
    NETD,
    BLK,
    PKGD,
];
