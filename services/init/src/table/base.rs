// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the base image and the full image (`boot-base.img`,
//! `boot-full.img`, xtask `image base` and `image full`): the shell's dialog
//! with the screen and the keys of the games table (`doom::TABLE`) and the
//! network service (`net::NETD`). The launcher connects to both the display
//! service and the network service, so the shell and its commands reach the
//! screen and the network, and has the larger quota of the two tables
//! (`NET_COMMAND_QUOTA`) and waits for the package service to say READY before
//! it starts the shell; the process service has the pool that init sizes at
//! boot (`INIT_RESERVE_PAGES`, `POOL_MIN_PAGES`). The disk service and the
//! package service close the table.

use super::doom;
use super::net::{NET_COMMAND_QUOTA, NET_PROCESS_SERVICE, NETD};
use super::pkg::{PKGD, STORE_BLK};
use super::{NET_SERVICE, Record, Wait};

// BASE_TABLE copies the records of the games table by number.
const _: () = assert!(doom::TABLE.len() == 12);

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

/// How long the launcher of the layered root waits for the layer service to say READY, and how
/// long init watches its start (spec 5, section 4): the time the index of the live layer takes to
/// build. The formula of the plan (3 times the measured time from the READY of the data service to
/// that of the layer service, within 30 s and `WAIT_MAX_MS`) gives the cap, 60 s, because the
/// measurement on EC2 was 293 s for a volume of 8,192 names. Temporary: the values come from the
/// formula again when the fast build of the index (issue 657) lands and the measurement is repeated.
pub const LAYERD_READY_MS: u32 = 60_000;

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

/// The pages init keeps free after the services started (the line `init:
/// free pages`): the restarts of all the records that restart, each while its
/// clients still hold the old instance, and the DMA objects one device that
/// did not stop leaves behind (`Instance::keep_dma`). `cargo xtask
/// init-reserve` checks that the sum of the restart needs of those records,
/// plus the largest DMA leak of one of them, fits it, and `cargo xtask
/// pkg-identity` that init's free pages stay at or above it. The EC2 table's
/// memory budget (`aws.rs`) counts the same reserve.
pub const INIT_RESERVE_PAGES: u64 = 16_384;

/// The pages of init's quota that init's own start-up spends and its sum of
/// the records does not see (kernel objects of the loads). Init keeps
/// them free on top of `INIT_RESERVE_PAGES`; when `pkg-identity` reports
/// fewer free pages than the reserve, raise this by the difference.
pub const INIT_SLACK_PAGES: u64 = 64;

/// The least pool of the process service: its 640 pages, the dialog pool of
/// 10 520 and ten quotas of 4 096 pages, which hold `httpd` with eight
/// children, its server and the shell (a reload of nginx takes 30 440 pages
/// of them, and the shell 4 096). Init sizes the pool at boot as the
/// remainder of its quota above `INIT_RESERVE_PAGES` (`init::quota::pool_pages`)
/// and never under this; a remainder under it prints a line that says by how
/// much, and `pkg-identity` fails on it.
pub const POOL_MIN_PAGES: u64 = 640 + 10_520 + 10 * 4_096;

// The pages above are what the table's own numbers give.
const _: () = assert!(
    POOL_MIN_PAGES * crate::PAGE
        == super::ramfs::POSIX_ABI_TABLE[1].quota
            + super::ramfs::BUSYBOX_DIALOG_POOL
            + 10 * NET_COMMAND_QUOTA
);

/// The process service of the base and the full image. Its quota here is the
/// minimum pool: init replaces it at boot with the pool it sizes
/// (`Init::size_pool`).
pub const BASE_PROCESS_SERVICE: Record = Record {
    quota: POOL_MIN_PAGES * crate::PAGE,
    ..NET_PROCESS_SERVICE
};

/// The table of the base and the full image.
///
/// What init has free after the services started (the line `init: free pages`)
/// is `INIT_RESERVE_PAGES` and the little over it that `INIT_SLACK_PAGES`
/// keeps: init gives the pool of the process service everything above them
/// (`Init::size_pool`), so a service that grows takes its pages from the
/// pool and nothing is balanced by hand. `cargo xtask pkg-identity` holds the
/// image to the reserve. The full image's container of 54 MB leaves the memory of init
/// about 11 000 pages smaller than the base image's, so it runs on 1 GiB
/// (xtask `base_image::machine`). The disk and package services come out of
/// the same number.
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
    doom::TABLE[11],
    NETD,
    STORE_BLK,
    PKGD,
];
