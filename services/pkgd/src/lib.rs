// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The package service of stafeto (pk3-design): the store on the disk, the
//! packages attached to the file service as layers, the settings and the
//! revocation list. This library holds what the service decides, apart from
//! the calls: the format of the store and the steps that touch the disk
//! (`store`, `commit`). The
//! program (`main.rs`) is for stafeto alone; with the feature `host` the
//! library also writes a store to a file for xtask (`host`).

#![cfg_attr(not(any(test, feature = "host")), no_std)]

pub mod commit;
pub mod store;

#[cfg(any(test, feature = "host"))]
pub mod host;

#[cfg(test)]
mod commit_tests;
#[cfg(test)]
mod store_tests;
#[cfg(test)]
mod testkit;

mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

/// The series of the system: the packages of another do not attach.
pub use config::SERIES;

/// The roots of the trust of the official repository, one `.pub` line each.
pub use config::ROOTS;
