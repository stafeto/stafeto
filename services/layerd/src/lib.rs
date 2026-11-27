// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer service of stafeto (the layered file system, step C3 part A): the names of the
//! layered root, read only. This library holds what the service decides, apart from the calls to
//! the data file service and to the RAM file service (`Volume` and `Lower`): the format of the
//! COMPOSITION file (`composition`), the index of the names of the live layer (`index`) and its
//! construction from the volume in steps (`scan`), the walk of a path (`lookup`), the merged
//! listing of a directory (`listing`), the identity of a client (`identity`), the descriptions the
//! service keeps (`descriptions`), the answers to the requests (`names`) and the changes of names
//! (`change`). The program
//! (`main.rs`) is for stafeto alone.

#![cfg_attr(not(test), no_std)]

pub mod change;
pub mod composition;
pub mod descriptions;
pub mod identity;
pub mod index;
pub mod jobs;
pub mod listing;
pub mod lookup;
pub mod names;
pub mod reaper;
pub mod scan;
pub mod volume;

#[cfg(test)]
mod change_tests;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;
