// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What init decides (spec 13.4), apart from the calls it makes: its table
//! of services and the checks of it, the order it starts them in, the
//! labels it gives, the pause before a restart and the mark of a broken
//! service, the watchdog, the quota an instance needs, and the queue of
//! its worker thread with the worker's level. The program only calls
//! these functions; everything here builds for the host too, where
//! `cargo test -p init` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod labels;
pub mod quota;
pub mod restart;
pub mod table;
pub mod watch;
pub mod work;

/// The size of a page (spec 7.3).
pub const PAGE: u64 = bootimg::PAGE_SIZE;
