// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What `pkg` decides (pk4-design R1), apart from the calls it makes: the
//! repositories and their addresses, the command line of `curl`, the checks
//! of an index and of the list of revocations, the resolution of the names
//! and dependencies, the lines it prints and the line of every refusal.
//! Everything here takes bytes and numbers and gives decisions and text, so
//! `cargo test -p pkg` exercises it on the host; the program (`main`,
//! `client`, `spawn`, `sys`) makes the calls and decides nothing.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod config;
pub mod faults;
pub mod fetch;
pub mod output;
pub mod resolve;
pub mod verify;

/// The series of the system and the roots of trust the build baked in.
pub mod baked {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

/// The exit codes: success (also nothing to do), a refused operation, a bad
/// command line.
pub const EXIT_OK: i32 = 0;
pub const EXIT_REFUSED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

pub const USAGE: &str = "usage: pkg install|remove|upgrade|update|list|info|search|repo|check ...";
