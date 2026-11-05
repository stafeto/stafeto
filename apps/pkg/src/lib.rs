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
pub mod settings;
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

pub const USAGE_REPO: &str =
    "usage: pkg repo add <name> <https address> <key file> | remove <name> | list | save";

pub const USAGE: &str = "usage: pkg install|remove|upgrade|update|list|info|search|repo|check ...";

/// Whether `install` and `upgrade` may go on after the repositories were asked: when any one was
/// refused (signature, header, term, clock, serial, network) they refuse as a whole. A name is
/// never decided among the repositories that are left, so a damaged answer of one repository
/// cannot put the package of another in its place.
pub fn may_change_the_store(refused: usize) -> bool {
    refused == 0
}

/// The exit code of a command that only reads (`list`, `info`, `search`): it works over the good
/// repositories, and 1 says a line about a refused one was printed.
pub fn exit_of_reading(refused: usize) -> i32 {
    if refused == 0 { EXIT_OK } else { EXIT_REFUSED }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_repository_stops_a_change_and_marks_a_read() {
        assert!(may_change_the_store(0));
        assert!(!may_change_the_store(1));
        assert!(!may_change_the_store(3));
        assert_eq!(exit_of_reading(0), 0);
        assert_eq!(exit_of_reading(1), 1);
    }
}
