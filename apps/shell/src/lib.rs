// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the shell decides (spec 13.6), apart from the calls it makes: the
//! line it edits from the bytes of input and what it echoes, the commands
//! a line names, the records of init's LIST a page at a time, and the
//! lines of its output. The program only reads and
//! writes through the UART driver and asks init; everything here builds
//! for the host too, where `cargo test -p shell` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod command;
pub mod format;
pub mod line;
pub mod text;
