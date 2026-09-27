// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the driver of the PL011 decides (spec 13.5), apart from the
//! registers it reaches and the calls it makes: the registers and their
//! bits, the ring of output with the lines of the kernel log put between
//! the lines of the clients, the writes that wait for room, the ring of
//! input with the owner of the console and its waiting read, what an
//! interrupt pass reads and writes and what it writes to ICR and IMSC, and
//! the text of a batch of the kernel log. The program only reads the
//! registers, calls these and writes what they decide; everything here
//! builds for the host too, where `cargo test -p uart` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod input;
pub mod irq;
pub mod log;
pub mod output;
pub mod regs;
pub mod writes;
