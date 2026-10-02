// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the POSIX process service decides apart from the calls it makes:
//! the table of its records (`records`) and the queue of the spawns that
//! wait (`queue`). The program creates the
//! processes and keeps their handles; everything here builds for the host
//! too, where `cargo test -p posix-process-service` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod queue;
pub mod records;
