// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the POSIX process service decides apart from the calls it makes:
//! the table of its records (`records`), the queue of the spawns that
//! wait (`queue`), the waits that wait (`waits`) and the rules of
//! signals (`signals`), the steps of the walks over the records
//! (`walk`), and the controlling terminals of the sessions (`terminals`). The program creates the
//! processes and keeps their handles; everything here builds for the host
//! too, where `cargo test -p posix-process-service` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod executable;
#[cfg(feature = "image-probe")]
pub mod image_probe;
pub mod loaders;
pub mod queue;
pub mod records;
pub mod signals;
pub mod terminals;
pub mod waits;
pub mod walk;
