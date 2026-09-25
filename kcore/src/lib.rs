// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Hardware-independent kernel logic. Everything here builds for the kernel
//! target and for the host, where `cargo test -p kcore` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod bootinfo;
pub mod fdt;
pub mod layout;
