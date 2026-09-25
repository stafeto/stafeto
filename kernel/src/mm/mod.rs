// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's memory: physical frames, its page tables, object pages and
//! the address spaces of processes.

pub mod aspace;
pub mod kmap;
pub mod pages;
pub mod phys;
