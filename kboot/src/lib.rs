// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the kernel reads once at boot: the device tree, the facts it gives
//! (`bootinfo`), and the map of usable memory with the check of the boot
//! image (`memmap`). The code takes bytes from outside the kernel and
//! contains no `unsafe`; the compiler enforces that. It builds for the
//! kernel target and for the host, where `cargo test -p kboot` exercises it,
//! and the EFI boot loader links it as well.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Pages of 4 KiB (spec 7.1, 7.2): the memory map counts in them, and
/// `kcore` re-exports the constants for frames, tables and quotas.
pub const PAGE_SHIFT: u32 = 12;
pub const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;

#[macro_use]
pub mod must;
pub mod bootinfo;
pub mod fdt;
pub mod memmap;

#[cfg(feature = "builder")]
extern crate alloc;
