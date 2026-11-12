// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The firmware's description of the machine, turned into the device tree
//! the kernel boots with (the Ч2 note): ACPI tables and the EFI memory map
//! in, a tree and a verdict of the kernel's own parser out. No hardware is
//! touched here: the boot loader (`boot/efi-loader`) reads the memory, this
//! crate works on slices, so every case runs on the host.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod acpi;
pub mod check;
pub mod efimap;
pub mod error;
pub mod platform;
pub mod tree;

pub use error::Error;

#[cfg(test)]
mod tests;
