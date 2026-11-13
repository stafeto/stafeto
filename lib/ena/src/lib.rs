// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A driver of the Amazon ENA network device (PCI 1d0f:ec20 and kin) as a
//! library: no call of the kernel and no stack. The owner of the device maps
//! BAR 0 and the DMA objects and gives the driver a `Platform` (the
//! registers, a clock, the barriers, the console) and a `Region` of memory;
//! the driver brings the device up on polling (reset, version and capability
//! registers, the admin queue, the device attributes, the event queue with
//! keep-alive), watches it and resets it in place.
//!
//! The data path (the queue pairs) is a later step. Licence: the numbers of
//! `regs` and `admin` come from the BSD-3-Clause headers named in `NOTICE`.

#![cfg_attr(not(test), no_std)]

pub mod admin;
pub mod device;
pub mod mmio;
pub mod regs;

#[cfg(any(test, feature = "model"))]
pub mod model;

#[cfg(test)]
mod tests;

pub use device::{Ena, Event, Failure, Info, KeepAlive, Platform, ReadMode, Region};
