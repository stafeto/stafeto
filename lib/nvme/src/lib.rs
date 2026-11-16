// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A driver of an NVMe controller (PCI class 0x010802) as a library: no call
//! of the kernel and no stack. The owner of the controller maps BAR 0 and two
//! DMA objects (the queues and the cells) and gives the driver a `Platform`
//! (the registers, a clock, the barriers, the console) and the two `Region`s.
//! The driver brings the controller up on polling (capabilities, disable,
//! admin queue, enable, Identify, Set Features, one I/O queue pair), runs
//! Read, Write and Flush on four cells of 16 KiB, watches the controller and
//! resets it in place.
//!
//! Every step of `Nvme::poll` and every call of the submission makes at most
//! one register access and a bounded number of stores (the constants of
//! `device`). The numbers are those of the NVM Express Base Specification;
//! no code of another system is part of this library.

#![cfg_attr(not(test), no_std)]

pub mod cmd;
pub mod device;
pub mod mmio;
pub mod regs;

#[cfg(any(test, feature = "model"))]
pub mod model;

#[cfg(test)]
mod tests;

pub use device::{
    Cause, Completion, Config, Event, Failure, Info, Nvme, Outcome, Platform, Region, Reject,
    Unsupported,
};
