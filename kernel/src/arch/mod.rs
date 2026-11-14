// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's seam to the machine. `karch` holds what touches the
//! hardware and knows no kernel object; this module re-exports it and adds
//! what only the kernel can say: the block of each CPU (`cpu`, which carries
//! what the CPU owns), the entry of exceptions (`exceptions`), the bring-up
//! of the ITS inside the GIC's (`gic`), the ITS itself (`its`, whose
//! sections are part of the protocol of `OBJ`) and the backtrace of a
//! report (`backtrace`). Only AArch64 exists.

pub mod backtrace;
pub mod cpu;
pub mod exceptions;
pub mod gic;
pub mod its;

#[cfg(feature = "early-marks")]
pub use karch::marks;
#[cfg(any(feature = "fault-probe", feature = "overflow-probe"))]
pub use karch::probe;
pub use karch::{cache, mmio, mmu, registers, symbols, timer, user};
pub use karch::{irq_pending, on_empty_stack};
