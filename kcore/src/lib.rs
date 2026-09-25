// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Hardware-independent kernel logic. Everything here builds for the kernel
//! target and for the host, where `cargo test -p kcore` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod asid;
pub mod backtrace;
pub mod bootinfo;
pub mod esr;
pub mod fdt;
pub mod frames;
pub mod gic;
pub mod handles;
pub mod layout;
pub mod memmap;
pub mod notify;
pub mod paging;
pub mod process;
pub mod quota;
pub mod sched;
pub mod slab;
pub mod sync;
pub mod sysreg;
pub mod thread;
pub mod time;
pub mod timer;
pub mod tlb;
