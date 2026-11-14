// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Hardware-independent kernel logic. Everything here builds for the kernel
//! target and for the host, where `cargo test -p kcore` exercises it.

#![cfg_attr(not(test), no_std)]

/// Pages of 4 KiB (spec 7.1, 7.2): frames, translation tables, pools and
/// quotas all count in them. The constants live in `kboot`, whose memory map
/// counts in pages too.
pub use kboot::{PAGE_SHIFT, PAGE_SIZE};

#[macro_use]
pub mod must;
pub mod args;
pub mod asid;
pub mod backtrace;
pub mod budget;
pub mod console;
pub mod esr;
pub mod frames;
pub mod gic;
pub mod handles;
pub mod idlepoll;
pub mod its;
pub mod layout;
pub mod log;
pub mod maps;
pub mod notify;
pub mod pagelist;
pub mod paging;
pub mod process;
pub mod qsbr;
pub mod quota;
pub mod sched;
pub mod slab;
pub mod stamps;
pub mod sync;
pub mod sysreg;
pub mod time;
pub mod timer;
pub mod tlb;
pub mod token;
pub mod upcall;
pub mod window;
