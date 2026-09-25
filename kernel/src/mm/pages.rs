// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pages for kernel object pools: frames from the allocator, reached
//! through the linear map. Pools never give a page back (spec 7.8), so the
//! count of pages taken only grows.

use super::phys::FRAMES;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use kcore::layout::LINEAR_BASE;
use kcore::slab::PageSource;

pub struct KernelPages;

/// Pages the pools took from the frame allocator.
static TAKEN: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every page is a frame just taken from the allocator, 4 KiB
// aligned, reached through the linear map, and never handed out again.
unsafe impl PageSource for KernelPages {
    fn alloc_page(&mut self) -> Option<NonNull<u8>> {
        let pa = FRAMES.lock().as_mut()?.alloc(0)?;
        TAKEN.fetch_add(1, Ordering::Relaxed);
        NonNull::new((LINEAR_BASE + pa as usize) as *mut u8)
    }
}

/// Pages the pools of kernel objects hold: KSTATS reports them (spec 11),
/// and together with the free frames they stay the same over the life of
/// objects that give back all they took.
pub fn taken() -> usize {
    TAKEN.load(Ordering::Relaxed)
}
