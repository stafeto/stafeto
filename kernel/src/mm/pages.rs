// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pages for kernel object pools: frames from the allocator, reached
//! through the linear map. The pools of a payer take them through
//! kcore::slab::PaidPages and give them back with the payer's shell
//! (spec 7.8); the pool of processes with no parent keeps its pages.

use super::phys::FRAMES;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use kcore::layout::LINEAR_BASE;
use kcore::slab::PageSource;

pub struct KernelPages;

/// Pages the pools and page logs hold now.
static TAKEN: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every page is a frame just taken from the allocator, 4 KiB
// aligned and reached through the linear map; only `give_back` hands it
// back.
unsafe impl PageSource for KernelPages {
    fn alloc_page(&mut self) -> Option<NonNull<u8>> {
        let pa = FRAMES.lock().as_mut()?.alloc(0)?;
        TAKEN.fetch_add(1, Ordering::Relaxed);
        NonNull::new((LINEAR_BASE + pa as usize) as *mut u8)
    }
}

/// Gives a page of a payer's pools or page log back to the frame
/// allocator (the stage Shell). Test builds fill it with POISON first: a
/// use after the release reads the poison until the frame is taken again.
///
/// # Safety
/// `page` came from KernelPages, and nothing uses it afterwards.
pub unsafe fn give_back(page: NonNull<u8>) {
    #[cfg(feature = "ktest")]
    // SAFETY: the caller's promise: the page is the caller's to the end.
    unsafe {
        core::ptr::write_bytes(page.as_ptr(), POISON, kcore::PAGE_SIZE as usize)
    };
    let pa = (page.as_ptr() as usize - LINEAR_BASE) as u64;
    FRAMES.lock().as_mut().expect("frame allocator").free(pa, 0);
    TAKEN.fetch_sub(1, Ordering::Relaxed);
}

/// What test builds fill a page that went back with.
#[cfg(feature = "ktest")]
pub const POISON: u8 = 0xA5;

/// Pages the pools of kernel objects and the page logs of their payers
/// hold: KSTATS reports them (spec 11), and together with the free frames
/// they stay the same over the life of objects that give back all they
/// took, their payer's shell included.
pub fn taken() -> usize {
    TAKEN.load(Ordering::Relaxed)
}
