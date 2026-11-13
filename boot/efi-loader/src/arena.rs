// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loader's heap: a bump allocator over a block in the image's `.bss`.
//! It never frees, and it works the same after `ExitBootServices`, which
//! the firmware's pool allocator does not: the final tree is built from the
//! final memory map when no firmware service is left (the note, 2.2).

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

const SIZE: usize = 4 << 20;

#[repr(align(4096))]
struct Block(UnsafeCell<[u8; SIZE]>);

// SAFETY: the loader runs on one CPU; the offsets below are claimed with an
// atomic exchange and no two allocations overlap.
unsafe impl Sync for Block {}

pub struct Bump {
    block: Block,
    used: AtomicUsize,
}

impl Bump {
    pub const fn new() -> Self {
        Self {
            block: Block(UnsafeCell::new([0; SIZE])),
            used: AtomicUsize::new(0),
        }
    }
}

// SAFETY: `alloc` returns disjoint, aligned ranges of the block or null.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = self.block.0.get() as usize;
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let start = (base + used).next_multiple_of(layout.align()) - base;
            let end = start + layout.size();
            if end > SIZE {
                return core::ptr::null_mut();
            }
            match self
                .used
                .compare_exchange(used, end, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return (base + start) as *mut u8,
                Err(now) => used = now,
            }
        }
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}
