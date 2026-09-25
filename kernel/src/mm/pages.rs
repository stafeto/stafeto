// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pages for kernel object pools: frames from the allocator, reached
//! through the linear map.

use super::phys::FRAMES;
use core::ptr::NonNull;
use kcore::layout::LINEAR_BASE;
use kcore::slab::PageSource;

#[cfg_attr(not(feature = "ktest"), allow(dead_code))]
pub struct KernelPages;

impl PageSource for KernelPages {
    fn alloc_page(&mut self) -> Option<NonNull<u8>> {
        let pa = FRAMES.lock().as_mut()?.alloc(0)?;
        NonNull::new((LINEAR_BASE + pa as usize) as *mut u8)
    }
}
