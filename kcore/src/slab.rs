// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pools of fixed-size kernel objects (spec 7.8): O(1) allocation and
//! release in pages the caller supplies; free slots form a list through
//! the slots themselves. Pages are never given back.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

pub const PAGE: usize = 4096;

/// Source of 4 KiB pages, as virtual addresses.
///
/// # Safety
/// `alloc_page` returns a pointer to PAGE bytes, aligned to PAGE, valid for
/// reads and writes, that nothing else uses from then on: a pool writes its
/// objects there and never gives the page back.
pub unsafe trait PageSource {
    fn alloc_page(&mut self) -> Option<NonNull<u8>>;
}

struct FreeSlot {
    next: Option<NonNull<FreeSlot>>,
}

pub struct Pool<T> {
    free: Option<NonNull<FreeSlot>>,
    in_use: usize,
    pages: usize,
    _objects: PhantomData<T>,
}

// SAFETY: a pool owns the objects in its slots.
unsafe impl<T: Send> Send for Pool<T> {}

impl<T> Pool<T> {
    const ALIGN: usize = if align_of::<T>() > align_of::<FreeSlot>() {
        align_of::<T>()
    } else {
        align_of::<FreeSlot>()
    };
    const SLOT: usize = {
        let size = if size_of::<T>() > size_of::<FreeSlot>() {
            size_of::<T>()
        } else {
            size_of::<FreeSlot>()
        };
        size.div_ceil(Self::ALIGN) * Self::ALIGN
    };
    /// Objects per page. Naming it for a type that does not fit a page
    /// fails the build:
    ///
    /// ```compile_fail,E0080
    /// assert_eq!(kcore::slab::Pool::<[u8; 5000]>::PER_PAGE, 0);
    /// ```
    pub const PER_PAGE: usize = {
        assert!(
            Self::SLOT <= PAGE && Self::ALIGN <= PAGE,
            "objects of this type do not fit a pool page"
        );
        PAGE / Self::SLOT
    };

    pub const fn new() -> Self {
        // Evaluating PER_PAGE checks that T fits a page.
        const { assert!(Self::PER_PAGE > 0) };
        Self {
            free: None,
            in_use: 0,
            pages: 0,
            _objects: PhantomData,
        }
    }

    pub fn in_use(&self) -> usize {
        self.in_use
    }

    pub fn pages(&self) -> usize {
        self.pages
    }

    /// Moves `value` into a free slot; gives it back when no page is left.
    pub fn alloc(&mut self, src: &mut impl PageSource, value: T) -> Result<NonNull<T>, T> {
        if self.free.is_none() {
            let Some(page) = src.alloc_page() else {
                return Err(value);
            };
            self.pages += 1;
            for i in (0..Self::PER_PAGE).rev() {
                // SAFETY: slot i lies inside the new page and is aligned for FreeSlot and T.
                unsafe {
                    let slot = page.as_ptr().add(i * Self::SLOT).cast::<FreeSlot>();
                    slot.write(FreeSlot { next: self.free });
                    self.free = Some(NonNull::new_unchecked(slot));
                }
            }
        }
        let slot = self.free.expect("a free slot after growing");
        // SAFETY: slot is a free slot of this pool, large and aligned enough for T.
        unsafe {
            self.free = slot.as_ref().next;
            let object = slot.cast::<T>();
            object.as_ptr().write(value);
            self.in_use += 1;
            Ok(object)
        }
    }

    /// Drops the object and returns its slot to the pool.
    ///
    /// # Safety
    /// `object` came from `alloc` of this pool and is not used afterwards.
    pub unsafe fn free(&mut self, object: NonNull<T>) {
        // SAFETY: the caller guarantees `object` is a live object of this pool.
        unsafe {
            object.as_ptr().drop_in_place();
            let slot = object.cast::<FreeSlot>();
            slot.as_ptr().write(FreeSlot { next: self.free });
            self.free = Some(slot);
        }
        self.in_use -= 1;
    }
}

impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    struct Pages {
        left: usize,
    }

    // SAFETY: each page is a fresh 4 KiB-aligned allocation, leaked on purpose.
    unsafe impl PageSource for Pages {
        fn alloc_page(&mut self) -> Option<NonNull<u8>> {
            if self.left == 0 {
                return None;
            }
            self.left -= 1;
            let layout = std::alloc::Layout::from_size_align(PAGE, PAGE).unwrap();
            // SAFETY: the layout has a non-zero size; the page is leaked on purpose.
            NonNull::new(unsafe { std::alloc::alloc(layout) })
        }
    }

    #[test]
    fn allocations_are_distinct_aligned_and_keep_values() {
        let mut src = Pages { left: 4 };
        let mut pool: Pool<u64> = Pool::new();
        let a = pool.alloc(&mut src, 1).unwrap();
        let b = pool.alloc(&mut src, 2).unwrap();
        assert_ne!(a, b);
        assert!((a.as_ptr() as usize).is_multiple_of(8));
        // SAFETY: both objects are live.
        unsafe { assert_eq!((*a.as_ptr(), *b.as_ptr()), (1, 2)) };
    }

    #[test]
    fn freed_slot_is_reused_first() {
        let mut src = Pages { left: 4 };
        let mut pool: Pool<u64> = Pool::new();
        let a = pool.alloc(&mut src, 1).unwrap();
        // SAFETY: a is live and not used afterwards.
        unsafe { pool.free(a) };
        assert_eq!(pool.alloc(&mut src, 2).unwrap(), a);
    }

    #[test]
    fn pool_grows_by_pages() {
        let mut src = Pages { left: 4 };
        let mut pool: Pool<[u64; 32]> = Pool::new();
        assert_eq!(Pool::<[u64; 32]>::PER_PAGE, 16);
        for i in 0..17 {
            pool.alloc(&mut src, [i; 32]).unwrap();
        }
        assert_eq!(pool.pages(), 2);
    }

    #[test]
    fn drop_runs_on_free() {
        struct Counted(Rc<Cell<usize>>);
        impl Drop for Counted {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Rc::new(Cell::new(0));
        let mut src = Pages { left: 1 };
        let mut pool: Pool<Counted> = Pool::new();
        let c = pool
            .alloc(&mut src, Counted(drops.clone()))
            .unwrap_or_else(|_| panic!("no page"));
        // SAFETY: c is live and not used afterwards.
        unsafe { pool.free(c) };
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn out_of_pages_returns_the_value() {
        let mut src = Pages { left: 0 };
        let mut pool: Pool<u64> = Pool::new();
        assert_eq!(pool.alloc(&mut src, 7), Err(7));
    }

    #[test]
    fn object_near_page_size_takes_a_page_each() {
        let mut src = Pages { left: 3 };
        let mut pool: Pool<[u8; 4000]> = Pool::new();
        assert_eq!(Pool::<[u8; 4000]>::PER_PAGE, 1);
        for _ in 0..3 {
            pool.alloc(&mut src, [0; 4000]).unwrap();
        }
        assert_eq!(pool.pages(), 3);
        assert!(pool.alloc(&mut src, [0; 4000]).is_err());
    }

    #[test]
    fn in_use_counts_live_objects() {
        let mut src = Pages { left: 1 };
        let mut pool: Pool<u64> = Pool::new();
        let a = pool.alloc(&mut src, 1).unwrap();
        pool.alloc(&mut src, 2).unwrap();
        // SAFETY: a is live and not used afterwards.
        unsafe { pool.free(a) };
        assert_eq!(pool.in_use(), 1);
    }

    #[test]
    fn small_objects_share_a_page() {
        assert_eq!(Pool::<u8>::PER_PAGE, 512);
        let mut src = Pages { left: 1 };
        let mut pool: Pool<u8> = Pool::new();
        for i in 0..512 {
            pool.alloc(&mut src, i as u8).unwrap();
        }
        assert_eq!(pool.pages(), 1);
    }
}
