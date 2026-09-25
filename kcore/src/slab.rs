// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pools of fixed-size kernel objects (spec 7.8): O(1) allocation and
//! release in pages the caller supplies; free slots form a list through
//! the slots themselves. A pool never gives a page back by itself. The
//! pools of a payer take their pages through `PaidPages`, which charges
//! each page to the payer's quota and writes it down in the payer's
//! `PageLog`; the pages go back when the payer's shell goes.

use crate::quota::Account;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

pub const PAGE: usize = 4096;

/// Source of 4 KiB pages, as virtual addresses.
///
/// # Safety
/// `alloc_page` returns a pointer to PAGE bytes, aligned to PAGE, valid for
/// reads and writes, that nothing else uses until the one who took it
/// gives it back: a pool writes its objects there, and only a page log
/// gives its pages back.
pub unsafe trait PageSource {
    fn alloc_page(&mut self) -> Option<NonNull<u8>>;
}

// SAFETY: the pages are those of the source borrowed.
unsafe impl<S: PageSource> PageSource for &mut S {
    fn alloc_page(&mut self) -> Option<NonNull<u8>> {
        (**self).alloc_page()
    }
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
    /// Bytes one object takes in a page: its size, at least a free slot's
    /// link, rounded up to the alignment.
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

    /// Makes sure the next `alloc` takes no page: takes one from `src` now
    /// unless a slot is free. False when `src` has none.
    pub fn reserve(&mut self, src: &mut impl PageSource) -> bool {
        if self.free.is_some() {
            return true;
        }
        let Some(page) = src.alloc_page() else {
            return false;
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
        true
    }

    /// Moves `value` into a free slot; gives it back when no page is left.
    pub fn alloc(&mut self, src: &mut impl PageSource, value: T) -> Result<NonNull<T>, T> {
        if !self.reserve(src) {
            return Err(value);
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

/// Addresses a page log keeps in itself; the rest go to list pages.
pub const INLINE_PAGES: usize = 8;
/// Addresses one list page holds, besides the link to the one before.
pub const LIST_ENTRIES: usize = PAGE / size_of::<usize>() - 1;

/// A page of a page log: addresses of pool pages, and the list page
/// written before it.
#[repr(C)]
struct ListPage {
    entries: [Option<NonNull<u8>>; LIST_ENTRIES],
    next: Option<NonNull<ListPage>>,
}

const _: () = assert!(size_of::<ListPage>() == PAGE);

/// The pages the pools of one payer took (spec 7.8), and the list pages
/// that name them: the first INLINE_PAGES addresses in the log itself,
/// the rest in list pages of LIST_ENTRIES addresses each, newest first,
/// which the payer pays for as well. The pages go back only when the
/// payer's shell goes, `release_step` a portion at a time, with how far
/// it came kept in the log: an object freed earlier leaves its slot in the
/// pool for the next object of its kind.
pub struct PageLog {
    inline: [Option<NonNull<u8>>; INLINE_PAGES],
    /// The newest list page, which links to the one before it.
    list: Option<NonNull<ListPage>>,
    /// Pool pages written down.
    pages: usize,
    /// List pages.
    list_pages: usize,
}

impl PageLog {
    /// A log with no page.
    pub const fn new() -> PageLog {
        PageLog {
            inline: [None; INLINE_PAGES],
            list: None,
            pages: 0,
            list_pages: 0,
        }
    }

    /// Pool pages written down, list pages not counted.
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// List pages.
    pub fn list_pages(&self) -> usize {
        self.list_pages
    }

    /// Whether the address of the next page needs a new list page.
    fn needs_list_page(&self) -> bool {
        self.pages >= INLINE_PAGES && self.pages - INLINE_PAGES == self.list_pages * LIST_ENTRIES
    }

    /// Addresses in the newest list page.
    fn in_list(&self) -> usize {
        self.pages.saturating_sub(INLINE_PAGES) - (self.list_pages - 1) * LIST_ENTRIES
    }

    /// Makes `page` the newest list page.
    ///
    /// # Safety
    /// `page` is PAGE bytes, aligned to PAGE, that nothing else uses until
    /// the log gives it back.
    unsafe fn add_list_page(&mut self, page: NonNull<u8>) {
        let list = page.cast::<ListPage>();
        // SAFETY: the caller's promise; only the link is written, and each
        // entry before it is read.
        unsafe { (&raw mut (*list.as_ptr()).next).write(self.list) };
        self.list = Some(list);
        self.list_pages += 1;
    }

    /// Writes `page` down; a list page is there when one is needed.
    fn record(&mut self, page: NonNull<u8>) {
        if self.pages < INLINE_PAGES {
            self.inline[self.pages] = Some(page);
        } else {
            let list = self.list.expect("a list page for the address");
            let i = self.in_list();
            // SAFETY: the list page is the log's, and entry i lies in it.
            unsafe { (&raw mut (*list.as_ptr()).entries[i]).write(Some(page)) };
        }
        self.pages += 1;
    }

    /// Takes the newest page off the log: a pool page, or a list page once
    /// the addresses in it went. None once the log is empty.
    fn pop(&mut self) -> Option<NonNull<u8>> {
        if let Some(list) = self.list {
            let i = self.in_list();
            // SAFETY: the list page is the log's; its first i entries are
            // written.
            unsafe {
                if i == 0 {
                    self.list = (*list.as_ptr()).next;
                    self.list_pages -= 1;
                    return Some(list.cast());
                }
                self.pages -= 1;
                return (*list.as_ptr()).entries[i - 1];
            }
        }
        self.pages = self.pages.checked_sub(1)?;
        self.inline[self.pages].take()
    }

    /// Gives back up to `n` pages through `free`, newest first: pool pages,
    /// and each list page once the addresses in it went. True once none is
    /// left. A step takes O(n).
    pub fn release_step(&mut self, n: usize, mut free: impl FnMut(NonNull<u8>)) -> bool {
        for _ in 0..n {
            let Some(page) = self.pop() else {
                return true;
            };
            free(page);
        }
        self.pages == 0 && self.list.is_none()
    }
}

impl Default for PageLog {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PageLog {
    fn drop(&mut self) {
        // Only a check: the pages go back through `release_step`, which the
        // payer's last portion runs to the end (spec 7.8). A host test that
        // failed midway reports its own panic instead.
        #[cfg(test)]
        if std::thread::panicking() {
            return;
        }
        assert!(
            self.pages == 0 && self.list.is_none(),
            "pool pages dropped without their release"
        );
    }
}

/// Pages a payer pays for (spec 7.5, 7.8): each costs its quota PAGE bytes
/// before `frames` gives it, and goes into its page log, a list page first
/// when the log needs one. A page is charged once, when a pool grows, and
/// refunded when the log gives it back; slots cost nothing. A charge that
/// passed always finds a frame: every frame taken after boot is charged to
/// someone, and the quotas add up to the frames free at boot, so a source
/// that fails after a charge stops the kernel, as a count that does not
/// add up does (Account::return_rest).
pub struct PaidPages<'a, F: PageSource> {
    frames: F,
    quota: &'a mut Account,
    log: &'a mut PageLog,
}

impl<'a, F: PageSource> PaidPages<'a, F> {
    /// Pages from `frames`, charged to `quota` and written down in `log`.
    pub fn new(frames: F, quota: &'a mut Account, log: &'a mut PageLog) -> PaidPages<'a, F> {
        PaidPages { frames, quota, log }
    }

    /// A frame charged to the quota; None when the quota falls short.
    fn take(&mut self) -> Option<NonNull<u8>> {
        self.quota.charge(PAGE as u64).ok()?;
        let page = self.frames.alloc_page();
        Some(page.expect("a charge that passed found no frame (spec 7.8)"))
    }
}

// SAFETY: the pages come from `frames`, which keeps the contract; the log
// only writes their addresses down, and a list page is the log's alone.
unsafe impl<F: PageSource> PageSource for PaidPages<'_, F> {
    fn alloc_page(&mut self) -> Option<NonNull<u8>> {
        if self.log.needs_list_page() {
            let list = self.take()?;
            // SAFETY: a fresh page that nothing else uses.
            unsafe { self.log.add_list_page(list) };
        }
        let page = self.take()?;
        self.log.record(page);
        Some(page)
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
    fn slot_is_the_size_rounded_to_the_alignment() {
        // At least the link of a free slot, 8 bytes.
        assert_eq!(Pool::<u8>::SLOT, 8);
        assert_eq!(Pool::<[u32; 3]>::SLOT, 16);
        assert_eq!(Pool::<[u8; 4000]>::SLOT, 4000);
        assert_eq!(Pool::<[u64; 32]>::SLOT * Pool::<[u64; 32]>::PER_PAGE, PAGE);
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

    #[test]
    fn reserve_takes_a_page_only_when_no_slot_is_free() {
        let mut src = Pages { left: 1 };
        let mut pool: Pool<[u64; 32]> = Pool::new();
        assert!(pool.reserve(&mut src));
        assert_eq!((pool.pages(), src.left), (1, 0));
        // The page is there: neither the reserve nor the allocation takes
        // another from a source that has none.
        assert!(pool.reserve(&mut src));
        pool.alloc(&mut src, [7; 32]).unwrap();
        assert_eq!(pool.pages(), 1);
        let mut full: Pool<[u8; 4000]> = Pool::new();
        assert!(!full.reserve(&mut src));
    }

    const KIB: u64 = 1024;

    /// Frames for the paid pools: fresh pages from the host allocator, each
    /// remembered, and taken back one by one.
    struct Frames {
        given: Vec<usize>,
        left: usize,
    }

    impl Frames {
        fn new(left: usize) -> Frames {
            Frames {
                given: Vec::new(),
                left,
            }
        }
    }

    // SAFETY: each page is a fresh 4 KiB-aligned allocation that only
    // `give_back` frees.
    unsafe impl PageSource for Frames {
        fn alloc_page(&mut self) -> Option<NonNull<u8>> {
            let mut pages = Pages { left: self.left };
            let page = pages.alloc_page()?;
            self.left = pages.left;
            self.given.push(page.as_ptr() as usize);
            Some(page)
        }
    }

    fn give_back(page: NonNull<u8>) {
        let layout = std::alloc::Layout::from_size_align(PAGE, PAGE).unwrap();
        // SAFETY: the page came from the host allocator with this layout.
        unsafe { std::alloc::dealloc(page.as_ptr(), layout) };
    }

    /// Gives every page of `log` back, each refunded to `quota`, and
    /// returns them in the order they went.
    fn release(log: &mut PageLog, quota: &mut Account) -> Vec<usize> {
        let mut back = Vec::new();
        let done = log.release_step(usize::MAX, |page| {
            back.push(page.as_ptr() as usize);
            quota.refund(PAGE as u64);
            give_back(page);
        });
        assert!(done);
        back
    }

    #[test]
    fn growth_charges_a_whole_page() {
        let mut frames = Frames::new(4);
        let mut quota = Account::new(64 * KIB);
        let mut log = PageLog::new();
        let mut pool: Pool<u64> = Pool::new();
        pool.alloc(&mut PaidPages::new(&mut frames, &mut quota, &mut log), 1)
            .unwrap();
        assert_eq!(quota.used(), PAGE as u64);
        assert_eq!((log.pages(), log.list_pages(), pool.pages()), (1, 0, 1));
        // Short of a page, the pool does not grow: nothing is charged, and
        // no frame is taken.
        let mut short = Account::new(PAGE as u64 - 1);
        let mut other_log = PageLog::new();
        let mut other: Pool<u64> = Pool::new();
        let paid = &mut PaidPages::new(&mut frames, &mut short, &mut other_log);
        assert_eq!(other.alloc(paid, 2), Err(2));
        assert_eq!(
            (short.used(), other_log.pages(), frames.given.len()),
            (0, 0, 1)
        );
        assert_eq!(release(&mut log, &mut quota), frames.given);
        assert_eq!(quota.used(), 0);
    }

    #[test]
    fn slots_in_a_paid_page_cost_nothing() {
        let mut frames = Frames::new(4);
        let mut quota = Account::new(64 * KIB);
        let mut log = PageLog::new();
        let mut pool: Pool<[u64; 32]> = Pool::new();
        for i in 0..Pool::<[u64; 32]>::PER_PAGE {
            let paid = &mut PaidPages::new(&mut frames, &mut quota, &mut log);
            pool.alloc(paid, [i as u64; 32]).unwrap();
            assert_eq!(quota.used(), PAGE as u64);
        }
        let paid = &mut PaidPages::new(&mut frames, &mut quota, &mut log);
        pool.alloc(paid, [0; 32]).unwrap();
        assert_eq!((quota.used(), log.pages()), (2 * PAGE as u64, 2));
        release(&mut log, &mut quota);
    }

    #[test]
    fn freeing_a_slot_refunds_nothing() {
        let mut frames = Frames::new(4);
        let mut quota = Account::new(64 * KIB);
        let mut log = PageLog::new();
        let mut pool: Pool<u64> = Pool::new();
        let paid = &mut PaidPages::new(&mut frames, &mut quota, &mut log);
        let a = pool.alloc(paid, 1).unwrap();
        pool.alloc(paid, 2).unwrap();
        // SAFETY: a is live and not used afterwards.
        unsafe { pool.free(a) };
        assert_eq!(quota.used(), PAGE as u64);
        // The slot is there for the next object of the kind, at no cost.
        let paid = &mut PaidPages::new(&mut frames, &mut quota, &mut log);
        assert_eq!(pool.alloc(paid, 3).unwrap(), a);
        assert_eq!((quota.used(), log.pages()), (PAGE as u64, 1));
        release(&mut log, &mut quota);
    }

    #[test]
    fn every_page_goes_back_once() {
        let pool_pages = INLINE_PAGES + LIST_ENTRIES + 5;
        let mut frames = Frames::new(pool_pages + 2);
        let mut quota = Account::new(1 << 30);
        let mut log = PageLog::new();
        let mut pool: Pool<[u8; 4000]> = Pool::new();
        for _ in 0..pool_pages {
            let paid = &mut PaidPages::new(&mut frames, &mut quota, &mut log);
            pool.alloc(paid, [0; 4000]).unwrap();
        }
        assert_eq!((log.pages(), log.list_pages()), (pool_pages, 2));
        // Steps of 64 give back every page, list pages included, in just
        // as many steps as that takes.
        let mut back = Vec::new();
        let mut done = false;
        for _ in 0..(pool_pages + 2).div_ceil(64) {
            let before = back.len();
            done = log.release_step(64, |page| back.push(page.as_ptr() as usize));
            assert!(back.len() - before <= 64);
        }
        back.sort_unstable();
        let mut given = frames.given.clone();
        given.sort_unstable();
        assert_eq!(back, given, "a page went back twice, or not at all");
        assert!(done && log.pages() == 0 && log.list_pages() == 0);
        // Nothing is left for another step.
        assert!(log.release_step(64, |_| panic!("a page went back twice")));
        for page in given {
            quota.refund(PAGE as u64);
            give_back(NonNull::new(page as *mut u8).unwrap());
        }
        assert_eq!(quota.used(), 0);
    }

    #[test]
    fn list_pages_are_charged_too() {
        let mut frames = Frames::new(2 * INLINE_PAGES + LIST_ENTRIES + 4);
        let mut quota = Account::new(1 << 30);
        let mut log = PageLog::new();
        let mut pool: Pool<[u8; 4000]> = Pool::new();
        // Whether the pool grew by a page.
        let mut grow = |quota: &mut Account, log: &mut PageLog| {
            let paid = &mut PaidPages::new(&mut frames, quota, log);
            pool.alloc(paid, [0; 4000]).is_ok()
        };
        for _ in 0..INLINE_PAGES {
            assert!(grow(&mut quota, &mut log));
        }
        assert_eq!(
            (quota.used(), log.list_pages()),
            (INLINE_PAGES as u64 * 4 * KIB, 0)
        );
        // The next address needs a list page, which the payer pays for too.
        assert!(grow(&mut quota, &mut log));
        assert_eq!(quota.used(), (INLINE_PAGES as u64 + 2) * 4 * KIB);
        assert_eq!((log.pages(), log.list_pages()), (INLINE_PAGES + 1, 1));
        for _ in 1..LIST_ENTRIES {
            assert!(grow(&mut quota, &mut log));
        }
        assert_eq!(log.list_pages(), 1);
        assert!(grow(&mut quota, &mut log));
        assert_eq!(log.list_pages(), 2);
        release(&mut log, &mut quota);
        // A quota with room for the list page and not the page it lists:
        // the list page stays paid and written down until the release.
        let mut tight = Account::new((INLINE_PAGES as u64 + 1) * 4 * KIB);
        for _ in 0..INLINE_PAGES {
            assert!(grow(&mut tight, &mut log));
        }
        assert!(!grow(&mut tight, &mut log));
        assert_eq!(
            (tight.used(), log.pages(), log.list_pages()),
            (tight.limit(), INLINE_PAGES, 1)
        );
        release(&mut log, &mut tight);
        assert_eq!(tight.used(), 0);
    }

    #[test]
    #[should_panic(expected = "a charge that passed found no frame")]
    fn charged_page_without_a_frame_stops() {
        let mut frames = Frames::new(0);
        let mut quota = Account::new(64 * KIB);
        let mut log = PageLog::new();
        let mut pool: Pool<u64> = Pool::new();
        let _ = pool.alloc(&mut PaidPages::new(&mut frames, &mut quota, &mut log), 1);
    }
}
