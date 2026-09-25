// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Physical page allocator (spec 7.1): a binary buddy system over 4 KiB
//! frames. Free blocks form doubly linked lists threaded through the free
//! memory itself; one byte per frame records whether that frame heads a
//! free block, an allocated block, or neither, and at what order, so a
//! buddy is found and unlinked in O(1) and a free of the wrong block is
//! caught.

pub const PAGE_SHIFT: u32 = 12;
pub const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;
/// The largest block holds 2^MAX_ORDER frames (4 MiB).
pub const MAX_ORDER: u8 = 10;
const ORDERS: usize = MAX_ORDER as usize + 1;
const NIL: u64 = u64::MAX;
/// Metadata byte of a frame that does not head a free block; a head of a
/// free block stores order + 1; a head of an allocated block stores
/// `ALLOCATED | order`, which never collides with either of those.
const NOT_FREE: u8 = 0;
const ALLOCATED: u8 = 0x80;

/// Word access to the physical memory the allocator manages.
///
/// # Safety
/// For every 8-byte-aligned physical address inside the frames handed to the
/// allocator, `write` stores the word there and `read` returns the last
/// word stored, and neither touches any other memory. The allocator keeps
/// its free lists in free frames through these calls: while a frame is free
/// it belongs to the allocator, and nothing else may use it.
pub unsafe trait PhysMem {
    fn read(&self, pa: u64) -> u64;
    fn write(&mut self, pa: u64, value: u64);
}

pub struct FrameAllocator<'m, M: PhysMem> {
    mem: M,
    base_pfn: u64,
    meta: &'m mut [u8],
    heads: [u64; ORDERS],
    free_frames: u64,
}

impl<'m, M: PhysMem> FrameAllocator<'m, M> {
    /// An allocator without free frames, for frames from `base` on; `meta`
    /// holds one byte per frame it may ever manage.
    pub fn new(mem: M, base: u64, meta: &'m mut [u8]) -> Self {
        assert!(
            base.is_multiple_of(PAGE_SIZE),
            "allocator base {base:#x} is not page-aligned"
        );
        meta.fill(NOT_FREE);
        Self {
            mem,
            base_pfn: base >> PAGE_SHIFT,
            meta,
            heads: [NIL; ORDERS],
            free_frames: 0,
        }
    }

    /// Metadata bytes for `span` bytes of physical addresses.
    pub fn meta_bytes(span: u64) -> usize {
        span.div_ceil(PAGE_SIZE) as usize
    }

    pub fn free_frames(&self) -> u64 {
        self.free_frames
    }

    /// Hands every whole frame of `[base, end)` to the allocator; none of
    /// them may be free or allocated already.
    pub fn add_region(&mut self, base: u64, end: u64) {
        let first = base.div_ceil(PAGE_SIZE);
        let last = end >> PAGE_SHIFT;
        if first >= last {
            return;
        }
        assert!(
            first >= self.base_pfn && last <= self.base_pfn + self.meta.len() as u64,
            "region {base:#x}..{end:#x} outside the allocator's span"
        );
        let mut pfn = first;
        while pfn < last {
            let mut order = MAX_ORDER;
            while order > 0 && (!pfn.is_multiple_of(1 << order) || pfn + (1 << order) > last) {
                order -= 1;
            }
            assert!(
                !self.overlaps_a_block(pfn, order),
                "region {base:#x}..{end:#x} overlaps frames already added"
            );
            self.free_block(pfn, order);
            pfn += 1 << order;
        }
    }

    /// A block of 2^order frames, aligned to its size; None when none is left.
    pub fn alloc(&mut self, order: u8) -> Option<u64> {
        if order > MAX_ORDER {
            return None;
        }
        let mut o = order;
        while self.heads[o as usize] == NIL {
            if o == MAX_ORDER {
                return None;
            }
            o += 1;
        }
        let pfn = self.heads[o as usize];
        self.unlink(pfn, o);
        while o > order {
            o -= 1;
            self.push(pfn + (1 << o), o);
        }
        self.set_meta(pfn, ALLOCATED | order);
        self.free_frames -= 1 << order;
        Some(pfn << PAGE_SHIFT)
    }

    /// Returns a block from `alloc(order)`.
    pub fn free(&mut self, pa: u64, order: u8) {
        assert!(
            order <= MAX_ORDER,
            "free of order {order} above {MAX_ORDER}"
        );
        assert!(
            pa.is_multiple_of(PAGE_SIZE << order),
            "free of misaligned block {pa:#x}"
        );
        let pfn = pa >> PAGE_SHIFT;
        assert!(
            self.in_range(pfn, order),
            "free of {pa:#x} outside the allocator"
        );
        if self.meta_at(pfn) != (ALLOCATED | order) {
            assert!(!self.in_free_block(pfn), "double free of frame {pa:#x}");
            panic!("free of frame {pa:#x} that was not allocated with order {order}");
        }
        self.set_meta(pfn, NOT_FREE);
        self.free_block(pfn, order);
    }

    fn free_block(&mut self, pfn: u64, order: u8) {
        assert!(
            !self.in_free_block(pfn),
            "double free of frame {:#x}",
            pfn << PAGE_SHIFT
        );
        self.free_frames += 1 << order;
        let (mut pfn, mut order) = (pfn, order);
        while order < MAX_ORDER {
            let buddy = pfn ^ (1 << order);
            if !self.in_range(buddy, order) || self.meta_at(buddy) != order + 1 {
                break;
            }
            self.unlink(buddy, order);
            pfn = pfn.min(buddy);
            order += 1;
        }
        self.push(pfn, order);
    }

    /// True when a free block covers frame `pfn`. A free block of order o
    /// starts at `pfn` rounded down to 2^o frames, so MAX_ORDER + 1 lookups
    /// cover every case, including a frame already merged into a larger block.
    fn in_free_block(&self, pfn: u64) -> bool {
        (0..=MAX_ORDER).any(|o| {
            let head = pfn & !((1u64 << o) - 1);
            head >= self.base_pfn && self.meta_at(head) == o + 1
        })
    }

    /// True when a free or allocated block shares a frame with the aligned
    /// block of 2^order frames at `pfn`. Blocks are aligned to their size, so
    /// such a block either covers `pfn` or starts inside the range.
    fn overlaps_a_block(&self, pfn: u64, order: u8) -> bool {
        let covers_pfn = (0..=MAX_ORDER).any(|o| {
            let head = pfn & !((1u64 << o) - 1);
            head >= self.base_pfn && {
                let m = self.meta_at(head);
                m == o + 1 || m == (ALLOCATED | o)
            }
        });
        let start = (pfn - self.base_pfn) as usize;
        covers_pfn
            || self.meta[start..start + (1 << order)]
                .iter()
                .any(|&m| m != NOT_FREE)
    }

    fn in_range(&self, pfn: u64, order: u8) -> bool {
        pfn >= self.base_pfn && pfn + (1 << order) <= self.base_pfn + self.meta.len() as u64
    }

    fn meta_at(&self, pfn: u64) -> u8 {
        self.meta[(pfn - self.base_pfn) as usize]
    }

    fn set_meta(&mut self, pfn: u64, value: u8) {
        self.meta[(pfn - self.base_pfn) as usize] = value;
    }

    // A free block starts with its list links: the next block's frame number
    // at offset 0, the previous one's at offset 8.
    fn push(&mut self, pfn: u64, order: u8) {
        let head = self.heads[order as usize];
        self.mem.write(pfn << PAGE_SHIFT, head);
        self.mem.write((pfn << PAGE_SHIFT) + 8, NIL);
        if head != NIL {
            self.mem.write((head << PAGE_SHIFT) + 8, pfn);
        }
        self.heads[order as usize] = pfn;
        self.set_meta(pfn, order + 1);
    }

    fn unlink(&mut self, pfn: u64, order: u8) {
        let next = self.mem.read(pfn << PAGE_SHIFT);
        let prev = self.mem.read((pfn << PAGE_SHIFT) + 8);
        if prev == NIL {
            self.heads[order as usize] = next;
        } else {
            self.mem.write(prev << PAGE_SHIFT, next);
        }
        if next != NIL {
            self.mem.write((next << PAGE_SHIFT) + 8, prev);
        }
        self.set_meta(pfn, NOT_FREE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Mem(HashMap<u64, u64>);

    // SAFETY: a map of words; `read` returns the last `write`.
    unsafe impl PhysMem for Mem {
        fn read(&self, pa: u64) -> u64 {
            *self.0.get(&pa).unwrap_or(&0)
        }
        fn write(&mut self, pa: u64, value: u64) {
            self.0.insert(pa, value);
        }
    }

    const BASE: u64 = 0x4000_0000;
    const FRAMES: usize = 4096; // 16 MiB

    fn allocator(meta: &mut [u8]) -> FrameAllocator<'_, Mem> {
        FrameAllocator::new(Mem::default(), BASE, meta)
    }

    fn full(meta: &mut [u8]) -> FrameAllocator<'_, Mem> {
        let mut a = allocator(meta);
        a.add_region(BASE, BASE + FRAMES as u64 * PAGE_SIZE);
        a
    }

    #[test]
    fn meta_bytes_is_one_per_frame() {
        assert_eq!(FrameAllocator::<Mem>::meta_bytes(16 << 20), 4096);
        assert_eq!(FrameAllocator::<Mem>::meta_bytes(4097), 2);
    }

    #[test]
    fn adding_a_region_counts_its_frames() {
        let mut meta = vec![0; FRAMES];
        assert_eq!(full(&mut meta).free_frames(), FRAMES as u64);
    }

    #[test]
    fn allocations_are_aligned_distinct_and_inside() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let mut seen = Vec::new();
        for order in [0u8, 3, 9, 0, 3] {
            let pa = a.alloc(order).unwrap();
            assert!(pa.is_multiple_of(PAGE_SIZE << order));
            assert!(pa >= BASE && pa + (PAGE_SIZE << order) <= BASE + (FRAMES as u64) * PAGE_SIZE);
            assert!(!seen.contains(&pa));
            seen.push(pa);
        }
    }

    #[test]
    fn freeing_coalesces_back_to_the_largest_blocks() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let pa = a.alloc(0).unwrap();
        a.free(pa, 0);
        for _ in 0..4 {
            assert!(a.alloc(MAX_ORDER).is_some());
        }
        assert_eq!(a.free_frames(), 0);
    }

    #[test]
    fn exhaustion_returns_none_and_recovers_after_free() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let all: Vec<u64> = std::iter::from_fn(|| a.alloc(0)).collect();
        assert_eq!(all.len(), FRAMES);
        assert_eq!(a.alloc(0), None);
        for pa in all {
            a.free(pa, 0);
        }
        assert_eq!(a.free_frames(), FRAMES as u64);
        assert!(a.alloc(MAX_ORDER).is_some());
    }

    #[test]
    fn unaligned_region_edges_are_handled() {
        let mut meta = vec![0; FRAMES];
        let mut a = allocator(&mut meta);
        a.add_region(BASE + 0x800, BASE + 3 * PAGE_SIZE + 100);
        assert_eq!(a.free_frames(), 2);
        let mut got = [a.alloc(0).unwrap(), a.alloc(0).unwrap()];
        got.sort();
        assert_eq!(got, [BASE + PAGE_SIZE, BASE + 2 * PAGE_SIZE]);
        assert_eq!(a.alloc(0), None);
    }

    #[test]
    fn holes_between_regions_are_never_handed_out() {
        let mut meta = vec![0; FRAMES];
        let mut a = allocator(&mut meta);
        a.add_region(BASE, BASE + (1 << 20));
        a.add_region(BASE + (2 << 20), BASE + (3 << 20));
        while let Some(pa) = a.alloc(0) {
            assert!(!(BASE + (1 << 20)..BASE + (2 << 20)).contains(&pa));
        }
    }

    #[test]
    fn order_above_max_is_refused() {
        let mut meta = vec![0; FRAMES];
        assert_eq!(full(&mut meta).alloc(MAX_ORDER + 1), None);
    }

    #[test]
    fn random_workload_keeps_blocks_disjoint_and_counts_exact() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let mut held: Vec<(u64, u8)> = Vec::new();
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..3000 {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let r = x >> 33;
            if !r.is_multiple_of(3) || held.is_empty() {
                let order = (r % 5) as u8;
                if let Some(pa) = a.alloc(order) {
                    let end = pa + (PAGE_SIZE << order);
                    for &(p, o) in &held {
                        assert!(end <= p || pa >= p + (PAGE_SIZE << o), "overlapping blocks");
                    }
                    held.push((pa, order));
                }
            } else {
                let (pa, order) = held.swap_remove((r as usize / 3) % held.len());
                a.free(pa, order);
            }
            let used: u64 = held.iter().map(|&(_, o)| 1u64 << o).sum();
            assert_eq!(a.free_frames() + used, FRAMES as u64);
        }
        for (pa, order) in held {
            a.free(pa, order);
        }
        for _ in 0..4 {
            assert!(a.alloc(MAX_ORDER).is_some());
        }
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_panics() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let pa = a.alloc(0).unwrap();
        a.free(pa, 0);
        a.free(pa, 0);
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_of_a_merged_frame_panics() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let first = a.alloc(0).unwrap();
        let second = a.alloc(0).unwrap();
        a.free(second, 0);
        a.free(first, 0);
        a.free(second, 0);
    }

    #[test]
    #[should_panic(expected = "outside the allocator")]
    fn free_outside_the_allocator_panics() {
        let mut meta = vec![0; FRAMES];
        full(&mut meta).free(0x1000, 0);
    }

    #[test]
    #[should_panic(expected = "not allocated")]
    fn freeing_an_interior_frame_of_a_live_block_panics() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let big = a.alloc(9).unwrap();
        a.free(big + PAGE_SIZE, 0);
    }

    #[test]
    #[should_panic(expected = "not allocated")]
    fn freeing_with_a_larger_order_panics() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        // Two order-0 allocations from a freshly built allocator come out in
        // increasing address order, so the first one is 2-frame aligned.
        let x = a.alloc(0).unwrap();
        assert!(x.is_multiple_of(2 * PAGE_SIZE));
        a.free(x, 1);
    }

    #[test]
    #[should_panic(expected = "not allocated")]
    fn freeing_a_frame_in_a_hole_panics() {
        let mut meta = vec![0; FRAMES];
        let mut a = allocator(&mut meta);
        a.add_region(BASE, BASE + (1 << 20));
        a.add_region(BASE + (2 << 20), BASE + (3 << 20));
        a.free(BASE + (1 << 20), 0);
    }

    #[test]
    #[should_panic(expected = "misaligned")]
    fn freeing_a_misaligned_block_panics() {
        let mut meta = vec![0; FRAMES];
        full(&mut meta).free(BASE + PAGE_SIZE, 1);
    }

    #[test]
    #[should_panic(expected = "above")]
    fn freeing_an_order_above_max_panics() {
        let mut meta = vec![0; FRAMES];
        full(&mut meta).free(BASE, MAX_ORDER + 1);
    }

    #[test]
    #[should_panic(expected = "outside the allocator's span")]
    fn adding_a_region_past_the_span_panics() {
        let mut meta = vec![0; FRAMES];
        let end = BASE + FRAMES as u64 * PAGE_SIZE;
        allocator(&mut meta).add_region(end - PAGE_SIZE, end + PAGE_SIZE);
    }

    #[test]
    #[should_panic(expected = "outside the allocator's span")]
    fn adding_a_region_below_the_span_panics() {
        let mut meta = vec![0; FRAMES];
        allocator(&mut meta).add_region(BASE - PAGE_SIZE, BASE + PAGE_SIZE);
    }

    #[test]
    #[should_panic(expected = "already added")]
    fn adding_a_region_twice_panics() {
        let mut meta = vec![0; FRAMES];
        full(&mut meta).add_region(BASE, BASE + PAGE_SIZE);
    }

    #[test]
    #[should_panic(expected = "already added")]
    fn adding_a_region_over_a_smaller_free_one_panics() {
        // The second frame is free, the first is not: a check of the block's
        // first frame alone misses it.
        let mut meta = vec![0; FRAMES];
        let mut a = allocator(&mut meta);
        a.add_region(BASE + PAGE_SIZE, BASE + 2 * PAGE_SIZE);
        a.add_region(BASE, BASE + 2 * PAGE_SIZE);
    }

    #[test]
    #[should_panic(expected = "already added")]
    fn adding_a_region_over_an_allocated_block_panics() {
        let mut meta = vec![0; FRAMES];
        let mut a = full(&mut meta);
        let pa = a.alloc(0).unwrap();
        a.add_region(pa, pa + PAGE_SIZE);
    }
}
