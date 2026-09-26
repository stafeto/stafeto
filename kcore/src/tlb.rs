// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The order of TTBR0 writes, barriers and TLB maintenance around address
//! spaces (spec 7.2, 7.4). QEMU drops its whole TLB whenever the ASID in TTBR0
//! changes, and its table walker sees every store at once, so it shows no
//! missing step here; the tests run the same order against a TLB that
//! caches whatever the tables in TTBR0 map, at any moment, and a walker
//! that may still read a cleared descriptor until a barrier.

use crate::asid::{AsidAllocator, AsidTag, tlbi_asid, tlbi_page, ttbr0};
use crate::paging::TTBR_ROOT_MASK;

/// TTBR0 and the TLB of this CPU; the kernel implements them with MSR and
/// TLBI and the barriers of the Arm template.
pub trait Mmu {
    fn ttbr0(&self) -> u64;
    /// `msr ttbr0_el1; isb`
    fn set_ttbr0(&mut self, ttbr: u64);
    /// `dsb nshst; tlbi vmalle1; dsb nsh; isb`: every EL1&0 entry of this
    /// CPU, after earlier table stores reach its walker.
    fn flush_all(&mut self);
    /// `dsb ishst; tlbi aside1is; dsb ish`, walk-cache entries included;
    /// `operand` from `tlbi_asid`.
    fn invalidate_asid(&mut self, operand: u64);
    /// `dsb ishst` with no `isb`: earlier table stores reach the table
    /// walker (spec 7.4; [G13], [G14], [G15]).
    fn tables_written(&mut self);
    /// `tlbi vale1is` alone, for a page of a program; `operand` from
    /// `tlbi_page`. The barriers around a batch are `forget_range`'s
    /// ([G13]).
    fn invalidate_user_page(&mut self, operand: u64);
    /// `dsb ish` with no `isb`: the TLBIs before it complete on every CPU
    /// (spec 7.4; [G13], [G15]).
    fn user_pages_invalidated(&mut self);
}

/// Puts the tables rooted at `root` into TTBR0 with an ASID of this
/// generation. A new generation flushes the TLB first, with TTBR0 on the
/// empty table `empty`: otherwise a walk of the old tables between the
/// flush and the new TTBR0 would bring their entries back under an ASID
/// the new generation hands to another space.
pub fn switch_to(
    asids: &mut AsidAllocator,
    tag: &mut AsidTag,
    root: u64,
    empty: u64,
    mmu: &mut impl Mmu,
) {
    let act = asids.activate(tag);
    if act.flush_tlb {
        mmu.set_ttbr0(ttbr0(empty, 0));
        mmu.flush_all();
    }
    mmu.set_ttbr0(ttbr0(root, act.asid));
}

/// Drops the TLB entries of the `pages` pages from `start` once the tables
/// of the space with `tag` no longer map them, or map them with other
/// rights (spec 7.4, 7.7), and makes the stores that changed their
/// descriptors reach the table walker before this returns: one `dsb
/// ishst` for the stores, a `tlbi vale1is` a page, and one `dsb ish` after
/// the last, with no `isb` ([G13], [G15]). Without an ASID of this
/// generation the TLB holds nothing of the space (the flush that began the
/// generation dropped it), so only the barrier is left: the next
/// activation may put the tables into TTBR0 with no barrier of its own.
/// O(pages): the caller keeps `pages` within a portion (spec 7.7).
pub fn forget_range(
    asids: &AsidAllocator,
    tag: &AsidTag,
    start: u64,
    pages: u64,
    mmu: &mut impl Mmu,
) {
    mmu.tables_written();
    if let Some(asid) = asids.current(tag) {
        for i in 0..pages {
            mmu.invalidate_user_page(tlbi_page(start + (i << 12), asid));
        }
        mmu.user_pages_invalidated();
    }
}

/// Makes the tables rooted at `root` safe to free: TTBR0 leaves them, and
/// the TLB drops every entry of their ASID, which is free again afterwards.
/// In this order, so that no walk brings the entries back in between.
pub fn retire(
    asids: &mut AsidAllocator,
    tag: &mut AsidTag,
    root: u64,
    empty: u64,
    mmu: &mut impl Mmu,
) {
    if mmu.ttbr0() & TTBR_ROOT_MASK == root {
        mmu.set_ttbr0(ttbr0(empty, 0));
    }
    if let Some(asid) = asids.release(tag) {
        mmu.invalidate_asid(tlbi_asid(asid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    const EMPTY: u64 = 0x4000_1000;
    const PAGES: [u64; 3] = [0x40_0000, 0x40_1000, 0x80_0000];

    #[derive(Debug, PartialEq, Eq)]
    enum Op {
        SetTtbr0(u64),
        FlushAll,
        InvalidateAsid(u64),
        TablesWritten,
        InvalidateUserPage(u64),
        UserPagesInvalidated,
    }

    /// Notes the operations in order.
    #[derive(Default)]
    struct Log {
        ttbr0: u64,
        ops: Vec<Op>,
    }

    impl Mmu for Log {
        fn ttbr0(&self) -> u64 {
            self.ttbr0
        }
        fn set_ttbr0(&mut self, ttbr: u64) {
            self.ttbr0 = ttbr;
            self.ops.push(Op::SetTtbr0(ttbr));
        }
        fn flush_all(&mut self) {
            self.ops.push(Op::FlushAll);
        }
        fn invalidate_asid(&mut self, operand: u64) {
            self.ops.push(Op::InvalidateAsid(operand));
        }
        fn tables_written(&mut self) {
            self.ops.push(Op::TablesWritten);
        }
        fn invalidate_user_page(&mut self, operand: u64) {
            self.ops.push(Op::InvalidateUserPage(operand));
        }
        fn user_pages_invalidated(&mut self) {
            self.ops.push(Op::UserPagesInvalidated);
        }
    }

    #[test]
    fn a_new_generation_flushes_with_ttbr0_on_the_empty_table() {
        let mut asids = AsidAllocator::new(8);
        let mut log = Log::default();
        let mut tags: Vec<AsidTag> = (0..256).map(|_| AsidTag::default()).collect();
        for tag in &mut tags[..255] {
            switch_to(&mut asids, tag, 0x5000, EMPTY, &mut log);
        }
        assert!(!log.ops.contains(&Op::FlushAll));
        log.ops.clear();
        switch_to(&mut asids, &mut tags[255], 0x6000, EMPTY, &mut log);
        assert_eq!(
            log.ops,
            [
                Op::SetTtbr0(EMPTY),
                Op::FlushAll,
                Op::SetTtbr0(ttbr0(0x6000, 1))
            ]
        );
    }

    #[test]
    fn retire_leaves_the_tables_before_their_asid_goes() {
        let mut asids = AsidAllocator::new(8);
        let mut log = Log::default();
        let (mut running, mut other) = (AsidTag::default(), AsidTag::default());
        switch_to(&mut asids, &mut other, 0x5000, EMPTY, &mut log);
        switch_to(&mut asids, &mut running, 0x6000, EMPTY, &mut log);
        log.ops.clear();
        retire(&mut asids, &mut running, 0x6000, EMPTY, &mut log);
        assert_eq!(
            log.ops,
            [Op::SetTtbr0(EMPTY), Op::InvalidateAsid(tlbi_asid(2))]
        );
        log.ops.clear();
        retire(&mut asids, &mut other, 0x5000, EMPTY, &mut log);
        assert_eq!(log.ops, [Op::InvalidateAsid(tlbi_asid(1))]);
        log.ops.clear();
        forget_range(&asids, &other, PAGES[0], 1, &mut log);
        retire(&mut asids, &mut other, 0x5000, EMPTY, &mut log);
        assert_eq!(
            log.ops,
            [Op::TablesWritten],
            "a retired space touched the TLB"
        );
    }

    /// A range ends its table stores with one `dsb ishst`, drops each page
    /// with a lone TLBI, and completes them with one `dsb ish` after the
    /// last; a space with no ASID of this generation gets the first barrier
    /// alone ([G13]).
    #[test]
    fn forget_range_ends_with_one_dsb_ish() {
        let mut asids = AsidAllocator::new(8);
        let mut log = Log::default();
        let (mut ran, never_ran) = (AsidTag::default(), AsidTag::default());
        switch_to(&mut asids, &mut ran, 0x5000, EMPTY, &mut log);
        log.ops.clear();
        forget_range(&asids, &ran, 0x40_0000, 3, &mut log);
        assert_eq!(
            log.ops,
            [
                Op::TablesWritten,
                Op::InvalidateUserPage(tlbi_page(0x40_0000, 1)),
                Op::InvalidateUserPage(tlbi_page(0x40_1000, 1)),
                Op::InvalidateUserPage(tlbi_page(0x40_2000, 1)),
                Op::UserPagesInvalidated,
            ]
        );
        log.ops.clear();
        forget_range(&asids, &never_ran, 0x40_0000, 3, &mut log);
        assert_eq!(log.ops, [Op::TablesWritten]);
    }

    /// A cached translation: the ASID that tags it, the space whose tables
    /// it came from, and the page.
    type Entry = (u16, u32, u64);

    /// A TLB that walks the tables in TTBR0 before and after every
    /// operation, as a CPU may at any moment, and keeps what it finds. A
    /// descriptor cleared in memory stays visible to the walk until the
    /// next barrier.
    struct Model {
        ttbr0: u64,
        tlb: HashSet<Entry>,
        /// Live tables by root: the space they belong to and its pages.
        tables: HashMap<u64, (u32, HashSet<u64>)>,
        /// Pages unmapped in memory, as (root, page), whose cleared
        /// descriptors the walker may not see yet.
        stale: HashSet<(u64, u64)>,
        /// Lone TLBIs, as (ASID, page number), that the next `dsb ish`
        /// completes; one issued while the walker may still see a cleared
        /// descriptor drops nothing for good, so it is not kept.
        pending: Vec<(u16, u64)>,
    }

    impl Model {
        fn new() -> Model {
            Model {
                ttbr0: ttbr0(EMPTY, 0),
                tlb: HashSet::new(),
                tables: HashMap::new(),
                stale: HashSet::new(),
                pending: Vec::new(),
            }
        }

        /// Clears the descriptor of `va` in the tables at `root`, a plain
        /// store; returns whether the page was mapped.
        fn unmap(&mut self, root: u64, va: u64) -> bool {
            let pages = &mut self.tables.get_mut(&root).expect("live tables").1;
            let mapped = pages.remove(&va);
            if mapped {
                self.stale.insert((root, va));
            }
            mapped
        }

        fn walk(&mut self) {
            let root = self.ttbr0 & TTBR_ROOT_MASK;
            if root == EMPTY {
                return;
            }
            let (space, pages) = self
                .tables
                .get(&root)
                .expect("TTBR0 holds tables that went back to the allocator");
            let asid = (self.ttbr0 >> 48) as u16;
            let stale = self.stale.iter().filter(|s| s.0 == root).map(|s| s.1);
            for va in pages.iter().copied().chain(stale) {
                self.tlb.insert((asid, *space, va));
            }
        }

        /// Entries tagged with the ASID in TTBR0 all came from the tables
        /// in TTBR0, and only from pages they still map.
        fn check(&self, step: usize) {
            let root = self.ttbr0 & TTBR_ROOT_MASK;
            let asid = (self.ttbr0 >> 48) as u16;
            let running = self.tables.get(&root);
            for &(a, space, va) in &self.tlb {
                if a != asid {
                    continue;
                }
                let Some((id, pages)) = running else {
                    panic!("step {step}: the TLB holds ASID {a} while TTBR0 is empty");
                };
                assert_eq!(
                    space, *id,
                    "step {step}: space {id} sees a page of space {space} under ASID {a}"
                );
                assert!(
                    pages.contains(&va),
                    "step {step}: space {id} sees its unmapped page {va:#x}"
                );
            }
        }
    }

    impl Mmu for Model {
        fn ttbr0(&self) -> u64 {
            self.ttbr0
        }
        fn set_ttbr0(&mut self, ttbr: u64) {
            self.walk();
            self.ttbr0 = ttbr;
            self.walk();
        }
        // Each TLBI below begins with a barrier for the table stores.
        fn flush_all(&mut self) {
            self.walk();
            self.stale.clear();
            self.tlb.clear();
            self.walk();
        }
        fn invalidate_asid(&mut self, operand: u64) {
            self.walk();
            self.stale.clear();
            let asid = (operand >> 48) as u16;
            self.tlb.retain(|&(a, _, _)| a != asid);
            self.walk();
        }
        fn tables_written(&mut self) {
            self.walk();
            self.stale.clear();
            self.walk();
        }
        fn invalidate_user_page(&mut self, operand: u64) {
            self.walk();
            if self.stale.is_empty() {
                self.pending
                    .push(((operand >> 48) as u16, operand & ((1 << 44) - 1)));
            }
            self.walk();
        }
        fn user_pages_invalidated(&mut self) {
            self.walk();
            for (asid, page) in core::mem::take(&mut self.pending) {
                self.tlb.retain(|&(a, _, va)| a != asid || va >> 12 != page);
            }
            self.walk();
        }
    }

    /// A space that never ran, and so has no ASID, unmaps a page and then
    /// runs: the unmap needs no TLBI, but the walk after the switch must
    /// not find the page.
    #[test]
    fn an_unmap_without_an_asid_reaches_the_walker_before_the_space_runs() {
        let mut asids = AsidAllocator::new(8);
        let mut m = Model::new();
        m.tables.insert(0x5000, (1, PAGES.into_iter().collect()));
        let mut tag = AsidTag::default();
        assert!(m.unmap(0x5000, PAGES[0]));
        forget_range(&asids, &tag, PAGES[0], 1, &mut m);
        switch_to(&mut asids, &mut tag, 0x5000, EMPTY, &mut m);
        m.check(0);
    }

    struct Space {
        id: u32,
        root: u64,
        tag: AsidTag,
    }

    /// 300 spaces on 8-bit ASIDs, so generations turn over again and again:
    /// random switches, unmaps of a page or of a range of two, and spaces
    /// that go and are replaced by new ones on the same root. No space ever sees another one's page or a
    /// page it unmapped, and a space that went leaves nothing in the TLB.
    #[test]
    fn no_space_sees_what_it_should_not() {
        let mut asids = AsidAllocator::new(8);
        let mut m = Model::new();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut ids = 0;
        let mut new_space = |m: &mut Model, root: u64, bits: u64| {
            ids += 1;
            let pages = (0..PAGES.len())
                .filter(|i| bits & (1 << i) != 0)
                .map(|i| PAGES[i])
                .collect();
            m.tables.insert(root, (ids, pages));
            Space {
                id: ids,
                root,
                tag: AsidTag::default(),
            }
        };
        let mut spaces: Vec<Space> = (0..300)
            .map(|i| new_space(&mut m, 0x1000_0000 + i * 0x1000, i))
            .collect();
        for step in 0..25_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let s = &mut spaces[(x >> 8) as usize % 300];
            match x % 8 {
                0 => {
                    let va = PAGES[(x >> 32) as usize % PAGES.len()];
                    if m.unmap(s.root, va) {
                        forget_range(&asids, &s.tag, va, 1, &mut m);
                        assert!(
                            m.stale.is_empty() && m.pending.is_empty(),
                            "step {step}: the walker or a TLBI may still keep page {va:#x} after forget_range"
                        );
                    }
                }
                2 => {
                    // The first two pages, a range of two, whichever of
                    // them are mapped.
                    let unmapped = [PAGES[0], PAGES[1]].map(|va| m.unmap(s.root, va));
                    if unmapped.contains(&true) {
                        forget_range(&asids, &s.tag, PAGES[0], 2, &mut m);
                        assert!(
                            m.stale.is_empty() && m.pending.is_empty(),
                            "step {step}: the walker or a TLBI may still keep a page after forget_range"
                        );
                    }
                }
                1 => {
                    retire(&mut asids, &mut s.tag, s.root, EMPTY, &mut m);
                    m.tables.remove(&s.root);
                    assert!(
                        m.tlb.iter().all(|e| e.1 != s.id),
                        "step {step}: space {} left entries in the TLB",
                        s.id
                    );
                    // The tables of the new space take the frames back at
                    // once; their own stores and barrier come after any
                    // left from the old space.
                    m.stale.retain(|&(root, _)| root != s.root);
                    *s = new_space(&mut m, s.root, x >> 40);
                }
                _ => switch_to(&mut asids, &mut s.tag, s.root, EMPTY, &mut m),
            }
            m.check(step);
        }
        assert!(
            asids.generation() > 10,
            "only {} generations",
            asids.generation()
        );
    }
}
