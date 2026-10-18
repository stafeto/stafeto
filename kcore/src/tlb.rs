// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The order of TTBR0 writes, barriers and TLB maintenance around address
//! spaces (spec 7.2, 7.4). QEMU drops its whole TLB whenever the ASID in TTBR0
//! changes, and its table walker sees every store at once, so it shows no
//! missing step here; the tests run the same order against a TLB that
//! caches whatever the tables in TTBR0 map, at any moment, and a walker
//! that may still read a cleared descriptor until a barrier.

use crate::asid::{AsidAllocator, AsidCpus, AsidTag, tlbi_asid, tlbi_page, ttbr0};
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

/// Puts the tables rooted at `root` into TTBR0 with the ASID of `tag` when
/// the switch needs no lock (`AsidCpus::fast`); false when it does
/// (`switch_slow`).
pub fn switch_fast(
    cpus: &AsidCpus,
    cpu: usize,
    tag: &AsidTag,
    root: u64,
    mmu: &mut impl Mmu,
) -> bool {
    let Some(asid) = cpus.fast(cpu, tag) else {
        return false;
    };
    mmu.set_ttbr0(ttbr0(root, asid));
    true
}

/// Puts the tables rooted at `root` into TTBR0 with an ASID of this
/// generation, under the lock of the allocator. A CPU that owes a flush
/// (a generation began since its last switch) flushes first, with TTBR0 on
/// the empty table `empty`: otherwise a walk of the old tables between the
/// flush and the new TTBR0 would bring their entries back under an ASID
/// the new generation hands to another space. `clear` empties the map of
/// a new generation (`AsidAllocator::activate`).
#[allow(clippy::too_many_arguments)]
pub fn switch_slow(
    asids: &mut AsidAllocator,
    cpus: &AsidCpus,
    cpu: usize,
    tag: &AsidTag,
    root: u64,
    empty: u64,
    mmu: &mut impl Mmu,
    clear: impl FnOnce(&mut [u64]),
) {
    let act = asids.activate(cpus, cpu, tag, clear);
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
/// the last, with no `isb` ([G13], [G15]). The TLBIs reach every CPU, so
/// a thread of the space on another CPU loses the entries too. They name
/// the ASID the tag holds, of whichever generation: a CPU that ran the
/// space when the generation ended keeps the entries under that number
/// (`AsidAllocator::reserved`). A space that never ran has no entry
/// anywhere, so only the barrier is left: the next activation may put the
/// tables into TTBR0 with no barrier of its own. O(pages): the caller
/// keeps `pages` within a portion (spec 7.7).
pub fn forget_range(tag: &AsidTag, start: u64, pages: u64, mmu: &mut impl Mmu) {
    mmu.tables_written();
    if let Some(asid) = tag.asid() {
        for i in 0..pages {
            mmu.invalidate_user_page(tlbi_page(start + (i << 12), asid));
        }
        mmu.user_pages_invalidated();
    }
}

/// Makes the tables rooted at `root` safe to free: TTBR0 of this CPU
/// leaves them, and the TLBs of every CPU drop each entry of their ASID,
/// which is free again afterwards. In this order, so that no walk of this
/// CPU brings the entries back in between.
pub fn retire(
    asids: &mut AsidAllocator,
    cpus: &AsidCpus,
    tag: &mut AsidTag,
    root: u64,
    empty: u64,
    mmu: &mut impl Mmu,
) {
    if mmu.ttbr0() & TTBR_ROOT_MASK == root {
        mmu.set_ttbr0(ttbr0(empty, 0));
    }
    if let Some(asid) = asids.release(cpus, tag) {
        mmu.invalidate_asid(tlbi_asid(asid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    const EMPTY: u64 = 0x4000_1000;

    /// The ASIDs of the machine and the allocator, one CPU's view (CPU 0).
    struct Asids {
        cpus: AsidCpus,
        alloc: AsidAllocator,
    }

    impl Asids {
        fn new(bits: u32) -> Asids {
            Asids {
                cpus: AsidCpus::new(),
                alloc: AsidAllocator::new(bits),
            }
        }
        fn generation(&self) -> u64 {
            self.cpus.generation()
        }
    }

    /// The switch of CPU `cpu`: the fast path, then the slow one.
    fn switch_on(
        a: &mut Asids,
        cpu: usize,
        tag: &AsidTag,
        root: u64,
        empty: u64,
        mmu: &mut impl Mmu,
    ) {
        if !switch_fast(&a.cpus, cpu, tag, root, mmu) {
            switch_slow(&mut a.alloc, &a.cpus, cpu, tag, root, empty, mmu, |w| {
                w.fill(0)
            });
        }
    }

    fn switch_to(a: &mut Asids, tag: &AsidTag, root: u64, empty: u64, mmu: &mut impl Mmu) {
        switch_on(a, 0, tag, root, empty, mmu)
    }

    fn retire(a: &mut Asids, tag: &mut AsidTag, root: u64, empty: u64, mmu: &mut impl Mmu) {
        super::retire(&mut a.alloc, &a.cpus, tag, root, empty, mmu)
    }
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
        let mut asids = Asids::new(8);
        let mut log = Log::default();
        let mut tags: Vec<AsidTag> = (0..256).map(|_| AsidTag::default()).collect();
        for tag in &mut tags[..255] {
            switch_to(&mut asids, tag, 0x5000, EMPTY, &mut log);
        }
        assert!(!log.ops.contains(&Op::FlushAll));
        log.ops.clear();
        switch_to(&mut asids, &tags[255], 0x6000, EMPTY, &mut log);
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
        let mut asids = Asids::new(8);
        let mut log = Log::default();
        let (mut running, mut other) = (AsidTag::default(), AsidTag::default());
        switch_to(&mut asids, &other, 0x5000, EMPTY, &mut log);
        switch_to(&mut asids, &running, 0x6000, EMPTY, &mut log);
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
        forget_range(&other, PAGES[0], 1, &mut log);
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
        let mut asids = Asids::new(8);
        let mut log = Log::default();
        let (ran, never_ran) = (AsidTag::default(), AsidTag::default());
        switch_to(&mut asids, &ran, 0x5000, EMPTY, &mut log);
        log.ops.clear();
        forget_range(&ran, 0x40_0000, 3, &mut log);
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
        forget_range(&never_ran, 0x40_0000, 3, &mut log);
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
        let mut asids = Asids::new(8);
        let mut m = Model::new();
        m.tables.insert(0x5000, (1, PAGES.into_iter().collect()));
        let tag = AsidTag::default();
        assert!(m.unmap(0x5000, PAGES[0]));
        forget_range(&tag, PAGES[0], 1, &mut m);
        switch_to(&mut asids, &tag, 0x5000, EMPTY, &mut m);
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
        let mut asids = Asids::new(8);
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
                        forget_range(&s.tag, va, 1, &mut m);
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
                        forget_range(&s.tag, PAGES[0], 2, &mut m);
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
                _ => switch_to(&mut asids, &s.tag, s.root, EMPTY, &mut m),
            }
            m.check(step);
        }
        assert!(
            asids.generation() > 10,
            "only {} generations",
            asids.generation()
        );
    }

    /// One mem_unmap of `pages` pages from `start`, inside one mapping of
    /// `maps` over an object whose frames go when `refs` falls to 0: the
    /// cut (the edges take a reference each), portions of 2 pages that
    /// clear descriptors and end with `forget_range`, and the reference of
    /// the middle once its last page is done. `early` lets that reference
    /// go between the stores of the last portion and its `forget_range`.
    /// Err when the frames go while a TLB entry or an unfinished TLBI may
    /// still reach them.
    #[allow(clippy::too_many_arguments)]
    fn unmap_call(
        m: &mut Model,
        tag: &AsidTag,
        maps: &mut crate::maps::Maps<u32>,
        refs: &mut u32,
        (root, start, pages): (u64, u64, u64),
        early: bool,
    ) -> Result<(), String> {
        let index = maps.find_inside(start, pages).unwrap();
        *refs += maps.split(index, start, pages).unwrap();
        let release = |m: &Model, refs: &mut u32| {
            *refs -= 1;
            if *refs == 0 && (!m.stale.is_empty() || !m.pending.is_empty() || !m.tlb.is_empty()) {
                return Err(format!(
                    "the frames went with {} stale, {} pending and {} cached",
                    m.stale.len(),
                    m.pending.len(),
                    m.tlb.len()
                ));
            }
            Ok(())
        };
        let mut done = 0;
        while done < pages {
            let n = (pages - done).min(2);
            let va = start + (done << 12);
            for i in 0..n {
                assert!(m.unmap(root, va + (i << 12)));
            }
            let last = maps.drop_prefix(index, n as u32).is_some();
            if last && early {
                release(m, refs)?;
            }
            forget_range(tag, va, n, m);
            if last && !early {
                release(m, refs)?;
            }
            done += n;
        }
        Ok(())
    }

    /// A mapping of 6 pages is unmapped in three calls, the middle 2
    /// pages, then each edge: no frame goes while the TLB or a pending
    /// TLBI may still reach it, and the reference of the last call goes
    /// only after its final `dsb ish`. An early release is caught.
    #[test]
    fn the_reference_goes_after_the_last_dsb_ish() {
        for early in [false, true] {
            let mut asids = Asids::new(8);
            let mut m = Model::new();
            let base = 0x40_0000;
            m.tables
                .insert(0x5000, (1, (0..6).map(|i| base + (i << 12)).collect()));
            let tag = AsidTag::default();
            switch_to(&mut asids, &tag, 0x5000, EMPTY, &mut m);
            let mut maps = crate::maps::Maps::new();
            maps.insert(crate::maps::Mapping::new(
                base,
                6,
                0,
                1u32,
                abi::Rights::MAP_READ,
            ))
            .unwrap();
            let mut refs = 1;
            let calls = [(2, 2), (0, 2), (4, 2)];
            let mut outcome = Ok(());
            for (page, pages) in calls {
                let args = (0x5000, base + (page << 12), pages);
                outcome = outcome
                    .and_then(|()| unmap_call(&mut m, &tag, &mut maps, &mut refs, args, early));
            }
            if early {
                assert!(
                    outcome.is_err(),
                    "a reference that went early was not caught"
                );
            } else {
                assert_eq!(outcome, Ok(()));
                assert_eq!((refs, maps.len()), (0, 0));
            }
        }
    }

    /// Four CPUs, each with its own TTBR0 and TLB; a TLBI by ASID reaches
    /// every TLB, a flush its own. A CPU walks the tables in its TTBR0 at
    /// any moment and keeps what it finds, as (ASID, space).
    struct Multi {
        ttbr0: [u64; 4],
        tlb: [HashSet<(u16, u32)>; 4],
        /// Root of live tables and the space they belong to.
        spaces: HashMap<u64, u32>,
    }

    struct On<'a> {
        m: &'a mut Multi,
        cpu: usize,
    }

    impl Multi {
        fn walk(&mut self) {
            for c in 0..4 {
                let root = self.ttbr0[c] & TTBR_ROOT_MASK;
                if root == EMPTY {
                    continue;
                }
                let space = *self
                    .spaces
                    .get(&root)
                    .expect("a CPU holds tables that went back to the allocator");
                self.tlb[c].insert(((self.ttbr0[c] >> 48) as u16, space));
            }
        }

        /// What each CPU may use: an entry under the ASID in its TTBR0
        /// belongs to the space in its TTBR0.
        fn check(&self, step: usize) {
            for c in 0..4 {
                let root = self.ttbr0[c] & TTBR_ROOT_MASK;
                let asid = (self.ttbr0[c] >> 48) as u16;
                for &(a, space) in &self.tlb[c] {
                    if a != asid || root == EMPTY {
                        continue;
                    }
                    assert_eq!(
                        space, self.spaces[&root],
                        "step {step}: CPU {c} runs space {} and holds a page of space {space} under ASID {a}",
                        self.spaces[&root]
                    );
                }
            }
        }
    }

    impl Mmu for On<'_> {
        fn ttbr0(&self) -> u64 {
            self.m.ttbr0[self.cpu]
        }
        fn set_ttbr0(&mut self, ttbr: u64) {
            self.m.walk();
            self.m.ttbr0[self.cpu] = ttbr;
            self.m.walk();
        }
        fn flush_all(&mut self) {
            self.m.walk();
            self.m.tlb[self.cpu].clear();
            self.m.walk();
        }
        fn invalidate_asid(&mut self, operand: u64) {
            self.m.walk();
            let asid = (operand >> 48) as u16;
            for tlb in &mut self.m.tlb {
                tlb.retain(|&(a, _)| a != asid);
            }
            self.m.walk();
        }
        fn tables_written(&mut self) {}
        fn invalidate_user_page(&mut self, _: u64) {}
        fn user_pages_invalidated(&mut self) {}
    }

    /// Spaces on four CPUs at once, 300 of them on 8-bit ASIDs: random
    /// switches (a space may run on several CPUs), spaces that go (the
    /// CPUs that still hold their tables leave them first, as an idle CPU
    /// does) and are replaced on the same root. No CPU ever uses an entry
    /// of another space under the ASID it runs with, across generations
    /// that each CPU only learns of at its next switch.
    #[test]
    fn four_cpus_never_use_an_entry_of_another_space() {
        let mut a = Asids::new(8);
        let mut m = Multi {
            ttbr0: [ttbr0(EMPTY, 0); 4],
            tlb: Default::default(),
            spaces: HashMap::new(),
        };
        let root = |i: u64| 0x1000_0000 + i * 0x1000;
        let mut tags: Vec<AsidTag> = (0..300).map(|_| AsidTag::default()).collect();
        for i in 0..300 {
            m.spaces.insert(root(i), i as u32);
        }
        let mut next_id = 300;
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..60_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = (x >> 8) as usize % 300;
            let cpu = (x >> 24) as usize % 4;
            match x % 16 {
                0 => {
                    // The space goes: every CPU leaves its tables, one
                    // retires the space.
                    for c in 0..4 {
                        if m.ttbr0[c] & TTBR_ROOT_MASK == root(i as u64) {
                            On { m: &mut m, cpu: c }.set_ttbr0(ttbr0(EMPTY, 0));
                        }
                    }
                    let mut mmu = On { m: &mut m, cpu };
                    retire(&mut a, &mut tags[i], root(i as u64), EMPTY, &mut mmu);
                    m.spaces.insert(root(i as u64), next_id);
                    next_id += 1;
                }
                1 => {
                    // The CPU idles.
                    On { m: &mut m, cpu }.set_ttbr0(ttbr0(EMPTY, 0));
                }
                _ => {
                    if m.ttbr0[cpu] & TTBR_ROOT_MASK != root(i as u64) {
                        let mut mmu = On { m: &mut m, cpu };
                        switch_on(&mut a, cpu, &tags[i], root(i as u64), EMPTY, &mut mmu);
                    }
                }
            }
            m.check(step);
        }
        assert!(a.generation() > 10, "only {} generations", a.generation());
    }
}
