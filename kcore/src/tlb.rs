// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The order of TTBR0 writes and TLB maintenance around address spaces
//! (spec 7.2). QEMU drops its whole TLB whenever the ASID in TTBR0 changes,
//! so it shows no missing step here; the tests run the same order against
//! a TLB that caches whatever the tables in TTBR0 map, at any moment.

use crate::asid::{AsidAllocator, AsidTag, tlbi_asid, tlbi_page, ttbr0};
use crate::paging::TTBR_ROOT_MASK;

/// TTBR0 and the TLB of this CPU; the kernel implements them with MSR and
/// TLBI and the barriers of the Arm template.
pub trait Mmu {
    fn ttbr0(&self) -> u64;
    /// `msr ttbr0_el1; isb`
    fn set_ttbr0(&mut self, ttbr: u64);
    /// `tlbi vmalle1; dsb nsh; isb`: every EL1&0 entry of this CPU.
    fn flush_all(&mut self);
    /// `dsb ishst; tlbi vale1is; dsb ish; isb`; `operand` from `tlbi_page`.
    fn invalidate_page(&mut self, operand: u64);
    /// `dsb ishst; tlbi aside1is; dsb ish; isb`, walk-cache entries
    /// included; `operand` from `tlbi_asid`.
    fn invalidate_asid(&mut self, operand: u64);
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

/// Drops the TLB entry of the page at `va` once the tables of the space
/// with `tag` no longer map it. Without an ASID of this generation the TLB
/// holds nothing of the space: the flush that began the generation dropped
/// it.
pub fn forget_page(asids: &AsidAllocator, tag: &AsidTag, va: u64, mmu: &mut impl Mmu) {
    if let Some(asid) = asids.current(tag) {
        mmu.invalidate_page(tlbi_page(va, asid));
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
        InvalidatePage(u64),
        InvalidateAsid(u64),
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
        fn invalidate_page(&mut self, operand: u64) {
            self.ops.push(Op::InvalidatePage(operand));
        }
        fn invalidate_asid(&mut self, operand: u64) {
            self.ops.push(Op::InvalidateAsid(operand));
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
        forget_page(&asids, &other, PAGES[0], &mut log);
        retire(&mut asids, &mut other, 0x5000, EMPTY, &mut log);
        assert!(log.ops.is_empty(), "a retired space touched the TLB");
    }

    /// A cached translation: the ASID that tags it, the space whose tables
    /// it came from, and the page.
    type Entry = (u16, u32, u64);

    /// A TLB that walks the tables in TTBR0 before and after every
    /// operation, as a CPU may at any moment, and keeps what it finds.
    struct Model {
        ttbr0: u64,
        tlb: HashSet<Entry>,
        /// Live tables by root: the space they belong to and its pages.
        tables: HashMap<u64, (u32, HashSet<u64>)>,
    }

    impl Model {
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
            for &va in pages {
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
        fn flush_all(&mut self) {
            self.walk();
            self.tlb.clear();
            self.walk();
        }
        fn invalidate_page(&mut self, operand: u64) {
            self.walk();
            let asid = (operand >> 48) as u16;
            let page = operand & ((1 << 44) - 1);
            self.tlb.retain(|&(a, _, va)| a != asid || va >> 12 != page);
            self.walk();
        }
        fn invalidate_asid(&mut self, operand: u64) {
            self.walk();
            let asid = (operand >> 48) as u16;
            self.tlb.retain(|&(a, _, _)| a != asid);
            self.walk();
        }
    }

    struct Space {
        id: u32,
        root: u64,
        tag: AsidTag,
    }

    /// 300 spaces on 8-bit ASIDs, so generations turn over again and again:
    /// random switches, unmaps and spaces that go and are replaced by new
    /// ones on the same root. No space ever sees another one's page or a
    /// page it unmapped, and a space that went leaves nothing in the TLB.
    #[test]
    fn no_space_sees_what_it_should_not() {
        let mut asids = AsidAllocator::new(8);
        let mut m = Model {
            ttbr0: ttbr0(EMPTY, 0),
            tlb: HashSet::new(),
            tables: HashMap::new(),
        };
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
        for step in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let s = &mut spaces[(x >> 8) as usize % 300];
            match x % 8 {
                0 => {
                    let va = PAGES[(x >> 32) as usize % PAGES.len()];
                    let pages = &mut m.tables.get_mut(&s.root).unwrap().1;
                    if pages.remove(&va) {
                        forget_page(&asids, &s.tag, va, &mut m);
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
                    // The tables of the new space take the frames back at once.
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
