// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Address space identifiers (spec 7.2): the tag that keeps TLB entries of
//! different processes apart, so a switch between processes needs no TLB
//! flush. ASIDs are handed out in generations: when one generation runs out,
//! the next begins with a flush of the whole TLB, and every address space
//! gets a new ASID at its next activation. ASID 0 belongs to the kernel.

use crate::paging::TTBR_ROOT_MASK;

/// The widest ASID the architecture has.
const MAX_BITS: u32 = 16;
const WORDS: usize = (1 << MAX_BITS) / 64;

/// ASID width that ID_AA64MMFR0_EL1 allows: 16 bits when ASIDBits (bits
/// [7:4]) reads 0b0010, else 8. head.S sets TCR_EL1.AS by the same rule.
pub fn asid_bits(mmfr0: u64) -> u32 {
    if (mmfr0 >> 4) & 0xF == 0b0010 { 16 } else { 8 }
}

/// TTBR0_EL1 for the tables rooted at `root`, tagged with `asid` (ASID in
/// bits [63:48], TCR_EL1.A1 = 0).
pub fn ttbr0(root: u64, asid: u16) -> u64 {
    (root & TTBR_ROOT_MASK) | (u64::from(asid) << 48)
}

/// Operand of `tlbi vale1is`: the page number of `va` in bits [43:0] and
/// the ASID in bits [63:48].
pub fn tlbi_page(va: u64, asid: u16) -> u64 {
    ((va >> 12) & ((1 << 44) - 1)) | (u64::from(asid) << 48)
}

/// Operand of `tlbi aside1is`: the ASID in bits [63:48].
pub fn tlbi_asid(asid: u16) -> u64 {
    u64::from(asid) << 48
}

/// An address space's claim on an ASID, valid only in the generation that
/// issued it. The default tag has never run. Not `Copy`: one address space
/// owns a tag, and a copy would let two of them run with one ASID.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AsidTag {
    generation: u64,
    asid: u16,
}

/// What an activation hands back: the ASID for TTBR0 and whether a new
/// generation began, in which case the caller flushes the whole TLB before
/// it installs the ASID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a new generation needs a TLB flush"]
pub struct Activation {
    pub asid: u16,
    pub flush_tlb: bool,
}

pub struct AsidAllocator {
    bits: u32,
    /// Starts at 1, so the default tag (generation 0) is never current.
    generation: u64,
    free: u32,
    /// Where the search for a free ASID starts.
    next: usize,
    /// One bit per ASID of this generation; bit 0, the kernel's, always set.
    used: [u64; WORDS],
}

impl AsidAllocator {
    /// An allocator for `bits`-wide ASIDs, 8 or 16.
    pub fn new(bits: u32) -> AsidAllocator {
        assert!(bits == 8 || bits == MAX_BITS, "ASIDs are 8 or 16 bits wide");
        let mut a = AsidAllocator {
            bits,
            generation: 1,
            free: 0,
            next: 1,
            used: [0; WORDS],
        };
        a.reset();
        a
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// ASIDs this generation can still hand out.
    pub fn free_asids(&self) -> u32 {
        self.free
    }

    /// The tag's ASID when the tag belongs to this generation.
    pub fn current(&self, tag: &AsidTag) -> Option<u16> {
        (tag.generation == self.generation).then_some(tag.asid)
    }

    /// The ASID for an address space about to run. A tag of this generation
    /// keeps its ASID; any other tag gets a free one, and when none is left
    /// a new generation begins.
    pub fn activate(&mut self, tag: &mut AsidTag) -> Activation {
        if let Some(asid) = self.current(tag) {
            return Activation {
                asid,
                flush_tlb: false,
            };
        }
        let flush_tlb = self.free == 0;
        if flush_tlb {
            self.generation += 1;
            self.reset();
        }
        let asid = self.take();
        *tag = AsidTag {
            generation: self.generation,
            asid,
        };
        Activation { asid, flush_tlb }
    }

    /// Gives back the ASID of an address space that goes away and returns
    /// it when it was current. The tag is void afterwards, so releasing it
    /// again frees nothing. The caller invalidates that ASID's TLB entries
    /// before the next `activate` can hand it out again. A tag of an older
    /// generation owns nothing: the flush that began this generation
    /// already dropped its entries.
    pub fn release(&mut self, tag: &mut AsidTag) -> Option<u16> {
        let asid = self.current(tag);
        *tag = AsidTag::default();
        let i = usize::from(asid?);
        let bit = 1 << (i % 64);
        assert!(self.used[i / 64] & bit != 0, "ASID {i} released while free");
        self.used[i / 64] &= !bit;
        self.free += 1;
        asid
    }

    fn reset(&mut self) {
        self.used = [0; WORDS];
        self.used[0] = 1;
        self.free = (1 << self.bits) - 1;
        self.next = 1;
    }

    /// Marks the first free ASID from `next` on, wrapping around once.
    fn take(&mut self) -> u16 {
        let limit = 1 << self.bits;
        let i = self
            .first_free(self.next, limit)
            .or_else(|| self.first_free(1, self.next))
            .expect("a free ASID when the count says so");
        self.used[i / 64] |= 1 << (i % 64);
        self.free -= 1;
        self.next = if i + 1 == limit { 1 } else { i + 1 };
        i as u16
    }

    /// First clear bit in `[from, to)`, a word at a time.
    fn first_free(&self, from: usize, to: usize) -> Option<usize> {
        let mut i = from;
        while i < to {
            // Bits below `i` in its word count as used.
            let word = self.used[i / 64] | ((1 << (i % 64)) - 1);
            if word != u64::MAX {
                let found = i / 64 * 64 + (!word).trailing_zeros() as usize;
                return (found < to).then_some(found);
            }
            i = (i / 64 + 1) * 64;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// ID_AA64MMFR0_EL1 of QEMU's cortex-a72 and cortex-a53.
    const MMFR0_A72: u64 = 0x1124;
    const MMFR0_A53: u64 = 0x1122;

    fn fresh(a: &mut AsidAllocator) -> (AsidTag, Activation) {
        let mut tag = AsidTag::default();
        let act = a.activate(&mut tag);
        (tag, act)
    }

    #[test]
    fn asid_width_comes_from_mmfr0() {
        assert_eq!(asid_bits(MMFR0_A72), 16);
        assert_eq!(asid_bits(MMFR0_A53), 16);
        assert_eq!(asid_bits(0x1104), 8);
        // Reserved encodings fall back to 8 bits, as TCR_EL1.AS stays clear.
        assert_eq!(asid_bits(0x1114), 8);
    }

    #[test]
    #[should_panic(expected = "8 or 16 bits")]
    fn other_widths_are_refused() {
        AsidAllocator::new(12);
    }

    #[test]
    fn eight_bit_asids_run_from_1_to_255() {
        let mut a = AsidAllocator::new(8);
        assert_eq!(a.bits(), 8);
        assert_eq!(a.free_asids(), 255);
        let mut seen = HashSet::new();
        for _ in 0..255 {
            let (_, act) = fresh(&mut a);
            assert!(!act.flush_tlb);
            assert_ne!(act.asid, 0, "ASID 0 is the kernel's");
            assert!(seen.insert(act.asid), "ASID {} issued twice", act.asid);
        }
        assert_eq!(a.free_asids(), 0);
        assert_eq!(a.generation(), 1);
    }

    #[test]
    fn sixteen_bit_asids_run_from_1_to_65535() {
        let mut a = AsidAllocator::new(16);
        let mut seen = HashSet::new();
        for _ in 0..65535 {
            let (_, act) = fresh(&mut a);
            assert!(!act.flush_tlb);
            assert_ne!(act.asid, 0);
            assert!(seen.insert(act.asid));
        }
        assert_eq!(a.free_asids(), 0);
        assert_eq!(a.generation(), 1);
    }

    #[test]
    fn an_active_tag_keeps_its_asid() {
        let mut a = AsidAllocator::new(16);
        let (mut tag, first) = fresh(&mut a);
        let again = a.activate(&mut tag);
        assert_eq!(again.asid, first.asid);
        assert!(!again.flush_tlb);
        assert_eq!(a.current(&tag), Some(first.asid));
        assert_eq!(a.free_asids(), 65534);
    }

    #[test]
    fn exhaustion_starts_a_new_generation_with_a_flush() {
        let mut a = AsidAllocator::new(8);
        for _ in 0..255 {
            let _ = fresh(&mut a);
        }
        let (tag, act) = fresh(&mut a);
        assert!(act.flush_tlb, "a new generation must flush the TLB");
        assert_eq!(a.generation(), 2);
        assert_eq!(act.asid, 1);
        assert_eq!(a.current(&tag), Some(1));
        assert_eq!(a.free_asids(), 254);
    }

    #[test]
    fn an_old_tag_gets_a_new_asid_without_another_flush() {
        let mut a = AsidAllocator::new(8);
        let (mut old, first) = fresh(&mut a);
        for _ in 0..254 {
            let _ = fresh(&mut a);
        }
        let (newer, rollover) = fresh(&mut a);
        assert!(rollover.flush_tlb);
        assert_eq!(a.current(&old), None, "an old generation's ASID is void");
        let again = a.activate(&mut old);
        assert!(!again.flush_tlb);
        assert_eq!(a.current(&old), Some(again.asid));
        assert_ne!(again.asid, 0);
        assert_ne!(
            again.asid, rollover.asid,
            "two live spaces of one generation share an ASID"
        );
        assert_eq!(a.current(&newer), Some(rollover.asid));
        // The number the old tag had before is no longer its own.
        assert_eq!(first.asid, rollover.asid);
    }

    #[test]
    fn live_tags_of_one_generation_never_share_an_asid() {
        let mut a = AsidAllocator::new(8);
        let mut tags: Vec<AsidTag> = (0..300).map(|_| AsidTag::default()).collect();
        // Activate 300 spaces round and round: every pass after the first
        // generation runs out mixes old and new tags.
        for _ in 0..3 {
            for tag in tags.iter_mut() {
                let _ = a.activate(tag);
            }
        }
        let live: Vec<u16> = tags.iter().filter_map(|t| a.current(t)).collect();
        let distinct: HashSet<u16> = live.iter().copied().collect();
        assert_eq!(live.len(), distinct.len());
        assert!(!distinct.contains(&0));
        assert!(a.generation() > 1);
    }

    #[test]
    fn a_released_asid_is_issued_again_without_a_flush() {
        let mut a = AsidAllocator::new(8);
        let mut tags: Vec<AsidTag> = (0..255).map(|_| AsidTag::default()).collect();
        for tag in tags.iter_mut() {
            let _ = a.activate(tag);
        }
        assert_eq!(a.release(&mut tags[6]), Some(7));
        assert_eq!(a.free_asids(), 1);
        let (_, act) = fresh(&mut a);
        assert!(!act.flush_tlb);
        assert_eq!(act.asid, 7);
        assert_eq!(a.generation(), 1);
    }

    #[test]
    fn releasing_an_old_tag_frees_nothing() {
        let mut a = AsidAllocator::new(8);
        let (mut old, _) = fresh(&mut a);
        for _ in 0..254 {
            let _ = fresh(&mut a);
        }
        let (newer, act) = fresh(&mut a);
        assert!(act.flush_tlb);
        // The old tag's number now belongs to `newer`: releasing the old tag
        // must not hand it out a second time.
        assert_eq!(a.release(&mut old), None);
        assert_eq!(a.free_asids(), 254);
        assert_eq!(a.current(&newer), Some(act.asid));
        let (_, other) = fresh(&mut a);
        assert_ne!(other.asid, act.asid);
    }

    #[test]
    fn a_tag_that_never_ran_has_nothing_to_release() {
        let mut a = AsidAllocator::new(16);
        assert_eq!(a.current(&AsidTag::default()), None);
        assert_eq!(a.release(&mut AsidTag::default()), None);
        assert_eq!(a.free_asids(), 65535);
    }

    #[test]
    fn a_released_tag_releases_nothing_twice() {
        let mut a = AsidAllocator::new(8);
        let (mut tag, act) = fresh(&mut a);
        let _ = fresh(&mut a);
        assert_eq!(a.release(&mut tag), Some(act.asid));
        assert_eq!(tag, AsidTag::default(), "a released tag keeps its claim");
        assert_eq!(a.release(&mut tag), None);
        assert_eq!(a.free_asids(), 254);
    }

    /// 300 address spaces on 8-bit ASIDs run and go at random; one that goes
    /// is replaced by a new one. After every step the tags of this
    /// generation hold distinct ASIDs, none of them the kernel's, and the
    /// free count adds up.
    #[test]
    fn random_activations_and_releases_never_share_an_asid() {
        let mut a = AsidAllocator::new(8);
        let mut tags: Vec<AsidTag> = (0..300).map(|_| AsidTag::default()).collect();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = (x >> 8) as usize % tags.len();
            // One step in eight releases: enough spaces stay to run out of
            // ASIDs again and again.
            if x.is_multiple_of(8) {
                // The released tag is void, as a new space's would be.
                let _ = a.release(&mut tags[i]);
            } else {
                let _ = a.activate(&mut tags[i]);
            }
            let mut seen = [false; 256];
            let mut live = 0;
            for asid in tags.iter().filter_map(|t| a.current(t)) {
                let asid = usize::from(asid);
                assert!(asid != 0 && !seen[asid], "step {step}: ASID {asid} twice");
                seen[asid] = true;
                live += 1;
            }
            assert_eq!(a.free_asids(), 255 - live, "step {step}");
        }
        assert!(a.generation() > 50, "only {} generations", a.generation());
    }

    #[test]
    fn ttbr0_holds_the_root_and_the_asid() {
        assert_eq!(ttbr0(0x4008_1000, 0xABCD), 0xABCD_0000_4008_1000);
        assert_eq!(ttbr0(0x4008_1000 | 1, 0), 0x4008_1000);
    }

    #[test]
    fn tlbi_operands_hold_the_page_number_and_the_asid() {
        assert_eq!(tlbi_page(0x0040_0123, 5), (5 << 48) | 0x400);
        assert_eq!(
            tlbi_page(0x0000_FFFF_FFFF_F000, 0xFFFF),
            (0xFFFF << 48) | 0xF_FFFF_FFFF
        );
        assert_eq!(tlbi_asid(5), 5 << 48);
    }
}
