// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Address space identifiers (spec 7.2): the tag that keeps TLB entries of
//! different processes apart, so a switch between processes needs no TLB
//! flush. ASIDs are handed out in generations (Linux's scheme, SMP stage 5):
//! the generation lives in the bits above the ASID of every tag, and when
//! one generation runs out the next begins at once, with no flush: each CPU
//! flushes its own TLB at its next switch of address space
//! (`flush_pending`), and the ASID a CPU was running when the generation
//! ended stays that space's (`reserved`). ASID 0 belongs to the kernel.
//!
//! A switch to a space whose tag is of the current generation takes no lock
//! (`AsidCpus::fast`): one compare-and-swap of the CPU's own `active` word,
//! which a new generation empties, so that a CPU never takes the fast path
//! with a number the new generation may hand out. Everything else goes
//! through `AsidAllocator`, under the lock of the objects, for a time that
//! does not depend on the number of ASIDs.

use crate::bootinfo::MAX_CPUS;
use crate::paging::TTBR_ROOT_MASK;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

/// The widest ASID the architecture has.
const MAX_BITS: u32 = 16;
const WORDS: usize = (1 << MAX_BITS) / 64;
/// One bit per word of the map, set while the word is full.
const SUMMARY: usize = WORDS / 64;
/// A tag holds the generation above bit 16 and the ASID below.
const GEN_SHIFT: u32 = 16;
const ASID_MASK: u64 = 0xFFFF;
const ALL_CPUS: u32 = (1 << MAX_CPUS) - 1;

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

/// An address space's claim on an ASID: the generation that issued it above
/// bit 16 and the ASID below, 0 for a space that has never run. Written
/// only under the lock of the allocator, read by any CPU. Not `Copy`: one
/// address space owns a tag, and a copy would let two of them run with one
/// ASID.
#[derive(Debug, Default)]
pub struct AsidTag {
    id: AtomicU64,
}

impl AsidTag {
    fn load(&self) -> u64 {
        self.id.load(Relaxed)
    }

    /// The ASID the tag names, of whichever generation: the TLB of a CPU
    /// may still hold entries under it when the generation has changed
    /// (`reserved`), so a space changes its tables with a TLBI for this
    /// number whenever it has one. None for a space that never ran.
    pub fn asid(&self) -> Option<u16> {
        let id = self.load();
        (id != 0).then_some((id & ASID_MASK) as u16)
    }
}

/// What a slow activation hands back: the ASID for TTBR0 and whether this
/// CPU flushes its TLB before it installs the ASID (a generation began
/// since its last switch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a new generation needs a TLB flush"]
pub struct Activation {
    pub asid: u16,
    pub flush_tlb: bool,
}

/// A word on a line of its own: the CPUs' `active` words never share one.
#[repr(align(64))]
#[derive(Debug, Default)]
struct Line(AtomicU64);

/// What the CPUs share without a lock: the generation, the `active` word of
/// each CPU, and the mask of the CPUs that still owe a flush.
#[derive(Debug)]
pub struct AsidCpus {
    /// Starts at 1, so the default tag (generation 0) is never current.
    generation: AtomicU64,
    /// Bit i is set while CPU i has not flushed since the last new
    /// generation. A CPU clears its own bit.
    flush_pending: AtomicU32,
    /// The tag of the space CPU i switched to last, 0 after a new
    /// generation took it into `reserved`.
    active: [Line; MAX_CPUS],
}

impl AsidCpus {
    pub const fn new() -> AsidCpus {
        AsidCpus {
            generation: AtomicU64::new(1),
            flush_pending: AtomicU32::new(0),
            active: [const { Line(AtomicU64::new(0)) }; MAX_CPUS],
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Relaxed)
    }

    /// The tag's ASID when the tag belongs to this generation.
    pub fn current(&self, tag: &AsidTag) -> Option<u16> {
        let id = tag.load();
        (id >> GEN_SHIFT == self.generation()).then_some((id & ASID_MASK) as u16)
    }

    /// Empties the `active` word of CPU `cpu`, so that its next switch
    /// takes the slow path. For tests that stand in for a CPU.
    pub fn forget_active(&self, cpu: usize) {
        self.active[cpu].0.store(0, Relaxed);
    }

    /// The switch with no lock, for CPU `cpu`: the tag is of this
    /// generation and the CPU's `active` word is not empty, so this CPU has
    /// flushed since the generation began. One compare-and-swap puts the
    /// tag into `active`; a new generation that empties `active` first
    /// makes it fail, and one that comes later keeps the number reserved.
    pub fn fast(&self, cpu: usize, tag: &AsidTag) -> Option<u16> {
        let id = tag.load();
        let active = &self.active[cpu].0;
        let old = active.load(Relaxed);
        if old != 0
            && id >> GEN_SHIFT == self.generation()
            && active.compare_exchange(old, id, Relaxed, Relaxed).is_ok()
        {
            Some((id & ASID_MASK) as u16)
        } else {
            None
        }
    }
}

impl Default for AsidCpus {
    fn default() -> Self {
        Self::new()
    }
}

/// The map of used ASIDs, on a line of its own so that `dc zva` clears it
/// word for word.
#[repr(C, align(64))]
struct Map([u64; WORDS]);

/// The part of the ASIDs that a lock guards: the map of used numbers of
/// this generation, and the numbers the CPUs kept across generations.
pub struct AsidAllocator {
    bits: u32,
    free: u32,
    /// Where the search for a free ASID starts.
    next: usize,
    /// One bit per ASID of this generation; bit 0, the kernel's, always set.
    used: Map,
    /// Bit i is set while `used.0[i]` is all ones.
    full: [u64; SUMMARY],
    /// The tag each CPU was running when a generation ended, as the tag
    /// held it (so with that generation): the number stays used in every
    /// generation after, and a tag equal to it takes it into its own.
    reserved: [u64; MAX_CPUS],
}

impl AsidAllocator {
    /// An allocator for `bits`-wide ASIDs, 8 or 16.
    pub fn new(bits: u32) -> AsidAllocator {
        assert!(
            bits == 8 || bits == MAX_BITS || (cfg!(feature = "narrow-asid") && bits == 4),
            "ASIDs are 8 or 16 bits wide"
        );
        let mut a = AsidAllocator {
            bits,
            free: 0,
            next: 1,
            used: Map([0; WORDS]),
            full: [0; SUMMARY],
            reserved: [0; MAX_CPUS],
        };
        a.empty_map();
        a
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// ASIDs this generation can still hand out.
    pub fn free_asids(&self) -> u32 {
        self.free
    }

    /// The ASID for a space about to run on CPU `cpu`, the slow way: a tag
    /// of this generation keeps its ASID; one of an earlier generation
    /// that a CPU reserved takes the number into this one; any other gets a
    /// free number, and when none is left a new generation begins. A new
    /// generation clears the map with `clear` (the kernel zeroes it by
    /// cache blocks) and reserves the numbers the CPUs run, which is all it
    /// does: no flush, no walk of the spaces. The CPU flushes when a
    /// generation began since its last switch.
    pub fn activate(
        &mut self,
        cpus: &AsidCpus,
        cpu: usize,
        tag: &AsidTag,
        clear: impl FnOnce(&mut [u64]),
    ) -> Activation {
        let mut id = tag.load();
        if id >> GEN_SHIFT != cpus.generation() {
            id = self.new_context(cpus, id, clear);
            tag.id.store(id, Relaxed);
        }
        let mine = 1 << cpu;
        let flush_tlb = cpus.flush_pending.fetch_and(!mine, Relaxed) & mine != 0;
        cpus.active[cpu].0.store(id, Relaxed);
        Activation {
            asid: (id & ASID_MASK) as u16,
            flush_tlb,
        }
    }

    /// The tag of this generation for a space whose tag is `old`, another
    /// generation's or empty.
    fn new_context(&mut self, cpus: &AsidCpus, old: u64, clear: impl FnOnce(&mut [u64])) -> u64 {
        if let Some(id) = self.adopt(cpus, old) {
            return id;
        }
        if self.free == 0 {
            cpus.generation.fetch_add(1, Relaxed);
            self.new_generation(cpus, clear);
            // The space may be what a CPU was running.
            if let Some(id) = self.adopt(cpus, old) {
                return id;
            }
        }
        cpus.generation() << GEN_SHIFT | u64::from(self.take())
    }

    /// `old`'s number in this generation, when a CPU reserved exactly `old`:
    /// every reservation of it moves to the new tag.
    fn adopt(&mut self, cpus: &AsidCpus, old: u64) -> Option<u64> {
        if old == 0 {
            return None;
        }
        let id = cpus.generation() << GEN_SHIFT | (old & ASID_MASK);
        let mut hit = false;
        for r in self.reserved.iter_mut().filter(|r| **r == old) {
            *r = id;
            hit = true;
        }
        hit.then_some(id)
    }

    /// Begins a generation (the counter is raised already): an empty map
    /// but for the kernel's number and what the CPUs reserve, the `active`
    /// words emptied, every CPU owing a flush.
    fn new_generation(&mut self, cpus: &AsidCpus, clear: impl FnOnce(&mut [u64])) {
        clear(&mut self.used.0);
        self.empty_map();
        for cpu in 0..MAX_CPUS {
            let running = cpus.active[cpu].0.swap(0, Relaxed);
            if running != 0 {
                self.reserved[cpu] = running;
            }
            let kept = self.reserved[cpu];
            if kept != 0 {
                self.set((kept & ASID_MASK) as usize);
            }
        }
        cpus.flush_pending.store(ALL_CPUS, Relaxed);
    }

    /// The map as a new generation has it, the kernel's number the only one
    /// used, once the words are zero.
    fn empty_map(&mut self) {
        self.used.0[0] = 1;
        self.full = [0; SUMMARY];
        self.free = (1 << self.bits) - 1;
        self.next = 1;
    }

    /// Gives back the ASID of an address space that goes away and returns
    /// it when it was the space's own, of this generation or reserved by a
    /// CPU. The tag is void afterwards, so releasing it again frees
    /// nothing. The caller invalidates that ASID's TLB entries on every CPU
    /// before the next `activate` can hand it out again.
    pub fn release(&mut self, cpus: &AsidCpus, tag: &mut AsidTag) -> Option<u16> {
        let id = tag.id.swap(0, Relaxed);
        if id == 0 {
            return None;
        }
        let mut owned = id >> GEN_SHIFT == cpus.generation();
        for r in self.reserved.iter_mut().filter(|r| **r == id) {
            *r = 0;
            owned = true;
        }
        // No CPU may take its `active` tag into a later generation.
        for line in &cpus.active {
            let _ = line.0.compare_exchange(id, 0, Relaxed, Relaxed);
        }
        let i = (id & ASID_MASK) as usize;
        owned.then(|| {
            self.unset(i);
            i as u16
        })
    }

    fn set(&mut self, i: usize) {
        let (w, bit) = (i / 64, 1 << (i % 64));
        if self.used.0[w] & bit == 0 {
            self.used.0[w] |= bit;
            self.free -= 1;
            if self.used.0[w] == u64::MAX {
                self.full[w / 64] |= 1 << (w % 64);
            }
        }
    }

    fn unset(&mut self, i: usize) {
        let (w, bit) = (i / 64, 1 << (i % 64));
        assert!(self.used.0[w] & bit != 0, "ASID {i} released while free");
        self.used.0[w] &= !bit;
        self.full[w / 64] &= !(1 << (w % 64));
        self.free += 1;
    }

    /// Marks the first free ASID from `next` on, wrapping around once.
    fn take(&mut self) -> u16 {
        let limit = 1 << self.bits;
        let i = self
            .first_free(self.next, limit)
            .or_else(|| self.first_free(1, self.next))
            .expect("a free ASID when the count says so");
        self.set(i);
        self.next = if i + 1 == limit { 1 } else { i + 1 };
        i as u16
    }

    /// First clear bit in `[from, to)`: the word of `from`, then the words
    /// the summary does not call full, a word of the summary at a time.
    fn first_free(&self, from: usize, to: usize) -> Option<usize> {
        if from >= to {
            return None;
        }
        let w = from / 64;
        // Bits below `from` in its word count as used.
        let word = self.used.0[w] | ((1 << (from % 64)) - 1);
        if word != u64::MAX {
            let found = w * 64 + (!word).trailing_zeros() as usize;
            return (found < to).then_some(found);
        }
        let mut s = w + 1;
        while s < WORDS {
            let word = self.full[s / 64] | ((1 << (s % 64)) - 1);
            if word != u64::MAX {
                let w = s / 64 * 64 + (!word).trailing_zeros() as usize;
                let found = w * 64 + (!self.used.0[w]).trailing_zeros() as usize;
                return (found < to).then_some(found);
            }
            s = (s / 64 + 1) * 64;
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

    /// The allocator with the words the CPUs share.
    struct Sys {
        cpus: AsidCpus,
        a: AsidAllocator,
    }

    impl Sys {
        fn new(bits: u32) -> Sys {
            Sys {
                cpus: AsidCpus::new(),
                a: AsidAllocator::new(bits),
            }
        }

        fn run(&mut self, cpu: usize, tag: &AsidTag) -> Activation {
            self.a.activate(&self.cpus, cpu, tag, |w| w.fill(0))
        }

        fn fresh(&mut self, cpu: usize) -> (AsidTag, Activation) {
            let tag = AsidTag::default();
            let act = self.run(cpu, &tag);
            (tag, act)
        }

        fn current(&self, tag: &AsidTag) -> Option<u16> {
            self.cpus.current(tag)
        }

        fn release(&mut self, tag: &mut AsidTag) -> Option<u16> {
            self.a.release(&self.cpus, tag)
        }

        fn generation(&self) -> u64 {
            self.cpus.generation()
        }
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
        let mut s = Sys::new(8);
        assert_eq!(s.a.bits(), 8);
        assert_eq!(s.a.free_asids(), 255);
        let mut seen = HashSet::new();
        let mut tags = Vec::new();
        for _ in 0..255 {
            let (tag, act) = s.fresh(0);
            assert!(!act.flush_tlb);
            assert_ne!(act.asid, 0, "ASID 0 is the kernel's");
            assert!(seen.insert(act.asid), "ASID {} issued twice", act.asid);
            tags.push(tag);
        }
        assert_eq!(s.a.free_asids(), 0);
        assert_eq!(s.generation(), 1);
    }

    #[test]
    fn sixteen_bit_asids_run_from_1_to_65535() {
        let mut s = Sys::new(16);
        let mut seen = HashSet::new();
        for _ in 0..65535 {
            let (_, act) = s.fresh(0);
            assert!(!act.flush_tlb);
            assert_ne!(act.asid, 0);
            assert!(seen.insert(act.asid));
        }
        assert_eq!(s.a.free_asids(), 0);
        assert_eq!(s.generation(), 1);
    }

    #[test]
    fn the_fast_path_needs_a_tag_of_this_generation_and_a_full_active_word() {
        let mut s = Sys::new(16);
        let (tag, first) = s.fresh(0);
        assert_eq!(s.current(&tag), Some(first.asid));
        // CPU 0 ran a space: its active word is full, so the tag passes.
        assert_eq!(s.cpus.fast(0, &tag), Some(first.asid));
        // CPU 1 never ran one: the slow path begins its word.
        assert_eq!(s.cpus.fast(1, &tag), None);
        assert!(!s.run(1, &tag).flush_tlb);
        assert_eq!(s.cpus.fast(1, &tag), Some(first.asid));
        // A tag that never ran has no generation.
        assert_eq!(s.cpus.fast(0, &AsidTag::default()), None);
        assert_eq!(s.a.free_asids(), 65534);
    }

    /// The generation ends under CPU 0, which runs `a` (ASID 255); `b`
    /// begins the next.
    fn rolled_over() -> (Sys, AsidTag, AsidTag, Activation) {
        let mut s = Sys::new(8);
        let a = AsidTag::default();
        let mut keep = Vec::new();
        for i in 0..255 {
            if i == 254 {
                let _ = s.run(0, &a);
            } else {
                keep.push(s.fresh(0).0);
            }
        }
        let b = AsidTag::default();
        let act = s.run(0, &b);
        assert!(act.flush_tlb, "CPU 0 flushes at its own new generation");
        assert_eq!(s.generation(), 2);
        (s, a, b, act)
    }

    #[test]
    fn a_new_generation_leaves_the_flush_to_each_cpu() {
        let mut s = Sys::new(8);
        let tags: Vec<AsidTag> = (0..256).map(|_| AsidTag::default()).collect();
        for tag in &tags[..255] {
            let _ = s.run(0, tag);
        }
        let _ = s.run(1, &tags[0]);
        assert_eq!(s.generation(), 1);
        let act = s.run(0, &tags[255]);
        assert_eq!(s.generation(), 2);
        assert!(act.flush_tlb);
        // CPU 0 has flushed; CPU 1 owes its flush, and its active word is
        // empty, so no fast path hides it.
        assert_eq!(s.cpus.fast(1, &tags[255]), None);
        assert!(s.run(1, &tags[255]).flush_tlb);
        assert!(!s.run(1, &tags[255]).flush_tlb);
        assert_eq!(s.cpus.fast(1, &tags[255]), Some(act.asid));
        // CPU 2 has never run a space and owes the flush all the same.
        assert!(s.run(2, &tags[255]).flush_tlb);
    }

    #[test]
    fn the_asid_a_cpu_ran_at_the_end_of_a_generation_stays_with_its_space() {
        let (mut s, mut a, b, act) = rolled_over();
        // `a` was the last space CPU 0 ran: its number 255 is reserved, and
        // the new generation begins with ASID 1.
        assert_eq!(act.asid, 1);
        assert_eq!(s.current(&a), None);
        let again = s.run(1, &a);
        assert_eq!(again.asid, 255);
        assert_eq!(s.current(&a), Some(255));
        assert_eq!(s.current(&b), Some(1));
        assert_eq!(s.a.free_asids(), 253);
        assert_eq!(s.release(&mut a), Some(255));
    }

    #[test]
    fn a_space_the_cpus_did_not_reserve_gets_a_new_asid() {
        let mut s = Sys::new(8);
        let (mut old, first) = s.fresh(0);
        for _ in 0..254 {
            let _ = s.fresh(0);
        }
        // The last space CPU 0 ran holds 255; `old` has 1 and is not reserved.
        let (_, rollover) = s.fresh(1);
        assert!(!rollover.flush_tlb || s.generation() == 2);
        assert_eq!(s.generation(), 2);
        assert_eq!(s.current(&old), None);
        let again = s.run(2, &old);
        assert_ne!(again.asid, 0);
        assert_ne!(again.asid, rollover.asid, "two live spaces share an ASID");
        assert_ne!(again.asid, 255, "a reserved ASID went to another space");
        assert_eq!(first.asid, rollover.asid);
        // Releasing it frees the number it holds now, and a void tag nothing.
        assert_eq!(s.release(&mut old), Some(again.asid));
        assert_eq!(s.release(&mut old), None);
    }

    #[test]
    fn a_reserved_asid_of_a_space_that_goes_comes_free_with_a_tlbi() {
        let (mut s, mut a, _, _) = rolled_over();
        // `a` goes before it ran in the new generation: 255 comes free, and
        // the caller drops its TLB entries on every CPU.
        assert_eq!(s.release(&mut a), Some(255));
        assert_eq!(s.a.free_asids(), 254);
        let (_, other) = s.fresh(3);
        assert_ne!(other.asid, 0);
    }

    #[test]
    fn a_released_asid_is_issued_again_without_a_generation() {
        let mut s = Sys::new(8);
        let mut tags: Vec<AsidTag> = (0..255).map(|_| AsidTag::default()).collect();
        for tag in tags.iter() {
            let _ = s.run(0, tag);
        }
        assert_eq!(s.release(&mut tags[6]), Some(7));
        assert_eq!(s.a.free_asids(), 1);
        let (_, act) = s.fresh(0);
        assert_eq!(act.asid, 7);
        assert_eq!(s.generation(), 1);
    }

    #[test]
    fn a_released_tag_takes_no_cpu_into_the_next_generation() {
        let mut s = Sys::new(8);
        let (mut tag, _) = s.fresh(0);
        assert_eq!(s.cpus.fast(0, &tag), Some(1));
        let _ = s.release(&mut tag);
        assert_eq!(s.cpus.active[0].0.load(Relaxed), 0);
    }

    #[test]
    fn a_tag_that_never_ran_has_nothing_to_release() {
        let mut s = Sys::new(16);
        assert_eq!(s.current(&AsidTag::default()), None);
        assert_eq!(s.release(&mut AsidTag::default()), None);
        assert_eq!(s.a.free_asids(), 65535);
    }

    #[test]
    fn a_released_tag_releases_nothing_twice() {
        let mut s = Sys::new(8);
        let (mut tag, act) = s.fresh(0);
        let _ = s.fresh(0);
        assert_eq!(s.release(&mut tag), Some(act.asid));
        assert_eq!(tag.asid(), None, "a released tag keeps its claim");
        assert_eq!(s.release(&mut tag), None);
        assert_eq!(s.a.free_asids(), 254);
    }

    /// A generation is the same work however many ASIDs there are: the map
    /// goes in one `clear` and the CPUs' words are all it reads.
    #[test]
    fn a_new_generation_clears_the_map_once() {
        let mut s = Sys::new(16);
        for _ in 0..65535 {
            let _ = s.fresh(0);
        }
        let mut cleared = 0;
        let tag = AsidTag::default();
        let act = s.a.activate(&s.cpus, 0, &tag, |w| {
            cleared += 1;
            assert_eq!(w.len(), WORDS);
            w.fill(0)
        });
        assert_eq!(cleared, 1);
        assert!(act.flush_tlb);
        // The one CPU that ran a space reserved its number: 65534 left.
        assert_eq!(s.a.free_asids(), 65534 - 1);
    }

    /// Four CPUs run and drop 300 spaces on 8-bit ASIDs at random. After
    /// every step the spaces of this generation hold distinct ASIDs, none
    /// of them the kernel's or a number a CPU reserved, and the free count
    /// adds up.
    #[test]
    fn random_activations_and_releases_never_share_an_asid() {
        let mut s = Sys::new(8);
        let mut tags: Vec<AsidTag> = (0..300).map(|_| AsidTag::default()).collect();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = (x >> 8) as usize % tags.len();
            let cpu = (x >> 20) as usize % 4;
            if x.is_multiple_of(8) {
                let _ = s.release(&mut tags[i]);
            } else if s.cpus.fast(cpu, &tags[i]).is_none() {
                let _ = s.run(cpu, &tags[i]);
            }
            let mut seen = [false; 256];
            let mut used = 0;
            for asid in tags.iter().filter_map(|t| s.current(t)) {
                let asid = usize::from(asid);
                assert!(asid != 0 && !seen[asid], "step {step}: ASID {asid} twice");
                seen[asid] = true;
                used += 1;
            }
            let bit = |n: usize| s.a.used.0[n / 64] >> (n % 64) & 1 == 1;
            // Every number a current tag or a CPU holds is marked used, and
            // the free count is what the map says.
            assert!(
                (1..256).all(|n| !seen[n] || bit(n)),
                "step {step}: a tag's ASID is free"
            );
            assert!(
                s.a.reserved
                    .iter()
                    .filter(|r| **r != 0)
                    .all(|r| bit((*r & ASID_MASK) as usize)),
                "step {step}: a reserved ASID is free"
            );
            let marked = (1..256).filter(|&n| bit(n)).count();
            assert_eq!(s.a.free_asids() as usize, 255 - marked, "step {step}");
            assert!(marked >= used, "step {step}");
        }
        assert!(s.generation() > 50, "only {} generations", s.generation());
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
