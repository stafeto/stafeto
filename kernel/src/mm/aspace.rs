// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Address spaces of processes (spec 7.2): the lower half, which TTBR0
//! translates, with tables from the frame allocator and user pages only,
//! and an ASID that tags its TLB entries, so a switch between processes
//! flushes nothing. Outside processes TTBR0 holds head.S's empty table with
//! ASID 0, the kernel's.

use super::kmap::FrameTables;
use super::phys::FRAMES;
use crate::arch::{mmu, registers, symbols};
use crate::boot::Boot;
use core::sync::atomic::{AtomicU64, Ordering};
use kcore::asid::{self, AsidAllocator, AsidTag};
use kcore::layout::image_pa;
use kcore::paging::{Attrs, MapError, PageTable, TTBR_ROOT_MASK};
use kcore::sync::Lock;
use kcore::tlb::{self, Mmu};

static ASIDS: Lock<Option<AsidAllocator>> = Lock::new(None);

/// Physical address of head.S's empty root table; zero until `init`.
static EMPTY_ROOT: AtomicU64 = AtomicU64::new(0);

/// Starts the ASID allocator with the width the CPU allows (head.S set
/// TCR_EL1.AS by the same rule) and notes where the empty table lies.
pub fn init(boot: &Boot) {
    EMPTY_ROOT.store(
        image_pa(boot.kernel_pa, symbols::empty_table()),
        Ordering::Relaxed,
    );
    let bits = asid::asid_bits(registers::id_aa64mmfr0_el1());
    *ASIDS.lock() = Some(AsidAllocator::new(bits));
}

fn with_asids<R>(f: impl FnOnce(&mut AsidAllocator) -> R) -> R {
    f(ASIDS.lock().as_mut().expect("ASID allocator"))
}

fn with_tables<R>(f: impl FnOnce(&mut FrameTables<'_>) -> R) -> R {
    let mut guard = FRAMES.lock();
    f(&mut FrameTables {
        frames: guard.as_mut().expect("frame allocator"),
    })
}

fn empty_root() -> u64 {
    let empty = EMPTY_ROOT.load(Ordering::Relaxed);
    assert!(empty != 0, "address spaces are used before aspace::init");
    empty
}

/// Points TTBR0 at the empty table with ASID 0: no user address translates.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "the idle loop (milestone 1.2c) leaves user tables; so far only the kernel tests do"
    )
)]
pub fn deactivate() {
    // SAFETY: the empty table maps nothing.
    unsafe { mmu::set_ttbr0(asid::ttbr0(empty_root(), 0)) };
}

/// This CPU's TTBR0 and TLB, in the order kcore::tlb gives. Only this
/// module makes one, and it hands kcore::tlb nothing but the roots of live
/// address spaces and the empty table.
struct Cpu;

impl Mmu for Cpu {
    fn ttbr0(&self) -> u64 {
        registers::ttbr0_el1()
    }

    fn set_ttbr0(&mut self, ttbr: u64) {
        // SAFETY: the tables map user pages only and live as long as their
        // space, which `destroy` consumes after it takes TTBR0 off them;
        // the empty table maps nothing.
        unsafe { mmu::set_ttbr0(ttbr) }
    }

    fn tables_written(&mut self) {
        mmu::tables_written()
    }

    fn flush_all(&mut self) {
        mmu::flush_tlb()
    }

    fn invalidate_page(&mut self, operand: u64) {
        mmu::invalidate_page(operand)
    }

    fn invalidate_asid(&mut self, operand: u64) {
        mmu::invalidate_asid(operand)
    }
}

/// The lower half of one process. `destroy` consumes the space and frees
/// its tables, so no method can reach them afterwards; a space dropped
/// without it stops the kernel. The frames its pages map belong to others
/// and stay. Every method takes the frame allocator's lock or the ASID
/// allocator's, one at a time and never one inside the other, so none may
/// be called while the caller holds either.
pub struct AddressSpace {
    tables: PageTable,
    tag: AsidTag,
}

impl AddressSpace {
    /// An empty address space: one root table, no ASID until it first runs.
    pub fn new() -> Result<AddressSpace, MapError> {
        Ok(AddressSpace {
            tables: with_tables(|mem| PageTable::new(mem))?,
            tag: AsidTag::default(),
        })
    }

    /// Maps `[va, va + size)` to the frames at `[pa, pa + size)`, page by
    /// page, with user attributes (EL0 access, nG, never executable by the
    /// kernel). On error part of the range may already be mapped. Code the
    /// kernel wrote into the frames needs the instruction cache made
    /// coherent (arch::cache::sync_icache) before a mapping with
    /// `Attrs::USER_TEXT` runs it.
    pub fn map(&mut self, va: usize, pa: u64, size: u64, attrs: Attrs) -> Result<(), MapError> {
        let result = with_tables(|mem| self.tables.map_user(mem, va as u64, pa, size, attrs));
        // An entry that turns valid needs no TLB maintenance: the stores
        // only have to reach the table walker.
        mmu::tables_written();
        result
    }

    /// Unmaps the page at `va`, drops its TLB entry and returns the frame
    /// it mapped. The cleared descriptor reaches the table walker before
    /// this returns, also when the space has no ASID and so no TLB entry
    /// (kcore::tlb::forget_page): the frame may go elsewhere right after.
    pub fn unmap(&mut self, va: usize) -> Result<u64, MapError> {
        let pa = with_tables(|mem| self.tables.unmap_page(mem, va as u64))?;
        with_asids(|a| tlb::forget_page(a, &self.tag, va as u64, &mut Cpu));
        Ok(pa)
    }

    /// Physical address and leaf descriptor that `va` translates to.
    pub fn translate(&self, va: usize) -> Option<(u64, u64)> {
        with_tables(|mem| self.tables.translate(mem, va as u64))
    }

    /// The space's ASID, when it has one of this generation.
    #[cfg_attr(
        not(feature = "ktest"),
        expect(dead_code, reason = "only the kernel tests ask for the ASID so far")
    )]
    pub fn asid(&self) -> Option<u16> {
        with_asids(|a| a.current(&self.tag))
    }

    /// Whether TTBR0 holds this space's tables. The space in TTBR0 always
    /// has an ASID of this generation: a new generation begins only in the
    /// `activate` of another space, which then takes TTBR0.
    pub fn is_active(&self) -> bool {
        registers::ttbr0_el1() & TTBR_ROOT_MASK == self.tables.root()
    }

    /// Switches TTBR0 to this space, with a new ASID when its old one is of
    /// an earlier generation (kcore::tlb::switch_to).
    pub fn activate(&mut self) {
        let (root, empty) = (self.tables.root(), empty_root());
        with_asids(|a| tlb::switch_to(a, &mut self.tag, root, empty, &mut Cpu));
    }

    /// Takes TTBR0 off the tables, drops their TLB entries with the ASID,
    /// which is free again afterwards (kcore::tlb::retire), and gives the
    /// tables back to the frame allocator. The work grows with the number of
    /// tables and runs with interrupts masked; milestone 1.3 splits it into
    /// portions through the cleanup queue (spec 7.7).
    pub fn destroy(mut self) {
        let (root, empty) = (self.tables.root(), empty_root());
        with_asids(|a| tlb::retire(a, &mut self.tag, root, empty, &mut Cpu));
        with_tables(|mem| PageTable::from_root(root).release(mem));
        // The tables are gone with the only value that named them. Neither
        // field has anything to drop, and `drop` is for a space that never
        // came here.
        core::mem::forget(self);
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Only a check: the work is `destroy`'s, which takes two locks and
        // consumes the space without dropping it, while a drop may happen
        // anywhere. Reaching here means the tables were never freed.
        panic!("address space dropped without destroy");
    }
}

/// Width of the ASIDs the allocator hands out.
#[cfg(feature = "ktest")]
pub fn asid_bits() -> u32 {
    with_asids(|a| a.bits())
}

#[cfg(feature = "ktest")]
pub fn asid_generation() -> u64 {
    with_asids(|a| a.generation())
}

/// Takes every ASID still free in this generation, so that the next
/// activation of a space without one begins a new generation.
#[cfg(feature = "ktest")]
pub fn use_up_asids() {
    with_asids(|a| {
        for _ in 0..a.free_asids() {
            let _ = a.activate(&mut AsidTag::default());
        }
    });
}
