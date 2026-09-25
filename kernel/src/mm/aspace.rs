// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Address spaces of processes (spec 7.2): the lower half, which TTBR0
//! translates, with tables from the frame allocator and user pages only,
//! and an ASID that tags its TLB entries, so a switch between processes
//! flushes nothing. Outside processes TTBR0 holds head.S's empty table with
//! ASID 0, the kernel's. Each table costs the quota of the space's process
//! a page (spec 7.5): the calls that take or give back tables name it.

use super::kmap::FrameTables;
use super::phys::FRAMES;
use crate::arch::{mmu, registers, symbols};
use crate::boot::Boot;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};
use kcore::asid::{self, AsidAllocator, AsidTag};
use kcore::frames::PAGE_SIZE;
use kcore::layout::image_pa;
use kcore::paging::{Attrs, MapError, PageTable, Release, TTBR_ROOT_MASK, TableMemory};
use kcore::quota::Account;
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

/// Tables from the frame allocator, each charged to `quota`: a table that
/// does not fit there is no memory. A charge that passed always finds its
/// frame (spec 7.8).
struct Charged<'a> {
    tables: FrameTables<'a>,
    quota: &'a mut Account,
}

// SAFETY: the tables are FrameTables', which keep that contract; the
// charge changes only the count.
unsafe impl TableMemory for Charged<'_> {
    fn alloc_table(&mut self) -> Option<u64> {
        self.quota.charge(PAGE_SIZE).ok()?;
        let table = self.tables.alloc_table();
        Some(table.expect("a charge that passed found no frame (spec 7.8)"))
    }

    fn free_table(&mut self, pa: u64) {
        self.tables.free_table(pa);
        self.quota.refund(PAGE_SIZE);
    }

    fn read(&self, pa: u64) -> u64 {
        self.tables.read(pa)
    }

    fn write(&mut self, pa: u64, value: u64) {
        self.tables.write(pa, value)
    }
}

/// `with_tables` with every table taken or given back charged to `quota`.
fn with_charged<R>(quota: &mut Account, f: impl FnOnce(&mut Charged<'_>) -> R) -> R {
    let mut guard = FRAMES.lock();
    f(&mut Charged {
        tables: FrameTables {
            frames: guard.as_mut().expect("frame allocator"),
        },
        quota,
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
        // space, which `retire` consumes after it takes TTBR0 off them;
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

/// The lower half of one process. `retire` consumes the space, and its
/// tables go back through the release it returns, so no method can reach
/// them afterwards; a space dropped without it stops the kernel. The
/// frames its pages map belong to others and stay. Every method takes the
/// frame allocator's lock or the ASID allocator's, one at a time and
/// never one inside the other, so none may be called while the caller
/// holds either.
pub struct AddressSpace {
    tables: PageTable,
    tag: AsidTag,
}

impl AddressSpace {
    /// An empty address space: one root table, charged to `quota`, and no
    /// ASID until it first runs.
    pub fn new(quota: &mut Account) -> Result<AddressSpace, MapError> {
        Ok(AddressSpace {
            tables: with_charged(quota, |mem| PageTable::new(mem))?,
            tag: AsidTag::default(),
        })
    }

    /// Maps `[va, va + size)` to the frames at `[pa, pa + size)`, page by
    /// page, with user attributes (EL0 access, nG, never executable by the
    /// kernel); the tables it takes are charged to `quota`. On error part
    /// of the range may already be mapped. Code the kernel wrote into the
    /// frames needs the instruction cache made coherent
    /// (arch::cache::sync_icache) before a mapping with `Attrs::USER_TEXT`
    /// runs it.
    pub fn map(
        &mut self,
        va: usize,
        pa: u64,
        size: u64,
        attrs: Attrs,
        quota: &mut Account,
    ) -> Result<(), MapError> {
        let result = with_charged(quota, |mem| {
            self.tables.map_user(mem, va as u64, pa, size, attrs)
        });
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

    /// Takes TTBR0 off the tables and drops their TLB entries with the
    /// ASID, which is free again afterwards (kcore::tlb::retire). The space
    /// is consumed: nothing maps, unmaps, translates or runs through it any
    /// more, and no walk reaches the tables, so they may go back in any
    /// order and at any pace, through the release this returns (spec 7.7).
    pub fn retire(self) -> SpaceRelease {
        // `drop` is for a space that never came here, and the tag has
        // nothing to drop.
        let mut space = ManuallyDrop::new(self);
        let (root, empty) = (space.tables.root(), empty_root());
        with_asids(|a| tlb::retire(a, &mut space.tag, root, empty, &mut Cpu));
        // SAFETY: the space is never dropped or used again, so the tables
        // pass to the release, the only value that names them from now on.
        let tables = unsafe { core::ptr::read(&space.tables) };
        SpaceRelease {
            tables: tables.into_release(),
            spent: false,
        }
    }

    /// `retire`, then every step of the release in a row, the tables
    /// refunded to `quota`. The work grows with the number of tables and
    /// runs with interrupts masked: for tests and for a process that never
    /// got its object; processes give their tables back a portion at a time.
    pub fn destroy(self, quota: &mut Account) {
        let mut release = self.retire();
        while !release.step(quota) {}
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Only a check: the work is `retire`'s, which takes two locks and
        // consumes the space without dropping it, while a drop may happen
        // anywhere. Reaching here means the tables were never freed.
        panic!("address space dropped without retire");
    }
}

/// The tables of a retired space on their way back to the frame allocator
/// (kcore::paging::Release). It has one owner, the process at the stage
/// Space, and a release dropped before its last table went stops the
/// kernel.
pub struct SpaceRelease {
    tables: Release,
    /// Every table went back.
    spent: bool,
}

impl SpaceRelease {
    /// One step: at most 512 entries read and at most one table back to
    /// the allocator and refunded to `quota`, the root last. True once
    /// every table went, and on every step after that.
    pub fn step(&mut self, quota: &mut Account) -> bool {
        if !self.spent {
            self.spent = with_charged(quota, |mem| self.tables.step(mem));
        }
        self.spent
    }

    /// Tables given back so far.
    #[cfg(feature = "ktest")]
    pub fn freed(&self) -> usize {
        self.tables.freed()
    }
}

impl Drop for SpaceRelease {
    fn drop(&mut self) {
        // Only a check, as for AddressSpace: the work is `step`'s.
        assert!(self.spent, "a space dropped before its tables went");
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
