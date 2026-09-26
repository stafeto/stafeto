// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Memory objects (spec 4, 7.3, 7.7): pages whose frames the object owns,
//! taken and zeroed whole when it is made. The quota of the process that
//! makes it, its payer, pays at once for the pages and the nodes of their
//! list (kcore::pagelist), which make the object's own budget, and for
//! its place in the payer's pool of memory objects by the page (spec 7.5,
//! 7.8); the object holds the payer's shell, and its frames are charged
//! to its budget, which goes back to the payer whole with the place.
//! `create` makes an object with no frame, and `fill` takes up to
//! CREATE_PORTION frames a portion, so that mem_create goes in portions
//! with interrupts polled between them (spec 7.7): meanwhile the reference
//! `create` hands out, which the thread that makes the object holds
//! (thread::Long::Create), is its only one, and no handle names it. An
//! object lives while references to it are left: its handles and that
//! one. The last one queues it for cleanup, whose portions give its frames
//! back, up to kcore::pagelist::RELEASE_STEP a portion, and then its place
//! and its budget.

use crate::cleanup::{self, Item};
use crate::mm::phys::{self, Frame, LinearMem};
use crate::object::{Live, Object, Refs};
use crate::process::{self, Process};
use abi::{Error, MemoryInfo};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::frames::PhysMem;
use kcore::pagelist::{self, ListMemory, PageList};
use kcore::quota::Account;

/// Pages one portion of mem_create takes and zeroes, at most (spec 7.7).
pub const CREATE_PORTION: usize = 8;

/// A memory object (spec 7.3): pages whose frames it takes whole when it
/// is made and gives back in portions once nothing refers to it (spec
/// 7.7); its handles and the long call that makes it keep it (spec 4).
pub struct Memory {
    /// Where its frames come from.
    backing: Backing,
    /// What its frames are charged to: its pages and the nodes of their
    /// list, which the payer's quota paid for at once (spec 7.5).
    budget: Account,
    /// Its handles, and the reference `create` hands out while the object
    /// is made: the references that keep it.
    refs: Refs,
    /// Its mappings now (object_info MEMORY).
    mappings: u32,
    /// The process whose pool holds it and whose quota paid its budget; the
    /// object holds its shell until the place goes back.
    payer: NonNull<Process>,
    /// Its place in the cleanup queue once nothing refers to it.
    cleanup: Item,
}

/// Where the frames of a memory object come from.
enum Backing {
    /// Frames of its own, in a list that fills while the object is made
    /// and goes back in portions once nothing refers to it.
    Owned(PageList),
}

// SAFETY: memory objects are reached under the kernel's rules (spec 8.1):
// one CPU, interrupts masked inside the kernel.
unsafe impl Send for Memory {}

/// Memory objects whose places have not gone back.
static LIVE: Live = Live::new();

/// Frames of a memory object from the frame allocator, each charged to the
/// object's budget (phys::alloc_zeroed, phys::free), and the words of the
/// nodes of its list through the linear map.
struct Budget<'a>(&'a mut Account);

// SAFETY: a frame comes zeroed from the allocator and is the list's until
// `free_frame`, which gives it back once no table maps it: an object goes
// only once nothing refers to it (spec 7.7). Words go through the linear
// map, which covers all RAM, and the list touches only its own nodes.
unsafe impl ListMemory for Budget<'_> {
    fn alloc_frame(&mut self) -> u64 {
        let frame = phys::alloc_zeroed(0, self.0);
        frame
            .expect("the budget of a memory object covers its frames")
            .into_raw()
    }

    fn free_frame(&mut self, pa: u64) {
        // SAFETY: the list gives back a frame of order 0 that `alloc_frame`
        // took.
        unsafe { phys::free(Frame::from_raw(pa, 0), self.0) }
    }

    fn read(&self, pa: u64) -> u64 {
        // SAFETY: the list reads its own nodes.
        unsafe { LinearMem::new() }.read(pa)
    }

    fn write(&mut self, pa: u64, value: u64) {
        // SAFETY: the list writes its own nodes.
        unsafe { LinearMem::new() }.write(pa, value)
    }
}

/// An object of `pages` pages, 1 to kcore::pagelist::MAX_PAGES, with no
/// frame yet, which `payer`, the process of the thread that makes it, pays
/// for (spec 7.3, 7.5): first a place in the payer's pool of memory
/// objects, whose page the payer's quota pays for when the pool grows,
/// then the budget, the pages and the nodes of their list, charged to the
/// payer's quota at once. NO_MEMORY when the quota falls short for
/// either, and nothing stays but a page of the pool. The object holds the
/// payer's shell; the caller gets the first reference.
pub fn create(payer: NonNull<Process>, pages: usize) -> Result<NonNull<Memory>, Error> {
    let bytes = (pages + pagelist::nodes(pages)) as u64 * PAGE_SIZE;
    let memory = Memory {
        backing: Backing::Owned(PageList::new(pages)),
        budget: Account::new(bytes),
        refs: Refs::one(),
        mappings: 0,
        payer,
        cleanup: Item::new(),
    };
    let m = process::paid_alloc(payer, memory)?;
    if let Err(e) = process::charge(payer, bytes) {
        // SAFETY: the object was just made, nothing else refers to it, and
        // its list holds no frame.
        unsafe { process::paid_free(payer, m) };
        return Err(e);
    }
    process::retain_shell(payer);
    LIVE.made();
    Ok(m)
}

/// One portion of the making of `m` (spec 7.7): up to CREATE_PORTION of
/// its frames from its budget, zeroed, in the order of its pages, and the
/// nodes they need. True once every page has its frame. O(1).
pub fn fill(m: NonNull<Memory>) -> bool {
    // SAFETY: the caller holds the object's only reference
    // (thread::Long::Create); only the fields are borrowed.
    let (backing, budget) = unsafe { (&mut (*m.as_ptr()).backing, &mut (*m.as_ptr()).budget) };
    match backing {
        Backing::Owned(list) => list.fill(&mut Budget(budget), CREATE_PORTION),
    }
}

/// object_info MEMORY of `m`, which the caller holds (spec 11): its size in
/// bytes, the pages whose frames it owns, every page once it is whole, and
/// its mappings.
pub fn info(m: NonNull<Memory>) -> MemoryInfo {
    // SAFETY: the caller holds a reference to the object; only the fields
    // are read.
    let (backing, mappings) = unsafe { (&(*m.as_ptr()).backing, (*m.as_ptr()).mappings) };
    let Backing::Owned(list) = backing;
    MemoryInfo {
        size: list.pages() as u64 * PAGE_SIZE,
        pages: list.filled() as u64,
        mappings: mappings.into(),
    }
}

/// The count of references to `m`, through the raw pointer.
///
/// # Safety
/// `m` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(m: NonNull<Memory>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*m.as_ptr()).refs }
}

/// Adds a reference to `m`: a new handle (spec 4).
pub fn retain(m: NonNull<Memory>) {
    // SAFETY: the caller holds a reference to the object; only the count is
    // touched.
    unsafe { refs(m) }.retain();
}

/// Drops a reference to `m`; the last one queues the object for cleanup at
/// `cause` (spec 7.7). O(1).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it
/// afterwards.
pub unsafe fn release(m: NonNull<Memory>, cause: u8) {
    // SAFETY: the caller's reference keeps the object alive until here; the
    // pool keeps it in place until its portions.
    unsafe {
        if refs(m).release() {
            let item = NonNull::new_unchecked(&raw mut (*m.as_ptr()).cleanup);
            cleanup::enqueue(item, Object::Memory(m), cause);
        }
    }
}

/// A portion of an object nobody refers to (cleanup::portion), at `level`
/// (spec 7.7): up to kcore::pagelist::RELEASE_STEP of its frames, pages and
/// then nodes, go back to the frame allocator, each refunded to its
/// budget, and with frames left the object goes back to the head of
/// `level`. Once none is left its place goes back to the payer's pool, its
/// budget to the payer's quota, and its reference to the payer's shell
/// goes, which may queue the shell at `level`. O(1): at most RELEASE_STEP
/// frames.
///
/// # Safety
/// Nothing refers to the object, and it is in no queue.
pub unsafe fn clean(m: NonNull<Memory>, level: u8) {
    let p = m.as_ptr();
    // SAFETY: the caller's promise; only the fields are borrowed.
    let (backing, budget) = unsafe { (&mut (*p).backing, &mut (*p).budget) };
    let done = match backing {
        Backing::Owned(list) => list.release_step(&mut Budget(budget)),
    };
    if !done {
        // SAFETY: the object stays alive and in place until its next
        // portion.
        unsafe {
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::requeue(item, Object::Memory(m), level);
        }
        return;
    }
    // SAFETY: as above; only the fields are read.
    let (payer, paid) = unsafe { ((*p).payer, (*p).budget) };
    assert!(
        paid.used() == 0,
        "a memory object goes with frames charged to it"
    );
    // SAFETY: nothing uses the object afterwards; the payer's pool is
    // there, since the object holds the payer's shell.
    unsafe {
        process::paid_free(payer, m);
        LIVE.gone(m);
    }
    process::refund(payer, paid.limit());
    // SAFETY: the object's reference to its payer's shell goes with it.
    unsafe { process::release_shell(payer, level) };
}

// The poison of an object that went (Live::gone) reaches its count.
const _: () = assert!(core::mem::offset_of!(Memory, refs) >= 8);

#[cfg(feature = "ktest")]
pub use test_access::{filled, frame, in_use, payer};

/// What the kernel tests read here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Memory objects whose places have not gone back.
    pub fn in_use() -> usize {
        LIVE.count()
    }

    /// The pages of `m`, which the test knows alive, that have their frames.
    pub fn filled(m: NonNull<Memory>) -> usize {
        // SAFETY: the test knows the object alive; only the field is read.
        let Backing::Owned(list) = unsafe { &(*m.as_ptr()).backing };
        list.filled()
    }

    /// The frame of page `i` of `m`, which the test holds, and which has
    /// the frame.
    pub fn frame(m: NonNull<Memory>, i: usize) -> u64 {
        // SAFETY: as in `filled`; the list reads its nodes through the
        // linear map.
        let (backing, budget) = unsafe { (&(*m.as_ptr()).backing, &mut (*m.as_ptr()).budget) };
        let Backing::Owned(list) = backing;
        list.frame(&Budget(budget), i)
    }

    /// The process that pays for `m`, which the test holds.
    pub fn payer(m: NonNull<Memory>) -> NonNull<Process> {
        // SAFETY: the test holds a reference to the object; only the field is
        // read.
        unsafe { (*m.as_ptr()).payer }
    }
}
