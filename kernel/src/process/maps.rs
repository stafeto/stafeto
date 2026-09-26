// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The mappings of a process (spec 7.4, 7.5, 7.7): a table of up to
//! abi::MAX_MAPPINGS entries (kcore::maps) in a block of the process's pool
//! of blocks, which the process pays for whoever maps into it. An entry
//! shows pages of a memory object and holds a reference to it, so the
//! object lives while it is mapped anywhere. mem_map, mem_unmap and
//! mem_protect change one entry a portion at a time, PORTION pages, or
//! EXEC_PORTION when the pages become executable, with how far they came
//! kept in the calling thread (thread::Long) and the entry marked busy
//! meanwhile; every portion first checks that the process lives. mem_map
//! charges the tables its range may take to the process's quota up front
//! (kcore::paging::tables_bound), so that its portions never fail, and
//! gives back what they did not take; the tables stay until the space
//! goes. The entries go at the stage Mappings, after the stage Space took
//! the ASID and with it every TLB entry of the process.

use super::*;
use crate::arch::cache;
use crate::memory;
use crate::thread::Long;
use abi::Access;
use core::mem::{MaybeUninit, align_of, size_of};
use kcore::maps::{Mapping, Maps};

/// The mapping table of a process: MAX_MAPPINGS entries in one block of
/// its pool of blocks.
pub type Table = Maps<NonNull<Memory>>;

const _: () =
    assert!(size_of::<Table>() <= size_of::<Block>() && align_of::<Table>() <= align_of::<Block>());

/// Pages a portion of mem_map, mem_unmap or mem_protect takes at most
/// (spec 7.7).
pub const PORTION: u32 = 32;

/// Pages a portion takes at most when they become executable (mem_map or
/// mem_protect with RX): the instruction cache is made coherent for each
/// of them first (spec 7.4, 7.7).
pub const EXEC_PORTION: u32 = 8;

/// The entry of the table of `target` that a long call changes (spec 7.7),
/// by its index, which stays while the entry is busy, and its pages the
/// call is done with, from its start. The call holds a reference to
/// `target`, so its quota is there to refund, though the process may end
/// meanwhile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub target: NonNull<Process>,
    index: u32,
    done: u32,
}

/// The mapping table of `process`, if it has one.
///
/// # Safety
/// `process` is alive, and nothing else borrows its table meanwhile.
pub(super) unsafe fn table<'a>(process: NonNull<Process>) -> Option<&'a mut Table> {
    // SAFETY: the caller's promise; the block holds the table from its
    // first mapping on (`add_mapping`).
    unsafe { (*process.as_ptr()).maps.map(|t| &mut *t.as_ptr()) }
}

/// The entry `on` changes, which is in the table of its process.
///
/// # Safety
/// As for `table`; the process lives, so the entry is there.
unsafe fn entry(on: &Change) -> Mapping<NonNull<Memory>> {
    // SAFETY: the caller's promise.
    let table = unsafe { table(on.target) }.expect("a table with a busy entry");
    *table.get(on.index as usize)
}

/// The address space of `process`, which lives.
///
/// # Safety
/// As for `table`.
unsafe fn space<'a>(process: NonNull<Process>) -> &'a mut AddressSpace {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { (*process.as_ptr()).space() }
}

/// The address of page `page` of `m`.
fn page_address(m: &Mapping<NonNull<Memory>>, page: u32) -> u64 {
    m.start + (u64::from(page) << kcore::PAGE_SHIFT)
}

/// INVALID_ARGS when `pages` pages from `va` touch a page of `process`
/// that a mapping or the message buffer of one of its threads holds (spec
/// 6.2, 7.4): step (5) of mem_map. The threads are those that have not
/// ended, at most abi::MAX_THREADS; the blocks of `map_frames`, at most
/// MAX_BLOCKS, count too. The caller holds a reference to the process.
pub fn check_free(process: NonNull<Process>, va: u64, pages: u64) -> Result<(), Error> {
    let end = va + (pages << kcore::PAGE_SHIFT);
    // SAFETY: the caller holds a reference to the process; only the table,
    // the blocks and the list of threads are read.
    unsafe {
        if let Some(table) = table(process) {
            table.check_free(va, pages)?;
        }
        if (*process.as_ptr()).frames.overlaps(va, end) {
            return Err(Error::InvalidArgs);
        }
        let mut next = (*process.as_ptr()).threads;
        while let Some(t) = next {
            if thread::buffer_page(t).is_some_and(|b| (va..end).contains(&(b as u64))) {
                return Err(Error::InvalidArgs);
            }
            next = (*t.as_ptr()).siblings.and_then(|s| s.next);
        }
    }
    Ok(())
}

/// Whether page `va` of `process`, which the caller holds, lies in one of
/// its mappings, whose pages may not be mapped yet (thread_create, spec
/// 6.2).
pub fn in_mapping(process: NonNull<Process>, va: usize) -> bool {
    // SAFETY: the caller holds a reference to the process; only the table
    // is read.
    unsafe { table(process) }.is_some_and(|t| t.check_free(va as u64, 1).is_err())
}

/// The resources of mem_map, step (6), and its entry, `mapping`, whose
/// range the call checked (`check_free`): LIMIT_REACHED when `target`
/// has abi::MAX_MAPPINGS mappings; NO_MEMORY when its quota falls short for
/// the block of its table at its first mapping, whose page its pool of
/// blocks takes, or for the most tables the range may take, which are
/// charged to it now (spec 7.5). A failure changes nothing but the block,
/// which stays the table's. Then the entry goes in, busy, with a new
/// reference to its object; returns the change, and the bytes charged for
/// tables. The caller holds a reference to `target`, which lives.
pub fn add_mapping(
    target: NonNull<Process>,
    mapping: Mapping<NonNull<Memory>>,
) -> Result<(Change, u64), Error> {
    let p = target.as_ptr();
    // SAFETY: the caller's promise; only these fields are borrowed.
    unsafe {
        if table(target).is_some_and(|t| t.len() == kcore::maps::MAX_MAPPINGS) {
            return Err(Error::LimitReached);
        }
        if (*p).maps.is_none() {
            let (pools, quota, log) = (&mut (*p).pools, &mut (*p).quota, &mut (*p).pages);
            let block = pools
                .blocks
                .alloc(
                    &mut PaidPages::new(KernelPages, quota, log),
                    MaybeUninit::uninit(),
                )
                .map_err(|_| Error::NoMemory)?;
            let t = block.cast::<Table>();
            t.write(Table::new());
            (*p).maps = Some(t);
        }
    }
    let prepaid = kcore::paging::tables_bound(mapping.start, mapping.pages.into()) * PAGE_SIZE;
    charge(target, prepaid)?;
    // SAFETY: as above.
    let table = unsafe { table(target) }.expect("the table was just made");
    let index = table
        .insert(mapping)
        .expect("a table with room takes a checked entry");
    table.set_busy(index, true);
    memory::retain_mapping(mapping.object);
    let on = Change {
        target,
        index: index as u32,
        done: 0,
    };
    Ok((on, prepaid))
}

/// The entry of exactly `pages` pages from `va` in the table of `target`,
/// which the caller holds, that no long call works on: its index and the
/// rights it was mapped with (spec 7.4, 7.7). INVALID_ARGS when no mapping
/// is that range, BAD_STATE when a long call works on it: steps (5) of
/// mem_unmap and mem_protect.
pub fn find_mapping(target: NonNull<Process>, va: u64, pages: u64) -> Result<(u32, Rights), Error> {
    // SAFETY: the caller holds a reference to the process; only the table
    // is read.
    let table = unsafe { table(target) }.ok_or(Error::InvalidArgs)?;
    let index = table.find_idle(va, pages)?;
    Ok((index as u32, table.get(index).rights))
}

/// Marks entry `index` of the table of `target`, which `find_mapping`
/// found, busy for a long call, and returns the change it begins.
pub fn begin_change(target: NonNull<Process>, index: u32) -> Change {
    // SAFETY: the caller holds a reference to the process, which lives.
    let table = unsafe { table(target) }.expect("a table with the entry");
    table.set_busy(index as usize, true);
    Change {
        target,
        index,
        done: 0,
    }
}

/// One portion of `long`, a mem_map, mem_unmap or mem_protect (spec 7.4,
/// 7.7): BAD_STATE when its process ended, and nothing is touched; else
/// up to PORTION pages of the entry, EXEC_PORTION when they become
/// executable, from where the call stopped: mem_map maps them to the
/// frames of the object, with tables from what it paid for up front;
/// mem_unmap unmaps them; mem_protect gives them the new access. Pages
/// that become executable have the instruction cache made coherent first
/// ([G18]); the TLB entries of pages unmapped or changed go before the
/// portion ends ([G13]). True once every page of the entry is done.
pub fn step_change(long: &mut Long) -> Result<bool, Error> {
    let (on, access) = match *long {
        Long::Map { on, access, .. } | Long::Protect { on, access } => (on, Some(access)),
        Long::Unmap { on } => (on, None),
        Long::Create(_) => unreachable!("mem_create changes no mapping"),
    };
    check_alive(on.target)?;
    // SAFETY: the process lives, and the entry is the call's.
    let (m, space) = unsafe { (entry(&on), space(on.target)) };
    let exec = access == Some(Access::ReadExec);
    let n = if exec { EXEC_PORTION } else { PORTION }.min(m.pages - on.done);
    let va = page_address(&m, on.done);
    let mut frames = [0; PORTION as usize];
    let frames = &mut frames[..n as usize];
    if exec || matches!(long, Long::Map { .. }) {
        for (i, f) in frames.iter_mut().enumerate() {
            *f = memory::frame(m.object, (m.offset + on.done) as usize + i);
        }
    }
    if exec {
        cache::sync_icache_frames(frames);
    }
    match (long, access.map(Attrs::user)) {
        (Long::Map { prepaid, on, .. }, Some(attrs)) => {
            space.map_pages(va, frames, attrs, prepaid);
            on.done += n;
        }
        (Long::Protect { on, .. }, Some(attrs)) => {
            space.protect_pages(va, n.into(), attrs);
            on.done += n;
        }
        (Long::Unmap { on }, None) => {
            space.unmap_pages(va, n.into());
            on.done += n;
        }
        _ => unreachable!("a change of a mapping has its access"),
    }
    if exec {
        crate::testpoint::code_mapped(frames);
    }
    Ok(on.done + n == m.pages)
}

/// The end of `long` after its last portion (spec 7.4, 7.7): the entry of
/// mem_map or mem_protect goes idle, and what mem_map did not spend on
/// tables goes back to the quota of the process; the entry of mem_unmap
/// leaves the table, and its reference to the object goes at `cause`.
///
/// # Safety
/// `long` ended with its last portion, its process lives, and nothing uses
/// it afterwards.
pub unsafe fn finish_change(long: Long, cause: u8) {
    match long {
        Long::Map { on, prepaid, .. } => {
            // SAFETY: the caller's promise.
            unsafe { table(on.target) }
                .expect("a table with a busy entry")
                .set_busy(on.index as usize, false);
            refund(on.target, prepaid);
        }
        Long::Protect { on, .. } => {
            // SAFETY: as above.
            unsafe { table(on.target) }
                .expect("a table with a busy entry")
                .set_busy(on.index as usize, false);
        }
        Long::Unmap { on } => {
            // SAFETY: as above.
            let m = unsafe { table(on.target) }
                .expect("a table with a busy entry")
                .remove(on.index as usize);
            // SAFETY: the entry went, and its reference with it.
            unsafe { memory::release_mapping(m.object, cause) };
        }
        Long::Create(_) => unreachable!("mem_create changes no mapping"),
    }
}

/// `long` stops for good midway (spec 7.7): its thread ended with its
/// process, or its `svc` changed, or its process ended. While the process
/// lives, its entry keeps what the portions did, in O(1): mem_map's keeps
/// the pages it mapped, and leaves the table without one; mem_unmap's
/// loses the pages it unmapped, and leaves without one left; mem_protect's
/// goes idle with some pages of the new access and the rest of the old,
/// each within the rights of the entry and W^X. An entry that went leaves
/// its reference to the object at `cause`. A process that ended keeps its
/// entries for its stage Mappings, and the call touches none of its tables.
/// What mem_map did not spend on tables goes back to the quota either way.
///
/// # Safety
/// Nothing uses `long` afterwards.
pub unsafe fn abandon_change(long: Long, cause: u8) {
    let on = match long {
        Long::Map { on, .. } | Long::Protect { on, .. } | Long::Unmap { on } => on,
        Long::Create(_) => unreachable!("mem_create changes no mapping"),
    };
    if check_alive(on.target).is_ok() {
        // SAFETY: the process lives, and the entry is the call's.
        let table = unsafe { table(on.target) }.expect("a table with a busy entry");
        let index = on.index as usize;
        let gone = match long {
            Long::Map { .. } => table.shrink_to(index, on.done),
            Long::Unmap { .. } => table.drop_prefix(index, on.done),
            _ => {
                table.set_busy(index, false);
                None
            }
        };
        if let Some(object) = gone {
            // SAFETY: the entry went, and its reference with it.
            unsafe { memory::release_mapping(object, cause) };
        }
    }
    if let Long::Map { prepaid, .. } = long {
        refund(on.target, prepaid);
    }
}

/// The stage Mappings (spec 7.7): every entry of the table, busy or not,
/// leaves it, its reference to the object going at `level`, and the block
/// goes back to the pool of blocks. The stage Space took the ASID, so no
/// TLB entry maps a frame of an object that goes. One portion: at most
/// abi::MAX_MAPPINGS entries, each O(1).
///
/// # Safety
/// `process` is alive and on its stages.
pub(super) unsafe fn release_all(process: NonNull<Process>, level: u8) -> bool {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; only the table and the pool are
    // touched, and each entry's reference goes with the entry.
    unsafe {
        let Some(t) = (*p).maps.take() else {
            return true;
        };
        // Each entry that goes lets its reference to the object go.
        (*t.as_ptr()).drain(|m| memory::release_mapping(m.object, level));
        (*p).pools.blocks.free(t.cast::<Block>());
    }
    true
}
