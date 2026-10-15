// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The program's mappings (POSIX `mmap`, `munmap`, `mprotect`, `madvise`,
//! `mlock`; spec 2, 3.4): small anonymous private mappings are pages of the
//! heap, which lose their access when unmapped (#187), and a large one
//! (64 KiB or more) has a memory object of its own that `mem_unmap`
//! returns. A range across several pieces of the memory map is walked one
//! piece at a time (`State::protect`, `State::unmap`).

use crate::allocation::{State, heap};
use crate::constants::*;
use posix_map::space::State as Page;
use rt::abi::Access;

const PAGE: usize = 4096;
/// The size from which a mapping has an object of its own (256 KiB). A
/// smaller one is pages of the heap: the table of the kernel holds 128
/// mappings, and 62 threads with stacks of 64 KiB must fit in it.
const OWN_FROM: usize = 64;

pub const PROT_NONE: i32 = 0;
pub const PROT_READ: i32 = 1;
pub const PROT_WRITE: i32 = 2;
pub const PROT_EXEC: i32 = 4;
pub const MAP_SHARED: i32 = 1;
pub const MAP_PRIVATE: i32 = 2;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANONYMOUS: i32 = 0x20;

/// The access `prot` asks for: write means read too, and code is not
/// allowed (EACCES: the layer's objects carry no MAP_EXEC).
fn access_of(prot: i32) -> Result<Access, i32> {
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(EINVAL);
    }
    if prot & PROT_EXEC != 0 {
        return Err(EACCES);
    }
    Ok(match prot & (PROT_READ | PROT_WRITE) {
        0 => Access::None,
        PROT_READ => Access::Read,
        _ => Access::ReadWrite,
    })
}

/// The pages of the range as `(state, first, pages)` runs of the room
/// (pages outside it are left out).
fn runs(state: &State, address: usize, pages: usize, mut f: impl FnMut(Page, usize, usize)) {
    let mut at = address;
    let end = address + pages * PAGE;
    while at < end {
        let Some(page) = state.space.get(at) else {
            at += PAGE;
            continue;
        };
        let mut to = at + PAGE;
        while to < end && state.space.get(to) == Some(page) {
            to += PAGE;
        }
        f(page, at, (to - at) / PAGE);
        at = to;
    }
}

fn whole_pages(len: usize) -> Result<usize, i32> {
    len.checked_next_multiple_of(PAGE)
        .filter(|&bytes| bytes != 0)
        .map(|bytes| bytes / PAGE)
        .ok_or(EINVAL)
}

/// Gives back the pages of the program's mappings in the range: those of
/// the heap lose their access, those of an object of their own are
/// unmapped. Pages in no mapping are left alone.
fn release(state: &mut State, address: usize, pages: usize) -> Result<(), i32> {
    // The runs first: the calls below change the states.
    let mut list = [(Page::Free, 0usize, 0usize); posix_map::MAX_PIECES * 2];
    let mut n = 0;
    let mut full = false;
    runs(state, address, pages, |page, at, count| {
        if matches!(page, Page::User | Page::Own) {
            if n < list.len() {
                list[n] = (page, at, count);
                n += 1;
            } else {
                full = true;
            }
        }
    });
    if full {
        return Err(ENOMEM);
    }
    for &(page, at, count) in &list[..n] {
        match page {
            Page::User => state.give(at, count),
            _ => {
                state.unmap(at, count)?;
                state.space.set(at, count, Page::Unbacked);
            }
        }
    }
    Ok(())
}

/// `mmap` of anonymous private memory: the address, or an errno.
pub fn mmap(
    addr: usize,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<usize, i32> {
    mmap_inner(addr, len, prot, flags, fd, offset)
}

fn mmap_inner(
    addr: usize,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<usize, i32> {
    let _ = (fd, offset);
    crate::allocation::probe_pause();
    let access = access_of(prot)?;
    if len == 0 {
        return Err(EINVAL);
    }
    let kind = flags & (MAP_SHARED | MAP_PRIVATE);
    if kind == 0 || kind == (MAP_SHARED | MAP_PRIVATE) {
        return Err(EINVAL);
    }
    if flags & MAP_ANONYMOUS == 0 {
        return Err(ENOSYS);
    }
    if kind == MAP_SHARED {
        return Err(ENOTSUP);
    }
    let pages = whole_pages(len)?;
    let fixed = flags & MAP_FIXED != 0;
    if fixed && !addr.is_multiple_of(PAGE) {
        return Err(EINVAL);
    }
    heap(|state| {
        let result = if fixed {
            let end = addr.checked_add(pages * PAGE).ok_or(ENOMEM)?;
            if addr < state.space.base() || end > state.space.limit() {
                return Err(ENOMEM);
            }
            release(state, addr, pages)?;
            if state.space.all(addr, pages, Page::Free) {
                state.take_at(addr, pages).map(|()| addr)
            } else {
                state
                    .make_own(Some(addr), pages, Access::ReadWrite, false)
                    .map(|(_, at)| at)
            }
        } else if pages >= OWN_FROM {
            state
                .make_own(None, pages, Access::ReadWrite, false)
                .map(|(_, at)| at)
        } else {
            let at = state.take(pages)?;
            // SAFETY: the heap gave these pages to this caller alone.
            unsafe { core::ptr::write_bytes(at as *mut u8, 0, pages * PAGE) };
            Ok(at)
        }?;
        if access != Access::ReadWrite {
            if let Err(error) = state.protect(result, pages, access) {
                release(state, result, pages)?;
                return Err(error);
            }
        }
        Ok(result)
    })
}

/// `munmap`: the pages of the range lose their mapping; a range with no
/// mapping in it is not an error.
pub fn munmap(addr: usize, len: usize) -> Result<(), i32> {
    if !addr.is_multiple_of(PAGE) || len == 0 {
        return Err(EINVAL);
    }
    let pages = whole_pages(len)?;
    addr.checked_add(pages * PAGE).ok_or(EINVAL)?;
    heap(|state| release(state, addr, pages))
}

/// Whether every page of the range is in a mapping of the program.
fn mapped(state: &State, address: usize, pages: usize) -> bool {
    let mut all = true;
    let mut seen = 0;
    runs(state, address, pages, |page, _, count| {
        all &= matches!(page, Page::User | Page::Own);
        seen += count;
    });
    all && seen == pages
}

/// `mprotect`: the pages of the range get the access, across several
/// pieces of the map; ENOMEM when a page is in no mapping of the program.
pub fn mprotect(addr: usize, len: usize, prot: i32) -> Result<(), i32> {
    let access = access_of(prot)?;
    if !addr.is_multiple_of(PAGE) {
        return Err(EINVAL);
    }
    if len == 0 {
        return Ok(());
    }
    let pages = whole_pages(len)?;
    addr.checked_add(pages * PAGE).ok_or(ENOMEM)?;
    heap(|state| {
        if !mapped(state, addr, pages) {
            return Err(ENOMEM);
        }
        state.protect(addr, pages, access)
    })
}

/// Checks the range of `madvise`, `posix_madvise` and `mlock`: aligned,
/// and in mappings of the program (ENOMEM otherwise).
pub fn check_range(addr: usize, len: usize) -> Result<(), i32> {
    if !addr.is_multiple_of(PAGE) {
        return Err(EINVAL);
    }
    if len == 0 {
        return Ok(());
    }
    let pages = whole_pages(len)?;
    addr.checked_add(pages * PAGE).ok_or(ENOMEM)?;
    heap(|state| {
        if mapped(state, addr, pages) {
            Ok(())
        } else {
            Err(ENOMEM)
        }
    })
}
