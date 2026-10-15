// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The program's mappings (POSIX `mmap`, `munmap`, `mprotect`, `madvise`,
//! `mlock`; spec 2, 3.4): small anonymous private mappings are pages of the
//! heap, which lose their access when unmapped (#187), and a large one
//! (64 KiB or more) has a memory object of its own that `mem_unmap`
//! returns. A range across several pieces of the memory map is walked one
//! piece at a time (`State::protect`, `State::unmap`).

use crate::allocation::{LIMIT_AS, LIMIT_DATA, Source, State, heap};
use crate::constants::*;
use core::sync::atomic::{AtomicBool, Ordering};
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

static LIMITS_LOADED: AtomicBool = AtomicBool::new(false);

/// Reads RLIMIT_DATA and RLIMIT_AS from the process service once, outside the
/// heap's lock.
fn load_limits() {
    if LIMITS_LOADED.load(Ordering::Acquire) {
        return;
    }
    // The service starts both at the process's quota, which the kernel
    // enforces on its own; the layer counts only a limit below it.
    let quota = rt::sys::process_memory(crate::allocation::process()).map_or(u64::MAX, |m| m.quota);
    for (resource, cell) in [(2, &LIMIT_DATA), (9, &LIMIT_AS)] {
        if let Ok(limit) = crate::resources::get(resource) {
            cell.store(
                if limit.soft >= quota {
                    u64::MAX
                } else {
                    limit.soft
                },
                Ordering::Relaxed,
            );
        }
    }
    LIMITS_LOADED.store(true, Ordering::Release);
}

/// `setrlimit` of RLIMIT_DATA or RLIMIT_AS (Linux's 2 and 9): the soft
/// limit the heap's section checks.
pub(crate) fn set_limit(resource: i32, soft: u64) {
    let cell = if resource == 2 {
        &LIMIT_DATA
    } else {
        &LIMIT_AS
    };
    cell.store(soft, Ordering::Relaxed);
}

/// What a mapping of a file keeps to write its pages back: the descriptor
/// the layer holds for it and the byte of the file the object starts at.
pub use posix_map::Back;

/// The object of a shared mapping of a file: one the process service gave
/// (`existing`, whose first page is the file's first page), or a new one
/// that covers the file from its first page; `offset_pages` is where the
/// mapping starts in it; `back` is the file it writes to.
pub struct FileSource {
    pub existing: Option<rt::handle::Handle<rt::handle::Memory>>,
    pub offset_pages: usize,
    pub back: Back,
    /// The descriptor was open for writing: the program may map the object
    /// writable now or by `mprotect`.
    pub may_write: bool,
    /// The mapping asks for write access: its pages go back to the file.
    pub writable: bool,
}

/// A duplicate of the object that shows the page at `address` and the pages
/// it covers, for the process service (Put, Attach).
pub fn object_at(address: usize) -> Option<(rt::handle::Handle<rt::handle::Memory>, usize)> {
    use rt::abi::Rights;
    let (raw, pages) = heap(|state| {
        let index = state.map.find(address)?;
        let object = state.map.piece(index).object();
        let pages = state
            .map
            .pieces_of(object)
            .map(|p| p.offset() + p.pages())
            .max()?;
        Some((state.map.object(object).handle.raw(), pages))
    })?;
    let held = rt::handle::Handle::<rt::handle::Memory>::borrowed(raw);
    rt::sys::handle_duplicate(
        &*held,
        Rights::MAP_READ | Rights::MAP_WRITE | Rights::DUPLICATE | Rights::TRANSFER,
    )
    .ok()
    .map(|copy| (copy, pages))
}

/// `mmap`: the address, or an errno. A shared mapping has an object of
/// its own and goes to a forked child as the same pages; a private one is
/// pages of the heap, or an object of its own from 256 KiB. `file` is the
/// object and the file of a shared mapping of a file; the pages are zeros
/// and the caller fills a mapping of a file and then gives it its access
/// (`mprotect`), so `prot` of such a mapping includes PROT_WRITE.
pub fn mmap(
    addr: usize,
    len: usize,
    prot: i32,
    flags: i32,
    file: Option<FileSource>,
) -> Result<usize, i32> {
    mmap0(addr, len, prot, flags, file)
}

fn mmap0(
    addr: usize,
    len: usize,
    prot: i32,
    flags: i32,
    file: Option<FileSource>,
) -> Result<usize, i32> {
    crate::allocation::probe_pause();
    load_limits();
    let access = access_of(prot)?;
    if len == 0 {
        return Err(EINVAL);
    }
    let kind = flags & (MAP_SHARED | MAP_PRIVATE);
    if kind == 0 || kind == (MAP_SHARED | MAP_PRIVATE) {
        return Err(EINVAL);
    }
    let shared = kind == MAP_SHARED;
    let pages = whole_pages(len)?;
    let fixed = flags & MAP_FIXED != 0;
    if fixed && !addr.is_multiple_of(PAGE) {
        return Err(EINVAL);
    }
    let source = match file.filter(|_| shared) {
        Some(file) => Source {
            existing: file.existing,
            offset: file.offset_pages,
            back: Some(file.back),
            may_write: file.may_write,
            dirty: file.writable,
        },
        None => Source::anonymous(),
    };
    heap(|state| {
        state.within_data(pages)?;
        let result = if fixed {
            let end = addr.checked_add(pages * PAGE).ok_or(ENOMEM)?;
            if addr < state.space.base() || end > state.space.limit() {
                return Err(ENOMEM);
            }
            release(state, addr, pages)?;
            if !shared && state.space.all(addr, pages, Page::Free) {
                state.take_at(addr, pages).map(|()| {
                    // SAFETY: the heap gave these pages to this caller alone.
                    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, pages * PAGE) };
                    addr
                })
            } else {
                state
                    .make_own(Some(addr), pages, Access::ReadWrite, shared, source)
                    .map(|(_, at)| at)
            }
        } else if shared || pages >= OWN_FROM {
            state
                .make_own(None, pages, Access::ReadWrite, shared, source)
                .map(|(_, at)| at)
        } else {
            let at = state.take(pages)?;
            // SAFETY: the heap gave these pages to this caller alone.
            unsafe { core::ptr::write_bytes(at as *mut u8, 0, pages * PAGE) };
            Ok(at)
        }?;
        if access != Access::ReadWrite
            && let Err(error) = state.protect(result, pages, access)
        {
            release(state, result, pages)?;
            return Err(error);
        }
        Ok(result)
    })
}

/// A forked child joins the process service's entries of the shared objects
/// it inherited, so that they live as long as it maps them.
pub(crate) fn attach_shared() {
    use rt::handle::{Handle, Memory};
    let mut found: [Option<(u64, usize, Handle<Memory>)>; posix_map::MAX_OBJECTS] =
        [const { None }; posix_map::MAX_OBJECTS];
    heap(|state| {
        let mut n = 0;
        for (index, object) in state.map.objects() {
            let Some(back) = object.back.filter(|b| b.registered) else {
                continue;
            };
            let pages = state
                .map
                .pieces_of(index)
                .map(|p| p.offset() + p.pages())
                .max()
                .unwrap_or(0);
            let held = Handle::<Memory>::borrowed(object.handle.raw());
            if let Ok(copy) = rt::sys::handle_duplicate(
                &*held,
                rt::abi::Rights::MAP_READ
                    | rt::abi::Rights::MAP_WRITE
                    | rt::abi::Rights::DUPLICATE
                    | rt::abi::Rights::TRANSFER,
            ) {
                found[n] = Some((back.key, pages, copy));
                n += 1;
            }
        }
    });
    for (key, pages, copy) in found.iter().flatten() {
        let _ = crate::shares::attach(*key, *pages, copy);
    }
}

/// A piece of a shared mapping of a file in a range: its address, its
/// pages, the descriptor the layer holds and the byte of the file it starts
/// at.
#[derive(Clone, Copy)]
pub struct FilePiece {
    pub address: usize,
    pub pages: usize,
    pub fd: i32,
    pub offset: u64,
    /// The identity of the file the descriptor must still show.
    pub key: u64,
    /// The access of the piece now.
    pub access: Access,
}

impl Default for FilePiece {
    fn default() -> Self {
        FilePiece {
            address: 0,
            pages: 0,
            fd: -1,
            offset: 0,
            key: 0,
            access: Access::Read,
        }
    }
}

/// The pieces of shared mappings of files in the range, up to `out.len()`:
/// how many. With `dirty` only those of objects the program had writable
/// (what a write back writes); else all (what a refresh reads).
pub fn file_pieces(addr: usize, len: usize, dirty: bool, out: &mut [FilePiece]) -> usize {
    let Ok(pages) = whole_pages(len) else {
        return 0;
    };
    pieces_in(addr, pages, dirty, out)
}

/// As `file_pieces` for every page of the room from `addr` on, for the
/// write back at `exit` and `exec`.
pub fn file_pieces_from(addr: usize, out: &mut [FilePiece]) -> usize {
    let (base, limit) = heap(|state| (state.space.base(), state.space.limit()));
    let from = addr.max(base);
    pieces_in(from, (limit - from) / PAGE, true, out)
}

fn pieces_in(addr: usize, pages: usize, dirty: bool, out: &mut [FilePiece]) -> usize {
    heap(|state| {
        let mut n = 0;
        for (index, from, count) in state.map.walk(addr, pages) {
            let piece = state.map.piece(index);
            let object = state.map.object(piece.object());
            let Some(back) = object.back.filter(|_| object.shared) else {
                continue;
            };
            if dirty && !object.dirty {
                continue;
            }
            if n < out.len() {
                out[n] = FilePiece {
                    address: from,
                    pages: count,
                    fd: back.fd,
                    offset: back.offset()
                        + ((piece.offset() + (from - piece.address) / PAGE) * PAGE) as u64,
                    key: back.key,
                    access: piece.access(),
                };
                n += 1;
            }
        }
        n
    })
}

/// The descriptor the layer already holds for the file of `key`.
pub fn fd_of_key(key: u64) -> Option<i32> {
    heap(|state| state.fd_of_key(key))
}

/// The descriptors and keys of the files whose last mapping `munmap` took since
/// the last call, up to `out.len()`: how many. The caller closes the
/// descriptors and tells the process service of the keys.
pub fn closed_files(out: &mut [(i32, u64, bool)]) -> usize {
    heap(|state| state.take_closed(out))
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
        if access == Access::ReadWrite
            && state
                .map
                .walk(addr, pages)
                .any(|(i, ..)| !state.map.object(state.map.piece(i).object()).may_write)
        {
            return Err(EACCES);
        }
        state.protect(addr, pages, access)
    })
}

/// Checks the range of `madvise`, `posix_madvise`, `mlock` and `msync`:
/// aligned, and in mappings (ENOMEM otherwise).
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
        if state.map.covers(addr, pages) {
            Ok(())
        } else {
            Err(ENOMEM)
        }
    })
}
