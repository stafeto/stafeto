// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's copies of immutable files: a `pread` of such a file copies from memory with no
//! call of the file service.
//!
//! * The file service says per description (SNAPSHOT_FD) whether its file can change through no
//!   description: only the files of the boot image and of package layers, and the motd. The first
//!   `pread` of a description asks once. A file that can change, or one above `FILE_MAX`, keeps
//!   the old path for the life of the description; so does every file when the service does not
//!   know the method.
//! * The copy of an immutable file of `FILE_MAX` (256 KiB) or less goes into the arena: up to
//!   `PIECES_MAX` memory objects of `PIECE_BYTES` made as they are needed, with the process's own
//!   quota, mapped as pieces of the kind `posix_map::Kind::FileCache` (a forked child has none).
//!   A file takes a run of whole pages of one piece; the pages are filled with READ_AT_FD_INTO in
//!   portions of `READ_PORTION`, a step of the service each.
//! * An entry (the copy) is named by the node key of the service, so the descriptions of one file
//!   share it and a place a layer takes again gets a new copy. A description names its entry by
//!   (slot, generation) of the description, never by the number: a number closed and opened
//!   again reads the new file. The last close of a description (the release of its target) lets
//!   go of the entry, which stays as a warm copy until it is evicted.
//! * The arena holds `budget` bytes of pages (default 2 MiB, `STAFETO_FILE_CACHE`: 0 turns the
//!   cache off, a number is the budget in KiB). A copy that needs pages evicts entries by the
//!   clock, those no description names first; an entry a read is copying from is never evicted.
//! * Every state is behind one lock the cache only tries: a call that finds it taken (another
//!   thread, or a handler the lock's holder was interrupted by) goes by the service as before,
//!   and so does every call the cache cannot serve. The copy out of the arena runs outside the
//!   lock, with the entry pinned by a reader count.
//! * `fork` leaves the child with no state (the arena is not inherited), `exec` starts a new
//!   image. `read` and `lseek` are untouched: the position of a description lives in the service.

use core::cell::UnsafeCell;
use core::ffi::c_char;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
use posix_fs::{FsError, RamTarget, Transport};
use posix_map::PAGE;
use posix_map::cache::{
    BUDGET_PAGES, Cache, ENTRIES, FILE_MAX, Know, NONE, PIECE_BYTES, Phase, Plan, budget_from,
};
use proto_fs::READ_PORTION;
use rt::handle::{Handle, Memory};
use rt::sys;

const _: () = assert!(READ_PORTION.is_multiple_of(PAGE));

// The state, its lock and the reader counts.
struct Shared(UnsafeCell<Cache>);
// SAFETY: every access to the cell holds LOCK.
unsafe impl Sync for Shared {}
static CACHE: Shared = Shared(UnsafeCell::new(Cache::new()));
static LOCK: AtomicBool = AtomicBool::new(false);
static READERS: [AtomicU16; ENTRIES] = [const { AtomicU16::new(0) }; ENTRIES];

/// 0 not read yet, 1 on, 2 off.
static MODE: AtomicU8 = AtomicU8::new(0);

static HITS: AtomicU64 = AtomicU64::new(0);
static FILLS: AtomicU64 = AtomicU64::new(0);
static SNAPSHOTS: AtomicU64 = AtomicU64::new(0);
static SERVICE_READS: AtomicU64 = AtomicU64::new(0);

/// The counters for the probes: copies served from memory, files copied in, SNAPSHOT_FD calls,
/// and reads of files of the service that went to it (`pread` the cache did not serve).
pub fn probe_counters() -> [u64; 4] {
    [
        HITS.load(Ordering::Relaxed),
        FILLS.load(Ordering::Relaxed),
        SNAPSHOTS.load(Ordering::Relaxed),
        SERVICE_READS.load(Ordering::Relaxed),
    ]
}

/// The pieces the arena holds and the pages taken in them (for the probes).
pub fn probe_arena() -> (usize, usize) {
    match Guard::try_new() {
        Some(guard) => (guard.pieces_made, guard.used_pages),
        None => (0, 0),
    }
}

/// The budget of the running cache set to `kib` KiB (at most the default), for the probes.
pub fn probe_budget(kib: usize) {
    if !active() {
        return;
    }
    let pages = kib.div_ceil(PAGE / 1024).clamp(1, BUDGET_PAGES);
    loop {
        if let Some(mut guard) = Guard::try_new() {
            guard.budget_pages = pages;
            return;
        }
        core::hint::spin_loop();
    }
}

/// A `pread` of a file of the service went to the service.
pub fn note_service_read() {
    SERVICE_READS.fetch_add(1, Ordering::Relaxed);
}

struct Guard(&'static mut Cache);

impl Guard {
    fn try_new() -> Option<Self> {
        if LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        // SAFETY: the lock is held, until the guard drops.
        Some(Self(unsafe { &mut *CACHE.0.get() }))
    }
}

impl core::ops::Deref for Guard {
    type Target = Cache;
    fn deref(&self) -> &Cache {
        self.0
    }
}

impl core::ops::DerefMut for Guard {
    fn deref_mut(&mut self) -> &mut Cache {
        self.0
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}

unsafe extern "C" {
    fn getenv(name: *const c_char) -> *const c_char;
}

/// Whether the cache runs; reads the variable on the first call.
fn active() -> bool {
    match MODE.load(Ordering::Acquire) {
        1 => true,
        2 => false,
        _ => {
            // SAFETY: a NUL-terminated name; the answer is a C string or null.
            let value = unsafe { getenv(c"STAFETO_FILE_CACHE".as_ptr()) };
            let text = (!value.is_null()).then(|| {
                // SAFETY: a C string the environment owns.
                unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes()
            });
            match budget_from(text) {
                Some(pages) => {
                    if let Some(mut guard) = Guard::try_new() {
                        guard.budget_pages = pages;
                    } else {
                        return false;
                    }
                    posix_fs::set_ram_closed(closed);
                    MODE.store(1, Ordering::Release);
                    true
                }
                None => {
                    MODE.store(2, Ordering::Release);
                    false
                }
            }
        }
    }
}

/// A memory object of `PIECE_BYTES` mapped as a piece of the arena: its base and handle.
fn new_piece() -> Option<(usize, u64)> {
    let object = sys::mem_create(PIECE_BYTES as u64).ok()?;
    let raw = object.raw().0;
    let base = crate::allocation::heap(|state| {
        state.map_special_more(object, PIECE_BYTES / PAGE, posix_map::Kind::FileCache)
    })
    .ok()?;
    Some((base, raw))
}

/// A read of the description `target` of the service for the bytes of `out` at `offset`, from
/// the copy of its file. None when the read goes to the service (the file can change, is too
/// large, has no copy yet and `create` is not set, or the cache is off or busy). `create` lets
/// the call ask the service about the description and copy the file in; a mapping's fill does
/// not set it.
pub fn pread(
    transport: &Transport,
    target: RamTarget,
    offset: u64,
    out: &mut [u8],
    create: bool,
) -> Option<Result<usize, FsError>> {
    if !active() || target.kind() != Ok(posix_fs::FileKind::Regular) {
        return None;
    }
    let (slot, generation) = (target.description_slot(), target.generation());
    let mut asked = false;
    let (at, len, entry) = loop {
        let mut guard = Guard::try_new()?;
        match guard.plan(slot, generation, create, &READERS, &mut new_piece) {
            Plan::Direct => return None,
            Plan::Ask if asked => return None,
            Plan::Ask => {
                drop(guard);
                asked = true;
                SNAPSHOTS.fetch_add(1, Ordering::Relaxed);
                let reply = match transport.snapshot(target.fd()) {
                    Ok(reply) => reply,
                    Err(error) => {
                        lost(error);
                        return Some(Err(error));
                    }
                };
                let mut guard = Guard::try_new()?;
                match reply {
                    Some(r) if r.immutable() && r.length as usize <= FILE_MAX && r.key != 0 => {
                        guard.put(slot, generation, Know::Immutable, r.key, r.length as u32);
                    }
                    _ => {
                        guard.put(slot, generation, Know::Direct, 0, 0);
                    }
                }
            }
            Plan::Hit { at, len, entry } => break (at, len, entry),
            Plan::Fill { entry, piece } => {
                let (base, handle, first, len) = {
                    let e = guard.entries[usize::from(entry)];
                    (
                        guard.pieces[piece].base,
                        guard.pieces[piece].handle,
                        usize::from(e.first),
                        e.len as usize,
                    )
                };
                drop(guard);
                let filled = fill(transport, target.fd(), handle, first, len);
                // The entry is this call's until it is published: wait for the lock.
                let mut guard = loop {
                    if let Some(guard) = Guard::try_new() {
                        break guard;
                    }
                    core::hint::spin_loop();
                };
                match filled {
                    Ok(()) => {
                        FILLS.fetch_add(1, Ordering::Relaxed);
                        let place = Cache::index(slot);
                        // The description may have gone meanwhile (a close, or another one took
                        // its place): the copy stays for whoever asks for the key.
                        if guard.desc_of(slot, generation) == Some(place) {
                            guard.filled(entry, place);
                        } else {
                            guard.entries[usize::from(entry)].phase = Phase::Ready;
                        }
                        break (base + first * PAGE, len, entry);
                    }
                    Err(error) => {
                        guard.failed(entry, &READERS);
                        if error == Some(FsError::Io) {
                            guard.clear(&READERS);
                        }
                        return error.map(Err);
                    }
                }
            }
        }
    };
    HITS.fetch_add(1, Ordering::Relaxed);
    let n = if offset >= len as u64 {
        0
    } else {
        (len - offset as usize).min(out.len())
    };
    if n > 0 {
        // SAFETY: the entry is pinned by a reader count, so its pages stay filled and mapped;
        // the copy lies inside the file's `len` bytes of them.
        let from = unsafe { core::slice::from_raw_parts((at + offset as usize) as *const u8, n) };
        out[..n].copy_from_slice(from);
    }
    if entry != NONE {
        READERS[usize::from(entry)].fetch_sub(1, Ordering::AcqRel);
    }
    Some(Ok(n))
}

/// The service answered a call of the cache with a failure of the session (the service is
/// gone): the copies go, so that a read gives the error the path of messages gives.
fn lost(error: FsError) {
    if error == FsError::Io
        && let Some(mut guard) = Guard::try_new()
    {
        guard.clear(&READERS);
    }
}

/// Fills the pages from page `first` of the piece object `handle` with the `len` bytes of the
/// file of the service's description `fd`, a portion of the service at a time. Ok(None-like): an
/// error that is the file's answer is `Some`, a failure of the means falls back (None inside Err).
fn fill(
    transport: &Transport,
    fd: u32,
    handle: u64,
    first: usize,
    len: usize,
) -> Result<(), Option<FsError>> {
    let object = Handle::<Memory>::borrowed(rt::abi::Handle(handle));
    let mut done = 0;
    while done < len {
        let count = (len - done).min(READ_PORTION);
        let place = (first * PAGE + done) as u64;
        match transport.read_into(fd, Some(done as u64), count, &object, place) {
            Ok(Some(n)) if n == count => done += n,
            // A short read of an immutable file or a service that cannot do it: the old path.
            Ok(_) => return Err(None),
            Err(error) => return Err(Some(error)),
        }
    }
    Ok(())
}

/// The last close of the description `target` goes through the layer: its place lets go of the
/// entry, which stays as a warm copy.
pub fn closed(target: RamTarget) {
    if MODE.load(Ordering::Acquire) != 1 {
        return;
    }
    let (slot, generation) = (target.description_slot(), target.generation());
    // A short wait for a lock held for a few steps; a stale place costs nothing but a count.
    for _ in 0..64 {
        if let Some(mut guard) = Guard::try_new() {
            if let Some(at) = guard.desc_of(slot, generation) {
                guard.forget(at);
            }
            return;
        }
        core::hint::spin_loop();
    }
}

/// A forked child has no copies: the pieces are the parent's.
pub(crate) fn after_fork() {
    LOCK.store(false, Ordering::Release);
    // SAFETY: the child has one thread and the lock is released above.
    let cache = unsafe { &mut *CACHE.0.get() };
    let budget = cache.budget_pages;
    *cache = Cache::new();
    cache.budget_pages = budget;
    for r in &READERS {
        r.store(0, Ordering::Release);
    }
}
