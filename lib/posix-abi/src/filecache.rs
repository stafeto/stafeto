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
//!   `PIECES_MAX` memory objects made as they are needed, outside the lock, with the process's own
//!   quota (the first the size of its file, the second of 64 KiB, the others of 256 KiB: `PIECE_SIZES`), mapped as pieces of
//!   the kind `posix_map::Kind::FileCache` (a forked child has none). A file takes a run of whole
//!   pages of one piece; the pages are filled with READ_AT_FD_INTO in portions of `READ_PORTION`,
//!   a step of the service each. Pieces are never given back.
//! * An entry (the copy) is named by the node key of the service, so the descriptions of one file
//!   share it and a place a layer takes again gets a new copy. A description names its entry by
//!   (slot, generation) of the description, never by the number: a number closed and opened
//!   again reads the new file. The last close of a description (the release of its target) lets
//!   go of the entry, which stays as a warm copy until it is evicted.
//! * The arena holds `budget` bytes of pages (default 2 MiB, `STAFETO_FILE_CACHE`: 0 turns the
//!   cache off, a number is the budget in KiB). A copy that needs pages evicts entries by the
//!   clock, those no description names first; an entry a read is copying from is never evicted.
//! * Every state is behind one lock that is only tried (at most `TRIES` tries where a call has a
//!   way out): a call that finds it taken goes by the service as before, so no thread waits for
//!   the holder of a lower level. The sections under the lock are bounded by the constants of the
//!   state and make no call of the system; the piece is made before the lock is taken, and a
//!   filler that finds the lock taken after its fill leaves its verdict for the next holder. The
//!   copy out of the arena runs outside the lock, with the entry pinned by a reader count.
//! * `fork` leaves the child with no state (the arena is not inherited; the reset is in place and
//!   makes no temporary, since the child runs on a copy of the caller's stack), `exec` starts a new
//!   image. `read` and `lseek` are untouched: the position of a description lives in the service.

use core::cell::UnsafeCell;
use core::ffi::c_char;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use posix_fs::{FsError, RamTarget, Transport};
use posix_map::PAGE;
use posix_map::cache::{
    BUDGET_PAGES, Cache, FILE_MAX, Know, NONE, Phase, Plan, Shared, budget_from,
};
use proto_fs::READ_PORTION;
use rt::handle::{Handle, Memory};
use rt::sys;

const _: () = assert!(READ_PORTION.is_multiple_of(PAGE));

/// The tries of a wait for the lock that has a way out: a lock held by a thread of a lower level
/// that a higher one preempted is not waited for, the call goes by the service. Every section
/// under the lock is bounded by the constants of the state (at most 1,040 visits of entries by
/// the clock, 8 pieces of 64 pages for a run, 520 entries for a key) and makes no call of the
/// system.
const TRIES: u32 = 64;

// The state and its lock; the words the readers use without the lock are `SHARED`.
struct Held(UnsafeCell<Cache>);
// SAFETY: every access to the cell holds LOCK.
unsafe impl Sync for Held {}
static CACHE: Held = Held(UnsafeCell::new(Cache::new()));
static LOCK: AtomicBool = AtomicBool::new(false);
static SHARED: Shared = Shared::new();

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
    if let Some(mut guard) = Guard::waiting() {
        guard.budget_pages = pages;
    }
}

/// A `pread` of a file of the service went to the service.
pub fn note_service_read() {
    SERVICE_READS.fetch_add(1, Ordering::Relaxed);
}

struct Guard(&'static mut Cache);

impl Guard {
    /// The lock after at most `TRIES` tries.
    fn waiting() -> Option<Self> {
        for _ in 0..TRIES {
            if let Some(guard) = Self::try_new() {
                return Some(guard);
            }
            core::hint::spin_loop();
        }
        None
    }

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
                    let Some(mut guard) = Guard::waiting() else {
                        return false;
                    };
                    guard.budget_pages = pages;
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

/// Makes a piece of `pages` pages (a memory object of the process's own, mapped as a piece of
/// the arena) outside the lock and offers it to the next holder, which clears `making` when it takes the piece. One thread makes it; the
/// others, and a call that finds a piece waiting, look again. The system's refusal is final.
fn make_piece(pages: usize) {
    if !SHARED.begin_make() {
        return;
    }
    let made = sys::mem_create((pages * PAGE) as u64)
        .ok()
        .and_then(|object| {
            let raw = object.raw().0;
            crate::allocation::heap(|state| {
                state.map_special_more(object, pages, posix_map::Kind::FileCache)
            })
            .ok()
            .map(|base| (base, raw))
        });
    match made {
        Some((base, handle)) => SHARED.offer(base, handle, pages),
        None => SHARED.refuse(),
    }
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
    // A read of no bytes asks nothing of the cache: the service answers it as before.
    if out.is_empty() || !active() || target.kind() != Ok(posix_fs::FileKind::Regular) {
        return None;
    }
    let (slot, generation) = (target.description_slot(), target.generation());
    let (mut asked, mut pieces) = (false, 0);
    let (at, len, entry) = loop {
        let mut guard = Guard::try_new()?;
        match guard.plan(slot, generation, create, &SHARED) {
            Plan::Direct => return None,
            Plan::NeedPiece { pages } => {
                drop(guard);
                pieces += 1;
                if pieces > 2 {
                    return None;
                }
                make_piece(pages);
            }
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
                // The entry is this call's until it is published. A lock that stays taken is not
                // waited for: the verdict goes to the next holder, which applies it.
                let held = Guard::waiting();
                match filled {
                    Ok(()) => {
                        FILLS.fetch_add(1, Ordering::Relaxed);
                        match held {
                            Some(mut guard) => {
                                let place = Cache::index(slot);
                                // The description may have gone meanwhile (a close, or another
                                // one took its place): the copy stays for whoever asks for the key.
                                if guard.desc_of(slot, generation) == Some(place) {
                                    guard.filled(entry, place);
                                } else {
                                    guard.entries[usize::from(entry)].phase = Phase::Ready;
                                }
                            }
                            None => verdict(entry, 1),
                        }
                        break (base + first * PAGE, len, entry);
                    }
                    Err(error) => {
                        match held {
                            Some(mut guard) => {
                                guard.failed(entry, &SHARED);
                                if error == Some(FsError::Io) {
                                    guard.clear(&SHARED);
                                } else if error.is_none() {
                                    // The service cannot give this copy: the description keeps the
                                    // old path instead of trying again at each read.
                                    guard.put(slot, generation, Know::Direct, 0, 0);
                                }
                            }
                            None => {
                                SHARED.readers[usize::from(entry)].store(0, Ordering::Release);
                                verdict(entry, 2);
                            }
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
        SHARED.readers[usize::from(entry)].fetch_sub(1, Ordering::AcqRel);
    }
    Some(Ok(n))
}

/// The verdict of a fill whose filler found the lock taken: the next holder applies it.
fn verdict(entry: u16, code: u8) {
    SHARED.pending[usize::from(entry)].store(code, Ordering::Release);
    SHARED.due.store(true, Ordering::Release);
}

/// The service answered a call of the cache with a failure of the session (the service is
/// gone): the copies go, so that a read gives the error the path of messages gives.
fn lost(error: FsError) {
    if error == FsError::Io
        && let Some(mut guard) = Guard::waiting()
    {
        guard.clear(&SHARED);
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
    // A stale place costs nothing but a count, so a lock that stays taken is not waited for.
    if let Some(mut guard) = Guard::waiting()
        && let Some(at) = guard.desc_of(slot, generation)
    {
        guard.forget(at);
    }
}

/// A forked child has no copies: the pieces are the parent's. The reset is in place: the child
/// runs on a copy of the caller's stack, which may be a handler's alternate stack of a few KiB,
/// so no value of the size of the state is made here.
pub(crate) fn after_fork() {
    // A process that never used the cache has nothing to reset (and its pages stay untouched).
    if MODE.load(Ordering::Acquire) != 1 {
        return;
    }
    LOCK.store(false, Ordering::Release);
    // SAFETY: the child has one thread and the lock is released above.
    let cache = unsafe { &mut *CACHE.0.get() };
    cache.reset();
    SHARED.reset();
}
