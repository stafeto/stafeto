// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's buffer for the large reads of files: a memory object of `SIZE` bytes (60 KiB,
//! 15 pages) of the process's own quota, mapped as the *file buffer piece* of the memory map
//! (posix_map::Kind::FileBuffer). The layer cuts it into cells of `proto_fs::READ_PORTION`
//! bytes, rounded up to pages. A `read` or `pread` of a file of the RAM service for more than
//! one message (`MAX_READ`) takes a cell, asks the service to fill it (READ_FD_INTO or
//! READ_AT_FD_INTO: a copy of the object goes in the request, the service maps it for the
//! copy alone and unmaps it again) and copies the bytes out of the cell into the program's
//! buffer. The call is one step of the service, so up to `READ_PORTION` bytes are the state of
//! the file at one moment (XSH 2.9.7), and one call replaces a message for each 1,016 bytes.
//!
//! * The first large read asks for the buffer; the other threads go by messages meanwhile. A
//!   refusal (no memory, no room in the map) is final until `exec`, and the object goes at once.
//! * A read of up to the portion that finds no free cell waits a little for one (a cell is held
//!   for one step of the service) and goes by messages when none comes: then it is not atomic,
//!   as every read of more than one message was before. A read inside a signal handler does not
//!   wait.
//! * A failure of the means (`handle_duplicate`, the service's `mem_map`, a service without the
//!   methods) sends the read by messages as well, never an error the messages would not give.
//! * The cost is 15 pages of quota and one piece of the map for the life of the process
//!   (docs/posix-coverage.md); only `read` and `pread` ask for it, not the fill of a mapping.
//! * A `siglongjmp` out of a handler that interrupted a read keeps its cell for good, as it
//!   keeps the holds of the files (`abandon_holds`); five such exits leave the process reading
//!   by messages.
//! * A forked child has neither the piece (`Map::inherited` leaves it out) nor the cells, and
//!   asks for its own. An exec'd image starts without one.
//! * The state and the cells are atomic words; no lock of the layer is held over a request.
//!   The object is made and mapped under the lock of the heap alone.

use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};

/// The reads that went through a cell, for the probes.
static THROUGH: AtomicU64 = AtomicU64::new(0);

/// How many reads went through a cell of the buffer so far.
pub fn probe_through() -> u64 {
    THROUGH.load(Ordering::Relaxed)
}

/// The turns a read of up to a portion looks for a free cell for before it goes by messages.
const WAIT: u32 = 2000;
use posix_fs::{FsError, MAX_READ, Transport};
use proto_fs::READ_PORTION;
use rt::handle::{Handle, Memory};
use rt::sys;

/// The bytes of one cell: the portion, whole pages.
const CELL: usize = READ_PORTION.next_multiple_of(posix_map::PAGE);
/// The bytes of the buffer: as many whole cells as 64 KiB holds (5 of 12 KiB).
const CELLS: usize = 64 * 1024 / CELL;
const SIZE: usize = (CELLS * CELL).next_multiple_of(posix_map::PAGE);

const _: () = assert!(CELLS >= 2 && CELLS <= 8);
const _: () = assert!(READ_PORTION > MAX_READ);

/// The states of the buffer; any other value is `Ready`, the address of the piece (a page,
/// never below 4 KiB).
const ABSENT: usize = 0;
const ASKING: usize = 1;
const REFUSED: usize = 2;

static STATE: AtomicUsize = AtomicUsize::new(ABSENT);
/// The handle of the object, which the map of the layer owns; valid while `STATE` is `Ready`.
static OBJECT: AtomicU64 = AtomicU64::new(0);
/// The free cells, a bit each.
static FREE: AtomicU8 = AtomicU8::new(0);

/// A cell a read holds; it goes back when the value drops.
struct Cell {
    index: u32,
    base: usize,
}

impl Cell {
    /// The place of the cell in the object, which the request names.
    fn place(&self) -> u64 {
        u64::from(self.index) * CELL as u64
    }

    /// The first `count` bytes of the cell, once the service has filled them.
    fn bytes(&self, count: usize) -> &[u8] {
        debug_assert!(count <= CELL);
        // SAFETY: the cell is this value's alone (its bit is taken), the piece stays mapped
        // until the process ends or execs, and the service wrote the bytes before it replied.
        unsafe {
            core::slice::from_raw_parts((self.base + self.place() as usize) as *const u8, count)
        }
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        FREE.fetch_or(1 << self.index, Ordering::AcqRel);
    }
}

/// A cell for a read of `size` bytes: None for a read that one message carries, while the
/// buffer is asked for or refused, and when every cell is taken.
fn cell(size: usize) -> Option<Cell> {
    if size <= MAX_READ {
        return None;
    }
    let base = match STATE.load(Ordering::Acquire) {
        ABSENT => ask()?,
        ASKING | REFUSED => return None,
        base => base,
    };
    let mut free = FREE.load(Ordering::Acquire);
    loop {
        if free == 0 {
            return None;
        }
        let index = free.trailing_zeros();
        match FREE.compare_exchange_weak(
            free,
            free & !(1 << index),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(Cell { index, base }),
            Err(now) => free = now,
        }
    }
}

/// A cell for a read of `size` bytes. A read of one portion at most that finds none waits a
/// little for one, unless it runs inside a signal handler (the thread that holds the cell may
/// be the one the handler interrupted).
fn cell_waiting(size: usize) -> Option<Cell> {
    if let Some(cell) = cell(size) {
        return Some(cell);
    }
    if size > READ_PORTION
        || STATE.load(Ordering::Acquire) == REFUSED
        || rt::upcall::query().is_ok_and(|q| q.depth != 0)
    {
        return None;
    }
    for turn in 0..WAIT {
        if let Some(cell) = cell(size) {
            return Some(cell);
        }
        if STATE.load(Ordering::Acquire) == REFUSED {
            return None;
        }
        if turn % 16 == 15 {
            let _ = sys::yield_now();
        } else {
            core::hint::spin_loop();
        }
    }
    None
}

/// The buffer is asked for by one thread: the object and its piece. The address of the piece,
/// or None (refused, or another thread asks).
fn ask() -> Option<usize> {
    if STATE
        .compare_exchange(ABSENT, ASKING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    match make() {
        Ok(base) => {
            FREE.store(((1u16 << CELLS) - 1) as u8, Ordering::Release);
            STATE.store(base, Ordering::Release);
            Some(base)
        }
        Err(()) => {
            STATE.store(REFUSED, Ordering::Release);
            None
        }
    }
}

/// The object, mapped as the file buffer piece.
fn make() -> Result<usize, ()> {
    let object = sys::mem_create(SIZE as u64).map_err(drop)?;
    let raw = object.raw().0;
    let base = crate::allocation::heap(|state| {
        state.map_special(object, SIZE / posix_map::PAGE, posix_map::Kind::FileBuffer)
    })
    .map_err(drop)?;
    OBJECT.store(raw, Ordering::Release);
    Ok(base)
}

/// A read of the description `fd` of the RAM service for the bytes of `out` (more than one
/// message of them) through a cell: from `offset`, or from the position of the description
/// when there is none. Up to `READ_PORTION` bytes come back, the count. None when the read
/// goes by messages (no cell to be had).
pub(crate) fn read(
    transport: &Transport,
    fd: u32,
    offset: Option<u64>,
    out: &mut [u8],
) -> Option<Result<usize, FsError>> {
    let count = out.len().min(READ_PORTION);
    let cell = cell_waiting(count)?;
    let object = Handle::<Memory>::borrowed(rt::abi::Handle(OBJECT.load(Ordering::Acquire)));
    match transport.read_into(fd, offset, count, &object, cell.place()) {
        Ok(Some(n)) => {
            THROUGH.fetch_add(1, Ordering::Relaxed);
            out[..n].copy_from_slice(cell.bytes(n));
            Some(Ok(n))
        }
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }
}

/// A forked child: no buffer and no cell.
pub(crate) fn after_fork() {
    STATE.store(ABSENT, Ordering::Release);
    FREE.store(0, Ordering::Release);
}
