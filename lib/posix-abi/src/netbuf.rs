// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's shared buffer with the network service (BUFFER of
//! proto_net): a memory object of `proto_net::BUFFER_SIZE` bytes of the
//! process's own quota, mapped as the *network buffer piece* of the memory
//! map (posix_map::Kind::NetBuffer) and in the service for the session's
//! life. The layer cuts it into `proto_net::SLOTS` cells of `proto_net::SLOT`
//! bytes; one call of a stream (`send`, `recv`, `read`, `write`, `writev`)
//! takes a cell for the whole of its long operation and gives it back after
//! the service's last reply, a cancel's among them. No ring and nothing
//! that steers the service lies in the buffer: the cell and the length go
//! in the request.
//!
//! * The first call of a stream of more than `DATA_MAX` bytes asks for the
//!   buffer; the other threads go by messages meanwhile. A refusal (no
//!   memory, the service's limit, `buffers 0`) is final until `exec`, and the
//!   object goes at once.
//! * A call that finds no free cell goes by messages.
//! * A forked child has neither the piece (`Map::inherited` leaves it out)
//!   nor the cells: its session is a clone without a buffer, and it asks for
//!   its own. An exec'd image starts without one; ABANDON lets the
//!   service's mapping go.
//! * The state and the cells are atomic words; no lock of the layer is
//!   held over a request. The object is made and mapped under the lock of
//!   the heap alone.

use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use proto_net::{BUFFER_SIZE, DATA_MAX, SLOT, SLOTS};
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights};
use rt::sys;

/// The states of the buffer; any other value is `Ready`, the address of
/// the piece (a page, never below 4 KiB).
const ABSENT: usize = 0;
const ASKING: usize = 1;
const REFUSED: usize = 2;

static STATE: AtomicUsize = AtomicUsize::new(ABSENT);
/// The free cells, a bit each.
static FREE: AtomicU16 = AtomicU16::new(0);

const _: () = assert!(SLOTS == 16);

/// A cell a call holds; it goes back when the value drops.
pub(crate) struct Cell {
    index: u32,
    base: usize,
}

impl Cell {
    /// The offset of the cell in the buffer, which the request names.
    pub(crate) fn offset(&self) -> u32 {
        self.index * SLOT as u32
    }

    /// The bytes of the cell.
    ///
    /// The service writes into a cell only while the call that holds it
    /// waits for a reply of a RECV, and reads from it only in a SEND: the
    /// slice is used between the requests.
    pub(crate) fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: the cell is this value's alone (its bit is taken) and the
        // piece stays mapped until the process ends or execs.
        unsafe {
            core::slice::from_raw_parts_mut((self.base + self.offset() as usize) as *mut u8, SLOT)
        }
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        FREE.fetch_or(1 << self.index, Ordering::AcqRel);
    }
}

/// A cell for a call of `size` bytes of a stream: None for a call that one
/// message carries, while the buffer is asked for or refused, and when every
/// cell is taken.
pub(crate) fn cell(size: usize) -> Option<Cell> {
    if size <= DATA_MAX {
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

/// The buffer is asked for by one thread: the object, its piece and
/// BUFFER. The address of the piece, or None (refused, or another thread
/// asks).
fn ask() -> Option<usize> {
    if STATE
        .compare_exchange(ABSENT, ASKING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    let r = make();
    rt::println!("DIAGW ask result ok={}", r.is_ok());
    match r {
        Ok(base) => {
            FREE.store(u16::MAX, Ordering::Release);
            STATE.store(base, Ordering::Release);
            Some(base)
        }
        Err(()) => {
            STATE.store(REFUSED, Ordering::Release);
            None
        }
    }
}

/// The object, mapped as the network buffer piece and handed to the
/// service; the piece goes again when the service refuses.
fn make() -> Result<usize, ()> {
    let service = crate::net::session().ok_or_else(|| rt::println!("DIAGW no session"))?;
    let object = sys::mem_create(BUFFER_SIZE as u64).map_err(|e| rt::println!("DIAGW mem_create {e:?}"))?;
    let copy = sys::handle_duplicate(
        &object,
        Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
    )
    .map_err(drop)?;
    let pages = BUFFER_SIZE / posix_map::PAGE;
    let base = crate::allocation::heap(|state| {
        state.map_special(object, pages, posix_map::Kind::NetBuffer)
    })
    .map_err(|e| rt::println!("DIAGW map_special {e:?}"))?;
    let mut w = Writer::new();
    let asked = proto_net::write_buffer(BUFFER_SIZE as u32, &mut w).is_ok()
        && given(&rt::handle::Handle::borrowed(service), w.as_bytes(), copy);
    if !asked {
        rt::println!("DIAGW BUFFER not taken");
        let _ = crate::allocation::heap(|state| state.unmap_special(posix_map::Kind::NetBuffer));
        return Err(());
    }
    Ok(base)
}

/// BUFFER with `copy`: whether the service took it.
fn given(
    service: &rt::handle::Handle<rt::handle::Channel>,
    request: &[u8],
    copy: rt::handle::Handle<rt::handle::Memory>,
) -> bool {
    let mut copy = Some(copy.erase());
    let reply = loop {
        let Some(handle) = copy.take() else {
            return false;
        };
        match sys::send_handles(service, request, [handle]) {
            Ok(reply) => break reply,
            Err(refused) if refused.error == Error::Interrupted => {
                copy = refused.back.and_then(|mut back| back.pop());
            }
            Err(_) => return false,
        }
    };
    let mut buffer = [0u8; MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    r.u32()
        .is_ok_and(|word| Status::from_code(word) == Status::Ok)
}

/// A forked child: no buffer and no cell.
pub(crate) fn after_fork() {
    STATE.store(ABSENT, Ordering::Release);
    FREE.store(0, Ordering::Release);
}
