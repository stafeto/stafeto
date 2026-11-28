// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The worker thread of the layer service (the layered file system, step C4 part A): the bytes of
//! the copies up. No step of the loop may hold a copy, so a lower file is copied here, at the level 30
//! with no budget, on the CPUs of the service (`GENERAL_CPUS`), as the worker thread of the data file
//! service is. The thread has sessions of its own: with the data file service (the label `SERVICE`)
//! and with the RAM file service (the boot profile), and one window of `WINDOW_BYTES`, given to the
//! data file service with WINDOW and to the RAM file service with each read: the first cell of it
//! is the place a piece of the lower file is read into and the part the data file service writes
//! from. The bytes cross two copies (the RAM file service into the cell, the data file service from
//! the cell into littlefs) and none in this service. Its own work is a few calls for each 64 KiB;
//! the work of the RAM file service goes on at its level under its step of 12 KiB, and the work of
//! the data file service under its budget.
//!
//! The loop and the thread share a table of the orders (one place for each place of the table of
//! copies, `layerd::copy`): the loop writes an order and marks the place ORDERED and kicks the
//! thread; the thread takes it, runs it (`layerd::copy::Copier`, one unit of one copy in each
//! turn, round robin) and writes how it ended, marks the place ENDED and notifies the loop. Each
//! change of a state is a release store and each look at it an acquire load.

use crate::data::Data;
use abi::{Access, Rights};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering::Acquire, Ordering::Release};
use layerd::copy::{Copier, Ended, Order, PLACES};
use layerd::volume::{Bulk, CELL, R, Volume};
use proto_data as p;
use rt::fs::Files;
use rt::handle::{Channel, Memory, Process};
use rt::{Handle, sys};

/// The level of the thread: with the worker thread of the data file service, below every service
/// it calls and below the ceiling of the programs.
pub const LEVEL: u8 = 30;
/// The thread's message buffer: the page after the registrar's.
const MSGBUF: usize = abi::INIT_MSGBUF as usize + 2 * 4096;
/// Where the window is mapped.
const WINDOW_AT: usize = 0x58_4000_0000;
/// The label of the kick the loop gives the thread.
const LABEL_KICK: u64 = 1;

static STACK: rt::Stack<{ 64 * 1024 }> = rt::Stack::new();

const FREE: u8 = 0;
const ORDERED: u8 = 1;
const TAKEN: u8 = 2;
const ENDED: u8 = 3;

struct Place {
    state: AtomicU8,
    order: UnsafeCell<Option<Order>>,
    ended: UnsafeCell<Option<Ended>>,
}

struct Orders([Place; PLACES]);

// SAFETY: a place's cells are written by the thread that owns its state (the loop for FREE and
// ENDED, the worker for ORDERED and TAKEN) and read by the other after the release store of the
// state that follows the write.
unsafe impl Sync for Orders {}

static ORDERS: Orders = Orders(
    [const {
        Place {
            state: AtomicU8::new(FREE),
            order: UnsafeCell::new(None),
            ended: UnsafeCell::new(None),
        }
    }; PLACES],
);

/// The raw handles the thread works with, set before it starts.
static DONE: AtomicU64 = AtomicU64::new(0);
static JOBS: AtomicU64 = AtomicU64::new(0);
static FILES: AtomicU64 = AtomicU64::new(0);
static DATA: AtomicU64 = AtomicU64::new(0);
static MEMORY: AtomicU64 = AtomicU64::new(0);

/// The loop's side: an order for the thread. The place is free, since the table of copies hands
/// out a place only after its outcome was taken.
pub fn publish(order: &Order) {
    let place = &ORDERS.0[usize::from(order.place)];
    debug_assert_eq!(place.state.load(Acquire), FREE);
    // SAFETY: the place is FREE: the thread does not look at it before the store below.
    unsafe { *place.order.get() = Some(*order) };
    place.state.store(ORDERED, Release);
}

/// The loop's side: how a copy ended, once for each; None when none has.
pub fn collect() -> Option<Ended> {
    for place in &ORDERS.0 {
        if place.state.load(Acquire) == ENDED {
            // SAFETY: ENDED is the thread's last word on the place, after its write.
            let ended = unsafe { (*place.ended.get()).take() };
            place.state.store(FREE, Release);
            if ended.is_some() {
                return ended;
            }
        }
    }
    None
}

/// What the thread starts with: its sessions and its window, made by the loop's thread (the
/// connections wait for init), and the handles of the two notifications.
pub struct Start<'a> {
    pub process: &'a Handle<Process>,
    pub files: Files,
    pub data: Handle<Channel>,
    /// The loop's channel and level: the notification that says a copy ended.
    pub done: Handle<Channel>,
}

/// Starts the thread: the window made and given to the data file service, the thread created. The
/// handle the loop kicks it with.
pub fn start(start: Start<'_>) -> Result<Handle<Channel>, &'static str> {
    let memory = sys::mem_create(p::WINDOW_BYTES as u64).map_err(|_| "no memory for the window")?;
    sys::mem_map(
        start.process,
        &memory,
        0,
        p::WINDOW_BYTES as u64,
        WINDOW_AT,
        Access::ReadWrite,
    )
    .map_err(|_| "the window did not map")?;
    let mut data = Data {
        session: start.data,
    };
    data.window(&memory).map_err(|_| "the window was refused")?;
    let jobs = sys::channel_create(LEVEL).map_err(|_| "no channel for the thread")?;
    let kick = sys::handle_label(&jobs, Rights::NOTIFY, LABEL_KICK, LEVEL)
        .map_err(|_| "no kick for the thread")?;
    DONE.store(start.done.into_raw().0, Release);
    JOBS.store(jobs.into_raw().0, Release);
    // The Files and the data session are kept for the thread's life.
    FILES.store(start.files.sessions().0.raw().0, Release);
    core::mem::forget(start.files);
    DATA.store(data.session.into_raw().0, Release);
    MEMORY.store(memory.into_raw().0, Release);
    // The break `break-layerd-copy-in-loop` has no thread: the loop copies in its own steps.
    if cfg!(feature = "break-layerd-copy-in-loop") {
        return Ok(kick);
    }
    // SAFETY: STACK is the thread's alone, and the page after the registrar's message buffer is
    // free.
    let thread = unsafe {
        sys::thread_create(
            start.process,
            run,
            STACK.top(),
            0,
            LEVEL,
            abi::Policy::RoundRobin,
            MSGBUF,
        )
    }
    .map_err(|_| "no thread")?;
    sys::thread_start(&thread).map_err(|_| "the thread did not start")?;
    core::mem::forget(thread);
    Ok(kick)
}

/// The calls of a copy: the sessions, the window, and the cell, the first of the window.
pub struct Moves {
    files: Files,
    data: Data,
    memory: Handle<Memory>,
}

impl Moves {
    /// The calls from the raw handles `start` left.
    fn from_statics() -> Moves {
        Moves {
            files: Files::from_sessions(Handle::from_raw(abi::Handle(FILES.load(Acquire))), None),
            data: Data {
                session: Handle::from_raw(abi::Handle(DATA.load(Acquire))),
            },
            memory: Handle::from_raw(abi::Handle(MEMORY.load(Acquire))),
        }
    }

    /// The part of the cell the data file service writes: one part with no lease.
    fn pwrite_cell(&mut self, handle: u32, offset: u64, count: usize) -> R<usize> {
        self.data.part(handle, offset, count)
    }
}

impl Bulk for Moves {
    fn open_lower(&mut self, path: &[u8]) -> R<u32> {
        self.files
            .open_marked_bytes(path, proto_fs::READ_ONLY)
            .map(|(fd, _)| fd)
    }

    fn read_lower(&mut self, fd: u32, offset: u64, at: usize, len: usize) -> R<usize> {
        self.files
            .read_into(fd, Some(offset), len, &self.memory, at as u64)
    }

    fn cut(&mut self, point: u8) {
        crate::data::stop(point)
    }

    fn cell(&self) -> &[u8] {
        // SAFETY: the window is mapped at `WINDOW_AT` for `WINDOW_BYTES`; this thread reads the cell
        // between its calls, when neither service moves bytes of it.
        unsafe { core::slice::from_raw_parts(WINDOW_AT as *const u8, CELL) }
    }

    fn close_lower(&mut self, fd: u32) {
        let _ = self.files.close(fd);
    }

    fn open_work(&mut self, path: &[u8], mode: u32, ino: u64) -> R<u32> {
        self.data
            .open_numbered(path, p::WRITE | p::CREATE | p::EXCLUSIVE, mode, ino)
    }

    fn write_cell(&mut self, handle: u32, offset: u64, count: usize) -> R<usize> {
        self.pwrite_cell(handle, offset, count)
    }

    fn fsync(&mut self, handle: u32) -> R<()> {
        self.data.fsync(handle)
    }

    fn chown(&mut self, path: &[u8], uid: u32, gid: u32) -> R<()> {
        self.data.chown(path, uid, gid)
    }

    fn chmod(&mut self, path: &[u8], mode: u32) -> R<()> {
        self.data.chmod(path, mode)
    }

    fn utimens(&mut self, path: &[u8], atime: i64, mtime: i64) -> R<()> {
        self.data.utimens(path, atime, mtime)
    }

    fn close(&mut self, handle: u32) -> R<()> {
        self.data.close(handle)
    }
}

extern "C" fn run(_: u64) -> ! {
    let jobs = Handle::<Channel>::borrowed(abi::Handle(JOBS.load(Acquire)));
    let done = Handle::<Channel>::borrowed(abi::Handle(DONE.load(Acquire)));
    let mut moves = Moves::from_statics();
    let mut copier = Copier::new();
    loop {
        take_orders(&mut copier);
        if copier.busy() == 0 {
            // Nothing to do: wait for the loop's kick. A kick that came since the look at the orders
            // is still pending.
            let _ = sys::receive(&jobs);
            continue;
        }
        if let Some(ended) = copier.turn(&mut moves) {
            let place = &ORDERS.0[usize::from(ended.place)];
            // SAFETY: the place is TAKEN: the loop does not look at it before the store below.
            unsafe { *place.ended.get() = Some(ended) };
            place.state.store(ENDED, Release);
            let _ = sys::notify(&done, 1);
        }
    }
}

/// The orders the loop has written become copies of the copier, while it has a place for them.
fn take_orders(copier: &mut Copier) {
    for place in &ORDERS.0 {
        if place.state.load(Acquire) != ORDERED {
            continue;
        }
        // SAFETY: ORDERED is the loop's last word on the place, after its write.
        let Some(order) = (unsafe { *place.order.get() }) else {
            continue;
        };
        if copier.add(order) {
            place.state.store(TAKEN, Release);
        }
    }
}

/// The break `break-layerd-copy-in-loop`: the loop's own thread runs the copier to the end, in the
/// step that handed the orders out, as the worker thread would have.
#[cfg(feature = "break-layerd-copy-in-loop")]
pub fn inline() {
    let mut moves = Moves::from_statics();
    let mut copier = Copier::new();
    take_orders(&mut copier);
    while copier.busy() > 0 {
        if let Some(ended) = copier.turn(&mut moves) {
            let place = &ORDERS.0[usize::from(ended.place)];
            // SAFETY: the place is TAKEN: the loop collects it only after the store below.
            unsafe { *place.ended.get() = Some(ended) };
            place.state.store(ENDED, Release);
        }
    }
    core::mem::forget(moves);
}
