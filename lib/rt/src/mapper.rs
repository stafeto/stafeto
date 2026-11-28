// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread of a service that maps and unmaps large objects. The kernel maps an object in
//! portions of 16 pages with points of preemption, so a mapping of tens of megabytes takes a
//! long call; the main thread of a service must not wait for it. The thread touches no table
//! of the service: it takes an order from the cell, makes the call at the level the order
//! names, leaves the outcome and tells the main thread with NOTIFY (the pattern of init's
//! worker). One order is in the cell at a time, and the thread has a static stack of 16 KiB.

use crate::abi::{Access, Error, Policy};
use crate::handle::{Channel, Handle, Memory, Process, Thread};
use crate::{Stack, sys};
use core::cell::{Cell as Level, UnsafeCell};
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

const STACK_SIZE: usize = 16 * 1024;

static STACK: Stack<STACK_SIZE> = Stack::new();

/// What the thread does. A mapping borrows the object's handle: its owner keeps it until the
/// outcome is taken.
enum Order {
    Map {
        memory: u64,
        offset: u64,
        size: u64,
        at: usize,
        access: Access,
    },
    /// Takes `size` bytes at `at` out of the space (nothing when `size` is 0), and closes the
    /// handle `close` when that went well (`abi::Handle::INVALID`: none). The close is the
    /// last reference of an object whose other holders are gone, so its teardown is queued
    /// at the level the order works at.
    Unmap {
        size: u64,
        at: usize,
        close: crate::abi::Handle,
    },
}

const FREE: u8 = 0;
const GIVEN: u8 = 1;
const DONE: u8 = 2;

struct Slot {
    state: AtomicU8,
    order: UnsafeCell<Option<Order>>,
    outcome: UnsafeCell<Option<Result<(), Error>>>,
}
// SAFETY: the state gives the cell to one thread at a time and one thread uses it.
unsafe impl Sync for Slot {}

static CELL: Slot = Slot {
    state: AtomicU8::new(FREE),
    order: UnsafeCell::new(None),
    outcome: UnsafeCell::new(None),
};

/// The raw handles the thread uses: the service's process, the thread's channel, the handle
/// it tells through. The bits it tells with.
static HANDLES: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
/// The thread, the cell and the handles are one set for the process: a second start is refused.
static STARTED: AtomicBool = AtomicBool::new(false);
static BITS: AtomicU64 = AtomicU64::new(0);
const PROCESS: usize = 0;
const WAKE: usize = 1;
const TELL: usize = 2;

fn view<K>(i: usize) -> ManuallyDrop<Handle<K>> {
    Handle::borrowed(crate::abi::Handle(HANDLES[i].load(Ordering::Relaxed)))
}

/// The main thread's side.
pub struct Mapper {
    thread: Handle<Thread>,
    wake: Handle<Channel>,
    /// The level the thread works at now (it is set with each order and can be raised while
    /// the order is in the cell).
    level: Level<u8>,
}

impl Mapper {
    /// Starts the thread in `process` at level 1, waiting. It tells with NOTIFY of `bits`
    /// through `tell`, a handle with NOTIFY (the service's channel, or a copy with a label of
    /// its own) that the caller keeps for the life of the service. `buffer` is the thread's
    /// message buffer, a page of the process that no other thread uses.
    pub fn start(
        process: &Handle<Process>,
        tell: &Handle<Channel>,
        bits: u64,
        buffer: usize,
    ) -> Result<Mapper, Error> {
        if STARTED.swap(true, Ordering::AcqRel) {
            return Err(Error::BadState);
        }
        let wake = sys::channel_create(1)?;
        BITS.store(bits, Ordering::Relaxed);
        for (i, raw) in [
            (PROCESS, process.raw()),
            (WAKE, wake.raw()),
            (TELL, tell.raw()),
        ] {
            HANDLES[i].store(raw.0, Ordering::Relaxed);
        }
        // SAFETY: STACK is the thread's alone.
        let thread =
            unsafe { sys::thread_create(process, work, STACK.top(), 0, 1, Policy::Fifo, buffer) }?;
        sys::thread_start(&thread)?;
        Ok(Mapper {
            thread,
            wake,
            level: Level::new(1),
        })
    }

    /// Whether the cell is free for an order.
    pub fn idle(&self) -> bool {
        CELL.state.load(Ordering::Acquire) == FREE
    }

    /// Maps `size` bytes of `memory` from `offset` at `at` in one call, working at `level`.
    /// The caller keeps `memory` until the outcome is taken.
    pub fn map(
        &self,
        level: u8,
        memory: &Handle<Memory>,
        offset: u64,
        size: u64,
        at: usize,
        access: Access,
    ) -> Result<(), Error> {
        self.give(
            level,
            Order::Map {
                memory: memory.raw().0,
                offset,
                size,
                at,
                access,
            },
        )
    }

    /// Takes `size` bytes at `at` out of the space, working at `level`.
    pub fn unmap(&self, level: u8, size: u64, at: usize) -> Result<(), Error> {
        self.give(
            level,
            Order::Unmap {
                size,
                at,
                close: crate::abi::Handle::INVALID,
            },
        )
    }

    /// `unmap`, and once the range is out the thread closes `memory` (nothing is unmapped
    /// when `size` is 0): when the handle is the last reference of the object, the kernel
    /// takes it apart at `level`, behind the threads above it, and not at the level of the
    /// caller. After an outcome of Ok the handle is closed and its owner must not close it
    /// again (`Handle::into_raw`); after an error it is open. The caller keeps `memory` until
    /// the outcome is taken.
    pub fn unmap_close(
        &self,
        level: u8,
        size: u64,
        at: usize,
        memory: &Handle<Memory>,
    ) -> Result<(), Error> {
        self.give(
            level,
            Order::Unmap {
                size,
                at,
                close: memory.raw(),
            },
        )
    }

    /// Raises the level of the order in the cell to `level` when it is higher than the
    /// order's: a client that waits for the thread lends its level.
    pub fn raise(&self, level: u8) {
        if level > self.level.get()
            && sys::thread_set_priority(&self.thread, level, Policy::Fifo).is_ok()
        {
            self.level.set(level);
        }
    }

    fn give(&self, level: u8, order: Order) -> Result<(), Error> {
        assert_eq!(
            CELL.state.load(Ordering::Acquire),
            FREE,
            "one order at a time"
        );
        sys::thread_set_priority(&self.thread, level, Policy::Fifo)?;
        self.level.set(level);
        // SAFETY: FREE: the cell is the main thread's.
        unsafe { *CELL.order.get() = Some(order) };
        CELL.state.store(GIVEN, Ordering::Release);
        if let Err(error) = sys::notify(&self.wake, 1) {
            // The thread was not woken: the order is taken back, so that the cell does not stay
            // given for ever.
            // SAFETY: the thread has not seen the order; the cell is the main thread's again.
            unsafe { *CELL.order.get() = None };
            CELL.state.store(FREE, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }

    /// The outcome of the order once the thread did it.
    pub fn take(&self) -> Option<Result<(), Error>> {
        if CELL.state.load(Ordering::Acquire) != DONE {
            return None;
        }
        // SAFETY: DONE: the cell is the main thread's.
        let outcome = unsafe { (*CELL.outcome.get()).take() };
        CELL.state.store(FREE, Ordering::Release);
        outcome
    }
}

extern "C" fn work(_: u64) -> ! {
    let (process, wake, tell) = (
        view::<Process>(PROCESS),
        view::<Channel>(WAKE),
        view::<Channel>(TELL),
    );
    loop {
        sys::receive(&wake).expect("the thread's channel lives as long as the service");
        if CELL.state.load(Ordering::Acquire) != GIVEN {
            continue;
        }
        // SAFETY: GIVEN: the cell is the thread's.
        let Some(order) = (unsafe { (*CELL.order.get()).take() }) else {
            continue;
        };
        let outcome = match order {
            Order::Map {
                memory,
                offset,
                size,
                at,
                access,
            } => {
                let memory = Handle::<Memory>::borrowed(crate::abi::Handle(memory));
                sys::mem_map(&process, &memory, offset, size, at, access)
            }
            Order::Unmap { size, at, close } => {
                let outcome = if size == 0 {
                    Ok(())
                } else {
                    // SAFETY: the range is one that no slice of the service reaches any more
                    // (the caller's promise when it gave the order).
                    unsafe { sys::mem_unmap(&process, at, size) }
                };
                if outcome.is_ok() && close != crate::abi::Handle::INVALID {
                    drop(Handle::<Memory>::from_raw(close));
                }
                outcome
            }
        };
        // SAFETY: still GIVEN: the cell is the thread's until the store.
        unsafe { *CELL.outcome.get() = Some(outcome) };
        CELL.state.store(DONE, Ordering::Release);
        let _ = sys::notify(&tell, BITS.load(Ordering::Relaxed));
    }
}
