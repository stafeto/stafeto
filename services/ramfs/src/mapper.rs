// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread of the service that maps and unmaps the objects of layers. The kernel maps an
//! object in portions of 16 pages with points of preemption, so a layer of tens of megabytes
//! takes a long call; the main thread of the service must not wait for it. The thread touches
//! no table of the service: it takes an order from the cell, makes the call at the level the
//! client named, leaves the outcome and tells the main thread with NOTIFY and a label of its
//! own (the pattern of init's worker).

use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use rt::abi::{Access, Error, Policy, Rights};
use rt::handle::{Channel, Handle, Memory, Process, Thread};
use rt::{Stack, sys};

/// The label of the notification that an order is done.
pub const LABEL: u64 = 0x4c41_5952;
/// The window of layer record `index`: 64 windows of 1 GiB above the windows of the service.
pub const WINDOW: usize = 0x60_0000_0000;
pub const WINDOW_SIZE: u64 = 1 << 30;
/// The thread's message buffer, the page after that of the main thread.
const BUFFER: usize = rt::abi::INIT_MSGBUF as usize + 4096;
const STACK_SIZE: usize = 16 * 1024;

static STACK: Stack<STACK_SIZE> = Stack::new();

pub const fn window(index: usize) -> usize {
    WINDOW + index * WINDOW_SIZE as usize
}

enum Order {
    Map {
        memory: Handle<Memory>,
        size: u64,
        at: usize,
    },
    Unmap {
        size: u64,
        at: usize,
    },
}

const FREE: u8 = 0;
const GIVEN: u8 = 1;
const DONE: u8 = 2;

struct Cell {
    state: AtomicU8,
    order: UnsafeCell<Option<Order>>,
    outcome: UnsafeCell<Option<Result<(), Error>>>,
}
// SAFETY: the state gives the cell to one thread at a time and one thread uses it.
unsafe impl Sync for Cell {}

static CELL: Cell = Cell {
    state: AtomicU8::new(FREE),
    order: UnsafeCell::new(None),
    outcome: UnsafeCell::new(None),
};

/// The raw handles the thread uses: the service's process, the thread's channel and the
/// copy of the service's channel it tells through.
static HANDLES: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
const PROCESS: usize = 0;
const WAKE: usize = 1;
const TELL: usize = 2;

fn view<K>(i: usize) -> ManuallyDrop<Handle<K>> {
    Handle::borrowed(rt::abi::Handle(HANDLES[i].load(Ordering::Relaxed)))
}

/// The main thread's side.
pub struct Mapper {
    thread: Handle<Thread>,
    wake: Handle<Channel>,
}

impl Mapper {
    /// Starts the thread in `process` at level 1, waiting. It tells `channel`, the service's
    /// channel, with NOTIFY and `LABEL` at `level`.
    pub fn start(
        process: &Handle<Process>,
        channel: &Handle<Channel>,
        level: u8,
    ) -> Result<Mapper, Error> {
        let wake = sys::channel_create(1)?;
        let tell = sys::handle_label(channel, Rights::NOTIFY, LABEL, level)?;
        for (i, raw) in [
            (PROCESS, process.raw()),
            (WAKE, wake.raw()),
            (TELL, tell.into_raw()),
        ] {
            HANDLES[i].store(raw.0, Ordering::Relaxed);
        }
        // SAFETY: STACK is the thread's alone.
        let thread =
            unsafe { sys::thread_create(process, work, STACK.top(), 0, 1, Policy::Fifo, BUFFER) }?;
        sys::thread_start(&thread)?;
        Ok(Mapper { thread, wake })
    }

    /// Whether the cell is free for an order.
    pub fn idle(&self) -> bool {
        CELL.state.load(Ordering::Acquire) == FREE
    }

    /// Maps `memory` read-only at `at`, working at `level`.
    pub fn map(
        &self,
        level: u8,
        memory: Handle<Memory>,
        size: u64,
        at: usize,
    ) -> Result<(), Error> {
        self.give(level, Order::Map { memory, size, at })
    }

    /// Takes `size` bytes at `at` out of the space.
    pub fn unmap(&self, level: u8, size: u64, at: usize) -> Result<(), Error> {
        self.give(level, Order::Unmap { size, at })
    }

    fn give(&self, level: u8, order: Order) -> Result<(), Error> {
        assert_eq!(
            CELL.state.load(Ordering::Acquire),
            FREE,
            "one order at a time"
        );
        sys::thread_set_priority(&self.thread, level, Policy::Fifo)?;
        // SAFETY: FREE: the cell is the main thread's.
        unsafe { *CELL.order.get() = Some(order) };
        CELL.state.store(GIVEN, Ordering::Release);
        sys::notify(&self.wake, 1)
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
            Order::Map { memory, size, at } => {
                // The mapping holds the object; the handle goes with the order.
                sys::mem_map(&process, &memory, 0, size, at, Access::Read)
            }
            // SAFETY: the range is a window of a layer that no slice reaches any more.
            Order::Unmap { size, at } => unsafe { sys::mem_unmap(&process, at, size) },
        };
        // SAFETY: still GIVEN: the cell is the thread's until the store.
        unsafe { *CELL.outcome.get() = Some(outcome) };
        CELL.state.store(DONE, Ordering::Release);
        let _ = sys::notify(&tell, 1);
    }
}
