// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread that lets go of the objects of images (images.rs). The last
//! process that used an image frees its entry, and the service's handle of
//! the object (the code and the read-only data, megabytes for a program
//! with a large library) is the last one: closing it queues the release of
//! its pages at the level of the caller, and a level at or above the
//! caller's runs inside the call. The loop at the service's level would
//! spend a long stretch of one step in it, so the loop hands the handle to
//! this thread (`give`) and the thread closes it at the base level of the
//! process whose end freed the image (spec 7.7: the cleanup of a process
//! runs at the level of its cause), then tells the loop (REAPED). The loop
//! reports the end of the process once its object is back (`take`).
//!
//! One place for each entry of the table of images: the loop writes the
//! handle, the level and the record and tells the thread (a bit of the
//! place); the thread sets its own priority to the level, closes the handle,
//! sets the flag and tells the loop, and goes back to the level of the
//! service, so that the next notice wakes it before anything below. The
//! thread's stack and message buffer are its own.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64, Ordering};
use proto_process::IMAGES;
use rt::handle::{Channel, Handle, Memory, Process, Thread};
use rt::sys::Received;
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 8 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, five pages after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 5 * 4096;

struct Place {
    /// The place is given and not taken yet.
    used: AtomicBool,
    handle: AtomicU64,
    level: AtomicU8,
    record: AtomicU16,
    /// The object is for the exit of the record: the loop reports its end
    /// when the last of its objects is back.
    exit: AtomicBool,
    done: AtomicBool,
}

static PLACES: [Place; IMAGES] = [const {
    Place {
        used: AtomicBool::new(false),
        handle: AtomicU64::new(0),
        level: AtomicU8::new(1),
        record: AtomicU16::new(0),
        exit: AtomicBool::new(false),
        done: AtomicBool::new(false),
    }
}; IMAGES];
/// The channel the thread waits on, the copy of the loop's channel that
/// tells the loop (label REAPED) and the level of the service.
static WAITS: AtomicU64 = AtomicU64::new(0);
static TELLS: AtomicU64 = AtomicU64::new(0);
static THREAD: AtomicU64 = AtomicU64::new(0);
static HIGH: AtomicU8 = AtomicU8::new(1);
/// The longest close so far, in ticks (the steps build prints a new longest).
#[cfg(feature = "steps")]
static LONGEST: AtomicU64 = AtomicU64::new(0);

/// Starts the thread in `own`, the service's process, at `level`; `tells` is
/// the copy of the loop's channel with NOTIFY and the label REAPED. The copy
/// of the thread's channel the loop tells it through comes back.
pub fn start(
    own: &Handle<Process>,
    tells: Handle<Channel>,
    level: u8,
) -> Result<Handle<Channel>, abi::Error> {
    let waits = sys::channel_create(level)?;
    let wake = sys::handle_duplicate(&waits, abi::Rights::NOTIFY)?;
    WAITS.store(waits.into_raw().0, Ordering::Release);
    TELLS.store(tells.into_raw().0, Ordering::Release);
    HIGH.store(level, Ordering::Release);
    // SAFETY: STACK is the thread's alone, and the page five after the main
    // thread's buffer is free.
    let thread = unsafe {
        sys::thread_create(own, serve, STACK.top(), 0, level, abi::Policy::Fifo, BUFFER)
    }?;
    // The thread lives as long as the service.
    THREAD.store(thread.into_raw().0, Ordering::Release);
    sys::thread_start(&Handle::<Thread>::borrowed(abi::Handle(
        THREAD.load(Ordering::Acquire),
    )))?;
    Ok(wake)
}

/// Gives the thread `memory` to close at `level`, for the record `record`
/// (`exit`: its end waits for it). The object comes back when no place is
/// free or the thread could not be told.
pub fn give(
    wake: &Handle<Channel>,
    memory: Handle<Memory>,
    level: u8,
    record: usize,
    exit: bool,
) -> Result<(), Handle<Memory>> {
    let Some(place) = PLACES.iter().position(|p| {
        p.used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }) else {
        return Err(memory);
    };
    let slot = &PLACES[place];
    slot.done.store(false, Ordering::Release);
    slot.level.store(level.max(1), Ordering::Release);
    slot.record.store(record as u16, Ordering::Release);
    slot.exit.store(exit, Ordering::Release);
    let raw = memory.into_raw().0;
    slot.handle.store(raw, Ordering::Release);
    if sys::notify(wake, 1 << place).is_err() {
        slot.handle.store(0, Ordering::Release);
        slot.used.store(false, Ordering::Release);
        return Err(Handle::from_raw(abi::Handle(raw)));
    }
    Ok(())
}

/// A place the thread is done with: the record it was given for and whether
/// its end waits for it; the place is free again. None when no place is done.
pub fn take() -> Option<(usize, bool)> {
    for slot in &PLACES {
        if slot.used.load(Ordering::Acquire) && slot.done.load(Ordering::Acquire) {
            let taken = (
                usize::from(slot.record.load(Ordering::Acquire)),
                slot.exit.load(Ordering::Acquire),
            );
            slot.done.store(false, Ordering::Relaxed);
            slot.used.store(false, Ordering::Release);
            return Some(taken);
        }
    }
    None
}

/// Whether a place is done and not taken.
pub fn waiting() -> bool {
    PLACES
        .iter()
        .any(|p| p.used.load(Ordering::Acquire) && p.done.load(Ordering::Acquire))
}

extern "C" fn serve(_: u64) -> ! {
    let waits = Handle::<Channel>::borrowed(abi::Handle(WAITS.load(Ordering::Acquire)));
    let Ok(me) = sys::self_thread() else {
        sys::thread_exit();
    };
    loop {
        match sys::receive(&waits) {
            Ok(Received::Notification { bits, .. }) => {
                for place in 0..PLACES.len() {
                    if bits >> place & 1 != 0 {
                        close(place, &me);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => sys::thread_exit(),
        }
    }
}

/// Closes the object of `place` at its level, then tells the loop.
fn close(place: usize, me: &Handle<Thread>) {
    let slot = &PLACES[place];
    let raw = slot.handle.swap(0, Ordering::Acquire);
    if raw == 0 {
        return;
    }
    let level = slot.level.load(Ordering::Acquire);
    let _ = sys::thread_set_priority(me, level, abi::Policy::Fifo);
    #[cfg(feature = "steps")]
    let began = rt::time::now();
    drop(Handle::<Memory>::from_raw(abi::Handle(raw)));
    #[cfg(feature = "steps")]
    {
        let took = rt::time::now().saturating_sub(began);
        if took > LONGEST.fetch_max(took, Ordering::Relaxed) {
            rt::println!("posix-process: reaper level {level} {took} ticks");
        }
    }
    slot.done.store(true, Ordering::Release);
    let _ = sys::thread_set_priority(me, HIGH.load(Ordering::Acquire), abi::Policy::Fifo);
    let tells = Handle::<Channel>::borrowed(abi::Handle(TELLS.load(Ordering::Acquire)));
    let _ = sys::notify(&tells, 1);
}
