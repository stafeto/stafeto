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

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use posix_process_service::reaping::Places;
use proto_process::IMAGES;
use rt::handle::{Channel, Handle, Memory, Process, Thread};
use rt::sys::Received;
use rt::{Stack, abi, sys};

const STACK_SIZE: usize = 8 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer, five pages after the main thread's.
const BUFFER: usize = abi::INIT_MSGBUF as usize + 5 * 4096;

static PLACES: Places<IMAGES> = Places::new();
/// The channel the thread waits on, the copy of the loop's channel that
/// tells the loop (label REAPED) and the level of the service.
static WAITS: AtomicU64 = AtomicU64::new(0);
static TELLS: AtomicU64 = AtomicU64::new(0);
static THREAD: AtomicU64 = AtomicU64::new(0);
static HIGH: AtomicU8 = AtomicU8::new(1);
/// The longest close so far, in ticks, and the highest level one was made
/// at (the steps build prints a new longest of each).
#[cfg(feature = "steps")]
static LONGEST: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "steps")]
static HIGHEST: AtomicU8 = AtomicU8::new(0);

/// Starts the thread in `own`, the service's process, at `level`; `tells` is
/// the copy of the loop's channel with NOTIFY and the label REAPED, `exit`
/// the one with the label of the thread's end. The copy of the thread's
/// channel the loop tells it through comes back.
pub fn start(
    own: &Handle<Process>,
    tells: Handle<Channel>,
    exit: Handle<Channel>,
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
        sys::thread_create_with(
            own,
            serve,
            STACK.top(),
            0,
            level,
            abi::Policy::Fifo,
            BUFFER,
            Some((&exit, level)),
        )
    }?;
    // The exit place holds a slot of the channel until the thread goes.
    let _ = exit.into_raw();
    THREAD.store(thread.into_raw().0, Ordering::Release);
    sys::thread_start(&Handle::<Thread>::borrowed(abi::Handle(
        THREAD.load(Ordering::Acquire),
    )))?;
    Ok(wake)
}

/// Gives the thread `memory` to close at `level`, for the record `record`
/// (`exit`: its end waits for it, and `child` is the handle of its process,
/// whose memory account the thread watches until the pages are back). The
/// object comes back when no place is free or the thread could not be told.
pub fn give(
    wake: &Handle<Channel>,
    memory: Handle<Memory>,
    child: u64,
    level: u8,
    record: usize,
    exit: bool,
) -> Result<(), Handle<Memory>> {
    let raw = memory.into_raw().0;
    let Some(place) = PLACES.give(raw, child, level, record, exit) else {
        return Err(Handle::from_raw(abi::Handle(raw)));
    };
    if sys::notify(wake, 1 << place).is_err() {
        return Err(Handle::from_raw(abi::Handle(PLACES.undo(place))));
    }
    // A close of a higher level than the one the thread works at lifts it
    // (never lowers it: idle it stands at the service's level): the close it
    // is in the middle of does not run below what waits.
    let thread = Handle::<Thread>::borrowed(abi::Handle(THREAD.load(Ordering::Acquire)));
    let top = PLACES.highest_open();
    if sys::thread_info(&thread).is_ok_and(|i| i.base < top) {
        let _ = sys::thread_set_priority(&thread, top, abi::Policy::Fifo);
    }
    Ok(())
}

/// A place the thread is done with: the record it was given for and whether
/// its end waits for it; the place is free again. None when no place is done.
pub fn take() -> Option<(usize, bool)> {
    PLACES.take()
}

/// Whether a place is done and not taken.
pub fn waiting() -> bool {
    PLACES.waiting()
}

/// The thread ended: the loop closes the objects of the places it was given
/// and had not closed, and marks them done. This is the failure path: the
/// close of an object of tens of megabytes runs in one step of the loop at the
/// service's level, as it did before the reaper, so the steps of that path
/// pass the bound of a step. It happens once, when the thread is gone.
pub fn close_open() {
    for (place, handle) in PLACES.open() {
        drop(Handle::<Memory>::from_raw(abi::Handle(handle)));
        PLACES.finish(place);
    }
}

extern "C" fn serve(_: u64) -> ! {
    let waits = Handle::<Channel>::borrowed(abi::Handle(WAITS.load(Ordering::Acquire)));
    let Ok(me) = sys::self_thread() else {
        sys::thread_exit();
    };
    // The timer of the pauses is on the thread's own channel, as the loop's
    // timer is on the loop's.
    let nap = Nap::new(&waits, HIGH.load(Ordering::Acquire));
    #[cfg(feature = "steps")]
    if let Err(e) = &nap {
        rt::println!("posix-process: the reaper has no timer ({e:?})");
    }
    let nap = nap.ok();
    // The places told while the thread paused wait here.
    let mut told = 0u64;
    loop {
        if told == 0 {
            match sys::receive(&waits) {
                Ok(Received::Notification {
                    source: abi::Source::Timer,
                    ..
                }) => {}
                Ok(Received::Notification { bits, .. }) => told |= bits,
                Ok(_) => {}
                Err(_) => sys::thread_exit(),
            }
            continue;
        }
        let place = told.trailing_zeros() as usize;
        told &= told - 1;
        if place < IMAGES {
            close(place, &me, nap.as_ref(), &waits, &mut told);
        }
    }
}

/// Closes the object of `place` at the highest level among the places that
/// wait (its own at least), then tells the loop.
fn close(
    place: usize,
    me: &Handle<Thread>,
    nap: Option<&Nap>,
    waits: &Handle<Channel>,
    told: &mut u64,
) {
    let Some(work) = PLACES.start(place) else {
        // A notice of a place that holds nothing: given and closed already.
        return;
    };
    let level = work.level.max(PLACES.highest_open());
    let _ = sys::thread_set_priority(me, level, abi::Policy::Fifo);
    #[cfg(feature = "steps")]
    let began = rt::time::now();
    drop(Handle::<Memory>::from_raw(abi::Handle(work.handle)));
    #[cfg(feature = "steps")]
    {
        let took = rt::time::now().saturating_sub(began);
        if took > LONGEST.fetch_max(took, Ordering::Relaxed) {
            rt::println!("posix-process: reaper level {level} {took} ticks");
        }
        if level > HIGHEST.fetch_max(level, Ordering::Relaxed) {
            rt::println!("posix-process: reaper highest level {level}");
        }
    }
    // Only the last object of a process waits for its pages: the account of
    // the process holds the others' pages until they are closed too.
    let more = PLACES.another_open(place, work.child);
    if let (Some(nap), true, false) = (nap, work.child != 0, more) {
        settle(nap, work.child, level, waits, told);
    }
    PLACES.finish(place);
    let _ = sys::thread_set_priority(me, HIGH.load(Ordering::Acquire), abi::Policy::Fifo);
    let tells = Handle::<Channel>::borrowed(abi::Handle(TELLS.load(Ordering::Acquire)));
    let _ = sys::notify(&tells, 1);
}

/// The memory a process uses once its pages are back (its own shell and
/// tables), bytes: the pause for the pages ends below it.
const SETTLED: u64 = 64 * 1024;
/// The label of the thread's timer on its channel.
const TIMER_LABEL: u64 = 1 << 62;
/// The longest `settle` waits, and one pause, in nanoseconds.
const SETTLE_NS: u64 = 100_000_000;
const NAP_NS: u64 = 1_000_000;

/// Waits at the thread's level until the memory account of the process
/// `child` has what it keeps for its shell: the close queues what is left
/// of the object and of its payer's shell at that level, and the queue
/// runs there only when nothing above wants the CPU, so the thread pauses
/// (1 ms at a time, until 100 ms of the clock went by since it began) and
/// looks again. It stops at once for a place of a higher level than its own:
/// that close must not wait behind this one's pages. The process ends in
/// the record once its pages are back.
fn settle(nap: &Nap, child: u64, level: u8, waits: &Handle<Channel>, told: &mut u64) {
    let child = Handle::<Process>::borrowed(abi::Handle(child));
    let began = rt::time::ticks_to_ns(rt::time::now());
    let until = began + SETTLE_NS;
    let mut naps = 0u32;
    // Why the wait ended, for the steps build's line (the probe judges the
    // deadline only: the other ends leave the pages to the queue).
    let mut why = "deadline";
    while rt::time::ticks_to_ns(rt::time::now()) < until {
        let used = sys::process_memory(&child).map_or(0, |m| m.used);
        if used <= SETTLED {
            why = "drained";
            break;
        }
        if PLACES.highest_open() > level {
            why = "higher";
            break;
        }
        if !nap.sleep(waits, told, until) {
            why = "timer";
            break;
        }
        naps += 1;
    }
    #[cfg(feature = "steps")]
    rt::println!(
        "posix-process: reaper waited {naps} pauses, {} ns, the child uses {} ended by {why}",
        rt::time::ticks_to_ns(rt::time::now()).saturating_sub(began),
        sys::process_memory(&child).map_or(0, |m| m.used)
    );
    #[cfg(not(feature = "steps"))]
    let _ = (naps, why);
}

/// The thread's own timer, on the channel it waits on.
struct Nap {
    timer: Handle<rt::handle::Timer>,
}

impl Nap {
    fn new(waits: &Handle<Channel>, level: u8) -> Result<Nap, abi::Error> {
        let ends = sys::handle_label(waits, abi::Rights::RECEIVE, TIMER_LABEL, level)?;
        let timer = sys::timer_create(&ends, level)?;
        Ok(Nap { timer })
    }

    /// Sleeps a pause (not past `until`) on `waits`; the places told meanwhile
    /// are added to `told`. False when the timer or the channel failed.
    fn sleep(&self, waits: &Handle<Channel>, told: &mut u64, until: u64) -> bool {
        let deadline = (rt::time::ticks_to_ns(rt::time::now()) + NAP_NS).min(until);
        if sys::timer_set(&self.timer, deadline).is_err() {
            return false;
        }
        loop {
            match sys::receive(waits) {
                Ok(Received::Notification {
                    source: abi::Source::Timer,
                    ..
                }) => {
                    if rt::time::reached(deadline) {
                        return true;
                    }
                }
                Ok(Received::Notification { bits, .. }) => *told |= bits,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }
}
