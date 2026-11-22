// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The signal handlers a thread is inside of, as the layer's own distributor counts them.
//!
//! The kernel keeps a depth for the entry of a thread, but a long jump out of a handler leaves it
//! above zero for the rest of the thread (`thread_upcall_bind` refuses after one, and `rt` binds
//! once per thread). A thread that ever jumped out of a handler would then look as if it ran in
//! one for good. The layer therefore notes each handler it calls (`enter` before the callback,
//! `leave` after it) with the frame of the call, and the hook of the jump takes off the ones the
//! jump leaves (`trim`, called from `posix_abi::shared::jump_mark`).
//!
//! The record of a thread holds `FRAMES` frames; a thread nested deeper is counted, and a jump
//! that leaves the last recorded frame leaves every deeper level too, so the count drops to the
//! recorded ones and trimming goes on. A jump that stops short of the last recorded frame leaves
//! the deeper levels counted, which sends the thread's large calls on `/data` by messages, never
//! into a wrong state.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use entries::{Frame, nested};

/// The frames a thread records.
const FRAMES: usize = 16;

struct Row {
    /// The handlers entered and not left.
    depth: AtomicU32,
    /// The frame of each recorded handler: its stack pointer (16-aligned) with the stack in bit 0.
    frames: [AtomicU64; FRAMES],
}

impl Row {
    const fn new() -> Row {
        Row {
            depth: AtomicU32::new(0),
            frames: [const { AtomicU64::new(0) }; FRAMES],
        }
    }
}

static ROWS: [Row; crate::relibc::PLACES + 1] = [const { Row::new() }; crate::relibc::PLACES + 1];

/// A thread with no block has no handlers: a spare row that nothing reads.
static NONE: Row = Row::new();

fn row() -> &'static Row {
    // SAFETY: a published block lives as long as its thread.
    match unsafe { posix_thread::block().as_ref() } {
        Some(block) => &ROWS[usize::try_from(block.thread_id).expect("a bounded thread place")],
        None => &NONE,
    }
}

/// Whether the layer notes handlers at all: set once the process makes a window for `/data`
/// (`track`). A process that never used it pays one load and a branch for each handler (the path
/// of a signal to a sleeping thread is measured by the rtbench rows S5, to the instruction).
/// A handler that was entered before the flag went up is not noted (`enter` says so, and
/// its `leave` is skipped), so the first large call on `/data` made inside such a handler
/// does not know it runs in one.
static TRACKING: AtomicBool = AtomicBool::new(false);

/// The layer notes handlers from now on.
#[cfg(feature = "data")]
pub(crate) fn track() {
    TRACKING.store(true, Ordering::Release);
}

/// The calling thread calls a handler: whether it was noted (the caller then calls `leave`).
#[inline(always)]
pub(crate) fn enter() -> bool {
    if !TRACKING.load(Ordering::Relaxed) {
        return false;
    }
    noted();
    true
}

#[inline(never)]
fn noted() {
    enter_from(crate::change::frame());
}

/// The calling thread calls a handler from the frame `frame`.
fn enter_from(frame: Frame) {
    let row = row();
    // The frame first, then the depth: a signal that comes between the two reads the depth of the
    // handlers before this one and a frame no one reads yet. Only the thread itself writes its row.
    let at = row.depth.load(Ordering::Relaxed) as usize;
    if let Some(slot) = row.frames.get(at) {
        slot.store(frame.sp | u64::from(frame.z), Ordering::Relaxed);
    }
    row.depth.store(at as u32 + 1, Ordering::Relaxed);
}

/// The handler returned.
pub(crate) fn leave() {
    let _ = row()
        .depth
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
}

/// Whether the calling thread is inside a handler that was noted.
#[cfg(feature = "data")]
pub(crate) fn active() -> bool {
    row().depth.load(Ordering::Relaxed) != 0
}

/// A long jump to the frame `target`: the handlers whose frames lie inside it are left.
pub(crate) fn trim(target: Frame) {
    // No handler was noted before the first window: nothing to take off.
    if !TRACKING.load(Ordering::Relaxed) {
        return;
    }
    let row = row();
    loop {
        let mut depth = row.depth.load(Ordering::Relaxed) as usize;
        if depth == 0 {
            return;
        }
        // Levels past the recorded ones lie deeper than the last recorded frame: when the jump
        // leaves that one it leaves them all.
        let recorded = depth.min(FRAMES);
        let word = row.frames[recorded - 1].load(Ordering::Relaxed);
        if depth > FRAMES {
            let frame = Frame {
                z: (word & 1) as u8,
                sp: word & !1,
            };
            if !nested(frame, target) {
                return;
            }
            depth = FRAMES;
        }
        let frame = Frame {
            z: (word & 1) as u8,
            sp: word & !1,
        };
        if !nested(frame, target) {
            return;
        }
        row.depth.store(depth as u32 - 1, Ordering::Relaxed);
    }
}

/// A reused place has no handlers.
pub(crate) fn reset(place: u64) {
    if !TRACKING.load(Ordering::Relaxed) {
        return;
    }
    ROWS[place as usize].depth.store(0, Ordering::Relaxed);
}
