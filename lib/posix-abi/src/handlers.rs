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
//! The record of a thread holds `FRAMES` frames; a thread nested deeper is counted but not
//! trimmed exactly, so it stays "inside a handler" until it returns from them, which sends its
//! large calls on `/data` by messages, never into a wrong state.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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

/// The calling thread calls a handler from the frame `frame`.
pub(crate) fn enter(frame: Frame) {
    let row = row();
    let at = row.depth.fetch_add(1, Ordering::Relaxed) as usize;
    if let Some(slot) = row.frames.get(at) {
        slot.store(frame.sp | u64::from(frame.z), Ordering::Relaxed);
    }
}

/// The handler returned.
pub(crate) fn leave() {
    let _ = row()
        .depth
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
}

/// Whether the calling thread is inside a handler.
pub(crate) fn active() -> bool {
    row().depth.load(Ordering::Relaxed) != 0
}

/// A long jump to the frame `target`: the handlers whose frames lie inside it are left.
pub(crate) fn trim(target: Frame) {
    let row = row();
    loop {
        let depth = row.depth.load(Ordering::Relaxed) as usize;
        if depth == 0 || depth > FRAMES {
            return;
        }
        let word = row.frames[depth - 1].load(Ordering::Relaxed);
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
    ROWS[place as usize].depth.store(0, Ordering::Relaxed);
}
