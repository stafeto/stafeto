// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel log (spec 3.2, 16.3): a ring of LOG_RECORDS records in
//! .bss (kcore::log::Ring). debug_write puts its bytes there (`text`),
//! and the kernel its lines about processes, the fault of a program and
//! init's registers (`log_line!`, `kernel`). While the kernel has the
//! console's port (console::is_kernels) a record goes to the port at once
//! and is marked shown; otherwise it waits for the port's driver, which
//! takes records with object_info LOG (`take`). The panic shows what
//! nobody showed or took (`show_unshown`).

use crate::arch::timer;
use crate::console;
use crate::thread::{self, Thread};
use abi::{LOG_KERNEL_KIND, LOG_RECORD, LOG_TEXT_KIND, LogBatch};
use core::fmt::{self, Write};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};
use kcore::log::{Chunks, Ring};
use kcore::sync::Lock;

/// The records of the ring: 64 of 80 bytes, 5 120 bytes of .bss.
const LOG_RECORDS: usize = 64;

static RING: Lock<Ring<LOG_RECORDS>> = Lock::new(Ring::new());

/// Writes a record of `kind` with `bytes`, 1 to abi::LOG_TEXT of them, at
/// the counter's time now: to the port as well, and shown, while the
/// kernel has the port (spec 3.2). O(1) but for the port, which it waits
/// for.
fn record(kind: u8, bytes: &[u8]) {
    let time = timer::now();
    let shown = console::is_kernels();
    if shown {
        console::write_bytes(bytes);
    }
    RING.lock().push(time, kind, bytes, shown);
}

/// The bytes of a debug_write, up to abi::LOG_TEXT, as one record of
/// abi::LOG_TEXT_KIND; none for no bytes (spec 11, 16.3).
pub fn text(bytes: &[u8]) {
    if !bytes.is_empty() {
        record(LOG_TEXT_KIND, bytes);
    }
}

/// Text of the kernel that `write` produces, as records of
/// abi::LOG_KERNEL_KIND in a row, abi::LOG_TEXT bytes each but the last
/// (spec 7.9, 16.3).
pub fn kernel(write: impl FnOnce(&mut dyn Write)) {
    let mut chunks = Chunks::new(|piece: &[u8]| record(LOG_KERNEL_KIND, piece));
    write(&mut chunks);
    chunks.finish();
}

/// One line of the kernel, `args` and a newline, as `kernel` writes it.
pub fn line(args: fmt::Arguments<'_>) {
    kernel(|w| {
        let _ = w.write_fmt(args);
        let _ = w.write_str("\n");
    });
}

/// object_info LOG for `t`, the calling thread (spec 11, 16.3): up to
/// abi::LOG_BATCH records nobody showed or took go into the start of its
/// message buffer, abi::LOG_RECORD bytes each, and the cursor moves past
/// them. A thread that makes calls has its buffer. O(64): the ring and a
/// copy of up to 960 bytes.
pub fn take(t: NonNull<Thread>) -> LogBatch {
    RING.lock()
        .take(|i, r| thread::write_words(t, i * LOG_RECORD, &r.words()))
}

/// The panic shows what nobody showed or took, oldest first, on the port
/// it took back, once (spec 16.1). It reads the ring without the lock: one
/// CPU, and a writer it interrupted, which never runs again, leaves at
/// most one record half written, whose text is at most abi::LOG_TEXT bytes.
pub fn show_unshown() {
    static SHOWN: AtomicBool = AtomicBool::new(false);
    if SHOWN.swap(true, Relaxed) {
        return;
    }
    // SAFETY: the panic runs alone and never returns to a holder of the
    // lock; see above.
    let ring = unsafe { &*RING.as_ptr() };
    for r in ring.unshown() {
        console::write_bytes(r.text());
    }
}

/// A line of the kernel into its log, with the arguments of `format_args!`.
macro_rules! log_line {
    ($($arg:tt)*) => {
        $crate::log::line(format_args!($($arg)*))
    };
}
