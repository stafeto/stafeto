// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel log (spec 3.2, 16.3): a ring of LOG_RECORDS records in
//! .bss (kcore::log::Ring). debug_write puts its bytes there (`text`),
//! and the kernel its lines about processes, the fault of a program and
//! init's registers (`log_line!`, `kernel`). While the kernel has the
//! console's port (console::is_kernels) a record goes to the port at once
//! and is marked shown; otherwise it waits for the port's driver, which
//! takes records with object_info LOG (`take`). The panic shows what
//! nobody showed or took (`show_unshown`). What the kernel said before
//! it knew its port goes there once it does (`show_early`).

use crate::arch::timer;
use crate::console;
use crate::local::local;
use crate::thread::{self, Thread};
use abi::{LOG_KERNEL_KIND, LOG_RECORD, LOG_TEXT_KIND, LogBatch};
use core::fmt::{self, Write};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};
use kcore::log::Chunks;
pub use kcore::log::Ring;

/// The records of the ring: 64 of 80 bytes, 5 120 bytes of .bss.
#[cfg(not(feature = "trace"))]
pub const LOG_RECORDS: usize = 64;
#[cfg(feature = "trace")]
pub const LOG_RECORDS: usize = 256;

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
    local().ring.lock().push(time, kind, bytes, shown);
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
    local()
        .ring
        .lock()
        .take(|i, r| thread::write_words(t, i * LOG_RECORD, &r.words()))
}

/// Non-destructive read from `first`, also returning the next sequence.
pub fn peek(t: NonNull<Thread>, first: u64) -> (LogBatch, u64) {
    local().ring.lock().peek(first, |i, r| {
        thread::write_words(t, i * LOG_RECORD, &r.words())
    })
}

/// Non-destructive read of the ring of another CPU, the `k`th other than
/// this one in the order of their numbers (1 for the first), from `first`;
/// the owner's cursor stays, and nothing in the ring changes
/// (`Ring::peek_shared`). None for a `k` past the CPUs that are up.
pub fn peek_other(t: NonNull<Thread>, k: usize, first: u64) -> Option<(LogBatch, u64)> {
    let me = crate::arch::cpu::this().index();
    let cpu = (0..crate::smp::cpus()).filter(|&c| c != me).nth(k - 1)?;
    let ring = crate::arch::cpu::block(cpu).local.ring.as_ptr();
    // SAFETY: the rings of the CPUs that are up live for good, and only
    // their owners write them.
    Some(unsafe {
        Ring::peek_shared(ring, first, |i, r| {
            let mut words = r.words();
            // Byte 10, zero in a record that `take` gives, says the kernel
            // showed this one on its console: the driver that reads the
            // ring of another CPU shows the rest, among them what that CPU
            // said before the driver started (abi::LOG_SHOWN_AT).
            words[abi::LOG_SHOWN_AT / 8] |= u64::from(r.shown) << (8 * (abi::LOG_SHOWN_AT % 8));
            thread::write_words(t, i * LOG_RECORD, &words)
        })
    })
}

#[cfg(feature = "trace")]
fn event(kind: u8, args: fmt::Arguments<'_>) {
    let mut chunks =
        Chunks::new(|piece: &[u8]| local().ring.lock().push(timer::now(), kind, piece, false));
    let _ = chunks.write_fmt(args);
    chunks.finish();
}

#[cfg(feature = "trace")]
pub fn syscall(number: u16, thread: u16) {
    event(
        abi::LOG_SYSCALL_KIND,
        format_args!("call={number} thread={thread}"),
    );
}

#[cfg(feature = "trace")]
pub fn switch(thread: u16) {
    event(abi::LOG_SWITCH_KIND, format_args!("thread={thread}"));
}

#[cfg(feature = "trace")]
pub fn interrupt(line: u32) {
    event(abi::LOG_INTERRUPT_KIND, format_args!("line={line}"));
}

/// What the kernel said before it had its port goes out on the port, in
/// its order, and counts as shown (console::set_port, spec 3.2). O(64).
pub fn show_early() {
    local().ring.lock().show(|r| console::write_bytes(r.text()));
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
    let ring = unsafe { &*local().ring.as_ptr() };
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
