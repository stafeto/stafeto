// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel log (spec 3.2, 16.3): a ring of LOG_RECORDS records in
//! .bss (kcore::log::Ring). debug_write puts its bytes there (`text`),
//! and the kernel its lines about processes, the fault of a program and
//! init's registers (`log_line!`, `kernel`). While the kernel has the
//! console's port (console::is_kernels) a record goes to the port at once
//! and is marked shown; otherwise it waits for the port's driver, which
//! takes records with object_info LOG (`take`). The panic shows what
//! nobody showed, took or was given by a reader on another CPU
//! (`show_unshown`). What the kernel said before
//! it knew its port goes there once it does (`show_early`). On the port
//! the kernel writes a piece of a line longer than a record without its
//! header (console_line::strip): no driver is there to assemble the pieces.
//! The kernel feature `keep-pieces` leaves the headers on the port for the
//! probe images, whose runner assembles the lines (xtask::untag).
//! The ring keeps the record as it came.
//!
//! The driver does not poll for the log while the system is idle: it binds
//! the log's line (`irq_bind` of abi::LOG_LINE, `irq.rs`) and its `irq_ack`
//! arms `LOG_ARMED`. A record that lands while it is armed claims the arming
//! (`wake_if_armed`) and sets the flag of its CPU, and the way out of the
//! kernel posts the notification (`take_wake`, `thread::flush_copy_exit`,
//! `cmd::flush_posted`, `sched::sleep`): a record
//! takes no `OBJ`, no queue lock and posts nothing. The two sides keep the
//! order of a Dekker pair: the writer writes the ring, fences and reads
//! `LOG_ARMED`; `irq_ack` writes `LOG_ARMED`, fences and reads the rings
//! (`recheck`). Records of the `trace` feature go past `record` and wake
//! nobody.

use crate::arch::cpu::MAX_CPUS;
use crate::arch::timer;
use crate::console;
use crate::local::local;
use crate::thread::{self, Thread};
use abi::{LOG_KERNEL_KIND, LOG_RECORD, LOG_TEXT_KIND, LogBatch};
use core::fmt::{self, Write};
use core::ptr::NonNull;
use core::sync::atomic::Ordering::{Relaxed, SeqCst};
use core::sync::atomic::{AtomicBool, fence};
pub use kcore::log::Ring;
use kcore::log::{Chunks, Source, merge_unseen};

/// The records of the ring: 64 of 80 bytes, 5 120 bytes of .bss.
#[cfg(not(feature = "trace"))]
pub const LOG_RECORDS: usize = 64;
#[cfg(feature = "trace")]
pub const LOG_RECORDS: usize = 256;

/// The console's driver waits for a record: its binding of the log's line
/// is open (`irq::ack` armed it) and no record has claimed the arming since.
/// Written by `irq_ack` under `OBJ` and by the first record after it.
static LOG_ARMED: AtomicBool = AtomicBool::new(false);

/// A record's `bytes` on the kernel's port: a piece of a line longer than a
/// record without its header (console_line::strip). A function of its own,
/// so that the code of `record` keeps its form for `wcet bound`.
#[inline(never)]
fn port(bytes: &[u8]) {
    console::write_bytes(console_line::strip(bytes));
}

/// Writes a record of `kind` with `bytes`, 1 to abi::LOG_TEXT of them, at
/// the counter's time now: to the port as well, and shown, while the
/// kernel has the port (spec 3.2). O(1) but for the port, which it waits
/// for.
fn record(kind: u8, bytes: &[u8]) {
    let time = timer::now();
    let shown = console::is_kernels();
    if shown {
        port(bytes);
    }
    local().ring.lock().push(time, kind, bytes, shown);
    wake_if_armed();
}

/// After a record: when the driver waits, this CPU makes the post at its
/// next way out of the kernel (`take_wake`). The barrier orders the write
/// of the ring (the release store of its `seq`) before the read of
/// `LOG_ARMED`, as `irq_ack` orders its write of `LOG_ARMED` before its
/// read of the rings (`recheck`): one side sees the other. The load alone
/// costs a barrier and a read while nobody waits; the claim is one swap a
/// time the driver arms. No lock, no call into another module: it is safe
/// in an interrupt and inside a section of `OBJ`.
#[inline(always)]
fn wake_if_armed() {
    fence(SeqCst);
    if LOG_ARMED.load(Relaxed) {
        claim_arming();
    }
}

/// Takes the arming, once: the claimant sets the flag of its CPU.
#[inline(never)]
fn claim_arming() {
    if LOG_ARMED.swap(false, SeqCst) {
        local().deferred.fetch_or(crate::local::LOG_WAKE, Relaxed);
    }
}

/// Arms the wake (`irq_ack` of the log's binding, under `OBJ`, on the
/// transition from masked to open): a record that lands from now on posts.
pub fn arm() {
    LOG_ARMED.store(true, SeqCst);
}

/// Disarms the wake (the last handle of the binding, under `OBJ`).
pub fn disarm() {
    LOG_ARMED.store(false, SeqCst);
}

/// After `arm`, outside the section: when any ring holds a record the
/// driver has not passed, the arming is claimed at once, so that the post
/// goes out with the call's way out of the kernel and one record or a
/// thousand give one notification. A ring that is hard to read counts as
/// holding one (`Ring::has_unseen_shared`). O(CPUs): one look at each ring,
/// no retry.
pub fn recheck() {
    fence(SeqCst);
    // The feature `break-log-wake` is the negative build: no look at the
    // rings, so a record that landed before the arming is never posted.
    let any = !cfg!(feature = "break-log-wake")
        && (0..crate::smp::cpus()).any(|c| {
            let ring = crate::arch::cpu::block(c).local.ring.as_ptr();
            // SAFETY: the rings of the CPUs that are up live for good, and
            // only their owners write them.
            unsafe { Ring::has_unseen_shared(ring) }
        });
    if any {
        claim_arming();
    }
}

/// Whether the log's wake is armed (the kernel tests).
#[cfg(feature = "ktest")]
pub fn is_armed() -> bool {
    LOG_ARMED.load(SeqCst)
}

/// Passes every record of every ring, as the driver's reads do (the kernel
/// tests): no ring holds a record nobody has seen afterwards.
#[cfg(feature = "ktest")]
pub fn pass_all() {
    let me = crate::arch::cpu::this().index();
    for c in 0..crate::smp::cpus() {
        if c == me {
            while local().ring.lock().take(|_, _| {}).left != 0 {}
            continue;
        }
        let ring = crate::arch::cpu::block(c).local.ring.as_ptr();
        let mut first = 0;
        loop {
            // SAFETY: the rings of the CPUs that are up live for good, and
            // the test runs while the other CPUs write nothing.
            let (batch, next) = unsafe { Ring::peek_shared(ring, first, true, |_, _| {}) };
            first = next;
            if batch.left == 0 {
                break;
            }
        }
    }
}

/// Whether a post waits on this CPU, which the way out of the kernel makes
/// (`take_wake`).
#[inline(always)]
pub fn wake_due() -> bool {
    local().deferred.load(Relaxed) & crate::local::LOG_WAKE != 0
}

/// Clears the flag of this CPU; true when it stood, and the caller posts
/// (`irq::deliver_log`).
#[inline(always)]
pub fn take_wake() -> bool {
    local().deferred.fetch_and(!crate::local::LOG_WAKE, Relaxed) & crate::local::LOG_WAKE != 0
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

/// Read of the ring of this CPU from `first`, also returning the next
/// sequence; no cursor of the ring moves.
pub fn peek(t: NonNull<Thread>, first: u64) -> (LogBatch, u64) {
    local().ring.lock().peek(first, |i, r| {
        thread::write_words(t, i * LOG_RECORD, &r.words())
    })
}

/// Read of the ring of another CPU, the `k`th other than this one in the
/// order of their numbers (1 for the first), from `first`; the owner's
/// cursor stays, and with `advance` (the console's read) the ring's `seen`
/// cursor moves past what this gave (`Ring::peek_shared`). None for a `k` past
/// the CPUs that are up.
pub fn peek_other(
    t: NonNull<Thread>,
    k: usize,
    first: u64,
    advance: bool,
) -> Option<(LogBatch, u64)> {
    let me = crate::arch::cpu::this().index();
    let cpu = (0..crate::smp::cpus()).filter(|&c| c != me).nth(k - 1)?;
    let ring = crate::arch::cpu::block(cpu).local.ring.as_ptr();
    // SAFETY: the rings of the CPUs that are up live for good, and only
    // their owners write them.
    Some(unsafe {
        Ring::peek_shared(ring, first, advance, |i, r| {
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
    local().ring.lock().show(|r| port(r.text()));
}

/// The panic shows what nobody showed, took or was given by a reader on
/// another CPU (`Ring::peek_shared` moves the ring's `seen` cursor), oldest
/// first across the rings of all the CPUs that are up, on the port it took
/// back, once (spec 16.1). The ring of this CPU it reads without the lock:
/// one CPU, and a writer it interrupted, which never runs again, leaves at
/// most one record half written, whose text is at most abi::LOG_TEXT bytes.
/// The other CPUs are not stopped: their rings are read the way the driver
/// reads them, between two looks at the owner's seqlock, so a record is
/// whole or left out, and a CPU stuck in the middle of a write gives
/// nothing after a bounded wait. A record a driver on another CPU takes
/// while the panic prints may come out twice. O(CPUs x 64), no bound
/// needed: the panic path has none.
pub fn show_unshown() {
    static SHOWN: AtomicBool = AtomicBool::new(false);
    if SHOWN.swap(true, Relaxed) {
        return;
    }
    let me = crate::arch::cpu::this().index();
    let cpus = crate::smp::cpus();
    let sources: [Source<'_, LOG_RECORDS>; MAX_CPUS] = core::array::from_fn(|c| {
        if c >= cpus {
            return Source::none();
        }
        let ring = crate::arch::cpu::block(c).local.ring.as_ptr();
        if c == me {
            // SAFETY: the panic runs alone on this CPU and never returns
            // to a holder of the lock; see above.
            Source::own(unsafe { &*ring })
        } else {
            // SAFETY: the rings of the CPUs that are up live for good, and
            // only their owners write them.
            unsafe { Source::shared(ring) }
        }
    });
    let mut spans = [(0, 0); MAX_CPUS];
    merge_unseen(&sources, &mut spans, |r| port(r.text()));
}

/// A line of the kernel into its log, with the arguments of `format_args!`.
macro_rules! log_line {
    ($($arg:tt)*) => {
        $crate::log::line(format_args!($($arg)*))
    };
}
