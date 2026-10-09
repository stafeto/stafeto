// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! object_info and debug_write (spec 11, 16).

use super::{Args, Values, call_maxima, lookup};
use crate::memory;
use crate::mm::{pages, phys};
use crate::object::Object;
use crate::process;
use crate::thread::{self, Thread};
use crate::{channel, cleanup, irq, sched, session, timer};
use abi::{Error, KernelStats, ProcessHandles, ProcessMemory, Rights};
use core::ptr::NonNull;
use kcore::args::{inline_len_arg, reserved_arg};

/// The rights SELF_THREAD may grant: those the creator of a thread gets
/// from thread_create, so a thread gets nothing on itself that its creator
/// did not have.
const SELF_RIGHTS: Rights = abi::OWNER_RIGHTS;

/// object_info(x0 handle, x1 kind, x2 reserved and 0): each kind has a
/// function of its own, which checks x2 first (INVALID_ARGS) and then the
/// handle; an unknown kind is INVALID_ARGS. For a process handle with any
/// rights: PROCESS_STATE returns abi::ProcessState::to_words in x1-x4,
/// PROCESS_MEMORY the quota (abi::ProcessMemory) and PROCESS_HANDLES the
/// table (abi::ProcessHandles) in x1-x3. KERNEL_STATS takes the system
/// resource with KSTATS and returns abi::KernelStats in x1-x8 (spec 16).
/// MEMORY takes a memory object's handle, a device window's too, with any
/// rights and returns abi::MemoryInfo in x1-x3; THREAD_STATE a thread's and
/// returns abi::ThreadInfo in x1-x4; CHANNEL a channel's, a labelled copy
/// too, and returns abi::ChannelInfo in x1-x4; IRQ an interrupt binding's
/// and returns abi::IrqInfo in x1-x3. LABEL takes a labelled copy of a
/// channel and in x2 a handle of that channel with RECEIVE, and returns the
/// copy's label in x1, O(1): ACCESS_DENIED for a copy of another channel,
/// WRONG_TYPE for a channel handle without a label (the lookup of x2 comes
/// first). SELF_THREAD requires x0 zero and x2 a subset of MANAGE | DUPLICATE |
/// TRANSFER, the rights the creator of a thread gets from thread_create,
/// returning a new owned handle of those rights to the actual caller. Its
/// handle-table insertion is paid by that process; failure retains no new
/// reference. THREAD_CURRENT requires x2
/// zero and compares the supplied Thread object with the caller, returning
/// only bool 0/1. Both preserve registers outside their one-word result.
/// LOG takes the system resource with
/// KSTATS, takes up to abi::LOG_BATCH records of the kernel log into the
/// start of the caller's message buffer and returns abi::LogBatch in
/// x1-x3 (spec 16.3, crate::log::take).
pub(super) fn object_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    match a[1] {
        abi::INFO_PROCESS_STATE => process_state(thread, a),
        abi::INFO_PROCESS_MEMORY => process_memory(thread, a),
        abi::INFO_PROCESS_HANDLES => process_handles(thread, a),
        abi::INFO_KERNEL_STATS => kernel_stats_info(thread, a),
        abi::INFO_MEMORY => memory_info(thread, a),
        abi::INFO_THREAD_SELF => thread_self(thread, a),
        abi::INFO_THREAD_CURRENT => thread_current(thread, a),
        abi::INFO_THREAD_STATE => thread_state(thread, a),
        abi::INFO_CHANNEL => channel_info(thread, a),
        abi::INFO_IRQ => irq_info(thread, a),
        abi::INFO_LABEL => label_info(thread, a),
        abi::INFO_LOG => log_info(thread, a),
        _ => Err(Error::InvalidArgs),
    }
}

/// PROCESS_STATE: x2 reserved; the process's state words.
fn process_state(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let p = lookup(thread, a[0], Rights::NONE, Object::process)?;
    // SAFETY: the handle holds the process.
    let state = unsafe { p.as_ref() }.state();
    Ok(Values::new(&state.to_words()))
}

/// PROCESS_MEMORY: x2 reserved; the quota of the process.
fn process_memory(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let q = process::quota(lookup(thread, a[0], Rights::NONE, Object::process)?);
    let memory = ProcessMemory {
        quota: q.limit(),
        used: q.used(),
        returned: q.returned(),
    };
    Ok(Values::new(&memory.to_words()))
}

/// PROCESS_HANDLES: x2 reserved; the handle table of the process.
fn process_handles(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let (live, retired, limit) =
        process::handle_counts(lookup(thread, a[0], Rights::NONE, Object::process)?);
    let handles = ProcessHandles {
        live: live.into(),
        retired: retired.into(),
        limit: limit.into(),
    };
    Ok(Values::new(&handles.to_words()))
}

/// KERNEL_STATS: x2 is 0, or 1 for the call maxima in the buffer.
fn kernel_stats_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if a[2] > 1 {
        return Err(Error::InvalidArgs);
    }
    lookup(thread, a[0], Rights::KSTATS, Object::resource)?;
    if a[2] == 1 {
        if thread::buffer_page(thread).is_none() {
            return Err(Error::InvalidArgs);
        }
        thread::write_words(thread, 0, &call_maxima());
    }
    Ok(Values::new(&kernel_stats().to_words()))
}

/// MEMORY: x2 reserved; a memory object's or device window's counts.
fn memory_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let m = lookup(thread, a[0], Rights::NONE, Object::memory)?;
    Ok(Values::new(&memory::info(m).to_words()))
}

/// SELF_THREAD: the one kind that acts. It inserts a new owned handle of the
/// caller's own thread into the caller's table, with the rights in x2.
fn thread_self(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[0])?;
    if a[2] & !u64::from(SELF_RIGHTS.0) != 0 {
        return Err(Error::InvalidArgs);
    }
    let process = super::caller(thread);
    process::check_alive(process)?;
    process::handle_room(process)?;
    let handle = process::insert_handle(
        process,
        Object::Thread(thread),
        // Checked above: a subset of SELF_RIGHTS, so within u32.
        Rights(a[2] as u32),
    )?;
    Ok(Values::new(&[handle.0]))
}

/// THREAD_CURRENT: x2 reserved; whether the thread of the handle is the caller.
fn thread_current(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let supplied = lookup(thread, a[0], Rights::NONE, Object::thread)?;
    Ok(Values::new(&[u64::from(supplied == thread)]))
}

/// THREAD_STATE: x2 reserved; a thread's state words.
fn thread_state(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let t = lookup(thread, a[0], Rights::NONE, Object::thread)?;
    Ok(Values::new(&thread::info(t).to_words()))
}

/// CHANNEL: x2 reserved; a channel's counts.
fn channel_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let c = lookup(thread, a[0], Rights::NONE, Object::channel)?;
    Ok(Values::new(&channel::info(c).to_words()))
}

/// IRQ: x2 reserved; an interrupt binding's counts.
fn irq_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
    let b = lookup(thread, a[0], Rights::NONE, Object::irq)?;
    Ok(Values::new(&irq::info(b).to_words()))
}

/// LABEL: x2 is a handle of the channel of the labelled copy in x0, with
/// RECEIVE (looked up first).
fn label_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let own = lookup(thread, a[2], Rights::RECEIVE, Object::channel)?;
    let s = lookup(thread, a[0], Rights::NONE, Object::session)?;
    if session::channel(s) != own {
        return Err(Error::AccessDenied);
    }
    Ok(Values::new(&[session::label(s)]))
}

/// LOG: x2 is 0 to take the records, or a cursor plus 1 to peek at them.
fn log_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    lookup(thread, a[0], Rights::KSTATS, Object::resource)?;
    if a[2] == 0 {
        Ok(Values::new(&crate::log::take(thread).to_words()))
    } else {
        let (batch, next) = crate::log::peek(thread, a[2] - 1);
        let [count, lost, left] = batch.to_words();
        Ok(Values::new(&[count, lost, left, next + 1]))
    }
}

/// What the kernel counts about itself, for KERNEL_STATS: the scheduler's
/// idle time and latencies, the cleanup queue, the frames, the pages of
/// the pools and of the page logs of their payers, and the longest portion
/// of firings of timers.
fn kernel_stats() -> KernelStats {
    let s = sched::stats();
    KernelStats {
        idle: s.idle,
        idle_latency: s.idle_latency,
        irq_latency: s.irq_latency,
        cleanup_queue: cleanup::len(),
        longest_portion: cleanup::longest(),
        free_frames: phys::free_frames(),
        pool_pages: pages::taken() as u64,
        longest_firing: timer::longest_firing(),
        entry_to_poll: sched::longest_entry_to_poll(),
    }
}

/// debug_write(x0 system resource with DEBUG, x1 length up to 64, x2-x9
/// the bytes as abi::inline_words packs them): puts the bytes into the
/// kernel log as one record, and while the kernel has the console's port
/// writes them there at once, interrupts masked (spec 3.2, 16.3); returns
/// their count in x1.
pub(super) fn debug_write(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let len = inline_len_arg(a[1])?;
    lookup(thread, a[0], Rights::DEBUG, Object::resource)?;
    let words: &[u64; 8] = a[2..].try_into().expect("x2-x9");
    crate::log::text(&abi::inline_bytes(words)[..len]);
    Ok(Values::new(&[a[1]]))
}
