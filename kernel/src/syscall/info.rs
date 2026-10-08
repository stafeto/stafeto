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

/// object_info(x0 handle, x1 kind, x2 reserved and 0): the kind and x2
/// first (INVALID_ARGS), then the handle. For a process handle with any
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
/// first). SELF_THREAD requires x0/x2 zero and returns a new owned NONE
/// handle to the actual caller. Its handle-table insertion is paid by that
/// process; failure retains no new reference. THREAD_CURRENT requires x2
/// zero and compares the supplied Thread object with the caller, returning
/// only bool 0/1. Both preserve registers outside their one-word result.
/// LOG takes the system resource with
/// KSTATS, takes up to abi::LOG_BATCH records of the kernel log into the
/// start of the caller's message buffer and returns abi::LogBatch in
/// x1-x3 (spec 16.3, crate::log::take).
pub(super) fn object_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if a[1] == abi::INFO_KERNEL_STATS {
        if a[2] > 1 {
            return Err(Error::InvalidArgs);
        }
    } else if a[1] != abi::INFO_LOG && a[1] != abi::INFO_LABEL {
        reserved_arg(a[2])?;
    }
    if a[1] == abi::INFO_THREAD_SELF {
        reserved_arg(a[0])?;
    }
    let target = || lookup(thread, a[0], Rights::NONE, Object::process);
    match a[1] {
        abi::INFO_PROCESS_STATE => {
            let p = target()?;
            // SAFETY: the handle holds the process.
            let state = unsafe { p.as_ref() }.state();
            Ok(Values::new(&state.to_words()))
        }
        abi::INFO_PROCESS_MEMORY => {
            let q = process::quota(target()?);
            let memory = ProcessMemory {
                quota: q.limit(),
                used: q.used(),
                returned: q.returned(),
            };
            Ok(Values::new(&memory.to_words()))
        }
        abi::INFO_PROCESS_HANDLES => {
            let (live, retired, limit) = process::handle_counts(target()?);
            let handles = ProcessHandles {
                live: live.into(),
                retired: retired.into(),
                limit: limit.into(),
            };
            Ok(Values::new(&handles.to_words()))
        }
        abi::INFO_KERNEL_STATS => {
            lookup(thread, a[0], Rights::KSTATS, Object::resource)?;
            match a[2] {
                0 => {}
                1 => {
                    if thread::buffer_page(thread).is_none() {
                        return Err(Error::InvalidArgs);
                    }
                    thread::write_words(thread, 0, &call_maxima());
                }
                _ => return Err(Error::InvalidArgs),
            }
            Ok(Values::new(&kernel_stats().to_words()))
        }
        abi::INFO_MEMORY => {
            let m = lookup(thread, a[0], Rights::NONE, Object::memory)?;
            Ok(Values::new(&memory::info(m).to_words()))
        }
        abi::INFO_THREAD_SELF => {
            let process = super::caller(thread);
            process::check_alive(process)?;
            process::handle_room(process)?;
            let handle = process::insert_handle(process, Object::Thread(thread), Rights::NONE)?;
            Ok(Values::new(&[handle.0]))
        }
        abi::INFO_THREAD_CURRENT => {
            let supplied = lookup(thread, a[0], Rights::NONE, Object::thread)?;
            Ok(Values::new(&[u64::from(supplied == thread)]))
        }
        abi::INFO_THREAD_STATE => {
            let t = lookup(thread, a[0], Rights::NONE, Object::thread)?;
            Ok(Values::new(&thread::info(t).to_words()))
        }
        abi::INFO_CHANNEL => {
            let c = lookup(thread, a[0], Rights::NONE, Object::channel)?;
            Ok(Values::new(&channel::info(c).to_words()))
        }
        abi::INFO_IRQ => {
            let b = lookup(thread, a[0], Rights::NONE, Object::irq)?;
            Ok(Values::new(&irq::info(b).to_words()))
        }
        abi::INFO_LABEL => {
            let own = lookup(thread, a[2], Rights::RECEIVE, Object::channel)?;
            let s = lookup(thread, a[0], Rights::NONE, Object::session)?;
            if session::channel(s) != own {
                return Err(Error::AccessDenied);
            }
            Ok(Values::new(&[session::label(s)]))
        }
        abi::INFO_LOG => {
            lookup(thread, a[0], Rights::KSTATS, Object::resource)?;
            if a[2] == 0 {
                Ok(Values::new(&crate::log::take(thread).to_words()))
            } else {
                let (batch, next) = crate::log::peek(thread, a[2] - 1);
                let [count, lost, left] = batch.to_words();
                Ok(Values::new(&[count, lost, left, next + 1]))
            }
        }
        _ => Err(Error::InvalidArgs),
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
