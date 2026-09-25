// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Starting init (spec 13.3, report 5.2) from the program in the boot
//! image: its process, each segment on fresh frames with the protection
//! its place in the program gives it, the stack right under
//! abi::INIT_STACK_TOP with an unmapped guard page below, the first
//! thread with its message buffer at abi::INIT_MSGBUF, init's first
//! handles, and the thread started at the entry, FIFO at 63 with x0 = 0.
//! bootimg::Program::parse checked that the segments, the stack and the
//! buffer do not overlap. A step that fails stops the boot with a panic
//! that names it.

use crate::arch::cache;
use crate::process::{self, Process};
use crate::thread::{self, Policy};
use bootimg::{Part, Program};
use core::fmt;
use core::ptr::NonNull;
use kcore::frames::{MAX_ORDER, PAGE_SIZE};
use kcore::layout::LINEAR_BASE;
use kcore::paging::Attrs;

/// Init's priority and priority ceiling (spec 13.3): the highest.
const PRIORITY: u8 = 63;

/// Makes init from `program` and leaves the kernel for it. Init's end
/// ends the run (process::set_init).
pub fn start(program: &Program<'_>) -> ! {
    let p = process::create(kcore::handles::MAX_HANDLES, PRIORITY)
        .unwrap_or_else(|e| panic!("init: no process: {e:?}"));
    process::set_init(p);
    for part in Part::ALL {
        let segment = &program.segments[part as usize];
        if segment.mem_size == 0 {
            continue;
        }
        let pages = segment.pages();
        let size = pages.end - pages.start;
        let pa = map(
            p,
            pages.start,
            size,
            attrs(part),
            format_args!("{part} segment"),
        );
        let at = LINEAR_BASE + pa as usize;
        // SAFETY: map_frames just gave the process these frames, zeroed and
        // at least `size` bytes, which hold the segment's bytes (Program::parse);
        // the linear map reaches them, and no program runs yet.
        unsafe {
            core::ptr::copy_nonoverlapping(
                segment.bytes.as_ptr(),
                at as *mut u8,
                segment.bytes.len(),
            )
        };
        if part == Part::Code {
            cache::sync_icache(at, size as usize);
        }
    }
    let stack = u64::from(program.stack_size);
    map(
        p,
        abi::INIT_STACK_TOP - stack,
        stack,
        Attrs::USER_DATA,
        format_args!("stack"),
    );
    let t = thread::create(
        p,
        program.entry as usize,
        abi::INIT_STACK_TOP as usize,
        0,
        PRIORITY,
        Policy::Fifo,
    )
    .unwrap_or_else(|e| panic!("init: no thread: {e:?}"));
    thread::give_buffer(t, abi::INIT_MSGBUF as usize)
        .unwrap_or_else(|e| panic!("init: no message buffer: {e:?}"));
    process::install_init_handles(p, t).unwrap_or_else(|e| panic!("init: no handles: {e:?}"));
    thread::start(t).unwrap_or_else(|e| panic!("init: its thread did not start: {e:?}"));
    // SAFETY: the references `create` handed out go; init's handles, its
    // thread and the scheduler hold init from now on.
    unsafe {
        thread::release(t);
        process::release(p);
    }
    crate::sched::resume()
}

/// The protection a segment's place in the program gives it (W^X).
fn attrs(part: Part) -> Attrs {
    match part {
        Part::Code => Attrs::USER_TEXT,
        Part::Rodata => Attrs::USER_RODATA,
        Part::Data => Attrs::USER_DATA,
    }
}

/// Maps `size` bytes of fresh zeroed frames for init's `what` at `va` with
/// `attrs` and returns their physical address. One block of frames holds
/// them (Process::map_frames), and a block holds at most 4 MiB: a bigger
/// part of init, which the boot image's format allows, stops the boot.
fn map(p: NonNull<Process>, va: u64, size: u64, attrs: Attrs, what: fmt::Arguments<'_>) -> u64 {
    // SAFETY: init's process is alive, and nothing else borrows it while
    // the kernel builds it.
    let process = unsafe { &mut *p.as_ptr() };
    process
        .map_frames(va as usize, size, attrs)
        .unwrap_or_else(|e| {
            panic!(
                "init: no frames for its {what} of {size:#x} bytes at {va:#x} ({e:?}; a block of frames holds at most {} MiB)",
                (PAGE_SIZE << MAX_ORDER) >> 20
            )
        })
}
