// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Starting init (spec 3.3, 13.3) from the program in the boot image: its
//! process, with every frame free after its shell as its quota (spec
//! 7.5); each segment in a memory object of its own that init pays for,
//! with the bytes of the file copied in, mapped as mem_map maps it with
//! the access its place in the program gives it (W^X); the stack the same
//! way right under abi::INIT_STACK_TOP, with an unmapped guard page below;
//! the first thread with its message buffer at abi::INIT_MSGBUF; init's
//! first handles, the boot image among them as a memory object; and the
//! thread started at the entry, FIFO at 63 with x0 = 0. Init has four
//! mappings, or fewer when its program has no read-only data or data.
//! bootimg::Program::parse checked that the segments, the stack and the
//! buffer do not overlap. A step that fails stops the boot with a panic
//! that names it.

use crate::memory;
use crate::process::{self, Process};
use abi::Access;
use bootimg::{Part, Program};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;

/// Init's priority and priority ceiling (spec 13.3): the highest.
const PRIORITY: u8 = 63;

// The boot image aligns files and segments to its own page (spec 13.1),
// and the kernel maps them in its pages: the two must be one size.
const _: () = assert!(bootimg::PAGE_SIZE == PAGE_SIZE);

/// Makes init from `program` and the boot image `image`, whole pages
/// (boot::init_program), and leaves the kernel for it. Init's end ends
/// the run (process::set_init). Its shell takes the page the kernel keeps
/// outside every quota; its quota is every frame free after that
/// (process::create_init), and everything else of it is charged to it as
/// to any process, its memory objects too; it has no parent to give the
/// quota back to.
#[cfg(not(feature = "ktest"))]
pub fn start(program: &Program<'_>, image: kcore::bootinfo::Region) -> ! {
    use crate::thread;
    use abi::Policy;
    let p = process::create_init(kcore::handles::MAX_HANDLES, PRIORITY)
        .unwrap_or_else(|e| panic!("init: no process: {e:?}"));
    process::set_init(p);
    match load(p, program) {
        Ok(()) => {}
        Err(Failure {
            what,
            size,
            error,
            made: false,
        }) => {
            panic!("init: no memory object for its {what} of {size:#x} bytes ({error:?})")
        }
        Err(Failure {
            what, size, error, ..
        }) => {
            panic!("init: its {what} of {size:#x} bytes did not map ({error:?})")
        }
    }
    let pages = (image.size / PAGE_SIZE) as usize;
    let boot = memory::create_boot(p, image.base, pages)
        .unwrap_or_else(|e| panic!("init: no memory object for the boot image: {e:?}"));
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
    process::install_init_handles(p, t, boot).unwrap_or_else(|e| panic!("init: no handles: {e:?}"));
    thread::start(t).unwrap_or_else(|e| panic!("init: its thread did not start: {e:?}"));
    // SAFETY: the references `create`, `create_boot` and `create_init` handed
    // out go; init's handles, its thread and the scheduler hold init from
    // now on, and its handle holds the boot image, so none is the last and
    // nothing is queued for cleanup.
    unsafe {
        memory::release(boot, PRIORITY);
        thread::release(t, PRIORITY);
        process::release(p, PRIORITY);
    }
    crate::sched::resume()
}

/// What of a program did not load (`load`): its part, its size in bytes,
/// why, and whether its memory object was made, so that its mapping
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub what: &'static str,
    pub size: u64,
    pub error: abi::Error,
    pub made: bool,
}

/// Loads `program` into `p`, a new process with nothing mapped where the
/// program goes (spec 13.3): each segment into a new memory object that
/// `p` pays for (memory::create_whole), the bytes of the file copied into
/// its frames through the linear map and the rest of it zero, mapped at
/// its address with its access (process::map_whole: code RX, read-only
/// data R, data RW); then a stack object of the program's stack size,
/// mapped RW right under abi::INIT_STACK_TOP, the page below it left
/// unmapped as its guard. The mappings hold the objects. With interrupts
/// masked: the work grows with the program. A part that fails stops the
/// load, and what loaded before stays mapped.
pub fn load(p: NonNull<Process>, program: &Program<'_>) -> Result<(), Failure> {
    for part in Part::ALL {
        let segment = &program.segments[part as usize];
        if segment.mem_size == 0 {
            continue;
        }
        let pages = segment.pages();
        let what = match part {
            Part::Code => "code segment",
            Part::Rodata => "rodata segment",
            Part::Data => "data segment",
        };
        let size = pages.end - pages.start;
        load_part(p, pages.start, size, segment.bytes, access(part)).map_err(|(made, error)| {
            Failure {
                what,
                size,
                error,
                made,
            }
        })?;
    }
    let size = u64::from(program.stack_size);
    let at = abi::INIT_STACK_TOP - size;
    load_part(p, at, size, &[], Access::ReadWrite).map_err(|(made, error)| Failure {
        what: "stack",
        size,
        error,
        made,
    })
}

/// The access a segment's place in the program gives it (W^X).
fn access(part: Part) -> Access {
    match part {
        Part::Code => Access::ReadExec,
        Part::Rodata => Access::Read,
        Part::Data => Access::ReadWrite,
    }
}

/// A memory object of `size` bytes, whole pages, that `p` pays for, with
/// `bytes` at its start, mapped whole at `va` of `p` with `access`. The
/// error comes with whether the object was made.
fn load_part(
    p: NonNull<Process>,
    va: u64,
    size: u64,
    bytes: &[u8],
    access: Access,
) -> Result<(), (bool, abi::Error)> {
    let m = memory::create_whole(p, (size / PAGE_SIZE) as usize).map_err(|e| (false, e))?;
    let page = PAGE_SIZE as usize;
    for (i, chunk) in bytes.chunks(page).enumerate() {
        let at = LINEAR_BASE + memory::frame(m, i) as usize;
        // SAFETY: the frame is the object's, zeroed and a page long, and
        // the linear map reaches it; no program runs yet, and nothing else
        // refers to the object.
        unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), at as *mut u8, chunk.len()) };
    }
    let mapped = process::map_whole(p, m, va as usize, access);
    // SAFETY: the reference `create_whole` handed out goes; the mapping,
    // if it went in, holds the object, and without it the object goes.
    unsafe { memory::release(m, PRIORITY) };
    mapped.map_err(|e| (true, e))
}
