// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loader of programs in the simple format of the boot image (spec
//! 13.2, 13.3; lib/bootimg), as the kernel loads init: a new process, a
//! memory object for each segment and one for the stack, which the caller
//! pays for, each mapped into the process with the access of its part
//! through a copy of its handle with the rights of that access alone, and
//! the first thread, whose x0 holds abi::START_CHANNEL. A mapping keeps
//! the rights it was made with (spec 5.2, 7.4), so the process cannot make
//! its code writable or its data executable with mem_protect;
//! `map_narrowed` maps any other object into another process the same
//! way. The bytes of a segment go into its object through a window of the
//! caller's own space. `spawn` loads a program with its start channel and
//! its exit channel, one label for both, and gets its start data ready
//! (rt::startup::Giver). The ELF loader comes in milestone 4.

use crate::handle::{Channel, Handle, Memory, Process, Thread};
use crate::startup::Giver;
use crate::sys;
use abi::{Access, Call, Error, INIT_MSGBUF, INIT_STACK_TOP, Policy, Rights, START_CHANNEL};
use bootimg::{PAGE_SIZE, Part, Program, Segment};

/// The new process and its first thread (spec 7.5, 8, 13.3).
pub struct Params<'a> {
    /// The process's quota in bytes, whole pages, its room for handles and
    /// its priority ceiling (process_create x0-x2).
    pub quota: u64,
    pub handle_limit: u32,
    pub ceiling: u8,
    /// The exit channel with the priority of the exit notification
    /// (process_create x3, x4).
    pub exit: Option<(&'a Handle<Channel>, u8)>,
    /// The start channel, which moves into the process's entry 0
    /// (process_create x5).
    pub start: Option<Handle<Channel>>,
    /// The first thread's priority and policy.
    pub priority: u8,
    pub policy: Policy,
}

/// A process that `load` made and its first thread.
pub struct Child {
    pub process: Handle<Process>,
    pub thread: Handle<Thread>,
}

/// The access a part is mapped with (spec 3.3): code RX, read-only data R,
/// data RW.
const fn access(part: Part) -> Access {
    match part {
        Part::Code => Access::ReadExec,
        Part::Rodata => Access::Read,
        Part::Data => Access::ReadWrite,
    }
}

/// Makes a process with `params` and loads `program` into it (spec 13.2):
/// each segment goes into a new memory object, its bytes copied through
/// `window` of the caller's process `own` (a handle with MANAGE), and is
/// mapped at its address with the access of its part (`access`) through a
/// copy of the object's handle with that access's rights; the stack is an
/// object of `program.stack_size` bytes right under abi::INIT_STACK_TOP,
/// mapped RW, with the page below it left unmapped. The caller pays for
/// the objects, and each mapping holds its object. The first thread
/// starts at the entry point with its stack pointer at INIT_STACK_TOP, its
/// message buffer at abi::INIT_MSGBUF and abi::START_CHANNEL in x0, and
/// does not run until thread_start.
///
/// On an error the process goes again, and the error comes back; the
/// start channel comes back with it when process_create failed, since
/// only a process that was made takes it.
///
/// # Safety
/// `window` is the first address of a range of the caller's space, as big
/// as the file bytes of the biggest segment, that only the loader maps and
/// uses while the call runs: it maps each object there, writes it and
/// unmaps it again.
pub unsafe fn load(
    own: &Handle<Process>,
    program: &Program<'_>,
    window: usize,
    params: Params<'_>,
) -> Result<Child, (Error, Option<Handle<Channel>>)> {
    let process = sys::process_create_with(
        params.quota,
        params.handle_limit,
        params.ceiling,
        params.exit,
        params.start,
    )?;
    // SAFETY: the caller's promise for `window`.
    let filled = unsafe {
        fill(
            own,
            &process,
            program,
            window,
            params.priority,
            params.policy,
        )
    };
    match filled {
        Ok(thread) => Ok(Child { process, thread }),
        Err(e) => {
            // The process has no thread that runs: its end and the close of
            // the last handle let it go.
            let _ = sys::process_kill(&process);
            let _ = process.close();
            Err((e, None))
        }
    }
}

/// A program `spawn` starts (spec 13.3, 13.4).
pub struct SpawnParams<'a> {
    /// The parent's channel, a handle with no label and DUPLICATE, where
    /// the program's requests, the CLIENT_GONE of its start channel and
    /// the notification of its end come.
    pub channel: &'a Handle<Channel>,
    /// The label that names the program there, not 0; the parent gives
    /// each program its own (init from a 64-bit count, spec 13.4). Its
    /// slot, which the exit notification and CLIENT_GONE go into, has
    /// priority `notice`.
    pub label: u64,
    pub notice: u8,
    /// The process's quota in bytes, whole pages, its room for handles and
    /// its priority ceiling; the first thread's priority and policy.
    pub quota: u64,
    pub handle_limit: u32,
    pub ceiling: u8,
    pub priority: u8,
    pub policy: Policy,
}

/// A program `spawn` loaded, whose first thread does not run yet: its
/// process and thread, the label that names it, and its start data, which
/// already hold copies of the process and the thread under the names
/// `process` and `thread`. Closing the handles of a program does not end
/// it (spec 5.2): a `Spawned` that goes leaves a program that runs, and
/// one whose thread never started to its end with process_kill.
pub struct Spawned {
    pub process: Handle<Process>,
    pub thread: Handle<Thread>,
    pub label: u64,
    pub giver: Giver,
}

impl Spawned {
    /// thread_start: the program runs and asks for its start data.
    pub fn start(&self) -> Result<(), Error> {
        sys::thread_start(&self.thread)
    }
}

/// Loads `program` as `load` does, with the start channel and the exit
/// channel of one label (spec 13.3): a copy A of `params.channel` with
/// SEND, NOTIFY, DUPLICATE, TRANSFER and `params.label`, a session whose
/// slot has priority `params.notice`, is the exit channel (x3, the
/// notification at `params.notice`); a copy B of A with SEND and TRANSFER
/// alone moves into the program's entry 0 (x5); A goes once the program
/// is loaded. The requests of the program, the CLIENT_GONE of its last
/// copy of B and the notification of its end so all carry the label. The
/// `giver` of the result holds copies of the process and of the thread
/// with MANAGE and TRANSFER. The errors are those of handle_duplicate,
/// `load` and of the copies; on an error the process goes, and A and B
/// with it.
///
/// # Safety
/// As for `load`: only the loader uses `window` while the call runs.
pub unsafe fn spawn(
    own: &Handle<Process>,
    program: &Program<'_>,
    window: usize,
    params: SpawnParams<'_>,
) -> Result<Spawned, Error> {
    let rights = Rights::SEND | Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER;
    let a = sys::handle_label(params.channel, rights, params.label, params.notice)?;
    let b = sys::handle_duplicate(&a, Rights::SEND | Rights::TRANSFER)?;
    let load_params = Params {
        quota: params.quota,
        handle_limit: params.handle_limit,
        ceiling: params.ceiling,
        exit: Some((&a, params.notice)),
        start: Some(b),
        priority: params.priority,
        policy: params.policy,
    };
    // SAFETY: the caller's promise for `window`.
    let child = unsafe { load(own, program, window, load_params) }.map_err(|(e, _)| e)?;
    drop(a);
    match start_data(&child) {
        Ok(giver) => Ok(Spawned {
            process: child.process,
            thread: child.thread,
            label: params.label,
            giver,
        }),
        Err(e) => {
            // The process has no thread that runs: its end and the close of
            // the last handle let it go.
            let _ = sys::process_kill(&child.process);
            Err(e)
        }
    }
}

/// Start data with copies of the process and the thread of `child` with
/// MANAGE and TRANSFER, under the names `process` and `thread`.
fn start_data(child: &Child) -> Result<Giver, Error> {
    let rights = Rights::MANAGE | Rights::TRANSFER;
    let process = sys::handle_duplicate(&child.process, rights)?;
    let thread = sys::handle_duplicate(&child.thread, rights)?;
    let mut giver = Giver::new();
    // Two names of an empty giver fit.
    let _ = giver.give("process", process.erase());
    let _ = giver.give("thread", thread.erase());
    Ok(giver)
}

/// Maps `len` bytes of `m` from `offset` at `addr` of `process` with
/// `access` through a copy of the handle with `access.rights()` alone,
/// which goes again: the mapping keeps no right past its access (spec 5.2,
/// 7.4). `m` needs DUPLICATE and the rights of `access`; the errors are
/// those of handle_duplicate, mem_map and handle_close.
pub fn map_narrowed(
    process: &Handle<Process>,
    m: &Handle<Memory>,
    offset: u64,
    len: u64,
    addr: usize,
    access: Access,
) -> Result<(), Error> {
    let narrow = sys::handle_duplicate(m, access.rights())?;
    let mapped = sys::mem_map(process, &narrow, offset, len, addr, access);
    mapped.and(narrow.close())
}

/// The segments and the stack of `program` in `process`, and its first
/// thread.
///
/// # Safety
/// As for `load`.
unsafe fn fill(
    own: &Handle<Process>,
    process: &Handle<Process>,
    program: &Program<'_>,
    window: usize,
    priority: u8,
    policy: Policy,
) -> Result<Handle<Thread>, Error> {
    for part in Part::ALL {
        let segment = &program.segments[part as usize];
        if segment.mem_size > 0 {
            // SAFETY: the promise of `fill`'s caller.
            unsafe { place(own, process, segment, access(part), window) }?;
        }
    }
    let stack = u64::from(program.stack_size);
    let segment = Segment {
        vaddr: INIT_STACK_TOP - stack,
        mem_size: stack,
        bytes: &[],
    };
    // SAFETY: as above.
    unsafe { place(own, process, &segment, Access::ReadWrite, window) }?;
    first_thread(process, program.entry, priority, policy)
}

/// A new memory object with the whole pages of `segment`, its file bytes
/// at the start, mapped at the segment's address of `process` with
/// `access` (`map_narrowed`). The handles go; the mapping holds the
/// object.
///
/// # Safety
/// As for `load`.
unsafe fn place(
    own: &Handle<Process>,
    process: &Handle<Process>,
    segment: &Segment<'_>,
    access: Access,
    window: usize,
) -> Result<(), Error> {
    let pages = segment.pages();
    let len = pages.end - pages.start;
    let m = sys::mem_create(len)?;
    // SAFETY: the promise of `place`'s caller.
    let copied = unsafe { copy(own, &m, segment.bytes, window) };
    let result =
        copied.and_then(|()| map_narrowed(process, &m, 0, len, pages.start as usize, access));
    let closed = m.close();
    result.and(closed)
}

/// `bytes` into the first bytes of `m`, a new object whose pages are zero:
/// the pages they take are mapped at `window` of the caller, written and
/// unmapped.
///
/// # Safety
/// As for `load`.
unsafe fn copy(
    own: &Handle<Process>,
    m: &Handle<Memory>,
    bytes: &[u8],
    window: usize,
) -> Result<(), Error> {
    if bytes.is_empty() {
        return Ok(());
    }
    let len = (bytes.len() as u64).next_multiple_of(PAGE_SIZE);
    sys::mem_map(own, m, 0, len, window, Access::ReadWrite)?;
    // SAFETY: the window maps `len` bytes of the new object, readable and
    // writable, and only the loader uses it (the caller's promise); `bytes`
    // lies elsewhere.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), window as *mut u8, bytes.len()) };
    // SAFETY: the mapping is the one made above, which nothing uses now.
    unsafe { sys::mem_unmap(own, window, len) }
}

/// thread_create in `process` at `entry`, on the stack under
/// INIT_STACK_TOP, with the buffer at INIT_MSGBUF and START_CHANNEL in x0
/// (spec 13.3).
fn first_thread(
    process: &Handle<Process>,
    entry: u64,
    priority: u8,
    policy: Policy,
) -> Result<Handle<Thread>, Error> {
    let x = [
        process.raw().0,
        entry,
        INIT_STACK_TOP,
        START_CHANNEL.0,
        priority.into(),
        policy as u64,
        INIT_MSGBUF,
        0,
        0,
        0,
    ];
    // SAFETY: the thread runs in the new process, on its own stack; it uses
    // no memory of the caller.
    let after = unsafe { sys::raw::<{ Call::ThreadCreate.number() }>(x) };
    match Error::from_code(after[0]) {
        None => Ok(Handle::from_raw(abi::Handle(after[1]))),
        Some(e) => Err(e),
    }
}
