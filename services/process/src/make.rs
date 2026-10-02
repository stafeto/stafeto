// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! How a thread of the service makes a POSIX process (spec 2, section
//! 3.1): Create through the service's channel with no label gives the
//! record, its exit place and the empty process; the thread loads the
//! program from the boot image into it at the process's own priority
//! (rt::loader::fill), so that the copy of its segments never runs on the
//! service's loop and a big program delays nobody above the process; then
//! Loaded or Abandon tells the loop how it went. Until the loader of 5c
//! the service pays for the segments from its quota.

use bootimg::{BootImage, Program};
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use proto_process::{Create, Method};
use proto_wire::{Name, Reader, Status, Writer};
use rt::handle::{Channel, Handle, Process, Thread};
use rt::{abi, loader, sys};

/// The boot image the service maps read-only at its start (`set_image`).
static IMAGE: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
/// The service's channel with no label, its own process, init's channel
/// the level of its loop and the channel of the identity sessions, which
/// the main thread keeps for good (`set_handles`).
static OWN: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// The boot image, `len` bytes mapped at `addr` for as long as the
/// service lives.
pub fn set_image(addr: usize, len: usize) {
    IMAGE[0].store(addr, Ordering::Relaxed);
    IMAGE[1].store(len, Ordering::Release);
}

/// The handles the threads of the service share: `channel`, the service's
/// channel with no label, `own`, its process with MANAGE, and `init`, its
/// channel to init (Startup::parent); `level`, the loop's priority.
pub fn set_handles(
    channel: &Handle<Channel>,
    own: &Handle<Process>,
    init: &Handle<Channel>,
    level: u8,
    identities: &Handle<Channel>,
) {
    OWN[0].store(channel.raw().0, Ordering::Relaxed);
    OWN[1].store(own.raw().0, Ordering::Relaxed);
    OWN[2].store(init.raw().0, Ordering::Relaxed);
    OWN[4].store(identities.raw().0, Ordering::Relaxed);
    OWN[3].store(level.into(), Ordering::Release);
}

/// The service's channel to init.
pub fn init() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(abi::Handle(OWN[2].load(Ordering::Acquire)))
}

/// The service's channel with no label.
pub fn channel() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(abi::Handle(OWN[0].load(Ordering::Acquire)))
}

pub fn own() -> ManuallyDrop<Handle<Process>> {
    Handle::borrowed(abi::Handle(OWN[1].load(Ordering::Acquire)))
}

fn level() -> u8 {
    OWN[3].load(Ordering::Acquire) as u8
}

/// The program `name` of the boot image.
fn program(name: &Name) -> Option<Program<'static>> {
    let len = IMAGE[1].load(Ordering::Acquire);
    let addr = IMAGE[0].load(Ordering::Relaxed);
    if len == 0 {
        return None;
    }
    // SAFETY: the main thread mapped the boot image read-only at `addr`,
    // `len` bytes, for as long as the service lives, before any thread
    // that makes processes started.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(addr as *const u8, len) };
    let boot = BootImage::parse(bytes).ok()?;
    let file = boot
        .files()
        .find(|f| f.name.as_bytes() == name.as_bytes())?;
    Program::parse(file.data).ok()
}

/// A process the service made and loaded, whose first thread waits for
/// thread_start: the label of its record, a copy of the process
/// with MANAGE, DUPLICATE and TRANSFER, the record's session and its
/// identity session, and the thread.
pub struct Made {
    pub label: u64,
    pub process: Handle<Process>,
    pub session: Handle<Channel>,
    pub identity: Handle<Channel>,
    pub thread: Handle<Thread>,
}

/// Why no process was made: the status for init or the parent, and the
/// label of the record when one was made, which Abandon then ends.
pub struct Failed {
    pub status: Status,
    pub label: Option<u64>,
}

/// A request through the service's channel with no label: its reply's
/// bytes in `buffer` and its handles.
fn ask(
    w: &Writer,
    handles: rt::handle::Outgoing,
    buffer: &mut [u8; abi::MESSAGE_MAX],
) -> Result<(usize, rt::handle::Incoming), Status> {
    let channel = channel();
    let reply = sys::send_handles(&channel, w.as_bytes(), handles)
        .map_err(|refused| Status::Kernel(refused.error))?;
    let len = reply.bytes(buffer).len();
    let status = Status::from_code(Reader::new(&buffer[..len]).u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    Ok((len, reply.handles))
}

/// Loaded of the record of `label`, with its first thread, the router of
/// the process's signals until the process names another (Router).
pub fn loaded(label: u64, thread: Handle<Thread>) -> Result<(), Status> {
    let mut w = Writer::new();
    Method::Loaded.header().write(&mut w)?;
    w.u64(label)?;
    let mut buffer = [0; abi::MESSAGE_MAX];
    ask(&w, [thread.erase()].into(), &mut buffer).map(drop)
}

/// Abandon of the record of `label` (0 for none), whose process is killed,
/// and of the Spawn of the record of `parent` (0 for none), which gets
/// `status`.
pub fn abandon(label: u64, parent: u64, status: Status) -> Result<(), Status> {
    let mut w = Writer::new();
    Method::Abandon.header().write(&mut w)?;
    w.u64(label)?;
    w.u64(parent)?;
    w.u32(status.code())?;
    let mut buffer = [0; abi::MESSAGE_MAX];
    ask(&w, rt::handle::Outgoing::new(), &mut buffer).map(drop)
}

/// The status of a reply, its first word.
pub fn status(bytes: &[u8]) -> Result<Status, Status> {
    Ok(Status::from_code(Reader::new(bytes).u32()?))
}

/// ADOPTED for `ticket` with what `made` gave: the session, the process,
/// a copy of its thread and the identity session, then thread_start and Loaded once init took
/// them; a refusal of init, or no process, ends the record and the Spawn
/// of `parent` (0 for none) with Abandon. `buffer` is the calling
/// thread's.
pub fn adopted(ticket: u64, made: Result<Made, Failed>, parent: u64) {
    let mut w = Writer::new();
    if proto_init::Method::Adopted.header().write(&mut w).is_err() || w.u64(ticket).is_err() {
        return;
    }
    let init = init();
    let made = match made {
        Ok(made) => made,
        Err(failed) => {
            // Init hears of the failure first, then the process goes, and
            // with it the last copy of the start channel. Init answers at
            // once; a lost answer leaves its record waiting until the start
            // channel's end.
            let _ = w.u32(failed.status.code().max(1));
            let _ = sys::send(&init, w.as_bytes());
            let _ = abandon(failed.label.unwrap_or(0), parent, failed.status);
            return;
        }
    };
    let Made {
        label,
        process,
        session,
        identity,
        thread,
    } = made;
    // DUPLICATE: the process names its main thread the router of its
    // signals with a copy of it (proto_process Router).
    let rights = abi::Rights::MANAGE | abi::Rights::DUPLICATE | abi::Rights::TRANSFER;
    let copy = sys::handle_duplicate(&thread, rights);
    let taken = w.u32(0).is_ok()
        && copy.is_ok_and(|copy| {
            let mut buffer = [0; abi::MESSAGE_MAX];
            let handles = [
                session.erase(),
                process.erase(),
                copy.erase(),
                identity.erase(),
            ];
            sys::send_handles(&init, w.as_bytes(), handles)
                .is_ok_and(|reply| status(reply.bytes(&mut buffer)) == Ok(Status::Ok))
        });
    if taken && sys::thread_start(&thread).is_ok() {
        let _ = loaded(label, thread);
    } else {
        let _ = abandon(label, parent, Status::from_code(proto_process::AGAIN));
    }
}

/// Makes the process of `create` with the start channel and the witness of
/// `start` (proto_init Adoption) from the
/// program `name` of the boot image, loading it through `window` of the
/// service's space, which only the calling thread uses, while `thread`,
/// the caller's own, runs at `level`: the process's priority, or that of
/// the parent whose Spawn waits for it when higher, so that a parent
/// waits for no copy below its own level; never above the loop's. The
/// record stays LOADING until `loaded`.
///
/// # Safety
/// Only the calling thread maps and uses `window`, a range as big as the
/// biggest segment of a program of the boot image.
pub unsafe fn make(
    create: &Create,
    start: [Handle<Channel>; 2],
    name: &Name,
    window: usize,
    thread: &Handle<Thread>,
    level: u8,
) -> Result<Made, Failed> {
    let refused = |status| Failed {
        status,
        label: None,
    };
    let program = program(name).ok_or(refused(Status::from_code(proto_process::INVALID)))?;
    // The end of an identity session waits in its channel, which no loop
    // receives on, and the session stays until it is received: this thread
    // empties the channel before each Create, so that the sessions of the
    // processes that went do not fill it and no step of the loop grows
    // with their number.
    let identities = Handle::<Channel>::borrowed(abi::Handle(OWN[4].load(Ordering::Acquire)));
    while sys::try_receive(&identities).is_ok() {}
    let mut w = Writer::new();
    Method::Create.header().write(&mut w).map_err(refused)?;
    create.write(&mut w).map_err(refused)?;
    let mut buffer = [0; abi::MESSAGE_MAX];
    let [start, witness] = start;
    let (len, mut handles) =
        ask(&w, [start.erase(), witness.erase()].into(), &mut buffer).map_err(refused)?;
    let mut r = Reader::new(&buffer[..len]);
    // The status, then the PID, which init's start data do not need, and
    // the label first: past it the record exists, and a failure ends it.
    let (_, _, label) = (|| Ok::<_, Status>((r.u32()?, r.u32()?, r.u64()?)))().map_err(refused)?;
    let failed = |status| Failed {
        status,
        label: Some(label),
    };
    let handed = (|| {
        r.finish()?;
        let process = handles.take::<Process>(0).map_err(|_| Status::BadSize)?;
        let session = handles.take::<Channel>(1).map_err(|_| Status::BadSize)?;
        let identity = handles.take::<Channel>(2).map_err(|_| Status::BadSize)?;
        Ok((process, session, identity))
    })();
    let (process, session, identity) = handed.map_err(failed)?;
    // The copy runs at its level, and the thread goes back to the loop's
    // level for its next request.
    let copy_level = level.clamp(1, self::level());
    let _ = sys::thread_set_priority(thread, copy_level, abi::Policy::Fifo);
    // SAFETY: the caller's promise for `window`.
    let filled = unsafe {
        loader::fill(
            &own(),
            &process,
            &program,
            window,
            create.priority,
            abi::Policy::Fifo,
        )
    };
    let _ = sys::thread_set_priority(thread, self::level(), abi::Policy::Fifo);
    let first = filled.map_err(|e| failed(Status::Kernel(e)))?;
    Ok(Made {
        label,
        process,
        session,
        identity,
        thread: first,
    })
}
