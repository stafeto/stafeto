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
/// The service's channel with no label, its own process, and the level of
/// its loop, which the main thread keeps for good (`set_handles`).
static OWN: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// The boot image, `len` bytes mapped at `addr` for as long as the
/// service lives.
pub fn set_image(addr: usize, len: usize) {
    IMAGE[0].store(addr, Ordering::Relaxed);
    IMAGE[1].store(len, Ordering::Release);
}

/// The handles the threads of the service share: `channel`, the service's
/// channel with no label, and `own`, its process with MANAGE; `level`, the
/// loop's priority.
pub fn set_handles(channel: &Handle<Channel>, own: &Handle<Process>, level: u8) {
    OWN[0].store(channel.raw().0, Ordering::Relaxed);
    OWN[1].store(own.raw().0, Ordering::Relaxed);
    OWN[2].store(level.into(), Ordering::Release);
}

/// The service's channel with no label.
pub fn channel() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(abi::Handle(OWN[0].load(Ordering::Acquire)))
}

fn own() -> ManuallyDrop<Handle<Process>> {
    Handle::borrowed(abi::Handle(OWN[1].load(Ordering::Acquire)))
}

fn level() -> u8 {
    OWN[2].load(Ordering::Acquire) as u8
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
/// with MANAGE, DUPLICATE and TRANSFER, the record's session, and the
/// thread.
pub struct Made {
    pub label: u64,
    pub process: Handle<Process>,
    pub session: Handle<Channel>,
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

/// Loaded or Abandon of the record of `label` (`method`).
pub fn tell(method: Method, label: u64) -> Result<(), Status> {
    let mut w = Writer::new();
    method.header().write(&mut w)?;
    w.u64(label)?;
    let mut buffer = [0; abi::MESSAGE_MAX];
    ask(&w, rt::handle::Outgoing::new(), &mut buffer).map(drop)
}

/// Makes the process of `create` with the start channel `start` from the
/// program `name` of the boot image, loading it through `window` of the
/// service's space, which only the calling thread uses, while `thread`,
/// the caller's own, runs at the process's priority. The record stays
/// LOADING until `tell(Loaded)`.
///
/// # Safety
/// Only the calling thread maps and uses `window`, a range as big as the
/// biggest segment of a program of the boot image.
pub unsafe fn make(
    create: &Create,
    start: Handle<Channel>,
    name: &Name,
    window: usize,
    thread: &Handle<Thread>,
) -> Result<Made, Failed> {
    let refused = |status| Failed {
        status,
        label: None,
    };
    let program = program(name).ok_or(refused(Status::from_code(proto_process::INVALID)))?;
    let mut w = Writer::new();
    Method::Create.header().write(&mut w).map_err(refused)?;
    create.write(&mut w).map_err(refused)?;
    let mut buffer = [0; abi::MESSAGE_MAX];
    let (len, mut handles) = ask(&w, [start.erase()].into(), &mut buffer).map_err(refused)?;
    let mut r = Reader::new(&buffer[..len]);
    let made = (|| {
        // The status, then the PID, which init's start data do not need.
        let (_, _, label) = (r.u32()?, r.u32()?, r.u64()?);
        r.finish()?;
        let process = handles.take::<Process>(0).map_err(|_| Status::BadSize)?;
        let session = handles.take::<Channel>(1).map_err(|_| Status::BadSize)?;
        Ok((label, process, session))
    })();
    let (label, process, session) = made.map_err(refused)?;
    let failed = |status| Failed {
        status,
        label: Some(label),
    };
    // The copy runs at the process's own level, and the thread goes back
    // to the loop's level for its next request.
    let _ = sys::thread_set_priority(thread, create.priority, abi::Policy::Fifo);
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
    let _ = sys::thread_set_priority(thread, level(), abi::Policy::Fifo);
    let first = filled.map_err(|e| failed(Status::Kernel(e)))?;
    Ok(Made {
        label,
        process,
        session,
        thread: first,
    })
}
