// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's place for the display service (sub-project 3, part 3a;
//! spec 3, 3.8): the session with the service (`proto_gpu`) that the start
//! area gives in the slot `Display`, as `random` keeps the entropy
//! service's. The part holds the session and its life across `fork`,
//! spawn and `exec`, and the display piece of the memory map (the buffer of
//! the screen). The calls of the screen itself (`open`, `flush`,
//! `input_read` and `close`, at the end of this file; the C functions of
//! libc.so call them) build on this interface:
//!
//! * `session()` is the process's `Display` session (SEND, DUPLICATE,
//!   TRANSFER), None in an image without the display service: the C
//!   function then answers ENODEV. OPEN goes on it; it is sent, never
//!   closed or replaced by the caller.
//! * `map_buffer(buffer, pages)` makes the buffer that OPEN returned the
//!   process's display piece and gives its address (EBUSY with one
//!   already, ENOMEM past the limits); `unmap_buffer()` takes it out
//!   (CLOSE, `exec`, exit), with the object's handle.
//! * A forked child gets a session of its own (a CLONE the parent made,
//!   `clone_session`), no owner session and no display piece: the
//!   parent's address faults until something maps it. `munmap` and
//!   `mprotect` on the piece give EINVAL.
//!
//! The session is cloned for every `fork` and spawn that has one: one
//! request to the display service (`cargo xtask posix-display` measures
//! the price in a fork). A refusal fails no fork: the child has no session
//! and its screen calls give ENODEV; the line says so.

use crate::constants::*;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use proto_gpu::{Method, Rect, Screen};
use proto_wire::{Status, Writer};
use rt::abi::{Error, MESSAGE_MAX};
use rt::handle::{Channel, Handle, Memory};

/// The session with the display service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the display service, which the start gives
/// (init's CONNECT, or the loader's slot Display).
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// A forked child: `session`, the clone the parent made, takes the place of
/// the parent's value, which names nothing of the child's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
    // The parent's owner and focus sessions name nothing of the child's
    // table: forgotten, never closed. The child owns no screen.
    OWNER.store(0, Ordering::Release);
    FOCUS.store(0, Ordering::Release);
    STATE.store(CLOSED, Ordering::Release);
}

/// The session with the display service, for the requests and for the
/// clones a child gets.
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}

/// Hides the session for the calls of a fork or spawn that follow (a
/// probe of the price of the clone), or shows it again: the value that was
/// there comes back to the caller, 0 for none.
#[cfg(feature = "thread-probe")]
pub fn probe_swap_session(raw: u64) -> u64 {
    SESSION.swap(raw, Ordering::AcqRel)
}

/// A clone of the process's session for a child (proto_gpu CLONE), when it
/// has one. A refusal fails no fork or spawn: the child gets no session. A
/// service that ended (PEER_CLOSED) closes the process's session, so that
/// no later fork asks again and none writes a line; another refusal (the
/// service at its limit) writes one.
pub(crate) fn clone_session() -> Option<Handle<Channel>> {
    let display = session()?;
    match rt::service::clone_session(
        &Handle::<Channel>::borrowed(display),
        &proto_gpu::Method::Clone.header().bytes(),
    ) {
        Ok(clone) => Some(clone),
        Err(proto_wire::Status::Kernel(rt::abi::Error::PeerClosed)) => {
            // The service ended (spec 3, 5.1): every session of it is dead
            // until a new shell. This one closes and no fork asks again.
            let raw = SESSION.swap(0, Ordering::AcqRel);
            if raw != 0 {
                drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
            }
            None
        }
        Err(status) => {
            rt::println!(
                "posix: the display service refused a session for a child ({status:?}); the child has none"
            );
            None
        }
    }
}

/// `buffer`, `pages` pages with MAP_READ and MAP_WRITE, becomes the display
/// piece of the memory map: its address. EBUSY when the map has one,
/// ENOMEM past the room, the limits or the table; the handle goes with a
/// refusal.
pub fn map_buffer(buffer: Handle<Memory>, pages: usize) -> Result<usize, i32> {
    crate::allocation::heap(|state| state.map_display(buffer, pages))
}

/// The display piece leaves the map and the process, and its object
/// closes; Ok when there is none.
pub fn unmap_buffer() -> Result<(), i32> {
    crate::allocation::heap(|state| state.unmap_display())
}

/// The address and pages of the display piece, None without one.
pub fn buffer() -> Option<(usize, usize)> {
    crate::allocation::regions(|map| map.display_piece())
}

// ------------------------------------------------------------------ the screen

/// The states of the process's screen.
const CLOSED: u32 = 0;
const OPENING: u32 = 1;
const OPEN: u32 = 2;

/// The longest OPEN is asked again after CLEARING, and its pause.
const CLEARING_TRIES: u32 = 50;
const CLEARING_PAUSE_NS: i64 = 10_000_000;

static STATE: AtomicU32 = AtomicU32::new(CLOSED);
/// The owner's session and the session of keyboard focus, 0 for none.
static OWNER: AtomicU64 = AtomicU64::new(0);
static FOCUS: AtomicU64 = AtomicU64::new(0);
/// What OPEN described: width, height, stride, format, flags.
static SCREEN: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];

/// A key event as `struct stafeto_key` of `<stafeto/display.h>` has it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Key {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}

/// The screen of the process: what `struct stafeto_display` carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub pixels: usize,
}

/// The errno of a refusal of the channel: the service is gone (ENODEV),
/// the kernel is out of memory (ENOMEM), the session was closed under the
/// call by a `close` in another thread (EBADF; the handle's number carries
/// a generation, so no other channel receives the request), anything else
/// EIO.
fn channel_errno(error: Error) -> i32 {
    match error {
        Error::PeerClosed => ENODEV,
        Error::BadHandle => EBADF,
        Error::NoMemory => ENOMEM,
        _ => EIO,
    }
}

/// The errno of a refusal of the display service, `open` for OPEN's.
fn status_errno(status: Status) -> i32 {
    use proto_gpu::{BUSY, CLEARING, INVALID, IO, NO_DEVICE, REVOKED};
    match status {
        Status::Kernel(error) => match error {
            Error::LimitReached => EAGAIN,
            other => channel_errno(other),
        },
        s if s == proto_gpu::code(BUSY) || s == proto_gpu::code(CLEARING) => EBUSY,
        s if s == proto_gpu::code(NO_DEVICE) || s == proto_gpu::code(REVOKED) => ENODEV,
        s if s == proto_gpu::code(INVALID) => EINVAL,
        s if s == proto_gpu::code(IO) => EIO,
        _ => EIO,
    }
}

/// One request and its reply; a send that came back INTERRUPTED goes
/// again, as the other calls of the layer do: the service never saw it.
fn call(channel: &Handle<Channel>, bytes: &[u8]) -> Result<rt::sys::Reply, Error> {
    loop {
        match rt::sys::send(channel, bytes) {
            Err(Error::Interrupted) => continue,
            other => return other,
        }
    }
}

/// The status at the head of a reply.
fn status_of(reply: &rt::sys::Reply) -> Result<Status, i32> {
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let word = bytes.get(..4).ok_or(EIO)?;
    Ok(Status::from_code(u32::from_le_bytes([
        word[0], word[1], word[2], word[3],
    ])))
}

/// The process's screen, as `open` returned it: the description of the
/// open screen, the address from the display piece of the map.
fn described() -> Option<Opened> {
    let (pixels, _) = buffer()?;
    let field = |i: usize| SCREEN[i].load(Ordering::Acquire);
    Some(Opened {
        width: field(0),
        height: field(1),
        stride: field(2),
        format: field(3),
        pixels,
    })
}

/// `stafeto_display_open`: the screen. A process that has it gets the same
/// description again, with no request. Else OPEN goes to the service
/// through the process's `Display` session, again up to 50 times 10 ms
/// apart while the service says CLEARING (the last owner's buffer is being
/// cleared); BUSY is EBUSY at once. ENODEV for a process without the
/// session, for a service that ended or restarted (its sessions are
/// closed channels) and for a device that did not answer; ENOMEM when the
/// buffer does not fit the map; EINTR when a signal ends a pause.
pub fn open() -> Result<Opened, i32> {
    let Some(session) = session() else {
        return Err(ENODEV);
    };
    match STATE.compare_exchange(CLOSED, OPENING, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {}
        Err(OPEN) => return described().ok_or(EIO),
        Err(_) => return Err(EBUSY),
    }
    let result = open_screen(&Handle::<Channel>::borrowed(session));
    STATE.store(
        if result.is_ok() { OPEN } else { CLOSED },
        Ordering::Release,
    );
    result
}

fn open_screen(session: &Handle<Channel>) -> Result<Opened, i32> {
    use proto_gpu::{CLEARING, FORMAT_XRGB8888, NO_INPUT};
    let request = Method::Open.header().bytes();
    let mut tries = 0;
    let mut reply = loop {
        let reply = call(session, &request).map_err(channel_errno)?;
        let status = status_of(&reply)?;
        if status == Status::Ok || status == proto_gpu::code(NO_INPUT) {
            break reply;
        }
        if status == proto_gpu::code(CLEARING) && tries < CLEARING_TRIES {
            tries += 1;
            crate::threads::sleep::pause(CLEARING_PAUSE_NS)?;
            continue;
        }
        return Err(status_errno(status));
    };
    let mut buffer = [0; MESSAGE_MAX];
    let (_, screen) = Screen::read(reply.bytes(&mut buffer)).map_err(|_| EIO)?;
    let memory = reply.handles.take::<Memory>(0).map_err(|_| EIO)?;
    let owner = reply.handles.take::<Channel>(1).map_err(|_| EIO)?;
    // The focus session is there unless the service had none to give.
    let focus = if reply.handles.len() > 2 {
        Some(reply.handles.take::<Channel>(2).map_err(|_| EIO)?)
    } else {
        None
    };
    if screen.format != FORMAT_XRGB8888 || !screen.fits() || screen.width == 0 || screen.height == 0
    {
        return Err(EIO);
    }
    let bytes = u64::from(screen.stride) * u64::from(screen.height);
    // The buffer maps first: a refusal closes the owner's session, which
    // gives the screen back.
    let pixels = map_buffer(memory, bytes.div_ceil(4096) as usize)?;
    for (cell, value) in SCREEN.iter().zip([
        screen.width,
        screen.height,
        screen.stride,
        screen.format,
        screen.flags,
    ]) {
        cell.store(value, Ordering::Release);
    }
    FOCUS.store(focus.map_or(0, |f| f.into_raw().0), Ordering::Release);
    OWNER.store(owner.into_raw().0, Ordering::Release);
    Ok(Opened {
        width: screen.width,
        height: screen.height,
        stride: screen.stride,
        format: screen.format,
        pixels,
    })
}

/// `stafeto_display_flush`: the rectangle of points the program wrote goes
/// to the device, and the call returns when the device showed it. EBADF
/// without an open screen, EINVAL for an empty rectangle or one outside the
/// screen, ENODEV when the service ended or took the screen away. A signal
/// does not end the wait: the call goes on, as with SA_RESTART.
pub fn flush(x: u32, y: u32, w: u32, h: u32) -> Result<(), i32> {
    if STATE.load(Ordering::Acquire) != OPEN {
        return Err(EBADF);
    }
    let screen = described().ok_or(EBADF)?;
    let rect = Rect { x, y, w, h };
    if !rect.within(screen.width, screen.height) {
        return Err(EINVAL);
    }
    if SCREEN[4].load(Ordering::Acquire) & proto_gpu::CLEAN_BEFORE_FLUSH != 0 {
        // The device does not see the cache of the processor: the lines
        // of the rectangle are written back first, while the display piece
        // is there (a `close` in another thread takes it away: then the
        // call is EBADF, and the result of a flush against a close is
        // undefined all the same).
        let screen = described().ok_or(EBADF)?;
        for row in y..y + h {
            let at = screen.pixels + row as usize * screen.stride as usize + x as usize * 4;
            rt::dma::clean(at, w as usize * 4);
        }
    }
    let mut request = Writer::new();
    rect.write(&mut request).map_err(|_| EINVAL)?;
    let owner = Handle::<Channel>::borrowed(rt::abi::Handle(OWNER.load(Ordering::Acquire)));
    let reply = call(&owner, request.as_bytes()).map_err(channel_errno)?;
    match status_of(&reply)? {
        Status::Ok => Ok(()),
        status => Err(status_errno(status)),
    }
}

/// `stafeto_input_read`: up to `out.len()` key events (at most 120 at a
/// time) the service has, without waiting; the count, 0 for none. EBADF
/// without an open screen; ENODEV when the screen has no focus session
/// (an image without the input service) or the service ended or took the
/// focus away.
pub fn input_read(out: &mut [Key]) -> Result<usize, i32> {
    if STATE.load(Ordering::Acquire) != OPEN {
        return Err(EBADF);
    }
    let raw = FOCUS.load(Ordering::Acquire);
    if raw == 0 {
        return Err(ENODEV);
    }
    if out.is_empty() {
        return Err(EINVAL);
    }
    let max = out.len().min(proto_input::MAX_READ as usize);
    let mut request = Writer::new();
    proto_input::write_read(max as u32, &mut request).map_err(|_| EINVAL)?;
    let focus = Handle::<Channel>::borrowed(rt::abi::Handle(raw));
    let reply = call(&focus, request.as_bytes()).map_err(channel_errno)?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let mut count = 0;
    proto_input::read_events(bytes, |event| {
        if count < max {
            out[count] = Key {
                kind: event.kind,
                code: event.code,
                value: event.value,
            };
            count += 1;
        }
    })
    .map_err(|status| match status {
        Status::Unknown(c) if c == proto_input::REVOKED => ENODEV,
        other => status_errno(other),
    })?;
    Ok(count)
}

/// Lets the screen go: the display piece leaves the map and both sessions
/// close, which gives the screen back. The caller holds the state.
fn release() {
    let _ = unmap_buffer();
    for cell in [&OWNER, &FOCUS] {
        let raw = cell.swap(0, Ordering::AcqRel);
        if raw != 0 {
            drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
        }
    }
}

/// `stafeto_display_close`: CLOSE to the service, the buffer unmapped, the
/// sessions closed. A service that is gone has nothing to answer: the
/// screen is closed all the same. EBADF without an open screen.
pub fn close() -> Result<(), i32> {
    if STATE
        .compare_exchange(OPEN, OPENING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(EBADF);
    }
    let owner = Handle::<Channel>::borrowed(rt::abi::Handle(OWNER.load(Ordering::Acquire)));
    let _ = call(&owner, &Method::Close.header().bytes());
    release();
    STATE.store(CLOSED, Ordering::Release);
    Ok(())
}

/// `exec` takes the screen back (spec 3, 3.5): the new image has the
/// process's `Display` session and neither the buffer nor the owner's
/// session, so that it can open the screen the moment it starts.
pub(crate) fn release_for_exec() {
    if STATE.swap(CLOSED, Ordering::AcqRel) == OPEN {
        release();
    }
}
