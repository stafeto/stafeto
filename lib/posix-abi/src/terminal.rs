// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The console as a terminal (5f; proto_tty): a process with a session of
//! the terminal service reads and writes its standard descriptors there,
//! and the service's line discipline edits, echoes and maps the bytes.
//! Reads and writes are long operations in two steps from the calling
//! thread (`long::run_with`), outside the lock of the files, as those of
//! pipes: a signal ends the wait with no effect unless its handler had
//! SA_RESTART. A write goes in pieces of MAX_WRITE bytes, and the service
//! may take part of one; the count of what went comes back once a signal
//! stops it after some bytes.

use crate::constants::*;
use posix_fs::Transport;
use proto_tty::{
    CONSOLE, Cancel, Control, Drain, MAX_READ, MAX_WRITE, Method, QUEUE_BOTH, Read, SetAttr,
    Termios, Write,
};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Handle};

pub const ENOTTY: i32 = 25;

/// The repaired counterfeit endpoint is one clone of the loader root.
/// Keep its other 254 clones in the old image until exec commits: the
/// inherited true endpoint must move without allocating clone 256.
pub fn probe_full_exec() -> i32 {
    let result = crate::shared::with_files(|fs| Ok(fs.terminal().map(Handle::raw)));
    let Ok(Some(terminal)) = result else {
        return EIO;
    };
    for _ in 0..254 {
        let Ok(channel) = clone(terminal) else {
            return EIO;
        };
        let _ = channel.into_raw();
    }
    if clone(terminal).is_err() { 0 } else { EIO }
}

pub fn probe_edge(group: u32) -> i32 {
    let result = crate::shared::with_files(|fs| Ok(fs.terminal().map(Handle::raw)));
    let Ok(Some(terminal)) = result else {
        return EIO;
    };
    let mut w = Writer::new();
    let _ = proto_wire::Header::new(23, proto_tty::VERSION).write(&mut w);
    let _ = w.u32(group);
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let Ok(reply) = rt::sys::send(&Handle::<Channel>::borrowed(terminal), w.as_bytes()) else {
        return EIO;
    };
    if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() == Ok(0) {
        0
    } else {
        EIO
    }
}

/// Diagnostic requests are served only by the special terminal probe
/// image. Production services return UNKNOWN_METHOD for these numbers.
pub fn probe_trusted(target: u32, newborn: bool) -> i32 {
    let result = crate::shared::with_files(|fs| Ok(fs.terminal().map(Handle::raw)));
    let Ok(Some(terminal)) = result else {
        return EIO;
    };
    let mut w = Writer::new();
    let _ =
        proto_wire::Header::new(if newborn { 22 } else { 21 }, proto_tty::VERSION).write(&mut w);
    let _ = w.u32(target);
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let Ok(reply) = rt::sys::send(&Handle::<Channel>::borrowed(terminal), w.as_bytes()) else {
        return EIO;
    };
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    match r.u32() {
        Ok(0) if !newborn => 0,
        Ok(0) if r.u32() == Ok(1) => 0,
        Ok(proto_process::PERMISSION) => EPERM,
        _ => EIO,
    }
}

/// The errno of a refusal of the terminal service.
fn refusal(status: Status) -> Option<i32> {
    match status.code() {
        proto_tty::BAD_TERMINAL => Some(ENOTTY),
        proto_tty::INVALID => Some(EINVAL),
        _ if status == Status::Kernel(rt::abi::Error::LimitReached) => Some(EAGAIN),
        _ => None,
    }
}

/// ABANDON through the session `terminal`, as pipes::abandon: the
/// operations of an old image's threads go at exec.
pub(crate) fn abandon(terminal: rt::abi::Handle) {
    let session = Handle::<Channel>::borrowed(terminal);
    let request = Method::Abandon.header().bytes();
    while rt::sys::send(&session, &request) == Err(rt::abi::Error::Interrupted) {}
}

/// Clone of the session `terminal` for a child (proto_tty CLONE).
pub(crate) fn clone(terminal: rt::abi::Handle) -> Result<Handle<Channel>, i32> {
    rt::service::clone_session(
        &Handle::<Channel>::borrowed(terminal),
        &Method::Clone.header().bytes(),
    )
    .map_err(crate::process::clone_errno)
}

/// A read of up to `out.len()` bytes (MAX_READ at most) of the terminal
/// `number` (the console for the standard descriptors): the count, 0 at
/// an end-of-file.
#[inline(never)]
pub fn read(transport: Transport, number: u32, out: &mut [u8]) -> Result<usize, i32> {
    if out.is_empty() {
        return Ok(0);
    }
    let terminal = transport.terminal().ok_or(EBADF)?;
    let count = out.len().min(MAX_READ) as u32;
    let mut start = Writer::new();
    Read {
        key: None,
        terminal: number,
        count,
    }
    .write(&mut start)
    .map_err(|_| EIO)?;
    crate::long::run_with(
        &terminal,
        start.as_bytes(),
        |cancel, key, w| {
            if cancel {
                Cancel {
                    key,
                    terminal: number,
                }
                .write(Method::ReadCancel, w)
            } else {
                Read {
                    key: Some(key),
                    terminal: number,
                    count,
                }
                .write(w)
            }
        },
        &mut out[..count as usize],
        &refusal,
    )
}

/// One message of a write: `bytes`, at most MAX_WRITE; the count the
/// service took.
#[inline(never)]
fn write_once(terminal: &Handle<Channel>, number: u32, bytes: &[u8]) -> Result<usize, i32> {
    let mut start = Writer::new();
    Write {
        key: None,
        terminal: number,
        bytes,
    }
    .write(&mut start)
    .map_err(|_| EIO)?;
    let mut result = [0; 4];
    let n = crate::long::run_with(
        terminal,
        start.as_bytes(),
        |cancel, key, w| {
            if cancel {
                Cancel {
                    key,
                    terminal: number,
                }
                .write(Method::WriteCancel, w)
            } else {
                Write {
                    key: Some(key),
                    terminal: number,
                    bytes,
                }
                .write(w)
            }
        },
        &mut result,
        &refusal,
    )?;
    let written = proto_tty::written(&result[..n]).map_err(|_| EIO)? as usize;
    if written == 0 || written > bytes.len() {
        return Err(EIO);
    }
    Ok(written)
}

/// A write of `bytes` to the terminal `number`: all of them unless a
/// signal stops it after some (their count).
#[inline(never)]
pub fn write(transport: Transport, number: u32, bytes: &[u8]) -> Result<usize, i32> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let terminal = transport.terminal().ok_or(EBADF)?;
    let mut done = 0;
    while done < bytes.len() {
        let piece = &bytes[done..bytes.len().min(done + MAX_WRITE)];
        match write_once(&terminal, number, piece) {
            Ok(n) => done += n,
            Err(_) if done > 0 => break,
            Err(errno) => return Err(errno),
        }
    }
    Ok(done)
}

/// One request of the terminal service that answers at once, and the
/// bytes of its reply: a send the kernel took back goes again.
#[inline(never)]
fn call<'a>(
    transport: Transport,
    request: &[u8],
    buffer: &'a mut [u8; rt::abi::MESSAGE_MAX],
) -> Result<&'a [u8], i32> {
    let terminal = transport.terminal().ok_or(EBADF)?;
    let reply = loop {
        match rt::sys::send(&terminal, request) {
            Err(rt::abi::Error::Interrupted) => continue,
            other => break other.map_err(|_| EIO)?,
        }
    };
    Ok(reply.bytes(buffer))
}

/// The errno of the status that starts a reply, 0 for Ok.
fn status_of(reply: &[u8]) -> Result<(), i32> {
    let mut r = proto_wire::Reader::new(reply);
    match Status::from_code(r.u32().map_err(|_| EIO)?) {
        Status::Ok => Ok(()),
        status => Err(refusal(status).unwrap_or(EIO)),
    }
}

/// GET_ATTR (tcgetattr): the settings of the terminal `number`.
#[inline(never)]
pub fn get_attr(transport: Transport, number: u32) -> Result<Termios, i32> {
    let mut w = Writer::new();
    proto_tty::get_attr(number, &mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let reply = call(transport, w.as_bytes(), &mut buffer)?;
    proto_tty::attr_reply(reply).map_err(|status| refusal(status).unwrap_or(EIO))
}

/// tcdrain: returns once the service has given the driver all the output
/// of the terminal `number`; a signal ends the wait with EINTR.
#[inline(never)]
pub fn drain(transport: Transport, number: u32) -> Result<(), i32> {
    let terminal = transport.terminal().ok_or(EBADF)?;
    let mut start = Writer::new();
    Drain {
        key: None,
        terminal: number,
    }
    .write(&mut start)
    .map_err(|_| EIO)?;
    crate::long::run_with(
        &terminal,
        start.as_bytes(),
        |cancel, key, w| {
            if cancel {
                Cancel {
                    key,
                    terminal: number,
                }
                .write(Method::DrainCancel, w)
            } else {
                Drain {
                    key: Some(key),
                    terminal: number,
                }
                .write(w)
            }
        },
        &mut [],
        &refusal,
    )
    .map(drop)
}

/// SET_ATTR (tcsetattr): TCSADRAIN and TCSAFLUSH wait for the output to
/// go first (`drain`), then the service changes the settings at once,
/// and for TCSAFLUSH drops the input not read.
#[inline(never)]
pub fn set_attr(
    transport: Transport,
    number: u32,
    action: u32,
    termios: Termios,
) -> Result<(), i32> {
    if action != proto_tty::NOW {
        drain(transport, number)?;
    }
    let mut w = Writer::new();
    SetAttr {
        terminal: number,
        action,
        termios,
    }
    .write(&mut w)
    .map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    status_of(call(transport, w.as_bytes(), &mut buffer)?)
}

/// FLUSH_QUEUES (tcflush) or FLOW (tcflow): `word` is the queue or the
/// action, which the service checks.
#[inline(never)]
pub fn control(transport: Transport, number: u32, method: Method, word: u32) -> Result<(), i32> {
    let mut w = Writer::new();
    Control {
        terminal: number,
        word,
    }
    .write(method, &mut w)
    .map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    status_of(call(transport, w.as_bytes(), &mut buffer)?)
}

const _: () = assert!(QUEUE_BOTH == 2 && CONSOLE == 0);

/// A request of the controlling terminal (5f, T3; proto_tty ACQUIRE,
/// SET_PGRP, GET_PGRP, GET_SID, CONTROLLING) of the terminal `number`,
/// with a copy of the process's identity, which the service has the
/// process service vouch for: the word of the reply (0 for those with
/// none). EPERM, ENOTTY and EINVAL as the service answers; ENOTTY without
/// an identity it could use.
#[inline(never)]
pub fn job(
    transport: Transport,
    number: u32,
    method: Method,
    group: Option<u32>,
) -> Result<u32, i32> {
    let terminal = transport.terminal().ok_or(EBADF)?;
    let mut w = Writer::new();
    proto_tty::job(method, number, group, &mut w).map_err(|_| EINVAL)?;
    let rights = rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let reply = loop {
        let identity =
            crate::process::identity().and_then(|i| rt::sys::handle_duplicate(i, rights).ok());
        let sent = match identity {
            Some(copy) => rt::sys::send_handles(&terminal, w.as_bytes(), [copy.erase()])
                .map_err(|refused| refused.error),
            None => rt::sys::send(&terminal, w.as_bytes()),
        };
        match sent {
            Err(rt::abi::Error::Interrupted) => continue,
            other => break other.map_err(|_| EIO)?,
        }
    };
    let bytes = reply.bytes(&mut buffer);
    let mut r = proto_wire::Reader::new(bytes);
    let code = r.u32().map_err(|_| EIO)?;
    match code {
        0 => Ok(r.u32().unwrap_or(0)),
        proto_tty::PERMISSION => Err(EPERM),
        proto_tty::NOT_CONTROLLING | proto_tty::NO_IDENTITY => Err(ENOTTY),
        code => Err(refusal(Status::from_code(code)).unwrap_or(EIO)),
    }
}
