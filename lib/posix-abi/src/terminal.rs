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
        proto_tty::BAD_DESCRIPTION => Some(EBADF),
        proto_tty::PERMISSION => Some(EACCES),
        proto_tty::NOT_CONTROLLING => Some(ENXIO),
        proto_tty::INVALID => Some(EINVAL),
        proto_tty::IO_ERROR => Some(EIO),
        proto_tty::RESTART => Some(JOB_RESTART),
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

/// Clone all descriptions, for diagnostic clients of the layer.
pub(crate) fn clone(terminal: rt::abi::Handle) -> Result<Handle<Channel>, i32> {
    clone_kept(terminal, None)
}

pub(crate) fn clone_kept(
    terminal: rt::abi::Handle,
    ids: Option<&[u32]>,
) -> Result<Handle<Channel>, i32> {
    let mut request = Writer::new();
    Method::Clone
        .header()
        .write(&mut request)
        .map_err(|_| EIO)?;
    if let Some(ids) = ids {
        request.u32(ids.len() as u32).map_err(|_| EIO)?;
        for &id in ids {
            request.u32(id).map_err(|_| EIO)?;
        }
    }
    rt::service::clone_session(&Handle::<Channel>::borrowed(terminal), request.as_bytes())
        .map_err(crate::process::clone_errno)
}

// Internal retry result: the service posted TTIN/TTOU before any effect.
const JOB_RESTART: i32 = 4096;

fn blocked(signal: u8) -> u32 {
    let bit = 1 << (signal - 1);
    u32::from(
        (crate::threads::own_block()
            .mask
            .load(core::sync::atomic::Ordering::SeqCst)
            | crate::process::page()
                .ignored
                .load(core::sync::atomic::Ordering::Acquire))
            & bit
            != 0,
    )
}

fn retry<T>(mut operation: impl FnMut() -> Result<T, i32>) -> Result<T, i32> {
    let block = crate::threads::own_block();
    let handled = block.handled.load(core::sync::atomic::Ordering::SeqCst);
    loop {
        match operation() {
            Err(JOB_RESTART) => {
                crate::signals::deliver_now();
                if block.handled.load(core::sync::atomic::Ordering::SeqCst) != handled
                    && block.flags.load(core::sync::atomic::Ordering::SeqCst)
                        & posix_thread::flag::NO_RESTART
                        != 0
                {
                    return Err(EINTR);
                }
            }
            result => return result,
        }
    }
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
    let master = number & proto_tty::MASTER != 0;
    retry(|| {
        let mut start = Writer::new();
        Read {
            key: None,
            terminal: number,
            blocked: blocked(proto_process::SIGTTIN),
            count,
        }
        .write_side(&mut start, master)
        .map_err(|_| EIO)?;
        crate::long::run_terminal(
            master,
            &terminal,
            start.as_bytes(),
            |cancel, key, w| {
                if cancel {
                    Cancel {
                        key,
                        terminal: number,
                    }
                    .write(
                        if master {
                            Method::MasterReadCancel
                        } else {
                            Method::ReadCancel
                        },
                        w,
                    )
                } else {
                    Read {
                        key: Some(key),
                        terminal: number,
                        blocked: blocked(proto_process::SIGTTIN),
                        count,
                    }
                    .write_side(w, master)
                }
            },
            &mut out[..count as usize],
            &refusal,
        )
    })
}

/// One message of a write: `bytes`, at most MAX_WRITE; the count the
/// service took.
#[inline(never)]
fn write_once(terminal: &Handle<Channel>, number: u32, bytes: &[u8]) -> Result<usize, i32> {
    let master = number & proto_tty::MASTER != 0;
    retry(|| {
        let mut start = Writer::new();
        Write {
            key: None,
            terminal: number,
            blocked: blocked(proto_process::SIGTTOU),
            bytes,
        }
        .write_side(&mut start, master)
        .map_err(|_| EIO)?;
        let mut result = [0; 4];
        let n = crate::long::run_terminal(
            master,
            terminal,
            start.as_bytes(),
            |cancel, key, w| {
                if cancel {
                    Cancel {
                        key,
                        terminal: number,
                    }
                    .write(
                        if master {
                            Method::MasterWriteCancel
                        } else {
                            Method::WriteCancel
                        },
                        w,
                    )
                } else {
                    Write {
                        key: Some(key),
                        terminal: number,
                        blocked: blocked(proto_process::SIGTTOU),
                        bytes,
                    }
                    .write_side(w, master)
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
    })
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
    authenticated: bool,
    buffer: &'a mut [u8; rt::abi::MESSAGE_MAX],
) -> Result<&'a [u8], i32> {
    let terminal = transport.terminal().ok_or(EBADF)?;
    let reply = loop {
        let sent = if authenticated {
            let identity = crate::process::identity()
                .and_then(|i| {
                    rt::sys::handle_duplicate(
                        i,
                        rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER,
                    )
                    .ok()
                })
                .ok_or(EIO)?;
            rt::sys::send_handles(&terminal, request, [identity.erase()]).map_err(|e| e.error)
        } else {
            rt::sys::send(&terminal, request)
        };
        match sent {
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

/// Open through the process's own service session.
pub fn open(transport: Transport, kind: u32, flags: u32, number: u32) -> Result<u32, i32> {
    let mut w = Writer::new();
    proto_tty::Open {
        kind,
        flags,
        number,
    }
    .write(&mut w)
    .map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let reply = call(transport, w.as_bytes(), true, &mut buffer)?;
    status_of(reply)?;
    let mut r = proto_wire::Reader::new(reply);
    r.u32().map_err(|_| EIO)?;
    let id = r.u32().map_err(|_| EIO)?;
    r.finish().map_err(|_| EIO)?;
    Ok(id)
}

pub fn description(
    transport: Transport,
    id: u32,
    method: Method,
    word: Option<u32>,
) -> Result<u32, i32> {
    let mut w = Writer::new();
    proto_tty::description(method, id, word, &mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let reply = call(
        transport,
        w.as_bytes(),
        method == Method::Grant,
        &mut buffer,
    )?;
    status_of(reply)?;
    let mut r = proto_wire::Reader::new(reply);
    r.u32().map_err(|_| EIO)?;
    Ok(r.u32().unwrap_or(0))
}

pub fn stat(transport: Transport, id: u32) -> Result<proto_tty::Stat, i32> {
    let mut w = Writer::new();
    proto_tty::description(Method::Stat, id, None, &mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let reply = call(transport, w.as_bytes(), false, &mut buffer)?;
    status_of(reply)?;
    proto_tty::Stat::read(proto_wire::Reader::new(&reply[4..])).map_err(|_| EIO)
}

/// GET_ATTR (tcgetattr): the settings of the terminal `number`.
#[inline(never)]
pub fn get_attr(transport: Transport, number: u32) -> Result<Termios, i32> {
    let mut w = Writer::new();
    proto_tty::get_attr(number, &mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let reply = call(transport, w.as_bytes(), false, &mut buffer)?;
    proto_tty::attr_reply(reply).map_err(|status| refusal(status).unwrap_or(EIO))
}

/// tcdrain: returns once the service has given the driver all the output
/// of the terminal `number`; a signal ends the wait with EINTR.
#[inline(never)]
pub fn drain(transport: Transport, number: u32) -> Result<(), i32> {
    let terminal = transport.terminal().ok_or(EBADF)?;
    retry(|| {
        let mut start = Writer::new();
        Drain {
            key: None,
            terminal: number,
            blocked: blocked(proto_process::SIGTTOU),
        }
        .write(&mut start)
        .map_err(|_| EIO)?;
        crate::long::run_with_identity(
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
                        blocked: blocked(proto_process::SIGTTOU),
                    }
                    .write(w)
                }
            },
            &mut [],
            &refusal,
        )
        .map(drop)
    })
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
    retry(|| {
        let mut w = Writer::new();
        SetAttr {
            terminal: number,
            blocked: blocked(proto_process::SIGTTOU),
            action,
            termios,
        }
        .write(&mut w)
        .map_err(|_| EIO)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        status_of(call(transport, w.as_bytes(), true, &mut buffer)?)
    })
}

/// FLUSH_QUEUES (tcflush) or FLOW (tcflow): `word` is the queue or the
/// action, which the service checks.
#[inline(never)]
pub fn control(transport: Transport, number: u32, method: Method, word: u32) -> Result<(), i32> {
    retry(|| {
        let mut w = Writer::new();
        Control {
            terminal: number,
            blocked: blocked(proto_process::SIGTTOU),
            word,
        }
        .write(method, &mut w)
        .map_err(|_| EIO)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        status_of(call(transport, w.as_bytes(), true, &mut buffer)?)
    })
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
    retry(|| {
        let mut w = Writer::new();
        proto_tty::job(method, number, group, &mut w).map_err(|_| EINVAL)?;
        if method == Method::SetPgrp {
            w.u32(blocked(proto_process::SIGTTOU)).map_err(|_| EIO)?;
        }
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
    })
}
