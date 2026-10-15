// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pipes (5e; proto_pipe): their ends live in the pipe service, and a
//! descriptor names one (posix_fs::Target::Pipe). Reads and writes are
//! long operations in two steps from the calling thread
//! (`long::run_with`), outside the lock of the files: a signal ends the
//! wait with no effect unless its handler had SA_RESTART. A write of up
//! to {PIPE_BUF} bytes (proto_pipe::ATOMIC) is one message and goes whole;
//! a longer one goes in pieces of proto_pipe::MAX_WRITE bytes, and the
//! count of what went comes back once a signal or O_NONBLOCK stops it
//! after some bytes ([write]).

use crate::constants::*;
use posix_fs::Transport;
use proto_pipe::{Endpoint, MAX_READ, MAX_WRITE, Method};
use proto_wire::{Status, Writer};

/// The errno of a refusal of the pipe service.
fn refusal(status: Status) -> Option<i32> {
    match status.code() {
        proto_pipe::BAD_FD => Some(EBADF),
        proto_pipe::AGAIN => Some(EAGAIN),
        proto_pipe::BROKEN => Some(EPIPE),
        proto_pipe::NFILE => Some(ENFILE),
        proto_pipe::MFILE => Some(EMFILE),
        proto_pipe::INVALID => Some(EINVAL),
        _ => crate::sockets::refusal(status),
    }
}

/// ABANDON through the session `pipes`: the operations of its threads
/// that wait go, as when the session goes. An exec asks it of the session
/// it hands to the new image, whose stopped threads never end their
/// waits; a send that comes back INTERRUPTED goes again, the service
/// never saw it. The reply says nothing more than the session answered.
pub(crate) fn abandon(pipes: rt::abi::Handle) {
    let session = rt::handle::Handle::<rt::handle::Channel>::borrowed(pipes);
    let request = Method::Abandon.header().bytes();
    while rt::sys::send(&session, &request) == Err(rt::abi::Error::Interrupted) {}
}

/// A read of up to `out.len()` bytes (MAX_READ at most) of the read end
/// `end`: the count, 0 at the end of the data.
#[inline(never)]
pub fn read(transport: Transport, end: u32, out: &mut [u8]) -> Result<usize, i32> {
    read_endpoint(transport, Endpoint::anonymous(end), out)
}

pub fn read_endpoint(transport: Transport, end: Endpoint, out: &mut [u8]) -> Result<usize, i32> {
    if out.is_empty() {
        return Ok(0);
    }
    let pipes = transport.pipes().map_err(crate::error)?;
    let count = out.len().min(MAX_READ) as u32;
    let mut start = Writer::new();
    read_request(end, None, count, &mut start).map_err(|_| EIO)?;
    crate::long::run_with(
        &pipes,
        start.as_bytes(),
        |cancel, key, w| {
            if cancel {
                cancel_request(Method::ReadCancel, key, end, w)
            } else {
                read_request(end, Some(key), count, w)
            }
        },
        &mut out[..count as usize],
        &refusal,
    )
}

/// One message of a write: `bytes`, at most MAX_WRITE; the count that
/// went.
#[inline(never)]
fn write_once(
    pipes: &rt::handle::Handle<rt::handle::Channel>,
    end: Endpoint,
    bytes: &[u8],
) -> Result<usize, i32> {
    let mut start = Writer::new();
    write_request(end, None, bytes, &mut start).map_err(|_| EIO)?;
    let mut result = [0; 4];
    let n = crate::long::run_with(
        pipes,
        start.as_bytes(),
        |cancel, key, w| {
            if cancel {
                cancel_request(Method::WriteCancel, key, end, w)
            } else {
                write_request(end, Some(key), bytes, w)
            }
        },
        &mut result,
        &refusal,
    )?;
    let written = proto_pipe::written(&result[..n]).map_err(|_| EIO)? as usize;
    if written > bytes.len() {
        return Err(EIO);
    }
    Ok(written)
}

/// A write of `bytes` to the write end `end`: all of them unless a signal,
/// O_NONBLOCK or the end of the readers stops it after some (their
/// count); EPIPE with no reader before any byte went, which the caller
/// follows with SIGPIPE.
#[inline(never)]
pub fn write(transport: Transport, end: u32, bytes: &[u8]) -> Result<usize, i32> {
    write_endpoint(transport, Endpoint::anonymous(end), bytes)
}

pub fn write_endpoint(transport: Transport, end: Endpoint, bytes: &[u8]) -> Result<usize, i32> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let pipes = transport.pipes().map_err(crate::error)?;
    let limit = if end.is_named() {
        proto_pipe::NAMED_MAX_WRITE
    } else {
        MAX_WRITE
    };
    let mut done = 0;
    while done < bytes.len() {
        let piece = &bytes[done..bytes.len().min(done + limit)];
        match write_once(&pipes, end, piece) {
            Ok(n) => done += n,
            Err(_) if done > 0 => break,
            Err(errno) => return Err(errno),
        }
    }
    Ok(done)
}

/// pipe2's ends: the two numbers of a new pipe's ends in the service.
#[inline(never)]
pub fn create(transport: Transport, nonblock: bool) -> Result<(u32, u32), i32> {
    transport.pipe_create(nonblock).map_err(crate::error)
}

/// F_GETFL of the end `end`: its access mode and O_NONBLOCK.
#[inline(never)]
pub fn status_flags(transport: Transport, end: u32) -> Result<i32, i32> {
    status_flags_endpoint(transport, Endpoint::anonymous(end))
}

pub fn status_flags_endpoint(transport: Transport, end: Endpoint) -> Result<i32, i32> {
    let [flags, _] = transport
        .pipe_endpoint_call(Method::GetFlags, end, None)
        .map_err(crate::error)?;
    let access = if flags & proto_pipe::RDWR != 0 {
        O_RDWR
    } else if flags & proto_pipe::WRITE_END != 0 {
        O_WRONLY
    } else {
        O_RDONLY
    };
    let nonblock = if flags & proto_pipe::NONBLOCK != 0 {
        O_NONBLOCK
    } else {
        0
    };
    let append = if end.is_named() && flags & proto_pipe::APPEND != 0 {
        O_APPEND
    } else {
        0
    };
    Ok(access | nonblock | append)
}

/// F_SETFL of the end `end`: O_NONBLOCK of its description, which every
/// process that holds it shares.
#[inline(never)]
pub fn set_status_flags(transport: Transport, end: u32, flags: i32) -> Result<(), i32> {
    set_status_flags_endpoint(transport, Endpoint::anonymous(end), flags)
}

pub fn set_status_flags_endpoint(
    transport: Transport,
    end: Endpoint,
    flags: i32,
) -> Result<(), i32> {
    let mut word = if flags & O_NONBLOCK != 0 {
        proto_pipe::NONBLOCK
    } else {
        0
    };
    if end.is_named() && flags & O_APPEND != 0 {
        word |= proto_pipe::APPEND;
    }
    transport
        .pipe_endpoint_call(Method::SetFlags, end, Some(word))
        .map(drop)
        .map_err(crate::error)
}

fn read_request(end: Endpoint, key: Option<u64>, count: u32, w: &mut Writer) -> Result<(), Status> {
    key.map_or(Method::ReadStart, |_| Method::ReadTake)
        .header()
        .write(w)?;
    if let Some(key) = key {
        w.u64(key)?;
    }
    end.write(w)?;
    w.u32(count)
}
fn write_request(
    end: Endpoint,
    key: Option<u64>,
    bytes: &[u8],
    w: &mut Writer,
) -> Result<(), Status> {
    key.map_or(Method::WriteStart, |_| Method::WriteTake)
        .header()
        .write(w)?;
    if let Some(key) = key {
        w.u64(key)?;
    }
    end.write(w)?;
    w.bytes(bytes)
}
fn cancel_request(method: Method, key: u64, end: Endpoint, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)?;
    w.u64(key)?;
    end.write(w)
}
