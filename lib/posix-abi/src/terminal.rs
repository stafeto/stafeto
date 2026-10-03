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
use proto_tty::{CONSOLE, Cancel, MAX_READ, MAX_WRITE, Method, Read, Write};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Handle};

const ENOTTY: i32 = 25;

/// The errno of a refusal of the terminal service.
fn refusal(status: Status) -> Option<i32> {
    match status.code() {
        proto_tty::BAD_TERMINAL => Some(ENOTTY),
        proto_tty::INVALID => Some(EINVAL),
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

/// A read of up to `out.len()` bytes (MAX_READ at most) of the console:
/// the count, 0 at an end-of-file.
#[inline(never)]
pub fn read(transport: Transport, out: &mut [u8]) -> Result<usize, i32> {
    if out.is_empty() {
        return Ok(0);
    }
    let terminal = transport.terminal().ok_or(EBADF)?;
    let count = out.len().min(MAX_READ) as u32;
    let mut start = Writer::new();
    Read {
        key: None,
        terminal: CONSOLE,
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
                    terminal: CONSOLE,
                }
                .write(Method::ReadCancel, w)
            } else {
                Read {
                    key: Some(key),
                    terminal: CONSOLE,
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
fn write_once(terminal: &Handle<Channel>, bytes: &[u8]) -> Result<usize, i32> {
    let mut start = Writer::new();
    Write {
        key: None,
        terminal: CONSOLE,
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
                    terminal: CONSOLE,
                }
                .write(Method::WriteCancel, w)
            } else {
                Write {
                    key: Some(key),
                    terminal: CONSOLE,
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

/// A write of `bytes` to the console: all of them unless a signal stops it
/// after some (their count).
#[inline(never)]
pub fn write(transport: Transport, bytes: &[u8]) -> Result<usize, i32> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let terminal = transport.terminal().ok_or(EBADF)?;
    let mut done = 0;
    while done < bytes.len() {
        let piece = &bytes[done..bytes.len().min(done + MAX_WRITE)];
        match write_once(&terminal, piece) {
            Ok(n) => done += n,
            Err(_) if done > 0 => break,
            Err(errno) => return Err(errno),
        }
    }
    Ok(done)
}
