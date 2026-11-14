// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Output through debug_write (spec 11). A program gives its handle to
//! the system resource with DEBUG once (`set`); `write`, `write_fmt`,
//! `print!` and `println!` then send what they get in pieces of at most
//! abi::INLINE_MAX bytes, one call per piece. A line of up to 64 bytes,
//! its newline included, is never split between calls, whatever text
//! comes with it in one `write`, so lines of threads and processes do not
//! mix. A longer line goes in tagged pieces of console_line::PAYLOAD
//! bytes (console_line): the console's driver puts them out as one line
//! once its last piece comes, however the pieces of other writers lie
//! between them.

use crate::handle::{Handle, Resource};
use crate::sys;
use abi::{Error, INLINE_MAX};
use console_line::PAYLOAD;
use core::fmt;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU64, Ordering};

/// The handle output goes through; abi::Handle::INVALID until `set`.
static CONSOLE: AtomicU64 = AtomicU64::new(abi::Handle::INVALID.0);

/// Output goes through `resource` from now on: the console owns it until
/// the process ends, so a panic can print whatever the program closed. A
/// handle an earlier call set stays open.
pub fn set(resource: Handle<Resource>) {
    CONSOLE.store(resource.into_raw().0, Ordering::Relaxed);
}

/// Output goes nowhere until the next `set`, and the handle `set` gave
/// goes without a close: in a forked child its value is the parent's,
/// which names nothing of the child's.
pub fn forget() {
    CONSOLE.store(abi::Handle::INVALID.0, Ordering::Relaxed);
}

/// A view of the handle `set` gave; BAD_HANDLE before it.
fn resource() -> Result<ManuallyDrop<Handle<Resource>>, Error> {
    match abi::Handle(CONSOLE.load(Ordering::Relaxed)) {
        abi::Handle::INVALID => Err(Error::BadHandle),
        h => Ok(Handle::borrowed(h)),
    }
}

/// The length of the piece that starts `bytes` (not empty): the lines
/// that fit whole in abi::INLINE_MAX bytes; 0 when the first line is longer.
fn piece_len(bytes: &[u8]) -> usize {
    let mut len = 0;
    for line in bytes.split_inclusive(|&b| b == b'\n') {
        if len + line.len() > INLINE_MAX {
            break;
        }
        len += line.len();
    }
    len
}

/// A new identifier for a line that goes in tagged pieces.
fn line_id() -> u32 {
    console_line::id_from(crate::time::now())
}

/// Sends the tagged pieces of `line` (the text of one line, or the tail of
/// one) as the line `id`: the first piece carries the mark of the start when
/// `first` (the line has no piece sent yet), the last the mark of the end.
fn send_tagged(
    resource: &Handle<Resource>,
    id: u32,
    mut line: &[u8],
    mut first: bool,
) -> Result<(), Error> {
    let mut out = [0; INLINE_MAX];
    loop {
        let n = line.len().min(PAYLOAD);
        let (now, rest) = line.split_at(n);
        let len = if first {
            console_line::first_piece(id, now, &mut out)
        } else {
            console_line::piece(id, rest.is_empty(), now, &mut out)
        };
        first = false;
        sys::debug_write(resource, &out[..len])?;
        if rest.is_empty() {
            return Ok(());
        }
        line = rest;
    }
}

/// Writes `bytes` in pieces of at most abi::INLINE_MAX that cut no line
/// of up to abi::INLINE_MAX bytes, a longer line in tagged pieces; stops
/// at the first call that fails.
pub fn write(mut bytes: &[u8]) -> Result<(), Error> {
    let resource = resource()?;
    while !bytes.is_empty() {
        let n = piece_len(bytes);
        if n == 0 {
            let end = bytes
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |i| i + 1);
            let (line, rest) = bytes.split_at(end);
            send_tagged(&resource, line_id(), line, true)?;
            bytes = rest;
        } else {
            let (piece, rest) = bytes.split_at(n);
            sys::debug_write(&resource, piece)?;
            bytes = rest;
        }
    }
    Ok(())
}

/// Formats `args` into pieces of at most abi::INLINE_MAX bytes and writes
/// each as it fills or as a line ends; stops writing at the first call that fails.
pub fn write_fmt(args: fmt::Arguments<'_>) -> Result<(), Error> {
    let mut pieces = Pieces {
        resource: resource()?,
        buf: [0; INLINE_MAX],
        len: 0,
        line: None,
        error: None,
    };
    // A formatting error that no failed call caused comes from a Display
    // implementation; what it formatted goes out all the same.
    let _ = fmt::write(&mut pieces, args);
    pieces.flush();
    pieces.error.map_or(Ok(()), Err)
}

/// Formatted bytes on their way out, a piece at a time.
struct Pieces {
    resource: ManuallyDrop<Handle<Resource>>,
    buf: [u8; INLINE_MAX],
    len: usize,
    /// The identifier of the line that goes in tagged pieces, once the
    /// line is longer than abi::INLINE_MAX bytes.
    line: Option<u32>,
    /// The first call that failed; nothing is written after it.
    error: Option<Error>,
}

impl Pieces {
    /// Sends the bytes the buffer holds: a line that fits, as one call; the
    /// tail of a long line, as its last pieces.
    fn flush(&mut self) {
        let (len, line) = (self.len, self.line.take());
        self.len = 0;
        if (len == 0 && line.is_none()) || self.error.is_some() {
            return;
        }
        let result = match line {
            None => sys::debug_write(&self.resource, &self.buf[..len]).map(|_| ()),
            Some(id) => send_tagged(&self.resource, id, &self.buf[..len], false),
        };
        if let Err(e) = result {
            self.error = Some(e);
        }
    }

    /// The buffer is full and a byte more comes: the line is longer than a
    /// call holds, and goes in tagged pieces from here. The first
    /// PAYLOAD bytes go out and the rest stay.
    fn spill(&mut self) {
        if self.error.is_some() {
            self.len = 0;
            return;
        }
        let opens = self.line.is_none();
        let id = *self.line.get_or_insert_with(line_id);
        let mut out = [0; INLINE_MAX];
        let len = if opens {
            console_line::first_piece(id, &self.buf[..PAYLOAD], &mut out)
        } else {
            console_line::piece(id, false, &self.buf[..PAYLOAD], &mut out)
        };
        if let Err(e) = sys::debug_write(&self.resource, &out[..len]) {
            self.error = Some(e);
        }
        self.buf.copy_within(PAYLOAD..INLINE_MAX, 0);
        self.len = INLINE_MAX - PAYLOAD;
    }
}

impl fmt::Write for Pieces {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == INLINE_MAX {
                self.spill();
            }
            self.buf[self.len] = b;
            self.len += 1;
            if b == b'\n' {
                self.flush();
            }
        }
        if self.error.is_some() {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}
