// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Output through debug_write (spec 11). A program gives its handle to
//! the system resource with DEBUG once (`set`); `write`, `write_fmt`,
//! `print!` and `println!` then send what they get in pieces of at most
//! abi::INLINE_MAX bytes, one call per piece. A line of up to 64 bytes,
//! its newline included, is one call, so lines of threads do not mix.

use crate::handle::{Handle, Resource};
use crate::sys;
use abi::{Error, INLINE_MAX};
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

/// A view of the handle `set` gave; BAD_HANDLE before it.
fn resource() -> Result<ManuallyDrop<Handle<Resource>>, Error> {
    match abi::Handle(CONSOLE.load(Ordering::Relaxed)) {
        abi::Handle::INVALID => Err(Error::BadHandle),
        h => Ok(Handle::borrowed(h)),
    }
}

/// Writes `bytes` in pieces of at most abi::INLINE_MAX; stops at the
/// first call that fails.
pub fn write(bytes: &[u8]) -> Result<(), Error> {
    let resource = resource()?;
    for piece in bytes.chunks(INLINE_MAX) {
        sys::debug_write(&resource, piece)?;
    }
    Ok(())
}

/// Formats `args` into pieces of at most abi::INLINE_MAX bytes and writes
/// each as it fills; stops writing at the first call that fails.
pub fn write_fmt(args: fmt::Arguments<'_>) -> Result<(), Error> {
    let mut pieces = Pieces {
        resource: resource()?,
        buf: [0; INLINE_MAX],
        len: 0,
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
    /// The first call that failed; nothing is written after it.
    error: Option<Error>,
}

impl Pieces {
    fn flush(&mut self) {
        if self.len > 0
            && self.error.is_none()
            && let Err(e) = sys::debug_write(&self.resource, &self.buf[..self.len])
        {
            self.error = Some(e);
        }
        self.len = 0;
    }
}

impl fmt::Write for Pieces {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == INLINE_MAX {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        if self.error.is_some() {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}
