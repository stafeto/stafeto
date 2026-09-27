// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Text the shell puts together before one WRITE: bytes and formatted
//! pieces into a buffer of N bytes, which keeps its first N and drops the
//! rest.

use core::fmt;

/// The bytes of one WRITE at most.
pub const WRITE_MAX: usize = proto_uart::WRITE_MAX;

/// A buffer of N bytes of text.
pub struct Text<const N: usize = WRITE_MAX> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Text<N> {
    pub const fn new() -> Text<N> {
        Text {
            bytes: [0; N],
            len: 0,
        }
    }

    /// Adds `bytes`, those that fit.
    pub fn put(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(N - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<const N: usize> Default for Text<N> {
    fn default() -> Text<N> {
        Text::new()
    }
}

impl<const N: usize> fmt::Write for Text<N> {
    /// Adds what fits; an error once something did not.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let fits = s.len() <= N - self.len;
        self.put(s.as_bytes());
        if fits { Ok(()) } else { Err(fmt::Error) }
    }
}
