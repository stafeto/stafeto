// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Lock receipts and service statuses fit the immutable inline register envelope.

use super::{EIO, Failure, inline_abi as abi};

pub(super) struct InlineReply {
    bytes: [u8; abi::INLINE_MAX],
    length: usize,
}
impl InlineReply {
    pub(super) fn read(words: &[u64; 8], length: usize) -> Result<Self, Failure> {
        if length > abi::INLINE_MAX {
            return Err(Failure::Fatal(EIO));
        }
        Ok(Self {
            bytes: abi::inline_bytes(words),
            length,
        })
    }
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
