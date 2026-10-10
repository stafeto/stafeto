// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Status-only ChangeRelease replies without a message-sized copy.

use proto_wire::{Reader, Status};

pub(super) fn read(words: &[u64; 8], length: usize, handles: usize) -> Result<(), Status> {
    if handles != 0 || length > abi::INLINE_MAX {
        return Err(Status::BadSize);
    }
    let bytes = abi::inline_bytes(words);
    let mut input = Reader::new(&bytes[..length]);
    match Status::from_code(input.u32()?) {
        Status::Ok => {
            if input.u32()? != 0 {
                return Err(Status::BadSize);
            }
            input.finish()
        }
        status => Err(status),
    }
}
