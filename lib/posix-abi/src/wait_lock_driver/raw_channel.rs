// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Pure decoders shared by exact private-channel syscalls and host tests.
use super::{Error, Source};

pub fn close_result(code: u64) -> Result<(), Error> {
    match Error::from_code(code) {
        None | Some(Error::BadHandle) => Ok(()),
        Some(error) => Err(error),
    }
}
pub fn duplicate_result(words: &[u64; 10]) -> Result<u64, Error> {
    match Error::from_code(words[0]) {
        None => Ok(words[1]),
        Some(error) => Err(error),
    }
}
pub fn receive_result(words: &[u64; 10]) -> Result<(), Error> {
    if let Some(error) = Error::from_code(words[0]) {
        return Err(error);
    }
    // Source is x1 bits24..27; x10 label is unavailable and deliberately unused.
    if Source::from_code((words[1] >> 24) & 0xf) == Source::Message {
        Err(Error::BadState)
    } else {
        Ok(())
    }
}
