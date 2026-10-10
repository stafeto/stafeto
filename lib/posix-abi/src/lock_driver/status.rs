// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Status replies use the shared eight-byte header with a zero reserved word.

use proto_wire::{Reader, Status};

pub fn read(bytes: &[u8]) -> Result<u32, Status> {
    let mut body = Reader::new(bytes);
    let code = body.u32()?;
    if body.u32()? != 0 {
        return Err(Status::BadSize);
    }
    body.finish()?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_status_encoder_roundtrips_success_and_remote_refusals() {
        for status in [Status::Ok, Status::Unknown(310), Status::BadSize] {
            assert_eq!(read(&proto_wire::reply(status)), Ok(status.code()));
        }
    }

    #[test]
    fn status_requires_the_reserved_zero_and_exact_eight_byte_extent() {
        assert_eq!(read(&[0; 4]), Err(Status::BadSize));
        assert_eq!(read(&[0; 12]), Err(Status::BadSize));
        let mut bytes = proto_wire::reply(Status::Ok);
        bytes[4] = 1;
        assert_eq!(read(&bytes), Err(Status::BadSize));
    }
}
