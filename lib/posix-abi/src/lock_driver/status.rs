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

    #[test]
    fn actual_lock_transient_and_retired_status_codes_survive_the_wire_header() {
        for code in [
            proto_fs::AUTHENTICATING,
            proto_fs::JOBS_FULL,
            proto_fs::OPEN_RETIRED,
        ] {
            let bytes = proto_wire::reply(Status::Unknown(code));
            assert_eq!(read(&bytes), Ok(code));
        }
    }

    #[test]
    fn malformed_reserved_error_header_is_not_a_canonical_remote_refusal() {
        for code in [
            proto_fs::AUTHENTICATING,
            proto_fs::JOBS_FULL,
            proto_fs::OPEN_RETIRED,
        ] {
            let mut bytes = proto_wire::reply(Status::Unknown(code));
            bytes[4..].copy_from_slice(&1u32.to_le_bytes());
            assert_eq!(read(&bytes), Err(Status::BadSize));
        }
    }

    #[test]
    fn refused_reply_requires_the_whole_header_and_no_trailing_bytes() {
        let bytes = proto_wire::reply(Status::Unknown(proto_fs::JOBS_FULL));
        for length in 0..bytes.len() {
            assert_eq!(read(&bytes[..length]), Err(Status::BadSize));
        }
        let mut extended = [0; proto_wire::HEADER_LEN + 1];
        extended[..proto_wire::HEADER_LEN].copy_from_slice(&bytes);
        assert_eq!(read(&extended), Err(Status::BadSize));
    }
}
