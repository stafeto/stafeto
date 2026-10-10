// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#[path = "../../lib/rt/src/fs/change_release_reply.rs"]
mod reply;

use proto_wire::Status;

fn words(code: u32, reserved: u32) -> [u64; 8] {
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&code.to_le_bytes());
    bytes[4..].copy_from_slice(&reserved.to_le_bytes());
    abi::inline_words(&bytes)
}

#[test]
fn release_success_requires_exact_zero_reserved_status() {
    let good = words(0, 0);
    assert_eq!(reply::read(&good, 8, 0), Ok(()));
    for length in [0, 3, 4, 7, 9, 64, 65, abi::MESSAGE_MAX] {
        assert_eq!(reply::read(&good, length, 0), Err(Status::BadSize));
    }
    assert_eq!(reply::read(&words(0, 1), 8, 0), Err(Status::BadSize));
    assert_eq!(reply::read(&good, 8, 1), Err(Status::BadSize));
}

#[test]
fn release_error_preserves_existing_first_word_mapping() {
    for code in [
        proto_fs::AUTHENTICATING,
        proto_fs::RESOLVING,
        proto_fs::JOBS_FULL,
        123456,
    ] {
        for length in [4, 8, 64] {
            assert_eq!(
                reply::read(&words(code, 42), length, 0),
                Err(Status::from_code(code))
            );
        }
        assert_eq!(reply::read(&words(code, 0), 65, 0), Err(Status::BadSize));
        assert_eq!(reply::read(&words(code, 0), 8, 1), Err(Status::BadSize));
    }
}
