// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The fixed inline envelope of init's successful ADOPT reply.

use proto_init::Adoption;
use proto_wire::Status;

/// Checks the actual envelope before decoding the complete inline body.
/// The two channels remain owned by the caller until this succeeds.
pub fn read(len: usize, bytes: &[u8; 64], handles: usize) -> Result<Adoption, Status> {
    if len != bytes.len() || handles != 2 {
        return Err(Status::BadSize);
    }
    Adoption::read(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_init::InitialSource;
    use proto_wire::{Name, Writer};

    fn valid() -> (Adoption, [u8; 64]) {
        let adoption = Adoption {
            source: InitialSource {
                artifact: 5,
                raw: 12,
                canonical: Some(3),
            },
            ticket: 123,
            quota: 512 * 4096,
            handle_limit: 32,
            ceiling: 31,
            priority: 30,
            root: true,
            program: Name::new(b"posix-probe").unwrap(),
        };
        let mut w = Writer::new();
        adoption.write(&mut w).unwrap();
        (adoption, w.as_bytes().try_into().unwrap())
    }

    #[test]
    fn requires_actual_length_and_exactly_two_channels() {
        let (adoption, bytes) = valid();
        assert_eq!(read(64, &bytes, 2), Ok(adoption));
        for len in (0..64).chain([65, 1024, usize::MAX]) {
            assert_eq!(read(len, &bytes, 2), Err(Status::BadSize));
        }
        for caps in [0, 1, 3, 4, usize::MAX] {
            assert_eq!(read(64, &bytes, caps), Err(Status::BadSize));
        }
    }

    #[test]
    fn preserves_source_reserved_and_refusal_checks() {
        let (_, bytes) = valid();
        for (offset, value) in [(0, 1), (4, 1), (31, 1), (60, 1)] {
            let mut bad = bytes;
            bad[offset] = value;
            assert_eq!(read(64, &bad, 2), Err(Status::BadSize));
        }
        for offset in [48, 52, 56] {
            let mut bad = bytes;
            bad[offset..offset + 4].copy_from_slice(&1024_u32.to_le_bytes());
            assert_eq!(read(64, &bad, 2), Err(Status::BadSize));
        }
        let mut bad = bytes;
        bad[52..56].copy_from_slice(&5_u32.to_le_bytes());
        assert_eq!(read(64, &bad, 2), Err(Status::BadSize));
    }
}
