// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The exact successful metadata reply of a retained regular image.
#![no_std]
use proto_wire::{Reader, Status};

/// The caller retains the reply handles until this validation completes.
#[inline]
pub fn image_reply_size(bytes: &[u8], handle_count: usize) -> Result<u64, Status> {
    if handle_count != 0 {
        return Err(Status::BadSize);
    }
    let mut reader = Reader::new(bytes);
    let status = reader.u32()?;
    if status != 0 {
        if reader.u32()? != 0 {
            return Err(Status::BadSize);
        }
        reader.finish()?;
        return Err(Status::from_code(status));
    }
    let info = proto_fs::NodeInfo::read(&mut reader)?;
    reader.finish()?;
    if info.kind != 2 {
        return Err(Status::BadSize);
    }
    Ok(info.size)
}

#[cfg(test)]
mod tests {
    use super::*;
    // The timestamp migration expands the typed reply while retaining these metadata offsets.
    const REPLY_BYTES: usize = if proto_fs::VERSION >= 11 { 120 } else { 96 };
    fn regular() -> [u8; REPLY_BYTES] {
        let mut bytes = [0; REPLY_BYTES];
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0o644u32.to_le_bytes());
        bytes[52..60].copy_from_slice(&8177u64.to_le_bytes());
        bytes[60..64].copy_from_slice(&4096u32.to_le_bytes());
        bytes
    }
    #[test]
    fn exact_regular_metadata_returns_its_size() {
        assert_eq!(image_reply_size(&regular(), 0), Ok(8177));
    }
    #[test]
    fn reply_extent_and_caps_are_checked_before_size() {
        let bytes = regular();
        for end in 0..bytes.len() {
            assert_eq!(image_reply_size(&bytes[..end], 0), Err(Status::BadSize));
        }
        let mut trailing = proto_wire::Writer::new();
        trailing.bytes(&bytes).unwrap();
        trailing.u32(0).unwrap();
        assert_eq!(
            image_reply_size(trailing.as_bytes(), 0),
            Err(Status::BadSize)
        );
        for caps in 1..=4 {
            assert_eq!(image_reply_size(&bytes, caps), Err(Status::BadSize));
        }
    }
    #[test]
    fn error_reply_has_exact_zero_reserved_shape() {
        for code in [501u32, 313, 319] {
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&code.to_le_bytes());
            assert_eq!(image_reply_size(&bytes, 0), Err(Status::from_code(code)));
            assert_eq!(image_reply_size(&bytes[..4], 0), Err(Status::BadSize));
            assert_eq!(image_reply_size(&bytes, 1), Err(Status::BadSize));
            bytes[4] = 1;
            assert_eq!(image_reply_size(&bytes, 0), Err(Status::BadSize));
        }
    }
    #[test]
    fn image_kind_and_typed_metadata_reject_invalid_inputs() {
        for (offset, value) in [(4usize, 1u32), (4, 3), (4, 4), (8, 0o10000), (60, 0)] {
            let mut bytes = regular();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(image_reply_size(&bytes, 0), Err(Status::BadSize));
        }
        for code in [1u32, 501, 0xffff_ffff] {
            let mut bytes = regular();
            bytes[..4].copy_from_slice(&code.to_le_bytes());
            assert_eq!(image_reply_size(&bytes, 0), Err(Status::BadSize));
        }
    }
}
