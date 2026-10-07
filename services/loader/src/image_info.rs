// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
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

/// Only the canonical own Process NOT_FOUND permits the initial-image fork path.
pub fn fork_source_reply(
    bytes: &[u8],
    handles: usize,
    cap: Option<(abi::ObjectKind, abi::Rights)>,
) -> Result<bool, Status> {
    let mut r = Reader::new(bytes);
    let status = r.u32()?;
    if status == 0 {
        r.finish()?;
        let rights = abi::Rights::SEND | abi::Rights::DUPLICATE | abi::Rights::TRANSFER;
        if handles != 1
            || !matches!(cap, Some((abi::ObjectKind::Channel, got)) if got.contains(rights))
        {
            return Err(Status::BadSize);
        }
        return Ok(true);
    }
    if r.u32()? != 0 || handles != 0 {
        return Err(Status::BadSize);
    }
    r.finish()?;
    if status == proto_process::NOT_FOUND {
        Ok(false)
    } else {
        Err(Status::from_code(status))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CloneImageProgress {
    Continue,
    Authenticate,
    Ready,
}
/// A retained image success has exactly one channel; progress/error has none.
pub fn clone_image_reply(
    bytes: &[u8],
    handles: usize,
    cap: Option<(abi::ObjectKind, abi::Rights)>,
) -> Result<CloneImageProgress, Status> {
    let mut r = Reader::new(bytes);
    let status = r.u32()?;
    if status == 0 {
        r.finish()?;
        let rights = abi::Rights::SEND | abi::Rights::TRANSFER;
        if handles != 1
            || !matches!(cap, Some((abi::ObjectKind::Channel, got)) if got.contains(rights))
        {
            return Err(Status::BadSize);
        }
        return Ok(CloneImageProgress::Ready);
    }
    if r.u32()? != 0 || handles != 0 {
        return Err(Status::BadSize);
    }
    r.finish()?;
    match status {
        proto_fs::RESOLVING => Ok(CloneImageProgress::Continue),
        proto_fs::AUTHENTICATING => Ok(CloneImageProgress::Authenticate),
        _ => Err(Status::from_code(status)),
    }
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

#[cfg(test)]
mod fork_reply_tests {
    use super::*;
    use abi::{ObjectKind, Rights};
    fn error(code: u32) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&code.to_le_bytes());
        bytes
    }
    #[test]
    fn initial_fork_requires_exact_not_found_and_retained_source_requires_duplicate_right() {
        let none = error(proto_process::NOT_FOUND);
        assert_eq!(fork_source_reply(&none, 0, None), Ok(false));
        for (bytes, count) in [(&none[..4], 0), (&none[..], 1), (&[0; 8][..], 1)] {
            assert_eq!(fork_source_reply(bytes, count, None), Err(Status::BadSize));
        }
        let mut bad = none;
        bad[4] = 1;
        assert_eq!(fork_source_reply(&bad, 0, None), Err(Status::BadSize));
        assert_eq!(
            fork_source_reply(&error(proto_process::PERMISSION), 0, None),
            Err(Status::from_code(proto_process::PERMISSION))
        );
        let full = Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER;
        assert_eq!(
            fork_source_reply(&[0; 4], 1, Some((ObjectKind::Channel, full))),
            Ok(true)
        );
        for cap in [
            (ObjectKind::Memory, full),
            (ObjectKind::Channel, Rights::SEND | Rights::TRANSFER),
        ] {
            assert_eq!(
                fork_source_reply(&[0; 4], 1, Some(cap)),
                Err(Status::BadSize)
            );
        }
    }
    #[test]
    fn clone_progress_preserves_ambiguity_and_rejects_extra_caps_reserved_words_and_trailing_bytes()
    {
        assert_eq!(
            clone_image_reply(&error(proto_fs::RESOLVING), 0, None),
            Ok(CloneImageProgress::Continue)
        );
        assert_eq!(
            clone_image_reply(&error(proto_fs::AUTHENTICATING), 0, None),
            Ok(CloneImageProgress::Authenticate)
        );
        assert_eq!(
            clone_image_reply(&error(proto_fs::IMAGE_ABORT_REQUIRED), 0, None),
            Err(Status::from_code(proto_fs::IMAGE_ABORT_REQUIRED))
        );
        let cap = Some((ObjectKind::Channel, Rights::SEND | Rights::TRANSFER));
        assert_eq!(
            clone_image_reply(&[0; 4], 1, cap),
            Ok(CloneImageProgress::Ready)
        );
        for (bytes, n) in [
            (&[0; 4][..], 0),
            (&[0; 8][..], 1),
            (&[0; 4][..], 2),
            (&error(proto_fs::RESOLVING)[..], 1),
        ] {
            assert_eq!(clone_image_reply(bytes, n, cap), Err(Status::BadSize));
        }
        let mut bad = error(proto_fs::RESOLVING);
        bad[4] = 1;
        assert_eq!(clone_image_reply(&bad, 0, None), Err(Status::BadSize));
    }
}
