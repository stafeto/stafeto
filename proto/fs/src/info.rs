// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Complete node information transported independently of a C structure layout.

use crate::Timestamp;
use proto_wire::{Reader, Status, Writer};

/// Kind is 1 directory, 2 regular, 3 character, 5 symbolic link. Permissions contain only the
/// low twelve mode bits. Times use signed seconds and normalized nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeInfo {
    pub kind: u32,
    pub permissions: u32,
    pub device: u64,
    pub special_device: u64,
    pub inode: u64,
    pub links: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub block_size: u32,
    pub blocks: u64,
    pub access_time: Timestamp,
    pub modify_time: Timestamp,
    pub change_time: Timestamp,
}

impl NodeInfo {
    pub fn write(&self, out: &mut Writer) -> Result<(), Status> {
        out.u32(self.kind)?;
        out.u32(self.permissions)?;
        out.u64(self.device)?;
        out.u64(self.special_device)?;
        out.u64(self.inode)?;
        out.u64(self.links)?;
        out.u32(self.uid)?;
        out.u32(self.gid)?;
        out.u64(self.size)?;
        out.u32(self.block_size)?;
        out.u64(self.blocks)?;
        self.access_time.write(out)?;
        self.modify_time.write(out)?;
        self.change_time.write(out)
    }

    pub fn read(input: &mut Reader<'_>) -> Result<Self, Status> {
        let info = Self {
            kind: input.u32()?,
            permissions: input.u32()?,
            device: input.u64()?,
            special_device: input.u64()?,
            inode: input.u64()?,
            links: input.u64()?,
            uid: input.u32()?,
            gid: input.u32()?,
            size: input.u64()?,
            block_size: input.u32()?,
            blocks: input.u64()?,
            access_time: Timestamp::read(input)?,
            modify_time: Timestamp::read(input)?,
            change_time: Timestamp::read(input)?,
        };
        if !matches!(info.kind, 1 | 2 | 3 | 5)
            || info.permissions & !0o7777 != 0
            || info.block_size == 0
        {
            return Err(Status::BadSize);
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn information_wire_roundtrip_truncation_and_validation() {
        let info = NodeInfo {
            kind: 3,
            permissions: 0o7777,
            device: 1 << 40,
            special_device: 2 << 40,
            inode: 3 << 40,
            links: 4 << 40,
            uid: 5,
            gid: 6,
            size: 7 << 40,
            block_size: 512,
            blocks: 8 << 40,
            access_time: Timestamp::new(i64::MIN, 1).unwrap(),
            modify_time: Timestamp::new(-1, 2).unwrap(),
            change_time: Timestamp::new(i64::MAX, 999_999_999).unwrap(),
        };
        let mut writer = Writer::new();
        info.write(&mut writer).unwrap();
        let bytes = writer.as_bytes();
        assert_eq!(bytes.len(), 116);
        assert_eq!(&bytes[8..16], &info.device.to_le_bytes());
        assert_eq!(&bytes[100..108], &info.change_time.seconds.to_le_bytes());
        let mut reader = Reader::new(bytes);
        assert_eq!(NodeInfo::read(&mut reader), Ok(info));
        assert_eq!(reader.finish(), Ok(()));
        for end in 0..bytes.len() {
            assert_eq!(
                NodeInfo::read(&mut Reader::new(&bytes[..end])),
                Err(Status::BadSize)
            );
        }
        for (offset, value) in [(0, 4u32), (4, 0o10000), (56, 0)] {
            let mut invalid = [0; 116];
            invalid.copy_from_slice(bytes);
            invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                NodeInfo::read(&mut Reader::new(&invalid)),
                Err(Status::BadSize)
            );
        }
        writer.u32(0).unwrap();
        let mut reader = Reader::new(writer.as_bytes());
        NodeInfo::read(&mut reader).unwrap();
        assert_eq!(reader.finish(), Err(Status::BadSize));
    }
}
