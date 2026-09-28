// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Complete node information transported independently of a C structure layout.

use proto_wire::{Reader, Status, Writer};

/// Kind is 1 directory, 2 regular, 3 character. Permissions contain only the
/// low twelve mode bits. Times are nanoseconds on the file service's clock.
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
    pub access_ns: u64,
    pub modify_ns: u64,
    pub change_ns: u64,
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
        out.u64(self.access_ns)?;
        out.u64(self.modify_ns)?;
        out.u64(self.change_ns)
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
            access_ns: input.u64()?,
            modify_ns: input.u64()?,
            change_ns: input.u64()?,
        };
        if !(1..=3).contains(&info.kind) || info.permissions & !0o7777 != 0 || info.block_size == 0
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
            access_ns: 9 << 40,
            modify_ns: 10 << 40,
            change_ns: u64::MAX,
        };
        let mut writer = Writer::new();
        info.write(&mut writer).unwrap();
        let bytes = writer.as_bytes();
        assert_eq!(bytes.len(), 92);
        assert_eq!(&bytes[8..16], &info.device.to_le_bytes());
        assert_eq!(&bytes[84..92], &info.change_ns.to_le_bytes());
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
            let mut invalid = [0; 92];
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
