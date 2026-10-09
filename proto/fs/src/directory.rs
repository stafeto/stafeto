// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Descriptor-based directory replies, excluding the outer status word.

use proto_wire::{Reader, Status, Writer};

/// A directory walk may restart while its current child is removed. Each
/// request is bounded by the service's portion; transport errors end the walk.
pub fn directory_walk<R>(mut call: impl FnMut() -> Result<R, Status>) -> Result<R, Status> {
    loop {
        match call() {
            Err(Status::Unknown(crate::RESOLVING)) => {}
            result => return result,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntry<'a> {
    pub kind: u32,
    pub inode: u64,
    pub name: &'a [u8],
}

impl<'a> DirectoryEntry<'a> {
    fn valid(&self) -> bool {
        (1..=3).contains(&self.kind)
            && self.inode != 0
            && !self.name.is_empty()
            && !self.name.contains(&0)
            && !self.name.contains(&b'/')
    }

    pub fn read(input: &mut Reader<'a>) -> Result<Option<Self>, Status> {
        let kind = input.u32()?;
        let inode = input.u64()?;
        let name = input.bytes(input.left())?;
        if kind == 0 {
            return if inode == 0 && name.is_empty() {
                Ok(None)
            } else {
                Err(Status::BadSize)
            };
        }
        let entry = Self { kind, inode, name };
        if entry.valid() {
            Ok(Some(entry))
        } else {
            Err(Status::BadSize)
        }
    }

    pub fn write(entry: Option<Self>, out: &mut Writer) -> Result<(), Status> {
        if entry.is_some_and(|entry| !entry.valid()) {
            return Err(Status::BadSize);
        }
        let (kind, inode, name) = entry.map_or((0, 0, b"".as_slice()), |entry| {
            (entry.kind, entry.inode, entry.name)
        });
        out.u32(kind)?;
        out.u64(inode)?;
        out.bytes(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_walk_survives_restarts_and_preserves_terminal_errors() {
        for terminal in [Ok(19), Err(Status::Unknown(10)), Err(Status::BadSize)] {
            let mut calls = 0;
            let result = directory_walk(|| {
                calls += 1;
                if calls <= 64 {
                    Err(Status::Unknown(crate::RESOLVING))
                } else {
                    terminal
                }
            });
            assert_eq!(calls, 65);
            assert_eq!(result, terminal);
        }
    }

    #[test]
    fn directory_records_preserve_wide_inodes_and_byte_names() {
        let entry = DirectoryEntry {
            kind: 2,
            inode: u64::MAX,
            name: b"raw\xff",
        };
        let mut out = Writer::new();
        DirectoryEntry::write(Some(entry), &mut out).unwrap();
        assert_eq!(&out.as_bytes()[4..12], &u64::MAX.to_le_bytes());
        assert_eq!(
            DirectoryEntry::read(&mut Reader::new(out.as_bytes())),
            Ok(Some(entry))
        );
        let mut end = Writer::new();
        DirectoryEntry::write(None, &mut end).unwrap();
        assert_eq!(
            DirectoryEntry::read(&mut Reader::new(end.as_bytes())),
            Ok(None)
        );
        for length in 0..12 {
            assert_eq!(
                DirectoryEntry::read(&mut Reader::new(&out.as_bytes()[..length])),
                Err(Status::BadSize)
            );
        }
    }

    #[test]
    fn malformed_entries_and_false_end_markers_are_rejected() {
        for (kind, inode, name) in [
            (4, 1, b"a".as_slice()),
            (2, 0, b"a"),
            (2, 1, b""),
            (1, 1, b"a/b"),
            (2, 1, b"a\0b"),
            (0, 1, b""),
            (0, 0, b"a"),
        ] {
            let mut out = Writer::new();
            out.u32(kind).unwrap();
            out.u64(inode).unwrap();
            out.bytes(name).unwrap();
            assert_eq!(
                DirectoryEntry::read(&mut Reader::new(out.as_bytes())),
                Err(Status::BadSize)
            );
        }
    }
}
