// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact backend identity accompanies every published RAM descriptor.

use core::num::NonZeroU64;
use rt::fs::PreparedOpen;

use super::{FileKind, FsError};

/// The numeric mapping and the complete open-description lifetime.
#[derive(Clone, Copy, Debug)]
pub struct RamTarget {
    packed: u32,
    generation: NonZeroU64,
}

// These bits belong only to the local target, never to a native message.
const KIND_SHIFT: u32 = 16;
const KIND_MASK: u32 = 7 << KIND_SHIFT;
const _: () = {
    assert!(core::mem::size_of::<RamTarget>() == 16);
    assert!(KIND_MASK & proto_fs::OPEN_RESULT_MASK == 0);
};

impl PartialEq for RamTarget {
    fn eq(&self, other: &Self) -> bool {
        // Cached metadata does not change exact backend identity.
        self.fd() == other.fd()
            && self.description_slot() == other.description_slot()
            && self.generation == other.generation
    }
}
impl Eq for RamTarget {}

impl RamTarget {
    /// Accept a strictly decoded native result before local publication.
    pub fn from_prepared(held: PreparedOpen) -> Result<Self, FsError> {
        if !(3..35).contains(&held.fd) || held.slot >= 128 {
            return Err(FsError::Io);
        }
        Ok(Self {
            packed: held.fd | (held.slot << proto_fs::OPEN_DESCRIPTION_SHIFT),
            generation: NonZeroU64::new(held.generation).ok_or(FsError::Io)?,
        })
    }

    /// A file's type stays fixed throughout this exact description's lifetime.
    pub(crate) fn with_kind(mut self, kind: FileKind) -> Self {
        let tag = match kind {
            FileKind::Directory => 1,
            FileKind::Regular => 2,
            FileKind::Character => 3,
            FileKind::Fifo => 4,
        };
        self.packed = (self.packed & !KIND_MASK) | (tag << KIND_SHIFT);
        self
    }

    /// Unknown targets cannot authorize a successful synchronization.
    pub fn kind(self) -> Result<FileKind, FsError> {
        match (self.packed & KIND_MASK) >> KIND_SHIFT {
            1 => Ok(FileKind::Directory),
            2 => Ok(FileKind::Regular),
            3 => Ok(FileKind::Character),
            4 => Ok(FileKind::Fifo),
            _ => Err(FsError::Io),
        }
    }

    pub fn fd(self) -> u32 {
        self.packed & proto_fs::OPEN_FD_MASK
    }

    pub fn description_slot(self) -> u32 {
        (self.packed & proto_fs::OPEN_DESCRIPTION_MASK) >> proto_fs::OPEN_DESCRIPTION_SHIFT
    }

    pub fn generation(self) -> u64 {
        self.generation.get()
    }

    /// ExactClone and CloseExact share this identity without a type marker.
    pub fn prepared(self) -> PreparedOpen {
        PreparedOpen {
            fd: self.fd(),
            slot: self.description_slot(),
            generation: self.generation(),
            random: false,
        }
    }
}

/// Paired RAM metadata and pipe data custody of one named FIFO descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FifoTarget {
    packed: u32,
    ram_generation: NonZeroU64,
    pipe_generation: NonZeroU64,
}
const _: () = assert!(core::mem::size_of::<FifoTarget>() == 24);
impl FifoTarget {
    pub fn new(ram: RamTarget, endpoint: proto_pipe::Endpoint) -> Result<Self, FsError> {
        let slot = endpoint.id & !proto_pipe::NAMED_END;
        if ram.kind()? != FileKind::Fifo || endpoint.id & proto_pipe::NAMED_END == 0 || slot >= 128
        {
            return Err(FsError::Io);
        }
        Ok(Self {
            packed: ram.fd() | (ram.description_slot() << 8) | (slot << 15),
            ram_generation: ram.generation,
            pipe_generation: NonZeroU64::new(endpoint.generation).ok_or(FsError::Io)?,
        })
    }
    pub fn from_packed(
        packed: u32,
        ram_generation: u64,
        pipe_generation: u64,
    ) -> Result<Self, FsError> {
        if packed & !0x003fff3f != 0 {
            return Err(FsError::Io);
        }
        let ram = RamTarget::from_prepared(PreparedOpen {
            fd: packed & 63,
            slot: (packed >> 8) & 127,
            generation: ram_generation,
            random: false,
        })?
        .with_kind(FileKind::Fifo);
        Self::new(
            ram,
            proto_pipe::Endpoint {
                id: proto_pipe::NAMED_END | ((packed >> 15) & 127),
                generation: pipe_generation,
            },
        )
    }
    pub fn packed(self) -> u32 {
        self.packed
    }
    pub fn ram(self) -> RamTarget {
        RamTarget {
            packed: (self.packed & 0x7f3f) | (4 << KIND_SHIFT),
            generation: self.ram_generation,
        }
    }
    pub fn endpoint(self) -> proto_pipe::Endpoint {
        proto_pipe::Endpoint {
            id: proto_pipe::NAMED_END | ((self.packed >> 15) & 127),
            generation: self.pipe_generation.get(),
        }
    }
    pub fn ram_generation(self) -> u64 {
        self.ram_generation.get()
    }
    pub fn pipe_generation(self) -> u64 {
        self.pipe_generation.get()
    }
}

#[cfg(test)]
mod fifo_tests {
    use super::*;
    fn ram(kind: FileKind, generation: u64) -> RamTarget {
        RamTarget::from_prepared(PreparedOpen {
            fd: 34,
            slot: 127,
            generation,
            random: false,
        })
        .unwrap()
        .with_kind(kind)
    }
    #[test]
    fn paired_identity_preserves_both_full_generations_at_slot_boundaries() {
        let a = FifoTarget::new(
            ram(FileKind::Fifo, 0x1234567800000001),
            proto_pipe::Endpoint::named(127, 0xabcdef1200000001),
        )
        .unwrap();
        assert_eq!(a.ram().fd(), 34);
        assert_eq!(a.ram().description_slot(), 127);
        assert_eq!(a.ram_generation(), 0x1234567800000001);
        assert_eq!(
            a.endpoint(),
            proto_pipe::Endpoint::named(127, 0xabcdef1200000001)
        );
        assert_eq!(a.ram().kind(), Ok(FileKind::Fifo));
        assert_eq!(
            FifoTarget::from_packed(a.packed(), a.ram_generation(), a.pipe_generation()),
            Ok(a)
        );
        let b =
            FifoTarget::from_packed(a.packed(), a.ram_generation(), 0xabcdef1300000001).unwrap();
        assert_ne!(a, b);
        assert_ne!(a.endpoint(), b.endpoint());
        let c =
            FifoTarget::from_packed(a.packed(), 0x1234567900000001, a.pipe_generation()).unwrap();
        assert_ne!(a, c);
        assert_ne!(a.ram(), c.ram());
    }
    #[test]
    fn unpaired_or_malformed_identity_cannot_publish_as_fifo() {
        assert_eq!(
            FifoTarget::new(ram(FileKind::Regular, 1), proto_pipe::Endpoint::named(0, 1)),
            Err(FsError::Io)
        );
        assert_eq!(
            FifoTarget::new(ram(FileKind::Fifo, 1), proto_pipe::Endpoint::anonymous(0)),
            Err(FsError::Io)
        );
        assert_eq!(
            FifoTarget::new(
                ram(FileKind::Fifo, 1),
                proto_pipe::Endpoint {
                    id: proto_pipe::NAMED_END,
                    generation: 0
                }
            ),
            Err(FsError::Io)
        );
        let good =
            FifoTarget::new(ram(FileKind::Fifo, 1), proto_pipe::Endpoint::named(127, 1)).unwrap();
        for bit in [6, 7, 22, 31] {
            assert_eq!(
                FifoTarget::from_packed(good.packed() | (1 << bit), 1, 1),
                Err(FsError::Io)
            );
        }
        assert_eq!(
            FifoTarget::from_packed(good.packed(), 0, 1),
            Err(FsError::Io)
        );
        assert_eq!(
            FifoTarget::from_packed(good.packed(), 1, 0),
            Err(FsError::Io)
        );
    }
}
