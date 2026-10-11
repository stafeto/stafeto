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
