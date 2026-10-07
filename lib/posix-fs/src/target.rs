// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact backend identity accompanies every published RAM descriptor.

use core::num::NonZeroU64;
use rt::fs::PreparedOpen;

use super::FsError;

/// The numeric mapping and the complete open-description lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RamTarget {
    packed: u32,
    generation: NonZeroU64,
}

const _: () = assert!(core::mem::size_of::<RamTarget>() == 16);

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
