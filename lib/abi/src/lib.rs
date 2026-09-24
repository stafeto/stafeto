// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stafeto kernel interface shared by the kernel and programs (spec 5,
//! 12): handle layout, rights and error codes. System call numbers join it
//! with the first system calls.

#![cfg_attr(not(test), no_std)]

/// A process's name for a kernel object (spec 5.1): the low 16 bits index
/// its handle table, the high 48 bits carry the entry's generation. The
/// layout belongs to the kernel; programs treat the value as opaque.
/// Generations start at 1, so no handle is zero.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(pub u64);

impl Handle {
    pub const INDEX_BITS: u32 = 16;
    pub const GENERATION_BITS: u32 = u64::BITS - Self::INDEX_BITS;
    pub const MAX_INDEX: u32 = (1 << Self::INDEX_BITS) - 1;
    /// An entry freed at this generation is retired, never reused.
    pub const MAX_GENERATION: u64 = (1 << Self::GENERATION_BITS) - 1;
    pub const INVALID: Handle = Handle(0);

    pub const fn new(index: u32, generation: u64) -> Handle {
        Handle(
            ((generation & Self::MAX_GENERATION) << Self::INDEX_BITS)
                | (index & Self::MAX_INDEX) as u64,
        )
    }

    pub const fn index(self) -> u32 {
        (self.0 & Self::MAX_INDEX as u64) as u32
    }

    pub const fn generation(self) -> u64 {
        self.0 >> Self::INDEX_BITS
    }
}

/// What a handle allows (spec 5.2). A copy carries a subset, never more.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rights(pub u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const DUPLICATE: Rights = Rights(1 << 0);
    pub const TRANSFER: Rights = Rights(1 << 1);
    pub const SEND: Rights = Rights(1 << 2);
    pub const NOTIFY: Rights = Rights(1 << 3);
    pub const RECEIVE: Rights = Rights(1 << 4);
    pub const MAP_READ: Rights = Rights(1 << 5);
    pub const MAP_WRITE: Rights = Rights(1 << 6);
    pub const MAP_EXEC: Rights = Rights(1 << 7);
    pub const MANAGE: Rights = Rights(1 << 8);
    pub const DEVICE: Rights = Rights(1 << 9);
    pub const DEBUG: Rights = Rights(1 << 10);
    pub const KSTATS: Rights = Rights(1 << 11);

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, other: Rights) -> Rights {
        self.union(other)
    }
}

/// Error codes of system calls (spec 12); zero means success.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadHandle = 1,
    WrongType = 2,
    AccessDenied = 3,
    InvalidArgs = 4,
    NoMemory = 5,
    LimitReached = 6,
    PeerClosed = 7,
    WouldBlock = 8,
    BadState = 9,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_packs_index_and_generation() {
        let h = Handle::new(0xBEEF, 0x1234_5678_9ABC);
        assert_eq!(h.0, 0x1234_5678_9ABC_BEEF);
        assert_eq!((h.index(), h.generation()), (0xBEEF, 0x1234_5678_9ABC));
    }

    #[test]
    fn max_generation_keeps_the_index() {
        assert_eq!(Handle::GENERATION_BITS, 48);
        assert_eq!(Handle::MAX_GENERATION, (1 << 48) - 1);
        let h = Handle::new(Handle::MAX_INDEX, Handle::MAX_GENERATION);
        assert_eq!(h, Handle(u64::MAX));
        assert_eq!(
            (h.index(), h.generation()),
            (Handle::MAX_INDEX, Handle::MAX_GENERATION)
        );
    }

    #[test]
    fn handle_is_eight_bytes() {
        assert_eq!(core::mem::size_of::<Handle>(), 8);
    }

    #[test]
    fn handle_with_a_generation_is_never_zero() {
        assert_ne!(Handle::new(0, 1), Handle::INVALID);
    }

    #[test]
    fn rights_contain_their_subsets() {
        let r = Rights::SEND | Rights::DUPLICATE;
        assert!(r.contains(Rights::SEND));
        assert!(r.contains(Rights::NONE));
        assert!(!r.contains(Rights::RECEIVE));
        assert!(!r.contains(Rights::SEND | Rights::RECEIVE));
    }

    #[test]
    fn rights_are_distinct_bits() {
        let all = [
            Rights::DUPLICATE,
            Rights::TRANSFER,
            Rights::SEND,
            Rights::NOTIFY,
            Rights::RECEIVE,
            Rights::MAP_READ,
            Rights::MAP_WRITE,
            Rights::MAP_EXEC,
            Rights::MANAGE,
            Rights::DEVICE,
            Rights::DEBUG,
            Rights::KSTATS,
        ];
        let union = all.iter().fold(Rights::NONE, |a, b| a | *b);
        assert_eq!(union.0.count_ones(), 12);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(Error::BadHandle as u32, 1);
        assert_eq!(Error::WouldBlock as u32, 8);
        assert_eq!(Error::BadState as u32, 9);
    }
}
