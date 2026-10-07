// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Shared clock protocol v3. GET: clock u32; reply status u32, seconds i64,
//! nanos u64, resolution u64, generation u64. SET: seconds i64, nanos i64
//! and, until the service has one for the session, a handle: a copy of the
//! caller's identity session of the process service (NOTIFY, TRANSFER,
//! DUPLICATE), for which the service has the process service vouch
//! through its notary session; a handle a later SET brings takes the
//! place of the one before (an exec gives the session a new image's
//! identity); reply status alone, PERMISSION unless
//! the caller's effective UID is 0 (spec 2, 3.1). WATCH: empty body, one NOTIFY channel; reply status.
//! ANCHOR: empty body; reply status, seconds i64, nanos u64, mono u64,
//! resolution u64, generation u64. OBSERVE: empty body, subscribed session
//! with one observation consumer. Same anchor reply, then the high/low u64
//! words of the nonnegative i128 peak since the previous observation.
//! PAGE: empty body; reply status and one handle, the service's page of
//! the CLOCK_REALTIME anchor with MAP_READ (`page` for its layout).
//! CLONE: empty body; reply status and one handle, a new session (SEND,
//! TRANSFER) with a label of the service's own, for a child of the
//! client (spec 2, 3.7; 5c).
//! VERIFY_SESSION: empty body and one offered session. A normal session
//! of this service with SEND and TRANSFER returns unchanged; any other
//! channel is replaced with an ordinary empty clone.
//! The kernel answers an accepted request once (spec 6.1): a client sends
//! a request again only when the send came back INTERRUPTED, which the
//! service never saw, so SET and OBSERVE take effect once with no journal.

#![no_std]
use proto_wire::{Header, Reader, Status};
pub const VERSION: u16 = 5;
pub const REALTIME: u32 = 0;
pub const MONOTONIC: u32 = 1;
pub const INVALID: u32 = 400;
pub const OVERFLOW: u32 = 401;
pub const FULL: u32 = 402;
/// EPERM: the caller may not set the clock.
pub const PERMISSION: u32 = 403;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Method {
    Get = 1,
    Set = 2,
    Watch = 5,
    Anchor = 6,
    Observe = 7,
    Page = 10,
    Clone = 11,
    VerifySession = 12,
}
impl Method {
    pub const fn header(self) -> Header {
        Header {
            version: VERSION,
            method: self as u16,
        }
    }
    pub const fn from_number(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Get),
            2 => Some(Self::Set),
            5 => Some(Self::Watch),
            6 => Some(Self::Anchor),
            7 => Some(Self::Observe),
            10 => Some(Self::Page),
            11 => Some(Self::Clone),
            12 => Some(Self::VerifySession),
            _ => None,
        }
    }
}
pub const METHODS: &[u16] = &[1, 2, 5, 6, 7, 10, 11, 12];

/// Decode the complete PAGE reply before accepting custody of its memory.
pub fn decode_page_reply(bytes: &[u8], handle_count: usize) -> Result<(), Status> {
    let mut reader = Reader::new(bytes);
    let status = Status::from_code(reader.u32()?);
    if status != Status::Ok && reader.u32()? != 0 {
        return Err(Status::BadSize);
    }
    reader.finish()?;
    let expected_handles = usize::from(status == Status::Ok);
    if handle_count != expected_handles {
        return Err(Status::BadSize);
    }
    match status {
        Status::Ok => Ok(()),
        error => Err(error),
    }
}

#[cfg(test)]
mod reply_tests {
    use super::*;

    #[test]
    fn page_success_requires_one_handle_and_the_complete_status_word() {
        let bytes = 0_u32.to_le_bytes();
        assert_eq!(decode_page_reply(&bytes, 1), Ok(()));
        for count in [0, 2, usize::MAX] {
            assert_eq!(decode_page_reply(&bytes, count), Err(Status::BadSize));
        }
        for length in 0..4 {
            assert_eq!(decode_page_reply(&bytes[..length], 1), Err(Status::BadSize));
        }
        assert_eq!(decode_page_reply(&[0, 0, 0, 0, 1], 1), Err(Status::BadSize));
    }

    #[test]
    fn page_failure_preserves_status_and_rejects_attached_handles_or_bytes() {
        // Kernel NoMemory and the clock's permission error use the service runtime's reply.
        for status in [Status::from_code(5), Status::from_code(PERMISSION)] {
            let bytes = proto_wire::reply(status);
            assert_eq!(bytes.len(), 8);
            assert_eq!(decode_page_reply(&bytes, 0), Err(status));
            for count in [1, 2, usize::MAX] {
                assert_eq!(decode_page_reply(&bytes, count), Err(Status::BadSize));
            }
            for length in 0..8 {
                assert_eq!(decode_page_reply(&bytes[..length], 0), Err(Status::BadSize));
            }
            let mut nonzero_reserved = bytes;
            nonzero_reserved[4] = 1;
            assert_eq!(
                decode_page_reply(&nonzero_reserved, 0),
                Err(Status::BadSize)
            );
            let mut trailing = [0; 9];
            trailing[..8].copy_from_slice(&bytes);
            assert_eq!(decode_page_reply(&trailing, 0), Err(Status::BadSize));
        }
    }
}

/// The page of the CLOCK_REALTIME anchor (spec 2, 3.6): a counter s and
/// two places. The service writes place (s + 1) mod 2 word by word, then
/// raises s with Release; a reader takes s with Acquire, place s mod 2
/// word by word, an Acquire fence, s again, and starts over when s moved.
/// CLOCK_REALTIME is then the anchor's ns plus the monotonic ns since its
/// instant.
pub mod page {
    use core::sync::atomic::{Ordering, fence};
    /// The counter s, a u64 word.
    pub const SEQUENCE: usize = 0;
    /// The first place; the second follows it.
    pub const PLACES: usize = 8;
    /// A place: words of the anchor's ns (low and high halves of an i128),
    /// its monotonic instant in ns, and its generation.
    pub const LOW: usize = 0;
    pub const HIGH: usize = 8;
    pub const MONO: usize = 16;
    pub const GENERATION: usize = 24;
    pub const PLACE_SIZE: usize = 32;
    /// One complete realtime anchor from the shared page.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Anchor {
        pub value_ns: i128,
        pub monotonic_ns: u64,
        pub generation: u64,
    }

    impl Anchor {
        /// Add elapsed monotonic nanoseconds with checked signed arithmetic.
        pub fn realtime_ns(self, monotonic_now: u64) -> Option<i128> {
            self.value_ns
                .checked_add(i128::from(monotonic_now.saturating_sub(self.monotonic_ns)))
        }
    }

    /// Read one snapshot in six atomic loads. A changed sequence defers it.
    /// Each call to `load` must read the aligned AtomicU64 at the byte offset
    /// in the mapped page with the supplied ordering.
    pub fn read_anchor_once(mut load: impl FnMut(usize, Ordering) -> u64) -> Option<Anchor> {
        let sequence = load(SEQUENCE, Ordering::Acquire);
        let place = PLACES + (sequence % 2) as usize * PLACE_SIZE;
        let low = load(place + LOW, Ordering::Relaxed);
        let high = load(place + HIGH, Ordering::Relaxed);
        let monotonic_ns = load(place + MONO, Ordering::Relaxed);
        let generation = load(place + GENERATION, Ordering::Relaxed);
        fence(Ordering::Acquire);
        if load(SEQUENCE, Ordering::Relaxed) != sequence {
            return None;
        }
        Some(Anchor {
            value_ns: ((u128::from(high) << 64) | u128::from(low)) as i128,
            monotonic_ns,
            generation,
        })
    }

    /// The size of the object.
    pub const SIZE: usize = 4096;
}

#[cfg(test)]
mod page_tests;
