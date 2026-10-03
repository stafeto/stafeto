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
//! The kernel answers an accepted request once (spec 6.1): a client sends
//! a request again only when the send came back INTERRUPTED, which the
//! service never saw, so SET and OBSERVE take effect once with no journal.

#![no_std]
use proto_wire::Header;
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
            _ => None,
        }
    }
}
pub const METHODS: &[u16] = &[1, 2, 5, 6, 7, 10, 11];

/// The page of the CLOCK_REALTIME anchor (spec 2, 3.6): a counter s and
/// two places. The service writes place (s + 1) mod 2 word by word, then
/// raises s with Release; a reader takes s with Acquire, place s mod 2
/// word by word, an Acquire fence, s again, and starts over when s moved.
/// CLOCK_REALTIME is then the anchor's ns plus the monotonic ns since its
/// instant.
pub mod page {
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
    /// The size of the object.
    pub const SIZE: usize = 4096;
}
