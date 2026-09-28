// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Shared clock protocol v1. GET: clock u32; reply status u32, seconds i64,
//! nanos u64, resolution u64, generation u64. SET: nonce u64, seconds i64,
//! nanos i64; ACK: nonce u64. SET/ACK reply with status alone. Successful SET
//! is retained per session until ACK and may be retried without applying twice.
//! WATCH: empty body, one NOTIFY channel; reply status. ANCHOR: empty body;
//! reply status, seconds i64, nanos u64, mono u64, resolution u64, generation u64.
//! OBSERVE: nonce u64, subscribed session with one observation consumer. Same anchor reply, then the
//! high/low u64 words of the nonnegative i128 peak since the previous observation.
//! The last nonce/result is retained until the next observation for retry safety.

#![no_std]
use proto_wire::Header;
pub const VERSION: u16 = 1;
pub const REALTIME: u32 = 0;
pub const MONOTONIC: u32 = 1;
pub const INVALID: u32 = 400;
pub const OVERFLOW: u32 = 401;
pub const FULL: u32 = 402;
pub const PENDING_MAX: usize = 64;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Method {
    Get = 1,
    Set = 2,
    Ack = 3,
    Watch = 5,
    Anchor = 6,
    Observe = 7,
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
            3 => Some(Self::Ack),
            5 => Some(Self::Watch),
            6 => Some(Self::Anchor),
            7 => Some(Self::Observe),
            _ => None,
        }
    }
}
pub const METHODS: &[u16] = &[1, 2, 3, 5, 6, 7];
