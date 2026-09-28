// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process protocol v1. Sender PID comes from the kernel, never the body.
//! Enroll/Child have no body and one process handle. Query has no body/handles.
//! Successful registration/query reply: status u32, pid u32, parent u32,
//! uid/euid/suid/gid/egid/sgid u32. Change: nonce u64, operation u32, id u32.
//! Change/ACK reply status alone; ACK body nonce u64. Changes are retained
//! by PID/session/nonce until ACK or session disconnect, with body matching.
#![cfg_attr(not(test), no_std)]
use proto_wire::Header;
pub const VERSION: u16 = 1;
pub const INVALID: u32 = 500;
pub const PERMISSION: u32 = 501;
pub const FULL: u32 = 502;
pub const UNREGISTERED: u32 = 503;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
}
impl Credentials {
    pub const ROOT: Self = Self {
        uid: 0,
        euid: 0,
        suid: 0,
        gid: 0,
        egid: 0,
        sgid: 0,
    };
    pub const fn words(self) -> [u32; 6] {
        [
            self.uid, self.euid, self.suid, self.gid, self.egid, self.sgid,
        ]
    }
    pub const fn from_words(w: [u32; 6]) -> Self {
        Self {
            uid: w[0],
            euid: w[1],
            suid: w[2],
            gid: w[3],
            egid: w[4],
            sgid: w[5],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    Enroll = 1,
    Query = 2,
    Change = 3,
    Ack = 4,
    Child = 5,
}
impl Method {
    pub const fn header(self) -> Header {
        Header {
            version: VERSION,
            method: self as u16,
        }
    }
}
pub const METHODS: &[u16] = &[1, 2, 3, 4, 5];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Change {
    Uid = 1,
    EffectiveUid = 2,
    Gid = 3,
    EffectiveGid = 4,
}
impl Change {
    pub const fn from_number(n: u32) -> Option<Self> {
        match n {
            1 => Some(Self::Uid),
            2 => Some(Self::EffectiveUid),
            3 => Some(Self::Gid),
            4 => Some(Self::EffectiveGid),
            _ => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_fields_and_numbers_are_stable() {
        let value = Credentials::from_words([1, 2, 3, 4, 5, 6]);
        assert_eq!(value.words(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(Credentials::ROOT.words(), [0; 6]);
        for (i, m) in [
            Method::Enroll,
            Method::Query,
            Method::Change,
            Method::Ack,
            Method::Child,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(*m as u16, METHODS[i]);
            assert_eq!(m.header().version, 1);
        }
        for i in 1..=4 {
            assert_eq!(Change::from_number(i).unwrap() as u32, i);
        }
        assert_eq!(Change::from_number(0), None);
        assert_eq!(Change::from_number(5), None);
    }
}
