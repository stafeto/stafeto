// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process protocol v2 (spec 2, section 3.1). The service gives every
//! session it serves: the label of the session names the caller's record
//! (`Label`), never the body. Create comes only through the service's
//! channel with no label, from the service's own thread that takes the
//! processes init loaded (proto_init ADOPT): body root u32 (0 or 1), one
//! process handle. Child comes through a session: no body, one process
//! handle, the new record inheriting the caller's credentials, 32 live
//! children a record at most (FULL). Either handle carries MANAGE
//! (PERMISSION otherwise). Both reply
//! with the snapshot and one handle, the new record's session. Query has no
//! body or handles. Snapshot reply: status u32, pid u32, parent u32,
//! uid/euid/suid/gid/egid/sgid u32. Change: nonce u64, operation u32, id
//! u32. Change/ACK reply status alone; ACK body nonce u64. Changes are
//! retained by session and nonce until ACK or the session's end, with body
//! matching. A record goes when the last copy of its session closes.
#![cfg_attr(not(test), no_std)]
use proto_wire::Header;
pub const VERSION: u16 = 2;
pub const INVALID: u32 = 500;
pub const PERMISSION: u32 = 501;
pub const FULL: u32 = 502;
pub const UNREGISTERED: u32 = 503;

/// Records of the service at most: PID = index + RECORDS * generation.
pub const RECORDS: usize = 256;
/// Generations of a record run from 1 to this and wrap to 1, so that a
/// PID stays a positive i32.
pub const GENERATION_MAX: u32 = (1 << 23) - 1;
/// The parent PID of a record that init created.
pub const INIT_PID: u32 = 1;

/// The label of a session the service gave (spec 2, section 3.1): bit 63
/// set, which no label of init has; bit 62, the identity session, and the
/// image number in bits 40-61 are 0 until they come; the generation of
/// the record in bits 16-39; its index in bits 0-15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    pub index: u16,
    pub generation: u32,
}

impl Label {
    const SERVICE: u64 = 1 << 63;

    pub const fn raw(self) -> u64 {
        Self::SERVICE | (self.generation as u64) << 16 | self.index as u64
    }

    /// The label `raw` names, when it is one the service gives: bit 63,
    /// bits 40-62 0, an index below RECORDS and a generation of 1 to
    /// GENERATION_MAX.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        let index = (raw & 0xFFFF) as u16;
        let generation = ((raw >> 16) & 0xFF_FFFF) as u32;
        if raw & Self::SERVICE == 0
            || raw >> 40 != Self::SERVICE >> 40
            || index as usize >= RECORDS
            || generation == 0
            || generation > GENERATION_MAX
        {
            return None;
        }
        Some(Self { index, generation })
    }

    /// The PID of the record: index + RECORDS * generation.
    pub const fn pid(self) -> u32 {
        self.index as u32 + RECORDS as u32 * self.generation
    }

    /// The generation after `generation`, from 1 to GENERATION_MAX.
    pub const fn next_generation(generation: u32) -> u32 {
        if generation >= GENERATION_MAX {
            1
        } else {
            generation + 1
        }
    }
}
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
    /// The credentials of a process init creates without root.
    pub const NOBODY: Self = Self {
        uid: 65534,
        euid: 65534,
        suid: 65534,
        gid: 65534,
        egid: 65534,
        sgid: 65534,
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
    Create = 1,
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
            Method::Create,
            Method::Query,
            Method::Change,
            Method::Ack,
            Method::Child,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(*m as u16, METHODS[i]);
            assert_eq!(m.header().version, 2);
        }
        for i in 1..=4 {
            assert_eq!(Change::from_number(i).unwrap() as u32, i);
        }
        assert_eq!(Change::from_number(0), None);
        assert_eq!(Change::from_number(5), None);
        assert_eq!(Credentials::NOBODY.words(), [65534; 6]);
    }

    #[test]
    fn labels_are_the_services_own_and_name_one_record() {
        let label = Label {
            index: 5,
            generation: 3,
        };
        assert_eq!(label.raw(), 1 << 63 | 3 << 16 | 5);
        assert_eq!(Label::from_raw(label.raw()), Some(label));
        assert_eq!(label.pid(), 5 + 256 * 3);
        // Labels of init, the identity bit, image numbers, an index past
        // the records and generation 0 name no record.
        for raw in [
            0,
            7,
            3 << 16 | 5,
            label.raw() | 1 << 62,
            label.raw() | 1 << 40,
            1 << 63 | 3 << 16 | 256,
            1 << 63 | 5,
            1 << 63 | u64::from(GENERATION_MAX + 1) << 16,
        ] {
            assert_eq!(Label::from_raw(raw), None, "{raw:#x}");
        }
        let last = Label {
            index: 255,
            generation: GENERATION_MAX,
        };
        assert_eq!(Label::from_raw(last.raw()), Some(last));
        assert!(i32::try_from(last.pid()).is_ok());
        assert_eq!(Label::next_generation(GENERATION_MAX), 1);
        assert_eq!(Label::next_generation(1), 2);
    }
}
