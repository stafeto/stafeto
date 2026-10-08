// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Canonical initial Stage and registered RAM source-proof envelopes.
use crate::initial_identity::Query;
use crate::initial_publication::{read_source, write_source};
use bootimg::exec_bindings::InitialSource;
use proto_wire::{Reader, Status, Writer};

pub const BODY: usize = 96;
pub const PROOF: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stage {
    pub epoch: u64,
    pub ticket: u64,
    pub label: u64,
    pub source: InitialSource,
    pub query: Query,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}
impl Stage {
    /// A settled reconciliation carries metadata and no new owner.
    pub fn read_reconciliation(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if handles != 0 {
            return Err(Status::BadSize);
        }
        Self::read(bytes, 1)
    }

    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if bytes.len() != BODY || handles != 1 {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(bytes);
        let epoch = r.u64()?;
        let ticket = r.u64()?;
        let label = r.u64()?;
        let source = read_source(&mut r)?;
        let query = Query::read(r.bytes(40)?, 1)?;
        let uid = r.u32()?;
        let gid = r.u32()?;
        let mode = r.u32()?;
        if r.u32()? != 0
            || epoch == 0
            || ticket == 0
            || label != query.receipt.label
            || ticket != query.receipt.init_ticket
            || ticket != query.receipt.key.key
            || mode > 1
        {
            return Err(Status::BadSize);
        }
        r.finish()?;
        Ok(Self {
            epoch,
            ticket,
            label,
            source,
            query,
            uid,
            gid,
            mode,
        })
    }
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        if self.epoch == 0
            || self.ticket == 0
            || self.mode > 1
            || self.label != self.query.receipt.label
            || self.ticket != self.query.receipt.init_ticket
            || self.ticket != self.query.receipt.key.key
        {
            return Err(Status::BadSize);
        }
        w.u64(self.epoch)?;
        w.u64(self.ticket)?;
        w.u64(self.label)?;
        write_source(self.source, w)?;
        self.query.write(w)?;
        w.u32(self.uid)?;
        w.u32(self.gid)?;
        w.u32(self.mode)?;
        w.u32(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub stage: Stage,
    pub source_label: u64,
}
impl Proof {
    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if handles != 0 {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(bytes);
        let status = Status::from_code(r.u32()?);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        if status != Status::Ok {
            r.finish()?;
            return Err(status);
        }
        if bytes.len() != PROOF {
            return Err(Status::BadSize);
        }
        let stage = Stage::read(r.bytes(BODY)?, 1)?;
        let source_label = r.u64()?;
        if source_label == 0 || r.u32()? != 1 || r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        r.finish()?;
        Ok(Self {
            stage,
            source_label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Label,
        initial_map::{Key, Receipt},
    };
    fn stage() -> Stage {
        let label = Label {
            index: 3,
            generation: 0x1_0001,
        };
        Stage {
            epoch: 37,
            ticket: 29,
            label: label.raw_at(1),
            source: InitialSource {
                artifact: 1,
                raw: 2,
                canonical: None,
            },
            query: Query {
                receipt: Receipt {
                    key: Key { key: 29, image: 1 },
                    label: label.raw_at(1),
                    pid: label.pid(),
                    init_ticket: 29,
                },
            },
            uid: 12,
            gid: 13,
            mode: 1,
        }
    }
    #[test]
    fn reconciliation_has_exact_canonical_body_and_zero_new_owners() {
        let mut w = Writer::new();
        stage().write(&mut w).unwrap();
        let bytes = w.as_bytes();
        assert_eq!(Stage::read_reconciliation(bytes, 0), Ok(stage()));
        assert!(Stage::read(bytes, 0).is_err());
        for caps in 1..=4 {
            assert!(Stage::read_reconciliation(bytes, caps).is_err());
        }
        for length in 0..bytes.len() {
            assert!(Stage::read_reconciliation(&bytes[..length], 0).is_err());
        }
        for offset in [36, 40, 44, 48, 52, 92] {
            let mut bad = bytes.to_vec();
            bad[offset] ^= 1;
            assert_eq!(Stage::read_reconciliation(&bad, 0), Stage::read(&bad, 1));
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(Stage::read_reconciliation(&trailing, 0).is_err());
    }

    #[test]
    fn source_proof_requires_complete_echo_and_canonical_status() {
        let mut w = Writer::new();
        w.bytes(&[0; 8]).unwrap();
        stage().write(&mut w).unwrap();
        w.u64(71).unwrap();
        w.u32(1).unwrap();
        w.u32(0).unwrap();
        assert_eq!(w.as_bytes().len(), 120);
        assert_eq!(
            Proof::read(w.as_bytes(), 0),
            Ok(Proof {
                stage: stage(),
                source_label: 71
            })
        );
        let good = w.as_bytes().to_vec();
        for at in [4, 100, 112, 116] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            assert!(Proof::read(&bad, 0).is_err());
        }
        for caps in 1..=4 {
            assert!(Proof::read(&good, caps).is_err());
        }
        for len in 0..120 {
            assert!(Proof::read(&good[..len], 0).is_err());
        }
        let mut tail = good.clone();
        tail.push(0);
        assert!(Proof::read(&tail, 0).is_err());
        assert_eq!(
            Proof::read(&proto_wire::reply(Status::BadSize), 0),
            Err(Status::BadSize)
        );
    }
}
