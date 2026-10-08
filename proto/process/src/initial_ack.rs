// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact initial lifecycle acknowledgement from the trusted Init endpoint.
use crate::initial_identity::Query;
use crate::initial_map::Receipt;
use proto_wire::{Reader, Status, Writer};

pub const BODY: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub epoch: u64,
    pub ticket: u64,
    pub label: u64,
    pub receipt: Receipt,
}
impl Ack {
    fn valid(self) -> bool {
        self.ticket != 0
            && self.ticket == self.receipt.init_ticket
            && self.ticket == self.receipt.key.key
            && self.label == self.receipt.label
            && self.receipt.key.image == crate::IMAGE
            && self.receipt.valid()
    }
    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if bytes.len() != BODY || handles != 0 {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(bytes);
        let epoch = r.u64()?;
        let ticket = r.u64()?;
        let label = r.u64()?;
        // The canonical receipt codec is shared with the identity envelope.
        // This metadata-only acknowledgement carries no identity capability.
        let receipt = Query::read(r.bytes(40)?, 1)?.receipt;
        r.finish()?;
        let out = Self {
            epoch,
            ticket,
            label,
            receipt,
        };
        if !out.valid() {
            return Err(Status::BadSize);
        }
        Ok(out)
    }
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        w.u64(self.epoch)?;
        w.u64(self.ticket)?;
        w.u64(self.label)?;
        Query {
            receipt: self.receipt,
        }
        .write(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Label, initial_map::Key};
    #[test]
    fn exact_body_preserves_epoch_and_rejects_capabilities_reserved_and_aliases() {
        let label = Label {
            index: 3,
            generation: 9,
        };
        let receipt = Receipt {
            key: Key {
                key: 83,
                image: crate::IMAGE,
            },
            label: label.raw_at(crate::IMAGE),
            pid: label.pid(),
            init_ticket: 83,
        };
        for epoch in [0, 0x9876_5432_1234_5678] {
            let ack = Ack {
                epoch,
                ticket: 83,
                label: receipt.label,
                receipt,
            };
            let mut w = Writer::new();
            ack.write(&mut w).unwrap();
            let bytes = w.as_bytes();
            assert_eq!(bytes.len(), BODY);
            assert_eq!(Ack::read(bytes, 0), Ok(ack));
            assert!(Ack::read(bytes, 1).is_err());
            assert!(Ack::read(&bytes[..63], 0).is_err());
            let mut trailing = [0; 65];
            trailing[..64].copy_from_slice(bytes);
            assert!(Ack::read(&trailing, 0).is_err());
            for offset in [8, 16, 24, 26, 28, 32, 40, 48, 52, 56] {
                let mut bad = [0; 64];
                bad.copy_from_slice(bytes);
                bad[offset] ^= 1;
                assert!(Ack::read(&bad, 0).is_err(), "offset {offset}");
            }
        }
    }
}
