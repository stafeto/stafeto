// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Canonical initial-identity envelopes. Native admission authenticates the
//! actual identity Channel, current initial receipt and immutable Init instance.
use crate::initial_map::{Key, Receipt, SCHEMA};
use crate::initial_publication::{read_source, write_source};
use bootimg::exec_bindings::InitialSource;
use proto_wire::{Reader, Status, Writer};

pub const QUERY: usize = 40;
pub const REPLY: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    pub receipt: Receipt,
}
impl Query {
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        if !self.receipt.valid() {
            return Err(Status::BadSize);
        }
        w.u16(SCHEMA)?;
        w.u16(0)?;
        w.u32(0)?;
        w.u64(self.receipt.key.key)?;
        w.u64(self.receipt.label)?;
        w.u32(self.receipt.pid)?;
        w.u32(self.receipt.key.image)?;
        w.u64(self.receipt.init_ticket)
    }

    /// Count the incoming identity capability before taking any object.
    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if bytes.len() != QUERY || handles != 1 {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(bytes);
        if r.u16()? != SCHEMA || r.u16()? != 0 || r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let key = r.u64()?;
        let label = r.u64()?;
        let pid = r.u32()?;
        let image = r.u32()?;
        let init_ticket = r.u64()?;
        r.finish()?;
        let receipt = Receipt {
            key: Key { key, image },
            label,
            pid,
            init_ticket,
        };
        if !receipt.valid() {
            return Err(Status::BadSize);
        }
        Ok(Self { receipt })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub query: Query,
    pub source: InitialSource,
}
impl Reply {
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        w.bytes(&proto_wire::reply(Status::Ok))?;
        self.query.write(w)?;
        write_source(self.source, w)
    }

    /// The caller additionally matches the echoed receipt to its retained request.
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
        if bytes.len() != REPLY {
            return Err(Status::BadSize);
        }
        // The embedded query retains its one-identity envelope contract.
        let query = Query::read(r.bytes(QUERY)?, 1)?;
        let source = read_source(&mut r)?;
        r.finish()?;
        Ok(Self { query, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Label, Method};
    use bootimg::exec_bindings::NONE;

    fn query_bytes() -> [u8; QUERY] {
        // Independent literal schema/key/Work label/PID/image/ticket.
        [
            1, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 7, 0, 3, 0, 0, 1, 0, 128, 7, 3, 0, 0,
            1, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0,
        ]
    }
    fn expected() -> Query {
        let label = Label {
            index: 7,
            generation: 3,
        };
        Query {
            receipt: Receipt {
                key: Key { key: 19, image: 1 },
                label: label.raw_at(1),
                pid: label.pid(),
                init_ticket: 23,
            },
        }
    }
    fn reply_bytes() -> [u8; REPLY] {
        let mut bytes = [0; REPLY];
        bytes[8..48].copy_from_slice(&query_bytes());
        bytes[48..52].copy_from_slice(&5u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&12u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&3u32.to_le_bytes());
        bytes
    }

    #[test]
    fn literal_wire_matches_canonical_query_and_reply() {
        assert_eq!(Method::InitialOf as u16, 61);
        assert!(crate::METHODS.contains(&61));
        assert_eq!(Query::read(&query_bytes(), 1), Ok(expected()));
        let mut w = Writer::new();
        expected().write(&mut w).unwrap();
        assert_eq!(w.as_bytes(), query_bytes());
        let reply = Reply {
            query: expected(),
            source: InitialSource {
                artifact: 5,
                raw: 12,
                canonical: Some(3),
            },
        };
        assert_eq!(Reply::read(&reply_bytes(), 0), Ok(reply));
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        assert_eq!(w.as_bytes(), reply_bytes());
        let mut none = reply_bytes();
        none[56..60].copy_from_slice(&NONE.to_le_bytes());
        assert_eq!(Reply::read(&none, 0).unwrap().source.canonical, None);
    }

    #[test]
    fn malformed_receipts_and_identity_counts_refuse() {
        let valid = query_bytes();
        for count in [0, 2, 4] {
            assert_eq!(Query::read(&valid, count), Err(Status::BadSize));
        }
        for size in 0..QUERY {
            assert_eq!(Query::read(&valid[..size], 1), Err(Status::BadSize));
        }
        let mut tail = [0; QUERY + 1];
        tail[..QUERY].copy_from_slice(&valid);
        assert_eq!(Query::read(&tail, 1), Err(Status::BadSize));
        for (at, value) in [
            (0, 2),
            (2, 1),
            (4, 1),
            (8, 0),
            (23, 0),
            (23, 192),
            (18, 0),
            (24, 8),
            (28, 0),
            (32, 0),
        ] {
            let mut bad = valid;
            bad[at] = value;
            assert_eq!(Query::read(&bad, 1), Err(Status::BadSize), "byte {at}");
        }
        for image in [2u32, crate::IMAGE_MAX + 1] {
            let mut bad = valid;
            bad[28..32].copy_from_slice(&image.to_le_bytes());
            assert_eq!(Query::read(&bad, 1), Err(Status::BadSize));
        }
    }

    #[test]
    fn malformed_sources_and_reply_envelopes_refuse() {
        let valid = reply_bytes();
        for size in 0..REPLY {
            assert_eq!(Reply::read(&valid[..size], 0), Err(Status::BadSize));
        }
        for count in [1, 2, 4] {
            assert_eq!(Reply::read(&valid, count), Err(Status::BadSize));
        }
        let mut tail = [0; REPLY + 1];
        tail[..REPLY].copy_from_slice(&valid);
        assert_eq!(Reply::read(&tail, 0), Err(Status::BadSize));
        for at in [4, 60] {
            let mut bad = valid;
            bad[at] = 1;
            assert_eq!(Reply::read(&bad, 0), Err(Status::BadSize));
        }
        for (at, value) in [
            (48, 12),
            (48, bootimg::rootfs::FILES_MAX as u32),
            (52, bootimg::rootfs::FILES_MAX as u32),
            (56, bootimg::rootfs::ENTRIES_MAX as u32),
        ] {
            let mut bad = valid;
            bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(Reply::read(&bad, 0), Err(Status::BadSize));
        }
        let refused = proto_wire::reply(Status::from_code(crate::PERMISSION));
        assert_eq!(
            Reply::read(&refused, 0),
            Err(Status::from_code(crate::PERMISSION))
        );
        assert_eq!(Reply::read(&refused, 1), Err(Status::BadSize));
        let mut bad = valid;
        bad[..8].copy_from_slice(&refused);
        assert_eq!(Reply::read(&bad, 0), Err(Status::BadSize));
    }
}
