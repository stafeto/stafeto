// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial memory-map envelopes. Runtime admission additionally authenticates
//! the current receipt, Memory objects and their exact rights.

use crate::{IMAGE_MAX, Label, Place};
use abi::Access;
use proto_wire::{Reader, Status, Writer};

pub const SCHEMA: u16 = 1;
pub const ENTRIES: usize = 4;
pub const HEADER: usize = 48;
pub const ENTRY: usize = 24;
pub const PAGE: u64 = 4096;

const _: () = assert!(ENTRIES == abi::MESSAGE_HANDLES);
const _: () = assert!(HEADER + ENTRY * ENTRIES <= abi::MESSAGE_MAX);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub key: u64,
    pub image: u32,
}

impl Key {
    pub const FIRST: Self = Self { key: 0, image: 0 };

    fn valid(self, ack: bool) -> bool {
        (self.key != 0 && self.image != 0 && self.image <= IMAGE_MAX)
            || (!ack && self == Self::FIRST)
    }

    fn write(self, w: &mut Writer, ack: bool) -> Result<(), Status> {
        if !self.valid(ack) {
            return Err(Status::BadSize);
        }
        w.u64(self.key)?;
        w.u32(self.image)?;
        w.u32(0)
    }

    fn read(bytes: &[u8], handles: usize, ack: bool) -> Result<Self, Status> {
        if handles != 0 {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(bytes);
        let out = Self {
            key: r.u64()?,
            image: r.u32()?,
        };
        if r.u32()? != 0 || !out.valid(ack) {
            return Err(Status::BadSize);
        }
        r.finish()?;
        Ok(out)
    }

    pub fn write_query(self, w: &mut Writer) -> Result<(), Status> {
        self.write(w, false)
    }

    pub fn write_ack(self, w: &mut Writer) -> Result<(), Status> {
        self.write(w, true)
    }

    pub fn read_query(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        Self::read(bytes, handles, false)
    }

    pub fn read_ack(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        Self::read(bytes, handles, true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub key: Key,
    pub label: u64,
    pub pid: u32,
    pub init_ticket: u64,
}

impl Receipt {
    pub(crate) fn valid(self) -> bool {
        if !self.key.valid(true)
            || self.init_ticket == 0
            || self.pid == 0
            || self.pid > i32::MAX as u32
        {
            return false;
        }
        let Some((label, Place::Work, image)) = Label::parse_image(self.label) else {
            return false;
        };
        image == self.key.image
            && label.raw_at(self.key.image) == self.label
            && label.pid() == self.pid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub address: u64,
    pub pages: u32,
    pub access: Access,
    pub slot: u32,
}

impl Entry {
    pub const EMPTY: Self = Self {
        address: 0,
        pages: 0,
        access: Access::Read,
        slot: 0,
    };

    fn end(self) -> Option<u64> {
        if self.pages == 0 || !self.address.is_multiple_of(PAGE) {
            return None;
        }
        self.address
            .checked_add(u64::from(self.pages).checked_mul(PAGE)?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub receipt: Receipt,
    pub count: u16,
    pub entries: [Entry; ENTRIES],
}

impl Reply {
    pub(crate) fn validate(&self) -> Result<(), Status> {
        let count = usize::from(self.count);
        if !(1..=ENTRIES).contains(&count) || !self.receipt.valid() {
            return Err(Status::BadSize);
        }
        for (slot, entry) in self.entries[..count].iter().enumerate() {
            let end = entry.end().ok_or(Status::BadSize)?;
            if entry.slot != slot as u32 {
                return Err(Status::BadSize);
            }
            for previous in &self.entries[..slot] {
                if entry.address < previous.end().ok_or(Status::BadSize)? && previous.address < end
                {
                    return Err(Status::BadSize);
                }
            }
        }
        if self.entries[count..]
            .iter()
            .any(|entry| *entry != Entry::EMPTY)
        {
            return Err(Status::BadSize);
        }
        Ok(())
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        w.bytes(&proto_wire::reply(Status::Ok))?;
        w.u16(SCHEMA)?;
        w.u16(self.count)?;
        w.u32(0)?;
        w.u64(self.receipt.key.key)?;
        w.u64(self.receipt.label)?;
        w.u32(self.receipt.pid)?;
        w.u32(self.receipt.key.image)?;
        w.u64(self.receipt.init_ticket)?;
        for entry in &self.entries[..usize::from(self.count)] {
            w.u64(entry.address)?;
            w.u32(entry.pages)?;
            w.u32(entry.access.raw() as u32)?;
            w.u32(entry.slot)?;
            w.u32(0)?;
        }
        Ok(())
    }

    /// `handles` is the actual incoming count, checked before taking objects.
    /// Canonical refusals return their status; malformed envelopes return BAD_SIZE.
    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        let mut r = Reader::new(bytes);
        let status = Status::from_code(r.u32()?);
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        if status != Status::Ok {
            r.finish()?;
            return Err(if handles == 0 {
                status
            } else {
                Status::BadSize
            });
        }
        let schema = r.u16()?;
        let count = r.u16()?;
        if schema != SCHEMA
            || !(1..=ENTRIES as u16).contains(&count)
            || r.u32()? != 0
            || handles != usize::from(count)
        {
            return Err(Status::BadSize);
        }
        let key = r.u64()?;
        let label = r.u64()?;
        let pid = r.u32()?;
        let image = r.u32()?;
        let init_ticket = r.u64()?;
        let mut out = Self {
            receipt: Receipt {
                key: Key { key, image },
                label,
                pid,
                init_ticket,
            },
            count,
            entries: [Entry::EMPTY; ENTRIES],
        };
        for entry in &mut out.entries[..usize::from(count)] {
            let address = r.u64()?;
            let pages = r.u32()?;
            let access = Access::from_raw(u64::from(r.u32()?)).ok_or(Status::BadSize)?;
            let slot = r.u32()?;
            if r.u32()? != 0 {
                return Err(Status::BadSize);
            }
            *entry = Entry {
                address,
                pages,
                access,
                slot,
            };
        }
        r.finish()?;
        out.validate()?;
        Ok(out)
    }
}

pub fn read_ack_reply(bytes: &[u8], handles: usize) -> Result<(), Status> {
    if handles != 0 {
        return Err(Status::BadSize);
    }
    let mut r = Reader::new(bytes);
    let status = Status::from_code(r.u32()?);
    if r.u32()? != 0 {
        return Err(Status::BadSize);
    }
    r.finish()?;
    if status == Status::Ok {
        Ok(())
    } else {
        Err(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(count: u16) -> Reply {
        let label = Label {
            index: 7,
            generation: 3,
        };
        let mut out = Reply {
            receipt: Receipt {
                key: Key { key: 19, image: 2 },
                label: label.raw_at(2),
                pid: label.pid(),
                init_ticket: 23,
            },
            count,
            entries: [Entry::EMPTY; ENTRIES],
        };
        for (slot, entry) in out.entries[..usize::from(count)].iter_mut().enumerate() {
            *entry = Entry {
                address: (slot as u64 + 1) * PAGE,
                pages: 1,
                access: [
                    Access::ReadExec,
                    Access::Read,
                    Access::ReadWrite,
                    Access::ReadWrite,
                ][slot],
                slot: slot as u32,
            };
        }
        out
    }

    fn encoded(reply: Reply) -> Vec<u8> {
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        w.as_bytes().to_vec()
    }

    #[test]
    fn requests_enforce_first_query_and_exact_replay_key() {
        let key = Key {
            key: 9,
            image: IMAGE_MAX,
        };
        for query in [Key::FIRST, key] {
            let mut w = Writer::new();
            query.write_query(&mut w).unwrap();
            assert_eq!(w.as_bytes().len(), 16);
            assert_eq!(Key::read_query(w.as_bytes(), 0), Ok(query));
            assert_eq!(Key::read_query(w.as_bytes(), 1), Err(Status::BadSize));
            for cut in 0..16 {
                assert!(Key::read_query(&w.as_bytes()[..cut], 0).is_err());
            }
            let mut bad = w.as_bytes().to_vec();
            bad.push(0);
            assert_eq!(Key::read_query(&bad, 0), Err(Status::BadSize));
            bad.pop();
            bad[12] = 1;
            assert_eq!(Key::read_query(&bad, 0), Err(Status::BadSize));
        }
        let mut w = Writer::new();
        key.write_ack(&mut w).unwrap();
        assert_eq!(Key::read_ack(w.as_bytes(), 0), Ok(key));
        assert_eq!(Key::read_ack(&[0; 16], 0), Err(Status::BadSize));
        assert_eq!(Key::read_ack(w.as_bytes(), 1), Err(Status::BadSize));
        for invalid in [
            Key { key: 0, image: 1 },
            Key { key: 1, image: 0 },
            Key {
                key: 1,
                image: IMAGE_MAX + 1,
            },
        ] {
            assert!(invalid.write_query(&mut Writer::new()).is_err());
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&invalid.key.to_le_bytes());
            bytes[8..12].copy_from_slice(&invalid.image.to_le_bytes());
            assert_eq!(Key::read_query(&bytes, 0), Err(Status::BadSize));
        }
        for bad in [
            Key::FIRST,
            Key { key: 0, image: 1 },
            Key { key: 1, image: 0 },
            Key {
                key: 1,
                image: IMAGE_MAX + 1,
            },
        ] {
            assert!(bad.write_ack(&mut Writer::new()).is_err());
        }
    }

    #[test]
    fn all_map_counts_round_trip_with_exact_slots_and_length() {
        for count in 1..=4 {
            let reply = sample(count);
            let bytes = encoded(reply);
            assert_eq!(bytes.len(), HEADER + ENTRY * usize::from(count));
            assert_eq!(Reply::read(&bytes, usize::from(count)), Ok(reply));
            for cut in 0..bytes.len() {
                assert!(Reply::read(&bytes[..cut], usize::from(count)).is_err());
            }
            for handles in 0..=5 {
                if handles != usize::from(count) {
                    assert_eq!(Reply::read(&bytes, handles), Err(Status::BadSize));
                }
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert_eq!(
                Reply::read(&trailing, usize::from(count)),
                Err(Status::BadSize)
            );
        }
    }

    #[test]
    fn invalid_schema_fields_access_count_and_slot_are_rejected() {
        let bytes = encoded(sample(4));
        for (at, word) in [
            (4, 1u32),
            (12, 1),
            (16, 0),
            (40, 0),
            (56, 0),
            (60, 2),
            (64, 1),
            (68, 1),
        ] {
            let mut bad = bytes.clone();
            bad[at..at + 4].copy_from_slice(&word.to_le_bytes());
            assert_eq!(Reply::read(&bad, 4), Err(Status::BadSize), "offset {at}");
        }
        for (at, word) in [(8, 2u16), (10, 0), (10, 5)] {
            let mut bad = bytes.clone();
            bad[at..at + 2].copy_from_slice(&word.to_le_bytes());
            assert_eq!(Reply::read(&bad, 4), Err(Status::BadSize));
        }
    }

    #[test]
    fn receipt_binds_work_label_pid_and_exact_image() {
        let good = sample(1);
        let bytes = encoded(good);
        let label = Label {
            index: 7,
            generation: 3,
        };
        for wrong in [
            label.raw_at(1),
            label.exit_at(2),
            label.identity_at(2),
            label.loader_at(2),
            Label {
                index: 256,
                generation: 3,
            }
            .raw_at(2),
            Label {
                index: 7,
                generation: 0,
            }
            .raw_at(2),
            Label {
                index: 7,
                generation: crate::GENERATION_MAX + 1,
            }
            .raw_at(2),
        ] {
            let mut bad = bytes.clone();
            bad[24..32].copy_from_slice(&wrong.to_le_bytes());
            assert_eq!(Reply::read(&bad, 1), Err(Status::BadSize));
        }
        for (at, word) in [
            (32, 0u32),
            (32, good.receipt.pid + 1),
            (32, u32::MAX),
            (36, 0),
            (36, 1),
            (36, IMAGE_MAX + 1),
        ] {
            let mut bad = bytes.clone();
            bad[at..at + 4].copy_from_slice(&word.to_le_bytes());
            assert_eq!(Reply::read(&bad, 1), Err(Status::BadSize));
        }
    }

    #[test]
    fn ranges_allow_adjacency_and_reject_overlap_and_overflow() {
        let mut reply = sample(4);
        assert!(reply.validate().is_ok());
        reply.entries[1].address = reply.entries[0].address;
        assert_eq!(reply.validate(), Err(Status::BadSize));
        let mut reply = sample(1);
        reply.entries[0].address += 1;
        assert_eq!(reply.validate(), Err(Status::BadSize));
        reply.entries[0].address = u64::MAX - PAGE + 1;
        assert_eq!(reply.validate(), Err(Status::BadSize));
        reply.entries[0].address = PAGE;
        reply.entries[0].pages = 0;
        assert_eq!(reply.validate(), Err(Status::BadSize));
    }

    #[test]
    fn canonical_refusals_and_ack_have_no_handles_or_trailing_bytes() {
        for status in [
            Status::Ok,
            Status::BadSize,
            Status::UnknownMethod,
            Status::Kernel(abi::Error::BadState),
        ] {
            let bytes = proto_wire::reply(status);

            for cut in 0..8 {
                assert_eq!(read_ack_reply(&bytes[..cut], 0), Err(Status::BadSize));
            }
            let mut reserved = bytes;
            reserved[4] = 1;
            assert_eq!(read_ack_reply(&reserved, 0), Err(Status::BadSize));
            assert_eq!(
                read_ack_reply(&bytes, 0),
                if status == Status::Ok {
                    Ok(())
                } else {
                    Err(status)
                }
            );
            if status != Status::Ok {
                assert_eq!(Reply::read(&bytes, 0), Err(status));
            }
            assert_eq!(read_ack_reply(&bytes, 1), Err(Status::BadSize));
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert_eq!(read_ack_reply(&trailing, 0), Err(Status::BadSize));
            if status != Status::Ok {
                assert_eq!(Reply::read(&trailing, 0), Err(Status::BadSize));
            }
        }
    }
}
