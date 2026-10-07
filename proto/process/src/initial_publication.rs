// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private initial-image admission and memory publication envelopes.
//! Decoding validates values; runtime admission authenticates the sender,
//! current attempt and the actual Memory objects before accepting custody.

use crate::{Create, initial_map};
use bootimg::exec_bindings::{InitialSource, NONE};
use proto_wire::{Name, Reader, Status, Writer};

pub const ADMISSION: usize = 56;
pub const HEADER: usize = initial_map::HEADER + 16;
pub const MAX: usize = HEADER + initial_map::ENTRY * initial_map::ENTRIES;
const _: () = assert!(MAX + proto_wire::HEADER_LEN <= abi::MESSAGE_MAX);

fn source_valid(source: InitialSource) -> bool {
    source.artifact < bootimg::rootfs::FILES_MAX as u32
        && source.raw < bootimg::rootfs::FILES_MAX as u32
        && source.artifact != source.raw
        && source
            .canonical
            .is_none_or(|n| n < bootimg::rootfs::ENTRIES_MAX as u32)
}

fn write_source(source: InitialSource, w: &mut Writer) -> Result<(), Status> {
    if !source_valid(source) {
        return Err(Status::BadSize);
    }
    w.u32(source.artifact)?;
    w.u32(source.raw)?;
    w.u32(source.canonical.unwrap_or(NONE))?;
    w.u32(0)
}

fn read_source(r: &mut Reader<'_>) -> Result<InitialSource, Status> {
    let (artifact, raw, canonical, zero) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
    let source = InitialSource {
        artifact,
        raw,
        canonical: (canonical != NONE).then_some(canonical),
    };
    if zero != 0 || !source_valid(source) {
        return Err(Status::BadSize);
    }
    Ok(source)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    pub create: Create,
    pub program: Name,
    pub source: InitialSource,
}
impl Admission {
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        if self.create.ticket == 0
            || self.create.ceiling > 63
            || self.create.priority == 0
            || self.create.priority > self.create.ceiling
        {
            return Err(Status::BadSize);
        }
        self.create.write(w)?;
        w.name(Some(self.program))?;
        write_source(self.source, w)
    }
    /// The complete body and two actual start/witness channels.
    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if bytes.len() != ADMISSION || handles != 2 {
            return Err(Status::BadSize);
        }
        let create = Create::read(Reader::new(&bytes[..24]))?;
        if create.ticket == 0 {
            return Err(Status::BadSize);
        }
        let mut r = Reader::new(&bytes[24..]);
        let program = r.name()?.ok_or(Status::BadSize)?;
        let source = read_source(&mut r)?;
        r.finish()?;
        Ok(Self {
            create,
            program,
            source,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publication {
    pub map: initial_map::Reply,
    pub source: InitialSource,
}
impl Publication {
    pub fn validate(&self) -> Result<(), Status> {
        self.map.validate()?;
        if !source_valid(self.source) {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        w.bytes(&proto_wire::reply(Status::Ok))?;
        w.u16(initial_map::SCHEMA)?;
        w.u16(self.map.count)?;
        w.u32(0)?;
        w.u64(self.map.receipt.key.key)?;
        w.u64(self.map.receipt.label)?;
        w.u32(self.map.receipt.pid)?;
        w.u32(self.map.receipt.key.image)?;
        w.u64(self.map.receipt.init_ticket)?;
        write_source(self.source, w)?;
        for e in &self.map.entries[..usize::from(self.map.count)] {
            w.u64(e.address)?;
            w.u32(e.pages)?;
            w.u32(e.access.raw() as u32)?;
            w.u32(e.slot)?;
            w.u32(0)?;
        }
        Ok(())
    }
    pub fn read(bytes: &[u8], handles: usize) -> Result<Self, Status> {
        if !(HEADER..=MAX).contains(&bytes.len()) {
            return Err(Status::BadSize);
        }
        let mut source_reader = Reader::new(&bytes[initial_map::HEADER..HEADER]);
        let source = read_source(&mut source_reader)?;
        source_reader.finish()?;
        // Reuse the accepted map decoder with a bounded 144-byte body.
        let mut body = [0; initial_map::HEADER + initial_map::ENTRY * initial_map::ENTRIES];
        body[..initial_map::HEADER].copy_from_slice(&bytes[..initial_map::HEADER]);
        let entries = &bytes[HEADER..];
        body[initial_map::HEADER..initial_map::HEADER + entries.len()].copy_from_slice(entries);
        let map = initial_map::Reply::read(&body[..initial_map::HEADER + entries.len()], handles)?;
        Ok(Self { map, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Label,
        initial_map::{ENTRIES, Entry, Key, PAGE, Receipt, Reply},
    };
    use abi::Access;

    pub(crate) fn fixture(count: u16) -> Publication {
        let label = Label {
            index: 7,
            generation: 3,
        };
        let mut map = Reply {
            receipt: Receipt {
                key: Key { key: 19, image: 1 },
                label: label.raw_at(1),
                pid: label.pid(),
                init_ticket: 23,
            },
            count,
            entries: [Entry::EMPTY; ENTRIES],
        };
        for (slot, e) in map.entries[..usize::from(count)].iter_mut().enumerate() {
            *e = Entry {
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
        Publication {
            map,
            source: InitialSource {
                artifact: 5,
                raw: 12,
                canonical: Some(3),
            },
        }
    }
    #[test]
    fn admissions_round_trip_and_require_original_envelope() {
        let a = Admission {
            create: Create {
                quota: 4096,
                handle_limit: 32,
                ceiling: 31,
                priority: 30,
                root: true,
                ticket: 23,
            },
            program: Name::new(b"posix-probe").unwrap(),
            source: fixture(1).source,
        };
        let mut w = Writer::new();
        a.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), ADMISSION);
        assert_eq!(Admission::read(w.as_bytes(), 2), Ok(a));
        for cut in 0..ADMISSION {
            assert!(Admission::read(&w.as_bytes()[..cut], 2).is_err());
        }
        for caps in [0, 1, 3, 4] {
            assert!(Admission::read(w.as_bytes(), caps).is_err());
        }
        let mut b = w.as_bytes().to_vec();
        b.push(0);
        assert!(Admission::read(&b, 2).is_err());
        for offset in [15, 52] {
            let mut b = w.as_bytes().to_vec();
            b[offset] = 1;
            assert!(Admission::read(&b, 2).is_err());
        }
        let mut b = w.as_bytes().to_vec();
        b[16..24].fill(0);
        assert!(Admission::read(&b, 2).is_err());
        let mut b = w.as_bytes().to_vec();
        b[24..40].fill(0);
        assert!(Admission::read(&b, 2).is_err());
        let mut bad = a;
        bad.create.priority = 0;
        assert!(bad.write(&mut Writer::new()).is_err());
    }
    #[test]
    fn publications_round_trip_and_check_every_cut_and_cap_count() {
        for count in 1..=4 {
            let p = fixture(count);
            let mut w = Writer::new();
            p.write(&mut w).unwrap();
            assert_eq!(
                w.as_bytes().len(),
                HEADER + usize::from(count) * initial_map::ENTRY
            );
            assert_eq!(Publication::read(w.as_bytes(), usize::from(count)), Ok(p));
            for cut in 0..w.as_bytes().len() {
                assert!(Publication::read(&w.as_bytes()[..cut], usize::from(count)).is_err());
            }
            for caps in 0..=4 {
                if caps != usize::from(count) {
                    assert!(Publication::read(w.as_bytes(), caps).is_err());
                }
            }
            let mut b = w.as_bytes().to_vec();
            b.push(0);
            assert!(Publication::read(&b, usize::from(count)).is_err());
        }
    }
    #[test]
    fn publication_rejects_invalid_source_receipt_and_ranges() {
        let p = fixture(2);
        let mut w = Writer::new();
        p.write(&mut w).unwrap();
        for offset in [4, 12, 60, 84] {
            let mut b = w.as_bytes().to_vec();
            b[offset] = 1;
            assert!(Publication::read(&b, 2).is_err());
        }
        for offset in [48, 52, 56] {
            let mut b = w.as_bytes().to_vec();
            b[offset..offset + 4].copy_from_slice(&1024_u32.to_le_bytes());
            assert!(Publication::read(&b, 2).is_err());
        }
        let mut b = w.as_bytes().to_vec();
        b[52..56].copy_from_slice(&5_u32.to_le_bytes());
        assert!(Publication::read(&b, 2).is_err());
        let mut bad = p;
        bad.map.entries[1].address = PAGE;
        assert!(bad.write(&mut Writer::new()).is_err());
        let mut b = w.as_bytes().to_vec();
        b[88..96].copy_from_slice(&PAGE.to_le_bytes());
        assert!(Publication::read(&b, 2).is_err());
        let mut b = w.as_bytes().to_vec();
        b[16..24].fill(0);
        assert!(Publication::read(&b, 2).is_err());
        let mut b = w.as_bytes().to_vec();
        b[0] = 1;
        assert!(Publication::read(&b, 2).is_err());
    }
}
