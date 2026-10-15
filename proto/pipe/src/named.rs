// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{Method, NONBLOCK, WRITE_END};
use proto_wire::{Reader, Status, Writer};

pub const NAMED_END: u32 = 1 << 31;
pub const RAM_BROKER: u64 = 1 << 61;
pub const NAMED_MAX: usize = 128;
pub const NAMED_ROOT_MAX: usize = 96;
pub const NAMED_MAX_WRITE: usize = crate::MAX_WRITE - 8;
const _: () = assert!(crate::ATOMIC <= NAMED_MAX_WRITE);
pub const APPEND: u32 = 4;
pub const NO_READER: u32 = 707;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Endpoint {
    pub id: u32,
    pub generation: u64,
}
impl Endpoint {
    pub const fn anonymous(id: u32) -> Self {
        Self { id, generation: 0 }
    }
    pub const fn named(slot: u32, generation: u64) -> Self {
        Self {
            id: NAMED_END | slot,
            generation,
        }
    }
    /// A socket of the service: `SOCK_END | slot`, no generation.
    pub const fn socket(slot: u32) -> Self {
        Self {
            id: crate::sock::SOCK_END | slot,
            generation: 0,
        }
    }
    pub const fn is_named(self) -> bool {
        self.id & NAMED_END != 0
    }
    pub const fn is_sock(self) -> bool {
        self.id & crate::sock::SOCK_END != 0 && self.id & NAMED_END == 0
    }
    pub const fn slot(self) -> usize {
        (self.id & !(NAMED_END | crate::sock::SOCK_END)) as usize
    }
    const fn valid(self) -> bool {
        self.slot() < NAMED_MAX
            && self.is_named() == (self.generation != 0)
            && (self.id & crate::sock::SOCK_END == 0
                || (self.id & NAMED_END == 0 && self.slot() < crate::sock::SOCKETS))
    }
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        w.u32(self.id)?;
        if self.is_named() {
            w.u64(self.generation)?;
        }
        Ok(())
    }
    pub fn parse(r: &mut Reader<'_>) -> Result<Self, Status> {
        let id = r.u32()?;
        let generation = if id & NAMED_END != 0 { r.u64()? } else { 0 };
        let endpoint = Self { id, generation };
        if !endpoint.valid() {
            return Err(Status::BadSize);
        }
        Ok(endpoint)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NamedTicket {
    pub slot: u32,
    pub generation: u64,
}
impl NamedTicket {
    /// Resident Open records use public slots 32 through 47 in the shared key domain.
    pub const fn is_open_key(self) -> bool {
        self.slot >= 32 && self.slot < 48 && self.generation != 0
    }

    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.slot)?;
        w.u64(self.generation)
    }
    pub fn read(r: &mut Reader<'_>) -> Result<Self, Status> {
        let value = Self {
            slot: r.u32()?,
            generation: r.u64()?,
        };
        if value.generation == 0 {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
    pub fn parse(mut r: Reader<'_>) -> Result<Self, Status> {
        let value = Self::read(&mut r)?;
        r.finish()?;
        Ok(value)
    }
    pub fn request(self, method: Method, w: &mut Writer) -> Result<(), Status> {
        method.header().write(w)?;
        self.write(w)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerPrepare {
    pub ticket: NamedTicket,
    pub client: u64,
    pub open: NamedTicket,
    pub inode: NamedTicket,
    pub flags: u32,
}
impl BrokerPrepare {
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        Method::BrokerPrepare.header().write(w)?;
        self.ticket.write(w)?;
        w.u64(self.client)?;
        self.open.write(w)?;
        self.inode.write(w)?;
        w.u32(self.flags)
    }
    pub fn parse(mut r: Reader<'_>) -> Result<Self, Status> {
        let value = Self {
            ticket: NamedTicket::read(&mut r)?,
            client: r.u64()?,
            open: NamedTicket::read(&mut r)?,
            inode: NamedTicket::read(&mut r)?,
            flags: r.u32()?,
        };
        r.finish()?;
        if !value.open.is_open_key() || value.flags & !(NONBLOCK | WRITE_END | APPEND) != 0 {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerCancel {
    pub client: u64,
    pub open: NamedTicket,
}
impl BrokerCancel {
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        Method::BrokerCancel.header().write(w)?;
        w.u64(self.client)?;
        self.open.write(w)
    }
    pub fn parse(mut r: Reader<'_>) -> Result<Self, Status> {
        let value = Self {
            client: r.u64()?,
            open: NamedTicket::read(&mut r)?,
        };
        r.finish()?;
        if !value.open.is_open_key() {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum NamedPhase {
    #[default]
    Witness = 0,
    Grant = 1,
    Waiting = 2,
    Ready = 3,
    Taken = 4,
    Failed = 5,
    Cancelled = 6,
    Preparing = 7,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedReply {
    pub ticket: NamedTicket,
    pub phase: NamedPhase,
    pub result: u32,
    pub endpoint: Endpoint,
}
impl NamedReply {
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        w.u32(0)?;
        self.ticket.write(w)?;
        w.u32(self.phase as u32)?;
        w.u32(self.result)?;
        w.u32(self.endpoint.id)?;
        w.u64(self.endpoint.generation)
    }
    pub fn parse(mut r: Reader<'_>) -> Result<Self, Status> {
        let code = r.u32()?;
        if code != 0 {
            return Err(Status::from_code(code));
        }
        let ticket = NamedTicket::read(&mut r)?;
        let phase = match r.u32()? {
            0 => NamedPhase::Witness,
            1 => NamedPhase::Grant,
            2 => NamedPhase::Waiting,
            3 => NamedPhase::Ready,
            4 => NamedPhase::Taken,
            5 => NamedPhase::Failed,
            6 => NamedPhase::Cancelled,
            7 => NamedPhase::Preparing,
            _ => return Err(Status::BadSize),
        };
        let result = r.u32()?;
        let endpoint = Endpoint {
            id: r.u32()?,
            generation: r.u64()?,
        };
        r.finish()?;
        if endpoint != Endpoint::default()
            && (!endpoint.is_named() || endpoint.slot() >= NAMED_MAX || endpoint.generation == 0)
        {
            return Err(Status::BadSize);
        }
        Ok(Self {
            ticket,
            phase,
            result,
            endpoint,
        })
    }
}

/// Readiness requests retain a full generation for every named item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchSet {
    pub len: usize,
    pub items: [proto_wire::watch::Item; proto_wire::watch::MAX],
    pub generations: [u64; proto_wire::watch::MAX],
}
impl Default for WatchSet {
    fn default() -> Self {
        Self::new()
    }
}
impl WatchSet {
    pub const fn new() -> Self {
        Self {
            len: 0,
            items: [proto_wire::watch::Item {
                description: 0,
                events: 0,
            }; proto_wire::watch::MAX],
            generations: [0; proto_wire::watch::MAX],
        }
    }
    pub fn endpoint(&self, i: usize) -> Endpoint {
        Endpoint {
            id: self.items[i].description,
            generation: self.generations[i],
        }
    }
    pub fn parse(mut body: Reader<'_>) -> Result<Self, Status> {
        let mut set = Self::new();
        set.len = body.u32()? as usize;
        if set.len == 0 || set.len > set.items.len() {
            return Err(Status::BadSize);
        }
        for i in 0..set.len {
            let endpoint = Endpoint::parse(&mut body)?;
            let events = body.u32()?;
            if events & !proto_wire::watch::EVENTS != 0 {
                return Err(Status::BadSize);
            }
            set.items[i] = proto_wire::watch::Item {
                description: endpoint.id,
                events,
            };
            set.generations[i] = endpoint.generation;
        }
        body.finish()?;
        Ok(set)
    }
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.len == 0 || self.len > self.items.len() {
            return Err(Status::BadSize);
        }
        w.u32(self.len as u32)?;
        for i in 0..self.len {
            self.endpoint(i).write(w)?;
            if self.items[i].events & !proto_wire::watch::EVENTS != 0 {
                return Err(Status::BadSize);
            }
            w.u32(self.items[i].events)?;
        }
        Ok(())
    }
    pub fn endpoints(&self) -> impl Iterator<Item = Endpoint> + '_ {
        (0..self.len)
            .filter(move |&i| !(0..i).any(|j| self.endpoint(j) == self.endpoint(i)))
            .map(|i| self.endpoint(i))
    }
    pub fn ready(&self, mut readiness: impl FnMut(Endpoint) -> u32) -> proto_wire::watch::Ready {
        let mut ready = proto_wire::watch::Ready {
            len: self.len,
            events: [0; proto_wire::watch::MAX],
        };
        for i in 0..self.len {
            ready.events[i] =
                readiness(self.endpoint(i)) & (self.items[i].events | proto_wire::watch::ALWAYS);
        }
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_captures_the_existing_resident_open_key_domain() {
        for slot in [0, 15, 31, 32, 47, 48] {
            let open = NamedTicket {
                slot,
                generation: 0x2_0000_0001,
            };
            let prepare = BrokerPrepare {
                ticket: NamedTicket {
                    slot: 3,
                    generation: 1,
                },
                client: 99,
                open,
                inode: NamedTicket {
                    slot: 5,
                    generation: 1,
                },
                flags: NONBLOCK | WRITE_END,
            };
            let cancel = BrokerCancel { client: 99, open };
            let mut wire = Writer::new();
            prepare.write(&mut wire).unwrap();
            let parsed_prepare =
                BrokerPrepare::parse(Reader::new(&wire.as_bytes()[proto_wire::HEADER_LEN..]));
            let mut wire = Writer::new();
            cancel.write(&mut wire).unwrap();
            let parsed_cancel =
                BrokerCancel::parse(Reader::new(&wire.as_bytes()[proto_wire::HEADER_LEN..]));
            if (32..48).contains(&slot) {
                assert!(open.is_open_key());
                assert_eq!(parsed_prepare, Ok(prepare));
                assert_eq!(parsed_cancel, Ok(cancel));
            } else {
                assert!(!open.is_open_key());
                assert_eq!(parsed_prepare, Err(Status::BadSize));
                assert_eq!(parsed_cancel, Err(Status::BadSize));
            }
        }
    }

    #[test]
    fn named_wire_keeps_full_generations_and_maximum_atomic_payload() {
        let endpoint = Endpoint::named(127, 0xfedc_ba98_7654_3210);
        let mut w = Writer::new();
        endpoint.write(&mut w).unwrap();
        assert_eq!(
            Endpoint::parse(&mut Reader::new(w.as_bytes())),
            Ok(endpoint)
        );
        assert_eq!(
            Endpoint::parse(&mut Reader::new(&w.as_bytes()[..4])),
            Err(Status::BadSize)
        );
        let reply = NamedReply {
            ticket: NamedTicket {
                slot: 127,
                generation: 0x2_0000_0001,
            },
            phase: NamedPhase::Taken,
            result: 0,
            endpoint,
        };
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 36);
        assert_eq!(NamedReply::parse(Reader::new(w.as_bytes())), Ok(reply));
        for count in [NAMED_MAX_WRITE, NAMED_MAX_WRITE + 1] {
            let bytes = [0x5a; NAMED_MAX_WRITE + 1];
            let mut w = Writer::new();
            endpoint.write(&mut w).unwrap();
            w.bytes(&bytes[..count]).unwrap();
            let parsed = crate::Write::parse_endpoint(Reader::new(w.as_bytes()), false);
            if count == NAMED_MAX_WRITE {
                assert!(parsed.is_ok());
            } else {
                assert_eq!(parsed, Err(Status::BadSize));
            }
        }
    }

    #[test]
    fn watches_distinguish_same_slot_different_generations() {
        let mut set = WatchSet::new();
        set.len = 3;
        for i in 0..3 {
            set.items[i].description = NAMED_END | 7;
            set.items[i].events = proto_wire::watch::IN;
            set.generations[i] = if i == 1 { 0x2_0000_0001 } else { 0x1_0000_0001 };
        }
        let mut w = Writer::new();
        set.write(&mut w).unwrap();
        assert_eq!(WatchSet::parse(Reader::new(w.as_bytes())), Ok(set));
        assert_eq!(set.endpoints().count(), 2);
        let ready = set.ready(|e| {
            if e.generation == 0x2_0000_0001 {
                proto_wire::watch::NVAL
            } else {
                proto_wire::watch::IN
            }
        });
        assert_eq!(
            &ready.events[..3],
            &[
                proto_wire::watch::IN,
                proto_wire::watch::NVAL,
                proto_wire::watch::IN
            ]
        );
    }
}
