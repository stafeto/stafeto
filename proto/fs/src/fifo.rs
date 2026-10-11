// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact hidden-open custody for a named pipe grant.

use crate::{Method, OpenKey};
use proto_wire::{Reader, Status, Writer};

/// The original Open and both full description generations precede transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FifoGrant {
    pub key: OpenKey,
    pub fd: u32,
    pub generation: u64,
    pub ticket_slot: u32,
    pub ticket_generation: u64,
    /// Pipe NONBLOCK, WRITE_END and APPEND bits.
    pub flags: u32,
}
impl FifoGrant {
    pub fn validate(self) -> Result<(), Status> {
        if !(32..48).contains(&self.key.slot)
            || self.key.generation == 0
            || self.generation == 0
            || self.ticket_slot >= 128
            || self.ticket_generation == 0
            || self.flags & !7 != 0
        {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        Method::OpenFifoGrant.header().write(w)?;
        w.u32(self.key.slot)?;
        w.u64(self.key.generation)?;
        w.u32(self.fd)?;
        w.u64(self.generation)?;
        w.u32(self.ticket_slot)?;
        w.u64(self.ticket_generation)?;
        w.u32(self.flags)
    }
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let value = Self {
            key: OpenKey {
                slot: r.u32()?,
                generation: r.u64()?,
            },
            fd: r.u32()?,
            generation: r.u64()?,
            ticket_slot: r.u32()?,
            ticket_generation: r.u64()?,
            flags: r.u32()?,
        };
        r.finish()?;
        value.validate()?;
        Ok(value)
    }
}

/// Transfer cancellation custody after the exact endpoint has been retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FifoAck {
    pub key: OpenKey,
    pub ticket_slot: u32,
    pub ticket_generation: u64,
}
impl FifoAck {
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        Method::OpenFifoAck.header().write(w)?;
        w.u32(self.key.slot)?;
        w.u64(self.key.generation)?;
        w.u32(self.ticket_slot)?;
        w.u64(self.ticket_generation)
    }
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let value = Self {
            key: OpenKey {
                slot: r.u32()?,
                generation: r.u64()?,
            },
            ticket_slot: r.u32()?,
            ticket_generation: r.u64()?,
        };
        r.finish()?;
        if !(32..48).contains(&value.key.slot)
            || value.key.generation == 0
            || value.ticket_slot >= 128
            || value.ticket_generation == 0
        {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grant_preserves_both_generations_and_rejects_unpaid_places() {
        let request = FifoGrant {
            key: OpenKey {
                slot: 47,
                generation: u64::MAX,
            },
            fd: 0x1234,
            generation: u64::MAX - 1,
            ticket_slot: 127,
            ticket_generation: u64::MAX - 2,
            flags: 7,
        };
        let mut wire = Writer::new();
        request.write(&mut wire).unwrap();
        assert_eq!(
            FifoGrant::read(Reader::new(&wire.as_bytes()[proto_wire::HEADER_LEN..])),
            Ok(request)
        );
        assert_eq!(
            FifoGrant {
                key: OpenKey {
                    slot: 32,
                    ..request.key
                },
                ..request
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            FifoGrant {
                key: OpenKey {
                    slot: 31,
                    ..request.key
                },
                ..request
            }
            .validate(),
            Err(Status::BadSize)
        );
        for bad in [
            FifoGrant {
                key: OpenKey {
                    slot: 48,
                    ..request.key
                },
                ..request
            },
            FifoGrant {
                generation: 0,
                ..request
            },
            FifoGrant {
                ticket_generation: 0,
                ..request
            },
            FifoGrant {
                ticket_slot: 128,
                ..request
            },
            FifoGrant {
                flags: 8,
                ..request
            },
        ] {
            assert_eq!(bad.validate(), Err(Status::BadSize));
        }
    }
    #[test]
    fn ack_is_exact_and_has_no_optional_tail() {
        let ack = FifoAck {
            key: OpenKey {
                slot: 32,
                generation: 99,
            },
            ticket_slot: 127,
            ticket_generation: u64::MAX,
        };
        let mut wire = Writer::new();
        ack.write(&mut wire).unwrap();
        assert_eq!(
            FifoAck::read(Reader::new(&wire.as_bytes()[proto_wire::HEADER_LEN..])),
            Ok(ack)
        );
        wire.u32(0).unwrap();
        assert_eq!(
            FifoAck::read(Reader::new(&wire.as_bytes()[proto_wire::HEADER_LEN..])),
            Err(Status::BadSize)
        );
    }
}
