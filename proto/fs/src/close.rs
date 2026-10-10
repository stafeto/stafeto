// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact numeric close events have their own sixteen replay domains.

use crate::{
    INVALID_ARGUMENT, Method, OPEN_DESCRIPTION_MASK, OPEN_DESCRIPTION_SHIFT, OPEN_FD_MASK,
};
use proto_wire::{Reader, Status, Writer};

pub const CLOSE_KEY_PLACES: usize = 16;
pub const CLOSE_KEY_FIRST: u32 = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseKey {
    pub slot: u32,
    pub generation: u64,
}
impl CloseKey {
    pub fn validate(self) -> Result<usize, u32> {
        let index = self
            .slot
            .checked_sub(CLOSE_KEY_FIRST)
            .ok_or(INVALID_ARGUMENT)?;
        if index as usize >= CLOSE_KEY_PLACES || self.generation == 0 {
            return Err(INVALID_ARGUMENT);
        }
        Ok(index as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseEvent {
    pub key: CloseKey,
    pub packed: u32,
    pub description_generation: u64,
    pub last_alias: bool,
}
impl CloseEvent {
    pub fn validate(self) -> Result<usize, u32> {
        let index = self.key.validate()?;
        if self.packed & !(OPEN_FD_MASK | OPEN_DESCRIPTION_MASK) != 0
            || !(3..35).contains(&(self.packed & OPEN_FD_MASK))
            || (self.packed & OPEN_DESCRIPTION_MASK) >> OPEN_DESCRIPTION_SHIFT >= 128
            || self.description_generation == 0
        {
            return Err(INVALID_ARGUMENT);
        }
        Ok(index)
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.validate().map_err(Status::from_code)?;
        Method::CloseEvent.header().write(out)?;
        out.u32(self.key.slot)?;
        out.u64(self.key.generation)?;
        out.u32(self.packed)?;
        out.u64(self.description_generation)?;
        out.u32(u32::from(self.last_alias))
    }
    pub fn read(mut body: Reader<'_>) -> Result<Self, Status> {
        let key = CloseKey {
            slot: body.u32()?,
            generation: body.u64()?,
        };
        let packed = body.u32()?;
        let description_generation = body.u64()?;
        let last_alias = body.u32()?;
        body.finish()?;
        if last_alias > 1 {
            return Err(Status::BadSize);
        }
        let event = Self {
            key,
            packed,
            description_generation,
            last_alias: last_alias != 0,
        };
        event.validate().map_err(Status::from_code)?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> CloseEvent {
        CloseEvent {
            key: CloseKey {
                slot: 48,
                generation: 9,
            },
            packed: 3 | 127 << OPEN_DESCRIPTION_SHIFT,
            description_generation: 11,
            last_alias: true,
        }
    }
    #[test]
    fn close_domains_are_separate_from_every_existing_job_key() {
        for slot in 0..48 {
            assert!(
                CloseKey {
                    slot,
                    generation: 1
                }
                .validate()
                .is_err()
            );
        }
        for slot in 48..64 {
            assert_eq!(
                CloseKey {
                    slot,
                    generation: u64::MAX
                }
                .validate(),
                Ok((slot - 48) as usize)
            );
            assert!(
                crate::OpenKey {
                    slot,
                    generation: 1
                }
                .validate()
                .is_err()
            );
            assert!(
                CloseKey {
                    slot,
                    generation: 0
                }
                .validate()
                .is_err()
            );
        }
        for slot in [64, u32::MAX] {
            assert!(
                CloseKey {
                    slot,
                    generation: 1
                }
                .validate()
                .is_err()
            );
        }
    }
    #[test]
    fn exact_close_event_roundtrips_with_its_new_method_and_version() {
        for last_alias in [false, true] {
            let event = CloseEvent {
                last_alias,
                ..event()
            };
            let mut out = Writer::new();
            event.write(&mut out).unwrap();
            let mut input = Reader::new(out.as_bytes());
            assert_eq!(
                crate::Header::read(&mut input).unwrap(),
                Method::CloseEvent.header()
            );
            assert_eq!(CloseEvent::read(input), Ok(event));
            assert_eq!(out.as_bytes().len(), proto_wire::HEADER_LEN + 28);
        }
        assert_eq!(Method::from_number(49), Some(Method::CloseEvent));
    }
    #[test]
    fn close_events_reject_invalid_descriptors_and_never_publish_partial_requests() {
        for packed in [
            2,
            35,
            3 | 128 << OPEN_DESCRIPTION_SHIFT,
            event().packed | crate::OPEN_RANDOM,
            u32::MAX,
        ] {
            let mut out = Writer::new();
            assert!(CloseEvent { packed, ..event() }.write(&mut out).is_err());
            assert!(out.as_bytes().is_empty());
        }
        assert!(
            CloseEvent {
                description_generation: 0,
                ..event()
            }
            .validate()
            .is_err()
        );
    }
    #[test]
    fn close_event_body_rejects_truncation_extra_bytes_and_noncanonical_boolean() {
        let mut out = Writer::new();
        event().write(&mut out).unwrap();
        let body = &out.as_bytes()[proto_wire::HEADER_LEN..];
        for len in 0..body.len() {
            assert!(CloseEvent::read(Reader::new(&body[..len])).is_err());
        }
        let mut bad = [0; 29];
        bad[..28].copy_from_slice(body);
        assert!(CloseEvent::read(Reader::new(&bad)).is_err());
        bad[24..28].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            CloseEvent::read(Reader::new(&bad[..28])),
            Err(Status::BadSize)
        );
    }
}
