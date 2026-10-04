// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{ExpenditureRoot, IMAGE_MAX, LoaderOf, RECORDS, WhoReply};
use proto_wire::{Reader, Status, Writer};

// RetainedLoader is additive in VERSION10. Vouch21 and WhoReply252 retain
// their ordinary contract. Success is status0/kind plus Who252 (260 bytes,
// no handles); errors are status/nonzero plus zero (8 bytes, no handles).

/// A retained snapshot accompanies a genuine loader identity capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedLoader {
    pub pid: u32,
    pub index: u32,
    pub image: u32,
    pub ticket: u64,
    pub root: ExpenditureRoot,
}
impl RetainedLoader {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(1)?;
        w.u32(self.pid)?;
        w.u32(self.index)?;
        w.u32(self.image)?;
        w.u64(self.ticket)?;
        w.u32(self.root.pid)?;
        w.u32(self.root.generation)
    }
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        if r.u32()? != 1 {
            return Err(Status::BadSize);
        }
        let value = Self {
            pid: r.u32()?,
            index: r.u32()?,
            image: r.u32()?,
            ticket: r.u64()?,
            root: ExpenditureRoot {
                pid: r.u32()?,
                generation: r.u32()?,
            },
        };
        r.finish()?;
        if value.pid == 0
            || value.pid > i32::MAX as u32
            || value.index as usize >= RECORDS
            || value.pid % RECORDS as u32 != value.index
            || value.image == 0
            || value.image > IMAGE_MAX
            || value.ticket == 0
            || value.root.pid == 0
            || value.root.generation == 0
        {
            return Err(Status::BadSize);
        }
        Ok(value)
    }
    pub fn matches(&self, who: &WhoReply) -> bool {
        self.pid == who.pid
            && self.index == who.index
            && self.image == who.image
            && self.root == who.root
            && who.loader
                == Some(LoaderOf {
                    image: self.image,
                    ticket: self.ticket,
                })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedLoaderState {
    Loading = 1,
    Handoff = 2,
}
/// Handoff proves capture retention and owner life, with no file authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedLoaderReply {
    pub state: RetainedLoaderState,
    pub who: WhoReply,
}
impl RetainedLoaderReply {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(0)?;
        w.u32(self.state as u32)?;
        self.who.write(w)
    }
    pub fn read(bytes: &[u8]) -> Result<Self, Status> {
        let mut r = Reader::new(bytes);
        let status = r.u32()?;
        if status != 0 {
            if r.u32()? != 0 {
                return Err(Status::BadSize);
            }
            r.finish()?;
            return Err(Status::from_code(status));
        }
        if bytes.len() != 260 {
            return Err(Status::BadSize);
        }
        let state = match r.u32()? {
            1 => RetainedLoaderState::Loading,
            2 => RetainedLoaderState::Handoff,
            _ => return Err(Status::BadSize),
        };
        let who = WhoReply::read(r.bytes(252)?)?;
        r.finish()?;
        if who.loader.is_none() {
            return Err(Status::BadSize);
        }
        Ok(Self { state, who })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Credentials, Groups, ResourceLimits};

    fn snapshot() -> WhoReply {
        WhoReply {
            pid: 300,
            index: 44,
            image: 2,
            loader: Some(LoaderOf {
                image: 2,
                ticket: 9,
            }),
            credentials: Credentials::NOBODY,
            generation: 7,
            ctty: None,
            groups: Groups::EMPTY,
            limits: ResourceLimits::initial(4096),
            root: ExpenditureRoot {
                pid: 300,
                generation: 1,
            },
        }
    }

    #[test]
    fn retained_request_has_one_fixed_purpose_and_complete_snapshot() {
        let who = snapshot();
        let request = RetainedLoader {
            pid: who.pid,
            index: who.index,
            image: who.image,
            ticket: who.loader.unwrap().ticket,
            root: who.root,
        };
        let mut w = Writer::new();
        request.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 32);
        assert_eq!(RetainedLoader::read(Reader::new(w.as_bytes())), Ok(request));
        assert!(request.matches(&who));
        for at in [0, 4, 12, 16, 24, 28] {
            let mut bytes = w.as_bytes().to_vec();
            bytes[at..at + 4].fill(0);
            assert_eq!(
                RetainedLoader::read(Reader::new(&bytes)),
                Err(Status::BadSize)
            );
        }
        let mut extra = w.as_bytes().to_vec();
        extra.push(0);
        assert_eq!(
            RetainedLoader::read(Reader::new(&extra)),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn handoff_reply_is_typed_and_errors_use_the_canonical_envelope() {
        for state in [RetainedLoaderState::Loading, RetainedLoaderState::Handoff] {
            let reply = RetainedLoaderReply {
                state,
                who: snapshot(),
            };
            let mut w = Writer::new();
            reply.write(&mut w).unwrap();
            assert_eq!(w.as_bytes().len(), 260);
            assert_eq!(RetainedLoaderReply::read(w.as_bytes()), Ok(reply));
            assert_eq!(WhoReply::read(w.as_bytes()), Err(Status::BadSize));
            let mut bytes = w.as_bytes().to_vec();
            bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
            assert_eq!(RetainedLoaderReply::read(&bytes), Err(Status::BadSize));
            assert_eq!(
                RetainedLoaderReply::read(&w.as_bytes()[..252]),
                Err(Status::BadSize)
            );
            let mut ordinary = reply;
            ordinary.who.loader = None;
            let mut w = Writer::new();
            ordinary.write(&mut w).unwrap();
            assert_eq!(
                RetainedLoaderReply::read(w.as_bytes()),
                Err(Status::BadSize)
            );
        }
        let mut w = Writer::new();
        w.bytes(&proto_wire::reply(Status::from_code(crate::PERMISSION)))
            .unwrap();
        assert_eq!(
            RetainedLoaderReply::read(w.as_bytes()),
            Err(Status::from_code(crate::PERMISSION))
        );
        assert_eq!(
            RetainedLoaderReply::read(&w.as_bytes()[..4]),
            Err(Status::BadSize)
        );
    }
}
