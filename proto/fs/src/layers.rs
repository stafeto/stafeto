// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer session: attach a package file as a layer of the tree, or
//! detach it, in portions. `LayerStart` begins either operation and
//! `LayerStep` continues the one running while the reply says RESOLVING.
//! Only the session that init labels `LAYERS` may use them.

use crate::{BAD_LAYER, BAD_MODE, CONFLICT, INVALID_ARGUMENT, Method, RESOLVING};

const OK: u32 = 0;
use proto_wire::{Reader, Status, Writer};

/// The layer numbers a client may name: 1 to `LAYER_NUMBER_MAX`. Numbers from
/// 0x8000 up belong to the layers of the boot image.
pub const LAYER_NUMBER_MAX: u32 = 0x7FFF;
/// The first number of a layer that the service attached from the boot image.
pub const IMAGE_LAYER_FIRST: u32 = 0x8000;

/// What `LayerStart` begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LayerOp {
    /// With two descriptors: a memory object holding the package file
    /// (read access, no write access) and a channel for the notification
    /// that the layer is released.
    Attach = 1,
    /// With no descriptor.
    Detach = 2,
}

impl LayerOp {
    fn read(value: u32) -> Result<Self, Status> {
        match value {
            1 => Ok(Self::Attach),
            2 => Ok(Self::Detach),
            _ => Err(Status::from_code(INVALID_ARGUMENT)),
        }
    }
}

/// The body of `LayerStart`: `op`, `layer` and `level` as u32 each. `level`
/// is the level the service's mapping thread works at for an attach (1 and
/// above) and 0 for a detach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerStart {
    pub op: LayerOp,
    pub layer: u32,
    pub level: u32,
}

impl LayerStart {
    pub fn validate(self) -> Result<(), Status> {
        let level_ok = match self.op {
            LayerOp::Attach => self.level >= 1,
            LayerOp::Detach => self.level == 0,
        };
        if !(1..=LAYER_NUMBER_MAX).contains(&self.layer) || !level_ok {
            return Err(Status::from_code(INVALID_ARGUMENT));
        }
        Ok(())
    }

    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        Method::LayerStart.header().write(out)?;
        out.u32(self.op as u32)?;
        out.u32(self.layer)?;
        out.u32(self.level)
    }

    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let start = Self {
            op: LayerOp::read(input.u32()?)?,
            layer: input.u32()?,
            level: input.u32()?,
        };
        input.finish()?;
        start.validate()?;
        Ok(start)
    }
}

/// The body of `LayerStep`: the layer number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerStep {
    pub layer: u32,
}

impl LayerStep {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if !(1..=LAYER_NUMBER_MAX).contains(&self.layer) {
            return Err(Status::from_code(INVALID_ARGUMENT));
        }
        Method::LayerStep.header().write(out)?;
        out.u32(self.layer)
    }

    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let step = Self {
            layer: input.u32()?,
        };
        input.finish()?;
        if !(1..=LAYER_NUMBER_MAX).contains(&step.layer) {
            return Err(Status::from_code(INVALID_ARGUMENT));
        }
        Ok(step)
    }
}

/// The reply to either method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerReply {
    /// The layer has more steps: send `LayerStep`.
    Resolving,
    /// Done; `names` is the number of names the operation put in the tree or
    /// took out of it.
    Done { names: u32 },
    /// Refused because of entry `entry` of the layer's table (`CONFLICT`,
    /// `BAD_LAYER` or `BAD_MODE`); the tree is as before.
    Entry { status: u32, entry: u32 },
    /// Refused for a reason that names no entry.
    Refused { status: u32 },
}

impl LayerReply {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        match self {
            Self::Resolving => out.u32(RESOLVING),
            Self::Done { names } => {
                out.u32(OK)?;
                out.u32(names)
            }
            Self::Entry { status, entry } => {
                if !matches!(status, CONFLICT | BAD_LAYER | BAD_MODE) {
                    return Err(Status::BadSize);
                }
                out.u32(status)?;
                out.u32(entry)
            }
            Self::Refused { status } => {
                if matches!(status, OK | RESOLVING | CONFLICT | BAD_LAYER | BAD_MODE) {
                    return Err(Status::BadSize);
                }
                out.u32(status)
            }
        }
    }

    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let status = input.u32()?;
        let reply = match status {
            RESOLVING => Self::Resolving,
            OK => Self::Done {
                names: input.u32()?,
            },
            CONFLICT | BAD_LAYER | BAD_MODE => Self::Entry {
                status,
                entry: input.u32()?,
            },
            // A refusal that is a status alone comes as a reply of the header's length.
            _ => return Ok(Self::Refused { status }),
        };
        input.finish()?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(write: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
        let mut out = Writer::new();
        write(&mut out).unwrap();
        out.as_bytes().to_vec()
    }

    #[test]
    fn start_round_trips_and_every_cut_or_extra_byte_is_an_error() {
        for start in [
            LayerStart {
                op: LayerOp::Attach,
                layer: 1,
                level: 9,
            },
            LayerStart {
                op: LayerOp::Detach,
                layer: LAYER_NUMBER_MAX,
                level: 0,
            },
        ] {
            let wire = bytes(|out| start.write(out));
            let mut input = Reader::new(&wire);
            assert_eq!(
                crate::Header::read(&mut input).unwrap(),
                Method::LayerStart.header()
            );
            assert_eq!(LayerStart::read(input), Ok(start));
            let body = &wire[proto_wire::HEADER_LEN..];
            assert_eq!(body.len(), 12);
            for length in 0..body.len() {
                assert!(LayerStart::read(Reader::new(&body[..length])).is_err());
            }
            let mut extra = body.to_vec();
            extra.push(0);
            assert!(LayerStart::read(Reader::new(&extra)).is_err());
        }
    }

    #[test]
    fn start_refuses_the_numbers_and_levels_that_do_not_fit() {
        let ok = LayerStart {
            op: LayerOp::Attach,
            layer: 5,
            level: 3,
        };
        for bad in [
            LayerStart { layer: 0, ..ok },
            LayerStart {
                layer: LAYER_NUMBER_MAX + 1,
                ..ok
            },
            LayerStart {
                layer: IMAGE_LAYER_FIRST,
                ..ok
            },
            LayerStart { level: 0, ..ok },
            LayerStart {
                op: LayerOp::Detach,
                level: 1,
                ..ok
            },
        ] {
            assert!(bytes_fail(bad));
        }
        // An operation number that is neither 1 nor 2.
        for op in [0u32, 3, u32::MAX] {
            let mut wire = Vec::new();
            for word in [op, 5, 3] {
                wire.extend_from_slice(&word.to_le_bytes());
            }
            assert!(LayerStart::read(Reader::new(&wire)).is_err());
        }
    }

    fn bytes_fail(start: LayerStart) -> bool {
        let mut out = Writer::new();
        let wrote = start.write(&mut out).is_err();
        let mut wire = Vec::new();
        for word in [start.op as u32, start.layer, start.level] {
            wire.extend_from_slice(&word.to_le_bytes());
        }
        wrote && LayerStart::read(Reader::new(&wire)).is_err()
    }

    #[test]
    fn step_round_trips_and_is_exact() {
        let step = LayerStep { layer: 77 };
        let wire = bytes(|out| step.write(out));
        let body = &wire[proto_wire::HEADER_LEN..];
        assert_eq!(LayerStep::read(Reader::new(body)), Ok(step));
        for length in 0..body.len() {
            assert!(LayerStep::read(Reader::new(&body[..length])).is_err());
        }
        let mut extra = body.to_vec();
        extra.push(0);
        assert!(LayerStep::read(Reader::new(&extra)).is_err());
        for layer in [0, LAYER_NUMBER_MAX + 1] {
            assert!(LayerStep::read(Reader::new(&layer.to_le_bytes())).is_err());
            assert!(LayerStep { layer }.write(&mut Writer::new()).is_err());
        }
    }

    #[test]
    fn replies_round_trip_and_keep_their_shape() {
        for reply in [
            LayerReply::Resolving,
            LayerReply::Done { names: 115 },
            LayerReply::Entry {
                status: CONFLICT,
                entry: 7,
            },
            LayerReply::Entry {
                status: BAD_LAYER,
                entry: 0,
            },
            LayerReply::Entry {
                status: BAD_MODE,
                entry: 1023,
            },
            LayerReply::Refused {
                status: crate::PERMISSION,
            },
        ] {
            let wire = bytes(|out| reply.write(out));
            assert_eq!(LayerReply::read(Reader::new(&wire)), Ok(reply));
            for length in 0..wire.len() {
                if length != 4
                    || matches!(reply, LayerReply::Resolving | LayerReply::Refused { .. })
                {
                    continue;
                }
                assert!(LayerReply::read(Reader::new(&wire[..length])).is_err());
            }
            let mut extra = wire.clone();
            extra.push(0);
            // A refusal that is a status alone may come padded to the header's length.
            assert_eq!(
                LayerReply::read(Reader::new(&extra)).is_err(),
                !matches!(reply, LayerReply::Refused { .. })
            );
        }
        let mut out = Writer::new();
        assert!(
            LayerReply::Entry {
                status: crate::PERMISSION,
                entry: 0
            }
            .write(&mut out)
            .is_err()
        );
        assert!(
            LayerReply::Refused { status: CONFLICT }
                .write(&mut out)
                .is_err()
        );
    }
}
