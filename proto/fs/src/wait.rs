// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Waiting locks have a separate paid key domain, never an OpenKey alias.
//! Arm transfers one notification channel; handle counts are checked by the service.

use crate::{DataDescription, INVALID_ARGUMENT, LockKind, Method};
use proto_wire::{Reader, Status, Writer};

pub const WAIT_KEY_PLACES: usize = 16;
pub const WAIT_START_BODY_BYTES: usize = 56;
pub const WAIT_KEY_BODY_BYTES: usize = 12;
pub const WAIT_REPLY_BYTES: usize = 16;
const _: () = assert!(proto_wire::HEADER_LEN + WAIT_START_BODY_BYTES <= abi::INLINE_MAX);
const _: () = assert!(proto_wire::HEADER_LEN + WAIT_KEY_BODY_BYTES <= abi::INLINE_MAX);
const _: () = assert!(WAIT_REPLY_BYTES <= abi::INLINE_MAX);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitKey {
    pub slot: u32,
    pub generation: u64,
}
impl WaitKey {
    pub fn validate(self) -> Result<usize, u32> {
        if self.slot as usize >= WAIT_KEY_PLACES || self.generation == 0 {
            return Err(INVALID_ARGUMENT);
        }
        Ok(self.slot as usize)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WaitMode {
    Pid = 1,
    Ofd = 2,
}
impl WaitMode {
    pub const fn ofd(self) -> bool {
        matches!(self, Self::Ofd)
    }
    fn read(value: u32) -> Result<Self, Status> {
        match value {
            1 => Ok(Self::Pid),
            2 => Ok(Self::Ofd),
            _ => Err(Status::from_code(INVALID_ARGUMENT)),
        }
    }
}

pub fn write_wait_key(method: Method, key: WaitKey, out: &mut Writer) -> Result<(), Status> {
    key.validate().map_err(Status::from_code)?;
    if !matches!(
        method,
        Method::WaitQuery | Method::WaitCancel | Method::WaitRelease | Method::WaitArm
    ) {
        return Err(Status::from_code(INVALID_ARGUMENT));
    }
    method.header().write(out)?;
    out.u32(key.slot)?;
    out.u64(key.generation)
}
pub fn read_wait_key(mut input: Reader<'_>) -> Result<WaitKey, Status> {
    let key = WaitKey {
        slot: input.u32()?,
        generation: input.u64()?,
    };
    input.finish()?;
    key.validate().map_err(Status::from_code)?;
    Ok(key)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitStart {
    pub key: WaitKey,
    pub description: DataDescription,
    pub mode: WaitMode,
    pub kind: LockKind,
    pub whence: u32,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}
impl WaitStart {
    pub fn validate(self) -> Result<(), Status> {
        self.key.validate().map_err(Status::from_code)?;
        self.description.validate()?;
        if self.kind == LockKind::Unlock || self.whence > 2 || self.mode.ofd() && self.pid != 0 {
            return Err(Status::from_code(INVALID_ARGUMENT));
        }
        Ok(())
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        Method::WaitStart.header().write(out)?;
        out.u32(self.key.slot)?;
        out.u64(self.key.generation)?;
        out.u32(self.description.packed)?;
        out.u64(self.description.generation)?;
        out.u32(self.mode as u32)?;
        out.u32(self.kind as u32)?;
        out.u32(self.whence)?;
        out.u64(self.start as u64)?;
        out.u64(self.length as u64)?;
        out.u32(self.pid as u32)
    }
    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let request = Self {
            key: WaitKey {
                slot: input.u32()?,
                generation: input.u64()?,
            },
            description: DataDescription {
                packed: input.u32()?,
                generation: input.u64()?,
            },
            mode: WaitMode::read(input.u32()?)?,
            kind: match input.u32()? {
                0 => LockKind::Read,
                1 => LockKind::Write,
                _ => return Err(Status::from_code(INVALID_ARGUMENT)),
            },
            whence: input.u32()?,
            start: input.u64()? as i64,
            length: input.u64()? as i64,
            pid: input.u32()? as i32,
        };
        input.finish()?;
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WaitPhase {
    Queued = 0,
    NeedsArm = 1,
    Sleeping = 2,
    Complete = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitReply {
    pub phase: WaitPhase,
    pub result: u32,
}
impl WaitReply {
    pub fn validate(self) -> Result<(), Status> {
        if self.phase != WaitPhase::Complete && self.result != 0 {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        out.u32(0)?;
        out.u32(self.phase as u32)?;
        out.u32(self.result)?;
        out.u32(0)
    }
    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let status = Status::from_code(input.u32()?);
        if status != Status::Ok {
            if input.u32()? != 0 {
                return Err(Status::BadSize);
            }
            input.finish()?;
            return Err(status);
        }
        let phase = match input.u32()? {
            0 => WaitPhase::Queued,
            1 => WaitPhase::NeedsArm,
            2 => WaitPhase::Sleeping,
            3 => WaitPhase::Complete,
            _ => return Err(Status::BadSize),
        };
        let result = input.u32()?;
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        let reply = Self { phase, result };
        reply.validate()?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> WaitStart {
        WaitStart {
            key: WaitKey {
                slot: 15,
                generation: u64::MAX,
            },
            description: DataDescription {
                packed: 3 | (127 << crate::OPEN_DESCRIPTION_SHIFT),
                generation: u64::MAX,
            },
            mode: WaitMode::Pid,
            kind: LockKind::Write,
            whence: 2,
            start: i64::MIN,
            length: -19,
            pid: i32::MIN,
        }
    }
    fn body(request: WaitStart) -> Vec<u8> {
        let mut out = Writer::new();
        request.write(&mut out).unwrap();
        let mut input = Reader::new(out.as_bytes());
        assert_eq!(
            crate::Header::read(&mut input).unwrap(),
            Method::WaitStart.header()
        );
        out.as_bytes()[proto_wire::HEADER_LEN..].to_vec()
    }
    #[test]
    fn wait_keys_are_separate_and_preserve_full_generations() {
        assert_eq!(WAIT_KEY_PLACES, 16);
        assert_eq!(crate::JOB_KEY_PLACES, 48);
        for slot in 0..80 {
            assert_eq!(
                WaitKey {
                    slot,
                    generation: 1
                }
                .validate()
                .is_ok(),
                slot < 16
            );
        }
        assert!(
            WaitKey {
                generation: 0,
                ..request().key
            }
            .validate()
            .is_err()
        );
        for method in [
            Method::WaitQuery,
            Method::WaitCancel,
            Method::WaitRelease,
            Method::WaitArm,
        ] {
            let mut out = Writer::new();
            write_wait_key(method, request().key, &mut out).unwrap();
            let mut input = Reader::new(out.as_bytes());
            assert_eq!(crate::Header::read(&mut input).unwrap(), method.header());
            assert_eq!(read_wait_key(input), Ok(request().key));
            let body = &out.as_bytes()[proto_wire::HEADER_LEN..];
            assert_eq!(body.len(), WAIT_KEY_BODY_BYTES);
            for n in 0..body.len() {
                assert!(read_wait_key(Reader::new(&body[..n])).is_err());
            }
            let mut extra = body.to_vec();
            extra.push(0);
            assert!(read_wait_key(Reader::new(&extra)).is_err());
        }
        for method in [
            Method::LockQuery,
            Method::OpenCancel,
            Method::ChangeRelease,
            Method::WaitStart,
        ] {
            let mut out = Writer::new();
            assert!(write_wait_key(method, request().key, &mut out).is_err());
            assert!(out.as_bytes().is_empty());
        }
    }
    #[test]
    fn start_has_exact_little_endian_layout_and_signed_fields() {
        let bytes = body(request());
        assert_eq!(bytes.len(), WAIT_START_BODY_BYTES);
        let mut expected = Vec::new();
        expected.extend(15u32.to_le_bytes());
        expected.extend(u64::MAX.to_le_bytes());
        expected.extend(request().description.packed.to_le_bytes());
        expected.extend(u64::MAX.to_le_bytes());
        expected.extend(1u32.to_le_bytes());
        expected.extend(1u32.to_le_bytes());
        expected.extend(2u32.to_le_bytes());
        expected.extend(i64::MIN.to_le_bytes());
        expected.extend((-19i64).to_le_bytes());
        expected.extend(i32::MIN.to_le_bytes());
        assert_eq!(bytes, expected);
        for mode in [WaitMode::Pid, WaitMode::Ofd] {
            for kind in [LockKind::Read, LockKind::Write] {
                let request = WaitStart {
                    mode,
                    kind,
                    pid: if mode.ofd() { 0 } else { i32::MIN },
                    ..request()
                };
                let bytes = body(request);
                assert_eq!(WaitStart::read(Reader::new(&bytes)), Ok(request));
                for n in 0..bytes.len() {
                    assert!(WaitStart::read(Reader::new(&bytes[..n])).is_err());
                }
                let mut extra = bytes;
                extra.push(0);
                assert!(WaitStart::read(Reader::new(&extra)).is_err());
            }
        }
    }
    #[test]
    fn start_rejects_unlock_invalid_modes_and_stale_descriptions() {
        for invalid in [
            WaitStart {
                key: WaitKey {
                    slot: 16,
                    generation: 1,
                },
                ..request()
            },
            WaitStart {
                key: WaitKey {
                    slot: 0,
                    generation: 0,
                },
                ..request()
            },
            WaitStart {
                kind: LockKind::Unlock,
                ..request()
            },
            WaitStart {
                whence: 3,
                ..request()
            },
            WaitStart {
                mode: WaitMode::Ofd,
                ..request()
            },
            WaitStart {
                description: DataDescription {
                    generation: 0,
                    ..request().description
                },
                ..request()
            },
            WaitStart {
                description: DataDescription {
                    packed: request().description.packed | crate::OPEN_RANDOM,
                    generation: 1,
                },
                ..request()
            },
        ] {
            let mut out = Writer::new();
            assert!(invalid.write(&mut out).is_err());
            assert!(out.as_bytes().is_empty());
        }
        for (offset, values) in [
            (24, vec![0, 3, u32::MAX]),
            (28, vec![2, 3, u32::MAX]),
            (32, vec![3, u32::MAX]),
        ] {
            for value in values {
                let mut bytes = body(request());
                bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                assert!(WaitStart::read(Reader::new(&bytes)).is_err());
            }
        }
    }
    #[test]
    fn replies_have_fixed_phases_and_retain_terminal_outcomes() {
        assert_eq!(WAIT_REPLY_BYTES, 16);
        assert_eq!(crate::LOCK_DEADLOCK, 332);
        for (number, phase) in [
            (0u32, WaitPhase::Queued),
            (1, WaitPhase::NeedsArm),
            (2, WaitPhase::Sleeping),
            (3, WaitPhase::Complete),
        ] {
            for result in [
                0,
                crate::BAD_FD,
                crate::LOCK_CANCELLED,
                crate::LOCK_DEADLOCK,
            ] {
                let reply = WaitReply { phase, result };
                let mut out = Writer::new();
                if phase != WaitPhase::Complete && result != 0 {
                    assert!(reply.write(&mut out).is_err());
                    assert!(out.as_bytes().is_empty());
                    continue;
                }
                reply.write(&mut out).unwrap();
                assert_eq!(out.as_bytes().len(), WAIT_REPLY_BYTES);
                assert_eq!(&out.as_bytes()[4..8], &number.to_le_bytes());
                assert_eq!(WaitReply::read(Reader::new(out.as_bytes())), Ok(reply));
                for n in 0..16 {
                    assert!(WaitReply::read(Reader::new(&out.as_bytes()[..n])).is_err());
                }
                let mut extra = out.as_bytes().to_vec();
                extra.push(0);
                assert!(WaitReply::read(Reader::new(&extra)).is_err());
            }
        }
    }
    #[test]
    fn malformed_reply_cannot_become_a_terminal_receipt() {
        for (phase, result, reserved) in [
            (4, 0, 0),
            (0, crate::BAD_FD, 0),
            (1, 1, 0),
            (2, 1, 0),
            (3, 0, 1),
        ] {
            let mut out = Writer::new();
            for word in [0, phase, result, reserved] {
                out.u32(word).unwrap();
            }
            assert!(WaitReply::read(Reader::new(out.as_bytes())).is_err());
        }
        for code in [crate::AUTHENTICATING, crate::JOBS_FULL, crate::OPEN_RETIRED] {
            let mut out = Writer::new();
            out.u32(code).unwrap();
            out.u32(0).unwrap();
            assert_eq!(
                WaitReply::read(Reader::new(out.as_bytes())),
                Err(Status::from_code(code))
            );
            for n in 0..8 {
                assert_eq!(
                    WaitReply::read(Reader::new(&out.as_bytes()[..n])),
                    Err(Status::BadSize)
                );
            }
            let mut extra = out.as_bytes().to_vec();
            extra.push(0);
            assert_eq!(WaitReply::read(Reader::new(&extra)), Err(Status::BadSize));
            let mut reserved = out.as_bytes().to_vec();
            reserved[4] = 1;
            assert_eq!(
                WaitReply::read(Reader::new(&reserved)),
                Err(Status::BadSize)
            );
        }
    }
    #[test]
    fn wait_method_numbers_and_version_are_exact() {
        assert_eq!(crate::VERSION, 18);
        for (number, method) in [
            (54, Method::WaitStart),
            (55, Method::WaitQuery),
            (56, Method::WaitCancel),
            (57, Method::WaitRelease),
            (58, Method::WaitArm),
        ] {
            assert_eq!(Method::from_number(number), Some(method));
            assert!(crate::METHODS.contains(&number));
        }
        assert_eq!(Method::from_number(59), None);
    }
}
