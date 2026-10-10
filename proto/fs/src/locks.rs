// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact nonblocking lock commands use the sixteen paid Control key domains.

use crate::{DataDescription, INVALID_ARGUMENT, Method, OpenKey};
use proto_wire::{Reader, Status, Writer};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LockCommand {
    GetPid = 1,
    SetPid = 2,
    GetOfd = 3,
    SetOfd = 4,
}
impl LockCommand {
    fn read(value: u32) -> Result<Self, Status> {
        match value {
            1 => Ok(Self::GetPid),
            2 => Ok(Self::SetPid),
            3 => Ok(Self::GetOfd),
            4 => Ok(Self::SetOfd),
            _ => Err(Status::from_code(INVALID_ARGUMENT)),
        }
    }
    pub fn ofd(self) -> bool {
        matches!(self, Self::GetOfd | Self::SetOfd)
    }
    pub fn get(self) -> bool {
        matches!(self, Self::GetPid | Self::GetOfd)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LockKind {
    Read = 0,
    Write = 1,
    Unlock = 2,
}
impl LockKind {
    fn read(value: u32) -> Result<Self, Status> {
        match value {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Unlock),
            _ => Err(Status::from_code(INVALID_ARGUMENT)),
        }
    }
}

fn validate_key(key: OpenKey) -> Result<(), Status> {
    key.validate().map_err(Status::from_code)?;
    if !(32..48).contains(&key.slot) {
        return Err(Status::from_code(INVALID_ARGUMENT));
    }
    Ok(())
}

pub fn write_lock_key(method: Method, key: OpenKey, out: &mut Writer) -> Result<(), Status> {
    validate_key(key)?;
    if !matches!(method, Method::LockQuery | Method::LockRelease) {
        return Err(Status::from_code(INVALID_ARGUMENT));
    }
    method.header().write(out)?;
    out.u32(key.slot)?;
    out.u64(key.generation)
}

pub fn read_lock_key(mut input: Reader<'_>) -> Result<OpenKey, Status> {
    let key = OpenKey {
        slot: input.u32()?,
        generation: input.u64()?,
    };
    input.finish()?;
    validate_key(key)?;
    Ok(key)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockStart {
    pub key: OpenKey,
    pub description: DataDescription,
    pub command: LockCommand,
    pub kind: LockKind,
    pub whence: u32,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}
impl LockStart {
    pub fn validate(self) -> Result<(), Status> {
        validate_key(self.key)?;
        self.description.validate()?;
        if self.whence > 2
            || self.command.ofd() && self.pid != 0
            || self.command == LockCommand::GetPid && self.kind == LockKind::Unlock
        {
            return Err(Status::from_code(INVALID_ARGUMENT));
        }
        Ok(())
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        Method::LockStart.header().write(out)?;
        out.u32(self.key.slot)?;
        out.u64(self.key.generation)?;
        out.u32(self.description.packed)?;
        out.u64(self.description.generation)?;
        out.u32(self.command as u32)?;
        out.u32(self.kind as u32)?;
        out.u32(self.whence)?;
        out.u64(self.start as u64)?;
        out.u64(self.length as u64)?;
        out.u32(self.pid as u32)
    }
    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let request = Self {
            key: OpenKey {
                slot: input.u32()?,
                generation: input.u64()?,
            },
            description: DataDescription {
                packed: input.u32()?,
                generation: input.u64()?,
            },
            command: LockCommand::read(input.u32()?)?,
            kind: LockKind::read(input.u32()?)?,
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
pub enum LockPhase {
    Pending,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockBlocker {
    pub kind: LockKind,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockReply {
    pub phase: LockPhase,
    pub result: u32,
    pub blocker: Option<LockBlocker>,
}
impl LockReply {
    fn validate(self) -> Result<(), Status> {
        if self.phase == LockPhase::Pending && (self.result != 0 || self.blocker.is_some())
            || self.result != 0 && self.blocker.is_some()
            || self.blocker.is_some_and(|b| {
                b.kind == LockKind::Unlock
                    || b.start < 0
                    || b.length < 0
                    || b.pid == 0
                    || b.pid < -1
            })
        {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        out.u32(0)?;
        out.u32(u32::from(self.phase == LockPhase::Complete))?;
        out.u32(self.result)?;
        out.u32(u32::from(self.blocker.is_some()))?;
        if let Some(blocker) = self.blocker {
            out.u32(blocker.kind as u32)?;
            out.u64(blocker.start as u64)?;
            out.u64(blocker.length as u64)?;
            out.u32(blocker.pid as u32)?;
        }
        Ok(())
    }
    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let status = Status::from_code(input.u32()?);
        if status != Status::Ok {
            return Err(status);
        }
        let phase = match input.u32()? {
            0 => LockPhase::Pending,
            1 => LockPhase::Complete,
            _ => return Err(Status::BadSize),
        };
        let result = input.u32()?;
        let blocker = match input.u32()? {
            0 => None,
            1 => Some(LockBlocker {
                kind: LockKind::read(input.u32()?)?,
                start: input.u64()? as i64,
                length: input.u64()? as i64,
                pid: input.u32()? as i32,
            }),
            _ => return Err(Status::BadSize),
        };
        input.finish()?;
        let reply = Self {
            phase,
            result,
            blocker,
        };
        reply.validate()?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> LockStart {
        LockStart {
            key: OpenKey {
                slot: 32,
                generation: u64::MAX,
            },
            description: DataDescription {
                packed: 3 | (127 << crate::OPEN_DESCRIPTION_SHIFT),
                generation: u64::MAX,
            },
            command: LockCommand::SetPid,
            kind: LockKind::Write,
            whence: 2,
            start: i64::MIN,
            length: -19,
            pid: -1,
        }
    }

    #[test]
    fn control_domains_are_exact_and_separate_from_io_and_close() {
        for slot in 0..80 {
            let key = OpenKey {
                slot,
                generation: 1,
            };
            assert_eq!(validate_key(key).is_ok(), (32..48).contains(&slot));
        }
        assert!(
            validate_key(OpenKey {
                generation: 0,
                ..request().key
            })
            .is_err()
        );
        for method in [Method::LockQuery, Method::LockRelease] {
            let mut out = Writer::new();
            write_lock_key(method, request().key, &mut out).unwrap();
            let mut input = Reader::new(out.as_bytes());
            assert_eq!(crate::Header::read(&mut input).unwrap(), method.header());
            assert_eq!(read_lock_key(input), Ok(request().key));
            assert!(
                read_lock_key(Reader::new(
                    &out.as_bytes()[proto_wire::HEADER_LEN..out.as_bytes().len() - 1]
                ))
                .is_err()
            );
        }
        let mut out = Writer::new();
        assert!(write_lock_key(Method::ChangeRelease, request().key, &mut out).is_err());
        assert!(out.as_bytes().is_empty());
    }

    #[test]
    fn start_roundtrips_signed_fields_and_requires_exact_body() {
        for command in [
            LockCommand::GetPid,
            LockCommand::SetPid,
            LockCommand::GetOfd,
            LockCommand::SetOfd,
        ] {
            let request = LockStart {
                command,
                pid: if command.ofd() { 0 } else { -1 },
                ..request()
            };
            let mut out = Writer::new();
            request.write(&mut out).unwrap();
            let mut input = Reader::new(out.as_bytes());
            assert_eq!(
                crate::Header::read(&mut input).unwrap(),
                Method::LockStart.header()
            );
            assert_eq!(LockStart::read(input), Ok(request));
            let body = &out.as_bytes()[proto_wire::HEADER_LEN..];
            assert_eq!(body.len(), 56);
            for length in 0..body.len() {
                assert!(LockStart::read(Reader::new(&body[..length])).is_err());
            }
            let mut extra = body.to_vec();
            extra.push(0);
            assert!(LockStart::read(Reader::new(&extra)).is_err());
        }
        for (number, method) in [
            (50, Method::LockStart),
            (51, Method::LockQuery),
            (52, Method::LockRelease),
        ] {
            assert_eq!(Method::from_number(number), Some(method));
            assert!(crate::METHODS.contains(&number));
        }
    }

    #[test]
    fn invalid_requests_leave_writer_empty_and_ofd_pid_is_checked() {
        for invalid in [
            LockStart {
                whence: 3,
                ..request()
            },
            LockStart {
                command: LockCommand::GetOfd,
                ..request()
            },
            LockStart {
                command: LockCommand::SetOfd,
                ..request()
            },
            LockStart {
                command: LockCommand::GetPid,
                kind: LockKind::Unlock,
                ..request()
            },
            LockStart {
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
        assert!(
            LockStart {
                command: LockCommand::GetOfd,
                kind: LockKind::Unlock,
                pid: 0,
                ..request()
            }
            .validate()
            .is_ok()
        );
        let mut out = Writer::new();
        request().write(&mut out).unwrap();
        for offset in [24, 28] {
            let mut body = out.as_bytes()[proto_wire::HEADER_LEN..].to_vec();
            body[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(LockStart::read(Reader::new(&body)).is_err());
        }
    }

    #[test]
    fn replies_retain_terminal_result_and_distinguish_pid_from_ofd_blocker() {
        for reply in [
            LockReply {
                phase: LockPhase::Pending,
                result: 0,
                blocker: None,
            },
            LockReply {
                phase: LockPhase::Complete,
                result: 0,
                blocker: None,
            },
            LockReply {
                phase: LockPhase::Complete,
                result: crate::BAD_FD,
                blocker: None,
            },
            LockReply {
                phase: LockPhase::Complete,
                result: 0,
                blocker: Some(LockBlocker {
                    kind: LockKind::Read,
                    start: 13,
                    length: 0,
                    pid: -1,
                }),
            },
            LockReply {
                phase: LockPhase::Complete,
                result: 0,
                blocker: Some(LockBlocker {
                    kind: LockKind::Write,
                    start: i64::MAX,
                    length: 1,
                    pid: 991,
                }),
            },
        ] {
            let mut out = Writer::new();
            reply.write(&mut out).unwrap();
            assert_eq!(LockReply::read(Reader::new(out.as_bytes())), Ok(reply));
            for length in 0..out.as_bytes().len() {
                assert!(LockReply::read(Reader::new(&out.as_bytes()[..length])).is_err());
            }
            let mut extra = out.as_bytes().to_vec();
            extra.push(0);
            assert!(LockReply::read(Reader::new(&extra)).is_err());
        }
        assert!(
            LockReply {
                phase: LockPhase::Pending,
                result: crate::BAD_FD,
                blocker: None
            }
            .validate()
            .is_err()
        );
        let mut refusal = Writer::new();
        refusal.u32(crate::OPEN_RETIRED).unwrap();
        assert_eq!(
            LockReply::read(Reader::new(refusal.as_bytes())),
            Err(Status::from_code(crate::OPEN_RETIRED))
        );
    }
}
