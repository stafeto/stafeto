// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The Change family: one keyed, paid job for each operation on names and
//! metadata. Start captures the operation, Second adds the second path of
//! a two-path operation, Step advances it, Query reads it, and Release
//! forgets it. The error of the operation itself is the `result` of the
//! reply; the status of a reply is non-zero only for an error of the protocol.

use crate::{MAX_PATH, OpenKey};
use proto_wire::{Reader, Status, Writer};

/// The base of a path that must be absolute: a relative path answers BAD_FD.
pub const BASE_ABSOLUTE: u32 = 0xFFFF_FFFF;
/// The current directory of the session. Reserved until the service holds the
/// current directory (5i-7): every request that names it answers BAD_FD.
pub const BASE_CWD: u32 = 0xFFFF_FFFE;

/// Flags of the operations.
pub const UNLINK_REMOVEDIR: u32 = 1;
pub const LINK_FOLLOW: u32 = 1;
pub const NOFOLLOW: u32 = 1;
pub const ACCESS_EFFECTIVE: u32 = 1;
pub const PATH_REQUIRE_DIR: u32 = 1;
pub const PATH_FOLLOW_LAST: u32 = 2;

/// The argument of Chown that leaves the field as it is.
pub const ID_UNCHANGED: u64 = 0xFFFF_FFFF;
/// Nanosecond fields of Times that stand for "now" and "leave it".
pub const TIME_NOW: u64 = 0x3FFF_FFFF;
pub const TIME_OMIT: u64 = 0x3FFF_FFFE;

/// The bytes of the result of StatVfs: eleven u64.
pub const STATVFS_BYTES: usize = 88;
/// The most bytes a reply of Step carries after its fixed part.
pub const RESULT_MAX: usize = 512;
/// The mask of the permission bits and the three set-id bits.
pub const MODE_MASK: u64 = 0o7777;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ChangeOp {
    Unlink = 1,
    Mkdir = 2,
    Rename = 3,
    Link = 4,
    Symlink = 5,
    ReadLink = 6,
    Chmod = 7,
    Chown = 8,
    Times = 9,
    Access = 10,
    StatVfs = 11,
    Path = 12,
}
impl ChangeOp {
    pub fn from_number(number: u32) -> Option<Self> {
        Some(match number {
            1 => Self::Unlink,
            2 => Self::Mkdir,
            3 => Self::Rename,
            4 => Self::Link,
            5 => Self::Symlink,
            6 => Self::ReadLink,
            7 => Self::Chmod,
            8 => Self::Chown,
            9 => Self::Times,
            10 => Self::Access,
            11 => Self::StatVfs,
            12 => Self::Path,
            _ => return None,
        })
    }
    /// Rename, Link and Symlink need a Second before they can run.
    pub const fn needs_second(self) -> bool {
        matches!(self, Self::Rename | Self::Link | Self::Symlink)
    }
    /// An empty path names the object of the base descriptor itself.
    pub const fn takes_empty_path(self) -> bool {
        matches!(
            self,
            Self::Chmod | Self::Chown | Self::Times | Self::StatVfs | Self::Path
        )
    }
    /// The flag bits the operation takes.
    pub const fn flag_mask(self) -> u32 {
        match self {
            Self::Unlink | Self::Link | Self::Access => 1,
            Self::Chmod | Self::Chown | Self::Times => NOFOLLOW,
            Self::Path => PATH_REQUIRE_DIR | PATH_FOLLOW_LAST,
            _ => 0,
        }
    }
}

/// Where a relative path starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    Absolute,
    Cwd,
    /// A descriptor of the session with the generation of its description.
    Fd {
        fd: u32,
        generation: u64,
    },
}
impl Base {
    pub fn from_wire(fd: u32, generation: u64) -> Result<Self, Status> {
        match fd {
            BASE_ABSOLUTE | BASE_CWD if generation != 0 => Err(Status::BadSize),
            BASE_ABSOLUTE => Ok(Self::Absolute),
            BASE_CWD => Ok(Self::Cwd),
            _ => Ok(Self::Fd { fd, generation }),
        }
    }
    pub fn wire(self) -> (u32, u64) {
        match self {
            Self::Absolute => (BASE_ABSOLUTE, 0),
            Self::Cwd => (BASE_CWD, 0),
            Self::Fd { fd, generation } => (fd, generation),
        }
    }
}

fn write_key(out: &mut Writer, key: OpenKey) -> Result<(), Status> {
    out.u32(key.slot)?;
    out.u64(key.generation)
}
fn read_key(input: &mut Reader<'_>) -> Result<OpenKey, Status> {
    let key = OpenKey {
        slot: input.u32()?,
        generation: input.u64()?,
    };
    key.validate().map_err(Status::from_code)?;
    Ok(key)
}

/// Method 44. The arguments by operation:
/// Mkdir: mode, umask. Chmod: mode. Chown: uid, gid (ID_UNCHANGED keeps the field).
/// Times: seconds and nanoseconds of the access time, then of the modification time.
/// Access: mode bits. ReadLink: the size of the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeStart<'a> {
    pub key: OpenKey,
    pub op: ChangeOp,
    pub flags: u32,
    pub base: Base,
    pub args: [u64; 4],
    pub path: &'a [u8],
}
impl ChangeStart<'_> {
    pub fn validate(&self) -> Result<(), Status> {
        self.key.validate().map_err(Status::from_code)?;
        if self.path.len() > MAX_PATH || self.flags & !self.op.flag_mask() != 0 {
            return Err(Status::BadSize);
        }
        let invalid = Status::from_code(crate::INVALID_ARGUMENT);
        if self.path.is_empty()
            && !(matches!(self.base, Base::Fd { .. }) && self.op.takes_empty_path())
        {
            return Err(invalid);
        }
        let a = self.args;
        let valid = match self.op {
            ChangeOp::Mkdir => a[0] <= MODE_MASK && a[1] <= 0o777 && a[2] == 0 && a[3] == 0,
            ChangeOp::Chmod => a[0] <= MODE_MASK && a[1..] == [0; 3],
            ChangeOp::Chown => a[0] <= ID_UNCHANGED && a[1] <= ID_UNCHANGED && a[2..] == [0; 2],
            ChangeOp::Access => a[0] <= 7 && a[1..] == [0; 3],
            ChangeOp::ReadLink => a[0] != 0 && a[1..] == [0; 3],
            ChangeOp::Times => [a[1], a[3]]
                .iter()
                .all(|&n| n < 1_000_000_000 || n == TIME_NOW || n == TIME_OMIT),
            _ => a == [0; 4],
        };
        if !valid {
            return Err(invalid);
        }
        Ok(())
    }
    pub fn write(&self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        write_key(out, self.key)?;
        out.u32(self.op as u32)?;
        out.u32(self.flags)?;
        let (fd, generation) = self.base.wire();
        out.u32(fd)?;
        out.u64(generation)?;
        for arg in self.args {
            out.u64(arg)?;
        }
        out.bytes(self.path)
    }
}
impl<'a> ChangeStart<'a> {
    pub fn read(mut input: Reader<'a>) -> Result<Self, Status> {
        let key = read_key(&mut input)?;
        let op = ChangeOp::from_number(input.u32()?)
            .ok_or_else(|| Status::from_code(crate::INVALID_ARGUMENT))?;
        let flags = input.u32()?;
        let fd = input.u32()?;
        let generation = input.u64()?;
        let base = Base::from_wire(fd, generation)?;
        let mut args = [0; 4];
        for arg in &mut args {
            *arg = input.u64()?;
        }
        let path = input.bytes(input.left())?;
        let value = Self {
            key,
            op,
            flags,
            base,
            args,
            path,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Method 45. The bytes are the second path of Rename and Link (1..=511) or
/// the contents of the new link of Symlink (0..=511).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeSecond<'a> {
    pub key: OpenKey,
    pub base: Base,
    pub bytes: &'a [u8],
}
impl ChangeSecond<'_> {
    /// The length the operation takes.
    pub fn validate_for(&self, op: ChangeOp) -> Result<(), Status> {
        if !op.needs_second() {
            return Err(Status::from_code(crate::INVALID_ARGUMENT));
        }
        if self.bytes.len() > MAX_PATH {
            return Err(Status::BadSize);
        }
        if self.bytes.is_empty() && op != ChangeOp::Symlink {
            return Err(Status::from_code(crate::INVALID_ARGUMENT));
        }
        Ok(())
    }
    pub fn write(&self, out: &mut Writer) -> Result<(), Status> {
        if self.bytes.len() > MAX_PATH {
            return Err(Status::BadSize);
        }
        write_key(out, self.key)?;
        let (fd, generation) = self.base.wire();
        out.u32(fd)?;
        out.u64(generation)?;
        out.bytes(self.bytes)
    }
}
impl<'a> ChangeSecond<'a> {
    pub fn read(mut input: Reader<'a>) -> Result<Self, Status> {
        let key = read_key(&mut input)?;
        let fd = input.u32()?;
        let generation = input.u64()?;
        let base = Base::from_wire(fd, generation)?;
        let bytes = input.bytes(input.left())?;
        if bytes.len() > MAX_PATH {
            return Err(Status::BadSize);
        }
        Ok(Self { key, base, bytes })
    }
}

/// The body of Step, Query and Release: the key alone.
pub fn write_key_body(out: &mut Writer, key: OpenKey) -> Result<(), Status> {
    write_key(out, key)
}
pub fn read_key_body(mut input: Reader<'_>) -> Result<OpenKey, Status> {
    let key = read_key(&mut input)?;
    input.finish()?;
    Ok(key)
}

/// Where a job is. Start answers with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ChangePhase {
    Captured = 0,
    Resolving = 1,
    AwaitingSecond = 2,
    Preparing = 3,
    Ready = 4,
    Done = 5,
    Canceling = 6,
}
impl ChangePhase {
    pub fn from_number(number: u32) -> Option<Self> {
        Some(match number {
            0 => Self::Captured,
            1 => Self::Resolving,
            2 => Self::AwaitingSecond,
            3 => Self::Preparing,
            4 => Self::Ready,
            5 => Self::Done,
            6 => Self::Canceling,
            _ => return None,
        })
    }
}

fn error_reply(bytes: &[u8], handles: usize) -> Result<Reader<'_>, Status> {
    if handles != 0 {
        return Err(Status::BadSize);
    }
    let mut input = Reader::new(bytes);
    let code = input.u32()?;
    if code != 0 {
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        return Err(Status::from_code(code));
    }
    Ok(input)
}

pub fn change_start_reply(bytes: &[u8], handles: usize) -> Result<ChangePhase, Status> {
    let mut input = error_reply(bytes, handles)?;
    let phase = ChangePhase::from_number(input.u32()?).ok_or(Status::BadSize)?;
    input.finish()?;
    Ok(phase)
}

pub fn write_start_reply(out: &mut Writer, phase: ChangePhase) -> Result<(), Status> {
    out.u32(0)?;
    out.u32(phase as u32)
}

/// The reply of Step and Query. `state` 0 is running, 1 is done. A running
/// job has no result. `restarts` counts the restarts of resolution after a
/// change of the tree between steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeReply<'a> {
    pub done: bool,
    pub result: u32,
    pub restarts: u32,
    pub value: u64,
    pub bytes: &'a [u8],
}
impl ChangeReply<'_> {
    pub fn validate(&self) -> Result<(), Status> {
        if self.bytes.len() > RESULT_MAX
            || (!self.done && (self.result != 0 || self.value != 0 || !self.bytes.is_empty()))
            || (self.result != 0 && (self.value != 0 || !self.bytes.is_empty()))
        {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn write(&self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        out.u32(0)?;
        out.u32(u32::from(self.done))?;
        out.u32(self.result)?;
        out.u32(self.restarts)?;
        out.u64(self.value)?;
        out.bytes(self.bytes)
    }
}
impl<'a> ChangeReply<'a> {
    pub fn read(bytes: &'a [u8], handles: usize) -> Result<Self, Status> {
        let mut input = error_reply(bytes, handles)?;
        let done = match input.u32()? {
            0 => false,
            1 => true,
            _ => return Err(Status::BadSize),
        };
        let result = input.u32()?;
        let restarts = input.u32()?;
        let value = input.u64()?;
        let bytes = input.bytes(input.left())?;
        let value = Self {
            done,
            result,
            restarts,
            value,
            bytes,
        };
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::MESSAGE_MAX;
    use proto_wire::HEADER_LEN;

    const KEY: OpenKey = OpenKey {
        slot: 31,
        generation: u64::MAX,
    };
    fn start(op: ChangeOp, path: &[u8]) -> ChangeStart<'_> {
        ChangeStart {
            key: KEY,
            op,
            flags: 0,
            base: Base::Absolute,
            args: [0; 4],
            path,
        }
    }
    fn round(value: ChangeStart<'_>) {
        let mut out = Writer::new();
        value.write(&mut out).unwrap();
        assert_eq!(
            ChangeStart::read(Reader::new(out.as_bytes())),
            Ok(value),
            "{value:?}"
        );
    }
    #[test]
    fn every_operation_round_trips_with_its_arguments() {
        let mut mkdir = start(ChangeOp::Mkdir, b"/tmp/d");
        mkdir.args = [0o755, 0o22, 0, 0];
        round(mkdir);
        let mut unlink = start(ChangeOp::Unlink, b"/tmp/d");
        unlink.flags = UNLINK_REMOVEDIR;
        round(unlink);
        round(start(ChangeOp::Rename, b"/a"));
        let mut link = start(ChangeOp::Link, b"/a");
        link.flags = LINK_FOLLOW;
        round(link);
        round(start(ChangeOp::Symlink, b"/a"));
        let mut readlink = start(ChangeOp::ReadLink, b"/a");
        readlink.args[0] = 511;
        round(readlink);
        let mut chmod = start(ChangeOp::Chmod, b"/a");
        chmod.args[0] = 0o4755;
        chmod.flags = NOFOLLOW;
        round(chmod);
        let mut chown = start(ChangeOp::Chown, b"/a");
        chown.args = [ID_UNCHANGED, 7, 0, 0];
        round(chown);
        let mut times = start(ChangeOp::Times, b"/a");
        times.args = [u64::MAX, TIME_NOW, 5, TIME_OMIT];
        round(times);
        times.args = [1 << 40, 999_999_999, 0, 0];
        round(times);
        let mut access = start(ChangeOp::Access, b"/a");
        access.args[0] = 7;
        access.flags = ACCESS_EFFECTIVE;
        round(access);
        round(start(ChangeOp::StatVfs, b"/a"));
        let mut path = start(ChangeOp::Path, b"/a");
        path.flags = PATH_REQUIRE_DIR | PATH_FOLLOW_LAST;
        round(path);
        let mut fd = start(ChangeOp::Chmod, b"");
        fd.base = Base::Fd {
            fd: 34,
            generation: 9,
        };
        round(fd);
        fd.base = Base::Cwd;
        assert_eq!(
            fd.validate(),
            Err(Status::from_code(crate::INVALID_ARGUMENT))
        );
    }
    #[test]
    fn paths_of_511_pass_and_512_is_refused() {
        let long = [b'a'; MAX_PATH + 1];
        round(start(ChangeOp::Unlink, &long[..MAX_PATH]));
        assert_eq!(
            start(ChangeOp::Unlink, &long).validate(),
            Err(Status::BadSize)
        );
        // The largest request fits a message.
        let mut out = Writer::new();
        let mut mkdir = start(ChangeOp::Mkdir, &long[..MAX_PATH]);
        mkdir.args[0] = 0o7777;
        mkdir.write(&mut out).unwrap();
        assert!(HEADER_LEN + out.as_bytes().len() <= MESSAGE_MAX);
        let second = ChangeSecond {
            key: KEY,
            base: Base::Absolute,
            bytes: &long[..MAX_PATH],
        };
        let mut out = Writer::new();
        second.write(&mut out).unwrap();
        assert!(HEADER_LEN + out.as_bytes().len() <= MESSAGE_MAX);
        let oversized = ChangeSecond {
            bytes: &long,
            ..second
        };
        assert_eq!(oversized.write(&mut Writer::new()), Err(Status::BadSize));
    }
    #[test]
    fn empty_first_path_needs_a_descriptor_and_an_operation_that_takes_it() {
        let invalid = Err(Status::from_code(crate::INVALID_ARGUMENT));
        assert_eq!(start(ChangeOp::Chmod, b"").validate(), invalid);
        for op in [ChangeOp::Unlink, ChangeOp::Mkdir, ChangeOp::Access] {
            let mut value = start(op, b"");
            value.base = Base::Fd {
                fd: 3,
                generation: 1,
            };
            assert_eq!(value.validate(), invalid, "{op:?}");
        }
        for op in [
            ChangeOp::Chmod,
            ChangeOp::Chown,
            ChangeOp::StatVfs,
            ChangeOp::Path,
        ] {
            let mut value = start(op, b"");
            value.base = Base::Fd {
                fd: 3,
                generation: 1,
            };
            assert_eq!(value.validate(), Ok(()), "{op:?}");
        }
    }
    #[test]
    fn unknown_operations_flags_and_arguments_are_refused() {
        let mut out = Writer::new();
        start(ChangeOp::Unlink, b"/a").write(&mut out).unwrap();
        let mut bytes = [0; 128];
        let n = out.as_bytes().len();
        bytes[..n].copy_from_slice(out.as_bytes());
        for op in [0u32, 13, u32::MAX] {
            bytes[12..16].copy_from_slice(&op.to_le_bytes());
            assert_eq!(
                ChangeStart::read(Reader::new(&bytes[..n])),
                Err(Status::from_code(crate::INVALID_ARGUMENT)),
                "{op}"
            );
        }
        let mut unlink = start(ChangeOp::Unlink, b"/a");
        unlink.flags = 2;
        assert_eq!(unlink.validate(), Err(Status::BadSize));
        let mut mkdir = start(ChangeOp::Mkdir, b"/a");
        mkdir.args[0] = 0o10000;
        assert!(mkdir.validate().is_err());
        let mut times = start(ChangeOp::Times, b"/a");
        times.args[1] = 1_000_000_000;
        assert!(times.validate().is_err());
        let mut readlink = start(ChangeOp::ReadLink, b"/a");
        assert!(readlink.validate().is_err(), "size 0");
        readlink.args[0] = 1;
        assert!(readlink.validate().is_ok());
        let mut stat = start(ChangeOp::StatVfs, b"/a");
        stat.args[2] = 1;
        assert!(stat.validate().is_err());
        let mut key = start(ChangeOp::Unlink, b"/a");
        key.key.slot = 32;
        assert!(key.validate().is_err());
        key.key = OpenKey {
            slot: 0,
            generation: 0,
        };
        assert!(key.validate().is_err());
        // Truncated and extended bodies.
        for end in 0..60 {
            if let Ok(value) = ChangeStart::read(Reader::new(&bytes[..end]))
                && end < n
            {
                panic!("short body {end} read as {value:?}");
            }
        }
    }
    #[test]
    fn second_takes_a_link_content_of_0_and_511_and_a_path_of_1_to_511() {
        let content = [b'x'; MAX_PATH];
        let second = |bytes| ChangeSecond {
            key: KEY,
            base: Base::Fd {
                fd: 5,
                generation: 2,
            },
            bytes,
        };
        for bytes in [&content[..0], &content[..], &content[..1]] {
            let value = second(bytes);
            let mut out = Writer::new();
            value.write(&mut out).unwrap();
            assert_eq!(ChangeSecond::read(Reader::new(out.as_bytes())), Ok(value));
            assert_eq!(value.validate_for(ChangeOp::Symlink), Ok(()));
        }
        let empty = second(&content[..0]);
        for op in [ChangeOp::Rename, ChangeOp::Link] {
            assert_eq!(
                empty.validate_for(op),
                Err(Status::from_code(crate::INVALID_ARGUMENT))
            );
            assert_eq!(second(&content).validate_for(op), Ok(()));
        }
        for op in [ChangeOp::Unlink, ChangeOp::Chmod, ChangeOp::Path] {
            assert_eq!(
                second(&content).validate_for(op),
                Err(Status::from_code(crate::INVALID_ARGUMENT))
            );
        }
    }
    #[test]
    fn keys_bodies_and_replies_round_trip() {
        let mut out = Writer::new();
        write_key_body(&mut out, KEY).unwrap();
        assert_eq!(read_key_body(Reader::new(out.as_bytes())), Ok(KEY));
        out.u32(0).unwrap();
        assert!(read_key_body(Reader::new(out.as_bytes())).is_err());
        let mut out = Writer::new();
        write_start_reply(&mut out, ChangePhase::AwaitingSecond).unwrap();
        assert_eq!(
            change_start_reply(out.as_bytes(), 0),
            Ok(ChangePhase::AwaitingSecond)
        );
        assert_eq!(change_start_reply(out.as_bytes(), 1), Err(Status::BadSize));
        let bytes = [7u8; RESULT_MAX];
        for reply in [
            ChangeReply {
                done: false,
                result: 0,
                restarts: 3,
                value: 0,
                bytes: &[],
            },
            ChangeReply {
                done: true,
                result: 0,
                restarts: 0,
                value: 9,
                bytes: &bytes,
            },
            ChangeReply {
                done: true,
                result: crate::NO_ENTRY,
                restarts: u32::MAX,
                value: 0,
                bytes: &[],
            },
        ] {
            let mut out = Writer::new();
            reply.write(&mut out).unwrap();
            assert!(HEADER_LEN + out.as_bytes().len() <= MESSAGE_MAX);
            assert_eq!(ChangeReply::read(out.as_bytes(), 0), Ok(reply));
        }
        let running_with_result = ChangeReply {
            done: false,
            result: 1,
            restarts: 0,
            value: 0,
            bytes: &[],
        };
        assert_eq!(
            running_with_result.write(&mut Writer::new()),
            Err(Status::BadSize)
        );
        let error = proto_wire::reply(Status::from_code(crate::OPEN_RETIRED));
        assert_eq!(
            ChangeReply::read(&error, 0),
            Err(Status::from_code(crate::OPEN_RETIRED))
        );
        let mut bad = error;
        bad[4] = 1;
        assert_eq!(ChangeReply::read(&bad, 0), Err(Status::BadSize));
    }
    #[test]
    fn bases_keep_the_two_reserved_values_apart_from_descriptors() {
        assert_eq!(Base::from_wire(BASE_ABSOLUTE, 0), Ok(Base::Absolute));
        assert_eq!(Base::from_wire(BASE_CWD, 0), Ok(Base::Cwd));
        assert_eq!(Base::from_wire(BASE_CWD, 1), Err(Status::BadSize));
        assert_eq!(
            Base::from_wire(4, 0),
            Ok(Base::Fd {
                fd: 4,
                generation: 0
            })
        );
        assert_eq!(Base::Absolute.wire(), (BASE_ABSOLUTE, 0));
    }
}
