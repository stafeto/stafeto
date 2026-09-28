// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Value messages for the current same-process POSIX owner. Paths and write
//! bytes are encoded into the message; no executor or caller storage address
//! is accepted. Directory identifiers and UART routes are process-local.

#![cfg_attr(not(test), no_std)]

pub mod exchange;
pub use proto_fs::MAX_READ;
pub const MAX_WRITE: usize = proto_fs::MAX_WRITE - exchange::HEADER_BYTES;
use proto_fs::{NodeInfo, SeekFrom};
use proto_wire::{Header, Reader, Status, Writer};
pub const MESSAGE_MAX: usize = MAX_READ + 8;
pub const VERSION: u16 = 1;

fn valid_path(path: &[u8]) -> Result<(), Status> {
    if path.len() > proto_fs::MAX_PATH || path.contains(&0) {
        Err(Status::BadSize)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Open {
        flags: u32,
        path: &'a [u8],
    },
    Close {
        fd: u32,
    },
    Read {
        fd: u32,
        count: u32,
    },
    Write {
        fd: u32,
        bytes: &'a [u8],
    },
    Seek {
        fd: u32,
        offset: i64,
        origin: SeekFrom,
    },
    Dup {
        fd: u32,
    },
    Dup2 {
        source: u32,
        target: u32,
    },
    Dup3 {
        source: u32,
        target: u32,
        flags: u32,
    },
    Chdir {
        path: &'a [u8],
    },
    Cwd,
    Stat {
        path: &'a [u8],
    },
    Fstat {
        fd: u32,
    },
    OpenDir {
        path: &'a [u8],
    },
    FdOpenDir {
        fd: u32,
    },
    DirRead {
        stream: u64,
    },
    DirClose {
        stream: u64,
    },
    DirFd {
        stream: u64,
    },
    DirTell {
        stream: u64,
    },
    DirSeek {
        stream: u64,
        position: i64,
    },
    DirRewind {
        stream: u64,
    },
    Cleanup,
}

impl<'a> Request<'a> {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        let method = match self {
            Self::Open { .. } => 1,
            Self::Close { .. } => 2,
            Self::Read { .. } => 3,
            Self::Write { .. } => 4,
            Self::Seek { .. } => 5,
            Self::Dup { .. } => 6,
            Self::Dup2 { .. } => 7,
            Self::Dup3 { .. } => 8,
            Self::Chdir { .. } => 9,
            Self::Cwd => 10,
            Self::Stat { .. } => 11,
            Self::Fstat { .. } => 12,
            Self::OpenDir { .. } => 13,
            Self::FdOpenDir { .. } => 14,
            Self::DirRead { .. } => 15,
            Self::DirClose { .. } => 16,
            Self::DirFd { .. } => 17,
            Self::DirTell { .. } => 18,
            Self::DirSeek { .. } => 19,
            Self::DirRewind { .. } => 20,
            Self::Cleanup => 21,
        };
        Header::new(method, VERSION).write(out)?;
        match self {
            Self::Open { flags, path } => {
                out.u32(flags)?;
                valid_path(path)?;
                out.bytes(path)?;
            }
            Self::Close { fd } => {
                out.u32(fd)?;
            }
            Self::Read { fd, count } => {
                out.u32(fd)?;
                out.u32(count)?;
            }
            Self::Write { fd, bytes } => {
                out.u32(fd)?;
                if bytes.len() > MAX_WRITE {
                    return Err(Status::BadSize);
                }
                out.bytes(bytes)?;
            }
            Self::Seek { fd, offset, origin } => {
                out.u32(fd)?;
                out.u64(offset as u64)?;
                out.u32(origin as u32)?;
            }
            Self::Dup { fd } => {
                out.u32(fd)?;
            }
            Self::Dup2 { source, target } => {
                out.u32(source)?;
                out.u32(target)?;
            }
            Self::Dup3 {
                source,
                target,
                flags,
            } => {
                out.u32(source)?;
                out.u32(target)?;
                out.u32(flags)?;
            }
            Self::Chdir { path } => {
                valid_path(path)?;
                out.bytes(path)?;
            }
            Self::Cwd => {}
            Self::Stat { path } => {
                valid_path(path)?;
                out.bytes(path)?;
            }
            Self::Fstat { fd } => {
                out.u32(fd)?;
            }
            Self::OpenDir { path } => {
                valid_path(path)?;
                out.bytes(path)?;
            }
            Self::FdOpenDir { fd } => {
                out.u32(fd)?;
            }
            Self::DirRead { stream } => {
                out.u64(stream)?;
            }
            Self::DirClose { stream } => {
                out.u64(stream)?;
            }
            Self::DirFd { stream } => {
                out.u64(stream)?;
            }
            Self::DirTell { stream } => {
                out.u64(stream)?;
            }
            Self::DirSeek { stream, position } => {
                out.u64(stream)?;
                out.u64(position as u64)?;
            }
            Self::DirRewind { stream } => {
                out.u64(stream)?;
            }
            Self::Cleanup => {}
        }
        Ok(())
    }

    pub fn read(bytes: &'a [u8]) -> Result<Self, Status> {
        if bytes.len() > MESSAGE_MAX {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let header = Header::read(&mut input)?;
        if header.version != VERSION {
            return Err(Status::BadVersion);
        }
        let request = match header.method {
            1 => {
                let flags = input.u32()?;
                let path = input.bytes(input.left())?;
                valid_path(path)?;
                Self::Open { flags, path }
            }
            2 => {
                let fd = input.u32()?;
                Self::Close { fd }
            }
            3 => {
                let fd = input.u32()?;
                let count = input.u32()?;
                Self::Read { fd, count }
            }
            4 => {
                let fd = input.u32()?;
                let bytes = input.bytes(input.left())?;
                if bytes.len() > MAX_WRITE {
                    return Err(Status::BadSize);
                }
                Self::Write { fd, bytes }
            }
            5 => {
                let fd = input.u32()?;
                let offset = input.u64()? as i64;
                let origin = SeekFrom::from_number(input.u32()?).ok_or(Status::BadSize)?;
                Self::Seek { fd, offset, origin }
            }
            6 => {
                let fd = input.u32()?;
                Self::Dup { fd }
            }
            7 => {
                let source = input.u32()?;
                let target = input.u32()?;
                Self::Dup2 { source, target }
            }
            8 => {
                let source = input.u32()?;
                let target = input.u32()?;
                let flags = input.u32()?;
                Self::Dup3 {
                    source,
                    target,
                    flags,
                }
            }
            9 => {
                let path = input.bytes(input.left())?;
                valid_path(path)?;
                Self::Chdir { path }
            }
            10 => Self::Cwd,
            11 => {
                let path = input.bytes(input.left())?;
                valid_path(path)?;
                Self::Stat { path }
            }
            12 => {
                let fd = input.u32()?;
                Self::Fstat { fd }
            }
            13 => {
                let path = input.bytes(input.left())?;
                valid_path(path)?;
                Self::OpenDir { path }
            }
            14 => {
                let fd = input.u32()?;
                Self::FdOpenDir { fd }
            }
            15 => {
                let stream = input.u64()?;
                Self::DirRead { stream }
            }
            16 => {
                let stream = input.u64()?;
                Self::DirClose { stream }
            }
            17 => {
                let stream = input.u64()?;
                Self::DirFd { stream }
            }
            18 => {
                let stream = input.u64()?;
                Self::DirTell { stream }
            }
            19 => {
                let stream = input.u64()?;
                let position = input.u64()? as i64;
                Self::DirSeek { stream, position }
            }
            20 => {
                let stream = input.u64()?;
                Self::DirRewind { stream }
            }
            21 => Self::Cleanup,
            _ => return Err(Status::UnknownMethod),
        };
        input.finish()?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply<'a> {
    Error(i32),
    Unit,
    Number(u64),
    Info(NodeInfo),
    Bytes(&'a [u8]),
    Input { uart: Option<u64>, extent: u32 },
}

impl<'a> Reply<'a> {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if let Self::Error(code) = self {
            if !(1..=4095).contains(&code) {
                return Err(Status::BadSize);
            }
            out.u32(code as u32)?;
            return out.u32(0);
        }
        out.u32(0)?;
        match self {
            Self::Error(_) => unreachable!(),
            Self::Unit => out.u32(0),
            Self::Number(value) => {
                out.u32(1)?;
                out.u64(value)
            }
            Self::Info(info) => {
                out.u32(2)?;
                info.write(out)
            }
            Self::Bytes(bytes) => {
                if bytes.len() > MAX_READ {
                    return Err(Status::BadSize);
                }
                // Pack the length with the tag to fit a full RAM read in 1024 bytes.
                out.u32(3 | ((bytes.len() as u32) << 16))?;
                out.bytes(bytes)
            }
            Self::Input { uart, extent } => {
                if extent == 0 || extent as usize > MAX_READ || uart == Some(0) {
                    return Err(Status::BadSize);
                }
                out.u32(4)?;
                out.u64(uart.unwrap_or(0))?;
                out.u32(extent)
            }
        }
    }

    pub fn read(bytes: &'a [u8]) -> Result<Self, Status> {
        if bytes.len() > MESSAGE_MAX {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let status = input.u32()?;
        let tag = input.u32()?;
        if status != 0 {
            if status > 4095 || tag != 0 {
                return Err(Status::BadSize);
            }
            input.finish()?;
            return Ok(Self::Error(status as i32));
        }
        let reply = match tag {
            0 => Self::Unit,
            1 => Self::Number(input.u64()?),
            2 => Self::Info(NodeInfo::read(&mut input)?),
            4 => {
                let raw = input.u64()?;
                let extent = input.u32()?;
                if extent == 0 || extent as usize > MAX_READ {
                    return Err(Status::BadSize);
                }
                Self::Input {
                    uart: if raw == 0 { None } else { Some(raw) },
                    extent,
                }
            }
            tag if tag & 0xffff == 3 => {
                let length = (tag >> 16) as usize;
                if length > MAX_READ {
                    return Err(Status::BadSize);
                }
                Self::Bytes(input.bytes(length)?)
            }
            _ => return Err(Status::BadSize),
        };
        input.finish()?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests;
