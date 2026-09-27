// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! File and directory operations for the evolving Rust POSIX layer.
//! The current RAM service uses UTF-8 paths and offers only absolute seeking.

#![no_std]

use posix_path::{MAX_PATH, PathError, PathState};
use proto_wire::Status;
use rt::Handle;
use rt::fs::Files;
use rt::handle::Channel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    NoEntry,
    BadFileDescriptor,
    IsDirectory,
    NotDirectory,
    NoSpace,
    NameTooLong,
    InvalidArgument,
    UnsupportedEncoding,
    Io,
}

impl From<PathError> for FsError {
    fn from(error: PathError) -> Self {
        match error {
            PathError::Empty => Self::NoEntry,
            PathError::TooLong => Self::NameTooLong,
            PathError::Invalid => Self::InvalidArgument,
        }
    }
}

impl From<Status> for FsError {
    fn from(status: Status) -> Self {
        match status {
            Status::Unknown(proto_fs::NO_ENTRY) => Self::NoEntry,
            Status::Unknown(proto_fs::BAD_FD) => Self::BadFileDescriptor,
            Status::Unknown(proto_fs::IS_DIRECTORY) => Self::IsDirectory,
            Status::Unknown(proto_fs::NO_SPACE) => Self::NoSpace,
            Status::BadSize => Self::InvalidArgument,
            _ => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Directory,
    Regular,
}

impl FileKind {
    fn from_wire(kind: u32) -> Result<Self, FsError> {
        match kind {
            1 => Ok(Self::Directory),
            2 => Ok(Self::Regular),
            _ => Err(FsError::Io),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub kind: FileKind,
    pub size: u32,
}

pub struct Directory {
    path: [u8; MAX_PATH + 1],
    length: usize,
    next: u32,
}

impl Directory {
    pub fn rewind(&mut self) {
        self.next = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub kind: FileKind,
    pub name_len: usize,
}

pub struct PosixFs {
    files: Files,
    paths: PathState,
}

impl PosixFs {
    pub fn connect(parent: &Handle<Channel>) -> Result<Self, FsError> {
        Ok(Self {
            files: Files::connect(parent).map_err(FsError::from)?,
            paths: PathState::new(),
        })
    }

    pub fn cwd(&self) -> &[u8] {
        self.paths.cwd()
    }

    fn path<'a>(&self, input: &[u8], out: &'a mut [u8; MAX_PATH + 1]) -> Result<&'a str, FsError> {
        let length = self.paths.resolve(input, out)?;
        core::str::from_utf8(&out[..length]).map_err(|_| FsError::UnsupportedEncoding)
    }

    pub fn chdir(&mut self, path: &[u8]) -> Result<(), FsError> {
        if self.stat(path)?.kind != FileKind::Directory {
            return Err(FsError::NotDirectory);
        }
        self.paths.set_cwd(path)?;
        Ok(())
    }

    pub fn open(&self, path: &[u8], flags: u32) -> Result<u32, FsError> {
        if path.last() == Some(&b'/') && self.stat(path)?.kind == FileKind::Regular {
            return Err(FsError::NotDirectory);
        }
        let mut resolved = [0; MAX_PATH + 1];
        let path = self.path(path, &mut resolved)?;
        self.files.open(path, flags).map_err(FsError::from)
    }

    pub fn close(&self, fd: u32) -> Result<(), FsError> {
        self.files.close(fd).map_err(FsError::from)
    }

    pub fn read(&self, fd: u32, out: &mut [u8]) -> Result<usize, FsError> {
        self.files.read(fd, out).map_err(FsError::from)
    }

    pub fn write(&self, fd: u32, bytes: &[u8]) -> Result<usize, FsError> {
        self.files.write(fd, bytes).map_err(FsError::from)
    }

    pub fn seek_set(&self, fd: u32, offset: u32) -> Result<u32, FsError> {
        self.files.lseek(fd, offset).map_err(FsError::from)
    }

    pub fn fstat(&self, fd: u32) -> Result<Metadata, FsError> {
        Ok(Metadata {
            kind: FileKind::Regular,
            size: self.files.fstat_size(fd).map_err(FsError::from)?,
        })
    }

    pub fn stat(&self, path: &[u8]) -> Result<Metadata, FsError> {
        let trailing_slash = path.last() == Some(&b'/');
        let mut resolved = [0; MAX_PATH + 1];
        let path = self.path(path, &mut resolved)?;
        let meta = self.files.lookup(path).map_err(FsError::from)?;
        let kind = FileKind::from_wire(meta.kind)?;
        if trailing_slash && kind == FileKind::Regular {
            return Err(FsError::NotDirectory);
        }
        Ok(Metadata {
            kind,
            size: meta.size,
        })
    }

    pub fn opendir(&self, path: &[u8]) -> Result<Directory, FsError> {
        let mut resolved = [0; MAX_PATH + 1];
        let length = self.paths.resolve(path, &mut resolved)?;
        let name =
            core::str::from_utf8(&resolved[..length]).map_err(|_| FsError::UnsupportedEncoding)?;
        let meta = self.files.lookup(name).map_err(FsError::from)?;
        match FileKind::from_wire(meta.kind)? {
            FileKind::Directory => Ok(Directory {
                path: resolved,
                length,
                next: 0,
            }),
            FileKind::Regular => Err(FsError::NotDirectory),
        }
    }

    pub fn readdir(
        &self,
        dir: &mut Directory,
        out: &mut [u8],
    ) -> Result<Option<DirEntry>, FsError> {
        let path = core::str::from_utf8(&dir.path[..dir.length])
            .map_err(|_| FsError::UnsupportedEncoding)?;
        match self
            .files
            .read_dir(path, dir.next, out)
            .map_err(FsError::from)?
        {
            Some((name_len, kind)) => {
                dir.next = dir.next.checked_add(1).ok_or(FsError::Io)?;
                let kind = FileKind::from_wire(kind)?;
                Ok(Some(DirEntry { kind, name_len }))
            }
            None => Ok(None),
        }
    }
}
