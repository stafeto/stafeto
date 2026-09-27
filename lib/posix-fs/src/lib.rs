// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! File and directory operations for the evolving Rust POSIX layer.
//! The current RAM service uses UTF-8 paths and bounded regular files.

#![no_std]

pub use posix_fd::Flags as DescriptorFlags;
use posix_fd::{Error as DescriptorError, Table};
use posix_path::{MAX_PATH, PathError, PathState};
pub use proto_fs::SeekFrom;
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
    TooManyOpenFiles,
    NotSeekable,
    OffsetOverflow,
    NoData,
    NameTooLong,
    InvalidArgument,
    UnsupportedEncoding,
    Io,
}

impl From<DescriptorError> for FsError {
    fn from(error: DescriptorError) -> Self {
        match error {
            DescriptorError::BadFileDescriptor => Self::BadFileDescriptor,
            DescriptorError::TooManyOpenFiles => Self::TooManyOpenFiles,
            DescriptorError::InvalidArgument => Self::InvalidArgument,
            DescriptorError::Io => Self::Io,
        }
    }
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
            Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES) => Self::TooManyOpenFiles,
            Status::Unknown(proto_fs::INVALID_ARGUMENT) | Status::BadSize => Self::InvalidArgument,
            Status::Unknown(proto_fs::OFFSET_OVERFLOW) => Self::OffsetOverflow,
            Status::Unknown(proto_fs::NO_DATA) => Self::NoData,
            _ => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Directory,
    Regular,
    Character,
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

/// Local descriptor bound. The RAM service separately bounds open descriptions.
pub const OPEN_MAX: usize = 32;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Backend {
    Input,
    Output,
    Error,
    Ram(u32),
}

fn release(files: &Files, backend: Backend) -> Result<(), DescriptorError> {
    match backend {
        Backend::Ram(fd) => files.close(fd).map_err(|_| DescriptorError::Io),
        _ => Ok(()),
    }
}

/// One process's file state, mutated by one owner. Duplication keeps the same
/// service descriptor, hence the same offset and file access mode. Process
/// transfer and concurrent access will require service-owned session sharing.
pub struct PosixFs {
    files: Files,
    paths: PathState,
    descriptors: Table<Backend, OPEN_MAX>,
}

impl PosixFs {
    pub fn connect(parent: &Handle<Channel>) -> Result<Self, FsError> {
        Self::from_files(Files::connect(parent).map_err(FsError::from)?)
    }

    pub fn connect_with_uart(parent: &Handle<Channel>) -> Result<Self, FsError> {
        Self::from_files(Files::connect_with_uart(parent).map_err(FsError::from)?)
    }

    fn from_files(files: Files) -> Result<Self, FsError> {
        let mut descriptors = Table::default();
        for backend in [Backend::Input, Backend::Output, Backend::Error] {
            descriptors.insert(backend, DescriptorFlags::default())?;
        }
        Ok(Self {
            files,
            paths: PathState::new(),
            descriptors,
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

    pub fn open(&mut self, path: &[u8], flags: u32) -> Result<u32, FsError> {
        if path.last() == Some(&b'/') && self.stat(path)?.kind == FileKind::Regular {
            return Err(FsError::NotDirectory);
        }
        let mut resolved = [0; MAX_PATH + 1];
        let path = self.path(path, &mut resolved)?;
        self.descriptors.vacant(0)?;
        let backend = self.files.open(path, flags).map_err(FsError::from)?;
        match self
            .descriptors
            .insert(Backend::Ram(backend), DescriptorFlags::default())
        {
            Ok(fd) => Ok(fd),
            Err(error) => {
                let _ = self.files.close(backend);
                Err(error.into())
            }
        }
    }

    pub fn close(&mut self, fd: u32) -> Result<(), FsError> {
        self.descriptors
            .close(fd, |backend| release(&self.files, backend))
            .map_err(FsError::from)
    }

    pub fn dup(&mut self, fd: u32) -> Result<u32, FsError> {
        self.dup_from(fd, 0, DescriptorFlags::default())
    }

    pub fn dup_from(
        &mut self,
        fd: u32,
        minimum: u32,
        flags: DescriptorFlags,
    ) -> Result<u32, FsError> {
        self.descriptors
            .duplicate(fd, minimum, flags)
            .map_err(FsError::from)
    }

    pub fn dup2(&mut self, source: u32, target: u32) -> Result<u32, FsError> {
        self.descriptors
            .dup2(source, target, |backend| release(&self.files, backend))
            .map_err(FsError::from)
    }

    pub fn dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: DescriptorFlags,
    ) -> Result<u32, FsError> {
        self.descriptors
            .dup3(source, target, flags, |backend| {
                release(&self.files, backend)
            })
            .map_err(FsError::from)
    }

    pub fn descriptor_flags(&self, fd: u32) -> Result<DescriptorFlags, FsError> {
        self.descriptors.flags(fd).map_err(FsError::from)
    }

    pub fn set_descriptor_flags(&mut self, fd: u32, flags: DescriptorFlags) -> Result<(), FsError> {
        self.descriptors.set_flags(fd, flags).map_err(FsError::from)
    }

    pub fn read(&self, fd: u32, out: &mut [u8]) -> Result<usize, FsError> {
        let backend = match self.descriptors.get(fd)? {
            Backend::Input => 0,
            Backend::Ram(fd) => fd,
            _ => return Err(FsError::BadFileDescriptor),
        };
        self.files.read(backend, out).map_err(FsError::from)
    }

    pub fn write(&self, fd: u32, bytes: &[u8]) -> Result<usize, FsError> {
        let backend = match self.descriptors.get(fd)? {
            Backend::Output => 1,
            Backend::Error => 2,
            Backend::Ram(fd) => fd,
            _ => return Err(FsError::BadFileDescriptor),
        };
        self.files.write(backend, bytes).map_err(FsError::from)
    }

    pub fn seek_set(&self, fd: u32, offset: u32) -> Result<u32, FsError> {
        self.lseek(fd, i64::from(offset), SeekFrom::Start)
            .map(|offset| offset as u32)
    }

    pub fn lseek(&self, fd: u32, offset: i64, origin: SeekFrom) -> Result<i64, FsError> {
        match self.descriptors.get(fd)? {
            Backend::Ram(fd) => self
                .files
                .seek_from(fd, offset, origin)
                .map_err(FsError::from),
            _ => Err(FsError::NotSeekable),
        }
    }

    pub fn fstat(&self, fd: u32) -> Result<Metadata, FsError> {
        match self.descriptors.get(fd)? {
            Backend::Ram(fd) => Ok(Metadata {
                kind: FileKind::Regular,
                size: self.files.fstat_size(fd).map_err(FsError::from)?,
            }),
            _ => Ok(Metadata {
                kind: FileKind::Character,
                size: 0,
            }),
        }
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
            FileKind::Regular | FileKind::Character => Err(FsError::NotDirectory),
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
