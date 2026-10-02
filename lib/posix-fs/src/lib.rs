// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! File and directory operations for the evolving Rust POSIX layer.
//! The current RAM service uses UTF-8 paths and bounded regular files.

#![no_std]

pub use posix_fd::Flags as DescriptorFlags;
use posix_fd::{Error as DescriptorError, Table};
use posix_path::{MAX_PATH, PathError, PathState};
pub use proto_fs::{DIRECTORY_ONLY, MAX_READ, NodeInfo, SeekFrom};
use proto_wire::Status;
use rt::Handle;
use rt::fs::Files;
use rt::handle::Channel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    NoEntry,
    PermissionDenied,
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
    Interrupted,
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
            Status::Kernel(rt::abi::Error::Interrupted) => Self::Interrupted,
            Status::Unknown(proto_fs::NO_ENTRY) => Self::NoEntry,
            Status::Unknown(proto_fs::ACCESS_DENIED) => Self::PermissionDenied,
            Status::Unknown(proto_fs::BAD_FD) => Self::BadFileDescriptor,
            Status::Unknown(proto_fs::IS_DIRECTORY) => Self::IsDirectory,
            Status::Unknown(proto_fs::NOT_DIRECTORY) => Self::NotDirectory,
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
            3 => Ok(Self::Character),
            _ => Err(FsError::Io),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub kind: FileKind,
    pub size: u32,
}

/// Owns a process descriptor until closedir. The caller must not close or
/// replace it while this stream is live. Positions belong to the service.
pub struct Directory {
    fd: u32,
}

impl Directory {
    pub fn descriptor(&self) -> u32 {
        self.fd
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub inode: u64,
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
/// transfer requires service-owned session sharing. The shared C ABI worker
/// serializes calls from threads of the same process.
pub struct PosixFs {
    files: Files,
    paths: PathState,
    descriptors: Table<Backend, OPEN_MAX>,
}

/// A prepared read. RAM data is already serialized through the file owner;
/// console waiting runs on the client while PosixFs retains the transport.
pub struct PreparedRead(ReadState);

// Fixed stack storage keeps reads usable before process allocation is initialized.
#[allow(clippy::large_enum_variant)]
enum ReadState {
    Data(usize, [u8; MAX_READ]),
    Input(rt::fs::Input, usize),
}

impl PreparedRead {
    /// The non-owning console route, retained by this process's file owner.
    pub fn input(&self) -> Option<(rt::fs::Input, usize)> {
        match &self.0 {
            ReadState::Input(input, extent) => Some((*input, *extent)),
            ReadState::Data(..) => None,
        }
    }

    pub fn complete(self) -> Result<(usize, [u8; MAX_READ]), FsError> {
        match self.0 {
            ReadState::Data(length, bytes) => Ok((length, bytes)),
            ReadState::Input(input, extent) => {
                let mut bytes = [0; MAX_READ];
                let length = input.read(&mut bytes[..extent]).map_err(FsError::from)?;
                Ok((length, bytes))
            }
        }
    }
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

    /// Validate a descriptor and snapshot console routing without waiting.
    /// Keep this owner alive until every prepared console read finishes.
    /// Closing or replacing a local fd does not close its retained transport.
    pub fn prepare_read(&self, fd: u32, count: usize) -> Result<PreparedRead, FsError> {
        let backend = self.descriptors.get(fd)?;
        let extent = count.min(MAX_READ);
        if matches!(backend, Backend::Input) && extent != 0 {
            return Ok(PreparedRead(ReadState::Input(self.files.input(), extent)));
        }
        let mut bytes = [0; MAX_READ];
        let length = self.read(fd, &mut bytes[..extent])?;
        Ok(PreparedRead(ReadState::Data(length, bytes)))
    }

    pub fn read(&self, fd: u32, out: &mut [u8]) -> Result<usize, FsError> {
        let backend = match self.descriptors.get(fd)? {
            Backend::Input => 0,
            Backend::Ram(fd) => fd,
            _ => return Err(FsError::BadFileDescriptor),
        };
        self.files.read(backend, out).map_err(FsError::from)
    }

    /// The console route of `fd` when it is standard output or error, for
    /// a write the caller makes after it let go of the file state (the
    /// owner stays alive meanwhile); None for a file of the service.
    pub fn console_route(&self, fd: u32) -> Result<Option<rt::fs::Input>, FsError> {
        Ok(match self.descriptors.get(fd)? {
            Backend::Output | Backend::Error => Some(self.files.input()),
            _ => None,
        })
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
            Backend::Ram(fd) => {
                let info = self
                    .files
                    .descriptor_information(fd)
                    .map_err(FsError::from)?;
                Ok(Metadata {
                    kind: FileKind::from_wire(info.kind)?,
                    size: u32::try_from(info.size).map_err(|_| FsError::OffsetOverflow)?,
                })
            }
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

    pub fn stat_information(&self, path: &[u8]) -> Result<NodeInfo, FsError> {
        let trailing_slash = path.last() == Some(&b'/');
        let mut resolved = [0; MAX_PATH + 1];
        let name = self.path(path, &mut resolved)?;
        let info = self.files.node_information(name).map_err(FsError::from)?;
        if trailing_slash && FileKind::from_wire(info.kind)? != FileKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(info)
    }

    pub fn descriptor_information(&self, fd: u32) -> Result<NodeInfo, FsError> {
        match self.descriptors.get(fd)? {
            Backend::Ram(fd) => self.files.descriptor_information(fd).map_err(FsError::from),
            // Unnamed console transport; richer terminal metadata comes with
            // the terminal service and its namespace entry.
            _ => Ok(NodeInfo {
                kind: 3,
                permissions: 0o666,
                device: 2,
                special_device: 1,
                inode: 1,
                links: 1,
                uid: 0,
                gid: 0,
                size: 0,
                block_size: 1024,
                blocks: 0,
                access_ns: 0,
                modify_ns: 0,
                change_ns: 0,
            }),
        }
    }

    pub fn opendir(&mut self, path: &[u8]) -> Result<Directory, FsError> {
        if self.stat(path)?.kind != FileKind::Directory {
            return Err(FsError::NotDirectory);
        }
        let fd = self.open(path, proto_fs::READ_ONLY | proto_fs::DIRECTORY_ONLY)?;
        self.set_descriptor_flags(
            fd,
            DescriptorFlags {
                close_on_exec: true,
                close_on_fork: false,
            },
        )?;
        Ok(Directory { fd })
    }

    /// Transfer an existing readable directory descriptor to a stream. Flags
    /// remain unchanged. Failure leaves ownership with the caller.
    pub fn fdopendir(&self, fd: u32) -> Result<Directory, FsError> {
        if self.fstat(fd)?.kind != FileKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(Directory { fd })
    }

    pub fn closedir(&mut self, dir: &Directory) -> Result<(), FsError> {
        self.close(dir.fd)
    }

    pub fn directory_position(&self, dir: &Directory) -> Result<i64, FsError> {
        self.lseek(dir.fd, 0, SeekFrom::Current)
    }

    pub fn seekdir(&self, dir: &Directory, position: i64) -> Result<(), FsError> {
        self.lseek(dir.fd, position, SeekFrom::Start).map(|_| ())
    }

    pub fn rewinddir(&self, dir: &Directory) -> Result<(), FsError> {
        self.seekdir(dir, 0)
    }

    pub fn readdir(
        &self,
        dir: &mut Directory,
        out: &mut [u8],
    ) -> Result<Option<DirEntry>, FsError> {
        match self.descriptors.get(dir.fd)? {
            Backend::Ram(fd) => self
                .files
                .read_dir_fd(fd, out)
                .map_err(FsError::from)?
                .map(|(name_len, kind, inode)| {
                    Ok(DirEntry {
                        inode,
                        kind: FileKind::from_wire(kind)?,
                        name_len,
                    })
                })
                .transpose(),
            _ => Err(FsError::NotDirectory),
        }
    }
}
