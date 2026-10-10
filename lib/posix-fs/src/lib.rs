// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! File and directory operations for the evolving Rust POSIX layer.
//! The RAM service owns byte paths, inode traversal and bounded regular files.

#![no_std]

pub mod change;
pub mod closing;
pub mod open;
mod target;
pub use target::RamTarget;

use core::mem::ManuallyDrop;
pub use posix_fd::Flags as DescriptorFlags;
use posix_fd::{Error as DescriptorError, Table};
use posix_path::{MAX_PATH, PathError, PathState};
pub use proto_fs::{
    APPEND, CHANGES, CREATE, DIRECTORY_ONLY, EXCLUSIVE, MAX_READ, NO_FOLLOW, NodeInfo, SeekFrom,
    TRUNCATE, Timestamp,
};
use proto_wire::Status;
use rt::Handle;
use rt::fs::{Files, View};
use rt::handle::Channel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    NoEntry,
    AlreadyExists,
    Loop,
    ReadOnlyFilesystem,
    TextBusy,
    OperationNotPermitted,
    PermissionDenied,
    BadFileDescriptor,
    IsDirectory,
    NotDirectory,
    NoSpace,
    FileTooLarge,
    TooManyOpenFiles,
    NotSeekable,
    OffsetOverflow,
    NoData,
    NameTooLong,
    InvalidArgument,
    UnsupportedEncoding,
    Interrupted,
    /// A pipe that would wait with O_NONBLOCK, or a wait past the limits.
    Again,
    /// A write to a pipe with no reader.
    Broken,
    /// Every pipe of the service in use.
    TooManyInSystem,
    /// A directory with too many links (EMLINK).
    TooManyLinks,
    /// A directory that is not empty (ENOTEMPTY).
    NotEmpty,
    /// A name or a directory in use that cannot go (EBUSY).
    Busy,
    /// A rename or a link between two devices (EXDEV).
    CrossDevice,
    /// An operation the object does not support (EOPNOTSUPP).
    NotSupported,
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
            Status::Unknown(proto_fs::ALREADY_EXISTS) => Self::AlreadyExists,
            Status::Unknown(proto_fs::LOOP) => Self::Loop,
            Status::Unknown(proto_fs::READ_ONLY_FILESYSTEM) => Self::ReadOnlyFilesystem,
            Status::Unknown(proto_fs::TEXT_BUSY) => Self::TextBusy,
            Status::Unknown(proto_fs::PERMISSION) => Self::OperationNotPermitted,
            Status::Unknown(proto_fs::ACCESS_DENIED) => Self::PermissionDenied,
            Status::Unknown(proto_fs::BAD_FD) => Self::BadFileDescriptor,
            Status::Unknown(proto_fs::IS_DIRECTORY) => Self::IsDirectory,
            Status::Unknown(proto_fs::NOT_DIRECTORY) => Self::NotDirectory,
            Status::Unknown(proto_fs::NO_SPACE) => Self::NoSpace,
            Status::Unknown(proto_fs::FILE_TOO_LARGE) => Self::FileTooLarge,
            Status::Unknown(proto_fs::NAME_TOO_LONG) => Self::NameTooLong,
            Status::Unknown(proto_fs::TOO_MANY_OPEN_FILES) => Self::TooManyOpenFiles,
            Status::Unknown(proto_fs::INVALID_ARGUMENT) | Status::BadSize => Self::InvalidArgument,
            Status::Unknown(proto_fs::OFFSET_OVERFLOW) => Self::OffsetOverflow,
            Status::Unknown(proto_fs::NO_DATA) => Self::NoData,
            Status::Unknown(proto_fs::TOO_MANY_LINKS) => Self::TooManyLinks,
            Status::Unknown(proto_fs::NOT_EMPTY) => Self::NotEmpty,
            Status::Unknown(proto_fs::BUSY) => Self::Busy,
            Status::Unknown(proto_fs::CROSS_DEVICE) => Self::CrossDevice,
            Status::Unknown(proto_fs::NOT_SUPPORTED) => Self::NotSupported,
            _ => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Directory,
    Regular,
    Character,
    Fifo,
}

/// The kind of a pipe's node information (NodeInfo::kind).
pub const FIFO: u32 = 4;

impl FileKind {
    fn from_wire(kind: u32) -> Result<Self, FsError> {
        match kind {
            1 => Ok(Self::Directory),
            2 => Ok(Self::Regular),
            3 => Ok(Self::Character),
            FIFO => Ok(Self::Fifo),
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
/// The longest current directory, in bytes.
pub const MAX_CWD: usize = MAX_PATH;

/// What a descriptor names: the console's input, output or error, an
/// open description of the RAM file service by its number in the
/// process's session, an end of a pipe of the pipe service by its
/// number there (5e), or an opaque open description of the terminal
/// service (5f). The implicit standard console uses CONSOLE (0); an
/// explicit terminal open has its own generation and description ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Input,
    Output,
    Error,
    Ram(RamTarget),
    Pipe(u32),
    Tty(u32),
    /// A random device (`/dev/random`, `/dev/urandom`, 5e'): the service's
    /// open description of this number takes the writes, the closes and
    /// the `fstat`, and the layer serves the reads from its generator.
    Random(RamTarget),
}

/// The name `ttyname` gives the terminal `terminal`.
pub fn terminal_path(terminal: u32) -> Option<&'static str> {
    (terminal == proto_tty::CONSOLE).then_some("/dev/console")
}

/// One process's file state, mutated by one owner: the table of
/// descriptors and the current directory. The requests to the services go
/// through the `Transport`, which needs no owner: the owner snapshots a
/// descriptor's target and holds it (`hold`), lets go of its lock, and the
/// request runs outside it (spec 2, 3.4; 5c). Duplication keeps the same
/// service descriptor, hence the same offset and file access mode.
pub struct PosixFs {
    files: Files,
    /// The session with the pipe service, when the process has one.
    pipes: Option<Handle<Channel>>,
    /// The session with the terminal service, when the process has one:
    /// the console's input, output and error go there (5f).
    terminal: Option<Handle<Channel>>,
    paths: PathState,
    descriptors: Table<Target, OPEN_MAX, open::Recovery, (), entries::Frame>,
}

// Control frame recovery fits in the existing custody payload union.
// Dedicated close records additionally retain one frame apiece.
const _: () = assert!(
    core::mem::size_of::<Table<Target, OPEN_MAX, open::Recovery, (), entries::Frame>>()
        == core::mem::size_of::<Table<Target, OPEN_MAX, open::Recovery>>()
            + posix_fd::JOBS_MAX * core::mem::size_of::<entries::Frame>()
);

/// Owned startup transports, prepared before the pinned descriptor table exists.
pub struct StartupFiles {
    files: Files,
    pipes: Option<Handle<Channel>>,
    terminal: Option<Handle<Channel>>,
}

impl StartupFiles {
    pub fn connect(parent: &Handle<Channel>, uart: bool) -> Result<Self, FsError> {
        let files = if uart {
            Files::connect_with_uart(parent)
        } else {
            Files::connect(parent)
        }
        .map_err(FsError::from)?;
        Ok(Self {
            files,
            pipes: rt::service::connect(parent, "pipe").ok(),
            terminal: None,
        })
    }

    pub fn from_sessions(
        files: Handle<Channel>,
        uart: Option<Handle<Channel>>,
        pipes: Option<Handle<Channel>>,
        terminal: Option<Handle<Channel>>,
    ) -> Self {
        Self {
            files: Files::from_sessions(files, uart),
            pipes,
            terminal,
        }
    }

    pub fn set_terminal(&mut self, terminal: Option<Handle<Channel>>) {
        self.terminal = terminal;
    }

    pub fn bind(&self, identity: &Handle<Channel>) -> Result<(), FsError> {
        self.files.bind(identity).map_err(FsError::from)
    }
}

/// The transports of a process's files, borrowed from its PosixFs, which
/// stays alive while a transport is used: what a request needs outside
/// the owner's lock.
#[derive(Clone, Copy)]
pub struct Transport(View, Option<rt::abi::Handle>, Option<rt::abi::Handle>);

/// A path the owner resolved against its current directory, for a
/// request outside its lock.
pub struct Resolved {
    bytes: [u8; MAX_PATH + 1],
    len: usize,
    /// The path the caller gave ends with a slash: a directory is meant.
    pub trailing_slash: bool,
}

impl Resolved {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn as_str(&self) -> Result<&str, FsError> {
        core::str::from_utf8(&self.bytes[..self.len]).map_err(|_| FsError::UnsupportedEncoding)
    }
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

/// The node information of the console's descriptors.
const CONSOLE_INFO: NodeInfo = NodeInfo {
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
    access_time: proto_fs::Timestamp::ZERO,
    modify_time: proto_fs::Timestamp::ZERO,
    change_time: proto_fs::Timestamp::ZERO,
};

impl Transport {
    /// Borrow the existing file session for paid client phases.
    pub fn files(&self) -> ManuallyDrop<Files> {
        self.0.files()
    }

    /// The session with the pipe service: BadFileDescriptor without one.
    pub fn pipes(&self) -> Result<ManuallyDrop<Handle<Channel>>, FsError> {
        self.1
            .map(Handle::borrowed)
            .ok_or(FsError::BadFileDescriptor)
    }

    /// The session with the terminal service, when the process has one.
    pub fn terminal(&self) -> Option<ManuallyDrop<Handle<Channel>>> {
        self.2.map(Handle::borrowed)
    }

    /// Close of the service's description `fd` that the table handed back.
    /// The console's targets take no frame of the requests: the probes of
    /// requests before the heap run it on a small stack.
    pub fn release(&self, target: Option<Target>) -> Result<(), FsError> {
        match target {
            Some(Target::Ram(fd) | Target::Random(fd)) => self.close_file(fd),
            Some(Target::Pipe(end)) => self.close_pipe(end),
            Some(Target::Tty(id)) => self.close_terminal(id),
            _ => Ok(()),
        }
    }

    fn close_terminal(&self, id: u32) -> Result<(), FsError> {
        let mut request = proto_wire::Writer::new();
        proto_tty::description(proto_tty::Method::Close, id, None, &mut request)
            .map_err(FsError::from)?;
        let terminal = self.terminal().ok_or(FsError::BadFileDescriptor)?;
        let reply = loop {
            match rt::sys::send(&terminal, request.as_bytes()) {
                Err(rt::abi::Error::Interrupted) => continue,
                result => break result.map_err(|_| FsError::Io)?,
            }
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let code = proto_wire::Reader::new(reply.bytes(&mut buffer))
            .u32()
            .map_err(FsError::from)?;
        match code {
            0 => Ok(()),
            proto_tty::BAD_DESCRIPTION => Err(FsError::BadFileDescriptor),
            _ => Err(FsError::Io),
        }
    }

    #[inline(never)]
    fn close_file(&self, fd: RamTarget) -> Result<(), FsError> {
        self.files()
            .close_exact(fd.prepared())
            .map(|_| ())
            .map_err(FsError::from)
    }

    #[inline(never)]
    fn close_pipe(&self, end: u32) -> Result<(), FsError> {
        self.pipe_call(proto_pipe::Method::Close, end, None)
            .map(drop)
    }

    /// A request of one end of a pipe (CLOSE, GET_FLAGS, SET_FLAGS, STAT)
    /// and the words of its reply after the status. Its buffers stay out
    /// of the frames of its callers (`release` runs on small stacks too).
    #[inline(never)]
    pub fn pipe_call(
        &self,
        method: proto_pipe::Method,
        end: u32,
        word: Option<u32>,
    ) -> Result<[u32; 2], FsError> {
        let mut w = proto_wire::Writer::new();
        proto_pipe::end_request(method, end, word, &mut w).map_err(|_| FsError::Io)?;
        self.pipe_send(w.as_bytes())
    }

    /// A request to the pipe service and up to two words of its reply.
    #[inline(never)]
    fn pipe_send(&self, request: &[u8]) -> Result<[u32; 2], FsError> {
        let pipes = self.pipes()?;
        let reply = loop {
            match rt::sys::send(&pipes, request) {
                Err(rt::abi::Error::Interrupted) => continue,
                other => break other.map_err(|_| FsError::Io)?,
            }
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
        match Status::from_code(r.u32().map_err(|_| FsError::Io)?) {
            Status::Ok => Ok([r.u32().unwrap_or(0), r.u32().unwrap_or(0)]),
            status => Err(pipe_error(status)),
        }
    }

    /// CREATE: a new pipe, its read end and its write end.
    pub fn pipe_create(&self, nonblock: bool) -> Result<(u32, u32), FsError> {
        let mut w = proto_wire::Writer::new();
        proto_pipe::Method::Create
            .header()
            .write(&mut w)
            .and_then(|()| w.u32(if nonblock { proto_pipe::NONBLOCK } else { 0 }))
            .map_err(|_| FsError::Io)?;
        let [read, write] = self.pipe_send(w.as_bytes())?;
        Ok((read, write))
    }

    /// Capture the complete held outcome before the descriptor becomes public.
    pub fn opened_target(held: rt::fs::PreparedOpen, access: u32) -> Result<Target, FsError> {
        if access > proto_fs::READ_WRITE {
            return Err(FsError::InvalidArgument);
        }
        let exact = RamTarget::from_prepared(held)?;
        Ok(if held.random && access != proto_fs::WRITE_ONLY {
            Target::Random(exact)
        } else {
            Target::Ram(exact)
        })
    }

    /// The console's input route of the process.
    pub fn input(&self) -> rt::fs::Input {
        self.files().input()
    }

    pub fn prepare_read(&self, target: Target, count: usize) -> Result<PreparedRead, FsError> {
        let extent = count.min(MAX_READ);
        if matches!(target, Target::Input) && extent != 0 {
            return Ok(PreparedRead(ReadState::Input(self.input(), extent)));
        }
        let mut bytes = [0; MAX_READ];
        let length = self.read(target, &mut bytes[..extent])?;
        Ok(PreparedRead(ReadState::Data(length, bytes)))
    }

    pub fn read(&self, target: Target, out: &mut [u8]) -> Result<usize, FsError> {
        let fd = match target {
            Target::Input => 0,
            Target::Ram(fd) => fd.fd(),
            _ => return Err(FsError::BadFileDescriptor),
        };
        self.files().read(fd, out).map_err(FsError::from)
    }

    /// pread of the service's description `fd`.
    pub fn read_at(&self, fd: u32, offset: u64, out: &mut [u8]) -> Result<usize, FsError> {
        self.files().read_at(fd, offset, out).map_err(FsError::from)
    }

    /// pwrite of the service's description `fd`.
    pub fn write_at(&self, fd: u32, offset: u64, bytes: &[u8]) -> Result<usize, FsError> {
        self.files()
            .write_at(fd, offset, bytes)
            .map_err(FsError::from)
    }

    pub fn write(&self, target: Target, bytes: &[u8]) -> Result<usize, FsError> {
        let fd = match target {
            Target::Output => 1,
            Target::Error => 2,
            Target::Ram(fd) | Target::Random(fd) => fd.fd(),
            _ => return Err(FsError::BadFileDescriptor),
        };
        self.files().write(fd, bytes).map_err(FsError::from)
    }

    pub fn lseek(&self, target: Target, offset: i64, origin: SeekFrom) -> Result<i64, FsError> {
        match target {
            Target::Ram(fd) | Target::Random(fd) => self
                .files()
                .seek_from(fd.fd(), offset, origin)
                .map_err(FsError::from),
            _ => Err(FsError::NotSeekable),
        }
    }

    fn terminal_information(&self, id: u32, physical: Option<u32>) -> Result<NodeInfo, FsError> {
        let mut w = proto_wire::Writer::new();
        proto_tty::Method::Stat
            .header()
            .write(&mut w)
            .map_err(FsError::from)?;
        w.u32(id).map_err(FsError::from)?;
        if let Some(terminal) = physical {
            w.u32(terminal).map_err(FsError::from)?;
        }
        let channel = self.terminal().ok_or(FsError::BadFileDescriptor)?;
        let reply = loop {
            match rt::sys::send(&channel, w.as_bytes()) {
                Err(rt::abi::Error::Interrupted) => continue,
                result => break result.map_err(|_| FsError::Io)?,
            }
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        let mut r = proto_wire::Reader::new(bytes);
        match r.u32().map_err(FsError::from)? {
            0 => {}
            proto_tty::BAD_DESCRIPTION => return Err(FsError::BadFileDescriptor),
            proto_tty::NO_ENTRY => return Err(FsError::NoEntry),
            _ => return Err(FsError::Io),
        }
        let info =
            proto_tty::Stat::read(proto_wire::Reader::new(&bytes[4..])).map_err(FsError::from)?;
        Ok(NodeInfo {
            kind: 3,
            uid: info.uid,
            gid: info.gid,
            permissions: info.mode & 0o7777,
            device: 4,
            special_device: u64::from(info.terminal) + (u64::from(info.side) << 32),
            inode: u64::from(info.terminal) + 1,
            ..CONSOLE_INFO
        })
    }

    pub fn descriptor_information(&self, target: Target) -> Result<NodeInfo, FsError> {
        match target {
            Target::Ram(fd) | Target::Random(fd) => self
                .files()
                .descriptor_information(fd.fd())
                .map_err(FsError::from),
            Target::Tty(id) => self.terminal_information(id, None),
            Target::Pipe(end) => {
                let [pipe, _] = self.pipe_call(proto_pipe::Method::Stat, end, None)?;
                Ok(NodeInfo {
                    kind: FIFO,
                    permissions: 0o600,
                    device: 3,
                    special_device: 0,
                    inode: u64::from(pipe) + 1,
                    links: 1,
                    size: 0,
                    block_size: proto_pipe::CAPACITY as u32,
                    ..CONSOLE_INFO
                })
            }
            // Unnamed console transport; richer terminal metadata comes with
            // the terminal service and its namespace entry.
            _ => Ok(CONSOLE_INFO),
        }
    }

    pub fn fstat(&self, target: Target) -> Result<Metadata, FsError> {
        let info = self.descriptor_information(target)?;
        Ok(Metadata {
            kind: FileKind::from_wire(info.kind)?,
            size: u32::try_from(info.size).map_err(|_| FsError::OffsetOverflow)?,
        })
    }

    /// The terminal a descriptor's `target` is: the console's standard
    /// descriptors when the process has a session with the terminal
    /// service, and the terminals opened by name; None for the rest.
    pub fn terminal_number(&self, target: Target) -> Option<u32> {
        match target {
            Target::Tty(number) => Some(number),
            Target::Input | Target::Output | Target::Error if self.terminal().is_some() => {
                Some(proto_tty::CONSOLE)
            }
            _ => None,
        }
    }

    /// A virtual terminal leaf whose parent the RAM service resolved by inode.
    /// Parent search includes dot components and links under the actual identity.
    pub fn terminal_open(&self, path: &Resolved) -> Result<Option<(u32, u32)>, FsError> {
        self.terminal_leaf(None, path.as_bytes(), path.trailing_slash)
    }

    /// The same for a path that starts at a descriptor of the session: `base`
    /// is that descriptor and the generation of its description, None for a
    /// path from the root. A path with a slash in the end names a directory,
    /// which a virtual leaf is not: `trailing_slash` makes that ENOTDIR.
    pub fn terminal_leaf(
        &self,
        base: Option<(u32, u64)>,
        bytes: &[u8],
        trailing_slash: bool,
    ) -> Result<Option<(u32, u32)>, FsError> {
        if self.terminal().is_none() {
            return Ok(None);
        }
        let mut end = bytes.len();
        while end > 0 && bytes[end - 1] == b'/' {
            end -= 1;
        }
        // The slash before the leaf. A path from a descriptor may have none:
        // its parent is the descriptor's directory itself.
        let slash = match bytes[..end].iter().rposition(|&b| b == b'/') {
            Some(slash) => Some(slash),
            None if base.is_some() => None,
            None => return Ok(None),
        };
        let leaf = &bytes[slash.map_or(0, |slash| slash + 1)..end];
        let (named, parent): ((u32, u32), &[u8]) = match leaf {
            b"console" => ((proto_tty::OPEN_CONSOLE, 0), b"/dev/."),
            b"tty" => ((proto_tty::OPEN_CONTROLLING, 0), b"/dev/."),
            b"ptmx" => ((proto_tty::OPEN_MASTER, 0), b"/dev/."),
            _ => match core::str::from_utf8(leaf)
                .ok()
                .and_then(|n| n.parse::<u32>().ok())
            {
                Some(n) => ((proto_tty::OPEN_SLAVE, n), b"/dev/pts/."),
                None => return Ok(None),
            },
        };
        let mut directory = [0; MAX_PATH + 2];
        let length = match slash {
            Some(slash) => {
                directory[..slash].copy_from_slice(&bytes[..slash]);
                directory[slash..slash + 2].copy_from_slice(b"/.");
                slash + 2
            }
            None => {
                directory[0] = b'.';
                1
            }
        };
        let (actual, parent) =
            match self
                .files()
                .node_information_from(base, &directory[..length], true)
            {
                Ok(actual) => (actual, parent),
                Err(Status::Unknown(proto_fs::NO_ENTRY))
                    if named.0 == proto_tty::OPEN_SLAVE
                        && base.is_none()
                        && slash.is_some_and(|slash| bytes[..slash].ends_with(b"/pts")) =>
                {
                    // The terminal service also mounts pts for boot profiles whose
                    // immutable RAM image contains only /dev. Resolve its real parent.
                    let mount = slash.unwrap_or(0) - 4;
                    directory[mount..mount + 2].copy_from_slice(b"/.");
                    (
                        self.files()
                            .node_information_bytes(&directory[..mount + 2])?,
                        b"/dev/.".as_slice(),
                    )
                }
                Err(error) => return Err(error.into()),
            };
        let expected = match self.files().node_information_bytes(parent) {
            Ok(info) => info,
            Err(Status::Unknown(proto_fs::NO_ENTRY)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if actual.kind != 1 || actual.device != expected.device || actual.inode != expected.inode {
            return Ok(None);
        }
        if trailing_slash {
            return Err(FsError::NotDirectory);
        }
        Ok(Some(named))
    }

    /// The node information of a virtual leaf `terminal_leaf` found.
    pub fn terminal_leaf_information(&self, kind: u32, number: u32) -> Result<NodeInfo, FsError> {
        match kind {
            proto_tty::OPEN_MASTER => {
                self.terminal_information(proto_tty::STAT_PATH, Some(proto_tty::STAT_PATH))
            }
            proto_tty::OPEN_SLAVE => self.terminal_information(
                proto_tty::STAT_PATH,
                Some(number.checked_add(1).ok_or(FsError::NoEntry)?),
            ),
            _ => Ok(CONSOLE_INFO),
        }
    }

    pub fn stat(&self, path: &Resolved) -> Result<Metadata, FsError> {
        if self.terminal_open(path)?.is_some() {
            return Ok(Metadata {
                kind: FileKind::Character,
                size: 0,
            });
        }
        let meta = self
            .files()
            .lookup_bytes(path.as_bytes())
            .map_err(FsError::from)?;
        let kind = FileKind::from_wire(meta.kind)?;
        if path.trailing_slash && kind == FileKind::Regular {
            return Err(FsError::NotDirectory);
        }
        Ok(Metadata {
            kind,
            size: meta.size,
        })
    }

    pub fn stat_information(&self, path: &Resolved) -> Result<NodeInfo, FsError> {
        if let Some((kind, number)) = self.terminal_open(path)? {
            return self.terminal_leaf_information(kind, number);
        }
        let info = self
            .files()
            .node_information_bytes(path.as_bytes())
            .map_err(FsError::from)?;
        if path.trailing_slash && FileKind::from_wire(info.kind)? != FileKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(info)
    }

    pub fn readdir(&self, target: Target, out: &mut [u8]) -> Result<Option<DirEntry>, FsError> {
        match target {
            Target::Ram(fd) => self
                .files()
                .read_dir_fd(fd.fd(), out)
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

/// A descriptor a process starts with, from its parent's table (spec 2,
/// 3.2): its number, what it names, and the service's number of the
/// description for a file of the service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inherited {
    pub fd: u32,
    pub target: InheritedTarget,
}

/// Loader names carry raw RAM numbers until bound startup normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InheritedTarget {
    Ready(Target),
    RawRam { fd: u32, random_hint: bool },
}

/// The errno-like error of a refusal of the pipe service.
pub fn pipe_error(status: Status) -> FsError {
    match status.code() {
        proto_pipe::BAD_FD => FsError::BadFileDescriptor,
        proto_pipe::AGAIN => FsError::Again,
        proto_pipe::BROKEN => FsError::Broken,
        proto_pipe::NFILE => FsError::TooManyInSystem,
        proto_pipe::MFILE => FsError::TooManyOpenFiles,
        proto_pipe::INVALID => FsError::InvalidArgument,
        _ => match status {
            Status::Kernel(rt::abi::Error::LimitReached) => FsError::Again,
            Status::Kernel(rt::abi::Error::Interrupted) => FsError::Interrupted,
            _ => FsError::Io,
        },
    }
}

impl PosixFs {
    /// Initialize the process table directly in its permanent allocation.
    /// Errors consume startup transports before any destination field is written.
    ///
    /// # Safety
    /// `destination` names aligned, writable, uninitialized storage for Self.
    /// The caller owns it exclusively and pins its address through all records
    /// and waiters. Existing initialized resources require their own cleanup.
    #[inline(never)]
    pub unsafe fn initialize_at(
        destination: *mut Self,
        startup: StartupFiles,
        cwd: &[u8],
        inherited: Option<&[Inherited]>,
        secure: bool,
    ) -> Result<(), FsError> {
        let mut paths = PathState::new();
        if !cwd.is_empty() {
            paths.set_cwd(cwd)?;
        }
        let mut occupied = [false; OPEN_MAX];
        if let Some(list) = inherited {
            for item in list {
                let slot = occupied
                    .get_mut(item.fd as usize)
                    .ok_or(FsError::BadFileDescriptor)?;
                if *slot {
                    return Err(FsError::InvalidArgument);
                }
                *slot = true;
            }
        }
        let mut normalized = [None; OPEN_MAX];
        let mut captured = [None; OPEN_MAX];
        if let Some(list) = inherited {
            for (index, item) in list.iter().enumerate() {
                let ram_fd = |target| match target {
                    InheritedTarget::RawRam { fd, .. } => Some(fd),
                    InheritedTarget::Ready(Target::Ram(exact) | Target::Random(exact)) => {
                        Some(exact.fd())
                    }
                    _ => None,
                };
                let target = if let Some(fd) = ram_fd(item.target) {
                    let previous = list[..index]
                        .iter()
                        .position(|old| ram_fd(old.target) == Some(fd));
                    let info = if let Some(previous) = previous {
                        captured[previous].expect("previous RAM import normalized")
                    } else {
                        startup
                            .files
                            .capture_description(fd)
                            .map_err(FsError::from)?
                    };
                    let target = Transport::opened_target(info.held, info.flags & 3)?;
                    match item.target {
                        InheritedTarget::RawRam { random_hint, .. } => {
                            if matches!(target, Target::Random(_)) != random_hint {
                                return Err(FsError::Io);
                            }
                        }
                        InheritedTarget::Ready(expected) if expected != target => {
                            return Err(FsError::Io);
                        }
                        _ => {}
                    }
                    captured[index] = Some(info);
                    target
                } else {
                    let InheritedTarget::Ready(target) = item.target else {
                        unreachable!("raw RAM import has a numeric description");
                    };
                    target
                };
                normalized[item.fd as usize] = Some(target);
            }
        }
        let StartupFiles {
            files,
            pipes,
            terminal,
        } = startup;
        // SAFETY: the caller supplies exclusive uninitialized storage; preflight
        // completed and every field receives its initial valid value here.
        unsafe {
            core::ptr::addr_of_mut!((*destination).files).write(files);
            core::ptr::addr_of_mut!((*destination).pipes).write(pipes);
            core::ptr::addr_of_mut!((*destination).terminal).write(terminal);
            core::ptr::addr_of_mut!((*destination).paths).write(paths);
            Table::initialize_at(
                core::ptr::addr_of_mut!((*destination).descriptors),
                |target| matches!(target, Target::Tty(_)),
            );
        }
        // SAFETY: all fields are initialized; startup owns the only reference.
        let own = unsafe { &mut *destination };
        if let Some(list) = inherited {
            for item in list {
                own.descriptors
                    .place(
                        item.fd,
                        normalized[item.fd as usize].expect("normalized import"),
                        DescriptorFlags::default(),
                    )
                    .expect("validated startup descriptor");
            }
        }
        if inherited.is_none() || secure {
            for (fd, target) in [(0, Target::Input), (1, Target::Output), (2, Target::Error)] {
                if !occupied[fd as usize] {
                    own.descriptors
                        .place(fd, target, DescriptorFlags::default())
                        .expect("fresh standard descriptor");
                }
            }
        }
        Ok(())
    }

    /// The files of a program init started, through `parent`: the RAM
    /// files and, when init's table gives it one, a session with the pipe
    /// service.
    pub fn connect(parent: &Handle<Channel>) -> Result<Self, FsError> {
        let mut fs = Self::from_files(Files::connect(parent).map_err(FsError::from)?)?;
        fs.pipes = rt::service::connect(parent, "pipe").ok();
        Ok(fs)
    }

    pub fn connect_with_uart(parent: &Handle<Channel>) -> Result<Self, FsError> {
        let mut fs = Self::from_files(Files::connect_with_uart(parent).map_err(FsError::from)?)?;
        fs.pipes = rt::service::connect(parent, "pipe").ok();
        Ok(fs)
    }

    /// The session with the pipe service the program was given (its
    /// loader's start, the slot Pipes).
    pub fn set_pipes(&mut self, pipes: Option<Handle<Channel>>) {
        self.pipes = pipes;
    }

    /// The session with the terminal service the program was given (from
    /// init, or its loader's start, the slot Terminal): the console's
    /// targets go to it.
    pub fn set_terminal(&mut self, terminal: Option<Handle<Channel>>) {
        self.terminal = terminal;
    }

    /// The files through sessions the program was given (its loader's
    /// start, spec 2, 3.2), with `cwd` its current directory and the
    /// descriptors of `inherited` (the console's 0, 1 and 2 when None).
    /// With `secure`, the secure mode of a set-ID program, a free 0, 1 or
    /// 2 gets the console, so that no file the program opens becomes one
    /// of them.
    pub fn from_sessions(
        files: Handle<Channel>,
        uart: Option<Handle<Channel>>,
        cwd: &[u8],
        inherited: Option<&[Inherited]>,
        secure: bool,
    ) -> Result<Self, FsError> {
        let mut destination = core::mem::MaybeUninit::uninit();
        let startup = StartupFiles::from_sessions(files, uart, None, None);
        // SAFETY: this compatibility constructor owns fresh local storage until return.
        unsafe {
            Self::initialize_at(destination.as_mut_ptr(), startup, cwd, inherited, secure)?;
        }
        // SAFETY: initialize_at completed all fields.
        Ok(unsafe { destination.assume_init() })
    }

    /// The files of a forked child (spec 2, 3.2), whose table is a copy of
    /// its parent's: its own sessions `files`, `uart`, `pipes` and
    /// `terminal`, clones of its
    /// parent's that share the descriptions of the descriptors without
    /// FD_CLOFORK, in place of the parent's, which name nothing of the
    /// child's and go without a close; the descriptors with FD_CLOFORK go
    /// with no word to the service, which gave the child's session none of
    /// theirs, and so do the holds of the parent's requests.
    pub fn after_fork(
        &mut self,
        files: Handle<Channel>,
        uart: Option<Handle<Channel>>,
        pipes: Option<Handle<Channel>>,
        terminal: Option<Handle<Channel>>,
    ) {
        let parent = core::mem::replace(&mut self.files, Files::from_sessions(files, uart));
        core::mem::forget(parent);
        core::mem::forget(core::mem::replace(&mut self.pipes, pipes));
        core::mem::forget(core::mem::replace(&mut self.terminal, terminal));
        self.descriptors.discard_open_after_fork();
        while self.descriptors.abandon_hold().is_some() {}
        let mut closing = [false; OPEN_MAX];
        for (fd, _, flags) in self.descriptors.open() {
            closing[fd as usize] = flags.close_on_fork;
        }
        for (fd, close) in closing.iter().enumerate() {
            if *close {
                let _ = self.descriptors.close(fd as u32);
            }
        }
    }

    /// The service's descriptions a forked child's session shares with
    /// its parent's: those of the descriptors without FD_CLOFORK, each
    /// once, into `out`; how many.
    pub fn kept_by_fork(&self, out: &mut [rt::fs::PreparedOpen; OPEN_MAX]) -> usize {
        let mut count = 0;
        for (_, target, flags) in self.descriptors.open() {
            if let Target::Ram(n) | Target::Random(n) = target
                && !flags.close_on_fork
                && !out[..count].contains(&n.prepared())
            {
                out[count] = n.prepared();
                count += 1;
            }
        }
        count
    }

    /// Every RAM description retained by exec, including FD_CLOFORK.
    pub fn kept_by_exec(&self, out: &mut [rt::fs::PreparedOpen; OPEN_MAX]) -> usize {
        let mut count = 0;
        for (_, target, _) in self.descriptors.open() {
            if let Target::Ram(n) | Target::Random(n) = target
                && !out[..count].contains(&n.prepared())
            {
                out[count] = n.prepared();
                count += 1;
            }
        }
        count
    }

    /// The terminal descriptions retained by a forked child, each once.
    pub fn terminals_kept_by_fork(&self, out: &mut [u32; OPEN_MAX]) -> usize {
        let mut count = 0;
        for (_, target, flags) in self.descriptors.open() {
            if !flags.close_on_fork
                && let Target::Tty(id) = target
                && !out[..count].contains(&id)
            {
                out[count] = id;
                count += 1;
            }
        }
        count
    }

    /// Pipe ends retained by a forked child, each once.
    pub fn pipes_kept_by_fork(&self, out: &mut [u32; OPEN_MAX]) -> usize {
        let mut count = 0;
        for (_, target, flags) in self.descriptors.open() {
            if let Target::Pipe(n) = target
                && !flags.close_on_fork
                && !out[..count].contains(&n)
            {
                out[count] = n;
                count += 1;
            }
        }
        count
    }

    /// The session with the RAM file service and the console's driver's,
    /// which a child gets clones of.
    /// Authenticate the file session before any operation can commit.
    pub fn bind(&self, identity: &Handle<Channel>) -> Result<(), FsError> {
        self.files.bind(identity).map_err(FsError::from)
    }

    pub fn sessions(&self) -> (&Handle<Channel>, Option<&Handle<Channel>>) {
        self.files.sessions()
    }

    /// The session with the pipe service, when the process has one.
    pub fn pipes(&self) -> Option<&Handle<Channel>> {
        self.pipes.as_ref()
    }

    /// The session with the terminal service, when the process has one.
    pub fn terminal(&self) -> Option<&Handle<Channel>> {
        self.terminal.as_ref()
    }

    fn from_files(files: Files) -> Result<Self, FsError> {
        let mut descriptors = Table::with_early_release(|target| matches!(target, Target::Tty(_)));
        for target in [Target::Input, Target::Output, Target::Error] {
            descriptors.insert(target, DescriptorFlags::default())?;
        }
        Ok(Self {
            files,
            pipes: None,
            terminal: None,
            paths: PathState::new(),
            descriptors,
        })
    }

    /// The transports, for a request outside the owner's lock.
    pub fn transport(&self) -> Transport {
        Transport(
            self.files.view(),
            self.pipes.as_ref().map(Handle::raw),
            self.terminal.as_ref().map(Handle::raw),
        )
    }

    pub fn cwd(&self) -> &[u8] {
        self.paths.cwd()
    }

    /// `input` against the current directory.
    pub fn resolve(&self, input: &[u8]) -> Result<Resolved, FsError> {
        let mut bytes = [0; MAX_PATH + 1];
        let len = self.paths.resolve(input, &mut bytes)?;
        Ok(Resolved {
            bytes,
            len,
            trailing_slash: input.last() == Some(&b'/'),
        })
    }

    /// The current directory becomes `path`, which the caller found to be
    /// a directory.
    pub fn set_cwd(&mut self, path: &[u8]) -> Result<(), FsError> {
        self.paths.set_cwd(path).map_err(FsError::from)
    }

    /// What `fd` names.
    pub fn target(&self, fd: u32) -> Result<Target, FsError> {
        self.descriptors.get(fd).map_err(FsError::from)
    }

    /// What `fd` names, held for a request outside the owner's lock.
    /// RAM and pipe close waits for `unhold`; terminal last-fd close
    /// releases its real hold immediately, while armed I/O keeps a pin.
    pub fn hold(&mut self, fd: u32) -> Result<Target, FsError> {
        self.descriptors.hold(fd).map_err(FsError::from)
    }

    /// The request on `target` is over: what to release, when its last
    /// descriptor went meanwhile.
    pub fn unhold(&mut self, target: Target) -> Option<Target> {
        self.descriptors.unhold(target)
    }

    /// The holds of requests that never end go: the next target whose
    /// last descriptor went meanwhile, to release (posix_fd abandon_hold).
    pub fn abandon_hold(&mut self) -> Option<Target> {
        self.descriptors.abandon_hold()
    }

    /// A descriptor of the service's description `target` (a file or a
    /// random device) with `flags`, the lowest free one: the caller
    /// closes it on an error.
    pub fn insert(&mut self, target: Target, flags: DescriptorFlags) -> Result<u32, FsError> {
        self.descriptors
            .insert(target, flags)
            .map_err(FsError::from)
    }

    /// The lowest free descriptor for terminal `terminal` of the terminal
    /// service (an open of its name, `terminal_named`).
    pub fn insert_terminal(
        &mut self,
        terminal: u32,
        flags: DescriptorFlags,
    ) -> Result<u32, FsError> {
        self.descriptors
            .insert(Target::Tty(terminal), flags)
            .map_err(FsError::from)
    }

    /// The two descriptors of a new pipe, its ends `read` and `write`,
    /// the lowest free numbers, both with `flags`: both or neither; the
    /// caller closes the ends in the service on an error.
    pub fn insert_pipe(
        &mut self,
        read: u32,
        write: u32,
        flags: DescriptorFlags,
    ) -> Result<(u32, u32), FsError> {
        let first = self.descriptors.insert(Target::Pipe(read), flags)?;
        match self.descriptors.insert(Target::Pipe(write), flags) {
            Ok(second) => Ok((first, second)),
            Err(error) => {
                let _ = self.descriptors.close(first);
                Err(error.into())
            }
        }
    }

    /// Close: the descriptor goes; what to release outside the lock.
    pub fn take_close(&mut self, fd: u32) -> Result<Option<Target>, FsError> {
        self.descriptors.close(fd).map_err(FsError::from)
    }

    /// dup2 and dup3: the target and what it named before, to release.
    pub fn take_dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: Option<DescriptorFlags>,
    ) -> Result<(u32, Option<Target>), FsError> {
        match flags {
            None => self.descriptors.dup2(source, target),
            Some(flags) => self.descriptors.dup3(source, target, flags),
        }
        .map_err(FsError::from)
    }

    /// The descriptors that are open, what they name and their flags.
    pub fn descriptors(&self) -> impl Iterator<Item = (u32, Target, DescriptorFlags)> + '_ {
        self.descriptors.open()
    }

    pub fn chdir(&mut self, path: &[u8]) -> Result<(), FsError> {
        if self.stat(path)?.kind != FileKind::Directory {
            return Err(FsError::NotDirectory);
        }
        self.paths.set_cwd(path)?;
        Ok(())
    }

    /// Open by a single owner: the request, then the descriptor.
    pub fn open(&mut self, path: &[u8], flags: u32) -> Result<u32, FsError> {
        self.open_policy(path, flags, 0, 0, DescriptorFlags::default())
    }

    pub fn close(&mut self, fd: u32) -> Result<(), FsError> {
        let release = self.take_close(fd)?;
        self.transport().release(release)
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
        let (fd, release) = self.take_dup3(source, target, None)?;
        self.transport().release(release)?;
        Ok(fd)
    }

    pub fn dup3(
        &mut self,
        source: u32,
        target: u32,
        flags: DescriptorFlags,
    ) -> Result<u32, FsError> {
        let (fd, release) = self.take_dup3(source, target, Some(flags))?;
        self.transport().release(release)?;
        Ok(fd)
    }

    pub fn descriptor_flags(&self, fd: u32) -> Result<DescriptorFlags, FsError> {
        self.descriptors.flags(fd).map_err(FsError::from)
    }

    pub fn set_descriptor_flags(&mut self, fd: u32, flags: DescriptorFlags) -> Result<(), FsError> {
        self.descriptors.set_flags(fd, flags).map_err(FsError::from)
    }

    pub fn prepare_read(&self, fd: u32, count: usize) -> Result<PreparedRead, FsError> {
        self.transport().prepare_read(self.target(fd)?, count)
    }

    pub fn read(&self, fd: u32, out: &mut [u8]) -> Result<usize, FsError> {
        self.transport().read(self.target(fd)?, out)
    }

    /// Whether `fd` is the console's input (standard input as the process
    /// started, wherever `dup2` moved it).
    pub fn console_input(&self, fd: u32) -> Result<bool, FsError> {
        Ok(matches!(self.target(fd)?, Target::Input))
    }

    /// The console route of `fd` when it is standard output or error, for
    /// a write the caller makes after it let go of the file state (the
    /// owner stays alive meanwhile); None for a file of the service.
    pub fn console_route(&self, fd: u32) -> Result<Option<rt::fs::Input>, FsError> {
        Ok(match self.target(fd)? {
            Target::Output | Target::Error => Some(self.files.input()),
            _ => None,
        })
    }

    pub fn write(&self, fd: u32, bytes: &[u8]) -> Result<usize, FsError> {
        self.transport().write(self.target(fd)?, bytes)
    }

    pub fn seek_set(&self, fd: u32, offset: u32) -> Result<u32, FsError> {
        self.lseek(fd, i64::from(offset), SeekFrom::Start)
            .map(|offset| offset as u32)
    }

    pub fn lseek(&self, fd: u32, offset: i64, origin: SeekFrom) -> Result<i64, FsError> {
        self.transport().lseek(self.target(fd)?, offset, origin)
    }

    pub fn fstat(&self, fd: u32) -> Result<Metadata, FsError> {
        self.transport().fstat(self.target(fd)?)
    }

    pub fn stat(&self, path: &[u8]) -> Result<Metadata, FsError> {
        self.transport().stat(&self.resolve(path)?)
    }

    pub fn stat_information(&self, path: &[u8]) -> Result<NodeInfo, FsError> {
        self.transport().stat_information(&self.resolve(path)?)
    }

    pub fn descriptor_information(&self, fd: u32) -> Result<NodeInfo, FsError> {
        self.transport().descriptor_information(self.target(fd)?)
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
        self.transport().readdir(self.target(dir.fd)?, out)
    }
}
