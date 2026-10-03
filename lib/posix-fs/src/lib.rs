// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! File and directory operations for the evolving Rust POSIX layer.
//! The current RAM service uses UTF-8 paths and bounded regular files.

#![no_std]

use core::mem::ManuallyDrop;
pub use posix_fd::Flags as DescriptorFlags;
use posix_fd::{Error as DescriptorError, Table};
use posix_path::{MAX_PATH, PathError, PathState};
pub use proto_fs::{DIRECTORY_ONLY, MAX_READ, NodeInfo, SeekFrom};
use proto_wire::Status;
use rt::Handle;
use rt::fs::{Files, View};
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
    /// A pipe that would wait with O_NONBLOCK, or a wait past the limits.
    Again,
    /// A write to a pipe with no reader.
    Broken,
    /// Every pipe of the service in use.
    TooManyInSystem,
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
/// process's session, or an end of a pipe of the pipe service by its
/// number there (5e).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Input,
    Output,
    Error,
    Ram(u32),
    Pipe(u32),
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
    paths: PathState,
    descriptors: Table<Target, OPEN_MAX>,
}

/// The transports of a process's files, borrowed from its PosixFs, which
/// stays alive while a transport is used: what a request needs outside
/// the owner's lock.
#[derive(Clone, Copy)]
pub struct Transport(View, Option<rt::abi::Handle>);

/// A path the owner resolved against its current directory, for a
/// request outside its lock.
pub struct Resolved {
    bytes: [u8; MAX_PATH + 1],
    len: usize,
    /// The path the caller gave ends with a slash: a directory is meant.
    pub trailing_slash: bool,
}

impl Resolved {
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
    access_ns: 0,
    modify_ns: 0,
    change_ns: 0,
};

impl Transport {
    fn files(&self) -> ManuallyDrop<Files> {
        self.0.files()
    }

    /// The session with the pipe service: BadFileDescriptor without one.
    pub fn pipes(&self) -> Result<ManuallyDrop<Handle<Channel>>, FsError> {
        self.1
            .map(Handle::borrowed)
            .ok_or(FsError::BadFileDescriptor)
    }

    /// Close of the service's description `fd` that the table handed back.
    /// The console's targets take no frame of the requests: the probes of
    /// requests before the heap run it on a small stack.
    pub fn release(&self, target: Option<Target>) -> Result<(), FsError> {
        match target {
            Some(Target::Ram(fd)) => self.close_file(fd),
            Some(Target::Pipe(end)) => self.close_pipe(end),
            _ => Ok(()),
        }
    }

    #[inline(never)]
    fn close_file(&self, fd: u32) -> Result<(), FsError> {
        self.files().close(fd).map_err(FsError::from)
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

    pub fn open(&self, path: &str, flags: u32) -> Result<u32, FsError> {
        self.files().open(path, flags).map_err(FsError::from)
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
            Target::Ram(fd) => fd,
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
            Target::Ram(fd) => fd,
            _ => return Err(FsError::BadFileDescriptor),
        };
        self.files().write(fd, bytes).map_err(FsError::from)
    }

    pub fn lseek(&self, target: Target, offset: i64, origin: SeekFrom) -> Result<i64, FsError> {
        match target {
            Target::Ram(fd) => self
                .files()
                .seek_from(fd, offset, origin)
                .map_err(FsError::from),
            _ => Err(FsError::NotSeekable),
        }
    }

    pub fn descriptor_information(&self, target: Target) -> Result<NodeInfo, FsError> {
        match target {
            Target::Ram(fd) => self
                .files()
                .descriptor_information(fd)
                .map_err(FsError::from),
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

    pub fn stat(&self, path: &Resolved) -> Result<Metadata, FsError> {
        let meta = self.files().lookup(path.as_str()?).map_err(FsError::from)?;
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
        let info = self
            .files()
            .node_information(path.as_str()?)
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

/// A descriptor a process starts with, from its parent's table (spec 2,
/// 3.2): its number, what it names, and the service's number of the
/// description for a file of the service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inherited {
    pub fd: u32,
    pub target: Target,
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
        let mut fs = match inherited {
            None => Self::from_files(Files::from_sessions(files, uart))?,
            Some(list) => {
                let mut fs = Self {
                    files: Files::from_sessions(files, uart),
                    pipes: None,
                    paths: PathState::new(),
                    descriptors: Table::default(),
                };
                for d in list {
                    fs.descriptors
                        .place(d.fd, d.target, DescriptorFlags::default())?;
                }
                if secure {
                    for (fd, target) in
                        [(0, Target::Input), (1, Target::Output), (2, Target::Error)]
                    {
                        if fs.descriptors.get(fd).is_err() {
                            fs.descriptors
                                .place(fd, target, DescriptorFlags::default())?;
                        }
                    }
                }
                fs
            }
        };
        if !cwd.is_empty() {
            fs.paths.set_cwd(cwd)?;
        }
        Ok(fs)
    }

    /// The files of a forked child (spec 2, 3.2), whose table is a copy of
    /// its parent's: its own sessions `files` and `uart`, clones of its
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
    ) {
        let parent = core::mem::replace(&mut self.files, Files::from_sessions(files, uart));
        core::mem::forget(parent);
        core::mem::forget(core::mem::replace(&mut self.pipes, pipes));
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
    pub fn kept_by_fork(&self, out: &mut [u32; OPEN_MAX]) -> usize {
        let mut count = 0;
        for (_, target, flags) in self.descriptors.open() {
            if let Target::Ram(n) = target
                && !flags.close_on_fork
                && !out[..count].contains(&n)
            {
                out[count] = n;
                count += 1;
            }
        }
        count
    }

    /// The ends of pipes a forked child's session shares with its
    /// parent's: those of the descriptors without FD_CLOFORK, each once,
    /// into `out`; how many.
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
    pub fn sessions(&self) -> (&Handle<Channel>, Option<&Handle<Channel>>) {
        self.files.sessions()
    }

    /// The session with the pipe service, when the process has one.
    pub fn pipes(&self) -> Option<&Handle<Channel>> {
        self.pipes.as_ref()
    }

    fn from_files(files: Files) -> Result<Self, FsError> {
        let mut descriptors = Table::default();
        for target in [Target::Input, Target::Output, Target::Error] {
            descriptors.insert(target, DescriptorFlags::default())?;
        }
        Ok(Self {
            files,
            pipes: None,
            paths: PathState::new(),
            descriptors,
        })
    }

    /// The transports, for a request outside the owner's lock.
    pub fn transport(&self) -> Transport {
        Transport(self.files.view(), self.pipes.as_ref().map(Handle::raw))
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

    /// What `fd` names, held for a request outside the owner's lock: a
    /// close meanwhile leaves the service's description until `unhold`.
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

    /// A descriptor of the service's description `fd` with `flags`, the
    /// lowest free one: the caller closes `fd` on an error.
    pub fn insert(&mut self, fd: u32, flags: DescriptorFlags) -> Result<u32, FsError> {
        self.descriptors
            .insert(Target::Ram(fd), flags)
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
        if path.last() == Some(&b'/') && self.stat(path)?.kind == FileKind::Regular {
            return Err(FsError::NotDirectory);
        }
        let resolved = self.resolve(path)?;
        self.descriptors.vacant(0)?;
        let transport = self.transport();
        let fd = transport.open(resolved.as_str()?, flags)?;
        match self.insert(fd, DescriptorFlags::default()) {
            Ok(fd) => Ok(fd),
            Err(error) => {
                let _ = transport.release(Some(Target::Ram(fd)));
                Err(error)
            }
        }
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
