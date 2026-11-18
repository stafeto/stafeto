// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The requests of `proto_data` on a volume: the table of open files and directories of the
//! sessions, the canonical form of a path, the refusal to remove or rename what is open, and the
//! mapping of the volume's errors to the protocol's codes. The service runs `Server::handle` on its
//! worker thread; the tests run it against the device in memory.

use crate::fs::{Dir, Entry, Error, File, Fs, Kind, Open, Whence};
use crate::{DIRS, Device, FILES};
use proto_data as p;
use proto_data::{MAX_PATH, Method};
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

/// The descriptions open at once: the slots of the volume.
const OPEN: usize = FILES + DIRS;

#[derive(Clone, Copy)]
struct Description {
    used: bool,
    owner: u64,
    generation: u16,
    kind: Kind,
    slot: u8,
    path: [u8; MAX_PATH],
    len: usize,
}

impl Description {
    const EMPTY: Description = Description {
        used: false,
        owner: 0,
        generation: 0,
        kind: Kind::File,
        slot: 0,
        path: [0; MAX_PATH],
        len: 0,
    };

    fn path(&self) -> &[u8] {
        &self.path[..self.len]
    }
}

pub struct Server {
    open: [Description; OPEN],
    generation: u16,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// `path` in its canonical form: absolute, no empty component, no `.`, no `..`; the root is `/`.
pub fn canonical(path: &[u8], out: &mut [u8; MAX_PATH]) -> Result<usize, Status> {
    if path.len() > MAX_PATH {
        return Err(p::code(p::NAME_TOO_LONG));
    }
    if path.first() != Some(&b'/') {
        return Err(p::code(p::INVALID));
    }
    let mut n = 0;
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => return Err(p::code(p::INVALID)),
            _ => {
                if part.len() > crate::NAME_MAX {
                    return Err(p::code(p::NAME_TOO_LONG));
                }
                out[n] = b'/';
                out[n + 1..n + 1 + part.len()].copy_from_slice(part);
                n += 1 + part.len();
            }
        }
    }
    if n == 0 {
        out[0] = b'/';
        n = 1;
    }
    Ok(n)
}

/// The protocol's status for an error of the volume.
pub fn status_of(error: Error) -> Status {
    p::code(match error {
        Error::Io => p::IO,
        Error::Corrupt => p::CORRUPT,
        Error::NoEntry => p::NO_ENTRY,
        Error::Exists => p::EXISTS,
        Error::NotDirectory => p::NOT_DIRECTORY,
        Error::IsDirectory => p::IS_DIRECTORY,
        Error::NotEmpty => p::NOT_EMPTY,
        Error::BadDescriptor => p::BAD_HANDLE,
        Error::TooBig => p::TOO_BIG,
        Error::Invalid => p::INVALID,
        Error::NoSpace => p::NO_SPACE,
        Error::NoMemory => p::TOO_MANY_OPEN,
        Error::NameTooLong => p::NAME_TOO_LONG,
        Error::Other(_) => p::IO,
    })
}

fn kind_word(kind: Kind) -> u32 {
    match kind {
        Kind::File => p::KIND_FILE,
        Kind::Directory => p::KIND_DIRECTORY,
    }
}

type Res<T> = Result<T, Status>;

fn volume<T>(result: Result<T, Error>) -> Res<T> {
    result.map_err(status_of)
}

/// Whether `inner` is `outer` or lies under it.
fn within(inner: &[u8], outer: &[u8]) -> bool {
    inner.starts_with(outer)
        && (outer == b"/" || inner.len() == outer.len() || inner[outer.len()] == b'/')
}

impl Server {
    pub const fn new() -> Self {
        Self {
            open: [Description::EMPTY; OPEN],
            generation: 0,
        }
    }

    pub fn open_count(&self) -> usize {
        self.open.iter().filter(|d| d.used).count()
    }

    fn handle_of(&self, index: usize) -> u32 {
        (index as u32 + 1) | (u32::from(self.open[index].generation) << 8)
    }

    fn find(&self, owner: u64, handle: u32) -> Res<usize> {
        let index = (handle & 0xFF) as usize;
        let bad = || p::code(p::BAD_HANDLE);
        let d = index
            .checked_sub(1)
            .and_then(|i| self.open.get(i))
            .ok_or_else(bad)?;
        if !d.used || d.owner != owner || u32::from(d.generation) != handle >> 8 {
            return Err(bad());
        }
        Ok(index - 1)
    }

    /// Closes everything a session held (the session went).
    pub fn gone<D: Device>(&mut self, fs: &mut Fs<'_, D>, owner: u64) {
        for i in 0..OPEN {
            if self.open[i].used && self.open[i].owner == owner {
                let _ = self.release(fs, i);
            }
        }
    }

    /// Closes every file and directory still open, for the stop of the service: a file's data
    /// reaches the volume when it is closed. The number of the descriptions that did not close.
    pub fn close_all<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> usize {
        let mut failed = 0;
        for i in 0..OPEN {
            if self.open[i].used && self.release(fs, i).is_err() {
                failed += 1;
            }
        }
        failed
    }

    fn release<D: Device>(&mut self, fs: &mut Fs<'_, D>, index: usize) -> Result<(), Error> {
        let d = self.open[index];
        self.open[index].used = false;
        match d.kind {
            Kind::File => fs.close(File(d.slot)),
            Kind::Directory => fs.closedir(Dir(d.slot)),
        }
    }

    /// Whether a description holds `path` or something under it.
    fn in_use(&self, path: &[u8]) -> bool {
        if cfg!(feature = "break-datafs-busy") {
            return false;
        }
        self.open.iter().any(|d| d.used && within(d.path(), path))
    }

    /// The reply to `request` (its header and body) from the session `owner`: the status first. The
    /// reply is whole in the returned writer.
    pub fn handle<D: Device>(&mut self, fs: &mut Fs<'_, D>, owner: u64, request: &[u8]) -> Writer {
        let mut w = Writer::new();
        let done = w.u32(0).and_then(|()| self.run(fs, owner, request, &mut w));
        match done {
            Ok(()) => w,
            Err(status) => {
                let mut w = Writer::new();
                let _ = w.u32(status.code());
                w
            }
        }
    }

    fn run<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        owner: u64,
        request: &[u8],
        w: &mut Writer,
    ) -> Res<()> {
        let mut r = Reader::new(request);
        let header = Header::read(&mut r)?;
        if header.version != p::VERSION {
            return Err(Status::BadVersion);
        }
        let method = Method::from_number(header.method).ok_or(Status::UnknownMethod)?;
        if !fs.is_mounted() {
            return Err(p::code(p::NOT_READY));
        }
        let mut path = [0u8; MAX_PATH];
        match method {
            Method::Open => {
                let flags = r.u32()?;
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                self.do_open(fs, owner, flags, &path[..n], w)
            }
            Method::Close => {
                let index = self.find(owner, r.u32()?)?;
                r.finish()?;
                volume(self.release(fs, index))
            }
            Method::Read => {
                let index = self.find(owner, r.u32()?)?;
                let count = (r.u32()? as usize).min(p::MAX_READ);
                r.finish()?;
                let d = self.open[index];
                if d.kind != Kind::File {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                let mut buffer = [0u8; p::MAX_READ];
                let n = volume(fs.read(File(d.slot), &mut buffer[..count]))?;
                w.u32(n as u32)?;
                w.bytes(&buffer[..n])
            }
            Method::Write => {
                let index = self.find(owner, r.u32()?)?;
                let data = r.bytes(r.left())?;
                let d = self.open[index];
                if d.kind != Kind::File {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                let n = volume(fs.write(File(d.slot), data))?;
                w.u32(n as u32)
            }
            Method::Seek => {
                let index = self.find(owner, r.u32()?)?;
                let offset = r.u64()? as i64;
                let whence = match r.u32()? {
                    p::SEEK_SET => Whence::Set,
                    p::SEEK_CUR => Whence::Current,
                    p::SEEK_END => Whence::End,
                    _ => return Err(p::code(p::INVALID)),
                };
                r.finish()?;
                let d = self.open[index];
                if d.kind != Kind::File {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                let offset = i32::try_from(offset).map_err(|_| p::code(p::TOO_BIG))?;
                let at = volume(fs.seek(File(d.slot), offset, whence))?;
                w.u64(at)
            }
            Method::Fsync => {
                let index = self.find(owner, r.u32()?)?;
                r.finish()?;
                let d = self.open[index];
                match d.kind {
                    Kind::File => volume(fs.sync(File(d.slot))),
                    // Every change of a directory is durable when it returns.
                    Kind::Directory => Ok(()),
                }
            }
            Method::Truncate => {
                let index = self.find(owner, r.u32()?)?;
                let size = r.u64()?;
                r.finish()?;
                let d = self.open[index];
                if d.kind != Kind::File {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                let size = u32::try_from(size)
                    .ok()
                    .filter(|&s| s <= i32::MAX as u32)
                    .ok_or_else(|| p::code(p::TOO_BIG))?;
                volume(fs.truncate(File(d.slot), size))
            }
            Method::Stat => {
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                let info = volume(fs.stat(&path[..n]))?;
                w.u32(kind_word(info.kind))?;
                w.u32(info.size)
            }
            Method::Fstat => {
                let index = self.find(owner, r.u32()?)?;
                r.finish()?;
                let d = self.open[index];
                match d.kind {
                    Kind::File => {
                        let size = volume(fs.size(File(d.slot)))?;
                        w.u32(p::KIND_FILE)?;
                        w.u32(size as u32)
                    }
                    Kind::Directory => {
                        w.u32(p::KIND_DIRECTORY)?;
                        w.u32(0)
                    }
                }
            }
            Method::Mkdir => {
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                volume(fs.mkdir(&path[..n]))
            }
            Method::Unlink | Method::Rmdir => {
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                let path = &path[..n];
                if path == b"/" {
                    return Err(p::code(p::BUSY));
                }
                let info = volume(fs.stat(path))?;
                match (method, info.kind) {
                    (Method::Unlink, Kind::Directory) => return Err(p::code(p::IS_DIRECTORY)),
                    (Method::Rmdir, Kind::File) => return Err(p::code(p::NOT_DIRECTORY)),
                    _ => {}
                }
                if self.in_use(path) {
                    return Err(p::code(p::BUSY));
                }
                volume(fs.remove(path))
            }
            Method::Rename => {
                let (from, to) = p::read_rename(r)?;
                let mut other = [0u8; MAX_PATH];
                let n = canonical(from, &mut path)?;
                let m = canonical(to, &mut other)?;
                let (from, to) = (&path[..n], &other[..m]);
                if from == b"/" || to == b"/" || within(to, from) && to != from {
                    return Err(p::code(p::INVALID));
                }
                if self.in_use(from) || self.in_use(to) {
                    return Err(p::code(p::BUSY));
                }
                // The kinds must agree, as rename(2) has it.
                let source = volume(fs.stat(from))?;
                match fs.stat(to) {
                    Ok(target) if target.kind != source.kind => {
                        return Err(p::code(match target.kind {
                            Kind::Directory => p::IS_DIRECTORY,
                            Kind::File => p::NOT_DIRECTORY,
                        }));
                    }
                    Ok(_) | Err(Error::NoEntry) => {}
                    Err(error) => return Err(status_of(error)),
                }
                volume(fs.rename(from, to))
            }
            Method::Readdir => {
                let index = self.find(owner, r.u32()?)?;
                r.finish()?;
                let d = self.open[index];
                if d.kind != Kind::Directory {
                    return Err(p::code(p::NOT_DIRECTORY));
                }
                match volume(fs.readdir(Dir(d.slot)))? {
                    None => {
                        w.u32(0)?;
                        w.u32(0)?;
                        w.u32(0)
                    }
                    Some(entry) => write_entry(w, &entry),
                }
            }
            Method::Rewind => {
                let index = self.find(owner, r.u32()?)?;
                r.finish()?;
                let d = self.open[index];
                if d.kind != Kind::Directory {
                    return Err(p::code(p::NOT_DIRECTORY));
                }
                volume(fs.rewinddir(Dir(d.slot)))
            }
            Method::Statfs => {
                r.finish()?;
                let used = volume(fs.used_blocks())?;
                w.u64(fs.blocks())?;
                w.u64(used)?;
                w.u32(p::BLOCK)
            }
        }
    }

    fn do_open<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        owner: u64,
        flags: u32,
        path: &[u8],
        w: &mut Writer,
    ) -> Res<()> {
        if flags & !p::FLAGS_ALL != 0 {
            return Err(p::code(p::INVALID));
        }
        let index = self
            .open
            .iter()
            .position(|d| !d.used)
            .ok_or_else(|| p::code(p::TOO_MANY_OPEN))?;
        let kind = if flags & p::DIRECTORY != 0 {
            Kind::Directory
        } else {
            Kind::File
        };
        let slot = match kind {
            Kind::Directory => {
                if flags & (p::WRITE | p::CREATE | p::TRUNCATE | p::APPEND) != 0 {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                volume(fs.opendir(path))?.0
            }
            Kind::File => {
                let mut open = match flags & (p::READ | p::WRITE) {
                    p::READ => Open::READ,
                    p::WRITE => Open::WRITE,
                    p::READ_WRITE_BOTH => Open::READ_WRITE,
                    _ => return Err(p::code(p::INVALID)),
                };
                for (flag, lfs) in [
                    (p::CREATE, Open::CREATE),
                    (p::EXCLUSIVE, Open::EXCLUSIVE),
                    (p::TRUNCATE, Open::TRUNCATE),
                    (p::APPEND, Open::APPEND),
                ] {
                    if flags & flag != 0 {
                        open = open.with(lfs);
                    }
                }
                // A directory opens only as one.
                if let Ok(info) = fs.stat(path)
                    && info.kind == Kind::Directory
                {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                volume(fs.open(path, open))?.0
            }
        };
        self.generation = self.generation.wrapping_add(1);
        let d = &mut self.open[index];
        *d = Description {
            used: true,
            owner,
            generation: self.generation,
            kind,
            slot,
            path: [0; MAX_PATH],
            len: path.len(),
        };
        d.path[..path.len()].copy_from_slice(path);
        w.u32(self.handle_of(index))?;
        w.u32(kind_word(kind))
    }
}

fn write_entry(w: &mut Writer, entry: &Entry) -> Res<()> {
    w.u32(1)?;
    w.u32(kind_word(entry.kind))?;
    w.u32(entry.size)?;
    w.bytes(entry.name())
}

/// The longest request the service takes, for its job table.
pub const REQUEST_MAX: usize = abi::MESSAGE_MAX;

const _: () = assert!(HEADER_LEN == 8);
