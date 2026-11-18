// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The requests of `proto_data` on a volume: the table of the open descriptions, the sessions that
//! hold them, the passes of EXPORT, the canonical form of a path, and the mapping of the volume's
//! errors to the protocol's codes. The service runs `Server::handle` on its worker thread; the tests
//! run it against the device in memory.
//!
//! A description (an open file or directory) has its own position and flags and a count of the
//! references to it: each session that holds it counts one, each unspent pass one. The descriptions of
//! one path share one open file of the volume (a `Node`), because littlefs keeps a file's size and
//! blocks in each open of it and a second open does not see the writes of the first. A read or a
//! write seeks the shared file to the description's position first (skipped while the file is
//! already there), so the work of one description in a row costs what it did before.
//!
//! littlefs also detaches an open file from its name when the name is removed or renamed, and may
//! reuse its blocks (`tests_open`). A file that is open and unlinked, or replaced by a rename, is
//! therefore moved under `/.orphans` first, with the file closed and reopened at the new name around
//! the move; the last description to close removes it, and `clean_orphans` removes what a stop or a
//! cut left, at the next mount. A rename of an open file closes and reopens it the same way.

use crate::fs::{Dir, Entry, Error, File, Fs, Kind, Open, Whence};
use crate::{DIRS, Device, FILES};
use proto_data as p;
use proto_data::{HELD_MAX, MAX_PATH, Method};
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

/// The sessions of the table: the loop of the service holds as many.
pub const SESSIONS: usize = 32;
/// The descriptions open at once (a bit of a session's mask each).
pub const DESCRIPTIONS: usize = 16;
/// The passes alive at once.
pub const PASSES: usize = 8;
/// The hidden directory of the files that are unlinked and still open.
pub const ORPHANS: &[u8] = b"/.orphans";

#[derive(Clone, Copy)]
struct PathBuf {
    bytes: [u8; MAX_PATH],
    len: usize,
}

impl PathBuf {
    const EMPTY: PathBuf = PathBuf {
        bytes: [0; MAX_PATH],
        len: 0,
    };

    fn set(&mut self, path: &[u8]) {
        self.bytes[..path.len()].copy_from_slice(path);
        self.len = path.len();
    }

    fn get(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy)]
struct Description {
    used: bool,
    generation: u8,
    kind: Kind,
    /// A file: the index of its `Node`. A directory: its slot in the volume.
    object: u8,
    read: bool,
    write: bool,
    append: bool,
    pos: u32,
    /// The sessions that hold it and the passes that name it.
    refs: u8,
}

impl Description {
    const EMPTY: Description = Description {
        used: false,
        generation: 0,
        kind: Kind::File,
        object: 0,
        read: false,
        write: false,
        append: false,
        pos: 0,
        refs: 0,
    };
}

/// The open file of the volume that the descriptions of one path share.
#[derive(Clone, Copy)]
struct Node {
    used: bool,
    slot: u8,
    /// The descriptions that use it.
    refs: u8,
    /// Under `ORPHANS`: removed when the last description goes.
    orphan: bool,
    /// The volume failed while it was closed and reopened: every operation answers IO.
    broken: bool,
    /// Where the file of the volume is positioned now, so that the next operation at that place
    /// does not seek (a seek of a file that was written makes littlefs flush it).
    at: Option<u32>,
    path: PathBuf,
}

impl Node {
    const EMPTY: Node = Node {
        used: false,
        slot: 0,
        refs: 0,
        orphan: false,
        broken: false,
        at: None,
        path: PathBuf::EMPTY,
    };
}

#[derive(Clone, Copy)]
struct Session {
    used: bool,
    label: u64,
    /// The descriptions held, a bit each.
    held: u16,
    /// For a session made by CLONE: the session that made it, and the birth number while the child
    /// has sent nothing (0 after its first request).
    parent: u64,
    birth: u16,
}

impl Session {
    const EMPTY: Session = Session {
        used: false,
        label: 0,
        held: 0,
        parent: 0,
        birth: 0,
    };
}

#[derive(Clone, Copy)]
struct Pass {
    used: bool,
    label: u64,
    owner: u64,
    description: u8,
}

pub struct Server {
    descriptions: [Description; DESCRIPTIONS],
    nodes: [Node; FILES],
    dirs: [PathBuf; DIRS],
    sessions: [Session; SESSIONS],
    passes: [Pass; PASSES],
    generation: u8,
    epoch: u16,
    birth_seq: u16,
    orphan_seq: u32,
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

fn bad_handle() -> Status {
    p::code(p::BAD_HANDLE)
}

/// The path of an orphan: `ORPHANS`, a slash and the number in decimal.
fn orphan_path(seq: u32) -> ([u8; 32], usize) {
    let mut out = [0u8; 32];
    out[..ORPHANS.len()].copy_from_slice(ORPHANS);
    let mut n = ORPHANS.len();
    out[n] = b'/';
    n += 1;
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut v = seq;
    loop {
        digits[count] = b'0' + (v % 10) as u8;
        count += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        out[n] = digits[count];
        n += 1;
    }
    (out, n)
}

/// A path that names the hidden directory or something under it.
fn hidden(path: &[u8]) -> bool {
    within(path, ORPHANS)
}

fn visible(path: &[u8]) -> Res<()> {
    if hidden(path) {
        Err(p::code(p::NO_ENTRY))
    } else {
        Ok(())
    }
}

/// Removes what a stop or a cut of the power left under `ORPHANS`: the files that were unlinked
/// while open. Run once after the mount, before the first request. The files removed.
pub fn clean_orphans<D: Device>(fs: &mut Fs<'_, D>) -> Result<usize, Error> {
    let mut removed = 0;
    loop {
        let dir = match fs.opendir(ORPHANS) {
            Ok(dir) => dir,
            Err(Error::NoEntry) => return Ok(removed),
            Err(e) => return Err(e),
        };
        let mut name = [0u8; MAX_PATH];
        let mut found = None;
        let mut result = Ok(());
        loop {
            match fs.readdir(dir) {
                Ok(Some(e)) if e.name() == b"." || e.name() == b".." => {}
                Ok(Some(e)) => {
                    let n = ORPHANS.len();
                    name[..n].copy_from_slice(ORPHANS);
                    name[n] = b'/';
                    let len = e.name().len();
                    name[n + 1..n + 1 + len].copy_from_slice(e.name());
                    found = Some(n + 1 + len);
                    break;
                }
                Ok(None) => break,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        let closed = fs.closedir(dir);
        result?;
        closed?;
        let Some(len) = found else {
            return Ok(removed);
        };
        fs.remove(&name[..len])?;
        removed += 1;
    }
}

impl Server {
    /// A server whose handles carry the epoch 1.
    pub const fn new() -> Self {
        Self::with_epoch(1)
    }

    /// A server of the instance `epoch` (0 is made 1): the handles it gives carry it, and a handle
    /// of another epoch, which a client kept over a restart, answers STALE.
    pub const fn with_epoch(epoch: u16) -> Self {
        Self {
            descriptions: [Description::EMPTY; DESCRIPTIONS],
            nodes: [Node::EMPTY; FILES],
            dirs: [PathBuf::EMPTY; DIRS],
            sessions: [Session::EMPTY; SESSIONS],
            passes: [Pass {
                used: false,
                label: 0,
                owner: 0,
                description: 0,
            }; PASSES],
            generation: 0,
            epoch: if epoch == 0 { 1 } else { epoch },
            birth_seq: 0,
            orphan_seq: 0,
        }
    }

    pub fn open_count(&self) -> usize {
        self.descriptions.iter().filter(|d| d.used).count()
    }

    /// The sessions the server knows.
    pub fn session_count(&self) -> usize {
        self.sessions.iter().filter(|s| s.used).count()
    }

    /// The passes made and not spent.
    pub fn pass_count(&self) -> usize {
        self.passes.iter().filter(|p| p.used).count()
    }

    /// The files of the volume open (shared by the descriptions of a path).
    pub fn node_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.used).count()
    }

    fn handle_of(&self, index: usize) -> u32 {
        (index as u32 + 1)
            | (u32::from(self.descriptions[index].generation) << 8)
            | (u32::from(self.epoch) << 16)
    }

    /// The description a handle names for the session `si`: STALE for a handle of another epoch,
    /// BAD_HANDLE for one that names nothing the session holds.
    fn find(&self, si: usize, handle: u32) -> Res<usize> {
        let epoch = (handle >> 16) as u16;
        if epoch == 0 {
            return Err(bad_handle());
        }
        if epoch != self.epoch {
            return Err(p::code(p::STALE));
        }
        let index = ((handle & 0xFF) as usize)
            .checked_sub(1)
            .filter(|&i| i < DESCRIPTIONS)
            .ok_or_else(bad_handle)?;
        let d = &self.descriptions[index];
        if !d.used
            || u32::from(d.generation) != (handle >> 8) & 0xFF
            || self.sessions[si].held & (1 << index) == 0
        {
            return Err(bad_handle());
        }
        Ok(index)
    }

    /// The session of `label`, made when it has none. A request of a clone's label ends its birth.
    fn session(&mut self, label: u64) -> Res<usize> {
        if let Some(i) = self
            .sessions
            .iter()
            .position(|s| s.used && s.label == label)
        {
            self.sessions[i].birth = 0;
            return Ok(i);
        }
        let i = self.free_session()?;
        self.sessions[i] = Session {
            used: true,
            label,
            ..Session::EMPTY
        };
        Ok(i)
    }

    fn free_session(&self) -> Res<usize> {
        self.sessions
            .iter()
            .position(|s| !s.used)
            .ok_or(Status::Kernel(abi::Error::LimitReached))
    }

    /// Closes everything a session held, or gives up the reference of a pass whose last copy went
    /// (the label went).
    pub fn gone<D: Device>(&mut self, fs: &mut Fs<'_, D>, label: u64) {
        if let Some(i) = self.passes.iter().position(|p| p.used && p.label == label) {
            self.passes[i].used = false;
            let _ = self.deref(fs, usize::from(self.passes[i].description));
            return;
        }
        if let Some(si) = self
            .sessions
            .iter()
            .position(|s| s.used && s.label == label)
        {
            for di in 0..DESCRIPTIONS {
                if self.sessions[si].held & (1 << di) != 0 {
                    let _ = self.deref(fs, di);
                }
            }
            self.sessions[si] = Session::EMPTY;
        }
    }

    /// Closes every file and directory still open, for the stop of the service: a file's data
    /// reaches the volume when it is closed. The number of the descriptions that did not close.
    pub fn close_all<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> usize {
        let mut failed = 0;
        for i in 0..DESCRIPTIONS {
            if self.descriptions[i].used {
                self.descriptions[i].refs = 1;
                if self.deref(fs, i).is_err() {
                    failed += 1;
                }
            }
        }
        for s in &mut self.sessions {
            s.held = 0;
        }
        for pass in &mut self.passes {
            pass.used = false;
        }
        failed
    }

    /// One reference of a description goes; the last one closes it.
    fn deref<D: Device>(&mut self, fs: &mut Fs<'_, D>, di: usize) -> Result<(), Error> {
        let d = &mut self.descriptions[di];
        d.refs = d.refs.saturating_sub(1);
        if d.refs > 0 {
            return Ok(());
        }
        let d = *d;
        self.descriptions[di].used = false;
        match d.kind {
            Kind::File => self.node_unref(fs, usize::from(d.object)),
            Kind::Directory => fs.closedir(Dir(d.object)),
        }
    }

    /// The session `si` lets go of a description.
    fn unhold<D: Device>(&mut self, fs: &mut Fs<'_, D>, si: usize, di: usize) -> Result<(), Error> {
        self.sessions[si].held &= !(1 << di);
        self.deref(fs, di)
    }

    fn node_unref<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize) -> Result<(), Error> {
        let n = &mut self.nodes[ni];
        n.refs = n.refs.saturating_sub(1);
        if n.refs > 0 {
            return Ok(());
        }
        let n = *n;
        self.nodes[ni].used = false;
        let closed = if n.broken {
            Ok(())
        } else {
            fs.close(File(n.slot))
        };
        if n.orphan {
            let _ = fs.remove(n.path.get());
        }
        closed
    }

    fn node_at(&self, path: &[u8]) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.used && !n.orphan && n.path.get() == path)
    }

    /// Whether a description holds `path` or something under it, except a file that the rename or
    /// the unlink of that very path handles (`Server::run`).
    fn dir_in_use(&self, path: &[u8]) -> bool {
        if cfg!(feature = "break-datafs-busy") {
            return false;
        }
        self.nodes
            .iter()
            .any(|n| n.used && !n.orphan && within(n.path.get(), path))
            || self.descriptions.iter().any(|d| {
                d.used
                    && d.kind == Kind::Directory
                    && within(self.dirs[usize::from(d.object)].get(), path)
            })
    }

    /// The open file `ni` is closed (which commits what was written), moved by the volume to `to`
    /// and opened again there. On an error the node is broken when it could not be opened again.
    fn move_node<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize, to: &[u8]) -> Res<()> {
        let node = self.nodes[ni];
        if node.broken {
            return Err(p::code(p::IO));
        }
        self.nodes[ni].broken = true;
        volume(fs.close(File(node.slot)))?;
        let renamed = fs.rename(node.path.get(), to);
        let at = if renamed.is_ok() { to } else { node.path.get() };
        let file = volume(fs.open(at, Open::READ_WRITE))?;
        let n = &mut self.nodes[ni];
        n.slot = file.0;
        n.broken = false;
        n.at = None;
        if renamed.is_ok() {
            n.path.set(to);
        }
        volume(renamed)
    }

    /// The open file `ni` leaves the tree and stays readable and writable for its descriptions.
    fn orphan<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize) -> Res<()> {
        match fs.mkdir(ORPHANS) {
            Ok(()) | Err(Error::Exists) => {}
            Err(e) => return Err(status_of(e)),
        }
        self.orphan_seq = self.orphan_seq.wrapping_add(1);
        let (path, len) = orphan_path(self.orphan_seq);
        self.move_node(fs, ni, &path[..len])?;
        self.nodes[ni].orphan = true;
        Ok(())
    }

    /// Seeks the open file of `ni` to `pos` unless it is there.
    fn place<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize, pos: u32) -> Res<File> {
        let n = &mut self.nodes[ni];
        if n.broken {
            return Err(p::code(p::IO));
        }
        let file = File(n.slot);
        if n.at != Some(pos) {
            n.at = None;
            let pos = i32::try_from(pos).map_err(|_| p::code(p::TOO_BIG))?;
            volume(fs.seek(file, pos, Whence::Set))?;
            n.at = Some(pos as u32);
        }
        Ok(file)
    }

    /// The reply to `request` (its header and body) from the session `owner`: the status first. The
    /// reply is whole in the returned writer. `aux` is the label the service made for the call: the
    /// new session of CLONE, the pass of EXPORT, the pass the handle of ADOPT names (0 for the rest).
    pub fn handle<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        owner: u64,
        aux: u64,
        request: &[u8],
    ) -> Writer {
        let mut w = Writer::new();
        let done = w
            .u32(0)
            .and_then(|()| self.run(fs, owner, aux, request, &mut w));
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
        aux: u64,
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
        let si = self.session(owner)?;
        let mut path = [0u8; MAX_PATH];
        match method {
            Method::Open => {
                let flags = r.u32()?;
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                visible(&path[..n])?;
                self.do_open(fs, si, flags, &path[..n], w)
            }
            Method::Close => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                volume(self.unhold(fs, si, di))
            }
            Method::Read => {
                let di = self.find(si, r.u32()?)?;
                let count = (r.u32()? as usize).min(p::MAX_READ);
                r.finish()?;
                let pos = self.descriptions[di].pos;
                let n = self.read_at(fs, di, pos, count, w)?;
                self.descriptions[di].pos = pos + n as u32;
                Ok(())
            }
            Method::Pread => {
                let di = self.find(si, r.u32()?)?;
                let count = (r.u32()? as usize).min(p::MAX_READ);
                let offset = r.u64()?;
                r.finish()?;
                let offset = u32::try_from(offset)
                    .ok()
                    .filter(|&o| o <= i32::MAX as u32)
                    .ok_or_else(|| p::code(p::TOO_BIG))?;
                self.read_at(fs, di, offset, count, w).map(drop)
            }
            Method::Write => {
                let di = self.find(si, r.u32()?)?;
                let data = r.bytes(r.left())?;
                let pos = self.descriptions[di].pos;
                let (at, n) = self.write_at(fs, di, pos, data)?;
                self.descriptions[di].pos = at + n as u32;
                w.u32(n as u32)
            }
            Method::Pwrite => {
                let di = self.find(si, r.u32()?)?;
                let offset = r.u64()?;
                let data = r.bytes(r.left())?;
                let offset = u32::try_from(offset)
                    .ok()
                    .filter(|&o| o <= i32::MAX as u32)
                    .ok_or_else(|| p::code(p::TOO_BIG))?;
                let (_, n) = self.write_at(fs, di, offset, data)?;
                w.u32(n as u32)
            }
            Method::Seek => {
                let di = self.find(si, r.u32()?)?;
                let offset = r.u64()? as i64;
                let whence = r.u32()?;
                r.finish()?;
                let d = self.descriptions[di];
                if d.kind != Kind::File {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                let base = match whence {
                    p::SEEK_SET => 0,
                    p::SEEK_CUR => i64::from(d.pos),
                    p::SEEK_END => self.size_of(fs, usize::from(d.object))? as i64,
                    _ => return Err(p::code(p::INVALID)),
                };
                let at = base
                    .checked_add(offset)
                    .filter(|&at| at >= 0)
                    .ok_or_else(|| p::code(p::INVALID))?;
                let at = u32::try_from(at)
                    .ok()
                    .filter(|&a| a <= i32::MAX as u32)
                    .ok_or_else(|| p::code(p::TOO_BIG))?;
                self.descriptions[di].pos = at;
                w.u64(u64::from(at))
            }
            Method::Fsync => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                match d.kind {
                    Kind::File => {
                        let n = &self.nodes[usize::from(d.object)];
                        if n.broken {
                            return Err(p::code(p::IO));
                        }
                        volume(fs.sync(File(n.slot)))
                    }
                    // Every change of a directory is durable when it returns.
                    Kind::Directory => Ok(()),
                }
            }
            Method::Truncate => {
                let di = self.find(si, r.u32()?)?;
                let size = r.u64()?;
                r.finish()?;
                let d = self.descriptions[di];
                if d.kind != Kind::File {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                if !d.write {
                    return Err(bad_handle());
                }
                let size = u32::try_from(size)
                    .ok()
                    .filter(|&s| s <= i32::MAX as u32)
                    .ok_or_else(|| p::code(p::TOO_BIG))?;
                let ni = usize::from(d.object);
                if self.nodes[ni].broken {
                    return Err(p::code(p::IO));
                }
                let file = File(self.nodes[ni].slot);
                self.nodes[ni].at = None;
                volume(fs.truncate(file, size))
            }
            Method::Stat => {
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                visible(&path[..n])?;
                let info = volume(fs.stat(&path[..n]))?;
                w.u32(kind_word(info.kind))?;
                w.u32(info.size)
            }
            Method::Fstat => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                match d.kind {
                    Kind::File => {
                        let size = self.size_of(fs, usize::from(d.object))?;
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
                visible(&path[..n])?;
                volume(fs.mkdir(&path[..n]))
            }
            Method::Unlink | Method::Rmdir => {
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                let path = &path[..n];
                if path == b"/" {
                    return Err(p::code(p::BUSY));
                }
                visible(path)?;
                let info = volume(fs.stat(path))?;
                match (method, info.kind) {
                    (Method::Unlink, Kind::Directory) => return Err(p::code(p::IS_DIRECTORY)),
                    (Method::Rmdir, Kind::File) => return Err(p::code(p::NOT_DIRECTORY)),
                    _ => {}
                }
                if info.kind == Kind::Directory {
                    if self.dir_in_use(path) {
                        return Err(p::code(p::BUSY));
                    }
                    return volume(fs.remove(path));
                }
                match self.node_at(path) {
                    // Open: the descriptions keep the file, which leaves the tree.
                    Some(ni) => self.orphan(fs, ni),
                    None => volume(fs.remove(path)),
                }
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
                visible(from)?;
                visible(to)?;
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
                if source.kind == Kind::Directory {
                    if self.dir_in_use(from) || self.dir_in_use(to) {
                        return Err(p::code(p::BUSY));
                    }
                    return volume(fs.rename(from, to));
                }
                if from == to {
                    return Ok(());
                }
                // A file that the rename replaces and that is open goes under the orphans first.
                if let Some(target) = self.node_at(to) {
                    self.orphan(fs, target)?;
                }
                match self.node_at(from) {
                    Some(ni) => self.move_node(fs, ni, to),
                    None => volume(fs.rename(from, to)),
                }
            }
            Method::Readdir => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                if d.kind != Kind::Directory {
                    return Err(p::code(p::NOT_DIRECTORY));
                }
                let root = self.dirs[usize::from(d.object)].get() == b"/";
                loop {
                    match volume(fs.readdir(Dir(d.object)))? {
                        None => {
                            w.u32(0)?;
                            w.u32(0)?;
                            return w.u32(0);
                        }
                        Some(entry) if root && entry.name() == &ORPHANS[1..] => {}
                        Some(entry) => return write_entry(w, &entry),
                    }
                }
            }
            Method::Rewind => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                if d.kind != Kind::Directory {
                    return Err(p::code(p::NOT_DIRECTORY));
                }
                volume(fs.rewinddir(Dir(d.object)))
            }
            Method::Statfs => {
                r.finish()?;
                let used = volume(fs.used_blocks())?;
                w.u64(fs.blocks())?;
                w.u64(used)?;
                w.u32(p::BLOCK)
            }
            Method::GetFlags => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                let mut flags = 0;
                if d.kind == Kind::Directory {
                    flags |= p::DIRECTORY;
                }
                if d.read {
                    flags |= p::READ;
                }
                if d.write {
                    flags |= p::WRITE;
                }
                if d.append {
                    flags |= p::APPEND;
                }
                w.u32(flags)
            }
            Method::SetFlags => {
                let di = self.find(si, r.u32()?)?;
                let flags = r.u32()?;
                r.finish()?;
                if flags & !p::APPEND != 0 || self.descriptions[di].kind != Kind::File {
                    return Err(p::code(p::INVALID));
                }
                self.descriptions[di].append = flags & p::APPEND != 0;
                Ok(())
            }
            Method::Clone => {
                let count = r.u32()?;
                let mut handles = [0; p::CLONE_MAX];
                let count = p::read_handles(r, count, &mut handles)?;
                let mask = self.mask_of(si, &handles[..count])?;
                if aux == 0 || self.sessions.iter().any(|s| s.used && s.label == aux) {
                    return Err(p::code(p::INVALID));
                }
                let ci = self.free_session()?;
                self.birth_seq = self.birth_seq.wrapping_add(1).max(1);
                self.sessions[ci] = Session {
                    used: true,
                    label: aux,
                    held: mask,
                    parent: owner,
                    birth: self.birth_seq,
                };
                self.add_refs(mask);
                w.u32((ci as u32 + 1) | (u32::from(self.birth_seq) << 16))
            }
            Method::CloneMore => {
                let birth = r.u32()?;
                let count = r.u32()?;
                let mut handles = [0; p::CLONE_MAX];
                let count = p::read_handles(r, count, &mut handles)?;
                if count == 0 {
                    return Err(p::code(p::INVALID));
                }
                let mask = self.mask_of(si, &handles[..count])?;
                let ci = ((birth & 0xFFFF) as usize)
                    .checked_sub(1)
                    .filter(|&i| i < SESSIONS)
                    .ok_or_else(bad_handle)?;
                let child = self.sessions[ci];
                if !child.used
                    || child.birth == 0
                    || u32::from(child.birth) != birth >> 16
                    || child.parent != owner
                {
                    return Err(bad_handle());
                }
                let fresh = mask & !child.held;
                if (child.held | mask).count_ones() as usize > HELD_MAX {
                    return Err(p::code(p::TOO_MANY_OPEN));
                }
                self.sessions[ci].held |= mask;
                self.add_refs(fresh);
                Ok(())
            }
            Method::Export => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                if aux == 0 || self.passes.iter().any(|p| p.used && p.label == aux) {
                    return Err(p::code(p::INVALID));
                }
                let mine = self
                    .passes
                    .iter()
                    .filter(|p| p.used && p.owner == owner)
                    .count();
                let free = self.passes.iter().position(|p| !p.used);
                let Some(free) = free.filter(|_| mine < p::PASSES_MAX) else {
                    return Err(Status::Kernel(abi::Error::LimitReached));
                };
                self.passes[free] = Pass {
                    used: true,
                    label: aux,
                    owner,
                    description: di as u8,
                };
                self.descriptions[di].refs += 1;
                Ok(())
            }
            Method::Adopt => {
                r.finish()?;
                let pi = self
                    .passes
                    .iter()
                    .position(|p| p.used && p.label == aux && aux != 0)
                    .ok_or_else(bad_handle)?;
                self.passes[pi].used = false;
                let di = usize::from(self.passes[pi].description);
                if self.sessions[si].held & (1 << di) != 0 {
                    // The session has it: the reference of the pass goes.
                    let _ = self.deref(fs, di);
                } else if self.sessions[si].held.count_ones() as usize >= HELD_MAX {
                    let _ = self.deref(fs, di);
                    return Err(p::code(p::TOO_MANY_OPEN));
                } else {
                    // The reference of the pass becomes the session's.
                    self.sessions[si].held |= 1 << di;
                }
                w.u32(self.handle_of(di))?;
                w.u32(kind_word(self.descriptions[di].kind))
            }
        }
    }

    /// The bits of the descriptions the handles name, all held by `si`.
    fn mask_of(&self, si: usize, handles: &[u32]) -> Res<u16> {
        let mut mask = 0u16;
        for &h in handles {
            mask |= 1 << self.find(si, h)?;
        }
        Ok(mask)
    }

    fn add_refs(&mut self, mask: u16) {
        for di in 0..DESCRIPTIONS {
            if mask & (1 << di) != 0 {
                self.descriptions[di].refs += 1;
            }
        }
    }

    /// The size of a shared file, with what the descriptions wrote and has not been synced.
    fn size_of<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize) -> Res<u64> {
        let n = &self.nodes[ni];
        if n.broken {
            return Err(p::code(p::IO));
        }
        volume(fs.size(File(n.slot)))
    }

    /// READ and PREAD: up to `count` bytes at `pos` into the reply; the count read.
    fn read_at<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        di: usize,
        pos: u32,
        count: usize,
        w: &mut Writer,
    ) -> Res<usize> {
        let d = self.descriptions[di];
        if d.kind != Kind::File {
            return Err(p::code(p::IS_DIRECTORY));
        }
        if !d.read {
            return Err(bad_handle());
        }
        let ni = usize::from(d.object);
        let file = self.place(fs, ni, pos)?;
        self.nodes[ni].at = None;
        let mut buffer = [0u8; p::MAX_READ];
        let n = volume(fs.read(file, &mut buffer[..count]))?;
        self.nodes[ni].at = Some(pos + n as u32);
        w.u32(n as u32)?;
        w.bytes(&buffer[..n])?;
        Ok(n)
    }

    /// WRITE and PWRITE: `data` at `pos`, or at the end of the file for an append description, the
    /// end taken now. The place written and the count.
    fn write_at<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        di: usize,
        pos: u32,
        data: &[u8],
    ) -> Res<(u32, usize)> {
        let d = self.descriptions[di];
        if d.kind != Kind::File {
            return Err(p::code(p::IS_DIRECTORY));
        }
        if !d.write {
            return Err(bad_handle());
        }
        let ni = usize::from(d.object);
        let pos = if d.append {
            u32::try_from(self.size_of(fs, ni)?)
                .ok()
                .filter(|&s| s <= i32::MAX as u32)
                .ok_or_else(|| p::code(p::TOO_BIG))?
        } else {
            pos
        };
        let file = self.place(fs, ni, pos)?;
        self.nodes[ni].at = None;
        let n = volume(fs.write(file, data))?;
        self.nodes[ni].at = Some(pos + n as u32);
        Ok((pos, n))
    }

    fn do_open<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        si: usize,
        flags: u32,
        path: &[u8],
        w: &mut Writer,
    ) -> Res<()> {
        if flags & !p::FLAGS_ALL != 0 {
            return Err(p::code(p::INVALID));
        }
        if self.sessions[si].held.count_ones() as usize >= HELD_MAX {
            return Err(p::code(p::TOO_MANY_OPEN));
        }
        let di = self
            .descriptions
            .iter()
            .position(|d| !d.used)
            .ok_or_else(|| p::code(p::TOO_MANY_OPEN))?;
        let kind = if flags & p::DIRECTORY != 0 {
            Kind::Directory
        } else {
            Kind::File
        };
        let mut description = Description {
            used: true,
            kind,
            refs: 1,
            ..Description::EMPTY
        };
        match kind {
            Kind::Directory => {
                if flags & (p::WRITE | p::CREATE | p::TRUNCATE | p::APPEND) != 0 {
                    return Err(p::code(p::IS_DIRECTORY));
                }
                let slot = volume(fs.opendir(path))?.0;
                self.dirs[usize::from(slot)].set(path);
                description.object = slot;
            }
            Kind::File => {
                description.read = flags & p::READ != 0;
                description.write = flags & p::WRITE != 0;
                description.append = flags & p::APPEND != 0;
                if !description.read && !description.write {
                    return Err(p::code(p::INVALID));
                }
                if flags & p::TRUNCATE != 0 && !description.write {
                    return Err(p::code(p::INVALID));
                }
                let (ni, fresh) = match self.node_at(path) {
                    Some(ni) => {
                        if flags & p::CREATE != 0 && flags & p::EXCLUSIVE != 0 {
                            return Err(p::code(p::EXISTS));
                        }
                        (ni, false)
                    }
                    None => {
                        // A directory opens only as one.
                        if let Ok(info) = fs.stat(path)
                            && info.kind == Kind::Directory
                        {
                            return Err(p::code(p::IS_DIRECTORY));
                        }
                        let ni = self
                            .nodes
                            .iter()
                            .position(|n| !n.used)
                            .ok_or_else(|| p::code(p::TOO_MANY_OPEN))?;
                        let mut open = Open::READ_WRITE;
                        if flags & p::CREATE != 0 {
                            open = open.with(Open::CREATE);
                            if flags & p::EXCLUSIVE != 0 {
                                open = open.with(Open::EXCLUSIVE);
                            }
                        }
                        let file = volume(fs.open(path, open))?;
                        let mut node = Node {
                            used: true,
                            slot: file.0,
                            ..Node::EMPTY
                        };
                        node.path.set(path);
                        self.nodes[ni] = node;
                        (ni, true)
                    }
                };
                if flags & p::TRUNCATE != 0 {
                    let file = File(self.nodes[ni].slot);
                    self.nodes[ni].at = None;
                    if let Err(e) = fs.truncate(file, 0) {
                        if fresh {
                            self.nodes[ni].refs = 1;
                            let _ = self.node_unref(fs, ni);
                        }
                        return Err(status_of(e));
                    }
                }
                self.nodes[ni].refs += 1;
                description.object = ni as u8;
            }
        }
        self.generation = self.generation.wrapping_add(1).max(1);
        description.generation = self.generation;
        self.descriptions[di] = description;
        self.sessions[si].held |= 1 << di;
        w.u32(self.handle_of(di))?;
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
