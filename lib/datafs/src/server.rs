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
//! cut left, at the next mount. A rename of an open file closes and reopens it the same way, after a
//! sync that a failing volume can refuse without harm to the file. A rename over an open file makes two
//! commits; the old target carries a mark (a token that its name spells, and its home name) from
//! before the first, so that a mount puts it back when the cut came between them (`recover_orphans`).

use crate::attr::{
    ATTR_COUNTER_TYPE, ATTR_FORMAT_TYPE, ATTR_TYPE, Attr, Entry as Record, INO_BLOCK,
    RESERVE_BLOCKS, Standing, VOLUME_FORMAT, default_attr, read_entry,
};
use crate::binding::{self, Binding, Caller, Root, Vouched};
use crate::fs::{Dir, Error, File, Fs, Kind, Open, Whence};
use crate::{BLOCK, DIRS, Device, FILES};
use posix_perm::{self as perm, Denial, TimesRequest};
use proto_data as p;
use proto_data::Method;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

/// The sessions of the table: the loop of the service holds as many.
pub const SESSIONS: usize = 64;
/// The descriptions open at once (a bit of a session's mask each).
pub const DESCRIPTIONS: usize = 64;
/// The longest path the service takes.
pub const MAX_PATH: usize = p::MAX_PATH;
/// The descriptions one session holds at most.
pub const HELD_MAX: usize = p::HELD_MAX;
/// The descriptions CLONE and CLONE_MORE carry at most.
pub const CLONE_MAX: usize = p::CLONE_MAX;
/// The passes one process tree has made and not spent at once.
pub const PASSES_MAX: usize = p::PASSES_MAX;
/// The live clones of one process tree.
pub const ROOT_CLONES: usize = p::ROOT_CLONES;
/// The distinct descriptions the sessions of one process tree hold together.
pub const ROOT_DESCRIPTIONS: usize = p::ROOT_DESCRIPTIONS;
/// The entries of one directory at most (the service keeps the minimum of the protocol).
pub const DIR_ENTRIES_MAX: usize = p::DIR_ENTRIES_MAX;
/// The passes alive at once.
pub const PASSES: usize = 16;
/// The directories whose attributes the server remembers between requests (the search of a path).
const DIR_CACHE: usize = 32;
/// The directories whose count of entries the server remembers.
const COUNT_CACHE: usize = 8;
/// The hidden directory of the files that are unlinked and still open.
pub const ORPHANS: &[u8] = b"/.orphans";
/// The user attribute of an orphan that a rename over an open file made: its token and home name.
const ATTR_HOME: u8 = 0x68;
/// The user attribute of the root: the count of the mounts, the epoch of the instance.
const ATTR_EPOCH: u8 = 0x65;
/// The bits of the epoch a handle carries (bits 16 to 31).
pub const EPOCH_BITS: u32 = 16;
const EPOCH_MASK: u32 = (1 << EPOCH_BITS) - 1;

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
    /// Every write is durable before its reply.
    sync: bool,
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
        sync: false,
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
    /// Written since the attribute was last written: the time of the last write (`mtime` and
    /// `ctime`) and the clearing of the set-ID bits wait for the sync or the last close.
    wrote: bool,
    wrote_at: i64,
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
        wrote: false,
        wrote_at: 0,
        path: PathBuf::EMPTY,
    };
}

#[derive(Clone, Copy)]
struct Session {
    used: bool,
    label: u64,
    /// The descriptions held, a bit each.
    held: u64,
    /// Who the client is (rules 1 and 2).
    binding: Binding,
    /// For a session made by CLONE: the session that made it, and the birth number while the child
    /// has sent nothing (0 after its first request).
    parent: u64,
    birth: u16,
    /// The client at the top of the tree of sessions this session belongs to (its own label for a
    /// client of init, the root of the expenditure for a session made by SESSION): the limits of a
    /// process tree count by it.
    root: Root,
}

impl Session {
    const EMPTY: Session = Session {
        used: false,
        label: 0,
        held: 0,
        binding: Binding::Unbound,
        parent: 0,
        birth: 0,
        root: Root::Label(0),
    };
}

#[derive(Clone, Copy)]
struct Pass {
    used: bool,
    label: u64,
    /// The root of the session that made it.
    owner: Root,
    description: u8,
}

/// What a directory's listing keeps between two READDIR calls: the entry that did not fit the
/// reply of the last one.
#[derive(Clone, Copy)]
struct Pending {
    ino: u64,
    kind: Kind,
    name: [u8; crate::NAME_MAX],
    len: usize,
}

/// A directory whose permission attributes the server remembers.
#[derive(Clone, Copy)]
struct Cached {
    used: bool,
    path: PathBuf,
    attr: perm::Attr,
}

/// A directory whose count of entries the server remembers.
#[derive(Clone, Copy)]
struct Counted {
    used: bool,
    path: PathBuf,
    entries: usize,
}

pub struct Server {
    descriptions: [Description; DESCRIPTIONS],
    pending: [Option<Pending>; DIRS],
    cache: [Cached; DIR_CACHE],
    cache_hand: usize,
    counts: [Counted; COUNT_CACHE],
    counts_hand: usize,
    /// The present moment in nanoseconds, which the service sets before each job (the clock page).
    now: i64,
    /// The next file number to hand out and the end of the block reserved in the counter.
    ino_next: u64,
    ino_end: u64,
    /// The volume's format is above this service's: every request answers NOT_READY.
    refused: bool,
    nodes: [Node; FILES],
    dirs: [PathBuf; DIRS],
    sessions: [Session; SESSIONS],
    passes: [Pass; PASSES],
    generation: u8,
    epoch: u32,
    birth_seq: u16,
    orphan_seq: u32,
    #[cfg(test)]
    pub(crate) fail_reopen: bool,
    #[cfg(test)]
    pub(crate) fail_second: bool,
    /// Tests: every session starts as a native client's (user 0), as before permissions; the
    /// permission tests turn it off.
    #[cfg(test)]
    pub(crate) default_service: bool,
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
        Error::NoEntry | Error::NoAttr => p::NO_ENTRY,
        Error::Exists => p::EXISTS,
        Error::NotDirectory => p::NOT_DIRECTORY,
        Error::IsDirectory => p::IS_DIRECTORY,
        Error::NotEmpty => p::NOT_EMPTY,
        Error::BadDescriptor => p::BAD_HANDLE,
        Error::TooBig => p::TOO_BIG,
        Error::Invalid => p::INVALID,
        Error::NoSpace => p::NO_SPACE,
        Error::NoMemory => p::TABLE_FULL,
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

/// The path of an orphan: `ORPHANS`, a slash and its token in decimal.
fn orphan_path(token: u64) -> ([u8; 32], usize) {
    let mut out = [0u8; 32];
    out[..ORPHANS.len()].copy_from_slice(ORPHANS);
    let mut n = ORPHANS.len();
    out[n] = b'/';
    n += 1;
    let mut digits = [0u8; 20];
    let mut count = 0;
    let mut v = token;
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

/// The token an orphan's name spells, if it spells one.
fn token_of(name: &[u8]) -> Option<u64> {
    if name.is_empty() || name.len() > 20 {
        return None;
    }
    name.iter().try_fold(0u64, |v, &b| {
        b.is_ascii_digit()
            .then(|| v.checked_mul(10)?.checked_add(u64::from(b - b'0')))
            .flatten()
    })
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

/// What `recover_orphans` did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Recovered {
    /// Orphans removed: files that were unlinked while open, and replaced files whose home name
    /// is taken.
    pub removed: usize,
    /// Orphans put back under their home name: the old target of a rename that a cut stopped
    /// between its two commits.
    pub restored: usize,
    /// Entries that could not be removed or restored (the volume failed); they stay.
    pub failed: usize,
}

/// Makes the hidden directory of the orphans, so that the first unlink of an open file does not
/// have to make it on a volume that may be full. Run after the mount.
pub fn ensure_orphans<D: Device>(fs: &mut Fs<'_, D>) -> Result<(), Error> {
    match fs.mkdir(ORPHANS) {
        Ok(()) | Err(Error::Exists) => Ok(()),
        Err(e) => Err(e),
    }
}

/// The count of the mounts of the volume, the epoch of this instance: read from the root's
/// attribute, one more, written back. It differs from the epoch of every earlier instance of the
/// volume (until the count wraps past the bits a handle carries).
pub fn bump_epoch<D: Device>(fs: &mut Fs<'_, D>) -> Result<u32, Error> {
    let mut old = [0u8; 4];
    let last = match fs.getattr(b"/", ATTR_EPOCH, &mut old) {
        Ok(4) => u32::from_le_bytes(old),
        Ok(_) | Err(Error::NoAttr) => 0,
        Err(e) => return Err(e),
    };
    let mut next = last.wrapping_add(1);
    if next & EPOCH_MASK == 0 {
        next = next.wrapping_add(1);
    }
    fs.setattr(b"/", ATTR_EPOCH, &next.to_le_bytes())?;
    Ok(next)
}

/// What the mount work did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Mounted {
    /// The volume's format mark is above this service's: the service refuses it (every request
    /// answers NOT_READY) and wrote nothing.
    pub refused: bool,
    /// Entries that got a record (a volume of version 2 has none).
    pub converted: usize,
    /// The walk of the tree ended: the format mark was written. False when it was cut short by its
    /// bound (`CONVERT_MAX` records written); the next mount goes on. Entries deeper than
    /// `CONVERT_DEPTH` directories are left with no record (they read as the closed default, which is
    /// safe) and do not hold the mark back.
    pub complete: bool,
}

/// The entries one run of the conversion looks at at most, and the depth it goes to.
pub const CONVERT_MAX: usize = 8192;
const CONVERT_DEPTH: usize = 32;

impl Server {
    /// The work after the mount that gives the volume the attributes of version 3 (rule 12), after
    /// `ensure_orphans` and `recover_orphans` and before the first request. A volume whose format
    /// mark is above `VOLUME_FORMAT` is refused and left as it is. A volume with no mark, or an
    /// older one, gets the record of every entry that has none (the closed default, a number from the
    /// counter at the root), then the mark: a cut in between starts the walk again at the next mount,
    /// and the entries done keep their records.
    pub fn mount_work<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Result<Mounted, Error> {
        let mut mark = [0u8; 4];
        let format = match fs.getattr(b"/", ATTR_FORMAT_TYPE, &mut mark) {
            Ok(4) => Some(u32::from_le_bytes(mark)),
            Ok(_) => Some(u32::MAX),
            Err(Error::NoAttr) => None,
            Err(e) => return Err(e),
        };
        self.ino_next = 0;
        self.ino_end = 0;
        // What the server remembers of directories starts empty at every mount.
        for c in &mut self.cache {
            c.used = false;
        }
        for c in &mut self.counts {
            c.used = false;
        }
        match format {
            Some(f) if f > VOLUME_FORMAT => {
                self.refused = true;
                return Ok(Mounted {
                    refused: true,
                    converted: 0,
                    complete: false,
                });
            }
            Some(f) if f == VOLUME_FORMAT => {
                return Ok(Mounted {
                    refused: false,
                    converted: 0,
                    complete: true,
                });
            }
            _ => {}
        }
        let (converted, complete) = self.convert(fs)?;
        if complete {
            fs.setattr(b"/", ATTR_FORMAT_TYPE, &VOLUME_FORMAT.to_le_bytes())?;
        }
        Ok(Mounted {
            refused: false,
            converted,
            complete,
        })
    }

    /// Walks the tree and writes the record of every entry that has none. The root first.
    fn convert<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Result<(usize, bool), Error> {
        let mut converted = 0;
        // The root has number 1 and the default `0755`.
        if let Ok(root) = entry_of(fs, b"/", Kind::Directory)
            && root.standing == Standing::Missing
        {
            let mut a = default_attr(Kind::Directory, b"/");
            a.ino = 1;
            fs.setattr(b"/", ATTR_TYPE, &a.to_bytes())?;
            converted += 1;
        }
        let mut path = [0u8; MAX_PATH + 1];
        path[0] = b'/';
        let mut len = 1;
        // The entry each level has gone past, so that a level that was closed for a write
        // is opened again and skips what it did.
        let mut done = [0usize; CONVERT_DEPTH];
        let mut depth = 0;
        'levels: loop {
            let dir = fs.opendir(&path[..len])?;
            let mut skip = done[depth];
            loop {
                let entry = match fs.readdir(dir) {
                    Ok(Some(e)) => e,
                    Ok(None) => {
                        fs.closedir(dir)?;
                        if depth == 0 {
                            return Ok((converted, true));
                        }
                        // Up: drop the last name of the path.
                        depth -= 1;
                        len = path[..len]
                            .iter()
                            .rposition(|&b| b == b'/')
                            .map_or(1, |i| i.max(1));
                        continue 'levels;
                    }
                    Err(e) => {
                        let _ = fs.closedir(dir);
                        return Err(e);
                    }
                };
                let name = entry.name();
                if name == b"." || name == b".." {
                    continue;
                }
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                done[depth] += 1;
                let mut child = [0u8; MAX_PATH + 1 + crate::NAME_MAX];
                child[..len].copy_from_slice(&path[..len]);
                let mut n = len;
                if len > 1 {
                    child[n] = b'/';
                    n += 1;
                }
                if n + name.len() > MAX_PATH {
                    continue;
                }
                child[n..n + name.len()].copy_from_slice(name);
                n += name.len();
                let child_path = &child[..n];
                let rec = match entry_of(fs, child_path, entry.kind) {
                    Ok(r) => r,
                    Err(_) => {
                        fs.closedir(dir)?;
                        return Err(Error::Io);
                    }
                };
                let mut wrote = false;
                if rec.standing == Standing::Missing {
                    // The bound counts the records written, so that a volume of more entries than
                    // the bound still ends: each mount writes some, and the entries done are skipped
                    // at no write.
                    if converted >= CONVERT_MAX {
                        fs.closedir(dir)?;
                        return Ok((converted, false));
                    }
                    let mut a = default_attr(entry.kind, child_path);
                    // A number from the counter; a failed reserve leaves the entry for the next mount.
                    match self.next_ino(fs) {
                        Ok(ino) => a.ino = ino,
                        Err(_) => {
                            fs.closedir(dir)?;
                            return Err(Error::Io);
                        }
                    }
                    fs.closedir(dir)?;
                    fs.setattr(child_path, ATTR_TYPE, &a.to_bytes())?;
                    converted += 1;
                    wrote = true;
                }
                if entry.kind == Kind::Directory && depth + 1 < CONVERT_DEPTH {
                    if !wrote {
                        fs.closedir(dir)?;
                    }
                    path[..n].copy_from_slice(&child[..n]);
                    len = n;
                    depth += 1;
                    done[depth] = 0;
                    continue 'levels;
                }
                if wrote {
                    // Closed for the write: open again past what was done.
                    continue 'levels;
                }
            }
        }
    }
}

/// Whether the request may take blocks from the allocator: a write, a new directory, a file made or
/// grown, a rename (which may split a directory). With an empty window such a request walks the
/// whole volume to find its blocks; while the service stops, the worker answers it with the stop
/// status and does not walk the volume inside the stop (`services/datafs`), where a walk would
/// not fit in the time of the stop.
pub fn needs_blocks(request: &[u8]) -> bool {
    let mut r = Reader::new(request);
    let Ok(header) = Header::read(&mut r) else {
        return false;
    };
    match Method::from_number(header.method) {
        Some(
            Method::Write | Method::Pwrite | Method::Mkdir | Method::Truncate | Method::Rename,
        ) => true,
        Some(Method::Open) => r
            .u32()
            .is_ok_and(|flags| flags & (p::CREATE | p::TRUNCATE) != 0),
        _ => false,
    }
}

/// Deals with what a stop or a cut of the power left under `ORPHANS`, once after the mount and
/// before the first request. A file that a rename over an open file moved there carries a mark
/// (its token, which its name spells, and its home name): when the home name is missing, the rename
/// never reached its second commit, and the file goes back. Every other entry is removed. An entry
/// that cannot be dealt with stays and is counted; the others go on.
pub fn recover_orphans<D: Device>(fs: &mut Fs<'_, D>) -> Result<Recovered, Error> {
    let mut done = Recovered::default();
    let mut skip = 0;
    loop {
        let dir = match fs.opendir(ORPHANS) {
            Ok(dir) => dir,
            Err(Error::NoEntry) => return Ok(done),
            Err(e) => return Err(e),
        };
        let mut path = [0u8; MAX_PATH];
        let mut found = None;
        let mut result = Ok(());
        let mut passed = 0;
        loop {
            match fs.readdir(dir) {
                Ok(Some(e)) if e.name() == b"." || e.name() == b".." => {}
                Ok(Some(_)) if passed < skip => passed += 1,
                Ok(Some(e)) => {
                    let n = ORPHANS.len();
                    path[..n].copy_from_slice(ORPHANS);
                    path[n] = b'/';
                    let len = e.name().len();
                    path[n + 1..n + 1 + len].copy_from_slice(e.name());
                    found = Some((n + 1, n + 1 + len));
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
        let Some((name_at, len)) = found else {
            return Ok(done);
        };
        let entry = &path[..len];
        let token = token_of(&path[name_at..len]);
        let mut mark = [0u8; 8 + MAX_PATH];
        let home = match fs.getattr(entry, ATTR_HOME, &mut mark) {
            Ok(n) if n > 8 && token == Some(u64::from_le_bytes(mark[..8].try_into().unwrap())) => {
                Some(&mark[8..n])
            }
            _ => None,
        };
        // A marked file whose home name is free goes back; if that fails it stays.
        let back = home.filter(|h| !hidden(h) && matches!(fs.stat(h), Err(Error::NoEntry)));
        match back {
            Some(home) => {
                if fs.rename(entry, home).is_ok() {
                    let _ = fs.removeattr(home, ATTR_HOME);
                    done.restored += 1;
                } else {
                    done.failed += 1;
                    skip += 1;
                }
            }
            None => {
                if fs.remove(entry).is_ok() {
                    done.removed += 1;
                } else {
                    done.failed += 1;
                    skip += 1;
                }
            }
        }
    }
}

impl Server {
    /// A server whose handles carry the epoch 1.
    pub const fn new() -> Self {
        Self::with_epoch(1)
    }

    /// A server of the instance `epoch` (its low `EPOCH_BITS` bits, 0 made 1): the handles it gives carry it, and a handle
    /// of another epoch, which a client kept over a restart, answers STALE.
    pub const fn with_epoch(epoch: u32) -> Self {
        Self {
            descriptions: [Description::EMPTY; DESCRIPTIONS],
            pending: [None; DIRS],
            cache: [Cached {
                used: false,
                path: PathBuf::EMPTY,
                attr: perm::Attr {
                    kind: perm::Kind::File,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                },
            }; DIR_CACHE],
            cache_hand: 0,
            counts: [Counted {
                used: false,
                path: PathBuf::EMPTY,
                entries: 0,
            }; COUNT_CACHE],
            counts_hand: 0,
            now: 0,
            ino_next: 0,
            ino_end: 0,
            refused: false,
            nodes: [Node::EMPTY; FILES],
            dirs: [PathBuf::EMPTY; DIRS],
            sessions: [Session::EMPTY; SESSIONS],
            passes: [Pass {
                used: false,
                label: 0,
                owner: Root::Label(0),
                description: 0,
            }; PASSES],
            generation: 0,
            epoch: if epoch & EPOCH_MASK == 0 {
                1
            } else {
                epoch & EPOCH_MASK
            },
            birth_seq: 0,
            orphan_seq: 0,
            #[cfg(test)]
            fail_reopen: false,
            #[cfg(test)]
            fail_second: false,
            #[cfg(test)]
            default_service: true,
        }
    }

    /// Sets the epoch of this instance (as `with_epoch` does) on a server made by `new`: the service
    /// keeps its server in a static, because the tables are too large for the worker's stack.
    pub fn set_epoch(&mut self, epoch: u32) {
        self.epoch = if epoch & EPOCH_MASK == 0 {
            1
        } else {
            epoch & EPOCH_MASK
        };
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

    /// The handle of a description: its place plus one (bits 0 to 7), its generation (8 to 15) and
    /// the epoch of the instance (16 to 31).
    fn handle_of(&self, index: usize) -> u32 {
        (index as u32 + 1)
            | (u32::from(self.descriptions[index].generation) << 8)
            | (self.epoch << 16)
    }

    /// The description a handle names for the session `si`: STALE for a handle of another epoch,
    /// BAD_HANDLE for one that names nothing the session holds.
    fn find(&self, si: usize, handle: u32) -> Res<usize> {
        let epoch = handle >> 16;
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
            root: Root::Label(label),
            binding: self.birth_binding(label),
            ..Session::EMPTY
        };
        Ok(i)
    }

    /// The binding a session starts with: the profile of a native client when its label has the mark.
    fn birth_binding(&self, label: u64) -> Binding {
        #[cfg(test)]
        if self.default_service {
            return Binding::Service;
        }
        binding::initial(label)
    }

    /// A session made by CLONE inherits neither the mark nor the identity.
    fn clone_binding(&self) -> Binding {
        #[cfg(test)]
        if self.default_service {
            return Binding::Service;
        }
        Binding::Unbound
    }

    fn free_session(&self) -> Res<usize> {
        self.sessions
            .iter()
            .position(|s| !s.used)
            .ok_or_else(|| p::code(p::TABLE_FULL))
    }

    /// The sessions a root has besides its own (the session of the client of init that is the root):
    /// the clones made under it and the sessions SESSION made for it. One count for both, so that
    /// no process tree fills the table of sessions by either way.
    fn tree_sessions(&self, root: Root) -> usize {
        self.sessions
            .iter()
            .filter(|s| s.used && s.root == root && root != Root::Label(s.label))
            .count()
    }

    /// The distinct descriptions the sessions of the tree `root` hold.
    fn root_held(&self, root: Root) -> u64 {
        self.sessions
            .iter()
            .filter(|s| s.used && s.root == root)
            .fold(0, |all, s| all | s.held)
    }

    /// Whether the session `si` may hold the description `di` too: its own limit and its tree's.
    fn may_hold(&self, si: usize, di: usize) -> Res<()> {
        let s = &self.sessions[si];
        if s.held & (1 << di) != 0 {
            return Ok(());
        }
        let tree = self.root_held(s.root);
        if s.held.count_ones() as usize >= HELD_MAX
            || (tree & (1 << di) == 0 && tree.count_ones() as usize >= ROOT_DESCRIPTIONS)
        {
            return Err(p::code(p::TOO_MANY_OPEN));
        }
        Ok(())
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
        // The size of an orphan, before its file closes: the bytes it held come back with its name.
        let size = if n.orphan && !n.broken {
            fs.size(File(n.slot)).unwrap_or(0)
        } else {
            0
        };
        // The last close of a file with writes writes its attribute (not for an orphan, which has
        // no name left; a record this service cannot rewrite is left as it is).
        if n.wrote && !n.orphan && !n.broken {
            self.nodes[ni] = n;
            let _ = self.write_times(fs, ni);
            self.nodes[ni].used = false;
        }
        let closed = if n.broken {
            Ok(())
        } else {
            fs.close(File(n.slot))
        };
        if n.orphan && fs.remove(n.path.get()).is_ok() {
            fs.note_freed_file(size);
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

    /// The open file `ni` is synced (what the descriptions wrote reaches the volume; a failure
    /// here leaves the node as it was), closed, moved by the volume to `to` and opened again there.
    /// When the move happened the call is Ok and the node has its new path, whether or not it could
    /// be opened again: if it could not, it is broken and answers IO. With `home`, the file carries
    /// a mark (the `token` and the home name) from before the move, for the recovery at the next
    /// mount (`recover_orphans`).
    fn move_node<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        ni: usize,
        to: &[u8],
        home: Option<(u64, &[u8])>,
    ) -> Res<()> {
        let node = self.nodes[ni];
        if node.broken {
            return Err(p::code(p::IO));
        }
        // littlefs drops a file at close even when the sync inside it fails, so sync first.
        volume(fs.sync(File(node.slot)))?;
        // The attribute follows the name: the time of the writes goes in before the move.
        let _ = self.write_times(fs, ni);
        self.nodes[ni].broken = true;
        volume(fs.close(File(node.slot)))?;
        let moved = match home {
            Some((token, home)) => {
                let mut mark = [0u8; 8 + MAX_PATH];
                mark[..8].copy_from_slice(&token.to_le_bytes());
                mark[8..8 + home.len()].copy_from_slice(home);
                fs.setattr(node.path.get(), ATTR_HOME, &mark[..8 + home.len()])
                    .and_then(|()| fs.rename(node.path.get(), to))
            }
            None => fs.rename(node.path.get(), to),
        };
        let n = &mut self.nodes[ni];
        if moved.is_ok() {
            n.path.set(to);
            n.orphan = hidden(to);
        }
        #[cfg(test)]
        let reopened = if self.fail_reopen {
            Err(Error::Io)
        } else {
            fs.open(self.nodes[ni].path.get(), Open::READ_WRITE)
        };
        #[cfg(not(test))]
        let reopened = fs.open(n.path.get(), Open::READ_WRITE);
        let n = &mut self.nodes[ni];
        match reopened {
            Ok(file) => {
                n.slot = file.0;
                n.broken = false;
                n.at = None;
            }
            Err(e) if moved.is_err() => return Err(status_of(e)),
            Err(_) => {}
        }
        volume(moved)
    }

    /// A token for a new orphan: the epoch of the instance and a count, which no earlier instance
    /// of the volume has used.
    fn next_token(&mut self) -> u64 {
        self.orphan_seq = self.orphan_seq.wrapping_add(1);
        (u64::from(self.epoch) << 32) | u64::from(self.orphan_seq)
    }

    /// The open file `ni` leaves the tree and stays readable and writable for its descriptions. With
    /// `home`, a rename is replacing it there: the mark lets a mount put it back.
    fn orphan<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize, home: Option<&[u8]>) -> Res<()> {
        let token = self.next_token();
        let (path, len) = orphan_path(token);
        let mark = home.map(|h| (token, h));
        match self.move_node(fs, ni, &path[..len], mark) {
            // The directory is made at the mount; a volume that lost it gets it again here.
            Err(Status::Unknown(p::NO_ENTRY)) => {
                match fs.mkdir(ORPHANS) {
                    Ok(()) | Err(Error::Exists) => {}
                    Err(e) => return Err(status_of(e)),
                }
                self.move_node(fs, ni, &path[..len], mark)
            }
            other => other,
        }
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
        // The channels (rule 15): the root takes SESSION and VERIFY_SESSION, which the worker
        // answers (it holds their handle and asks the process service), and a session takes neither.
        if p::is_root(owner) {
            return Err(p::code(if method.is_root_method() {
                p::INVALID
            } else {
                p::IS_ROOT
            }));
        }
        if method.is_root_method() {
            return Err(p::code(p::IS_ROOT));
        }
        if self.refused || !fs.is_mounted() {
            return Err(p::code(p::NOT_READY));
        }
        let si = self.session(owner)?;
        // Rules 1 and 2: the identity of the session, and the requests an unbound one may make.
        let who = self.sessions[si].binding.caller();
        if binding::needs_binding(method) && who.is_none() {
            return Err(p::code(p::NOT_BOUND));
        }
        // An unbound session has no identity: the methods it may make read none, and a change that
        // made one read it would see nobody, never the superuser.
        let caller = who.unwrap_or(Caller::NOBODY);
        let mut path = [0u8; MAX_PATH];
        match method {
            Method::Open => {
                let (flags, mode, raw) = p::read_open(r)?;
                let n = canonical(raw, &mut path)?;
                visible(&path[..n])?;
                self.do_open(fs, si, &caller, (flags, mode), &path[..n], w)
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
                let append = self.descriptions[di].append;
                let (at, n) = self.write_at(fs, di, &caller, pos, append, data)?;
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
                let (_, n) = self.write_at(fs, di, &caller, offset, false, data)?;
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
                    Kind::File => self.sync_node(fs, usize::from(d.object)),
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
                    return Err(bad_handle());
                }
                if !d.write {
                    return Err(bad_handle());
                }
                if size > p::FILE_MAX {
                    return Err(p::code(p::TOO_BIG));
                }
                let ni = usize::from(d.object);
                let current = self.size_of(fs, ni)?;
                // The limit is for a file that grows past it: a file already larger may be made
                // smaller (the check of `inode_newsize_ok` of Linux, XSH `ftruncate()`).
                if size > current && size > caller.fsize_limit {
                    return Err(p::code(p::FILE_SIZE_LIMIT));
                }
                if size > current {
                    // Growing is blocks: the reserve and the room apply as to a write.
                    let room = self.room_bytes(fs, &caller)?;
                    if size - current > room {
                        return Err(p::code(p::NO_SPACE));
                    }
                }
                if self.nodes[ni].broken {
                    return Err(p::code(p::IO));
                }
                let file = File(self.nodes[ni].slot);
                self.nodes[ni].at = None;
                volume(fs.truncate(file, size as u32))?;
                self.nodes[ni].wrote = true;
                self.nodes[ni].wrote_at = self.now;
                Ok(())
            }
            Method::Stat => {
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                visible(&path[..n])?;
                self.search(fs, &caller, false, &path[..n])?;
                let (info, entry) = self.load(fs, &path[..n])?;
                let mut attr = entry.attr;
                let size = match self.node_at(&path[..n]) {
                    Some(ni) => {
                        // The write time of a file written and still unsynced shows at once (XBD 4.12).
                        self.overlay_pending(ni, &mut attr);
                        self.size_of(fs, ni)? as u32
                    }
                    None => info.size,
                };
                stat_record(info.kind, size, &attr, 1).write(w)
            }
            Method::Fstat => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                match d.kind {
                    Kind::File => {
                        let ni = usize::from(d.object);
                        let size = self.size_of(fs, ni)?;
                        let node_path = self.nodes[ni].path;
                        let entry = entry_of(fs, node_path.get(), Kind::File)?;
                        let mut attr = entry.attr;
                        self.overlay_pending(ni, &mut attr);
                        let nlink = u32::from(!self.nodes[ni].orphan);
                        stat_record(Kind::File, size as u32, &attr, nlink).write(w)
                    }
                    Kind::Directory => {
                        let dir_path = self.dirs[usize::from(d.object)];
                        let entry = entry_of(fs, dir_path.get(), Kind::Directory)?;
                        stat_record(Kind::Directory, 0, &entry.attr, 1).write(w)
                    }
                }
            }
            Method::Mkdir => {
                let (mode, raw) = p::read_mode_path(r)?;
                let n = canonical(raw, &mut path)?;
                visible(&path[..n])?;
                self.do_mkdir(fs, &caller, mode, &path[..n])
            }
            Method::Unlink | Method::Rmdir => {
                let n = canonical(r.bytes(r.left())?, &mut path)?;
                visible(&path[..n])?;
                self.do_remove(fs, &caller, method == Method::Rmdir, &path[..n])
            }
            Method::Rename => {
                let (from, to) = p::read_rename(r)?;
                let mut other = [0u8; MAX_PATH];
                let n = canonical(from, &mut path)?;
                let m = canonical(to, &mut other)?;
                self.do_rename(fs, &caller, &path[..n], &other[..m])
            }
            Method::Readdir => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                self.do_readdir(fs, di, w)
            }
            Method::Rewind => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                if d.kind != Kind::Directory {
                    return Err(p::code(p::NOT_DIRECTORY));
                }
                self.pending[usize::from(d.object)] = None;
                volume(fs.rewinddir(Dir(d.object)))
            }
            Method::Statfs => {
                r.finish()?;
                // From the bits of the allocator's window: no read of the device once the first
                // walk is done (`Fs::free_blocks`), and never more free than there are.
                let free = volume(fs.free_blocks())?;
                w.u64(fs.blocks())?;
                w.u64(free)?;
                w.u64(free.saturating_sub(RESERVE_BLOCKS))?;
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
                if d.sync {
                    flags |= p::SYNC;
                }
                w.u32(flags)
            }
            Method::SetFlags => {
                let di = self.find(si, r.u32()?)?;
                let flags = r.u32()?;
                r.finish()?;
                if flags & !p::SET_FLAGS_ALL != 0 || self.descriptions[di].kind != Kind::File {
                    return Err(p::code(p::INVALID));
                }
                self.descriptions[di].append = flags & p::APPEND != 0;
                self.descriptions[di].sync = flags & p::SYNC != 0;
                Ok(())
            }
            Method::Chmod => {
                let (mode, raw) = p::read_mode_path(r)?;
                let n = canonical(raw, &mut path)?;
                visible(&path[..n])?;
                self.search(fs, &caller, false, &path[..n])?;
                self.change_mode(fs, &caller, &path[..n], mode)
            }
            Method::Chown => {
                let (uid, gid, raw) = p::read_chown(r)?;
                let n = canonical(raw, &mut path)?;
                visible(&path[..n])?;
                self.search(fs, &caller, false, &path[..n])?;
                self.change_owner(fs, &caller, &path[..n], uid, gid)
            }
            Method::Utimens => {
                let (atime, mtime, raw) = p::read_utimens(r)?;
                let n = canonical(raw, &mut path)?;
                visible(&path[..n])?;
                self.search(fs, &caller, false, &path[..n])?;
                self.change_times(fs, &caller, &path[..n], atime, mtime)
            }
            Method::Fchmod => {
                let di = self.find(si, r.u32()?)?;
                let mode = p::read_fchmod(r)?;
                let at = self.path_of(di)?;
                self.change_mode(fs, &caller, at.get(), mode)
            }
            Method::Fchown => {
                let di = self.find(si, r.u32()?)?;
                let (uid, gid) = p::read_fchown(r)?;
                let at = self.path_of(di)?;
                self.change_owner(fs, &caller, at.get(), uid, gid)
            }
            Method::Futimens => {
                let di = self.find(si, r.u32()?)?;
                let (atime, mtime) = p::read_futimens(r)?;
                let at = self.path_of(di)?;
                self.change_times(fs, &caller, at.get(), atime, mtime)
            }
            Method::Access => {
                let (bits, flags, raw) = p::read_access(r)?;
                let n = canonical(raw, &mut path)?;
                visible(&path[..n])?;
                let real = flags & p::ACCESS_REAL != 0;
                self.search(fs, &caller, real, &path[..n])?;
                let (info, entry) = self.load(fs, &path[..n])?;
                if bits == 0 {
                    return Ok(());
                }
                perm::access(
                    caller.ids,
                    caller.groups(),
                    &entry.attr.perm(info.kind),
                    bits,
                    real,
                )
                .map_err(denied)
            }
            Method::Where => {
                let di = self.find(si, r.u32()?)?;
                r.finish()?;
                let d = self.descriptions[di];
                if d.kind == Kind::File && self.nodes[usize::from(d.object)].orphan {
                    return Err(p::code(p::NO_ENTRY));
                }
                let at = self.path_of(di)?;
                w.bytes(at.get())
            }
            // BIND, SESSION and VERIFY_SESSION carry a handle of the call and a vouching of the
            // process service, which the worker does (`Server::bind`, `Server::bind_new`).
            Method::Bind | Method::Session | Method::VerifySession => Err(p::code(p::INVALID)),
            Method::Clone => {
                let count = r.u32()?;
                let mut handles = [0; CLONE_MAX];
                let count = p::read_handles(r, count, &mut handles)?;
                if count == 0 {
                    return Err(p::code(p::INVALID));
                }
                let mask = self.mask_of(si, &handles[..count])?;
                if aux == 0 || self.sessions.iter().any(|s| s.used && s.label == aux) {
                    return Err(p::code(p::INVALID));
                }
                // A process tree has a few clones alive at once, so that one client cannot fill the
                // table of sessions for every other.
                let root = self.sessions[si].root;
                if self.tree_sessions(root) >= ROOT_CLONES {
                    return Err(p::code(p::TOO_MANY_OPEN));
                }
                let ci = self.free_session()?;
                self.birth_seq = self.birth_seq.wrapping_add(1).max(1);
                // A clone inherits neither the mark nor the identity: the child binds its own session.
                self.sessions[ci] = Session {
                    used: true,
                    label: aux,
                    held: mask,
                    binding: self.clone_binding(),
                    parent: owner,
                    birth: self.birth_seq,
                    root,
                };
                self.add_refs(mask);
                w.u32((ci as u32 + 1) | (u32::from(self.birth_seq) << 16))
            }
            Method::CloneMore => {
                let birth = r.u32()?;
                let count = r.u32()?;
                let mut handles = [0; CLONE_MAX];
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
                let root = self.sessions[si].root;
                let mine = self
                    .passes
                    .iter()
                    .filter(|p| p.used && p.owner == root)
                    .count();
                if mine >= PASSES_MAX {
                    return Err(p::code(p::TOO_MANY_OPEN));
                }
                let free = self
                    .passes
                    .iter()
                    .position(|p| !p.used)
                    .ok_or_else(|| p::code(p::TABLE_FULL))?;
                self.passes[free] = Pass {
                    used: true,
                    label: aux,
                    owner: root,
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
                let di = usize::from(self.passes[pi].description);
                // A session at its limit leaves the pass unspent, and the caller keeps it.
                self.may_hold(si, di)?;
                self.passes[pi].used = false;
                if self.sessions[si].held & (1 << di) != 0 {
                    // The session has it: the reference of the pass goes.
                    let _ = self.deref(fs, di);
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
    fn mask_of(&self, si: usize, handles: &[u32]) -> Res<u64> {
        let mut mask = 0u64;
        for &h in handles {
            mask |= 1 << self.find(si, h)?;
        }
        Ok(mask)
    }

    fn add_refs(&mut self, mask: u64) {
        for di in 0..DESCRIPTIONS {
            if mask & (1 << di) != 0 {
                self.descriptions[di].refs += 1;
            }
        }
    }

    /// The path a description is at: its file's current path, or its directory's.
    fn path_of(&self, di: usize) -> Res<PathBuf> {
        let d = self.descriptions[di];
        Ok(match d.kind {
            Kind::File => self.nodes[usize::from(d.object)].path,
            Kind::Directory => self.dirs[usize::from(d.object)],
        })
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
        // A directory read as a file is EISDIR; one opened with no access bits has no READ at all.
        if d.kind != Kind::File {
            return Err(if d.read {
                p::code(p::IS_DIRECTORY)
            } else {
                bad_handle()
            });
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

    /// The bytes a write by `caller` may add to the volume: the free blocks the caller may use
    /// (those above the reserve unless the caller is user 0), as bytes.
    fn room_bytes<D: Device>(&mut self, fs: &mut Fs<'_, D>, caller: &Caller) -> Res<u64> {
        let free = volume(fs.free_blocks())?;
        let usable = if caller.is_superuser() {
            free
        } else {
            free.saturating_sub(RESERVE_BLOCKS)
        };
        Ok(usable * BLOCK as u64)
    }

    /// WRITE and PWRITE (rule 13): `data` at `pos`, or at the end of the file when `append`, the
    /// end taken now. The write stops short at the file size limit of the caller (and `FILE_MAX`) or
    /// at the last free block the caller may use, and answers the count; a status comes only when no
    /// byte could be written. The place written and the count.
    fn write_at<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        di: usize,
        caller: &Caller,
        pos: u32,
        append: bool,
        data: &[u8],
    ) -> Res<(u32, usize)> {
        let d = self.descriptions[di];
        if d.kind != Kind::File || !d.write {
            return Err(bad_handle());
        }
        let ni = usize::from(d.object);
        let size = self.size_of(fs, ni)?;
        let pos = if append {
            u32::try_from(size)
                .ok()
                .filter(|&s| s <= i32::MAX as u32)
                .ok_or_else(|| p::code(p::TOO_BIG))?
        } else {
            pos
        };
        let start = u64::from(pos);
        let limit = caller.fsize_limit.min(p::FILE_MAX);
        let mut allowed = data.len().min(limit.saturating_sub(start) as usize);
        if allowed == 0 && !data.is_empty() {
            return Err(p::code(if caller.fsize_limit <= p::FILE_MAX {
                p::FILE_SIZE_LIMIT
            } else {
                p::TOO_BIG
            }));
        }
        // The blocks the write adds: the part past the end of the file, up to the room.
        let room = self.room_bytes(fs, caller)?;
        // Over the end of the file the gap between the end and `pos` is zeros that take blocks too.
        let fits = if start < size {
            (size - start).saturating_add(room)
        } else {
            room.saturating_sub(start - size)
        };
        if (allowed as u64) > fits {
            allowed = fits as usize;
            if allowed == 0 && !data.is_empty() {
                return Err(p::code(p::NO_SPACE));
            }
        }
        let file = self.place(fs, ni, pos)?;
        self.nodes[ni].at = None;
        let n = volume(fs.write(file, &data[..allowed]))?;
        self.nodes[ni].at = Some(pos + n as u32);
        if n > 0 {
            self.nodes[ni].wrote = true;
            self.nodes[ni].wrote_at = self.now;
            if d.sync {
                self.sync_node(fs, ni)?;
            }
        }
        Ok((pos, n))
    }

    /// The file is synced and its attribute written (the time of the writes, the set-ID bits
    /// cleared): what FSYNC and a description with SYNC make durable.
    fn sync_node<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize) -> Res<()> {
        let n = &self.nodes[ni];
        if n.broken {
            return Err(p::code(p::IO));
        }
        volume(fs.sync(File(n.slot)))?;
        self.write_times(fs, ni)
    }

    /// What the attribute of the file of node `ni` will say once its pending writes are folded in:
    /// the time of the last write as `mtime` and `ctime`, the set-ID bits cleared (see `write_times`).
    fn overlay_pending(&self, ni: usize, attr: &mut Attr) {
        let n = &self.nodes[ni];
        if n.wrote {
            attr.mtime = n.wrote_at;
            attr.ctime = n.wrote_at;
            attr.mode = perm::mode_after_write(attr.mode);
        }
    }

    /// Before a change of the attribute of the file at `path` (CHMOD, CHOWN, UTIMENS and their
    /// variants by description): the writes still pending on its open node are folded into the
    /// record with one commit and the mark is cleared, so that the last close does not write the time
    /// of the writes over a time or a mode the caller just set.
    fn fold_pending<D: Device>(&mut self, fs: &mut Fs<'_, D>, path: &[u8]) -> Res<()> {
        match self.node_at(path) {
            Some(ni) if self.nodes[ni].wrote => self.write_times(fs, ni),
            _ => Ok(()),
        }
    }

    /// The attribute of the file of node `ni` takes the time of its writes (`mtime`, `ctime`) and
    /// loses its set-ID bits (rule 10 and 7). CORRUPT for a record of a format this service does not
    /// know: it is never rewritten.
    fn write_times<D: Device>(&mut self, fs: &mut Fs<'_, D>, ni: usize) -> Res<()> {
        let n = self.nodes[ni];
        if !n.wrote {
            return Ok(());
        }
        let entry = entry_of(fs, n.path.get(), Kind::File)?;
        if entry.standing == Standing::Foreign {
            return Err(p::code(p::CORRUPT));
        }
        let mut attr = entry.attr;
        attr.mtime = n.wrote_at;
        attr.ctime = n.wrote_at;
        attr.mode = perm::mode_after_write(attr.mode);
        volume(fs.setattr(n.path.get(), ATTR_TYPE, &attr.to_bytes()))?;
        self.nodes[ni].wrote = false;
        Ok(())
    }

    // ---- The attribute of an entry, the search of a path, and what a directory holds ----

    /// The kind and size of the entry at `path`, and its record.
    fn load<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        path: &[u8],
    ) -> Res<(crate::fs::Info, Record)> {
        let info = volume(fs.stat(path))?;
        let entry = entry_of(fs, path, info.kind)?;
        Ok((info, entry))
    }

    /// The permission attributes of the directory at `path`, from the memory of the server or the
    /// volume. NO_ENTRY when it is not there, NOT_DIRECTORY when it is a file.
    fn dir_perm<D: Device>(&mut self, fs: &mut Fs<'_, D>, path: &[u8]) -> Res<perm::Attr> {
        if let Some(c) = self.cache.iter().find(|c| c.used && c.path.get() == path) {
            return Ok(c.attr);
        }
        let info = volume(fs.stat(path))?;
        if info.kind != Kind::Directory {
            return Err(p::code(p::NOT_DIRECTORY));
        }
        let entry = entry_of(fs, path, Kind::Directory)?;
        let attr = entry.attr.perm(Kind::Directory);
        let hand = self.cache_hand;
        self.cache_hand = (hand + 1) % DIR_CACHE;
        self.cache[hand].used = true;
        self.cache[hand].path.set(path);
        self.cache[hand].attr = attr;
        Ok(attr)
    }

    /// Search permission on every directory of `path` but its last component (rule 3), with the real
    /// or the effective identifiers.
    fn search<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        real: bool,
        path: &[u8],
    ) -> Res<()> {
        let id = caller.identity(real);
        for (i, &b) in path.iter().enumerate() {
            if b != b'/' || path.len() == 1 {
                continue;
            }
            let dir = if i == 0 { &path[..1] } else { &path[..i] };
            let attr = self.dir_perm(fs, dir)?;
            if !perm::permits(id, &attr, perm::EXEC) {
                return Err(p::code(p::ACCESS));
            }
        }
        Ok(())
    }

    /// What the server remembers of the directories at `path` or under it is dropped: their
    /// attributes may have changed, or the names under them moved.
    fn forget(&mut self, path: &[u8]) {
        for c in &mut self.cache {
            if c.used && within(c.path.get(), path) {
                c.used = false;
            }
        }
        for c in &mut self.counts {
            if c.used && within(c.path.get(), path) {
                c.used = false;
            }
        }
    }

    /// The entries of the directory at `dir`, from the memory of the server or by one scan of the
    /// directory. TABLE_FULL when every directory place of the volume is held and the scan cannot be
    /// made.
    fn dir_entries<D: Device>(&mut self, fs: &mut Fs<'_, D>, dir: &[u8]) -> Res<usize> {
        if let Some(c) = self.counts.iter().find(|c| c.used && c.path.get() == dir) {
            return Ok(c.entries);
        }
        let slot = match fs.opendir(dir) {
            Ok(slot) => slot,
            // Every directory place of the volume is held by a description: the count cannot be
            // made, and a create is not let through unchecked.
            Err(Error::NoMemory) => return Err(p::code(p::TABLE_FULL)),
            Err(e) => return Err(status_of(e)),
        };
        let mut n = 0;
        loop {
            match fs.readdir(slot) {
                Ok(Some(e)) => {
                    let name = e.name();
                    if name != b"." && name != b".." && !(dir == b"/" && name == &ORPHANS[1..]) {
                        n += 1;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = fs.closedir(slot);
                    return Err(status_of(e));
                }
            }
        }
        volume(fs.closedir(slot))?;
        let hand = self.counts_hand;
        self.counts_hand = (hand + 1) % COUNT_CACHE;
        self.counts[hand].used = true;
        self.counts[hand].path.set(dir);
        self.counts[hand].entries = n;
        Ok(n)
    }

    /// A name is about to be added to `dir`: NO_SPACE when it holds `DIR_ENTRIES_MAX` entries.
    fn room_in_dir<D: Device>(&mut self, fs: &mut Fs<'_, D>, dir: &[u8]) -> Res<()> {
        if self.dir_entries(fs, dir)? >= DIR_ENTRIES_MAX {
            Err(p::code(p::NO_SPACE))
        } else {
            Ok(())
        }
    }

    /// The remembered count of `dir` follows a name added (`+1`) or removed (`-1`).
    fn count_add(&mut self, dir: &[u8], delta: isize) {
        if let Some(c) = self
            .counts
            .iter_mut()
            .find(|c| c.used && c.path.get() == dir)
        {
            c.entries = (c.entries as isize + delta).max(0) as usize;
        }
    }

    /// The reserve (rule 14): a caller other than user 0 gets NO_SPACE with fewer than
    /// `RESERVE_BLOCKS` free blocks, for a create, a rename and a change of attributes: each may
    /// split or compact a pair of metadata blocks, which takes blocks the superuser needs to remove
    /// what fills the volume.
    fn reserve_allows<D: Device>(&mut self, fs: &mut Fs<'_, D>, caller: &Caller) -> Res<()> {
        if caller.is_superuser() || volume(fs.free_blocks())? >= RESERVE_BLOCKS {
            Ok(())
        } else {
            Err(p::code(p::NO_SPACE))
        }
    }

    /// The directory at `path` has its `mtime` and `ctime` set to now (rule 10): a name was added,
    /// removed or renamed in it. A record this service cannot rewrite is left as it is.
    fn touch<D: Device>(&mut self, fs: &mut Fs<'_, D>, path: &[u8]) {
        if let Ok(entry) = entry_of(fs, path, Kind::Directory)
            && entry.standing != Standing::Foreign
        {
            let mut attr = entry.attr;
            attr.mtime = self.now;
            attr.ctime = self.now;
            let _ = fs.setattr(path, ATTR_TYPE, &attr.to_bytes());
        }
    }

    /// The next file number: from the block of numbers reserved in the counter at the root, which is
    /// raised by one block with one commit when it is used up.
    fn next_ino<D: Device>(&mut self, fs: &mut Fs<'_, D>) -> Res<u64> {
        if self.ino_next >= self.ino_end {
            let mut old = [0u8; 8];
            let last = match fs.getattr(b"/", ATTR_COUNTER_TYPE, &mut old) {
                Ok(8) => u64::from_le_bytes(old),
                Ok(_) | Err(Error::NoAttr) => 2,
                Err(e) => return Err(status_of(e)),
            }
            .max(2);
            let end = last + INO_BLOCK;
            volume(fs.setattr(b"/", ATTR_COUNTER_TYPE, &end.to_le_bytes()))?;
            self.ino_next = last;
            self.ino_end = end;
        }
        let ino = self.ino_next;
        self.ino_next += 1;
        Ok(ino)
    }

    /// The record of a new entry made by `caller` in `parent` (rule 5): the owner and the group by
    /// the rules of `posix-perm`, the mode as it came (the layer applied the umask), a new number,
    /// every time now.
    fn new_record<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        parent: &perm::Attr,
        kind: Kind,
        mode: u32,
    ) -> Res<Attr> {
        let pkind = match kind {
            Kind::File => perm::Kind::File,
            Kind::Directory => perm::Kind::Directory,
        };
        let made = perm::creation(caller.identity(false), parent, pkind, mode, 0);
        let ino = self.next_ino(fs)?;
        Ok(Attr {
            uid: made.uid,
            gid: made.gid,
            mode: made.mode,
            ino,
            atime: self.now,
            mtime: self.now,
            ctime: self.now,
        })
    }

    fn do_mkdir<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        mode: u32,
        path: &[u8],
    ) -> Res<()> {
        if path == b"/" {
            return Err(p::code(p::EXISTS));
        }
        self.search(fs, caller, false, path)?;
        let (parent, _) = split(path);
        let parent_attr = self.dir_perm(fs, parent)?;
        perm::place_allowed(caller.identity(false), &parent_attr, None).map_err(denied)?;
        if fs.stat(path).is_ok() {
            return Err(p::code(p::EXISTS));
        }
        self.room_in_dir(fs, parent)?;
        self.reserve_allows(fs, caller)?;
        let record = self.new_record(fs, caller, &parent_attr, Kind::Directory, mode)?;
        volume(fs.mkdir(path))?;
        // The record is written in the same job as the name; a cut between the two commits leaves
        // an entry with no record, which reads as the closed default.
        if let Err(e) = fs.setattr(path, ATTR_TYPE, &record.to_bytes()) {
            let _ = fs.remove(path);
            return Err(status_of(e));
        }
        self.count_add(parent, 1);
        self.touch(fs, parent);
        Ok(())
    }

    fn do_remove<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        rmdir: bool,
        path: &[u8],
    ) -> Res<()> {
        if path == b"/" {
            return Err(p::code(p::BUSY));
        }
        self.search(fs, caller, false, path)?;
        let (parent, _) = split(path);
        let parent_attr = self.dir_perm(fs, parent)?;
        let (info, entry) = self.load(fs, path)?;
        perm::remove_allowed(
            caller.identity(false),
            &parent_attr,
            &entry.attr.perm(info.kind),
        )
        .map_err(denied)?;
        match (rmdir, info.kind) {
            (false, Kind::Directory) => return Err(p::code(p::IS_DIRECTORY)),
            (true, Kind::File) => return Err(p::code(p::NOT_DIRECTORY)),
            _ => {}
        }
        if info.kind == Kind::Directory {
            if self.dir_in_use(path) {
                return Err(p::code(p::BUSY));
            }
            volume(fs.remove(path))?;
            // The two blocks of its pair come back at the next walk.
            fs.note_freed_blocks(2);
            self.forget(path);
        } else {
            match self.node_at(path) {
                // Open: the descriptions keep the file, which leaves the tree; its blocks are
                // counted when the last description closes (`node_unref`).
                Some(ni) => self.orphan(fs, ni, None)?,
                None => {
                    volume(fs.remove(path))?;
                    fs.note_freed_file(u64::from(info.size));
                }
            }
        }
        self.count_add(parent, -1);
        self.touch(fs, parent);
        Ok(())
    }

    fn do_rename<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        from: &[u8],
        to: &[u8],
    ) -> Res<()> {
        if from == b"/" || to == b"/" {
            return Err(p::code(p::INVALID));
        }
        visible(from)?;
        visible(to)?;
        self.search(fs, caller, false, from)?;
        self.search(fs, caller, false, to)?;
        let (from_parent, _) = split(from);
        let (to_parent, _) = split(to);
        let from_attr = self.dir_perm(fs, from_parent)?;
        let to_attr = self.dir_perm(fs, to_parent)?;
        let (source, source_entry) = self.load(fs, from)?;
        // A directory into its own subtree is INVALID; a file has no subtree (a path through it
        // already failed the search with NOT_DIRECTORY).
        if source.kind == Kind::Directory && within(to, from) && to != from {
            return Err(p::code(p::INVALID));
        }
        let replaced = fs.stat(to);
        let target_entry = match replaced {
            Ok(target) if target.kind != source.kind => {
                return Err(p::code(match target.kind {
                    Kind::Directory => p::IS_DIRECTORY,
                    Kind::File => p::NOT_DIRECTORY,
                }));
            }
            Ok(target) => Some(entry_of(fs, to, target.kind)?),
            Err(Error::NoEntry) => None,
            Err(error) => return Err(status_of(error)),
        };
        perm::rename_allowed(
            caller.identity(false),
            &from_attr,
            &source_entry.attr.perm(source.kind),
            &to_attr,
            target_entry
                .as_ref()
                .map(|e| e.attr.perm(source.kind))
                .as_ref(),
            from_parent == to_parent,
        )
        .map_err(denied)?;
        // A rename to itself succeeds and does nothing (XSH `rename()`): no count moves, no time.
        if from == to {
            return Ok(());
        }
        // A rename may split a directory's pair of blocks: below the reserve it is the superuser's.
        self.reserve_allows(fs, caller)?;
        // A name added to another directory counts toward its cap.
        if from_parent != to_parent && target_entry.is_none() {
            self.room_in_dir(fs, to_parent)?;
        }
        if source.kind == Kind::Directory {
            if self.dir_in_use(from) || self.dir_in_use(to) {
                return Err(p::code(p::BUSY));
            }
            volume(fs.rename(from, to))?;
            self.forget(from);
            self.forget(to);
        } else {
            if from == to {
                return Ok(());
            }
            // A file that the rename replaces and that is open goes under the orphans first,
            // marked with its home name; if the second commit fails it goes back.
            let target = self.node_at(to);
            if let Some(t) = target {
                self.orphan(fs, t, Some(to))?;
            }
            #[cfg(test)]
            let refused = self.fail_second;
            #[cfg(not(test))]
            let refused = false;
            let moved = match self.node_at(from) {
                _ if refused => Err(p::code(p::NO_SPACE)),
                Some(ni) => self.move_node(fs, ni, to, None),
                None => volume(fs.rename(from, to)),
            };
            // A file the rename replaced and that nobody had open gave its blocks back.
            if let (Ok(()), None, Ok(old)) = (&moved, target, replaced) {
                fs.note_freed_file(u64::from(old.size));
            }
            if let Some(t) = target {
                let at = self.nodes[t].path;
                match &moved {
                    Ok(()) => {
                        let _ = fs.removeattr(at.get(), ATTR_HOME);
                    }
                    Err(_) => {
                        let _ = self.move_node(fs, t, to, None);
                        let _ = fs.removeattr(to, ATTR_HOME);
                    }
                }
            }
            moved?;
        }
        if from_parent != to_parent {
            self.count_add(from_parent, -1);
            if target_entry.is_none() {
                self.count_add(to_parent, 1);
            }
        } else if target_entry.is_some() {
            self.count_add(to_parent, -1);
        }
        if target_entry.is_some() && from_parent != to_parent {
            // The replaced name is gone from the destination and the source's name came: no change.
        }
        self.touch(fs, from_parent);
        if to_parent != from_parent {
            self.touch(fs, to_parent);
        }
        Ok(())
    }

    /// CHMOD and FCHMOD (rule 7).
    fn change_mode<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        path: &[u8],
        mode: u32,
    ) -> Res<()> {
        self.fold_pending(fs, path)?;
        let (info, entry) = self.load(fs, path)?;
        let new = perm::chmod_result(caller.identity(false), &entry.attr.perm(info.kind), mode)
            .map_err(denied)?;
        self.reserve_allows(fs, caller)?;
        self.write_changed(fs, path, info.kind, entry, |a, now| {
            a.mode = new;
            a.ctime = now;
        })
    }

    /// CHOWN and FCHOWN (rule 7): `UID_KEEP` leaves a number as it is.
    fn change_owner<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        path: &[u8],
        uid: u32,
        gid: u32,
    ) -> Res<()> {
        self.fold_pending(fs, path)?;
        let (info, entry) = self.load(fs, path)?;
        let keep = |v: u32| (v != p::UID_KEEP).then_some(v);
        let owned = perm::chown_result(
            caller.identity(false),
            &entry.attr.perm(info.kind),
            keep(uid),
            keep(gid),
        )
        .map_err(denied)?;
        self.reserve_allows(fs, caller)?;
        self.write_changed(fs, path, info.kind, entry, |a, now| {
            a.mode = owned.mode;
            a.uid = owned.uid;
            a.gid = owned.gid;
            a.ctime = now;
        })
    }

    /// UTIMENS and FUTIMENS (rule 8).
    fn change_times<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        caller: &Caller,
        path: &[u8],
        atime: p::TimeSpec,
        mtime: p::TimeSpec,
    ) -> Res<()> {
        self.fold_pending(fs, path)?;
        let (info, entry) = self.load(fs, path)?;
        let request = match (atime, mtime) {
            (p::TimeSpec::Omit, p::TimeSpec::Omit) => TimesRequest::Omit,
            (p::TimeSpec::Now, p::TimeSpec::Now) => TimesRequest::Now,
            _ => TimesRequest::Explicit,
        };
        perm::utimens_allowed(caller.identity(false), &entry.attr.perm(info.kind), request)
            .map_err(denied)?;
        if request == TimesRequest::Omit {
            return Ok(());
        }
        self.reserve_allows(fs, caller)?;
        let pick = |t: p::TimeSpec, old: i64, now: i64| match t {
            p::TimeSpec::Now => now,
            p::TimeSpec::Omit => old,
            p::TimeSpec::At(t) => t,
        };
        self.write_changed(fs, path, info.kind, entry, |a, now| {
            a.atime = pick(atime, a.atime, now);
            a.mtime = pick(mtime, a.mtime, now);
            a.ctime = now;
        })
    }

    /// Writes the record of the entry at `path` after `change` (one commit). A record of a format
    /// this service does not know is never rewritten: CORRUPT. The memory of the directories is
    /// dropped for a directory, whose permissions may have changed.
    fn write_changed<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        path: &[u8],
        kind: Kind,
        entry: Record,
        change: impl FnOnce(&mut Attr, i64),
    ) -> Res<()> {
        if entry.standing == Standing::Foreign {
            return Err(p::code(p::CORRUPT));
        }
        let mut attr = entry.attr;
        change(&mut attr, self.now);
        volume(fs.setattr(path, ATTR_TYPE, &attr.to_bytes()))?;
        if kind == Kind::Directory {
            self.forget(path);
        }
        Ok(())
    }

    /// READDIR: the entries of the next batch (rule of the listing): `ino`, `kind` and the name of
    /// as many as the reply holds, `.` and `..` first. An entry that did not fit waits in the
    /// description's slot for the next call.
    fn do_readdir<D: Device>(&mut self, fs: &mut Fs<'_, D>, di: usize, w: &mut Writer) -> Res<()> {
        let d = self.descriptions[di];
        if d.kind != Kind::Directory || !d.read {
            return Err(bad_handle());
        }
        let slot = usize::from(d.object);
        let dir = self.dirs[slot];
        let root = dir.get() == b"/";
        let mut batch = p::DirBatch::new();
        let mut more = false;
        loop {
            let next = match self.pending[slot].take() {
                Some(pending) => pending,
                None => match volume(fs.readdir(Dir(d.object)))? {
                    None => break,
                    Some(entry) if root && entry.name() == &ORPHANS[1..] => continue,
                    Some(entry) => {
                        let ino = entry_ino(fs, dir.get(), entry.name(), entry.kind)?;
                        let mut pending = Pending {
                            ino,
                            kind: entry.kind,
                            name: [0; crate::NAME_MAX],
                            len: entry.name().len(),
                        };
                        pending.name[..pending.len].copy_from_slice(entry.name());
                        pending
                    }
                },
            };
            if !batch.push(next.ino, kind_word(next.kind), &next.name[..next.len]) {
                self.pending[slot] = Some(next);
                more = true;
                break;
            }
        }
        batch.write(more, w)
    }

    fn do_open<D: Device>(
        &mut self,
        fs: &mut Fs<'_, D>,
        si: usize,
        caller: &Caller,
        (flags, mode): (u32, u32),
        path: &[u8],
        w: &mut Writer,
    ) -> Res<()> {
        if flags & !p::FLAGS_ALL != 0 {
            return Err(p::code(p::INVALID));
        }
        let tree = self.root_held(self.sessions[si].root);
        if self.sessions[si].held.count_ones() as usize >= HELD_MAX
            || tree.count_ones() as usize >= ROOT_DESCRIPTIONS
        {
            return Err(p::code(p::TOO_MANY_OPEN));
        }
        let di = self
            .descriptions
            .iter()
            .position(|d| !d.used)
            .ok_or_else(|| p::code(p::TABLE_FULL))?;
        // Search on every directory of the path first (rule 3).
        self.search(fs, caller, false, path)?;
        let id = caller.identity(false);
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
                let (info, entry) = self.load(fs, path)?;
                if info.kind != Kind::Directory {
                    return Err(p::code(p::NOT_DIRECTORY));
                }
                // With no access bits (exactly DIRECTORY) the open asks search on the directory
                // itself; with READ it asks read.
                let wanted = if flags & p::READ != 0 {
                    perm::READ
                } else {
                    perm::EXEC
                };
                if !perm::permits(id, &entry.attr.perm(Kind::Directory), wanted) {
                    return Err(p::code(p::ACCESS));
                }
                let slot = match fs.opendir(path) {
                    Ok(dir) => dir.0,
                    Err(Error::NoMemory) => return Err(p::code(p::TABLE_FULL)),
                    Err(e) => return Err(status_of(e)),
                };
                self.dirs[usize::from(slot)].set(path);
                self.pending[usize::from(slot)] = None;
                description.object = slot;
                description.read = flags & p::READ != 0;
            }
            Kind::File => {
                description.read = flags & p::READ != 0;
                description.write = flags & p::WRITE != 0;
                description.append = flags & p::APPEND != 0;
                description.sync = flags & p::SYNC != 0;
                if !description.read && !description.write {
                    return Err(p::code(p::INVALID));
                }
                if flags & p::TRUNCATE != 0 && !description.write {
                    return Err(p::code(p::INVALID));
                }
                let existing = match fs.stat(path) {
                    // O_CREAT with O_EXCL names an entry that exists: EEXIST, whatever it is.
                    Ok(_) if flags & p::CREATE != 0 && flags & p::EXCLUSIVE != 0 => {
                        return Err(p::code(p::EXISTS));
                    }
                    Ok(info) if info.kind == Kind::Directory => {
                        return Err(p::code(p::IS_DIRECTORY));
                    }
                    Ok(info) => Some(info),
                    Err(Error::NoEntry) => None,
                    Err(e) => return Err(status_of(e)),
                };
                let mut created = None;
                if existing.is_some() {
                    if flags & p::CREATE != 0 && flags & p::EXCLUSIVE != 0 {
                        return Err(p::code(p::EXISTS));
                    }
                    let entry = entry_of(fs, path, Kind::File)?;
                    let mut wanted = 0;
                    if flags & p::READ != 0 {
                        wanted |= perm::READ;
                    }
                    if flags & (p::WRITE | p::TRUNCATE) != 0 {
                        wanted |= perm::WRITE;
                    }
                    if !perm::permits(id, &entry.attr.perm(Kind::File), wanted) {
                        return Err(p::code(p::ACCESS));
                    }
                } else {
                    if flags & p::CREATE == 0 {
                        return Err(p::code(p::NO_ENTRY));
                    }
                    // A new file needs write and search on its parent, room in it, and the reserve.
                    let (parent, _) = split(path);
                    let parent_attr = self.dir_perm(fs, parent)?;
                    perm::place_allowed(id, &parent_attr, None).map_err(denied)?;
                    self.room_in_dir(fs, parent)?;
                    self.reserve_allows(fs, caller)?;
                    created = Some((
                        parent_attr,
                        self.new_record(fs, caller, &parent_attr, Kind::File, mode)?,
                    ));
                }
                let (ni, fresh) = match self.node_at(path) {
                    Some(ni) => (ni, false),
                    None => {
                        let ni = self
                            .nodes
                            .iter()
                            .position(|n| !n.used)
                            .ok_or_else(|| p::code(p::TABLE_FULL))?;
                        let mut open = Open::READ_WRITE;
                        if created.is_some() {
                            open = open.with(Open::CREATE).with(Open::EXCLUSIVE);
                        }
                        let file = volume(fs.open(path, open))?;
                        if let Some((_, record)) = &created
                            && let Err(e) = fs.setattr(path, ATTR_TYPE, &record.to_bytes())
                        {
                            // The record goes in the same job as the name: without it the entry
                            // would be the closed default, so the name goes again.
                            let _ = fs.close(file);
                            let _ = fs.remove(path);
                            return Err(status_of(e));
                        }
                        // The name exists: the count and the directory's time follow now, whatever
                        // comes after.
                        if created.is_some() {
                            let (parent, _) = split(path);
                            self.count_add(parent, 1);
                            self.touch(fs, parent);
                        }
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
                    self.nodes[ni].wrote = true;
                    self.nodes[ni].wrote_at = self.now;
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

    // ---- What the service's worker does for a session ----

    /// Binds the session of `label` to the identity the process service vouched for (BIND, after
    /// the worker asked it): INVALID for a session that is still bound. A session of a native client is never bound this way.
    pub fn bind(&mut self, label: u64, vouched: Vouched) -> Result<(), Status> {
        // A session the service has not seen is made (a client that connected and sent BIND first).
        let si = self.session(label)?;
        if !binding::may_bind(&self.sessions[si].binding) {
            return Err(p::code(p::INVALID));
        }
        self.sessions[si].binding = Binding::Bound(vouched);
        // The child has sent its first request: CLONE_MORE of the parent is over.
        self.sessions[si].birth = 0;
        Ok(())
    }

    /// Makes the session of SESSION: a new session with the label `label` that is bound from its
    /// birth (rule 15), counted under the root of the expenditure the vouching names. TABLE_FULL
    /// when no session is free; TOO_MANY_OPEN past `ROOT_CLONES` of that root.
    pub fn bind_new(&mut self, label: u64, vouched: Vouched) -> Result<(), Status> {
        if label == 0 || self.sessions.iter().any(|s| s.used && s.label == label) {
            return Err(p::code(p::INVALID));
        }
        let root = Root::Expense(vouched.root);
        if self.tree_sessions(root) >= ROOT_CLONES {
            return Err(p::code(p::TOO_MANY_OPEN));
        }
        let si = self.free_session()?;
        self.sessions[si] = Session {
            used: true,
            label,
            root,
            binding: Binding::Bound(vouched),
            ..Session::EMPTY
        };
        Ok(())
    }

    /// The binding of the session of `label`, for the worker's look at its generation before a job.
    pub fn binding_of(&self, label: u64) -> Option<Binding> {
        self.sessions
            .iter()
            .find(|s| s.used && s.label == label)
            .map(|s| s.binding)
    }

    /// Replaces the binding of the session of `label` (the answer of the second vouching, or a lapse).
    pub fn set_binding(&mut self, label: u64, binding: Binding) {
        if let Some(s) = self
            .sessions
            .iter_mut()
            .find(|s| s.used && s.label == label)
        {
            s.binding = binding;
        }
    }

    /// Whether `label` is a live session of the service (VERIFY_SESSION).
    pub fn is_live(&self, label: u64) -> bool {
        self.sessions.iter().any(|s| s.used && s.label == label)
    }

    /// The present moment the next requests see, in nanoseconds since the Unix epoch.
    pub fn set_now(&mut self, ns: i64) {
        self.now = ns;
    }
}

/// The path split into its directory and its last name; the root splits into itself and nothing.
fn split(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => (&path[..1.min(path.len())], &path[path.len().min(1)..]),
        Some(i) => (&path[..i], &path[i + 1..]),
    }
}

/// The status of a refusal of `posix-perm`.
fn denied(denial: Denial) -> Status {
    p::code(match denial {
        Denial::Access => p::ACCESS,
        Denial::Permission => p::PERMISSION,
    })
}

/// The record of the entry at `path` of `kind` as it stands on the volume (none: the closed default).
fn entry_of<D: Device>(fs: &mut Fs<'_, D>, path: &[u8], kind: Kind) -> Res<Record> {
    let mut buf = [0u8; 64];
    match fs.getattr(path, ATTR_TYPE, &mut buf) {
        Ok(n) => Ok(read_entry(kind, path, Some(&buf[..n.min(64)]))),
        Err(Error::NoAttr) => Ok(read_entry(kind, path, None)),
        Err(e) => Err(status_of(e)),
    }
}

/// The number of the entry `name` of the directory `dir` (`.` and `..` name the directory and its
/// parent): what STAT gives for that name. THE ONE PLACE READDIR READS AN ENTRY'S ATTRIBUTE: it looks
/// the entry up by its path (the cost grows with the entry's place in a large directory); a later
/// change of littlefs that reads the attribute of the entry the iterator stands at replaces this body.
fn entry_ino<D: Device>(fs: &mut Fs<'_, D>, dir: &[u8], name: &[u8], kind: Kind) -> Res<u64> {
    let mut path = [0u8; MAX_PATH + 1 + crate::NAME_MAX];
    let len = if name == b"." {
        path[..dir.len()].copy_from_slice(dir);
        dir.len()
    } else if name == b".." {
        let (parent, _) = split(dir);
        path[..parent.len()].copy_from_slice(parent);
        parent.len()
    } else {
        let mut n = dir.len();
        path[..n].copy_from_slice(dir);
        if dir != b"/" {
            path[n] = b'/';
            n += 1;
        }
        path[n..n + name.len()].copy_from_slice(name);
        n + name.len()
    };
    let kind = if name == b"." || name == b".." {
        Kind::Directory
    } else {
        kind
    };
    Ok(entry_of(fs, &path[..len], kind)?.attr.ino)
}

/// The stat record of an entry.
fn stat_record(kind: Kind, size: u32, attr: &Attr, nlink: u32) -> p::Stat {
    p::Stat {
        kind: kind_word(kind),
        mode: attr.mode,
        uid: attr.uid,
        gid: attr.gid,
        size: u64::from(size),
        ino: attr.ino,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
        nlink,
    }
}

/// The longest request the service takes, for its job table.
pub const REQUEST_MAX: usize = abi::MESSAGE_MAX;

const _: () = assert!(HEADER_LEN == 8);
