// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The names of the layered root: the methods 70 to 85 that the layer service (`services/layerd`)
//! speaks to the POSIX layer of a program (proto_fs 23). The layer service holds no bytes of files.
//! It decides names: which layer a path lands in, whether the caller may search the directories
//! of the path, and what the caller does next. A request carries the whole path (absolute, at most
//! `MAX_PATH` bytes, last in the body) and the reply is one of three answers.
//!
//! | Method | Through | Request after the header | Reply after the status |
//! |---|---|---|---|
//! | SESSION (70) | the root channel alone | none, and one handle: a copy of the caller's identity session | one handle: a new session (SEND, TRANSFER), bound |
//! | VERIFY_SESSION (71) | the root channel alone | none, and one handle (SEND, TRANSFER) | the offered session itself, or BAD_FD with no handle |
//! | BIND (72) | a session | none, and one handle: a copy of the caller's identity session | none |
//! | OPEN (73) | a session | `flags` u32, the path | the open answer (below) |
//! | STAT (74) | a session | `flags` u32 (`STAT_NO_FOLLOW`), the path | the `NodeInfo` of the name (116 bytes) |
//! | FSTAT (75) | a session | `handle` u32 | the `NodeInfo` of the directory |
//! | READ_DIR (76) | a session | `handle` u32 | `more` u32, `cursor` u64, then entries to the end of the message |
//! | REWIND (77) | a session | `handle` u32 | none |
//! | SEEK_DIR (78) | a session | `handle` u32, `cursor` u64 (one READ_DIR gave) | none |
//! | CLOSE (79) | a session | `handle` u32 | none |
//! | CLONE (80) | a session | `count` u32, that many handles | `birth` u32, and one handle: a new session for a child |
//! | CLONE_MORE (81) | a session | `birth` u32, `count` u32, the handles | none |
//! | ACCESS (82) | a session | `bits` u32, `flags` u32 (`ACCESS_REAL`), the path | none |
//! | READLINK (83) | a session | the path | the target, to the end of the message |
//! | CHANGE (84) | a session | the `Change` request (below) | none; COPYING with a ticket |
//! | WAIT (85) | a session | `ticket` u64 | none, when the copy that COPYING named is done |
//!
//! The root channel takes SESSION and VERIFY_SESSION and nothing else, a session never takes them
//! (the status `INVALID_ARGUMENT`), and the root of the service also takes the SESSION of
//! proto_layer (its number 18, which the numbers here never meet). A session made by SESSION is bound
//! to the process its identity copy names (the service asks the process service, Vouch, and reads
//! the generation of the process's record again before each request, as `proto_data` rule 1
//! says), and a binding that lapsed answers `AUTHENTICATING` until BIND.
//!
//! **Open answers.** OPEN answers one of three things. REDIRECT (the status `REDIRECT` and a
//! `Redirect` with the target `REDIRECT_RAM` and the absolute path): the name lies in the lower
//! set, the program opens it at the RAM file service with its own session, which checks the rights
//! of its identity against the lower attributes. OK with the form `OPEN_PASS` and one handle (a pass
//! of the description, TRANSFER alone) for a file of a layer of the user: the layer service opened it
//! at the data file service as the service's own client, after its own check of the rights, and the
//! program spends the pass with ADOPT in its own session with the data file service. OK with the form
//! `OPEN_DIRECTORY` and a handle (`handle` below) for a directory that has a name in a layer of the
//! user: its listing is merged, so the layer service keeps the description and READ_DIR serves it.
//! A directory that lies in the lower set alone is REDIRECT. A path whose first component is one
//! of `PASS_THROUGH` is REDIRECT with the target `REDIRECT_DATA` for `data` and `REDIRECT_RAM` for
//! the others. A write flag or a create flag is `READ_ONLY_FILESYSTEM` until the service
//! writes names.
//!
//! **Numbers.** `st_dev` of the whole root is one number, `DEVICE`, which the POSIX layer puts in
//! every stat of a path of the layered root (the service answers 0 in the `device` field). `st_ino`
//! of a name of the lower set is the number the RAM file service gives; that of a file of a layer
//! of the user is the number the data file service keeps, and a file the layer service creates gets
//! a number with `UPPER_INO_TAG` (bit 62) set: the numbers of the RAM file service have bits 62 and
//! 63 clear (a node's place plus one in the low half and its generation in the high half), and the
//! numbers the data file service makes from a path have bit 63 set.
//!
//! **Handles.** The handle of a description of the service is its place (bits 0 to 7), its
//! generation (8 to 15) and the epoch of the instance (16 to 31), as in `proto_data`: a handle of
//! an earlier instance answers `STALE`.
//!
//! **Listing.** READ_DIR serves a merged directory in stages: the names of the layers of the user
//! first, the `.wh.` marks and the opaque marker left out, then the entries of the lower directory
//! (at most `LOWER_PER_READDIR` in one reply) that no layer of the user hides or shadows; a
//! directory with the opaque marker has no second stage. `cursor` is the position after the entries
//! of the reply: its high half is the stage and its low half the position in the stage. SEEK_DIR
//! returns a description to a cursor a reply gave and REWIND to the start. A reply may have `more`
//! and no entry (the lower entries the layer hides took the request): the program asks again. An entry is `ino` u64,
//! `kind` u32 (the kinds of `NodeInfo`), `name_len` u32 (1 to `NAME_MAX`) and the name.
//!
//! **Changes.** CHANGE carries `op` u32 (`ChangeOp`), `a` u64, `b` u64, then the first path (two
//! bytes of length, low byte first, and the bytes) and the second path to the end of the message
//! (empty when the operation has none). The meaning of `a` and `b` by operation is in `ChangeOp`.
//! A service that does not write names answers every CHANGE with `READ_ONLY_FILESYSTEM`. A change
//! that has to copy a file up first answers `COPYING` and a ticket u64 (the reply body after the
//! status): the program sends WAIT with the ticket and, when it is answered, sends the same CHANGE
//! again; the file is the layer of the user's by then. A request that finds the copy of a file that
//! somebody else is making answers `COPYING` as well. WAIT is a deferred reply, its answer is
//! the end of the copy (status 0) or its failure.
//!
//! **Statuses.** Besides the codes of this crate (`NO_ENTRY`, `ACCESS_DENIED`, `NOT_DIRECTORY`,
//! `READ_ONLY_FILESYSTEM`, `BAD_FD`, `INVALID_ARGUMENT`, `NAME_TOO_LONG`, `LOOP`, `NO_SPACE`,
//! `TOO_MANY_FILES_IN_SYSTEM`), the service answers `COPYING`, `STALE` and, while it builds the
//! index of its names at the start, the code `STARTING` of proto_layer (1318): ask again.

use crate::{MAX_PATH, NodeInfo, Redirect};
use proto_wire::{Header, Reader, Status, Writer};

/// The first and the last number of the methods of the names, both given.
pub const NAMES_FIRST: u16 = 70;
pub const NAMES_LAST: u16 = 85;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameMethod {
    Session = 70,
    VerifySession = 71,
    Bind = 72,
    Open = 73,
    Stat = 74,
    Fstat = 75,
    ReadDir = 76,
    Rewind = 77,
    SeekDir = 78,
    Close = 79,
    Clone = 80,
    CloneMore = 81,
    Access = 82,
    Readlink = 83,
    Change = 84,
    Wait = 85,
}

impl NameMethod {
    pub const ALL: [NameMethod; 16] = [
        NameMethod::Session,
        NameMethod::VerifySession,
        NameMethod::Bind,
        NameMethod::Open,
        NameMethod::Stat,
        NameMethod::Fstat,
        NameMethod::ReadDir,
        NameMethod::Rewind,
        NameMethod::SeekDir,
        NameMethod::Close,
        NameMethod::Clone,
        NameMethod::CloneMore,
        NameMethod::Access,
        NameMethod::Readlink,
        NameMethod::Change,
        NameMethod::Wait,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<NameMethod> {
        NameMethod::ALL.into_iter().find(|m| m.number() == number)
    }

    /// The header of a request of this method, in the version of this crate.
    pub const fn header(self) -> Header {
        Header::new(self.number(), crate::VERSION)
    }
}

/// The numbers of the names, for a service's list of methods.
pub const NAMES: [u16; 16] = {
    let mut out = [0; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = NAMES_FIRST + i as u16;
        i += 1;
    }
    out
};

/// `st_dev` of every name of the layered root; the POSIX layer puts it in a stat (the service
/// answers 0): the bytes of "layr".
pub const DEVICE: u64 = 0x6c61_7972;
/// The bit of the number of a file the layer service creates (bit 63 is the data file service's
/// numbers of a path, and the RAM file service's numbers have both clear).
pub const UPPER_INO_TAG: u64 = 1 << 62;
/// The entries of the lower directory one READ_DIR serves at most.
pub const LOWER_PER_READDIR: usize = 8;
/// The names below the root that the layered root passes through to the services that own them:
/// the first is the data file service's (`REDIRECT_DATA`), the others lie in the RAM file service or
/// are the POSIX layer's own (`/proc`, `/dev`).
pub const PASS_THROUGH: [&[u8]; 5] = [b"data", b"proc", b"dev", b"tmp", b"run"];
/// The longest name of an entry.
pub const NAME_MAX: usize = 255;

/// Whether `path` is one of `PASS_THROUGH` or lies below one.
pub fn is_pass_through(path: &[u8]) -> bool {
    let first = path.strip_prefix(b"/").unwrap_or(path);
    let name = first.split(|&b| b == b'/').next().unwrap_or(&[]);
    PASS_THROUGH.contains(&name)
}

/// The places of the descriptions of the service: a handle holds the place in eight bits.
pub const PLACES_MAX: usize = 256;

/// The handle of the description at `place` with `generation`, in the instance `epoch`.
pub const fn handle(place: u8, generation: u8, epoch: u16) -> u32 {
    place as u32 | (generation as u32) << 8 | (epoch as u32) << 16
}

/// The place, the generation and the epoch of a handle.
pub const fn split_handle(handle: u32) -> (u8, u8, u16) {
    (handle as u8, (handle >> 8) as u8, (handle >> 16) as u16)
}

/// The flag of STAT: do not follow a link at the end of the path.
pub const STAT_NO_FOLLOW: u32 = 1;
/// The forms of an OK answer of OPEN.
pub const OPEN_PASS: u32 = 1;
pub const OPEN_DIRECTORY: u32 = 2;
/// The flags OPEN takes: the access mode and the flags of this crate.
const OPEN_MODE: u32 = 3;
const OPEN_FLAGS: u32 = OPEN_MODE
    | crate::DIRECTORY_ONLY
    | crate::CHANGES
    | crate::CREATE
    | crate::EXCLUSIVE
    | crate::TRUNCATE
    | crate::APPEND
    | crate::NO_FOLLOW;

/// Whether the flags of an OPEN write: an access for writing, a cut, or the legacy flag that stands
/// for a create, a cut and an append at once. An append with read access writes nothing, and a
/// create (`CREATE`) writes only when the name is not there: the service decides that one.
pub const fn open_writes(flags: u32) -> bool {
    flags & OPEN_MODE != crate::READ_ONLY || flags & (crate::CHANGES | crate::TRUNCATE) != 0
}

/// A path of a request: BAD_SIZE for one that is empty, relative, over `MAX_PATH` bytes or holds a
/// NUL.
pub fn check_path(path: &[u8]) -> Result<&[u8], Status> {
    if path.is_empty() || path.len() > MAX_PATH || path[0] != b'/' || path.contains(&0) {
        Err(Status::BadSize)
    } else {
        Ok(path)
    }
}

/// The request OPEN after its header.
pub fn write_open(flags: u32, path: &[u8], w: &mut Writer) -> Result<(), Status> {
    check_path(path)?;
    NameMethod::Open.header().write(w)?;
    w.u32(flags)?;
    w.bytes(path)
}

/// The flags and the path of an OPEN: BAD_SIZE for a path that is none, INVALID_ARGUMENT status
/// word for a flag the request does not take (access mode 3 or an unknown bit).
pub fn read_open<'a>(mut body: Reader<'a>) -> Result<(u32, &'a [u8]), Status> {
    let flags = body.u32()?;
    let path = check_path(body.bytes(body.left())?)?;
    if flags & !OPEN_FLAGS != 0 || flags & OPEN_MODE == OPEN_MODE {
        return Err(Status::from_code(crate::INVALID_ARGUMENT));
    }
    Ok((flags, path))
}

/// The request STAT after its header.
pub fn write_stat(flags: u32, path: &[u8], w: &mut Writer) -> Result<(), Status> {
    check_path(path)?;
    NameMethod::Stat.header().write(w)?;
    w.u32(flags)?;
    w.bytes(path)
}

/// The flags and the path of a STAT.
pub fn read_stat<'a>(mut body: Reader<'a>) -> Result<(u32, &'a [u8]), Status> {
    let flags = body.u32()?;
    let path = check_path(body.bytes(body.left())?)?;
    if flags & !STAT_NO_FOLLOW != 0 {
        return Err(Status::from_code(crate::INVALID_ARGUMENT));
    }
    Ok((flags, path))
}

/// The request ACCESS after its header.
pub fn write_access(bits: u32, flags: u32, path: &[u8], w: &mut Writer) -> Result<(), Status> {
    check_path(path)?;
    NameMethod::Access.header().write(w)?;
    w.u32(bits)?;
    w.u32(flags)?;
    w.bytes(path)
}

/// The bits, the flags and the path of an ACCESS (bits 0 to 7, flags 0 or 1).
pub fn read_access<'a>(mut body: Reader<'a>) -> Result<(u32, u32, &'a [u8]), Status> {
    let (bits, flags) = (body.u32()?, body.u32()?);
    let path = check_path(body.bytes(body.left())?)?;
    if bits > 7 || flags > 1 {
        return Err(Status::from_code(crate::INVALID_ARGUMENT));
    }
    Ok((bits, flags, path))
}

/// A request of one handle: FSTAT, READ_DIR, REWIND, CLOSE.
pub fn write_handle(method: NameMethod, handle: u32, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)?;
    w.u32(handle)
}

/// The handle of such a request.
pub fn read_handle(mut body: Reader<'_>) -> Result<u32, Status> {
    let handle = body.u32()?;
    body.finish()?;
    Ok(handle)
}

/// The request SEEK_DIR after its header.
pub fn write_seek_dir(handle: u32, cursor: u64, w: &mut Writer) -> Result<(), Status> {
    NameMethod::SeekDir.header().write(w)?;
    w.u32(handle)?;
    w.u64(cursor)
}

/// The handle and the cursor of a SEEK_DIR.
pub fn read_seek_dir(mut body: Reader<'_>) -> Result<(u32, u64), Status> {
    let value = (body.u32()?, body.u64()?);
    body.finish()?;
    Ok(value)
}

/// The request READLINK after its header.
pub fn write_readlink(path: &[u8], w: &mut Writer) -> Result<(), Status> {
    check_path(path)?;
    NameMethod::Readlink.header().write(w)?;
    w.bytes(path)
}

/// The path of a READLINK.
pub fn read_readlink<'a>(mut body: Reader<'a>) -> Result<&'a [u8], Status> {
    check_path(body.bytes(body.left())?)
}

/// The request WAIT after its header.
pub fn write_wait(ticket: u64, w: &mut Writer) -> Result<(), Status> {
    NameMethod::Wait.header().write(w)?;
    w.u64(ticket)
}

/// The ticket of a WAIT.
pub fn read_wait(mut body: Reader<'_>) -> Result<u64, Status> {
    let ticket = body.u64()?;
    body.finish()?;
    Ok(ticket)
}

/// The reply COPYING: the status and the ticket.
pub fn write_copying(ticket: u64, w: &mut Writer) -> Result<(), Status> {
    w.u32(crate::COPYING)?;
    w.u64(ticket)
}

/// The ticket of a reply whose status is COPYING; None for a reply of another status.
pub fn read_copying(bytes: &[u8]) -> Option<Result<u64, Status>> {
    let mut r = Reader::new(bytes);
    if r.u32().ok()? != crate::COPYING {
        return None;
    }
    Some(r.u64().and_then(|ticket| r.finish().map(|()| ticket)))
}

/// The answer of OPEN as the program reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenAnswer<'a> {
    /// The status REDIRECT: open the path at the service the target names.
    Redirect(Redirect<'a>),
    /// A pass of the description (the handle of the reply) to spend with ADOPT at the data file
    /// service.
    Pass,
    /// A directory description of the service.
    Directory { handle: u32 },
}

impl<'a> OpenAnswer<'a> {
    /// The reply: status OK (or REDIRECT), then the form and the handle.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        match self {
            OpenAnswer::Redirect(r) => r.write(w),
            OpenAnswer::Pass => {
                w.u32(0)?;
                w.u32(OPEN_PASS)?;
                w.u32(0)
            }
            OpenAnswer::Directory { handle } => {
                w.u32(0)?;
                w.u32(OPEN_DIRECTORY)?;
                w.u32(*handle)
            }
        }
    }

    /// A whole reply of OPEN: a status other than OK and REDIRECT comes back as the error. BAD_SIZE
    /// for a form that is none, a pass with a handle word or a directory with the handle 0.
    pub fn read(bytes: &'a [u8]) -> Result<OpenAnswer<'a>, Status> {
        if let Some(redirect) = Redirect::read_reply(bytes) {
            return redirect.map(OpenAnswer::Redirect);
        }
        let mut r = Reader::new(bytes);
        match Status::from_code(r.u32()?) {
            Status::Ok => {}
            status => return Err(status),
        }
        let (form, handle) = (r.u32()?, r.u32()?);
        r.finish()?;
        match (form, handle) {
            (OPEN_PASS, 0) => Ok(OpenAnswer::Pass),
            (OPEN_DIRECTORY, h) if h != 0 => Ok(OpenAnswer::Directory { handle: h }),
            _ => Err(Status::BadSize),
        }
    }
}

/// The reply of STAT and FSTAT: the status and the node information.
pub fn write_info(info: &NodeInfo, w: &mut Writer) -> Result<(), Status> {
    w.u32(0)?;
    info.write(w)
}

/// The `NodeInfo` of a reply of STAT or FSTAT.
pub fn read_info(bytes: &[u8]) -> Result<NodeInfo, Status> {
    let mut r = Reader::new(bytes);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let info = NodeInfo::read(&mut r)?;
    r.finish()?;
    Ok(info)
}

/// The bytes of an entry of READ_DIR before its name.
pub const ENTRY_HEAD: usize = 16;
/// The bytes of a reply of READ_DIR before its entries: the status, `more` and the cursor.
pub const DIR_HEAD: usize = 16;

/// One entry of a READ_DIR reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntry<'a> {
    pub ino: u64,
    pub kind: u32,
    pub name: &'a [u8],
}

/// Builds the reply of READ_DIR: the head is written by `begin` and the entries by `push`, which
/// says whether the entry fit.
pub struct DirReply {
    w: Writer,
}

impl DirReply {
    pub fn new() -> Result<DirReply, Status> {
        let mut w = Writer::new();
        w.u32(0)?;
        w.u32(0)?;
        w.u64(0)?;
        Ok(DirReply { w })
    }

    /// Adds an entry; BAD_SIZE for a name that is none, Err when the message is full (the entry is
    /// not added).
    pub fn push(&mut self, entry: &DirEntry<'_>) -> Result<(), Status> {
        if entry.name.is_empty() || entry.name.len() > NAME_MAX || !matches!(entry.kind, 1..=6) {
            return Err(Status::BadSize);
        }
        if self.w.as_bytes().len() + ENTRY_HEAD + entry.name.len() > abi::MESSAGE_MAX {
            return Err(Status::BadSize);
        }
        self.w.u64(entry.ino)?;
        self.w.u32(entry.kind)?;
        self.w.u32(entry.name.len() as u32)?;
        self.w.bytes(entry.name)
    }

    /// The reply with `more` and the `cursor` after its last entry.
    pub fn finish(self, more: bool, cursor: u64) -> Result<[u8; abi::MESSAGE_MAX], Status> {
        let mut bytes = [0u8; abi::MESSAGE_MAX];
        let src = self.w.as_bytes();
        bytes[..src.len()].copy_from_slice(src);
        bytes[4..8].copy_from_slice(&u32::from(more).to_le_bytes());
        bytes[8..16].copy_from_slice(&cursor.to_le_bytes());
        Ok(bytes)
    }

    pub fn len(&self) -> usize {
        self.w.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == DIR_HEAD
    }
}

/// The head of a READ_DIR reply read back: `more`, the cursor and the entries to walk. A reply may
/// have `more` and no entry (the entries of the lower set the layer hides took the request): the
/// program asks again.
pub fn read_dir_reply(bytes: &[u8]) -> Result<(bool, u64, DirEntries<'_>), Status> {
    let mut r = Reader::new(bytes);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let more = match r.u32()? {
        0 => false,
        1 => true,
        _ => return Err(Status::BadSize),
    };
    let cursor = r.u64()?;
    let rest = r.bytes(r.left())?;
    Ok((more, cursor, DirEntries { rest }))
}

/// The entries of a READ_DIR reply.
pub struct DirEntries<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for DirEntries<'a> {
    type Item = Result<DirEntry<'a>, Status>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let mut r = Reader::new(self.rest);
        let item = (|| {
            let (ino, kind, len) = (r.u64()?, r.u32()?, r.u32()? as usize);
            if len == 0 || len > NAME_MAX || !matches!(kind, 1..=6) {
                return Err(Status::BadSize);
            }
            let name = r.bytes(len)?;
            Ok((DirEntry { ino, kind, name }, r.left()))
        })();
        match item {
            Ok((entry, left)) => {
                self.rest = &self.rest[self.rest.len() - left..];
                Some(Ok(entry))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

/// The cursor of a stage and a position in it.
pub const fn cursor(stage: u32, position: u32) -> u64 {
    (stage as u64) << 32 | position as u64
}

/// The stage and the position of a cursor.
pub const fn split_cursor(cursor: u64) -> (u32, u32) {
    ((cursor >> 32) as u32, cursor as u32)
}

/// The descriptions CLONE and CLONE_MORE carry at most: a session holds `PER_SESSION` (16) of the
/// service, so a clone needs no more.
pub const CLONE_MAX: usize = 16;

/// The request CLONE after its header: the handles the new session holds, shared with the caller.
pub fn write_clone(handles: &[u32], w: &mut Writer) -> Result<(), Status> {
    if handles.len() > CLONE_MAX {
        return Err(Status::BadSize);
    }
    NameMethod::Clone.header().write(w)?;
    w.u32(handles.len() as u32)?;
    handles.iter().try_for_each(|&h| w.u32(h))
}

/// The request CLONE_MORE after its header: more handles for the session CLONE made (`birth`).
pub fn write_clone_more(birth: u32, handles: &[u32], w: &mut Writer) -> Result<(), Status> {
    if handles.len() > CLONE_MAX {
        return Err(Status::BadSize);
    }
    NameMethod::CloneMore.header().write(w)?;
    w.u32(birth)?;
    w.u32(handles.len() as u32)?;
    handles.iter().try_for_each(|&h| w.u32(h))
}

fn read_handles(mut body: Reader<'_>, out: &mut [u32; CLONE_MAX]) -> Result<usize, Status> {
    let count = body.u32()? as usize;
    if count > CLONE_MAX {
        return Err(Status::from_code(crate::INVALID_ARGUMENT));
    }
    for slot in out.iter_mut().take(count) {
        *slot = body.u32()?;
    }
    body.finish()?;
    Ok(count)
}

/// The handles of a CLONE: how many of `out` are set.
pub fn read_clone(body: Reader<'_>, out: &mut [u32; CLONE_MAX]) -> Result<usize, Status> {
    read_handles(body, out)
}

/// The birth number and the handles of a CLONE_MORE: how many of `out` are set.
pub fn read_clone_more(
    mut body: Reader<'_>,
    out: &mut [u32; CLONE_MAX],
) -> Result<(u32, usize), Status> {
    let birth = body.u32()?;
    Ok((birth, read_handles(body, out)?))
}

/// The reply of CLONE after its status: the birth number (the new session is the handle of the
/// reply).
pub fn write_clone_reply(birth: u32, w: &mut Writer) -> Result<(), Status> {
    w.u32(0)?;
    w.u32(birth)
}

/// The birth number of a whole reply of CLONE.
pub fn read_clone_reply(bytes: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(bytes);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let birth = r.u32()?;
    r.finish()?;
    Ok(birth)
}

/// The operations of CHANGE and the meaning of `a` and `b` for each. The first path is the name
/// the operation acts on, the second one the target of a RENAME or a LINK or the text of a SYMLINK
/// (empty for the other operations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ChangeOp {
    /// `a` the mode.
    Mkdir = 1,
    Unlink = 2,
    Rmdir = 3,
    Rename = 4,
    /// The first path is the new link, the second its text.
    Symlink = 5,
    /// The first path is the existing name, the second the new one.
    Link = 6,
    /// `a` the mode.
    Chmod = 7,
    /// `a` the user and `b` the group, `u32::MAX` for no change.
    Chown = 8,
    /// `a` and `b` the access and modification times, i64 nanoseconds as u64 (the values
    /// `UTIME_NOW` and `UTIME_OMIT` of proto_data).
    Utimens = 9,
    /// `a` the size.
    Truncate = 10,
}

impl ChangeOp {
    pub fn from_number(n: u32) -> Option<ChangeOp> {
        Some(match n {
            1 => ChangeOp::Mkdir,
            2 => ChangeOp::Unlink,
            3 => ChangeOp::Rmdir,
            4 => ChangeOp::Rename,
            5 => ChangeOp::Symlink,
            6 => ChangeOp::Link,
            7 => ChangeOp::Chmod,
            8 => ChangeOp::Chown,
            9 => ChangeOp::Utimens,
            10 => ChangeOp::Truncate,
            _ => return None,
        })
    }
}

/// A CHANGE request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change<'a> {
    pub op: ChangeOp,
    pub a: u64,
    pub b: u64,
    pub first: &'a [u8],
    pub second: &'a [u8],
}

impl Change<'_> {
    /// The request with its header. The second path may be empty; the first may not.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        check_path(self.first)?;
        if !self.second.is_empty() && self.op != ChangeOp::Symlink {
            check_path(self.second)?;
        }
        NameMethod::Change.header().write(w)?;
        w.u32(self.op as u32)?;
        w.u64(self.a)?;
        w.u64(self.b)?;
        w.u16(self.first.len() as u16)?;
        w.bytes(self.first)?;
        w.bytes(self.second)
    }

    /// BAD_SIZE for a body out of the layout, INVALID_ARGUMENT for an operation that is none.
    pub fn read(mut body: Reader<'_>) -> Result<Change<'_>, Status> {
        let op = body.u32()?;
        let (a, b) = (body.u64()?, body.u64()?);
        let len = usize::from(body.u16()?);
        let first = check_path(body.bytes(len)?)?;
        let second = body.bytes(body.left())?;
        let op = ChangeOp::from_number(op).ok_or(Status::from_code(crate::INVALID_ARGUMENT))?;
        Ok(Change {
            op,
            a,
            b,
            first,
            second,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{COPYING, REDIRECT_RAM};

    #[test]
    fn the_methods_are_70_to_85_each_once_and_clear_of_the_ram_service() {
        assert_eq!(NameMethod::ALL.len(), 16);
        for (i, m) in NameMethod::ALL.iter().enumerate() {
            assert_eq!(m.number(), 70 + i as u16);
            assert_eq!(NameMethod::from_number(m.number()), Some(*m));
            assert_eq!(NAMES[i], m.number());
            assert!(crate::Method::from_number(m.number()).is_none());
            assert!(!crate::METHODS.contains(&m.number()));
            assert_eq!(m.header().version, crate::VERSION);
        }
        assert_eq!(NameMethod::from_number(69), None);
        assert_eq!(NameMethod::from_number(86), None);
        assert_eq!((NAMES_FIRST, NAMES_LAST), (70, 85));
        // The SESSION of proto_layer (18) never meets the names.
        assert!(!NAMES.contains(&18));
    }

    #[test]
    fn the_constants_have_the_values_the_design_gives() {
        assert_eq!(crate::VERSION, 23);
        assert_eq!(UPPER_INO_TAG, 1 << 62);
        assert_eq!(LOWER_PER_READDIR, 8);
        assert_eq!(
            DEVICE,
            u64::from_be_bytes([0, 0, 0, 0, b'l', b'a', b'y', b'r'])
        );
        assert!(is_pass_through(b"/data/x"));
        assert!(is_pass_through(b"/tmp"));
        assert!(!is_pass_through(b"/etc/tmp"));
        assert!(!is_pass_through(b"/database"));
        assert_ne!(COPYING, crate::STALE);
        const { assert!(COPYING > crate::REDIRECT && crate::STALE > COPYING) };
    }

    #[test]
    fn a_handle_packs_its_place_its_generation_and_its_epoch() {
        for (p, g, e) in [(0u8, 0u8, 0u16), (255, 255, 65535), (7, 9, 3)] {
            assert_eq!(split_handle(handle(p, g, e)), (p, g, e));
        }
        assert_eq!(handle(1, 2, 3), 1 | 2 << 8 | 3 << 16);
    }

    #[test]
    fn open_round_trips_and_refuses_what_it_does_not_take() {
        let mut w = Writer::new();
        write_open(
            crate::READ_ONLY | crate::DIRECTORY_ONLY,
            b"/etc/motd",
            &mut w,
        )
        .unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Header::read(&mut r), Ok(NameMethod::Open.header()));
        assert_eq!(read_open(r), Ok((crate::DIRECTORY_ONLY, &b"/etc/motd"[..])));
        for bad in [3u32, 1 << 20, crate::READ_WRITE | 1 << 9] {
            let mut w = Writer::new();
            w.u32(bad).unwrap();
            w.bytes(b"/x").unwrap();
            assert_eq!(
                read_open(Reader::new(w.as_bytes())),
                Err(Status::from_code(crate::INVALID_ARGUMENT)),
                "{bad}"
            );
        }
        for path in [&b""[..], b"x", b"/a\0b"] {
            let mut w = Writer::new();
            w.u32(0).unwrap();
            w.bytes(path).unwrap();
            assert_eq!(read_open(Reader::new(w.as_bytes())), Err(Status::BadSize));
        }
        assert!(!open_writes(crate::READ_ONLY));
        assert!(!open_writes(
            crate::READ_ONLY | crate::DIRECTORY_ONLY | crate::NO_FOLLOW
        ));
        // A create of a name that may be there and an append with read access write nothing by
        // themselves: the service decides the first, the second is a read.
        assert!(!open_writes(crate::READ_ONLY | crate::CREATE));
        assert!(!open_writes(crate::READ_ONLY | crate::APPEND));
        for flags in [
            crate::WRITE_ONLY,
            crate::READ_WRITE,
            crate::TRUNCATE,
            crate::CHANGES,
        ] {
            assert!(open_writes(flags), "{flags}");
        }
    }

    #[test]
    fn the_three_open_answers_round_trip() {
        let redirect = Redirect {
            target: REDIRECT_RAM,
            index: 0,
            links: 0,
            path: b"/etc/passwd",
        };
        for answer in [
            OpenAnswer::Redirect(redirect),
            OpenAnswer::Pass,
            OpenAnswer::Directory {
                handle: 0x0001_0207,
            },
        ] {
            let mut w = Writer::new();
            answer.write(&mut w).unwrap();
            assert_eq!(OpenAnswer::read(w.as_bytes()), Ok(answer));
        }
        // A forged form, a pass with a handle word, a directory with none.
        for (form, handle) in [(0, 0), (3, 0), (OPEN_PASS, 5), (OPEN_DIRECTORY, 0)] {
            let mut w = Writer::new();
            w.u32(0).unwrap();
            w.u32(form).unwrap();
            w.u32(handle).unwrap();
            assert_eq!(OpenAnswer::read(w.as_bytes()), Err(Status::BadSize));
        }
        let mut w = Writer::new();
        w.u32(crate::READ_ONLY_FILESYSTEM).unwrap();
        assert_eq!(
            OpenAnswer::read(w.as_bytes()),
            Err(Status::from_code(crate::READ_ONLY_FILESYSTEM))
        );
    }

    #[test]
    fn a_listing_reply_round_trips_with_its_cursor() {
        let mut reply = DirReply::new().unwrap();
        assert!(reply.is_empty());
        let names: [&[u8]; 3] = [b"a", b"bb", b"ccc"];
        for (i, name) in names.iter().enumerate() {
            reply
                .push(&DirEntry {
                    ino: 10 + i as u64,
                    kind: 2,
                    name,
                })
                .unwrap();
        }
        let len = reply.len();
        let bytes = reply.finish(true, cursor(1, 5)).unwrap();
        let (more, cur, entries) = read_dir_reply(&bytes[..len]).unwrap();
        assert!(more);
        assert_eq!(split_cursor(cur), (1, 5));
        let got: Vec<_> = entries.map(|e| e.unwrap()).collect();
        assert_eq!(got.len(), 3);
        assert_eq!((got[2].ino, got[2].name), (12, &b"ccc"[..]));
        // `more` with no entry is a reply (ask again); an unknown value of `more` is none.
        let empty = DirReply::new().unwrap();
        let mut bytes = empty.finish(true, 0).unwrap();
        assert!(read_dir_reply(&bytes[..DIR_HEAD]).unwrap().0);
        bytes[4] = 2;
        assert!(read_dir_reply(&bytes[..DIR_HEAD]).is_err());
        let bytes = DirReply::new().unwrap().finish(false, 0).unwrap();
        let (more, _, mut entries) = read_dir_reply(&bytes[..DIR_HEAD]).unwrap();
        assert!(!more && entries.next().is_none());
    }

    #[test]
    fn a_full_message_refuses_the_entry_and_a_bad_entry_is_refused() {
        let mut reply = DirReply::new().unwrap();
        let name = [b'n'; NAME_MAX];
        let mut pushed = 0;
        while reply
            .push(&DirEntry {
                ino: 1,
                kind: 2,
                name: &name,
            })
            .is_ok()
        {
            pushed += 1;
        }
        assert!(pushed >= 3);
        assert!(reply.len() <= abi::MESSAGE_MAX);
        assert!(
            reply
                .push(&DirEntry {
                    ino: 1,
                    kind: 0,
                    name: b"x"
                })
                .is_err()
        );
        assert!(
            reply
                .push(&DirEntry {
                    ino: 1,
                    kind: 1,
                    name: b""
                })
                .is_err()
        );
    }

    #[test]
    fn a_change_round_trips_each_operation() {
        for n in 1..=10u32 {
            let op = ChangeOp::from_number(n).unwrap();
            let change = Change {
                op,
                a: 0o644,
                b: u64::MAX,
                first: b"/etc/x",
                second: if matches!(op, ChangeOp::Rename | ChangeOp::Link) {
                    b"/etc/y"
                } else {
                    b""
                },
            };
            let mut w = Writer::new();
            change.write(&mut w).unwrap();
            let mut r = Reader::new(w.as_bytes());
            assert_eq!(Header::read(&mut r), Ok(NameMethod::Change.header()));
            assert_eq!(Change::read(r), Ok(change));
        }
        assert_eq!(ChangeOp::from_number(0), None);
        assert_eq!(ChangeOp::from_number(11), None);
        let mut w = Writer::new();
        w.u32(11).unwrap();
        w.u64(0).unwrap();
        w.u64(0).unwrap();
        w.u16(2).unwrap();
        w.bytes(b"/x").unwrap();
        assert_eq!(
            Change::read(Reader::new(w.as_bytes())),
            Err(Status::from_code(crate::INVALID_ARGUMENT))
        );
    }

    #[test]
    fn copying_carries_its_ticket_and_wait_names_it() {
        let mut w = Writer::new();
        write_copying(0x1234_5678_9abc, &mut w).unwrap();
        assert_eq!(read_copying(w.as_bytes()), Some(Ok(0x1234_5678_9abc)));
        let mut w = Writer::new();
        w.u32(0).unwrap();
        assert_eq!(read_copying(w.as_bytes()), None);
        let mut w = Writer::new();
        w.u32(COPYING).unwrap();
        assert!(matches!(read_copying(w.as_bytes()), Some(Err(_))));
        let mut w = Writer::new();
        write_wait(77, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Header::read(&mut r), Ok(NameMethod::Wait.header()));
        assert_eq!(read_wait(r), Ok(77));
    }

    #[test]
    fn the_small_requests_round_trip() {
        let mut w = Writer::new();
        write_handle(NameMethod::ReadDir, 0x0102_0304, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_handle(r), Ok(0x0102_0304));
        let mut w = Writer::new();
        write_seek_dir(5, cursor(1, 2), &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_seek_dir(r), Ok((5, cursor(1, 2))));
        let mut w = Writer::new();
        write_access(4, 1, b"/etc", &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_access(r), Ok((4, 1, &b"/etc"[..])));
        let mut w = Writer::new();
        w.u32(8).unwrap();
        w.u32(0).unwrap();
        w.bytes(b"/x").unwrap();
        assert!(read_access(Reader::new(w.as_bytes())).is_err());
        let mut w = Writer::new();
        write_stat(STAT_NO_FOLLOW, b"/a", &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_stat(r), Ok((STAT_NO_FOLLOW, &b"/a"[..])));
        let mut w = Writer::new();
        write_readlink(b"/l", &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_readlink(r), Ok(&b"/l"[..]));
    }

    #[test]
    fn clone_and_clone_more_round_trip() {
        let mut w = Writer::new();
        write_clone(&[3, 5, 0x0102_0304], &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        let h = Header::read(&mut r).unwrap();
        assert_eq!(h.method, NameMethod::Clone.number());
        let mut out = [0; CLONE_MAX];
        assert_eq!(read_clone(r, &mut out), Ok(3));
        assert_eq!(&out[..3], &[3, 5, 0x0102_0304]);
        let mut w = Writer::new();
        write_clone_more(9, &[7], &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_clone_more(r, &mut out), Ok((9, 1)));
        assert_eq!(out[0], 7);
        // Too many handles are refused on both sides.
        assert!(write_clone(&[0; CLONE_MAX + 1], &mut Writer::new()).is_err());
        let mut w = Writer::new();
        w.u32(CLONE_MAX as u32 + 1).unwrap();
        assert!(read_clone(Reader::new(w.as_bytes()), &mut out).is_err());
        // A count that the body does not hold, and bytes left over.
        let mut w = Writer::new();
        w.u32(2).unwrap();
        w.u32(1).unwrap();
        assert!(read_clone(Reader::new(w.as_bytes()), &mut out).is_err());
        let mut w = Writer::new();
        w.u32(1).unwrap();
        w.u32(1).unwrap();
        w.u32(2).unwrap();
        assert!(read_clone(Reader::new(w.as_bytes()), &mut out).is_err());
        let mut w = Writer::new();
        write_clone_reply(12, &mut w).unwrap();
        assert_eq!(read_clone_reply(w.as_bytes()), Ok(12));
        assert!(read_clone_reply(&[1, 1, 0, 0]).is_err());
    }

    #[test]
    fn the_numbers_of_the_ram_service_keep_the_top_bits_clear() {
        // The number of a node is its place plus one in the low half and its generation in the
        // high half (services/ramfs `inode`): a generation under 2^30 leaves bits 62 and 63
        // clear.
        let generation_bits = 30;
        let top = ((1u64 << generation_bits) - 1) << 32 | u64::from(u32::MAX);
        assert_eq!(top & (UPPER_INO_TAG | 1 << 63), 0);
    }
}
