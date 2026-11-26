// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the layer service (services/layerd), proto_wire, version 1: the numbers of its
//! methods, which never change once given, its codes and the bodies of its requests and replies.
//! Every number goes low byte first, every call is one request and one reply whose first four bytes
//! are the status. The protocol is for `init`, the process service and the native command `layer`;
//! the POSIX layer and `libc.so` do not speak it, so the crate stays outside the closure of the
//! ABI fingerprint (a test of xtask keeps it there).
//!
//! The layers of the root: the lower step (the packages, one step for the service whatever their
//! number), the frozen layers of the user (`/.layers/NN/`, read-only, at most `LAYERS_MAX` on a
//! volume) and the live layer, the one that takes the writes. A layer is named by a selector (see
//! `Selector`): its number NN, its chain id, the live layer, or all of them.
//!
//! | Method | Who | Request after the header | Reply after the status |
//! |---|---|---|---|
//! | LIST (1) | all | `first` u32 | `count` u32 (`LIST_MAX` at most), `next` u32 (0 at the end), the entries |
//! | STATUS (2) | all | none | the `Stat` record |
//! | DIFF (3) | all | selector (live, number or chain id), `first` u32 | `count` u32, `next` u32 (0 at the end), the changes |
//! | COMPOSE (4) | UID 0 | `count` u32 (0 to `LAYERS_MAX`), that many selectors (number or chain id); the identity session | `composition` u32, `live` u32, and the root of the composition as the reply's handle |
//! | FREEZE (5) | UID 0 | `flags` u32, the note; the identity session | long: the `Frozen` record |
//! | ROLLBACK (6) | UID 0 | selector (number or chain id); the identity session | `live` u32 |
//! | SQUASH (7) | UID 0 | `from` selector, `to` selector (number or chain id); the identity session | long: the `Sealed` record |
//! | CHECK (8) | UID 0 | selector (number, chain id or all) | long: the `Checked` record |
//! | EXPORT (9) | UID 0 | selector (number or chain id), the path of the archive | long: the `Exported` record |
//! | IMPORT (10) | UID 0 | `flags` u32, [`diff_id` 32 bytes when IMPORT_DIGEST], the note, the path of the archive; the identity session | long: the `Imported` record |
//! | REMOVE (11) | UID 0 | selector (number or chain id); the identity session | none |
//! | TAKE (12) | all | `key` u64; the first time a handle with NOTIFY labelled k | READY and the result, ARMED, or the refusal |
//! | CANCEL (13) | the session that started the job | `key` u64 | CANCELLED, or READY and a result that was ready |
//!
//! "UID 0" is the superuser, whom the service knows by the identity session that follows the body
//! (Vouch, as for `pkgd`); NOT_ALLOWED for any other, and for a request without the session. The
//! requests marked "long" are the two-step operations of `proto_wire::long` (READY, WAIT, ARMED,
//! CANCELLED): a result ready at once comes in the reply, otherwise WAIT with the key that TAKE and
//! CANCEL name. Hashing never runs in a step of the main loop, so FREEZE, SQUASH, CHECK, EXPORT
//! and IMPORT are the jobs of the worker thread. The commit of a FREEZE (the new composition) is
//! passed before its job starts: a client that cancels the wait keeps its snapshot, listed as
//! unsealed, and the service seals it all the same. CANCEL of the other four undoes them.
//!
//! A text is one byte of length and the bytes (`put_text`); a path is two bytes of length (low
//! byte first) and the bytes, at most `PATH_MAX`, with no NUL (`put_path`).

#![cfg_attr(not(test), no_std)]

use proto_wire::{Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The most layers of the user on a volume (frozen and live, and those a rollback keeps), and
/// the most a composition names.
pub const LAYERS_MAX: usize = 16;
/// The largest number NN of a layer, the two digits of `/.layers/NN/`.
pub const NUMBER_MAX: u32 = 99;
/// The number of the entries of the lower step, which has none of the user's.
pub const NO_NUMBER: u32 = u32::MAX;
/// The longest note of a layer (and the longest name of a package in an entry of the lower step),
/// in bytes.
pub const NOTE_MAX: usize = 63;
/// The longest path a change or an archive names: that of `proto_fs::MAX_PATH`.
pub const PATH_MAX: usize = 511;
/// The bytes of a SHA-256 value: a root, a chain id, a `diff_id`.
pub const DIGEST_LEN: usize = 32;
/// The most entries one LIST reply holds (156 bytes each at the most, 12 before them).
pub const LIST_MAX: u32 = 6;
/// The most changes one DIFF reply holds.
pub const DIFF_MAX: u32 = 128;

/// The kinds of a LIST entry.
pub const KIND_PACKAGES: u32 = 1;
pub const KIND_FROZEN: u32 = 2;
pub const KIND_LIVE: u32 = 3;

/// Flags of a LIST entry: the layer is sealed (its root and chain id are set), it lies above the
/// live layer after a rollback and is kept until REMOVE, its last check found a difference.
pub const ENTRY_SEALED: u32 = 1;
pub const ENTRY_DEFERRED: u32 = 2;
pub const ENTRY_DAMAGED: u32 = 4;
const ENTRY_FLAGS: u32 = ENTRY_SEALED | ENTRY_DEFERRED | ENTRY_DAMAGED;

/// The kinds of a change of DIFF, as `docker diff` letters them: A, C and D.
pub const CHANGE_ADDED: u32 = 1;
pub const CHANGE_CHANGED: u32 = 2;
pub const CHANGE_DELETED: u32 = 3;

/// Bit 0 of the flags of FREEZE: revoke the descriptions open for writing in the live layer
/// (they answer EIO afterwards) where the service would answer BUSY.
pub const FREEZE_FORCE: u32 = 1;
/// Bit 0 of the flags of IMPORT: the `diff_id` of the archive follows, and the service refuses
/// an archive that has another.
pub const IMPORT_DIGEST: u32 = 1;

/// Flags of STATUS: the index of names is still being built, the volume is not served (no data
/// disk, or its start failed), a frozen layer waits to be sealed, a start found a layer that does
/// not match its MANIFEST and raised the composition to the last one that does.
pub const STATUS_STARTING: u32 = 1;
pub const STATUS_NO_STORE: u32 = 2;
pub const STATUS_UNSEALED: u32 = 4;
pub const STATUS_DEGRADED: u32 = 8;

/// The jobs STATUS names: none, the copy of a file up into the live layer, the sealing of a
/// frozen layer, a check, a squash, an export, an import.
pub const JOB_NONE: u32 = 0;
pub const JOB_COPY_UP: u32 = 1;
pub const JOB_SEAL: u32 = 2;
pub const JOB_CHECK: u32 = 3;
pub const JOB_SQUASH: u32 = 4;
pub const JOB_EXPORT: u32 = 5;
pub const JOB_IMPORT: u32 = 6;

/// The codes of the service (`Status::Unknown`), clear of the codes of the wire (below 512) and
/// of the services it is a client of (proto_blk 1101 to 1108, proto_data 1201 to 1224).
pub const NOT_ALLOWED: u32 = 1301;
/// A description is open for writing (FREEZE without FORCE), or another job runs.
pub const BUSY: u32 = 1302;
/// No layer has that number or chain id, or a key names no job.
pub const NOT_FOUND: u32 = 1303;
/// The layer is not sealed yet: EXPORT, SQUASH and CHECK need its root.
pub const UNSEALED: u32 = 1304;
/// The live layer, or a layer of the lower step, where only a frozen one will do.
pub const NOT_FROZEN: u32 = 1305;
/// The layers of a SQUASH are not frozen layers that follow one another.
pub const BAD_RANGE: u32 = 1306;
/// The volume holds `LAYERS_MAX` layers: SQUASH or REMOVE one.
pub const TOO_MANY: u32 = 1307;
pub const NO_SPACE: u32 = 1308;
/// The root is not served: there is no data volume.
pub const NO_STORE: u32 = 1309;
/// An imported layer differs from the `diff_id` or the MANIFEST that came with it.
pub const MISMATCH: u32 = 1310;
/// The archive holds a name or an entry the service refuses (an absolute path, `..`, a link out
/// of the layer, a device, a set-ID bit, `.wh.` with no name, a path twice).
pub const BAD_ARCHIVE: u32 = 1311;
/// A path is over what the live layer or the archive format holds.
pub const TOO_LONG: u32 = 1312;
pub const IO: u32 = 1313;
pub const INVALID: u32 = 1314;
/// A TAKE or CANCEL names a key of no job of this session.
pub const NO_JOB: u32 = 1315;
/// The layer is in a composition a process tree uses.
pub const IN_USE: u32 = 1316;
/// The volume's layers are damaged beyond what the start could raise.
pub const DAMAGED: u32 = 1317;
/// The index of names is not built yet: ask again.
pub const STARTING: u32 = 1318;

/// Every code of the service, for the check that none repeats.
pub const CODES: [u32; 18] = [
    NOT_ALLOWED,
    BUSY,
    NOT_FOUND,
    UNSEALED,
    NOT_FROZEN,
    BAD_RANGE,
    TOO_MANY,
    NO_SPACE,
    NO_STORE,
    MISMATCH,
    BAD_ARCHIVE,
    TOO_LONG,
    IO,
    INVALID,
    NO_JOB,
    IN_USE,
    DAMAGED,
    STARTING,
];

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    List = 1,
    Status = 2,
    Diff = 3,
    Compose = 4,
    Freeze = 5,
    Rollback = 6,
    Squash = 7,
    Check = 8,
    Export = 9,
    Import = 10,
    Remove = 11,
    Take = 12,
    Cancel = 13,
}

impl Method {
    pub const ALL: [Method; 13] = [
        Method::List,
        Method::Status,
        Method::Diff,
        Method::Compose,
        Method::Freeze,
        Method::Rollback,
        Method::Squash,
        Method::Check,
        Method::Export,
        Method::Import,
        Method::Remove,
        Method::Take,
        Method::Cancel,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    /// The header of a request of this method.
    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

/// A string of at most `max` bytes: its length in one byte, then the bytes.
pub fn put_text(w: &mut Writer, text: &[u8], max: usize) -> Result<(), Status> {
    if text.len() > max {
        return Err(Status::BadSize);
    }
    w.bytes(&[text.len() as u8])?;
    w.bytes(text)
}

/// The string `put_text` wrote: BAD_SIZE for one over `max` bytes or cut.
pub fn get_text<'a>(r: &mut Reader<'a>, max: usize) -> Result<&'a [u8], Status> {
    let len = usize::from(r.bytes(1)?[0]);
    if len > max {
        return Err(Status::BadSize);
    }
    r.bytes(len)
}

/// A path: its length in two bytes, then the bytes. INVALID for one that is empty, over
/// `PATH_MAX` or holds a NUL.
pub fn put_path(w: &mut Writer, path: &[u8]) -> Result<(), Status> {
    check_path(path)?;
    w.u16(path.len() as u16)?;
    w.bytes(path)
}

/// The path `put_path` wrote: BAD_SIZE for one cut, INVALID for one `put_path` refuses.
pub fn get_path<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Status> {
    let len = usize::from(r.u16()?);
    let path = r.bytes(len)?;
    check_path(path)?;
    Ok(path)
}

fn check_path(path: &[u8]) -> Result<(), Status> {
    if path.is_empty() || path.len() > PATH_MAX || path.contains(&0) {
        Err(code(INVALID))
    } else {
        Ok(())
    }
}

fn get_digest(r: &mut Reader<'_>) -> Result<[u8; DIGEST_LEN], Status> {
    let mut digest = [0; DIGEST_LEN];
    digest.copy_from_slice(r.bytes(DIGEST_LEN)?);
    Ok(digest)
}

/// A request that is a header and nothing else.
pub fn write_empty(method: Method, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)
}

/// A request that is a header and one u32.
pub fn write_word(method: Method, value: u32, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)?;
    w.u32(value)
}

/// The u32 of such a body: BAD_SIZE unless it is exactly that.
pub fn read_word(mut body: Reader<'_>) -> Result<u32, Status> {
    let value = body.u32()?;
    body.finish()?;
    Ok(value)
}

/// The tags of a selector, as the methods that take one allow them (`Selector::read`).
pub const ALLOW_LIVE: u8 = 1;
pub const ALLOW_NUMBER: u8 = 2;
pub const ALLOW_CHAIN: u8 = 4;
pub const ALLOW_ALL: u8 = 8;
/// The frozen layers: by number or by chain id.
pub const ALLOW_STACK: u8 = ALLOW_NUMBER | ALLOW_CHAIN;

/// The name of a layer in a request: a tag u32, then for a number its NN as u32, for a chain id
/// its 32 bytes, for the live layer and for all of them nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selector {
    Live,
    Number(u32),
    Chain([u8; DIGEST_LEN]),
    All,
}

impl Selector {
    const fn tag(&self) -> u32 {
        match self {
            Selector::Live => 0,
            Selector::Number(_) => 1,
            Selector::Chain(_) => 2,
            Selector::All => 3,
        }
    }

    const fn allowed(&self, allow: u8) -> bool {
        let bit = match self {
            Selector::Live => ALLOW_LIVE,
            Selector::Number(_) => ALLOW_NUMBER,
            Selector::Chain(_) => ALLOW_CHAIN,
            Selector::All => ALLOW_ALL,
        };
        allow & bit != 0
    }

    /// INVALID for a form the method does not allow or a number over `NUMBER_MAX`.
    pub fn write(&self, w: &mut Writer, allow: u8) -> Result<(), Status> {
        if !self.allowed(allow) {
            return Err(code(INVALID));
        }
        w.u32(self.tag())?;
        match self {
            Selector::Live | Selector::All => Ok(()),
            Selector::Number(n) if *n <= NUMBER_MAX => w.u32(*n),
            Selector::Number(_) => Err(code(INVALID)),
            Selector::Chain(id) => w.bytes(id),
        }
    }

    /// BAD_SIZE for a cut selector, INVALID for an unknown tag, a form not in `allow` or a number
    /// over `NUMBER_MAX`.
    pub fn read(r: &mut Reader<'_>, allow: u8) -> Result<Selector, Status> {
        let selector = match r.u32()? {
            0 => Selector::Live,
            1 => Selector::Number(r.u32()?),
            2 => Selector::Chain(get_digest(r)?),
            3 => Selector::All,
            _ => return Err(code(INVALID)),
        };
        match selector {
            Selector::Number(n) if n > NUMBER_MAX => Err(code(INVALID)),
            _ if !selector.allowed(allow) => Err(code(INVALID)),
            _ => Ok(selector),
        }
    }
}

/// One entry of LIST: a layer of the lower step (the packages, one entry each, `number` is
/// `NO_NUMBER`, `note` the package name, `root` the SHA-256 of the package), a frozen layer or the
/// live one (an entry of the lower step carries `ENTRY_SEALED`: its root is set). `root` and `chain` are zero until the layer is sealed (and `chain` stays zero for the
/// lower step, whose layers the chain does not cover). `time` is seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub number: u32,
    pub kind: u32,
    pub flags: u32,
    pub root: [u8; DIGEST_LEN],
    pub chain: [u8; DIGEST_LEN],
    pub bytes: u64,
    pub time: u64,
    pub note: &'a [u8],
}

impl Entry<'_> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        w.u32(self.number)?;
        w.u32(self.kind)?;
        w.u32(self.flags)?;
        w.bytes(&self.root)?;
        w.bytes(&self.chain)?;
        w.u64(self.bytes)?;
        w.u64(self.time)?;
        put_text(w, self.note, NOTE_MAX)
    }

    /// INVALID for a kind that is none of the three, a flag that is none of the three, a number
    /// that does not suit the kind, or the sealed flag on the live layer or an unsealed layer
    /// with a root.
    fn check(&self) -> Result<(), Status> {
        let number_ok = match self.kind {
            KIND_PACKAGES => self.number == NO_NUMBER,
            KIND_FROZEN | KIND_LIVE => self.number <= NUMBER_MAX,
            _ => false,
        };
        let sealed = self.flags & ENTRY_SEALED != 0;
        let seal_ok = (sealed && self.kind != KIND_LIVE) || (!sealed && self.root == [0; 32]);
        if !number_ok || self.flags & !ENTRY_FLAGS != 0 || !seal_ok {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

/// The reply of LIST or DIFF after its status: how many entries follow and where the next reply
/// starts (0 at the end of the list).
pub fn write_list_head(count: u32, next: u32, w: &mut Writer) -> Result<(), Status> {
    w.u32(count)?;
    w.u32(next)
}

/// The reply of LIST read back: the entries in `out` and `next`; BAD_SIZE for more than
/// `LIST_MAX` or a cut or longer reply, INVALID for an entry `Entry::write` refuses.
pub fn read_list<'a>(
    reply: &'a [u8],
    out: &mut [Option<Entry<'a>>; LIST_MAX as usize],
) -> Result<(u32, u32), Status> {
    let mut r = Reader::new(reply);
    ok_status(&mut r)?;
    let (count, next) = (r.u32()?, r.u32()?);
    if count > LIST_MAX {
        return Err(Status::BadSize);
    }
    for slot in out.iter_mut().take(count as usize) {
        let entry = Entry {
            number: r.u32()?,
            kind: r.u32()?,
            flags: r.u32()?,
            root: get_digest(&mut r)?,
            chain: get_digest(&mut r)?,
            bytes: r.u64()?,
            time: r.u64()?,
            note: get_text(&mut r, NOTE_MAX)?,
        };
        entry.check()?;
        *slot = Some(entry);
    }
    r.finish()?;
    Ok((count, next))
}

fn ok_status(r: &mut Reader<'_>) -> Result<(), Status> {
    match Status::from_code(r.u32()?) {
        Status::Ok => Ok(()),
        status => Err(status),
    }
}

/// DIFF: the layer (live, number or chain id) and the index of the first change wanted.
pub fn write_diff(layer: &Selector, first: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Diff.header().write(w)?;
    layer.write(w, ALLOW_LIVE | ALLOW_STACK)?;
    w.u32(first)
}

pub fn read_diff(mut body: Reader<'_>) -> Result<(Selector, u32), Status> {
    let layer = Selector::read(&mut body, ALLOW_LIVE | ALLOW_STACK)?;
    let first = body.u32()?;
    body.finish()?;
    Ok((layer, first))
}

/// One change of a DIFF reply: its kind and the path from the root of the layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change<'a> {
    pub kind: u32,
    pub path: &'a [u8],
}

impl Change<'_> {
    /// INVALID for a kind that is none of the three, a path that is not absolute or one
    /// `put_path` refuses.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if !(CHANGE_ADDED..=CHANGE_DELETED).contains(&self.kind) || self.path.first() != Some(&b'/')
        {
            return Err(code(INVALID));
        }
        w.u32(self.kind)?;
        put_path(w, self.path)
    }
}

/// The reply of DIFF read back: `visit` gets each change; the number of changes and `next`.
/// BAD_SIZE for more than `DIFF_MAX` or a cut or longer reply, INVALID for a change
/// `Change::write` refuses.
pub fn read_changes<'a>(
    reply: &'a [u8],
    mut visit: impl FnMut(Change<'a>),
) -> Result<(u32, u32), Status> {
    let mut r = Reader::new(reply);
    ok_status(&mut r)?;
    let (count, next) = (r.u32()?, r.u32()?);
    if count > DIFF_MAX {
        return Err(Status::BadSize);
    }
    for _ in 0..count {
        let kind = r.u32()?;
        let path = get_path(&mut r)?;
        if !(CHANGE_ADDED..=CHANGE_DELETED).contains(&kind) || path[0] != b'/' {
            return Err(code(INVALID));
        }
        visit(Change { kind, path });
    }
    r.finish()?;
    Ok((count, next))
}

/// COMPOSE: the frozen layers (0 to `LAYERS_MAX`, by number or chain id), bottom first.
pub fn write_compose(layers: &[Selector], w: &mut Writer) -> Result<(), Status> {
    if layers.len() > LAYERS_MAX {
        return Err(Status::BadSize);
    }
    Method::Compose.header().write(w)?;
    w.u32(layers.len() as u32)?;
    for layer in layers {
        layer.write(w, ALLOW_STACK)?;
    }
    Ok(())
}

/// The layers of a COMPOSE body, in `out`; their number. BAD_SIZE for more than `LAYERS_MAX`.
pub fn read_compose(
    mut body: Reader<'_>,
    out: &mut [Selector; LAYERS_MAX],
) -> Result<usize, Status> {
    let count = body.u32()? as usize;
    if count > LAYERS_MAX {
        return Err(Status::BadSize);
    }
    for slot in out.iter_mut().take(count) {
        *slot = Selector::read(&mut body, ALLOW_STACK)?;
    }
    body.finish()?;
    Ok(count)
}

/// The reply of COMPOSE after its status (the root is its handle): the number of the
/// composition (above 0, the service's own) and the number of the live layer it made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Composed {
    pub composition: u32,
    pub live: u32,
}

impl Composed {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.composition)?;
        w.u32(self.live)
    }

    pub fn read(bytes: &[u8]) -> Result<Composed, Status> {
        let mut r = Reader::new(bytes);
        ok_status(&mut r)?;
        let composed = Composed {
            composition: r.u32()?,
            live: r.u32()?,
        };
        r.finish()?;
        if composed.composition == 0 || composed.live > NUMBER_MAX {
            return Err(code(INVALID));
        }
        Ok(composed)
    }
}

/// FREEZE: the flags (`FREEZE_FORCE`) and the note of the snapshot (empty or up to `NOTE_MAX`).
pub fn write_freeze(flags: u32, note: &[u8], w: &mut Writer) -> Result<(), Status> {
    if flags & !FREEZE_FORCE != 0 {
        return Err(code(INVALID));
    }
    Method::Freeze.header().write(w)?;
    w.u32(flags)?;
    put_text(w, note, NOTE_MAX)
}

pub fn read_freeze(mut body: Reader<'_>) -> Result<(u32, &[u8]), Status> {
    let flags = body.u32()?;
    let note = get_text(&mut body, NOTE_MAX)?;
    body.finish()?;
    if flags & !FREEZE_FORCE != 0 {
        return Err(code(INVALID));
    }
    Ok((flags, note))
}

/// A request that is a header and one selector (ROLLBACK, REMOVE with `ALLOW_STACK`, CHECK with
/// `ALLOW_STACK | ALLOW_ALL`).
pub fn write_select(
    method: Method,
    layer: &Selector,
    allow: u8,
    w: &mut Writer,
) -> Result<(), Status> {
    method.header().write(w)?;
    layer.write(w, allow)
}

pub fn read_select(mut body: Reader<'_>, allow: u8) -> Result<Selector, Status> {
    let layer = Selector::read(&mut body, allow)?;
    body.finish()?;
    Ok(layer)
}

/// The reply of ROLLBACK after its status: the number of the new live layer, over the one chosen
/// (`read_live` takes the whole reply, status first).
pub fn write_live(live: u32, w: &mut Writer) -> Result<(), Status> {
    if live > NUMBER_MAX {
        return Err(code(INVALID));
    }
    w.u32(live)
}

pub fn read_live(reply: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(reply);
    ok_status(&mut r)?;
    let live = r.u32()?;
    r.finish()?;
    if live > NUMBER_MAX {
        return Err(code(INVALID));
    }
    Ok(live)
}

/// SQUASH: the first and the last of the frozen layers to merge into one.
pub fn write_squash(from: &Selector, to: &Selector, w: &mut Writer) -> Result<(), Status> {
    Method::Squash.header().write(w)?;
    from.write(w, ALLOW_STACK)?;
    to.write(w, ALLOW_STACK)
}

pub fn read_squash(mut body: Reader<'_>) -> Result<(Selector, Selector), Status> {
    let from = Selector::read(&mut body, ALLOW_STACK)?;
    let to = Selector::read(&mut body, ALLOW_STACK)?;
    body.finish()?;
    Ok((from, to))
}

/// EXPORT: the layer and the path of the archive on the data volume (as `/data` has it, from the
/// root of the volume) that the service writes.
pub fn write_export(layer: &Selector, path: &[u8], w: &mut Writer) -> Result<(), Status> {
    Method::Export.header().write(w)?;
    layer.write(w, ALLOW_STACK)?;
    put_path(w, path)
}

pub fn read_export(mut body: Reader<'_>) -> Result<(Selector, &[u8]), Status> {
    let layer = Selector::read(&mut body, ALLOW_STACK)?;
    let path = get_path(&mut body)?;
    body.finish()?;
    Ok((layer, path))
}

/// IMPORT: the flags, the `diff_id` the archive must have (with `IMPORT_DIGEST`), the note of the
/// new layer and the path of the archive on the data volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Import<'a> {
    pub diff_id: Option<[u8; DIGEST_LEN]>,
    pub note: &'a [u8],
    pub path: &'a [u8],
}

impl Import<'_> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::Import.header().write(w)?;
        match self.diff_id {
            Some(id) => {
                w.u32(IMPORT_DIGEST)?;
                w.bytes(&id)?;
            }
            None => w.u32(0)?,
        }
        put_text(w, self.note, NOTE_MAX)?;
        put_path(w, self.path)
    }
}

pub fn read_import(mut body: Reader<'_>) -> Result<Import<'_>, Status> {
    let flags = body.u32()?;
    if flags & !IMPORT_DIGEST != 0 {
        return Err(code(INVALID));
    }
    let diff_id = if flags & IMPORT_DIGEST != 0 {
        Some(get_digest(&mut body)?)
    } else {
        None
    };
    let note = get_text(&mut body, NOTE_MAX)?;
    let path = get_path(&mut body)?;
    body.finish()?;
    Ok(Import {
        diff_id,
        note,
        path,
    })
}

/// TAKE and CANCEL: the key of the job, above 0.
pub fn write_key(method: Method, key: u64, w: &mut Writer) -> Result<(), Status> {
    if key == 0 {
        return Err(Status::BadSize);
    }
    method.header().write(w)?;
    w.u64(key)
}

pub fn read_key(mut body: Reader<'_>) -> Result<u64, Status> {
    let key = body.u64()?;
    body.finish()?;
    if key == 0 {
        return Err(Status::BadSize);
    }
    Ok(key)
}

/// The result of a job that sealed a layer (the bytes after READY): its number, root (the
/// SHA-256 of its MANIFEST) and chain id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub number: u32,
    pub root: [u8; DIGEST_LEN],
    pub chain: [u8; DIGEST_LEN],
}

impl Sealed {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        w.u32(self.number)?;
        w.bytes(&self.root)?;
        w.bytes(&self.chain)
    }

    fn read_from(r: &mut Reader<'_>) -> Result<Sealed, Status> {
        let sealed = Sealed {
            number: r.u32()?,
            root: get_digest(r)?,
            chain: get_digest(r)?,
        };
        sealed.check()?;
        Ok(sealed)
    }

    pub fn read(bytes: &[u8]) -> Result<Sealed, Status> {
        let mut r = Reader::new(bytes);
        let sealed = Sealed::read_from(&mut r)?;
        r.finish()?;
        Ok(sealed)
    }

    fn check(&self) -> Result<(), Status> {
        if self.number > NUMBER_MAX {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

/// The result of FREEZE: the layer it froze and sealed, and the number of the new live layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frozen {
    pub sealed: Sealed,
    pub live: u32,
}

impl Frozen {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if self.live > NUMBER_MAX {
            return Err(code(INVALID));
        }
        self.sealed.write(w)?;
        w.u32(self.live)
    }

    pub fn read(bytes: &[u8]) -> Result<Frozen, Status> {
        let mut r = Reader::new(bytes);
        let sealed = Sealed::read_from(&mut r)?;
        let live = r.u32()?;
        r.finish()?;
        if live > NUMBER_MAX {
            return Err(code(INVALID));
        }
        Ok(Frozen { sealed, live })
    }
}

/// The result of IMPORT: the new frozen layer and the `diff_id` of the archive (SHA-256 of the
/// bytes as they came).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Imported {
    pub sealed: Sealed,
    pub diff_id: [u8; DIGEST_LEN],
}

impl Imported {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.sealed.write(w)?;
        w.bytes(&self.diff_id)
    }

    pub fn read(bytes: &[u8]) -> Result<Imported, Status> {
        let mut r = Reader::new(bytes);
        let sealed = Sealed::read_from(&mut r)?;
        let diff_id = get_digest(&mut r)?;
        r.finish()?;
        Ok(Imported { sealed, diff_id })
    }
}

/// The result of EXPORT: the root of the layer, the `diff_id` of the archive written (SHA-256 of
/// its bytes) and its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exported {
    pub root: [u8; DIGEST_LEN],
    pub diff_id: [u8; DIGEST_LEN],
    pub size: u64,
}

impl Exported {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.bytes(&self.root)?;
        w.bytes(&self.diff_id)?;
        w.u64(self.size)
    }

    pub fn read(bytes: &[u8]) -> Result<Exported, Status> {
        let mut r = Reader::new(bytes);
        let exported = Exported {
            root: get_digest(&mut r)?,
            diff_id: get_digest(&mut r)?,
            size: r.u64()?,
        };
        r.finish()?;
        Ok(exported)
    }
}

/// The result of CHECK: the layers and files it went through and, when a sum differs, the layer
/// and the path of the first file (the check stops there). A difference is a result and not a
/// refusal, so that its path comes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked<'a> {
    pub layers: u32,
    pub files: u64,
    pub first_bad: Option<(u32, &'a [u8])>,
}

impl Checked<'_> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.layers)?;
        w.u64(self.files)?;
        match self.first_bad {
            None => w.u32(0),
            Some((layer, path)) => {
                if layer > NUMBER_MAX {
                    return Err(code(INVALID));
                }
                w.u32(1)?;
                w.u32(layer)?;
                put_path(w, path)
            }
        }
    }

    pub fn read(bytes: &[u8]) -> Result<Checked<'_>, Status> {
        let mut r = Reader::new(bytes);
        let (layers, files) = (r.u32()?, r.u64()?);
        let first_bad = match r.u32()? {
            0 => None,
            1 => {
                let layer = r.u32()?;
                if layer > NUMBER_MAX {
                    return Err(code(INVALID));
                }
                Some((layer, get_path(&mut r)?))
            }
            _ => return Err(code(INVALID)),
        };
        r.finish()?;
        Ok(Checked {
            layers,
            files,
            first_bad,
        })
    }
}

/// The reply of STATUS after its status: the live layer, the frozen layers and those a rollback
/// keeps, the flags, the generation of the composition (it grows with every change of it), the
/// names the live layer added, changed and deleted, the names of the merged index, the bytes the
/// live layer holds, and the job that runs (a `JOB_` value, how far it is and how far it goes, in
/// the job's own unit: bytes or files).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub live: u32,
    pub frozen: u32,
    pub deferred: u32,
    pub flags: u32,
    pub generation: u64,
    pub added: u32,
    pub changed: u32,
    pub deleted: u32,
    pub names: u32,
    pub bytes: u64,
    pub job: u32,
    pub done: u64,
    pub total: u64,
}

impl Stat {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        w.u32(self.live)?;
        w.u32(self.frozen)?;
        w.u32(self.deferred)?;
        w.u32(self.flags)?;
        w.u64(self.generation)?;
        w.u32(self.added)?;
        w.u32(self.changed)?;
        w.u32(self.deleted)?;
        w.u32(self.names)?;
        w.u64(self.bytes)?;
        w.u32(self.job)?;
        w.u64(self.done)?;
        w.u64(self.total)
    }

    pub fn read(bytes: &[u8]) -> Result<Stat, Status> {
        let mut r = Reader::new(bytes);
        ok_status(&mut r)?;
        let stat = Stat {
            live: r.u32()?,
            frozen: r.u32()?,
            deferred: r.u32()?,
            flags: r.u32()?,
            generation: r.u64()?,
            added: r.u32()?,
            changed: r.u32()?,
            deleted: r.u32()?,
            names: r.u32()?,
            bytes: r.u64()?,
            job: r.u32()?,
            done: r.u64()?,
            total: r.u64()?,
        };
        r.finish()?;
        stat.check()?;
        Ok(stat)
    }

    fn check(&self) -> Result<(), Status> {
        let flags = STATUS_STARTING | STATUS_NO_STORE | STATUS_UNSEALED | STATUS_DEGRADED;
        if self.live > NUMBER_MAX
            || self.frozen as usize > LAYERS_MAX
            || self.deferred as usize > LAYERS_MAX
            || self.flags & !flags != 0
            || self.job > JOB_IMPORT
        {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
