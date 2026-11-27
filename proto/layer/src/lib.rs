// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the layer service (services/layerd), proto_wire, version 1: the numbers of its
//! methods, which never change once given, its codes and the bodies of its requests and replies.
//! Every number goes low byte first, every call is one request and one reply whose first four
//! bytes are the status. The protocol is for `init`, the process service and the native command
//! `layer`; the POSIX layer and `libc.so` do not speak it, so the crate stays outside the closure
//! of the ABI fingerprint (a test of xtask keeps it there).
//!
//! The layers of the root: the lower set (the packages, one step for the service whatever their
//! number; the package lines come from the package service's LIST), the frozen layers of the user
//! (`/.layers/NN/`, read-only) and the live layer, the one that takes the writes. At most
//! `LAYERS_MAX` layers are held on a volume (those a rollback keeps and the live layers of
//! compositions count). A layer is named by a selector (see `Selector`): its number NN, its chain
//! id, the live layer, or all of them. Numbers come from a counter in the service's COMPOSITION
//! file: the next is (the last + 1) mod 100, skipping any number still on the volume (the work
//! directory included); the order of the stack is the one COMPOSITION lists, never the order of
//! the numbers.
//!
//! | Method | Who | Request after the header | Reply after the status |
//! |---|---|---|---|
//! | LIST (1) | all | `first` u32 | `count` u32 (`LIST_MAX` at most), `next` u32 (0 at the end), the entries |
//! | STATUS (2) | all | none | the `Stat` record |
//! | DIFF (3) | UID 0 | selector (live, number or chain id), `cursor` u32; the identity session | `count` u32, `next` u32 (0 at the end), the changes |
//! | COMPOSE (4) | UID 0 | `flags` u32, `count` u32 (0 to `LAYERS_MAX`), that many selectors (number or chain id, none twice); the identity session | long: the `Composed` record, and the root of the composition as the reply's handle |
//! | FREEZE (5) | UID 0 | the note; the identity session | long: the `Frozen` record |
//! | ROLLBACK (6) | UID 0 | selector (number or chain id); the identity session | long: `live` u32 |
//! | SQUASH (7) | UID 0 | `from` selector, `to` selector (number or chain id); the identity session | long: the `Sealed` record |
//! | CHECK (8) | UID 0 | selector (number, chain id or all); the identity session | long: the `Checked` record |
//! | EXPORT (9) | UID 0 | selector (number or chain id), `offset` u64; the identity session | long: the `ExportPart` record, the bytes in the cells of the buffer |
//! | IMPORT_BEGIN (10) | UID 0 | the `ImportBegin` record; the identity session | `receipt` u32 |
//! | FEED (11) | the receipt's session | `receipt` u32, `cell` u32, `len` u32 | none |
//! | IMPORT_COMMIT (12) | the receipt's session | `receipt` u32 | long: the `Imported` record |
//! | IMPORT_CANCEL (13) | the receipt's session | `receipt` u32 | none |
//! | REMOVE (14) | UID 0 | selector (number or chain id); the identity session | long: `count` u32 (the layers removed) |
//! | TAKE (15) | all | `key` u64; the first time a handle with NOTIFY labelled k | READY and the result, ARMED, or the refusal |
//! | CANCEL (16) | the session that started the job | `key` u64 | CANCELLED, or READY with what is done |
//! | BUFFER (17) | all | `size` u32 (`BUFFER_SIZE`) and a memory object with MAP_READ and MAP_WRITE; optionally the identity session after it | none |
//! | SESSION (18) | the root channel (`ROOT`) alone | none, and one handle: a copy of the caller's identity session | one handle: a new session of the service, bound |
//!
//! "UID 0" is the superuser, whom the service knows by the identity session that follows the body
//! (Vouch, as for `pkgd`); NOT_ALLOWED for any other, and for a request without the session. A
//! client gets its session through the root channel: `layer` asks `init` for it (TakeRoot with
//! the mark `ROOT_LAYER`, which the process service gains with the service itself), and the other
//! methods go through that session. The root of a composition (the handle COMPOSE gives) is a
//! second root channel of the service that speaks `proto_fs` and takes SESSION and VERIFY_SESSION
//! alone; its sessions see the composition's tree. The last copy of that handle gone discards the
//! live layer of the composition, or keeps it as a deferred layer when the request had
//! `COMPOSE_KEEP`.
//!
//! The requests marked "long" are the two-step operations of `proto_wire::long` (READY, WAIT,
//! ARMED, CANCELLED): a result ready at once comes in the reply, otherwise WAIT with the key that
//! TAKE and CANCEL name. Hashing never runs in a step of the main loop, so SQUASH, CHECK, EXPORT
//! and the sealing of FREEZE and IMPORT_COMMIT are jobs of the worker thread, taken from a small
//! queue (`JOBS_MAX` waiting; a CHECK gives way to a FREEZE; BUSY only when the queue is full).
//! ROLLBACK, REMOVE and COMPOSE are long because they write COMPOSITION and sync it.
//!
//! CANCEL keeps the contract of `proto_wire::long`. Before the commit of the change (the rename of
//! COMPOSITION) it answers CANCELLED and nothing is done. After the commit it answers READY with
//! what is done: for FREEZE, SQUASH and IMPORT_COMMIT a record whose layer is marked unsealed
//! (root and chain zero), and the service goes on sealing as a job of its own, visible in STATUS
//! (`STATUS_UNSEALED`, `JOB_SEAL`) and in LIST (`ENTRY_SEALED` unset). A cancelled EXPORT changes
//! nothing. A client that goes away counts as a CANCEL of each of its jobs.
//!
//! The archive of EXPORT and IMPORT is ustar that the service writes and reads itself (a PAX
//! record carries a name that does not fit; the MANIFEST is not in the archive, its root travels
//! beside it). It goes through the cells of the client's buffer: `CELLS` cells of `CELL_BYTES`,
//! the client's object, as in proto_pkg. EXPORT fills the cells from `offset` and says how many
//! bytes it put there; IMPORT_BEGIN, FEED and IMPORT_COMMIT bring the archive in, a cell at a
//! time. An imported layer goes over the top frozen layer, with a new empty live layer above it:
//! BUSY when the live layer is not empty, and the chain id is computed over that parent.
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
/// The most entries one LIST reply holds (196 bytes each at the most, 12 before them).
pub const LIST_MAX: u32 = 5;
/// The most changes one DIFF reply holds. The size of a message limits a page first (a path is up
/// to 511 bytes), and the service may cut a page early.
pub const DIFF_MAX: u32 = 128;
/// The cells of the buffer of a session and the bytes of each, as in proto_pkg.
pub const CELLS: u32 = 4;
pub const CELL_BYTES: u32 = 16_384;
pub const BUFFER_SIZE: u32 = CELLS * CELL_BYTES;
/// The jobs that wait in the queue of the worker thread.
pub const JOBS_MAX: u32 = 8;
/// The block of a ustar archive: its size is a multiple of it, and two blocks at least.
pub const BLOCK: u64 = 512;

/// The label of the service's root channel, which it registers with the process service (the
/// mark `ROOT_LAYER`, which lands with the service) and which takes SESSION alone. Bit 63 marks
/// the labels the service gives itself, and bit 60 lies above any session of its own.
pub const ROOT: u64 = 1 << 63 | 1 << 60;

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

/// Bit 0 of the flags of COMPOSE: when the last copy of the root is gone, keep the live layer of
/// the composition as a deferred layer.
pub const COMPOSE_KEEP: u32 = 1;
/// Bit 0 of the flags of IMPORT_BEGIN: the `diff_id` of the archive follows, and the service
/// refuses an archive that has another. Bit 1: the root of the layer follows (after the
/// `diff_id`, when there is one), and the service refuses a layer whose MANIFEST has another.
pub const IMPORT_DIGEST: u32 = 1;
pub const IMPORT_ROOT: u32 = 2;

/// Flags of STATUS: the index of names is still being built, the volume is not served (no data
/// disk, or its start failed), a frozen layer waits to be sealed, a start found a layer that does
/// not match its MANIFEST and raised the composition to the last one that does.
pub const STATUS_STARTING: u32 = 1;
pub const STATUS_NO_STORE: u32 = 2;
pub const STATUS_UNSEALED: u32 = 4;
pub const STATUS_DEGRADED: u32 = 8;

/// The jobs STATUS names: none, the copy of a file up into the live layer, the sealing of a
/// frozen layer, a check, a squash, an export, an import, the deletion of removed layers.
pub const JOB_NONE: u32 = 0;
pub const JOB_COPY_UP: u32 = 1;
pub const JOB_SEAL: u32 = 2;
pub const JOB_CHECK: u32 = 3;
pub const JOB_SQUASH: u32 = 4;
pub const JOB_EXPORT: u32 = 5;
pub const JOB_IMPORT: u32 = 6;
pub const JOB_REMOVE: u32 = 7;

/// The codes of the service (`Status::Unknown`), clear of the codes of the wire (below 512) and
/// of the services it is a client of (proto_blk 1101 to 1108, proto_data 1201 to 1224).
pub const NOT_ALLOWED: u32 = 1301;
/// A description is open for writing in the live layer (FREEZE), the live layer is not empty
/// (IMPORT_BEGIN), or the queue of jobs is full.
pub const BUSY: u32 = 1302;
/// No layer has that number or chain id.
pub const NOT_FOUND: u32 = 1303;
/// The layer is not sealed yet: EXPORT, SQUASH and CHECK need its root.
pub const UNSEALED: u32 = 1304;
/// The live layer, or the lower set, where only a frozen layer will do.
pub const NOT_FROZEN: u32 = 1305;
/// The layers of a SQUASH are not frozen layers that follow one another, or REMOVE names a
/// layer of the main stack (only a deferred layer goes).
pub const BAD_RANGE: u32 = 1306;
/// The volume holds `LAYERS_MAX` layers: SQUASH or REMOVE one.
pub const TOO_MANY: u32 = 1307;
pub const NO_SPACE: u32 = 1308;
/// The root is not served: there is no data volume.
pub const NO_STORE: u32 = 1309;
/// An imported layer differs from the `diff_id` or the root that came with it.
pub const MISMATCH: u32 = 1310;
/// The archive holds a name or an entry the service refuses (an absolute path, `..`, a link out
/// of the layer, a device, a set-ID bit, `.wh.` with no name, a path twice).
pub const BAD_ARCHIVE: u32 = 1311;
/// A path is over what the live layer or the archive format holds.
pub const TOO_LONG: u32 = 1312;
pub const IO: u32 = 1313;
pub const INVALID: u32 = 1314;
/// A TAKE, CANCEL, FEED, IMPORT_COMMIT or IMPORT_CANCEL names a key or a receipt of no job of
/// this session.
pub const NO_JOB: u32 = 1315;
/// The layer is in a composition a process tree uses.
pub const IN_USE: u32 = 1316;
/// The volume's layers are damaged beyond what the start could raise.
pub const DAMAGED: u32 = 1317;
/// The index of names is not built yet: ask again.
pub const STARTING: u32 = 1318;
/// EXPORT or FEED before the session has a buffer (BUFFER).
pub const NO_BUFFER: u32 = 1319;

/// Every code of the service, for the check that none repeats.
pub const CODES: [u32; 19] = [
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
    NO_BUFFER,
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
    ImportBegin = 10,
    Feed = 11,
    ImportCommit = 12,
    ImportCancel = 13,
    Remove = 14,
    Take = 15,
    Cancel = 16,
    Buffer = 17,
    Session = 18,
}

impl Method {
    pub const ALL: [Method; 18] = [
        Method::List,
        Method::Status,
        Method::Diff,
        Method::Compose,
        Method::Freeze,
        Method::Rollback,
        Method::Squash,
        Method::Check,
        Method::Export,
        Method::ImportBegin,
        Method::Feed,
        Method::ImportCommit,
        Method::ImportCancel,
        Method::Remove,
        Method::Take,
        Method::Cancel,
        Method::Buffer,
        Method::Session,
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

const ZERO: [u8; DIGEST_LEN] = [0; DIGEST_LEN];

/// A request that is a header and nothing else (STATUS, SESSION; the handle of SESSION goes with
/// the call).
pub fn write_empty(method: Method, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)
}

/// A request that is a header and one u32 (LIST).
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

/// One entry of LIST.
///
/// The lower set is one entry: kind `KIND_PACKAGES`, number `NO_NUMBER`, `ENTRY_SEALED`, `root`
/// the SHA-256 of the set as COMPOSITION records it, and everything else zero (the package lines
/// come from the package service's LIST). A frozen layer has its `parent` (the number of the layer
/// below, `NO_NUMBER` for the lowest), and once sealed its root, its chain id and `lower`, the
/// digest of the lower set at the time of the freeze (a difference after `pkg upgrade` is
/// printed). The live layer has `composition` 0 for the main root and the number of the
/// composition that owns it otherwise. `time` is seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub number: u32,
    pub kind: u32,
    pub flags: u32,
    pub parent: u32,
    pub composition: u32,
    pub root: [u8; DIGEST_LEN],
    pub chain: [u8; DIGEST_LEN],
    pub lower: [u8; DIGEST_LEN],
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
        w.u32(self.parent)?;
        w.u32(self.composition)?;
        w.bytes(&self.root)?;
        w.bytes(&self.chain)?;
        w.bytes(&self.lower)?;
        w.u64(self.bytes)?;
        w.u64(self.time)?;
        put_text(w, self.note, NOTE_MAX)
    }

    fn read<'a>(r: &mut Reader<'a>) -> Result<Entry<'a>, Status> {
        let entry = Entry {
            number: r.u32()?,
            kind: r.u32()?,
            flags: r.u32()?,
            parent: r.u32()?,
            composition: r.u32()?,
            root: get_digest(r)?,
            chain: get_digest(r)?,
            lower: get_digest(r)?,
            bytes: r.u64()?,
            time: r.u64()?,
            note: get_text(r, NOTE_MAX)?,
        };
        entry.check()?;
        Ok(entry)
    }

    /// INVALID for an entry that does not make sense: a kind that is none of the three, a flag
    /// that is none of the three, a number that does not suit the kind, a parent that is no
    /// number or the layer itself; an entry of the lower set that is unsealed, deferred,
    /// damaged, or has a chain id, a parent, a lower digest or a composition; a live layer that
    /// is sealed, deferred, damaged, or has a root, a chain id or a lower digest; a frozen layer
    /// of a composition, or one whose seal and root and chain id do not agree.
    fn check(&self) -> Result<(), Status> {
        let sealed = self.flags & ENTRY_SEALED != 0;
        let deferred = self.flags & ENTRY_DEFERRED != 0;
        let damaged = self.flags & ENTRY_DAMAGED != 0;
        let parent_ok =
            self.parent == NO_NUMBER || (self.parent <= NUMBER_MAX && self.parent != self.number);
        let kind_ok = match self.kind {
            KIND_PACKAGES => {
                self.number == NO_NUMBER
                    && sealed
                    && !deferred
                    && !damaged
                    && self.parent == NO_NUMBER
                    && self.composition == 0
                    && self.chain == ZERO
                    && self.lower == ZERO
            }
            KIND_FROZEN => {
                self.number <= NUMBER_MAX
                    && self.composition == 0
                    && (sealed == (self.root != ZERO))
                    && (sealed == (self.chain != ZERO))
                    && (sealed || self.lower == ZERO)
            }
            KIND_LIVE => {
                self.number <= NUMBER_MAX
                    && !sealed
                    && !deferred
                    && !damaged
                    && self.root == ZERO
                    && self.chain == ZERO
                    && self.lower == ZERO
            }
            _ => false,
        };
        if kind_ok && parent_ok && self.flags & !ENTRY_FLAGS == 0 {
            Ok(())
        } else {
            Err(code(INVALID))
        }
    }
}

/// The reply of LIST or DIFF after its status: how many entries follow and where the next reply
/// starts (0 at the end of the list). A reply with no entry has `next` 0: a service that cuts a
/// page early still moves on.
pub fn write_list_head(count: u32, next: u32, w: &mut Writer) -> Result<(), Status> {
    if count == 0 && next != 0 {
        return Err(code(INVALID));
    }
    w.u32(count)?;
    w.u32(next)
}

fn read_list_head(r: &mut Reader<'_>, max: u32) -> Result<(u32, u32), Status> {
    ok_status(r)?;
    let (count, next) = (r.u32()?, r.u32()?);
    if count > max {
        return Err(Status::BadSize);
    }
    if count == 0 && next != 0 {
        return Err(code(INVALID));
    }
    Ok((count, next))
}

/// The reply of LIST read back: the entries in `out` and `next`; BAD_SIZE for more than
/// `LIST_MAX` or a cut or longer reply, INVALID for an entry `Entry::write` refuses.
pub fn read_list<'a>(
    reply: &'a [u8],
    out: &mut [Option<Entry<'a>>; LIST_MAX as usize],
) -> Result<(u32, u32), Status> {
    let mut r = Reader::new(reply);
    let (count, next) = read_list_head(&mut r, LIST_MAX)?;
    for slot in out.iter_mut().take(count as usize) {
        *slot = Some(Entry::read(&mut r)?);
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

/// DIFF: the layer (live, number or chain id) and the cursor: 0 for the start, then the `next`
/// of the last reply. A cursor is a position the service defines and keeps stable (a client
/// does not read into it), as the position of a directory listing is.
pub fn write_diff(layer: &Selector, cursor: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Diff.header().write(w)?;
    layer.write(w, ALLOW_LIVE | ALLOW_STACK)?;
    w.u32(cursor)
}

pub fn read_diff(mut body: Reader<'_>) -> Result<(Selector, u32), Status> {
    let layer = Selector::read(&mut body, ALLOW_LIVE | ALLOW_STACK)?;
    let cursor = body.u32()?;
    body.finish()?;
    Ok((layer, cursor))
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
    let (count, next) = read_list_head(&mut r, DIFF_MAX)?;
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

/// COMPOSE: the flags (`COMPOSE_KEEP`) and the frozen layers (0 to `LAYERS_MAX`, by number or
/// chain id), bottom first. INVALID for the same selector twice (the service refuses a number
/// and the chain id of the same layer as well).
pub fn write_compose(flags: u32, layers: &[Selector], w: &mut Writer) -> Result<(), Status> {
    if layers.len() > LAYERS_MAX {
        return Err(Status::BadSize);
    }
    if flags & !COMPOSE_KEEP != 0 || has_twice(layers) {
        return Err(code(INVALID));
    }
    Method::Compose.header().write(w)?;
    w.u32(flags)?;
    w.u32(layers.len() as u32)?;
    for layer in layers {
        layer.write(w, ALLOW_STACK)?;
    }
    Ok(())
}

fn has_twice(layers: &[Selector]) -> bool {
    layers
        .iter()
        .enumerate()
        .any(|(i, a)| layers[i + 1..].contains(a))
}

/// The flags and layers of a COMPOSE body, the layers in `out`; their number. BAD_SIZE for more
/// than `LAYERS_MAX`.
pub fn read_compose(
    mut body: Reader<'_>,
    out: &mut [Selector; LAYERS_MAX],
) -> Result<(u32, usize), Status> {
    let flags = body.u32()?;
    let count = body.u32()? as usize;
    if count > LAYERS_MAX {
        return Err(Status::BadSize);
    }
    for slot in out.iter_mut().take(count) {
        *slot = Selector::read(&mut body, ALLOW_STACK)?;
    }
    body.finish()?;
    if flags & !COMPOSE_KEEP != 0 || has_twice(&out[..count]) {
        return Err(code(INVALID));
    }
    Ok((flags, count))
}

/// The result of COMPOSE (after READY; the root is the reply's handle): the number of the
/// composition (above 0, the service's own) and the number of the live layer it made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Composed {
    pub composition: u32,
    pub live: u32,
}

impl Composed {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        w.u32(self.composition)?;
        w.u32(self.live)
    }

    pub fn read(bytes: &[u8]) -> Result<Composed, Status> {
        let mut r = Reader::new(bytes);
        let composed = Composed {
            composition: r.u32()?,
            live: r.u32()?,
        };
        r.finish()?;
        composed.check()?;
        Ok(composed)
    }

    fn check(&self) -> Result<(), Status> {
        if self.composition == 0 || self.live > NUMBER_MAX {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

/// FREEZE: the note of the snapshot (empty or up to `NOTE_MAX`). The flag that revoked the
/// descriptions open for writing is not in version 1: a FREEZE with one open is BUSY.
pub fn write_freeze(note: &[u8], w: &mut Writer) -> Result<(), Status> {
    Method::Freeze.header().write(w)?;
    put_text(w, note, NOTE_MAX)
}

pub fn read_freeze(mut body: Reader<'_>) -> Result<&[u8], Status> {
    let note = get_text(&mut body, NOTE_MAX)?;
    body.finish()?;
    Ok(note)
}

/// A request that is a header and one selector (ROLLBACK and REMOVE with `ALLOW_STACK`, CHECK
/// with `ALLOW_STACK | ALLOW_ALL`).
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

/// The result of ROLLBACK (after READY): the number of the new live layer, over the one chosen.
pub fn write_live(live: u32, w: &mut Writer) -> Result<(), Status> {
    if live > NUMBER_MAX {
        return Err(code(INVALID));
    }
    w.u32(live)
}

pub fn read_live(bytes: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(bytes);
    let live = r.u32()?;
    r.finish()?;
    if live > NUMBER_MAX {
        return Err(code(INVALID));
    }
    Ok(live)
}

/// The result of REMOVE (after READY): the layers removed, the one named and the deferred layers
/// stacked on it (1 to `LAYERS_MAX`). Their files go in the background.
pub fn write_removed(count: u32, w: &mut Writer) -> Result<(), Status> {
    if count == 0 || count as usize > LAYERS_MAX {
        return Err(code(INVALID));
    }
    w.u32(count)
}

pub fn read_removed(bytes: &[u8]) -> Result<u32, Status> {
    let mut r = Reader::new(bytes);
    let count = r.u32()?;
    r.finish()?;
    if count == 0 || count as usize > LAYERS_MAX {
        return Err(code(INVALID));
    }
    Ok(count)
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

/// BUFFER: the size of the client's object (the memory object goes with the call), which is
/// `BUFFER_SIZE`; INVALID for any other.
pub fn write_buffer(size: u32, w: &mut Writer) -> Result<(), Status> {
    if size != BUFFER_SIZE {
        return Err(code(INVALID));
    }
    Method::Buffer.header().write(w)?;
    w.u32(size)
}

pub fn read_buffer(body: Reader<'_>) -> Result<u32, Status> {
    let size = read_word(body)?;
    if size != BUFFER_SIZE {
        return Err(code(INVALID));
    }
    Ok(size)
}

/// EXPORT: the layer and the offset in the archive from which the service fills the cells of the
/// buffer, a multiple of `BLOCK`. The archive is the same on every call for a sealed layer.
pub fn write_export(layer: &Selector, offset: u64, w: &mut Writer) -> Result<(), Status> {
    if !offset.is_multiple_of(BLOCK) {
        return Err(code(INVALID));
    }
    Method::Export.header().write(w)?;
    layer.write(w, ALLOW_STACK)?;
    w.u64(offset)
}

pub fn read_export(mut body: Reader<'_>) -> Result<(Selector, u64), Status> {
    let layer = Selector::read(&mut body, ALLOW_STACK)?;
    let offset = body.u64()?;
    body.finish()?;
    if !offset.is_multiple_of(BLOCK) {
        return Err(code(INVALID));
    }
    Ok((layer, offset))
}

/// The result of EXPORT (after READY): the root of the layer, the size of the whole archive (a
/// multiple of `BLOCK`, two blocks at least), the bytes put in the cells from the offset of the
/// request (0 only at the end of the archive), and the `diff_id` (SHA-256 of the whole archive),
/// which is set once the cells hold its last byte and is zero before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportPart {
    pub root: [u8; DIGEST_LEN],
    pub total: u64,
    pub copied: u32,
    pub diff_id: [u8; DIGEST_LEN],
}

impl ExportPart {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        w.bytes(&self.root)?;
        w.u64(self.total)?;
        w.u32(self.copied)?;
        w.bytes(&self.diff_id)
    }

    pub fn read(bytes: &[u8]) -> Result<ExportPart, Status> {
        let mut r = Reader::new(bytes);
        let part = ExportPart {
            root: get_digest(&mut r)?,
            total: r.u64()?,
            copied: r.u32()?,
            diff_id: get_digest(&mut r)?,
        };
        r.finish()?;
        part.check()?;
        Ok(part)
    }

    fn check(&self) -> Result<(), Status> {
        if archive_size_ok(self.total) && self.copied <= BUFFER_SIZE {
            Ok(())
        } else {
            Err(code(INVALID))
        }
    }
}

fn archive_size_ok(size: u64) -> bool {
    size >= 2 * BLOCK && size.is_multiple_of(BLOCK)
}

/// IMPORT_BEGIN: the size of the archive (a multiple of `BLOCK`, two blocks at least), the
/// `diff_id` it must have, the root its layer must have, and the note of the new layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportBegin<'a> {
    pub size: u64,
    pub diff_id: Option<[u8; DIGEST_LEN]>,
    pub root: Option<[u8; DIGEST_LEN]>,
    pub note: &'a [u8],
}

impl ImportBegin<'_> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        if !archive_size_ok(self.size) {
            return Err(code(INVALID));
        }
        Method::ImportBegin.header().write(w)?;
        w.u64(self.size)?;
        let flags = (u32::from(self.diff_id.is_some()) * IMPORT_DIGEST)
            | (u32::from(self.root.is_some()) * IMPORT_ROOT);
        w.u32(flags)?;
        if let Some(id) = self.diff_id {
            w.bytes(&id)?;
        }
        if let Some(root) = self.root {
            w.bytes(&root)?;
        }
        put_text(w, self.note, NOTE_MAX)
    }
}

pub fn read_import_begin(mut body: Reader<'_>) -> Result<ImportBegin<'_>, Status> {
    let size = body.u64()?;
    let flags = body.u32()?;
    if flags & !(IMPORT_DIGEST | IMPORT_ROOT) != 0 || !archive_size_ok(size) {
        return Err(code(INVALID));
    }
    let diff_id = if flags & IMPORT_DIGEST != 0 {
        Some(get_digest(&mut body)?)
    } else {
        None
    };
    let root = if flags & IMPORT_ROOT != 0 {
        Some(get_digest(&mut body)?)
    } else {
        None
    };
    let note = get_text(&mut body, NOTE_MAX)?;
    body.finish()?;
    Ok(ImportBegin {
        size,
        diff_id,
        root,
        note,
    })
}

/// FEED: the receipt, the cell of the buffer and the bytes in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feed {
    pub receipt: u32,
    pub cell: u32,
    pub len: u32,
}

impl Feed {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        Method::Feed.header().write(w)?;
        w.u32(self.receipt)?;
        w.u32(self.cell)?;
        w.u32(self.len)
    }

    /// BAD_SIZE for another length of body, INVALID for a cell of CELLS or more or a length of 0
    /// or over CELL_BYTES.
    pub fn read(mut body: Reader<'_>) -> Result<Feed, Status> {
        let feed = Feed {
            receipt: body.u32()?,
            cell: body.u32()?,
            len: body.u32()?,
        };
        body.finish()?;
        feed.check()?;
        Ok(feed)
    }

    fn check(&self) -> Result<(), Status> {
        if self.cell >= CELLS || self.len == 0 || self.len > CELL_BYTES {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

/// IMPORT_COMMIT and IMPORT_CANCEL: the receipt, above 0 (the same body as a key of TAKE).
pub fn write_receipt(method: Method, receipt: u32, w: &mut Writer) -> Result<(), Status> {
    if receipt == 0 {
        return Err(Status::BadSize);
    }
    write_word(method, receipt, w)
}

pub fn read_receipt(body: Reader<'_>) -> Result<u32, Status> {
    match read_word(body)? {
        0 => Err(Status::BadSize),
        receipt => Ok(receipt),
    }
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

/// The layer a job made or sealed (the bytes after READY): its number, root (the SHA-256 of its
/// MANIFEST) and chain id. A layer whose sealing is not done (the job was cancelled after its
/// commit) has root and chain id both zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub number: u32,
    pub root: [u8; DIGEST_LEN],
    pub chain: [u8; DIGEST_LEN],
}

impl Sealed {
    pub fn is_sealed(&self) -> bool {
        self.root != ZERO
    }

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

    /// INVALID for a number over `NUMBER_MAX`, or a root and a chain id of which one is zero.
    fn check(&self) -> Result<(), Status> {
        if self.number > NUMBER_MAX || (self.root == ZERO) != (self.chain == ZERO) {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

/// The result of FREEZE: the layer it froze, and the number of the new live layer (another
/// number than the frozen layer's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frozen {
    pub sealed: Sealed,
    pub live: u32,
}

impl Frozen {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        self.sealed.write(w)?;
        w.u32(self.live)
    }

    pub fn read(bytes: &[u8]) -> Result<Frozen, Status> {
        let mut r = Reader::new(bytes);
        let frozen = Frozen {
            sealed: Sealed::read_from(&mut r)?,
            live: r.u32()?,
        };
        r.finish()?;
        frozen.check()?;
        Ok(frozen)
    }

    fn check(&self) -> Result<(), Status> {
        if self.live > NUMBER_MAX || self.live == self.sealed.number {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

/// The result of IMPORT_COMMIT: the new frozen layer, the `diff_id` of the archive (SHA-256 of
/// the bytes as they came) and the number of the new live layer above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Imported {
    pub frozen: Frozen,
    pub diff_id: [u8; DIGEST_LEN],
}

impl Imported {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.frozen.write(w)?;
        w.bytes(&self.diff_id)
    }

    pub fn read(bytes: &[u8]) -> Result<Imported, Status> {
        let mut r = Reader::new(bytes);
        let frozen = Frozen {
            sealed: Sealed::read_from(&mut r)?,
            live: r.u32()?,
        };
        frozen.check()?;
        let diff_id = get_digest(&mut r)?;
        r.finish()?;
        Ok(Imported { frozen, diff_id })
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
/// live layer holds, the job that runs (a `JOB_` value, how far it is and how far it goes, in the
/// job's own unit: bytes or files) and the number of jobs that wait.
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
    pub queued: u32,
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
        w.u32(self.queued)?;
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
            queued: r.u32()?,
            done: r.u64()?,
            total: r.u64()?,
        };
        r.finish()?;
        stat.check()?;
        Ok(stat)
    }

    /// INVALID for a live number over `NUMBER_MAX`, more than `LAYERS_MAX` layers held (the live
    /// one counts), a flag that is none of the four, an unknown job, more than `JOBS_MAX` waiting,
    /// jobs waiting while none runs, or progress with no job or past its end.
    fn check(&self) -> Result<(), Status> {
        let flags = STATUS_STARTING | STATUS_NO_STORE | STATUS_UNSEALED | STATUS_DEGRADED;
        let held = u64::from(self.frozen) + u64::from(self.deferred) + 1;
        let idle = self.job == JOB_NONE;
        if self.live > NUMBER_MAX
            || held > LAYERS_MAX as u64
            || self.flags & !flags != 0
            || self.job > JOB_REMOVE
            || self.queued > JOBS_MAX
            || (idle && (self.queued != 0 || self.done != 0 || self.total != 0))
            || self.done > self.total
        {
            Err(code(INVALID))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
