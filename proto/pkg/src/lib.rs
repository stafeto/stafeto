// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the package service (services/pkgd), proto_wire, version
//! 1: the numbers of its methods, which never change once given, its codes
//! and the bodies of its requests. Every number goes low byte first.
//!
//! | Method | Who | Request after the header | Reply after the status |
//! |---|---|---|---|
//! | LIST (1) | all | `first` u32 | `count` u32 (4 at most), `next` u32 (0 at the end), the entries |
//! | INFO (2) | all | name, `offset` u32 | `total` u32, up to 960 bytes of `meta` from `offset` |
//! | INSTALL_BEGIN (3) | UID 0 | the index record, the repository, the flags; the identity session | long: the number of the receipt, u32 |
//! | FEED (4) | the receipt's session | `receipt` u32, `cell` u32, `len` u32 | none |
//! | INSTALL_COMMIT (5) | the receipt's session | `receipt` u32, `flags` u32 | long: none |
//! | INSTALL_CANCEL (6) | the receipt's session | `receipt` u32 | none |
//! | REMOVE (7) | UID 0 | `count` u32, the names; the identity session | long: none |
//! | SETTINGS_GET (8) | all | `offset` u32 | `total` u32, `copied` u32, `generation` u64; the bytes are in cell 0 of the buffer |
//! | SETTINGS_SET (9) | UID 0 | `len` u32 (the blob is in the buffer); the identity session | long: none |
//! | SERIAL (10) | all | the repository name | `serial` u64 |
//! | SERIAL_SET (11) | UID 0 | the repository name, `serial` u64; the identity session | long: none |
//! | CLONE (12) | all | none | the new session as the reply's handle |
//! | REVOKED_SET (13) | UID 0 | `len` u32 (the list is in the buffer); the identity session | long: none |
//! | TAKE (14) | all | `key` u64; the first time a handle with NOTIFY labelled k | READY and the result, ARMED, or the refusal |
//! | BUFFER (15) | all | `size` u32 and a memory object with MAP_READ and MAP_WRITE; optionally the identity session after it | none |
//! | STATUS (16) | all | none | `generation` u64, `blocks` u64, `free` u64, `disk` u32, `image` u32, `flags` u32 |
//! | WORLD_SET (17) | UID 0 | the package name, `world` u32 (1 the world, 0 a dependency); the identity session | long: none |
//!
//! A string is one byte of length and the bytes. The buffer is CELLS cells
//! of CELL_BYTES, the client's object, as in proto_blk. The service has four
//! places for buffers: the two first are for sessions of the superuser, whom
//! the service knows by the identity session that BUFFER may bring (Vouch, as
//! for the requests that change the store), and the other two are for any
//! session, so that programs that are not the superuser's cannot keep the
//! others from installing; BUSY when the places of the session's kind are all
//! in use.

#![cfg_attr(not(test), no_std)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

use proto_wire::{Header, Reader, Status, Writer};

pub mod blob;

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The cells of the buffer of a session and the bytes of each.
pub const CELLS: u32 = 4;
pub const CELL_BYTES: u32 = 16_384;
pub const BUFFER_SIZE: u32 = CELLS * CELL_BYTES;
/// The most entries one LIST reply holds.
pub const LIST_MAX: u32 = 4;
/// The most bytes of `meta` one INFO reply holds.
pub const INFO_MAX: usize = 960;
/// The longest name of a package or a repository, and of a version, in bytes.
pub const NAME_MAX: usize = 63;
pub const REPO_MAX: usize = 32;
/// The most names one REMOVE holds.
pub const REMOVE_MAX: u32 = 8;

/// Flags of a LIST entry.
pub const ENTRY_WORLD: u32 = 1;
pub const ENTRY_IMAGE: u32 = 2;
pub const ENTRY_DEPENDENCY: u32 = 4;
pub const ENTRY_REVOKED: u32 = 8;
/// Bit 0 of the flags of INSTALL_BEGIN: the package goes into the world.
pub const BEGIN_WORLD: u32 = 1;
/// Bit 0 of the flags of INSTALL_COMMIT: the last package of the group.
pub const COMMIT_END: u32 = 1;
/// Flags of STATUS: the store is damaged, read-only, or still being read, or not served at
/// all (`STATUS_NO_STORE`: its start failed or the disk stopped answering; a change is `IO`).
pub const STATUS_DAMAGED: u32 = 1;
pub const STATUS_READ_ONLY: u32 = 2;
pub const STATUS_STARTING: u32 = 4;
pub const STATUS_NO_STORE: u32 = 8;

/// The codes of the service (`Status::Unknown`), clear of the codes of the
/// wire (below 512) and of proto_blk's (1101 to 1108).
pub const NOT_ALLOWED: u32 = 1201;
pub const BAD_SIGNATURE: u32 = 1202;
pub const BAD_HASH: u32 = 1203;
pub const BAD_MANIFEST: u32 = 1204;
pub const UNTRUSTED_KEY: u32 = 1205;
pub const CONFLICT: u32 = 1206;
pub const NO_SPACE: u32 = 1207;
pub const NO_MEMORY: u32 = 1208;
pub const TOO_LONG: u32 = 1209;
pub const IN_IMAGE: u32 = 1210;
pub const NEEDED_BY: u32 = 1211;
pub const ROLLBACK: u32 = 1212;
pub const WRONG_SERIES: u32 = 1213;
pub const REVOKED: u32 = 1214;
pub const BAD_PACKAGE: u32 = 1215;
pub const NOT_FOUND: u32 = 1216;
pub const BUSY: u32 = 1217;
pub const NO_BUFFER: u32 = 1218;
pub const IO: u32 = 1219;
pub const NO_FLUSH: u32 = 1220;
pub const DAMAGED: u32 = 1221;
pub const INVALID: u32 = 1222;

/// Every code of the service, for the check that none repeats.
pub const CODES: [u32; 22] = [
    NOT_ALLOWED,
    BAD_SIGNATURE,
    BAD_HASH,
    BAD_MANIFEST,
    UNTRUSTED_KEY,
    CONFLICT,
    NO_SPACE,
    NO_MEMORY,
    TOO_LONG,
    IN_IMAGE,
    NEEDED_BY,
    ROLLBACK,
    WRONG_SERIES,
    REVOKED,
    BAD_PACKAGE,
    NOT_FOUND,
    BUSY,
    NO_BUFFER,
    IO,
    NO_FLUSH,
    DAMAGED,
    INVALID,
];

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    List = 1,
    Info = 2,
    InstallBegin = 3,
    Feed = 4,
    InstallCommit = 5,
    InstallCancel = 6,
    Remove = 7,
    SettingsGet = 8,
    SettingsSet = 9,
    Serial = 10,
    SerialSet = 11,
    Clone = 12,
    RevokedSet = 13,
    Take = 14,
    Buffer = 15,
    Status = 16,
    WorldSet = 17,
}

impl Method {
    pub const ALL: [Method; 17] = [
        Method::List,
        Method::Info,
        Method::InstallBegin,
        Method::Feed,
        Method::InstallCommit,
        Method::InstallCancel,
        Method::Remove,
        Method::SettingsGet,
        Method::SettingsSet,
        Method::Serial,
        Method::SerialSet,
        Method::Clone,
        Method::RevokedSet,
        Method::Take,
        Method::Buffer,
        Method::Status,
        Method::WorldSet,
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

/// One entry of LIST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a [u8],
    pub version: &'a [u8],
    pub sha256: [u8; 32],
    pub flags: u32,
    pub repository: &'a [u8],
}

impl Entry<'_> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        put_text(w, self.name, NAME_MAX)?;
        put_text(w, self.version, NAME_MAX)?;
        w.bytes(&self.sha256)?;
        w.u32(self.flags)?;
        put_text(w, self.repository, REPO_MAX)
    }
}

/// The reply of LIST after its status: how many entries follow and where
/// the next reply starts (0 at the end of the list).
pub fn write_list_head(count: u32, next: u32, w: &mut Writer) -> Result<(), Status> {
    w.u32(count)?;
    w.u32(next)
}

/// The reply of LIST read back: the entries and `next`.
pub fn read_list<'a>(
    reply: &'a [u8],
    out: &mut [Option<Entry<'a>>; 4],
) -> Result<(u32, u32), Status> {
    let mut r = Reader::new(reply);
    match Status::from_code(r.u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let (count, next) = (r.u32()?, r.u32()?);
    if count > LIST_MAX {
        return Err(Status::BadSize);
    }
    for slot in out.iter_mut().take(count as usize) {
        let name = get_text(&mut r, NAME_MAX)?;
        let version = get_text(&mut r, NAME_MAX)?;
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(r.bytes(32)?);
        let flags = r.u32()?;
        let repository = get_text(&mut r, REPO_MAX)?;
        *slot = Some(Entry {
            name,
            version,
            sha256,
            flags,
            repository,
        });
    }
    r.finish()?;
    Ok((count, next))
}

/// INFO: the name of a package and the offset in its `meta`.
pub fn write_info(name: &[u8], offset: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Info.header().write(w)?;
    put_text(w, name, NAME_MAX)?;
    w.u32(offset)
}

pub fn read_info(mut body: Reader<'_>) -> Result<(&[u8], u32), Status> {
    let name = get_text(&mut body, NAME_MAX)?;
    let offset = body.u32()?;
    body.finish()?;
    Ok((name, offset))
}

/// INSTALL_BEGIN: the record of the index (name, version, size, SHA-256),
/// the repository and the flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Begin<'a> {
    pub name: &'a [u8],
    pub version: &'a [u8],
    pub size: u64,
    pub sha256: [u8; 32],
    pub repository: &'a [u8],
    pub flags: u32,
}

impl Begin<'_> {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::InstallBegin.header().write(w)?;
        put_text(w, self.name, NAME_MAX)?;
        put_text(w, self.version, NAME_MAX)?;
        w.u64(self.size)?;
        w.bytes(&self.sha256)?;
        put_text(w, self.repository, REPO_MAX)?;
        w.u32(self.flags)
    }
}

pub fn read_begin(mut body: Reader<'_>) -> Result<Begin<'_>, Status> {
    let name = get_text(&mut body, NAME_MAX)?;
    let version = get_text(&mut body, NAME_MAX)?;
    let size = body.u64()?;
    let mut sha256 = [0; 32];
    sha256.copy_from_slice(body.bytes(32)?);
    let repository = get_text(&mut body, REPO_MAX)?;
    let flags = body.u32()?;
    body.finish()?;
    Ok(Begin {
        name,
        version,
        size,
        sha256,
        repository,
        flags,
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

    /// BAD_SIZE for another length of body, INVALID for a cell of CELLS or
    /// more or a length of 0 or over CELL_BYTES.
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

/// INSTALL_COMMIT: the receipt and the flags.
pub fn write_commit(receipt: u32, flags: u32, w: &mut Writer) -> Result<(), Status> {
    Method::InstallCommit.header().write(w)?;
    w.u32(receipt)?;
    w.u32(flags)
}

pub fn read_commit(mut body: Reader<'_>) -> Result<(u32, u32), Status> {
    let (receipt, flags) = (body.u32()?, body.u32()?);
    body.finish()?;
    Ok((receipt, flags))
}

/// REMOVE: `count` names (1 to REMOVE_MAX).
pub fn write_remove(names: &[&[u8]], w: &mut Writer) -> Result<(), Status> {
    if names.is_empty() || names.len() > REMOVE_MAX as usize {
        return Err(Status::BadSize);
    }
    Method::Remove.header().write(w)?;
    w.u32(names.len() as u32)?;
    for name in names {
        put_text(w, name, NAME_MAX)?;
    }
    Ok(())
}

/// The names of a REMOVE body, in `out`; their number.
pub fn read_remove<'a>(mut body: Reader<'a>, out: &mut [&'a [u8]; 8]) -> Result<usize, Status> {
    let count = body.u32()?;
    if count == 0 || count > REMOVE_MAX {
        return Err(Status::BadSize);
    }
    for slot in out.iter_mut().take(count as usize) {
        *slot = get_text(&mut body, NAME_MAX)?;
    }
    body.finish()?;
    Ok(count as usize)
}

/// SERIAL and SERIAL_SET: the repository name and, for the second, the serial.
pub fn write_serial(repository: &[u8], serial: Option<u64>, w: &mut Writer) -> Result<(), Status> {
    let method = if serial.is_some() {
        Method::SerialSet
    } else {
        Method::Serial
    };
    method.header().write(w)?;
    put_text(w, repository, REPO_MAX)?;
    match serial {
        Some(serial) => w.u64(serial),
        None => Ok(()),
    }
}

pub fn read_serial(mut body: Reader<'_>, set: bool) -> Result<(&[u8], u64), Status> {
    let repository = get_text(&mut body, REPO_MAX)?;
    let serial = if set { body.u64()? } else { 0 };
    body.finish()?;
    Ok((repository, serial))
}

/// WORLD_SET: the name of a package of the disk and whether it is in the world (1) or
/// only a dependency (0).
pub fn write_world(name: &[u8], world: bool, w: &mut Writer) -> Result<(), Status> {
    Method::WorldSet.header().write(w)?;
    put_text(w, name, NAME_MAX)?;
    w.u32(u32::from(world))
}

/// The name and the flag of a WORLD_SET body: BAD_SIZE for a flag other than 0 or 1.
pub fn read_world(mut body: Reader<'_>) -> Result<(&[u8], bool), Status> {
    let name = get_text(&mut body, NAME_MAX)?;
    let flag = body.u32()?;
    body.finish()?;
    if flag > 1 {
        return Err(Status::BadSize);
    }
    Ok((name, flag == 1))
}

/// TAKE: the key of the operation, above 0.
pub fn write_take(key: u64, w: &mut Writer) -> Result<(), Status> {
    if key == 0 {
        return Err(Status::BadSize);
    }
    Method::Take.header().write(w)?;
    w.u64(key)
}

pub fn read_take(mut body: Reader<'_>) -> Result<u64, Status> {
    let key = body.u64()?;
    body.finish()?;
    if key == 0 {
        return Err(Status::BadSize);
    }
    Ok(key)
}

/// The reply of SETTINGS_GET after its status: the length of the blob, the
/// bytes put in cell 0 and the generation of the store the blob is of. A blob
/// longer than a cell comes in parts; a client that sees the generation change
/// between the parts starts again, so it never joins the start of the old blob
/// to the end of a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub total: u32,
    pub copied: u32,
    pub generation: u64,
}

impl Settings {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.total)?;
        w.u32(self.copied)?;
        w.u64(self.generation)
    }

    pub fn read(bytes: &[u8]) -> Result<Settings, Status> {
        let mut r = Reader::new(bytes);
        match Status::from_code(r.u32()?) {
            Status::Ok => {}
            status => return Err(status),
        }
        let settings = Settings {
            total: r.u32()?,
            copied: r.u32()?,
            generation: r.u64()?,
        };
        r.finish()?;
        Ok(settings)
    }
}

/// The reply of STATUS after its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub generation: u64,
    pub blocks: u64,
    pub free: u64,
    pub disk: u32,
    pub image: u32,
    pub flags: u32,
}

impl Stat {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u64(self.generation)?;
        w.u64(self.blocks)?;
        w.u64(self.free)?;
        w.u32(self.disk)?;
        w.u32(self.image)?;
        w.u32(self.flags)
    }

    pub fn read(bytes: &[u8]) -> Result<Stat, Status> {
        let mut r = Reader::new(bytes);
        match Status::from_code(r.u32()?) {
            Status::Ok => {}
            status => return Err(status),
        }
        let stat = Stat {
            generation: r.u64()?,
            blocks: r.u64()?,
            free: r.u64()?,
            disk: r.u32()?,
            image: r.u32()?,
            flags: r.u32()?,
        };
        r.finish()?;
        Ok(stat)
    }
}

#[cfg(test)]
mod tests;
