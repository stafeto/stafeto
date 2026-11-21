// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The account files: `/etc/passwd`, `/etc/group` and `/etc/shadow` of the file service, kept on
//! the data volume as `/etc/passwd`, `/etc/group` and `/etc/shadow` of the volume (mode 0600, in a
//! directory of mode 0700).
//!
//! At the start the service reads the three files of the image (the file service's own, which
//! are immutable), the three of the volume if there are any, and merges them (`accounts::merge`):
//! the result goes into the file service as `/etc/passwd.new`, `/etc/group.new` and
//! `/etc/shadow.new`, ordinary files that the boot script (`/etc/rc`) moves over the image's, so
//! that `adduser`, `passwd` and the rest can write them. With a volume the home of `user` is
//! `/data/home/user`, made here (owner 1000:100, mode 0700) when it is not there.
//!
//! Then, once a second, the service reads the three files of the file service, and a set that
//! has changed and is the same in two looks in a row is written to the volume (a temporary file,
//! `fsync`, a rename; shadow, group, passwd in that order, so that a cut between them leaves a
//! hash for an account the next boot drops, never an account with no line). Until the live files
//! have left the image's (the boot script has not moved the new ones yet) or equal the merge,
//! nothing is written: the volume's accounts are never overwritten by the image's.

use crate::{Data, files};
use accounts::{Files, Merged, Note, Options, Reason};
use posix_fs::{DescriptorFlags, FsError};
use proto_data as p;
use proto_wire::Status;

const N: usize = accounts::FILE_MAX;
/// The files, in the order passwd, group, shadow.
const LIVE: [&[u8]; 3] = [b"/etc/passwd", b"/etc/group", b"/etc/shadow"];
const NEW: [&[u8]; 3] = [b"/etc/passwd.new", b"/etc/group.new", b"/etc/shadow.new"];
/// The volume's copies and their temporary names.
const VOLUME: [&[u8]; 3] = [b"/etc/passwd", b"/etc/group", b"/etc/shadow"];
const TEMP: [&[u8]; 3] = [b"/etc/passwd.tmp", b"/etc/group.tmp", b"/etc/shadow.tmp"];
const MODES: [u32; 3] = [0o644, 0o644, 0o600];
/// The order of writing to the volume: shadow, group, passwd.
const ORDER: [usize; 3] = [2, 1, 0];
const VOLUME_DIR: &[u8] = b"/etc";
/// The ordinary account of the image and its numbers; its home is on the volume.
const USER: &[u8] = b"user";
const USER_UID: u32 = 1000;
const USER_GID: u32 = 100;
const HOMES: &[u8] = b"/home";
const HOME: &[u8] = b"/home/user";
/// The home as the passwd file names it (the volume is mounted at /data).
const HOME_PATH: &[u8] = b"/data/home/user";

/// Three files.
pub struct Three {
    bytes: [[u8; N]; 3],
    len: [usize; 3],
}

impl Three {
    const fn new() -> Three {
        Three {
            bytes: [[0; N]; 3],
            len: [0; 3],
        }
    }

    fn file(&self, i: usize) -> &[u8] {
        &self.bytes[i][..self.len[i]]
    }

    fn files(&self) -> Files<'_> {
        Files {
            passwd: self.file(0),
            group: self.file(1),
            shadow: self.file(2),
        }
    }

    fn same(&self, other: &Three) -> bool {
        (0..3).all(|i| self.file(i) == other.file(i))
    }

    fn set(&mut self, i: usize, bytes: &[u8]) {
        self.bytes[i][..bytes.len()].copy_from_slice(bytes);
        self.len[i] = bytes.len();
    }

    fn copy_from(&mut self, other: &Three) {
        for i in 0..3 {
            self.set(i, other.file(i));
        }
    }
}

/// The buffers of the service, in its static memory (a stack of 128 KiB would not hold them).
struct Work {
    image: Three,
    volume: Three,
    /// What the last look found in the file service, and what the volume holds.
    live: Three,
    saved: Three,
    merged: Merged,
}

struct Cell(core::cell::UnsafeCell<Work>);

// SAFETY: reached from the one thread of the service.
unsafe impl Sync for Cell {}

static WORK: Cell = Cell(core::cell::UnsafeCell::new(Work {
    image: Three::new(),
    volume: Three::new(),
    live: Three::new(),
    saved: Three::new(),
    merged: Merged::new(),
}));

fn work() -> &'static mut Work {
    // SAFETY: the one thread of the service; no reference outlives a call.
    unsafe { &mut *WORK.0.get() }
}

/// Reads a file of the file service. Ok(None): not there. A file longer than the buffer is an
/// error.
fn read_ram(path: &[u8], out: &mut [u8]) -> Result<Option<usize>, FsError> {
    let files = files();
    let fd = match files.open(path, proto_fs::READ_ONLY) {
        Ok(fd) => fd,
        Err(FsError::NoEntry) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut len = 0;
    let result = loop {
        if len == out.len() {
            break Err(FsError::FileTooLarge);
        }
        match files.read(fd, &mut out[len..]) {
            Ok(0) => break Ok(()),
            Ok(n) => len += n,
            Err(error) => break Err(error),
        }
    };
    let closed = files.close(fd);
    result.and(closed)?;
    Ok(Some(len))
}

/// Creates `path` in the file service with `mode`; one that is there already is an error.
fn create_ram(path: &[u8], mode: u32, bytes: &[u8]) -> Result<(), FsError> {
    let files = files();
    let flags = proto_fs::WRITE_ONLY | proto_fs::CREATE | proto_fs::EXCLUSIVE;
    let fd = files.open_policy(path, flags, mode, 0, DescriptorFlags::default())?;
    let mut done = 0;
    let result = loop {
        if done == bytes.len() {
            break Ok(());
        }
        match files.write(fd, &bytes[done..]) {
            Ok(0) => break Err(FsError::NoSpace),
            Ok(n) => done += n,
            Err(error) => break Err(error),
        }
    };
    let closed = files.close(fd);
    result.and(closed)
}

/// Reads the three files of the file service into `into`: false when one could not be read
/// (an absent file is empty).
fn read_live(into: &mut Three) -> bool {
    for i in 0..3 {
        match read_ram(LIVE[i], &mut into.bytes[i]) {
            Ok(n) => into.len[i] = n.unwrap_or(0),
            Err(_) => return false,
        }
    }
    true
}

/// The name of a refused entry as far as it can be printed: names are `[a-z0-9_-]`, anything else
/// is shown as `?`.
struct Printable<'a>(&'a [u8]);

impl core::fmt::Display for Printable<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &b in self.0.iter().take(32) {
            let c = if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' {
                b as char
            } else {
                '?'
            };
            core::fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

fn report(note: Note<'_>) {
    let why = match note.reason {
        Reason::Malformed => "malformed",
        Reason::UidRange => "user number out of range",
        Reason::GidRange => "group number out of range",
        Reason::NumberTaken => "number taken",
        Reason::NameTaken => "name taken",
        Reason::NoGroup => "no such group",
        Reason::Full => "no room",
    };
    rt::println!(
        "datakey: {} entry {} left out: {why}",
        note.file,
        Printable(note.name)
    );
}

impl Data {
    /// A file of the volume into `out`. Ok(None): not there.
    fn read_file(&self, path: &[u8], out: &mut [u8]) -> Result<Option<usize>, Status> {
        let handle = match self.call(|w| p::open(path, p::READ, 0o600, w)) {
            Ok(reply) => reply.word(0),
            Err(Status::Unknown(p::NO_ENTRY)) => return Ok(None),
            Err(status) => return Err(status),
        };
        let mut len = 0;
        let result = loop {
            let reply = match self.call(|w| p::read(handle, p::MAX_READ as u32, w)) {
                Ok(reply) => reply,
                Err(status) => break Err(status),
            };
            let n = reply.word(0) as usize;
            if n == 0 {
                break Ok(());
            }
            if n > reply.len.saturating_sub(8) {
                break Err(Status::BadSize);
            }
            if len + n > out.len() {
                break Err(Status::Unknown(p::TOO_BIG));
            }
            out[len..len + n].copy_from_slice(&reply.bytes[8..8 + n]);
            len += n;
        };
        let closed = self.close(handle);
        result.and(closed)?;
        Ok(Some(len))
    }

    /// `path` of the volume made (mode `mode`). Ok(true): made now; Ok(false): it was there.
    fn make_dir(&self, path: &[u8], mode: u32) -> Result<bool, Status> {
        match self.call(|w| p::mkdir(path, mode, w)) {
            Ok(_) => Ok(true),
            Err(Status::Unknown(p::EXISTS)) => Ok(false),
            Err(status) => Err(status),
        }
    }

    /// `bytes` written to `tmp` of the volume (mode 0600), synced, and renamed to `path`.
    fn save_file(&self, tmp: &[u8], path: &[u8], bytes: &[u8]) -> Result<(), Status> {
        let handle = self.call(|w| p::open(tmp, p::WRITE | p::CREATE | p::TRUNCATE, 0o600, w))?;
        let handle = handle.word(0);
        let written = (|| {
            let mut at = 0;
            while at < bytes.len() {
                let n = (bytes.len() - at).min(900);
                let wrote = self
                    .call(|w| p::write(handle, &bytes[at..at + n], w))?
                    .word(0) as usize;
                if wrote != n {
                    return Err(Status::BadSize);
                }
                at += n;
            }
            self.call(|w| p::handle_call(proto_data::Method::Fsync, handle, w))
                .map(drop)
        })();
        let closed = self.close(handle);
        written.and(closed)?;
        self.call(|w| p::rename(tmp, path, w)).map(drop)
    }
}

/// What the service keeps watching once the accounts are placed.
pub struct Watch {
    /// The live files have been seen as something other than the image's, or as the merge.
    armed: bool,
    /// The last look, for the next to compare with (the first look has nothing).
    looked: bool,
}

/// Places the merged files in the file service as `*.new` and makes the home of `user` on the
/// volume. `volume`: the data service answered (the volume is mounted). Returns what the
/// service must watch, or None when no account file was placed.
pub fn start(data: Option<&Data>, volume: bool) -> Option<Watch> {
    let w = work();
    // The image's files: without a passwd file with root in it the service leaves the accounts
    // alone (a probe image, or a table with none).
    if !read_live(&mut w.image) || w.image.len[0] == 0 || w.image.len[2] == 0 {
        rt::println!("datakey: no account files in the image, they are left alone");
        return None;
    }
    let mut kept = 0;
    if let (Some(data), true) = (data, volume) {
        for i in 0..3 {
            match data.read_file(VOLUME[i], &mut w.volume.bytes[i]) {
                Ok(n) => {
                    w.volume.len[i] = n.unwrap_or(0);
                    kept += usize::from(n.is_some());
                }
                Err(status) => rt::println!(
                    "datakey: the volume's {} could not be read: status {}",
                    core::str::from_utf8(VOLUME[i]).unwrap_or("?"),
                    status.code()
                ),
            }
        }
    }
    let options = Options {
        home: volume.then_some((USER, HOME_PATH)),
    };
    let merged = &mut w.merged;
    *merged = Merged::new();
    accounts::merge(&w.image.files(), &w.volume.files(), &options, merged, &mut report);
    if merged.passwd.data().is_empty()
        || merged.passwd.full
        || merged.group.full
        || merged.shadow.full
    {
        rt::println!("datakey: the merged account files do not fit, the image's are left alone");
        return None;
    }
    let parts = [merged.passwd.data(), merged.group.data(), merged.shadow.data()];
    for i in 0..3 {
        if let Err(error) = create_ram(NEW[i], MODES[i], parts[i]) {
            rt::println!("datakey: the account files could not be placed: {error:?}");
            return None;
        }
    }
    if volume {
        rt::println!(
            "datakey: accounts restored from /data ({kept} of 3 files there), home of user is /data/home/user"
        );
        if let Some(data) = data {
            make_home(data);
        }
    } else {
        rt::println!("datakey: no data volume, the accounts are the image's and live in memory");
    }
    Some(Watch {
        armed: false,
        looked: false,
    })
}

/// The home of `user` on the volume, owned by the account, when it is not there yet.
fn make_home(data: &Data) {
    let made = (|| -> Result<(), Status> {
        data.make_dir(HOMES, 0o755)?;
        if data.make_dir(HOME, 0o700)? {
            data.call(|w| p::chown(HOME, USER_UID, USER_GID, w))?;
            data.call(|w| p::chmod(HOME, 0o700, w))?;
            rt::println!("datakey: /data/home/user made, owner {USER_UID}:{USER_GID}");
        }
        Ok(())
    })();
    if let Err(status) = made {
        rt::println!("datakey: the home of user could not be made: status {}", status.code());
    }
}

impl Watch {
    /// One look, once a second: the live files against what the volume holds.
    pub fn look(&mut self, data: &Data) {
        let w = work();
        let mut now = Three::new();
        if !read_live(&mut now) {
            self.looked = false;
            return;
        }
        // A set that no look has seen twice is not written; one the first look sees is compared
        // with the next.
        let stable = self.looked && now.same(&w.live);
        w.live.copy_from(&now);
        self.looked = true;
        if !stable {
            return;
        }
        let from_image = w.live.same(&w.image);
        let is_merge = w.live.file(0) == w.merged.passwd.data()
            && w.live.file(1) == w.merged.group.data()
            && w.live.file(2) == w.merged.shadow.data();
        if !self.armed {
            if from_image && !is_merge {
                return;
            }
            self.armed = true;
            // Nothing is on the volume that this boot's merge did not read: the merge is the
            // first thing kept.
            w.saved = Three::new();
        }
        if w.live.same(&w.saved) {
            return;
        }
        match save(data, &w.live) {
            Ok(()) => {
                w.saved.copy_from(&w.live);
                rt::println!("datakey: accounts saved to /data");
            }
            Err(status) => {
                rt::println!("datakey: the accounts could not be saved: status {}", status.code());
            }
        }
    }
}

/// The three files written to the volume: shadow, group, passwd.
fn save(data: &Data, set: &Three) -> Result<(), Status> {
    data.make_dir(VOLUME_DIR, 0o700)?;
    for i in ORDER {
        data.save_file(TEMP[i], VOLUME[i], set.file(i))?;
    }
    Ok(())
}
