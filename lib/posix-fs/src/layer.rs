// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer service's side of the layer that needs no kernel (`posix_abi::layer`): which absolute
//! paths belong to the layered root, the flags and the errno of a request of the names
//! (`proto_fs::names`), the stamp of the layered device, the path a description of a directory
//! stands for, the buffer a listing keeps between two `getdents`, and which descriptions a child
//! inherits. The calls are `posix_abi::layer`'s; the tests run on the host.

use proto_fs::NodeInfo;
use proto_fs::names as n;

/// `st_dev` of every name of the layered root.
pub const DEVICE: u64 = n::DEVICE;

/// The code of `proto_layer` that says the service builds its index: ask again. The POSIX layer
/// does not depend on `proto_layer`; the layer service's tests keep the two equal.
pub const STARTING: u32 = 1318;

/// Linux's errno numbers, which relibc uses.
pub mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EBADF: i32 = 9;
    pub const EACCES: i32 = 13;
    pub const EBUSY: i32 = 16;
    pub const EXDEV: i32 = 18;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const EFBIG: i32 = 27;
    pub const ENOSPC: i32 = 28;
    pub const EMLINK: i32 = 31;
    pub const ENOTEMPTY: i32 = 39;
    pub const EROFS: i32 = 30;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ELOOP: i32 = 40;
    pub const EOPNOTSUPP: i32 = 95;
}

/// Whether the absolute path `absolute` (made plain: no dots, no doubled slashes, a slash at the
/// end allowed) belongs to the layered root: every path but the pass-through names of the root
/// (`/data`, `/proc`, `/dev`, `/tmp`, `/run` and what lies below them), which their own services
/// answer. `/datax` is a layered name, as `/dat` is.
pub fn belongs(absolute: &[u8]) -> bool {
    absolute.first() == Some(&b'/') && !n::is_pass_through(absolute)
}

/// `base` (the absolute path of a directory) and the relative path `rel` as one path in `out`, a
/// slash between them: the length, None when it does not fit.
pub fn join(base: &[u8], rel: &[u8], out: &mut [u8]) -> Option<usize> {
    let slash = usize::from(base.last() != Some(&b'/'));
    let total = base.len() + slash + rel.len();
    if total > out.len() {
        return None;
    }
    out[..base.len()].copy_from_slice(base);
    if slash == 1 {
        out[base.len()] = b'/';
    }
    out[base.len() + slash..total].copy_from_slice(rel);
    Some(total)
}

/// The flags of the layer's `open` that the layer service takes (the values of
/// `posix_abi::constants`, which a test of that crate keeps equal).
pub mod oflag {
    pub const ACCMODE: i32 = 3;
    pub const CREAT: i32 = 0o100;
    pub const EXCL: i32 = 0o200;
    pub const TRUNC: i32 = 0o1000;
    pub const APPEND: i32 = 0o2000;
    pub const DIRECTORY: i32 = 0o200000;
    pub const NOFOLLOW: i32 = 0o400000;
}

/// The flags of OPEN for the flags of an `open`: the access mode and the creation, truncation,
/// append, no-follow and directory-only flags. EINVAL for access mode 3.
pub fn open_flags(flags: i32) -> Result<u32, i32> {
    use oflag as o;
    if flags & o::ACCMODE == o::ACCMODE {
        return Err(errno::EINVAL);
    }
    let mut out = (flags & o::ACCMODE) as u32;
    for (local, wire) in [
        (o::DIRECTORY, proto_fs::DIRECTORY_ONLY),
        (o::CREAT, proto_fs::CREATE),
        (o::EXCL, proto_fs::EXCLUSIVE),
        (o::TRUNC, proto_fs::TRUNCATE),
        (o::APPEND, proto_fs::APPEND),
        (o::NOFOLLOW, proto_fs::NO_FOLLOW),
    ] {
        if flags & local != 0 {
            out |= wire;
        }
    }
    Ok(out)
}

/// The errno of a status code of the layer service. A code the protocol does not have is EIO. The
/// statuses that mean "ask again" (`STARTING`, `AUTHENTICATING`) and "the service restarted"
/// (`STALE`) are EIO here: the caller handles them before it asks for an errno.
pub fn errno_of(code: u32) -> i32 {
    match code {
        proto_fs::NO_ENTRY => errno::ENOENT,
        proto_fs::ALREADY_EXISTS => errno::EEXIST,
        proto_fs::LOOP => errno::ELOOP,
        proto_fs::READ_ONLY_FILESYSTEM => errno::EROFS,
        proto_fs::PERMISSION => errno::EPERM,
        proto_fs::ACCESS_DENIED => errno::EACCES,
        proto_fs::BAD_FD => errno::EBADF,
        proto_fs::IS_DIRECTORY => errno::EISDIR,
        proto_fs::NOT_DIRECTORY => errno::ENOTDIR,
        proto_fs::NO_SPACE => errno::ENOSPC,
        proto_fs::NAME_TOO_LONG => errno::ENAMETOOLONG,
        proto_fs::TOO_MANY_OPEN_FILES => errno::EMFILE,
        proto_fs::TOO_MANY_FILES_IN_SYSTEM => errno::ENFILE,
        proto_fs::INVALID_ARGUMENT => errno::EINVAL,
        proto_fs::NOT_SUPPORTED => errno::EOPNOTSUPP,
        proto_fs::TOO_MANY_LINKS => errno::EMLINK,
        proto_fs::NOT_EMPTY => errno::ENOTEMPTY,
        proto_fs::BUSY => errno::EBUSY,
        proto_fs::CROSS_DEVICE => errno::EXDEV,
        proto_fs::FILE_TOO_LARGE => errno::EFBIG,
        _ => errno::EIO,
    }
}

/// The ticket of a reply whose status is COPYING (the layer service copies a file of the lower set
/// up before it writes it): the program sends WAIT with it and then sends its request again. None
/// for a reply of another status; an error for a COPYING reply with no ticket.
pub fn copying_ticket(reply: &[u8]) -> Option<Result<u64, i32>> {
    n::read_copying(reply).map(|ticket| ticket.map_err(|_| errno::EIO))
}

/// The tag of the label of the copy of its channel that a thread brings to WAIT: bit 62, a namespace
/// of the tickets (at most 40 bits) that no other labelled copy of a channel uses (`wait.rs` has bit
/// 63, the fast sockets 1 << 62 | 0xfa57 << 32 and 0xfa58, the data window 0x5749_4e44_0000 and on).
pub const WAIT_TAG: u64 = 1 << 62;

/// The label of that copy: the ticket with the tag. The label the thread sends and the one its
/// receive matches are this one (`waits_for`).
pub const fn wait_label(ticket: u64) -> u64 {
    WAIT_TAG | ticket
}

/// Whether a notification labelled `label` is the one of the copy `ticket`.
pub const fn waits_for(label: u64, ticket: u64) -> bool {
    label == wait_label(ticket)
}

/// The errno of a copy that failed, which the answer to WAIT carries as a status of the layer
/// service: a full volume is ENOSPC and a volume that cannot be written (or a program, which is
/// never copied up) is EROFS; any other failure is EIO.
pub fn copy_errno(code: u32) -> i32 {
    match code {
        proto_fs::NO_SPACE => errno::ENOSPC,
        proto_fs::READ_ONLY_FILESYSTEM => errno::EROFS,
        _ => errno::EIO,
    }
}

/// What the answer to WAIT asks of the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waited {
    /// The copy is over: the request that said COPYING is sent again, and sees the present state
    /// (the copy, or the name as it became).
    Over,
    /// The copy goes on: the service holds the notification the WAIT brought and gives it when the
    /// copy ends. The program waits for it in `receive` on its own channel, where a signal ends the
    /// wait, and asks WAIT again after it.
    Going,
    /// The service has no place for the waiter, or builds its index: WAIT is sent again after a
    /// pause.
    Pause,
    /// The session is not bound: BIND, then WAIT again.
    Bind,
    /// The copy failed, or the request is refused: this errno.
    Failed(i32),
}

/// The plan for the status of the answer to WAIT. `busy` is the status of a service that has no job
/// for the request. WAIT is answered at once: 0 when the copy is over, COPYING while it goes on.
pub fn waited(status: u32, busy: u32) -> Waited {
    match status {
        0 => Waited::Over,
        proto_fs::COPYING => Waited::Going,
        proto_fs::AUTHENTICATING => Waited::Bind,
        s if s == STARTING || s == busy => Waited::Pause,
        s => Waited::Failed(copy_errno(s)),
    }
}

/// The node information the layered root reports: the device is the root's.
pub fn stamp(mut info: NodeInfo) -> NodeInfo {
    info.device = DEVICE;
    info
}

/// The bytes of entries one batch of READ_DIR holds at most (the message less its head).
pub const BATCH: usize = abi::MESSAGE_MAX - n::DIR_HEAD;

/// One entry of a listing: its number, the kind word of the wire and its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ino: u64,
    pub kind: u32,
    name: [u8; n::NAME_MAX],
    len: usize,
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }

    /// `d_type` of the entry, as the kinds of `NodeInfo` name them.
    pub fn d_type(&self) -> u8 {
        match self.kind {
            1 => 4,
            2 => 8,
            3 => 2,
            4 => 1,
            5 => 10,
            6 => 12,
            _ => 0,
        }
    }
}

/// What a listing keeps of a directory between two `getdents`: the last reply the service sent,
/// where the next entry starts in it, and how many entries have been given since the start (the
/// position of the directory stream). A reply is fetched when the buffer is used up and the
/// service said there is more; a reply with no entry and `more` set is read over, and the caller
/// asks again.
pub struct Listing {
    batch: [u8; BATCH],
    len: usize,
    at: usize,
    /// The start of the entry given last, so that the reader can put it back.
    last: usize,
    index: u64,
    more: bool,
}

impl Listing {
    pub const fn new() -> Listing {
        Listing {
            batch: [0; BATCH],
            len: 0,
            at: 0,
            last: 0,
            index: 0,
            more: true,
        }
    }

    /// The entries given since the start (the position `telldir` reports).
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The listing starts again: the caller sends REWIND first.
    pub fn restart(&mut self) {
        *self = Listing::new();
    }

    /// Whether the next entry needs a reply from the service: the buffer is used up and the last
    /// reply did not say it was the end.
    pub fn needs_batch(&self) -> bool {
        self.at == self.len && self.more
    }

    /// Takes a whole reply (its status word first) as the next batch. EIO for a reply the protocol
    /// does not have; every entry must parse before the batch is kept.
    pub fn load(&mut self, reply: &[u8]) -> Result<(), i32> {
        let (more, _cursor, entries) = n::read_dir_reply(reply).map_err(|_| errno::EIO)?;
        for entry in entries {
            entry.map_err(|_| errno::EIO)?;
        }
        let bytes = reply.get(n::DIR_HEAD..).ok_or(errno::EIO)?;
        if bytes.len() > BATCH {
            return Err(errno::EIO);
        }
        self.batch[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len();
        self.at = 0;
        self.last = 0;
        self.more = more;
        Ok(())
    }

    /// The next entry of the buffer, or None when it is used up (`needs_batch` says whether the
    /// directory goes on).
    pub fn take(&mut self) -> Option<Entry> {
        if self.at >= self.len {
            return None;
        }
        let mut reader = proto_wire::Reader::new(&self.batch[self.at..self.len]);
        let ino = reader.u64().ok()?;
        let kind = reader.u32().ok()?;
        let len = reader.u32().ok()? as usize;
        let name = reader.bytes(len).ok()?;
        let mut entry = Entry {
            ino,
            kind,
            name: [0; n::NAME_MAX],
            len,
        };
        entry.name[..len].copy_from_slice(name);
        self.last = self.at;
        self.at += n::ENTRY_HEAD + len;
        self.index += 1;
        Some(entry)
    }

    /// Puts the entry given last back (the reader found no room for it). One step only.
    pub fn put_back(&mut self) {
        if self.index > 0 && self.at > self.last {
            self.at = self.last;
            self.index -= 1;
        }
    }
}

impl Default for Listing {
    fn default() -> Listing {
        Listing::new()
    }
}

/// The descriptions of the file service that the layered root opened (`REDIRECT` of the layer
/// service): a `stat` of one reports the layered device, as a `stat` of its path does. The place of
/// each number the service has (`proto_fs::OPEN_FD_MASK`) holds the generation of the description
/// marked there, 0 for none: a number the service gives again to another description has another
/// generation, so a mark that outlives its description marks nothing.
static MARKED: [core::sync::atomic::AtomicU64; proto_fs::OPEN_FD_MASK as usize + 1] =
    [const { core::sync::atomic::AtomicU64::new(0) }; proto_fs::OPEN_FD_MASK as usize + 1];

fn place(fd: u32) -> &'static core::sync::atomic::AtomicU64 {
    &MARKED[(fd & proto_fs::OPEN_FD_MASK) as usize]
}

/// The description `fd` of the file service, of this `generation`, is one of the layered root.
pub fn mark_ram(fd: u32, generation: u64) {
    place(fd).store(generation, core::sync::atomic::Ordering::Release);
}

/// The description `fd` of the file service is gone.
pub fn unmark_ram(fd: u32) {
    place(fd).store(0, core::sync::atomic::Ordering::Release);
}

/// Whether the description `fd` of this `generation` is one of the layered root.
pub fn is_marked_ram(fd: u32, generation: u64) -> bool {
    generation != 0 && place(fd).load(core::sync::atomic::Ordering::Acquire) == generation
}

/// The descriptions of the data file service that the layered root adopted (the pass of a file of a
/// layer of the user): a `stat` of one reports the layered device, as a `stat` of its path does.
/// Their handles are kept as handle plus one (0 is a free place), `MARKED_DATA` at most; a handle
/// that finds no place keeps the device of the data file service. A mark goes with the description,
/// but does not cross an exec (the loader's word of `Names::Data` has no room for it).
const MARKED_DATA: usize = 64;
static DATA_MARKS: [core::sync::atomic::AtomicU64; MARKED_DATA] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MARKED_DATA];

/// The description `handle` of the data file service is one of the layered root: false when the
/// table of marks is full.
pub fn mark_data(handle: u32) -> bool {
    let want = u64::from(handle) + 1;
    DATA_MARKS.iter().any(|slot| {
        slot.compare_exchange(
            0,
            want,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
            || slot.load(core::sync::atomic::Ordering::Acquire) == want
    })
}

/// The description `handle` of the data file service is gone.
pub fn unmark_data(handle: u32) {
    let want = u64::from(handle) + 1;
    for slot in &DATA_MARKS {
        let _ = slot.compare_exchange(
            want,
            0,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        );
    }
}

/// Whether the description `handle` of the data file service is one of the layered root.
pub fn is_marked_data(handle: u32) -> bool {
    let want = u64::from(handle) + 1;
    DATA_MARKS
        .iter()
        .any(|slot| slot.load(core::sync::atomic::Ordering::Acquire) == want)
}

/// The bit that marks a number of the file service in the word of `Names::File` an exec carries:
/// the numbers have eleven bits, and the loader passes the word as it is.
pub const MARK_WORD: u32 = 1 << 30;

/// The word of `Names::File` for the description `fd` of this `generation`, with the mark of the
/// layered root when it has one.
pub fn mark_word(fd: u32, generation: u64) -> u32 {
    if is_marked_ram(fd, generation) {
        fd | MARK_WORD
    } else {
        fd
    }
}

/// The number and the mark of a word of `Names::File`.
pub const fn unmark_word(word: u32) -> (u32, bool) {
    (word & !MARK_WORD, word & MARK_WORD != 0)
}

/// The path a description of a directory stands for, kept by the layer for the relative paths and
/// `fchdir` against it (the service has no WHERE).
#[derive(Clone, Copy)]
pub struct DirPath {
    bytes: [u8; proto_fs::MAX_PATH + 1],
    len: usize,
}

impl DirPath {
    /// The path without its slash at the end (the root is `/`).
    pub fn new(path: &[u8]) -> Option<DirPath> {
        if path.is_empty() || path.len() > proto_fs::MAX_PATH {
            return None;
        }
        let end = path.iter().rposition(|&b| b != b'/').map_or(1, |i| i + 1);
        let mut out = DirPath {
            bytes: [0; proto_fs::MAX_PATH + 1],
            len: end,
        };
        out.bytes[..end].copy_from_slice(&path[..end]);
        Some(out)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// A description a child inherits: the handle of the service's description, and whether the
/// descriptor carries FD_CLOFORK (a copy of the process after `fork` or `spawn` does not).
pub use crate::data::Held;

/// The most descriptions a plan holds: the service guarantees `CLONE_MAX` for a session and a
/// session holds that many at most.
pub const PLAN_MAX: usize = n::CLONE_MAX;

/// The descriptions CLONE carries for a child: those of the descriptors without FD_CLOFORK, each
/// once. `needed` is false when there is nothing to carry: the child's slot stays empty and it
/// takes a session when it first uses the layered root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClonePlan {
    pub handles: [u32; PLAN_MAX],
    pub count: usize,
}

impl ClonePlan {
    pub fn needed(&self) -> bool {
        self.count > 0
    }

    pub fn handles(&self) -> &[u32] {
        &self.handles[..self.count]
    }
}

pub fn clone_plan(held: impl IntoIterator<Item = Held>) -> ClonePlan {
    let mut plan = ClonePlan {
        handles: [0; PLAN_MAX],
        count: 0,
    };
    for h in held {
        if !h.clofork && plan.count < PLAN_MAX && !plan.handles[..plan.count].contains(&h.handle) {
            plan.handles[plan.count] = h.handle;
            plan.count += 1;
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[test]
    fn the_pass_through_names_and_what_lies_below_them_are_not_layered() {
        for p in [
            "/",
            "/etc",
            "/etc/passwd",
            "/datax",
            "/dat",
            "/tmpx/a",
            "/bin/",
        ] {
            assert!(belongs(p.as_bytes()), "{p}");
        }
        for p in [
            "/data",
            "/data/",
            "/data/a",
            "/proc/1/stat",
            "/dev/null",
            "/tmp",
            "/tmp/x/y",
            "/run",
            "/run/x",
        ] {
            assert!(!belongs(p.as_bytes()), "{p}");
        }
        // Not an absolute path: no root to belong to.
        assert!(!belongs(b"etc"));
        assert!(!belongs(b""));
    }

    #[test]
    fn a_relative_path_joins_the_directory_with_one_slash() {
        let mut out = [0u8; 32];
        let k = join(b"/etc", b"passwd", &mut out).unwrap();
        assert_eq!(&out[..k], b"/etc/passwd");
        let k = join(b"/", b"etc", &mut out).unwrap();
        assert_eq!(&out[..k], b"/etc");
        let k = join(b"/a/", b"b/", &mut out).unwrap();
        assert_eq!(&out[..k], b"/a/b/");
        assert_eq!(
            join(b"/abcdefgh", b"0123456789abcdefghijklmnop", &mut out),
            None
        );
    }

    #[test]
    fn the_flags_of_an_open_become_the_flags_of_the_request() {
        use oflag as o;
        assert_eq!(open_flags(0), Ok(proto_fs::READ_ONLY));
        assert_eq!(open_flags(1), Ok(proto_fs::WRITE_ONLY));
        assert_eq!(open_flags(2), Ok(proto_fs::READ_WRITE));
        assert_eq!(open_flags(3), Err(errno::EINVAL));
        let all =
            open_flags(o::CREAT | o::EXCL | o::TRUNC | o::APPEND | o::DIRECTORY | o::NOFOLLOW)
                .unwrap();
        assert_eq!(
            all,
            proto_fs::CREATE
                | proto_fs::EXCLUSIVE
                | proto_fs::TRUNCATE
                | proto_fs::APPEND
                | proto_fs::DIRECTORY_ONLY
                | proto_fs::NO_FOLLOW
        );
        // Every flag a request of the layer service takes is one this function produces: the
        // request reader refuses any other bit.
        let mut w = proto_wire::Writer::new();
        n::write_open(all | 2, b"/x", &mut w).unwrap();
    }

    #[test]
    fn the_codes_the_client_keeps_are_the_services() {
        assert_eq!(STARTING, proto_layer::STARTING);
    }

    #[test]
    fn the_statuses_become_the_errno_of_a_name() {
        assert_eq!(errno_of(proto_fs::NO_ENTRY), errno::ENOENT);
        assert_eq!(errno_of(proto_fs::READ_ONLY_FILESYSTEM), errno::EROFS);
        assert_eq!(errno_of(proto_fs::ACCESS_DENIED), errno::EACCES);
        assert_eq!(errno_of(proto_fs::NOT_DIRECTORY), errno::ENOTDIR);
        assert_eq!(errno_of(proto_fs::TOO_MANY_FILES_IN_SYSTEM), errno::ENFILE);
        assert_eq!(errno_of(proto_fs::BAD_FD), errno::EBADF);
        assert_eq!(errno_of(proto_fs::TOO_MANY_LINKS), errno::EMLINK);
        assert_eq!(errno_of(proto_fs::NOT_EMPTY), errno::ENOTEMPTY);
        assert_eq!(errno_of(proto_fs::BUSY), errno::EBUSY);
        assert_eq!(errno_of(proto_fs::CROSS_DEVICE), errno::EXDEV);
        assert_eq!(errno_of(proto_fs::FILE_TOO_LARGE), errno::EFBIG);
        assert_eq!(errno_of(proto_fs::STALE), errno::EIO);
        assert_eq!(errno_of(STARTING), errno::EIO);
        assert_eq!(errno_of(proto_fs::AUTHENTICATING), errno::EIO);
        assert_eq!(errno_of(0xffff), errno::EIO);
    }

    #[test]
    fn the_layered_device_is_stamped_over_the_services_zero() {
        let info = NodeInfo {
            kind: 2,
            permissions: 0o644,
            device: 0,
            special_device: 0,
            inode: 9,
            links: 1,
            uid: 0,
            gid: 0,
            size: 5,
            block_size: 4096,
            blocks: 1,
            access_time: proto_fs::Timestamp::ZERO,
            modify_time: proto_fs::Timestamp::ZERO,
            change_time: proto_fs::Timestamp::ZERO,
        };
        let stamped = stamp(info);
        assert_eq!(stamped.device, DEVICE);
        assert_eq!(stamped.inode, 9);
        assert_eq!(DEVICE, 0x6c61_7972);
    }

    fn reply(more: bool, entries: &[(u64, u32, &[u8])]) -> ([u8; abi::MESSAGE_MAX], usize) {
        let mut r = n::DirReply::new().unwrap();
        for &(ino, kind, name) in entries {
            r.push(&n::DirEntry { ino, kind, name }).unwrap();
        }
        let len = r.len();
        (r.finish(more, 7).unwrap(), len)
    }

    #[test]
    fn a_listing_gives_its_entries_and_asks_for_more_only_when_told() {
        let mut l = Listing::new();
        assert!(l.needs_batch());
        let (bytes, len) = reply(true, &[(1, 1, b"."), (2, 2, b"passwd"), (3, 5, b"link")]);
        l.load(&bytes[..len]).unwrap();
        assert!(!l.needs_batch());
        let a = l.take().unwrap();
        assert_eq!((a.name(), a.d_type(), a.ino), (&b"."[..], 4, 1));
        let b = l.take().unwrap();
        assert_eq!((b.name(), b.d_type()), (&b"passwd"[..], 8));
        // Put the entry back and take it again: the position goes back with it.
        l.put_back();
        assert_eq!(l.index(), 1);
        assert_eq!(l.take().unwrap().name(), b"passwd");
        assert_eq!(l.take().unwrap().d_type(), 10);
        assert!(l.take().is_none());
        // The last reply said `more`: the next entry needs another reply.
        assert!(l.needs_batch());
        // A reply with no entry and `more` set is read over, and the caller asks again.
        let (bytes, len) = reply(true, &[]);
        l.load(&bytes[..len]).unwrap();
        assert!(l.take().is_none() && l.needs_batch());
        // The end: no entry, no `more`.
        let (bytes, len) = reply(false, &[]);
        l.load(&bytes[..len]).unwrap();
        assert!(l.take().is_none() && !l.needs_batch());
        assert_eq!(l.index(), 3);
        l.restart();
        assert_eq!(l.index(), 0);
        assert!(l.needs_batch());
    }

    #[test]
    fn a_malformed_reply_is_refused_whole() {
        let mut l = Listing::new();
        let (mut bytes, len) = reply(false, &[(1, 2, b"abc")]);
        // A name that runs past the end of the reply.
        bytes[len - 5] = 200;
        assert_eq!(l.load(&bytes[..len]), Err(errno::EIO));
        // The status of an error is no listing.
        assert_eq!(l.load(&[0x2d, 1, 0, 0]), Err(errno::EIO));
        assert!(l.take().is_none());
    }

    #[test]
    fn the_mark_of_a_description_of_the_file_service_is_of_its_generation() {
        // Numbers the other tests of this process do not use.
        let (a, b) = (1500, 1501);
        assert!(!is_marked_ram(a, 7));
        mark_ram(a, 7);
        assert!(is_marked_ram(a, 7) && !is_marked_ram(b, 7));
        // The number given again to another description has another generation: no mark.
        assert!(!is_marked_ram(a, 8) && !is_marked_ram(a, 0));
        assert_eq!(mark_word(a, 7), a | MARK_WORD);
        assert_eq!(mark_word(a, 8), a);
        assert_eq!(mark_word(b, 7), b);
        assert_eq!(unmark_word(a | MARK_WORD), (a, true));
        assert_eq!(unmark_word(b), (b, false));
        unmark_ram(a);
        assert!(!is_marked_ram(a, 7));
        // The numbers of the service have eleven bits: the mark bit is clear in every one.
        assert_eq!(proto_fs::OPEN_FD_MASK & MARK_WORD, 0);
        mark_ram(2047, 3);
        assert!(is_marked_ram(2047, 3));
        unmark_ram(2047);
    }

    #[test]
    fn the_mark_of_an_adopted_description_goes_with_it_and_the_table_is_bounded() {
        let base = 0x7000_0000;
        assert!(!is_marked_data(base));
        assert!(mark_data(base));
        // Marked twice is one place.
        assert!(mark_data(base));
        assert!(is_marked_data(base) && !is_marked_data(base + 1));
        unmark_data(base);
        assert!(!is_marked_data(base));
        // A full table refuses the next handle, and a place freed takes it.
        for i in 0..MARKED_DATA as u32 {
            assert!(mark_data(base + i));
        }
        assert!(!mark_data(base + MARKED_DATA as u32));
        unmark_data(base + 3);
        assert!(mark_data(base + MARKED_DATA as u32));
        for i in 0..=MARKED_DATA as u32 {
            unmark_data(base + i);
        }
        assert!(!is_marked_data(base + 1));
        // The handle 0 is a handle like another.
        assert!(mark_data(0) && is_marked_data(0));
        unmark_data(0);
    }

    #[test]
    fn a_copying_reply_has_its_ticket_and_no_other_reply_has_one() {
        let mut w = proto_wire::Writer::new();
        n::write_copying(0x0102_0304_0506, &mut w).unwrap();
        assert_eq!(copying_ticket(w.as_bytes()), Some(Ok(0x0102_0304_0506)));
        // A reply that is not COPYING (the plain status 0, a redirect, a refusal) has none.
        assert_eq!(copying_ticket(&[0, 0, 0, 0]), None);
        assert_eq!(copying_ticket(&proto_fs::REDIRECT.to_le_bytes()), None);
        assert_eq!(
            copying_ticket(&proto_fs::READ_ONLY_FILESYSTEM.to_le_bytes()),
            None
        );
        // COPYING with no ticket, or with bytes after it, is broken.
        assert_eq!(
            copying_ticket(&proto_fs::COPYING.to_le_bytes()),
            Some(Err(errno::EIO))
        );
        let mut long = w.as_bytes().to_vec();
        long.push(0);
        assert_eq!(copying_ticket(&long), Some(Err(errno::EIO)));
        // The request a client sends for the wait round-trips with the same ticket.
        let mut w = proto_wire::Writer::new();
        n::write_wait(77, &mut w).unwrap();
        let mut r = proto_wire::Reader::new(w.as_bytes());
        assert_eq!(
            proto_wire::Header::read(&mut r),
            Ok(n::NameMethod::Wait.header())
        );
        assert_eq!(n::read_wait(r), Ok(77));
    }

    #[test]
    fn the_label_a_wait_sends_is_the_label_its_receive_matches() {
        let ticket = u64::from(u32::MAX) << 8 | 11;
        let sent = wait_label(ticket);
        assert!(waits_for(sent, ticket));
        assert!(
            !waits_for(ticket, ticket),
            "the plain ticket is no label of a wait"
        );
        assert!(!waits_for(sent, ticket + 1));
        // The tag is bit 62 alone, and no ticket reaches it.
        assert_eq!(sent & !ticket, WAIT_TAG);
        assert_eq!(ticket & WAIT_TAG, 0);
        // The labels of the other copies of a channel are other labels.
        for other in [
            1u64 << 63 | 5,
            1 << 62 | 0xfa57 << 32,
            0xfa58,
            0x5749_4e44_0000,
        ] {
            assert!(!waits_for(other, ticket) || other == sent);
        }
    }

    #[test]
    fn the_answer_to_wait_is_a_resend_a_pause_a_bind_or_an_errno() {
        let busy = 0x8000_0007;
        assert_eq!(waited(0, busy), Waited::Over);
        assert_eq!(waited(proto_fs::COPYING, busy), Waited::Going);
        assert_eq!(waited(STARTING, busy), Waited::Pause);
        assert_eq!(waited(busy, busy), Waited::Pause);
        assert_eq!(waited(proto_fs::AUTHENTICATING, busy), Waited::Bind);
        assert_eq!(
            waited(proto_fs::NO_SPACE, busy),
            Waited::Failed(errno::ENOSPC)
        );
        assert_eq!(
            waited(proto_fs::READ_ONLY_FILESYSTEM, busy),
            Waited::Failed(errno::EROFS)
        );
        // The code of an I/O error of the layer service, and any other one, is EIO.
        for code in [1313, proto_fs::NO_ENTRY, proto_fs::STALE, 9999] {
            assert_eq!(waited(code, busy), Waited::Failed(errno::EIO), "{code}");
        }
        assert_eq!(copy_errno(proto_fs::NO_SPACE), errno::ENOSPC);
        assert_eq!(copy_errno(proto_fs::READ_ONLY_FILESYSTEM), errno::EROFS);
        assert_eq!(copy_errno(0), errno::EIO);
    }

    #[test]
    fn a_path_of_a_description_has_no_slash_at_its_end() {
        assert_eq!(DirPath::new(b"/etc/").unwrap().bytes(), b"/etc");
        assert_eq!(DirPath::new(b"/").unwrap().bytes(), b"/");
        assert_eq!(DirPath::new(b"//").unwrap().bytes(), b"/");
        assert!(DirPath::new(b"").is_none());
    }

    #[test]
    fn a_clone_carries_each_description_once_and_no_close_on_fork() {
        let held = [
            Held {
                handle: 5,
                clofork: false,
            },
            Held {
                handle: 5,
                clofork: false,
            },
            Held {
                handle: 6,
                clofork: true,
            },
            Held {
                handle: 7,
                clofork: false,
            },
        ];
        let plan = clone_plan(held);
        assert_eq!(plan.handles(), &[5, 7]);
        assert!(plan.needed());
        assert!(!clone_plan([]).needed());
        let many: Vec<Held> = (0..40)
            .map(|handle| Held {
                handle,
                clofork: false,
            })
            .collect();
        assert_eq!(clone_plan(many).count, PLAN_MAX);
    }
}
