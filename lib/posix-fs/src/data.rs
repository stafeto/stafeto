// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data file service's side of the layer that needs no kernel: which paths belong to `/data`
//! and the path the service gets, the errno each status of the protocol becomes, the node
//! information a stat record makes, the buffer a directory listing keeps between two `getdents`,
//! and which descriptions a child inherits. `posix_abi::data` does the calls and uses these; the
//! tests run on the host.

use proto_data as p;
use proto_fs::{NodeInfo, Timestamp};

/// The directory the service's volume is mounted at.
pub const MOUNT: &[u8] = b"/data";

/// The path the service gets for an absolute path of the layer (the dots and the extra slashes are
/// gone already, `posix_path::simplify`): `/data` and `/data/` are the root of the volume `/`,
/// `/data/a/b` is `/a/b`, and a slash at the end goes. None for any other path, `/datax` and
/// `/dat` included: a prefix of the name alone is no mount.
pub fn volume_path(absolute: &[u8]) -> Option<&[u8]> {
    let rest = absolute.strip_prefix(MOUNT)?;
    match rest {
        [] | [b'/'] => Some(b"/"),
        [b'/', ..] => {
            let end = rest.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
            Some(&rest[..end])
        }
        _ => None,
    }
}

/// Whether `absolute` is a path of the mount (the mount point and everything below it).
pub fn is_mount(absolute: &[u8]) -> bool {
    volume_path(absolute).is_some()
}

/// Linux's errno numbers, which relibc uses.
pub mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EBADF: i32 = 9;
    pub const EACCES: i32 = 13;
    pub const EBUSY: i32 = 16;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const EFBIG: i32 = 27;
    pub const ENOSPC: i32 = 28;
    pub const EROFS: i32 = 30;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ENOTEMPTY: i32 = 39;
}

/// The errno of a status code of the service. A code the protocol does not have is EIO. The
/// statuses that mean "bind and ask again" (NOT_BOUND) or "the service restarted" (STALE) are EIO
/// here: the caller handles them before it asks for an errno.
pub fn errno_of(code: u32) -> i32 {
    use proto_data::Errno as E;
    match p::errno(code) {
        Some(E::Eacces) => errno::EACCES,
        Some(E::Eperm) => errno::EPERM,
        Some(E::Enoent) => errno::ENOENT,
        Some(E::Eexist) => errno::EEXIST,
        Some(E::Enotdir) => errno::ENOTDIR,
        Some(E::Eisdir) => errno::EISDIR,
        Some(E::Enotempty) => errno::ENOTEMPTY,
        Some(E::Ebadf) => errno::EBADF,
        Some(E::Efbig) => errno::EFBIG,
        Some(E::Einval) => errno::EINVAL,
        Some(E::Enospc) => errno::ENOSPC,
        Some(E::Eio) | None => errno::EIO,
        Some(E::Emfile) => errno::EMFILE,
        Some(E::Enfile) => errno::ENFILE,
        Some(E::Enametoolong) => errno::ENAMETOOLONG,
        Some(E::Ebusy) => errno::EBUSY,
        Some(E::Erofs) => errno::EROFS,
    }
}

/// The device number of the volume in `stat` (the ASCII of "data"): constant, and not the RAM file
/// service's.
pub const DEVICE: u64 = 0x6461_7461;
/// The block of the volume in `stat`.
pub const BLOCK_SIZE: u32 = 4096;

/// The time of a stat record in nanoseconds as a timestamp: floor division, so a time before the
/// epoch keeps its nanoseconds in 0..1e9.
fn stamp(ns: i64) -> Timestamp {
    let seconds = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    Timestamp::new(seconds, nanos).unwrap_or(Timestamp::ZERO)
}

/// The node information of a stat record: directories and files with their owner, mode, number and
/// times; `st_nlink` is the record's (1, and 0 for an unlinked open file), `st_blksize` 4096,
/// `st_blocks` the size in sectors of 512 rounded up.
pub fn node_info(stat: &p::Stat) -> NodeInfo {
    NodeInfo {
        kind: if stat.kind == p::KIND_DIRECTORY { 1 } else { 2 },
        permissions: stat.mode & 0o7777,
        device: DEVICE,
        special_device: 0,
        inode: stat.ino,
        links: u64::from(stat.nlink),
        uid: stat.uid,
        gid: stat.gid,
        size: stat.size,
        block_size: BLOCK_SIZE,
        blocks: stat.size.div_ceil(512),
        access_time: stamp(stat.atime),
        modify_time: stamp(stat.mtime),
        change_time: stamp(stat.ctime),
    }
}

/// The bytes of entries one batch of READDIR holds at most (the message less its status and `more`).
pub const BATCH: usize = abi::MESSAGE_MAX - p::DIR_REPLY_HEAD;

/// One entry of a listing: its number, the kind word of the wire and its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ino: u64,
    pub kind: u32,
    name: [u8; p::NAME_MAX],
    len: usize,
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }

    /// `d_type` of the entry: DT_DIR or DT_REG.
    pub fn d_type(&self) -> u8 {
        if self.kind == p::KIND_DIRECTORY { 4 } else { 8 }
    }
}

/// What a listing keeps of a directory between two `getdents`: the last batch the service sent,
/// where the next entry starts in it, and how many entries have been given since the start (the
/// position of the directory stream). A batch is fetched only when the buffer is used up and the
/// service said there is more.
pub struct Listing {
    batch: [u8; BATCH],
    len: usize,
    at: usize,
    /// The start of the entry given last, so that the reader can put it back.
    last: usize,
    index: u64,
    more: bool,
    /// The service answered an empty batch: the directory is over.
    over: bool,
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
            over: false,
        }
    }

    /// The entries given since the start (the position `telldir` reports).
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The listing starts again: the caller sends REWIND (or opens again) first.
    pub fn restart(&mut self) {
        *self = Listing::new();
    }

    /// Whether the next entry needs a batch from the service: the buffer is used up and the last
    /// batch was not the end.
    pub fn needs_batch(&self) -> bool {
        self.at == self.len && self.more && !self.over
    }

    /// Takes a reply after its status (`more` u32 and the entries) as the next batch. BAD_SIZE
    /// (as errno EIO) for a reply the protocol does not have; a batch with no entry and `more` 0 is
    /// the end.
    pub fn load(&mut self, body: &[u8]) -> Result<(), i32> {
        let mut entries =
            p::read_dir_reply(proto_wire::Reader::new(body)).map_err(|_| errno::EIO)?;
        let more = entries.more;
        let start = 4;
        let bytes = &body[start..];
        // Every entry must parse before the batch is kept.
        let mut count = 0;
        while entries.next_entry().map_err(|_| errno::EIO)?.is_some() {
            count += 1;
        }
        if bytes.len() > BATCH {
            return Err(errno::EIO);
        }
        self.batch[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len();
        self.at = 0;
        self.last = 0;
        self.more = more;
        self.over = count == 0 && !more;
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
            name: [0; p::NAME_MAX],
            len,
        };
        entry.name[..len].copy_from_slice(name);
        self.last = self.at;
        self.at += p::DIR_ENTRY_HEAD + len;
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

/// A description a child inherits: the handle of the service's description, and whether the
/// descriptor carries FD_CLOFORK (a copy of the process after `fork` or `spawn` does not).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub handle: u32,
    pub clofork: bool,
}

/// The descriptions CLONE carries for a child (rule of the layer): those of the descriptors without
/// FD_CLOFORK, and the description of the current directory when it is under `/data`, each once.
/// `needed` is false when there is nothing to carry: the child's slot stays empty and it takes a
/// session when it first uses `/data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClonePlan {
    pub handles: [u32; p::CLONE_MAX],
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

/// Plans a CLONE from the descriptions of the table and the current directory's.
pub fn clone_plan(held: impl IntoIterator<Item = Held>, cwd: Option<u32>) -> ClonePlan {
    let mut plan = ClonePlan {
        handles: [0; p::CLONE_MAX],
        count: 0,
    };
    let mut add = |handle: u32| {
        if plan.count < p::CLONE_MAX && !plan.handles[..plan.count].contains(&handle) {
            plan.handles[plan.count] = handle;
            plan.count += 1;
        }
    };
    for h in held {
        if !h.clofork {
            add(h.handle);
        }
    }
    if let Some(handle) = cwd {
        add(handle);
    }
    plan
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[test]
    fn the_mount_is_the_whole_name_data_and_what_is_below_it() {
        let cases: [(&[u8], Option<&[u8]>); 10] = [
            (b"/data", Some(b"/")),
            (b"/data/", Some(b"/")),
            (b"/data/a", Some(b"/a")),
            (b"/data/a/b", Some(b"/a/b")),
            (b"/data/a/", Some(b"/a")),
            (b"/datax", None),
            (b"/data2/a", None),
            (b"/dat", None),
            (b"/", None),
            (b"/etc/data", None),
        ];
        for (path, want) in cases {
            assert_eq!(
                volume_path(path),
                want,
                "{}",
                core::str::from_utf8(path).unwrap()
            );
            assert_eq!(is_mount(path), want.is_some());
        }
    }

    #[test]
    fn every_status_of_the_protocol_has_an_errno_and_the_table_is_the_protocols() {
        use errno::*;
        for (code, want) in [
            (p::NO_ENTRY, ENOENT),
            (p::EXISTS, EEXIST),
            (p::NOT_DIRECTORY, ENOTDIR),
            (p::IS_DIRECTORY, EISDIR),
            (p::NOT_EMPTY, ENOTEMPTY),
            (p::BAD_HANDLE, EBADF),
            (p::TOO_BIG, EFBIG),
            (p::INVALID, EINVAL),
            (p::NO_SPACE, ENOSPC),
            (p::IO, EIO),
            (p::TOO_MANY_OPEN, EMFILE),
            (p::NAME_TOO_LONG, ENAMETOOLONG),
            (p::BUSY, EBUSY),
            (p::NOT_READY, EIO),
            (p::CORRUPT, EIO),
            (p::STALE, EIO),
            (p::ACCESS, EACCES),
            (p::TABLE_FULL, ENFILE),
            (p::PERMISSION, EPERM),
            (p::NOT_BOUND, EIO),
            (p::FILE_SIZE_LIMIT, EFBIG),
            (p::IS_ROOT, EIO),
            (p::READ_ONLY, EROFS),
        ] {
            assert_eq!(errno_of(code), want, "{code}");
        }
        // Every code the protocol lists is in the table above, and a code it does not have is EIO.
        assert_eq!(p::CODES.len(), 23);
        assert_eq!(errno_of(0), EIO);
        assert_eq!(errno_of(9999), EIO);
        assert_eq!(errno::EROFS, 30);
    }

    fn sample() -> p::Stat {
        p::Stat {
            kind: p::KIND_FILE,
            mode: 0o644,
            uid: 1000,
            gid: 100,
            size: 1025,
            ino: 77,
            atime: 1_500_000_000,
            mtime: -1,
            ctime: 2_000_000_001,
            nlink: 1,
        }
    }

    #[test]
    fn a_stat_record_becomes_the_node_information_of_the_layer() {
        let info = node_info(&sample());
        assert_eq!(
            (info.kind, info.permissions, info.uid, info.gid),
            (2, 0o644, 1000, 100)
        );
        assert_eq!((info.inode, info.links, info.size), (77, 1, 1025));
        assert_eq!(
            (info.device, info.block_size, info.blocks),
            (DEVICE, 4096, 3)
        );
        assert_eq!(info.access_time, Timestamp::new(1, 500_000_000).unwrap());
        assert_eq!(info.change_time, Timestamp::new(2, 1).unwrap());
        // A time before the epoch keeps its nanoseconds in range.
        assert_eq!(info.modify_time, Timestamp::new(-1, 999_999_999).unwrap());
        let dir = node_info(&p::Stat {
            kind: p::KIND_DIRECTORY,
            size: 0,
            nlink: 1,
            ..sample()
        });
        assert_eq!((dir.kind, dir.size, dir.blocks, dir.links), (1, 0, 0, 1));
        // An unlinked open file has no link.
        let gone = node_info(&p::Stat {
            nlink: 0,
            ..sample()
        });
        assert_eq!(gone.links, 0);
        assert_ne!(DEVICE, 0);
    }

    fn reply(more: bool, names: &[&[u8]]) -> Vec<u8> {
        let mut batch = p::DirBatch::new();
        for (i, name) in names.iter().enumerate() {
            let kind = if *name == b"d" {
                p::KIND_DIRECTORY
            } else {
                p::KIND_FILE
            };
            assert!(batch.push(100 + i as u64, kind, name));
        }
        let mut w = proto_wire::Writer::new();
        batch.write(more, &mut w).unwrap();
        w.as_bytes().to_vec()
    }

    #[test]
    fn a_listing_gives_the_entries_of_a_batch_then_asks_for_the_next() {
        let mut l = Listing::new();
        assert!(l.needs_batch(), "nothing yet");
        l.load(&reply(true, &[b".", b"..", b"d", b"file"])).unwrap();
        assert!(!l.needs_batch());
        let mut seen = Vec::new();
        while let Some(e) = l.take() {
            seen.push((e.name().to_vec(), e.ino, e.d_type()));
        }
        assert_eq!(
            seen,
            [
                (b".".to_vec(), 100, 8),
                (b"..".to_vec(), 101, 8),
                (b"d".to_vec(), 102, 4),
                (b"file".to_vec(), 103, 8)
            ]
        );
        assert_eq!(l.index(), 4);
        // The buffer is used up and the service said there is more.
        assert!(l.needs_batch());
        l.load(&reply(false, &[b"last"])).unwrap();
        assert_eq!(l.take().unwrap().name(), b"last");
        assert_eq!(l.index(), 5);
        assert!(l.take().is_none());
        assert!(!l.needs_batch(), "the last batch said no more");
    }

    #[test]
    fn the_entry_that_found_no_room_goes_back_and_comes_again() {
        let mut l = Listing::new();
        l.load(&reply(false, &[b"a", b"b", b"c"])).unwrap();
        assert_eq!(l.take().unwrap().name(), b"a");
        assert_eq!(l.take().unwrap().name(), b"b");
        l.put_back();
        assert_eq!(l.index(), 1);
        assert_eq!(l.take().unwrap().name(), b"b");
        assert_eq!(l.take().unwrap().name(), b"c");
        l.put_back();
        assert_eq!(l.take().unwrap().name(), b"c");
        // Nothing to put back before the first entry.
        let mut fresh = Listing::new();
        fresh.put_back();
        assert_eq!(fresh.index(), 0);
    }

    #[test]
    fn an_empty_end_batch_ends_the_listing_and_a_restart_begins_again() {
        let mut l = Listing::new();
        l.load(&reply(false, &[])).unwrap();
        assert!(l.take().is_none());
        assert!(!l.needs_batch());
        l.restart();
        assert!(l.needs_batch());
        assert_eq!(l.index(), 0);
        // A reply that is no batch is EIO and leaves the buffer as it was.
        assert_eq!(l.load(&[2, 0, 0, 0]), Err(errno::EIO));
        assert_eq!(l.load(&[1, 0, 0, 0]), Err(errno::EIO));
        assert_eq!(l.load(&[]), Err(errno::EIO));
    }

    #[test]
    fn the_longest_names_are_kept_whole() {
        let name = [b'n'; p::NAME_MAX];
        let mut l = Listing::new();
        l.load(&reply(true, &[&name, &name, &name])).unwrap();
        for _ in 0..3 {
            assert_eq!(l.take().unwrap().name(), &name[..]);
        }
    }

    #[test]
    fn a_clone_carries_the_descriptions_without_fd_clofork_and_the_current_directory() {
        let held = [
            Held {
                handle: 5,
                clofork: false,
            },
            Held {
                handle: 6,
                clofork: true,
            },
            Held {
                handle: 5,
                clofork: false,
            },
            Held {
                handle: 9,
                clofork: false,
            },
        ];
        let plan = clone_plan(held, Some(11));
        assert_eq!(plan.handles(), [5, 9, 11]);
        assert!(plan.needed());
        // The current directory's description counts once.
        assert_eq!(clone_plan(held, Some(9)).handles(), [5, 9]);
        // Only FD_CLOFORK descriptions and no current directory under /data: nothing to carry, and
        // the child's slot stays empty.
        let none = clone_plan(
            [Held {
                handle: 6,
                clofork: true,
            }],
            None,
        );
        assert!(!none.needed());
        assert!(none.handles().is_empty());
        assert!(!clone_plan([], None).needed());
        // The current directory alone is enough.
        assert_eq!(clone_plan([], Some(3)).handles(), [3]);
        // No more than a message carries.
        let many: Vec<Held> = (0..40)
            .map(|handle| Held {
                handle,
                clofork: false,
            })
            .collect();
        assert_eq!(clone_plan(many, None).count, p::CLONE_MAX);
    }
}
