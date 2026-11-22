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
    pub const EMLINK: i32 = 31;
    pub const EXDEV: i32 = 18;
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
    pub handles: [u32; PLAN_MAX],
    pub count: usize,
}

/// The most descriptions a plan holds: three messages of CLONE and CLONE_MORE (the service may
/// hold more than the 32 it guarantees).
pub const PLAN_MAX: usize = 3 * p::CLONE_MAX;

impl ClonePlan {
    pub fn needed(&self) -> bool {
        self.count > 0
    }

    pub fn handles(&self) -> &[u32] {
        &self.handles[..self.count]
    }

    /// The messages the plan goes in: the first is CLONE, the rest CLONE_MORE.
    pub fn messages(&self) -> impl Iterator<Item = &[u32]> {
        self.handles().chunks(p::CLONE_MAX)
    }
}

/// Plans a CLONE from the descriptions of the table and the current directory's.
pub fn clone_plan(held: impl IntoIterator<Item = Held>, cwd: Option<u32>) -> ClonePlan {
    let mut plan = ClonePlan {
        handles: [0; PLAN_MAX],
        count: 0,
    };
    let mut add = |handle: u32| {
        if plan.count < PLAN_MAX && !plan.handles[..plan.count].contains(&handle) {
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

/// The flags of the layer's `open` the data volume looks at (the values of `posix_abi::constants`,
/// which a test of that crate keeps equal).
pub mod oflag {
    pub const ACCMODE: i32 = 3;
    pub const WRONLY: i32 = 1;
    pub const RDWR: i32 = 2;
    pub const CREAT: i32 = 0o100;
    pub const EXCL: i32 = 0o200;
    pub const TRUNC: i32 = 0o1000;
    pub const APPEND: i32 = 0o2000;
    pub const DIRECTORY: i32 = 65536;
    /// The layer's own bit for O_DSYNC and O_SYNC of the platform (either asks for every write to be
    /// durable); the RAM file service never sees it.
    pub const SYNC: i32 = 1 << 25;
}

/// What an `open` of a path of the volume sends: the flags of the protocol, the mode with the
/// creation mask applied, and whether the file is truncated by an open of its own first (an
/// open for reading with O_TRUNC: the service truncates only through a description with write
/// access, so the layer opens for writing with TRUNCATE, closes it, and opens for reading).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenPlan {
    pub flags: u32,
    pub mode: u32,
    pub truncate_first: bool,
}

/// Translates the flags of an `open` (and its mode and creation mask) into the plan of the
/// requests, or the errno: EINVAL for the access mode 3 and for O_CREAT on a directory, EISDIR for
/// a directory opened for writing or truncated.
pub fn open_plan(flags: i32, mode: u32, umask: u32) -> Result<OpenPlan, i32> {
    use oflag as o;
    let access = flags & o::ACCMODE;
    let (reads, writes) = match access {
        0 => (true, false),
        o::WRONLY => (false, true),
        o::RDWR => (true, true),
        _ => return Err(errno::EINVAL),
    };
    let directory = flags & o::DIRECTORY != 0;
    if directory && flags & o::CREAT != 0 {
        return Err(errno::EINVAL);
    }
    if directory && (writes || flags & o::TRUNC != 0) {
        return Err(errno::EISDIR);
    }
    let mut asked = 0;
    if reads {
        asked |= p::READ;
    }
    if writes {
        asked |= p::WRITE;
        // The end of the file and a durable write mean something for a description that writes.
        if flags & o::APPEND != 0 {
            asked |= p::APPEND;
        }
        if flags & o::SYNC != 0 {
            asked |= p::SYNC;
        }
    }
    if directory {
        asked |= p::DIRECTORY;
    }
    let creating = flags & o::CREAT != 0;
    if creating {
        asked |= p::CREATE;
        if flags & o::EXCL != 0 {
            asked |= p::EXCLUSIVE;
        }
    }
    let mut truncate_first = false;
    if flags & o::TRUNC != 0 {
        if writes {
            asked |= p::TRUNCATE;
        } else {
            truncate_first = true;
        }
    }
    let mode = if creating {
        mode & p::MODE_MASK & !(umask & 0o777)
    } else {
        0
    };
    Ok(OpenPlan {
        flags: asked,
        mode,
        truncate_first,
    })
}

/// The open that truncates for an open that only reads: the plan of its first request (write
/// access, TRUNCATE, and the creation the caller asked for), which closes at once.
pub fn truncating_open(plan: OpenPlan) -> OpenPlan {
    OpenPlan {
        flags: (plan.flags & (p::CREATE | p::EXCLUSIVE)) | p::WRITE | p::TRUNCATE,
        mode: plan.mode,
        truncate_first: false,
    }
}

/// The reading open that follows it: no creation, no exclusion.
pub fn reading_open(plan: OpenPlan) -> OpenPlan {
    OpenPlan {
        flags: plan.flags & !(p::CREATE | p::EXCLUSIVE),
        mode: 0,
        truncate_first: false,
    }
}

/// The bytes one WRITE message carries (`proto_data::MAX_WRITE`) and one PWRITE message: its
/// offset takes 8 bytes of the same message.
pub const WRITE_MAX: usize = p::MAX_WRITE;
pub const PWRITE_MAX: usize = p::MAX_WRITE - 8;

/// How a write of `total` bytes goes in messages of at most `max` bytes, and what it returns: the
/// sum of the messages that went, and only when none did the error of the one that failed (the
/// next call meets the same error: ENOSPC, EFBIG).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Splitter {
    total: usize,
    done: usize,
    max: usize,
}

impl Splitter {
    pub const fn new(total: usize, max: usize) -> Splitter {
        Splitter {
            total,
            done: 0,
            max,
        }
    }

    /// The bytes the next message carries, None when all went. A write of no bytes sends none.
    pub fn next_len(&self) -> Option<usize> {
        let left = self.total - self.done;
        (left > 0).then_some(left.min(self.max))
    }

    /// Where the next message starts in the buffer.
    pub fn at(&self) -> usize {
        self.done
    }

    /// A message of `asked` bytes was taken for `wrote`: whether another follows (the service
    /// wrote all of it and bytes are left).
    pub fn took(&mut self, asked: usize, wrote: usize) -> bool {
        let wrote = wrote.min(asked);
        self.done += wrote;
        wrote == asked && self.done < self.total
    }

    /// The result when a message failed with `error`.
    pub fn failed(&self, error: i32) -> Result<usize, i32> {
        if self.done > 0 {
            Ok(self.done)
        } else {
            Err(error)
        }
    }

    pub fn written(&self) -> usize {
        self.done
    }
}

/// What a call of one part in a cell or one `INLINE` message needs to know of the next part of a
/// call that goes in parts (READ_INTO, PREAD_INTO, WRITE_FROM, PWRITE_FROM with the leases of
/// `proto_data`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartPlan {
    /// Where the part starts in the call's bytes.
    pub at: usize,
    /// The bytes of the part.
    pub len: usize,
    /// More parts of the call follow this one (`MORE`).
    pub more: bool,
    /// The lease number the part carries: 0 on the first part, which asks for a lease, and on a
    /// part after one that was `UNLEASED`.
    pub lease: u32,
}

impl PartPlan {
    /// The `flags` field of the request.
    pub const fn flags(&self) -> u32 {
        if self.more { p::MORE } else { 0 }
    }
}

/// The reply to a part as the layer holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartAnswer {
    pub count: u32,
    pub flags: u32,
    pub lease: u32,
}

/// What a part's reply leaves to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The next part goes.
    Next,
    /// The call is over: all went, a part came back short (the end of the file, a limit), or the
    /// lease lapsed. `Parts::finish` gives the result.
    Done,
    /// The reply broke the protocol (more bytes than the part had, `LAPSED` with bytes). The call
    /// is over and a lease that may be live is the caller's to RELEASE (`Parts::live_lease`).
    Bad,
}

/// The state of a call of more than one message, which goes in parts of at most `max` bytes: the
/// bytes done, the lease the next part carries and what the replies said. It decides the parts, the
/// result (the sum; an error after some parts is that sum, the error alone when none went), and
/// the numbers the probes count. A read and a write go the same way: a part that comes back with
/// fewer bytes than it had ends the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parts {
    total: usize,
    done: usize,
    max: usize,
    lease: u32,
    lapsed: bool,
    unleased: u32,
}

impl Parts {
    pub const fn new(total: usize, max: usize) -> Parts {
        Parts {
            total,
            done: 0,
            max,
            lease: 0,
            lapsed: false,
            unleased: 0,
        }
    }

    /// The next part, None when the call is over. A call of no bytes sends none.
    pub fn next_part(&self) -> Option<PartPlan> {
        if self.lapsed {
            return None;
        }
        let left = self.total - self.done;
        if left == 0 {
            return None;
        }
        let len = left.min(self.max);
        Some(PartPlan {
            at: self.done,
            len,
            more: left > len,
            lease: self.lease,
        })
    }

    /// The bytes one part carries from now on: the call goes on by messages after its cell failed.
    /// The parts already done stay done.
    pub fn set_max(&mut self, max: usize) {
        self.max = max;
    }

    /// The reply to the part `plan`.
    pub fn took(&mut self, plan: &PartPlan, answer: PartAnswer) -> Step {
        if answer.flags & p::LAPSED != 0 {
            // The lease ended before the part: the part did not run, and the call is as short as
            // the parts before it.
            if answer.count != 0 {
                self.lease = 0;
                return Step::Bad;
            }
            self.lapsed = true;
            self.lease = 0;
            return Step::Done;
        }
        let count = answer.count as usize;
        if count > plan.len {
            // The lease this part may hold is released by the caller.
            self.lease = plan.lease.max(answer.lease);
            return Step::Bad;
        }
        self.done += count;
        if answer.flags & p::UNLEASED != 0 {
            self.unleased += 1;
        }
        // A lease goes on only after a part that left more to come and filled its bytes; a part
        // that fell short ended it in the service.
        self.lease = if plan.more && count == plan.len {
            answer.lease
        } else {
            0
        };
        if count < plan.len || self.done == self.total {
            Step::Done
        } else {
            Step::Next
        }
    }

    /// The lease a call that broke off by its own fault (`Step::Bad`) may still hold in the
    /// service, to RELEASE; None when there is none.
    pub const fn live_lease(&self) -> Option<u32> {
        if self.lease != 0 {
            Some(self.lease)
        } else {
            None
        }
    }

    /// The lease the next part carries, for the hook that gives a lease back at a jump.
    pub const fn lease(&self) -> u32 {
        self.lease
    }

    /// Whether a reply said `LAPSED`: the call is short because its lease ran out.
    pub const fn lapsed(&self) -> bool {
        self.lapsed
    }

    /// How many replies said `UNLEASED`.
    pub const fn unleased(&self) -> u32 {
        self.unleased
    }

    /// The bytes done.
    pub const fn done(&self) -> usize {
        self.done
    }

    /// The result of a call that ended without an error of its own.
    pub const fn finish(&self) -> usize {
        self.done
    }

    /// The result when a part failed with `error` (what the parts before it did is the sum).
    pub fn failed(&self, error: i32) -> Result<usize, i32> {
        if self.done > 0 {
            Ok(self.done)
        } else {
            Err(error)
        }
    }
}

/// Whether a call of `total` bytes fits in one message of the old methods: `max` is the bytes of
/// one message of the method (`WRITE_MAX`, `PWRITE_MAX`, `proto_data::MAX_READ`).
pub const fn fits_one_message(total: usize, max: usize) -> bool {
    total <= max
}

/// The bytes of a part in the message when the call has no cell: `INLINE_WRITE`, `INLINE_PWRITE`
/// or `INLINE_READ` by the method.
pub const fn inline_max(write: bool, positional: bool) -> usize {
    match (write, positional) {
        (false, _) => p::INLINE_READ,
        (true, false) => p::INLINE_WRITE,
        (true, true) => p::INLINE_PWRITE,
    }
}

/// The bytes of a part of a call: the cell, or the message.
pub const fn part_max(cell: bool, write: bool, positional: bool) -> usize {
    if cell {
        p::CELL_BYTES
    } else {
        inline_max(write, positional)
    }
}

/// Copies `len` bytes that start `at` bytes into the concatenation of the buffers of `iov` to
/// `out` (the part of a `writev` that goes in a cell or a message). The bytes copied: `len`
/// unless the buffers end first.
pub fn gather(iov: &[&[u8]], at: usize, out: &mut [u8]) -> usize {
    let mut skip = at;
    let mut done = 0;
    for part in iov {
        if skip >= part.len() {
            skip -= part.len();
            continue;
        }
        let take = (part.len() - skip).min(out.len() - done);
        out[done..done + take].copy_from_slice(&part[skip..skip + take]);
        done += take;
        skip = 0;
        if done == out.len() {
            break;
        }
    }
    done
}

/// Copies `bytes` into the concatenation of the buffers of `iov` from `at` bytes in (the part of
/// a `readv` that came back). The bytes copied: all unless the buffers end first.
pub fn scatter(iov: &mut [&mut [u8]], at: usize, bytes: &[u8]) -> usize {
    let mut skip = at;
    let mut done = 0;
    for part in iov.iter_mut() {
        if skip >= part.len() {
            skip -= part.len();
            continue;
        }
        let take = (part.len() - skip).min(bytes.len() - done);
        part[skip..skip + take].copy_from_slice(&bytes[done..done + take]);
        done += take;
        skip = 0;
        if done == bytes.len() {
            break;
        }
    }
    done
}

/// The total bytes of the buffers of a vector.
pub fn total_len(iov: &[&[u8]]) -> usize {
    iov.iter()
        .map(|part| part.len())
        .fold(0, usize::saturating_add)
}

/// The total bytes of the buffers of a vector to read into.
pub fn total_len_mut(iov: &[&mut [u8]]) -> usize {
    iov.iter()
        .map(|part| part.len())
        .fold(0, usize::saturating_add)
}

/// A time of `utimensat` (the seconds and the nanoseconds or a mark, as the layer holds them) as
/// the protocol has it: a time outside the range the volume keeps (i64 nanoseconds) is the nearest
/// end of it.
pub fn time_spec(seconds: u64, nanos: u64) -> p::TimeSpec {
    if nanos == proto_fs::TIME_NOW {
        return p::TimeSpec::Now;
    }
    if nanos == proto_fs::TIME_OMIT {
        return p::TimeSpec::Omit;
    }
    let total = i128::from(seconds.cast_signed()) * 1_000_000_000 + i128::from(nanos);
    let clamped = total.clamp(i128::from(i64::MIN) + 2, i128::from(i64::MAX) - 2);
    p::TimeSpec::At(clamped as i64)
}

/// The errno of a `link` whose two paths are both on the volume: the volume has one name for a
/// file (EMLINK), a directory has no second name (EPERM).
pub fn link_errno(old_is_directory: bool) -> i32 {
    if old_is_directory {
        errno::EPERM
    } else {
        errno::EMLINK
    }
}

/// Where the two paths of a `rename` or `link` are: both on the volume, or one of them (EXDEV).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Neither,
    Both,
    Across,
}

pub fn route_of(old_on_volume: bool, new_on_volume: bool) -> Route {
    match (old_on_volume, new_on_volume) {
        (false, false) => Route::Neither,
        (true, true) => Route::Both,
        _ => Route::Across,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
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
            (p::NO_WINDOW, EIO),
        ] {
            assert_eq!(errno_of(code), want, "{code}");
        }
        // Every code the protocol lists is in the table above, and a code it does not have is EIO.
        assert_eq!(p::CODES.len(), 24);
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
        // More than a message carries go in more messages, up to three.
        let many: Vec<Held> = (0..100)
            .map(|handle| Held {
                handle,
                clofork: false,
            })
            .collect();
        let plan = clone_plan(many, None);
        assert_eq!(plan.count, PLAN_MAX);
        let sizes: Vec<usize> = plan.messages().map(<[u32]>::len).collect();
        assert_eq!(sizes, [p::CLONE_MAX, p::CLONE_MAX, p::CLONE_MAX]);
        let forty: Vec<Held> = (0..40)
            .map(|handle| Held {
                handle,
                clofork: false,
            })
            .collect();
        let sizes: Vec<usize> = clone_plan(forty, None)
            .messages()
            .map(<[u32]>::len)
            .collect();
        assert_eq!(sizes, [32, 8]);
    }

    #[test]
    fn open_flags_become_the_flags_of_the_protocol() {
        use oflag as o;
        let plan = |f, m, u| open_plan(f, m, u).unwrap();
        assert_eq!(plan(0, 0, 0).flags, p::READ);
        assert_eq!(plan(o::WRONLY, 0, 0).flags, p::WRITE);
        assert_eq!(plan(o::RDWR, 0, 0).flags, p::READ | p::WRITE);
        let all = plan(
            o::WRONLY | o::CREAT | o::EXCL | o::TRUNC | o::APPEND | o::SYNC,
            0o666,
            0o022,
        );
        assert_eq!(
            all.flags,
            p::WRITE | p::CREATE | p::EXCLUSIVE | p::TRUNCATE | p::APPEND | p::SYNC
        );
        assert_eq!(all.mode, 0o644, "the creation mask applies");
        assert!(!all.truncate_first);
        // O_APPEND is kept for a description that writes: losing it would lose the atomic end.
        assert!(plan(o::RDWR | o::APPEND, 0, 0).flags & p::APPEND != 0);
        // And means nothing for one that only reads.
        assert_eq!(plan(o::APPEND, 0, 0).flags, p::READ);
        assert_eq!(plan(o::DIRECTORY, 0, 0).flags, p::READ | p::DIRECTORY);
    }

    #[test]
    fn a_mode_matters_only_for_a_creation() {
        use oflag as o;
        assert_eq!(open_plan(o::WRONLY, 0o777, 0).unwrap().mode, 0);
        assert_eq!(
            open_plan(o::WRONLY | o::CREAT, 0o7777, 0o027).unwrap().mode,
            0o7750
        );
        // EXCL with no CREAT asks for nothing.
        assert_eq!(open_plan(o::EXCL, 0, 0).unwrap().flags, p::READ);
    }

    #[test]
    fn open_refuses_what_has_no_meaning() {
        use oflag as o;
        assert_eq!(open_plan(3, 0, 0), Err(errno::EINVAL));
        assert_eq!(open_plan(o::DIRECTORY | o::CREAT, 0, 0), Err(errno::EINVAL));
        assert_eq!(
            open_plan(o::DIRECTORY | o::WRONLY, 0, 0),
            Err(errno::EISDIR)
        );
        assert_eq!(open_plan(o::DIRECTORY | o::TRUNC, 0, 0), Err(errno::EISDIR));
    }

    #[test]
    fn truncation_with_reading_is_an_open_of_its_own_first() {
        use oflag as o;
        let plan = open_plan(o::TRUNC | o::CREAT | o::EXCL, 0o600, 0).unwrap();
        assert!(plan.truncate_first);
        assert_eq!(plan.flags & p::TRUNCATE, 0);
        let first = truncating_open(plan);
        assert_eq!(
            first.flags,
            p::WRITE | p::TRUNCATE | p::CREATE | p::EXCLUSIVE
        );
        assert_eq!(first.mode, 0o600);
        let second = reading_open(plan);
        assert_eq!(second.flags, p::READ);
        assert_eq!(second.mode, 0);
    }

    #[test]
    fn a_write_goes_in_messages_and_the_sum_comes_back_after_a_failure() {
        let mut s = Splitter::new(2500, 1012);
        assert_eq!(s.next_len(), Some(1012));
        assert!(s.took(1012, 1012));
        assert_eq!((s.at(), s.next_len()), (1012, Some(1012)));
        assert!(s.took(1012, 1012));
        assert_eq!(s.next_len(), Some(476));
        // No room for the last message: the sum is the result, and the next call fails.
        assert_eq!(s.failed(errno::ENOSPC), Ok(2024));
        let first = Splitter::new(10, 4);
        assert_eq!(first.failed(errno::ENOSPC), Err(errno::ENOSPC));
        // A short message ends the write.
        let mut t = Splitter::new(2000, 1012);
        assert!(!t.took(1012, 500));
        assert_eq!(t.written(), 500);
        // A write of no bytes sends none.
        assert_eq!(Splitter::new(0, 1012).next_len(), None);
        let mut done = Splitter::new(1012, 1012);
        assert!(!done.took(1012, 1012));
        assert_eq!(done.next_len(), None);
    }

    /// The largest piece of a write and of a pwrite fits one message, and one byte more does not.
    /// (The planted fault: the length of a WRITE for a PWRITE made every pwrite of more than 1,004
    /// bytes fail as EIO, and the asynchronous writes of the Open POSIX tests with it.)
    #[test]
    fn a_piece_of_a_write_and_of_a_pwrite_fits_one_message() {
        let mut w = proto_wire::Writer::new();
        assert!(p::write(1, &[0; WRITE_MAX], &mut w).is_ok());
        assert!(p::write(1, &[0; WRITE_MAX + 1], &mut proto_wire::Writer::new()).is_err());
        let mut w = proto_wire::Writer::new();
        assert!(p::pwrite(1, u64::MAX, &[0; PWRITE_MAX], &mut w).is_ok());
        assert!(p::pwrite(1, 0, &[0; PWRITE_MAX + 1], &mut proto_wire::Writer::new()).is_err());
        assert!(p::pwrite(1, 0, &[0; WRITE_MAX], &mut proto_wire::Writer::new()).is_err());
    }

    #[test]
    fn times_are_marks_or_nanoseconds_inside_the_range() {
        assert_eq!(time_spec(0, proto_fs::TIME_NOW), p::TimeSpec::Now);
        assert_eq!(time_spec(0, proto_fs::TIME_OMIT), p::TimeSpec::Omit);
        assert_eq!(time_spec(5, 7), p::TimeSpec::At(5_000_000_007));
        assert_eq!(
            time_spec((-1i64).cast_unsigned(), 0),
            p::TimeSpec::At(-1_000_000_000)
        );
        let p::TimeSpec::At(top) = time_spec(i64::MAX.cast_unsigned(), 0) else {
            panic!()
        };
        assert!(top > i64::MAX - 10, "clamped to the end of the range");
    }

    #[test]
    fn a_link_and_a_rename_across_the_mount_are_xdev_by_their_routes() {
        assert_eq!(route_of(false, false), Route::Neither);
        assert_eq!(route_of(true, true), Route::Both);
        assert_eq!(route_of(true, false), Route::Across);
        assert_eq!(route_of(false, true), Route::Across);
        assert_eq!(link_errno(false), errno::EMLINK);
        assert_eq!(link_errno(true), errno::EPERM);
    }

    fn ans(count: usize, flags: u32, lease: u32) -> PartAnswer {
        PartAnswer {
            count: count as u32,
            flags,
            lease,
        }
    }

    /// Runs a call of `total` bytes in parts of `max` against a service that gives lease 7 and
    /// takes every part whole: the plans it sent.
    fn run_whole(total: usize, max: usize) -> (Vec<PartPlan>, Parts) {
        let mut parts = Parts::new(total, max);
        let mut sent = Vec::new();
        while let Some(plan) = parts.next_part() {
            sent.push(plan);
            let lease = if plan.more { 7 } else { 0 };
            let step = parts.took(&plan, ans(plan.len, 0, lease));
            assert_ne!(step, Step::Bad);
            if step == Step::Done {
                break;
            }
        }
        (sent, parts)
    }

    #[test]
    fn a_call_goes_in_parts_of_the_cell_with_more_and_the_lease() {
        let total = 3 * p::CELL_BYTES + 100;
        let (sent, parts) = run_whole(total, p::CELL_BYTES);
        assert_eq!(sent.len(), 4);
        let at: Vec<usize> = sent.iter().map(|x| x.at).collect();
        assert_eq!(at, [0, 65_536, 131_072, 196_608]);
        let lens: Vec<usize> = sent.iter().map(|x| x.len).collect();
        assert_eq!(lens, [65_536, 65_536, 65_536, 100]);
        let more: Vec<bool> = sent.iter().map(|x| x.more).collect();
        assert_eq!(more, [true, true, true, false]);
        // The first part asks for a lease, the next ones carry its number.
        let lease: Vec<u32> = sent.iter().map(|x| x.lease).collect();
        assert_eq!(lease, [0, 7, 7, 7]);
        assert_eq!(sent[0].flags(), p::MORE);
        assert_eq!(sent[3].flags(), 0);
        assert_eq!(parts.finish(), total);
        assert_eq!(parts.live_lease(), None);
        assert!(!parts.lapsed());
    }

    #[test]
    fn a_call_of_exact_cells_ends_without_more_on_the_last() {
        let (sent, parts) = run_whole(2 * p::CELL_BYTES, p::CELL_BYTES);
        assert_eq!(sent.len(), 2);
        assert!(sent[0].more && !sent[1].more);
        assert_eq!(parts.finish(), 2 * p::CELL_BYTES);
    }

    #[test]
    fn a_call_of_no_bytes_sends_no_part() {
        assert_eq!(Parts::new(0, p::CELL_BYTES).next_part(), None);
    }

    #[test]
    fn inline_parts_have_the_bounds_of_their_method() {
        assert_eq!(part_max(true, true, false), p::CELL_BYTES);
        assert_eq!(part_max(false, true, false), 996);
        assert_eq!(part_max(false, true, true), 988);
        assert_eq!(part_max(false, false, true), 1008);
        assert_eq!(part_max(false, false, false), 1008);
        let (sent, _) = run_whole(5000, part_max(false, true, true));
        assert_eq!(sent.len(), 6);
        assert!(sent.iter().all(|x| x.len <= 988));
        assert!(fits_one_message(WRITE_MAX, WRITE_MAX));
        assert!(!fits_one_message(WRITE_MAX + 1, WRITE_MAX));
    }

    #[test]
    fn a_short_part_ends_the_call_with_the_sum() {
        // A read that meets the end of the file in the third part.
        let mut parts = Parts::new(10 * p::CELL_BYTES, p::CELL_BYTES);
        for k in 0..3 {
            let plan = parts.next_part().unwrap();
            let got = if k == 2 { 1234 } else { plan.len };
            let lease = if got == plan.len { 9 } else { 0 };
            let step = parts.took(&plan, ans(got, 0, lease));
            assert_eq!(step, if k == 2 { Step::Done } else { Step::Next });
        }
        assert_eq!(parts.finish(), 2 * p::CELL_BYTES + 1234);
        assert_eq!(parts.live_lease(), None);
        assert_eq!(
            parts.next_part().map(|x| x.at),
            Some(2 * p::CELL_BYTES + 1234)
        );
        // The caller stops on Done: next_part is not asked again.
    }

    #[test]
    fn a_read_at_the_end_of_the_file_is_the_sum_of_the_parts_before() {
        let mut parts = Parts::new(2 * p::CELL_BYTES, p::CELL_BYTES);
        let plan = parts.next_part().unwrap();
        assert_eq!(parts.took(&plan, ans(0, 0, 0)), Step::Done);
        assert_eq!(parts.finish(), 0);
    }

    #[test]
    fn a_lapsed_lease_gives_a_short_result_and_is_noted() {
        let mut parts = Parts::new(4 * p::CELL_BYTES, p::CELL_BYTES);
        let first = parts.next_part().unwrap();
        assert_eq!(parts.took(&first, ans(first.len, 0, 5)), Step::Next);
        let second = parts.next_part().unwrap();
        assert_eq!(second.lease, 5);
        assert_eq!(parts.took(&second, ans(0, p::LAPSED, 0)), Step::Done);
        assert!(parts.lapsed());
        assert_eq!(parts.finish(), p::CELL_BYTES);
        assert_eq!(parts.next_part(), None);
        assert_eq!(parts.live_lease(), None);
    }

    #[test]
    fn a_lapsed_reply_with_bytes_breaks_the_protocol() {
        let mut parts = Parts::new(2 * p::CELL_BYTES, p::CELL_BYTES);
        let first = parts.next_part().unwrap();
        assert_eq!(parts.took(&first, ans(10, p::LAPSED, 0)), Step::Bad);
    }

    #[test]
    fn a_reply_with_more_bytes_than_the_part_is_bad_and_its_lease_is_to_release() {
        let mut parts = Parts::new(2 * p::CELL_BYTES, p::CELL_BYTES);
        let first = parts.next_part().unwrap();
        assert_eq!(parts.took(&first, ans(p::CELL_BYTES + 1, 0, 3)), Step::Bad);
        assert_eq!(parts.live_lease(), Some(3));
        assert_eq!(parts.done(), 0);
        assert_eq!(parts.failed(5), Err(5));
        // Bad after a part that went well keeps the lease the part before it gave.
        let mut parts = Parts::new(3 * p::CELL_BYTES, p::CELL_BYTES);
        let a = parts.next_part().unwrap();
        assert_eq!(parts.took(&a, ans(a.len, 0, 3)), Step::Next);
        let b = parts.next_part().unwrap();
        assert_eq!(parts.took(&b, ans(b.len + 1, 0, 0)), Step::Bad);
        assert_eq!(parts.live_lease(), Some(3));
        assert_eq!(parts.failed(5), Ok(p::CELL_BYTES));
    }

    #[test]
    fn an_unleased_part_runs_alone_and_the_next_asks_again() {
        let mut parts = Parts::new(3 * p::CELL_BYTES, p::CELL_BYTES);
        let first = parts.next_part().unwrap();
        assert_eq!(
            parts.took(&first, ans(first.len, p::UNLEASED, 0)),
            Step::Next
        );
        assert_eq!(parts.unleased(), 1);
        let second = parts.next_part().unwrap();
        assert_eq!((second.lease, second.more), (0, true));
        assert_eq!(parts.took(&second, ans(second.len, 0, 4)), Step::Next);
        let third = parts.next_part().unwrap();
        assert_eq!((third.lease, third.more), (4, false));
        assert_eq!(parts.took(&third, ans(third.len, 0, 0)), Step::Done);
        assert_eq!(parts.finish(), 3 * p::CELL_BYTES);
        assert_eq!(parts.unleased(), 1);
    }

    #[test]
    fn an_error_after_some_parts_is_the_sum_and_the_first_alone_is_the_error() {
        let mut parts = Parts::new(3 * p::CELL_BYTES, p::CELL_BYTES);
        assert_eq!(parts.failed(28), Err(28));
        let first = parts.next_part().unwrap();
        assert_eq!(parts.took(&first, ans(first.len, 0, 2)), Step::Next);
        assert_eq!(parts.failed(28), Ok(p::CELL_BYTES));
    }

    #[test]
    fn the_call_goes_on_by_messages_after_the_cell_is_given_up() {
        let mut parts = Parts::new(p::CELL_BYTES + 2000, p::CELL_BYTES);
        let first = parts.next_part().unwrap();
        assert_eq!(parts.took(&first, ans(first.len, 0, 6)), Step::Next);
        parts.set_max(p::INLINE_WRITE);
        let next = parts.next_part().unwrap();
        assert_eq!(
            (next.at, next.len, next.more, next.lease),
            (p::CELL_BYTES, 996, true, 6)
        );
    }

    #[test]
    fn a_part_that_filled_its_bytes_but_lost_its_lease_asks_for_another() {
        let mut parts = Parts::new(2 * p::CELL_BYTES, p::CELL_BYTES);
        let first = parts.next_part().unwrap();
        assert_eq!(parts.took(&first, ans(first.len, 0, 0)), Step::Next);
        assert_eq!(parts.next_part().unwrap().lease, 0);
    }

    #[test]
    fn gather_and_scatter_walk_a_vector_across_its_buffers() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5];
        let c: [u8; 0] = [];
        let d = [6u8, 7, 8, 9];
        let iov: [&[u8]; 4] = [&a, &b, &c, &d];
        assert_eq!(total_len(&iov), 9);
        let mut out = [0u8; 4];
        assert_eq!(gather(&iov, 2, &mut out), 4);
        assert_eq!(out, [3, 4, 5, 6]);
        let mut out = [0u8; 8];
        assert_eq!(gather(&iov, 6, &mut out), 3);
        assert_eq!(&out[..3], &[7, 8, 9]);
        assert_eq!(gather(&iov, 9, &mut out), 0);

        let mut x = [0u8; 3];
        let mut y = [0u8; 0];
        let mut z = [0u8; 4];
        let mut vec: [&mut [u8]; 3] = [&mut x, &mut y, &mut z];
        assert_eq!(total_len_mut(&vec), 7);
        assert_eq!(scatter(&mut vec, 2, &[1, 2, 3]), 3);
        assert_eq!(scatter(&mut vec, 5, &[9, 9, 9, 9]), 2);
        assert_eq!(x, [0, 0, 1]);
        assert_eq!(z, [2, 3, 9, 9]);
    }

    #[test]
    fn a_vector_in_cell_parts_reassembles_to_the_same_bytes() {
        // 3 buffers of odd sizes across 3 parts of 64 KiB.
        let sizes = [70_001usize, 5, 100_000, 31_000];
        let data: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(k, n)| (0..*n).map(|i| (i * 7 + k * 13) as u8).collect())
            .collect();
        let iov: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let total = total_len(&iov);
        let mut parts = Parts::new(total, p::CELL_BYTES);
        let mut joined = Vec::new();
        let mut cell = vec![0u8; p::CELL_BYTES];
        while let Some(plan) = parts.next_part() {
            let n = gather(&iov, plan.at, &mut cell[..plan.len]);
            assert_eq!(n, plan.len);
            joined.extend_from_slice(&cell[..n]);
            if parts.took(&plan, ans(plan.len, 0, if plan.more { 1 } else { 0 })) == Step::Done {
                break;
            }
        }
        assert_eq!(joined, data.concat());
    }
}
