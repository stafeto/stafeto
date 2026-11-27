// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the service asks of the data file service (the data volume, `proto_data`) and of the RAM
//! file service (the lower set, its boot profile), as two traits the program implements with
//! calls and the host tests with a tree in memory. A status is the status of the reply: a code of
//! `proto_data` for the volume, a code of `proto_fs` for the lower set.

use proto_data::Stat;
use proto_wire::Status;

pub type R<T> = Result<T, Status>;

/// The entry a directory listing visits: the number, the kind of `proto_data` (`KIND_FILE`,
/// `KIND_DIRECTORY`) and the name.
pub type Visit<'a> = &'a mut dyn FnMut(u64, u32, &[u8]);

/// The data volume.
pub trait Volume {
    /// A pass for a description (EXPORT), which a program spends with ADOPT.
    type Pass;

    fn open(&mut self, path: &[u8], flags: u32, mode: u32) -> R<u32>;
    /// OPEN with CREATE and EXCLUSIVE that gives the new file the number `ino` (a native client's
    /// request).
    fn open_numbered(&mut self, path: &[u8], flags: u32, mode: u32, ino: u64) -> R<u32>;
    /// The size of the open file `handle` is set to `size`.
    fn truncate(&mut self, handle: u32, size: u64) -> R<()>;
    fn chmod(&mut self, path: &[u8], mode: u32) -> R<()>;
    /// `uid` and `gid` of `proto_data::UID_KEEP` leave the field as it is.
    fn chown(&mut self, path: &[u8], uid: u32, gid: u32) -> R<()>;
    /// The times, in the words of `proto_data::TimeSpec`.
    fn utimens(&mut self, path: &[u8], atime: i64, mtime: i64) -> R<()>;
    fn close(&mut self, handle: u32) -> R<()>;
    fn read(&mut self, handle: u32, out: &mut [u8]) -> R<usize>;
    fn write(&mut self, handle: u32, bytes: &[u8]) -> R<usize>;
    fn fsync(&mut self, handle: u32) -> R<()>;
    fn stat(&mut self, path: &[u8]) -> R<Stat>;
    fn mkdir(&mut self, path: &[u8], mode: u32) -> R<()>;
    fn rename(&mut self, from: &[u8], to: &[u8]) -> R<()>;
    fn unlink(&mut self, path: &[u8]) -> R<()>;
    fn rmdir(&mut self, path: &[u8]) -> R<()>;
    /// One batch of the entries of the directory description `handle`, `.` and `..` included;
    /// whether more follow.
    fn read_dir(&mut self, handle: u32, visit: Visit<'_>) -> R<bool>;
    /// The pass of the description `handle`.
    fn export(&mut self, handle: u32) -> R<Self::Pass>;
    /// One batch of the entries of the directory description `handle` as the bytes of the reply
    /// after its `more` word (`proto_data::read_dir_reply`: for each entry the number u64, the kind
    /// u32, the length of the name u32 and the name) copied to `out`; the length and whether more
    /// follow. The build of the index reads a batch in one step and takes its entries in others.
    fn read_dir_raw(&mut self, handle: u32, out: &mut [u8; BATCH_BYTES]) -> R<(usize, bool)> {
        let mut len = 0;
        let mut full = false;
        let more = self.read_dir(handle, &mut |ino, kind, name| {
            let end = len + ENTRY_HEAD + name.len();
            if end > out.len() {
                full = true;
                return;
            }
            out[len..len + 8].copy_from_slice(&ino.to_le_bytes());
            out[len + 8..len + 12].copy_from_slice(&kind.to_le_bytes());
            out[len + 12..len + 16].copy_from_slice(&(name.len() as u32).to_le_bytes());
            out[len + ENTRY_HEAD..end].copy_from_slice(name);
            len = end;
        })?;
        if full {
            return Err(Status::BadSize);
        }
        Ok((len, more))
    }
}

/// The bytes of a batch of a listing: a message less its status and its `more` word.
pub const BATCH_BYTES: usize = abi::MESSAGE_MAX;
/// The bytes before the name of an entry of a batch.
pub const ENTRY_HEAD: usize = 16;

/// The entry at `at` of a raw batch (`Volume::read_dir_raw`): the number, the kind, the name and
/// the offset after it; None past the end or for a broken entry.
pub fn raw_entry(batch: &[u8], at: usize) -> Option<(u64, u32, &[u8], usize)> {
    let head = batch.get(at..at + ENTRY_HEAD)?;
    let ino = u64::from_le_bytes(head[..8].try_into().ok()?);
    let kind = u32::from_le_bytes(head[8..12].try_into().ok()?);
    let len = u32::from_le_bytes(head[12..16].try_into().ok()?) as usize;
    let end = at + ENTRY_HEAD + len;
    Some((ino, kind, batch.get(at + ENTRY_HEAD..end)?, end))
}

/// What the lower set says of a name: the kind of `NodeInfo` (1 directory, 2 file, 5 symbolic
/// link, others for the rest), the mode, the owner and the number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowerStat {
    pub kind: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
}

/// The lower set: the tree of the RAM file service as the boot profile of the service sees it. A
/// directory is read by its path and kept open between the requests of a listing.
///
/// A path of the lower set is resolved one step a call: the RAM file service walks a path in steps
/// that its caller polls, and each step costs it about 1,400 ticks, so a path of many components is
/// never resolved inside one step of the loop. `stat_start` and `open_dir_start` make the
/// preparation (one round trip), the `poll` of each is one more round trip of the resolve or of
/// its finishing call, and the caller asks again until the answer comes. After an answer or an
/// error of a poll the preparation is spent; a caller that drops one earlier gives it back with
/// `stat_cancel` or `close_dir`, which are no-ops for a spent one.
pub trait Lower {
    /// A directory of the lower set: being opened, then open.
    type Dir;
    /// A stat in flight.
    type Probe;

    /// Starts the open of the directory at `path`; the directory is not open until `open_dir_poll`
    /// says so.
    fn open_dir_start(&mut self, path: &[u8]) -> R<Self::Dir>;
    /// One step of the open of `dir`; true when it is open. An error spends the preparation.
    fn open_dir_poll(&mut self, dir: &mut Self::Dir) -> R<bool>;
    /// The next entry: the number, the kind of `NodeInfo` and the name copied to `name`; None at
    /// the end. `.` and `..` are among them.
    fn next(&mut self, dir: &mut Self::Dir, name: &mut [u8; 256]) -> R<Option<(u64, u32, usize)>>;
    /// Closes a directory, open or still being opened.
    fn close_dir(&mut self, dir: Self::Dir);
    /// The text of the link at `path`, copied to `out`.
    fn readlink(&mut self, path: &[u8], out: &mut [u8]) -> R<usize>;
    /// Starts the stat of `path`; a link at the end is looked at (not followed) when `follow` is
    /// false.
    fn stat_start(&mut self, path: &[u8], follow: bool) -> R<Self::Probe>;
    /// One step of the stat: the attributes when the answer is in, None while the resolve goes
    /// on. NO_ENTRY and NOT_DIRECTORY say there is no such name. An answer or an error spends the
    /// preparation.
    fn stat_poll(&mut self, probe: &mut Self::Probe) -> R<Option<LowerStat>>;
    /// Gives a stat that is not answered back.
    fn stat_cancel(&mut self, probe: Self::Probe);
}
