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
}

/// The lower set: the tree of the RAM file service as the boot profile of the service sees it. A
/// directory is read by its path and kept open between the requests of a listing.
pub trait Lower {
    type Dir;

    fn open_dir(&mut self, path: &[u8]) -> R<Self::Dir>;
    /// The next entry: the number, the kind of `NodeInfo` and the name copied to `name`; None at
    /// the end. `.` and `..` are among them.
    fn next(&mut self, dir: &mut Self::Dir, name: &mut [u8; 256]) -> R<Option<(u64, u32, usize)>>;
    fn close_dir(&mut self, dir: Self::Dir);
    /// The text of the link at `path`, copied to `out`.
    fn readlink(&mut self, path: &[u8], out: &mut [u8]) -> R<usize>;
}
