// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded RAM files and per-client open descriptions for the first POSIX
//! userspace experiment. A single service thread owns `Ram`; each IPC
//! session owns its own `Fds`, so closing a session closes its files.

#![cfg_attr(not(test), no_std)]

use proto_fs::{
    BAD_FD, IS_DIRECTORY, Metadata, NO_ENTRY, NO_SPACE, NodeInfo, READ_ONLY, WRITE_ONLY,
};

const FILE_CAPACITY: usize = 1024;
const OPEN_MAX: usize = 32;
const MOTD: &[u8] = b"stafeto ramfs\n";

pub const DIR: u32 = 1;
pub const REG: u32 = 2;

pub fn directory_entry(path: &str, index: u32) -> Result<Option<(&'static str, u32)>, u32> {
    let entries: &[(&str, u32)] = match path {
        "/" => &[(".", DIR), ("..", DIR), ("etc", DIR), ("tmp", DIR)],
        "/etc" => &[(".", DIR), ("..", DIR), ("motd", REG)],
        "/tmp" => &[(".", DIR), ("..", DIR), ("probe", REG)],
        _ => return Err(NO_ENTRY),
    };
    Ok(entries.get(index as usize).copied())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryRecord {
    pub name: &'static str,
    pub kind: u32,
    pub inode: u64,
}

fn directory_count(path: &str) -> i64 {
    if path == "/" { 4 } else { 3 }
}

#[derive(Clone, Copy)]
enum File {
    Root,
    Etc,
    Tmp,
    Motd,
    Scratch,
}

#[derive(Clone, Copy)]
struct Open {
    file: File,
    offset: i64,
    flags: u32,
}

pub struct Fds {
    open: [Option<Open>; OPEN_MAX],
}

impl Default for Fds {
    fn default() -> Self {
        Self {
            open: [None; OPEN_MAX],
        }
    }
}

impl Fds {
    pub fn open(&mut self, path: &str, flags: u32) -> Result<u32, u32> {
        if flags & !7 != 0 || flags & 3 == 3 {
            return Err(proto_wire::BAD_SIZE);
        }
        let directory_only = flags & proto_fs::DIRECTORY_ONLY != 0;
        let flags = flags & 3;
        let file = match path {
            "/" | "/etc" | "/tmp" if flags != READ_ONLY => return Err(IS_DIRECTORY),
            "/" => File::Root,
            "/etc" => File::Etc,
            "/tmp" => File::Tmp,
            "/etc/motd" if flags == READ_ONLY => File::Motd,
            "/etc/motd" => return Err(proto_fs::ACCESS_DENIED),
            "/tmp/probe" => File::Scratch,
            _ => return Err(NO_ENTRY),
        };
        if directory_only && !file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        let slot = self
            .open
            .iter_mut()
            .position(|fd| fd.is_none())
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
        self.open[slot] = Some(Open {
            file,
            offset: 0,
            flags,
        });
        Ok(slot as u32 + 3)
    }

    fn get(&self, fd: u32) -> Result<Open, u32> {
        let slot = fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        self.open.get(slot).and_then(|fd| *fd).ok_or(BAD_FD)
    }

    fn get_mut(&mut self, fd: u32) -> Result<&mut Open, u32> {
        let slot = fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        self.open
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(BAD_FD)
    }

    pub fn close(&mut self, fd: u32) -> Result<(), u32> {
        self.get(fd)?;
        self.open[(fd - 3) as usize] = None;
        Ok(())
    }

    pub fn seek(&mut self, fd: u32, offset: u32) -> Result<u32, u32> {
        let open = self.get_mut(fd)?;
        open.offset = i64::from(offset);
        Ok(offset)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileTimes {
    access: u64,
    modify: u64,
    change: u64,
}

impl File {
    fn is_directory(self) -> bool {
        matches!(self, Self::Root | Self::Etc | Self::Tmp)
    }

    fn index(self) -> usize {
        match self {
            Self::Root => 0,
            Self::Etc => 1,
            Self::Tmp => 2,
            Self::Motd => 3,
            Self::Scratch => 4,
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Root => "/",
            Self::Etc => "/etc",
            Self::Tmp => "/tmp",
            Self::Motd => "/etc/motd",
            Self::Scratch => "/tmp/probe",
        }
    }
}

pub struct Ram {
    scratch: [u8; FILE_CAPACITY],
    len: usize,
    times: [FileTimes; 5],
}

impl Default for Ram {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Ram {
    /// Seeded namespace with one creation time on the caller's file clock.
    pub fn new(now: u64) -> Self {
        Self {
            scratch: [0; FILE_CAPACITY],
            len: 0,
            times: [FileTimes {
                access: now,
                modify: now,
                change: now,
            }; 5],
        }
    }

    pub fn information(&self, path: &str) -> Result<NodeInfo, u32> {
        let (kind, inode, links, permissions, file) = match path {
            "/" => (DIR, 1, 4, 0o555, File::Root),
            "/etc" => (DIR, 2, 2, 0o555, File::Etc),
            "/tmp" => (DIR, 3, 2, 0o555, File::Tmp),
            "/etc/motd" => (REG, 4, 1, 0o444, File::Motd),
            "/tmp/probe" => (REG, 5, 1, 0o644, File::Scratch),
            _ => return Err(NO_ENTRY),
        };
        let size = self.bytes(file).len() as u64;
        let times = self.times[file.index()];
        Ok(NodeInfo {
            kind,
            permissions,
            device: 1,
            special_device: 0,
            inode,
            links,
            uid: 0,
            gid: 0,
            size,
            block_size: FILE_CAPACITY as u32,
            blocks: size.div_ceil(512),
            access_ns: times.access,
            modify_ns: times.modify,
            change_ns: times.change,
        })
    }

    pub fn descriptor_information(&self, fds: &Fds, fd: u32) -> Result<NodeInfo, u32> {
        self.information(fds.get(fd)?.file.path())
    }

    /// A successful nonempty request updates atime even when it reads EOF.
    pub fn read_at(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        out: &mut [u8],
        now: u64,
    ) -> Result<usize, u32> {
        let file = fds.get(fd)?.file;
        let n = self.read(fds, fd, out)?;
        if !out.is_empty() {
            self.times[file.index()].access = now;
        }
        Ok(n)
    }

    pub fn write_at(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        bytes: &[u8],
        now: u64,
    ) -> Result<usize, u32> {
        let file = fds.get(fd)?.file;
        let n = self.write(fds, fd, bytes)?;
        if n > 0 {
            let times = &mut self.times[file.index()];
            times.modify = now;
            times.change = now;
        }
        Ok(n)
    }

    pub fn directory_read(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        now: u64,
    ) -> Result<Option<DirectoryRecord>, u32> {
        let open = fds.get_mut(fd)?;
        if !open.file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        let index = u32::try_from(open.offset).map_err(|_| proto_fs::INVALID_ARGUMENT)?;
        let entry = self.directory_read_path(open.file.path(), index, now)?;
        if entry.is_some() {
            open.offset += 1;
        }
        Ok(entry)
    }

    pub fn directory_read_path(
        &mut self,
        path: &str,
        index: u32,
        now: u64,
    ) -> Result<Option<DirectoryRecord>, u32> {
        let info = self.information(path)?;
        if info.kind != DIR {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        let entry = directory_entry(path, index)?;
        self.times[(info.inode - 1) as usize].access = now;
        Ok(entry.map(|(name, kind)| DirectoryRecord {
            name,
            kind,
            inode: match (path, name) {
                (_, "..") => 1,
                (_, ".") => info.inode,
                ("/", "etc") => 2,
                ("/", "tmp") => 3,
                ("/etc", "motd") => 4,
                ("/tmp", "probe") => 5,
                _ => unreachable!("static namespace entry"),
            },
        }))
    }

    pub fn lookup(&self, path: &str) -> Result<Metadata, u32> {
        let (kind, size) = match path {
            "/" | "/etc" | "/tmp" => (DIR, 0),
            "/etc/motd" => (REG, MOTD.len() as u32),
            "/tmp/probe" => (REG, self.len as u32),
            _ => return Err(NO_ENTRY),
        };
        Ok(Metadata { kind, size })
    }

    fn bytes(&self, file: File) -> &[u8] {
        match file {
            File::Root | File::Etc | File::Tmp => &[],
            File::Motd => MOTD,
            File::Scratch => &self.scratch[..self.len],
        }
    }

    pub fn size(&self, fds: &Fds, fd: u32) -> Result<u32, u32> {
        Ok(self.bytes(fds.get(fd)?.file).len() as u32)
    }

    /// Reposition one open description without extending its file. RAM files
    /// expose a single data extent and the required virtual hole at EOF.
    pub fn seek_from(
        &self,
        fds: &mut Fds,
        fd: u32,
        offset: i64,
        origin: proto_fs::SeekFrom,
    ) -> Result<i64, u32> {
        use proto_fs::{INVALID_ARGUMENT, NO_DATA, OFFSET_OVERFLOW, SeekFrom};
        let open = fds.get_mut(fd)?;
        if open.file.is_directory() && matches!(origin, SeekFrom::Data | SeekFrom::Hole) {
            return Err(INVALID_ARGUMENT);
        }
        let size = if open.file.is_directory() {
            directory_count(open.file.path())
        } else {
            self.bytes(open.file).len() as i64
        };
        let next = match origin {
            SeekFrom::Start => offset,
            SeekFrom::Current => open.offset.checked_add(offset).ok_or(OFFSET_OVERFLOW)?,
            SeekFrom::End => size.checked_add(offset).ok_or(OFFSET_OVERFLOW)?,
            SeekFrom::Data | SeekFrom::Hole => {
                if offset < 0 {
                    return Err(INVALID_ARGUMENT);
                }
                if offset >= size {
                    return Err(NO_DATA);
                }
                if origin == SeekFrom::Data {
                    offset
                } else {
                    size
                }
            }
        };
        if next < 0 {
            return Err(INVALID_ARGUMENT);
        }
        open.offset = next;
        Ok(next)
    }

    pub fn read(&self, fds: &mut Fds, fd: u32, out: &mut [u8]) -> Result<usize, u32> {
        let open = fds.get_mut(fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags == WRITE_ONLY {
            return Err(BAD_FD);
        }
        let bytes = self.bytes(open.file);
        let start = open.offset.min(bytes.len() as i64) as usize;
        let n = out.len().min(bytes.len() - start);
        out[..n].copy_from_slice(&bytes[start..start + n]);
        open.offset += n as i64;
        Ok(n)
    }

    pub fn write(&mut self, fds: &mut Fds, fd: u32, bytes: &[u8]) -> Result<usize, u32> {
        let open = fds.get_mut(fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags == READ_ONLY || matches!(open.file, File::Motd) {
            return Err(BAD_FD);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let offset = usize::try_from(open.offset).map_err(|_| NO_SPACE)?;
        let end = offset.checked_add(bytes.len()).ok_or(NO_SPACE)?;
        if end > FILE_CAPACITY {
            return Err(NO_SPACE);
        }
        if offset > self.len {
            self.scratch[self.len..offset].fill(0);
        }
        self.scratch[offset..end].copy_from_slice(bytes);
        self.len = self.len.max(end);
        open.offset = end as i64;
        Ok(bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_fs::READ_WRITE;

    #[test]
    fn directory_descriptions_keep_positions_identity_and_access_times() {
        let mut ram = Ram::new(10);
        let mut fds = Fds::default();
        let fd = fds
            .open("/etc", READ_ONLY | proto_fs::DIRECTORY_ONLY)
            .unwrap();
        let second = fds.open("/etc", READ_ONLY).unwrap();
        assert_eq!(ram.descriptor_information(&fds, fd).unwrap().inode, 2);
        assert_eq!(fds.open("/etc", WRITE_ONLY), Err(IS_DIRECTORY));
        assert_eq!(
            fds.open("/etc/motd", proto_fs::DIRECTORY_ONLY),
            Err(proto_fs::NOT_DIRECTORY)
        );
        assert_eq!(
            ram.read_at(&mut fds, fd, &mut [0; 1], 15),
            Err(IS_DIRECTORY)
        );
        assert_eq!(ram.write_at(&mut fds, fd, b"x", 16), Err(IS_DIRECTORY));
        assert_eq!(ram.information("/etc").unwrap().access_ns, 10);
        for (now, name, inode, kind) in
            [(20, ".", 2, DIR), (30, "..", 1, DIR), (40, "motd", 4, REG)]
        {
            assert_eq!(
                ram.directory_read(&mut fds, fd, now),
                Ok(Some(DirectoryRecord { name, kind, inode }))
            );
        }
        assert_eq!(ram.directory_read(&mut fds, fd, 50), Ok(None));
        assert_eq!(
            ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Current),
            Ok(3)
        );
        let info = ram.information("/etc").unwrap();
        assert_eq!(
            (info.access_ns, info.modify_ns, info.change_ns),
            (50, 10, 10)
        );
        assert_eq!(
            ram.directory_read(&mut fds, second, 60)
                .unwrap()
                .unwrap()
                .name,
            "."
        );
        assert_eq!(
            ram.seek_from(&mut fds, fd, 1, proto_fs::SeekFrom::Start),
            Ok(1)
        );
        assert_eq!(
            ram.directory_read(&mut fds, fd, 70).unwrap().unwrap().name,
            ".."
        );
        let before = ram.information("/etc").unwrap();
        assert_eq!(
            ram.seek_from(&mut fds, fd, -1, proto_fs::SeekFrom::Start),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(
            ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Data),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(
            ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Current),
            Ok(2)
        );
        fds.close(fd).unwrap();
        assert_eq!(ram.directory_read(&mut fds, fd, 80), Err(BAD_FD));
        let regular = fds.open("/etc/motd", READ_ONLY).unwrap();
        assert_eq!(
            ram.directory_read(&mut fds, regular, 90),
            Err(proto_fs::NOT_DIRECTORY)
        );
        assert_eq!(ram.information("/etc").unwrap(), before);
    }

    #[test]
    fn metadata_identity_and_clock_updates_are_shared_across_sessions() {
        let mut ram = Ram::new(10);
        let root = ram.information("/").unwrap();
        assert_eq!(
            (root.kind, root.inode, root.links, root.permissions),
            (DIR, 1, 4, 0o555)
        );
        let motd = ram.information("/etc/motd").unwrap();
        assert_eq!(
            (
                motd.kind,
                motd.inode,
                motd.links,
                motd.permissions,
                motd.size,
                motd.blocks
            ),
            (REG, 4, 1, 0o444, 14, 1)
        );
        let mut a = Fds::default();
        let mut b = Fds::default();
        assert_eq!(
            a.open("/etc/motd", WRITE_ONLY),
            Err(proto_fs::ACCESS_DENIED)
        );
        let fa = a.open("/tmp/probe", READ_WRITE).unwrap();
        let fb = b.open("/tmp/probe", READ_ONLY).unwrap();
        ram.write_at(&mut a, fa, b"abc", 20).unwrap();
        let info = ram.descriptor_information(&b, fb).unwrap();
        assert_eq!(info, ram.information("/tmp/probe").unwrap());
        assert_eq!(
            (
                info.inode,
                info.size,
                info.blocks,
                info.access_ns,
                info.modify_ns,
                info.change_ns
            ),
            (5, 3, 1, 10, 20, 20)
        );
        assert_eq!(ram.read_at(&mut b, fb, &mut [0; 3], 30), Ok(3));
        assert_eq!(ram.read_at(&mut b, fb, &mut [0; 1], 40), Ok(0));
        let info = ram.information("/tmp/probe").unwrap();
        assert_eq!(
            (info.access_ns, info.modify_ns, info.change_ns),
            (40, 20, 20)
        );
        assert_eq!(ram.read_at(&mut b, fb, &mut [], 50), Ok(0));
        assert_eq!(ram.write_at(&mut a, fa, b"", 60), Ok(0));
        assert_eq!(ram.write_at(&mut b, fb, b"x", 70), Err(BAD_FD));
        a.seek(fa, FILE_CAPACITY as u32).unwrap();
        assert_eq!(ram.write_at(&mut a, fa, b"x", 80), Err(NO_SPACE));
        assert_eq!(ram.information("/tmp/probe").unwrap(), info);
        b.close(fb).unwrap();
        assert_eq!(ram.descriptor_information(&b, fb), Err(BAD_FD));
        assert_eq!(ram.information("/missing"), Err(NO_ENTRY));
        assert_eq!(ram.information("/").unwrap(), root);
    }

    #[test]
    fn description_limit_reports_emfile_and_recovers_on_close() {
        let mut fds = Fds::default();
        for expected in 3..OPEN_MAX as u32 + 3 {
            assert_eq!(fds.open("/etc/motd", READ_ONLY), Ok(expected));
        }
        assert_eq!(
            fds.open("/etc/motd", READ_ONLY),
            Err(proto_fs::TOO_MANY_OPEN_FILES)
        );
        fds.close(7).unwrap();
        assert_eq!(fds.open("/etc/motd", READ_ONLY), Ok(7));
    }

    #[test]
    fn directory_entries_match_files_and_end_cleanly() {
        assert_eq!(directory_entry("/", 0), Ok(Some((".", DIR))));
        assert_eq!(directory_entry("/", 1), Ok(Some(("..", DIR))));
        assert_eq!(directory_entry("/", 2), Ok(Some(("etc", DIR))));
        assert_eq!(directory_entry("/", 3), Ok(Some(("tmp", DIR))));
        assert_eq!(directory_entry("/", 4), Ok(None));
        assert_eq!(directory_entry("/etc", 2), Ok(Some(("motd", REG))));
        assert_eq!(directory_entry("/tmp", 2), Ok(Some(("probe", REG))));
        assert_eq!(directory_entry("/missing", 0), Err(NO_ENTRY));
    }

    #[test]
    fn lookup_reports_directory_and_current_file_sizes() {
        let mut ram = Ram::default();
        assert_eq!(ram.lookup("/etc"), Ok(Metadata { kind: DIR, size: 0 }));
        assert_eq!(
            ram.lookup("/etc/motd"),
            Ok(Metadata {
                kind: REG,
                size: 14
            })
        );
        assert_eq!(ram.lookup("/missing"), Err(NO_ENTRY));
        let mut fds = Fds::default();
        assert_eq!(fds.open("/etc", WRITE_ONLY), Err(IS_DIRECTORY));
        let fd = fds.open("/tmp/probe", READ_WRITE).unwrap();
        assert_eq!(ram.write(&mut fds, fd, b"abc"), Ok(3));
        assert_eq!(
            ram.lookup("/tmp/probe"),
            Ok(Metadata { kind: REG, size: 3 })
        );
    }

    #[test]
    fn sessions_have_independent_offsets_and_close_invalidates_fd() {
        let ram = Ram::default();
        let mut a = Fds::default();
        let mut b = Fds::default();
        let fa = a.open("/etc/motd", READ_ONLY).unwrap();
        let fb = b.open("/etc/motd", READ_ONLY).unwrap();
        let mut out = [0; 7];
        assert_eq!(ram.read(&mut a, fa, &mut out), Ok(7));
        assert_eq!(&out, b"stafeto");
        assert_eq!(ram.read(&mut b, fb, &mut out), Ok(7));
        assert_eq!(&out, b"stafeto");
        assert_eq!(a.close(fa), Ok(()));
        assert_eq!(ram.read(&mut a, fa, &mut out), Err(BAD_FD));
        assert_eq!(ram.size(&b, fb), Ok(MOTD.len() as u32));
    }

    #[test]
    fn seek_origins_and_failures_preserve_offset_and_size() {
        use proto_fs::{INVALID_ARGUMENT, NO_DATA, OFFSET_OVERFLOW, SeekFrom::*};
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let fd = fds.open("/tmp/probe", READ_WRITE).unwrap();
        ram.write(&mut fds, fd, b"abc").unwrap();
        assert_eq!(ram.seek_from(&mut fds, fd, -1, End), Ok(2));
        assert_eq!(ram.seek_from(&mut fds, fd, -1, Current), Ok(1));
        assert_eq!(
            ram.seek_from(&mut fds, fd, -2, Current),
            Err(INVALID_ARGUMENT)
        );
        assert_eq!(ram.seek_from(&mut fds, fd, 0, Current), Ok(1));
        assert_eq!(ram.seek_from(&mut fds, fd, 1, Data), Ok(1));
        assert_eq!(ram.seek_from(&mut fds, fd, 1, Hole), Ok(3));
        assert_eq!(ram.seek_from(&mut fds, fd, 3, Data), Err(NO_DATA));
        assert_eq!(ram.seek_from(&mut fds, fd, 3, Hole), Err(NO_DATA));
        assert_eq!(ram.seek_from(&mut fds, fd, -1, Hole), Err(INVALID_ARGUMENT));
        assert_eq!(ram.seek_from(&mut fds, fd, 0, Current), Ok(3));
        assert_eq!(ram.seek_from(&mut fds, fd, i64::MAX, Start), Ok(i64::MAX));
        assert_eq!(
            ram.seek_from(&mut fds, fd, 1, Current),
            Err(OFFSET_OVERFLOW)
        );
        assert_eq!(
            ram.seek_from(&mut fds, fd, i64::MAX, End),
            Err(OFFSET_OVERFLOW)
        );
        assert_eq!(
            ram.seek_from(&mut fds, fd, -1, Start),
            Err(INVALID_ARGUMENT)
        );
        assert_eq!(ram.seek_from(&mut fds, fd, 0, Current), Ok(i64::MAX));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(ram.read(&mut fds, fd, &mut [0; 1]), Ok(0));
        assert_eq!(ram.write(&mut fds, fd, b"x"), Err(NO_SPACE));
        assert_eq!(ram.write(&mut fds, fd, b""), Ok(0));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(ram.seek_from(&mut fds, fd, 7, Start), Ok(7));
        assert_eq!(ram.write(&mut fds, fd, b"z"), Ok(1));
        assert_eq!(ram.seek_from(&mut fds, fd, 0, Start), Ok(0));
        let mut bytes = [0; 8];
        assert_eq!(ram.read(&mut fds, fd, &mut bytes), Ok(8));
        assert_eq!(&bytes, b"abc\0\0\0\0z");
        // RAM reports a single data extent even when it contains zero bytes.
        assert_eq!(ram.seek_from(&mut fds, fd, 4, Data), Ok(4));
        assert_eq!(ram.seek_from(&mut fds, fd, 4, Hole), Ok(8));
        fds.close(fd).unwrap();
        assert_eq!(ram.seek_from(&mut fds, fd, 0, Start), Err(BAD_FD));
    }

    #[test]
    fn zero_io_checks_access_without_modifying_files_or_offsets() {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let read = fds.open("/etc/motd", READ_ONLY).unwrap();
        let write = fds.open("/tmp/probe", WRITE_ONLY).unwrap();
        assert_eq!(ram.read(&mut fds, write, &mut []), Err(BAD_FD));
        assert_eq!(ram.write(&mut fds, read, b""), Err(BAD_FD));
        assert_eq!(ram.read(&mut fds, 99, &mut []), Err(BAD_FD));
        assert_eq!(ram.write(&mut fds, 99, b""), Err(BAD_FD));
        fds.seek(write, 100).unwrap();
        assert_eq!(ram.write(&mut fds, write, b""), Ok(0));
        assert_eq!(ram.size(&fds, write), Ok(0));
        assert_eq!(
            ram.seek_from(&mut fds, write, 0, proto_fs::SeekFrom::Current),
            Ok(100)
        );
        assert_eq!(ram.read(&mut fds, read, &mut []), Ok(0));
        let mut first = [0; 1];
        assert_eq!(ram.read(&mut fds, read, &mut first), Ok(1));
        assert_eq!(&first, b"s");
    }

    #[test]
    fn write_seek_read_and_no_space_leave_file_intact() {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let fd = fds.open("/tmp/probe", READ_WRITE).unwrap();
        assert_eq!(ram.write(&mut fds, fd, b"abc"), Ok(3));
        assert_eq!(fds.seek(fd, 1), Ok(1));
        assert_eq!(ram.write(&mut fds, fd, b"Z"), Ok(1));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(fds.seek(fd, FILE_CAPACITY as u32), Ok(FILE_CAPACITY as u32));
        assert_eq!(ram.write(&mut fds, fd, b"overflow"), Err(NO_SPACE));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(fds.seek(fd, 0), Ok(0));
        let mut out = [0; 3];
        assert_eq!(ram.read(&mut fds, fd, &mut out), Ok(3));
        assert_eq!(&out, b"aZc");
    }
}
