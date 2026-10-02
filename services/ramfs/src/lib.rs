// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded RAM files and per-client open descriptions for the first POSIX
//! userspace experiment. A single service thread owns `Ram`; each IPC
//! session owns its own `Fds`, so closing a session closes its files. Next
//! to its fixed tree (`/etc/motd`, the scratch file `/tmp/probe`) the
//! service shows the files of the boot image's table `rootfs` (`tree`),
//! read-only, with the modes and owners of the table, and reads them from
//! the mapped image as they lie.

#![cfg_attr(not(test), no_std)]

pub mod tree;

use proto_fs::{
    BAD_FD, IS_DIRECTORY, Metadata, NO_ENTRY, NO_SPACE, NodeInfo, READ_ONLY, WRITE_ONLY,
};
use tree::Tree;

const FILE_CAPACITY: usize = 1024;
const OPEN_MAX: usize = 32;
const MOTD: &[u8] = b"stafeto ramfs\n";
/// The inode of entry `n` of the table is this plus the number of the
/// first entry that names its file (the fixed tree has 1 to 5).
const IMAGE_INODE: u64 = 6;

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

/// The effective IDs an exec is checked with (proto_process Vouch of the
/// loader: those of the record it loads).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Who {
    pub euid: u32,
    pub egid: u32,
}

/// A program file OpenExec found (spec 2, 3.2; 5c): the entry of the
/// image's table the image session reads, and its mode and owner, whose
/// set-ID bits the service tells the process service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exec {
    pub entry: u16,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Who OpenExec opens a program for (condition O1): a request through the session
/// of the loaders, whose label init marks (`proto_fs::is_loaders`), and an
/// identity the process service vouched for as a loader's that loads
/// (`who`, None when it refused): the effective IDs of the record the
/// loader loads, its PID and the loader's ticket. PERMISSION otherwise.
pub fn exec_for(
    label: u64,
    who: Option<proto_process::WhoReply>,
) -> Result<(Who, u32, proto_process::LoaderOf), u32> {
    if !proto_fs::is_loaders(label) {
        return Err(proto_fs::PERMISSION);
    }
    let who = who.ok_or(proto_fs::PERMISSION)?;
    let loader = who.loader.ok_or(proto_fs::PERMISSION)?;
    let ids = Who {
        euid: who.credentials.euid,
        egid: who.credentials.egid,
    };
    Ok((ids, who.pid, loader))
}

/// The set-user-ID and set-group-ID bits of a mode.
pub const SET_UID: u32 = 0o4000;
pub const SET_GID: u32 = 0o2000;

/// Whether `who` may do what `bit` of the class names (0o1 execute or
/// search, of the owner, the group or the others by its effective IDs)
/// on a node of `info`. Root may search any directory and execute a file
/// with any execute bit.
fn may(info: &NodeInfo, who: Who, bit: u32) -> bool {
    if who.euid == 0 {
        return info.kind == DIR || info.permissions & 0o111 != 0;
    }
    let class = if who.euid == info.uid {
        info.permissions >> 6
    } else if who.egid == info.gid {
        info.permissions >> 3
    } else {
        info.permissions
    };
    class & bit != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryRecord<'a> {
    pub name: &'a str,
    pub kind: u32,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum File {
    Root,
    Etc,
    Tmp,
    Motd,
    Scratch,
    /// Entry `n` of the table, a directory or a regular file.
    ImageDir(u16),
    ImageRegular(u16),
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
    fn insert(&mut self, file: File, flags: u32) -> Result<u32, u32> {
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
        matches!(self, Self::Root | Self::Etc | Self::Tmp | Self::ImageDir(_))
    }

    /// The place of a file of the fixed tree among its times; the files of
    /// the image are read-only and keep the time the service started.
    fn index(self) -> Option<usize> {
        match self {
            Self::Root => Some(0),
            Self::Etc => Some(1),
            Self::Tmp => Some(2),
            Self::Motd => Some(3),
            Self::Scratch => Some(4),
            Self::ImageDir(_) | Self::ImageRegular(_) => None,
        }
    }
}

pub struct Ram<'a> {
    scratch: [u8; FILE_CAPACITY],
    len: usize,
    times: [FileTimes; 5],
    /// When the service started: the times of the files of the image.
    born: u64,
    tree: Option<Tree<'a>>,
}

impl Default for Ram<'_> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<'a> Ram<'a> {
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
            born: now,
            tree: None,
        }
    }

    /// `new` with the files of the boot image's table as well.
    pub fn with_tree(now: u64, tree: Tree<'a>) -> Self {
        Self {
            tree: Some(tree),
            ..Self::new(now)
        }
    }

    fn resolve(&self, path: &str) -> Result<File, u32> {
        Ok(match path {
            "/" => File::Root,
            "/etc" => File::Etc,
            "/tmp" => File::Tmp,
            "/etc/motd" => File::Motd,
            "/tmp/probe" => File::Scratch,
            _ => {
                let tree = self.tree.as_ref().ok_or(NO_ENTRY)?;
                let n = tree.find(path).ok_or(NO_ENTRY)?;
                if tree.entry(n).is_directory() {
                    File::ImageDir(n)
                } else {
                    File::ImageRegular(n)
                }
            }
        })
    }

    pub fn open(&self, fds: &mut Fds, path: &str, flags: u32) -> Result<u32, u32> {
        if flags & !7 != 0 || flags & 3 == 3 {
            return Err(proto_wire::BAD_SIZE);
        }
        let directory_only = flags & proto_fs::DIRECTORY_ONLY != 0;
        let flags = flags & 3;
        let file = self.resolve(path)?;
        if file.is_directory() && flags != READ_ONLY {
            return Err(IS_DIRECTORY);
        }
        if matches!(file, File::Motd | File::ImageRegular(_)) && flags != READ_ONLY {
            return Err(proto_fs::ACCESS_DENIED);
        }
        if directory_only && !file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        fds.insert(file, flags)
    }

    fn touch_access(&mut self, file: File, now: u64) {
        if let Some(index) = file.index() {
            self.times[index].access = now;
        }
    }

    fn inode(&self, file: File) -> u64 {
        match file {
            File::Root => 1,
            File::Etc => 2,
            File::Tmp => 3,
            File::Motd => 4,
            File::Scratch => 5,
            File::ImageDir(n) | File::ImageRegular(n) => {
                IMAGE_INODE + u64::from(self.tree().canonical(n))
            }
        }
    }

    /// The tree of a file of the image, which only a tree gives.
    fn tree(&self) -> &Tree<'a> {
        self.tree.as_ref().expect("files of the image need a tree")
    }

    pub fn information(&self, path: &str) -> Result<NodeInfo, u32> {
        Ok(self.node_information(self.resolve(path)?))
    }

    /// OpenExec's resolution of `path` for `who`, in one step of the
    /// service (condition O3): the path is made plain (`.` goes, `..` takes the
    /// directory back, and above `/` names nothing: NO_ENTRY), every
    /// directory on the way needs search by `who` (ACCESS_DENIED) and
    /// is one (NOT_DIRECTORY); the last is a regular file of the image
    /// that `who` may execute: ACCESS_DENIED for a directory or a file
    /// without execute, NO_ENTRY for none.
    pub fn exec(&self, path: &str, who: Who) -> Result<Exec, u32> {
        let mut plain = [0u8; proto_fs::MAX_PATH];
        let mut len = 0;
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            if part == ".." {
                if len == 0 {
                    return Err(NO_ENTRY);
                }
                len = plain[..len].iter().rposition(|&b| b == b'/').unwrap_or(0);
                continue;
            }
            let end = len + 1 + part.len();
            let room = plain.get_mut(len..end).ok_or(proto_fs::INVALID_ARGUMENT)?;
            room[0] = b'/';
            room[1..].copy_from_slice(part.as_bytes());
            let directory = core::str::from_utf8(&plain[..len.max(1)]).map_err(|_| NO_ENTRY)?;
            let directory = if len == 0 { "/" } else { directory };
            let info = self.information(directory)?;
            if info.kind != DIR {
                return Err(proto_fs::NOT_DIRECTORY);
            }
            if !may(&info, who, 0o1) {
                return Err(proto_fs::ACCESS_DENIED);
            }
            len = end;
        }
        let plain = core::str::from_utf8(&plain[..len]).map_err(|_| NO_ENTRY)?;
        let file = if plain.is_empty() {
            File::Root
        } else {
            self.resolve(plain)?
        };
        let info = self.node_information(file);
        if info.kind != REG || !may(&info, who, 0o1) {
            return Err(proto_fs::ACCESS_DENIED);
        }
        let File::ImageRegular(entry) = file else {
            return Err(proto_fs::ACCESS_DENIED);
        };
        Ok(Exec {
            entry,
            mode: info.permissions,
            uid: info.uid,
            gid: info.gid,
        })
    }

    /// The information of the program file of an image session.
    pub fn image_information(&self, entry: u16) -> Result<NodeInfo, u32> {
        let tree = self.tree.as_ref().ok_or(NO_ENTRY)?;
        if entry >= tree.len() || tree.entry(entry).is_directory() {
            return Err(NO_ENTRY);
        }
        Ok(self.node_information(File::ImageRegular(entry)))
    }

    /// ReadAt of an image session: the bytes of the program file `entry`
    /// from `offset`; the time of the image does not change.
    pub fn image_read(&self, entry: u16, offset: u64, out: &mut [u8]) -> Result<usize, u32> {
        self.image_information(entry)?;
        if i64::try_from(offset).is_err() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let bytes = self.bytes(File::ImageRegular(entry));
        let start = usize::try_from(offset).map_or(bytes.len(), |o| o.min(bytes.len()));
        let n = out.len().min(bytes.len() - start);
        out[..n].copy_from_slice(&bytes[start..start + n]);
        Ok(n)
    }

    fn node_information(&self, file: File) -> NodeInfo {
        let size = self.bytes(file).len() as u64;
        let (kind, links, permissions, uid, gid, times) = match file {
            File::ImageDir(n) | File::ImageRegular(n) => {
                let entry = self.tree().entry(n);
                let kind = if file.is_directory() { DIR } else { REG };
                let times = FileTimes {
                    access: self.born,
                    modify: self.born,
                    change: self.born,
                };
                let links = u64::from(self.tree().links(n));
                (
                    kind,
                    links,
                    entry.mode & 0o7777,
                    entry.uid,
                    entry.gid,
                    times,
                )
            }
            _ => {
                let (kind, links, permissions) = match file {
                    File::Root => (DIR, 4 + self.root_links(), 0o555),
                    File::Etc => (DIR, 2, 0o555),
                    File::Tmp => (DIR, 2, 0o555),
                    File::Motd => (REG, 1, 0o444),
                    _ => (REG, 1, 0o644),
                };
                let times = self.times[file.index().expect("fixed tree")];
                (kind, links, permissions, 0, 0, times)
            }
        };
        NodeInfo {
            kind,
            permissions,
            device: 1,
            special_device: 0,
            inode: self.inode(file),
            links,
            uid,
            gid,
            size,
            block_size: FILE_CAPACITY as u32,
            blocks: size.div_ceil(512),
            access_ns: times.access,
            modify_ns: times.modify,
            change_ns: times.change,
        }
    }

    /// The directories of the image at `/`: each has a `..` in `/`.
    fn root_links(&self) -> u64 {
        self.tree
            .as_ref()
            .map_or(0, |tree| u64::from(tree.root_links()))
    }

    pub fn descriptor_information(&self, fds: &Fds, fd: u32) -> Result<NodeInfo, u32> {
        Ok(self.node_information(fds.get(fd)?.file))
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
            self.touch_access(file, now);
        }
        Ok(n)
    }

    /// Reads from `offset` of the file and leaves the position of the open
    /// description where it is. The offset is at most `i64::MAX`.
    pub fn pread(
        &mut self,
        fds: &Fds,
        fd: u32,
        offset: u64,
        out: &mut [u8],
        now: u64,
    ) -> Result<usize, u32> {
        let open = fds.get(fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags == WRITE_ONLY {
            return Err(BAD_FD);
        }
        if i64::try_from(offset).is_err() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let bytes = self.bytes(open.file);
        let start = usize::try_from(offset).map_or(bytes.len(), |o| o.min(bytes.len()));
        let n = out.len().min(bytes.len() - start);
        out[..n].copy_from_slice(&bytes[start..start + n]);
        if !out.is_empty() {
            self.touch_access(open.file, now);
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
            let times = &mut self.times[file.index().expect("only the scratch file is written")];
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
    ) -> Result<Option<DirectoryRecord<'a>>, u32> {
        let open = fds.get_mut(fd)?;
        if !open.file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        let index = u32::try_from(open.offset).map_err(|_| proto_fs::INVALID_ARGUMENT)?;
        let entry = self.entry_of(open.file, index, now);
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
    ) -> Result<Option<DirectoryRecord<'a>>, u32> {
        let file = self.resolve(path)?;
        if !file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        Ok(self.entry_of(file, index, now))
    }

    /// Entry `index` of directory `dir`: `.`, `..`, then the fixed
    /// entries, then the children from the table; the access time of the
    /// directory is `now`.
    fn entry_of(&mut self, dir: File, index: u32, now: u64) -> Option<DirectoryRecord<'a>> {
        self.touch_access(dir, now);
        let tree = self.tree;
        let index = index as usize;
        let name_of = |tree: &Tree<'a>, n: u16| {
            let path = tree.entry(n).path;
            &path[path.rfind('/').map_or(0, |slash| slash + 1)..]
        };
        // The fixed children of the directory, which come before the image's.
        let fixed: &[(&'static str, File)] = match dir {
            File::Root => &[("etc", File::Etc), ("tmp", File::Tmp)],
            File::Etc => &[("motd", File::Motd)],
            File::Tmp => &[("probe", File::Scratch)],
            _ => &[],
        };
        match index {
            0 => Some(DirectoryRecord {
                name: ".",
                kind: DIR,
                inode: self.inode(dir),
            }),
            1 => {
                let parent = match dir {
                    File::ImageDir(n) => self.tree().parent(n).map(File::ImageDir),
                    _ => None,
                };
                Some(DirectoryRecord {
                    name: "..",
                    kind: DIR,
                    inode: parent.map_or(1, |parent| self.inode(parent)),
                })
            }
            _ => {
                let index = index - 2;
                if let Some(&(name, file)) = fixed.get(index) {
                    return Some(DirectoryRecord {
                        name,
                        kind: if file.is_directory() { DIR } else { REG },
                        inode: self.inode(file),
                    });
                }
                let tree = tree?;
                let parent = match dir {
                    File::ImageDir(n) => Some(n),
                    File::Root => None,
                    _ => return None,
                };
                let n = *tree.children(parent).get(index - fixed.len())?;
                let file = if tree.entry(n).is_directory() {
                    File::ImageDir(n)
                } else {
                    File::ImageRegular(n)
                };
                Some(DirectoryRecord {
                    name: name_of(&tree, n),
                    kind: if file.is_directory() { DIR } else { REG },
                    inode: self.inode(file),
                })
            }
        }
    }

    /// The entries of a directory, with `.` and `..`.
    fn directory_count(&self, dir: File) -> i64 {
        let kids = |parent: Option<u16>| {
            self.tree
                .as_ref()
                .map_or(0, |tree| tree.children(parent).len() as i64)
        };
        match dir {
            File::Root => 4 + kids(None),
            File::ImageDir(n) => 2 + kids(Some(n)),
            _ => 3,
        }
    }

    pub fn lookup(&self, path: &str) -> Result<Metadata, u32> {
        let file = self.resolve(path)?;
        let (kind, size) = if file.is_directory() {
            (DIR, 0)
        } else {
            (REG, self.bytes(file).len() as u32)
        };
        Ok(Metadata { kind, size })
    }

    fn bytes(&self, file: File) -> &[u8] {
        match file {
            File::Root | File::Etc | File::Tmp | File::ImageDir(_) => &[],
            File::Motd => MOTD,
            File::Scratch => &self.scratch[..self.len],
            File::ImageRegular(n) => self.tree().data(n),
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
            self.directory_count(open.file)
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
        if open.flags == READ_ONLY || matches!(open.file, File::Motd | File::ImageRegular(_)) {
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
        let fd = ram
            .open(&mut fds, "/etc", READ_ONLY | proto_fs::DIRECTORY_ONLY)
            .unwrap();
        let second = ram.open(&mut fds, "/etc", READ_ONLY).unwrap();
        assert_eq!(ram.descriptor_information(&fds, fd).unwrap().inode, 2);
        assert_eq!(ram.open(&mut fds, "/etc", WRITE_ONLY), Err(IS_DIRECTORY));
        assert_eq!(
            ram.open(&mut fds, "/etc/motd", proto_fs::DIRECTORY_ONLY),
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
        let regular = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
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
            ram.open(&mut a, "/etc/motd", WRITE_ONLY),
            Err(proto_fs::ACCESS_DENIED)
        );
        let fa = ram.open(&mut a, "/tmp/probe", READ_WRITE).unwrap();
        let fb = ram.open(&mut b, "/tmp/probe", READ_ONLY).unwrap();
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
        let ram = Ram::default();
        let mut fds = Fds::default();
        for expected in 3..OPEN_MAX as u32 + 3 {
            assert_eq!(ram.open(&mut fds, "/etc/motd", READ_ONLY), Ok(expected));
        }
        assert_eq!(
            ram.open(&mut fds, "/etc/motd", READ_ONLY),
            Err(proto_fs::TOO_MANY_OPEN_FILES)
        );
        fds.close(7).unwrap();
        assert_eq!(ram.open(&mut fds, "/etc/motd", READ_ONLY), Ok(7));
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
        assert_eq!(ram.open(&mut fds, "/etc", WRITE_ONLY), Err(IS_DIRECTORY));
        let fd = ram.open(&mut fds, "/tmp/probe", READ_WRITE).unwrap();
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
        let fa = ram.open(&mut a, "/etc/motd", READ_ONLY).unwrap();
        let fb = ram.open(&mut b, "/etc/motd", READ_ONLY).unwrap();
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
        let fd = ram.open(&mut fds, "/tmp/probe", READ_WRITE).unwrap();
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
        let read = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        let write = ram.open(&mut fds, "/tmp/probe", WRITE_ONLY).unwrap();
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
        let fd = ram.open(&mut fds, "/tmp/probe", READ_WRITE).unwrap();
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

    use crate::tree::{Index, load, test_image};
    use bootimg::rootfs::{DIRECTORY, Entry, REGULAR};

    fn entry(path: &str, mode: u32, file: u32) -> Entry<'_> {
        Entry {
            path,
            mode,
            uid: 0,
            gid: 0,
            file,
        }
    }

    /// `/bin/ash` and `/bin/ls` are one file `a` (owner 3, 4), `/bin/sub/b`
    /// is `b` and `/lib` is an empty directory.
    fn image() -> Vec<u8> {
        let owned = |entry: Entry<'static>| Entry {
            uid: 3,
            gid: 4,
            ..entry
        };
        test_image(&[
            entry("/bin", DIRECTORY | 0o755, 0),
            owned(entry("/bin/ash", REGULAR | 0o4755, 1)),
            owned(entry("/bin/ls", REGULAR | 0o4755, 1)),
            entry("/bin/sub", DIRECTORY | 0o700, 0),
            entry("/bin/sub/b", REGULAR | 0o640, 2),
            entry("/lib", DIRECTORY | 0o755, 0),
        ])
    }

    #[test]
    fn image_files_have_the_mode_owner_size_inode_and_links_of_the_table() {
        let bytes = image();
        let mut index = Index::new();
        let mut ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let ash = ram.information("/bin/ash").unwrap();
        let ls = ram.information("/bin/ls").unwrap();
        assert_eq!(
            (
                ash.kind,
                ash.permissions,
                ash.uid,
                ash.gid,
                ash.size,
                ash.links
            ),
            (REG, 0o4755, 3, 4, 11, 2)
        );
        assert_eq!(ash.blocks, 1);
        assert_eq!((ls.inode, ls.links), (ash.inode, 2));
        let b = ram.information("/bin/sub/b").unwrap();
        assert_eq!((b.permissions, b.size, b.links), (0o640, 4, 1));
        assert_ne!(b.inode, ash.inode);
        // The times are the service's start: nothing of the image changes.
        assert_eq!((ash.access_ns, ash.modify_ns, ash.change_ns), (10, 10, 10));
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/bin/ash", READ_ONLY).unwrap();
        assert_eq!(ram.read_at(&mut fds, fd, &mut [0; 4], 99), Ok(4));
        assert_eq!(ram.information("/bin/ash").unwrap().access_ns, 10);
        assert_eq!(ram.descriptor_information(&fds, fd).unwrap(), ash);
        // `/bin` has `.`, its entry in `/`, and `..` of `sub`.
        let bin = ram.information("/bin").unwrap();
        assert_eq!((bin.kind, bin.permissions, bin.links), (DIR, 0o755, 3));
        let root = ram.information("/").unwrap();
        // `.`, `..`, `etc`, `tmp`, `bin` and `lib` give 2 + 4.
        assert_eq!((root.links, root.inode), (6, 1));
        assert_eq!(
            ram.lookup("/bin/sub/b"),
            Ok(Metadata { kind: REG, size: 4 })
        );
        assert_eq!(ram.lookup("/bin"), Ok(Metadata { kind: DIR, size: 0 }));
        assert_eq!(ram.information("/bin/none"), Err(NO_ENTRY));
        assert_eq!(ram.information("/bin/ash/x"), Err(NO_ENTRY));
        // The fixed tree is as before.
        assert_eq!(ram.information("/etc/motd").unwrap().size, 14);
    }

    /// The entries of the directory `path`, one call each.
    fn names<'a>(ram: &mut Ram<'a>, path: &str) -> Vec<(&'a str, u32, u64)> {
        let mut out = Vec::new();
        while let Some(entry) = ram.directory_read_path(path, out.len() as u32, 20).unwrap() {
            out.push((entry.name, entry.kind, entry.inode));
        }
        out
    }

    #[test]
    fn image_directories_list_dot_dotdot_the_fixed_entries_then_the_children() {
        let bytes = image();
        let mut index = Index::new();
        let mut ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let mut fds = Fds::default();
        let bin = ram.information("/bin").unwrap().inode;
        let sub = ram.information("/bin/sub").unwrap().inode;
        let ash = ram.information("/bin/ash").unwrap().inode;
        let root: Vec<_> = names(&mut ram, "/").iter().map(|e| (e.0, e.1)).collect();
        assert_eq!(
            root,
            [
                (".", DIR),
                ("..", DIR),
                ("etc", DIR),
                ("tmp", DIR),
                ("bin", DIR),
                ("lib", DIR)
            ]
        );
        assert_eq!(
            names(&mut ram, "/bin"),
            [
                (".", DIR, bin),
                ("..", DIR, 1),
                ("ash", REG, ash),
                ("ls", REG, ash),
                ("sub", DIR, sub),
            ]
        );
        let parent_of_sub = names(&mut ram, "/bin/sub");
        assert_eq!((parent_of_sub[1].0, parent_of_sub[1].2), ("..", bin));
        assert_eq!(names(&mut ram, "/lib").len(), 2);
        assert_eq!(names(&mut ram, "/etc").len(), 3);
        assert_eq!(
            ram.directory_read_path("/bin/ash", 0, 20),
            Err(proto_fs::NOT_DIRECTORY)
        );
        // An open directory advances through the same entries, and its
        // size for seeking counts them (`.`, `..` and the children).
        let fd = ram.open(&mut fds, "/bin", READ_ONLY | proto_fs::DIRECTORY_ONLY);
        let fd = fd.unwrap();
        assert_eq!(
            ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::End),
            Ok(5)
        );
        ram.seek_from(&mut fds, fd, 4, proto_fs::SeekFrom::Start)
            .unwrap();
        let last = ram.directory_read(&mut fds, fd, 30).unwrap().unwrap();
        assert_eq!(last.name, "sub");
        assert_eq!(ram.directory_read(&mut fds, fd, 30), Ok(None));
        let root_fd = ram.open(&mut fds, "/", READ_ONLY).unwrap();
        assert_eq!(
            ram.seek_from(&mut fds, root_fd, 0, proto_fs::SeekFrom::End),
            Ok(6)
        );
        assert_eq!(ram.open(&mut fds, "/bin", WRITE_ONLY), Err(IS_DIRECTORY));
    }

    #[test]
    fn image_files_are_read_only_and_read_from_the_start_of_their_own_bytes() {
        let bytes = image();
        let mut index = Index::new();
        let mut ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let mut fds = Fds::default();
        assert_eq!(
            ram.open(&mut fds, "/bin/ash", WRITE_ONLY),
            Err(proto_fs::ACCESS_DENIED)
        );
        assert_eq!(
            ram.open(&mut fds, "/bin/ash", READ_WRITE),
            Err(proto_fs::ACCESS_DENIED)
        );
        assert_eq!(
            ram.open(&mut fds, "/bin/ash", proto_fs::DIRECTORY_ONLY),
            Err(proto_fs::NOT_DIRECTORY)
        );
        let fd = ram.open(&mut fds, "/bin/ash", READ_ONLY).unwrap();
        assert_eq!(ram.write(&mut fds, fd, b"x"), Err(BAD_FD));
        let mut out = [0; 16];
        assert_eq!(ram.read(&mut fds, fd, &mut out), Ok(11));
        assert_eq!(&out[..11], b"alpha bytes");
        // The same file through the other link, and the other file.
        let other = ram.open(&mut fds, "/bin/ls", READ_ONLY).unwrap();
        assert_eq!(ram.read(&mut fds, other, &mut out[..5]), Ok(5));
        assert_eq!(&out[..5], b"alpha");
        let b = ram.open(&mut fds, "/bin/sub/b", READ_ONLY).unwrap();
        assert_eq!(ram.read(&mut fds, b, &mut out), Ok(4));
        assert_eq!(&out[..4], b"beta");
    }

    #[test]
    fn pread_takes_the_offset_of_the_file_and_keeps_the_position() {
        let bytes = image();
        let mut index = Index::new();
        let mut ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/bin/ash", READ_ONLY).unwrap();
        let mut out = [0; 32];
        // From the start, from the middle, up to the end, and a count over it.
        assert_eq!(ram.pread(&fds, fd, 0, &mut out[..5], 40), Ok(5));
        assert_eq!(&out[..5], b"alpha");
        assert_eq!(ram.pread(&fds, fd, 6, &mut out, 40), Ok(5));
        assert_eq!(&out[..5], b"bytes");
        assert_eq!(ram.pread(&fds, fd, 10, &mut out, 40), Ok(1));
        assert_eq!(out[0], b's');
        // At the end, past it, and at the largest offset.
        assert_eq!(ram.pread(&fds, fd, 11, &mut out, 40), Ok(0));
        assert_eq!(ram.pread(&fds, fd, 1 << 40, &mut out, 40), Ok(0));
        assert_eq!(ram.pread(&fds, fd, i64::MAX as u64, &mut out, 40), Ok(0));
        assert_eq!(
            ram.pread(&fds, fd, i64::MAX as u64 + 1, &mut out, 40),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        // The position of the description did not move, so a read starts at 0.
        assert_eq!(ram.read(&mut fds, fd, &mut out[..5]), Ok(5));
        assert_eq!(&out[..5], b"alpha");
        assert_eq!(ram.pread(&fds, fd, 0, &mut [], 40), Ok(0));
        // A read updates the access time of a file of the fixed tree only.
        let motd = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        assert_eq!(ram.pread(&fds, motd, 7, &mut out, 50), Ok(7));
        assert_eq!(&out[..7], b" ramfs\n");
        assert_eq!(ram.information("/etc/motd").unwrap().access_ns, 50);
        assert_eq!(ram.information("/bin/ash").unwrap().access_ns, 10);
        // The scratch file reads at an offset as well, and errors are the
        // read's: a closed descriptor, a directory, a write-only open.
        let scratch = ram.open(&mut fds, "/tmp/probe", READ_WRITE).unwrap();
        ram.write(&mut fds, scratch, b"abcdef").unwrap();
        assert_eq!(ram.pread(&fds, scratch, 4, &mut out, 60), Ok(2));
        assert_eq!(&out[..2], b"ef");
        let write_only = ram.open(&mut fds, "/tmp/probe", WRITE_ONLY).unwrap();
        assert_eq!(ram.pread(&fds, write_only, 0, &mut out, 60), Err(BAD_FD));
        let dir = ram.open(&mut fds, "/bin", READ_ONLY).unwrap();
        assert_eq!(ram.pread(&fds, dir, 0, &mut out, 60), Err(IS_DIRECTORY));
        fds.close(fd).unwrap();
        assert_eq!(ram.pread(&fds, fd, 0, &mut out, 60), Err(BAD_FD));
    }

    #[test]
    fn a_path_of_the_most_bytes_names_a_file_of_the_image() {
        let name = "n".repeat(255);
        let deep = format!("/{name}/{}", "m".repeat(254));
        assert_eq!(deep.len(), proto_fs::MAX_PATH);
        assert_eq!(bootimg::rootfs::PATH_MAX, proto_fs::MAX_PATH);
        let bytes = test_image(&[
            entry(&deep[..256], DIRECTORY | 0o755, 0),
            entry(&deep, REGULAR | 0o644, 1),
        ]);
        let mut index = Index::new();
        let ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let mut fds = Fds::default();
        assert!(ram.open(&mut fds, &deep, READ_ONLY).is_ok());
        assert_eq!(ram.information(&deep).unwrap().size, 11);
        assert_eq!(proto_fs::valid_path(deep.as_bytes()), Ok(deep.as_str()));
    }

    #[test]
    fn without_a_tree_the_image_paths_do_not_exist() {
        let ram = Ram::default();
        assert_eq!(ram.information("/bin"), Err(NO_ENTRY));
        assert_eq!(ram.lookup("/bin/ash"), Err(NO_ENTRY));
    }

    /// OpenExec opens for a loader alone: through the session of the
    /// loaders, with an identity the process service vouched for as a
    /// loader's; another session, a refused Vouch and a process's own
    /// identity get PERMISSION.
    #[test]
    fn exec_is_for_a_loader_through_the_loaders_session() {
        use proto_process::{Credentials, LoaderOf, WhoReply};
        let loader = LoaderOf {
            image: 1,
            ticket: 3 << 8 | 2,
        };
        let who = WhoReply {
            pid: 300,
            credentials: Credentials {
                euid: 0,
                ..Credentials::NOBODY
            },
            generation: 1,
            loader: Some(loader),
        };
        let loaders = proto_fs::LOADERS | 9;
        assert_eq!(
            exec_for(loaders, Some(who)),
            Ok((
                Who {
                    euid: 0,
                    egid: 65534
                },
                300,
                loader
            ))
        );
        let refused = Err(proto_fs::PERMISSION);
        assert_eq!(exec_for(9, Some(who)), refused, "a client's session");
        assert_eq!(exec_for(proto_fs::OWN | 9, Some(who)), refused, "a clone");
        assert_eq!(exec_for(loaders, None), refused, "Vouch refused");
        let process = WhoReply {
            loader: None,
            ..who
        };
        assert_eq!(exec_for(loaders, Some(process)), refused, "no loader");
    }

    /// OpenExec resolves in one step for the loader's effective IDs:
    /// search on every directory, execute on the file, `.` and `..`
    /// within the tree and none above `/`, and a regular file of the
    /// image; the set-ID bits come with the owner.
    #[test]
    fn exec_checks_search_and_execute_for_the_loaders_ids() {
        let bytes = image();
        let mut index = Index::new();
        let ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let root = Who { euid: 0, egid: 0 };
        let nobody = Who {
            euid: 65534,
            egid: 65534,
        };
        let owner = Who { euid: 3, egid: 9 };
        let ash = ram.exec("/bin/ash", nobody).unwrap();
        assert_eq!((ash.mode, ash.uid, ash.gid), (0o4755, 3, 4));
        assert_eq!(ram.exec("/bin/./ash", nobody), Ok(ash));
        assert_eq!(ram.exec("/lib/../bin/ash", nobody), Ok(ash));
        assert_eq!(ram.exec("//bin//ash", nobody), Ok(ash));
        // `..` above the root names nothing.
        assert_eq!(ram.exec("/../bin/ash", nobody), Err(NO_ENTRY));
        assert_eq!(ram.exec("/bin/../../bin/ash", nobody), Err(NO_ENTRY));
        // /bin/sub is 0700 of root: no search for others, root passes,
        // and b (0640) has no execute bit even for root.
        assert_eq!(ram.exec("/bin/sub/b", nobody), Err(proto_fs::ACCESS_DENIED));
        assert_eq!(ram.exec("/bin/sub/b", root), Err(proto_fs::ACCESS_DENIED));
        assert_eq!(ram.exec("/bin/ash", owner).map(|e| e.entry), Ok(ash.entry));
        // A directory, a file of the fixed tree, a file on the way.
        assert_eq!(ram.exec("/bin", root), Err(proto_fs::ACCESS_DENIED));
        assert_eq!(ram.exec("/etc/motd", root), Err(proto_fs::ACCESS_DENIED));
        assert_eq!(ram.exec("/bin/ash/x", root), Err(proto_fs::NOT_DIRECTORY));
        assert_eq!(ram.exec("/bin/none", root), Err(NO_ENTRY));
        assert_eq!(ram.exec("/", root), Err(proto_fs::ACCESS_DENIED));
        // An executable file under a directory only root may search.
        let locked = test_image(&[
            entry("/sbin", DIRECTORY | 0o700, 0),
            entry("/sbin/x", REGULAR | 0o755, 1),
        ]);
        let mut locked_index = Index::new();
        let locked = Ram::with_tree(10, load(&locked, &mut locked_index).unwrap());
        assert_eq!(locked.exec("/sbin/x", nobody), Err(proto_fs::ACCESS_DENIED));
        assert!(locked.exec("/sbin/x", root).is_ok());
        // The image session reads the file and nothing else.
        let mut out = [0; 4];
        assert_eq!(ram.image_read(ash.entry, 0, &mut out), Ok(4));
        assert_eq!(ram.image_information(ash.entry).unwrap().size, 11);
        let bin = ram.exec("/bin/sub", root);
        assert!(bin.is_err());
        assert_eq!(ram.image_read(0, 0, &mut out), Err(NO_ENTRY), "a directory");
        assert_eq!(ram.image_read(99, 0, &mut out), Err(NO_ENTRY));
    }
}
