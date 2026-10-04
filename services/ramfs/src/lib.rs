// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! RAM inode storage with fixed boot nodes, paid mutable overlays and
//! shared open descriptions. One service thread owns the namespace and
//! every client retains its descriptors, current directory and preparations.
//! The original guest operations use this storage; mutation entry points
//! are exercised through the same backend on the host.
#![cfg_attr(not(test), no_std)]

pub mod authority;
pub mod places;
pub mod resolve;
#[cfg(test)]
mod resolve_tests;
pub mod storage;
#[cfg(test)]
mod storage_tests;
pub mod tree;

use storage::{BOOT_ROOT, Pin, Storage, Token};

use proto_fs::{
    BAD_FD, IS_DIRECTORY, Metadata, NO_ENTRY, NO_SPACE, NodeInfo, READ_ONLY, WRITE_ONLY,
};
use tree::Tree;

const FILE_CAPACITY: usize = 1024;
const OPEN_MAX: usize = 32;
/// The open descriptions of the service at most, which the sessions share
/// (spec 2, 3.7; 5c): past them, open is TOO_MANY_OPEN_FILES.
pub const DESCRIPTIONS: usize = 128;
const MOTD: &[u8] = b"stafeto ramfs\n";
/// The inode of entry `n` of the table is this plus the number of the
/// first entry that names its file (the fixed tree has 1 to 5).
const IMAGE_INODE: u64 = 6;
/// The path of the entry of the table that is the null device.
const NULL_DEVICE: &str = "/dev/null";
/// The paths of the entries of the table that are the random devices (5e'):
/// the layer of the client reads them from its own generator, the service
/// only keeps the descriptions (writes are accepted and dropped).
const RANDOM_DEVICES: [&str; 2] = ["/dev/random", "/dev/urandom"];

pub const DIR: u32 = 1;
pub const REG: u32 = 2;
/// A character device: the null and the random devices.
pub const CHAR: u32 = 3;

/// What entry `n` of the table is: a directory, a device by its path, or a
/// regular file.
fn image_file(tree: &Tree<'_>, n: u16) -> File {
    let path = tree.entry(n).path;
    if tree.entry(n).is_directory() {
        File::ImageDir(n)
    } else if path == NULL_DEVICE {
        File::Null(n)
    } else if RANDOM_DEVICES.contains(&path) {
        File::Random(n)
    } else {
        File::ImageRegular(n)
    }
}

pub fn directory_entry(path: &str, index: u32) -> Result<Option<(&'static str, u32)>, u32> {
    let entries: &[(&str, u32)] = match path {
        "/" => &[(".", DIR), ("..", DIR), ("etc", DIR), ("tmp", DIR)],
        "/etc" => &[(".", DIR), ("..", DIR), ("motd", REG)],
        "/tmp" => &[(".", DIR), ("..", DIR), ("probe", REG)],
        _ => return Err(NO_ENTRY),
    };
    Ok(entries.get(index as usize).copied())
}

/// Whether a READ_INTO may run: file descriptor 0, a count within
/// `proto_fs::READ_INTO_MAX`, a place on a page boundary, exactly one handle
/// that is a memory object with `MAP_READ` and `MAP_WRITE` (`writable`), and
/// room for the count's pages in the object from the place (`size`, its
/// bytes). The copy is one step of the service's loop, so the count bounds
/// that step.
pub fn read_into_valid(
    fd: u32,
    count: usize,
    at: u64,
    handles: usize,
    writable: bool,
    size: u64,
) -> bool {
    let len = (count as u64).next_multiple_of(4096);
    fd == 0
        && count <= proto_fs::READ_INTO_MAX
        && at.is_multiple_of(4096)
        && handles == 1
        && writable
        && at.checked_add(len).is_some_and(|end| end <= size)
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
    Node(Token),
    NodeDir(Token),
    /// Entry `n` of the table, a directory or a regular file.
    ImageDir(u16),
    ImageRegular(u16),
    /// The entry `/dev/null` of the table: writes are accepted and
    /// dropped, reads are at the end of the file.
    Null(u16),
    /// The entries `/dev/random` and `/dev/urandom` of the table: writes
    /// are accepted and dropped; the bytes of a read come from the
    /// client's layer, so the service refuses to read them.
    Random(u16),
}

#[derive(Clone, Copy)]
struct Open {
    file: File,
    offset: i64,
    flags: u32,
}

/// The descriptors of one session: each names an open description of the
/// service (`Ram`), which sessions a client cloned for its children share
/// with their offsets and access modes (Clone). `claimed`: the session's
/// first request took what Clone made for its label.
#[derive(Clone, Copy)]
pub struct Fds {
    slots: [Option<u8>; OPEN_MAX],
    pub claimed: bool,
    pub binding: authority::Binding,
    pub authority_index: u16,
    pub binding_preparation: Option<u16>,
    pub binding_source: Option<(u16, u64)>,
    pub resolvers: [u64; 16],
    pub root: storage::Root,
    pub cwd: Option<Token>,
    preparations: [Option<storage::Reservation>; 16],
}

impl Default for Fds {
    fn default() -> Self {
        Self {
            slots: [None; OPEN_MAX],
            claimed: false,
            binding: authority::Binding::Unbound,
            authority_index: storage::NONE,
            binding_preparation: None,
            binding_source: None,
            resolvers: [0; 16],
            root: BOOT_ROOT,
            cwd: None,
            preparations: [None; 16],
        }
    }
}

impl Fds {
    /// The description of `fd`.
    fn description(&self, fd: u32) -> Result<usize, u32> {
        let slot = fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        self.slots
            .get(slot)
            .copied()
            .flatten()
            .map(usize::from)
            .ok_or(BAD_FD)
    }

    /// The descriptors that name a description, for a session that goes.
    pub fn numbers(&self) -> impl Iterator<Item = u32> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, d)| d.is_some())
            .map(|(slot, _)| slot as u32 + 3)
    }
}

/// An open description and the descriptors of all sessions that name it.
#[derive(Clone, Copy)]
struct Shared {
    open: Open,
    refs: u16,
    root: storage::Root,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileTimes {
    access: u64,
    modify: u64,
    change: u64,
}

impl File {
    fn is_directory(self) -> bool {
        matches!(
            self,
            Self::Root | Self::Etc | Self::Tmp | Self::ImageDir(_) | Self::NodeDir(_)
        )
    }

    /// A character device: writes are dropped, and it has no contents.
    fn is_device(self) -> bool {
        matches!(self, Self::Null(_) | Self::Random(_))
    }

    /// The kind of the file as the protocol numbers it.
    fn kind(self) -> u32 {
        if self.is_directory() {
            DIR
        } else if self.is_device() {
            CHAR
        } else {
            REG
        }
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
            Self::ImageDir(_)
            | Self::ImageRegular(_)
            | Self::Null(_)
            | Self::Random(_)
            | Self::Node(_)
            | Self::NodeDir(_) => None,
        }
    }
}

pub struct Ram<'a> {
    pub storage: Storage<'a>,
    /// The open descriptions, shared by the sessions that name them.
    descriptions: [Option<Shared>; DESCRIPTIONS],
    description_generations: [u64; DESCRIPTIONS],
    tree: Option<Tree<'a>>,
}

#[cfg(test)]
impl Default for Ram<'_> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<'a> Ram<'a> {
    #[cfg(test)]
    pub fn new(now: u64) -> Self {
        Self::test_ram(now, None)
    }

    #[cfg(test)]
    pub fn with_tree(now: u64, tree: Tree<'a>) -> Self {
        Self::test_ram(now, Some(tree))
    }

    #[cfg(test)]
    fn test_ram(now: u64, tree: Option<Tree<'a>>) -> Self {
        extern crate std;
        // SAFETY: State consists of integer arrays, booleans and optional integer accounts.
        let state = std::boxed::Box::leak(unsafe {
            std::boxed::Box::<storage::State>::new_zeroed().assume_init()
        });
        state.initialize();
        let data =
            std::boxed::Box::leak(std::vec![0; storage::PAGES * storage::PAGE].into_boxed_slice());
        Self::with_storage(now, state, data, tree)
    }

    pub fn with_storage(
        now: u64,
        state: &'a mut storage::State,
        data: &'a mut [u8],
        tree: Option<Tree<'a>>,
    ) -> Self {
        Self {
            storage: Storage::new(state, data, tree, now),
            descriptions: [None; DESCRIPTIONS],
            description_generations: [0; DESCRIPTIONS],
            tree,
        }
    }

    fn token(&self, file: File) -> Token {
        match file {
            File::Root => storage::ROOT,
            File::Etc => Token {
                slot: 1,
                generation: 1,
            },
            File::Tmp => Token {
                slot: 2,
                generation: 1,
            },
            File::Motd => Token {
                slot: 3,
                generation: 1,
            },
            File::Scratch => Token {
                slot: 4,
                generation: 1,
            },
            File::ImageDir(n) | File::ImageRegular(n) | File::Null(n) | File::Random(n) => Token {
                slot: 5 + storage::canonical(self.tree(), n),
                generation: 1,
            },
            File::Node(token) | File::NodeDir(token) => token,
        }
    }

    fn file(&self, token: Token) -> File {
        match token.slot {
            0 => File::Root,
            1 => File::Etc,
            2 => File::Tmp,
            3 => File::Motd,
            4 => File::Scratch,
            n if (n as usize) < storage::ORIGINALS => image_file(self.tree(), n - 5),
            _ if self.storage.node(token).is_ok_and(|n| n.kind == DIR) => File::NodeDir(token),
            _ => File::Node(token),
        }
    }

    fn length(&self, file: File) -> usize {
        self.storage
            .node(self.token(file))
            .map_or(0, |n| n.length as usize)
    }

    /// The open description `fd` of `fds` names.
    fn get(&self, fds: &Fds, fd: u32) -> Result<Open, u32> {
        let index = fds.description(fd)?;
        Ok(self.descriptions[index].expect("a named description").open)
    }

    /// The open description `fd` of `fds` names takes `open`.
    fn put(&mut self, fds: &Fds, fd: u32, open: Open) -> Result<(), u32> {
        let index = fds.description(fd)?;
        self.descriptions[index]
            .as_mut()
            .expect("a named description")
            .open = open;
        Ok(())
    }

    /// A new description of `open` under the lowest free descriptor of
    /// `fds`: TOO_MANY_OPEN_FILES with the session's descriptors or the
    /// service's descriptions taken.
    fn insert(&mut self, fds: &mut Fds, open: Open) -> Result<u32, u32> {
        let slot = fds
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
        let index = self
            .descriptions
            .iter()
            .position(Option::is_none)
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
        let generation = self.description_generations[index]
            .checked_add(1)
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
        self.storage.charge_description(fds.root)?;
        if let Err(code) = self.storage.pin(self.token(open.file), Pin::Fd) {
            self.storage.release_description(fds.root);
            return Err(code);
        }
        self.descriptions[index] = Some(Shared {
            open,
            refs: 1,
            root: fds.root,
            generation,
        });
        self.description_generations[index] = generation;
        fds.slots[slot] = Some(index as u8);
        Ok(slot as u32 + 3)
    }

    /// Close: the descriptor goes, and its description with the last one
    /// that names it, in any session.
    pub fn close(&mut self, fds: &mut Fds, fd: u32) -> Result<(), u32> {
        let index = fds.description(fd)?;
        fds.slots[(fd - 3) as usize] = None;
        let shared = self.descriptions[index]
            .as_mut()
            .expect("a named description");
        shared.refs -= 1;
        if shared.refs == 0 {
            let file = shared.open.file;
            let root = shared.root;
            let token = self.token(file);
            self.descriptions[index] = None;
            self.storage.unpin(token, Pin::Fd)?;
            self.storage.release_description(root);
        }
        Ok(())
    }

    /// The descriptors of a session that goes, all of them closed.
    pub fn reserve_create(
        &mut self,
        fds: &mut Fds,
        parent: Token,
        name: &[u8],
        kind: u32,
    ) -> Result<storage::Reservation, u32> {
        let place = fds
            .preparations
            .iter()
            .position(Option::is_none)
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
        let r = self
            .storage
            .reserve(fds.root, parent, name, (kind, 0o644, 0, 0))?;
        fds.preparations[place] = Some(r);
        Ok(r)
    }

    pub fn commit_create(&mut self, fds: &mut Fds, r: storage::Reservation) -> Result<Token, u32> {
        let place = fds
            .preparations
            .iter()
            .position(|p| p.is_some_and(|p| p.token == r.token))
            .ok_or(NO_ENTRY)?;
        let token = self.storage.commit(r)?;
        fds.preparations[place] = None;
        Ok(token)
    }

    /// One reference or preparation per cleanup step.
    pub fn release_step(&mut self, fds: &mut Fds) -> bool {
        if let Some(root) = fds.binding_preparation.take() {
            self.storage.release_preparation(root);
            fds.binding_source = None;
            return true;
        }
        if let Some(r) = fds
            .preparations
            .iter_mut()
            .find(|r| r.is_some())
            .and_then(Option::take)
        {
            let _ = self.storage.cancel(r);
            return true;
        }
        if let Some(cwd) = fds.cwd.take() {
            let _ = self.storage.unpin(cwd, Pin::Cwd);
            return true;
        }
        let first = fds.numbers().next();
        if let Some(fd) = first {
            let _ = self.close(fds, fd);
            return true;
        }
        false
    }

    pub fn description_token(&self, fds: &Fds, fd: u32) -> Result<Token, u32> {
        let slot = fds.description(fd)?;
        Ok(Token {
            slot: slot as u16,
            generation: self.descriptions[slot]
                .expect("named description")
                .generation,
        })
    }

    /// A raw token can serve as a relative base only when this session retains it.
    pub fn owns_directory_base(&self, fds: &Fds, token: Token) -> bool {
        if !self.storage.node(token).is_ok_and(|n| n.kind == DIR) {
            return false;
        }
        fds.cwd.unwrap_or(storage::ROOT) == token
            || fds
                .numbers()
                .any(|fd| self.description_token(fds, fd) == Ok(token))
    }
    pub fn set_cwd_token(&mut self, fds: &mut Fds, token: Token) -> Result<(), u32> {
        if self.storage.node(token)?.kind != DIR {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        self.storage.pin(token, Pin::Cwd)?;
        if let Some(old) = fds.cwd.replace(token) {
            self.storage.unpin(old, Pin::Cwd)?;
        }
        Ok(())
    }

    pub fn release(&mut self, fds: &mut Fds) {
        if let Some(root) = fds.binding_preparation.take() {
            self.storage.release_preparation(root);
        }
        fds.binding_source = None;
        if let Some(cwd) = fds.cwd.take() {
            let _ = self.storage.unpin(cwd, Pin::Cwd);
        }
        for r in &mut fds.preparations {
            if let Some(r) = r.take() {
                let _ = self.storage.cancel(r);
            }
        }
        let numbers: [Option<u32>; OPEN_MAX] = {
            let mut list = [None; OPEN_MAX];
            for (place, fd) in list.iter_mut().zip(fds.numbers()) {
                *place = Some(fd);
            }
            list
        };
        for fd in numbers.into_iter().flatten() {
            let _ = self.close(fds, fd);
        }
    }

    /// Clone's descriptors: a session's of the same numbers as `list` of
    /// `fds`, which share their descriptions, offsets and access modes;
    /// BAD_FD for a number no descriptor has. O(OPEN_MAX).
    pub fn clone_fds(&mut self, fds: &Fds, list: &[u32]) -> Result<Fds, u32> {
        let mut out = Fds {
            root: fds.root,
            ..Fds::default()
        };
        for &fd in list {
            let index = fds.description(fd)?;
            out.slots[(fd - 3) as usize] = Some(index as u8);
        }
        if let Some(cwd) = fds.cwd {
            self.storage.pin(cwd, Pin::Cwd)?;
            out.cwd = Some(cwd);
        }
        for index in out.slots.iter().flatten() {
            self.descriptions[usize::from(*index)]
                .as_mut()
                .expect("a named description")
                .refs += 1;
        }
        Ok(out)
    }

    /// The descriptions that are open.
    pub fn open_descriptions(&self) -> usize {
        self.descriptions.iter().flatten().count()
    }

    pub fn seek(&mut self, fds: &mut Fds, fd: u32, offset: u32) -> Result<u32, u32> {
        let mut open = self.get(fds, fd)?;
        open.offset = i64::from(offset);
        self.put(fds, fd, open)?;
        Ok(offset)
    }

    fn resolve(&self, path: &str) -> Result<File, u32> {
        Ok(self.file(self.storage.resolve(path.as_bytes())?))
    }

    /// Whether the description `fd` is a random device, whose reads the
    /// client's layer serves.
    pub fn is_random(&self, fds: &Fds, fd: u32) -> bool {
        self.get(fds, fd)
            .is_ok_and(|open| matches!(open.file, File::Random(_)))
    }

    pub fn open(&mut self, fds: &mut Fds, path: &str, flags: u32) -> Result<u32, u32> {
        if flags & !15 != 0 || flags & 3 == 3 {
            return Err(proto_wire::BAD_SIZE);
        }
        let directory_only = flags & proto_fs::DIRECTORY_ONLY != 0;
        let changes = flags & proto_fs::CHANGES != 0;
        let flags = flags & 3;
        // Creating is not done yet: a file that is missing is as much
        // refused as one that is no device.
        let file = match self.resolve(path) {
            Err(NO_ENTRY) if changes => return Err(proto_fs::INVALID_ARGUMENT),
            found => found?,
        };
        self.open_file(
            fds,
            file,
            flags
                | if directory_only {
                    proto_fs::DIRECTORY_ONLY
                } else {
                    0
                }
                | if changes { proto_fs::CHANGES } else { 0 },
        )
    }

    pub fn open_token(
        &mut self,
        fds: &mut Fds,
        token: Token,
        flags: u32,
        identity: authority::Identity,
    ) -> Result<u32, u32> {
        if flags & !15 != 0 || flags & 3 == 3 {
            return Err(proto_wire::BAD_SIZE);
        }
        let file = self.file(token);
        if flags & proto_fs::CHANGES != 0 && !file.is_device() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let node = self.storage.node(token)?;
        let bits = match flags & 3 {
            proto_fs::READ_ONLY => 4,
            proto_fs::WRITE_ONLY => 2,
            _ => 6,
        };
        if !identity.permits(node, bits) {
            return Err(proto_fs::ACCESS_DENIED);
        }
        self.open_file(fds, self.file(token), flags)
    }

    fn open_file(&mut self, fds: &mut Fds, file: File, flags: u32) -> Result<u32, u32> {
        let changes = flags & proto_fs::CHANGES != 0;
        let directory_only = flags & proto_fs::DIRECTORY_ONLY != 0;
        let flags = flags & 3;
        if changes && !file.is_device() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if file.is_directory() && flags != READ_ONLY {
            return Err(IS_DIRECTORY);
        }
        if matches!(file, File::Motd | File::ImageRegular(_)) && flags != READ_ONLY {
            return Err(proto_fs::ACCESS_DENIED);
        }
        if directory_only && !file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        self.insert(
            fds,
            Open {
                file,
                offset: 0,
                flags,
            },
        )
    }

    fn touch_access(&mut self, file: File, now: u64) {
        if file.index().is_some() {
            self.storage
                .node_mut(self.token(file))
                .expect("live inode")
                .times[0] = now;
        }
    }

    fn inode(&self, file: File) -> u64 {
        match file {
            File::Root => 1,
            File::Etc => 2,
            File::Tmp => 3,
            File::Motd => 4,
            File::Scratch => 5,
            File::Node(token) | File::NodeDir(token) => {
                (u64::from(token.slot) + 1) | token.generation << 32
            }
            File::ImageDir(n) | File::ImageRegular(n) | File::Null(n) | File::Random(n) => {
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
                // `..` of a node needs it to be a directory `who` may
                // search, as any other name in it.
                let here = core::str::from_utf8(&plain[..len]).map_err(|_| NO_ENTRY)?;
                let info = self.information(here)?;
                if info.kind != DIR {
                    return Err(proto_fs::NOT_DIRECTORY);
                }
                if !may(&info, who, 0o1) {
                    return Err(proto_fs::ACCESS_DENIED);
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
    pub fn exec_token(&self, token: Token, identity: authority::Identity) -> Result<Exec, u32> {
        let n = self.storage.node(token)?;
        if n.kind != REG || n.boot == storage::NONE || !identity.permits(n, 1) {
            return Err(proto_fs::ACCESS_DENIED);
        }
        Ok(Exec {
            entry: n.boot,
            mode: n.mode,
            uid: n.uid,
            gid: n.gid,
        })
    }

    pub fn token_information(&self, token: Token) -> Result<NodeInfo, u32> {
        self.storage.node(token)?;
        Ok(self.node_information(self.file(token)))
    }

    pub fn directory_read_token(
        &mut self,
        token: Token,
        index: u32,
        identity: authority::Identity,
        now: u64,
    ) -> Result<Option<DirectoryRecord<'a>>, u32> {
        let node = self.storage.node(token)?;
        if node.kind != DIR {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        if !identity.permits(node, 4) {
            return Err(proto_fs::ACCESS_DENIED);
        }
        Ok(self.entry_of(self.file(token), index, now))
    }

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
        let tree = self.tree.as_ref().ok_or(NO_ENTRY)?;
        if entry >= tree.len() || tree.entry(entry).is_directory() {
            return Err(NO_ENTRY);
        }
        if i64::try_from(offset).is_err() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        self.storage
            .read(self.token(File::ImageRegular(entry)), offset, out)
    }

    fn node_information(&self, file: File) -> NodeInfo {
        let size = self.length(file) as u64;
        let n = self.storage.node(self.token(file)).expect("live inode");
        let times = FileTimes {
            access: n.times[0],
            modify: n.times[1],
            change: n.times[2],
        };
        let (kind, links, permissions, uid, gid) =
            (n.kind, u64::from(n.links), n.mode, n.uid, n.gid);
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

    pub fn descriptor_information(&self, fds: &Fds, fd: u32) -> Result<NodeInfo, u32> {
        Ok(self.node_information(self.get(fds, fd)?.file))
    }

    /// A successful nonempty request updates atime even when it reads EOF.
    pub fn read_at(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        out: &mut [u8],
        now: u64,
    ) -> Result<usize, u32> {
        let file = self.get(fds, fd)?.file;
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
        let open = self.get(fds, fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags == WRITE_ONLY {
            return Err(BAD_FD);
        }
        if i64::try_from(offset).is_err() || matches!(open.file, File::Random(_)) {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let n = self.storage.read(self.token(open.file), offset, out)?;
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
        let file = self.get(fds, fd)?.file;
        let n = self.write(fds, fd, bytes)?;
        // The null device keeps no times.
        if n > 0 && file.index().is_some() {
            let node = self.storage.node_mut(self.token(file)).expect("live inode");
            node.times[1] = now;
            node.times[2] = now;
        }
        Ok(n)
    }

    /// pwrite: `bytes` at `offset` of the file, the position of the open
    /// description as it was.
    pub fn pwrite(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        offset: u64,
        bytes: &[u8],
        now: u64,
    ) -> Result<usize, u32> {
        let at = i64::try_from(offset).map_err(|_| proto_fs::INVALID_ARGUMENT)?;
        let mut open = self.get(fds, fd)?;
        let position = open.offset;
        open.offset = at;
        self.put(fds, fd, open)?;
        let written = self.write_at(fds, fd, bytes, now);
        open.offset = position;
        self.put(fds, fd, open)?;
        written
    }

    pub fn directory_read(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        now: u64,
    ) -> Result<Option<DirectoryRecord<'a>>, u32> {
        let mut open = self.get(fds, fd)?;
        if !open.file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        let index = u32::try_from(open.offset).map_err(|_| proto_fs::INVALID_ARGUMENT)?;
        let entry = self.entry_of(open.file, index, now);
        if entry.is_some() {
            open.offset += 1;
            self.put(fds, fd, open)?;
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
                        kind: file.kind(),
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
                let file = image_file(&tree, n);
                Some(DirectoryRecord {
                    name: name_of(&tree, n),
                    kind: file.kind(),
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
        Ok(Metadata {
            kind: file.kind(),
            size: self.length(file) as u32,
        })
    }

    pub fn size(&self, fds: &Fds, fd: u32) -> Result<u32, u32> {
        Ok(self.length(self.get(fds, fd)?.file) as u32)
    }

    /// Reposition one open description without extending its file. RAM files
    /// expose a single data extent and the required virtual hole at EOF.
    pub fn seek_from(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        offset: i64,
        origin: proto_fs::SeekFrom,
    ) -> Result<i64, u32> {
        use proto_fs::{INVALID_ARGUMENT, NO_DATA, OFFSET_OVERFLOW, SeekFrom};
        let mut open = self.get(fds, fd)?;
        if open.file.is_directory() && matches!(origin, SeekFrom::Data | SeekFrom::Hole) {
            return Err(INVALID_ARGUMENT);
        }
        let size = if open.file.is_directory() {
            self.directory_count(open.file)
        } else {
            self.length(open.file) as i64
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
        self.put(fds, fd, open)?;
        Ok(next)
    }

    pub fn read(&mut self, fds: &mut Fds, fd: u32, out: &mut [u8]) -> Result<usize, u32> {
        let mut open = self.get(fds, fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags == WRITE_ONLY {
            return Err(BAD_FD);
        }
        if matches!(open.file, File::Random(_)) {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let n = self
            .storage
            .read(self.token(open.file), open.offset as u64, out)?;
        open.offset += n as i64;
        self.put(fds, fd, open)?;
        Ok(n)
    }

    pub fn write(&mut self, fds: &mut Fds, fd: u32, bytes: &[u8]) -> Result<usize, u32> {
        let mut open = self.get(fds, fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags == READ_ONLY || matches!(open.file, File::Motd | File::ImageRegular(_)) {
            return Err(BAD_FD);
        }
        if bytes.is_empty() || open.file.is_device() {
            return Ok(bytes.len());
        }
        let offset = usize::try_from(open.offset).map_err(|_| NO_SPACE)?;
        let end = offset.checked_add(bytes.len()).ok_or(NO_SPACE)?;
        if end > FILE_CAPACITY {
            return Err(NO_SPACE);
        }
        self.storage
            .write(self.token(open.file), fds.root, offset, bytes)?;
        open.offset = end as i64;
        self.put(fds, fd, open)?;
        Ok(bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_fs::READ_WRITE;

    /// The checks of READ_INTO, one at a time: each refusal is its own
    /// (dropping any check lets its case through).
    #[test]
    fn read_into_checks_each_argument() {
        let ok = |fd, count, at, handles, writable, size| {
            read_into_valid(fd, count, at, handles, writable, size)
        };
        let max = proto_fs::READ_INTO_MAX;
        assert!(ok(0, max, 0, 1, true, max as u64));
        assert!(ok(0, 1, 4096, 1, true, 8192));
        assert!(!ok(1, 10, 0, 1, true, 4096), "fd other than 0");
        assert!(!ok(0, max + 1, 0, 1, true, 1 << 20), "count past the limit");
        assert!(!ok(0, 10, 100, 1, true, 8192), "place off a page boundary");
        assert!(!ok(0, 10, 0, 0, true, 4096), "no object");
        assert!(!ok(0, 10, 0, 2, true, 4096), "two handles");
        assert!(!ok(0, 10, 0, 1, false, 4096), "no MAP_WRITE");
        assert!(
            !ok(0, 4097, 0, 1, true, 4096),
            "object shorter than the count"
        );
        assert!(!ok(0, 10, 4096, 1, true, 4096), "place at the object's end");
        assert!(
            !ok(0, 10, u64::MAX - 4095, 1, true, u64::MAX),
            "place that wraps"
        );
    }

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
        ram.close(&mut fds, fd).unwrap();
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
        ram.seek(&mut a, fa, FILE_CAPACITY as u32).unwrap();
        assert_eq!(ram.write_at(&mut a, fa, b"x", 80), Err(NO_SPACE));
        assert_eq!(ram.information("/tmp/probe").unwrap(), info);
        ram.close(&mut b, fb).unwrap();
        assert_eq!(ram.descriptor_information(&b, fb), Err(BAD_FD));
        assert_eq!(ram.information("/missing"), Err(NO_ENTRY));
        assert_eq!(ram.information("/").unwrap(), root);
    }

    #[test]
    fn description_limit_reports_emfile_and_recovers_on_close() {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        for expected in 3..OPEN_MAX as u32 + 3 {
            assert_eq!(ram.open(&mut fds, "/etc/motd", READ_ONLY), Ok(expected));
        }
        assert_eq!(
            ram.open(&mut fds, "/etc/motd", READ_ONLY),
            Err(proto_fs::TOO_MANY_OPEN_FILES)
        );
        ram.close(&mut fds, 7).unwrap();
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
        let mut ram = Ram::default();
        let mut a = Fds::default();
        let mut b = Fds::default();
        let fa = ram.open(&mut a, "/etc/motd", READ_ONLY).unwrap();
        let fb = ram.open(&mut b, "/etc/motd", READ_ONLY).unwrap();
        let mut out = [0; 7];
        assert_eq!(ram.read(&mut a, fa, &mut out), Ok(7));
        assert_eq!(&out, b"stafeto");
        assert_eq!(ram.read(&mut b, fb, &mut out), Ok(7));
        assert_eq!(&out, b"stafeto");
        assert_eq!(ram.close(&mut a, fa), Ok(()));
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
        ram.close(&mut fds, fd).unwrap();
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
        ram.seek(&mut fds, write, 100).unwrap();
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
        assert_eq!(ram.seek(&mut fds, fd, 1), Ok(1));
        assert_eq!(ram.write(&mut fds, fd, b"Z"), Ok(1));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(
            ram.seek(&mut fds, fd, FILE_CAPACITY as u32),
            Ok(FILE_CAPACITY as u32)
        );
        assert_eq!(ram.write(&mut fds, fd, b"overflow"), Err(NO_SPACE));
        assert_eq!(ram.size(&fds, fd), Ok(3));
        assert_eq!(ram.seek(&mut fds, fd, 0), Ok(0));
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
        assert_eq!(ram.information("/bin/ash/x"), Err(proto_fs::NOT_DIRECTORY));
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

    /// The null device takes any write whole and drops it, reads end at
    /// once and the size stays zero, though the file of the table has
    /// bytes; the other image files stay read-only.
    #[test]
    fn the_null_device_drops_writes_and_reads_nothing() {
        let bytes = test_image(&[
            entry("/dev", DIRECTORY | 0o755, 0),
            entry("/dev/null", REGULAR | 0o666, 2),
            entry("/dev/other", REGULAR | 0o666, 2),
        ]);
        let mut index = Index::new();
        let mut ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/dev/null", READ_WRITE).unwrap();
        let block = [7u8; 4096];
        for _ in 0..512 {
            assert_eq!(ram.write_at(&mut fds, fd, &block, 20), Ok(4096));
        }
        assert_eq!(ram.pwrite(&mut fds, fd, 9, b"abc", 21), Ok(3));
        assert_eq!(ram.size(&fds, fd), Ok(0));
        let mut out = [1u8; 8];
        assert_eq!(ram.read(&mut fds, fd, &mut out), Ok(0));
        assert_eq!(ram.pread(&fds, fd, 0, &mut out, 22), Ok(0));
        assert_eq!(ram.information("/dev/null").unwrap().size, 0);
        let writer = ram.open(&mut fds, "/dev/null", WRITE_ONLY).unwrap();
        assert_eq!(ram.write(&mut fds, writer, b"x"), Ok(1));
        // O_CREAT, O_TRUNC and O_APPEND reach the device and nothing else.
        let cut = ram
            .open(&mut fds, "/dev/null", WRITE_ONLY | proto_fs::CHANGES)
            .unwrap();
        assert_eq!(ram.write(&mut fds, cut, b"z"), Ok(1));
        assert_eq!(
            ram.open(&mut fds, "/dev/other", WRITE_ONLY | proto_fs::CHANGES),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(
            ram.open(&mut fds, "/dev/none", WRITE_ONLY | proto_fs::CHANGES),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        // Another file of the table is no device.
        assert_eq!(
            ram.open(&mut fds, "/dev/other", WRITE_ONLY),
            Err(proto_fs::ACCESS_DENIED)
        );
    }

    /// The random devices: the open says so (the layer reads them), a
    /// write is dropped, the service refuses to read or pread them, the
    /// size stays zero, and `/dev/null` and the two are character devices
    /// by `lookup`, `information` and the directory.
    #[test]
    fn the_random_devices_are_characters_the_layer_reads() {
        let bytes = test_image(&[
            entry("/dev", DIRECTORY | 0o755, 0),
            entry("/dev/null", REGULAR | 0o666, 2),
            entry("/dev/random", REGULAR | 0o666, 2),
            entry("/dev/urandom", REGULAR | 0o666, 2),
            entry("/dev/other", REGULAR | 0o666, 2),
        ]);
        let mut index = Index::new();
        let mut ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
        let mut fds = Fds::default();
        for path in ["/dev/random", "/dev/urandom"] {
            let fd = ram.open(&mut fds, path, READ_WRITE).unwrap();
            assert!(ram.is_random(&fds, fd), "{path}");
            assert_eq!(ram.write(&mut fds, fd, b"abc"), Ok(3));
            assert_eq!(ram.write_at(&mut fds, fd, &[1; 4096], 20), Ok(4096));
            assert_eq!(ram.size(&fds, fd), Ok(0));
            let mut out = [9u8; 8];
            assert_eq!(
                ram.read(&mut fds, fd, &mut out),
                Err(proto_fs::INVALID_ARGUMENT)
            );
            assert_eq!(
                ram.pread(&fds, fd, 0, &mut out, 22),
                Err(proto_fs::INVALID_ARGUMENT)
            );
            assert_eq!(out, [9u8; 8], "no byte of the service");
            assert_eq!(ram.lookup(path).map(|m| m.kind), Ok(CHAR));
            assert_eq!(ram.information(path).map(|i| i.kind), Ok(CHAR));
            let cut = ram
                .open(&mut fds, path, WRITE_ONLY | proto_fs::CHANGES)
                .unwrap();
            assert!(ram.is_random(&fds, cut));
        }
        let null = ram.open(&mut fds, "/dev/null", READ_ONLY).unwrap();
        assert!(!ram.is_random(&fds, null));
        assert_eq!(ram.lookup("/dev/null").map(|m| m.kind), Ok(CHAR));
        let other = ram.open(&mut fds, "/dev/other", READ_ONLY).unwrap();
        assert!(!ram.is_random(&fds, other));
        assert_eq!(ram.lookup("/dev/other").map(|m| m.kind), Ok(REG));
        let kinds: Vec<(&str, u32)> = (0..8)
            .filter_map(|i| ram.directory_read_path("/dev", i, 30).unwrap())
            .map(|r| (r.name, r.kind))
            .collect();
        assert!(kinds.contains(&("null", CHAR)), "{kinds:?}");
        assert!(kinds.contains(&("random", CHAR)), "{kinds:?}");
        assert!(kinds.contains(&("urandom", CHAR)), "{kinds:?}");
        assert!(kinds.contains(&("other", REG)), "{kinds:?}");
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
        ram.close(&mut fds, fd).unwrap();
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
        let mut ram = Ram::with_tree(10, load(&bytes, &mut index).unwrap());
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
            index: 0,
            ctty: None,
            image: 1,
            groups: proto_process::Groups::EMPTY,
            limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
            root: proto_process::ExpenditureRoot {
                pid: 2,
                generation: 1,
            },
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
            index: 0,
            ctty: None,
            image: 1,
            groups: proto_process::Groups::EMPTY,
            limits: proto_process::ResourceLimits::initial(2 * 1024 * 1024),
            root: proto_process::ExpenditureRoot {
                pid: 2,
                generation: 1,
            },
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
        // `..` of a file, and of a directory only root may search.
        assert_eq!(
            ram.exec("/bin/ash/../ash", nobody),
            Err(proto_fs::NOT_DIRECTORY)
        );
        assert_eq!(
            ram.exec("/bin/sub/../ash", nobody),
            Err(proto_fs::ACCESS_DENIED)
        );
        assert_eq!(ram.exec("/bin/sub/../ash", root), Ok(ash));
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

    /// Clone's session shares the descriptions it names: an offset one
    /// session moves the other sees; a close in one leaves the description
    /// to the other, and the last close frees it.
    #[test]
    fn cloned_sessions_share_descriptions_and_offsets() {
        let mut ram = Ram::default();
        let mut parent = Fds::default();
        let fd = ram.open(&mut parent, "/etc/motd", READ_ONLY).unwrap();
        let other = ram.open(&mut parent, "/tmp/probe", READ_WRITE).unwrap();
        let mut child = ram.clone_fds(&parent, &[fd]).unwrap();
        assert_eq!(ram.read(&mut child, fd, &mut [0; 10]), Ok(10));
        assert_eq!(
            ram.seek_from(&mut parent, fd, 0, proto_fs::SeekFrom::Current),
            Ok(10)
        );
        assert_eq!(
            ram.read(&mut child, other, &mut [0; 1]),
            Err(BAD_FD),
            "not cloned"
        );
        assert_eq!(ram.open_descriptions(), 2);
        ram.close(&mut parent, fd).unwrap();
        assert_eq!(ram.open_descriptions(), 2, "the child still names it");
        assert_eq!(ram.read(&mut child, fd, &mut [0; 10]), Ok(4));
        ram.release(&mut child);
        assert_eq!(ram.open_descriptions(), 1);
        assert_eq!(ram.clone_fds(&parent, &[fd]).err(), Some(BAD_FD));
        ram.release(&mut parent);
        assert_eq!(ram.open_descriptions(), 0);
    }

    /// The service's descriptions are bounded across its sessions.
    #[test]
    fn descriptions_are_bounded_across_sessions() {
        let mut ram = Ram::default();
        let mut sessions = [Fds::default(); DESCRIPTIONS / OPEN_MAX];
        for (i, fds) in sessions.iter_mut().enumerate() {
            fds.root = storage::Root {
                id: i as u64 + 1,
                generation: 1,
            };
            for _ in 0..OPEN_MAX {
                ram.open(fds, "/etc/motd", READ_ONLY).unwrap();
            }
        }
        let mut one_more = Fds::default();
        assert_eq!(
            ram.open(&mut one_more, "/etc/motd", READ_ONLY),
            Err(proto_fs::TOO_MANY_OPEN_FILES)
        );
        ram.release(&mut sessions[0]);
        assert!(ram.open(&mut one_more, "/etc/motd", READ_ONLY).is_ok());
    }
}
