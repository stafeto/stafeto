// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! RAM inode storage with fixed boot nodes, paid mutable overlays and
//! shared open descriptions. One service thread owns the namespace and
//! every client retains its descriptors, current directory and preparations.
//! The original guest operations use this storage; mutation entry points
//! are exercised through the same backend on the host.
#![cfg_attr(not(test), no_std)]

pub mod authority;
pub mod change;
#[cfg(test)]
mod change_tests;
pub mod cwd;
#[cfg(test)]
mod cwd_tests;
pub mod data;
pub mod directory;
#[cfg(test)]
mod directory_tests;
pub mod image;
#[cfg(test)]
mod image_tests;
pub mod io;
#[cfg(test)]
mod io_tests;
pub mod job;
pub mod maintenance;
pub mod metadata;
#[cfg(test)]
mod metadata_tests;
pub use storage::namespace;
#[cfg(test)]
mod create_tests;
#[cfg(test)]
mod namespace_tests;
pub mod open;
pub mod places;
pub mod resolve;
#[cfg(test)]
mod resolve_tests;
pub mod storage;
#[cfg(test)]
mod storage_tests;
pub mod time_source;
pub mod tree;

use storage::{BOOT_ROOT, Pin, Storage, Token};

/// Read the common Clone count before allocating a session or retaining references.
pub fn clone_count(body: &mut proto_wire::Reader<'_>, handle_count: usize) -> Result<usize, u32> {
    let count = body.u32().map_err(|_| proto_wire::BAD_SIZE)? as usize;
    if count > OPEN_MAX || handle_count != 0 {
        return Err(proto_wire::BAD_SIZE);
    }
    Ok(count)
}

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

/// One name of a directory as the listing gives it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryRecord {
    name: [u8; 255],
    length: u8,
    pub kind: u32,
    pub inode: u64,
}
impl DirectoryRecord {
    fn new(name: &[u8], kind: u32, inode: u64) -> Self {
        let mut bytes = [0; 255];
        bytes[..name.len()].copy_from_slice(name);
        Self {
            name: bytes,
            length: name.len() as u8,
            kind,
            inode,
        }
    }
    pub fn name(&self) -> &[u8] {
        &self.name[..self.length as usize]
    }
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

/// What the walk to the next name of a directory gave.
#[allow(clippy::large_enum_variant)]
enum Walked {
    Entry(u64, u16, DirectoryRecord),
    End,
    More(u16),
}

/// The last index the call by index of the service serves: it counts from the
/// head of the list, so that its step is bounded by the portion of the list
/// (the layer lists by descriptor, a portion of the list at a time).
pub const INDEX_MAX: u32 = 2 + storage::LIST_PORTION as u32;

#[derive(Clone, Copy)]
struct Open {
    file: File,
    /// For a directory the cookie of the last name given: the next name is
    /// the first one with a greater cookie.
    offset: i64,
    flags: u32,
    /// For a directory the entry that has the cookie `offset`, a shortcut
    /// that is checked before it is used.
    hint: u16,
    /// For a directory the entry a walk to `offset` has reached when its
    /// portion ran out, or NONE; checked before it is used.
    scan: u16,
}

/// The descriptors of one session: each names an open description of the
/// service (`Ram`), which sessions a client cloned for its children share
/// with their offsets and access modes (Clone). `claimed`: the session's
/// first request took what Clone made for its label.
#[derive(Clone, Copy)]
pub struct Fds {
    slots: [Option<u8>; OPEN_MAX],
    /// Reserved descriptions are paid and held, but are not yet public descriptors.
    tentative: u32,
    pub claimed: bool,
    pub binding: authority::Binding,
    pub authority_index: u16,
    pub binding_preparation: Option<u16>,
    pub binding_source: Option<(u16, u64)>,
    /// The completed binding result remains available until a new preparation.
    pub binding_outcome: Option<u32>,
    #[cfg(feature = "auth-probe")]
    pub auth_probe_hold: bool,
    #[cfg(feature = "auth-probe")]
    pub auth_probe_gc: Option<Token>,
    #[cfg(feature = "auth-probe")]
    pub auth_probe_gc_reservation: Option<storage::Reservation>,
    pub resolvers: [u64; 16],
    pub open_watermarks: [u64; proto_fs::JOB_KEY_PLACES],
    pub image_hold: Option<image::ImageHold>,
    pub image_outcome: Option<image::ImageOutcome>,
    /// Exact completed operations survive Close as tombstones until this fd is reused.
    open_receipts: [OpenReceipt; OPEN_MAX],
    pub root: storage::Root,
    pub cwd: Option<Token>,
    preparations: [Option<storage::Reservation>; 16],
}

impl Default for Fds {
    fn default() -> Self {
        Self {
            slots: [None; OPEN_MAX],
            tentative: 0,
            claimed: false,
            binding: authority::Binding::Unbound,
            authority_index: storage::NONE,
            binding_preparation: None,
            binding_source: None,
            binding_outcome: None,
            #[cfg(feature = "auth-probe")]
            auth_probe_hold: false,
            #[cfg(feature = "auth-probe")]
            auth_probe_gc: None,
            #[cfg(feature = "auth-probe")]
            auth_probe_gc_reservation: None,
            resolvers: [0; 16],
            open_watermarks: [0; proto_fs::JOB_KEY_PLACES],
            image_hold: None,
            image_outcome: None,
            open_receipts: [OpenReceipt::EMPTY; OPEN_MAX],
            root: BOOT_ROOT,
            cwd: None,
            preparations: [None; 16],
        }
    }
}

impl Fds {
    /// Transfer one exact retained birth into an unclaimed RT default session.
    pub fn claim_retained_birth(&mut self, birth: &mut Option<(u64, Self)>, label: u64) -> bool {
        let Some((owner, source)) = birth.as_mut().filter(|(owner, _)| *owner == label) else {
            return false;
        };
        debug_assert_eq!(*owner, label);
        debug_assert!(self.fresh_clone_destination());
        core::mem::swap(self, source);
        *birth = None;
        true
    }
    fn fresh_clone_destination(&self) -> bool {
        if self.slots.iter().any(Option::is_some)
            || self.tentative != 0
            || self.claimed
            || self.binding != authority::Binding::Unbound
            || self.authority_index != storage::NONE
            || self.binding_preparation.is_some()
            || self.binding_source.is_some()
            || self.binding_outcome.is_some()
            || self.resolvers.iter().any(|&id| id != 0)
            || self
                .open_watermarks
                .iter()
                .any(|&generation| generation != 0)
            || self.image_hold.is_some()
            || self.image_outcome.is_some()
            || self
                .open_receipts
                .iter()
                .any(|&receipt| receipt != OpenReceipt::EMPTY)
            || self.root != BOOT_ROOT
            || self.cwd.is_some()
            || self.preparations.iter().any(Option::is_some)
        {
            return false;
        }
        #[cfg(feature = "auth-probe")]
        if self.auth_probe_hold
            || self.auth_probe_gc.is_some()
            || self.auth_probe_gc_reservation.is_some()
        {
            return false;
        }
        true
    }
    /// Binding, path jobs, and unpublished creations share one session budget.
    pub fn preparation_count(&self) -> usize {
        self.resolvers.iter().filter(|&&id| id != 0).count()
            + self.preparations.iter().filter(|p| p.is_some()).count()
            + usize::from(self.binding_preparation.is_some())
    }
    pub fn preparation_available(&self) -> bool {
        self.preparation_count() < self.resolvers.len()
    }
    /// Retained references in this session, without authenticating or mutating it.
    #[cfg(feature = "auth-probe")]
    pub fn retained_counts(&self) -> [u32; 5] {
        [
            self.slots.iter().filter(|slot| slot.is_some()).count() as u32,
            u32::from(self.cwd.is_some()),
            u32::from(self.binding_preparation.is_some()),
            u32::from(self.authority_index != storage::NONE),
            self.resolvers.iter().filter(|&&id| id != 0).count() as u32,
        ]
    }
    /// The description of `fd`.
    fn description(&self, fd: u32) -> Result<usize, u32> {
        let slot = fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        if slot >= OPEN_MAX || self.tentative & (1 << slot) != 0 {
            return Err(BAD_FD);
        }
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
            .filter(|(slot, d)| d.is_some() && self.tentative & (1 << slot) == 0)
            .map(|(slot, _)| slot as u32 + 3)
    }
}

/// Exact ownership of a paid descriptor before its Open result is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TentativeOpen {
    pub fd: u32,
    pub description: Token,
}

/// Move-only publication authority, produced before the file effect.
/// Apply within the same service step and Fds, without changing its descriptors.
#[derive(Debug)]
pub struct FinishOpenPreflight {
    key: proto_fs::OpenKey,
    held: TentativeOpen,
    slot: usize,
    mode: FinishMode,
}
#[derive(Debug)]
enum FinishMode {
    Publish,
    Replay,
}

/// A completed operation owns the precise description in one session slot.
#[derive(Clone, Copy, PartialEq, Eq)]
struct OpenReceipt {
    key: proto_fs::OpenKey,
    description: Token,
}
const _: () = assert!(core::mem::size_of::<OpenReceipt>() == 32);
impl OpenReceipt {
    const EMPTY: Self = Self {
        key: proto_fs::OpenKey {
            slot: 0,
            generation: 0,
        },
        description: Token {
            slot: 0,
            generation: 0,
        },
    };
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
    access: proto_fs::Timestamp,
    modify: proto_fs::Timestamp,
    change: proto_fs::Timestamp,
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
    /// The steps of a cancel that were refused or did not end; the service
    /// prints the count when it moves.
    pub cancel_refusals: u32,
}

#[cfg(test)]
impl Default for Ram<'_> {
    fn default() -> Self {
        Self::new(proto_fs::Timestamp::legacy_ns(0))
    }
}

impl<'a> Ram<'a> {
    #[cfg(test)]
    pub fn new(now: proto_fs::Timestamp) -> Self {
        Self::test_ram(now, None)
    }

    #[cfg(test)]
    pub fn with_tree(now: proto_fs::Timestamp, tree: Tree<'a>) -> Self {
        Self::test_ram(now, Some(tree))
    }

    #[cfg(test)]
    fn test_ram(now: proto_fs::Timestamp, tree: Option<Tree<'a>>) -> Self {
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
        now: proto_fs::Timestamp,
        state: &'a mut storage::State,
        data: &'a mut [u8],
        tree: Option<Tree<'a>>,
    ) -> Self {
        Self {
            storage: Storage::new(state, data, tree, now),
            descriptions: [None; DESCRIPTIONS],
            description_generations: [0; DESCRIPTIONS],
            tree,
            cancel_refusals: 0,
        }
    }

    /// A cancel left something held. A debug build and the host tests stop
    /// here; any build counts it.
    pub fn refused_cancel(&mut self) {
        self.cancel_refusals = self.cancel_refusals.saturating_add(1);
        debug_assert!(false, "a step of a cancel was refused");
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

    /// Prepay every descriptor resource before a namespace or truncation effect.
    /// A creation's access is authorized by its parent and captured intent.
    pub fn prepare_open_token(
        &mut self,
        fds: &mut Fds,
        token: Token,
        flags: u32,
        identity: authority::Identity,
        creation: Option<storage::Reservation>,
    ) -> Result<TentativeOpen, u32> {
        let allowed = 3
            | proto_fs::DIRECTORY_ONLY
            | proto_fs::CHANGES
            | proto_fs::CREATE
            | proto_fs::EXCLUSIVE
            | proto_fs::TRUNCATE
            | proto_fs::APPEND
            | proto_fs::NO_FOLLOW;
        if flags & !allowed != 0 || flags & 3 == 3 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let created = if let Some(reservation) = creation {
            if self.storage.reserved_token(reservation, fds.root)? != token {
                return Err(proto_fs::PERMISSION);
            }
            true
        } else {
            false
        };
        if flags & proto_fs::CHANGES != 0 && (creation.is_some() || !self.file(token).is_device()) {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let node = self.storage.node(token)?;
        let access = flags & 3;
        if created && node.links != 0 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if !created
            && flags & (proto_fs::CREATE | proto_fs::EXCLUSIVE)
                == proto_fs::CREATE | proto_fs::EXCLUSIVE
        {
            return Err(proto_fs::ALREADY_EXISTS);
        }
        if node.kind == storage::SYMLINK {
            return Err(proto_fs::LOOP);
        }
        if flags & proto_fs::DIRECTORY_ONLY != 0 && node.kind != DIR {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        if node.kind == DIR
            && flags & proto_fs::CREATE != 0
            && flags & proto_fs::DIRECTORY_ONLY == 0
        {
            return Err(IS_DIRECTORY);
        }
        if node.kind == DIR && (access != READ_ONLY || flags & proto_fs::TRUNCATE != 0) {
            return Err(IS_DIRECTORY);
        }
        if node.kind == REG
            && (access != READ_ONLY || flags & proto_fs::TRUNCATE != 0)
            && self.read_only_regular(token)?
        {
            return Err(proto_fs::READ_ONLY_FILESYSTEM);
        }
        let bits = match access {
            READ_ONLY => 4,
            WRITE_ONLY => 2,
            _ => 6,
        };
        if !created && !identity.permits(node, bits) {
            return Err(proto_fs::ACCESS_DENIED);
        }
        let fd = self.insert(
            fds,
            Open {
                file: self.file(token),
                offset: 0,
                hint: crate::storage::NONE,
                scan: crate::storage::NONE,
                flags: access | (flags & proto_fs::APPEND),
            },
        )?;
        let description = self.description_token(fds, fd)?;
        fds.tentative |= 1 << (fd - 3);
        Ok(TentativeOpen { fd, description })
    }
    /// Boot regular files and the fixed motd remain immutable until full executable pins.
    pub fn read_only_regular(&self, token: Token) -> Result<bool, u32> {
        let node = self.storage.node(token)?;
        Ok(node.kind == REG && (node.boot != storage::NONE || token.slot == 3))
    }
    fn tentative_slot(&self, fds: &Fds, held: TentativeOpen) -> Result<usize, u32> {
        let slot = held.fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        if slot >= OPEN_MAX || fds.tentative & (1 << slot) == 0 {
            return Err(BAD_FD);
        }
        let description = fds.slots[slot].ok_or(BAD_FD)? as usize;
        if held.description.slot as usize != description
            || !self.descriptions[description]
                .is_some_and(|d| d.generation == held.description.generation)
        {
            return Err(BAD_FD);
        }
        Ok(slot)
    }
    pub fn validate_tentative(&self, fds: &Fds, held: TentativeOpen) -> Result<Token, u32> {
        let slot = self.tentative_slot(fds, held)?;
        let description = fds.slots[slot].expect("retained tentative description");
        Ok(self.token(
            self.descriptions[description as usize]
                .expect("retained description")
                .open
                .file,
        ))
    }

    /// This publication cannot allocate or fail after a successful effect preflight.
    pub fn publish_open(&mut self, fds: &mut Fds, held: TentativeOpen) -> Result<u32, u32> {
        let slot = self.tentative_slot(fds, held)?;
        fds.tentative &= !(1 << slot);
        Ok(held.fd)
    }
    /// Check receipt and exact descriptor ownership before any file effect.
    /// The same service step keeps these mappings unchanged until finish_open.
    pub fn preflight_finish_open(
        &self,
        fds: &Fds,
        key: proto_fs::OpenKey,
        held: TentativeOpen,
    ) -> Result<FinishOpenPreflight, u32> {
        key.validate()?;
        let (slot, mode) = if fds.open_receipts.iter().any(|receipt| receipt.key == key) {
            if self.finished_open(fds, key)? != held {
                return Err(proto_fs::PERMISSION);
            }
            ((held.fd - 3) as usize, FinishMode::Replay)
        } else {
            (self.tentative_slot(fds, held)?, FinishMode::Publish)
        };
        Ok(FinishOpenPreflight {
            key,
            held,
            slot,
            mode,
        })
    }
    /// Consume a preflight while the exact session mappings remain unchanged.
    /// Journal.commit only changes file metadata and namespace, preserving them.
    pub fn finish_preflighted(
        &mut self,
        fds: &mut Fds,
        proof: FinishOpenPreflight,
    ) -> TentativeOpen {
        if matches!(proof.mode, FinishMode::Publish) {
            fds.open_receipts[proof.slot] = OpenReceipt {
                key: proof.key,
                description: proof.held.description,
            };
            fds.tentative &= !(1 << proof.slot);
        }
        proof.held
    }
    /// The caller validates the exact committed paid job before this handoff.
    /// Receipt storage and the descriptor reference are already paid.
    pub fn finish_open(
        &mut self,
        fds: &mut Fds,
        key: proto_fs::OpenKey,
        held: TentativeOpen,
    ) -> Result<TentativeOpen, u32> {
        let proof = self.preflight_finish_open(fds, key, held)?;
        Ok(self.finish_preflighted(fds, proof))
    }
    /// Recover a completed outcome only while this session still owns its reference.
    pub fn finished_open(&self, fds: &Fds, key: proto_fs::OpenKey) -> Result<TentativeOpen, u32> {
        key.validate()?;
        let slot = fds
            .open_receipts
            .iter()
            .position(|receipt| receipt.key == key)
            .ok_or(proto_fs::OPEN_RETIRED)?;
        let receipt = fds.open_receipts[slot];
        if fds.tentative & (1 << slot) != 0
            || fds.slots[slot] != u8::try_from(receipt.description.slot).ok()
            || !self.descriptions[receipt.description.slot as usize]
                .is_some_and(|shared| shared.generation == receipt.description.generation)
        {
            return Err(proto_fs::OPEN_RETIRED);
        }
        Ok(TentativeOpen {
            fd: slot as u32 + 3,
            description: receipt.description,
        })
    }
    /// Preserve the exact description's device type through Commit and final handoff.
    pub fn marked_open(&self, fds: &Fds, held: TentativeOpen) -> Result<u32, u32> {
        let slot = held.fd.checked_sub(3).ok_or(BAD_FD)? as usize;
        if slot >= OPEN_MAX || fds.slots[slot] != u8::try_from(held.description.slot).ok() {
            return Err(BAD_FD);
        }
        let shared = self
            .descriptions
            .get(held.description.slot as usize)
            .and_then(Option::as_ref)
            .filter(|shared| shared.generation == held.description.generation)
            .ok_or(BAD_FD)?;
        Ok(held.fd
            | ((held.description.slot as u32) << proto_fs::OPEN_DESCRIPTION_SHIFT)
            | if matches!(shared.open.file, File::Random(_)) {
                proto_fs::OPEN_RANDOM
            } else {
                0
            })
    }
    /// Cancel owns a description generation; an old key leaves reused fds intact.
    pub fn cancel_finished_open(
        &mut self,
        fds: &mut Fds,
        key: proto_fs::OpenKey,
    ) -> Result<(), u32> {
        match self.finished_open(fds, key) {
            Ok(held) => self.close(fds, held.fd),
            Err(proto_fs::OPEN_RETIRED) => Ok(()),
            Err(code) => Err(code),
        }
    }

    pub fn cancel_open(&mut self, fds: &mut Fds, held: TentativeOpen) -> Result<(), u32> {
        let slot = self.tentative_slot(fds, held)?;
        fds.tentative &= !(1 << slot);
        self.close(fds, held.fd)
    }
    fn release_tentative_step(&mut self, fds: &mut Fds) -> bool {
        if fds.tentative == 0 {
            return false;
        }
        let slot = fds.tentative.trailing_zeros() as usize;
        fds.tentative &= !(1 << slot);
        let _ = self.close(fds, slot as u32 + 3);
        true
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
        if !fds.preparation_available() {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
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

    /// Diagnostic setup uses the same paid reserve and commit as normal creation.
    #[cfg(feature = "auth-probe")]
    pub fn auth_probe_gc_reserve(&mut self, fds: &mut Fds) -> Result<(), u32> {
        if fds.auth_probe_gc.is_some() || fds.auth_probe_gc_reservation.is_some() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let reservation = self.reserve_create(fds, storage::ROOT, b"auth-probe-gc", REG)?;
        fds.auth_probe_gc_reservation = Some(reservation);
        Ok(())
    }

    #[cfg(feature = "auth-probe")]
    pub fn auth_probe_gc_commit(&mut self, fds: &mut Fds) -> Result<(), u32> {
        let reservation = fds
            .auth_probe_gc_reservation
            .take()
            .ok_or(proto_fs::INVALID_ARGUMENT)?;
        match self.commit_create(fds, reservation) {
            Ok(token) => {
                fds.auth_probe_gc = Some(token);
                Ok(())
            }
            Err(code) => {
                if let Some(place) = fds
                    .preparations
                    .iter_mut()
                    .find(|r| r.is_some_and(|r| r.token == reservation.token))
                {
                    let _ = self
                        .storage
                        .cancel(place.take().expect("exact retained reservation"));
                }
                Err(code)
            }
        }
    }

    /// Binding and resolver jobs share the session's sixteen preparation slots.
    pub fn begin_binding(&mut self, fds: &mut Fds) -> Result<(), u32> {
        if fds.binding_preparation.is_some() || !fds.preparation_available() {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        let root = self.storage.charge_preparation(fds.root)?;
        fds.binding_preparation = Some(root);
        fds.binding_outcome = None;
        Ok(())
    }
    /// Completing a preparation is idempotent and records its terminal result.
    pub fn complete_binding(&mut self, fds: &mut Fds, outcome: u32) {
        if let Some(root) = fds.binding_preparation.take() {
            self.storage.release_preparation(root);
        }
        fds.binding_source = None;
        fds.binding_outcome = Some(outcome);
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
            #[cfg(feature = "auth-probe")]
            if fds
                .auth_probe_gc_reservation
                .is_some_and(|held| held.token == r.token)
            {
                fds.auth_probe_gc_reservation = None;
            }
            let _ = self.storage.cancel(r);
            return true;
        }
        if self.release_image(fds) {
            return true;
        }
        if let Some(cwd) = fds.cwd.take() {
            let _ = self.storage.unpin(cwd, Pin::Cwd);
            return true;
        }
        if self.release_tentative_step(fds) {
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

    /// The node the description of `fd` stands for, if the description is
    /// the one the caller names (BAD_FD otherwise).
    pub fn description_node(&self, fds: &Fds, fd: u32, generation: u64) -> Result<Token, u32> {
        let description = self.description_token(fds, fd)?;
        if description.generation != generation {
            return Err(BAD_FD);
        }
        let shared = self.descriptions[description.slot as usize]
            .as_ref()
            .ok_or(BAD_FD)?;
        Ok(self.token(shared.open.file))
    }

    /// The base of a path in ResolveStart, ResolveSecond and OpenStart. A slot
    /// with bit 31 set is read by `proto_fs::Base::from_wire`: a descriptor of
    /// the session with the generation of its description, the reserved
    /// current directory of the session, which the service does not hold yet
    /// (BAD_FD), or the reserved absolute base (BAD_FD for a relative path);
    /// a reserved value with a generation is BAD_SIZE. Any other slot is a node token the session retains. An
    /// absolute path takes the root whatever the base says.
    pub fn request_base(
        &self,
        fds: &Fds,
        slot: u32,
        generation: u64,
        relative: bool,
    ) -> Result<Token, u32> {
        if !relative {
            return Ok(Token {
                slot: u16::try_from(slot).unwrap_or(storage::NONE),
                generation,
            });
        }
        if slot & (1 << 31) != 0 {
            // The same reading of the base as the Change family has; the
            // descriptor travels with bit 31 set in this form.
            return match proto_fs::Base::from_wire(slot, generation) {
                Err(status) => Err(status.code()),
                // The service does not hold the current directory yet
                // (5i-7), and a relative path has no root to start from.
                Ok(proto_fs::Base::Absolute | proto_fs::Base::Cwd) => Err(BAD_FD),
                Ok(proto_fs::Base::Fd { fd, generation }) => {
                    self.description_node(fds, fd & !(1 << 31), generation)
                }
            };
        }
        let token = Token {
            slot: u16::try_from(slot).unwrap_or(storage::NONE),
            generation,
        };
        if self.owns_directory_base(fds, token) {
            Ok(token)
        } else {
            Err(BAD_FD)
        }
    }

    /// A raw token can serve as a relative base only when this session retains it.
    pub fn owns_directory_base(&self, fds: &Fds, token: Token) -> bool {
        if !self.storage.node(token).is_ok_and(|n| n.kind == DIR) {
            return false;
        }
        fds.cwd.unwrap_or(storage::ROOT) == token
            || fds.numbers().any(|fd| {
                fds.description(fd)
                    .ok()
                    .and_then(|slot| self.descriptions[slot].as_ref())
                    .is_some_and(|description| self.token(description.open.file) == token)
            })
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
        self.release_image(fds);
        #[cfg(feature = "auth-probe")]
        {
            fds.auth_probe_gc_reservation = None;
        }
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
        while self.release_tentative_step(fds) {}
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

    /// Capture a published description before importing it into a local table.
    pub fn capture_description(&self, fds: &Fds, fd: u32) -> Result<(TentativeOpen, u32), u32> {
        let description = self.description_token(fds, fd)?;
        let flags = self.descriptions[description.slot as usize]
            .as_ref()
            .ok_or(BAD_FD)?
            .open
            .flags;
        Ok((TentativeOpen { fd, description }, flags))
    }

    /// A stale exact cleanup leaves the replacement and its shared references intact.
    pub fn close_exact_description(
        &mut self,
        fds: &mut Fds,
        held: TentativeOpen,
    ) -> Result<bool, u32> {
        if self.description_token(fds, held.fd) != Ok(held.description) {
            return Ok(false);
        }
        self.close(fds, held.fd)?;
        Ok(true)
    }

    /// Clone's descriptors: a session's of the same numbers as `list` of
    /// `fds`, which share their descriptions, offsets and access modes;
    /// BAD_FD for a number no descriptor has. O(OPEN_MAX).
    pub fn clone_fds(&mut self, fds: &Fds, list: &[u32]) -> Result<Fds, u32> {
        let mut out = Fds::default();
        self.clone_fds_into(fds, list, &mut out)?;
        Ok(out)
    }

    /// Fill a fresh destination after validating the complete descriptor list.
    /// Errors preserve the destination and all source references.
    #[inline(never)]
    pub fn clone_fds_into(&mut self, fds: &Fds, list: &[u32], out: &mut Fds) -> Result<(), u32> {
        if !out.fresh_clone_destination() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let mut slots = [None; OPEN_MAX];
        for &fd in list {
            let index = fds.description(fd)?;
            slots[(fd - 3) as usize] = Some(index as u8);
        }
        if let Some(cwd) = fds.cwd {
            self.storage.pin(cwd, Pin::Cwd)?;
        }
        out.root = fds.root;
        out.slots = slots;
        out.cwd = fds.cwd;
        // At most 641 session/birth records, including this child, own 32 references each.
        for index in out.slots.iter().flatten() {
            self.descriptions[usize::from(*index)]
                .as_mut()
                .expect("a named description")
                .refs += 1;
        }
        Ok(())
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
                hint: crate::storage::NONE,
                scan: crate::storage::NONE,
                flags,
            },
        )
    }

    fn touch_access(&mut self, file: File, now: proto_fs::Timestamp) {
        if file.index().is_some() || matches!(file, File::Node(_) | File::NodeDir(_)) {
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
        now: proto_fs::Timestamp,
    ) -> Result<Option<DirectoryRecord>, u32> {
        let node = self.storage.node(token)?;
        if node.kind != DIR {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        if !identity.permits(node, 4) {
            return Err(proto_fs::ACCESS_DENIED);
        }
        if index > INDEX_MAX {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        Ok(self.nth_entry(self.file(token), index, now))
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
            block_size: storage::PAGE as u32,
            blocks: self.storage.blocks(self.token(file)),
            access_time: times.access,
            modify_time: times.modify,
            change_time: times.change,
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
        now: proto_fs::Timestamp,
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
        now: proto_fs::Timestamp,
    ) -> Result<usize, u32> {
        let open = self.get(fds, fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags & 3 == WRITE_ONLY {
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
        now: proto_fs::Timestamp,
    ) -> Result<usize, u32> {
        let file = self.get(fds, fd)?.file;
        let n = self.write_position(fds, fd, bytes, None)?;
        // Character devices keep no times.
        if n > 0 && !file.is_device() {
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
        now: proto_fs::Timestamp,
    ) -> Result<usize, u32> {
        i64::try_from(offset).map_err(|_| proto_fs::INVALID_ARGUMENT)?;
        let file = self.get(fds, fd)?.file;
        let n = self.write_position(fds, fd, bytes, Some(offset))?;
        if n > 0 && !file.is_device() {
            let node = self.storage.node_mut(self.token(file)).expect("live inode");
            node.times[1] = now;
            node.times[2] = now;
        }
        Ok(n)
    }

    pub fn directory_read(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        now: proto_fs::Timestamp,
    ) -> Result<Option<DirectoryRecord>, u32> {
        let mut open = self.get(fds, fd)?;
        if !open.file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        let after = u64::try_from(open.offset).map_err(|_| proto_fs::INVALID_ARGUMENT)?;
        match self.entry_after(open.file, after, open.hint, open.scan, now) {
            Walked::Entry(cookie, hint, record) => {
                open.offset = cookie as i64;
                open.hint = hint;
                open.scan = storage::NONE;
                self.put(fds, fd, open)?;
                Ok(Some(record))
            }
            Walked::End => {
                open.scan = storage::NONE;
                self.put(fds, fd, open)?;
                Ok(None)
            }
            // A long list: the walk goes on in the next call.
            Walked::More(scan) => {
                open.scan = scan;
                self.put(fds, fd, open)?;
                Err(proto_fs::RESOLVING)
            }
        }
    }

    pub fn directory_read_path(
        &mut self,
        path: &str,
        index: u32,
        now: proto_fs::Timestamp,
    ) -> Result<Option<DirectoryRecord>, u32> {
        let file = self.resolve(path)?;
        if !file.is_directory() {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        Ok(self.nth_entry(file, index, now))
    }

    /// The record of the entry `.` or `..` of `dir`, or of the name at `entry`.
    fn record_of(&self, dir: Token, cookie: u64, entry: u16) -> Option<DirectoryRecord> {
        match cookie {
            1 => {
                let file = self.file(dir);
                Some(DirectoryRecord::new(b".", DIR, self.inode(file)))
            }
            2 => {
                let parent = self.storage.node(dir).ok()?.parent;
                let inode = self.inode(self.file(parent));
                Some(DirectoryRecord::new(b"..", DIR, inode))
            }
            _ => {
                let (_, name, token) = self.storage.entry_record(entry as usize)?;
                let file = self.file(token);
                Some(DirectoryRecord::new(name, file.kind(), self.inode(file)))
            }
        }
    }

    /// The name of directory `dir` that follows the position `after`, a
    /// cookie: 0 is before `.`, 1 before `..`, 2 before the first name. A name
    /// that exists from start to end of a listing is given exactly once,
    /// whatever else the directory goes through, because a position is the
    /// cookie of the name before it and cookies only rise along the listing.
    /// Gives the cookie, the entry (a shortcut for the next call) and the
    /// record; the access time of the directory is `now`. A walk of a long
    /// list that does not reach the position within a portion gives the entry
    /// it reached, which the next call starts from.
    fn entry_after(
        &mut self,
        dir: File,
        after: u64,
        hint: u16,
        scan: u16,
        now: proto_fs::Timestamp,
    ) -> Walked {
        self.touch_access(dir, now);
        let token = self.token(dir);
        let (cookie, entry) = match after {
            0 | 1 => (after + 1, storage::NONE),
            _ => match self.storage.child_after(token, after, hint, scan) {
                storage::Walk::Found(entry) => (self.storage.entry_cookie(entry), entry as u16),
                storage::Walk::End => return Walked::End,
                storage::Walk::More(reached) => return Walked::More(reached),
            },
        };
        match self.record_of(token, cookie, entry) {
            Some(record) => Walked::Entry(cookie, entry, record),
            None => Walked::End,
        }
    }

    /// Entry `index` of directory `dir`: `.`, `..`, then the names in the
    /// order of their cookies; the access time of the directory is `now`.
    fn nth_entry(
        &mut self,
        dir: File,
        index: u32,
        now: proto_fs::Timestamp,
    ) -> Option<DirectoryRecord> {
        self.touch_access(dir, now);
        let token = self.token(dir);
        match index {
            0 | 1 => self.record_of(token, u64::from(index) + 1, storage::NONE),
            _ => {
                let mut entry = self.storage.first_child(token)?;
                for _ in 2..index {
                    entry = self.storage.child_next(entry)?;
                }
                self.record_of(token, 3, entry as u16)
            }
        }
    }

    /// The position after the last name of the directory.
    fn directory_count(&self, dir: File) -> i64 {
        self.storage.last_cookie(self.token(dir)) as i64
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
        if open.flags & 3 == WRITE_ONLY {
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
        self.write_position(fds, fd, bytes, None)
    }
    /// An explicit position bypasses APPEND and never changes the shared description.
    fn write_position(
        &mut self,
        fds: &mut Fds,
        fd: u32,
        bytes: &[u8],
        position: Option<u64>,
    ) -> Result<usize, u32> {
        let mut open = self.get(fds, fd)?;
        if open.file.is_directory() {
            return Err(IS_DIRECTORY);
        }
        if open.flags & 3 == READ_ONLY || matches!(open.file, File::Motd | File::ImageRegular(_)) {
            return Err(BAD_FD);
        }
        if bytes.is_empty() || open.file.is_device() {
            return Ok(bytes.len());
        }
        let offset = if let Some(at) = position {
            usize::try_from(at).map_err(|_| NO_SPACE)?
        } else if open.flags & proto_fs::APPEND != 0 {
            self.length(open.file)
        } else {
            usize::try_from(open.offset).map_err(|_| NO_SPACE)?
        };
        let end = offset.checked_add(bytes.len()).ok_or(NO_SPACE)?;
        let capacity = if matches!(open.file, File::Scratch) {
            FILE_CAPACITY
        } else {
            storage::FILE_PAGES * storage::PAGE
        };
        if end > capacity {
            return Err(NO_SPACE);
        }
        self.storage
            .write(self.token(open.file), fds.root, offset, bytes)?;
        if position.is_none() {
            open.offset = end as i64;
            self.put(fds, fd, open)?;
        }
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
    fn signed_times_survive_storage_write_read_and_information() {
        let initial = proto_fs::Timestamp::new(i64::MIN, 0).unwrap();
        let written = proto_fs::Timestamp::from_ns(-1).unwrap();
        let read = proto_fs::Timestamp::new(i64::MAX, 999_999_999).unwrap();
        let mut ram = Ram::new(initial);
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/tmp/probe", READ_WRITE).unwrap();
        assert_eq!(ram.write_at(&mut fds, fd, b"x", written), Ok(1));
        let info = ram.descriptor_information(&fds, fd).unwrap();
        assert_eq!(
            (info.access_time, info.modify_time, info.change_time),
            (initial, written, written)
        );
        let mut byte = [0];
        assert_eq!(ram.pread(&fds, fd, 0, &mut byte, read), Ok(1));
        assert_eq!(byte, *b"x");
        let info = ram.descriptor_information(&fds, fd).unwrap();
        assert_eq!(
            (info.access_time, info.modify_time, info.change_time),
            (read, written, written)
        );
        assert_eq!(ram.pread(&fds, fd, 0, &mut [], initial), Ok(0));
        assert_eq!(
            ram.descriptor_information(&fds, fd).unwrap().access_time,
            read
        );
    }

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
        let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(10));
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
            ram.read_at(
                &mut fds,
                fd,
                &mut [0; 1],
                proto_fs::Timestamp::legacy_ns(15)
            ),
            Err(IS_DIRECTORY)
        );
        assert_eq!(
            ram.write_at(&mut fds, fd, b"x", proto_fs::Timestamp::legacy_ns(16)),
            Err(IS_DIRECTORY)
        );
        assert_eq!(
            ram.information("/etc").unwrap().access_time,
            proto_fs::Timestamp::legacy_ns(10)
        );
        for (now, name, inode, kind) in
            [(20, ".", 2, DIR), (30, "..", 1, DIR), (40, "motd", 4, REG)]
        {
            assert_eq!(
                ram.directory_read(&mut fds, fd, proto_fs::Timestamp::legacy_ns(now)),
                Ok(Some(DirectoryRecord::new(name.as_bytes(), kind, inode)))
            );
        }
        assert_eq!(
            ram.directory_read(&mut fds, fd, proto_fs::Timestamp::legacy_ns(50)),
            Ok(None)
        );
        assert_eq!(
            ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::Current),
            Ok(5),
            "the position is the cookie of `motd`, the third entry of the table"
        );
        let info = ram.information("/etc").unwrap();
        assert_eq!(
            (info.access_time, info.modify_time, info.change_time),
            (
                proto_fs::Timestamp::legacy_ns(50),
                proto_fs::Timestamp::legacy_ns(10),
                proto_fs::Timestamp::legacy_ns(10)
            )
        );
        assert_eq!(
            ram.directory_read(&mut fds, second, proto_fs::Timestamp::legacy_ns(60))
                .unwrap()
                .unwrap()
                .name(),
            b"."
        );
        assert_eq!(
            ram.seek_from(&mut fds, fd, 1, proto_fs::SeekFrom::Start),
            Ok(1)
        );
        assert_eq!(
            ram.directory_read(&mut fds, fd, proto_fs::Timestamp::legacy_ns(70))
                .unwrap()
                .unwrap()
                .name(),
            b".."
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
        assert_eq!(
            ram.directory_read(&mut fds, fd, proto_fs::Timestamp::legacy_ns(80)),
            Err(BAD_FD)
        );
        let regular = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        assert_eq!(
            ram.directory_read(&mut fds, regular, proto_fs::Timestamp::legacy_ns(90)),
            Err(proto_fs::NOT_DIRECTORY)
        );
        assert_eq!(ram.information("/etc").unwrap(), before);
    }

    #[test]
    fn metadata_identity_and_clock_updates_are_shared_across_sessions() {
        let mut ram = Ram::new(proto_fs::Timestamp::legacy_ns(10));
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
        ram.write_at(&mut a, fa, b"abc", proto_fs::Timestamp::legacy_ns(20))
            .unwrap();
        let info = ram.descriptor_information(&b, fb).unwrap();
        assert_eq!(info, ram.information("/tmp/probe").unwrap());
        assert_eq!(
            (
                info.inode,
                info.size,
                info.blocks,
                info.access_time,
                info.modify_time,
                info.change_time
            ),
            (
                5,
                3,
                8,
                proto_fs::Timestamp::legacy_ns(10),
                proto_fs::Timestamp::legacy_ns(20),
                proto_fs::Timestamp::legacy_ns(20)
            )
        );
        assert_eq!(
            ram.read_at(&mut b, fb, &mut [0; 3], proto_fs::Timestamp::legacy_ns(30)),
            Ok(3)
        );
        assert_eq!(
            ram.read_at(&mut b, fb, &mut [0; 1], proto_fs::Timestamp::legacy_ns(40)),
            Ok(0)
        );
        let info = ram.information("/tmp/probe").unwrap();
        assert_eq!(
            (info.access_time, info.modify_time, info.change_time),
            (
                proto_fs::Timestamp::legacy_ns(40),
                proto_fs::Timestamp::legacy_ns(20),
                proto_fs::Timestamp::legacy_ns(20)
            )
        );
        assert_eq!(
            ram.read_at(&mut b, fb, &mut [], proto_fs::Timestamp::legacy_ns(50)),
            Ok(0)
        );
        assert_eq!(
            ram.write_at(&mut a, fa, b"", proto_fs::Timestamp::legacy_ns(60)),
            Ok(0)
        );
        assert_eq!(
            ram.write_at(&mut b, fb, b"x", proto_fs::Timestamp::legacy_ns(70)),
            Err(BAD_FD)
        );
        ram.seek(&mut a, fa, FILE_CAPACITY as u32).unwrap();
        assert_eq!(
            ram.write_at(&mut a, fa, b"x", proto_fs::Timestamp::legacy_ns(80)),
            Err(NO_SPACE)
        );
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
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
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
        assert_eq!(
            (ash.access_time, ash.modify_time, ash.change_time),
            (
                proto_fs::Timestamp::legacy_ns(10),
                proto_fs::Timestamp::legacy_ns(10),
                proto_fs::Timestamp::legacy_ns(10)
            )
        );
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/bin/ash", READ_ONLY).unwrap();
        assert_eq!(
            ram.read_at(
                &mut fds,
                fd,
                &mut [0; 4],
                proto_fs::Timestamp::legacy_ns(99)
            ),
            Ok(4)
        );
        assert_eq!(
            ram.information("/bin/ash").unwrap().access_time,
            proto_fs::Timestamp::legacy_ns(10)
        );
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
    fn names<'a>(ram: &mut Ram<'a>, path: &str) -> Vec<(&'static str, u32, u64)> {
        let mut out = Vec::new();
        while let Some(entry) = ram
            .directory_read_path(path, out.len() as u32, proto_fs::Timestamp::legacy_ns(20))
            .unwrap()
        {
            let name = std::string::String::from_utf8(entry.name().to_vec()).unwrap();
            out.push((
                &*std::boxed::Box::leak(name.into_boxed_str()),
                entry.kind,
                entry.inode,
            ));
        }
        out
    }

    #[test]
    fn image_directories_list_dot_dotdot_the_fixed_entries_then_the_children() {
        let bytes = image();
        let mut index = Index::new();
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
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
            ram.directory_read_path("/bin/ash", 0, proto_fs::Timestamp::legacy_ns(20)),
            Err(proto_fs::NOT_DIRECTORY)
        );
        // An open directory advances through the same entries, and its end
        // for seeking is the cookie of the last name.
        let fd = ram.open(&mut fds, "/bin", READ_ONLY | proto_fs::DIRECTORY_ONLY);
        let fd = fd.unwrap();
        assert_eq!(
            ram.seek_from(&mut fds, fd, 0, proto_fs::SeekFrom::End),
            Ok(10),
            "the end is the cookie of the last name"
        );
        ram.seek_from(&mut fds, fd, 9, proto_fs::SeekFrom::Start)
            .unwrap();
        let last = ram
            .directory_read(&mut fds, fd, proto_fs::Timestamp::legacy_ns(30))
            .unwrap()
            .unwrap();
        assert_eq!(last.name(), b"sub");
        assert_eq!(
            ram.directory_read(&mut fds, fd, proto_fs::Timestamp::legacy_ns(30)),
            Ok(None)
        );
        let root_fd = ram.open(&mut fds, "/", READ_ONLY).unwrap();
        assert_eq!(
            ram.seek_from(&mut fds, root_fd, 0, proto_fs::SeekFrom::End),
            Ok(12)
        );
        assert_eq!(ram.open(&mut fds, "/bin", WRITE_ONLY), Err(IS_DIRECTORY));
    }

    #[test]
    fn image_files_are_read_only_and_read_from_the_start_of_their_own_bytes() {
        let bytes = image();
        let mut index = Index::new();
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
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
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/dev/null", READ_WRITE).unwrap();
        let block = [7u8; 4096];
        for _ in 0..512 {
            assert_eq!(
                ram.write_at(&mut fds, fd, &block, proto_fs::Timestamp::legacy_ns(20)),
                Ok(4096)
            );
        }
        assert_eq!(
            ram.pwrite(&mut fds, fd, 9, b"abc", proto_fs::Timestamp::legacy_ns(21)),
            Ok(3)
        );
        assert_eq!(ram.size(&fds, fd), Ok(0));
        let mut out = [1u8; 8];
        assert_eq!(ram.read(&mut fds, fd, &mut out), Ok(0));
        assert_eq!(
            ram.pread(&fds, fd, 0, &mut out, proto_fs::Timestamp::legacy_ns(22)),
            Ok(0)
        );
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
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
        let mut fds = Fds::default();
        for path in ["/dev/random", "/dev/urandom"] {
            let fd = ram.open(&mut fds, path, READ_WRITE).unwrap();
            assert!(ram.is_random(&fds, fd), "{path}");
            assert_eq!(ram.write(&mut fds, fd, b"abc"), Ok(3));
            assert_eq!(
                ram.write_at(&mut fds, fd, &[1; 4096], proto_fs::Timestamp::legacy_ns(20)),
                Ok(4096)
            );
            assert_eq!(ram.size(&fds, fd), Ok(0));
            let mut out = [9u8; 8];
            assert_eq!(
                ram.read(&mut fds, fd, &mut out),
                Err(proto_fs::INVALID_ARGUMENT)
            );
            assert_eq!(
                ram.pread(&fds, fd, 0, &mut out, proto_fs::Timestamp::legacy_ns(22)),
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
        let kinds: Vec<(std::string::String, u32)> = (0..8)
            .filter_map(|i| {
                ram.directory_read_path("/dev", i, proto_fs::Timestamp::legacy_ns(30))
                    .unwrap()
            })
            .map(|r| {
                (
                    std::string::String::from_utf8(r.name().to_vec()).unwrap(),
                    r.kind,
                )
            })
            .collect();
        for expected in [
            ("null", CHAR),
            ("random", CHAR),
            ("urandom", CHAR),
            ("other", REG),
        ] {
            assert!(
                kinds.contains(&(expected.0.into(), expected.1)),
                "{kinds:?}"
            );
        }
    }

    #[test]
    fn random_open_marker_tracks_exact_receipts_clone_and_reused_descriptions() {
        let bytes = test_image(&[
            entry("/dev", DIRECTORY | 0o755, 0),
            entry("/dev/random", REGULAR | 0o666, 2),
        ]);
        let mut index = Index::new();
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(0),
            load(&bytes, &mut index).unwrap(),
        );
        let dev = ram.storage.lookup(storage::ROOT, b"dev").unwrap();
        let random = ram.storage.lookup(dev, b"random").unwrap();
        let identity = authority::Identity {
            uid: 0,
            gid: 0,
            groups: proto_process::Groups::EMPTY,
        };
        let mut fds = Fds::default();
        let mut receipts = [None; OPEN_MAX];
        for (slot, saved) in receipts.iter_mut().enumerate() {
            let held = ram
                .prepare_open_token(&mut fds, random, READ_WRITE, identity, None)
                .unwrap();
            let key = proto_fs::OpenKey {
                slot: slot as u32,
                generation: 1,
            };
            assert_eq!(held.fd, slot as u32 + 3);
            assert_eq!(
                ram.marked_open(&fds, held),
                Ok(proto_fs::OPEN_RANDOM
                    | held.fd
                    | ((held.description.slot as u32) << proto_fs::OPEN_DESCRIPTION_SHIFT))
            );
            assert_eq!(ram.finish_open(&mut fds, key, held), Ok(held));
            assert_eq!(
                ram.marked_open(&fds, ram.finished_open(&fds, key).unwrap()),
                Ok(proto_fs::OPEN_RANDOM
                    | held.fd
                    | ((held.description.slot as u32) << proto_fs::OPEN_DESCRIPTION_SHIFT))
            );
            *saved = Some((key, held));
        }
        assert_eq!(ram.open_descriptions(), OPEN_MAX);
        let numbers: Vec<u32> = fds.numbers().collect();
        let mut child = ram.clone_fds(&fds, &numbers).unwrap();
        for fd in numbers {
            assert!(ram.is_random(&child, fd));
        }
        let (old_key, old) = receipts[0].unwrap();
        ram.close(&mut fds, old.fd).unwrap();
        let regular = ram
            .prepare_open_token(
                &mut fds,
                Token {
                    slot: 4,
                    generation: 1,
                },
                READ_WRITE,
                identity,
                None,
            )
            .unwrap();
        assert_eq!(regular.fd, old.fd);
        assert_ne!(regular.description.slot, old.description.slot);
        assert_eq!(regular.description.generation, old.description.generation);
        assert_eq!(ram.marked_open(&fds, old), Err(BAD_FD));
        assert_eq!(ram.close_exact_description(&mut fds, old), Ok(false));
        assert_eq!(ram.description_token(&fds, regular.fd), Err(BAD_FD));
        assert_eq!(
            ram.marked_open(&fds, regular),
            Ok(regular.fd
                | ((regular.description.slot as u32) << proto_fs::OPEN_DESCRIPTION_SHIFT))
        );
        let new_key = proto_fs::OpenKey {
            slot: 0,
            generation: 2,
        };
        ram.finish_open(&mut fds, new_key, regular).unwrap();
        assert_eq!(
            ram.capture_description(&fds, regular.fd),
            Ok((regular, READ_WRITE))
        );
        assert_eq!(ram.close_exact_description(&mut fds, old), Ok(false));
        assert_eq!(
            ram.finished_open(&fds, old_key),
            Err(proto_fs::OPEN_RETIRED)
        );
        ram.cancel_finished_open(&mut fds, old_key).unwrap();
        assert_eq!(ram.finished_open(&fds, new_key), Ok(regular));
        assert!(ram.is_random(&child, old.fd));
        ram.release(&mut child);
        ram.release(&mut fds);
        assert_eq!(ram.open_descriptions(), 0);
        let mut full: [Fds; 4] = core::array::from_fn(|group| Fds {
            root: storage::Root {
                id: 500 + group as u64,
                generation: 1,
            },
            ..Fds::default()
        });
        for session in &mut full {
            for _ in 0..OPEN_MAX {
                let held = ram
                    .prepare_open_token(session, random, READ_WRITE, identity, None)
                    .unwrap();
                ram.publish_open(session, held).unwrap();
            }
        }
        let last = TentativeOpen {
            fd: 34,
            description: ram.description_token(&full[3], 34).unwrap(),
        };
        assert_eq!(last.description.slot, 127);
        assert_eq!(
            ram.marked_open(&full[3], last),
            Ok(proto_fs::OPEN_RANDOM | (127 << proto_fs::OPEN_DESCRIPTION_SHIFT) | 34)
        );
        for session in &mut full {
            ram.release(session);
        }
        assert_eq!(ram.open_descriptions(), 0);
    }

    #[test]
    fn pread_takes_the_offset_of_the_file_and_keeps_the_position() {
        let bytes = image();
        let mut index = Index::new();
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
        let mut fds = Fds::default();
        let fd = ram.open(&mut fds, "/bin/ash", READ_ONLY).unwrap();
        let mut out = [0; 32];
        // From the start, from the middle, up to the end, and a count over it.
        assert_eq!(
            ram.pread(
                &fds,
                fd,
                0,
                &mut out[..5],
                proto_fs::Timestamp::legacy_ns(40)
            ),
            Ok(5)
        );
        assert_eq!(&out[..5], b"alpha");
        assert_eq!(
            ram.pread(&fds, fd, 6, &mut out, proto_fs::Timestamp::legacy_ns(40)),
            Ok(5)
        );
        assert_eq!(&out[..5], b"bytes");
        assert_eq!(
            ram.pread(&fds, fd, 10, &mut out, proto_fs::Timestamp::legacy_ns(40)),
            Ok(1)
        );
        assert_eq!(out[0], b's');
        // At the end, past it, and at the largest offset.
        assert_eq!(
            ram.pread(&fds, fd, 11, &mut out, proto_fs::Timestamp::legacy_ns(40)),
            Ok(0)
        );
        assert_eq!(
            ram.pread(
                &fds,
                fd,
                1 << 40,
                &mut out,
                proto_fs::Timestamp::legacy_ns(40)
            ),
            Ok(0)
        );
        assert_eq!(
            ram.pread(
                &fds,
                fd,
                i64::MAX as u64,
                &mut out,
                proto_fs::Timestamp::legacy_ns(40)
            ),
            Ok(0)
        );
        assert_eq!(
            ram.pread(
                &fds,
                fd,
                i64::MAX as u64 + 1,
                &mut out,
                proto_fs::Timestamp::legacy_ns(40)
            ),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        // The position of the description did not move, so a read starts at 0.
        assert_eq!(ram.read(&mut fds, fd, &mut out[..5]), Ok(5));
        assert_eq!(&out[..5], b"alpha");
        assert_eq!(
            ram.pread(&fds, fd, 0, &mut [], proto_fs::Timestamp::legacy_ns(40)),
            Ok(0)
        );
        // A read updates the access time of a file of the fixed tree only.
        let motd = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        assert_eq!(
            ram.pread(&fds, motd, 7, &mut out, proto_fs::Timestamp::legacy_ns(50)),
            Ok(7)
        );
        assert_eq!(&out[..7], b" ramfs\n");
        assert_eq!(
            ram.information("/etc/motd").unwrap().access_time,
            proto_fs::Timestamp::legacy_ns(50)
        );
        assert_eq!(
            ram.information("/bin/ash").unwrap().access_time,
            proto_fs::Timestamp::legacy_ns(10)
        );
        // The scratch file reads at an offset as well, and errors are the
        // read's: a closed descriptor, a directory, a write-only open.
        let scratch = ram.open(&mut fds, "/tmp/probe", READ_WRITE).unwrap();
        ram.write(&mut fds, scratch, b"abcdef").unwrap();
        assert_eq!(
            ram.pread(
                &fds,
                scratch,
                4,
                &mut out,
                proto_fs::Timestamp::legacy_ns(60)
            ),
            Ok(2)
        );
        assert_eq!(&out[..2], b"ef");
        let write_only = ram.open(&mut fds, "/tmp/probe", WRITE_ONLY).unwrap();
        assert_eq!(
            ram.pread(
                &fds,
                write_only,
                0,
                &mut out,
                proto_fs::Timestamp::legacy_ns(60)
            ),
            Err(BAD_FD)
        );
        let dir = ram.open(&mut fds, "/bin", READ_ONLY).unwrap();
        assert_eq!(
            ram.pread(&fds, dir, 0, &mut out, proto_fs::Timestamp::legacy_ns(60)),
            Err(IS_DIRECTORY)
        );
        ram.close(&mut fds, fd).unwrap();
        assert_eq!(
            ram.pread(&fds, fd, 0, &mut out, proto_fs::Timestamp::legacy_ns(60)),
            Err(BAD_FD)
        );
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
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
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
        let ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
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
        let locked = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&locked, &mut locked_index).unwrap(),
        );
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
    #[test]
    fn paid_open_preserves_device_only_changes_profile() {
        use crate::open::Journal;
        use crate::resolve::{Intent, Progress, Resolve};
        use crate::storage::{ROOT, Root};
        let bytes = test_image(&[
            entry("/dev", DIRECTORY | 0o755, 0),
            entry("/dev/null", REGULAR | 0o666, 2),
            entry("/dev/urandom", REGULAR | 0o666, 2),
            entry("/dev/other", REGULAR | 0o666, 2),
        ]);
        let mut index = Index::new();
        let mut ram = Ram::with_tree(
            proto_fs::Timestamp::legacy_ns(10),
            load(&bytes, &mut index).unwrap(),
        );
        let identity = authority::Identity {
            uid: 0,
            gid: 0,
            groups: proto_process::Groups::EMPTY,
        };
        let mut fds = Fds {
            root: Root {
                id: 800,
                generation: 1,
            },
            ..Fds::default()
        };
        for (path, extra, expected) in [
            (b"/dev/null".as_slice(), WRITE_ONLY, Ok(())),
            (b"/dev/urandom".as_slice(), READ_WRITE, Ok(())),
            (
                b"/dev/other".as_slice(),
                READ_ONLY,
                Err(proto_fs::INVALID_ARGUMENT),
            ),
            (
                b"/dev".as_slice(),
                READ_ONLY,
                Err(proto_fs::INVALID_ARGUMENT),
            ),
            (
                b"/dev/null".as_slice(),
                proto_fs::DIRECTORY_ONLY,
                Err(proto_fs::NOT_DIRECTORY),
            ),
        ] {
            let flags = extra | proto_fs::CHANGES;
            let mut journal = Journal::new(flags, 0, 0).unwrap();
            let intent = Intent::Open { flags };
            let mut resolver =
                Resolve::with_intent(&mut ram.storage, path, ROOT, identity, intent).unwrap();
            for _ in 0..2000 {
                if matches!(
                    resolver.step(&mut ram.storage, identity).unwrap(),
                    Progress::Found(_)
                ) {
                    break;
                }
            }
            let proof = resolver
                .result_proof(&ram.storage, identity, intent)
                .unwrap();
            let target = proof.target.unwrap();
            let before_node = *ram.storage.node(target).unwrap();
            let mut charge = ram.storage.charge_preparation(fds.root).unwrap();
            let before_usage = ram.storage.usage(fds.root);
            let before_epoch = ram.storage.state.epoch;
            let before_generations = ram.description_generations;
            let result = journal.prepare(&mut ram, &mut fds, proof, identity, &mut charge);
            assert_eq!(result.map(|_| ()), expected);
            if result.is_ok() {
                let proof = resolver
                    .result_proof(&ram.storage, identity, intent)
                    .unwrap();
                let held = journal
                    .commit(
                        &mut ram,
                        &mut fds,
                        Some(proof),
                        identity,
                        &mut charge,
                        proto_fs::Timestamp::legacy_ns(20),
                    )
                    .unwrap();
                assert_eq!(
                    journal.commit(
                        &mut ram,
                        &mut fds,
                        None,
                        identity,
                        &mut charge,
                        proto_fs::Timestamp::legacy_ns(99)
                    ),
                    Ok(held)
                );
                let fd = ram.publish_open(&mut fds, held).unwrap();
                assert_eq!(ram.write(&mut fds, fd, b"device"), Ok(6));
                assert_eq!(ram.size(&fds, fd), Ok(0));
                ram.close(&mut fds, fd).unwrap();
            }
            assert_eq!(ram.storage.usage(fds.root), before_usage);
            assert_eq!(ram.open_descriptions(), 0);
            assert_eq!(ram.storage.state.epoch, before_epoch);
            let after_node = ram.storage.node(target).unwrap();
            assert_eq!(after_node.times, before_node.times);
            assert_eq!(after_node.length, before_node.length);
            assert_eq!(after_node.mode, before_node.mode);
            assert_eq!(after_node.pins, before_node.pins);
            if expected.is_err() {
                assert_eq!(ram.description_generations, before_generations);
            }
            ram.storage.release_preparation(charge);
            resolver.release(&mut ram.storage);
        }
        for change in [
            proto_fs::CREATE,
            proto_fs::EXCLUSIVE,
            proto_fs::TRUNCATE,
            proto_fs::APPEND,
            proto_fs::NO_FOLLOW,
        ] {
            assert!(matches!(
                Journal::new(proto_fs::CHANGES | change, 0, 0),
                Err(proto_fs::INVALID_ARGUMENT)
            ));
        }
        assert_eq!(ram.storage.preparations_used(), 0);
    }
}

#[cfg(test)]
mod birth_claim_tests {
    use super::*;
    use crate::storage::Root;

    #[test]
    fn wrong_label_keeps_the_birth_and_default_destination() {
        let mut destination = Fds::default();
        let source = Fds {
            root: Root {
                id: 17,
                generation: 9,
            },
            binding_outcome: Some(proto_fs::PERMISSION),
            ..Fds::default()
        };
        let mut birth = Some((41, source));
        assert!(!destination.claim_retained_birth(&mut birth, 42));
        assert!(destination.fresh_clone_destination());
        let (owner, source) = birth.as_ref().unwrap();
        assert_eq!(*owner, 41);
        assert_eq!(
            source.root,
            Root {
                id: 17,
                generation: 9
            }
        );
        assert_eq!(source.binding_outcome, Some(proto_fs::PERMISSION));
        assert!(destination.claim_retained_birth(&mut birth, 41));
        assert!(birth.is_none());
        assert_eq!(
            destination.root,
            Root {
                id: 17,
                generation: 9
            }
        );
        assert_eq!(destination.binding_outcome, Some(proto_fs::PERMISSION));
    }

    #[test]
    fn exact_claim_preserves_the_description_and_its_offset_until_release() {
        let mut ram = Ram::default();
        let mut source = Fds::default();
        let fd = ram.open(&mut source, "/etc/motd", READ_ONLY).unwrap();
        let mut prefix = [0; 3];
        assert_eq!(ram.read(&mut source, fd, &mut prefix), Ok(3));
        let mut birth = Some((41, source));
        let mut destination = Fds::default();
        assert!(!destination.claim_retained_birth(&mut birth, 42));
        assert_eq!(ram.open_descriptions(), 1);
        assert!(destination.claim_retained_birth(&mut birth, 41));
        assert!(birth.is_none());
        assert_eq!(ram.open_descriptions(), 1);
        assert_eq!(ram.read(&mut destination, fd, &mut prefix), Ok(3));
        assert_eq!(&prefix, b"fet");
        ram.release(&mut destination);
        assert_eq!(ram.open_descriptions(), 0);
    }

    #[test]
    fn missing_birth_keeps_the_unclaimed_destination() {
        let mut destination = Fds::default();
        assert!(!destination.claim_retained_birth(&mut None, 41));
        assert!(destination.fresh_clone_destination());
    }
}
