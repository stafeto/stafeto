// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One bounded inode namespace with boot-backed bytes and paid overlays.
//! Reservations retain their expenditure root until cancellation or reclamation.

use crate::tree::Tree;
use proto_fs::{NO_ENTRY, NO_SPACE};

pub const INODES: usize = 256;
pub const DENTRIES: usize = 512;
pub const PAGES: usize = 4096;
pub const PAGE: usize = 4096;
pub const FILE_PAGES: usize = 2048;
pub const INODE_SHARE: u16 = 192;
pub const DENTRY_SHARE: u16 = 384;
pub const PAGE_SHARE: u16 = 3072;
pub const DESCRIPTION_SHARE: u16 = 96;
pub const ROOTS: usize = 320;
pub const PREPARATIONS: usize = 128;
pub const PREPARATION_SHARE: u16 = 96;
pub const ORIGINALS: usize = bootimg::rootfs::ENTRIES_MAX + 5;
pub const NODES: usize = ORIGINALS + INODES;
pub const NONE: u16 = u16::MAX;
pub const SYMLINK: u32 = 5;

pub fn canonical(tree: &Tree<'_>, n: u16) -> u16 {
    tree.canonical(n)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub slot: u16,
    pub generation: u64,
}
pub const ROOT: Token = Token {
    slot: 0,
    generation: 1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub id: u64,
    pub generation: u64,
}
pub const BOOT_ROOT: Root = Root {
    id: 0,
    generation: 1,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub inodes: u16,
    pub dentries: u16,
    pub pages: u16,
    pub descriptions: u16,
}
impl Usage {
    const EMPTY: Self = Self {
        inodes: 0,
        dentries: 0,
        pages: 0,
        descriptions: 0,
    };
}
#[derive(Clone, Copy)]
struct Account {
    key: Root,
    usage: Usage,
    pending: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pin {
    Fd,
    Cwd,
    Image,
    Pending,
    Parent,
}
impl Pin {
    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy)]
pub struct Node {
    pub generation: u64,
    pub kind: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub parent: Token,
    pub length: u64,
    pub times: [u64; 3],
    pub pins: [u16; 5],
    /// The boot entry (canonical for regular hard links), or NONE for fixed nodes.
    pub boot: u16,
    overlay: u16,
    reclaim: bool,
}
impl Node {
    const EMPTY: Self = Self {
        generation: 0,
        kind: 0,
        mode: 0,
        uid: 0,
        gid: 0,
        links: 0,
        parent: ROOT,
        length: 0,
        times: [0; 3],
        pins: [0; 5],
        boot: NONE,
        overlay: NONE,
        reclaim: false,
    };
    pub fn live(&self) -> bool {
        self.kind != 0 && !self.reclaim
    }
    fn retained(&self) -> bool {
        self.links != 0 || self.pins.iter().any(|&n| n != 0)
    }
}
#[derive(Clone, Copy)]
struct Overlay {
    node: u16,
    root: u16,
    pages: [u16; FILE_PAGES],
    head: u16,
}
impl Overlay {
    const EMPTY: Self = Self {
        node: NONE,
        root: NONE,
        pages: [NONE; FILE_PAGES],
        head: NONE,
    };
    fn initialize(&mut self, node: u16, root: u16) {
        self.pages.fill(NONE);
        self.head = NONE;
        self.node = node;
        self.root = root;
    }
}
#[derive(Clone, Copy)]
struct Dentry {
    parent: Token,
    node: Token,
    name: [u8; 255],
    len: u8,
    root: u16,
    reserved: bool,
}
impl Dentry {
    const EMPTY: Self = Self {
        parent: ROOT,
        node: ROOT,
        name: [0; 255],
        len: 0,
        root: NONE,
        reserved: false,
    };
}
#[derive(Clone, Copy)]
struct Original {
    parent: Token,
    node: Token,
    hidden: bool,
}
impl Original {
    const EMPTY: Self = Self {
        parent: ROOT,
        node: ROOT,
        hidden: false,
    };
}

/// The tables are initialized in BSS. Data pages come from one Memory object.
pub struct State {
    pub nodes: [Node; NODES],
    originals: [Original; ORIGINALS],
    original_len: usize,
    overlays: [Overlay; INODES],
    dentries: [Dentry; DENTRIES],
    accounts: [Option<Account>; ROOTS],
    inode_free: [u16; INODES],
    inode_len: usize,
    dentry_free: [u16; DENTRIES],
    dentry_len: usize,
    page_free: [u16; PAGES],
    page_len: usize,
    generations: [u64; INODES],
    pub epoch: u64,
    pending: [Option<Reservation>; PREPARATIONS],
    preparation_used: u16,
    reclaim_queue: [u16; INODES],
    reclaim_head: usize,
    reclaim_len: usize,
    page_next: [u16; PAGES],
    page_logical: [u16; PAGES],
}
impl State {
    pub const fn new() -> Self {
        Self {
            nodes: [Node::EMPTY; NODES],
            originals: [Original::EMPTY; ORIGINALS],
            original_len: 0,
            overlays: [Overlay::EMPTY; INODES],
            dentries: [Dentry::EMPTY; DENTRIES],
            accounts: [None; ROOTS],
            inode_free: [0; INODES],
            inode_len: INODES,
            dentry_free: [0; DENTRIES],
            dentry_len: DENTRIES,
            page_free: [0; PAGES],
            page_len: PAGES,
            generations: [0; INODES],
            epoch: 1,
            pending: [None; PREPARATIONS],
            preparation_used: 0,
            reclaim_queue: [0; INODES],
            reclaim_head: 0,
            reclaim_len: 0,
            page_next: [NONE; PAGES],
            page_logical: [0; PAGES],
        }
    }
}
impl State {
    pub fn initialize(&mut self) {
        self.nodes.fill(Node::EMPTY);
        self.originals.fill(Original::EMPTY);
        self.overlays.fill(Overlay::EMPTY);
        self.dentries.fill(Dentry::EMPTY);
        self.accounts.fill(None);
        self.pending.fill(None);
        self.inode_len = INODES;
        self.dentry_len = DENTRIES;
        self.page_len = PAGES;
        self.epoch = 1;
        self.preparation_used = 0;
    }
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// An allocated inode/name pair remains unpublished until commit.
#[derive(Clone, Copy, Debug)]
pub struct Reservation {
    pub token: Token,
    dentry: u16,
    epoch: u64,
    place: u16,
    root: u16,
}

pub struct Storage<'a> {
    pub state: &'a mut State,
    data: &'a mut [u8],
    pub tree: Option<Tree<'a>>,
}
impl<'a> Storage<'a> {
    pub fn new(state: &'a mut State, data: &'a mut [u8], tree: Option<Tree<'a>>, now: u64) -> Self {
        assert_eq!(data.len(), PAGES * PAGE);
        for (i, free) in state.inode_free.iter_mut().enumerate() {
            *free = (INODES - i - 1) as u16;
        }
        for (i, free) in state.dentry_free.iter_mut().enumerate() {
            *free = (DENTRIES - i - 1) as u16;
        }
        for (i, free) in state.page_free.iter_mut().enumerate() {
            *free = (PAGES - i - 1) as u16;
        }
        let out = Self { state, data, tree };
        for (i, (kind, mode, links, length, parent)) in [
            (crate::DIR, 0o555, 4, 0, ROOT),
            (crate::DIR, 0o555, 2, 0, ROOT),
            (crate::DIR, 0o1777, 2, 0, ROOT),
            (
                crate::REG,
                0o444,
                1,
                crate::MOTD.len() as u64,
                Token {
                    slot: 1,
                    generation: 1,
                },
            ),
            (
                crate::REG,
                0o644,
                1,
                0,
                Token {
                    slot: 2,
                    generation: 1,
                },
            ),
        ]
        .into_iter()
        .enumerate()
        {
            out.state.nodes[i] = Node {
                generation: 1,
                kind,
                mode,
                links,
                length,
                parent,
                times: [now; 3],
                ..Node::EMPTY
            };
        }
        out.state.original_len = 4;
        for (d, slot) in [1, 2, 3, 4].into_iter().enumerate() {
            out.state.originals[d] = Original {
                parent: out.state.nodes[slot].parent,
                node: Token {
                    slot: slot as u16,
                    generation: 1,
                },
                hidden: false,
            };
        }
        if let Some(tree) = tree {
            out.state.nodes[0].links += u32::from(tree.root_links());
            for n in 0..tree.len() {
                let entry = tree.entry(n);
                let slot = 5 + canonical(&tree, n) as usize;
                let parent = tree.parent(n).map_or(ROOT, |p| Token {
                    slot: 5 + p,
                    generation: 1,
                });
                if out.state.nodes[slot].kind == 0 {
                    let file = crate::image_file(&tree, n);
                    out.state.nodes[slot] = Node {
                        generation: 1,
                        kind: file.kind(),
                        mode: entry.mode & 0o7777,
                        uid: entry.uid,
                        gid: entry.gid,
                        links: u32::from(tree.links(n)),
                        parent,
                        length: if file.is_device() {
                            0
                        } else {
                            tree.data(n).len() as u64
                        },
                        times: [now; 3],
                        boot: canonical(&tree, n),
                        ..Node::EMPTY
                    };
                }
                out.state.originals[4 + n as usize] = Original {
                    parent,
                    node: Token {
                        slot: slot as u16,
                        generation: 1,
                    },
                    hidden: false,
                };
            }
            out.state.original_len += tree.len() as usize;
        }
        out
    }
    pub fn token(&self, slot: u16) -> Result<Token, u32> {
        let n = self.state.nodes.get(slot as usize).ok_or(NO_ENTRY)?;
        if !n.live() {
            return Err(NO_ENTRY);
        }
        Ok(Token {
            slot,
            generation: n.generation,
        })
    }
    pub fn node(&self, token: Token) -> Result<&Node, u32> {
        let n = self.state.nodes.get(token.slot as usize).ok_or(NO_ENTRY)?;
        if n.generation != token.generation || !n.live() {
            return Err(NO_ENTRY);
        }
        Ok(n)
    }
    pub fn node_mut(&mut self, token: Token) -> Result<&mut Node, u32> {
        self.node(token)?;
        Ok(&mut self.state.nodes[token.slot as usize])
    }
    /// Metadata changes invalidate every retained path proof before publishing fields.
    pub fn set_attributes(
        &mut self,
        token: Token,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), u32> {
        self.node(token)?;
        let next = self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        let node = &mut self.state.nodes[token.slot as usize];
        node.mode = mode;
        node.uid = uid;
        node.gid = gid;
        self.state.epoch = next;
        Ok(())
    }
    fn account(&mut self, key: Root) -> Result<usize, u32> {
        if let Some(i) = self
            .state
            .accounts
            .iter()
            .position(|a| a.is_some_and(|a| a.key == key))
        {
            return Ok(i);
        }
        let i = self
            .state
            .accounts
            .iter()
            .position(|a| a.is_none_or(|a| a.usage == Usage::EMPTY && a.pending == 0))
            .ok_or(NO_SPACE)?;
        self.state.accounts[i] = Some(Account {
            key,
            usage: Usage::EMPTY,
            pending: 0,
        });
        Ok(i)
    }
    pub fn usage(&self, root: Root) -> Usage {
        self.state
            .accounts
            .iter()
            .flatten()
            .find(|a| a.key == root)
            .map_or(Usage::EMPTY, |a| a.usage)
    }
    pub fn available(&self) -> Usage {
        Usage {
            inodes: self.state.inode_len as u16,
            dentries: self.state.dentry_len as u16,
            pages: self.state.page_len as u16,
            descriptions: 0,
        }
    }
    fn uncharge(&mut self, root: usize, field: fn(&mut Usage) -> &mut u16) {
        let a = self.state.accounts[root].as_mut().expect("charged account");
        *field(&mut a.usage) -= 1;
        if a.usage == Usage::EMPTY && a.pending == 0 {
            self.state.accounts[root] = None;
        }
    }
    pub fn charge_description(&mut self, root: Root) -> Result<(), u32> {
        let i = self.account(root)?;
        let a = self.state.accounts[i].as_mut().unwrap();
        if a.usage.descriptions == DESCRIPTION_SHARE {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        a.usage.descriptions += 1;
        Ok(())
    }
    pub fn release_description(&mut self, root: Root) {
        if let Some(i) = self
            .state
            .accounts
            .iter()
            .position(|a| a.is_some_and(|a| a.key == root))
        {
            self.uncharge(i, |u| &mut u.descriptions);
        }
    }
    pub fn pin(&mut self, token: Token, kind: Pin) -> Result<(), u32> {
        let n = self.node_mut(token)?;
        n.pins[kind.index()] = n.pins[kind.index()].checked_add(1).ok_or(NO_SPACE)?;
        Ok(())
    }
    pub fn unpin(&mut self, token: Token, kind: Pin) -> Result<(), u32> {
        let n = self.node_mut(token)?;
        n.pins[kind.index()] = n.pins[kind.index()].checked_sub(1).ok_or(NO_ENTRY)?;
        self.collect(token);
        Ok(())
    }
    fn collect(&mut self, token: Token) {
        let n = &mut self.state.nodes[token.slot as usize];
        if !n.retained() && n.overlay != NONE && !n.reclaim {
            n.reclaim = true;
            let tail = (self.state.reclaim_head + self.state.reclaim_len) % INODES;
            self.state.reclaim_queue[tail] = n.overlay;
            self.state.reclaim_len += 1;
        }
    }
    fn original_name(&self, i: usize) -> &[u8] {
        match i {
            0 => b"etc",
            1 => b"tmp",
            2 => b"motd",
            3 => b"probe",
            _ => {
                let path = self
                    .tree
                    .as_ref()
                    .unwrap()
                    .entry((i - 4) as u16)
                    .path
                    .as_bytes();
                &path[path.iter().rposition(|&b| b == b'/').unwrap() + 1..]
            }
        }
    }
    pub fn entry(&self, parent: Token, index: usize) -> Option<(&[u8], Token)> {
        if index < self.state.original_len {
            let d = self.state.originals[index];
            return (!d.hidden && d.parent == parent).then(|| (self.original_name(index), d.node));
        }
        let d = self.state.dentries.get(index - self.state.original_len)?;
        (d.len != 0 && !d.reserved && d.parent == parent)
            .then_some((&d.name[..d.len as usize], d.node))
    }
    pub fn entries(&self) -> usize {
        self.state.original_len + DENTRIES
    }
    pub fn lookup(&self, parent: Token, name: &[u8]) -> Result<Token, u32> {
        for (i, original) in self.state.originals[..self.state.original_len]
            .iter()
            .enumerate()
        {
            if !original.hidden && original.parent == parent && self.original_name(i) == name {
                return Ok(original.node);
            }
        }
        for dentry in &self.state.dentries {
            if dentry.len != 0
                && !dentry.reserved
                && dentry.parent == parent
                && dentry.len as usize == name.len()
                && &dentry.name[..dentry.len as usize] == name
            {
                return Ok(dentry.node);
            }
        }
        Err(NO_ENTRY)
    }
    pub fn resolve(&self, path: &[u8]) -> Result<Token, u32> {
        let mut token = ROOT;
        for name in path.split(|&b| b == b'/').filter(|n| !n.is_empty()) {
            if self.node(token)?.kind != crate::DIR {
                return Err(proto_fs::NOT_DIRECTORY);
            }
            token = match name {
                b"." => token,
                b".." => self.node(token)?.parent,
                _ => self.lookup(token, name)?,
            };
        }
        Ok(token)
    }
    fn overlay(&mut self, token: Token, root: Root) -> Result<usize, u32> {
        let n = self.node(token)?;
        if n.overlay != NONE {
            return Ok(n.overlay as usize);
        }
        let a = self.account(root)?;
        if self.state.inode_len == 0 || self.state.accounts[a].unwrap().usage.inodes == INODE_SHARE
        {
            return Err(NO_SPACE);
        }
        let next = self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        self.state.inode_len -= 1;
        let i = self.state.inode_free[self.state.inode_len] as usize;
        self.state.overlays[i].initialize(token.slot, a as u16);
        self.state.nodes[token.slot as usize].overlay = i as u16;
        self.state.accounts[a].as_mut().unwrap().usage.inodes += 1;
        self.state.epoch = next;
        Ok(i)
    }
    pub fn reserve(
        &mut self,
        root: Root,
        parent: Token,
        name: &[u8],
        attributes: (u32, u32, u32, u32),
    ) -> Result<Reservation, u32> {
        let (kind, mode, uid, gid) = attributes;
        if name.is_empty()
            || name.len() > 255
            || name.contains(&0)
            || name.contains(&b'/')
            || name == b"."
            || name == b".."
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if self.node(parent)?.kind != crate::DIR {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        if self.node(parent)?.links == 0 {
            return Err(NO_ENTRY);
        }
        if self.lookup(parent, name).is_ok() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if ![crate::DIR, crate::REG, SYMLINK].contains(&kind) {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let a = self.account(root)?;
        let usage = self.state.accounts[a].unwrap().usage;
        let place = self
            .state
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
        if self.state.preparation_used as usize == PREPARATIONS
            || self.state.accounts[a].unwrap().pending == PREPARATION_SHARE
        {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        if self.node(parent)?.pins[Pin::Pending.index()] == u16::MAX {
            return Err(NO_SPACE);
        }
        if self.state.inode_len == 0
            || self.state.dentry_len == 0
            || usage.inodes == INODE_SHARE
            || usage.dentries == DENTRY_SHARE
        {
            return Err(NO_SPACE);
        }
        let i = self.state.inode_free[self.state.inode_len - 1] as usize;
        let generation = self.state.generations[i].checked_add(1).ok_or(NO_SPACE)?;
        let token = Token {
            slot: (ORIGINALS + i) as u16,
            generation,
        };
        self.state.inode_len -= 1;
        self.state.dentry_len -= 1;
        let d = self.state.dentry_free[self.state.dentry_len] as usize;
        self.state.generations[i] = generation;
        self.state.overlays[i].initialize(token.slot, a as u16);
        self.state.nodes[token.slot as usize] = Node {
            generation,
            kind,
            mode,
            uid,
            gid,
            parent,
            overlay: i as u16,
            pins: [0, 0, 0, 1, 0],
            ..Node::EMPTY
        };
        let entry = &mut self.state.dentries[d];
        *entry = Dentry {
            parent,
            node: token,
            len: name.len() as u8,
            root: a as u16,
            reserved: true,
            ..Dentry::EMPTY
        };
        entry.name[..name.len()].copy_from_slice(name);
        let usage = &mut self.state.accounts[a].as_mut().unwrap().usage;
        usage.inodes += 1;
        usage.dentries += 1;
        self.pin(parent, Pin::Pending)?;
        let reservation = Reservation {
            token,
            dentry: d as u16,
            epoch: self.state.epoch,
            place: place as u16,
            root: a as u16,
        };
        self.state.pending[place] = Some(reservation);
        self.state.accounts[a].as_mut().unwrap().pending += 1;
        self.state.preparation_used += 1;
        Ok(reservation)
    }
    pub fn commit(&mut self, reservation: Reservation) -> Result<Token, u32> {
        let d = self.state.dentries[reservation.dentry as usize];
        if !d.reserved || d.node != reservation.token || reservation.epoch != self.state.epoch {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let next = self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        self.node(reservation.token)?;
        self.node(d.parent)?;
        self.state.dentries[reservation.dentry as usize].reserved = false;
        let n = &mut self.state.nodes[reservation.token.slot as usize];
        n.pins[Pin::Pending.index()] -= 1;
        n.links = if n.kind == crate::DIR { 2 } else { 1 };
        if n.kind == crate::DIR {
            self.state.nodes[d.parent.slot as usize].links += 1;
        }
        self.unpin(d.parent, Pin::Pending)?;
        self.state.epoch = next;
        self.end_preparation(reservation);
        Ok(reservation.token)
    }
    pub fn cancel(&mut self, r: Reservation) -> Result<(), u32> {
        let d = self.state.dentries[r.dentry as usize];
        if !d.reserved || d.node != r.token {
            return Err(NO_ENTRY);
        }
        self.drop_dentry(r.dentry as usize);
        self.unpin(d.parent, Pin::Pending)?;
        self.unpin(r.token, Pin::Pending)?;
        self.end_preparation(r);
        Ok(())
    }

    fn end_preparation(&mut self, r: Reservation) {
        self.state.pending[r.place as usize] = None;
        self.release_preparation(r.root);
    }
    pub fn preparations_used(&self) -> u16 {
        self.state.preparation_used
    }
    pub fn charge_preparation(&mut self, root: Root) -> Result<u16, u32> {
        if self.state.preparation_used as usize == PREPARATIONS {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        let a = self.account(root)?;
        if self.state.accounts[a].unwrap().pending == PREPARATION_SHARE {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        self.state.accounts[a].as_mut().unwrap().pending += 1;
        self.state.preparation_used += 1;
        Ok(a as u16)
    }
    /// Move the one existing charge after authenticating its actual expenditure root.
    pub fn reassign_preparation(&mut self, old: u16, root: Root) -> Result<u16, u32> {
        if self.state.accounts[old as usize].unwrap().key == root {
            return Ok(old);
        }
        let new = self.account(root)?;
        if self.state.accounts[new].unwrap().pending == PREPARATION_SHARE {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        self.state.accounts[new].as_mut().unwrap().pending += 1;
        self.release_preparation(old);
        self.state.preparation_used += 1;
        Ok(new as u16)
    }
    pub fn release_preparation(&mut self, root: u16) {
        let a = self.state.accounts[root as usize]
            .as_mut()
            .expect("paid preparation");
        a.pending -= 1;
        self.state.preparation_used -= 1;
        if a.pending == 0 && a.usage == Usage::EMPTY {
            self.state.accounts[root as usize] = None;
        }
    }

    fn drop_dentry(&mut self, i: usize) {
        let root = self.state.dentries[i].root as usize;
        self.state.dentries[i] = Dentry::EMPTY;
        self.state.dentry_free[self.state.dentry_len] = i as u16;
        self.state.dentry_len += 1;
        self.uncharge(root, |u| &mut u.dentries);
    }
    /// Model namespace deletion. Public mutation methods are added separately.
    pub fn unlink(&mut self, parent: Token, name: &[u8], root: Root) -> Result<Token, u32> {
        let token = self.lookup(parent, name)?;
        if self.node(token)?.kind == crate::DIR {
            return Err(proto_fs::IS_DIRECTORY);
        }
        let next = self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        let original = (0..self.state.original_len)
            .find(|&i| self.entry(parent, i).is_some_and(|(n, _)| n == name));
        // Reserve the tombstone's name charge before publishing a boot overlay.
        let original_account = if original.is_some() {
            let a = self.account(root)?;
            if self.state.dentry_len == 0
                || self.state.accounts[a].unwrap().usage.dentries == DENTRY_SHARE
            {
                return Err(NO_SPACE);
            }
            Some(a)
        } else {
            None
        };
        self.overlay(token, root)?;
        if let Some(i) = original {
            let a = original_account.expect("reserved original name");
            self.state.dentry_len -= 1;
            let d = self.state.dentry_free[self.state.dentry_len] as usize;
            self.state.dentries[d] = Dentry {
                parent,
                node: token,
                root: a as u16,
                reserved: true,
                ..Dentry::EMPTY
            };
            self.state.accounts[a].as_mut().unwrap().usage.dentries += 1;
            self.state.originals[i].hidden = true;
        } else {
            let i = self
                .state
                .dentries
                .iter()
                .position(|d| {
                    d.len != 0
                        && !d.reserved
                        && d.parent == parent
                        && &d.name[..d.len as usize] == name
                })
                .ok_or(NO_ENTRY)?;
            self.drop_dentry(i);
        }
        self.state.nodes[token.slot as usize].links -= 1;
        self.state.epoch = next;
        self.collect(token);
        Ok(token)
    }
    /// Model hard link with one paid name; the shared inode retains its original root.
    pub fn link(
        &mut self,
        root: Root,
        parent: Token,
        name: &[u8],
        token: Token,
    ) -> Result<(), u32> {
        if name.is_empty()
            || name.len() > 255
            || name.contains(&0)
            || name.contains(&b'/')
            || name == b"."
            || name == b".."
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if self.node(parent)?.kind != crate::DIR {
            return Err(proto_fs::NOT_DIRECTORY);
        }
        if self.node(token)?.kind == crate::DIR {
            return Err(proto_fs::PERMISSION);
        }
        if self.lookup(parent, name).is_ok() {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let next = self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        let links = self.node(token)?.links.checked_add(1).ok_or(NO_SPACE)?;
        let a = self.account(root)?;
        if self.state.dentry_len == 0
            || self.state.accounts[a].unwrap().usage.dentries == DENTRY_SHARE
        {
            return Err(NO_SPACE);
        }
        self.state.dentry_len -= 1;
        let i = self.state.dentry_free[self.state.dentry_len] as usize;
        self.state.dentries[i] = Dentry {
            parent,
            node: token,
            root: a as u16,
            len: name.len() as u8,
            ..Dentry::EMPTY
        };
        self.state.dentries[i].name[..name.len()].copy_from_slice(name);
        self.state.accounts[a].as_mut().unwrap().usage.dentries += 1;
        self.state.nodes[token.slot as usize].links = links;
        self.state.epoch = next;
        Ok(())
    }

    pub fn boot_bytes(&self, token: Token) -> &'a [u8] {
        let n = &self.state.nodes[token.slot as usize];
        if token.slot == 3 {
            crate::MOTD
        } else if n.boot != NONE && n.kind == crate::REG {
            self.tree.as_ref().unwrap().data(n.boot)
        } else {
            &[]
        }
    }
    pub fn read(&self, token: Token, offset: u64, out: &mut [u8]) -> Result<usize, u32> {
        let n = self.node(token)?;
        let count = out.len().min(n.length.saturating_sub(offset) as usize);
        let boot = self.boot_bytes(token);
        if n.overlay == NONE && offset <= boot.len() as u64 && count <= boot.len() - offset as usize
        {
            let bytes = &boot[offset as usize..offset as usize + count];
            #[cfg(not(target_arch = "aarch64"))]
            let copied = 0;
            #[cfg(target_arch = "aarch64")]
            let mut copied = 0;
            #[cfg(target_arch = "aarch64")]
            while copied + 32 <= count {
                // SAFETY: every scalar word pair stays inside both checked slices.
                // AArch64 normal-memory loads/stores support unaligned addresses;
                // output cannot alias the immutable boot mapping. This avoids the
                // freestanding byte-copy builtin at opt-level="s", without SIMD.
                unsafe {
                    core::arch::asm!(
                        "ldp {a}, {b}, [{source}]",
                        "ldp {c}, {d}, [{source}, #16]",
                        "stp {a}, {b}, [{destination}]",
                        "stp {c}, {d}, [{destination}, #16]",
                        source = in(reg) bytes.as_ptr().add(copied),
                        destination = in(reg) out.as_mut_ptr().add(copied),
                        a = out(reg) _, b = out(reg) _, c = out(reg) _, d = out(reg) _,
                        options(nostack, preserves_flags),
                    );
                }
                copied += 32;
            }
            out[copied..count].copy_from_slice(&bytes[copied..]);
            return Ok(count);
        }
        let mut copied = 0;
        while copied < count {
            let at = offset as usize + copied;
            let amount = (PAGE - at % PAGE).min(count - copied);
            let p = if n.overlay == NONE {
                NONE
            } else {
                self.state.overlays[n.overlay as usize].pages[at / PAGE]
            };
            let chunk = &mut out[copied..copied + amount];
            if p == NONE {
                let available = boot.len().saturating_sub(at).min(amount);
                chunk[..available]
                    .copy_from_slice(&boot[at.min(boot.len())..at.min(boot.len()) + available]);
                chunk[available..].fill(0);
            } else {
                let start = p as usize * PAGE + at % PAGE;
                chunk.copy_from_slice(&self.data[start..start + amount]);
            }
            copied += amount;
        }
        Ok(count)
    }
    pub fn write(
        &mut self,
        token: Token,
        root: Root,
        offset: usize,
        bytes: &[u8],
    ) -> Result<usize, u32> {
        let end = offset
            .checked_add(bytes.len())
            .filter(|&n| n <= FILE_PAGES * PAGE)
            .ok_or(NO_SPACE)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let first = offset / PAGE;
        let last = (end - 1) / PAGE;
        let existing = self.node(token)?.overlay;
        // A refused first write must leave the boot inode and its quota unchanged.
        let (a, need) = if existing == NONE {
            (self.account(root)?, last - first + 1)
        } else {
            let overlay = &self.state.overlays[existing as usize];
            (
                overlay.root as usize,
                (first..=last).filter(|&p| overlay.pages[p] == NONE).count(),
            )
        };
        if need > self.state.page_len
            || self.state.accounts[a].unwrap().usage.pages as usize + need > PAGE_SHARE as usize
        {
            return Err(NO_SPACE);
        }
        let i = self.overlay(token, root)?;
        for p in first..=last {
            if self.state.overlays[i].pages[p] != NONE {
                continue;
            }
            self.state.page_len -= 1;
            let page = self.state.page_free[self.state.page_len];
            let start = p * PAGE;
            let boot = self.boot_bytes(token);
            let amount = boot.len().saturating_sub(start).min(PAGE);
            let data = &mut self.data[page as usize * PAGE..(page as usize + 1) * PAGE];
            data[..amount]
                .copy_from_slice(&boot[start.min(boot.len())..start.min(boot.len()) + amount]);
            data[amount..].fill(0);
            // Publish the page only after its boot prefix and zero tail are initialized.
            self.state.overlays[i].pages[p] = page;
            self.state.page_next[page as usize] = self.state.overlays[i].head;
            self.state.page_logical[page as usize] = p as u16;
            self.state.overlays[i].head = page;
            self.state.accounts[a].as_mut().unwrap().usage.pages += 1;
        }
        for (n, b) in bytes.iter().enumerate() {
            let at = offset + n;
            let p = self.state.overlays[i].pages[at / PAGE];
            self.data[p as usize * PAGE + at % PAGE] = *b;
        }
        self.state.nodes[token.slot as usize].length =
            self.state.nodes[token.slot as usize].length.max(end as u64);
        Ok(bytes.len())
    }
    /// One overlay slot or one page per call. A detached inode keeps its charge until the final pin.
    pub fn reclaim_step(&mut self) -> bool {
        if self.state.reclaim_len == 0 {
            return false;
        }
        let i = self.state.reclaim_queue[self.state.reclaim_head] as usize;
        let overlay = self.state.overlays[i];
        if overlay.head != NONE {
            let page = overlay.head;
            let p = self.state.page_logical[page as usize] as usize;
            self.state.overlays[i].head = self.state.page_next[page as usize];
            self.state.overlays[i].pages[p] = NONE;
            self.state.page_free[self.state.page_len] = page;
            self.state.page_len += 1;
            self.uncharge(overlay.root as usize, |u| &mut u.pages);
        } else {
            self.state.nodes[overlay.node as usize] = Node {
                generation: self.state.nodes[overlay.node as usize].generation,
                ..Node::EMPTY
            };
            self.state.overlays[i] = Overlay::EMPTY;
            self.state.inode_free[self.state.inode_len] = i as u16;
            self.state.inode_len += 1;
            self.uncharge(overlay.root as usize, |u| &mut u.inodes);
            self.state.reclaim_head = (self.state.reclaim_head + 1) % INODES;
            self.state.reclaim_len -= 1;
        }
        true
    }
    pub fn blocks(&self, token: Token) -> u64 {
        let n = &self.state.nodes[token.slot as usize];
        let pages = if n.overlay == NONE {
            0
        } else {
            self.state.overlays[n.overlay as usize]
                .pages
                .iter()
                .filter(|&&p| p != NONE)
                .count()
        };
        (self.boot_bytes(token).len() as u64).div_ceil(512) + pages as u64 * 8
    }
}

#[cfg(test)]
mod page_tests {
    extern crate std;
    use super::*;

    const FIRST: Root = Root {
        id: 11,
        generation: 7,
    };

    fn create(storage: &mut Storage<'_>, name: &[u8]) -> Token {
        let reservation = storage
            .reserve(FIRST, ROOT, name, (crate::REG, 0o644, 1, 2))
            .unwrap();
        storage.commit(reservation).unwrap()
    }

    fn drain(storage: &mut Storage<'_>) -> usize {
        let mut steps = 0;
        while storage.reclaim_step() {
            steps += 1;
            assert!(steps <= PAGES + INODES);
        }
        steps
    }

    #[test]
    fn lookup_matches_entry_oracle_at_full_dentry_capacity() {
        use bootimg::rootfs::{Entry, REGULAR};
        let image = crate::tree::test_image(&[Entry {
            path: "/boot",
            mode: REGULAR | 0o644,
            uid: 1,
            gid: 2,
            file: 1,
        }]);
        let mut index = crate::tree::Index::new();
        let tree = crate::tree::load(&image, &mut index).unwrap();
        let mut ram = crate::Ram::with_tree(0, tree);
        let storage = &mut ram.storage;
        let directory = storage
            .reserve(FIRST, ROOT, b"directory", (crate::DIR, 0o755, 0, 0))
            .unwrap();
        let directory = storage.commit(directory).unwrap();
        let shared = create(storage, b"same");
        let nested = storage
            .reserve(FIRST, directory, b"same", (crate::REG, 0o644, 0, 0))
            .unwrap();
        let nested = storage.commit(nested).unwrap();
        let raw = create(storage, b"\xffraw");
        let _pending = storage
            .reserve(FIRST, ROOT, b"pending", (crate::REG, 0o644, 0, 0))
            .unwrap();
        let oracle = |storage: &Storage<'_>, parent, name: &[u8]| {
            (0..storage.entries())
                .find_map(|i| {
                    storage
                        .entry(parent, i)
                        .filter(|(bytes, _)| *bytes == name)
                        .map(|(_, token)| token)
                })
                .ok_or(NO_ENTRY)
        };
        for parent in [ROOT, directory] {
            for name in [
                b"same".as_slice(),
                b"\xffraw",
                b"pending",
                b"boot",
                b"",
                b"absent",
            ] {
                assert_eq!(storage.lookup(parent, name), oracle(storage, parent, name));
            }
        }
        assert_eq!(storage.lookup(ROOT, b"same"), Ok(shared));
        assert_eq!(storage.lookup(directory, b"same"), Ok(nested));
        assert_eq!(storage.lookup(ROOT, b"\xffraw"), Ok(raw));
        assert_eq!(storage.lookup(ROOT, b"pending"), Err(NO_ENTRY));
        storage.unlink(ROOT, b"boot", FIRST).unwrap();
        assert_eq!(
            storage.lookup(ROOT, b"boot"),
            oracle(storage, ROOT, b"boot")
        );
        assert_eq!(storage.lookup(ROOT, b"boot"), Err(NO_ENTRY));
        for i in 0..DENTRIES {
            if storage.available().dentries == 0 {
                break;
            }
            let root = if storage.usage(FIRST).dentries < DENTRY_SHARE {
                FIRST
            } else {
                Root {
                    id: 22,
                    generation: 9,
                }
            };
            storage
                .link(root, ROOT, std::format!("filler{i}").as_bytes(), shared)
                .unwrap();
        }
        assert_eq!(storage.available().dentries, 0);
        let last = &storage.state.dentries[DENTRIES - 1];
        let name = &last.name[..last.len as usize];
        assert!(!name.is_empty());
        assert_eq!(storage.lookup(ROOT, name), Ok(shared));
        for parent in [ROOT, directory] {
            assert_eq!(storage.lookup(parent, name), oracle(storage, parent, name));
            for i in 0..storage.entries() {
                if let Some((name, _)) = storage.entry(parent, i) {
                    assert_eq!(storage.lookup(parent, name), oracle(storage, parent, name));
                }
            }
        }
        assert_eq!(
            storage.lookup(ROOT, b"still-absent"),
            oracle(storage, ROOT, b"still-absent")
        );
        let last_name = std::vec::Vec::from(name);
        let usage = storage.usage(FIRST);
        assert_eq!(
            storage
                .reserve(FIRST, ROOT, &last_name, (crate::REG, 0o644, 0, 0))
                .err(),
            Some(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(storage.usage(FIRST), usage);
    }

    #[test]
    fn reused_overlay_is_initialized_before_reserved_inode_publication() {
        let mut ram = crate::Ram::new(0);
        let storage = &mut ram.storage;
        let old = create(storage, b"old");
        storage.write(old, FIRST, PAGE + 5, b"old bytes").unwrap();
        let slot = storage.node(old).unwrap().overlay as usize;
        storage.unlink(ROOT, b"old", FIRST).unwrap();
        assert_eq!(drain(storage), 2);
        // Free metadata may contain stale links; admission must initialize every field.
        storage.state.overlays[slot] = Overlay {
            node: old.slot,
            root: 7,
            pages: [123; FILE_PAGES],
            head: 123,
        };
        let reservation = storage
            .reserve(FIRST, ROOT, b"new", (crate::REG, 0o644, 0, 0))
            .unwrap();
        assert_eq!(
            storage.node(reservation.token).unwrap().overlay as usize,
            slot
        );
        assert_eq!(reservation.token.slot, old.slot);
        assert!(reservation.token.generation > old.generation);
        let overlay = &storage.state.overlays[slot];
        assert_eq!(overlay.node, reservation.token.slot);
        assert_eq!(overlay.root, reservation.root);
        assert_eq!(overlay.head, NONE);
        assert!(overlay.pages.iter().all(|&page| page == NONE));
        assert_eq!(storage.usage(FIRST).pages, 0);
        assert_eq!(storage.lookup(ROOT, b"new"), Err(NO_ENTRY));
        let new = storage.commit(reservation).unwrap();
        storage
            .write(new, FIRST, FILE_PAGES * PAGE - 1, b"z")
            .unwrap();
        let mut tail = [0xa5; 8];
        assert_eq!(
            storage.read(new, (FILE_PAGES * PAGE - 8) as u64, &mut tail),
            Ok(8)
        );
        assert_eq!(tail, *b"\0\0\0\0\0\0\0z");
        assert_eq!(storage.usage(FIRST).pages, 1);
        storage.unlink(ROOT, b"new", FIRST).unwrap();
        assert_eq!(drain(storage), 2);
        assert_eq!(storage.usage(FIRST), Usage::default());
    }

    #[test]
    fn reused_backing_page_preserves_boot_prefix_and_clears_sparse_tail() {
        use bootimg::rootfs::{Entry, REGULAR};
        let image = crate::tree::test_image(&[Entry {
            path: "/boot",
            mode: REGULAR | 0o644,
            uid: 1,
            gid: 2,
            file: 1,
        }]);
        let mut index = crate::tree::Index::new();
        let tree = crate::tree::load(&image, &mut index).unwrap();
        let mut ram = crate::Ram::with_tree(0, tree);
        let storage = &mut ram.storage;
        storage.data.fill(0xa5);
        let dirty = create(storage, b"dirty");
        storage.write(dirty, FIRST, 0, &[0xa5; PAGE]).unwrap();
        let dirty_overlay = storage.node(dirty).unwrap().overlay as usize;
        let physical = storage.state.overlays[dirty_overlay].pages[0];
        storage.unlink(ROOT, b"dirty", FIRST).unwrap();
        assert_eq!(drain(storage), 2);
        assert_eq!(storage.usage(FIRST).pages, 0);

        let boot = storage.resolve(b"/boot").unwrap();
        storage.write(boot, FIRST, PAGE - 1, b"z").unwrap();
        let boot_overlay = storage.node(boot).unwrap().overlay as usize;
        assert_eq!(storage.state.overlays[boot_overlay].pages[0], physical);
        let mut out = [0xa5; PAGE];
        assert_eq!(storage.read(boot, 0, &mut out), Ok(PAGE));
        assert_eq!(&out[..11], b"alpha bytes");
        assert!(out[11..PAGE - 1].iter().all(|&b| b == 0));
        assert_eq!(out[PAGE - 1], b'z');
        assert_eq!(tree.data(0), b"alpha bytes");

        storage.unlink(ROOT, b"boot", FIRST).unwrap();
        assert_eq!(drain(storage), 2);
        let sparse = create(storage, b"sparse");
        storage.write(sparse, FIRST, 2 * PAGE + 7, b"x").unwrap();
        let sparse_overlay = storage.node(sparse).unwrap().overlay as usize;
        assert_eq!(storage.state.overlays[sparse_overlay].pages[2], physical);
        let mut gap = [0xa5; 2 * PAGE + 8];
        assert_eq!(storage.read(sparse, 0, &mut gap), Ok(gap.len()));
        assert!(gap[..gap.len() - 1].iter().all(|&b| b == 0));
        assert_eq!(gap[gap.len() - 1], b'x');
        assert_eq!(storage.usage(FIRST).pages, 1);
    }
}
