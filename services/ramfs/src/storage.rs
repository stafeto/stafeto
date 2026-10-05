// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One bounded inode namespace with boot-backed bytes and paid overlays.
//! Reservations retain their expenditure root until cancellation or reclamation.

#[path = "namespace.rs"]
pub mod namespace;

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
    /// Writable open descriptions, counted through their final retained reference.
    pub writers: u16,
    pub parent: Token,
    pub length: u64,
    /// Payload changes are independent of namespace proof invalidation.
    pub data_generation: u64,
    /// Shrinking never makes truncated boot bytes visible after a later extension.
    pub boot_visible_length: u64,
    pub times: [proto_fs::Timestamp; 3],
    pub pins: [u16; 5],
    /// The boot entry (canonical for regular hard links), or NONE for fixed nodes.
    pub boot: u16,
    overlay: u16,
    reclaim: bool,
    orphan_parent: bool,
}
impl Node {
    const EMPTY: Self = Self {
        generation: 0,
        kind: 0,
        mode: 0,
        uid: 0,
        gid: 0,
        links: 0,
        writers: 0,
        parent: ROOT,
        length: 0,
        data_generation: 0,
        boot_visible_length: 0,
        times: [proto_fs::Timestamp::ZERO; 3],
        pins: [0; 5],
        boot: NONE,
        overlay: NONE,
        reclaim: false,
        orphan_parent: false,
    };
    pub fn live(&self) -> bool {
        self.kind != 0 && !self.reclaim
    }
    fn retained(&self) -> bool {
        self.links != 0 || self.pins.iter().any(|&n| n != 0)
    }
}
fn boot_sectors(logical: usize, visible_length: u64) -> u16 {
    visible_length
        .saturating_sub((logical * PAGE) as u64)
        .min(PAGE as u64)
        .div_ceil(512) as u16
}

#[derive(Clone, Copy)]
struct Overlay {
    node: u16,
    root: u16,
    pages: [u16; FILE_PAGES],
    group_tail: [u16; FILE_PAGES / 64],
    head: u16,
    mapped_count: u16,
    shadow_boot_sectors: u16,
}
impl Overlay {
    const EMPTY: Self = Self {
        node: NONE,
        root: NONE,
        pages: [NONE; FILE_PAGES],
        group_tail: [NONE; FILE_PAGES / 64],
        head: NONE,
        mapped_count: 0,
        shadow_boot_sectors: 0,
    };
    /// At most 63 mapping cells and 31 previous group tails are inspected.
    fn predecessor(&self, logical: usize) -> u16 {
        let group = logical / 64;
        for index in (group * 64..logical).rev() {
            if self.pages[index] != NONE {
                return self.pages[index];
            }
        }
        for index in (0..group).rev() {
            if self.group_tail[index] != NONE {
                return self.group_tail[index];
            }
        }
        NONE
    }

    fn initialize(&mut self, node: u16, root: u16) {
        self.pages.fill(NONE);
        self.group_tail.fill(NONE);
        self.head = NONE;
        self.mapped_count = 0;
        self.shadow_boot_sectors = 0;
        self.node = node;
        self.root = root;
    }
}
/// A detached chain retains its page charge without referencing a reusable overlay.
#[derive(Clone, Copy)]
struct RetiredPages {
    head: u16,
    root: u16,
}
impl RetiredPages {
    const EMPTY: Self = Self {
        head: NONE,
        root: NONE,
    };
}

#[derive(Clone, Copy)]
struct Dentry {
    parent: Token,
    node: Token,
    name: [u8; 255],
    len: u8,
    root: u16,
    reserved: bool,
    cookie: u64,
}
impl Dentry {
    const EMPTY: Self = Self {
        parent: ROOT,
        node: ROOT,
        name: [0; 255],
        len: 0,
        root: NONE,
        reserved: false,
        cookie: 0,
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

/// Filesystem capacity uses the immutable canonical boot population and paid pools.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSystemInfo {
    pub block_size: u64,
    pub fragment_size: u64,
    pub blocks: u64,
    pub free_blocks: u64,
    pub available_blocks: u64,
    pub files: u64,
    pub free_files: u64,
    pub available_files: u64,
    pub filesystem_id: u64,
    pub flags: u64,
    pub name_max: u64,
}

/// The tables are initialized in BSS. Data pages come from one Memory object.
pub struct State {
    pub nodes: [Node; NODES],
    originals: [Original; ORIGINALS],
    original_len: usize,
    next_cookie: u64,
    boot_files: u64,
    boot_blocks: u64,
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
    retired: [RetiredPages; PAGES],
    retired_head: usize,
    retired_len: usize,
    retired_turn: bool,
    page_next: [u16; PAGES],
    page_logical: [u16; PAGES],
}
impl State {
    pub const fn new() -> Self {
        Self {
            nodes: [Node::EMPTY; NODES],
            originals: [Original::EMPTY; ORIGINALS],
            original_len: 0,
            next_cookie: (3 + ORIGINALS) as u64,
            boot_files: 0,
            boot_blocks: 0,
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
            retired: [RetiredPages::EMPTY; PAGES],
            retired_head: 0,
            retired_len: 0,
            retired_turn: false,
            page_next: [NONE; PAGES],
            page_logical: [0; PAGES],
        }
    }
}
impl State {
    pub fn initialize(&mut self) {
        self.nodes.fill(Node::EMPTY);
        self.boot_files = 0;
        self.boot_blocks = 0;
        self.originals.fill(Original::EMPTY);
        self.overlays.fill(Overlay::EMPTY);
        self.dentries.fill(Dentry::EMPTY);
        self.accounts.fill(None);
        self.pending.fill(None);
        self.inode_len = INODES;
        self.dentry_len = DENTRIES;
        self.page_len = PAGES;
        self.epoch = 1;
        self.next_cookie = (3 + ORIGINALS) as u64;
        self.preparation_used = 0;
        self.retired.fill(RetiredPages::EMPTY);
        self.retired_head = 0;
        self.retired_len = 0;
        self.retired_turn = false;
    }
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// An allocated inode/name pair remains unpublished until commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub token: Token,
    dentry: u16,
    epoch: u64,
    place: u16,
    root: u16,
}

impl Reservation {
    pub fn charge(&self) -> u16 {
        self.root
    }
}

pub struct Storage<'a> {
    pub state: &'a mut State,
    data: &'a mut [u8],
    pub tree: Option<Tree<'a>>,
}

#[derive(Clone, Copy)]
struct TempPage {
    physical: u16,
    logical: u16,
    ready: bool,
}
impl TempPage {
    const EMPTY: Self = Self {
        physical: NONE,
        logical: NONE,
        ready: false,
    };
}

pub(crate) struct DataWrite {
    token: Token,
    generation: u64,
    overlay: u16,
    private_overlay: bool,
    root: u16,
    pages: [TempPage; 2],
    predecessor: u16,
    predecessor_ready: bool,
    pub offset: u64,
    pub count: usize,
    committed: bool,
    canceled: bool,
}

pub(crate) struct DataTruncate {
    token: Token,
    generation: u64,
    old_length: u64,
    pub length: u64,
    overlay: u16,
    root: u16,
    tail: TempPage,
    scan: usize,
    detached: usize,
    last_keep: u16,
    first_retired: u16,
    mapped_count: u16,
    shadow_boot_sectors: u16,
    boot_visible_length: u64,
    committed: bool,
    canceled: bool,
}

impl Storage<'_> {
    /// Publish one initialized page into the increasing logical chain.
    fn link_page(&mut self, index: usize, logical: usize, page: u16, predecessor: u16) {
        let overlay = &mut self.state.overlays[index];
        let successor = if predecessor == NONE {
            overlay.head
        } else {
            self.state.page_next[predecessor as usize]
        };
        self.state.page_next[page as usize] = successor;
        self.state.page_logical[page as usize] = logical as u16;
        overlay.pages[logical] = page;
        if predecessor == NONE {
            overlay.head = page;
        } else {
            self.state.page_next[predecessor as usize] = page;
        }
        let group = logical / 64;
        let old_tail = overlay.group_tail[group];
        if old_tail == NONE || (self.state.page_logical[old_tail as usize] as usize) < logical {
            overlay.group_tail[group] = page;
        }
    }

    fn io_generation(&self, token: Token, generation: u64) -> Result<(), u32> {
        if self.node(token)?.data_generation != generation {
            return Err(proto_fs::STALE_PROOF);
        }
        Ok(())
    }

    fn io_preflight(&self, token: Token) -> Result<(), u32> {
        self.content_guard(token)?;
        self.node(token)?
            .data_generation
            .checked_add(1)
            .ok_or(NO_SPACE)?;
        self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        Ok(())
    }

    fn io_take_page(&mut self, root: u16, logical: usize) -> TempPage {
        self.state.page_len -= 1;
        let physical = self.state.page_free[self.state.page_len];
        self.state.accounts[root as usize]
            .as_mut()
            .expect("paid root")
            .usage
            .pages += 1;
        TempPage {
            physical,
            logical: logical as u16,
            ready: false,
        }
    }

    fn io_free_page(&mut self, root: u16, page: &mut TempPage) {
        self.state.page_free[self.state.page_len] = page.physical;
        self.state.page_len += 1;
        self.uncharge(root as usize, |usage| &mut usage.pages);
        *page = TempPage::EMPTY;
    }

    fn io_initialize_page(&mut self, token: Token, page: &mut TempPage, source: u16) {
        let destination = page.physical as usize * PAGE;
        if source != NONE {
            let source = source as usize * PAGE;
            self.data.copy_within(source..source + PAGE, destination);
        } else {
            let boot = self.boot_bytes(token);
            let at = page.logical as usize * PAGE;
            let amount = boot.len().saturating_sub(at).min(PAGE);
            let data = &mut self.data[destination..destination + PAGE];
            data[..amount].copy_from_slice(&boot[at.min(boot.len())..at.min(boot.len()) + amount]);
            data[amount..].fill(0);
        }
        page.ready = true;
    }

    pub(crate) fn prepare_data_write(
        &mut self,
        token: Token,
        root: Root,
        offset: u64,
        requested: usize,
    ) -> Result<DataWrite, u32> {
        self.io_preflight(token)?;
        let capacity = (FILE_PAGES * PAGE) as u64;
        if offset >= capacity {
            return Err(proto_fs::FILE_TOO_LARGE);
        }
        offset
            .checked_add(requested as u64)
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or(proto_fs::OFFSET_OVERFLOW)?;
        let existing = self.node(token)?.overlay;
        let account = if existing == NONE {
            self.account(root)?
        } else {
            self.state.overlays[existing as usize].root as usize
        };
        let usage = self.state.accounts[account]
            .expect("retained account")
            .usage;
        if existing == NONE && (self.state.inode_len == 0 || usage.inodes == INODE_SHARE) {
            return Err(NO_SPACE);
        }
        let mut credit = self.state.page_len.min((PAGE_SHARE - usage.pages) as usize);
        let wanted = requested.min((capacity - offset) as usize);
        let mut count = 0;
        while count < wanted {
            let at = offset as usize + count;
            let amount = (PAGE - at % PAGE).min(wanted - count);
            let missing =
                existing == NONE || self.state.overlays[existing as usize].pages[at / PAGE] == NONE;
            if missing {
                if credit == 0 {
                    break;
                }
                credit -= 1;
            }
            count += amount;
        }
        if count == 0 {
            return Err(NO_SPACE);
        }
        let overlay = if existing == NONE {
            self.state.inode_len -= 1;
            let slot = self.state.inode_free[self.state.inode_len];
            // Free overlays have no mapped pages; reclamation cleared each entry.
            let held = &mut self.state.overlays[slot as usize];
            debug_assert_eq!(held.head, NONE);
            held.node = token.slot;
            held.root = account as u16;
            self.state.accounts[account].as_mut().unwrap().usage.inodes += 1;
            slot
        } else {
            existing
        };
        let mut pages = [TempPage::EMPTY; 2];
        let mut next = 0;
        let first = offset as usize / PAGE;
        let last = (offset as usize + count - 1) / PAGE;
        for logical in first..=last {
            if self.state.overlays[overlay as usize].pages[logical] == NONE {
                pages[next] = self.io_take_page(account as u16, logical);
                next += 1;
            }
        }
        Ok(DataWrite {
            token,
            generation: self.node(token)?.data_generation,
            overlay,
            private_overlay: existing == NONE,
            root: account as u16,
            pages,
            predecessor: NONE,
            predecessor_ready: false,
            offset,
            count,
            committed: false,
            canceled: false,
        })
    }

    pub(crate) fn step_data_write(&mut self, data: &mut DataWrite) -> Result<bool, u32> {
        if data.canceled {
            return Err(proto_fs::BAD_FD);
        }
        self.io_generation(data.token, data.generation)?;
        if let Some(page) = data
            .pages
            .iter_mut()
            .find(|page| page.physical != NONE && !page.ready)
        {
            self.io_initialize_page(data.token, page, NONE);
        }
        let ready = data
            .pages
            .iter()
            .all(|page| page.physical == NONE || page.ready);
        if ready && !data.predecessor_ready {
            if let Some(page) = data.pages.iter().find(|page| page.physical != NONE) {
                data.predecessor =
                    self.state.overlays[data.overlay as usize].predecessor(page.logical as usize);
            }
            data.predecessor_ready = true;
        }
        Ok(ready)
    }

    pub(crate) fn commit_data_write(
        &mut self,
        data: &mut DataWrite,
        bytes: &[u8],
        now: proto_fs::Timestamp,
    ) -> Result<(), u32> {
        if data.committed {
            return Ok(());
        }
        if data.canceled
            || !data.predecessor_ready
            || bytes.len() != data.count
            || data
                .pages
                .iter()
                .any(|page| page.physical != NONE && !page.ready)
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        self.io_generation(data.token, data.generation)?;
        self.io_preflight(data.token)?;
        let boot_length = self.node(data.token)?.boot_visible_length;
        let mut predecessor = data.predecessor;
        for page in &mut data.pages {
            if page.physical == NONE {
                continue;
            }
            let overlay = &mut self.state.overlays[data.overlay as usize];
            debug_assert_eq!(overlay.pages[page.logical as usize], NONE);
            overlay.mapped_count += 1;
            overlay.shadow_boot_sectors += boot_sectors(page.logical as usize, boot_length);
            self.link_page(
                data.overlay as usize,
                page.logical as usize,
                page.physical,
                predecessor,
            );
            predecessor = page.physical;
            *page = TempPage::EMPTY;
        }
        let mut done = 0;
        while done < bytes.len() {
            let at = data.offset as usize + done;
            let amount = (PAGE - at % PAGE).min(bytes.len() - done);
            let physical = self.state.overlays[data.overlay as usize].pages[at / PAGE] as usize;
            let start = physical * PAGE + at % PAGE;
            self.data[start..start + amount].copy_from_slice(&bytes[done..done + amount]);
            done += amount;
        }
        let node = &mut self.state.nodes[data.token.slot as usize];
        node.overlay = data.overlay;
        node.length = node.length.max(data.offset + data.count as u64);
        node.data_generation += 1;
        node.times[1] = now;
        node.times[2] = now;
        node.mode &= !0o6000;
        self.state.epoch += 1;
        data.private_overlay = false;
        data.committed = true;
        Ok(())
    }

    pub(crate) fn cancel_data_write(&mut self, data: &mut DataWrite) -> Result<bool, u32> {
        data.canceled = true;
        if let Some(page) = data.pages.iter_mut().find(|page| page.physical != NONE) {
            self.io_free_page(data.root, page);
            return Ok(false);
        }
        if data.private_overlay {
            let overlay = &mut self.state.overlays[data.overlay as usize];
            overlay.node = NONE;
            overlay.root = NONE;
            self.state.inode_free[self.state.inode_len] = data.overlay;
            self.state.inode_len += 1;
            self.uncharge(data.root as usize, |usage| &mut usage.inodes);
            data.private_overlay = false;
            return Ok(false);
        }
        Ok(true)
    }

    pub(crate) fn prepare_data_truncate(
        &mut self,
        token: Token,
        length: u64,
    ) -> Result<DataTruncate, u32> {
        self.io_preflight(token)?;
        let node = *self.node(token)?;
        let root = if node.overlay == NONE {
            NONE
        } else {
            self.state.overlays[node.overlay as usize].root
        };
        let mut tail = TempPage::EMPTY;
        if length < node.length && !length.is_multiple_of(PAGE as u64) && node.overlay != NONE {
            let logical = length as usize / PAGE;
            if self.state.overlays[node.overlay as usize].pages[logical] != NONE {
                let usage = self.state.accounts[root as usize]
                    .expect("retained root")
                    .usage;
                if self.state.page_len == 0 || usage.pages == PAGE_SHARE {
                    return Err(NO_SPACE);
                }
                tail = self.io_take_page(root, logical);
            }
        }
        let scan = if length == 0 || length >= node.length || node.overlay == NONE {
            FILE_PAGES
        } else {
            0
        };
        Ok(DataTruncate {
            token,
            generation: node.data_generation,
            old_length: node.length,
            length,
            overlay: node.overlay,
            root,
            tail,
            scan,
            detached: 0,
            last_keep: NONE,
            first_retired: NONE,
            mapped_count: if length >= node.length && node.overlay != NONE {
                self.state.overlays[node.overlay as usize].mapped_count
            } else {
                0
            },
            shadow_boot_sectors: if length >= node.length && node.overlay != NONE {
                self.state.overlays[node.overlay as usize].shadow_boot_sectors
            } else {
                0
            },
            boot_visible_length: node.boot_visible_length.min(length),
            committed: false,
            canceled: false,
        })
    }

    pub(crate) fn step_data_truncate(&mut self, data: &mut DataTruncate) -> Result<bool, u32> {
        if data.canceled {
            return Err(proto_fs::BAD_FD);
        }
        self.io_generation(data.token, data.generation)?;
        if data.tail.physical != NONE && !data.tail.ready {
            let source =
                self.state.overlays[data.overlay as usize].pages[data.tail.logical as usize];
            self.io_initialize_page(data.token, &mut data.tail, source);
            let start = data.tail.physical as usize * PAGE + data.length as usize % PAGE;
            let end = (data.tail.physical as usize + 1) * PAGE;
            self.data[start..end].fill(0);
            return Ok(data.scan == FILE_PAGES);
        }
        let end = (data.scan + 64).min(FILE_PAGES);
        if data.scan < end {
            let first_removed = (data.length as usize).div_ceil(PAGE);
            for logical in data.scan..end {
                if self.state.overlays[data.overlay as usize].pages[logical] != NONE {
                    if logical >= first_removed || logical == data.tail.logical as usize {
                        data.detached += 1;
                        if data.first_retired == NONE {
                            data.first_retired =
                                self.state.overlays[data.overlay as usize].pages[logical];
                        }
                    } else {
                        data.last_keep = self.state.overlays[data.overlay as usize].pages[logical];
                    }
                    // A COW tail replaces the same logical mapping. Prospective counts
                    // are paid by this scan and validated by the captured data generation.
                    if logical < first_removed {
                        data.mapped_count += 1;
                        data.shadow_boot_sectors += boot_sectors(logical, data.boot_visible_length);
                    }
                }
            }
            data.scan = end;
        }
        Ok(data.scan == FILE_PAGES)
    }

    pub(crate) fn commit_data_truncate(
        &mut self,
        data: &mut DataTruncate,
        now: proto_fs::Timestamp,
    ) -> Result<(), u32> {
        if data.committed {
            return Ok(());
        }
        if data.canceled
            || data.scan != FILE_PAGES
            || (data.tail.physical != NONE && !data.tail.ready)
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        self.io_generation(data.token, data.generation)?;
        self.io_preflight(data.token)?;
        if data.length == 0 {
            self.truncate_zero(data.token, now)?;
            self.state.nodes[data.token.slot as usize].mode &= !0o6000;
            data.committed = true;
            return Ok(());
        }
        if data.length < data.old_length && data.overlay != NONE {
            if data.detached != 0 && self.state.retired_len == PAGES {
                return Err(NO_SPACE);
            }
            let first_removed = (data.length as usize).div_ceil(PAGE);
            let overlay = &mut self.state.overlays[data.overlay as usize];
            let retired = data.first_retired;
            let mut final_last = data.last_keep;
            overlay.pages[first_removed..].fill(NONE);
            if data.tail.physical != NONE {
                let tail = data.tail.physical;
                overlay.pages[data.tail.logical as usize] = tail;
                self.state.page_logical[tail as usize] = data.tail.logical;
                self.state.page_next[tail as usize] = NONE;
                if data.last_keep == NONE {
                    overlay.head = tail;
                } else {
                    self.state.page_next[data.last_keep as usize] = tail;
                }
                final_last = tail;
                data.tail = TempPage::EMPTY;
            } else if data.last_keep == NONE {
                overlay.head = NONE;
            } else {
                self.state.page_next[data.last_keep as usize] = NONE;
            }
            if final_last == NONE {
                overlay.group_tail.fill(NONE);
            } else {
                let group = self.state.page_logical[final_last as usize] as usize / 64;
                overlay.group_tail[group] = final_last;
                overlay.group_tail[group + 1..].fill(NONE);
            }
            overlay.mapped_count = data.mapped_count;
            overlay.shadow_boot_sectors = data.shadow_boot_sectors;
            if retired != NONE {
                let tail = (self.state.retired_head + self.state.retired_len) % PAGES;
                self.state.retired[tail] = RetiredPages {
                    head: retired,
                    root: data.root,
                };
                self.state.retired_len += 1;
            }
        }
        let node = &mut self.state.nodes[data.token.slot as usize];
        node.length = data.length;
        node.boot_visible_length = data.boot_visible_length;
        node.data_generation += 1;
        node.times[1] = now;
        node.times[2] = now;
        node.mode &= !0o6000;
        self.state.epoch += 1;
        data.committed = true;
        Ok(())
    }

    pub(crate) fn cancel_data_truncate(&mut self, data: &mut DataTruncate) -> Result<bool, u32> {
        data.canceled = true;
        if data.tail.physical != NONE {
            self.io_free_page(data.root, &mut data.tail);
            return Ok(false);
        }
        Ok(true)
    }
}
impl<'a> Storage<'a> {
    pub fn new(
        state: &'a mut State,
        data: &'a mut [u8],
        tree: Option<Tree<'a>>,
        now: proto_fs::Timestamp,
    ) -> Self {
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
                boot_visible_length: length,
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
                        boot_visible_length: tree.data(n).len() as u64,
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
        // Canonical hard-link aliases occupy one initialized Node. Empty original
        // slots add no inode capacity. Boot capacity remains fixed after startup.
        for node in &out.state.nodes[..ORIGINALS] {
            if node.kind != 0 {
                out.state.boot_files += 1;
                out.state.boot_blocks += node.boot_visible_length.div_ceil(PAGE as u64);
            }
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
    /// Content changes require an inode with no pending or active executable pin.
    pub(crate) fn content_guard(&self, token: Token) -> Result<(), u32> {
        if self.node(token)?.pins[Pin::Image.index()] != 0 {
            return Err(proto_fs::TEXT_BUSY);
        }
        Ok(())
    }
    pub(crate) fn exec_guard(&self, token: Token) -> Result<(), u32> {
        if self.node(token)?.writers != 0 {
            return Err(proto_fs::TEXT_BUSY);
        }
        Ok(())
    }
    pub(crate) fn acquire_writer(&mut self, token: Token) -> Result<(), u32> {
        self.content_guard(token)?;
        let node = self.node_mut(token)?;
        node.writers = node.writers.checked_add(1).ok_or(NO_SPACE)?;
        Ok(())
    }
    pub(crate) fn release_writer(&mut self, token: Token) {
        let node = self.node_mut(token).expect("retained writable inode");
        node.writers = node.writers.checked_sub(1).expect("owned writer");
    }
    pub fn pin(&mut self, token: Token, kind: Pin) -> Result<(), u32> {
        if kind == Pin::Image {
            self.exec_guard(token)?;
        }
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
    fn next_directory_cookie(&mut self) -> Result<u64, u32> {
        let cookie = self.state.next_cookie;
        if cookie >= i64::MAX as u64 {
            return Err(NO_SPACE);
        }
        self.state.next_cookie = cookie + 1;
        Ok(cookie)
    }
    /// Stable positions belong to naming lifetimes and survive physical-row reuse.
    pub(crate) fn directory_entry(
        &self,
        parent: Token,
        index: usize,
    ) -> Option<(u64, &[u8], Token)> {
        let (name, token) = self.entry(parent, index)?;
        let cookie = if index < self.state.original_len {
            3 + index as u64
        } else {
            self.state.dentries[index - self.state.original_len].cookie
        };
        Some((cookie, name, token))
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
        self.reserve_with_charge(root, parent, name, attributes, None)
    }
    /// Move an admitted job's charge into its reservation, without allocating another.
    /// The caller must validate the exact job, owner, and authority before this transfer.
    pub fn reserve_paid(
        &mut self,
        root: Root,
        parent: Token,
        name: &[u8],
        attributes: (u32, u32, u32, u32),
        charge: &mut u16,
    ) -> Result<Reservation, u32> {
        let paid = *charge;
        if !self
            .state
            .accounts
            .get(paid as usize)
            .and_then(Option::as_ref)
            .is_some_and(|a| a.key == root && a.pending != 0)
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let reservation = self.reserve_with_charge(root, parent, name, attributes, Some(paid))?;
        *charge = NONE;
        Ok(reservation)
    }
    fn reserve_with_charge(
        &mut self,
        root: Root,
        parent: Token,
        name: &[u8],
        attributes: (u32, u32, u32, u32),
        paid: Option<u16>,
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
        if paid.is_none()
            && (self.state.preparation_used as usize == PREPARATIONS
                || self.state.accounts[a].unwrap().pending == PREPARATION_SHARE)
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
        let cookie = self.next_directory_cookie()?;
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
            cookie,
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
        if paid.is_none() {
            self.state.accounts[a].as_mut().unwrap().pending += 1;
            self.state.preparation_used += 1;
        }
        Ok(reservation)
    }
    /// Only a live, exact unpublished reservation grants a creation's initial access.
    pub fn reserved_token(&self, r: Reservation, root: Root) -> Result<Token, u32> {
        if self.state.pending.get(r.place as usize).copied().flatten() != Some(r)
            || !self
                .state
                .accounts
                .get(r.root as usize)
                .and_then(Option::as_ref)
                .is_some_and(|account| account.key == root)
        {
            return Err(proto_fs::PERMISSION);
        }
        if r.epoch != self.state.epoch {
            return Err(proto_fs::STALE_PROOF);
        }
        Ok(r.token)
    }
    /// Match the reserved namespace edge before the admitted creation is published.
    pub fn reserved_edge(
        &self,
        r: Reservation,
        root: Root,
        parent: Token,
        leaf: &[u8],
    ) -> Result<(), u32> {
        self.reserved_token(r, root)?;
        let d = &self.state.dentries[r.dentry as usize];
        if !d.reserved
            || d.node != r.token
            || d.parent != parent
            || &d.name[..d.len as usize] != leaf
        {
            return Err(proto_fs::STALE_PROOF);
        }
        Ok(())
    }
    pub fn commit(&mut self, reservation: Reservation) -> Result<Token, u32> {
        let token = self.commit_keep_charge(reservation)?;
        self.release_preparation(reservation.root);
        Ok(token)
    }
    /// Publish once, retaining the paid charge for the completed operation journal.
    pub fn commit_keep_charge(&mut self, reservation: Reservation) -> Result<Token, u32> {
        if self
            .state
            .pending
            .get(reservation.place as usize)
            .copied()
            .flatten()
            != Some(reservation)
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let d = self.state.dentries[reservation.dentry as usize];
        if !d.reserved || d.node != reservation.token || reservation.epoch != self.state.epoch {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let next = self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        let directory = self.node(reservation.token)?.kind == crate::DIR;
        let parent = self.node(d.parent)?;
        if parent.links == 0 {
            return Err(NO_ENTRY);
        }
        let parent_links = if directory {
            parent
                .links
                .checked_add(1)
                .ok_or(namespace::TOO_MANY_LINKS)?
        } else {
            parent.links
        };
        self.state.dentries[reservation.dentry as usize].reserved = false;
        let n = &mut self.state.nodes[reservation.token.slot as usize];
        n.pins[Pin::Pending.index()] -= 1;
        n.links = if n.kind == crate::DIR { 2 } else { 1 };
        if n.kind == crate::DIR {
            self.state.nodes[d.parent.slot as usize].links = parent_links;
        }
        self.unpin(d.parent, Pin::Pending)?;
        self.state.epoch = next;
        self.state.pending[reservation.place as usize] = None;
        Ok(reservation.token)
    }
    pub fn cancel(&mut self, r: Reservation) -> Result<(), u32> {
        self.cancel_keep_charge(r)?;
        self.release_preparation(r.root);
        Ok(())
    }
    /// Roll back an unpublished reserve while keeping the exact job's paid admission.
    pub fn cancel_keep_charge(&mut self, r: Reservation) -> Result<(), u32> {
        if self.state.pending.get(r.place as usize).copied().flatten() != Some(r) {
            return Err(NO_ENTRY);
        }
        let d = self.state.dentries[r.dentry as usize];
        if !d.reserved || d.node != r.token {
            return Err(NO_ENTRY);
        }
        self.drop_dentry(r.dentry as usize);
        self.unpin(d.parent, Pin::Pending)?;
        self.unpin(r.token, Pin::Pending)?;
        self.state.pending[r.place as usize] = None;
        Ok(())
    }

    #[cfg(feature = "auth-probe")]
    pub fn preparations_for_root(&self, root: Root) -> u16 {
        self.state
            .accounts
            .iter()
            .flatten()
            .find(|a| a.key == root)
            .map_or(0, |a| a.pending)
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
    /// Trusted model adapter using the common paid namespace journal.
    pub fn unlink(&mut self, parent: Token, name: &[u8], root: Root) -> Result<Token, u32> {
        namespace::model_unlink(self, parent, name, root)
    }
    /// Trusted token-source model adapter using the common paid namespace journal.
    pub fn link(
        &mut self,
        root: Root,
        parent: Token,
        name: &[u8],
        token: Token,
    ) -> Result<(), u32> {
        namespace::model_link(self, root, parent, name, token)
    }

    pub fn boot_bytes(&self, token: Token) -> &'a [u8] {
        let n = &self.state.nodes[token.slot as usize];
        let bytes = if token.slot == 3 {
            crate::MOTD
        } else if n.boot != NONE && n.kind == crate::REG {
            self.tree.as_ref().unwrap().data(n.boot)
        } else {
            &[]
        };
        &bytes[..bytes.len().min(n.boot_visible_length as usize)]
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
        self.content_guard(token)?;
        let data_generation = self
            .node(token)?
            .data_generation
            .checked_add(1)
            .ok_or(NO_SPACE)?;
        let permission_epoch = if self.node(token)?.mode & 0o6000 != 0 {
            Some(self.state.epoch.checked_add(1).ok_or(NO_SPACE)?)
        } else {
            None
        };
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
            let overlay = &mut self.state.overlays[i];
            overlay.mapped_count += 1;
            overlay.shadow_boot_sectors +=
                boot_sectors(p, self.state.nodes[token.slot as usize].boot_visible_length);
            let predecessor = overlay.predecessor(p);
            self.link_page(i, p, page, predecessor);
            self.state.accounts[a].as_mut().unwrap().usage.pages += 1;
        }
        for (n, b) in bytes.iter().enumerate() {
            let at = offset + n;
            let p = self.state.overlays[i].pages[at / PAGE];
            self.data[p as usize * PAGE + at % PAGE] = *b;
        }
        self.state.nodes[token.slot as usize].length =
            self.state.nodes[token.slot as usize].length.max(end as u64);
        self.state.nodes[token.slot as usize].data_generation = data_generation;
        if let Some(epoch) = permission_epoch {
            self.state.nodes[token.slot as usize].mode &= !0o6000;
            self.state.epoch = epoch;
        }
        Ok(bytes.len())
    }
    /// All fallible preflight precedes the single detachment of a live file's data.
    /// The admitted caller owns the Open/Truncate journal and exact authority proof.
    pub fn truncate_zero(&mut self, token: Token, now: proto_fs::Timestamp) -> Result<(), u32> {
        let node = self.node(token)?;
        if node.kind != crate::REG {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        self.content_guard(token)?;
        let data_generation = node.data_generation.checked_add(1).ok_or(NO_SPACE)?;
        let epoch = self.state.epoch.checked_add(1).ok_or(NO_SPACE)?;
        let overlay = node.overlay;
        let chain = if overlay == NONE {
            RetiredPages::EMPTY
        } else {
            let held = &self.state.overlays[overlay as usize];
            RetiredPages {
                head: held.head,
                root: held.root,
            }
        };
        // Every existing nonempty chain owns a page. A nonempty live chain therefore
        // has a guaranteed credit before any of its pages can enter the retired FIFO.
        if chain.head != NONE && self.state.retired_len == PAGES {
            return Err(NO_SPACE);
        }
        if chain.head != NONE {
            let tail = (self.state.retired_head + self.state.retired_len) % PAGES;
            self.state.retired[tail] = chain;
            self.state.retired_len += 1;
        }
        if overlay != NONE {
            self.state.overlays[overlay as usize].pages.fill(NONE);
            self.state.overlays[overlay as usize].group_tail.fill(NONE);
            self.state.overlays[overlay as usize].head = NONE;
            self.state.overlays[overlay as usize].mapped_count = 0;
            self.state.overlays[overlay as usize].shadow_boot_sectors = 0;
        }
        let node = &mut self.state.nodes[token.slot as usize];
        node.length = 0;
        node.boot_visible_length = 0;
        node.data_generation = data_generation;
        node.times[1] = now;
        node.times[2] = now;
        self.state.epoch = epoch;
        Ok(())
    }
    /// One page or inode slot per call, alternating two independently paid queues.
    pub fn reclaim_step(&mut self) -> bool {
        if self.state.retired_len != 0 && (self.state.reclaim_len == 0 || self.state.retired_turn) {
            self.state.retired_turn = false;
            self.reclaim_retired_page();
            return true;
        }
        if self.reclaim_inode_step() {
            self.state.retired_turn = true;
            return true;
        }
        false
    }
    fn reclaim_retired_page(&mut self) {
        let entry = &mut self.state.retired[self.state.retired_head];
        let page = entry.head;
        let root = entry.root;
        entry.head = self.state.page_next[page as usize];
        if entry.head == NONE {
            *entry = RetiredPages::EMPTY;
            self.state.retired_head = (self.state.retired_head + 1) % PAGES;
            self.state.retired_len -= 1;
        }
        self.state.page_free[self.state.page_len] = page;
        self.state.page_len += 1;
        self.uncharge(root as usize, |u| &mut u.pages);
    }
    /// The inode queue keeps its original guaranteed credit for every live overlay.
    fn reclaim_inode_step(&mut self) -> bool {
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
            if self.state.overlays[i].group_tail[p / 64] == page {
                self.state.overlays[i].group_tail[p / 64] = NONE;
            }
            self.state.overlays[i].mapped_count -= 1;
            self.state.overlays[i].shadow_boot_sectors -= boot_sectors(
                p,
                self.state.nodes[overlay.node as usize].boot_visible_length,
            );
            self.state.page_free[self.state.page_len] = page;
            self.state.page_len += 1;
            self.uncharge(overlay.root as usize, |u| &mut u.pages);
        } else {
            let node = self.state.nodes[overlay.node as usize];
            self.state.nodes[overlay.node as usize] = Node {
                generation: node.generation,
                ..Node::EMPTY
            };
            self.state.overlays[i] = Overlay::EMPTY;
            self.state.inode_free[self.state.inode_len] = i as u16;
            self.state.inode_len += 1;
            self.uncharge(overlay.root as usize, |u| &mut u.inodes);
            self.state.reclaim_head = (self.state.reclaim_head + 1) % INODES;
            self.state.reclaim_len -= 1;
            if node.orphan_parent {
                self.unpin(node.parent, Pin::Parent)
                    .expect("exact orphan parent pin");
            }
        }
        true
    }
    /// Read-only capacity observation never allocates an expenditure account.
    pub fn filesystem_information(&self, root: Root) -> FileSystemInfo {
        let usage = self.usage(root);
        let free_blocks = self.state.page_len as u64;
        let free_files = self.state.inode_len as u64;
        FileSystemInfo {
            block_size: PAGE as u64,
            fragment_size: PAGE as u64,
            blocks: self.state.boot_blocks + PAGES as u64,
            free_blocks,
            available_blocks: free_blocks.min(u64::from(PAGE_SHARE.saturating_sub(usage.pages))),
            files: self.state.boot_files + INODES as u64,
            free_files,
            available_files: free_files.min(u64::from(INODE_SHARE.saturating_sub(usage.inodes))),
            filesystem_id: 1,
            flags: 0,
            name_max: 255,
        }
    }

    /// Live backing in 512-byte units; sparse holes and retired pages are excluded.
    pub fn blocks(&self, token: Token) -> u64 {
        let node = &self.state.nodes[token.slot as usize];
        let boot = node.boot_visible_length.div_ceil(512);
        if node.overlay == NONE {
            return boot;
        }
        let overlay = &self.state.overlays[node.overlay as usize];
        boot - u64::from(overlay.shadow_boot_sectors) + 8 * u64::from(overlay.mapped_count)
    }
}

impl Storage<'_> {
    pub(crate) fn cwd_result_preflight(&self, root: u16, count: usize) -> Result<(), u32> {
        let a = self.state.accounts[root as usize]
            .as_ref()
            .expect("paid result root");
        if count > crate::cwd::getcwd::MAX_PAGES
            || count > self.state.page_len
            || count > usize::from(PAGE_SHARE - a.usage.pages)
        {
            return Err(crate::cwd::getcwd::NO_MEMORY);
        }
        Ok(())
    }
    pub(crate) fn cwd_result_allocate(
        &mut self,
        pages: &mut crate::cwd::getcwd::ResultPages,
    ) -> Result<(), u32> {
        self.cwd_result_preflight(pages.root, 1)?;
        if pages.count as usize == crate::cwd::getcwd::MAX_PAGES {
            return Err(crate::cwd::getcwd::NO_MEMORY);
        }
        let page = self.io_take_page(pages.root, 0);
        self.data[page.physical as usize * PAGE..(page.physical as usize + 1) * PAGE].fill(0);
        self.state.page_next[page.physical as usize] = pages.head;
        pages.head = page.physical;
        pages.first = PAGE as u16;
        pages.count += 1;
        Ok(())
    }
    pub(crate) fn cwd_result_prepend(
        &mut self,
        pages: &mut crate::cwd::getcwd::ResultPages,
        bytes: &[u8],
    ) {
        assert!(bytes.len() <= pages.first as usize);
        pages.first -= bytes.len() as u16;
        let at = pages.head as usize * PAGE + pages.first as usize;
        self.data[at..at + bytes.len()].copy_from_slice(bytes);
        pages.length += bytes.len() as u32;
    }
    pub(crate) fn cwd_result_next(&self, page: u16) -> u16 {
        self.state.page_next[page as usize]
    }
    pub(crate) fn cwd_result_read(&self, page: u16, offset: usize, out: &mut [u8]) {
        let first = (PAGE - offset).min(out.len());
        let at = page as usize * PAGE + offset;
        out[..first].copy_from_slice(&self.data[at..at + first]);
        if first < out.len() {
            let remaining = out.len() - first;
            let next = self.state.page_next[page as usize] as usize * PAGE;
            out[first..].copy_from_slice(&self.data[next..next + remaining]);
        }
    }
    pub(crate) fn cwd_result_free(&mut self, pages: &mut crate::cwd::getcwd::ResultPages) {
        let page = pages.head;
        pages.head = self.state.page_next[page as usize];
        self.state.page_next[page as usize] = NONE;
        self.state.page_free[self.state.page_len] = page;
        self.state.page_len += 1;
        self.uncharge(pages.root as usize, |u| &mut u.pages);
        pages.count -= 1;
        if pages.head == NONE {
            pages.first = 0;
            pages.length = 0;
        }
    }
}

#[cfg(test)]
mod directory_cookie_tests {
    use super::*;
    const EXPENSE: Root = Root {
        id: 11,
        generation: 7,
    };
    #[test]
    fn terminal_cookie_preserves_existing_dynamic_and_same_inode_rename() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let r = ram
            .storage
            .reserve(EXPENSE, ROOT, b"a", (crate::REG, 0o644, 0, 0))
            .unwrap();
        let token = ram.storage.commit(r).unwrap();
        ram.storage.link(EXPENSE, ROOT, b"b", token).unwrap();
        let cookie = ram
            .storage
            .state
            .dentries
            .iter()
            .find(|d| d.len != 0 && &d.name[..d.len as usize] == b"a")
            .unwrap()
            .cookie;
        ram.storage.state.next_cookie = i64::MAX as u64;
        let epoch = ram.storage.state.epoch;
        let times = ram.storage.node(token).unwrap().times;
        crate::directory_tests::rename(&mut ram, b"/a", b"/b");
        assert_eq!(ram.storage.state.epoch, epoch);
        assert_eq!(ram.storage.node(token).unwrap().times, times);
        crate::directory_tests::rename(&mut ram, b"/a", b"/c");
        assert_eq!(ram.storage.lookup(ROOT, b"c"), Ok(token));
        let current = ram
            .storage
            .state
            .dentries
            .iter()
            .find(|d| d.len != 0 && &d.name[..d.len as usize] == b"c")
            .unwrap()
            .cookie;
        assert_eq!(current, cookie);
        assert_eq!(ram.storage.state.next_cookie, i64::MAX as u64);
        assert_eq!(ram.storage.link(EXPENSE, ROOT, b"d", token), Err(NO_SPACE));
        assert_eq!(ram.storage.node(token).unwrap().links, 2);
        ram.storage.unlink(ROOT, b"c", EXPENSE).unwrap();
        ram.storage.unlink(ROOT, b"b", EXPENSE).unwrap();
        while ram.storage.reclaim_step() {}
        assert_eq!(ram.storage.usage(EXPENSE), Usage::EMPTY);
    }
    #[test]
    fn cookie_max_last_issued_reservation_cleanup_needs_no_new_cookie() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        ram.storage.state.next_cookie = i64::MAX as u64 - 1;
        let reserved = ram
            .storage
            .reserve(EXPENSE, ROOT, b"last", (crate::REG, 0o644, 0, 0))
            .unwrap();
        assert_eq!(
            ram.storage.state.dentries[reserved.dentry as usize].cookie,
            i64::MAX as u64 - 1
        );
        assert_eq!(ram.storage.state.next_cookie, i64::MAX as u64);
        let before = ram.storage.available();
        let usage = ram.storage.usage(EXPENSE);
        let pins = ram.storage.node(ROOT).unwrap().pins;
        let epoch = ram.storage.state.epoch;
        assert_eq!(
            ram.storage
                .reserve(EXPENSE, ROOT, b"over", (crate::REG, 0o644, 0, 0)),
            Err(NO_SPACE)
        );
        assert_eq!(ram.storage.available(), before);
        assert_eq!(ram.storage.usage(EXPENSE), usage);
        assert_eq!(ram.storage.node(ROOT).unwrap().pins, pins);
        assert_eq!(ram.storage.state.epoch, epoch);
        ram.storage.cancel(reserved).unwrap();
        while ram.storage.reclaim_step() {}
        assert_eq!(ram.storage.usage(EXPENSE), Usage::EMPTY);
        assert_eq!(ram.storage.state.next_cookie, i64::MAX as u64);
    }
}

#[cfg(test)]
mod page_tests {
    extern crate std;
    use super::*;

    #[test]
    fn retirement_records_and_node_growth_have_fixed_accounted_layout() {
        assert_eq!(core::mem::size_of::<RetiredPages>(), 4);
        std::println!(
            "T4 blocks layout: Overlay={} DataTruncate={} State={}",
            core::mem::size_of::<Overlay>(),
            core::mem::size_of::<DataTruncate>(),
            core::mem::size_of::<State>()
        );
        std::println!(
            "T3 layout: Node {} bytes, State {} bytes, retirement table {} bytes, nodes {}",
            core::mem::size_of::<Node>(),
            core::mem::size_of::<State>(),
            core::mem::size_of::<[RetiredPages; PAGES]>(),
            NODES
        );
    }

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

    fn blocks_oracle(storage: &Storage<'_>, token: Token) -> u64 {
        let node = storage.node(token).unwrap();
        let mut result = node.boot_visible_length.div_ceil(512);
        if node.overlay != NONE {
            for (logical, &physical) in storage.state.overlays[node.overlay as usize]
                .pages
                .iter()
                .enumerate()
            {
                if physical != NONE {
                    result += 8;
                    result -= u64::from(boot_sectors(logical, node.boot_visible_length));
                }
            }
        }
        result
    }
    fn count_parity(storage: &Storage<'_>, token: Token) {
        assert_eq!(storage.blocks(token), blocks_oracle(storage, token));
        let node = storage.node(token).unwrap();
        if node.overlay != NONE {
            let overlay = &storage.state.overlays[node.overlay as usize];
            let mapped = overlay.pages.iter().filter(|&&p| p != NONE).count();
            let shadow: u16 = overlay
                .pages
                .iter()
                .enumerate()
                .filter(|(_, p)| **p != NONE)
                .map(|(logical, _)| boot_sectors(logical, node.boot_visible_length))
                .sum();
            assert_eq!(usize::from(overlay.mapped_count), mapped);
            assert_eq!(overlay.shadow_boot_sectors, shadow);
        }
    }
    fn finish_truncate(storage: &mut Storage<'_>, token: Token, length: u64) {
        let mut data = storage.prepare_data_truncate(token, length).unwrap();
        while !storage.step_data_truncate(&mut data).unwrap() {}
        storage
            .commit_data_truncate(&mut data, proto_fs::Timestamp::ZERO)
            .unwrap();
        while !storage.cancel_data_truncate(&mut data).unwrap() {}
        count_parity(storage, token);
    }

    #[test]
    fn boot_union_counters_follow_paid_publication_shrink_extension_and_gc() {
        use bootimg::rootfs::{Entry, REGULAR};
        let table = bootimg::rootfs::write::rootfs(
            &[
                Entry {
                    path: "/boot",
                    mode: REGULAR | 0o644,
                    uid: 1,
                    gid: 2,
                    file: 1,
                },
                Entry {
                    path: "/alias",
                    mode: REGULAR | 0o644,
                    uid: 1,
                    gid: 2,
                    file: 1,
                },
            ],
            3,
        )
        .unwrap();
        let payload = std::vec![b'b'; PAGE * 2 + 1];
        let image =
            bootimg::write::image(&[("init", b"init"), ("boot", &payload), ("rootfs", &table)])
                .unwrap();
        let mut index = crate::tree::Index::new();
        let tree = crate::tree::load(&image, &mut index).unwrap();
        let mut ram = crate::Ram::with_tree(proto_fs::Timestamp::ZERO, tree);
        let storage = &mut ram.storage;
        let token = storage.resolve(b"/boot").unwrap();
        assert_eq!(token, storage.resolve(b"/alias").unwrap());
        assert_eq!(storage.blocks(token), 17);
        let base = storage.filesystem_information(FIRST);
        assert_eq!(base.files, INODES as u64 + 6);
        assert_eq!(base.blocks, PAGES as u64 + 4);
        assert!(storage.state.accounts.iter().all(Option::is_none));
        storage.write(token, FIRST, PAGE * 4, b"sparse").unwrap();
        count_parity(storage, token);
        assert_eq!(storage.blocks(token), 25);
        let mut data = storage
            .prepare_data_write(token, FIRST, PAGE as u64 - 1, 2)
            .unwrap();
        while !storage.step_data_write(&mut data).unwrap() {}
        assert_eq!(storage.blocks(token), 25);
        let paid = storage.filesystem_information(FIRST);
        assert_eq!(paid.free_blocks, base.free_blocks - 3);
        storage
            .commit_data_write(&mut data, b"xy", proto_fs::Timestamp::ZERO)
            .unwrap();
        assert_eq!(storage.blocks(token), 25);
        count_parity(storage, token);
        while !storage.cancel_data_write(&mut data).unwrap() {}
        storage.write(token, FIRST, PAGE + 10, b"replace").unwrap();
        count_parity(storage, token);
        assert_eq!(storage.blocks(token), 25);
        finish_truncate(storage, token, PAGE as u64 + 513);
        assert_eq!(storage.blocks(token), 16);
        let retired = storage.filesystem_information(FIRST);
        assert_eq!(retired.free_blocks, base.free_blocks - 4);
        drain(storage);
        assert_eq!(
            storage.filesystem_information(FIRST).free_blocks,
            base.free_blocks - 2
        );
        count_parity(storage, token);
        finish_truncate(storage, token, (PAGE * 6) as u64);
        assert_eq!(storage.blocks(token), 16);
        assert_eq!(
            storage.node(token).unwrap().boot_visible_length,
            PAGE as u64 + 513
        );
        finish_truncate(storage, token, 0);
        assert_eq!(storage.blocks(token), 0);
        assert_eq!(
            storage.filesystem_information(FIRST).free_blocks,
            base.free_blocks - 2
        );
        drain(storage);
        assert_eq!(
            storage.filesystem_information(FIRST).free_blocks,
            base.free_blocks
        );
        finish_truncate(storage, token, PAGE as u64);
        assert_eq!(storage.blocks(token), 0);
    }

    #[test]
    fn full_mapping_scan_counters_and_cancel_keep_the_exact_original_map() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let storage = &mut ram.storage;
        let token = create(storage, b"full");
        for logical in 0..FILE_PAGES {
            storage.write(token, FIRST, logical * PAGE, b"x").unwrap();
        }
        count_parity(storage, token);
        assert_eq!(storage.blocks(token), 8 * FILE_PAGES as u64);
        let before = storage.filesystem_information(FIRST);
        let mut canceled = storage
            .prepare_data_truncate(token, PAGE as u64 + 1)
            .unwrap();
        while !storage.step_data_truncate(&mut canceled).unwrap() {}
        assert_eq!(canceled.mapped_count, 2);
        assert_eq!(canceled.shadow_boot_sectors, 0);
        assert_eq!(storage.blocks(token), 8 * FILE_PAGES as u64);
        while !storage.cancel_data_truncate(&mut canceled).unwrap() {}
        assert_eq!(storage.filesystem_information(FIRST), before);
        count_parity(storage, token);
        finish_truncate(storage, token, PAGE as u64 + 1);
        assert_eq!(storage.blocks(token), 16);
        drain(storage);
        assert_eq!(
            storage.filesystem_information(FIRST).free_blocks,
            PAGES as u64 - 2
        );
    }

    #[test]
    fn filesystem_free_and_root_availability_follow_reservation_cancel_and_gc() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let storage = &mut ram.storage;
        let base = storage.filesystem_information(FIRST);
        assert_eq!(
            (base.files, base.blocks),
            (INODES as u64 + 5, PAGES as u64 + 1)
        );
        assert_eq!(
            (base.available_files, base.available_blocks),
            (u64::from(INODE_SHARE), u64::from(PAGE_SHARE))
        );
        let reserve = storage
            .reserve(FIRST, ROOT, b"hidden", (crate::REG, 0o644, 1, 2))
            .unwrap();
        storage.write(reserve.token, FIRST, 0, b"hidden").unwrap();
        let paid = storage.filesystem_information(FIRST);
        assert_eq!(paid.free_files, base.free_files - 1);
        assert_eq!(paid.free_blocks, base.free_blocks - 1);
        assert_eq!(paid.available_files, base.available_files - 1);
        storage.cancel(reserve).unwrap();
        assert_eq!(storage.filesystem_information(FIRST), paid);
        assert!(storage.reclaim_step());
        assert_eq!(
            storage.filesystem_information(FIRST).free_blocks,
            base.free_blocks
        );
        assert_eq!(
            storage.filesystem_information(FIRST).free_files,
            base.free_files - 1
        );
        assert!(storage.reclaim_step());
        assert_eq!(storage.filesystem_information(FIRST), base);
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
        let mut ram = crate::Ram::with_tree(proto_fs::Timestamp::legacy_ns(0), tree);
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
        let mut ram = crate::Ram::new(proto_fs::Timestamp::legacy_ns(0));
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
            group_tail: [123; FILE_PAGES / 64],
            head: 123,
            mapped_count: 55,
            shadow_boot_sectors: 77,
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
        assert_eq!(overlay.group_tail, [NONE; FILE_PAGES / 64]);
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
        let mut ram = crate::Ram::with_tree(proto_fs::Timestamp::legacy_ns(0), tree);
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

#[cfg(test)]
mod sorted_chain_tests {
    use super::*;
    const ACCOUNT: Root = Root {
        id: 88,
        generation: 7,
    };
    fn file(storage: &mut Storage<'_>, name: &[u8]) -> Token {
        let reservation = storage
            .reserve(ACCOUNT, ROOT, name, (crate::REG, 0o600, 0, 0))
            .unwrap();
        storage.commit(reservation).unwrap()
    }
    fn check(storage: &Storage<'_>, token: Token) {
        let overlay = &storage.state.overlays[storage.node(token).unwrap().overlay as usize];
        let mut physical = overlay.head;
        for (logical, &mapped) in overlay.pages.iter().enumerate() {
            if mapped == NONE {
                continue;
            }
            assert_eq!(physical, mapped, "logical {logical}");
            assert_eq!(
                storage.state.page_logical[physical as usize] as usize,
                logical
            );
            physical = storage.state.page_next[physical as usize];
        }
        assert_eq!(physical, NONE);
        for group in 0..FILE_PAGES / 64 {
            let expected = overlay.pages[group * 64..(group + 1) * 64]
                .iter()
                .rfind(|&&page| page != NONE)
                .copied()
                .unwrap_or(NONE);
            assert_eq!(overlay.group_tail[group], expected, "group {group}");
        }
    }
    fn paid_write(storage: &mut Storage<'_>, token: Token, logical: usize) {
        let mut write = storage
            .prepare_data_write(token, ACCOUNT, (logical * PAGE) as u64, 1)
            .unwrap();
        while !storage.step_data_write(&mut write).unwrap() {}
        storage
            .commit_data_write(&mut write, b"x", proto_fs::Timestamp::ZERO)
            .unwrap();
        assert!(storage.cancel_data_write(&mut write).unwrap());
    }
    fn truncate(storage: &mut Storage<'_>, token: Token, length: u64) {
        let mut truncate = storage.prepare_data_truncate(token, length).unwrap();
        while !storage.step_data_truncate(&mut truncate).unwrap() {}
        storage
            .commit_data_truncate(&mut truncate, proto_fs::Timestamp::ZERO)
            .unwrap();
        storage
            .commit_data_truncate(&mut truncate, proto_fs::Timestamp::ZERO)
            .unwrap();
        assert!(storage.cancel_data_truncate(&mut truncate).unwrap());
        check(storage, token);
    }
    #[test]
    fn sparse_reverse_and_permuted_insertions_keep_both_write_paths_sorted() {
        for paid in [false, true] {
            let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
            let storage = &mut ram.storage;
            let token = file(storage, b"insertion");
            for logical in [2047, 64, 63, 0, 1024, 128, 1, 1023] {
                if paid {
                    paid_write(storage, token, logical);
                } else {
                    storage.write(token, ACCOUNT, logical * PAGE, b"l").unwrap();
                }
                check(storage, token);
            }
            for i in 0..128 {
                let logical = (i * 73 + 119) % FILE_PAGES;
                if paid {
                    paid_write(storage, token, logical);
                } else {
                    storage.write(token, ACCOUNT, logical * PAGE, b"l").unwrap();
                }
                check(storage, token);
            }
            // A two-page paid insertion links the second new page after the first.
            let mut write = storage
                .prepare_data_write(token, ACCOUNT, (33 * PAGE - 1) as u64, 2)
                .unwrap();
            while !storage.step_data_write(&mut write).unwrap() {}
            storage
                .commit_data_write(&mut write, b"ab", proto_fs::Timestamp::ZERO)
                .unwrap();
            check(storage, token);
        }
    }
    #[test]
    fn full_mapping_tail_split_extend_gc_and_reuse_preserve_live_cache() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let storage = &mut ram.storage;
        let token = file(storage, b"full-chain");
        for logical in (0..FILE_PAGES).rev() {
            paid_write(storage, token, logical);
        }
        check(storage, token);
        truncate(storage, token, PAGE as u64 + 1);
        let retained = storage.usage(ACCOUNT).pages;
        assert_eq!(retained, FILE_PAGES as u16 + 1);
        for _ in 0..PAGES * 2 {
            storage.reclaim_step();
        }
        assert_eq!(storage.usage(ACCOUNT).pages, 2);
        check(storage, token);
        paid_write(storage, token, 63);
        paid_write(storage, token, 64);
        paid_write(storage, token, 2047);
        check(storage, token);
        truncate(storage, token, (65 * PAGE) as u64);
        truncate(storage, token, (64 * PAGE) as u64);
        truncate(storage, token, (63 * PAGE + 17) as u64);
        truncate(storage, token, 0);
        paid_write(storage, token, 2047);
        paid_write(storage, token, 0);
        check(storage, token);
    }
    #[test]
    fn absent_tail_cancel_and_generation_failure_leave_links_and_cache_unchanged() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let storage = &mut ram.storage;
        let token = file(storage, b"sparse-tail");
        for logical in [2047, 128, 64, 0] {
            paid_write(storage, token, logical);
        }
        let mut old = storage
            .prepare_data_truncate(token, (63 * PAGE + 17) as u64)
            .unwrap();
        while !storage.step_data_truncate(&mut old).unwrap() {}
        paid_write(storage, token, 63);
        assert_eq!(
            storage.commit_data_truncate(&mut old, proto_fs::Timestamp::ZERO),
            Err(proto_fs::STALE_PROOF)
        );
        while !storage.cancel_data_truncate(&mut old).unwrap() {}
        check(storage, token);
        let mut canceled = storage
            .prepare_data_truncate(token, (63 * PAGE + 17) as u64)
            .unwrap();
        while !storage.step_data_truncate(&mut canceled).unwrap() {}
        while !storage.cancel_data_truncate(&mut canceled).unwrap() {}
        check(storage, token);
        truncate(storage, token, (62 * PAGE + 17) as u64);
        assert_eq!(
            storage.state.overlays[storage.node(token).unwrap().overlay as usize].mapped_count,
            1
        );
    }
    #[test]
    fn inode_gc_clears_only_the_popped_group_tail_and_reinitializes_reused_overlay() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let storage = &mut ram.storage;
        let token = file(storage, b"inode-cache");
        for logical in [128, 64, 1, 0] {
            paid_write(storage, token, logical);
        }
        let slot = storage.node(token).unwrap().overlay as usize;
        storage.unlink(ROOT, b"inode-cache", ACCOUNT).unwrap();
        for _ in 0..4 {
            assert!(storage.reclaim_inode_step());
            let overlay = &storage.state.overlays[slot];
            for group in 0..FILE_PAGES / 64 {
                let expected = overlay.pages[group * 64..(group + 1) * 64]
                    .iter()
                    .rfind(|&&page| page != NONE)
                    .copied()
                    .unwrap_or(NONE);
                assert_eq!(overlay.group_tail[group], expected);
            }
        }
        assert!(storage.reclaim_inode_step());
        assert_eq!(
            storage.state.overlays[slot].group_tail,
            [NONE; FILE_PAGES / 64]
        );
        let replacement = file(storage, b"replacement-cache");
        paid_write(storage, replacement, 2047);
        paid_write(storage, replacement, 0);
        check(storage, replacement);
    }
}

#[cfg(test)]
mod root_sorted_review {
    use super::*;
    const ACCOUNT: Root = Root {
        id: 89,
        generation: 9,
    };
    fn file(storage: &mut Storage<'_>) -> Token {
        let reservation = storage
            .reserve(ACCOUNT, ROOT, b"root-sorted", (crate::REG, 0o600, 0, 0))
            .unwrap();
        storage.commit(reservation).unwrap()
    }
    fn chain(storage: &Storage<'_>, token: Token) {
        let overlay = &storage.state.overlays[storage.node(token).unwrap().overlay as usize];
        let mut physical = overlay.head;
        for (logical, &mapped) in overlay.pages.iter().enumerate() {
            if mapped == NONE {
                continue;
            }
            assert_eq!(physical, mapped);
            assert_eq!(
                storage.state.page_logical[physical as usize] as usize,
                logical
            );
            physical = storage.state.page_next[physical as usize];
        }
        assert_eq!(physical, NONE);
        for group in 0..32 {
            assert_eq!(
                overlay.group_tail[group],
                overlay.pages[group * 64..(group + 1) * 64]
                    .iter()
                    .rev()
                    .find(|&&p| p != NONE)
                    .copied()
                    .unwrap_or(NONE)
            );
        }
    }
    #[test]
    fn captured_predecessor_is_rejected_after_an_intervening_legacy_insert() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let storage = &mut ram.storage;
        let token = file(storage);
        storage.write(token, ACCOUNT, 0, b"a").unwrap();
        let mut old = storage
            .prepare_data_write(token, ACCOUNT, (2047 * PAGE) as u64, 1)
            .unwrap();
        while !storage.step_data_write(&mut old).unwrap() {}
        storage.write(token, ACCOUNT, 2046 * PAGE, b"b").unwrap();
        let slot = storage.node(token).unwrap().overlay as usize;
        let maps = storage.state.overlays[slot].pages;
        let tails = storage.state.overlays[slot].group_tail;
        assert_eq!(
            storage.commit_data_write(&mut old, b"x", proto_fs::Timestamp::ZERO),
            Err(proto_fs::STALE_PROOF)
        );
        assert_eq!(storage.state.overlays[slot].pages, maps);
        assert_eq!(storage.state.overlays[slot].group_tail, tails);
        while !storage.cancel_data_write(&mut old).unwrap() {}
        assert_eq!(storage.usage(ACCOUNT).pages, 2);
        chain(storage, token);
    }
    #[test]
    fn boundary_insertions_with_one_existing_page_keep_exact_bytes_and_chain() {
        for existing in [62, 63, 64, 65] {
            let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
            let storage = &mut ram.storage;
            let token = file(storage);
            for logical in [2047, existing, 0] {
                storage.write(token, ACCOUNT, logical * PAGE, b"s").unwrap();
            }
            let offset = 64 * PAGE - 1;
            let mut write = storage
                .prepare_data_write(token, ACCOUNT, offset as u64, 2)
                .unwrap();
            while !storage.step_data_write(&mut write).unwrap() {}
            storage
                .commit_data_write(&mut write, b"XY", proto_fs::Timestamp::ZERO)
                .unwrap();
            let count = storage.usage(ACCOUNT).pages;
            storage
                .commit_data_write(&mut write, b"XY", proto_fs::Timestamp::ZERO)
                .unwrap();
            assert_eq!(storage.usage(ACCOUNT).pages, count);
            assert!(storage.cancel_data_write(&mut write).unwrap());
            let mut bytes = [0; 2];
            assert_eq!(storage.read(token, offset as u64, &mut bytes), Ok(2));
            assert_eq!(&bytes, b"XY");
            chain(storage, token);
        }
    }
}
