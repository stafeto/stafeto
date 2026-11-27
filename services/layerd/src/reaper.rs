// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What is left to do after a change is visible: the reaper. A directory a change removes (an
//! `rmdir`, or a rename over a directory) leaves the layer in one step, renamed into `work/`, and
//! its entry leaves the index at once; what is left of it is done here, a piece in each step of the
//! loop and never more than the bound of a step allows:
//!
//! - the entries that lay in the directory (marks of deletion, the only names a directory that is
//!   empty in the merged view can hold) are taken out of the index, `SLOTS_PER_READDIR` places of
//!   the table a step (`Index::remove_children_step`), and the key of the directory is given back
//!   after the last one;
//! - the directory in `work/` is removed from the volume, one call to the data file service in each
//!   step: the listing of a directory, the removal of each name in it, the removal of the directory.
//!
//! The same queue takes what a failed change made and left (a directory or a file in `work/`, or a
//! name made and not indexed): the work of a path that would have been scrubbed in the step of the
//! change is done here. The queue holds `REAPS` items; a change that removes a directory asks for a
//! place before it touches the volume and answers STARTING (the clients ask again) when there is
//! none, and an item of a failure that finds the queue full is dropped (the next start empties
//! `work/`).

use crate::listing::SLOTS_PER_READDIR;
use crate::names::Core;
use crate::volume::{Lower, Volume};
use proto_data as d;

/// The items the reaper holds.
pub const REAPS: usize = 4;
const PATH_MAX: usize = d::MAX_PATH;
const NAME_MAX: usize = d::NAME_MAX;
/// The names of a directory one listing takes before their removal.
const BATCH: usize = 8;
/// The failed removals of one item after which it is dropped.
const RETRIES: u8 = 8;

#[derive(Clone, Copy)]
struct Item {
    path: [u8; PATH_MAX],
    len: u16,
    /// The path is a directory (its content goes first).
    dir: bool,
    /// The key of a retired directory whose orphans are in the index (0 for none).
    key: u32,
}

const NO_ITEM: Item = Item {
    path: [0; PATH_MAX],
    len: 0,
    dir: false,
    key: 0,
};

/// Where the removal of the item stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing started: the entries in the index first.
    Orphans(usize),
    /// The listing of the directory being emptied is to be opened, is open (`handle`), or its names
    /// are being removed one by one.
    Open,
    List,
    Close,
    Names(usize),
    /// The directory being emptied has no name left: it is removed and the walk goes up.
    Rmdir,
    /// Everything below the item is gone: the item itself (a file, or the emptied directory).
    Last,
}

/// The reaper and the lock of the changes (`Core::lock`).
pub struct Workers {
    items: [Item; REAPS],
    count: usize,
    phase: Phase,
    /// The directory being emptied (a path below the item's) and the names of its last listing.
    path: [u8; PATH_MAX],
    plen: usize,
    handle: u32,
    names: [[u8; NAME_MAX]; BATCH],
    lens: [u8; BATCH],
    kinds: [u32; BATCH],
    listed: usize,
    /// The removals of the item that failed: past `RETRIES` the item is dropped (the next start
    /// empties `work/`).
    fails: u8,
    /// The job that holds the lock of the changes, plus one (0 for none).
    lock: u8,
}

impl Workers {
    pub const fn new() -> Workers {
        Workers {
            items: [NO_ITEM; REAPS],
            count: 0,
            phase: Phase::Orphans(0),
            path: [0; PATH_MAX],
            plen: 0,
            handle: 0,
            names: [[0; NAME_MAX]; BATCH],
            lens: [0; BATCH],
            kinds: [0; BATCH],
            listed: 0,
            fails: 0,
            lock: 0,
        }
    }

    /// A place is free for an item.
    pub fn room(&self) -> bool {
        self.count < REAPS
    }

    /// Items wait.
    pub fn busy(&self) -> bool {
        self.count > 0
    }

    /// Queues the removal of `path` (below it first, when it is a directory) and of the orphans of
    /// the retired directory with `key`. False when the queue is full.
    pub fn push(&mut self, path: &[u8], dir: bool, key: u32) -> bool {
        if self.count == REAPS || path.len() > PATH_MAX {
            return false;
        }
        let item = &mut self.items[self.count];
        item.path[..path.len()].copy_from_slice(path);
        item.len = path.len() as u16;
        item.dir = dir;
        item.key = key;
        self.count += 1;
        true
    }

    /// Takes the lock of the changes for the job `who` (a small number); false when another job
    /// holds it.
    pub fn lock(&mut self, who: u8) -> bool {
        if self.lock == 0 || self.lock == who + 1 {
            self.lock = who + 1;
            true
        } else {
            false
        }
    }

    /// Lets the lock go (the job `who` holds it, or no job does).
    pub fn unlock(&mut self, who: u8) {
        if self.lock == who + 1 {
            self.lock = 0;
        }
    }

    /// Whether some job holds the lock.
    pub fn locked(&self) -> bool {
        self.lock != 0
    }

    fn head_done(&mut self) {
        self.items.copy_within(1..self.count, 0);
        self.count -= 1;
        self.fails = 0;
        self.phase = Phase::Orphans(0);
    }
}

impl Default for Workers {
    fn default() -> Self {
        Workers::new()
    }
}

impl<V: Volume, L: Lower> Core<'_, V, L> {
    /// Whether the reaper has work.
    pub fn reaping(&self) -> bool {
        self.work.busy()
    }

    /// One step of the reaper: at most `SLOTS_PER_READDIR` places of the table, or one call to the
    /// data file service. True while work is left.
    pub fn reap_step(&mut self) -> bool {
        if self.work.count == 0 {
            return false;
        }
        let w = &mut *self.work;
        let (item_len, item_dir, item_key) =
            (usize::from(w.items[0].len), w.items[0].dir, w.items[0].key);
        match w.phase {
            Phase::Orphans(from) => {
                w.phase = if item_key == 0 {
                    Phase::Open
                } else {
                    match self
                        .index
                        .remove_children_step(item_key, from, SLOTS_PER_READDIR)
                    {
                        Some(next) => Phase::Orphans(next),
                        None => Phase::Open,
                    }
                };
                if w.phase == Phase::Open {
                    if item_dir {
                        w.path[..item_len].copy_from_slice(&w.items[0].path[..item_len]);
                        w.plen = item_len;
                    } else {
                        w.phase = Phase::Last;
                    }
                }
            }
            Phase::Open => {
                match self
                    .volume
                    .open(&w.path[..w.plen], d::READ | d::DIRECTORY, 0)
                {
                    Ok(h) => {
                        w.handle = h;
                        w.phase = Phase::List;
                    }
                    // Not there (or not a directory): the work of the path is done or never was.
                    Err(_) => {
                        w.head_done();
                    }
                }
            }
            Phase::List => {
                w.listed = 0;
                let (names, lens, kinds, listed) =
                    (&mut w.names, &mut w.lens, &mut w.kinds, &mut w.listed);
                let result = self.volume.read_dir(w.handle, &mut |_, kind, name| {
                    if name == b"." || name == b".." || *listed == BATCH || name.len() > NAME_MAX {
                        return;
                    }
                    names[*listed][..name.len()].copy_from_slice(name);
                    lens[*listed] = name.len() as u8;
                    kinds[*listed] = kind;
                    *listed += 1;
                });
                // A listing that fails ends the directory with what the batch holds.
                let _ = result;
                w.phase = Phase::Close;
            }
            Phase::Close => {
                let _ = self.volume.close(w.handle);
                w.phase = if w.listed == 0 {
                    Phase::Rmdir
                } else {
                    Phase::Names(0)
                };
            }
            Phase::Names(i) => {
                let len = usize::from(w.lens[i]);
                let at = w.plen + 1 + len;
                if at > PATH_MAX {
                    // A path past the limit cannot be there: leave the item.
                    w.head_done();
                    return w.count > 0;
                }
                let dir = w.kinds[i] == d::KIND_DIRECTORY;
                let plen = w.plen;
                w.path[plen] = b'/';
                w.path[plen + 1..at].copy_from_slice(&w.names[i][..len]);
                if dir {
                    // Enter it: its listing is next.
                    w.plen = at;
                    w.phase = Phase::Open;
                } else {
                    if self.volume.unlink(&w.path[..at]).is_err() {
                        w.fails += 1;
                        if w.fails >= RETRIES {
                            w.head_done();
                            return w.count > 0;
                        }
                    }
                    w.phase = if i + 1 < w.listed {
                        Phase::Names(i + 1)
                    } else {
                        Phase::Open
                    };
                }
            }
            Phase::Rmdir => {
                if w.plen == item_len {
                    w.phase = Phase::Last;
                } else {
                    if self.volume.rmdir(&w.path[..w.plen]).is_err() {
                        w.fails += 1;
                        if w.fails >= RETRIES {
                            w.head_done();
                            return w.count > 0;
                        }
                    }
                    let up = w.path[..w.plen]
                        .iter()
                        .rposition(|&b| b == b'/')
                        .unwrap_or(0);
                    w.plen = up;
                    w.phase = Phase::Open;
                }
            }
            Phase::Last => {
                if item_dir {
                    let _ = self.volume.rmdir(&w.items[0].path[..item_len]);
                } else {
                    let _ = self.volume.unlink(&w.items[0].path[..item_len]);
                }
                w.head_done();
            }
        }
        w.count > 0
    }
}
