// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The steps that touch the disk, over a `Device` (pk3-design R6, R7): the
//! choice of the superblock at a start, the layout of an empty store, and
//! the transactions that make a new table the store's state. A transaction
//! is the flush of the data (F1), the table into a free extent with a flush
//! (F2), the layers attached or detached, and a superblock with a generation
//! one higher into the copy with the lower one, with a flush (F3); the order
//! of an installation, a removal, a new settings layer, a serial and a list of
//! revocations is `transact`. The device behind the trait is the disk service
//! for the service, a file for the host's writer and a model with a crash for
//! the tests; the same trait carries the calls to the file service (`attach`,
//! `detach`) and the places the crash tests stop at (`point`), so a model sees
//! the whole order.

use crate::store::{
    BLOCK, Extent, RECORDS, SUPERS, Superblock, TABLE_BLOCKS, TABLE_BYTES, Table, find_free,
    free_blocks,
};

/// A device refused or lost an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failed;

/// The places of the plan a crash test stops at (`store-crash`, pk3-design R17),
/// in the order of the table of the note; the number is the one the build for the
/// crash gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// An object and an extent are taken, nothing is written.
    Begin = 1,
    /// The first write of the data of a package was accepted.
    Data,
    /// The data are flushed (F1).
    DataFlushed,
    /// The first of the five blocks of the table was accepted.
    TablePart,
    /// The table is flushed (F2) in an installation.
    TableFlushed,
    /// The layers are attached, the superblock is not written.
    Attached,
    /// The write of the superblock is torn inside its first sector: the copy it goes to is refused
    /// at the next start, and the other copy is the state.
    SuperTorn,
    /// The superblock was accepted and is still to be flushed.
    SuperWritten,
    /// The superblock is flushed (F3) in an installation.
    Committed,
    /// The table is flushed in a removal.
    RemoveTable,
    /// The superblock is flushed in a removal, the layers are not detached.
    RemoveCommitted,
    /// The table is flushed in a change of the settings.
    SettingsTable,
    /// A new store has its table and no superblock yet.
    FormatTable,
}

impl Point {
    pub const ALL: [Point; 13] = [
        Point::Begin,
        Point::Data,
        Point::DataFlushed,
        Point::TablePart,
        Point::TableFlushed,
        Point::Attached,
        Point::SuperTorn,
        Point::SuperWritten,
        Point::Committed,
        Point::RemoveTable,
        Point::RemoveCommitted,
        Point::SettingsTable,
        Point::FormatTable,
    ];

    pub const fn number(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            Point::Begin => "begin",
            Point::Data => "data",
            Point::DataFlushed => "data-flushed",
            Point::TablePart => "table-part",
            Point::TableFlushed => "table-flushed",
            Point::Attached => "attached",
            Point::SuperTorn => "super-torn",
            Point::SuperWritten => "super-written",
            Point::Committed => "committed",
            Point::RemoveTable => "remove-table",
            Point::RemoveCommitted => "remove-committed",
            Point::SettingsTable => "settings-table",
            Point::FormatTable => "format-table",
        }
    }
}

/// The disk as the store needs it: blocks of 4 KiB, written, read and
/// flushed. A write that returned is on the medium only after a flush.
///
/// The other methods are the calls of a plan that are not the disk's; each has
/// a default for a device that has no file service to call and no crash to
/// place: the writer of the host.
pub trait Device {
    fn blocks(&self) -> u64;
    fn read(&mut self, block: u64, out: &mut [u8; BLOCK]) -> Result<(), Failed>;
    fn write(&mut self, block: u64, data: &[u8; BLOCK]) -> Result<(), Failed>;
    fn flush(&mut self) -> Result<(), Failed>;

    /// Attaches the package or the settings layer of table place `slot` to
    /// the file service; the code of the refusal (`proto_pkg`) when it
    /// refuses. The tree is as before when it does.
    fn attach(&mut self, slot: usize) -> Result<(), u32> {
        let _ = slot;
        Ok(())
    }

    /// Detaches the layer of `slot`.
    fn detach(&mut self, slot: usize) {
        let _ = slot;
    }

    /// The plan is at `point`: the build for the crash tests stops here when it is
    /// its point.
    fn point(&mut self, point: Point) {
        let _ = point;
    }

    /// The write of the superblock `data` to `block` is about to come: the
    /// build for the crash tests writes the first 64 bytes of it alone and stops.
    fn tear(&mut self, block: u64, data: &[u8; BLOCK]) {
        let _ = (block, data);
    }
}

/// The store a start found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub superblock: Superblock,
    /// The copy (0 or 1) that holds `superblock`; the next one goes to the other.
    pub copy: u8,
}

impl Opened {
    pub fn table_extent(&self) -> Extent {
        Extent {
            first: self.superblock.table_first,
            blocks: TABLE_BLOCKS,
        }
    }
}

/// What a start made of the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// A good store; its table is in the `Table` given.
    Store(Opened),
    /// Both superblocks are zeros: nothing was ever written.
    Blank,
    /// Something is there and no copy is good.
    Damaged,
}

/// Reads the table `sb` names into `table` and checks it: SHA-256,
/// generation and every rule.
fn load(dev: &mut impl Device, sb: &Superblock, table: &mut Table) -> Result<bool, Failed> {
    if sb.table_len as usize != TABLE_BYTES || sb.table_first < SUPERS {
        return Ok(false);
    }
    if sb
        .table_first
        .checked_add(TABLE_BLOCKS)
        .is_none_or(|end| end > sb.blocks)
    {
        return Ok(false);
    }
    // A table that cannot be read makes this copy no good; the other may be.
    if read_table(dev, sb.table_first, table).is_err() {
        return Ok(false);
    }
    Ok(table.sha() == sb.table_sha
        && table
            .check(sb.generation, sb.blocks, sb.table_first)
            .is_ok())
}

/// The five blocks of the table at `first`.
pub fn read_table(dev: &mut impl Device, first: u64, table: &mut Table) -> Result<(), Failed> {
    for (i, chunk) in table.0.as_chunks_mut::<BLOCK>().0.iter_mut().enumerate() {
        dev.read(first + i as u64, chunk)?;
    }
    Ok(())
}

/// The state at a start: both superblocks are read, the good ones tried by
/// generation, highest first; the first whose table is whole wins.
pub fn open(dev: &mut impl Device, table: &mut Table) -> Result<Start, Failed> {
    let blocks = dev.blocks();
    let mut found: [Option<Superblock>; 2] = [None, None];
    let mut zeros = true;
    let mut buf = [0u8; BLOCK];
    for (copy, slot) in found.iter_mut().enumerate() {
        // A superblock that cannot be read is a copy that is not good.
        if dev.read(copy as u64, &mut buf).is_err() {
            zeros = false;
            continue;
        }
        zeros &= buf.iter().all(|&b| b == 0);
        *slot = Superblock::decode(&buf, blocks).ok();
    }
    let order = match (found[0], found[1]) {
        (Some(a), Some(b)) if b.generation > a.generation => [1, 0],
        _ => [0, 1],
    };
    for copy in order {
        if let Some(sb) = found[copy]
            && load(dev, &sb, table)?
        {
            return Ok(Start::Store(Opened {
                superblock: sb,
                copy: copy as u8,
            }));
        }
    }
    Ok(if zeros { Start::Blank } else { Start::Damaged })
}

/// A new store: a table of generation 1 with the official repository and no package in blocks 2 to 6 and the
/// superblock of copy 0, each flushed before the next (`store formatted`).
/// The disk is the store's, so nothing is read first.
pub fn format(dev: &mut impl Device, table: &mut Table) -> Result<Opened, Failed> {
    table.init(1);
    // The official repository has the first place, with no serial yet.
    table.set_repo(0, b"stafeto", 0);
    write_table(dev, table, SUPERS)?;
    dev.point(Point::FormatTable);
    let sb = superblock_of(dev.blocks(), table, SUPERS);
    write_super(dev, 0, &sb)?;
    Ok(Opened {
        superblock: sb,
        copy: 0,
    })
}

/// The superblock of `table` placed at `first`.
pub fn superblock_of(blocks: u64, table: &Table, first: u64) -> Superblock {
    Superblock {
        blocks,
        generation: table.generation(),
        table_first: first,
        table_len: TABLE_BYTES as u32,
        table_sha: table.sha(),
    }
}

/// The table into the five blocks at `first`, then a flush (F2).
pub fn write_table(dev: &mut impl Device, table: &Table, first: u64) -> Result<(), Failed> {
    for (i, chunk) in table.0.as_chunks::<BLOCK>().0.iter().enumerate() {
        dev.write(first + i as u64, chunk)?;
        if i == 0 {
            dev.point(Point::TablePart);
        }
    }
    dev.flush()
}

/// The superblock into `copy`, then a flush (F3): the table it names is the
/// store's state once this returns.
pub fn write_super(dev: &mut impl Device, copy: u8, sb: &Superblock) -> Result<(), Failed> {
    let bytes = sb.encode();
    dev.tear(u64::from(copy), &bytes);
    dev.write(u64::from(copy), &bytes)?;
    dev.point(Point::SuperWritten);
    dev.flush()
}

/// The next state: `next` (already the next generation) goes into a free
/// extent and the superblock into the copy `opened` does not hold. `accepted`
/// is the table of the state `opened` names: its records and its own extent
/// stay clear, since a crash before the superblock leaves that state in use.
/// Fails with `Failed` also when no extent of the table's size is free.
pub fn publish(
    dev: &mut impl Device,
    opened: &Opened,
    accepted: &Table,
    next: &Table,
) -> Result<Opened, Failed> {
    let first = free_table_extent(accepted, next, opened).ok_or(Failed)?;
    write_table(dev, next, first)?;
    let sb = superblock_of(dev.blocks(), next, first);
    let copy = 1 - opened.copy;
    write_super(dev, copy, &sb)?;
    Ok(Opened {
        superblock: sb,
        copy,
    })
}

/// What a transaction changes besides the table (pk3-design R7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One or more packages in: the layers of the replaced go and the new ones
    /// attach before the superblock, so a refusal of the file service leaves the
    /// old state with no write to undo.
    Install,
    /// Packages out: the layers detach after the superblock, since their bytes
    /// are all in memory and the disk no longer matters to them.
    Remove,
    /// A new settings layer: as an installation, the old layer replaced.
    Settings,
    /// A serial of a repository: the table alone.
    Serial,
    /// The flag "world" of a package: the table alone.
    World,
    /// A new list of revocations: the layers of the packages it revokes detach after the
    /// superblock.
    Revoked,
}

/// The layers of a transaction, by the place of the table: `detach` the
/// packages that go (or the settings layer that a new one replaces), `attach` the
/// ones that come. The new settings layer has the place `store::SETTINGS_NEW`, so that it
/// differs from the old one until the table is the state.
#[derive(Clone, Copy, Debug)]
pub struct Change<'a> {
    pub kind: Kind,
    pub detach: &'a [usize],
    pub attach: &'a [usize],
}

/// Why a transaction did not become the store's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The disk failed: the state of the medium is the old or the new one, whole.
    Io,
    /// No run of five blocks is free for the next table.
    NoSpace,
    /// The file service refused a layer (the code of `proto_pkg`); the state is the old
    /// one and the layers are as they were.
    Attach(u32),
}

impl From<Failed> for Refused {
    fn from(_: Failed) -> Refused {
        Refused::Io
    }
}

/// The layers as they were: those attached by this transaction go, those it
/// detached come back.
fn undo(dev: &mut impl Device, change: &Change<'_>, attached: usize) {
    for &slot in change.attach[..attached].iter().rev() {
        dev.detach(slot);
    }
    for &slot in change.detach {
        // A layer that cannot come back leaves a package missing from the tree
        // until the next start, which reads the old state: nothing else to do.
        let _ = dev.attach(slot);
    }
}

/// The transaction `change` from the state `opened` (whose table is `accepted`) to
/// `next` (already the next generation): F1, the table into a free extent and F2,
/// then the layers and the superblock in the order of the kind (`Kind`), F3. The data
/// the table names are written by the caller before. `Err(Io)` leaves the store with
/// the old state or the new one, whole; either error leaves the layers as they were,
/// except that after `Io` from the last flush the new state may be the medium's.
pub fn transact(
    dev: &mut impl Device,
    opened: &Opened,
    accepted: &Table,
    next: &Table,
    change: &Change<'_>,
) -> Result<Opened, Refused> {
    dev.flush()?;
    dev.point(Point::DataFlushed);
    let first = free_table_extent(accepted, next, opened).ok_or(Refused::NoSpace)?;
    write_table(dev, next, first)?;
    match change.kind {
        Kind::Install => dev.point(Point::TableFlushed),
        Kind::Remove => dev.point(Point::RemoveTable),
        Kind::Settings => dev.point(Point::SettingsTable),
        Kind::Serial | Kind::World | Kind::Revoked => {}
    }
    let attach_first = matches!(change.kind, Kind::Install | Kind::Settings);
    if attach_first {
        for &slot in change.detach {
            dev.detach(slot);
        }
        for (done, &slot) in change.attach.iter().enumerate() {
            if let Err(code) = dev.attach(slot) {
                undo(dev, change, done);
                return Err(Refused::Attach(code));
            }
        }
        dev.point(Point::Attached);
    }
    let sb = superblock_of(dev.blocks(), next, first);
    let copy = 1 - opened.copy;
    if let Err(failed) = write_super(dev, copy, &sb) {
        if attach_first {
            undo(dev, change, change.attach.len());
        }
        return Err(failed.into());
    }
    dev.point(match change.kind {
        Kind::Remove => Point::RemoveCommitted,
        _ => Point::Committed,
    });
    if !attach_first {
        for &slot in change.detach {
            dev.detach(slot);
        }
    }
    Ok(Opened {
        superblock: sb,
        copy,
    })
}

/// Where the next table goes: clear of everything the accepted state holds
/// (its records, its table) and of what the next state's records name.
pub fn free_table_extent(accepted: &Table, next: &Table, opened: &Opened) -> Option<u64> {
    let mut held = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let n = accepted.occupied(opened.table_extent(), &mut held);
    let mut new = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let m = next.occupied(opened.table_extent(), &mut new);
    find_free(
        &held[..n],
        &new[..m],
        opened.superblock.blocks,
        TABLE_BLOCKS,
    )
}

/// The blocks free in the table of the state `opened`.
pub fn free_of(table: &Table, opened: &Opened) -> u64 {
    let mut list = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let n = table.occupied(opened.table_extent(), &mut list);
    free_blocks(&list[..n], opened.superblock.blocks)
}
