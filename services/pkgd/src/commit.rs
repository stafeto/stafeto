// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The steps that touch the disk, over a `Device` (pk3-design R6, R7): the
//! choice of the superblock at a start, the layout of an empty store, and
//! the two writes that make a new table the store's state: the table into
//! a free extent with a flush (F2), then a superblock with a generation
//! one higher into the copy with the lower one, with a flush (F3). The
//! flush before the table (F1) belongs to whoever wrote the data. The
//! device behind the trait is the disk service for the service, a file for
//! the host's writer and a model with a crash for the tests.

use crate::store::{
    BLOCK, Extent, RECORDS, SUPERS, Superblock, TABLE_BLOCKS, TABLE_BYTES, Table, find_free,
    free_blocks,
};

/// A device refused or lost an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failed;

/// The disk as the store needs it: blocks of 4 KiB, written, read and
/// flushed. A write that returned is on the medium only after a flush.
pub trait Device {
    fn blocks(&self) -> u64;
    fn read(&mut self, block: u64, out: &mut [u8; BLOCK]) -> Result<(), Failed>;
    fn write(&mut self, block: u64, data: &[u8; BLOCK]) -> Result<(), Failed>;
    fn flush(&mut self) -> Result<(), Failed>;
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
    if sb.table_first + TABLE_BLOCKS > sb.blocks {
        return Ok(false);
    }
    read_table(dev, sb.table_first, table)?;
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
        dev.read(copy as u64, &mut buf)?;
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

/// A new store: an empty table of generation 1 in blocks 2 to 6 and the
/// superblock of copy 0, each flushed before the next (`store formatted`).
/// The disk is the store's, so nothing is read first.
pub fn format(dev: &mut impl Device, table: &mut Table) -> Result<Opened, Failed> {
    table.init(1);
    write_table(dev, table, SUPERS)?;
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
    }
    dev.flush()
}

/// The superblock into `copy`, then a flush (F3): the table it names is the
/// store's state once this returns.
pub fn write_super(dev: &mut impl Device, copy: u8, sb: &Superblock) -> Result<(), Failed> {
    dev.write(u64::from(copy), &sb.encode())?;
    dev.flush()
}

/// The next state: `table` (already the next generation) goes into a free
/// extent and the superblock into the copy `opened` does not hold. Fails
/// with `Failed` also when no extent of the table's size is free.
pub fn publish(dev: &mut impl Device, opened: &Opened, table: &Table) -> Result<Opened, Failed> {
    let first = free_table_extent(table, opened).ok_or(Failed)?;
    write_table(dev, table, first)?;
    let sb = superblock_of(dev.blocks(), table, first);
    let copy = 1 - opened.copy;
    write_super(dev, copy, &sb)?;
    Ok(Opened {
        superblock: sb,
        copy,
    })
}

/// Where the next table goes: free in the accepted table (so also clear of
/// the accepted table itself, which the old state still needs).
pub fn free_table_extent(next: &Table, opened: &Opened) -> Option<u64> {
    // The next table's own records are the ones that must stay clear, and
    // the accepted table's extent: a crash before the superblock leaves the
    // old table in use.
    let mut list = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let n = next.occupied(opened.table_extent(), &mut list);
    find_free(&list[..n], &[], opened.superblock.blocks, TABLE_BLOCKS)
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
