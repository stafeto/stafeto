// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The steps that write the disk, with a crash after every write and every
//! flush, and each way the medium may keep what was not flushed (pk3-design
//! R16.4): the store at the next start is the whole state before or the whole
//! state after, and the free space is the disk less the extents of the table
//! it finds.

use crate::commit::{self, Device, Opened, Start};
use crate::store::*;
use crate::testkit::{Loss, ModelDisk};

const DISK: u64 = 131_072;

fn losses(pending: usize) -> Vec<Loss> {
    let mut all = vec![Loss::All, Loss::None];
    // Every subset of up to six pending writes; the rest by prefixes.
    if pending <= 6 {
        all.extend((0..1u64 << pending).map(Loss::Some));
    } else {
        all.extend((0..=pending).map(|k| Loss::Some((1u64 << k) - 1)));
    }
    all
}

/// What a start finds on `disk`: the state, its generation and the names in it.
fn state(disk: &mut ModelDisk) -> (Start, Table) {
    let mut table = Table::zeroed();
    let start = commit::open(disk, &mut table).unwrap();
    (start, table)
}

/// The free space of a store a start found equals the disk less its extents.
fn assert_clean(opened: &Opened, table: &Table) {
    let mut list = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let n = table.occupied(opened.table_extent(), &mut list);
    let held: u64 = list[..n].iter().map(|e| e.blocks).sum();
    assert_eq!(commit::free_of(table, opened), DISK - SUPERS - held);
}

/// Runs `scenario` on `disk` once with no crash to count its operations, then
/// again for a crash after each, with every loss, and gives each state found.
fn crash_everywhere(
    base: &ModelDisk,
    scenario: impl Fn(&mut ModelDisk) -> Result<(), commit::Failed>,
    mut judge: impl FnMut(usize, Loss, bool, &mut ModelDisk),
) -> usize {
    let mut probe = base.after(Loss::None, false);
    scenario(&mut probe).unwrap();
    let total = probe.ops;
    for limit in 0..total {
        let mut disk = base.after(Loss::None, false);
        disk.limit = Some(limit);
        assert!(
            scenario(&mut disk).is_err(),
            "operation {limit} should fail"
        );
        for loss in losses(disk.pending()) {
            for tear in [false, true] {
                let mut found = disk.after(loss, tear);
                judge(limit, loss, tear, &mut found);
            }
        }
    }
    total
}

#[test]
fn a_format_that_crashes_anywhere_gives_a_blank_disk_or_the_empty_store() {
    let base = ModelDisk::new(DISK);
    let total = crash_everywhere(
        &base,
        |disk| commit::format(disk, &mut Table::zeroed()).map(drop),
        |limit, loss, tear, found| {
            let (start, table) = state(found);
            match start {
                Start::Blank => assert!(limit <= 7, "blank after {limit} {loss:?} {tear}"),
                Start::Store(opened) => {
                    assert_eq!(opened.superblock.generation, 1);
                    assert_eq!(opened.copy, 0);
                    assert_eq!(table.record(0), Record::EMPTY);
                    assert_clean(&opened, &table);
                    // Only the superblock's write, once it lands, makes a store.
                    assert!(limit >= 7, "a store after {limit}");
                }
                Start::Damaged => panic!("damaged after {limit} {loss:?} {tear}"),
            }
        },
    );
    // Five blocks of the table, a flush, the superblock, a flush.
    assert_eq!(total, 8);
    // The format after a crash starts again and ends the same.
    let mut disk = ModelDisk::new(DISK);
    disk.limit = Some(3);
    assert!(commit::format(&mut disk, &mut Table::zeroed()).is_err());
    let mut again = disk.after(Loss::None, false);
    let opened = commit::format(&mut again, &mut Table::zeroed()).unwrap();
    assert_eq!(opened.superblock.generation, 1);
    assert_eq!(
        commit::free_of(&Table::zeroed_init(), &opened),
        DISK - SUPERS - TABLE_BLOCKS
    );
}

impl Table {
    /// An empty table, for the tests that count free blocks of the empty store.
    fn zeroed_init() -> Table {
        let mut t = Table::zeroed();
        t.init(1);
        t
    }
}

fn formatted() -> (ModelDisk, Opened, Table) {
    let mut disk = ModelDisk::new(DISK);
    let mut table = Table::zeroed();
    let opened = commit::format(&mut disk, &mut table).unwrap();
    (disk, opened, table)
}

fn package_record(first: u64, blocks: u32, name: &str) -> Record {
    Record {
        kind: PACKAGE,
        flags: WORLD,
        repo: 0,
        first,
        blocks,
        length: u64::from(blocks) * BLOCK as u64,
        number: 0,
        installed: 1,
        sha256: [4; 32],
        name: to_field(name.as_bytes()).unwrap(),
        version: to_field(b"1").unwrap(),
    }
}

/// A transaction as the service makes it: the data into a free extent, a
/// flush (F1), then the table and the superblock.
fn install(
    disk: &mut ModelDisk,
    opened: &Opened,
    table: &Table,
    name: &str,
    blocks: u32,
    slot: usize,
) -> Result<Opened, commit::Failed> {
    let mut next = Table(table.0);
    let mut list = [Extent {
        first: 0,
        blocks: 0,
    }; RECORDS + 1];
    let n = next.occupied(opened.table_extent(), &mut list);
    let first = find_free(&list[..n], &[], DISK, u64::from(blocks)).ok_or(commit::Failed)?;
    for i in 0..u64::from(blocks) {
        disk.write(first + i, &[0xD0 + slot as u8; BLOCK])?;
    }
    disk.flush()?;
    next.set_record(slot, &package_record(first, blocks, name));
    next.set_generation(opened.superblock.generation + 1);
    commit::publish(disk, opened, &next)
}

#[test]
fn an_installation_that_crashes_anywhere_gives_the_old_state_or_the_new() {
    let (disk, opened, mut table) = formatted();
    table.set_repo(0, b"stafeto", 0);
    // The repository part is part of the old state: write it as one.
    let mut with_repo = Table(table.0);
    with_repo.set_generation(2);
    let mut base = disk.after(Loss::None, false);
    let opened = commit::publish(&mut base, &opened, &with_repo).unwrap();
    let total = crash_everywhere(
        &base,
        |d| install(d, &opened, &with_repo, "hello", 3, 0).map(drop),
        |limit, loss, tear, found| {
            let (start, table) = state(found);
            let Start::Store(now) = start else {
                panic!("no store after {limit} {loss:?} {tear}");
            };
            assert_clean(&now, &table);
            let package = table.record(0);
            if now.superblock.generation == 2 {
                assert_eq!(package, Record::EMPTY);
            } else {
                assert_eq!(now.superblock.generation, 3);
                assert_eq!(package.name_bytes(), b"hello");
                // The data of a package the table names were flushed before the table.
                assert!(limit > 3 + 1 + 5, "new state after {limit}");
                for i in 0..package.blocks {
                    assert_eq!(found.peek(package.first + u64::from(i)), [0xD0; BLOCK]);
                }
            }
        },
    );
    // Three blocks of data, F1, five of the table, F2, the superblock, F3.
    assert_eq!(total, 3 + 1 + 5 + 1 + 1 + 1);
}

#[test]
fn a_second_state_goes_to_the_other_copy_and_the_third_back() {
    let (mut disk, opened, mut table) = formatted();
    table.set_repo(0, b"stafeto", 0);
    let mut copies = vec![opened.copy];
    let mut opened = opened;
    for (i, name) in ["a", "b", "c"].iter().enumerate() {
        opened = install(&mut disk, &opened, &table, name, 1 + i as u32, i).unwrap();
        let mut read = Table::zeroed();
        let Start::Store(found) = commit::open(&mut disk, &mut read).unwrap() else {
            panic!("store");
        };
        assert_eq!(found, opened);
        table = read;
        copies.push(opened.copy);
        assert_clean(&opened, &table);
    }
    assert_eq!(copies, [0, 1, 0, 1]);
    assert_eq!(opened.superblock.generation, 4);
    // The old table's blocks come free for the next one and no state loses them.
    assert_eq!(
        commit::free_of(&table, &opened),
        DISK - SUPERS - TABLE_BLOCKS - 6
    );
}

#[test]
fn the_writes_come_in_the_order_the_note_gives() {
    let (mut disk, opened, mut table) = formatted();
    table.set_repo(0, b"stafeto", 0);
    disk.log.clear();
    install(&mut disk, &opened, &table, "hello", 2, 0).unwrap();
    let log = disk.log.join(",");
    // Data blocks, F1, the table, F2, the superblock of the older copy, F3.
    assert_eq!(
        log,
        "write 7,write 8,flush,write 9,write 10,write 11,write 12,write 13,flush,write 1,flush"
    );
}

#[test]
fn a_torn_superblock_never_costs_the_old_state() {
    let (disk, opened, mut table) = formatted();
    table.set_repo(0, b"stafeto", 0);
    let mut base = disk.after(Loss::None, false);
    // The state after one installation is in copy 1; tear a write to copy 0.
    let opened = install(&mut base, &opened, &table, "a", 1, 0).unwrap();
    let mut read = Table::zeroed();
    commit::open(&mut base, &mut read).unwrap();
    let mut next = Table(read.0);
    next.set_generation(opened.superblock.generation + 1);
    let first = commit::free_table_extent(&next, &opened).unwrap();
    commit::write_table(&mut base, &next, first).unwrap();
    let sb = commit::superblock_of(DISK, &next, first);
    base.write(u64::from(1 - opened.copy), &sb.encode())
        .unwrap();
    for mask in 0..2u64 {
        let mut found = base.after(Loss::Some(mask), true);
        let (start, table) = state(&mut found);
        let Start::Store(now) = start else {
            panic!("store")
        };
        assert!(now.superblock.generation >= opened.superblock.generation);
        assert_clean(&now, &table);
    }
}
