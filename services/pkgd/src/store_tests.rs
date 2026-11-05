// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::commit::{self, Device, Opened, Start};
use crate::store::*;
use crate::testkit::ModelDisk;

const DISK: u64 = 131_072;

fn sample_super() -> Superblock {
    Superblock {
        blocks: DISK,
        generation: 7,
        table_first: 40,
        table_len: TABLE_BYTES as u32,
        table_sha: [9; 32],
    }
}

fn record(first: u64, blocks: u32, name: &str) -> Record {
    Record {
        kind: PACKAGE,
        flags: WORLD,
        repo: 0,
        first,
        blocks,
        length: u64::from(blocks) * BLOCK as u64 - 5,
        number: 0,
        installed: 12,
        sha256: [3; 32],
        name: to_field(name.as_bytes()).unwrap(),
        version: to_field(b"1.0").unwrap(),
    }
}

fn table_with(records: &[(usize, Record)]) -> Table {
    let mut t = Table::zeroed();
    t.init(7);
    t.set_repo(0, b"stafeto", 0);
    for (i, r) in records {
        t.set_record(*i, r);
    }
    t
}

#[test]
fn a_superblock_round_trips_and_each_field_is_checked() {
    let sb = sample_super();
    let good = sb.encode();
    assert_eq!(Superblock::decode(&good, DISK), Ok(sb));
    // The words of the note: the layout offsets.
    assert_eq!(&good[..8], b"STAFSTOR");
    assert_eq!(u64::from_le_bytes(good[24..32].try_into().unwrap()), 7);
    assert_eq!(u64::from_le_bytes(good[32..40].try_into().unwrap()), 40);
    assert!(good[128..].iter().all(|&b| b == 0));
    let broken = |at: usize| {
        let mut b = good;
        b[at] ^= 1;
        Superblock::decode(&b, DISK)
    };
    assert_eq!(broken(0), Err(SuperError::Magic));
    assert_eq!(broken(8), Err(SuperError::Version));
    assert_eq!(broken(12), Err(SuperError::BlockSize));
    assert_eq!(broken(16), Err(SuperError::Blocks));
    for at in [24, 32, 40, 48, 79, 96, 127] {
        assert_eq!(broken(at), Err(SuperError::Hash), "byte {at}");
    }
    assert_eq!(Superblock::decode(&good, DISK - 1), Err(SuperError::Blocks));
    assert_eq!(
        Superblock::decode(&good[..100], DISK),
        Err(SuperError::Magic)
    );
}

#[test]
fn a_table_round_trips_and_each_rule_is_checked() {
    let t = table_with(&[(0, record(10, 3, "hello")), (5, record(20, 1, "world"))]);
    assert_eq!(t.check(7, DISK, 2), Ok(()));
    assert_eq!(t.record(0), record(10, 3, "hello"));
    assert_eq!(t.repo(0), Some((&b"stafeto"[..], 0)));
    assert_eq!(t.find_repo(b"stafeto"), Some(0));
    assert_eq!(t.find_repo(b"games"), None);
    assert_eq!(t.check(8, DISK, 2), Err(TableError::Generation));
    for at in [0, 8, 20, 24, 40] {
        let mut b = Table(t.0);
        b.0[at] ^= 1;
        assert_eq!(b.check(7, DISK, 2), Err(TableError::Header), "byte {at}");
    }
    let bad = |r: Record| table_with(&[(0, r)]).check(7, DISK, 2);
    let ok = record(10, 3, "hello");
    assert_eq!(
        bad(Record {
            kind: SETTINGS,
            ..ok
        }),
        Err(TableError::Record(0))
    );
    assert_eq!(bad(Record { flags: 8, ..ok }), Err(TableError::Record(0)));
    assert_eq!(bad(Record { blocks: 2, ..ok }), Err(TableError::Record(0)));
    assert_eq!(bad(Record { length: 0, ..ok }), Err(TableError::Record(0)));
    assert_eq!(
        bad(Record {
            repo: NO_REPO,
            ..ok
        }),
        Err(TableError::Record(0))
    );
    assert_eq!(bad(Record { repo: 16, ..ok }), Err(TableError::Record(0)));
    assert_eq!(
        bad(Record {
            name: to_field(b"Bad Name").unwrap(),
            ..ok
        }),
        Err(TableError::Record(0))
    );
    // Extents: inside the superblocks, past the disk, on the table, on each other.
    assert_eq!(bad(Record { first: 1, ..ok }), Err(TableError::Extents));
    assert_eq!(
        bad(Record {
            first: DISK - 2,
            ..ok
        }),
        Err(TableError::Extents)
    );
    assert_eq!(bad(Record { first: 3, ..ok }), Err(TableError::Extents));
    let crossing = table_with(&[(0, record(10, 3, "a")), (1, record(12, 3, "b"))]);
    assert_eq!(crossing.check(7, DISK, 2), Err(TableError::Extents));
    let touching = table_with(&[(0, record(10, 3, "a")), (1, record(13, 3, "b"))]);
    assert_eq!(touching.check(7, DISK, 2), Ok(()));
    // The settings and the list sit in their places only.
    let mut s = Record {
        kind: SETTINGS,
        repo: NO_REPO,
        ..ok
    };
    s.name = [0; 64];
    s.version = [0; 64];
    assert_eq!(table_with(&[(SETTINGS_SLOT, s)]).check(7, DISK, 2), Ok(()));
    assert_eq!(
        table_with(&[(REVOKED_SLOT, s)]).check(7, DISK, 2),
        Err(TableError::Record(REVOKED_SLOT))
    );
    assert_eq!(
        table_with(&[(3, s)]).check(7, DISK, 2),
        Err(TableError::Record(3))
    );
}

/// A disk with `table` as its state, through the writes the service makes.
#[test]
fn a_table_names_a_package_once_a_repository_it_has_and_a_version_that_reads() {
    let a = record(10, 3, "hello");
    // The same name twice, in two places.
    let twice = table_with(&[(0, a), (4, record(20, 1, "hello"))]);
    assert_eq!(twice.check(7, DISK, 2), Err(TableError::Record(4)));
    // A repository place that is empty, and one that is not.
    let mut t = table_with(&[(0, Record { repo: 3, ..a })]);
    assert_eq!(t.check(7, DISK, 2), Err(TableError::Record(0)));
    t.set_repo(3, b"games", 1);
    assert_eq!(t.check(7, DISK, 2), Ok(()));
    // A version that is empty, has a space or a control byte, or has bytes after its length.
    for version in [&b""[..], b"1 0", b"1\x01", b"1.0"] {
        let mut field = [0u8; 64];
        field[0] = version.len() as u8;
        field[1..=version.len()].copy_from_slice(version);
        if version == b"1.0" {
            field[10] = 1;
        }
        let r = Record {
            version: field,
            ..a
        };
        assert_eq!(
            table_with(&[(0, r)]).check(7, DISK, 2),
            Err(TableError::Record(0)),
            "{version:?}"
        );
    }
}

fn disk_with(table: &mut Table, generation: u64, copy: u8, first: u64) -> ModelDisk {
    let mut disk = ModelDisk::new(DISK);
    table.set_generation(generation);
    commit::write_table(&mut disk, table, first).unwrap();
    let sb = commit::superblock_of(DISK, table, first);
    commit::write_super(&mut disk, copy, &sb).unwrap();
    disk
}

#[test]
fn the_copy_with_the_higher_generation_wins_in_either_place() {
    let mut old = table_with(&[(0, record(10, 3, "old"))]);
    let mut new = table_with(&[(0, record(10, 3, "new"))]);
    for (old_copy, new_copy) in [(0u8, 1u8), (1, 0)] {
        let mut disk = disk_with(&mut old, 5, old_copy, 2);
        new.set_generation(6);
        commit::write_table(&mut disk, &new, 100).unwrap();
        let sb = commit::superblock_of(DISK, &new, 100);
        commit::write_super(&mut disk, new_copy, &sb).unwrap();
        let mut table = Table::zeroed();
        let Start::Store(opened) = commit::open(&mut disk, &mut table).unwrap() else {
            panic!("a store");
        };
        assert_eq!(opened.superblock.generation, 6);
        assert_eq!(opened.copy, new_copy);
        assert_eq!(table.record(0).name_bytes(), b"new");
    }
}

#[test]
fn one_good_copy_is_enough_and_a_broken_newer_one_falls_back() {
    let mut old = table_with(&[(0, record(10, 3, "old"))]);
    let mut disk = disk_with(&mut old, 5, 0, 2);
    // A newer superblock whose table was never written: the old state stays.
    let mut new = table_with(&[(0, record(10, 3, "new"))]);
    new.set_generation(6);
    let sb = commit::superblock_of(DISK, &new, 100);
    commit::write_super(&mut disk, 1, &sb).unwrap();
    let mut table = Table::zeroed();
    let Start::Store(opened) = commit::open(&mut disk, &mut table).unwrap() else {
        panic!("a store");
    };
    assert_eq!((opened.superblock.generation, opened.copy), (5, 0));
    assert_eq!(table.record(0).name_bytes(), b"old");
    // A table of another generation under a good superblock is not good.
    let mut other = table_with(&[]);
    let mut disk = disk_with(&mut other, 5, 0, 2);
    let mut stranger = table_with(&[]);
    stranger.set_generation(4);
    commit::write_table(&mut disk, &stranger, 2).unwrap();
    assert_eq!(commit::open(&mut disk, &mut table).unwrap(), Start::Damaged);
}

#[test]
fn zeros_are_blank_and_noise_is_damaged() {
    let mut table = Table::zeroed();
    let mut disk = ModelDisk::new(DISK);
    assert_eq!(commit::open(&mut disk, &mut table).unwrap(), Start::Blank);
    disk.write(0, &[0x55; BLOCK]).unwrap();
    assert_eq!(commit::open(&mut disk, &mut table).unwrap(), Start::Damaged);
    let mut one = ModelDisk::new(DISK);
    one.write(1, &[1; BLOCK]).unwrap();
    assert_eq!(commit::open(&mut one, &mut table).unwrap(), Start::Damaged);
}

#[test]
fn a_table_that_is_not_the_one_the_superblock_hashed_is_refused() {
    let mut t = table_with(&[(0, record(10, 3, "hello"))]);
    let mut disk = disk_with(&mut t, 5, 0, 2);
    // A byte of a record changes on the medium after the superblock was made.
    let mut block = disk.peek(2);
    block[HEADER_FOR_TEST + 40] ^= 1;
    disk.write(2, &block).unwrap();
    let mut table = Table::zeroed();
    assert_eq!(commit::open(&mut disk, &mut table).unwrap(), Start::Damaged);
}

const HEADER_FOR_TEST: usize = 64;

fn extent(first: u64, blocks: u64) -> Extent {
    Extent { first, blocks }
}

#[test]
fn free_space_is_the_first_run_that_fits() {
    let occupied = [extent(2, 5), extent(10, 3), extent(20, 2)];
    assert_eq!(find_free(&occupied, &[], 100, 3), Some(7));
    assert_eq!(find_free(&occupied, &[], 100, 4), Some(13));
    assert_eq!(find_free(&occupied, &[], 100, 8), Some(22));
    assert_eq!(find_free(&occupied, &[extent(7, 1)], 100, 3), Some(13));
    assert_eq!(find_free(&occupied, &[], 22 + 7, 8), None);
    assert_eq!(find_free(&occupied, &[], 22 + 8, 8), Some(22));
    assert_eq!(find_free(&[], &[], 100, 98), Some(2));
    assert_eq!(find_free(&[], &[], 100, 99), None);
    assert_eq!(free_blocks(&occupied, 100), 100 - 2 - 10);
}

/// A small generator, so the property has the same cases every time.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, below: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % below
    }
}

#[test]
fn a_run_never_crosses_the_records_the_table_or_what_a_transaction_took() {
    let mut rng = Lcg(42);
    for _ in 0..200 {
        let mut table = Table::zeroed();
        table.init(1);
        table.set_repo(0, b"stafeto", 0);
        let own = extent(2 + rng.next(40), TABLE_BLOCKS);
        let mut at = own.end() + rng.next(5);
        let mut taken = Vec::new();
        for i in 0..64 {
            if rng.next(4) == 0 {
                continue;
            }
            let blocks = 1 + rng.next(9) as u32;
            if at + u64::from(blocks) > 5000 {
                break;
            }
            // Records before and after the table, never on it.
            table.set_record(i, &record(at, blocks, &format!("p{i}")));
            at += u64::from(blocks) + rng.next(6);
            if at < own.end() && at + 12 > own.first {
                at = own.end();
            }
        }
        for _ in 0..rng.next(4) {
            taken.push(extent(2 + rng.next(300), 1 + rng.next(8)));
        }
        let mut list = [extent(0, 0); RECORDS + 1];
        let n = table.occupied(own, &mut list);
        for _ in 0..20 {
            let need = 1 + rng.next(20);
            let Some(first) = find_free(&list[..n], &taken, 6000, need) else {
                continue;
            };
            let run = extent(first, need);
            assert!(run.first >= SUPERS && run.end() <= 6000);
            for e in list[..n].iter().chain(&taken).chain([&own]) {
                assert!(
                    run.end() <= e.first || e.end() <= run.first,
                    "{run:?} on {e:?}"
                );
            }
        }
    }
}

#[test]
fn a_table_past_the_superblocks_has_the_whole_disk_free() {
    let mut disk = ModelDisk::new(DISK);
    let mut table = Table::zeroed();
    let opened: Opened = commit::format(&mut disk, &mut table).unwrap();
    assert_eq!(
        commit::free_of(&table, &opened),
        DISK - SUPERS - TABLE_BLOCKS
    );
    assert_eq!(
        commit::free_table_extent(&table, &table, &opened),
        Some(SUPERS + TABLE_BLOCKS)
    );
}

#[test]
fn extents_at_the_end_of_the_number_line_are_refused_and_never_wrap() {
    let edge = Record {
        first: u64::MAX - 1,
        blocks: 4,
        length: 4 * BLOCK as u64,
        ..record(10, 4, "edge")
    };
    assert_eq!(
        table_with(&[(0, edge)]).check(7, DISK, 2),
        Err(TableError::Extents)
    );
    let huge = Record {
        first: 10,
        blocks: u32::MAX,
        length: u64::from(u32::MAX) * BLOCK as u64,
        ..edge
    };
    assert_eq!(
        table_with(&[(0, huge)]).check(7, DISK, 2),
        Err(TableError::Extents)
    );
    assert_eq!(
        table_with(&[]).check(7, DISK, u64::MAX - 2),
        Err(TableError::Extents)
    );
    assert_eq!(
        Extent {
            first: u64::MAX,
            blocks: 5
        }
        .end(),
        u64::MAX
    );
    // A superblock that names a table at the edge is no good, and the start says so.
    let mut t = table_with(&[]);
    let mut disk = disk_with(&mut t, 5, 0, 2);
    let sb = Superblock {
        table_first: u64::MAX - 1,
        ..commit::superblock_of(DISK, &t, 2)
    };
    disk.write(0, &sb.encode()).unwrap();
    disk.write(1, &sb.encode()).unwrap();
    let mut table = Table::zeroed();
    assert_eq!(commit::open(&mut disk, &mut table).unwrap(), Start::Damaged);
}
