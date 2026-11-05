// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The receipts and the group (pk3-design R16.8): FEED past the size, the hash and the
//! writes of a package fed in pieces of any size, the extent that a cancelled receipt
//! frees, the group that lets one session at a time in, and the table it builds.

use crate::receipts::*;
use crate::store::*;
use pkgfmt::sha::sha256;

const DISK: u64 = 131_072;
const OWNER: u64 = 7;

fn table() -> (Table, Extent) {
    let mut t = Table::zeroed();
    t.init(5);
    t.set_repo(0, b"stafeto", 0);
    (
        t,
        Extent {
            first: 2,
            blocks: TABLE_BLOCKS,
        },
    )
}

fn args(name: &str, size: u64) -> BeginArgs<'_> {
    BeginArgs {
        name: name.as_bytes(),
        version: b"1.0",
        size,
        sha256: [1; 32],
        repo: 0,
        world: true,
    }
}

fn begin(
    g: &mut Group,
    owner: u64,
    t: &(Table, Extent),
    name: &str,
    size: u64,
) -> Result<(u32, usize, Extent), u32> {
    g.begin(owner, &t.0, t.1, DISK, &args(name, size), 99)
}

/// Feeds `bytes` in pieces of the sizes `cuts` give (repeating) and runs the work of
/// the service: the portions hashed and the blocks written as they become ready.
fn receive(bytes: &[u8], cuts: &[usize]) -> (Receipt, Vec<u8>) {
    let mut receipt = Receipt::new(1, bytes.len() as u64);
    let mut disk = Vec::new();
    let mut fed = 0usize;
    for cut in cuts.iter().cycle() {
        if fed == bytes.len() {
            break;
        }
        let next = (fed + cut).min(bytes.len());
        assert!(check_feed(bytes.len() as u64, fed as u64, (next - fed) as u32).is_ok());
        fed = next;
        receipt.set_fed(fed as u64);
        while let Some((from, to)) = receipt.portion() {
            assert!(to - from <= PORTION);
            receipt.absorb(&bytes[from as usize..to as usize]);
            while let Some((first, blocks)) = receipt.blocks_to_write() {
                let at = first as usize * BLOCK;
                disk.extend_from_slice(&bytes[at..at + blocks as usize * BLOCK]);
                receipt.wrote(blocks);
            }
        }
    }
    (receipt, disk)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + (i >> 9)) as u8).collect()
}

#[test]
fn a_feed_past_the_size_is_too_long_and_the_exact_end_is_not() {
    assert_eq!(check_feed(8192, 0, 8192), Ok(()));
    assert_eq!(check_feed(8192, 4096, 4096), Ok(()));
    assert_eq!(check_feed(8192, 4096, 4097), Err(TooLong));
    assert_eq!(check_feed(8192, 8192, 1), Err(TooLong));
    assert_eq!(check_feed(u64::MAX, u64::MAX, 1), Err(TooLong));
}

#[test]
fn the_hash_and_the_writes_do_not_depend_on_how_the_package_is_cut() {
    let bytes = pattern(9 * BLOCK);
    let covered = sha256(&bytes[..8 * BLOCK]);
    let whole = sha256(&bytes);
    for cuts in [
        vec![16_384],
        vec![1],
        vec![4095, 1, 4097],
        vec![BLOCK],
        vec![8 * BLOCK],
        vec![8 * BLOCK + 1],
        vec![7, 4093, 16_000, 3],
    ] {
        let (receipt, disk) = receive(&bytes, &cuts);
        assert!(receipt.complete(), "{cuts:?}");
        assert_eq!(disk, bytes, "{cuts:?}");
        assert_eq!(receipt.digests(), Some((covered, whole)), "{cuts:?}");
    }
}

#[test]
fn a_package_of_two_pages_has_a_covered_part_of_one() {
    let bytes = pattern(2 * BLOCK);
    let (receipt, _) = receive(&bytes, &[5000]);
    assert_eq!(
        receipt.digests(),
        Some((sha256(&bytes[..BLOCK]), sha256(&bytes)))
    );
}

#[test]
fn a_receipt_is_not_complete_until_everything_came_was_hashed_and_written() {
    let bytes = pattern(4 * BLOCK);
    let mut r = Receipt::new(1, bytes.len() as u64);
    assert!(!r.complete());
    r.set_fed(3 * BLOCK as u64 + 10);
    let (from, to) = r.portion().unwrap();
    assert_eq!((from, to), (0, 3 * BLOCK as u64 + 10));
    r.absorb(&bytes[..to as usize]);
    // Three whole blocks are ready; the tenth byte of the fourth is not a block.
    assert_eq!(r.blocks_to_write(), Some((0, 3)));
    r.wrote(3);
    assert_eq!(r.blocks_to_write(), None);
    assert!(!r.complete());
    r.set_fed(4 * BLOCK as u64);
    r.absorb(&bytes[to as usize..]);
    assert_eq!(r.blocks_to_write(), Some((3, 1)));
    r.wrote(1);
    assert!(r.complete());
    // A count that goes back or past the size changes nothing.
    r.set_fed(1);
    r.set_fed(u64::MAX);
    assert!(r.complete());
    assert!(r.digests().is_some());
    // The digests of a receipt that is not complete are not given.
    assert!(Receipt::new(2, 2 * BLOCK as u64).digests().is_none());
}

#[test]
fn one_session_holds_the_store_and_one_receipt_is_open_at_a_time() {
    let t = table();
    let mut g = Group::new();
    assert_eq!(g.owner(), None);
    let (number, slot, extent) = begin(&mut g, OWNER, &t, "a", 3 * BLOCK as u64).unwrap();
    assert_eq!((slot, extent.blocks), (0, 3));
    assert_eq!(g.owner(), Some(OWNER));
    // Another session, and the same one with the receipt still open.
    assert_eq!(
        begin(&mut g, 8, &t, "b", 2 * BLOCK as u64),
        Err(proto_pkg::BUSY)
    );
    assert_eq!(
        begin(&mut g, OWNER, &t, "b", 2 * BLOCK as u64),
        Err(proto_pkg::BUSY)
    );
    assert!(g.receipt(number).is_some() && g.receipt(number + 1).is_none());
    g.release();
    assert_eq!(g.owner(), None);
    assert!(begin(&mut g, 8, &t, "b", 2 * BLOCK as u64).is_ok());
}

#[test]
fn what_a_cancelled_receipt_took_is_free_again_and_its_number_is_never_used_twice() {
    let t = table();
    let mut g = Group::new();
    let (n1, s1, e1) = begin(&mut g, OWNER, &t, "a", 5 * BLOCK as u64).unwrap();
    g.release();
    let (n2, s2, e2) = begin(&mut g, OWNER, &t, "a", 5 * BLOCK as u64).unwrap();
    assert_eq!((s1, e1), (s2, e2));
    assert_ne!(n1, n2);
    assert!(g.receipt(n1).is_none());
}

#[test]
fn the_extents_and_places_of_a_group_do_not_cross_each_other_or_the_table() {
    let mut t = table();
    t.0.set_record(
        0,
        &Record {
            kind: PACKAGE,
            flags: WORLD,
            repo: 0,
            first: 8,
            blocks: 4,
            length: 4 * BLOCK as u64,
            number: 0,
            installed: 1,
            sha256: [0; 32],
            name: to_field(b"old").unwrap(),
            version: to_field(b"1").unwrap(),
        },
    );
    let mut g = Group::new();
    let mut taken = vec![
        t.1,
        Extent {
            first: 8,
            blocks: 4,
        },
    ];
    let mut slots = vec![0];
    for (name, blocks) in [("a", 3u64), ("b", 2), ("c", 5), ("d", 2)] {
        let (number, slot, extent) = begin(&mut g, OWNER, &t, name, blocks * BLOCK as u64).unwrap();
        for e in &taken {
            assert!(
                extent.first >= e.end() || extent.end() <= e.first,
                "{extent:?} on {e:?}"
            );
        }
        assert!(!slots.contains(&slot));
        taken.push(extent);
        slots.push(slot);
        // The data come; the package is complete and committed.
        let bytes = pattern(blocks as usize * BLOCK);
        let (whole, _) = receive(&bytes, &[BLOCK]);
        assert!(whole.complete());
        let r = g.receipt(number).unwrap();
        r.set_fed(blocks * BLOCK as u64);
        r.absorb(&bytes);
        r.wrote(blocks);
        assert!(g.commit(number).is_ok());
    }
    // A fifth package does not fit the group.
    assert_eq!(
        begin(&mut g, OWNER, &t, "e", 2 * BLOCK as u64),
        Err(proto_pkg::INVALID)
    );
}

#[test]
fn a_package_that_is_not_complete_is_not_committed() {
    let t = table();
    let mut g = Group::new();
    let (number, ..) = begin(&mut g, OWNER, &t, "a", 2 * BLOCK as u64).unwrap();
    g.receipt(number).unwrap().set_fed(BLOCK as u64);
    assert_eq!(g.commit(number).unwrap_err(), proto_pkg::INVALID);
    assert_eq!(g.commit(number + 1).unwrap_err(), proto_pkg::INVALID);
    assert!(g.receipt(number).is_some());
    assert_eq!(g.staged().count(), 0);
}

#[test]
fn the_refusals_of_a_begin() {
    let t = table();
    let mut g = Group::new();
    let page = BLOCK as u64;
    // Names, versions and repositories.
    assert_eq!(
        begin(&mut g, OWNER, &t, "Bad Name", 2 * page),
        Err(proto_pkg::INVALID)
    );
    assert_eq!(
        begin(&mut g, OWNER, &t, "", 2 * page),
        Err(proto_pkg::INVALID)
    );
    let mut a = args("a", 2 * page);
    a.version = b"";
    assert_eq!(
        g.begin(OWNER, &t.0, t.1, DISK, &a, 1),
        Err(proto_pkg::INVALID)
    );
    let mut a = args("a", 2 * page);
    a.repo = 1;
    assert_eq!(
        g.begin(OWNER, &t.0, t.1, DISK, &a, 1),
        Err(proto_pkg::INVALID)
    );
    a.repo = 99;
    assert_eq!(
        g.begin(OWNER, &t.0, t.1, DISK, &a, 1),
        Err(proto_pkg::INVALID)
    );
    // Sizes: not whole pages, one page, none.
    for size in [0, page, 2 * page + 1] {
        assert_eq!(
            begin(&mut g, OWNER, &t, "a", size),
            Err(proto_pkg::BAD_PACKAGE),
            "{size}"
        );
    }
    // A refusal opens no group.
    assert_eq!(g.owner(), None);
    // A disk too small: the table takes 2..7.
    assert_eq!(
        g.begin(OWNER, &t.0, t.1, 8, &args("a", 2 * page), 1),
        Err(proto_pkg::NO_SPACE)
    );
    assert!(
        g.begin(OWNER, &t.0, t.1, 9, &args("a", 2 * page), 1)
            .is_ok()
    );
}

#[test]
fn all_places_taken_is_no_space() {
    let mut t = table();
    for i in 0..PACKAGES {
        t.0.set_record(
            i,
            &Record {
                kind: PACKAGE,
                flags: WORLD,
                repo: 0,
                first: 10 + i as u64,
                blocks: 1,
                length: BLOCK as u64,
                number: 0,
                installed: 1,
                sha256: [0; 32],
                name: to_field(format!("p{i}").as_bytes()).unwrap(),
                version: to_field(b"1").unwrap(),
            },
        );
    }
    let mut g = Group::new();
    assert_eq!(
        begin(&mut g, OWNER, &t, "z", 2 * BLOCK as u64),
        Err(proto_pkg::NO_SPACE)
    );
}

#[test]
fn the_table_of_a_group_has_the_next_generation_and_replaces_by_name() {
    let mut t = table();
    let old = Record {
        kind: PACKAGE,
        flags: WORLD,
        repo: 0,
        first: 8,
        blocks: 2,
        length: 2 * BLOCK as u64,
        number: 0,
        installed: 1,
        sha256: [0; 32],
        name: to_field(b"a").unwrap(),
        version: to_field(b"1").unwrap(),
    };
    t.0.set_record(3, &old);
    let mut g = Group::new();
    let mut out = GroupTable::new();
    for (name, blocks) in [("a", 2u64), ("b", 3)] {
        let (number, ..) = begin(&mut g, OWNER, &t, name, blocks * BLOCK as u64).unwrap();
        let bytes = pattern(blocks as usize * BLOCK);
        let r = g.receipt(number).unwrap();
        r.set_fed(bytes.len() as u64);
        r.absorb(&bytes);
        r.wrote(blocks);
        g.commit(number).unwrap();
    }
    g.table(&t.0, &mut out);
    assert_eq!(out.next.generation(), 6);
    // `a` was in place 3; the new `a` is in place 0 and `b` in 1.
    assert_eq!((out.detach(), out.attach()), (&[3][..], &[0, 1][..]));
    assert_eq!(out.next.record(3), Record::EMPTY);
    assert_eq!(out.next.record(0).name_bytes(), b"a");
    assert_eq!(out.next.record(1).name_bytes(), b"b");
    assert_eq!(out.next.record(0).installed, 99);
    assert_eq!(out.next.record(0).flags, WORLD);
    assert_eq!(
        out.next.check(6, DISK, 2),
        Ok(()),
        "{:?}",
        out.next.check(6, DISK, 2)
    );
    // The accepted table is untouched.
    assert_eq!(t.0.record(3), old);
}

#[test]
fn a_package_that_is_not_in_the_world_is_a_dependency() {
    let t = table();
    let mut g = Group::new();
    let mut a = args("lib", 2 * BLOCK as u64);
    a.world = false;
    g.begin(OWNER, &t.0, t.1, DISK, &a, 1).unwrap();
    let r = g.receipt(1).unwrap();
    let bytes = pattern(2 * BLOCK);
    r.set_fed(bytes.len() as u64);
    r.absorb(&bytes);
    r.wrote(2);
    let staged = g.commit(1).unwrap().staged;
    assert_eq!(staged.record.flags, DEPENDENCY);
}

#[test]
fn a_session_that_goes_at_any_step_leaves_the_store_free() {
    let t = table();
    for step in 0..4 {
        let mut g = Group::new();
        let (number, ..) = begin(&mut g, OWNER, &t, "a", 2 * BLOCK as u64).unwrap();
        if step >= 1 {
            let bytes = pattern(2 * BLOCK);
            let r = g.receipt(number).unwrap();
            r.set_fed(bytes.len() as u64);
            r.absorb(&bytes);
            r.wrote(2);
        }
        if step >= 2 {
            g.commit(number).unwrap();
        }
        if step >= 3 {
            assert!(begin(&mut g, OWNER, &t, "b", 2 * BLOCK as u64).is_ok());
        }
        g.release();
        assert_eq!(g.owner(), None, "step {step}");
        assert_eq!(g.staged().count(), 0);
        assert!(g.receipt(number).is_none());
        assert!(
            begin(&mut g, 8, &t, "a", 2 * BLOCK as u64).is_ok(),
            "step {step}"
        );
    }
}
