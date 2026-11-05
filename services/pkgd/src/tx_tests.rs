// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The transactions of the store (pk3-design R7, R16.4, R16.5): an installation of one
//! package, of a group, of a replacement, a removal, new settings, a serial and a list
//! of revocations, each with a crash after every write and every flush and every
//! way the medium may keep what was not flushed; and the order of the writes, the
//! flushes and the calls to the file service of each.

use crate::commit::{self, Change, Device, Kind, Opened, Refused, Start};
use crate::store::*;
use crate::testkit::{Loss, ModelDisk};

const DISK: u64 = 131_072;

fn record(first: u64, blocks: u32, name: &str, repo: u8) -> Record {
    Record {
        kind: PACKAGE,
        flags: WORLD,
        repo,
        first,
        blocks,
        length: u64::from(blocks) * BLOCK as u64,
        number: 0,
        installed: 1,
        sha256: [4; 32],
        name: to_field(name.as_bytes()).unwrap(),
        version: to_field(b"1.0").unwrap(),
    }
}

/// A store of the packages `a` (2 blocks), `b` and `c` in places 0 to 2, with the
/// official repository, each package's data on the disk; the state is flushed.
fn store() -> (ModelDisk, Opened, Table) {
    let mut disk = ModelDisk::new(DISK);
    let mut table = Table::zeroed();
    let mut opened = commit::format(&mut disk, &mut table).unwrap();
    let mut next = Table(table.0);
    next.set_repo(0, b"stafeto", 0);
    let mut at = 20;
    for (i, name) in ["a", "b", "c"].iter().enumerate() {
        for b in 0..2 {
            disk.write(at + b, &[0xD0 + i as u8; BLOCK]).unwrap();
        }
        next.set_record(i, &record(at, 2, name, 0));
        at += 2;
    }
    disk.flush().unwrap();
    next.set_generation(opened.superblock.generation + 1);
    opened = commit::publish(&mut disk, &opened, &table, &next).unwrap();
    let mut read = Table::zeroed();
    let Start::Store(found) = commit::open(&mut disk, &mut read).unwrap() else {
        panic!("a store");
    };
    assert_eq!(found, opened);
    (disk, opened, read)
}

/// One transaction: the table it makes, the data it writes before, its layers.
struct Tx {
    next: Table,
    /// The extents the data go to, with the byte of their fill.
    data: Vec<(Extent, u8)>,
    kind: Kind,
    detach: Vec<usize>,
    attach: Vec<usize>,
    /// The change of the blocks the table names: positive adds.
    delta: i64,
}

impl Tx {
    fn new(opened: &Opened, accepted: &Table, kind: Kind) -> Tx {
        let mut next = Table(accepted.0);
        next.set_generation(opened.superblock.generation + 1);
        Tx {
            next,
            data: Vec::new(),
            kind,
            detach: Vec::new(),
            attach: Vec::new(),
            delta: 0,
        }
    }

    /// A package `name` of `blocks` in table place `slot`, its data in the first free
    /// extent of the accepted state and of this transaction.
    fn add(
        mut self,
        opened: &Opened,
        accepted: &Table,
        slot: usize,
        name: &str,
        blocks: u32,
    ) -> Tx {
        let mut held = [Extent {
            first: 0,
            blocks: 0,
        }; RECORDS + 1];
        let n = accepted.occupied(opened.table_extent(), &mut held);
        let mut taken = [Extent {
            first: 0,
            blocks: 0,
        }; RECORDS + 1];
        let m = self.next.occupied(opened.table_extent(), &mut taken);
        // The table the transaction writes also needs room: leave it to `publish`.
        let first = find_free(&held[..n], &taken[..m], DISK, u64::from(blocks)).unwrap();
        self.next.set_record(slot, &record(first, blocks, name, 0));
        self.data.push((
            Extent {
                first,
                blocks: u64::from(blocks),
            },
            0xE0u8.wrapping_add(slot as u8),
        ));
        self.delta += i64::from(blocks);
        self
    }

    fn remove(mut self, accepted: &Table, slot: usize) -> Tx {
        self.delta -= i64::from(accepted.record(slot).blocks);
        self.next.set_record(slot, &Record::EMPTY);
        self
    }

    fn data_ops(&self) -> usize {
        self.data.iter().map(|(e, _)| e.blocks as usize).sum()
    }

    fn run(
        &self,
        disk: &mut ModelDisk,
        opened: &Opened,
        accepted: &Table,
    ) -> Result<Opened, Refused> {
        for (e, fill) in &self.data {
            for b in 0..e.blocks {
                disk.write(e.first + b, &[*fill; BLOCK])?;
            }
        }
        let change = Change {
            kind: self.kind,
            detach: &self.detach,
            attach: &self.attach,
        };
        commit::transact(disk, opened, accepted, &self.next, &change)
    }
}

fn losses(pending: usize) -> Vec<Loss> {
    let mut all = vec![Loss::All, Loss::None];
    if pending <= 6 {
        all.extend((0..1u64 << pending).map(Loss::Some));
    } else {
        // Prefixes, and some subsets that no pattern picks.
        all.extend((0..=pending).map(|k| Loss::Some((1u64 << k) - 1)));
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..24 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            all.push(Loss::Some(x & ((1u64 << pending) - 1)));
        }
    }
    all
}

/// The blocks free in a table: the disk less the superblocks, its own extent and the
/// extents of its records, counted by hand.
fn free_by_hand(table: &Table) -> u64 {
    let held: u64 = (0..RECORDS)
        .map(|i| table.record(i))
        .filter(|r| r.kind != EMPTY)
        .map(|r| u64::from(r.blocks))
        .sum();
    DISK - SUPERS - TABLE_BLOCKS - held
}

/// Crashes the transaction after each of its operations in every way. The state a start
/// finds is the old one (the table `accepted` to the byte) or the new one (`tx.next`);
/// the data of the new one are whole; the free space of each is the disk less the blocks
/// its records name, and the new one differs from the old by `delta`; no start finds the new state
/// before the superblock is written, and the transaction that ran to its end is the
/// new state after any power failure.
fn matrix(tx: &Tx, disk: &ModelDisk, opened: &Opened, accepted: &Table) {
    let mut probe = disk.after(Loss::None, false);
    tx.run(&mut probe, opened, accepted).unwrap();
    let total = probe.ops;
    // The writes of the data, F1, five of the table, F2: the superblock is the next.
    let before_super = tx.data_ops() + 1 + 5 + 1;
    let old_free = free_by_hand(accepted);
    assert_eq!(old_free, commit::free_of(accepted, opened));
    let judge = |what: &str, found: &mut ModelDisk, must_be_new: Option<bool>| {
        let mut table = Table::zeroed();
        let Start::Store(now) = commit::open(found, &mut table).unwrap() else {
            panic!("no store after {what}");
        };
        let is_new = now.superblock.generation == opened.superblock.generation + 1;
        if is_new {
            assert_eq!(table.0, tx.next.0, "{what}");
            for (e, fill) in &tx.data {
                for b in 0..e.blocks {
                    assert_eq!(found.peek(e.first + b), [*fill; BLOCK], "{what}: data");
                }
            }
            assert_eq!(
                free_by_hand(&table) as i64,
                old_free as i64 - tx.delta,
                "{what}: the free space of the new state"
            );
        } else {
            assert_eq!(
                now.superblock.generation, opened.superblock.generation,
                "{what}"
            );
            assert_eq!(table.0, accepted.0, "{what}");
        }
        assert_eq!(
            commit::free_of(&table, &now),
            free_by_hand(&table),
            "{what}"
        );
        if let Some(wanted) = must_be_new {
            assert_eq!(is_new, wanted, "{what}");
        }
    };
    for limit in 0..total {
        let mut crashed = disk.after(Loss::None, false);
        crashed.limit = Some(limit);
        assert!(tx.run(&mut crashed, opened, accepted).is_err(), "{limit}");
        for loss in losses(crashed.pending()) {
            for tear in [false, true] {
                let mut found = crashed.after(loss, tear);
                // Before the superblock is accepted the state is the old one.
                let only_old = (limit <= before_super).then_some(false);
                judge(&format!("{limit} {loss:?} {tear}"), &mut found, only_old);
            }
        }
    }
    // Run to its end: the superblock and its flush are on the medium.
    for loss in [Loss::All, Loss::None] {
        for tear in [false, true] {
            let mut done = probe.after(loss, tear);
            judge("the end", &mut done, Some(true));
        }
    }
}

#[test]
fn an_installation_of_a_package_crashes_to_the_old_state_or_the_new() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install).add(&opened, &accepted, 3, "d", 3);
    tx.attach = vec![3];
    matrix(&tx, &disk, &opened, &accepted);
}

#[test]
fn a_group_of_three_crashes_to_the_old_state_or_the_new_whole() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install);
    for (slot, name, blocks) in [(3, "d", 2), (4, "e", 3), (5, "f", 1)] {
        tx = tx.add(&opened, &accepted, slot, name, blocks);
    }
    tx.attach = vec![3, 4, 5];
    matrix(&tx, &disk, &opened, &accepted);
}

#[test]
fn a_replacement_crashes_with_the_old_package_or_the_new_never_both_or_none() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install)
        .remove(&accepted, 0)
        .add(&opened, &accepted, 3, "a", 4);
    tx.detach = vec![0];
    tx.attach = vec![3];
    matrix(&tx, &disk, &opened, &accepted);
}

#[test]
fn a_removal_crashes_to_the_old_state_with_its_data_or_the_new() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Remove).remove(&accepted, 1);
    tx.detach = vec![1];
    matrix(&tx, &disk, &opened, &accepted);
}

#[test]
fn new_settings_crash_to_the_old_blob_or_the_new() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Settings);
    tx = tx.add(&opened, &accepted, SETTINGS_SLOT, "x", 2);
    let mut r = tx.next.record(SETTINGS_SLOT);
    r.kind = SETTINGS;
    r.repo = NO_REPO;
    r.name = [0; 64];
    r.version = [0; 64];
    tx.next.set_record(SETTINGS_SLOT, &r);
    tx.attach = vec![SETTINGS_NEW];
    matrix(&tx, &disk, &opened, &accepted);
}

#[test]
fn a_serial_crashes_to_the_old_number_or_the_new() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Serial);
    assert!(tx.next.set_repo(0, b"stafeto", 7));
    matrix(&tx, &disk, &opened, &accepted);
}

#[test]
fn a_list_of_revocations_crashes_to_the_old_list_or_the_new_with_its_flags() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Revoked);
    tx = tx.add(&opened, &accepted, REVOKED_SLOT, "x", 1);
    let mut list = tx.next.record(REVOKED_SLOT);
    list.kind = REVOKED_LIST;
    list.repo = NO_REPO;
    list.name = [0; 64];
    list.version = [0; 64];
    list.number = 2;
    tx.next.set_record(REVOKED_SLOT, &list);
    let mut c = tx.next.record(2);
    c.flags |= REVOKED;
    tx.next.set_record(2, &c);
    tx.detach = vec![2];
    matrix(&tx, &disk, &opened, &accepted);
}

/// The log of a transaction in short: runs of writes counted, the flushes, the points
/// and the calls to the file service.
fn shape(log: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut writes = 0;
    for line in log {
        if line.starts_with("write") {
            writes += 1;
            continue;
        }
        if writes > 0 {
            out.push(format!("w{writes}"));
            writes = 0;
        }
        out.push(match line.as_str() {
            "flush" => "F".to_string(),
            other => other.replace("point ", "@"),
        });
    }
    if writes > 0 {
        out.push(format!("w{writes}"));
    }
    out.join(" ")
}

fn run_logged(
    tx: &Tx,
    mut disk: ModelDisk,
    opened: &Opened,
    accepted: &Table,
) -> (ModelDisk, Result<Opened, Refused>) {
    disk.log.clear();
    let result = tx.run(&mut disk, opened, accepted);
    (disk, result)
}

#[test]
fn an_installation_writes_flushes_and_attaches_in_the_order_of_the_note() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install).add(&opened, &accepted, 3, "d", 3);
    tx.attach = vec![3];
    let (disk, done) = run_logged(&tx, disk, &opened, &accepted);
    done.unwrap();
    // The data, F1; the table, F2; the layer; the superblock, F3.
    assert_eq!(
        shape(&disk.log),
        "w3 F @data-flushed w1 @table-part w4 F @table-flushed attach 3 @attached w1 @super-written F @committed"
    );
    // The superblock goes into the copy with the lower generation.
    assert!(
        disk.log
            .iter()
            .any(|l| *l == format!("write {}", 1 - opened.copy))
    );
}

#[test]
fn a_group_attaches_every_package_after_the_table_and_before_the_superblock() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install);
    for (slot, name) in [(3, "d"), (4, "e"), (5, "f")] {
        tx = tx.add(&opened, &accepted, slot, name, 1);
    }
    tx.attach = vec![3, 4, 5];
    let (disk, done) = run_logged(&tx, disk, &opened, &accepted);
    done.unwrap();
    assert_eq!(
        shape(&disk.log),
        "w3 F @data-flushed w1 @table-part w4 F @table-flushed attach 3 attach 4 attach 5 @attached w1 @super-written F @committed"
    );
    assert_eq!(disk.attached.iter().copied().collect::<Vec<_>>(), [3, 4, 5]);
}

#[test]
fn a_refusal_of_the_second_package_of_a_group_undoes_the_first_and_keeps_the_old_state() {
    let (mut disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install).remove(&accepted, 0);
    for (slot, name) in [(3, "a"), (4, "e"), (5, "f")] {
        tx = tx.add(&opened, &accepted, slot, name, 1);
    }
    tx.detach = vec![0];
    tx.attach = vec![3, 4, 5];
    disk.attached.insert(0);
    disk.refuse = vec![4];
    let (disk, done) = run_logged(&tx, disk, &opened, &accepted);
    assert_eq!(done, Err(Refused::Attach(proto_pkg::CONFLICT)));
    // The replaced package leaves, the first new one comes, the second is refused: the
    // first goes and the replaced one is back; the superblock is never written.
    assert_eq!(
        shape(&disk.log),
        "w3 F @data-flushed w1 @table-part w4 F @table-flushed detach 0 attach 3 refused 4 detach 3 attach 0"
    );
    assert_eq!(disk.attached.iter().copied().collect::<Vec<_>>(), [0]);
    let mut found = disk.after(Loss::None, false);
    let mut table = Table::zeroed();
    let Start::Store(now) = commit::open(&mut found, &mut table).unwrap() else {
        panic!("a store");
    };
    assert_eq!(now.superblock.generation, opened.superblock.generation);
    assert_eq!(table.0, accepted.0);
    // Run again with the layer accepted: the state the refusal left is as good as new.
    let mut again = found.after(Loss::None, false);
    again.attached.insert(0);
    tx.run(&mut again, &now, &table).unwrap();
}

#[test]
fn a_removal_detaches_after_the_superblock_is_flushed() {
    let (disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Remove).remove(&accepted, 1);
    tx.detach = vec![1];
    let (disk, done) = run_logged(&tx, disk, &opened, &accepted);
    done.unwrap();
    assert_eq!(
        shape(&disk.log),
        "F @data-flushed w1 @table-part w4 F @remove-table w1 @super-written F @remove-committed detach 1"
    );
}

#[test]
fn a_new_settings_layer_replaces_the_old_one_and_comes_back_on_a_refusal() {
    let (mut disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Settings);
    tx.detach = vec![SETTINGS_SLOT];
    tx.attach = vec![SETTINGS_NEW];
    disk.attached.insert(SETTINGS_SLOT);
    let (ok, done) = run_logged(&tx, disk.after(Loss::None, false), &opened, &accepted);
    done.unwrap();
    assert!(
        shape(&ok.log).ends_with(
            "@settings-table detach 64 attach 66 @attached w1 @super-written F @committed"
        )
    );
    let mut refused = disk.after(Loss::None, false);
    refused.attached.insert(SETTINGS_SLOT);
    refused.refuse = vec![SETTINGS_NEW];
    let (refused, done) = run_logged(&tx, refused, &opened, &accepted);
    assert_eq!(done, Err(Refused::Attach(proto_pkg::CONFLICT)));
    assert!(shape(&refused.log).ends_with("detach 64 refused 66 attach 64"));
    assert_eq!(
        refused.attached.iter().copied().collect::<Vec<_>>(),
        [SETTINGS_SLOT]
    );
}

#[test]
fn a_failed_write_of_the_superblock_takes_the_layers_back() {
    let (mut disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install).add(&opened, &accepted, 3, "d", 2);
    tx.attach = vec![3];
    // The writes of the data, F1, the table, F2: the superblock is the operation after.
    disk.limit = Some(disk.ops + tx.data_ops() + 1 + 5 + 1);
    let (disk, done) = run_logged(&tx, disk, &opened, &accepted);
    assert_eq!(done, Err(Refused::Io));
    assert!(
        shape(&disk.log).ends_with("attach 3 @attached detach 3"),
        "{}",
        shape(&disk.log)
    );
    assert!(disk.attached.is_empty());
}

#[test]
fn a_failed_flush_of_the_data_stops_before_any_table_is_written() {
    let (mut disk, opened, accepted) = store();
    let mut tx = Tx::new(&opened, &accepted, Kind::Install).add(&opened, &accepted, 3, "d", 2);
    tx.attach = vec![3];
    disk.limit = Some(disk.ops + tx.data_ops());
    let (disk, done) = run_logged(&tx, disk, &opened, &accepted);
    assert_eq!(done, Err(Refused::Io));
    assert!(disk.attached.is_empty());
    assert_eq!(
        disk.log.iter().filter(|l| l.starts_with("write")).count(),
        2
    );
}

#[test]
fn a_disk_with_no_room_for_the_next_table_refuses_before_any_layer_is_touched() {
    // The records name everything after the table: no run of five blocks is free.
    let mut accepted = Table::zeroed();
    accepted.init(2);
    accepted.set_repo(0, b"stafeto", 0);
    accepted.set_record(0, &record(7, (DISK - 7) as u32, "a", 0));
    let mut disk = ModelDisk::new(DISK);
    let opened = Opened {
        superblock: commit::superblock_of(DISK, &accepted, 2),
        copy: 0,
    };
    let mut next = Table(accepted.0);
    next.set_generation(3);
    next.set_record(1, &record(7, 1, "b", 0));
    let change = Change {
        kind: Kind::Install,
        detach: &[],
        attach: &[1],
    };
    let done = commit::transact(&mut disk, &opened, &accepted, &next, &change);
    assert_eq!(done, Err(Refused::NoSpace));
    assert!(disk.attached.is_empty());
    assert_eq!(shape(&disk.log), "F @data-flushed");
}
