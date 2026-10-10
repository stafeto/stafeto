// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::{
    Kind, Range,
    wait_receipts::Id,
    waiters::{CAPACITY, Input, Phase, Pool},
};
use crate::storage::{Root, Token};
use proto_fs::WaitKey;

fn input(number: usize, root: u64) -> Input {
    Input {
        receipt: Id::new(
            number / 16,
            0x100 + number as u64,
            WaitKey {
                slot: (number % 16) as u32,
                generation: 1,
            },
        )
        .unwrap(),
        root: Root {
            id: root,
            generation: 7,
        },
        inode: Token {
            slot: 3,
            generation: 9,
        },
        range: Range::relative(0, 20, 4).unwrap(),
        kind: Kind::Write,
    }
}

fn order(pool: &Pool) -> Vec<Id> {
    let mut found = Vec::new();
    let mut cursor = pool.cursor();
    while !cursor.done() {
        assert!(
            pool.scan(&mut cursor, |_, input, _| found.push(input.receipt))
                .unwrap()
                <= 8
        );
    }
    found
}

#[test]
fn wait_registration_limits_charge_full_root_and_refund_terminal_place() {
    let mut pool = Pool::new();
    let first = pool.register(input(0, 10)).unwrap();
    for number in 1..4 {
        pool.register(input(number, 10)).unwrap();
    }
    assert_eq!(pool.register(input(4, 10)), Err(proto_fs::NO_LOCKS));
    let mut next_life = input(4, 10);
    next_life.root.generation += 1;
    pool.register(next_life).unwrap();
    for number in 5..16 {
        pool.register(input(number, 20 + (number / 4) as u64))
            .unwrap();
    }
    assert_eq!(pool.count(), CAPACITY);
    assert_eq!(pool.register(input(16, 30)), Err(proto_fs::NO_LOCKS));
    assert_eq!(pool.complete(first).unwrap(), input(0, 10));
    pool.register(input(16, 10)).unwrap();
    assert_eq!(pool.count(), CAPACITY);
    println!(
        "WAIT registration Pool: {} bytes",
        core::mem::size_of::<Pool>()
    );
    assert!(core::mem::size_of::<Pool>() <= 2048);
}

#[test]
fn wait_registration_duplicate_is_immutable_and_keeps_fifo_on_conflict() {
    let mut pool = Pool::new();
    let first = pool.register(input(0, 10)).unwrap();
    let second = pool.register(input(1, 10)).unwrap();
    assert_eq!(pool.register(input(0, 10)).unwrap(), first);
    let mut changed = input(0, 10);
    changed.range = Range::relative(0, 21, 4).unwrap();
    assert_eq!(pool.register(changed), Err(proto_fs::INVALID_ARGUMENT));
    assert_eq!(pool.count(), 2);
    assert_eq!(pool.run(first), Err(proto_fs::JOBS_FULL));
    pool.ready(first).unwrap();
    assert_eq!(pool.run(first).unwrap(), input(0, 10));
    pool.ready(first).unwrap();
    assert_eq!(pool.snapshot(first).unwrap().1, Phase::Running);
    pool.sleep(first).unwrap();
    assert_eq!(
        order(&pool),
        vec![input(0, 10).receipt, input(1, 10).receipt]
    );
    assert_eq!(pool.snapshot(second).unwrap().1, Phase::Sleeping);
}

#[test]
fn wait_registration_old_token_and_scan_cannot_touch_reused_slot() {
    let mut pool = Pool::new();
    let old = pool.register(input(0, 10)).unwrap();
    let mut cursor = pool.cursor();
    pool.complete(old).unwrap();
    let mut replacement = input(0, 10);
    replacement.receipt = Id::new(
        0,
        0x100,
        WaitKey {
            slot: 0,
            generation: 2,
        },
    )
    .unwrap();
    let current = pool.register(replacement).unwrap();
    assert_eq!(pool.ready(old), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(pool.complete(old), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(
        pool.scan(&mut cursor, |_, _, _| panic!(
            "old cursor obtained new authority"
        )),
        Err(proto_fs::OPEN_RETIRED)
    );
    assert_eq!(
        pool.snapshot(current).unwrap(),
        (replacement, Phase::Sleeping)
    );
    assert_eq!(pool.count(), 1);
}

#[test]
fn wait_registration_scans_eight_and_unlinks_head_middle_tail() {
    let mut pool = Pool::new();
    let tokens: Vec<_> = (0..16)
        .map(|number| pool.register(input(number, (number / 4) as u64)).unwrap())
        .collect();
    let mut cursor = pool.cursor();
    let mut seen = Vec::new();
    assert_eq!(
        pool.scan(&mut cursor, |_, input, _| seen.push(input.receipt))
            .unwrap(),
        8
    );
    assert!(!cursor.done());
    assert_eq!(
        pool.scan(&mut cursor, |_, input, _| seen.push(input.receipt))
            .unwrap(),
        8
    );
    assert!(cursor.done());
    assert_eq!(
        seen,
        (0..16)
            .map(|n| input(n, (n / 4) as u64).receipt)
            .collect::<Vec<_>>()
    );
    for number in [0, 7, 15] {
        pool.complete(tokens[number]).unwrap();
    }
    assert_eq!(
        order(&pool),
        (1..15)
            .filter(|&n| n != 7)
            .map(|n| input(n, (n / 4) as u64).receipt)
            .collect::<Vec<_>>()
    );
    for number in (1..15).filter(|&n| n != 7) {
        pool.complete(tokens[number]).unwrap();
    }
    assert_eq!(pool.count(), 0);
    assert!(pool.cursor().done());
    let newest = pool.register(input(32, 20)).unwrap();
    assert_eq!(order(&pool), vec![input(32, 20).receipt]);
    pool.complete(newest).unwrap();
    assert!(pool.cursor().done());
}

#[test]
fn wait_registration_preserves_captured_inode_range_and_full_receipt_label() {
    let mut pool = Pool::new();
    let first = pool.register(input(0, 10)).unwrap();
    let mut another = input(0, 10);
    another.receipt = Id::new(
        0,
        0x200,
        WaitKey {
            slot: 0,
            generation: 1,
        },
    )
    .unwrap();
    another.inode.generation += 1;
    let second = pool.register(another).unwrap();
    pool.ready(first).unwrap();
    pool.run(first).unwrap();
    pool.sleep(first).unwrap();
    assert_eq!(pool.snapshot(first).unwrap().0, input(0, 10));
    assert_eq!(pool.snapshot(second).unwrap().0, another);
    let mut invalid = input(2, 30);
    invalid.root.generation = 0;
    assert_eq!(pool.register(invalid), Err(proto_fs::INVALID_ARGUMENT));
    invalid = input(2, 30);
    invalid.inode.generation = 0;
    assert_eq!(pool.register(invalid), Err(proto_fs::INVALID_ARGUMENT));
}
