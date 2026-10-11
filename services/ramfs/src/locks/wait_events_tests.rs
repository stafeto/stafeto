// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

extern crate std;
use super::*;
use crate::{
    Fds, Ram,
    locks::{actor::Command, wait_receipts::Id, waiters::Input},
};
use proto_fs::{DataDescription, LockKind, WaitKey, WaitMode, WaitStart};

fn events() -> std::boxed::Box<Events> {
    let mut allocation = std::boxed::Box::<Events>::new_uninit();
    // SAFETY: exclusive aligned allocation initialized directly.
    unsafe {
        Events::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    }
}

#[test]
fn exact_inode_generation_wakes_once_without_downgrading_running_attempt() {
    let (_ram, mut queue, mut pool, ids) = super::super::wait_departure::tests::fixture();
    let a = pool.find(ids[0]).unwrap();
    let b = pool.find(ids[1]).unwrap();
    let inode = pool.snapshot(a).unwrap().0.inode;
    let mut events = events();
    events.attach(&pool, a).unwrap();
    events.attach(&pool, b).unwrap();
    events.changed(Token {
        generation: inode.generation + 1,
        ..inode
    });
    assert!(!events.pending());
    events.changed(Token {
        slot: inode.slot + 1,
        ..inode
    });
    assert!(!events.pending());
    events.changed(inode);
    assert_eq!(
        events.part(&mut queue, &mut pool).unwrap(),
        Progress {
            visited: 2,
            readied: 2
        }
    );
    assert!(!events.pending());
    assert_eq!(
        queue.query(ids[0]).unwrap().phase,
        proto_fs::WaitPhase::Queued
    );
    pool.run(a).unwrap();
    queue.activate(ids[0]).unwrap();
    events.poll();
    assert_eq!(events.part(&mut queue, &mut pool).unwrap().readied, 0);
    assert_eq!(pool.snapshot(a).unwrap().1, Phase::Running);
    assert_eq!(queue.active(), Some(ids[0]));
    queue.sleep(ids[0], false).unwrap();
    pool.sleep(a).unwrap();
    events.changed(inode);
    assert_eq!(events.part(&mut queue, &mut pool).unwrap().readied, 1);
    assert_eq!(pool.snapshot(a).unwrap().1, Phase::Ready);
}

#[test]
fn reused_pool_slot_retires_old_index_and_stale_detach_preserves_new_receipt() {
    let (_ram, _queue, mut pool, ids) = super::super::wait_departure::tests::fixture();
    let old = pool.find(ids[0]).unwrap();
    let (input, _) = pool.snapshot(old).unwrap();
    let mut events = events();
    events.attach(&pool, old).unwrap();
    events.changed(input.inode);
    pool.complete(old).unwrap();
    let next = pool
        .register(Input {
            receipt: Id::new(
                0,
                77,
                WaitKey {
                    slot: 0,
                    generation: 2,
                },
            )
            .unwrap(),
            inode: Token {
                generation: input.inode.generation + 1,
                ..input.inode
            },
            ..input
        })
        .unwrap();
    assert_eq!(next.slot(), old.slot());
    events.attach(&pool, next).unwrap();
    assert!(!events.pending());
    assert_eq!(events.detach(old), Err(proto_fs::OPEN_RETIRED));
    events.changed(input.inode);
    assert!(!events.pending());
    events.changed(pool.snapshot(next).unwrap().0.inode);
    assert!(events.pending());
    events.detach(next).unwrap();
    assert!(!events.pending());
    events.changed(pool.snapshot(next).unwrap().0.inode);
    assert!(!events.pending());
}

#[test]
fn sixteen_paid_waits_on_four_billing_roots_wake_in_two_eight_cell_portions() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let fd = ram
        .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let (source, _) = ram.capture_description(&fds, fd).unwrap();
    let mut allocation = std::boxed::Box::<Queue>::new_uninit();
    // SAFETY: exclusive aligned allocation initialized directly.
    let mut queue = unsafe {
        Queue::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    };
    let mut pool = Pool::new();
    let mut events = events();
    for slot in 0..16 {
        // Genuine capture and root anchor retain each independently paid billing root.
        fds.root = crate::storage::Root {
            id: 10 + u64::from(slot / 4),
            generation: 1,
        };
        let wire = WaitStart {
            key: WaitKey {
                slot,
                generation: 1,
            },
            description: DataDescription {
                packed: ram.marked_open(&fds, source).unwrap(),
                generation: source.description.generation,
            },
            mode: WaitMode::Ofd,
            kind: LockKind::Read,
            whence: 0,
            start: 0,
            length: 2,
            pid: 0,
        };
        let captured = ram.capture_wait(&fds, wire).unwrap();
        let id = queue
            .admit(0, 77, wire, captured, &mut ram.storage)
            .unwrap();
        queue.sleep(id, false).unwrap();
        let Command::Set(Some(kind)) = captured.request.command else {
            panic!("capture")
        };
        let registration = pool
            .register(Input {
                receipt: id,
                root: captured.root,
                inode: captured.request.inode,
                range: captured.request.range,
                kind,
            })
            .unwrap();
        events.attach(&pool, registration).unwrap();
    }
    events.poll();
    for _ in 0..2 {
        assert_eq!(
            events.part(&mut queue, &mut pool).unwrap(),
            Progress {
                visited: 8,
                readied: 8
            }
        );
    }
    assert!(!events.pending());
    assert!(queue.has_work());
    std::println!("WAIT Events {} bytes", core::mem::size_of::<Events>());
    assert!(core::mem::size_of::<Events>() <= 24 * 1024);
}
