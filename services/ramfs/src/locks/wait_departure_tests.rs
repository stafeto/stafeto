// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

extern crate std;
use super::*;
use crate::{
    Fds,
    locks::{actor::Command, wait_receipts::Id, waiters::Input},
};
use proto_fs::{DataDescription, LockKind, WaitKey, WaitMode, WaitReply, WaitStart};
use std::{cell::RefCell, rc::Rc};

struct Tracked {
    id: u8,
    events: Rc<RefCell<Vec<u8>>>,
}
impl Drop for Tracked {
    fn drop(&mut self) {
        self.events.borrow_mut().push(self.id);
    }
}
pub(crate) fn fixture() -> (Ram<'static>, std::boxed::Box<Queue>, Pool, Vec<Id>) {
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
    let mut ids = Vec::new();
    for slot in 0..9 {
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
        if slot < 2 {
            queue.sleep(id, false).unwrap();
            let Command::Set(Some(kind)) = captured.request.command else {
                panic!("capture")
            };
            pool.register(Input {
                receipt: id,
                root: captured.root,
                inode: captured.request.inode,
                range: captured.request.range,
                kind,
            })
            .unwrap();
        }
        ids.push(id);
    }
    (ram, queue, pool, ids)
}

fn inode_events() -> std::boxed::Box<Events> {
    let mut allocation = std::boxed::Box::<Events>::new_uninit();
    // SAFETY: exclusive aligned complete Events allocation.
    unsafe {
        Events::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    }
}

#[test]
fn departure_releases_eight_places_after_notify_but_keeps_active_actor_paid() {
    let (mut ram, mut queue, mut pool, ids) = fixture();
    let mut inode_events = inode_events();
    for id in &ids[..2] {
        inode_events.attach(&pool, pool.find(*id).unwrap()).unwrap();
    }
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut notifications = Notifications::new();
    for (i, &id) in ids[..2].iter().enumerate() {
        notifications
            .arm(
                &mut queue,
                &pool,
                id,
                Tracked {
                    id: i as u8,
                    events: events.clone(),
                },
            )
            .unwrap();
    }
    queue
        .complete(
            ids[1],
            WaitReply {
                phase: WaitPhase::Complete,
                result: 0,
            },
        )
        .unwrap();
    queue.activate(ids[7]).unwrap();
    let progress = part(
        &mut queue,
        (&mut pool, &mut inode_events),
        &mut notifications,
        &mut ram,
        (0, 77),
        0,
        |h| h.events.borrow_mut().push(100 + h.id),
    )
    .unwrap();
    assert_eq!(
        progress,
        Progress {
            visited: 8,
            released: 7,
            cancel_actor: true
        }
    );
    assert_eq!(*events.borrow(), [100, 0, 101, 1]);
    assert_eq!(pool.count(), 0);
    assert_eq!(queue.retained(), 2);
    assert_eq!(queue.active(), Some(ids[7]));
    assert!(queue.snapshot(ids[7]).unwrap().2);
    assert_eq!(queue.query(ids[8]).unwrap().phase, WaitPhase::Queued);
    // Publication can already have succeeded when the cancellation reaches Actor.
    queue
        .complete(
            ids[7],
            WaitReply {
                phase: WaitPhase::Complete,
                result: 0,
            },
        )
        .unwrap();
    assert_eq!(queue.query(ids[7]).unwrap().result, 0);
    let last = part(
        &mut queue,
        (&mut pool, &mut inode_events),
        &mut notifications,
        &mut ram,
        (0, 77),
        8,
        |_| panic!("unarmed receipt"),
    )
    .unwrap();
    assert_eq!(
        last,
        Progress {
            visited: 8,
            released: 1,
            cancel_actor: false
        }
    );
    part(
        &mut queue,
        (&mut pool, &mut inode_events),
        &mut notifications,
        &mut ram,
        (0, 77),
        0,
        |_| panic!("duplicate notify"),
    )
    .unwrap();
    assert_eq!(queue.retained(), 0);
    assert!(!queue.retains(0, 77));
    assert_eq!(*events.borrow(), [100, 0, 101, 1]);
}

#[test]
fn full_departed_label_and_invalid_cursor_cannot_release_other_custody() {
    let (mut ram, mut queue, mut pool, ids) = fixture();
    let mut inode_events = inode_events();
    for id in &ids[..2] {
        inode_events.attach(&pool, pool.find(*id).unwrap()).unwrap();
    }
    let mut notifications = Notifications::<u8>::new();
    assert_eq!(
        part(
            &mut queue,
            (&mut pool, &mut inode_events),
            &mut notifications,
            &mut ram,
            (0, 78),
            0,
            |_| {}
        ),
        Err(proto_fs::OPEN_RETIRED)
    );
    assert_eq!(
        part(
            &mut queue,
            (&mut pool, &mut inode_events),
            &mut notifications,
            &mut ram,
            (0, 77),
            17,
            |_| {}
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(queue.retained(), 9);
    assert_eq!(queue.query(ids[0]).unwrap().phase, WaitPhase::NeedsArm);
    assert_eq!(pool.count(), 2);
}

#[test]
fn departed_event_is_detached_before_inode_reuse_in_a_different_pool_slot() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let root = ram.storage.resolve(b"/").unwrap();
    let reservation = ram
        .reserve_create(&mut fds, root, b"old", crate::REG)
        .unwrap();
    let old = ram.commit_create(&mut fds, reservation).unwrap();
    let other_fd = ram
        .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let old_fd = ram.open(&mut fds, "/old", proto_fs::READ_WRITE).unwrap();
    let mut allocation = std::boxed::Box::<Queue>::new_uninit();
    // SAFETY: exclusive aligned complete Queue allocation.
    let mut queue = unsafe {
        Queue::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    };
    let mut pool = Pool::new();
    let mut events = inode_events();
    let mut notifications = Notifications::<u8>::new();
    let admit = |ram: &mut Ram<'_>, queue: &mut Queue, pool: &mut Pool, fd: u32, key_slot: u32| {
        let (source, _) = ram.capture_description(&fds, fd).unwrap();
        let wire = WaitStart {
            key: WaitKey {
                slot: key_slot,
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
        pool.register(Input {
            receipt: id,
            root: captured.root,
            inode: captured.request.inode,
            range: captured.request.range,
            kind: crate::locks::Kind::Read,
        })
        .unwrap()
    };
    let other = admit(&mut ram, &mut queue, &mut pool, other_fd, 0);
    let retired = admit(&mut ram, &mut queue, &mut pool, old_fd, 1);
    assert_eq!(other.slot(), 0);
    assert_eq!(retired.slot(), 1);
    events.attach(&pool, other).unwrap();
    events.attach(&pool, retired).unwrap();
    let progress = part(
        &mut queue,
        (&mut pool, &mut events),
        &mut notifications,
        &mut ram,
        (0, 77),
        0,
        |_| panic!("unarmed departure"),
    )
    .unwrap();
    assert_eq!(progress.visited, 8);
    assert_eq!(progress.released, 2);
    assert_eq!(pool.count(), 0);
    assert_eq!(queue.retained(), 0);
    ram.close(&mut fds, old_fd).unwrap();
    ram.storage.unlink(root, b"old", fds.root).unwrap();
    while ram.storage.reclaim_step() {}
    let reservation = ram
        .reserve_create(&mut fds, root, b"new", crate::REG)
        .unwrap();
    let new = ram.commit_create(&mut fds, reservation).unwrap();
    assert_eq!(new.slot, old.slot);
    assert!(new.generation > old.generation);
    let new_fd = ram.open(&mut fds, "/new", proto_fs::READ_WRITE).unwrap();
    let (source, _) = ram.capture_description(&fds, new_fd).unwrap();
    let wire = WaitStart {
        key: WaitKey {
            slot: 2,
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
    let registration = pool
        .register(Input {
            receipt: id,
            root: captured.root,
            inode: captured.request.inode,
            range: captured.request.range,
            kind: crate::locks::Kind::Read,
        })
        .unwrap();
    assert_eq!(registration.slot(), other.slot());
    assert_ne!(registration.slot(), retired.slot());
    assert_eq!(events.attach(&pool, registration), Ok(()));
    events.changed(new);
    assert_eq!(events.part(&mut queue, &mut pool).unwrap().readied, 1);
    assert_eq!(
        queue.snapshot(id).unwrap().1,
        crate::locks::wait_receipts::Phase::Ready
    );
}
