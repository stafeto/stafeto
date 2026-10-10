// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

extern crate std;
use super::*;
use crate::{
    Fds, Ram,
    locks::{actor::Command, waiters::Input},
};
use proto_fs::{DataDescription, LockKind, WaitKey, WaitMode, WaitStart};
use std::{cell::RefCell, rc::Rc};

struct Tracked {
    id: u8,
    closed: Rc<RefCell<Vec<u8>>>,
}
impl Drop for Tracked {
    fn drop(&mut self) {
        self.closed.borrow_mut().push(self.id);
    }
}
fn handle(id: u8, closed: &Rc<RefCell<Vec<u8>>>) -> Tracked {
    Tracked {
        id,
        closed: closed.clone(),
    }
}
fn fixture() -> (Ram<'static>, std::boxed::Box<Queue>, Pool, Id) {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let fd = ram
        .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let (source, _) = ram.capture_description(&fds, fd).unwrap();
    let wire = WaitStart {
        key: WaitKey {
            slot: 0,
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
    let mut allocation = std::boxed::Box::<Queue>::new_uninit();
    // SAFETY: exclusive aligned allocation initialized directly.
    let mut q = unsafe {
        Queue::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    };
    let id = q.admit(0, 77, wire, captured, &mut ram.storage).unwrap();
    q.sleep(id, false).unwrap();
    let Command::Set(Some(kind)) = captured.request.command else {
        panic!("genuine capture")
    };
    let mut pool = Pool::new();
    pool.register(Input {
        receipt: id,
        root: captured.root,
        inode: captured.request.inode,
        range: captured.request.range,
        kind,
    })
    .unwrap();
    (ram, q, pool, id)
}
fn done() -> WaitReply {
    WaitReply {
        phase: WaitPhase::Complete,
        result: 0,
    }
}

#[test]
fn canonical_reply_precedes_notify_and_final_close_before_place_reuse() {
    let (_ram, mut q, mut pool, id) = fixture();
    let closed = Rc::new(RefCell::new(Vec::new()));
    let mut notifications = Notifications::new();
    assert_eq!(
        notifications
            .arm(&mut q, &pool, id, handle(1, &closed))
            .unwrap()
            .phase,
        WaitPhase::Sleeping
    );
    assert!(closed.borrow().is_empty());
    notifications
        .arm(&mut q, &pool, id, handle(2, &closed))
        .unwrap();
    assert_eq!(*closed.borrow(), [2]);
    assert_eq!(
        notifications.complete(&q, &mut pool, id, |_| panic!("unfinished notify")),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    q.complete(id, done()).unwrap();
    let mut told = 0;
    notifications
        .complete(&q, &mut pool, id, |h| {
            assert_eq!(q.query(id), Ok(done()));
            assert_eq!(h.id, 1);
            assert_eq!(*closed.borrow(), [2]);
            told += 1;
        })
        .unwrap();
    assert_eq!(told, 1);
    assert_eq!(*closed.borrow(), [2, 1]);
    assert_eq!(pool.count(), 0);
    assert_eq!(q.retained(), 1);
    notifications
        .complete(&q, &mut pool, id, |_| panic!("duplicate notify"))
        .unwrap();
}

#[test]
fn late_arm_preserves_active_attempt_and_complete_arm_only_returns_receipt() {
    let (_ram, mut q, mut pool, id) = fixture();
    let mut notifications = Notifications::new();
    let closed = Rc::new(RefCell::new(Vec::new()));
    q.ready(id).unwrap();
    q.activate(id).unwrap();
    assert_eq!(
        notifications
            .arm(&mut q, &pool, id, handle(1, &closed))
            .unwrap()
            .phase,
        WaitPhase::Queued
    );
    assert_eq!(q.active(), Some(id));
    q.sleep(id, false).unwrap();
    assert_eq!(q.query(id).unwrap().phase, WaitPhase::Sleeping);
    q.complete(id, done()).unwrap();
    notifications.complete(&q, &mut pool, id, |_| {}).unwrap();
    assert_eq!(
        notifications.arm(&mut q, &pool, id, handle(2, &closed)),
        Ok(done())
    );
    assert_eq!(*closed.borrow(), [1, 2]);
    assert_eq!(pool.count(), 0);
}

#[test]
fn stale_full_receipt_cannot_replace_or_close_reused_notifications() {
    let (mut ram, mut q, mut pool, old) = fixture();
    let original = q.snapshot(old).unwrap().0;
    let closed = Rc::new(RefCell::new(Vec::new()));
    let mut notifications = Notifications::new();
    notifications
        .arm(&mut q, &pool, old, handle(1, &closed))
        .unwrap();
    q.complete(old, done()).unwrap();
    notifications.complete(&q, &mut pool, old, |_| {}).unwrap();
    q.release(old, &mut ram.storage).unwrap();
    let next = Id::new(
        0,
        77,
        WaitKey {
            slot: 0,
            generation: 2,
        },
    )
    .unwrap();
    // Reuse the exact place with a new full receipt using genuine captured authority.
    let wire = WaitStart {
        key: next.key(),
        description: DataDescription {
            packed: original.source.fd
                | u32::from(original.source.description.slot) << proto_fs::OPEN_DESCRIPTION_SHIFT,
            generation: original.source.description.generation,
        },
        mode: WaitMode::Ofd,
        kind: LockKind::Read,
        whence: 0,
        start: 0,
        length: 2,
        pid: 0,
    };
    assert_eq!(q.admit(0, 77, wire, original, &mut ram.storage), Ok(next));
    q.sleep(next, false).unwrap();
    pool.register(Input {
        receipt: next,
        root: original.root,
        inode: original.request.inode,
        range: original.request.range,
        kind: crate::locks::Kind::Read,
    })
    .unwrap();
    notifications
        .arm(&mut q, &pool, next, handle(2, &closed))
        .unwrap();
    assert_eq!(
        notifications.arm(&mut q, &pool, old, handle(3, &closed)),
        Err(proto_fs::OPEN_RETIRED)
    );
    assert_eq!(*closed.borrow(), [1, 3]);
    q.complete(next, done()).unwrap();
    notifications
        .complete(&q, &mut pool, next, |h| assert_eq!(h.id, 2))
        .unwrap();
    assert_eq!(*closed.borrow(), [1, 3, 2]);
}
