// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
extern crate std;
use super::super::Range;
use super::*;
use crate::{Fds, Ram};
use proto_fs::{DataDescription, LockKind, WaitKey, WaitMode, WaitStart};
use std::boxed::Box;

struct Fixture {
    ram: Ram<'static>,
    locks: Box<SimpleLocks>,
    waits: Box<Waits<u32>>,
    queue: Box<Queue>,
    captured: Captured,
    wire: WaitStart,
}
impl Fixture {
    fn new() -> Self {
        let mut ram = Ram::default();
        let mut fds = Fds::default();
        let fd = ram
            .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        let (source, _) = ram.capture_description(&fds, fd).unwrap();
        let (inode, _) = ram.live_description(&fds, source).unwrap();
        let wire = WaitStart {
            key: WaitKey {
                slot: 0,
                generation: 1,
            },
            description: DataDescription {
                packed: ram.marked_open(&fds, source).unwrap(),
                generation: source.description.generation,
            },
            mode: WaitMode::Pid,
            kind: LockKind::Write,
            whence: 0,
            start: 0,
            length: 1,
            pid: 256,
        };
        let captured = Captured {
            request: Request {
                inode,
                owner: Owner::Process(256),
                root: 0,
                range: Range::relative(0, 0, 1).unwrap(),
                command: Command::Set(Some(Kind::Write)),
            },
            root: storage::BOOT_ROOT,
            source,
            unlocked_query: false,
        };
        let mut locks = Box::<SimpleLocks>::new_uninit();
        let mut waits = Box::<Waits<u32>>::new_uninit();
        let mut queue = Box::<Queue>::new_uninit();
        unsafe {
            SimpleLocks::initialize_at(locks.as_mut_ptr());
            Waits::initialize_at(waits.as_mut_ptr());
            Queue::initialize_at(queue.as_mut_ptr());
        }
        Self {
            ram,
            locks: unsafe { locks.assume_init() },
            waits: unsafe { waits.assume_init() },
            queue: unsafe { queue.assume_init() },
            captured,
            wire,
        }
    }
    fn hold(&mut self, pid: u32, byte: i64, kind: Kind) {
        let mut request = self.captured.request;
        request.owner = Owner::Process(pid);
        request.range = Range::relative(0, byte, 1).unwrap();
        request.command = Command::Set(Some(kind));
        self.locks
            .set(&mut self.ram.storage, storage::BOOT_ROOT, request, |_| true)
            .unwrap();
    }
    fn wait(&mut self, place: usize, pid: u32, byte: i64) -> Id {
        let mut captured = self.captured;
        captured.request.owner = Owner::Process(pid);
        captured.request.range = Range::relative(0, byte, 1).unwrap();
        let wire = WaitStart {
            pid: pid as i32,
            start: byte,
            ..self.wire
        };
        let id = self
            .queue
            .admit(
                place,
                41 + place as u64,
                wire,
                captured,
                &mut self.ram.storage,
            )
            .unwrap();
        self.waits.register(&mut self.queue, id).unwrap();
        id
    }
    fn query(&mut self, id: Id) -> WaitReply {
        self.waits
            .query(
                &mut self.queue,
                &mut self.locks,
                &mut self.ram.storage,
                id,
                true,
                |_| true,
            )
            .unwrap()
    }
    fn tick(&mut self) {
        self.waits.maintenance(
            &mut self.queue,
            &mut self.locks,
            &mut self.ram.storage,
            |_, _| true,
            |_| true,
            |_| {},
        );
    }
    fn settle(&mut self, id: Id) -> WaitReply {
        for _ in 0..4096 {
            self.tick();
            let reply = self.query(id);
            if reply.phase != WaitPhase::Queued {
                return reply;
            }
        }
        panic!("bounded graph did not settle");
    }
}

#[test]
fn all_reader_blockers_and_second_waiter_of_one_pid_are_followed() {
    let mut f = Fixture::new();
    f.hold(257, 0, Kind::Read);
    f.hold(258, 0, Kind::Read);
    f.hold(256, 1, Kind::Write);
    f.hold(259, 2, Kind::Write);
    let unrelated = f.wait(0, 258, 2);
    let cycle = f.wait(1, 258, 1);
    let target = f.wait(2, 256, 0);
    assert_eq!(f.query(target).phase, WaitPhase::Queued);
    assert_eq!(f.settle(target).result, proto_fs::LOCK_DEADLOCK);
    assert_ne!(f.queue.query(unrelated).unwrap().phase, WaitPhase::Complete);
    assert_ne!(f.queue.query(cycle).unwrap().phase, WaitPhase::Complete);
}

#[test]
fn cancel_between_cycle_validation_and_publication_discards_stale_edge() {
    let mut f = Fixture::new();
    f.hold(256, 0, Kind::Write);
    f.hold(257, 1, Kind::Write);
    let other = f.wait(0, 257, 0);
    let target = f.wait(1, 256, 1);
    f.query(target);
    for _ in 0..4096 {
        f.tick();
        if f.waits
            .check_ref()
            .is_some_and(|check| check.path_len == 2 && check.validation == 2)
        {
            break;
        }
    }
    assert!(
        f.waits
            .check_ref()
            .is_some_and(|check| check.path_len == 2 && check.validation == 2)
    );
    f.waits.cancel(&mut f.queue, other).unwrap();
    f.tick();
    assert_ne!(
        f.queue.query(target).unwrap().result,
        proto_fs::LOCK_DEADLOCK
    );
    assert_eq!(f.settle(target).phase, WaitPhase::NeedsArm);
}

#[test]
fn writer_fifo_prevents_reader_bypass_and_notification_never_grants() {
    let mut f = Fixture::new();
    f.hold(256, 0, Kind::Read);
    let first = f.wait(0, 257, 0);
    assert_eq!(f.settle(first).phase, WaitPhase::NeedsArm);
    let second = f.wait(1, 258, 0);
    let slot = f.waits.slot(second).unwrap();
    f.waits.registrations[slot]
        .as_mut()
        .unwrap()
        .captured
        .request
        .command = Command::Set(Some(Kind::Read));
    let reader = f.waits.registrations[slot]
        .as_ref()
        .unwrap()
        .captured
        .request;
    assert!(
        f.waits
            .older_conflict(reader, Some(second), |_| true)
            .is_some()
    );
    f.waits.arm(&mut f.queue, first, 7).unwrap();
    f.locks
        .close(
            &mut f.ram.storage,
            f.captured.request.inode,
            Owner::Process(256),
        )
        .unwrap();
    f.waits.changed(f.captured.request.inode);
    let mut notifications = 0;
    for _ in 0..CAPACITY {
        f.waits.maintenance(
            &mut f.queue,
            &mut f.locks,
            &mut f.ram.storage,
            |_, _| true,
            |_| true,
            |_| notifications += 1,
        );
    }
    assert!(notifications > 0);
    assert_ne!(f.queue.query(first).unwrap().phase, WaitPhase::Complete);
    assert_eq!(
        f.query(first),
        WaitReply {
            phase: WaitPhase::Complete,
            result: 0
        }
    );
    assert_eq!(f.queue.query(first).unwrap(), f.query(first));
    f.waits.release_registration(first);
    f.queue.release(first, &mut f.ram.storage).unwrap();
}

#[test]
fn lost_source_completes_bad_fd_without_installing_lock() {
    let mut f = Fixture::new();
    let id = f.wait(0, 256, 0);
    let reply = f
        .waits
        .query(
            &mut f.queue,
            &mut f.locks,
            &mut f.ram.storage,
            id,
            false,
            |_| true,
        )
        .unwrap();
    assert_eq!(reply.result, proto_fs::BAD_FD);
    assert!(!f.locks.has_locks());
    f.waits.release_registration(id);
    f.queue.release(id, &mut f.ram.storage).unwrap();
    assert_eq!(f.waits.count(), 0);
}

#[test]
fn same_owner_replacement_does_not_wait_behind_its_own_fifo_entry() {
    let mut f = Fixture::new();
    let id = f.wait(0, 256, 0);
    let request = f.queue.snapshot(id).unwrap().0.request;
    assert!(f.waits.older_conflict(request, None, |_| true).is_none());
    let mut different = request;
    different.owner = Owner::Process(257);
    assert!(f.waits.older_conflict(different, None, |_| true).is_some());
    let slot = f.waits.slot(id).unwrap();
    let owner = Owner::Description {
        slot: 7,
        generation: 11,
    };
    f.waits.registrations[slot]
        .as_mut()
        .unwrap()
        .captured
        .request
        .owner = owner;
    different.owner = owner;
    assert!(f.waits.older_conflict(different, None, |_| true).is_none());
}

#[test]
fn recycled_pid_bucket_without_exact_waiter_is_not_a_depth_limit_error() {
    let mut f = Fixture::new();
    f.hold(513, 0, Kind::Write);
    f.wait(0, 257, 1); // Retained older generation in the same PID slot.
    f.wait(1, 769, 2); // A second generation makes this bucket mixed.
    let target = f.wait(2, 256, 0);
    f.query(target);
    f.waits.check_mut().unwrap().vertices[0].depth = 15;
    assert_eq!(f.settle(target).phase, WaitPhase::NeedsArm);
    assert_ne!(f.queue.query(target).unwrap().result, proto_fs::NO_LOCKS);
}

#[test]
fn released_fifo_blocker_between_snapshot_and_visit_cannot_alias_new_registration() {
    let mut f = Fixture::new();
    f.hold(256, 0, Kind::Write);
    let older = f.wait(0, 257, 0);
    let target = f.wait(1, 258, 0);
    f.query(target);
    for _ in 0..4096 {
        if f.waits
            .check_ref()
            .is_some_and(|check| check.blockers_len == 2 && check.blocker == 1)
        {
            break;
        }
        f.tick();
    }
    assert!(
        f.waits
            .check_ref()
            .is_some_and(|check| check.blockers_len == 2 && check.blocker == 1)
    );
    f.waits.cancel(&mut f.queue, older).unwrap();
    f.waits.release_registration(older);
    f.queue.release(older, &mut f.ram.storage).unwrap();
    f.tick();
    assert_eq!(f.settle(target).phase, WaitPhase::NeedsArm);
}

#[test]
fn dead_pid_with_retained_source_cannot_publish_set_and_cancel_replays() {
    let mut f = Fixture::new();
    let id = f.wait(0, 256, 0);
    let reply = f
        .waits
        .query(
            &mut f.queue,
            &mut f.locks,
            &mut f.ram.storage,
            id,
            true,
            |_| false,
        )
        .unwrap();
    assert_eq!(reply.result, proto_fs::LOCK_CANCELLED);
    assert!(!f.locks.has_locks());
    assert_eq!(f.query(id), reply);
    f.waits.release_registration(id);
    f.queue.release(id, &mut f.ram.storage).unwrap();
}
