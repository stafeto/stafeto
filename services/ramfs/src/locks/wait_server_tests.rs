// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

extern crate std;
use super::*;
use crate::storage::Pin;
use proto_fs::{DataDescription, LockKind, WaitMode};

fn queue() -> std::boxed::Box<Queue> {
    let mut allocation = std::boxed::Box::<Queue>::new_uninit();
    // SAFETY: exclusive uninitialized aligned allocation.
    unsafe {
        Queue::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    }
}
fn fixture() -> (Ram<'static>, Fds, WaitStart) {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let fd = ram
        .open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE)
        .unwrap();
    let (source, _) = ram.capture_description(&fds, fd).unwrap();
    let wire = WaitStart {
        key: WaitKey {
            slot: 15,
            generation: 1,
        },
        description: DataDescription {
            packed: ram.marked_open(&fds, source).unwrap(),
            generation: source.description.generation,
        },
        mode: WaitMode::Ofd,
        kind: LockKind::Write,
        whence: 1,
        start: 3,
        length: 2,
        pid: 0,
    };
    (ram, fds, wire)
}
fn done(result: u32) -> WaitReply {
    WaitReply {
        phase: WaitPhase::Complete,
        result,
    }
}

fn locks() -> std::boxed::Box<LockService> {
    let mut allocation = std::boxed::Box::<LockService>::new_uninit();
    // SAFETY: exclusive aligned allocation initialized directly.
    unsafe {
        LockService::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    }
}
fn actor_result(locks: &mut LockService, ram: &mut Ram<'_>) -> Result<Response, Error> {
    for _ in 0..10000 {
        let progress = locks.step_with_owners(&mut ram.storage, |_| true, |_| true);
        assert!(progress.visited <= 8);
        if let Some(result) = progress.completed {
            return result;
        }
    }
    panic!("genuine actor did not finish");
}

#[test]
fn genuine_wait_conflict_parks_without_actor_and_retries_original_fifo_place() {
    let (mut ram, mut fds, holder_wire) = fixture();
    let holder = ram.capture_wait(&fds, holder_wire).unwrap();
    let fd = ram
        .open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE)
        .unwrap();
    let (source, _) = ram.capture_description(&fds, fd).unwrap();
    let wire = WaitStart {
        description: DataDescription {
            packed: ram.marked_open(&fds, source).unwrap(),
            generation: source.description.generation,
        },
        ..holder_wire
    };
    let mut table = locks();
    table
        .start(&mut ram.storage, holder.request, holder.root)
        .unwrap();
    assert_eq!(actor_result(&mut table, &mut ram), Ok(Response::Changed));
    for _ in 0..1000 {
        if !table.busy() {
            break;
        }
        let progress = table.step_with_owners(&mut ram.storage, |_| true, |_| true);
        assert!(progress.visited <= 8);
        assert!(progress.completed.is_none());
    }
    assert!(!table.busy());
    let mut q = queue();
    let mut sleepers = Pool::new();
    start(&mut q, &mut ram, &fds, 0, 77, wire).unwrap();
    let id = q.occupied(0, 77, wire.key.slot).unwrap().unwrap();
    begin(&mut q, &mut table, &mut ram, id, Some(&fds)).unwrap();
    let result = actor_result(&mut table, &mut ram);
    assert!(matches!(result, Err(Error::Conflict(_))));
    let Finish::Sleeping(registration) =
        finish(&mut q, &mut sleepers, &mut ram, result, Some(&fds), |_| {
            true
        })
        .unwrap()
    else {
        panic!("real conflict was not parked")
    };
    assert_eq!(q.query(id).unwrap().phase, WaitPhase::NeedsArm);
    assert!(!q.has_work());
    assert!(!table.busy());
    assert_eq!(sleepers.count(), 1);
    q.armed(id).unwrap();
    ram.seek(&mut fds, fd, 100).unwrap();
    table
        .close(holder.request.inode, holder.request.owner)
        .unwrap();
    for _ in 0..1000 {
        if !table.busy() {
            break;
        }
        table.step_with_owners(&mut ram.storage, |_| true, |_| true);
    }
    assert!(!table.busy());
    sleepers.ready(registration).unwrap();
    assert_eq!(sleepers.run(registration).unwrap().receipt, id);
    q.ready(id).unwrap();
    begin(&mut q, &mut table, &mut ram, id, Some(&fds)).unwrap();
    let result = actor_result(&mut table, &mut ram);
    assert_eq!(result, Ok(Response::Changed));
    assert_eq!(
        finish(&mut q, &mut sleepers, &mut ram, result, Some(&fds), |_| {
            true
        }),
        Ok(Finish::Complete(id))
    );
    assert_eq!(q.query(id), Ok(done(0)));
    assert_eq!(q.snapshot(id).unwrap().0.request.range.first(), 3);
    // The service may notify and close only after this durable canonical reply.
    assert_eq!(sleepers.find(id), Some(registration));
    sleepers.complete(registration).unwrap();
    release(&mut q, &mut ram, 0, 77, wire.key).unwrap();
}

#[test]
fn genuine_actor_internal_cancel_retries_but_client_cancel_is_terminal() {
    let (mut ram, fds, wire) = fixture();
    let mut q = queue();
    let mut table = locks();
    let mut sleepers = Pool::new();
    start(&mut q, &mut ram, &fds, 0, 77, wire).unwrap();
    let id = q.occupied(0, 77, wire.key.slot).unwrap().unwrap();
    begin(&mut q, &mut table, &mut ram, id, Some(&fds)).unwrap();
    assert!(table.cancel());
    let result = actor_result(&mut table, &mut ram);
    assert_eq!(result, Err(Error::Cancelled));
    assert_eq!(
        finish(&mut q, &mut sleepers, &mut ram, result, Some(&fds), |_| {
            true
        }),
        Ok(Finish::Retried(id))
    );
    assert_eq!(q.query(id).unwrap().phase, WaitPhase::Queued);
    begin(&mut q, &mut table, &mut ram, id, Some(&fds)).unwrap();
    assert_eq!(cancel(&mut q, 0, 77, wire.key).unwrap().1, true);
    assert!(table.cancel());
    let result = actor_result(&mut table, &mut ram);
    assert_eq!(
        finish(&mut q, &mut sleepers, &mut ram, result, Some(&fds), |_| {
            true
        }),
        Ok(Finish::Complete(id))
    );
    assert_eq!(q.query(id), Ok(done(proto_fs::LOCK_CANCELLED)));
}

#[test]
fn genuine_fd_closed_before_wait_attempt_never_enters_actor() {
    let (mut ram, mut fds, wire) = fixture();
    let mut q = queue();
    let mut table = locks();
    start(&mut q, &mut ram, &fds, 0, 77, wire).unwrap();
    let id = q.occupied(0, 77, wire.key.slot).unwrap().unwrap();
    ram.close(&mut fds, wire.description.fd()).unwrap();
    begin(&mut q, &mut table, &mut ram, id, Some(&fds)).unwrap();
    assert!(!table.busy());
    assert_eq!(q.active(), None);
    assert_eq!(q.query(id), Ok(done(proto_fs::BAD_FD)));
}

#[test]
fn wait_server_replay_keeps_captured_seek_and_custody_after_real_close() {
    let (mut ram, mut fds, wire) = fixture();
    let mut q = queue();
    let before = fds.open_watermarks;
    assert_eq!(
        start(&mut q, &mut ram, &fds, 0, 77, wire).unwrap().phase,
        WaitPhase::Queued
    );
    let id = q.occupied(0, 77, 15).unwrap().unwrap();
    let captured = q.snapshot(id).unwrap().0;
    assert_eq!(captured.request.range.first(), 3);
    ram.seek(&mut fds, wire.description.fd(), 100).unwrap();
    ram.close(&mut fds, wire.description.fd()).unwrap();
    assert_eq!(
        start(&mut q, &mut ram, &fds, 0, 77, wire),
        Ok(WaitReply {
            phase: WaitPhase::Queued,
            result: 0
        })
    );
    assert_eq!(q.snapshot(id).unwrap().0, captured);
    assert_eq!(fds.open_watermarks, before);
    assert_eq!(
        ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize],
        1
    );
    assert_eq!(
        start(
            &mut q,
            &mut ram,
            &fds,
            0,
            77,
            WaitStart { start: 4, ..wire }
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    );
}

#[test]
fn wait_server_absent_cancel_and_release_fence_late_start() {
    for use_cancel in [false, true] {
        let (mut ram, fds, wire) = fixture();
        let mut q = queue();
        assert_eq!(query(&q, 0, 77, wire.key), Err(proto_fs::NO_ENTRY));
        if use_cancel {
            assert_eq!(
                cancel(&mut q, 0, 77, wire.key),
                Ok((done(proto_fs::LOCK_CANCELLED), false))
            );
        } else {
            release(&mut q, &mut ram, 0, 77, wire.key).unwrap();
        }
        assert_eq!(
            start(&mut q, &mut ram, &fds, 0, 77, wire),
            Err(proto_fs::OPEN_RETIRED)
        );
        assert_eq!(query(&q, 0, 77, wire.key), Err(proto_fs::OPEN_RETIRED));
        assert_eq!(q.retained(), 0);
        // A newly authenticated full label has an independent watermark.
        assert!(start(&mut q, &mut ram, &fds, 0, 78, wire).is_ok());
    }
}

#[test]
fn wait_server_future_or_foreign_cancel_cannot_discard_current_receipt() {
    let (mut ram, fds, wire) = fixture();
    let mut q = queue();
    start(&mut q, &mut ram, &fds, 0, 77, wire).unwrap();
    let key = WaitKey {
        generation: 2,
        ..wire.key
    };
    assert_eq!(cancel(&mut q, 0, 77, key), Err(proto_fs::JOBS_FULL));
    assert_eq!(
        release(&mut q, &mut ram, 0, 77, key),
        Err(proto_fs::JOBS_FULL)
    );
    assert_eq!(cancel(&mut q, 0, 78, wire.key), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(query(&q, 0, 77, wire.key).unwrap().phase, WaitPhase::Queued);
    assert_eq!(q.retained(), 1);
}

#[test]
fn wait_server_active_cancel_is_pending_and_canonical_success_wins() {
    let (mut ram, fds, wire) = fixture();
    let mut q = queue();
    start(&mut q, &mut ram, &fds, 0, 77, wire).unwrap();
    let id = q.occupied(0, 77, wire.key.slot).unwrap().unwrap();
    q.activate(id).unwrap();
    assert_eq!(
        release(&mut q, &mut ram, 0, 77, wire.key),
        Err(proto_fs::JOBS_FULL)
    );
    assert_eq!(
        cancel(&mut q, 0, 77, wire.key),
        Ok((
            WaitReply {
                phase: WaitPhase::Queued,
                result: 0
            },
            true
        ))
    );
    assert_eq!(q.active(), Some(id));
    q.complete(id, done(0)).unwrap();
    assert_eq!(cancel(&mut q, 0, 77, wire.key), Ok((done(0), false)));
    assert_eq!(query(&q, 0, 77, wire.key), Ok(done(0)));
    let captured = q.snapshot(id).unwrap().0;
    release(&mut q, &mut ram, 0, 77, wire.key).unwrap();
    assert_eq!(q.retained(), 0);
    assert_eq!(
        ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize],
        0
    );
    assert_eq!(
        start(&mut q, &mut ram, &fds, 0, 77, wire),
        Err(proto_fs::OPEN_RETIRED)
    );
}

#[test]
fn wait_capture_requires_real_access_and_strict_wait_input() {
    let (mut ram, mut fds, wire) = fixture();
    assert!(ram.capture_wait(&fds, wire).is_ok());
    assert_eq!(
        ram.capture_wait(
            &fds,
            WaitStart {
                kind: LockKind::Unlock,
                ..wire
            }
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(
        ram.capture_wait(&fds, WaitStart { pid: 1, ..wire }),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    let fd = ram
        .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let (source, _) = ram.capture_description(&fds, fd).unwrap();
    let readonly = WaitStart {
        description: DataDescription {
            packed: ram.marked_open(&fds, source).unwrap(),
            generation: source.description.generation,
        },
        ..wire
    };
    assert_eq!(ram.capture_wait(&fds, readonly), Err(proto_fs::BAD_FD));
    ram.close(&mut fds, fd).unwrap();
    assert_eq!(ram.capture_wait(&fds, readonly), Err(proto_fs::BAD_FD));
}
