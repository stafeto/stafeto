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
