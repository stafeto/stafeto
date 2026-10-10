// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
extern crate std;
use super::*;
use crate::{Fds, Ram, storage::Root};
use proto_fs::{DataDescription, LockCommand, LockKind, LockStart, OpenKey, WaitMode};

fn queue() -> std::boxed::Box<Queue> {
    let mut allocation = std::boxed::Box::<Queue>::new_uninit();
    // SAFETY: exclusive aligned allocation initialized in place.
    unsafe {
        Queue::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    }
}
fn fixture(ram: &mut Ram<'_>) -> (WaitStart, Captured) {
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
        whence: 1,
        start: 3,
        length: 2,
        pid: 0,
    };
    let capture = LockStart {
        key: OpenKey {
            slot: 32,
            generation: 1,
        },
        description: wire.description,
        command: LockCommand::SetOfd,
        kind: wire.kind,
        whence: wire.whence,
        start: wire.start,
        length: wire.length,
        pid: 0,
    };
    (wire, ram.capture_lock(&fds, capture).unwrap())
}
fn done(result: u32) -> WaitReply {
    WaitReply {
        phase: WaitPhase::Complete,
        result,
    }
}
fn pins(ram: &Ram<'_>, captured: Captured) -> u16 {
    ram.storage.node(captured.request.inode).unwrap().pins[Pin::Lock as usize]
}

#[test]
fn real_custody_survives_sleep_cancel_and_terminal_release() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    let id = q.admit(0, 41, wire, captured, &mut ram.storage).unwrap();
    assert_eq!(pins(&ram, captured), 1);
    assert_eq!(q.retained(), 1);
    assert!(q.has_work());
    assert_eq!(q.release(id, &mut ram.storage), Err(proto_fs::JOBS_FULL));
    q.activate(id).unwrap();
    assert_eq!(q.release(id, &mut ram.storage), Err(proto_fs::JOBS_FULL));
    q.sleep(id, false).unwrap();
    assert!(!q.has_work());
    assert_eq!(q.active(), None);
    assert_eq!(q.query(id).unwrap().phase, WaitPhase::NeedsArm);
    assert_eq!(pins(&ram, captured), 1);
    assert_eq!(q.release(id, &mut ram.storage), Err(proto_fs::JOBS_FULL));
    assert_eq!(q.request_cancel(id), Ok(false));
    assert_eq!(q.query(id), Ok(done(proto_fs::LOCK_CANCELLED)));
    assert_eq!(pins(&ram, captured), 1);
    assert_eq!(q.retained(), 1);
    assert!(!q.has_work());
    assert_eq!(q.query(id), Ok(done(proto_fs::LOCK_CANCELLED)));
    q.release(id, &mut ram.storage).unwrap();
    assert_eq!(pins(&ram, captured), 0);
    assert_eq!(q.retained(), 0);
    assert_eq!(
        q.admit(0, 41, wire, captured, &mut ram.storage),
        Err(proto_fs::OPEN_RETIRED)
    );
}
#[test]
fn exact_replay_preserves_wire_capture_and_first_canonical_result() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    let id = q.admit(3, 41, wire, captured, &mut ram.storage).unwrap();
    let mut other = captured;
    other.request.range = super::super::Range::relative(0, 91, 0).unwrap();
    assert_eq!(q.admit(3, 41, wire, other, &mut ram.storage), Ok(id));
    assert_eq!(q.snapshot(id).unwrap().0, captured);
    assert_eq!(pins(&ram, captured), 1);
    assert_eq!(
        q.same_start(
            id,
            WaitStart {
                pid: 7,
                mode: WaitMode::Pid,
                ..wire
            }
        ),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(
        q.same_start(id, WaitStart { start: 5, ..wire }),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    q.activate(id).unwrap();
    assert_eq!(q.request_cancel(id), Ok(true));
    assert!(q.snapshot(id).unwrap().2);
    assert_eq!(q.active(), Some(id));
    assert!(q.has_work());
    q.complete_active(Ok(Response::Changed)).unwrap();
    assert_eq!(q.query(id), Ok(done(0)));
    q.request_cancel(id).unwrap();
    q.complete(id, done(proto_fs::LOCK_CANCELLED)).unwrap();
    assert_eq!(q.query(id), Ok(done(0)));
    assert!(!q.has_work());
    assert_eq!(q.admit(3, 41, wire, other, &mut ram.storage), Ok(id));
    assert_eq!(q.query(id), Ok(done(0)));
    q.release(id, &mut ram.storage).unwrap();
}
#[test]
fn wake_retains_armed_capture_and_never_recounts_sleeping_work() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    let id = q.admit(0, 41, wire, captured, &mut ram.storage).unwrap();
    q.sleep(id, false).unwrap();
    q.armed(id).unwrap();
    q.ready(id).unwrap();
    assert!(q.has_work());
    assert_eq!(q.snapshot(id).unwrap().0, captured);
    q.activate(id).unwrap();
    q.sleep(id, false).unwrap();
    assert_eq!(q.query(id).unwrap().phase, WaitPhase::Sleeping);
    assert!(!q.has_work());
    assert_eq!(q.next_ready(), None);
    q.ready(id).unwrap();
    q.activate(id).unwrap();
    assert_eq!(
        q.complete_active(Err(Error::Busy)),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(q.active(), Some(id));
    assert!(q.has_work());
    q.complete_active(Err(Error::Cancelled)).unwrap();
    assert_eq!(q.query(id), Ok(done(proto_fs::LOCK_CANCELLED)));
    assert!(!q.has_work());
    q.release(id, &mut ram.storage).unwrap();
}
#[test]
fn label_generation_and_watermark_are_exact_without_aba() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    let key = WaitKey {
        generation: u64::MAX - 1,
        ..wire.key
    };
    q.retire(3, 41, key).unwrap();
    assert!(q.is_retired(3, 41, key).unwrap());
    assert!(!q.is_retired(3, 42, key).unwrap());
    assert!(!q.is_retired(4, 41, key).unwrap());
    assert_eq!(
        q.admit(3, 41, wire, captured, &mut ram.storage),
        Err(proto_fs::OPEN_RETIRED)
    );
    let next = WaitStart {
        key: WaitKey {
            generation: u64::MAX,
            ..key
        },
        ..wire
    };
    let id = q.admit(3, 41, next, captured, &mut ram.storage).unwrap();
    assert_eq!(Id::new(3, 41, next.key), Ok(id));
    assert_eq!(q.find(id.slot(), 42, next.key), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(q.find(id.slot(), 41, key), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(q.retire(3, 42, key), Err(proto_fs::JOBS_FULL));
    q.complete(id, done(0)).unwrap();
    q.release(id, &mut ram.storage).unwrap();
    let newer = q.admit(3, 42, wire, captured, &mut ram.storage).unwrap();
    assert_eq!(newer.slot(), id.slot());
    assert_eq!(q.query(id), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(q.release(id, &mut ram.storage), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(q.occupied(3, 41, 0), Err(proto_fs::OPEN_RETIRED));
    assert!(q.retains(3, 42));
    assert_eq!(q.occupied(3, 42, 0), Ok(Some(newer)));
    q.request_cancel(newer).unwrap();
    q.release(newer, &mut ram.storage).unwrap();
}
#[test]
fn all_5120_paid_cells_pin_once_and_release_every_root_account() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    let mut ids = std::vec::Vec::new();
    for place in 0..crate::places::COUNT {
        let captured = Captured {
            root: if place == 0 {
                captured.root
            } else {
                Root {
                    id: place as u64 + 17,
                    generation: 91,
                }
            },
            ..captured
        };
        for local in 0..SHARE {
            let wire = WaitStart {
                key: WaitKey {
                    slot: local as u32,
                    ..wire.key
                },
                ..wire
            };
            let id = q
                .admit(place, place as u64 + 1, wire, captured, &mut ram.storage)
                .unwrap();
            assert_eq!(usize::from(id.slot()), place * SHARE + local);
            q.sleep(id, false).unwrap();
            ids.push(id);
        }
    }
    assert_eq!(ids.len(), 5120);
    assert_eq!(pins(&ram, captured), 5120);
    assert_eq!(q.retained(), 5120);
    assert!(!q.has_work());
    for id in ids {
        q.request_cancel(id).unwrap();
        q.release(id, &mut ram.storage).unwrap();
    }
    assert_eq!(pins(&ram, captured), 0);
    assert_eq!(q.retained(), 0);
    assert!(!q.has_work());
    let mut anchors = std::vec::Vec::new();
    for id in 0..crate::storage::ROOTS - 1 {
        anchors.push(
            ram.storage
                .lock_anchor(Root {
                    id: 1000 + id as u64,
                    generation: 1,
                })
                .unwrap(),
        );
    }
    for anchor in anchors {
        ram.storage.release_lock_anchor(anchor).unwrap();
    }
}
#[test]
fn bounded_ready_scan_and_actual_initialized_geometry() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    assert!(q.jobs.iter().all(Option::is_none));
    assert!(q.marks.iter().all(|m| m.owner == 0 && m.generation == 0));
    let id = q
        .admit(
            crate::places::COUNT - 1,
            41,
            WaitStart {
                key: WaitKey {
                    slot: 15,
                    ..wire.key
                },
                ..wire
            },
            captured,
            &mut ram.storage,
        )
        .unwrap();
    for _ in 0..usize::from(id.slot()) / 8 {
        let before = q.cursor;
        assert_eq!(q.next_ready(), None);
        assert_eq!(q.cursor, before + 8);
    }
    assert_eq!(q.next_ready(), Some(id));
    q.activate(id).unwrap();
    assert_eq!(q.next_ready(), None);
    q.complete_active(Ok(Response::Changed)).unwrap();
    q.release(id, &mut ram.storage).unwrap();
    std::println!(
        "WAIT Queue {} Job {} OptionJob {} Mark {} Captured {} Id {}",
        core::mem::size_of::<Queue>(),
        core::mem::size_of::<Job>(),
        core::mem::size_of::<Option<Job>>(),
        core::mem::size_of::<Mark>(),
        core::mem::size_of::<Captured>(),
        core::mem::size_of::<Id>()
    );
    assert!(core::mem::size_of::<Job>() <= 320);
    assert!(core::mem::size_of::<Queue>() <= PLACES * (320 + 16) + 128);
}

#[test]
fn conflicts_never_publish_terminal_wait_and_ready_cancel_is_canonical() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    let id = q.admit(0, 41, wire, captured, &mut ram.storage).unwrap();
    assert_eq!(
        q.complete(id, done(proto_fs::LOCK_CONFLICT)),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(q.query(id).unwrap().phase, WaitPhase::Queued);
    assert!(q.has_work());
    assert_eq!(q.request_cancel(id), Ok(false));
    assert_eq!(q.query(id), Ok(done(proto_fs::LOCK_CANCELLED)));
    q.complete(id, done(0)).unwrap();
    assert_eq!(q.query(id), Ok(done(proto_fs::LOCK_CANCELLED)));
    assert!(!q.has_work());
    q.release(id, &mut ram.storage).unwrap();
}
#[test]
fn admission_pin_failure_returns_the_new_root_anchor() {
    let mut ram = Ram::default();
    let (wire, captured) = fixture(&mut ram);
    let mut q = queue();
    let mut broken = captured;
    broken.root = Root {
        id: 9999,
        generation: 71,
    };
    broken.request.inode.generation = u64::MAX;
    assert_eq!(
        q.admit(0, 41, wire, broken, &mut ram.storage),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    assert_eq!(q.retained(), 0);
    assert!(!q.has_work());
    assert_eq!(pins(&ram, captured), 0);
    let mut anchors = std::vec::Vec::new();
    for id in 0..crate::storage::ROOTS - 1 {
        anchors.push(
            ram.storage
                .lock_anchor(Root {
                    id: 2000 + id as u64,
                    generation: 1,
                })
                .expect("failed admission returned payer"),
        );
    }
    for anchor in anchors {
        ram.storage.release_lock_anchor(anchor).unwrap();
    }
}
