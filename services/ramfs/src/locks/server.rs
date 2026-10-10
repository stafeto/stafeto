// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact lock RPC custody shares the existing session Control watermark.

use super::{
    actor::Response,
    jobs::{Id, Queue},
    request::reply,
    service::LockService,
};
use crate::{Fds, Ram};
use proto_fs::{LockReply, LockStart, OpenKey};

/// Replay precedes renewed authority and fd checks, preserving the captured origin.
pub fn replay(
    queue: &Queue,
    place: usize,
    owner: u64,
    wire: LockStart,
) -> Result<Option<LockReply>, u32> {
    wire.validate().map_err(|error| error.code())?;
    let Some(id) = queue.occupied(place, owner, wire.key.slot)? else {
        return Ok(None);
    };
    if id.key() != wire.key {
        return Err(if wire.key.generation <= id.key().generation {
            proto_fs::OPEN_RETIRED
        } else {
            proto_fs::JOBS_FULL
        });
    }
    queue.same_start(id, wire)?;
    queue.query(id).map(Some)
}

/// The caller authenticates fresh requests and checks the other Control families.
pub fn start(
    queue: &mut Queue,
    ram: &mut Ram<'_>,
    fds: &mut Fds,
    place: usize,
    owner: u64,
    wire: LockStart,
) -> Result<LockReply, u32> {
    if let Some(result) = replay(queue, place, owner, wire)? {
        return Ok(result);
    }
    if wire.key.generation <= fds.open_watermarks[wire.key.slot as usize] {
        return Err(proto_fs::OPEN_RETIRED);
    }
    if fds.departed {
        return Err(proto_fs::BAD_FD);
    }
    let captured = ram.capture_lock(fds, wire)?;
    let id = queue.admit(place, owner, wire, captured, &mut ram.storage)?;
    fds.open_watermarks[wire.key.slot as usize] = wire.key.generation;
    queue.query(id)
}

/// Queries observe immutable outcomes and never execute preparation.
pub fn query(
    queue: &Queue,
    fds: &Fds,
    place: usize,
    owner: u64,
    key: OpenKey,
) -> Result<LockReply, u32> {
    validate_key(key)?;
    if let Some(id) = queue.occupied(place, owner, key.slot)?
        && id.key() == key
    {
        return queue.query(id);
    }
    Err(
        if key.generation <= fds.open_watermarks[key.slot as usize] {
            proto_fs::OPEN_RETIRED
        } else {
            proto_fs::NO_ENTRY
        },
    )
}

/// An absent Release fences a Start which has not yet reached the service.
/// Active custody asks the caller to cancel its actor and retains the debt.
pub fn release(
    queue: &mut Queue,
    ram: &mut Ram<'_>,
    fds: &mut Fds,
    place: usize,
    owner: u64,
    key: OpenKey,
) -> Result<bool, u32> {
    validate_key(key)?;
    let id = queue
        .occupied(place, owner, key.slot)?
        .filter(|id| id.key() == key);
    fds.open_watermarks[key.slot as usize] =
        fds.open_watermarks[key.slot as usize].max(key.generation);
    let Some(id) = id else { return Ok(false) };
    let cancel = queue.request_release(id)?;
    if !cancel {
        assert!(queue.release(id, &mut ram.storage)?);
    }
    Ok(cancel)
}

/// Cancellation preserves a repeatable canonical outcome until explicit Release.
/// The caller cancels the active actor only when the returned flag is true.
pub fn cancel(
    queue: &mut Queue,
    fds: &mut Fds,
    place: usize,
    owner: u64,
    key: OpenKey,
) -> Result<(LockReply, bool), u32> {
    validate_key(key)?;
    let id = queue
        .occupied(place, owner, key.slot)?
        .filter(|id| id.key() == key);
    fds.open_watermarks[key.slot as usize] =
        fds.open_watermarks[key.slot as usize].max(key.generation);
    let Some(id) = id else {
        return Ok((reply(Err(super::actor::Error::Cancelled)), false));
    };
    let (_, phase, _) = queue.snapshot(id)?;
    if phase == super::jobs::Phase::Queued {
        queue.complete_queued(id, reply(Err(super::actor::Error::Cancelled)))?;
    }
    Ok((queue.query(id)?, phase == super::jobs::Phase::Active))
}

fn validate_key(key: OpenKey) -> Result<(), u32> {
    key.validate()?;
    if !(32..48).contains(&key.slot) {
        return Err(proto_fs::INVALID_ARGUMENT);
    }
    Ok(())
}

pub fn custody_empty(queue: &Queue, fds: &Fds, place: usize, owner: u64) -> bool {
    fds.custody_empty()
        && (!fds.departed || fds.lock_departure == 16)
        && !queue.retains(place, owner)
}

/// The retained Fds marks eight jobs before its existing physical cleanup turn.
pub fn depart(
    queue: &mut Queue,
    locks: &mut LockService,
    fds: &mut Fds,
    place: usize,
    owner: u64,
) -> bool {
    if !fds.departed || fds.lock_departure == 16 {
        return false;
    }
    if queue.depart(place, owner, usize::from(fds.lock_departure)) {
        locks.cancel();
    }
    fds.lock_departure += 8;
    true
}

/// One ready request rechecks its genuine numeric fd before any actor effect.
pub fn begin(
    queue: &mut Queue,
    locks: &mut LockService,
    ram: &mut Ram<'_>,
    id: Id,
    fds: Option<&Fds>,
) {
    assert!(!locks.busy());
    let (captured, phase, releasing) = queue.snapshot(id).expect("exact ready request");
    assert!(phase == super::jobs::Phase::Queued && !releasing);
    let live = fds
        .filter(|fds| !fds.departed)
        .and_then(|fds| ram.live_description(fds, captured.source).ok())
        .is_some_and(|(inode, _)| inode == captured.request.inode);
    if !live {
        queue
            .complete_queued(
                id,
                proto_fs::LockReply {
                    phase: proto_fs::LockPhase::Complete,
                    result: proto_fs::BAD_FD,
                    blocker: None,
                },
            )
            .expect("exact invalid source outcome");
    } else if captured.unlocked_query {
        queue
            .complete_queued(id, reply(Ok(Response::Blocker(None))))
            .expect("exact OFD unlocked query");
    } else {
        match locks.start(&mut ram.storage, captured.request, captured.root) {
            Ok(()) => queue.activate(id).expect("exact started request"),
            Err(error) => queue
                .complete_queued(id, reply(Err(error)))
                .expect("exact refused request"),
        }
    }
}

/// The canonical actor result precedes releasing cancelled request custody.
pub fn finish(
    queue: &mut Queue,
    ram: &mut Ram<'_>,
    result: Result<Response, super::actor::Error>,
) -> bool {
    let id = queue
        .complete_active(result)
        .expect("exact active lock request");
    if queue.snapshot(id).expect("completed request").2 {
        assert!(
            queue
                .release(id, &mut ram.storage)
                .expect("completed release")
        );
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::locks::{Range, actor::Error, jobs::Phase};
    use proto_fs::{DataDescription, LockCommand, LockKind, LockPhase};

    fn queue() -> std::boxed::Box<Queue> {
        let mut allocation = std::boxed::Box::<Queue>::new_uninit();
        // SAFETY: exclusive aligned storage initialized directly.
        unsafe {
            Queue::initialize_at(allocation.as_mut_ptr());
            allocation.assume_init()
        }
    }
    fn fixture(ram: &mut Ram<'_>) -> (Fds, LockStart) {
        let mut fds = Fds::default();
        let fd = ram
            .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        let (source, _) = ram.capture_description(&fds, fd).unwrap();
        let wire = LockStart {
            key: OpenKey {
                slot: 32,
                generation: 1,
            },
            description: DataDescription {
                packed: ram.marked_open(&fds, source).unwrap(),
                generation: source.description.generation,
            },
            command: LockCommand::GetOfd,
            kind: LockKind::Write,
            whence: 1,
            start: 2,
            length: 3,
            pid: 0,
        };
        (fds, wire)
    }
    fn service() -> std::boxed::Box<LockService> {
        let mut allocation = std::boxed::Box::<LockService>::new_uninit();
        // SAFETY: exclusive aligned storage initialized directly.
        unsafe {
            LockService::initialize_at(allocation.as_mut_ptr());
            allocation.assume_init()
        }
    }
    fn run(
        queue: &mut Queue,
        service: &mut LockService,
        ram: &mut Ram<'_>,
        fds: &mut Fds,
        wire: LockStart,
    ) -> LockReply {
        start(queue, ram, fds, 1, 41, wire).unwrap();
        let id = queue.occupied(1, 41, wire.key.slot).unwrap().unwrap();
        begin(queue, service, ram, id, Some(fds));
        for _ in 0..512 {
            if !service.busy() {
                return query(queue, fds, 1, 41, wire.key).unwrap();
            }
            let (storage, descriptions) = ram.lock_parts();
            let progress =
                service.step_with_owners(storage, |_| true, |token| descriptions.live(token));
            assert!(progress.visited <= 8);
            if let Some(result) = progress.completed {
                assert!(!finish(queue, ram, result));
            }
        }
        panic!("finite actor did not complete");
    }
    #[test]
    fn genuine_actor_progress_preserves_ofd_unlocked_query_and_returns_paid_groups() {
        let mut ram = Ram::default();
        let (mut fds, mut wire) = fixture(&mut ram);
        fds.root = crate::storage::Root {
            id: 10,
            generation: 1,
        };
        wire.whence = 0;
        wire.command = LockCommand::SetOfd;
        wire.kind = LockKind::Read;
        let mut queue = queue();
        let mut service = service();
        assert_eq!(
            run(&mut queue, &mut service, &mut ram, &mut fds, wire).result,
            0
        );
        let charged = service.counts();
        release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key).unwrap();
        wire.key.generation += 1;
        wire.command = LockCommand::GetOfd;
        wire.kind = LockKind::Unlock;
        let response = run(&mut queue, &mut service, &mut ram, &mut fds, wire);
        assert_eq!(response.result, 0);
        assert_eq!(response.blocker, None);
        assert_eq!(service.counts(), charged);
        release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key).unwrap();
        wire.key.generation += 1;
        wire.command = LockCommand::SetOfd;
        assert_eq!(
            run(&mut queue, &mut service, &mut ram, &mut fds, wire).result,
            0
        );
        release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key).unwrap();
        assert!(!queue.has_work());
        assert_eq!(service.counts().published, 0);
    }
    #[test]
    fn unlocked_ofd_query_bypasses_another_descriptions_conflicting_write() {
        let mut ram = Ram::default();
        let (mut fds, mut wire) = fixture(&mut ram);
        fds.root = crate::storage::Root {
            id: 10,
            generation: 1,
        };
        let first = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_ONLY)
            .unwrap();
        let (first, _) = ram.capture_description(&fds, first).unwrap();
        let original = DataDescription {
            packed: ram.marked_open(&fds, first).unwrap(),
            generation: first.description.generation,
        };
        let peer = ram
            .open(&mut fds, "/tmp/probe", proto_fs::READ_WRITE)
            .unwrap();
        let (source, _) = ram.capture_description(&fds, peer).unwrap();
        let peer_description = DataDescription {
            packed: ram.marked_open(&fds, source).unwrap(),
            generation: source.description.generation,
        };
        wire.description = peer_description;
        wire.command = LockCommand::SetOfd;
        wire.kind = LockKind::Write;
        wire.whence = 0;
        let mut queue = queue();
        let mut service = service();
        assert_eq!(
            run(&mut queue, &mut service, &mut ram, &mut fds, wire).result,
            0
        );
        release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key).unwrap();
        wire.key.generation += 1;
        wire.description = original;
        wire.command = LockCommand::GetOfd;
        wire.kind = LockKind::Unlock;
        let result = run(&mut queue, &mut service, &mut ram, &mut fds, wire);
        assert_eq!(result.blocker, None);
        assert_eq!(result.result, 0);
        assert_eq!(service.counts().published, 1);
        release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key).unwrap();
        wire.key.generation += 1;
        wire.description = peer_description;
        wire.command = LockCommand::SetOfd;
        assert_eq!(
            run(&mut queue, &mut service, &mut ram, &mut fds, wire).result,
            0
        );
        release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key).unwrap();
    }
    #[test]
    fn queued_start_rejects_numeric_fd_reuse_before_any_actor_effect() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        let mut service = service();
        start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        let id = queue.occupied(1, 41, 32).unwrap().unwrap();
        ram.close(&mut fds, wire.description.fd()).unwrap();
        let replacement = ram
            .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
            .unwrap();
        assert_eq!(replacement, wire.description.fd());
        begin(&mut queue, &mut service, &mut ram, id, Some(&fds));
        assert!(!service.busy());
        assert_eq!(
            query(&queue, &fds, 1, 41, wire.key).unwrap().result,
            proto_fs::BAD_FD
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(false)
        );
    }
    #[test]
    fn cancelled_actor_completion_returns_the_request_debt_and_requests_legacy_cleanup() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        let mut service = service();
        start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        let id = queue.occupied(1, 41, 32).unwrap().unwrap();
        begin(&mut queue, &mut service, &mut ram, id, Some(&fds));
        assert!(service.busy());
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(true)
        );
        service.cancel();
        let mut returned = false;
        for _ in 0..512 {
            let (storage, descriptions) = ram.lock_parts();
            let progress =
                service.step_with_owners(storage, |_| true, |token| descriptions.live(token));
            assert!(progress.visited <= 8);
            if let Some(result) = progress.completed {
                assert_eq!(result, Err(Error::Cancelled));
                returned = finish(&mut queue, &mut ram, result);
                break;
            }
        }
        assert!(returned);
        assert!(!queue.retains(1, 41));
        assert!(!queue.has_work());
        assert_eq!(
            query(&queue, &fds, 1, 41, wire.key),
            Err(proto_fs::OPEN_RETIRED)
        );
    }
    #[test]
    fn endpoint_death_retains_paid_fds_until_all_sixteen_outcomes_return() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        let mut service = service();
        for local in 0..16 {
            let wire = LockStart {
                key: OpenKey {
                    slot: 32 + local,
                    ..wire.key
                },
                ..wire
            };
            let terminal = run(&mut queue, &mut service, &mut ram, &mut fds, wire);
            assert_eq!(terminal.phase, LockPhase::Complete);
        }
        assert!(!queue.has_work());
        ram.close(&mut fds, wire.description.fd()).unwrap();
        assert!(fds.custody_empty());
        fds.departed = true;
        fds.lock_departure = 0;
        assert!(!custody_empty(&queue, &fds, 1, 41));
        assert!(depart(&mut queue, &mut service, &mut fds, 1, 41));
        assert_eq!(fds.lock_departure, 8);
        assert!(queue.has_work());
        for slot in 32..48 {
            let id = queue.occupied(1, 41, slot).unwrap().unwrap();
            assert_eq!(queue.snapshot(id).unwrap().2, slot < 40);
        }
        assert!(depart(&mut queue, &mut service, &mut fds, 1, 41));
        assert_eq!(fds.lock_departure, 16);
        assert!(!depart(&mut queue, &mut service, &mut fds, 1, 41));
        assert!(!custody_empty(&queue, &fds, 1, 41));
        for _ in 0..super::super::jobs::PLACES.div_ceil(8) {
            assert!(queue.cleanup_released(&mut ram.storage) <= 8);
        }
        assert!(!queue.has_work());
        assert!(custody_empty(&queue, &fds, 1, 41));
    }
    #[test]
    fn replay_preserves_captured_cursor_and_terminal_result_after_fd_death() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        ram.seek(&mut fds, wire.description.fd(), 9).unwrap();
        let pending = start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        assert_eq!(pending.phase, LockPhase::Pending);
        let id = queue.occupied(1, 41, 32).unwrap().unwrap();
        assert_eq!(
            queue.snapshot(id).unwrap().0.request.range,
            Range::relative(9, 2, 3).unwrap()
        );
        ram.seek(&mut fds, wire.description.fd(), 17).unwrap();
        assert_eq!(
            start(&mut queue, &mut ram, &mut fds, 1, 41, wire),
            Ok(pending)
        );
        assert_eq!(query(&queue, &fds, 1, 41, wire.key), Ok(pending));
        assert_eq!(queue.snapshot(id).unwrap().1, Phase::Queued);
        let terminal = LockReply {
            phase: LockPhase::Complete,
            result: proto_fs::LOCK_CONFLICT,
            blocker: None,
        };
        queue.complete_queued(id, terminal).unwrap();
        ram.close(&mut fds, wire.description.fd()).unwrap();
        fds.departed = true;
        assert_eq!(
            start(&mut queue, &mut ram, &mut fds, 1, 41, wire),
            Ok(terminal)
        );
        assert_eq!(query(&queue, &fds, 1, 41, wire.key), Ok(terminal));
        assert_eq!(
            replay(&queue, 1, 41, LockStart { start: 3, ..wire }),
            Err(proto_fs::INVALID_ARGUMENT)
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(false)
        );
        assert_eq!(
            query(&queue, &fds, 1, 41, wire.key),
            Err(proto_fs::OPEN_RETIRED)
        );
    }
    #[test]
    fn release_before_start_fences_old_generation_without_a_job_or_live_fd() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        assert_eq!(
            query(&queue, &fds, 1, 41, wire.key),
            Err(proto_fs::NO_ENTRY)
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(false)
        );
        assert_eq!(fds.open_watermarks[32], 1);
        assert_eq!(
            start(&mut queue, &mut ram, &mut fds, 1, 41, wire),
            Err(proto_fs::OPEN_RETIRED)
        );
        let fresh = LockStart {
            key: OpenKey {
                generation: 2,
                ..wire.key
            },
            ..wire
        };
        start(&mut queue, &mut ram, &mut fds, 1, 41, fresh).unwrap();
        assert_eq!(
            start(
                &mut queue,
                &mut ram,
                &mut fds,
                1,
                41,
                LockStart {
                    key: OpenKey {
                        generation: 3,
                        ..wire.key
                    },
                    ..wire
                }
            ),
            Err(proto_fs::JOBS_FULL)
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(false)
        );
        assert!(queue.retains(1, 41));
        assert_eq!(
            query(&queue, &fds, 1, 41, fresh.key).unwrap().phase,
            LockPhase::Pending
        );
    }
    #[test]
    fn active_release_preserves_custody_until_canonical_actor_completion() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        let id = queue.occupied(1, 41, 32).unwrap().unwrap();
        queue.activate(id).unwrap();
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(true)
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(true)
        );
        assert!(queue.retains(1, 41));
        assert_eq!(
            query(&queue, &fds, 1, 41, wire.key).unwrap().phase,
            LockPhase::Pending
        );
        queue.complete_active(Err(Error::Cancelled)).unwrap();
        assert_eq!(
            query(&queue, &fds, 1, 41, wire.key).unwrap().result,
            proto_fs::LOCK_CANCELLED
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(false)
        );
        assert!(!queue.retains(1, 41));
    }
    #[test]
    fn cancel_before_start_fences_generation_without_custody_or_effect() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        let cancelled = reply(Err(Error::Cancelled));
        assert_eq!(
            cancel(&mut queue, &mut fds, 1, 41, wire.key),
            Ok((cancelled, false))
        );
        assert_eq!(
            cancel(&mut queue, &mut fds, 1, 41, wire.key),
            Ok((cancelled, false))
        );
        assert_eq!(queue.retained(), 0);
        assert_eq!(
            start(&mut queue, &mut ram, &mut fds, 1, 41, wire),
            Err(proto_fs::OPEN_RETIRED)
        );
        let fresh = LockStart {
            key: OpenKey {
                generation: 2,
                ..wire.key
            },
            ..wire
        };
        start(&mut queue, &mut ram, &mut fds, 1, 41, fresh).unwrap();
        assert_eq!(
            cancel(&mut queue, &mut fds, 1, 41, wire.key),
            Ok((cancelled, false))
        );
        assert_eq!(
            query(&queue, &fds, 1, 41, fresh.key).unwrap().phase,
            LockPhase::Pending
        );
        release(&mut queue, &mut ram, &mut fds, 1, 41, fresh.key).unwrap();
    }

    #[test]
    fn queued_cancel_retains_repeatable_outcome_until_acknowledged_release() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        let cancelled = reply(Err(Error::Cancelled));
        assert_eq!(
            cancel(&mut queue, &mut fds, 1, 41, wire.key),
            Ok((cancelled, false))
        );
        assert_eq!(queue.retained(), 1);
        assert!(!queue.has_work());
        assert!(queue.next_ready().is_none());
        assert_eq!(query(&queue, &fds, 1, 41, wire.key), Ok(cancelled));
        assert_eq!(
            cancel(&mut queue, &mut fds, 1, 41, wire.key),
            Ok((cancelled, false))
        );
        assert_eq!(
            start(&mut queue, &mut ram, &mut fds, 1, 41, wire),
            Ok(cancelled)
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(false)
        );
        assert_eq!(queue.retained(), 0);
    }

    #[test]
    fn completed_query_keeps_blocker_when_cancel_races_after_pending_observation() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        let pending = start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        assert_eq!(pending.phase, LockPhase::Pending);
        let id = queue.occupied(1, 41, 32).unwrap().unwrap();
        let terminal = LockReply {
            phase: LockPhase::Complete,
            result: 0,
            blocker: Some(proto_fs::LockBlocker {
                kind: LockKind::Write,
                start: 7,
                length: 11,
                pid: -1,
            }),
        };
        queue.complete_queued(id, terminal).unwrap();
        for _ in 0..3 {
            assert_eq!(
                cancel(&mut queue, &mut fds, 1, 41, wire.key),
                Ok((terminal, false))
            );
            assert_eq!(query(&queue, &fds, 1, 41, wire.key), Ok(terminal));
            assert_eq!(queue.retained(), 1);
        }
        release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key).unwrap();
        assert_eq!(queue.retained(), 0);
    }

    #[test]
    fn active_cancel_keeps_canonical_actor_outcome_until_explicit_release() {
        let mut ram = Ram::default();
        let (mut fds, wire) = fixture(&mut ram);
        let mut queue = queue();
        let mut service = service();
        start(&mut queue, &mut ram, &mut fds, 1, 41, wire).unwrap();
        let id = queue.occupied(1, 41, 32).unwrap().unwrap();
        begin(&mut queue, &mut service, &mut ram, id, Some(&fds));
        let (pending, active) = cancel(&mut queue, &mut fds, 1, 41, wire.key).unwrap();
        assert!(active);
        assert_eq!(pending.phase, LockPhase::Pending);
        service.cancel();
        for _ in 0..512 {
            let (storage, descriptions) = ram.lock_parts();
            let progress =
                service.step_with_owners(storage, |_| true, |token| descriptions.live(token));
            assert!(progress.visited <= 8);
            if let Some(result) = progress.completed {
                assert_eq!(result, Err(Error::Cancelled));
                assert!(!finish(&mut queue, &mut ram, result));
                break;
            }
        }
        let terminal = reply(Err(Error::Cancelled));
        assert_eq!(query(&queue, &fds, 1, 41, wire.key), Ok(terminal));
        assert_eq!(queue.retained(), 1);
        assert!(!queue.has_work());
        assert_eq!(
            cancel(&mut queue, &mut fds, 1, 41, wire.key),
            Ok((terminal, false))
        );
        assert_eq!(
            release(&mut queue, &mut ram, &mut fds, 1, 41, wire.key),
            Ok(false)
        );
        assert_eq!(queue.retained(), 0);
    }
}
