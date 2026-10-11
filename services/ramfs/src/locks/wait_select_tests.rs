// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
extern crate std;
use super::*;
use crate::{
    Fds, Ram,
    locks::{
        Kind, Owner, Range,
        actor::{Request, Response},
        jobs,
        waiters::Input,
    },
    storage::Root,
};
use proto_fs::{
    DataDescription, LockCommand, LockKind, LockStart, OpenKey, WaitKey, WaitMode, WaitStart,
};
use std::boxed::Box;
type Table = Actor<64, 1285, 256, 128, 16, 64>;
fn actor() -> Box<Table> {
    let mut out = Box::<Table>::new_uninit();
    // SAFETY: exclusive aligned complete allocation.
    unsafe {
        Table::initialize_at(out.as_mut_ptr());
        out.assume_init()
    }
}
fn selector() -> Box<Selector> {
    let mut out = Box::<Selector>::new_uninit();
    // SAFETY: exclusive aligned complete allocation.
    unsafe {
        Selector::initialize_at(out.as_mut_ptr());
        out.assume_init()
    }
}
fn waits() -> Box<Queue> {
    let mut out = Box::<Queue>::new_uninit();
    // SAFETY: exclusive aligned complete allocation.
    unsafe {
        Queue::initialize_at(out.as_mut_ptr());
        out.assume_init()
    }
}
fn controls() -> Box<jobs::Queue> {
    let mut out = Box::<jobs::Queue>::new_uninit();
    // SAFETY: exclusive aligned complete allocation.
    unsafe {
        jobs::Queue::initialize_at(out.as_mut_ptr());
        out.assume_init()
    }
}
fn capture(ram: &mut Ram<'_>, number: usize, start: i64, kind: Kind) -> (WaitStart, Captured) {
    let mut fds = Fds {
        root: Root {
            id: 100 + (number / 4) as u64,
            generation: 1,
        },
        ..Fds::default()
    };
    let fd = ram
        .open(&mut fds, "/etc/motd", proto_fs::READ_ONLY)
        .unwrap();
    let (source, _) = ram.capture_description(&fds, fd).unwrap();
    let mut wire = WaitStart {
        key: WaitKey {
            slot: (number % 16) as u32,
            generation: 1,
        },
        description: DataDescription {
            packed: ram.marked_open(&fds, source).unwrap(),
            generation: source.description.generation,
        },
        mode: WaitMode::Ofd,
        kind: LockKind::Read,
        whence: 0,
        start,
        length: 4,
        pid: 0,
    };
    let mut captured = ram.capture_wait(&fds, wire).unwrap();
    // Model checked ingress kind and independent PID owners, retaining real inode/root custody.
    wire.kind = if kind == Kind::Read {
        LockKind::Read
    } else {
        LockKind::Write
    };
    captured.request.command = Command::Set(Some(kind));
    captured.request.owner = Owner::Process(256 + number as u32);
    (wire, captured)
}
fn register(
    ram: &mut Ram<'_>,
    queue: &mut Queue,
    pool: &mut Pool,
    number: usize,
    start: i64,
    kind: Kind,
) -> Candidate {
    let (wire, captured) = capture(ram, number, start, kind);
    let id = queue
        .admit(
            number / 16,
            10 + number as u64,
            wire,
            captured,
            &mut ram.storage,
        )
        .unwrap();
    queue.sleep(id, true).unwrap();
    let registration = pool
        .register(Input {
            receipt: id,
            root: captured.root,
            inode: captured.request.inode,
            range: captured.request.range,
            kind,
        })
        .unwrap();
    Candidate {
        registration,
        captured,
    }
}
fn control(
    ram: &mut Ram<'_>,
    queue: &mut jobs::Queue,
    generation: u64,
    start: i64,
    kind: Kind,
) -> (ControlId, Captured) {
    control_custom(ram, queue, generation, start, kind, 32, |_| {})
}
fn control_custom(
    ram: &mut Ram<'_>,
    queue: &mut jobs::Queue,
    generation: u64,
    start: i64,
    kind: Kind,
    slot: u32,
    project: impl FnOnce(&mut Captured),
) -> (ControlId, Captured) {
    let (wire, mut captured) = capture(ram, 20, start, kind);
    captured.request.owner = Owner::Process(280);
    captured.request.range = Range::relative(0, start, 20).unwrap();
    project(&mut captured);
    let wire = LockStart {
        key: OpenKey { slot, generation },
        description: wire.description,
        command: LockCommand::SetOfd,
        kind: wire.kind,
        whence: wire.whence,
        start: wire.start,
        length: 20,
        pid: 0,
    };
    let id = queue
        .admit(0, 91, wire, captured, &mut ram.storage)
        .unwrap();
    (id, captured)
}
fn run(actor: &mut Table, request: Request) -> Result<Response, super::super::actor::Error> {
    for _ in 0..4096 {
        if !actor.busy() {
            break;
        }
        actor.step();
    }
    actor.start(request).unwrap();
    for _ in 0..4096 {
        let p = actor.step_with_owners(|_| true, |_| true);
        assert!(p.visited <= 8);
        if let Some(result) = p.completed {
            return result;
        }
    }
    panic!("actor did not complete");
}
fn choose(
    s: &mut Selector,
    pool: &Pool,
    queue: &Queue,
    actor: &Table,
    jobs: &mut jobs::Queue,
) -> Decision {
    for _ in 0..4096 {
        let progress = s.part(pool, queue, jobs, actor, |_| true, |_| true);
        assert!(progress.visited <= 8);
        if let Some(decision) = progress.decision {
            return decision;
        }
    }
    panic!("selection did not finish");
}
#[test]
fn oldest_eligible_wait_precedes_control_with_real_actor_and_exact_credit() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let mut a = actor();
    let mut s = selector();
    let first = register(&mut ram, &mut q, &mut pool, 0, 0, Kind::Write);
    let later = register(&mut ram, &mut q, &mut pool, 1, 0, Kind::Write);
    let (id, captured) = control(&mut ram, &mut cq, 1, 0, Kind::Write);
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(
        choose(&mut s, &pool, &q, &a, &mut cq),
        Decision::Wait(first)
    );
    assert!(!a.busy()); // Selector never acquires the Actor or reserves lock records.
    pool.ready(first.registration).unwrap();
    q.ready(first.registration.receipt()).unwrap();
    pool.run(first.registration).unwrap();
    assert_eq!(run(&mut a, first.captured.request), Ok(Response::Changed));
    assert!(matches!(
        run(&mut a, captured.request),
        Err(super::super::actor::Error::Conflict(_))
    ));
    // Internal retry cannot reset a paid Control's attempt credit.
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
    assert_ne!(first.registration, later.registration);
}
#[test]
fn reader_checks_all_live_blockers_and_skips_only_the_ineligible_candidate() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let mut a = actor();
    let mut s = selector();
    let first = register(&mut ram, &mut q, &mut pool, 0, 0, Kind::Write);
    let second = register(&mut ram, &mut q, &mut pool, 1, 8, Kind::Write);
    for n in 0..12 {
        let mut blocker = first.captured.request;
        blocker.owner = Owner::Process(300 + n);
        blocker.command = Command::Set(Some(Kind::Read));
        assert_eq!(run(&mut a, blocker), Ok(Response::Changed));
    }
    let (id, captured) = control(&mut ram, &mut cq, 1, 0, Kind::Write);
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(
        choose(&mut s, &pool, &q, &a, &mut cq),
        Decision::Wait(second)
    );
    // Dead published PID blockers do not inhibit the oldest waiter.
    let mut another = selector();
    let (id, captured) = control_custom(&mut ram, &mut cq, 1, 0, Kind::Write, 33, |_| {});
    another.begin(id, captured, &pool, &cq).unwrap();
    for _ in 0..4096 {
        let p = another.part(&pool, &q, &mut cq, &a, |_| false, |_| true);
        assert!(p.visited <= 8);
        if let Some(d) = p.decision {
            assert_eq!(d, Decision::Wait(first));
            return;
        }
    }
    panic!("dead blocker selection did not finish");
}
#[test]
fn sixteen_registrations_and_unrelated_activity_cannot_extend_one_selection() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let a = actor();
    let mut s = selector();
    let mut last = None;
    for n in 0..16 {
        last = Some(register(
            &mut ram,
            &mut q,
            &mut pool,
            n,
            if n == 15 { 0 } else { 100 },
            Kind::Write,
        ));
    }
    let (id, captured) = control(&mut ram, &mut cq, 1, 0, Kind::Write);
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(
        s.part(&pool, &q, &mut cq, &a, |_| true, |_| true).visited,
        8
    );
    // Repeated events call begin with the same immutable full id; no restart.
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(
        s.part(&pool, &q, &mut cq, &a, |_| true, |_| true).visited,
        8
    );
    assert_eq!(
        choose(&mut s, &pool, &q, &a, &mut cq),
        Decision::Wait(last.unwrap())
    );
    println!("WAIT Selector: {} bytes", core::mem::size_of::<Selector>());
}
#[test]
fn owner_inode_range_and_kind_filter_preserve_real_lock_semantics() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let a = actor();
    let first = register(&mut ram, &mut q, &mut pool, 0, 0, Kind::Read);
    let (id, captured) = control(&mut ram, &mut cq, 1, 0, Kind::Read);
    let mut s = selector();
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
    let (id, captured) = control_custom(&mut ram, &mut cq, 1, 0, Kind::Write, 33, |c| {
        c.request.owner = first.captured.request.owner
    });
    let mut s = selector();
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
    // A separately pinned exact boot inode models an unrelated file authority.
    let (id, captured) = control_custom(&mut ram, &mut cq, 1, 0, Kind::Write, 34, |c| {
        c.request.inode = Token {
            slot: 1,
            generation: 1,
        }
    });
    let mut s = selector();
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
}
#[test]
fn stale_registration_or_reader_revision_spends_credit_without_restarting() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let mut a = actor();
    let mut s = selector();
    let first = register(&mut ram, &mut q, &mut pool, 0, 0, Kind::Write);
    let (id, captured) = control(&mut ram, &mut cq, 1, 0, Kind::Write);
    s.begin(id, captured, &pool, &cq).unwrap();
    s.part(&pool, &q, &mut cq, &a, |_| true, |_| true);
    pool.complete(first.registration).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
    let other = register(&mut ram, &mut q, &mut pool, 1, 0, Kind::Write);
    let (id, captured) = control_custom(&mut ram, &mut cq, 1, 0, Kind::Write, 33, |_| {});
    let mut s = selector();
    s.begin(id, captured, &pool, &cq).unwrap();
    s.part(&pool, &q, &mut cq, &a, |_| true, |_| true);
    for n in 0..8 {
        let mut b = other.captured.request;
        b.owner = Owner::Process(300 + n);
        b.command = Command::Set(Some(Kind::Read));
        run(&mut a, b).unwrap();
    }
    let p = s.part(&pool, &q, &mut cq, &a, |_| true, |_| true);
    assert_eq!(p.decision, None);
    let mut change = other.captured.request;
    change.range = Range::relative(0, 100, 4).unwrap();
    run(&mut a, change).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
}
#[test]
fn next_full_generation_receives_credit_and_changed_capture_is_rejected() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let a = actor();
    let mut s = selector();
    let first = register(&mut ram, &mut q, &mut pool, 0, 0, Kind::Write);
    let (id, captured) = control(&mut ram, &mut cq, 1, 0, Kind::Write);
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(
        choose(&mut s, &pool, &q, &a, &mut cq),
        Decision::Wait(first)
    );
    let mut changed = captured;
    changed.source.fd += 1;
    assert_eq!(
        s.begin(id, changed, &pool, &cq),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    cq.activate(id).unwrap();
    cq.complete_active(Ok(Response::Changed)).unwrap();
    cq.release(id, &mut ram.storage).unwrap();
    let (next, captured) = control(&mut ram, &mut cq, 2, 0, Kind::Write);
    assert_ne!(next, id);
    assert_eq!(cq.wait_attempt_spent(id), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(cq.spend_wait_attempt(id), Err(proto_fs::OPEN_RETIRED));
    assert_eq!(cq.wait_attempt_spent(next), Ok(false));
    s.begin(next, captured, &pool, &cq).unwrap();
    assert_eq!(
        choose(&mut s, &pool, &q, &a, &mut cq),
        Decision::Wait(first)
    );
}

#[test]
fn paid_job_credit_survives_a_b_a_and_internal_actor_cancellation() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let a = actor();
    let mut s = selector();
    let first = register(&mut ram, &mut q, &mut pool, 0, 0, Kind::Write);
    let (aid, ac) = control_custom(&mut ram, &mut cq, 1, 0, Kind::Write, 32, |_| {});
    let (bid, bc) = control_custom(&mut ram, &mut cq, 1, 0, Kind::Write, 33, |_| {});
    assert_eq!(cq.wait_attempt_spent(aid), Ok(false));
    s.begin(aid, ac, &pool, &cq).unwrap();
    assert_eq!(
        choose(&mut s, &pool, &q, &a, &mut cq),
        Decision::Wait(first)
    );
    cq.activate(aid).unwrap();
    assert_eq!(cq.retry_active(), Ok(true));
    assert_eq!(cq.wait_attempt_spent(aid), Ok(true));
    assert_eq!(cq.spend_wait_attempt(aid), Ok(false));
    s.begin(bid, bc, &pool, &cq).unwrap();
    assert_eq!(
        choose(&mut s, &pool, &q, &a, &mut cq),
        Decision::Wait(first)
    );
    s.begin(aid, ac, &pool, &cq).unwrap();
    assert_eq!(choose(&mut s, &pool, &q, &a, &mut cq), Decision::Control);
}

#[test]
fn retired_fifo_cursor_consumes_paid_credit_in_a_bounded_turn() {
    let mut ram = Ram::default();
    let mut q = waits();
    let mut pool = Pool::new();
    let mut cq = controls();
    let a = actor();
    let mut s = selector();
    let mut ninth = None;
    for n in 0..16 {
        let c = register(&mut ram, &mut q, &mut pool, n, 100, Kind::Write);
        if n == 8 {
            ninth = Some(c);
        }
    }
    let (id, captured) = control(&mut ram, &mut cq, 1, 0, Kind::Write);
    s.begin(id, captured, &pool, &cq).unwrap();
    assert_eq!(
        s.part(&pool, &q, &mut cq, &a, |_| true, |_| true).visited,
        8
    );
    pool.complete(ninth.unwrap().registration).unwrap();
    let p = s.part(&pool, &q, &mut cq, &a, |_| true, |_| true);
    assert!(p.visited <= 8);
    assert_eq!(p.decision, Some(Decision::Control));
    assert_eq!(cq.wait_attempt_spent(id), Ok(true));
}
