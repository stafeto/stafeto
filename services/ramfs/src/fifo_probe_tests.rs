// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
use super::{Gate, PERIOD_NS, Phase, Scope};
use crate as ramfs;
use ramfs::{TentativeOpen, storage::Token};
fn scope() -> Scope {
    Scope {
        owner: 0x1_0000_0123,
        source: TentativeOpen {
            fd: 3,
            description: Token {
                slot: 4,
                generation: 0x1_0000_0005,
            },
        },
        inode: Token {
            slot: 6,
            generation: 7,
        },
        holder: 0x10001,
    }
}
#[test]
fn fixed_deadline_and_full_nonce_scope_survive_replay() {
    let mut g = Gate::new();
    let s = scope();
    g.arm(s, 0x1_0000_0001, 10).unwrap();
    let deadline = g.deadline;
    g.arm(s, 0x1_0000_0001, deadline - 1).unwrap();
    assert_eq!(g.deadline, deadline);
    let mut different = s;
    different.source.description.generation += 1;
    assert!(g.arm(different, 0x1_0000_0001, 20).is_err());
    assert_eq!(g.scope, Some(s));
    assert!(g.arm(s, 0x2_0000_0001, 20).is_err());
    assert_eq!(g.nonce, 0x1_0000_0001);
    g.expire(deadline);
    assert_eq!(g.phase, Phase::Expired);
    assert!(!g.active());
    assert!(!g.pause_wait());
    assert!(!g.frozen());
    g.arm(s, 0x1_0000_0001, deadline + PERIOD_NS).unwrap();
    assert_eq!(g.phase, Phase::Expired);
    assert_eq!(g.deadline, deadline);
    g.arm(s, 0x2_0000_0001, deadline + 1).unwrap();
    assert_eq!(g.phase, Phase::Armed);
}
#[test]
fn exact_owner_closure_invalidates_only_its_own_live_gate() {
    let mut g = Gate::new();
    let s = scope();
    g.arm(s, 1, 10).unwrap();
    g.invalidate(s.owner as u32 as u64);
    assert_eq!(g.phase, Phase::Armed);
    g.invalidate(s.owner);
    assert_eq!(g.phase, Phase::Invalidated);
    assert!(!g.active());
}
#[test]
fn only_real_expected_change_and_exact_paid_control_advance_the_barrier() {
    use proto_fs::{DataDescription, LockCommand, LockKind, LockStart, OpenKey, WaitKey};
    use ramfs::{
        Fds, Ram,
        locks::{
            Kind, Owner, Range,
            actor::Command,
            jobs::Queue,
            wait_receipts::Id as WaitId,
            waiters::{Input, Pool},
        },
        storage::BOOT_ROOT,
    };
    let mut ram = Ram::default();
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
        whence: 0,
        start: 4,
        length: 4,
        pid: 0,
    };
    let mut c = ram.capture_lock(&fds, wire).unwrap();
    let s = Scope {
        owner: 0x1_0000_0123,
        source,
        inode: c.request.inode,
        holder: 257,
    };
    let mut g = Gate::new();
    g.arm(s, 1, 10).unwrap();
    c.request.owner = Owner::Process(s.holder);
    c.request.command = Command::Set(None);
    let mut wrong = c;
    wrong.request.inode.generation += 1;
    g.changed(wrong);
    assert_eq!(g.phase, Phase::Armed);
    wrong = c;
    wrong.request.owner = Owner::Process(s.holder + 1);
    g.changed(wrong);
    assert_eq!(g.phase, Phase::Armed);
    wrong = c;
    wrong.request.range = Range::relative(0, 0, 4).unwrap();
    g.changed(wrong);
    assert_eq!(g.phase, Phase::Armed);
    g.changed(c);
    assert!(g.frozen());
    assert!(g.pause_wait());
    let mut queue = Box::<Queue>::new_uninit();
    let mut q = unsafe {
        Queue::initialize_at(queue.as_mut_ptr());
        queue.assume_init()
    };
    c.request.owner = Owner::Process(258);
    c.request.command = Command::Set(Some(Kind::Write));
    let id = q.admit(0, s.owner, wire, c, &mut ram.storage).unwrap();
    g.accepted(id, c);
    assert_eq!(g.phase, Phase::Selecting);
    assert!(!g.frozen());
    assert!(g.pause_wait());
    g.visit(id, 8);
    assert_eq!(g.visited, 8);
    let mut pool = Pool::new();
    let r = pool
        .register(Input {
            receipt: WaitId::new(
                0,
                s.owner,
                WaitKey {
                    slot: 0,
                    generation: 1,
                },
            )
            .unwrap(),
            root: BOOT_ROOT,
            inode: s.inode,
            range: c.request.range,
            kind: Kind::Read,
        })
        .unwrap();
    g.finish(id, Some(r));
    assert_eq!(g.phase, Phase::Selected);
    assert_eq!(g.control, Some(id));
    assert_eq!(g.selected, Some(r));
    assert!(!g.pause_wait());
    g.expire(g.deadline);
    assert_eq!(g.phase, Phase::Selected);
    println!("FIFO test Gate {} bytes", core::mem::size_of::<Gate>());
}
