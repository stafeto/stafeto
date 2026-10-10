// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
use super::*;
use crate::locks::actor::Response;
use crate::locks::{Kind, Range};
use proto_process::lifetimes::Page;
use std::{boxed::Box, vec::Vec};
type Table = Actor<32, 8, 256, 16, 4, 16>;
fn inode(slot: u16) -> Token {
    Token {
        slot,
        generation: 1,
    }
}
fn pid(number: u32) -> Owner {
    Owner::Process(256 + number)
}
fn ofd(number: u16) -> Owner {
    Owner::Description {
        slot: number,
        generation: 1,
    }
}
fn page() -> Page {
    let page = Page::new();
    for index in 0..32 {
        page.publish(256 + index).unwrap();
    }
    page
}
fn fresh() -> Box<Table> {
    let mut allocation = Box::<Table>::new_uninit();
    // SAFETY: the Box owns the exclusive aligned complete actor allocation.
    unsafe {
        Table::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    }
}
fn request(node: u16, owner: Owner, command: Command) -> Request {
    Request {
        inode: inode(node),
        owner,
        root: 0,
        range: Range::relative(0, 0, 10).unwrap(),
        command,
    }
}
fn drain(actor: &mut Table, page: &Page) {
    for _ in 0..4096 {
        if !actor.busy() {
            return;
        }
        assert!(
            actor
                .step_with_owners(|pid| page.live(pid), |_| true)
                .visited
                <= records::PORTION
        );
    }
    panic!("bounded actor cleanup did not finish");
}
fn run(actor: &mut Table, page: &Page, request: Request) -> Response {
    drain(actor, page);
    actor.start(request).unwrap();
    for _ in 0..4096 {
        let progress = actor.step_with_owners(|pid| page.live(pid), |_| true);
        assert!(progress.visited <= records::PORTION);
        if let Some(result) = progress.completed {
            return result.unwrap();
        }
    }
    panic!("actor operation did not finish");
}
fn read(
    actor: &Table,
    reader: &mut Reader,
    page: &Page,
    ofd_alive: impl Fn(Token) -> bool,
) -> Vec<Lock> {
    let mut blockers = Vec::new();
    for _ in 0..4096 {
        let mut calls = 0;
        let progress = actor.reader_part(
            reader,
            |pid| {
                calls += 1;
                page.live(pid)
            },
            &ofd_alive,
        );
        assert!(progress.visited <= records::PORTION);
        assert!(calls <= progress.visited);
        blockers.extend(progress.blockers.into_iter().flatten());
        match progress.state {
            ReadState::Done => return blockers,
            ReadState::Invalidated => panic!("unexpected snapshot change"),
            ReadState::More => {}
        }
    }
    panic!("Reader exceeded finite stable chain bound");
}
#[test]
fn all_genuine_process_and_ofd_blockers_are_returned_without_own_owner() {
    let mut actor = fresh();
    let page = page();
    for owner in [pid(0), pid(1), pid(2), ofd(1)] {
        assert_eq!(
            run(
                &mut actor,
                &page,
                request(0, owner, Command::Set(Some(Kind::Read)))
            ),
            Response::Changed
        );
    }
    let before = actor.counts();
    let mut reader = actor
        .reader(request(0, pid(0), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    let blockers = read(&actor, &mut reader, &page, |_| true);
    assert_eq!(blockers.len(), 3);
    for owner in [pid(1), pid(2), ofd(1)] {
        assert!(blockers.iter().any(|lock| lock.owner == owner));
    }
    assert_eq!(actor.counts(), before);
    assert!(!actor.busy() || actor.debt());
    let mut reader = actor
        .reader(request(0, ofd(1), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    assert!(
        read(&actor, &mut reader, &page, |_| true)
            .iter()
            .all(|lock| lock.owner != ofd(1))
    );
}
#[test]
fn genuine_lifetimes_filter_dead_pid_and_full_ofd_generation() {
    let mut actor = fresh();
    let page = page();
    for owner in [pid(1), pid(2), ofd(1), ofd(2)] {
        run(
            &mut actor,
            &page,
            request(0, owner, Command::Set(Some(Kind::Read))),
        );
    }
    assert!(page.retire(258));
    let mut reader = actor
        .reader(request(0, pid(0), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    let blockers = read(&actor, &mut reader, &page, |token| {
        token
            == Token {
                slot: 1,
                generation: 1,
            }
    });
    assert_eq!(blockers.len(), 2);
    assert!(blockers.iter().any(|lock| lock.owner == pid(1)));
    assert!(blockers.iter().any(|lock| lock.owner == ofd(1)));
    let mut reader = actor
        .reader(request(0, pid(0), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    assert!(
        read(&actor, &mut reader, &page, |token| token
            == Token {
                slot: 1,
                generation: 2
            })
        .iter()
        .all(|lock| matches!(lock.owner, Owner::Process(_)))
    );
}
#[test]
fn ten_groups_are_read_in_bounded_portions_and_reader_holds_no_actor() {
    let mut actor = fresh();
    let page = page();
    for number in 1..=10 {
        run(
            &mut actor,
            &page,
            request(0, pid(number), Command::Set(Some(Kind::Read))),
        );
    }
    drain(&mut actor, &page);
    let mut reader = actor
        .reader(request(0, pid(0), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    let first = actor.reader_part(&mut reader, |pid| page.live(pid), |_| true);
    assert_eq!(first.visited, 8);
    assert_eq!(first.state, ReadState::More);
    assert_eq!(first.blockers.iter().flatten().count(), 4);
    run(
        &mut actor,
        &page,
        request(1, pid(12), Command::Set(Some(Kind::Write))),
    );
    assert!(actor.reader_snapshot_valid(reader.snapshot()));
    let remaining = read(&actor, &mut reader, &page, |_| true);
    assert_eq!(remaining.len(), 6);
}
#[test]
fn commit_unlock_and_close_invalidate_before_reclaimed_cursor_is_read() {
    for change in 0..3 {
        let mut actor = fresh();
        let page = page();
        for number in 1..=6 {
            run(
                &mut actor,
                &page,
                request(0, pid(number), Command::Set(Some(Kind::Read))),
            );
        }
        let mut reader = actor
            .reader(request(0, pid(0), Command::Get(Kind::Write)))
            .unwrap()
            .unwrap();
        assert_eq!(
            actor.reader_part(&mut reader, |_| true, |_| true).state,
            ReadState::More
        );
        match change {
            0 => {
                run(
                    &mut actor,
                    &page,
                    Request {
                        range: Range::relative(0, 0, 5).unwrap(),
                        ..request(0, pid(2), Command::Set(Some(Kind::Read)))
                    },
                );
            }
            1 => {
                run(&mut actor, &page, request(0, pid(2), Command::Set(None)));
            }
            _ => {
                actor.close(inode(0), pid(2)).unwrap();
            }
        }
        drain(&mut actor, &page);
        let immediate = actor.reader_part(
            &mut reader,
            |_| panic!("must not read invalidated head"),
            |_| panic!("must not read invalidated head"),
        );
        assert_eq!(immediate.state, ReadState::Invalidated);
        assert_eq!(immediate.visited, 0);
        // Exercise reallocation after actual old-head/group cleanup.
        run(
            &mut actor,
            &page,
            request(0, pid(8), Command::Set(Some(Kind::Read))),
        );
        let progress = actor.reader_part(
            &mut reader,
            |_| panic!("must not read reclaimed cursor"),
            |_| panic!("must not read reclaimed cursor"),
        );
        assert_eq!(progress.state, ReadState::Invalidated);
        assert_eq!(progress.visited, 0);
        assert!(progress.blockers.iter().all(Option::is_none));
    }
}
#[test]
fn logical_departure_is_invisible_before_structural_detach_with_page_still_live() {
    let mut actor = fresh();
    let page = page();
    run(
        &mut actor,
        &page,
        request(0, pid(1), Command::Set(Some(Kind::Read))),
    );
    let mut reader = actor
        .reader(request(0, pid(0), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    assert!(actor.pid_visible(257));
    actor.depart_pid(257).unwrap();
    assert!(page.live(257));
    assert!(!actor.pid_visible(257));
    assert!(actor.reader_snapshot_valid(reader.snapshot()));
    assert!(read(&actor, &mut reader, &page, |_| true).is_empty());
    drain(&mut actor, &page);
    assert!(!actor.reader_snapshot_valid(reader.snapshot()));
}
#[test]
fn saturation_never_resets_on_group_or_inode_reuse_and_normal_actor_still_works() {
    let mut actor = fresh();
    let page = page();
    let old = actor.reader_snapshot(inode(0)).unwrap();
    actor.groups.set_test_inode_revision(inode(0), u64::MAX - 1);
    run(
        &mut actor,
        &page,
        request(0, pid(1), Command::Set(Some(Kind::Read))),
    );
    assert!(!actor.reader_snapshot_valid(old));
    assert!(
        actor
            .reader(request(0, pid(0), Command::Get(Kind::Write)))
            .unwrap()
            .is_none()
    );
    run(&mut actor, &page, request(0, pid(1), Command::Set(None)));
    drain(&mut actor, &page);
    let mut changed = request(0, pid(2), Command::Set(Some(Kind::Write)));
    changed.inode.generation = 2;
    assert_eq!(run(&mut actor, &page, changed), Response::Changed);
    assert!(actor.reader_snapshot(changed.inode).is_none());
    assert_eq!(actor.groups.inode_revisions_for_test(inode(0)), u64::MAX);
}

#[test]
fn allocation_invalidates_before_a_new_group_has_published_any_records() {
    let mut actor = fresh();
    let page = page();
    run(
        &mut actor,
        &page,
        request(0, pid(1), Command::Set(Some(Kind::Read))),
    );
    drain(&mut actor, &page);
    let mut reader = actor
        .reader(request(0, pid(0), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    actor
        .start(request(0, pid(2), Command::Set(Some(Kind::Read))))
        .unwrap();
    for _ in 0..4096 {
        let progress = actor.step_with_owners(|pid| page.live(pid), |_| true);
        if matches!(
            progress.group_event,
            Some(super::super::GroupEvent::Created { .. })
        ) {
            assert!(progress.completed.is_none());
            let read = actor.reader_part(
                &mut reader,
                |_| panic!("allocation must invalidate old chain"),
                |_| panic!("allocation must invalidate old chain"),
            );
            assert_eq!(read.state, ReadState::Invalidated);
            assert_eq!(read.visited, 0);
            return;
        }
    }
    panic!("genuine allocation event missing");
}
#[test]
fn an_empty_reader_snapshot_has_full_generation_and_does_not_advance_on_other_inode() {
    let mut actor = fresh();
    let page = page();
    let snapshot = actor.reader_snapshot(inode(0)).unwrap();
    let different = actor
        .reader_snapshot(Token {
            slot: 0,
            generation: 2,
        })
        .unwrap();
    assert_ne!(snapshot, different);
    run(
        &mut actor,
        &page,
        request(1, pid(1), Command::Set(Some(Kind::Read))),
    );
    assert!(actor.reader_snapshot_valid(snapshot));
}

#[test]
fn full_new_pid_and_ofd_generations_are_never_reduced_to_numeric_places() {
    let mut actor = fresh();
    let page = page();
    assert!(page.retire(256));
    page.publish(512).unwrap();
    let new_ofd = Owner::Description {
        slot: 1,
        generation: 2,
    };
    for owner in [Owner::Process(512), new_ofd] {
        run(
            &mut actor,
            &page,
            request(0, owner, Command::Set(Some(Kind::Read))),
        );
    }
    let mut reader = actor
        .reader(request(0, pid(3), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    let blockers = read(&actor, &mut reader, &page, |token| {
        token
            == Token {
                slot: 1,
                generation: 2,
            }
    });
    assert_eq!(blockers.len(), 2);
    assert!(
        blockers
            .iter()
            .any(|lock| lock.owner == Owner::Process(512))
    );
    assert!(blockers.iter().any(|lock| lock.owner == new_ofd));
    let mut reader = actor
        .reader(request(0, pid(3), Command::Get(Kind::Write)))
        .unwrap()
        .unwrap();
    let blockers = read(&actor, &mut reader, &page, |token| {
        token
            == Token {
                slot: 1,
                generation: 1,
            }
    });
    assert_eq!(blockers.len(), 1);
    assert_eq!(blockers[0].owner, Owner::Process(512));
    assert!(!actor.pid_visible(256));
    assert!(actor.pid_visible(512));
}

#[test]
fn reader_and_eight_blocker_reply_have_small_measured_layouts() {
    let reader = core::mem::size_of::<Reader>();
    let snapshot = core::mem::size_of::<ReadSnapshot>();
    let progress = core::mem::size_of::<ReadProgress>();
    std::println!("Reader {reader}, ReadSnapshot {snapshot}, ReadProgress {progress}");
    assert!(reader <= 256);
    assert!(snapshot <= 32);
    assert!(progress <= 512);
}
