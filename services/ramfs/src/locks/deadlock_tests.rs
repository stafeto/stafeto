// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

extern crate std;
use super::*;
use crate::locks::{
    Kind, Lock, Range,
    actor::{Actor, Command, Request, Response},
};
use proto_process::lifetimes::Page;
use std::vec::Vec;

fn scope(scan: u64) -> Scope {
    Scope {
        owner: 1,
        key: WaitKey {
            slot: 0,
            generation: 1,
        },
        scan,
    }
}
fn inode(slot: u16) -> Token {
    Token {
        slot,
        generation: 1,
    }
}
fn page(count: usize) -> Page {
    let page = Page::new();
    for index in 0..count {
        page.publish(256 + index as u32).unwrap();
    }
    page
}
fn graph(count: usize) -> Graph {
    let mut graph = Graph::new(256, scope(1)).unwrap();
    for index in 1..count {
        graph.register(256 + index as u32).unwrap();
    }
    graph.begin().unwrap();
    graph
}
fn watch(graph: &mut Graph, vertex: Vertex, inode: Token) -> Watch {
    for _ in 0..3 {
        let part = graph.watch_part(vertex, inode).unwrap();
        assert!(part.visited <= PORTION);
        if let WatchPart::Ready(watch) = part.part {
            return watch;
        }
    }
    panic!("bounded watch setup did not finish");
}
fn next(graph: &mut Graph, page: &Page) -> Progress {
    let mut life = 0;
    let mut inodes = 0;
    let progress = graph.step(
        |pid| {
            life += 1;
            page.live(pid)
        },
        |_| {
            inodes += 1;
            true
        },
    );
    assert!(progress.visited <= PORTION);
    assert!(life + inodes <= PORTION);
    assert!(life + inodes <= progress.visited);
    progress
}
fn drive(graph: &mut Graph, page: &Page, edges: &[&[usize]]) -> Verdict {
    for _ in 0..256 {
        match next(graph, page).work {
            Work::NeedEdges(vertex) => {
                let index = (vertex.pid() - 256) as usize;
                watch(graph, vertex, inode(index as u16));
                for &to in edges[index] {
                    graph
                        .blocker(vertex, Owner::Process(256 + to as u32))
                        .unwrap();
                }
                graph
                    .finish_edges(vertex, !edges[index].is_empty())
                    .unwrap();
            }
            Work::ClearWatch(watch) => graph.unwatched(watch).unwrap(),
            Work::Done(verdict) => return verdict,
            Work::Progress | Work::Rebuild => {}
            Work::Cleaned => panic!("unexpected cleanup"),
        }
    }
    panic!("graph failed its finite progress bound");
}

#[test]
fn second_genuine_published_blocker_can_complete_the_candidate_cycle() {
    type Table = Actor<16, 4, 256, 128, 2, 16>;
    let page = page(4);
    let mut allocation = std::boxed::Box::<Table>::new_uninit();
    // SAFETY: exclusive aligned actor storage is initialized field by field.
    let mut table = unsafe {
        Table::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    };
    let range = |start, length| Range::relative(0, start, length).unwrap();
    let mut run = |pid, file, range, command| {
        for _ in 0..256 {
            if !table.busy() {
                break;
            }
            assert!(table.step_with_life(|pid| page.live(pid)).visited <= PORTION);
        }
        assert!(
            !table.busy(),
            "paid cleanup must finish before next actor start"
        );
        table
            .start(Request {
                owner: Owner::Process(pid),
                inode: inode(file),
                root: 0,
                range,
                command,
            })
            .unwrap();
        for _ in 0..256 {
            let progress = table.step_with_life(|pid| page.live(pid));
            assert!(progress.visited <= PORTION);
            if let Some(result) = progress.completed {
                return result.unwrap();
            }
        }
        panic!("actor did not finish");
    };
    assert_eq!(
        run(257, 0, range(0, 5), Command::Set(Some(Kind::Read))),
        Response::Changed
    );
    assert_eq!(
        run(258, 0, range(5, 5), Command::Set(Some(Kind::Read))),
        Response::Changed
    );
    assert_eq!(
        run(256, 1, range(0, 10), Command::Set(Some(Kind::Write))),
        Response::Changed
    );
    assert_eq!(
        run(259, 2, range(0, 10), Command::Set(Some(Kind::Write))),
        Response::Changed
    );
    let Response::Blocker(Some(forward)) = run(257, 2, range(0, 10), Command::Get(Kind::Write))
    else {
        panic!("actual blocker outside the waiting graph");
    };
    let Response::Blocker(Some(first)) = run(256, 0, range(0, 5), Command::Get(Kind::Write)) else {
        panic!("first actual blocker");
    };
    let Response::Blocker(Some(second)) = run(256, 0, range(5, 5), Command::Get(Kind::Write))
    else {
        panic!("second actual blocker");
    };
    let Response::Blocker(Some(back)) = run(258, 1, range(0, 10), Command::Get(Kind::Write)) else {
        panic!("actual reverse blocker");
    };
    let request = Lock {
        owner: Owner::Process(256),
        kind: Kind::Write,
        range: range(0, 10),
    };
    assert!(first.conflicts(request));
    assert!(second.conflicts(request));
    let mut graph = Graph::new(256, scope(1)).unwrap();
    graph.register(257).unwrap();
    graph.register(258).unwrap();
    graph.begin().unwrap();
    for _ in 0..64 {
        match next(&mut graph, &page).work {
            Work::NeedEdges(vertex) => {
                if vertex.pid() == 256 {
                    watch(&mut graph, vertex, inode(0));
                    graph.blocker(vertex, first.owner).unwrap();
                    graph.blocker(vertex, second.owner).unwrap();
                } else if vertex.pid() == 257 {
                    watch(&mut graph, vertex, inode(2));
                    graph.blocker(vertex, forward.owner).unwrap();
                } else {
                    watch(&mut graph, vertex, inode(1));
                    graph.blocker(vertex, back.owner).unwrap();
                }
                graph.finish_edges(vertex, true).unwrap();
            }
            Work::Done(verdict) => {
                assert_eq!(verdict, Verdict::Deadlock);
                return;
            }
            Work::Progress => {}
            _ => panic!("unexpected work"),
        }
    }
    panic!("genuine blocker cycle not detected");
}

#[test]
fn reachable_foreign_cycle_does_not_implicate_candidate() {
    assert_eq!(
        drive(&mut graph(3), &page(3), &[&[1], &[2], &[1]]),
        Verdict::NoCycle
    );
    assert_eq!(
        drive(&mut graph(3), &page(3), &[&[], &[2], &[1]]),
        Verdict::NoCycle
    );
}
#[test]
fn own_pid_and_ofd_are_not_pid_dependency_edges() {
    let mut graph = graph(1);
    let page = page(1);
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    watch(&mut graph, vertex, inode(0));
    graph.blocker(vertex, Owner::Process(256)).unwrap();
    graph
        .blocker(
            vertex,
            Owner::Description {
                slot: 0,
                generation: 1,
            },
        )
        .unwrap();
    graph.finish_edges(vertex, true).unwrap();
    assert_eq!(drive(&mut graph, &page, &[&[]]), Verdict::NoCycle);
}
#[test]
fn same_pid_registrations_union_blockers_from_all_waits_and_inodes() {
    let mut graph = Graph::new(256, scope(1)).unwrap();
    assert_eq!(graph.register(256).unwrap(), graph.register(256).unwrap());
    graph.register(257).unwrap();
    graph.register(258).unwrap();
    graph.begin().unwrap();
    let page = page(3);
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    watch(&mut graph, vertex, inode(0));
    graph.blocker(vertex, Owner::Process(257)).unwrap();
    watch(&mut graph, vertex, inode(3));
    graph.blocker(vertex, Owner::Process(258)).unwrap();
    graph.finish_edges(vertex, true).unwrap();
    assert_eq!(
        drive(&mut graph, &page, &[&[1, 2], &[], &[0]]),
        Verdict::Deadlock
    );
}
#[test]
fn exact_pid_generation_never_overwrites_a_reused_process_place() {
    let page = page(2);
    page.retire(256);
    page.publish(512).unwrap();
    assert!(!page.live(256));
    assert!(page.live(512));
    let mut graph = Graph::new(257, scope(1)).unwrap();
    let old = graph.register(256).unwrap();
    assert_eq!(graph.register(512), Err(Error::PidCollision));
    assert_eq!(graph.register(256), Ok(old));
    graph.begin().unwrap();
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    watch(&mut graph, vertex, inode(0));
    graph.blocker(vertex, Owner::Process(512)).unwrap();
    graph.finish_edges(vertex, true).unwrap();
    assert_eq!(next(&mut graph, &page).visited, 1);
    assert_eq!(next(&mut graph, &page).work, Work::Done(Verdict::NoCycle));
}
#[test]
fn sixteen_vertex_cycle_and_final_checks_are_split_into_eight_object_steps() {
    let mut graph = graph(16);
    let page = page(16);
    let edges: Vec<Vec<usize>> = (0..16).map(|n| std::vec![(n + 1) % 16]).collect();
    let refs: Vec<&[usize]> = edges.iter().map(Vec::as_slice).collect();
    assert_eq!(drive(&mut graph, &page, &refs), Verdict::Deadlock);
    assert_eq!(graph.watch_count, 16);
    assert_eq!(graph.cycle.count_ones(), 16);
    assert!(core::mem::size_of::<Graph>() <= 4096);
    std::println!(
        "deadlock Graph={} Watch={} Progress={}",
        core::mem::size_of::<Graph>(),
        core::mem::size_of::<Watch>(),
        core::mem::size_of::<Progress>()
    );
}
#[test]
fn fifteen_new_parents_do_not_hide_an_unbounded_vertex_walk() {
    let mut graph = graph(16);
    let page = page(16);
    let mut expanded = Vec::new();
    for _ in 0..128 {
        let before = matches!(graph.phase, Phase::Expand { .. });
        let progress = next(&mut graph, &page);
        if before {
            expanded.push(progress.visited);
        }
        match progress.work {
            Work::NeedEdges(vertex) => {
                watch(&mut graph, vertex, inode(vertex.index as u16));
                if vertex.pid() == 256 {
                    for to in 257..272 {
                        graph.blocker(vertex, Owner::Process(to)).unwrap();
                    }
                } else {
                    graph.blocker(vertex, Owner::Process(256)).unwrap();
                }
                graph.finish_edges(vertex, true).unwrap();
            }
            Work::Done(verdict) => {
                assert_eq!(verdict, Verdict::Deadlock);
                assert_eq!(&expanded[..2], &[8, 7]);
                return;
            }
            Work::Progress => {}
            _ => panic!(),
        }
    }
    panic!();
}
#[test]
fn life_death_and_inode_invalidation_never_publish_the_stale_cycle() {
    for death in [false, true] {
        let mut graph = graph(2);
        let page = page(2);
        for _ in 0..64 {
            if matches!(graph.phase, Phase::Life(_)) && death {
                page.retire(257);
            }
            let progress = graph.step(|pid| page.live(pid), |_| death);
            assert!(progress.visited <= PORTION);
            match progress.work {
                Work::NeedEdges(vertex) => {
                    watch(&mut graph, vertex, inode(vertex.index as u16));
                    graph
                        .blocker(
                            vertex,
                            Owner::Process(if vertex.pid() == 256 { 257 } else { 256 }),
                        )
                        .unwrap();
                    graph.finish_edges(vertex, true).unwrap();
                }
                Work::ClearWatch(watch) => {
                    graph.unwatched(watch).unwrap();
                }
                Work::Rebuild => break,
                Work::Done(verdict) => panic!("stale cycle reached {verdict:?}"),
                Work::Progress => {}
                Work::Cleaned => panic!(),
            }
        }
        assert!(matches!(graph.phase, Phase::Traverse));
        assert_eq!(graph.round, 1);
    }
}
#[test]
fn third_dirty_attempt_defers_with_acknowledged_watches_and_finite_progress() {
    let mut graph = graph(2);
    let page = page(2);
    let mut rounds = 0;
    let mut cleared = 0;
    for _ in 0..128 {
        match next(&mut graph, &page).work {
            Work::NeedEdges(vertex) => {
                let watch = watch(&mut graph, vertex, inode(0));
                assert!(graph.changed(watch));
            }
            Work::ClearWatch(watch) => {
                graph.unwatched(watch).unwrap();
                cleared += 1;
            }
            Work::Rebuild => rounds += 1,
            Work::Done(verdict) => {
                assert_eq!(verdict, Verdict::Deferred);
                assert_eq!(rounds, 2);
                assert_eq!(cleared, 3);
                assert_eq!(graph.watch_count, 0);
                return;
            }
            Work::Progress => {}
            Work::Cleaned => panic!(),
        }
    }
    panic!("dirty source stalled graph forever");
}
#[test]
fn unwatch_ack_is_required_before_rebuild_and_stale_attempt_watch_is_ignored() {
    let mut graph = graph(2);
    let page = page(2);
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    let old = watch(&mut graph, vertex, inode(0));
    graph.changed(old);
    assert_eq!(next(&mut graph, &page).work, Work::ClearWatch(old));
    for _ in 0..16 {
        assert_eq!(next(&mut graph, &page).work, Work::ClearWatch(old));
        assert_eq!(graph.round, 0);
    }
    graph.unwatched(old).unwrap();
    assert_eq!(graph.unwatched(old), Err(Error::Invalid));
    for _ in 0..8 {
        if next(&mut graph, &page).work == Work::Rebuild {
            break;
        }
    }
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    let fresh = watch(&mut graph, vertex, inode(0));
    assert_ne!(old, fresh);
    assert!(!graph.changed(old));
    assert!(!graph.dirty);
    assert!(graph.changed(fresh));
}
#[test]
fn another_scan_or_inode_generation_cannot_dirty_a_recycled_watch() {
    let page = page(1);
    let mut old = graph(1);
    let Work::NeedEdges(vertex) = next(&mut old, &page).work else {
        panic!();
    };
    let stale = watch(&mut old, vertex, inode(0));
    old.finish_edges(vertex, false).unwrap();
    assert_eq!(drive(&mut old, &page, &[&[]]), Verdict::NoCycle);
    old.cleanup().unwrap();
    for _ in 0..32 {
        match next(&mut old, &page).work {
            Work::ClearWatch(watch) => old.unwatched(watch).unwrap(),
            Work::Cleaned => break,
            Work::Progress => {}
            _ => panic!("wrong cleanup phase"),
        }
    }
    assert!(matches!(old.phase, Phase::Cleaned));
    let mut fresh = Graph::new(256, scope(2)).unwrap();
    fresh.begin().unwrap();
    let Work::NeedEdges(vertex) = next(&mut fresh, &page).work else {
        panic!();
    };
    let now = watch(&mut fresh, vertex, inode(0));
    assert!(!fresh.changed(stale));
    assert!(!fresh.dirty);
    let changed_inode = Token {
        generation: 2,
        ..inode(0)
    };
    assert_eq!(
        fresh.watch_part(vertex, changed_inode),
        Err(Error::StaleInode)
    );
    let unrelated = Watch {
        inode: inode(1),
        ..now
    };
    assert!(!fresh.changed(unrelated));
}
#[test]
fn watch_lookup_is_bounded_and_continuation_cannot_skip_or_switch_inode() {
    let mut graph = graph(1);
    let page = page(1);
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    for slot in 0..8 {
        watch(&mut graph, vertex, inode(slot));
    }
    let part = graph.watch_part(vertex, inode(8)).unwrap();
    assert_eq!(part.visited, 8);
    assert_eq!(part.part, WatchPart::Continue);
    assert_eq!(graph.finish_edges(vertex, false), Err(Error::Phase));
    assert_eq!(graph.watch_part(vertex, inode(9)), Err(Error::Phase));
    let part = graph.watch_part(vertex, inode(8)).unwrap();
    assert_eq!(part.visited, 1);
    assert!(matches!(part.part, WatchPart::Ready(_)));
    for slot in 9..16 {
        watch(&mut graph, vertex, inode(slot));
    }
    let same = watch(&mut graph, vertex, inode(0));
    assert_eq!(same.index, 0);
    for _ in 0..2 {
        assert_eq!(
            graph.watch_part(vertex, inode(16)).unwrap().part,
            WatchPart::Continue
        );
    }
    assert_eq!(graph.watch_part(vertex, inode(16)), Err(Error::Full));
}
#[test]
fn scope_pid_and_phase_inputs_are_checked_before_mutating_the_graph() {
    for pid in [0, 1, 255, i32::MAX as u32 + 1, u32::MAX] {
        assert!(matches!(Graph::new(pid, scope(1)), Err(Error::Invalid)));
    }
    assert!(Graph::new(i32::MAX as u32, scope(1)).is_ok());
    assert!(matches!(Graph::new(256, scope(0)), Err(Error::Invalid)));
    let mut graph = graph(16);
    assert_eq!(graph.register(272), Err(Error::Phase));
    let mut vertices = Graph::new(256, scope(1)).unwrap();
    for pid in 257..272 {
        vertices.register(pid).unwrap();
    }
    assert_eq!(vertices.register(272), Err(Error::Full));
    let page = page(16);
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    assert_eq!(
        graph.blocker(vertex, Owner::Process(257)),
        Err(Error::Phase)
    );
    assert_eq!(graph.finish_edges(vertex, true), Err(Error::Invalid));
    watch(&mut graph, vertex, inode(0));
    graph.blocker(vertex, Owner::Process(257)).unwrap();
    assert_eq!(graph.finish_edges(vertex, false), Err(Error::Invalid));
}

#[test]
fn dirty_between_eight_object_final_barrier_portions_discards_the_proof() {
    for during_life in [false, true] {
        let mut graph = graph(16);
        let page = page(16);
        for _ in 0..256 {
            let at_barrier = if during_life {
                matches!(graph.phase, Phase::Life(_))
            } else {
                matches!(graph.phase, Phase::Inodes(_))
            };
            if at_barrier {
                assert_eq!(next(&mut graph, &page).visited, 8);
                let watch = graph.watches[0].unwrap();
                assert!(graph.changed(watch));
                assert_eq!(next(&mut graph, &page).work, Work::ClearWatch(watch));
                assert_eq!(graph.round, 0);
                break;
            }
            match next(&mut graph, &page).work {
                Work::NeedEdges(vertex) => {
                    watch(&mut graph, vertex, inode(vertex.index as u16));
                    graph
                        .blocker(
                            vertex,
                            Owner::Process(256 + u32::from((vertex.index + 1) % 16)),
                        )
                        .unwrap();
                    graph.finish_edges(vertex, true).unwrap();
                }
                Work::Progress => {}
                work => panic!("unexpected barrier work {work:?}"),
            }
        }
        assert!(matches!(graph.phase, Phase::Clear { .. }));
    }
}
#[test]
fn process_label_slot_mapping_agrees_with_the_actual_lifetime_page() {
    let page = Page::new();
    page.publish(256).unwrap();
    page.publish(384).unwrap();
    assert!(page.live(256));
    assert!(page.live(384));
    let mut graph = Graph::new(256, scope(1)).unwrap();
    assert_eq!(graph.register(384).unwrap().pid(), 384);
    for pid in [
        0,
        1,
        255,
        256,
        384,
        511,
        512,
        i32::MAX as u32,
        i32::MAX as u32 + 1,
        u32::MAX,
    ] {
        let page = Page::new();
        assert_eq!(
            page.publish(pid).is_ok(),
            Graph::new(pid, scope(1)).is_ok(),
            "{pid}"
        );
    }
}
#[test]
fn defer_during_partial_unwatch_preserves_acknowledged_retirement() {
    let mut graph = graph(1);
    let page = page(1);
    let Work::NeedEdges(vertex) = next(&mut graph, &page).work else {
        panic!();
    };
    let first = watch(&mut graph, vertex, inode(0));
    let second = watch(&mut graph, vertex, inode(1));
    graph.changed(first);
    assert_eq!(next(&mut graph, &page).work, Work::ClearWatch(first));
    graph.unwatched(first).unwrap();
    graph.defer().unwrap();
    assert_eq!(next(&mut graph, &page).work, Work::ClearWatch(second));
    graph.unwatched(second).unwrap();
    for _ in 0..4 {
        if next(&mut graph, &page).work == Work::Done(Verdict::Deferred) {
            return;
        }
    }
    panic!("deferral lost an acknowledgement");
}

#[test]
fn permanent_graph_initialization_and_episode_restart_clear_sixteen_in_two_portions() {
    let mut allocation = std::boxed::Box::<Graph>::new_uninit();
    // SAFETY: exclusive aligned writable graph allocation.
    let mut graph = unsafe {
        Graph::initialize_empty_at(allocation.as_mut_ptr());
        allocation.assume_init()
    };
    assert_eq!(graph.step(|_| false, |_| false).work, Work::Cleaned);
    graph.restart(256, scope(1)).unwrap();
    assert!(!graph.seed_ready());
    assert_eq!(graph.step(|_| false, |_| false).visited, 0);
    assert_eq!(graph.step(|_| false, |_| false).visited, 1);
    assert!(graph.seed_ready());
    for pid in 257..272 {
        graph.register(pid).unwrap();
    }
    graph.begin().unwrap();
    let Work::NeedEdges(vertex) = graph.step(|_| true, |_| true).work else {
        panic!("missing vertex")
    };
    let old_watch = watch(&mut graph, vertex, inode(0));
    assert_eq!(graph.restart(512, scope(2)), Err(Error::Phase));
    graph.defer().unwrap();
    assert_eq!(
        graph.step(|_| true, |_| true).work,
        Work::ClearWatch(old_watch)
    );
    assert_eq!(graph.restart(512, scope(2)), Err(Error::Phase));
    graph.unwatched(old_watch).unwrap();
    graph.step(|_| true, |_| true);
    assert_eq!(
        graph.step(|_| true, |_| true).work,
        Work::Done(Verdict::Deferred)
    );
    graph.cleanup().unwrap();
    graph.step(|_| true, |_| true);
    assert_eq!(graph.step(|_| true, |_| true).work, Work::Cleaned);
    assert_eq!(graph.restart(512, scope(1)), Err(Error::Invalid));
    graph.restart(512, scope(2)).unwrap();
    assert_eq!(graph.step(|_| false, |_| false).visited, 8);
    assert!(!graph.seed_ready());
    assert_eq!(graph.step(|_| false, |_| false).visited, 8);
    assert!(!graph.seed_ready());
    assert_eq!(graph.step(|_| false, |_| false).visited, 1);
    assert!(graph.seed_ready());
    assert_eq!(graph.register(512).unwrap().pid(), 512);
    for pid in 513..528 {
        graph.register(pid).unwrap();
    }
    graph.begin().unwrap();
    assert!(!graph.changed(old_watch));
    println!(
        "permanent Graph={} Pool={}",
        core::mem::size_of::<Graph>(),
        core::mem::size_of::<crate::locks::waiters::Pool>()
    );
}
