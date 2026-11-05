// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sessions of 1 056 places: the search for a free number, the stack of free
//! descriptions, the receipts at the places of the keys, and the portions of a
//! clone, of CLONE_MORE and of a departure (stafeto-design#578).

use super::*;
use locks::simple::SimpleLocks;
use numbers::PLACES;
use proto_fs::{READ_ONLY, TOO_MANY_FILES_IN_SYSTEM, TOO_MANY_OPEN_FILES};

fn identity() -> authority::Identity {
    authority::Identity {
        uid: 0,
        gid: 0,
        groups: proto_process::Groups::EMPTY,
    }
}
fn held(ram: &Ram<'_>, fds: &Fds, fd: u32) -> TentativeOpen {
    TentativeOpen {
        fd,
        description: ram.description_token(fds, fd).unwrap(),
    }
}
fn refs(ram: &Ram<'_>, token: Token) -> (u16, u16) {
    let shared = ram.descriptions[token.slot as usize].as_ref().unwrap();
    (shared.refs, shared.fd_refs)
}
/// A session that holds `count` numbers of the file `/etc/motd`.
fn session(ram: &mut Ram<'_>, count: usize) -> Fds {
    let mut fds = Fds::default();
    for _ in 0..count {
        ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
    }
    fds
}

#[test]
fn a_closed_number_is_issued_again_and_the_lowest_free_one_comes_first() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    for expected in 3..3 + 200 {
        assert_eq!(ram.open(&mut fds, "/etc/motd", READ_ONLY), Ok(expected));
    }
    // Free numbers in three different words of the map: the lowest is reissued first.
    for fd in [130, 67, 3, 66] {
        ram.close(&mut fds, fd).unwrap();
    }
    assert!(!ram.wides.get(&fds).live.get(130 - 3));
    for expected in [3, 66, 67, 130, 203] {
        assert_eq!(ram.open(&mut fds, "/etc/motd", READ_ONLY), Ok(expected));
    }
    ram.release(&mut fds);
    assert!(ram.detached(&fds) && ram.wides.get(&fds).taken.is_empty());
    assert_eq!(ram.open_descriptions(), 0);
    assert_eq!(ram.wides.held(), 0);
}

#[test]
fn a_thousand_opens_pass_the_first_word_of_the_map_and_the_next_one_succeeds() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    for expected in 3..3 + 1000 {
        assert_eq!(
            ram.open(&mut fds, "/etc/motd", READ_ONLY),
            Ok(expected),
            "{expected}"
        );
    }
    // The 65th open took number 67; the 1 001st takes 1003, the last word of the map is used.
    assert_eq!(ram.open(&mut fds, "/etc/motd", READ_ONLY), Ok(1003));
    for fd in [3, 100, 1003] {
        assert_eq!(ram.read(&mut fds, fd, &mut [0; 1]), Ok(1));
    }
    ram.release(&mut fds);
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn the_places_of_a_session_end_at_emfile_and_the_service_at_enfile() {
    let mut ram = Ram::default();
    let mut fds = session(&mut ram, PLACES);
    assert_eq!(
        ram.open(&mut fds, "/etc/motd", READ_ONLY),
        Err(TOO_MANY_OPEN_FILES)
    );
    ram.release(&mut fds);
    // Eight roots of 1 024 take every description of the service: a session with
    // places to spare is told ENFILE, never EMFILE.
    let mut roots = std::vec::Vec::new();
    for id in 0..8 {
        let mut fds = Fds {
            root: storage::Root {
                id: id + 10,
                generation: 1,
            },
            ..Fds::default()
        };
        for _ in 0..DESCRIPTIONS / 8 {
            ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        }
        roots.push(fds);
    }
    let mut late = Fds::default();
    assert_eq!(
        ram.open(&mut late, "/etc/motd", READ_ONLY),
        Err(TOO_MANY_FILES_IN_SYSTEM)
    );
    for fds in &mut roots {
        ram.release(fds);
    }
}

#[test]
fn a_description_given_back_is_taken_once_and_its_old_token_is_stale() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let first = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
    let old = held(&ram, &fds, first);
    ram.close(&mut fds, first).unwrap();
    let second = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
    let third = ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
    let (second, third) = (held(&ram, &fds, second), held(&ram, &fds, third));
    // The place of the first description comes back with another generation, once.
    assert_eq!(second.description.slot, old.description.slot);
    assert!(second.description.generation > old.description.generation);
    assert_ne!(third.description.slot, second.description.slot);
    assert_eq!(held(&ram, &fds, second.fd), second);
    assert_eq!(held(&ram, &fds, third.fd), third);
    assert_ne!(ram.description_token(&fds, old.fd), Ok(old.description));
    assert_eq!(ram.close_exact_description(&mut fds, old), Ok(false));
    assert_eq!(ram.open_descriptions(), 2);
    ram.release(&mut fds);
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn the_receipt_of_a_key_place_answers_its_own_generation_and_retires_the_older() {
    let mut ram = Ram::default();
    let mut fds = Fds::default();
    let motd = Token {
        slot: 3,
        generation: 1,
    };
    let open = |ram: &mut Ram<'_>, fds: &mut Fds| {
        ram.prepare_open_token(fds, motd, READ_ONLY, identity(), None)
            .unwrap()
    };
    let key = |slot, generation| proto_fs::OpenKey { slot, generation };
    let a = open(&mut ram, &mut fds);
    ram.finish_open(&mut fds, key(5, 1), a).unwrap();
    // A second key at the same place: a new generation.
    let b = open(&mut ram, &mut fds);
    assert_ne!(a.fd, b.fd);
    ram.finish_open(&mut fds, key(5, 2), b).unwrap();
    assert_eq!(ram.finished_open(&fds, key(5, 2)), Ok(b));
    assert_eq!(
        ram.finished_open(&fds, key(5, 1)),
        Err(proto_fs::OPEN_RETIRED)
    );
    // The replay of the finished key answers the same, and no other number takes it.
    assert_eq!(ram.finish_open(&mut fds, key(5, 2), b), Ok(b));
    assert_eq!(
        ram.finish_open(&mut fds, key(5, 2), a),
        Err(proto_fs::PERMISSION)
    );
    // A key of another place, finished on a third number, leaves the first alone.
    let c = open(&mut ram, &mut fds);
    ram.finish_open(&mut fds, key(47, 9), c).unwrap();
    assert_eq!(ram.finished_open(&fds, key(5, 2)), Ok(b));
    assert_eq!(ram.finished_open(&fds, key(47, 9)), Ok(c));
    // A receipt answers only while its descriptor is open.
    ram.close(&mut fds, b.fd).unwrap();
    assert_eq!(
        ram.finished_open(&fds, key(5, 2)),
        Err(proto_fs::OPEN_RETIRED)
    );
    let d = open(&mut ram, &mut fds);
    assert_eq!(d.fd, b.fd);
    assert_eq!(
        ram.finished_open(&fds, key(5, 2)),
        Err(proto_fs::OPEN_RETIRED)
    );
    assert_eq!(
        ram.finished_open(&fds, key(48, 1)),
        Err(proto_fs::INVALID_ARGUMENT)
    );
    ram.release(&mut fds);
}

#[test]
fn a_clone_takes_a_portion_and_clone_more_the_rest_in_portions() {
    let mut ram = Ram::default();
    let mut parent = session(&mut ram, 1000);
    let all: std::vec::Vec<u32> = ram.numbers(&parent).collect();
    let mut locks = SimpleLocks::default();
    let mut child = Fds::default();
    ram.clone_fds_into(&parent, &all[..CLONE_PORTION], &mut child)
        .unwrap();
    assert_eq!(ram.numbers(&child).count(), CLONE_PORTION);
    for portion in all[CLONE_PORTION..].chunks(CLONE_PORTION) {
        ram.clone_more_fds(&parent, portion, &mut child).unwrap();
    }
    assert_eq!(ram.numbers(&child).collect::<std::vec::Vec<_>>(), all);
    for &fd in [3u32, 35, 36, 500, 1002].iter() {
        let token = held(&ram, &parent, fd);
        assert_eq!(held(&ram, &child, fd), token);
        assert_eq!(refs(&ram, token.description), (2, 2));
    }
    // A number the birth holds is passed over, once counted.
    ram.clone_more_fds(&parent, &all[..4], &mut child).unwrap();
    assert_eq!(refs(&ram, held(&ram, &parent, 3).description), (2, 2));
    // The child leaves in portions: logical death first, numbers a step at a time.
    let mut steps = 0;
    while !ram.detached(&child) {
        assert!(ram.detach_session_descriptions(&mut child, &mut locks) <= CLONE_PORTION);
        steps += 1;
    }
    assert_eq!(steps, 1000usize.div_ceil(CLONE_PORTION));
    assert_eq!(refs(&ram, held(&ram, &parent, 3).description), (2, 1));
    while ram.release_step(&mut child) {}
    assert!(child.custody_empty());
    assert_eq!(refs(&ram, held(&ram, &parent, 3).description), (1, 1));
    ram.release(&mut parent);
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn clone_more_refuses_a_number_the_caller_does_not_hold_and_changes_nothing() {
    let mut ram = Ram::default();
    let mut parent = session(&mut ram, 40);
    let mut child = Fds::default();
    ram.clone_fds_into(&parent, &[3, 4], &mut child).unwrap();
    let state = |ram: &Ram<'_>, fds: &Fds| {
        let wide = ram.wides.get(fds);
        (wide.numbers, wide.taken, wide.live)
    };
    let before = state(&ram, &child);
    let counts = refs(&ram, held(&ram, &parent, 5).description);
    // A number of none, a number no further than the places, one the caller detached.
    assert_eq!(
        ram.clone_more_fds(&parent, &[5, 6, 999], &mut child),
        Err(BAD_FD)
    );
    assert_eq!(
        ram.clone_more_fds(&parent, &[5, 2], &mut child),
        Err(BAD_FD)
    );
    let gone = held(&ram, &parent, 6);
    ram.detach_descriptor(&mut parent, gone).unwrap();
    assert_eq!(
        ram.clone_more_fds(&parent, &[5, 6], &mut child),
        Err(BAD_FD)
    );
    assert_eq!(
        ram.clone_more_fds(&parent, &[], &mut child),
        Err(proto_wire::BAD_SIZE)
    );
    // A number the birth holds with another description is refused.
    let mut other = session(&mut ram, 1);
    assert_eq!(
        ram.clone_more_fds(&other, &[3], &mut child),
        Err(BAD_FD),
        "the birth holds 3 from the parent"
    );
    assert_eq!(state(&ram, &child), before);
    assert_eq!(refs(&ram, held(&ram, &parent, 5).description), counts);
    ram.release(&mut other);
    ram.release(&mut child);
    ram.release(&mut parent);
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn a_departure_retires_a_portion_of_the_references_in_each_step() {
    let mut ram = Ram::default();
    let mut fds = session(&mut ram, PLACES);
    let mut locks = SimpleLocks::default();
    let mut rounds = 0;
    let mut total = 0;
    while !ram.detached(&fds) {
        let done = ram.detach_session_descriptions(&mut fds, &mut locks);
        assert!((1..=CLONE_PORTION).contains(&done));
        total += done;
        rounds += 1;
    }
    assert_eq!(total, PLACES);
    assert_eq!(rounds, PLACES.div_ceil(CLONE_PORTION));
    assert_eq!(ram.detach_session_descriptions(&mut fds, &mut locks), 0);
    // The numbers stay with their descriptions until each is closed in a step.
    assert!(!fds.custody_empty());
    assert_eq!(ram.open_descriptions(), PLACES);
    for left in (0..PLACES).rev() {
        assert!(ram.release_step(&mut fds));
        assert_eq!(fds.custody_empty(), left == 0);
    }
    assert_eq!(ram.open_descriptions(), 0);
}

#[test]
fn the_tables_of_numbers_come_from_a_pool_and_go_back_with_the_last_number() {
    let mut ram = Ram::default();
    // A session that holds no file has no tables, and a clone of none takes none.
    let mut empty = Fds::default();
    ram.clone_fds_into(&Fds::default(), &[], &mut empty)
        .unwrap();
    assert_eq!(ram.wides.held(), 0);
    let mut sessions = std::vec::Vec::new();
    for _ in 0..WIDES {
        let mut fds = Fds::default();
        ram.open(&mut fds, "/etc/motd", READ_ONLY).unwrap();
        sessions.push(fds);
    }
    assert_eq!(ram.wides.held(), WIDES);
    // The pool is empty: the next session is told ENFILE and takes nothing.
    let mut late = Fds::default();
    assert_eq!(
        ram.open(&mut late, "/etc/motd", READ_ONLY),
        Err(TOO_MANY_FILES_IN_SYSTEM)
    );
    assert_eq!(ram.open_descriptions(), WIDES);
    assert_eq!(ram.storage.usage(late.root).descriptions as usize, WIDES);
    // The last number of a session that goes takes its tables back, a closed one does not.
    ram.close(&mut sessions[0], 3).unwrap();
    assert_eq!(ram.wides.held(), WIDES);
    assert!(ram.release_step(&mut sessions[0]));
    assert_eq!(ram.wides.held(), WIDES - 1);
    assert_eq!(ram.open(&mut late, "/etc/motd", READ_ONLY), Ok(3));
    for fds in &mut sessions[1..] {
        ram.release(fds);
    }
    ram.release(&mut late);
    assert_eq!(ram.wides.held(), 0);
    assert_eq!(ram.open_descriptions(), 0);
}
