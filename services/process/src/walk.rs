// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The walk of kill(0), kill(-pgid) and kill(-1) over the records (spec 2,
//! 3.1): one step at a time, so that no request or notification of the
//! service waits for more than a step, however many processes there are.
//! A step looks at LOOKS places from the walk's cursor, or at the first
//! record the target takes, which it gives for the caller to deliver; the
//! caller goes back to its receive between steps, and the walk's cursor
//! is all it keeps. No record is met twice: the cursor only moves forward
//! over the indices. A record that goes while the walk is on may be
//! missed; one born into a target in an index the walk passed gets the
//! signal at its birth (`takes_newborn`), so that no child of a member
//! escapes kill(-pgid) by its place.

use crate::records::Records;
use proto_process::RECORDS;

/// The places one step looks at at most.
pub const LOOKS: usize = 16;

/// Whom a walk takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The members of the group with this number.
    Group(u32),
    /// Every record but the sender's.
    All,
}

/// What one step found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The record in this index is a target: deliver to it.
    Found(usize),
    /// LOOKS places held no target: step again.
    Looked,
    /// Every place was seen.
    Done,
}

/// A walk of the sender in `sender` over the places of the records.
#[derive(Clone, Copy, Debug)]
pub struct Walk {
    target: Target,
    sender: usize,
    cursor: usize,
}

impl Walk {
    pub const fn new(target: Target, sender: usize) -> Self {
        Self {
            target,
            sender,
            cursor: 0,
        }
    }

    /// The next step: the first target from the cursor within LOOKS
    /// places, `Looked` when none is there, `Done` at the end of the
    /// places. A LOADING record is a target: a child a member spawns
    /// while the walk is on gets the signal, which waits on its page until
    /// it starts (or, for SIGKILL, ends its load).
    pub fn step<P>(&mut self, records: &Records<P>) -> Step {
        for _ in 0..LOOKS {
            let Some(index) = (self.cursor < RECORDS).then_some(self.cursor) else {
                return Step::Done;
            };
            self.cursor += 1;
            let taken = records.get(index).is_some_and(|r| match self.target {
                Target::Group(pgid) => r.pgid == pgid,
                Target::All => index != self.sender,
            });
            if taken {
                return Step::Found(index);
            }
        }
        if self.cursor >= RECORDS {
            Step::Done
        } else {
            Step::Looked
        }
    }
}

impl Walk {
    /// Whether a record born in `index` into group `pgid` while the walk is
    /// on is a target the walk passed already: the caller signals it at its
    /// birth. One the cursor has not passed is met by the walk itself.
    pub const fn takes_newborn(&self, index: usize, pgid: u32) -> bool {
        index < self.cursor
            && match self.target {
                Target::Group(group) => group == pgid,
                Target::All => index != self.sender,
            }
    }

    /// The sender of the walk.
    pub const fn sender(&self) -> usize {
        self.sender
    }
}

/// The status of a walk at its end ([P24-KILL]): 0 when a process took the
/// signal; else INVALID when one refused it as unsupported, PERMISSION
/// when processes were there and none could be signalled, NO_PROCESS for
/// none.
pub const fn outcome(delivered: bool, refused: bool, denied: bool) -> u32 {
    if delivered {
        0
    } else if refused {
        proto_process::INVALID
    } else if denied {
        proto_process::PERMISSION
    } else {
        proto_process::NO_PROCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{Join, State};
    use proto_process::{Credentials, End, Label};

    fn add(t: &mut Records<u32>, parent: Option<usize>, join: Join) -> Label {
        let label = t.next_label().unwrap();
        t.insert(label, 0, parent, Credentials::ROOT, 31, join);
        t.get_mut(usize::from(label.index)).unwrap().state = State::Alive;
        label
    }

    /// Walks to the end: the indices found, and the most places one step
    /// looked at (counted by the cursor).
    fn run(walk: &mut Walk, t: &Records<u32>) -> (Vec<usize>, usize, usize) {
        let (mut found, mut steps) = (Vec::new(), 0);
        let mut longest = 0;
        loop {
            let before = walk.cursor;
            let step = walk.step(t);
            longest = longest.max(walk.cursor - before);
            steps += 1;
            match step {
                Step::Found(i) => found.push(i),
                Step::Looked => {}
                Step::Done => return (found, steps, longest),
            }
            assert!(steps < 4 * RECORDS, "a walk ends");
        }
    }

    /// A group is walked once, member by member, and a step looks at
    /// LOOKS places at most, however many records there are.
    #[test]
    fn a_step_is_bounded_and_every_member_is_met_once() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t, None, Join::Inherit);
        let g = add(&mut t, Some(usize::from(p.index)), Join::NewGroup);
        let mut members = vec![usize::from(g.index)];
        // Members and others alternate; most of the table is empty.
        for i in 0..20 {
            let join = if i % 2 == 0 {
                Join::Group(g.pid())
            } else {
                Join::Inherit
            };
            let l = add(&mut t, Some(usize::from(p.index)), join);
            if i % 2 == 0 {
                members.push(usize::from(l.index));
            }
        }
        members.sort_unstable();
        let mut walk = Walk::new(Target::Group(g.pid()), usize::from(p.index));
        let (found, steps, longest) = run(&mut walk, &t);
        assert_eq!(found, members);
        // The bound is a small constant, whatever the number of records.
        assert!(longest <= 16, "a step looked at {longest} places");
        assert!(steps >= RECORDS / 16, "{RECORDS} places take {steps} steps");
        // A walk past its end stays done.
        assert_eq!(walk.step(&t), Step::Done);
    }

    /// kill(-1) takes every record but the sender's, the LOADING ones and
    /// zombies among them.
    #[test]
    fn everyone_but_the_sender() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t, None, Join::Inherit);
        let a = add(&mut t, Some(usize::from(p.index)), Join::Inherit);
        let b = add(&mut t, Some(usize::from(p.index)), Join::NewGroup);
        let loading = t.next_label().unwrap();
        t.insert(
            loading,
            0,
            Some(usize::from(p.index)),
            Credentials::ROOT,
            31,
            Join::Inherit,
        );
        let i = t.find_exit(b.exit()).unwrap();
        t.exited(i, End::Exited(0));
        let mut walk = Walk::new(Target::All, usize::from(p.index));
        let (found, _, _) = run(&mut walk, &t);
        let mut want = vec![
            usize::from(a.index),
            usize::from(b.index),
            usize::from(loading.index),
        ];
        want.sort_unstable();
        assert_eq!(found, want);
        let mut walk = Walk::new(Target::All, usize::from(a.index));
        assert_eq!(
            run(&mut walk, &t).0.len(),
            3,
            "p, the zombie b and the LOADING one"
        );
    }

    /// A member that leaves before the cursor reaches it is not met; a
    /// record that takes its index in front of the cursor is met once, and
    /// none is met twice.
    #[test]
    fn members_that_come_and_go_are_met_at_most_once() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t, None, Join::Inherit);
        let pi = usize::from(p.index);
        let g = add(&mut t, Some(pi), Join::NewGroup);
        let a = add(&mut t, Some(pi), Join::Group(g.pid()));
        let b = add(&mut t, Some(pi), Join::Group(g.pid()));
        let mut walk = Walk::new(Target::Group(g.pid()), pi);
        let mut found = Vec::new();
        loop {
            match walk.step(&t) {
                Step::Found(i) => {
                    found.push(i);
                    if i == usize::from(g.index) {
                        // a leaves before the cursor reaches it; a new
                        // member takes a free index ahead of the cursor.
                        let ai = t.find_exit(a.exit()).unwrap();
                        t.exited(ai, End::Exited(0));
                        t.reap(ai);
                        add(&mut t, Some(pi), Join::Group(g.pid()));
                    }
                }
                Step::Looked => {}
                Step::Done => break,
            }
        }
        let mut seen = found.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), found.len(), "no record twice: {found:?}");
        // The index of the member that left holds a new member, ahead of
        // the cursor: met once, as the leader and b are.
        let new = t.get(usize::from(a.index)).unwrap();
        assert_ne!(new.label.generation, a.generation);
        assert_eq!(seen, [g.index, a.index, b.index].map(usize::from));
    }

    /// A child born into the group behind the cursor is a target the walk
    /// passed: it gets the signal at its birth; one ahead of the cursor
    /// the walk meets; another group's, or the sender of kill(-1), none.
    #[test]
    fn a_newborn_behind_the_cursor_is_signalled_at_birth() {
        let mut t = Records::<u32>::new();
        let leader = add(&mut t, None, Join::Inherit);
        let member = add(&mut t, Some(usize::from(leader.index)), Join::Inherit);
        let mut walk = Walk::new(Target::Group(leader.pid()), usize::from(leader.index));
        assert_eq!(walk.step(&t), Step::Found(usize::from(leader.index)));
        assert_eq!(walk.step(&t), Step::Found(usize::from(member.index)));
        let behind = usize::from(member.index);
        assert!(walk.takes_newborn(behind, leader.pid()));
        assert!(
            !walk.takes_newborn(behind, leader.pid() + 1),
            "another group"
        );
        assert!(
            !walk.takes_newborn(200, leader.pid()),
            "ahead: the walk meets it"
        );
        let all = Walk {
            target: Target::All,
            sender: 0,
            cursor: 5,
        };
        assert!(all.takes_newborn(3, 1));
        assert!(!all.takes_newborn(0, 1), "not the sender");
    }

    /// The code at a walk's end, in the order of [P24-KILL].
    #[test]
    fn the_outcome_of_a_walk() {
        use proto_process::{INVALID, NO_PROCESS, PERMISSION};
        assert_eq!(outcome(true, true, true), 0);
        assert_eq!(outcome(false, true, true), INVALID);
        assert_eq!(outcome(false, false, true), PERMISSION);
        assert_eq!(outcome(false, false, false), NO_PROCESS);
    }
}
