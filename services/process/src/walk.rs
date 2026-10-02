// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The walk of kill(0), kill(-pgid) and kill(-1) over the records (spec 2,
//! 3.1): one step at a time, so that no request or notification of the
//! service waits for more than a step, however many processes there are.
//! A step looks at LOOKS places from the walk's cursor, or at the first
//! record the target takes, which it gives for the caller to deliver; the
//! caller goes back to its receive between steps, and the walk's cursor
//! is all it keeps. A record that comes or goes while the walk is on
//! may be missed or not, and no record is met twice: the cursor only
//! moves forward over the indices.

use crate::records::{Records, State};
use proto_process::RECORDS;

/// The places one step looks at at most.
pub const LOOKS: usize = 16;

/// Whom a walk takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The members of the group with this number.
    Group(u32),
    /// Every record but the sender's, and no LOADING one.
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
    /// places. A LOADING record is no target (its PID is unknown to its
    /// parent still).
    pub fn step<P>(&mut self, records: &Records<P>) -> Step {
        for _ in 0..LOOKS {
            let Some(index) = (self.cursor < RECORDS).then_some(self.cursor) else {
                return Step::Done;
            };
            self.cursor += 1;
            let taken = records.get(index).is_some_and(|r| {
                r.state != State::Loading
                    && match self.target {
                        Target::Group(pgid) => r.pgid == pgid,
                        Target::All => index != self.sender,
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::Join;
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

    /// kill(-1) takes every record but the sender's and the LOADING ones,
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
        let mut want = vec![usize::from(a.index), usize::from(b.index)];
        want.sort_unstable();
        assert_eq!(found, want);
        let mut walk = Walk::new(Target::All, usize::from(a.index));
        assert_eq!(run(&mut walk, &t).0.len(), 2, "p and the zombie b");
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
}
