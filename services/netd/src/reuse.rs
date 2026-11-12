// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The groups of SO_REUSEPORT: streams of one port and one exact address
//! that all asked for the option before BIND, under one effective user (the
//! next process may not take the port of another user, as on Linux). Each
//! member has a queue of `listen` of its own. The service names for a SYN the
//! next member after the last one chosen that listens and has room in its
//! queue (the table of destinations names the first member that listens; the
//! others have no entry there). The stack hands the SYN to the first socket in
//! LISTEN of the set of places of the socket named; the sets keep the queue
//! sockets of different members apart (`owners`), so that socket is the
//! chosen member's own and the choice is exact. A member that is full is
//! skipped, and so is one the service believed to listen that turns out not
//! to (the next member after it is tried). Each group counts the SYNs each
//! member took (`served`), which the profile exports by position.

/// The members of a group at most.
pub const REUSE_MAX: usize = 16;
/// The groups at once.
pub const GROUPS_MAX: usize = 32;
/// The group a place is in, or none.
pub const NO_GROUP: u8 = u8::MAX;
/// The positions the profile counts apart: a member at a later position is
/// counted with the last.
pub const SERVED_POSITIONS: usize = 8;

/// What a group asks of the sockets while it picks a member.
pub trait Members {
    /// Whether the member `place` listens and has room in its queue.
    fn usable(&mut self, place: usize) -> bool;
    /// Whether the member `place`, found usable, can take the SYN. A member
    /// that cannot is left out of the choice by the implementation (it is no
    /// longer usable), and the next one is tried.
    fn confirm(&mut self, place: usize) -> bool;
}

/// Why a place cannot join a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The group has `REUSE_MAX` members, or no group is free.
    Full,
    /// The group belongs to another user.
    OtherUser,
}

#[derive(Clone, Copy)]
struct Group {
    used: bool,
    address: [u8; 4],
    port: u16,
    uid: u32,
    len: u8,
    /// Where the circle goes on: the position of the member to look at first.
    next: u8,
    members: [u16; REUSE_MAX],
    /// The SYNs each member took, by position.
    served: [u64; REUSE_MAX],
}

const EMPTY: Group = Group {
    used: false,
    address: [0; 4],
    port: 0,
    uid: 0,
    len: 0,
    next: 0,
    members: [0; REUSE_MAX],
    served: [0; REUSE_MAX],
};

/// The groups.
pub struct Groups {
    groups: [Group; GROUPS_MAX],
}

impl Default for Groups {
    fn default() -> Self {
        Self::new()
    }
}

impl Groups {
    pub const fn new() -> Self {
        Groups {
            groups: [EMPTY; GROUPS_MAX],
        }
    }

    /// The group of `address` and `port`, if there is one.
    pub fn find(&self, address: [u8; 4], port: u16) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.used && g.port == port && g.address == address)
    }

    /// Puts `place` into the group of `address` and `port` (made when there
    /// is none) for the user `uid`: the group.
    pub fn join(
        &mut self,
        address: [u8; 4],
        port: u16,
        uid: u32,
        place: usize,
    ) -> Result<usize, Refused> {
        let k = match self.find(address, port) {
            Some(k) => {
                if self.groups[k].uid != uid {
                    return Err(Refused::OtherUser);
                }
                k
            }
            None => {
                let k = self
                    .groups
                    .iter()
                    .position(|g| !g.used)
                    .ok_or(Refused::Full)?;
                self.groups[k] = Group {
                    used: true,
                    address,
                    port,
                    uid,
                    ..EMPTY
                };
                k
            }
        };
        let g = &mut self.groups[k];
        if usize::from(g.len) >= REUSE_MAX {
            return Err(Refused::Full);
        }
        g.members[usize::from(g.len)] = place as u16;
        g.served[usize::from(g.len)] = 0;
        g.len += 1;
        Ok(k)
    }

    /// Takes `place` out of group `k`; the group goes with its last member.
    pub fn leave(&mut self, k: usize, place: usize) {
        let g = &mut self.groups[k];
        let len = usize::from(g.len);
        if let Some(at) = g.members[..len]
            .iter()
            .position(|&m| usize::from(m) == place)
        {
            // The order of the members is kept: the circle goes by position.
            g.members.copy_within(at + 1..len, at);
            g.served.copy_within(at + 1..len, at);
            g.len -= 1;
            // A member before the pointer left: the pointer moves back with
            // the rest, so the circle does not jump over the next member.
            if at < usize::from(g.next) {
                g.next -= 1;
            }
            if g.next >= g.len {
                g.next = 0;
            }
        }
        if g.len == 0 {
            *g = EMPTY;
        }
    }

    /// The members of group `k`.
    pub fn members(&self, k: usize) -> &[u16] {
        let g = &self.groups[k];
        &g.members[..usize::from(g.len)]
    }

    /// The member that gets the next SYN: the first from the pointer of the
    /// circle for which `usable` holds (it listens and has room in its
    /// queue); the pointer goes on to the member after it. None when no member
    /// is usable.
    pub fn pick(&mut self, k: usize, mut usable: impl FnMut(usize) -> bool) -> Option<usize> {
        let g = &mut self.groups[k];
        let len = usize::from(g.len);
        let first = usize::from(g.next);
        for i in 0..len {
            let at = (first + i) % len;
            let m = usize::from(g.members[at]);
            if usable(m) {
                g.next = ((at + 1) % len) as u8;
                return Some(m);
            }
        }
        None
    }
}

impl Groups {
    /// The member that takes the next SYN: the circle's choice among the
    /// usable members whose `confirm` holds, at most `REUSE_MAX` tries. The
    /// SYN is counted for the member. None when no member takes it.
    pub fn pick_member(&mut self, k: usize, members: &mut impl Members) -> Option<usize> {
        for _ in 0..REUSE_MAX {
            let m = self.pick(k, |m| members.usable(m))?;
            if members.confirm(m) {
                let g = &mut self.groups[k];
                if let Some(at) = g.members[..usize::from(g.len)]
                    .iter()
                    .position(|&p| usize::from(p) == m)
                {
                    g.served[at] += 1;
                }
                return Some(m);
            }
        }
        None
    }

    /// The SYNs the members took, summed over the groups by position (a
    /// position beyond `SERVED_POSITIONS` is counted in the last).
    pub fn served_by_position(&self) -> [u64; SERVED_POSITIONS] {
        let mut out = [0; SERVED_POSITIONS];
        for g in self.groups.iter().filter(|g| g.used) {
            for (at, n) in g.served[..usize::from(g.len)].iter().enumerate() {
                out[at.min(SERVED_POSITIONS - 1)] += n;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_is_made_by_its_first_member_and_goes_with_its_last() {
        let mut g = Groups::new();
        let k = g.join([0; 4], 80, 7, 3).unwrap();
        assert_eq!(g.join([0; 4], 80, 7, 9), Ok(k));
        assert_eq!(g.members(k), [3, 9]);
        assert_eq!(g.find([0; 4], 80), Some(k));
        g.leave(k, 3);
        assert_eq!(g.members(k), [9]);
        g.leave(k, 9);
        assert_eq!(g.find([0; 4], 80), None);
    }

    #[test]
    fn another_user_may_not_join() {
        let mut g = Groups::new();
        g.join([0; 4], 80, 7, 1).unwrap();
        assert_eq!(g.join([0; 4], 80, 8, 2), Err(Refused::OtherUser));
        // Another address is another group.
        assert!(g.join([10, 0, 2, 15], 80, 8, 2).is_ok());
    }

    #[test]
    fn a_group_holds_sixteen_members() {
        let mut g = Groups::new();
        for place in 0..REUSE_MAX {
            g.join([0; 4], 80, 1, place).unwrap();
        }
        assert_eq!(g.join([0; 4], 80, 1, 99), Err(Refused::Full));
    }

    #[test]
    fn thirty_two_groups_at_most() {
        let mut g = Groups::new();
        for port in 0..GROUPS_MAX as u16 {
            g.join([0; 4], 1000 + port, 1, 0).unwrap();
        }
        assert_eq!(g.join([0; 4], 9, 1, 0), Err(Refused::Full));
    }

    fn four() -> (Groups, usize) {
        let mut g = Groups::new();
        let k = g.join([0; 4], 80, 1, 10).unwrap();
        for place in 11..14 {
            g.join([0; 4], 80, 1, place).unwrap();
        }
        (g, k)
    }

    #[test]
    fn the_circle_gives_each_member_the_same_share() {
        let (mut g, k) = four();
        let mut count = [0u32; 4];
        for _ in 0..256 {
            count[g.pick(k, |_| true).unwrap() - 10] += 1;
        }
        assert_eq!(count, [64; 4]);
    }

    #[test]
    fn a_member_with_no_room_or_not_listening_is_skipped() {
        let (mut g, k) = four();
        let mut got = Vec::new();
        for _ in 0..6 {
            got.push(g.pick(k, |m| m != 11 && m != 12).unwrap());
        }
        assert_eq!(got, [10, 13, 10, 13, 10, 13]);
        assert_eq!(g.pick(k, |_| false), None);
    }

    #[test]
    fn the_circle_does_not_jump_when_a_member_leaves() {
        let (mut g, k) = four();
        assert_eq!(g.pick(k, |_| true), Some(10));
        assert_eq!(g.pick(k, |_| true), Some(11));
        // 12 is next; 10 leaves, from before the pointer.
        g.leave(k, 10);
        assert_eq!(g.pick(k, |_| true), Some(12));
        assert_eq!(g.pick(k, |_| true), Some(13));
        assert_eq!(g.pick(k, |_| true), Some(11));
        // The member at the pointer leaves: the one after it is next.
        g.leave(k, 12);
        assert_eq!(g.pick(k, |_| true), Some(13));
        // A member before the pointer and then one at it leave.
        g.leave(k, 11);
        g.join([0; 4], 80, 1, 20).unwrap();
        assert_eq!(g.pick(k, |_| true), Some(13));
        assert_eq!(g.pick(k, |_| true), Some(20));
    }

    #[test]
    fn a_new_member_is_picked_within_len_picks() {
        let (mut g, k) = four();
        for _ in 0..7 {
            g.pick(k, |_| true);
        }
        g.join([0; 4], 80, 1, 99).unwrap();
        let seen: Vec<_> = (0..5).map(|_| g.pick(k, |_| true).unwrap()).collect();
        assert!(seen.contains(&99), "{seen:?}");
    }

    /// Members for a test: the places in `dead` look usable and cannot take
    /// the SYN (a count behind), and are usable no more once found out.
    struct Fake {
        dead: Vec<usize>,
        found_out: Vec<usize>,
        confirms: u32,
    }

    impl Members for Fake {
        fn usable(&mut self, place: usize) -> bool {
            !self.found_out.contains(&place)
        }
        fn confirm(&mut self, place: usize) -> bool {
            self.confirms += 1;
            if self.dead.contains(&place) {
                self.found_out.push(place);
                return false;
            }
            true
        }
    }

    #[test]
    fn a_member_that_cannot_take_the_syn_leaves_the_choice_to_the_next_one() {
        let (mut g, k) = four();
        // The circle is at 10, which is dead: the SYN goes to 11, not away.
        let mut f = Fake {
            dead: vec![10],
            found_out: Vec::new(),
            confirms: 0,
        };
        assert_eq!(g.pick_member(k, &mut f), Some(11));
        assert_eq!(f.confirms, 2);
        // The ones after it come in turn; the dead one is not tried again.
        assert_eq!(g.pick_member(k, &mut f), Some(12));
        assert_eq!(g.pick_member(k, &mut f), Some(13));
        assert_eq!(g.pick_member(k, &mut f), Some(11));
        assert_eq!(f.confirms, 5);
        // Every member dead: none, after at most REUSE_MAX tries.
        let mut all = Fake {
            dead: vec![10, 11, 12, 13],
            found_out: Vec::new(),
            confirms: 0,
        };
        assert_eq!(g.pick_member(k, &mut all), None);
        assert_eq!(all.confirms, 4);
    }

    #[test]
    fn each_member_counts_the_syns_it_took_by_position() {
        let (mut g, k) = four();
        let mut f = Fake {
            dead: vec![11],
            found_out: Vec::new(),
            confirms: 0,
        };
        for _ in 0..9 {
            g.pick_member(k, &mut f).unwrap();
        }
        // 11 is dead: nine SYNs go to 10, 12 and 13 in turn, three each.
        assert_eq!(g.served_by_position(), [3, 0, 3, 3, 0, 0, 0, 0]);
        // A second group adds at its own positions; a leaving member takes
        // its count along and the positions close up.
        let k2 = g.join([0; 4], 81, 1, 30).unwrap();
        let mut all = Fake {
            dead: Vec::new(),
            found_out: Vec::new(),
            confirms: 0,
        };
        g.pick_member(k2, &mut all).unwrap();
        assert_eq!(g.served_by_position(), [4, 0, 3, 3, 0, 0, 0, 0]);
        g.leave(k, 10);
        assert_eq!(g.served_by_position(), [1, 3, 3, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_member_beyond_the_counted_positions_is_counted_in_the_last() {
        let mut g = Groups::new();
        let k = g.join([0; 4], 80, 1, 0).unwrap();
        for place in 1..12 {
            g.join([0; 4], 80, 1, place).unwrap();
        }
        let mut all = Fake {
            dead: Vec::new(),
            found_out: Vec::new(),
            confirms: 0,
        };
        for _ in 0..12 {
            g.pick_member(k, &mut all).unwrap();
        }
        assert_eq!(g.served_by_position(), [1, 1, 1, 1, 1, 1, 1, 5]);
    }
}
