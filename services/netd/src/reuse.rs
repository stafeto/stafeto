// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The groups of SO_REUSEPORT: streams of one port and one exact address
//! that all asked for the option before BIND, under one effective user (the
//! next process may not take the port of another user, as on Linux). Each
//! member has a queue of `listen` of its own; the service names for a SYN the
//! member that the hash of the four picks among those that listen, or the next
//! that has room (the table of destinations names the first member that
//! listens; the others have no entry there). The stack hands the SYN to the
//! first socket in LISTEN of the set of the group of places of the socket
//! named, which may belong to the queue of another member, so the choice by
//! the hash holds only roughly and the connection goes to the member whose
//! socket took the SYN (`Net::adopt`).

/// The members of a group at most.
pub const REUSE_MAX: usize = 16;
/// The groups at once.
pub const GROUPS_MAX: usize = 32;
/// The group a place is in, or none.
pub const NO_GROUP: u8 = u8::MAX;

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
    members: [u16; REUSE_MAX],
}

const EMPTY: Group = Group {
    used: false,
    address: [0; 4],
    port: 0,
    uid: 0,
    len: 0,
    members: [0; REUSE_MAX],
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
            // The order of the members is kept: the hash picks by position.
            g.members.copy_within(at + 1..len, at);
            g.len -= 1;
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

    /// The member that gets a SYN of the hash `hash`: the `hash` modulo the
    /// number of members for which `listens` holds, and from there on the
    /// first that `has_room` holds for. None when no member listens or none
    /// has room.
    pub fn pick(
        &self,
        k: usize,
        hash: u64,
        mut listens: impl FnMut(usize) -> bool,
        mut has_room: impl FnMut(usize) -> bool,
    ) -> Option<usize> {
        let mut live = [0u16; REUSE_MAX];
        let mut n = 0;
        for &m in self.members(k) {
            if listens(usize::from(m)) {
                live[n] = m;
                n += 1;
            }
        }
        if n == 0 {
            return None;
        }
        let first = (hash % n as u64) as usize;
        (0..n)
            .map(|i| usize::from(live[(first + i) % n]))
            .find(|&m| has_room(m))
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

    #[test]
    fn the_hash_picks_among_the_members_that_listen_and_the_next_has_room() {
        let mut g = Groups::new();
        let k = g.join([0; 4], 80, 1, 10).unwrap();
        g.join([0; 4], 80, 1, 11).unwrap();
        g.join([0; 4], 80, 1, 12).unwrap();
        // 11 does not listen: the hash picks among 10 and 12.
        let listens = |m: usize| m != 11;
        assert_eq!(g.pick(k, 0, listens, |_| true), Some(10));
        assert_eq!(g.pick(k, 1, listens, |_| true), Some(12));
        assert_eq!(g.pick(k, 2, listens, |_| true), Some(10));
        // The one picked is full: the next goes on, round the circle.
        assert_eq!(g.pick(k, 0, listens, |m| m == 12), Some(12));
        assert_eq!(g.pick(k, 1, listens, |m| m == 10), Some(10));
        // Nobody has room, or nobody listens.
        assert_eq!(g.pick(k, 0, listens, |_| false), None);
        assert_eq!(g.pick(k, 0, |_| false, |_| true), None);
    }

    #[test]
    fn every_member_is_picked_by_some_hash() {
        let mut g = Groups::new();
        let k = g.join([0; 4], 80, 1, 0).unwrap();
        for place in 1..4 {
            g.join([0; 4], 80, 1, place).unwrap();
        }
        let mut seen = [false; 4];
        for hash in 0..16u64 {
            seen[g.pick(k, hash, |_| true, |_| true).unwrap()] = true;
        }
        assert_eq!(seen, [true; 4]);
    }
}
