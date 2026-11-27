// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Who the client of a session is, as `lib/datafs` keeps it (`binding`, `vouching`): a session
//! made by SESSION is bound at birth to the process the copy of its identity session names, the
//! process service vouches for the copy (Vouch), and the service reads the generation of the
//! process's record on the page of generations before each request: when it moved (a `setuid`, an
//! `exec`, a new group list) the service asks Vouch again with the stored copy, and a request sent
//! after `setuid` returned runs under the new identity. An answer for another process, or none,
//! unbinds the session, which then answers AUTHENTICATING until BIND. The answer about a loader is
//! no identity: Vouch also vouches for the copy a loader holds while a set-ID image loads.

use posix_perm::{Identity, Ids};
use proto_process::WhoReply;

pub const GROUPS_MAX: usize = proto_process::SUPPLEMENTARY_MAX;

/// What the process service vouched for: one process at one generation of its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vouched {
    pub pid: u32,
    /// The place of the process's record on the page of generations.
    pub index: u32,
    pub generation: u64,
    pub ids: Ids,
    pub groups: [u32; GROUPS_MAX],
    pub group_count: usize,
}

impl Vouched {
    pub fn identity(&self, real: bool) -> Identity<'_> {
        Identity::of(self.ids, &self.groups[..self.group_count], real)
    }

    pub fn groups(&self) -> &[u32] {
        &self.groups[..self.group_count]
    }
}

/// None for the answer about a loader.
pub fn vouched_from(who: &WhoReply) -> Option<Vouched> {
    if who.loader.is_some() {
        return None;
    }
    let mut groups = [0u32; GROUPS_MAX];
    let count = (who.groups.count as usize).min(GROUPS_MAX);
    groups[..count].copy_from_slice(&who.groups.ids[..count]);
    let c = who.credentials;
    Some(Vouched {
        pid: who.pid,
        index: who.index,
        generation: who.generation,
        ids: Ids {
            uid: c.uid,
            euid: c.euid,
            gid: c.gid,
            egid: c.egid,
        },
        groups,
        group_count: count,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    Unbound,
    Bound(Vouched),
}

/// How the look at a binding before a request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Looked {
    /// Nothing to look at (an unbound session).
    Nothing,
    /// The generation of the record is the stored one: no call was made.
    Stands,
    /// The generation moved and the process service vouched again.
    Renewed,
    /// The generation moved and the process service no longer vouches for the stored copy.
    Lapsed,
}

impl Binding {
    pub fn bound(&self) -> Option<&Vouched> {
        match self {
            Binding::Bound(v) => Some(v),
            Binding::Unbound => None,
        }
    }

    /// Before a request: reads the generation of the stored record again (`generation`, the word
    /// of the page for the record's place) and, when it moved, asks Vouch once more (`ask`, with
    /// the stored copy of the identity session).
    pub fn look(
        &mut self,
        generation: impl FnOnce(u32) -> u64,
        ask: impl FnOnce() -> Option<WhoReply>,
    ) -> Looked {
        let Binding::Bound(stored) = *self else {
            return Looked::Nothing;
        };
        if generation(stored.index) == stored.generation {
            return Looked::Stands;
        }
        match ask().and_then(|who| vouched_from(&who)) {
            Some(v) if v.pid == stored.pid => {
                *self = Binding::Bound(v);
                Looked::Renewed
            }
            _ => {
                *self = Binding::Unbound;
                Looked::Lapsed
            }
        }
    }
}

/// An answer of the process service for tests: a process of the user `uid` in group `uid`.
#[cfg(test)]
pub(crate) fn tests_who(uid: u32) -> WhoReply {
    tests::who(7, 1, 1, uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::{Credentials, ExpenditureRoot, Groups, ResourceLimits};

    pub(crate) fn who(pid: u32, index: u32, generation: u64, euid: u32) -> WhoReply {
        WhoReply {
            pid,
            credentials: Credentials {
                uid: 1000,
                euid,
                suid: 1000,
                gid: 100,
                egid: 100,
                sgid: 100,
            },
            generation,
            loader: None,
            index,
            ceiling: 31,
            ctty: None,
            image: 0,
            groups: Groups {
                count: 2,
                ids: {
                    let mut ids = [0; proto_process::SUPPLEMENTARY_MAX];
                    ids[0] = 7;
                    ids[1] = 8;
                    ids
                },
            },
            limits: ResourceLimits::initial(1 << 20),
            root: ExpenditureRoot {
                pid: 5,
                generation: 6,
            },
        }
    }

    #[test]
    fn an_answer_becomes_an_identity_with_its_groups() {
        let v = vouched_from(&who(10, 3, 9, 1000)).unwrap();
        assert_eq!((v.pid, v.index, v.generation), (10, 3, 9));
        assert_eq!((v.ids.euid, v.ids.egid), (1000, 100));
        assert_eq!(v.groups(), &[7, 8]);
        assert_eq!(v.identity(false).uid, 1000);
    }

    #[test]
    fn a_standing_generation_asks_nothing_and_a_moved_one_asks_once() {
        let mut b = Binding::Bound(vouched_from(&who(10, 3, 9, 1000)).unwrap());
        let asked = core::cell::Cell::new(0);
        assert_eq!(
            b.look(
                |i| {
                    assert_eq!(i, 3);
                    9
                },
                || {
                    asked.set(asked.get() + 1);
                    None
                }
            ),
            Looked::Stands
        );
        assert_eq!(asked.get(), 0);
        let looked = b.look(
            |_| 10,
            || {
                asked.set(asked.get() + 1);
                Some(who(10, 3, 10, 0))
            },
        );
        assert_eq!((looked, asked.get()), (Looked::Renewed, 1));
        assert_eq!(b.bound().unwrap().ids.euid, 0);
        assert_eq!(b.look(|_| 10, || None), Looked::Stands);
    }

    #[test]
    fn another_process_none_or_a_loader_unbinds_the_session() {
        for answer in [Some(who(11, 3, 99, 1000)), None, {
            let mut w = who(10, 3, 99, 0);
            w.loader = Some(proto_process::LoaderOf {
                image: 1,
                ticket: 2,
            });
            Some(w)
        }] {
            let mut b = Binding::Bound(vouched_from(&who(10, 3, 9, 1000)).unwrap());
            assert_eq!(b.look(|_| 99, || answer), Looked::Lapsed);
            assert_eq!(b, Binding::Unbound);
            assert_eq!(b.look(|_| 0, || None), Looked::Nothing);
        }
    }
}
