// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Who a session's client is: the pure part of the binding of rules 1 and 2 of `proto_data`.
//!
//! A session is one of three things: a session of a native client of init's list (`Service`: user 0,
//! group 0, no supplementary groups, no file size limit; the mark is in its label), a session bound
//! to a process by the vouching of the process service (`Bound`), or a session with neither
//! (`Unbound`: a clone before its first BIND, or one whose binding lapsed). The worker thread of the
//! service does the vouching (it asks the process service, which is a call that waits) and hands the
//! answer to the server (`Server::bind`); this module holds what is decided from the answers:
//! which requests an unbound session may make, which identity a check uses, when the stored record
//! is asked about again, and when a binding has lapsed.

use posix_perm::{Identity, Ids};
use proto_data::Method;

/// The supplementary groups a binding keeps at most: the process service's limit.
pub const GROUPS_MAX: usize = proto_process::SUPPLEMENTARY_MAX;

/// Whose limits a session counts under. A client of init is its own root (its label); a session made
/// by SESSION counts under the root of the expenditure the process service names. The two are
/// different kinds of number and never compare equal, whatever their values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Root {
    /// The label of a client of init: it and the clones made under it.
    Label(u64),
    /// The root of the expenditure in an answer of Vouch.
    Expense(u64),
}

impl Root {
    /// The root as two plain words, for a table the other thread reads: the number and whether it
    /// is the root of an expenditure (the two kinds never compare equal).
    pub const fn key(self) -> (u64, bool) {
        match self {
            Root::Label(n) => (n, false),
            Root::Expense(n) => (n, true),
        }
    }
}

/// What the process service vouched for: one process at one generation of its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vouched {
    /// The process the identity session names.
    pub pid: u32,
    /// The place of the process's record, whose word on the page of generations is read again
    /// before each job of the session.
    pub index: u32,
    /// The generation of the process's record when it was vouched for. Reading the generation again
    /// before each job and asking again when it moved is what makes a request sent after `setuid`
    /// returned run under the new identity.
    pub generation: u64,
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub groups: [u32; GROUPS_MAX],
    pub group_count: usize,
    /// The file size limit (`RLIMIT_FSIZE`, soft), `u64::MAX` for none.
    pub fsize_limit: u64,
    /// The root of the expenditure the process counts under (the process tree's top), by which the
    /// limits of a tree are kept.
    pub root: u64,
}

impl Vouched {
    pub fn ids(&self) -> Ids {
        Ids {
            uid: self.uid,
            euid: self.euid,
            gid: self.gid,
            egid: self.egid,
        }
    }
}

/// How a session stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    Unbound,
    Service,
    Bound(Vouched),
}

/// The identity a check runs with: the identifiers, the supplementary groups and the file size
/// limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    pub ids: Ids,
    pub groups: [u32; GROUPS_MAX],
    pub group_count: usize,
    pub fsize_limit: u64,
}

impl Caller {
    /// The profile of a native client: user 0, group 0, no groups, no limit.
    pub const SERVICE: Caller = Caller {
        ids: Ids {
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
        },
        groups: [0; GROUPS_MAX],
        group_count: 0,
        fsize_limit: u64::MAX,
    };

    /// Nobody: what an unbound session runs as on the few requests it may make. No identifier of a
    /// process, no groups, a file size limit of 0, and never the superuser.
    pub const NOBODY: Caller = Caller {
        ids: Ids {
            uid: u32::MAX - 1,
            euid: u32::MAX - 1,
            gid: u32::MAX - 1,
            egid: u32::MAX - 1,
        },
        groups: [0; GROUPS_MAX],
        group_count: 0,
        fsize_limit: 0,
    };

    /// The identity of the checks: the effective pair, or the real pair when `real`.
    pub fn identity(&self, real: bool) -> Identity<'_> {
        Identity::of(self.ids, &self.groups[..self.group_count], real)
    }

    /// The groups, for `posix_perm::access`.
    pub fn groups(&self) -> &[u32] {
        &self.groups[..self.group_count]
    }

    /// Whether the effective user is 0 (the reserve and the limits of the superuser).
    pub fn is_superuser(&self) -> bool {
        self.ids.euid == 0
    }
}

impl Binding {
    /// The identity of the session, None while it is unbound.
    pub fn caller(&self) -> Option<Caller> {
        match self {
            Binding::Unbound => None,
            Binding::Service => Some(Caller::SERVICE),
            Binding::Bound(v) => Some(Caller {
                ids: v.ids(),
                groups: v.groups,
                group_count: v.group_count.min(GROUPS_MAX),
                fsize_limit: v.fsize_limit,
            }),
        }
    }

    pub fn is_bound(&self) -> bool {
        !matches!(self, Binding::Unbound)
    }
}

/// The binding a new session starts with: a label with the service mark is `Service`, any other
/// `Unbound` until SESSION or BIND binds it.
pub fn initial(label: u64) -> Binding {
    if proto_data::is_service(label) {
        Binding::Service
    } else {
        Binding::Unbound
    }
}

/// Whether a request needs the session to be bound (rule 2): everything except BIND, CLOSE, CLONE,
/// CLONE_MORE, WINDOW, RELEASE and the requests that only read or hand on a description the session
/// holds (READ, PREAD and their READ_INTO and PREAD_INTO).
pub const fn needs_binding(method: Method) -> bool {
    !matches!(
        method,
        Method::Bind
            | Method::Close
            | Method::Clone
            | Method::CloneMore
            | Method::Read
            | Method::Pread
            | Method::Seek
            | Method::Fstat
            | Method::Readdir
            | Method::Rewind
            | Method::Where
            | Method::GetFlags
            | Method::Export
            | Method::Adopt
            | Method::Window
            | Method::ReadInto
            | Method::PreadInto
            | Method::Release
    )
}

/// What the worker does about a stored binding before a job of the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refresh {
    /// The generation of the process's record is the stored one: the stored identity stands.
    Stands,
    /// The record moved (a `setuid`, a new group list, a new limit): ask the process service again
    /// with the stored copy of the identity session.
    Ask,
}

/// The stored generation against the one the page of generations shows now.
pub const fn refresh(stored: u64, now: u64) -> Refresh {
    if stored == now {
        Refresh::Stands
    } else {
        Refresh::Ask
    }
}

/// What a second vouching with the stored copy leads to: the new identity of the same process, or
/// a lapse. No answer unbinds the session: the process executed a new image (`exec` keeps the pid, but
/// the copy of the identity session of the old image vouches for nothing) or exited. An answer for
/// another process (the pid differs) unbinds it too, as a guard against an answer about someone else.
pub fn revouch(stored: &Vouched, answer: Option<Vouched>) -> Binding {
    match answer {
        Some(v) if v.pid == stored.pid => Binding::Bound(v),
        _ => Binding::Unbound,
    }
}

/// Whether BIND may bind the session: only one that is unbound (BIND on a bound session is INVALID).
pub fn may_bind(binding: &Binding) -> bool {
    matches!(binding, Binding::Unbound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vouched(pid: u32, generation: u64, euid: u32) -> Vouched {
        Vouched {
            pid,
            index: 3,
            generation,
            uid: euid,
            euid,
            suid: euid,
            gid: 100,
            egid: 100,
            sgid: 100,
            groups: [7; GROUPS_MAX],
            group_count: 2,
            fsize_limit: 1000,
            root: u64::from(pid),
        }
    }

    #[test]
    fn a_label_with_the_service_mark_is_the_superuser_and_every_other_is_unbound() {
        assert_eq!(initial(proto_data::SERVICE), Binding::Service);
        assert_eq!(initial(0), Binding::Unbound);
        // The mark of the service's own labels does not make a session a native client.
        assert_eq!(
            initial(proto_data::SERVICE | proto_data::OWN),
            Binding::Unbound
        );
        let c = Binding::Service.caller().unwrap();
        assert!(c.is_superuser() && c.groups().is_empty() && c.fsize_limit == u64::MAX);
        assert_eq!(Binding::Unbound.caller(), None);
    }

    #[test]
    fn an_unbound_session_may_only_read_or_hand_on_what_it_holds() {
        for m in Method::ALL {
            let free = matches!(
                m,
                Method::Bind
                    | Method::Close
                    | Method::Clone
                    | Method::CloneMore
                    | Method::Read
                    | Method::Pread
                    | Method::Seek
                    | Method::Fstat
                    | Method::Readdir
                    | Method::Rewind
                    | Method::Where
                    | Method::GetFlags
                    | Method::Export
                    | Method::Adopt
                    | Method::Window
                    | Method::ReadInto
                    | Method::PreadInto
                    | Method::Release
            );
            assert_eq!(needs_binding(m), !free, "{m:?}");
        }
        // Every request that names a path or writes needs a binding.
        for m in [
            Method::Open,
            Method::Write,
            Method::Pwrite,
            Method::WriteFrom,
            Method::PwriteFrom,
            Method::OpenNumbered,
            Method::MkdirNumbered,
            Method::Truncate,
            Method::Fsync,
            Method::SetFlags,
            Method::Fchmod,
            Method::Fchown,
            Method::Futimens,
            Method::Stat,
            Method::Mkdir,
            Method::Unlink,
            Method::Rmdir,
            Method::Rename,
            Method::Statfs,
            Method::Chmod,
            Method::Chown,
            Method::Utimens,
            Method::Access,
        ] {
            assert!(needs_binding(m), "{m:?}");
        }
    }

    #[test]
    fn a_moved_generation_asks_again_and_the_same_process_keeps_the_binding() {
        assert_eq!(refresh(5, 5), Refresh::Stands);
        assert_eq!(refresh(5, 6), Refresh::Ask);
        let stored = vouched(10, 5, 1000);
        // After setuid(0): the same process at the next generation, the new identity is used.
        let next = vouched(10, 6, 0);
        match revouch(&stored, Some(next)) {
            Binding::Bound(v) => {
                assert_eq!((v.euid, v.generation), (0, 6));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_answer_for_another_process_or_no_answer_lapses_the_binding() {
        let stored = vouched(10, 5, 1000);
        assert_eq!(
            revouch(&stored, Some(vouched(11, 5, 1000))),
            Binding::Unbound
        );
        assert_eq!(revouch(&stored, None), Binding::Unbound);
        // A session that lapsed may be bound again; one that is bound may not.
        assert!(may_bind(&Binding::Unbound));
        assert!(!may_bind(&Binding::Bound(stored)));
        assert!(!may_bind(&Binding::Service));
    }

    #[test]
    fn the_identity_of_a_check_is_the_effective_pair_unless_the_real_one_is_asked() {
        let mut v = vouched(10, 1, 1000);
        v.euid = 0;
        let c = Binding::Bound(v).caller().unwrap();
        assert!(c.is_superuser());
        assert_eq!(c.identity(false).uid, 0);
        assert_eq!(c.identity(true).uid, 1000);
        assert_eq!(c.groups(), &[7, 7]);
        assert_eq!(c.fsize_limit, 1000);
    }
}
