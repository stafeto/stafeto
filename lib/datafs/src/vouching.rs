// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the service's worker does with the process service's answers, without the calls: the
//! identity a `WhoReply` makes, and the look at the generation before a job (rules 1 and 2 of
//! `proto_data`). The worker passes the page of generations and the call of Vouch as closures; the
//! host tests pass a table and a counter.

use crate::binding::{Binding, GROUPS_MAX, Refresh, Vouched, refresh, revouch};
use crate::server::Server;
use proto_process::WhoReply;

/// The index of `RLIMIT_FSIZE` in the limits of a `WhoReply` (the process service's table).
const FSIZE: usize = 2;

/// The identity a process service's answer stands for.
pub fn vouched_from(who: &WhoReply) -> Vouched {
    let mut groups = [0u32; GROUPS_MAX];
    let count = (who.groups.count as usize).min(GROUPS_MAX);
    groups[..count].copy_from_slice(&who.groups.ids[..count]);
    let c = who.credentials;
    Vouched {
        pid: who.pid,
        index: who.index,
        generation: who.generation,
        uid: c.uid,
        euid: c.euid,
        suid: c.suid,
        gid: c.gid,
        egid: c.egid,
        sgid: c.sgid,
        groups,
        group_count: count,
        fsize_limit: who.limits.values[FSIZE].soft,
        root: (u64::from(who.root.pid) << 32) | u64::from(who.root.generation),
    }
}

/// How the look at a session's binding before a job ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Looked {
    /// A session of a native client, or an unbound one: nothing to look at.
    Nothing,
    /// The generation of the record is the stored one: no call was made.
    Stands,
    /// The generation moved and the process service vouched again: the identity may have changed.
    Renewed,
    /// The generation moved and the process service no longer vouches for the stored copy (another
    /// process, or none): the session is unbound and answers NOT_BOUND until BIND.
    Lapsed,
}

/// Before a job of the session `label`: reads the generation of its record again (`generation`,
/// the word of the page for the record's place, read with Acquire) and, when it moved, asks Vouch
/// once more (`ask`, with the stored copy of the identity session). The answer of another process
/// unbinds the session. A request sent after `setuid` returned is checked by the new identity.
pub fn before_job(
    server: &mut Server,
    label: u64,
    generation: impl Fn(u32) -> u64,
    ask: impl FnOnce() -> Option<WhoReply>,
) -> Looked {
    let Some(Binding::Bound(stored)) = server.binding_of(label) else {
        return Looked::Nothing;
    };
    if refresh(stored.generation, generation(stored.index)) == Refresh::Stands {
        return Looked::Stands;
    }
    let renewed = revouch(&stored, ask().map(|who| vouched_from(&who)));
    server.set_binding(label, renewed);
    match renewed {
        Binding::Bound(_) => Looked::Renewed,
        _ => Looked::Lapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{Fs, Storage};
    use crate::mem::MemDevice;
    use proto_data as p;
    use proto_process::{Credentials, ExpenditureRoot, Groups, ResourceLimits};
    use proto_wire::Writer;
    use std::boxed::Box;
    use std::cell::Cell;

    fn who(pid: u32, index: u32, generation: u64, euid: u32) -> WhoReply {
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

    fn rig() -> (Server, Fs<'static, MemDevice>) {
        let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
        let mut fs = Fs::new(MemDevice::new(4096), state).unwrap();
        fs.format().unwrap();
        fs.mount().unwrap();
        let mut server = Server::new();
        server.default_service = false;
        server::ensure(&mut fs);
        server.mount_work(&mut fs).unwrap();
        (server, fs)
    }

    mod server {
        pub fn ensure(fs: &mut crate::fs::Fs<'_, crate::mem::MemDevice>) {
            crate::server::ensure_orphans(fs).unwrap();
        }
    }

    fn call(
        server: &mut Server,
        fs: &mut Fs<'static, MemDevice>,
        label: u64,
        build: impl FnOnce(&mut Writer) -> Result<(), proto_wire::Status>,
    ) -> Result<std::vec::Vec<u8>, proto_wire::Status> {
        let mut w = Writer::new();
        build(&mut w).unwrap();
        let reply = server.handle(fs, label, 0, w.as_bytes());
        p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
    }

    #[test]
    fn an_answer_becomes_an_identity_with_the_groups_the_limit_and_the_root() {
        let v = vouched_from(&who(10, 3, 9, 1000));
        assert_eq!(
            (v.pid, v.index, v.generation, v.euid, v.egid),
            (10, 3, 9, 1000, 100)
        );
        assert_eq!(&v.groups[..v.group_count], &[7, 8]);
        // The default limit of a process on file size (the process service's initial table).
        assert_eq!(v.fsize_limit, 8 * 1024 * 1024);
        assert_eq!(v.root, (5 << 32) | 6);
    }

    #[test]
    fn a_stored_generation_that_stands_makes_no_call_and_a_moved_one_asks_once() {
        let (mut server, _fs) = rig();
        server
            .bind_new(40, vouched_from(&who(10, 3, 9, 1000)))
            .unwrap();
        let asked = Cell::new(0);
        let page = Cell::new(9u64);
        let look = |server: &mut Server, answer: Option<WhoReply>| {
            before_job(
                server,
                40,
                |_| page.get(),
                || {
                    asked.set(asked.get() + 1);
                    answer
                },
            )
        };
        assert_eq!(look(&mut server, None), Looked::Stands);
        assert_eq!(asked.get(), 0, "no call while the generation stands");
        // The record moved (setuid, a new group list): Vouch is asked once, and the answer is kept.
        page.set(10);
        assert_eq!(look(&mut server, Some(who(10, 3, 10, 0))), Looked::Renewed);
        assert_eq!(asked.get(), 1);
        match server.binding_of(40) {
            Some(Binding::Bound(v)) => assert_eq!((v.euid, v.generation), (0, 10)),
            other => panic!("{other:?}"),
        }
        // The new generation stands: no more calls.
        assert_eq!(look(&mut server, None), Looked::Stands);
        assert_eq!(asked.get(), 1);
    }

    #[test]
    fn an_answer_for_another_process_or_none_unbinds_the_session() {
        let (mut server, _fs) = rig();
        server
            .bind_new(41, vouched_from(&who(10, 3, 9, 1000)))
            .unwrap();
        let moved = |s: &mut Server, a: Option<WhoReply>| before_job(s, 41, |_| 99, || a);
        // The record at that place is another process's now (the process executed a new image, or
        // exited): the answer names another pid.
        assert_eq!(
            moved(&mut server, Some(who(11, 3, 99, 1000))),
            Looked::Lapsed
        );
        assert_eq!(server.binding_of(41), Some(Binding::Unbound));
        // The unbound session is not asked about again; a session of a native client never is.
        assert_eq!(moved(&mut server, None), Looked::Nothing);
        server
            .bind_new(42, vouched_from(&who(12, 4, 1, 1000)))
            .unwrap();
        assert_eq!(before_job(&mut server, 42, |_| 2, || None), Looked::Lapsed);
        assert_eq!(
            before_job(&mut server, p::SERVICE | 7, |_| 0, || None),
            Looked::Nothing
        );
    }

    #[test]
    fn after_a_change_of_euid_the_check_uses_the_new_identity() {
        let (mut server, mut fs) = rig();
        const ROOT: u64 = p::SERVICE | 1;
        // A directory only user 0 may enter, and a file in it.
        call(&mut server, &mut fs, ROOT, |w| p::mkdir(b"/d", 0o700, w)).unwrap();
        let h = call(&mut server, &mut fs, ROOT, |w| {
            p::open(b"/d/f", p::WRITE | p::CREATE, 0o600, w)
        })
        .unwrap();
        let _ = h;
        // A process of user 1000 binds a session; its stat is refused.
        server
            .bind_new(50, vouched_from(&who(20, 6, 1, 1000)))
            .unwrap();
        let stat = |server: &mut Server, fs: &mut Fs<'static, MemDevice>| {
            call(server, fs, 50, |w| {
                p::path_call(p::Method::Stat, b"/d/f", w)
            })
            .map(drop)
        };
        let page = Cell::new(1u64);
        let look = |server: &mut Server, euid: u32| {
            before_job(
                server,
                50,
                |_| page.get(),
                || Some(who(20, 6, page.get(), euid)),
            )
        };
        assert_eq!(look(&mut server, 1000), Looked::Stands);
        assert_eq!(stat(&mut server, &mut fs), Err(p::code(p::ACCESS)));
        // setuid(0) returned: the generation of the record moved; the very next job is checked by
        // the new identity.
        page.set(2);
        assert_eq!(look(&mut server, 0), Looked::Renewed);
        assert_eq!(stat(&mut server, &mut fs), Ok(()));
        // Back to 1000: refused again.
        page.set(3);
        assert_eq!(look(&mut server, 1000), Looked::Renewed);
        assert_eq!(stat(&mut server, &mut fs), Err(p::code(p::ACCESS)));
    }
}
