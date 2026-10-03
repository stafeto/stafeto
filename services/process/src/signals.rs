// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the service decides of a signal for a process (spec 2, 3.3): who
//! may send it (`may_signal`, kill's rule), which it refuses until stops
//! come (`refused`), and how it lands on the record's page (`post`): an
//! ignored signal goes, the first sending's information stays until a
//! thread takes the signal, and the bit is set after it (Release), so
//! that a thread that sees the bit sees the information.

use core::sync::atomic::Ordering;
use proto_process::{
    Credentials, Page, SIGCONT, SIGKILL, SIGNAL_MAX, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU,
};

/// Whether a process of `sender`'s credentials may send a signal to one of
/// `target`'s ([P24-KILL]): an effective UID of 0, or a real or effective
/// UID of the sender equal to the real or saved UID of the target; SIGCONT
/// also within one session (`same_session`).
pub const fn may_signal(
    sender: Credentials,
    target: Credentials,
    signal: u8,
    same_session: bool,
) -> bool {
    sender.euid == 0
        || sender.uid == target.uid
        || sender.uid == target.suid
        || sender.euid == target.uid
        || sender.euid == target.suid
        || (signal == SIGCONT && same_session)
}

/// The bit of `signal` (1 to SIGNAL_MAX) in the page's sets.
pub const fn bit(signal: u8) -> u64 {
    1 << (signal - 1)
}

/// Whether the service refuses `signal` for the target of `page` (EINVAL,
/// [P24-KILL] "unsupported signal"): past SIGNAL_MAX, SIGSTOP, and
/// SIGTSTP, SIGTTIN, SIGTTOU unless the target catches or ignores them,
/// until stops come (5e).
pub fn refused(signal: u8, page: &Page) -> bool {
    if signal > SIGNAL_MAX || signal == SIGSTOP {
        return true;
    }
    let handled = page.caught.load(Ordering::Acquire) | page.ignored.load(Ordering::Acquire);
    matches!(signal, SIGTSTP | SIGTTIN | SIGTTOU) && handled & bit(signal) == 0
}

/// What became of a signal sent to a process (`post`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posted {
    /// Its action ignores it: it goes.
    Ignored,
    /// It waits on the page now: the router's entry takes it.
    Pending,
    /// It waited already, with its first information.
    Merged,
}

/// The information of a sending: si_code, the sender's PID and real UID,
/// the child's status for SIGCHLD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub code: i32,
    pub pid: u32,
    pub uid: u32,
    pub status: i32,
}

/// Posts `signal` (1 to SIGNAL_MAX except SIGKILL, which the service carries
/// out itself) with `info` on `page`. The service is the page's one
/// writer of the information and of the bits it sets; a thread of the
/// process clears a bit when it takes the signal.
pub fn post(page: &Page, signal: u8, info: Info) -> Posted {
    debug_assert!(signal != SIGKILL && (1..=SIGNAL_MAX).contains(&signal));
    let bit = bit(signal);
    if page.ignored.load(Ordering::Acquire) & bit != 0 {
        return Posted::Ignored;
    }
    if page.pending.load(Ordering::Acquire) & bit != 0 {
        return Posted::Merged;
    }
    let slot = &page.info[usize::from(signal - 1)];
    slot.code.store(info.code, Ordering::Relaxed);
    slot.pid.store(info.pid, Ordering::Relaxed);
    slot.uid.store(info.uid, Ordering::Relaxed);
    slot.status.store(info.status, Ordering::Relaxed);
    if page.pending.fetch_or(bit, Ordering::Release) & bit != 0 {
        return Posted::Merged;
    }
    Posted::Pending
}

/// The page of a new child: a spawned one's main thread starts with
/// `mask`, and the parent's SIG_IGN pass but those of `default`
/// ([P24-SPAWN]); a forked one takes the classes of its parent's actions
/// and its flags of SIGCHLD, which ForkStart named ([P24-FORK]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageStart {
    Spawn {
        mask: u64,
        default: u64,
    },
    Fork {
        ignored: u64,
        caught: u64,
        flags: u64,
    },
}

impl PageStart {
    /// Writes the words of `page`, the child's, from `from`, its parent's;
    /// the service does so before the record is a target of any walk.
    pub fn write(self, page: &Page, from: &Page) {
        use core::sync::atomic::Ordering::{Acquire, Release};
        match self {
            PageStart::Spawn { mask, default } => {
                page.start_mask.store(mask, Release);
                let ignored = from.ignored.load(Acquire) & !default;
                page.ignored.store(ignored, Release);
            }
            PageStart::Fork {
                ignored,
                caught,
                flags,
            } => {
                page.ignored.store(ignored, Release);
                page.caught.store(caught, Release);
                page.flags.store(flags, Release);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::{SIGCHLD, SIGTERM, SIGUSR1};

    fn page() -> Box<Page> {
        // SAFETY: a Page is atomics and integers, for which zero is valid.
        unsafe { Box::new(core::mem::zeroed()) }
    }

    fn ids(uid: u32, euid: u32, suid: u32) -> Credentials {
        Credentials {
            uid,
            euid,
            suid,
            gid: 0,
            egid: 0,
            sgid: 0,
        }
    }

    /// kill's rule of permission, by the numbers.
    #[test]
    fn who_may_signal_whom() {
        let root = Credentials::ROOT;
        let nobody = Credentials::NOBODY;
        let user = ids(1000, 1000, 1000);
        assert!(may_signal(root, user, SIGTERM, false));
        assert!(may_signal(user, user, SIGTERM, false));
        assert!(!may_signal(user, root, SIGTERM, false));
        assert!(!may_signal(nobody, user, SIGTERM, false));
        // The sender's real or effective UID against the target's real or
        // saved one; the target's effective UID counts for nothing.
        assert!(may_signal(ids(1000, 5, 5), ids(7, 7, 1000), SIGTERM, false));
        assert!(may_signal(ids(5, 1000, 5), ids(1000, 7, 7), SIGTERM, false));
        assert!(!may_signal(
            ids(5, 5, 1000),
            ids(1000, 1000, 1000),
            SIGTERM,
            false
        ));
        assert!(!may_signal(user, ids(7, 1000, 7), SIGTERM, false));
        assert!(may_signal(user, root, SIGCONT, true));
        assert!(!may_signal(user, root, SIGCONT, false));
    }

    /// An ignored signal goes; the first sending's information stays.
    #[test]
    fn a_signal_lands_on_the_page_once() {
        let p = page();
        p.ignored.store(bit(SIGCHLD), Ordering::Relaxed);
        let info = |pid| Info {
            code: 0,
            pid,
            uid: 1000,
            status: 0,
        };
        assert_eq!(post(&p, SIGCHLD, info(300)), Posted::Ignored);
        assert_eq!(p.pending.load(Ordering::Relaxed), 0);
        assert_eq!(post(&p, SIGTERM, info(300)), Posted::Pending);
        assert_eq!(post(&p, SIGTERM, info(301)), Posted::Merged);
        let slot = &p.info[usize::from(SIGTERM - 1)];
        assert_eq!(slot.pid.load(Ordering::Relaxed), 300, "the first siginfo");
        assert_eq!(p.pending.load(Ordering::Relaxed), bit(SIGTERM));
        // A thread took it: the next sending's information is kept.
        p.pending.fetch_and(!bit(SIGTERM), Ordering::Relaxed);
        assert_eq!(post(&p, SIGTERM, info(302)), Posted::Pending);
        assert_eq!(slot.pid.load(Ordering::Relaxed), 302);
    }

    /// SIGSTOP always, the job-control stops unless handled, and numbers
    /// past 64 are refused.
    #[test]
    fn stops_are_refused_until_5e() {
        let p = page();
        assert!(refused(SIGSTOP, &p));
        assert!(refused(SIGTSTP, &p));
        assert!(refused(65, &p));
        assert!(!refused(SIGUSR1, &p));
        p.caught.store(bit(SIGTSTP), Ordering::Relaxed);
        p.ignored.store(bit(SIGTTIN), Ordering::Relaxed);
        assert!(!refused(SIGTSTP, &p));
        assert!(!refused(SIGTTIN, &p));
        assert!(refused(SIGTTOU, &p));
        assert!(!refused(SIGCONT, &p));
    }

    /// A forked child's page has its parent's classes from its start, so
    /// a signal its parent ignores never waits on it; a spawned child's
    /// passes the parent's SIG_IGN but those set to the default.
    #[test]
    fn a_new_page_takes_what_its_child_starts_with() {
        use proto_process::{PAGE_NOCLDWAIT, SIGHUP, SIGTERM};
        let parent = page();
        parent
            .ignored
            .store(bit(SIGHUP) | bit(SIGTERM), Ordering::Relaxed);
        let forked = page();
        PageStart::Fork {
            ignored: bit(SIGHUP),
            caught: bit(SIGUSR1),
            flags: PAGE_NOCLDWAIT,
        }
        .write(&forked, &parent);
        assert_eq!(forked.ignored.load(Ordering::Relaxed), bit(SIGHUP));
        assert_eq!(forked.caught.load(Ordering::Relaxed), bit(SIGUSR1));
        assert_eq!(forked.flags.load(Ordering::Relaxed), PAGE_NOCLDWAIT);
        let info = Info {
            code: 0,
            pid: 2,
            uid: 0,
            status: 0,
        };
        assert_eq!(post(&forked, SIGHUP, info), Posted::Ignored);
        assert_eq!(forked.pending.load(Ordering::Relaxed), 0);
        assert_eq!(post(&forked, SIGUSR1, info), Posted::Pending);
        let spawned = page();
        PageStart::Spawn {
            mask: 1 << 3,
            default: bit(SIGTERM),
        }
        .write(&spawned, &parent);
        assert_eq!(spawned.ignored.load(Ordering::Relaxed), bit(SIGHUP));
        assert_eq!(spawned.start_mask.load(Ordering::Relaxed), 1 << 3);
        assert_eq!(spawned.caught.load(Ordering::Relaxed), 0);
    }
}
