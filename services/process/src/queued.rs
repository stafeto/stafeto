// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The occurrences of signals queued behind the one on a process's page
//! (sigqueue and the real-time signals): a page holds one occurrence of a
//! signal with its information, and the rest wait here, in the order they
//! came, in a pool shared by all records. When a thread takes the occurrence
//! off the page it asks for the next (`SIGNAL_NEXT`), and the service puts
//! it on the page.
//!
//! SIGQUEUE_MAX is counted at the sender (XSH sigqueue): the occurrences a
//! process sent that wait still, queued here or on the page of a receiver.
//! Those queued here are a count (`Sent::queued`); those on pages are a list
//! of at most SIGQUEUE_MAX places (`Waiting`) that `outstanding` checks against
//! the pages, since the service does not see a thread take an occurrence off
//! a page. The pool is the limit of the system: its end is EAGAIN as well.
//! The occurrences of kill that wait for one receiver stay at
//! SIGQUEUE_MAX - 1.

use crate::signals::Info;
use proto_process::{RECORDS, SIGQUEUE_MAX};

/// Occurrences the pool holds in all.
pub const POOL: usize = 512;
const NONE: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Entry {
    signal: u8,
    info: Info,
    next: u16,
}

const BLANK: Entry = Entry {
    signal: 0,
    info: Info {
        code: 0,
        pid: 0,
        uid: 0,
        status: 0,
        value: 0,
    },
    next: NONE,
};

/// An occurrence of sigqueue on the page of a receiver: where it is and its
/// serial number (the `status` of its information on the page, which nothing
/// else uses for a sigqueue), by which the page says whether it is still
/// the one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Waiting {
    pub receiver: u8,
    pub signal: u8,
    pub serial: u32,
}

const NO_WAITING: Waiting = Waiting {
    receiver: 0,
    signal: 0,
    serial: 0,
};

/// What the process with `pid` (the sender) has waiting.
#[derive(Clone, Copy)]
struct Sent {
    pid: u32,
    /// Occurrences queued in the pool.
    queued: u16,
    held: u8,
    list: [Waiting; SIGQUEUE_MAX],
}

const NO_SENT: Sent = Sent {
    pid: 0,
    queued: 0,
    held: 0,
    list: [NO_WAITING; SIGQUEUE_MAX],
};

pub struct Queued {
    entries: [Entry; POOL],
    /// The first free entry; the free ones are linked by `next`.
    free: u16,
    /// The first and the last occurrence of each record, and how many.
    head: [u16; RECORDS],
    tail: [u16; RECORDS],
    count: [u8; RECORDS],
    /// How many of those did not come by sigqueue (they have a limit of
    /// their own at a receiver).
    others: [u8; RECORDS],
    /// What each process sent (index: the record, `pid % RECORDS`).
    sent: [Sent; RECORDS],
}

impl Default for Queued {
    fn default() -> Self {
        Self::new()
    }
}

impl Queued {
    /// What `new` makes, in place in zeroed memory (the service's `.bss`).
    ///
    /// # Safety
    /// `at` is valid for writes, exclusive and zeroed.
    #[cfg(target_os = "none")]
    pub unsafe fn initialize_at(at: *mut Self) {
        use core::ptr::addr_of_mut;
        // SAFETY: each field is in bounds and written once; `free` and
        // `count` are zero in `new`.
        unsafe {
            let entries = addr_of_mut!((*at).entries).cast::<Entry>();
            for i in 0..POOL {
                let next = if i + 1 < POOL { (i + 1) as u16 } else { NONE };
                entries.add(i).write(Entry { next, ..BLANK });
            }
            rt::bss::fill(addr_of_mut!((*at).head), NONE);
            rt::bss::fill(addr_of_mut!((*at).tail), NONE);
        }
    }

    pub const fn new() -> Self {
        let mut entries = [BLANK; POOL];
        let mut i = 0;
        while i < POOL {
            entries[i].next = if i + 1 < POOL { (i + 1) as u16 } else { NONE };
            i += 1;
        }
        Self {
            entries,
            free: 0,
            head: [NONE; RECORDS],
            tail: [NONE; RECORDS],
            count: [0; RECORDS],
            others: [0; RECORDS],
            sent: [NO_SENT; RECORDS],
        }
    }

    /// How many occurrences wait for the record.
    pub fn len(&self, record: usize) -> usize {
        usize::from(self.count[record])
    }

    /// Queues the occurrence behind the others of the record; false when the
    /// pool is empty, or the occurrence is not one of sigqueue and the record
    /// holds SIGQUEUE_MAX - 1 of those (a sigqueue is limited at its
    /// sender).
    pub fn push(&mut self, record: usize, signal: u8, info: Info) -> bool {
        let by_sigqueue = info.code == proto_process::SI_QUEUE;
        if self.free == NONE
            || (!by_sigqueue && usize::from(self.others[record]) >= SIGQUEUE_MAX - 1)
        {
            return false;
        }
        let at = self.free;
        self.free = self.entries[usize::from(at)].next;
        self.entries[usize::from(at)] = Entry {
            signal,
            info,
            next: NONE,
        };
        match self.tail[record] {
            NONE => self.head[record] = at,
            last => self.entries[usize::from(last)].next = at,
        }
        self.tail[record] = at;
        self.count[record] += 1;
        if by_sigqueue {
            self.sent_of(info.pid).queued += 1;
        } else {
            self.others[record] += 1;
        }
        true
    }

    /// The row of the sender `pid`, new when the record has another process.
    fn sent_of(&mut self, pid: u32) -> &mut Sent {
        let row = &mut self.sent[(pid % RECORDS as u32) as usize];
        if row.pid != pid {
            *row = Sent { pid, ..NO_SENT };
        }
        row
    }

    /// How many occurrences of sigqueue the process `pid` has waiting: those
    /// queued, and those on pages that `alive` still finds there. The
    /// occurrences `alive` does not find are forgotten. O(SIGQUEUE_MAX).
    pub fn outstanding(&mut self, pid: u32, alive: impl Fn(Waiting) -> bool) -> usize {
        let row = self.sent_of(pid);
        let mut kept = 0;
        for i in 0..usize::from(row.held) {
            if alive(row.list[i]) {
                row.list[kept] = row.list[i];
                kept += 1;
            }
        }
        row.held = kept as u8;
        usize::from(row.queued) + kept
    }

    /// The occurrence `held` of the process `pid` is on a page. Room is
    /// there when `outstanding` said the process had a place; a list that is
    /// full of dead places is swept by `alive` first.
    pub fn hold(&mut self, pid: u32, held: Waiting, alive: impl Fn(Waiting) -> bool) {
        if usize::from(self.sent_of(pid).held) >= SIGQUEUE_MAX {
            self.outstanding(pid, alive);
        }
        let row = self.sent_of(pid);
        if usize::from(row.held) < SIGQUEUE_MAX {
            row.list[usize::from(row.held)] = held;
            row.held += 1;
        }
    }

    /// Takes the oldest occurrence of `signal` of the record.
    pub fn take(&mut self, record: usize, signal: u8) -> Option<Info> {
        let (mut before, mut at) = (NONE, self.head[record]);
        while at != NONE {
            let entry = self.entries[usize::from(at)];
            if entry.signal == signal {
                self.unlink(record, before, at);
                return Some(entry.info);
            }
            (before, at) = (at, entry.next);
        }
        None
    }

    /// Drops every occurrence of `signal` of the record.
    pub fn drop_signal(&mut self, record: usize, signal: u8) {
        while self.take(record, signal).is_some() {}
    }

    /// Drops everything the record has queued.
    pub fn clear(&mut self, record: usize) {
        while self.head[record] != NONE {
            let at = self.head[record];
            self.unlink(record, NONE, at);
        }
    }

    /// The signals the record has queued, bit n - 1 for signal n.
    pub fn signals(&self, record: usize) -> u64 {
        let (mut set, mut at) = (0, self.head[record]);
        while at != NONE {
            let entry = &self.entries[usize::from(at)];
            set |= 1 << (entry.signal - 1);
            at = entry.next;
        }
        set
    }

    fn unlink(&mut self, record: usize, before: u16, at: u16) {
        let next = self.entries[usize::from(at)].next;
        match before {
            NONE => self.head[record] = next,
            b => self.entries[usize::from(b)].next = next,
        }
        if self.tail[record] == at {
            self.tail[record] = before;
        }
        let info = self.entries[usize::from(at)].info;
        if info.code == proto_process::SI_QUEUE {
            // Only a sender that is still the process of its record counts.
            let row = &mut self.sent[(info.pid % RECORDS as u32) as usize];
            if row.pid == info.pid {
                row.queued = row.queued.saturating_sub(1);
            }
        } else {
            self.others[record] -= 1;
        }
        self.entries[usize::from(at)].next = self.free;
        self.free = at;
        self.count[record] -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(value: u64) -> Info {
        Info {
            code: proto_process::SI_QUEUE,
            pid: 7,
            uid: 0,
            status: 0,
            value,
        }
    }

    #[test]
    fn occurrences_leave_in_the_order_they_came_for_each_signal() {
        let mut q = Queued::new();
        assert!(q.push(3, 40, info(1)));
        assert!(q.push(3, 41, info(2)));
        assert!(q.push(3, 40, info(3)));
        assert_eq!(q.len(3), 3);
        assert_eq!(q.signals(3), 1 << 39 | 1 << 40);
        assert_eq!(q.take(3, 40).map(|i| i.value), Some(1));
        assert_eq!(q.take(3, 40).map(|i| i.value), Some(3));
        assert_eq!(q.take(3, 40).map(|i| i.value), None);
        assert_eq!(q.signals(3), 1 << 40);
        assert_eq!(q.take(3, 41).map(|i| i.value), Some(2));
        assert_eq!(q.len(3), 0);
    }

    fn kill_info(value: u64) -> Info {
        Info {
            code: proto_process::SI_USER,
            ..info(value)
        }
    }

    #[test]
    fn a_receiver_holds_one_less_than_the_limit_of_kills_and_the_pool_is_shared() {
        let mut q = Queued::new();
        for i in 0..SIGQUEUE_MAX - 1 {
            assert!(q.push(1, 35, kill_info(i as u64)));
        }
        assert!(!q.push(1, 35, kill_info(99)));
        // The limit of sigqueue is the sender's: the receiver takes more.
        assert!(q.push(1, 35, info(1)));
        q.clear(1);
        assert_eq!(q.len(1), 0);
        let mut taken = 0;
        'fill: for record in 0..RECORDS {
            for _ in 0..2 * SIGQUEUE_MAX {
                if !q.push(record, 36, info(0)) {
                    break 'fill;
                }
                taken += 1;
            }
        }
        assert_eq!(taken, POOL);
        q.clear(0);
        assert!(q.push(RECORDS - 1, 36, info(0)));
    }

    fn from(pid: u32, value: u64) -> Info {
        Info { pid, ..info(value) }
    }

    #[test]
    fn what_a_sender_has_waiting_is_the_queued_and_the_held_that_are_still_there() {
        let mut q = Queued::new();
        let held = |n: u32| Waiting {
            receiver: n as u8,
            signal: 40,
            serial: n,
        };
        assert_eq!(q.outstanding(7, |_| false), 0);
        for n in 0..3u64 {
            assert!(q.push(5, 40, from(7, n)));
        }
        for n in 1..=4 {
            q.hold(7, held(n), |_| true);
        }
        assert_eq!(q.outstanding(7, |_| true), 7);
        // The receivers took the ones with an even serial.
        assert_eq!(q.outstanding(7, |h| h.serial % 2 == 1), 5);
        assert_eq!(q.outstanding(7, |_| true), 5, "what was forgotten stays so");
        // An occurrence that leaves the queue is no longer counted there.
        assert_eq!(q.take(5, 40).map(|i| i.value), Some(0));
        assert_eq!(q.outstanding(7, |_| true), 4);
        q.clear(5);
        assert_eq!(q.outstanding(7, |_| true), 2);
        // Other senders have counts of their own.
        assert_eq!(q.outstanding(8, |_| true), 0);
    }

    #[test]
    fn the_limit_is_the_senders_and_a_new_process_of_a_record_starts_clean() {
        let mut q = Queued::new();
        // Two senders put SIGQUEUE_MAX each at one receiver.
        for n in 0..SIGQUEUE_MAX as u64 {
            assert!(q.push(1, 35, from(7, n)));
            assert!(q.push(1, 35, from(9, n)));
        }
        assert_eq!(q.outstanding(7, |_| true), SIGQUEUE_MAX);
        assert_eq!(q.outstanding(9, |_| true), SIGQUEUE_MAX);
        // The process 7 ended and its record has the pid 7 + RECORDS: it has
        // nothing waiting, and the queued occurrences of the old one do not
        // lower its count when they go.
        let reused = 7 + RECORDS as u32;
        assert_eq!(q.outstanding(reused, |_| true), 0);
        assert!(q.push(2, 35, from(reused, 1)));
        q.clear(1);
        assert_eq!(q.outstanding(reused, |_| true), 1);
        assert_eq!(q.outstanding(9, |_| true), 0);
    }

    #[test]
    fn a_list_full_of_dead_places_is_swept_to_take_a_new_one() {
        let mut q = Queued::new();
        let held = |n: u32| Waiting {
            receiver: 1,
            signal: 40,
            serial: n,
        };
        for n in 0..SIGQUEUE_MAX as u32 {
            q.hold(7, held(n), |_| true);
        }
        assert_eq!(q.outstanding(7, |_| true), SIGQUEUE_MAX);
        q.hold(7, held(99), |h| h.serial >= 30);
        assert_eq!(q.outstanding(7, |_| true), 3);
    }

    #[test]
    fn dropping_a_signal_keeps_the_others_and_the_tail() {
        let mut q = Queued::new();
        q.push(2, 35, info(1));
        q.push(2, 36, info(2));
        q.push(2, 35, info(3));
        q.drop_signal(2, 35);
        assert_eq!(q.len(2), 1);
        assert!(q.push(2, 37, info(4)));
        assert_eq!(q.take(2, 36).map(|i| i.value), Some(2));
        assert_eq!(q.take(2, 37).map(|i| i.value), Some(4));
        assert_eq!(q.outstanding(7, |_| true), 0);
    }
}
