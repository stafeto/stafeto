// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The occurrences of signals queued behind the one on a process's page
//! (sigqueue and the real-time signals): a page holds one occurrence of a
//! signal with its information, and the rest wait here, in the order they
//! came, in a pool shared by all records with at most SIGQUEUE_MAX - 1 for
//! each. When a thread takes the occurrence off the page it asks for the next
//! (`SIGNAL_NEXT`), and the service puts it on the page.

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

pub struct Queued {
    entries: [Entry; POOL],
    /// The first free entry; the free ones are linked by `next`.
    free: u16,
    /// The first and the last occurrence of each record, and how many.
    head: [u16; RECORDS],
    tail: [u16; RECORDS],
    count: [u8; RECORDS],
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
        }
    }

    /// How many occurrences wait for the record.
    pub fn len(&self, record: usize) -> usize {
        usize::from(self.count[record])
    }

    /// Queues the occurrence behind the others of the record; false when
    /// the record holds SIGQUEUE_MAX - 1 or the pool is empty.
    pub fn push(&mut self, record: usize, signal: u8, info: Info) -> bool {
        if self.len(record) >= SIGQUEUE_MAX - 1 || self.free == NONE {
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
        true
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

    /// How many of the queued occurrences of the record came by sigqueue.
    pub fn sent_by_sigqueue(&self, record: usize) -> usize {
        let (mut n, mut at) = (0, self.head[record]);
        while at != NONE {
            let entry = &self.entries[usize::from(at)];
            n += usize::from(entry.info.code == proto_process::SI_QUEUE);
            at = entry.next;
        }
        n
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

    #[test]
    fn a_record_holds_one_less_than_the_limit_and_the_pool_is_shared() {
        let mut q = Queued::new();
        for i in 0..SIGQUEUE_MAX - 1 {
            assert!(q.push(1, 35, info(i as u64)));
        }
        assert!(!q.push(1, 35, info(99)));
        q.clear(1);
        assert_eq!(q.len(1), 0);
        let mut taken = 0;
        'fill: for record in 0..RECORDS {
            for _ in 0..SIGQUEUE_MAX - 1 {
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
        assert_eq!(q.sent_by_sigqueue(2), 0);
    }
}
