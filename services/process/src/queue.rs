// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The records whose Spawn waits for the receiving thread of the service,
//! in their order: each index once, push, pop and the removal of a record
//! that ended O(1), linked by the indices.

use proto_process::RECORDS;

pub struct Queue {
    head: Option<u16>,
    tail: Option<u16>,
    next: [Option<u16>; RECORDS],
    previous: [Option<u16>; RECORDS],
    queued: [bool; RECORDS],
}

impl Default for Queue {
    fn default() -> Self {
        Self::new()
    }
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            head: None,
            tail: None,
            next: [None; RECORDS],
            previous: [None; RECORDS],
            queued: [false; RECORDS],
        }
    }

    /// `index` at the tail; false when it waits already.
    pub fn push(&mut self, index: usize) -> bool {
        if self.queued[index] {
            return false;
        }
        self.queued[index] = true;
        self.previous[index] = self.tail;
        self.next[index] = None;
        match self.tail {
            Some(t) => self.next[usize::from(t)] = Some(index as u16),
            None => self.head = Some(index as u16),
        }
        self.tail = Some(index as u16);
        true
    }

    /// Whether no index waits.
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// The index at the head, which leaves.
    pub fn pop(&mut self) -> Option<usize> {
        let head = usize::from(self.head?);
        self.remove(head);
        Some(head)
    }

    /// `index` leaves, wherever it waits.
    pub fn remove(&mut self, index: usize) {
        if !self.queued[index] {
            return;
        }
        self.queued[index] = false;
        let (p, n) = (self.previous[index], self.next[index]);
        match p {
            Some(p) => self.next[usize::from(p)] = n,
            None => self.head = n,
        }
        match n {
            Some(n) => self.previous[usize::from(n)] = p,
            None => self.tail = p,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_leave_in_their_order_once_each() {
        let mut q = Queue::new();
        assert_eq!(q.pop(), None);
        assert!(q.push(3));
        assert!(q.push(9));
        assert!(!q.push(3), "an index waits once");
        assert!(q.push(1));
        q.remove(9);
        q.remove(9);
        assert_eq!(q.pop(), Some(3));
        assert!(q.push(3));
        assert_eq!(q.pop(), Some(1));
        q.remove(3);
        assert_eq!(q.pop(), None);
        for i in 0..RECORDS {
            assert!(q.push(i));
        }
        q.remove(0);
        q.remove(RECORDS - 1);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(
            (2..RECORDS - 1).map(|_| q.pop().unwrap()).last(),
            Some(RECORDS - 2)
        );
        assert_eq!(q.pop(), None);
    }
}
