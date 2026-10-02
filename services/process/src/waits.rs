// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The waits of the service that wait (WaitStart answered WAIT k): each
//! under the key rt::service::LongOps gave it, in the place of the key,
//! and the keys of each record's waits, WAITS_OF_RECORD of them, so that
//! the end of a child looks at its parent's waits alone, not at all the
//! service's. A key whose operation went is stale: the caller says which
//! are alive (`live`), and a stale place is free.

use proto_process::{RECORDS, Selector};

/// The waits of one record at most (rt::service::LONG_SESSION_MAX).
pub const WAITS_OF_RECORD: usize = 16;

/// A wait that waits: its client, the record of its caller, and what it
/// takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    pub label: u64,
    pub key: u64,
    pub parent: usize,
    pub selector: Selector,
    pub options: u32,
}

pub struct Waits<const N: usize> {
    waits: [Option<Wait>; N],
    keys: [[u64; WAITS_OF_RECORD]; RECORDS],
}

impl<const N: usize> Default for Waits<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Waits<N> {
    pub const fn new() -> Self {
        Self {
            waits: [None; N],
            keys: [[0; WAITS_OF_RECORD]; RECORDS],
        }
    }

    /// The place of `key` (LongOps: the place plus 1 in its low 32 bits).
    fn slot(key: u64) -> usize {
        ((key & 0xffff_ffff) as usize).saturating_sub(1) % N
    }

    /// The wait of `key`, when `live` says its operation waits.
    pub fn get(&self, key: u64, live: impl Fn(&Wait) -> bool) -> Option<Wait> {
        self.waits[Self::slot(key)].filter(|w| w.key == key && live(w))
    }

    /// Keeps `wait` for its record; false when the record has
    /// WAITS_OF_RECORD waits that `live` says wait.
    pub fn add(&mut self, wait: Wait, live: impl Fn(&Wait) -> bool) -> bool {
        let keys = &self.keys[wait.parent];
        let free = (0..WAITS_OF_RECORD).find(|&i| self.get(keys[i], &live).is_none());
        let Some(free) = free else {
            return false;
        };
        self.keys[wait.parent][free] = wait.key;
        self.waits[Self::slot(wait.key)] = Some(wait);
        true
    }

    /// The live waits of the record in `parent` that `takes` says take the
    /// child that ended: WAITS_OF_RECORD looks at most.
    pub fn told(
        &self,
        parent: usize,
        takes: impl Fn(Selector) -> bool,
        live: impl Fn(&Wait) -> bool,
    ) -> impl Iterator<Item = Wait> + '_ {
        let found: [Option<Wait>; WAITS_OF_RECORD] = core::array::from_fn(|i| {
            self.get(self.keys[parent][i], &live)
                .filter(|w| w.parent == parent && takes(w.selector))
        });
        found.into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(label: u64, key: u64, parent: usize, selector: Selector) -> Wait {
        Wait {
            label,
            key,
            parent,
            selector,
            options: proto_process::WEXITED,
        }
    }

    /// The end of a child tells its parent's waits that take it, and no
    /// wait of another record, whatever it takes.
    #[test]
    fn a_child_tells_its_parents_waits_alone() {
        let mut w = Waits::<64>::new();
        let all = |_: &Wait| true;
        assert!(w.add(wait(10, 1 << 32 | 1, 3, Selector::Any), all));
        assert!(w.add(wait(10, 1 << 32 | 2, 3, Selector::Pid(300)), all));
        assert!(w.add(wait(20, 1 << 32 | 3, 4, Selector::Any), all));
        let told: Vec<u64> = w
            .told(3, |s| s == Selector::Any, all)
            .map(|w| w.key)
            .collect();
        assert_eq!(told, [1 << 32 | 1], "the parent's wait for any child alone");
        let by_pid: Vec<u64> = w
            .told(3, |s| matches!(s, Selector::Any | Selector::Pid(300)), all)
            .map(|w| w.key)
            .collect();
        assert_eq!(by_pid.len(), 2);
        assert_eq!(
            w.told(5, |_| true, all).count(),
            0,
            "no waits of a record of none"
        );
        // A wait that went is stale: its place and key are free again.
        let gone = |w: &Wait| w.key != (1 << 32 | 1);
        assert_eq!(w.told(3, |_| true, gone).count(), 1);
        assert!(w.get(1 << 32 | 1, gone).is_none());
    }

    #[test]
    fn a_record_keeps_waits_of_record_waits() {
        let mut w = Waits::<64>::new();
        let all = |_: &Wait| true;
        for k in 1..=WAITS_OF_RECORD as u64 {
            assert!(w.add(wait(10, 1 << 32 | k, 7, Selector::Any), all));
        }
        assert!(!w.add(wait(10, 1 << 32 | 17, 7, Selector::Any), all));
        let all_but_one = |w: &Wait| w.key != (1 << 32 | 5);
        assert!(w.add(wait(10, 1 << 32 | 17, 7, Selector::Any), all_but_one));
    }
}
