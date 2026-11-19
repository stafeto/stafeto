// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use proto_pipe::named::WatchSet;
use proto_wire::watch::MAX;

#[derive(Clone, Copy)]
struct Registration {
    label: u64,
    key: u64,
    set: WatchSet,
    queues: [u8; MAX],
    retired: bool,
    cleaned: u8,
    /// How many of the record's unique queues are subscribed so far.
    registered: u8,
    /// How many unique queues the record has in all.
    wanted: u8,
    /// A later portion of subscriptions was refused: `Take` answers AGAIN.
    refused: bool,
}

/// The most queues one step of the service subscribes a watch to. A request
/// subscribes the first portion and answers `Wait`, and a turn of the
/// service's own subscribes each next portion, so no step grows with the
/// size of the set (at most `MAX` = 32 elements). In `posix-poll` the
/// request step of a set of 32 was 19563 ticks against the bound of
/// 20410 (96 %); the portion of 16 brings it to about 15200, under 0.9 of
/// the bound (18369). Should a run show more than 16500, lower this to 8.
pub const WATCH_STEP_QUEUES: usize = 16;
/// Each readiness operation subscribes once to an underlying queue: a ring
/// end (0 to 127) or a socket (128 to 255).
pub fn unique_queues(queues: &[u8]) -> impl Iterator<Item = u32> + '_ {
    let mut seen = [0u128; 2];
    queues
        .iter()
        .copied()
        .filter(move |&queue| {
            let bit = 1u128 << (queue % 128);
            let word = &mut seen[usize::from(queue / 128)];
            let fresh = *word & bit == 0;
            *word |= bit;
            fresh
        })
        .map(u32::from)
}

pub struct Pool<const N: usize> {
    list: [Option<Registration>; N],
}
impl<const N: usize> Default for Pool<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Pool<N> {
    /// What `new` makes, in place in zeroed memory (the service's `.bss`).
    ///
    /// # Safety
    /// `at` is valid for writes, exclusive and zeroed.
    pub unsafe fn initialize_at(at: *mut Self) {
        // SAFETY: the field is in bounds.
        let list = unsafe { core::ptr::addr_of_mut!((*at).list) }.cast::<Option<Registration>>();
        for i in 0..N {
            // SAFETY: the element `i` of the array is in bounds.
            unsafe { list.add(i).write(None) };
        }
    }

    pub const fn new() -> Self {
        Self { list: [None; N] }
    }
    pub fn insert(&mut self, label: u64, key: u64, set: WatchSet, queues: [u8; MAX]) -> bool {
        let Some(free) = self.list.iter_mut().find(|r| r.is_none()) else {
            return false;
        };
        *free = Some(Registration {
            label,
            key,
            set,
            queues,
            retired: false,
            cleaned: 0,
            registered: 0,
            wanted: unique_queues(&queues[..set.len]).count() as u8,
            refused: false,
        });
        true
    }
    fn live_mut(&mut self, label: u64, key: u64) -> Option<&mut Registration> {
        self.list
            .iter_mut()
            .flatten()
            .find(|r| !r.retired && r.label == label && r.key == key)
    }
    /// How many unique queues of the live record are subscribed.
    pub fn registered(&self, label: u64, key: u64) -> Option<usize> {
        self.list
            .iter()
            .flatten()
            .find(|r| !r.retired && r.label == label && r.key == key)
            .map(|r| usize::from(r.registered))
    }
    /// The record has `n` unique queues subscribed.
    pub fn mark_registered(&mut self, label: u64, key: u64, n: usize) {
        if let Some(r) = self.live_mut(label, key) {
            r.registered = n as u8;
        }
    }
    /// The first live record with queues still to subscribe.
    pub fn pending(&self) -> Option<(u64, u64)> {
        self.list
            .iter()
            .flatten()
            .find(|r| !r.retired && !r.refused && r.registered < r.wanted)
            .map(|r| (r.label, r.key))
    }
    /// A later portion was refused: the record stays (a `Cancel` takes it
    /// off) and `Take` answers AGAIN.
    pub fn refuse(&mut self, label: u64, key: u64) {
        if let Some(r) = self.live_mut(label, key) {
            r.refused = true;
        }
    }
    pub fn refused(&self, label: u64, key: u64) -> bool {
        self.list
            .iter()
            .flatten()
            .any(|r| !r.retired && r.label == label && r.key == key && r.refused)
    }
    pub fn get(&self, label: u64, key: u64) -> Option<&WatchSet> {
        self.list
            .iter()
            .flatten()
            .find(|r| !r.retired && r.label == label && r.key == key)
            .map(|r| &r.set)
    }
    pub fn remove(&mut self, label: u64, key: u64) -> Option<WatchSet> {
        self.list
            .iter_mut()
            .find(|r| r.is_some_and(|r| !r.retired && r.label == label && r.key == key))?
            .take()
            .map(|r| r.set)
    }
    pub fn queues(&self, label: u64, key: u64) -> Option<&[u8; MAX]> {
        self.list
            .iter()
            .flatten()
            .find(|r| !r.retired && r.label == label && r.key == key)
            .map(|r| &r.queues)
    }
    pub fn retire(&mut self, label: u64) {
        for r in self.list.iter_mut().flatten().filter(|r| r.label == label) {
            r.retired = true;
        }
    }
    pub fn cleanup_due(&self) -> bool {
        self.list.iter().flatten().any(|r| r.retired)
    }
    pub fn cleanup(&mut self) -> Option<(u64, u64, u32)> {
        let slot = self
            .list
            .iter_mut()
            .find(|r| r.is_some_and(|r| r.retired))?;
        let r = slot.as_mut()?;
        let result = (r.label, r.key, u32::from(r.queues[usize::from(r.cleaned)]));
        r.cleaned += 1;
        if usize::from(r.cleaned) == r.set.len {
            *slot = None;
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_pipe::Endpoint;

    #[test]
    fn canonical_queues_preserve_first_occurrence_and_last_end() {
        assert_eq!(
            unique_queues(&[127, 0, 127, 64, 0, 63, 64]).collect::<Vec<_>>(),
            [127, 0, 64, 63]
        );
        assert_eq!(
            unique_queues(&[128, 255, 128, 0, 255]).collect::<Vec<_>>(),
            [128, 255, 0]
        );
    }

    #[test]
    fn retired_watch_cleans_captured_ring_not_reused_named_slot() {
        let mut pool = Pool::<2>::new();
        let mut set = WatchSet::new();
        set.len = 2;
        for (i, endpoint) in [
            Endpoint::named(3, 0x1_0000_0001),
            Endpoint::named(3, 0x2_0000_0001),
        ]
        .into_iter()
        .enumerate()
        {
            set.items[i].description = endpoint.id;
            set.generations[i] = endpoint.generation;
        }
        let mut queues = [0; MAX];
        queues[0] = 14;
        queues[1] = 27;
        assert!(pool.insert(1, 7, set, queues));
        assert_eq!(
            pool.get(1, 7).unwrap().endpoint(1).generation,
            0x2_0000_0001
        );
        pool.retire(2);
        assert!(!pool.cleanup_due());
        pool.retire(1);
        assert!(pool.get(1, 7).is_none());
        assert_eq!(pool.cleanup(), Some((1, 7, 14)));
        assert!(pool.cleanup_due());
        assert_eq!(pool.cleanup(), Some((1, 7, 27)));
        assert!(!pool.cleanup_due());
        assert_eq!(pool.cleanup(), None);
    }
}
