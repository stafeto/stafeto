// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::{Pipes, Waiter};
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

impl Registration {
    /// A live record with queues still to subscribe.
    fn open(&self) -> bool {
        !self.retired && !self.refused && self.registered < self.wanted
    }
}

/// The most queues one step of the service subscribes a watch to. A request
/// subscribes the first portion and answers `Wait`, and a turn of its own
/// subscribes each next portion, so no step grows with the size of the set
/// (at most `MAX` = 32 elements). In `posix-poll` the request step of a set
/// of 32 took 19563 ticks against the bound of 20410 (96 %). Parsing and
/// the readiness check of 32 elements are 7200 of them whatever the split,
/// and a subscription costs 270 ticks and more with each operation already
/// waiting at the queue (up to 8), so a portion of 8 keeps the step under
/// 16500 where a portion of 16 reached 18501 (0.9 of the bound is 18369).
pub const WATCH_STEP_QUEUES: usize = 8;

/// What one portion of a watch's subscriptions did (`Pool::portion`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Portion {
    /// The queues the portion subscribed.
    pub subscribed: usize,
    /// No queue of the watch is left to subscribe.
    pub last: bool,
    /// The portion was the last, was asked to check, and an element of the
    /// set is ready.
    pub ready: bool,
}
impl Portion {
    const NONE: Self = Self {
        subscribed: 0,
        last: true,
        ready: false,
    };
}
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
    /// How many records are open (`Registration::open`): `pending` costs no
    /// scan of the places while none is.
    open: u16,
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
        Self {
            list: [None; N],
            open: 0,
        }
    }
    /// Puts the record in a free place and returns the place.
    pub fn insert(
        &mut self,
        label: u64,
        key: u64,
        set: WatchSet,
        queues: [u8; MAX],
    ) -> Option<usize> {
        let (at, free) = self
            .list
            .iter_mut()
            .enumerate()
            .find(|(_, r)| r.is_none())?;
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
        self.open += 1;
        Some(at)
    }
    /// The first live record with queues still to subscribe, and its place.
    pub fn pending(&self) -> Option<(u64, u64, usize)> {
        if self.open == 0 {
            return None;
        }
        self.list.iter().enumerate().find_map(|(at, r)| {
            let r = r.as_ref()?;
            r.open().then_some((r.label, r.key, at))
        })
    }
    /// Subscribes the next portion (at most `WATCH_STEP_QUEUES` queues) of
    /// the record at `at` (from `insert` or `pending`, in the same step).
    /// A refusal leaves the queues subscribed so far (a cancel takes them
    /// off). With `check`, the portion that completes the record also looks
    /// at the readiness of every element: the queues of the portions that
    /// came after the request's check were not subscribed when a change
    /// happened.
    pub fn portion(
        &mut self,
        at: usize,
        pipes: &mut Pipes,
        alive: impl Fn(Waiter) -> bool,
        check: bool,
    ) -> Result<Portion, u32> {
        let Some(r) = self.list[at].as_mut() else {
            return Ok(Portion::NONE);
        };
        let done = usize::from(r.registered);
        let mut subscribed = 0;
        for description in unique_queues(&r.queues[..r.set.len])
            .skip(done)
            .take(WATCH_STEP_QUEUES)
        {
            pipes.wait_new(description, (r.label, r.key), &alive)?;
            subscribed += 1;
            r.registered += 1;
        }
        let last = r.registered >= r.wanted;
        if last {
            self.open -= 1;
        }
        let ready = check
            && last
            && (0..r.set.len).any(|i| {
                pipes.queue_readiness(u32::from(r.queues[i]))
                    & (r.set.items[i].events | proto_wire::watch::ALWAYS)
                    != 0
            });
        Ok(Portion {
            subscribed,
            last,
            ready,
        })
    }
    /// The record at `at` needs no more subscriptions.
    pub fn complete(&mut self, at: usize) {
        if let Some(r) = self.list[at].as_mut() {
            if r.open() {
                self.open -= 1;
            }
            r.registered = r.wanted;
        }
    }
    /// A later portion was refused: the record stays (a `Cancel` takes it
    /// off) and `Take` answers AGAIN.
    pub fn refuse(&mut self, label: u64, key: u64) {
        if let Some(r) = self
            .list
            .iter_mut()
            .flatten()
            .find(|r| !r.retired && r.label == label && r.key == key)
        {
            if r.open() {
                self.open -= 1;
            }
            r.refused = true;
        }
    }
    /// The set of the live record and whether a later portion was refused.
    pub fn get_state(&self, label: u64, key: u64) -> Option<(&WatchSet, bool)> {
        self.list
            .iter()
            .flatten()
            .find(|r| !r.retired && r.label == label && r.key == key)
            .map(|r| (&r.set, r.refused))
    }
    pub fn refused(&self, label: u64, key: u64) -> bool {
        self.get_state(label, key)
            .is_some_and(|(_, refused)| refused)
    }
    pub fn get(&self, label: u64, key: u64) -> Option<&WatchSet> {
        self.list
            .iter()
            .flatten()
            .find(|r| !r.retired && r.label == label && r.key == key)
            .map(|r| &r.set)
    }
    pub fn remove(&mut self, label: u64, key: u64) -> Option<WatchSet> {
        let record = self
            .list
            .iter_mut()
            .find(|r| r.is_some_and(|r| !r.retired && r.label == label && r.key == key))?
            .take()?;
        if record.open() {
            self.open -= 1;
        }
        Some(record.set)
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
            if r.open() {
                self.open -= 1;
            }
            r.retired = true;
        }
    }
    /// The places in use (the timing line of `steps` builds).
    #[cfg(feature = "steps")]
    pub fn live(&self) -> usize {
        self.list.iter().flatten().count()
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
    fn open_records_are_counted_through_each_way_out() {
        let mut pool = Pool::<4>::new();
        let mut set = WatchSet::new();
        set.len = 2;
        let mut queues = [0; MAX];
        queues[1] = 1;
        assert_eq!(pool.pending(), None);
        let a = pool.insert(1, 1, set, queues).unwrap();
        let b = pool.insert(1, 2, set, queues).unwrap();
        let c = pool.insert(2, 3, set, queues).unwrap();
        let d = pool.insert(3, 4, set, queues).unwrap();
        assert_eq!(pool.pending(), Some((1, 1, a)));
        pool.complete(a);
        assert_eq!(pool.pending(), Some((1, 2, b)));
        pool.refuse(1, 2);
        assert_eq!(pool.pending(), Some((2, 3, c)));
        pool.retire(2);
        assert_eq!(pool.pending(), Some((3, 4, d)));
        assert!(pool.remove(3, 4).is_some());
        assert_eq!(pool.pending(), None);
        assert_eq!(pool.open, 0);
        // The second refusal, retirement or removal of the same record
        // does not count it out twice.
        pool.refuse(1, 2);
        pool.retire(1);
        pool.retire(2);
        assert_eq!(pool.open, 0);
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
        assert!(pool.insert(1, 7, set, queues).is_some());
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
