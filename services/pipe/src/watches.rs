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
        });
        true
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
