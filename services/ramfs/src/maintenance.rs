// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fixed maintenance traversal keeps blocked transports from retaining the cursor.

/// Limit consecutive own dispatches that have no confirmed cleanup progress.
/// External work restarts a burst; retained jobs and charges remain intact.
pub struct Burst<const STEPS: usize> {
    remaining: usize,
}
impl<const STEPS: usize> Default for Burst<STEPS> {
    fn default() -> Self {
        Self { remaining: STEPS }
    }
}
impl<const STEPS: usize> Burst<STEPS> {
    pub fn restart(&mut self) {
        self.remaining = STEPS;
    }
    pub fn again(&mut self, progressed: bool, pending: bool) -> bool {
        if progressed {
            self.restart();
        } else {
            self.remaining = self.remaining.saturating_sub(1);
        }
        pending && self.remaining != 0
    }
}

/// Trying a cancellation proves progress only when it retires a job or
/// returns a page. A partial data cancellation returns one page per portion.
pub fn orphan_progress(before: (u16, u16), after: (u16, u16)) -> bool {
    after.0 < before.0 || after.1 > before.1
}

pub struct Cursor {
    pub position: usize,
    pub remaining: usize,
}
impl Default for Cursor {
    fn default() -> Self {
        Self {
            position: 1,
            remaining: 0,
        }
    }
}
impl Cursor {
    pub fn complete(&mut self, worked: bool, slots: usize) {
        if !worked {
            self.position = 1 + self.position % (slots - 1);
            self.remaining = self.remaining.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuck_orphan_stops_own_dispatches_after_reaching_every_slot() {
        const SLOTS: usize = crate::storage::PREPARATIONS;
        let mut burst = Burst::<{ 4 * SLOTS + 2 * crate::places::COUNT }>::default();
        let mut seen = [false; SLOTS];
        let mut step = 0;
        loop {
            // Orphans have one turn in four; empty slots also consume turns.
            if step % 4 == 0 {
                seen[(step / 4) % SLOTS] = true;
            }
            step += 1;
            if !burst.again(orphan_progress((1, 0), (1, 0)), true) {
                break;
            }
            assert!(step < 4 * SLOTS + 2 * crate::places::COUNT);
        }
        assert!(seen.into_iter().all(|slot| slot));
        assert!(!burst.again(false, true));
        burst.restart();
        assert!(burst.again(false, true));
    }

    #[test]
    fn partial_page_cleanup_keeps_a_long_orphan_alive() {
        let mut burst = Burst::<{ 4 * crate::storage::PREPARATIONS }>::default();
        // A full paid page pool needs more than one burst to release it.
        for free in 0..crate::storage::PAGES as u16 {
            for _ in 1..4 * crate::storage::PREPARATIONS {
                assert!(burst.again(false, true));
            }
            assert!(burst.again(orphan_progress((1, free), (1, free + 1)), true));
        }
        assert!(!burst.again(orphan_progress((1, 4096), (0, 4096)), false));
        assert!(!orphan_progress((1, 5), (1, 4)));
    }

    #[test]
    fn waiting_destination_gives_the_retained_source_a_turn() {
        let mut cursor = Cursor {
            position: 1,
            remaining: 3,
        };
        // Destination waits; the next retained birth performs three refresh phases.
        let waiting = crate::authority::retained_source_phase(
            19,
            19,
            true,
            Some(crate::authority::BindingPurpose::Refresh),
            8,
            7,
        )
        .unwrap();
        cursor.complete(waiting.progresses(), 3);
        assert_eq!(cursor.position, 2);
        for _ in 0..3 {
            cursor.complete(true, 3);
            assert_eq!(cursor.position, 2);
            assert_eq!(cursor.remaining, 2);
        }
        // A completed source lets the destination observe the refreshed authority.
        cursor.complete(false, 3);
        assert_eq!(cursor.position, 1);
        assert_eq!(cursor.remaining, 1);
    }
}

/// Departure debt keeps the existing session cells until every physical hold returns.
pub struct Departures<const WORDS: usize> {
    bits: [u64; WORDS],
    position: usize,
    limit: usize,
    count: usize,
}
impl<const WORDS: usize> Departures<WORDS> {
    pub const fn new(limit: usize) -> Self {
        assert!(limit > 0 && limit <= WORDS * 64);
        Self {
            bits: [0; WORDS],
            position: 0,
            limit,
            count: 0,
        }
    }
    pub fn contains(&self, index: usize) -> bool {
        index < self.limit && self.bits[index / 64] & (1 << (index % 64)) != 0
    }
    pub fn admit(&mut self, index: usize) {
        assert!(index < self.limit);
        if !self.contains(index) {
            self.bits[index / 64] |= 1 << (index % 64);
            self.count += 1;
        }
    }
    pub fn release(&mut self, index: usize) {
        assert!(self.contains(index));
        self.bits[index / 64] &= !(1 << (index % 64));
        self.count -= 1;
    }
    pub fn pending(&self) -> bool {
        self.count != 0
    }
    /// Inspect at most WORDS + 1 bitmap words and rotate among all retained cells.
    pub fn next_place(&mut self) -> Option<usize> {
        if !self.pending() {
            return None;
        }
        let first = self.position / 64;
        let low = self.position % 64;
        for word in first..WORDS {
            let bits = self.bits[word]
                & if word == first {
                    u64::MAX << low
                } else {
                    u64::MAX
                };
            if bits != 0 {
                return Some(self.advance(word, bits));
            }
        }
        for word in 0..=first {
            let bits = self.bits[word]
                & if word == first {
                    (1u64 << low).wrapping_sub(1)
                } else {
                    u64::MAX
                };
            if bits != 0 {
                return Some(self.advance(word, bits));
            }
        }
        unreachable!("nonempty bounded departure bitmap")
    }
    fn advance(&mut self, word: usize, bits: u64) -> usize {
        let index = word * 64 + bits.trailing_zeros() as usize;
        assert!(index < self.limit);
        self.position = (index + 1) % self.limit;
        index
    }
}

#[cfg(test)]
mod departure_tests {
    use super::*;
    #[test]
    fn departures_visit_all_641_cells_once_per_round_and_release_only_exact_debt() {
        let mut queue = Departures::<11>::new(641);
        for index in 0..641 {
            queue.admit(index);
            queue.admit(index);
        }
        for index in 0..641 {
            assert_eq!(queue.next_place(), Some(index));
        }
        for index in 0..641 {
            assert_eq!(queue.next_place(), Some(index));
            queue.release(index);
        }
        assert!(!queue.pending());
        assert_eq!(queue.next_place(), None);
        assert!(!queue.contains(641));
    }
    #[test]
    fn departure_cursor_remains_fair_across_new_arrivals_and_word_boundaries() {
        let mut queue = Departures::<3>::new(129);
        for index in [0, 63, 64, 128] {
            queue.admit(index);
        }
        assert_eq!(queue.next_place(), Some(0));
        queue.release(0);
        assert_eq!(queue.next_place(), Some(63));
        queue.admit(0);
        assert_eq!(queue.next_place(), Some(64));
        assert_eq!(queue.next_place(), Some(128));
        assert_eq!(queue.next_place(), Some(0));
        assert_eq!(queue.next_place(), Some(63));
        queue.release(63);
        queue.release(64);
        queue.release(128);
        queue.release(0);
        queue.admit(128);
        assert_eq!(queue.next_place(), Some(128));
    }
    #[test]
    #[should_panic]
    fn departure_admission_rejects_a_place_past_the_actual_table() {
        Departures::<11>::new(641).admit(641);
    }
}
