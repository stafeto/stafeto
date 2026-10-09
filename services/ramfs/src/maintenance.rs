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
