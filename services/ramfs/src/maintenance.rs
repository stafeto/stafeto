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

/// A share of the service's time for one kind of work: at most `budget`
/// nanoseconds of every `window`. The service sleeps when the work has used
/// its budget, and the clients below its priority run.
pub struct Share {
    window: u64,
    budget: u64,
    end: u64,
    spent: u64,
    last: u64,
}
impl Share {
    pub const fn new(window: u64, budget: u64) -> Self {
        Self {
            window,
            budget,
            end: 0,
            spent: 0,
            last: 0,
        }
    }
    /// The work cost `cost` nanoseconds and ended at `now`. The result is the
    /// time until which the work waits, when this window's budget is used up.
    pub fn charge(&mut self, now: u64, cost: u64) -> Option<u64> {
        if now >= self.end {
            self.end = now.saturating_add(self.window);
            self.spent = 0;
        }
        self.spent = self.spent.saturating_add(cost);
        (self.spent >= self.budget).then_some(self.end)
    }
    /// A turn of the work ran from `began` to `ended`; `busy` is the time
    /// the service spent on other work since the previous turn ended. The
    /// time since the previous turn ended counts when it is at most `gap`
    /// (round trips, empty turns). A longer gap may hold idle time, so it
    /// counts only as far as the busy time shows: work of the service in a
    /// long gap is charged, its idle time is not. A spent budget forgets
    /// the run: the next turn starts a new one.
    pub fn turn(&mut self, began: u64, ended: u64, gap: u64, busy: u64) -> Option<u64> {
        let since = if self.last == 0 {
            0
        } else {
            began.saturating_sub(self.last)
        };
        let between = if self.last != 0 && since <= gap {
            since
        } else {
            busy.min(since)
        };
        let cost = ended.saturating_sub(began).saturating_add(between);
        let paused = self.charge(ended, cost);
        self.last = if paused.is_some() { 0 } else { ended };
        paused
    }
}

/// Trying a cancellation proves progress only when it retires a job or
/// returns a page. A partial data cancellation returns one page per portion.
pub fn orphan_progress(before: (u16, u16), after: (u16, u16)) -> bool {
    after.0 < before.0 || after.1 > before.1
}

/// The most places in use that one step of the audit visits.
pub const AUDIT_LIVE_RUN: usize = 4;
/// The time, in counter ticks, after which a step visits no further place in use. The cleanup
/// of a place in use costs from about 600 ticks (nothing to do) to several thousand (a session
/// that is authenticated, or a departure in portions), and before the map a step ended at the
/// first place in use. A step now goes on to another place only while the places it has visited
/// cost little, so that it is longer than a step of that kind by less than this time and the
/// search of the map.
pub const AUDIT_STEP_TICKS: u64 = 2_500;

/// The places that may hold a session, a birth or a departure: a superset by meaning. A bit is
/// set when a place is given out (a session is placed, a birth is stored) and cleared only when
/// the service itself frees the place, so the audit never misses a place in use; at worst it
/// looks at a place in vain. The words are cells, for the set that the service makes through a
/// shared reference (`Service::place`).
pub struct Occupancy<const WORDS: usize> {
    words: [core::cell::Cell<u64>; WORDS],
}
impl<const WORDS: usize> Occupancy<WORDS> {
    pub const fn new() -> Self {
        Self {
            words: [const { core::cell::Cell::new(0) }; WORDS],
        }
    }
    pub fn set(&self, index: usize) {
        let word = &self.words[index / 64];
        word.set(word.get() | 1 << (index % 64));
    }
    pub fn clear(&self, index: usize) {
        let word = &self.words[index / 64];
        word.set(word.get() & !(1 << (index % 64)));
    }
    pub fn contains(&self, index: usize) -> bool {
        self.words[index / 64].get() & (1 << (index % 64)) != 0
    }
    /// The first set bit in `low..=high`, by words.
    fn first_in(&self, low: usize, high: usize) -> Option<usize> {
        if low > high {
            return None;
        }
        for w in low / 64..=high / 64 {
            let mut bits = self.words[w].get();
            if w == low / 64 {
                bits &= !0 << (low % 64);
            }
            if w == high / 64 && high % 64 != 63 {
                bits &= (1 << (high % 64 + 1)) - 1;
            }
            if bits != 0 {
                return Some(w * 64 + bits.trailing_zeros() as usize);
            }
        }
        None
    }
    /// The distance from `position` to the next set bit among the places `1..slots`, going on
    /// from the last place to the first (place 0 is never audited).
    pub fn distance(&self, position: usize, slots: usize) -> Option<usize> {
        if let Some(found) = self.first_in(position, slots - 1) {
            return Some(found - position);
        }
        self.first_in(1, position - 1)
            .map(|found| found + (slots - 1) - position)
    }
}
impl<const WORDS: usize> Default for Occupancy<WORDS> {
    fn default() -> Self {
        Self::new()
    }
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
    /// Opens a round over `slots` places at `now`: every place but the last is passed before the
    /// closing step. The time from which its first step may run is `first` later, so that the
    /// turn that opens the round (the heartbeat's) takes no step.
    pub fn open(&mut self, now: u64, first: u64, slots: usize) -> u64 {
        self.remaining = slots - 1;
        now.saturating_add(first)
    }
    /// Whether a step of the audit goes on to another place in use, after it visited `visited`
    /// of them, the last with the result `worked`, and has spent `spent` ticks. It stops after
    /// progress (a place that worked is tried again in the next step, and a step that worked
    /// ends there, as it did before the map), at the end of the round, after `AUDIT_LIVE_RUN`
    /// places and once the visits cost `AUDIT_STEP_TICKS`.
    pub fn step_continues(&self, visited: usize, worked: bool, spent: u64) -> bool {
        !worked && self.remaining != 0 && visited < AUDIT_LIVE_RUN && spent < AUDIT_STEP_TICKS
    }
    /// Moves `count` places on, all of them passed.
    fn advance(&mut self, count: usize, slots: usize) {
        self.position = 1 + (self.position - 1 + count) % (slots - 1);
        self.remaining -= count;
    }
    /// Passes the places that hold nothing, by the map of places that may hold something and
    /// then the exact test `empty` of a place the map names, and never the last step of the
    /// round: it stays for an ordinary step. Stops at a place in use.
    pub fn skip_unoccupied<const WORDS: usize>(
        &mut self,
        slots: usize,
        map: &Occupancy<WORDS>,
        empty: impl Fn(usize) -> bool,
    ) {
        while self.remaining > 1 {
            let room = self.remaining - 1;
            let distance = map.distance(self.position, slots).unwrap_or(usize::MAX);
            let moved = distance.min(room);
            self.advance(moved, slots);
            if moved < distance || self.remaining <= 1 || !empty(self.position) {
                return;
            }
            // A set bit with nothing behind it: passed.
            self.complete(false, slots);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_lets_work_run_until_its_budget_and_waits_for_the_window_to_end() {
        let mut share = Share::new(10_000, 2_500);
        assert_eq!(share.charge(1_000, 600), None);
        assert_eq!(share.charge(1_800, 800), None);
        // The window opened at 1000 and ends at 11000.
        assert_eq!(share.charge(2_600, 1_100), Some(11_000));
        assert_eq!(share.charge(2_700, 100), Some(11_000));
        // After the end a new window opens with a fresh budget.
        assert_eq!(share.charge(11_000, 200), None);
        assert_eq!(share.charge(11_300, 2_400), Some(21_000));
    }

    #[test]
    fn turns_charge_the_wall_time_since_the_previous_turn_ended() {
        const GAP: u64 = 1_000;
        let mut share = Share::new(10_000, 2_500);
        // Turns of 100 with empty turns and round trips of 400 between them:
        // each turn after the first costs 500. Charging only the bodies would
        // reach 2500 after 25 turns and the run would last 12 000.
        let mut now = 1_000u64;
        let mut tripped = None;
        assert_eq!(share.turn(now, now + 100, GAP, 0), None);
        now += 100;
        let start = 1_000;
        for _ in 0..20 {
            let began = now + 400;
            now = began + 100;
            if let Some(until) = share.turn(began, now, GAP, 0) {
                tripped = Some((now, until));
                break;
            }
        }
        let (at, until) = tripped.expect("the budget trips");
        assert!(at - start <= 2_500 + 500, "ran {} of wall time", at - start);
        assert_eq!(until, 11_100);
    }

    #[test]
    fn an_idle_gap_longer_than_the_limit_charges_only_the_turn() {
        let mut share = Share::new(10_000, 2_500);
        assert_eq!(share.turn(1_000, 1_100, 1_000, 0), None);
        // Idle for 5000 (no busy time): the turn costs 100 alone.
        assert_eq!(share.turn(6_100, 6_200, 1_000, 0), None);
        assert_eq!(share.turn(6_900, 7_000, 1_000, 0), None);
        // The first turn charged 100, the second 100, the third 800.
        assert_eq!(share.charge(7_000, 1_500), Some(11_100));
    }

    #[test]
    fn a_gap_of_exactly_the_limit_is_charged() {
        let mut share = Share::new(10_000, 2_500);
        assert_eq!(share.turn(1_000, 1_100, 1_000, 0), None);
        // Gap 1000 = the limit: charged in full, 1000 + 400 = 1400 so far
        // plus 100 for the first turn.
        assert_eq!(share.turn(2_100, 2_500, 1_000, 0), None);
        assert_eq!(share.spent, 100 + 1_000 + 400);
    }

    #[test]
    fn busy_work_in_a_gap_over_the_limit_is_charged() {
        let mut share = Share::new(10_000, 2_500);
        assert_eq!(share.turn(1_000, 1_100, 1_000, 0), None);
        // A gap of 1500 filled with 1500 of busy work (a long legacy step,
        // queued requests) counts in full.
        assert_eq!(share.turn(2_600, 2_700, 1_000, 1_500), None);
        assert_eq!(share.spent, 100 + 1_500 + 100);
        // Busy time never counts past the gap itself.
        assert_eq!(share.turn(3_200, 3_300, 1_000, 9_000), None);
        assert_eq!(share.spent, 1_700 + 500 + 100);
    }

    #[test]
    fn a_tripped_budget_forgets_the_run() {
        let mut share = Share::new(2_000, 500);
        assert_eq!(share.turn(100, 200, 2_000, 0), None);
        assert_eq!(share.turn(200, 900, 2_000, 0), Some(2_200));
        // The service paused to the end of the window. With the run
        // forgotten the next turn costs its own 100; the 1300 since the
        // trip would trip the new window at once.
        assert_eq!(share.turn(2_200, 2_300, 2_000, 0), None);
        assert_eq!(share.spent, 100);
    }

    #[test]
    fn work_that_never_stops_gets_the_share_and_no_more() {
        let mut share = Share::new(10_000, 2_500);
        let (mut now, mut worked, mut slept) = (0u64, 0u64, 0u64);
        while now < 1_000_000 {
            now += 300;
            worked += 300;
            if let Some(until) = share.charge(now, 300) {
                slept += until - now;
                now = until;
            }
        }
        // A quarter of the time, within one step of rounding.
        assert!(worked * 100 / now <= 28, "{worked} of {now}");
        assert!(slept > 0);
    }

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

/// A session of `label` is gone: when its custody is not empty its departure
/// (indexed by its place) is admitted, with one hold on the place. A label with
/// no place has no departure of its own: its index would be birth 0's.
pub fn session_gone<const W: usize>(
    places: &crate::places::Places,
    departures: &mut Departures<W>,
    label: u64,
    custody_empty: bool,
) {
    let place = places.place(label);
    if place < crate::places::COUNT && !custody_empty && !departures.contains(place) {
        places.hold(label);
        departures.admit(place);
    }
}

/// The label was closed (its birth, if any, is in `births[index]`).
/// `birth_custody_empty` cleans the birth's fields and tells whether its custody
/// is empty. A birth whose custody is not empty departs (index `sessions + index`)
/// with a hold of its own, next to a departure of the session that may be running.
/// Returns true when nothing of the label is left to wait for here: the caller
/// forgets the clone; the place itself goes back only after its last departure.
pub fn label_closed<const W: usize, T>(
    places: &crate::places::Places,
    departures: &mut Departures<W>,
    sessions: usize,
    births: &mut [Option<(u64, T)>],
    index: usize,
    label: u64,
    birth_custody_empty: impl FnOnce(&mut T) -> bool,
) -> bool {
    let session_running = departures.contains(places.place(label));
    if let Some(Some((l, birth))) = births.get_mut(index)
        && *l == label
    {
        if !birth_custody_empty(birth) {
            if !departures.contains(sessions + index) {
                places.hold(label);
                departures.admit(sessions + index);
            }
            return false;
        }
        births[index] = None;
    } else if session_running {
        return false;
    }
    places.release(label);
    true
}

/// The slot of births that the new `label` (index `index`) would take is occupied.
/// A stale birth (its label has no place) goes on the departures, so that it is
/// cleaned and its slot freed; a live one is left alone. Either way the new label
/// goes back to the free list and the caller refuses, with an error that ends when
/// the departure does. False when the slot is free.
pub fn birth_taken<const W: usize, T>(
    places: &crate::places::Places,
    departures: &mut Departures<W>,
    sessions: usize,
    births: &mut [Option<(u64, T)>],
    index: usize,
    label: u64,
    depart: impl FnOnce(&mut T),
) -> bool {
    let Some(Some((old, birth))) = births.get_mut(index) else {
        return false;
    };
    if places.place(*old) >= crate::places::COUNT && !departures.contains(sessions + index) {
        depart(birth);
        departures.admit(sessions + index);
    }
    places.release(label);
    true
}

/// A departure of `label` at `index` ended: the slot is emptied by the caller, the
/// departure and one hold go, and the place is freed by the last one.
pub fn departure_finished<const W: usize>(
    places: &crate::places::Places,
    departures: &mut Departures<W>,
    index: usize,
    label: u64,
) {
    departures.release(index);
    places.finish(label);
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
    fn gone_then_closed_cleans_the_birth_and_frees_the_place_once() {
        use crate::places::{COUNT, Places};
        let places = Places::new();
        let mut departures = Departures::<13>::new(COUNT + 512);
        let mut births: Vec<Option<(u64, u32)>> = (0..512).map(|_| None).collect();
        let label = places.issue(3).unwrap();
        let index = (label & 511) as usize;
        births[index] = Some((label, 1));
        // `gone`: the session has custody left, its departure runs.
        session_gone(&places, &mut departures, label, false);
        assert!(departures.contains(index));
        // `closed` while that departure runs: the birth departs too (custody left).
        let done = label_closed(
            &places,
            &mut departures,
            COUNT,
            &mut births,
            index,
            label,
            |_| false,
        );
        assert!(!done && departures.contains(COUNT + index));
        // Its custody ends: the birth is emptied, and the place waits for the session.
        births[index] = None;
        departure_finished(&places, &mut departures, COUNT + index, label);
        assert_eq!(places.used(), 1);
        departure_finished(&places, &mut departures, index, label);
        assert_eq!(places.used(), 0);
        assert!(births[index].is_none() && !departures.pending());
        // A birth with no custody left is cleaned at once, with the session running.
        let label = places.issue(4).unwrap();
        let index = (label & 511) as usize;
        births[index] = Some((label, 1));
        session_gone(&places, &mut departures, label, false);
        assert!(label_closed(
            &places,
            &mut departures,
            COUNT,
            &mut births,
            index,
            label,
            |_| true
        ));
        assert!(births[index].is_none());
        assert_eq!(places.used(), 1);
        departure_finished(&places, &mut departures, index, label);
        assert_eq!(places.used(), 0);
    }
    #[test]
    fn a_stale_birth_is_cleaned_and_clone_is_refused_only_until_then() {
        use crate::places::{COUNT, Places};
        let places = Places::new();
        let mut departures = Departures::<13>::new(COUNT + 512);
        let mut births: Vec<Option<(u64, u32)>> = (0..512).map(|_| None).collect();
        let old = places.issue(1).unwrap();
        let index = (old & 511) as usize;
        births[index] = Some((old, 1));
        // The old place went back while its birth stayed (the defect of #700).
        places.release(old);
        let new = places.issue(2).unwrap();
        assert_eq!(new & 511, old & 511);
        let mut departed = 0;
        assert!(birth_taken(
            &places,
            &mut departures,
            COUNT,
            &mut births,
            index,
            new,
            |_| departed += 1
        ));
        assert_eq!(departed, 1);
        assert!(departures.contains(COUNT + index));
        assert_eq!(places.used(), 0);
        // The departure ends and empties the slot: the next clone is served.
        births[index] = None;
        departure_finished(&places, &mut departures, COUNT + index, old);
        let next = places.issue(3).unwrap();
        assert_eq!(next & 511, old & 511);
        assert!(!birth_taken(
            &places,
            &mut departures,
            COUNT,
            &mut births,
            index,
            next,
            |_| {}
        ));
        assert_eq!(places.used(), 1);
    }
    #[test]
    #[should_panic]
    fn departure_admission_rejects_a_place_past_the_actual_table() {
        Departures::<11>::new(641).admit(641);
    }
}

#[cfg(test)]
mod audit_map_tests {
    use super::*;

    const SLOTS: usize = 640;
    type Map = Occupancy<10>;

    /// The seeded generator of the tests (xorshift64).
    struct Seed(u64);
    impl Seed {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// The walk that looks at every place in turn: the reference of the map's walk. The places
    /// it visits, in order.
    fn linear_walk(mut cursor: Cursor, slots: usize, empty: impl Fn(usize) -> bool) -> Vec<usize> {
        let mut visits = Vec::new();
        while cursor.remaining != 0 {
            while cursor.remaining > 1 && empty(cursor.position) {
                cursor.complete(false, slots);
            }
            visits.push(cursor.position);
            cursor.complete(false, slots);
        }
        visits
    }

    /// The walk by the map, in steps of the audit. `visit` gives the result and the cost in
    /// ticks of the cleanup of a place. The places visited (in order), the places each step
    /// visited and the ticks each step spent.
    fn map_walk(
        mut cursor: Cursor,
        slots: usize,
        map: &Map,
        empty: impl Fn(usize) -> bool,
        mut visit: impl FnMut(usize) -> (bool, u64),
    ) -> (Vec<usize>, Vec<usize>, Vec<u64>) {
        let (mut visits, mut per_step, mut costs) = (Vec::new(), Vec::new(), Vec::new());
        while cursor.remaining != 0 {
            let (mut visited, mut spent) = (0, 0);
            loop {
                cursor.skip_unoccupied(slots, map, &empty);
                visits.push(cursor.position);
                let (worked, cost) = visit(cursor.position);
                visited += 1;
                spent += cost;
                cursor.complete(worked, slots);
                if !cursor.step_continues(visited, worked, spent) {
                    break;
                }
            }
            per_step.push(visited);
            costs.push(spent);
        }
        (visits, per_step, costs)
    }

    fn table(occupied: &[usize], extra_bits: &[usize]) -> Map {
        let map = Map::new();
        for &i in occupied.iter().chain(extra_bits) {
            map.set(i);
        }
        map
    }

    #[test]
    fn a_round_opens_with_its_first_step_due_a_period_later() {
        let mut cursor = Cursor::default();
        let due = cursor.open(1_000, 6_000, SLOTS);
        assert_eq!(due, 7_000);
        assert_eq!(cursor.remaining, SLOTS - 1);
        // The opening takes no step: the position is where the last round left it.
        assert_eq!(cursor.position, 1);
        assert_eq!(cursor.open(u64::MAX - 1, 6_000, SLOTS), u64::MAX);
    }

    #[test]
    fn the_map_finds_the_next_set_bit_across_words_and_the_end() {
        let map = table(&[1, 63, 64, 639], &[]);
        assert_eq!(map.distance(1, SLOTS), Some(0));
        assert_eq!(map.distance(2, SLOTS), Some(61));
        assert_eq!(map.distance(64, SLOTS), Some(0));
        assert_eq!(map.distance(65, SLOTS), Some(574));
        // After the last place the walk goes on at place 1.
        assert_eq!(map.distance(639, SLOTS), Some(0));
        let only = table(&[100], &[]);
        assert_eq!(only.distance(101, SLOTS), Some(638));
        assert_eq!(Map::new().distance(5, SLOTS), None);
        // Place 0 is never audited, so a bit there is not found.
        let zero = table(&[0], &[]);
        assert_eq!(zero.distance(1, SLOTS), None);
    }

    #[test]
    fn the_walk_by_the_map_visits_the_places_of_the_linear_walk_in_the_same_order() {
        let mut seed = Seed(0x9e37_79b9_7f4a_7c15);
        for _ in 0..400 {
            let live = seed.below(40);
            let occupied: Vec<usize> = (0..live).map(|_| 1 + seed.below(SLOTS - 1)).collect();
            // A superset: bits with nothing behind them, which the exact test passes.
            let extra: Vec<usize> = (0..seed.below(20))
                .map(|_| 1 + seed.below(SLOTS - 1))
                .collect();
            let map = table(&occupied, &extra);
            let empty = |i: usize| !occupied.contains(&i);
            let cursor = Cursor {
                position: 1 + seed.below(SLOTS - 1),
                remaining: 1 + seed.below(SLOTS - 1),
            };
            let reference = linear_walk(
                Cursor {
                    position: cursor.position,
                    remaining: cursor.remaining,
                },
                SLOTS,
                empty,
            );
            let (visits, _, _) = map_walk(cursor, SLOTS, &map, empty, |_| (false, 0));
            assert_eq!(visits, reference, "occupied {occupied:?}");
        }
    }

    fn occupied_set(seed: &mut Seed, live: usize) -> Vec<usize> {
        let mut occupied = Vec::new();
        while occupied.len() < live {
            let i = 1 + seed.below(SLOTS - 1);
            if !occupied.contains(&i) {
                occupied.push(i);
            }
        }
        occupied
    }

    #[test]
    fn a_round_with_l_places_in_use_that_need_no_work_takes_few_steps() {
        let mut seed = Seed(12345);
        for cost in [0u64, 600, 1_000, 2_500, 5_000] {
            // The visits one step makes: the places until their cost reaches the time of a step.
            let per_step = if cost == 0 {
                AUDIT_LIVE_RUN
            } else {
                (AUDIT_STEP_TICKS.div_ceil(cost) as usize).min(AUDIT_LIVE_RUN)
            };
            for live in [0usize, 1, 2, 3, 4, 5, 8, 9, 17, 100, 639] {
                let occupied = occupied_set(&mut seed, live);
                let map = table(&occupied, &[]);
                let cursor = Cursor {
                    position: 1 + seed.below(SLOTS - 1),
                    remaining: SLOTS - 1,
                };
                let (visits, steps, spent) = map_walk(
                    cursor,
                    SLOTS,
                    &map,
                    |i| !occupied.contains(&i),
                    |_| (false, cost),
                );
                // Every place in use is visited once; the last place of the round is visited
                // too, in use or not, so at most L + 1 places.
                assert!(
                    visits.len() <= live + 1,
                    "L {live}: {} visits",
                    visits.len()
                );
                for place in &occupied {
                    assert_eq!(visits.iter().filter(|v| *v == place).count(), 1);
                }
                assert!(steps.len() <= (live + 1).div_ceil(per_step));
                assert!(steps.iter().all(|&n| n <= per_step));
                // No step spends the time of a step before its last visit.
                assert!(spent.iter().all(|&t| t < AUDIT_STEP_TICKS + cost.max(1)));
                if live == 0 {
                    // An idle table's round is one step.
                    assert_eq!(steps.len(), 1);
                }
            }
        }
    }

    #[test]
    fn a_step_ends_after_a_place_that_needed_work_as_it_did_before_the_map() {
        let mut seed = Seed(99);
        for live in [1usize, 2, 5, 20, 100] {
            let occupied = occupied_set(&mut seed, live);
            let map = table(&occupied, &[]);
            // Each place in use needs one unit of work, then is done.
            let mut owed: Vec<usize> = occupied.clone();
            let cursor = Cursor {
                position: 1 + seed.below(SLOTS - 1),
                remaining: SLOTS - 1,
            };
            let (visits, steps, _) = map_walk(
                cursor,
                SLOTS,
                &map,
                |i| !occupied.contains(&i),
                |place| match owed.iter().position(|&p| p == place) {
                    Some(at) => {
                        owed.swap_remove(at);
                        (true, 6_000)
                    }
                    None => (false, 600),
                },
            );
            // A worked visit ends its step, so no step has two of them, and each place is
            // visited twice at most: once for its work and once to find it done.
            assert!(steps.len() <= live + 1, "L {live}: {} steps", steps.len());
            assert!(visits.len() <= 2 * live + 1);
            assert!(owed.is_empty());
        }
    }

    #[test]
    fn a_place_with_a_session_never_lacks_its_bit() {
        // The service sets the bit before it stores a session or a birth, and clears it only
        // where it frees the place itself; another path may empty a place with no clear.
        let mut seed = Seed(777);
        let map = Map::new();
        let mut live = [false; SLOTS];
        for _ in 0..20_000 {
            let i = 1 + seed.below(SLOTS - 1);
            match seed.below(3) {
                0 => {
                    map.set(i);
                    live[i] = true;
                }
                1 if live[i] => {
                    map.clear(i);
                    live[i] = false;
                }
                _ => live[i] = false,
            }
            if seed.below(50) == 0 {
                for (j, &used) in live.iter().enumerate() {
                    assert!(!used || map.contains(j), "place {j} lacks its bit");
                }
            }
        }
    }
}
