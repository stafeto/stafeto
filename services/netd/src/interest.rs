// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The interest sets of the service (spec 6, 3.4): a set belongs to one
//! session and holds records, each naming a place and the events its owner
//! asks for. A record is on the list of its place (at most `PLACE_INTEREST`),
//! on the list of its set, and while its place is ready for it on the list of
//! the ready records of the set. Everything here is lists of indices in fixed
//! tables, so the steps that walk them are bounded by the portions below and
//! never by the number of sockets. The tables know nothing of smoltcp: the
//! service gives them the events of a place.

use proto_net::sockets::{EpollReady, epoll};

/// The sets of the service, and of one session.
pub const SETS_MAX: usize = 64;
pub const SESSION_SETS: usize = 4;
/// The records of the service, of one set and of one place.
pub const INTEREST_MAX: usize = 2048;
pub const SET_ENTRIES: usize = 1024;
pub const PLACE_INTEREST: usize = 16;
/// The records a step of departure lets go of.
pub const DROP_PORTION: usize = 32;
/// The most the records of a wait look at: twice the pairs it may answer.
pub const WAIT_LOOKS: usize = 2 * proto_net::sockets::EPOLL_MOST;

const NONE: u16 = u16::MAX;
const GENERATION_MASK: u32 = (1 << 24) - 1;

/// The flags of a record.
const ET: u8 = 1;
const ONESHOT: u8 = 2;
/// The record reports (a oneshot record does not after a report, until MOD).
const ENABLED: u8 = 4;
const READY: u8 = 8;
/// The record was added with EPOLLEXCLUSIVE: of the sets that have such a
/// record on a place, one that waits is given the event.
const EXCLUSIVE: u8 = 16;

/// What a record of `events` (the events of Linux with the modes) asks for
/// and the modes it has.
const fn modes(events: u32) -> u8 {
    let mut flags = ENABLED;
    if events & epoll::ET != 0 {
        flags |= ET;
    }
    if events & epoll::ONESHOT != 0 {
        flags |= ONESHOT;
    }
    if events & epoll::EXCLUSIVE != 0 {
        flags |= EXCLUSIVE;
    }
    flags
}

/// Why a record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The place has `PLACE_INTEREST` records, the set `SET_ENTRIES`, or the
    /// service `INTEREST_MAX`.
    NoSpace,
    Exists,
    NoEntry,
}

#[derive(Clone, Copy)]
struct Interest {
    set: u8,
    flags: u8,
    place: u16,
    /// The events asked for, without the modes.
    events: u32,
    label: u32,
    /// The events the last report carried (for the records by edge).
    last: u32,
    /// The changes of the place when the record was last looked at.
    seen: u16,
    next_place: u16,
    prev_place: u16,
    next_set: u16,
    prev_set: u16,
    next_ready: u16,
    prev_ready: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetState {
    Free,
    Live,
    /// Dropped: its records go in steps, and it answers nobody.
    Departing,
}

#[derive(Clone, Copy)]
struct Set {
    state: SetState,
    /// The label of the session that owns the set.
    label: u64,
    generation: u32,
    /// The list of the ready records.
    head: u16,
    tail: u16,
    /// The list of all the records.
    first: u16,
    entries: u16,
    /// The operations that wait on the set, by their index.
    waiters: u128,
}

/// The tables of the interest sets of `PLACES` places.
pub struct Interests<const PLACES: usize> {
    entries: [Interest; INTEREST_MAX],
    free: u16,
    sets: [Set; SETS_MAX],
    /// The first record of each place.
    heads: [u16; PLACES],
    /// How many times a frame (or a deferred error) changed each place.
    changes: [u16; PLACES],
    /// The events of each place as the service worked them out last.
    cache: [u32; PLACES],
    /// The records in use in all the sets.
    live: u16,
    /// The sets with ready records and operations that wait: the step of
    /// waking tells them.
    pub due: u64,
    /// The sets dropped whose records are still on their way out.
    departing: u64,
}

const EMPTY_ENTRY: Interest = Interest {
    set: 0,
    flags: 0,
    place: 0,
    events: 0,
    label: 0,
    last: 0,
    seen: 0,
    next_place: NONE,
    prev_place: NONE,
    next_set: NONE,
    prev_set: NONE,
    next_ready: NONE,
    prev_ready: NONE,
};

const EMPTY_SET: Set = Set {
    state: SetState::Free,
    label: 0,
    generation: 0,
    head: NONE,
    tail: NONE,
    first: NONE,
    entries: 0,
    waiters: 0,
};

impl<const PLACES: usize> Interests<PLACES> {
    /// The tables in place in zeroed memory (`.bss`).
    ///
    /// # Safety
    /// `at` is valid for writes, exclusive and zeroed.
    pub unsafe fn initialize_at(at: *mut Self) {
        // SAFETY: the memory is zeroed, which is a valid `Interests` but
        // for the lists, which this sets.
        let this = unsafe { &mut *at };
        this.reset();
    }

    pub fn reset(&mut self) {
        for (k, entry) in self.entries.iter_mut().enumerate() {
            *entry = EMPTY_ENTRY;
            entry.next_place = if k + 1 < INTEREST_MAX {
                k as u16 + 1
            } else {
                NONE
            };
        }
        self.free = 0;
        self.sets.fill(EMPTY_SET);
        self.heads.fill(NONE);
        self.changes.fill(0);
        self.cache.fill(0);
        self.live = 0;
        self.due = 0;
        self.departing = 0;
    }

    // ----- the sets -----

    /// A set for the session `label`: None at `SETS_MAX` sets or
    /// `SESSION_SETS` of that session.
    pub fn new_set(&mut self, label: u64) -> Option<usize> {
        let mut free = None;
        let mut own = 0;
        for (k, set) in self.sets.iter().enumerate() {
            if set.state == SetState::Free {
                free.get_or_insert(k);
            } else if set.label == label {
                own += 1;
            }
        }
        if own >= SESSION_SETS {
            return None;
        }
        let k = free?;
        let set = &mut self.sets[k];
        set.generation = match (set.generation + 1) & GENERATION_MASK {
            0 => 1,
            g => g,
        };
        *set = Set {
            state: SetState::Live,
            label,
            generation: set.generation,
            ..EMPTY_SET
        };
        Some(k)
    }

    /// The number of a set on the wire: the index and the generation.
    pub fn wire(&self, k: usize) -> u32 {
        k as u32 | self.sets[k].generation << 8
    }

    /// The live set named by `wire` that the session `label` owns.
    pub fn find_set(&self, label: u64, wire: u32) -> Option<usize> {
        let k = (wire & 0xff) as usize;
        let set = self.sets.get(k)?;
        (set.state == SetState::Live && set.label == label && set.generation == wire >> 8)
            .then_some(k)
    }

    /// The records of the set `k`.
    pub fn entry_count(&self, k: usize) -> usize {
        usize::from(self.sets[k].entries)
    }

    /// The live sets of `label`, and those dropped whose records go.
    pub fn sets_of(&self, label: u64) -> usize {
        self.sets
            .iter()
            .filter(|s| s.state != SetState::Free && s.label == label)
            .count()
    }

    /// The set is dropped (EPOLL_DROP, or its session went): it answers
    /// nobody, and its records go in steps. Its waiting operations, which the
    /// caller tells, are returned.
    pub fn drop_set(&mut self, k: usize) -> u128 {
        let set = &mut self.sets[k];
        if set.state != SetState::Live {
            return 0;
        }
        set.state = SetState::Departing;
        self.due &= !(1 << k);
        self.departing |= 1 << k;
        core::mem::take(&mut self.sets[k].waiters)
    }

    /// Drops every live set of the session `label`: the operations that wait
    /// on them.
    pub fn drop_sets_of(&mut self, label: u64) -> u128 {
        let mut waiting = 0;
        for k in 0..SETS_MAX {
            if self.sets[k].state == SetState::Live && self.sets[k].label == label {
                waiting |= self.drop_set(k);
            }
        }
        waiting
    }

    /// One step of departure: at most `DROP_PORTION` records of the dropped
    /// sets go, and a set with none left is free. True when more are left.
    pub fn depart_step(&mut self) -> bool {
        let mut left = DROP_PORTION;
        while self.departing != 0 {
            let k = self.departing.trailing_zeros() as usize;
            while left > 0 && self.sets[k].first != NONE {
                self.remove(usize::from(self.sets[k].first));
                left -= 1;
            }
            if self.sets[k].first != NONE {
                return true;
            }
            self.sets[k].state = SetState::Free;
            self.sets[k].label = 0;
            self.departing &= !(1 << k);
        }
        false
    }

    pub fn departing(&self) -> bool {
        self.departing != 0
    }

    /// Whether the set `k` is live.
    pub fn is_live(&self, k: usize) -> bool {
        self.sets[k].state == SetState::Live
    }

    pub fn add_waiter(&mut self, k: usize, op: usize) {
        self.sets[k].waiters |= 1 << op;
    }

    pub fn remove_waiter(&mut self, k: usize, op: usize) {
        self.sets[k].waiters &= !(1 << op);
    }

    pub fn waiters(&self, k: usize) -> u128 {
        self.sets[k].waiters
    }

    pub fn has_ready(&self, k: usize) -> bool {
        self.sets[k].head != NONE
    }

    // ----- the records -----

    /// Whether no record is in use: the frames of a service nobody uses epoll
    /// on look at nothing.
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub fn head(&self, place: usize) -> Option<usize> {
        let h = self.heads[place];
        (h != NONE).then_some(usize::from(h))
    }

    /// Whether the place has records.
    pub fn watched(&self, place: usize) -> bool {
        self.heads[place] != NONE
    }

    /// The record of set `k` on `place`.
    pub fn find(&self, k: usize, place: usize) -> Option<usize> {
        let mut at = self.heads[place];
        for _ in 0..PLACE_INTEREST {
            if at == NONE {
                return None;
            }
            let e = &self.entries[usize::from(at)];
            if usize::from(e.set) == k {
                return Some(usize::from(at));
            }
            at = e.next_place;
        }
        None
    }

    /// Adds a record of set `k` on `place` asking `events` (with the modes),
    /// whose place has the events `ev` now. It is ready at once when `ev`
    /// matches (as Linux reports what is ready at ADD).
    pub fn add(
        &mut self,
        k: usize,
        place: usize,
        events: u32,
        label: u32,
        ev: u32,
    ) -> Result<usize, Refused> {
        if self.find(k, place).is_some() {
            return Err(Refused::Exists);
        }
        let mut on_place = 0;
        let mut at = self.heads[place];
        while at != NONE && on_place < PLACE_INTEREST {
            on_place += 1;
            at = self.entries[usize::from(at)].next_place;
        }
        if on_place >= PLACE_INTEREST
            || usize::from(self.sets[k].entries) >= SET_ENTRIES
            || self.free == NONE
        {
            return Err(Refused::NoSpace);
        }
        let idx = usize::from(self.free);
        self.free = self.entries[idx].next_place;
        let head = self.heads[place];
        let first = self.sets[k].first;
        self.entries[idx] = Interest {
            set: k as u8,
            flags: modes(events),
            place: place as u16,
            events: events & epoll::EVENTS,
            label,
            last: 0,
            seen: self.changes[place],
            next_place: head,
            prev_place: NONE,
            next_set: first,
            prev_set: NONE,
            next_ready: NONE,
            prev_ready: NONE,
        };
        if head != NONE {
            self.entries[usize::from(head)].prev_place = idx as u16;
        }
        self.heads[place] = idx as u16;
        if first != NONE {
            self.entries[usize::from(first)].prev_set = idx as u16;
        }
        self.sets[k].first = idx as u16;
        self.sets[k].entries += 1;
        self.live += 1;
        self.cache[place] = ev;
        self.consider(idx, ev, false);
        Ok(idx)
    }

    /// Changes the record of set `k` on `place` (EPOLL_MOD): new events and
    /// label, enabled again.
    pub fn modify(
        &mut self,
        k: usize,
        place: usize,
        events: u32,
        label: u32,
        ev: u32,
    ) -> Result<(), Refused> {
        let idx = self.find(k, place).ok_or(Refused::NoEntry)?;
        let e = &mut self.entries[idx];
        // A record added with EPOLLEXCLUSIVE stays one.
        e.flags = (e.flags & (READY | EXCLUSIVE)) | modes(events & !epoll::EXCLUSIVE);
        e.events = events & epoll::EVENTS;
        e.label = label;
        e.last = 0;
        e.seen = self.changes[place];
        self.cache[place] = ev;
        self.consider(idx, ev, false);
        Ok(())
    }

    /// Removes the record of set `k` on `place` (EPOLL_DEL).
    pub fn delete(&mut self, k: usize, place: usize) -> Result<(), Refused> {
        let idx = self.find(k, place).ok_or(Refused::NoEntry)?;
        self.remove(idx);
        Ok(())
    }

    /// Removes the record `idx` from all three lists.
    pub fn remove(&mut self, idx: usize) {
        let e = self.entries[idx];
        let place = usize::from(e.place);
        let set = usize::from(e.set);
        if e.prev_place != NONE {
            self.entries[usize::from(e.prev_place)].next_place = e.next_place;
        } else {
            self.heads[place] = e.next_place;
        }
        if e.next_place != NONE {
            self.entries[usize::from(e.next_place)].prev_place = e.prev_place;
        }
        if e.prev_set != NONE {
            self.entries[usize::from(e.prev_set)].next_set = e.next_set;
        } else {
            self.sets[set].first = e.next_set;
        }
        if e.next_set != NONE {
            self.entries[usize::from(e.next_set)].prev_set = e.prev_set;
        }
        self.sets[set].entries -= 1;
        self.live -= 1;
        if e.flags & READY != 0 {
            self.unlink_ready(idx);
        }
        self.entries[idx] = EMPTY_ENTRY;
        self.entries[idx].next_place = self.free;
        self.free = idx as u16;
    }

    /// Removes the records on `place` of the sets whose session is `label`
    /// (the session let go of the description), or of every set when `label`
    /// is None (the place is free). At most `PLACE_INTEREST` records.
    pub fn drop_place(&mut self, place: usize, label: Option<u64>) {
        let mut at = self.heads[place];
        for _ in 0..PLACE_INTEREST {
            if at == NONE {
                break;
            }
            let idx = usize::from(at);
            at = self.entries[idx].next_place;
            let own =
                label.is_none_or(|l| self.sets[usize::from(self.entries[idx].set)].label == l);
            if own {
                self.remove(idx);
            }
        }
        if self.heads[place] == NONE {
            self.cache[place] = 0;
        }
    }

    // ----- the lists of ready records -----

    fn push_ready(&mut self, idx: usize) {
        let k = usize::from(self.entries[idx].set);
        let tail = self.sets[k].tail;
        self.entries[idx].prev_ready = tail;
        self.entries[idx].next_ready = NONE;
        self.entries[idx].flags |= READY;
        if tail != NONE {
            self.entries[usize::from(tail)].next_ready = idx as u16;
        } else {
            self.sets[k].head = idx as u16;
        }
        self.sets[k].tail = idx as u16;
    }

    fn unlink_ready(&mut self, idx: usize) {
        let e = self.entries[idx];
        let k = usize::from(e.set);
        if e.prev_ready != NONE {
            self.entries[usize::from(e.prev_ready)].next_ready = e.next_ready;
        } else {
            self.sets[k].head = e.next_ready;
        }
        if e.next_ready != NONE {
            self.entries[usize::from(e.next_ready)].prev_ready = e.prev_ready;
        } else {
            self.sets[k].tail = e.prev_ready;
        }
        self.entries[idx].flags &= !READY;
        self.entries[idx].next_ready = NONE;
        self.entries[idx].prev_ready = NONE;
    }

    /// The events of record `idx` that `ev` gives it.
    fn deliverable(&self, idx: usize, ev: u32) -> u32 {
        ev & (self.entries[idx].events | epoll::ERR | epoll::HUP)
    }

    /// Puts the record on the list of ready ones when its place's events
    /// `ev` ask for it: by level whenever they match, by edge when the place
    /// changed since the record was looked at, or an event is new since its
    /// last report. A set with waiting operations becomes due.
    fn consider(&mut self, idx: usize, ev: u32, scanning: bool) {
        let e = self.entries[idx];
        let changes = self.changes[usize::from(e.place)];
        self.entries[idx].seen = changes;
        if e.flags & ENABLED == 0 || e.flags & READY != 0 {
            return;
        }
        let deliver = self.deliverable(idx, ev);
        let listed = if e.flags & ET == 0 {
            deliver != 0
        } else if scanning {
            // What the place lacks now is not "last" any more: it comes as
            // new when it is back.
            let last = e.last & ev;
            self.entries[idx].last = last;
            deliver != 0 && (changes != e.seen || deliver & !last != 0)
        } else {
            deliver != 0
        };
        if listed {
            self.push_ready(idx);
            let k = usize::from(e.set);
            if self.sets[k].waiters != 0 {
                self.due |= 1 << k;
            }
        }
    }

    /// A frame or a deferred error changed `place`.
    pub fn changed(&mut self, place: usize) {
        self.changes[place] = self.changes[place].wrapping_add(1);
    }

    /// The records on `place` look at its events `ev`: those that ask for
    /// them are listed. Returns how many records it looked at. Of the records
    /// added with EPOLLEXCLUSIVE only the first whose set has an operation
    /// waiting is listed (and so its set woken): the other sets leave the
    /// event to it, as the waiters of Linux that wake one.
    pub fn scan(&mut self, place: usize, ev: u32) -> usize {
        self.cache[place] = ev;
        let mut looked = 0;
        let mut taken = false;
        let mut at = self.heads[place];
        while at != NONE && looked < PLACE_INTEREST {
            let idx = usize::from(at);
            at = self.entries[idx].next_place;
            looked += 1;
            if self.entries[idx].flags & EXCLUSIVE != 0 {
                if taken {
                    continue;
                }
                self.consider(idx, ev, true);
                let e = self.entries[idx];
                if e.flags & READY != 0 && self.sets[usize::from(e.set)].waiters != 0 {
                    taken = true;
                }
            } else {
                self.consider(idx, ev, true);
            }
        }
        looked
    }

    /// How many records are on `place`, at most `PLACE_INTEREST`.
    pub fn on_place(&self, place: usize) -> usize {
        let mut n = 0;
        let mut at = self.heads[place];
        while at != NONE && n < PLACE_INTEREST {
            n += 1;
            at = self.entries[usize::from(at)].next_place;
        }
        n
    }

    /// The pairs of set `k`'s ready records for a wait of `most` (at most
    /// `EPOLL_MOST`) pairs: looks at the records that were on the list at the
    /// start, at most `2 * most` of them. A record whose place no longer has
    /// its events leaves the list; a oneshot record is disabled after its
    /// report; a record by edge leaves the list with what was reported kept
    /// in `last`; a record by level goes to the tail (behind the last record
    /// looked at, so that each is reported once in a take).
    pub fn take(&mut self, k: usize, most: usize, out: &mut EpollReady) {
        let last = self.sets[k].tail;
        for _ in 0..(2 * most).min(WAIT_LOOKS) {
            let h = self.sets[k].head;
            if h == NONE || out.len >= most {
                break;
            }
            let idx = usize::from(h);
            let e = self.entries[idx];
            let deliver = self.deliverable(idx, self.cache[usize::from(e.place)]);
            self.unlink_ready(idx);
            if deliver != 0 {
                out.push(e.label, deliver);
                if e.flags & ONESHOT != 0 {
                    self.entries[idx].flags &= !ENABLED;
                } else if e.flags & ET != 0 {
                    self.entries[idx].last = deliver;
                } else {
                    self.push_ready(idx);
                }
            }
            if h == last {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_net::sockets::epoll::{ERR, ET, EXCLUSIVE as EXCL, HUP, IN, ONESHOT, OUT};

    type Table = Interests<8>;

    fn table() -> Box<Table> {
        let mut t: Box<Table> = unsafe { Box::new_zeroed().assume_init() };
        t.reset();
        t
    }

    fn pairs(t: &mut Table, k: usize, most: usize) -> Vec<(u32, u32)> {
        let mut out = EpollReady::EMPTY;
        t.take(k, most, &mut out);
        out.as_slice().to_vec()
    }

    #[test]
    fn a_level_record_comes_back_to_the_tail_until_the_events_go() {
        let mut t = table();
        let k = t.new_set(7).unwrap();
        t.add(k, 1, IN, 11, IN).unwrap();
        t.add(k, 2, IN, 22, IN).unwrap();
        assert_eq!(pairs(&mut t, k, 1), [(11, IN)]);
        // The first went to the tail: the second is reported before it.
        assert_eq!(pairs(&mut t, k, 1), [(22, IN)]);
        assert_eq!(pairs(&mut t, k, 8), [(11, IN), (22, IN)]);
        // The events of place 1 went: its record leaves the list.
        t.scan(1, 0);
        assert_eq!(pairs(&mut t, k, 8), [(22, IN)]);
        t.scan(2, 0);
        assert_eq!(pairs(&mut t, k, 8), []);
        // Events come back: the record is listed again.
        t.scan(2, IN);
        assert_eq!(pairs(&mut t, k, 8), [(22, IN)]);
    }

    #[test]
    fn a_level_record_is_reported_once_per_take_even_with_few_records() {
        let mut t = table();
        let k = t.new_set(7).unwrap();
        t.add(k, 1, IN, 11, IN).unwrap();
        // One record, room for four pairs: the record is reported once.
        assert_eq!(pairs(&mut t, k, 4), [(11, IN)]);
    }

    #[test]
    fn an_edge_record_waits_for_a_change_of_its_place() {
        let mut t = table();
        let k = t.new_set(7).unwrap();
        t.add(k, 1, IN | ET, 11, IN).unwrap();
        assert_eq!(pairs(&mut t, k, 8), [(11, IN)]);
        assert_eq!(pairs(&mut t, k, 8), []);
        // The same events, no change: nothing.
        t.scan(1, IN);
        assert_eq!(pairs(&mut t, k, 8), []);
        // A frame arrived: the record reports again.
        t.changed(1);
        t.scan(1, IN);
        assert_eq!(pairs(&mut t, k, 8), [(11, IN)]);
        // A new event with no frame (the socket was shut down) reports too.
        t.scan(1, IN | HUP);
        assert_eq!(pairs(&mut t, k, 8), [(11, IN | HUP)]);
    }

    #[test]
    fn a_take_that_saw_stale_records_only_leaves_the_rest_of_the_list() {
        let mut t: Box<Interests<1280>> = unsafe { Box::new_zeroed().assume_init() };
        t.reset();
        let k = t.new_set(1).unwrap();
        for place in 0..400 {
            t.add(k, place, IN, place as u32, IN).unwrap();
        }
        // Every place lost its event but the last, whose record is at the tail.
        for place in 0..399 {
            t.scan(place, 0);
        }
        let mut out = EpollReady::EMPTY;
        t.take(k, 64, &mut out);
        // The window is 128 records: nothing came, and records are left (the
        // service wakes the wait for them, `has_ready`).
        assert_eq!(out.len, 0);
        assert!(t.has_ready(k));
        t.take(k, 64, &mut out);
        t.take(k, 64, &mut out);
        assert_eq!(out.len, 0);
        assert!(t.has_ready(k));
        t.take(k, 64, &mut out);
        assert_eq!(out.len, 1);
        assert_eq!(out.as_slice()[0].0, 399);
    }

    #[test]
    fn an_edge_record_reports_an_event_that_went_and_came_back() {
        let mut t = table();
        let k = t.new_set(7).unwrap();
        t.add(k, 1, OUT | ET, 11, OUT).unwrap();
        assert_eq!(pairs(&mut t, k, 8), [(11, OUT)]);
        // The buffer filled (OUT went) and drained (OUT is back): a report,
        // with no frame counted.
        t.scan(1, 0);
        assert_eq!(pairs(&mut t, k, 8), []);
        t.scan(1, OUT);
        assert_eq!(pairs(&mut t, k, 8), [(11, OUT)]);
    }

    #[test]
    fn a_oneshot_record_reports_once_until_it_is_modified() {
        let mut t = table();
        let k = t.new_set(7).unwrap();
        t.add(k, 1, IN | ONESHOT, 11, IN).unwrap();
        assert_eq!(pairs(&mut t, k, 8), [(11, IN)]);
        t.changed(1);
        t.scan(1, IN);
        assert_eq!(pairs(&mut t, k, 8), []);
        t.modify(k, 1, IN | ONESHOT, 12, IN).unwrap();
        assert_eq!(pairs(&mut t, k, 8), [(12, IN)]);
    }

    #[test]
    fn error_and_hangup_are_reported_whatever_was_asked() {
        let mut t = table();
        let k = t.new_set(7).unwrap();
        t.add(k, 1, OUT, 11, 0).unwrap();
        assert_eq!(pairs(&mut t, k, 8), []);
        t.scan(1, ERR | HUP | IN);
        assert_eq!(pairs(&mut t, k, 8), [(11, ERR | HUP)]);
    }

    #[test]
    fn deleting_from_the_middle_keeps_the_lists() {
        let mut t = table();
        let k = t.new_set(7).unwrap();
        for place in 0..4 {
            t.add(k, place, IN, 10 + place as u32, IN).unwrap();
        }
        t.delete(k, 1).unwrap();
        assert_eq!(t.entry_count(k), 3);
        assert!(t.find(k, 1).is_none());
        assert_eq!(t.delete(k, 1), Err(Refused::NoEntry));
        assert_eq!(pairs(&mut t, k, 8), [(10, IN), (12, IN), (13, IN)]);
        t.delete(k, 0).unwrap();
        t.delete(k, 3).unwrap();
        assert_eq!(pairs(&mut t, k, 8), [(12, IN)]);
        assert_eq!(t.add(k, 2, IN, 1, IN), Err(Refused::Exists));
    }

    #[test]
    fn a_place_takes_sixteen_records_and_a_set_a_thousand() {
        let mut t = table();
        for n in 0..PLACE_INTEREST {
            // One set for each of 16 sessions: SESSION_SETS is per session.
            let k = t.new_set(100 + n as u64).unwrap();
            t.add(k, 0, IN, n as u32, 0).unwrap();
        }
        let k = t.new_set(1).unwrap();
        assert_eq!(t.add(k, 0, IN, 99, 0), Err(Refused::NoSpace));
        assert_eq!(t.on_place(0), PLACE_INTEREST);
    }

    #[test]
    fn a_set_holds_at_most_its_entries_and_the_service_its_records() {
        let mut t: Box<Interests<1280>> = unsafe { Box::new_zeroed().assume_init() };
        t.reset();
        let k = t.new_set(1).unwrap();
        for place in 0..SET_ENTRIES {
            t.add(k, place, IN, 0, 0).unwrap();
        }
        assert_eq!(t.add(k, SET_ENTRIES, IN, 0, 0), Err(Refused::NoSpace));
        let j = t.new_set(2).unwrap();
        for place in 0..INTEREST_MAX - SET_ENTRIES {
            t.add(j, place, IN, 0, 0).unwrap();
        }
        assert_eq!(t.add(j, 1100, IN, 0, 0), Err(Refused::NoSpace));
    }

    #[test]
    fn the_sets_of_a_session_are_limited_and_named_by_their_generation() {
        let mut t = table();
        let sets: Vec<_> = (0..SESSION_SETS).map(|_| t.new_set(5).unwrap()).collect();
        assert!(t.new_set(5).is_none());
        let wire = t.wire(sets[0]);
        assert_eq!(t.find_set(5, wire), Some(sets[0]));
        // Another session does not find it.
        assert_eq!(t.find_set(6, wire), None);
        t.drop_set(sets[0]);
        assert_eq!(t.find_set(5, wire), None);
        while t.depart_step() {}
        // The place is free again, with a new generation.
        let again = t.new_set(5).unwrap();
        assert_eq!(again, sets[0]);
        assert_ne!(t.wire(again), wire);
        assert_eq!(t.find_set(5, wire), None);
    }

    #[test]
    fn the_sets_of_a_session_that_went_depart_in_portions() {
        let mut t: Box<Interests<1280>> = unsafe { Box::new_zeroed().assume_init() };
        t.reset();
        let k = t.new_set(1).unwrap();
        let other = t.new_set(2).unwrap();
        for place in 0..100 {
            t.add(k, place, IN, 0, IN).unwrap();
        }
        t.add(other, 0, IN, 0, IN).unwrap();
        t.add_waiter(k, 3);
        let waiting = t.drop_sets_of(1);
        assert_eq!(waiting, 1 << 3);
        assert!(t.departing());
        let mut steps = 0;
        while t.depart_step() {
            steps += 1;
            assert!(steps < 10);
        }
        // 100 records at 32 a step: three steps with more left, a fourth that
        // finishes.
        assert_eq!(steps, 3);
        assert!(!t.departing());
        assert_eq!(t.sets_of(1), 0);
        assert_eq!(t.entry_count(other), 1);
        assert_eq!(t.on_place(0), 1);
        for place in 1..100 {
            assert!(!t.watched(place));
        }
        // The records were returned to the free list.
        let again = t.new_set(3).unwrap();
        for place in 0..INTEREST_MAX.min(1024) {
            t.add(again, place, IN, 0, 0).unwrap();
        }
    }

    #[test]
    fn a_session_lets_go_of_a_place_and_only_its_records_go() {
        let mut t = table();
        let mine = t.new_set(1).unwrap();
        let theirs = t.new_set(2).unwrap();
        t.add(mine, 3, IN, 1, IN).unwrap();
        t.add(theirs, 3, IN, 2, IN).unwrap();
        t.drop_place(3, Some(1));
        assert!(t.find(mine, 3).is_none());
        assert!(t.find(theirs, 3).is_some());
        assert_eq!(pairs(&mut t, mine, 8), []);
        assert_eq!(pairs(&mut t, theirs, 8), [(2, IN)]);
        t.drop_place(3, None);
        assert!(!t.watched(3));
    }

    #[test]
    fn a_ready_record_of_a_set_with_waiters_makes_the_set_due() {
        let mut t = table();
        let k = t.new_set(1).unwrap();
        t.add(k, 1, IN, 1, 0).unwrap();
        assert_eq!(t.due, 0);
        t.add_waiter(k, 5);
        t.scan(1, IN);
        assert_eq!(t.due, 1 << k);
        // A set with no waiter is not due.
        let j = t.new_set(2).unwrap();
        t.add(j, 2, IN, 1, 0).unwrap();
        t.due = 0;
        t.scan(2, IN);
        assert_eq!(t.due, 0);
    }

    #[test]
    fn a_dropped_set_answers_nobody_and_its_ready_list_goes_with_it() {
        let mut t = table();
        let k = t.new_set(1).unwrap();
        t.add(k, 1, IN, 1, IN).unwrap();
        let wire = t.wire(k);
        t.drop_set(k);
        assert!(!t.is_live(k));
        assert_eq!(t.find_set(1, wire), None);
        assert!(!t.is_empty());
        while t.depart_step() {}
        assert!(!t.has_ready(k));
        assert!(!t.watched(1));
        assert!(t.is_empty());
    }

    #[test]
    fn an_exclusive_record_wakes_one_of_the_waiting_sets() {
        let mut t = table();
        let a = t.new_set(1).unwrap();
        let b = t.new_set(2).unwrap();
        t.add(a, 1, IN | EXCL, 10, 0).unwrap();
        t.add(b, 1, IN | EXCL, 20, 0).unwrap();
        t.add_waiter(a, 3);
        t.add_waiter(b, 4);
        t.scan(1, IN);
        // One set has the event and is due; the other has nothing.
        let (ra, rb) = (t.has_ready(a), t.has_ready(b));
        assert!(ra != rb, "exactly one set is given the event");
        assert_eq!(t.due.count_ones(), 1);
        let woken = if ra { a } else { b };
        assert_eq!(t.due, 1 << woken);
    }

    #[test]
    fn exclusive_records_of_sets_that_wait_for_nothing_all_get_the_event() {
        let mut t = table();
        let a = t.new_set(1).unwrap();
        let b = t.new_set(2).unwrap();
        t.add(a, 1, IN | EXCL, 10, 0).unwrap();
        t.add(b, 1, IN | EXCL, 20, 0).unwrap();
        t.scan(1, IN);
        assert!(t.has_ready(a) && t.has_ready(b));
        assert_eq!(t.due, 0);
    }

    #[test]
    fn an_exclusive_record_passes_over_a_set_that_does_not_wait() {
        let mut t = table();
        let a = t.new_set(1).unwrap();
        let b = t.new_set(2).unwrap();
        t.add(a, 1, IN | EXCL, 10, 0).unwrap();
        t.add(b, 1, IN | EXCL, 20, 0).unwrap();
        // Only a waits: it is the one woken, whichever record is first.
        t.add_waiter(a, 3);
        t.scan(1, IN);
        assert!(t.has_ready(a));
        assert_eq!(t.due, 1 << a);
    }

    #[test]
    fn a_plain_record_is_given_the_event_beside_an_exclusive_one() {
        let mut t = table();
        let a = t.new_set(1).unwrap();
        let b = t.new_set(2).unwrap();
        let c = t.new_set(3).unwrap();
        t.add(a, 1, IN | EXCL, 10, 0).unwrap();
        t.add(b, 1, IN | EXCL, 20, 0).unwrap();
        t.add(c, 1, IN, 30, 0).unwrap();
        for k in [a, b, c] {
            t.add_waiter(k, k);
        }
        t.scan(1, IN);
        assert!(t.has_ready(c));
        assert_eq!([a, b].iter().filter(|&&k| t.has_ready(k)).count(), 1);
    }
}
