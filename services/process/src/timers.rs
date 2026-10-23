// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The timers of processes: the alarm of a process (`alarm`,
//! ITIMER_REAL) and the timers of `timer_create`, in one table of the
//! service. All deadlines lie on the scale of the kernel's `clock_now`
//! (nanoseconds); the layer turns a calendar time into that scale when it
//! arms a timer. One kernel timer serves the whole table: the service arms
//! it at the earliest deadline (`earliest`) and, when it fires, takes at
//! most EXPIRY_BUDGET of expired timers a step (`next`, `expire`), so a
//! step stays bounded however many are due. Every operation is a scan of
//! the table (SLOTS places), constant in time and with no call of the
//! kernel.
//!
//! A timer on the processor time of its process has a place here as well
//! (`create_external`): the helper of the library keeps its deadline, tells
//! the service of each expiry (`fire`), and the service sends the signal
//! the way it does for the timers it keeps (code SI_TIMER, merging with a
//! signal that waits, the overrun count of `account`). The place counts in
//! the timers of the process.

/// The places of the table, for the timers of all processes.
pub const SLOTS: usize = 192;
/// The alarm of each record has a place of its own after the table, so that
/// no number of timers takes it (`alarm` has no error to give).
pub const ALARMS: usize = 256;
/// The timers a process makes with `timer_create` (the alarm is one more).
pub const PER_PROCESS: usize = 32;
/// What a notification of the kernel's timer may spend: an ordinary signal
/// costs 1, a signal that stops or ends a process (SIGKILL, SIGSTOP, the
/// job signals: a call of the kernel and a report to the parent) costs
/// DEAR_COST. Four of the first took about 11,000 ticks, four of the second
/// 24,000 (term B is 20,410); with the cost of 2 a step takes two of them at
/// most and 16,197 ticks in the steps probe (the limit with a reserve is 18,369).
pub const EXPIRY_BUDGET: usize = 4;
pub const DEAR_COST: usize = 2;
/// DELAYTIMER_MAX: the overrun count stops here.
pub const DELAYTIMER_MAX: u32 = i32::MAX as u32;
/// The least time between two looks of the service at a periodic timer, in
/// nanoseconds: a timer that fires more often would hold the service. The
/// interval of such a timer stays what the program set; the expirations the
/// service did not look at are counted at the next look (`expire`), so that
/// the overrun count follows the interval.
pub const MIN_INTERVAL: u64 = 1_000_000;
/// A deadline farther than this from now is set at this distance (about
/// 146 years), so that the arithmetic of the kernel's timer never wraps.
pub const HORIZON: u64 = 1 << 62;

/// What `expire` found of one timer that was due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expired {
    /// The signal to send, 0 for SIGEV_NONE.
    pub signal: u8,
    /// The bytes of sigval the timer was made with.
    pub value: u64,
    /// Whether it is the alarm of the process (code SI_KERNEL) and not a
    /// timer of `timer_create` (SI_TIMER).
    pub alarm: bool,
    /// The record that owns it.
    pub owner: u8,
    /// How many times it expired since the last look, at least 1.
    pub count: u64,
    /// The place, for `account`.
    pub slot: usize,
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    alarm: bool,
    armed: bool,
    owner: u8,
    signal: u8,
    /// The overrun count of the signal that waits now, and of the one before
    /// it (the last that was delivered, which `timer_getoverrun` shows while
    /// the current one waits).
    overrun: u32,
    last: u32,
    /// The signal is one nobody takes (`account`): its expirations since the
    /// first count as overruns of it.
    unseen: bool,
    /// The deadline is an absolute time of CLOCK_REALTIME: a step of the
    /// calendar moves it (`step`).
    real: bool,
    /// The library keeps the deadline (a timer on processor time): the place
    /// is never armed here and `fire` tells of an expiry.
    external: bool,
    deadline: u64,
    interval: u64,
    /// The service does not look at the timer before this time: a periodic
    /// timer with an interval below MIN_INTERVAL waits that long between
    /// looks.
    not_before: u64,
    value: u64,
}

const FREE: Slot = Slot {
    used: false,
    alarm: false,
    armed: false,
    owner: 0,
    signal: 0,
    overrun: 0,
    last: 0,
    unseen: false,
    real: false,
    external: false,
    deadline: 0,
    interval: 0,
    not_before: 0,
    value: 0,
};

/// The table.
pub struct Timers {
    slots: [Slot; SLOTS + ALARMS],
    /// The generation of each place, in the high bits of an id: an id of a
    /// timer that went names nothing even when its place is used again.
    generation: [u32; SLOTS],
}

/// Why a call of the table failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// No place, or the process holds PER_PROCESS timers already.
    Again,
    /// No timer of that id belongs to the process.
    Invalid,
}

/// The time left and the interval of a timer, in nanoseconds; both 0 for
/// a timer that is not armed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Setting {
    pub remaining: u64,
    pub interval: u64,
}

impl Default for Timers {
    fn default() -> Self {
        Self::new()
    }
}

impl Timers {
    pub const fn new() -> Self {
        Self {
            slots: [FREE; SLOTS + ALARMS],
            generation: [0; SLOTS],
        }
    }

    /// The id of the timer in `slot`: its generation above 8 bits of place.
    fn id(&self, slot: usize) -> u32 {
        self.generation[slot] << 8 | slot as u32
    }

    /// The place of the timer `id` of `owner`.
    fn find(&self, owner: u8, id: u32) -> Option<usize> {
        let slot = (id & 0xFF) as usize;
        if slot >= SLOTS {
            return None;
        }
        let s = &self.slots[slot];
        (s.used && !s.alarm && s.owner == owner && self.id(slot) == id).then_some(slot)
    }

    fn alarm_of(&self, owner: u8) -> Option<usize> {
        let slot = SLOTS + usize::from(owner);
        self.slots[slot].used.then_some(slot)
    }

    fn take(&mut self, owner: u8, alarm: bool) -> Result<usize, Fail> {
        if alarm {
            let slot = SLOTS + usize::from(owner);
            self.slots[slot] = Slot {
                used: true,
                alarm,
                owner,
                ..FREE
            };
            return Ok(slot);
        }
        let slot = self.slots[..SLOTS]
            .iter()
            .position(|s| !s.used)
            .ok_or(Fail::Again)?;
        // The generation counts 24 bits and skips 0, so that an id is never 0.
        let mut generation = (self.generation[slot] + 1) & 0x00FF_FFFF;
        if generation == 0 {
            generation = 1;
        }
        self.generation[slot] = generation;
        self.slots[slot] = Slot {
            used: true,
            alarm,
            owner,
            ..FREE
        };
        Ok(slot)
    }

    /// A timer of `owner` that sends `signal` (0: none) with `value`, or
    /// with its own id as the value when `own_id`; its id. Again past
    /// PER_PROCESS timers of the owner or with the table full.
    pub fn create(&mut self, owner: u8, signal: u8, value: u64, own_id: bool) -> Result<u32, Fail> {
        self.make(owner, signal, value, own_id, false)
    }

    /// A place for a timer on processor time of `owner` that sends `signal`
    /// with `value`, whose expiries the library tells (`fire`); its id.
    pub fn create_external(&mut self, owner: u8, signal: u8, value: u64) -> Result<u32, Fail> {
        self.make(owner, signal, value, false, true)
    }

    fn make(
        &mut self,
        owner: u8,
        signal: u8,
        value: u64,
        own_id: bool,
        external: bool,
    ) -> Result<u32, Fail> {
        let held = self
            .slots
            .iter()
            .filter(|s| s.used && !s.alarm && s.owner == owner)
            .count();
        if held >= PER_PROCESS {
            return Err(Fail::Again);
        }
        let slot = self.take(owner, false)?;
        let id = self.id(slot);
        self.slots[slot].signal = signal;
        self.slots[slot].external = external;
        self.slots[slot].value = if own_id { u64::from(id) } else { value };
        Ok(id)
    }

    /// The library tells that the timer `id` of `owner`, a place made with
    /// `create_external`, expired `count` times (at least 1) since its last
    /// word: what `expire` gives for a timer the service keeps. Invalid for
    /// any other timer.
    pub fn fire(&self, owner: u8, id: u32, count: u64) -> Result<Expired, Fail> {
        let slot = self.find(owner, id).ok_or(Fail::Invalid)?;
        let s = &self.slots[slot];
        if !s.external || count == 0 {
            return Err(Fail::Invalid);
        }
        Ok(Expired {
            signal: s.signal,
            value: s.value,
            alarm: false,
            owner: s.owner,
            count,
            slot,
        })
    }

    /// Deletes the timer `id` of `owner`.
    pub fn delete(&mut self, owner: u8, id: u32) -> Result<(), Fail> {
        let slot = self.find(owner, id).ok_or(Fail::Invalid)?;
        self.slots[slot] = FREE;
        Ok(())
    }

    fn setting(slot: &Slot, now: u64) -> Setting {
        if slot.armed {
            Setting {
                remaining: slot.deadline.saturating_sub(now).max(1),
                interval: slot.interval,
            }
        } else {
            Setting::default()
        }
    }

    fn arm(slot: &mut Slot, deadline: Option<u64>, interval: u64, now: u64) {
        slot.real = false;
        match deadline {
            None => {
                slot.armed = false;
                slot.interval = 0;
            }
            Some(deadline) => {
                slot.armed = true;
                slot.deadline = deadline.min(now.saturating_add(HORIZON));
                slot.interval = interval.min(HORIZON);
                slot.not_before = 0;
            }
        }
        // A new setting starts a new signal: no overrun carries over.
        slot.overrun = 0;
        slot.last = 0;
        slot.unseen = false;
    }

    /// Arms the timer `id` of `owner` at `deadline` (None: disarms) with
    /// `interval` (0: once); the setting before.
    pub fn set(
        &mut self,
        owner: u8,
        id: u32,
        deadline: Option<u64>,
        interval: u64,
        now: u64,
    ) -> Result<Setting, Fail> {
        let slot = self.find(owner, id).ok_or(Fail::Invalid)?;
        let old = Self::setting(&self.slots[slot], now);
        Self::arm(&mut self.slots[slot], deadline, interval, now);
        Ok(old)
    }

    /// Marks the timer `id` of `owner`, just armed, as one whose deadline is
    /// an absolute time of CLOCK_REALTIME.
    pub fn mark_real(&mut self, owner: u8, id: u32) {
        if let Some(slot) = self.find(owner, id) {
            self.slots[slot].real = self.slots[slot].armed;
        }
    }

    /// The calendar of CLOCK_REALTIME was set `delta` ns ahead of the
    /// monotonic scale: the deadlines of the timers armed in it come
    /// `delta` earlier (not before `now`).
    pub fn step(&mut self, delta: i64, now: u64) {
        for s in self
            .slots
            .iter_mut()
            .filter(|s| s.used && s.armed && s.real)
        {
            let moved = i128::from(s.deadline) - i128::from(delta);
            s.deadline = moved.clamp(i128::from(now), i128::from(u64::MAX)) as u64;
            s.not_before = 0;
        }
    }

    /// The setting of the timer `id` of `owner`.
    pub fn get(&self, owner: u8, id: u32, now: u64) -> Result<Setting, Fail> {
        let slot = self.find(owner, id).ok_or(Fail::Invalid)?;
        Ok(Self::setting(&self.slots[slot], now))
    }

    /// The overrun count of the timer `id` of `owner`.
    /// While the signal of the timer waits (`waiting`) it is the count of the
    /// signal delivered before; else the count of the one delivered last.
    pub fn overrun(&self, owner: u8, id: u32, waiting: bool) -> Result<u32, Fail> {
        let slot = self.find(owner, id).ok_or(Fail::Invalid)?;
        let s = &self.slots[slot];
        Ok(if waiting { s.last } else { s.overrun })
    }

    /// The signal of the timer `id` of `owner`.
    pub fn signal_of_id(&self, owner: u8, id: u32) -> Result<u8, Fail> {
        let slot = self.find(owner, id).ok_or(Fail::Invalid)?;
        Ok(self.slots[slot].signal)
    }

    /// Arms the alarm of `owner` (None: disarms) with `interval`; the
    /// setting before. A disarmed alarm gives its place back.
    pub fn alarm(
        &mut self,
        owner: u8,
        deadline: Option<u64>,
        interval: u64,
        now: u64,
    ) -> Result<Setting, Fail> {
        let Some(slot) = self.alarm_of(owner) else {
            let Some(deadline) = deadline else {
                return Ok(Setting::default());
            };
            let slot = self.take(owner, true)?;
            self.slots[slot].signal = proto_process::SIGALRM;
            Self::arm(&mut self.slots[slot], Some(deadline), interval, now);
            return Ok(Setting::default());
        };
        let old = Self::setting(&self.slots[slot], now);
        if deadline.is_none() {
            self.slots[slot] = FREE;
        } else {
            Self::arm(&mut self.slots[slot], deadline, interval, now);
        }
        Ok(old)
    }

    /// The setting of the alarm of `owner`.
    pub fn alarm_setting(&self, owner: u8, now: u64) -> Setting {
        self.alarm_of(owner).map_or(Setting::default(), |slot| {
            Self::setting(&self.slots[slot], now)
        })
    }

    /// Takes away what a process leaves: at its end all of it, at an exec
    /// the timers of `timer_create` (the alarm goes on in the new image).
    pub fn clear(&mut self, owner: u8, alarm_too: bool) {
        for slot in &mut self.slots {
            if slot.used && slot.owner == owner && (alarm_too || !slot.alarm) {
                *slot = FREE;
            }
        }
    }

    /// The nearest deadline of an armed timer.
    pub fn earliest(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter(|s| s.used && s.armed)
            .map(|s| s.deadline.max(s.not_before))
            .min()
    }

    /// The place of the armed timer with the nearest deadline at or before
    /// `now`.
    pub fn next(&self, now: u64) -> Option<usize> {
        self.due(now)
            .0
            .first()
            .copied()
            .filter(|_| self.due(now).1 > 0)
    }

    /// The places of up to EXPIRY_BUDGET armed timers due at or before
    /// `now`, the nearest deadline first, and how many: one pass over the
    /// table. A timer's expiry changes no other, so the list stays good
    /// through the step.
    pub fn due(&self, now: u64) -> ([usize; EXPIRY_BUDGET], usize) {
        let mut found = [0usize; EXPIRY_BUDGET];
        let mut count = 0;
        for (i, s) in self.slots.iter().enumerate() {
            if !(s.used && s.armed && s.deadline.max(s.not_before) <= now) {
                continue;
            }
            // Insert by deadline into the short list.
            let mut at = count;
            while at > 0
                && self.slots[found[at - 1]]
                    .deadline
                    .max(self.slots[found[at - 1]].not_before)
                    > s.deadline.max(s.not_before)
            {
                at -= 1;
            }
            if at >= EXPIRY_BUDGET {
                continue;
            }
            let end = count.min(EXPIRY_BUDGET - 1);
            for k in (at..end).rev() {
                found[k + 1] = found[k];
            }
            found[at] = i;
            count = (count + 1).min(EXPIRY_BUDGET);
        }
        (found, count)
    }

    /// The mark of the timer in `slot`: its id with the generation. It rides
    /// in the `status` of the information of each occurrence the timer sends,
    /// so that the service can tell its own occurrence from another's.
    pub fn mark(&self, slot: usize) -> u32 {
        if slot < SLOTS { self.id(slot) } else { 0 }
    }

    /// The signal the timer in `slot` sends (0: none).
    pub fn signal_of(&self, slot: usize) -> u8 {
        self.slots[slot].signal
    }

    /// Takes the expirations of the due timer in `slot`: a periodic timer
    /// goes on at the first multiple of its interval after `now`, a timer
    /// of one shot is disarmed.
    pub fn expire(&mut self, slot: usize, now: u64) -> Expired {
        let s = &mut self.slots[slot];
        // An interval of 0 is a timer of one shot.
        let count = match (now - s.deadline).checked_div(s.interval) {
            None => {
                s.armed = false;
                1
            }
            Some(passed) => {
                let count = passed + 1;
                let next = u128::from(s.deadline) + u128::from(count) * u128::from(s.interval);
                match u64::try_from(next) {
                    Ok(next) => s.deadline = next,
                    Err(_) => s.armed = false,
                }
                // The next look comes MIN_INTERVAL after this one at the
                // soonest: the expirations in between join the next count.
                s.not_before = if s.interval < MIN_INTERVAL {
                    now.saturating_add(MIN_INTERVAL)
                } else {
                    0
                };
                count
            }
        };
        Expired {
            signal: s.signal,
            value: s.value,
            alarm: s.alarm,
            owner: s.owner,
            count,
            slot,
        }
    }

    /// Records what became of the signal of an expiration (`Expired`): sent
    /// as a new one, the overrun is the expirations that came with it
    /// beyond the first; found waiting, they all join the overrun.
    ///
    /// `unseen` says the signal is one nobody takes (ignored by default, no
    /// handler): after the first, its expirations join the overrun of the
    /// first, as if it waited.
    pub fn account(&mut self, slot: usize, count: u64, merged: bool, unseen: bool) {
        let s = &mut self.slots[slot];
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        let merged = merged || (unseen && s.unseen);
        s.unseen = unseen;
        if !merged {
            s.last = s.overrun;
        }
        s.overrun = if merged {
            s.overrun.saturating_add(count)
        } else {
            count - 1
        }
        .min(DELAYTIMER_MAX);
    }

    /// The places of the table in use (not the alarms), for tests.
    pub fn used(&self) -> usize {
        self.slots[..SLOTS].iter().filter(|s| s.used).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn a_timer_of_one_shot_expires_once_and_disarms() {
        let mut t = Timers::new();
        let id = t.create(3, 10, 0x1234, false).unwrap();
        assert_eq!(t.get(3, id, 0).unwrap(), Setting::default());
        assert_eq!(
            t.set(3, id, Some(100 * MS), 0, 0).unwrap(),
            Setting::default()
        );
        assert_eq!(t.get(3, id, 40 * MS).unwrap().remaining, 60 * MS);
        assert_eq!(t.earliest(), Some(100 * MS));
        assert_eq!(t.next(99 * MS), None);
        let slot = t.next(100 * MS).unwrap();
        let e = t.expire(slot, 100 * MS);
        assert_eq!(
            (e.signal, e.value, e.count, e.alarm, e.owner),
            (10, 0x1234, 1, false, 3)
        );
        assert_eq!(t.earliest(), None);
        assert_eq!(t.get(3, id, 200 * MS).unwrap(), Setting::default());
    }

    #[test]
    fn a_periodic_timer_counts_what_passed_and_goes_on_after_now() {
        let mut t = Timers::new();
        let id = t.create(1, 12, 7, false).unwrap();
        t.set(1, id, Some(200 * MS), 100 * MS, 0).unwrap();
        let slot = t.next(550 * MS).unwrap();
        let e = t.expire(slot, 550 * MS);
        assert_eq!(e.count, 4, "200, 300, 400, 500");
        assert_eq!(t.earliest(), Some(600 * MS));
        t.account(slot, e.count, false, false);
        assert_eq!(t.overrun(1, id, false).unwrap(), 3);
        // The next signal found the last one waiting: the overrun grows.
        let e = t.expire(slot, 600 * MS);
        t.account(slot, e.count, true, false);
        assert_eq!(t.overrun(1, id, false).unwrap(), 4);
        // A new setting starts again.
        t.set(1, id, Some(700 * MS), 0, 650 * MS).unwrap();
        assert_eq!(t.overrun(1, id, false).unwrap(), 0);
    }

    #[test]
    fn a_step_of_the_calendar_moves_the_deadlines_that_follow_it() {
        let mut t = Timers::new();
        let (a, b) = (
            t.create(1, 12, 0, false).unwrap(),
            t.create(1, 12, 0, false).unwrap(),
        );
        t.set(1, a, Some(10_000), 0, 100).unwrap();
        t.mark_real(1, a);
        t.set(1, b, Some(10_000), 0, 100).unwrap();
        // The calendar is set 3,000 ns ahead: a comes earlier, b stays.
        t.step(3_000, 500);
        assert_eq!(t.get(1, a, 500).unwrap().remaining, 6_500);
        assert_eq!(t.get(1, b, 500).unwrap().remaining, 9_500);
        // Set 100,000 back: a is due now at the earliest, set back, it waits.
        t.step(-5_000, 500);
        assert_eq!(t.get(1, a, 500).unwrap().remaining, 11_500);
        t.step(1_000_000, 500);
        assert_eq!(t.get(1, a, 500).unwrap().remaining, 1);
    }

    #[test]
    fn a_waiting_signal_shows_the_count_of_the_one_delivered_before() {
        let mut t = Timers::new();
        let id = t.create(1, 12, 0, false).unwrap();
        let slot = t.find(1, id).unwrap();
        t.account(slot, 100, false, false);
        assert_eq!(t.overrun(1, id, false).unwrap(), 99);
        assert_eq!(t.overrun(1, id, true).unwrap(), 0);
        t.account(slot, 5, false, false);
        assert_eq!(t.overrun(1, id, true).unwrap(), 99);
        assert_eq!(t.overrun(1, id, false).unwrap(), 4);
    }

    #[test]
    fn the_overrun_stops_at_delaytimer_max() {
        let mut t = Timers::new();
        let id = t.create(1, 12, 0, false).unwrap();
        let slot = t.find(1, id).unwrap();
        t.slots[slot].overrun = DELAYTIMER_MAX - 1;
        t.account(slot, 5, true, false);
        assert_eq!(t.overrun(1, id, false).unwrap(), DELAYTIMER_MAX);
        t.account(slot, u64::MAX, false, false);
        assert_eq!(t.overrun(1, id, false).unwrap(), DELAYTIMER_MAX);
    }

    #[test]
    fn a_short_interval_is_kept_and_looked_at_rarely_and_a_far_deadline_cut() {
        let mut t = Timers::new();
        let id = t.create(1, 12, 0, false).unwrap();
        t.set(1, id, Some(u64::MAX), 1, 10).unwrap();
        let s = t.get(1, id, 10).unwrap();
        assert_eq!(s.interval, 1);
        assert_eq!(s.remaining, HORIZON);
        // An interval of 16 ns: 100 expirations by the first look, and the
        // next look is MIN_INTERVAL later, with all that came meanwhile.
        t.set(1, id, Some(1_000), 16, 0).unwrap();
        let slot = t.find(1, id).unwrap();
        let first = t.expire(slot, 1_000 + 99 * 16);
        assert_eq!(first.count, 100);
        assert_eq!(t.earliest(), Some(1_000 + 99 * 16 + MIN_INTERVAL));
        let later = 1_000 + 99 * 16 + MIN_INTERVAL;
        assert_eq!(t.due(later - 1).1, 0);
        assert_eq!(t.due(later).1, 1);
        assert_eq!(
            t.expire(slot, later).count,
            (later - (1_000 + 100 * 16)) / 16 + 1
        );
    }

    #[test]
    fn ids_belong_to_their_owner_and_do_not_come_back() {
        let mut t = Timers::new();
        let id = t.create(1, 12, 0, false).unwrap();
        assert_eq!(t.get(2, id, 0), Err(Fail::Invalid));
        assert_eq!(t.delete(2, id), Err(Fail::Invalid));
        assert_eq!(t.delete(1, id), Ok(()));
        assert_eq!(t.get(1, id, 0), Err(Fail::Invalid));
        let again = t.create(1, 12, 0, false).unwrap();
        assert_ne!(again, id, "the place is used again, the id is not");
        assert_eq!(t.get(1, id, 0), Err(Fail::Invalid));
        assert_ne!(again, 0);
    }

    #[test]
    fn a_process_holds_per_process_timers_and_the_table_holds_slots() {
        let mut t = Timers::new();
        for _ in 0..PER_PROCESS {
            t.create(1, 12, 0, false).unwrap();
        }
        assert_eq!(t.create(1, 12, 0, false), Err(Fail::Again));
        // The alarm is one more, and other processes have their own.
        t.alarm(1, Some(5), 0, 0).unwrap();
        let mut owner = 2;
        while t.used() < SLOTS {
            for _ in 0..PER_PROCESS {
                if t.used() == SLOTS {
                    break;
                }
                t.create(owner, 12, 0, false).unwrap();
            }
            owner += 1;
        }
        assert_eq!(t.create(owner, 12, 0, false), Err(Fail::Again));
        // The alarm has its own place: a full table does not take it, and
        // every record has one.
        for process in 0..=255u8 {
            assert_eq!(
                t.alarm(process, Some(5), 0, 0).map(|s| s.remaining),
                Ok(if process == 1 { 5 } else { 0 })
            );
        }
    }

    #[test]
    fn the_alarm_reports_the_time_left_and_survives_an_exec_but_not_the_end() {
        let mut t = Timers::new();
        assert_eq!(t.alarm(4, None, 0, 0).unwrap(), Setting::default());
        assert_eq!(
            t.alarm(4, Some(3000 * MS), 0, 0).unwrap(),
            Setting::default()
        );
        let s = t.alarm(4, Some(9000 * MS), 0, 1000 * MS).unwrap();
        assert_eq!(s.remaining, 2000 * MS);
        let id = t.create(4, 10, 0, false).unwrap();
        t.clear(4, false);
        assert_eq!(t.get(4, id, 0), Err(Fail::Invalid));
        assert_eq!(t.alarm_setting(4, 2000 * MS).remaining, 7000 * MS);
        let slot = t.next(9000 * MS).unwrap();
        let e = t.expire(slot, 9000 * MS);
        assert!(e.alarm);
        assert_eq!(e.signal, proto_process::SIGALRM);
        t.alarm(4, Some(20_000 * MS), 0, 9000 * MS).unwrap();
        t.clear(4, true);
        assert_eq!(t.used(), 0);
        // A cancel gives the place back.
        t.alarm(5, Some(MS), 0, 0).unwrap();
        assert_eq!(t.alarm(5, None, 0, 0).unwrap().remaining, MS);
        assert_eq!(t.used(), 0);
    }

    #[test]
    fn the_nearest_due_timer_comes_first() {
        let mut t = Timers::new();
        let a = t.create(1, 10, 1, false).unwrap();
        let b = t.create(1, 10, 2, false).unwrap();
        t.set(1, a, Some(30 * MS), 0, 0).unwrap();
        t.set(1, b, Some(20 * MS), 0, 0).unwrap();
        let first = t.next(100 * MS).unwrap();
        assert_eq!(t.expire(first, 100 * MS).value, 2);
        let second = t.next(100 * MS).unwrap();
        assert_eq!(t.expire(second, 100 * MS).value, 1);
        assert_eq!(t.next(100 * MS), None);
    }

    #[test]
    fn a_timer_can_carry_its_own_id_as_the_value() {
        let mut t = Timers::new();
        let id = t.create(1, 14, 0xdead, true).unwrap();
        t.set(1, id, Some(5), 0, 0).unwrap();
        let slot = t.next(5).unwrap();
        assert_eq!(t.expire(slot, 5).value, u64::from(id));
    }

    #[test]
    fn due_gives_the_nearest_four_in_order() {
        let mut t = Timers::new();
        for (i, at) in [90u64, 10, 70, 30, 50, 20, 80, 60].into_iter().enumerate() {
            let id = t.create(1, 10, i as u64, false).unwrap();
            t.set(1, id, Some(at), 0, 0).unwrap();
        }
        let (list, count) = t.due(75);
        assert_eq!(count, EXPIRY_BUDGET);
        let values: Vec<u64> = list.iter().map(|&s| t.slots[s].value).collect();
        // Deadlines 10, 20, 30, 50 are the values 1, 5, 3, 4.
        assert_eq!(values, [1, 5, 3, 4]);
        assert_eq!(t.due(5).1, 0);
        assert_eq!(t.due(15).1, 1);
    }

    #[test]
    fn a_timer_on_processor_time_is_told_of_and_counts_its_overrun() {
        let mut t = Timers::new();
        let id = t.create_external(2, 36, 0x55).unwrap();
        // It never arms here: a setting only starts a new signal.
        t.set(2, id, None, 0, 0).unwrap();
        assert_eq!(t.earliest(), None);
        let e = t.fire(2, id, 1).unwrap();
        assert_eq!(
            (e.signal, e.value, e.count, e.alarm, e.owner),
            (36, 0x55, 1, false, 2)
        );
        t.account(e.slot, e.count, false, false);
        // Nine more expiries find the signal waiting: all join.
        for _ in 0..9 {
            let e = t.fire(2, id, 1).unwrap();
            t.account(e.slot, e.count, true, false);
        }
        assert_eq!(t.overrun(2, id, false).unwrap(), 9);
        let e = t.fire(2, id, 4).unwrap();
        t.account(e.slot, e.count, true, false);
        assert_eq!(t.overrun(2, id, false).unwrap(), 13);
        // Another process, a timer the service keeps and a count of 0 are none of it.
        assert_eq!(t.fire(3, id, 1), Err(Fail::Invalid));
        assert_eq!(t.fire(2, id, 0), Err(Fail::Invalid));
        let own = t.create(2, 36, 0, false).unwrap();
        assert_eq!(t.fire(2, own, 1), Err(Fail::Invalid));
        t.delete(2, id).unwrap();
        assert_eq!(t.fire(2, id, 1), Err(Fail::Invalid));
    }

    #[test]
    fn a_place_of_a_timer_on_processor_time_counts_in_the_timers_of_the_process() {
        let mut t = Timers::new();
        for _ in 0..PER_PROCESS {
            t.create_external(1, 36, 0).unwrap();
        }
        assert_eq!(t.create_external(1, 36, 0), Err(Fail::Again));
        assert_eq!(t.create(1, 36, 0, false), Err(Fail::Again));
    }
}
