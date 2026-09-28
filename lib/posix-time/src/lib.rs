// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Shared realtime anchor, wide calendar arithmetic and interval history.
#![no_std]
pub const SECOND: i128 = 1_000_000_000;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    Invalid,
    Overflow,
    Full,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Time {
    pub seconds: i64,
    pub nanos: i64,
}
impl Time {
    pub const ZERO: Self = Self {
        seconds: 0,
        nanos: 0,
    };
    pub fn value(self) -> Result<i128, Error> {
        if self.seconds < 0 || !(0..1_000_000_000).contains(&self.nanos) {
            return Err(Error::Invalid);
        }
        Ok(i128::from(self.seconds) * SECOND + i128::from(self.nanos))
    }
    pub fn from_value(value: i128) -> Result<Self, Error> {
        if value < 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            seconds: (value / SECOND).try_into().map_err(|_| Error::Overflow)?,
            nanos: (value % SECOND) as i64,
        })
    }
    pub fn from_mono(value: u64) -> Self {
        Self {
            seconds: (value / 1_000_000_000) as i64,
            nanos: (value % 1_000_000_000) as i64,
        }
    }
}
pub fn resolution(hz: u64) -> Result<u64, Error> {
    if hz == 0 {
        return Err(Error::Invalid);
    }
    Ok(1_000_000_000u64.div_ceil(hz))
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Snapshot {
    pub time: Time,
    pub resolution: u64,
    pub generation: u64,
}
/// A consistent realtime anchor, valid even when the current date overflows time_t.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub time: Time,
    pub mono: u64,
    pub resolution: u64,
    pub generation: u64,
}
/// Interval history belongs to one observing consumer, reset after each sample.
#[derive(Clone, Copy, Debug)]
pub struct History {
    peak: i128,
}
impl History {
    pub fn new(current: i128) -> Self {
        Self { peak: current }
    }
    pub fn see(&mut self, value: i128) {
        self.peak = self.peak.max(value);
    }
    pub fn take(&mut self, current: i128, anchor: Anchor) -> Observation {
        self.see(current);
        let peak = self.peak;
        self.peak = current;
        Observation { anchor, peak }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub anchor: Anchor,
    pub peak: i128,
}
/// An absolute deadline keeps signed seconds; negative values are in the past.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Deadline {
    pub clock: u32,
    seconds: i64,
    nanos: i64,
}
impl Deadline {
    pub fn new(clock: u32, seconds: i64, nanos: i64) -> Result<Self, Error> {
        if !matches!(clock, proto_clock::REALTIME | proto_clock::MONOTONIC)
            || !(0..1_000_000_000).contains(&nanos)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            clock,
            seconds,
            nanos,
        })
    }
    pub fn value(self) -> i128 {
        i128::from(self.seconds) * SECOND + i128::from(self.nanos)
    }
    pub fn expired(self, mono: u64, observation: Option<Observation>) -> Result<bool, Error> {
        if self.clock == proto_clock::MONOTONIC {
            return Ok(self.value() <= i128::from(mono));
        }
        Ok(self.value() <= observation.ok_or(Error::Invalid)?.peak)
    }
    /// Return the wide monotonic instant. A new anchor recalculates REALTIME;
    /// MONOTONIC needs no service reading. Arithmetic cannot wrap far dates.
    pub fn target(self, anchor: Option<Anchor>) -> Result<i128, Error> {
        let value = self.value();
        if self.clock == proto_clock::MONOTONIC {
            return Ok(value);
        }
        let anchor = anchor.ok_or(Error::Invalid)?;
        Ok(value - anchor.time.value()? + i128::from(anchor.mono))
    }
}
/// A sleep keeps relative intervals independent of calendar settings.
#[derive(Clone, Copy, Debug)]
pub enum Sleep {
    Relative(i128),
    Absolute(Deadline),
}
impl Sleep {
    pub fn new(
        clock: u32,
        absolute: bool,
        seconds: i64,
        nanos: i64,
        start: u64,
    ) -> Result<Self, Error> {
        let deadline = Deadline::new(clock, seconds, nanos)?;
        if seconds < 0 {
            return Err(Error::Invalid);
        }
        Ok(if absolute {
            Self::Absolute(deadline)
        } else {
            Self::Relative(i128::from(start) + deadline.value())
        })
    }
    pub fn calendar(self) -> bool {
        matches!(self, Self::Absolute(d) if d.clock == proto_clock::REALTIME)
    }
    pub fn expired(self, now: u64, observation: Option<Observation>) -> Result<bool, Error> {
        match self {
            Self::Relative(end) => Ok(end <= i128::from(now)),
            Self::Absolute(deadline) => deadline.expired(now, observation),
        }
    }
    pub fn target(self, anchor: Option<Anchor>) -> Result<i128, Error> {
        match self {
            Self::Relative(end) => Ok(end),
            Self::Absolute(deadline) => deadline.target(anchor),
        }
    }
    /// Only relative calls return a remainder; absolute calls leave it untouched.
    pub fn remaining(self, now: u64) -> Result<Option<Time>, Error> {
        match self {
            Self::Relative(end) => Time::from_value((end - i128::from(now)).max(0)).map(Some),
            Self::Absolute(_) => Ok(None),
        }
    }
}

pub struct Clock {
    value: i128,
    mono: u64,
    resolution: u64,
    generation: u64,
}
impl Clock {
    pub fn new(mono: u64, hz: u64) -> Result<Self, Error> {
        Ok(Self {
            value: 0,
            mono,
            resolution: resolution(hz)?,
            generation: 0,
        })
    }
    pub fn current(&self, now: u64) -> Result<i128, Error> {
        Ok(self.value + i128::from(now.checked_sub(self.mono).ok_or(Error::Invalid)?))
    }
    pub fn anchor(&self) -> Anchor {
        Anchor {
            time: Time::from_value(self.value).expect("valid stored calendar anchor"),
            mono: self.mono,
            resolution: self.resolution,
            generation: self.generation,
        }
    }
    pub fn get(&self, id: u32, now: u64) -> Result<Snapshot, Error> {
        let time = match id {
            proto_clock::MONOTONIC => Time::from_mono(now),
            proto_clock::REALTIME => {
                let elapsed = now.checked_sub(self.mono).ok_or(Error::Invalid)?;
                Time::from_value(self.value + i128::from(elapsed))?
            }
            _ => return Err(Error::Invalid),
        };
        Ok(Snapshot {
            time,
            resolution: self.resolution,
            generation: self.generation,
        })
    }
    pub fn set(&mut self, time: Time, now: u64) -> Result<(), Error> {
        let value = time.value()?;
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        self.value = value / i128::from(self.resolution) * i128::from(self.resolution);
        self.mono = now;
        self.generation = generation;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use proto_clock::{MONOTONIC, REALTIME};
    fn time(seconds: i64, nanos: i64) -> Time {
        Time { seconds, nanos }
    }
    #[test]
    fn calendar_moves_forward_and_backward_without_changing_monotonic() {
        let mut c = Clock::new(1_000, 62_500_000).unwrap();
        assert_eq!(c.get(REALTIME, 1_123).unwrap().time, time(0, 123));
        c.set(time(1_700_000_000, 17), 2_000).unwrap();
        assert_eq!(
            c.get(REALTIME, 2_032).unwrap().time,
            time(1_700_000_000, 48)
        );
        assert_eq!(c.get(MONOTONIC, 2_032).unwrap().time, time(0, 2_032));
        c.set(time(2, 1), 3_000).unwrap();
        assert_eq!(c.get(REALTIME, 3_000).unwrap().time, time(2, 0));
        assert_eq!(c.get(MONOTONIC, 3_000).unwrap().time, time(0, 3_000));
        assert_eq!(c.get(REALTIME, 3_000).unwrap().generation, 2);
    }
    #[test]
    fn rounding_applies_to_the_whole_calendar_value() {
        let mut c = Clock::new(0, 24_000_000).unwrap();
        assert_eq!(resolution(24_000_000), Ok(42));
        let input = time(1, 43);
        c.set(input, 100).unwrap();
        assert_eq!(
            c.get(REALTIME, 100).unwrap().time.value().unwrap(),
            input.value().unwrap() / 42 * 42
        );
        assert_eq!(resolution(62_500_000), Ok(16));
        assert_eq!(resolution(2_000_000_000), Ok(1));
        assert_eq!(resolution(0), Err(Error::Invalid));
    }
    #[test]
    fn calendar_uses_more_than_u64_nanoseconds_and_detects_time_t_overflow() {
        let mut c = Clock::new(0, 1_000_000_000).unwrap();
        c.set(time(20_000_000_000, 999_999_999), 4).unwrap();
        assert_eq!(c.get(REALTIME, 5).unwrap().time, time(20_000_000_001, 0));
        c.set(time(i64::MAX, 999_999_999), 10).unwrap();
        assert_eq!(c.get(REALTIME, 11), Err(Error::Overflow));
        assert_eq!(c.get(MONOTONIC, 11).unwrap().time, time(0, 11));
    }
    #[test]
    fn invalid_settings_and_generation_overflow_leave_the_anchor_unchanged() {
        let mut c = Clock::new(100, 1_000_000_000).unwrap();
        for invalid in [time(-1, 0), time(0, -1), time(0, 1_000_000_000)] {
            assert_eq!(c.set(invalid, 200), Err(Error::Invalid));
            assert_eq!(c.get(REALTIME, 201).unwrap().time, time(0, 101));
            assert_eq!(c.generation, 0);
        }
        assert_eq!(c.get(2, 201), Err(Error::Invalid));
        assert_eq!(c.get(REALTIME, 99), Err(Error::Invalid));
        c.generation = u64::MAX;
        assert_eq!(c.set(time(10, 0), 200), Err(Error::Overflow));
        assert_eq!(c.get(REALTIME, 201).unwrap().time, time(0, 101));
    }
    #[test]
    fn absolute_deadlines_follow_each_clock_and_both_calendar_steps() {
        let mut clock = Clock::new(100, 1_000_000_000).unwrap();
        clock.set(time(10, 0), 100).unwrap();
        let calendar = Deadline::new(REALTIME, 11, 0).unwrap();
        let mono = Deadline::new(MONOTONIC, 0, 777).unwrap();
        assert_eq!(calendar.target(Some(clock.anchor())), Ok(1_000_000_100));
        clock.set(time(12, 0), 200).unwrap();
        assert_eq!(calendar.target(Some(clock.anchor())), Ok(-999_999_800));
        assert_eq!(mono.target(Some(clock.anchor())), Ok(777));
        clock.set(time(1, 0), 300).unwrap();
        assert_eq!(calendar.target(Some(clock.anchor())), Ok(10_000_000_300));
        assert_eq!(mono.target(None), Ok(777));
        assert_eq!(calendar.target(None), Err(Error::Invalid));
    }
    #[test]
    fn deadlines_preserve_past_and_far_future_without_wrapping() {
        assert_eq!(
            Deadline::new(MONOTONIC, -1, 999_999_999)
                .unwrap()
                .target(None),
            Ok(-1)
        );
        let far = Deadline::new(MONOTONIC, i64::MAX, 999_999_999)
            .unwrap()
            .target(None)
            .unwrap();
        assert!(far > i128::from(u64::MAX));
        assert!(u64::try_from(far).is_err());
        for ns in [-1, 1_000_000_000] {
            assert_eq!(Deadline::new(REALTIME, 0, ns), Err(Error::Invalid));
        }
        assert_eq!(Deadline::new(2, 0, 0), Err(Error::Invalid));
    }
    #[test]
    fn anchor_keeps_deadlines_valid_after_current_time_overflows_time_t() {
        let mut clock = Clock::new(0, 1_000_000_000).unwrap();
        clock.set(time(i64::MAX, 999_999_999), 50).unwrap();
        assert_eq!(clock.get(REALTIME, 51), Err(Error::Overflow));
        let deadline = Deadline::new(REALTIME, i64::MAX, 999_999_999).unwrap();
        assert_eq!(deadline.target(Some(clock.anchor())), Ok(50));
    }
    #[test]
    fn interval_peak_preserves_brief_forward_steps_and_resets_for_new_waits() {
        let mut clock = Clock::new(100, 1_000_000_000).unwrap();
        clock.set(time(10, 0), 100).unwrap();
        let mut history = History::new(clock.current(100).unwrap());
        let deadline = Deadline::new(REALTIME, 11, 0).unwrap();
        history.see(clock.current(200).unwrap());
        clock.set(time(12, 0), 200).unwrap();
        history.see(clock.current(200).unwrap());
        clock.set(time(10, 0), 300).unwrap();
        let sample = history.take(clock.current(300).unwrap(), clock.anchor());
        assert_eq!(deadline.expired(300, Some(sample)), Ok(true));
        assert!(deadline.target(Some(sample.anchor)).unwrap() > 300);
        let next = history.take(clock.current(400).unwrap(), clock.anchor());
        assert_eq!(deadline.expired(400, Some(next)), Ok(false));
        assert_eq!(
            Deadline::new(MONOTONIC, 0, 500)
                .unwrap()
                .expired(400, Some(sample)),
            Ok(false)
        );
    }
    #[test]
    fn relative_sleep_ignores_calendar_steps_and_reports_elapsed_remainder() {
        for clock in [REALTIME, MONOTONIC] {
            let sleep = Sleep::new(clock, false, 2, 100, 500).unwrap();
            assert!(!sleep.calendar());
            assert_eq!(sleep.target(None), Ok(2_000_000_600));
            assert_eq!(sleep.expired(2_000_000_599, None), Ok(false));
            assert_eq!(sleep.expired(2_000_000_600, None), Ok(true));
            assert_eq!(sleep.remaining(1_000_000_500), Ok(Some(time(1, 100))));
            assert_eq!(sleep.remaining(3_000_000_000), Ok(Some(Time::ZERO)));
            let mut model = Clock::new(0, 1_000_000_000).unwrap();
            for date in [100, 1] {
                model.set(time(date, 0), 500).unwrap();
                let sample = Observation {
                    anchor: model.anchor(),
                    peak: model.current(500).unwrap(),
                };
                assert_eq!(sleep.expired(600, Some(sample)), Ok(false));
                assert_eq!(sleep.target(Some(sample.anchor)), Ok(2_000_000_600));
            }
        }
    }
    #[test]
    fn absolute_sleep_uses_original_clock_and_ignores_remainder() {
        let sleep = Sleep::new(REALTIME, true, 11, 0, 123).unwrap();
        assert!(sleep.calendar());
        assert_eq!(sleep.remaining(456), Ok(None));
        let mut model = Clock::new(100, 1_000_000_000).unwrap();
        model.set(time(10, 0), 100).unwrap();
        let mut history = History::new(model.current(100).unwrap());
        assert_eq!(sleep.target(Some(model.anchor())), Ok(1_000_000_100));
        history.see(12 * SECOND);
        model.set(time(1, 0), 200).unwrap();
        let sample = history.take(model.current(200).unwrap(), model.anchor());
        assert_eq!(sleep.expired(200, Some(sample)), Ok(true));
        assert_eq!(sleep.target(Some(sample.anchor)), Ok(10_000_000_200));
        let next = history.take(model.current(300).unwrap(), model.anchor());
        assert_eq!(sleep.expired(300, Some(next)), Ok(false));
        let mono = Sleep::new(MONOTONIC, true, 0, 999, 100).unwrap();
        assert!(!mono.calendar());
        assert_eq!(mono.expired(998, Some(sample)), Ok(false));
        assert_eq!(mono.expired(999, None), Ok(true));
    }
    #[test]
    fn sleep_preserves_largest_duration_without_saturating_deadline() {
        let sleep = Sleep::new(REALTIME, false, i64::MAX, 999_999_999, u64::MAX).unwrap();
        assert!(sleep.target(None).unwrap() > i128::from(u64::MAX));
        assert_eq!(sleep.expired(u64::MAX, None), Ok(false));
        assert_eq!(
            sleep.remaining(u64::MAX),
            Ok(Some(time(i64::MAX, 999_999_999)))
        );
        assert_eq!(
            Sleep::new(MONOTONIC, false, 0, 0, 123)
                .unwrap()
                .expired(123, None),
            Ok(true)
        );
    }
    #[test]
    fn sleep_rejects_negative_and_malformed_values_in_both_modes() {
        for absolute in [false, true] {
            for (clock, sec, ns) in [
                (2, 0, 0),
                (REALTIME, -1, 0),
                (MONOTONIC, 0, -1),
                (REALTIME, 0, 1_000_000_000),
            ] {
                assert!(matches!(
                    Sleep::new(clock, absolute, sec, ns, 100),
                    Err(Error::Invalid)
                ));
            }
        }
    }
}
