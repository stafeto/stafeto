// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Explicit startup time modes and one bounded calendar-time attempt.

use core::cell::Cell;
use core::sync::atomic::Ordering;
use proto_clock::page::Anchor;
use proto_fs::Timestamp;
use proto_wire::Status;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Legacy,
    Clocked,
}

impl Mode {
    pub fn parse(args: &[u8]) -> Result<Self, Status> {
        match args {
            proto_fs::RAM_TIME_LEGACY => Ok(Self::Legacy),
            proto_fs::RAM_TIME_CLOCKED => Ok(Self::Clocked),
            _ => Err(Status::BadSize),
        }
    }
}

/// An unstable snapshot defers the step. Overflow refuses its effect.
pub fn read_timestamp_once(
    load: impl FnMut(usize, Ordering) -> u64,
    monotonic_now: u64,
) -> Result<Option<Timestamp>, Status> {
    read_validated_once(load, monotonic_now).map(|snapshot| snapshot.map(|(_, time)| time))
}

fn read_validated_once(
    load: impl FnMut(usize, Ordering) -> u64,
    monotonic_now: u64,
) -> Result<Option<(Anchor, Timestamp)>, Status> {
    let Some(anchor) = proto_clock::page::read_anchor_once(load) else {
        return Ok(None);
    };
    let ns = anchor.realtime_ns(monotonic_now).ok_or(Status::BadSize)?;
    Timestamp::from_ns(ns).map(|time| Some((anchor, time)))
}

/// The service owns this cache on its single dispatch thread. Startup primes
/// it before publishing Ready; transient page changes keep calendar time.
#[derive(Default)]
pub struct Calendar {
    validated: Cell<Option<(Anchor, Timestamp)>>,
}

impl Calendar {
    pub fn read_once(
        &self,
        load: impl FnMut(usize, Ordering) -> u64,
        monotonic_now: u64,
    ) -> Result<Option<Timestamp>, Status> {
        let Some((anchor, time)) = read_validated_once(load, monotonic_now)? else {
            return Ok(None);
        };
        self.validated.set(Some((anchor, time)));
        Ok(Some(time))
    }

    /// Exactly one six-load attempt, followed by local checked arithmetic.
    /// An out-of-range extrapolation keeps the last valid calendar value.
    pub fn now(
        &self,
        load: impl FnMut(usize, Ordering) -> u64,
        monotonic_now: u64,
    ) -> Result<Timestamp, Status> {
        if let Ok(Some(time)) = self.read_once(load, monotonic_now) {
            return Ok(time);
        }
        let (anchor, last) = self.validated.get().ok_or(Status::BadSize)?;
        let time = anchor
            .realtime_ns(monotonic_now)
            .and_then(|ns| Timestamp::from_ns(ns).ok())
            .unwrap_or(last);
        self.validated.set(Some((anchor, time)));
        Ok(time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU64;

    fn page(sequence: u64, value: i128, mono: u64, generation: u64) -> [u64; 9] {
        let mut words = [0; 9];
        words[0] = sequence;
        let place = 1 + (sequence % 2) as usize * 4;
        words[place] = value as u64;
        words[place + 1] = (value >> 64) as u64;
        words[place + 2] = mono;
        words[place + 3] = generation;
        words
    }

    fn sample(calendar: &Calendar, words: [u64; 9], now: u64, changing: bool) -> Timestamp {
        let mut loads = 0;
        let time = calendar
            .now(
                |offset, _| {
                    loads += 1;
                    if changing && offset == 0 && loads == 6 {
                        words[0].wrapping_add(1)
                    } else {
                        words[offset / 8]
                    }
                },
                now,
            )
            .unwrap();
        assert_eq!(loads, 6, "one bounded page attempt per dispatch");
        time
    }

    #[test]
    fn calendar_requires_startup_and_accepts_stable_odd_anchor() {
        let calendar = Calendar::default();
        let words = page(1, 1_700_000_000_000_000_000, 100, 7);
        let invalid = page(0, i128::MAX, 0, 0);
        assert_eq!(
            calendar.now(|offset, _| invalid[offset / 8], u64::MAX),
            Err(Status::BadSize)
        );
        assert_eq!(
            calendar.read_once(|offset, _| words[offset / 8], 101),
            Ok(Some(Timestamp::new(1_700_000_000, 1).unwrap()))
        );
        assert_eq!(
            sample(&calendar, words, 102, false),
            Timestamp::new(1_700_000_000, 2).unwrap()
        );
    }

    #[test]
    fn changing_snapshot_uses_calendar_anchor_and_reanchor_replaces_it() {
        let calendar = Calendar::default();
        let first = page(0, 2_000_000_000, 100, 1);
        assert_eq!(
            sample(&calendar, first, 105, false),
            Timestamp::new(2, 5).unwrap()
        );
        let unpublished = page(1, 900_000_000_000, 200, 2);
        assert_eq!(
            sample(&calendar, unpublished, 110, true),
            Timestamp::new(2, 10).unwrap()
        );
        // A successful Change/Data attempt refreshes the same dispatch cache.
        let next = page(1, -2_000_000_000, 200, 3);
        assert_eq!(
            calendar.read_once(|offset, _| next[offset / 8], 201),
            Ok(Some(Timestamp::new(-2, 1).unwrap()))
        );
        assert_eq!(
            sample(&calendar, unpublished, 205, true),
            Timestamp::new(-2, 5).unwrap()
        );
        // Earlier monotonic readings use the anchor instant without underflow.
        assert_eq!(
            sample(&calendar, unpublished, 190, true),
            Timestamp::new(-2, 0).unwrap()
        );
    }

    #[test]
    fn invalid_candidate_preserves_cache_and_overflow_keeps_last_calendar_value() {
        let calendar = Calendar::default();
        let max = i128::from(i64::MAX) * 1_000_000_000 + 999_999_999;
        let valid = page(0, max - 3, 100, 1);
        let last = Timestamp::new(i64::MAX, 999_999_998).unwrap();
        assert_eq!(sample(&calendar, valid, 102, false), last);
        let invalid = page(1, i128::MAX, 100, 2);
        assert_eq!(
            calendar.read_once(|offset, _| invalid[offset / 8], 101),
            Err(Status::BadSize)
        );
        assert_eq!(sample(&calendar, invalid, 104, false), last);
        assert_eq!(sample(&calendar, invalid, u64::MAX, true), last);
        // Overflow never installs the bad anchor; a later valid reading recovers.
        let recovered = page(1, 6_000_000_000, 300, 3);
        assert_eq!(
            sample(&calendar, recovered, 301, false),
            Timestamp::new(6, 1).unwrap()
        );
    }

    #[test]
    fn only_explicit_time_modes_are_accepted() {
        assert_eq!(Mode::parse(proto_fs::RAM_TIME_LEGACY), Ok(Mode::Legacy));
        assert_eq!(Mode::parse(proto_fs::RAM_TIME_CLOCKED), Ok(Mode::Clocked));
        for args in [&b""[..], &b"time-clocked\0"[..], &b"time"[..]] {
            assert_eq!(Mode::parse(args), Err(Status::BadSize));
        }
    }

    #[test]
    fn signed_calendar_conversion_and_defer_precede_effects() {
        let words: [AtomicU64; 9] = core::array::from_fn(|_| AtomicU64::new(0));
        let read = |value: i128, mutate: bool| {
            words[0].store(0, Ordering::Relaxed);
            words[1].store(value as u64, Ordering::Relaxed);
            words[2].store((value >> 64) as u64, Ordering::Relaxed);
            words[3].store(100, Ordering::Relaxed);
            let mut count = 0;
            let result = read_timestamp_once(
                |offset, ordering| {
                    let value = words[offset / 8].load(ordering);
                    if count == 2 && mutate {
                        words[0].store(2, Ordering::Release);
                    }
                    count += 1;
                    value
                },
                101,
            );
            assert_eq!(count, 6);
            result
        };
        assert_eq!(
            read(-2, false),
            Ok(Some(Timestamp::new(-1, 999_999_999).unwrap()))
        );
        assert_eq!(read(-2, true), Ok(None));
        assert_eq!(read(i128::MAX, false), Err(Status::BadSize));
        let max = i128::from(i64::MAX) * 1_000_000_000 + 999_999_999;
        assert_eq!(
            read(max - 1, false),
            Ok(Some(Timestamp::new(i64::MAX, 999_999_999).unwrap()))
        );
        assert_eq!(read(max, false), Err(Status::BadSize));
        let min = i128::from(i64::MIN) * 1_000_000_000;
        assert_eq!(
            read(min - 1, false),
            Ok(Some(Timestamp::new(i64::MIN, 0).unwrap()))
        );
        assert_eq!(read(min - 2, false), Err(Status::BadSize));
    }
}
