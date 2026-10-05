// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Explicit startup time modes and one bounded calendar-time attempt.

use core::sync::atomic::Ordering;
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
    let Some(anchor) = proto_clock::page::read_anchor_once(load) else {
        return Ok(None);
    };
    let ns = anchor.realtime_ns(monotonic_now).ok_or(Status::BadSize)?;
    Timestamp::from_ns(ns).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU64;

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
