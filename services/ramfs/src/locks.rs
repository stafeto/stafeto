// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Byte ranges for advisory file locks. Arithmetic is independent of the
//! service's paid records and captures SEEK_CUR and SEEK_END before waiting.

/// The greatest byte offset representable by relibc's off_t.
pub const OFFSET_MAX: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// The range includes a byte before the beginning of the file.
    Invalid,
    /// A byte offset cannot be represented by off_t.
    Overflow,
}

/// The inclusive bounds of a nonempty lock region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    first: u64,
    last: u64,
}

impl Range {
    /// Normalize l_start and l_len relative to the captured seek origin.
    /// The origin is zero for SEEK_SET, the current cursor for SEEK_CUR,
    /// and the current length for SEEK_END. An intermediate anchor can
    /// exceed off_t when a negative length still describes valid bytes.
    pub fn relative(origin: u64, start: i64, length: i64) -> Result<Self, RangeError> {
        if origin > OFFSET_MAX {
            return Err(RangeError::Overflow);
        }
        let anchor = i128::from(origin) + i128::from(start);
        let (first, last) = match length.cmp(&0) {
            core::cmp::Ordering::Greater => (anchor, anchor + i128::from(length) - 1),
            core::cmp::Ordering::Less => (anchor + i128::from(length), anchor - 1),
            core::cmp::Ordering::Equal => (anchor, i128::from(OFFSET_MAX)),
        };
        if first < 0 || last < 0 {
            return Err(RangeError::Invalid);
        }
        if first > i128::from(OFFSET_MAX) || last > i128::from(OFFSET_MAX) {
            return Err(RangeError::Overflow);
        }
        Ok(Self {
            first: first as u64,
            last: last as u64,
        })
    }

    pub const fn first(self) -> u64 {
        self.first
    }

    pub const fn last(self) -> u64 {
        self.last
    }

    /// The canonical SEEK_SET pair. A range through OFFSET_MAX uses zero
    /// length, including a finite request ending at that same final byte.
    pub const fn start_and_length(self) -> (i64, i64) {
        let length = if self.last == OFFSET_MAX {
            0
        } else {
            (self.last - self.first + 1) as i64
        };
        (self.first as i64, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_negative_and_open_lengths_capture_the_seek_origin() {
        assert_eq!(
            Range::relative(50, 10, 4).unwrap().start_and_length(),
            (60, 4)
        );
        assert_eq!(
            Range::relative(50, 10, -4).unwrap().start_and_length(),
            (56, 4)
        );
        assert_eq!(
            Range::relative(50, -10, 0).unwrap().start_and_length(),
            (40, 0)
        );
        assert_eq!(Range::relative(0, 0, 0).unwrap().last(), OFFSET_MAX);
        assert_eq!(Range::relative(100, -100, 1).unwrap().first(), 0);
    }

    #[test]
    fn inclusive_last_byte_and_negative_length_use_wide_arithmetic() {
        let last = Range::relative(OFFSET_MAX, 0, 1).unwrap();
        assert_eq!((last.first(), last.last()), (OFFSET_MAX, OFFSET_MAX));
        assert_eq!(last.start_and_length(), (i64::MAX, 0));
        let backwards = Range::relative(OFFSET_MAX, 1, -2).unwrap();
        assert_eq!(
            (backwards.first(), backwards.last()),
            (OFFSET_MAX - 1, OFFSET_MAX)
        );
        assert_eq!(Range::relative(OFFSET_MAX, 1, i64::MIN).unwrap().first(), 0);
        assert_eq!(
            Range::relative(OFFSET_MAX, -i64::MAX, i64::MAX)
                .unwrap()
                .last(),
            OFFSET_MAX - 1
        );
    }

    #[test]
    fn invalid_negative_offsets_and_positive_overflow_are_distinct() {
        for (origin, start, length) in [
            (0, -1, 0),
            (0, 0, -1),
            (0, 1, -2),
            (0, i64::MIN, 1),
            (OFFSET_MAX, 0, i64::MIN),
        ] {
            assert_eq!(
                Range::relative(origin, start, length),
                Err(RangeError::Invalid)
            );
        }
        for (origin, start, length) in [
            (OFFSET_MAX, 1, 0),
            (OFFSET_MAX, 0, 2),
            (OFFSET_MAX, 2, -1),
            (OFFSET_MAX + 1, -1, 1),
        ] {
            assert_eq!(
                Range::relative(origin, start, length),
                Err(RangeError::Overflow)
            );
        }
    }
}
