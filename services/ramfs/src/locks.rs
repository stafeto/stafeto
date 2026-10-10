// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Byte ranges for advisory file locks. Arithmetic is independent of the
//! service's paid records and captures SEEK_CUR and SEEK_END before waiting.

pub mod actor;
pub mod budget;
pub mod deadlock;
pub mod dispatch;
pub mod groups;
pub mod jobs;
pub mod preparation;
pub mod records;
pub mod request;
pub mod server;
pub mod service;
pub mod wait_departure;
pub mod wait_notifications;
pub mod wait_receipts;
pub mod wait_server;
pub mod waiters;
#[cfg(test)]
mod waiters_tests;

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

    pub const fn overlaps(self, other: Self) -> bool {
        self.first <= other.last && other.first <= self.last
    }

    /// The retained edges after removing a region, in increasing order.
    /// The caller can reserve both edges before publishing an unlock.
    pub fn subtract(self, cut: Self) -> [Option<Self>; 2] {
        if !self.overlaps(cut) {
            return [Some(self), None];
        }
        let left = (self.first < cut.first).then(|| Self {
            first: self.first,
            last: cut.first - 1,
        });
        let right = (cut.last < self.last).then(|| Self {
            first: cut.last + 1,
            last: self.last,
        });
        match (left, right) {
            (None, right) => [right, None],
            (left, right) => [left, right],
        }
    }

    /// Join adjacent or overlapping regions. A gap leaves them separate.
    pub fn merge(self, other: Self) -> Option<Self> {
        // Valid offsets are at most i64::MAX, so adding one fits in u64.
        if self.first > other.last + 1 || other.first > self.last + 1 {
            return None;
        }
        Some(Self {
            first: self.first.min(other.first),
            last: self.last.max(other.last),
        })
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

/// The process PID already includes the process service's record generation.
/// An OFD names one exact lifetime in the shared-description table. The two
/// kinds remain independent even when the process opened that description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Process(u32),
    Description { slot: u16, generation: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
}

/// One region of a single file. The service authenticates its owner and
/// selects the file's records before checking conflicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    pub owner: Owner,
    pub kind: Kind,
    pub range: Range,
}

impl Lock {
    /// Existing regions of the same exact owner are replaced by a request.
    pub fn conflicts(self, request: Self) -> bool {
        self.owner != request.owner
            && self.range.overlaps(request.range)
            && (matches!(self.kind, Kind::Write) || matches!(request.kind, Kind::Write))
    }

    /// The old regions to preserve while this owner changes the cut region.
    /// Existing records of every other owner are preserved in full.
    pub fn remainder(self, owner: Owner, cut: Range) -> [Option<Self>; 2] {
        if self.owner != owner {
            return [Some(self), None];
        }
        self.range
            .subtract(cut)
            .map(|range| range.map(|range| Self { range, ..self }))
    }

    /// Canonical coalescing keeps both the lock type and exact owner.
    pub fn merge(self, other: Self) -> Option<Self> {
        if self.owner != other.owner || self.kind != other.kind {
            return None;
        }
        self.range
            .merge(other.range)
            .map(|range| Self { range, ..self })
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

    fn lock(owner: Owner, kind: Kind, start: i64, length: i64) -> Lock {
        Lock {
            owner,
            kind,
            range: Range::relative(0, start, length).unwrap(),
        }
    }

    #[test]
    fn shared_reads_and_exact_owners_define_conflicts() {
        let a = lock(Owner::Process(256), Kind::Read, 10, 20);
        let b = lock(Owner::Process(512), Kind::Read, 20, 20);
        assert!(!a.conflicts(b));
        assert!(a.conflicts(Lock {
            kind: Kind::Write,
            ..b
        }));
        assert!(!a.conflicts(Lock {
            owner: a.owner,
            kind: Kind::Write,
            ..b
        }));
        assert!(!a.conflicts(lock(b.owner, Kind::Write, 30, 1)));
        assert!(a.conflicts(lock(b.owner, Kind::Write, 29, 1)));
        assert!(a.conflicts(lock(b.owner, Kind::Write, 0, 0)));
    }

    #[test]
    fn description_lifetimes_and_process_owners_stay_independent() {
        let owner = Owner::Description {
            slot: 0,
            generation: 256,
        };
        let held = lock(owner, Kind::Write, 10, 20);
        assert!(!held.conflicts(lock(owner, Kind::Write, 10, 20)));
        for other in [
            Owner::Description {
                slot: 0,
                generation: 512,
            },
            Owner::Description {
                slot: 1,
                generation: 256,
            },
            Owner::Process(256),
        ] {
            assert!(held.conflicts(lock(other, Kind::Read, 10, 20)));
            assert!(lock(other, Kind::Read, 10, 20).conflicts(held));
        }
    }

    #[test]
    fn removing_a_middle_region_retains_both_edges_and_their_type() {
        let owner = Owner::Process(256);
        let original = lock(owner, Kind::Write, 10, 30);
        assert_eq!(
            original.remainder(owner, Range::relative(0, 20, 10).unwrap()),
            [
                Some(lock(owner, Kind::Write, 10, 10)),
                Some(lock(owner, Kind::Write, 30, 10)),
            ]
        );
        assert_eq!(original.remainder(owner, original.range), [None, None]);
        assert_eq!(
            original.remainder(Owner::Process(512), original.range),
            [Some(original), None]
        );
        assert_eq!(
            original.remainder(owner, Range::relative(0, 40, 1).unwrap()),
            [Some(original), None]
        );
    }

    #[test]
    fn subtract_handles_the_first_and_last_representable_bytes() {
        let all = Range::relative(0, 0, 0).unwrap();
        let first = Range::relative(0, 0, 1).unwrap();
        let last = Range::relative(0, i64::MAX, 1).unwrap();
        assert_eq!(all.subtract(first)[0].unwrap().start_and_length(), (1, 0));
        assert_eq!(
            all.subtract(last)[0].unwrap().start_and_length(),
            (0, i64::MAX)
        );
        assert_eq!(last.subtract(last), [None, None]);
        assert_eq!(
            all.subtract(Range::relative(0, 1, 0).unwrap()),
            [Some(first), None]
        );
    }

    #[test]
    fn coalescing_preserves_gaps_kinds_and_exact_owners() {
        let a = lock(Owner::Process(256), Kind::Read, 10, 10);
        let next = lock(a.owner, a.kind, 20, 10);
        let expected = Some(lock(a.owner, a.kind, 10, 20));
        assert_eq!(a.merge(next), expected);
        assert_eq!(next.merge(a), expected);
        assert_eq!(
            a.merge(lock(a.owner, a.kind, 19, 10)),
            Some(lock(a.owner, a.kind, 10, 19))
        );
        assert_eq!(a.merge(lock(a.owner, a.kind, 21, 10)), None);
        assert_eq!(
            a.merge(Lock {
                kind: Kind::Write,
                ..next
            }),
            None
        );
        assert_eq!(
            a.merge(Lock {
                owner: Owner::Process(512),
                ..next
            }),
            None
        );
        let last = lock(a.owner, a.kind, i64::MAX, 1);
        assert_eq!(last.merge(last), Some(last));
    }

    #[test]
    fn range_algebra_matches_a_small_independent_byte_model() {
        let bits = |range: Range| {
            (range.first()..=range.last()).fold(0_u32, |bits, byte| bits | (1 << byte))
        };
        for first in 0..16 {
            for last in first..16 {
                let range = Range::relative(0, first, last - first + 1).unwrap();
                for cut_first in 0..16 {
                    for cut_last in cut_first..16 {
                        let cut = Range::relative(0, cut_first, cut_last - cut_first + 1).unwrap();
                        let kept = range.subtract(cut);
                        let actual = kept
                            .into_iter()
                            .flatten()
                            .fold(0, |mask, edge| mask | bits(edge));
                        assert_eq!(actual, bits(range) & !bits(cut));
                        assert_eq!(range.overlaps(cut), bits(range) & bits(cut) != 0);
                        let union = bits(range) | bits(cut);
                        let contiguous = union.count_ones()
                            == 32 - union.leading_zeros() - union.trailing_zeros();
                        assert_eq!(range.merge(cut).is_some(), contiguous);
                        if let Some(merged) = range.merge(cut) {
                            assert_eq!(bits(merged), union);
                        }
                        if let [Some(left), Some(right)] = kept {
                            assert!(left.last() < right.first());
                        }
                    }
                }
            }
        }
    }
}
