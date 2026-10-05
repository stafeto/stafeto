// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::page::{self, Anchor};
use core::sync::atomic::{AtomicU64, Ordering};

fn words(sequence: u64, value: i128) -> [AtomicU64; 9] {
    let words = core::array::from_fn(|_| AtomicU64::new(u64::MAX));
    words[0].store(sequence, Ordering::Relaxed);
    let slot = (page::PLACES + (sequence % 2) as usize * page::PLACE_SIZE) / 8;
    words[slot].store(value as u64, Ordering::Relaxed);
    words[slot + 1].store((value >> 64) as u64, Ordering::Relaxed);
    words[slot + 2].store(500, Ordering::Relaxed);
    words[slot + 3].store(42, Ordering::Relaxed);
    words
}

#[test]
fn both_slots_preserve_full_signed_anchor_and_read_order() {
    for sequence in [0, 1, u64::MAX - 1, u64::MAX] {
        for value in [i128::MIN, -1_000_000_001, 0, i128::MAX] {
            let words = words(sequence, value);
            let slot = page::PLACES + (sequence % 2) as usize * page::PLACE_SIZE;
            let expected = [
                (page::SEQUENCE, Ordering::Acquire),
                (slot + page::LOW, Ordering::Relaxed),
                (slot + page::HIGH, Ordering::Relaxed),
                (slot + page::MONO, Ordering::Relaxed),
                (slot + page::GENERATION, Ordering::Relaxed),
                (page::SEQUENCE, Ordering::Relaxed),
            ];
            let mut count = 0;
            let actual = page::read_anchor_once(|offset, ordering| {
                assert_eq!((offset, ordering), expected[count]);
                count += 1;
                words[offset / 8].load(ordering)
            });
            assert_eq!(count, 6);
            assert_eq!(
                actual,
                Some(Anchor {
                    value_ns: value,
                    monotonic_ns: 500,
                    generation: 42
                })
            );
        }
    }
}

#[test]
fn writer_during_any_field_defers_once_including_same_slot_reuse() {
    for sequence in [0_u64, 1, u64::MAX] {
        for advance in [1, 2] {
            for changed_after in 1..=4 {
                let words = words(sequence, -123);
                let mut count = 0;
                let actual = page::read_anchor_once(|offset, ordering| {
                    let value = words[offset / 8].load(ordering);
                    if count == changed_after {
                        words[0].store(sequence.wrapping_add(advance), Ordering::Release);
                    }
                    count += 1;
                    value
                });
                assert_eq!(actual, None);
                assert_eq!(count, 6);
            }
        }
    }
}

#[test]
fn realtime_addition_checks_overflow_and_monotonic_rollback() {
    let mut anchor = Anchor {
        value_ns: -1_000_000_001,
        monotonic_ns: 500,
        generation: 42,
    };
    assert_eq!(anchor.realtime_ns(501), Some(-1_000_000_000));
    assert_eq!(anchor.realtime_ns(499), Some(-1_000_000_001));
    anchor.value_ns = i128::MAX;
    assert_eq!(anchor.realtime_ns(500), Some(i128::MAX));
    assert_eq!(anchor.realtime_ns(501), None);
    anchor.value_ns = i128::MIN;
    anchor.monotonic_ns = 0;
    assert_eq!(
        anchor.realtime_ns(u64::MAX),
        Some(i128::MIN + i128::from(u64::MAX))
    );
}
