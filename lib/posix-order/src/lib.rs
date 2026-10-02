// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Unsigned byte collation for the C locale and allocation-free heap sorting.

#![no_std]

use core::cmp::Ordering;

pub fn collate(left: &[u8], right: &[u8]) -> Ordering {
    left.cmp(right)
}

/// Sort count elements using callbacks that compare and swap current indices.
/// Comparator arguments always refer to actual elements, never temporary copies.
pub fn sort_by(
    count: usize,
    mut compare: impl FnMut(usize, usize) -> Ordering,
    mut swap: impl FnMut(usize, usize),
) {
    fn sift(
        mut root: usize,
        count: usize,
        compare: &mut impl FnMut(usize, usize) -> Ordering,
        swap: &mut impl FnMut(usize, usize),
    ) {
        while root < count / 2 {
            let mut child = root * 2 + 1;
            if child + 1 < count && compare(child, child + 1) == Ordering::Less {
                child += 1;
            }
            if compare(root, child) != Ordering::Less {
                break;
            }
            swap(root, child);
            root = child;
        }
    }
    for root in (0..count / 2).rev() {
        sift(root, count, &mut compare, &mut swap);
    }
    for end in (1..count).rev() {
        swap(0, end);
        sift(0, end, &mut compare, &mut swap);
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, vec::Vec};

    #[test]
    fn c_collation_uses_unsigned_bytes_and_prefix_order() {
        assert_eq!(collate(b"", b"a"), Ordering::Less);
        assert_eq!(collate(b"A", b"a"), Ordering::Less);
        assert_eq!(collate(&[0x80], &[0x7f]), Ordering::Greater);
        assert_eq!(collate(&[0xff], &[0x80]), Ordering::Greater);
        assert_eq!(collate(b"abc", b"abcd"), Ordering::Less);
        assert_eq!(collate(b"same", b"same"), Ordering::Equal);
    }

    #[test]
    fn sort_matches_reference_for_empty_sorted_reverse_and_duplicate_inputs() {
        for count in 0..130 {
            for pattern in 0..4 {
                let input: Vec<usize> = (0..count)
                    .map(|i| match pattern {
                        0 => i,
                        1 => count - i,
                        2 => i % 7,
                        _ => (i * 31 + 19) % 127,
                    })
                    .collect();
                let mut expected = input.clone();
                expected.sort();
                let actual = RefCell::new(input);
                sort_by(
                    count,
                    |a, b| actual.borrow()[a].cmp(&actual.borrow()[b]),
                    |a, b| actual.borrow_mut().swap(a, b),
                );
                assert_eq!(actual.into_inner(), expected);
            }
        }
    }

    #[test]
    fn comparator_context_and_payload_identity_survive_sorting() {
        let rows = RefCell::new([(3, 10), (1, 20), (3, 30), (2, 40)]);
        let direction = -1i32;
        sort_by(
            4,
            |a, b| (rows.borrow()[a].0 * direction).cmp(&(rows.borrow()[b].0 * direction)),
            |a, b| rows.borrow_mut().swap(a, b),
        );
        let rows = rows.into_inner();
        assert_eq!(rows.map(|row| row.0), [3, 3, 2, 1]);
        assert!(rows.contains(&(3, 10)) && rows.contains(&(3, 30)));
        assert_eq!(rows[2], (2, 40));
        assert_eq!(rows[3], (1, 20));
    }
}
