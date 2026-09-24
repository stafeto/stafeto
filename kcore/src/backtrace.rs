// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Walking frame records on the kernel stacks. A frame record is two
//! words: the caller's frame pointer and a return address.

use core::ops::Range;

/// True when a frame record at `fp` lies inside the stack `[lo, hi)`.
pub fn record_in_stack(fp: usize, lo: usize, hi: usize) -> bool {
    fp.is_multiple_of(16) && fp >= lo && fp.checked_add(16).is_some_and(|end| end <= hi)
}

/// True when the walk may follow `fp` to `next`: callers' frames sit at
/// higher addresses, so a chain that does not grow is corrupt or ends.
pub fn continues(fp: usize, next: usize) -> bool {
    next > fp
}

/// Walks the frame records from `fp` and calls `visit` with each return
/// address, at most `max` times. `stacks` lists where records may lie: an
/// exception stack before the stack its entry interrupted. The walk moves up
/// its stack and may leave it only for a stack listed later, because
/// exception entry on a separate stack records a frame pointer into the
/// interrupted one. It stops at a zero return address or at a record
/// outside these rules. `read` returns the word at an address; the walk
/// reads only words of records inside `stacks`.
pub fn walk(
    fp: usize,
    stacks: &[Range<usize>],
    max: usize,
    read: impl Fn(usize) -> usize,
    mut visit: impl FnMut(usize),
) {
    let stack_of = |fp: usize| {
        stacks
            .iter()
            .position(|s| record_in_stack(fp, s.start, s.end))
    };
    let Some(mut at) = stack_of(fp) else {
        return;
    };
    let mut fp = fp;
    for _ in 0..max {
        let (next, lr) = (read(fp), read(fp + 8));
        if lr == 0 {
            break;
        }
        visit(lr);
        match stack_of(next) {
            Some(s) if s == at && continues(fp, next) => {}
            Some(s) if s > at => at = s,
            _ => break,
        }
        fp = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LO: usize = 0x1000;
    const HI: usize = 0x2000;

    #[test]
    fn record_inside_the_stack_is_valid() {
        assert!(record_in_stack(0x1000, LO, HI));
        assert!(record_in_stack(0x1FF0, LO, HI));
    }

    #[test]
    fn record_must_be_16_byte_aligned() {
        assert!(!record_in_stack(0x1008, LO, HI));
    }

    #[test]
    fn record_must_fit_below_the_top() {
        assert!(!record_in_stack(0x2000, LO, HI));
    }

    #[test]
    fn record_below_the_stack_is_invalid() {
        assert!(!record_in_stack(0x0FF0, LO, HI));
        assert!(!record_in_stack(0, LO, HI));
    }

    #[test]
    fn address_overflow_is_invalid() {
        assert!(!record_in_stack(usize::MAX - 15, 0, usize::MAX));
    }

    #[test]
    fn chain_must_move_up_the_stack() {
        assert!(continues(0x1100, 0x1200));
        assert!(!continues(0x1100, 0x1100));
        assert!(!continues(0x1100, 0x1000));
        assert!(!continues(0x1100, 0));
    }

    /// An exception stack and the kernel stack it interrupted, in walk order.
    const EXCEPTION: Range<usize> = 0x8000..0x9000;
    const KERNEL: Range<usize> = LO..HI;

    /// Walks from `fp` over memory holding the given frame records
    /// `(address, caller's fp, return address)`; other words read as zero.
    fn walk_records(
        fp: usize,
        stacks: &[Range<usize>],
        max: usize,
        records: &[(usize, usize, usize)],
    ) -> Vec<usize> {
        let read = |a: usize| {
            records
                .iter()
                .find_map(|&(at, next, lr)| match a {
                    _ if a == at => Some(next),
                    _ if a == at + 8 => Some(lr),
                    _ => None,
                })
                .unwrap_or(0)
        };
        let mut seen = Vec::new();
        walk(fp, stacks, max, read, |lr| seen.push(lr));
        seen
    }

    #[test]
    fn walk_follows_the_chain_up_one_stack() {
        let records = [
            (0x1100, 0x1200, 0xA),
            (0x1200, 0x1300, 0xB),
            (0x1300, 0, 0xC),
        ];
        let seen = walk_records(0x1100, &[KERNEL], 32, &records);
        assert_eq!(seen, [0xA, 0xB, 0xC]);
    }

    #[test]
    fn walk_stops_at_a_zero_return_address() {
        let records = [(0x1100, 0x1200, 0), (0x1200, 0, 0xB)];
        assert!(walk_records(0x1100, &[KERNEL], 32, &records).is_empty());
    }

    #[test]
    fn walk_stops_when_the_chain_turns_down_its_stack() {
        let records = [(0x1100, 0x1200, 0xA), (0x1200, 0x1100, 0xB)];
        let seen = walk_records(0x1100, &[KERNEL], 32, &records);
        assert_eq!(seen, [0xA, 0xB]);
    }

    #[test]
    fn walk_goes_from_the_exception_stack_to_the_interrupted_one() {
        let records = [
            (0x8F00, 0x8F80, 0xA),
            // The exception entry's record: the interrupted fp is lower.
            (0x8F80, 0x1100, 0xE),
            (0x1100, 0x1200, 0xB),
            (0x1200, 0, 0xC),
        ];
        let seen = walk_records(0x8F00, &[EXCEPTION, KERNEL], 32, &records);
        assert_eq!(seen, [0xA, 0xE, 0xB, 0xC]);
    }

    #[test]
    fn walk_never_goes_back_to_an_earlier_stack() {
        let records = [(0x1100, 0x8F00, 0xA), (0x8F00, 0x8F80, 0xB)];
        let seen = walk_records(0x1100, &[EXCEPTION, KERNEL], 32, &records);
        assert_eq!(seen, [0xA]);
    }

    #[test]
    fn walk_from_outside_every_stack_prints_nothing() {
        let records = [(0x3000, 0x3100, 0xA)];
        assert!(walk_records(0x3000, &[EXCEPTION, KERNEL], 32, &records).is_empty());
    }

    #[test]
    fn walk_stops_after_max_frames() {
        let records: Vec<_> = (0..8)
            .map(|i| (0x1100 + i * 0x10, 0x1110 + i * 0x10, 0xA + i))
            .collect();
        let seen = walk_records(0x1100, &[KERNEL], 3, &records);
        assert_eq!(seen, [0xA, 0xB, 0xC]);
    }
}
