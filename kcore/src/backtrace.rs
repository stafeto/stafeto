// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Checks for walking frame records on a stack. A frame record is two
//! words: the caller's frame pointer and a return address.

/// True when a frame record at `fp` lies inside the stack `[lo, hi)`.
pub fn record_in_stack(fp: usize, lo: usize, hi: usize) -> bool {
    fp.is_multiple_of(16) && fp >= lo && fp.checked_add(16).is_some_and(|end| end <= hi)
}

/// True when the walk may follow `fp` to `next`: callers' frames sit at
/// higher addresses, so a chain that does not grow is corrupt or ends.
pub fn continues(fp: usize, next: usize) -> bool {
    next > fp
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
}
