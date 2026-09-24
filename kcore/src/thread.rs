// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Threads (spec 4, 8): scheduling parameters and the checks on where a
//! new thread starts. The scheduler that uses priority and policy comes in
//! milestone 1.2c; until then they are only stored.

use crate::layout::USER_END;
use abi::Error;

/// Priority levels (spec 8): 0 to 63, higher runs first. Level 0 belongs to
/// the idle thread alone.
pub const PRIORITY_LEVELS: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Round robin with a 4 ms quantum.
    RoundRobin,
    /// First in, first out, no quantum: for real-time threads.
    Fifo,
}

/// Checks the start of a program's thread: `entry` is an instruction in the
/// lower half, `stack` a 16-byte-aligned stack pointer no higher than its
/// top, and `priority` a level other than the idle thread's.
pub fn check_start(entry: u64, stack: u64, priority: u8) -> Result<(), Error> {
    let entry_ok = entry < USER_END as u64 && entry.is_multiple_of(4);
    let stack_ok = stack <= USER_END as u64 && stack.is_multiple_of(16);
    let priority_ok = (1..PRIORITY_LEVELS).contains(&priority);
    if entry_ok && stack_ok && priority_ok {
        Ok(())
    } else {
        Err(Error::InvalidArgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOP: u64 = USER_END as u64;

    #[test]
    fn a_plain_start_is_accepted() {
        assert_eq!(check_start(0x40_0000, 0x80_1000, 30), Ok(()));
    }

    #[test]
    fn starts_at_the_edges_are_accepted() {
        assert_eq!(check_start(TOP - 4, TOP, 1), Ok(()));
        assert_eq!(check_start(0, 0, PRIORITY_LEVELS - 1), Ok(()));
    }

    #[test]
    fn entry_outside_the_lower_half_or_misaligned_is_rejected() {
        assert_eq!(check_start(TOP, 0x80_1000, 30), Err(Error::InvalidArgs));
        assert_eq!(
            check_start(u64::MAX - 3, 0x80_1000, 30),
            Err(Error::InvalidArgs)
        );
        assert_eq!(
            check_start(0x40_0002, 0x80_1000, 30),
            Err(Error::InvalidArgs)
        );
    }

    #[test]
    fn stack_above_the_lower_half_or_misaligned_is_rejected() {
        assert_eq!(
            check_start(0x40_0000, TOP + 16, 30),
            Err(Error::InvalidArgs)
        );
        assert_eq!(
            check_start(0x40_0000, 0x80_0FF8, 30),
            Err(Error::InvalidArgs)
        );
    }

    #[test]
    fn idle_and_out_of_range_priorities_are_rejected() {
        assert_eq!(
            check_start(0x40_0000, 0x80_1000, 0),
            Err(Error::InvalidArgs)
        );
        assert_eq!(
            check_start(0x40_0000, 0x80_1000, PRIORITY_LEVELS),
            Err(Error::InvalidArgs)
        );
    }
}
