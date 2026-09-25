// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Threads (spec 4, 8): scheduling parameters, whose values abi fixes, and
//! the checks on where a new thread starts and where its message buffer
//! goes.

use crate::frames::PAGE_SIZE;
use crate::layout::USER_END;
use abi::Error;
pub use abi::{PRIORITY_LEVELS, Policy};

/// Checks the start of a program's thread: `entry` is an instruction in the
/// lower half, `stack` a 16-byte-aligned stack pointer no higher than its
/// top, and `priority` a level other than 0, which goes to no thread.
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

/// Checks where a thread's message buffer goes (report 4.1): a whole page
/// in the lower half, other than page 0, which stays unmapped so that a
/// null pointer faults.
pub fn check_buffer(va: u64) -> Result<(), Error> {
    if va != 0 && va.is_multiple_of(PAGE_SIZE) && va < USER_END as u64 {
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

    #[test]
    fn message_buffer_is_a_page_in_the_lower_half() {
        for va in [PAGE_SIZE, 0x100_0000, TOP - PAGE_SIZE] {
            assert_eq!(check_buffer(va), Ok(()));
        }
        for va in [0, 8, 0x100_0800, TOP, TOP + PAGE_SIZE, !(PAGE_SIZE - 1)] {
            assert_eq!(check_buffer(va), Err(Error::InvalidArgs));
        }
    }
}
