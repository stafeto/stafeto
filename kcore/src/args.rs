// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Checks on the values system calls take from registers (spec 11): each
//! turns a raw register into the value a call works with, or gives the
//! error the spec names for it. The data structures of kcore take values
//! already checked here.

use crate::PAGE_SIZE;
use crate::handles::MAX_HANDLES;
use crate::layout::USER_END;
use abi::{CLIENT_GONE, Error, PRIORITY_LEVELS, Policy, Rights};

/// A priority from a register, as `thread_create` and
/// `thread_set_priority` take it: 1-63. INVALID_ARGS for 0, 64 and up, and
/// bits set above the byte.
pub fn priority_arg(raw: u64) -> Result<u8, Error> {
    match u8::try_from(raw) {
        Ok(p) if (1..PRIORITY_LEVELS).contains(&p) => Ok(p),
        _ => Err(Error::InvalidArgs),
    }
}

/// A policy from a register: INVALID_ARGS for a value abi::Policy lacks.
pub fn policy_arg(raw: u64) -> Result<Policy, Error> {
    Policy::from_raw(raw).ok_or(Error::InvalidArgs)
}

/// The priority of a source's slot (spec 6.5) from a register: in
/// `process_create` 0 exactly when there is no exit channel, in
/// `handle_duplicate` exactly when there is no new label (`channel` false),
/// otherwise a priority. INVALID_ARGS for anything else.
pub fn notify_priority_arg(raw: u64, channel: bool) -> Result<u8, Error> {
    match (channel, raw) {
        (false, 0) => Ok(0),
        (true, _) => priority_arg(raw),
        (false, _) => Err(Error::InvalidArgs),
    }
}

/// ACCESS_DENIED when `priority` is above any of `ceilings` (spec 8):
/// for `thread_create` and `thread_set_priority` the ceilings of the
/// thread's process and of the caller's, for the ceiling of a child and a
/// notification priority the caller's. A priority is authority too: a
/// handle to another process's thread does not lift the thread above the
/// caller's own ceiling.
pub fn under_ceilings(priority: u8, ceilings: &[u8]) -> Result<(), Error> {
    if ceilings.iter().all(|&c| priority <= c) {
        Ok(())
    } else {
        Err(Error::AccessDenied)
    }
}

/// The rights of a copy from a register (spec 5.2, 11): INVALID_ARGS for
/// a bit that is no right.
pub fn rights_arg(raw: u64) -> Result<Rights, Error> {
    match u32::try_from(raw) {
        Ok(bits) if Rights::ALL.contains(Rights(bits)) => Ok(Rights(bits)),
        _ => Err(Error::InvalidArgs),
    }
}

/// The bits of `notify` from a register: INVALID_ARGS with bit 63,
/// CLIENT_GONE, in any slot: only the kernel posts it, into the slot of a
/// session whose last copy went (spec 5.3), so that no client fakes the
/// end of another; no bits at all are fine.
pub fn bits_arg(raw: u64) -> Result<u64, Error> {
    if raw & CLIENT_GONE == 0 {
        Ok(raw)
    } else {
        Err(Error::InvalidArgs)
    }
}

/// The flags of `receive` (spec 6.1, 11): true when the call waits, false
/// for abi::NO_WAIT; INVALID_ARGS for any other bit.
pub fn wait_arg(raw: u64) -> Result<bool, Error> {
    match raw {
        0 => Ok(true),
        abi::NO_WAIT => Ok(false),
        _ => Err(Error::InvalidArgs),
    }
}

/// The memory quota `process_create` takes, in bytes: whole pages, at
/// least one. INVALID_ARGS otherwise.
pub fn quota_arg(raw: u64) -> Result<u64, Error> {
    if raw > 0 && raw.is_multiple_of(PAGE_SIZE) {
        Ok(raw)
    } else {
        Err(Error::InvalidArgs)
    }
}

/// The handle limit `process_create` takes: 1 to MAX_HANDLES. INVALID_ARGS
/// otherwise.
pub fn handle_limit_arg(raw: u64) -> Result<u32, Error> {
    match u32::try_from(raw) {
        Ok(limit) if (1..=MAX_HANDLES).contains(&limit) => Ok(limit),
        _ => Err(Error::InvalidArgs),
    }
}

/// A reserved register that must be 0: INVALID_ARGS otherwise. `object_info`
/// takes x2 this way, kept clear for a use the spec has not named yet.
pub fn reserved_arg(raw: u64) -> Result<(), Error> {
    if raw == 0 {
        Ok(())
    } else {
        Err(Error::InvalidArgs)
    }
}

/// The length of an inline byte buffer packed into x2-x9 (spec 11), as
/// `debug_write` takes it in x1: at most abi::INLINE_MAX. INVALID_ARGS
/// otherwise.
pub fn inline_len_arg(raw: u64) -> Result<usize, Error> {
    match usize::try_from(raw) {
        Ok(len) if len <= abi::INLINE_MAX => Ok(len),
        _ => Err(Error::InvalidArgs),
    }
}

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

/// Checks where a thread's message buffer goes (spec 11): a whole page
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
    fn priority_arguments() {
        assert_eq!(priority_arg(1), Ok(1));
        assert_eq!(priority_arg(63), Ok(63));
        for raw in [0, 64, 255, 1 << 8 | 10, 1 << 32 | 10, u64::MAX] {
            assert_eq!(priority_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
        assert_eq!(policy_arg(0), Ok(Policy::RoundRobin));
        assert_eq!(policy_arg(1), Ok(Policy::Fifo));
        for raw in [2, 1 << 32, u64::MAX] {
            assert_eq!(policy_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
    }

    #[test]
    fn priority_ceilings() {
        // thread_create and thread_set_priority: the thread's process and
        // the caller's, whichever is lower.
        assert_eq!(under_ceilings(40, &[40, 63]), Ok(()));
        assert_eq!(under_ceilings(41, &[40, 63]), Err(Error::AccessDenied));
        assert_eq!(under_ceilings(41, &[63, 40]), Err(Error::AccessDenied));
        assert_eq!(under_ceilings(1, &[1, 1]), Ok(()));
        // process_create: a child's ceiling is at most its parent's.
        assert_eq!(under_ceilings(30, &[30]), Ok(()));
        assert_eq!(under_ceilings(31, &[30]), Err(Error::AccessDenied));
        // The notification priority: 0 without an exit channel, and only
        // then; with one, a priority at most the caller's ceiling.
        assert_eq!(notify_priority_arg(0, false), Ok(0));
        assert_eq!(notify_priority_arg(5, false), Err(Error::InvalidArgs));
        assert_eq!(notify_priority_arg(0, true), Err(Error::InvalidArgs));
        assert_eq!(notify_priority_arg(64, true), Err(Error::InvalidArgs));
        assert_eq!(notify_priority_arg(5, true), Ok(5));
        assert_eq!(under_ceilings(5, &[4]), Err(Error::AccessDenied));
    }

    #[test]
    fn rights_arg_takes_the_known_rights_only() {
        assert_eq!(rights_arg(0), Ok(Rights::NONE));
        assert_eq!(rights_arg(Rights::ALL.0.into()), Ok(Rights::ALL));
        assert_eq!(rights_arg(0b1001), Ok(Rights::DUPLICATE | Rights::NOTIFY));
        for raw in [1 << 12, 1 << 31, 1 << 32, u64::MAX] {
            assert_eq!(rights_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
    }

    #[test]
    fn bit_63_is_refused() {
        assert_eq!(CLIENT_GONE, 1 << 63);
        for raw in [CLIENT_GONE, CLIENT_GONE | 1, u64::MAX] {
            assert_eq!(bits_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
        for raw in [0, 1, !CLIENT_GONE] {
            assert_eq!(bits_arg(raw), Ok(raw), "{raw:#x}");
        }
    }

    #[test]
    fn receive_waits_unless_told_not_to() {
        assert_eq!(wait_arg(0), Ok(true));
        assert_eq!(wait_arg(abi::NO_WAIT), Ok(false));
        for raw in [1, abi::NO_WAIT | 1, 1 << 17, 1 << 63, u64::MAX] {
            assert_eq!(wait_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
    }

    #[test]
    fn process_create_values() {
        for quota in [PAGE_SIZE, 3 * PAGE_SIZE, 1 << 40] {
            assert_eq!(quota_arg(quota), Ok(quota));
        }
        for quota in [0, 1, PAGE_SIZE - 1, PAGE_SIZE + 8, u64::MAX] {
            assert_eq!(quota_arg(quota), Err(Error::InvalidArgs));
        }
        assert_eq!(handle_limit_arg(1), Ok(1));
        assert_eq!(handle_limit_arg(u64::from(MAX_HANDLES)), Ok(MAX_HANDLES));
        for limit in [0, u64::from(MAX_HANDLES) + 1, 1 << 32 | 16, u64::MAX] {
            assert_eq!(handle_limit_arg(limit), Err(Error::InvalidArgs));
        }
    }

    #[test]
    fn a_reserved_register_takes_only_zero() {
        assert_eq!(reserved_arg(0), Ok(()));
        for raw in [1, 1 << 32, u64::MAX] {
            assert_eq!(reserved_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
    }

    #[test]
    fn an_inline_length_stops_at_inline_max() {
        assert_eq!(inline_len_arg(0), Ok(0));
        assert_eq!(inline_len_arg(abi::INLINE_MAX as u64), Ok(abi::INLINE_MAX));
        for raw in [abi::INLINE_MAX as u64 + 1, 1 << 32, u64::MAX] {
            assert_eq!(inline_len_arg(raw), Err(Error::InvalidArgs), "{raw:#x}");
        }
    }

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
