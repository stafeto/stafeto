// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The windows of one process on one shared channel, as logic with no kernel
//! call in it. A process has up to `WINDOWS_MAX` windows, numbered from 0 (the
//! lowest free number is the next window's). The service holds a copy of the
//! process's channel for each window, and the copy's label says which window a
//! notification is for: the label is made of a tag, a sequence number that
//! grows with every copy the library hands out (so the end of a copy of a
//! closed window is never taken for the end of the copy of a window that took
//! its number later) and the window's number.

use crate::errno::{EAGAIN, EINVAL};
use crate::layout::{A8, BITS};

/// The most windows a process has.
pub const WINDOWS_MAX: usize = 8;

/// The tag in the high bits of a label.
const TAG: u64 = 0x5749;
const SEQUENCE_MAX: u32 = (1 << 28) - 1;

/// The label of the copy number `sequence` hands the service for window
/// `slot`.
pub const fn label(sequence: u32, slot: usize) -> u64 {
    assert!(slot < WINDOWS_MAX);
    TAG << 32 | ((sequence & SEQUENCE_MAX) as u64) << 4 | slot as u64
}

/// The slot number of the manager's label: no window has it (`slot_of` gives
/// None for it), so the copy of the channel that carries the manager's ring
/// never mixes with a window's.
pub const MANAGER_SLOT: usize = 15;

/// The bit of the mask of `stafeto_windows_wait` that says the manager's ring
/// holds events (`STAFETO_MANAGER_EVENTS`). It is above the windows' bits.
pub const MANAGER_BIT: u32 = 1 << 30;
const _: () = assert!(MANAGER_BIT > 1 << (WINDOWS_MAX - 1) && MANAGER_BIT < 1 << 31);

/// The label of the copy number `sequence` hands the service for the manager's
/// ring.
pub const fn manager_label(sequence: u32) -> u64 {
    TAG << 32 | ((sequence & SEQUENCE_MAX) as u64) << 4 | MANAGER_SLOT as u64
}

/// Whether `label` is a label of the manager's ring.
pub const fn is_manager_label(label: u64) -> bool {
    label >> 32 == TAG && (label & 0xf) as usize == MANAGER_SLOT
}

/// The mask a wait across the windows returns when the manager's ring has
/// something (`pending`) or the service that holds the subscription went
/// (`gone`): the windows' mask with `MANAGER_BIT` added.
pub const fn with_manager(mask: u32, pending: bool, gone: bool) -> u32 {
    if pending || gone {
        mask | MANAGER_BIT
    } else {
        mask
    }
}

/// The window a label names; None for a label that is none of the library's.
pub const fn slot_of(label: u64) -> Option<usize> {
    let slot = (label & 0xf) as usize;
    if label >> 32 != TAG || slot >= WINDOWS_MAX {
        None
    } else {
        Some(slot)
    }
}

/// The lowest number of a window not in `used` (bit k: window k is made or
/// being made); EAGAIN when all of them are.
pub const fn free_slot(used: u32) -> Result<usize, i32> {
    let mut slot = 0;
    while slot < WINDOWS_MAX {
        if used & (1 << slot) == 0 {
            return Ok(slot);
        }
        slot += 1;
    }
    Err(EAGAIN)
}

/// The most a window's size can be (the service's capacity, which ATTACH of
/// buffers of `bytes` each with lines of `stride` bytes gives it): the width a
/// line holds and the lines a buffer holds.
pub const fn capacity(format: u32, stride: u32, bytes: u64) -> (u32, u32) {
    let width = if format == A8 { stride } else { stride / 4 };
    let lines = if stride == 0 {
        0
    } else {
        bytes / stride as u64
    };
    let lines = if lines > u32::MAX as u64 {
        u32::MAX
    } else {
        lines as u32
    };
    (width, lines)
}

/// Whether a size of `w` by `h` is one the capacity `cap` holds: EINVAL for an
/// empty size or one past the capacity.
pub const fn resize_ok(w: u32, h: u32, cap: (u32, u32)) -> Result<(), i32> {
    if w == 0 || h == 0 || w > cap.0 || h > cap.1 {
        Err(EINVAL)
    } else {
        Ok(())
    }
}

/// What a wait on the window `slot` of a window that went away reports in
/// `stafeto_windows_wait` (`STAFETO_WINDOW_GONE`).
pub const GONE: u32 = 1 << 4;
const _: () = assert!(GONE & BITS == 0);

/// The window mask of `stafeto_windows_wait` and its `bits` array: window k
/// has `bits[k]` (a window that went away has `GONE`); the mask has bit k for
/// each window with something. `windows` gives, for each number, None for a
/// window that is not open, or its pending bits and whether it is gone.
pub fn report(
    windows: impl Iterator<Item = Option<(u32, bool)>>,
    bits: &mut [u32; WINDOWS_MAX],
) -> u32 {
    let mut mask = 0;
    *bits = [0; WINDOWS_MAX];
    for (slot, window) in windows.take(WINDOWS_MAX).enumerate() {
        let Some((pending, gone)) = window else {
            continue;
        };
        let value = pending | if gone { GONE } else { 0 };
        if value != 0 {
            bits[slot] = value;
            mask |= 1 << slot;
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_names_its_window_and_nothing_else() {
        for slot in 0..WINDOWS_MAX {
            for sequence in [0, 1, 77, SEQUENCE_MAX] {
                assert_eq!(slot_of(label(sequence, slot)), Some(slot));
            }
        }
        // The labels of two windows differ in every sequence, and one window's
        // labels differ from try to try.
        assert_ne!(label(5, 0), label(5, 1));
        assert_ne!(label(5, 3), label(6, 3));
        assert_eq!(slot_of(0), None);
        assert_eq!(slot_of(0x5749_0000_0000 | 8), None);
        assert_eq!(slot_of(0x5748_0000_0000), None);
        assert_eq!(slot_of(1 << 63 | label(0, 1)), None);
    }

    #[test]
    fn the_managers_label_names_no_window_and_no_window_label_is_the_managers() {
        for sequence in [0, 1, 77, SEQUENCE_MAX] {
            let managers = manager_label(sequence);
            assert!(is_manager_label(managers));
            assert_eq!(slot_of(managers), None);
            for slot in 0..WINDOWS_MAX {
                assert!(!is_manager_label(label(sequence, slot)));
            }
        }
        assert!(!is_manager_label(0));
        assert!(!is_manager_label(0x5748_0000_000f));
        assert_ne!(manager_label(1), manager_label(2));
    }

    #[test]
    fn the_managers_bit_joins_the_mask_and_stays_positive() {
        assert_eq!(with_manager(0b101, false, false), 0b101);
        assert_eq!(with_manager(0b101, true, false), 0b101 | MANAGER_BIT);
        assert_eq!(with_manager(0, false, true), MANAGER_BIT);
        assert!(MANAGER_BIT as i32 > 0);
        assert_eq!(MANAGER_BIT & 0xff, 0);
    }

    #[test]
    fn the_next_window_has_the_lowest_free_number() {
        assert_eq!(free_slot(0), Ok(0));
        assert_eq!(free_slot(0b1), Ok(1));
        assert_eq!(free_slot(0b1011), Ok(2));
        assert_eq!(free_slot(0b0111_1111), Ok(7));
    }

    #[test]
    fn the_ninth_window_is_refused() {
        assert_eq!(free_slot(0xff), Err(EAGAIN));
        assert_eq!(free_slot(0xffff_ffff), Err(EAGAIN));
        // A number outside the table is no room either.
        assert_eq!(free_slot(0xff | 1 << 8), Err(EAGAIN));
    }

    /// The capacity is what the service computes at ATTACH: the width a stride
    /// holds (a mask: the stride) and the lines the smallest buffer holds.
    #[test]
    fn the_capacity_is_the_stride_and_the_lines_a_buffer_holds() {
        use crate::layout::XRGB8888;
        // 50 by 50 points: 200 bytes a line, 3 pages hold 61 lines.
        assert_eq!(capacity(XRGB8888, 200, 3 * 4096), (50, 61));
        // The whole screen: 640 by 400 in 250 pages.
        assert_eq!(capacity(XRGB8888, 2560, 250 * 4096), (640, 400));
        assert_eq!(capacity(A8, 64, 4096), (64, 64));
        assert_eq!(capacity(XRGB8888, 0, 4096), (0, 0));
    }

    #[test]
    fn a_size_past_the_capacity_or_empty_is_refused() {
        let cap = (50, 61);
        assert_eq!(resize_ok(50, 61, cap), Ok(()));
        assert_eq!(resize_ok(1, 1, cap), Ok(()));
        assert_eq!(resize_ok(51, 61, cap), Err(EINVAL));
        assert_eq!(resize_ok(50, 62, cap), Err(EINVAL));
        assert_eq!(resize_ok(0, 10, cap), Err(EINVAL));
        assert_eq!(resize_ok(10, 0, cap), Err(EINVAL));
    }

    #[test]
    fn bits_go_to_the_window_they_came_for() {
        let mut bits = [9; WINDOWS_MAX];
        let windows = [
            Some((0, false)),
            Some((0b0001, false)),
            None,
            Some((0, false)),
            Some((0b1000, true)),
            Some((0, true)),
        ];
        let mask = report(windows.into_iter(), &mut bits);
        assert_eq!(mask, 0b11_0010);
        assert_eq!(bits, [0, 1, 0, 0, 8 | GONE, GONE, 0, 0]);
        assert_eq!(report([Some((0, false))].into_iter(), &mut bits), 0);
        assert_eq!(bits, [0; WINDOWS_MAX]);
    }
}
