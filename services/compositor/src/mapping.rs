// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The mappings of the windows' buffers. The service maps each buffer of an ATTACH with one
//! `mem_map` call from the mapper thread (`rt::mapper`), so a buffer takes one of the
//! kernel's mapping entries however many pages it has, and unmaps it the same way. This
//! module holds what the host tests reach: the budget of the entries, the status an ATTACH
//! gets for a refused mapping, and the choice of the order the mapper thread gets next.

use crate::{BUFFERS, MAX_WINDOWS};
use abi::Error;
use proto_gpu::{BUFFER_BYTES, SCREEN_BYTES};
use proto_wire::Status;

/// The pages the service maps or unmaps at most in one call of its step thread (the frame
/// buffer and the pool): a page costs the kernel about 200 ticks of a mapping and 80 of an
/// unmapping, and a step stays under 16 500 (xtask).
pub const CHUNK: usize = 32;
const PAGE: usize = 4096;

/// The mapping entries the service itself holds: the frame buffer and the pool in pieces of
/// `CHUNK` pages, the cursor's picture, the segments of the image and its stack, and a margin
/// of 11 (the message buffers of the three threads take at most 3 of it).
pub const OWN_MAPPINGS: usize = (BUFFER_BYTES as usize / PAGE).div_ceil(CHUNK)
    + (SCREEN_BYTES as usize / PAGE).div_ceil(CHUNK)
    + 1
    + (3 + 1)
    + MARGIN;
const MARGIN: usize = 11;

// A window's buffers take one entry each: all the windows with all their buffers and the
// service's own fit the kernel's table.
const _: () = assert!(MAX_WINDOWS * BUFFERS + OWN_MAPPINGS <= abi::MAX_MAPPINGS as usize);

/// The status of the ATTACH whose buffer the kernel refused to map: LIMIT_REACHED for the
/// table of the entries, NO_MEMORY for the tables it could not pay, INVALID for the rest.
pub fn attach_status(error: Error) -> Status {
    match error {
        #[cfg(not(feature = "break-compositor-status"))]
        Error::LimitReached => proto_gpu::LIMIT,
        Error::NoMemory => Status::Kernel(Error::NoMemory),
        _ => proto_comp::code(proto_comp::INVALID),
    }
}

/// A job that waits for the mapper thread: the place of the window, the level its client
/// works at, and whether it is a window that went (its buffers are to be unmapped) or the
/// ATTACH in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    pub slot: usize,
    pub level: u8,
    pub dying: bool,
}

/// The order the mapper thread gets next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    /// Unmap a buffer of the dying window at the place.
    Unmap(usize),
    /// Map the next buffer of the ATTACH in progress.
    Attach,
}

/// The next order: none while the thread has one; the unmapping of a window that went before
/// the mapping for an ATTACH (the place and its entries come back first), the highest level
/// first among the windows that went, the lowest place among equals.
pub fn pick(busy: bool, waits: &[Wait]) -> Option<Pick> {
    if busy {
        return None;
    }
    let mut best: Option<Wait> = None;
    for w in waits.iter().filter(|w| w.dying) {
        if best.is_none_or(|b| w.level > b.level) {
            best = Some(*w);
        }
    }
    match best {
        Some(w) => Some(Pick::Unmap(w.slot)),
        None => waits.iter().any(|w| !w.dying).then_some(Pick::Attach),
    }
}

/// The level the thread works at while jobs wait: the highest one among them.
pub fn waiting_level(waits: &[Wait]) -> Option<u8> {
    waits.iter().map(|w| w.level).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(slot: usize, level: u8, dying: bool) -> Wait {
        Wait { slot, level, dying }
    }

    #[test]
    fn a_refused_mapping_has_its_own_status() {
        assert_eq!(attach_status(Error::LimitReached), proto_gpu::LIMIT);
        assert_eq!(
            attach_status(Error::NoMemory),
            Status::Kernel(Error::NoMemory)
        );
        let invalid = proto_comp::code(proto_comp::INVALID);
        for error in [Error::InvalidArgs, Error::AccessDenied, Error::WrongType] {
            assert_eq!(attach_status(error), invalid);
        }
    }

    #[test]
    fn the_budget_holds_the_windows_and_the_service() {
        assert!(MAX_WINDOWS * BUFFERS + OWN_MAPPINGS <= abi::MAX_MAPPINGS as usize);
        // The frame buffer's 8 and the pool's 8, the cursor, the image, the margin.
        assert_eq!(OWN_MAPPINGS, 8 + 8 + 1 + 4 + MARGIN);
    }

    #[test]
    fn a_busy_thread_gets_no_order() {
        assert_eq!(pick(true, &[wait(0, 5, true), wait(1, 5, false)]), None);
        assert_eq!(pick(false, &[]), None);
    }

    #[test]
    fn a_window_that_went_comes_before_the_attach() {
        let waits = [wait(2, 9, false), wait(5, 3, true)];
        assert_eq!(pick(false, &waits), Some(Pick::Unmap(5)));
        assert_eq!(pick(false, &waits[..1]), Some(Pick::Attach));
    }

    #[test]
    fn the_highest_dying_level_goes_first_and_the_lowest_place_among_equals() {
        let waits = [wait(4, 3, true), wait(1, 7, true), wait(2, 7, true)];
        assert_eq!(pick(false, &waits), Some(Pick::Unmap(1)));
    }

    #[test]
    fn the_level_is_the_highest_waiting_one() {
        assert_eq!(waiting_level(&[]), None);
        let waits = [wait(0, 4, true), wait(1, 20, false), wait(2, 9, true)];
        assert_eq!(waiting_level(&waits), Some(20));
    }
}
