// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rules of the kernel's console port (spec 3.2, 9): which device
//! windows take the port from the kernel, and how long the kernel waits
//! for the port's transmitter before it powers off (spec 16.1).

use crate::PAGE_SIZE;
use crate::bootinfo::Region;

/// FR, the flag register of the PL011, at offset 0x018: BUSY (bit 3) while
/// the transmitter sends a character, from the FIFO or the shift register;
/// TXFF (bit 5) while the transmit FIFO is full [R12, G36].
pub const FR_BUSY: u32 = 1 << 3;
pub const FR_TXFF: u32 = 1 << 5;

/// Whether the device window of the `pages` pages from `base` covers a
/// page of the console port `port` (spec 3.2, 9): such a window takes the
/// port from the kernel while it lives. A port of no bytes has no page.
pub fn covers(port: Region, base: u64, pages: u64) -> bool {
    let first = port.base & !(PAGE_SIZE - 1);
    let last = port.end().next_multiple_of(PAGE_SIZE);
    let end = base.saturating_add(pages.saturating_mul(PAGE_SIZE));
    port.size > 0 && first < end && base < last
}

/// Waits for the transmitter of the PL011 to go idle (spec 16.1): reads
/// the flag register through `fr` until BUSY is clear, or until
/// `expired` says the time is up, which it asks after each read that
/// finds BUSY. True when the transmitter went idle.
pub fn drain(mut fr: impl FnMut() -> u32, mut expired: impl FnMut() -> bool) -> bool {
    loop {
        if fr() & FR_BUSY == 0 {
            return true;
        }
        if expired() {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PL011 of QEMU `virt`.
    const PORT: Region = Region {
        base: 0x0900_0000,
        size: 0x1000,
    };

    #[test]
    fn a_window_over_the_console_page_takes_the_port() {
        assert!(covers(PORT, 0x0900_0000, 1));
        assert!(covers(PORT, 0x08FF_F000, 2));
        assert!(covers(PORT, 0x08F0_0000, 0x200));
        let small = Region {
            base: 0x0900_0800,
            size: 0x20,
        };
        assert!(covers(small, 0x08FF_F000, 2));
    }

    #[test]
    fn a_window_beside_the_console_page_leaves_it() {
        assert!(!covers(PORT, 0x08FF_F000, 1));
        assert!(!covers(PORT, 0x0900_1000, 1));
        assert!(!covers(PORT, 0x0901_0000, 16));
        let none = Region { base: 0, size: 0 };
        assert!(!covers(none, 0, 16));
    }

    #[test]
    fn drain_waits_for_busy_to_clear() {
        let mut polls = 0;
        let idle = drain(
            || {
                polls += 1;
                if polls <= 3 { FR_BUSY } else { 0 }
            },
            || false,
        );
        assert!(idle);
        assert!(polls >= 4, "{polls} polls");
    }

    #[test]
    fn drain_stops_at_its_deadline() {
        let (mut polls, mut asked) = (0, 0);
        let idle = drain(
            || {
                polls += 1;
                assert!(polls < 1000, "drain polls past its deadline");
                FR_BUSY | FR_TXFF
            },
            || {
                asked += 1;
                asked == 5
            },
        );
        assert!(!idle);
        assert_eq!((polls, asked), (5, 5));
    }
}
