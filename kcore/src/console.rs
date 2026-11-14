// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rules of the kernel's console port (spec 3.2, 9): which device
//! windows take the port from the kernel, and how long the kernel waits
//! for the port's transmitter before it powers off (spec 16.1).

use crate::PAGE_SIZE;
use kboot::bootinfo::Region;

/// FR, the flag register of the PL011, at offset 0x018: BUSY (bit 3) while
/// the transmitter sends a character, from the FIFO or the shift register;
/// TXFF (bit 5) while the transmit FIFO is full [R12, G36].
pub const FR_BUSY: u32 = 1 << 3;
pub const FR_TXFF: u32 = 1 << 5;

/// LSR of the 16550, at register 5: THRE (bit 5) when the transmit FIFO or
/// holding register has room, TEMT (bit 6) when FIFO and shift register are
/// both empty.
pub const LSR_THRE: u32 = 1 << 5;
pub const LSR_TEMT: u32 = 1 << 6;
/// The register number of LSR, THR, IER and LCR of a 16550, before the
/// register shift.
pub const REG_THR: usize = 0;
pub const REG_IER: usize = 1;
pub const REG_LCR: usize = 3;
pub const REG_LSR: usize = 5;
/// LCR for 8 data bits, 1 stop bit, no parity, DLAB clear.
pub const LCR_8N1: u32 = 0x03;

/// Waits for room in the transmitter of a 16550 (spec 3.2): reads LSR
/// through `lsr` until THRE is set, or until `expired` says the time is up,
/// which it asks after each read that finds no room. True when there is room.
pub fn wait_room(mut lsr: impl FnMut() -> u32, mut expired: impl FnMut() -> bool) -> bool {
    loop {
        if lsr() & LSR_THRE != 0 {
            return true;
        }
        if expired() {
            return false;
        }
    }
}

/// Waits for the transmitter of a 16550 to go idle (TEMT), as `drain` does
/// for the PL011.
pub fn drain_16550(mut lsr: impl FnMut() -> u32, mut expired: impl FnMut() -> bool) -> bool {
    loop {
        if lsr() & LSR_TEMT != 0 {
            return true;
        }
        if expired() {
            return false;
        }
    }
}

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
    fn a_full_transmitter_is_waited_for_up_to_the_limit() {
        let mut busy = 3;
        assert!(wait_room(
            || {
                busy -= 1;
                if busy > 0 { 0 } else { LSR_THRE }
            },
            || false
        ));
        let mut asked = 0;
        assert!(!wait_room(
            || 0,
            || {
                asked += 1;
                asked == 5
            }
        ));
        assert_eq!(asked, 5);
        assert!(drain_16550(|| LSR_THRE | LSR_TEMT, || false));
        assert!(!drain_16550(|| LSR_THRE, || true));
    }

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
