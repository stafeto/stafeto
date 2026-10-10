// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The registers of the PL011 the driver uses (spec 13.5), 32 bits each,
//! by their offsets in its page, and their bits: the PL011 TRM [R12], the
//! model of QEMU (hw/char/pl011.c) and the header of Linux
//! (include/linux/amba/serial.h) agree on them.

/// Data: a byte to send, or a byte that came with its errors in bits 11:8.
pub const DR: usize = 0x000;
/// Flags.
pub const FR: usize = 0x018;
/// Line control.
pub const LCR_H: usize = 0x02C;
/// Control.
pub const CR: usize = 0x030;
/// The levels of the FIFOs that raise the interrupts.
pub const IFLS: usize = 0x034;
/// The mask of the interrupts: a bit set lets its interrupt out.
pub const IMSC: usize = 0x038;
/// The interrupts that are raised and let out.
pub const MIS: usize = 0x040;
/// A bit written clears its interrupt.
pub const ICR: usize = 0x044;

/// FR: the transmitter sends; the receive FIFO is empty; the transmit
/// FIFO is full; the transmit FIFO is empty.
pub const FR_BUSY: u32 = 1 << 3;
pub const FR_RXFE: u32 = 1 << 4;
pub const FR_TXFF: u32 = 1 << 5;
pub const FR_TXFE: u32 = 1 << 7;

/// LCR_H: the FIFOs on; words of 8 bits.
pub const LCR_H_FEN: u32 = 1 << 4;
pub const LCR_H_WLEN_8: u32 = 0x60;

/// CR: the UART, its transmitter and its receiver on.
pub const CR_UARTEN: u32 = 1 << 0;
pub const CR_TXE: u32 = 1 << 8;
pub const CR_RXE: u32 = 1 << 9;
/// What the driver writes to CR once the rest is set.
pub const CR_ON: u32 = CR_UARTEN | CR_TXE | CR_RXE;

/// IFLS: receive and transmit at half of their FIFOs (RX4_8 | TX4_8), the
/// value QEMU and a PL011 have after reset.
pub const IFLS_HALF: u32 = 0x12;

/// The interrupts, the same bit in IMSC, MIS and ICR: receive (the FIFO
/// at its level), transmit (the FIFO at its level), receive timeout (bytes
/// wait and the line is quiet), and the errors: framing, parity, break,
/// overrun.
pub const RX: u32 = 1 << 4;
pub const TX: u32 = 1 << 5;
pub const RT: u32 = 1 << 6;
pub const FE: u32 = 1 << 7;
pub const PE: u32 = 1 << 8;
pub const BE: u32 = 1 << 9;
pub const OE: u32 = 1 << 10;
/// The interrupts of input, of errors, and all eleven of the PL011.
pub const INPUT: u32 = RX | RT;
pub const ERRORS: u32 = FE | PE | BE | OE;
pub const ALL: u32 = 0x7FF;

/// DR: the errors of a byte that came, framing to overrun in bits 8 to 11.
pub const DR_ERRORS: u32 = 0xF00;

/// The least depth of the FIFOs of a PL011 (QEMU's; 32 from r1p5 on).
pub const FIFO_DEPTH: usize = 16;

/// FIFO empty alone does not account for the character in the shift register.
pub fn drained(flags: u32) -> bool {
    flags & (FR_TXFE | FR_BUSY) == FR_TXFE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_drain_waits_for_fifo_and_final_stop_bits() {
        assert!(!drained(0));
        assert!(!drained(FR_BUSY));
        assert!(!drained(FR_TXFE | FR_BUSY));
        assert!(drained(FR_TXFE));
        assert!(drained(FR_TXFE | FR_RXFE));
    }
}
