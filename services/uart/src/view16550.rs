// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A 16550 shown to the driver as a PL011 (spec 13.5): the flags, the data
//! register and the masked interrupts the driver reads are made up from LSR,
//! so that the logic of input, output and the log is one for both. The
//! console of EC2 is a 16550 with byte registers one apart; it is polled, no
//! interrupt is bound, and its FIFOs are the firmware's.

use crate::regs::{DR, FR, FR_BUSY, FR_RXFE, FR_TXFE, FR_TXFF, IMSC, LCR_H, MIS, RT, RX, TX};
use core::cell::Cell;

/// The kind byte of the arguments for a 16550 that is polled; the shift and
/// the width of its registers follow it.
pub const KIND_16550: u8 = 1;
/// The period of the poll, in ns.
pub const POLL_NS: u64 = 10_000_000;

/// Whether the console of the kind byte `kind` is polled. A deliberate break
/// (feature `break-uart-poll`) says no: the driver then has neither an
/// interrupt nor a timer for the port, and the dialog of the shell fails.
pub const fn polls(kind: u8) -> bool {
    kind == KIND_16550 && !cfg!(feature = "break-uart-poll")
}

/// The arguments of the driver after its window's base: the kind byte, then
/// the register shift (0 to 3) and the access width (1 or 4), as the
/// kernel takes them from the tree. None for a PL011 (no kind byte) or a
/// layout the view does not drive.
pub fn layout(own: &[u8]) -> Option<(u8, u8)> {
    let kind = *own.get(8)?;
    if kind != KIND_16550 {
        return None;
    }
    let shift = own.get(9).copied().unwrap_or(0);
    let width = own.get(10).copied().unwrap_or(1);
    (shift <= 3 && (width == 1 || width == 4)).then_some((shift, width))
}

// LSR and the registers of the 16550, by their numbers before the shift.
const RBR_THR: usize = 0;
const IER: usize = 1;
const IIR_FCR: usize = 2;
const LCR: usize = 3;
const MCR: usize = 4;
const LSR_REG: usize = 5;
const LSR_DR: u32 = 1;
const LSR_ERRORS: u32 = 0x1E;
const LSR_THRE: u32 = 1 << 5;
const LSR_TEMT: u32 = 1 << 6;
/// FCR: FIFOs on, the receive FIFO cleared, trigger at 8. The transmit FIFO
/// is not cleared: the tail of the kernel's last line may sit in it.
const FCR_TAKEOVER: u32 = 0x83;
/// IIR[7:6] both set: the FIFOs are on (a 16550A).
const IIR_FIFO: u32 = 0xC0;
const FIFO_DEPTH: u8 = 16;

/// The access to the registers of the 16550: `reg` is the register number,
/// the byte or the word at its place after the shift.
pub trait Bus {
    fn read(&self, reg: usize) -> u32;
    fn write(&self, reg: usize, value: u32);
}

/// The view: a bus, the bytes written since LSR last showed room, the copy of
/// the interrupt mask the driver writes, the depth of the transmit FIFO and
/// the count of each error bit of LSR (overrun, parity, framing, break).
pub struct View<B: Bus> {
    bus: B,
    sent: Cell<u8>,
    imsc: Cell<u32>,
    depth: Cell<u8>,
    errors: [Cell<u32>; 4],
}

impl<B: Bus> View<B> {
    pub fn new(bus: B) -> View<B> {
        View {
            bus,
            sent: Cell::new(0),
            imsc: Cell::new(0),
            depth: Cell::new(1),
            errors: [const { Cell::new(0) }; 4],
        }
    }

    /// LSR, with the error bits it showed counted: reading it clears them.
    fn lsr(&self) -> u32 {
        let lsr = self.bus.read(LSR_REG);
        for (n, count) in self.errors.iter().enumerate() {
            if lsr & (LSR_ERRORS & (2 << n)) != 0 {
                count.set(count.get().saturating_add(1));
            }
        }
        lsr
    }

    /// Overrun, parity, framing and break errors counted so far.
    pub fn line_errors(&self) -> [u32; 4] {
        [
            self.errors[0].get(),
            self.errors[1].get(),
            self.errors[2].get(),
            self.errors[3].get(),
        ]
    }

    /// The depth of the transmit FIFO the setup found.
    pub fn depth(&self) -> u8 {
        self.depth.get()
    }

    /// The register `reg` of the PL011, as the driver reads it.
    pub fn read(&self, reg: usize) -> u32 {
        let lsr = self.lsr();
        match reg {
            FR => {
                if lsr & LSR_THRE != 0 {
                    self.sent.set(0);
                }
                let mut flags = 0;
                if lsr & LSR_DR == 0 {
                    flags |= FR_RXFE;
                }
                // THRE says only that the FIFO is empty. Bytes counted since it
                // last said so tell how full it is; with none counted and THRE
                // clear, something else (the kernel's tail) fills it.
                let unknown = lsr & LSR_THRE == 0 && self.sent.get() == 0;
                if unknown || self.sent.get() >= self.depth.get() {
                    flags |= FR_TXFF;
                }
                flags
                    | if lsr & LSR_TEMT != 0 {
                        FR_TXFE
                    } else {
                        FR_BUSY
                    }
            }
            DR => self.bus.read(RBR_THR) & 0xFF,
            MIS => {
                let mut raw = 0;
                if lsr & LSR_DR != 0 {
                    raw |= RX | RT;
                }
                if lsr & LSR_THRE != 0 {
                    raw |= TX;
                }
                raw & self.imsc.get()
            }
            IMSC => self.imsc.get(),
            _ => 0,
        }
    }

    /// The register `reg` of the PL011, as the driver writes it. The line
    /// control is the one place the 16550 is set up: no interrupts, FIFOs on
    /// (the receive FIFO cleared), 8N1 with the divisor latch closed, DTR,
    /// RTS and OUT2; the depth of the transmit FIFO is 16 only when IIR says
    /// the FIFOs are on. The divisor stays the firmware's.
    pub fn write(&self, reg: usize, value: u32) {
        match reg {
            DR => {
                self.sent.set(self.sent.get().saturating_add(1));
                self.bus.write(RBR_THR, value & 0xFF);
            }
            IMSC => self.imsc.set(value),
            LCR_H => {
                self.bus.write(IER, 0);
                self.bus.write(IIR_FCR, FCR_TAKEOVER);
                self.bus.write(LCR, 0x03);
                self.bus.write(MCR, 0x0B);
                let fifo = self.bus.read(IIR_FCR) & IIR_FIFO == IIR_FIFO;
                self.depth.set(if fifo { FIFO_DEPTH } else { 1 });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A 16550 with a transmit FIFO of 16 bytes that empties on a call of
    /// `tick`, a receive queue, errors that LSR clears when read, and the
    /// FCR it was given.
    struct Model {
        fifo: bool,
        tx: RefCell<Vec<u8>>,
        sent: RefCell<Vec<u8>>,
        rx: RefCell<Vec<u8>>,
        errors: Cell<u32>,
        fcr: Cell<u32>,
        writes: RefCell<Vec<(usize, u32)>>,
    }

    impl Model {
        fn new(fifo: bool) -> Model {
            Model {
                fifo,
                tx: RefCell::new(Vec::new()),
                sent: RefCell::new(Vec::new()),
                rx: RefCell::new(Vec::new()),
                errors: Cell::new(0),
                fcr: Cell::new(0),
                writes: RefCell::new(Vec::new()),
            }
        }
        fn tick(&self) {
            let mut tx = self.tx.borrow_mut();
            self.sent.borrow_mut().extend(tx.drain(..));
        }
    }

    impl Bus for &Model {
        fn read(&self, reg: usize) -> u32 {
            match reg {
                RBR_THR => {
                    let mut rx = self.rx.borrow_mut();
                    if rx.is_empty() {
                        0
                    } else {
                        u32::from(rx.remove(0))
                    }
                }
                IIR_FCR => {
                    if self.fcr.get() & 1 != 0 && self.fifo {
                        0xC1
                    } else {
                        0x01
                    }
                }
                LSR_REG => {
                    let mut l = self.errors.replace(0);
                    if !self.rx.borrow().is_empty() {
                        l |= LSR_DR;
                    }
                    let n = self.tx.borrow().len();
                    if n == 0 {
                        l |= LSR_THRE | LSR_TEMT;
                    }
                    l
                }
                _ => 0,
            }
        }
        fn write(&self, reg: usize, value: u32) {
            self.writes.borrow_mut().push((reg, value));
            match reg {
                RBR_THR => self.tx.borrow_mut().push(value as u8),
                IIR_FCR => self.fcr.set(value),
                _ => {}
            }
        }
    }

    #[test]
    fn the_flags_of_a_pl011_come_from_lsr() {
        let m = Model::new(true);
        let v = View::new(&m);
        v.write(LCR_H, 0x70);
        assert_eq!(v.read(FR) & FR_RXFE, FR_RXFE, "nothing received");
        assert_eq!(v.read(FR) & (FR_TXFF | FR_BUSY), 0, "idle and room");
        m.rx.borrow_mut().push(b'x');
        assert_eq!(v.read(FR) & FR_RXFE, 0);
        assert_eq!(v.read(DR), u32::from(b'x'));
        v.write(DR, u32::from(b'a'));
        assert_ne!(v.read(FR) & FR_BUSY, 0, "a byte in the FIFO");
    }

    #[test]
    fn a_fifo_of_16_takes_16_bytes_and_then_says_full_until_it_empties() {
        let m = Model::new(true);
        let v = View::new(&m);
        v.write(LCR_H, 0x70);
        assert_eq!(v.depth(), 16);
        let mut put = 0;
        while v.read(FR) & FR_TXFF == 0 {
            v.write(DR, 0x41);
            put += 1;
            assert!(put <= 16);
        }
        // LSR says THRE only while the model's FIFO is empty, so after the
        // first byte it would say full if the flag followed LSR alone.
        assert_eq!(put, 16, "the count of the view says full");
        m.tick();
        assert_eq!(v.read(FR) & FR_TXFF, 0, "room again");
        assert_eq!(m.sent.borrow().len(), 16);
    }

    #[test]
    fn a_port_without_fifos_takes_one_byte_at_a_time() {
        let m = Model::new(false);
        let v = View::new(&m);
        v.write(LCR_H, 0x70);
        assert_eq!(v.depth(), 1);
        v.write(DR, 0x41);
        assert_ne!(v.read(FR) & FR_TXFF, 0);
    }

    #[test]
    fn the_takeover_keeps_the_tail_of_the_transmit_fifo() {
        let m = Model::new(true);
        let v = View::new(&m);
        v.write(LCR_H, 0x70);
        let fcr = m
            .writes
            .borrow()
            .iter()
            .find(|(r, _)| *r == IIR_FCR)
            .map(|(_, w)| *w)
            .unwrap();
        assert_eq!(fcr & 0x04, 0, "the transmit FIFO is not cleared");
        assert_eq!(fcr & 0x03, 0x03, "FIFOs on, receive FIFO cleared");
    }

    #[test]
    fn the_masked_interrupts_follow_the_mask_and_lsr() {
        let m = Model::new(true);
        let v = View::new(&m);
        v.write(LCR_H, 0x70);
        assert_eq!(v.read(MIS), 0, "all masked");
        v.write(IMSC, RX | RT | TX);
        assert_eq!(v.read(MIS), TX, "room, nothing received");
        m.rx.borrow_mut().push(1);
        assert_eq!(v.read(MIS), RX | RT | TX);
        v.write(IMSC, RX);
        assert_eq!(v.read(MIS), RX);
    }

    #[test]
    fn the_error_bits_of_lsr_are_counted_before_a_read_clears_them() {
        let m = Model::new(true);
        let v = View::new(&m);
        v.write(LCR_H, 0x70);
        m.errors.set(0x02 | 0x08);
        let _ = v.read(FR);
        m.errors.set(0x10);
        let _ = v.read(FR);
        let _ = v.read(FR);
        assert_eq!(v.line_errors(), [1, 0, 1, 1]);
    }

    #[test]
    fn the_layout_comes_from_the_arguments() {
        let base = 0x090a_0000u64.to_le_bytes();
        let mut own = base.to_vec();
        assert_eq!(layout(&own), None, "no kind byte: a PL011");
        own.extend([KIND_16550]);
        assert_eq!(layout(&own), Some((0, 1)));
        own.extend([2, 4]);
        assert_eq!(layout(&own), Some((2, 4)));
        own[9] = 4;
        assert_eq!(layout(&own), None, "a shift over 3");
        own[9] = 0;
        own[10] = 2;
        assert_eq!(layout(&own), None, "a width of 2");
    }

    #[test]
    fn a_16550_console_is_polled() {
        // Under the deliberate break (`--features break-uart-poll`) the
        // driver arms no poll and this test fails.
        assert!(polls(KIND_16550));
        assert!(!polls(0));
        assert_eq!(POLL_NS, 10_000_000);
    }
}
