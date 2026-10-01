// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the driver does for an interrupt of the PL011 (spec 9, 13.5),
//! whose line is level-triggered and masked by the kernel at delivery. A
//! pass reads MIS; reads the receive FIFO into the ring of input, up to
//! RX_PASS bytes and the room of the ring (`receive_limit`, `receive`);
//! writes up to TX_PASS bytes of output to the transmit FIFO
//! (`transmit_limit`, `transmit`); then writes ICR and IMSC as `Irq::end`
//! decides and reads IMSC back before irq_ack. Input is never cleared in
//! ICR: reading the FIFO empty clears it, and a clear written after the
//! last read would drop the interrupt of a byte that came in between. A
//! full ring masks input until a read takes bytes (`Irq::drained`), and
//! the transmit interrupt is let out only while output waits; the driver
//! writes the first bytes of an idle output itself (`Irq::start`). The
//! program reaches the registers; what it writes there comes from here.

use crate::input::Input;
use crate::output::Output;
use crate::regs::{ERRORS, INPUT, TX};

/// The most bytes a pass reads from the receive FIFO.
pub const RX_PASS: usize = 32;
/// The most bytes a pass writes to the transmit FIFO: half the least
/// depth of a FIFO.
pub const TX_PASS: usize = 16;

/// What the end of a pass writes: ICR first, then IMSC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct End {
    pub icr: u32,
    pub imsc: u32,
}

/// The driver's copy of IMSC.
pub struct Irq {
    imsc: u32,
}

impl Irq {
    /// Input let out, transmit masked: IMSC once the driver set the PL011
    /// up (spec 13.5).
    pub const fn new() -> Irq {
        Irq { imsc: INPUT }
    }

    /// What IMSC holds.
    pub fn imsc(&self) -> u32 {
        self.imsc
    }

    /// Whether the transmit interrupt is let out: output waits, and a pass
    /// comes for it.
    pub fn transmitting(&self) -> bool {
        self.imsc & TX != 0
    }

    /// The most bytes a pass for `mis` reads from the receive FIFO into a
    /// ring with room for `room`: RX_PASS or the room, whichever is less;
    /// none when `mis` shows no input.
    pub fn receive_limit(&self, mis: u32, room: usize) -> usize {
        if mis & INPUT == 0 {
            0
        } else {
            room.min(RX_PASS)
        }
    }

    /// The most bytes a pass for `mis` writes to the transmit FIFO:
    /// TX_PASS when `mis` shows transmit, none otherwise.
    pub fn transmit_limit(&self, mis: u32) -> usize {
        if mis & TX == 0 { 0 } else { TX_PASS }
    }

    /// The end of a pass for `mis`, with the ring of input full or not and
    /// the output idle or not: ICR clears transmit once the output is idle,
    /// never input. Error interrupts stay masked; Input::push counts byte
    /// errors from DR. IMSC masks input while the ring is full and lets
    /// transmit out only while output waits. An output that
    /// was idle outside a pass the program starts itself (`start`).
    pub fn end(&mut self, mis: u32, ring_full: bool, idle: bool) -> End {
        let mut icr = mis & ERRORS;
        if ring_full {
            self.imsc &= !INPUT;
        } else {
            self.imsc |= INPUT;
        }
        if idle {
            self.imsc &= !TX;
            icr |= TX;
        } else {
            self.imsc |= TX;
        }
        End {
            icr,
            imsc: self.imsc,
        }
    }

    /// Starts `output` after the program put bytes there outside a pass
    /// (spec 13.5): while transmit is masked, writes up to TX_PASS bytes
    /// to the transmit FIFO as `transmit` does, through `tx_full` and
    /// `dr`, and gives the IMSC to write when bytes are left, transmit let
    /// out. A PL011 raises transmit only as its FIFO falls through its
    /// level, never for a FIFO nobody fills. The program calls it after
    /// each put into the output: a write, the writes that waited, a batch
    /// of the log, its own line.
    pub fn start(
        &mut self,
        output: &mut Output,
        tx_full: impl FnMut() -> bool,
        dr: impl FnMut(u8),
    ) -> Option<u32> {
        if self.transmitting() {
            return None;
        }
        transmit(TX_PASS, tx_full, dr, output);
        if output.is_idle() {
            return None;
        }
        self.imsc |= TX;
        Some(self.imsc)
    }

    /// A read took bytes out of the ring of input: the IMSC to write when
    /// input is let out again, once the ring has room.
    pub fn drained(&mut self, ring_full: bool) -> Option<u32> {
        if ring_full || self.imsc & INPUT == INPUT {
            return None;
        }
        self.imsc |= INPUT;
        Some(self.imsc)
    }
}

impl Default for Irq {
    fn default() -> Irq {
        Irq::new()
    }
}

/// Reads the receive FIFO into `input`: up to `limit` bytes, while
/// `rx_empty` (FR.RXFE) says bytes wait, each as `dr` reads DR. Gives the
/// count.
pub fn receive<T, H>(
    limit: usize,
    mut rx_empty: impl FnMut() -> bool,
    mut dr: impl FnMut() -> u32,
    input: &mut Input<T, H>,
) -> usize {
    let mut n = 0;
    while n < limit && !rx_empty() && input.push(dr()) {
        n += 1;
    }
    n
}

/// Writes bytes of `output` to the transmit FIFO: up to `limit`, while
/// `tx_full` (FR.TXFF) says there is room, each as `dr` writes DR. Gives
/// the count.
pub fn transmit(
    limit: usize,
    mut tx_full: impl FnMut() -> bool,
    mut dr: impl FnMut(u8),
    output: &mut Output,
) -> usize {
    let mut n = 0;
    while n < limit && !tx_full() {
        let Some(b) = output.next_byte() else { break };
        dr(b);
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regs::{FE, OE, RT, RX};
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// A receive FIFO of the model: the bytes that wait.
    struct Fifo(VecDeque<u32>);

    impl Fifo {
        fn of(n: usize) -> Fifo {
            Fifo((0..n).map(|i| u32::from(b'a' + (i % 26) as u8)).collect())
        }
    }

    /// A pass of the receive side, as the program makes it: gives the
    /// count and the end.
    fn receive_pass(
        irq: &mut Irq,
        mis: u32,
        fifo: &mut Fifo,
        input: &mut Input<()>,
    ) -> (usize, End) {
        let limit = irq.receive_limit(mis, input.room());
        let fifo_cell = core::cell::RefCell::new(&mut fifo.0);
        let n = receive(
            limit,
            || fifo_cell.borrow().is_empty(),
            || fifo_cell.borrow_mut().pop_front().unwrap(),
            input,
        );
        (n, irq.end(mis, input.is_full(), true))
    }

    #[test]
    fn a_full_receive_ring_masks_the_receive_interrupts() {
        let mut irq = Irq::new();
        let mut input = Input::new();
        for _ in 0..250 {
            assert!(input.push(u32::from(b'.')));
        }
        let mut fifo = Fifo::of(20);
        let (n, end) = receive_pass(&mut irq, RX, &mut fifo, &mut input);
        assert_eq!((n, fifo.0.len()), (6, 14));
        assert!(input.is_full());
        assert_eq!(end.imsc & INPUT, 0, "input stays let out");
        assert_eq!(end.icr & INPUT, 0, "input cleared with bytes left");
        // A full ring reads nothing more.
        assert_eq!(irq.receive_limit(RX | RT, input.room()), 0);
        assert_eq!(irq.drained(true), None);
        assert!(input.read(1, 64, (), &mut [0; 64]) == crate::input::Taken::Now(64, ()));
        assert_eq!(irq.drained(input.is_full()), Some(INPUT));
        assert_eq!(irq.drained(false), None);
    }

    /// Reading the FIFO empty clears input, in the PL011 and in QEMU
    /// alike; QEMU raises it again only as its FIFO goes from no byte to
    /// one. A byte that comes after the last read of a pass raises it, and
    /// a clear in ICR at the end of the pass would drop it for good.
    #[test]
    fn a_pass_never_clears_receive() {
        let mut irq = Irq::new();
        let mut input = Input::new();
        let mut fifo = Fifo::of(40);
        let (n, end) = receive_pass(&mut irq, RX, &mut fifo, &mut input);
        assert_eq!(n, RX_PASS);
        assert_eq!(end.icr & INPUT, 0);
        assert_eq!(end.imsc & INPUT, INPUT);
        let (n, end) = receive_pass(&mut irq, RX | RT, &mut fifo, &mut input);
        assert_eq!((n, fifo.0.len()), (8, 0));
        assert_eq!(end.icr & INPUT, 0);
        assert_eq!(end.imsc & INPUT, INPUT);
        // The errors are cleared with each pass; no input, no reads.
        let end = irq.end(OE | FE, false, true);
        assert_eq!(end.icr & (OE | FE | INPUT), OE | FE);
        assert_eq!(irq.receive_limit(TX, 256), 0);
    }

    #[test]
    fn transmit_interrupt_is_open_only_while_bytes_wait() {
        let mut irq = Irq::new();
        let mut output = Output::new();
        assert!(!irq.transmitting());
        assert!(output.put(&[b'x'; 20]));
        // The driver starts an idle output itself, and only that.
        let mut sent = 0;
        assert_eq!(
            irq.start(&mut output, || false, |_| sent += 1),
            Some(INPUT | TX)
        );
        assert_eq!(sent, 16);
        assert_eq!(irq.start(&mut output, || false, |_| sent += 1), None);
        assert_eq!(sent, 16);
        assert_eq!(transmit(TX_PASS, || false, |_| {}, &mut output), 4);
        let end = irq.end(TX, false, output.is_idle());
        assert_eq!((end.imsc & TX, end.icr & TX), (0, TX));
        assert!(!irq.transmitting());
        // Bytes left after a pass keep it let out, and not cleared.
        assert!(output.put(&[b'y'; 40]));
        irq.start(&mut output, || false, |_| {});
        transmit(TX_PASS, || false, |_| {}, &mut output);
        let end = irq.end(TX, false, output.is_idle());
        assert_eq!((end.imsc & TX, end.icr & TX), (TX, 0));
        // An output that goes idle within the first bytes never lets it out.
        let mut short = Output::new();
        assert!(short.put(b"ok"));
        let mut irq = Irq::new();
        assert_eq!(irq.start(&mut short, || false, |_| {}), None);
        assert!(short.is_idle() && !irq.transmitting());
    }

    #[test]
    fn a_transmit_pass_writes_at_most_16_bytes() {
        let mut output = Output::new();
        let text: Vec<u8> = (0..100).map(|i| b'a' + (i % 26) as u8).collect();
        assert!(output.put(&text));
        let irq = Irq::new();
        assert_eq!(irq.transmit_limit(RX | RT), 0);
        let limit = irq.transmit_limit(TX);
        let mut sent = Vec::new();
        assert_eq!(transmit(limit, || false, |b| sent.push(b), &mut output), 16);
        assert_eq!(sent, text[..16]);
        // A full FIFO stops the pass early.
        let mut polls = 0;
        let n = transmit(
            TX_PASS,
            || {
                polls += 1;
                polls > 5
            },
            |b| sent.push(b),
            &mut output,
        );
        assert_eq!(n, 5);
        assert_eq!(sent, text[..21]);
    }
}
