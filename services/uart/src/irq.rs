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
//! transmit stays masked during the absolute retry deadline. New writes
//! and receive passes preserve that deadline; its timer resumes one
//! bounded output portion (`Irq::start`). The
//! program reaches the registers; what it writes there comes from here.

use crate::input::Input;
use crate::output::Output;
use crate::regs::{ERRORS, INPUT, TX};

/// The most bytes a pass reads from the receive FIFO.
pub const RX_PASS: usize = 32;
/// Each pass fills up to one FIFO, checking TXFF before every byte.
pub const TX_PASS: usize = 32;
/// The gap between transmit portions, in absolute timer nanoseconds.
pub const TX_GAP_NS: u64 = 1_000_000;

/// What the end of a pass writes: ICR first, then IMSC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct End {
    pub icr: u32,
    pub imsc: u32,
}

/// The driver's copy of IMSC.
pub struct Irq {
    imsc: u32,
    tx_deadline: u64,
}

impl Irq {
    /// Input let out, transmit masked: IMSC once the driver set the PL011
    /// up (spec 13.5).
    pub const fn new() -> Irq {
        Irq {
            imsc: INPUT,
            tx_deadline: 0,
        }
    }

    /// What IMSC holds.
    pub fn imsc(&self) -> u32 {
        self.imsc
    }

    /// Whether the transmit interrupt is currently enabled.
    pub fn transmitting(&self) -> bool {
        self.imsc & TX != 0
    }

    /// Whether an absolute transmit or physical-drain retry is held.
    pub fn deferred(&self) -> bool {
        self.tx_deadline != 0
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
    /// TX_PASS when `mis` shows transmit outside its retry deadline.
    pub fn transmit_limit(&self, mis: u32) -> usize {
        if mis & TX == 0 || self.tx_deadline != 0 {
            0
        } else {
            TX_PASS
        }
    }

    /// The end of a pass for `mis`, with the ring of input full or not and
    /// the output idle or not: ICR clears transmit once the output is idle,
    /// never input. Error interrupts stay masked; Input::push counts byte
    /// errors from DR. IMSC masks input while the ring is full and lets
    /// transmit out while output waits outside its retry deadline. An output that
    /// was idle outside a pass the program starts itself (`start`).
    pub fn end(&mut self, mis: u32, ring_full: bool, idle: bool) -> End {
        let mut icr = mis & ERRORS;
        if ring_full {
            self.imsc &= !INPUT;
        } else {
            self.imsc |= INPUT;
        }
        if idle || self.tx_deadline != 0 {
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
    /// each put into the output and at a transmit expiry. A held retry
    /// deadline prevents a new write from starting another portion.
    pub fn start(
        &mut self,
        output: &mut Output,
        tx_full: impl FnMut() -> bool,
        dr: impl FnMut(u8),
    ) -> Option<u32> {
        if self.transmitting() || self.tx_deadline != 0 {
            return None;
        }
        transmit(TX_PASS, tx_full, dr, output);
        if output.is_idle() {
            return None;
        }
        self.imsc |= TX;
        Some(self.imsc)
    }

    /// Mask transmit after one portion and keep its absolute retry deadline.
    /// Input remains enabled according to its ring's state.
    pub fn defer_transmit(&mut self, now: u64) -> u64 {
        self.imsc &= !TX;
        self.tx_deadline = now.saturating_add(TX_GAP_NS);
        self.tx_deadline
    }

    /// Resume once the currently held deadline is reached. A stale timer
    /// notice cannot resume a newer portion or an idle transmitter.
    pub fn resume_transmit(&mut self, now: u64) -> bool {
        if self.tx_deadline == 0 || now < self.tx_deadline {
            return false;
        }
        self.tx_deadline = 0;
        true
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

/// Discard at most one bounded receive pass. New arrivals cannot extend it.
/// No interrupt mask, transmit FIFO or output state is changed.
pub fn discard_receive(mut rx_empty: impl FnMut() -> bool, mut dr: impl FnMut() -> u32) -> usize {
    let mut n = 0;
    while n < RX_PASS && !rx_empty() {
        let _ = dr();
        n += 1;
    }
    n
}

/// Apply the console input flush and restore RX/RT if the old full ring
/// masked them. Return the IMSC to write and read back; TX state is preserved.
pub fn flush_input<T, H>(
    input: &mut Input<T, H>,
    irqs: &mut Irq,
    label: u64,
    nonce: u64,
    rx_empty: impl FnMut() -> bool,
    dr: impl FnMut() -> u32,
) -> Result<Option<u32>, abi::Error> {
    if !input.flush(label, nonce, || {
        discard_receive(rx_empty, dr);
        true
    }) {
        return Err(abi::Error::BadState);
    }
    Ok(irqs.drained(input.is_full()))
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

    #[test]
    fn input_flush_reopens_full_ring_rx_and_preserves_transmit_state() {
        let mut input: Input<(), &str> = Input::new();
        let mut irqs = Irq::new();
        let mut out = [0; 2];
        assert_eq!(input.start(7, 2, &mut out), crate::input::Start::Wait(1));
        input.take(7, 1, Some("reader"), &mut out);
        for _ in 0..crate::input::RX_RING {
            assert!(input.push(u32::from(b'o')));
        }
        assert_eq!(input.to_tell(), Some(&"reader"));
        irqs.end(INPUT, true, false);
        assert_eq!(irqs.imsc() & INPUT, 0);
        assert!(irqs.transmitting());
        assert_eq!(
            flush_input(
                &mut input,
                &mut irqs,
                7,
                1,
                || true,
                || panic!("empty FIFO read")
            ),
            Ok(Some(INPUT | TX))
        );
        assert!(irqs.transmitting());
        assert_eq!(
            input.take(7, 1, None, &mut out),
            crate::input::Taken2::Armed
        );
        assert!(input.push(u32::from(b'n')));
        assert_eq!(input.to_tell(), Some(&"reader"));
    }

    #[test]
    fn receive_flush_is_bounded_even_when_the_fifo_continuously_refills() {
        let mut reads = 0;
        assert_eq!(
            discard_receive(
                || false,
                || {
                    reads += 1;
                    0
                }
            ),
            RX_PASS
        );
        assert_eq!(reads, 32);
        let left = core::cell::Cell::new(16);
        assert_eq!(
            discard_receive(
                || left.get() == 0,
                || {
                    left.set(left.get() - 1);
                    0
                }
            ),
            16
        );
        assert_eq!(discard_receive(|| true, || panic!("empty FIFO read")), 0);
    }

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
        assert!(output.put(&[b'x'; TX_PASS + 4]));
        // The driver starts an idle output itself, and only that.
        let mut sent = 0;
        assert_eq!(
            irq.start(&mut output, || false, |_| sent += 1),
            Some(INPUT | TX)
        );
        assert_eq!(sent, TX_PASS);
        assert_eq!(irq.start(&mut output, || false, |_| sent += 1), None);
        assert_eq!(sent, TX_PASS);
        assert_eq!(transmit(TX_PASS, || false, |_| {}, &mut output), 4);
        let end = irq.end(TX, false, output.is_idle());
        assert_eq!((end.imsc & TX, end.icr & TX), (0, TX));
        assert!(!irq.transmitting());
        // Bytes left after a pass keep it let out, and not cleared.
        assert!(output.put(&[b'y'; TX_PASS * 3]));
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
    fn deferred_transmit_blocks_new_starts_and_stale_tx_interrupts() {
        let mut irq = Irq::new();
        let mut output = Output::new();
        assert!(output.put(&[b'x'; 100]));
        let mut sent = Vec::new();
        assert!(irq.start(&mut output, || false, |b| sent.push(b)).is_some());
        assert_eq!(sent.len(), TX_PASS);
        let deadline = irq.defer_transmit(700);
        assert_eq!(deadline, 700 + TX_GAP_NS);
        assert_eq!(irq.imsc() & TX, 0);
        assert_eq!(irq.transmit_limit(TX | RX), 0);
        assert!(output.put(b"new"));
        assert_eq!(irq.start(&mut output, || false, |b| sent.push(b)), None);
        assert_eq!(sent.len(), TX_PASS);
        assert!(!irq.resume_transmit(deadline - 1));
        assert!(irq.resume_transmit(deadline));
        assert!(irq.start(&mut output, || false, |b| sent.push(b)).is_some());
        assert_eq!(sent.len(), 2 * TX_PASS);
    }

    #[test]
    fn receive_irq_preserves_transmit_deadline_and_input_progress() {
        let mut irq = Irq::new();
        let deadline = irq.defer_transmit(7);
        let mut input = Input::new();
        let mut fifo = Fifo::of(4);
        let (n, end) = receive_pass(&mut irq, RX | RT, &mut fifo, &mut input);
        assert_eq!(n, 4);
        assert_eq!(end.imsc, INPUT);
        let end = irq.end(RX | RT, false, false);
        assert_eq!(end.imsc, INPUT);
        assert_eq!(end.icr & INPUT, 0);
        assert_eq!(irq.transmit_limit(TX), 0);
        assert!(!irq.resume_transmit(deadline - 1));
        assert!(irq.resume_transmit(deadline));
    }

    #[test]
    fn duplicate_expiry_cannot_advance_a_new_transmit_portion() {
        let mut irq = Irq::new();
        let first = irq.defer_transmit(20);
        assert!(irq.resume_transmit(first));
        assert!(!irq.resume_transmit(first));
        let second = irq.defer_transmit(first);
        assert_eq!(second, first + TX_GAP_NS);
        assert!(!irq.resume_transmit(first));
        assert!(!irq.resume_transmit(second - 1));
        assert!(irq.resume_transmit(second));
    }

    #[test]
    fn paced_full_fifo_preserves_all_bytes_until_the_next_deadline() {
        let mut irq = Irq::new();
        let mut output = Output::new();
        let text: Vec<u8> = (0..100).map(|i| b'a' + (i % 26) as u8).collect();
        assert!(output.put(&text));
        let mut sent = Vec::new();
        assert!(irq.start(&mut output, || true, |b| sent.push(b)).is_some());
        assert!(sent.is_empty());
        let deadline = irq.defer_transmit(100);
        assert!(irq.resume_transmit(deadline));
        assert!(irq.start(&mut output, || false, |b| sent.push(b)).is_some());
        let mut now = deadline;
        while !output.is_idle() {
            now = irq.defer_transmit(now);
            assert!(!irq.resume_transmit(now - 1));
            assert!(irq.resume_transmit(now));
            let before = sent.len();
            irq.start(&mut output, || false, |b| sent.push(b));
            assert!(sent.len() - before <= TX_PASS);
        }
        assert_eq!(sent, text);
        assert!(!irq.resume_transmit(now + TX_GAP_NS));
        assert!(output.put(b"new"));
        irq.start(&mut output, || false, |b| sent.push(b));
        assert_eq!(&sent[text.len()..], b"new");
        assert!(output.is_idle());
    }

    #[test]
    fn paced_output_answers_all_waiting_writes_in_order_under_backpressure() {
        use crate::output::TX_RING;
        use crate::writes::{Taken, Writes};
        let mut irq = Irq::new();
        let mut output = Output::new();
        let mut writes = Writes::new();
        let mut expected = vec![b'x'; TX_RING];
        assert!(output.put(&expected));
        for token in 0..4 {
            let bytes = vec![b'a' + token; 128];
            expected.extend_from_slice(&bytes);
            assert_eq!(
                writes.write(&mut output, u64::from(token), &bytes, token),
                Taken::Waits
            );
        }
        let mut answered = Vec::new();
        let mut sent = Vec::new();
        let mut now = 100;
        for _ in 0..200 {
            writes.flush(&mut output, |token, count| answered.push((token, count)));
            let before = sent.len();
            let waiting = irq.start(&mut output, || false, |b| sent.push(b)).is_some();
            assert!(sent.len() - before <= TX_PASS);
            if !waiting {
                break;
            }
            now = irq.defer_transmit(now);
            assert_eq!(irq.end(RX, false, false).imsc, INPUT);
            assert!(!irq.resume_transmit(now - 1));
            assert!(irq.resume_transmit(now));
        }
        assert!(writes.is_empty() && output.is_idle());
        assert!(writes.roomy(&output));
        assert_eq!(answered, vec![(0, 128), (1, 128), (2, 128), (3, 128)]);
        assert_eq!(sent, expected);
    }

    #[test]
    fn transmit_deadline_saturates_without_wrapping_into_an_early_expiry() {
        let mut irq = Irq::new();
        assert_eq!(irq.defer_transmit(u64::MAX - 10), u64::MAX);
        assert!(!irq.resume_transmit(u64::MAX - 1));
        assert!(irq.resume_transmit(u64::MAX));
    }

    #[test]
    fn a_transmit_pass_writes_at_most_32_bytes_and_preserves_fifo_order() {
        let mut output = Output::new();
        let text: Vec<u8> = (0..100).map(|i| b'a' + (i % 26) as u8).collect();
        assert!(output.put(&text));
        let irq = Irq::new();
        assert_eq!(irq.transmit_limit(RX | RT), 0);
        let limit = irq.transmit_limit(TX);
        let mut sent = Vec::new();
        assert_eq!(transmit(limit, || false, |b| sent.push(b), &mut output), 32);
        assert_eq!(sent, text[..32]);
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
        assert_eq!(sent, text[..37]);
        while !output.is_idle() {
            assert!(transmit(TX_PASS, || false, |b| sent.push(b), &mut output) <= 32);
        }
        assert_eq!(sent, text);
    }
}
