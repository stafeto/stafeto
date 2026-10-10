// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Port 0 of the Virtio console (Virtio 1.2, 5.3): its receive queue 0 and
//! transmit queue 1, two entries each, on the queues of the device's
//! crate. The driver never waits for the device: a transmission is added
//! and rung, and ends when the interrupt shows its buffer used; a receive
//! buffer stays with the device until it comes back with bytes. A receive
//! that comes back empty is the end of the host's input: the buffer is not
//! given again, and the console goes on with output alone.

use crate::Host;
use alloc::boxed::Box;
pub use virtio_console::receive::RX_BYTES;
use virtio_console::receive::Receive;
use virtio_drivers::device::common::Feature;
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::Transport;
use virtio_drivers::transport::pci::PciTransport;

/// The bytes one transmission takes at most, within a bounce page.
pub const TX_BYTES: usize = 1024;

const RECEIVEQ: u16 = 0;
const TRANSMITQ: u16 = 1;

pub struct Port {
    transport: PciTransport,
    receiveq: VirtQueue<Host, 2>,
    transmitq: VirtQueue<Host, 2>,
    rx: Box<[u8; RX_BYTES]>,
    received: Receive,
    tx: Box<[u8; TX_BYTES]>,
    tx_len: usize,
    /// The transmission the device holds, if any.
    tx_token: Option<u16>,
}

impl Port {
    /// The port on `transport`, a device the driver reset (Virtio 1.2,
    /// 3.1.1): VERSION_1 alone, no event index and no indirect entries; a
    /// receive buffer goes to the device at once.
    pub fn new(mut transport: PciTransport) -> Result<Port, virtio_drivers::Error> {
        let _: Feature = transport.begin_init(Feature::VERSION_1);
        let receiveq = VirtQueue::new(&mut transport, RECEIVEQ, false, false)?;
        let transmitq = VirtQueue::new(&mut transport, TRANSMITQ, false, false)?;
        transport.finish_init();
        let mut port = Port {
            transport,
            receiveq,
            transmitq,
            rx: Box::new([0; RX_BYTES]),
            received: Receive::default(),
            tx: Box::new([0; TX_BYTES]),
            tx_len: 0,
            tx_token: None,
        };
        port.give_receive()?;
        Ok(port)
    }

    /// Rings the device for `queue` when the queue asks for it, after the
    /// stores of the queue's memory [G34].
    fn ring(&mut self, queue: u16) {
        rt::dma::wmb();
        self.transport.notify(queue);
    }

    /// Gives the receive buffer to the device when it has none and the
    /// bytes of the last receive are all taken.
    fn give_receive(&mut self) -> Result<(), virtio_drivers::Error> {
        if !self.received.should_post() {
            return Ok(());
        }
        // SAFETY: the buffer lives in the port, which the queue does not
        // outlive, and nothing touches it until `pop_used` gives it back.
        let token = unsafe { self.receiveq.add(&[], &mut [&mut self.rx[..]]) }?;
        self.received.token = Some(token);
        if self.receiveq.should_notify() {
            self.ring(RECEIVEQ);
        }
        Ok(())
    }

    /// After an interrupt: reads the ISR, which drops the level of INTx,
    /// takes a receive and a transmission the device finished. Gives
    /// whether a transmission ended.
    pub fn interrupt(&mut self) -> bool {
        let _ = self.transport.ack_interrupt();
        self.finish_receive();
        self.finish_transmit()
    }

    fn finish_receive(&mut self) {
        let queue = &mut self.receiveq;
        let buffer = &mut self.rx;
        self.received.finish(queue.peek_used(), |token| {
            // SAFETY: the same buffer give_receive added under this exact token;
            // Receive calls this only after its used completion is visible.
            unsafe { queue.pop_used(token, &[], &mut [&mut buffer[..]]) }
                .ok()
                .map(|n| n as usize)
        });
    }

    fn finish_transmit(&mut self) -> bool {
        let Some(token) = self.tx_token else {
            return false;
        };
        if self.transmitq.peek_used() != Some(token) {
            return false;
        }
        // SAFETY: the same buffer `send` added with this token.
        let _ = unsafe {
            self.transmitq
                .pop_used(token, &[&self.tx[..self.tx_len]], &mut [])
        };
        self.tx_token = None;
        true
    }

    /// The next byte of input, if one came; the receive buffer goes back
    /// to the device once its bytes are all taken.
    pub fn next_byte(&mut self) -> Option<u8> {
        let at = self.received.next_index()?;
        let b = self.rx[at];
        if self.received.should_post() {
            let _ = self.give_receive();
        }
        Some(b)
    }

    /// Discard the returned receive prefix, including one completion already
    /// visible in the used ring. An unreturned DMA buffer remains with the device;
    /// bytes arriving after this observation belong to a later receive.
    pub fn flush_receive(&mut self) -> Result<(), virtio_drivers::Error> {
        self.finish_receive();
        self.received.discard();
        self.give_receive()
    }

    /// Whether the host's input ended.
    pub fn input_ended(&self) -> bool {
        self.received.ended()
    }

    /// Whether a transmission is with the device.
    pub fn sending(&self) -> bool {
        self.tx_token.is_some()
    }

    /// A transmission of the bytes `fill` puts into the buffer, up to
    /// TX_BYTES, when none is with the device; gives whether one started.
    /// The call returns at once: the interrupt ends it.
    pub fn send(&mut self, fill: impl FnOnce(&mut [u8]) -> usize) -> bool {
        if self.sending() {
            return false;
        }
        let n = fill(&mut self.tx[..]).min(TX_BYTES);
        if n == 0 {
            return false;
        }
        // SAFETY: the buffer lives in the port and stays untouched until
        // `finish_transmit` gives it back.
        let Ok(token) = (unsafe { self.transmitq.add(&[&self.tx[..n]], &mut []) }) else {
            return false;
        };
        self.tx_len = n;
        self.tx_token = Some(token);
        if self.transmitq.should_notify() {
            self.ring(TRANSMITQ);
        }
        true
    }
}
