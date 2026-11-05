// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The second device's interface while a program owns the device (spec 6,
//! 3.9): its stack keeps the DHCP client of the second address, and its
//! frames go through the bypass ring (`netd::bypass`) in place of the
//! device's queues. A step takes at most `RING_RX` frames from the ring,
//! each copied into the service's own buffer and checked there
//! (`bypass::accepts`) before the stack sees it; what the stack sends goes
//! into the ring to the owner, `STEP_TX` frames at most in a pass, and the
//! owner is told once at the end of the step. The interface keeps the
//! capabilities of the device it was made with (no sums by smoltcp), so the
//! sums are checked and written here, as `device.rs` does for the queues.

use netd::bypass::{Broken, Own, Ring, Taker};
use netd::ring::STEP_TX;
use proto_net::fast::FRAME_MAX;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use virtio_net::frames::fill_sums;

/// The ring with the frames a step took from it (`bypass::Taker`), and
/// what the pass of sending puts in the ring to the owner.
pub struct Fast {
    pub taker: Taker,
    /// Where the stack builds a frame for the owner.
    out: [u8; FRAME_MAX],
    /// Frames put in the ring to the owner since the owner was told.
    pub pushed: u32,
    /// The frames of the pass of sending so far.
    sent: usize,
    /// Frames the full ring to the owner had no room for.
    pub lost: u64,
}

impl Fast {
    /// The ring at `base`, as `Ring::at`.
    ///
    /// # Safety
    ///
    /// As `Ring::at`.
    pub unsafe fn new(base: usize) -> Fast {
        Fast {
            // SAFETY: the caller's promise.
            taker: unsafe { Taker::new(base) },
            out: [0; FRAME_MAX],
            pushed: 0,
            sent: 0,
            lost: 0,
        }
    }

    /// The frames of a step (`Taker::take`); the pass of sending starts.
    pub fn take(&mut self, own: Own) -> u32 {
        self.sent = 0;
        self.taker.take(own)
    }
}

pub struct RxToken<'a> {
    frame: &'a [u8],
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.frame)
    }
}

pub struct TxToken<'a> {
    ring: &'a mut Ring,
    out: &'a mut [u8; FRAME_MAX],
    pushed: &'a mut u32,
    lost: &'a mut u64,
    broken: &'a mut bool,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let len = len.min(FRAME_MAX);
        let result = f(&mut self.out[..len]);
        fill_sums(&mut self.out[..len]);
        match self.ring.put(&self.out[..len]) {
            Ok(true) => *self.pushed += 1,
            Ok(false) => *self.lost += 1,
            Err(Broken) => *self.broken = true,
        }
        result
    }
}

impl phy::Device for Fast {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(RxToken<'_>, TxToken<'_>)> {
        self.sent += 1;
        let Fast {
            taker,
            out,
            pushed,
            lost,
            ..
        } = self;
        let (frame, ring, broken) = taker.next_frame()?;
        Some((
            RxToken { frame },
            TxToken {
                ring,
                out,
                pushed,
                lost,
                broken,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<TxToken<'_>> {
        if self.sent >= STEP_TX || self.taker.broken {
            return None;
        }
        self.sent += 1;
        Some(TxToken {
            ring: &mut self.taker.ring,
            out: &mut self.out,
            pushed: &mut self.pushed,
            lost: &mut self.lost,
            broken: &mut self.taker.broken,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        // As the queues' device (the interface took those): the sums are
        // this module's.
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
        caps.max_transmission_unit = FRAME_MAX;
        caps
    }
}
