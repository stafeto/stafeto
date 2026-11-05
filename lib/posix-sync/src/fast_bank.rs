// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The bank of the service's notifications (`receiver.rs`; the claim is in `posix-abi/src/fast.rs`): the part that
//! takes no kernel call, so that the host tests can run it.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// CLIENT_GONE of the kernel's notifications (spec 5.3); `fast.rs` asserts
/// that it equals `rt::abi::CLIENT_GONE`.
pub const CLIENT_GONE: u64 = 1 << 63;

/// The label of the service's notifications on the thread's channel: apart
/// from the labels of `wait` (bit 63) and of the long operations (small
/// numbers).
///
/// Each try of CLAIM labels its copy of the channel anew (`FAST_LABEL`
/// with the number of the try in the low 32 bits): the service closes the
/// copy of a refused try, the kernel puts its CLIENT_GONE on the channel
/// with that label, and the bank takes only the label of the claim that
/// holds the device, so the departure of a refused try never reads as the
/// end of the service.
pub const FAST_LABEL: u64 = 1 << 62 | 0xfa57 << 32;
/// The bits of a label that mark a notification of the fast path.
pub const FAST_MASK: u64 = 1 << 62 | 0xffff << 32;
/// The bit `wait` gives when the service let go of its notifications: it
/// ended, or it took the device back.
pub const GONE: u32 = 16;

/// The bits of a notification of the service as `wait` gives them.
pub fn bits_of(bits: u64) -> u32 {
    let own = (bits & 0xf) as u32;
    if bits & CLIENT_GONE != 0 {
        own | GONE
    } else {
        own
    }
}

/// The notifications of the service that a wait of another owner took off
/// the thread's channel, kept until `wait` or the program's loop takes them.
pub struct Bank {
    /// The label of the try that got the device (0 before).
    active: AtomicU64,
    /// The bits of `bits_of` that came and nobody took yet.
    pending: AtomicU32,
    /// The service let go of its notifications: sticky to the end of the
    /// process.
    lost: AtomicBool,
}

impl Bank {
    pub const fn new() -> Self {
        Self {
            active: AtomicU64::new(0),
            pending: AtomicU32::new(0),
            lost: AtomicBool::new(false),
        }
    }

    /// The try with this label holds the device.
    pub fn activate(&self, label: u64) {
        self.active.store(label, Ordering::Release);
    }

    /// Takes in a notification with a label of the fast path: the active
    /// try's goes into `pending`, a past try's is dropped.
    pub fn deposit(&self, label: u64, bits: u64) {
        if label != self.active.load(Ordering::Acquire) {
            return;
        }
        if bits & CLIENT_GONE != 0 {
            self.lost.store(true, Ordering::Release);
        }
        self.pending.fetch_or(bits_of(bits), Ordering::AcqRel);
    }

    /// Hands out the banked bits, each bit to one taker.
    pub fn take(&self) -> u32 {
        self.pending.swap(0, Ordering::AcqRel)
    }

    pub fn lost(&self) -> bool {
        self.lost.load(Ordering::Acquire)
    }
}
