// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The barriers between the processor's accesses to the rings and the
//! device's: the stores to DMA memory before the store to the doorbell
//! (`wmb`, `dmb oshst`), and the load of a used index before the loads of
//! the memory it covers (`rmb`, `dmb oshld`). The device sees the guest's
//! memory as a coherent processor does (Virtio 1.2, 6.1, without
//! VIRTIO_F_ACCESS_PLATFORM), so ordering is all a ring needs. `ring` rings
//! a queue's doorbell after its barrier.

use virtio_drivers::transport::Transport;

/// Orders the program's stores to DMA memory before its next store to a
/// device's register, the doorbell.
#[inline]
pub fn wmb() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a barrier has no other effect.
    unsafe {
        core::arch::asm!("dmb oshst", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
}

/// Orders a load of a device's index before the loads of the DMA memory it
/// covers.
#[inline]
pub fn rmb() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a barrier has no other effect.
    unsafe {
        core::arch::asm!("dmb oshld", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
}

/// Rings the doorbell of `queue` once the request is in it: the stores of
/// the descriptors and the ring reach the device first.
#[inline]
pub fn ring<T: Transport>(transport: &mut T, queue: u16) {
    wmb();
    transport.notify(queue);
}
