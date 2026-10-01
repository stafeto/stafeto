// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the driver of the Virtio PCI console decides (spec 13.5), apart
//! from the device and the calls it makes: where its DMA object holds the
//! device's queues and the bounce pages of the buffers it shares
//! (`dma`), and the registers of its PCI function it writes (`pci`). The
//! clients' protocol, the rings and the kernel log are those of the
//! PL011's driver (uart). Everything here builds for the host too, where
//! `cargo test -p virtio-console` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod dma;
pub mod pci;
