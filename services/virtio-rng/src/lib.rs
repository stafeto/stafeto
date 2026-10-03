// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the driver of the Virtio entropy device decides (Virtio 1.2, 5.4),
//! apart from the device and the calls it makes: where its DMA object
//! holds the queue and the bounce page (`dma`), where its PCI function
//! goes on Apple VZ (`PLACE`), and the fills its clients wait for
//! (`fills`). Everything here builds for the host too, where `cargo test
//! -p virtio-rng` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod fills;

use virtio_pci::Place;

/// The entropy device of Apple VZ: Red Hat's Virtio entropy device, modern,
/// at device 6 of bus 0 after the console (found by a walk of the bus with
/// the runner's configuration, tools/vz-run.swift). BAR 0 is 32 KiB and BAR
/// 2 64 bytes; they go past the console's (virtio_console::pci), each
/// aligned to its size.
pub const PLACE: Place = Place {
    id: 0x1044_1af4,
    bar: 0x1_0001_0000,
    bar_len: 0x8000,
    bar2: 0x5001_0000,
};

/// The driver's DMA object (spec 7.3; spec 2, section 4): DMA_PAGES pages,
/// contiguous and uncached. The queue takes the first QUEUE_PAGES (its
/// driver and device areas, eight entries), and a request of the device
/// goes through the bounce page after them, copied out once the device
/// wrote it: the driver's own memory has no address the device knows.
/// Uncached: no cache maintenance, only the barriers of the queue.
pub mod dma {
    pub const DMA_PAGES: usize = 4;
    pub const PAGE: usize = 4096;
    pub const QUEUE_PAGES: usize = 2;
    /// The page of the bounce buffer; one request is with the device at a
    /// time.
    pub const BOUNCE_PAGE: usize = QUEUE_PAGES;
}

/// The Virtio device ID of an entropy source (Virtio 1.2, 5).
pub const ENTROPY_DEVICE: u32 = 4;

/// The registers of a virtio-mmio transport the driver reads before the
/// device's crate does (Virtio 1.2, 4.2.2): the magic "virt", the version
/// and the device ID; `Status`, which init writes 0 to once an instance
/// ended (init's table), is at 0x70.
pub mod mmio {
    pub const MAGIC: usize = 0x00;
    pub const MAGIC_VALUE: u32 = 0x7472_6976;
    pub const VERSION: usize = 0x04;
    pub const DEVICE_ID: usize = 0x08;
    pub const STATUS: usize = 0x70;
    /// The bytes of one transport on QEMU's `virt`.
    pub const LEN: usize = 0x200;
}

/// Whether the registers `read` gives are those of a virtio-mmio transport
/// of an entropy device, version 1 (legacy) or 2.
pub fn is_mmio_entropy(read: impl Fn(usize) -> u32) -> bool {
    read(mmio::MAGIC) == mmio::MAGIC_VALUE
        && matches!(read(mmio::VERSION), 1 | 2)
        && read(mmio::DEVICE_ID) == ENTROPY_DEVICE
}

#[cfg(test)]
mod tests {
    use super::*;

    // The console's BAR 0 takes 64 KiB from 0x1_0000_0000, its BAR 2
    // starts the 32-bit window (virtio_console::pci); each BAR is aligned
    // to its size.
    const _: () = assert!(PLACE.bar >= 0x1_0000_0000 + 0x1_0000);
    const _: () = assert!(PLACE.bar.is_multiple_of(PLACE.bar_len));
    const _: () = assert!(PLACE.bar2 > 0x5000_0000 && PLACE.bar2.is_multiple_of(64));

    #[test]
    fn the_bars_of_the_entropy_device_pass_the_consoles() {
        let writes = PLACE.set_up(0);
        assert_eq!(writes[1], (virtio_pci::BAR0, 0x0001_0004));
    }

    #[test]
    fn an_mmio_transport_must_be_an_entropy_device() {
        let regs = |magic: u32, version: u32, id: u32| {
            move |at: usize| match at {
                mmio::MAGIC => magic,
                mmio::VERSION => version,
                mmio::DEVICE_ID => id,
                _ => 0,
            }
        };
        assert!(is_mmio_entropy(regs(mmio::MAGIC_VALUE, 2, 4)));
        assert!(is_mmio_entropy(regs(mmio::MAGIC_VALUE, 1, 4)));
        // An empty transport of QEMU reads device ID 0.
        assert!(!is_mmio_entropy(regs(mmio::MAGIC_VALUE, 2, 0)));
        assert!(!is_mmio_entropy(regs(mmio::MAGIC_VALUE, 3, 4)));
        assert!(!is_mmio_entropy(regs(0, 2, 4)));
    }
}
