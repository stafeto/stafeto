// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Where the service maps the objects and the windows of its devices, and
//! the DMA of the device's crate over them (`virtio_net::host`): device `d`
//! has the pages of its queues at `dma_at(d)` (the object `dma`, or `dma1`
//! for the second device, uncached) and its 512 buffers at `net_at(d)` (the
//! object `net`, or the first megabyte of `net1a`, cached), each device in
//! its own slot of the library's statics (`Host<D>`).

use netd::pci;
use netd::ring::NET_PAGES;
use virtio_mmio::PAGE;
pub use virtio_net::Host;
use virtio_net::Region;

/// The pages of the object `dma`: the two queues take three each.
pub const DMA_PAGES: usize = 8;

/// Where the service maps the objects and the transport page of device
/// `d`.
pub const fn dma_at(d: usize) -> usize {
    0x10_0000_0000 + d * 0x0100_0000
}

pub const fn net_at(d: usize) -> usize {
    0x10_0400_0000 + d * 0x0100_0000
}

pub const fn mmio_at(d: usize) -> usize {
    0x10_1000_0000 + d * 0x1_0000
}

/// Where the service maps the window `ecam` (the pages of the functions)
/// and the window `bar` (the BARs 0 of the devices) of VZ; device `d`
/// takes its own offset inside each (`netd::pci`).
pub const fn ecam_at() -> usize {
    0x10_2000_0000
}

pub const fn bar_at() -> usize {
    0x10_3000_0000
}

/// Where the service maps the shared buffers of the sessions (BUFFER): entry
/// `i` of `netd::buffers` at `BUFFERS_AT + i * BUFFER_SPAN`, above the
/// windows and the objects of the devices.
pub const BUFFERS_AT: usize = 0x11_0000_0000;
pub const BUFFER_SPAN: usize = proto_net::BUFFER_SIZE;

pub const fn buffer_at(i: usize) -> usize {
    BUFFERS_AT + i * BUFFER_SPAN
}

const _: () = assert!(bar_at() + 0x1000_0000 <= BUFFERS_AT);
const _: () = assert!(BUFFER_SPAN == 0x4_0000);

/// Tells device `d` the physical addresses of its two objects, before the
/// first queue: the queues take the first DMA_PAGES pages of `dma`, the
/// buffers the NET_PAGES pages of `net`.
pub fn attach(d: usize, dma_pa: u64, net_pa: u64) -> bool {
    let queues = Region {
        va: dma_at(d),
        pa: dma_pa,
        len: DMA_PAGES * PAGE,
    };
    let buffers = Region {
        va: net_at(d),
        pa: net_pa,
        len: NET_PAGES * PAGE,
    };
    virtio_net::host::attach(d, queues, &[buffers])
}

/// BAR 0 of the PCI device `d` of VZ: where the window `bar` maps it, and
/// where it lies for the device.
pub fn bar(d: usize) -> Region {
    let place = &pci::PLACES[d];
    Region {
        va: bar_at() + pci::bar_offset(d) as usize,
        pa: place.bar,
        len: place.bar_len as usize,
    }
}
