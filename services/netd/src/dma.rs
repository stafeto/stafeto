// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The DMA of the device's crate over the two objects of the service: `dma`
//! (the pages of the queues, uncached) and `net` (the buffers of the two
//! rings, cached). The crate's `Hal` is a set of functions with no state,
//! so each device of the service is a type parameter `Host<D>` over its own
//! slot of the statics. The first stage serves device 0; the addresses
//! below leave room for a second.
//!
//! The buffers are cached memory and no cache line is cleaned or
//! invalidated: a device without VIRTIO_F_ACCESS_PLATFORM sees the memory
//! of the guest as a coherent processor does (Virtio 1.2, 6.1), and TCG,
//! HVF and Apple VZ all keep host and guest in one coherent domain. A
//! machine with a device outside that domain cleans the lines in `share`
//! and `unshare` and nowhere else. The barriers that order the stores to a
//! ring are `virtio_mmio::ring` and `rt::dma::rmb`.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use netd::ring::NET_PAGES;
use virtio_drivers::{BufferDirection, Hal, PhysAddr};
use virtio_mmio::{Arena, PAGE};

/// The devices the statics have room for.
pub const DEVICES: usize = 2;
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

struct Slot {
    dma_pa: AtomicU64,
    net_pa: AtomicU64,
    queue_taken: AtomicUsize,
}

static SLOTS: [Slot; DEVICES] = [const {
    Slot {
        dma_pa: AtomicU64::new(0),
        net_pa: AtomicU64::new(0),
        queue_taken: AtomicUsize::new(0),
    }
}; DEVICES];

/// Tells device `d` the physical addresses of its two objects, before the
/// first queue.
pub fn attach(d: usize, dma_pa: u64, net_pa: u64) {
    let slot = &SLOTS[d];
    slot.dma_pa.store(dma_pa, Ordering::Relaxed);
    slot.net_pa.store(net_pa, Ordering::Relaxed);
    slot.queue_taken.store(0, Ordering::Relaxed);
}

/// The DMA of device `D`.
pub struct Host<const D: usize>;

impl<const D: usize> Host<D> {
    const OK: () = assert!(D < DEVICES);
}

// SAFETY: `dma_alloc` gives zeroed pages of the object `dma`, each at most
// once and aligned to a page, or the address 0 for a failure; `share`
// gives the physical address of a buffer inside the object `net` or stops
// the service; `mmio_phys_to_virt` is for PCI BARs, which virtio-mmio has
// none of, and stops.
unsafe impl<const D: usize> Hal for Host<D> {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        #[allow(clippy::let_unit_value)]
        let _ = Self::OK;
        let slot = &SLOTS[D];
        let first = slot.queue_taken.load(Ordering::Relaxed);
        let Some(end) = first.checked_add(pages).filter(|&e| e <= DMA_PAGES) else {
            // The crate takes a physical address of 0 for a failure.
            return (0, NonNull::dangling());
        };
        slot.queue_taken.store(end, Ordering::Relaxed);
        let va = dma_at(D) + first * PAGE;
        let pa = slot.dma_pa.load(Ordering::Relaxed) + (first * PAGE) as u64;
        // SAFETY: the pages are the object `dma`, mapped read and write at
        // dma_at(D), and no one else has them; the crate expects zeroes.
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, pages * PAGE) };
        match NonNull::new(va as *mut u8) {
            Some(at) => (pa, at),
            None => (0, NonNull::dangling()),
        }
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // The queues live as long as the service.
        0
    }

    unsafe fn mmio_phys_to_virt(_paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        panic!("virtio-mmio has no BAR");
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        let net_pa = SLOTS[D].net_pa.load(Ordering::Relaxed);
        let arena = Arena::new(net_at(D), net_pa, NET_PAGES, 0);
        let va = buffer.as_ptr().cast::<u8>() as usize;
        match arena.and_then(|a| a.phys(va, buffer.len())) {
            Some(pa) => pa,
            None => panic!("a buffer of a queue outside the object net"),
        }
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}
