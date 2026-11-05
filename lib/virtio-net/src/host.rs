// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The DMA of the device's crate over a driver's objects: the pages of the
//! queues (one object, uncached) and the buffers of the frames (up to
//! `REGIONS` objects, cached). The crate's `Hal` is a set of functions with
//! no state, so each device of a driver is a type parameter `Host<D>` over
//! its own slot of the statics: the network service drives two devices,
//! slot 0 and slot 1.
//!
//! The buffers are cached memory and no cache line is cleaned or
//! invalidated: a device without VIRTIO_F_ACCESS_PLATFORM sees the memory
//! of the guest as a coherent processor does (Virtio 1.2, 6.1), and TCG,
//! HVF and Apple VZ all keep host and guest in one coherent domain. A
//! machine with a device outside that domain cleans the lines in `share`
//! and `unshare` and nowhere else. The barriers that order the stores to a
//! ring are `barrier::ring` and `barrier::rmb`.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

/// The bytes of a page.
pub const PAGE: usize = 4096;
/// The devices the statics have room for.
pub const DEVICES: usize = 2;
/// The objects of buffers one device has at most: one 4 MiB object holds
/// 2 048 buffers of 2 KiB, and a driver that wants 8 192 takes four.
pub const REGIONS: usize = 4;

/// Memory a device reaches: mapped at `va` in the driver, at `pa` for the
/// device, `len` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub va: usize,
    pub pa: u64,
    pub len: usize,
}

impl Region {
    /// The physical address of the `len` bytes at `va`, when all of them lie
    /// in the region; None otherwise, and for an empty range.
    pub fn phys(&self, va: usize, len: usize) -> Option<u64> {
        let last = va.checked_add(len)?;
        if len == 0 || va < self.va || last > self.va.checked_add(self.len)? {
            return None;
        }
        Some(self.pa + (va - self.va) as u64)
    }
}

/// The physical address of the `len` bytes at `va`, when all of them lie in
/// one of `regions`.
pub fn phys_in(regions: &[Region], va: usize, len: usize) -> Option<u64> {
    regions.iter().find_map(|r| r.phys(va, len))
}

struct Place {
    va: AtomicUsize,
    pa: AtomicU64,
    len: AtomicUsize,
}

impl Place {
    const fn new() -> Place {
        Place {
            va: AtomicUsize::new(0),
            pa: AtomicU64::new(0),
            len: AtomicUsize::new(0),
        }
    }

    fn set(&self, r: Region) {
        self.va.store(r.va, Ordering::Relaxed);
        self.pa.store(r.pa, Ordering::Relaxed);
        self.len.store(r.len, Ordering::Relaxed);
    }

    fn get(&self) -> Region {
        Region {
            va: self.va.load(Ordering::Relaxed),
            pa: self.pa.load(Ordering::Relaxed),
            len: self.len.load(Ordering::Relaxed),
        }
    }
}

struct Slot {
    queues: Place,
    queue_taken: AtomicUsize,
    buffers: [Place; REGIONS],
    count: AtomicUsize,
    /// BAR 0 of a PCI device, which the crate asks a virtual address of for
    /// each Virtio structure.
    bar: Place,
}

static SLOTS: [Slot; DEVICES] = [const {
    Slot {
        queues: Place::new(),
        queue_taken: AtomicUsize::new(0),
        buffers: [const { Place::new() }; REGIONS],
        count: AtomicUsize::new(0),
        bar: Place::new(),
    }
}; DEVICES];

/// Tells device `d` where its memory is, before its first queue: the pages
/// of the queues (`queues`, page-aligned, which the queues take from the
/// start one `dma_alloc` at a time) and the objects of its buffers
/// (`buffers`, at most REGIONS). False, and nothing set, for a device past
/// the statics, too many objects or queues off a page.
pub fn attach(d: usize, queues: Region, buffers: &[Region]) -> bool {
    let Some(slot) = SLOTS.get(d) else {
        return false;
    };
    if buffers.len() > REGIONS
        || !queues.va.is_multiple_of(PAGE)
        || !queues.pa.is_multiple_of(PAGE as u64)
    {
        return false;
    }
    slot.queues.set(queues);
    slot.queue_taken.store(0, Ordering::Relaxed);
    for (place, r) in slot.buffers.iter().zip(buffers) {
        place.set(*r);
    }
    slot.count.store(buffers.len(), Ordering::Relaxed);
    true
}

/// Tells device `d` where its BAR 0 lies: the structures of a Virtio PCI
/// device are in it. False for a device past the statics.
pub fn attach_bar(d: usize, bar: Region) -> bool {
    let Some(slot) = SLOTS.get(d) else {
        return false;
    };
    slot.bar.set(bar);
    true
}

/// The DMA of device `D`.
pub struct Host<const D: usize>;

impl<const D: usize> Host<D> {
    const OK: () = assert!(D < DEVICES);

    /// The physical address of the buffer at `va` of `len` bytes, when it
    /// lies in one of the device's objects of buffers.
    #[inline]
    pub fn phys(va: usize, len: usize) -> Option<u64> {
        #[allow(clippy::let_unit_value)]
        let _ = Self::OK;
        let slot = &SLOTS[D];
        let count = slot.count.load(Ordering::Relaxed).min(REGIONS);
        slot.buffers[..count]
            .iter()
            .find_map(|place| place.get().phys(va, len))
    }
}

// SAFETY: `dma_alloc` gives zeroed pages of the queues' object, each at
// most once and aligned to a page, or the address 0 for a failure; `share`
// gives the physical address of a buffer inside an object of buffers or
// stops the driver; `mmio_phys_to_virt` gives an address inside the mapping
// of BAR 0 for a structure inside BAR 0 of the device, and stops the driver
// for any other.
unsafe impl<const D: usize> Hal for Host<D> {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        #[allow(clippy::let_unit_value)]
        let _ = Self::OK;
        let slot = &SLOTS[D];
        let queues = slot.queues.get();
        let first = slot.queue_taken.load(Ordering::Relaxed);
        let Some(end) = first.checked_add(pages).filter(|&e| e <= queues.len / PAGE) else {
            // The crate takes a physical address of 0 for a failure.
            return (0, NonNull::dangling());
        };
        slot.queue_taken.store(end, Ordering::Relaxed);
        let va = queues.va + first * PAGE;
        let pa = queues.pa + (first * PAGE) as u64;
        // SAFETY: the pages are the queues' object, mapped read and write at
        // its address, and no one else has them; the crate expects zeroes.
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, pages * PAGE) };
        match NonNull::new(va as *mut u8) {
            Some(at) => (pa, at),
            None => (0, NonNull::dangling()),
        }
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // The queues live as long as the driver.
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        let bar = SLOTS[D].bar.get();
        let offset = paddr.wrapping_sub(bar.pa);
        assert!(
            offset.saturating_add(size as u64) <= bar.len as u64,
            "a Virtio structure outside BAR 0"
        );
        NonNull::new((bar.va + offset as usize) as *mut u8)
            .expect("the mapping of BAR 0 is no null")
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        match Self::phys(buffer.as_ptr().cast::<u8>() as usize, buffer.len()) {
            Some(pa) => pa,
            None => panic!("a buffer of a queue outside the objects of buffers"),
        }
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: usize = 1 << 20;

    /// Four objects of 4 MiB, mapped one after another in the driver and
    /// scattered in physical memory.
    fn four() -> [Region; 4] {
        let pas = [0x4800_0000, 0x4040_0000, 0x5200_0000, 0x4c00_0000];
        core::array::from_fn(|i| Region {
            va: 0x20_0000_0000 + i * 4 * MIB,
            pa: pas[i],
            len: 4 * MIB,
        })
    }

    #[test]
    fn each_buffer_takes_the_base_of_its_own_object() {
        let regions = four();
        for (i, r) in regions.iter().enumerate() {
            for at in [0, 2048, 4 * MIB - 2048] {
                assert_eq!(
                    phys_in(&regions, r.va + at, 2048),
                    Some(r.pa + at as u64),
                    "object {i}, offset {at:#x}"
                );
            }
        }
    }

    #[test]
    fn a_buffer_across_two_objects_or_outside_all_has_no_address() {
        let regions = four();
        // The last kilobyte of the first object and the first of the second
        // are next to each other in the driver, and far apart for the device.
        assert_eq!(phys_in(&regions, regions[1].va - 1024, 2048), None);
        assert_eq!(phys_in(&regions, regions[0].va - 1, 1), None);
        assert_eq!(phys_in(&regions, regions[3].va + 4 * MIB, 1), None);
        assert_eq!(phys_in(&regions, regions[2].va, 0), None, "empty");
        assert_eq!(phys_in(&regions, usize::MAX, 2), None);
        assert_eq!(phys_in(&[], regions[0].va, 1), None);
    }

    #[test]
    fn the_slot_finds_the_object_and_hands_out_the_queues_pages_once() {
        let queues = vec![0xAAu8; 3 * PAGE + PAGE];
        let start = (queues.as_ptr() as usize).next_multiple_of(PAGE);
        let regions = four();
        assert!(attach(
            1,
            Region {
                va: start,
                pa: 0x4100_0000,
                len: 3 * PAGE
            },
            &regions
        ));
        for r in regions {
            assert_eq!(Host::<1>::phys(r.va + 4096, 1514), Some(r.pa + 4096));
        }
        let (pa, at) = Host::<1>::dma_alloc(2, BufferDirection::Both);
        assert_eq!((pa, at.as_ptr() as usize), (0x4100_0000, start));
        // SAFETY: the two pages lie in `queues`.
        let zeroed = unsafe { core::slice::from_raw_parts(start as *const u8, 2 * PAGE) };
        assert!(zeroed.iter().all(|&b| b == 0));
        let (pa, _) = Host::<1>::dma_alloc(1, BufferDirection::Both);
        assert_eq!(pa, 0x4100_0000 + 2 * PAGE as u64);
        assert_eq!(
            Host::<1>::dma_alloc(1, BufferDirection::Both).0,
            0,
            "used up"
        );
        assert!(!attach(2, regions[0], &[]), "no third device");
        assert!(!attach(1, regions[0], &[regions[0]; 5]), "five objects");
    }
}
