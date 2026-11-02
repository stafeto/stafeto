// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the drivers of virtio-mmio devices share on QEMU's `virt` (Virtio
//! 1.2, 4.2): the check of a transport before the driver writes to it
//! (`check`, `transport`), the device's crate over the DMA object of a
//! driver (`DmaHal`), the start of a device that offers `VIRTIO_F_VERSION_1`
//! and nothing else (`start`), and the interrupt (`Isr`, `reopen`).
//! Everything that needs no call of the kernel builds for the host too,
//! where `cargo test -p virtio-mmio` exercises it.
//!
//! A driver of a service uses it in this order:
//!
//! 1. maps the window init gives it and its DMA object, and tells the
//!    library where the object is (`attach`: address in the driver,
//!    physical address, pages, and how many of the first pages the queues
//!    take);
//! 2. `transport` checks the magic, the version and the device ID, and
//!    makes the device's `MmioTransport`; a transport with no device or
//!    another one is a `Reject`, before any write;
//! 3. `start` resets the device and negotiates `VERSION_1` alone;
//! 4. `VirtQueue::<DmaHal, N>::new(..)` takes the queues' pages from the
//!    first pages of the object; every buffer a queue's `add` gets lies in
//!    the object after them, so that the device's crate gets the physical
//!    address by a subtraction (`DmaHal::share`) and copies nothing;
//! 5. `transport.finish_init()` turns the device on;
//! 6. at a notification of the line, `Isr::read` reads the interrupt
//!    status (which also drops the level), the driver handles the queues,
//!    and `reopen` gives the line back (irq_ack) with the source cleared.
//!
//! The driver never waits for the device: it adds a request to a queue,
//! rings the doorbell (`rt::dma::wmb`, then `Transport::notify`) and goes
//! on; the interrupt brings the answer.

#![cfg_attr(not(test), no_std)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use virtio_drivers::device::common::Feature;
use virtio_drivers::transport::{DeviceStatus, InterruptStatus, Transport};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

/// The bytes of a page, of the DMA object and of the queues' places.
pub const PAGE: usize = 4096;

/// The Virtio device IDs the drivers of stafeto check for (Virtio 1.2, 5).
pub mod device {
    pub const ENTROPY: u32 = 4;
    pub const GPU: u32 = 16;
    pub const INPUT: u32 = 18;
}

/// The registers of a virtio-mmio transport the driver reads before the
/// device's crate does (Virtio 1.2, 4.2.2): the magic "virt", the version
/// (2 is the modern layout `VERSION_1` needs) and the device ID; `Status`
/// is where init writes 0 to stop the device once an instance ended.
pub mod regs {
    pub const MAGIC: usize = 0x00;
    pub const MAGIC_VALUE: u32 = 0x7472_6976;
    pub const VERSION: usize = 0x04;
    pub const DEVICE_ID: usize = 0x08;
    pub const INTERRUPT_STATUS: usize = 0x60;
    pub const STATUS: usize = 0x70;
    /// The version of the modern layout.
    pub const MODERN: u32 = 2;
    /// The bytes of one transport on QEMU's `virt`.
    pub const LEN: usize = 0x200;
}

/// Why a transport is not the device the driver wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The magic is not "virt": no transport there.
    Magic(u32),
    /// A legacy (1) or an unknown version: only the modern layout offers
    /// `VERSION_1`.
    Version(u32),
    /// Another device, or none: an empty transport of QEMU reads ID 0.
    Device(u32),
}

/// Whether the registers `read` gives are those of a modern virtio-mmio
/// transport of the device `device`. Reads only; the driver writes
/// nothing before this passes.
pub fn check(read: impl Fn(usize) -> u32, device: u32) -> Result<(), Reject> {
    let magic = read(regs::MAGIC);
    if magic != regs::MAGIC_VALUE {
        return Err(Reject::Magic(magic));
    }
    let version = read(regs::VERSION);
    if version != regs::MODERN {
        return Err(Reject::Version(version));
    }
    let id = read(regs::DEVICE_ID);
    if id != device {
        return Err(Reject::Device(id));
    }
    Ok(())
}

/// The DMA object of a driver and what is in it: the first `queue_pages`
/// pages go to the queues one `alloc` at a time, and the driver puts its
/// buffers in the pages after them. The arithmetic of `DmaHal`, apart from
/// the global it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arena {
    va: usize,
    pa: u64,
    pages: usize,
    queue_pages: usize,
    taken: usize,
}

impl Arena {
    /// The object mapped at `va` whose first byte is at the physical
    /// address `pa`: `pages` pages, the first `queue_pages` for the
    /// queues. None for no pages, more queue pages than pages, or an
    /// address that is no multiple of a page.
    pub const fn new(va: usize, pa: u64, pages: usize, queue_pages: usize) -> Option<Arena> {
        if pages == 0 || queue_pages > pages || !va.is_multiple_of(PAGE) || !pa.is_multiple_of(PAGE as u64) {
            return None;
        }
        Some(Arena {
            va,
            pa,
            pages,
            queue_pages,
            taken: 0,
        })
    }

    /// The first page of `pages` more for the queues; None when the queues'
    /// places are used up.
    pub fn alloc(&mut self, pages: usize) -> Option<usize> {
        let first = self.taken;
        let end = first.checked_add(pages)?;
        if pages == 0 || end > self.queue_pages {
            return None;
        }
        self.taken = end;
        Some(first)
    }

    /// The address in the driver of page `page`.
    pub fn page_va(&self, page: usize) -> usize {
        self.va + page * PAGE
    }

    /// The physical address of page `page`.
    pub fn page_pa(&self, page: usize) -> u64 {
        self.pa + (page * PAGE) as u64
    }

    /// The physical address of the `len` bytes at `va`, when all of them
    /// lie in the object after the queues' places; None otherwise, and for
    /// an empty range.
    pub fn phys(&self, va: usize, len: usize) -> Option<u64> {
        let start = self.va + self.queue_pages * PAGE;
        let end = self.va + self.pages * PAGE;
        let last = va.checked_add(len)?;
        if len == 0 || va < start || last > end {
            return None;
        }
        Some(self.pa + (va - self.va) as u64)
    }

    /// The pages after the queues': where the driver's buffers go.
    pub fn buffer_pages(&self) -> core::ops::Range<usize> {
        self.queue_pages..self.pages
    }
}

/// The driver's arena, for `DmaHal`: the Hal of the device's crate has no
/// state of its own, only functions. One thread of the driver reaches it.
struct Global {
    va: AtomicUsize,
    pa: AtomicUsize,
    pages: AtomicUsize,
    queue_pages: AtomicUsize,
    taken: AtomicUsize,
}

static GLOBAL: Global = Global {
    va: AtomicUsize::new(0),
    pa: AtomicUsize::new(0),
    pages: AtomicUsize::new(0),
    queue_pages: AtomicUsize::new(0),
    taken: AtomicUsize::new(0),
};

/// The address types of AArch64 are 64 bits, and so is usize there.
const _: () = assert!(usize::BITS >= 64 || cfg!(test));

impl Global {
    fn arena(&self) -> Arena {
        Arena {
            va: self.va.load(Ordering::Relaxed),
            pa: self.pa.load(Ordering::Relaxed) as u64,
            pages: self.pages.load(Ordering::Relaxed),
            queue_pages: self.queue_pages.load(Ordering::Relaxed),
            taken: self.taken.load(Ordering::Relaxed),
        }
    }
}

/// Tells `DmaHal` where the driver's DMA object is, before the first
/// queue: see `Arena::new`. False, and nothing set, when the arguments are
/// no object.
pub fn attach(va: usize, pa: u64, pages: usize, queue_pages: usize) -> bool {
    let Some(arena) = Arena::new(va, pa, pages, queue_pages) else {
        return false;
    };
    GLOBAL.va.store(arena.va, Ordering::Relaxed);
    GLOBAL.pa.store(arena.pa as usize, Ordering::Relaxed);
    GLOBAL.pages.store(arena.pages, Ordering::Relaxed);
    GLOBAL.queue_pages.store(arena.queue_pages, Ordering::Relaxed);
    GLOBAL.taken.store(0, Ordering::Relaxed);
    true
}

/// The arena `attach` set (all zero before it).
pub fn arena() -> Arena {
    GLOBAL.arena()
}

/// The DMA of the device's crate on the driver's object. The queues take
/// the object's first pages; a buffer that a queue's `add` gets lies in
/// the rest, and the device's physical address of it is the object's plus
/// its offset: nothing is copied, so a driver writes its commands where
/// the device reads them and reads the answers where the device wrote
/// them. A buffer outside the object is a fault of the driver, which stops
/// it (init starts it again).
pub struct DmaHal;

// SAFETY: `dma_alloc` gives pages of the driver's object, each at most
// once and zeroed, aligned to a page; `share` gives the physical address
// of a buffer inside the object or stops; `mmio_phys_to_virt` is for PCI
// BARs, which virtio-mmio has none of, and stops.
unsafe impl Hal for DmaHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let mut arena = GLOBAL.arena();
        // The crate takes a physical address of 0 for a failure.
        let Some(first) = arena.alloc(pages) else {
            return (0, NonNull::dangling());
        };
        GLOBAL.taken.store(arena.taken, Ordering::Relaxed);
        let va = arena.page_va(first);
        // SAFETY: the pages are the driver's object, mapped read and write
        // at `attach`'s address, and no one else has them; the crate
        // expects zeroes.
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, pages * PAGE) };
        match NonNull::new(va as *mut u8) {
            Some(at) => (arena.page_pa(first), at),
            None => (0, NonNull::dangling()),
        }
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // The queues live as long as the driver.
        0
    }

    unsafe fn mmio_phys_to_virt(_paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        panic!("virtio-mmio has no BAR");
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        let arena = GLOBAL.arena();
        match arena.phys(buffer.as_ptr().cast::<u8>() as usize, buffer.len()) {
            Some(pa) => pa,
            None => panic!("a buffer of a queue outside the driver's DMA object"),
        }
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}

/// The reads of the device's status after its reset, at most, before the
/// driver gives up: Virtio 1.2, 2.4.1, the reset is done once it reads 0.
pub const RESET_READS: u32 = 1_000_000;

/// Why `start` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// The device's status never read 0 after the reset.
    Reset,
    /// The device does not offer `VIRTIO_F_VERSION_1`; it has FAILED set.
    Features,
}

/// Resets the device and negotiates its features: `VIRTIO_F_VERSION_1`
/// alone, whatever else the device offers. The device forgets every queue
/// before it may master the bus again (Virtio 1.2, 2.4.1), which also
/// covers an instance whose stop by init did not run. The driver makes its
/// queues next and then calls `finish_init`.
pub fn start<T: Transport>(transport: &mut T) -> Result<(), StartError> {
    transport.set_status(DeviceStatus::empty());
    if !(0..RESET_READS).any(|_| transport.get_status().is_empty()) {
        return Err(StartError::Reset);
    }
    let negotiated: Feature = transport.begin_init(Feature::VERSION_1);
    if negotiated != Feature::VERSION_1 {
        transport.set_status(DeviceStatus::FAILED);
        return Err(StartError::Features);
    }
    Ok(())
}

/// What the interrupt status of a transport said (Virtio 1.2, 4.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Isr(u32);

impl Isr {
    const QUEUE: u32 = 1 << 0;
    const CONFIG: u32 = 1 << 1;

    pub const fn from_bits(bits: u32) -> Isr {
        Isr(bits)
    }

    /// Reads the interrupt status and acknowledges it, which drops the
    /// level of the line; nothing for the status 0.
    pub fn read<T: Transport>(transport: &mut T) -> Isr {
        Isr::from_status(transport.ack_interrupt())
    }

    fn from_status(status: InterruptStatus) -> Isr {
        Isr(status.bits())
    }

    /// A used buffer is in some queue.
    pub const fn queue(self) -> bool {
        self.0 & Isr::QUEUE != 0
    }

    /// The device's configuration changed.
    pub const fn config(self) -> bool {
        self.0 & Isr::CONFIG != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[cfg(target_os = "none")]
pub use device_side::*;

/// What needs the kernel's calls: the registers and the line.
#[cfg(target_os = "none")]
mod device_side {
    use super::*;
    use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};

    /// Why `transport` failed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum OpenError {
        Rejected(Reject),
        /// The device's crate took the registers for no usable transport.
        Unusable,
    }

    /// The transport of the device `device` whose registers start at
    /// `base`, after `check`: the status the device had before the
    /// driver's reset (0 at the machine's start and after init stopped the
    /// device of an instance that ended), for the driver's line.
    ///
    /// # Safety
    ///
    /// `base` is the start of a virtio-mmio transport of `regs::LEN`
    /// bytes in a device window the process maps read and write, and
    /// nothing else reaches the registers from here on.
    pub unsafe fn transport(
        base: usize,
        device: u32,
    ) -> Result<(MmioTransport<'static>, u32), OpenError> {
        // SAFETY: the registers read lie within the transport, aligned.
        let read = |offset: usize| unsafe { rt::mmio::read32(base + offset) };
        check(read, device).map_err(OpenError::Rejected)?;
        let status = read(regs::STATUS);
        let header = NonNull::new(base as *mut VirtIOHeader).ok_or(OpenError::Unusable)?;
        // SAFETY: the caller's promise.
        let transport = unsafe { MmioTransport::new(header, regs::LEN) };
        let transport = transport.map_err(|_| OpenError::Unusable)?;
        Ok((transport, status))
    }

    /// Opens the line again (irq_ack) once the source is cleared [G26]: the
    /// kernel masked it at delivery, and `Isr::read` dropped the level.
    pub fn reopen(irq: &rt::Handle<rt::handle::Interrupt>) {
        // The binding lives as long as the driver.
        let _ = rt::sys::irq_ack(irq);
    }

    /// Rings the doorbell of `queue` once the request is in it: the stores
    /// of the descriptors and the ring reach the device first.
    pub fn ring<T: Transport>(transport: &mut T, queue: u16) {
        rt::dma::wmb();
        transport.notify(queue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs_of(magic: u32, version: u32, id: u32) -> impl Fn(usize) -> u32 {
        move |at| match at {
            regs::MAGIC => magic,
            regs::VERSION => version,
            regs::DEVICE_ID => id,
            _ => 0,
        }
    }

    #[test]
    fn a_modern_transport_of_the_device_passes() {
        let ok = regs_of(regs::MAGIC_VALUE, 2, device::GPU);
        assert_eq!(check(ok, device::GPU), Ok(()));
    }

    #[test]
    fn an_empty_transport_reads_id_0() {
        let empty = regs_of(regs::MAGIC_VALUE, 2, 0);
        assert_eq!(check(empty, device::GPU), Err(Reject::Device(0)));
    }

    #[test]
    fn another_device_is_refused() {
        let rng = regs_of(regs::MAGIC_VALUE, 2, device::ENTROPY);
        assert_eq!(check(rng, device::GPU), Err(Reject::Device(4)));
    }

    #[test]
    fn legacy_and_unknown_versions_are_refused() {
        for version in [0, 1, 3] {
            let t = regs_of(regs::MAGIC_VALUE, version, device::GPU);
            assert_eq!(check(t, device::GPU), Err(Reject::Version(version)));
        }
    }

    #[test]
    fn the_magic_comes_first() {
        // No device at the address: the magic is wrong before the rest is
        // looked at.
        let none = regs_of(0, 2, device::GPU);
        assert_eq!(check(none, device::GPU), Err(Reject::Magic(0)));
    }

    #[test]
    fn the_arena_hands_out_the_queues_pages_in_order() {
        let mut a = Arena::new(0x10_0000_0000, 0x4000_0000, 16, 4).expect("an arena");
        assert_eq!(a.alloc(1), Some(0));
        assert_eq!(a.alloc(2), Some(1));
        assert_eq!(a.alloc(2), None);
        assert_eq!(a.alloc(1), Some(3));
        assert_eq!(a.alloc(1), None);
        assert_eq!(a.alloc(0), None);
        assert_eq!(a.page_va(3), 0x10_0000_3000);
        assert_eq!(a.page_pa(3), 0x4000_3000);
    }

    #[test]
    fn the_arena_refuses_what_is_no_object() {
        assert!(Arena::new(0, 0, 0, 0).is_none());
        assert!(Arena::new(0x1000, 0, 4, 5).is_none());
        assert!(Arena::new(0x1001, 0, 4, 1).is_none());
        assert!(Arena::new(0x1000, 0x10, 4, 1).is_none());
    }

    #[test]
    fn a_buffer_has_the_physical_address_of_its_offset() {
        let a = Arena::new(0x10_0000_0000, 0x4000_0000, 16, 4).expect("an arena");
        // The first buffer page, its first and last bytes, and the end.
        assert_eq!(a.phys(0x10_0000_4000, 56), Some(0x4000_4000));
        assert_eq!(a.phys(0x10_0000_4040, 24), Some(0x4000_4040));
        assert_eq!(a.phys(0x10_0001_0000 - 1, 1), Some(0x4000_FFFF));
        assert_eq!(a.buffer_pages(), 4..16);
    }

    #[test]
    fn a_buffer_outside_the_buffer_pages_has_no_address() {
        let a = Arena::new(0x10_0000_0000, 0x4000_0000, 16, 4).expect("an arena");
        // In the queues' pages, before the object, past its end, over its
        // end, empty, and a length that wraps the address space.
        assert_eq!(a.phys(0x10_0000_3FFF, 1), None);
        assert_eq!(a.phys(0x0FFF_FFFF_F000, 8), None);
        assert_eq!(a.phys(0x10_0001_0000, 1), None);
        assert_eq!(a.phys(0x10_0000_FFF8, 16), None);
        assert_eq!(a.phys(0x10_0000_4000, 0), None);
        assert_eq!(a.phys(0x10_0000_4000, usize::MAX), None);
    }

    #[test]
    fn the_interrupt_status_names_its_sources() {
        assert!(Isr::from_bits(1).queue() && !Isr::from_bits(1).config());
        assert!(Isr::from_bits(2).config() && !Isr::from_bits(2).queue());
        let both = Isr::from_bits(3);
        assert!(both.queue() && both.config());
        assert!(Isr::from_bits(0).is_empty());
    }

    #[test]
    fn the_hal_takes_the_queues_pages_of_the_attached_object() {
        // The one test that touches the global: a page-aligned buffer of
        // the host stands for the object.
        #[repr(align(4096))]
        struct Pages([u8; 16 * PAGE]);
        let mut pages = Box::new(Pages([0xAA; 16 * PAGE]));
        let va = pages.0.as_mut_ptr() as usize;
        assert!(!attach(va + 1, 0, 16, 4));
        assert!(attach(va, 0x8000_0000, 16, 4));
        let (pa, at) = DmaHal::dma_alloc(2, BufferDirection::Both);
        assert_eq!(pa, 0x8000_0000);
        assert_eq!(at.as_ptr() as usize, va);
        assert!(pages.0[..2 * PAGE].iter().all(|&b| b == 0));
        assert!(pages.0[2 * PAGE..].iter().all(|&b| b == 0xAA));
        let (pa, _) = DmaHal::dma_alloc(3, BufferDirection::Both);
        assert_eq!(pa, 0, "past the queues' pages");
        let buffer = NonNull::from(&mut pages.0[4 * PAGE + 8..4 * PAGE + 64]);
        // SAFETY: the buffer is inside the attached object.
        let shared = unsafe { DmaHal::share(buffer, BufferDirection::DriverToDevice) };
        assert_eq!(shared, 0x8000_0000 + 4 * PAGE as u64 + 8);
    }
}
