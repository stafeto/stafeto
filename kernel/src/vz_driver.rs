// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Virtio PCI console on the native Apple virtual platform.

extern crate alloc;

use alloc::alloc::{Layout, alloc_zeroed};
use core::alloc::GlobalAlloc;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use kcore::bootinfo::Region;
use kcore::layout::{LINEAR_BASE, image_pa};
use virtio_drivers::device::console::VirtIOConsole;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{Cam, DeviceFunction, MmioCam, PciRoot};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

const PCI: usize = LINEAR_BASE + 0x4002_8000;
const ECAM_PA: u64 = 0x4000_0000;
const ECAM: usize = LINEAR_BASE + ECAM_PA as usize;
const BAR_PA: u64 = 0x1_0000_0000;

/// The PCI windows this driver uses, ECAM and the console's BAR: the
/// kernel tables map them (mm::kmap), and no device window may reach them
/// (memory::forbid).
pub const DEVICES: [Region; 2] = [
    Region {
        base: ECAM_PA,
        size: 0x1000_0000,
    },
    Region {
        base: BAR_PA,
        size: 0x1_0000,
    },
];

#[repr(align(4096))]
struct Arena([u8; 128 * 1024]);
struct Storage(UnsafeCell<Arena>);
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage(UnsafeCell::new(Arena([0; 128 * 1024])));
static NEXT: AtomicUsize = AtomicUsize::new(0);
static KERNEL_PA: AtomicUsize = AtomicUsize::new(0);
type Console = VirtIOConsole<Host, PciTransport>;
struct ConsoleCell(UnsafeCell<MaybeUninit<Console>>);
unsafe impl Sync for ConsoleCell {}
static CONSOLE: ConsoleCell = ConsoleCell(UnsafeCell::new(MaybeUninit::uninit()));
static READY: AtomicBool = AtomicBool::new(false);

struct Bump;
#[global_allocator]
static ALLOCATOR: Bump = Bump;

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = STORAGE.0.get() as usize;
        let mut old = NEXT.load(Ordering::Relaxed);
        loop {
            let aligned = (base + old + layout.align() - 1) & !(layout.align() - 1);
            let Some(end) = aligned.checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            if end > base + 128 * 1024 {
                return core::ptr::null_mut();
            }
            match NEXT.compare_exchange_weak(old, end - base, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return aligned as *mut u8,
                Err(actual) => old = actual,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

pub fn dma_range() -> core::ops::Range<usize> {
    let start = unsafe { core::ptr::addr_of_mut!((*STORAGE.0.get()).0) as usize };
    start..start + 128 * 1024
}

pub fn prepare_dma() {
    // The boot table mapped the arena cacheable. Drop its cache lines before
    // the permanent tables map it as normal non-cacheable memory.
    for p in crate::arch::cache::data_lines(dma_range()) {
        unsafe {
            asm!("dc civac, {p}", p = in(reg) p, options(nostack, preserves_flags));
        }
    }
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

fn physical(pointer: usize) -> PhysAddr {
    image_pa(KERNEL_PA.load(Ordering::Relaxed) as u64, pointer)
}

fn sync(pointer: usize, size: usize, op: &str) {
    for p in crate::arch::cache::data_lines(pointer..pointer + size) {
        unsafe {
            match op {
                "clean" => asm!("dc cvac, {p}", p = in(reg) p, options(nostack, preserves_flags)),
                _ => asm!("dc ivac, {p}", p = in(reg) p, options(nostack, preserves_flags)),
            }
        }
    }
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

struct Host;
unsafe impl Hal for Host {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let layout = Layout::from_size_align(pages * 4096, 4096).unwrap();
        let pointer = unsafe { alloc_zeroed(layout) };
        let pointer = NonNull::new(pointer).expect("VZ DMA arena exhausted");
        (physical(pointer.as_ptr() as usize), pointer)
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        assert!(paddr >= BAR_PA && paddr + size as u64 <= BAR_PA + DEVICES[1].size);
        NonNull::new((LINEAR_BASE + paddr as usize) as *mut u8).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
        let pointer = buffer.as_ptr() as *mut u8 as usize;
        if matches!(
            direction,
            BufferDirection::DriverToDevice | BufferDirection::Both
        ) {
            sync(pointer, buffer.len(), "clean");
        }
        physical(pointer)
    }

    unsafe fn unshare(_paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
        if matches!(
            direction,
            BufferDirection::DeviceToDriver | BufferDirection::Both
        ) {
            sync(
                buffer.as_ptr() as *mut u8 as usize,
                buffer.len(),
                "invalidate",
            );
        }
    }
}

unsafe fn read16(p: usize) -> u16 {
    let v: u32;
    unsafe {
        asm!("ldrh {v:w}, [{p}]", v = out(reg) v, p = in(reg) p, options(nostack, preserves_flags));
    }
    v as u16
}
unsafe fn write16(p: usize, v: u16) {
    unsafe {
        asm!("strh {v:w}, [{p}]", v = in(reg) u32::from(v), p = in(reg) p, options(nostack, preserves_flags));
    }
}

pub fn init(kernel_pa: u64) {
    KERNEL_PA.store(kernel_pa as usize, Ordering::Relaxed);
    // SAFETY: the VZ kernel tables map the PCI windows as device memory.
    unsafe {
        assert_eq!(crate::arch::mmio::read32(PCI), 0x1043_1af4);
        let command = read16(PCI + 4);
        write16(PCI + 4, command & !2);
        crate::arch::mmio::write32(PCI + 0x10, 4);
        crate::arch::mmio::write32(PCI + 0x14, 1);
        crate::arch::mmio::write32(PCI + 0x18, 0x5000_0000);
        write16(PCI + 4, command | 6);
        let cam = MmioCam::new(ECAM as *mut u8, Cam::Ecam);
        let mut root = PciRoot::new(cam);
        let transport = PciTransport::new::<Host, _>(
            &mut root,
            DeviceFunction {
                bus: 0,
                device: 5,
                function: 0,
            },
        )
        .expect("VZ PCI transport");
        let mut console = VirtIOConsole::<Host, _>::new(transport).expect("VZ console");
        console
            .send_bytes(b"stafeto virtio console\r\n")
            .expect("VZ console transmit");
        (*CONSOLE.0.get()).write(console);
        READY.store(true, Ordering::Release);
    }
}

pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

pub fn write_bytes(bytes: &[u8]) {
    if !ready() {
        return;
    }
    // SAFETY: the single CPU owns the console whenever kernel code runs.
    let console = unsafe { (*CONSOLE.0.get()).assume_init_mut() };
    for part in bytes.split_inclusive(|&b| b == b'\n') {
        if let Some(line) = part.strip_suffix(b"\n") {
            if !line.is_empty() {
                console.send_bytes(line).expect("VZ console write");
            }
            console.send_bytes(b"\r\n").expect("VZ console newline");
        } else if !part.is_empty() {
            console.send_bytes(part).expect("VZ console write");
        }
    }
}

pub fn poll_input(out: &mut [u8]) -> usize {
    if !ready() {
        return 0;
    }
    // SAFETY: as in write_bytes; calls run with interrupts masked.
    let console = unsafe { (*CONSOLE.0.get()).assume_init_mut() };
    let mut count = 0;
    while count < out.len() {
        match console.recv(true) {
            Ok(Some(byte)) => {
                out[count] = byte;
                count += 1;
            }
            Ok(None) | Err(_) => break,
        }
    }
    count
}
