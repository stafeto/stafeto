// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the kernel learns at boot: the device tree's information, the memory
//! the boot itself occupies and the RAM left for the allocator.

use crate::arch::symbols;
use kcore::bootinfo::{self, BootInfo, Region, RegionList};
use kcore::fdt::{self, Fdt};
use kcore::layout::{LINEAR_BASE, dtb_gib_is_mappable, fits_in_one_gib};
use kcore::memmap;

pub struct Boot {
    pub info: BootInfo,
    pub kernel_pa: u64,
    /// The kernel image in physical memory, including .bss, the boot stack
    /// and the boot page tables.
    pub kernel_image: Region,
    pub dtb: Region,
    /// RAM nothing uses yet, in whole pages, sorted.
    pub usable: RegionList<32>,
}

pub fn collect(dtb_pa: usize, kernel_pa: usize) -> Boot {
    if dtb_pa == 0 {
        panic!("no device tree in x0: boot the arm64 Image, not the ELF");
    }
    if !dtb_gib_is_mappable(dtb_pa as u64) {
        panic!("device tree pointer {dtb_pa:#x} is outside the RAM the boot page tables map");
    }
    let dtb = (LINEAR_BASE + dtb_pa) as *const u8;
    if !fits_in_one_gib(dtb_pa as u64, fdt::HEADER_SIZE as u64) {
        panic!("device tree header at {dtb_pa:#x} crosses a GiB boundary");
    }
    // SAFETY: head.S mapped the GiB holding the device tree; the header lies in it.
    let header = unsafe { core::slice::from_raw_parts(dtb, fdt::HEADER_SIZE) };
    let total = fdt::total_size_from_header(header)
        .unwrap_or_else(|e| panic!("device tree at {dtb_pa:#x}: {e:?}"));
    if !fits_in_one_gib(dtb_pa as u64, total as u64) {
        panic!("device tree at {dtb_pa:#x} crosses a GiB boundary; only its first GiB is mapped");
    }
    // SAFETY: the whole blob lies in the mapped GiB, and nothing writes to it.
    let fdt = unsafe { Fdt::from_ptr(dtb) }
        .unwrap_or_else(|e| panic!("device tree at {dtb_pa:#x}: {e:?}"));
    let info = bootinfo::parse(&fdt).unwrap_or_else(|e| panic!("device tree: {e:?}"));

    let image = symbols::image();
    let kernel_image = Region {
        base: kernel_pa as u64,
        size: (image.end - image.start) as u64,
    };
    let dtb = Region {
        base: dtb_pa as u64,
        size: total as u64,
    };
    let mut taken: RegionList<24> = RegionList::new();
    let boot_regions = [Some(kernel_image), Some(dtb), info.initrd];
    for r in boot_regions
        .into_iter()
        .flatten()
        .chain(info.reserved.as_slice().iter().copied())
    {
        taken
            .push(r)
            .unwrap_or_else(|e| panic!("boot reservations: {e:?}"));
    }
    let usable = memmap::usable(info.memory.as_slice(), taken.as_slice())
        .unwrap_or_else(|e| panic!("memory map: {e:?}"));
    Boot {
        info,
        kernel_pa: kernel_pa as u64,
        kernel_image,
        dtb,
        usable,
    }
}
