// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the kernel learns at boot: the device tree's information, the memory
//! the boot itself occupies, the RAM left for the allocator, and init from
//! the boot image.

use crate::arch::symbols;
use bootimg::{BootImage, Program};
use kcore::bootinfo::{self, BootInfo, Region, RegionList};
use kcore::fdt::{self, Fdt};
use kcore::layout::{LINEAR_BASE, dtb_gib_is_mappable, fits_in_one_gib};
use kcore::memmap;
use kcore::sync::SetOnce;

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

/// What `collect` found. Static: every entry from EL0 starts over at the top
/// of the kernel stack, so after the first one nothing is left of
/// `kernel_main`'s frame (spec 8.1).
static BOOT: SetOnce<Boot> = SetOnce::new();

/// Reads the device tree and works out the usable RAM, once.
pub fn collect(dtb_pa: usize, kernel_pa: usize) -> &'static Boot {
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
    let blob = unsafe { core::slice::from_raw_parts(dtb, total) };
    let fdt = Fdt::new(blob).unwrap_or_else(|e| panic!("device tree at {dtb_pa:#x}: {e:?}"));
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
    let boot = Boot {
        info,
        kernel_pa: kernel_pa as u64,
        kernel_image,
        dtb,
        usable,
    };
    BOOT.set(boot)
        .unwrap_or_else(|_| panic!("boot::collect runs once"))
}

/// Init from the boot image (spec 3.3, 13.1), checked in full: where the
/// image lies (memmap::check_boot_image), its header and table, that it
/// is whole pages, which init maps as a memory object, then init's
/// program. The kernel reads the image through the linear map, so only
/// once its own tables map all RAM; the allocator never gets the image's
/// frames, so the bytes stay for good. A boot image that is missing,
/// damaged, cut short or not whole pages stops the boot here with a panic
/// that says what is wrong.
pub fn init_program(boot: &Boot) -> Program<'static> {
    let Some(r) = boot.info.initrd else {
        panic!("no boot image: QEMU takes it with -initrd, U-Boot's booti as its ramdisk");
    };
    memmap::check_boot_image(
        boot.info.memory.as_slice(),
        boot.info.no_map.as_slice(),
        r,
        boot.kernel_image,
        boot.dtb,
    )
    .unwrap_or_else(|e| panic!("boot image {:#x}..{:#x} {e}", r.base, r.end()));
    // SAFETY: the image lies in RAM the linear map covers, apart from the
    // kernel and the device tree, and the allocator never gets its frames,
    // so nothing writes to it.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (LINEAR_BASE + r.base as usize) as *const u8,
            r.size as usize,
        )
    };
    let image = BootImage::parse(bytes).unwrap_or_else(|e| panic!("boot image: {e}"));
    if !r.size.is_multiple_of(kcore::PAGE_SIZE) {
        panic!("boot image: not whole pages");
    }
    let init = image.init().unwrap_or_else(|e| panic!("boot image: {e}"));
    Program::parse(init).unwrap_or_else(|e| panic!("boot image: init: {e}"))
}
