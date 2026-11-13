// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loader's check of its own tree and placement with the kernel's code
//! (`kcore::bootinfo::parse`, `kcore::memmap`, `kcore::layout`), repeating
//! what `kernel::boot::collect` and `boot::init_program` do. A panic of the
//! kernel before it reads the tree is not visible on EC2 (spec 3.2), so the
//! loader finds every such panic first and prints it (the note, 2.2).

use crate::error::Error;
use kcore::bootinfo::{BOOT_TAKEN, BootInfo, BootInfoError, Region, RegionList, USABLE_REGIONS};
use kcore::fdt::{self, Fdt};
use kcore::layout::{dtb_gib_is_mappable, fits_in_one_gib};
use kcore::memmap;

// The arm64 Image header (Linux booting.rst), as `xtask::image` checks it.
const IMAGE_SIZE_OFFSET: usize = 0x10;
const TEXT_OFFSET: usize = 0x8;
const FLAGS_OFFSET: usize = 0x18;
const MAGIC_OFFSET: usize = 0x38;
const MAGIC: u32 = 0x644d_5241;
/// Little endian, 4 KiB pages, may be placed anywhere in RAM.
const FLAGS: u64 = 0xa;
const TWO_MIB: u64 = 2 << 20;

/// The number of bytes the kernel occupies in memory, from its header: the
/// magic, `text_offset` 0, the flags `head.S` is built for and an
/// `image_size` that covers the file.
pub fn image_size(file: &[u8]) -> Result<u64, Error> {
    let u32_at = |o: usize| crate::acpi::u32_at(file, o);
    let u64_at = |o: usize| crate::acpi::u64_at(file, o);
    let short = Error::Truncated("kernel image header");
    if u32_at(MAGIC_OFFSET).ok_or(short)? != MAGIC {
        return Err(Error::BadSignature("kernel image (arm64 magic)"));
    }
    if u64_at(TEXT_OFFSET).ok_or(short)? != 0 {
        return Err(Error::Unsupported("kernel image text_offset is not 0"));
    }
    if u64_at(FLAGS_OFFSET).ok_or(short)? != FLAGS {
        return Err(Error::Unsupported("kernel image flags"));
    }
    let size = u64_at(IMAGE_SIZE_OFFSET).ok_or(short)?;
    if size < file.len() as u64 {
        return Err(Error::Unsupported(
            "kernel image_size is smaller than the file",
        ));
    }
    Ok(size)
}

/// Where the loader put things, as physical regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    /// The kernel from its first byte, `image_size` long.
    pub kernel: Region,
    pub tree: Region,
    pub boot_image: Region,
}

/// What the check found, for the loader's summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub memory: usize,
    pub reserved: usize,
    pub no_map: usize,
    pub usable: usize,
    pub cpus: usize,
    pub msi_entries: usize,
}

fn describe(e: BootInfoError) -> Error {
    Error::Check(match e {
        BootInfoError::Fdt(_) => "the tree is not a valid device tree",
        BootInfoError::BadReg => "a property of the tree (reg, ranges, msi-map) is malformed",
        BootInfoError::BadInitrd => "the tree's boot image range ends before it starts",
        BootInfoError::TooManyRegions => "the tree has more regions than the kernel's lists hold",
        BootInfoError::NoMemory => "the tree has no memory",
    })
}

/// Checks `blob` placed as `at` the way the kernel will: the tree and the
/// kernel lie where `head.S` maps them, the kernel's parse accepts the tree,
/// the lists hold the reservations, and the boot image lies where the
/// kernel reads it.
pub fn check(blob: &[u8], at: &Placement) -> Result<(Summary, BootInfo), Error> {
    if !at.kernel.base.is_multiple_of(TWO_MIB) {
        return Err(Error::Check("the kernel is not at a 2 MiB boundary"));
    }
    if !dtb_gib_is_mappable(at.kernel.base) || !fits_in_one_gib(at.kernel.base, at.kernel.size) {
        return Err(Error::Check("the kernel is not inside one GiB of 1..511"));
    }
    // `break-dtb-gib` leaves the tree's GiB unchecked, for the run that must
    // see the kernel's own panic.
    if !cfg!(feature = "break-dtb-gib") {
        if !dtb_gib_is_mappable(at.tree.base) {
            return Err(Error::Check(
                "the tree is outside the GiBs the boot page tables map",
            ));
        }
        if !fits_in_one_gib(at.tree.base, fdt::HEADER_SIZE as u64)
            || !fits_in_one_gib(at.tree.base, blob.len() as u64)
        {
            return Err(Error::Check("the tree crosses a GiB boundary"));
        }
    }
    let tree = Fdt::new(blob).map_err(|_| Error::Check("the tree is not a valid device tree"))?;
    let info = kcore::bootinfo::parse(&tree).map_err(describe)?;
    if info.gic.is_none() {
        return Err(Error::Check("the tree has no interrupt controller"));
    }
    if info.cpus.as_slice().is_empty() {
        return Err(Error::Check("the tree has no CPUs"));
    }
    if info.initrd != Some(at.boot_image) {
        return Err(Error::Check(
            "the tree names another boot image than the loader read",
        ));
    }
    let blob_region = Region {
        base: at.tree.base,
        size: blob.len() as u64,
    };
    let inside_ram = |r: Region| {
        memmap::usable::<USABLE_REGIONS>(info.memory.as_slice(), info.no_map.as_slice())
            .map(|u| {
                u.as_slice()
                    .iter()
                    .any(|m| m.base <= r.base && r.end() <= m.end())
            })
            .unwrap_or(false)
    };
    if !inside_ram(at.kernel) || !inside_ram(blob_region) {
        return Err(Error::Check(
            "the kernel or the tree is not in usable memory",
        ));
    }
    // `boot::collect`: the kernel, the tree, the boot image, then everything
    // reserved, in `taken`.
    let mut taken: RegionList<BOOT_TAKEN> = RegionList::new();
    for r in [at.kernel, blob_region, at.boot_image]
        .into_iter()
        .chain(info.reserved.as_slice().iter().copied())
    {
        taken.push(r).map_err(describe)?;
    }
    let usable = memmap::usable::<USABLE_REGIONS>(info.memory.as_slice(), taken.as_slice())
        .map_err(|_| Error::Check("memory minus the boot's reservations has too many pieces"))?;
    memmap::check_boot_image(
        info.memory.as_slice(),
        info.no_map.as_slice(),
        at.boot_image,
        at.kernel,
        blob_region,
    )
    .map_err(|_| Error::Check("the boot image lies where the kernel cannot read it"))?;
    let summary = Summary {
        memory: info.memory.as_slice().len(),
        reserved: info.reserved.as_slice().len(),
        no_map: info.no_map.as_slice().len(),
        usable: usable.as_slice().len(),
        cpus: info.cpus.as_slice().len(),
        msi_entries: info.msi_map().count(),
    };
    Ok((summary, info))
}
