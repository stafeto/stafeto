// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The EFI memory map as the device tree's `memory` and `reserved-memory`
//! (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section 4). The rule is Linux arm64's
//! (`drivers/firmware/efi/efi-init.c`, `reserve_regions`): memory is what
//! carries the write-back attribute, and what the firmware keeps (runtime
//! services, ACPI, reserved) is withheld from the kernel with `no-map`.

use crate::error::Error;
use alloc::vec::Vec;
use kboot::bootinfo::{MEMORY_REGIONS, Region};
use kcore::layout::{GIB, fits_in_one_gib};

/// `EFI_MEMORY_WB` (UEFI 2.10, "GetMemoryMap()").
pub const ATTR_WB: u64 = 0x8;

/// The kernel's list of `no-map` regions is the narrowest of the lists a
/// reserved range goes in (`BootInfo::no_map`), and every reserved range here
/// is `no-map`.
pub const NO_MAP_REGIONS: usize = 8;

const PAGE: u64 = 4096;

// Memory types (UEFI 2.10, "GetMemoryMap()").
const LOADER_CODE: u32 = 1;
const LOADER_DATA: u32 = 2;
const BOOT_CODE: u32 = 3;
const BOOT_DATA: u32 = 4;
pub const CONVENTIONAL: u32 = 7;
const MMIO: u32 = 11;
const MMIO_PORT: u32 = 12;

/// One descriptor of the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desc {
    pub ty: u32,
    pub phys: u64,
    pub pages: u64,
    pub attr: u64,
}

impl Desc {
    fn region(&self) -> Region {
        Region {
            base: self.phys,
            size: self.pages * PAGE,
        }
    }

    /// Memory the kernel may use once it has taken its own part.
    fn is_free(&self) -> bool {
        matches!(
            self.ty,
            LOADER_CODE | LOADER_DATA | BOOT_CODE | BOOT_DATA | CONVENTIONAL
        )
    }
}

/// The numbers the loader reports (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub descriptors: usize,
    pub memory_before: usize,
    pub reserved_before: usize,
    pub memory: usize,
    pub reserved: usize,
    /// Bytes of memory that the merge of reserved regions across a gap took
    /// away from the kernel.
    pub lost_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub memory: Vec<Region>,
    /// All `no-map`.
    pub reserved: Vec<Region>,
    pub stats: Stats,
}

fn merge_adjacent(mut v: Vec<Region>) -> Vec<Region> {
    v.sort_unstable_by_key(|r| r.base);
    let mut out: Vec<Region> = Vec::new();
    for r in v {
        match out.last_mut() {
            Some(last) if last.end() >= r.base => {
                last.size = last.size.max(r.end() - last.base);
            }
            _ => out.push(r),
        }
    }
    out
}

/// Sorts the map into the lists the tree takes, joining neighbours.
/// `protect` are ranges the loader has put things in (the kernel, the tree,
/// the boot image): the merge across a gap never swallows them.
pub fn classify(map: &[Desc], protect: &[Region]) -> Result<Classified, Error> {
    let mut memory = Vec::new();
    let mut reserved = Vec::new();
    for d in map {
        if d.attr & ATTR_WB == 0 || d.ty == MMIO || d.ty == MMIO_PORT || d.pages == 0 {
            continue;
        }
        memory.push(d.region());
        if !d.is_free() {
            reserved.push(d.region());
        }
    }
    let mut stats = Stats {
        descriptors: map.len(),
        memory_before: memory.len(),
        reserved_before: reserved.len(),
        ..Stats::default()
    };
    if cfg!(feature = "break-merge") {
        memory.sort_unstable_by_key(|r| r.base);
        reserved.sort_unstable_by_key(|r| r.base);
    } else {
        memory = merge_adjacent(memory);
        reserved = merge_adjacent(reserved);
        if memory.len() > MEMORY_REGIONS {
            return Err(Error::TooManyRegions("memory"));
        }
        // Too many separate reserved ranges: join the pair with the smallest
        // gap between them, which gives the kernel's RAM in the gap up.
        while reserved.len() > NO_MAP_REGIONS {
            let gap = |i: usize| reserved[i + 1].base - reserved[i].end();
            let best = (0..reserved.len() - 1)
                .filter(|&i| {
                    let hole = Region {
                        base: reserved[i].end(),
                        size: gap(i),
                    };
                    !protect.iter().any(|p| overlaps(*p, hole))
                })
                .min_by_key(|&i| gap(i))
                .ok_or(Error::TooManyRegions(
                    "reserved (the loader's own ranges lie between)",
                ))?;
            stats.lost_bytes += gap(best);
            reserved[best].size = reserved[best + 1].end() - reserved[best].base;
            reserved.remove(best + 1);
        }
    }
    stats.memory = memory.len();
    stats.reserved = reserved.len();
    Ok(Classified {
        memory,
        reserved,
        stats,
    })
}

fn overlaps(a: Region, b: Region) -> bool {
    a.base < b.end() && b.base < a.end() && a.size > 0 && b.size > 0
}

/// The lowest 2 MiB boundary in conventional memory, in a GiB the boot page
/// tables map (1..511), from which `size` bytes lie free and inside one GiB:
/// the place for the kernel and the tree (the note, 4.4). None when there is
/// none.
pub fn find_slot(map: &[Desc], size: u64) -> Option<u64> {
    const TWO_MIB: u64 = 2 << 20;
    let mut best: Option<u64> = None;
    for d in map.iter().filter(|d| d.ty == CONVENTIONAL) {
        let r = d.region();
        let mut start = r.base.div_ceil(TWO_MIB) * TWO_MIB;
        while start + size <= r.end() {
            if (GIB..511 * GIB).contains(&start) && fits_in_one_gib(start, size) {
                if best.is_none_or(|b| start < b) {
                    best = Some(start);
                }
                break;
            }
            // Past a GiB boundary inside the descriptor: try the next one.
            start = if start < GIB {
                GIB
            } else {
                (start / GIB + 1) * GIB
            };
        }
    }
    best
}

/// The room for the tree after the kernel in the one slot (the note, 4.4).
pub const TREE_ROOM: u64 = 64 << 10;

/// Where the tree goes: right after the kernel's image in the slot, whole
/// pages on. The break `break-dtb-gib` puts it across the next GiB boundary
/// instead, where the boot page tables do not map its tail.
pub fn tree_base(kernel_base: u64, image_size: u64) -> u64 {
    if cfg!(feature = "break-dtb-gib") {
        return (kernel_base / GIB + 1) * GIB - 0x800;
    }
    kernel_base + image_size.div_ceil(PAGE) * PAGE
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn d(ty: u32, phys: u64, pages: u64) -> Desc {
        Desc {
            ty,
            phys,
            pages,
            attr: 0xF,
        }
    }

    /// What edk2 on QEMU `virt` gives, in the shape: RAM from 1 GiB with the
    /// firmware's pieces in it.
    fn qemu_like() -> Vec<Desc> {
        vec![
            d(7, 0x4000_0000, 0x100),
            d(4, 0x4010_0000, 0x40),
            d(3, 0x4014_0000, 0x20),
            d(6, 0x4016_0000, 0x10),
            d(5, 0x4017_0000, 0x10),
            d(5, 0x4018_0000, 0x10),
            d(6, 0x4019_0000, 0x10),
            d(9, 0x401a_0000, 0x4),
            d(10, 0x401a_4000, 0x4),
            d(7, 0x401a_8000, 0x1000),
            d(0, 0x5000_0000, 0x10),
            d(7, 0x5001_0000, 0x1000),
            Desc {
                ty: 11,
                phys: 0x900_0000,
                pages: 1,
                attr: 1,
            },
            Desc {
                ty: 7,
                phys: 0x0,
                pages: 0x100,
                attr: 1,
            },
        ]
    }

    #[test]
    fn neighbours_join_and_the_firmware_s_pieces_are_withheld() {
        let c = classify(&qemu_like(), &[]).unwrap();
        assert_eq!(c.memory.len(), 2, "{:x?}", c.memory);
        assert_eq!(c.memory[0].base, 0x4000_0000);
        assert_eq!(c.memory[0].end(), 0x401a_8000 + 0x1000 * 4096);
        assert_eq!(
            c.memory[1],
            Region {
                base: 0x5000_0000,
                size: 0x10 * 4096 + 0x1000 * 4096
            }
        );
        // 6, 5, 5, 6 join; 9 and 10 join them (all one class); type 0 is apart.
        assert_eq!(c.reserved.len(), 2);
        assert_eq!(
            c.reserved[0],
            Region {
                base: 0x4016_0000,
                size: 0x48 * 4096
            }
        );
        assert_eq!(
            c.reserved[1],
            Region {
                base: 0x5000_0000,
                size: 0x10 * 4096
            }
        );
        assert_eq!(c.stats.descriptors, 14);
        assert_eq!(c.stats.memory_before, 12);
        assert_eq!(c.stats.reserved_before, 7);
        assert_eq!(c.stats.lost_bytes, 0);
    }

    #[test]
    fn what_has_no_write_back_attribute_or_is_mmio_stays_out() {
        let c = classify(
            &[
                d(7, 0x4000_0000, 16),
                Desc {
                    ty: 7,
                    phys: 0x8000_0000,
                    pages: 16,
                    attr: 7,
                },
                d(11, 0x9000_0000, 16),
                d(12, 0x9100_0000, 16),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            c.memory,
            [Region {
                base: 0x4000_0000,
                size: 16 * 4096
            }]
        );
        assert!(c.reserved.is_empty());
    }

    /// The map of the note's synthetic test: 120 descriptors with 12 regions
    /// that must stay apart.
    fn fragmented() -> Vec<Desc> {
        let mut v = Vec::new();
        let mut at = 0x4000_0000u64;
        for i in 0..57u64 {
            // Every fifth pair is a runtime region, with free memory between;
            // the gaps grow with i so that the smallest is the first.
            v.push(d(7, at, 16));
            at += 16 * 4096;
            if i % 5 == 0 {
                v.push(d(5, at, 4));
                at += 4 * 4096;
                v.push(d(7, at, (i + 1) * 2));
                at += (i + 1) * 2 * 4096;
            } else {
                v.push(d(4, at, 4));
                at += 4 * 4096;
            }
        }
        v
    }

    #[test]
    fn twelve_separate_runtime_regions_fold_by_the_smallest_gap_and_report_the_loss() {
        let map = fragmented();
        assert!(map.len() >= 120);
        let c = classify(&map, &[]).unwrap();
        assert!(c.stats.reserved_before >= 12, "{:?}", c.stats);
        assert_eq!(c.reserved.len(), NO_MAP_REGIONS);
        assert!(c.stats.lost_bytes > 0);
        // Everything that was reserved is still reserved.
        for r in classify(&map, &[]).unwrap().reserved.iter() {
            assert!(
                c.reserved
                    .iter()
                    .any(|x| x.base <= r.base && r.end() <= x.end())
            );
        }
    }

    #[test]
    fn the_merge_across_a_gap_never_swallows_a_range_the_loader_holds() {
        let map = fragmented();
        // Protect the gap that would be joined first: the one after the
        // first runtime region.
        let first = classify(&map, &[]).unwrap();
        let hole = Region {
            base: first.reserved[0].end() - 0x1000,
            size: 0x2000,
        };
        let _ = hole;
        let held = Region {
            base: 0x4000_0000 + 16 * 4096 + 4 * 4096 + 0x1000,
            size: 0x1000,
        };
        let c = classify(&map, &[held]).unwrap();
        assert!(!c.reserved.iter().any(|r| overlaps(*r, held)));
    }

    #[test]
    fn more_than_eight_memory_regions_are_an_error_not_a_guess() {
        let map: Vec<Desc> = (0..9)
            .map(|i| d(7, 0x4000_0000 + i * 0x1000_0000, 16))
            .collect();
        assert_eq!(classify(&map, &[]), Err(Error::TooManyRegions("memory")));
    }

    #[test]
    fn the_tree_follows_the_image_inside_the_slots_gib() {
        let base = 0x4020_0000;
        let tree = tree_base(base, 0x2_c123);
        assert_eq!(tree, base + 0x2_d000);
        assert!(fits_in_one_gib(base, tree + TREE_ROOM - base));
    }

    #[test]
    fn the_slot_is_the_lowest_2_mib_boundary_of_enough_free_memory_in_one_gib() {
        let map = qemu_like();
        // The first free piece has 1 MiB, too small for 4 MiB and not a
        // 2 MiB boundary anyway: the next free memory, 0x401a_8000 + 16 MiB.
        assert_eq!(find_slot(&map, 4 * MIB), Some(0x4020_0000));
        // A piece in the first GiB is no place.
        assert_eq!(find_slot(&[d(7, 0, 0x10000)], MIB), None);
        // A piece that crosses a GiB boundary: the slot is wholly in one.
        let m = [d(7, 0x7fe0_0000, 0x600)];
        assert_eq!(find_slot(&m, 2 * MIB), Some(0x7fe0_0000));
        assert_eq!(find_slot(&m, 3 * MIB), Some(0x8000_0000));
        assert_eq!(find_slot(&m, 5 * MIB), None);
    }
}
