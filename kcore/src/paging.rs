// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Stage-1 translation tables, 4 KiB granule, 48-bit addresses (spec 7.2):
//! descriptors and table construction. The caller supplies memory for
//! tables; this module issues no barriers or TLB maintenance, which is the
//! caller's job when a table is live.

pub const PAGE: u64 = 4096;
pub const BLOCK_2M: u64 = 2 << 20;
/// Output address bits [47:12] of a descriptor.
const OA_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const VALID: u64 = 1;
/// Bit 1: table (levels 0-2) or page (level 3); clear for a block.
const TABLE_OR_PAGE: u64 = 1 << 1;
const AP_EL0: u64 = 1 << 6;
const AP_READ_ONLY: u64 = 1 << 7;
const SH_INNER: u64 = 0b11 << 8;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11;
pub const PXN: u64 = 1 << 53;
pub const UXN: u64 = 1 << 54;
/// AttrIndx values; MAIR_EL1 (head.S) holds normal write-back memory at 0 and
/// Device-nGnRE at 1.
const ATTR_NORMAL: u64 = 0 << 2;
const ATTR_DEVICE: u64 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Memory {
    Normal,
    Device,
}

/// Access rights and memory type of a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attrs {
    pub memory: Memory,
    pub write: bool,
    pub kernel_exec: bool,
    pub user: bool,
    pub user_exec: bool,
}

impl Attrs {
    pub const KERNEL_TEXT: Attrs = Attrs {
        memory: Memory::Normal,
        write: false,
        kernel_exec: true,
        user: false,
        user_exec: false,
    };
    pub const KERNEL_RODATA: Attrs = Attrs {
        kernel_exec: false,
        ..Attrs::KERNEL_TEXT
    };
    pub const KERNEL_DATA: Attrs = Attrs {
        write: true,
        ..Attrs::KERNEL_RODATA
    };
    pub const DEVICE: Attrs = Attrs {
        memory: Memory::Device,
        ..Attrs::KERNEL_DATA
    };

    /// W^X, no executable device memory, and EL0 execution only on EL0 pages.
    pub fn is_valid(&self) -> bool {
        let exec = self.kernel_exec || self.user_exec;
        !(self.write && exec)
            && !(self.memory == Memory::Device && exec)
            && !(self.user_exec && !self.user)
    }

    /// Descriptor bits besides the address and the type. User mappings are
    /// not global (nG), so their TLB entries belong to one ASID.
    pub fn bits(&self) -> u64 {
        let mut d = AF;
        d |= match self.memory {
            Memory::Normal => ATTR_NORMAL | SH_INNER,
            Memory::Device => ATTR_DEVICE,
        };
        if self.user {
            d |= AP_EL0 | NG;
        }
        if !self.write {
            d |= AP_READ_ONLY;
        }
        if !self.kernel_exec {
            d |= PXN;
        }
        if !self.user_exec {
            d |= UXN;
        }
        d
    }
}

pub fn page_descriptor(pa: u64, attrs: Attrs) -> u64 {
    (pa & OA_MASK) | attrs.bits() | TABLE_OR_PAGE | VALID
}

pub fn block_descriptor(pa: u64, attrs: Attrs) -> u64 {
    (pa & OA_MASK) | attrs.bits() | VALID
}

pub fn table_descriptor(pa: u64) -> u64 {
    (pa & OA_MASK) | TABLE_OR_PAGE | VALID
}

/// Memory for translation tables.
pub trait TableMemory {
    /// Physical address of a zeroed 4 KiB table, or None when memory runs out.
    fn alloc_table(&mut self) -> Option<u64>;
    fn read(&self, pa: u64) -> u64;
    fn write(&mut self, pa: u64, value: u64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    Misaligned,
    WriteAndExecute,
    AlreadyMapped,
    NoMemory,
}

fn index(va: u64, level: u32) -> u64 {
    (va >> (39 - 9 * level)) & 0x1FF
}

/// A translation table tree, named by the physical address of its root.
pub struct PageTable {
    root: u64,
}

impl PageTable {
    pub fn new(mem: &mut impl TableMemory) -> Result<PageTable, MapError> {
        Ok(PageTable {
            root: mem.alloc_table().ok_or(MapError::NoMemory)?,
        })
    }

    /// A tree that already exists, such as the one TTBR1 points at.
    pub fn from_root(root: u64) -> PageTable {
        PageTable { root }
    }

    pub fn root(&self) -> u64 {
        self.root
    }

    /// Maps `[va, va + size)` to `[pa, pa + size)`, with 2 MiB blocks where
    /// both addresses and the remaining size allow, and 4 KiB pages elsewhere.
    /// On error part of the range may already be mapped.
    pub fn map(
        &mut self,
        mem: &mut impl TableMemory,
        va: u64,
        pa: u64,
        size: u64,
        attrs: Attrs,
    ) -> Result<(), MapError> {
        if !attrs.is_valid() {
            return Err(MapError::WriteAndExecute);
        }
        if !va.is_multiple_of(PAGE) || !pa.is_multiple_of(PAGE) || !size.is_multiple_of(PAGE) {
            return Err(MapError::Misaligned);
        }
        let mut off = 0;
        while off < size {
            let (v, p) = (va.wrapping_add(off), pa + off);
            let block =
                v.is_multiple_of(BLOCK_2M) && p.is_multiple_of(BLOCK_2M) && size - off >= BLOCK_2M;
            let (level, desc, step) = if block {
                (2, block_descriptor(p, attrs), BLOCK_2M)
            } else {
                (3, page_descriptor(p, attrs), PAGE)
            };
            let slot = self.entry(mem, v, level)?;
            if mem.read(slot) != 0 {
                return Err(MapError::AlreadyMapped);
            }
            mem.write(slot, desc);
            off += step;
        }
        Ok(())
    }

    /// Address of the level-`level` entry for `va`, creating the tables above it.
    fn entry(&mut self, mem: &mut impl TableMemory, va: u64, level: u32) -> Result<u64, MapError> {
        let mut table = self.root;
        for l in 0..level {
            let slot = table + index(va, l) * 8;
            let d = mem.read(slot);
            table = if d & (VALID | TABLE_OR_PAGE) == VALID | TABLE_OR_PAGE {
                d & OA_MASK
            } else if d & VALID == 0 {
                let t = mem.alloc_table().ok_or(MapError::NoMemory)?;
                mem.write(slot, table_descriptor(t));
                t
            } else {
                return Err(MapError::AlreadyMapped);
            };
        }
        Ok(table + index(va, level) * 8)
    }

    /// Physical address and leaf descriptor that `va` translates to.
    pub fn translate(&self, mem: &impl TableMemory, va: u64) -> Option<(u64, u64)> {
        let mut table = self.root;
        for level in 0..=3u32 {
            let d = mem.read(table + index(va, level) * 8);
            if d & VALID == 0 {
                return None;
            }
            let is_table_or_page = d & TABLE_OR_PAGE != 0;
            if level < 3 && is_table_or_page {
                table = d & OA_MASK;
                continue;
            }
            if level == 0 || (level == 3 && !is_table_or_page) {
                return None;
            }
            let span = 1u64 << (39 - 9 * level);
            return Some(((d & OA_MASK & !(span - 1)) | (va & (span - 1)), d));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Tables {
        words: HashMap<u64, u64>,
        next: u64,
        left: usize,
    }

    impl TableMemory for Tables {
        fn alloc_table(&mut self) -> Option<u64> {
            if self.left == 0 {
                return None;
            }
            self.left -= 1;
            let t = self.next;
            self.next += PAGE;
            Some(t)
        }
        fn read(&self, pa: u64) -> u64 {
            *self.words.get(&pa).unwrap_or(&0)
        }
        fn write(&mut self, pa: u64, value: u64) {
            self.words.insert(pa, value);
        }
    }

    fn tables(n: usize) -> Tables {
        Tables {
            words: HashMap::new(),
            next: 0x8000_0000,
            left: n,
        }
    }

    #[test]
    fn kernel_text_page_descriptor() {
        assert_eq!(
            page_descriptor(0x4020_0000, Attrs::KERNEL_TEXT),
            0x0040_0000_4020_0783
        );
    }

    #[test]
    fn rodata_and_data_page_descriptors() {
        assert_eq!(
            page_descriptor(0x4030_0000, Attrs::KERNEL_RODATA),
            0x0060_0000_4030_0783
        );
        assert_eq!(
            page_descriptor(0x4040_0000, Attrs::KERNEL_DATA),
            0x0060_0000_4040_0703
        );
    }

    #[test]
    fn device_page_descriptor() {
        assert_eq!(
            page_descriptor(0x0900_0000, Attrs::DEVICE),
            0x0060_0000_0900_0407
        );
    }

    #[test]
    fn ram_block_matches_the_boot_tables() {
        // BLOCK_RAM in head.S.
        assert_eq!(
            block_descriptor(0x4000_0000, Attrs::KERNEL_DATA),
            0x0060_0000_4000_0701
        );
    }

    #[test]
    fn user_attributes_set_ng_and_el0_access() {
        let user_data = Attrs {
            user: true,
            ..Attrs::KERNEL_DATA
        };
        let d = page_descriptor(0x5000_0000, user_data);
        assert_ne!(d & (1 << 11), 0, "nG");
        assert_ne!(d & (1 << 6), 0, "AP[1]");
    }

    #[test]
    fn write_and_execute_together_are_refused() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        let wx = Attrs {
            write: true,
            ..Attrs::KERNEL_TEXT
        };
        assert_eq!(
            pt.map(&mut t, 0x4000_0000, 0x4000_0000, PAGE, wx),
            Err(MapError::WriteAndExecute)
        );
        let dx = Attrs {
            kernel_exec: true,
            ..Attrs::DEVICE
        };
        assert!(!dx.is_valid());
        let ux = Attrs {
            user_exec: true,
            ..Attrs::KERNEL_RODATA
        };
        assert!(!ux.is_valid());
    }

    #[test]
    fn misaligned_requests_are_refused() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        let d = Attrs::KERNEL_DATA;
        assert_eq!(
            pt.map(&mut t, 0x4000_0800, 0x4000_0000, PAGE, d),
            Err(MapError::Misaligned)
        );
        assert_eq!(
            pt.map(&mut t, 0x4000_0000, 0x4000_0800, PAGE, d),
            Err(MapError::Misaligned)
        );
        assert_eq!(
            pt.map(&mut t, 0x4000_0000, 0x4000_0000, 100, d),
            Err(MapError::Misaligned)
        );
    }

    #[test]
    fn single_page_maps_and_translates() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(&mut t, 0x1234_5000, 0x4567_8000, PAGE, Attrs::KERNEL_DATA)
            .unwrap();
        let (pa, d) = pt.translate(&t, 0x1234_5ABC).unwrap();
        assert_eq!(pa, 0x4567_8ABC);
        assert_eq!(d & 0b11, 0b11);
        assert_eq!(pt.translate(&t, 0x1234_6000), None);
    }

    #[test]
    fn aligned_range_uses_2mib_blocks() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(
            &mut t,
            0x4000_0000,
            0x4000_0000,
            2 * BLOCK_2M,
            Attrs::KERNEL_DATA,
        )
        .unwrap();
        let (pa, d) = pt.translate(&t, 0x4020_0123).unwrap();
        assert_eq!(pa, 0x4020_0123);
        assert_eq!(d & 0b11, 0b01, "block");
    }

    #[test]
    fn unaligned_range_uses_pages_around_a_block() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(
            &mut t,
            0x401F_F000,
            0x401F_F000,
            BLOCK_2M + 2 * PAGE,
            Attrs::KERNEL_DATA,
        )
        .unwrap();
        assert_eq!(pt.translate(&t, 0x401F_F000).unwrap().1 & 0b11, 0b11);
        assert_eq!(pt.translate(&t, 0x4020_0000).unwrap().1 & 0b11, 0b01);
        assert_eq!(pt.translate(&t, 0x4040_0000).unwrap().1 & 0b11, 0b11);
        assert_eq!(pt.translate(&t, 0x4040_1000), None);
    }

    #[test]
    fn upper_half_addresses_use_the_top_entries() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        let va = 0xFFFF_FFFF_C000_0000;
        pt.map(&mut t, va, 0x4020_0000, PAGE, Attrs::KERNEL_TEXT)
            .unwrap();
        assert_ne!(t.read(pt.root() + 511 * 8), 0);
        assert_eq!(pt.translate(&t, va + 8).unwrap().0, 0x4020_0008);
    }

    #[test]
    fn mapping_twice_is_refused() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(&mut t, 0x1000, 0x4000_0000, PAGE, Attrs::KERNEL_DATA)
            .unwrap();
        assert_eq!(
            pt.map(&mut t, 0x1000, 0x4000_1000, PAGE, Attrs::KERNEL_DATA),
            Err(MapError::AlreadyMapped)
        );
    }

    #[test]
    fn mapping_inside_a_block_is_refused() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(
            &mut t,
            0x4000_0000,
            0x4000_0000,
            BLOCK_2M,
            Attrs::KERNEL_DATA,
        )
        .unwrap();
        assert_eq!(
            pt.map(&mut t, 0x4000_1000, 0x5000_0000, PAGE, Attrs::KERNEL_DATA),
            Err(MapError::AlreadyMapped)
        );
    }

    #[test]
    fn running_out_of_tables_is_reported() {
        let mut t = tables(2);
        let mut pt = PageTable::new(&mut t).unwrap();
        assert_eq!(
            pt.map(&mut t, 0x1000, 0x4000_0000, PAGE, Attrs::KERNEL_DATA),
            Err(MapError::NoMemory)
        );
    }

    #[test]
    fn from_root_walks_existing_tables() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(&mut t, 0x2000, 0x4000_2000, PAGE, Attrs::KERNEL_DATA)
            .unwrap();
        let again = PageTable::from_root(pt.root());
        assert_eq!(again.translate(&t, 0x2000).unwrap().0, 0x4000_2000);
    }
}
