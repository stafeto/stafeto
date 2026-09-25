// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Stage-1 translation tables, 4 KiB granule, 48-bit addresses (spec 7.2):
//! descriptors and table construction. The caller supplies memory for
//! tables; this module issues no barriers or TLB maintenance, which is the
//! caller's job when a table is live.

use crate::PAGE_SIZE;
use crate::layout::USER_END;
use abi::Error;

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
/// Not global: the TLB entry belongs to one ASID.
pub const NG: u64 = 1 << 11;
pub const PXN: u64 = 1 << 53;
pub const UXN: u64 = 1 << 54;
/// MAIR_EL1 entries that head.S sets: normal write-back memory at index 0,
/// Device-nGnRE at index 1.
pub const MAIR_NORMAL: u64 = 0;
pub const MAIR_DEVICE: u64 = 1;
/// AttrIndx, descriptor bits [4:2], selects a MAIR_EL1 entry.
const ATTR_SHIFT: u32 = 2;
const ATTR_NORMAL: u64 = MAIR_NORMAL << ATTR_SHIFT;
const ATTR_DEVICE: u64 = MAIR_DEVICE << ATTR_SHIFT;
/// Root table address bits of TTBR0_EL1 and TTBR1_EL1; the ASID sits above
/// them, CnP in bit 0.
pub const TTBR_ROOT_MASK: u64 = OA_MASK;

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
    /// A program's code: EL0 reads and executes it.
    pub const USER_TEXT: Attrs = Attrs {
        memory: Memory::Normal,
        write: false,
        kernel_exec: false,
        user: true,
        user_exec: true,
    };
    pub const USER_RODATA: Attrs = Attrs {
        user_exec: false,
        ..Attrs::USER_TEXT
    };
    pub const USER_DATA: Attrs = Attrs {
        write: true,
        ..Attrs::USER_RODATA
    };

    /// W^X, no executable device memory, EL0 execution only on EL0 pages,
    /// and the kernel never executes a user page.
    pub fn is_valid(&self) -> bool {
        let exec = self.kernel_exec || self.user_exec;
        !(self.write && exec)
            && !(self.memory == Memory::Device && exec)
            && !(self.user_exec && !self.user)
            && !(self.user && self.kernel_exec)
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

/// The MAIR_EL1 index a block or page descriptor selects.
pub fn attr_index(desc: u64) -> u64 {
    (desc >> ATTR_SHIFT) & 0b111
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
///
/// # Safety
/// `alloc_table` returns the physical address of a zeroed 4 KiB frame,
/// aligned to 4 KiB, that belongs to the table tree from then on and that
/// nothing else uses. `free_table` takes back only such a table, once the
/// tree no longer refers to it. `read` and `write` access the 8-byte word
/// at a physical address inside a table of the tree, and nothing else;
/// `read` returns the last word written. A table from `alloc_table` reads
/// as zero to the table walker before the tree links it. The MMU walks
/// these tables, so a table that is not real, zeroed and owned memory maps
/// whatever it happens to hold.
pub unsafe trait TableMemory {
    /// Physical address of a zeroed 4 KiB table, or None when memory runs out.
    fn alloc_table(&mut self) -> Option<u64>;
    fn free_table(&mut self, pa: u64);
    fn read(&self, pa: u64) -> u64;
    fn write(&mut self, pa: u64, value: u64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    Misaligned,
    WriteAndExecute,
    AlreadyMapped,
    NoMemory,
    /// No 4 KiB page maps the address.
    NotMapped,
    /// A user mapping with kernel attributes, or at addresses TTBR0 does
    /// not translate.
    NotUser,
}

/// A refused mapping as a system call reports it (spec 11): NO_MEMORY when
/// the quota or the frames ran out for a table, INVALID_ARGS for the rest.
impl From<MapError> for Error {
    fn from(e: MapError) -> Error {
        match e {
            MapError::NoMemory => Error::NoMemory,
            _ => Error::InvalidArgs,
        }
    }
}

fn index(va: u64, level: u32) -> u64 {
    (va >> (39 - 9 * level)) & 0x1FF
}

/// A valid descriptor with bit 1 set: a table at levels 0-2, a page at level 3.
fn is_table_or_page(d: u64) -> bool {
    d & (VALID | TABLE_OR_PAGE) == VALID | TABLE_OR_PAGE
}

/// Where a stepwise release of a table tree stands: the path from the
/// root to the table being read, as (table, next entry) for levels 0-2,
/// and how many tables went. Only its `Release` holds it.
#[derive(Debug)]
struct Cursor {
    path: [(u64, u16); 3],
    /// Tables on the path; 0 before the first step and after the last.
    depth: usize,
    freed: usize,
    done: bool,
}

/// A table tree on its way back to the allocator (spec 7.7), from
/// `PageTable::into_release`: the tree is consumed, so nothing maps,
/// unmaps or translates through it any more, and `step` frees it a table
/// at a time. It is neither Clone nor Copy: the place of the walk has one
/// owner, the object whose tree goes, and no second walk can repeat a
/// step and free a table twice.
#[derive(Debug)]
pub struct Release {
    root: u64,
    cursor: Cursor,
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
        self.map_range(mem, va, pa, size, attrs, true)
    }

    /// Maps `[va, va + size)` to `[pa, pa + size)` for a program: user
    /// attributes only, below USER_END, and in 4 KiB pages even where a
    /// block would fit, so that every page can be unmapped on its own. On
    /// error part of the range may already be mapped.
    pub fn map_user(
        &mut self,
        mem: &mut impl TableMemory,
        va: u64,
        pa: u64,
        size: u64,
        attrs: Attrs,
    ) -> Result<(), MapError> {
        let inside = va
            .checked_add(size)
            .is_some_and(|end| end <= USER_END as u64);
        if !attrs.user || !inside {
            return Err(MapError::NotUser);
        }
        self.map_range(mem, va, pa, size, attrs, false)
    }

    fn map_range(
        &mut self,
        mem: &mut impl TableMemory,
        va: u64,
        pa: u64,
        size: u64,
        attrs: Attrs,
        blocks: bool,
    ) -> Result<(), MapError> {
        if !attrs.is_valid() {
            return Err(MapError::WriteAndExecute);
        }
        if !va.is_multiple_of(PAGE_SIZE)
            || !pa.is_multiple_of(PAGE_SIZE)
            || !size.is_multiple_of(PAGE_SIZE)
        {
            return Err(MapError::Misaligned);
        }
        let mut off = 0;
        while off < size {
            let (v, p) = (va.wrapping_add(off), pa + off);
            let block = blocks
                && v.is_multiple_of(BLOCK_2M)
                && p.is_multiple_of(BLOCK_2M)
                && size - off >= BLOCK_2M;
            let (level, desc, step) = if block {
                (2, block_descriptor(p, attrs), BLOCK_2M)
            } else {
                (3, page_descriptor(p, attrs), PAGE_SIZE)
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
            table = if is_table_or_page(d) {
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

    /// Removes the 4 KiB page that maps `va` and returns its physical
    /// address. Tables stay, even when they become empty; a 2 MiB block is
    /// not a page and stays too. The caller invalidates the TLB entry.
    pub fn unmap_page(&mut self, mem: &mut impl TableMemory, va: u64) -> Result<u64, MapError> {
        if !va.is_multiple_of(PAGE_SIZE) {
            return Err(MapError::Misaligned);
        }
        let mut table = self.root;
        for level in 0..3 {
            let d = mem.read(table + index(va, level) * 8);
            if !is_table_or_page(d) {
                return Err(MapError::NotMapped);
            }
            table = d & OA_MASK;
        }
        let slot = table + index(va, 3) * 8;
        let d = mem.read(slot);
        if !is_table_or_page(d) {
            return Err(MapError::NotMapped);
        }
        mem.write(slot, 0);
        Ok(d & OA_MASK)
    }

    /// Frees every table of the tree, the root last, and returns how many
    /// there were. The pages and blocks it maps belong to others and stay.
    /// The MMU must no longer walk the tree: no TTBR points at it, and the
    /// TLB holds nothing from it.
    pub fn release(self, mem: &mut impl TableMemory) -> usize {
        let mut release = self.into_release();
        while !release.step(mem) {}
        release.freed()
    }

    /// The tree as a release that has not begun (`Release::step`).
    pub fn into_release(self) -> Release {
        Release {
            root: self.root,
            cursor: Cursor {
                path: [(0, 0); 3],
                depth: 0,
                freed: 0,
                done: false,
            },
        }
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
            // A level-0 block does not exist with a 4 KiB granule, and at
            // level 3 bit 1 clear is reserved. Tables built here hold
            // neither; the check keeps a foreign or damaged table (such as
            // one read through `from_root`) from turning into a bogus mapping.
            if level == 0 || (level == 3 && !is_table_or_page) {
                return None;
            }
            let span = 1u64 << (39 - 9 * level);
            return Some(((d & OA_MASK & !(span - 1)) | (va & (span - 1)), d));
        }
        None
    }
}

impl Release {
    /// One step of the release: it reads entries of one table of levels
    /// 0-2, at most 512, and frees at most one table: the next level-3
    /// table below a level-2 one, whose entries map pages and need no
    /// reading, or the table itself once no table is left below it, which
    /// takes the walk back up. A table below levels 0 and 1 is only
    /// entered, and the next step reads it. The root goes last; then the
    /// step returns true, and so does every later one, freeing nothing.
    /// The same conditions as for `PageTable::release` hold from the first
    /// step on.
    pub fn step(&mut self, mem: &mut impl TableMemory) -> bool {
        let cursor = &mut self.cursor;
        if cursor.done {
            return true;
        }
        if cursor.depth == 0 {
            cursor.path[0] = (self.root, 0);
            cursor.depth = 1;
        }
        let level = cursor.depth - 1;
        let (table, from) = cursor.path[level];
        for i in u64::from(from)..512 {
            let d = mem.read(table + i * 8);
            if !is_table_or_page(d) {
                continue;
            }
            cursor.path[level].1 = i as u16 + 1;
            if level == 2 {
                mem.free_table(d & OA_MASK);
                cursor.freed += 1;
            } else {
                cursor.path[level + 1] = (d & OA_MASK, 0);
                cursor.depth += 1;
            }
            return false;
        }
        mem.free_table(table);
        cursor.freed += 1;
        cursor.depth -= 1;
        cursor.done = cursor.depth == 0;
        cursor.done
    }

    /// Tables freed so far.
    pub fn freed(&self) -> usize {
        self.cursor.freed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct Tables {
        words: HashMap<u64, u64>,
        next: u64,
        left: usize,
        freed: Vec<u64>,
        /// Addresses read since the log was last taken.
        reads: RefCell<Vec<u64>>,
    }

    const FIRST_TABLE: u64 = 0x8000_0000;

    // SAFETY: tables are distinct, zeroed (absent words read as 0) and owned
    // by the test; `read` returns the last `write`.
    unsafe impl TableMemory for Tables {
        fn alloc_table(&mut self) -> Option<u64> {
            if self.left == 0 {
                return None;
            }
            self.left -= 1;
            let t = self.next;
            self.next += PAGE_SIZE;
            Some(t)
        }
        fn free_table(&mut self, pa: u64) {
            self.freed.push(pa);
        }
        fn read(&self, pa: u64) -> u64 {
            self.reads.borrow_mut().push(pa);
            *self.words.get(&pa).unwrap_or(&0)
        }
        fn write(&mut self, pa: u64, value: u64) {
            self.words.insert(pa, value);
        }
    }

    impl Tables {
        /// Every table handed out so far.
        fn allocated(&self) -> Vec<u64> {
            (FIRST_TABLE..self.next)
                .step_by(PAGE_SIZE as usize)
                .collect()
        }

        /// The addresses read since the last call.
        fn take_reads(&self) -> Vec<u64> {
            self.reads.take()
        }
    }

    fn tables(n: usize) -> Tables {
        Tables {
            words: HashMap::new(),
            next: FIRST_TABLE,
            left: n,
            freed: Vec::new(),
            reads: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn attr_index_names_the_mair_entry() {
        assert_eq!(
            attr_index(page_descriptor(0x0900_0000, Attrs::DEVICE)),
            MAIR_DEVICE
        );
        assert_eq!(
            attr_index(page_descriptor(0x4000_0000, Attrs::KERNEL_DATA)),
            MAIR_NORMAL
        );
        assert_eq!(
            attr_index(block_descriptor(0x4000_0000, Attrs::KERNEL_TEXT)),
            MAIR_NORMAL
        );
    }

    #[test]
    fn ttbr_root_mask_drops_the_asid_and_the_low_bits() {
        let ttbr = (0xABCD_u64 << 48) | 0x4008_1000 | 1;
        assert_eq!(ttbr & TTBR_ROOT_MASK, 0x4008_1000);
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
            pt.map(&mut t, 0x4000_0000, 0x4000_0000, PAGE_SIZE, wx),
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
    fn kernel_cannot_execute_user_pages() {
        let attrs = Attrs {
            memory: Memory::Normal,
            write: false,
            kernel_exec: true,
            user: true,
            user_exec: false,
        };
        assert!(!attrs.is_valid());
    }

    #[test]
    fn misaligned_requests_are_refused() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        let d = Attrs::KERNEL_DATA;
        assert_eq!(
            pt.map(&mut t, 0x4000_0800, 0x4000_0000, PAGE_SIZE, d),
            Err(MapError::Misaligned)
        );
        assert_eq!(
            pt.map(&mut t, 0x4000_0000, 0x4000_0800, PAGE_SIZE, d),
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
        pt.map(
            &mut t,
            0x1234_5000,
            0x4567_8000,
            PAGE_SIZE,
            Attrs::KERNEL_DATA,
        )
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
            BLOCK_2M + 2 * PAGE_SIZE,
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
        pt.map(&mut t, va, 0x4020_0000, PAGE_SIZE, Attrs::KERNEL_TEXT)
            .unwrap();
        assert_ne!(t.read(pt.root() + 511 * 8), 0);
        assert_eq!(pt.translate(&t, va + 8).unwrap().0, 0x4020_0008);
    }

    #[test]
    fn mapping_twice_is_refused() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(&mut t, 0x1000, 0x4000_0000, PAGE_SIZE, Attrs::KERNEL_DATA)
            .unwrap();
        assert_eq!(
            pt.map(&mut t, 0x1000, 0x4000_1000, PAGE_SIZE, Attrs::KERNEL_DATA),
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
            pt.map(
                &mut t,
                0x4000_1000,
                0x5000_0000,
                PAGE_SIZE,
                Attrs::KERNEL_DATA
            ),
            Err(MapError::AlreadyMapped)
        );
    }

    #[test]
    fn running_out_of_tables_is_reported() {
        let mut t = tables(2);
        let mut pt = PageTable::new(&mut t).unwrap();
        assert_eq!(
            pt.map(&mut t, 0x1000, 0x4000_0000, PAGE_SIZE, Attrs::KERNEL_DATA),
            Err(MapError::NoMemory)
        );
    }

    #[test]
    fn from_root_walks_existing_tables() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(&mut t, 0x2000, 0x4000_2000, PAGE_SIZE, Attrs::KERNEL_DATA)
            .unwrap();
        let again = PageTable::from_root(pt.root());
        assert_eq!(again.translate(&t, 0x2000).unwrap().0, 0x4000_2000);
    }

    #[test]
    fn user_page_descriptors() {
        assert_eq!(
            page_descriptor(0x4567_8000, Attrs::USER_DATA),
            0x0060_0000_4567_8F43
        );
        assert_eq!(
            page_descriptor(0x4567_8000, Attrs::USER_RODATA),
            0x0060_0000_4567_8FC3
        );
        assert_eq!(
            page_descriptor(0x4567_8000, Attrs::USER_TEXT),
            0x0020_0000_4567_8FC3
        );
        for attrs in [Attrs::USER_TEXT, Attrs::USER_RODATA, Attrs::USER_DATA] {
            assert!(attrs.is_valid());
            let d = page_descriptor(0x4567_8000, attrs);
            assert_ne!(d & NG, 0, "user pages are not global");
            assert_ne!(d & PXN, 0, "the kernel never executes a user page");
        }
    }

    #[test]
    fn user_ranges_map_as_pages_even_where_a_block_fits() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map_user(&mut t, 0x20_0000, 0x4020_0000, BLOCK_2M, Attrs::USER_DATA)
            .unwrap();
        let (pa, d) = pt.translate(&t, 0x20_0000).unwrap();
        assert_eq!((pa, d & 0b11), (0x4020_0000, 0b11));
        let (pa, d) = pt.translate(&t, 0x3F_F123).unwrap();
        assert_eq!((pa, d & 0b11), (0x403F_F123, 0b11));
    }

    #[test]
    fn user_ranges_refuse_kernel_attributes() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        assert_eq!(
            pt.map_user(&mut t, 0x1000, 0x4000_0000, PAGE_SIZE, Attrs::KERNEL_DATA),
            Err(MapError::NotUser)
        );
        let wx = Attrs {
            write: true,
            ..Attrs::USER_TEXT
        };
        assert_eq!(
            pt.map_user(&mut t, 0x1000, 0x4000_0000, PAGE_SIZE, wx),
            Err(MapError::WriteAndExecute)
        );
        assert_eq!(pt.translate(&t, 0x1000), None);
    }

    #[test]
    fn user_ranges_stay_below_user_end() {
        let end = USER_END as u64;
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        let d = Attrs::USER_DATA;
        assert_eq!(
            pt.map_user(&mut t, end, 0x4000_0000, PAGE_SIZE, d),
            Err(MapError::NotUser)
        );
        assert_eq!(
            pt.map_user(&mut t, end - PAGE_SIZE, 0x4000_0000, 2 * PAGE_SIZE, d),
            Err(MapError::NotUser)
        );
        assert_eq!(
            pt.map_user(&mut t, u64::MAX - PAGE_SIZE + 1, 0x4000_0000, PAGE_SIZE, d),
            Err(MapError::NotUser)
        );
        pt.map_user(&mut t, end - PAGE_SIZE, 0x4000_0000, PAGE_SIZE, d)
            .unwrap();
        assert_eq!(pt.translate(&t, end - 1).unwrap().0, 0x4000_0FFF);
    }

    #[test]
    fn unmapping_a_page_returns_its_frame() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map_user(&mut t, 0x1000, 0x4000_0000, 2 * PAGE_SIZE, Attrs::USER_DATA)
            .unwrap();
        assert_eq!(pt.unmap_page(&mut t, 0x1000), Ok(0x4000_0000));
        assert_eq!(pt.translate(&t, 0x1000), None);
        assert_eq!(pt.translate(&t, 0x2000).unwrap().0, 0x4000_1000);
        assert_eq!(pt.unmap_page(&mut t, 0x1000), Err(MapError::NotMapped));
    }

    #[test]
    fn unmapping_needs_a_page_address() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map_user(&mut t, 0x1000, 0x4000_0000, PAGE_SIZE, Attrs::USER_DATA)
            .unwrap();
        assert_eq!(pt.unmap_page(&mut t, 0x1008), Err(MapError::Misaligned));
        assert!(pt.translate(&t, 0x1000).is_some());
    }

    #[test]
    fn unmapping_where_nothing_is_mapped_creates_no_tables() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        assert_eq!(pt.unmap_page(&mut t, 0x1234_5000), Err(MapError::NotMapped));
        assert_eq!(t.allocated(), [pt.root()]);
    }

    #[test]
    fn unmapping_leaves_a_block_alone() {
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
        assert_eq!(pt.unmap_page(&mut t, 0x4000_1000), Err(MapError::NotMapped));
        assert!(pt.translate(&t, 0x4000_1000).is_some());
    }

    #[test]
    fn release_frees_every_table_once() {
        let mut t = tables(16);
        let mut pt = PageTable::new(&mut t).unwrap();
        // Two leaf tables under one L2 table, a second L1 entry, a second and
        // the last L0 entry: 1 root, 3 L1, 4 L2 and 5 L3 tables.
        for va in [
            0x1000,
            0x40_0000,
            0x4000_0000,
            0x80_0000_0000,
            USER_END as u64 - PAGE_SIZE,
        ] {
            pt.map_user(&mut t, va, 0x5000_0000, PAGE_SIZE, Attrs::USER_DATA)
                .unwrap();
        }
        let root = pt.root();
        assert_eq!(pt.release(&mut t), 13);
        let mut freed = t.freed.clone();
        assert_eq!(freed.last(), Some(&root), "the root goes last");
        freed.sort();
        assert_eq!(freed, t.allocated(), "each table exactly once");
        assert!(
            !freed.contains(&0x5000_0000),
            "a mapped page is not a table"
        );
    }

    #[test]
    fn release_in_steps_frees_every_table_once() {
        let mut t = tables(16);
        let mut pt = PageTable::new(&mut t).unwrap();
        // As in release_frees_every_table_once: 1 root, 3 L1, 4 L2 and 5 L3.
        for va in [
            0x1000,
            0x40_0000,
            0x4000_0000,
            0x80_0000_0000,
            USER_END as u64 - PAGE_SIZE,
        ] {
            pt.map_user(&mut t, va, 0x5000_0000, PAGE_SIZE, Attrs::USER_DATA)
                .unwrap();
        }
        let root = pt.root();
        let mut release = pt.into_release();
        let mut steps = 1;
        while !release.step(&mut t) {
            steps += 1;
        }
        // A step per child table of levels 0-2 and one to free each of
        // them: (3 + 1) + (4 + 3) + (5 + 4).
        assert_eq!((steps, release.freed()), (20, 13));
        let mut freed = t.freed.clone();
        assert_eq!(freed.last(), Some(&root), "the root goes last");
        freed.sort();
        assert_eq!(freed, t.allocated(), "each table exactly once");
        // Once done, a step does nothing.
        assert!(release.step(&mut t));
        assert_eq!(t.freed.len(), 13);
    }

    #[test]
    fn a_step_reads_at_most_one_table() {
        // A page every 2 MiB through 1 GiB: 512 L3 tables under one L2.
        let mut t = tables(516);
        let mut pt = PageTable::new(&mut t).unwrap();
        for va in (0..1 << 30).step_by(BLOCK_2M as usize) {
            pt.map_user(&mut t, va, 0x5000_0000, PAGE_SIZE, Attrs::USER_DATA)
                .unwrap();
        }
        let all = t.allocated();
        assert_eq!(all.len(), 515);
        let leaves: Vec<u64> = all[3..].to_vec();
        t.take_reads();
        let mut release = pt.into_release();
        let mut steps = 0;
        loop {
            let freed = t.freed.len();
            let done = release.step(&mut t);
            steps += 1;
            let reads = t.take_reads();
            let table = reads.first().map(|pa| pa & !(PAGE_SIZE - 1));
            assert!(
                reads.len() <= 512,
                "step {steps} read {} words",
                reads.len()
            );
            assert!(
                reads.iter().all(|pa| Some(pa & !(PAGE_SIZE - 1)) == table),
                "step {steps} read more than one table"
            );
            assert!(
                table.is_none_or(|table| !leaves.contains(&table)),
                "step {steps} read a level-3 table"
            );
            assert!(t.freed.len() - freed <= 1, "step {steps} freed two tables");
            if done {
                break;
            }
        }
        // Root and L1: a step to enter and one to free; L2: one per leaf
        // and one to free itself.
        assert_eq!((steps, release.freed()), (2 + 2 + 513, 515));
    }

    #[test]
    fn release_skips_blocks() {
        let mut t = tables(8);
        let mut pt = PageTable::new(&mut t).unwrap();
        pt.map(
            &mut t,
            0x4000_0000,
            0x4000_0000,
            BLOCK_2M + PAGE_SIZE,
            Attrs::KERNEL_DATA,
        )
        .unwrap();
        assert_eq!(pt.release(&mut t), 4);
        let mut freed = t.freed.clone();
        freed.sort();
        assert_eq!(freed, t.allocated());
    }
}
