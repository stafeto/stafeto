// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's own translation tables (spec 7.2): the image in 4 KiB pages
//! with W^X and an unmapped guard page under the boot stack, all RAM in the
//! linear map, and the devices the kernel uses.

use super::phys::{self, Frames, LinearMem};
use crate::arch::{mmu, symbols};
use crate::boot::Boot;
use kcore::PAGE_SIZE;
use kcore::bootinfo::Region;
use kcore::frames::PhysMem;
use kcore::layout::{LINEAR_BASE, image_pa};
use kcore::memmap;
use kcore::paging::{Attrs, PageTable, TableMemory};

/// Tables from the frame allocator, reached through the linear map.
pub struct FrameTables<'a> {
    pub frames: &'a mut Frames,
}

// SAFETY: every table is a frame just taken from the allocator and zeroed
// here; the tree owns it until `free_table` gives it back. Tables are
// reached through the linear map.
unsafe impl TableMemory for FrameTables<'_> {
    fn alloc_table(&mut self) -> Option<u64> {
        let pa = self.frames.alloc(0)?;
        // SAFETY: the frame was just taken from the allocator.
        let mut mem = unsafe { LinearMem::new() };
        for i in 0..512 {
            mem.write(pa + i * 8, 0);
        }
        // The zeroes reach the table walker before a parent entry links
        // this table into a live tree; the asm block also keeps the
        // compiler from moving the stores.
        mmu::tables_written();
        Some(pa)
    }

    fn free_table(&mut self, pa: u64) {
        self.frames.free(pa, 0);
    }

    fn read(&self, pa: u64) -> u64 {
        // SAFETY: the trees these tables serve own every table they reach.
        unsafe { LinearMem::new() }.read(pa)
    }

    fn write(&mut self, pa: u64, value: u64) {
        // SAFETY: as in `read`.
        unsafe { LinearMem::new() }.write(pa, value)
    }
}

fn map(
    pt: &mut PageTable,
    mem: &mut FrameTables<'_>,
    va: usize,
    pa: u64,
    size: u64,
    attrs: Attrs,
    what: &str,
) {
    if size == 0 {
        return;
    }
    pt.map(mem, va as u64, pa, size, attrs)
        .unwrap_or_else(|e| panic!("mapping {what} at {va:#x}: {e:?}"));
}

/// A device region widened to whole pages.
fn pages(r: Region) -> (u64, u64) {
    let base = r.base / PAGE_SIZE * PAGE_SIZE;
    let end = r.end().div_ceil(PAGE_SIZE) * PAGE_SIZE;
    (base, end - base)
}

/// Builds the kernel tables and switches TTBR1 to them.
pub fn switch_to_kernel_tables(boot: &Boot) {
    let root = {
        let mut guard = phys::FRAMES.lock();
        let mut mem = FrameTables {
            frames: guard.as_mut().expect("frame allocator"),
        };
        let mut pt = PageTable::new(&mut mem).expect("no frame for the root table");
        let image = symbols::image_layout();
        let pa = |va: usize| image_pa(boot.kernel_pa, va);
        let sections = [
            (
                image.start,
                image.text_end,
                Attrs::KERNEL_TEXT,
                "kernel text",
            ),
            (
                image.text_end,
                image.rodata_end,
                Attrs::KERNEL_RODATA,
                "kernel rodata",
            ),
            (
                image.rodata_end,
                image.stack_guard,
                Attrs::KERNEL_DATA,
                "kernel data, boot tables and emergency stack",
            ),
            (
                image.stack_guard + PAGE_SIZE as usize,
                image.end,
                Attrs::KERNEL_DATA,
                "boot stack",
            ),
        ];
        for (start, end, attrs, what) in sections {
            map(
                &mut pt,
                &mut mem,
                start,
                pa(start),
                (end - start) as u64,
                attrs,
                what,
            );
        }
        let ram = memmap::usable::<32>(boot.info.memory.as_slice(), boot.info.no_map.as_slice())
            .expect("linear map regions");
        for r in ram.as_slice() {
            map(
                &mut pt,
                &mut mem,
                LINEAR_BASE + r.base as usize,
                r.base,
                r.size,
                Attrs::KERNEL_DATA,
                "RAM",
            );
        }
        let info = &boot.info;
        for dev in [
            info.uart_pl011,
            info.gic_distributor,
            info.gic_cpu_interface,
        ]
        .into_iter()
        .flatten()
        {
            let (base, size) = pages(dev);
            map(
                &mut pt,
                &mut mem,
                LINEAR_BASE + base as usize,
                base,
                size,
                Attrs::DEVICE,
                "device",
            );
        }
        pt.root()
    };
    // SAFETY: the new tables map the image at the same addresses with W^X,
    // the boot stack, all RAM and the console.
    unsafe { mmu::replace_ttbr1(root, boot.kernel_pa) };
}
