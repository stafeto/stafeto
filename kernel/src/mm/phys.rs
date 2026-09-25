// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Physical memory: the frame allocator and the linear-map access it uses.
//! At first only RAM in the GiBs head.S mapped is usable; the rest joins
//! once the kernel page tables map all RAM.

use crate::boot::Boot;
use kcore::PAGE_SIZE;
use kcore::bootinfo::{Region, RegionList};
use kcore::frames::{FrameAllocator, PhysMem};
use kcore::layout::{GIB, LINEAR_BASE};
use kcore::memmap;
use kcore::sync::Lock;

/// Physical memory through the linear map. `read` and `write` take any
/// physical address, so only code that owns the memory it names may make one.
pub struct LinearMem(());

impl LinearMem {
    /// # Safety
    /// Every address later passed to `read` or `write` is RAM the caller
    /// owns: free frames for the allocator, tables of a tree it builds, or
    /// frames it has just taken.
    pub const unsafe fn new() -> LinearMem {
        LinearMem(())
    }
}

// SAFETY: the linear map holds all RAM as normal memory, so a word written
// at `LINEAR_BASE + pa` reads back there. The allocator is given only RAM
// that nothing else uses.
unsafe impl PhysMem for LinearMem {
    fn read(&self, pa: u64) -> u64 {
        // SAFETY: callers touch only RAM that the linear map covers.
        unsafe { ((LINEAR_BASE + pa as usize) as *const u64).read() }
    }

    fn write(&mut self, pa: u64, value: u64) {
        // SAFETY: as in `read`.
        unsafe { ((LINEAR_BASE + pa as usize) as *mut u64).write(value) }
    }
}

pub type Frames = FrameAllocator<'static, LinearMem>;

pub static FRAMES: Lock<Option<Frames>> = Lock::new(None);

/// The allocator's metadata, which `init` carves out of usable RAM.
static METADATA: Lock<Region> = Lock::new(Region { base: 0, size: 0 });

/// Starts the allocator with the usable RAM that is mapped now; returns the
/// rest, which becomes reachable with the kernel page tables.
pub fn init(boot: &Boot) -> RegionList<32> {
    let memory = boot.info.memory.as_slice();
    let span_base = memory.iter().map(|r| r.base).min().expect("no memory") / PAGE_SIZE * PAGE_SIZE;
    let span_end = memory.iter().map(|r| r.end()).max().expect("no memory");
    let meta_len = Frames::meta_bytes(span_end - span_base);
    let meta_size = (meta_len as u64).div_ceil(PAGE_SIZE) * PAGE_SIZE;

    let gib = |pa: u64| Region {
        base: pa / GIB * GIB,
        size: GIB,
    };
    let both = [gib(boot.kernel_pa), gib(boot.dtb.base)];
    let mapped: &[Region] = if both[0] == both[1] {
        &both[..1]
    } else {
        &both
    };

    let mut now: RegionList<64> = RegionList::new();
    for r in boot.usable.as_slice() {
        for w in mapped {
            if let Some(c) = memmap::clip(*r, *w) {
                now.push(c).expect("too many usable regions");
            }
        }
    }
    let host = now
        .as_slice()
        .iter()
        .position(|r| r.size >= meta_size)
        .expect("no room for frame allocator metadata");
    let meta_pa = now.as_slice()[host].base;
    *METADATA.lock() = Region {
        base: meta_pa,
        size: meta_size,
    };
    // SAFETY: these pages are usable RAM in a mapped GiB, and nothing else uses them.
    let meta = unsafe {
        core::slice::from_raw_parts_mut((LINEAR_BASE + meta_pa as usize) as *mut u8, meta_len)
    };
    // SAFETY: the allocator touches only the RAM given to it below, which
    // nothing else uses.
    let mut frames = Frames::new(unsafe { LinearMem::new() }, span_base, meta);
    for (i, r) in now.as_slice().iter().enumerate() {
        let base = if i == host {
            r.base + meta_size
        } else {
            r.base
        };
        frames.add_region(base, r.end());
    }
    *FRAMES.lock() = Some(frames);
    memmap::usable(boot.usable.as_slice(), mapped).expect("memory map")
}

/// Where the allocator keeps its metadata.
#[cfg(feature = "ktest")]
pub fn metadata() -> Region {
    *METADATA.lock()
}

pub fn free_frames() -> u64 {
    FRAMES.lock().as_ref().map_or(0, |f| f.free_frames())
}

/// Hands more RAM to the allocator.
pub fn add(regions: &[Region]) {
    let mut guard = FRAMES.lock();
    let frames = guard.as_mut().expect("frame allocator");
    for r in regions {
        frames.add_region(r.base, r.end());
    }
}
