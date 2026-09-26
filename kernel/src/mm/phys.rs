// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Physical memory: the frame allocator and the linear-map access it uses,
//! and the blocks of frames a holder owns (`Frame`), which the quota of a
//! process pays for (`alloc_zeroed`, `free`). At first only RAM in the GiBs
//! head.S mapped is usable; the rest joins once the kernel page tables map
//! all RAM.

use crate::boot::Boot;
use abi::Error;
use core::ops::Range;
use kcore::PAGE_SIZE;
use kcore::bootinfo::{Region, RegionList};
use kcore::frames::{FrameAllocator, PhysMem};
use kcore::layout::{GIB, LINEAR_BASE};
use kcore::memmap;
use kcore::quota::Account;
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

/// A block of 2^order frames that its holder owns: a message buffer, or a
/// page of a memory object, whose list keeps the address `into_raw` gave
/// until `from_raw` makes it a block again (spec 6.2, 7.3, 7.8). The
/// kernel reaches it through the linear map only, never through the tables
/// of a program, and through raw pointers only: a program may write the
/// block through its own mapping. Neither Copy nor Clone: `free` takes it
/// back, and a block dropped otherwise stops the kernel.
pub struct Frame {
    pa: u64,
    order: u8,
}

impl Frame {
    /// The block at `pa` of 2^`order` frames.
    ///
    /// # Safety
    /// The allocator handed the block out, and nothing else owns it: the
    /// caller took it back from `into_raw` with its order.
    pub unsafe fn from_raw(pa: u64, order: u8) -> Frame {
        Frame { pa, order }
    }

    /// The block as its physical address, for a holder that keeps its
    /// frames by their addresses (the list of pages of a memory object,
    /// kcore::pagelist): the holder owns the block from then on, and
    /// `from_raw` makes it a block again for `free`.
    pub fn into_raw(self) -> u64 {
        let pa = self.pa;
        core::mem::forget(self);
        pa
    }

    /// The physical address of the block.
    pub fn pa(&self) -> u64 {
        self.pa
    }

    /// The block's first byte in the linear map.
    fn base(&self) -> *mut u8 {
        (LINEAR_BASE + self.pa as usize) as *mut u8
    }

    /// The size of the block in bytes.
    fn len(&self) -> usize {
        (PAGE_SIZE as usize) << self.order
    }

    /// The word at byte `offset` of the block (spec 6.2): the value of a
    /// handle a message carries. Panics for an offset that is not a
    /// multiple of 8 or lies past the block.
    pub fn word(&self, offset: usize) -> u64 {
        assert!(
            offset.is_multiple_of(8) && offset < self.len(),
            "a word past a block of frames"
        );
        // SAFETY: the block is RAM the linear map covers, its holder owns
        // it (`from_raw`), and the aligned word lies in it.
        unsafe { self.base().add(offset).cast::<u64>().read() }
    }

    /// Writes `value` into the word at byte `offset` of the block (spec
    /// 6.2): the value or the info word of a handle that came. Panics as
    /// `word` does.
    pub fn set_word(&mut self, offset: usize, value: u64) {
        assert!(
            offset.is_multiple_of(8) && offset < self.len(),
            "a word past a block of frames"
        );
        // SAFETY: as in `word`.
        unsafe { self.base().add(offset).cast::<u64>().write(value) }
    }

    /// Copies the bytes `range` of `src` to the same offsets of this block
    /// (spec 6.2): a part of a message from its sender's buffer. Panics for
    /// a range past either block.
    pub fn copy_from(&mut self, src: &Frame, range: Range<usize>) {
        assert!(
            range.start <= range.end && range.end <= self.len().min(src.len()),
            "a copy past a block of frames"
        );
        // SAFETY: both blocks are RAM the linear map covers, their holders
        // own them (`from_raw`), and the range lies in both; two blocks
        // never overlap, since each has one holder.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.base().add(range.start),
                self.base().add(range.start),
                range.len(),
            )
        };
    }
}

impl Drop for Frame {
    /// A block goes back only through `free`: one dropped otherwise would
    /// leave the allocator and its payer's quota short (spec 7.8).
    fn drop(&mut self) {
        panic!("a frame dropped without phys::free");
    }
}

/// A block of 2^`order` zeroed frames charged to `quota` (spec 7.5, 7.8),
/// which the caller gives back with `free`. NO_MEMORY when the quota falls
/// short, or, for a block of more frames than one, when no free block is
/// big enough; the charge goes back then. A single frame whose charge
/// passed always finds one (spec 7.8).
pub fn alloc_zeroed(order: u8, quota: &mut Account) -> Result<Frame, Error> {
    let size = PAGE_SIZE << order;
    quota.charge(size)?;
    let Some(pa) = FRAMES
        .lock()
        .as_mut()
        .expect("frame allocator")
        .alloc(order)
    else {
        // A block may miss while its frames are free apart; a single frame
        // may not.
        assert!(order > 0, "a charge that passed found no frame (spec 7.8)");
        quota.refund(size);
        return Err(Error::NoMemory);
    };
    // SAFETY: the allocator just handed the block out; no program sees it
    // before it is zeroed.
    let frame = unsafe { Frame::from_raw(pa, order) };
    // SAFETY: as above; the block is RAM the linear map covers.
    unsafe { core::ptr::write_bytes(frame.base(), 0, frame.len()) };
    Ok(frame)
}

/// Gives `frame` back to the allocator and refunds it to `quota`, which
/// paid for it (`alloc_zeroed`, spec 7.5, 7.8).
///
/// # Safety
/// No table of a program maps the frame any more, and the TLB entries of
/// such a mapping went: the allocator may hand the frame to another holder
/// at once.
pub unsafe fn free(frame: Frame, quota: &mut Account) {
    FRAMES
        .lock()
        .as_mut()
        .expect("frame allocator")
        .free(frame.pa, frame.order);
    quota.refund(PAGE_SIZE << frame.order);
    core::mem::forget(frame);
}

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
