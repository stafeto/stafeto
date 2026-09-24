// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Processes (spec 4): for now an address space, the frames the process
//! owns there and the count of its threads, in objects from a kernel pool.
//! The handle table, quotas and the priority ceiling come with the system
//! calls that need them.

use crate::mm::aspace::AddressSpace;
use crate::mm::pages::KernelPages;
use crate::mm::phys::FRAMES;
use abi::Error;
use core::ptr::NonNull;
use kcore::frames::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;
use kcore::paging::{Attrs, MapError};
use kcore::slab::Pool;
use kcore::sync::Lock;

/// Blocks of frames one process may own.
const MAX_BLOCKS: usize = 8;

pub struct Process {
    /// Destroyed first by `destroy`: TTBR0 leaves its tables, its TLB
    /// entries go and the tables return to the allocator before `frames`
    /// gives back the frames the tables mapped.
    pub space: AddressSpace,
    frames: OwnedFrames,
    threads: usize,
}

/// Blocks of frames, as (physical address, order), that `release` gives
/// back to the allocator when their owner goes.
struct OwnedFrames([Option<(u64, u8)>; MAX_BLOCKS]);

impl OwnedFrames {
    /// Gives every block back to the frame allocator.
    fn release(&mut self) {
        let mut guard = FRAMES.lock();
        let frames = guard.as_mut().expect("frame allocator");
        for (pa, order) in self.0.iter_mut().filter_map(Option::take) {
            frames.free(pa, order);
        }
    }
}

impl Drop for OwnedFrames {
    fn drop(&mut self) {
        // Only a check, as for AddressSpace: the work is `release`'s.
        assert!(
            self.0.iter().all(Option::is_none),
            "frames dropped without release"
        );
    }
}

static PROCESSES: Lock<Pool<Process>> = Lock::new(Pool::new());

impl Process {
    /// Maps `size` bytes of fresh zeroed frames at `va` with `attrs` and
    /// returns their physical address, through which the kernel fills them
    /// (the linear map). The frames belong to the process until it goes.
    /// INVALID_ARGS for a range that is not whole pages or cannot be mapped,
    /// NO_MEMORY when frames or table memory run out or the process owns
    /// MAX_BLOCKS blocks already. O(size) with interrupts masked: for tests
    /// and for loading init at boot; calls from programs map memory objects
    /// in portions (spec 7.7).
    #[cfg_attr(
        not(feature = "ktest"),
        expect(
            dead_code,
            reason = "the loader of init (milestone 1.2c) maps frames; so far only the kernel tests do"
        )
    )]
    pub fn map_frames(&mut self, va: usize, size: u64, attrs: Attrs) -> Result<u64, Error> {
        if size == 0 || !size.is_multiple_of(PAGE_SIZE) || !(va as u64).is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidArgs);
        }
        let slot = self
            .frames
            .0
            .iter()
            .position(Option::is_none)
            .ok_or(Error::NoMemory)?;
        let order = (size / PAGE_SIZE).next_power_of_two().trailing_zeros() as u8;
        let pa = FRAMES
            .lock()
            .as_mut()
            .expect("frame allocator")
            .alloc(order)
            .ok_or(Error::NoMemory)?;
        // SAFETY: the block was just allocated and lies in the linear map;
        // no program sees it before it is zeroed.
        unsafe {
            core::ptr::write_bytes(
                (LINEAR_BASE + pa as usize) as *mut u8,
                0,
                (PAGE_SIZE << order) as usize,
            )
        };
        // Owned before it is mapped: on an error part of the range may be
        // mapped, and the frames must stay until the tables go.
        self.frames.0[slot] = Some((pa, order));
        self.space.map(va, pa, size, attrs).map_err(|e| match e {
            MapError::NoMemory => Error::NoMemory,
            _ => Error::InvalidArgs,
        })?;
        Ok(pa)
    }

    pub fn add_thread(&mut self) {
        self.threads += 1;
    }

    pub fn remove_thread(&mut self) {
        self.threads -= 1;
    }
}

/// A process with an empty address space. NO_MEMORY when no frame is left
/// for its root table or its pool.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "init (milestone 1.2c) is the first process; so far only the kernel tests do"
    )
)]
pub fn create() -> Result<NonNull<Process>, Error> {
    let space = AddressSpace::new().map_err(|_| Error::NoMemory)?;
    let process = Process {
        space,
        frames: OwnedFrames([None; MAX_BLOCKS]),
        threads: 0,
    };
    let allocated = PROCESSES.lock().alloc(&mut KernelPages, process);
    allocated.map_err(|mut process| {
        // No object for it: its space goes, with the pool's lock released.
        process.space.destroy();
        Error::NoMemory
    })
}

/// Destroys a process. Everything it holds goes here and nowhere else,
/// in this order: its address space (TTBR0 leaves the tables, their TLB
/// entries go, the tables return to the allocator), then the frames it
/// owned, which the tables mapped. Each step takes its locks alone; the
/// pool's lock comes last, when nothing in the object owns memory any more.
///
/// # Safety
/// `process` came from `create`, and nothing uses it afterwards.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "process_exit (milestone 1.2c) destroys processes; so far only the kernel tests do"
    )
)]
pub unsafe fn destroy(mut process: NonNull<Process>) {
    // SAFETY: the caller hands over a live process.
    let p = unsafe { process.as_mut() };
    assert!(
        p.threads == 0,
        "a process goes while it has {} threads",
        p.threads
    );
    p.space.destroy();
    p.frames.release();
    // SAFETY: as above.
    unsafe { PROCESSES.lock().free(process) };
}

/// Objects the process pool holds now.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    PROCESSES.lock().in_use()
}
