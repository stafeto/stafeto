// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Processes (spec 4, 8): an address space, the frames the process owns
//! there, its handle table, its priority ceiling and its state, in objects
//! from a kernel pool. A process lives while references to it are left:
//! handles to it, its threads, and the one `create` hands out; the last
//! `release` destroys it. Quotas come with the calls that need them.

use crate::mm::aspace::AddressSpace;
use crate::mm::pages::KernelPages;
use crate::mm::phys::FRAMES;
use crate::object::{self, Chunks, Handles, Object};
use crate::thread::Thread;
use abi::{Error, Handle, ProcessState, Rights};
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
    /// gives back the frames the tables mapped. Present from `create` on;
    /// `destroy` takes it out, since destroying a space consumes it.
    space: Option<AddressSpace>,
    frames: OwnedFrames,
    /// Released first when the process goes: its handles hold references
    /// to other objects.
    handles: Handles,
    /// Handles to the process, its threads, and the reference `create`
    /// hands out.
    refs: u32,
    /// No thread of the process gets a base priority above it (spec 8).
    ceiling: u8,
    state: ProcessState,
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
    fn space(&mut self) -> &mut AddressSpace {
        self.space
            .as_mut()
            .expect("a process is used after its address space went")
    }

    /// Destroys the address space (AddressSpace::destroy); the process has
    /// none afterwards.
    fn destroy_space(&mut self) {
        self.space
            .take()
            .expect("an address space is destroyed twice")
            .destroy();
    }

    /// Puts the process's address space into TTBR0 unless it is there
    /// already. TTBR0 itself says whose space it holds, whatever switched
    /// it.
    pub fn activate(&mut self) {
        let space = self.space();
        if !space.is_active() {
            space.activate();
        }
    }

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
        self.space().map(va, pa, size, attrs).map_err(|e| match e {
            MapError::NoMemory => Error::NoMemory,
            _ => Error::InvalidArgs,
        })?;
        Ok(pa)
    }

    /// Whether the process lives and, if not, why it ended.
    pub fn state(&self) -> ProcessState {
        self.state
    }

    /// The highest base priority a thread of the process may have.
    pub fn ceiling(&self) -> u8 {
        self.ceiling
    }

    /// What `kind` makes of the object behind `h`, checked in the order of
    /// the system calls: BAD_HANDLE, WRONG_TYPE, then ACCESS_DENIED when
    /// the handle lacks `rights`.
    pub fn lookup<U>(
        &self,
        h: Handle,
        rights: Rights,
        kind: impl FnOnce(&Object) -> Option<U>,
    ) -> Result<U, Error> {
        self.handles.get_as(h, rights, kind).map_err(Error::from)
    }
}

/// A process with an empty address space, an empty handle table for up to
/// `handle_limit` handles and priority ceiling `ceiling`; the caller gets
/// its first reference. INVALID_ARGS for a limit above
/// kcore::handles::MAX_HANDLES or a ceiling outside 1-63, NO_MEMORY when
/// no frame is left for its root table or its pool.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "init (milestone 1.2c) is the first process; so far only the kernel tests do"
    )
)]
pub fn create(handle_limit: u32, ceiling: u8) -> Result<NonNull<Process>, Error> {
    let ceiling = kcore::sched::priority_arg(u64::from(ceiling))?;
    let handles = Handles::new(handle_limit).map_err(Error::from)?;
    let space = AddressSpace::new().map_err(|_| Error::NoMemory)?;
    let process = Process {
        space: Some(space),
        frames: OwnedFrames([None; MAX_BLOCKS]),
        handles,
        refs: 1,
        ceiling,
        state: ProcessState::Alive,
    };
    let allocated = PROCESSES.lock().alloc(&mut KernelPages, process);
    allocated.map_err(|mut process| {
        // No object for it: its space goes, with the pool's lock released.
        process.destroy_space();
        Error::NoMemory
    })
}

/// Adds a reference to a live process.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "threads and handles of milestone 1.2c refer to processes; so far only the kernel tests do"
    )
)]
pub fn retain(mut process: NonNull<Process>) {
    // SAFETY: the caller holds a reference, so the process is alive.
    let p = unsafe { process.as_mut() };
    p.refs = p.refs.checked_add(1).expect("process references overflow");
}

/// Drops a reference; the last one destroys the process.
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
pub unsafe fn release(mut process: NonNull<Process>) {
    // SAFETY: the caller's reference keeps the process alive until here.
    let last = unsafe {
        let p = process.as_mut();
        p.refs -= 1;
        p.refs == 0
    };
    if last {
        // SAFETY: that was the last reference.
        unsafe { destroy(process) };
    }
}

/// Destroys a process nobody refers to. Everything it holds goes here and
/// nowhere else, in this order: its handles, each releasing its object,
/// which may destroy that object in turn; its address space (TTBR0 leaves
/// the tables, their TLB entries go, the tables return to the allocator);
/// the frames it owned, which the tables mapped. Each step takes its locks
/// alone; the pool's lock comes last, when nothing in the object owns
/// memory any more.
///
/// # Safety
/// No reference to `process` is left.
unsafe fn destroy(mut process: NonNull<Process>) {
    // SAFETY: no reference is left, so no handle in the table names this
    // process or one of its threads, each of which would hold one: the
    // objects released below are other processes' and threads'.
    let p = unsafe { process.as_mut() };
    p.handles.release_with(&mut Chunks, |object| {
        // SAFETY: the table is gone, and with it the handle's reference.
        unsafe { object::release(object) }
    });
    p.destroy_space();
    p.frames.release();
    // SAFETY: nothing refers to the process any more.
    unsafe { PROCESSES.lock().free(process) };
}

/// Puts `object` in the handle table of `process` with `rights`; the new
/// handle holds a reference to it. LIMIT_REACHED at the table's limit,
/// NO_MEMORY when no chunk is left for the table.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "init's handles and thread_create (milestone 1.2c) make handles; so far only the kernel tests do"
    )
)]
pub fn insert_handle(
    mut process: NonNull<Process>,
    object: Object,
    rights: Rights,
) -> Result<Handle, Error> {
    // SAFETY: the caller holds a reference to the process.
    let h = unsafe { process.as_mut() }
        .handles
        .insert(&mut Chunks, object, rights)
        .map_err(Error::from)?;
    object::retain(object);
    Ok(h)
}

/// Closes handle `h` of `process`: its reference goes, and the object goes
/// with its last one. BAD_HANDLE for a handle that is not live.
pub fn close_handle(mut process: NonNull<Process>, h: Handle) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process other than the
    // handle, so the process outlives the release below.
    let (object, _) = unsafe { process.as_mut() }
        .handles
        .remove(h)
        .map_err(Error::from)?;
    // SAFETY: the handle is gone, and its reference with it.
    unsafe { object::release(object) };
    Ok(())
}

/// Puts init's first handles in the fresh table of `init` (spec 13.3): the
/// system resource with every right, init's process and its `first`
/// thread, and an entry for the boot image that goes at once, so that
/// INIT_BOOT_IMAGE stays bad (until milestone 1.3 brings the boot image as
/// a memory object). The values follow from the order in a fresh table and
/// are those abi fixes.
#[cfg_attr(
    not(feature = "ktest"),
    expect(
        dead_code,
        reason = "the kernel starts init in milestone 1.2c; so far only the kernel tests do"
    )
)]
pub fn install_init_handles(init: NonNull<Process>, first: NonNull<Thread>) -> Result<(), Error> {
    let handles = [
        insert_handle(init, Object::Resource, abi::INIT_RESOURCE_RIGHTS)?,
        insert_handle(init, Object::Process(init), abi::OWNER_RIGHTS)?,
        insert_handle(init, Object::Thread(first), abi::OWNER_RIGHTS)?,
        insert_handle(init, Object::Resource, Rights::NONE)?,
    ];
    close_handle(init, handles[3])?;
    assert_eq!(
        handles,
        [
            abi::INIT_RESOURCE,
            abi::INIT_PROCESS,
            abi::INIT_THREAD,
            abi::INIT_BOOT_IMAGE
        ],
        "init's handles went into a table that was not fresh"
    );
    Ok(())
}

/// Objects the process pool holds now.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    PROCESSES.lock().in_use()
}
