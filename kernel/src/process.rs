// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Processes (spec 4, 8): an address space, the frames the process owns
//! there, its handle table, its priority ceiling, its threads and how it
//! lives, in objects from a kernel pool. A process lives while references
//! to it are left: handles to it, its threads, and the one `create` hands
//! out; the last `release` queues it for cleanup, and its portion takes it
//! apart (`clean`). A process ends earlier (`end`):
//! process_exit, process_kill, a fault at EL0 or the exit of its last
//! started thread stop its threads and give back what it holds, and a
//! shell with the reason stays for object_info until the last reference
//! (spec 4, 7.9). Every release names the level of its cause, which the
//! cleanup it may start takes (spec 7.7).
//! Quotas come with the calls that need them.

use crate::cleanup::{self, Item};
use crate::mm::aspace::AddressSpace;
use crate::mm::pages::KernelPages;
use crate::mm::phys::FRAMES;
use crate::object::{self, Chunks, Handles, Object};
use crate::sched;
use crate::thread::{self, Siblings, Thread};
use abi::{Error, Handle, ProcessState, Rights};
use core::ptr::NonNull;
use kcore::frames::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;
use kcore::paging::{Attrs, MapError};
use kcore::process::Life;
use kcore::slab::Pool;
use kcore::sync::Lock;

/// Blocks of frames one process may own.
const MAX_BLOCKS: usize = 8;

pub struct Process {
    /// Destroyed before `frames` and the threads' message buffers go:
    /// TTBR0 leaves its tables, its TLB entries go and the tables return
    /// to the allocator before the frames the tables mapped. Present from
    /// `create` until the process ends or goes; destroying a space
    /// consumes it.
    space: Option<AddressSpace>,
    frames: OwnedFrames,
    /// Released first when the process ends or goes: its handles hold
    /// references to other objects.
    handles: Handles,
    /// Handles to the process, its threads, and the reference `create`
    /// hands out.
    refs: u32,
    /// No thread of the process gets a base priority above it (spec 8).
    ceiling: u8,
    /// The threads it started and whether it ended, and why.
    life: Life,
    /// The process's threads, alive or ended, linked through
    /// Thread::siblings: a thread joins at `create` and leaves when it goes.
    threads: Option<NonNull<Thread>>,
    /// Init's end ends the run (spec 7.9).
    init: bool,
    /// Its place in the cleanup queue once its last reference goes.
    cleanup: Item,
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

// SAFETY: processes and their threads are reached under the kernel's
// rules (spec 8.1): one CPU, interrupts masked inside the kernel, the
// pools behind locks.
unsafe impl Send for Process {}

static PROCESSES: Lock<Pool<Process>> = Lock::new(Pool::new());

impl Process {
    fn space(&mut self) -> &mut AddressSpace {
        self.space
            .as_mut()
            .expect("a process is used after its address space went")
    }

    /// Destroys the address space (AddressSpace::destroy) unless it went
    /// already; the process has none afterwards.
    fn destroy_space(&mut self) {
        if let Some(space) = self.space.take() {
            space.destroy();
        }
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
        self.life.state()
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
/// its first reference. INVALID_ARGS for a limit outside
/// 1-kcore::handles::MAX_HANDLES or a ceiling outside 1-63, NO_MEMORY when
/// no frame is left for its root table or its pool.
pub fn create(handle_limit: u32, ceiling: u8) -> Result<NonNull<Process>, Error> {
    let ceiling = kcore::sched::priority_arg(u64::from(ceiling))?;
    kcore::process::handle_limit_arg(u64::from(handle_limit))?;
    let handles = Handles::new(handle_limit).map_err(Error::from)?;
    let space = AddressSpace::new().map_err(|_| Error::NoMemory)?;
    let process = Process {
        space: Some(space),
        frames: OwnedFrames([None; MAX_BLOCKS]),
        handles,
        refs: 1,
        ceiling,
        life: Life::new(),
        threads: None,
        init: false,
        cleanup: Item::new(),
    };
    let allocated = PROCESSES.lock().alloc(&mut KernelPages, process);
    allocated.map_err(|mut process| {
        // No object for it: its space goes, with the pool's lock released.
        process.destroy_space();
        Error::NoMemory
    })
}

/// The count of references to `process`. Only the count is borrowed,
/// through the raw pointer: the process's own table may be in the middle
/// of `release_with` meanwhile (`release_contents`). Test builds stop a
/// process that went: the poison of its slot reaches the count.
///
/// # Safety
/// `process` is alive, and nothing else borrows the count.
unsafe fn refs<'a>(process: NonNull<Process>) -> &'a mut u32 {
    // SAFETY: the caller's promise; only the field is borrowed.
    let refs = unsafe { &mut (*process.as_ptr()).refs };
    #[cfg(feature = "ktest")]
    assert!(
        *refs != u32::from_ne_bytes([POISON; 4]),
        "a process is used after it went"
    );
    refs
}

/// Adds a reference to a live process. A process nobody refers to waits
/// for its portion, and taking it back from the queue would free it twice.
pub fn retain(process: NonNull<Process>) {
    // SAFETY: the caller holds a reference, so the process is alive.
    let refs = unsafe { refs(process) };
    assert!(*refs > 0, "a process nobody refers to is retained");
    *refs = refs.checked_add(1).expect("process references overflow");
}

/// Drops a reference; the last one queues the process for cleanup at
/// `cause`, the level of the cleanup this release starts (spec 7.7).
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
pub unsafe fn release(process: NonNull<Process>, cause: u8) {
    // SAFETY: the caller's reference keeps the process alive until here.
    let last = unsafe {
        let refs = refs(process);
        *refs = refs
            .checked_sub(1)
            .expect("a process is released once too often");
        *refs == 0
    };
    if last {
        // SAFETY: that was the last reference: nothing reaches the process
        // until its portion, and the pool keeps it in place.
        unsafe {
            let item = NonNull::new_unchecked(&raw mut (*process.as_ptr()).cleanup);
            cleanup::enqueue(item, Object::Process(process), cause);
        }
    }
}

/// The portion of a process nobody refers to (cleanup): what it holds
/// goes, unless it went when the process ended (`release_contents`), and
/// then the shell. What it releases is queued at `level`. The pool's lock
/// comes last, when nothing in the object owns memory any more.
///
/// # Safety
/// No reference to `process` is left, and it is in no queue.
pub unsafe fn clean(process: NonNull<Process>, level: u8) {
    // SAFETY: no reference is left, so no handle in the table names this
    // process or one of its threads, each of which would hold one: the
    // objects released there are other processes' and threads'.
    unsafe { release_contents(process, level) };
    // SAFETY: nothing refers to the process any more.
    unsafe { PROCESSES.lock().free(process) };
    // Test builds poison the slot past the pool's link: a use after free
    // then reads garbage instead of the old fields, and `life` stops it.
    #[cfg(feature = "ktest")]
    // SAFETY: the slot is the pool's again; its first word is the link.
    unsafe {
        core::ptr::write_bytes(
            process.cast::<u8>().as_ptr().add(8),
            POISON,
            core::mem::size_of::<Process>() - 8,
        )
    };
}

/// What test builds fill a gone process with, past the pool's link.
#[cfg(feature = "ktest")]
const POISON: u8 = 0xA5;

// The poison reaches `refs`, which `refs` checks.
#[cfg(feature = "ktest")]
const _: () = assert!(core::mem::offset_of!(Process, refs) >= 8);

/// Gives back what the process holds, in this order: its handles, each
/// releasing its object, which may queue that object for cleanup at
/// `cause`; its address space (TTBR0 leaves the tables, their TLB entries
/// go, the tables return to the allocator); the message buffers of the
/// threads that are left, and the frames the process owned, which the
/// tables mapped. Each step takes its locks alone. A second call finds
/// nothing left to do.
///
/// # Safety
/// `process` is alive, and nothing borrows its table.
unsafe fn release_contents(process: NonNull<Process>, cause: u8) {
    let p = process.as_ptr();
    // SAFETY: only the table is borrowed: releasing its objects may reach
    // the process's other fields (`refs`, `space`, `threads`) through its
    // threads, but never the table.
    let handles = unsafe { &mut (*p).handles };
    handles.release_with(&mut Chunks, |object| {
        // SAFETY: the table is gone, and with it the handle's reference.
        unsafe { object::release(object, cause) }
    });
    // SAFETY: the table is done; nothing else borrows the process now.
    unsafe {
        (*p).destroy_space();
        let mut next = (*p).threads;
        while let Some(t) = next {
            next = (*t.as_ptr()).siblings.next;
            // Shells that handles elsewhere hold: their pages went with
            // the space.
            thread::drop_buffer(t);
        }
        (*p).frames.release();
    }
}

/// Ends `process` with `reason` unless it ended before, when the first
/// reason stays: process_exit, process_kill and a fault at EL0 come here. Every thread of the process leaves the scheduler for good;
/// the handle table, the address space, the threads' message buffers and
/// the frames go; a shell with the reason stays for `object_info` until
/// the last reference. What that releases is queued for cleanup at
/// `cause`: the effective priority of the thread that made the call or
/// the fault. The running thread may be one of the process's: it never
/// runs again and may be gone afterwards, so the caller leaves through
/// sched::resume. When the process is init, the run ends (`init_ended`).
///
/// # Safety
/// The caller holds a reference to `process`.
pub unsafe fn end(process: NonNull<Process>, reason: ProcessState, cause: u8) {
    // SAFETY: the caller's reference keeps the process alive.
    if unsafe { (*life(process)).end(reason) } {
        // SAFETY: as above; the end was just recorded.
        unsafe { teardown(process, cause) };
    }
}

/// A started thread of `process` ended through thread_exit; the last one
/// ends the process with code 0, with the thread's priority as the
/// `cause`. Threads that never started do not count.
///
/// # Safety
/// As for `end`.
pub unsafe fn thread_exited(process: NonNull<Process>, cause: u8) {
    // SAFETY: the caller's reference keeps the process alive.
    if unsafe { (*life(process)).exit() } {
        // SAFETY: as above; the end was just recorded.
        unsafe { teardown(process, cause) };
    }
}

/// A thread of `process` starts (thread::start): BAD_STATE once the
/// process has ended. The caller holds a reference to the process.
pub fn thread_started(process: NonNull<Process>) -> Result<(), Error> {
    // SAFETY: the caller's reference keeps the process alive.
    unsafe { (*life(process)).start() }
}

/// BAD_STATE once `process` has ended; the caller holds a reference.
pub fn check_alive(process: NonNull<Process>) -> Result<(), Error> {
    // SAFETY: the caller's reference keeps the process alive.
    if unsafe { (*life(process)).is_alive() } {
        Ok(())
    } else {
        Err(Error::BadState)
    }
}

/// The process's life, as a raw pointer to its field (see `refs`). Test
/// builds stop a process that went, as `refs` does.
///
/// # Safety
/// `process` is alive.
unsafe fn life(process: NonNull<Process>) -> *mut Life {
    // SAFETY: the caller's promise; the count is only checked.
    unsafe { refs(process) };
    // SAFETY: the caller's promise.
    unsafe { &raw mut (*process.as_ptr()).life }
}

/// The rest of an end whose reason was just recorded: the threads stop,
/// then what the process holds goes (`release_contents`), releases queued
/// at `cause`. A reference taken for the while keeps the process through
/// its threads' and its table's releases, which may drop every other one.
/// From milestone 1.3 the quota goes back to the parent and the exit
/// channel hears of the end afterwards.
///
/// # Safety
/// As for `end`.
unsafe fn teardown(process: NonNull<Process>, cause: u8) {
    retain(process);
    let p = process.as_ptr();
    // SAFETY: the reference above keeps the process alive. A thread whose
    // last reference was the kernel's stays until its portion, in the list.
    unsafe {
        let mut next = (*p).threads;
        while let Some(t) = next {
            next = (*t.as_ptr()).siblings.next;
            sched::exit(t, cause);
        }
        release_contents(process, cause);
    }
    // SAFETY: as above.
    let (init, state) = unsafe { ((*p).init, (*life(process)).state()) };
    // SAFETY: the reference taken above.
    unsafe { release(process, cause) };
    if init {
        init_ended(state);
    }
}

/// Init ended (spec 7.9): until milestone 1.4 an exit ends the run and
/// turns the machine off, while a fault or a kill stops it with a report,
/// as a panic does.
#[cfg(not(feature = "ktest"))]
fn init_ended(state: ProcessState) -> ! {
    match state {
        ProcessState::Exited { code } => {
            kprintln!("init exited with code {code}");
            crate::psci::system_off()
        }
        ProcessState::Fault { esr, far, elr } => {
            panic!("init terminated by a fault: ESR={esr:#x} FAR={far:#x} ELR={elr:#x}")
        }
        other => panic!("init terminated: {other:?}"),
    }
}

/// In test builds the running test judges init's end and the tests go on.
#[cfg(feature = "ktest")]
fn init_ended(_: ProcessState) -> ! {
    crate::ktest::el0::init_ended()
}

/// Marks `process` as init (spec 13.3): its end ends the run.
pub fn set_init(process: NonNull<Process>) {
    // SAFETY: the caller holds a reference to the process.
    unsafe { (*process.as_ptr()).init = true };
}

/// Whether `process` is init.
pub fn is_init(process: NonNull<Process>) -> bool {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    unsafe { (*process.as_ptr()).init }
}

/// Puts `t`, a new thread of `process`, at the head of its threads.
pub fn add_thread(process: NonNull<Process>, t: NonNull<Thread>) {
    // SAFETY: the process and its threads are alive, and a thread holds a
    // reference to its process; only the list's fields are touched.
    unsafe {
        let head = &raw mut (*process.as_ptr()).threads;
        let old = *head;
        (*t.as_ptr()).siblings = Siblings {
            prev: None,
            next: old,
        };
        if let Some(o) = old {
            (*o.as_ptr()).siblings.prev = Some(t);
        }
        *head = Some(t);
    }
}

/// Takes `t` out of its process's threads, when it goes.
///
/// # Safety
/// `t` is a live thread of `process`, in its list.
pub unsafe fn remove_thread(process: NonNull<Process>, t: NonNull<Thread>) {
    // SAFETY: the caller's promise; only the list's fields are touched.
    unsafe {
        let Siblings { prev, next } = (*t.as_ptr()).siblings;
        match prev {
            Some(p) => (*p.as_ptr()).siblings.next = next,
            None => (*process.as_ptr()).threads = next,
        }
        if let Some(n) = next {
            (*n.as_ptr()).siblings.prev = prev;
        }
    }
}

/// Maps the frame at `pa` at page `va` of the process with `attrs`.
/// INVALID_ARGS for a page that is mapped already or outside the lower
/// half, NO_MEMORY when no frame is left for a table.
pub fn map_page(process: NonNull<Process>, va: usize, pa: u64, attrs: Attrs) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process; only the field
    // is borrowed (see `retain`).
    let space = unsafe { &mut (*process.as_ptr()).space };
    let space = space.as_mut().ok_or(Error::BadState)?;
    space.map(va, pa, PAGE_SIZE, attrs).map_err(|e| match e {
        MapError::NoMemory => Error::NoMemory,
        _ => Error::InvalidArgs,
    })
}

/// Unmaps page `va` of the process and drops its TLB entry; returns the
/// frame it mapped, or None when nothing maps it or the process's space
/// went with its end.
pub fn unmap_page(process: NonNull<Process>, va: usize) -> Option<u64> {
    // SAFETY: as in `map_page`.
    let space = unsafe { &mut (*process.as_ptr()).space };
    space.as_mut()?.unmap(va).ok()
}

/// What page `va` of the process translates to: the frame and the leaf
/// descriptor; None when nothing maps it or the process's space went.
pub fn translate(process: NonNull<Process>, va: usize) -> Option<(u64, u64)> {
    // SAFETY: as in `map_page`.
    let space = unsafe { &(*process.as_ptr()).space };
    space.as_ref()?.translate(va)
}

/// Puts `object` in the handle table of `process` with `rights`; the new
/// handle holds a reference to it. LIMIT_REACHED at the table's limit,
/// NO_MEMORY when no chunk is left for the table. The process lives: the
/// table of one that ended stays empty.
pub fn insert_handle(
    mut process: NonNull<Process>,
    object: Object,
    rights: Rights,
) -> Result<Handle, Error> {
    assert!(
        check_alive(process).is_ok(),
        "a handle went into the table of a process that ended"
    );
    // SAFETY: the caller holds a reference to the process.
    let h = unsafe { process.as_mut() }
        .handles
        .insert(&mut Chunks, object, rights)
        .map_err(Error::from)?;
    object::retain(object);
    Ok(h)
}

/// Closes handle `h` of `process`: its reference goes, and the last one
/// queues the object for cleanup at `cause`. BAD_HANDLE for a handle that
/// is not live.
pub fn close_handle(mut process: NonNull<Process>, h: Handle, cause: u8) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process other than the
    // handle, so the process outlives the release below.
    let (object, _) = unsafe { process.as_mut() }
        .handles
        .remove(h)
        .map_err(Error::from)?;
    // SAFETY: the handle is gone, and its reference with it.
    unsafe { object::release(object, cause) };
    Ok(())
}

/// Puts init's first handles in the fresh table of `init` (spec 13.3): the
/// system resource with every right, init's process and its `first`
/// thread, and an entry for the boot image that goes at once, so that
/// INIT_BOOT_IMAGE stays bad (until milestone 1.3 brings the boot image as
/// a memory object). The values follow from the order in a fresh table and
/// are those abi fixes.
pub fn install_init_handles(init: NonNull<Process>, first: NonNull<Thread>) -> Result<(), Error> {
    let handles = [
        insert_handle(init, Object::Resource, abi::INIT_RESOURCE_RIGHTS)?,
        insert_handle(init, Object::Process(init), abi::OWNER_RIGHTS)?,
        insert_handle(init, Object::Thread(first), abi::OWNER_RIGHTS)?,
        insert_handle(init, Object::Resource, Rights::NONE)?,
    ];
    // The system resource is never queued: any level will do.
    close_handle(init, handles[3], 1)?;
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
