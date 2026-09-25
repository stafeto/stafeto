// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Processes (spec 4, 8): an address space, the frames the process owns
//! there, its handle table, its priority ceiling, its threads that have
//! not ended, its parent and children, and how it lives, in objects from a
//! kernel pool. A process lives while references to it are left: handles
//! to it, its threads, and the one `create` hands out; its children hold
//! only its shell. It ends (`end`) through process_exit, process_kill, a
//! fault at EL0 or the exit of its last started thread, when its last
//! reference goes while it lives, and when its parent ends. The end itself
//! only stops its threads,
//! at most abi::MAX_THREADS, and queues the process for cleanup; the queue
//! takes it apart in stages, a portion at a time, with how far it came
//! kept in the process (`Stage`, spec 7.7), its descendants first. A shell
//! with the reason stays for object_info until the last reference queues
//! it once more. Every release names the level of its cause, which the
//! cleanup it may start takes. A process pays from its quota for what goes
//! with it (spec 7.5): its shell, the chunks and directory of its handle
//! table, the tables of its space, its threads and their message buffers,
//! and the frames of `map_frames`. A child's quota comes off its parent's
//! and goes back in two parts: what is free at the child's stage Quota,
//! and the rest with its shell.

use crate::cleanup::{self, Item};
use crate::mm::aspace::{AddressSpace, SpaceRelease};
use crate::mm::pages::KernelPages;
use crate::mm::phys::FRAMES;
use crate::object::{self, Chunks, Handles, Object};
use crate::sched;
use crate::thread::{self, Siblings, Thread};
use abi::{Error, Handle, MAX_THREADS, ProcessState, Rights};
use core::ptr::NonNull;
use kcore::frames::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;
use kcore::paging::{Attrs, MapError};
use kcore::process::Life;
use kcore::quota::Account;
use kcore::slab::Pool;
use kcore::sync::Lock;

/// Blocks of frames one process may own.
const MAX_BLOCKS: usize = 8;

pub struct Process {
    /// From `create` until the first portion of the stage Space takes it:
    /// from then on no call reaches its tables (`map_page` fails,
    /// `translate` finds nothing).
    space: Option<AddressSpace>,
    /// The tables of the space on their way back, from that first portion
    /// until the root went: TTBR0 left them and their TLB entries went
    /// first, so the tables go before `frames` and the threads' message
    /// buffers, which the tables mapped.
    retired: Option<SpaceRelease>,
    frames: OwnedFrames,
    /// Released at the stage Handles: its handles hold references to
    /// other objects.
    handles: Handles,
    /// Handles to the process, its threads, the reference `create` hands
    /// out, and the cleanup queue's while the process is on its stages:
    /// the references that keep it alive.
    refs: u32,
    /// References that keep the object but not the process: each child's
    /// to its parent, until the child's shell goes, when the rest of the
    /// child's quota comes back (spec 7.5). A ring of a parent that holds a
    /// handle to its child and a child that holds its parent does not keep
    /// the parent alive.
    shell_refs: u32,
    /// Its memory quota: the limit its parent gave, what is charged to
    /// it, and what went back to the parent (spec 7.5).
    quota: Account,
    /// No thread of the process gets a base priority above it (spec 8).
    ceiling: u8,
    /// The threads it started and whether it ended, and why. A process
    /// lives exactly while it is whole (`stage`).
    life: Life,
    /// The threads that have not ended, linked through Thread::siblings:
    /// a thread joins at `create` and leaves at thread_exit, at the stage
    /// Buffers after the end stopped it, or when it goes. Shells of
    /// threads that ended are not in it.
    threads: Option<NonNull<Thread>>,
    /// Threads in `threads`, at most abi::MAX_THREADS.
    thread_count: u32,
    /// The process that made it (process_create, `create_child`), whose
    /// shell it holds until its own shell goes (`shell_refs`) and which its
    /// quota came from; None for init and the other processes `create`
    /// makes.
    parent: Option<NonNull<Process>>,
    /// Its children that have not passed their stage Quota, linked through
    /// `child_siblings`: a child joins when it is made (`adopt`) and leaves
    /// at that stage. A child in the list is alive as an object, since its
    /// shell goes only after the stage.
    children: Option<NonNull<Process>>,
    /// Its links in its parent's `children`; None outside the list.
    child_siblings: Option<ChildLinks>,
    /// Init's end ends the run (spec 7.9).
    init: bool,
    /// How far its teardown came.
    stage: Stage,
    /// Its place in the cleanup queue: on its stages, and as a shell once
    /// its last reference goes.
    cleanup: Item,
}

/// Neighbours in the list of a parent's children.
#[derive(Clone, Copy)]
struct ChildLinks {
    prev: Option<NonNull<Process>>,
    next: Option<NonNull<Process>>,
}

/// Where the teardown of a process stands (spec 7.7). A process is whole
/// until it ends; then the cleanup queue holds it, with a reference of its
/// own, and each portion takes one step of its stage, in the order of
/// STAGES, with how far it came kept in the process. Children, Handles and
/// Space take as many portions as their steps; the others one. After the
/// stage Quota the queue lets its reference go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No teardown began: the process lives.
    Whole,
    /// A child a portion: the first child in the list ends, killed, if it
    /// lives, and goes right in front of the process in the queue; the
    /// process waits behind it until the child leaves the list at its own
    /// stage Quota. Descendants go depth first, and the kernel stack does
    /// not grow with the depth of the tree (spec 4).
    Children,
    /// A chunk of the handle table a portion, up to 64 handles, each
    /// releasing its object; the chunk directory with the last chunk
    /// (HandleTable::release_step).
    Handles,
    /// The first portion takes the space: TTBR0 leaves its tables and
    /// their TLB entries go with the ASID (AddressSpace::retire). Then a
    /// table a portion (SpaceRelease::step).
    Space,
    /// The message buffers of the threads the end stopped, at most
    /// abi::MAX_THREADS, and the threads leave the list. After Space, so
    /// that no TLB entry maps a frame that goes.
    Buffers,
    /// The blocks of frames the process owned, at most MAX_BLOCKS.
    Frames,
    /// The free part of its quota goes back to the parent, and the
    /// process leaves its parent's list of children: by now its
    /// descendants passed their own stage Quota (spec 7.5).
    Quota,
    /// Nothing but the object and the reason are left: the last reference
    /// queues the shell, and its portion gives the slot back, the rest of
    /// the quota to the parent and then the reference to the parent's
    /// shell.
    Shell,
}

/// The stages of a teardown in the order they run (spec 7.7).
const STAGES: [Stage; 7] = [
    Stage::Children,
    Stage::Handles,
    Stage::Space,
    Stage::Buffers,
    Stage::Frames,
    Stage::Quota,
    Stage::Shell,
];

/// The stage after `stage`, which is one of STAGES but the last.
fn after(stage: Stage) -> Stage {
    let i = STAGES
        .iter()
        .position(|&s| s == stage)
        .expect("a stage of a teardown");
    STAGES[i + 1]
}

/// What the shell of a process costs its quota: its slot in the pool.
pub const SHELL_COST: u64 = Pool::<Process>::SLOT as u64;

/// Blocks of frames, as (physical address, order), that `release` gives
/// back to the allocator when their owner goes.
struct OwnedFrames([Option<(u64, u8)>; MAX_BLOCKS]);

impl OwnedFrames {
    /// Gives every block back to the frame allocator and refunds it to
    /// `quota`.
    fn release(&mut self, quota: &mut Account) {
        let mut guard = FRAMES.lock();
        let frames = guard.as_mut().expect("frame allocator");
        for (pa, order) in self.0.iter_mut().filter_map(Option::take) {
            frames.free(pa, order);
            quota.refund(PAGE_SIZE << order);
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
            space.destroy(&mut self.quota);
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
    /// (the linear map). The frames belong to the process until it goes,
    /// and its quota pays for them and for the tables. INVALID_ARGS for a
    /// range that is not whole pages or cannot be mapped, NO_MEMORY when
    /// the quota, frames or table memory run out or the process owns
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
        self.quota.charge(PAGE_SIZE << order)?;
        let Some(pa) = FRAMES
            .lock()
            .as_mut()
            .expect("frame allocator")
            .alloc(order)
        else {
            self.quota.refund(PAGE_SIZE << order);
            return Err(Error::NoMemory);
        };
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
        let space = self.space.as_mut().expect("frames map into a space");
        space
            .map(va, pa, size, attrs, &mut self.quota)
            .map_err(|e| match e {
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

/// A process with a quota of `quota` bytes, an empty address space, an
/// empty handle table for up to `handle_limit` handles and priority
/// ceiling `ceiling`, and no parent; the caller gets its first reference.
/// Its shell and root table are charged to its quota at once.
/// INVALID_ARGS for a limit outside 1-kcore::handles::MAX_HANDLES or a
/// ceiling outside 1-63, NO_MEMORY when the quota does not cover the shell
/// and the root table, or no frame is left for the table or the pool.
/// Only children (`create_child`), init (`create_init`) and the kernel
/// tests' processes (`create_root`) come from here.
fn create(quota: u64, handle_limit: u32, ceiling: u8) -> Result<NonNull<Process>, Error> {
    let ceiling = kcore::sched::priority_arg(u64::from(ceiling))?;
    kcore::process::handle_limit_arg(u64::from(handle_limit))?;
    let handles = Handles::new(handle_limit).map_err(Error::from)?;
    let mut quota = Account::new(quota);
    quota.charge(SHELL_COST)?;
    let space = AddressSpace::new(&mut quota).map_err(|_| Error::NoMemory)?;
    let process = Process {
        space: Some(space),
        retired: None,
        frames: OwnedFrames([None; MAX_BLOCKS]),
        handles,
        refs: 1,
        shell_refs: 0,
        quota,
        ceiling,
        life: Life::new(),
        threads: None,
        thread_count: 0,
        parent: None,
        children: None,
        child_siblings: None,
        init: false,
        stage: Stage::Whole,
        cleanup: Item::new(),
    };
    let allocated = PROCESSES.lock().alloc(&mut KernelPages, process);
    allocated.map_err(|mut process| {
        // No object for it: its space goes, with the pool's lock released.
        process.destroy_space();
        Error::NoMemory
    })
}

/// Init's process, as `create` makes one (spec 7.5, 13.3): outside the
/// kernel tests the only process with no parent, whose quota nobody paid.
/// Test builds have no init.
#[cfg(not(feature = "ktest"))]
pub fn create_init(quota: u64, handle_limit: u32, ceiling: u8) -> Result<NonNull<Process>, Error> {
    create(quota, handle_limit, ceiling)
}

/// A process with no parent for the kernel tests, as `create` makes one:
/// its quota comes from nowhere, and its count is checked all the same
/// when its shell goes (Account::return_rest).
#[cfg(feature = "ktest")]
pub fn create_root(quota: u64, handle_limit: u32, ceiling: u8) -> Result<NonNull<Process>, Error> {
    create(quota, handle_limit, ceiling)
}

/// A child of `parent`, which lives (spec 4, 7.5): `quota` comes off the
/// parent's quota first, NO_MEMORY when it does not fit there; then the
/// child is made with it as `create` makes a process, and joins its
/// parent (`adopt`). The quota goes back to the parent in two parts: at
/// once when the child is not made, and otherwise what is free at the
/// child's stage Quota and the rest when its shell goes.
pub fn create_child(
    parent: NonNull<Process>,
    quota: u64,
    handle_limit: u32,
    ceiling: u8,
) -> Result<NonNull<Process>, Error> {
    charge(parent, quota)?;
    let child = create(quota, handle_limit, ceiling).inspect_err(|_| refund(parent, quota))?;
    adopt(parent, child);
    Ok(child)
}

/// Charges `bytes` to the quota of `process`: NO_MEMORY when they do not
/// fit, or once the process passed its stage Quota (spec 7.5). Only the
/// field is borrowed (see `refs`).
pub fn charge(process: NonNull<Process>, bytes: u64) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process, or the process
    // is the parent of one it holds; only the field is borrowed.
    unsafe { (*process.as_ptr()).quota.charge(bytes) }
}

/// Gives back to the quota of `process` bytes a charge took, as `charge`.
pub fn refund(process: NonNull<Process>, bytes: u64) {
    // SAFETY: as in `charge`.
    unsafe { (*process.as_ptr()).quota.refund(bytes) }
}

/// The quota of `process`, which the caller holds: object_info's
/// PROCESS_MEMORY.
pub fn quota(process: NonNull<Process>) -> Account {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    unsafe { (*process.as_ptr()).quota }
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
/// `cause`, the level of the cleanup this release starts (spec 7.7): a
/// process that lives ends, killed, and its teardown begins; a shell goes
/// once no child holds it either (`release_shell`). No other process can
/// lose its last reference: the queue holds one to a process on its
/// stages.
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
    if !last {
        return;
    }
    // SAFETY: that was the last reference: nothing else reaches the
    // process, and the pool keeps it in place; only the fields are touched.
    unsafe {
        match (*process.as_ptr()).stage {
            // No thread holds it, so none is left to stop.
            Stage::Whole => {
                let ended = (*life(process)).end(ProcessState::Killed);
                assert!(ended, "a whole process that ended");
                begin(process, cause);
            }
            Stage::Shell => queue_shell(process, cause),
            _ => unreachable!("the cleanup queue holds a process on its stages"),
        }
    }
}

/// Drops a child's reference to its parent's shell, at the child's shell
/// portion (`free`); the last reference of either kind queues the shell
/// at `cause`.
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
unsafe fn release_shell(process: NonNull<Process>, cause: u8) {
    // SAFETY: the caller's reference keeps the object alive until here;
    // only the fields are touched, the count through `refs`.
    unsafe {
        let refs = *refs(process);
        let p = process.as_ptr();
        (*p).shell_refs = (*p)
            .shell_refs
            .checked_sub(1)
            .expect("a shell is released once too often");
        if (*p).shell_refs == 0 && refs == 0 && (*p).stage == Stage::Shell {
            queue_shell(process, cause);
        }
    }
}

/// Queues the shell of a process for its last portion unless a child
/// still holds it.
///
/// # Safety
/// No reference that keeps the process alive is left, and its stages are
/// over.
unsafe fn queue_shell(process: NonNull<Process>, cause: u8) {
    // SAFETY: the caller's promise: nothing but children reach the shell,
    // and the pool keeps it in place.
    unsafe {
        if (*process.as_ptr()).shell_refs == 0 {
            let item = NonNull::new_unchecked(&raw mut (*process.as_ptr()).cleanup);
            cleanup::enqueue(item, Object::Process(process), cause);
        }
    }
}

/// The teardown of a process that just ended begins: the cleanup queue
/// takes a reference of its own and queues the process at `level` for its
/// first stage.
///
/// # Safety
/// `process` is alive, whole, and in no queue.
unsafe fn begin(process: NonNull<Process>, level: u8) {
    // SAFETY: the caller's promise; only the fields are touched.
    unsafe {
        let p = process.as_ptr();
        assert!(
            (*p).stage == Stage::Whole,
            "the teardown of a process begins twice"
        );
        (*p).stage = STAGES[0];
        // The queue's own reference. `retain` refuses a count of 0, which
        // it is when the last reference ended the process (`release`).
        let refs = refs(process);
        *refs = refs.checked_add(1).expect("process references overflow");
        let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
        cleanup::enqueue(item, Object::Process(process), level);
    }
}

/// One portion of a process in the cleanup queue (cleanup::portion): one
/// step of its stage (`Stage`); what the step releases is queued at
/// `level`. With work left the process goes back to the head of `level`,
/// so the next portion there goes on with it, and at the stage Children
/// its first child goes in front of it; after the stage Quota the queue
/// lets its reference go, which queues the shell when it was the last. A
/// shell's portion gives the slot back.
///
/// # Safety
/// The process was just taken from the queue: it is on its stages, with
/// the queue's reference, or a shell nobody refers to.
pub unsafe fn clean(process: NonNull<Process>, level: u8) {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; only the field is read.
    let stage = unsafe { (*p).stage };
    // The child that goes in front of the process at the stage Children.
    let mut first = None;
    let done = match stage {
        Stage::Whole => unreachable!("a whole process in the cleanup queue"),
        Stage::Children => {
            // SAFETY: the process is alive; only the field is read.
            first = unsafe { (*p).children };
            first.is_none()
        }
        // SAFETY: the process is alive, and the step borrows only the
        // field it works on.
        Stage::Handles => unsafe { release_handles(process, level) },
        // SAFETY: as above.
        Stage::Space => unsafe { release_space(p) },
        // SAFETY: as above.
        Stage::Buffers => unsafe { release_buffers(process) },
        // SAFETY: as above; the stage Space is over, so no TLB entry
        // maps the frames.
        Stage::Frames => unsafe {
            (*p).frames.release(&mut (*p).quota);
            true
        },
        // SAFETY: as above.
        Stage::Quota => unsafe { leave_parent(process) },
        Stage::Shell => {
            // SAFETY: nothing refers to the shell.
            unsafe { free(process, level) };
            return;
        }
    };
    let next = if done { after(stage) } else { stage };
    // SAFETY: the process is alive; the queue's reference goes last, and
    // nothing uses the process afterwards; the child is alive while it is
    // in the list.
    unsafe {
        (*p).stage = next;
        if next == Stage::Shell {
            release(process, level);
        } else {
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::requeue(item, Object::Process(process), level);
        }
        if let Some(child) = first {
            end_child(child, level);
        }
    }
}

/// The stage Children, after the parent went back to the head of `level`:
/// the parent's first child ends, killed, if it lives, which stops its
/// threads and queues it (`end`), and goes to the head of `level` unless
/// it stands higher, right in front of the parent.
///
/// # Safety
/// `child` is in its parent's list, so it is alive; the parent is queued.
unsafe fn end_child(child: NonNull<Process>, level: u8) {
    // SAFETY: the caller's promise; only the fields are touched.
    unsafe {
        if (*child.as_ptr()).stage == Stage::Whole {
            end(child, ProcessState::Killed, level);
        }
        let item = NonNull::new_unchecked(&raw mut (*child.as_ptr()).cleanup);
        cleanup::raise(item, level);
    }
}

/// The stage Handles: one step of the table's release, each handle's
/// object released at `level`. True once the table holds nothing.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn release_handles(process: NonNull<Process>, level: u8) -> bool {
    // SAFETY: only the table and the quota its chunks go back to are
    // borrowed: releasing its objects reaches no other field but `refs`,
    // through raw pointers, since a release only counts and queues.
    let (handles, quota) = unsafe {
        let p = process.as_ptr();
        (&mut (*p).handles, &mut (*p).quota)
    };
    handles.release_step(&mut Chunks(quota), |object| {
        // SAFETY: the table let the handle go, and its reference with it.
        unsafe { object::release(object, level) }
    })
}

/// The stage Space: the first portion takes the space and retires it,
/// each later one gives a table back. True once the root went.
///
/// # Safety
/// `p` is alive and on its stages.
unsafe fn release_space(p: *mut Process) -> bool {
    // SAFETY: the caller's promise; only the fields are borrowed.
    let (space, retired, quota) = unsafe { (&mut (*p).space, &mut (*p).retired, &mut (*p).quota) };
    let Some(release) = retired.as_mut() else {
        let space = space.take().expect("a space at the stage Space");
        *retired = Some(space.retire());
        return false;
    };
    let spent = release.step(quota);
    if spent {
        *retired = None;
    }
    spent
}

/// The stage Buffers: the message buffers of the threads the end stopped
/// go, and the threads leave the list. The ASID went at the stage Space,
/// so the frames go back without unmapping. One portion: true.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn release_buffers(process: NonNull<Process>) -> bool {
    // SAFETY: the caller's promise; the threads of the list are alive,
    // since each is either held or queued for cleanup behind this portion.
    unsafe {
        while let Some(t) = (*process.as_ptr()).threads {
            thread::drop_buffer(t);
            remove_thread(process, t);
        }
    }
    true
}

/// The stage Quota: the free part of the quota goes back to the parent
/// (Account::return_free), and nothing is charged to the process from
/// then on; then the process leaves its parent's list of children. The
/// quota of a process with no parent goes nowhere. True: one portion.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn leave_parent(process: NonNull<Process>) -> bool {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; the parent's object is there, since the
    // process holds its shell, and so are the neighbours in its list.
    unsafe {
        #[cfg(feature = "ktest")]
        if (*p).children.is_some() {
            EARLY_QUOTA.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        let free = (*p).quota.return_free();
        let Some(parent) = (*p).parent else {
            return true;
        };
        refund(parent, free);
        let ChildLinks { prev, next } = (*p)
            .child_siblings
            .take()
            .expect("a child in its parent's list until its stage Quota");
        match prev {
            Some(q) => child_links(q).next = next,
            None => (*parent.as_ptr()).children = next,
        }
        if let Some(n) = next {
            child_links(n).prev = prev;
        }
    }
    true
}

/// The links of `child`, a process in its parent's list.
///
/// # Safety
/// `child` is alive and in the list; nothing else borrows its links.
unsafe fn child_links<'a>(child: NonNull<Process>) -> &'a mut ChildLinks {
    // SAFETY: the caller's promise.
    unsafe { (*child.as_ptr()).child_siblings.as_mut() }.expect("a child in the list")
}

/// Makes `child`, a process `create` just made with a quota the parent
/// paid, a child of `parent`, which lives (spec 4): the child holds a
/// reference to its parent's shell until its own shell goes, and stands at
/// the head of its parent's list of children until its stage Quota.
/// `create_child` comes here; init and the kernel tests' processes
/// (`create_init`, `create_root`) have no parent.
fn adopt(parent: NonNull<Process>, child: NonNull<Process>) {
    // SAFETY: the caller holds references to both; only the fields of the
    // tree are touched.
    unsafe {
        let (p, c) = (parent.as_ptr(), child.as_ptr());
        assert!(
            (*p).stage == Stage::Whole && (*c).parent.is_none(),
            "a child of a process that ended, or with a parent already"
        );
        (*p).shell_refs = (*p).shell_refs.checked_add(1).expect("children overflow");
        (*c).parent = Some(parent);
        let old = (*p).children;
        (*c).child_siblings = Some(ChildLinks {
            prev: None,
            next: old,
        });
        if let Some(o) = old {
            child_links(o).prev = Some(child);
        }
        (*p).children = Some(child);
    }
}

/// A shell's portion: the slot goes back to the pool, the rest of the
/// quota to the parent (Account::return_rest: nothing else is charged by
/// now, since whatever held the shell went), and then the reference to
/// the parent's shell, which queues that shell at `level` if it was the
/// last.
///
/// # Safety
/// Nothing refers to the shell, and it is in no queue.
unsafe fn free(process: NonNull<Process>, level: u8) {
    // SAFETY: the caller's promise; only the fields are touched.
    let (parent, rest) = unsafe {
        let p = process.as_ptr();
        (*p).quota.refund(SHELL_COST);
        ((*p).parent, (*p).quota.return_rest())
    };
    // SAFETY: the caller's promise; every stage gave its memory back.
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
    if let Some(parent) = parent {
        refund(parent, rest);
        // SAFETY: the shell's reference to its parent goes with it.
        unsafe { release_shell(parent, level) };
    }
}

/// What test builds fill a gone process with, past the pool's link.
#[cfg(feature = "ktest")]
const POISON: u8 = 0xA5;

// The poison reaches `refs`, which `refs` checks.
#[cfg(feature = "ktest")]
const _: () = assert!(core::mem::offset_of!(Process, refs) >= 8);

/// Ends `process` with `reason` unless it ended before, when the first
/// reason stays: process_exit, process_kill and a fault at EL0 come here.
/// In the call itself every thread of the process leaves the scheduler for
/// good, and the process is queued for its teardown at `cause`, the
/// effective priority of the thread that made the call or the fault; what
/// the teardown releases is queued at that level too. The running thread
/// may be one of the process's: it never runs again and may be gone
/// afterwards, so the caller leaves through sched::resume. When the
/// process is init, the run ends (`init_ended`).
///
/// # Safety
/// The caller holds a reference to `process`.
pub unsafe fn end(process: NonNull<Process>, reason: ProcessState, cause: u8) {
    // SAFETY: the caller's reference keeps the process alive.
    if unsafe { (*life(process)).end(reason) } {
        // SAFETY: as above; the end was just recorded.
        unsafe { stop(process, cause) };
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
        unsafe { stop(process, cause) };
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

/// The part of an end that runs in the call, once its reason was just
/// recorded: each thread of the list, at most abi::MAX_THREADS, leaves the
/// scheduler and loses the kernel's reference, which may queue it for
/// cleanup at `cause`, though it stays alive and in the list until its
/// portion or the stage Buffers; then the teardown begins at `cause`
/// (spec 7.7). From milestone 1.3b the exit channel hears of the end once
/// the stages gave back what they can.
///
/// # Safety
/// As for `end`.
unsafe fn stop(process: NonNull<Process>, cause: u8) {
    let p = process.as_ptr();
    // SAFETY: the caller's reference keeps the process alive, and a
    // release only queues, so every thread of the list stays alive here.
    unsafe {
        let mut next = (*p).threads;
        while let Some(t) = next {
            next = (*t.as_ptr()).siblings.and_then(|s| s.next);
            sched::exit(t, cause);
        }
        begin(process, cause);
    }
    // SAFETY: as above.
    let (init, state) = unsafe { ((*p).init, (*life(process)).state()) };
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

/// LIMIT_REACHED when `process` has abi::MAX_THREADS threads that have
/// not ended (spec 8): thread::create asks before it takes a slot.
pub fn thread_room(process: NonNull<Process>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    if unsafe { (*process.as_ptr()).thread_count } < MAX_THREADS {
        Ok(())
    } else {
        Err(Error::LimitReached)
    }
}

/// Puts `t`, a new thread of `process`, at the head of its threads, after
/// `thread_room` let it.
pub fn add_thread(process: NonNull<Process>, t: NonNull<Thread>) {
    // SAFETY: the process and its threads are alive, and a thread holds a
    // reference to its process; only the list's fields are touched.
    unsafe {
        let p = process.as_ptr();
        (*p).thread_count += 1;
        let old = (*p).threads;
        (*t.as_ptr()).siblings = Some(Siblings {
            prev: None,
            next: old,
        });
        if let Some(o) = old {
            sibling(o).prev = Some(t);
        }
        (*p).threads = Some(t);
    }
}

/// Takes `t` out of its process's threads, if it is there: when it exits,
/// at the stage Buffers, or when it goes.
///
/// # Safety
/// `t` is a live thread of `process`.
pub unsafe fn remove_thread(process: NonNull<Process>, t: NonNull<Thread>) {
    // SAFETY: the caller's promise; only the list's fields are touched.
    unsafe {
        let Some(Siblings { prev, next }) = (*t.as_ptr()).siblings.take() else {
            return;
        };
        let p = process.as_ptr();
        (*p).thread_count -= 1;
        match prev {
            Some(q) => sibling(q).next = next,
            None => (*p).threads = next,
        }
        if let Some(n) = next {
            sibling(n).prev = prev;
        }
    }
}

/// The links of `t`, a thread in its process's list.
///
/// # Safety
/// `t` is alive and in the list; nothing else borrows its links.
unsafe fn sibling<'a>(t: NonNull<Thread>) -> &'a mut Siblings {
    // SAFETY: the caller's promise.
    unsafe { (*t.as_ptr()).siblings.as_mut() }.expect("a thread in the list")
}

/// Maps the frame at `pa` at page `va` of the process with `attrs`; the
/// tables it takes are charged to the process. INVALID_ARGS for a page
/// that is mapped already or outside the lower half, NO_MEMORY when the
/// quota or the frames run out for a table, BAD_STATE once the stage
/// Space took the space.
pub fn map_page(process: NonNull<Process>, va: usize, pa: u64, attrs: Attrs) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process; only the fields
    // are borrowed (see `refs`).
    let (space, quota) = unsafe {
        let p = process.as_ptr();
        (&mut (*p).space, &mut (*p).quota)
    };
    let space = space.as_mut().ok_or(Error::BadState)?;
    space
        .map(va, pa, PAGE_SIZE, attrs, quota)
        .map_err(|e| match e {
            MapError::NoMemory => Error::NoMemory,
            _ => Error::InvalidArgs,
        })
}

/// Unmaps page `va` of the process and drops its TLB entry; returns the
/// frame it mapped, or None when nothing maps it or the stage Space took
/// the space: its ASID went then, and with it every TLB entry.
pub fn unmap_page(process: NonNull<Process>, va: usize) -> Option<u64> {
    // SAFETY: as in `map_page`.
    let space = unsafe { &mut (*process.as_ptr()).space };
    space.as_mut()?.unmap(va).ok()
}

/// What page `va` of the process translates to: the frame and the leaf
/// descriptor; None when nothing maps it or the stage Space took the
/// space.
pub fn translate(process: NonNull<Process>, va: usize) -> Option<(u64, u64)> {
    // SAFETY: as in `map_page`.
    let space = unsafe { &(*process.as_ptr()).space };
    space.as_ref()?.translate(va)
}

/// Puts `object` in the handle table of `process` with `rights`; the new
/// handle holds a reference to it. A new chunk or directory of the table
/// is charged to `process`, whoever the handle comes from. LIMIT_REACHED
/// at the table's limit, NO_MEMORY when the quota or the pool runs out for
/// a chunk. The process lives: the table of one that ended stays empty.
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
    let p = unsafe { process.as_mut() };
    let h = p
        .handles
        .insert(&mut Chunks(&mut p.quota), object, rights)
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

/// Entry 0 of the fresh table of a child that process_create made
/// (spec 13.3): with no start channel, a stub goes in and out at once, so
/// abi::START_CHANNEL stays bad there for good, even for a channel the
/// child makes itself. The directory and the first chunk of the table are
/// charged to the child: NO_MEMORY when its quota or the pool runs out.
pub fn reserve_start(child: NonNull<Process>) -> Result<(), Error> {
    let stub = insert_handle(child, Object::Resource, Rights::NONE)?;
    assert_eq!(
        stub,
        abi::START_CHANNEL,
        "the start entry went into a table that was not fresh"
    );
    // The system resource is never queued: any level will do.
    close_handle(child, stub, 1)
}

/// The handles of `process`, which the caller holds, for object_info's
/// PROCESS_HANDLES: live, retired at their last generation, and the limit.
/// A process whose stage Handles is over has an empty table.
pub fn handle_counts(process: NonNull<Process>) -> (u32, u32, u32) {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    let handles = unsafe { &(*process.as_ptr()).handles };
    (handles.len(), handles.retired(), handles.limit())
}

/// Objects the process pool holds now.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    PROCESSES.lock().in_use()
}

/// Processes that came to their stage Quota with children still in their
/// list: none may, since the stage Children waits for each (test builds).
#[cfg(feature = "ktest")]
static EARLY_QUOTA: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// How many processes came to their stage Quota before their children
/// passed theirs, since the last call.
#[cfg(feature = "ktest")]
pub fn take_early_quota() -> u32 {
    EARLY_QUOTA.swap(0, core::sync::atomic::Ordering::Relaxed)
}

/// The parent of `process`, which the test holds.
#[cfg(feature = "ktest")]
pub fn parent(process: NonNull<Process>) -> Option<NonNull<Process>> {
    // SAFETY: the test holds a reference to the process; only the field is
    // read.
    unsafe { (*process.as_ptr()).parent }
}

/// How far the teardown of `process` came: its stage, the handles left in
/// its table, and the tables of its space that went back.
#[cfg(feature = "ktest")]
pub fn progress(process: NonNull<Process>) -> (Stage, u32, usize) {
    // SAFETY: the test holds a reference to the process, and nothing
    // runs its portions meanwhile.
    let p = unsafe { process.as_ref() };
    let tables = p.retired.as_ref().map_or(0, |r| r.freed());
    (p.stage, p.handles.len(), tables)
}
