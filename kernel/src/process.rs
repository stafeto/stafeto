// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Processes (spec 4, 8): an address space, the frames the process owns
//! there, its handle table, its priority ceiling, its threads that have
//! not ended, its parent and children, and how it lives, in an object in
//! its parent's pool of shells. A process lives while references to it
//! are left: handles to it, its threads, and the one `create` hands out;
//! its children hold only its shell. It ends (`end`) through
//! process_exit, process_kill, a fault at EL0 or the exit of its last
//! started thread, when its last reference goes while it lives, and when
//! its parent ends. The end itself only stops its threads, at most
//! abi::MAX_THREADS, and queues the process for cleanup; the queue
//! takes it apart in stages, a portion at a time, with how far it came
//! kept in the process (`Stage`, spec 7.7): first a wave that stops its
//! descendants above the cause, at its priority ceiling, then the
//! teardown at the level of the cause, its descendants first. Once it gave
//! its quota back, its exit channel hears of the end (spec 7.9), through a
//! slot in its shell. A shell with the reason stays for object_info until
//! the last reference queues it once more. Every release names the level of its cause, which the
//! cleanup it may start takes. A process pays from its quota for what goes
//! with it (spec 7.5, 7.8): a page at a time as its pools grow, for its
//! threads, the blocks of its handle table, the shells of its children, the
//! channels it made, the sessions of the labels it gave (spec 5.3) and its
//! timers, at most abi::MAX_TIMERS (spec 10); and
//! for the tables of its space, the message buffers of its threads and the
//! frames of `map_frames`. The pages of its pools go back only with
//! its shell, in portions. A child's quota comes off its parent's and goes
//! back in two parts: what is free at the child's stage Quota, and the
//! rest with its shell.

use crate::channel::{self, Channel, Owner};
use crate::cleanup::{self, Item};
use crate::mm::aspace::{AddressSpace, SpaceRelease};
use crate::mm::pages::{self, KernelPages};
use crate::mm::phys::FRAMES;
use crate::object::{self, Block, Chunks, Handles, Object};
use crate::sched;
use crate::session::Session;
use crate::thread::{self, Siblings, Thread};
use crate::timer::Timer;
use abi::{Error, Handle, MAX_THREADS, MAX_TIMERS, ProcessState, Rights};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::layout::LINEAR_BASE;
use kcore::notify::Slot;
use kcore::paging::Attrs;
use kcore::process::Life;
use kcore::quota::Account;
use kcore::slab::{PageLog, PaidPages, Pool};
use kcore::sync::Lock;

/// Blocks of frames one process may own.
const MAX_BLOCKS: usize = 8;

/// Pages a portion of the stage Shell gives back, at most (spec 7.7).
const SHELL_PORTION: usize = 64;

/// The bits of an exit notification (spec 6.5, 7.9): bit 0, once.
const EXIT_BITS: u64 = 1;

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
    /// child's quota comes back (spec 7.5), and each channel's and each
    /// session's and each timer's the process pays for, until its place
    /// goes back to the pool (spec 7.8).
    /// A ring of a parent that holds a handle to its child and a child that
    /// holds its parent does not keep the parent alive.
    shell_refs: u32,
    /// Its memory quota: the limit its parent gave, what is charged to
    /// it, and what went back to the parent (spec 7.5).
    quota: Account,
    /// The pages of `pools` and the list pages that name them, each
    /// charged to `quota`: they go back at the stage Shell (spec 7.8).
    pages: PageLog,
    /// What the process pays for by the page.
    pools: Pools,
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
    /// Timers in its pool of timers, at most abi::MAX_TIMERS (spec 10).
    timer_count: u32,
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
    /// R, the level of its teardown once it ended (spec 7.7): the highest
    /// of the priority of its exit notification (`set_exit`), the cause of
    /// its end and those of the calls that hastened it (`hasten`). It only
    /// grows.
    level: u8,
    /// Where its end goes as a notification (process_create x3, spec 7.9):
    /// set once, before anything can end the process.
    exit: Option<Exit>,
    /// At the stage Stop, the child it stops next; a child that leaves
    /// the list moves it on (`leave_parent`).
    stop_next: Option<NonNull<Process>>,
    /// How far its teardown came.
    stage: Stage,
    /// Its place in the cleanup queue: on its stages, and as a shell once
    /// its last reference goes.
    cleanup: Item,
}

/// The pools of what a process pays for by the page (spec 7.5, 7.8): a
/// page is charged when a pool grows, a slot that goes back refunds
/// nothing, and the pages go back only with the process's shell. Every
/// object in them holds a reference to the process or to its shell, so by
/// then they hold nothing.
struct Pools {
    /// Its threads, whoever made them.
    threads: Pool<Thread>,
    /// The chunks and the directory of its handle table.
    blocks: Pool<Block>,
    /// The shells of its children.
    children: Pool<Process>,
    /// The channels it made.
    channels: Pool<Channel>,
    /// The sessions of the labels it gave (handle_duplicate).
    sessions: Pool<Session>,
    /// The timers it made.
    timers: Pool<Timer>,
}

/// The source of a process's exit notification (spec 6.5, 7.9): its slot,
/// which lies in the shell and holds the shell while it stands in the
/// channel's queue, the label of the handle process_create took as x3,
/// and the channel, which the shell holds, with one of its slots, until
/// the shell goes.
struct Exit {
    slot: Slot<Owner>,
    label: u64,
    channel: NonNull<Channel>,
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
/// STAGES, with how far it came kept in the process. Stop, Children,
/// Handles, Space and Shell take as many portions as their steps; the
/// others one. The stage Stop runs at S, the higher of the process's
/// ceiling and R (`level`); the others at R, but for Shell, which runs at
/// the level of the last reference. After the stage Notify the queue lets
/// its reference go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No teardown began: the process lives.
    Whole,
    /// Only for a process with children when it ends: a child a portion,
    /// the one at the cursor `stop_next`, ends, killed, at R, if it lives,
    /// which stops its threads and begins its own teardown (`end`). At S
    /// no thread of a descendant runs meanwhile: none has an effective
    /// priority above its process's ceiling, and no ceiling of a
    /// descendant is above this one's (spec 4, 8).
    Stop,
    /// A child a portion: the first child in the list, which the stage
    /// Stop ended, goes right in front of the process in the queue
    /// (`hasten`); the process waits behind it until the child leaves the
    /// list at its own stage Quota. Descendants go depth first, and the
    /// kernel stack does not grow with the depth of the tree (spec 4).
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
    /// The exit channel, if there is one and it is open, hears of the end
    /// (spec 7.9): bit 0 into the slot in the shell, which goes to a
    /// receiver that waits or into the channel's queue, where it holds the
    /// shell. After Quota: the parent hears of the end once the process and
    /// its descendants gave back what they could. One portion.
    Notify,
    /// Nothing but the object and the reason are left: the last reference
    /// queues the shell. Each portion gives up to SHELL_PORTION pages of
    /// its pools back to the frame allocator; the last one gives the slot
    /// back to its parent's pool, the rest of the quota to the parent, and
    /// then the references to the exit channel and to the parent's shell.
    Shell,
}

/// The stages of a teardown in the order they run (spec 7.7).
const STAGES: [Stage; 9] = [
    Stage::Stop,
    Stage::Children,
    Stage::Handles,
    Stage::Space,
    Stage::Buffers,
    Stage::Frames,
    Stage::Quota,
    Stage::Notify,
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
// rules (spec 8.1): one CPU, interrupts masked inside the kernel, ROOTS
// behind a lock.
unsafe impl Send for Process {}

/// The shells of processes with no parent: at boot the reserve, a page
/// for init's shell taken before init's quota is counted (spec 7.5);
/// in test builds the kernel tests' processes. Its pages stay.
static ROOTS: Lock<Pool<Process>> = Lock::new(Pool::new());

/// Processes whose shells have not gone (test builds).
#[cfg(feature = "ktest")]
static LIVE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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
            // A block may miss while its frames are free apart; a single
            // frame may not (spec 7.8).
            assert!(order > 0, "a charge that passed found no frame (spec 7.8)");
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
        space.map(va, pa, size, attrs, &mut self.quota)?;
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
        self.handles.get_as(h, rights, kind)
    }

    /// As `lookup`, with every right of the handle as well: what a handle
    /// that moves takes along (process_create x5).
    pub fn lookup_with_rights<U>(
        &self,
        h: Handle,
        rights: Rights,
        kind: impl FnOnce(&Object) -> Option<U>,
    ) -> Result<(U, Rights), Error> {
        let found = self.lookup(h, rights, kind)?;
        let (_, all) = self.handles.get(h)?;
        Ok((found, all))
    }
}

/// A process with a quota of `quota` bytes, an empty address space, an
/// empty handle table for up to `handle_limit` handles and priority
/// ceiling `ceiling`, and no parent yet; the caller gets its first
/// reference. Its root table is charged to its quota at once. Its shell
/// takes a slot in the pool of `payer`, whose quota pays for a page when
/// the pool grows (spec 7.5), or with no payer in ROOTS. INVALID_ARGS for
/// a limit outside 1-kcore::handles::MAX_HANDLES or a ceiling outside
/// 1-63, NO_MEMORY when the quota does not cover the root table or the
/// payer's does not cover a new page of its pool. Only children
/// (`create_child`), init (`create_init`) and the kernel tests' processes
/// (`create_root`) come from here.
fn create(
    quota: u64,
    handle_limit: u32,
    ceiling: u8,
    payer: Option<NonNull<Process>>,
) -> Result<NonNull<Process>, Error> {
    let ceiling = kcore::sched::priority_arg(u64::from(ceiling))?;
    kcore::process::handle_limit_arg(u64::from(handle_limit))?;
    let handles = Handles::new(handle_limit)?;
    let mut quota = Account::new(quota);
    let space = AddressSpace::new(&mut quota).map_err(|_| Error::NoMemory)?;
    let process = Process {
        space: Some(space),
        retired: None,
        frames: OwnedFrames([None; MAX_BLOCKS]),
        handles,
        refs: 1,
        shell_refs: 0,
        quota,
        pages: PageLog::new(),
        pools: Pools {
            threads: Pool::new(),
            blocks: Pool::new(),
            children: Pool::new(),
            channels: Pool::new(),
            sessions: Pool::new(),
            timers: Pool::new(),
        },
        ceiling,
        life: Life::new(),
        threads: None,
        thread_count: 0,
        timer_count: 0,
        parent: None,
        children: None,
        child_siblings: None,
        init: false,
        level: 0,
        exit: None,
        stop_next: None,
        stage: Stage::Whole,
        cleanup: Item::new(),
    };
    let allocated = match payer {
        // SAFETY: the caller holds a reference to the payer; the new
        // process is no field of it.
        Some(payer) => unsafe { paid_slot(payer, |pools| &mut pools.children, process) },
        None => ROOTS.lock().alloc(&mut KernelPages, process),
    };
    let process = allocated.map_err(|mut process| {
        // No object for it: its space goes, with the pool's lock released.
        process.destroy_space();
        Error::NoMemory
    })?;
    #[cfg(feature = "ktest")]
    LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(process)
}

/// Puts `value` in a slot of the pool `pool` picks among those of `payer`,
/// whose quota pays for a page when the pool grows (spec 7.8); gives the
/// value back when the quota falls short.
///
/// # Safety
/// `payer` is alive, and nothing else borrows its pools, its quota or its
/// page log meanwhile.
unsafe fn paid_slot<T>(
    payer: NonNull<Process>,
    pool: impl FnOnce(&mut Pools) -> &mut Pool<T>,
    value: T,
) -> Result<NonNull<T>, T> {
    let p = payer.as_ptr();
    // SAFETY: the caller's promise; only these fields are borrowed.
    let (pools, quota, log) = unsafe { (&mut (*p).pools, &mut (*p).quota, &mut (*p).pages) };
    pool(pools).alloc(&mut PaidPages::new(KernelPages, quota, log), value)
}

/// Init's process, as `create` makes one (spec 7.5, 13.3): outside the
/// kernel tests the only process with no parent. Its shell takes the
/// reserve, a page of ROOTS taken before its quota is counted; the quota
/// is every frame free then, so each frame taken from then on is charged
/// to init or to a process below it. Test builds have no init.
#[cfg(not(feature = "ktest"))]
pub fn create_init(handle_limit: u32, ceiling: u8) -> Result<NonNull<Process>, Error> {
    if !ROOTS.lock().reserve(&mut KernelPages) {
        return Err(Error::NoMemory);
    }
    let quota = crate::mm::phys::free_frames() * PAGE_SIZE;
    create(quota, handle_limit, ceiling, None)
}

/// A process with no parent for the kernel tests, as `create` makes one:
/// its shell comes from ROOTS and its quota from nowhere, and its count is
/// checked all the same when its shell goes (Account::return_rest).
#[cfg(feature = "ktest")]
pub fn create_root(quota: u64, handle_limit: u32, ceiling: u8) -> Result<NonNull<Process>, Error> {
    create(quota, handle_limit, ceiling, None)
}

/// A child of `parent`, which lives (spec 4, 7.5): `quota` comes off the
/// parent's quota first, NO_MEMORY when it does not fit there; then the
/// child is made with it as `create` makes a process, its shell in the
/// parent's pool, and joins its parent (`adopt`). The quota goes back to
/// the parent in two parts: at once when the child is not made, and
/// otherwise what is free at the child's stage Quota and the rest when
/// its shell goes. The page of the pool stays the parent's.
pub fn create_child(
    parent: NonNull<Process>,
    quota: u64,
    handle_limit: u32,
    ceiling: u8,
) -> Result<NonNull<Process>, Error> {
    charge(parent, quota)?;
    let child = create(quota, handle_limit, ceiling, Some(parent))
        .inspect_err(|_| refund(parent, quota))?;
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
/// of `release_step` meanwhile (`release_handles`). Test builds stop a
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

/// Adds a reference to the shell of `process`: an object in its pools
/// that it pays for holds one (spec 7.8), so its pages stay until the
/// object's slot went back, and so does its exit slot while it stands in
/// the queue of the exit channel (spec 6.5).
pub fn retain_shell(process: NonNull<Process>) {
    // SAFETY: the caller holds a reference to the process; only the field
    // is touched, and `refs` checks the object.
    unsafe {
        refs(process);
        let p = process.as_ptr();
        (*p).shell_refs = (*p)
            .shell_refs
            .checked_add(1)
            .expect("shell references overflow");
    }
}

/// Drops a reference to the shell of `process`: a child's to its parent at
/// the child's shell portion (`free`), an object's to its payer once its
/// slot went back, or the exit slot's once receive or the stage Close took
/// it; the last reference of either kind queues the shell at `cause`.
///
/// # Safety
/// The reference is the caller's, and the caller does not use it afterwards.
pub unsafe fn release_shell(process: NonNull<Process>, cause: u8) {
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

/// The teardown of a process that just ended begins at `cause` (spec
/// 7.7): R grows to it, and the cleanup queue takes a reference of its
/// own and queues the process for its first stage: Stop at S for a
/// process with children, Children at R otherwise.
///
/// # Safety
/// `process` is alive, whole, and in no queue.
unsafe fn begin(process: NonNull<Process>, cause: u8) {
    // SAFETY: the caller's promise; only the fields are touched.
    unsafe {
        let p = process.as_ptr();
        assert!(
            (*p).stage == Stage::Whole,
            "the teardown of a process begins twice"
        );
        (*p).level = (*p).level.max(cause);
        (*p).stop_next = (*p).children;
        (*p).stage = if (*p).children.is_some() {
            Stage::Stop
        } else {
            Stage::Children
        };
        // The queue's own reference. `retain` refuses a count of 0, which
        // it is when the last reference ended the process (`release`).
        let refs = refs(process);
        *refs = refs.checked_add(1).expect("process references overflow");
        let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
        cleanup::enqueue(item, Object::Process(process), stage_level(p));
    }
}

/// The level the stage of `p` runs at: S, the higher of its ceiling and
/// R, at the stage Stop, R at the others (spec 7.7).
///
/// # Safety
/// `p` is alive; only the fields are read.
unsafe fn stage_level(p: *const Process) -> u8 {
    // SAFETY: the caller's promise.
    unsafe {
        match (*p).stage {
            Stage::Stop => (*p).ceiling.max((*p).level),
            _ => (*p).level,
        }
    }
}

/// Hastens the teardown of `process`, which ended (spec 7.7, 11): R grows
/// to `level`, and the process goes to the head of the level of its stage
/// (`stage_level`), however high it stood in the queue, so that it runs
/// before anything that waits for it there. A shell has no stage left to
/// hasten. process_kill of a process that ended comes here with the
/// caller's priority, and so does the stage Children for each child. O(1).
///
/// # Safety
/// `process` ended; the caller holds a reference to it, or it is in its
/// parent's list, and none of its portions runs now.
pub unsafe fn hasten(process: NonNull<Process>, level: u8) {
    // SAFETY: the caller's promise; a process on its stages is queued
    // outside its own portions, since the queue holds it.
    unsafe {
        let p = process.as_ptr();
        refs(process);
        (*p).level = (*p).level.max(level);
        match (*p).stage {
            Stage::Whole => unreachable!("a process that lives is hastened"),
            Stage::Shell => {}
            _ => {
                let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
                cleanup::raise(item, stage_level(p));
            }
        }
    }
}

/// One portion of a process in the cleanup queue (cleanup::portion), taken
/// at `level`: one step of its stage (`Stage`); what the step releases is
/// queued at R, whatever level the stage runs at. With work left the
/// process goes back to the head of the level of its stage, so the next
/// portion there goes on with it, and at the stage Children its first
/// child goes in front of it; after the stage Notify the queue lets its
/// reference go, which queues the shell when it was the last. A shell's
/// portion, at `level`, gives pages of its pools back, and the last one
/// the slot.
///
/// # Safety
/// The process was just taken from the queue: it is on its stages, with
/// the queue's reference, or a shell nobody refers to.
pub unsafe fn clean(process: NonNull<Process>, level: u8) {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; only the fields are read.
    let (stage, r) = unsafe { ((*p).stage, (*p).level) };
    // The child that goes in front of the process at the stage Children.
    let mut first = None;
    let done = match stage {
        Stage::Whole => unreachable!("a whole process in the cleanup queue"),
        // SAFETY: the process is alive, and its children in the list too.
        Stage::Stop => unsafe { stop_child(process, r) },
        Stage::Children => {
            // SAFETY: the process is alive; only the field is read.
            first = unsafe { (*p).children };
            first.is_none()
        }
        // SAFETY: the process is alive, and the step borrows only the
        // field it works on.
        Stage::Handles => unsafe { release_handles(process, r) },
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
        // SAFETY: as above; the queue's reference keeps the shell.
        Stage::Notify => unsafe { notify_exit(process, r) },
        Stage::Shell => {
            // SAFETY: nothing refers to the shell, so nothing lives in its
            // pools; the shell stays in place until its last portion.
            unsafe {
                if release_pages(p) {
                    free(process, level);
                } else {
                    let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
                    cleanup::requeue(item, Object::Process(process), level);
                }
            }
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
            release(process, r);
        } else {
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::requeue(item, Object::Process(process), stage_level(p));
        }
        if let Some(child) = first {
            wait_for_child(child, r);
        }
    }
}

/// The stage Stop: the child at the cursor ends, killed, at `level` (R) if
/// it lives (`end`), and the cursor moves on. A child that ended before
/// is on its own stages already and stops its own descendants. True once
/// the cursor is past the last child. The child is used through `end`
/// first, whose check stops test builds on a shell that went.
///
/// # Safety
/// `process` is alive and at its stage Stop.
unsafe fn stop_child(process: NonNull<Process>, level: u8) -> bool {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; the child at the cursor is in the
    // list, so it is alive as an object.
    unsafe {
        if let Some(child) = (*p).stop_next {
            end(child, ProcessState::Killed, level);
            (*p).stop_next = child_links(child).next;
        }
        (*p).stop_next.is_none()
    }
}

/// The stage Children, after the parent went back to the head of its level
/// R, `level`: the parent's first child, which ended at the stage Stop,
/// goes to the head of the level of its own stage, right in front of the
/// parent at the same level (`hasten`).
///
/// # Safety
/// `child` is in its parent's list, so it is alive; the parent is queued.
unsafe fn wait_for_child(child: NonNull<Process>, level: u8) {
    // SAFETY: the caller's promise; only the field is read.
    let stage = unsafe { (*child.as_ptr()).stage };
    assert!(
        stage != Stage::Whole,
        "a child lives at its parent's stage Children"
    );
    // SAFETY: as above; the child's portions are not running.
    unsafe { hasten(child, level) };
}

/// The stage Handles: one step of the table's release, each handle's
/// object released at `level`. True once the table holds nothing.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn release_handles(process: NonNull<Process>, level: u8) -> bool {
    // SAFETY: releasing its objects reaches no other field but `refs`,
    // through raw pointers, since a release only counts and queues.
    let (handles, mut chunks) = unsafe { table(process) };
    handles.release_step(&mut chunks, |object, rights| {
        // SAFETY: the table let the handle go, and its reference with it.
        unsafe { object::release(object, rights, level) }
    })
}

/// The handle table of `process` and the memory for its blocks: the
/// process's pool of blocks, which its quota pays for by the page
/// (spec 7.5, 7.8).
///
/// # Safety
/// `process` is alive, and nothing else borrows its table, its pools, its
/// quota or its page log meanwhile.
unsafe fn table<'a>(process: NonNull<Process>) -> (&'a mut Handles, Chunks<'a>) {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; only these fields are borrowed.
    unsafe {
        let chunks = Chunks {
            blocks: &mut (*p).pools.blocks,
            pages: PaidPages::new(KernelPages, &mut (*p).quota, &mut (*p).pages),
        };
        (&mut (*p).handles, chunks)
    }
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
        // The cursor of the parent's stage Stop never names a child that
        // left: O(1), since no child joins a process that ended.
        if (*parent.as_ptr()).stop_next == Some(process) {
            (*parent.as_ptr()).stop_next = next;
        }
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

/// The stage Notify: bit 0 goes into the slot of the exit channel, at
/// `level` (R), unless there is none (spec 7.9); a channel that closed
/// gets nothing (channel::post), and the notification is lost with it, as
/// a notification to a parent that ends with its channel. True: one
/// portion.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn notify_exit(process: NonNull<Process>, level: u8) -> bool {
    // SAFETY: the caller's promise; the slot lives as long as the shell,
    // which the channel's queue holds while the slot stands there.
    unsafe {
        let exit = &raw mut (*process.as_ptr()).exit;
        if let Some(e) = (*exit).as_mut() {
            let slot = NonNull::new_unchecked(&raw mut e.slot);
            // PEER_CLOSED: nothing is posted (spec 6.5).
            let _ = channel::post(e.channel, slot, EXIT_BITS, level);
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

/// The stage Shell: up to SHELL_PORTION pages of the process's pools and
/// of its page log go back to the frame allocator, each refunded to its
/// quota (spec 7.8). True once none is left.
///
/// # Safety
/// Nothing refers to the shell: no object lives in its pools.
unsafe fn release_pages(p: *mut Process) -> bool {
    // SAFETY: the caller's promise; only the fields are borrowed.
    let (log, quota) = unsafe { (&mut (*p).pages, &mut (*p).quota) };
    log.release_step(SHELL_PORTION, |page| {
        // SAFETY: the page came from KernelPages through the pools, and no
        // object lives there any more.
        unsafe { pages::give_back(page) };
        quota.refund(PAGE_SIZE);
    })
}

/// A shell's last portion, once its pages went: the slot goes back to the
/// pool it came from, its parent's or ROOTS, then the exit channel gets
/// its slot and its reference back, the rest of the quota goes to the
/// parent (Account::return_rest: nothing is charged by now, since
/// whatever held the shell went), and then the reference to the parent's
/// shell, which queues that shell at `level` if it was the last.
///
/// # Safety
/// Nothing refers to the shell, its pages went, and it is in no queue.
unsafe fn free(process: NonNull<Process>, level: u8) {
    // SAFETY: the caller's promise; only the fields are touched.
    let (parent, rest, exit) = unsafe {
        let p = process.as_ptr();
        let exit = (*p).exit.as_ref().map(|e| {
            assert!(
                !e.slot.is_queued(),
                "a shell goes while its exit slot is queued"
            );
            e.channel
        });
        ((*p).parent, (*p).quota.return_rest(), exit)
    };
    // SAFETY: the caller's promise; every stage gave its memory back, and
    // the parent's pool is there, since the shell holds the parent's.
    unsafe {
        match parent {
            Some(parent) => (*parent.as_ptr()).pools.children.free(process),
            None => ROOTS.lock().free(process),
        }
    }
    #[cfg(feature = "ktest")]
    LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
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
    if let Some(c) = exit {
        channel::remove_source(c);
        // SAFETY: the shell's reference to its exit channel goes with it.
        unsafe { channel::release(c, Rights::NONE, level) };
    }
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
/// reason stays: process_exit, process_kill, a fault at EL0 and the stage
/// Stop of its parent come here. In the call itself every thread of the
/// process leaves the scheduler for good, and the process is queued for
/// its teardown at `cause`, the effective priority of the thread that made
/// the call or the fault (`begin`): its stage Stop at its ceiling, the
/// rest at the level of the cause, and what the teardown releases is
/// queued at that level too. The running thread may be one of the
/// process's: it never runs again and may be gone afterwards, so the
/// caller leaves through sched::resume. When the process is init, the run
/// ends (`init_ended`). True when the process ended here.
///
/// # Safety
/// The caller holds a reference to `process`, or `process` is in its
/// parent's list.
pub unsafe fn end(process: NonNull<Process>, reason: ProcessState, cause: u8) -> bool {
    // SAFETY: the caller's reference keeps the process alive.
    let ended = unsafe { (*life(process)).end(reason) };
    if ended {
        // SAFETY: as above; the end was just recorded.
        unsafe { stop(process, cause) };
    }
    ended
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

/// A slot for `thread`, a new thread of `process` (thread::create), in the
/// process's pool of threads, whose quota pays for a page when the pool
/// grows (spec 7.5, 7.8). NO_MEMORY when the quota falls short.
pub fn thread_slot(process: NonNull<Process>, thread: Thread) -> Result<NonNull<Thread>, Error> {
    // SAFETY: the caller holds a reference to the process; the thread is
    // no field of it.
    unsafe { paid_slot(process, |pools| &mut pools.threads, thread) }.map_err(|_| Error::NoMemory)
}

/// Gives the slot of `t`, a thread of `process` that goes (thread::clean),
/// back to the process's pool of threads, where its page stays paid until
/// the process's shell goes.
///
/// # Safety
/// `t` came from `thread_slot` of `process`, which is alive, and nothing
/// uses it afterwards.
pub unsafe fn free_thread_slot(process: NonNull<Process>, t: NonNull<Thread>) {
    // SAFETY: the caller's promise; only the pool is touched.
    unsafe { (*process.as_ptr()).pools.threads.free(t) }
}

/// A slot for `channel`, a new channel of `process` (channel::create), in
/// the process's pool of channels, whose quota pays for a page when the
/// pool grows (spec 7.5, 7.8). NO_MEMORY when the quota falls short.
pub fn channel_slot(
    process: NonNull<Process>,
    channel: Channel,
) -> Result<NonNull<Channel>, Error> {
    // SAFETY: the caller holds a reference to the process; the channel is
    // no field of it.
    unsafe { paid_slot(process, |pools| &mut pools.channels, channel) }.map_err(|_| Error::NoMemory)
}

/// Gives the slot of `c`, a channel that `process` paid for and that goes
/// (channel::clean), back to the process's pool of channels, where its
/// page stays paid until the process's shell goes.
///
/// # Safety
/// `c` came from `channel_slot` of `process`, whose shell it holds, and
/// nothing uses it afterwards.
pub unsafe fn free_channel_slot(process: NonNull<Process>, c: NonNull<Channel>) {
    // SAFETY: the caller's promise; only the pool is touched.
    unsafe { (*process.as_ptr()).pools.channels.free(c) }
}

/// A place for `session`, which `process` makes (session::create), in the
/// process's pool of sessions, whose quota pays for a page when the pool
/// grows (spec 5.3, 7.8). NO_MEMORY when the quota falls short.
pub fn session_slot(
    process: NonNull<Process>,
    session: Session,
) -> Result<NonNull<Session>, Error> {
    // SAFETY: the caller holds a reference to the process; the session is
    // no field of it.
    unsafe { paid_slot(process, |pools| &mut pools.sessions, session) }.map_err(|_| Error::NoMemory)
}

/// Gives the place of `s`, a session that `process` paid for and that goes
/// (session::clean), back to the process's pool of sessions, where its
/// page stays paid until the process's shell goes.
///
/// # Safety
/// `s` came from `session_slot` of `process`, whose shell it holds, and
/// nothing uses it afterwards.
pub unsafe fn free_session_slot(process: NonNull<Process>, s: NonNull<Session>) {
    // SAFETY: the caller's promise; only the pool is touched.
    unsafe { (*process.as_ptr()).pools.sessions.free(s) }
}

/// LIMIT_REACHED when `process` pays for abi::MAX_TIMERS timers (spec 10):
/// timer::create asks before it takes a slot of the channel or of the pool.
pub fn timer_room(process: NonNull<Process>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    if unsafe { (*process.as_ptr()).timer_count } < MAX_TIMERS {
        Ok(())
    } else {
        Err(Error::LimitReached)
    }
}

/// A place for `timer`, which `process` makes (timer::create) after
/// `timer_room` let it, in the process's pool of timers, whose quota pays
/// for a page when the pool grows (spec 7.8): one more timer of the
/// process. NO_MEMORY when the quota falls short.
pub fn timer_slot(process: NonNull<Process>, timer: Timer) -> Result<NonNull<Timer>, Error> {
    // SAFETY: the caller holds a reference to the process; the timer is no
    // field of it.
    let t = unsafe { paid_slot(process, |pools| &mut pools.timers, timer) }
        .map_err(|_| Error::NoMemory)?;
    // SAFETY: as above; only the field is touched.
    unsafe { (*process.as_ptr()).timer_count += 1 };
    Ok(t)
}

/// Gives the place of `t`, a timer that `process` paid for and that goes
/// (timer::clean), back to the process's pool of timers, where its page
/// stays paid until the process's shell goes: one timer fewer.
///
/// # Safety
/// `t` came from `timer_slot` of `process`, whose shell it holds, and
/// nothing uses it afterwards.
pub unsafe fn free_timer_slot(process: NonNull<Process>, t: NonNull<Timer>) {
    // SAFETY: the caller's promise; only the pool and the count are
    // touched.
    unsafe {
        let p = process.as_ptr();
        (*p).pools.timers.free(t);
        (*p).timer_count -= 1;
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
    Ok(space.map(va, pa, PAGE_SIZE, attrs, quota)?)
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

/// LIMIT_REACHED when the handle table of `process` has no room for one
/// more entry (spec 11): a call that would insert a handle checks this
/// before it allocates anything for the call, so a full table costs
/// nothing beyond the checks that come before it in the fixed order.
pub fn handle_room(process: NonNull<Process>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process; only the field
    // is read.
    if unsafe { (*process.as_ptr()).handles.room() } > 0 {
        Ok(())
    } else {
        Err(Error::LimitReached)
    }
}

/// Puts `object` in the handle table of `process` with `rights`; the new
/// handle holds a reference to it. A new chunk or directory of the table
/// comes from the pool of blocks of `process`, whose quota pays for a page
/// when the pool grows, whoever the handle comes from. LIMIT_REACHED at
/// the table's limit, NO_MEMORY when the quota falls short for a page.
/// The process lives: the table of one that ended stays empty.
pub fn insert_handle(
    process: NonNull<Process>,
    object: Object,
    rights: Rights,
) -> Result<Handle, Error> {
    assert!(
        check_alive(process).is_ok(),
        "a handle went into the table of a process that ended"
    );
    // SAFETY: the caller holds a reference to the process.
    let (handles, mut chunks) = unsafe { table(process) };
    let h = handles.insert(&mut chunks, object, rights)?;
    object::retain(object, rights);
    Ok(h)
}

/// Closes handle `h` of `process`: its reference goes, and the last one
/// queues the object for cleanup at `cause`. BAD_HANDLE for a handle that
/// is not live.
pub fn close_handle(mut process: NonNull<Process>, h: Handle, cause: u8) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process other than the
    // handle, so the process outlives the release below.
    let (object, rights) = unsafe { process.as_mut() }.handles.remove(h)?;
    // SAFETY: the handle is gone, and its reference with it.
    unsafe { object::release(object, rights, cause) };
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
/// child makes itself. The directory and the first chunk of the table
/// share the first page of the child's pool of blocks, which the child
/// pays for: NO_MEMORY when its quota falls short.
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

/// Entry 0 of the fresh table of a child that process_create made
/// (spec 13.3): the start channel, `object` with `rights`, which the
/// caller's handle names. The handle takes a new reference first; the
/// caller's handle goes only once the child is made, so the count of
/// handles with RECEIVE and the copies of a session never fall to zero
/// on the way, and a child that fails leaves the handle where it was. The
/// directory and the first chunk share the first page of the child's pool
/// of blocks, which the child pays for: NO_MEMORY when its quota falls
/// short.
pub fn move_start(child: NonNull<Process>, object: Object, rights: Rights) -> Result<(), Error> {
    let h = insert_handle(child, object, rights)?;
    assert_eq!(
        h,
        abi::START_CHANNEL,
        "the start entry went into a table that was not fresh"
    );
    Ok(())
}

/// The end of `child`, which process_create just made, goes as a
/// notification into `c` (spec 7.9): a slot of `priority` in the child's
/// shell with `label`, the label of the caller's handle, which took one of
/// the channel's slots already (channel::add_source). The shell holds the
/// channel until it goes. R, the level of the child's teardown, is at
/// least `priority` from now on (spec 7.7). Nothing can end the child
/// before: it has no thread, and only the caller holds it.
pub fn set_exit(child: NonNull<Process>, c: NonNull<Channel>, label: u64, priority: u8) {
    // SAFETY: the caller holds a reference to the child, which is whole;
    // only the fields are touched.
    unsafe {
        let p = child.as_ptr();
        assert!(
            (*p).stage == Stage::Whole && (*p).exit.is_none(),
            "an exit channel for a process that ended, or has one"
        );
        (*p).exit = Some(Exit {
            slot: Slot::new(priority, Owner::Exit(child)),
            label,
            channel: c,
        });
        (*p).level = (*p).level.max(priority);
    }
    channel::retain(c, Rights::NONE);
}

/// The label of the exit notification of `process`, which receive reports
/// with its slot.
pub fn exit_label(process: NonNull<Process>) -> u64 {
    // SAFETY: the exit slot is being taken, and it holds the shell; only
    // the field is read, and `refs` checks the object.
    unsafe {
        refs(process);
        (*process.as_ptr())
            .exit
            .as_ref()
            .expect("an exit slot")
            .label
    }
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

/// Processes whose shells have not gone.
#[cfg(feature = "ktest")]
pub fn in_use() -> usize {
    LIVE.load(core::sync::atomic::Ordering::Relaxed)
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
