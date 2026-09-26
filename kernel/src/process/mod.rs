// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Processes (spec 4, 8): an address space, the table of its mappings, its
//! handle table, its priority ceiling, its threads that have not ended, its
//! parent and children, and how it lives, in an object in its parent's pool
//! of shells. A process lives while references to it are left: handles to
//! it, its threads, and the one `create` hands out; its children hold only
//! its shell. It ends (`end`) through process_exit, process_kill, a fault
//! at EL0 or the exit of its last started thread, when its last reference
//! goes while it lives, and when its parent ends. The end itself only stops
//! its threads, at most abi::MAX_THREADS, and queues the process for
//! cleanup; the queue takes it apart in stages, a portion at a time, with
//! how far it came kept in the process (`Stage`, spec 7.7): first a wave
//! that stops its descendants above the cause, at its priority ceiling,
//! then the teardown at the level of the cause, its descendants first. Once
//! it gave its quota back, its exit channel hears of the end (spec 7.9),
//! through a slot in its shell. A shell with the reason stays for
//! object_info until the last reference queues it once more. Every release
//! names the level of its cause, which the cleanup it may start takes. A
//! process pays from its quota for what goes with it (spec 7.5, 7.8): a
//! page at a time as its pools grow, for its threads, the blocks of its
//! handle table, the shells of its children, the channels it made, the
//! sessions of the labels it gave (spec 5.3), its timers, at most
//! abi::MAX_TIMERS (spec 10), the memory objects and the interrupt bindings
//! it made, and the table of its mappings, whoever maps into it (`maps`);
//! at once, for the pages of those objects (spec 7.3); and for the tables
//! of its space, up front for a mapping, and the message buffers of its
//! threads. The pages of its pools go back only with its shell, in
//! portions. A child's quota comes off its parent's and goes back in two
//! parts: what is free at the child's stage Quota, and the rest with its
//! shell. The requests its threads accepted wait in it for their replies
//! (spec 4, 6.8); once it ended, its stage Replies wakes their clients with
//! PEER_CLOSED.

use crate::channel::{Channel, Owner, Source};
use crate::cleanup::{self, Item};
use crate::irq::Irq;
use crate::memory::Memory;
use crate::mm::aspace::{AddressSpace, SpaceRelease};
use crate::mm::pages::{self, KernelPages};
use crate::object::{self, Block, Chunks, Handles, Live, Moving, Object, Refs};
use crate::sched;
use crate::session::Session;
use crate::thread::{self, Siblings, Thread};
use crate::timer::Timer;
use abi::{Error, Handle, MAX_THREADS, MAX_TIMERS, ProcessState, Rights};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::notify::Slot;
use kcore::paging::Attrs;
use kcore::process::Life;
use kcore::quota::Account;
use kcore::sched::{ReadyQueue, Scheduler};
use kcore::slab::{PageLog, PaidPages, Pool};
use kcore::sync::Lock;

mod maps;
mod table;
mod teardown;

#[cfg(feature = "icount")]
pub use maps::EXEC_PORTION;
#[cfg(feature = "ktest")]
pub use maps::PORTION;
pub use maps::{
    Change, abandon_change, add_mapping, begin_change, check_free, find_mapping, finish_change,
    in_mapping, map_whole, step_change,
};
#[cfg(not(feature = "ktest"))]
pub use table::install_init_handles;
pub use table::{
    close_handle, handle_counts, handle_room, insert_handle, move_start, put_handles,
    reserve_handles, reserve_start, take_handles,
};
pub use teardown::{Stage, clean, exit_label, hasten, raise_replies, set_exit};
use teardown::{begin, queue_shell};

pub struct Process {
    /// From `create` until the first portion of the stage Space takes it:
    /// from then on no call reaches its tables (`map_page` fails,
    /// `translate` finds nothing).
    space: Option<AddressSpace>,
    /// The tables of the space on their way back, from that first portion
    /// until the root went: TTBR0 left them and their TLB entries went
    /// first, so the tables go before the threads' message buffers and the
    /// objects of the mappings, whose frames the tables mapped.
    retired: Option<SpaceRelease>,
    /// The table of its mappings, in a block of its pool of blocks, from
    /// its first mapping until the stage Mappings (spec 7.4).
    maps: Option<NonNull<maps::Table>>,
    /// Released at the stage Handles: its handles hold references to
    /// other objects.
    handles: Handles,
    /// Handles to the process, its threads, the reference `create` hands
    /// out, and the cleanup queue's while the process is on its stages:
    /// the references that keep it alive.
    refs: Refs,
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
    /// The source of its exit notification (process_create x3, spec 6.5,
    /// 7.9): its slot lies in the shell and holds the shell while it stands
    /// in the channel's queue, with the label of the handle process_create
    /// took as x3; the shell holds the channel, with one of its slots,
    /// until the shell goes. Set once, before anything can end the process.
    exit: Option<Source>,
    /// At the stage Stop, the child it stops next; a child that leaves
    /// the list moves it on (`leave_parent`).
    stop_next: Option<NonNull<Process>>,
    /// The requests its threads accepted and have not answered (spec 6.1,
    /// 6.8): the own slots of their clients, which wait for the replies, at
    /// the levels the clients had. Any thread of the process may answer.
    /// A request holds no reference to its client: while it stands here the
    /// client lives, and a client that ends takes its slot out
    /// (channel::cancel). Reached only with the scheduler locked
    /// (`accepted`).
    accepted: ReadyQueue<Slot<Owner>>,
    /// How far its teardown came.
    stage: Stage,
    /// Its place in the cleanup queue: on its stages, and as a shell once
    /// its last reference goes.
    cleanup: Item,
}

// Two shells to a page of a pool (spec 7.8).
const _: () = assert!(Pool::<Process>::PER_PAGE >= 2);

/// The pools of what a process pays for by the page (spec 7.5, 7.8): a
/// page is charged when a pool grows, a slot that goes back refunds
/// nothing, and the pages go back only with the process's shell. Every
/// object in them holds a reference to the process or to its shell, so by
/// then they hold nothing.
pub struct Pools {
    /// Its threads, whoever made them.
    threads: Pool<Thread>,
    /// The chunks and the directory of its handle table, and the table of
    /// its mappings (`maps`).
    blocks: Pool<Block>,
    /// The shells of its children.
    children: Pool<Process>,
    /// The channels it made.
    channels: Pool<Channel>,
    /// The sessions of the labels it gave (handle_duplicate).
    sessions: Pool<Session>,
    /// The timers it made, at most abi::MAX_TIMERS (spec 10).
    timers: Pool<Timer>,
    /// The memory objects it made (spec 7.3).
    memories: Pool<Memory>,
    /// The interrupt bindings it made (spec 9).
    irqs: Pool<Irq>,
}

/// Neighbours in the list of a parent's children.
#[derive(Clone, Copy)]
struct ChildLinks {
    prev: Option<NonNull<Process>>,
    next: Option<NonNull<Process>>,
}

// SAFETY: processes and their threads are reached under the kernel's
// rules (spec 8.1): one CPU, interrupts masked inside the kernel, ROOTS
// behind a lock.
unsafe impl Send for Process {}

/// The shells of processes with no parent: at boot the reserve, a page
/// for init's shell taken before init's quota is counted (spec 7.5);
/// in test builds the kernel tests' processes. Its pages stay.
static ROOTS: Lock<Pool<Process>> = Lock::new(Pool::new());

/// Processes whose shells have not gone.
static LIVE: Live = Live::new();

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

    /// Whether the process lives and, if not, why it ended.
    pub fn state(&self) -> ProcessState {
        self.life.state()
    }

    /// The highest base priority a thread of the process may have.
    pub fn ceiling(&self) -> u8 {
        self.ceiling
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
    let ceiling = kcore::args::priority_arg(u64::from(ceiling))?;
    kcore::args::handle_limit_arg(u64::from(handle_limit))?;
    let handles = Handles::new(handle_limit)?;
    let mut quota = Account::new(quota);
    let space = AddressSpace::new(&mut quota).map_err(|_| Error::NoMemory)?;
    let process = Process {
        space: Some(space),
        retired: None,
        maps: None,
        handles,
        refs: Refs::one(),
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
            memories: Pool::new(),
            irqs: Pool::new(),
        },
        ceiling,
        life: Life::new(),
        threads: None,
        thread_count: 0,
        parent: None,
        children: None,
        child_siblings: None,
        init: false,
        level: 0,
        exit: None,
        stop_next: None,
        accepted: ReadyQueue::new(),
        stage: Stage::Whole,
        cleanup: Item::new(),
    };
    let allocated = match payer {
        // SAFETY: the caller holds a reference to the payer; the new
        // process is no field of it.
        Some(payer) => unsafe { paid_slot(payer, process) },
        None => ROOTS.lock().alloc(&mut KernelPages, process),
    };
    let process = allocated.map_err(|mut process| {
        // No object for it: its space goes, with the pool's lock released.
        process.destroy_space();
        Error::NoMemory
    })?;
    LIVE.made();
    Ok(process)
}

/// Puts `value` in a slot of the pool of its kind among those of `payer`,
/// whose quota pays for a page when the pool grows (spec 7.8); gives the
/// value back when the quota falls short.
///
/// # Safety
/// `payer` is alive, and nothing else borrows its pools, its quota or its
/// page log meanwhile.
unsafe fn paid_slot<T: Paid>(payer: NonNull<Process>, value: T) -> Result<NonNull<T>, T> {
    let p = payer.as_ptr();
    // SAFETY: the caller's promise; only these fields are borrowed.
    let (pools, quota, log) = unsafe { (&mut (*p).pools, &mut (*p).quota, &mut (*p).pages) };
    T::pool(pools).alloc(&mut PaidPages::new(KernelPages, quota, log), value)
}

/// A kind of object a process pays for by the page (spec 7.5, 7.8): it
/// names its pool among the payer's. The pages go back with the payer's
/// shell (Stage::Shell), so a kind needs no stage of its own.
pub trait Paid: Sized {
    fn pool(pools: &mut Pools) -> &mut Pool<Self>;
}

impl Paid for Thread {
    fn pool(pools: &mut Pools) -> &mut Pool<Thread> {
        &mut pools.threads
    }
}

impl Paid for Process {
    fn pool(pools: &mut Pools) -> &mut Pool<Process> {
        &mut pools.children
    }
}

impl Paid for Channel {
    fn pool(pools: &mut Pools) -> &mut Pool<Channel> {
        &mut pools.channels
    }
}

impl Paid for Session {
    fn pool(pools: &mut Pools) -> &mut Pool<Session> {
        &mut pools.sessions
    }
}

impl Paid for Timer {
    fn pool(pools: &mut Pools) -> &mut Pool<Timer> {
        &mut pools.timers
    }
}

impl Paid for Memory {
    fn pool(pools: &mut Pools) -> &mut Pool<Memory> {
        &mut pools.memories
    }
}

impl Paid for Irq {
    fn pool(pools: &mut Pools) -> &mut Pool<Irq> {
        &mut pools.irqs
    }
}

/// A place for `value`, an object that `payer` makes (thread::create,
/// channel::create, session::create, timer::create, memory::create,
/// irq::bind), in
/// the payer's pool of its kind, whose quota pays for a page when the pool
/// grows (spec 7.5, 7.8). NO_MEMORY when the quota falls short.
pub fn paid_alloc<T: Paid>(payer: NonNull<Process>, value: T) -> Result<NonNull<T>, Error> {
    // SAFETY: the caller holds a reference to the payer; the value is no
    // field of it.
    unsafe { paid_slot(payer, value) }.map_err(|_| Error::NoMemory)
}

/// Gives the place of `object`, which goes (its kind's `clean`, or the
/// last portion of a child's shell), back to the payer's pool of its kind,
/// where its page stays paid until the payer's shell goes.
///
/// # Safety
/// `object` came from the pool of `payer` (`paid_alloc`, or `create` for a
/// child's shell), and the payer is alive: the object holds the payer's
/// shell, or it is a thread of the payer. Nothing uses it afterwards.
pub unsafe fn paid_free<T: Paid>(payer: NonNull<Process>, object: NonNull<T>) {
    // SAFETY: the caller's promise; only the pool is touched.
    unsafe { T::pool(&mut (*payer.as_ptr()).pools).free(object) }
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

/// The quota of `process`, which pays for the frames it owns
/// (phys::alloc_zeroed, phys::free, spec 7.5): the message buffers of its
/// threads. Only the field is borrowed (see `refs`).
///
/// # Safety
/// The caller holds a reference to `process`, which has not passed its
/// stage Quota, and nothing else borrows its quota while the caller holds
/// the borrow.
pub unsafe fn account<'a>(process: NonNull<Process>) -> &'a mut Account {
    // SAFETY: the caller's promise.
    unsafe { &mut (*process.as_ptr()).quota }
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
/// of `release_step` meanwhile (`release_handles`).
///
/// # Safety
/// `process` is alive, and nothing else borrows the count.
#[must_use]
unsafe fn refs<'a>(process: NonNull<Process>) -> &'a mut Refs {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*process.as_ptr()).refs }
}

/// Adds a reference to a live process (Refs::retain).
pub fn retain(process: NonNull<Process>) {
    // SAFETY: the caller holds a reference, so the process is alive.
    unsafe { refs(process) }.retain();
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
    if !unsafe { refs(process) }.release() {
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
        refs(process).check();
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
        let refs = refs(process).get();
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

// The poison of a shell that went (Live::gone) reaches its count.
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
/// builds stop a process that went, as `Refs::check` does.
///
/// # Safety
/// `process` is alive.
unsafe fn life(process: NonNull<Process>) -> *mut Life {
    // SAFETY: the caller's promise; the count is only checked.
    unsafe { refs(process) }.check();
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
/// as a panic does. In test builds the running test judges init's end
/// instead, and the tests go on (testpoint::init_ended).
fn init_ended(state: ProcessState) -> ! {
    crate::testpoint::init_ended();
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

/// LIMIT_REACHED when `process` pays for abi::MAX_TIMERS timers (spec 10):
/// timer::create asks before it takes a slot of the channel or of the pool.
pub fn timer_room(process: NonNull<Process>) -> Result<(), Error> {
    // SAFETY: the caller holds a reference to the process; only the pool
    // is read.
    if unsafe { (*process.as_ptr()).pools.timers.in_use() } < MAX_TIMERS as usize {
        Ok(())
    } else {
        Err(Error::LimitReached)
    }
}

/// The queue of the requests `process` accepted (Process::accepted), which
/// changes together with the states of the clients in it: reached only
/// with the scheduler locked, which `_locked` shows (sched::locked).
///
/// # Safety
/// `process` is alive.
pub unsafe fn accepted(
    process: NonNull<Process>,
    _locked: &mut Scheduler<Thread>,
) -> &mut ReadyQueue<Slot<Owner>> {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { &mut (*process.as_ptr()).accepted }
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

/// Processes that came to their stage Quota with children still in their
/// list: none may, since the stage Children waits for each (test builds).
#[cfg(feature = "ktest")]
static EARLY_QUOTA: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(feature = "ktest")]
pub use test_access::{
    has_accepted, in_use, mapping, mappings, parent, progress, take_early_quota,
};

/// What the kernel tests read and steer here (crate::ktest).
#[cfg(feature = "ktest")]
mod test_access {
    use super::*;

    /// Processes whose shells have not gone.
    pub fn in_use() -> usize {
        LIVE.count()
    }

    /// How many processes came to their stage Quota before their children
    /// passed theirs, since the last call.
    pub fn take_early_quota() -> u32 {
        EARLY_QUOTA.swap(0, core::sync::atomic::Ordering::Relaxed)
    }

    /// The parent of `process`, which the test holds.
    pub fn parent(process: NonNull<Process>) -> Option<NonNull<Process>> {
        // SAFETY: the test holds a reference to the process; only the field is
        // read.
        unsafe { (*process.as_ptr()).parent }
    }

    /// Whether requests the threads of `process`, which the test holds,
    /// accepted wait for their replies.
    pub fn has_accepted(process: NonNull<Process>) -> bool {
        // SAFETY: the test holds a reference to the process; only the mask
        // of the queue is read.
        sched::locked(|k| unsafe { !accepted(process, k.s).is_empty() })
    }

    /// The mappings of `process`, which the test holds.
    pub fn mappings(process: NonNull<Process>) -> usize {
        // SAFETY: the test holds a reference to the process; only the table
        // is read.
        unsafe { maps::table(process) }.map_or(0, |t| t.len())
    }

    /// The mapping of exactly `pages` pages from `va` of `process`, which
    /// the test holds.
    pub fn mapping(
        process: NonNull<Process>,
        va: usize,
        pages: u64,
    ) -> Option<kcore::maps::Mapping<NonNull<Memory>>> {
        // SAFETY: as in `mappings`.
        let table = unsafe { maps::table(process) }?;
        let index = table.find(va as u64, pages).ok()?;
        Some(*table.get(index))
    }

    /// How far the teardown of `process` came: its stage, the handles left in
    /// its table, and the tables of its space that went back.
    pub fn progress(process: NonNull<Process>) -> (Stage, u32, usize) {
        // SAFETY: the test holds a reference to the process, and nothing
        // runs its portions meanwhile.
        let p = unsafe { process.as_ref() };
        let tables = p.retired.as_ref().map_or(0, |r| r.freed());
        (p.stage, p.handles.len(), tables)
    }
}
