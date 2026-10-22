// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The teardown of a process (spec 7.7, 7.9): its stages, a portion at a
//! time with how far it came kept in the process, and the notification
//! of its end to its exit channel.

use super::table::table;
use super::{
    Channel, ChildLinks, Error, LIVE, NonNull, Object, Owner, PAGE_SIZE, Process, ProcessState,
    ROOTS, Source, Thread, accepted, child_links, cleanup, control, end, object, pages, paid_free,
    refs, refund, release, release_shell, remove_thread, sched, thread,
};
use crate::syscall;

/// Pages a portion of the stage Shell gives back, at most (spec 7.7):
/// each goes back to the frame allocator, FRAME_UNITS units of work, in one
/// section under OBJ.
const SHELL_PORTION: usize = kcore::pagelist::FRAMES_PER_SECTION;

/// The work a portion of the stage Threads does, at most (spec 7.7): a
/// thread that waits in send, in receive or for a reply leaves its queue
/// and lets go what its wait held, WAIT_UNITS units of work; any other
/// thread leaves the scheduler in one unit. 6 senders or 12 ready threads
/// take one portion, which is one section under OBJ with the check of the
/// gate.
const THREADS_PORTION: usize = 12;

/// The units of work of a thread that waits in IPC (channel::cancel).
const WAIT_UNITS: usize = 2;

/// Clients of one level a portion of the stage Replies wakes, at most
/// (spec 7.7).
const REPLIES_PORTION: usize = 32;

/// The work a portion of the stage Buffers does, at most (spec 7.7): the
/// buffer of each thread is FRAME_UNITS units, and each handle of a request
/// it made and the long call it was making one more (thread::held); a
/// thread goes into the portion only when its units fit. The buffers of 4
/// threads with no handles take one portion, one section under OBJ.
const BUFFERS_PORTION: usize = 8;
/// A thread goes into a portion only when its units fit, so the heaviest
/// thread (its frame, the handles of its request and its long call) has to
/// fit alone, or the stage would never end (the long call is one unit more,
/// hence the strict comparison).
const _: () = assert!(FRAME_UNITS + abi::MESSAGE_HANDLES < BUFFERS_PORTION);

/// Handle table entries a portion of the stage Handles releases, at most
/// (spec 7.7): an eighth of a chunk, in one section under OBJ, each last
/// copy of a session telling its receiver the client is gone.
const HANDLES_PORTION: usize = 8;
const _: () = assert!(kcore::handles::CHUNK.is_multiple_of(HANDLES_PORTION));

/// The units of work of a frame that goes back to the frame allocator
/// (spec 7.7): its free may merge blocks up to kcore::frames::MAX_ORDER.
const FRAME_UNITS: usize = 2;

/// The bits of an exit notification (spec 6.5, 7.9): bit 0, once.
const EXIT_BITS: u64 = 1;

/// Where the teardown of a process stands (spec 7.7). A process is whole
/// until it ends; then the cleanup queue holds it, with a reference of its
/// own, and each portion takes one step of its stage, in the order of
/// STAGES, with how far it came kept in the process. Threads, Stop,
/// Replies, Children, Handles, Space and Shell take as many portions as
/// their steps; the others one. The stages Threads and Stop run at S, the
/// higher of the process's ceiling and R (`level`); Replies at the higher
/// of R and its top client; the others at R, but for Shell, which runs at
/// the level of the last reference. After the stage Notify the queue lets
/// its reference go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No teardown began: the process lives.
    Whole,
    /// Only for a process with threads when it ends: its threads, from the
    /// cursor `threads_next` on, leave the scheduler for good (sched::exit),
    /// THREADS_PORTION units of work a portion, and each loses the
    /// kernel's reference, which may queue it for cleanup at R; they stay
    /// in the list until the stage Buffers. At S none of them runs
    /// meanwhile: no effective priority is above the ceiling, the cleanup
    /// queue wins over threads of its level (kcore::sched::Scheduler::pick),
    /// and the fast path of send hands off to none of them
    /// (Scheduler::can_hand_off). A thread that leaves the list moves the
    /// cursor on (`remove_thread`). Until its portion, a thread that waits
    /// in receive on a channel that a live process receives on too takes
    /// requests and notifications there as any receiver does (spec 6.8):
    /// its client wakes with PEER_CLOSED at the stage Replies, and the
    /// notification goes with the process.
    Threads,
    /// Only for a process with children when it ends: a child a portion,
    /// the one at the cursor `stop_next`, ends, killed, at R, if it lives,
    /// which begins its own teardown (`end`), its stage Threads first. At S
    /// no thread of a descendant runs meanwhile: none has an effective
    /// priority above its process's ceiling, and no ceiling of a
    /// descendant is above this one's (spec 4, 8).
    Stop,
    /// Up to REPLIES_PORTION clients of the top level of the queue of
    /// requests its threads accepted (`accepted`) a portion: each wakes
    /// with PEER_CLOSED (spec 6.8). Its threads are dead, so no request
    /// joins the queue, and a client that ends leaves it itself
    /// (channel::cancel). One portion when the queue is empty.
    Replies,
    /// A child a portion: the first child in the list, which the stage
    /// Stop ended, goes right in front of the process in the queue
    /// (`hasten`); the process waits behind it until the child leaves the
    /// list at its own stage Quota. Descendants go depth first, and the
    /// kernel stack does not grow with the depth of the tree (spec 4).
    Children,
    /// An eighth of a chunk of the handle table a portion, up to HANDLES_PORTION
    /// handles, each releasing its object; the chunk directory with the
    /// last part of the last chunk (HandleTable::release_step).
    Handles,
    /// The first portion takes the space: TTBR0 leaves its tables and
    /// their TLB entries go with the ASID (AddressSpace::retire). Then a
    /// table a portion (SpaceRelease::step).
    Space,
    /// The message buffers of the threads the end stopped, at most
    /// abi::MAX_THREADS, with the handles of the requests they made, up to
    /// abi::MESSAGE_HANDLES each, and what the long calls they were making
    /// held (thread::drop_long), BUFFERS_PORTION units of work a portion,
    /// and the threads leave the list. After Space, so that no TLB entry
    /// maps a frame that goes.
    Buffers,
    /// The entries of the table of its mappings, at most abi::MAX_MAPPINGS,
    /// each letting its memory object go, and the block of the table
    /// (maps::release_all), MAPPINGS_PORTION entries a portion. After Space, so that no TLB entry
    /// maps a frame of an object that goes.
    Mappings,
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
const STAGES: [Stage; 11] = [
    Stage::Threads,
    Stage::Stop,
    Stage::Replies,
    Stage::Children,
    Stage::Handles,
    Stage::Space,
    Stage::Buffers,
    Stage::Mappings,
    Stage::Quota,
    Stage::Notify,
    Stage::Shell,
];

// STAGES lists the stages in the order of their declaration after Whole.
const _: () = {
    let mut i = 0;
    while i < STAGES.len() {
        assert!(STAGES[i] as usize == i + 1);
        i += 1;
    }
};

/// The stage after `stage`, which is one of STAGES but the last: the one
/// at the index of its discriminant there. O(1).
fn after(stage: Stage) -> Stage {
    STAGES[stage as usize]
}

/// `stage`, or the first stage after it with work, when it is Threads or
/// Stop and its cursor names nothing: no portion goes to an empty one.
///
/// # Safety
/// `p` is alive; only the cursors are read.
unsafe fn with_work(p: *mut Process, stage: Stage) -> Stage {
    // SAFETY: the caller's promise.
    unsafe {
        let mut stage = stage;
        if stage == Stage::Threads && (*p).threads_next.is_none() {
            stage = Stage::Stop;
        }
        if stage == Stage::Stop && (*p).stop_next.is_none() {
            stage = Stage::Replies;
        }
        stage
    }
}

/// Queues the shell of a process for its last portion unless a child
/// still holds it.
///
/// # Safety
/// No reference that keeps the process alive is left, and its stages are
/// over.
pub(super) unsafe fn queue_shell(process: NonNull<Process>, cause: u8) {
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
/// own and queues the process for its first stage: Threads at S for a
/// process with threads in its list past `stopped`, the thread the call
/// took off when it heads the list, Stop at S for one with children,
/// Replies otherwise (`stage_level`). Runs inside the caller's section.
///
/// # Safety
/// `process` is alive and whole; a continuation may own its cleanup item.
/// `stopped`, if any, is a
/// thread of it that left the scheduler.
pub(super) unsafe fn begin(process: NonNull<Process>, cause: u8, stopped: Option<NonNull<Thread>>) {
    // SAFETY: the caller's promise; only the fields are touched.
    unsafe {
        let p = process.as_ptr();
        assert!(
            (*p).stage == Stage::Whole,
            "the teardown of a process begins twice"
        );
        (*p).level = (*p).level.max(cause);
        (*p).stop_next = (*p).children;
        (*p).threads_next = (*p).threads;
        if let Some(t) = stopped
            && (*p).threads_next == Some(t)
        {
            (*p).threads_next = (*t.as_ptr()).siblings.and_then(|s| s.next);
        }
        (*p).stage = with_work(p, Stage::Threads);
        let continued = control::cancel(process);
        // The queue's own reference. `retain` refuses a count of 0, which
        // it is when the last reference ended the process (`release`).
        if continued == control::Continuation::None {
            refs(process).take();
        }
        // A continuation whose portion runs keeps the reference and the
        // item: its next section queues the process (`control::portion`).
        if continued != control::Continuation::Running {
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::enqueue(item, Object::Process(process), stage_level(process));
        }
    }
}

/// The level the stage of `process` runs at (spec 7.7): S, the higher of
/// its ceiling and R, at the stages Threads and Stop; the higher of R and
/// the top level of its accepted requests at the stage Replies, read under
/// OBJ, which the caller holds; R at the others. O(1).
///
/// # Safety
/// `process` is alive; only the fields are read.
pub(super) unsafe fn stage_level(process: NonNull<Process>) -> u8 {
    let p = process.as_ptr();
    // SAFETY: the caller's promise.
    unsafe {
        match (*p).stage {
            Stage::Threads | Stage::Stop => (*p).ceiling.max((*p).level),
            Stage::Replies => {
                let top = sched::locked(|k| accepted(process, k.s).top());
                top.map_or((*p).level, |top| top.max((*p).level))
            }
            _ => (*p).level,
        }
    }
}

/// thread_set_priority moved a client in the queue of accepted requests of
/// `process` (channel::raise): at the stage Replies the process goes up in
/// the cleanup queue to the level of its top client when that is higher
/// (spec 7.7). Nothing at other stages. Runs inside the caller's section.
///
/// # Safety
/// `process` is alive: a client waits for its reply.
pub unsafe fn raise_replies(process: NonNull<Process>) {
    let p = process.as_ptr();
    // SAFETY: the caller's promise; a process at its stage Replies stands
    // in the cleanup queue between its portions.
    unsafe {
        if (*p).stage == Stage::Replies {
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::raise_above(item, stage_level(process));
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
    crate::obj::assert_held();
    // SAFETY: the caller's promise; a process on its stages is queued
    // outside its own portions, since the queue holds it.
    unsafe {
        let p = process.as_ptr();
        refs(process).check();
        (*p).level = (*p).level.max(level);
        match (*p).stage {
            Stage::Whole => unreachable!("a process that lives is hastened"),
            Stage::Shell => {}
            _ => {
                let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
                cleanup::raise(item, stage_level(process));
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
    // The stage changes only in this process's own portions (after Whole);
    // R changes under OBJ, from any CPU (`hasten`), so it is read in the
    // section.
    // SAFETY: the caller's promise; only the field is read.
    let stage = unsafe { (*p).stage };
    // What a stage takes from what no link reaches, before its section: the
    // entries of the handle table, the table of the space that went, and the
    // pages of the shell's log with their poison.
    let mut handles = [None; HANDLES_PORTION];
    let mut table = None;
    let mut pages_back = [None; SHELL_PORTION];
    let mut handles_left = false;
    let mut pages_left = false;
    // SAFETY: the process is alive and on its stages, and nothing else
    // reaches these fields while its portion runs.
    unsafe {
        match stage {
            Stage::Whole => {
                // The continuation owns the item and its reference.
                control::portion(process, level);
                return;
            }
            Stage::Handles => handles_left = !collect_handles(process, &mut handles),
            Stage::Space => table = collect_table(p),
            Stage::Shell => pages_left = !collect_pages(p, &mut pages_back),
            Stage::Quota => crate::testpoint::quota_stage((*p).children.is_some()),
            #[cfg(feature = "window-probe")]
            Stage::Threads => crate::cmd::window::hold_until_replied((*p).threads_next),
            _ => {}
        }
    }
    // The one section of the portion: the step, the move to the next stage
    // and the queue (the level of the next stage is read here too).
    let section = crate::obj::lock();
    // SAFETY: as above; only the field is read.
    let r = unsafe { (*p).level };
    // The child that goes in front of the process at the stage Children.
    let mut first = None;
    let mut heads = None;
    // SAFETY: the process is alive; the stage functions' own promises are
    // those of the caller.
    let done = unsafe {
        match stage {
            Stage::Whole => unreachable!("handled above"),
            Stage::Threads => stop_threads(process, r),
            Stage::Stop => stop_child(process, r),
            Stage::Replies => {
                let (done, n) = wake_clients(process);
                heads = Some(n);
                done
            }
            Stage::Children => {
                first = (*p).children;
                first.is_none()
            }
            Stage::Handles => {
                release_handles(&handles, r);
                !handles_left
            }
            Stage::Space => release_space(p, table),
            Stage::Buffers => release_buffers(process, r),
            Stage::Mappings => super::maps::release_all(process, r),
            Stage::Quota => leave_parent(process),
            Stage::Notify => notify_exit(process, r),
            Stage::Shell => {
                // Nothing refers to the shell, so nothing lives in its
                // pools; it stays in place until its last portion.
                give_back_pages(p, &pages_back);
                if !pages_left {
                    free(process, level);
                } else {
                    let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
                    cleanup::requeue(item, Object::Process(process), level);
                }
                drop(section);
                return;
            }
        }
    };
    let next = match (done, stage) {
        (false, _) => stage,
        // SAFETY: the process is alive; only the cursor is read.
        (true, Stage::Threads) => unsafe { with_work(p, Stage::Stop) },
        (true, _) => after(stage),
    };
    // SAFETY: the process is alive; the queue's reference goes last, and
    // nothing uses the process afterwards; the child is alive while it is
    // in the list.
    unsafe {
        (*p).stage = next;
        if next == Stage::Shell {
            release(process, r);
        } else {
            let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
            cleanup::requeue(item, Object::Process(process), stage_level(process));
        }
    }
    if let Some(child) = first {
        // The child's turn in front of the parent changes its level and
        // its place in the queue of its CPU, which the sections of every
        // CPU change without that queue's lock: inside the section.
        // SAFETY: the child is in its parent's list, so it is alive.
        unsafe { wait_for_child(child, r) };
    }
    drop(section);
    // After the section: what the tests see of the portion.
    if let Some(n) = heads.filter(|&n| n > 0) {
        crate::testpoint::heads_taken(level, n);
    }
    #[cfg(feature = "window-probe")]
    if stage == Stage::Threads && done {
        // The threads are gone and the stage is not Replies yet: the
        // clients of the process stay in their wait for a while.
        crate::cmd::window::hold_replies();
    }
}

/// The stage Threads: from the thread at the cursor on, each thread of
/// the list leaves the scheduler (sched::exit) and loses the kernel's
/// reference at `level` (R), WAIT_UNITS units of work for a thread that
/// waits in IPC, which also leaves its queue and lets go what its wait
/// held, one for any other, THREADS_PORTION units a portion; a thread goes
/// into the portion only when its units fit. True once the cursor is past
/// the last thread. Runs inside the caller's section, the check of the gate
/// and the threads in one.
///
/// # Safety
/// `process` is alive and at its stage Threads.
unsafe fn stop_threads(process: NonNull<Process>, level: u8) -> bool {
    crate::obj::assert_held();
    let p = process.as_ptr();
    let mut work = 0;
    // Nothing leaves the scheduler while a thread of the process may
    // still run at EL0 on another CPU (control::mark_ending).
    // SAFETY: the caller's promise.
    if unsafe { !super::control::gate_seen(process) } {
        return false;
    }
    // SAFETY: the caller's promise; a thread in the list is alive, since a
    // release only queues it, and its portion takes it out of the list
    // first.
    unsafe {
        while let Some(t) = (*p).threads_next {
            let units = if thread::waits(t) { WAIT_UNITS } else { 1 };
            if work + units > THREADS_PORTION {
                break;
            }
            work += units;
            (*p).threads_next = (*t.as_ptr()).siblings.and_then(|s| s.next);
            sched::exit(t, level);
        }
        (*p).threads_next.is_none()
    }
}

/// The stage Stop: the child at the cursor ends, killed, at `level` (R) if
/// it lives (`end`), and the cursor moves on. A child that ended before
/// is on its own stages already and stops its own descendants. True once
/// the cursor is past the last child. The child is used through `end`
/// first, whose check stops test builds on a shell that went. Runs inside
/// the caller's section.
///
/// # Safety
/// `process` is alive and at its stage Stop.
unsafe fn stop_child(process: NonNull<Process>, level: u8) -> bool {
    crate::obj::assert_held();
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

/// The stage Replies: up to REPLIES_PORTION clients at the top level of the
/// queue of accepted requests of `process` leave it, each woken with
/// PEER_CLOSED in x0 alone at the tail of its level with a new quantum (spec
/// 6.8), inside the caller's section. True once the queue is empty; a
/// process that took no request passes at once. Also how many clients woke.
///
/// # Safety
/// `process` is alive and at its stage Replies.
unsafe fn wake_clients(process: NonNull<Process>) -> (bool, usize) {
    crate::obj::assert_held();
    let taken = sched::locked(|k| {
        // SAFETY: the caller's promise; a client in the queue is alive.
        unsafe {
            let top = accepted(process, k.s).top()?;
            let mut heads = 0;
            while heads < REPLIES_PORTION
                && let Some(slot) = accepted(process, k.s).first(top)
            {
                accepted(process, k.s).remove(slot);
                let Owner::Thread(t) = (*slot.as_ptr()).owner() else {
                    unreachable!("an accepted request of no thread");
                };
                (*t.as_ptr()).waits = None;
                syscall::set_result(t, Err(Error::PeerClosed));
                sched::wake(k, t);
                heads += 1;
            }
            Some((heads, !accepted(process, k.s).is_empty()))
        }
    });
    match taken {
        None => (true, 0),
        Some((heads, left)) => (!left, heads),
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

/// The stage Handles, before its section: one step of the table's release,
/// HANDLES_PORTION entries taken out of the table into `batch`, with the
/// rights of their handles. True once the table holds nothing.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn collect_handles(
    process: NonNull<Process>,
    batch: &mut [Option<(Object, abi::Rights)>; HANDLES_PORTION],
) -> bool {
    // SAFETY: the table is the process's own, and nothing reaches it while
    // its portion runs.
    let (handles, mut chunks) = unsafe { table(process) };
    let mut n = 0;
    handles.release_step(&mut chunks, HANDLES_PORTION, |object, rights| {
        batch[n] = Some((object, rights));
        n += 1;
    })
}

/// The stage Handles, in the caller's section: each handle of the step
/// (`collect_handles`) lets its object go at `level`.
///
/// # Safety
/// The entries left the table with their handles, and their references
/// with them.
unsafe fn release_handles(batch: &[Option<(Object, abi::Rights)>; HANDLES_PORTION], level: u8) {
    crate::obj::assert_held();
    for &(object, rights) in batch.iter().flatten() {
        // SAFETY: the caller's promise.
        unsafe { object::release(object, rights, level) }
    }
}

/// The stage Space, before its section: the step of the retired space reads
/// the entries of its tables, and notes the table it frees, for
/// `release_space`. None for the first portion, which retires the space.
///
/// # Safety
/// `p` is alive and on its stages.
unsafe fn collect_table(p: *mut Process) -> Option<u64> {
    // SAFETY: the caller's promise; only the field is borrowed.
    unsafe { (*p).retired.as_mut() }.and_then(|release| release.collect())
}

/// The stage Space: the first portion takes the space off this CPU's
/// TTBR0 and retires it; its ASID goes, and with it the TLB entries of
/// every CPU, once all CPUs passed a quiescent point, where each leaves the
/// tables (qsbr::quiesce, aspace::leave): no walk of a CPU that kept the
/// tables in TTBR0 may bring an entry back under a number that is issued
/// again. The portions in between give nothing back and requeue; each later
/// one then gives the table `collect_table` named back. True once the root
/// went. Runs inside the caller's section.
///
/// # Safety
/// `p` is alive and on its stages.
unsafe fn release_space(p: *mut Process, table: Option<u64>) -> bool {
    crate::obj::assert_held();
    // SAFETY: the caller's promise; only the fields are borrowed.
    let (space, retired, quota) = unsafe { (&mut (*p).space, &mut (*p).retired, &mut (*p).quota) };
    let Some(release) = retired.as_mut() else {
        let space = space.take().expect("a space at the stage Space");
        let release = retired.insert(space.retire_quiet());
        // With this CPU the only one up, the TTBR0 it just left is the only
        // one that held the tables: no period to wait for.
        if cfg!(feature = "break-asid-retire") || crate::smp::cpus() == 1 {
            release.drop_asid();
        } else {
            // SAFETY: the node is in this process, which stays alive until
            // its stage Space is done, and that waits for `reclaim`.
            unsafe { crate::qsbr::retire(NonNull::from(&mut (*p).space_node), reclaim_asid) };
        }
        return false;
    };
    release.free(table, quota);
    let spent = release.is_spent();
    if spent {
        *retired = None;
    }
    spent
}

/// The period of a retired space passed (qsbr), in a section under `OBJ`:
/// its ASID goes. The portions of the process run on this CPU, between the
/// points where it frees what it retired, so none reads `retired` now.
///
/// # Safety
/// `d` is the `space_node` of a process at its stage Space, which has a
/// `retired` space.
unsafe fn reclaim_asid(d: NonNull<crate::qsbr::Deferred>) {
    let offset = core::mem::offset_of!(Process, space_node);
    // SAFETY: the node is the field of a process that stays alive until its
    // release took the ASID away.
    unsafe {
        let p = d.as_ptr().byte_sub(offset).cast::<Process>();
        (*p).retired
            .as_mut()
            .expect("a retired space waits for its period")
            .drop_asid();
    }
}

/// The stage Buffers: the message buffers of the threads the end stopped
/// go, with the handles of the requests they made and what their long
/// calls held, released at `level` (R, thread::drop_buffer), and the
/// threads leave the list, BUFFERS_PORTION units of work a portion. The
/// ASID went at the stage Space, so the frames go back without unmapping.
/// True once the list is empty. Runs inside the caller's section.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn release_buffers(process: NonNull<Process>, level: u8) -> bool {
    crate::obj::assert_held();
    let mut work = 0;
    // SAFETY: the caller's promise; the threads of the list are alive,
    // since each is either held or queued for cleanup behind this portion,
    // and none waits in a queue any more.
    unsafe {
        while let Some(t) = (*process.as_ptr()).threads {
            let units = FRAME_UNITS + thread::held(t);
            if work + units > BUFFERS_PORTION {
                break;
            }
            work += units;
            thread::drop_buffer(t, level);
            remove_thread(process, t);
        }
        (*process.as_ptr()).threads.is_none()
    }
}

/// The stage Quota: the free part of the quota goes back to the parent
/// (Account::return_free), and nothing is charged to the process from
/// then on; then the process leaves its parent's list of children. The
/// quota of a process with no parent goes nowhere. True: one portion.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn leave_parent(process: NonNull<Process>) -> bool {
    crate::obj::assert_held();
    let p = process.as_ptr();
    // SAFETY: the caller's promise; the parent's object is there, since the
    // process holds its shell, and so are the neighbours in its list.
    unsafe {
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
/// portion. Runs inside the caller's section.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn notify_exit(process: NonNull<Process>, level: u8) -> bool {
    crate::obj::assert_held();
    // SAFETY: the caller's promise; the slot lives as long as the shell,
    // which the channel's queue holds while the slot stands there.
    unsafe {
        let exit = &raw mut (*process.as_ptr()).exit;
        if let Some(e) = (*exit).as_mut() {
            // PEER_CLOSED: nothing is posted (spec 6.5).
            let _ = Source::post(NonNull::from(e), EXIT_BITS, level);
        }
    }
    true
}

/// The stage Shell: takes up to SHELL_PORTION pages of the process's pools
/// and of its page log off the log into `batch`, newest first, for
/// `give_back_pages`. True once none is left. Outside any section: the log
/// and the pages are the shell's own.
///
/// # Safety
/// Nothing refers to the shell: no object lives in its pools.
unsafe fn collect_pages(p: *mut Process, batch: &mut [Option<NonNull<u8>>; SHELL_PORTION]) -> bool {
    // SAFETY: the caller's promise; only the field is borrowed.
    let log = unsafe { &mut (*p).pages };
    let mut n = 0;
    log.release_step(SHELL_PORTION, |page| {
        pages::scrub(page);
        batch[n] = Some(page);
        n += 1;
    })
}

/// Gives the pages `collect_pages` took back to the frame allocator, each
/// refunded to the quota of the shell (spec 7.8), in the caller's section.
///
/// # Safety
/// The pages came from `collect_pages` of this shell, and nothing uses them.
unsafe fn give_back_pages(p: *mut Process, batch: &[Option<NonNull<u8>>; SHELL_PORTION]) {
    // SAFETY: the caller's promise; only the field is borrowed.
    let quota = unsafe { &mut (*p).quota };
    for &page in batch.iter().flatten() {
        // SAFETY: the page came from KernelPages through the pools, and no
        // object lives there any more.
        unsafe { pages::give_back(page) };
        quota.refund(PAGE_SIZE);
    }
}

/// A shell's last portion, once its pages went: the exit channel gets its
/// slot and its reference back (Source::detach), the slot of the shell goes
/// back to the pool it came from, its parent's or ROOTS, the rest of the
/// quota goes to the parent (Account::return_rest: nothing is charged by
/// now, since whatever held the shell went), and then the reference to the
/// parent's shell, which queues that shell at `level` if it was the last.
///
/// # Safety
/// Nothing refers to the shell, its pages went, and it is in no queue.
unsafe fn free(process: NonNull<Process>, level: u8) {
    // SAFETY: the caller's promise; only the fields are touched, and the
    // exit source goes with the shell.
    let (parent, rest) = unsafe {
        let p = process.as_ptr();
        assert!(
            (*p).accepted.is_empty(),
            "a shell goes with requests its threads accepted"
        );
        if let Some(e) = (*p).exit.as_mut() {
            e.detach(level);
        }
        ((*p).parent, (*p).quota.return_rest())
    };
    // SAFETY: the caller's promise; every stage gave its memory back, and
    // the parent's pool is there, since the shell holds the parent's.
    unsafe {
        match parent {
            Some(parent) => paid_free(parent, process),
            None => ROOTS.lock().free(process),
        }
        LIVE.gone(process);
    }
    if let Some(parent) = parent {
        refund(parent, rest);
        // SAFETY: the shell's reference to its parent goes with it.
        unsafe { release_shell(parent, level) };
    }
}

/// The end of `child`, which process_create just made, goes as a
/// notification into `c` (spec 7.9): a source in the child's shell whose
/// slot has `priority` and `label`, the label of the caller's handle, and
/// took one of the channel's slots already (channel::reserve_source). The
/// shell holds the channel until it goes. R, the level of the child's
/// teardown, is at least `priority` from now on (spec 7.7). Nothing can end
/// the child before: it has no thread, and only the caller holds it.
pub fn set_exit(child: NonNull<Process>, c: NonNull<Channel>, label: u64, priority: u8) {
    // SAFETY: the caller holds a reference to the child, which is whole;
    // only the fields are touched.
    unsafe {
        let p = child.as_ptr();
        assert!(
            (*p).stage == Stage::Whole && (*p).exit.is_none(),
            "an exit channel for a process that ended, or has one"
        );
        let exit = (*p).exit.insert(Source::new(c));
        exit.attach(Owner::Exit(child), priority, label);
        (*p).level = (*p).level.max(priority);
    }
}

/// The label of the exit notification of `process`, which receive reports
/// with its slot.
pub fn exit_label(process: NonNull<Process>) -> u64 {
    // SAFETY: the exit slot is being taken, and it holds the shell; only
    // the field is read, and `refs` checks the object.
    unsafe {
        refs(process).check();
        (*process.as_ptr())
            .exit
            .as_ref()
            .expect("an exit slot")
            .label()
    }
}
