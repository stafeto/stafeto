// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The teardown of a process (spec 7.7, 7.9): its stages, a portion at a
//! time with how far it came kept in the process, and the notification
//! of its end to its exit channel.

use super::table::table;
use super::*;
use crate::syscall;

/// Pages a portion of the stage Shell gives back, at most (spec 7.7).
const SHELL_PORTION: usize = 64;

/// Clients of one level a portion of the stage Replies wakes, at most
/// (spec 7.7).
const REPLIES_PORTION: usize = 32;

/// The work a portion of the stage Buffers does, at most (spec 7.7): the
/// buffer of each thread is a unit, and each handle of a request it made
/// and the long call it was making one more; the thread that reaches it is
/// the portion's last. The buffers of abi::MAX_THREADS threads with no
/// handles take one portion.
const BUFFERS_PORTION: usize = 64;

/// The bits of an exit notification (spec 6.5, 7.9): bit 0, once.
const EXIT_BITS: u64 = 1;

/// Where the teardown of a process stands (spec 7.7). A process is whole
/// until it ends; then the cleanup queue holds it, with a reference of its
/// own, and each portion takes one step of its stage, in the order of
/// STAGES, with how far it came kept in the process. Stop, Replies,
/// Children, Handles, Space and Shell take as many portions as their
/// steps; the others one. The stage Stop runs at S, the higher of the
/// process's ceiling and R (`level`); Replies at the higher of R and its
/// top client; the others at R, but for Shell, which runs at the level of
/// the last reference. After the stage Notify the queue lets its reference
/// go.
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
    /// A chunk of the handle table a portion, up to 64 handles, each
    /// releasing its object; the chunk directory with the last chunk
    /// (HandleTable::release_step).
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
    /// (maps::release_all). One portion. After Space, so that no TLB entry
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
const STAGES: [Stage; 10] = [
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

/// The stage after `stage`, which is one of STAGES but the last.
fn after(stage: Stage) -> Stage {
    let i = STAGES
        .iter()
        .position(|&s| s == stage)
        .expect("a stage of a teardown");
    STAGES[i + 1]
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
/// own and queues the process for its first stage: Stop at S for a
/// process with children, Replies otherwise (`stage_level`). It takes the
/// scheduler's lock.
///
/// # Safety
/// `process` is alive, whole, and in no queue.
pub(super) unsafe fn begin(process: NonNull<Process>, cause: u8) {
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
            Stage::Replies
        };
        // The queue's own reference. `retain` refuses a count of 0, which
        // it is when the last reference ended the process (`release`).
        refs(process).take();
        let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
        cleanup::enqueue(item, Object::Process(process), stage_level(process));
    }
}

/// The level the stage of `process` runs at (spec 7.7): S, the higher of
/// its ceiling and R, at the stage Stop; the higher of R and the top level
/// of its accepted requests at the stage Replies, read under the
/// scheduler's lock; R at the others. O(1).
///
/// # Safety
/// `process` is alive; only the fields are read.
unsafe fn stage_level(process: NonNull<Process>) -> u8 {
    let p = process.as_ptr();
    // SAFETY: the caller's promise.
    unsafe {
        match (*p).stage {
            Stage::Stop => (*p).ceiling.max((*p).level),
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
/// (spec 7.7). Nothing at other stages. It takes the scheduler's lock.
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
    // SAFETY: the caller's promise; only the fields are read.
    let (stage, r) = unsafe { ((*p).stage, (*p).level) };
    // The child that goes in front of the process at the stage Children.
    let mut first = None;
    let done = match stage {
        Stage::Whole => unreachable!("a whole process in the cleanup queue"),
        // SAFETY: the process is alive, and its children in the list too.
        Stage::Stop => unsafe { stop_child(process, r) },
        // SAFETY: the process is alive; its clients wait.
        Stage::Replies => unsafe { wake_clients(process, level) },
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
        Stage::Buffers => unsafe { release_buffers(process, r) },
        // SAFETY: as above.
        Stage::Mappings => unsafe { super::maps::release_all(process, r) },
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
            cleanup::requeue(item, Object::Process(process), stage_level(process));
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

/// The stage Replies, taken at `level`: up to REPLIES_PORTION clients at
/// the top level of the queue of accepted requests of `process` leave it,
/// each woken with PEER_CLOSED in x0 alone at the tail of its level with a
/// new quantum (spec 6.8), under one hold of the scheduler's lock. True
/// once the queue is empty; a process that took no request passes at once.
///
/// # Safety
/// `process` is alive and at its stage Replies.
unsafe fn wake_clients(process: NonNull<Process>, level: u8) -> bool {
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
                k.s.wake(t);
                heads += 1;
            }
            Some((heads, !accepted(process, k.s).is_empty()))
        }
    });
    let Some((heads, left)) = taken else {
        return true;
    };
    crate::testpoint::heads_taken(level, heads);
    !left
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
/// go, with the handles of the requests they made and what their long
/// calls held, released at `level` (R), and the threads leave the list,
/// BUFFERS_PORTION units of work a portion. The ASID went at the stage
/// Space, so the frames go back without unmapping. True once the list is
/// empty.
///
/// # Safety
/// `process` is alive and on its stages.
unsafe fn release_buffers(process: NonNull<Process>, level: u8) -> bool {
    let mut work = 0;
    // SAFETY: the caller's promise; the threads of the list are alive,
    // since each is either held or queued for cleanup behind this portion,
    // and none waits in a queue any more.
    unsafe {
        while work < BUFFERS_PORTION
            && let Some(t) = (*process.as_ptr()).threads
        {
            work += 1 + thread::drop_transit(t, level) + thread::drop_long(t, level);
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
        assert!(
            (*p).accepted.is_empty(),
            "a shell goes with requests its threads accepted"
        );
        ((*p).parent, (*p).quota.return_rest(), exit)
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
        refs(process).check();
        (*process.as_ptr())
            .exit
            .as_ref()
            .expect("an exit slot")
            .label
    }
}
