// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the Change jobs of the file service: one operation on a name
//! or on metadata from its place in the table to the Release of its job.
//!
//! The paid record of the operation (a Control record of the descriptor table)
//! stands for one of the sixteen jobs a session may keep in the service, and
//! its token names the key of the job. The record holds the frame where the
//! operation began. A thread that leaves the operation by a long jump from a
//! handler leaves the record in work; the next operation of that thread finds
//! that its own record's frame does not contain the frame it runs in, and
//! sends the Release. The service keeps the effect at most once by the key
//! whatever the collector does: a record taken for left by mistake costs an
//! EIO to the operation that is still alive, or a place held longer, and
//! never a second effect.

use crate::constants::*;
use core::mem::ManuallyDrop;
use core::sync::atomic::AtomicU32;
use entries::Frame;
use posix_change::{Failure, Wire};
use posix_fs::change::{
    ControlClaimToken, ControlResult, ControlToken, JOBS_MAX, JobPlace, OwnerToken,
};
use posix_fs::{FsError, PosixFs};
use proto_fs::{Base, ChangeDone, ChangeOp, ChangePhase, ChangeStart, OpenKey, RESULT_MAX};
use proto_wire::Status;
use rt::fs::Files;

/// One operation: the first path, with the base it starts from, and for the
/// operations with a second path (Rename, Link) or contents (Symlink) the
/// second.
pub struct Request<'a> {
    pub op: ChangeOp,
    pub flags: u32,
    pub base: Base,
    pub args: [u64; 4],
    pub path: &'a [u8],
    pub second: Option<(Base, &'a [u8])>,
}

/// What a finished operation gives: the value and how many bytes of the
/// result lie in the buffer the caller supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub value: u64,
    pub length: usize,
}

/// The range of the alternate signal stack of the calling thread. It is empty
/// while `sigaltstack` answers ENOSYS, so `z` is 0 for every frame and the
/// order of the frames is that of the main stack. The call that fills the
/// range (5g or 5h) adds the probe of a handler on the alternate stack that
/// calls `unlink` in the middle of a long `rename` of the main thread.
fn alternate_stack() -> Option<(u64, u64)> {
    None
}

/// The frame of the caller, as the position of its stack pointer.
#[inline(always)]
fn here() -> Frame {
    let sp: u64;
    // SAFETY: reads the stack pointer, and nothing else.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    let z = match alternate_stack() {
        Some((low, high)) if (low..high).contains(&sp) => 1,
        _ => 0,
    };
    Frame { z, sp }
}

fn errno_of(status: Status) -> i32 {
    crate::error(FsError::from(status))
}

/// The errno of the code an operation finished with.
fn errno_of_result(code: u32) -> i32 {
    match code {
        proto_fs::JOBS_FULL | proto_fs::STALE_PROOF | proto_fs::RESOLVING => EIO,
        code => errno_of(Status::Unknown(code)),
    }
}

/// The requests a probe hook sees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    Start,
    Second,
    Step,
}

/// The hook of the probes, called after each request of an operation was
/// answered. It answers true to lose the reply: the loop sees an interrupted
/// send, as if the request had been taken off the queue, and sends it again.
#[cfg(feature = "change-probe")]
static HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Sets the hook (None for none): a probe forks, or loses a reply, in the
/// middle of an operation with it.
#[cfg(feature = "change-probe")]
pub fn probe_hook(hook: Option<fn(Probe) -> bool>) {
    HOOK.store(
        hook.map_or(0, |hook| hook as usize),
        core::sync::atomic::Ordering::Release,
    );
}

/// The reply of the request stands as it came, or is lost.
#[cfg(feature = "change-probe")]
fn probe<T>(kind: Probe, reply: Result<T, Status>) -> Result<T, Status> {
    let hook = HOOK.load(core::sync::atomic::Ordering::Acquire);
    if hook == 0 {
        return reply;
    }
    // SAFETY: only `probe_hook` stores a value, a `fn(Probe) -> bool`.
    let hook: fn(Probe) -> bool = unsafe { core::mem::transmute::<usize, fn(Probe) -> bool>(hook) };
    if hook(kind) {
        return Err(Status::Kernel(rt::abi::Error::Interrupted));
    }
    reply
}

#[cfg(not(feature = "change-probe"))]
#[inline(always)]
fn probe<T>(_: Probe, reply: Result<T, Status>) -> Result<T, Status> {
    reply
}

/// The requests of one operation, sent to the session of the process.
struct Live {
    files: ManuallyDrop<Files>,
    /// The thread whose operation sends; None for a helper that only releases.
    owner: Option<OwnerToken>,
    token: ControlToken,
    /// None for a collector that only releases.
    claim: Option<ControlClaimToken>,
    here: Frame,
}

impl Wire for Live {
    fn live(&mut self) -> bool {
        let Some(claim) = self.claim else {
            return true;
        };
        crate::shared::with_files(|files| Ok(files.change_is_live(claim))).unwrap_or(false)
    }
    fn start(&mut self, start: &ChangeStart<'_>) -> Result<ChangePhase, Status> {
        probe(Probe::Start, self.files.change_start_once(start))
    }
    fn second(&mut self, key: OpenKey, base: Base, bytes: &[u8]) -> Result<(), Status> {
        probe(
            Probe::Second,
            self.files.change_second_once(key, base, bytes),
        )
    }
    fn step(
        &mut self,
        key: OpenKey,
        out: &mut [u8; RESULT_MAX],
    ) -> Result<Option<ChangeDone>, Status> {
        probe(Probe::Step, self.files.change_step_once(key, out))
    }
    fn release(&mut self, key: OpenKey) -> Result<(), Status> {
        self.files.change_release_once(key)
    }
    fn authenticate(&mut self) -> Result<(), Status> {
        self.files.finish_binding()
    }
    fn wait_for_room(&mut self) {
        // What this process left behind may be what fills the table.
        collect(self.owner, self.here, Some(self.token), true);
        // One millisecond on the timer of the thread, outside the deferral
        // of signals: a handler that runs ends the sleep, the request goes
        // again either way. A spin without a sleep would starve the holder
        // of the place when it runs on this processor at a lower level.
        let _ = crate::threads::sleep::pause(1_000_000);
    }
}

fn key_of(token: ControlToken) -> OpenKey {
    OpenKey {
        slot: token.slot() as u32,
        generation: token.generation(),
    }
}

/// Wakes the threads that wait for a place of a job.
pub fn wake_places() {
    let address = crate::shared::with_files(|files| Ok(files.jobs_wait_address()));
    if let Ok(address) = address {
        posix_sync::futex_wake(address as *const AtomicU32, u32::MAX);
    }
}

/// Takes a place of a job for `begin`, which runs under the same hold of the
/// lock as the check. A thread that finds all sixteen places held by its own
/// operations answers EAGAIN: it waits for itself (the nested handlers of one
/// thread each hold one), and no other thread can free a place. Otherwise it
/// collects what it left behind, and waits on the word of the places.
pub(crate) fn take_place<R>(
    owner: OwnerToken,
    here: Frame,
    begin: impl Fn(&mut PosixFs) -> Result<R, FsError>,
) -> Result<R, i32> {
    enum Step<R> {
        Taken(R),
        Wait(usize, u32),
    }
    loop {
        collect(Some(owner), here, None, true);
        let step = crate::shared::with_files(|files| match files.job_place(owner) {
            JobPlace::Free => begin(files).map(Step::Taken).map_err(crate::error),
            JobPlace::Full { own: true, .. } => Err(EAGAIN),
            JobPlace::Full { sequence, .. } => Ok(Step::Wait(files.jobs_wait_address(), sequence)),
        })?;
        match step {
            Step::Taken(taken) => return Ok(taken),
            Step::Wait(address, sequence) => {
                // SAFETY: the table lives in the pinned state of the layer.
                let word = unsafe { &*(address as *const AtomicU32) };
                // The word moves when a place goes; a millisecond bounds the
                // wait for a wake that raced with this check.
                let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(1_000_000);
                let _ = posix_sync::futex_wait(
                    word,
                    sequence,
                    crate::clock::CLOCK_MONOTONIC as u32,
                    Some(deadline),
                );
            }
        }
    }
}

/// Releases the jobs of the records that no operation owns any more: those of
/// `me` whose frame does not contain `current`, and those of threads that
/// ended. `skip` is the record of the operation that collects. `blocking`
/// takes the lock of the files, otherwise a busy lock leaves the work to the
/// next call.
pub(crate) fn collect(
    me: Option<OwnerToken>,
    current: Frame,
    skip: Option<ControlToken>,
    blocking: bool,
) {
    let mut freed = false;
    for _ in 0..JOBS_MAX {
        let find = |files: &mut PosixFs| {
            let picked = posix_change::pick_abandoned(
                me,
                current,
                skip,
                files
                    .change_tokens()
                    .filter_map(|token| Some((token, files.change_snapshot(token).ok()?))),
            );
            let Some((token, mine)) = picked else {
                return Ok(None);
            };
            // The debt is the Release; the authority over the job goes.
            files.begin_change_cleanup(token).map_err(crate::error)?;
            Ok(Some((token, mine, files.transport())))
        };
        let found = if blocking {
            crate::shared::with_files(find)
        } else {
            crate::shared::try_with_files(find)
        };
        let Ok(Some((token, mine, transport))) = found else {
            break;
        };
        let mut wire = Live {
            files: transport.files(),
            owner: me,
            token,
            claim: None,
            here: current,
        };
        posix_change::release(&mut wire, key_of(token));
        let _ = crate::shared::with_files(|files| {
            files.finish_change_cleanup(token).map_err(crate::error)?;
            if let (true, Some(owner)) = (mine, me) {
                files
                    .ack_change_record(token, owner)
                    .map_err(crate::error)?;
            }
            Ok(())
        });
        freed = true;
    }
    if freed {
        wake_places();
    }
}

/// The lifetime of the thread `owner` ended: its records lose the owner and
/// wait for whoever collects (`help`). False when the lock of the files is
/// busy; the caller asks again.
pub(crate) fn detach(owner: u64) -> bool {
    let Ok(owner) = OwnerToken::new(owner) else {
        return false;
    };
    crate::shared::try_with_files(|files| {
        while files.abandon_change_owner(owner).is_some() {}
        Ok(())
    })
    .is_ok()
}

/// One pass over the records without an owner: a surviving thread or the
/// collector of the threads pays their Release.
pub(crate) fn help() {
    collect(None, Frame::main(0), None, false);
}

/// The frame of the caller for an operation that takes a place: the same
/// position the collector compares against.
#[inline(always)]
pub(crate) fn frame() -> Frame {
    here()
}

/// Runs one operation to its end and releases its job. The bytes of the
/// result of ReadLink, StatVfs and Path go to `out`.
///
/// Errors: the errno of the operation, EAGAIN when the thread waits for itself
/// for a place, EIO for a retired key, a job that vanished, or a record that
/// went with a `fork`.
#[inline(never)]
pub fn run(request: &Request<'_>, out: &mut [u8; RESULT_MAX]) -> Result<Outcome, i32> {
    let here = here();
    let owner = OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)?;
    let (token, claim) = take_place(owner, here, |files| files.begin_change_record(owner, here))?;
    let transport = crate::shared::with_files(|files| Ok(files.transport()))?;
    let key = key_of(token);
    let start = ChangeStart {
        key,
        op: request.op,
        flags: request.flags,
        base: request.base,
        args: request.args,
        path: request.path,
    };
    let mut wire = Live {
        files: transport.files(),
        owner: Some(owner),
        token,
        claim: Some(claim),
        here,
    };
    let driven = posix_change::drive(&mut wire, &start, request.second, out);
    let result = match driven {
        Ok(done) if done.result == 0 => Ok(Outcome {
            value: done.value,
            length: done.length,
        }),
        Ok(done) => Err(errno_of_result(done.result)),
        Err(Failure::Io) => Err(EIO),
        Err(Failure::Status(status)) => Err(errno_of(status)),
    };
    // The outcome is saved before the Release, so that a collector that frees
    // the place keeps it. A record that is gone is the child of a `fork`: the
    // parent owns the job, and the child sends nothing.
    let saved = match result {
        Ok(outcome) => ControlResult::Value(outcome.value),
        Err(errno) => ControlResult::Failed(errno),
    };
    let revoked = crate::shared::with_files(|files| {
        files
            .complete_change_record(claim, saved)
            .map_err(crate::error)?;
        files.begin_change_cleanup(token).map_err(crate::error)?;
        Ok(())
    });
    if revoked.is_err() {
        wake_places();
        return Err(EIO);
    }
    posix_change::release(&mut wire, key);
    let _ = crate::shared::with_files(|files| {
        files.finish_change_cleanup(token).map_err(crate::error)?;
        files
            .ack_change_record(token, owner)
            .map_err(crate::error)?;
        Ok(())
    });
    wake_places();
    result
}
