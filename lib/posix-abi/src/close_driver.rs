// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Immutable numeric close events retain physical debt through canonical confirmation.

use crate::constants::*;
use posix_fs::closing::{Asked, CloseAdmission, CloseCommandFence, CloseToken, OwnerToken};
use posix_fs::{DescriptorFlags, FsError, Target, Transport};
use proto_wire::Status;

#[cfg(feature = "close-probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    Event,
    Physical,
}
#[cfg(feature = "close-probe")]
static HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "close-probe")]
pub fn probe_hook(hook: Option<fn(Probe, CloseToken) -> bool>) {
    HOOK.store(
        hook.map_or(0, |hook| hook as usize),
        core::sync::atomic::Ordering::Release,
    );
}
#[cfg(feature = "close-probe")]
fn probed(phase: Probe, token: CloseToken) -> bool {
    let raw = HOOK.load(core::sync::atomic::Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: probe_hook stores only this function-pointer type.
    let hook: fn(Probe, CloseToken) -> bool = unsafe { core::mem::transmute(raw) };
    hook(phase, token)
}

fn protocol(status: Status) -> i32 {
    if status == Status::BadSize {
        EIO
    } else {
        crate::error(FsError::from(status))
    }
}
fn ram(target: Target) -> Option<posix_fs::RamTarget> {
    target.ram_target()
}

enum Admission {
    /// The record this call started, its snapshot and fence read under the
    /// admitting lock: the first turn needs no second look.
    Started(
        CloseToken,
        u32,
        Transport,
        posix_fs::closing::Snapshot,
        Option<CloseCommandFence>,
        Asked,
    ),
    Pending(CloseToken),
    Open(posix_fs::open::OpenToken),
    Legacy(u32, Transport, Option<Target>),
    Full,
}

/// Admission and backend selection share one table lock.
pub(crate) fn close(fd: u32) -> Result<(), i32> {
    operation(fd, None, false).map(|_| ())
}
pub(crate) fn replace(
    source: u32,
    target: u32,
    flags: Option<DescriptorFlags>,
) -> Result<u32, i32> {
    operation(target, Some((source, flags)), false)
}
/// An implementation-owned descriptor must publish cleanup before its caller
/// releases signal deferral. Retry only Full, never a post-admission error.
pub(crate) fn close_owned(fd: u32) -> Result<(), i32> {
    operation(fd, None, true).map(|_| ())
}
fn operation(
    fd: u32,
    replacement: Option<(u32, Option<DescriptorFlags>)>,
    wait_for_admission: bool,
) -> Result<u32, i32> {
    let owner = crate::relibc::open_owner()
        .ok()
        .and_then(|owner| OwnerToken::new(owner).ok());
    let frame = crate::change::frame();
    loop {
        let step = crate::shared::with_files(|files| {
            for number in [replacement.map_or(fd, |(source, _)| source), fd] {
                if let Some(token) = files.closing(number) {
                    return Ok(Admission::Pending(token));
                }
                if let Some(token) = files.pending_open(number) {
                    return Ok(Admission::Open(token));
                }
            }
            let backend = files.target(fd);
            let remote = backend.is_ok_and(|target| ram(target).is_some());
            // The close of an alias of a description holds nothing physical
            // and owes the service only the release of record locks: with
            // none held, it is as local as the close of a pipe.
            let local =
                !remote || (replacement.is_none() && files.closes_alias_with_no_record_lock(fd));
            if local {
                let (number, release) = match replacement {
                    Some((source, flags)) => match files
                        .try_take_dup3(source, fd, flags)
                        .map_err(crate::error)?
                    {
                        posix_fs::open::Replacement::Complete { fd, release } => (fd, release),
                        posix_fs::open::Replacement::Pending(token) => {
                            return Ok(Admission::Open(token));
                        }
                    },
                    None => (fd, files.take_close(fd).map_err(crate::error)?),
                };
                return Ok(Admission::Legacy(number, files.transport(), release));
            }
            let result = match replacement {
                Some((source, flags)) => {
                    files.begin_replace_record(owner, source, fd, flags, frame)
                }
                None => files.begin_close_record(owner, fd, frame),
            };
            match result {
                Ok(CloseAdmission::Started { token, snapshot }) => {
                    let fence = files.close_command_fence(token).map_err(crate::error)?;
                    Ok(Admission::Started(
                        token,
                        fd,
                        files.transport(),
                        snapshot,
                        fence,
                        files.record_locks_question(),
                    ))
                }
                Ok(CloseAdmission::PendingClose(token)) => Ok(Admission::Pending(token)),
                Ok(CloseAdmission::PendingOpen(token)) => Ok(Admission::Open(token)),
                Ok(CloseAdmission::Replaced(number)) => {
                    Ok(Admission::Legacy(number, files.transport(), None))
                }
                Err(FsError::TooManyOpenFiles) => Ok(Admission::Full),
                Err(error) => Err(crate::error(error)),
            }
        })?;
        match step {
            Admission::Started(token, number, transport, snapshot, fence, asked) => {
                // Only this admitted continuation may infer success after an exact
                // helper retires the confirmed record, including a delayed reply.
                if first_turn(token, transport, snapshot, fence, asked)? {
                    return Ok(number);
                }
                drive(token)?;
                return Ok(number);
            }
            Admission::Pending(token) => drive(token)?,
            Admission::Open(token) => crate::open_driver::wait_pending(token)?,
            Admission::Legacy(number, transport, release) => {
                transport.release(release).map_err(crate::error)?;
                return Ok(number);
            }
            Admission::Full => {
                if !help_once() {
                    if !wait_for_admission {
                        return Err(EMFILE);
                    }
                    let _ = rt::sys::yield_now();
                }
            }
        }
    }
}

/// One unlocked helper turn on the lock debt that fences the record.
fn fence_turn(debt: CloseCommandFence) -> Result<(), i32> {
    match debt {
        CloseCommandFence::Control(token) => crate::lock_driver::cleanup_step(token).map(drop),
        CloseCommandFence::Wait(token) => crate::wait_lock_driver::cleanup_step(token).map(drop),
    }
}

/// The first turn of the record this call admitted, from the state the
/// admission read: Ok(true) when the record is retired.
fn first_turn(
    token: CloseToken,
    transport: Transport,
    snapshot: posix_fs::closing::Snapshot,
    fence: Option<CloseCommandFence>,
    asked: Asked,
) -> Result<bool, i32> {
    if let Some(debt) = fence {
        fence_turn(debt)?;
        return Ok(false);
    }
    if snapshot.complete {
        return Ok(false);
    }
    event_step(token, transport, snapshot, Some(asked))
}

fn drive(token: CloseToken) -> Result<(), i32> {
    loop {
        match step(token) {
            Ok(true) => return Ok(()),
            Ok(false) | Err(EINTR) => {}
            Err(error) => return Err(error),
        }
    }
}

/// One canonical request or one local retirement; every RPC occurs unlocked.
fn step(token: CloseToken) -> Result<bool, i32> {
    let state = crate::shared::with_files(|files| {
        let Ok(snapshot) = files.close_snapshot(token) else {
            return Ok(None);
        };
        let fence = files.close_command_fence(token).map_err(crate::error)?;
        Ok(Some((files.transport(), snapshot, fence)))
    })?;
    let Some((transport, snapshot, fence)) = state else {
        return Ok(true);
    };
    if let Some(debt) = fence {
        fence_turn(debt)?;
        return Ok(false);
    }
    if !snapshot.complete {
        return event_step(token, transport, snapshot, None);
    }
    if let Some(target) = snapshot.release {
        let held = ram(target).ok_or(EIO)?;
        if let Target::Fifo(pair) = target {
            match transport.pipe_endpoint_call(proto_pipe::Method::Close, pair.endpoint(), None) {
                Ok(_) | Err(FsError::BadFileDescriptor) => {}
                Err(FsError::Interrupted) => return Ok(false),
                Err(error) => return Err(crate::error(error)),
            }
        }
        let receipt = transport.files().close_exact(held.prepared());
        #[cfg(feature = "close-probe")]
        let mut receipt = receipt;
        #[cfg(feature = "close-probe")]
        if probed(Probe::Physical, token) && receipt.is_ok() {
            receipt = Err(Status::Kernel(rt::abi::Error::Interrupted));
        }
        return crate::shared::with_files(|files| {
            let Ok(current) = files.close_snapshot(token) else {
                return Ok(true);
            };
            if current.release.is_none() {
                return Ok(false);
            }
            match receipt {
                Ok(_) => {
                    files
                        .finish_close_release(token, target)
                        .map_err(crate::error)?;
                    Ok(false)
                }
                Err(Status::BadSize | Status::Kernel(rt::abi::Error::Interrupted)) => Ok(false),
                Err(error) => Err(protocol(error)),
            }
        });
    }
    let addresses = crate::shared::with_files(|files| retire(files, token))?;
    if let Some(addresses) = addresses {
        wake(addresses);
    }
    Ok(true)
}

/// Acknowledges a confirmed record that holds nothing physical, under the
/// lock: the addresses its waiters and the waiters for a place of a job
/// sleep on, or None when the record is gone or still owes its release.
fn retire(files: &mut posix_fs::PosixFs, token: CloseToken) -> Result<Option<[usize; 2]>, i32> {
    let Ok(current) = files.close_snapshot(token) else {
        return Ok(None);
    };
    if !current.complete || current.release.is_some() {
        return Ok(None);
    }
    let address = files.close_wait_address(token).map_err(crate::error)?;
    files
        .ack_close_record(token, current.owner)
        .map_err(crate::error)?;
    Ok(Some([address, files.jobs_wait_address()]))
}

/// Wakes both sets of waiters with no further look at the files: with no
/// waiter neither wake calls the kernel.
fn wake(addresses: [usize; 2]) {
    for address in addresses {
        posix_sync::futex_wake(address as *const core::sync::atomic::AtomicU32, u32::MAX);
    }
}

// Keep the event request storage out of Lock cleanup and physical release.
#[inline(never)]
fn event_step(
    token: CloseToken,
    transport: Transport,
    snapshot: posix_fs::closing::Snapshot,
    asked: Option<Asked>,
) -> Result<bool, i32> {
    let held = ram(snapshot.backend).ok_or(EIO)?;
    let event = proto_fs::CloseEvent {
        key: proto_fs::CloseKey {
            slot: token.slot() as u32,
            generation: token.generation(),
        },
        packed: held.prepared().marked_fd(),
        description_generation: held.generation(),
        last_alias: snapshot.last_alias,
    };
    let answer = transport.files().close_event_answer(event);
    let none = matches!(answer, Ok(true));
    let receipt = answer.map(drop);
    #[cfg(feature = "close-probe")]
    let mut receipt = receipt;
    #[cfg(feature = "close-probe")]
    if probed(Probe::Event, token) && receipt.is_ok() {
        receipt = Err(Status::Kernel(rt::abi::Error::Interrupted));
    }
    // The record that holds nothing physical is acknowledged under the same
    // lock that confirms the event.
    let (done, addresses) = crate::shared::with_files(|files| {
        // A concurrent helper can retire this exact generation during send.
        let Ok(current) = files.close_snapshot(token) else {
            return Ok((true, None));
        };
        if current.complete {
            return Ok((false, None));
        }
        match receipt {
            Ok(()) => {
                files.finish_close_record(token).map_err(crate::error)?;
                // No lock command is outstanding at the answer, and none began
                // since the question: the process holds no record lock.
                if none && let Some(asked) = asked {
                    files.record_locks_answered_none(asked);
                }
                match retire(files, token)? {
                    Some(addresses) => Ok((true, Some(addresses))),
                    None => Ok((false, None)),
                }
            }
            Err(Status::BadSize | Status::Kernel(rt::abi::Error::Interrupted)) => Ok((false, None)),
            Err(error) => Err(protocol(error)),
        }
    })?;
    if let Some(addresses) = addresses {
        wake(addresses);
    }
    Ok(done)
}

fn help_once() -> bool {
    let token = crate::shared::try_with_files(|files| {
        static CURSOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
        let cursor = CURSOR.load(core::sync::atomic::Ordering::Relaxed);
        let token = files
            .close_tokens()
            .min_by_key(|token| (token.slot() + 16 - cursor) % 16);
        if let Some(token) = token {
            CURSOR.store(
                (token.slot() + 1) % 16,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(token)
    })
    .ok()
    .flatten();
    if let Some(token) = token {
        let _ = step(token);
        true
    } else {
        false
    }
}
pub(crate) fn help() {
    let _ = help_once();
}

pub(crate) fn detach(owner: u64) -> bool {
    let Ok(owner) = OwnerToken::new(owner) else {
        return false;
    };
    crate::shared::try_with_files(|files| {
        while files.abandon_close_owner(owner).is_some() {}
        Ok(true)
    })
    .unwrap_or(false)
}

/// A competing descriptor operation completes the exact frozen event first.
pub(crate) fn settle_token(token: CloseToken) -> Result<(), i32> {
    drive(token)
}
pub(crate) fn settle_all() -> Result<(), i32> {
    loop {
        let token = crate::shared::with_files(|files| Ok(files.close_tokens().next()))?;
        let Some(token) = token else {
            return Ok(());
        };
        drive(token)?;
    }
}
