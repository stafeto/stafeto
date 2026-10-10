// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Immutable numeric close events retain physical debt through canonical confirmation.

use crate::constants::*;
use posix_fs::closing::{CloseAdmission, CloseToken, OwnerToken};
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
    match target {
        Target::Ram(held) | Target::Random(held) => Some(held),
        _ => None,
    }
}

enum Admission {
    Started(CloseToken, u32),
    Pending(CloseToken),
    Open(posix_fs::open::OpenToken),
    Legacy(u32, Transport, Option<Target>),
    Full,
}

/// Admission and backend selection share one table lock.
pub(crate) fn close(fd: u32) -> Result<(), i32> {
    operation(fd, None).map(|_| ())
}
pub(crate) fn replace(
    source: u32,
    target: u32,
    flags: Option<DescriptorFlags>,
) -> Result<u32, i32> {
    operation(target, Some((source, flags)))
}
fn operation(fd: u32, replacement: Option<(u32, Option<DescriptorFlags>)>) -> Result<u32, i32> {
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
            if !remote {
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
                Ok(CloseAdmission::Started { token, .. }) => Ok(Admission::Started(token, fd)),
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
            Admission::Started(token, number) => {
                // Only this admitted continuation may infer success after an exact
                // helper retires the confirmed record, including a delayed reply.
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
                    return Err(EMFILE);
                }
            }
        }
    }
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
        Ok(files
            .close_snapshot(token)
            .ok()
            .map(|snapshot| (files.transport(), snapshot)))
    })?;
    let Some((transport, snapshot)) = state else {
        return Ok(true);
    };
    if !snapshot.complete {
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
        let receipt = transport.files().close_event_once(event);
        #[cfg(feature = "close-probe")]
        let mut receipt = receipt;
        #[cfg(feature = "close-probe")]
        if probed(Probe::Event, token) && receipt.is_ok() {
            receipt = Err(Status::Kernel(rt::abi::Error::Interrupted));
        }
        let confirmed = crate::shared::with_files(|files| {
            // A concurrent helper can retire this exact generation during send.
            let Ok(current) = files.close_snapshot(token) else {
                return Ok(true);
            };
            if current.complete {
                return Ok(false);
            }
            match receipt {
                Ok(()) => {
                    files.finish_close_record(token).map_err(crate::error)?;
                    Ok(false)
                }
                Err(Status::BadSize | Status::Kernel(rt::abi::Error::Interrupted)) => Ok(false),
                Err(error) => Err(protocol(error)),
            }
        })?;
        return Ok(confirmed);
    }
    if let Some(target) = snapshot.release {
        let held = ram(target).ok_or(EIO)?;
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
    let address = crate::shared::with_files(|files| {
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
        Ok(Some(address))
    })?;
    if let Some(address) = address {
        posix_sync::futex_wake(address as *const core::sync::atomic::AtomicU32, u32::MAX);
        crate::change::wake_places();
    }
    Ok(true)
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
