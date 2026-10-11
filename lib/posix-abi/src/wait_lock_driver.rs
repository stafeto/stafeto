// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid private channels and canonical WAIT receipts; public activation is separate.

use crate::constants::{EBADF, EDEADLK, EINTR, EIO, ENOLCK};
use ::core::sync::atomic::Ordering;
use posix_fs::wait::{
    Input, OwnerToken, Snapshot, TerminalReply, WaitCancelReason, WaitClaim, WaitPlace,
    WaitRecordPhase, WaitResult, WaitToken,
};
use posix_fs::{FsError, Transport};
use proto_fs::{Method, WaitKey, WaitReply};
use proto_wire::Status;
use rt::abi::{Call, Error, Rights, Source};
use rt::handle::{Channel, Handle};
use rt::sys;

mod core;
mod packet;
mod raw_channel;
use core::{Failure, Phase, Reason, Session, State};

#[cfg(feature = "wait-probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    Start,
    Arm,
    Query,
    Complete,
    Receive,
    Cancel,
    Release,
    CloseChannel,
}
#[cfg(feature = "wait-probe")]
static PROBE: ::core::sync::atomic::AtomicUsize = ::core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "wait-probe")]
pub fn probe_hook(hook: Option<fn(Probe, WaitToken) -> bool>) {
    PROBE.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}
#[cfg(feature = "wait-probe")]
fn probed(phase: Probe, token: WaitToken) -> bool {
    let raw = PROBE.load(Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: probe_hook stores only functions with this exact signature.
    let hook: fn(Probe, WaitToken) -> bool = unsafe { ::core::mem::transmute(raw) };
    hook(phase, token)
}

fn failure(error: Status) -> Failure {
    match error {
        Status::Kernel(Error::Interrupted) => Failure::Interrupted,
        Status::Unknown(proto_fs::JOBS_FULL) => Failure::Room,
        Status::Unknown(proto_fs::AUTHENTICATING) => Failure::Authenticating,
        Status::Unknown(proto_fs::RESOLVING) => Failure::Resolving,
        Status::Unknown(proto_fs::OPEN_RETIRED) => Failure::Retired,
        Status::Unknown(code) => Failure::Rejected(code),
        error => Failure::Fatal(crate::error(error.into())),
    }
}
fn kernel(error: Error) -> Failure {
    if error == Error::BadHandle {
        Failure::Retired
    } else {
        failure(Status::Kernel(error))
    }
}

struct OuterRestart(u32);
impl OuterRestart {
    fn enter() -> Self {
        Self(
            crate::threads::own_block()
                .flags
                .fetch_and(!posix_thread::flag::NO_RESTART, Ordering::SeqCst)
                & posix_thread::flag::NO_RESTART,
        )
    }
}
impl Drop for OuterRestart {
    fn drop(&mut self) {
        crate::threads::own_block()
            .flags
            .fetch_or(self.0, Ordering::SeqCst);
    }
}
fn ending() -> bool {
    crate::threads::own_block().flags.load(Ordering::SeqCst) & posix_thread::flag::NO_RESTART != 0
}
struct Live {
    token: WaitToken,
    claim: Option<WaitClaim>,
    owner: Option<OwnerToken>,
    transport: Transport,
    room_repeats: u32,
}
impl Live {
    fn snapshot(&self) -> Result<Option<Snapshot>, i32> {
        crate::shared::with_files(|files| match files.wait_snapshot(self.token) {
            Ok(s) if self.owner.is_none() || s.owner == self.owner => Ok(Some(s)),
            Ok(_) | Err(FsError::BadFileDescriptor) => Ok(None),
            Err(e) => Err(crate::error(e)),
        })
    }
    fn key(&self) -> WaitKey {
        WaitKey {
            slot: self.token.slot() as u32,
            generation: self.token.generation(),
        }
    }
    fn inline(response: sys::Reply) -> Result<([u8; 64], usize), Failure> {
        if !response.handles.is_empty() || response.len > rt::abi::INLINE_MAX {
            return Err(Failure::Fatal(EIO));
        }
        let bytes = rt::abi::inline_bytes(&response.words);
        Ok((bytes, response.len))
    }
    fn call(&self, p: &packet::Packet) -> Result<WaitReply, Failure> {
        // Any unexpected owned reply handles are destroyed before a handler can jump.
        let reply = {
            let _scope = rt::upcall::defer_entries().map_err(kernel)?;
            let response =
                sys::send(self.transport.files().sessions().0, p.as_bytes()).map_err(kernel)?;
            let (bytes, len) = Self::inline(response)?;
            packet::reply(&bytes[..len]).map_err(failure)?
        };
        #[cfg(feature = "wait-probe")]
        {
            let method = u16::from_le_bytes([p.as_bytes()[0], p.as_bytes()[1]]);
            let phase = if method == Method::WaitStart as u16 {
                Probe::Start
            } else if method == Method::WaitCancel as u16 {
                Probe::Cancel
            } else {
                Probe::Query
            };
            if probed(phase, self.token)
                || (reply.phase == proto_fs::WaitPhase::Complete
                    && probed(Probe::Complete, self.token))
            {
                return Err(Failure::Interrupted);
            }
        }
        Ok(reply)
    }
    fn keyed(&self, method: Method) -> Result<WaitReply, Failure> {
        self.call(&packet::Packet::keyed(method, self.key()).map_err(failure)?)
    }
    fn raw_close(raw: u64) -> Result<(), i32> {
        let mut args = [0; 10];
        args[0] = raw;
        // SAFETY: close only this exact generation; it reads no program memory.
        let result = unsafe { sys::raw::<{ Call::HandleClose.number() }>(args) };
        raw_channel::close_result(result[0]).map_err(|_| EIO)
    }
}
impl Session for Live {
    type Completion = WaitReply;
    fn state(&mut self) -> Result<State, i32> {
        let Some(s) = self.snapshot()? else {
            return Ok(State {
                phase: Phase::Gone,
                claim_live: false,
                saved: false,
                channel: false,
            });
        };
        if s.result.is_some() != s.recovery.outcome().is_some() {
            return Err(EIO);
        }
        let phase = match s.phase {
            WaitRecordPhase::Working => Phase::Working,
            WaitRecordPhase::Complete => Phase::Complete,
            WaitRecordPhase::Cleaning => Phase::Cleaning,
            WaitRecordPhase::Cleaned => Phase::Cleaned,
        };
        let claim_live = crate::shared::with_files(|files| {
            Ok(self.claim.is_some_and(|c| files.wait_is_live(c)))
        })?;
        Ok(State {
            phase,
            claim_live,
            saved: s.result.is_some(),
            channel: s.channel.is_some(),
        })
    }
    fn ending(&mut self) -> bool {
        ending()
    }
    fn start(&mut self) -> Result<WaitReply, Failure> {
        let wire = crate::shared::with_files(|files| {
            if !self.claim.is_some_and(|c| files.wait_is_live(c)) {
                return Ok(None);
            }
            Ok(Some(
                files
                    .wait_snapshot(self.token)
                    .map_err(crate::error)?
                    .recovery
                    .request(self.token),
            ))
        })
        .map_err(Failure::Fatal)?
        .ok_or(Failure::Retired)?;
        self.call(&packet::Packet::start(wire).map_err(failure)?)
    }
    fn query(&mut self) -> Result<WaitReply, Failure> {
        self.keyed(Method::WaitQuery)
    }
    fn cancel(&mut self) -> Result<WaitReply, Failure> {
        self.keyed(Method::WaitCancel)
    }
    #[inline(never)]
    fn release(&mut self) -> Result<(), Failure> {
        let p = packet::Packet::keyed(Method::WaitRelease, self.key()).map_err(failure)?;
        let released = (|| {
            let _scope = rt::upcall::defer_entries().map_err(kernel)?;
            let response =
                sys::send(self.transport.files().sessions().0, p.as_bytes()).map_err(kernel)?;
            let (bytes, len) = Self::inline(response)?;
            packet::released(&bytes[..len]).map_err(failure)
        })();
        #[cfg(feature = "wait-probe")]
        if released.is_ok() && probed(Probe::Release, self.token) {
            return Err(Failure::Interrupted);
        }
        released
    }
    fn arm(&mut self) -> Result<WaitReply, Failure> {
        let reply = (|| {
            let _scope = rt::upcall::defer_entries().map_err(kernel)?;
            let raw = self
                .snapshot()
                .map_err(Failure::Fatal)?
                .and_then(|s| s.channel)
                .ok_or(Failure::Retired)?;
            let mut args = [0; 10];
            args[0] = raw;
            args[1] = u64::from((Rights::NOTIFY | Rights::TRANSFER).0);
            // SAFETY: generation-safe duplication of the private resident channel only.
            let result = unsafe { sys::raw::<{ Call::HandleDuplicate.number() }>(args) };
            let duplicated = raw_channel::duplicate_result(&result).map_err(kernel)?;
            let copy = Handle::<Channel>::from_raw(rt::abi::Handle(duplicated));
            let p = packet::Packet::keyed(Method::WaitArm, self.key()).map_err(failure)?;
            // Moving send reconciles consumed versus Refused.back before scope resumes.
            let response = sys::send_handles(
                self.transport.files().sessions().0,
                p.as_bytes(),
                [copy.erase()],
            )
            .map_err(|refused| {
                let error = refused.error;
                drop(refused.back);
                kernel(error)
            })?;
            let (bytes, len) = Self::inline(response)?;
            packet::reply(&bytes[..len]).map_err(failure)
        })();
        #[cfg(feature = "wait-probe")]
        if reply.is_ok() && probed(Probe::Arm, self.token) {
            return Err(Failure::Interrupted);
        }
        reply
    }
    fn receive(&mut self) -> Result<(), Failure> {
        #[cfg(feature = "wait-probe")]
        let _ = probed(Probe::Receive, self.token);
        let _scope = rt::upcall::defer_entries().map_err(kernel)?;
        if ending() || crate::signals::pending_unblocked() {
            return Err(Failure::Interrupted);
        }
        let raw = self
            .snapshot()
            .map_err(Failure::Fatal)?
            .and_then(|s| s.channel)
            .ok_or(Failure::Retired)?;
        let mut args = [0; 10];
        args[0] = raw;
        // SAFETY: private notification-only RECEIVE, no SEND capability was transferred.
        // Label is x10 outside raw's prefix and is deliberately never synthesized/routed.
        let result = unsafe { sys::raw::<{ Call::Receive.number() }>(args) };
        raw_channel::receive_result(&result).map_err(kernel)
    }
    fn close_channel(&mut self) -> Result<(), i32> {
        let debt = crate::shared::with_files(|files| {
            files.wait_channel_debt(self.token).map_err(crate::error)
        })?;
        if let Some(debt) = debt {
            Self::raw_close(debt.raw())?;
            crate::shared::with_files(|files| {
                // A concurrent exact helper may already have confirmed and acked.
                if files.wait_snapshot(self.token).is_err() {
                    return Ok(());
                }
                files
                    .confirm_wait_channel_closed(debt)
                    .map_err(crate::error)
            })?;
        }
        #[cfg(feature = "wait-probe")]
        let _ = probed(Probe::CloseChannel, self.token);
        Ok(())
    }
    fn authenticate(&mut self) -> Result<(), Failure> {
        self.transport.files().finish_binding().map_err(failure)
    }
    fn pause(&mut self, room: bool) {
        if room {
            let ns = posix_change::room_pause_ns(self.room_repeats);
            self.room_repeats = self.room_repeats.saturating_add(1);
            let _ = crate::threads::sleep::pause(ns);
        } else {
            let _ = sys::yield_now();
        }
    }
    fn publish(&mut self, reply: WaitReply) -> Result<(), i32> {
        let terminal = TerminalReply::from_reply(reply).map_err(crate::error)?;
        crate::shared::with_files(|files| {
            let Ok(s) = files.wait_snapshot(self.token) else {
                return Ok(());
            };
            if self.owner.is_some() && s.owner != self.owner || s.result.is_some() {
                return Ok(());
            }
            let result = if reply.result == 0 {
                WaitResult::Value(0)
            } else {
                let errno = if reply.result == proto_fs::LOCK_CANCELLED {
                    match s.reason {
                        Some(WaitCancelReason::Signal) => EINTR,
                        Some(WaitCancelReason::Close) => EBADF,
                        _ => EIO,
                    }
                } else if reply.result == proto_fs::LOCK_DEADLOCK {
                    EDEADLK
                } else {
                    crate::lock_fields::terminal_result(reply.result)
                        .err()
                        .unwrap_or(EIO)
                };
                WaitResult::Failed(errno)
            };
            files
                .publish_wait_cleanup(self.token, result, terminal)
                .map_err(crate::error)?;
            Ok(())
        })
    }
    fn begin_cleanup(&mut self, reason: Reason) -> Result<(), i32> {
        crate::shared::with_files(|files| {
            if files.wait_snapshot(self.token).is_err() {
                return Ok(());
            }
            let reason = match reason {
                Reason::Signal => WaitCancelReason::Signal,
                Reason::Abandoned => WaitCancelReason::Abandoned,
            };
            files
                .begin_wait_cleanup(self.token, reason)
                .map_err(crate::error)?;
            Ok(())
        })
    }
    fn finish_cleanup(&mut self) -> Result<(), i32> {
        crate::shared::with_files(|files| {
            if files.wait_snapshot(self.token).is_err() {
                return Ok(());
            }
            files.finish_wait_cleanup(self.token).map_err(crate::error)
        })
    }
    fn acknowledge(&mut self) -> Result<WaitReply, i32> {
        let owner = self.owner.ok_or(EIO)?;
        crate::shared::with_files(|files| {
            let (result, recovery) = files
                .ack_wait_record(self.token, owner)
                .map_err(crate::error)?;
            match result {
                WaitResult::Value(0) => {}
                WaitResult::Failed(e) => return Err(e),
                _ => return Err(EIO),
            }
            recovery.outcome().ok_or(EIO)
        })
    }
}
/// The helper never creates a channel, receives, or performs implicit Bind.
#[inline(never)]
pub(crate) fn cleanup_step(token: WaitToken) -> Result<bool, i32> {
    let transport = crate::shared::with_files(|files| {
        Ok(files.wait_snapshot(token).ok().map(|_| files.transport()))
    })?;
    let Some(transport) = transport else {
        return Ok(true);
    };
    core::cleanup_step(&mut Live {
        token,
        claim: None,
        owner: None,
        transport,
        room_repeats: 0,
    })
}

/// Select under the table lock; pay at most one cleanup turn after unlocking.
#[inline(never)]
pub(crate) fn collect(
    me: Option<OwnerToken>,
    current: entries::Frame,
    skip: Option<WaitToken>,
    blocking: bool,
) -> bool {
    let find = |files: &mut posix_fs::PosixFs| {
        static CURSOR: ::core::sync::atomic::AtomicUsize =
            ::core::sync::atomic::AtomicUsize::new(0);
        let cursor = CURSOR.load(Ordering::Relaxed);
        let token = files
            .pick_wait_cleanup_from(me, current, skip, cursor)
            .map_err(crate::error)?;
        if let Some(token) = token {
            // FILES_LOCK still protects selection: a pending handler, refused
            // Send or departing helper cannot repeatedly hide later local debts.
            CURSOR.store(
                (token.slot() + 1) % posix_fs::wait::WAIT_RECORDS,
                Ordering::Relaxed,
            );
        }
        Ok(token)
    };
    let picked = if blocking {
        crate::shared::with_files(find)
    } else {
        crate::shared::try_with_files(find)
    };
    let Ok(Some(token)) = picked else {
        return false;
    };
    let _ = cleanup_step(token);
    true
}

/// No flock pointer or temporary channel survives a signal-entry boundary.
pub(crate) fn operation(fd: u32, input: Input) -> Result<WaitReply, i32> {
    let _outer = OuterRestart::enter();
    let owner = OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)?;
    let frame = crate::change::frame();
    let mut repeats = 0u32;
    let (token, claim, transport) = loop {
        collect(Some(owner), frame, None, true);
        if ending() {
            return Err(EINTR);
        }
        let taken = crate::shared::with_files(|files| {
            let source = files.lock_source(fd).map_err(crate::error)?;
            match files.wait_place(owner, frame) {
                WaitPlace::Free => {
                    let (token, claim) = files
                        .begin_wait_record(owner, source, frame, input)
                        .map_err(crate::error)?;
                    Ok(Some((token, claim, files.transport())))
                }
                WaitPlace::Full { own: true } | WaitPlace::Retired => Err(ENOLCK),
                WaitPlace::Full { own: false } => Ok(None),
            }
        })
        .map_err(|errno| {
            if errno == crate::constants::EMFILE {
                ENOLCK
            } else {
                errno
            }
        })?;
        if let Some(taken) = taken {
            break taken;
        }
        let _ = crate::threads::sleep::pause(posix_change::room_pause_ns(repeats));
        repeats = repeats.saturating_add(1);
    };
    let mut live = Live {
        token,
        claim: Some(claim),
        owner: Some(owner),
        transport,
        room_repeats: 0,
    };
    let created = (|| {
        let _scope = rt::upcall::defer_entries().map_err(kernel)?;
        let priority = (crate::threads::own_block()
            .base_level
            .load(Ordering::Relaxed) as u8)
            .max(1);
        let channel = sys::channel_create(priority).map_err(|e| {
            if matches!(e, Error::NoMemory | Error::LimitReached) {
                Failure::Room
            } else {
                kernel(e)
            }
        })?;
        let raw = channel.raw().0;
        let attached = crate::shared::with_files(|files| {
            files.attach_wait_channel(claim, raw).map_err(crate::error)
        });
        match attached {
            Ok(()) => {
                let _ = channel.into_raw();
                Ok(())
            }
            Err(_) => {
                drop(channel);
                Err(Failure::Retired)
            }
        }
    })();
    core::prepared(&mut live, created)?;
    core::drive(&mut live)
}
