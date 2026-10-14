// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident Open ownership precedes every request; final handoff has a bounded defer.

use crate::constants::*;
use posix_fs::open::{
    Abandoned, Claim, ClaimToken, FinalizeRecovery, FinalizeResult, OpenPhase, OpenToken,
    OwnerToken, Phase, Recovery, WaitValue,
};
use posix_fs::{DescriptorFlags, Transport};
use proto_wire::Status;

fn protocol(error: Status) -> i32 {
    if error == Status::BadSize {
        EIO
    } else {
        crate::error(error.into())
    }
}
fn key(token: OpenToken) -> proto_fs::OpenKey {
    proto_fs::OpenKey {
        slot: token.slot() as u32,
        generation: token.generation(),
    }
}
struct Defer;
impl Defer {
    fn enter() -> Self {
        posix_sync::enter();
        Self
    }
}
impl Drop for Defer {
    fn drop(&mut self) {
        posix_sync::leave();
    }
}

pub(crate) struct Options {
    pub flags: u32,
    pub nonblock: bool,
    pub mode: u32,
    pub umask: u32,
    pub descriptor_flags: DescriptorFlags,
}

/// All closure bodies inspect local state; requests execute after releasing FILES_LOCK.
pub(crate) fn open(
    transport: Transport,
    base: Option<(u32, u64)>,
    path: &[u8],
    options: Options,
) -> Result<u32, i32> {
    let Options {
        flags,
        nonblock,
        mode,
        umask,
        descriptor_flags,
    } = options;
    let owner = OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)?;
    // The record stands for one job of the session: a place of the table of
    // sixteen is taken first, and waited for when none is free.
    let here = crate::change::frame();
    let (token, mut claim) = crate::change::take_place(owner, here, |files| {
        files.begin_open_record(owner, flags & 3, descriptor_flags)
    })?;
    let mut recovery = Recovery::starting(flags & 3, descriptor_flags).map_err(crate::error)?;
    recovery.fifo_flags = (if nonblock { proto_pipe::NONBLOCK } else { 0 }
        | if flags & proto_fs::APPEND != 0 {
            proto_pipe::APPEND
        } else {
            0
        }
        | if flags & 3 == proto_fs::WRITE_ONLY {
            proto_pipe::WRITE_END
        } else {
            0
        }) as u8;
    let files = transport.files();
    enum FinalPhase {
        Published(u32),
        Prepared(Status),
        Fifo(posix_fs::RamTarget),
    }
    let result = (|| {
        recovery.job = files
            .open_start_from(key(token), base, path, flags, mode, umask)
            .map_err(protocol)?;
        recovery.phase = Phase::Traversing;
        save(claim, recovery)?;
        while !files.open_advance(recovery.job, false).map_err(protocol)? {}
        recovery.phase = Phase::Preparing;
        save(claim, recovery)?;
        loop {
            // Binding and preparation retries run without a numeric reservation or defer.
            files.open_prepare_recover(recovery.job).map_err(protocol)?;
            let defer = Defer::enter();
            let final_result = (|| {
                let (entry, context) = crate::shared::with_files(|files| {
                    let entry = files.reserve_open_record(claim).map_err(crate::error)?;
                    let context = files
                        .begin_open_finalize(claim, entry)
                        .map_err(crate::error)?;
                    Ok((entry, context))
                })?;
                recovery.phase = Phase::Committing;
                let finished = match context.send_once() {
                    FinalizeResult::Finished(held) => Ok(held),
                    FinalizeResult::Deferred { proof, reason } => {
                        crate::shared::with_files(|files| {
                            files
                                .unreserve_open_record(claim, entry, proof)
                                .map_err(crate::error)?;
                            Ok(())
                        })?;
                        recovery.phase = Phase::Preparing;
                        return Ok(FinalPhase::Prepared(reason));
                    }
                    FinalizeResult::Rejected(error) => return Err(protocol(error)),
                    FinalizeResult::Unresolved(context) => match context.query_once() {
                        FinalizeRecovery::Finished(held) => Ok(held),
                        FinalizeRecovery::Prepared(proof) => {
                            crate::shared::with_files(|files| {
                                files
                                    .unreserve_open_record(claim, entry, proof)
                                    .map_err(crate::error)?;
                                Ok(())
                            })?;
                            recovery.phase = Phase::Preparing;
                            return Ok(FinalPhase::Prepared(Status::Ok));
                        }
                        FinalizeRecovery::Failed(_) => Err(EIO),
                    },
                }?;
                recovery = recovery.remember(finished);
                save(claim, recovery)?;
                let target = transport
                    .capture_opened_target(finished, recovery.access as u32)
                    .map_err(crate::error)?;
                if let posix_fs::Target::Ram(target) = target
                    && target.kind() == Ok(posix_fs::FileKind::Fifo)
                {
                    if recovery.access as u32 == proto_fs::READ_WRITE {
                        return Err(EINVAL);
                    }
                    return Ok(FinalPhase::Fifo(target));
                }
                crate::shared::with_files(|files| {
                    files
                        .stage_open_record(claim, target)
                        .map_err(crate::error)?;
                    files.publish_open_record(claim).map_err(crate::error)?;
                    files
                        .ack_open_record(token, owner)
                        .map_err(crate::error)?
                        .into_result()
                })
                .map(FinalPhase::Published)
            })();
            if final_result.is_err() {
                // Deferred handlers encounter cleanup with its final claim already revoked.
                let _ = crate::shared::with_files(|files| {
                    files.begin_open_cancel(claim).map_err(crate::error)
                });
            }
            wake(token);
            drop(defer);
            match final_result? {
                FinalPhase::Published(fd) => return Ok(fd),
                FinalPhase::Fifo(metadata) => {
                    let target = fifo_open(transport, token, claim, metadata, &mut recovery)?;
                    let _defer = Defer::enter();
                    return crate::shared::with_files(|files| {
                        files
                            .stage_open_record(claim, posix_fs::Target::Fifo(target))
                            .map_err(crate::error)?;
                        files.publish_open_record(claim).map_err(crate::error)?;
                        files
                            .ack_open_record(token, owner)
                            .map_err(crate::error)?
                            .into_result()
                    });
                }
                FinalPhase::Prepared(reason) => {
                    claim = crate::shared::with_files(|files| {
                        match files
                            .claim_open_record(token, owner)
                            .map_err(crate::error)?
                        {
                            Claim::Acquired { token, .. } => Ok(token),
                            _ => Err(EIO),
                        }
                    })?;
                    if reason == Status::Unknown(proto_fs::AUTHENTICATING) {
                        files.finish_binding().map_err(protocol)?;
                    } else {
                        rt::sys::yield_now().map_err(|error| protocol(Status::Kernel(error)))?;
                    }
                }
            }
        }
    })();
    if let Err(errno) = result {
        let _ =
            crate::shared::with_files(|files| files.begin_open_cancel(claim).map_err(crate::error));
        let canonical = fifo_cleanup(transport, token, recovery)
            && files.open_cancel_key_once(key(token)).is_ok();
        let completion = crate::shared::with_files(|files| {
            if let Some(completion) = files
                .acknowledge_open_cancel(token, owner, canonical, errno)
                .map_err(crate::error)?
            {
                return Ok(Some(completion));
            }
            files
                .abandon_open_record(token, recovery)
                .map_err(crate::error)?;
            Ok(None)
        });
        wake(token);
        if let Ok(Some(completion)) = completion {
            return completion.into_result();
        }
    }
    result
}

fn save(claim: ClaimToken, recovery: Recovery) -> Result<(), i32> {
    crate::shared::with_files(|files| {
        files
            .update_open_record(claim, recovery)
            .map_err(crate::error)
    })
}

/// Local lifetime detachment leaves every remote debt in its prepaid hold.
pub(crate) fn detach(owner: u64) -> bool {
    let Ok(owner) = OwnerToken::new(owner) else {
        return false;
    };
    let notified = crate::shared::try_with_files(|files| {
        let mut tokens = [None; posix_fs::OPEN_MAX];
        for (slot, token) in files.open_tokens().enumerate() {
            tokens[slot] = Some(token);
        }
        for token in tokens.into_iter().flatten() {
            let Ok(snapshot) = files.open_snapshot(token) else {
                continue;
            };
            if snapshot.owner != Some(owner) {
                continue;
            }
            let recovery = if let Some(recovery) = snapshot.recovery {
                recovery
            } else {
                // Exact key cleanup remains available if the entry has already disappeared.
                files
                    .published_open_recovery(snapshot.entry)
                    .unwrap_or_default()
            };
            let _ = files.abandon_open_record(token, recovery);
        }
        while let Some(outcome) = files.detach_open_helper(owner) {
            match outcome {
                Abandoned::ClaimReleased(_) | Abandoned::Recover { .. } => {}
                Abandoned::Discarded { release: None, .. } => {}
                Abandoned::Discarded {
                    release: Some(_), ..
                } => {
                    // Published RAM entries used the resident recovery path above.
                    debug_assert!(false, "unexpected ephemeral Open disposal");
                }
            }
        }
        let complete = files.open_tokens().all(|token| {
            files.open_snapshot(token).is_ok_and(|snapshot| {
                snapshot.owner != Some(owner) && snapshot.claimant != Some(owner)
            })
        });
        let addresses =
            tokens.map(|token| token.and_then(|token| files.open_wait_address(token).ok()));
        Ok((complete, addresses))
    });
    if let Ok((complete, addresses)) = notified {
        for address in addresses.into_iter().flatten() {
            posix_sync::futex_wake(address as *const core::sync::atomic::AtomicU32, u32::MAX);
        }
        complete
    } else {
        false
    }
}

/// Wake uses the pinned header after releasing FILES_LOCK, including exact slot reuse.
/// A record that goes frees a place of a job too: its waiters wake as well.
fn wake(token: OpenToken) {
    crate::change::wake_places();
    let address =
        crate::shared::with_files(|files| files.open_wait_address(token).map_err(crate::error));
    if let Ok(address) = address {
        posix_sync::futex_wake(address as *const core::sync::atomic::AtomicU32, u32::MAX);
    }
}

/// One exact cleanup request, without authority to begin Start or Commit.
pub(crate) fn help() {
    let helper = crate::relibc::open_owner()
        .ok()
        .and_then(|owner| OwnerToken::new(owner).ok());
    let pending = crate::shared::try_with_files(|files| {
        static CURSOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
        let cursor = CURSOR.load(core::sync::atomic::Ordering::Relaxed);
        let token = files
            .open_tokens()
            .filter(|&token| {
                files.open_snapshot(token).is_ok_and(|snapshot| {
                    snapshot.phase == OpenPhase::Canceling || snapshot.owner.is_none()
                })
            })
            .min_by_key(|token| (token.slot() + posix_fs::OPEN_MAX - cursor) % posix_fs::OPEN_MAX);
        if let Some(token) = token {
            CURSOR.store(
                (token.slot() + 1) % posix_fs::OPEN_MAX,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        let Some(token) = token else {
            return Ok(None);
        };
        if !prepare_cancel(files, token, helper)? {
            return Ok(None);
        }
        Ok(Some((files.transport(), token)))
    })
    .ok()
    .flatten();
    let Some((transport, token)) = pending else {
        return;
    };
    send_cancel(transport, token);
}

fn cancel_pending(transport: Transport, token: OpenToken) {
    let Ok(helper) =
        crate::relibc::open_owner().and_then(|owner| OwnerToken::new(owner).map_err(|_| EIO))
    else {
        return;
    };
    let ready = crate::shared::try_with_files(|files| prepare_cancel(files, token, Some(helper)));
    if ready != Ok(true) {
        return;
    }
    send_cancel(transport, token);
}

fn prepare_cancel(
    files: &mut posix_fs::PosixFs,
    token: OpenToken,
    helper: Option<OwnerToken>,
) -> Result<bool, i32> {
    let snapshot = files.open_snapshot(token).map_err(crate::error)?;
    if snapshot.phase == OpenPhase::Canceling {
        return Ok(true);
    }
    if snapshot.owner.is_some() {
        return Ok(false);
    }
    let Some(helper) = helper else {
        return Ok(false);
    };
    match files
        .claim_open_record(token, helper)
        .map_err(crate::error)?
    {
        Claim::Acquired { token: claim, .. } => {
            files.begin_open_cancel(claim).map_err(crate::error)?;
            Ok(true)
        }
        Claim::Canceling(_) => Ok(true),
        Claim::Busy(_) | Claim::Complete(_) => Ok(false),
    }
}

fn send_cancel(transport: Transport, token: OpenToken) {
    let recovery = crate::shared::try_with_files(|files| {
        Ok(files
            .open_snapshot(token)
            .ok()
            .and_then(|snapshot| snapshot.recovery)
            .unwrap_or_default())
    });
    if recovery.is_ok_and(|recovery| fifo_cleanup(transport, token, recovery))
        && transport.files().open_cancel_key_once(key(token)).is_ok()
    {
        let address = crate::shared::try_with_files(|files| {
            let address = files.open_wait_address(token).map_err(crate::error)?;
            let _snapshot = files.finish_open_cancel(token, EIO).map_err(crate::error)?;
            Ok(address)
        });
        if let Ok(address) = address {
            posix_sync::futex_wake(address as *const core::sync::atomic::AtomicU32, u32::MAX);
        }
    }
}

/// A live operation retains its final-phase ownership while a conflicting dup waits.
pub(crate) fn wait_pending(token: OpenToken) -> Result<(), i32> {
    let snapshot = crate::shared::with_files(|files| Ok(files.open_snapshot(token).ok()))?;
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    if let Some(owner) = snapshot.owner {
        let _ = crate::relibc::detach_ended_open_owner(owner.value());
    }
    if let Some(helper) = snapshot
        .claimant
        .filter(|helper| Some(*helper) != snapshot.owner)
    {
        let _ = crate::relibc::detach_ended_open_owner(helper.value());
    }
    let pending = crate::shared::with_files(|files| {
        let Ok(snapshot) = files.open_snapshot(token) else {
            return Ok(None);
        };
        if snapshot.completion.is_some() {
            return Ok(None);
        }
        Ok(Some((
            snapshot,
            files.transport(),
            files.open_wait_address(token).map_err(crate::error)?,
            files.open_wait_snapshot(token).map_err(crate::error)?,
        )))
    })?;
    let Some((snapshot, transport, address, wait)) = pending else {
        return Ok(());
    };
    if snapshot.phase == OpenPhase::Canceling || snapshot.owner.is_none() {
        cancel_pending(transport, token);
    }
    match wait {
        WaitValue::Sequence(sequence) => {
            let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(1_000_000);
            // SAFETY: FILES remains pinned; its atomic header survives free and reuse.
            let word = unsafe { &*(address as *const core::sync::atomic::AtomicU32) };
            match posix_sync::futex_wait(
                word,
                sequence,
                crate::clock::CLOCK_MONOTONIC as u32,
                Some(deadline),
            ) {
                Ok(_) | Err(EAGAIN | ETIMEDOUT) => Ok(()),
                Err(error) => Err(error),
            }
        }
        WaitValue::NeverSleep => crate::threads::sleep::pause(1_000_000),
    }
}

fn save_fifo_capability(
    claim: ClaimToken,
    recovery: &mut Recovery,
    capability: Option<rt::handle::Handle<rt::handle::Channel>>,
) -> Result<(), i32> {
    recovery.fifo_capability = capability.as_ref().map_or(0, |handle| handle.raw().0);
    save(claim, *recovery)?;
    if let Some(capability) = capability {
        let _ = capability.into_raw();
    }
    Ok(())
}

fn fifo_ticket(recovery: Recovery) -> proto_pipe::NamedTicket {
    proto_pipe::NamedTicket {
        slot: recovery.fifo_ticket_slot,
        generation: recovery.fifo_ticket_generation,
    }
}

/// Each short response becomes resident before signal delivery reopens. The
/// rendezvous receive itself owns neither FILES_LOCK nor signal deferral.
fn fifo_open(
    transport: Transport,
    token: OpenToken,
    claim: ClaimToken,
    metadata: posix_fs::RamTarget,
    recovery: &mut Recovery,
) -> Result<posix_fs::FifoTarget, i32> {
    use core::sync::atomic::Ordering;
    use proto_pipe::{Method, NamedPhase};
    use rt::handle::{Channel, Handle};
    let session = transport.pipes().map_err(crate::error)?;
    let block = crate::threads::own_block();
    let _restart = crate::long::OuterRestart::enter(&block.flags);
    recovery.fifo_stage = 1;
    save(claim, *recovery)?;
    loop {
        let _short = crate::long::ShortScope::enter(true)?;
        let response = rt::pipe::request(
            &session,
            Method::PayerWitness,
            proto_pipe::NamedTicket {
                slot: token.slot() as u32,
                generation: token.generation(),
            },
            None,
        );
        match response {
            Err(Status::Kernel(rt::abi::Error::Interrupted)) => continue,
            Err(error) => return Err(protocol(error)),
            Ok(response) => {
                recovery.fifo_ticket_slot = response.state.ticket.slot;
                recovery.fifo_ticket_generation = response.state.ticket.generation;
                recovery.fifo_stage = 2;
                save_fifo_capability(claim, recovery, response.capability)?;
                break;
            }
        }
    }
    let held = metadata.prepared();
    let grant = proto_fs::FifoGrant {
        key: key(token),
        fd: recovery.backend_fd,
        generation: held.generation,
        ticket_slot: recovery.fifo_ticket_slot,
        ticket_generation: recovery.fifo_ticket_generation,
        flags: recovery.fifo_flags as u32,
    };
    let mut brokered = false;
    let mut full = false;
    loop {
        if core::mem::take(&mut full) {
            // The end's queue of waiters is full: try again shortly. A caught signal ends the
            // pause and the check below decides about it.
            let _ = crate::threads::sleep::pause(1_000_000);
        }
        if crate::long::ending(&block.flags, true) {
            return Err(EINTR);
        }
        let _short = crate::long::ShortScope::enter(true)?;
        let response = if !brokered {
            let raw = core::mem::take(&mut recovery.fifo_capability);
            let witness = (raw != 0).then(|| Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
            save(claim, *recovery)?;
            match transport.files().fifo_grant(grant, witness) {
                Ok(response) => {
                    brokered = true;
                    match response.capability {
                        Some(capability) => rt::pipe::request(
                            &session,
                            Method::NamedAttach,
                            fifo_ticket(*recovery),
                            Some(capability),
                        ),
                        None => rt::pipe::request(
                            &session,
                            Method::NamedQuery,
                            fifo_ticket(*recovery),
                            None,
                        ),
                    }
                }
                Err(refused) => {
                    save_fifo_capability(claim, recovery, refused.capability)?;
                    match refused.status {
                        Status::Kernel(rt::abi::Error::Interrupted)
                        | Status::Unknown(proto_fs::RESOLVING | proto_fs::AUTHENTICATING) => {
                            continue;
                        }
                        error => Err(error),
                    }
                }
            }
        } else {
            rt::pipe::request(&session, Method::NamedQuery, fifo_ticket(*recovery), None)
        };
        let response = match response {
            Err(Status::Kernel(rt::abi::Error::Interrupted)) => continue,
            Err(error) => return Err(protocol(error)),
            Ok(response) => response,
        };
        // The paid ticket is resident before Query advances allocation. A
        // returned grant moves straight to Attach, without another RAM hop.
        if let Some(capability) = response.capability {
            if response.state.phase != NamedPhase::Grant {
                return Err(EIO);
            }
            match rt::pipe::request(
                &session,
                Method::NamedAttach,
                fifo_ticket(*recovery),
                Some(capability),
            ) {
                Ok(attached) => {
                    full = attached.state.phase == NamedPhase::Grant;
                    continue;
                }
                Err(Status::Kernel(rt::abi::Error::Interrupted)) => continue,
                Err(error) => return Err(protocol(error)),
            }
        }
        let response = response.state;
        match response.phase {
            NamedPhase::Witness | NamedPhase::Preparing | NamedPhase::Grant => {
                continue;
            }
            NamedPhase::Waiting => {
                recovery.fifo_stage = 3;
                save(claim, *recovery)?;
            }
            NamedPhase::Ready | NamedPhase::Taken => break,
            NamedPhase::Failed => {
                return Err(if response.result == proto_pipe::NO_READER {
                    ENXIO
                } else {
                    crate::error(posix_fs::pipe_error(Status::from_code(response.result)))
                });
            }
            NamedPhase::Cancelled => return Err(EINTR),
        }
        drop(_short);
        // Arm the ordinary thread channel with the complete paid ticket.
        let channel =
            Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
        let handled = block.handled.load(Ordering::SeqCst);
        let arm = {
            let _short = crate::long::ShortScope::enter(true)?;
            let notification = rt::sys::handle_label(
                &channel,
                rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER,
                recovery.fifo_ticket_generation,
                block.base_level.load(Ordering::Relaxed) as u8,
            )
            .map_err(|_| EAGAIN)?;
            rt::pipe::request(
                &session,
                Method::NamedQuery,
                fifo_ticket(*recovery),
                Some(notification),
            )
            .map_err(protocol)?
        };
        if arm.state.phase != NamedPhase::Waiting {
            continue;
        }
        let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
        if crate::long::ending(&block.flags, true) {
            drop(guard);
            return Err(EINTR);
        }
        if block.handled.load(Ordering::SeqCst) != handled {
            drop(guard);
            continue;
        }
        let got = rt::sys::receive(&channel);
        drop(guard);
        match got {
            Ok(_) | Err(rt::abi::Error::Interrupted) => {}
            Err(_) => return Err(EIO),
        }
    }
    // Take and both acknowledgements remain recoverable in the same local record.
    let _short = crate::long::ShortScope::enter(true)?;
    let taken = loop {
        match rt::pipe::request(&session, Method::NamedTake, fifo_ticket(*recovery), None) {
            Err(Status::Kernel(rt::abi::Error::Interrupted)) => continue,
            other => break other.map_err(protocol)?.state,
        }
    };
    if taken.phase != NamedPhase::Taken {
        return Err(EIO);
    }
    recovery.fifo_endpoint_id = taken.endpoint.id;
    recovery.fifo_endpoint_generation = taken.endpoint.generation;
    recovery.fifo_stage = 4;
    save(claim, *recovery)?;
    let target = posix_fs::FifoTarget::new(metadata, taken.endpoint).map_err(crate::error)?;
    loop {
        match transport.files().fifo_ack(proto_fs::FifoAck {
            key: key(token),
            ticket_slot: recovery.fifo_ticket_slot,
            ticket_generation: recovery.fifo_ticket_generation,
        }) {
            Err(Status::Kernel(rt::abi::Error::Interrupted)) => continue,
            other => {
                other.map_err(protocol)?;
                break;
            }
        }
    }
    recovery.fifo_stage = 5;
    save(claim, *recovery)?;
    loop {
        match rt::pipe::request(&session, Method::NamedAck, fifo_ticket(*recovery), None) {
            Err(Status::Kernel(rt::abi::Error::Interrupted)) => continue,
            other => {
                other.map_err(protocol)?;
                break;
            }
        }
    }
    recovery.fifo_stage = 6;
    save(claim, *recovery)?;
    Ok(target)
}

/// No path is replayed. A saved endpoint closes safely after uncertain Ack;
/// an unacknowledged candidate is cancelled by its exact retained ticket.
fn fifo_cleanup(transport: Transport, token: OpenToken, mut recovery: Recovery) -> bool {
    use proto_pipe::Method;
    if recovery.fifo_stage == 0 {
        return true;
    }
    let Ok(session) = transport.pipes() else {
        return false;
    };
    if recovery.fifo_ticket_generation == 0 && recovery.fifo_stage < 6 {
        let Ok(response) = rt::pipe::request(
            &session,
            Method::PayerWitness,
            proto_pipe::NamedTicket {
                slot: token.slot() as u32,
                generation: token.generation(),
            },
            None,
        ) else {
            return false;
        };
        recovery.fifo_ticket_slot = response.state.ticket.slot;
        recovery.fifo_ticket_generation = response.state.ticket.generation;
    }
    if recovery.fifo_ticket_generation != 0 {
        let cancelled =
            rt::pipe::request(&session, Method::NamedCancel, fifo_ticket(recovery), None);
        if cancelled.is_ok() {
            if rt::pipe::request(&session, Method::NamedAck, fifo_ticket(recovery), None).is_err() {
                return false;
            }
        } else if recovery.fifo_stage < 5 {
            return false;
        }
    }
    if recovery.fifo_stage >= 5 && recovery.fifo_endpoint_generation != 0 {
        let endpoint = proto_pipe::Endpoint {
            id: recovery.fifo_endpoint_id,
            generation: recovery.fifo_endpoint_generation,
        };
        match transport.pipe_endpoint_call(Method::Close, endpoint, None) {
            Ok(_) | Err(posix_fs::FsError::BadFileDescriptor) => {}
            Err(_) => return false,
        }
    }
    let Ok(_short) = crate::long::ShortScope::enter(true) else {
        return false;
    };
    let Ok(raw) = crate::shared::try_with_files(|files| {
        files.take_open_capability(token).map_err(crate::error)
    }) else {
        return false;
    };
    if raw != 0 {
        drop(rt::handle::Handle::<rt::handle::Channel>::from_raw(
            rt::abi::Handle(raw),
        ));
    }
    true
}
