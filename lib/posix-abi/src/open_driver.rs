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
    #[cfg(feature = "full-capacity-probe")]
    rt::println!(
        "capacity-open: pid={} status={}",
        crate::process::getpid(),
        error.code()
    );
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

/// All closure bodies inspect local state; requests execute after releasing FILES_LOCK.
pub(crate) fn open(
    transport: Transport,
    path: &[u8],
    flags: u32,
    mode: u32,
    umask: u32,
    descriptor_flags: DescriptorFlags,
) -> Result<u32, i32> {
    let owner = OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)?;
    let (token, mut claim) = crate::shared::with_files(|files| {
        files
            .begin_open_record(owner, flags & 3, descriptor_flags)
            .map_err(crate::error)
    })?;
    let mut recovery = Recovery::starting(flags & 3, descriptor_flags).map_err(crate::error)?;
    let files = transport.files();
    enum FinalPhase {
        Published(u32),
        Prepared(Status),
    }
    let result = (|| {
        recovery.job = files
            .open_start(key(token), path, flags, mode, umask)
            .map_err(protocol)?;
        recovery.phase = Phase::Traversing;
        #[cfg(feature = "full-capacity-probe")]
        rt::println!(
            "capacity-open: pid={} stage=1 job={}",
            crate::process::getpid(),
            recovery.job
        );
        save(claim, recovery)?;
        while !files.open_advance(recovery.job, false).map_err(protocol)? {}
        recovery.phase = Phase::Preparing;
        #[cfg(feature = "full-capacity-probe")]
        rt::println!(
            "capacity-open: pid={} stage=2 job={}",
            crate::process::getpid(),
            recovery.job
        );
        save(claim, recovery)?;
        loop {
            // Binding and preparation retries run without a numeric reservation or defer.
            while !files.open_advance(recovery.job, true).map_err(protocol)? {}
            #[cfg(feature = "full-capacity-probe")]
            rt::println!(
                "capacity-open: pid={} stage=3 job={}",
                crate::process::getpid(),
                recovery.job
            );
            #[cfg(feature = "open-finalize-clock-probe")]
            crate::open_finalize_probe::prepared(crate::open_finalize_probe::Prepared {
                owner,
                token,
                claim,
                job: recovery.job,
                session: files.sessions().0.raw(),
            })?;
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
                #[cfg(feature = "full-capacity-probe")]
                rt::println!(
                    "capacity-open: pid={} stage=4 job={}",
                    crate::process::getpid(),
                    recovery.job
                );
                let finished = match context.send_once() {
                    FinalizeResult::Finished(held) => Ok(held),
                    FinalizeResult::Deferred { proof, reason } => {
                        #[cfg(feature = "open-finalize-clock-probe")]
                        crate::open_finalize_probe::deferred(owner, token, reason);
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
                        FinalizeRecovery::Failed(_error) => {
                            #[cfg(feature = "full-capacity-probe")]
                            rt::println!(
                                "capacity-open: pid={} stage=5 status={}",
                                crate::process::getpid(),
                                _error.code()
                            );
                            Err(EIO)
                        }
                    },
                }?;
                recovery = recovery.remember(finished);
                save(claim, recovery)?;
                let target = Transport::opened_target(finished, recovery.access as u32)
                    .map_err(crate::error)?;
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
        #[cfg(feature = "full-capacity-probe")]
        rt::println!(
            "capacity-open: pid={} token={} generation={} job={} phase={} errno={}",
            crate::process::getpid(),
            token.slot(),
            token.generation(),
            recovery.job,
            recovery.phase as u32,
            errno
        );
        let _ =
            crate::shared::with_files(|files| files.begin_open_cancel(claim).map_err(crate::error));
        let canonical = files.open_cancel_key_once(key(token)).is_ok();
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
pub(crate) fn detach(owner: u64) {
    let Ok(owner) = OwnerToken::new(owner) else {
        return;
    };
    let notified = crate::shared::with_files(|files| {
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
        Ok(tokens)
    });
    if let Ok(tokens) = notified {
        for token in tokens.into_iter().flatten() {
            wake(token);
        }
    }
}

/// Wake uses the pinned header after releasing FILES_LOCK, including exact slot reuse.
fn wake(token: OpenToken) {
    let address =
        crate::shared::with_files(|files| files.open_wait_address(token).map_err(crate::error));
    if let Ok(address) = address {
        posix_sync::futex_wake(address as *const core::sync::atomic::AtomicU32, u32::MAX);
    }
}

/// One exact cleanup request, without authority to begin Start or Commit.
pub(crate) fn help() {
    let pending = crate::shared::with_files(|files| {
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
        Ok(token.map(|token| (files.transport(), token)))
    })
    .ok()
    .flatten();
    let Some((transport, token)) = pending else {
        return;
    };
    cancel_pending(transport, token);
}

fn cancel_pending(transport: Transport, token: OpenToken) {
    let Ok(helper) =
        crate::relibc::open_owner().and_then(|owner| OwnerToken::new(owner).map_err(|_| EIO))
    else {
        return;
    };
    let ready = crate::shared::with_files(|files| {
        let snapshot = files.open_snapshot(token).map_err(crate::error)?;
        if snapshot.phase == OpenPhase::Canceling {
            return Ok(true);
        }
        if snapshot.owner.is_some() {
            return Ok(false);
        }
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
    });
    if ready != Ok(true) {
        return;
    }
    if transport.files().open_cancel_key_once(key(token)).is_ok() {
        let _ = crate::shared::with_files(|files| {
            let _snapshot = files.finish_open_cancel(token, EIO).map_err(crate::error)?;
            Ok(())
        });
        wake(token);
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
