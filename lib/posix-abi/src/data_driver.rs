// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact paid data custody, with one final native call under signal defer.

use crate::constants::*;
use posix_fs::data::{
    DataKind, DataOutcome, DataPhase, DataResult, OwnerToken, Phase, ScalarClaim, ScalarClaimToken,
    ScalarPhase, ScalarResult, ScalarToken, StartResult, WaitValue,
};
use posix_fs::{Target, Transport};
use proto_wire::Status;

fn key(token: ScalarToken) -> proto_fs::OpenKey {
    proto_fs::OpenKey {
        slot: token.slot() as u32,
        generation: token.generation(),
    }
}
fn owner() -> Result<OwnerToken, i32> {
    OwnerToken::new(crate::relibc::open_owner()?).map_err(|_| EIO)
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

/// Atomic admission selects the RAM route and saves the complete immutable input.
/// Other device routes remain with their respective public driver.
pub(crate) fn begin(
    fd: u32,
    kind: DataKind,
    count: u32,
    position: u64,
    input: &[u8],
) -> Result<Option<Operation>, i32> {
    let eligible = |target| {
        matches!(target, Target::Ram(_))
            || (matches!(target, Target::Random(_)) && kind == DataKind::Write)
    };
    if !crate::shared::with_files(|files| files.target(fd).map(eligible).map_err(crate::error))? {
        return Ok(None);
    }
    let owner = owner()?;
    crate::shared::with_files(|files| {
        let target = files.target(fd).map_err(crate::error)?;
        if !eligible(target) {
            return Ok(None);
        }
        let (token, claim, transport) = files
            .begin_data(owner, fd, kind, count, position, input)
            .map_err(crate::error)?;
        Ok(Some(Operation {
            token,
            owner,
            claim: Some(claim),
            transport,
            active: true,
        }))
    })
}

pub(crate) struct Operation {
    token: ScalarToken,
    owner: OwnerToken,
    claim: Option<ScalarClaimToken>,
    transport: Transport,
    active: bool,
}

impl Operation {
    /// Read bytes leave resident custody only in this original caller's local defer.
    pub(crate) fn run(mut self, out: &mut [u8]) -> Result<u64, i32> {
        loop {
            if crate::threads::cancel::requested() {
                return Err(EINTR);
            }
            let snapshot = crate::shared::with_files(|files| {
                files.data_snapshot(self.token).map_err(crate::error)
            })?;
            if snapshot.result.is_some() {
                self.claim = None;
                // Canonical remote cleanup preserves the result in this ownerSome hold.
                cleanup(self.token);
                let defer = Defer::enter();
                let result = crate::shared::with_files(|files| {
                    files
                        .acknowledge_data(self.token, self.owner, out)
                        .map_err(crate::error)
                });
                wake(self.token);
                drop(defer);
                let result = result?;
                self.active = false;
                return match result {
                    ScalarResult::Bytes(n) => Ok(n),
                    ScalarResult::Failed(errno) => Err(errno),
                };
            }
            if snapshot.owner != Some(self.owner) {
                return Err(EIO);
            }
            if snapshot.phase == ScalarPhase::Cleaning {
                self.claim = None;
                cleanup(self.token);
                crate::threads::sleep::pause(1_000_000)?;
                continue;
            }
            let claim = match self.claim {
                Some(claim) => claim,
                None => match crate::shared::with_files(|files| {
                    files
                        .claim_data(self.token, self.owner)
                        .map_err(crate::error)
                })? {
                    ScalarClaim::Acquired { token, .. } => {
                        self.claim = Some(token);
                        token
                    }
                    ScalarClaim::Busy(helper) => {
                        let _ = crate::relibc::detach_ended_open_owner(helper.value());
                        wait(self.token)?;
                        continue;
                    }
                    ScalarClaim::Complete(_) => continue,
                    ScalarClaim::Cleanup(_) => {
                        terminal_exhausted(self.token, self.owner)?;
                        cleanup(self.token);
                        continue;
                    }
                },
            };
            match advance(claim, self.transport)? {
                Progress::ClaimReleased => self.claim = None,
                Progress::More => {}
                Progress::Commit => {
                    commit(claim)?;
                    self.claim = None;
                }
                Progress::Cache(outcome) => {
                    if cache(claim, self.transport, outcome)? {
                        self.claim = None;
                    }
                }
                Progress::Retired => {
                    terminal_retired(claim, self.owner)?;
                    self.claim = None;
                }
            }
        }
    }
}

// Drop releases the exact effect claim before Point.finish can run user handlers.
impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(claim) = self.claim.take() {
            release(claim);
        }
        if self.active {
            let _ = crate::shared::with_files(|files| {
                files
                    .abandon_data(self.token, self.owner)
                    .map_err(crate::error)
            });
            wake(self.token);
        }
    }
}

enum Progress {
    More,
    ClaimReleased,
    Commit,
    Cache(DataOutcome),
    Retired,
}
fn release(claim: ScalarClaimToken) {
    let _ =
        crate::shared::with_files(|files| files.release_data_claim(claim).map_err(crate::error));
    wake(claim.scalar());
}
fn save(claim: ScalarClaimToken, recovery: posix_fs::data::Recovery) -> Result<(), i32> {
    crate::shared::with_files(|files| files.update_data(claim, recovery).map_err(crate::error))
}

/// Each preparation request runs with neither layer lock nor signal defer held.
#[inline(never)]
fn advance(claim: ScalarClaimToken, transport: Transport) -> Result<Progress, i32> {
    let snapshot =
        crate::shared::with_files(|files| files.data_claim_snapshot(claim).map_err(crate::error))?;
    if snapshot.owner.is_none() {
        release(claim);
        cleanup(claim.scalar());
        return Ok(Progress::ClaimReleased);
    }
    let mut recovery = snapshot.recovery;
    let files = transport.files();
    if recovery.phase == Phase::Starting {
        let context = crate::shared::with_files(|files| {
            files.data_start_context(claim).map_err(crate::error)
        })?;
        match context.send_once() {
            StartResult::Started { phase, job } => {
                recovery.job = job;
                recovery.phase = if recovery.kind().writes() {
                    Phase::Feeding
                } else {
                    Phase::Preparing
                };
                if matches!(phase, DataPhase::Ready | DataPhase::TimeDeferred) {
                    recovery.phase = Phase::Ready;
                }
                save(claim, recovery)?;
            }
            StartResult::Rejected(proof) => {
                crate::shared::with_files(|files| {
                    files
                        .reject_data_start(proof, crate::error)
                        .map_err(crate::error)
                })?;
                wake(claim.scalar());
                return Ok(Progress::ClaimReleased);
            }
            StartResult::Ambiguous(Status::Unknown(proto_fs::AUTHENTICATING)) => {
                release(claim);
                files.finish_binding().map_err(|e| crate::error(e.into()))?;
                return Ok(Progress::ClaimReleased);
            }
            StartResult::Ambiguous(_) => {
                // Unknown Start retains the same key; Query or exact replay follows.
                release(claim);
                return Ok(Progress::ClaimReleased);
            }
        }
    }
    let context =
        crate::shared::with_files(|files| files.data_query_context(claim).map_err(crate::error))?;
    let query = match context.query_once() {
        Ok(query) => query,
        Err(Status::Unknown(proto_fs::AUTHENTICATING)) => {
            release(claim);
            files.finish_binding().map_err(|e| crate::error(e.into()))?;
            return Ok(Progress::ClaimReleased);
        }
        Err(Status::Unknown(proto_fs::OPEN_RETIRED)) => return Ok(Progress::Retired),
        Err(_) => {
            release(claim);
            return Ok(Progress::ClaimReleased);
        }
    };
    if query.outcome.result != DataResult::None {
        return Ok(Progress::Cache(query.outcome));
    }
    if recovery.phase == Phase::Committing {
        if let Some(proof) = query.prepared {
            crate::shared::with_files(|files| {
                files.restore_data_preparation(proof).map_err(crate::error)
            })?;
            wake(claim.scalar());
            // An actual owned Query proves pre-effect continuation after uncertainty.
            if query.outcome.phase == DataPhase::TimeDeferred {
                crate::threads::sleep::pause(1_000_000)?;
            }
            return Ok(Progress::ClaimReleased);
        }
        release(claim);
        return Ok(Progress::ClaimReleased);
    }
    match query.outcome.phase {
        DataPhase::Captured | DataPhase::Feeding if recovery.kind().writes() => {
            let start = recovery.feed_end as usize;
            let end = (start + proto_fs::FEED_MAX).min(recovery.count() as usize);
            if start < end
                && files
                    .data_feed_once(recovery.job, start as u32, &recovery.input()[start..end])
                    .is_ok()
            {
                recovery.feed_end = end as u16;
                recovery.phase = Phase::Feeding;
                save(claim, recovery)?;
            }
            Ok(Progress::More)
        }
        DataPhase::Captured | DataPhase::Preparing => {
            let _ = files.data_step_once(recovery.job);
            Ok(Progress::More)
        }
        DataPhase::Ready | DataPhase::TimeDeferred => {
            recovery.phase = Phase::Ready;
            save(claim, recovery)?;
            Ok(Progress::Commit)
        }
        DataPhase::Completed | DataPhase::Canceling | DataPhase::Feeding => Err(EIO),
    }
}

/// The final defer contains one native Commit and local revocation before handlers.
#[inline(never)]
fn commit(claim: ScalarClaimToken) -> Result<(), i32> {
    let defer = Defer::enter();
    let result = (|| {
        let context = crate::shared::with_files(|files| {
            let mut recovery = files
                .data_claim_snapshot(claim)
                .map_err(crate::error)?
                .recovery;
            recovery.phase = Phase::Committing;
            files.update_data(claim, recovery).map_err(crate::error)?;
            files.data_commit_context(claim).map_err(crate::error)
        })?;
        // Query and ReadResult run after this defer; completed bytes remain server-resident.
        let _ = context.send_once();
        Ok(())
    })();
    release(claim);
    drop(defer);
    result
}

#[inline(never)]
fn cache(claim: ScalarClaimToken, transport: Transport, outcome: DataOutcome) -> Result<bool, i32> {
    let snapshot =
        crate::shared::with_files(|files| files.data_claim_snapshot(claim).map_err(crate::error))?;
    let mut bytes = [0; proto_fs::MAX_READ];
    let count = match outcome.result {
        DataResult::Bytes(n) if snapshot.recovery.kind().reads() => n as usize,
        _ => 0,
    };
    if snapshot.recovery.kind().reads()
        && matches!(outcome.result, DataResult::Bytes(_))
        && transport
            .files()
            .data_read_result_once(key(claim.scalar()), count, &mut bytes)
            .is_err()
    {
        // The known server cache survives interrupted or malformed retrieval.
        return Ok(false);
    }
    crate::shared::with_files(|files| {
        files
            .save_data_result(claim, outcome, &bytes[..count], crate::error)
            .map_err(crate::error)
    })?;
    wake(claim.scalar());
    Ok(true)
}

#[inline(never)]
fn terminal_exhausted(token: ScalarToken, owner: OwnerToken) -> Result<(), i32> {
    crate::shared::with_files(|files| {
        let proof = files
            .exhausted_data_cleanup_authority(token, owner)
            .map_err(crate::error)?;
        files
            .begin_data_terminal_cleanup(token, owner, proof)
            .map_err(crate::error)
    })?;
    wake(token);
    Ok(())
}

#[inline(never)]
fn terminal_retired(claim: ScalarClaimToken, owner: OwnerToken) -> Result<(), i32> {
    let context = crate::shared::with_files(|files| {
        files
            .data_terminal_query_context(claim)
            .map_err(crate::error)
    })?;
    use posix_fs::data::TerminalQueryResult;
    if let TerminalQueryResult::Retired(proof) =
        context.query_once().map_err(|e| crate::error(e.into()))?
    {
        crate::shared::with_files(|files| {
            files
                .begin_data_terminal_cleanup(claim.scalar(), owner, proof)
                .map_err(crate::error)
        })?;
        wake(claim.scalar());
    } else {
        release(claim);
    }
    Ok(())
}

fn cleanup(token: ScalarToken) {
    let context =
        crate::shared::with_files(|files| files.begin_data_cleanup(token).map_err(crate::error));
    if let Ok(context) = context
        && let Ok(proof) = context.send_once()
    {
        let _ = crate::shared::with_files(|files| {
            files.finish_data_cleanup(proof).map_err(crate::error)
        });
        wake(token);
    }
}

fn wake(token: ScalarToken) {
    if let Ok(address) = crate::shared::with_files(|files| {
        files
            .data_wait_word(token)
            .map(|word| word as *const _ as usize)
            .map_err(crate::error)
    }) {
        posix_sync::futex_wake(address as *const core::sync::atomic::AtomicU32, u32::MAX);
    }
}

fn wait(token: ScalarToken) -> Result<(), i32> {
    let (address, wait) = crate::shared::with_files(|files| {
        Ok((
            files.data_wait_word(token).map_err(crate::error)? as *const _ as usize,
            files.data_wait_snapshot(token).map_err(crate::error)?,
        ))
    })?;
    match wait {
        WaitValue::Sequence(sequence) => {
            // SAFETY: the hold header is pinned until process teardown, including reuse.
            let word = unsafe { &*(address as *const core::sync::atomic::AtomicU32) };
            let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(1_000_000);
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

pub(crate) fn detach(owner: u64) {
    let Ok(owner) = OwnerToken::new(owner) else {
        return;
    };
    for _ in 0..posix_fs::OPEN_MAX {
        let abandoned = crate::shared::with_files(|files| Ok(files.abandon_data_owner(owner)));
        let Ok(Some(abandoned)) = abandoned else {
            break;
        };
        use posix_fs::data::ScalarAbandoned;
        let token = match abandoned {
            ScalarAbandoned::Recover { token, .. }
            | ScalarAbandoned::ClaimReleased(token)
            | ScalarAbandoned::Discarded(token) => token,
        };
        wake(token);
    }
}

/// One bounded candidate. Live original operations retain cache before cleanup.
pub(crate) fn help() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CURSOR: AtomicUsize = AtomicUsize::new(0);
    let candidate = crate::shared::with_files(|files| {
        let cursor = CURSOR.load(Ordering::Relaxed);
        let token = files
            .data_tokens()
            .min_by_key(|t| (t.slot() + posix_fs::OPEN_MAX - cursor) % posix_fs::OPEN_MAX);
        if let Some(token) = token {
            CURSOR.store((token.slot() + 1) % posix_fs::OPEN_MAX, Ordering::Relaxed);
        }
        Ok(token)
    });
    let Ok(Some(token)) = candidate else { return };
    let snapshot =
        crate::shared::with_files(|files| files.data_snapshot(token).map_err(crate::error));
    let Ok(snapshot) = snapshot else { return };
    for lifetime in [snapshot.owner, snapshot.claimant].into_iter().flatten() {
        let _ = crate::relibc::detach_ended_open_owner(lifetime.value());
    }
    let snapshot =
        crate::shared::with_files(|files| files.data_snapshot(token).map_err(crate::error));
    let Ok(snapshot) = snapshot else { return };
    if snapshot.owner.is_none()
        || snapshot.result.is_some()
        || snapshot.phase == ScalarPhase::Cleaning
    {
        cleanup(token);
        return;
    }
    if snapshot.recovery.phase != Phase::Committing || snapshot.claimant.is_some() {
        return;
    }
    let Ok(helper) = owner() else { return };
    let claimed = crate::shared::with_files(|files| {
        Ok((
            files.claim_data(token, helper).map_err(crate::error)?,
            files.transport(),
        ))
    });
    if let Ok((ScalarClaim::Acquired { token: claim, .. }, transport)) = claimed {
        let query = crate::shared::with_files(|files| {
            files.data_query_context(claim).map_err(crate::error)
        });
        if let Ok(context) = query
            && let Ok(query) = context.query_once()
        {
            if query.outcome.result != DataResult::None {
                let _ = cache(claim, transport, query.outcome);
            } else if let Some(proof) = query.prepared {
                let _ = crate::shared::with_files(|files| {
                    files.restore_data_preparation(proof).map_err(crate::error)
                });
            }
        }
        release(claim);
    }
}
