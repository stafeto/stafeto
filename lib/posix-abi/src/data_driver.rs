// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact paid data custody, with one final native call under signal defer.

use crate::constants::*;
use posix_fs::data::{
    DataKind, DataOutcome, DataPhase, DataResult, OwnerToken, Phase, ScalarClaimState,
    ScalarClaimToken, ScalarPhase, ScalarResult, ScalarToken, StartResult, WaitValue,
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

/// Recover the original call object from its retained, exact paid Table entry.
#[cfg(feature = "full-capacity-probe")]
pub(crate) fn retained_operation(token: ScalarToken) -> Result<Operation, i32> {
    let owner = owner()?;
    crate::shared::with_files(|files| {
        files
            .retained_data_byte(token, owner)
            .map_err(crate::error)?;
        Ok(Operation {
            token,
            owner,
            claim: None,
            transport: files.transport(),
            active: true,
        })
    })
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
    let operation = crate::shared::with_files(|files| {
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
    })?;
    #[cfg(feature = "data-driver-probe")]
    if let Some(operation) = &operation {
        operation.observe(crate::data_probe::Stage::CapturedBeforeStart)?;
    }
    Ok(operation)
}

pub(crate) struct Operation {
    token: ScalarToken,
    owner: OwnerToken,
    claim: Option<ScalarClaimToken>,
    transport: Transport,
    active: bool,
}

impl Operation {
    #[cfg(feature = "data-driver-probe")]
    fn observe(&self, stage: crate::data_probe::Stage) -> Result<(), i32> {
        let state =
            crate::shared::with_files(|files| files.data_state(self.token).map_err(crate::error))?;
        crate::data_probe::observe(
            stage,
            crate::data_probe::Event {
                owner: self.owner,
                token: self.token,
                claim: self.claim,
                state,
            },
        )
    }

    /// Read bytes leave resident custody only in this original caller's local defer.
    pub(crate) fn run(self, out: &mut [u8]) -> Result<u64, i32> {
        self.run_inner(
            out,
            #[cfg(feature = "full-capacity-probe")]
            false,
        )
    }

    /// The private capacity actor retains the actual paid result in its Table.
    #[cfg(feature = "full-capacity-probe")]
    pub(crate) fn run_until_retained(self) -> Result<ScalarToken, i32> {
        crate::shared::with_files(|files| {
            let state = files.data_state(self.token).map_err(crate::error)?;
            if state.owner != Some(self.owner) || state.kind != DataKind::PRead || state.count != 1
            {
                return Err(EIO);
            }
            Ok(())
        })?;
        let token = self.token;
        self.run_inner(&mut [0; 1], true)?;
        Ok(token)
    }

    fn run_inner(
        mut self,
        out: &mut [u8],
        #[cfg(feature = "full-capacity-probe")] retain: bool,
    ) -> Result<u64, i32> {
        loop {
            if crate::threads::cancel::requested() {
                return Err(EINTR);
            }
            let snapshot = crate::shared::with_files(|files| {
                files.data_state(self.token).map_err(crate::error)
            })?;
            if snapshot.result.is_some() {
                #[cfg(feature = "full-capacity-probe")]
                if retain {
                    if let Some(ScalarResult::Failed(errno)) = snapshot.result {
                        return Err(errno);
                    }
                    let session = self.transport.files().sessions().0.raw();
                    crate::shared::with_files(|files| {
                        if files.sessions().0.raw() != session {
                            return Err(EIO);
                        }
                        // This exact view validates the complete saved byte and
                        // the owner, claimant, job, phase, pin and session.
                        files
                            .retained_data_byte(self.token, self.owner)
                            .map_err(crate::error)
                    })?;
                    self.claim = None;
                    self.active = false;
                    return Ok(1);
                }
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
                        .claim_data_token(self.token, self.owner)
                        .map_err(crate::error)
                })? {
                    ScalarClaimState::Acquired(token) => {
                        self.claim = Some(token);
                        token
                    }
                    ScalarClaimState::Busy(helper) => {
                        let _ = crate::relibc::detach_ended_open_owner(helper.value());
                        wait(self.token)?;
                        continue;
                    }
                    ScalarClaimState::Complete(_) => continue,
                    ScalarClaimState::Cleanup => {
                        terminal_exhausted(self.token, self.owner)?;
                        cleanup(self.token);
                        continue;
                    }
                },
            };
            match advance(claim, self.transport)? {
                Progress::ClaimReleased => self.claim = None,
                Progress::More => {}
                Progress::Feed(job) => feed(claim, job)?,
                Progress::Commit => {
                    #[cfg(feature = "data-driver-probe")]
                    self.observe(crate::data_probe::Stage::ReadyBeforeCommit)?;
                    let committed = commit(claim);
                    #[cfg(feature = "data-driver-probe")]
                    if committed.is_err() {
                        crate::data_probe::disarm_failed_commit(self.owner);
                    }
                    committed?;
                    self.claim = None;
                    #[cfg(feature = "data-driver-probe")]
                    self.observe(crate::data_probe::Stage::ClaimReleasedAfterCommit)?;
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
    #[inline(never)]
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
    Feed(u64),
    Cache(DataOutcome),
    Retired,
}
fn release(claim: ScalarClaimToken) {
    let _ =
        crate::shared::with_files(|files| files.release_data_claim(claim).map_err(crate::error));
    wake(claim.scalar());
}
fn progress(claim: ScalarClaimToken, phase: Phase, job: u64, feed_end: u16) -> Result<(), i32> {
    crate::shared::with_files(|files| {
        files
            .set_data_progress(claim, phase, job, feed_end)
            .map_err(crate::error)
    })
}

/// Each preparation request runs with neither layer lock nor signal defer held.
#[inline(never)]
fn advance(claim: ScalarClaimToken, transport: Transport) -> Result<Progress, i32> {
    let snapshot =
        crate::shared::with_files(|files| files.data_claim_state(claim).map_err(crate::error))?;
    if snapshot.owner.is_none() {
        release(claim);
        return Ok(Progress::ClaimReleased);
    }
    let state = snapshot;
    let files = transport.files();
    if state.progress == Phase::Starting {
        return start(claim, transport, state.kind);
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
    if state.progress == Phase::Committing {
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
        DataPhase::Captured | DataPhase::Feeding if state.kind.writes() => {
            if u32::from(state.feed_end) < state.count {
                Ok(Progress::Feed(state.job))
            } else if u32::from(state.feed_end) == state.count {
                // The immutable input is fully acknowledged, including count
                // zero. Preparation keeps this same key, job and held target.
                progress(claim, Phase::Preparing, state.job, state.feed_end)?;
                let _ = files.data_step_once(state.job);
                Ok(Progress::More)
            } else {
                Err(EIO)
            }
        }
        DataPhase::Captured | DataPhase::Preparing => {
            let _ = files.data_step_once(state.job);
            Ok(Progress::More)
        }
        DataPhase::Ready | DataPhase::TimeDeferred => {
            progress(claim, Phase::Ready, state.job, state.feed_end)?;
            Ok(Progress::Commit)
        }
        DataPhase::Completed | DataPhase::Canceling | DataPhase::Feeding => Err(EIO),
    }
}

/// Start and its exact rejection have their own bounded frame.
#[inline(never)]
fn start(claim: ScalarClaimToken, transport: Transport, kind: DataKind) -> Result<Progress, i32> {
    let context =
        crate::shared::with_files(|files| files.data_start_context(claim).map_err(crate::error))?;
    match context.send_once() {
        StartResult::Started { phase, job } => {
            let phase = if matches!(phase, DataPhase::Ready | DataPhase::TimeDeferred) {
                Phase::Ready
            } else if kind.writes() {
                Phase::Feeding
            } else {
                Phase::Preparing
            };
            progress(claim, phase, job, 0)?;
            Ok(Progress::More)
        }
        StartResult::Rejected(proof) => {
            crate::shared::with_files(|files| {
                files
                    .reject_data_start(proof, crate::error)
                    .map_err(crate::error)
            })?;
            wake(claim.scalar());
            Ok(Progress::ClaimReleased)
        }
        StartResult::Ambiguous(error) => {
            // Unknown Start retains the same key; exact replay follows.
            release(claim);
            if error == Status::Unknown(proto_fs::AUTHENTICATING) {
                transport
                    .files()
                    .finish_binding()
                    .map_err(|e| crate::error(e.into()))?;
            }
            Ok(Progress::ClaimReleased)
        }
    }
}

/// The owned feed copy has a separate frame from the preparation driver.
#[inline(never)]
fn feed(claim: ScalarClaimToken, job: u64) -> Result<(), i32> {
    let context =
        crate::shared::with_files(|files| files.data_feed_context(claim).map_err(crate::error))?;
    if context.send_once().is_ok() {
        progress(claim, Phase::Feeding, job, context.end())?;
    }
    Ok(())
}

/// The final defer contains one native Commit and local revocation before handlers.
#[inline(never)]
fn commit(claim: ScalarClaimToken) -> Result<(), i32> {
    let defer = Defer::enter();
    let result = (|| {
        let context = crate::shared::with_files(|files| {
            let state = files.data_claim_state(claim).map_err(crate::error)?;
            files
                .set_data_progress(claim, Phase::Committing, state.job, state.feed_end)
                .map_err(crate::error)?;
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
        crate::shared::with_files(|files| files.data_claim_state(claim).map_err(crate::error))?;
    let mut bytes = [0; proto_fs::MAX_READ];
    let count = match outcome.result {
        DataResult::Bytes(n) if snapshot.kind.reads() => n as usize,
        _ => 0,
    };
    if snapshot.kind.reads()
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
        files
            .begin_data_exhausted_cleanup(token, owner)
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
    use posix_fs::data::TerminalSmallQueryResult;
    if let TerminalSmallQueryResult::Retired(marker) = context
        .query_small_once()
        .map_err(|e| crate::error(e.into()))?
    {
        crate::shared::with_files(|files| {
            files
                .begin_data_terminal_cleanup_from_query(claim.scalar(), owner, &context, marker)
                .map_err(crate::error)
        })?;
        wake(claim.scalar());
    } else {
        release(claim);
    }
    Ok(())
}

#[inline(never)]
fn cleanup(token: ScalarToken) {
    let context =
        crate::shared::with_files(|files| files.begin_data_cleanup(token).map_err(crate::error));
    if let Ok(context) = context
        && let Ok(proof) = context.send_small_once()
    {
        let _ = crate::shared::with_files(|files| {
            files
                .finish_data_cleanup_from_context(&context, proof)
                .map_err(crate::error)
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
    let snapshot = crate::shared::with_files(|files| files.data_state(token).map_err(crate::error));
    let Ok(snapshot) = snapshot else { return };
    for lifetime in [snapshot.owner, snapshot.claimant].into_iter().flatten() {
        let _ = crate::relibc::detach_ended_open_owner(lifetime.value());
    }
    let snapshot = crate::shared::with_files(|files| files.data_state(token).map_err(crate::error));
    let Ok(snapshot) = snapshot else { return };
    if snapshot.owner.is_none()
        || snapshot.result.is_some()
        || snapshot.phase == ScalarPhase::Cleaning
    {
        cleanup(token);
        return;
    }
    if snapshot.progress != Phase::Committing || snapshot.claimant.is_some() {
        return;
    }
    let Ok(helper) = owner() else { return };
    let claimed = crate::shared::with_files(|files| {
        Ok((
            files
                .claim_data_token(token, helper)
                .map_err(crate::error)?,
            files.transport(),
        ))
    });
    if let Ok((ScalarClaimState::Acquired(claim), transport)) = claimed {
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
