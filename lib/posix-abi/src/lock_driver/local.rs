// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Atomic exact-token transitions tolerate retirement by another cleanup helper.

use super::local_types::{
    ControlClaimToken, ControlPhase, ControlResult, ControlToken, FsError, OwnerToken, PosixFs,
    control,
};

pub fn snapshot(
    files: &PosixFs,
    token: ControlToken,
    owner: Option<OwnerToken>,
) -> Result<Option<control::Snapshot>, FsError> {
    match files.control_snapshot(token) {
        Ok(snapshot) => {
            let lock = snapshot.recovery.lock().ok_or(FsError::Io)?;
            if snapshot.result.is_some() != lock.outcome().is_some() {
                return Err(FsError::Io);
            }
            Ok(Some(snapshot))
        }
        Err(FsError::BadFileDescriptor) if owner.is_none() => Ok(None),
        Err(_) => Err(FsError::Io),
    }
}

pub fn publish(
    files: &mut PosixFs,
    token: ControlToken,
    claim: Option<ControlClaimToken>,
    owner: Option<OwnerToken>,
    result: ControlResult,
    terminal: control::TerminalReply,
) -> Result<(), FsError> {
    let Some(current) = snapshot(files, token, owner)? else {
        return Ok(());
    };
    if current.result.is_some() {
        return Ok(());
    }
    if let Some(claim) = claim.filter(|&claim| files.lock_is_live(claim)) {
        files.complete_lock_record(claim, result, terminal)?;
    } else {
        if current.phase != ControlPhase::Cleaning {
            let reason = current.recovery.lock().ok_or(FsError::Io)?.cancel_reason();
            files.begin_lock_cleanup(token, reason)?;
        }
        files.publish_lock_cleanup(token, result, terminal)?;
    }
    Ok(())
}

pub fn begin(
    files: &mut PosixFs,
    token: ControlToken,
    owner: Option<OwnerToken>,
) -> Result<(), FsError> {
    let Some(current) = snapshot(files, token, owner)? else {
        return Ok(());
    };
    if !matches!(
        current.phase,
        ControlPhase::Cleaning | ControlPhase::Cleaned
    ) {
        let reason = current.recovery.lock().ok_or(FsError::Io)?.cancel_reason();
        files.begin_lock_cleanup(token, reason)?;
    }
    Ok(())
}

pub fn finish(
    files: &mut PosixFs,
    token: ControlToken,
    owner: Option<OwnerToken>,
) -> Result<(), FsError> {
    if snapshot(files, token, owner)?.is_some() {
        files.finish_lock_cleanup(token)?;
    }
    Ok(())
}
