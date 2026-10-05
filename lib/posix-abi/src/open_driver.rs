// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident Open ownership precedes every request; final handoff has a bounded defer.

use crate::constants::*;
use posix_fs::open::{Abandoned, ClaimToken, OpenPhase, OpenToken, OwnerToken, Phase, Recovery};
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
    let (token, claim) = crate::shared::with_files(|files| {
        files
            .begin_open_record(owner, flags & 3)
            .map_err(crate::error)
    })?;
    let mut recovery = Recovery {
        access: (flags & 3) as u8,
        ..Recovery::default()
    };
    let files = transport.files();
    let result = (|| {
        recovery.job = files
            .open_start(key(token), path, flags, mode, umask)
            .map_err(protocol)?;
        recovery.phase = Phase::Traversing;
        save(claim, recovery)?;
        while !files.open_advance(recovery.job, false).map_err(protocol)? {}
        recovery.phase = Phase::Preparing;
        save(claim, recovery)?;
        while !files.open_advance(recovery.job, true).map_err(protocol)? {}
        let _defer = Defer::enter();
        let final_result = (|| {
            crate::shared::with_files(|files| {
                files
                    .reserve_open_record(claim, descriptor_flags)
                    .map_err(crate::error)
            })?;
            recovery.phase = Phase::Committing;
            save(claim, recovery)?;
            let held = files.open_commit_once(recovery.job).map_err(protocol)?;
            recovery = recovery.remember(held);
            save(claim, recovery)?;
            let target =
                Transport::opened_target(held, recovery.access as u32).map_err(crate::error)?;
            crate::shared::with_files(|files| {
                files.stage_open_record(claim, target).map_err(crate::error)
            })?;
            let finished = files.open_finish_once(key(token)).map_err(protocol)?;
            if finished != held {
                return Err(EIO);
            }
            crate::shared::with_files(|files| {
                files.publish_open_record(claim).map_err(crate::error)?;
                files
                    .ack_open_record(token, owner)
                    .map_err(crate::error)?
                    .into_result()
            })
        })();
        if final_result.is_err() {
            // Revoke the claim before deferred handlers can encounter Pending.
            let _ = crate::shared::with_files(|files| {
                files.begin_open_cancel(claim).map_err(crate::error)
            });
        }
        final_result
    })();
    if let Err(errno) = result {
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
    let _ = crate::shared::with_files(|files| {
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
        Ok(())
    });
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
    if transport.files().open_cancel_key_once(key(token)).is_ok() {
        let _ = crate::shared::with_files(|files| {
            let _snapshot = files.finish_open_cancel(token, EIO).map_err(crate::error)?;
            Ok(())
        });
    }
}
