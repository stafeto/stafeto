// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real public dup waits on a controlled, paid Open reservation.
//! The fixture uses separate service ownership for its withheld local publication.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use posix_fs::open::{
    Claim, ClaimToken, Completion, OpenPhase, OpenToken, OwnerToken, Phase, Recovery,
};
use posix_fs::{DescriptorFlags, Target};

#[derive(Clone, Copy)]
struct Pending {
    token: OpenToken,
    claim: ClaimToken,
    owner: OwnerToken,
    target: Target,
    fd: u32,
    held: rt::fs::PreparedOpen,
    address: usize,
}
struct Cell(UnsafeCell<Option<Pending>>);
// SAFETY: the C supervisor serializes access; an owner worker publishes before its ready flag.
unsafe impl Sync for Cell {}
static PENDING: Cell = Cell(UnsafeCell::new(None));
fn state() -> Result<Pending, i32> {
    // SAFETY: the supervisor observes the owner's ready flag before inspecting this value.
    unsafe { *PENDING.0.get() }.ok_or(5)
}
fn wake(pending: Pending) {
    posix_sync::futex_wake(pending.address as *const AtomicU32, u32::MAX);
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_begin(source: i32, saturate: i32) -> i32 {
    let result: Result<i32, i32> = (|| {
        let owner = OwnerToken::new(posix_abi::relibc::open_owner()?).map_err(|_| 5)?;
        let (transport, token, claim) = posix_abi::shared::with_files(|files| {
            files.target(source as u32).map_err(posix_abi::error)?;
            let (token, claim) = files
                .begin_open_record(owner, proto_fs::READ_ONLY, DescriptorFlags::default())
                .map_err(posix_abi::error)?;
            Ok((files.transport(), token, claim))
        })?;
        let backend = transport.files();
        let key = proto_fs::OpenKey {
            slot: token.slot() as u32,
            generation: token.generation(),
        };
        let prepared = (|| {
            let job = backend
                .open_start(key, b"/etc/motd", proto_fs::READ_ONLY, 0, 0)
                .map_err(|_| 5)?;
            let mut recovery = Recovery::starting(proto_fs::READ_ONLY, DescriptorFlags::default())
                .map_err(posix_abi::error)?;
            recovery.job = job;
            recovery.phase = Phase::Traversing;
            posix_abi::shared::with_files(|files| {
                files
                    .update_open_record(claim, recovery)
                    .map_err(posix_abi::error)
            })?;
            while !backend.open_advance(job, false).map_err(|_| 5)? {}
            recovery.phase = Phase::Preparing;
            posix_abi::shared::with_files(|files| {
                files
                    .update_open_record(claim, recovery)
                    .map_err(posix_abi::error)
            })?;
            while !backend.open_advance(job, true).map_err(|_| 5)? {}
            let entry = posix_abi::shared::with_files(|files| {
                let entry = files.reserve_open_record(claim).map_err(posix_abi::error)?;
                recovery.phase = Phase::Committing;
                files
                    .update_open_record(claim, recovery)
                    .map_err(posix_abi::error)?;
                Ok(entry)
            })?;
            let held = backend.open_commit(job).map_err(|_| 5)?;
            recovery = recovery.remember(held);
            let target = posix_fs::Transport::opened_target(held, proto_fs::READ_ONLY)
                .map_err(posix_abi::error)?;
            posix_abi::shared::with_files(|files| {
                files
                    .update_open_record(claim, recovery)
                    .map_err(posix_abi::error)?;
                let address = files.open_wait_address(token).map_err(posix_abi::error)?;
                Ok((
                    entry.fd as i32,
                    Pending {
                        token,
                        claim,
                        owner,
                        target,
                        fd: entry.fd,
                        held,
                        address,
                    },
                ))
            })
        })();
        let (fd, pending) = match prepared {
            Ok(value) => value,
            Err(errno) => {
                let canonical = backend.open_cancel_key(key).is_ok();
                let _ = posix_abi::shared::with_files(|files| {
                    let _ = files.begin_open_cancel(claim);
                    files
                        .acknowledge_open_cancel(token, owner, canonical, errno)
                        .map_err(posix_abi::error)
                });
                return Err(errno);
            }
        };
        if saturate != 0 {
            // SAFETY: the address is the table's pinned atomic; saturation keeps its lifetime.
            unsafe { &*(pending.address as *const AtomicU32) }.store(u32::MAX, Ordering::Release);
        }
        // SAFETY: only the supervisor owns the fixture metadata.
        unsafe { *PENDING.0.get() = Some(pending) };
        Ok(fd)
    })();
    result.unwrap_or_else(|errno| -errno)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_waiting() -> i32 {
    state()
        .map(|pending| posix_sync::bucket_waiters(pending.address as *const AtomicU32) as i32)
        .unwrap_or(-1)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_finish(cancel: i32, reuse: i32) -> i32 {
    let result = (|| {
        let pending = state()?;
        if cancel != 0 {
            let transport = posix_abi::shared::with_files(|files| Ok(files.transport()))?;
            // Exact backend cancellation precedes local cancellation and replacement.
            let backend = transport.files();
            let key = proto_fs::OpenKey {
                slot: pending.token.slot() as u32,
                generation: pending.token.generation(),
            };
            if cancel == 2 {
                let mut request = proto_wire::Writer::new();
                proto_fs::Method::OpenCancel
                    .header()
                    .write(&mut request)
                    .map_err(|_| 5)?;
                request.u32(key.slot).map_err(|_| 5)?;
                request.u64(key.generation).map_err(|_| 5)?;
                // This accepted reply is deliberately unread; the helper retries the same key.
                drop(rt::sys::send(backend.sessions().0, request.as_bytes()).map_err(|_| 5)?);
                posix_abi::shared::with_files(|files| {
                    files
                        .begin_open_cancel(pending.claim)
                        .map_err(posix_abi::error)?;
                    Ok(())
                })?;
                wake(pending);
                return Ok(());
            }
            backend.open_cancel_key(key).map_err(|_| 5)?;
            if backend.capture_description(pending.held.fd).is_ok() {
                return Err(5);
            }
            let release = posix_abi::shared::with_files(|files| {
                files
                    .begin_open_cancel(pending.claim)
                    .map_err(posix_abi::error)?;
                let _snapshot = files
                    .finish_open_cancel(pending.token, 22)
                    .map_err(posix_abi::error)?;
                if reuse >= 0 {
                    // Cancellation and replacement precede any worker recheck.
                    let (fd, release) = files
                        .take_dup3(reuse as u32, pending.fd, None)
                        .map_err(posix_abi::error)?;
                    let _ = fd;
                    Ok(release)
                } else {
                    Ok(None)
                }
            })?;
            transport.release(release).map_err(posix_abi::error)?;
        } else {
            let transport = posix_abi::shared::with_files(|files| Ok(files.transport()))?;
            let held = transport
                .files()
                .open_finish(proto_fs::OpenKey {
                    slot: pending.token.slot() as u32,
                    generation: pending.token.generation(),
                })
                .map_err(|_| 5)?;
            if held != pending.held {
                return Err(5);
            }
            posix_abi::shared::with_files(|files| {
                files
                    .stage_open_record(pending.claim, pending.target)
                    .map_err(posix_abi::error)?;
                files
                    .publish_open_record(pending.claim)
                    .map_err(posix_abi::error)?;
                Ok(())
            })?;
        }
        wake(pending);
        Ok(())
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_ack(cancel: i32, expected: i32) -> i32 {
    let result = (|| {
        let pending = state()?;
        let completion = posix_abi::shared::with_files(|files| {
            files
                .ack_open_record(pending.token, pending.owner)
                .map_err(posix_abi::error)
        })?;
        // SAFETY: the supervisor acknowledges once after joining the worker.
        unsafe { *PENDING.0.get() = None };
        if completion
            != if cancel != 0 {
                Completion::Failed(if cancel == 2 { 5 } else { 22 })
            } else {
                Completion::Opened(expected as u32)
            }
        {
            return Err(5);
        }
        Ok(())
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_end() -> ! {
    // The main thread and duplicate worker keep this process alive.
    rt::sys::thread_exit()
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_owner_status() -> i32 {
    let result = (|| {
        let pending = state()?;
        let resident = posix_abi::shared::with_files(|files| {
            files.open_snapshot(pending.token).map_err(posix_abi::error)
        })?;
        if resident.owner != Some(pending.owner) {
            return Err(5);
        }
        // The supervisor never joins this owner, so its native handle and
        // exact relibc lifetime remain retained until the process exits.
        let (_, native) = posix_abi::relibc::target((pending.owner.value() & 63) + 1)?;
        let info = rt::sys::thread_info(&native).map_err(|_| 5)?;
        Ok(if info.state == rt::abi::ThreadState::Ended {
            2
        } else {
            0
        })
    })();
    result.unwrap_or(-1)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_ended_clean() -> i32 {
    let result = (|| {
        let pending = state()?;
        let (transport, live) = posix_abi::shared::with_files(|files| {
            Ok((
                files.transport(),
                files.open_snapshot(pending.token).is_ok(),
            ))
        })?;
        if live
            || transport
                .files()
                .capture_description(pending.held.fd)
                .is_ok()
        {
            return Err(5);
        }
        // SAFETY: the native owner has ended and the supervisor alone clears metadata.
        unsafe { *PENDING.0.get() = None };
        Ok(())
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_dup(source: i32, target: i32, flags: i32) -> i32 {
    let result = if flags == 0 {
        posix_abi::dup2(source, target)
    } else {
        posix_abi::dup3(source, target, posix_abi::constants::O_CLOEXEC)
    };
    result.unwrap_or_else(|errno| -errno)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_child_empty() -> i32 {
    let result = (|| {
        let pending = state()?;
        posix_abi::shared::with_files(|files| {
            if files.open_snapshot(pending.token).is_ok() || files.target(pending.fd).is_ok() {
                return Err(5);
            }
            Ok(())
        })
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_parent_live() -> i32 {
    let result = (|| {
        let pending = state()?;
        let transport = posix_abi::shared::with_files(|files| {
            let snapshot = files
                .open_snapshot(pending.token)
                .map_err(posix_abi::error)?;
            if snapshot.owner != Some(pending.owner) || snapshot.claimant != Some(pending.owner) {
                return Err(5);
            }
            Ok(files.transport())
        })?;
        if !matches!(
            transport.files().open_query(proto_fs::OpenKey {
                slot: pending.token.slot() as u32,
                generation: pending.token.generation(),
            }),
            Ok(rt::fs::OpenOutcome::Active { phase: 3, .. })
        ) {
            return Err(5);
        }
        Ok(())
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_release_original() -> i32 {
    state()
        .and_then(|pending| {
            posix_abi::shared::with_files(|files| {
                files
                    .release_open_claim(pending.claim)
                    .map_err(posix_abi::error)
            })
        })
        .err()
        .unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_claim() -> i32 {
    let result = (|| {
        let pending = state()?;
        let helper = OwnerToken::new(posix_abi::relibc::open_owner()?).map_err(|_| 5)?;
        posix_abi::shared::with_files(|files| {
            if !matches!(
                files.claim_open_record(pending.token, helper),
                Ok(Claim::Acquired { .. })
            ) {
                return Err(5);
            }
            Ok(())
        })
    })();
    result.err().unwrap_or(0)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_claimant_status() -> i32 {
    let result = (|| {
        let pending = state()?;
        let snapshot = posix_abi::shared::with_files(|files| {
            files.open_snapshot(pending.token).map_err(posix_abi::error)
        })?;
        if snapshot.owner != Some(pending.owner) || snapshot.phase != OpenPhase::Reserved {
            return Err(5);
        }
        let Some(helper) = snapshot.claimant else {
            return Ok(1);
        };
        if helper == pending.owner {
            return Err(5);
        }
        let (_, native) = posix_abi::relibc::target((helper.value() & 63) + 1)?;
        Ok(
            if rt::sys::thread_info(&native).map_err(|_| 5)?.state == rt::abi::ThreadState::Ended {
                2
            } else {
                0
            },
        )
    })();
    result.unwrap_or(-1)
}
#[unsafe(no_mangle)]
pub extern "C" fn files_pending_reclaim_original() -> i32 {
    let result = (|| {
        let mut pending = state()?;
        pending.claim = posix_abi::shared::with_files(|files| {
            match files
                .claim_open_record(pending.token, pending.owner)
                .map_err(posix_abi::error)?
            {
                Claim::Acquired { token, .. } => Ok(token),
                _ => Err(5),
            }
        })?;
        // SAFETY: the native helper ended; only the supervisor updates fixture metadata.
        unsafe { *PENDING.0.get() = Some(pending) };
        files_pending_parent_live().eq(&0).then_some(()).ok_or(5)
    })();
    result.err().unwrap_or(0)
}
