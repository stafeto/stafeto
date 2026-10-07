// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private one-shot observation of exact resident data custody outside locks.
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use posix_fs::data::{DataState, OwnerToken, ScalarClaimToken, ScalarToken};

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum Stage {
    CapturedBeforeStart,
    ReadyBeforeCommit,
    ClaimReleasedAfterCommit,
}

#[derive(Clone, Copy)]
pub struct Event {
    pub owner: OwnerToken,
    pub token: ScalarToken,
    pub claim: Option<ScalarClaimToken>,
    pub state: DataState,
}

static OWNER: AtomicU64 = AtomicU64::new(0);
static STAGE: AtomicU8 = AtomicU8::new(0);
static CALLBACK: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

/// The exact original owner installs a permanent callback after preparing its
/// owned helper resources. The first matching event selects one resident token.
pub fn register(
    owner: u64,
    stage: Stage,
    callback: fn(Event) -> Result<(), i32>,
) -> Result<(), i32> {
    OwnerToken::new(owner).map_err(|_| crate::constants::EINVAL)?;
    OWNER
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| crate::constants::EBUSY)?;
    STAGE.store(stage as u8, Ordering::Relaxed);
    CALLBACK.store(callback as usize, Ordering::Relaxed);
    ARMED.store(true, Ordering::Release);
    Ok(())
}

/// Disable precedes native helper End/join and release of the owned escrow.
pub fn disable(owner: u64) -> Result<(), i32> {
    if OWNER.load(Ordering::Acquire) != owner {
        return Err(crate::constants::EINVAL);
    }
    ARMED.store(false, Ordering::Release);
    CALLBACK.store(0, Ordering::Release);
    OWNER.store(0, Ordering::Release);
    Ok(())
}

pub(crate) fn observe(stage: Stage, event: Event) -> Result<(), i32> {
    if OWNER.load(Ordering::Acquire) != event.owner.value()
        || STAGE.load(Ordering::Relaxed) != stage as u8
        || !ARMED.swap(false, Ordering::AcqRel)
    {
        return Ok(());
    }
    let address = CALLBACK.load(Ordering::Acquire);
    if address == 0 || event.state.owner != Some(event.owner) {
        return Err(crate::constants::EIO);
    }
    // SAFETY: register installs a permanent callback of this exact type;
    // the same owner disables it after the operation/callback has returned.
    let callback: fn(Event) -> Result<(), i32> = unsafe { core::mem::transmute(address) };
    callback(event)
}

pub(crate) fn disarm_failed_commit(owner: OwnerToken) {
    if OWNER.load(Ordering::Acquire) == owner.value() {
        // SAFETY: the isolated guest kernel accepts this value-only disarm.
        // It releases any arm which local preflight prevented from reaching IPC.
        let _ = unsafe { rt::sys::raw::<0xffe2>([0; 10]) };
    }
}
