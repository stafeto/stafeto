// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private one-shot value callback after paid Prepare, outside locks and Defer.
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use posix_fs::open::{ClaimToken, OpenToken, OwnerToken};

#[derive(Clone, Copy)]
pub struct Prepared {
    pub owner: OwnerToken,
    pub token: OpenToken,
    pub claim: ClaimToken,
    pub job: u64,
    pub session: rt::abi::Handle,
}
static OWNER: AtomicU64 = AtomicU64::new(0);
static CALLBACK: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static SELECTED_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static SELECTED_GENERATION: AtomicU64 = AtomicU64::new(0);
static DEFERRED_REASON: AtomicU32 = AtomicU32::new(0);

/// The owner registers a permanent function after placing its helper resources
/// in owned escrow. The callback receives values and retains no caller pointer.
pub fn register(owner: u64, callback: fn(Prepared) -> Result<(), i32>) -> Result<(), i32> {
    OwnerToken::new(owner).map_err(|_| crate::constants::EINVAL)?;
    OWNER
        .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| crate::constants::EBUSY)?;
    DEFERRED_REASON.store(0, Ordering::Release);
    CALLBACK.store(callback as usize, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    Ok(())
}
/// Disable first, then end/join the actual helper, then close its owned escrow.
/// The registering owner calls this after its matching public Open returns.
pub fn disable(owner: u64) -> Result<(), i32> {
    if OWNER.load(Ordering::Acquire) != owner {
        return Err(crate::constants::EINVAL);
    }
    ARMED.store(false, Ordering::Release);
    CALLBACK.store(0, Ordering::Release);
    OWNER.store(0, Ordering::Release);
    Ok(())
}
pub(crate) fn prepared(value: Prepared) -> Result<(), i32> {
    if OWNER.load(Ordering::Acquire) != value.owner.value() || !ARMED.swap(false, Ordering::AcqRel)
    {
        return Ok(());
    }
    SELECTED_SLOT.store(value.token.slot(), Ordering::Relaxed);
    SELECTED_GENERATION.store(value.token.generation(), Ordering::Release);
    let address = CALLBACK.load(Ordering::Acquire);
    if address == 0 {
        return Err(crate::constants::EIO);
    }
    // SAFETY: register installed a permanent function of this exact type;
    // the registering owner disables it only after its callback/Open returns.
    let callback: fn(Prepared) -> Result<(), i32> = unsafe { core::mem::transmute(address) };
    callback(value)
}

/// Observe the actual strictly decoded native no-effect receipt for this key.
pub(crate) fn deferred(owner: OwnerToken, token: OpenToken, status: proto_wire::Status) {
    if OWNER.load(Ordering::Acquire) == owner.value()
        && SELECTED_GENERATION.load(Ordering::Acquire) == token.generation()
        && SELECTED_SLOT.load(Ordering::Relaxed) == token.slot()
    {
        DEFERRED_REASON.store(status.code(), Ordering::Release);
    }
}
pub fn deferred_reason() -> u32 {
    DEFERRED_REASON.load(Ordering::Acquire)
}
