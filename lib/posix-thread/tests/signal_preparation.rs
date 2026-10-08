// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#[path = "../../posix-sync/src/preparation.rs"]
mod preparation;

use core::sync::atomic::Ordering;
use posix_thread::{Block, flag, scope};
use preparation::{DeliveryPreparation, leave_block};

#[test]
fn repeated_claim_release_keeps_one_preparation_frame() {
    let block = Block::new();
    let guard = DeliveryPreparation::begin(&block);
    for _ in 0..256 {
        // A claim enters, then a new entry marks delivery deferred before leave.
        block.flags.fetch_add(flag::DEPTH_ONE, Ordering::SeqCst);
        block.flags.fetch_or(flag::ENTRY_DEFERRED, Ordering::SeqCst);
        assert!(!leave_block(&block));
        assert_eq!(block.flags.load(Ordering::SeqCst) >> flag::DEPTH_SHIFT, 1);
        assert!(guard.take_deferred());
        assert!(!guard.take_deferred());
    }
    drop(guard);
    assert_eq!(block.flags.load(Ordering::SeqCst) >> flag::DEPTH_SHIFT, 0);
    assert_eq!(block.scope.load(Ordering::SeqCst), 0);
}

#[test]
fn pending_survives_preparation_exit_and_user_callback_can_reenter() {
    let block = Block::new();
    let outer = DeliveryPreparation::begin(&block);
    block.flags.fetch_or(flag::ENTRY_DEFERRED, Ordering::SeqCst);
    drop(outer);
    assert_ne!(block.flags.load(Ordering::SeqCst) & flag::ENTRY_DEFERRED, 0);
    assert_eq!(
        block.scope.load(Ordering::SeqCst) & scope::DELIVERY_PREPARING,
        0
    );
    // A real user callback has no preparation owner and can deliver again.
    let nested = DeliveryPreparation::begin(&block);
    assert!(nested.take_deferred());
    drop(nested);
    block.flags.fetch_add(flag::DEPTH_ONE, Ordering::SeqCst);
    block.flags.fetch_or(flag::ENTRY_DEFERRED, Ordering::SeqCst);
    assert!(leave_block(&block));
}

#[test]
fn preparation_preserves_native_scope_errno_and_outer_critical_depth() {
    let block = Block::new();
    let resident = 7 | scope::NATIVE | scope::FALLBACK | (0x8000_1234u64 << scope::ERRNO_SHIFT);
    block.scope.store(resident, Ordering::SeqCst);
    block
        .flags
        .store(flag::DEPTH_ONE | flag::RAISED_ONE, Ordering::SeqCst);
    let guard = DeliveryPreparation::begin(&block);
    block.flags.fetch_or(flag::ENTRY_DEFERRED, Ordering::SeqCst);
    drop(guard);
    assert_eq!(block.scope.load(Ordering::SeqCst), resident);
    assert_eq!(block.flags.load(Ordering::SeqCst) >> flag::DEPTH_SHIFT, 1);
    assert_ne!(block.flags.load(Ordering::SeqCst) & flag::RAISED_MASK, 0);
    assert!(leave_block(&block));
}
