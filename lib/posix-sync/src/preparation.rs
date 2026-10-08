// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use core::sync::atomic::Ordering;
use posix_thread::{Block, flag};

pub(crate) fn leave_block(block: &Block) -> bool {
    let old = block.flags.fetch_sub(flag::DEPTH_ONE, Ordering::SeqCst);
    debug_assert!(old >> flag::DEPTH_SHIFT != 0, "balanced critical sections");
    if old >> flag::DEPTH_SHIFT != 1
        || block.scope.load(Ordering::SeqCst) & posix_thread::scope::DELIVERY_PREPARING != 0
    {
        return false;
    }
    if block
        .flags
        .fetch_and(!flag::ENTRY_DEFERRED, Ordering::SeqCst)
        & flag::ENTRY_DEFERRED
        == 0
    {
        return false;
    }
    true
}

/// Local ownership of signal preparation. The caller defers kernel entries
/// before construction and resumes them after this guard is dropped.
pub struct DeliveryPreparation<'a> {
    block: &'a Block,
}

impl<'a> DeliveryPreparation<'a> {
    pub fn begin(block: &'a Block) -> Self {
        let old = block
            .scope
            .fetch_or(posix_thread::scope::DELIVERY_PREPARING, Ordering::SeqCst);
        assert_eq!(
            old & posix_thread::scope::DELIVERY_PREPARING,
            0,
            "unique signal preparation"
        );
        block.flags.fetch_add(flag::DEPTH_ONE, Ordering::SeqCst);
        Self { block }
    }

    /// An outer delivery loop consumes this marker with its existing frame.
    pub fn take_deferred(&self) -> bool {
        self.block
            .flags
            .fetch_and(!flag::ENTRY_DEFERRED, Ordering::SeqCst)
            & flag::ENTRY_DEFERRED
            != 0
    }
}

impl Drop for DeliveryPreparation<'_> {
    fn drop(&mut self) {
        // Preparation keeps the deferred marker until the outer loop drains it.
        let deferred = leave_block(self.block);
        debug_assert!(!deferred);
        self.block
            .scope
            .fetch_and(!posix_thread::scope::DELIVERY_PREPARING, Ordering::SeqCst);
    }
}
