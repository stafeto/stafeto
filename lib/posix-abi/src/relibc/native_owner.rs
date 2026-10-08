// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact raw capability ownership under the exclusive TABLE borrow.
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(super) fn close_u64(field: &AtomicU64, close: impl FnOnce(u64) -> bool) -> bool {
    let raw = field.load(Ordering::Acquire);
    if raw != 0 && !close(raw) {
        return false;
    }
    field.store(0, Ordering::Release);
    true
}

pub(super) fn close_usize(field: &AtomicUsize, close: impl FnOnce(u64) -> bool) -> bool {
    let raw = field.load(Ordering::Acquire);
    if raw != 0 && !close(raw as u64) {
        return false;
    }
    field.store(0, Ordering::Release);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn returned_error_preserves_exact_owner_then_success_disarms_once() {
        let slot = AtomicU64::new(0x1234_0000_0042);
        assert!(!close_u64(&slot, |raw| {
            assert_eq!(raw, 0x1234_0000_0042);
            false
        }));
        assert_eq!(slot.load(Ordering::Acquire), 0x1234_0000_0042);
        assert!(close_u64(&slot, |raw| {
            assert_eq!(raw, 0x1234_0000_0042);
            true
        }));
        assert_eq!(slot.load(Ordering::Acquire), 0);
        assert!(close_u64(&slot, |_| panic!(
            "empty slot has no Close effect"
        )));
    }
    #[test]
    fn timer_slot_uses_the_same_retention_rule() {
        let slot = AtomicUsize::new(77);
        assert!(!close_usize(&slot, |raw| {
            assert_eq!(raw, 77);
            false
        }));
        assert_eq!(slot.load(Ordering::Acquire), 77);
        assert!(close_usize(&slot, |_| true));
        assert!(close_usize(&slot, |_| panic!(
            "closed timer stays disarmed"
        )));
    }
}
