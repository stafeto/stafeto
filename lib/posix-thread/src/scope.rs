// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use core::sync::atomic::{AtomicU64, Ordering};

pub const DEPTH_MASK: u64 = (1 << 29) - 1;
pub const NATIVE: u64 = 1 << 29;
pub const FALLBACK: u64 = 1 << 30;
pub const DELIVERY_PREPARING: u64 = 1 << 31;
pub const ERRNO_SHIFT: u32 = 32;
/// Return the previous depth; every other field survives the CAS.
pub fn enter(word: &AtomicU64) -> Option<u64> {
    word.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        (old & NATIVE != 0 && old & DEPTH_MASK != DEPTH_MASK).then(|| old + 1)
    })
    .map(|old| old & DEPTH_MASK)
    .ok()
}

pub fn leave(word: &AtomicU64) {
    word.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        (old & DEPTH_MASK != 0).then(|| (old & !DEPTH_MASK) | ((old & DEPTH_MASK) - 1))
    })
    .expect("balanced native scopes");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_scopes_preserve_preparing_tags_and_full_errno() {
        let original = NATIVE | FALLBACK | DELIVERY_PREPARING | (0x8000_1234u64 << 32);
        let word = AtomicU64::new(original);
        assert_eq!(enter(&word), Some(0));
        assert_eq!(enter(&word), Some(1));
        leave(&word);
        leave(&word);
        assert_eq!(word.load(Ordering::Acquire), original);
    }
    #[test]
    fn overflow_and_uninstalled_scope_have_no_effect() {
        let word = AtomicU64::new(u64::MAX);
        assert_eq!(enter(&word), None);
        assert_eq!(word.load(Ordering::Acquire), u64::MAX);
        word.store(FALLBACK | (12 << 32), Ordering::Release);
        assert_eq!(enter(&word), None);
        assert_eq!(word.load(Ordering::Acquire), FALLBACK | (12 << 32));
    }
    #[test]
    fn preparing_changes_between_enter_and_leave_survive() {
        let word = AtomicU64::new(NATIVE | (34 << 32));
        assert_eq!(enter(&word), Some(0));
        word.fetch_or(DELIVERY_PREPARING, Ordering::SeqCst);
        leave(&word);
        assert_eq!(
            word.load(Ordering::Acquire),
            NATIVE | DELIVERY_PREPARING | (34 << 32)
        );
    }
}
