// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Epoch words shared by the process service and signal delivery.
use crate::{SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU};
use core::sync::atomic::{AtomicU64, Ordering};

pub const MASK: u64 =
    (1 << (SIGCONT - 1)) | (1 << (SIGTSTP - 1)) | (1 << (SIGTTIN - 1)) | (1 << (SIGTTOU - 1));

#[derive(Clone, Copy)]
pub struct Class {
    pub low: u64,
    pub bit: u64,
    pub shift: u32,
}

pub const fn class(signal: u8) -> Option<Class> {
    match signal {
        SIGCONT => Some(Class {
            low: 1,
            bit: 1,
            shift: 1,
        }),
        SIGTSTP => Some(Class {
            low: 7,
            bit: 1,
            shift: 3,
        }),
        SIGTTIN => Some(Class {
            low: 7,
            bit: 2,
            shift: 3,
        }),
        SIGTTOU => Some(Class {
            low: 7,
            bit: 4,
            shift: 3,
        }),
        _ => None,
    }
}

pub const fn bits(stop: u64, cont: u64) -> u64 {
    ((stop & 7) << (SIGTSTP - 1)) | ((cont & 1) << (SIGCONT - 1))
}

/// Bits whose epoch is still the authority's epoch.
pub fn live(word: &AtomicU64, authority: &AtomicU64, class: Class) -> u64 {
    let current = authority.load(Ordering::Acquire) & !class.low;
    let word = word.load(Ordering::Acquire);
    if word & !class.low == current {
        word & class.low
    } else {
        0
    }
}

/// Assign or return a signal only within its original epoch.
pub fn insert(word: &AtomicU64, authority: &AtomicU64, signal: u8, ticket: u64) -> bool {
    let Some(c) = class(signal) else { return false };
    if ticket & c.low != 0 {
        return false;
    }
    let mut before = word.load(Ordering::Acquire);
    loop {
        if authority.load(Ordering::Acquire) & !c.low != ticket || before & !c.low > ticket {
            return false;
        }
        let kept = if before & !c.low == ticket {
            before & c.low
        } else {
            0
        };
        match word.compare_exchange(
            before,
            ticket | kept | c.bit,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return authority.load(Ordering::Acquire) & !c.low == ticket,
            Err(now) => before = now,
        }
    }
}

/// Take a bit together with its epoch; a cancelled assignment disappears.
pub fn take(word: &AtomicU64, authority: &AtomicU64, signal: u8) -> Option<u64> {
    let c = class(signal)?;
    take_ticket(
        word,
        authority,
        signal,
        word.load(Ordering::Acquire) & !c.low,
    )
}

/// Claim only the captured epoch, so a local fast path cannot take a new
/// process-origin assignment after cancellation and publication.
pub fn take_ticket(
    word: &AtomicU64,
    authority: &AtomicU64,
    signal: u8,
    ticket: u64,
) -> Option<u64> {
    let c = class(signal)?;
    let mut before = word.load(Ordering::Acquire);
    loop {
        if before & !c.low != ticket
            || before & c.bit == 0
            || authority.load(Ordering::Acquire) & !c.low != ticket
        {
            return None;
        }
        match word.compare_exchange(before, before & !c.bit, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return (authority.load(Ordering::Acquire) & !c.low == ticket).then_some(ticket);
            }
            Err(now) => before = now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_rejects_assignment_take_and_return() {
        let page = AtomicU64::new(0);
        let thread = AtomicU64::new(0);
        assert!(insert(&thread, &page, SIGTTIN, 0));
        page.store(8, Ordering::Release);
        assert_eq!(live(&thread, &page, class(SIGTTIN).unwrap()), 0);
        assert_eq!(take(&thread, &page, SIGTTIN), None);
        assert!(!insert(&page, &page, SIGTTIN, 0));
        assert!(insert(&thread, &page, SIGTSTP, 8));
        assert_eq!(take_ticket(&thread, &page, SIGTSTP, 0), None);
        assert_eq!(thread.load(Ordering::Acquire), 9);
        assert!(insert(&thread, &page, SIGTTOU, 8));
        assert_eq!(take(&thread, &page, SIGTSTP), Some(8));
        assert_eq!(take(&thread, &page, SIGTTOU), Some(8));
        assert_eq!(take(&thread, &page, SIGTSTP), None);
    }

    #[test]
    fn continuation_has_an_independent_epoch() {
        let page = AtomicU64::new(4);
        let thread = AtomicU64::new(2);
        assert!(!insert(&thread, &page, SIGCONT, 2));
        assert!(insert(&thread, &page, SIGCONT, 4));
        assert_eq!(take(&thread, &page, SIGCONT), Some(4));
        assert_eq!(
            bits(5, 1),
            (1 << (SIGTSTP - 1)) | (1 << (SIGTTOU - 1)) | (1 << (SIGCONT - 1))
        );
    }
}
