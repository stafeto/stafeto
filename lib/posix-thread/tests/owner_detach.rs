// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#[path = "../../posix-abi/src/owner_detach.rs"]
mod driver;
use core::cell::Cell;

#[test]
fn busy_retains_owner_and_debt_without_transition_or_wake() {
    let owner = Cell::new(true);
    let debt = Cell::new(true);
    let transitions = Cell::new(0);
    let wakes = Cell::new(0);
    assert!(!driver::run(32, || Err(()), |_| wakes.set(wakes.get() + 1)));
    assert!(owner.get() && debt.get());
    assert_eq!((transitions.get(), wakes.get()), (0, 0));
    assert!(driver::run(
        32,
        || {
            if owner.replace(false) {
                transitions.set(transitions.get() + 1);
                Ok(Some(Some(17)))
            } else {
                Ok(None)
            }
        },
        |_| wakes.set(wakes.get() + 1)
    ));
    assert!(debt.get());
    assert_eq!((transitions.get(), wakes.get()), (1, 1));
}

#[test]
fn all_retirement_variants_wake_after_unlock_and_full_scan_proves_completion() {
    let borrowed = Cell::new(false);
    let visits = Cell::new(0);
    let wakes = Cell::new(0);
    assert!(driver::run(
        4,
        || {
            borrowed.set(true);
            let visit = visits.get();
            visits.set(visit + 1);
            let result = if visit < 3 {
                Ok(Some(Some(41 + visit)))
            } else {
                Ok(None)
            };
            borrowed.set(false);
            result
        },
        |address| {
            assert!(!borrowed.get());
            assert_eq!(address, 41 + wakes.get());
            wakes.set(wakes.get() + 1);
        }
    ));
    assert_eq!((visits.get(), wakes.get()), (4, 3));
}

#[test]
fn bounded_exhaustion_is_not_completion_and_later_empty_scan_completes() {
    assert!(!driver::run(
        2,
        || Ok(Some(None)),
        |_| panic!("IO has no wake")
    ));
    assert!(driver::run(
        2,
        || Ok(None),
        |_| panic!("empty scan has no wake")
    ));
}

#[test]
fn busy_dispatch_preserves_cursor_and_debt_then_later_recovers() {
    let cursor = Cell::new(1);
    let owner = Cell::new(true);
    let wakes = Cell::new(0);
    driver::when_available(|| Err(()), || panic!("busy dispatch ran helper"));
    assert_eq!(cursor.get(), 1);
    assert!(owner.get());
    assert_eq!(wakes.get(), 0);
    driver::when_available(
        || Ok(()),
        || {
            cursor.set(cursor.get() + 1);
            owner.set(false);
            wakes.set(wakes.get() + 1);
        },
    );
    assert_eq!((cursor.get(), owner.get(), wakes.get()), (2, false, 1));
}
