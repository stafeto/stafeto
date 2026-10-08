// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#[path = "../../posix-abi/src/relibc/exit_intent.rs"]
mod exit_intent;
use core::cell::Cell;

struct Deferral<'a>(&'a Cell<bool>);
impl Drop for Deferral<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[test]
fn queued_primary_end_cannot_run_between_intent_and_retval() {
    let primary_ran = Cell::new(false);
    let retval = Cell::new(None);
    let intent = Cell::new(false);
    assert!(exit_intent::hold::<_, ()>(
        Ok(Deferral(&primary_ran)),
        || {
            assert!(!primary_ran.get());
            intent.set(true);
        }
    ));
    retval.set(Some(37));
    assert!(!primary_ran.get(), "common Defer survives libc retval.post");
    assert!(intent.get());
    assert_eq!(retval.get(), Some(37));
    // Only the real nonreturning ThreadExit ends the held kernel level.
}

#[test]
fn failed_defer_publishes_no_intent_or_retval() {
    let intent = Cell::new(false);
    let retval = Cell::new(None);
    assert!(!exit_intent::hold::<(), _>(Err(()), || {
        intent.set(true);
        retval.set(Some(37));
    }));
    assert!(!intent.get());
    assert_eq!(retval.get(), None);
}

#[test]
fn managed_exit_has_no_defer_or_early_intent() {
    assert!(exit_intent::hold_native::<(), ()>(
        false,
        || panic!("managed exit must keep its prior deferral path"),
        || panic!("managed exit publishes EXITED only at exit_thread")
    ));
}

#[test]
fn native_selection_defers_before_publication() {
    let held = Cell::new(false);
    let published = Cell::new(false);
    assert!(exit_intent::hold_native::<_, ()>(
        true,
        || {
            held.set(true);
            Ok(())
        },
        || {
            assert!(held.get());
            published.set(true);
        }
    ));
    assert!(published.get());
    published.set(false);
    assert!(!exit_intent::hold_native::<(), _>(
        true,
        || Err(()),
        || published.set(true)
    ));
    assert!(!published.get());
}
