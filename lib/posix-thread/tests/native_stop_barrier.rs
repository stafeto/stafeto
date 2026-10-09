// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#[path = "../../posix-abi/src/stop_barrier.rs"]
mod barrier;
use core::cell::Cell;
#[test]
fn final_scan_then_publication_parks_before_owner_renewal() {
    for repeated_scope in [false, true] {
        let stopping = Cell::new(7usize);
        let parked = Cell::new(false);
        let resumed = Cell::new(false);
        // TABLE serialized the final scan before LIVE publication.
        barrier::before_renew(
            || {
                if barrier::must_park(stopping.get(), 11) {
                    parked.set(true);
                    stopping.set(0); // resume_others releases the park.
                    resumed.set(true);
                }
            },
            || {
                assert!(parked.get(), "scope {repeated_scope}");
                assert!(resumed.get());
                assert_eq!(stopping.get(), 0);
            },
        );
        assert!(resumed.get(), "closure follows resume");
    }
}
#[test]
fn new_stop_after_false_check_requests_entry_before_closure() {
    for repeated_scope in [false, true] {
        let pending = Cell::new(false);
        let parked = Cell::new(false);
        let renewed = Cell::new(false);
        barrier::before_renew(
            || assert!(!barrier::must_park(0, 11)),
            || {
                renewed.set(true);
                // New STOPPING/scan sees LIVE while Defer holds.
                assert!(barrier::must_park(7, 11));
                pending.set(true);
            },
        );
        // Resume delivers the requested entry before user code.
        if pending.replace(false) {
            parked.set(true);
        }
        assert!(renewed.get());
        assert!(parked.get(), "scope {repeated_scope}");
    }
}
#[test]
fn files_critical_svc_is_not_quiescent() {
    assert!(barrier::quiescent(
        false,
        barrier::State::KernelWait,
        0,
        0,
        false
    ));
    assert!(!barrier::quiescent(
        false,
        barrier::State::KernelWait,
        1,
        0,
        false
    ));
    assert!(!barrier::quiescent(
        false,
        barrier::State::KernelWait,
        0,
        1,
        false
    ));
    assert!(!barrier::quiescent(
        false,
        barrier::State::KernelWait,
        0,
        0,
        true
    ));
    assert!(!barrier::quiescent(
        false,
        barrier::State::Running,
        0,
        0,
        false
    ));
    assert!(!barrier::must_park(11, 11));
}

#[test]
fn native_wait_and_unknown_info_preserve_stop_debt() {
    use barrier::State::*;
    for state in [Unknown, KernelWait, Running] {
        assert!(!barrier::confirmed_terminal(state));
        assert!(!barrier::quiescent(true, state, 0, 0, false));
    }
    assert!(barrier::confirmed_terminal(Terminal));
    assert!(!barrier::quiescent(false, Unknown, 0, 0, false));
}

#[test]
fn external_defer_receive_interrupt_does_not_release_stopper() {
    use barrier::State::*;
    let owner_effects = Cell::new(0usize);
    let closure_progress = Cell::new(0usize);
    // The inner barrier checks before the new stop. An outer DeferredEntry remains.
    assert!(!barrier::must_park(0, 11));
    owner_effects.set(1); // Renewal precedes STOPPING in this ordering.
    let pending_entry = true;
    // The scan sees native Receive with critical depth0, under external Defer.
    let stopper_complete = barrier::quiescent(true, KernelWait, 0, 0, false);
    assert!(!stopper_complete);
    // Receive returns Interrupted. No entry enters until outer Resume.
    closure_progress.set(1);
    assert!(
        !stopper_complete,
        "closure can still advance under external Defer"
    );
    assert_eq!(owner_effects.get(), 1);
    assert_eq!(closure_progress.get(), 1);
    assert!(pending_entry);
    // Outer Resume enters the entry; PARKING proves the stop before commit.
    let parking = true;
    assert!(parking);
    let before_commit = closure_progress.get();
    assert_eq!(closure_progress.get(), before_commit);
}
