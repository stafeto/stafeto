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
fn park_marker_requires_own_channel_and_a_receiving_thread() {
    assert!(barrier::confirmed_parked(9, 9, true));
    assert!(
        !barrier::confirmed_parked(9, 9, false),
        "Sending or AwaitingReply"
    );
    assert!(!barrier::confirmed_parked(9, 8, true), "another channel");
    assert!(!barrier::confirmed_parked(0, 0, true), "no marker");
    assert!(!barrier::confirmed_parked(0, 9, true));
}

/// One step of a thread's history seen by the scan: the marker in PARKING,
/// the kernel state, and whether the thread is parked or parking for the
/// stop that scans it.
#[derive(Clone, Copy)]
struct Step {
    marker: u64,
    state: barrier::State,
    receiving: bool,
    in_park: bool,
}

const C: u64 = 9;
const fn step(marker: u64, receiving: bool, running: bool, in_park: bool) -> Step {
    Step {
        marker,
        state: if running {
            barrier::State::Running
        } else {
            barrier::State::KernelWait
        },
        receiving,
        in_park,
    }
}

/// Histories of a thread X while a stopper scans. Variant 1: the old stop
/// ended, X republishes its marker and sees no stopper, clears it and goes
/// on into a wait of its own code; the new stopper began after that check, so
/// it reads from the republished marker on. Variant 2: the new stopper began
/// first, so X's republished marker means a park for the new stop.
fn histories() -> [&'static [Step]; 2] {
    static LEAVING: [Step; 6] = [
        step(C, false, true, false),  // marker republished, stop already over
        step(0, false, true, false),  // marker cleared
        step(0, false, false, false), // AwaitingReply in its own code
        step(0, true, false, false),  // Receiving on its own channel
        step(0, false, true, false),
        step(C, true, false, true), // a later stop parks it
    ];
    static PARKING_AGAIN: [Step; 5] = [
        step(0, true, false, false), // woken by the old stopper, not yet running
        step(0, false, true, false),
        step(C, false, true, true), // republished under the new stopper
        step(C, true, false, true),
        step(C, true, false, true),
    ];
    [&LEAVING, &PARKING_AGAIN]
}

/// Every pair of read times (first read at t1, second at t2 >= t1) over every
/// history: `observe` may report a park only for a thread that is parked or
/// parking at the time of its second read.
fn model_holds(
    scan: impl Fn(&dyn Fn() -> (barrier::State, bool), &dyn Fn() -> u64) -> (barrier::State, bool),
) -> bool {
    for history in histories() {
        for t1 in 0..history.len() {
            for t2 in t1..history.len() {
                let calls = Cell::new(0usize);
                let at = || {
                    let k = calls.get();
                    calls.set(k + 1);
                    history[if k == 0 { t1 } else { t2 }]
                };
                let state = || {
                    let h = at();
                    (h.state, h.receiving)
                };
                let marker = || at().marker;
                let (_, parked) = scan(&state, &marker);
                if parked && !history[t2].in_park {
                    return false;
                }
            }
        }
    }
    true
}

#[test]
fn stop_scan_never_counts_a_thread_that_left_its_park() {
    assert!(model_holds(|state, marker| barrier::observe(
        state, marker, C
    )));
}

#[test]
fn stop_others_reads_the_marker_only_through_observe() {
    let source = include_str!("../../posix-abi/src/signals.rs");
    assert!(source.contains("stop_barrier::observe("));
    assert_eq!(source.matches("PARKING[index]").count(), 1);
}

#[test]
fn model_rejects_marker_only_and_marker_first_scans() {
    // Marker alone: the republished marker of a leaving thread counts.
    assert!(!model_holds(|_, marker| {
        (
            barrier::State::Running,
            barrier::confirmed_parked(marker(), C, true),
        )
    }));
    // Marker read before the kernel state.
    assert!(!model_holds(|state, marker| {
        let m = marker();
        let (s, receiving) = state();
        (s, barrier::confirmed_parked(m, C, receiving))
    }));
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

#[test]
fn release_keeps_new_stopper_out_until_wakes_and_close_finish() {
    let stop = barrier::StopControl::new();
    assert!(stop.try_begin(7, 101));
    assert!(barrier::must_park(stop.owner(), 11));
    let woke = Cell::new(false);
    let closed = Cell::new(0);
    assert!(stop.release(
        7,
        || {
            assert!(!barrier::must_park(stop.owner(), 11));
            assert!(
                !stop.try_begin(11, 202),
                "new stop waits for every peer wake"
            );
            assert_eq!(stop.channel(), 101);
            woke.set(true);
        },
        |channel| {
            assert!(woke.get());
            assert_eq!(channel, 101, "close belongs to the releasing owner");
            assert!(!barrier::must_park(stop.owner(), 11));
            assert!(!stop.try_begin(11, 202), "new stop waits for channel close");
            closed.set(channel);
        },
    ));
    assert_eq!(closed.get(), 101);
    assert!(stop.try_begin(11, 202));
    assert_eq!(stop.owner(), 11);
    assert_eq!(stop.channel(), 202);
    assert!(stop.release(11, || {}, |channel| assert_eq!(channel, 202)));
}

#[test]
fn interleaved_release_cannot_close_the_next_stoppers_channel() {
    let stop = barrier::StopControl::new();
    assert!(stop.try_begin(7, 101));
    let claimed_during_wake = Cell::new(false);
    assert!(stop.release(
        7,
        || claimed_during_wake.set(stop.try_begin(11, 202)),
        |channel| assert_eq!(channel, 101, "release must close its own channel"),
    ));
    assert!(!claimed_during_wake.get());
    assert!(stop.try_begin(11, 202));
    assert!(stop.release(11, || {}, |channel| assert_eq!(channel, 202)));
}

#[test]
fn failed_contender_cannot_release_another_stop_or_its_channel() {
    let stop = barrier::StopControl::new();
    assert!(!stop.try_begin(0, 101));
    assert!(!stop.try_begin(7, 0));
    assert!(stop.try_begin(7, 101));
    assert!(!stop.try_begin(11, 202));
    assert!(!stop.release(
        11,
        || panic!("foreign peer wake"),
        |_| panic!("foreign close")
    ));
    assert_eq!(stop.owner(), 7);
    assert_eq!(stop.channel(), 101);
    assert!(stop.release(7, || {}, |channel| assert_eq!(channel, 101)));
    assert!(!stop.release(
        7,
        || panic!("duplicate wake"),
        |_| panic!("duplicate close")
    ));
}

#[test]
fn child_discards_parent_lifecycle_and_accepts_its_own_stop() {
    let stop = barrier::StopControl::new();
    assert!(stop.try_begin(7, 101));
    stop.reset_after_fork();
    assert_eq!(stop.owner(), 0);
    assert_eq!(stop.channel(), 0);
    assert!(stop.try_begin(11, 202));
    assert!(stop.release(11, || {}, |channel| assert_eq!(channel, 202)));
}

#[test]
fn cleanup_contender_sleeps_so_lower_priority_owner_can_finish() {
    let stop = barrier::StopControl::new();
    assert!(stop.try_begin(7, 101));
    let slept = Cell::new(false);
    let lower_owner_finished = Cell::new(false);
    assert!(stop.release(
        7,
        || {
            assert!(!stop.try_begin(11, 202));
            stop.wait_for_claim(
                || panic!("cleanup has no active owner to park behind"),
                || {
                    slept.set(true);
                    Ok::<(), i32>(())
                },
            )
            .unwrap();
        },
        |channel| {
            // A higher-priority contender must relinquish its runnable turn.
            assert!(slept.get(), "cleanup contention requires a blocking wait");
            assert_eq!(channel, 101);
            lower_owner_finished.set(true);
        },
    ));
    assert!(lower_owner_finished.get());
    assert!(stop.try_begin(11, 202));
    assert!(stop.release(11, || {}, |channel| assert_eq!(channel, 202)));
}

#[test]
fn claim_wait_parks_active_stop_and_preserves_cleanup_wait_errors() {
    let stop = barrier::StopControl::new();
    assert!(stop.try_begin(7, 101));
    let parked = Cell::new(false);
    stop.wait_for_claim(
        || parked.set(true),
        || panic!("active stop uses its ordinary park"),
    )
    .unwrap_or_else(|_: i32| panic!("park does not fail"));
    assert!(parked.get());
    assert!(stop.release(
        7,
        || {
            assert_eq!(
                stop.wait_for_claim(|| panic!("cleanup park"), || Err(11)),
                Err(11),
            );
            assert!(!stop.try_begin(11, 202));
        },
        |channel| assert_eq!(channel, 101),
    ));
    assert!(stop.try_begin(11, 202));
    assert!(stop.release(11, || {}, |channel| assert_eq!(channel, 202)));
}

#[test]
fn a_thread_on_its_way_into_the_park_is_not_parked_and_shortens_the_wait() {
    use barrier::State;
    // Marker of its own channel, kernel state Running: parking, not parked.
    assert!(barrier::is_parking(State::Running, 7, 7));
    assert!(!barrier::is_parking(State::Running, 0, 7));
    assert!(!barrier::is_parking(State::Running, 8, 7));
    assert!(!barrier::is_parking(State::KernelWait, 7, 7));
    assert!(!barrier::confirmed_parked(7, 7, false));
    // The wait: 20 microseconds, doubling to the look-again period; any
    // other thread gives the period back.
    let again = 1_000_000;
    let mut wait = barrier::next_wait(true, 0, again);
    assert_eq!(wait, 20_000);
    let mut total = 0;
    while wait < again {
        total += 1;
        wait = barrier::next_wait(true, wait, again);
    }
    assert_eq!((wait, total), (again, 6));
    assert_eq!(barrier::next_wait(false, 40_000, again), again);
    assert_eq!(barrier::next_wait(true, again, again), again);
}

#[test]
fn stop_others_waits_briefly_only_when_every_waited_thread_is_parking() {
    let source = include_str!("../../posix-abi/src/signals.rs");
    assert!(source.contains("stop_barrier::is_parking("));
    assert!(source.contains("stop_barrier::next_wait(!other, short_wait, LOOK_AGAIN_NS)"));
    assert!(source.contains("other |= !parking;"));
}
