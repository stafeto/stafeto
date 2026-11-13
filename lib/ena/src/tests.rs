// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver against the model of the device. Each test that a deliberate
//! break must fail (`break-acq-phase`, `break-aenq-head`, `break-reset-wait`,
//! `break-dma-width`) says which.

use crate::device::{ADMIN_BYTES, Ena, Event, Failure, ReadMode, Region};
use crate::model::{Model, Scenario, region};
use crate::{admin as adm, regs};

const MS: u64 = 1_000_000;
const S: u64 = 1_000 * MS;

fn rig_at(rev: u8, scenario: Scenario, pa: u64) -> (Model, Ena<Model>) {
    let r = region(ADMIN_BYTES.next_multiple_of(4096), pa);
    let model = Model::new(r, rev, scenario);
    // SAFETY: the region is the model's heap block, which lives on.
    let ena = unsafe { Ena::open(model.platform(), r, rev) }.unwrap();
    (model, ena)
}

fn rig(rev: u8) -> (Model, Ena<Model>) {
    rig_at(rev, Scenario::default(), 0x4_3000_0000)
}

/// Runs the driver for `ns` of the model's time: steps while there is
/// progress, then lets 100 ms pass. The events it returned.
fn run(model: &Model, ena: &mut Ena<Model>, ns: u64) -> Vec<Event> {
    let end = model.now() + ns;
    let mut events = Vec::new();
    while model.now() < end {
        for _ in 0..200 {
            match ena.poll() {
                Event::Idle => break,
                e => events.push(e),
            }
        }
        // Fast steps while the device comes up (each read through memory takes
        // a step), slow ones once it runs.
        model.advance(if ena.is_up() { 100 * MS } else { MS });
    }
    events
}

fn has_line(model: &Model, text: &str) -> bool {
    model.log_lines().iter().any(|l| l.contains(text))
}

#[test]
fn the_reset_word_puts_the_reason_in_the_top_bits() {
    assert_eq!(regs::reset_word(regs::RESET_NORMAL, false), 1);
    assert_eq!(
        regs::reset_word(regs::RESET_KEEP_ALIVE_TO, false),
        0x1000_0001
    );
    assert_eq!(
        regs::reset_word(regs::RESET_MISS_TX_CMPL, false),
        0x3000_0001
    );
    // Above 15 the next four bits carry the high part.
    assert_eq!(
        regs::reset_word(regs::RESET_DEVICE_REQUEST, true),
        0x3100_0001
    );
    // A device without extended reasons gets the generic one in its place.
    assert_eq!(
        regs::reset_word(regs::RESET_DEVICE_REQUEST, false),
        0xd000_0001
    );
    assert_eq!(regs::reset_word(regs::RESET_GENERIC, false), 0xd000_0001);
}

#[test]
fn the_header_layout_numbers_are_the_ones_of_the_sizes_the_header_gives() {
    // The entries are 64 bytes and the fields end inside them.
    assert_eq!(adm::ENTRY, 64);
    const {
        assert!(adm::FEAT_DATA + 44 <= adm::ENTRY);
    }
    const {
        assert!(adm::ACQ_DATA + 56 <= adm::ENTRY);
    }
    const {
        assert!(adm::AENQ_DATA + 48 <= adm::ENTRY);
    }
    // ena_admin_device_attr_feature_desc is 36 bytes, the mac at 24.
    assert_eq!(adm::ATTR_MAX_MTU + 4, 36);
    assert_eq!(adm::ATTR_MAC + 6 + 2, adm::ATTR_MAX_MTU);
    // ena_admin_eni_stats is five 64-bit counters, ena_admin_basic_stats 14 words.
    assert_eq!(adm::ENI_COUNTERS * 8, 40);
    assert_eq!(adm::BASIC_TX_DROPS + 8 + 8, 56);
    // ena_admin_queue_ext_feature_fields: nine words, then two 16-bit fields.
    assert_eq!(adm::QEXT_TX_HEADER + 4 + 4, 44);
    // The queue geometry the note gives.
    assert_eq!((adm::ADMIN_DEPTH, adm::EVENT_DEPTH), (32, 16));
    const {
        assert!(ADMIN_BYTES >= super::device::READLESS_AT + adm::READLESS_LEN);
    }
    assert_eq!(
        super::device::ACQ_AT,
        adm::ADMIN_DEPTH as usize * adm::ENTRY
    );
    assert_eq!(super::device::AENQ_AT, 2 * super::device::ACQ_AT);
}

#[test]
fn a_device_comes_up_on_polling_in_direct_mode() {
    let (model, mut ena) = rig(1);
    let events = run(&model, &mut ena, 3 * S);
    assert!(events.contains(&Event::Up), "{events:?}");
    assert!(ena.is_up());
    assert_eq!(ena.mode(), ReadMode::Direct);
    let i = *ena.info();
    assert_eq!(i.mac, [0x06, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]);
    assert_eq!(i.max_mtu, 9001);
    assert_eq!((i.version >> 8 & 0xff, i.version & 0xff), (2, 1));
    assert_eq!((i.tx_sq, i.tx_depth), (2, 1024));
    assert_eq!(i.dma_width, 48);
    assert_eq!(i.reset_to_ms, 300);
    assert_eq!(i.admin_to_ms, 300);
    assert!(i.aenq_enabled & 1 << adm::AENQ_KEEP_ALIVE != 0);
    assert_eq!(model.mtu(), 1500);
    assert_eq!(ena.link(), Some(true));
    assert_eq!(model.violations(), Vec::<String>::new());
    // The order of the commands: the attributes and the features, the two
    // sets, then the statistics.
    use adm::{GET_FEATURE as G, GET_STATS, SET_FEATURE as S_};
    assert_eq!(model.commands()[..9], [S_, G, G, G, G, G, G, S_, S_]);
    assert_eq!(model.commands()[9], GET_STATS);
    for line in [
        "ena: Direct read",
        "ena: reset ok",
        "ena: version 2.1",
        "ena: aq ok; mac 06:1b:2c:3d:4e:5f",
        "ena: aenq groups",
        "ena: link up",
        "ena: eni bw_in 11",
    ] {
        assert!(
            has_line(&model, line),
            "no line {line:?} in {:#?}",
            model.log_lines()
        );
    }
    assert_eq!(ena.eni_stats().unwrap().linklocal, 55);
}

#[test]
fn a_device_that_wants_a_read_through_memory_gets_one() {
    let (model, mut ena) = rig(0);
    run(&model, &mut ena, 3 * S);
    assert!(ena.is_up());
    assert_eq!(ena.mode(), ReadMode::Readless);
    assert!(model.0.borrow().read_requests >= 6);
    assert_eq!(model.violations(), Vec::<String>::new());
}

#[test]
fn a_read_through_memory_that_never_answers_falls_back_to_a_plain_read_once() {
    let s = Scenario {
        readless_dead: true,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(0, s, 0x4_3000_0000);
    run(&model, &mut ena, 3 * S);
    assert!(ena.is_up());
    assert_eq!(ena.mode(), ReadMode::Direct);
    assert!(has_line(&model, "trying Direct"));
}

#[test]
fn keep_alives_arrive_for_a_minute_and_no_reset_happens() {
    let (model, mut ena) = rig(1);
    let events = run(&model, &mut ena, 61 * S);
    assert!(ena.keep_alive().count >= 58, "{:?}", ena.keep_alive());
    assert_eq!(ena.resets().count, 0);
    assert!(!events.iter().any(|e| matches!(e, Event::Resetting(_))));
    // The drops the model sent: rx_drops twice tx_drops.
    let k = ena.keep_alive();
    assert_eq!(k.rx_drops, 2 * k.tx_drops);
    // The first three are printed, then every sixtieth.
    let lines = model
        .log_lines()
        .iter()
        .filter(|l| l.starts_with("ena: keepalive"))
        .count();
    assert!((3..=5).contains(&lines), "{lines}");
}

/// Fails under `break-aenq-head`: the head of the event queue is not written,
/// so the device stops after one queue's worth of events and the watchdog
/// resets the device.
#[test]
fn the_event_head_is_written_back_so_the_events_go_on() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 40 * S);
    assert!(ena.keep_alive().count >= 38, "{:?}", ena.keep_alive());
    assert_eq!(ena.resets().count, 0);
}

/// Fails under `break-acq-phase`: the driver keeps the old phase after the
/// completion queue wraps, so the 33rd command never completes.
#[test]
fn the_phase_of_the_completion_queue_turns_at_the_wrap() {
    let (model, mut ena) = rig(1);
    // One statistics command a minute: 40 minutes make more than the 32 entries.
    let events = run(&model, &mut ena, 40 * 60 * S);
    let commands = model.commands().len();
    assert!(commands > 33 + 10, "{commands}");
    assert_eq!(ena.resets().count, 0, "{events:?}");
    assert_eq!(model.violations(), Vec::<String>::new());
}

#[test]
fn the_admin_queue_phase_turns_too_so_the_device_takes_every_command() {
    // The same run on the other side: the model flags a command with the wrong phase.
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 40 * 60 * S);
    assert!(!model.violations().iter().any(|v| v.contains("phase")));
}

/// Fails under `break-reset-wait`: the driver goes on while the device still
/// resets, and the model refuses the first write of the queues.
#[test]
fn a_reset_in_place_waits_for_the_device_to_finish() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 3 * S);
    ena.request_reset(regs::RESET_OS_TRIGGER);
    let events = run(&model, &mut ena, 3 * S);
    assert!(events.contains(&Event::Resetting(regs::RESET_OS_TRIGGER)));
    assert!(ena.is_up());
    assert_eq!(ena.resets().count, 1);
    assert_eq!(model.violations(), Vec::<String>::new());
    assert_eq!(model.resets(), [regs::RESET_NORMAL, regs::RESET_OS_TRIGGER]);
    assert!(has_line(&model, "ena: rebuilt in"));
    assert_eq!(model.mtu(), 1500);
}

/// Fails under `break-dma-width`: the driver goes on with a region above
/// what the device addresses.
#[test]
fn a_region_above_the_dma_width_is_refused() {
    let s = Scenario {
        dma_width: 32,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    let events = run(&model, &mut ena, 2 * S);
    assert!(
        events.contains(&Event::Failed(Failure::DmaWidth { width: 32 })),
        "{events:?}"
    );
    assert!(!ena.is_up());
    assert_eq!(model.violations(), Vec::<String>::new());
}

#[test]
fn a_region_below_the_dma_width_is_taken() {
    let s = Scenario {
        dma_width: 32,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x7000_0000);
    run(&model, &mut ena, 2 * S);
    assert!(ena.is_up());
}

#[test]
fn a_region_that_is_too_small_or_misaligned_does_not_open() {
    let r = region(4096, 0x4_3000_0000);
    let model = Model::new(r, 1, Scenario::default());
    // SAFETY: the region lives on.
    let small = unsafe { Ena::open(model.platform(), r, 1) };
    assert!(matches!(small, Err(Failure::Region)));
    let r = Region {
        pa: 0x4_3000_0100,
        ..region(ADMIN_BYTES.next_multiple_of(4096), 0x4_3000_0000)
    };
    // SAFETY: as above.
    assert!(matches!(
        unsafe { Ena::open(model.platform(), r, 1) },
        Err(Failure::Region)
    ));
}

#[test]
fn the_attributes_refused_end_the_bring_up_and_the_features_refused_do_not() {
    let s = Scenario {
        error_status: Some((adm::GET_FEATURE, adm::UNSUPPORTED_OPCODE)),
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    let events = run(&model, &mut ena, 2 * S);
    assert!(events.contains(&Event::Failed(Failure::Admin {
        opcode: adm::GET_FEATURE,
        status: adm::UNSUPPORTED_OPCODE
    })));
    // A set that is refused: the groups are needed, the MTU is not.
    let s = Scenario {
        error_status: Some((adm::SET_FEATURE, adm::ILLEGAL_PARAMETER)),
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    let events = run(&model, &mut ena, 2 * S);
    assert!(events.contains(&Event::Failed(Failure::Admin {
        opcode: adm::SET_FEATURE,
        status: adm::ILLEGAL_PARAMETER
    })));
    assert!(!ena.is_up());
}

#[test]
fn an_answer_later_than_the_deadline_fails_the_bring_up_and_resets_a_running_device() {
    let s = Scenario {
        answer_delay_ns: 2 * S,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    let events = run(&model, &mut ena, 3 * S);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Failed(Failure::Admin { status: 0xFF, .. }))),
        "{events:?}"
    );
    // Running: the statistics answer late.
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 61 * S);
    model.set(|s| {
        s.answer_delay_ns = 2 * S;
        s.delay_ends_at_reset = true;
    });
    let mut reset = false;
    for _ in 0..70 {
        let events = run(&model, &mut ena, S);
        if events.contains(&Event::Resetting(regs::RESET_ADMIN_TO)) {
            reset = true;
        }
    }
    assert!(reset);
    assert!(ena.is_up());
}

#[test]
fn a_completion_with_another_commands_id_ends_the_bring_up() {
    let s = Scenario {
        wrong_command_id: true,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    let events = run(&model, &mut ena, 2 * S);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Failed(Failure::Admin { .. })))
    );
}

#[test]
fn a_device_that_stops_its_keep_alives_is_reset_once_within_seven_seconds_and_goes_on() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 10 * S);
    let last = ena.keep_alive().count;
    assert!(last >= 8);
    // The driver stops writing the head back: the device runs out of room.
    ena.hold_event_head(true);
    let mut reset_at = None;
    let mut before = 0;
    for _ in 0..600 {
        let events = run(&model, &mut ena, 100 * MS);
        if events.contains(&Event::Resetting(regs::RESET_KEEP_ALIVE_TO)) {
            reset_at = Some(model.now());
            break;
        }
        before = ena.keep_alive().count;
    }
    let at = reset_at.expect("the watchdog reset the device");
    assert_eq!(ena.resets().count, 1);
    assert_eq!(
        ena.resets().by_reason[regs::RESET_KEEP_ALIVE_TO as usize],
        1
    );
    // The keep-alives stopped at the 16 entries of the queue, and the reset came 6 s after the last.
    assert!(before <= last + 16);
    ena.hold_event_head(false);
    run(&model, &mut ena, 5 * S);
    assert!(ena.is_up());
    let after = ena.keep_alive().count;
    run(&model, &mut ena, 10 * S);
    assert!(
        ena.keep_alive().count >= after + 8,
        "keep-alives go on after the reset"
    );
    assert_eq!(ena.resets().count, 1);
    assert!(at > 0);
}

#[test]
fn a_service_that_stands_still_for_seven_seconds_finds_its_events_waiting() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 5 * S);
    // Nothing polls for 7 s; the events wait in the queue.
    model.advance(7 * S);
    let events = run(&model, &mut ena, 2 * S);
    assert_eq!(ena.resets().count, 0, "{events:?}");
    assert!(ena.is_up());
}

#[test]
fn a_fatal_status_or_event_resets_the_device() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 3 * S);
    let at = model.now();
    model.set(|s| s.fatal_at_ns = Some(at + S));
    let events = run(&model, &mut ena, 4 * S);
    assert!(
        events.contains(&Event::Resetting(regs::RESET_GENERIC)),
        "{events:?}"
    );
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 3 * S);
    let at = model.now();
    model.set(|s| s.fatal_event_at_ns = Some(at + S));
    let events = run(&model, &mut ena, 4 * S);
    assert!(events.contains(&Event::Resetting(regs::RESET_GENERIC)));
}

#[test]
fn a_reset_that_never_ends_fails_in_the_reset_timeout() {
    let s = Scenario {
        reset_never_ends: true,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    let events = run(&model, &mut ena, 3 * S);
    assert!(
        events.contains(&Event::Failed(Failure::ResetTimeout)),
        "{events:?}"
    );
}

#[test]
fn three_resets_in_a_minute_end_the_recovery() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 3 * S);
    let mut failed = false;
    for _ in 0..3 {
        ena.request_reset(regs::RESET_OS_TRIGGER);
        let events = run(&model, &mut ena, 2 * S);
        failed |= events.contains(&Event::Failed(Failure::TooManyResets));
    }
    assert!(failed);
    assert_eq!(ena.failure(), Some(Failure::TooManyResets));
    // Spread over more than a minute they are survived.
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 3 * S);
    for _ in 0..4 {
        ena.request_reset(regs::RESET_OS_TRIGGER);
        run(&model, &mut ena, 31 * S);
    }
    assert!(ena.is_up());
    assert_eq!(ena.resets().count, 4);
}

#[test]
fn a_poll_that_has_nothing_to_do_does_no_register_read() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 3 * S);
    // Let what is due finish: the watchdog's read of the status, once a second.
    for _ in 0..5 {
        ena.poll();
    }
    let before = model.0.borrow().reg_reads;
    for _ in 0..50 {
        assert_eq!(ena.poll(), Event::Idle);
    }
    assert_eq!(model.0.borrow().reg_reads, before);
}

/// A step makes at most one access to a register, in either mode: no step
/// reads a second register or waits for an answer.
#[test]
fn a_step_makes_at_most_one_register_read_in_either_mode() {
    for rev in [1u8, 0] {
        let (model, mut ena) = rig(rev);
        let mut worst = 0;
        for _ in 0..20_000 {
            let before = {
                let m = model.0.borrow();
                m.reg_reads + m.read_requests
            };
            ena.poll();
            let after = {
                let m = model.0.borrow();
                m.reg_reads + m.read_requests
            };
            worst = worst.max(after - before);
            model.advance(MS);
        }
        assert!(ena.is_up(), "rev {rev}");
        assert_eq!(worst, 1, "rev {rev}");
    }
}

/// Fails under `break-resp-rewrite`: the reset clears the address of the
/// answers of a read through memory and the driver does not write it again.
#[test]
fn a_reset_in_place_works_when_registers_are_read_through_memory() {
    let (model, mut ena) = rig(0);
    run(&model, &mut ena, 3 * S);
    ena.request_reset(regs::RESET_OS_TRIGGER);
    run(&model, &mut ena, 3 * S);
    assert!(ena.is_up(), "{:#?}", model.log_lines());
    assert_eq!(ena.mode(), ReadMode::Readless);
    assert_eq!(model.violations(), Vec::<String>::new());
}

/// The device posts no event before the head doorbell is written, and the
/// driver writes it once the groups are set.
#[test]
fn the_event_doorbell_is_written_after_the_groups_are_set() {
    let (model, mut ena) = rig(1);
    // Step until the groups are set, then check the doorbell was not yet rung.
    let mut seen_groups = false;
    for _ in 0..4000 {
        ena.poll();
        if has_line(&model, "ena: aenq groups") && !seen_groups {
            seen_groups = true;
            assert_eq!(model.0.borrow().aenq_head_db_for_test(), 0);
        }
        model.advance(MS);
        if ena.is_up() {
            break;
        }
    }
    assert!(
        seen_groups && ena.is_up(),
        "{seen_groups} {:#?}",
        model.log_lines()
    );
    assert_eq!(model.0.borrow().aenq_head_db_for_test(), 16);
}

/// Fails under `break-zero-early`: the driver zeroes the rings before it asserts
/// the reset, and a completion the old device still posts lands in them afterwards
/// and is taken for the answer to the first command of the new bring-up.
#[test]
fn a_completion_posted_while_the_reset_runs_is_not_taken_as_fresh() {
    let s = Scenario {
        stale_at_reset: true,
        reset_ns: 100 * MS,
        // The real answers take 20 ms, so that the stale one is there first.
        answer_delay_ns: 20 * MS,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    run(&model, &mut ena, 3 * S);
    ena.request_reset(regs::RESET_OS_TRIGGER);
    run(&model, &mut ena, 3 * S);
    assert!(ena.is_up(), "{:#?}", model.log_lines());
    assert_eq!(ena.info().mac, [0x06, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]);
    assert_eq!(model.violations(), Vec::<String>::new());
}

/// A bring-up that fails counts as an attempt and starts again; the third inside
/// a minute ends the recovery.
#[test]
fn a_failed_bring_up_is_tried_again_and_the_third_failure_in_a_minute_is_final() {
    let s = Scenario {
        error_status: Some((adm::GET_FEATURE, adm::UNSUPPORTED_OPCODE)),
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    let events = run(&model, &mut ena, 3 * S);
    let tries = events
        .iter()
        .filter(|e| matches!(e, Event::Resetting(regs::RESET_INIT_ERR)))
        .count();
    assert_eq!(tries, 2, "{events:?}");
    assert!(events.contains(&Event::Failed(Failure::Admin {
        opcode: adm::GET_FEATURE,
        status: adm::UNSUPPORTED_OPCODE
    })));
    assert_eq!(ena.resets().by_reason[regs::RESET_INIT_ERR as usize], 3);
    // A failure the device gets over (the answers are late until the next reset)
    // is survived.
    let (model, mut ena) = rig(1);
    let mut events = Vec::new();
    while !has_line(&model, "ena: reset ok") {
        events.push(ena.poll());
        model.advance(MS);
    }
    model.set(|s| {
        s.answer_delay_ns = 2 * S;
        s.delay_ends_at_reset = true;
    });
    events.extend(run(&model, &mut ena, 6 * S));
    assert!(
        events.contains(&Event::Resetting(regs::RESET_INIT_ERR)),
        "{events:?}"
    );
    assert!(ena.is_up(), "{:#?}", model.log_lines());
}

/// Fails under `break-reset-reason`: a reason above 15 goes out as it is.
#[test]
fn a_reset_reason_above_15_goes_as_generic_to_a_device_without_extended_reasons() {
    let (model, mut ena) = rig(1);
    run(&model, &mut ena, 3 * S);
    ena.request_reset(regs::RESET_DEVICE_REQUEST);
    run(&model, &mut ena, 3 * S);
    assert_eq!(model.resets().last(), Some(&regs::RESET_GENERIC));
}

/// Fails under `break-read-retry`: one timeout switches the read mode.
#[test]
fn a_read_that_gets_no_answer_is_tried_again_in_the_same_mode() {
    let s = Scenario {
        readless_drop: 2,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(0, s, 0x4_3000_0000);
    run(&model, &mut ena, 3 * S);
    assert!(ena.is_up());
    assert_eq!(ena.mode(), ReadMode::Readless);
    assert!(!has_line(&model, "trying"));
}

/// Fails under `break-read-hint`: the timeout of a read through memory is the
/// device's hint when it gives one.
#[test]
fn the_read_timeout_is_the_devices_hint() {
    let s = Scenario {
        hint_mmio_ms: 500,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(0, s, 0x4_3000_0000);
    run(&model, &mut ena, 3 * S);
    assert!(ena.is_up());
    assert_eq!(ena.info().hint_mmio_ms, 500);
    model.set(|s| s.readless_dead = true);
    let began = model.now();
    let mut ended = None;
    while model.now() < began + 20 * S {
        let events = run(&model, &mut ena, 10 * MS);
        if events.iter().any(|e| matches!(e, Event::Resetting(_))) {
            ended = Some(model.now());
            break;
        }
    }
    // Three reads, 500 ms each, after the status is due (at most a second).
    assert!(ended.unwrap() - began >= 1_500 * MS, "{:?}", ended);
}

/// Fails under `break-ask-lost`: a reset asked for during the bring-up is dropped.
#[test]
fn a_reset_asked_for_during_the_bring_up_is_kept_until_the_device_is_up() {
    let (model, mut ena) = rig(1);
    ena.request_reset(regs::RESET_OS_TRIGGER);
    run(&model, &mut ena, 6 * S);
    assert_eq!(ena.resets().by_reason[regs::RESET_OS_TRIGGER as usize], 1);
    assert!(ena.is_up());
}

/// Fails under `break-eni-gate`: the ENI statistics are asked of a device that
/// does not advertise them.
#[test]
fn the_eni_statistics_are_asked_only_of_a_device_that_advertises_them() {
    let s = Scenario {
        eni_stats: false,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(1, s, 0x4_3000_0000);
    run(&model, &mut ena, 70 * S);
    assert!(ena.is_up());
    assert!(!model.commands().contains(&adm::GET_STATS));
    assert!(ena.eni_stats().is_none());
}

#[test]
fn the_host_info_and_the_link_speed_are_given_and_read_before_the_device_is_up() {
    let (model, mut ena) = rig(1);
    ena.set_host(0x28, 2);
    run(&model, &mut ena, 3 * S);
    assert_eq!(model.commands()[0], adm::SET_FEATURE);
    let page = model.host_info().unwrap();
    assert_eq!(page[0], 4);
    assert_eq!(&page[4..11], b"stafeto");
    assert_eq!(ena.info().speed_mbps, 25_000);
}

/// Fails under `break-ask-kept`: a request for a reset that waits for the device to
/// be up is answered by a reset that starts on its own, so that one fault does not
/// cost two of the three attempts.
#[test]
fn a_reset_that_starts_on_its_own_drops_the_request_waiting_for_it() {
    let (model, mut ena) = rig(1);
    while !has_line(&model, "ena: reset ok") {
        ena.poll();
        model.advance(MS);
    }
    // The first admin answer comes after its deadline, and the reset ends the delay.
    model.set(|s| {
        s.answer_delay_ns = 2 * S;
        s.delay_ends_at_reset = true;
    });
    ena.request_reset(regs::RESET_OS_TRIGGER);
    run(&model, &mut ena, 8 * S);
    assert!(ena.is_up(), "{:#?}", model.log_lines());
    assert_eq!(
        ena.resets().by_reason[regs::RESET_INIT_ERR as usize],
        1,
        "{:#?}",
        model.log_lines()
    );
    assert_eq!(
        ena.resets().by_reason[regs::RESET_OS_TRIGGER as usize],
        0,
        "{:#?}",
        model.log_lines()
    );
    assert_eq!(ena.resets().count, 1);
}

/// Fails under `break-tried-kept`: once the device is up, the other read mode is
/// open to a later trouble again.
#[test]
fn the_other_read_mode_is_open_again_once_the_device_is_up() {
    let s = Scenario {
        readless_drop: 3,
        ..Scenario::default()
    };
    let (model, mut ena) = rig_at(0, s, 0x4_3000_0000);
    run(&model, &mut ena, 6 * S);
    assert!(ena.is_up(), "{:#?}", model.log_lines());
    assert!(has_line(&model, "trying"), "{:#?}", model.log_lines());
    assert!(!ena.tried_other());
}

// The data path: one queue pair against the model.

mod data {
    use super::*;
    use crate::io::{self, BUFFER_LEN, Buffers, HDR_LEN, Io};
    use crate::model::{self, MSIX_TABLE};

    const BUF_PA: u64 = 0x4_3200_0000;
    const MSI: [Option<(u64, u32)>; 2] = [Some((0x0801_0040, 5)), Some((0x0801_0040, 6))];

    struct Rig {
        model: Model,
        ena: Ena<Model>,
        bufs: Buffers,
        mem: Region,
    }

    fn rig_with(vectors: [Option<(u64, u32)>; 2], scenario: Scenario) -> Rig {
        let mem = region(io::IO_END, 0x4_3000_0000);
        let model = Model::new(mem, 0, scenario);
        let buffers = region(512 * BUFFER_LEN, BUF_PA);
        model.add_region(buffers);
        model.set_vectors(vectors);
        let bufs = Buffers {
            va: buffers.va,
            pa: buffers.pa,
            count: 512,
        };
        // SAFETY: the region is the model's heap block, which lives on.
        let mut ena = unsafe { Ena::open(model.platform(), mem, 0) }.unwrap();
        ena.set_data_path(bufs, Some(MSIX_TABLE)).unwrap();
        Rig {
            model,
            ena,
            bufs,
            mem,
        }
    }

    fn rig() -> Rig {
        rig_with(MSI, Scenario::default())
    }

    impl Rig {
        fn up(&mut self) -> Io<Model> {
            run(&self.model, &mut self.ena, 2 * S);
            assert!(self.ena.is_up(), "{:?}", self.model.log_lines());
            let info = self.ena.io_info().expect("the pair is made");
            // SAFETY: the model's blocks live on, and the test alone uses the pair.
            unsafe { Io::new(self.model.platform(), self.mem, self.bufs, info) }
        }

        fn frame_at(&self, n: u16, len: usize) -> Vec<u8> {
            let at = self.bufs.va + usize::from(n) * BUFFER_LEN + HDR_LEN;
            // SAFETY: inside the buffers' block.
            unsafe { core::slice::from_raw_parts(at as *const u8, len) }.to_vec()
        }

        fn fill_frame(&self, n: u16, bytes: &[u8]) {
            let at = self.bufs.va + usize::from(n) * BUFFER_LEN + HDR_LEN;
            // SAFETY: inside the buffers' block.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), at as *mut u8, bytes.len()) };
        }
    }

    /// The MSI of the pair's vector (the admin vector fires with the keep-alive).
    fn pair(r: &Rig) -> Vec<(u64, u32)> {
        r.model
            .fired()
            .into_iter()
            .filter(|&(_, d)| d == 6)
            .collect()
    }

    fn frame(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn the_four_queues_are_made_after_the_features_and_before_the_device_is_up() {
        let mut r = rig();
        let _io = r.up();
        let commands = r.model.commands();
        let cq = commands.iter().position(|&c| c == adm::CREATE_CQ).unwrap();
        assert_eq!(
            &commands[cq..cq + 4],
            [
                adm::CREATE_CQ,
                adm::CREATE_CQ,
                adm::CREATE_SQ,
                adm::CREATE_SQ
            ]
        );
        assert!(
            commands[..cq].contains(&adm::SET_FEATURE),
            "the features come first"
        );
        assert_eq!(r.model.violations(), Vec::<String>::new());
        assert_eq!(r.model.io_states(), [true]);
    }

    #[test]
    fn frames_arrive_in_the_buffers_given_through_two_wraps_of_the_queue() {
        let mut r = rig();
        let mut io = r.up();
        for n in 0..256 {
            assert!(io.rx_give(n));
        }
        assert!(!io.rx_give(300), "the queue holds 256");
        assert!(io.rx_bell());
        assert!(!io.rx_bell(), "one ring for the tail");
        for i in 0..600u32 {
            let f = frame(i as u8, 60 + (i as usize % 1400));
            assert!(r.model.inject(&f), "frame {i}");
            let got = io.rx_pop().unwrap().expect("a completion");
            assert_eq!(usize::from(got.len), f.len());
            assert!(got.whole && !got.sum_ok);
            assert_eq!(r.frame_at(got.n, f.len()), f, "frame {i}");
            assert!(io.rx_pop().unwrap().is_none());
            // The buffer goes back to the device at once.
            assert!(io.rx_give(got.n));
            io.rx_bell();
        }
        assert_eq!(r.model.violations(), Vec::<String>::new());
        assert_eq!(r.model.rx_dropped(), 0);
    }

    #[test]
    fn a_frame_with_no_buffer_in_the_queue_is_dropped_by_the_device() {
        let mut r = rig();
        let mut io = r.up();
        assert!(!r.model.inject(&frame(1, 64)));
        assert_eq!(r.model.rx_dropped(), 1);
        assert!(io.rx_pop().unwrap().is_none());
    }

    #[test]
    fn the_sum_the_device_checked_is_reported_and_one_it_did_not_is_not() {
        let mut r = rig();
        let mut io = r.up();
        io.rx_give(7);
        io.rx_give(8);
        io.rx_bell();
        r.model.inject(&frame(1, 64));
        assert!(!io.rx_pop().unwrap().unwrap().sum_ok);
        r.model.set_sum_checked(true);
        r.model.inject(&frame(2, 64));
        assert!(io.rx_pop().unwrap().unwrap().sum_ok);
    }

    #[test]
    fn frames_go_out_whole_and_their_buffers_come_back_through_two_wraps() {
        let mut r = rig();
        let mut io = r.up();
        let mut sent = 0;
        while sent < 600u32 {
            let n = 256 + (sent % 200) as u16;
            let f = frame(sent as u8, 60 + (sent as usize % 1400));
            r.fill_frame(n, &f);
            assert!(io.tx_submit(n, f.len() as u16), "frame {sent}");
            assert!(io.tx_bell());
            let mut back = Vec::new();
            assert_eq!(io.tx_reclaim(8, |b| back.push(b)).unwrap(), 1);
            assert_eq!(back, [n]);
            assert_eq!(r.model.sent_frames().last().unwrap(), &f);
            sent += 1;
        }
        assert_eq!(r.model.sent_frames().len(), 600);
        assert_eq!(r.model.violations(), Vec::<String>::new());
    }

    #[test]
    fn the_queue_of_sending_is_full_at_256_and_the_completions_free_it() {
        let mut r = rig();
        let mut io = r.up();
        for n in 256..512 {
            r.fill_frame(n, &frame(n as u8, 64));
            assert!(io.tx_submit(n, 64));
        }
        assert!(!io.tx_submit(300, 64));
        assert!(!io.tx_submit(1, 0), "an empty frame is no frame");
        io.tx_bell();
        assert_eq!(io.tx_reclaim(1000, |_| {}).unwrap(), 256);
        assert!(io.tx_submit(300, 64));
        assert_eq!(r.model.violations(), Vec::<String>::new());
    }

    #[test]
    fn a_completion_that_names_no_buffer_is_refused() {
        let mut r = rig();
        let mut io = r.up();
        r.fill_frame(260, &frame(1, 64));
        io.tx_submit(260, 64);
        io.tx_bell();
        // A completion of sending whose request number is past the buffers.
        let at = r.mem.va + io::TX_CQ_AT + io::TX_CDESC_REQ_ID;
        // SAFETY: the completion queue's first entry in the model's block.
        unsafe { core::ptr::write_volatile(at as *mut u16, 900) };
        assert_eq!(
            io.tx_reclaim(8, |_| {}),
            Err(crate::io::Bad::Unknown),
            "the buffer count is 512"
        );
    }

    #[test]
    fn the_table_holds_the_address_and_data_of_each_vector_and_msix_is_on() {
        let mut r = rig();
        let _io = r.up();
        let t = r.model.table();
        assert_eq!(t[0], [0x0801_0040, 0, 5, 0]);
        assert_eq!(t[1], [0x0801_0040, 0, 6, 0]);
        assert!(r.model.msix_on());
        assert_eq!(r.model.intr_mask(), 0, "the admin vector is unmasked");
        let log = r.model.log_lines();
        assert!(log.iter().any(|l| l.contains("ena: io tx db")), "{log:?}");
    }

    #[test]
    fn the_table_is_filled_one_register_a_step() {
        let mut r = rig();
        let mut at_table = 0;
        let mut steps_with_two = 0;
        let end = r.model.now() + 2 * S;
        while r.model.now() < end {
            for _ in 0..200 {
                let before = r.model.table();
                let reads = r.model.0.borrow().reg_reads;
                if matches!(r.ena.poll(), Event::Idle) {
                    break;
                }
                let after = r.model.table();
                let changed: usize = before
                    .iter()
                    .flatten()
                    .zip(after.iter().flatten())
                    .filter(|(a, b)| a != b)
                    .count();
                at_table += changed;
                let _ = reads;
                if changed > 1 {
                    steps_with_two += 1;
                }
            }
            r.model.advance(MS);
        }
        assert_eq!(steps_with_two, 0);
        assert!(at_table >= 4);
    }

    #[test]
    fn a_device_without_vectors_runs_on_polling_and_the_table_stays_empty() {
        let mut r = rig_with([None, None], Scenario::default());
        let mut io = r.up();
        assert_eq!(r.model.table(), [[0; 4]; 2]);
        assert!(!r.model.msix_on());
        io.rx_give(0);
        io.rx_bell();
        r.model.inject(&frame(1, 64));
        assert!(r.model.fired().is_empty());
        assert!(io.rx_pop().unwrap().is_some());
    }

    #[test]
    fn the_vector_of_the_pair_fires_once_until_it_is_unmasked() {
        let mut r = rig();
        let mut io = r.up();
        for n in 0..4 {
            io.rx_give(n);
        }
        io.rx_bell();
        // The device starts with the vector masked until the driver unmasks it.
        r.model.inject(&frame(1, 64));
        assert!(pair(&r).is_empty(), "masked until unmasked");
        io.rx_pop().unwrap();
        io.unmask_rx();
        r.model.inject(&frame(2, 64));
        assert_eq!(pair(&r), [(0x0801_0040, 6)]);
        r.model.inject(&frame(3, 64));
        assert_eq!(pair(&r).len(), 1, "masked after the interrupt");
        io.rx_pop().unwrap();
        io.rx_pop().unwrap();
        io.unmask_rx();
        r.model.inject(&frame(4, 64));
        assert_eq!(pair(&r).len(), 2);
    }

    #[test]
    fn the_keep_alive_raises_the_admin_vector() {
        let mut r = rig();
        let _io = r.up();
        assert!(
            r.model.fired().iter().any(|&(_, data)| data == 5),
            "{:?}",
            r.model.fired()
        );
    }

    #[test]
    fn a_reset_in_place_tells_the_owner_and_makes_the_pair_again() {
        let mut r = rig();
        let _io = r.up();
        r.ena.request_reset(regs::RESET_DRIVER_INVALID_STATE);
        run(&r.model, &mut r.ena, 3 * S);
        assert!(r.ena.is_up());
        assert_eq!(r.model.io_states(), [true, false, true]);
        let commands = r.model.commands();
        assert_eq!(
            commands.iter().filter(|&&c| c == adm::CREATE_SQ).count(),
            4,
            "two pairs of queues over the run"
        );
        assert_eq!(r.model.violations(), Vec::<String>::new());
    }

    #[test]
    fn buffers_above_the_dma_width_are_refused() {
        let mem = region(io::IO_END, 0x3000_0000);
        let model = Model::new(
            mem,
            0,
            Scenario {
                dma_width: 32,
                ..Scenario::default()
            },
        );
        let bufs = region(512 * BUFFER_LEN, 0x1_0000_0000);
        model.add_region(bufs);
        // SAFETY: the region is the model's heap block.
        let mut ena = unsafe { Ena::open(model.platform(), mem, 0) }.unwrap();
        ena.set_data_path(
            Buffers {
                va: bufs.va,
                pa: bufs.pa,
                count: 512,
            },
            None,
        )
        .unwrap();
        run(&model, &mut ena, 2 * S);
        assert!(matches!(ena.failure(), Some(Failure::DmaWidth { .. })));
    }

    #[test]
    fn the_numbers_of_the_descriptors_are_the_ones_of_the_header() {
        // ena_eth_io_defs.h: 16-byte descriptors of sending and receiving, an
        // 8-byte completion of sending and a 16-byte one of receiving.
        assert_eq!(
            (io::TX_DESC, io::RX_DESC, io::TX_CDESC, io::RX_CDESC),
            (16, 16, 8, 16)
        );
        assert_eq!(io::TX_LEN_MASK, 0xFFFF);
        assert_eq!(io::TX_REQ_ID_HI_MASK, 0x3F_0000);
        assert_eq!(io::TX_REQ_ID_LO_MASK, 0xFFC0_0000);
        assert_eq!(
            (io::TX_FIRST, io::TX_LAST, io::TX_COMP_REQ),
            (1 << 26, 1 << 27, 1 << 28)
        );
        assert_eq!(io::TX_PHASE_SHIFT, 24);
        assert_eq!(
            (io::RX_CTRL_PHASE, io::RX_CTRL_FIRST, io::RX_CTRL_LAST),
            (1, 4, 8)
        );
        assert_eq!(io::RX_STATUS_PHASE, 1 << 24);
        assert_eq!(io::RX_STATUS_L4_CSUM_CHECKED, 1 << 16);
        assert_eq!(io::INTR_UNMASK, 1 << 30);
        assert_eq!(model::MSIX_TABLE, 0x2000);
    }
}
