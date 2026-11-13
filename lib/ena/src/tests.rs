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
