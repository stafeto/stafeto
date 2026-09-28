// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
const ALL: u64 = u64::MAX;
fn info(signal: i32, value: u64) -> SigInfo {
    SigInfo::queued(signal, 42, 1000, value)
}
fn push<const N: usize>(pending: &mut Pending<N>, signal: i32, value: u64) -> Ticket {
    pending
        .enqueue(Destination::Process, info(signal, value), Mode::Queue)
        .unwrap()
        .ticket
}
fn take<const N: usize>(pending: &mut Pending<N>, thread: u64, set: u64) -> Delivery {
    let selected = pending.peek(thread, set).unwrap().unwrap();
    assert_eq!(pending.accept(selected.ticket), Some(selected));
    selected
}
#[test]
fn all_64_signal_bits_and_invalid_boundaries() {
    for signal in 1..=SIGNAL_MAX {
        assert_eq!(bit(signal), Ok(1u64 << (signal - 1)));
    }
    assert_eq!(bit(64), Ok(1 << 63));
    for signal in [i32::MIN, -1, 0, 65, i32::MAX] {
        assert_eq!(bit(signal), Err(Error::Signal));
    }
}
#[test]
fn fifo_survives_recycled_slots_and_coalesce_keeps_earliest_source() {
    let mut p = Pending::<3>::new(42).unwrap();
    push(&mut p, REALTIME_MIN, 1);
    let second = push(&mut p, REALTIME_MIN, 2);
    push(&mut p, REALTIME_MIN, 3);
    assert_eq!(take(&mut p, 1, ALL).info.si_value, 1);
    push(&mut p, REALTIME_MIN, 4); // Reuses the first physical slot.
    let old = p
        .enqueue(Destination::Process, info(REALTIME_MIN, 99), Mode::Coalesce)
        .unwrap();
    assert_eq!(
        old,
        Enqueued {
            ticket: second,
            inserted: false
        }
    );
    for value in 2..=4 {
        assert_eq!(take(&mut p, 1, ALL).info.si_value, value);
    }
    assert!(p.is_empty());
    assert_eq!(p.available(), 3);
}
#[test]
fn lowest_eligible_number_precedes_age_and_signal_64_is_selectable() {
    let mut p = Pending::<4>::new(42).unwrap();
    push(&mut p, 64, 1);
    push(&mut p, 33, 2);
    push(&mut p, 32, 3);
    push(&mut p, 31, 4);
    assert_eq!(take(&mut p, 1, bit(64).unwrap()).info.si_signo, 64);
    for signal in [31, 32, 33] {
        assert_eq!(take(&mut p, 1, ALL).info.si_signo, signal);
    }
}
#[test]
fn process_scope_remains_shared_until_acceptance_and_thread_scope_is_private() {
    let mut p = Pending::<4>::new(42).unwrap();
    let shared = push(&mut p, 33, 1);
    p.enqueue(Destination::Thread(7), info(32, 2), Mode::Queue)
        .unwrap();
    p.enqueue(Destination::Thread(8), info(64, 3), Mode::Queue)
        .unwrap();
    assert_eq!(p.pending(7, ALL), Ok(bit(32).unwrap() | bit(33).unwrap()));
    assert_eq!(p.pending(8, ALL), Ok(bit(33).unwrap() | bit(64).unwrap()));
    assert_eq!(p.pending(9, ALL), Ok(bit(33).unwrap()));
    assert_eq!(p.pending(7, bit(64).unwrap()), Ok(0));
    assert_eq!(p.peek(7, bit(33).unwrap()).unwrap().unwrap().ticket, shared);
    assert_eq!(p.peek(8, bit(33).unwrap()).unwrap().unwrap().ticket, shared);
    assert_eq!(take(&mut p, 8, bit(33).unwrap()).ticket, shared);
    assert_eq!(p.pending(9, ALL), Ok(0));
    assert_eq!(p.peek(8, bit(32).unwrap()), Ok(None));
    assert_eq!(take(&mut p, 7, ALL).destination, Destination::Thread(7));
    assert_eq!(take(&mut p, 8, ALL).destination, Destination::Thread(8));
}
#[test]
fn snapshot_preserves_every_field_and_wide_value_without_pointer_access() {
    let mut p = Pending::<1>::new(42).unwrap();
    let source = SigInfo {
        si_signo: 64,
        si_errno: -7,
        si_code: posix_types::constants::SI_QUEUE,
        si_pid: i32::MAX,
        si_uid: u32::MAX - 1,
        si_status: -99,
        si_addr: u64::MAX,
        si_value: 0x8000_ffff_1234_abcd,
    };
    let inserted = p
        .enqueue(Destination::Process, source, Mode::Queue)
        .unwrap();
    let selected = take(&mut p, 1, ALL);
    assert_eq!(selected.ticket, inserted.ticket);
    assert_eq!(selected.info, source);
    assert_eq!(SigInfo::from_words(selected.info.words()), source);
    let queued = info(32, u64::MAX);
    assert_eq!(queued.si_pid, 42);
    assert_eq!(queued.si_uid, 1000);
    assert_eq!(queued.si_code, posix_types::constants::SI_QUEUE);
    assert_eq!([queued.si_errno, queued.si_status], [0; 2]);
    assert_eq!(queued.si_addr, 0);
    assert_eq!(queued.si_value, u64::MAX);
}
#[test]
fn process_pool_limit_is_shared_by_all_destinations_and_failure_is_atomic() {
    let mut p = Pending::<DEFAULT_CAPACITY>::new(42).unwrap();
    for n in 0..DEFAULT_CAPACITY {
        let to = if n % 2 == 0 {
            Destination::Process
        } else {
            Destination::Thread(n as u64)
        };
        p.enqueue(to, info(32, n as u64), Mode::Queue).unwrap();
    }
    let first = p.peek(1, ALL).unwrap();
    assert_eq!(p.available(), 0);
    assert_eq!(
        p.enqueue(Destination::Thread(999), info(64, 1), Mode::Queue),
        Err(Error::Full)
    );
    assert_eq!(p.peek(1, ALL).unwrap(), first);
    assert_eq!(p.len(), DEFAULT_CAPACITY);
    for n in (1..DEFAULT_CAPACITY).step_by(2) {
        assert_eq!(p.discard_thread(n as u64), Ok(1));
    }
    for n in (0..DEFAULT_CAPACITY).step_by(2) {
        assert_eq!(take(&mut p, 1, ALL).info.si_value, n as u64);
    }
    assert!(p.is_empty());
}
#[test]
fn ordinary_coalescing_keeps_first_reason_even_when_storage_is_full() {
    let mut p = Pending::<1>::new(42).unwrap();
    let original = p
        .enqueue(Destination::Process, SigInfo::thread(10), Mode::Coalesce)
        .unwrap();
    assert!(original.inserted);
    let duplicate = p
        .enqueue(Destination::Process, info(10, 2), Mode::Coalesce)
        .unwrap();
    assert_eq!(
        duplicate,
        Enqueued {
            inserted: false,
            ..original
        }
    );
    assert_eq!(
        p.enqueue(Destination::Process, info(10, 3), Mode::Queue),
        Err(Error::Full)
    );
    assert_eq!(
        p.enqueue(Destination::Thread(1), info(10, 3), Mode::Coalesce),
        Err(Error::Full)
    );
    assert_eq!(take(&mut p, 1, ALL).info, SigInfo::thread(10));
}
#[test]
fn ignore_discards_all_occurrences_and_thread_exit_preserves_shared_signals() {
    let mut p = Pending::<6>::new(42).unwrap();
    for to in [
        Destination::Process,
        Destination::Thread(1),
        Destination::Thread(2),
    ] {
        p.enqueue(to, info(32, 1), Mode::Queue).unwrap();
        p.enqueue(to, info(33, 2), Mode::Queue).unwrap();
    }
    assert_eq!(p.discard_signal(32), Ok(3));
    assert_eq!(p.discard_thread(1), Ok(1));
    assert_eq!(p.len(), 2);
    assert_eq!(take(&mut p, 2, ALL).destination, Destination::Process);
    assert_eq!(take(&mut p, 2, ALL).destination, Destination::Thread(2));
    assert_eq!(p.discard_signal(32), Ok(0));
    assert_eq!(p.discard_thread(1), Ok(0));
}
#[test]
fn old_ticket_cannot_consume_reused_storage_or_duplicate_acceptance() {
    let mut p = Pending::<1>::new(42).unwrap();
    let old = push(&mut p, 32, 1);
    assert!(p.accept(old).is_some());
    assert_eq!(p.accept(old), None);
    let new = push(&mut p, 32, 2);
    assert_ne!(old, new);
    assert_eq!(p.accept(old), None);
    assert_eq!(p.len(), 1);
    assert_eq!(p.accept(new).unwrap().info.si_value, 2);
}
#[test]
fn last_ticket_is_valid_and_exhaustion_never_wraps_or_changes_pending_state() {
    let mut p = Pending::<2>::new(42).unwrap();
    p.next = Some(u64::MAX);
    let last = push(&mut p, 32, 1);
    assert_eq!(
        last,
        Ticket {
            process: 42,
            serial: u64::MAX
        }
    );
    assert_eq!(p.next, None);
    let prior = p.peek(1, ALL).unwrap();
    assert_eq!(
        p.enqueue(Destination::Process, info(33, 2), Mode::Queue),
        Err(Error::Exhausted)
    );
    assert_eq!(p.peek(1, ALL).unwrap(), prior);
    assert!(
        !p.enqueue(Destination::Process, info(32, 2), Mode::Coalesce)
            .unwrap()
            .inserted
    );
    assert_eq!(p.accept(last).unwrap().info.si_value, 1);
    assert_eq!(
        p.enqueue(Destination::Process, info(32, 3), Mode::Queue),
        Err(Error::Exhausted)
    );
    assert_eq!(p.len(), 0);
}
#[test]
fn invalid_requests_preserve_state_and_zero_capacity_is_a_paid_limit() {
    let mut p = Pending::<1>::new(42).unwrap();
    let ticket = push(&mut p, 64, 1);
    for signal in [0, 65, i32::MIN, i32::MAX] {
        assert_eq!(
            p.enqueue(Destination::Process, info(signal, 2), Mode::Queue),
            Err(Error::Signal)
        );
        assert_eq!(p.discard_signal(signal), Err(Error::Signal));
    }
    assert_eq!(
        p.enqueue(Destination::Thread(0), info(32, 2), Mode::Queue),
        Err(Error::Thread)
    );
    assert_eq!(p.peek(0, ALL), Err(Error::Thread));
    assert_eq!(p.pending(0, ALL), Err(Error::Thread));
    assert_eq!(p.discard_thread(0), Err(Error::Thread));
    assert_eq!(p.peek(1, 0), Ok(None));
    assert_eq!(p.accept(ticket).unwrap().info.si_value, 1);
    assert_eq!(
        Pending::<0>::new(42)
            .unwrap()
            .enqueue(Destination::Process, info(32, 2), Mode::Queue),
        Err(Error::Full)
    );
}
#[test]
fn peek_is_non_destructive_until_prepaid_reply_accepts_and_saved_copy_survives_reuse() {
    let mut p = Pending::<1>::new(42).unwrap();
    push(&mut p, 32, u64::MAX);
    let selection = p.peek(1, ALL).unwrap().unwrap();
    // Failed reply reservation leaves the original occurrence untouched.
    for _ in 0..100 {
        assert_eq!(p.peek(1, ALL), Ok(Some(selection)));
        assert_eq!(p.len(), 1);
    }
    // The sole owner has paid for its retained outcome before this acceptance.
    let saved = p.accept(selection.ticket).unwrap();
    push(&mut p, 32, 2);
    assert_eq!(saved, selection);
    assert_eq!(saved.info.si_value, u64::MAX);
    assert_eq!(p.accept(saved.ticket), None);
    assert_eq!(take(&mut p, 1, ALL).info.si_value, 2);
}

#[test]
fn tickets_from_another_process_cannot_accept_or_cancel_this_pools_signals() {
    let mut first = Pending::<1>::new(42).unwrap();
    let mut other = Pending::<1>::new(43).unwrap();
    let a = push(&mut first, 32, 1);
    let b = push(&mut other, 32, 2);
    assert_ne!(a, b);
    assert_eq!(first.accept(b), None);
    assert_eq!(other.accept(a), None);
    assert_eq!(first.accept(a).unwrap().info.si_value, 1);
    assert_eq!(other.accept(b).unwrap().info.si_value, 2);
    for process in [0, i32::MAX as u32 + 1, u32::MAX] {
        assert!(matches!(Pending::<1>::new(process), Err(Error::Process)));
    }
    assert!(Pending::<1>::new(i32::MAX as u32).is_ok());
}
