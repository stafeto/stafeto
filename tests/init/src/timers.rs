// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of the clock and of timers (spec 10).

use crate::channels::unlabeled;
use crate::harness::*;
use crate::messages::{receive_then_look, record};
use crate::processes::caller_ceiling;

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 11] = [
    (
        "clock_now_follows_the_counter",
        clock_now_follows_the_counter,
    ),
    ("timer_needs_receive", timer_needs_receive),
    (
        "timer_set_and_cancel_check_their_handles",
        timer_set_and_cancel_check_their_handles,
    ),
    ("timer_bounds_a_wait", timer_bounds_a_wait),
    (
        "notification_before_the_timer_comes_first",
        notification_before_the_timer_comes_first,
    ),
    (
        "timer_in_the_past_fires_at_once",
        timer_in_the_past_fires_at_once,
    ),
    ("timer_set_moves_the_deadline", timer_set_moves_the_deadline),
    ("cancel_keeps_posted_bits", cancel_keeps_posted_bits),
    ("timer_never_fires_early", timer_never_fires_early),
    ("timer_limit_is_64", timer_limit_is_64),
    (
        "timer_fires_at_its_slot_priority",
        timer_fires_at_its_slot_priority,
    ),
];

/// A timer on `c` whose slot has `priority`: it fires at that level, ahead
/// of the threads below it and after those above (spec 10), so a thread
/// whose wait it bounds gives it its own level at least.
pub(crate) fn timer_at(c: &Handle<Channel>, priority: u8) -> Result<Handle<Timer>, &'static str> {
    sys::timer_create(c, priority).map_err(|_| "timer_create failed")
}

/// timer_create with raw registers.
fn raw_timer_create(x: Regs) -> Regs {
    // SAFETY: timer_create only reads its registers.
    unsafe { sys::raw::<{ Call::TimerCreate.number() }>(x) }
}

/// Spins until the counter, in nanoseconds, passed `ns`.
fn spin_past(ns: u64) {
    while time::ticks_to_ns(time::now()) <= ns {}
}

/// `count` expiries of a timer made through a handle with `label`: bit 0.
pub(crate) fn expiry(label: u64, count: u32) -> Received {
    Received::Notification {
        source: Source::Timer,
        label,
        bits: 1,
        count,
    }
}

/// Spec 15.2 (time): a program reads the counter itself (CNTVCT_EL0,
/// spec 10), and clock_now between two such readings returns nanoseconds
/// between theirs, rounded down as rt::time converts them; it changes x0
/// and x1 alone.
fn clock_now_follows_the_counter() -> Outcome {
    let x = marked();
    let before = time::now();
    // SAFETY: clock_now reads no register.
    let after = unsafe { sys::raw::<{ Call::ClockNow.number() }>(x) };
    let later = time::now();
    let typed = sys::clock_now();
    check(
        after[0] == 0 && after[2..] == x[2..],
        "clock_now failed or changed registers past x1",
    )?;
    check(
        (time::ticks_to_ns(before)..=time::ticks_to_ns(later)).contains(&after[1]),
        "clock_now is not between two readings of the counter",
    )?;
    check(typed.is_ok_and(|ns| ns >= after[1]), "clock_now went back")
}

/// timer_create takes a channel with RECEIVE (spec 6.5, 10): a timer is a
/// bound on its creator's own wait, and the slots of the channel and the
/// priorities that lift its receivers are the receiver's. A priority
/// outside 1-63 fails with INVALID_ARGS before the handle is looked at, a
/// bad handle with BAD_HANDLE, a handle to another kind with WRONG_TYPE, a
/// copy with NOTIFY alone with ACCESS_DENIED; each changes x0 alone, and so
/// does a priority above the caller's own ceiling, ACCESS_DENIED: 31 in a
/// child under ceiling 30 (`caller_ceiling`). A copy with RECEIVE and a
/// label makes a timer whose expiries carry the label.
fn timer_needs_receive() -> Outcome {
    let c = channel(QUIET)?;
    let notify = copy(&c, Rights::NOTIFY)?;
    let labelled = session(&c, Rights::RECEIVE, TIMED, QUIET)?;
    let cases = [
        (abi::Handle::INVALID, 0, Error::InvalidArgs),
        (c.raw(), 64, Error::InvalidArgs),
        (c.raw(), 0x100 | u64::from(QUIET), Error::InvalidArgs),
        (abi::Handle::INVALID, QUIET.into(), Error::BadHandle),
        (init::PROCESS.raw(), QUIET.into(), Error::WrongType),
        (notify.raw(), QUIET.into(), Error::AccessDenied),
    ];
    let refused = cases.map(|(h, priority, error)| {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.0, priority]);
        failed(raw_timer_create(x), x, error)
    });
    let t = sys::timer_create(&labelled, QUIET);
    let fired = t
        .as_ref()
        .map_err(|&e| e)
        .and_then(|t| sys::timer_set(t, 0));
    let got = sys::try_receive(&c);
    if let Ok(t) = t {
        close(t)?;
    }
    close(labelled)?;
    close(notify)?;
    close(c)?;
    check(
        refused.iter().all(|&ok| ok),
        "timer_create took a channel without RECEIVE or a bad argument, or changed more than x0",
    )?;
    check(
        fired.is_ok() && got == Ok(expiry(TIMED, 1)),
        "a timer made through a labelled copy did not carry the label",
    )?;
    caller_ceiling(Checked::TimerCreate)
}

/// timer_set(x0 timer with MANAGE, x1 deadline) and timer_cancel(x0 timer
/// with MANAGE) check their handle (spec 10, 11) and change x0 alone on
/// an error: a closed handle fails with BAD_HANDLE, a handle to another
/// kind with WRONG_TYPE, a copy without MANAGE with ACCESS_DENIED.
/// timer_set on a timer whose channel closed fails with PEER_CLOSED and
/// changes x0 alone as well; timer_cancel still takes the timer.
fn timer_set_and_cancel_check_their_handles() -> Outcome {
    let gone = closed_handle()?;
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let seen = copy(&t, Rights::DUPLICATE)?;
    let refused = timer_handle_cases(gone, c.raw().0, seen.raw().0);
    close(seen)?;
    let armed = clock_now().and_then(|now| arm(&t, now + 1_000_000_000));
    // The last handle with RECEIVE goes: the channel closes (spec 6.8).
    close(c)?;
    let closed = x0_alone::<{ Call::TimerSet.number() }>(&[t.raw().0, 0], Error::PeerClosed.code());
    let cancelled = sys::timer_cancel(&t);
    close(t)?;
    armed?;
    check(
        refused,
        "a closed handle, a handle to another kind or a copy without MANAGE did not fail alone",
    )?;
    check(
        closed,
        "timer_set on a closed channel did not fail with PEER_CLOSED alone",
    )?;
    check(cancelled.is_ok(), "timer_cancel on a closed channel failed")
}

fn timer_handle_cases(gone: u64, channel: u64, seen: u64) -> bool {
    const SET: u16 = Call::TimerSet.number();
    const CANCEL: u16 = Call::TimerCancel.number();
    let resource = init::RESOURCE.raw().0;
    [
        x0_alone::<SET>(&[gone, 0], Error::BadHandle.code()),
        x0_alone::<CANCEL>(&[gone], Error::BadHandle.code()),
        x0_alone::<SET>(&[resource, 0], Error::WrongType.code()),
        x0_alone::<CANCEL>(&[channel], Error::WrongType.code()),
        x0_alone::<SET>(&[seen, 0], Error::AccessDenied.code()),
        x0_alone::<CANCEL>(&[seen], Error::AccessDenied.code()),
    ]
    .iter()
    .all(|&ok| ok)
}

/// Spec 15.2 (time): a timer on a channel and receive make a wait with a
/// bound (spec 6.1, 10). Init waits on an empty channel whose timer fires
/// 1 ms from now and wakes with the timer's notification, bit 0 once, not
/// before the deadline; nothing else comes.
fn timer_bounds_a_wait() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let deadline = clock_now()? + 1_000_000;
    let set = arm(&t, deadline);
    let got = sys::receive(&c);
    let woke = clock_now();
    let rest = sys::try_receive(&c);
    close(t)?;
    close(c)?;
    set?;
    check(
        got == Ok(expiry(0, 1)),
        "the wait did not end with the timer's notification",
    )?;
    check(
        woke.is_ok_and(|ns| ns >= deadline),
        "the wait ended before the timer's deadline",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "something came after the timer",
    )
}

/// Spec 15.2 (time): what came before the bound ends the wait first.
/// init notifies the channel, arms the timer 20 ms on and waits: the wait
/// ends at once with the notification, init cancels the timer, and once
/// the deadline passed nothing more comes.
fn notification_before_the_timer_comes_first() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let notified = sys::notify(&c, NOTIFIED);
    let deadline = clock_now()? + 20_000_000;
    let set = arm(&t, deadline);
    let got = sys::receive(&c);
    let cancelled = sys::timer_cancel(&t);
    spin_past(deadline);
    let rest = sys::try_receive(&c);
    close(t)?;
    close(c)?;
    set?;
    check(
        notified.is_ok() && cancelled.is_ok(),
        "notify or timer_cancel failed",
    )?;
    check(
        got == Ok(unlabeled(NOTIFIED, 1)),
        "the notification before the deadline did not come first",
    )?;
    check(rest == Err(Error::WouldBlock), "the cancelled timer fired")
}

/// Spec 15.2 (time): a deadline that passed fires in timer_set itself
/// (spec 10). Right after timer_set with 0, with the time clock_now gave,
/// and with a past deadline for an armed timer, the timer's notification
/// is there, bit 0 once each time.
fn timer_in_the_past_fires_at_once() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let result = past_deadlines(&c, &t);
    close(t)?;
    close(c)?;
    result
}

fn past_deadlines(c: &Handle<Channel>, t: &Handle<Timer>) -> Outcome {
    let now = clock_now()?;
    for (armed, past) in [(false, 0), (false, now), (true, now)] {
        if armed {
            arm(t, now + 1_000_000_000)?;
        }
        arm(t, past)?;
        check(
            sys::try_receive(c) == Ok(expiry(0, 1)),
            "a deadline in the past did not fire at once",
        )?;
    }
    check(
        sys::try_receive(c) == Err(Error::WouldBlock),
        "a timer set into the past fired once more",
    )
}

/// timer_set of an armed timer moves it (spec 10): armed a second away and
/// then 1 ms away, it fires at the nearer deadline, long before the far
/// one; armed 10 ms away and then a second away, it does not fire at the
/// nearer one, which a stall of the host cannot pass before the call.
fn timer_set_moves_the_deadline() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let result = moves(&c, &t);
    close(t)?;
    close(c)?;
    result
}

fn moves(c: &Handle<Channel>, t: &Handle<Timer>) -> Outcome {
    let now = clock_now()?;
    let (near, far) = (now + 1_000_000, now + 1_000_000_000);
    arm(t, far)?;
    arm(t, near)?;
    let got = sys::receive(c);
    let at = clock_now()?;
    check(
        got == Ok(expiry(0, 1)) && (near..far).contains(&at),
        "the timer did not move to the nearer deadline",
    )?;
    let now = clock_now()?;
    let (near, far) = (now + 10_000_000, now + 1_000_000_000);
    arm(t, near)?;
    arm(t, far)?;
    spin_past(near + 1_000_000);
    let rest = sys::try_receive(c);
    sys::timer_cancel(t).map_err(|_| "timer_cancel failed")?;
    check(
        rest == Err(Error::WouldBlock),
        "the timer fired at the deadline it moved away from",
    )
}

/// timer_cancel leaves what the timer posted (spec 10): a timer that fired
/// in timer_set and is cancelled afterwards still has its notification
/// waiting; cancelling a timer that is not armed is no error.
fn cancel_keeps_posted_bits() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let fired = arm(&t, 0);
    let cancelled = sys::timer_cancel(&t);
    let got = sys::try_receive(&c);
    let again = sys::timer_cancel(&t);
    close(t)?;
    close(c)?;
    fired?;
    check(cancelled.is_ok() && again.is_ok(), "timer_cancel failed")?;
    check(
        got == Ok(expiry(0, 1)),
        "timer_cancel took back what the timer posted",
    )
}

/// Spec 15.2 (time): a timer never fires before its deadline (spec 10).
/// For deadlines 200 µs away at 16 offsets a nanosecond apart, on the
/// ticks of the counter and between them, init wakes with the timer's
/// notification at a time clock_now gives no earlier than the deadline.
fn timer_never_fires_early() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let result = (0..16).try_for_each(|offset| {
        let deadline = clock_now()? + 200_000 + offset;
        arm(&t, deadline)?;
        let got = sys::receive(&c);
        let woke = clock_now()?;
        check(
            got == Ok(expiry(0, 1)) && woke >= deadline,
            "a timer fired before its deadline",
        )
    });
    close(t)?;
    close(c)?;
    result
}

/// Spec 15.2 (priorities, time): a timer fires at the priority of its slot
/// (spec 10). W at init's level waits on a channel of that level whose
/// timer's slot has LEVEL, H at HIGH on one of its level whose timer's
/// slot has HIGH, both timers for one deadline; S, FIFO at SPIN between
/// them, spins until H came back from its wait and notes whether W did.
/// Init lets them run: the firing of HIGH comes ahead of S and wakes H,
/// the firing of LEVEL waits until S ends, and only then W, whose level is
/// above S, gets its expiry. Only the priorities order them; a second on
/// the counter only keeps S from spinning forever.
fn timer_fires_at_its_slot_priority() -> Outcome {
    const SPIN: u8 = 15;
    reset_results();
    let low = channel(TEST_PRIORITY)?;
    let high = channel(HIGH)?;
    let timers = [timer_at(&low, LEVEL)?, timer_at(&high, HIGH)?];
    HANDLES[0].store(low.raw().0, Relaxed);
    HANDLES[1].store(high.raw().0, Relaxed);
    let h = spawn(1, receive_then_look, 1, HIGH, Policy::Fifo)?;
    let w = spawn(0, receive_then_look, 0, TEST_PRIORITY, Policy::Fifo)?;
    // W, behind init at its level, waits once init yields to it.
    let yielded = sys::yield_now();
    let s = spawn(2, look_once_ended, 1, SPIN, Policy::Fifo)?;
    let armed = clock_now().and_then(|now| {
        let at = now + 1_000_000;
        timers.iter().try_for_each(|t| arm(t, at))
    });
    let ran = armed.and_then(|()| let_run());
    for t in [h, w, s] {
        close(t)?;
    }
    for t in timers {
        close(t)?;
    }
    close(low)?;
    close(high)?;
    ran?;
    check(yielded.is_ok(), "yield failed")?;
    check(
        ended(0) && ended(1) && result(0)[0] == 0 && result(1)[0] == 0,
        "a timer's expiry did not come",
    )?;
    check(
        result(2)[..2] == [1, 0],
        "the timer of W fired above its slot's priority, or that of H below",
    )
}

/// Spins until the thread in `slot` came back from its call, or a second
/// passed, and leaves in `result` of slot 2 whether it did and whether the
/// thread in slot 0 did by then; ends.
extern "C" fn look_once_ended(slot: u64) -> ! {
    let end = time::now() + time::ns_to_ticks(1_000_000_000);
    while !ended(slot as usize) && time::now() < end {}
    record(
        2,
        &[ENDED[slot as usize].load(Relaxed), ENDED[0].load(Relaxed)],
    );
    sys::thread_exit()
}

/// Spec 15.2 (notifications): a process pays for abi::MAX_TIMERS timers at
/// most (spec 10). With 64 made, the next timer_create fails with
/// LIMIT_REACHED and changes x0 alone; once one of them went, another
/// fits.
fn timer_limit_is_64() -> Outcome {
    let c = channel(QUIET)?;
    let mut timers = [const { None }; abi::MAX_TIMERS as usize];
    let made = timers.iter_mut().try_for_each(|slot| {
        *slot = Some(timer(&c)?);
        Ok(())
    });
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, QUIET.into()]);
    let after = raw_timer_create(x);
    let freed = timers[0].take().map(close);
    let again = sys::timer_create(&c, QUIET);
    let remade = again.is_ok();
    if let Ok(t) = again {
        close(t)?;
    }
    for t in timers.into_iter().flatten() {
        close(t)?;
    }
    close(c)?;
    made?;
    check(
        failed(after, x, Error::LimitReached),
        "a timer past 64 was made, or the call changed more than x0",
    )?;
    check(
        freed == Some(Ok(())) && remade,
        "no new timer fit once one went",
    )
}

// Memory objects (spec 7.3, 7.7).
