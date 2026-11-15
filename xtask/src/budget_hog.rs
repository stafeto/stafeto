// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the time budgets of threads (`tests/budget-hog`, spec 8)
//! under QEMU's -icount, on one CPU and on four: a hog at a high level with
//! a budget of C for each period T must not take more than C of a window of
//! T from a task of a lower level on the same CPU, with no level running
//! above the hog (with one above it, the hog may take 2C of a window of T:
//! phase `carry` measures that, within the bound of the lag), and without
//! the budget the hog starves it. The lines the probe prints are checked against
//! their bounds here; `breaks` runs the same probe on the kernels with a
//! deliberate break, each of which must fail it.

use std::time::Duration;

use crate::{BOOT_PROFILE, BUDGET_HOG_PROGRAMS, Variant, build, build_boot_image, qemu};

const TIMEOUT: Duration = Duration::from_secs(180);

/// The numbers of the probe's lines: `budget window=10 min_share=873 ...`.
fn number(line: &str, key: &str) -> Result<u64, String> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(key))
        .ok_or_else(|| format!("missing {key} in {line:?}"))?
        .parse()
        .map_err(|e| format!("bad {key} in {line:?}: {e}"))
}

/// What the probe measured: the least share (per mille) of the victim and the
/// most time of the hog in microseconds for each window, the round trip of
/// the service's request and the victim's numbers with the notification's
/// boost.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Numbers {
    /// (window in ms, least victim share in per mille, most hog time in us,
    /// least hog time in us, times the budget ran out)
    pub windows: Vec<(u64, u64, u64, u64, u64)>,
    pub boost_n: u64,
    pub boost_max_us: u64,
    pub slot_share: u64,
    pub slot_gap_us: u64,
    pub victim_gap_us: u64,
    /// The same windows on CPU 1, when the machine has one.
    pub cpu1: Vec<(u64, u64, u64, u64, u64)>,
    pub cpu1_gap_us: u64,
    /// The requests a client with a budget made of a service whose budget
    /// was gone, and the times its budget ran out, with the service on its
    /// own CPU and on another ((0, 0) when the phase did not run).
    pub loan_same: (u64, u64),
    pub loan_other: (u64, u64),
    /// The requests a client at 40 made of a service that held a request
    /// of a client at 5 and had no budget, and the longest wait of one of
    /// them for the service, its own work not counted, in microseconds,
    /// with the service on its own CPU and on another ((0, 0) when the
    /// phase did not run).
    pub queue_same: (u64, u64),
    pub queue_other: (u64, u64),
    /// The overrun phase: the notifications that came, those not of count 1,
    /// the overruns the hog's budget counted, at the unbind half way and at
    /// the end; the unbind's results; the overruns of the polite thread and
    /// what its place held.
    pub overrun: Overrun,
    /// The carry phase: (window in ms, most hog time in us, least victim
    /// time in us).
    pub carry: Vec<(u64, u64, u64)>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Overrun {
    pub seen: bool,
    pub notes_at_unbind: u64,
    pub overruns_at_unbind: u64,
    pub bad: u64,
    pub unbound: bool,
    pub second_refused: bool,
    pub free: bool,
    pub notes_end: u64,
    pub overruns_end: u64,
    pub polite_overruns: u64,
    pub quiet: u64,
}

/// The budget of the hog, 300 us for each 1 ms, and the longest stretch the
/// kernel runs with interrupts masked (B), in microseconds under -icount: the
/// 8 865 instructions measured (kernel-test icount) of 16 ns each, with a
/// little room.
/// The most requests of the loan phase its budget pays for: 600 us for each
/// 2 ms of the 100 ms, at 500 us a request, make 60 at most (52 measured; a
/// client that is not charged makes 181 on its CPU).
const LOAN_MOST: u64 = 64;
/// The fewest requests the loan phase's client makes with the service on its
/// own CPU: the service goes from its reply to its next receive in one entry
/// (`reply_receive`), so it never waits at its low level behind the spinner
/// between two requests, and the client gets one request for each 2 ms
/// period (52 measured). The split of `reply_receive` into two entries has
/// its own kernel test (`reply_receive_takes_the_queued_request_at_its_level`):
/// the count of this phase with that break depends on the user code of
/// `Token::reply_receive` (9 requests with one body of it, 50 with another, on
/// one CPU and on four alike), so this bound judges the loan only.
const LOAN_LEAST_SAME: u64 = 26;
/// The longest wait of the client at 40 of the queue phase, its own 500 us of
/// work not counted: the rest of the request in hand (500 us at most), B for
/// the kernel's longest stretch, and 100 us for the entries and the lift.
const QUEUE_WAIT_US: u64 = 500 + 150 + 100;
/// The fewest requests the queue phase's client at 40 makes: one every 4 ms.
const QUEUE_LEAST: u64 = 5;
/// The fewest overruns of the hog of the overrun phase in its 100 ms before the
/// unbind: one for each period of 1 ms, less the start.
const OVERRUNS_LEAST: u64 = 80;
const HOG_US: u64 = 300;
const B_US: u64 = 150;
/// The carry phase: the interferer's work in each 2 ms (also the lag J of the
/// hog), its budget's period, and the hog's period, in microseconds.
const CARRY_J_US: u64 = 700;
const CARRY_SPIN_PERIOD_US: u64 = 2000;
const HOG_PERIOD_US: u64 = 1000;

/// The most a server of the budget `c` and the period `t` runs in a window of
/// `l` (all in the same unit) when a chunk lags `j` behind its activation:
/// `n * c + min(c, l + j - n * t)`, `n = (l + j) / t`.
fn window_bound(l: u64, c: u64, t: u64, j: u64) -> u64 {
    let n = (l + j) / t;
    n * c + c.min(l + j - n * t)
}

pub fn parse(lines: &[String]) -> Result<Numbers, String> {
    if !lines.iter().any(|l| l.starts_with("budget START "))
        || !lines.iter().any(|l| l == "budget DONE")
    {
        return Err(format!("the probe did not finish: {:?}", lines.last()));
    }
    let mut n = Numbers::default();
    for line in lines {
        let (rest, on_cpu1) = match line.strip_prefix("budget cpu1 ") {
            Some(rest) => (rest, true),
            None => (line.strip_prefix("budget ").unwrap_or(""), false),
        };
        if let Some(rest) = rest.strip_prefix("window=") {
            let w: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|w| w.parse().ok())
                .ok_or_else(|| format!("bad window in {line:?}"))?;
            let row = (
                w,
                number(line, "min_share=")?,
                number(line, "max_hog=")?,
                number(line, "hog_min=")?,
                number(line, "overruns=")?,
            );
            if on_cpu1 {
                n.cpu1.push(row);
            } else {
                n.windows.push(row);
            }
        } else if rest.starts_with("gaps ") {
            let gap = number(line, "victim_us=")?;
            if on_cpu1 {
                n.cpu1_gap_us = gap;
            } else {
                n.victim_gap_us = gap;
            }
        } else if line.starts_with("budget boost ") {
            n.boost_n = number(line, "n=")?;
            n.boost_max_us = number(line, "max_round_trip_us=")?;
        } else if line.starts_with("budget loan same ") {
            n.loan_same = (number(line, "requests=")?, number(line, "overruns=")?);
        } else if line.starts_with("budget loan other ") {
            n.loan_other = (number(line, "requests=")?, number(line, "overruns=")?);
        } else if line.starts_with("budget queue same ") {
            n.queue_same = (number(line, "requests=")?, number(line, "wait_us=")?);
        } else if line.starts_with("budget queue other ") {
            n.queue_other = (number(line, "requests=")?, number(line, "wait_us=")?);
        } else if line.starts_with("budget overrun unbind ") {
            n.overrun.seen = true;
            n.overrun.notes_at_unbind = number(line, "notes=")?;
            n.overrun.bad = number(line, "bad=")?;
            n.overrun.overruns_at_unbind = number(line, "overruns=")?;
            n.overrun.unbound = number(line, "first=")? == 1;
            n.overrun.second_refused = number(line, "second_is_bad_state=")? == 1;
            n.overrun.free = number(line, "free=")? == 1;
        } else if line.starts_with("budget overrun end ") {
            n.overrun.notes_end = number(line, "notes=")?;
            n.overrun.bad = n.overrun.bad.max(number(line, "bad=")?);
            n.overrun.overruns_end = number(line, "overruns=")?;
            n.overrun.polite_overruns = number(line, "polite_overruns=")?;
            n.overrun.quiet = number(line, "quiet=")?;
        } else if line.starts_with("budget carry window=") {
            n.carry.push((
                number(line, "window=")?,
                number(line, "hog_max_us=")?,
                number(line, "victim_min_us=")?,
            ));
        } else if line.starts_with("budget slot ") {
            n.slot_share = number(line, "min_share=")?;
            n.slot_gap_us = number(line, "max_gap_us=")?;
        }
    }
    if n.windows.len() != 3
        || n.boost_n == 0
        || n.loan_same.0 == 0
        || n.queue_same.0 == 0
        || !n.overrun.seen
        || n.carry.len() != 4
        || n.slot_share == 0 && n.slot_gap_us == 0
    {
        return Err(format!("the probe's lines are incomplete: {n:?}"));
    }
    Ok(n)
}

/// The bounds of the probe against what it measured.
pub fn verdict(n: &Numbers, cpus: usize) -> Result<(), String> {
    if cpus >= 2 && n.cpu1.len() != 3 {
        return Err("the probe did not run its hog on CPU 1".into());
    }
    for &(window, share, hog_most, hog_least, overruns) in n.windows.iter().chain(&n.cpu1) {
        // The hog takes the budget for each period the window touches, and
        // one longest call of the kernel (B) more.
        let most = window * HOG_US + B_US;
        if hog_most > most {
            return Err(format!(
                "the hog took {hog_most} us in a window of {window} ms: over {most}"
            ));
        }
        // The victim keeps what the hog and the trusted work leave: 70 % less
        // a tenth for the work of the kernel and the probe's own threads.
        if share < 600 {
            return Err(format!(
                "the victim got {share} per mille in a window of {window} ms: under 600"
            ));
        }
        // The budget comes back: the hog runs its budget in every window of
        // 5 ms and more.
        if window >= 5 && hog_least < window * HOG_US * 3 / 4 {
            return Err(format!(
                "the hog took {hog_least} us in a window of {window} ms: its budget did not come back"
            ));
        }
        if overruns == 0 {
            return Err("the budget of the hog never ran out".into());
        }
    }
    // The victim waits for the hog's budget and the worker's, and the
    // work of the kernel between them; a gap longer than a period is the
    // hog without a budget.
    if n.victim_gap_us.max(n.cpu1_gap_us) > 1000 - HOG_US + B_US {
        return Err(format!(
            "the victim waited {} us: over {}",
            n.victim_gap_us,
            1000 - HOG_US + B_US
        ));
    }
    // The carry: the interferer at 55 holds the CPU over the hog's
    // activation, so the hog takes more than C of a window of 1 ms, up to 2C
    // (the carry-in that "no more than C in a window of T" denies when a level
    // stands above it: no more than C and the kernel's longest stretch means
    // the phase does not test what it says).
    // It never takes more than the bound with the lag J of the interferer,
    // and the victim keeps what the busy period leaves: the window less the
    // interferer's 700 us of each 2 ms and the hog's 300 us of each 1 ms, the
    // kernel's longest stretch and a twentieth for the probe's own threads.
    for &(window, hog_most, victim_least) in &n.carry {
        let l = window * 1000;
        let most = window_bound(l, HOG_US, HOG_PERIOD_US, CARRY_J_US) + B_US;
        if hog_most > most {
            return Err(format!(
                "the hog took {hog_most} us in a window of {window} ms with a level above it: over {most}"
            ));
        }
        if window == 1 && hog_most <= HOG_US + B_US {
            return Err(format!(
                "the hog took {hog_most} us in a window of 1 ms: not over {}, the carry-in did not show",
                HOG_US + B_US
            ));
        }
        let owed =
            l.div_ceil(CARRY_SPIN_PERIOD_US) * CARRY_J_US + l.div_ceil(HOG_PERIOD_US) * HOG_US;
        let least = l.saturating_sub(owed + B_US + l / 20);
        if victim_least < least {
            return Err(format!(
                "the victim got {victim_least} us in a window of {window} ms with a hog and a level above it: under {least}"
            ));
        }
    }
    // The service's request takes its 500 us of work and no more: the boost
    // of its client stays when the budget of 200 us is gone.
    if n.boost_max_us > 700 {
        return Err(format!(
            "a request took {} us: the boost of its client did not stay with the budget gone",
            n.boost_max_us
        ));
    }
    // The loan: the 500 us of each request of a service whose budget is
    // gone are time of the client, whose budget of 600 us for each 2 ms then
    // runs out, and it makes at most 32 requests in the 50 ms of the phase
    // (a client that is not charged makes about 90 with the service on
    // another CPU).
    let mut loans = vec![("on its CPU", n.loan_same)];
    if cpus >= 2 {
        loans.push(("on another", n.loan_other));
    }
    let mut lost = Vec::new();
    for (what, (requests, overruns)) in loans {
        let least = if what == "on its CPU" {
            LOAN_LEAST_SAME
        } else {
            1
        };
        if overruns == 0 || !(least..=LOAN_MOST).contains(&requests) {
            lost.push(format!(
                "a client made {requests} requests of a service {what} whose budget was gone and its budget ran out {overruns} times"
            ));
        }
    }
    if !lost.is_empty() {
        return Err(format!(
            "{}: its work was not lent to the client ({LOAN_LEAST_SAME} to {LOAN_MOST} requests, at least one overrun)",
            lost.join("; ")
        ));
    }
    // The queue: a request at 40 that queues behind the request a service
    // without a budget holds lifts the service, which ends that request and
    // takes the next one in the same entry; the client waits for the rest of
    // one request and for the kernel's longest stretch; the spinner takes none of it.
    let mut queues = vec![("on its CPU", n.queue_same)];
    if cpus >= 2 {
        queues.push(("on another", n.queue_other));
    }
    for (what, (requests, wait)) in queues {
        if requests < QUEUE_LEAST || wait > QUEUE_WAIT_US {
            return Err(format!(
                "a client at 40 made {requests} requests of a service {what} that held a request of a client at 5 and waited up to {wait} us: the request that queued did not lift it (at least {QUEUE_LEAST} requests, at most {QUEUE_WAIT_US} us)"
            ));
        }
    }
    // The overruns: one notification for each overrun the budget counts,
    // each of count 1; the polite thread, which stays within its budget,
    // posts none; the unbind frees the budget and the place posts nothing
    // after it.
    let o = &n.overrun;
    if o.overruns_at_unbind < OVERRUNS_LEAST
        || o.notes_at_unbind != o.overruns_at_unbind
        || o.bad != 0
    {
        return Err(format!(
            "the place of the hog's budget got {} notifications for {} overruns ({} not of count 1; at least {OVERRUNS_LEAST} overruns, one notification for each)",
            o.notes_at_unbind, o.overruns_at_unbind, o.bad
        ));
    }
    if o.polite_overruns != 0 || o.quiet != 0 {
        return Err(format!(
            "a thread within its budget overran {} times and its place got {}",
            o.polite_overruns, o.quiet
        ));
    }
    if !o.unbound || !o.second_refused || !o.free {
        return Err(format!(
            "the unbind of the hog's budget: done {}, second refused {}, budget free {}",
            o.unbound, o.second_refused, o.free
        ));
    }
    if o.notes_end != o.notes_at_unbind || o.overruns_end != o.overruns_at_unbind {
        return Err(format!(
            "the budget went on after its unbind: {} notifications and {} overruns, {} and {} at the unbind",
            o.notes_end, o.overruns_end, o.notes_at_unbind, o.overruns_at_unbind
        ));
    }
    // The worker at 55 for each notification gets its 200 us of each
    // period and the boost of the slot goes with the budget: the victim
    // keeps 750 per mille at least, and no gap of its own passes 400 us.
    if n.slot_share < 750 || n.slot_gap_us > 400 {
        return Err(format!(
            "the boost of a notification outlived the budget: the victim got {} per mille with a gap of {} us",
            n.slot_share, n.slot_gap_us
        ));
    }
    Ok(())
}

/// One run of the probe on `cpus` CPUs with the kernel of `variant`.
pub fn probe(variant: Variant, cpus: usize) -> Result<Numbers, String> {
    let image = build_boot_image("budget-hog.img", &BUDGET_HOG_PROGRAMS, BOOT_PROFILE)?;
    let kernel = build(variant)?;
    let outcome = qemu::on_cpus(cpus, || {
        let mut cmd = qemu::command(&qemu::VIRT_V3, &kernel.image, Some(&image));
        cmd.args(qemu::HEADLESS);
        cmd.args(qemu::ICOUNT);
        qemu::run_until(cmd, TIMEOUT, Some("budget DONE"))
    })?;
    if outcome.timed_out || !outcome.stopped_on_marker {
        return Err(format!(
            "the probe on {cpus} CPUs did not finish: {:?}",
            outcome.lines.last()
        ));
    }
    for line in outcome.lines.iter().filter(|l| l.starts_with("budget ")) {
        println!("  [{cpus} CPUs] {line}");
    }
    parse(&outcome.lines)
}

pub fn run(args: &[String]) -> Result<(), String> {
    let cpus: Vec<usize> = match args {
        [] => vec![1, 4],
        [flag, n] if flag == "--cpus" => vec![
            n.parse()
                .ok()
                .filter(|n| (1..=8).contains(n))
                .ok_or("budget-hog --cpus expects 1..=8")?,
        ],
        _ => return Err("usage: cargo xtask budget-hog [--cpus N]".into()),
    };
    for n in cpus {
        let numbers = probe(Variant::Normal, n)?;
        verdict(&numbers, n).map_err(|e| format!("budget-hog on {n} CPUs: {e}"))?;
        println!("budget-hog: {n} CPUs pass");
    }
    Ok(())
}

/// `cargo xtask budget-break-unbound`: the share probe of the network service fails on the
/// image whose switch and stack bind no budget. The loop below the switch must lose the CPU in
/// the flood: its seconds up to the quiet ones came, and then none (a bounded wait counts that
/// silence as the catch), or it kept too little of its share. A probe that broke elsewhere
/// (the boot, the quiet seconds) fails the command.
pub fn unbound_break() -> Result<(), String> {
    match crate::fast_switch::probe(crate::fast_switch::Scenario::ShareUnbound) {
        Err(e) if crate::fast_switch::unbound_caught(&e) => {
            println!("budget-breaks: a network service that binds no budget is caught ({e})")
        }
        Err(e) => {
            return Err(format!(
                "the break (budget-unbound): the share probe broke: {e}"
            ));
        }
        Ok(()) => return Err("the break (budget-unbound) passed the share probe".into()),
    }
    Ok(())
}

/// `cargo xtask budget-breaks`: the probe fails on each kernel with a
/// break, the kernel tests fail the test of the level of a process on the
/// kernel that ignores it, and the host tests of kcore fail on each break
/// of the rules, the share probe of the network service fails on a service with no budget
/// bound (`break-budget-unbound`), and those of init fail the check of the shares of a CPU that lets a table
/// pass whatever its budgets take (`break-budget-share`).
pub fn breaks() -> Result<(), String> {
    for (variant, what) in [
        (Variant::BudgetOff, "a bind that binds nothing"),
        (
            Variant::BudgetSlotKeeps,
            "a boost of a notification that outlives the budget",
        ),
        (Variant::BudgetRefill, "a replenishment that never applies"),
        (
            Variant::BudgetKeepLevel,
            "a thread that keeps its level when its budget is gone",
        ),
        (
            Variant::BudgetForgiveLoan,
            "a server whose work for a client is not lent to it",
        ),
        (
            Variant::BudgetNoQueueLift,
            "a request that queues behind a server without a budget and does not lift it",
        ),
        (
            Variant::BudgetOverrunSilent,
            "an overrun that posts nothing to the budget's place",
        ),
    ] {
        // On four CPUs, so that the loan phase with the service on another
        // CPU runs on the break too.
        let cpus = if matches!(
            variant,
            Variant::BudgetForgiveLoan | Variant::BudgetNoQueueLift | Variant::BudgetOverrunSilent
        ) {
            4
        } else {
            1
        };
        match probe(variant, cpus).and_then(|n| verdict(&n, cpus)) {
            Err(e) => println!("budget-breaks: {what} is caught ({e})"),
            Ok(()) => return Err(format!("the break ({what}) passed the probe")),
        }
    }
    for (variant, test, what) in [
        (
            Variant::BudgetNoFree,
            "a_thread_with_no_budget_works_at_the_free_level",
            "a thread with no budget above the level of its process",
        ),
        (
            Variant::BudgetChildFree,
            "a_thread_with_no_budget_works_at_the_free_level",
            "a child with more free level than its creator",
        ),
        (
            Variant::BudgetNoQueueLiftTest,
            "a_request_that_queues_lifts_a_demoted_server_of_its_cpu",
            "a request that queues and does not lift the server",
        ),
        (
            Variant::BudgetOverrunSilentTest,
            "an_overrun_posts_one_notification_for_each_period",
            "an overrun that posts nothing to the budget's place",
        ),
        (
            Variant::BudgetUnbindKeepsTest,
            "unbinding_gives_a_thread_min_of_its_base_and_free",
            "an unbind that leaves the thread at the level its budget gave it",
        ),
        (
            Variant::NoticeHolderKeepsTest,
            "a_notification_holder_is_not_lifted_after_its_next_receive_or_send",
            "a thread that goes on holding a notification after its receive",
        ),
        (
            Variant::ReplyReceiveSplitTest,
            "reply_receive_takes_the_queued_request_at_its_level",
            "a reply_receive that returns to EL0 between its reply and its receive",
        ),
        (
            Variant::ReplyReceiveCopyTest,
            "reply_receive_copies_a_long_reply_before_it_takes_a_long_request",
            "a reply_receive that leaves the copy of its reply waiting while it takes a request",
        ),
        (
            Variant::NoticePayerNoneTest,
            "a_lift_is_not_charged_to_a_sender_that_waits_on_another_channel",
            "a lift of a notification's holder that names no payer",
        ),
        (
            Variant::LiftAgainNoticeTest,
            "a_receive_that_takes_a_notification_above_a_request_keeps_the_lift",
            "a holder that a receive of a notification leaves below a queued request",
        ),
        (
            Variant::LiftAgainReplyTest,
            "a_reply_between_the_halves_keeps_the_lift_a_queued_request_gave",
            "a holder that the reply between the halves leaves below a queued request",
        ),
        (
            Variant::BudgetUnbindNoChargeTest,
            "unbinding_gives_a_thread_min_of_its_base_and_free",
            "an unbind that does not charge the stint that runs",
        ),
        (
            Variant::BudgetUnbindKeepsEventTest,
            "the_timer_of_an_unbound_budget_leaves_the_former_thread_alone",
            "an unbind that leaves the event of the budget in the heap",
        ),
    ] {
        let a = build(variant)?;
        let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
        cmd.args(qemu::HEADLESS);
        let o = qemu::run_until(cmd, Duration::from_secs(300), None)?;
        let report = qemu::parse_report(&o.lines);
        // Only the break that leaves the event of an unbound budget in the heap
        // stops the run with a panic, in the free of the budget's place after
        // the named test; the test before it passed, the named one did not
        // report. Every other break must fail its test cleanly.
        let panicked = variant == Variant::BudgetUnbindKeepsEventTest
            && o.lines
                .iter()
                .any(|l| l == "KERNEL PANIC: a timer where the count puts one")
            && o.lines
                .iter()
                .any(|l| l == "TEST unbinding_a_client_lifts_the_server_that_works_for_it ok")
            && !o
                .lines
                .iter()
                .any(|l| l.starts_with(&format!("TEST {test} ")));
        // The break that leaves the copy of the reply waiting stops the run in
        // the named test with the panic of `copy_later`.
        // The test before it passed, and the named one did not report.
        let panicked = panicked
            || (variant == Variant::ReplyReceiveCopyTest
                && o.lines
                    .iter()
                    .any(|l| l.starts_with("KERNEL PANIC: a message copy waits for another"))
                && o.lines
                    .iter()
                    .any(|l| l == "TEST reply_receive_takes_the_queued_request_at_its_level ok")
                && !o
                    .lines
                    .iter()
                    .any(|l| l.starts_with(&format!("TEST {test} "))));
        if !panicked && !report.failed.iter().any(|(name, _)| name == test) {
            return Err(format!("the kernel with {what} passed its test"));
        }
        println!("budget-breaks: {what} is caught");
    }
    for feature in [
        "break-budget-refill",
        "break-budget-short-period",
        "break-budget-merge-always",
        "break-budget-no-overrun",
        "break-budget-keep-level",
        "break-budget-keep-slot",
        "break-budget-no-free",
        "break-budget-child-free",
        "break-budget-forgive-overrun",
        "break-budget-skip-boosted",
        "break-budget-handoff",
        "break-budget-forgive-loan",
        "break-budget-overrun-silent",
        "break-budget-unbind-keeps",
        "break-budget-unbind-no-charge",
        "break-budget-unbind-keeps-event",
        "break-budget-early-replenish",
        "break-budget-full-queue-delay",
    ] {
        let out =
            std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .current_dir(crate::root())
                .args(["test", "-p", "kcore", "--features", feature])
                .output()
                .map_err(|e| format!("cargo test: {e}"))?;
        if out.status.success() {
            return Err(format!("the host tests of kcore passed with {feature}"));
        }
        println!("budget-breaks: {feature} fails the host tests");
    }
    unbound_break()?;
    // init's table check: budgets that take all of a CPU must be refused.
    let out = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(crate::root())
        .args([
            "test",
            "-p",
            "init",
            "--lib",
            "--features",
            "break-budget-share",
        ])
        .output()
        .map_err(|e| format!("cargo test: {e}"))?;
    if out.status.success() {
        return Err("the host tests of init passed with break-budget-share".into());
    }
    println!("budget-breaks: break-budget-share fails the host tests of init");
    // init's journal of the overruns, and the three services with their request threads
    // unbound and init with no `free` level.
    crate::budget_journal::breaks()?;
    crate::service_budget::breaks(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(share: u64, hog: u64, boost: u64, slot: (u64, u64)) -> Vec<String> {
        vec![
            "budget START hz=62500000".into(),
            format!("budget window=1 min_share={share} max_hog={hog} hog_min=0 overruns=3"),
            format!(
                "budget window=5 min_share={share} max_hog={} hog_min=1400 overruns=3",
                hog * 5
            ),
            format!(
                "budget window=10 min_share={share} max_hog={} hog_min=2900 overruns=3",
                hog * 10
            ),
            "budget gaps victim_us=500 hog_us=100".into(),
            format!("budget boost n=40 max_round_trip_us={boost}"),
            "budget loan same requests=52 overruns=50".into(),
            "budget loan other requests=9 overruns=8".into(),
            "budget queue same requests=20 wait_us=400".into(),
            "budget queue other requests=20 wait_us=400".into(),
            format!("budget slot min_share={} max_gap_us={}", slot.0, slot.1),
            "budget overrun unbind notes=100 bad=0 overruns=100 first=1 second_is_bad_state=1 free=1".into(),
            "budget overrun end notes=100 bad=0 overruns=100 polite_overruns=0 quiet=0".into(),
            "budget carry window=1 hog_max_us=600 victim_min_us=0".into(),
            "budget carry window=2 hog_max_us=600 victim_min_us=700".into(),
            "budget carry window=5 hog_max_us=1500 victim_min_us=1700".into(),
            "budget carry window=10 hog_max_us=3000 victim_min_us=3500".into(),
            "budget DONE".into(),
        ]
    }

    #[test]
    fn a_probe_run_within_its_bounds_passes() {
        let n = parse(&lines(700, 300, 600, (800, 250))).unwrap();
        assert_eq!(n.windows.len(), 3);
        verdict(&n, 1).unwrap();
    }

    #[test]
    fn each_bound_fails_its_own_number() {
        for (case, text) in [
            (lines(50, 300, 600, (800, 250)), "victim got"),
            (lines(700, 600, 600, (800, 250)), "the hog took"),
            (lines(700, 300, 1500, (800, 250)), "request took"),
            (lines(700, 300, 600, (400, 900)), "outlived"),
        ] {
            let e = verdict(&parse(&case).unwrap(), 1).unwrap_err();
            assert!(e.contains(text), "{e}");
        }
    }

    #[test]
    fn the_carry_phase_checks_the_carry_in_the_hog_bound_and_the_victim() {
        let base = lines(700, 300, 600, (800, 250));
        for (from, to, text) in [
            // No carry-in: the phase would test nothing.
            (
                "window=1 hog_max_us=600",
                "window=1 hog_max_us=400",
                "carry-in did not show",
            ),
            // More than the bound with the lag.
            (
                "window=2 hog_max_us=600",
                "window=2 hog_max_us=1200",
                "with a level above it",
            ),
            // The victim starved.
            (
                "window=10 hog_max_us=3000 victim_min_us=3500",
                "window=10 hog_max_us=3000 victim_min_us=1000",
                "the victim got",
            ),
        ] {
            let case: Vec<String> = base.iter().map(|l| l.replace(from, to)).collect();
            let e = verdict(&parse(&case).unwrap(), 1).unwrap_err();
            assert!(e.contains(text), "{e}");
        }
        let short: Vec<String> = base
            .iter()
            .filter(|l| !l.starts_with("budget carry "))
            .cloned()
            .collect();
        assert!(parse(&short).is_err());
    }

    #[test]
    fn a_queue_wait_over_its_bound_fails() {
        let mut l = lines(700, 300, 600, (800, 250));
        for line in &mut l {
            if line.starts_with("budget queue same ") {
                *line = "budget queue same requests=20 wait_us=22000".into();
            }
        }
        let e = verdict(&parse(&l).unwrap(), 1).unwrap_err();
        assert!(e.contains("did not lift it"), "{e}");
        let mut l = lines(700, 300, 600, (800, 250));
        for line in &mut l {
            if line.starts_with("budget loan same ") {
                *line = "budget loan same requests=2 overruns=1".into();
            }
        }
        let e = verdict(&parse(&l).unwrap(), 1).unwrap_err();
        assert!(e.contains("not lent"), "{e}");
    }

    #[test]
    fn a_silent_place_or_a_budget_that_goes_on_after_its_unbind_fails() {
        for (from, to, text) in [
            (
                "unbind notes=100 bad=0",
                "unbind notes=0 bad=0",
                "notifications for",
            ),
            (
                "unbind notes=100 bad=0",
                "unbind notes=100 bad=3",
                "not of count 1",
            ),
            (
                "polite_overruns=0 quiet=0",
                "polite_overruns=0 quiet=1",
                "within its budget",
            ),
            (
                "second_is_bad_state=1",
                "second_is_bad_state=0",
                "unbind of the hog",
            ),
            (
                "end notes=100 bad=0 overruns=100",
                "end notes=140 bad=0 overruns=140",
                "went on after",
            ),
        ] {
            let mut l = lines(700, 300, 600, (800, 250));
            for line in &mut l {
                if line.contains(from) {
                    *line = line.replace(from, to);
                }
            }
            let e =
                verdict(&parse(&l).unwrap(), 1).expect_err(&format!("{from} passed the verdict"));
            assert!(e.contains(text), "{e}");
        }
    }

    #[test]
    fn a_run_that_did_not_finish_is_refused() {
        let mut l = lines(700, 300, 600, (800, 250));
        l.pop();
        assert!(parse(&l).is_err());
    }
}
