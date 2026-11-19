// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The arithmetic of the starvation gate, in microseconds, with no dependency: the probe prints
//! the terms with it and `cargo xtask service-budget` includes this file (`#[path]`) to read the
//! lines back and to test the numbers on the host.
//!
//! A window is ten cycles of the victim, from the start of the first to the end of the tenth,
//! sleeps included. `R` is the time the victim ran in it, `W` the time it was awake and `l` the
//! length of the window by the clock. The victim lost `L = W - R`, which is `R (1000 - s) / s`
//! for the share `s = 1000 R / W` per mille. What the budgets of the services explain is
//!
//! ```text
//! L <= S + E + 20 + I (+ D + E_d)
//! S = n C + min(C, l - n T) + B   n = l / T rounded down, B one overrun at the edge
//! E = 2 e (k + 1)                 k the overruns of the budget in the window
//! I                               the allowance of init for the service
//! D = n_d C_d + min(C_d, l - n_d T_d) + B   the console driver's budget, for the terminal phase
//!                                 (`service_us` with the driver's C and T: 75 us of each 5 ms)
//! E_d = 2 e (k_d + 1)             the events of the driver's budget, k_d its overruns in the window
//! ```
//!
//! `S` is the bound of the kernel (the module comment of `kcore/src/budget.rs`) for a thread
//! that runs at its own level for `C` of each `T`. The bound is taken over the whole window `l`:
//! a service may take its pieces while the victim sleeps, and a bound over `l` is an upper
//! bound.
//!
//! What the probe measures of the budgets is taken over the awake spans of the victim, the time
//! the loss `L = W - R` is counted over. For each cycle `c` of the window the victim reads the
//! counters just before its awake span (`SAMPLE_START[c]`) and just after it (`SAMPLE_END[c]`),
//! and for `X` in the `ran` and the `overruns` of the service and of the driver
//!
//! ```text
//! X_W = sum over c of (X(SAMPLE_END[c]) - X(SAMPLE_START[c]))      (`awake_sum`)
//! left = L - serve_ran_W - drv_ran_W - 2 e (k_W + 1) - 20          k_W = serve overruns_W
//! -e (k_W + 1) <= left                                              (`left_floor_us`)
//! ```
//!
//! The same counters over the length of the window, `serve_ran_l` and `drv_ran_l`, take in the
//! sleeps of the victim, where a service or the driver may run with the victim losing nothing,
//! and are printed beside the awake sums for information. A timer event of the budget of the
//! service that comes while the service or the driver runs is in their `ran` and in `E` both,
//! which is why `left` may fall to `-e (k_W + 1)`; what is left above zero is the work of init
//! and the heartbeats (`I`).

// The probe prints the terms and the gate reads them: each uses only part of this file.
#![allow(dead_code)]

/// The loss of a window, `W - R`.
pub const fn loss_us(r: u64, w: u64) -> u64 {
    w.saturating_sub(r)
}

/// The loss from the share `s` (per mille) of a window in which the victim ran `r`:
/// `r (1000 - s) / s`. The linearised `(1000 - s) * 8` is short of it by the factor `s / 1000`.
pub fn loss_from_share(r: u64, s: u64) -> u64 {
    (r * 1000u64.saturating_sub(s)).checked_div(s).unwrap_or(0)
}

/// The part of the window a budget of `c` of each `t` may take at its own level: `n c +
/// min(c, l - n t)` and one overrun `b` at the edge.
pub const fn service_us(c: u64, t: u64, b: u64, l: u64) -> u64 {
    let n = l / t;
    let rest = l - n * t;
    n * c + if rest < c { rest } else { c } + b
}

/// The timer events of the chunks of the budget in the window: the exhaustion and the
/// replenishment of each of `k + 1` chunks, `e` each of the two, `k` the overruns counted.
pub const fn events_us(e: u64, k: u64) -> u64 {
    2 * e * (k + 1)
}

/// The kernel's entries into the victim's own run that are no work of the victim (two of 10
/// microseconds).
pub const ENTRIES_US: u64 = 20;

/// The bound of the loss of the window: `S + E + 20 + I + D + E_d`, where `E_d` is the timer
/// events of the driver's own budget (`events_us` over its overruns in the window; 0 where the
/// driver takes no part).
pub const fn bound_us(
    service: u64,
    events: u64,
    init: u64,
    driver: u64,
    driver_events: u64,
) -> u64 {
    service + events + ENTRIES_US + init + driver + driver_events
}

/// The share, per mille, the victim keeps at least when it loses no more than `bound` in a
/// window in which it ran `r`: `1000 R / (R + bound)`.
pub fn share_bound_permille(r: u64, bound: u64) -> u64 {
    (1000 * r).checked_div(r + bound).unwrap_or(1000)
}

/// What the loss has over the bound: positive when the bound is broken.
pub const fn over_bound(loss: u64, bound: u64) -> i64 {
    loss as i64 - bound as i64
}

/// What is left of the loss when every term the probe measures is taken off (the `X` of the
/// note): `L - serve_ran - driver_ran - 2 e (overruns + 1) - 20`. The allowance of init and the
/// heartbeats of the services are not measured and are not in it.
pub const fn left_us(loss: u64, serve_ran: u64, driver_ran: u64, e: u64, overruns: u64) -> i64 {
    loss as i64
        - serve_ran as i64
        - driver_ran as i64
        - events_us(e, overruns) as i64
        - ENTRIES_US as i64
}

/// The sum over the cycles of a window of what a counter grew by between the two samples of the
/// cycle (just before its awake span and just after it): `pairs` are `(start, end)` of each
/// cycle. The sleeps of the victim between the cycles are not in it.
pub fn awake_sum(pairs: impl IntoIterator<Item = (u64, u64)>) -> u64 {
    pairs
        .into_iter()
        .map(|(start, end)| end.saturating_sub(start))
        .sum()
}

/// The lowest `left` the account allows, `-e (k_W + 1)`: the timer events that come during the
/// spans of the service or of the driver are in their `ran` and in `E`.
pub const fn left_floor_us(e: u64, overruns: u64) -> i64 {
    -((e * (overruns + 1)) as i64)
}

/// The terms of the control phase's worst window, where the victim runs against a spinner under
/// a budget of `c` and no service: what the budget and its events (`e` from the median window of
/// the same phase, two events a period) explain is `n c + min(c, l - n t) + 2 e n + 20`; the
/// loss over that is left.
pub const fn control_left_us(loss: u64, c: u64, t: u64, l: u64, e: u64) -> i64 {
    let n = l / t;
    loss as i64 - service_us(c, t, 0, l) as i64 - 2 * (e * n) as i64 - ENTRIES_US as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 5_000;
    const B: u64 = 150;
    const E: u64 = 30;
    const INIT: u64 = 70;

    #[test]
    fn the_exact_loss_of_run_44132799778() {
        // ramfs, pipe and tty: shares 886, 951 and 923 per mille over about 8000 us of running.
        assert_eq!(loss_from_share(8000, 886), 1029);
        assert_eq!(loss_from_share(8000, 951), 412);
        assert_eq!(loss_from_share(8000, 923), 667);
        // The linearised loss of the old gate undercounts them.
        assert_eq!((1000 - 886) * 8, 912);
        assert_eq!((1000 - 951) * 8, 392);
        assert_eq!((1000 - 923) * 8, 616);
        // W - R gives the same loss.
        assert_eq!(loss_us(8000, 9029), 1029);
        assert_eq!(loss_us(9000, 8000), 0);
    }

    #[test]
    fn the_third_c_is_in_a_window_longer_than_two_periods() {
        // The windows of the run: 10.83, 10.21 and 10.47 ms, n = 2, the second term saturated.
        assert_eq!(service_us(250, T, 0, 10_830), 750);
        assert_eq!(service_us(75, T, 0, 10_210), 225);
        assert_eq!(service_us(75, T, 0, 10_470), 225);
        // With the overrun at the edge.
        assert_eq!(service_us(250, T, B, 10_830), 900);
        assert_eq!(service_us(75, T, B, 10_210), 375);
        // A window a little over two periods has only part of the third.
        assert_eq!(service_us(250, T, 0, 10_100), 750 - 150);
        assert_eq!(service_us(250, T, 0, 10_000), 500);
    }

    #[test]
    fn the_events_count_the_chunks() {
        assert_eq!(events_us(E, 0), 60);
        assert_eq!(events_us(E, 2), 180);
    }

    #[test]
    fn the_bound_of_the_run_holds_for_ramfs_and_pipe_and_shows_the_driver_of_tty() {
        // From the note: ramfs 1029 <= 750 + 150 + 180 + 20 + 70 = 1170, pipe 412 <= 645.
        let ramfs = bound_us(service_us(250, T, B, 10_830), events_us(E, 2), INIT, 0, 0);
        assert_eq!(ramfs, 1170);
        assert!(over_bound(1029, ramfs) < 0);
        let pipe = bound_us(service_us(75, T, B, 10_210), events_us(E, 2), INIT, 0, 0);
        assert_eq!(pipe, 645);
        assert!(over_bound(412, pipe) < 0);
        // tty without the driver's term is over by 22, which is what is left for the driver.
        let tty = bound_us(service_us(75, T, B, 10_470), events_us(E, 2), INIT, 0, 0);
        assert_eq!(tty, 645);
        assert_eq!(over_bound(667, tty), 22);
        // With a driver term of 22 or more it holds.
        assert!(over_bound(667, bound_us(375, 180, INIT, 22, 0)) <= 0);
    }

    #[test]
    fn the_share_bound_is_the_loss_bound_in_shares() {
        // 8000 us run and 1170 us of loss allowed: 8000 / 9170 = 872 per mille. The linearised
        // bound 1000 - 1170 / 8 = 853 is milder by 18 per mille.
        assert_eq!(share_bound_permille(8000, 1170), 872);
        assert_eq!(1000 - 1170 / 8, 854);
        // The victim that kept 886 per mille (ramfs) is above it.
        assert!(886 >= share_bound_permille(8000, 1170));
        // 645 us: 8000 / 8645 = 925; the pipe's 951 holds, the tty's 923 does not.
        assert_eq!(share_bound_permille(8000, 645), 925);
        let bound = share_bound_permille(8000, 645);
        assert!(951 >= bound && 923 < bound);
        assert_eq!(share_bound_permille(0, 0), 1000);
    }

    #[test]
    fn what_is_left_takes_off_the_measured_terms_only() {
        // loss 667, serve ran 225, the driver 150, e 30, 3 overruns: 667 - 225 - 150 - 240 - 20.
        assert_eq!(left_us(667, 225, 150, E, 3), 32);
        // More taken off than lost is negative.
        assert_eq!(left_us(100, 225, 0, E, 0), -205);
    }

    #[test]
    fn the_awake_spans_leave_out_the_sleeps() {
        // Three cycles of a victim: the counter grows 10 in each awake span and 40 in each sleep
        // between them; the difference over the window takes in the two sleeps.
        let pairs = [(100, 110), (150, 160), (200, 210)];
        assert_eq!(awake_sum(pairs), 30);
        assert_eq!(210 - 100, 110);
        // A counter read that went backwards (a reset) counts nothing.
        assert_eq!(awake_sum([(5, 3), (3, 9)]), 6);
        assert_eq!(awake_sum([]), 0);
    }

    #[test]
    fn the_terminal_window_of_run_44389680495_before_and_after_the_awake_sums() {
        // From the issue: loss 630, serve ran 205, driver ran 538, events 480 (e 40 with 5 overruns
        // gives it), over the whole window l: left -613 by the old formula.
        let e = 40;
        assert_eq!(events_us(e, 5), 480);
        assert_eq!(left_us(630, 205, 538, e, 5), -613);
        // The awake sums of the same window are an assumption for the example: the driver ran
        // 120 us of its 538 while the victim was awake, the service 150 of 205, in 3 overruns.
        // The remainder is then inside the allowance of the note, and above its floor.
        let (serve_w, drv_w, k_w) = (150, 120, 3);
        assert_eq!(
            left_us(630, serve_w, drv_w, e, k_w),
            630 - 150 - 120 - 320 - 20
        );
        assert_eq!(left_us(630, serve_w, drv_w, e, k_w), 20);
        assert_eq!(left_floor_us(e, k_w), -160);
        assert!(left_us(630, serve_w, drv_w, e, k_w) >= left_floor_us(e, k_w));
        // The old remainder was below the floor of the awake account, which is the double count.
        assert!(left_us(630, 205, 538, e, 5) < left_floor_us(e, 5));
        assert_eq!(left_floor_us(e, 5), -240);
        // The bound is taken over l. The driver's term is the bound of its own budget (75 us of
        // each 5 ms) and no longer the time it ran: 375 us for this window, 163 under the 538 it
        // ran in all (its sleeps in the window included).
        let driver = service_us(75, T, B, 11_008);
        assert_eq!(driver, 375);
        let bound = bound_us(
            service_us(75, T, B, 11_008),
            events_us(e, 5),
            INIT,
            driver,
            0,
        );
        assert_eq!(bound, 375 + 480 + 20 + 70 + 375);
        // The loss of 630 us over the 8005 us the victim ran is inside it, with the share the
        // bound promises under what the victim kept (927 per mille).
        assert!(over_bound(630, bound) < 0);
        assert_eq!(share_bound_permille(8005, bound), 858);
        assert!(927 >= share_bound_permille(8005, bound));
    }

    #[test]
    fn the_events_of_the_drivers_budget_are_in_the_bound_of_the_terminal() {
        // The stub of the driver spends about 5 % against its 1.5 %, so its budget runs out in
        // every period: over the window of 11,008 us it is 2 periods and an edge, say 3 overruns,
        // each chunk with its two timer events (e 40): 2 * 40 * 4 = 320 us more of bound.
        let e = 40;
        assert_eq!(events_us(e, 3), 320);
        let base = bound_us(service_us(75, T, B, 11_008), events_us(e, 5), INIT, 375, 0);
        let with = bound_us(
            service_us(75, T, B, 11_008),
            events_us(e, 5),
            INIT,
            375,
            events_us(e, 3),
        );
        assert_eq!(with - base, 320);
        // A loss between the two bounds is inside only the second: 1,500 us against 1,320 and 1,640.
        assert_eq!((base, with), (1_320, 1_640));
        assert!(over_bound(1_500, base) > 0 && over_bound(1_500, with) < 0);
        // No overruns still count one chunk: 2 e.
        assert_eq!(events_us(e, 0), 80);
    }

    #[test]
    fn the_control_window_is_judged_by_its_own_terms() {
        // Worst window of the control phase of the run: 10 ms, C 250, loss 620 from the median
        // e of 30 ((620 - 500) / 4): the median window is explained, the entries take the 20 us
        // that lie under it.
        assert_eq!(
            control_left_us(620, 250, T, 10_000, E),
            620 - 500 - 120 - 20
        );
        // The worst window of the run (loss 1010, from 899 per mille) is 370 over (390 before the entries).
        assert_eq!(control_left_us(1010, 250, T, 10_000, E), 1010 - 640);
    }
}
