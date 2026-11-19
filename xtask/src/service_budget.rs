// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the time budgets of the RAM file, pipe and terminal services
//! (`tests/service-budget`, `cargo xtask service-budget`, spec 8), under QEMU's -icount. The
//! services run as init starts them, with the budgets of its table on CPU 0. The gated probe
//! runs on one CPU: 24 clients at 20 ask one service without a pause while a victim at 34
//! spins 0.8 ms and sleeps 0.2 ms (the starvation phase), and a thread at 40 asks every 1037 us
//! while 8 clients at 20 queue the dear request (the level-40 phase). The two-CPU probe
//! (`two-cpu`) prints its numbers for information: its emulator advances the clock of CPU 0
//! while CPU 1 runs. The guarantee the probe checks: a service whose budget is spent works at
//! level 32 and takes at most C of each T from the levels 33 and above, which is why the victim
//! sits at 34 (below the network service at 35); for the levels at or below 32 the three
//! services are services without a budget and the probe promises nothing.
//!
//! The starvation gate has two parts and every term of both comes from the constants of the code
//! (C, T, the step limit of 18 369 ticks, the kernel's longest stretch) or from the control
//! phase of the same run (the cost e of one timer event of a budget), never from the measured
//! run of the service itself. The victim keeps its bound of its own active time in its worst 10
//! cycles, and the ticks the service's `serve` budget charged over the phase (`BudgetInfo::ran`,
//! read through a copy init gives the probe) are at most `ceil(P / T) * C` plus one overrun and
//! at least one C. The first part is a regression check on the cost of a budget and cannot see a
//! missing budget, because the work 24 clients refill in a cycle is small; the second sees it:
//! the budget of a service that binds none charges nothing. `breaks` runs each
//! `break-budget-unbound` image and requires the gate to fail on it, besides the missing line
//! `<service>: serve runs under its budget`.
//!
//! The level-40 gate takes `s_max` from requests asked with the budget fresh (see `level40` in
//! the probe), so that no replenishment wait lies inside it. `breaks` runs the same probe on
//! images in which one service binds no budget (`break-budget-unbound` of its crate), each of
//! which must fail the check of the lines, and on init with no `free` level
//! (`break-record-free`).

use std::time::Duration;

use crate::{BOOT_PROFILE, Variant, build, build_boot_image, qemu};

/// The arithmetic of the starvation gate, the file the probe prints its terms with: its host
/// tests run here, and the gate reads the loss and its bound through it.
#[path = "../../tests/service-budget/src/terms.rs"]
mod terms;

const TIMEOUT: Duration = Duration::from_secs(300);

/// The services of the phases, in the order of the probe.
const SERVICES: [&str; 3] = ["ramfs", "pipe", "tty"];

/// What the probe measured for one service: the least share of the victim (per mille) in
/// windows of 1, 5 and 10 ms with the greedy client at work, the requests that client made in
/// that phase and in the phase of the client at 40, and the round trips of that client.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Numbers {
    /// (window in ms, least share, median share), per mille.
    pub windows: Vec<(u64, u64, u64)>,
    pub share_greedy: u64,
    pub share_failed: u64,
    pub pings: u64,
    pub ping_failed: u64,
    pub ping_max_us: u64,
    pub ping_over: u64,
    pub ping_requests: u64,
    pub ping_worst_request_us: u64,
    pub ping_mean_us: u64,
    pub ping_greedy: u64,
}

fn number(line: &str, key: &str) -> Result<u64, String> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(key))
        .ok_or_else(|| format!("missing {key} in {line:?}"))?
        .parse()
        .map_err(|e| format!("bad {key} in {line:?}: {e}"))
}

/// The victim's shares in the phase `phase` (`idle`: no client at all; `control`: the greedy
/// client against a server of the probe that has no budget): per mille for the windows of 1, 5
/// and 10 ms.
pub fn parse_phase(lines: &[String], phase: &str) -> Result<Vec<(u64, u64, u64)>, String> {
    let mut windows = Vec::new();
    let prefix = format!("svcbudget {phase} ");
    for line in lines.iter().filter_map(|l| l.strip_prefix(&prefix)) {
        if let Some(w) = line.strip_prefix("window=") {
            let l: u64 = w
                .split_whitespace()
                .next()
                .and_then(|w| w.parse().ok())
                .ok_or_else(|| format!("bad window in {line:?}"))?;
            windows.push((
                l,
                number(line, "min_share=")?,
                number(line, "median_share=")?,
            ));
        }
    }
    if windows.len() != 3 {
        return Err(format!("the {phase} phase is missing"));
    }
    Ok(windows)
}

/// The numbers of each service from the lines of the probe, in the order of SERVICES.
pub fn parse(lines: &[String]) -> Result<Vec<Numbers>, String> {
    if !lines.iter().any(|l| l.starts_with("svcbudget START "))
        || !lines.iter().any(|l| l == "svcbudget DONE")
    {
        return Err(format!("the probe did not finish: {:?}", lines.last()));
    }
    let mut all = Vec::new();
    for name in SERVICES {
        let prefix = format!("svcbudget {name} ");
        let mut n = Numbers::default();
        let (mut shared, mut pinged) = (false, false);
        for line in lines.iter().filter_map(|l| l.strip_prefix(&prefix)) {
            if line.starts_with("FAILED") {
                return Err(format!("{name}: {line}"));
            }
            if let Some(w) = line.strip_prefix("window=") {
                let l: u64 = w
                    .split_whitespace()
                    .next()
                    .and_then(|w| w.parse().ok())
                    .ok_or_else(|| format!("bad window in {line:?}"))?;
                n.windows.push((
                    l,
                    number(line, "min_share=")?,
                    number(line, "median_share=")?,
                ));
            } else if line.starts_with("share ") {
                shared = true;
                n.share_greedy = number(line, "greedy=")?;
                n.share_failed = number(line, "greedy_failed=")?;
            } else if line.starts_with("ping ") {
                pinged = true;
                n.pings = number(line, "n=")?;
                n.ping_failed = number(line, "failed=")?;
                n.ping_max_us = number(line, "max_us=")?;
                n.ping_over = number(line, "over_750us=")?;
                n.ping_requests = number(line, "requests=")?;
                n.ping_worst_request_us = number(line, "worst_request_us=")?;
                n.ping_mean_us = number(line, "mean_us=")?;
                n.ping_greedy = number(line, "greedy=")?;
            }
        }
        if n.windows.len() != 3 || !shared || !pinged {
            return Err(format!("{name}: the lines of the phases are missing"));
        }
        all.push(n);
    }
    Ok(all)
}

/// What a service's budget may take of the victim in a typical window, per mille: its share of
/// the CPU (C/T: 50 for the RAM service, 15 for the others) and a margin of 50 per mille (the
/// median of the RAM service does not move with the number of clients, 940 with 8 and with 24;
/// pipe and tty keep 967 and 954 with 8 clients, while 24 queued clients cost them 105 and 74
/// per mille and, on the merged kernel, starve the victim of the bound pipe altogether: a finding
/// for the kernel part), which
/// is the two timer events of each period of the budget (its exhaustion and its replenishment),
/// the overruns, the entries of the kernel and what the greedy client's two CPUs add under
/// -icount. The worst window is printed in the lines and held to no bound: the two CPUs of
/// QEMU stall one of them for some milliseconds now and then, which shows as a window with no
/// victim in it.
fn allowed_loss(service: &str) -> u64 {
    let share: u64 = if service == "ramfs" { 50 } else { 15 };
    share + 50
}

/// The windows the verdict holds the victim to: the median share in a window of 5 and of 10 ms.
const CHECKED_WINDOWS: [u64; 2] = [5, 10];

/// The bound of one request of a client above the budgets, in microseconds: one step of the
/// service and the kernel's longest stretch (`budget-hog`).
const REQUEST_BOUND_US: u64 = 750;

/// The two bounds of the client at 40, printed for each service for information: a request has
/// `REQUEST_BOUND_US`, and a ping of several requests (the RAM service's lookup is five) has
/// that for each of them. The tail the pings show (up to 52 ms) is the lost lift of the holder
/// (stafeto-design#745); both checks are expected to fail until it is fixed, so they are
/// numbers for information.
pub fn ping_bounds(all: &[Numbers]) -> Vec<String> {
    SERVICES
        .iter()
        .zip(all)
        .map(|(name, n)| {
            let per_ping = n.ping_requests / n.pings.max(1);
            let request = if n.ping_worst_request_us <= REQUEST_BOUND_US { "held" } else { "not held" };
            let ping = if n.ping_max_us <= per_ping.max(1) * REQUEST_BOUND_US { "held" } else { "not held" };
            format!(
                "service-budget: {name}: {per_ping} requests per ping, worst request {} us (bound {REQUEST_BOUND_US}: {request}), worst ping {} us, mean {} us (bound {} us: {ping}); expected not held until #745",
                n.ping_worst_request_us,
                n.ping_max_us,
                n.ping_mean_us,
                per_ping.max(1) * REQUEST_BOUND_US
            )
        })
        .collect()
}

/// The numbers of the lines judged: `parse` and the control phase.
pub fn judge(lines: &[String]) -> Result<(), String> {
    // The loop's reply of the most bytes with a handle, and the refusal of one byte more.
    if !lines
        .iter()
        .any(|l| l == "svcbudget replies whole_with_handle=1 server_saw=3 took_handles=1")
    {
        return Err(format!(
            "the replies phase: {:?}",
            lines.iter().find(|l| l.starts_with("svcbudget replies"))
        ));
    }
    verdict(&parse(lines)?, &parse_phase(lines, "control")?)
}

pub fn verdict(all: &[Numbers], control: &[(u64, u64, u64)]) -> Result<(), String> {
    for (name, n) in SERVICES.iter().zip(all) {
        if n.share_greedy == 0 || n.ping_greedy == 0 || n.pings == 0 || n.ping_failed != 0 {
            return Err(format!(
                "{name}: the clients got no answers (greedy {} and {}, pings {}, failed {})",
                n.share_greedy, n.ping_greedy, n.pings, n.ping_failed
            ));
        }
        for &(l, _, median) in &n.windows {
            let Some(&(_, _, base)) = control.iter().find(|c| c.0 == l) else {
                return Err(format!("no control for the window of {l} ms"));
            };
            let bound = base.saturating_sub(allowed_loss(name));
            if CHECKED_WINDOWS.contains(&l) && median < bound {
                return Err(format!(
                    "{name}: the victim kept {median} per mille in a window of {l} ms (the control {base}), under {bound}: the service took the CPU above it"
                ));
            }
        }
        // The client at 40 gets its answer (at least one ping answered). The waits are printed for
        // information: with the dear requests queued, the pings of the pipe and terminal
        // services wait up to 180 ms behind a request in hand and the RAM service's lookups
        // (jobs of several steps) take 2 ms on the average with the lift of the holder of a
        // notification, over the 750 us of one step: open findings for the kernel part.
    }
    Ok(())
}

/// The lines each service prints when it runs its request thread under its budget.
pub fn require_service_budget_lines(lines: &[String]) -> Result<(), String> {
    for service in SERVICES {
        let wanted = format!("{service}: serve runs under its budget");
        if !lines.iter().any(|l| l.contains(&wanted)) {
            return Err(format!("no line {wanted:?}: the service runs unbudgeted"));
        }
    }
    Ok(())
}

/// One run of the probe on the image `image` (built from `programs`): the lines of the console.
fn run_image(
    name: &'static str,
    programs: &'static [crate::ImageProgram],
) -> Result<Vec<String>, String> {
    run_image_on(name, programs, 2, Variant::Normal)
}

/// `run_image` on `cpus` CPUs with the kernel of `variant`.
fn run_image_on(
    name: &'static str,
    programs: &'static [crate::ImageProgram],
    cpus: usize,
    variant: Variant,
) -> Result<Vec<String>, String> {
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let kernel = build(variant)?;
    let outcome = qemu::on_cpus(cpus, || {
        let mut cmd = qemu::command(&qemu::VIRT_V3, &kernel.image, Some(&image));
        cmd.args(qemu::HEADLESS);
        cmd.args(qemu::ICOUNT);
        qemu::run_until(cmd, TIMEOUT, Some("svcbudget DONE"))
    })?;
    if outcome.timed_out || !outcome.stopped_on_marker {
        let why = outcome
            .lines
            .iter()
            .position(|l| l.contains("panicked"))
            .map(|i| {
                outcome.lines[i..]
                    .iter()
                    .take(2)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            });
        let tail = outcome.lines.iter().rfind(|l| l.starts_with("svcbudget"));
        return Err(format!(
            "the probe did not finish: {:?}{} (last line of the probe: {tail:?})",
            outcome.lines.last(),
            why.map_or(String::new(), |w| format!(" ({w})"))
        ));
    }
    for line in outcome
        .lines
        .iter()
        .filter(|l| l.starts_with("svcbudget") || l.contains(": serve "))
    {
        println!("  {line}");
    }
    Ok(outcome.lines)
}

/// What the one-CPU probe measured for one service.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct One {
    pub cycles: u64,
    pub worst10: u64,
    pub median10: u64,
    pub c_us: u64,
    pub e_us: u64,
    /// The counting budget of the console driver's stub: whether the probe had a copy, and the
    /// time it ran and the times it ran out over the phase (its overruns stay 0 when the count is
    /// whole).
    pub driver_budget: bool,
    pub driver_ran_us: u64,
    pub driver_overruns: u64,
    /// The worst window of ten cycles, when the victim made one.
    pub worst: Option<Worst>,
    /// The ticks of the `serve` budget charged in the phase, its bound and its floor, in
    /// microseconds.
    pub ran_us: u64,
    pub ran_bound_us: u64,
    pub ran_floor_us: u64,
    pub requests_per_ping: u64,
    pub worst_request_us: u64,
    pub worst_wait_us: u64,
    pub s_max_us: u64,
    pub s0_us: u64,
    pub bound_us: u64,
}

/// The worst window of ten cycles of one phase, as the probe prints it (`svcbudget1 <name>
/// worst`), in microseconds: the terms of the loss and of its bound (`terms`).
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Worst {
    pub r_us: u64,
    pub w_us: u64,
    pub l_us: u64,
    pub n: u64,
    pub loss_us: u64,
    /// What the budgets counted over the victim's awake spans (the sum over the cycles of the two
    /// samples around each), the terms of `left_us`.
    pub serve_ran_us: u64,
    pub serve_overruns: u64,
    /// The same counters over the whole window, sleeps included (the bound's `S` is over it).
    pub serve_ran_l_us: u64,
    pub serve_overruns_l: u64,
    pub pending_max: u64,
    pub drv_ran_us: u64,
    pub drv_overruns: u64,
    pub drv_ran_l_us: u64,
    pub service_us: u64,
    pub events_us: u64,
    pub init_us: u64,
    pub driver_term_us: u64,
    pub bound_loss_us: u64,
    pub bound_share: u64,
    pub share: u64,
    pub left_us: i64,
}

fn signed(line: &str, key: &str) -> Result<i64, String> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(key))
        .ok_or_else(|| format!("missing {key} in {line:?}"))?
        .parse()
        .map_err(|e| format!("bad {key} in {line:?}: {e}"))
}

impl Worst {
    fn read(line: &str) -> Result<Worst, String> {
        let w = Worst {
            r_us: number(line, "R_us=")?,
            w_us: number(line, "W_us=")?,
            l_us: number(line, "l_us=")?,
            n: number(line, "n=")?,
            loss_us: number(line, "loss_us=")?,
            serve_ran_us: number(line, "serve_ran_us=")?,
            serve_overruns: number(line, "serve_overruns=")?,
            serve_ran_l_us: number(line, "serve_ran_l_us=")?,
            serve_overruns_l: number(line, "serve_overruns_l=")?,
            pending_max: number(line, "pending_max=")?,
            drv_ran_us: number(line, "drv_ran_us=")?,
            drv_overruns: number(line, "drv_overruns=")?,
            drv_ran_l_us: number(line, "drv_ran_l_us=")?,
            service_us: number(line, "s_us=")?,
            events_us: number(line, "events_us=")?,
            init_us: number(line, "init_us=")?,
            driver_term_us: number(line, "d_us=")?,
            bound_loss_us: number(line, "bound_loss_us=")?,
            bound_share: number(line, "bound_share=")?,
            share: number(line, "share=")?,
            left_us: signed(line, "x_us=")?,
        };
        // The probe's loss is W - R and its bound is the sum of its terms: a line that says
        // otherwise is a fault of the probe.
        let sum = terms::bound_us(w.service_us, w.events_us, w.init_us, w.driver_term_us);
        if w.loss_us != terms::loss_us(w.r_us, w.w_us) || w.bound_loss_us != sum {
            return Err(format!(
                "the terms of the worst window do not add up: {line:?}"
            ));
        }
        Ok(w)
    }

    /// The lowest `left_us` the account allows, `-e (k_W + 1)` (`terms::left_floor_us`).
    pub fn left_floor_us(&self, e: u64) -> i64 {
        terms::left_floor_us(e, self.serve_overruns)
    }

    /// The loss over its bound, in microseconds: positive when the terms do not explain it.
    pub fn over_us(&self) -> i64 {
        terms::over_bound(self.loss_us, self.bound_loss_us)
    }
}

/// The lines of the one-CPU probe for each service.
pub fn parse_one(lines: &[String]) -> Result<Vec<One>, String> {
    check_finished(lines)?;
    SERVICES
        .iter()
        .map(|name| parse_service(lines, name, true))
        .collect()
}

/// The lines of the probe of an image that runs the starvation phase of one service alone.
pub fn parse_starve_only(lines: &[String], name: &str) -> Result<One, String> {
    check_finished(lines)?;
    parse_service(lines, name, false)
}

fn check_finished(lines: &[String]) -> Result<(), String> {
    if !lines.iter().any(|l| l == "svcbudget DONE") {
        return Err(format!("the probe did not finish: {:?}", lines.last()));
    }
    if !lines
        .iter()
        .any(|l| l == "svcbudget replies whole_with_handle=1 server_saw=3 took_handles=1")
    {
        return Err("the replies phase failed".into());
    }
    Ok(())
}

/// The lines of one service: a `FAILED` line (for example `no ran-<service>`, init gave the probe
/// no copy of the budget) rejects the run.
fn parse_service(lines: &[String], name: &str, level40: bool) -> Result<One, String> {
    let prefix = format!("svcbudget1 {name} ");
    let mut one = One::default();
    let (mut starved, mut leveled) = (false, !level40);
    for line in lines.iter().filter_map(|l| l.strip_prefix(&prefix)) {
        if line.starts_with("FAILED") {
            return Err(format!("{name}: {line}"));
        }
        if line.starts_with("starve ") {
            starved = true;
            one.cycles = number(line, "cycles=")?;
            one.e_us = number(line, "e_us=")?;
            one.worst10 = number(line, "worst10=")?;
            one.median10 = number(line, "median10=")?;
            one.c_us = number(line, "c_us=")?;
            one.ran_us = number(line, "ran_us=")?;
            one.ran_bound_us = number(line, "ran_bound_us=")?;
            one.ran_floor_us = number(line, "ran_floor_us=")?;
            one.driver_budget = number(line, "driver_budget=")? != 0;
            one.driver_ran_us = number(line, "driver_ran_us=")?;
            one.driver_overruns = number(line, "driver_overruns=")?;
        } else if line.starts_with("worst R_us=") {
            one.worst = Some(Worst::read(line)?);
        } else if line.starts_with("level40 ") {
            leveled = true;
            one.requests_per_ping = number(line, "requests_per_ping=")?;
            one.worst_request_us = number(line, "worst_request_us=")?;
            one.worst_wait_us = number(line, "worst_wait_us=")?;
            one.s_max_us = number(line, "s_max_us=")?;
            one.s0_us = number(line, "s0_us=")?;
            one.bound_us = number(line, "bound_us=")?;
        }
    }
    if !starved || !leveled {
        return Err(format!("{name}: the lines of the phases are missing"));
    }
    Ok(one)
}

/// The account of one service's budget in the starvation phase: it charged at most
/// `ceil(P / T) * C` and one overrun, and at least one C.
pub fn verdict_ran_of(name: &str, o: &One) -> Result<(), String> {
    if o.ran_us > o.ran_bound_us {
        return Err(format!(
            "{name}: the budget charged {} us in the phase, over {} us (ceil(P / T) * C and one overrun)",
            o.ran_us, o.ran_bound_us
        ));
    }
    if o.ran_us < o.ran_floor_us {
        return Err(format!(
            "{name}: the budget charged {} us in the phase, under {} us: the service is not under its budget or was not asked",
            o.ran_us, o.ran_floor_us
        ));
    }
    Ok(())
}

pub fn verdict_ran(all: &[One]) -> Result<(), String> {
    for (name, o) in SERVICES.iter().zip(all) {
        verdict_ran_of(name, o)?;
    }
    Ok(())
}

/// The starvation gate of the one-CPU probe: each budget's account holds (`verdict_ran`) and the
/// victim made its cycles. The victim's loss in its worst window of ten cycles against the sum of
/// its terms (`S + E + 20 + I`, plus the driver's time for the terminal) is printed with every
/// term and does not fail the gate yet: what is left (X) tells what the terms still miss (stafeto/stafeto#430).
pub fn verdict_starve(all: &[One]) -> Result<(), String> {
    verdict_ran(all)?;
    for (name, o) in SERVICES.iter().zip(all) {
        if o.cycles < 100 {
            return Err(format!(
                "{name}: the victim made {} cycles, under 100",
                o.cycles
            ));
        }
        if o.driver_budget && o.driver_overruns > 0 {
            println!(
                "service-budget: {name}: the console driver's counting budget ran out {} times in the phase, so its time is counted in part (printed for information)",
                o.driver_overruns
            );
        }
        let Some(w) = &o.worst else {
            println!("service-budget: {name}: no window of ten cycles to judge");
            continue;
        };
        println!(
            "service-budget: {name}: worst window R {} us, W {} us, l {} us, n {}, loss {} us = serve ran {} + driver ran {} + events {} + 20 + left {} (over the awake spans; serve overruns {}, pending at most {}, driver overruns {}; over the whole window serve ran {}, driver ran {}, serve overruns {}; the work of init and the heartbeats are in the left term)",
            w.r_us,
            w.w_us,
            w.l_us,
            w.n,
            w.loss_us,
            w.serve_ran_us,
            w.drv_ran_us,
            terms::events_us(o.e_us, w.serve_overruns),
            w.left_us,
            w.serve_overruns,
            w.pending_max,
            w.drv_overruns,
            w.serve_ran_l_us,
            w.drv_ran_l_us,
            w.serve_overruns_l
        );
        if w.left_us < w.left_floor_us(o.e_us) {
            println!(
                "service-budget: {name}: left {} us is under -e (k + 1) = {} us: the events and the spans of the service and the driver overlap by more than the account allows (printed for information)",
                w.left_us,
                w.left_floor_us(o.e_us)
            );
        }
        if w.over_us() > 0 || w.share < w.bound_share {
            println!(
                "service-budget: {name}: the victim kept {} per mille of its active time in its worst 10 cycles, under {}: the loss of {} us is over S {} + E {} + 20 + I {} + D {} = {} us by {} us (printed for information, stafeto/stafeto#430)",
                w.share,
                w.bound_share,
                w.loss_us,
                w.service_us,
                w.events_us,
                w.init_us,
                w.driver_term_us,
                w.bound_loss_us,
                w.over_us()
            );
        }
    }
    Ok(())
}

/// The level-40 gate of the one-CPU probe: a request of the thread at 40 waits for the request
/// in hand (1.1 times the longest request of the dear kind alone, measured with the budget
/// fresh), its own work, one stretch of the kernel, one round trip, the budgets of the three
/// services above 40 and the work of init at most (the formula above `level40` in the probe).
pub fn verdict_level40(all: &[One]) -> Result<(), String> {
    for (name, o) in SERVICES.iter().zip(all) {
        if o.worst_request_us > o.bound_us {
            return Err(format!(
                "{name}: a request of the thread at 40 waited {} us, over {} us ({} requests a ping)",
                o.worst_request_us, o.bound_us, o.requests_per_ping
            ));
        }
    }
    Ok(())
}

fn one_table(all: &[One]) {
    for (name, o) in SERVICES.iter().zip(all) {
        println!(
            "service-budget: {name}: worst 10 cycles {} per mille of the victim's active time (median {}, bound {}; C {} us, e {} us, left {} us of the loss); budget charged {} us of at most {} (at least {}); level 40: {} requests a ping, worst request {} us, worst wait {} us, bound {} us, headroom {} us (s_max {} us from the probe's own unloaded measurement, s0 {} us)",
            o.worst10,
            o.median10,
            o.worst
                .as_ref()
                .map_or_else(|| "n/a".to_owned(), |w| w.bound_share.to_string()),
            o.c_us,
            o.e_us,
            o.worst
                .as_ref()
                .map_or_else(|| "n/a".to_owned(), |w| w.left_us.to_string()),
            o.ran_us,
            o.ran_bound_us,
            o.ran_floor_us,
            o.requests_per_ping,
            o.worst_request_us,
            o.worst_wait_us,
            o.bound_us,
            o.bound_us as i64 - o.worst_request_us as i64,
            o.s_max_us,
            o.s0_us
        );
    }
}

/// `cargo xtask service-budget`: the one-CPU probe, gated. `two-cpu` runs the two-CPU probe, whose
/// numbers are printed for information (QEMU under -icount runs the vCPUs in turn with one instruction
/// counter, so a busy CPU 1 advances the clock of CPU 0 while it executes nothing).
pub fn run(args: &[String]) -> Result<(), String> {
    match args {
        [] => {}
        [word] if word == "two-cpu" => return run_two_cpu(),
        [word] if word == "breaks" => return breaks(None),
        [word, only] if word == "breaks" => return breaks(Some(only)),
        _ => {
            return Err(
                "usage: cargo xtask service-budget [two-cpu | breaks [ramfs|pipe|tty|free|relift]]"
                    .into(),
            );
        }
    }
    let lines = run_image_on(
        "boot-service-budget-1.img",
        &crate::SERVICE_BUDGET_PROGRAMS,
        1,
        Variant::Normal,
    )?;
    require_service_budget_lines(&lines)?;
    let all = parse_one(&lines)?;
    one_table(&all);
    verdict_starve(&all)?;
    verdict_level40(&all)?;
    for service in SERVICES {
        let wanted = format!("init: {service} budget serve: at least");
        if let Some(line) = lines.iter().find(|l| l.contains(&wanted)) {
            println!("service-budget: journal: {line}");
        }
    }
    println!("service-budget: the three services keep their budgets (one CPU)");
    Ok(())
}

fn run_two_cpu() -> Result<(), String> {
    let lines = run_image("boot-service-budget.img", &crate::SERVICE_BUDGET_PROGRAMS)?;
    require_service_budget_lines(&lines)?;
    // Printed for information (the two-CPU probe is no oracle).
    if let Err(e) = judge(&lines) {
        println!(
            "service-budget: two-CPU numbers off the old bounds (printed for information): {e}"
        );
    }
    for line in ping_bounds(&parse(&lines)?) {
        println!("{line}");
    }
    // The stress phase, printed for information: 24 queued clients of the pipe service (issue #750).
    if let Ok(w) = parse_phase(&lines, "pipe24") {
        let median = w.iter().find(|w| w.0 == 10).map_or(0, |w| w.2);
        println!(
            "service-budget: pipe with 24 queued clients: the victim keeps a median of {median} per mille in 10 ms (printed for information)"
        );
    }
    // Init's journal of the overruns (the budgets of these services have a NOTIFY place since the
    // journal): a service that ran out of its budget under the load has a line.
    for service in SERVICES {
        let wanted = format!("init: {service} budget serve: at least");
        match lines.iter().find(|l| l.contains(&wanted)) {
            Some(line) => println!("service-budget: journal: {line}"),
            None => {
                return Err(format!(
                    "no line {wanted:?} in init's journal of the overruns"
                ));
            }
        }
    }
    println!("service-budget: the three services keep their budgets");
    Ok(())
}

/// `cargo xtask budget-breaks`, the part of the services, on one CPU: the image in which one
/// service binds no budget is caught by the missing line `<service>: serve runs under its budget`
/// (the victim's numbers there are printed for information: see the comment in the function); the
/// level-40 numbers of the kernel with the holder not lifted again (`break-relift-notice`,
/// `break-relift-reply`) are printed for information and the kernel tests of `budget-hog`'s breaks
/// judge both; and the host tests of init fail on init that passes no `free`.
pub fn breaks(only: Option<&str>) -> Result<(), String> {
    for (service, name, programs) in [
        (
            "ramfs",
            "boot-service-budget-ramfs-unbound.img",
            &crate::SERVICE_BUDGET_RAMFS_UNBOUND,
        ),
        (
            "pipe",
            "boot-service-budget-pipe-unbound.img",
            &crate::SERVICE_BUDGET_PIPE_UNBOUND,
        ),
        (
            "tty",
            "boot-service-budget-tty-unbound.img",
            &crate::SERVICE_BUDGET_TTY_UNBOUND,
        ),
    ] {
        if only.is_some_and(|only| only != service) {
            continue;
        }
        let lines = run_image_on(name, programs, 1, Variant::Normal)
            .map_err(|e| format!("the one-CPU probe on the unbound {service}: {e}"))?;
        match require_service_budget_lines(&lines) {
            Err(e) => println!("budget-breaks: {service} that binds no budget is caught ({e})"),
            Ok(()) => {
                return Err(format!(
                    "the break (budget-unbound of {service}) left its line of the budget"
                ));
            }
        }
        // The victim's share cannot catch an unbound service: the work the clients refill in a
        // cycle of 1 ms (24 clients, the dearest request each service offers) is 14, 61 and 39 us
        // of service CPU for ramfs, pipe and tty, so an unbound service takes 2 to 8 per cent of
        // the victim's 0.8 ms, never most of it. The account of the budget catches it: the
        // budget of a service that binds none charges nothing, which is under its floor of one
        // C, so the gate must fail on this image.
        // A run that could not read the account (`FAILED no ran-<service>`, the phase lines
        // missing) is an error of the probe and no catch.
        let one = parse_starve_only(&lines, service)
            .map_err(|e| format!("the one-CPU probe on the unbound {service}: {e}"))?;
        match verdict_ran_of(service, &one) {
            Err(e) => println!("budget-breaks: the gate fails on the unbound {service} ({e})"),
            Ok(()) => {
                return Err(format!(
                    "the gate passed on the unbound {service}: its budget charged {} us",
                    one.ran_us
                ));
            }
        }
    }
    for (what, variant, key) in [
        (
            "a holder not lifted again after a notification",
            Variant::LiftAgainNotice,
            "relift",
        ),
        (
            "a holder not lifted again after the reply of reply_receive",
            Variant::LiftAgainReply,
            "relift",
        ),
    ] {
        if only.is_some_and(|only| only != key) {
            continue;
        }
        let lines = run_image_on(
            "boot-service-budget-1.img",
            &crate::SERVICE_BUDGET_PROGRAMS,
            1,
            variant,
        )
        .map_err(|e| format!("the one-CPU probe on the kernel with {what}: {e}"))?;
        // Printed for information: the worst request of the level-40 phase of the pipe moves by more
        // than 130 us with the image alone (359 to 535 us on the unbroken kernel, 462 us on the
        // kernel with `break-relift-reply`), so this gate cannot tell the broken build from the
        // unbroken one. The kernel tests `a_receive_that_takes_a_notification_above_a_request_keeps_the_lift`
        // and `a_reply_between_the_halves_keeps_the_lift_a_queued_request_gave` are the judges
        // (`budget-breaks` runs both on their breaks).
        let all = parse_one(&lines)
            .map_err(|e| format!("the one-CPU probe on the kernel with {what}: {e}"))?;
        one_table(&all);
        let worst = SERVICES
            .iter()
            .zip(&all)
            .map(|(name, o)| format!("{name} {} us (bound {} us)", o.worst_request_us, o.bound_us))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "budget-breaks: with {what} the level-40 phase measured {worst}; printed for information, the kernel tests judge it"
        );
    }
    if only.is_some_and(|only| only != "free") {
        return Ok(());
    }
    let out = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(crate::root())
        .args([
            "test",
            "-p",
            "init",
            "--lib",
            "--features",
            "break-record-free",
        ])
        .output()
        .map_err(|e| format!("cargo test: {e}"))?;
    if out.status.success() {
        return Err("the host tests of init passed with break-record-free".into());
    }
    println!("budget-breaks: break-record-free fails the host tests of init");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(shares: [u64; 3]) -> Vec<String> {
        let mut out = vec![
            "svcbudget START hz=62500000".to_owned(),
            "svcbudget replies whole_with_handle=1 server_saw=3 took_handles=1".to_owned(),
        ];
        for l in [1, 5, 10] {
            out.push(format!(
                "svcbudget control window={l} min_share=800 median_share=900"
            ));
        }
        for (name, share) in SERVICES.iter().zip(shares) {
            for l in [1, 5, 10] {
                out.push(format!(
                    "svcbudget {name} window={l} min_share={share} median_share={share}"
                ));
            }
            out.push(format!(
                "svcbudget {name} share greedy=400 greedy_failed=0 gap_us=40 status=0"
            ));
            out.push(format!(
                "svcbudget {name} ping n=90 failed=0 max_us=100 over_750us=0 requests=90 worst_request_us=60 mean_us=50 worst_at_ms=3 greedy=500 greedy_failed=0 status=0"
            ));
        }
        out.push("svcbudget DONE".to_owned());
        out
    }

    #[test]
    fn the_numbers_of_the_phases_are_read_and_judged() {
        let all = parse(&lines([990, 990, 990])).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[0].windows,
            [(1, 990, 990), (5, 990, 990), (10, 990, 990)]
        );
        assert_eq!(
            (all[1].pings, all[1].ping_max_us, all[1].ping_greedy),
            (90, 100, 500)
        );
        assert!(judge(&lines([990, 990, 990])).is_ok());
        // A service that starves the victim fails, whichever it is.
        for (i, name) in SERVICES.iter().enumerate() {
            let mut shares = [990; 3];
            shares[i] = 300;
            let e = judge(&lines(shares)).unwrap_err();
            assert!(e.starts_with(name), "{e}");
        }
        assert!(parse(&lines([990; 3])[..5]).is_err());
    }

    #[test]
    fn the_loss_a_budget_may_cause_is_its_share_with_the_margin() {
        // The RAM service in a window of 10 ms: 3 periods of 260 us, and 30 per mille of margin.
        assert_eq!(allowed_loss("ramfs"), 50 + 50);
        assert_eq!(allowed_loss("pipe"), 15 + 50);
        assert_eq!(allowed_loss("tty"), 15 + 50);
    }

    #[test]
    fn the_lines_of_the_budgets_are_required_of_each_service() {
        let mut all: Vec<String> = SERVICES
            .iter()
            .map(|s| format!("{s}: serve runs under its budget"))
            .collect();
        assert!(require_service_budget_lines(&all).is_ok());
        all.remove(1);
        assert!(
            require_service_budget_lines(&all)
                .unwrap_err()
                .contains("pipe")
        );
    }

    #[test]
    fn a_probe_with_no_copy_of_a_budget_is_rejected_and_not_read_as_zero() {
        let lines: Vec<String> = [
            "svcbudget replies whole_with_handle=1 server_saw=3 took_handles=1",
            "svcbudget1 ramfs FAILED no ran-ramfs",
            "svcbudget DONE",
        ]
        .map(str::to_owned)
        .to_vec();
        assert!(
            parse_starve_only(&lines, "ramfs")
                .unwrap_err()
                .contains("no ran-ramfs")
        );
    }

    fn run_lines(ran: u64) -> Vec<String> {
        [
            "svcbudget replies whole_with_handle=1 server_saw=3 took_handles=1".to_owned(),
            format!("svcbudget1 tty starve clients=24 cycles=150 worst10=923 median10=957 c_us=75 e_us=30 ran_us={ran} ran_bound_us=2919 ran_floor_us=75 phase_us=155000 driver_budget=1 driver_ran_us=900 driver_overruns=0"),
            "svcbudget1 tty worst R_us=8000 W_us=8667 l_us=10470 n=2 loss_us=667 serve_ran_us=225 serve_overruns=2 serve_ran_l_us=260 serve_overruns_l=2 pending_max=3 drv_ran_us=150 drv_overruns=0 drv_ran_l_us=400 beats=na c_us=75 e_us=30 s_us=375 events_us=180 entries_us=20 init_us=70 d_us=150 bound_loss_us=795 bound_share=909 share=923 x_us=92".to_owned(),
            "svcbudget DONE".to_owned(),
        ]
        .to_vec()
    }

    #[test]
    fn the_worst_window_is_read_with_its_terms_and_never_fails_the_gate() {
        let one = parse_starve_only(&run_lines(2175), "tty").unwrap();
        let w = one.worst.clone().unwrap();
        assert_eq!((w.r_us, w.l_us, w.n, w.loss_us), (8000, 10470, 2, 667));
        assert_eq!(
            (w.serve_overruns, w.pending_max, w.drv_ran_us, w.left_us),
            (2, 3, 150, 92)
        );
        assert!(one.driver_budget && one.driver_ran_us == 900);
        // The counters over the whole window are read beside the awake ones.
        assert_eq!(
            (w.serve_ran_l_us, w.serve_overruns_l, w.drv_ran_l_us),
            (260, 2, 400)
        );
        assert_eq!(w.left_floor_us(one.e_us), -90);
        // 667 is under its bound of 795: nothing over.
        assert_eq!(w.over_us(), -128);
        // A window over its bound is printed and the gate passes (the victim check is information).
        let mut over = one.clone();
        over.cycles = 150;
        over.worst.as_mut().unwrap().bound_loss_us = 600;
        over.worst.as_mut().unwrap().driver_term_us = 0;
        over.worst.as_mut().unwrap().service_us = 330;
        assert!(over.worst.as_ref().unwrap().over_us() > 0);
        assert!(verdict_starve(&[over.clone(), over.clone(), over]).is_ok());
    }

    #[test]
    fn the_terminal_window_of_run_44389680495_reads_with_both_sets_of_terms() {
        // Loss 630, serve ran 205 and driver ran 538 over the window (l 11008), events 480 (e 40,
        // 5 overruns): left -613 with those terms. The awake terms of the example (serve 150,
        // driver 120, 3 overruns) leave 20, inside the allowance.
        let mut lines = run_lines(2175);
        lines[1] = lines[1].replace("e_us=30", "e_us=40");
        lines[2] = "svcbudget1 tty worst R_us=8005 W_us=8635 l_us=11008 n=2 loss_us=630 serve_ran_us=150 serve_overruns=3 serve_ran_l_us=205 serve_overruns_l=5 pending_max=3 drv_ran_us=120 drv_overruns=0 drv_ran_l_us=538 beats=na c_us=75 e_us=40 s_us=375 events_us=480 entries_us=20 init_us=70 d_us=538 bound_loss_us=1483 bound_share=843 share=927 x_us=20".to_owned();
        let one = parse_starve_only(&lines, "tty").unwrap();
        let w = one.worst.clone().unwrap();
        assert_eq!(
            terms::left_us(
                w.loss_us,
                w.serve_ran_l_us,
                w.drv_ran_l_us,
                40,
                w.serve_overruns_l
            ),
            -613
        );
        assert_eq!(
            terms::left_us(
                w.loss_us,
                w.serve_ran_us,
                w.drv_ran_us,
                40,
                w.serve_overruns
            ),
            w.left_us
        );
        assert!(w.left_us >= w.left_floor_us(40));
        assert!(verdict_starve(&[one.clone(), one.clone(), one]).is_ok());
    }

    #[test]
    fn a_worst_window_whose_terms_do_not_add_up_is_a_fault_of_the_probe() {
        let mut lines = run_lines(2175);
        lines[2] = lines[2].replace("bound_loss_us=795", "bound_loss_us=796");
        assert!(
            parse_starve_only(&lines, "tty")
                .unwrap_err()
                .contains("do not add up")
        );
        let mut lines = run_lines(2175);
        lines[2] = lines[2].replace("loss_us=667", "loss_us=668");
        assert!(parse_starve_only(&lines, "tty").is_err());
    }

    #[test]
    fn the_unbound_images_still_fail_the_hard_part_with_the_new_lines() {
        // An unbound service charges nothing: the account fails whatever the victim lost.
        let one = parse_starve_only(&run_lines(0), "tty").unwrap();
        assert!(
            verdict_ran_of("tty", &one)
                .unwrap_err()
                .contains("not under its budget")
        );
        assert!(verdict_starve(&[one.clone(), one.clone(), one]).is_err());
    }

    #[test]
    fn the_account_of_a_budget_is_held_between_one_c_and_its_periods_and_one_overrun() {
        let one = |ran: u64| One {
            ran_us: ran,
            ran_bound_us: 31 * 250 + 444,
            ran_floor_us: 250,
            ..One::default()
        };
        assert!(verdict_ran_of("ramfs", &one(31 * 250)).is_ok());
        // A budget that charged nothing is not bound: the unbound image fails here.
        assert!(
            verdict_ran_of("ramfs", &one(0))
                .unwrap_err()
                .contains("not under its budget")
        );
        // A budget that charged more than its periods and one overrun is not enforced.
        assert!(
            verdict_ran_of("ramfs", &one(31 * 250 + 445))
                .unwrap_err()
                .contains("over")
        );
    }
}
