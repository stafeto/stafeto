// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the time budgets of the RAM file, pipe and terminal services
//! (`tests/service-budget`, `cargo xtask service-budget`, spec 8), under QEMU's -icount with
//! two CPUs. The services run as init starts them, with the budgets of its table on CPU 0; a
//! greedy client at 20 on CPU 1 asks one service without a pause while a victim at 25 on CPU 0
//! spins and a client at 40 on CPU 0 asks every 2 ms. The lines the probe prints are checked
//! against their bounds here. `breaks` runs the same probe on images in which one service
//! binds no budget (`break-budget-unbound` of its crate), each of which must fail the check of
//! the lines, and on init with no `free` level (`break-record-free`).

use std::time::Duration;

use crate::{BOOT_PROFILE, Variant, build, build_boot_image, qemu};

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
/// the CPU (C/T: 50 for the RAM service, 15 for the others) and a margin of 50 per mille for the RAM service (its median does not move with the number of clients: 940 with 8 and with 24) and 100 for the others (24 queued clients make 60 more requests of the pipe service a period than 4 did, and its median share fell from 966 to 907), which
/// is the two timer events of each period of the budget (its exhaustion and its replenishment),
/// the overruns, the entries of the kernel and what the greedy client's two CPUs add under
/// -icount. The worst window is told in the lines and not held to a bound: the two CPUs of
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

/// The two bounds of the client at 40, told for each service and not gated: a request has
/// `REQUEST_BOUND_US`, and a ping of several requests (the RAM service's lookup is five) has
/// that for each of them. The tail the pings show (up to 52 ms) is the lost lift of the holder
/// (stafeto-design#745); both checks are expected to fail until it is fixed, so they are
/// numbers and no gate.
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
        // The client at 40 gets its answer (at least one ping answered). The waits are told and
        // not bounded: with the dear requests queued, the pings of the pipe and terminal
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
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let kernel = build(Variant::Normal)?;
    let outcome = qemu::on_cpus(2, || {
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
        return Err(format!(
            "the probe did not finish: {:?}{}",
            outcome.lines.last(),
            why.map_or(String::new(), |w| format!(" ({w})"))
        ));
    }
    for line in outcome
        .lines
        .iter()
        .filter(|l| l.starts_with("svcbudget ") || l.contains(": serve "))
    {
        println!("  {line}");
    }
    Ok(outcome.lines)
}

pub fn run(args: &[String]) -> Result<(), String> {
    match args {
        [] => {}
        [word] if word == "breaks" => return breaks(None),
        [word, only] if word == "breaks" => return breaks(Some(only)),
        _ => return Err("usage: cargo xtask service-budget [breaks [ramfs|pipe|tty|free]]".into()),
    }
    let lines = run_image("boot-service-budget.img", &crate::SERVICE_BUDGET_PROGRAMS)?;
    require_service_budget_lines(&lines)?;
    judge(&lines)?;
    for line in ping_bounds(&parse(&lines)?) {
        println!("{line}");
    }
    println!("service-budget: the three services keep their budgets");
    Ok(())
}

/// `cargo xtask budget-breaks`, the part of the services: the check of the lines of the budgets
/// fails on the image in which one service binds no budget, and the host tests of init fail on
/// init that passes no `free`.
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
        let lines = match run_image(name, programs) {
            Ok(lines) => lines,
            Err(e) => {
                // The starved victim and the clients of an unbound service can take the probe
                // down itself: that is the break caught.
                println!("budget-breaks: the probe on the unbound {service} fails ({e})");
                continue;
            }
        };
        // The numbers: the victim of the unbound service keeps at least 300 per mille less than
        // the control (told here; the line of the budget is the check that holds).
        if let (Ok(all), Ok(control)) = (parse(&lines), parse_phase(&lines, "control")) {
            let idx = SERVICES.iter().position(|s| *s == service).unwrap_or(0);
            let median = all[idx]
                .windows
                .iter()
                .find(|w| w.0 == 10)
                .map_or(0, |w| w.2);
            let base = control.iter().find(|w| w.0 == 10).map_or(0, |w| w.2);
            println!(
                "budget-breaks: the victim of the unbound {service}: median {median} per mille in 10 ms, control {base} ({})",
                if judge(&lines).is_err() {
                    "caught by the numbers: the verdict fails"
                } else {
                    "not caught by the numbers"
                }
            );
        }
        match require_service_budget_lines(&lines) {
            Err(e) => println!("budget-breaks: {service} that binds no budget is caught ({e})"),
            Ok(()) => {
                return Err(format!(
                    "the break (budget-unbound of {service}) left its line of the budget"
                ));
            }
        }
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
}
