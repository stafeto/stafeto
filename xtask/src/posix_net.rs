// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the descriptors and sockets of a process that serves many
//! (`cargo xtask posix-net`, stage P4a of subproject 6): the shell image
//! with the network service on QEMU's user network, where xtask runs
//! `posix-net ADDRESS` (tests/posix-so/dyn/posix-net.c) over the serial port:
//! the limit of 1 024 descriptors, 1 000 sockets, a fork and an exec with
//! many descriptors, the buffers of the sockets by their place in the
//! service, and (stage P4a-2) epoll, poll and select over more than 64
//! descriptors and 1 000 sockets in one set. The program prints a line for
//! each check and xtask compares them with its own list. The run needs no
//! `-icount`.
//!
//! `cargo xtask posix-net steps` runs the same under -icount with the service
//! counting its steps, and judges every step against 0.9 of term B and the
//! steps of CLONE and CLONE_MORE against 0.8: the cost of a fork of a process
//! with hundreds of sockets.

use std::time::{Duration, Instant};

use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net, net_curl, net_probe, qemu, relibc, symbolize,
};

/// The checks of `posix-net` for stages P4a-1, P4a-2, P4a-3 and P4b-1, in the order the
/// program runs them.
pub const CHECKS: [&str; 65] = [
    "limits",
    "nofile-low",
    "rcvbuf-tiers",
    "fds-1000",
    "fork-900",
    "clofork-many",
    "exec-64",
    "spawn-high",
    "sockets-1000",
    "ephemeral-block",
    "bind-reuse-accepted",
    "epoll-basic",
    "epoll-200",
    "epoll-lt",
    "epoll-et",
    "epoll-et-pipe",
    "epoll-oneshot",
    "epoll-close",
    "epoll-fork",
    "epoll-exec",
    "epoll-errors",
    "epoll-rdhup",
    "epoll-err-rst",
    "epoll-signal",
    "epoll-stale-list",
    "epoll-et-inout",
    "epoll-listener",
    "epoll-threads",
    "poll-1000",
    "select-high",
    "fionread",
    "epoll-1000",
    "listen-again",
    "syn-full",
    "timewait-syn",
    "reuseport-4",
    "reuseport-handoff",
    "reuseport-uid",
    "linger-0",
    "linger-wait",
    "rcvtimeo",
    "sndtimeo",
    "accept-clofork",
    "scm-net",
    "scm-five",
    "scm-mixed",
    "scm-wait",
    "scm-dead-receiver",
    "scm-close-socket",
    "scm-ctrunc",
    "scm-retry",
    "scm-root",
    "scm-depart",
    "epoll-exclusive",
    "buffer-send",
    "buffer-recv",
    "buffer-nonblock",
    "buffer-writev",
    "buffer-threads",
    "buffer-fork",
    "buffer-exec",
    "buffer-signal",
    "fsetown",
    "epoll-rdhup-unix",
    "fast-claim-off",
    "wait-churn",
];

/// The image of the run with the counted steps of the network service and
/// the pipe service (the passes of SCM_RIGHTS wait there).
const STEPS_IMAGE: &str = "boot-posix-net-steps.img";

/// The tag under which the pipe service prints its steps.
const PIPE_TAG: &str = "4";

/// The programs of that image: the shell's image with `netd` and `pipe` that
/// print their longest steps.
pub fn steps_programs() -> &'static [crate::ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<crate::ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = net_curl::steps_programs().to_vec();
        for program in &mut programs {
            if program.0 == "pipe" {
                program.3 = &["steps"];
            }
        }
        programs
    })
}

/// How long the checks may take in all (the ci group allows 120 s for the
/// boot and the run).
const CHECKS_WITHIN: Duration = Duration::from_secs(100);
/// Under -icount the guest runs slower than the host's clock.
const CHECKS_WITHIN_STEPS: Duration = Duration::from_secs(500);

/// What a line says after `posix-net: `; the first line may follow the
/// prompt on the same line.
fn text_of(line: &str) -> Option<&str> {
    line.split_once("posix-net: ").map(|(_, text)| text)
}

/// The time the check `name` printed, in milliseconds.
fn took_ms(lines: &[String], name: &str) -> Option<u64> {
    lines.iter().find_map(|l| {
        let rest = text_of(l)?.strip_prefix(name)?.strip_prefix(" took ")?;
        rest.strip_suffix(" ms")?.parse().ok()
    })
}

/// `posix-net` for all its checks: a line for each, then the count.
///
/// `POSIX_NET_ONLY=NAME` runs the one check, for finding the cause of a failure.
fn checks(
    run: &mut qemu::Run,
    address: &str,
    within: Duration,
    only: Option<String>,
) -> Result<(), String> {
    let wanted: Vec<&str> = CHECKS
        .iter()
        .copied()
        .filter(|name| only.as_deref().is_none_or(|only| only == *name))
        .collect();
    match &only {
        Some(name) => run.send(&format!("posix-net {address} {name}"))?,
        None => run.send(&format!("posix-net {address}"))?,
    }
    let mut seen = 0;
    let end = Instant::now() + within;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        let line = run.expect_line("a line of posix-net", |l| text_of(l).is_some(), left)?;
        let text = text_of(&line).unwrap_or_default();
        if text.contains("failed") {
            return Err(format!("posix-net: {text}"));
        }
        if text.contains(" took ") || text.contains(" note: ") {
            continue;
        }
        if let Some(count) = text.strip_suffix(" checks ok") {
            if count != wanted.len().to_string() || seen != wanted.len() {
                return Err(format!(
                    "posix-net ran {count} checks, {seen} lines said ok, xtask knows {}",
                    wanted.len()
                ));
            }
            return Ok(());
        }
        let name = text
            .strip_suffix(" ok")
            .ok_or_else(|| format!("an unknown line of posix-net: {line:?}"))?;
        if wanted.get(seen) != Some(&name) {
            return Err(format!(
                "check {} is {name}, wanted {:?}",
                seen + 1,
                wanted.get(seen)
            ));
        }
        seen += 1;
    }
}

/// `cargo xtask posix-net [steps] [MACHINE]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let (steps, rest) = match args.first().map(String::as_str) {
        Some("steps") => (true, &args[1..]),
        _ => (false, args),
    };
    let machine = match rest {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask posix-net [steps] [tcg|hvf]".to_owned()),
    };
    probe(machine, steps)
}

pub fn probe(machine: &'static qemu::Machine, steps: bool) -> Result<(), String> {
    probe_only(machine, steps, std::env::var("POSIX_NET_ONLY").ok())
}

/// The check `wait-churn` on two CPUs, where the answers to a wait come late
/// from the other CPU (stafeto-design#569).
pub fn wait_churn_smp() -> Result<(), String> {
    qemu::on_cpus(2, || {
        probe_only(&qemu::VIRT, false, Some("wait-churn".to_owned()))
    })
}

fn probe_only(
    machine: &'static qemu::Machine,
    steps: bool,
    only: Option<String>,
) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let (name, programs) = if steps {
        (STEPS_IMAGE, steps_programs())
    } else {
        (net::IMAGE, net::programs())
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    if steps {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        let lease = run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        let address = net_curl::lease_address(&lease).ok_or(format!("the lease line {lease:?}"))?;
        run.expect("# ", DIALOG_STEP)?;
        checks(
            &mut run,
            &address,
            if steps {
                CHECKS_WITHIN_STEPS
            } else {
                CHECKS_WITHIN
            },
            only,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
    }) {
        return Err("the network image faulted".into());
    }
    net_probe::placing_fault(&output.lines)?;
    if steps {
        let pipe = net_probe::longest_over_starts_of(&output.lines, PIPE_TAG);
        if let Some(row) = pipe.iter().find(|r| r.1 > net_probe::STEP_MAX) {
            return Err(format!(
                "the pipe service: a step past 0.9 of term B ({}): {row:?}",
                net_probe::STEP_MAX
            ));
        }
        let worst_pipe = pipe.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "posix-net steps: the longest step of the pipe service is kind {} with {} ticks and detail {}; every kind: {pipe:?}",
            worst_pipe.0, worst_pipe.1, worst_pipe.2
        );
        let rows = steps_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "posix-net steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            net_probe::STEP_MAX
        );
    }
    let took = |name: &str| {
        took_ms(&output.lines, name).map_or("no time".to_owned(), |ms| format!("{ms} ms"))
    };
    println!(
        "posix-net passed in {:.0} s on {}: {} checks, a fork with 900 descriptors took {}, a poll of 1000 {}, 1000 events of epoll {}",
        started.elapsed().as_secs_f64(),
        machine.name,
        CHECKS.len(),
        took("fork-900"),
        took("poll-1000"),
        took("epoll-1000")
    );
    Ok(())
}

/// The longest step of each kind in the lines of a run under -icount, judged
/// against the bound; CLONE and CLONE_MORE against the portion bound.
fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = net_probe::longest_over_starts(lines);
    if !rows.iter().any(|r| r.0 == 19) {
        return Err(format!("no step of CLONE: {rows:?}"));
    }
    if !rows.iter().any(|r| r.0 == 20) {
        return Err(format!("no step of CLONE_MORE: {rows:?}"));
    }
    if let Some(row) = rows.iter().find(|r| r.1 > net_probe::STEP_MAX) {
        return Err(format!(
            "the network service: a step past 0.9 of term B ({}): {row:?}",
            net_probe::STEP_MAX
        ));
    }
    if let Some(row) = rows
        .iter()
        .find(|r| (r.0 == 19 || r.0 == 20) && r.1 > net_probe::PORTION_MAX)
    {
        return Err(format!(
            "the network service: CLONE or CLONE_MORE past 0.8 of term B ({}): {row:?}",
            net_probe::PORTION_MAX
        ));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checks xtask expects are those the program runs, in its order.
    #[test]
    fn the_checks_are_those_of_the_program() {
        let source =
            std::fs::read_to_string(crate::root().join("tests/posix-so/dyn/posix-net.c")).unwrap();
        let table = source.split("CHECKS[] = {").nth(1).unwrap();
        let table = table.split("};").next().unwrap();
        let names: Vec<&str> = table
            .lines()
            .filter_map(|l| l.trim().strip_prefix("{ \""))
            .filter_map(|l| l.split('"').next())
            .collect();
        assert_eq!(names, CHECKS);
    }

    #[test]
    fn the_lines_of_the_program_are_read() {
        assert_eq!(text_of("posix-net: limits ok"), Some("limits ok"));
        assert_eq!(text_of("/ # posix-net: limits ok"), Some("limits ok"));
        assert_eq!(text_of("net-sock: limits ok"), None);
        let lines = vec!["posix-net: fork-900 took 37 ms".to_owned()];
        assert_eq!(took_ms(&lines, "fork-900"), Some(37));
        assert_eq!(took_ms(&lines, "epoll-1000"), None);
        assert_eq!(took_ms(&[], "fork-900"), None);
    }

    #[test]
    fn a_step_past_the_bound_or_a_clone_past_its_portion_fails() {
        let line =
            |kind: u32, ticks: u32| format!("service step: 14 kind {kind} {ticks} ticks detail 0");
        let ok = vec![line(19, 8_000), line(20, 8_600), line(65, 10_000)];
        assert!(steps_verdict(&ok).is_ok());
        let long = vec![line(19, 8_000), line(20, 17_000), line(65, 10_000)];
        assert!(steps_verdict(&long).unwrap_err().contains("past 0.8"));
        let slow = vec![line(19, 8_000), line(20, 8_000), line(65, 19_000)];
        assert!(steps_verdict(&slow).unwrap_err().contains("past 0.9"));
        let none = vec![line(65, 10_000)];
        assert!(
            steps_verdict(&none)
                .unwrap_err()
                .contains("no step of CLONE")
        );
    }
}
