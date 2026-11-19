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
pub const CHECKS: [&str; 69] = [
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
    "reuseport-churn",
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
    "home-fork",
    "reap-queue",
];

/// The check of the stack instances (`cargo xtask posix-net instances`): one worker on each CPU
/// of the process makes sockets, connects to the next worker's listener on the loopback and
/// answers it, and each says the instance that holds its session (the one on its CPU) and how many
/// of its calls came from another CPU (none).
pub const SOLO: &str = "instances";

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
    // The check `instances` runs alone, in a process that has made no socket (it is no member
    // of the list of the full run).
    let wanted: Vec<&str> = if only.as_deref() == Some(SOLO) {
        vec![SOLO]
    } else {
        CHECKS
            .iter()
            .copied()
            .filter(|name| only.as_deref().is_none_or(|only| only == *name))
            .collect()
    };
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
    if args.first().map(String::as_str) == Some(SOLO) {
        return instances_smp();
    }
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
///
/// Interim measure for stafeto#503: on two CPUs the terminal service sometimes sends no sign of
/// life after `tty: ready` and init's watchdog ends it. That failure, and no other, gets one more
/// run (`FLICKER_503_RETRIES`); the lines of the first run are printed whole and saved, and ci
/// reports the retry (`flicker_503_notes`). Delete the retry with the fix of #503.
pub fn wait_churn_smp() -> Result<(), String> {
    let run = || {
        qemu::on_cpus(2, || {
            probe_run(&qemu::VIRT, false, Some("wait-churn".to_owned()))
        })
    };
    retrying(run, note_flicker_503).map_err(|failed| failed.error)
}

/// `run`, and once more after a failure that qualifies (`silent_service`), `note` told of the
/// first run's lines; the second result stands, whatever it is.
fn retrying(
    mut run: impl FnMut() -> Result<(), Failed>,
    mut note: impl FnMut(&[String]),
) -> Result<(), Failed> {
    let mut result = run();
    for _ in 0..FLICKER_503_RETRIES {
        let Err(failed) = &result else { break };
        if !silent_service(&failed.lines) {
            break;
        }
        note(&failed.lines);
        result = run();
    }
    result
}

/// How many more runs the step `posix-net wait-churn smp 2` gets after a silent service
/// (stafeto#503, to be deleted with the fix).
const FLICKER_503_RETRIES: usize = 1;

/// Whether the lines are those of a run in which init's watchdog ended a service: init's line
/// `went silent` and its lines `silent service` (init::serve::describe_silence).
fn silent_service(lines: &[String]) -> bool {
    lines
        .iter()
        .any(|l| l.contains("init: ") && l.contains(" went silent, "))
        && lines
            .iter()
            .any(|l| l.contains("init: ") && l.contains("silent service at"))
}

/// The retries of stafeto#503 this run made: the line each leaves for the summary of ci.
static FLICKER_503: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// The note of a retry: the first run's lines go to the console whole and to
/// `target/measure/flicker-503.txt`.
fn note_flicker_503(lines: &[String]) {
    println!(
        "== flicker stafeto#503: a silent service in the first run of posix-net wait-churn smp 2; its lines follow"
    );
    for line in lines {
        println!("{line}");
    }
    println!("== flicker stafeto#503: end of the first run's lines; running the step once more");
    let dir = crate::target_dir().join("measure");
    let saved = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::write(dir.join("flicker-503.txt"), lines.join("\n") + "\n"));
    if let Err(e) = saved {
        println!("flicker stafeto#503: the lines are not saved: {e}");
    }
    FLICKER_503
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(FLICKER_503_NOTE.to_owned());
}

const FLICKER_503_NOTE: &str =
    "flicker stafeto#503: posix-net wait-churn smp 2 was retried after a silent service";

/// The lines of the summary of ci for the retries made (empty in a run that needed none).
pub fn flicker_503_notes() -> Vec<String> {
    FLICKER_503
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The check `instances` on two CPUs: the stack of the service has an instance on each, and one
/// worker stands on each.
pub fn instances_smp() -> Result<(), String> {
    qemu::on_cpus(2, || probe_only(&qemu::VIRT, false, Some(SOLO.to_owned())))
}

fn probe_only(
    machine: &'static qemu::Machine,
    steps: bool,
    only: Option<String>,
) -> Result<(), String> {
    probe_run(machine, steps, only).map_err(|failed| failed.error)
}

/// A run that failed: the error and the lines of its console (empty when the run did not start).
struct Failed {
    error: String,
    lines: Vec<String>,
}

impl From<String> for Failed {
    fn from(error: String) -> Failed {
        Failed {
            error,
            lines: Vec::new(),
        }
    }
}

impl From<&str> for Failed {
    fn from(error: &str) -> Failed {
        Failed::from(error.to_owned())
    }
}

fn probe_run(
    machine: &'static qemu::Machine,
    steps: bool,
    only: Option<String>,
) -> Result<(), Failed> {
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
        let only = only.clone();
        let lease = run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        let address = net_curl::lease_address(&lease).ok_or(format!("the lease line {lease:?}"))?;
        run.expect("# ", DIALOG_STEP)?;
        net_probe::require_budget_lines(run.lines())?;
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
    if let Err(error) = talked {
        return Err(Failed {
            error,
            lines: output.lines,
        });
    }
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
        let pipe = net_probe::longest_over_starts_of(&output.lines, PIPE_TAG)?;
        if let Some(row) = pipe.iter().find(|r| r.1 > net_probe::STEP_MAX) {
            return Err(format!(
                "the pipe service: a step past 0.9 of term B ({}): {row:?}",
                net_probe::STEP_MAX
            )
            .into());
        }
        let worst_pipe = pipe.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "posix-net steps: the longest step of the pipe service is kind {} with {} ticks and detail {}; every kind: {pipe:?}",
            worst_pipe.0, worst_pipe.1, worst_pipe.2
        );
        let rows = steps_verdict(&output.lines, only.is_none())?;
        if only.is_none() || only.as_deref() == Some(REAP) {
            let reap = reap_counters(&output.lines)?;
            println!(
                "posix-net steps: the accept queue of port {}: syn_dropped {}, queue_reaped {}, embryo_recycled {}; the longest step of the service in the run is {} ticks, of its own work (kind 65, where the frames are routed) {} ticks",
                reap.port,
                reap.syn_dropped,
                reap.queue_reaped,
                reap.embryo_recycled,
                rows.iter().map(|r| r.1).max().unwrap_or(0),
                rows.iter().find(|r| r.0 == 65).map_or(0, |r| r.1)
            );
        }
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

/// The check that fills an accept queue, resets its connections and connects again.
const REAP: &str = "reap-queue";

/// What the service says of the listener of the check `reap-queue`.
#[derive(Debug, PartialEq, Eq)]
struct Reap {
    port: u16,
    syn_dropped: u32,
    queue_reaped: u32,
    embryo_recycled: u32,
}

/// The counters of the accept queue of the check `reap-queue`, from its note
/// `port P resets N` and the line `net: listener place X port P syn_dropped D
/// queue_reaped R embryo_recycled E` that the build with the feature `probe`
/// prints while the listener stands. The one SYN that finds the queue full is
/// dropped, and each of the N resets of queue sockets is replaced by the SYN
/// that follows it.
fn reap_counters(lines: &[String]) -> Result<Reap, String> {
    let note = lines
        .iter()
        .find_map(|l| text_of(l)?.strip_prefix("reap-queue note: port "))
        .ok_or("posix-net: no note of reap-queue")?;
    let words: Vec<&str> = note.split_whitespace().collect();
    let [port, "resets", resets] = words.as_slice() else {
        return Err(format!("posix-net: the note of reap-queue is {note:?}"));
    };
    let (port, resets): (u16, u32) = (
        port.parse().map_err(|_| format!("the port {port:?}"))?,
        resets
            .parse()
            .map_err(|_| format!("the resets {resets:?}"))?,
    );
    let reap = lines
        .iter()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let [
                "net:",
                "listener",
                "place",
                _,
                "port",
                p,
                "syn_dropped",
                d,
                "queue_reaped",
                r,
                "embryo_recycled",
                e,
            ] = w.as_slice()
            else {
                return None;
            };
            Some(Reap {
                port: p.parse().ok()?,
                syn_dropped: d.parse().ok()?,
                queue_reaped: r.parse().ok()?,
                embryo_recycled: e.parse().ok()?,
            })
        })
        .rfind(|r| r.port == port)
        .ok_or_else(|| format!("posix-net: no line `net: listener` for port {port}"))?;
    if reap.syn_dropped < 1 || reap.queue_reaped < resets {
        return Err(format!(
            "posix-net: the queue of port {port} dropped {} SYNs and replaced {} sockets, wanted at least 1 and {resets}",
            reap.syn_dropped, reap.queue_reaped
        ));
    }
    Ok(reap)
}

/// The longest step of each kind in the lines of a run under -icount, judged
/// against the bound; CLONE and CLONE_MORE against the portion bound.
fn steps_verdict(lines: &[String], whole: bool) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = net_probe::longest_over_starts(lines)?;
    // The run of one check (POSIX_NET_ONLY) has no fork in it.
    if whole && !rows.iter().any(|r| r.0 == 19) {
        return Err(format!("no step of CLONE: {rows:?}"));
    }
    if whole && !rows.iter().any(|r| r.0 == 20) {
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

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| (*l).to_owned()).collect()
    }

    fn silent_lines() -> Vec<String> {
        lines(&[
            "init: tty silent service at 1666.399 ms, expiry 2.050 ms late, late 0 times in a row",
            "init: uart console driver: thread receiving",
            "init: tty went silent, killed from level 50; restarts in 100 ms",
        ])
    }

    fn failure(text: &[&str]) -> Result<(), Failed> {
        Err(Failed {
            error: "no prompt".to_owned(),
            lines: lines(text),
        })
    }

    #[test]
    fn only_a_silent_service_with_its_lines_qualifies_for_the_retry() {
        assert!(silent_service(&silent_lines()));
        // The line `went silent` alone, the lines `silent service` alone, other failures.
        assert!(!silent_service(&silent_lines()[2..]));
        assert!(!silent_service(&silent_lines()[..2]));
        assert!(!silent_service(&lines(&["posix-net: limits ok"])));
        assert!(!silent_service(&lines(&["init: net ended: fault"])));
        assert!(!silent_service(&[]));
    }

    #[test]
    fn a_silent_service_gets_one_more_run_and_a_second_failure_stands() {
        let (mut runs, mut noted) = (0, 0);
        let silent = silent_lines();
        let result = retrying(
            || {
                runs += 1;
                Err(Failed {
                    error: format!("run {runs}"),
                    lines: silent.clone(),
                })
            },
            |first| {
                noted += 1;
                assert_eq!(first, silent.as_slice());
            },
        );
        assert_eq!((runs, noted), (2, 1), "one retry, however it ends");
        assert_eq!(result.err().unwrap().error, "run 2");
    }

    #[test]
    fn a_passing_second_run_passes_and_a_first_pass_runs_once() {
        let (mut runs, mut noted) = (0, 0);
        let silent = silent_lines();
        let result = retrying(
            || {
                runs += 1;
                if runs == 1 {
                    Err(Failed {
                        error: "silent".to_owned(),
                        lines: silent.clone(),
                    })
                } else {
                    Ok(())
                }
            },
            |_| noted += 1,
        );
        assert!(result.is_ok() && (runs, noted) == (2, 1));
        let mut runs = 0;
        assert!(
            retrying(
                || {
                    runs += 1;
                    Ok(())
                },
                |_| panic!("no failure, no note")
            )
            .is_ok()
        );
        assert_eq!(runs, 1);
    }

    #[test]
    fn another_failure_gets_no_retry() {
        for text in [
            &["init: net ended: fault"][..],
            &[
                "posix-net: limits ok",
                "init: tty went silent, killed from level 50",
            ][..],
            &[][..],
        ] {
            let mut runs = 0;
            let result = retrying(
                || {
                    runs += 1;
                    failure(text)
                },
                |_| panic!("no note for {text:?}"),
            );
            assert!(result.is_err());
            assert_eq!(runs, 1, "{text:?}");
        }
    }

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
        assert!(steps_verdict(&ok, true).is_ok());
        let long = vec![line(19, 8_000), line(20, 17_000), line(65, 10_000)];
        assert!(steps_verdict(&long, true).unwrap_err().contains("past 0.8"));
        let slow = vec![line(19, 8_000), line(20, 8_000), line(65, 19_000)];
        assert!(steps_verdict(&slow, true).unwrap_err().contains("past 0.9"));
        let none = vec![line(65, 10_000)];
        assert!(
            steps_verdict(&none, true)
                .unwrap_err()
                .contains("no step of CLONE")
        );
    }

    #[test]
    fn the_counters_of_the_reaped_queue_are_read_and_judged() {
        let said = |port: u16, dropped: u32, reaped: u32| {
            vec![
                "posix-net: reap-queue note: port 40001 resets 16".to_owned(),
                format!(
                    "net: listener place 9 port {port} syn_dropped {dropped} queue_reaped {reaped} embryo_recycled 0"
                ),
            ]
        };
        let ok = reap_counters(&said(40001, 1, 16)).unwrap();
        assert_eq!((ok.syn_dropped, ok.queue_reaped), (1, 16));
        assert!(reap_counters(&said(40001, 0, 16)).is_err());
        assert!(reap_counters(&said(40001, 1, 15)).is_err());
        assert!(reap_counters(&said(40002, 1, 16)).is_err());
        assert!(reap_counters(&[]).is_err());
    }

    #[test]
    fn a_run_of_one_check_needs_no_clone() {
        let rows = vec!["service step: 14 kind 65 10000 ticks detail 0".to_owned()];
        assert!(steps_verdict(&rows, false).is_ok());
        assert!(steps_verdict(&rows, true).is_err());
    }
}
