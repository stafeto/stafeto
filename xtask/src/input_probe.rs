// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the input service (services/virtio-input) on QEMU's
//! virtio-keyboard-device, which also runs under HVF. The image holds the
//! input service, the display service with its connection to it, and the
//! probe (tests/input-probe), which stands in for the display service
//! first (GRANT and REVOKE by its own session) and then asks the real one
//! for the screen, whose owner has the focus.
//!
//! The probe prints `input-probe: send X` and waits; xtask answers each
//! line with `sendkey` through the monitor (`monitor.rs`), so that the key
//! reaches the guest as a Linux event the probe checks by code: `b` with no
//! focus (dropped), `a` after GRANT (`1 30 1` and `1 30 0`), a burst of 80
//! presses nobody reads (64 events and LOST), `c` after a second GRANT, `d`
//! after REVOKE, then `a`, `b` and `c` around the owner of the screen
//! (OPEN, CLOSE, OPEN).
//!
//! A second run, under -icount (QEMU's own emulation), measures the steps
//! of the service: the probe in its `quick` build asks for the focus and
//! polls READ until the key `z`, while xtask sends three combinations of 16
//! keys, 32 events each, and `z`, so that the guest takes several events at
//! one interrupt.
//! Every step stays under 0.9 of term B.

use std::path::PathBuf;
use std::time::Duration;

use crate::monitor::Monitor;
use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, CHILD_STACK_SIZE, INIT_STACK_SIZE, ImageProgram, TERM_B, Variant, build,
    build_boot_image, longest_steps, qemu,
};

/// The stack of the input service: its loop's table of 16 sessions and the
/// 120 events of a reply.
pub const INPUT_STACK_SIZE: u32 = 32 * 1024;
/// The stack of the display service, as in the display probe.
const GPU_STACK_SIZE: u32 = crate::gpu_probe::GPU_STACK_SIZE;

/// The probe's image: the input service, the display service, the probe.
pub const PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-input"]),
    ("virtio-input", "virtio-input", INPUT_STACK_SIZE, &[]),
    ("virtio-gpu", "virtio-gpu", GPU_STACK_SIZE, &["crash"]),
    ("input-probe", "input-probe", CHILD_STACK_SIZE, &[]),
];

/// The image of the run under -icount: the service counts its steps, the
/// probe does not wait for the clock.
pub const STEPS_PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-input"]),
    ("virtio-input", "virtio-input", INPUT_STACK_SIZE, &["steps"]),
    ("virtio-gpu", "virtio-gpu", GPU_STACK_SIZE, &[]),
    ("input-probe", "input-probe", CHILD_STACK_SIZE, &["quick"]),
];

/// The service's line at each start: the transport, its line and the
/// device's status as the driver found it, before its own reset.
pub const SERVICE_LINE: &str = "virtio-input: virtio-mmio at 0xa001e00, line 63, status 0x0";
/// The start of the line that names the device and its keys.
const DEVICE_LINE: &str = "input: QEMU Virtio Keyboard, keys 0x";
const MARKER: &str = "input-probe: send ";
const ENDED: &str = "init: input-probe ended: exit code 0, not restarted";

/// The lines the probe prints once per check that passed.
const CHECKS: [&str; 14] = [
    "input-probe: a key with no focus is dropped",
    "input-probe: key 1 30 1",
    "input-probe: key 1 30 0",
    "input-probe: a burst leaves 64 events and LOST once",
    "input-probe: the focus goes to the last GRANT, the first is REVOKED",
    "input-probe: a session calls its own methods only",
    "input-probe: after REVOKE a key goes nowhere and the focus is REVOKED",
    "input-probe: OPEN gave the owner a session of focus",
    "input-probe: the key reaches the owner of the screen",
    "input-probe: with no owner a key goes nowhere, the next owner has the focus",
    "input-probe: 20 owners in turn keep their foci, the next owner reads",
    "input-probe: the end of the display service revokes the focus",
    "input-probe: a program init gave no session is refused",
    "input-probe: ok",
];

/// The presses of a burst.
const BURST: usize = 80;
/// What xtask presses for each `send X` line of the probe: the keys of
/// QEMU's `sendkey`, in order.
fn keys_for(what: &str) -> Result<Vec<&'static str>, String> {
    Ok(match what {
        "b" | "b2" => vec!["b"],
        "a" | "a2" => vec!["a"],
        "c" | "c2" => vec!["c"],
        "d" => vec!["d"],
        "burst" => vec!["a"; BURST],
        other => return Err(format!("the probe asked for the key {other:?}")),
    })
}

/// The order of the probe's requests for keys.
const REQUESTS: [&str; 8] = ["b", "a", "burst", "c", "d", "a2", "b2", "c2"];

/// The tag of the service's lines of steps (rt::service::report_steps).
const INPUT_TAG: &str = "13";
/// The kinds of the service's steps that must come: GRANT, REVOKE, READ
/// (the methods of proto_input), and its own steps: the interrupt.
const STEP_KINDS: [(usize, &str); 4] = [
    (1, "Grant"),
    (2, "Revoke"),
    (3, "Read"),
    (65, "the interrupt"),
];
/// The most one step of the service may take (spec 3, section 6): 0.9 of
/// term B, 18,369 ticks.
pub const STEP_MAX: u64 = TERM_B * 9 / 10;

/// Judges the lines of a run: the service started once, named its device,
/// every check of the probe passed once, none failed.
pub fn verdict(lines: &[String]) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| {
        l.starts_with("input-probe: failed")
            || (l.starts_with("virtio-input: ") && l.as_str() != SERVICE_LINE)
    }) {
        return Err(format!("the run said {failed:?}"));
    }
    for marker in CHECKS {
        // `ok` is printed by both roles.
        let wanted = if marker == "input-probe: ok" { 2 } else { 1 };
        if count(marker) != wanted {
            let service: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with("virtio-") || l.starts_with("input: "))
                .collect();
            return Err(format!(
                "{} lines {marker:?}, {wanted} expected; the services said {service:?}",
                count(marker)
            ));
        }
    }
    if count(SERVICE_LINE) != 1 {
        return Err(format!("the service started {} times", count(SERVICE_LINE)));
    }
    let device = lines.iter().filter(|l| l.starts_with(DEVICE_LINE)).count();
    if device != 1 {
        return Err(format!("{device} lines {DEVICE_LINE:?}, 1 expected"));
    }
    Ok(())
}

/// The steps of the service: every kind came and every row stays under
/// STEP_MAX.
pub fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = longest_steps(lines, INPUT_TAG);
    for (kind, name) in STEP_KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the input service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > STEP_MAX) {
        return Err(format!(
            "the input service: a step past 0.9 of term B ({STEP_MAX}): {row:?}"
        ));
    }
    Ok(rows)
}

/// The events one step of the service takes at most (PER_STEP of
/// services/virtio-input).
const PER_STEP: u64 = 16;

/// The lines of the interrupt step (kind 65): (ticks, events), each a new
/// longest, so the first is the shortest.
fn interrupt_steps(lines: &[String]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let [
            "service",
            "step:",
            tag,
            "kind",
            "65",
            ticks,
            "ticks",
            "detail",
            detail,
        ] = words.as_slice()
            && *tag == INPUT_TAG
            && let (Ok(ticks), Ok(detail)) = (ticks.parse(), detail.parse())
        {
            out.push((ticks, detail));
        }
    }
    out
}

/// The step of PER_STEP events from the lines of the interrupt step: the
/// shortest line is the base, the steepest rise over it per event is the
/// cost of an event; (base, ticks an event, projected step). None without
/// a line that carries events.
pub fn projection(lines: &[String]) -> Option<(u64, u64, u64)> {
    let steps = interrupt_steps(lines);
    let base = steps.iter().map(|s| s.0).min()?;
    let per_event = steps
        .iter()
        .filter(|s| s.1 > 0)
        .map(|&(ticks, events)| (ticks - base).div_ceil(events))
        .max()?;
    Some((base, per_event, base + PER_STEP * per_event))
}

/// Where the run keeps its monitor's socket.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Scratch, String> {
        let dir = std::env::temp_dir().join(format!("stafeto-input-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Scratch(dir))
    }

    fn socket(&self) -> PathBuf {
        self.0.join("monitor.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The QEMU command of a run: both devices, a monitor on a socket.
fn command(
    machine: &qemu::Machine,
    image: &std::path::Path,
    kernel: &std::path::Path,
    scratch: &Scratch,
) -> std::process::Command {
    let mut cmd = qemu::command(machine, kernel, Some(image));
    cmd.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    cmd.arg(format!(
        "unix:{},server=on,wait=off",
        scratch.socket().display()
    ));
    cmd.args(qemu::GPU);
    cmd.args(qemu::KEYBOARD);
    cmd
}

/// Presses `keys`, each held `hold` milliseconds.
fn press(monitor: &mut Monitor, keys: &[&str], hold: u32) -> Result<(), String> {
    for key in keys {
        monitor.sendkey(key, Some(hold))?;
    }
    Ok(())
}

/// Follows the run: each request of the probe answered with its keys, then
/// the end of both roles.
fn drive(run: &mut Run, scratch: &Scratch) -> Result<(), String> {
    const WITHIN: Duration = Duration::from_secs(120);
    let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
    for what in REQUESTS {
        let wanted = format!("{MARKER}{what}");
        run.expect_line(&wanted, |l| l == wanted, WITHIN)?;
        let keys = keys_for(what)?;
        // The burst is quick, the other keys are held as QEMU's default.
        let hold = if what == "burst" { 1 } else { 100 };
        press(&mut monitor, &keys, hold)?;
    }
    // The stranger ended at the start, before the first request of the
    // other; its lines are in the verdict's.
    run.expect_line(ENDED, |l| l == ENDED, WITHIN)?;
    Ok(())
}

/// `cargo xtask input-probe` and its run in `test` under HVF: the probe on
/// `machine`, the keys of the monitor, and, on QEMU's own emulation, the
/// steps of the service under -icount.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-input.img", &PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let cmd = command(machine, &image, &kernel.image, &scratch);
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = drive(&mut run, &scratch);
    let outcome = run.stop();
    driven.map_err(|e| format!("input-probe on {}: {e}", machine.name))?;
    verdict(&outcome.lines).map_err(|e| format!("input-probe on {}: {e}", machine.name))?;
    println!(
        "input-probe on {}: the keys reached the focus with their codes, LOST once, the focus followed GRANT, REVOKE and the owner of the screen",
        machine.name
    );
    if !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// The run under -icount: the probe polls, xtask sends the keys when it
/// asks, and the service's steps are read from its lines.
fn steps(machine: &qemu::Machine) -> Result<(), String> {
    const WITHIN: Duration = Duration::from_secs(300);
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-input-steps.img", &STEPS_PROGRAMS, BOOT_PROFILE)?;
    let scratch = Scratch::new()?;
    let mut cmd = command(machine, &image, &kernel.image, &scratch);
    cmd.args(qemu::ICOUNT);
    let mut run = Run::start(cmd, Input::Null)?;
    let driven = (|| {
        let mut monitor = Monitor::connect(&scratch.socket(), Duration::from_secs(20))?;
        let wanted = format!("{MARKER}keys");
        run.expect_line(&wanted, |l| l == wanted, WITHIN)?;
        // A combination is one command: its 16 presses and their SYN
        // events reach the device at once, 32 events, which the guest takes
        // in more than one step.
        for _ in 0..3 {
            monitor.sendkey("a-b-d-e-f-g-h-i-j-k-l-m-n-o-p-q", Some(1))?;
        }
        press(&mut monitor, &["z"], 1)?;
        run.expect_line(ENDED, |l| l == ENDED, WITHIN).map(|_| ())
    })();
    let outcome = run.stop();
    driven.map_err(|e| format!("input-probe under -icount: {e}"))?;
    if let Some(failed) = outcome
        .lines
        .iter()
        .find(|l| l.starts_with("input-probe: failed"))
    {
        return Err(format!("input-probe under -icount: {failed}"));
    }
    let rows = steps_verdict(&outcome.lines)?;
    crate::check_waits(&outcome.lines, &[INPUT_TAG], "input-probe")?;
    let (base, per_event, projected) = projection(&outcome.lines)
        .ok_or_else(|| "input-probe: no interrupt step carried events".to_owned())?;
    if projected > STEP_MAX {
        return Err(format!(
            "input-probe: a step of {PER_STEP} events projects to {projected} ticks ({base} and {per_event} an event), past {STEP_MAX}: lower PER_STEP"
        ));
    }
    println!(
        "input-probe on {}: a step of {PER_STEP} events projects to {projected} ticks ({base} and {per_event} an event)",
        machine.name
    );
    let text: Vec<_> = rows
        .iter()
        .map(|(kind, ticks, detail)| format!("kind {kind} {ticks} (detail {detail})"))
        .collect();
    println!(
        "input-probe on {}: the longest steps under -icount, ticks (0.9 of term B {STEP_MAX}): {}",
        machine.name,
        text.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_run() -> Vec<String> {
        let mut lines = vec![
            SERVICE_LINE.to_owned(),
            format!("{DEVICE_LINE}7fffffff (95 codes)"),
        ];
        for marker in CHECKS {
            let n = if marker == "input-probe: ok" { 2 } else { 1 };
            for _ in 0..n {
                lines.push(marker.to_owned());
            }
        }
        lines
    }

    #[test]
    fn a_run_with_every_check_passes() {
        assert_eq!(verdict(&good_run()), Ok(()));
    }

    #[test]
    fn a_missing_or_a_failed_check_is_named() {
        let mut lines = good_run();
        lines.retain(|l| l != "input-probe: key 1 30 0");
        assert!(verdict(&lines).unwrap_err().contains("key 1 30 0"));
        let mut lines = good_run();
        lines.push("input-probe: failed: READ".to_owned());
        assert!(verdict(&lines).unwrap_err().contains("failed: READ"));
        let mut lines = good_run();
        lines.push("virtio-input: a used buffer 70 out of the queue".to_owned());
        assert!(verdict(&lines).is_err());
    }

    #[test]
    fn a_service_that_started_twice_or_named_no_device_fails() {
        let mut lines = good_run();
        lines.push(SERVICE_LINE.to_owned());
        assert!(verdict(&lines).unwrap_err().contains("2 times"));
        let mut lines = good_run();
        lines.retain(|l| !l.starts_with(DEVICE_LINE));
        assert!(verdict(&lines).unwrap_err().contains("0 lines"));
    }

    #[test]
    fn every_request_of_the_probe_has_keys() {
        for what in REQUESTS {
            assert!(!keys_for(what).expect("keys").is_empty(), "{what}");
        }
        assert_eq!(keys_for("burst").expect("keys").len(), BURST);
        assert_eq!(keys_for("a").expect("keys"), ["a"]);
        assert!(keys_for("e").is_err());
    }

    fn step(kind: usize, ticks: u64) -> String {
        format!("service step: {INPUT_TAG} kind {kind} {ticks} ticks detail 0")
    }

    #[test]
    fn steps_under_the_bound_pass() {
        let lines: Vec<String> = [(1, 3000), (2, 1500), (3, 2500), (65, 6000), (64, 4000)]
            .iter()
            .map(|&(k, t)| step(k, t))
            .collect();
        assert_eq!(steps_verdict(&lines).map(|r| r.len()), Ok(5));
    }

    #[test]
    fn a_step_past_the_bound_or_a_missing_kind_fails() {
        let base = [(1, 3000), (2, 1500), (3, 2500), (65, 6000)];
        let make = |over: Option<(usize, u64)>, skip: Option<usize>| -> Vec<String> {
            base.iter()
                .filter(|(k, _)| Some(*k) != skip)
                .map(|&(k, t)| match over {
                    Some((ok, ot)) if ok == k => step(k, ot),
                    _ => step(k, t),
                })
                .collect()
        };
        assert!(steps_verdict(&make(Some((65, STEP_MAX + 1)), None)).is_err());
        assert!(
            steps_verdict(&make(None, Some(3)))
                .unwrap_err()
                .contains("Read")
        );
        assert!(steps_verdict(&make(Some((65, STEP_MAX)), None)).is_ok());
    }

    #[test]
    fn a_step_of_sixteen_events_is_projected_from_the_slope() {
        let lines: Vec<String> = [(951, 0), (1500, 2), (2034, 4)]
            .iter()
            .map(|&(t, d)| format!("service step: {INPUT_TAG} kind 65 {t} ticks detail {d}"))
            .collect();
        // Base 951, the steepest rise is 1083 over 4 events: 271 an event.
        assert_eq!(projection(&lines), Some((951, 275, 951 + 16 * 275)));
        assert_eq!(projection(&[]), None);
        let none: Vec<String> = vec![format!(
            "service step: {INPUT_TAG} kind 65 951 ticks detail 0"
        )];
        assert_eq!(projection(&none), None);
    }

    #[test]
    fn the_bound_is_the_specs() {
        assert_eq!(STEP_MAX, 18_369);
    }
}
