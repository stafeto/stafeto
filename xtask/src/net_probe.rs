// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the network service (services/netd) on QEMU's virtio-net
//! device and user-mode networking, which also runs under HVF. One client
//! of the service (tests/net-probe, roles `c` and `k`) asks for the
//! interface's address, pings the gateway 300 times (more than the 256
//! buffers of the ring of receiving, so a buffer that never goes back
//! shows), kills the service, and asks again through a new session. Three
//! runs:
//!
//! 1. `boot-net-probe.img`: DHCP. Two starts of the device (the second after
//!    the restart), two leases, DHCP frames sent, the lines of the client.
//! 2. `boot-net-probe-static.img`: the same with `/etc/netd.conf` giving the
//!    address of the user network. Two static lines, no lease, and no DHCP
//!    frame in any counter.
//! 3. `boot-net-steps.img` under -icount: the first run again with the
//!    service counting its steps. Every step stays under 0.9 of term B.
//!
//! The echo to the gateway is the one ICMP slirp answers; the stack's own
//! answer to a ping (feature `auto-icmp-echo-reply` of smoltcp) is
//! invisible to this probe, so a test reads the manifest of the service for
//! the feature.

use std::time::{Duration, Instant};

use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, CHILD_STACK_SIZE, INIT_STACK_SIZE, ImageProgram, TERM_B, Variant, build,
    build_boot_image, longest_steps, qemu, run_until,
};

pub use crate::net::NETD_STACK_SIZE;

const RNG: ImageProgram = (
    "virtio-rng",
    "virtio-rng",
    crate::entropy::RNG_STACK_SIZE,
    &[],
);
const ENTROPY: ImageProgram = (
    "entropy",
    "entropy",
    crate::entropy::ENTROPY_STACK_SIZE,
    &[],
);
const RAM: ImageProgram = ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]);

/// The probe's image: the RAM files (which hold `/etc`), the entropy device
/// and service, the network service with PING and CRASH, the client.
pub const PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-net-probe"]),
    RAM,
    RNG,
    ENTROPY,
    ("netd", "netd", NETD_STACK_SIZE, &["probe"]),
    ("net-probe", "net-probe", CHILD_STACK_SIZE, &[]),
];

/// The image of the run under -icount: the service counts its steps.
pub const STEPS_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-net-probe"]),
    RAM,
    RNG,
    ENTROPY,
    ("netd", "netd", NETD_STACK_SIZE, &["probe", "steps"]),
    ("net-probe", "net-probe", CHILD_STACK_SIZE, &[]),
];

/// The service's line at each start: the transport, its line, the device's
/// status as the driver found it (0: init stopped the device before the new
/// instance) and the MAC.
pub const DEVICE_LINE: &str =
    "virtio-net: virtio-mmio at 0xa000e00, line 55, status 0x0, mac 52:54:00:12:34:56";
const LEASE: &str = "net: lease 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3";
const STATIC: &str = "net: static 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3";
const CONFIG: &str =
    "net-probe: config 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3 mac 52:54:00:12:34:56";
const CONFIG_AFTER: &str =
    "net-probe: after restart config 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3 mac 52:54:00:12:34:56";
const PINGS: &str = "net-probe: ping 10.0.2.2 ok 300";
const PINGS_AFTER: &str = "net-probe: after restart ping 10.0.2.2 ok 10";
const KILLED: &str = "net-probe: the service was killed";
const OK: &str = "net-probe: ok";
const ENDED: &str = "init: net-probe ended: exit code 0, not restarted";
const RTT: &str = "net-probe: ping rtt max ";
const FRAMES: &str = "net: frames rx ";
const SERVICE_ENDED: &str = "init: net ended: fault";

/// The tag of the service's lines of steps (rt::service::report_steps).
const NET_TAG: &str = "13";
/// The kinds of steps that must come: CONFIG (21), PING (62) and the
/// service's own steps (65: the interrupt, the continuation and the
/// deadline).
const STEP_KINDS: [(usize, &str); 3] = [(21, "Config"), (62, "Ping"), (65, "the own steps")];
/// The most one step of the service may take (spec 6): 0.9 of term B.
pub const STEP_MAX: u64 = TERM_B * 9 / 10;

/// How the interface got its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Dhcp,
    Static,
}

/// The numbers after `max` and `median` of the line of round trips.
fn rtts(line: &str) -> Option<(u64, u64)> {
    let rest = line.strip_prefix(RTT)?;
    let words: Vec<&str> = rest.split_whitespace().collect();
    let [max, "us", "median", median, "us"] = words.as_slice() else {
        return None;
    };
    Some((max.parse().ok()?, median.parse().ok()?))
}

/// The `dhcp` counter of a line `net: frames rx R tx T dhcp D dropped X`.
fn dhcp_count(line: &str) -> Option<u64> {
    let rest = line.strip_prefix(FRAMES)?;
    let words: Vec<&str> = rest.split_whitespace().collect();
    let [rx, "tx", tx, "dhcp", dhcp, "dropped", dropped] = words.as_slice() else {
        return None;
    };
    rx.parse::<u64>().ok()?;
    tx.parse::<u64>().ok()?;
    dropped.parse::<u64>().ok()?;
    dhcp.parse().ok()
}

/// Judges the lines of a run: the device started twice, the address came
/// each time as `mode` says, the client printed every line once and did
/// not fail, and the service was killed once and restarted by init.
pub fn verdict(lines: &[String], mode: Mode) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| l.starts_with("net-probe: failed")) {
        return Err(failed.clone());
    }
    let (addressed, other) = match mode {
        Mode::Dhcp => (LEASE, "net: static"),
        Mode::Static => (STATIC, "net: lease"),
    };
    let once = [
        (DEVICE_LINE, 2),
        (addressed, 2),
        (CONFIG, 1),
        (PINGS, 1),
        (KILLED, 1),
        (CONFIG_AFTER, 1),
        (PINGS_AFTER, 1),
        (OK, 1),
        (ENDED, 1),
    ];
    for (marker, wanted) in once {
        if count(marker) != wanted {
            let found: Vec<_> = lines
                .iter()
                .filter(|l| {
                    l.starts_with("virtio-net: ")
                        || l.starts_with("net: ")
                        || l.starts_with("init: net")
                })
                .collect();
            return Err(format!(
                "{} lines {marker:?}, {wanted} expected; the service said {found:?}",
                count(marker)
            ));
        }
    }
    if let Some(line) = lines.iter().find(|l| l.starts_with(other)) {
        return Err(format!(
            "{line:?} in a run that gets its address by {mode:?}"
        ));
    }
    let dhcp: Vec<u64> = lines.iter().filter_map(|l| dhcp_count(l)).collect();
    if dhcp.is_empty() {
        return Err("the service printed no line of frames".to_owned());
    }
    match mode {
        Mode::Dhcp if dhcp.iter().copied().max() < Some(2) => {
            return Err(format!("DHCP frames sent: {dhcp:?}, 2 expected at least"));
        }
        Mode::Static if dhcp.iter().any(|&d| d != 0) => {
            return Err(format!("DHCP frames sent in a static run: {dhcp:?}"));
        }
        _ => {}
    }
    if !lines.iter().any(|l| rtts(l).is_some()) {
        return Err("no line of round trips".to_owned());
    }
    let restarts = lines
        .iter()
        .filter(|l| l.starts_with(SERVICE_ENDED) && l.contains("restarts in"))
        .count();
    if restarts != 1 {
        return Err(format!(
            "{restarts} lines of the service's fault with a restart, 1 expected"
        ));
    }
    Ok(())
}

/// The steps of the service: every kind came and every row stays under
/// STEP_MAX.
pub fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = longest_steps(lines, NET_TAG);
    for (kind, name) in STEP_KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the network service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > STEP_MAX) {
        return Err(format!(
            "the network service: a step past 0.9 of term B ({STEP_MAX}): {row:?}"
        ));
    }
    Ok(rows)
}

/// A run on `machine` of the image `name` with `programs`: the machine
/// starts, and the lines are read until the client ends. The time to the
/// first address is the host's wall time.
fn run(
    machine: &qemu::Machine,
    name: &'static str,
    programs: &'static [ImageProgram],
    mode: Mode,
) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    let began = Instant::now();
    let mut run = Run::start(cmd, Input::Null)?;
    let within = Duration::from_secs(60);
    let first = match mode {
        Mode::Dhcp => LEASE,
        Mode::Static => STATIC,
    };
    let result = run
        .expect_line(first, |l| l == first, within)
        .map(|_| began.elapsed())
        .and_then(|took| run.expect_line(ENDED, |l| l == ENDED, within).map(|_| took));
    let outcome = run.stop();
    let took = result.map_err(|e| format!("net-probe on {} ({name}): {e}", machine.name))?;
    verdict(&outcome.lines, mode)
        .map_err(|e| format!("net-probe on {} ({name}): {e}", machine.name))?;
    let rtt = outcome.lines.iter().find_map(|l| rtts(l));
    println!(
        "net-probe on {} ({name}): the address after {} ms of the host's time, {} round trips: ok",
        machine.name,
        took.as_millis(),
        rtt.map_or_else(
            || "no".to_owned(),
            |(max, median)| format!("max {max} us, median {median} us;")
        )
    );
    Ok(())
}

/// The run under -icount: the service's steps are read from its lines.
fn steps(machine: &qemu::Machine) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-net-steps.img", &STEPS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    cmd.args(qemu::ICOUNT);
    let output = run_until(cmd, crate::BOOT_TIMEOUT * 4, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    verdict(&output.lines, Mode::Dhcp)
        .map_err(|e| format!("net-probe under -icount on {}: {e}", machine.name))?;
    let rows = steps_verdict(&output.lines)?;
    crate::check_waits(&output.lines, &[NET_TAG], "net-probe")?;
    let text: Vec<_> = rows
        .iter()
        .map(|(kind, ticks, detail)| format!("kind {kind} {ticks} (frames {detail})"))
        .collect();
    println!(
        "net-probe on {}: the longest steps under -icount, ticks (0.9 of term B {STEP_MAX}): {}",
        machine.name,
        text.join(", ")
    );
    Ok(())
}

/// `cargo xtask net-probe [MACHINE]` and the job of `ci`: the three runs.
/// The steps run needs the emulation's own clock, so it runs on QEMU's
/// TCG only.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    run(machine, "boot-net-probe.img", &PROGRAMS, Mode::Dhcp)?;
    run(
        machine,
        "boot-net-probe-static.img",
        &PROGRAMS,
        Mode::Static,
    )?;
    if !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// `cargo xtask net-probe [MACHINE]`: the machine is `tcg` (the default),
/// `hvf` or the name of one of qemu::MACHINES.
pub fn command(args: &[String]) -> Result<(), String> {
    let machine = match args {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask net-probe [hvf|tcg|MACHINE]".to_owned()),
    };
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("net-probe on {}: {why}", machine.name))?;
    }
    probe(machine)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_run(mode: Mode) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        let address = match mode {
            Mode::Dhcp => LEASE,
            Mode::Static => STATIC,
        };
        let dhcp = if mode == Mode::Dhcp { 3 } else { 0 };
        for round in 0..2 {
            lines.push(DEVICE_LINE.to_owned());
            lines.push(address.to_owned());
            if round == 0 {
                lines.push(CONFIG.to_owned());
                lines.push(format!("{FRAMES}12 tx 9 dhcp {dhcp} dropped 0"));
                lines.push(PINGS.to_owned());
                lines.push(format!("{RTT}900 us median 300 us"));
                lines.push(KILLED.to_owned());
                lines.push(
                    "init: net ended: fault ESR=0x1 FAR=0x0 ELR=0x2; restarts in 100 ms".to_owned(),
                );
            }
        }
        lines.push(CONFIG_AFTER.to_owned());
        lines.push(PINGS_AFTER.to_owned());
        lines.push(OK.to_owned());
        lines.push(ENDED.to_owned());
        lines
    }

    #[test]
    fn a_run_with_every_line_passes() {
        assert_eq!(verdict(&good_run(Mode::Dhcp), Mode::Dhcp), Ok(()));
        assert_eq!(verdict(&good_run(Mode::Static), Mode::Static), Ok(()));
    }

    #[test]
    fn a_missing_line_is_named() {
        for marker in [
            DEVICE_LINE,
            LEASE,
            CONFIG,
            PINGS,
            KILLED,
            CONFIG_AFTER,
            PINGS_AFTER,
            OK,
        ] {
            let mut lines = good_run(Mode::Dhcp);
            let at = lines.iter().rposition(|l| l == marker).unwrap();
            lines.remove(at);
            assert!(
                verdict(&lines, Mode::Dhcp).unwrap_err().contains(marker),
                "{marker}"
            );
        }
    }

    #[test]
    fn a_failure_of_the_client_is_the_verdict() {
        let mut lines = good_run(Mode::Dhcp);
        lines.push("net-probe: failed: a PING of the gateway failed".to_owned());
        assert!(verdict(&lines, Mode::Dhcp).unwrap_err().contains("PING"));
    }

    #[test]
    fn dhcp_must_send_frames_and_a_static_run_none() {
        let mut lines = good_run(Mode::Dhcp);
        for l in lines.iter_mut().filter(|l| l.starts_with(FRAMES)) {
            *l = format!("{FRAMES}12 tx 9 dhcp 1 dropped 0");
        }
        assert!(verdict(&lines, Mode::Dhcp).unwrap_err().contains("DHCP"));
        // The line of the other way to get an address is a fault.
        let mut lines = good_run(Mode::Static);
        lines.push(LEASE.to_owned());
        assert!(verdict(&lines, Mode::Static).is_err());
        let mut lines = good_run(Mode::Static);
        for l in lines.iter_mut().filter(|l| l.starts_with(FRAMES)) {
            *l = format!("{FRAMES}12 tx 9 dhcp 2 dropped 0");
        }
        assert!(
            verdict(&lines, Mode::Static)
                .unwrap_err()
                .contains("static")
        );
    }

    #[test]
    fn the_service_must_restart_once() {
        let mut lines = good_run(Mode::Dhcp);
        lines.retain(|l| !l.starts_with(SERVICE_ENDED));
        assert!(verdict(&lines, Mode::Dhcp).unwrap_err().contains("restart"));
    }

    #[test]
    fn the_lines_of_numbers_are_read() {
        assert_eq!(
            rtts("net-probe: ping rtt max 900 us median 300 us"),
            Some((900, 300))
        );
        assert_eq!(rtts("net-probe: ping rtt max x us median 300 us"), None);
        assert_eq!(
            dhcp_count("net: frames rx 12 tx 9 dhcp 3 dropped 1"),
            Some(3)
        );
        assert_eq!(dhcp_count("net: frames rx 12 tx 9 dropped 1"), None);
    }

    fn step(kind: usize, ticks: u64) -> String {
        format!("service step: {NET_TAG} kind {kind} {ticks} ticks detail 0")
    }

    #[test]
    fn steps_under_the_bound_pass_and_past_it_fail() {
        let ok: Vec<String> = [(21, 3000), (62, 4000), (65, 9000), (64, 100)]
            .iter()
            .map(|&(k, t)| step(k, t))
            .collect();
        assert_eq!(steps_verdict(&ok).map(|r| r.len()), Ok(4));
        let mut over = ok.clone();
        over.push(step(65, STEP_MAX + 1));
        assert!(steps_verdict(&over).is_err());
        let missing: Vec<String> = ok
            .iter()
            .filter(|l| !l.contains("kind 62"))
            .cloned()
            .collect();
        assert!(steps_verdict(&missing).unwrap_err().contains("Ping"));
        assert_eq!(STEP_MAX, 18_369);
    }

    /// The service answers the pings of the network with the stack's own
    /// code: without this feature of smoltcp it stays silent, which no
    /// probe on the user network sees (slirp sends the guest no echo).
    #[test]
    fn the_stack_answers_ping_by_its_feature() {
        let manifest = std::fs::read_to_string(crate::root().join("services/netd/Cargo.toml"))
            .expect("the manifest of netd");
        let smoltcp = manifest
            .split("smoltcp = {")
            .nth(1)
            .and_then(|rest| rest.split("] }").next())
            .expect("the dependency on smoltcp");
        for feature in [
            "auto-icmp-echo-reply",
            "proto-ipv4",
            "medium-ethernet",
            "socket-dhcpv4",
            "socket-icmp",
            "iface-neighbor-cache-count-16",
        ] {
            assert!(
                smoltcp.contains(&format!("\"{feature}\"")),
                "smoltcp lacks {feature}"
            );
        }
        assert!(
            smoltcp.contains("default-features = false"),
            "the stack builds without std"
        );
    }

    /// The image of the shell holds the service built without PING and
    /// CRASH; only the probe's images have them.
    #[test]
    fn the_images_of_the_probe_build_the_service_with_its_features() {
        let features = |list: &[ImageProgram]| -> Vec<&'static str> {
            list.iter().find(|p| p.0 == "netd").unwrap().3.to_vec()
        };
        assert_eq!(features(&PROGRAMS), ["probe"]);
        assert_eq!(features(&STEPS_PROGRAMS), ["probe", "steps"]);
        assert_eq!(PROGRAMS[0].3, &["table-net-probe"]);
    }
}
