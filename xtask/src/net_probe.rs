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
//! The client has more roles than the first stage had: `b` (the registry of
//! ports and the sessions) and `sN` (N places of the table filled, half of
//! them sockets of connections that carry 64 KiB each way on the loopback).
//! The images run `b` and `s` at the limit of the sockets (`SOCKETS_LIMIT`).
//! `cargo xtask net-probe steps` is the measurement that chose the frames
//! of a step and that limit: `s` at 8, 64 and 256 places with each batch of
//! frames, and the rule of `netd::choose` over the longest steps.
//!
//! The echo to the gateway is the one ICMP slirp answers; the stack's own
//! answer to a ping (feature `auto-icmp-echo-reply` of smoltcp) is
//! invisible to this probe, so a test reads the manifest of the service for
//! the feature.

use std::time::{Duration, Instant};

use crate::qemu::{Input, Run};
use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, TERM_B, Variant, build, build_boot_image, qemu,
    run_until,
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
/// The stack of the client: the roles keep tables of 64 connections.
const PROBE_STACK_SIZE: u32 = 128 * 1024;
const RAM: ImageProgram = ("ramfs", "ramfs", crate::RAMFS_STACK_SIZE, &[]);

/// The probe's image: the RAM files (which hold `/etc`), the entropy device
/// and service, the network service with PING and CRASH, the client.
pub const PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-net-probe"]),
    RAM,
    RNG,
    ENTROPY,
    ("netd", "netd", NETD_STACK_SIZE, &["probe"]),
    ("net-probe", "net-probe", PROBE_STACK_SIZE, &[]),
];

/// The image of two network devices: the probe's image with init's table of
/// two devices (`table-net-probe-two`).
pub const TWO_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-net-probe-two"]),
    RAM,
    RNG,
    ENTROPY,
    ("netd", "netd", NETD_STACK_SIZE, &["probe"]),
    ("net-probe", "net-probe", PROBE_STACK_SIZE, &[]),
];

/// A free port of the host, taken and given back.
fn free_tcp_port() -> Result<u16, String> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("a free port: {e}"))?;
    Ok(listener
        .local_addr()
        .map_err(|e| format!("a free port: {e}"))?
        .port())
}

/// How long the second connection must stay open.
const SILENT_FOR: Duration = Duration::from_secs(1);

/// Whether a connection to the port stays open for `SILENT_FOR`: the second
/// device's stack answers a SYN with a reset when its filter lets one in,
/// and slirp closes the connection of the host at once. A closed connection
/// is the fault. The first reset of a stack that does not know its gateway's
/// address is lost (the stack asks for the address instead), so a first
/// connection makes that exchange and the second one is judged.
pub fn silent_port(port: u16) -> Result<(), String> {
    use std::io::Read;
    let address: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let connect = || {
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .map_err(|e| format!("connect to the forward of the second device: {e}"))
    };
    let first = connect()?;
    std::thread::sleep(Duration::from_millis(500));
    let mut stream = connect()?;
    stream
        .set_read_timeout(Some(SILENT_FOR))
        .map_err(|e| format!("timeout: {e}"))?;
    let mut byte = [0u8; 1];
    let read = stream.read(&mut byte);
    drop(first);
    match read {
        Ok(_) => Err("the second device closed a connection to its port 81: it answered a SYN (the filter of the second device does not hold)".to_owned()),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Ok(()),
        Err(e) => Err(format!("the connection to the second device ended: {e}")),
    }
}

/// The second device's lines at each start: the transport, its line, the
/// device's status and its MAC; and the lease the second user network gives
/// (10.0.3.0/24).
pub const DEVICE_LINE_TWO: &str =
    "virtio-net1: virtio-mmio at 0xa001c00, line 62, status 0x0, mac 52:54:00:12:34:57";
const LEASE_TWO: &str = "net: lease1 10.0.3.15/24 gw 10.0.3.2 dns 10.0.3.3";

/// Judges the lines of the run of two devices beyond `verdict`'s: each
/// device started twice (the second time after the restart), each leased
/// its address twice, said its first interrupt twice (once per start), and
/// the first device's did not mix with the second's.
pub fn two_verdict(lines: &[String]) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    for (marker, wanted) in [
        (DEVICE_LINE_TWO, 2),
        (LEASE_TWO, 2),
        ("virtio-net1: first interrupt", 2),
        ("virtio-net: first interrupt", 2),
    ] {
        if count(marker) != wanted {
            let found: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with("virtio-net") || l.starts_with("net: lease"))
                .collect();
            return Err(format!(
                "{} lines {marker:?}, {wanted} expected; the service said {found:?}",
                count(marker)
            ));
        }
    }
    Ok(())
}

/// The image of two devices under -icount: the service counts its steps.
pub const TWO_STEPS_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-net-probe-two"]),
    RAM,
    RNG,
    ENTROPY,
    ("netd", "netd", NETD_STACK_SIZE, &["probe", "steps"]),
    ("net-probe", "net-probe", PROBE_STACK_SIZE, &[]),
];

/// The image of the run under -icount: the service counts its steps.
#[allow(dead_code)] // the list of images of rootfs.rs names it.
pub const STEPS_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-net-probe"]),
    RAM,
    RNG,
    ENTROPY,
    ("netd", "netd", NETD_STACK_SIZE, &["probe", "steps"]),
    ("net-probe", "net-probe", PROBE_STACK_SIZE, &[]),
];

/// An image of the measurement of the steps: the role features of `init`
/// (`roles`, none for the default roles of the ci run) and the features of
/// the service on top of PING, CRASH, HOLD and the counting of steps. The
/// lists of features live as long as the program.
fn measured_programs(
    roles: Option<&'static str>,
    netd: &[&'static str],
) -> &'static [ImageProgram] {
    fn leak(features: Vec<&'static str>) -> &'static [&'static str] {
        Box::leak(features.into_boxed_slice())
    }
    let mut init = vec!["table-net-probe"];
    init.extend(roles);
    let mut service = vec!["probe", "steps"];
    service.extend_from_slice(netd);
    Box::leak(Box::new([
        ("init", "init", INIT_STACK_SIZE, leak(init)),
        RAM,
        RNG,
        ENTROPY,
        ("netd", "netd", NETD_STACK_SIZE, leak(service)),
        ("net-probe", "net-probe", PROBE_STACK_SIZE, &[]),
    ]))
}

/// The name of an image of the measurement.
fn measured_name(what: &str) -> &'static str {
    Box::leak(format!("boot-net-steps-{what}.img").into_boxed_str())
}

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
const BIND: &str = "net-probe: bind ok";
const FULL_BATCH: &str = "net-probe: full batch ok";
const ALL_GROUPS: &str = "net-probe: all groups ok";
const WAKES: &str = "net-probe: wakes ok 16 and 128";
const IDLE: &str = "net-probe: idle ok";
const LISTENERS: &str = "net-probe: listeners ok";
const TIMERS_PREFIX: &str = "net-probe: timers ok";
const WIRE_PREFIX: &str = "net-probe: wire ok 150";
const KILLED: &str = "net-probe: the service was killed";
const OK: &str = "net-probe: ok";
const ENDED: &str = "init: net-probe ended: exit code 0, not restarted";
const ENDED_PREFIX: &str = "init: net-probe ended: ";
const RTT: &str = "net-probe: ping rtt max ";
const FRAMES: &str = "net: frames rx ";
const SERVICE_ENDED: &str = "init: net ended: fault";

/// The tag of the service's lines of steps (rt::service::report_steps).
const NET_TAG: &str = "14";
/// The kinds of steps that must come: CONFIG (21), PING (62) and the
/// service's own steps (65: the interrupt, the continuation and the
/// deadline).
const STEP_KINDS: [(usize, &str); 3] = [(21, "Config"), (62, "Ping"), (65, "the own steps")];
/// The most one step of the service may take (spec 6): 0.9 of term B.
pub const STEP_MAX: u64 = TERM_B * 9 / 10;
/// The most the step of a CLONE of 64 descriptions may take: a portion, 0.8 of
/// term B.
pub const PORTION_MAX: u64 = TERM_B * 8 / 10;
/// The kinds of steps: CLONE, and the service's own steps.
const CLONE_KIND: usize = 19;
const OWN_KIND: usize = 65;

/// How the interface got its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Dhcp,
    Static,
}

/// What the client ran besides `c` and `k`: whether `b`, the places of `s`
/// if it ran, and the roles `f`, `a` and `w`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Roles {
    pub bind: bool,
    pub places: Option<usize>,
    pub full_batch: bool,
    pub all_groups: bool,
    pub wakes: bool,
    pub idle: bool,
    pub listeners: bool,
    pub timers: bool,
    pub wire: bool,
}

impl Roles {
    const NONE: Roles = Roles {
        bind: false,
        places: None,
        full_batch: false,
        all_groups: false,
        wakes: false,
        idle: false,
        listeners: false,
        timers: false,
        wire: false,
    };

    /// The images of the ci run: the registry, and the table filled to the
    /// limit.
    pub const LIMIT: Roles = Roles {
        bind: true,
        places: Some(SOCKETS_LIMIT),
        ..Roles::NONE
    };

    pub const fn places(places: usize) -> Roles {
        Roles {
            places: Some(places),
            ..Roles::NONE
        }
    }

    pub const FULL_BATCH: Roles = Roles {
        full_batch: true,
        ..Roles::NONE
    };
    pub const ALL_GROUPS: Roles = Roles {
        all_groups: true,
        ..Roles::NONE
    };
    pub const WAKES: Roles = Roles {
        wakes: true,
        ..Roles::NONE
    };
    pub const IDLE: Roles = Roles {
        idle: true,
        ..Roles::NONE
    };
    pub const LISTENERS: Roles = Roles {
        listeners: true,
        ..Roles::NONE
    };
    pub const TIMERS: Roles = Roles {
        timers: true,
        ..Roles::NONE
    };
    pub const WIRE: Roles = Roles {
        wire: true,
        ..Roles::NONE
    };
}

/// The sockets the service serves at once (the limit of its table).
pub const SOCKETS_LIMIT: usize = netd::places::SOCKETS_LIMIT;

/// The numbers after `max` and `median` of the line of round trips.
fn rtts(line: &str) -> Option<(u64, u64)> {
    let rest = line.strip_prefix(RTT)?;
    let words: Vec<&str> = rest.split_whitespace().collect();
    let [max, "us", "median", median, "us"] = words.as_slice() else {
        return None;
    };
    Some((max.parse().ok()?, median.parse().ok()?))
}

/// The counters of a line `net: frames rx R tx T dhcp D dropped X martian M
/// listen_short S bad_sum B demux_probe P`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frames {
    dropped: u64,
    dhcp: u64,
    martian: u64,
    listen_short: u64,
    bad_sum: u64,
    demux_probe: u64,
}

fn frames(line: &str) -> Option<Frames> {
    let rest = line.strip_prefix(FRAMES)?;
    let words: Vec<&str> = rest.split_whitespace().collect();
    let [
        rx,
        "tx",
        tx,
        "dhcp",
        dhcp,
        "dropped",
        dropped,
        "martian",
        martian,
        "listen_short",
        listen_short,
        "bad_sum",
        bad_sum,
        "demux_probe",
        demux_probe,
    ] = words.as_slice()
    else {
        return None;
    };
    rx.parse::<u64>().ok()?;
    tx.parse::<u64>().ok()?;
    Some(Frames {
        dropped: dropped.parse().ok()?,
        dhcp: dhcp.parse().ok()?,
        martian: martian.parse().ok()?,
        listen_short: listen_short.parse().ok()?,
        bad_sum: bad_sum.parse().ok()?,
        demux_probe: demux_probe.parse().ok()?,
    })
}

/// The `dhcp` counter of a line of frames.
fn dhcp_count(line: &str) -> Option<u64> {
    frames(line).map(|f| f.dhcp)
}

/// The time of the first CONNECT on the loopback after the start, in
/// microseconds, from the line of the role `b`.
fn loopback_connect(lines: &[String]) -> Option<u64> {
    lines.iter().find_map(|l| {
        l.strip_prefix("net-probe: loopback connect ")?
            .strip_suffix(" us")?
            .parse()
            .ok()
    })
}

/// The most the first CONNECT on the loopback may take by the guest's clock:
/// the ARP through the loop must not wait for a timer (spec 6).
pub const CONNECT_MAX_US: u64 = 200_000;
/// The longest chain the table of destinations may walk in a run.
const DEMUX_PROBE_MAX: u64 = netd::demux::PROBE_LIMIT as u64;

/// Judges the lines of a run: the device started twice, the address came
/// each time as `mode` says, the client printed every line once and did
/// not fail, and the service was killed once and restarted by init.
pub fn verdict(lines: &[String], mode: Mode, roles: Roles) -> Result<(), String> {
    let count = |marker: &str| lines.iter().filter(|l| l.as_str() == marker).count();
    if let Some(failed) = lines.iter().find(|l| l.starts_with("net-probe: failed")) {
        return Err(failed.clone());
    }
    let (addressed, other) = match mode {
        Mode::Dhcp => (LEASE, "net: static"),
        Mode::Static => (STATIC, "net: lease"),
    };
    let sockets = roles.places.map(|n| format!("net-probe: sockets {n} ok"));
    let mut once = vec![
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
    if roles.bind {
        once.push((BIND, 1));
    }
    if roles.full_batch {
        once.push((FULL_BATCH, 1));
    }
    if roles.all_groups {
        once.push((ALL_GROUPS, 1));
    }
    if roles.wakes {
        once.push((WAKES, 1));
    }
    if roles.idle {
        once.push((IDLE, 1));
    }
    if roles.listeners {
        once.push((LISTENERS, 1));
    }
    if roles.wire && !lines.iter().any(|l| l.starts_with(WIRE_PREFIX)) {
        return Err(format!("no line {WIRE_PREFIX:?}"));
    }
    if roles.timers && !lines.iter().any(|l| l.starts_with(TIMERS_PREFIX)) {
        return Err(format!("no line {TIMERS_PREFIX:?}"));
    }
    if let Some(sockets) = &sockets {
        once.push((sockets.as_str(), 1));
    }
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
    let counters: Vec<Frames> = lines.iter().filter_map(|l| frames(l)).collect();
    // A frame of 127.0.0.0/8 on the wire is a fault of the stack; a queue of
    // `listen` that `accept` could not refill is a fault of the table.
    if let Some(f) = counters
        .iter()
        .find(|f| f.martian != 0 || f.listen_short != 0 || f.bad_sum != 0 || f.dropped != 0)
    {
        return Err(format!("the service counted {f:?}"));
    }
    if let Some(f) = counters.iter().find(|f| f.demux_probe > DEMUX_PROBE_MAX) {
        return Err(format!(
            "the table of destinations walked {} places, {DEMUX_PROBE_MAX} at most: {f:?}",
            f.demux_probe
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

/// The longest step of each kind in `lines`: (kind, ticks, detail). The
/// service starts again in the run (the role `k` kills it), and each start
/// counts from nothing, so the longest is taken over all the lines of a
/// kind.
pub fn longest_over_starts(lines: &[String]) -> Vec<(usize, u64, u64)> {
    let mut out: Vec<(usize, u64, u64)> = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        let [
            "service",
            "step:",
            NET_TAG,
            "kind",
            kind,
            ticks,
            "ticks",
            "detail",
            detail,
        ] = words.as_slice()
        else {
            continue;
        };
        let (Ok(kind), Ok(ticks), Ok(detail)) = (kind.parse(), ticks.parse(), detail.parse())
        else {
            continue;
        };
        match out.iter_mut().find(|(k, ..)| *k == kind) {
            Some(row) if row.1 >= ticks => {}
            Some(row) => *row = (kind, ticks, detail),
            None => out.push((kind, ticks, detail)),
        }
    }
    out
}

/// The steps of the service: every kind came and every row stays under
/// STEP_MAX, and a CLONE (kind 19) under PORTION_MAX when the run made one.
pub fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = longest_over_starts(lines);
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
    if let Some(row) = rows.iter().find(|r| r.0 == CLONE_KIND && r.1 > PORTION_MAX) {
        return Err(format!(
            "the network service: CLONE past 0.8 of term B ({PORTION_MAX}): {row:?}"
        ));
    }
    Ok(rows)
}

/// The steps of the service under real traffic (`cargo xtask net-curl
/// steps`): the kinds the traffic makes came (the service's own steps, ACCEPT,
/// SEND, RECV, CLONE, WATCH_TAKE), and every row stays under STEP_MAX, a CLONE
/// under PORTION_MAX.
pub fn traffic_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    const KINDS: [(usize, &str); 6] = [
        (65, "the own steps"),
        (6, "Accept"),
        (8, "Send"),
        (10, "Recv"),
        (19, "Clone"),
        (28, "WatchTake"),
    ];
    let rows = longest_over_starts(lines);
    for (kind, name) in KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the network service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > STEP_MAX) {
        return Err(format!(
            "the network service: a step past 0.9 of term B ({STEP_MAX}): {row:?}"
        ));
    }
    if let Some(row) = rows.iter().find(|r| r.0 == CLONE_KIND && r.1 > PORTION_MAX) {
        return Err(format!(
            "the network service: CLONE past 0.8 of term B ({PORTION_MAX}): {row:?}"
        ));
    }
    Ok(rows)
}

/// A run on `machine` of the image `name` with `programs`: the machine
/// starts, and the lines are read until the client ends. The time to the
/// first address is the host's wall time. With `two` the machine has the
/// second network device too (`qemu::net_two`) and the lines of both are
/// judged.
fn run(
    machine: &qemu::Machine,
    name: &'static str,
    programs: &'static [ImageProgram],
    mode: Mode,
    roles: Roles,
    two: bool,
) -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    let forward = if two { Some(free_tcp_port()?) } else { None };
    if two {
        cmd.args(qemu::net_two(forward));
    }
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
        .and_then(|took| {
            // The client ends with any code: a failure is read from its lines.
            run.expect_line(ENDED, |l| l.starts_with(ENDED_PREFIX), within)
                .map(|_| took)
        });
    // The second device sends no reset: a connection to its port 81 through
    // the forward stays open (the stack never sees the SYN).
    let silent = match (result.as_ref(), forward) {
        (Ok(_), Some(port)) => silent_port(port),
        _ => Ok(()),
    };
    let outcome = run.stop();
    let took = result.map_err(|e| format!("net-probe on {} ({name}): {e}", machine.name))?;
    silent.map_err(|e| format!("net-probe on {} ({name}): {e}", machine.name))?;
    verdict(&outcome.lines, mode, roles)
        .map_err(|e| format!("net-probe on {} ({name}): {e}", machine.name))?;
    if two {
        two_verdict(&outcome.lines)
            .map_err(|e| format!("net-probe on {} ({name}): {e}", machine.name))?;
    }
    if let Some(us) = loopback_connect(&outcome.lines)
        && us > CONNECT_MAX_US
    {
        return Err(format!(
            "net-probe on {} ({name}): the first CONNECT on the loopback took {us} us, {CONNECT_MAX_US} at most",
            machine.name
        ));
    }
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

/// One run under -icount of an image of `programs`: the lines it printed.
fn steps_lines(
    machine: &qemu::Machine,
    name: &'static str,
    programs: &'static [ImageProgram],
    roles: Roles,
    strict: bool,
) -> Result<Vec<String>, String> {
    steps_lines_with(machine, name, programs, roles, strict, false)
}

/// `steps_lines`, with the second network device when `two`.
fn steps_lines_with(
    machine: &qemu::Machine,
    name: &'static str,
    programs: &'static [ImageProgram],
    roles: Roles,
    strict: bool,
    two: bool,
) -> Result<Vec<String>, String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    if two {
        cmd.args(qemu::net_two(None));
    }
    cmd.args(qemu::ICOUNT);
    // One CPU. The service alone on CPU 0 of two (the feature `net-alone` of
    // init, `-smp 2`) was tried: under -icount the counter is the instructions
    // of all the CPUs, so a step of the service holds the slices of the other
    // CPU and the longest step comes out in millions of ticks.
    let output = run_until(
        cmd,
        crate::BOOT_TIMEOUT * 20,
        Some(ENDED_PREFIX),
        &kernel.elf,
    )?;
    if strict {
        verdict(&output.lines, Mode::Dhcp, roles)
            .map_err(|e| format!("net-probe under -icount on {} ({name}): {e}", machine.name))?;
        if two {
            two_verdict(&output.lines).map_err(|e| {
                format!("net-probe under -icount on {} ({name}): {e}", machine.name)
            })?;
        }
        crate::check_waits(&output.lines, &[NET_TAG], "net-probe")?;
    }
    Ok(output.lines)
}

/// The longest steps of such a run.
fn steps_run(
    machine: &qemu::Machine,
    name: &'static str,
    programs: &'static [ImageProgram],
    roles: Roles,
    strict: bool,
) -> Result<Vec<(usize, u64, u64)>, String> {
    Ok(longest_over_starts(&steps_lines(
        machine, name, programs, roles, strict,
    )?))
}

fn print_rows(machine: &qemu::Machine, what: &str, rows: &[(usize, u64, u64)]) {
    let text: Vec<_> = rows
        .iter()
        .map(|(kind, ticks, detail)| format!("kind {kind} {ticks} (detail {detail})"))
        .collect();
    println!(
        "net-probe on {}: the longest steps under -icount, {what}, ticks (0.9 of term B {STEP_MAX}): {}",
        machine.name,
        text.join(", ")
    );
}

/// The check of `steps_verdict` over rows already read.
fn steps_verdict_rows(rows: &[(usize, u64, u64)]) -> Result<Vec<(usize, u64, u64)>, String> {
    let lines: Vec<String> = rows
        .iter()
        .map(|(kind, ticks, detail)| {
            format!("service step: {NET_TAG} kind {kind} {ticks} ticks detail {detail}")
        })
        .collect();
    steps_verdict(&lines)
}

/// The longest step of kind `kind` in `rows`: ticks and detail.
fn step_of(rows: &[(usize, u64, u64)], kind: usize) -> Option<(u64, u64)> {
    rows.iter().find(|r| r.0 == kind).map(|r| (r.1, r.2))
}

/// The longest steps of one run of the acceptance, by its name.
type Rows = (&'static str, Vec<(usize, u64, u64)>);

/// The runs under -icount that the acceptance reads: the default roles of
/// the ci run (the registry and the table filled), `s` at 8 places for the
/// evenness, and the roles `f`, `a` and `w` that bring the worst steps.
/// `netd` is the features of the service on top of the counting of steps
/// (the batch and the groups per step).
fn acceptance_runs(netd: &[&'static str]) -> Vec<(&'static str, &'static [ImageProgram], Roles)> {
    vec![
        ("s256", measured_programs(None, netd), Roles::LIMIT),
        (
            "s8",
            measured_programs(Some("net-sockets-8"), netd),
            Roles::places(8),
        ),
        (
            "f",
            measured_programs(Some("net-full-batch"), netd),
            Roles::FULL_BATCH,
        ),
        (
            "a",
            measured_programs(Some("net-all-groups"), netd),
            Roles::ALL_GROUPS,
        ),
        (
            "w",
            measured_programs(Some("net-wakes"), netd),
            Roles::WAKES,
        ),
        ("i", measured_programs(Some("net-idle"), netd), Roles::IDLE),
        (
            "l",
            measured_programs(Some("net-listen"), netd),
            Roles::LISTENERS,
        ),
        (
            "r",
            measured_programs(Some("net-timers"), netd),
            Roles::TIMERS,
        ),
        ("u", measured_programs(Some("net-wire"), netd), Roles::WIRE),
    ]
}

/// The acceptance of the step (reports/2026-11-04-net-p1a): every row of
/// every run within the bound, the longest own step at 256 places within
/// FLATNESS of that at 8, and the counters. Prints the rows and returns
/// them by run.
fn acceptance(
    machine: &qemu::Machine,
    tag: &str,
    netd: &[&'static str],
    strict: bool,
) -> Result<Vec<Rows>, String> {
    let mut all = Vec::new();
    for (what, programs, roles) in acceptance_runs(netd) {
        let rows = steps_run(
            machine,
            measured_name(&format!("{tag}-{what}")),
            programs,
            roles,
            strict,
        )?;
        let rows = if strict {
            steps_verdict_rows(&rows).map_err(|e| format!("run {what}: {e}"))?
        } else {
            rows
        };
        print_rows(machine, &format!("{tag} run {what}"), &rows);
        all.push((what, rows));
    }
    let own = |what: &str| {
        all.iter()
            .find(|(w, _)| *w == what)
            .and_then(|(_, rows)| step_of(rows, OWN_KIND))
            .map(|(ticks, _)| ticks)
            .unwrap_or(0)
    };
    if strict && !netd::choose::flat(own("s8"), own("s256")) {
        return Err(format!(
            "the longest step is not even: {} ticks at 256 places, {} at 8 (the spread {} at most)",
            own("s256"),
            own("s8"),
            netd::choose::FLATNESS
        ));
    }
    println!(
        "net-probe: the longest own step: s8 {}, s256 {}, f {}, a {}, w {}, i {}, l {}, r {}, u {} (bound {STEP_MAX}, evenness {} at most)",
        own("s8"),
        own("s256"),
        own("f"),
        own("a"),
        own("w"),
        own("i"),
        own("l"),
        own("r"),
        own("u"),
        netd::choose::FLATNESS
    );
    Ok(all)
}

/// The run under -icount for the ci: the acceptance at the batch and the
/// groups per step the code has.
fn steps(machine: &qemu::Machine) -> Result<(), String> {
    acceptance(machine, "ci", &[], true).map(|_| ())
}

/// The 90th percentiles of the parts of the steps from the lines
/// `net: split <part> n <samples> p50 <..> p90 <..> max <..>`: for each part
/// the line with the most samples, which is the service that ran the load (the
/// one the role `k` restarts has few).
fn split_parts(lines: &[String]) -> Option<netd::choose::Parts> {
    let p90 = |part: &str| -> Option<u64> {
        lines
            .iter()
            .filter_map(|l| {
                let w: Vec<&str> = l.split_whitespace().collect();
                let [
                    "net:",
                    "split",
                    name,
                    "n",
                    n,
                    "p50",
                    _,
                    "p90",
                    p90,
                    "max",
                    _,
                ] = w.as_slice()
                else {
                    return None;
                };
                (*name == part).then_some((n.parse::<u64>().ok()?, p90.parse::<u64>().ok()?))
            })
            .max_by_key(|&(n, _)| n)
            .map(|(_, p90)| p90)
    };
    Some(netd::choose::Parts {
        fixed_rx: p90("fixed_rx")?,
        fixed_tx: p90("fixed_tx")?,
        frame_rx: p90("frame_rx")?,
        frame_tx: p90("frame_tx")?,
        group: p90("group")?,
    })
}

/// `cargo xtask net-probe split`: the breakdown of the steps alone, for the
/// table of an intermediate state of the code.
fn split_only(machine: &qemu::Machine) -> Result<(), String> {
    let lines = steps_lines(
        machine,
        measured_name("split"),
        measured_programs(Some("net-sockets-256"), &["split"]),
        Roles::places(SOCKETS_LIMIT),
        false,
    )?;
    let parts = split_parts(&lines).ok_or("no breakdown of the steps in the lines")?;
    println!("net-probe: the parts of the steps, p90 ticks: {parts:?}");
    println!(
        "net-probe: a step of receiving of one frame {}, a step of sending of one group and one frame {} (budget {})",
        parts.receiving(1),
        parts.sending(1, 1),
        netd::choose::BUDGET
    );
    print_rows(machine, "split image", &longest_over_starts(&lines));
    Ok(())
}

/// `cargo xtask net-probe steps`: the measurement that chooses the frames of
/// a step and the groups the pass of sending visits (the rule is
/// `netd::choose`): the image with the breakdown of the step (feature
/// `split`) runs `s` at 256 places, the rule reads the 90th percentiles of its
/// parts, and the acceptance runs at the choice. The choice is written in
/// `netd::ring`; the command fails when the code has other numbers.
pub fn series(machine: &qemu::Machine) -> Result<(), String> {
    use netd::choose;
    let split_programs = measured_programs(Some("net-sockets-256"), &["split"]);
    let lines = steps_lines(
        machine,
        measured_name("split"),
        split_programs,
        Roles::places(SOCKETS_LIMIT),
        false,
    )?;
    for line in lines
        .iter()
        .filter(|l| l.starts_with("net: split "))
        .take(5)
    {
        println!("net-probe on {}: {line}", machine.name);
    }
    let mut parts = split_parts(&lines).ok_or("no breakdown of the step in the lines")?;
    println!("net-probe: the parts of the step, p90 ticks: {parts:?}");
    // The frames of the loop carry no sums; the frames of the wire do. The
    // image of the role `u` sends and takes frames of 1 514 bytes, and the
    // dearer of the two prices is the price of a frame.
    let wire_lines = steps_lines(
        machine,
        measured_name("split-wire"),
        measured_programs(Some("net-wire"), &["split"]),
        Roles::WIRE,
        false,
    )?;
    let wire = split_parts(&wire_lines).ok_or("no breakdown of the wire frames in the lines")?;
    println!(
        "net-probe: the cost of a frame of the wire, p90 ticks: received {}, sent {}",
        wire.frame_rx, wire.frame_tx
    );
    parts.frame_rx = parts.frame_rx.max(wire.frame_rx);
    parts.frame_tx = parts.frame_tx.max(wire.frame_tx);
    println!("net-probe: the parts the rule reads: {parts:?}");
    let choice = match choose::choose(&parts) {
        Ok(choice) => choice,
        Err(stop) => {
            // The gate is not passed. For the expert's note: the steps of the
            // smallest choice in the acceptance runs, which nothing in the
            // code adopts.
            println!(
                "net-probe: the gate is not passed: a step of receiving of one frame {} ticks, a step of sending of one group and one frame {} (budget {})",
                stop.receiving,
                stop.sending,
                choose::BUDGET
            );
            acceptance(machine, "smallest", &choice_features(1, 1, 1), false)?;
            return Err("the gate is not passed; the stage waits for the expert".to_owned());
        }
    };
    println!(
        "net-probe: receiving {} frames, sending {} frames in {} groups (estimates {} and {} ticks, budget {})",
        choice.receive,
        choice.send,
        choice.groups,
        parts.receiving(choice.receive),
        parts.sending(choice.groups, choice.send),
        choose::BUDGET
    );
    acceptance(
        machine,
        "chosen",
        &choice_features(choice.receive, choice.groups, choice.send),
        true,
    )?;
    let in_code = (
        netd::ring::STEP_RX,
        netd::ring::EGRESS_GROUPS,
        netd::ring::STEP_TX,
    );
    if in_code != (choice.receive, choice.groups, choice.send) {
        return Err(format!(
            "the choice is {choice:?}; netd::ring has {in_code:?}"
        ));
    }
    Ok(())
}

/// The features of the service that build the choice: the frames of receiving
/// (`batch-N`), the groups per step (`egress-N`) and the frames of sending
/// (`send-N`); the chosen values are the defaults of the code.
fn choice_features(receive: usize, groups: usize, send: usize) -> Vec<&'static str> {
    let mut features = Vec::new();
    features.extend(match receive {
        16 => Some("batch-16"),
        8 => Some("batch-8"),
        4 => Some("batch-4"),
        1 => Some("batch-1"),
        _ => None,
    });
    features.extend(match groups {
        1 => Some("egress-1"),
        4 => Some("egress-4"),
        _ => None,
    });
    features.extend(match send {
        16 => Some("send-16"),
        8 => Some("send-8"),
        4 => Some("send-4"),
        2 => Some("send-2"),
        _ => None,
    });
    features
}

/// `cargo xtask net-probe [MACHINE]` and the job of `ci`: the three runs.
/// The steps run needs the emulation's own clock, so it runs on QEMU's
/// TCG only.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    run(
        machine,
        "boot-net-probe.img",
        &PROGRAMS,
        Mode::Dhcp,
        Roles::LIMIT,
        false,
    )?;
    run(
        machine,
        "boot-net-probe-static.img",
        &PROGRAMS,
        Mode::Static,
        Roles::LIMIT,
        false,
    )?;
    run(
        machine,
        "boot-net-probe-two.img",
        &TWO_PROGRAMS,
        Mode::Dhcp,
        Roles::NONE,
        true,
    )?;
    if !machine.is_hvf() {
        steps(machine)?;
    }
    Ok(())
}

/// `cargo xtask net-probe [MACHINE]`: the machine is `tcg` (the default),
/// `hvf` or the name of one of qemu::MACHINES; `steps` is the measurement.
pub fn command(args: &[String]) -> Result<(), String> {
    // `steps RECEIVE GROUPS SEND`: the acceptance runs at that choice, read
    // without judging them (for the note of the expert).
    if let [first, receive, groups, send] = args
        && first == "steps"
    {
        let number = |text: &String, what: &str| -> Result<usize, String> {
            text.parse().map_err(|_| format!("{what} is a number"))
        };
        let (receive, groups, send) = (
            number(receive, "RECEIVE")?,
            number(groups, "GROUPS")?,
            number(send, "SEND")?,
        );
        let features: &'static [&'static str] =
            Box::leak(choice_features(receive, groups, send).into_boxed_slice());
        let tag: &'static str = Box::leak(format!("r{receive}g{groups}s{send}").into_boxed_str());
        return acceptance(&qemu::VIRT, tag, features, false).map(|_| ());
    }
    // `role NAME`: one run of the acceptance (s256, s8, f, a, w, i, l or r),
    // judged; for the deliberate breakages.
    if let [first, name] = args
        && first == "role"
    {
        let (what, programs, roles) = acceptance_runs(&[])
            .into_iter()
            .find(|(what, ..)| what == name)
            .ok_or_else(|| format!("no role {name}"))?;
        let rows = steps_run(
            &qemu::VIRT,
            measured_name(&format!("role-{what}")),
            programs,
            roles,
            true,
        )?;
        let rows = steps_verdict_rows(&rows).map_err(|e| format!("run {what}: {e}"))?;
        print_rows(&qemu::VIRT, &format!("role {what}"), &rows);
        return Ok(());
    }
    // `two-steps`: the image of two devices under -icount, judged by the
    // same bound as the others.
    if args == ["two-steps"] {
        let lines = steps_lines_with(
            &qemu::VIRT,
            "boot-net-steps-two.img",
            &TWO_STEPS_PROGRAMS,
            Roles::NONE,
            true,
            true,
        )?;
        let rows = steps_verdict(&lines).map_err(|e| format!("two devices: {e}"))?;
        print_rows(&qemu::VIRT, "two devices", &rows);
        return Ok(());
    }
    if args == ["split"] {
        return split_only(&qemu::VIRT);
    }
    let (steps, args) = match args.split_first() {
        Some((first, rest)) if first == "steps" => (true, rest),
        _ => (false, args),
    };
    let machine = match args {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask net-probe [steps] [hvf|tcg|MACHINE]".to_owned()),
    };
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("net-probe on {}: {why}", machine.name))?;
    }
    if steps {
        if machine.is_hvf() {
            return Err(
                "the measurement of the steps needs the emulation's clock (tcg)".to_owned(),
            );
        }
        return series(machine);
    }
    probe(machine)?;
    if machine.is_hvf() {
        rates(machine)?;
    }
    Ok(())
}

/// The rates of the loopback through the service on the machine (role `e`).
fn rates(machine: &qemu::Machine) -> Result<(), String> {
    static ECHO: [ImageProgram; 6] = [
        (
            "init",
            "init",
            INIT_STACK_SIZE,
            &["table-net-probe", "net-echo"],
        ),
        RAM,
        RNG,
        ENTROPY,
        ("netd", "netd", NETD_STACK_SIZE, &["probe"]),
        ("net-probe", "net-probe", PROBE_STACK_SIZE, &[]),
    ];
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-net-echo.img", &ECHO, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    let mut run = Run::start(cmd, Input::Null)?;
    let within = Duration::from_secs(90);
    let result = run.expect_line(ENDED, |l| l.starts_with(ENDED_PREFIX), within);
    let outcome = run.stop();
    result.map_err(|e| format!("net-probe echo on {}: {e}", machine.name))?;
    let echo: Vec<&String> = outcome
        .lines
        .iter()
        .filter(|l| l.starts_with("net-probe: echo "))
        .collect();
    if echo.len() != 2 {
        return Err(format!(
            "net-probe echo: {} lines of rates, 2 expected",
            echo.len()
        ));
    }
    for line in echo {
        println!("net-probe on {}: {line}", machine.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTERS: &str = "martian 0 listen_short 0 bad_sum 0 demux_probe 2";

    fn good_run(mode: Mode) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        let address = match mode {
            Mode::Dhcp => LEASE,
            Mode::Static => STATIC,
        };
        let dhcp = if mode == Mode::Dhcp { 3 } else { 0 };
        let places = SOCKETS_LIMIT;
        for round in 0..2 {
            lines.push(DEVICE_LINE.to_owned());
            lines.push(address.to_owned());
            if round == 0 {
                lines.push(CONFIG.to_owned());
                lines.push(format!("{FRAMES}12 tx 9 dhcp {dhcp} dropped 0 {COUNTERS}"));
                lines.push(PINGS.to_owned());
                lines.push(BIND.to_owned());
                lines.push(format!("net-probe: sockets {places} ok"));
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

    fn two_run() -> Vec<String> {
        let mut lines = good_run(Mode::Dhcp);
        for _ in 0..2 {
            lines.push(DEVICE_LINE_TWO.to_owned());
            lines.push(LEASE_TWO.to_owned());
            lines.push("virtio-net1: first interrupt".to_owned());
            lines.push("virtio-net: first interrupt".to_owned());
        }
        lines
    }

    #[test]
    fn a_run_of_two_devices_needs_the_lines_of_both() {
        assert_eq!(two_verdict(&two_run()), Ok(()));
        for marker in [
            DEVICE_LINE_TWO,
            LEASE_TWO,
            "virtio-net1: first interrupt",
            "virtio-net: first interrupt",
        ] {
            let mut lines = two_run();
            let at = lines.iter().position(|l| l == marker).unwrap();
            lines.remove(at);
            assert!(
                two_verdict(&lines).unwrap_err().contains(marker),
                "{marker}"
            );
        }
        // The second user network's lease is not the first's.
        assert!(two_verdict(&good_run(Mode::Dhcp)).is_err());
    }

    #[test]
    fn the_second_device_sits_on_the_transport_of_init_s_table() {
        let args = qemu::net_two(Some(4321)).join(" ");
        assert!(args.contains("hostfwd=tcp:127.0.0.1:4321-10.0.3.15:81"));
        assert!(!qemu::net_two(None).join(" ").contains("hostfwd"));
        assert!(args.contains("bus=virtio-mmio-bus.14"));
        assert!(args.contains(&format!("mac={}", qemu::NET_MAC_TWO)));
        assert!(args.contains("net=10.0.3.0/24"));
        assert_eq!(TWO_PROGRAMS[0].3, &["table-net-probe-two"]);
        assert_eq!(TWO_STEPS_PROGRAMS[4].3, &["probe", "steps"]);
    }

    #[test]
    fn a_run_with_every_line_passes() {
        assert_eq!(
            verdict(&good_run(Mode::Dhcp), Mode::Dhcp, Roles::LIMIT),
            Ok(())
        );
        assert_eq!(
            verdict(&good_run(Mode::Static), Mode::Static, Roles::LIMIT),
            Ok(())
        );
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
            BIND,
        ] {
            let mut lines = good_run(Mode::Dhcp);
            let at = lines.iter().rposition(|l| l == marker).unwrap();
            lines.remove(at);
            assert!(
                verdict(&lines, Mode::Dhcp, Roles::LIMIT)
                    .unwrap_err()
                    .contains(marker),
                "{marker}"
            );
        }
    }

    #[test]
    fn a_failure_of_the_client_is_the_verdict() {
        let mut lines = good_run(Mode::Dhcp);
        lines.push("net-probe: failed: a PING of the gateway failed".to_owned());
        assert!(
            verdict(&lines, Mode::Dhcp, Roles::LIMIT)
                .unwrap_err()
                .contains("PING")
        );
    }

    #[test]
    fn dhcp_must_send_frames_and_a_static_run_none() {
        let mut lines = good_run(Mode::Dhcp);
        for l in lines.iter_mut().filter(|l| l.starts_with(FRAMES)) {
            *l = format!("{FRAMES}12 tx 9 dhcp 1 dropped 0 {COUNTERS}");
        }
        assert!(
            verdict(&lines, Mode::Dhcp, Roles::LIMIT)
                .unwrap_err()
                .contains("DHCP")
        );
        // The line of the other way to get an address is a fault.
        let mut lines = good_run(Mode::Static);
        lines.push(LEASE.to_owned());
        assert!(verdict(&lines, Mode::Static, Roles::LIMIT).is_err());
        let mut lines = good_run(Mode::Static);
        for l in lines.iter_mut().filter(|l| l.starts_with(FRAMES)) {
            *l = format!("{FRAMES}12 tx 9 dhcp 2 dropped 0 {COUNTERS}");
        }
        assert!(
            verdict(&lines, Mode::Static, Roles::LIMIT)
                .unwrap_err()
                .contains("static")
        );
    }

    #[test]
    fn a_bad_sum_or_a_long_chain_is_a_fault() {
        let mut lines = good_run(Mode::Dhcp);
        let at = lines.iter().position(|l| l.starts_with(FRAMES)).unwrap();
        lines[at] = format!(
            "{FRAMES}12 tx 9 dhcp 3 dropped 0 martian 0 listen_short 0 bad_sum 1 demux_probe 2"
        );
        assert!(
            verdict(&lines, Mode::Dhcp, Roles::LIMIT)
                .unwrap_err()
                .contains("counted")
        );
        lines[at] = format!(
            "{FRAMES}12 tx 9 dhcp 3 dropped 0 martian 0 listen_short 0 bad_sum 0 demux_probe 9"
        );
        assert!(
            verdict(&lines, Mode::Dhcp, Roles::LIMIT)
                .unwrap_err()
                .contains("walked")
        );
    }

    #[test]
    fn the_roles_f_a_and_w_name_their_lines() {
        for (roles, line) in [
            (Roles::FULL_BATCH, FULL_BATCH),
            (Roles::ALL_GROUPS, ALL_GROUPS),
            (Roles::WAKES, WAKES),
        ] {
            let mut lines = good_run(Mode::Dhcp);
            lines.retain(|l| !l.starts_with("net-probe: sockets") && l != BIND);
            assert!(
                verdict(&lines, Mode::Dhcp, roles)
                    .unwrap_err()
                    .contains(line)
            );
            lines.push(line.to_owned());
            assert_eq!(verdict(&lines, Mode::Dhcp, roles), Ok(()));
        }
    }

    #[test]
    fn a_dropped_frame_of_the_loop_is_a_fault() {
        let mut lines = good_run(Mode::Dhcp);
        let at = lines.iter().position(|l| l.starts_with(FRAMES)).unwrap();
        lines[at] = format!(
            "{FRAMES}12 tx 9 dhcp 3 dropped 1 martian 0 listen_short 0 bad_sum 0 demux_probe 2"
        );
        assert!(
            verdict(&lines, Mode::Dhcp, Roles::LIMIT)
                .unwrap_err()
                .contains("counted")
        );
    }

    #[test]
    fn the_roles_i_l_and_r_name_their_lines() {
        for (roles, line) in [
            (Roles::IDLE, IDLE),
            (Roles::LISTENERS, LISTENERS),
            (
                Roles::TIMERS,
                "net-probe: timers ok (a segment sent again after 1004 ms)",
            ),
        ] {
            let mut lines = good_run(Mode::Dhcp);
            lines.retain(|l| !l.starts_with("net-probe: sockets") && l != BIND);
            assert!(verdict(&lines, Mode::Dhcp, roles).is_err());
            lines.push(line.to_owned());
            assert_eq!(verdict(&lines, Mode::Dhcp, roles), Ok(()));
        }
    }

    #[test]
    fn the_time_of_the_first_connect_is_read() {
        let lines = vec!["net-probe: loopback connect 1523 us".to_owned()];
        assert_eq!(loopback_connect(&lines), Some(1523));
        assert_eq!(loopback_connect(&[]), None);
    }

    #[test]
    fn the_parts_of_the_step_are_read_as_the_largest_p90_of_the_run() {
        let line =
            |part: &str, p90: u64| format!("net: split {part} n 100 p50 100 p90 {p90} max 9999");
        let mut lines: Vec<String> = [
            ("fixed_rx", 5000),
            ("fixed_tx", 6000),
            ("frame_rx", 1800),
            ("frame_tx", 1500),
            ("group", 1300),
        ]
        .iter()
        .map(|(n, v)| line(n, *v))
        .collect();
        // The restarted service has fewer samples: its line does not count.
        lines.push("net: split fixed_rx n 3 p50 1 p90 9000 max 9999".to_owned());
        lines.push(line("fixed_rx", 5000));
        let parts = split_parts(&lines).unwrap();
        assert_eq!(parts.fixed_rx, 5000);
        assert_eq!(parts.fixed_tx, 6000);
        assert_eq!(parts.group, 1300);
        assert!(netd::choose::choose(&parts).is_ok());
        assert_eq!(split_parts(&lines[..3]), None, "a part is missing");
    }

    #[test]
    fn the_service_must_restart_once() {
        let mut lines = good_run(Mode::Dhcp);
        lines.retain(|l| !l.starts_with(SERVICE_ENDED));
        assert!(
            verdict(&lines, Mode::Dhcp, Roles::LIMIT)
                .unwrap_err()
                .contains("restart")
        );
    }

    #[test]
    fn the_lines_of_numbers_are_read() {
        assert_eq!(
            rtts("net-probe: ping rtt max 900 us median 300 us"),
            Some((900, 300))
        );
        assert_eq!(rtts("net-probe: ping rtt max x us median 300 us"), None);
        assert_eq!(
            dhcp_count(
                "net: frames rx 12 tx 9 dhcp 3 dropped 1 martian 0 listen_short 0 bad_sum 0 demux_probe 1"
            ),
            Some(3)
        );
        assert_eq!(dhcp_count("net: frames rx 12 tx 9 dropped 1"), None);
    }

    fn step(kind: usize, ticks: u64) -> String {
        format!("service step: {NET_TAG} kind {kind} {ticks} ticks detail 0")
    }

    #[test]
    fn steps_under_the_bound_pass_and_past_it_fail() {
        // A CLONE past a portion fails, the other kinds past the bound too.
        let clone: Vec<String> = [(21, 3000), (62, 4000), (65, 9000), (19, PORTION_MAX + 1)]
            .iter()
            .map(|&(k, t)| step(k, t))
            .collect();
        assert!(steps_verdict(&clone).unwrap_err().contains("CLONE"));
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

    /// The probe is a client of the protocol alone: the graph of its build
    /// for the guest has neither the package of the service nor the stack
    /// and the driver the service builds on.
    #[test]
    fn the_probe_does_not_build_the_service() {
        let output = std::process::Command::new(env!("CARGO"))
            .args([
                "tree",
                "-p",
                "net-probe",
                "--target",
                "aarch64-unknown-none",
            ])
            .current_dir(crate::root())
            .output()
            .expect("cargo tree");
        assert!(output.status.success(), "{output:?}");
        let tree = String::from_utf8_lossy(&output.stdout);
        for package in ["netd ", "smoltcp ", "virtio-drivers ", "posix-fs "] {
            assert!(
                !tree.lines().any(|l| l.contains(package)),
                "the probe's graph holds {package}"
            );
        }
        assert!(tree.contains("proto-net "));
    }

    /// The images run the role `s` at the limit of the sockets, which the
    /// table of init spells out.
    #[test]
    fn the_roles_of_the_images_name_the_sockets_limit() {
        let table = std::fs::read_to_string(crate::root().join("services/init/src/table/net.rs"))
            .expect("the table of the network service");
        assert!(
            table.contains(&format!("b\"cbs{SOCKETS_LIMIT}k\"")),
            "the roles of the probe name another limit than {SOCKETS_LIMIT}"
        );
        const { assert!(SOCKETS_LIMIT <= netd::places::SOCKETS_MAX) };
        assert_eq!(Roles::LIMIT.places, Some(SOCKETS_LIMIT));
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
