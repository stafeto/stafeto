// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The measurement of HTTP on stafeto against Linux on Apple VZ (stage P7,
//! part 2): `cargo xtask net-bench run|tables`. See `docs/net-bench.md` for
//! the method; this file holds it.
//!
//! The rows are L1 (Linux, nginx with one worker), L4 (Linux, four workers),
//! S4 (stafeto, four workers on `netd`'s shared sockets) and F1 (stafeto,
//! `nginx-fast`: one worker with the TCP/IP stack in its process on the
//! second network device, `netd` out of the data path), each on VZ with
//! four CPUs and 1 GiB, one guest at a time. The loads are W1 (900 files of
//! 10 KiB over 64 long connections), W2 (64 files of 256 KiB over 64 long
//! connections) and W3 (the files of W1, a new connection for each request).
//! The load comes from the Mac (`vegeta` at a fixed rate, `wrk` for the
//! ceiling, `iperf3` for the limit of the NAT), and so does a floor: the
//! same load on Homebrew's nginx on the loopback.
//!
//! The Mac is not quiet. Other work runs on it, so the method makes the
//! rounds short and alternates the systems between them (a Latin square),
//! corrects each latency by the lag of the load generator behind its own
//! schedule, marks the steps a noisy floor or generator or a foreign guest
//! of VZ touched and keeps them out of the decision, and records the Mac's
//! load for every step and every round. Results are numbers with the spread
//! of their repeats; the command promises no ratio.
//!
//! A run keeps one file per measured step under `results/` of its directory
//! (`target/net-bench/<time>/`), so `--resume <directory>` repeats nothing a
//! finished step holds, and `tables <directory>` writes the tables again.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::linux_guest::{self, Report};
use crate::nginx_bench::{
    self, Sample, Server, Wrk, alerts, lags, malloc_failures, parse_wrk, percentile, run_tool,
    samples_of, slug, stage_of, stop_on, vz_guests, watched,
};
use crate::nginx_probe::{self, Connection};
use crate::{BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, net_vz, qemu, vz};

// The method -----------------------------------------------------------------

/// The decision criterion: p99 of a step, corrected for the lag of the
/// generator, at most 1 ms.
const P99_LIMIT_NS: u64 = 1_000_000;
/// A step is saturated at p99 above this, below 95 % of the asked rate or
/// with errors.
const SATURATED_P99_NS: u64 = 50_000_000;
const ACHIEVED_SHARE: f64 = 0.95;
/// A floor p99 above this marks the point "floor", a p99 of lag above it
/// marks the step "generator": a failure of 1 ms on such a step decides
/// nothing.
const FLOOR_MARK_NS: u64 = 500_000;
const LAG_MARK_NS: u64 = 500_000;
/// Bisection stops when the gap is this share of the lower rate.
const SPREAD: f64 = 0.05;
/// p99.9 needs this many requests in a run (N54).
const P999_REQUESTS: u64 = 100_000;
/// A step ends the search of a ceiling by a CPU of the guest that idles
/// less than this share (per cent).
const IDLE_MARK_PCT: f64 = 5.0;
/// Confirmation: passes needed in a row, retreats allowed, the factor of a
/// retreat.
const CONFIRMS: u32 = 3;
const RETREATS: u32 = 3;
const RETREAT: f64 = 0.95;
/// Rounds a run of confirmation may take before it gives up.
const MAX_ROUNDS: u32 = 12;
/// The shares of R* of the rounds' further stages, per cent.
const SHARES: [u32; 2] = [50, 80];
/// The warm-up pass over a set before a block, its rate for the set.
const PASS_RATE: u32 = 2000;
/// Idle time after which the cache of nginx's open files may have expired
/// (`inactive=60s`): the set is passed again.
const COLD_AFTER: Duration = Duration::from_secs(45);
const GRID: [u32; 16] = [
    250, 500, 1000, 1500, 2000, 3000, 4000, 6000, 8000, 12000, 16000, 24000, 32000, 48000, 64000,
    96000,
];
/// The pairs of rows whose ratios the tables print.
const PAIRS: [(System, System); 4] = [
    (System::S4, System::L4),
    (System::F1, System::L4),
    (System::F1, System::S4),
    (System::F1, System::L1),
];
const GRID_NEW: [u32; 6] = [100, 200, 300, 500, 700, 1000];
const CONNECTIONS: u32 = 64;
/// USER_HZ of Linux and of stafeto's `/proc/stat`: a jiffy is 10 ms.
const JIFFY_US: f64 = 10_000.0;
const START_WITHIN: Duration = Duration::from_secs(30);
/// The settings of nginx in the image of F1.
const FAST_CONF: &str = "/etc/nginx/nginx-fast.conf";

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
enum Workload {
    W1,
    W2,
    W3,
}

impl Workload {
    const ALL: [Workload; 3] = [Workload::W1, Workload::W2, Workload::W3];

    fn name(self) -> &'static str {
        match self {
            Workload::W1 => "w1",
            Workload::W2 => "w2",
            Workload::W3 => "w3",
        }
    }

    fn of(name: &str) -> Option<Workload> {
        Workload::ALL.into_iter().find(|w| w.name() == name)
    }

    fn keep_alive(self) -> bool {
        self != Workload::W3
    }

    /// The paths of the set, in the order the load takes them.
    fn paths(self) -> Vec<String> {
        match self {
            Workload::W1 | Workload::W3 => (0..linux_guest::W1_FILES)
                .map(|n| format!("/s/{n:04}.bin"))
                .collect(),
            Workload::W2 => (0..linux_guest::W2_FILES)
                .map(|n| format!("/l/{n:02}.bin"))
                .collect(),
        }
    }

    fn length(self) -> usize {
        match self {
            Workload::W1 | Workload::W3 => linux_guest::W1_LEN,
            Workload::W2 => linux_guest::W2_LEN,
        }
    }

    /// The rates of the first walk, from the bottom up.
    fn grid(self) -> Vec<u32> {
        match self {
            Workload::W1 => GRID.to_vec(),
            _ => GRID_NEW
                .iter()
                .chain(GRID.iter().filter(|r| **r > 1000))
                .copied()
                .collect(),
        }
    }

    /// The connections of the criterion run of `wrk` (no error of connect).
    /// A process of either system has 1 024 descriptors: the 900 files that
    /// nginx keeps open (`open_file_cache max=1000`) leave room for 100
    /// connections of one worker and overflow with 200 (the descriptors of
    /// L1 ran out in the first trial: `accept4() failed (24)`).
    fn criterion(self) -> u32 {
        match self {
            Workload::W2 => 200,
            _ => 100,
        }
    }

    /// The rate and seconds of the pass over the set before a block (the
    /// set is passed with long connections whatever the load, so the
    /// collapse of new connections stays in its own steps).
    fn pass(self) -> (u32, u32) {
        match self {
            Workload::W2 => (500, 8),
            _ => (PASS_RATE, 10),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
enum System {
    L1,
    L4,
    S4,
    F1,
}

impl System {
    const ALL: [System; 4] = [System::L1, System::L4, System::S4, System::F1];

    fn name(self) -> &'static str {
        match self {
            System::L1 => "L1",
            System::L4 => "L4",
            System::S4 => "S4",
            System::F1 => "F1",
        }
    }

    fn of(name: &str) -> Option<System> {
        System::ALL
            .into_iter()
            .find(|s| s.name().eq_ignore_ascii_case(name))
    }

    fn linux(self) -> bool {
        !matches!(self, System::S4 | System::F1)
    }

    fn workers(self) -> usize {
        if matches!(self, System::L1 | System::F1) {
            1
        } else {
            4
        }
    }

    /// The row this one is compared with (S4 with L4, F1 with L1: a worker
    /// against a worker).
    fn peer(self) -> Option<System> {
        match self {
            System::S4 => Some(System::L4),
            System::F1 => Some(System::L1),
            _ => None,
        }
    }
}

/// The systems in the order of round `round` (1 for the first): a Latin
/// square, each system in each place once in as many rounds as there are
/// systems.
fn order<T: Copy>(rows: &[T], round: u32) -> Vec<T> {
    let n = rows.len();
    (0..n)
        .map(|i| rows[(i + round as usize - 1) % n.max(1)])
        .collect()
}

/// What a step decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Pass,
    /// p99 above 1 ms on a clean step.
    Fail,
    /// Below 95 % of the asked rate, p99 above 50 ms, errors or an alert.
    Saturated,
    /// p99 above 1 ms on a step the floor, the generator or a foreign
    /// guest touched: no decision.
    Noisy,
}

/// The CPUs of the guest over a step.
#[derive(Clone, Debug, PartialEq, Default)]
struct CpuUse {
    /// Share of idle time of each CPU, per cent; empty when the guest
    /// showed fewer lines than CPUs.
    idle: Vec<f64>,
    /// CPU time of all CPUs per answer, microseconds.
    busy_us: f64,
    known: bool,
    /// CPU time per answer of each program (the processes of one name
    /// together), microseconds, the largest first; empty when not read.
    procs: Vec<(String, f64)>,
    /// Time of interrupts and of softirqs per answer, microseconds, summed
    /// over the CPUs (columns `irq` and `softirq` of `/proc/stat`, which
    /// Linux fills only when its kernel accounts the time of interrupts;
    /// they are inside `busy_us` too).
    irq_us: f64,
    softirq_us: f64,
    /// Where the processes of one name were at the end: `name=cpu,cpu;...`
    /// (field `processor` of `/proc/<pid>/stat`).
    placed: String,
    /// The profile of the network service between the two snapshots:
    /// `name`, the change of a counter or the largest value of a maximum.
    profile: Vec<(String, f64)>,
}

/// One step: what the load gave, with the latencies counted from the
/// scheduled time of each request (lag plus latency).
#[derive(Clone, Debug, PartialEq, Default)]
struct Measured {
    rate: u32,
    seconds: u32,
    requests: usize,
    ok: usize,
    failed: usize,
    malloc: usize,
    achieved: f64,
    p50: u64,
    p99: u64,
    p999: Option<u64>,
    /// p99 as vegeta counts it, from the moment a worker took the request.
    p99_raw: u64,
    lag_p99: u64,
    lag_max: u64,
    mbps: f64,
    foreign: bool,
    /// p99 of the floor at the same rate, where it was taken.
    floor: Option<u64>,
    /// The Mac's one-minute load at the end of the step.
    load: f64,
    cpu: Option<CpuUse>,
    alert: Option<String>,
    /// Counters of the system after the step (ListenDrops, `posix-net stat`).
    counters: String,
}

impl Measured {
    fn saturated(&self) -> bool {
        self.alert.is_some()
            || self.failed > 0
            || self.malloc > 0
            || self.achieved < f64::from(self.rate) * ACHIEVED_SHARE
            || self.p99 > SATURATED_P99_NS
    }

    fn marks(&self) -> Vec<&'static str> {
        let mut marks = Vec::new();
        if self.foreign {
            marks.push("foreign guest");
        }
        if self.floor.is_some_and(|f| f > FLOOR_MARK_NS) {
            marks.push("floor");
        }
        if self.lag_p99 > LAG_MARK_NS {
            marks.push("generator");
        }
        if self.alert.is_some() {
            marks.push("alert");
        }
        if self.saturated() && self.alert.is_none() {
            marks.push("saturated");
        }
        marks
    }

    /// Whether p99 stays above 1 ms after the floor of the Mac and the lag of
    /// the generator are taken off it: p99 minus the floor's p99 above 1 ms
    /// and p99 minus the p99 of lag above 1 ms. Where no floor was taken the
    /// floor counts as zero.
    fn fails_beyond_noise(&self) -> bool {
        self.p99.saturating_sub(self.floor.unwrap_or(0)) > P99_LIMIT_NS
            && self.p99.saturating_sub(self.lag_p99) > P99_LIMIT_NS
    }

    fn verdict(&self) -> Verdict {
        if self.saturated() {
            Verdict::Saturated
        } else if self.p99 <= P99_LIMIT_NS {
            Verdict::Pass
        } else if self.foreign || !self.fails_beyond_noise() {
            Verdict::Noisy
        } else {
            Verdict::Fail
        }
    }

    /// A step that never ran: the guest or the console failed under it.
    fn broken(rate: u32, why: String) -> Measured {
        Measured {
            rate,
            alert: Some(why),
            failed: 1,
            ..Measured::default()
        }
    }
}

/// The step of `samples` asked at `rate` for files of `length` bytes. The
/// percentiles count each request from its scheduled time, `t0 + seq/rate`:
/// the stall of vegeta itself is then in the latency, as an open loop has
/// it by definition. The lag is that scheduled time against the time a
/// worker took the request.
fn measure(samples: &[Sample], rate: u32, length: usize, malloc: usize) -> Measured {
    let stage = stage_of(samples, rate, malloc, length);
    let lag = lags(samples, rate);
    let mut corrected: Vec<u64> = samples
        .iter()
        .zip(&lag)
        .map(|(s, l)| s.latency + l)
        .collect();
    corrected.sort_unstable();
    Measured {
        rate,
        requests: stage.requests,
        ok: stage.ok,
        failed: stage.failed,
        malloc,
        achieved: stage.achieved,
        p50: percentile(&corrected, 500).unwrap_or(0),
        p99: percentile(&corrected, 990).unwrap_or(0),
        p999: (samples.len() as u64 >= P999_REQUESTS)
            .then(|| percentile(&corrected, 999))
            .flatten(),
        p99_raw: stage.p99.unwrap_or(0),
        lag_p99: stage.lag_p99.unwrap_or(0),
        lag_max: stage.lag_max.unwrap_or(0),
        mbps: stage.megabytes_per_second,
        ..Measured::default()
    }
}

/// How long a confirmation run takes: `base` seconds, longer to reach
/// 100 000 requests where `cap` allows it. The flag says whether the run
/// has p99.9 (N54).
fn run_seconds(rate: u32, base: u32, cap: u32) -> (u32, bool) {
    let needed = P999_REQUESTS.div_ceil(u64::from(rate.max(1)));
    if u64::from(base) * u64::from(rate) >= P999_REQUESTS {
        (base, true)
    } else if needed <= u64::from(cap) {
        (needed as u32, true)
    } else {
        (base, false)
    }
}

/// What the search of R* found.
#[derive(Debug, Default, PartialEq)]
struct Found {
    /// The highest rate that kept p99 within 1 ms below the first
    /// saturation, to 5 %.
    rstar: Option<u32>,
    /// The lowest rate tested above R* (the next one without 1 ms).
    above: Option<u32>,
    /// Rates below R* that failed 1 ms.
    below: Vec<u32>,
    /// Where noise stopped the bisection (twice noisy at one rate).
    floor_decides: Option<u32>,
    /// Rates of the walk below R* where noise left no decision.
    noisy: Vec<u32>,
}

/// The walk up the grid and the bisection of the last gap. `probe(rate,
/// attempt)` runs a step; a noisy failure is repeated once. Twice noisy in
/// the walk leaves that rate undecided; in the bisection it stops the
/// search with "at least L, above that the floor decides".
fn search(
    grid: &[u32],
    probe: &mut dyn FnMut(u32, u32) -> Result<Verdict, String>,
) -> Result<Found, String> {
    let mut found = Found::default();
    let mut fails: Vec<u32> = Vec::new();
    let mut decide = |rate: u32| -> Result<Verdict, String> {
        let first = probe(rate, 0)?;
        if first == Verdict::Noisy {
            probe(rate, 1)
        } else {
            Ok(first)
        }
    };
    let mut best: Option<u32> = None;
    let mut noisy: Vec<u32> = Vec::new();
    for &rate in grid {
        match decide(rate)? {
            Verdict::Pass => best = Some(rate),
            Verdict::Fail => fails.push(rate),
            Verdict::Saturated => break,
            // Twice noisy at a rate of the walk: no decision there, and the
            // walk goes on (a rate above may hold what this one hid).
            Verdict::Noisy => noisy.push(rate),
        }
    }
    // The gap to bisect: from the best rate to the next point of the grid.
    let mut next = best.and_then(|b| grid.iter().copied().find(|r| *r > b));
    if let (Some(mut low), Some(mut high)) = (best, next) {
        while f64::from(high - low) / f64::from(low) > SPREAD {
            let mid = (low + high) / 2;
            match decide(mid)? {
                Verdict::Pass => low = mid,
                Verdict::Fail => {
                    fails.push(mid);
                    high = mid
                }
                Verdict::Saturated => high = mid,
                Verdict::Noisy => {
                    found.floor_decides = Some(mid);
                    break;
                }
            }
        }
        best = Some(low);
        next = Some(high);
    }
    found.rstar = best;
    found.noisy = noisy
        .into_iter()
        .filter(|n| best.is_none_or(|b| *n < b))
        .collect();
    found.above = next;
    fails.sort_unstable();
    fails.dedup();
    found.below = fails
        .into_iter()
        .filter(|f| best.is_some_and(|b| *f < b))
        .collect();
    Ok(found)
}

/// The confirmation of R*: three passes in a row at one rate; a failure
/// steps the rate back by 5 % and starts the count again, at most three
/// times.
#[derive(Clone, Debug, PartialEq)]
struct Confirm {
    rstar: u32,
    passes: u32,
    retreats: u32,
    unproven: bool,
}

impl Confirm {
    fn new(rstar: u32) -> Confirm {
        Confirm {
            rstar,
            passes: 0,
            retreats: 0,
            unproven: false,
        }
    }

    fn done(&self) -> bool {
        self.passes >= CONFIRMS || self.unproven
    }

    fn step(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::Pass => self.passes += 1,
            // All three runs must give p99 within 1 ms: a run that fails
            // under noise does not count as a pass.
            Verdict::Fail | Verdict::Noisy | Verdict::Saturated => {
                self.passes = 0;
                if self.retreats >= RETREATS {
                    self.unproven = true;
                } else {
                    self.retreats += 1;
                    self.rstar = (f64::from(self.rstar) * RETREAT).floor() as u32;
                }
            }
        }
    }
}

// The guest's own numbers -------------------------------------------------------------

/// One CPU's line of `/proc/stat`: busy and idle jiffies. Linux has
/// `idle` and `iowait` as idle time; everything else counts as busy.
fn parse_stat(lines: &[String]) -> Vec<(u64, u64)> {
    let mut cpus: Vec<(usize, (u64, u64))> = Vec::new();
    for line in lines {
        let mut words = line.split_whitespace();
        let Some(name) = words.next().and_then(|w| w.strip_prefix("cpu")) else {
            continue;
        };
        let Ok(n) = name.parse::<usize>() else {
            continue;
        };
        let fields: Vec<u64> = words.map_while(|w| w.parse().ok()).collect();
        let idle: u64 = fields.iter().skip(3).take(2).sum();
        let all: u64 = fields.iter().take(8).sum();
        cpus.push((n, (all.saturating_sub(idle), idle)));
    }
    cpus.sort_by_key(|c| c.0);
    cpus.into_iter().map(|c| c.1).collect()
}

/// One process of `/proc/<pid>/stat`: its number, its name, its user and
/// system time together (jiffies) and the CPU it last ran on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Proc {
    pid: u64,
    name: String,
    jiffies: u64,
    cpu: u64,
}

/// The processes from the lines of `/proc/<pid>/stat`. The name is the text
/// between the first `(` and the last `)`, so that a name with spaces or
/// brackets stays whole; lines that are no stat line are skipped.
fn parse_proc_times(lines: &[String]) -> Vec<Proc> {
    let mut out = Vec::new();
    for line in lines {
        let (Some(open), Some(close)) = (line.find('('), line.rfind(')')) else {
            continue;
        };
        let Ok(pid) = line[..open].trim().parse::<u64>() else {
            continue;
        };
        // After the name: state ppid pgrp session tty tpgid flags minflt
        // cminflt majflt cmajflt utime stime (indexes 11 and 12), and field
        // 39, `processor` (index 36).
        let fields: Vec<&str> = line[close + 1..].split_whitespace().collect();
        let time = |i: usize| fields.get(i).and_then(|f| f.parse::<u64>().ok());
        if let (Some(user), Some(system)) = (time(11), time(12)) {
            out.push(Proc {
                pid,
                name: line[open + 1..close].to_owned(),
                jiffies: user + system,
                cpu: time(36).unwrap_or(0),
            });
        }
    }
    out
}

/// The CPU time per answer of each program between two readings of the
/// processes' times, microseconds, the largest first. A process that began
/// between them counts from zero; one that ended is not in the second reading
/// and its time is lost. On stafeto the table lists the processes the process
/// service started for the shell and what they started: the services of the
/// image (`netd`, the file service) are not in it.
fn proc_use(before: &[Proc], after: &[Proc], answers: usize) -> Vec<(String, f64)> {
    if answers == 0 {
        return Vec::new();
    }
    let mut by_name: Vec<(String, f64)> = Vec::new();
    for p in after {
        let was = before
            .iter()
            .find(|b| b.pid == p.pid && b.name == p.name)
            .map_or(0, |b| b.jiffies);
        let us = p.jiffies.saturating_sub(was) as f64 * JIFFY_US / answers as f64;
        match by_name.iter_mut().find(|(n, _)| *n == p.name) {
            Some(entry) => entry.1 += us,
            None => by_name.push((p.name.clone(), us)),
        }
    }
    by_name.sort_by(|a, b| b.1.total_cmp(&a.1));
    by_name
}

/// Where the processes of each name are: `name=cpu,cpu;...`, the CPUs in the
/// order of the processes.
fn placed_text(procs: &[Proc]) -> String {
    let mut by_name: Vec<(String, Vec<u64>)> = Vec::new();
    for p in procs {
        match by_name.iter_mut().find(|(n, _)| *n == p.name) {
            Some(entry) => entry.1.push(p.cpu),
            None => by_name.push((p.name.clone(), vec![p.cpu])),
        }
    }
    by_name
        .iter()
        .map(|(n, cpus)| {
            let cpus: Vec<String> = cpus.iter().map(u64::to_string).collect();
            format!("{n}={}", cpus.join(","))
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// The snapshot of the network service's profile, the records `net: prof
/// <id> <name> <value> ...` of the highest `<id>` that has its last counter
/// (`call_max`); None while it is not whole.
fn parse_profile(lines: &[String]) -> Option<(u64, Vec<(String, u64)>)> {
    let mut best: Option<u64> = None;
    for line in lines {
        let mut words = line.split_whitespace();
        if (words.next(), words.next()) != (Some("net:"), Some("prof")) {
            continue;
        }
        if let Some(id) = words.next().and_then(|w| w.parse::<u64>().ok())
            && line.contains(" call_max ")
        {
            best = best.max(Some(id));
        }
    }
    let id = best?;
    let mut pairs = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() < 3 || words[..2] != ["net:", "prof"] || words[2].parse() != Ok(id) {
            continue;
        }
        for pair in words[3..].chunks(2) {
            if let [name, value] = pair
                && let Ok(value) = value.parse()
            {
                pairs.push(((*name).to_owned(), value));
            }
        }
    }
    Some((id, pairs))
}

/// The profile of a run: the change of every counter between two snapshots
/// and the values of the maxima (names ending in `_max`) of the second.
fn profile_change(before: &[(String, u64)], after: &[(String, u64)]) -> Vec<(String, f64)> {
    after
        .iter()
        .map(|(name, now)| {
            let was = before
                .iter()
                .find(|(n, _)| n == name)
                .map_or(0, |(_, v)| *v);
            let value = if name.ends_with("_max") {
                *now
            } else {
                now.saturating_sub(was)
            };
            (name.clone(), value as f64)
        })
        .collect()
}

/// `name=microseconds` pairs joined by `;`, and back.
fn procs_text(procs: &[(String, f64)]) -> String {
    procs
        .iter()
        .map(|(n, us)| format!("{n}={us:.2}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn procs_of(text: &str) -> Vec<(String, f64)> {
    text.split(';')
        .filter_map(|p| {
            let (name, us) = p.rsplit_once('=')?;
            Some((name.to_owned(), us.parse().ok()?))
        })
        .collect()
}

/// The time of interrupts and of softirqs (columns 6 and 7 of the `cpu`
/// lines, jiffies), summed over the CPUs.
fn parse_irq(lines: &[String]) -> (u64, u64) {
    let (mut irq, mut soft) = (0, 0);
    for line in lines {
        let mut words = line.split_whitespace();
        let Some(name) = words.next().and_then(|w| w.strip_prefix("cpu")) else {
            continue;
        };
        if name.parse::<usize>().is_err() {
            continue;
        }
        let fields: Vec<u64> = words.map_while(|w| w.parse().ok()).collect();
        irq += fields.get(5).copied().unwrap_or(0);
        soft += fields.get(6).copied().unwrap_or(0);
    }
    (irq, soft)
}

/// The use of the CPUs between two readings of `/proc/stat`, for
/// `answers` answers. A reading with fewer lines than the guest has CPUs
/// leaves the use unknown (a layer that prints one `cpu0` line for all).
fn cpu_use(before: &[(u64, u64)], after: &[(u64, u64)], cpus: usize, answers: usize) -> CpuUse {
    if before.len() != cpus || after.len() != cpus {
        return CpuUse::default();
    }
    let mut busy = 0.0;
    let mut idle = Vec::new();
    for (b, a) in before.iter().zip(after) {
        let (db, di) = (a.0.saturating_sub(b.0), a.1.saturating_sub(b.1));
        busy += db as f64;
        idle.push(if db + di == 0 {
            0.0
        } else {
            100.0 * di as f64 / (db + di) as f64
        });
    }
    CpuUse {
        idle,
        busy_us: if answers == 0 {
            0.0
        } else {
            busy * JIFFY_US / answers as f64
        },
        known: true,
        ..CpuUse::default()
    }
}

/// The value named `name` in the two lines of `TcpExt` of `/proc/net/netstat`.
fn netstat_value(lines: &[String], name: &str) -> Option<u64> {
    let header = lines
        .iter()
        .position(|l| l.starts_with("TcpExt:") && l.contains(name))?;
    let at = lines[header].split_whitespace().position(|w| w == name)?;
    lines
        .get(header + 1)?
        .split_whitespace()
        .nth(at)?
        .parse()
        .ok()
}

/// The Mac's one-minute load.
fn load_now() -> f64 {
    Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()
        .and_then(|o| {
            // The locale may write a comma for the point.
            String::from_utf8_lossy(&o.stdout)
                .replace(',', ".")
                .split_whitespace()
                .find_map(|w| w.parse::<f64>().ok())
        })
        .unwrap_or(-1.0)
}

// Records ------------------------------------------------------------------------------

type Rec = BTreeMap<String, String>;

fn rec_text(rec: &Rec) -> String {
    rec.iter()
        .map(|(k, v)| format!("{k}={}\n", v.replace('\n', " ")))
        .collect()
}

fn rec_of(text: &str) -> Rec {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn opt<T: ToString>(value: Option<T>) -> String {
    value.map_or("-".to_owned(), |v| v.to_string())
}

fn unopt<T: std::str::FromStr>(text: &str) -> Option<T> {
    if text == "-" { None } else { text.parse().ok() }
}

impl Measured {
    fn rec(&self) -> Rec {
        let mut r = Rec::new();
        let mut put = |k: &str, v: String| {
            r.insert(k.to_owned(), v);
        };
        put("rate", self.rate.to_string());
        put("seconds", self.seconds.to_string());
        put("requests", self.requests.to_string());
        put("ok", self.ok.to_string());
        put("failed", self.failed.to_string());
        put("malloc", self.malloc.to_string());
        put("achieved", format!("{:.1}", self.achieved));
        put("p50", self.p50.to_string());
        put("p99", self.p99.to_string());
        put("p999", opt(self.p999));
        put("p99_raw", self.p99_raw.to_string());
        put("lag_p99", self.lag_p99.to_string());
        put("lag_max", self.lag_max.to_string());
        put("mbps", format!("{:.3}", self.mbps));
        put("foreign", self.foreign.to_string());
        put("floor", opt(self.floor));
        put("load", format!("{:.2}", self.load));
        put(
            "alert",
            self.alert.clone().unwrap_or_else(|| "-".to_owned()),
        );
        put("counters", self.counters.clone());
        if let Some(cpu) = &self.cpu {
            put("cpu_known", cpu.known.to_string());
            put("cpu_busy_us", format!("{:.2}", cpu.busy_us));
            put("cpu_procs", procs_text(&cpu.procs));
            put("cpu_irq_us", format!("{:.2}", cpu.irq_us));
            put("cpu_softirq_us", format!("{:.2}", cpu.softirq_us));
            put("cpu_placed", cpu.placed.clone());
            put("cpu_profile", procs_text(&cpu.profile));
            put(
                "cpu_idle",
                cpu.idle
                    .iter()
                    .map(|i| format!("{i:.1}"))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        r
    }

    fn of(r: &Rec) -> Option<Measured> {
        let g = |k: &str| r.get(k).map(String::as_str);
        let n = |k: &str| g(k)?.parse::<u64>().ok();
        let f = |k: &str| g(k)?.parse::<f64>().ok();
        Some(Measured {
            rate: n("rate")? as u32,
            seconds: n("seconds")? as u32,
            requests: n("requests")? as usize,
            ok: n("ok")? as usize,
            failed: n("failed")? as usize,
            malloc: n("malloc")? as usize,
            achieved: f("achieved")?,
            p50: n("p50")?,
            p99: n("p99")?,
            p999: unopt(g("p999")?),
            p99_raw: n("p99_raw")?,
            lag_p99: n("lag_p99")?,
            lag_max: n("lag_max")?,
            mbps: f("mbps")?,
            foreign: g("foreign")? == "true",
            floor: unopt(g("floor")?),
            load: f("load")?,
            alert: g("alert").filter(|a| *a != "-").map(str::to_owned),
            counters: g("counters").unwrap_or("").to_owned(),
            cpu: g("cpu_known").map(|k| CpuUse {
                known: k == "true",
                busy_us: f("cpu_busy_us").unwrap_or(0.0),
                procs: procs_of(g("cpu_procs").unwrap_or("")),
                irq_us: f("cpu_irq_us").unwrap_or(0.0),
                softirq_us: f("cpu_softirq_us").unwrap_or(0.0),
                placed: g("cpu_placed").unwrap_or("").to_owned(),
                profile: procs_of(g("cpu_profile").unwrap_or("")),
                idle: g("cpu_idle")
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|i| i.parse().ok())
                    .collect(),
            }),
        })
    }
}

// What the Mac runs ---------------------------------------------------------------------

/// The load of one attack of `vegeta`: its targets are the paths of the set
/// in turn, on at most 64 connections.
fn vegeta_args(targets: &Path, rate: u32, secs: u32, keep_alive: bool, out: &Path) -> Vec<String> {
    [
        "attack".to_owned(),
        format!("-targets={}", targets.display()),
        format!("-rate={}/1s", rate.max(1)),
        format!("-duration={secs}s"),
        format!("-keepalive={keep_alive}"),
        format!("-connections={CONNECTIONS}"),
        format!("-max-connections={CONNECTIONS}"),
        "-max-body=0".to_owned(),
        "-timeout=10s".to_owned(),
        format!("-output={}", out.display()),
    ]
    .to_vec()
}

fn write_targets(path: &Path, base: &str, paths: &[String]) -> Result<(), String> {
    let text: String = paths.iter().map(|p| format!("GET {base}{p}\n")).collect();
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The script of `wrk`: the paths of the set in turn, and with no
/// keep-alive the header that closes each connection.
fn wrk_script(paths: &[String], keep_alive: bool) -> String {
    let list: Vec<String> = paths.iter().map(|p| format!("\"{p}\"")).collect();
    format!(
        "local paths = {{{}}}\nlocal i = 0\n{}request = function()\n  i = i + 1\n  return wrk.format(\"GET\", paths[i % #paths + 1])\nend\n",
        list.join(","),
        if keep_alive {
            ""
        } else {
            "wrk.headers[\"Connection\"] = \"close\"\n"
        }
    )
}

/// One attack of `vegeta` at `base`: `warm` seconds with their results
/// dropped, then `secs`. On a guest, nginx's console is read through the
/// step and a line at crit or above ends the run with an error.
#[allow(clippy::too_many_arguments)]
fn attack(
    raw: &Path,
    mut guest: Option<&mut qemu::Run>,
    key: &str,
    wl: Workload,
    base: &str,
    rate: u32,
    secs: u32,
    warm: u32,
    keep_alive: bool,
) -> Result<Measured, String> {
    let tag = slug(key);
    let targets = raw.join(format!("targets-{tag}.txt"));
    write_targets(&targets, base, &wl.paths())?;
    let mut go =
        |name: &str, seconds: u32, out: &Path| -> Result<(Option<String>, usize), String> {
            let args = vegeta_args(&targets, rate, seconds, keep_alive, out);
            match guest.as_deref_mut() {
                Some(run) => {
                    let mut server = Server::Guest(run);
                    let mark = server.mark()?;
                    let (_, seen) =
                        watched(&mut server, raw, name, "vegeta", &args, seconds, None)?;
                    let log = server.log_since(mark)?;
                    let mut found = alerts(&log);
                    found.extend(seen);
                    Ok((found.first().cloned(), malloc_failures(&log)))
                }
                None => {
                    run_tool(raw, name, "vegeta", &args)?;
                    Ok((None, 0))
                }
            }
        };
    if warm > 0 {
        let out = raw.join(format!("{tag}-warm.bin"));
        let (alert, _) = go(&format!("vegeta-{tag}-warm.txt"), warm, &out)?;
        let _ = std::fs::remove_file(&out);
        stop_on(&format!("{key} (warm-up)"), &Vec::from_iter(alert))?;
    }
    let results = raw.join(format!("{tag}.bin"));
    let (alert, malloc) = go(&format!("vegeta-{tag}.txt"), secs, &results)?;
    let samples = samples_of(&results)?;
    let mut m = measure(&samples, rate, wl.length(), malloc);
    m.seconds = secs;
    m.alert = alert;
    std::fs::write(
        raw.join(format!("seconds-{tag}.csv")),
        nginx_bench::by_second(&samples, rate),
    )
    .map_err(|e| format!("seconds-{tag}.csv: {e}"))?;
    let _ = Command::new("gzip").arg("-f").arg(&results).status();
    Ok(m)
}

/// Homebrew's nginx on the loopback with stafeto's settings and the files
/// of both guests: the floor of the Mac.
struct Floor {
    child: Child,
    port: u16,
    root: PathBuf,
}

impl Floor {
    fn start(dir: &Path) -> Result<Floor, String> {
        let root = dir.join("floor");
        for sub in ["www", "tmp", "logs"] {
            std::fs::create_dir_all(root.join(sub)).map_err(|e| format!("{sub}: {e}"))?;
        }
        for (path, bytes) in linux_guest::www_files() {
            let at = root.join("www").join(path.trim_start_matches("/www/"));
            std::fs::create_dir_all(at.parent().unwrap_or(&root))
                .and_then(|()| std::fs::write(&at, bytes))
                .map_err(|e| format!("{path}: {e}"))?;
        }
        let port = crate::net_curl::free_tcp_port()?;
        let conf = root.join("nginx.conf");
        std::fs::write(&conf, nginx_bench::host_conf(&root, port))
            .map_err(|e| format!("nginx.conf: {e}"))?;
        let log =
            std::fs::File::create(root.join("error.log")).map_err(|e| format!("error.log: {e}"))?;
        let child = Command::new("nginx")
            .arg("-p")
            .arg(&root)
            .arg("-c")
            .arg(&conf)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .map_err(|e| format!("nginx of Homebrew: {e} (brew install nginx)"))?;
        let floor = Floor { child, port, root };
        let address: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
        let started = Instant::now();
        while Connection::open(address, Duration::from_secs(2))
            .and_then(|mut c| c.get("/index.html"))
            .is_err()
        {
            if started.elapsed() > START_WITHIN {
                return Err("Homebrew's nginx does not answer on the loopback".to_owned());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(floor)
    }

    fn stop(mut self) {
        let _ = Command::new("kill")
            .args(["-QUIT", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = std::fs::copy(
            self.root.join("nginx.conf"),
            self.root.join("../floor-nginx.conf"),
        );
    }
}

// The guests ---------------------------------------------------------------------------

/// What a run builds before it boots anything.
struct Prepared {
    linux: PathBuf,
    kernel: PathBuf,
    image: PathBuf,
    /// The image of F1.
    fast_image: PathBuf,
    config: String,
    /// The fingerprint of the settings of F1 (its own file).
    fast_config: String,
    www: String,
}

/// A guest on VZ with its console on a pipe.
/// What the guest showed before a run: the CPUs, the processes, and the
/// totals of the network service's profile when the image has it.
struct Window {
    stat: Vec<(u64, u64)>,
    irq: (u64, u64),
    procs: Vec<Proc>,
    snapshot: Option<Vec<(String, u64)>>,
}

struct Guest {
    sys: System,
    run: qemu::Run,
    address: SocketAddr,
    mac: String,
    _suffix: vz::Suffix,
    /// Guests of VZ on the Mac when this one came up.
    vz_start: usize,
    load_start: f64,
    others_start: String,
    report: Report,
    /// The set the load passed last, and when.
    warmed: Option<(Workload, Instant)>,
}

impl Guest {
    /// The CPU time of each process of the guest, from `/proc/<pid>/stat`
    /// (Linux and stafeto write the same fields).
    fn procs(&mut self) -> Result<Vec<Proc>, String> {
        let lines = crate::net_tls::capture(
            &mut self.run,
            "for f in /proc/[0-9]*/stat; do cat $f; done 2>/dev/null",
            "procs",
            DIALOG_STEP,
        )?;
        Ok(parse_proc_times(&lines))
    }

    /// The totals of the network service's profile (an image with the
    /// feature `profile`): `posix-net stat` makes the service print its
    /// records, which reach the console a moment later.
    fn profile(&mut self) -> Result<Vec<(String, u64)>, String> {
        let last = parse_profile(&self.run.text()).map_or(0, |(id, _)| id);
        crate::net_tls::capture(&mut self.run, "posix-net stat", "profile", DIALOG_STEP)?;
        for _ in 0..20 {
            if let Some((id, pairs)) = parse_profile(&self.run.text())
                && id > last
            {
                return Ok(pairs);
            }
            crate::net_tls::capture(&mut self.run, "sleep 1", "profwait", DIALOG_STEP)?;
        }
        Err("the network service printed no whole profile".to_owned())
    }

    /// The readings before a run, in the order that keeps the reads of the
    /// processes and of the profile out of the window of `/proc/stat`: they
    /// first, the CPUs last.
    fn open_window(&mut self, profile: bool) -> Result<Window, String> {
        let procs = self.procs()?;
        let snapshot = if profile { Some(self.profile()?) } else { None };
        let lines =
            crate::net_tls::capture(&mut self.run, "grep ^cpu /proc/stat", "stat", DIALOG_STEP)?;
        Ok(Window {
            stat: parse_stat(&lines),
            irq: parse_irq(&lines),
            procs,
            snapshot,
        })
    }

    /// The readings after a run (the CPUs first), and what the run used.
    fn close_window(&mut self, before: &Window, answers: usize) -> Result<CpuUse, String> {
        let lines =
            crate::net_tls::capture(&mut self.run, "grep ^cpu /proc/stat", "stat", DIALOG_STEP)?;
        let procs = self.procs()?;
        let snapshot = if before.snapshot.is_some() {
            Some(self.profile()?)
        } else {
            None
        };
        let mut used = cpu_use(
            &before.stat,
            &parse_stat(&lines),
            linux_guest::CPUS,
            answers,
        );
        let (irq, soft) = parse_irq(&lines);
        if answers != 0 {
            let per = JIFFY_US / answers as f64;
            used.irq_us = irq.saturating_sub(before.irq.0) as f64 * per;
            used.softirq_us = soft.saturating_sub(before.irq.1) as f64 * per;
        }
        used.procs = proc_use(&before.procs, &procs, answers);
        used.placed = placed_text(&procs);
        if let (Some(a), Some(b)) = (&before.snapshot, &snapshot) {
            used.profile = profile_change(a, b);
        }
        Ok(used)
    }

    /// The counters of the system: `ListenDrops` of Linux, `posix-net stat`
    /// of stafeto.
    fn counters(&mut self) -> Result<String, String> {
        if self.sys.linux() {
            let lines = crate::net_tls::capture(
                &mut self.run,
                "cat /proc/net/netstat",
                "netstat",
                DIALOG_STEP,
            )?;
            Ok(format!(
                "ListenDrops {} ListenOverflows {}",
                opt(netstat_value(&lines, "ListenDrops")),
                opt(netstat_value(&lines, "ListenOverflows"))
            ))
        } else {
            let lines =
                crate::net_tls::capture(&mut self.run, "posix-net stat", "pstat", DIALOG_STEP)?;
            Ok(lines
                .iter()
                .find(|l| l.contains("sessions") || l.contains("buffer"))
                .or(lines.first())
                .map_or(String::new(), |l| l.trim().to_owned()))
        }
    }
}

fn expect_fetch(address: SocketAddr) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match Connection::open(address, Duration::from_secs(2))
            .and_then(|mut c| c.get("/s/0000.bin"))
        {
            Ok(body) => {
                let files = linux_guest::www_files();
                let wanted = files
                    .iter()
                    .find(|f| f.0 == "/www/s/0000.bin")
                    .map(|f| f.1)
                    .ok_or("no /www/s/0000.bin")?;
                return nginx_probe::same("GET /s/0000.bin", &body, wanted);
            }
            Err(_) if started.elapsed() < START_WITHIN => {
                std::thread::sleep(Duration::from_millis(200))
            }
            Err(why) => return Err(format!("the first request: {why}")),
        }
    }
}

fn boot_linux(prep: &Prepared, sys: System) -> Result<Guest, String> {
    let suffix = vz::claim_suffix()?;
    let mut report = Report {
        system: sys.name(),
        ..Report::default()
    };
    let (load_start, others_start) = (load_now(), nginx_bench::other_guests(0));
    let command = linux_guest::linux_command(&prep.linux, &suffix)?;
    let mut run = qemu::Run::start(command, qemu::Input::Pipe)?;
    let result = (|| {
        let line = run.expect_line(
            "the address",
            |l| l.starts_with("linux-guest: address "),
            Duration::from_secs(60),
        )?;
        let address: Ipv4Addr = line
            .trim_start_matches("linux-guest: address ")
            .trim()
            .parse()
            .map_err(|e| format!("the address {line:?}: {e}"))?;
        let mac = run.expect_line(
            "the MAC",
            |l| l.starts_with("linux-guest: mac "),
            DIALOG_STEP,
        )?;
        report.mac = mac
            .trim_start_matches("linux-guest: mac ")
            .trim()
            .to_owned();
        if report.mac != vz::mac(suffix.value, 0) {
            return Err(format!("the guest has the MAC {}", report.mac));
        }
        let features = run.expect_line(
            "the features",
            |l| l.starts_with("linux-guest: features "),
            DIALOG_STEP,
        )?;
        report.features = features
            .trim_start_matches("linux-guest: features ")
            .trim()
            .to_owned();
        run.expect_line("ready", |l| l == "linux-guest: ready", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        linux_guest::workers_up(&mut run, DIALOG_STEP, 4)?;
        linux_guest::read_fingerprints(&mut run, &mut report, false)?;
        linux_guest::verify(&report, &prep.config, &prep.www)?;
        run.send("M=$(cat /var/run/nginx.pid)")?;
        if sys.workers() == 1 {
            // The same settings with one worker, the one allowed difference.
            let from = run.lines().len();
            run.send("sed 's/^worker_processes 4;/worker_processes 1;/' /etc/nginx/nginx.conf > /tmp/one.conf; kill -QUIT $M; while kill -0 $M 2>/dev/null; do sleep 0.2; done; nginx -c /tmp/one.conf & M=$!")?;
            nginx_probe::marker(&mut run, "one", START_WITHIN)?;
            let started = Instant::now();
            while run.lines()[from..]
                .iter()
                .filter(|l| l.contains("start worker process "))
                .count()
                < 1
            {
                if started.elapsed() > START_WITHIN {
                    return Err("the worker of L1 did not start".to_owned());
                }
                let _ = run.expect_seen("\u{0}pump", Duration::from_millis(100));
            }
        }
        expect_fetch((address, 80).into())?;
        Ok(address)
    })();
    match result {
        Ok(address) => Ok(Guest {
            sys,
            run,
            address: (address, 80).into(),
            mac: report.mac.clone(),
            _suffix: suffix,
            vz_start: vz_guests(None),
            load_start,
            others_start,
            report,
            warmed: None,
        }),
        Err(why) => {
            run.stop();
            Err(why)
        }
    }
}

fn boot_stafeto(prep: &Prepared, sys: System) -> Result<Guest, String> {
    let fast = sys == System::F1;
    let suffix = vz::claim_suffix()?;
    let mut report = Report {
        system: sys.name(),
        ..Report::default()
    };
    let (load_start, others_start) = (load_now(), nginx_bench::other_guests(0));
    let image = if fast { &prep.fast_image } else { &prep.image };
    let machine = linux_guest::machine_with(&suffix, if fast { 2 } else { 1 });
    let command = vz::command_on(&prep.kernel, image, machine)?;
    let mut run = qemu::Run::start(command, qemu::Input::Pipe)?;
    let result = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        let lease = run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        let lease = net_vz::parse_address(&lease, "lease").ok_or_else(|| format!("{lease:?}"))?;
        run.expect("# ", DIALOG_STEP)?;
        let driver = run
            .lines()
            .iter()
            .find(|l| l.starts_with("virtio-net: "))
            .cloned()
            .ok_or("no line of the driver of the network device")?;
        report.mac = driver
            .split("mac ")
            .nth(1)
            .map(|m| m.trim().to_owned())
            .ok_or_else(|| format!("the driver's line {driver:?} names no MAC"))?;
        net_vz::lease_is_ours("net-bench", &vz::mac(suffix.value, 0), lease.address)?;
        if fast {
            // The stack starts with the program, on the second device: the
            // address the load goes to is the static one of `netd.conf`.
            run.send(&format!("nginx-fast -c {FAST_CONF} & M=$!"))?;
            run.expect_line(
                "the stack",
                |l| l.contains("fast: the stack is up on "),
                START_WITHIN,
            )?;
            linux_guest::workers_up(&mut run, DIALOG_STEP, 1)?;
            linux_guest::read_fingerprints_of(
                &mut run,
                &mut report,
                false,
                "nginx-fast",
                &format!("nginx-fast -T -c {FAST_CONF}"),
            )?;
            linux_guest::verify(&report, &prep.fast_config, &prep.www)?;
            let address: Ipv4Addr = linux_guest::FAST_ADDRESS
                .parse()
                .map_err(|e| format!("{e}"))?;
            expect_fetch((address, 80).into())?;
            return Ok(address);
        }
        run.send("nginx -c /etc/nginx/nginx.conf & M=$!")?;
        run.expect_line(
            "the event method",
            |l| l.contains("using the \"epoll\" event method"),
            START_WITHIN,
        )?;
        linux_guest::workers_up(&mut run, DIALOG_STEP, 4)?;
        linux_guest::read_fingerprints(&mut run, &mut report, false)?;
        linux_guest::verify(&report, &prep.config, &prep.www)?;
        expect_fetch((lease.address, 80).into())?;
        Ok(lease.address)
    })();
    match result {
        Ok(address) => Ok(Guest {
            sys,
            run,
            address: (address, 80).into(),
            mac: report.mac.clone(),
            _suffix: suffix,
            vz_start: vz_guests(None),
            load_start,
            others_start,
            report,
            warmed: None,
        }),
        Err(why) => {
            run.stop();
            Err(why)
        }
    }
}

// The run -------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Options {
    systems: Vec<System>,
    workloads: Vec<Workload>,
    phases: Vec<String>,
    rounds: u32,
    /// The most rounds, those after `rounds` taking the open pairs alone.
    max_rounds: u32,
    /// Seconds of the warm-up and of a step of the first walk.
    warm: u32,
    stage: u32,
    /// Seconds of a confirmation run and its warm-up, and the longest a run
    /// may be stretched to reach 100 000 requests.
    confirm: u32,
    confirm_warm: u32,
    cap: u32,
    floor: u32,
    ceiling: u32,
    nat: u32,
    max_rate: Option<u32>,
    resume: Option<PathBuf>,
    /// The image of S4: the plain one, the one with the profile's counters of
    /// the network service, or that one with the shell's processes on CPUs 1
    /// to 3.
    image: ImageKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum ImageKind {
    #[default]
    Plain,
    Profile,
    Pinned,
    /// Every program on CPU 0, so that every call of the network service is
    /// a call on its own CPU.
    Cpu0,
}

const USAGE: &str = "usage: cargo xtask net-bench run [--systems l1,l4,s4,f1] [--workloads w1,w2,w3,w4,w5] [--phases nat,sweep,rounds] [--rounds N] [--max-rounds N] [--warm S] [--stage S] [--confirm S] [--confirm-warm S] [--cap S] [--floor S] [--ceiling S] [--nat S] [--max-rate R] [--image plain|profile|pinned|cpu0] [--quick] [--resume DIR] | tables DIR";

fn options(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        systems: vec![System::L1, System::L4, System::S4],
        workloads: Workload::ALL.to_vec(),
        phases: ["nat", "sweep", "rounds"].map(str::to_owned).to_vec(),
        rounds: CONFIRMS,
        max_rounds: MAX_ROUNDS,
        warm: 10,
        stage: 60,
        confirm: 300,
        confirm_warm: 30,
        cap: 1200,
        floor: 60,
        ceiling: 30,
        nat: 30,
        max_rate: None,
        resume: None,
        image: ImageKind::Plain,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value; {USAGE}"))
        };
        let number = |text: String, name: &str| {
            text.parse::<u32>()
                .map_err(|e| format!("{name}: {text:?}: {e}"))
        };
        match arg.as_str() {
            "--systems" => {
                o.systems = value(arg)?
                    .split(',')
                    .map(|s| {
                        System::of(s).ok_or_else(|| format!("no system {s:?} (l1, l4, s4, f1)"))
                    })
                    .collect::<Result<_, _>>()?
            }
            "--workloads" => {
                o.workloads = value(arg)?
                    .split(',')
                    .map(|s| {
                        Workload::of(s).ok_or_else(|| format!("no workload {s:?} (w1, w2, w3)"))
                    })
                    .collect::<Result<_, _>>()?
            }
            "--image" => {
                o.image = match value(arg)?.as_str() {
                    "plain" => ImageKind::Plain,
                    "profile" => ImageKind::Profile,
                    "pinned" => ImageKind::Pinned,
                    "cpu0" => ImageKind::Cpu0,
                    other => {
                        return Err(format!("no image {other:?} (plain, profile, pinned, cpu0)"));
                    }
                }
            }
            "--phases" => o.phases = value(arg)?.split(',').map(str::to_owned).collect(),
            "--rounds" => o.rounds = number(value(arg)?, arg)?,
            "--max-rounds" => o.max_rounds = number(value(arg)?, arg)?,
            "--warm" => o.warm = number(value(arg)?, arg)?,
            "--stage" => o.stage = number(value(arg)?, arg)?,
            "--confirm" => o.confirm = number(value(arg)?, arg)?,
            "--confirm-warm" => o.confirm_warm = number(value(arg)?, arg)?,
            "--cap" => o.cap = number(value(arg)?, arg)?,
            "--floor" => o.floor = number(value(arg)?, arg)?,
            "--ceiling" => o.ceiling = number(value(arg)?, arg)?,
            "--nat" => o.nat = number(value(arg)?, arg)?,
            "--max-rate" => o.max_rate = Some(number(value(arg)?, arg)?),
            "--resume" => o.resume = Some(PathBuf::from(value(arg)?)),
            "--quick" => {
                (o.warm, o.stage, o.confirm, o.confirm_warm) = (3, 8, 15, 3);
                (o.cap, o.floor, o.ceiling, o.nat) = (20, 8, 8, 3);
            }
            other => return Err(format!("{other}: {USAGE}")),
        }
    }
    if let Some(bad) = o
        .phases
        .iter()
        .find(|p| !["nat", "sweep", "rounds"].contains(&p.as_str()))
    {
        return Err(format!("no phase {bad:?} (nat, sweep, rounds)"));
    }
    if o.rounds == 0 {
        return Err("--rounds 0".to_owned());
    }
    if o.max_rounds < o.rounds || o.max_rounds > MAX_ROUNDS {
        return Err(format!(
            "--max-rounds {} is below --rounds {} or above {MAX_ROUNDS}",
            o.max_rounds, o.rounds
        ));
    }
    Ok(o)
}

struct Bench {
    opts: Options,
    dir: PathBuf,
    raw: PathBuf,
    results: PathBuf,
    prep: Prepared,
    floor: Option<Floor>,
    guest: Option<Guest>,
    phase: String,
}

fn say(text: String) {
    println!("net-bench: {text}");
}

impl Bench {
    fn get(&self, key: &str) -> Option<Rec> {
        std::fs::read_to_string(self.results.join(format!("{key}.rec")))
            .ok()
            .map(|t| rec_of(&t))
    }

    fn put(&self, key: &str, rec: &Rec) {
        let _ = std::fs::write(self.results.join(format!("{key}.rec")), rec_text(rec));
    }

    fn measured(&self, key: &str) -> Option<Measured> {
        self.get(key).and_then(|r| Measured::of(&r))
    }

    /// Brings `sys` up if it is not the guest that stands.
    fn boot(&mut self, sys: System) -> Result<(), String> {
        if self.guest.as_ref().is_some_and(|g| g.sys == sys) {
            return Ok(());
        }
        self.release();
        let guest = if sys.linux() {
            boot_linux(&self.prep, sys)
        } else {
            boot_stafeto(&self.prep, sys)
        };
        match guest {
            Ok(g) => {
                say(format!(
                    "{}: {} up at {}, MAC {}, load {:.2}",
                    self.phase,
                    sys.name(),
                    g.address,
                    g.mac,
                    g.load_start
                ));
                self.guest = Some(g);
                Ok(())
            }
            Err(why) => Err(format!("{}: {why}", sys.name())),
        }
    }

    /// Ends the guest and records its conditions: the Mac's load and the
    /// other machines at its start and end, its MAC, address and the
    /// fingerprints.
    fn release(&mut self) {
        let Some(mut g) = self.guest.take() else {
            return;
        };
        let row = format!(
            "{}\t{}\t{}\t{}\t{:.2}\t{:.2}\t{}\t{}\t{}\t{}\t{}\n",
            self.phase,
            g.sys.name(),
            g.mac,
            g.address,
            g.load_start,
            load_now(),
            g.others_start.replace('\t', " "),
            nginx_bench::other_guests(1).replace('\t', " "),
            g.report.config_digest.get(..16).unwrap_or(""),
            g.report.www_digest.get(..16).unwrap_or(""),
            g.report.nginx_v.first().map(|l| l.trim()).unwrap_or("")
        );
        let boots = self.dir.join("boots.tsv");
        let mut text = std::fs::read_to_string(&boots).unwrap_or_default();
        text.push_str(&row);
        let _ = std::fs::write(&boots, text);
        if g.sys.linux() {
            let _ = g.run.send("poweroff -f");
        }
        let output = g.run.stop();
        let _ = std::fs::write(
            self.raw.join(format!(
                "console-{}-{}-{}.log",
                slug(&self.phase),
                g.sys.name(),
                g.mac.replace(':', "")
            )),
            output.lines.join("\n") + "\n",
        );
    }

    /// One step on `sys` (from the records if it was taken).
    #[allow(clippy::too_many_arguments)]
    fn stage(
        &mut self,
        key: &str,
        sys: System,
        wl: Workload,
        rate: u32,
        secs: u32,
        warm: u32,
        cpu: bool,
        counters: bool,
    ) -> Result<Measured, String> {
        if let Some(m) = self.measured(key) {
            return Ok(m);
        }
        self.boot(sys)?;
        let raw = self.raw.clone();
        let profiled = self.opts.image != ImageKind::Plain && !sys.linux();
        let result = (|| {
            let g = self.guest.as_mut().ok_or("no guest")?;
            let base = format!("http://{}", g.address);
            if g.warmed
                .is_none_or(|(w, t)| w != wl || t.elapsed() > COLD_AFTER)
            {
                let (pass_rate, pass_secs) = wl.pass();
                attack(
                    &raw,
                    Some(&mut g.run),
                    &format!("{key}.pass"),
                    wl,
                    &base,
                    pass_rate,
                    pass_secs,
                    0,
                    true,
                )?;
            }
            let foreign_before = vz_guests(None) > g.vz_start;
            let before = if cpu {
                Some(g.open_window(profiled)?)
            } else {
                None
            };
            let mut m = attack(
                &raw,
                Some(&mut g.run),
                key,
                wl,
                &base,
                rate,
                secs,
                warm,
                wl.keep_alive(),
            )?;
            if let Some(before) = before {
                m.cpu = Some(g.close_window(&before, m.ok)?);
            }
            m.foreign = foreign_before || vz_guests(None) > g.vz_start;
            m.load = load_now();
            if counters {
                m.counters = g.counters()?;
            }
            g.warmed = Some((wl, Instant::now()));
            Ok::<Measured, String>(m)
        })();
        let m = match result {
            Ok(m) => m,
            Err(why) => {
                say(format!("{key}: {why}; the guest is dropped"));
                let log = self.dir.join("errors.txt");
                let mut text = std::fs::read_to_string(&log).unwrap_or_default();
                text.push_str(&format!("{key}: {why}\n"));
                let _ = std::fs::write(&log, text);
                self.release();
                let mut m = Measured::broken(rate, why);
                m.seconds = secs;
                m.load = load_now();
                m
            }
        };
        self.put(key, &m.rec());
        if m.alert.is_some() {
            // `watched` ended nginx at the alert: the next step starts anew.
            self.release();
        }
        say(format!(
            "{key}: asked {rate}/s, achieved {:.0}/s, p99 {:.3} ms (raw {:.3}, lag {:.3}), failed {}{}",
            m.achieved,
            m.p99 as f64 / 1e6,
            m.p99_raw as f64 / 1e6,
            m.lag_p99 as f64 / 1e6,
            m.failed,
            if m.marks().is_empty() {
                String::new()
            } else {
                format!(" ({})", m.marks().join(", "))
            }
        ));
        Ok(m)
    }

    /// The floor at `rate`: the same load on Homebrew's nginx.
    fn floor(&mut self, key: &str, wl: Workload, rate: u32) -> Result<Measured, String> {
        if let Some(m) = self.measured(key) {
            return Ok(m);
        }
        let port = self.floor.as_ref().ok_or("the floor is not up")?.port;
        let base = format!("http://127.0.0.1:{port}");
        let mut m = attack(
            &self.raw,
            None,
            key,
            wl,
            &base,
            rate,
            self.opts.floor,
            (self.opts.floor / 6).max(2),
            wl.keep_alive(),
        )?;
        m.load = load_now();
        self.put(key, &m.rec());
        say(format!(
            "{key}: floor p99 {:.3} ms (raw {:.3}, lag {:.3})",
            m.p99 as f64 / 1e6,
            m.p99_raw as f64 / 1e6,
            m.lag_p99 as f64 / 1e6
        ));
        Ok(m)
    }

    fn sweep_step(
        &mut self,
        sys: System,
        wl: Workload,
        rate: u32,
        attempt: u32,
    ) -> Result<Verdict, String> {
        let key = format!("sweep.{}.{}.{rate}.{attempt}", sys.name(), wl.name());
        let (stage, warm) = (self.opts.stage, self.opts.warm);
        let mut m = self.stage(&key, sys, wl, rate, stage, warm, false, wl == Workload::W3)?;
        if m.floor.is_none() && !m.saturated() && m.p99 > P99_LIMIT_NS {
            let at = self.floor(
                &format!("floor.sweep.{}.{}.{rate}", sys.name(), wl.name()),
                wl,
                rate,
            )?;
            m.floor = Some(at.p99);
            self.put(&key, &m.rec());
        }
        Ok(m.verdict())
    }

    fn sweeps(&mut self) -> Result<(), String> {
        self.phase = "sweep".to_owned();
        for sys in self.opts.systems.clone() {
            for wl in self.opts.workloads.clone() {
                let key = format!("search.{}.{}", sys.name(), wl.name());
                if self.get(&key).is_some() {
                    continue;
                }
                let grid: Vec<u32> = wl
                    .grid()
                    .into_iter()
                    .filter(|r| self.opts.max_rate.is_none_or(|m| *r <= m))
                    .collect();
                let found = search(&grid, &mut |rate, attempt| {
                    self.sweep_step(sys, wl, rate, attempt)
                })?;
                let mut rec = Rec::new();
                rec.insert("rstar".into(), found.rstar.unwrap_or(0).to_string());
                rec.insert("above".into(), opt(found.above));
                rec.insert(
                    "below".into(),
                    found
                        .below
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                rec.insert("floor_decides".into(), opt(found.floor_decides));
                rec.insert(
                    "noisy".into(),
                    found
                        .noisy
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
                self.put(&key, &rec);
                say(format!("{key}: {found:?}"));
            }
            self.release();
        }
        Ok(())
    }

    fn rstar_of(&self, sys: System, wl: Workload) -> Option<(u32, Option<u32>)> {
        let rec = self.get(&format!("search.{}.{}", sys.name(), wl.name()))?;
        let rstar: u32 = rec.get("rstar")?.parse().ok()?;
        (rstar > 0).then(|| (rstar, rec.get("above").and_then(|a| unopt(a))))
    }

    /// `wrk` against the set: the ceiling.
    fn ceiling(
        &mut self,
        key: &str,
        sys: System,
        wl: Workload,
        connections: u32,
    ) -> Result<(), String> {
        if self.get(key).is_some() {
            return Ok(());
        }
        self.boot(sys)?;
        let (raw, secs) = (self.raw.clone(), self.opts.ceiling);
        let profiled = self.opts.image != ImageKind::Plain && !sys.linux();
        let script = raw.join(format!("wrk-{}.lua", wl.name()));
        std::fs::write(&script, wrk_script(&wl.paths(), wl.keep_alive()))
            .map_err(|e| format!("{}: {e}", script.display()))?;
        let result = (|| {
            let g = self.guest.as_mut().ok_or("no guest")?;
            let args: Vec<String> = [
                "-t2".to_owned(),
                format!("-c{connections}"),
                format!("-d{secs}s"),
                "--timeout".to_owned(),
                "10s".to_owned(),
                "-s".to_owned(),
                script.display().to_string(),
                format!("http://{}/", g.address),
            ]
            .to_vec();
            let before = g.open_window(profiled)?;
            let mut server = Server::Guest(&mut g.run);
            let mark = server.mark()?;
            let (text, seen) = watched(
                &mut server,
                &raw,
                &format!("wrk-{}.txt", slug(key)),
                "wrk",
                &args,
                secs,
                None,
            )?;
            let log = server.log_since(mark)?;
            let wrk = parse_wrk(&text).ok_or_else(|| format!("wrk printed no rate: {text}"))?;
            let cpu = g.close_window(&before, wrk.requests as usize)?;
            let mut found = alerts(&log);
            found.extend(seen);
            Ok::<(Wrk, CpuUse, Option<String>), String>((wrk, cpu, found.first().cloned()))
        })();
        let mut rec = Rec::new();
        match result {
            Ok((wrk, cpu, alert)) => {
                rec.insert("per_second".into(), format!("{:.0}", wrk.per_second));
                rec.insert("transfer".into(), wrk.transfer.clone());
                rec.insert("connect".into(), wrk.connect.to_string());
                rec.insert("read".into(), wrk.read.to_string());
                rec.insert("write".into(), wrk.write.to_string());
                rec.insert("timeout".into(), wrk.timeout.to_string());
                rec.insert("non2xx".into(), wrk.non_2xx.to_string());
                if alert.is_some() {
                    self.release();
                }
                rec.insert("alert".into(), alert.unwrap_or_else(|| "-".into()));
                rec.insert("cpu_known".into(), cpu.known.to_string());
                rec.insert("cpu_procs".into(), procs_text(&cpu.procs));
                rec.insert("cpu_irq_us".into(), format!("{:.2}", cpu.irq_us));
                rec.insert("cpu_softirq_us".into(), format!("{:.2}", cpu.softirq_us));
                rec.insert("cpu_placed".into(), cpu.placed.clone());
                rec.insert("cpu_profile".into(), procs_text(&cpu.profile));
                rec.insert(
                    "cpu_idle".into(),
                    cpu.idle
                        .iter()
                        .map(|i| format!("{i:.1}"))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                say(format!(
                    "{key}: {:.0} requests/s, connect {} timeout {} non-2xx {}",
                    wrk.per_second, wrk.connect, wrk.timeout, wrk.non_2xx
                ));
            }
            Err(why) => {
                say(format!("{key}: {why}; the guest is dropped"));
                rec.insert("per_second".into(), "0".into());
                rec.insert("alert".into(), why);
                self.release();
            }
        }
        self.put(key, &rec);
        Ok(())
    }

    /// The limit of the NAT: `iperf3` between the Mac and L4 without nginx
    /// under load, three repeats of each test.
    fn nat(&mut self) -> Result<(), String> {
        self.phase = "nat".to_owned();
        let tests: [(&str, &[&str]); 5] = [
            ("tcp1-up", &[]),
            ("tcp1-down", &["-R"]),
            ("tcp4-up", &["-P", "4"]),
            ("tcp4-down", &["-P", "4", "-R"]),
            ("udp64", &["-u", "-b", "0", "-l", "64"]),
        ];
        for (name, extra) in tests {
            for rep in 1..=3 {
                let key = format!("nat.{name}.{rep}");
                if self.get(&key).is_some() {
                    continue;
                }
                self.boot(System::L4)?;
                let address = self.guest.as_ref().ok_or("no guest")?.address.ip();
                let mut args = vec![
                    "-c".to_owned(),
                    address.to_string(),
                    "-t".to_owned(),
                    self.opts.nat.to_string(),
                    "-J".to_owned(),
                ];
                args.extend(extra.iter().map(|a| (*a).to_owned()));
                let text = run_tool(
                    &self.raw,
                    &format!("iperf3-{name}-{rep}.json"),
                    "iperf3",
                    &args,
                )?;
                let value = parse_iperf(&text, name.starts_with("udp"))
                    .ok_or_else(|| format!("{name}: no result in the output of iperf3"))?;
                let mut rec = Rec::new();
                rec.insert("value".into(), format!("{value:.0}"));
                rec.insert("load".into(), format!("{:.2}", load_now()));
                self.put(&key, &rec);
                say(format!(
                    "{key}: {value:.0} {}",
                    if name.starts_with("udp") {
                        "packets/s"
                    } else {
                        "Mbit/s"
                    }
                ));
            }
        }
        self.release();
        Ok(())
    }

    /// The rounds: in each, every system in the order of the Latin square is
    /// started anew and, for each workload, takes the floor at its three
    /// rates, a ceiling by `wrk` (the first rounds), a confirmation run at
    /// its R* and, in the first rounds, runs at 50 and 80 % of the R* of
    /// the walk. A confirmation that fails steps R* back by 5 % and counts
    /// anew, so the rounds go on (up to `MAX_ROUNDS`) while a pair is open.
    fn rounds(&mut self) -> Result<(), String> {
        let mut states: BTreeMap<(System, Workload), (u32, Confirm)> = BTreeMap::new();
        for sys in self.opts.systems.clone() {
            for wl in self.opts.workloads.clone() {
                if let Some((rstar, _)) = self.rstar_of(sys, wl) {
                    states.insert((sys, wl), (rstar, Confirm::new(rstar)));
                }
            }
        }
        for round in 1..=self.opts.max_rounds {
            self.phase = format!("round {round}");
            for sys in order(&self.opts.systems.clone(), round) {
                // The ceilings of every load of the system come first, with
                // or without an R* (a row that holds no 1 ms, S4 on W2 or F1,
                // has its ceiling and its CPU time all the same).
                if round <= self.opts.rounds {
                    for wl in self.opts.workloads.clone() {
                        for c in [CONNECTIONS, wl.criterion()] {
                            self.ceiling(
                                &format!("ceiling.r{round}.{}.{}.c{c}", sys.name(), wl.name()),
                                sys,
                                wl,
                                c,
                            )?;
                        }
                    }
                }
                let pairs: Vec<Workload> = self
                    .opts
                    .workloads
                    .iter()
                    .copied()
                    .filter(|wl| states.get(&(sys, *wl)).is_some_and(|(_, c)| !c.done()))
                    .collect();
                for wl in pairs {
                    let (base, confirm) = states[&(sys, wl)].clone();
                    let rates = if round <= self.opts.rounds {
                        vec![
                            confirm.rstar,
                            base * SHARES[0] / 100,
                            base * SHARES[1] / 100,
                        ]
                    } else {
                        vec![confirm.rstar]
                    };
                    for rate in &rates {
                        self.floor(
                            &format!("floor.r{round}.{}.{}.{rate}", sys.name(), wl.name()),
                            wl,
                            *rate,
                        )?;
                    }
                    let verdict = self.confirm_run(round, sys, wl, confirm.rstar)?;
                    if round <= self.opts.rounds {
                        for (share, rate) in SHARES.iter().zip(&rates[1..]) {
                            let (secs, _) = run_seconds(*rate, self.opts.confirm, self.opts.cap);
                            let key = format!("share{share}.r{round}.{}.{}", sys.name(), wl.name());
                            let warm = self.opts.confirm_warm;
                            self.stage(&key, sys, wl, *rate, secs, warm, true, false)?;
                        }
                    }
                    let state = &mut states.get_mut(&(sys, wl)).ok_or("no state")?.1;
                    state.step(verdict);
                    let mut rec = Rec::new();
                    rec.insert("rstar".into(), state.rstar.to_string());
                    rec.insert("passes".into(), state.passes.to_string());
                    rec.insert("retreats".into(), state.retreats.to_string());
                    rec.insert("unproven".into(), state.unproven.to_string());
                    rec.insert("rounds".into(), round.to_string());
                    self.put(&format!("confirmstate.{}.{}", sys.name(), wl.name()), &rec);
                }
                self.release();
            }
            if states.values().all(|(_, c)| c.done()) {
                break;
            }
        }
        Ok(())
    }

    /// The confirmation run of a round at `rate`: one run, whose verdict the
    /// confirmation takes as it stands.
    fn confirm_run(
        &mut self,
        round: u32,
        sys: System,
        wl: Workload,
        rate: u32,
    ) -> Result<Verdict, String> {
        let (secs, _) = run_seconds(rate, self.opts.confirm, self.opts.cap);
        let warm = self.opts.confirm_warm;
        let key = format!("confirm.r{round}.{}.{}.0", sys.name(), wl.name());
        let mut m = self.stage(&key, sys, wl, rate, secs, warm, true, false)?;
        if m.floor.is_none() {
            let at = self.measured(&format!(
                "floor.r{round}.{}.{}.{rate}",
                sys.name(),
                wl.name()
            ));
            m.floor = at.map(|f| f.p99);
            self.put(&key, &m.rec());
        }
        Ok(m.verdict())
    }
}

/// The result of `iperf3 -J`: Mbit/s received for TCP, packets a second sent
/// for UDP.
fn parse_iperf(json: &str, udp: bool) -> Option<f64> {
    let number_after = |from: usize, name: &str| -> Option<f64> {
        let at = json[from..].find(&format!("\"{name}\":"))? + from + name.len() + 3;
        let rest = json[at..].trim_start();
        let end =
            rest.find(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-')))?;
        rest[..end].parse().ok()
    };
    if udp {
        let at = json.rfind("\"sum\":")?;
        let packets = number_after(at, "packets")?;
        let seconds = number_after(at, "seconds")?;
        (seconds > 0.0).then(|| packets / seconds)
    } else {
        let at = json.find("\"sum_received\":")?;
        number_after(at, "bits_per_second").map(|b| b / 1e6)
    }
}

// The tables ----------------------------------------------------------------------------

/// The records of a run.
struct Results {
    dir: PathBuf,
    recs: BTreeMap<String, Rec>,
}

impl Results {
    fn load(dir: &Path) -> Result<Results, String> {
        let results = dir.join("results");
        let mut recs = BTreeMap::new();
        for entry in
            std::fs::read_dir(&results).map_err(|e| format!("{}: {e}", results.display()))?
        {
            let path = entry.map_err(|e| e.to_string())?.path();
            if let (Some(name), Ok(text)) = (
                path.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_suffix(".rec")),
                std::fs::read_to_string(&path),
            ) {
                recs.insert(name.to_owned(), rec_of(&text));
            }
        }
        Ok(Results {
            dir: dir.to_path_buf(),
            recs,
        })
    }

    fn m(&self, key: &str) -> Option<Measured> {
        self.recs.get(key).and_then(Measured::of)
    }

    fn all(&self, prefix: &str) -> Vec<(&str, Measured)> {
        self.recs
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .filter_map(|(k, r)| Measured::of(r).map(|m| (k.as_str(), m)))
            .collect()
    }

    fn num(&self, key: &str, field: &str) -> Option<f64> {
        self.recs.get(key)?.get(field)?.parse().ok()
    }
}

fn ms(ns: u64) -> String {
    format!("{:.3}", ns as f64 / 1e6)
}

fn ms_opt(ns: Option<u64>) -> String {
    ns.map_or("-".to_owned(), ms)
}

/// `median [least; greatest]` of `values` (`-` for none, the one value for
/// a single one).
fn spread(values: &[f64], digits: usize) -> String {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return "-".to_owned();
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let median = if v.len() % 2 == 1 {
        v[v.len() / 2]
    } else {
        (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0
    };
    if v.len() == 1 {
        format!("{median:.digits$}")
    } else {
        format!(
            "{median:.digits$} [{:.digits$}; {:.digits$}]",
            v[0],
            v[v.len() - 1]
        )
    }
}

/// Bytes a second from the `Transfer/sec` of `wrk` ("38.46MB").
fn transfer_bytes(text: &str) -> Option<f64> {
    let text = text.trim();
    let end = text.find(|c: char| c.is_ascii_alphabetic())?;
    let value: f64 = text[..end].parse().ok()?;
    let unit = match text[end..]
        .trim_end_matches('B')
        .to_ascii_uppercase()
        .as_str()
    {
        "" => 1.0,
        "K" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        _ => return None,
    };
    Some(value * unit)
}

/// What limits the system first, by the rule of the method: a CPU of the
/// guest idle below 5 % at the ceiling, else the NAT where the ceiling's
/// transfer passes 80 % of the TCP limit of `iperf3`, else the load
/// generator where the steps of saturation are marked so, else nothing.
fn first_limit(
    idle: &[f64],
    transfer_mbit: Option<f64>,
    nat_mbit: Option<f64>,
    generator: bool,
) -> &'static str {
    if idle.iter().any(|i| *i < IDLE_MARK_PCT) {
        "guest CPU"
    } else if transfer_mbit
        .zip(nat_mbit)
        .is_some_and(|(t, n)| t > 0.8 * n)
    {
        "NAT"
    } else if generator {
        "generator"
    } else {
        "not determined"
    }
}

/// What the recorded confirmation runs of a row give.
struct Conf {
    rate: u32,
    runs: usize,
    passes: usize,
    proven: bool,
}

impl Results {
    /// The verdict of a recorded step of the walk under the present rule.
    /// A second try that was never taken stands as noisy.
    fn replayed(
        &self,
        sys: System,
        wl: Workload,
        rate: u32,
        attempt: u32,
    ) -> Result<Verdict, String> {
        let key = format!("sweep.{}.{}.{rate}.{attempt}", sys.name(), wl.name());
        match (self.m(&key), attempt) {
            (Some(m), _) => Ok(m.verdict()),
            (None, 1) => Ok(Verdict::Noisy),
            (None, _) => Err(format!("no record of {key}")),
        }
    }

    /// What the walk and the bisection find over the recorded steps under
    /// the present rule; where the records do not hold a rate the search
    /// asks for (the run took another path under the rule it had), what the
    /// run recorded. The flag says which.
    fn search_of(&self, sys: System, wl: Workload) -> Option<(Found, bool)> {
        let rec = self
            .recs
            .get(&format!("search.{}.{}", sys.name(), wl.name()))?;
        if let Ok(found) = search(&wl.grid(), &mut |rate, attempt| {
            self.replayed(sys, wl, rate, attempt)
        }) {
            return Some((found, true));
        }
        let list = |k: &str| -> Vec<u32> {
            rec.get(k)
                .map(|v| v.split(',').filter_map(|x| x.parse().ok()).collect())
                .unwrap_or_default()
        };
        let rstar: u32 = rec.get("rstar").and_then(|r| r.parse().ok()).unwrap_or(0);
        Some((
            Found {
                rstar: (rstar > 0).then_some(rstar),
                above: rec.get("above").and_then(|a| unopt(a)),
                below: list("below"),
                floor_decides: rec.get("floor_decides").and_then(|a| unopt(a)),
                noisy: list("noisy"),
            },
            false,
        ))
    }

    /// The confirmation over the recorded runs (the first run of each round)
    /// under the present rule: the highest rate with three passes in a row,
    /// or else the rate with most passes.
    fn confirmed(&self, sys: System, wl: Workload) -> Option<Conf> {
        let tail = format!(".{}.{}.0", sys.name(), wl.name());
        let mut runs: Vec<(u32, Measured)> = self
            .all("confirm.r")
            .into_iter()
            .filter(|(k, _)| k.ends_with(&tail))
            .filter_map(|(k, m)| {
                let round = k["confirm.r".len()..].split('.').next()?.parse().ok()?;
                Some((round, m))
            })
            .collect();
        runs.sort_by_key(|r| r.0);
        let mut rates: Vec<u32> = runs.iter().map(|r| r.1.rate).collect();
        rates.sort_unstable_by(|a, b| b.cmp(a));
        rates.dedup();
        let at = |rate: u32| -> Vec<Verdict> {
            runs.iter()
                .filter(|r| r.1.rate == rate)
                .map(|r| r.1.verdict())
                .collect()
        };
        let conf = |rate: u32, proven: bool| {
            let v = at(rate);
            Conf {
                rate,
                runs: v.len(),
                passes: v.iter().filter(|x| **x == Verdict::Pass).count(),
                proven,
            }
        };
        if let Some(rate) = rates.iter().copied().find(|r| {
            at(*r)
                .windows(3)
                .any(|w| w.iter().all(|x| *x == Verdict::Pass))
        }) {
            return Some(conf(rate, true));
        }
        rates
            .iter()
            .copied()
            .map(|r| conf(r, false))
            .max_by_key(|c| (c.passes, c.rate))
    }

    /// The Mac's load at the start and end of the guest of `sys` in `phase`.
    fn boot_load(&self, phase: &str, sys: System) -> Option<(f64, f64)> {
        let text = std::fs::read_to_string(self.dir.join("boots.tsv")).ok()?;
        text.lines().find_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.first() == Some(&phase) && f.get(1) == Some(&sys.name()))
                .then(|| Some((f.get(4)?.parse().ok()?, f.get(5)?.parse().ok()?)))
                .flatten()
        })
    }

    fn nat_median(&self, test: &str) -> Option<f64> {
        let v: Vec<f64> = (1..=3)
            .filter_map(|r| self.num(&format!("nat.{test}.{r}"), "value"))
            .collect();
        let text = spread(&v, 0);
        (text != "-")
            .then(|| text.split_whitespace().next().and_then(|t| t.parse().ok()))
            .flatten()
    }

    fn table_nat(&self) -> String {
        let mut t = String::from(
            "### Table 1. The limit of the NAT (iperf3, Mac and L4)\n\n| test | median [least; greatest] of 3 |\n|---|---|\n",
        );
        for (name, unit) in [
            ("tcp1-up", "Mbit/s"),
            ("tcp1-down", "Mbit/s"),
            ("tcp4-up", "Mbit/s"),
            ("tcp4-down", "Mbit/s"),
            ("udp64", "packets/s sent"),
        ] {
            let v: Vec<f64> = (1..=3)
                .filter_map(|r| self.num(&format!("nat.{name}.{r}"), "value"))
                .collect();
            t += &format!("| {name} ({unit}) | {} |\n", spread(&v, 0));
        }
        t
    }

    fn rows(&self) -> Vec<(Workload, System)> {
        let mut rows = Vec::new();
        for wl in Workload::ALL {
            for sys in System::ALL {
                if self
                    .recs
                    .contains_key(&format!("search.{}.{}", sys.name(), wl.name()))
                {
                    rows.push((wl, sys));
                }
            }
        }
        rows
    }

    fn table_main(&self) -> String {
        let mut t = String::from(
            "### Table 2. R* and the numbers at R* (median of the runs [least; greatest])\n\n| load | system | workers | R* of the walk (next rate above) | R* confirmed | passes of runs (first run of each round) | rates below R* without 1 ms | p50 ms at R* | p99 ms at R* | p99.9 ms at 50 % | p99.9 ms at 80 % | MB/s at R* | CPU us per request | idle % per CPU | first limit | requests per c.u. |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
        );
        let nat = self.nat_median("tcp4-down");
        for (wl, sys) in self.rows() {
            let name = format!("{}.{}", sys.name(), wl.name());
            let (found, replayed) = self.search_of(sys, wl).unwrap_or_default();
            let rstar = found.rstar.unwrap_or(0);
            let mut below = found
                .below
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            if !found.noisy.is_empty() {
                below += &format!(
                    "{}undecided (noise): {}",
                    if below.is_empty() { "" } else { "; " },
                    found
                        .noisy
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            let walk = match (rstar, found.floor_decides) {
                (0, _) if !found.noisy.is_empty() => {
                    "no decision: the floor of the Mac is above 1 ms".to_owned()
                }
                (0, _) => "no rate of the grid holds 1 ms".to_owned(),
                (r, Some(f)) => format!(">= {r} (above, the floor decides at {f})"),
                (r, None) => format!("{r} ({})", opt(found.above)),
            } + if replayed {
                ""
            } else {
                " (as recorded, old rule)"
            };
            let conf = self.confirmed(sys, wl);
            let (confirmed, proven) = conf.as_ref().map_or((0, false), |c| (c.rate, c.proven));
            let passes = conf.map_or("-".to_owned(), |c| format!("{} of {}", c.passes, c.runs));
            let runs: Vec<Measured> = self
                .all("confirm.r")
                .into_iter()
                .filter(|(k, m)| k.ends_with(&format!(".{name}.0")) && m.rate == confirmed)
                .map(|(_, m)| m)
                .collect();
            let col = |f: &dyn Fn(&Measured) -> Option<f64>| {
                spread(&runs.iter().filter_map(f).collect::<Vec<_>>(), 3)
            };
            let share = |share: u32| -> String {
                let v: Vec<f64> = self
                    .all(&format!("share{share}.r"))
                    .into_iter()
                    .filter(|(k, _)| k.ends_with(&format!(".{name}")))
                    .filter_map(|(_, m)| m.p999.map(|p| p as f64 / 1e6))
                    .collect();
                spread(&v, 3)
            };
            let cpu_idle: Vec<Vec<f64>> = runs
                .iter()
                .filter_map(|m| m.cpu.as_ref())
                .filter(|c| c.known)
                .map(|c| c.idle.clone())
                .collect();
            let idle_each: Vec<f64> = (0..linux_guest::CPUS)
                .filter_map(|i| {
                    let v: Vec<f64> = cpu_idle.iter().filter_map(|c| c.get(i).copied()).collect();
                    (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
                })
                .collect();
            let unknown =
                !runs.is_empty() && runs.iter().all(|m| m.cpu.as_ref().is_none_or(|c| !c.known));
            let ceiling_idle: Vec<f64> = self
                .recs
                .iter()
                .filter(|(k, _)| {
                    k.starts_with("ceiling.r") && k.ends_with(&format!(".{name}.c{CONNECTIONS}"))
                })
                .flat_map(|(_, r)| {
                    r.get("cpu_idle")
                        .cloned()
                        .unwrap_or_default()
                        .split(',')
                        .filter_map(|i| i.parse::<f64>().ok())
                        .collect::<Vec<_>>()
                })
                .collect();
            let transfer: Vec<f64> = self
                .recs
                .iter()
                .filter(|(k, _)| {
                    k.starts_with("ceiling.r") && k.ends_with(&format!(".{name}.c{CONNECTIONS}"))
                })
                .filter_map(|(_, r)| transfer_bytes(r.get("transfer")?))
                .map(|b| b * 8.0 / 1e6)
                .collect();
            let generator = self
                .all(&format!("sweep.{name}."))
                .iter()
                .any(|(_, m)| m.saturated() && m.lag_p99 > LAG_MARK_NS && 2 * m.lag_p99 > m.p99);
            let limit = first_limit(
                &ceiling_idle,
                transfer
                    .iter()
                    .copied()
                    .fold(None, |a: Option<f64>, b| Some(a.map_or(b, |a| a.max(b)))),
                nat,
                generator,
            );
            t += &format!(
                "| {} | {} | {} | {walk} | {}{} | {passes} | {} | {} | {} | {} | {} | {} | {} | {} | {limit} | {} |\n",
                wl.name().to_uppercase(),
                sys.name(),
                sys.workers(),
                if confirmed == 0 {
                    "-".to_owned()
                } else {
                    confirmed.to_string()
                },
                if confirmed > 0 && !proven {
                    " (not confirmed)"
                } else {
                    ""
                },
                if below.is_empty() { "-" } else { &below },
                col(&|m| Some(m.p50 as f64 / 1e6)),
                col(&|m| Some(m.p99 as f64 / 1e6)),
                share(50),
                share(80),
                col(&|m| Some(m.mbps)),
                col(&|m| m.cpu.as_ref().filter(|c| c.known).map(|c| c.busy_us)),
                if unknown {
                    "CPUs unknown".to_owned()
                } else if idle_each.is_empty() {
                    "-".to_owned()
                } else {
                    idle_each
                        .iter()
                        .map(|i| format!("{i:.0}"))
                        .collect::<Vec<_>>()
                        .join(" / ")
                },
                if confirmed == 0 {
                    "-".to_owned()
                } else {
                    format!("{}", u64::from(confirmed) * 3600)
                },
            );
        }
        t += "\nThe price of an hour is a placeholder (1 c.u. for every row), so the last column is R* x 3600 and the ratio of two rows is the ratio of their R*.\n";
        t
    }

    fn table_ratios(&self) -> String {
        let mut t = String::from(
            "### Table 2a. Ratios between the rows (S4 over L4, F1 over L4, S4 and L1)\n\n",
        );
        for (a, b) in PAIRS {
            let (an, bn) = (a.name(), b.name());
            let mut by_rstar = String::new();
            for wl in Workload::ALL {
                if let (Some(x), Some(y)) = (self.confirmed(a, wl), self.confirmed(b, wl)) {
                    let mark = |c: &Conf| {
                        format!(
                            "{}{}",
                            c.rate,
                            if c.proven { "" } else { " (not confirmed)" }
                        )
                    };
                    by_rstar += &format!(
                        "| {} | {} | {} | {} |\n",
                        wl.name().to_uppercase(),
                        mark(&x),
                        mark(&y),
                        if y.rate == 0 {
                            "-".to_owned()
                        } else {
                            format!("{:.2}", f64::from(x.rate) / f64::from(y.rate))
                        }
                    );
                }
            }
            let mut by_ceiling = String::new();
            for wl in Workload::ALL {
                for round in 1..=MAX_ROUNDS {
                    let rps = |sys: System| {
                        self.num(
                            &format!(
                                "ceiling.r{round}.{}.{}.c{CONNECTIONS}",
                                sys.name(),
                                wl.name()
                            ),
                            "per_second",
                        )
                    };
                    let (Some(x), Some(y)) = (rps(a), rps(b)) else {
                        continue;
                    };
                    let phase = format!("round {round}");
                    let load = |sys: System| {
                        self.boot_load(&phase, sys)
                            .map_or("-".to_owned(), |(p, q)| format!("{p:.2} / {q:.2}"))
                    };
                    by_ceiling += &format!(
                        "| {} | {round} | {x:.0} | {y:.0} | {:.4} | {} | {} |\n",
                        wl.name().to_uppercase(),
                        x / y,
                        load(a),
                        load(b)
                    );
                }
            }
            if by_rstar.is_empty() && by_ceiling.is_empty() {
                continue;
            }
            t += &format!(
                "#### {an} over {bn}\n\nBy R* over the recorded runs (not paired: the runs of the two rows were taken in different rounds, some at other loads of the Mac):\n\n| load | R* {an} | R* {bn} | {an} / {bn} |\n|---|---|---|---|\n{by_rstar}"
            );
            t += &format!(
                "\nBy the ceiling of `wrk -c64`, paired in each round (the Mac's one-minute load at the start and at the end of each guest):\n\n| load | round | {an} requests/s | {bn} requests/s | {an} / {bn} | load of {an} | load of {bn} |\n|---|---|---|---|---|---|---|\n{by_ceiling}\n"
            );
        }
        t
    }

    fn table_common(&self) -> String {
        let mut t = String::from(
            "### Table 4. At the rates of the walk both rows of a pair hold (R* of the walk under the present rule) (one run each, the length of a step of the walk)\n\n| load | pair | rate | p50 ms | p99 ms | p99.9 ms | the other row: p50 | p99 | p99.9 |\n|---|---|---|---|---|---|---|---|---|\n",
        );
        for wl in Workload::ALL {
            for sys in [System::S4, System::F1] {
                let Some(peer) = sys.peer() else { continue };
                let (Some(a), Some(b)) = (
                    self.search_of(sys, wl).and_then(|f| f.0.rstar),
                    self.search_of(peer, wl).and_then(|f| f.0.rstar),
                ) else {
                    continue;
                };
                for rate in wl.grid().into_iter().filter(|r| *r <= a.min(b)) {
                    let (x, y) = (
                        self.m(&format!("sweep.{}.{}.{rate}.0", sys.name(), wl.name())),
                        self.m(&format!("sweep.{}.{}.{rate}.0", peer.name(), wl.name())),
                    );
                    if let (Some(x), Some(y)) = (x, y) {
                        t += &format!(
                            "| {} | {} with {} | {rate} | {} | {} | {} | {} | {} | {} |\n",
                            wl.name().to_uppercase(),
                            sys.name(),
                            peer.name(),
                            ms(x.p50),
                            ms(x.p99),
                            ms_opt(x.p999),
                            ms(y.p50),
                            ms(y.p99),
                            ms_opt(y.p999)
                        );
                    }
                }
            }
        }
        t
    }

    fn table_ceilings(&self) -> String {
        let mut t = String::from(
            "### Table 5. Ceilings by `wrk` (`-t2 -c64`; the criterion `-c100`, `-c200` for W2: errors of connect), one run in each round\n\n| key | requests/s | transfer/s | connect | read | write | timeout | non-2xx | idle % per CPU | alert |\n|---|---|---|---|---|---|---|---|---|---|\n",
        );
        for (k, r) in self.recs.iter().filter(|(k, _)| k.starts_with("ceiling.")) {
            let g = |f: &str| r.get(f).cloned().unwrap_or_default();
            t += &format!(
                "| {k} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                g("per_second"),
                g("transfer"),
                g("connect"),
                g("read"),
                g("write"),
                g("timeout"),
                g("non2xx"),
                g("cpu_idle"),
                g("alert")
            );
        }
        t
    }

    fn table_floor(&self) -> String {
        let mut t = String::from(
            "### Table 6. The floor of the Mac at the rates of each round (Homebrew's nginx on the loopback)\n\n| key | p50 ms | p99 ms | p99.9 ms | p99 of lag ms | Mac load |\n|---|---|---|---|---|---|\n",
        );
        for (k, m) in self.all("floor.r") {
            t += &format!(
                "| {k} | {} | {} | {} | {} | {:.2} |\n",
                ms(m.p50),
                ms(m.p99),
                ms_opt(m.p999),
                ms(m.lag_p99),
                m.load
            );
        }
        t
    }

    fn table_conditions(&self) -> String {
        let mut t = String::from(
            "### Table 7. Conditions of every guest (a round, a system)\n\n| phase | system | MAC | address | Mac load at start | at end | other guests at start | at end | `nginx -T` | `/www` | nginx |\n|---|---|---|---|---|---|---|---|---|---|---|\n",
        );
        for line in std::fs::read_to_string(self.dir.join("boots.tsv"))
            .unwrap_or_default()
            .lines()
        {
            t += &format!("| {} |\n", line.split('\t').collect::<Vec<_>>().join(" | "));
        }
        t
    }

    fn table_w3(&self) -> String {
        let mut t = String::from(
            "### Table 8. W3 by rate (new connection for each request)\n\n| system | rate | achieved/s | answers 200 | failed | p99 ms | counters after | marks |\n|---|---|---|---|---|---|---|---|\n",
        );
        for sys in System::ALL {
            for (k, m) in self.all(&format!("sweep.{}.w3.", sys.name())) {
                if !k.ends_with(".0") {
                    continue;
                }
                t += &format!(
                    "| {} | {} | {:.0} | {} | {} | {} | {} | {} |\n",
                    sys.name(),
                    m.rate,
                    m.achieved,
                    m.ok,
                    m.failed,
                    ms(m.p99),
                    m.counters,
                    m.marks().join(", ")
                );
            }
        }
        t
    }

    /// How far the correction for the lag moved p99 over all the steps.
    fn table_correction(&self) -> String {
        let mut shifts: Vec<f64> = Vec::new();
        let mut late = 0;
        let mut all = 0;
        for (k, m) in self.all("") {
            if k.starts_with("sweep.")
                || k.starts_with("confirm.")
                || k.starts_with("share")
                || k.starts_with("floor.")
            {
                all += 1;
                shifts.push((m.p99 as f64 - m.p99_raw as f64) / 1e3);
                late += usize::from(m.lag_p99 > LAG_MARK_NS);
            }
        }
        format!(
            "### Correction for the lag of the generator\n\nSteps {all}; the correction moved p99 by (us) {}; steps with p99 of lag above 0.5 ms: {late}.\n",
            spread(&shifts, 1)
        )
    }
}

fn tables(dir: &Path) -> Result<String, String> {
    let r = Results::load(dir)?;
    let mut out = String::new();
    for part in [
        r.table_nat(),
        r.table_main(),
        r.table_ratios(),
        r.table_common(),
        r.table_ceilings(),
        r.table_floor(),
        r.table_conditions(),
        r.table_w3(),
        r.table_correction(),
    ] {
        out += &part;
        out += "\n";
    }
    Ok(out)
}

// The command ---------------------------------------------------------------------------

fn tools_present(phases: &[String]) -> Result<(), String> {
    let mut tools = vec![
        ("vegeta", "-version"),
        ("wrk", "--version"),
        ("nginx", "-v"),
    ];
    if phases.iter().any(|p| p == "nat") {
        tools.push(("iperf3", "--version"));
    }
    for (program, flag) in tools {
        Command::new(program)
            .arg(flag)
            .output()
            .map_err(|e| format!("{program}: {e} (brew install vegeta wrk nginx iperf3)"))?;
    }
    Ok(())
}

fn prepare(o: &Options) -> Result<Prepared, String> {
    crate::relibc()?;
    crate::net_build()?;
    let linux = if o.systems.iter().any(|s| s.linux()) {
        linux_guest::build_guest()?
    } else {
        linux_guest::linux_dir()
    };
    let (mut kernel, mut image, mut fast_image) = (PathBuf::new(), PathBuf::new(), PathBuf::new());
    if o.systems.iter().any(|s| !s.linux()) {
        crate::busybox_build()?;
        crate::nano_build()?;
        kernel = build(Variant::Normal)?.image;
        if o.systems.contains(&System::S4) {
            image = match o.image {
                ImageKind::Plain => linux_guest::build_image()?,
                ImageKind::Profile => linux_guest::build_variant(linux_guest::BenchImage::Profile)?,
                ImageKind::Pinned => linux_guest::build_variant(linux_guest::BenchImage::Pinned)?,
                ImageKind::Cpu0 => linux_guest::build_variant(linux_guest::BenchImage::Cpu0)?,
            };
        }
        if o.systems.contains(&System::F1) {
            fast_image = linux_guest::build_fast_image()?;
        }
    }
    let (config, www) = linux_guest::expected()?;
    let (fast_config, _) = linux_guest::expected_fast();
    Ok(Prepared {
        linux,
        kernel,
        image,
        fast_image,
        config,
        fast_config,
        www,
    })
}

fn run(args: &[String]) -> Result<(), String> {
    let o = options(args)?;
    tools_present(&o.phases)?;
    let dir = match &o.resume {
        Some(dir) => std::path::absolute(dir).map_err(|e| format!("{}: {e}", dir.display()))?,
        None => {
            let seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            crate::target_dir()
                .join("net-bench")
                .join(seconds.to_string())
        }
    };
    let (raw, results) = (dir.join("raw"), dir.join("results"));
    for d in [&raw, &results] {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let prep = prepare(&o)?;
    let floor = Floor::start(&dir)?;
    say(format!("run in {}", dir.display()));
    let mut bench = Bench {
        opts: o,
        dir: dir.clone(),
        raw,
        results,
        prep,
        floor: Some(floor),
        guest: None,
        phase: String::new(),
    };
    let phases = bench.opts.phases.clone();
    let result = (|| {
        for phase in &phases {
            match phase.as_str() {
                "nat" => bench.nat()?,
                "sweep" => bench.sweeps()?,
                _ => bench.rounds()?,
            }
        }
        Ok::<(), String>(())
    })();
    bench.release();
    if let Some(floor) = bench.floor.take() {
        floor.stop();
    }
    let text = tables(&dir)?;
    std::fs::write(dir.join("tables.md"), &text).map_err(|e| format!("tables.md: {e}"))?;
    say(format!("tables in {}", dir.join("tables.md").display()));
    result
}

/// `cargo xtask net-bench run|tables`.
pub fn command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("tables") if args.len() == 2 => {
            let text = tables(Path::new(&args[1]))?;
            print!("{text}");
            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(rate: u32, p99_ms: f64) -> Measured {
        Measured {
            rate,
            requests: 1000,
            ok: 1000,
            achieved: f64::from(rate),
            p99: (p99_ms * 1e6) as u64,
            ..Measured::default()
        }
    }

    #[test]
    fn the_rounds_take_a_latin_square_of_three_and_of_four_rows() {
        // Breakage 8: the order of the rounds.
        for rows in [vec!["L1", "L4", "S4"], vec!["L1", "L4", "S4", "F1"]] {
            let n = rows.len() as u32;
            assert_eq!(order(&rows, 1), rows);
            assert_eq!(order(&rows, 2)[0], rows[1]);
            for place in 0..rows.len() {
                let mut seen: Vec<&str> = (1..=n).map(|r| order(&rows, r)[place]).collect();
                seen.sort_unstable();
                let mut all = rows.clone();
                all.sort_unstable();
                assert_eq!(seen, all, "place {place}");
            }
            for round in 1..=2 * n {
                let mut o = order(&rows, round);
                o.sort_unstable();
                let mut all = rows.clone();
                all.sort_unstable();
                assert_eq!(o, all);
            }
        }
        assert_eq!(order(&["L1", "L4", "S4"], 3), ["S4", "L1", "L4"]);
        assert_eq!(order(&["L1", "L4", "S4"], 4), ["L1", "L4", "S4"]);
    }

    #[test]
    fn the_bisection_finds_the_edge_of_a_curve_with_a_dip_below_it() {
        // Breakage 7: the curve is not monotonic. 1 000 a second fails
        // (the guest wakes slowly on rare requests), the edge is 3 400.
        let curve = |rate: u32| match rate {
            1000 => Verdict::Fail,
            r if r <= 3400 => Verdict::Pass,
            r if r < 4000 => Verdict::Fail,
            _ => Verdict::Saturated,
        };
        let mut calls = 0;
        let found = search(&GRID, &mut |r, _| {
            calls += 1;
            Ok(curve(r))
        })
        .unwrap();
        let rstar = found.rstar.unwrap();
        assert!(rstar <= 3400, "{found:?}");
        assert!(f64::from(rstar) >= 3400.0 / 1.05, "{found:?}");
        assert_eq!(found.below, [1000]);
        assert!(
            found.above.unwrap() > 3400
                && f64::from(found.above.unwrap() - rstar) / f64::from(rstar) <= SPREAD
        );
        // The walk stopped at the saturation: nothing above 4 000 was asked.
        assert!(calls < 16 + 8, "{calls}");
    }

    #[test]
    fn a_curve_that_holds_every_rate_of_the_grid_has_no_bisection() {
        let found = search(&GRID, &mut |_, _| Ok(Verdict::Pass)).unwrap();
        assert_eq!(found.rstar, Some(96000));
        assert_eq!(found.above, None);
        let none = search(&GRID, &mut |_, _| Ok(Verdict::Fail)).unwrap();
        assert_eq!(none.rstar, None);
        let low = search(&GRID, &mut |_, _| Ok(Verdict::Saturated)).unwrap();
        assert_eq!(low.rstar, None);
    }

    #[test]
    fn a_noisy_failure_is_taken_again_and_twice_noisy_decides_nothing() {
        // Breakage 13: the floor is noisy at 500 and at 4 000.
        let mut asked: Vec<(u32, u32)> = Vec::new();
        let found = search(&GRID, &mut |rate, attempt| {
            asked.push((rate, attempt));
            Ok(match (rate, attempt) {
                (500, _) => Verdict::Noisy,
                (1500, 0) => Verdict::Noisy,
                (r, _) if r <= 3000 => Verdict::Pass,
                (3500, _) | (4000, _) => Verdict::Noisy,
                _ => Verdict::Saturated,
            })
        })
        .unwrap();
        assert!(asked.contains(&(500, 1)) && asked.contains(&(1500, 1)));
        assert_eq!(found.noisy, [500]);
        // 1 500 passed on the second attempt; 3 000 is the best, and the
        // bisection toward 4 000 stops at the noise: the floor decides.
        assert_eq!(found.rstar, Some(3000));
        assert_eq!(found.floor_decides, Some(3500));
    }

    #[test]
    fn a_failure_the_floor_or_the_generator_or_a_foreign_guest_touched_decides_nothing() {
        // Breakage 13: the rule of the floor.
        let clean = step(1000, 2.0);
        assert_eq!(clean.verdict(), Verdict::Fail);
        // The rule subtracts: p99 minus the floor's p99 and p99 minus the lag
        // must both stay above 1 ms.
        let floor = Measured {
            floor: Some(1_500_000),
            ..step(1000, 2.0)
        };
        assert_eq!(floor.verdict(), Verdict::Noisy);
        assert_eq!(floor.marks(), ["floor"]);
        // A floor above the old flag of 0.5 ms that leaves 1.4 ms is a failure.
        let flagged = Measured {
            floor: Some(600_000),
            lag_p99: 600_000,
            ..step(1000, 2.0)
        };
        assert_eq!(flagged.verdict(), Verdict::Fail);
        assert_eq!(flagged.marks(), ["floor", "generator"]);
        let quiet = Measured {
            floor: Some(400_000),
            ..step(1000, 2.0)
        };
        assert_eq!(quiet.verdict(), Verdict::Fail);
        let generator = Measured {
            lag_p99: 1_200_000,
            ..step(1000, 2.0)
        };
        assert_eq!(generator.verdict(), Verdict::Noisy);
        let foreign = Measured {
            foreign: true,
            ..step(1000, 2.0)
        };
        assert_eq!(foreign.verdict(), Verdict::Noisy);
        // A pass stays a pass on a noisy step: the noise only raises p99.
        assert_eq!(
            Measured {
                floor: Some(900_000),
                ..step(1000, 0.8)
            }
            .verdict(),
            Verdict::Pass
        );
        // Saturation is no noise.
        assert_eq!(
            Measured {
                floor: Some(900_000),
                ..step(1000, 60.0)
            }
            .verdict(),
            Verdict::Saturated
        );
        assert_eq!(
            Measured {
                achieved: 900.0,
                ..step(1000, 0.5)
            }
            .verdict(),
            Verdict::Saturated
        );
        assert_eq!(
            Measured {
                failed: 1,
                ..step(1000, 0.5)
            }
            .verdict(),
            Verdict::Saturated
        );
        assert_eq!(
            Measured {
                alert: Some("[crit]".into()),
                ..step(1000, 0.5)
            }
            .verdict(),
            Verdict::Saturated
        );
    }

    #[test]
    fn a_stall_of_the_generator_raises_the_corrected_p99_and_marks_the_step() {
        // Breakage 6: vegeta stood for 50 ms, then sent the missed
        // requests at once; each answer came in 0.2 ms.
        let rate = 1000;
        let base = 1_700_000_000_000_000_000u64;
        let mut samples = Vec::new();
        for seq in 0..2000u64 {
            let scheduled = base + seq * 1_000_000;
            let at = if (1000..1050).contains(&seq) {
                base + 1050 * 1_000_000
            } else {
                scheduled
            };
            samples.push(Sample {
                at,
                code: 200,
                latency: 200_000,
                seq,
            });
        }
        let m = measure(&samples, rate, 10, 0);
        // As vegeta counts it the stall is not there.
        assert_eq!(m.p99_raw, 200_000);
        assert!(m.p99 > P99_LIMIT_NS, "{}", m.p99);
        assert!(m.lag_p99 > LAG_MARK_NS && m.lag_max >= 49_000_000);
        assert!(m.marks().contains(&"generator"));
        assert_eq!(m.verdict(), Verdict::Noisy);
        // Without the stall the correction moves nothing.
        let even: Vec<Sample> = (0..2000u64)
            .map(|seq| Sample {
                at: base + seq * 1_000_000,
                code: 200,
                latency: 200_000,
                seq,
            })
            .collect();
        let m = measure(&even, rate, 10, 0);
        assert_eq!((m.p99, m.p99_raw), (200_000, 200_000));
        assert_eq!(m.verdict(), Verdict::Pass);
    }

    #[test]
    fn a_run_is_stretched_to_100000_requests_up_to_the_cap() {
        // Breakage 14.
        assert_eq!(run_seconds(1000, 300, 1200), (300, true));
        assert_eq!(run_seconds(334, 300, 1200), (300, true));
        assert_eq!(run_seconds(300, 300, 1200), (334, true));
        assert_eq!(run_seconds(100, 300, 1200), (1000, true));
        assert_eq!(run_seconds(80, 300, 1200), (300, false));
        assert_eq!(run_seconds(1000, 60, 1200), (100, true));
        assert_eq!(run_seconds(2000, 60, 1200), (60, true));
        // p99.9 of a measured run needs the requests too.
        let few: Vec<Sample> = (0..99_999u64)
            .map(|seq| Sample {
                at: seq * 1_000_000,
                code: 200,
                latency: 1,
                seq,
            })
            .collect();
        assert_eq!(measure(&few, 1000, 1, 0).p999, None);
        let enough: Vec<Sample> = (0..100_000u64)
            .map(|seq| Sample {
                at: seq * 1_000_000,
                code: 200,
                latency: 1,
                seq,
            })
            .collect();
        assert_eq!(measure(&enough, 1000, 1, 0).p999, Some(1));
    }

    #[test]
    fn the_confirmation_needs_three_passes_in_a_row_and_steps_back_on_a_failure() {
        let mut c = Confirm::new(1000);
        c.step(Verdict::Pass);
        c.step(Verdict::Pass);
        assert!(!c.done());
        c.step(Verdict::Fail);
        assert_eq!((c.passes, c.rstar, c.retreats), (0, 950, 1));
        // A run that fails under noise is no pass either (all three must pass).
        c.step(Verdict::Pass);
        c.step(Verdict::Noisy);
        assert_eq!((c.passes, c.rstar, c.retreats), (0, 902, 2));
        for _ in 0..3 {
            c.step(Verdict::Pass);
        }
        assert!(c.done() && !c.unproven && c.rstar == 902);
        let mut c = Confirm::new(1000);
        for _ in 0..4 {
            c.step(Verdict::Saturated);
        }
        assert!(c.done() && c.unproven && c.retreats == 3);
        assert_eq!(c.rstar, 856);
    }

    fn stat(cpus: &[[u64; 4]]) -> Vec<String> {
        let mut lines = vec!["cpu  1 1 1 1 0 0 0 0".to_owned()];
        for (i, c) in cpus.iter().enumerate() {
            lines.push(format!("cpu{i} {} 0 {} {} 0 0 0 0 0 0", c[0], c[1], c[2]));
        }
        lines
    }

    #[test]
    fn the_cpus_of_the_guest_give_idle_shares_and_time_per_answer() {
        let before = parse_stat(&stat(&[[0, 0, 0, 0]; 4]));
        let after = parse_stat(&stat(&[
            [300, 100, 600, 0],
            [100, 0, 900, 0],
            [0, 0, 1000, 0],
            [500, 500, 0, 0],
        ]));
        assert_eq!(before.len(), 4);
        let u = cpu_use(&before, &after, 4, 10_000);
        assert!(u.known);
        assert_eq!(u.idle, [60.0, 90.0, 100.0, 0.0]);
        // 1 000 busy jiffies of 10 ms over 10 000 answers: 1 000 us each.
        assert!((u.busy_us - (400.0 + 100.0 + 0.0 + 1000.0) * 10_000.0 / 10_000.0).abs() < 1e-6);
        // Idle time of Linux holds iowait: 4th and 5th fields.
        let io = parse_stat(&["cpu0 10 0 10 70 10 0 0 0".to_owned()]);
        assert_eq!(io, [(20, 80)]);
    }

    #[test]
    fn a_proc_stat_with_one_line_leaves_the_cpus_unknown() {
        // Breakage 5: the layer prints `cpu0` with all the time.
        let one = parse_stat(&["cpu0 100 0 100 0 0 0 0 0".to_owned()]);
        assert_eq!(one.len(), 1);
        let u = cpu_use(&one, &one, 4, 1000);
        assert!(!u.known && u.idle.is_empty());
        // The aggregate line `cpu` does not count as a CPU.
        assert_eq!(parse_stat(&["cpu 5 5 5 5 5 5 5 5".to_owned()]).len(), 0);
        let m = Measured {
            cpu: Some(u),
            ..step(1000, 0.5)
        };
        assert!(!Measured::of(&m.rec()).unwrap().cpu.unwrap().known);
    }

    #[test]
    fn the_times_of_the_processes_are_read_and_divided_by_the_answers() {
        let lines: Vec<String> = [
            "12 (sh) S 1 12 12 0 0 0 0 0 0 0 300 20 0 0 20 0",
            "30 (nginx) S 1 30 30 0 0 0 0 0 0 0 100 10 0 0 20 0",
            "31 (nginx) S 1 30 30 0 0 0 0 0 0 0 50 0 0 0 20 0",
            "40 (a (b) c) S 1 40 40 0 0 0 0 0 0 0 7 1 0 0 20 0",
            "not a stat line",
        ]
        .map(str::to_owned)
        .to_vec();
        let before = parse_proc_times(&lines);
        assert_eq!(before.len(), 4);
        assert_eq!(before[0].jiffies, 320);
        assert_eq!((before[3].pid, before[3].name.as_str()), (40, "a (b) c"));
        assert_eq!(before[3].jiffies, 8);
        let mut after = before.clone();
        after[0].jiffies += 100;
        after[1].jiffies += 50;
        after[2].jiffies += 25;
        after.push(Proc {
            pid: 50,
            name: "nginx".into(),
            jiffies: 25,
            cpu: 3,
        });
        // 100 jiffies of netd over 1000 answers: 1 s over 1000 = 1000 us.
        let used = proc_use(&before, &after, 1000);
        assert_eq!(used[0], ("sh".to_owned(), 1000.0));
        assert_eq!(used[1], ("nginx".to_owned(), 1000.0));
        assert!(proc_use(&before, &after, 0).is_empty());
        assert_eq!(procs_of(&procs_text(&used)), used);
    }

    #[test]
    fn the_cpu_of_a_process_is_field_39_and_the_irq_columns_are_read() {
        // 36 fields after the name put `processor` at index 36.
        let mut fields = vec!["0"; 37];
        fields[0] = "S";
        fields[36] = "2";
        let line = format!("30 (nginx) {}", fields.join(" "));
        let procs = parse_proc_times(&[line]);
        assert_eq!(procs[0].cpu, 2);
        assert_eq!(placed_text(&procs), "nginx=2");
        let stat = [
            "cpu  9 9 9 9 9 9 9 9".to_owned(),
            "cpu0 1 0 2 3 0 4 5 0".to_owned(),
            "cpu1 1 0 2 3 0 6 7 0".to_owned(),
        ];
        assert_eq!(parse_irq(&stat), (10, 12));
    }

    #[test]
    fn a_profile_snapshot_is_taken_whole_and_its_change_is_the_difference() {
        let lines: Vec<String> = [
            "net: prof 1 step_rx 10 step_tx 5",
            "net: prof 1 ring_max 70 call_max 90",
            "net: prof 2 step_rx 30 step_tx 9",
            "net: prof 2 ring_max 40",
            "boot noise",
        ]
        .map(str::to_owned)
        .to_vec();
        // Snapshot 2 has no call_max yet: the whole one is 1.
        let (id, first) = parse_profile(&lines).unwrap();
        assert_eq!(id, 1);
        assert_eq!(first[0], ("step_rx".to_owned(), 10));
        assert_eq!(first.len(), 4);
        let mut more = lines.clone();
        more.push("net: prof 2 call_max 80 c5 3".to_owned());
        let (id, second) = parse_profile(&more).unwrap();
        assert_eq!(id, 2);
        let change = profile_change(&first, &second);
        assert_eq!(change[0], ("step_rx".to_owned(), 20.0));
        let find = |name: &str| change.iter().find(|(n, _)| n == name).unwrap().1;
        assert_eq!(find("ring_max"), 40.0);
        assert_eq!(find("c5"), 3.0);
        assert!(parse_profile(&lines[2..]).is_none());
    }

    #[test]
    fn the_image_option_is_read_and_refused() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(options(&args(&[])).unwrap().image, ImageKind::Plain);
        assert_eq!(
            options(&args(&["--image", "pinned"])).unwrap().image,
            ImageKind::Pinned
        );
        assert_eq!(
            options(&args(&["--image", "cpu0"])).unwrap().image,
            ImageKind::Cpu0
        );
        assert!(options(&args(&["--image", "x"])).is_err());
    }

    #[test]
    fn a_step_survives_its_record() {
        let m = Measured {
            seconds: 60,
            p999: Some(1_500_000),
            floor: Some(300_000),
            foreign: true,
            load: 3.25,
            cpu: Some(CpuUse {
                idle: vec![10.5, 20.0, 30.0, 40.0],
                busy_us: 12.5,
                known: true,
                procs: vec![("nginx".into(), 50.5), ("sh".into(), 2.25)],
                irq_us: 1.5,
                softirq_us: 3.25,
                placed: "nginx=0,1,2,3".into(),
                profile: vec![("step_rx".into(), 120.0), ("ring_max".into(), 900.0)],
            }),
            counters: "ListenDrops 0 ListenOverflows 0".into(),
            alert: Some("nginx [crit] x=y".into()),
            mbps: 25.6,
            ..step(1000, 0.8)
        };
        let back = Measured::of(&rec_of(&rec_text(&m.rec()))).unwrap();
        assert_eq!(back, m);
        let plain = step(500, 0.1);
        assert_eq!(
            Measured::of(&rec_of(&rec_text(&plain.rec()))).unwrap(),
            plain
        );
    }

    #[test]
    fn the_numbers_of_the_tools_are_read() {
        let json = r#"{"end":{"sum_sent":{"bits_per_second":900000000.5},"sum_received":{"start":0,"bits_per_second":8.5e8,"sender":false}}}"#;
        assert!((parse_iperf(json, false).unwrap() - 850.0).abs() < 1e-6);
        let udp = r#"{"end":{"streams":[{"udp":{"packets":9}}],"sum":{"start":0,"end":10.0,"seconds":10,"bytes":1,"packets":500000,"lost_packets":0}}}"#;
        assert!((parse_iperf(udp, true).unwrap() - 50_000.0).abs() < 1e-6);
        assert_eq!(parse_iperf("{}", false), None);
        let net = vec![
            "TcpExt: SyncookiesSent ListenOverflows ListenDrops TW".to_owned(),
            "TcpExt: 0 7 9 100".to_owned(),
        ];
        assert_eq!(netstat_value(&net, "ListenDrops"), Some(9));
        assert_eq!(netstat_value(&net, "ListenOverflows"), Some(7));
        assert_eq!(netstat_value(&net, "Nope"), None);
        assert_eq!(transfer_bytes("38.46MB"), Some(38.46e6));
        assert_eq!(transfer_bytes("1.5GB"), Some(1.5e9));
        assert_eq!(transfer_bytes("512.00B"), Some(512.0));
        assert_eq!(
            first_limit(&[50.0, 3.0, 20.0, 10.0], None, None, true),
            "guest CPU"
        );
        assert_eq!(
            first_limit(&[50.0; 4], Some(900.0), Some(1000.0), false),
            "NAT"
        );
        assert_eq!(
            first_limit(&[50.0; 4], Some(100.0), Some(1000.0), true),
            "generator"
        );
        assert_eq!(first_limit(&[50.0; 4], None, None, false), "not determined");
        assert_eq!(spread(&[3.0, 1.0, 2.0], 1), "2.0 [1.0; 3.0]");
        assert_eq!(spread(&[4.0], 0), "4");
        assert_eq!(spread(&[], 0), "-");
    }

    #[test]
    fn the_sets_and_the_grids_of_the_loads() {
        assert_eq!(Workload::W1.paths().len(), 900);
        assert_eq!(Workload::W1.paths(), Workload::W3.paths());
        assert_eq!(Workload::W2.paths().len(), 64);
        assert_eq!(Workload::W1.grid(), GRID);
        let new = Workload::W3.grid();
        assert_eq!(new[..6], GRID_NEW);
        assert_eq!(new[6], 1500);
        assert_eq!(new.len(), 6 + 13);
        assert!(new.windows(2).all(|w| w[0] < w[1]));
        let script = wrk_script(&["/a".into(), "/b".into()], false);
        assert!(script.contains("\"/a\",\"/b\"") && script.contains("Connection"));
        assert!(!wrk_script(&["/a".into()], true).contains("Connection"));
        assert_eq!(System::S4.peer(), Some(System::L4));
        assert_eq!(System::F1.peer(), Some(System::L1));
        assert_eq!(System::of("f1"), Some(System::F1));
        assert!(!System::F1.linux());
        assert_eq!(System::F1.workers(), 1);
        assert_eq!(System::of("l1"), Some(System::L1));
    }

    #[test]
    fn the_options_are_read_and_refused() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let o = options(&args(&[
            "--systems",
            "s4,l4",
            "--workloads",
            "w3",
            "--stage",
            "20",
            "--max-rate",
            "4000",
        ]))
        .unwrap();
        assert_eq!(o.systems, [System::S4, System::L4]);
        assert_eq!(
            (o.workloads.clone(), o.stage, o.max_rate),
            (vec![Workload::W3], 20, Some(4000))
        );
        let q = options(&args(&["--quick"])).unwrap();
        assert!(q.stage < 60 && q.confirm < 300);
        assert!(options(&args(&["--systems", "x9"])).is_err());
        assert!(options(&args(&["--phases", "sweep,fly"])).is_err());
        assert!(options(&args(&["--rounds"])).is_err());
        assert!(options(&args(&["--rounds", "0"])).is_err());
        assert!(options(&args(&["--nope"])).is_err());
        assert!(command(&[]).is_err());
    }

    #[test]
    fn the_tables_come_from_the_records() {
        let dir = std::env::temp_dir().join(format!("net-bench-tables-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("results")).unwrap();
        let put = |key: &str, rec: Rec| {
            std::fs::write(
                dir.join("results").join(format!("{key}.rec")),
                rec_text(&rec),
            )
            .unwrap()
        };
        for (sys, rstar) in [("S4", 1500u32), ("L4", 3000)] {
            let mut search = Rec::new();
            search.insert("rstar".into(), rstar.to_string());
            search.insert("above".into(), (rstar * 3 / 2).to_string());
            search.insert("below".into(), "250".into());
            put(&format!("search.{sys}.w1"), search);
            let mut state = Rec::new();
            for (k, v) in [
                ("rstar", rstar.to_string()),
                ("passes", "3".into()),
                ("unproven", "false".into()),
            ] {
                state.insert(k.into(), v);
            }
            put(&format!("confirmstate.{sys}.w1"), state);
            for round in 1..=3 {
                put(
                    &format!("confirm.r{round}.{sys}.w1.0"),
                    step(rstar, 0.7).rec(),
                );
            }
            put(&format!("sweep.{sys}.w1.1000.0"), step(1000, 0.5).rec());
        }
        // The ceilings of the first round, paired, and the load of the guests.
        for (sys, rps) in [("S4", 3300.0), ("L4", 100_000.0)] {
            let mut r = Rec::new();
            r.insert("per_second".into(), format!("{rps}"));
            put(&format!("ceiling.r1.{sys}.w1.c64"), r);
        }
        std::fs::write(
            dir.join("boots.tsv"),
            "round 1\tS4\tmac\taddr\t2.00\t3.00\tx\ty\tz\tw\tv\nround 1\tL4\tmac\taddr\t1.00\t1.50\tx\ty\tz\tw\tv\n",
        )
        .unwrap();
        let text = tables(&dir).unwrap();
        // The search is not replayable from these few steps: as recorded.
        assert!(
            text.contains("| W1 | S4 | 4 | 1500 (2250) (as recorded, old rule) | 1500 | 3 of 3 |"),
            "{text}"
        );
        assert!(
            text.contains("| W1 | L4 | 4 | 3000 (4500) (as recorded, old rule) | 3000 | 3 of 3 |"),
            "{text}"
        );
        // Table 2a: the whole rows, by R* and paired by the ceilings.
        assert!(text.contains("| W1 | 1500 | 3000 | 0.50 |"), "{text}");
        assert!(
            text.contains("| W1 | 1 | 3300 | 100000 | 0.0330 | 2.00 / 3.00 | 1.00 / 1.50 |"),
            "{text}"
        );
        assert!(text.contains("| W1 | S4 with L4 | 1000 |"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_tables_recompute_the_search_and_the_confirmation_under_the_present_rule() {
        let dir = std::env::temp_dir().join(format!("net-bench-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("results")).unwrap();
        let put = |key: &str, m: &Measured| {
            std::fs::write(
                dir.join("results").join(format!("{key}.rec")),
                rec_text(&m.rec()),
            )
            .unwrap()
        };
        let mut found = Rec::new();
        found.insert("rstar".into(), "2000".into());
        std::fs::write(dir.join("results/search.S4.w1.rec"), rec_text(&found)).unwrap();
        // 250 to 1 000 pass; 1 500 took p99 1.8 ms with a floor of 0.6 ms, which
        // the old flag at 0.5 ms forgave and the subtraction (1.2 ms left) does not; 2 000
        // saturates; the bisection asks for 1 250, 1 375 and 1 312.
        for rate in [250, 500, 1000, 1250, 1312] {
            put(&format!("sweep.S4.w1.{rate}.0"), &step(rate, 0.8));
        }
        let fail = Measured {
            floor: Some(600_000),
            ..step(1500, 1.8)
        };
        put("sweep.S4.w1.1500.0", &fail);
        put(
            "sweep.S4.w1.1375.0",
            &Measured {
                rate: 1375,
                ..fail.clone()
            },
        );
        put("sweep.S4.w1.2000.0", &step(2000, 80.0));
        // Confirmation: three runs at 1 000, the second failing under noise.
        for (round, p99) in [(1, 0.8), (2, 1.8), (3, 0.9)] {
            let m = Measured {
                floor: Some(600_000),
                ..step(1000, p99)
            };
            put(&format!("confirm.r{round}.S4.w1.0"), &m);
        }
        let text = tables(&dir).unwrap();
        assert!(text.contains("| W1 | S4 | 4 | 1312 (1375) |"), "{text}");
        assert!(!text.contains("old rule"), "{text}");
        // Two of three: not confirmed, and the row says so.
        assert!(text.contains("| 1000 (not confirmed) | 2 of 3 |"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
