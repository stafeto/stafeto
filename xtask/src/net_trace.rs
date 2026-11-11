// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask net-trace`: where the time of a request goes. The images with the time stamps
//! (`net-bench run --trace`, which needs STAFETO_TRACE=1) dump their rings to the console as
//! lines `tr <label> <point> <ticks> <key>` (lib/trace); this reads them from the console logs
//! of a run, joins the records of the network service and of the workers by the key of the
//! frame and prints, for each path, the median, p90 and p99 of each segment between consecutive
//! points and its share of the round trip, and how often each stage found its queue empty and
//! slept.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: cargo xtask net-trace run [net-bench run options] | show [--worst N] [--from-us T --to-us T] FILE|DIR...";
/// The counter of the archived logs that do not give its frequency in the point-0 line: the generic
/// counter of VZ, 24 MHz, in ticks per microsecond.
const DEFAULT_TICKS_PER_US: f64 = 24.0;
/// How far before its first keyed point a loose point at the start of a path may lie.
const LOOK_BACK_US: f64 = 1000.0;

// The points, as in lib/trace.
const N_WAKE: u8 = 1;
const N_STEP: u8 = 2;
const N_RX: u8 = 3;
const N_TO_CONSUMER: u8 = 4;
const N_TO_STACK: u8 = 5;
const N_CWAKE: u8 = 6;
const N_CSKIP: u8 = 7;
const N_TX_SEEN: u8 = 8;
const N_STK_TX: u8 = 9;
const N_TX_SUBMIT: u8 = 10;
const N_BELL: u8 = 11;
const N_BELL_SKIP: u8 = 12;
const N_WAKE_STACK: u8 = 13;
const N_STK_BEGIN: u8 = 14;
const N_STK_END: u8 = 15;
const N_REQ_BEGIN: u8 = 16;
const N_REQ_END: u8 = 17;
const W_WAKE: u8 = 32;
const W_RX: u8 = 33;
const W_TX: u8 = 34;
const W_KICK: u8 = 35;
const W_SLEEP: u8 = 36;
const W_FOUND: u8 = 37;
const C_SEND: u8 = 48;
const C_RET: u8 = 49;
const C_EPOLL: u8 = 50;
const C_EPOLL_RET: u8 = 51;

// The points of the kernel's time stamps (abi::STAMP_*), the causes of a thread made ready (abi::WAKE_*)
// and the line of the virtual timer, whose interrupts are not those of a device.
const K_IRQ: u8 = abi::STAMP_IRQ;
const K_READY: u8 = abi::STAMP_READY;
const K_RUN: u8 = abi::STAMP_RUN;
const K_SGI_SENT: u8 = abi::STAMP_SGI_SENT;
const K_SGI_GOT: u8 = abi::STAMP_SGI_GOT;
const K_WFI: u8 = abi::STAMP_WFI;
const WAKE_COMMAND: u8 = abi::WAKE_COMMAND;
const TIMER_LINE: u32 = kcore::gic::VIRTUAL_TIMER_INTID;
/// The records of a ring of the kernel (kernel/src/stamps.rs `RECORDS`): a CPU that gave this many
/// has written over its older ones.
const KERNEL_RING: usize = 8192;
/// How far before the first record of a frame the interrupt that brought it may lie.
const IRQ_LOOK_BACK_US: f64 = 5000.0;

/// A record of the ring of a CPU of the kernel (the lines `tr k<cpu> <point> <ticks> <key>`):
/// the key of a thread made ready holds its number below, the cause in bits 16-23 and its CPU in
/// bits 24-31; that of an SGI sent the target CPU and, in bit 8, whether the SGI was sent (a
/// polling CPU takes the bell alone); that of a thread that got the CPU its number; that of
/// `wfi` 0 for the entry and 1 for the exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Kev {
    t: u64,
    cpu: u8,
    point: u8,
    key: u32,
}

/// The number of the CPU in the label `k<cpu>` of a ring of the kernel.
fn kernel_cpu(label: &str) -> Option<u8> {
    label.strip_prefix('k')?.parse().ok()
}

/// What the dump says of each ring of the kernel: its CPU, the records it made and the records it
/// gave (the line `tr k<cpu> 0 <made> <given>` after them).
fn kernel_given(text: &str) -> Vec<(u8, u64, u64)> {
    text.lines()
        .filter_map(|line| {
            let mut w = line.split_whitespace();
            (w.next()? == "tr").then_some(())?;
            let cpu = kernel_cpu(w.next()?)?;
            (u8::from_str_radix(w.next()?, 16).ok()? == 0).then_some(())?;
            let made = u64::from_str_radix(w.next()?, 16).ok()?;
            let given = u64::from_str_radix(w.next()?, 16).ok()?;
            Some((cpu, made, given))
        })
        .collect()
}

/// The records of the rings of the kernel in a console log, in time order.
fn parse_kernel(text: &str) -> Vec<Kev> {
    let mut out: Vec<Kev> = text
        .lines()
        .filter_map(|line| {
            let mut w = line.split_whitespace();
            (w.next()? == "tr").then_some(())?;
            let cpu = kernel_cpu(w.next()?)?;
            let point = u8::from_str_radix(w.next()?, 16).ok()?;
            let t = u64::from_str_radix(w.next()?, 16).ok()?;
            let key = u32::from_str_radix(w.next()?, 16).ok()?;
            // The line that ends the records of a CPU (`kernel_given`), no record.
            (point != 0).then_some(Kev { t, cpu, point, key })
        })
        .collect();
    out.sort_by_key(|k| k.t);
    out
}

#[derive(Clone, Debug)]
struct Ev {
    t: u64,
    id: u8,
    key: u32,
    label: String,
}

/// The records of the lines `tr ...` of a console log, in time order, and the ticks per
/// microsecond: the counter's frequency in Hz is the fifth field of a point-0 line.
fn parse(text: &str) -> (Vec<Ev>, f64) {
    let mut ticks_per_us = DEFAULT_TICKS_PER_US;
    let mut out: Vec<Ev> = text
        .lines()
        .filter_map(|line| {
            let mut w = line.split_whitespace();
            (w.next()? == "tr").then_some(())?;
            let label = w.next()?.to_owned();
            if kernel_cpu(&label).is_some() {
                return None;
            }
            let id = u8::from_str_radix(w.next()?, 16).ok()?;
            let t = u64::from_str_radix(w.next()?, 16).ok()?;
            let key = u32::from_str_radix(w.next()?, 16).ok()?;
            if id == 0
                && let Some(hz) = w.next().and_then(|v| u64::from_str_radix(v, 16).ok())
                && hz > 0
            {
                ticks_per_us = hz as f64 / 1e6;
            }
            Some(Ev { t, id, key, label })
        })
        .collect();
    out.sort_by_key(|e| e.t);
    (out, ticks_per_us)
}

/// The records of the frames, which carry the key of a segment: the span of these records is the
/// load of a run (a ring also holds what its component did before and after the load).
const FRAME_POINTS: [u8; 8] = [
    N_RX,
    N_TO_CONSUMER,
    N_TO_STACK,
    N_TX_SEEN,
    N_STK_TX,
    N_TX_SUBMIT,
    W_RX,
    W_TX,
];

/// The load window of a run: from the first to the last keyed record of a frame in any ring.
fn load_window(events: &[Ev]) -> Option<(u64, u64)> {
    let mut times = events
        .iter()
        .filter(|e| e.key != 0 && FRAME_POINTS.contains(&e.id))
        .map(|e| e.t);
    let first = times.next()?;
    Some(times.fold((first, first), |(lo, hi), t| (lo.min(t), hi.max(t))))
}

/// A point of a chain: the first record of a point with the key of the request, or the first
/// record of any of `ids` between the points around it.
#[derive(Clone, Copy)]
enum Step {
    Key(u8, &'static str),
    Next(&'static [u8], &'static str),
}

const SWITCH_PATH: &[Step] = &[
    Step::Key(N_RX, "rx"),
    Step::Key(N_TO_CONSUMER, "ring"),
    Step::Next(&[N_CWAKE, N_CSKIP], "cwake"),
    Step::Next(&[W_WAKE], "wwake"),
    Step::Key(W_RX, "wrx"),
    Step::Key(W_TX, "wtx"),
    Step::Next(&[W_KICK], "kick"),
    Step::Next(&[N_WAKE, N_STEP], "swake"),
    Step::Key(N_TX_SEEN, "seen"),
    Step::Key(N_TX_SUBMIT, "submit"),
    Step::Next(&[N_BELL, N_BELL_SKIP], "bell"),
];

const STACK_PATH: &[Step] = &[
    Step::Key(N_RX, "rx"),
    Step::Key(N_TO_STACK, "to_stack"),
    Step::Next(&[N_WAKE_STACK], "wake_stack"),
    Step::Next(&[N_STK_BEGIN], "step"),
    Step::Key(N_STK_TX, "stk_tx"),
    Step::Key(N_TX_SUBMIT, "submit"),
    Step::Next(&[N_BELL, N_BELL_SKIP], "bell"),
];

const OWN_PATH: &[Step] = &[
    Step::Next(&[W_WAKE], "wake"),
    Step::Key(W_RX, "wrx"),
    Step::Key(W_TX, "wtx"),
    Step::Next(&[W_KICK], "kick"),
];

/// Statistics of a list of microsecond values: count, median, p90, p99.
fn stats(values: &mut [f64]) -> (usize, f64, f64, f64) {
    values.sort_by(|a, b| a.total_cmp(b));
    let at = |q: f64| values[((values.len() as f64 - 1.0) * q).round() as usize];
    if values.is_empty() {
        return (0, 0.0, 0.0, 0.0);
    }
    (values.len(), at(0.5), at(0.9), at(0.99))
}

/// A point of a chain being built: its name, its time if keyed, the points it may be.
type Point = (&'static str, Option<u64>, Option<&'static [u8]>);

/// The loose records of a point in time order: of `worker` for the points of workers.
fn loose_of<'a>(
    all: &'a HashMap<u8, Vec<u64>>,
    by_label: &'a HashMap<u8, HashMap<&str, Vec<u64>>>,
    id: u8,
    worker: Option<&str>,
) -> &'a [u64] {
    let list = match worker {
        Some(w) if id >= W_WAKE => by_label.get(&id).and_then(|m| m.get(w)),
        _ => all.get(&id),
    };
    list.map_or(&[][..], Vec::as_slice)
}

/// The chain of every request that has all its keyed points: the points with their times. A
/// loose point of a worker (a wake-up, a poke) belongs to the chain only when the worker that
/// took the frame recorded it; the first loose point of a path lies at most `LOOK_BACK_US` before
/// the first keyed point.
fn chains(events: &[Ev], path: &[Step], ticks_per_us: f64) -> Vec<Vec<(&'static str, u64)>> {
    let mut keyed: HashMap<u32, Vec<&Ev>> = HashMap::new();
    let mut all: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut by_label: HashMap<u8, HashMap<&str, Vec<u64>>> = HashMap::new();
    for e in events {
        if e.key != 0 || e.id == N_WAKE {
            keyed.entry(e.key).or_default().push(e);
        }
        all.entry(e.id).or_default().push(e.t);
        by_label
            .entry(e.id)
            .or_default()
            .entry(e.label.as_str())
            .or_default()
            .push(e.t);
    }
    let look_back = (LOOK_BACK_US * ticks_per_us) as u64;
    let of = |id: u8, worker: Option<&str>| loose_of(&all, &by_label, id, worker);
    let mut out = Vec::new();
    for (key, list) in keyed {
        if key == 0 {
            continue;
        }
        let find = |id: u8| list.iter().filter(|e| e.id == id).map(|e| e.t).min();
        // The worker that took the frame.
        let worker = list
            .iter()
            .filter(|e| e.id == W_RX)
            .min_by_key(|e| e.t)
            .map(|e| e.label.as_str());
        let mut points: Vec<Point> = Vec::new();
        for step in path {
            match *step {
                Step::Key(id, name) => points.push((name, find(id), None)),
                Step::Next(ids, name) => points.push((name, None, Some(ids))),
            }
        }
        if points
            .iter()
            .any(|(_, t, ids)| t.is_none() && ids.is_none())
        {
            continue;
        }
        // The time order of the keyed points must hold; the loose ones go in between.
        let mut chain: Vec<(&'static str, u64)> = Vec::new();
        let mut last = 0;
        let mut ok = true;
        for (i, (name, t, ids)) in points.iter().enumerate() {
            match (t, ids) {
                (Some(t), _) => {
                    if *t < last {
                        ok = false;
                        break;
                    }
                    last = *t;
                    chain.push((name, *t));
                }
                (None, Some(ids)) => {
                    let next = points[i + 1..].iter().find_map(|p| p.1).unwrap_or(u64::MAX);
                    let found = if chain.is_empty() {
                        // At the start of a path the point is the last one before the first
                        // keyed point, not older than the look-back.
                        ids.iter()
                            .filter_map(|id| {
                                let times = of(*id, worker);
                                let at = times.partition_point(|t| *t < next);
                                at.checked_sub(1).map(|i| times[i])
                            })
                            .max()
                            .filter(|t| next == u64::MAX || next - t <= look_back)
                    } else {
                        ids.iter()
                            .filter_map(|id| {
                                let times = of(*id, worker);
                                let at = times.partition_point(|t| *t <= last);
                                times.get(at).copied().filter(|t| *t < next)
                            })
                            .min()
                    };
                    if let Some(t) = found {
                        last = t;
                        chain.push((name, t));
                    }
                }
                _ => {}
            }
        }
        if ok && chain.len() >= 2 {
            out.push(chain);
        }
    }
    out
}

/// The table of a path: each segment between consecutive points present, over all requests,
/// with its share of the median round trip.
fn path_table(
    name: &str,
    chains: &[Vec<(&'static str, u64)>],
    worst: usize,
    tpu: f64,
    out: &mut String,
) {
    if chains.is_empty() {
        return;
    }
    let mut totals: Vec<f64> = chains
        .iter()
        .map(|c| (c[c.len() - 1].1 - c[0].1) as f64 / tpu)
        .collect();
    let (n, med, p90, p99) = stats(&mut totals);
    out.push_str(&format!(
        "\n### {name}: {n} requests, round trip in the guest median {med:.1} us, p90 {p90:.1}, p99 {p99:.1}\n\n"
    ));
    out.push_str("| segment | requests | median us | p90 us | p99 us | share of the median round trip |\n|---|---|---|---|---|---|\n");
    let mut segments: Vec<((&str, &str), Vec<f64>)> = Vec::new();
    for c in chains {
        for pair in c.windows(2) {
            let key = (pair[0].0, pair[1].0);
            let us = (pair[1].1 - pair[0].1) as f64 / tpu;
            match segments.iter_mut().find(|(k, _)| *k == key) {
                Some((_, v)) => v.push(us),
                None => segments.push((key, vec![us])),
            }
        }
    }
    for ((a, b), mut v) in segments {
        let (n, m, p90, p99) = stats(&mut v);
        out.push_str(&format!(
            "| {a} to {b} | {n} | {m:.1} | {p90:.1} | {p99:.1} | {:.0} % |\n",
            m / med * 100.0
        ));
    }
    if worst > 0 {
        let mut order: Vec<&Vec<(&str, u64)>> = chains.iter().collect();
        order.sort_by_key(|c| std::cmp::Reverse(c[c.len() - 1].1 - c[0].1));
        out.push_str(&format!(
            "\nThe {worst} slowest requests (us from the first point, point by point):\n\n"
        ));
        for c in order.iter().take(worst) {
            let t0 = c[0].1;
            let line: Vec<String> = c
                .iter()
                .map(|(n, t)| format!("{n} {:.0}", (*t - t0) as f64 / tpu))
                .collect();
            out.push_str(&format!("* {}\n", line.join(", ")));
        }
    }
}

/// How often each stage found its queue empty and slept, and the other counts of the stages.
fn counts(events: &[Ev], requests: usize, out: &mut String) {
    let count = |ids: &[u8]| events.iter().filter(|e| ids.contains(&e.id)).count();
    let per = |n: usize| {
        if requests == 0 {
            0.0
        } else {
            n as f64 / requests as f64
        }
    };
    out.push_str("\n### Stages: events in the rings, and per request seen\n\n| stage | events | per request |\n|---|---|---|\n");
    let rows: [(&str, &[u8]); 13] = [
        ("switch woken by an interrupt", &[N_WAKE]),
        ("switch step", &[N_STEP]),
        ("consumer woken (its ring was idle)", &[N_CWAKE]),
        ("consumer not woken (running)", &[N_CSKIP]),
        ("stack thread woken", &[N_WAKE_STACK]),
        ("worker woke from its wait", &[W_WAKE]),
        ("worker slept (queue empty)", &[W_SLEEP]),
        ("worker found a frame before sleeping", &[W_FOUND]),
        ("worker poke or doorbell", &[W_KICK]),
        ("doorbell of the device rung", &[N_BELL]),
        ("doorbell of the device skipped", &[N_BELL_SKIP]),
        ("call of a socket sent", &[C_SEND]),
        ("epoll_pwait entered", &[C_EPOLL]),
    ];
    for (name, ids) in rows {
        let n = count(ids);
        if n > 0 {
            out.push_str(&format!("| {name} | {n} | {:.2} |\n", per(n)));
        }
    }
}

/// Durations between a begin and an end of the same thread or component: the calls of a
/// socket (sent to returned, per worker), the requests of the service, the steps of the stack,
/// within the load window (a ring also holds the idle time before and after the load).
fn durations(events: &[Ev], begin: u8, end: u8, window: Option<(u64, u64)>, tpu: f64) -> Vec<f64> {
    let mut open: HashMap<&str, u64> = HashMap::new();
    let mut out = Vec::new();
    for e in events {
        if window.is_some_and(|(from, to)| e.t < from || e.t > to) {
            continue;
        }
        if e.id == begin {
            open.insert(e.label.as_str(), e.t);
        } else if e.id == end
            && let Some(t) = open.remove(e.label.as_str())
        {
            out.push((e.t - t) as f64 / tpu);
        }
    }
    out
}

/// The name of a point, for the lists of silences.
fn point_name(id: u8) -> String {
    let names = [
        (N_WAKE, "switch woken"),
        (N_STEP, "switch step"),
        (N_RX, "frame off the device"),
        (N_TO_CONSUMER, "frame to a consumer"),
        (N_TO_STACK, "frame to the stack"),
        (N_CWAKE, "consumer woken"),
        (N_CSKIP, "consumer not woken"),
        (N_TX_SEEN, "TX entry seen"),
        (N_STK_TX, "frame from the stack"),
        (N_TX_SUBMIT, "frame to the device"),
        (N_BELL, "doorbell"),
        (N_BELL_SKIP, "doorbell skipped"),
        (N_WAKE_STACK, "stack thread woken"),
        (N_STK_BEGIN, "stack step"),
        (N_STK_END, "stack step end"),
        (N_REQ_BEGIN, "request received"),
        (N_REQ_END, "request answered"),
        (W_WAKE, "worker woke"),
        (W_RX, "worker took a frame"),
        (W_TX, "worker put a frame"),
        (W_KICK, "worker poke"),
        (W_SLEEP, "worker slept"),
        (W_FOUND, "worker found a frame"),
        (C_SEND, "call sent"),
        (C_RET, "call returned"),
        (C_EPOLL, "epoll entered"),
        (C_EPOLL_RET, "epoll returned"),
    ];
    names
        .iter()
        .find(|(i, _)| *i == id)
        .map_or(format!("point {id}"), |(_, n)| (*n).to_owned())
}

/// The silences of each component of more than 20 ms (a point `0xff` has the length, the
/// `0xfe` after it the record that ended it): the longest, with the time since the first
/// record of the ring.
fn silences(events: &[Ev], tpu: f64, out: &mut String) {
    let Some(t0) = events.iter().map(|e| e.t).min() else {
        return;
    };
    let mut rows: Vec<(f64, f64, String, String)> = Vec::new();
    for e in events.iter().filter(|e| e.id == 0xff) {
        let after = events
            .iter()
            .find(|a| a.id == 0xfe && a.label == e.label && a.t == e.t)
            .map_or(String::new(), |a| {
                format!(
                    "{} (key low half {:x})",
                    point_name((a.key >> 16) as u8),
                    a.key & 0xffff
                )
            });
        rows.push((
            f64::from(e.key) / tpu / 1000.0,
            (e.t - t0) as f64 / tpu / 1000.0,
            e.label.clone(),
            after,
        ));
    }
    if rows.is_empty() {
        return;
    }
    rows.sort_by(|a, b| b.0.total_cmp(&a.0));
    out.push_str("\n### Silences of a component longer than 20 ms (the longest 12)\n\n| component | silence ms | ends at ms from the first record | ended by |\n|---|---|---|---|\n");
    for (ms, at, label, after) in rows.iter().take(12) {
        out.push_str(&format!("| {label} | {ms:.1} | {at:.1} | {after} |\n"));
    }
}

/// The share of the time that each worker slept, from its first to its last record of a frame
/// taken (sleep: the point `W_SLEEP` to the next `W_WAKE` or `W_FOUND` of the worker), and the
/// frames that came twice with the same key more than a millisecond apart (TCP repeating them).
fn sleeps_and_repeats(events: &[Ev], tpu: f64, out: &mut String) {
    let mut labels: Vec<&str> = events
        .iter()
        .filter(|e| e.id == W_RX)
        .map(|e| e.label.as_str())
        .collect();
    labels.sort();
    labels.dedup();
    let mut rows = String::new();
    for label in labels {
        let mine: Vec<&Ev> = events.iter().filter(|e| e.label == label).collect();
        let times: Vec<u64> = mine.iter().filter(|e| e.id == W_RX).map(|e| e.t).collect();
        let (from, to) = (times[0], times[times.len() - 1]);
        let (mut asleep, mut slept, mut since) = (0u64, Vec::new(), None);
        for e in mine.iter().filter(|e| e.t >= from && e.t <= to) {
            match e.id {
                W_SLEEP => since = Some(e.t),
                W_WAKE | W_FOUND => {
                    if let Some(s) = since.take() {
                        asleep += e.t - s;
                        slept.push((e.t - s) as f64 / tpu);
                    }
                }
                _ => {}
            }
        }
        let (n, m, p90, p99) = stats(&mut slept);
        rows.push_str(&format!(
            "| {label} | {n} | {m:.1} | {p90:.1} | {p99:.1} | {:.0} % |\n",
            asleep as f64 / (to - from).max(1) as f64 * 100.0
        ));
    }
    if !rows.is_empty() {
        out.push_str("\n### Sleeps of the workers (to the next wake-up, or to the frame found before sleeping)\n\n| worker | sleeps | median us | p90 us | p99 us | share of the time asleep |\n|---|---|---|---|---|---|\n");
        out.push_str(&rows);
    }
    let mut seen: HashMap<(u8, u32), u64> = HashMap::new();
    let mut gaps = Vec::new();
    for e in events
        .iter()
        .filter(|e| (e.id == N_RX || e.id == W_RX) && e.key != 0)
    {
        if let Some(before) = seen.insert((e.id, e.key), e.t)
            && (e.t - before) as f64 > tpu * 1000.0
        {
            gaps.push((e.t - before) as f64 / tpu / 1000.0);
        }
    }
    let (n, m, _, p99) = stats(&mut gaps);
    if n > 0 {
        out.push_str(&format!(
            "\nFrames that came again with the same key more than 1 ms later (repeats of TCP): {n}, median gap {m:.1} ms, p99 {p99:.1} ms.\n"
        ));
    }
}

fn duration_rows(events: &[Ev], tpu: f64, out: &mut String) {
    let window = load_window(events);
    let mut rows = String::new();
    let items: [(&str, u8, u8); 4] = [
        (
            "call of a socket in the layer (sent to returned)",
            C_SEND,
            C_RET,
        ),
        ("epoll_pwait (entered to returned)", C_EPOLL, C_EPOLL_RET),
        (
            "request in the service (received to answered)",
            N_REQ_BEGIN,
            N_REQ_END,
        ),
        ("step of the stack thread", N_STK_BEGIN, N_STK_END),
    ];
    for (name, b, e) in items {
        let mut v = durations(events, b, e, window, tpu);
        if !v.is_empty() {
            let (n, m, p90, p99) = stats(&mut v);
            rows.push_str(&format!(
                "| {name} | {n} | {m:.1} | {p90:.1} | {p99:.1} |\n"
            ));
        }
    }
    if !rows.is_empty() {
        out.push_str("\n### Durations of calls and steps (within the load window)\n\n| what | count | median us | p90 us | p99 us |\n|---|---|---|---|---|\n");
        out.push_str(&rows);
    }
}

/// The report of one console log: the paths that its records make.
#[cfg(test)]
fn report(name: &str, text: &str, worst: usize, window: Option<(f64, f64)>) -> String {
    report_pooled(name, text, worst, window).0
}

/// `report`, and the splits of the windows of its requests for `show` to pool over logs.
fn report_pooled(
    name: &str,
    text: &str,
    worst: usize,
    window: Option<(f64, f64)>,
) -> (String, Vec<(&'static str, Vec<Split>)>) {
    let (mut events, tpu) = parse(text);
    let kernel = parse_kernel(text);
    if let Some((from, to)) = window
        && let Some(t0) = events.first().map(|e| e.t)
    {
        events.retain(|e| {
            let us = (e.t - t0) as f64 / tpu;
            us >= from && us <= to
        });
    }
    let mut out = format!("## {name}: {} records\n", events.len());
    if events.is_empty() {
        return (out, Vec::new());
    }
    let has = |id: u8| events.iter().any(|e| e.id == id);
    let mut requests = 0;
    for (title, path, wanted) in [
        (
            "through the switch to a worker (F1s)",
            SWITCH_PATH,
            has(N_TO_CONSUMER),
        ),
        (
            "through the stack of the service (S4)",
            STACK_PATH,
            has(N_TO_STACK),
        ),
        (
            "a worker with its own device (F1)",
            OWN_PATH,
            !has(N_RX) && has(W_RX),
        ),
    ] {
        if wanted {
            let c = chains(&events, path, tpu);
            requests = requests.max(c.len());
            path_table(title, &c, worst, tpu, &mut out);
        }
    }
    counts(&events, requests, &mut out);
    sleeps_and_repeats(&events, tpu, &mut out);
    silences(&events, tpu, &mut out);
    duration_rows(&events, tpu, &mut out);
    let pooled = kernel_report(&events, &kernel, &kernel_given(text), tpu, worst, &mut out);
    (out, pooled)
}

/// A record of a ring of a program or of the kernel.
#[derive(Clone, Copy, Debug)]
enum Item<'a> {
    User(&'a Ev),
    Kernel(&'a Kev),
}

impl Item<'_> {
    fn time(&self) -> u64 {
        match self {
            Item::User(e) => e.t,
            Item::Kernel(k) => k.t,
        }
    }
}

/// The records of the programs and of the kernel between `from` and `to` ticks, in the order of
/// their time (the counter is one for every CPU and for the kernel and the programs alike).
fn merge<'a>(user: &'a [Ev], kernel: &'a [Kev], from: u64, to: u64) -> Vec<Item<'a>> {
    let mut out: Vec<Item<'a>> = user
        .iter()
        .filter(|e| e.t >= from && e.t <= to)
        .map(Item::User)
        .chain(
            kernel
                .iter()
                .filter(|k| k.t >= from && k.t <= to)
                .map(Item::Kernel),
        )
        .collect();
    if !cfg!(feature = "break-stamps-merge") {
        out.sort_by_key(Item::time);
    }
    out
}

/// What the kernel did between two points of a request, in ticks: the threads made ready on
/// another CPU (the time from the wake-up to the SGI sent, in flight until the CPU came out of
/// `wfi`, from that to the handler of the SGI) and the wait of every thread made ready for the CPU
/// (to the moment it got it); `work` is what is left of the window, the time of the programs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Split {
    window: u64,
    post: u64,
    flight: u64,
    wfi: u64,
    queue: u64,
    work: u64,
    /// The threads made ready in the window, and the SGIs among them.
    hops: usize,
    sgis: usize,
}

/// The `Split` of the window `from` to `to` of the sorted records of the kernel.
fn split(kernel: &[Kev], from: u64, to: u64) -> Split {
    let win: Vec<&Kev> = kernel.iter().filter(|k| k.t >= from && k.t <= to).collect();
    let mut s = Split {
        window: to.saturating_sub(from),
        ..Split::default()
    };
    for r in win
        .iter()
        .filter(|k| k.point == K_READY && (k.key >> 16) as u8 != WAKE_COMMAND)
    {
        let (thread, target) = (r.key & 0xffff, (r.key >> 24) as u8);
        let run_after = |t: u64| {
            win.iter()
                .find(|k| k.point == K_RUN && k.cpu == target && k.key == thread && k.t >= t)
                .map(|k| k.t)
        };
        let sent = win.iter().find(|k| {
            k.point == K_SGI_SENT
                && k.cpu == r.cpu
                && k.key & 0xff == u32::from(target)
                && k.key & 0x100 != 0
                && k.t >= r.t
        });
        let got = sent.and_then(|s| {
            win.iter()
                .find(|k| k.point == K_SGI_GOT && k.cpu == target && k.t >= s.t)
        });
        match (target == r.cpu, sent, got) {
            (false, Some(sent), Some(got)) => {
                let out = win.iter().rev().find(|k| {
                    k.point == K_WFI
                        && k.key == 1
                        && k.cpu == target
                        && k.t >= sent.t
                        && k.t <= got.t
                });
                s.post += sent.t - r.t;
                match out.filter(|_| !cfg!(feature = "break-stamps-split")) {
                    Some(out) => {
                        s.flight += out.t - sent.t;
                        s.wfi += got.t - out.t;
                    }
                    None => s.flight += got.t - sent.t,
                }
                if let Some(run) = run_after(got.t) {
                    s.queue += run - got.t;
                    s.hops += 1;
                    s.sgis += 1;
                }
            }
            // On the CPU of its own, or on a polling CPU that took the bell alone.
            _ => {
                if let Some(run) = run_after(r.t) {
                    s.queue += run - r.t;
                    s.hops += 1;
                }
            }
        }
    }
    s.work = s.window.saturating_sub(s.post + s.flight + s.wfi + s.queue);
    s
}

/// One row of the table of splits: the medians of each part over `windows`, in microseconds.
fn split_row(name: &str, splits: &[Split], tpu: f64, out: &mut String) {
    if splits.is_empty() {
        return;
    }
    let median = |f: fn(&Split) -> u64| {
        let mut v: Vec<f64> = splits.iter().map(|s| f(s) as f64 / tpu).collect();
        stats(&mut v).1
    };
    let hops: usize = splits.iter().map(|s| s.hops).sum();
    let sgis: usize = splits.iter().map(|s| s.sgis).sum();
    out.push_str(&format!(
        "| {name} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.2} / {:.2} |\n",
        splits.len(),
        median(|s| s.window),
        median(|s| s.post),
        median(|s| s.flight),
        median(|s| s.wfi),
        median(|s| s.queue),
        median(|s| s.work),
        hops as f64 / splits.len() as f64,
        sgis as f64 / splits.len() as f64
    ));
}

/// The table of splits of a set of windows: all of them, and the slowest 1 % (at least one).
fn split_table(
    title: &str,
    windows: &[(u64, u64)],
    kernel: &[Kev],
    tpu: f64,
    out: &mut String,
) -> Vec<Split> {
    let splits: Vec<Split> = windows.iter().map(|&(a, b)| split(kernel, a, b)).collect();
    splits_table(title, &splits, tpu, out);
    splits
}

/// The table of `splits`: all of them, and the slowest 1 % (at least one).
fn splits_table(title: &str, splits: &[Split], tpu: f64, out: &mut String) {
    if splits.is_empty() {
        return;
    }
    let mut splits = splits.to_vec();
    out.push_str(&format!(
        "\n### Kernel: {title}\n\n| set | samples | window median us | wake to SGI sent | SGI in flight | out of wfi to the handler | wait in the run queue | work of the programs | threads made ready / SGIs per request |\n|---|---|---|---|---|---|---|---|---|\n"
    ));
    split_row("all", &splits, tpu, out);
    splits.sort_by_key(|s| std::cmp::Reverse(s.window));
    split_row(
        "the slowest 1 %",
        &splits[..splits.len().div_ceil(100)],
        tpu,
        out,
    );
}

/// The time that every ring of the kernel covers: from the oldest record of the latest ring that
/// wrote over its older ones (a busy CPU's covers less time than an idle one's) to the last record
/// of any ring. A window of a request outside it has no complete kernel records.
fn kernel_cover(kernel: &[Kev], given: &[(u8, u64, u64)]) -> Option<(u64, u64)> {
    let last = kernel.last()?.t;
    let mut from = kernel.first()?.t;
    let mut cpus: Vec<u8> = kernel.iter().map(|k| k.cpu).collect();
    cpus.sort_unstable();
    cpus.dedup();
    for cpu in cpus {
        let mine: Vec<&Kev> = kernel.iter().filter(|k| k.cpu == cpu).collect();
        let made = given.iter().find(|g| g.0 == cpu).map_or(0, |g| g.1);
        if mine.len() >= KERNEL_RING || made > KERNEL_RING as u64 {
            from = from.max(mine[0].t);
        }
    }
    Some((from, last))
}

/// What each CPU's ring of the kernel holds: the records by point, and the interrupts of devices
/// apart from those of the timer.
fn kernel_counts(kernel: &[Kev], tpu: f64, out: &mut String) {
    let (Some(first), Some(last)) = (kernel.first(), kernel.last()) else {
        return;
    };
    out.push_str(&format!(
        "\n### Kernel rings: {} records over {:.1} ms\n\n| CPU | records | interrupts of devices | timer | threads made ready | run | SGI sent (bell alone) | SGI got | wfi entered |\n|---|---|---|---|---|---|---|---|---|\n",
        kernel.len(),
        (last.t - first.t) as f64 / tpu / 1000.0
    ));
    let mut cpus: Vec<u8> = kernel.iter().map(|k| k.cpu).collect();
    cpus.sort_unstable();
    cpus.dedup();
    for cpu in cpus {
        let mine = || kernel.iter().filter(move |k| k.cpu == cpu);
        let n = |f: &dyn Fn(&Kev) -> bool| mine().filter(|k| f(k)).count();
        out.push_str(&format!(
            "| {cpu} | {} | {} | {} | {} | {} | {} ({}) | {} | {} |\n",
            mine().count(),
            n(&|k| k.point == K_IRQ && k.key != TIMER_LINE),
            n(&|k| k.point == K_IRQ && k.key == TIMER_LINE),
            n(&|k| k.point == K_READY),
            n(&|k| k.point == K_RUN),
            n(&|k| k.point == K_SGI_SENT),
            n(&|k| k.point == K_SGI_SENT && k.key & 0x100 == 0),
            n(&|k| k.point == K_SGI_GOT),
            n(&|k| k.point == K_WFI && k.key == 0),
        ));
    }
}

/// The name of a kernel record, for the lists of the slowest requests.
fn kernel_name(k: &Kev) -> String {
    let cause = |c: u8| match c {
        abi::WAKE_NOTIFY => "notification",
        abi::WAKE_REPLY => "reply",
        abi::WAKE_REQUEST => "request",
        abi::WAKE_COMMAND => "command",
        abi::WAKE_TIMER => "timer",
        abi::WAKE_IRQ => "interrupt",
        _ => "other",
    };
    match k.point {
        K_IRQ => format!("cpu{} line {}", k.cpu, k.key),
        K_READY => format!(
            "cpu{} thread {} ready ({}) on cpu{}",
            k.cpu,
            k.key & 0xffff,
            cause((k.key >> 16) as u8),
            k.key >> 24
        ),
        K_RUN => format!("cpu{} thread {} runs", k.cpu, k.key),
        K_SGI_SENT => format!(
            "cpu{} SGI to cpu{}{}",
            k.cpu,
            k.key & 0xff,
            if k.key & 0x100 == 0 {
                " (bell alone)"
            } else {
                ""
            }
        ),
        K_SGI_GOT => format!("cpu{} SGI got", k.cpu),
        K_WFI => format!("cpu{} wfi {}", k.cpu, if k.key == 1 { "out" } else { "in" }),
        other => format!("cpu{} point {other}", k.cpu),
    }
}

/// The windows of the requests of S4 (from the step of the stack that took the frame to the frame
/// that the stack passed to the switch) and of F1 (from the last interrupt of a device before the
/// worker took the frame to the worker's frame sent), with the kernel's rings in them.
fn kernel_report(
    events: &[Ev],
    kernel: &[Kev],
    given: &[(u8, u64, u64)],
    tpu: f64,
    worst: usize,
    out: &mut String,
) -> Vec<(&'static str, Vec<Split>)> {
    let mut pooled = Vec::new();
    if kernel.is_empty() {
        return pooled;
    }
    kernel_counts(kernel, tpu, out);
    for &(cpu, made, given) in given {
        let seen = kernel
            .iter()
            .filter(|k| usize::from(k.cpu) == usize::from(cpu))
            .count() as u64;
        out.push_str(&format!(
            "\nCPU {cpu}: {made} records made, {given} given by the kernel, {seen} read from the console (lost on the console: {}).\n",
            given.saturating_sub(seen)
        ));
    }
    let (cover_from, cover_to) = kernel_cover(kernel, given).unwrap_or((0, 0));
    out.push_str(&format!(
        "\nEvery ring of the kernel covers {:.1} ms; the windows of requests below lie inside it.\n",
        (cover_to - cover_from) as f64 / tpu / 1000.0
    ));
    let inside = |&(a, b): &(u64, u64)| a >= cover_from && b <= cover_to;
    let has = |id: u8| events.iter().any(|e| e.id == id);
    let at = |c: &[(&str, u64)], name: &str| c.iter().find(|p| p.0 == name).map(|p| p.1);
    if has(N_TO_STACK) {
        let windows: Vec<(u64, u64)> = chains(events, STACK_PATH, tpu)
            .iter()
            .filter_map(|c| Some((at(c, "step")?, at(c, "stk_tx")?)))
            .filter(|(a, b)| a < b)
            .filter(inside)
            .collect();
        let title = "S4, from the step of the stack to the frame it passed to the switch";
        pooled.push((title, split_table(title, &windows, kernel, tpu, out)));
        slowest_with_kernel(events, kernel, &windows, worst, tpu, out);
    }
    if !has(N_RX) && has(W_RX) {
        let mut irqs: Vec<u64> = kernel
            .iter()
            .filter(|k| k.point == K_IRQ && k.key != TIMER_LINE)
            .map(|k| k.t)
            .collect();
        irqs.sort_unstable();
        let back = (IRQ_LOOK_BACK_US * tpu) as u64;
        let windows: Vec<(u64, u64)> = chains(events, OWN_PATH, tpu)
            .iter()
            .filter_map(|c| {
                let (rx, tx) = (at(c, "wrx")?, at(c, "wtx")?);
                let i = irqs.partition_point(|t| *t <= rx).checked_sub(1)?;
                (rx - irqs[i] <= back && irqs[i] < tx).then_some((irqs[i], tx))
            })
            .filter(inside)
            .collect();
        let title = "F1, from the last interrupt of a device before the worker took the frame to the frame it sent";
        pooled.push((title, split_table(title, &windows, kernel, tpu, out)));
        slowest_with_kernel(events, kernel, &windows, worst, tpu, out);
    }
    pooled
}

/// The `worst` slowest windows with the records of the programs and of the kernel in them, in the
/// order of their time.
fn slowest_with_kernel(
    events: &[Ev],
    kernel: &[Kev],
    windows: &[(u64, u64)],
    worst: usize,
    tpu: f64,
    out: &mut String,
) {
    if worst == 0 || windows.is_empty() {
        return;
    }
    let mut order: Vec<&(u64, u64)> = windows.iter().collect();
    order.sort_by_key(|w| std::cmp::Reverse(w.1 - w.0));
    out.push_str(&format!(
        "\nThe {worst} slowest windows, records of the programs and of the kernel in them (us from the start):\n\n"
    ));
    for &&(from, to) in order.iter().take(worst) {
        let items: Vec<String> = merge(events, kernel, from, to)
            .iter()
            .map(|i| {
                let name = match i {
                    Item::User(e) => format!("{} point {}", e.label, e.id),
                    Item::Kernel(k) => kernel_name(k),
                };
                format!("{name} {:.1}", (i.time() - from) as f64 / tpu)
            })
            .collect();
        out.push_str(&format!(
            "* {:.1} us: {}\n",
            (to - from) as f64 / tpu,
            items.join(", ")
        ));
    }
}

fn logs_of(arg: &Path) -> Vec<PathBuf> {
    if arg.is_dir() {
        let dir = if arg.join("raw").is_dir() {
            arg.join("raw")
        } else {
            arg.to_owned()
        };
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("console-"))
            })
            .collect();
        files.sort();
        files
    } else {
        vec![arg.to_owned()]
    }
}

fn show(args: &[String]) -> Result<String, String> {
    let (mut worst, mut files, mut window) = (0, Vec::new(), None::<(f64, f64)>);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut number = |what: &str| -> Result<f64, String> {
            it.next()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("{what} needs a number\n{USAGE}"))
        };
        match a.as_str() {
            "--worst" => worst = number("--worst")? as usize,
            "--from-us" => window = Some((number("--from-us")?, window.map_or(f64::MAX, |w| w.1))),
            "--to-us" => window = Some((window.map_or(0.0, |w| w.0), number("--to-us")?)),
            other => files.extend(logs_of(Path::new(other))),
        }
    }
    if files.is_empty() {
        return Err(USAGE.to_owned());
    }
    let mut out = String::new();
    let mut pooled: Vec<(&str, Vec<Split>, usize)> = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        if text.lines().any(|l| l.starts_with("tr ")) {
            let name = f
                .file_name()
                .map_or(String::new(), |n| n.to_string_lossy().into_owned());
            let (text, splits) = report_pooled(&name, &text, worst, window);
            out.push_str(&text);
            for (title, list) in splits {
                match pooled.iter_mut().find(|p| p.0 == title) {
                    Some(p) => {
                        p.1.extend(list);
                        p.2 += 1;
                    }
                    None => pooled.push((title, list, 1)),
                }
            }
        }
    }
    // The windows of all the logs of one kind together, when there are several: the rings cover
    // seconds of a run, and the slowest 1 % of one guest is a handful of requests.
    for (title, splits, logs) in pooled.iter().filter(|p| p.2 > 1) {
        let title = format!("{title}; the windows of {logs} logs together");
        splits_table(&title, splits, DEFAULT_TICKS_PER_US, &mut out);
    }
    Ok(out)
}

pub fn command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("run") => {
            let seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let dir = crate::target_dir()
                .join("net-trace")
                .join(seconds.to_string());
            std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            let mut run = vec!["run".to_owned(), "--trace".to_owned()];
            run.extend(args[1..].iter().cloned());
            run.extend(["--resume".to_owned(), dir.display().to_string()]);
            let result = crate::net_bench::command(&run);
            let text = show(&[dir.display().to_string()])?;
            std::fs::write(dir.join("trace.md"), &text).map_err(|e| format!("trace.md: {e}"))?;
            print!("{text}");
            println!("\nin {}", dir.display());
            result
        }
        Some("show") => {
            print!("{}", show(&args[1..])?);
            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> String {
        // One request through the switch, in ticks (24 per microsecond): rx at 0, in the ring at
        // 24, the worker takes it at 240, answers at 480, the switch sees it at 720 and rings at 840
        // (35 us in all).
        [
            "tr n 3 1000 c0de0010",
            "tr n 4 1018 c0de0010",
            "tr n 6 1020 0",
            "tr w9 21 1100 0",
            "tr w9 21 10f0 c0de0010",
            "tr w9 22 11e0 c0de0010",
            "tr w9 23 11e8 1",
            "tr n 8 12d0 c0de0010",
            "tr n 0a 12e0 c0de0010",
            "tr n b 1348 0",
        ]
        .join("\n")
    }

    #[test]
    fn a_request_through_the_switch_has_its_segments() {
        let (events, tpu) = parse(&log());
        let c = chains(&events, SWITCH_PATH, tpu);
        assert_eq!(c.len(), 1);
        let names: Vec<&str> = c[0].iter().map(|p| p.0).collect();
        assert_eq!(
            names,
            [
                "rx", "ring", "cwake", "wrx", "wtx", "kick", "seen", "submit", "bell"
            ]
        );
        let text = report("t", &log(), 1, None);
        assert!(
            text.contains("1 requests, round trip in the guest median 35.0 us"),
            "{text}"
        );
        assert!(text.contains("| wrx to wtx |"), "{text}");
    }

    /// A line of the log: label, point, ticks and key (decimal here, hexadecimal in the line).
    fn line(label: &str, id: u8, t: u64, key: u32) -> String {
        format!("tr {label} {id:x} {t:x} {key:x}")
    }

    #[test]
    fn two_workers_do_not_mix_their_wakes_and_pokes() {
        // The frames of A and B go to the workers w1 and w2. The wake-up and the poke of w2 lie
        // between the points of w1, and the chain of A takes only those of w1.
        let log = [
            line("n", N_RX, 1000, 0xa),
            line("n", N_TO_CONSUMER, 1010, 0xa),
            line("n", N_RX, 1020, 0xb),
            line("n", N_TO_CONSUMER, 1030, 0xb),
            line("n", N_CWAKE, 1035, 0),
            line("w2", W_WAKE, 1050, 0),
            line("w2", W_RX, 1060, 0xb),
            line("w2", W_TX, 1070, 0xb),
            line("w1", W_WAKE, 1100, 0),
            line("w1", W_RX, 1110, 0xa),
            line("w1", W_TX, 1140, 0xa),
            line("w2", W_KICK, 1150, 0),
            line("w1", W_KICK, 1200, 0),
            line("n", N_WAKE, 1250, 1),
            line("n", N_TX_SEEN, 1300, 0xa),
            line("n", N_TX_SUBMIT, 1310, 0xa),
            line("n", N_TX_SEEN, 1320, 0xb),
            line("n", N_TX_SUBMIT, 1330, 0xb),
            line("n", N_BELL, 1400, 0),
        ]
        .join("\n");
        let (events, tpu) = parse(&log);
        let chains = chains(&events, SWITCH_PATH, tpu);
        let a = chains
            .iter()
            .find(|c| c[0].1 == 1000)
            .expect("the chain of A");
        let at = |name: &str| a.iter().find(|p| p.0 == name).map(|p| p.1);
        assert_eq!(at("wwake"), Some(1100), "{a:?}");
        assert_eq!(at("wrx"), Some(1110));
        assert_eq!(at("kick"), Some(1200), "{a:?}");
    }

    #[test]
    fn a_wake_long_before_the_frame_is_not_its_wake() {
        let log = [
            line("w1", W_WAKE, 1000, 0),
            line("w1", W_RX, 1000 + 24 * 5000, 0xa),
            line("w1", W_TX, 1010 + 24 * 5000, 0xa),
        ]
        .join("\n");
        let (events, tpu) = parse(&log);
        let c = chains(&events, OWN_PATH, tpu);
        assert_eq!(c.len(), 1);
        assert!(c[0].iter().all(|p| p.0 != "wake"), "{c:?}");
    }

    #[test]
    fn durations_count_only_the_load_window() {
        // A call of 2 us during the load (the frames of 1000 to 1200 ticks) and a wait of 4 ms
        // after it, in the same ring: only the first enters the table.
        let log = [
            line("w1", C_SEND, 900, 8),
            line("w1", C_RET, 948, 8),
            line("w1", W_RX, 1000, 0xa),
            line("w1", W_TX, 1200, 0xa),
            line("w1", C_SEND, 1100, 8),
            line("w1", C_RET, 1148, 8),
            line("w1", C_SEND, 50_000, 8),
            line("w1", C_RET, 146_000, 8),
        ]
        .join("\n");
        let (events, tpu) = parse(&log);
        let mut text = String::new();
        duration_rows(&events, tpu, &mut text);
        assert!(
            text.contains(
                "| call of a socket in the layer (sent to returned) | 1 | 2.0 | 2.0 | 2.0 |"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_counter_frequency_comes_from_the_first_line() {
        let log = "tr n 0 1000 10 2faf080\ntr n 3 1000 1\n";
        let (_, tpu) = parse(log);
        assert_eq!(tpu, 50.0);
        let (_, tpu) = parse("tr n 0 1000 10\n");
        assert_eq!(tpu, 24.0);
    }

    /// A record of a ring of the kernel: CPU, point, ticks and key, as the line is.
    fn kline(cpu: u8, point: u8, t: u64, key: u32) -> String {
        format!("tr k{cpu} {point:x} {t:x} {key:x}")
    }

    /// The key of a thread made ready: the number, the cause and the CPU it is made ready on.
    fn ready(thread: u32, cause: u8, cpu: u32) -> u32 {
        thread | u32::from(cause) << 16 | cpu << 24
    }

    /// One request of S4 (24 ticks to the microsecond are not wanted here: the counter of the
    /// log says 1 000 000 Hz, one tick a microsecond). The step of the stack on CPU 0 ends at 1000
    /// and wakes the worker (thread 5) on CPU 2, asleep in `wfi`; the worker runs, calls the stack
    /// (thread 3, CPU 0, asleep too), and the stack passes the frame at 2000.
    fn s4_log() -> String {
        [
            "tr n 0 0 1 f4240".to_owned(),
            line("n", N_RX, 900, 0xa),
            line("n", N_TO_STACK, 905, 0xa),
            line("n", N_WAKE_STACK, 910, 0),
            line("n", N_STK_BEGIN, 1000, 1),
            line("n", N_STK_TX, 2000, 0xa),
            line("n", N_TX_SUBMIT, 2010, 0xa),
            line("n", N_BELL, 2020, 0),
            // The rings of the kernel cover the window of the request.
            kline(0, K_WFI, 990, 0),
            kline(0, K_WFI, 2010, 0),
            // The stack wakes the worker on CPU 2: the SGI goes at 1010, CPU 2 comes out of
            // `wfi` at 1400, takes the SGI at 1420 and runs the worker at 1500.
            kline(0, K_READY, 1005, ready(5, abi::WAKE_NOTIFY, 2)),
            kline(0, K_SGI_SENT, 1010, 2 | 0x100),
            kline(2, K_WFI, 1400, 1),
            kline(2, K_SGI_GOT, 1420, 15),
            kline(2, K_READY, 1425, ready(5, WAKE_COMMAND, 2)),
            kline(2, K_RUN, 1500, 5),
            // The worker answers at 1700 through the stack on CPU 0, which was asleep: the SGI
            // at 1705, `wfi` out at 1760, the SGI taken at 1770, the stack runs at 1800.
            kline(2, K_READY, 1700, ready(3, abi::WAKE_REQUEST, 0)),
            kline(2, K_SGI_SENT, 1705, 1 << 8),
            kline(0, K_WFI, 1760, 1),
            kline(0, K_SGI_GOT, 1770, 15),
            kline(0, K_RUN, 1800, 3),
        ]
        .join("\n")
    }

    #[test]
    fn the_rings_of_the_kernel_are_not_the_records_of_the_programs() {
        let (events, tpu) = parse(&s4_log());
        assert_eq!(tpu, 1.0);
        assert!(
            events.iter().all(|e| !e.label.starts_with('k')),
            "{events:?}"
        );
        let kernel = parse_kernel(&s4_log());
        assert_eq!(kernel.len(), 13);
        assert!(kernel.windows(2).all(|w| w[0].t <= w[1].t));
        assert_eq!(
            kernel[1],
            Kev {
                t: 1005,
                cpu: 0,
                point: K_READY,
                key: ready(5, abi::WAKE_NOTIFY, 2)
            }
        );
    }

    #[test]
    fn the_rings_of_the_kernel_and_of_the_programs_meet_in_time_order() {
        // The program's record at 1450 lies between kernel records of CPU 2 and of CPU 0.
        let log = [
            line("w1", W_RX, 1450, 0xa),
            kline(2, K_WFI, 1400, 1),
            kline(0, K_SGI_GOT, 1500, 15),
            kline(1, K_RUN, 1300, 7),
            line("w1", W_TX, 1600, 0xa),
        ]
        .join("\n");
        let (events, _) = parse(&log);
        let kernel = parse_kernel(&log);
        let merged = merge(&events, &kernel, 1300, 1500);
        let times: Vec<u64> = merged.iter().map(Item::time).collect();
        assert_eq!(times, [1300, 1400, 1450, 1500], "{merged:?}");
        assert!(matches!(merged[2], Item::User(e) if e.id == W_RX));
    }

    #[test]
    fn a_wake_on_another_cpu_is_split_into_its_parts() {
        let kernel = parse_kernel(&s4_log());
        let s = split(&kernel, 1000, 2000);
        // Wake to SGI sent: 5 + 5. In flight until `wfi` out: 390 + 55. Out of `wfi` to the handler:
        // 20 + 10. The run queue: 80 + 30. Work: the rest of 1000.
        assert_eq!(
            (s.post, s.flight, s.wfi, s.queue),
            (10, 445, 30, 110),
            "{s:?}"
        );
        assert_eq!((s.hops, s.sgis, s.work), (2, 2, 405), "{s:?}");
    }

    #[test]
    fn the_report_of_a_request_gives_the_split_of_the_window_and_of_its_tail() {
        let text = report("t", &s4_log(), 1, None);
        assert!(
            text.contains(
                "| all | 1 | 1000.0 | 10.0 | 445.0 | 30.0 | 110.0 | 405.0 | 2.00 / 2.00 |"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "| the slowest 1 % | 1 | 1000.0 | 10.0 | 445.0 | 30.0 | 110.0 | 405.0 | 2.00 / 2.00 |"
            ),
            "{text}"
        );
        // The list of the slowest: the kernel's records between the program's.
        assert!(
            text.contains("cpu2 wfi out 400.0, cpu2 SGI got 420.0"),
            "{text}"
        );
    }

    #[test]
    fn the_line_after_the_records_of_a_cpu_counts_what_the_console_lost() {
        // CPU 0 has 7 records in the log, and the kernel says it gave 8: one was lost.
        let log = format!("{}\n{}\n", s4_log(), "tr k0 0 2000 8");
        let text = report("t", &log, 0, None);
        assert!(
            text.contains("CPU 0: 8192 records made, 8 given by the kernel, 7 read from the console (lost on the console: 1)"),
            "{text}"
        );
        assert_eq!(kernel_given(&log), [(0, 0x2000, 8)]);
        // The line is no record.
        assert_eq!(parse_kernel(&log).len(), parse_kernel(&s4_log()).len());
    }

    #[test]
    fn statistics_of_few_values() {
        let mut v = vec![3.0, 1.0, 2.0];
        assert_eq!(stats(&mut v), (3, 2.0, 3.0, 3.0));
    }
}
