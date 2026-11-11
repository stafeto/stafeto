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
const N_IRQ1: u8 = 18;
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
        (N_IRQ1, "interrupt of the second device"),
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
fn report(name: &str, text: &str, worst: usize, window: Option<(f64, f64)>) -> String {
    let (mut events, tpu) = parse(text);
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
        return out;
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
    out
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
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        if text.lines().any(|l| l.starts_with("tr ")) {
            let name = f
                .file_name()
                .map_or(String::new(), |n| n.to_string_lossy().into_owned());
            out.push_str(&report(&name, &text, worst, window));
        }
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

    #[test]
    fn statistics_of_few_values() {
        let mut v = vec![3.0, 1.0, 2.0];
        assert_eq!(stats(&mut v), (3, 2.0, 3.0, 3.0));
    }
}
