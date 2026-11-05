// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The measurement of nginx on stafeto from the Mac (`cargo xtask
//! nginx-bench`): a manual run, since the machines of ci have neither HVF
//! nor VZ. The image `boot-nginx-bench.img` (on VZ `boot-nginx-bench-vz.img`)
//! is the shell with the network service and nginx with the package's
//! settings unchanged, the files `/www/1k.bin`, `/www/10k.bin` and
//! `/www/256k.bin`, and init's table of the network image. With `--no-buffers`
//! the image's `netd.conf` says `buffers 0`, and every send goes by
//! messages.
//!
//! The load comes from the Mac: `wrk` (closed loop) gives the ceiling and
//! counts the errors of the connections, `vegeta` (open loop at a fixed
//! rate) gives the latencies. vegeta counts a latency from the moment a
//! worker takes the request, and a pacer that fell behind sends the missed
//! requests at once, so a stall of vegeta itself is not in the latency:
//! xtask computes each request's lag behind the schedule from its sequence
//! number and marks a stage whose p99 of lag passes 0.1 ms. One run:
//!
//! 1. every file once by its SHA-256;
//! 2. the ceiling: `wrk -t2 -c64 -d30s` of `/10k.bin` (R_max), and the
//!    criterion `wrk -t2 -c200 -d30s` (no error of `connect`);
//! 3. the ladder: `vegeta attack` of `/10k.bin` over 64 connections that
//!    stay open, at 10, 25, 50, 75 and 90 % of R_max for 60 s each, each
//!    after a warm-up of 10 s at its rate whose results are dropped;
//! 4. `/1k.bin` at 50 % of R_max; `/256k.bin`: its own ceiling by `wrk`
//!    and a stage at 50 % of it, with MB/s;
//! 5. `/10k.bin` on a new connection for every request, at 100 and 300 a
//!    second and at 25 % of R_max (it runs after step 6, nginx started again with the
//!    package's settings: on QEMU the flood of new connections leaves the
//!    forwarded port refusing for a while);
//! 6. nginx again with one listening socket for the four workers
//!    (`exclusive.conf`): its ceiling and the stage at 50 %;
//! 7. in the guest, `posix-net readfile` of `/www/256k.bin` and of
//!    `/www/10k.bin`: the time to read the file nginx sends, so the run
//!    says whether nginx waits for the file service or for the network.
//!
//! A stage whose achieved rate is below 95 % of the asked one, or that has
//! an answer other than 200, a failed request or a line `malloc(...)
//! failed` of nginx, is marked and its latencies stay out of the table of
//! p99. p99.9 is given only for a stage of 100 000 requests or more.
//! `--no-buffers` runs steps 1 to 4 and 7. `--quick` runs steps 1, 2 and
//! the stage at 50 %, shorter, to check the command itself.
//!
//! `--machine host` runs the same load against nginx of Homebrew on the Mac
//! with the same settings (kqueue for epoll, a port of the loopback), plus
//! stages at 1 000 to 10 000 requests a second, the range of stafeto: a
//! reference of what the Mac and the load generator give, and nothing to
//! compare stafeto with. Every run notes the other machines of QEMU and VZ
//! running on the Mac at its start and end.
//!
//! The table goes to `target/nginx-bench/<time>-<what>/table.md` with the
//! raw output of every tool and the console beside it.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::nginx_probe::{self, Connection};
use crate::qemu::{Forward, Proto};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, ImageProgram, SERVICES_STARTED, Variant, build,
    build_boot_image, net, net_vz, qemu, target_dir, vz,
};

/// The images of the measurement: on QEMU and on VZ, with the shared
/// buffers of the network service and without.
pub const IMAGE: &str = "boot-nginx-bench.img";
pub const NO_BUFFERS_IMAGE: &str = "boot-nginx-bench-nobuf.img";
pub const VZ_IMAGE: &str = "boot-nginx-bench-vz.img";
pub const VZ_NO_BUFFERS_IMAGE: &str = "boot-nginx-bench-vz-nobuf.img";
/// Every image of the measurement.
pub const IMAGES: [&str; 4] = [IMAGE, NO_BUFFERS_IMAGE, VZ_IMAGE, VZ_NO_BUFFERS_IMAGE];

/// `/etc/netd.conf` of the images without the shared buffers.
pub const NO_BUFFERS_CONF: &[u8] = b"buffers 0\n";

/// The length of `/www/1k.bin`.
pub const WWW_1K_LEN: usize = 1024;

/// The rule of a stage: below this share of the asked rate it is saturated.
const ACHIEVED_SHARE: f64 = 0.95;
/// p99.9 needs at least this many requests in a stage.
const P999_REQUESTS: usize = 100_000;
/// A stage whose p99 of lag behind the schedule passes this (ns) is marked:
/// vegeta itself stood, and that time is not in the latencies.
const GENERATOR_LATE_NS: u64 = 100_000;
/// The shares of R_max of the ladder, in per cent.
const LADDER: [u32; 5] = [10, 25, 50, 75, 90];
/// The connections of `wrk` for the ceiling and for the criterion.
const WRK_CONNECTIONS: u32 = 64;
const CRITERION_CONNECTIONS: u32 = 200;
/// The connections of `vegeta`: idle ones kept and the most open at once.
const VEGETA_CONNECTIONS: u32 = 64;
/// How long nginx may take to start its four workers.
const START_WITHIN: Duration = Duration::from_secs(30);
/// The rounds of `posix-net readfile` for the files of 256 KiB and 10 KiB.
/// The fixed rates of the reference run on the Mac: the range of stafeto's
/// stages, where the load generator is far from its own limit.
const HOST_RATES: [u32; 5] = [1000, 2500, 5000, 7500, 10000];
const READ_ROUNDS: [(&str, usize); 2] = [("/www/256k.bin", 100), ("/www/10k.bin", 1000)];

/// The bytes of `/www/1k.bin`.
pub fn www_1k() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| nginx_probe::noise(0xbb67_ae85_84ca_a73b, WWW_1K_LEN))
}

/// The files the load asks for, with their bytes.
fn files() -> [(&'static str, &'static [u8]); 3] {
    [
        ("/1k.bin", www_1k()),
        ("/10k.bin", nginx_probe::www_10k()),
        ("/256k.bin", nginx_probe::www_256k()),
    ]
}

/// The package's settings with one listening socket for the four workers:
/// nginx sets EPOLLEXCLUSIVE on it.
pub fn exclusive_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        nginx_probe::replaced(
            nginx_probe::NGINX_CONF,
            "listen 80 reuseport;",
            "listen 80;",
        )
    })
}

/// The settings of Homebrew's nginx on the Mac for the reference run: the
/// package's, with the paths in `dir`, the port `port` of the loopback,
/// kqueue (nginx's choice on macOS) for epoll, and no change of user.
pub fn host_conf(dir: &Path, port: u16) -> String {
    let d = dir.display();
    let mut text = nginx_probe::NGINX_CONF.to_owned();
    for (from, to) in [
        ("user nobody nobody;\n", String::new()),
        ("pid /var/run/nginx.pid;", format!("pid {d}/nginx.pid;")),
        ("use epoll; ", String::new()),
        ("    include /etc/nginx/mime.types;\n", String::new()),
        (
            "    access_log off;\n",
            format!(
                "    access_log off;\n    client_body_temp_path {d}/tmp/body;\n    proxy_temp_path {d}/tmp/proxy;\n    fastcgi_temp_path {d}/tmp/fastcgi;\n    uwsgi_temp_path {d}/tmp/uwsgi;\n    scgi_temp_path {d}/tmp/scgi;\n"
            ),
        ),
        ("listen 80 reuseport;", format!("listen 127.0.0.1:{port};")),
        ("root /www;", format!("root {d}/www;")),
    ] {
        text = nginx_probe::replaced(&text, from, &to);
    }
    text
}

/// The programs of the images: the network image's on QEMU or on VZ. Its
/// commands, and so nginx's master and workers, have the quota of
/// `NET_COMMAND_QUOTA` (services/init/src/table/net.rs).
pub fn programs(vz: bool) -> &'static [ImageProgram] {
    if vz {
        net::vz_programs(false)
    } else {
        net::programs()
    }
}

/// Builds the four images of the measurement (a step of ci, which can run
/// neither HVF nor VZ).
pub fn build_images() -> Result<(), String> {
    for name in IMAGES {
        let vz = name.contains("-vz");
        build_boot_image(name, programs(vz), BOOT_PROFILE)?;
    }
    Ok(())
}

/// The image of a run.
fn image_of(vz: bool, buffers: bool) -> &'static str {
    match (vz, buffers) {
        (false, true) => IMAGE,
        (false, false) => NO_BUFFERS_IMAGE,
        (true, true) => VZ_IMAGE,
        (true, false) => VZ_NO_BUFFERS_IMAGE,
    }
}

/// Where a run goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Hvf,
    Vz,
    Host,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Target::Hvf => "hvf",
            Target::Vz => "vz",
            Target::Host => "host",
        }
    }
}

#[derive(Debug, PartialEq)]
struct Options {
    target: Target,
    cpus: usize,
    buffers: bool,
    quick: bool,
}

const USAGE: &str = "usage: cargo xtask nginx-bench [--machine hvf|vz|host | --vz] [--cpus N] [--no-buffers] [--quick]";

fn options(args: &[String]) -> Result<Options, String> {
    let mut found = Options {
        target: Target::Hvf,
        cpus: 1,
        buffers: true,
        quick: false,
    };
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--machine" => {
                found.target = match rest.next().map(String::as_str) {
                    Some("hvf") => Target::Hvf,
                    Some("vz") => Target::Vz,
                    Some("host") => Target::Host,
                    _ => return Err(USAGE.to_owned()),
                }
            }
            "--vz" => found.target = Target::Vz,
            "--cpus" => {
                found.cpus = rest
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|n| (1..=4).contains(n))
                    .ok_or("--cpus takes 1 to 4")?
            }
            "--no-buffers" => found.buffers = false,
            "--quick" => found.quick = true,
            _ => return Err(USAGE.to_owned()),
        }
    }
    if found.target == Target::Host && (!found.buffers || found.cpus != 1) {
        return Err("--machine host takes neither --cpus nor --no-buffers".to_owned());
    }
    Ok(found)
}

/// The lengths of a run's loads.
#[derive(Debug, Clone, Copy)]
struct Lengths {
    ceiling: u32,
    stage: u32,
    warm_up: u32,
}

impl Lengths {
    fn of(quick: bool) -> Lengths {
        if quick {
            Lengths {
                ceiling: 10,
                stage: 20,
                warm_up: 5,
            }
        } else {
            Lengths {
                ceiling: 30,
                stage: 60,
                warm_up: 10,
            }
        }
    }
}

/// What `wrk` printed.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Wrk {
    pub requests: u64,
    pub seconds: f64,
    pub per_second: f64,
    pub transfer: String,
    pub connect: u64,
    pub read: u64,
    pub write: u64,
    pub timeout: u64,
    pub non_2xx: u64,
}

/// The numbers of the output of `wrk`.
pub fn parse_wrk(text: &str) -> Option<Wrk> {
    let mut found = Wrk::default();
    let mut rate = false;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("Requests/sec:") {
            found.per_second = rest.trim().parse().ok()?;
            rate = true;
        } else if let Some(rest) = line.strip_prefix("Transfer/sec:") {
            found.transfer = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("Socket errors:") {
            for part in rest.split(',') {
                let mut words = part.split_whitespace();
                let (name, value) = (words.next()?, words.next()?.parse().ok()?);
                match name {
                    "connect" => found.connect = value,
                    "read" => found.read = value,
                    "write" => found.write = value,
                    "timeout" => found.timeout = value,
                    _ => return None,
                }
            }
        } else if let Some(rest) = line.strip_prefix("Non-2xx or 3xx responses:") {
            found.non_2xx = rest.trim().parse().ok()?;
        } else if let Some((count, rest)) = line.split_once(" requests in ") {
            found.requests = count.trim().parse().ok()?;
            found.seconds = rest
                .split(',')
                .next()?
                .trim()
                .strip_suffix('s')?
                .parse()
                .ok()?;
        }
    }
    rate.then_some(found)
}

/// One result of `vegeta encode --to csv`: when a worker took the request
/// (ns since the epoch), the status (0 for a request that failed), the
/// latency (ns) and the request's number in the attack.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub at: u64,
    pub code: u16,
    pub latency: u64,
    pub seq: u64,
}

/// The fields of a line of CSV, quotes (`"` doubled inside) taken off.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// A line of the CSV: timestamp, code, latency, bytes out, bytes in, error,
/// body, attack, seq, method, URL, headers.
pub fn parse_sample(line: &str) -> Option<Sample> {
    let fields = csv_fields(line);
    let number = |i: usize| fields.get(i)?.parse::<u64>().ok();
    Some(Sample {
        at: number(0)?,
        code: u16::try_from(number(1)?).ok()?,
        latency: number(2)?,
        seq: number(8)?,
    })
}

/// Each request's lag behind the schedule of `rate` requests a second, in
/// ns: when a worker took it against its time on the schedule (its number
/// over the rate), the schedule set by the request that was least late.
pub fn lags(samples: &[Sample], rate: u32) -> Vec<u64> {
    let gap = |seq: u64| i128::from(seq) * 1_000_000_000 / i128::from(rate.max(1));
    let Some(start) = samples.iter().map(|s| s.at as i128 - gap(s.seq)).min() else {
        return Vec::new();
    };
    samples
        .iter()
        .map(|s| (s.at as i128 - start - gap(s.seq)).max(0) as u64)
        .collect()
}

/// The summary of `samples` by the second of the stage, as CSV: the second,
/// the requests taken in it, p50, p99 and the longest latency in ms, the
/// answers other than 200, and the longest lag behind the schedule in ms.
pub fn by_second(samples: &[Sample], rate: u32) -> String {
    let lag = lags(samples, rate);
    let first = samples.iter().map(|s| s.at).min().unwrap_or(0);
    let mut seconds: Vec<(Vec<u64>, usize, u64)> = Vec::new();
    for (s, lag) in samples.iter().zip(lag) {
        let i = ((s.at - first) / 1_000_000_000) as usize;
        if seconds.len() <= i {
            seconds.resize(i + 1, (Vec::new(), 0, 0));
        }
        let second = &mut seconds[i];
        second.0.push(s.latency);
        second.1 += usize::from(s.code != 200);
        second.2 = second.2.max(lag);
    }
    let mut out = "second,requests,p50_ms,p99_ms,max_ms,not_200,max_lag_ms\n".to_owned();
    for (i, (mut latencies, failed, lag)) in seconds.into_iter().enumerate() {
        latencies.sort_unstable();
        let at = |p| percentile(&latencies, p).map_or(0.0, |ns| ns as f64 / 1e6);
        out += &format!(
            "{i},{},{:.3},{:.3},{:.3},{failed},{:.3}\n",
            latencies.len(),
            at(500),
            at(990),
            at(1000),
            lag as f64 / 1e6
        );
    }
    out
}

/// The value at `per_mille` / 1000 of `sorted` by the nearest rank.
pub fn percentile(sorted: &[u64], per_mille: u32) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (sorted.len() as u64 * u64::from(per_mille)).div_ceil(1000);
    Some(sorted[(rank.max(1) - 1) as usize])
}

/// What a stage of `vegeta` gave.
#[derive(Debug, Clone, PartialEq)]
pub struct Stage {
    pub asked: u32,
    pub requests: usize,
    pub ok: usize,
    /// Answers other than 200 and requests that failed.
    pub failed: usize,
    /// Lines `malloc(...) failed` of nginx during the stage.
    pub malloc: usize,
    pub achieved: f64,
    pub p50: Option<u64>,
    pub p99: Option<u64>,
    pub p999: Option<u64>,
    pub megabytes_per_second: f64,
    /// The p99 and the longest of the lags behind the schedule.
    pub lag_p99: Option<u64>,
    pub lag_max: Option<u64>,
    /// A guest of vz-run came up beside the run during the stage.
    pub foreign: bool,
}

impl Stage {
    /// Whether the stage stays out of the table of p99: a foreign guest of
    /// VZ beside it, an error, below 95 % of the asked rate, or vegeta late
    /// on its own schedule.
    pub fn marked(&self) -> Option<&'static str> {
        if self.foreign {
            Some("foreign guest")
        } else if self.failed > 0 || self.malloc > 0 {
            Some("errors")
        } else if self.achieved < f64::from(self.asked) * ACHIEVED_SHARE {
            Some("saturated")
        } else if self.lag_p99.is_some_and(|l| l > GENERATOR_LATE_NS) {
            Some("generator late")
        } else {
            None
        }
    }
}

/// The mark of a ceiling of `wrk`: a foreign guest, or errors of connect,
/// timeouts, answers other than 200 or `malloc(...) failed`. The errors of
/// reading at the end of a run on QEMU come from the forwarded port and
/// leave the row unmarked.
pub fn ceiling_mark(wrk: &Wrk, malloc: usize, foreign: bool) -> Option<&'static str> {
    if foreign {
        Some("foreign guest")
    } else if wrk.connect + wrk.timeout + wrk.non_2xx > 0 || malloc > 0 {
        Some("errors")
    } else {
        None
    }
}

/// The stage of `samples` asked at `asked` requests a second for a file of
/// `length` bytes: the achieved rate is the answers of 200 over the time
/// from the first request to the end of the last answer; the percentiles
/// are over every request. vegeta reads every body to its end and keeps
/// none of it (`-max-body=0`, so its bytes in are 0): the bytes are the
/// file's length for each answer of 200.
pub fn stage_of(samples: &[Sample], asked: u32, malloc: usize, length: usize) -> Stage {
    let mut latencies: Vec<u64> = samples.iter().map(|s| s.latency).collect();
    latencies.sort_unstable();
    let ok = samples.iter().filter(|s| s.code == 200).count();
    let first = samples.iter().map(|s| s.at).min().unwrap_or(0);
    let last = samples.iter().map(|s| s.at + s.latency).max().unwrap_or(0);
    let seconds = (last.saturating_sub(first)) as f64 / 1e9;
    let bytes = (ok * length) as f64;
    let per_second = |n: f64| if seconds > 0.0 { n / seconds } else { 0.0 };
    let mut lag = lags(samples, asked);
    lag.sort_unstable();
    Stage {
        asked,
        requests: samples.len(),
        ok,
        failed: samples.len() - ok,
        malloc,
        achieved: per_second(ok as f64),
        p50: percentile(&latencies, 500),
        p99: percentile(&latencies, 990),
        p999: (samples.len() >= P999_REQUESTS)
            .then(|| percentile(&latencies, 999))
            .flatten(),
        megabytes_per_second: per_second(bytes) / 1e6,
        lag_p99: percentile(&lag, 990),
        lag_max: lag.last().copied(),
        foreign: false,
    }
}

/// The lines of nginx's log that say a buffer was not allocated.
fn malloc_failures(lines: &[String]) -> usize {
    lines
        .iter()
        .filter(|l| l.contains("malloc(") && l.contains("failed"))
        .count()
}

/// The lines of nginx at `crit` or above other than `malloc(...) failed`:
/// a fault of the system under the load (a worker whose `epoll_wait`
/// fails logs a line each turn of its loop).
fn alerts(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|l| {
            ["[alert]", "[emerg]", "[crit]"]
                .iter()
                .any(|w| l.contains(w))
        })
        .filter(|l| !(l.contains("malloc(") && l.contains("failed")))
        .cloned()
        .collect()
}

/// Ends the run after `step` when nginx logged `alerts`: the stages after it
/// would measure a broken server, and the flood of its log slows the reading
/// of the console.
fn stop_on(step: &str, alerts: &[String]) -> Result<(), String> {
    match alerts.first() {
        None => Ok(()),
        Some(first) => Err(format!(
            "{step}: nginx logged {} lines at crit or above, the first {:?}; the run stops here",
            alerts.len(),
            first.trim()
        )),
    }
}

/// A row of the report.
enum Row {
    Ceiling {
        step: String,
        path: String,
        connections: u32,
        wrk: Wrk,
        malloc: usize,
        mark: Option<&'static str>,
        command: String,
    },
    Stage {
        step: String,
        path: String,
        keep_alive: bool,
        stage: Stage,
        command: String,
    },
    Read {
        path: String,
        rounds: usize,
        mean_us: u64,
        line: String,
    },
    Note(String),
}

fn ms(ns: Option<u64>) -> String {
    ns.map_or("-".to_owned(), |ns| format!("{:.3}", ns as f64 / 1e6))
}

/// The Markdown of the rows.
fn table(rows: &[Row]) -> String {
    let mut out = String::new();
    out += "### Ceilings (wrk, closed loop)\n\n| Step | File | Connections | Requests/s | Transfer/s | Requests | Socket errors (connect/read/write/timeout) | Non-2xx | malloc failed | Mark |\n|---|---|---|---|---|---|---|---|---|---|\n";
    for row in rows {
        if let Row::Ceiling {
            step,
            path,
            connections,
            wrk,
            malloc,
            mark,
            ..
        } = row
        {
            out += &format!(
                "| {step} | {path} | {connections} | {:.0} | {} | {} | {}/{}/{}/{} | {} | {malloc} | {} |\n",
                wrk.per_second,
                wrk.transfer,
                wrk.requests,
                wrk.connect,
                wrk.read,
                wrk.write,
                wrk.timeout,
                wrk.non_2xx,
                mark.unwrap_or("")
            );
        }
    }
    out += "\n### Stages (vegeta, open loop)\n\n| Step | File | Keep-alive | Asked/s | Achieved/s | Requests | p50 ms | p99 ms | p99.9 ms | Failed | malloc failed | MB/s | Lag p99/max ms | Mark |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n";
    for row in rows {
        if let Row::Stage {
            step,
            path,
            keep_alive,
            stage: s,
            ..
        } = row
        {
            out += &format!(
                "| {step} | {path} | {} | {} | {:.0} | {} | {} | {} | {} | {} | {} | {:.1} | {}/{} | {} |\n",
                if *keep_alive { "yes" } else { "no" },
                s.asked,
                s.achieved,
                s.requests,
                ms(s.p50),
                ms(s.p99),
                ms(s.p999),
                s.failed,
                s.malloc,
                s.megabytes_per_second,
                ms(s.lag_p99),
                ms(s.lag_max),
                s.marked().unwrap_or("")
            );
        }
    }
    let reads: Vec<&Row> = rows
        .iter()
        .filter(|r| matches!(r, Row::Read { .. }))
        .collect();
    if !reads.is_empty() {
        out += "\n### Reads of the files in the guest (posix-net readfile)\n\n| File | Rounds | Mean us | Reads/s of one process | Line |\n|---|---|---|---|---|\n";
        for row in reads {
            if let Row::Read {
                path,
                rounds,
                mean_us,
                line,
            } = row
            {
                let per_second = if *mean_us > 0 {
                    format!("{:.0}", 1e6 / *mean_us as f64)
                } else {
                    "-".to_owned()
                };
                out += &format!(
                    "| {path} | {rounds} | {mean_us} | {per_second} | `{}` |\n",
                    line.trim()
                );
            }
        }
    }
    out += "\n### Commands and notes\n\n";
    for row in rows {
        match row {
            Row::Ceiling { step, command, .. } | Row::Stage { step, command, .. } => {
                out += &format!("- {step}: `{command}`\n")
            }
            Row::Note(text) => out += &format!("- {text}\n"),
            Row::Read { .. } => {}
        }
    }
    out
}

/// The server under load: nginx in a guest whose console xtask reads, or
/// Homebrew's nginx on the Mac.
enum Server<'a> {
    Guest(&'a mut qemu::Run),
    Host {
        child: Child,
        dir: PathBuf,
        conf: PathBuf,
    },
}

impl Server<'_> {
    /// A mark in the server's log, from which `log_since` reads.
    fn mark(&mut self) -> Result<usize, String> {
        Ok(self.log_lines()?.len())
    }

    fn log_lines(&mut self) -> Result<Vec<String>, String> {
        match self {
            Server::Guest(run) => {
                // The marker takes in what the console printed so far.
                static MARKS: AtomicU32 = AtomicU32::new(0);
                let tag = format!("mark{}", MARKS.fetch_add(1, Ordering::Relaxed));
                nginx_probe::marker(run, &tag, DIALOG_STEP)?;
                Ok(run.lines().to_vec())
            }
            Server::Host { dir, .. } => Ok(std::fs::read_to_string(dir.join("error.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()),
        }
    }

    fn log_since(&mut self, mark: usize) -> Result<Vec<String>, String> {
        let lines = self.log_lines()?;
        Ok(lines.get(mark..).unwrap_or_default().to_vec())
    }
}

/// The tools of the Mac and the place of a run's files.
struct Bench {
    dir: PathBuf,
    base: String,
    address: SocketAddr,
    lengths: Lengths,
    rows: Vec<Row>,
    /// The guests of vz-run when the run started (its own on VZ), and
    /// whether a new one ends the run (on VZ, where it takes the lease).
    vz_guests: usize,
    stop_on_foreign: bool,
}

/// Runs `program args`, its output into `name` in `dir`.
fn run_tool(dir: &Path, name: &str, program: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e} (brew install vegeta wrk)"))?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    std::fs::write(dir.join(name), &text).map_err(|e| format!("{name}: {e}"))?;
    if !output.status.success() {
        return Err(format!("{program} {args:?}: {}: {text}", output.status));
    }
    Ok(text)
}

/// Runs `program args` for its `seconds`, its output into `name` in `dir`,
/// while xtask reads the guest's console: at nginx's first line `[alert]`
/// or `[crit]` it ends nginx (`kill -QUIT` of the master; a worker whose
/// `epoll_wait` fails logs a line each turn of its loop, and reading such a
/// flood takes xtask longer than the guest takes to write it) and gives the
/// line. With `top`, halfway through the load the guest's `top` shows what
/// its processes take of its CPUs (into `top-TAG.txt`).
fn watched(
    server: &mut Server<'_>,
    dir: &Path,
    name: &str,
    program: &str,
    args: &[String],
    seconds: u32,
    top: Option<&str>,
) -> Result<(String, Option<String>), String> {
    let (owned_dir, owned_name, owned_program, owned_args) = (
        dir.to_path_buf(),
        name.to_owned(),
        program.to_owned(),
        args.to_vec(),
    );
    let load =
        std::thread::spawn(move || run_tool(&owned_dir, &owned_name, &owned_program, &owned_args));
    let mut seen = None;
    if let Server::Guest(run) = server {
        let started = Instant::now();
        let half = started + Duration::from_secs(u64::from(seconds) / 2);
        let end = started + Duration::from_secs(u64::from(seconds) + 2);
        if let Some(tag) = top {
            seen = alert_until(run, half);
            if seen.is_none() {
                let from = run.lines().len();
                run.send("top -b -n 1 | head -24")?;
                nginx_probe::marker(run, &format!("top-{tag}"), DIALOG_STEP * 3)?;
                let text = run.lines()[from..].join("\n");
                std::fs::write(dir.join(format!("top-{tag}.txt")), text)
                    .map_err(|e| format!("top: {e}"))?;
            }
        }
        if seen.is_none() {
            seen = alert_until(run, end);
        }
        if seen.is_some() {
            run.send("kill -QUIT $M")?;
        }
    }
    let text = load
        .join()
        .map_err(|_| format!("the thread of {program} panicked"))??;
    Ok((text, seen))
}

/// The first line of nginx at `alert` or `crit` on the console before
/// `until`.
fn alert_until(run: &mut qemu::Run, until: Instant) -> Option<String> {
    let left = until.saturating_duration_since(Instant::now());
    run.expect_line(
        "a line of nginx at alert",
        |l| l.contains("[alert]") || l.contains("[crit]"),
        left,
    )
    .ok()
}

/// The guests of vz-run on the Mac.
fn vz_guests() -> usize {
    guests().iter().filter(|g| g.contains("vz-run")).count()
}

impl Bench {
    /// Whether a guest of vz-run came up since the run started.
    fn foreign(&self) -> bool {
        vz_guests() > self.vz_guests
    }

    /// Ends the run after `step` beside a foreign guest of VZ.
    fn stop_on_foreign(&self, step: &str, foreign: bool) -> Result<(), String> {
        if foreign && self.stop_on_foreign {
            return Err(format!(
                "{step}: a foreign guest of vz-run came up beside the run (same MAC address, same lease); the run stops here"
            ));
        }
        Ok(())
    }

    /// Runs `program args`, its output into `name` in the run's directory.
    fn tool(&self, name: &str, program: &str, args: &[String]) -> Result<String, String> {
        run_tool(&self.dir, name, program, args)
    }

    /// `wrk -t2 -cC -dDs` of `path`.
    fn ceiling(
        &mut self,
        server: &mut Server<'_>,
        step: &str,
        path: &str,
        connections: u32,
    ) -> Result<(Wrk, Option<&'static str>), String> {
        let args: Vec<String> = [
            "-t2".to_owned(),
            format!("-c{connections}"),
            format!("-d{}s", self.lengths.ceiling),
            "--timeout".to_owned(),
            "10s".to_owned(),
            format!("{}{path}", self.base),
        ]
        .to_vec();
        let command = format!("wrk {}", args.join(" "));
        let mut foreign = self.foreign();
        let mark = server.mark()?;
        let name = format!("wrk-{}.txt", slug(step));
        let (text, seen) = watched(
            server,
            &self.dir,
            &name,
            "wrk",
            &args,
            self.lengths.ceiling,
            Some(&slug(step)),
        )?;
        let wrk = parse_wrk(&text).ok_or_else(|| format!("wrk printed no rate: {text}"))?;
        let log = server.log_since(mark)?;
        let malloc = malloc_failures(&log);
        let mut alerts = alerts(&log);
        alerts.extend(seen);
        foreign |= self.foreign();
        let marked = ceiling_mark(&wrk, malloc, foreign);
        println!(
            "nginx-bench: {step}: {:.0} requests/s, socket errors connect {} read {} write {} timeout {}, non-2xx {}, malloc failed {malloc}{}",
            wrk.per_second,
            wrk.connect,
            wrk.read,
            wrk.write,
            wrk.timeout,
            wrk.non_2xx,
            marked.map(|m| format!(" ({m})")).unwrap_or_default()
        );
        self.rows.push(Row::Ceiling {
            step: step.to_owned(),
            path: path.to_owned(),
            connections,
            wrk: wrk.clone(),
            malloc,
            mark: marked,
            command,
        });
        self.stop_on_foreign(step, foreign)?;
        if matches!(server, Server::Guest(_)) {
            stop_on(step, &alerts)?;
        } else if let Some(first) = alerts.first() {
            // Homebrew's nginx on macOS logs its own alerts under overload
            // (TCP_NODELAY on a socket the peer closed); they are noted.
            self.rows.push(Row::Note(format!(
                "{step}: Homebrew's nginx logged {} lines at crit or above, the first `{}`",
                alerts.len(),
                first.trim()
            )));
        }
        Ok((wrk, marked))
    }

    /// A warm-up and a stage of `vegeta attack` at `rate` of `path`.
    fn stage(
        &mut self,
        server: &mut Server<'_>,
        step: &str,
        path: &str,
        rate: u32,
        keep_alive: bool,
    ) -> Result<Stage, String> {
        let rate = rate.max(1);
        let targets = self.dir.join("targets.txt");
        std::fs::write(&targets, format!("GET {}{path}\n", self.base))
            .map_err(|e| format!("{}: {e}", targets.display()))?;
        let attack = |seconds: u32, output: &Path| -> Vec<String> {
            [
                "attack".to_owned(),
                format!("-targets={}", targets.display()),
                format!("-rate={rate}/1s"),
                format!("-duration={seconds}s"),
                format!("-keepalive={keep_alive}"),
                format!("-connections={VEGETA_CONNECTIONS}"),
                format!("-max-connections={VEGETA_CONNECTIONS}"),
                "-max-body=0".to_owned(),
                "-timeout=10s".to_owned(),
                format!("-output={}", output.display()),
            ]
            .to_vec()
        };
        let slug = slug(step);
        let warm = self.dir.join(format!("vegeta-{slug}-warm-up.bin"));
        let (_, seen) = watched(
            server,
            &self.dir,
            &format!("vegeta-{slug}-warm-up.txt"),
            "vegeta",
            &attack(self.lengths.warm_up, &warm),
            self.lengths.warm_up,
            None,
        )?;
        let _ = std::fs::remove_file(&warm);
        stop_on(&format!("{step} (warm-up)"), &Vec::from_iter(seen))?;
        let results = self.dir.join(format!("vegeta-{slug}.bin"));
        let args = attack(self.lengths.stage, &results);
        let command = format!("vegeta {}", args.join(" "))
            .replace(
                &targets.display().to_string(),
                &format!("targets.txt (GET {}{path})", self.base),
            )
            .replace(&format!("{}/", self.dir.display()), "");
        let mut foreign = self.foreign();
        let mark = server.mark()?;
        let (_, seen) = watched(
            server,
            &self.dir,
            &format!("vegeta-{slug}.txt"),
            "vegeta",
            &args,
            self.lengths.stage,
            None,
        )?;
        let log = server.log_since(mark)?;
        let malloc = malloc_failures(&log);
        let mut alerts = alerts(&log);
        alerts.extend(seen);
        self.tool(
            &format!("vegeta-{slug}-report.txt"),
            "vegeta",
            &["report".to_owned(), results.display().to_string()],
        )?;
        let samples = samples_of(&results)?;
        let length = files()
            .iter()
            .find(|(p, _)| *p == path)
            .map_or(0, |(_, bytes)| bytes.len());
        foreign |= self.foreign();
        let mut stage = stage_of(&samples, rate, malloc, length);
        stage.foreign = foreign;
        std::fs::write(
            self.dir.join(format!("seconds-{slug}.csv")),
            by_second(&samples, rate),
        )
        .map_err(|e| format!("seconds-{slug}.csv: {e}"))?;
        // The results compress well; `gunzip` gives vegeta's file back.
        let _ = Command::new("gzip").arg("-f").arg(&results).status();
        println!(
            "nginx-bench: {step}: asked {rate}/s, achieved {:.0}/s, {} requests, p50 {} ms, p99 {} ms, p99.9 {} ms, failed {}, malloc failed {}, lag p99 {} ms max {} ms{}",
            stage.achieved,
            stage.requests,
            ms(stage.p50),
            ms(stage.p99),
            ms(stage.p999),
            stage.failed,
            stage.malloc,
            ms(stage.lag_p99),
            ms(stage.lag_max),
            stage
                .marked()
                .map(|m| format!(" ({m})"))
                .unwrap_or_default()
        );
        self.rows.push(Row::Stage {
            step: step.to_owned(),
            path: path.to_owned(),
            keep_alive,
            stage: stage.clone(),
            command,
        });
        self.stop_on_foreign(step, foreign)?;
        if matches!(server, Server::Guest(_)) {
            stop_on(step, &alerts)?;
        } else if let Some(first) = alerts.first() {
            // Homebrew's nginx on macOS logs its own alerts under overload
            // (TCP_NODELAY on a socket the peer closed); they are noted.
            self.rows.push(Row::Note(format!(
                "{step}: Homebrew's nginx logged {} lines at crit or above, the first `{}`",
                alerts.len(),
                first.trim()
            )));
        }
        Ok(stage)
    }
}

/// The samples of a file of `vegeta attack`, through `vegeta encode --to csv`.
fn samples_of(results: &Path) -> Result<Vec<Sample>, String> {
    let mut child = Command::new("vegeta")
        .args(["encode", "--to", "csv"])
        .arg(results)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("vegeta encode: {e}"))?;
    let stdout = child.stdout.take().ok_or("vegeta encode: no stdout")?;
    let mut samples = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| format!("vegeta encode: {e}"))?;
        samples.push(parse_sample(&line).ok_or_else(|| format!("a line of the CSV {line:?}"))?);
    }
    let status = child.wait().map_err(|e| format!("vegeta encode: {e}"))?;
    if !status.success() {
        return Err(format!("vegeta encode: {status}"));
    }
    Ok(samples)
}

fn slug(step: &str) -> String {
    step.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// `share` per cent of `rate`.
fn share_of(rate: f64, share: u32) -> u32 {
    (rate * f64::from(share) / 100.0).round() as u32
}

/// Every file once by its SHA-256.
fn check_files(address: SocketAddr) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let first =
            Connection::open(address, Duration::from_secs(2)).and_then(|mut c| c.get("/10k.bin"));
        match first {
            Ok(_) => break,
            Err(_) if started.elapsed() < START_WITHIN => {
                std::thread::sleep(Duration::from_millis(300))
            }
            Err(why) => return Err(format!("the first request: {why}")),
        }
    }
    for (path, bytes) in files() {
        let body = Connection::open(address, Duration::from_secs(10))
            .and_then(|mut c| c.get(path))
            .map_err(|e| format!("GET {path}: {e}"))?;
        nginx_probe::same(&format!("GET {path}"), &body, bytes)?;
    }
    println!("nginx-bench: /1k.bin, /10k.bin and /256k.bin by SHA-256");
    Ok(())
}

/// The load of steps 1 to 4 against `server`; gives R_max.
fn load(bench: &mut Bench, server: &mut Server<'_>, options: &Options) -> Result<f64, String> {
    check_files(bench.address)?;
    let (ceiling, marked) = bench.ceiling(server, "2. ceiling", "/10k.bin", WRK_CONNECTIONS)?;
    if let Some(mark) = marked {
        return Err(format!(
            "the ceiling of /10k.bin is marked {mark}: no ladder is built on it"
        ));
    }
    let r_max = ceiling.per_second;
    if options.quick {
        bench.stage(
            server,
            "3. 50 % of R_max",
            "/10k.bin",
            share_of(r_max, 50),
            true,
        )?;
        return Ok(r_max);
    }
    bench.ceiling(server, "2. criterion", "/10k.bin", CRITERION_CONNECTIONS)?;
    for share in LADDER {
        bench.stage(
            server,
            &format!("3. {share} % of R_max"),
            "/10k.bin",
            share_of(r_max, share),
            true,
        )?;
    }
    bench.stage(
        server,
        "4. 1k at 50 % of R_max",
        "/1k.bin",
        share_of(r_max, 50),
        true,
    )?;
    let large = bench.ceiling(server, "4. ceiling of 256k", "/256k.bin", WRK_CONNECTIONS)?;
    bench.stage(
        server,
        "4. 256k at 50 % of its ceiling",
        "/256k.bin",
        share_of(large.0.per_second, 50),
        true,
    )?;
    if options.target == Target::Host {
        for rate in HOST_RATES {
            bench.stage(server, &format!("3h. {rate}/s"), "/10k.bin", rate, true)?;
        }
    }
    Ok(r_max)
}

/// Step 5 against `server`: a new connection for every request, at 100 and
/// 300 a second and at 25 % of R_max.
fn no_keep_alive(bench: &mut Bench, server: &mut Server<'_>, r_max: f64) -> Result<(), String> {
    for (step, rate) in [
        ("5. no keep-alive at 100/s".to_owned(), 100),
        ("5. no keep-alive at 300/s".to_owned(), 300),
        (
            "5. no keep-alive at 25 % of R_max".to_owned(),
            share_of(r_max, 25),
        ),
    ] {
        bench.stage(server, &step, "/10k.bin", rate, false)?;
    }
    Ok(())
}

/// Step 6 against `server`: the ceiling and the stage at 50 % with one
/// listening socket.
fn exclusive(bench: &mut Bench, server: &mut Server<'_>) -> Result<(), String> {
    let wrk = bench.ceiling(server, "6. exclusive ceiling", "/10k.bin", WRK_CONNECTIONS)?;
    bench.stage(
        server,
        "6. exclusive at 50 % of its ceiling",
        "/10k.bin",
        share_of(wrk.0.per_second, 50),
        true,
    )?;
    Ok(())
}

/// `nginx -c SETTINGS &` in the guest, with its PID in the shell's `M`.
fn start_guest(run: &mut qemu::Run, settings: &str) -> Result<(), String> {
    run.send(&format!("nginx -c {settings} & M=$!"))?;
    run.expect_line(
        "the event method",
        |l| l.contains("using the \"epoll\" event method"),
        START_WITHIN,
    )?;
    nginx_probe::lines_of(run, "start worker process ", 4, START_WITHIN)
}

/// `kill -QUIT` of the master and the wait for it.
fn quit_guest(run: &mut qemu::Run, tag: &str) -> Result<(), String> {
    run.send("kill -QUIT $M; wait $M")?;
    nginx_probe::marker(run, tag, Duration::from_secs(30))
}

/// `posix-net readfile` of the files nginx sends.
fn reads(bench: &mut Bench, run: &mut qemu::Run) -> Result<(), String> {
    for (path, rounds) in READ_ROUNDS {
        run.send(&format!("posix-net readfile {path} {rounds}"))?;
        let line = run.expect_line(
            "posix-net readfile",
            |l| l.contains("posix-net: readfile "),
            Duration::from_secs(60),
        )?;
        let mean_us =
            nginx_probe::readfile_mean(&line).ok_or_else(|| format!("the line {line:?}"))?;
        bench.rows.push(Row::Read {
            path: path.to_owned(),
            rounds,
            mean_us,
            line,
        });
    }
    Ok(())
}

/// The state of the network service's shared buffers as a note.
fn buffers_note(run: &mut qemu::Run, when: &str) -> Result<Row, String> {
    let (sessions, kib) = nginx_probe::buffered(run)?;
    Ok(Row::Note(format!(
        "posix-net stat {when}: {sessions} sessions hold a shared buffer, {kib} KiB went through the buffers"
    )))
}

/// The machines of QEMU and VZ running on the Mac besides the run's own
/// `own`, and the Mac's load average: they share its cores, and every guest of `vz-run` has the same
/// MAC address and so the same lease on the NAT, which a second guest
/// takes over in the middle of a stage.
fn other_guests(own: usize) -> String {
    let guests = guests();
    let load = Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    if guests.len() <= own {
        format!("none; the Mac's load average {load}")
    } else {
        format!(
            "{} ({}); the Mac's load average {load}",
            guests.len() - own,
            guests.join("; ")
        )
    }
}

/// The lines of `ps` of the machines of QEMU and VZ running on the Mac.
fn guests() -> Vec<String> {
    let list = Command::new("ps")
        .args(["-Ao", "pid,command"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    list.lines()
        .filter(|l| {
            l.split_whitespace().nth(1).is_some_and(|c| {
                c.ends_with("/vz-run") || c == "vz-run" || c.ends_with("qemu-system-aarch64")
            })
        })
        .map(|l| l.trim().chars().take(120).collect())
        .collect()
}

/// The directory of a run: `target/nginx-bench/<seconds>-<what>`.
fn run_dir(what: &str) -> Result<PathBuf, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let dir = target_dir()
        .join("nginx-bench")
        .join(format!("{seconds}-{what}"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// The head of the report: what ran where.
fn head(options: &Options, image: Option<&str>) -> String {
    let sysctl = |name: &str| {
        Command::new("sysctl")
            .args(["-n", name])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    };
    let version = |program: &str, flag: &str| {
        Command::new(program)
            .arg(flag)
            .output()
            .map(|o| {
                (String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr))
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_owned()
            })
            .unwrap_or_default()
    };
    let mut args = vec!["cargo xtask nginx-bench".to_owned()];
    args.push(format!("--machine {}", options.target.name()));
    if options.cpus != 1 {
        args.push(format!("--cpus {}", options.cpus));
    }
    if !options.buffers {
        args.push("--no-buffers".to_owned());
    }
    if options.quick {
        args.push("--quick".to_owned());
    }
    format!(
        "# nginx-bench\n\n- Command: `{}`\n- Commit: {}\n- Target: {}, {} CPU(s), shared buffers {}\n- Image: {}\n- Mac: {} ({}), {} cores, {} bytes of memory\n- wrk: {}; vegeta: {}\n- Loads: ceiling {} s, stage {} s after a warm-up of {} s\n\n",
        args.join(" "),
        crate::rtbench2::commit(),
        options.target.name(),
        options.cpus,
        if options.buffers {
            "on"
        } else {
            "off (buffers 0)"
        },
        image.unwrap_or("Homebrew nginx on the Mac"),
        sysctl("hw.model"),
        sysctl("machdep.cpu.brand_string"),
        sysctl("hw.ncpu"),
        sysctl("hw.memsize"),
        version("wrk", "--version"),
        version("vegeta", "-version"),
        Lengths::of(options.quick).ceiling,
        Lengths::of(options.quick).stage,
        Lengths::of(options.quick).warm_up,
    )
}

fn write_report(dir: &Path, head: &str, rows: &[Row]) -> Result<PathBuf, String> {
    let path = dir.join("table.md");
    std::fs::write(&path, format!("{head}{}", table(rows)))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    println!("nginx-bench: the table is {}", path.display());
    Ok(path)
}

/// Both load generators are on the Mac.
fn tools_present() -> Result<(), String> {
    for (program, flag) in [("wrk", "--version"), ("vegeta", "-version")] {
        Command::new(program)
            .arg(flag)
            .output()
            .map_err(|e| format!("{program}: {e}: brew install vegeta wrk"))?;
    }
    Ok(())
}

/// `cargo xtask nginx-bench ...`.
pub fn command(args: &[String]) -> Result<(), String> {
    let options = options(args)?;
    tools_present()?;
    match options.target {
        Target::Host => host(&options),
        _ => guest(&options),
    }
}

/// The run against stafeto in a guest.
fn guest(options: &Options) -> Result<(), String> {
    let vz = options.target == Target::Vz;
    if vz && let Some(other) = guests().iter().find(|g| g.contains("vz-run")) {
        return Err(format!(
            "another guest of vz-run runs ({other}): it has the same MAC address and takes the guest's lease; wait for it to end"
        ));
    }
    if !vz {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    crate::relibc()?;
    crate::busybox_build()?;
    crate::nano_build()?;
    crate::net_build()?;
    let kernel = build(Variant::Normal)?;
    let name = image_of(vz, options.buffers);
    let image = build_boot_image(name, programs(vz), BOOT_PROFILE)?;
    let what = format!(
        "{}-{}cpu-{}{}",
        options.target.name(),
        options.cpus,
        if options.buffers { "buffers" } else { "nobuf" },
        if options.quick { "-quick" } else { "" }
    );
    let dir = run_dir(&what)?;
    let (cmd, forwarded) = if vz {
        let machine = vz::Machine {
            cpus: Some(options.cpus),
            net: 1,
            ..vz::Machine::default()
        };
        (vz::command_on(&kernel.image, &image, machine)?, None)
    } else {
        let port = crate::net_curl::free_tcp_port()?;
        let mut cmd = qemu::on_cpus(options.cpus, || {
            qemu::command(&qemu::HVF_V3, &kernel.image, Some(&image))
        });
        cmd.args(qemu::HEADLESS);
        cmd.args(qemu::net(&[Forward {
            proto: Proto::Tcp,
            host: port,
            guest: 80,
        }]));
        (cmd, Some(port))
    };
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let head = head(options, Some(name));
    let mut rows = Vec::new();
    let mut bench: Option<Bench> = None;
    let result = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        let lease = run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        let address: SocketAddr = match forwarded {
            Some(port) => (Ipv4Addr::LOCALHOST, port).into(),
            None => {
                let lease = net_vz::parse_address(&lease, "lease")
                    .ok_or_else(|| format!("the lease {lease:?}"))?;
                (lease.address, 80).into()
            }
        };
        run.expect("# ", DIALOG_STEP)?;
        run.send("nproc")?;
        nginx_probe::marker(&mut run, "nproc", DIALOG_STEP)?;
        let cpus = run
            .lines()
            .iter()
            .rev()
            .find(|l| l.trim().parse::<usize>().is_ok())
            .map(|l| l.trim().to_owned())
            .unwrap_or_default();
        rows.push(Row::Note(format!(
            "the guest at {address} ({}), `nproc` says {cpus}; {}",
            lease.trim(),
            if vz {
                "VZ NAT, the Mac reaches the guest directly"
            } else {
                "QEMU's user network, a port of the Mac forwarded to 80"
            }
        )));
        rows.push(Row::Note(format!(
            "other guests on the Mac at the start: {}",
            other_guests(1)
        )));
        start_guest(&mut run, "/etc/nginx/nginx.conf")?;
        let bench = bench.insert(Bench {
            dir: dir.clone(),
            base: format!("http://{address}"),
            address,
            lengths: Lengths::of(options.quick),
            rows: Vec::new(),
            vz_guests: vz_guests(),
            stop_on_foreign: vz,
        });
        let r_max = load(bench, &mut Server::Guest(&mut run), options)?;
        bench
            .rows
            .push(buffers_note(&mut run, "after steps 1 to 4")?);
        if options.buffers && !options.quick {
            // Step 6, then step 5 with the package's settings again: on
            // QEMU a flood of new connections leaves the forwarded port
            // refusing for a while, and step 5 goes last.
            quit_guest(&mut run, "quit")?;
            start_guest(&mut run, "/etc/nginx/exclusive.conf")?;
            check_files(address)?;
            exclusive(bench, &mut Server::Guest(&mut run))?;
            quit_guest(&mut run, "quit-exclusive")?;
            start_guest(&mut run, "/etc/nginx/nginx.conf")?;
            check_files(address)?;
            no_keep_alive(bench, &mut Server::Guest(&mut run), r_max)?;
        }
        if !options.quick {
            reads(bench, &mut run)?;
        }
        quit_guest(&mut run, "end")?;
        Ok::<(), String>(())
    })();
    if let Some(bench) = bench.as_mut() {
        rows.append(&mut bench.rows);
    }
    rows.push(Row::Note(format!(
        "other guests on the Mac at the end: {}",
        other_guests(1)
    )));
    let output = run.stop();
    std::fs::write(dir.join("console.txt"), output.lines.join("\n"))
        .map_err(|e| format!("console.txt: {e}"))?;
    let errors: Vec<&String> = output
        .lines
        .iter()
        .filter(|l| {
            ["[alert]", "[emerg]", "[crit]"]
                .iter()
                .any(|w| l.contains(w))
        })
        .collect();
    rows.push(Row::Note(format!(
        "nginx logged {} lines at crit or above in the whole run ({} of them malloc failed){}",
        errors.len(),
        malloc_failures(&output.lines),
        errors
            .first()
            .map(|l| format!("; the first: `{}`", l.trim()))
            .unwrap_or_default()
    )));
    write_report(&dir, &head, &rows)?;
    let result = if vz { vz::stop_hint(result) } else { result };
    result?;
    if let Some(line) = output.lines.iter().find(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("init: net ended: fault")
    }) {
        return Err(format!("the image faulted: {line}"));
    }
    println!("nginx-bench passed: {}", dir.display());
    Ok(())
}

/// The reference run against Homebrew's nginx on the Mac.
fn host(options: &Options) -> Result<(), String> {
    let dir = run_dir(if options.quick { "host-quick" } else { "host" })?;
    let root = dir.join("server");
    for sub in ["www", "tmp", "logs"] {
        std::fs::create_dir_all(root.join(sub)).map_err(|e| format!("{sub}: {e}"))?;
    }
    for (path, bytes) in files() {
        std::fs::write(root.join("www").join(&path[1..]), bytes)
            .map_err(|e| format!("{path}: {e}"))?;
    }
    let port = crate::net_curl::free_tcp_port()?;
    let conf = root.join("nginx.conf");
    std::fs::write(&conf, host_conf(&root, port)).map_err(|e| format!("nginx.conf: {e}"))?;
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
    let address: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    let mut bench = Bench {
        dir: dir.clone(),
        base: format!("http://{address}"),
        address,
        lengths: Lengths::of(options.quick),
        vz_guests: vz_guests(),
        stop_on_foreign: false,
        rows: vec![Row::Note(format!(
            "Homebrew's {} at {address}, the package's settings (host_conf), kqueue",
            String::from_utf8_lossy(
                &Command::new("nginx")
                    .arg("-v")
                    .output()
                    .map(|o| o.stderr)
                    .unwrap_or_default()
            )
            .trim()
        ))],
    };
    let mut server = Server::Host {
        child,
        dir: root.clone(),
        conf,
    };
    bench.rows.push(Row::Note(format!(
        "other guests on the Mac at the start: {}",
        other_guests(0)
    )));
    let result = load(&mut bench, &mut server, options).and_then(|r_max| {
        if options.quick {
            Ok(())
        } else {
            no_keep_alive(&mut bench, &mut server, r_max)
        }
    });
    bench.rows.push(Row::Note(format!(
        "other guests on the Mac at the end: {}",
        other_guests(0)
    )));
    let Server::Host {
        mut child, conf, ..
    } = server
    else {
        unreachable!()
    };
    // The master ends its workers on SIGQUIT; its PID is the child's.
    let _ = Command::new("kill")
        .args(["-QUIT", &child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = std::fs::copy(&conf, dir.join("nginx.conf"));
    let head = head(options, None);
    write_report(&dir, &head, &bench.rows)?;
    result?;
    println!("nginx-bench passed: {}", dir.display());
    std::io::stdout().flush().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRK_OUTPUT: &str = "Running 30s test @ http://127.0.0.1:8080/10k.bin
  2 threads and 64 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     3.10ms    1.20ms  40.00ms   90.00%
    Req/Sec    10.32k   512.00    11.00k    70.00%
  616000 requests in 30.10s, 6.10GB read
  Socket errors: connect 0, read 12, write 1, timeout 3
  Non-2xx or 3xx responses: 5
Requests/sec:  20465.12
Transfer/sec:    207.52MB
";

    #[test]
    fn the_output_of_wrk_gives_the_rate_and_the_errors() {
        let wrk = parse_wrk(WRK_OUTPUT).unwrap();
        assert_eq!(wrk.requests, 616_000);
        assert!((wrk.seconds - 30.10).abs() < 1e-9);
        assert!((wrk.per_second - 20465.12).abs() < 1e-9);
        assert_eq!(wrk.transfer, "207.52MB");
        assert_eq!(
            (wrk.connect, wrk.read, wrk.write, wrk.timeout),
            (0, 12, 1, 3)
        );
        assert_eq!(wrk.non_2xx, 5);
        let clean: String = WRK_OUTPUT
            .lines()
            .filter(|l| !l.contains("Socket errors") && !l.contains("Non-2xx"))
            .map(|l| format!("{l}\n"))
            .collect();
        let wrk = parse_wrk(&clean).unwrap();
        assert_eq!((wrk.connect, wrk.read, wrk.non_2xx), (0, 0, 0));
        assert_eq!(
            parse_wrk("unable to connect to 127.0.0.1:1 Connection refused"),
            None
        );
    }

    #[test]
    fn a_line_of_the_csv_of_vegeta_gives_a_sample() {
        // The columns of vegeta 12.13.0's encoder: timestamp, code, latency,
        // bytes out, bytes in, error, body, attack, seq, method, URL, headers.
        let line = "1762300000000000000,200,1234567,0,0,,,,7,GET,http://127.0.0.1:8080/10k.bin,QWNjZXB0LVJhbmdlczogYnl0ZXM=";
        assert_eq!(
            parse_sample(line),
            Some(Sample {
                at: 1_762_300_000_000_000_000,
                code: 200,
                latency: 1_234_567,
                seq: 7,
            })
        );
        // A quoted error with commas and doubled quotes keeps seq in place.
        let failed = "1762300000000000000,0,10000000000,0,0,\"Get \"\"http://x\"\": dial tcp, a, b\",,,12,GET,http://x,";
        let failed = parse_sample(failed).unwrap();
        assert_eq!((failed.code, failed.seq), (0, 12));
        assert_eq!(parse_sample("timestamp,code"), None);
    }

    /// Samples at `rate` a second for `seconds`, the latency of the n-th
    /// `latency(n)`.
    fn samples(rate: u64, seconds: u64, latency: impl Fn(u64) -> u64) -> Vec<Sample> {
        let gap = 1_000_000_000 / rate;
        (0..rate * seconds)
            .map(|n| Sample {
                at: 1_000_000_000_000 + n * gap,
                code: 200,
                latency: latency(n),
                seq: n,
            })
            .collect()
    }

    /// The percentiles come from the latencies sorted, whatever their
    /// order in the file.
    #[test]
    fn the_percentiles_are_of_the_sorted_latencies() {
        // 1 000 latencies 1..=1000 us in a shuffled order.
        let s = samples(100, 10, |n| ((n * 7919) % 1000 + 1) * 1000);
        let stage = stage_of(&s, 100, 0, 10240);
        assert_eq!(stage.p50, Some(500_000));
        assert_eq!(stage.p99, Some(990_000));
        assert_eq!(
            percentile(&[5, 1, 9], 500),
            Some(1),
            "the input is taken as sorted"
        );
        assert_eq!(percentile(&[], 990), None);
        assert_eq!(percentile(&[7], 999), Some(7));
        assert_eq!(percentile(&[1, 2, 3, 4], 1000), Some(4));
        assert_eq!(percentile(&[1, 2, 3, 4], 1), Some(1));
    }

    #[test]
    fn a_stage_below_95_per_cent_of_its_rate_is_saturated() {
        let s = samples(1000, 10, |_| 1_000_000);
        let stage = stage_of(&s, 1000, 0, 10240);
        assert!(
            stage.achieved > 950.0 && stage.achieved <= 1000.0,
            "{}",
            stage.achieved
        );
        assert_eq!(stage.marked(), None);
        // The same answers asked at 1 100 a second: 909 achieved.
        assert_eq!(stage_of(&s, 1100, 0, 10240).marked(), Some("saturated"));
        // Answers that come late stretch the time: the last ends 2 s after
        // the requests stop.
        let late = samples(
            1000,
            10,
            |n| if n == 9999 { 2_000_000_000 } else { 1_000_000 },
        );
        assert_eq!(stage_of(&late, 1000, 0, 10240).marked(), Some("saturated"));
    }

    /// The lag of a request is its taking behind the schedule from its
    /// number; a pacer that stood and sent the missed requests at once
    /// marks the stage, though no latency grew.
    #[test]
    fn the_lag_behind_the_schedule_comes_from_seq() {
        let on_time = samples(1000, 10, |_| 1_000_000);
        assert!(lags(&on_time, 1000).iter().all(|&l| l == 0));
        let stage = stage_of(&on_time, 1000, 0, 10240);
        assert_eq!((stage.lag_p99, stage.lag_max), (Some(0), Some(0)));
        assert_eq!(stage.marked(), None);
        // vegeta stood 50 ms at every second: the 50 requests due then are
        // taken together at its end.
        let mut late = on_time.clone();
        for s in &mut late {
            let into = s.seq % 1000;
            if into < 50 {
                s.at += (50 - into) * 1_000_000;
            }
        }
        let lag = lags(&late, 1000);
        assert_eq!(lag.iter().max(), Some(&50_000_000));
        let stage = stage_of(&late, 1000, 0, 10240);
        assert_eq!(stage.p99, Some(1_000_000), "the latency did not grow");
        assert_eq!(stage.marked(), Some("generator late"));
        assert_eq!(stage.lag_max, Some(50_000_000));
    }

    #[test]
    fn the_summary_by_second_has_a_line_a_second() {
        let mut s = samples(100, 3, |n| if n == 150 { 9_000_000 } else { 1_000_000 });
        s[250].code = 0;
        let csv = by_second(&s, 100);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "second,requests,p50_ms,p99_ms,max_ms,not_200,max_lag_ms"
        );
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1], "0,100,1.000,1.000,1.000,0,0.000");
        assert_eq!(lines[2], "1,100,1.000,1.000,9.000,0,0.000");
        assert_eq!(lines[3], "2,100,1.000,1.000,1.000,1,0.000");
    }

    #[test]
    fn a_ceiling_with_errors_or_beside_a_foreign_guest_is_marked() {
        let wrk = parse_wrk(WRK_OUTPUT).unwrap();
        assert_eq!(ceiling_mark(&wrk, 0, false), Some("errors"));
        let clean = Wrk {
            read: 64,
            ..Wrk {
                per_second: 9876.0,
                ..Wrk::default()
            }
        };
        assert_eq!(ceiling_mark(&clean, 0, false), None, "reads at the end");
        assert_eq!(ceiling_mark(&clean, 1, false), Some("errors"));
        assert_eq!(ceiling_mark(&clean, 0, true), Some("foreign guest"));
        let mut stage = stage_of(&samples(100, 10, |_| 1_000_000), 100, 0, 10240);
        stage.foreign = true;
        assert_eq!(stage.marked(), Some("foreign guest"));
    }

    #[test]
    fn a_stage_with_an_error_is_marked() {
        let mut s = samples(100, 10, |_| 1_000_000);
        assert_eq!(stage_of(&s, 100, 1, 10240).marked(), Some("errors"));
        s[10].code = 0;
        let stage = stage_of(&s, 100, 0, 10240);
        assert_eq!((stage.ok, stage.failed), (999, 1));
        assert_eq!(stage.marked(), Some("errors"));
        assert_eq!(
            malloc_failures(&[
                "2026/11/05 [emerg] 259#0: *77 malloc(32768) failed (12: Out of memory)".to_owned(),
                "2026/11/05 [notice] 258#0: start worker process 259".to_owned(),
            ]),
            1
        );
    }

    #[test]
    fn a_line_at_crit_or_above_stops_the_run() {
        let lines = [
            "2026/11/05 [emerg] 259#0: *77 malloc(32768) failed (12: Out of memory)".to_owned(),
            "2026/11/05 [notice] 258#0: start worker process 259".to_owned(),
        ];
        assert!(alerts(&lines).is_empty());
        assert!(stop_on("3", &alerts(&lines)).is_ok());
        let bad =
            ["2026/11/05 02:46:55 [alert] 261#0: epoll_wait() failed (11: Try again)".to_owned()];
        assert_eq!(alerts(&bad).len(), 1);
        assert!(
            stop_on("3. 90 % of R_max", &alerts(&bad))
                .unwrap_err()
                .contains("epoll_wait")
        );
    }

    #[test]
    fn p999_needs_100_000_requests() {
        let few = stage_of(&samples(1000, 50, |n| n), 1000, 0, 10240);
        assert_eq!(few.requests, 50_000);
        assert_eq!(few.p999, None);
        let enough = stage_of(&samples(1000, 100, |n| n), 1000, 0, 10240);
        assert_eq!(enough.requests, 100_000);
        assert_eq!(enough.p999, Some(99_899));
        assert!(
            table(&[Row::Stage {
                step: "3".into(),
                path: "/10k.bin".into(),
                keep_alive: true,
                stage: few,
                command: "vegeta".into(),
            }])
            .contains("| - |")
        );
    }

    #[test]
    fn the_megabytes_count_the_answers_of_200() {
        let mut s = samples(100, 10, |_| 0);
        s[0].code = 500;
        let stage = stage_of(&s, 100, 0, 10240);
        // 999 answers of 10 240 bytes over 9.99 s.
        let want = 999.0 * 10240.0 / 9.99 / 1e6;
        assert!((stage.megabytes_per_second - want).abs() < 1e-6);
    }

    #[test]
    fn the_options() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            options(&[]).unwrap(),
            Options {
                target: Target::Hvf,
                cpus: 1,
                buffers: true,
                quick: false
            }
        );
        let o = options(&args("--vz --cpus 2 --no-buffers --quick")).unwrap();
        assert_eq!(
            (o.target, o.cpus, o.buffers, o.quick),
            (Target::Vz, 2, false, true)
        );
        assert_eq!(
            options(&args("--machine host")).unwrap().target,
            Target::Host
        );
        assert!(options(&args("--machine host --cpus 2")).is_err());
        assert!(options(&args("--cpus 0")).is_err());
        assert!(options(&args("--machine tcg")).is_err());
        assert_eq!(image_of(false, true), IMAGE);
        assert_eq!(image_of(true, false), VZ_NO_BUFFERS_IMAGE);
        assert_eq!(share_of(2000.0, 25), 500);
        assert_eq!(slug("3. 50 % of R_max"), "3-50-of-r-max");
    }

    #[test]
    fn the_settings_of_the_measurement_are_the_packages() {
        assert!(exclusive_conf().contains("listen 80;"));
        assert!(!exclusive_conf().contains("reuseport"));
        assert_eq!(
            exclusive_conf().lines().count(),
            nginx_probe::NGINX_CONF.lines().count()
        );
        let host = host_conf(Path::new("/tmp/b"), 8123);
        assert!(host.contains("listen 127.0.0.1:8123;"));
        assert!(host.contains("root /tmp/b/www;"));
        assert!(!host.contains("user ") && !host.contains("epoll") && !host.contains("/etc/"));
        for kept in [
            "worker_processes 4;",
            "worker_connections 512;",
            "keepalive_timeout 65;",
            "output_buffers 2 32k;",
            "sendfile off;",
            "tcp_nodelay on;",
            "open_file_cache max=1000 inactive=60s;",
        ] {
            assert!(host.contains(kept), "{kept}");
        }
    }

    /// The images hold nginx with the package's settings, the three files
    /// and, without the buffers, `buffers 0`; init has the table of the
    /// measurement.
    #[test]
    fn the_images_of_the_measurement() {
        use crate::rootfs::{self, Source};
        for name in IMAGES {
            let files = rootfs::files_of(name);
            let has = |path: &str| files.iter().find(|f| f.path == path);
            assert!(has("/bin/nginx").is_some(), "{name}");
            assert!(has("/bin/posix-net").is_some(), "{name}");
            assert!(
                matches!(
                    has("/etc/nginx/nginx.conf").and_then(|f| f.source),
                    Some(Source::Bytes(_, bytes)) if bytes == nginx_probe::NGINX_CONF.as_bytes()
                ),
                "{name}: the package's settings"
            );
            assert_eq!(
                has("/www/1k.bin").and_then(|f| f.source),
                Some(Source::Bytes("nginx-1k", www_1k())),
                "{name}"
            );
            assert!(has("/www/10k.bin").is_some() && has("/www/256k.bin").is_some());
            assert!(has("/etc/nginx/exclusive.conf").is_some());
            let conf = has("/etc/netd.conf").and_then(|f| f.source);
            if name.ends_with("-nobuf.img") {
                assert_eq!(conf, Some(Source::Bytes("netd.conf", NO_BUFFERS_CONF)));
            } else {
                assert_eq!(conf, None, "{name}: buffers at the default of 64");
            }
        }
        assert_eq!(programs(false)[0].3, &["table-net"]);
        assert_eq!(programs(true)[0].3, &["table-net-vz"]);
        assert!(programs(true).iter().any(|p| p.0 == "virtio-console"));
        assert!(programs(false).iter().any(|p| p.0 == "nginx"));
        assert_eq!(www_1k().len(), WWW_1K_LEN);
        assert_ne!(www_1k(), &nginx_probe::www_10k()[..WWW_1K_LEN]);
    }
}
