// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probes of the switch of the network service with nginx on the stack
//! as its consumer (`cargo xtask fast-probe switch ...`, stage Sh4b2): the
//! image with one network device (`boot-fast-switch.img`, init's table
//! `table-fast-switch`, `netd.conf` with `switch 8` and `flows 16384`), and
//! `nginx-fast` under nobody on the address of the lease.
//!
//! * `switch`: BusyBox `httpd` on 8080 and `nginx-fast` with four workers on
//!   80 in one run; 200 requests from the host to each, byte for byte; the
//!   counters of `posix-net stat` show four consumers, each with a share of
//!   the frames, no frame to the device with the shared address as its
//!   destination; a `wget` of the guest to nginx-fast on the shared address
//!   (the turn of the switch) comes whole, and the turned frames count; no
//!   reset of the device.
//! * `switch kill`: under a stream of new connections `kill -9` of a worker
//!   (one worker, then four): no connection fails, the first connection after
//!   the kill is answered, the device is never reset; with one worker the SYNs
//!   of the gap wait in the park and the new worker gets them.
//! * `switch idle`: a request after 2 s of rest, on an open connection and on
//!   a new one, is answered within 50 ms (a lost wake would wait for a tick).
//! * `switch steps`: the start and the first pages under -icount with the
//!   service counting its steps: every step, those of the switch among them
//!   (kinds 67 to 70), is under 0.9 of term B.
//! * `switch saturate`: three programs keep their rings full of entries the switch refuses, on
//!   four CPUs, while the probe asks `posix-net stat` four times; the switch (a level above the
//!   stack and the services on its CPU) holds a kernel time budget and budgets the consumers'
//!   time, so the stack answers within seconds and init's watchdog kills nothing (without them
//!   init kills the network service as silent).
//! * `switch share`: under -icount on one CPU, datagrams from the host keep the network service
//!   busy while a loop on CPU 0 counts what the levels below the switch get: in every window of
//!   10 ms it keeps at least `SHARE_MIN_PERCENT` of its rate with no flood (stafeto-design#655;
//!   the service has no pause of its own: its kernel budgets leave the time).
//! * `switch-probe`: the C program over the ring sends the frames the switch
//!   refuses; each is counted by its reason, none reaches the wire (the
//!   capture of the device), a broken ring disables its consumer alone.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::fast_nginx::{self, Kind, TINY};
use crate::nginx_probe::{Connection, same};
use crate::qemu::{self, Forward, Proto};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net_probe, relibc,
};

const CONF4: &str = "/etc/nginx/nginx-fast-4.conf";
const CONF9: &str = "/etc/nginx/nginx-fast-9.conf";
const CONF_B: &str = "/etc/nginx/nginx-fast-b.conf";
const CONF1: &str = "/etc/nginx/nginx-fast.conf";
const REQUESTS: usize = 200;
/// The requests through the proxy to `httpd` on 127.0.0.1:8080, made in batches of this size. A
/// stream of the service that has closed holds its four until the sweep frees it, and a worker's
/// next connection may pick the same source port (the workers choose theirs at random from a
/// block of 512): the service then lets the SYN start a new stream and counts it
/// (`orphan_reused`). The case comes by chance, so the probe asks for it after each batch.
const PROXY_BATCH: usize = 100;
/// The most proxied requests the probe makes while waiting for the case. Forty runs on the
/// GitHub runners met it after 100 to 1000 requests, 307 on the mean (counted in whole batches,
/// so the true mean is near 260): one request meets it with a chance of about 1 in 260. With
/// 4000 requests a false failure has the chance (1 - 1/260)^4000 = 2e-7, and a chance 1.5 times
/// lower than measured still leaves 4e-5, under the bound of 1e-4 the probe holds. A run that
/// meets the case early stops early (about 40 s); the worst run makes 4000 requests.
const PROXY_MAX: usize = 4000;
/// The requests to nginx-fast's own port 80 through the proxy of the same worker.
const SELF_REQUESTS: usize = 20;
/// How long `posix-net stat` may take to answer in the flood of `share`, in the time of the
/// host: a process that starts beside the flood and asks the service for its session, and then
/// three requests, on QEMU under -icount (the time of the host runs several times past the
/// time of the guest there).
const STAT_FLOOD_BOUND: Duration = Duration::from_secs(5);
/// How long `saturate` floods the ring.
const SATURATE_SECS: u64 = 300;
/// How many answers of `posix-net stat` the flood must get, and the bound of each: this many
/// times the answer of the quiet stack, but not under `SATURATE_FLOOR` (a slow host spends seconds
/// starting `posix-net` beside three programs at full speed, 6 s on the CI machine; a stack the
/// switch keeps off the processor is killed by init).
const SATURATE_SAMPLES: usize = 3;
/// The flood must last this long before the probe judges init's silence, and the samples lie
/// this far apart.
const SATURATE_LONG: Duration = Duration::from_secs(20);
const SATURATE_APART: Duration = Duration::from_secs(2);
/// The seconds the loop on CPU 0 counts for. Its share is logged only in `saturate` (local
/// TCG runs: 12 and 13 % with neither budget nor pause, 19 and 20 % with the pause alone, so TCG
/// does not tell the pause from the budget) and checked in `share`, under -icount.
const SPIN_SECS: u64 = 3;
/// The least share of its quiet rate the loop on CPU 0 keeps in any window of 10 ms of the flood
/// of `share`: the note's 20 % (stafeto-design `tasks/2026-11-14-sched-budgets-design.md`, the
/// layout of CPU 0). The switch's pause of 100 us in each run of 2 ms left it 4.8 %.
const SHARE_MIN_PERCENT: u64 = 20;
/// The datagrams of the flood of `share`: the threads that send, and the bytes of each.
const FLOOD_THREADS: usize = 3;
const FLOOD_BYTES: usize = 64;
/// The guest's port the datagrams go to: held by nobody.
const FLOOD_PORT: u16 = 9;
const SATURATE_BOUND: u32 = 40;
const SATURATE_FLOOR: Duration = Duration::from_secs(12);
/// How many programs flood a ring at once.
const SATURATE_CONSUMERS: usize = 3;
const READ_WITHIN: Duration = Duration::from_secs(60);
/// The share each worker's frames take at least, of those of all.
const SHARE_MIN: f64 = 0.10;
const IDLE_WITHIN: Duration = Duration::from_millis(50);
/// The wire's frames the capture of the probe keeps.
const PCAP: &str = "switch-probe.pcap";

/// `nginx-fast.conf` of the switch with four workers, and two locations over the loopback
/// network (R-2b): `/up/` goes to BusyBox's `httpd` of the service's stack on 127.0.0.1:8080 (a
/// packet for a port of another stack), `/self/` to the worker's own listener on 127.0.0.1:80
/// (a port of its own stack, which stays on its loopback interface).
pub fn conf4() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        let text = crate::nginx_probe::replaced(
            fast_nginx::switch_conf(),
            "worker_processes 1;",
            "worker_processes 4;",
        );
        crate::nginx_probe::replaced(
            &text,
            "        location / { }\n",
            "        location / { }\n        location /up/ { proxy_buffering off; proxy_pass http://127.0.0.1:8080/; }\n        location /up2/ { proxy_buffering off; proxy_pass http://127.0.0.1:8081/; }\n        location /self/ { proxy_pass http://127.0.0.1:80/; }\n",
        )
    })
}

/// `nginx-fast.conf` of the switch with nine workers: the ring budget of the service holds eight.
pub fn conf9() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        crate::nginx_probe::replaced(
            fast_nginx::switch_conf(),
            "worker_processes 1;",
            "worker_processes 9;",
        )
    })
}

/// The settings of a second nginx-fast, a consumer of its own on port 8081 (`/up2/` of the first
/// proxies to it over 127.0.0.1: a transfer between two stacks of consumers).
pub fn conf_b() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        let text =
            crate::nginx_probe::replaced(fast_nginx::switch_conf(), "listen 80;", "listen 8081;");
        crate::nginx_probe::replaced(
            &text,
            "pid /var/run/nginx-fast.pid;",
            "pid /var/run/nginx-fast-b.pid;",
        )
    })
}

pub fn command(args: &[String]) -> Result<(), String> {
    match args {
        [] => probe(Scenario::Plain),
        [a] if a == "kill" => probe(Scenario::Kill),
        [a] if a == "idle" => probe(Scenario::Idle),
        [a] if a == "attach" => probe(Scenario::Attach),
        [a] if a == "steps" => probe(Scenario::Steps),
        [a] if a == "frames" => probe(Scenario::Frames),
        [a] if a == "saturate" => probe(Scenario::Saturate),
        [a] if a == "share" => probe(Scenario::Share),
        _ => Err(
            "usage: cargo xtask fast-probe switch [kill|idle|attach|steps|frames|saturate|share]"
                .to_owned(),
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Scenario {
    Plain,
    Kill,
    Idle,
    /// `attach`: eight workers attach, the ninth is refused up front.
    Attach,
    Steps,
    /// `switch-probe`.
    Frames,
    /// `saturate`: a consumer floods its TX ring; the stack and init's watchdog are checked.
    Saturate,
    /// `share`: datagrams from the host keep the network service busy on its CPU under
    /// -icount; the share of that CPU a loop below the switch keeps is checked.
    Share,
    /// `share` on the service with the deliberate break `break-budget-unbound`: the probe must fail.
    ShareUnbound,
}

/// A counter of a line of the service after `key`.
fn counter(line: &str, key: &str) -> Option<u64> {
    let rest = line.split(&format!(" {key} ")).nth(1)?;
    rest.split([' ', ',']).next()?.parse().ok()
}

/// The longest wait of a request of the service in the flood of `share`, in the guest's time.
const ASK_FLOOD_BOUND_US: u64 = 5_000;

/// `switch-probe ask`: the requests it made and the longest wait of one, in microseconds of the
/// guest's time.
fn ask(run: &mut qemu::Run) -> Result<(u64, u64), String> {
    run.send("switch-probe ask 2")?;
    let line = run.expect_line(
        "the waits of `switch-probe ask`",
        |l| l.contains("switch-probe: ask calls "),
        Duration::from_secs(120),
    )?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let number = |name: &str| -> Result<u64, String> {
        let at = words.iter().position(|w| *w == name).ok_or(line.clone())?;
        words
            .get(at + 1)
            .and_then(|w| w.parse().ok())
            .ok_or_else(|| format!("no {name} in {line:?}"))
    };
    Ok((number("calls")?, number("max_us")?))
}

/// What `posix-net stat` makes the service say: the last lines `net: switch`.
struct Stat {
    consumers: u64,
    hairpin: u64,
    own_to_device: u64,
    tx_refused: u64,
    /// Parked SYNs given to a member that joined.
    park_given: u64,
    /// Packets of the loopback network routed through the tables.
    looped: u64,
    /// Memberships ended by LEAVE.
    left: u64,
    /// Consumer numbers that left and wait for the sweep (`sweeping`): ATTACH of a new worker
    /// has no number for them yet.
    sweeping: u64,
    /// Closed streams whose four a new SYN took over before the sweep.
    orphan_reused: u64,
    /// The refusals by reason (cumulative, also of consumers that left).
    refused_by: Vec<u64>,
    rx_by: Vec<u64>,
    line: String,
}

fn stat(run: &mut qemu::Run, tag: &str) -> Result<Stat, String> {
    stat_within(run, tag, Duration::from_secs(120))
}

/// `stat` with the time its answer may take.
fn stat_within(run: &mut qemu::Run, tag: &str, within: Duration) -> Result<Stat, String> {
    // The counter lines are under the 128 bytes (`LINE_MAX` of the console's driver, which
    // puts out a longer line in parts, and reassembles the 64-byte pieces of a line up to
    // that length) and so come whole. A line that came without a counter is asked for again:
    // the counters are cumulative. The retry is a safety net.
    let mut last = String::new();
    for _ in 0..STAT_ATTEMPTS {
        match stat_once(run, tag, within) {
            Ok(stat) => return Ok(stat),
            Err(e) if e.starts_with(TORN) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// How many times `stat` asks when the counter line comes cut.
const STAT_ATTEMPTS: usize = 4;
/// The start of the error for a counter line that came cut.
const TORN: &str = "torn counter line";

/// One `posix-net stat` and the parse of its lines.
fn stat_once(run: &mut qemu::Run, tag: &str, within: Duration) -> Result<Stat, String> {
    let from = run.lines().len();
    run.send("posix-net stat")?;
    // The service prints its counters when the request is over, so they may come after the
    // next prompt: the last line of them is waited for.
    run.expect_line(
        "the counters of the switch",
        |l| l.contains("net: switch rx_by "),
        within,
    )?;
    let _ = tag;
    let lines: Vec<String> = run.lines()[from..].to_vec();
    // The counters come in three lines (`report_switch`), each under the 128 bytes of a part
    // of the console; they are read as one.
    let mut parts = Vec::new();
    for head in [
        "net: switch consumers ",
        "net: switch tx_refused ",
        "net: switch left ",
    ] {
        let part = lines
            .iter()
            .rev()
            .find(|l| l.contains(head))
            .ok_or_else(|| format!("no line `{head}` after posix-net stat: {lines:?}"))?;
        parts.push(part.as_str());
    }
    let line = parts.join(" ");
    let by = lines
        .iter()
        .rev()
        .find(|l| l.contains("net: switch rx_by "))
        .ok_or("no line `net: switch rx_by`")?;
    let inner = by
        .split('[')
        .nth(1)
        .and_then(|r| r.split(']').next())
        .ok_or("rx_by")?;
    let rx_by: Vec<u64> = inner
        .split(',')
        .filter_map(|n| n.trim().parse().ok())
        .collect();
    let refused_by: Vec<u64> = lines
        .iter()
        .rev()
        .find(|l| l.contains("refused_by ["))
        .and_then(|l| l.split("refused_by [").nth(1))
        .and_then(|r| r.split(']').next())
        .map(|inner| {
            inner
                .split(',')
                .filter_map(|n| n.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    let orphan_reused = lines
        .iter()
        .rev()
        .find(|l| l.contains("net: frames rx "))
        .and_then(|l| counter(l, "orphan_reused"))
        .ok_or_else(|| format!("{TORN}: no orphan_reused in the line `net: frames rx`"))?;
    Ok(Stat {
        orphan_reused,
        refused_by,
        consumers: counter(&line, "consumers").ok_or_else(|| torn(&line))?,
        hairpin: counter(&line, "hairpin").ok_or_else(|| torn(&line))?,
        own_to_device: counter(&line, "own_to_device").ok_or_else(|| torn(&line))?,
        tx_refused: counter(&line, "tx_refused").ok_or_else(|| torn(&line))?,
        park_given: counter(&line, "park_given").ok_or_else(|| torn(&line))?,
        looped: counter(&line, "looped").ok_or_else(|| torn(&line))?,
        left: counter(&line, "left").ok_or_else(|| torn(&line))?,
        sweeping: counter(&line, "sweeping").ok_or_else(|| torn(&line))?,
        rx_by,
        line,
    })
}

/// The error for a counter line that lacks a counter, which is a line cut by another writer.
fn torn(line: &str) -> String {
    format!("{TORN}: {line:?}")
}

/// The shell prompt and the lease (one device).
pub(crate) fn booted(run: &mut qemu::Run) -> Result<(), String> {
    run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
    run.expect("net: lease 10.0.2.15/24", BOOT_TIMEOUT)?;
    run.expect("# ", DIALOG_STEP)?;
    run.send("S=ok")?;
    run.expect("# ", DIALOG_STEP)?;
    Ok(())
}

fn kind_of(s: Scenario) -> Kind {
    match s {
        Scenario::Steps => Kind::SwitchSteps,
        Scenario::ShareUnbound => Kind::SwitchUnbound,
        _ => Kind::Switch,
    }
}

pub fn probe(scenario: Scenario) -> Result<(), String> {
    let machine = &qemu::VIRT;
    relibc()?;
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    crate::probe_ca::ensure(false)?;
    let kernel = build(Variant::Normal)?;
    let kind = kind_of(scenario);
    let (name, programs) = (
        match kind {
            Kind::SwitchSteps => fast_nginx::SWITCH_STEPS_IMAGE,
            Kind::SwitchUnbound => fast_nginx::SWITCH_UNBOUND_IMAGE,
            _ => fast_nginx::SWITCH_IMAGE,
        },
        fast_nginx::programs(kind),
    );
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let ports = (
        crate::net_curl::free_tcp_port()?,
        crate::net_curl::free_tcp_port()?,
    );
    let udp_port = free_udp_port()?;
    let dir = crate::target_dir().join("fast-switch");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let pcap = dir.join(PCAP);
    let _ = std::fs::remove_file(&pcap);
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut forwards = vec![
        Forward {
            proto: Proto::Tcp,
            host: ports.0,
            guest: 80,
        },
        Forward {
            proto: Proto::Tcp,
            host: ports.1,
            guest: 8080,
        },
    ];
    if matches!(scenario, Scenario::Share | Scenario::ShareUnbound) {
        // The flood: datagrams to a port nobody holds, which the stack answers.
        forwards.push(Forward {
            proto: Proto::Udp,
            host: udp_port,
            guest: FLOOD_PORT,
        });
    }
    let mut net = qemu::net(&forwards);
    if scenario == Scenario::Frames {
        net.extend([
            "-object".to_owned(),
            format!("filter-dump,id=f9,netdev=n0,file={}", pcap.display()),
        ]);
    }
    cmd.args(net);
    if matches!(
        scenario,
        Scenario::Steps | Scenario::Share | Scenario::ShareUnbound
    ) {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    // The flood needs CPUs besides the switch's for the programs that make it.
    if scenario == Scenario::Saturate {
        cmd.args(["-smp", "4"]);
    }
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let began = Instant::now();
    let nginx: SocketAddr = ([127, 0, 0, 1], ports.0).into();
    let httpd: SocketAddr = ([127, 0, 0, 1], ports.1).into();
    let mut notes: Vec<String> = Vec::new();
    let talked = match scenario {
        Scenario::Plain => plain(&mut run, nginx, httpd, &mut notes),
        Scenario::Kill => kill(&mut run, nginx, &mut notes),
        Scenario::Idle => idle(&mut run, nginx, &mut notes),
        Scenario::Attach => attach(&mut run, nginx, &mut notes),
        Scenario::Steps => steps(&mut run, nginx, &mut notes),
        Scenario::Frames => frames(&mut run, &pcap, &mut notes),
        Scenario::Saturate => saturate(&mut run, &mut notes),
        Scenario::Share => share(&mut run, udp_port, &mut notes, false),
        Scenario::ShareUnbound => share(&mut run, udp_port, &mut notes, true),
    };
    let output = run.stop();
    crate::symbolize::backtrace(&output.lines, &kernel.elf);
    for note in &notes {
        println!("fast-switch: {note}");
    }
    talked?;
    // The workers killed by the probes end on signal 9.
    fast_nginx::verdict(&output.lines, 0)?;
    net_probe::placing_fault(&output.lines)?;
    if let Some(line) = output
        .lines
        .iter()
        .find(|l| l.contains("net: device 1 back") || l.contains("net: switch ring broken"))
        && scenario != Scenario::Frames
    {
        return Err(format!("the service said {line:?}"));
    }
    if scenario == Scenario::Steps {
        let rows = net_probe::longest_over_starts(&output.lines);
        crate::step_line::within_b(
            &output.lines,
            net_probe::NET_TAG,
            crate::step_line::Kinds::All,
        )?;
        if let Some(row) = rows.iter().find(|r| r.1 > net_probe::STEP_MAX) {
            return Err(format!(
                "the network service: a step past 0.9 of term B ({}): {row:?}",
                net_probe::STEP_MAX
            ));
        }
        for kind in [67, 68, 69, 70] {
            if !rows.iter().any(|r| r.0 == kind) {
                return Err(format!("no step of the switch of kind {kind}: {rows:?}"));
            }
        }
        println!(
            "fast-switch steps: every kind: {rows:?} (bound {})",
            net_probe::STEP_MAX
        );
        net_probe::say_margin("fast-probe switch steps", &rows);
    }
    println!(
        "fast-switch {scenario:?} passed in {:.0} s",
        began.elapsed().as_secs_f64()
    );
    Ok(())
}

fn start(run: &mut qemu::Run, conf: &str) -> Result<(), String> {
    fast_nginx::started(run, conf).map(drop)
}

fn requests(
    what: &str,
    address: SocketAddr,
    path: &str,
    want: &[u8],
    n: usize,
) -> Result<(), String> {
    for i in 0..n {
        let body = Connection::open(address, READ_WITHIN)
            .and_then(|mut c| c.get(path))
            .map_err(|e| format!("{what}: request {i}: {e}"))?;
        same(what, &body, want)?;
    }
    Ok(())
}

fn plain(
    run: &mut qemu::Run,
    nginx: SocketAddr,
    httpd: SocketAddr,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    booted(run)?;
    if std::env::var_os("FAST_SWITCH_NOHTTPD").is_none() {
        run.send("httpd -f -p 8080 -h /www &")?;
        run.expect("# ", DIALOG_STEP)?;
    }
    run.send("export STAFETO_FAST_STATS=1")?;
    run.expect("# ", DIALOG_STEP)?;
    let conf4 = std::env::var_os("FAST_SWITCH_ONE").is_none();
    start(run, if conf4 { CONF4 } else { CONF1 })?;
    let (_, workers) = fast_nginx::master_and_workers(run, "w", false)?;
    if workers.len() != if conf4 { 4 } else { 1 } {
        return Err(format!("{} workers, wanted 4", workers.len()));
    }
    requests("nginx-fast /tiny.txt", nginx, "/tiny.txt", TINY, REQUESTS)?;
    requests(
        "httpd /index.html",
        httpd,
        "/index.html",
        crate::rootfs::www_index(),
        REQUESTS,
    )?;
    notes.push(format!(
        "{REQUESTS} requests each to nginx-fast and httpd answered whole"
    ));
    let first = stat(run, "s1")?;
    notes.push(first.line.clone());
    if first.consumers != 4 {
        return Err(format!(
            "{} consumers, wanted 4: {}",
            first.consumers, first.line
        ));
    }
    let total: u64 = first.rx_by.iter().sum();
    let shares: Vec<f64> = first
        .rx_by
        .iter()
        .take(4)
        .map(|n| *n as f64 / total.max(1) as f64)
        .collect();
    // The consumer numbers are those the switch gave; the four with frames.
    let busy: Vec<f64> = first
        .rx_by
        .iter()
        .filter(|n| **n > 0)
        .map(|n| *n as f64 / total.max(1) as f64)
        .collect();
    if busy.len() != 4 || busy.iter().any(|s| *s < SHARE_MIN) {
        return Err(format!(
            "the frames of the workers {:?} (shares {shares:?}): each of four needs {SHARE_MIN}",
            first.rx_by
        ));
    }
    notes.push(format!("the shares of the workers: {busy:?}"));
    // The guest to nginx-fast on the shared address: the turn of the switch.
    run.send("wget -T 20 -q -O - http://10.0.2.15/tiny.txt; echo ngx-wget-end")?;
    let text = std::str::from_utf8(TINY)
        .map_err(|e| e.to_string())?
        .trim_end()
        .to_owned();
    if let Err(why) = run.expect_line(
        "the page by wget",
        |l| l.trim_end() == text,
        Duration::from_secs(40),
    ) {
        let seen = stat(run, "dbg").map(|s| s.line).unwrap_or_default();
        return Err(format!("{why}; the service says {seen}"));
    }
    let second = stat(run, "s2")?;
    if second.hairpin <= first.hairpin || second.hairpin == 0 {
        return Err(format!(
            "no frame turned at the shared address: {}",
            second.line
        ));
    }
    if second.own_to_device != 0 {
        return Err(format!(
            "frames to the device with the shared address as the destination: {}",
            second.line
        ));
    }
    notes.push(format!(
        "the guest's wget to the shared address came whole: {} frames turned, tx_refused {}",
        second.hairpin, second.tx_refused
    ));
    loopback(run, nginx, second.looped, notes)
}

/// The loopback network between stacks (R-2b): a `wget` of the guest to nginx-fast on 127.0.0.1
/// (the service's stack to a worker), nginx-fast as a proxy to `httpd` on 127.0.0.1:8080 (a worker
/// to the service's stack), and a worker's own loopback (its own port stays in its stack). The
/// packets of the first two go through the tables (`looped` grows), nothing of them reaches the
/// device.
fn loopback(
    run: &mut qemu::Run,
    nginx: SocketAddr,
    looped0: u64,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    let text = std::str::from_utf8(TINY)
        .map_err(|e| e.to_string())?
        .trim_end()
        .to_owned();
    run.send("wget -T 20 -q -O - http://127.0.0.1/tiny.txt; echo ngx-lo-end")?;
    if let Err(why) = run.expect_line(
        "the page by wget over 127.0.0.1",
        |l| l.trim_end() == text,
        Duration::from_secs(40),
    ) {
        let seen = stat(run, "lo")?.line;
        return Err(format!("{why}; the service says {seen}"));
    }
    run.expect("ngx-lo-end", Duration::from_secs(40))?;
    let after_wget = stat(run, "lo1")?;
    if after_wget.looped <= looped0 {
        return Err(format!(
            "no packet of the loopback network went through the tables: {}",
            after_wget.line
        ));
    }
    // The case comes by chance (see `PROXY_BATCH`): the requests go in batches and stop at the
    // first batch after which the service has counted it.
    let mut proxied = 0;
    while proxied < PROXY_MAX {
        if let Err(why) = requests(
            "nginx-fast as a proxy to httpd over 127.0.0.1",
            nginx,
            "/up/index.html",
            crate::rootfs::www_index(),
            PROXY_BATCH,
        ) {
            let seen = stat(run, "lo-dbg").map(|s| s.line).unwrap_or_default();
            let drops: Vec<String> = run
                .lines()
                .iter()
                .filter(|l| l.contains("net: switch dropped") || l.contains("net: bypass"))
                .rev()
                .take(2)
                .cloned()
                .collect();
            return Err(format!("{why}; the service says {seen} {drops:?}"));
        }
        proxied += PROXY_BATCH;
        if stat(run, "lo-case")?.orphan_reused > 0 {
            break;
        }
    }
    notes.push(format!(
        "{proxied} proxied requests until a SYN met a closed stream on its four"
    ));
    // The last proxied connection is still closing: its final packets count in `looped` until
    // two readings agree.
    let mut after_proxy = stat(run, "lo2")?;
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(250));
        let again = stat(run, "lo2")?;
        let settled = again.looped == after_proxy.looped;
        after_proxy = again;
        if settled {
            break;
        }
    }
    if after_proxy.looped <= after_wget.looped {
        return Err(format!(
            "the proxy's packets did not go through the tables: {}",
            after_proxy.line
        ));
    }
    if after_proxy.orphan_reused == 0 {
        return Err(format!(
            "no SYN of {proxied} proxied requests met a closed stream on its four: the probe does not reach the case: {}",
            after_proxy.line
        ));
    }
    requests(
        "a worker's own loopback",
        nginx,
        "/self/tiny.txt",
        TINY,
        SELF_REQUESTS,
    )?;
    // A packet for a port of the worker's own stack stays on its loopback interface: the 20
    // requests (and the proxy's own connections to port 80) leave nothing in the tables. The
    // streams of the proxy that closed earlier may still send a stray packet of their end
    // (a late ACK or RST), so a few are allowed; a request that went through the ring is a
    // dozen packets.
    let after_self = stat(run, "lo3")?;
    if after_self.looped - after_proxy.looped >= SELF_REQUESTS as u64 {
        return Err(format!(
            "the worker's own loopback went out through the ring: {} packets",
            after_self.looped - after_proxy.looped
        ));
    }
    if after_proxy.own_to_device != 0 || after_proxy.tx_refused != 0 {
        return Err(format!(
            "frames refused or sent to the device: {}",
            after_proxy.line
        ));
    }
    // Two consumers: a second nginx-fast holds port 8081, and the first proxies 1 MiB from it over
    // 127.0.0.1. The segments are sized for 1500 (the loopback MTU of the stack), pass the ring of
    // the first, the tables and the ring of the second, and the answers come back the same way.
    run.send(&format!("nginx-fast -c {CONF_B} & M2=$!"))?;
    run.expect_line(
        "the stack of the second nginx-fast",
        |l| l.contains("fast: the stack is up on "),
        Duration::from_secs(60),
    )?;
    let before = stat(run, "lo4")?;
    requests(
        "a consumer to a consumer over 127.0.0.1",
        nginx,
        "/up2/1m.bin",
        fast_nginx::one_mib(),
        3,
    )?;
    let after_pair = stat(run, "lo5")?;
    if after_pair.looped < before.looped + 3 * 700 {
        return Err(format!(
            "{} packets through the tables for 3 MiB between two consumers: {}",
            after_pair.looped - before.looped,
            after_pair.line
        ));
    }
    if after_pair.tx_refused != 0 {
        return Err(format!("packets refused: {}", after_pair.line));
    }
    notes.push(format!(
        "loopback: wget over 127.0.0.1 and a proxy to httpd came whole, {} packets through the tables, a worker's own loopback answered",
        after_proxy.looped - looped0
    ));
    Ok(())
}

/// A request of the stream that failed: when it began and ended, and why.
#[derive(Clone)]
struct Failure {
    began: Instant,
    ended: Instant,
    why: String,
}

/// A stream of new connections from the host, each a GET of the small page,
/// until `stop`; the failures and the number answered.
struct Stream {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    answered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    failures: std::sync::Arc<std::sync::Mutex<Vec<Failure>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Stream {
    fn start(address: SocketAddr) -> Stream {
        use std::sync::{Arc, Mutex, atomic::AtomicBool, atomic::AtomicUsize};
        let stop = Arc::new(AtomicBool::new(false));
        let answered = Arc::new(AtomicUsize::new(0));
        let failures = Arc::new(Mutex::new(Vec::new()));
        let (s, a, f) = (stop.clone(), answered.clone(), failures.clone());
        let thread = std::thread::spawn(move || {
            use std::sync::atomic::Ordering::Relaxed;
            while !s.load(Relaxed) {
                let began = Instant::now();
                let failed = |why: String| Failure {
                    began,
                    ended: Instant::now(),
                    why,
                };
                match Connection::open(address, READ_WITHIN).and_then(|mut c| c.get("/tiny.txt")) {
                    Ok(body) if body == TINY => {
                        a.fetch_add(1, Relaxed);
                    }
                    Ok(_) => f.lock().unwrap().push(failed("a wrong page".to_owned())),
                    Err(e) => f.lock().unwrap().push(failed(e)),
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        Stream {
            stop,
            answered,
            failures,
            thread: Some(thread),
        }
    }

    fn answered(&self) -> usize {
        self.answered.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn finish(mut self) -> Vec<Failure> {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.failures.lock().unwrap().clone()
    }
}

/// How long after `kill -9` was sent a request may still begin on a socket of the dying worker:
/// the line crosses the console, the shell runs `kill`, and TCG may be slow.
const KILL_SLACK: Duration = Duration::from_secs(2);
/// How long after the kill the service may take to reset the connection of the worker that died
/// (1.3 s seen on TCG); a read that timed out takes `READ_WITHIN`.
const KILL_RESET_WITHIN: Duration = Duration::from_secs(10);

/// The requests of the stream that failed over the kill of a worker. The stream asks one at a
/// time, so the kill meets at most one request in flight, and a request that a killed worker
/// had accepted and not answered ends in a reset or an end of the stream on a connection that was
/// up: that one is expected, and the service ends it within `KILL_RESET_WITHIN` of the kill (it
/// took 1.3 s on TCG, after the new worker's stack was up). Every other request (a timeout, a
/// refused connection, one that began after the worker was gone) must have been answered. The number of requests the kill reset, or what went wrong.
fn over_the_kill(failures: &[Failure], killed: Instant) -> Result<usize, String> {
    let offset = |t: Instant| -> i128 {
        if t >= killed {
            t.duration_since(killed).as_millis() as i128
        } else {
            -(killed.duration_since(t).as_millis() as i128)
        }
    };
    let seen: Vec<String> = failures
        .iter()
        .map(|f| {
            format!(
                "{} ms to {} ms from the kill: {}",
                offset(f.began),
                offset(f.ended),
                f.why
            )
        })
        .collect();
    let reset = |why: &str| {
        why.contains("closed with") || why.contains("reset") || why.contains("Broken pipe")
    };
    if failures.len() > 1
        || failures.iter().any(|f| {
            f.began > killed + KILL_SLACK || f.ended > killed + KILL_RESET_WITHIN || !reset(&f.why)
        })
    {
        return Err(format!(
            "{} requests failed over the kill, one in flight may, as a reset or an end of the stream within {} s of the kill: {seen:?}",
            failures.len(),
            KILL_RESET_WITHIN.as_secs()
        ));
    }
    Ok(failures.len())
}

/// Connections opened every 10 ms while a worker is gone: each sends a GET and is held until
/// `finish`, which returns how many were opened.
struct Gap {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<usize>,
}

impl Gap {
    fn start(address: SocketAddr) -> Gap {
        use std::io::Write;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut held = Vec::new();
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(mut c) = std::net::TcpStream::connect(address) {
                    let _ = c.write_all(b"GET /tiny.txt HTTP/1.1\r\nHost: x\r\n\r\n");
                    held.push(c);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            held.len()
        });
        Gap { stop, thread }
    }

    fn finish(self) -> usize {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.thread.join().unwrap_or(0)
    }
}

fn kill(run: &mut qemu::Run, nginx: SocketAddr, notes: &mut Vec<String>) -> Result<(), String> {
    booted(run)?;
    for (conf, count) in [(CONF1, 1usize), (CONF4, 4)] {
        start(run, conf)?;
        let (m, workers) = fast_nginx::master_and_workers(run, &format!("k{count}"), false)?;
        if workers.len() != count {
            return Err(format!("{} workers, wanted {count}", workers.len()));
        }
        requests("before the kill", nginx, "/tiny.txt", TINY, 10)?;
        let stream = Stream::start(nginx);
        let until = Instant::now() + Duration::from_secs(60);
        while stream.answered() < 5 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        let before = stream.answered();
        let given_before = stat(run, "kill")?.park_given;
        // With one worker no member is live between the kill and the new worker's JOIN. The
        // stream may be held by a request in flight then, so a second thread opens a
        // connection every 10 ms from the kill until the new worker's stack is up: their SYNs
        // are the ones the park must keep and give.
        let gap = (count == 1).then(|| Gap::start(nginx));
        let killed = Instant::now();
        run.send(&format!("kill -9 {}", workers[0]))?;
        run.expect_line(
            "the new worker",
            |l| l.contains("start worker process "),
            Duration::from_secs(60),
        )?;
        run.expect_line(
            "the stack of the new worker",
            |l| l.contains("fast: the stack is up on "),
            Duration::from_secs(60),
        )?;
        let opened = gap.map_or(0, Gap::finish);
        // Wait for answers that come after the kill.
        let until = Instant::now() + Duration::from_secs(90);
        while stream.answered() < before + 10 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        let after = stream.answered();
        let failures = stream.finish();
        let given = stat(run, "kill")?.park_given - given_before;
        let reset =
            over_the_kill(&failures, killed).map_err(|why| format!("{count} workers: {why}"))?;
        if after < before + 10 {
            return Err(format!(
                "{count} workers: {before} answered before the kill and {after} after: the new connections were not answered"
            ));
        }
        // The connections of the gap wait in the park and are given to the new worker; without
        // the park each of them waits for the repeat of its SYN.
        if count == 1 && given == 0 {
            return Err(format!(
                "one worker: none of the {opened} SYNs opened in the gap was parked and given to the new worker"
            ));
        }
        notes.push(format!(
            "{count} worker(s): {before} answered before the kill, {after} in all, {} request in flight at the kill, {opened} connection(s) opened in the gap, {given} parked SYN(s) given",
            if reset > 0 { "a" } else { "no" }
        ));
        if count == 4 {
            reload(run, nginx, notes)?;
        }
        run.send(&format!("kill -QUIT {m}; wait {m}; echo ngx-q{count}-end"))?;
        run.expect(&format!("ngx-q{count}-end"), Duration::from_secs(30))?;
        run.expect("# ", Duration::from_secs(60))?;
        // The group of port 80 drains its closing flows (10 s) before the port is free for a
        // new master.
        std::thread::sleep(Duration::from_secs(20));
    }
    Ok(())
}

/// `nginx -s reload` under a stream of new connections: each old worker closes its listening
/// socket before it ends, which makes its consumer leave the group (LEAVE), so no new SYN goes
/// to a socket nobody listens on (it would get no answer: the stack drops what it has no
/// listener for). No connection fails, and the switch counts one LEAVE per old worker.
fn reload(run: &mut qemu::Run, nginx: SocketAddr, notes: &mut Vec<String>) -> Result<(), String> {
    let (m, old) = fast_nginx::master_and_workers(run, "r4", false)?;
    // The worker that was killed before this step left its consumer number to the sweep of the
    // flow table; the new workers' ATTACH finds the number usable once the sweep is over.
    let sweep_wait = Duration::from_secs(60);
    let swept_by = Instant::now() + sweep_wait;
    let left_before = loop {
        let st = stat(run, "reload")?;
        if st.sweeping == 0 {
            break st.left;
        }
        if Instant::now() >= swept_by {
            return Err(format!(
                "reload: {} consumer number(s) still wait for the sweep after {} s",
                st.sweeping,
                sweep_wait.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let stream = Stream::start(nginx);
    let until = Instant::now() + Duration::from_secs(60);
    while stream.answered() < 5 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(50));
    }
    let before = stream.answered();
    let window = run.lines().len();
    run.send(&format!("kill -HUP {m}"))?;
    for _ in 0..old.len() {
        run.expect_line(
            "a new worker",
            |l| l.contains("start worker process "),
            Duration::from_secs(60),
        )?;
    }
    let until = Instant::now() + Duration::from_secs(90);
    while stream.answered() < before + 10 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
    }
    let after = stream.answered();
    let failures = stream.finish();
    // Each old worker ends by closing its listeners (LEAVE), after it has served what it holds:
    // the counter is read until all of them left.
    let left_by = Instant::now() + Duration::from_secs(30);
    let (left, sweeping) = loop {
        let st = stat(run, "reload")?;
        let left = st.left - left_before;
        if left >= old.len() as u64 || Instant::now() >= left_by {
            break (left, st.sweeping);
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    // A new worker whose ATTACH finds no usable number asks again for up to the bound of the
    // consumer (`SWEEP_WAIT_NS`): the old workers' numbers come back with the sweep.
    let attach_by = Instant::now()
        + Duration::from_nanos(proto_net::switch::SWEEP_WAIT_NS)
        + Duration::from_secs(10);
    let mut sweeping = sweeping;
    while run.lines()[window..]
        .iter()
        .filter(|l| l.contains("ATTACH ok"))
        .count()
        < old.len()
        && Instant::now() < attach_by
    {
        std::thread::sleep(Duration::from_millis(500));
        sweeping = stat(run, "reload")?.sweeping;
    }
    let lines = &run.lines()[window..];
    let said: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("gracefully shutting down"))
        .collect();
    let refused: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("ATTACH refused"))
        .collect();
    let attached = lines.iter().filter(|l| l.contains("ATTACH ok")).count();
    let report = || {
        let shut: Vec<String> = old
            .iter()
            .map(|pid| {
                let said = lines
                    .iter()
                    .any(|l| l.contains(&format!("{pid}#0: gracefully shutting down")));
                format!("{pid} {}", if said { "shut down" } else { "silent" })
            })
            .collect();
        format!(
            "old workers [{}] ({said:?}), {} ATTACH ok, {} ATTACH refused {refused:?}, {left} LEAVE(s) of {}, {sweeping} number(s) in the sweep",
            shut.join(", "),
            attached,
            refused.len(),
            old.len()
        )
    };
    if !failures.is_empty() || after < before + 10 {
        return Err(format!(
            "reload: {} failed, {before} answered before and {after} after, the first failure {:?}; {}",
            failures.len(),
            failures.first().map(|f| &f.why),
            report()
        ));
    }
    if !refused.is_empty() {
        return Err(format!(
            "reload: a new worker's ATTACH was refused; {}",
            report()
        ));
    }
    if attached < old.len() {
        return Err(format!(
            "reload: {attached} of {} new workers attached; {}",
            old.len(),
            report()
        ));
    }
    if left < old.len() as u64 {
        return Err(format!(
            "reload: {} old workers closed their listeners and the switch heard {left} LEAVE(s); {}",
            old.len(),
            report()
        ));
    }
    notes.push(format!(
        "reload under load: {before} answered before, {after} in all, no failure, {attached} ATTACH ok, {left} LEAVE(s) for {} old workers",
        old.len()
    ));
    Ok(())
}

/// Nine workers over a service that has room for eight rings: eight attach and serve, the
/// ninth is refused at ATTACH (LimitReached before any mapping) and ends with the code that
/// stops nginx's master from starting it again, so the master starts nine workers in all and
/// no loop of restarts follows.
fn attach(run: &mut qemu::Run, nginx: SocketAddr, notes: &mut Vec<String>) -> Result<(), String> {
    booted(run)?;
    start(run, CONF9)?;
    // The ninth worker's end comes after its refusal; the master would start another at once
    // if the end allowed it.
    std::thread::sleep(Duration::from_secs(8));
    let (m, workers) = fast_nginx::master_and_workers(run, "a9", false)?;
    if workers.len() != 8 {
        return Err(format!(
            "{} workers over eight rings, wanted 8",
            workers.len()
        ));
    }
    let started = run
        .lines()
        .iter()
        .filter(|l| l.contains("start worker process "))
        .count();
    if started != 9 {
        return Err(format!(
            "the master started {started} workers, wanted 9 (a loop of restarts follows a late failure)"
        ));
    }
    if !run
        .lines()
        .iter()
        .any(|l| l.contains("cannot be respawned"))
    {
        return Err(
            "the refused worker did not end with the code that stops the respawn".to_owned(),
        );
    }
    let st = stat(run, "attach")?;
    if st.consumers != 8 {
        return Err(format!(
            "{} consumers attached, wanted 8: {}",
            st.consumers, st.line
        ));
    }
    requests("with eight consumers", nginx, "/tiny.txt", TINY, 20)?;
    notes.push(
        "eight workers attached and served, the ninth was refused at ATTACH and not respawned"
            .to_owned(),
    );
    run.send(&format!("kill -QUIT {m}; wait {m}; echo ngx-a9-end"))?;
    run.expect("ngx-a9-end", Duration::from_secs(60))?;
    Ok(())
}

fn idle(run: &mut qemu::Run, nginx: SocketAddr, notes: &mut Vec<String>) -> Result<(), String> {
    booted(run)?;
    start(run, CONF1)?;
    // Warm: a page, then rest.
    requests("the first page", nginx, "/tiny.txt", TINY, 3)?;
    let mut open = Connection::open(nginx, READ_WITHIN)?;
    same("the page", &open.get("/tiny.txt")?, TINY)?;
    let mut times = Vec::new();
    for round in 0..3 {
        std::thread::sleep(Duration::from_secs(2));
        let at = Instant::now();
        let body = open.get("/tiny.txt")?;
        let on_open = at.elapsed();
        same("the page after rest", &body, TINY)?;
        std::thread::sleep(Duration::from_secs(2));
        let at = Instant::now();
        let body = Connection::open(nginx, READ_WITHIN).and_then(|mut c| c.get("/tiny.txt"))?;
        let on_new = at.elapsed();
        same("the page of a new connection after rest", &body, TINY)?;
        times.push((round, on_open, on_new));
        if on_open > IDLE_WITHIN || on_new > IDLE_WITHIN {
            return Err(format!(
                "after 2 s of rest an answer took {on_open:?} (open connection) and {on_new:?} (new): over {IDLE_WITHIN:?}; a wake was lost"
            ));
        }
    }
    notes.push(format!(
        "the answers after rest (round, open, new): {times:?}"
    ));
    Ok(())
}

fn steps(run: &mut qemu::Run, nginx: SocketAddr, notes: &mut Vec<String>) -> Result<(), String> {
    booted(run)?;
    // Eight consumers attach at once: their rings map in chunks, one chunk of pages in all
    // for a step of the stack, and the longest step stays under the bound. The service maps
    // at most 128 pieces (the kernel's limit); its budget for rings and buffers is 108 and a
    // ring takes 11, so all eight fit.
    let from = run.lines().len();
    run.send(
        "for p in 9001 9002 9003 9004 9005 9006 9007 9008; do switch-probe hold $p & done; wait; echo sw-eight-\"end\"",
    )?;
    run.expect("sw-eight-end", Duration::from_secs(600))?;
    let joined = eight_attached(&run.lines()[from..])?;
    run.expect("# ", DIALOG_STEP)?;
    // A hold inside the consumer's own block is refused.
    run.send("switch-probe hold-block")?;
    run.expect("switch-probe: hold-block ok", Duration::from_secs(120))?;
    run.expect("# ", DIALOG_STEP)?;
    notes.push(format!(
        "{joined} of 8 programs attached at once (none refused by the switch); a hold inside a block refused"
    ));
    run.send("httpd -f -p 8080 -h /www &")?;
    run.expect("# ", DIALOG_STEP)?;
    start(run, CONF4)?;
    requests("the small page", nginx, "/tiny.txt", TINY, 20)?;
    // A body of 256 KiB from the guest's stack to a worker on the shared address: large
    // frames of the stack are turned into the tables, and the step stays bound.
    run.send("dd if=/dev/zero of=/tmp/big bs=1k count=256 2>/dev/null; wget -q -O /dev/null --post-file=/tmp/big http://10.0.2.15/tiny.txt; echo ngx-post-\"end\"")?;
    run.expect("ngx-post-end", Duration::from_secs(300))?;
    run.send("wget -q -O - http://10.0.2.15/tiny.txt; echo ngx-wget-end")?;
    run.expect("ngx-wget-end", Duration::from_secs(60))?;
    notes.push("20 pages and a wget of the guest to the shared address under -icount".to_owned());
    // A worker killed: its ring is detached and unmapped in steps, a new one attaches.
    let (_, workers) = fast_nginx::master_and_workers(run, "sw", false)?;
    run.send(&format!("kill -9 {}", workers[0]))?;
    run.expect_line(
        "the new worker",
        |l| l.contains("start worker process "),
        Duration::from_secs(120),
    )?;
    requests("after the kill", nginx, "/tiny.txt", TINY, 20)?;
    notes.push("a worker killed and replaced under -icount".to_owned());
    parking_case(run, nginx, notes)
}

/// Every worker killed at once under connections that keep coming: the group has holders and no
/// member, the SYNs wait in the park, and the new workers get them (at most `PARK_GIVE` in a
/// step). The steps of the service, those of the switch among them, stay within the bound (the
/// probe judges them at the end), and every connection is answered.
/// The programs of the eight-at-once step that attached and joined. A refusal of the switch
/// fails the step (`failed errno 16` is ATTACH answering `LimitReached`, and the service's line
/// `switch attach: mapping the ring` is a late `mem_map` failure after OK); a program that did
/// not load (the guest's shell says "Out of memory") is no business of the switch, and each
/// miss must be matched by such a line.
fn eight_attached(lines: &[String]) -> Result<usize, String> {
    if let Some(l) = lines.iter().find(|l| {
        l.contains("failed errno 16") || l.contains("net: switch attach: mapping the ring")
    }) {
        return Err(format!("the switch refused or failed an attach: {l:?}"));
    }
    let joined = lines
        .iter()
        .filter(|l| l.contains("switch-probe: joined ok"))
        .count();
    let no_memory = lines.iter().filter(|l| l.contains("Out of memory")).count();
    if joined + no_memory < 8 {
        return Err(format!(
            "{joined} of 8 simultaneous consumers attached and joined, {no_memory} programs lacked memory"
        ));
    }
    Ok(joined)
}

fn parking_case(
    run: &mut qemu::Run,
    nginx: SocketAddr,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    let (_, workers) = fast_nginx::master_and_workers(run, "sp", false)?;
    let attempts: Vec<_> = (0..16u64)
        .map(|i| {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150 * i));
                Connection::open(nginx, READ_WITHIN).and_then(|mut c| c.get("/tiny.txt"))
            })
        })
        .collect();
    let list: Vec<String> = workers.iter().map(u32::to_string).collect();
    run.send(&format!("kill -9 {}", list.join(" ")))?;
    let mut failed = Vec::new();
    for a in attempts {
        match a.join() {
            Ok(Ok(body)) if body == TINY => {}
            Ok(Ok(_)) => failed.push("a wrong page".to_owned()),
            Ok(Err(e)) => failed.push(e),
            Err(_) => failed.push("a thread panicked".to_owned()),
        }
    }
    if !failed.is_empty() {
        return Err(format!(
            "{} of 16 connections over the loss of every worker failed: {:?}",
            failed.len(),
            failed.first()
        ));
    }
    // The image of the steps has no `posix-net`, so the parked SYNs are not counted here (the
    // probe `switch kill` counts them); the steps judged at the end include the handoffs.
    notes.push("every worker killed under 16 connections: all answered".to_owned());
    Ok(())
}

/// The records of a capture: their lengths and bytes.
/// A number of a consumer given again (review of Sh4b2, finding 1): `reuse-a` attaches, joins a
/// group, breaks its ring and keeps its session; `reuse-b` attaches after it, gets the same
/// number and joins the same group (the port is shared). When `reuse-a` then joins again and
/// closes its description, its pair is the old one: the join is refused and no LEAVE reaches the
/// switch (the counter of LEAVEs stays), so `reuse-b` stays a member.
fn reuse(run: &mut qemu::Run, notes: &mut Vec<String>) -> Result<(), String> {
    // The numbers of the consumers of the steps before come back after two rounds of the sweep:
    // with them all free `reuse-a` takes the lowest, 0, and `reuse-b` takes it again after it.
    std::thread::sleep(Duration::from_secs(8));
    let before = stat(run, "u0")?.left;
    let from = run.lines().len();
    run.send(
        "switch-probe reuse-a 9101 & sleep 3; switch-probe reuse-b 9101; wait; echo reuse-done",
    )?;
    run.expect("reuse-done", Duration::from_secs(120))?;
    run.expect("# ", DIALOG_STEP)?;
    let lines: Vec<String> = run.lines()[from..].to_vec();
    let number = |l: &String| {
        l.split("attached c ")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .map(str::to_owned)
    };
    let numbers: Vec<String> = lines.iter().filter_map(number).collect();
    if numbers.len() != 2 || numbers[0] != numbers[1] {
        return Err(format!(
            "the second consumer did not take the number of the first ({numbers:?}): the probe does not test its case; {lines:?}"
        ));
    }
    if !lines
        .iter()
        .any(|l| l.contains("reuse-a stale join refused"))
    {
        return Err(format!("the stale JOIN was not refused: {lines:?}"));
    }
    let after = stat(run, "u1")?.left;
    if after != before {
        return Err(format!(
            "{} LEAVE(s) reached the switch from a session whose consumer was gone",
            after - before
        ));
    }
    notes.push(format!(
        "number {} reused: the old session's JOIN refused and its close sent no LEAVE",
        numbers[0]
    ));
    Ok(())
}

fn pcap_records(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 24;
    while at + 16 <= bytes.len() {
        let len = u32::from_le_bytes([bytes[at + 8], bytes[at + 9], bytes[at + 10], bytes[at + 11]])
            as usize;
        if at + 16 + len > bytes.len() {
            break;
        }
        out.push(&bytes[at + 16..at + 16 + len]);
        at += 16 + len;
    }
    out
}

fn frames(
    run: &mut qemu::Run,
    pcap: &std::path::Path,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    booted(run)?;
    // The service's own address and the probe's attach.
    run.send("switch-probe attach")?;
    run.expect("switch-probe: counters", Duration::from_secs(60))?;
    run.expect("# ", DIALOG_STEP)?;
    run.send("switch-probe refuse")?;
    let mut refused = Vec::new();
    for mode in [
        "foreign-sport",
        "foreign-ip",
        "foreign-mac",
        "rst-foreign",
        "icmp",
        "fragment",
        "syn-ok",
        "long",
        "flags",
    ] {
        let want = format!("switch-probe: {mode} refused ");
        let line = run.expect_line(mode, |l| l.contains(&want), Duration::from_secs(60))?;
        let n: u32 = line
            .split(&want)
            .nth(1)
            .and_then(|r| r.trim().parse().ok())
            .unwrap_or(99);
        refused.push((mode, n));
        let wanted = u32::from(mode != "syn-ok");
        if n != wanted {
            let _ = run.expect("switch-probe: counters", Duration::from_secs(5));
            let _ = run.expect("# ", Duration::from_secs(5));
            let seen = stat(run, "dbg").map(|s| s.line).unwrap_or_default();
            return Err(format!(
                "{mode}: the switch refused {n} frames, wanted {wanted}; the service says {seen}"
            ));
        }
    }
    run.expect("switch-probe: counters", Duration::from_secs(30))?;
    run.expect("# ", DIALOG_STEP)?;
    notes.push(format!("refusals by mode: {refused:?}"));
    // The stat of the service counts them by reason.
    let after = stat(run, "r1")?;
    let by_reason: u64 = after.refused_by.iter().sum();
    if by_reason < 7 {
        return Err(format!(
            "{by_reason} refusals by reason after seven (the eighth, the flags, is the ring's): {} {:?}",
            after.line, after.refused_by
        ));
    }
    notes.push(format!("refusals by reason: {:?}", after.refused_by));
    // A hold below 1024 as nobody is refused, a join with no port too.
    run.send("switch-probe hold-nobody")?;
    run.expect("switch-probe: hold-nobody ok", Duration::from_secs(60))?;
    run.expect("# ", DIALOG_STEP)?;
    run.send("switch-probe join-bad")?;
    run.expect_line(
        "join-bad",
        |l| l.contains("switch-probe: join-bad ok errno 9"),
        Duration::from_secs(60),
    )?;
    run.expect("# ", DIALOG_STEP)?;
    notes.push(
        "hold of a port below 1024 as nobody: refused; JOIN without a port: EBADF".to_owned(),
    );
    // A hold at port 65535 (review of Sh4b2, finding 2): the end of the range does not wrap.
    run.send("switch-probe hold-top")?;
    run.expect("switch-probe: hold-top ok", Duration::from_secs(60))?;
    run.expect("# ", Duration::from_secs(30))?;
    notes.push("a hold at port 65535 is held or in use, and no wrapped port is held".to_owned());
    reuse(run, notes)?;
    // A broken ring disables its consumer alone; the service goes on.
    for mode in ["broken-tx", "broken-fill"] {
        run.send(&format!("switch-probe {mode}"))?;
        run.expect("switch-probe: broken ok", Duration::from_secs(60))?;
        run.expect("# ", DIALOG_STEP)?;
    }
    run.send("switch-probe attach")?;
    run.expect("switch-probe: counters", Duration::from_secs(60))?;
    run.expect("# ", DIALOG_STEP)?;
    notes.push(
        "a broken ring (TX, FILL) is told to its consumer; the service attached a new one after"
            .to_owned(),
    );
    // The wire: none of the refused frames got out.
    let bytes = std::fs::read(pcap).map_err(|e| format!("{}: {e}", pcap.display()))?;
    let records = pcap_records(&bytes);
    let other_mac = [2u8, 0, 0, 0, 0, 0x77];
    let other_ip = [198u8, 51, 100, 7];
    for (i, r) in records.iter().enumerate() {
        let has = |needle: &[u8]| r.windows(needle.len()).any(|w| w == needle);
        if r.len() == 1515 || has(&other_mac) || has(&other_ip) {
            return Err(format!(
                "capture record {i} ({} bytes) is a frame the switch refused",
                r.len()
            ));
        }
    }
    notes.push(format!(
        "the capture of the wire holds {} frames, none of them refused ones",
        records.len()
    ));
    Ok(())
}

/// `saturate`: three consumers keep their TX rings full of entries the switch refuses, so that
/// every step of the switch finds more to do. The switch is a level above the stack, the services
/// and the programs on its CPU; its kernel time budget and the budget of its consumers' entries
/// (`CONSUMER_BUDGET_NS`) leave them the rest of CPU 0.
///
/// Checked: at least `SATURATE_SAMPLES` answers of `posix-net stat` spread over a flood of
/// `SATURATE_LONG`, each within `max(SATURATE_FLOOR, SATURATE_BOUND` times the quiet answer`)`;
/// and, once the flood has lasted `SATURATE_LONG`, init has not called the network service
/// silent. The share of CPU 0 a loop below the switch keeps is only logged here (TCG does not
/// tell its budget from a pause); `share` checks it under -icount.
fn saturate(run: &mut qemu::Run, notes: &mut Vec<String>) -> Result<(), String> {
    booted(run)?;
    let quiet = Instant::now();
    stat(run, "quiet")?;
    let bound = SATURATE_FLOOR.max(quiet.elapsed() * SATURATE_BOUND);
    let base = spin_rate(run, "quiet")?;
    for _ in 0..SATURATE_CONSUMERS {
        run.send(&format!("switch-probe saturate {SATURATE_SECS} &"))?;
        run.expect("# ", DIALOG_STEP)?;
    }
    let began = Instant::now();
    let mut took = Vec::new();
    // The programs attach one after another; the stack answers while they do.
    while took.len() < SATURATE_SAMPLES || began.elapsed() < SATURATE_LONG {
        let asked = Instant::now();
        let s = stat(run, "flood")?;
        let t = asked.elapsed();
        if t > bound {
            return Err(format!(
                "sample {}: the stack answered `posix-net stat` after {t:?} of a flood (bound {bound:?}): the switch kept it off the processor",
                took.len() + 1
            ));
        }
        if s.consumers == SATURATE_CONSUMERS as u64 {
            took.push(t);
            // The samples lie apart, so that they spread over the flood.
            std::thread::sleep(SATURATE_APART);
        } else if began.elapsed() > bound * 2 {
            return Err(format!(
                "{} consumers, wanted {SATURATE_CONSUMERS}: {}",
                s.consumers, s.line
            ));
        }
    }
    let flooded = spin_rate(run, "flood")?;
    let share = flooded.mean * 100 / base.mean.max(1);
    // The flood lasted long enough: init must have said nothing of the network service.
    if let Some(l) = run.lines().iter().find(|l| l.contains("went silent")) {
        return Err(format!("init: {l}"));
    }
    // The programs flood for a long time; they are ended by the probe, which has its numbers.
    run.send("kill %1 %2 %3")?;
    run.expect("# ", DIALOG_STEP)?;
    let after = stat(run, "after")?;
    let waits = counter(&after.line, "budget_waits").ok_or("no `budget_waits`")?;
    println!(
        "fast-switch: the loop below the switch: {} per 100 ms quiet (least window of 10 ms {}), {} in the flood (least window {}), {share} % (logged, no limit)",
        base.mean, base.least, flooded.mean, flooded.least
    );
    notes.push(format!(
        "{waits} steps with the consumers' budget spent; {} answers of the stack in {:.0} s of flood: {took:?} (bound {bound:?}); the loop below the switch kept {share} % (logged)",
        took.len(),
        began.elapsed().as_secs_f64()
    ));
    Ok(())
}

/// What `switch-probe spin` says: the iterations per 100 ms, the mean and the least window of
/// 10 ms.
struct Spin {
    mean: u64,
    least: u64,
}

/// The rates of `switch-probe spin` on CPU 0.
fn spin_rate(run: &mut qemu::Run, what: &str) -> Result<Spin, String> {
    run.send(&format!("switch-probe spin {SPIN_SECS}"))?;
    let line = run.expect_line(
        what,
        |l| l.contains("switch-probe: spin rate "),
        Duration::from_secs(120),
    )?;
    parse_spin(&line).ok_or_else(|| format!("{what}: no rates in {line:?}"))
}

/// The rates of a line `switch-probe: spin rate N min10 M`.
fn parse_spin(line: &str) -> Option<Spin> {
    let rest = line.split("spin rate ").nth(1)?;
    let mut words = rest.split_whitespace();
    let mean = words.next()?.parse().ok()?;
    (words.next()? == "min10").then_some(())?;
    let least = words.next()?.parse().ok()?;
    Some(Spin { mean, least })
}

/// A free UDP port of the host.
fn free_udp_port() -> Result<u16, String> {
    let socket =
        std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("a UDP port: {e}"))?;
    Ok(socket.local_addr().map_err(|e| e.to_string())?.port())
}

/// Threads that send datagrams to `port` of the host as fast as they can, until `finish`.
struct Flood {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    sent: std::sync::Arc<std::sync::atomic::AtomicU64>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Flood {
    fn start(port: u16) -> Result<Flood, String> {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut threads = Vec::new();
        for _ in 0..FLOOD_THREADS {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")
                .map_err(|e| format!("a UDP socket of the flood: {e}"))?;
            let (stop, sent) = (stop.clone(), sent.clone());
            threads.push(std::thread::spawn(move || {
                let datagram = [0x5a; FLOOD_BYTES];
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if socket.send_to(&datagram, ("127.0.0.1", port)).is_ok() {
                        sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }));
        }
        Ok(Flood {
            stop,
            sent,
            threads,
        })
    }

    /// Stops the threads; the datagrams they sent.
    fn finish(self) -> u64 {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for t in self.threads {
            let _ = t.join();
        }
        self.sent.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The datagrams the flood has sent so far.
fn flood_sent(flood: &Flood) -> u64 {
    flood.sent.load(std::sync::atomic::Ordering::Relaxed)
}

/// A second of `switch-probe spin`: the line `spin sec K rate N min10 M`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Second {
    k: u64,
    rate: u64,
    least: u64,
}

fn parse_second(line: &str) -> Option<Second> {
    let rest = line.split("spin sec ").nth(1)?;
    let mut w = rest.split_whitespace();
    let k = w.next()?.parse().ok()?;
    (w.next()? == "rate").then_some(())?;
    let rate = w.next()?.parse().ok()?;
    (w.next()? == "min10").then_some(())?;
    let least = w.next()?.parse().ok()?;
    Some(Second { k, rate, least })
}

/// The loop runs this many seconds; seconds 1 to `QUIET_LAST` are the quiet rate (the second 0
/// is the loop starting), the flood starts when the line of `QUIET_LAST` has come, and the
/// seconds from `FLOOD_FROM` on are in it whole.
const SPIN_TOTAL: u64 = 10;
const QUIET_LAST: u64 = 3;
const FLOOD_FROM: u64 = 5;
/// The longest the unbound break waits for the seconds of the loop in all.
const UNBOUND_TOTAL: Duration = Duration::from_secs(300);
/// What the failure of the share says when the loop got no time in the flood.
pub const UNBOUND_SILENT: &str = "the loop below the switch got no time in the flood";
/// What the failure of the share says when the loop got time, but too little of it.
const SHARE_KEPT: &str = "the loop below the switch kept ";

/// Whether the failure of the share probe on the unbound image is the effect of the break (the
/// loop starved or short of its share, or init calling the service silent). A probe that broke
/// elsewhere (the boot, the quiet seconds) is no catch.
pub fn unbound_caught(error: &str) -> bool {
    error.starts_with(UNBOUND_SILENT)
        || error.starts_with(SHARE_KEPT)
        || error.starts_with("init: ") && error.contains("went silent")
}

/// `share`: the machine has one CPU, so the network service, the loop of `switch-probe spin` and
/// the shell stand on CPU 0, and the -icount clock is that CPU's alone. The loop runs for
/// `SPIN_TOTAL` seconds and says each second; the quiet rate is that of its seconds 1 to
/// `QUIET_LAST`. Then datagrams from the host to a port nobody holds keep the switch and the
/// stack busy (each is received, looked at and answered), and the share of the quiet rate the
/// loop keeps in its worst window of 10 ms of the seconds from `FLOOD_FROM` on must be at least
/// `SHARE_MIN_PERCENT`, and init must not call the service silent (its heartbeat comes from the
/// stack's thread). A `posix-net stat` in this flood gets no answer within two minutes, with the
/// budgets and without them (the loop keeps its share, so the processor is not short; the cause is
/// not looked into here); `saturate` checks the answers with a flood of the consumers' rings.
/// The numbers print before the check, so that a build without the kernel budgets shows its
/// share.
fn share(
    run: &mut qemu::Run,
    udp_port: u16,
    notes: &mut Vec<String>,
    unbound: bool,
) -> Result<(), String> {
    // A loop that gets no time under the flood (the service unbound) says nothing for minutes:
    // that is the failure, so the break is not waited for as long: 150 s for a second, and
    // `UNBOUND_TOTAL` for all the seconds together (a loop that gets one second now and then
    // does not renew the wait without end).
    let per_second = Duration::from_secs(if unbound { 150 } else { 900 });
    booted(run)?;
    // The unbound break has none of these lines, and is left to fail on the share itself.
    if !unbound {
        net_probe::require_budget_lines(run.lines())?;
    }
    let quiet_stat = stat(run, "quiet")?;
    let quiet_ask = ask(run)?;
    run.send(&format!("switch-probe spin {SPIN_TOTAL} &"))?;
    run.expect("# ", DIALOG_STEP)?;
    let mut seconds: Vec<Second> = Vec::new();
    let mut flood: Option<Flood> = None;
    let began = Instant::now();
    loop {
        let wait = if unbound {
            per_second.min(UNBOUND_TOTAL.saturating_sub(began.elapsed()))
        } else {
            per_second
        };
        let line = match run.expect_line(
            "a second of the loop below the switch",
            |l| l.contains("switch-probe: spin sec ") || l.contains("switch-probe: spin rate "),
            wait,
        ) {
            Ok(line) => line,
            Err(e) => {
                if let Some(f) = flood.take() {
                    f.finish();
                }
                // The seconds up to the quiet ones came, the flood began, and the loop then
                // got no time: that is the effect of the break. Anything else (the boot, the
                // quiet seconds) is a broken probe.
                return Err(if unbound && seconds.len() as u64 > QUIET_LAST {
                    format!(
                        "{UNBOUND_SILENT}: seconds {:?} came, then none in {} s of the flood ({e})",
                        seconds.iter().map(|s| s.k).collect::<Vec<_>>(),
                        began.elapsed().as_secs()
                    )
                } else {
                    e
                });
            }
        };
        let Some(second) = parse_second(&line) else {
            break;
        };
        seconds.push(second);
        if second.k == QUIET_LAST && flood.is_none() {
            flood = Some(Flood::start(udp_port)?);
        }
    }
    let sent = flood.as_ref().map_or(0, flood_sent);
    let quiet: Vec<&Second> = seconds
        .iter()
        .filter(|s| (1..=QUIET_LAST).contains(&s.k))
        .collect();
    let flooded: Vec<&Second> = seconds.iter().filter(|s| s.k >= FLOOD_FROM).collect();
    if quiet.len() as u64 != QUIET_LAST || flooded.is_empty() {
        return Err(format!("seconds of the loop: {seconds:?}"));
    }
    let base = quiet.iter().map(|s| s.rate).sum::<u64>() / quiet.len() as u64;
    let quiet_least = quiet.iter().map(|s| s.least).min().unwrap_or(0);
    let least = flooded.iter().map(|s| s.least).min().unwrap_or(0);
    let mean = flooded.iter().map(|s| s.rate).sum::<u64>() / flooded.len() as u64;
    let share = least * 100 / base.max(1);
    println!(
        "fast-switch: the loop below the switch: {base} per 100 ms quiet (least window of 10 ms {quiet_least}); in the flood {mean} (mean of seconds {FLOOD_FROM} to {}), least window of 10 ms {least}: {share} % of the quiet rate (at least {SHARE_MIN_PERCENT} %); {sent} datagrams sent in {:.0} s",
        seconds.last().map_or(0, |s| s.k),
        began.elapsed().as_secs_f64()
    );
    println!("fast-switch: seconds {seconds:?}");
    // The loop has ended and the flood goes on. The break with the service unbound fails on the
    // share, as it did.
    if flood.is_some() && !unbound {
        // A new process asks the network service for its session, and `posix-net stat` is
        // such a process: under the flood the service must answer within a bound
        // (stafeto-design#713: it waited behind the steps of the stack for as long as the
        // flood lasted).
        let asked = Instant::now();
        stat_within(run, "flood", STAT_FLOOD_BOUND).map_err(|e| {
            format!("`posix-net stat` got no answer within {STAT_FLOOD_BOUND:?} of the flood: {e}")
        })?;
        let stat_took = asked.elapsed();
        let flood_ask = ask(run)?;
        println!(
            "fast-switch: `posix-net stat` answered in {stat_took:?} of the host's time under the flood; the longest wait of a request in the guest's time: {} us in the flood ({} requests), {} us quiet ({} requests)",
            flood_ask.1, flood_ask.0, quiet_ask.1, quiet_ask.0
        );
        // A request waits for a few steps of the stack and a few receives, a few periods of
        // its budget (netd::gates::Yielding), not for the flood: 5 ms is above what it measured, 2.3 ms.
        if flood_ask.1 > ASK_FLOOD_BOUND_US {
            return Err(format!(
                "a request of the network service waited {} us in the guest's time in the flood, over {ASK_FLOOD_BOUND_US} us",
                flood_ask.1
            ));
        }
    }
    if let Some(f) = flood {
        f.finish();
    }
    println!("fast-switch: quiet  {}", quiet_stat.line);
    if let Some(l) = run.lines().iter().find(|l| l.contains("went silent")) {
        return Err(format!("init: {l}"));
    }
    if share < SHARE_MIN_PERCENT {
        return Err(format!(
            "{SHARE_KEPT}{share} % of CPU 0 in its worst window of 10 ms in the flood, under {SHARE_MIN_PERCENT} %"
        ));
    }
    notes.push(format!(
        "the loop below the switch kept {share} % of its quiet rate in its worst window of 10 ms ({SHARE_MIN_PERCENT} % wanted); {sent} datagrams sent"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_effects_of_the_unbound_break_count_as_caught() {
        assert!(unbound_caught(&format!(
            "{UNBOUND_SILENT}: seconds [0, 1, 2, 3] came"
        )));
        assert!(unbound_caught(
            "the loop below the switch kept 3 % of CPU 0 in its worst window"
        ));
        assert!(unbound_caught("init: net: service went silent"));
        // A probe that broke before the flood, or elsewhere, is no catch.
        assert!(!unbound_caught(
            "timed out waiting for \"# \"; last lines: []"
        ));
        assert!(!unbound_caught("seconds of the loop: []"));
        assert!(!unbound_caught(
            "the output ended before a second of the loop"
        ));
    }

    #[test]
    fn the_seconds_of_the_loop_below_the_switch_are_read_from_their_lines() {
        let line = "net: bells tx 5 frames 9switch-probe: spin sec 4 rate 123456 min10 7890";
        assert_eq!(
            parse_second(line),
            Some(Second {
                k: 4,
                rate: 123_456,
                least: 7_890
            })
        );
        assert!(parse_second("switch-probe: spin rate 123456 min10 7890").is_none());
        assert!(parse_second("switch-probe: spin sec 4 rate x min10 1").is_none());
    }

    #[test]
    fn the_rates_of_the_loop_below_the_switch_are_read_from_its_line() {
        let spin = parse_spin("switch-probe: spin rate 123456 min10 7890").unwrap();
        assert_eq!((spin.mean, spin.least), (123_456, 7_890));
        // A line of the older program, with the mean alone, or a broken one, gives nothing.
        assert!(parse_spin("switch-probe: spin rate 123456").is_none());
        assert!(parse_spin("switch-probe: spin rate x min10 1").is_none());
        assert!(parse_spin("switch-probe: counters rx_full 1 tx_refused 2").is_none());
    }

    #[test]
    fn the_eight_at_once_step_allows_a_miss_only_for_a_program_that_lacked_memory() {
        let v = |lines: &[&str]| {
            eight_attached(&lines.iter().map(|l| (*l).to_owned()).collect::<Vec<_>>())
        };
        let ok = "switch-probe: joined ok";
        assert_eq!(v(&[ok; 8]), Ok(8));
        assert_eq!(
            v(&[&[ok; 7][..], &["ash: switch-probe: Out of memory"]].concat()),
            Ok(7)
        );
        // A miss with no matching line, or a refusal of the switch, fails.
        assert!(v(&[ok; 7]).is_err());
        let refused = "switch-probe: stafeto_fast_attach(&claim) == 0 failed errno 16";
        assert!(v(&[&[ok; 7][..], &[refused]].concat()).is_err());
        assert!(
            v(&[
                &[ok; 8][..],
                &["net: switch attach: mapping the ring of 3: LimitReached"]
            ]
            .concat())
            .is_err()
        );
    }

    #[test]
    fn the_kill_resets_the_request_in_flight_and_no_other() {
        let killed = Instant::now() + Duration::from_secs(10);
        let at = |ms: i64| {
            if ms < 0 {
                killed - Duration::from_millis(-ms as u64)
            } else {
                killed + Duration::from_millis(ms as u64)
            }
        };
        let failure = |began: i64, ended: i64, why: &str| Failure {
            began: at(began),
            ended: at(ended),
            why: why.to_owned(),
        };
        let eof = "the connection closed with 0 bytes pending";
        assert_eq!(over_the_kill(&[], killed), Ok(0));
        assert_eq!(over_the_kill(&[failure(-3, 1300, eof)], killed), Ok(1));
        assert_eq!(
            over_the_kill(
                &[failure(
                    5,
                    900,
                    "read after 0 bytes: Connection reset by peer (os error 54)"
                )],
                killed
            ),
            Ok(1)
        );
        // Two failed requests: the stream asks one at a time.
        assert!(over_the_kill(&[failure(-30, -10, eof), failure(5, 90, eof)], killed).is_err());
        // A request that began after the worker was gone.
        assert!(over_the_kill(&[failure(2_500, 2_600, eof)], killed).is_err());
        // A timeout is no reset.
        assert!(
            over_the_kill(
                &[failure(
                    5,
                    900,
                    "read after 0 bytes: Resource temporarily unavailable"
                )],
                killed
            )
            .is_err()
        );
        // A connection that hung until the read timed out.
        assert!(over_the_kill(&[failure(5, 60_000, eof)], killed).is_err());
    }

    #[test]
    fn the_images_and_the_lines_are_those_of_the_programs() {
        let init = |k| {
            fast_nginx::programs(k)
                .iter()
                .find(|p| p.0 == "init")
                .unwrap()
                .3
        };
        assert_eq!(init(Kind::Switch), &["table-fast-switch"]);
        assert_eq!(init(Kind::SwitchSteps), &["table-fast-switch"]);
        assert_eq!(init(Kind::Scale), &["table-fast-switch-scale"]);
        assert!(conf4().contains("worker_processes 4;"));
        assert!(conf4().contains("proxy_pass http://127.0.0.1:8080/;"));
        assert!(conf4().contains("proxy_pass http://127.0.0.1:80/;"));
        assert!(conf4().contains("proxy_pass http://127.0.0.1:8081/;"));
        assert!(conf_b().contains("listen 8081;") && conf_b().contains("nginx-fast-b.pid"));
        assert!(conf4().contains("user nobody nobody;"));
        assert_eq!(fast_nginx::SWITCH_NETD_CONF, b"switch 8\nflows 16384\n");
        let netd =
            std::fs::read_to_string(crate::root().join("services/netd/src/main.rs")).unwrap();
        for line in [
            "net: switch consumers ",
            "net: switch tx_refused ",
            "net: switch left ",
            "net: switch rx_by ",
            "refused_by {refused:?}",
        ] {
            assert!(netd.contains(line), "{line}");
        }
        let probe =
            std::fs::read_to_string(crate::root().join("tests/posix-so/dyn/switch-probe.c"))
                .unwrap();
        for line in [
            "hold-nobody ok",
            "join-bad ok errno",
            "broken ok",
            " refused %u",
        ] {
            assert!(probe.contains(line), "{line}");
        }
    }

    #[test]
    fn a_capture_is_read_by_its_records() {
        let mut bytes = vec![0u8; 24];
        for len in [60u32, 1515] {
            let mut head = [0u8; 16];
            head[8..12].copy_from_slice(&len.to_le_bytes());
            bytes.extend(head);
            bytes.extend(vec![0u8; len as usize]);
        }
        let records = pcap_records(&bytes);
        assert_eq!(
            records.iter().map(|r| r.len()).collect::<Vec<_>>(),
            [60, 1515]
        );
    }
}
