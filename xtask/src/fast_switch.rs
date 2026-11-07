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
//! * `switch saturate`: three programs keep their rings full of entries the switch refuses for
//!   20 s on four CPUs; the switch (a level above the stack and the services on its CPU) pauses
//!   in its runs, so the stack answers `posix-net stat` within seconds and init's watchdog
//!   kills nothing (without the pauses the stack waits for the end of the flood, or init kills
//!   the network service as silent).
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
use netd::ring::{SWITCH_RUN_NS, SWITCH_STEP_BOUND_NS};

const CONF4: &str = "/etc/nginx/nginx-fast-4.conf";
const CONF9: &str = "/etc/nginx/nginx-fast-9.conf";
const CONF_B: &str = "/etc/nginx/nginx-fast-b.conf";
const CONF1: &str = "/etc/nginx/nginx-fast.conf";
const REQUESTS: usize = 200;
/// How long `saturate` floods the ring.
const SATURATE_SECS: u64 = 20;
/// How many answers of `posix-net stat` the flood must get, and the bound of each: this many
/// times the answer of the quiet stack, but not under `SATURATE_FLOOR` nor under three fifths of
/// the flood (a slow host spends seconds starting `posix-net` beside three programs at full
/// speed; a stack the switch keeps off the processor answers after the flood or is killed).
const SATURATE_SAMPLES: usize = 4;
/// What the host's clock may add to the longest run of the switch.
const SATURATE_JITTER: Duration = Duration::from_millis(40);
const SATURATE_BOUND: u32 = 40;
const SATURATE_FLOOR: Duration = Duration::from_millis(4_000);
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
        _ => Err(
            "usage: cargo xtask fast-probe switch [kill|idle|attach|steps|frames|saturate]"
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
}

/// A counter of a line of the service after `key`.
fn counter(line: &str, key: &str) -> Option<u64> {
    let rest = line.split(&format!(" {key} ")).nth(1)?;
    rest.split([' ', ',']).next()?.parse().ok()
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
    /// The refusals by reason (cumulative, also of consumers that left).
    refused_by: Vec<u64>,
    rx_by: Vec<u64>,
    line: String,
}

fn stat(run: &mut qemu::Run, tag: &str) -> Result<Stat, String> {
    let from = run.lines().len();
    run.send("posix-net stat")?;
    // The service prints its counters when the request is over, so they may come after the
    // next prompt: the last line of them is waited for.
    run.expect_line(
        "the counters of the switch",
        |l| l.contains("net: switch rx_by "),
        Duration::from_secs(120),
    )?;
    let _ = tag;
    let lines: Vec<String> = run.lines()[from..].to_vec();
    let line = lines
        .iter()
        .rev()
        .find(|l| l.contains("net: switch consumers "))
        .cloned()
        .ok_or_else(|| {
            format!("no line `net: switch consumers` after posix-net stat: {lines:?}")
        })?;
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
    Ok(Stat {
        refused_by,
        consumers: counter(&line, "consumers").ok_or("consumers")?,
        hairpin: counter(&line, "hairpin").ok_or("hairpin")?,
        own_to_device: counter(&line, "own_to_device").ok_or("own_to_device")?,
        tx_refused: counter(&line, "tx_refused").ok_or("tx_refused")?,
        park_given: counter(&line, "park_given").ok_or("park_given")?,
        looped: counter(&line, "looped").ok_or("looped")?,
        left: counter(&line, "left").ok_or("left")?,
        rx_by,
        line,
    })
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
        if kind == Kind::SwitchSteps {
            fast_nginx::SWITCH_STEPS_IMAGE
        } else {
            fast_nginx::SWITCH_IMAGE
        },
        fast_nginx::programs(kind),
    );
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let ports = (
        crate::net_curl::free_tcp_port()?,
        crate::net_curl::free_tcp_port()?,
    );
    let dir = crate::target_dir().join("fast-switch");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let pcap = dir.join(PCAP);
    let _ = std::fs::remove_file(&pcap);
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut net = qemu::net(&[
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
    ]);
    if scenario == Scenario::Frames {
        net.extend([
            "-object".to_owned(),
            format!("filter-dump,id=f9,netdev=n0,file={}", pcap.display()),
        ]);
    }
    cmd.args(net);
    if scenario == Scenario::Steps {
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
    if let Err(why) = requests(
        "nginx-fast as a proxy to httpd over 127.0.0.1",
        nginx,
        "/up/index.html",
        crate::rootfs::www_index(),
        20,
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
    let after_proxy = stat(run, "lo2")?;
    if after_proxy.looped <= after_wget.looped {
        return Err(format!(
            "the proxy's packets did not go through the tables: {}",
            after_proxy.line
        ));
    }
    requests("a worker's own loopback", nginx, "/self/tiny.txt", TINY, 20)?;
    // A packet for a port of the worker's own stack stays on its loopback interface: the 20
    // requests (and the proxy's own connections to port 80) leave nothing in the tables.
    let after_self = stat(run, "lo3")?;
    if after_self.looped != after_proxy.looped {
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

/// A stream of new connections from the host, each a GET of the small page,
/// until `stop`; the failures and the number answered.
struct Stream {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    answered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    failures: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
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
                match Connection::open(address, READ_WITHIN).and_then(|mut c| c.get("/tiny.txt")) {
                    Ok(body) if body == TINY => {
                        a.fetch_add(1, Relaxed);
                    }
                    Ok(_) => f.lock().unwrap().push("a wrong page".to_owned()),
                    Err(e) => f.lock().unwrap().push(e),
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

    fn finish(mut self) -> Vec<String> {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.failures.lock().unwrap().clone()
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
        run.send(&format!("kill -9 {}", workers[0]))?;
        run.expect_line(
            "the new worker",
            |l| l.contains("start worker process "),
            Duration::from_secs(60),
        )?;
        // Wait for answers that come after the kill.
        let until = Instant::now() + Duration::from_secs(90);
        while stream.answered() < before + 10 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        let after = stream.answered();
        let failures = stream.finish();
        let given = stat(run, "kill")?.park_given - given_before;
        if !failures.is_empty() {
            return Err(format!(
                "{count} workers: {} requests failed over the kill, the first {:?}",
                failures.len(),
                failures.first()
            ));
        }
        if after < before + 10 {
            return Err(format!(
                "{count} workers: {before} answered before the kill and {after} after: the new connections were not answered"
            ));
        }
        // With one worker no member is live between the kill and the new worker's JOIN: the
        // stream's connections in that gap wait in the park and are given to it (the stream
        // opens one every 20 ms, the restart takes far longer, also on TCG). Without the park
        // each of them waits for the repeat of its SYN.
        if count == 1 && given == 0 {
            return Err(
                "one worker: no SYN was parked over the kill and given to the new worker"
                    .to_owned(),
            );
        }
        notes.push(format!(
            "{count} worker(s): {before} answered before the kill, {after} in all, no failure, {given} parked SYN(s) given"
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
    let left_before = stat(run, "reload")?.left;
    let stream = Stream::start(nginx);
    let until = Instant::now() + Duration::from_secs(60);
    while stream.answered() < 5 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(50));
    }
    let before = stream.answered();
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
    if !failures.is_empty() || after < before + 10 {
        return Err(format!(
            "reload: {} failed, {before} answered before and {after} after, the first failure {:?}",
            failures.len(),
            failures.first()
        ));
    }
    let left = stat(run, "reload")?.left - left_before;
    if left < old.len() as u64 {
        return Err(format!(
            "reload: {} old workers closed their listeners and the switch heard {left} LEAVE(s)",
            old.len()
        ));
    }
    notes.push(format!(
        "reload under load: {before} answered before, {after} in all, no failure, {left} LEAVE(s) for {} old workers",
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
/// and the programs on its CPU; it takes a budget of the consumers' entries in each millisecond
/// and pauses after a run of `SWITCH_RUN_NS`, so that they run. Without both, the stack answers
/// nothing until the flood ends and init's watchdog kills the service as silent.
///
/// `posix-net stat` is asked `SATURATE_SAMPLES` times in the flood, each answer within its bound
/// (`SATURATE_BOUND` times the answer of the quiet stack, at least `SATURATE_FLOOR`), and the
/// longest run of the switch without a rest stays within a run and two steps.
fn saturate(run: &mut qemu::Run, notes: &mut Vec<String>) -> Result<(), String> {
    booted(run)?;
    let quiet = Instant::now();
    stat(run, "quiet")?;
    let bound = SATURATE_FLOOR
        .max(quiet.elapsed() * SATURATE_BOUND)
        .max(Duration::from_secs(SATURATE_SECS * 3 / 5));
    for _ in 0..SATURATE_CONSUMERS {
        run.send(&format!("switch-probe saturate {SATURATE_SECS} &"))?;
        run.expect("# ", DIALOG_STEP)?;
    }
    let began = Instant::now();
    let mut took = Vec::new();
    // The programs attach one after another; the stack answers while they do.
    while took.len() < SATURATE_SAMPLES {
        let asked = Instant::now();
        let s = stat(run, "flood")?;
        let t = asked.elapsed();
        if run
            .lines()
            .iter()
            .any(|l| l.contains("switch-probe: saturate ok "))
        {
            return Err(format!(
                "the flood ended before sample {} was answered ({t:?}): the switch kept the stack off the processor",
                took.len() + 1
            ));
        }
        if t > bound {
            return Err(format!(
                "sample {}: the stack answered `posix-net stat` after {t:?} of a flood (bound {bound:?}): the switch kept it off the processor",
                took.len() + 1
            ));
        }
        if s.consumers == SATURATE_CONSUMERS as u64 {
            took.push(t);
        } else if began.elapsed() > Duration::from_secs(SATURATE_SECS * 3 / 4) {
            return Err(format!(
                "{} consumers, wanted {SATURATE_CONSUMERS}: {}",
                s.consumers, s.line
            ));
        }
    }
    for _ in 0..SATURATE_CONSUMERS {
        run.expect_line(
            "the flood ends",
            |l| l.contains("switch-probe: saturate ok "),
            Duration::from_secs(60),
        )?;
    }
    if let Some(l) = run.lines().iter().find(|l| l.contains("went silent")) {
        return Err(format!("init: {l}"));
    }
    let after = stat(run, "after")?;
    let pauses = counter(&after.line, "pauses").ok_or("no `pauses` in the switch line")?;
    let failed = counter(&after.line, "pause_failed").ok_or("no `pause_failed`")?;
    let longest = counter(&after.line, "run_max_us").ok_or("no `run_max_us`")?;
    // A run and a step is the bound of the thread (the model test of `drive` holds it to that);
    // the clock is the host's wall clock, which a loaded TCG host stops for several milliseconds
    // (9.4 ms seen), so the probe allows `SATURATE_JITTER` more. Without the pauses the run
    // lasts as long as the flood.
    let limit = (SWITCH_RUN_NS + SWITCH_STEP_BOUND_NS + SATURATE_JITTER.as_nanos() as u64) / 1_000;
    if longest > limit {
        return Err(format!(
            "the longest run of the switch without a rest was {longest} us, over {limit} us: {}",
            after.line
        ));
    }
    if failed != 0 {
        return Err(format!("{failed} pauses did not happen: {}", after.line));
    }
    notes.push(format!(
        "{SATURATE_SAMPLES} answers of the stack in a flood of {SATURATE_SECS} s on {SATURATE_CONSUMERS} rings: {took:?} (bound {bound:?}); {pauses} pauses, the longest run {longest} us (limit {limit} us)"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
