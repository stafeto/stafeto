// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of nginx on the TCP/IP stack in its own process (`cargo xtask
//! fast-probe nginx`, stage P6b-3 of subproject 6, spec 6, 3.9 and 8.9): the
//! image of the shell with both network devices on QEMU (`table-fast-nginx`,
//! `handover 1`, the second address 10.0.3.15), `nginx-fast` (the object of
//! nginx, F-Stack, the device's driver and the glue of ports/f-stack) and a
//! forward of the host's ports P and Q to ports 80 and 443 of the second
//! address. xtask drives the shell over the serial port:
//!
//! 1. `nginx-fast -c /etc/nginx/nginx-fast.conf &`: the event method
//!    `epoll`, one worker, the glue's line (the stack is up on the second
//!    address), no line at `alert`, `emerg` or `crit`;
//! 2. the first `GET /index.html`, repeated up to 30 s, with the time it took;
//! 3. 200 `GET /index.html` over 16 connections, 100 connections at once that
//!    each take the page of 64 KiB (the worker's largest holding, which the
//!    quota of the command must cover), `/10k.bin`, `/256k.bin` and
//!    `/1m.bin`, each body compared by SHA-256; `posix-net stat`: no session
//!    of the network service holds a shared buffer, so the answers did not go
//!    through the service (the path is the fast one);
//! 4. HTTPS through Q: TLS 1.3 with HTTP/2 and HTTP/1.1, 100 streams of one
//!    connection, 256 KiB over HTTP/2;
//! 5. a connection that waits 60 ms before each of 30 requests: the median
//!    of the answer times is at most 4 ms and at most one answer in ten takes
//!    over 5 ms, so the idle loop wakes on the device's interrupt;
//! 6. `kill -HUP` of the master under four connections without pauses and a
//!    new request every 50 ms: the old worker ends within 2 s, the new one
//!    gets the device, the requests that fail do so inside one short window
//!    and every one after it passes;
//! 7. four connections in rest, `kill -9` of the worker: the device comes back
//!    (`net: device 1 back`), a new worker starts and answers;
//! 8. `kill -QUIT` of the master during the download of 1 MiB by a client
//!    that has stopped reading (a receive buffer of 64 KiB), which reads on
//!    when the worker shuts down: the client gets all of it, so the stack
//!    sent the tail of its buffer after the worker's last words;
//! 9. four connections in rest, `kill -QUIT` of the master: every connection
//!    reads the end of the stream within a second, none a reset;
//! 10. the settings with `user nobody`: the worker cannot claim the device
//!     (`epoll_ctl() failed (1: Operation not permitted)`) and ends with code
//!     2, and the master says it cannot respawn it.
//!
//! `fast-probe nginx crash` runs the image whose service faults on CRASH:
//! under a stream of requests the service ends, the worker leaves (the line
//! of the layer on the console), the master says `exited with fatal code 2
//! and cannot be respawned` within 2 s and starts no worker.
//!
//! `fast-probe nginx steps` runs steps 1, 2, 3 and 7 under -icount with the
//! service counting its steps and judges every step against 0.9 of term B.
//!
//! The same image on Apple VZ is the part of `cargo xtask net-vz --fast
//! --static1 --nginx` that runs in this file (`vz_run`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::fast_probe::{expect_all, steps_verdict};
use crate::nginx_probe::{
    Connection, Tls, first_page, nginx_processes, noise, pages, same, tls_streams, tls_versions,
    www_10k, www_256k,
};
use crate::qemu::{Forward, Proto};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, ImageProgram, SERVICES_STARTED, Variant, build,
    build_boot_image, busybox_build, nano_build, net, net_probe, qemu, relibc, rootfs, symbolize,
};

pub const IMAGE: &str = "boot-fast-nginx.img";
pub const CRASH_IMAGE: &str = "boot-fast-nginx-crash.img";
pub const STEPS_IMAGE: &str = "boot-fast-nginx-steps.img";
pub const VZ_IMAGE: &str = "boot-fast-nginx-vz.img";
pub const VZ_STEPS_IMAGE: &str = "boot-fast-nginx-vz-steps.img";
/// The images of the switch: one device, nginx-fast under nobody on the shared address.
pub const SWITCH_IMAGE: &str = "boot-fast-switch.img";
pub const SWITCH_STEPS_IMAGE: &str = "boot-fast-switch-steps.img";
pub const SWITCH_VZ_IMAGE: &str = "boot-fast-switch-vz.img";

/// The settings of the package.
pub const NGINX_FAST_CONF: &str = include_str!("../../tools/nginx/nginx-fast.conf");
const CONF: &str = "/etc/nginx/nginx-fast.conf";
const NOBODY_CONF: &str = "/etc/nginx/nginx-fast-nobody.conf";
pub const SNDBUF_CONF: &str = "/etc/nginx/nginx-fast-sndbuf.conf";

unsafe extern "C" {
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const u8, len: u32) -> i32;
}

const SOL_SOCKET: i32 = if cfg!(target_os = "macos") { 0xffff } else { 1 };
const SO_RCVBUF: i32 = if cfg!(target_os = "macos") { 0x1002 } else { 8 };

/// The receive buffer of `stream` set to `bytes`: it stops growing, so a
/// client that does not read leaves the data in the sender.
fn small_receive_buffer(stream: &std::net::TcpStream, bytes: i32) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    // SAFETY: SO_RCVBUF takes an int; the pointer and its length are those
    // of `bytes`, which lives through the call.
    let r = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_RCVBUF,
            (&raw const bytes).cast(),
            4,
        )
    };
    if r != 0 {
        return Err(format!("SO_RCVBUF: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The page of 64 bytes whose answer times the wake of the idle loop (the
/// page of the other steps is 64 KiB, which the file service reads in
/// messages of about 1 000 bytes: the time to read it is of the order of the
/// time to be measured).
pub const TINY: &[u8] = b"stafeto: nginx on the stack answers a page that fits one segment\n";

/// The file of 1 MiB the download of step 8 fetches.
pub const ONE_MIB: usize = 1 << 20;
const ONE_MIB_PATH: &str = "/www/1m.bin";

const START_WITHIN: Duration = Duration::from_secs(60);
const QUIT_WITHIN: Duration = Duration::from_secs(20);
const READ_WITHIN: Duration = Duration::from_secs(30);
const REQUESTS: usize = 200;
/// The hundred connections of the wide step are opened one after another
/// through the queue of one of the user network of QEMU: 135 ms on a fast
/// machine, 27 663 ms on ci (a SYN sent again after a second now and then).
/// The answers took 564 ms and 1 704 ms. The deadlines are twice the largest
/// seen: 60 s to open, and the 30 s of a read for each answer.
const WIDE_OPEN_WITHIN: Duration = Duration::from_secs(60);
/// The connections of the step that loads the worker's memory the most.
const WIDE: usize = 100;
const CONNECTIONS: usize = 16;
const WAKE_REQUESTS: usize = 30;
const WAKE_PAUSE: Duration = Duration::from_millis(60);
/// The answers after pauses took 0.7 to 3.8 ms on TCG (the median 1.1 to
/// 3.2 ms from run to run, with the load of the host). A loop that does not
/// wake on the device's interrupt answers after the next tick of the stack
/// (10 ms): in the run that took the interrupt away the median was 2.4 to
/// 3.7 ms and one answer in five took over 5 ms, so the verdict has both: the
/// median, and the share of the answers over 5 ms.
const WAKE_MEDIAN_MAX: Duration = Duration::from_millis(4);
const WAKE_SLOW: Duration = Duration::from_millis(5);
const WAKE_SLOW_SHARE_MAX: f64 = 0.10;
/// The old worker of a reload ends this soon.
const OLD_WORKER_WITHIN: Duration = Duration::from_secs(2);
/// The reload runs this long under load, and the last part of it must be
/// free of failures.
const RELOAD_FOR: Duration = Duration::from_secs(14);
const RELOAD_QUIET: Duration = Duration::from_secs(5);
/// The connections that read the end of the stream do so this soon.
const CLOSE_WITHIN: Duration = Duration::from_secs(1);
/// The master ends within this long of the stop of a worker.
const FATAL_WITHIN: Duration = Duration::from_secs(2);
const RUN_WITHIN: Duration = Duration::from_secs(300);

/// `/etc/netd.conf` of the images of the switch: eight consumers, 16 384 flows.
pub const SWITCH_NETD_CONF: &[u8] = b"switch 8\nflows 16384\n";

/// The package's settings with the worker under root: the images of the
/// second device (CLAIM wants the superuser) run these until the second
/// device goes (stage Sh4d).
pub fn root_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        crate::nginx_probe::replaced(NGINX_FAST_CONF, "user nobody nobody;", "user root;")
    })
}

/// The probe's settings of the second-device images: the package's under
/// root with the server of TLS and the variable of the stack's counters
/// (nginx drops the environment but for what `env` names).
pub fn probe_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| with_tls(root_conf()))
}

/// The probe's settings of the images of the switch: the package's under
/// nobody, with the same additions.
pub fn switch_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| with_tls(NGINX_FAST_CONF))
}

fn with_tls(base: &str) -> String {
    {
        let text = crate::nginx_probe::replaced(
            base,
            "worker_shutdown_timeout 5s;\n",
            "worker_shutdown_timeout 5s;\nenv STAFETO_FAST_STATS;\nenv STAFETO_FAST_WAKES;\n",
        );
        crate::nginx_probe::replaced(
            &text,
            "    server {\n",
            &format!(
                "    include {};\n    server {{\n",
                crate::nginx_probe::TLS_CONF_PATH
            ),
        )
    }
}

/// The probe's settings with the worker under nobody.
pub fn nobody_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        crate::nginx_probe::replaced(probe_conf(), "user root;", "user nobody nobody;")
    })
}

/// The probe's settings with a send buffer of 2 MiB on the listener, so that
/// the worker puts a whole answer of 1 MiB into the stack at once and closes
/// the connection while the peer has taken little of it.
pub fn sndbuf_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        crate::nginx_probe::replaced(probe_conf(), "listen 80;", "listen 80 sndbuf=2m;")
    })
}

/// The file of 1 MiB.
pub fn one_mib() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| noise(0x1f1f, ONE_MIB))
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Plain,
    /// The service with the methods of the probe (CRASH).
    Crash,
    /// The service counting its steps.
    Steps,
    /// Apple VZ.
    Vz,
    /// Apple VZ, the service counting its steps.
    VzSteps,
    /// The image of scale on QEMU (`fast-probe scale`): on the switch.
    Scale,
    /// The switch on QEMU (`fast-probe switch`): one device, the service built for the probe.
    Switch,
    /// The switch, the service counting its steps.
    SwitchSteps,
    /// The switch on Apple VZ (the measurement of F1 through the switch builds it).
    #[allow(dead_code)]
    SwitchVz,
}

/// The programs of the image: those of the image with the network and both
/// devices, init's table for the program, and `nginx-fast`.
pub fn programs(kind: Kind) -> &'static [ImageProgram] {
    static LISTS: [std::sync::OnceLock<Vec<ImageProgram>>; 9] = [
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
    ];
    let at = match kind {
        Kind::Plain => 0,
        Kind::Crash => 1,
        Kind::Steps => 2,
        Kind::Vz => 3,
        Kind::VzSteps => 4,
        Kind::Scale => 5,
        Kind::Switch => 6,
        Kind::SwitchSteps => 7,
        Kind::SwitchVz => 8,
    };
    LISTS[at].get_or_init(|| {
        let vz = matches!(kind, Kind::Vz | Kind::VzSteps | Kind::SwitchVz);
        let mut programs = match kind {
            Kind::Vz => net::vz_programs(true).to_vec(),
            Kind::SwitchVz => net::vz_programs(false).to_vec(),
            Kind::VzSteps => net::vz_steps_programs(true).to_vec(),
            _ => net::programs().to_vec(),
        };
        let table: &'static [&'static str] = match kind {
            Kind::SwitchVz => &["table-fast-switch-vz"],
            Kind::Switch | Kind::SwitchSteps => &["table-fast-switch"],
            Kind::Scale => &["table-fast-switch-scale"],
            _ if vz => &["table-fast-nginx-vz"],
            _ => &["table-fast-nginx"],
        };
        for program in &mut programs {
            match (program.0, kind) {
                ("init", _) => program.3 = table,
                ("netd", Kind::Crash) => program.3 = &["probe"],
                ("netd", Kind::Steps | Kind::SwitchSteps) => program.3 = &["steps"],
                ("netd", Kind::Switch | Kind::Scale) => program.3 = &["probe"],
                // The calls of the file service are counted and printed (step 3, `calls`).
                ("ramfs", Kind::Plain) => program.3 = &["profile"],
                _ => {}
            }
        }
        programs.push(
            *crate::PACKAGE_PROGRAMS
                .iter()
                .find(|p| p.0 == "nginx-fast")
                .expect("nginx-fast is a package program"),
        );
        programs
    })
}

/// `cargo xtask fast-probe nginx [crash|steps] [tcg|hvf]`.
pub fn command(args: &[String]) -> Result<(), String> {
    // On two CPUs the service has two stack instances and the worker may stand on CPU 1: the
    // stack of the worker starts all the same (its ATTACH and CLAIM reach the first instance).
    if args.first().map(String::as_str) == Some("smp") && args.len() == 1 {
        return qemu::on_cpus(2, || probe(&qemu::VIRT, Kind::Plain));
    }
    let (kind, rest) = match args.first().map(String::as_str) {
        Some("crash") => (Kind::Crash, &args[1..]),
        Some("steps") => (Kind::Steps, &args[1..]),
        _ => (Kind::Plain, args),
    };
    let machine = match rest {
        [] => &qemu::VIRT,
        [name] if name == "hvf" => &qemu::HVF_V3,
        [name] if name == "tcg" => &qemu::VIRT,
        _ => return Err("usage: cargo xtask fast-probe nginx [crash|steps] [tcg|hvf]".to_owned()),
    };
    if kind == Kind::Steps && machine.is_hvf() {
        return Err("fast-probe nginx steps runs under -icount, on TCG only".to_owned());
    }
    probe(machine, kind)
}

/// The Tls and the plain port of the host, and the machine's arguments.
struct Ports {
    http: u16,
    https: u16,
}

fn image_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Plain => IMAGE,
        Kind::Crash => CRASH_IMAGE,
        Kind::Steps => STEPS_IMAGE,
        Kind::Vz => VZ_IMAGE,
        Kind::VzSteps => VZ_STEPS_IMAGE,
        Kind::Scale => crate::fast_scale::IMAGE,
        Kind::Switch => SWITCH_IMAGE,
        Kind::SwitchSteps => SWITCH_STEPS_IMAGE,
        Kind::SwitchVz => SWITCH_VZ_IMAGE,
    }
}

/// Waits for a line with each of `wanted`, in any order, and fails on the
/// first line that says a worker or the stack broke (an alert or an
/// emergency of nginx).
fn expect_start(run: &mut qemu::Run, wanted: &[&str], within: Duration) -> Result<(), String> {
    expect_or_break(run, wanted, within)
}

/// The same for any lines: a line of nginx at `alert` or above
/// before all of `wanted` came is a failure (a worker that spins on
/// `epoll_wait` in a loop of alerts is one, and the transcript of such a loop
/// must not be waited on).
fn expect_or_break(run: &mut qemu::Run, wanted: &[&str], within: Duration) -> Result<(), String> {
    let mut left: Vec<&str> = wanted.to_vec();
    let end = Instant::now() + within;
    while !left.is_empty() {
        let line = run.expect_line(
            &format!("{left:?}"),
            |l| {
                left.iter().any(|w| l.contains(w))
                    || l.contains("[alert]")
                    || l.contains("[emerg]")
                    || l.contains("[crit]")
            },
            end.saturating_duration_since(Instant::now()),
        )?;
        if let Some(w) = left.iter().position(|w| line.contains(w)) {
            left.remove(w);
        } else {
            return Err(format!(
                "a line of an alert: {line:?}; still waiting for {left:?}"
            ));
        }
    }
    Ok(())
}

/// Waits for the lines of the start of `nginx-fast` and gives the time from
/// the command to the line of the layer.
pub(crate) fn started(run: &mut qemu::Run, settings: &str) -> Result<Duration, String> {
    let began = Instant::now();
    run.send(&format!("nginx-fast -c {settings} & M=$!"))?;
    expect_start(
        run,
        &[
            "using the \"epoll\" event method",
            "start worker process ",
            "fast: the stack is up on ",
        ],
        START_WITHIN,
    )?;
    Ok(began.elapsed())
}

/// The PID in the shell's `M`.
fn master_pid(run: &mut qemu::Run) -> Result<u32, String> {
    run.send("echo master-pid-\"$M\"-end")?;
    let line = run.expect_line(
        "the master's PID",
        |l| {
            l.split("master-pid-")
                .nth(1)
                .and_then(|r| r.split("-end").next())
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        },
        DIALOG_STEP,
    )?;
    line.split("master-pid-")
        .nth(1)
        .and_then(|r| r.split("-end").next())
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| format!("the line {line:?}"))
}

/// The processes of nginx: the master `m` and the PIDs of the others.
pub(crate) fn master_and_workers(
    run: &mut qemu::Run,
    tag: &str,
    root: bool,
) -> Result<(u32, Vec<u32>), String> {
    let m = master_pid(run)?;
    let processes = nginx_processes(run, tag)?;
    let others: Vec<u32> = processes.iter().filter(|p| p.0 != m).map(|p| p.0).collect();
    let user = if root { 0 } else { 65534 };
    if !processes.iter().any(|p| p.0 == m && p.1 == 0)
        || processes.iter().any(|p| p.0 != m && p.1 != user)
    {
        return Err(format!(
            "the nginx processes (PID, user ID) are {processes:?}: wanted the master {m} of user 0 and workers of user {user}"
        ));
    }
    Ok((m, others))
}

/// The memory the process `pid` holds, in KiB, from `/proc`.
fn resident_kib(run: &mut qemu::Run, pid: u32) -> Result<u64, String> {
    run.send(&format!("grep VmRSS /proc/{pid}/status"))?;
    let line = run.expect_line(
        "VmRSS",
        |l| l.trim_start().starts_with("VmRSS:") && l.trim_end().ends_with("kB"),
        DIALOG_STEP,
    )?;
    line.split_whitespace()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("the line {line:?}"))
}

/// `kill -QUIT $M; wait $M` and a marker after it.
fn quit_send(run: &mut qemu::Run, tag: &str) -> Result<(), String> {
    run.send(&format!("kill -QUIT $M; wait $M; echo ngx-\"{tag}\"-end"))
}

/// The master's end: the marker of `quit_send`, and the device back from the
/// worker that left with it.
fn quit_end(run: &mut qemu::Run, tag: &str) -> Result<(), String> {
    expect_all(
        run,
        &["net: device 1 back", &format!("ngx-{tag}-end")],
        QUIT_WITHIN,
    )
}

/// `kill -QUIT $M; wait $M`, within `QUIT_WITHIN`; the time it took.
pub(crate) fn quit(run: &mut qemu::Run, tag: &str) -> Result<Duration, String> {
    let at = Instant::now();
    quit_send(run, tag)?;
    quit_end(run, tag)?;
    Ok(at.elapsed())
}

/// Step 5: 30 requests on one connection with a pause before each; the
/// median of the times from the request to the whole answer, and the share
/// of those over `WAKE_SLOW`.
fn wake(address: SocketAddr) -> Result<(Duration, f64), String> {
    let mut c = Connection::open(address, READ_WITHIN)?;
    let mut times = Vec::new();
    for n in 0..WAKE_REQUESTS {
        // 60 ms plus a few ms that differ, so that the pause is no multiple
        // of the stack's tick of 10 ms.
        std::thread::sleep(WAKE_PAUSE + Duration::from_micros((n as u64 * 977) % 9_000));
        let at = Instant::now();
        let body = c.get("/tiny.txt")?;
        times.push(at.elapsed());
        same("the small page after a pause", &body, TINY)?;
    }
    println!(
        "fast-nginx: the times of the answers after a pause, us: {:?}",
        times.iter().map(|t| t.as_micros()).collect::<Vec<_>>()
    );
    let slow = times.iter().filter(|t| **t > WAKE_SLOW).count();
    times.sort_unstable();
    Ok((times[times.len() / 2], slow as f64 / times.len() as f64))
}

/// The sums of the three files over the plain port: `/10k.bin` and
/// `/256k.bin` once, `/1m.bin` once.
fn files(address: SocketAddr) -> Result<(), String> {
    for (path, want) in [
        ("/10k.bin", www_10k()),
        ("/256k.bin", www_256k()),
        (ONE_MIB_PATH.trim_start_matches("/www"), one_mib()),
    ] {
        let body = Connection::open(address, READ_WITHIN)
            .and_then(|mut c| c.get(path))
            .map_err(|e| format!("GET {path}: {e}"))?;
        same(&format!("GET {path}"), &body, want)?;
    }
    Ok(())
}

/// `width` connections open at once (the time to open them one after another
/// and the time to answer are given apart: a connection through the user
/// network of QEMU may wait for a SYN to be sent again), each fetching the page
/// of 64 KiB at the same time: the worker holds the buffers of all the answers together, which
/// is the largest holding of the run and sets the quota of the command.
fn wide(address: SocketAddr, width: usize) -> Result<(Duration, Duration), String> {
    let opening = Instant::now();
    let mut open = Vec::new();
    for n in 0..width {
        open.push(
            Connection::open(address, READ_WITHIN)
                .map_err(|e| format!("connection {} of {width}: {e}", n + 1))?,
        );
    }
    let opened = opening.elapsed();
    if opened > WIDE_OPEN_WITHIN {
        return Err(format!(
            "{width} connections took {} ms to open, past {} ms",
            opened.as_millis(),
            WIDE_OPEN_WITHIN.as_millis()
        ));
    }
    let answering = Instant::now();
    let threads: Vec<_> = open
        .into_iter()
        .map(|mut c| {
            std::thread::spawn(move || -> Result<(), String> {
                let body = c.get("/index.html")?;
                same("the page", &body, rootfs::www_index())
            })
        })
        .collect();
    let mut failed = Vec::new();
    for (n, thread) in threads.into_iter().enumerate() {
        if let Err(why) = thread
            .join()
            .map_err(|_| "a request thread panicked".to_owned())?
        {
            failed.push(format!("connection {}: {why}", n + 1));
        }
    }
    if failed.is_empty() {
        Ok((opened, answering.elapsed()))
    } else {
        Err(format!(
            "{} of {width} answers failed: {}",
            failed.len(),
            failed.first().map_or("", String::as_str)
        ))
    }
}

/// `posix-net stat` says no session of the network service holds a shared
/// buffer (the sockets of nginx are the stack's).
fn no_buffers(run: &mut qemu::Run) -> Result<(), String> {
    let (sessions, kib) = crate::nginx_probe::buffered(run)?;
    if sessions != 0 || kib != 0 {
        return Err(format!(
            "{sessions} sessions of the network service hold a shared buffer ({kib} KiB): nginx's sockets are no sockets of the stack"
        ));
    }
    Ok(())
}

/// The outcome of the load of the reload.
struct Load {
    done: usize,
    failures: Vec<Duration>,
}

/// Four connections of requests without a pause (each opens another when
/// its connection fails) and a request on a new connection every 50 ms,
/// until `stop`: the successes and the moments of the failures after
/// `begin`.
fn load(
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    begin: Instant,
) -> Vec<std::thread::JoinHandle<Load>> {
    let mut threads = Vec::new();
    for n in 0..5 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut out = Load {
                done: 0,
                failures: Vec::new(),
            };
            let mut connection: Option<Connection> = None;
            while !stop.load(Ordering::Relaxed) {
                if n == 4 {
                    // The paced one makes a new connection each time.
                    connection = None;
                    std::thread::sleep(Duration::from_millis(50));
                }
                let answer = (|| {
                    if connection.is_none() {
                        connection = Some(Connection::open(address, Duration::from_secs(3))?);
                    }
                    let body = connection.as_mut().expect("opened").get("/index.html")?;
                    same("the page under the reload", &body, rootfs::www_index())
                })();
                match answer {
                    Ok(()) => out.done += 1,
                    Err(_) => {
                        out.failures.push(begin.elapsed());
                        connection = None;
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            out
        }));
    }
    threads
}

/// Step 6.
fn reload(run: &mut qemu::Run, address: SocketAddr) -> Result<String, String> {
    let (_, old) = master_and_workers(run, "before-reload", true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let begin = Instant::now();
    let threads = load(address, stop.clone(), begin);
    let asked = (|| {
        std::thread::sleep(Duration::from_millis(1500));
        let hup_at = begin.elapsed();
        run.send("kill -HUP $M")?;
        let mut notes = Vec::new();
        run.expect_line(
            "reconfiguring",
            |l| l.contains("reconfiguring"),
            START_WITHIN,
        )?;
        let line = run.expect_line(
            "the old worker's end",
            |l| l.contains("exited with code 0"),
            START_WITHIN,
        )?;
        let gone = begin.elapsed() - hup_at;
        if gone > OLD_WORKER_WITHIN {
            return Err(format!(
                "the old worker took {} ms to end after the signal ({line:?})",
                gone.as_millis()
            ));
        }
        notes.push(format!(
            "the old worker ended {} ms after the signal",
            gone.as_millis()
        ));
        std::thread::sleep(RELOAD_FOR.saturating_sub(begin.elapsed()));
        Ok::<(Duration, Vec<String>), String>((hup_at, notes))
    })();
    stop.store(true, Ordering::Relaxed);
    let mut done = 0;
    let mut failures: Vec<Duration> = Vec::new();
    for thread in threads {
        let load = thread
            .join()
            .map_err(|_| "a load thread panicked".to_owned())?;
        done += load.done;
        failures.extend(load.failures);
    }
    let (hup_at, mut notes) = asked?;
    failures.sort_unstable();
    let end = begin.elapsed();
    if let Some(last) = failures.last()
        && end.saturating_sub(*last) < RELOAD_QUIET
    {
        return Err(format!(
            "the requests still failed {} ms before the end of the reload ({} failures, the last at {} ms, the signal at {} ms)",
            end.saturating_sub(*last).as_millis(),
            failures.len(),
            last.as_millis(),
            hup_at.as_millis()
        ));
    }
    let (_, now) = master_and_workers(run, "after-reload", true)?;
    if let Some(pid) = now.iter().find(|w| old.contains(w)) {
        return Err(format!("worker {pid} lived through the reload"));
    }
    println!(
        "fast-nginx: the failures of the reload at {:?} ms, the signal at {} ms",
        failures.iter().map(|f| f.as_millis()).collect::<Vec<_>>(),
        hup_at.as_millis()
    );
    let window = match (failures.first(), failures.last()) {
        (Some(a), Some(b)) => (*b - *a).as_millis(),
        _ => 0,
    };
    notes.push(format!(
        "{done} requests passed and {} failed under the reload, the failures inside a window of {window} ms after the signal",
        failures.len()
    ));
    Ok(notes.join("; "))
}

/// Step 8: a client with a small receive buffer (64 KiB) takes the first bytes
/// of a download of 1 MiB and stops reading, which stops the stack's
/// sending at the window; the master is told to quit; when the worker says
/// it shuts down gracefully (it has put the whole file into its 2 MiB send
/// buffer and closed the connection, and ends at once) the client reads on.
/// What the client has not taken is in the stack, which must keep sending
/// after the worker's last words (the layer's last steps, at most 200 ms) or
/// the client's read ends short.
fn quit_during_download(run: &mut qemu::Run, address: SocketAddr) -> Result<String, String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|e| format!("connect: {e}"))?;
    small_receive_buffer(&stream, 64 * 1024)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(b"GET /1m.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("request: {e}"))?;
    let mut head = [0u8; 256];
    let n = stream
        .read(&mut head)
        .map_err(|e| format!("first read: {e}"))?;
    let mut got = head[..n].to_vec();
    // Let the stack fill the window and the buffers before the signal.
    std::thread::sleep(Duration::from_millis(300));
    quit_send(run, "quit-download")?;
    run.expect_line(
        "the worker's graceful end",
        |l| l.contains("gracefully shutting down"),
        QUIT_WITHIN,
    )?;
    let at = Instant::now();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
            Err(e) => {
                return Err(format!(
                    "the download ended in an error after {} bytes: {e}",
                    got.len()
                ));
            }
        }
    }
    let body_at = got
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no end of the head")?
        + 4;
    let body = &got[body_at..];
    if body.len() != ONE_MIB {
        return Err(format!(
            "the download of 1 MiB ended with {} bytes after the master was told to quit",
            body.len()
        ));
    }
    same("GET /1m.bin during the quit", body, one_mib())?;
    quit_end(run, "quit-download")?;
    Ok(format!(
        "1 MiB whole, the client took it {} ms after the worker's last words",
        at.elapsed().as_millis()
    ))
}

/// Step 9: connections in rest read the end of the stream after the quit.
fn quit_with_rest(run: &mut qemu::Run, address: SocketAddr) -> Result<String, String> {
    use std::io::Read;
    let mut open = Vec::new();
    for n in 0..4 {
        let mut c = Connection::open(address, READ_WITHIN)?;
        let body = c
            .get("/index.html")
            .map_err(|e| format!("connection {n}: {e}"))?;
        same("the page before the quit", &body, rootfs::www_index())?;
        open.push(c);
    }
    let at = Instant::now();
    quit_send(run, "quit-rest")?;
    let mut slowest = Duration::ZERO;
    for (n, c) in open.iter_mut().enumerate() {
        let stream = c.stream();
        stream
            .set_read_timeout(Some(CLOSE_WITHIN))
            .map_err(|e| e.to_string())?;
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => slowest = slowest.max(at.elapsed()),
            Ok(_) => return Err(format!("connection {n} got data at the quit")),
            Err(e) => {
                return Err(format!(
                    "connection {n} did not read the end of the stream within {CLOSE_WITHIN:?} of the quit: {e}"
                ));
            }
        }
    }
    quit_end(run, "quit-rest")?;
    Ok(format!(
        "four connections read the end of the stream within {} ms of the quit",
        slowest.as_millis()
    ))
}

/// Step 10: the worker under nobody.
fn nobody(run: &mut qemu::Run) -> Result<String, String> {
    run.send(&format!("nginx-fast -c {NOBODY_CONF} & M=$!"))?;
    let at = Instant::now();
    run.expect_line(
        "the refused epoll_ctl",
        |l| l.contains("epoll_ctl(") && l.contains("(1: Operation not permitted)"),
        START_WITHIN,
    )?;
    run.expect_line(
        "the fatal end",
        |l| l.contains("exited with fatal code 2 and cannot be respawned"),
        START_WITHIN,
    )?;
    let took = at.elapsed();
    let (_, workers) = master_and_workers(run, "nobody", true)?;
    if !workers.is_empty() {
        return Err(format!(
            "workers {workers:?} stand after the worker's fatal end"
        ));
    }
    quit_send(run, "nobody-end")?;
    run.expect_line(
        "the master's end",
        |l| l.trim_end() == "ngx-nobody-end-end",
        QUIT_WITHIN,
    )?;
    Ok(format!(
        "under nobody the worker ended with code 2 and the master did not respawn it, {} ms after the start",
        took.as_millis()
    ))
}

/// Fails on a line of nginx at `crit` or above, but for the alerts the
/// scenarios cause (a worker killed, a worker that ended with 2), or on a
/// fault of the image.
pub(crate) fn verdict(lines: &[String], faults_allowed: usize) -> Result<(), String> {
    if let Some(line) = lines.iter().find(|l| {
        ["[alert]", "[emerg]", "[crit]"]
            .iter()
            .any(|level| l.contains(level))
            && !l.contains("exited on signal 9")
            && !l.contains("exited with fatal code 2")
            && !l.contains("epoll_ctl(")
    }) {
        return Err(format!("nginx logged: {line}"));
    }
    let faults = lines
        .iter()
        .filter(|l| l.contains("process fault:"))
        .count();
    if faults != faults_allowed
        || lines
            .iter()
            .any(|l| l.contains("KERNEL PANIC") || l.contains("out of memory"))
    {
        return Err(format!(
            "{faults} process faults, {faults_allowed} allowed, or a panic"
        ));
    }
    Ok(())
}

/// The shell prompt, the leases of both devices and the shell.
pub(crate) fn booted(run: &mut qemu::Run) -> Result<(), String> {
    run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
    expect_all(
        run,
        &["net: lease 10.0.2.15/24", "net: static1 10.0.3.15/24"],
        BOOT_TIMEOUT,
    )?;
    run.expect("# ", DIALOG_STEP)?;
    run.send("S=ok")?;
    run.expect("# ", DIALOG_STEP)?;
    Ok(())
}

pub fn probe(machine: &'static qemu::Machine, kind: Kind) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    relibc()?;
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    let ca = crate::probe_ca::ensure(false)?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(image_of(kind), programs(kind), BOOT_PROFILE)?;
    for package in ["nginx-fast", "f-stack"] {
        crate::notices::image_has_package_notices(&image, image_of(kind), package)?;
    }
    let ports = Ports {
        http: crate::net_curl::free_tcp_port()?,
        https: crate::net_curl::free_tcp_port()?,
    };
    let address: SocketAddr = ([127, 0, 0, 1], ports.http).into();
    let dir = crate::target_dir().join("fast-nginx");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tls = Tls {
        port: ports.https,
        ca,
        dir,
    };
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    cmd.args(qemu::net_two_with(&[
        Forward {
            proto: Proto::Tcp,
            host: ports.http,
            guest: 80,
        },
        Forward {
            proto: Proto::Tcp,
            host: ports.https,
            guest: 443,
        },
    ]));
    if kind == Kind::Steps {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let mut notes: Vec<String> = Vec::new();
    let talked = match kind {
        Kind::Crash => crash_scenario(&mut run, address, &mut notes),
        _ => scenario(&mut run, address, &tls, kind, &mut notes),
    };
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    for note in &notes {
        println!("fast-nginx: {note}");
    }
    talked?;
    verdict(&output.lines, usize::from(kind == Kind::Crash))?;
    net_probe::placing_fault(&output.lines)?;
    if kind == Kind::Steps {
        let rows = steps_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "fast-nginx steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            net_probe::STEP_MAX
        );
    }
    let elapsed = started.elapsed();
    if kind == Kind::Plain && elapsed > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s, past {} s",
            elapsed.as_secs_f64(),
            RUN_WITHIN.as_secs()
        ));
    }
    println!(
        "fast-nginx passed in {:.0} s on {}",
        elapsed.as_secs_f64(),
        machine.name
    );
    Ok(())
}

fn scenario(
    run: &mut qemu::Run,
    address: SocketAddr,
    tls: &Tls,
    kind: Kind,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    booted(run)?;
    run.send("export STAFETO_FAST_WAKES=1")?;
    run.expect("# ", DIALOG_STEP)?;
    // 1.
    let up = started(run, CONF)?;
    let (master, workers) = master_and_workers(run, "start", true)?;
    if workers.len() != 1 {
        return Err(format!("{} workers, wanted one", workers.len()));
    }
    notes.push(format!(
        "1: master {master} and worker {} of user 0; the stack up {} ms after the command",
        workers[0],
        up.as_millis()
    ));
    // 2.
    let at = Instant::now();
    first_page(address)?;
    notes.push(format!(
        "2: the first page {} ms after the start line",
        at.elapsed().as_millis()
    ));
    // 3.
    let at = Instant::now();
    pages(address, REQUESTS, CONNECTIONS)?;
    notes.push(format!(
        "3: {REQUESTS} requests over {CONNECTIONS} connections in {} ms",
        at.elapsed().as_millis()
    ));
    if kind == Kind::Plain {
        notes.push(format!("3: {}", calls(run, address)?));
    }
    if kind != Kind::Steps {
        let (opened, answered) = wide(address, WIDE)?;
        notes.push(format!(
            "3: {WIDE} connections at once, each with the page of 64 KiB: opened one after another in {} ms, answered in {} ms",
            opened.as_millis(),
            answered.as_millis()
        ));
        files(address)?;
        no_buffers(run)?;
        notes.push(
            "3: /10k.bin, /256k.bin and /1m.bin by SHA-256; no session holds a shared buffer"
                .to_owned(),
        );
        // 4.
        tls_versions(tls)?;
        tls_streams(tls, "before the reload")?;
        notes.push(
            "4: TLS 1.3 with HTTP/2 and HTTP/1.1, 100 streams, 256 KiB over HTTP/2".to_owned(),
        );
        let rss = resident_kib(run, workers[0])?;
        let master_rss = resident_kib(run, master)?;
        notes.push(format!(
            "4: the worker holds {rss} KiB and the master {master_rss} KiB after the load"
        ));
        // 5. The totals the worker says every second, one line before the
        // pauses and one after.
        let before = wakes_line(run)?;
        let (median, slow) = wake(address)?;
        notes.push(format!(
            "5: median answer after a pause of 60 ms {} us (at most {} us), {:.0} % over {} us (at most {:.0} %)",
            median.as_micros(),
            WAKE_MEDIAN_MAX.as_micros(),
            slow * 100.0,
            WAKE_SLOW.as_micros(),
            WAKE_SLOW_SHARE_MAX * 100.0
        ));
        if median > WAKE_MEDIAN_MAX || slow > WAKE_SLOW_SHARE_MAX {
            return Err(format!(
                "the answers after a pause: median {} us, {:.0} % over {} us: the idle loop does not wake on the interrupt",
                median.as_micros(),
                slow * 100.0,
                WAKE_SLOW.as_micros()
            ));
        }
        let wakes = wakes_line(run)?.since(&before);
        check_wakes(&wakes)?;
        notes.push(format!(
            "5: {} sleeps of the worker during the pauses, {} ended by a notification, {} by the deadline ({} of those with a frame already in the ring, at most 1 %), {} by another descriptor",
            wakes.sleeps, wakes.bell, wakes.deadline, wakes.deadline_found, wakes.other
        ));
        // 6.
        notes.push(format!("6: {}", reload(run, address)?));
        tls_streams(tls, "after the reload")?;
        let (_, workers) = master_and_workers(run, "after-https", true)?;
        let rss = resident_kib(run, workers[0])?;
        notes.push(format!(
            "6: the new worker holds {rss} KiB after the reload and HTTPS"
        ));
    }
    // 7.
    let (_, workers) = master_and_workers(run, "before-kill", true)?;
    let mut rest = Vec::new();
    for _ in 0..4 {
        let mut c = Connection::open(address, READ_WITHIN)?;
        c.get("/index.html")?;
        rest.push(c);
    }
    let at = Instant::now();
    run.send(&format!("kill -9 {}", workers[0]))?;
    expect_all(
        run,
        &["net: device 1 back", "start worker process "],
        START_WITHIN,
    )?;
    drop(rest);
    first_page(address)?;
    notes.push(format!(
        "7: kill -9 of the worker: the device back, a new worker and a page {} ms later",
        at.elapsed().as_millis()
    ));
    if kind == Kind::Steps {
        quit(run, "quit")?;
        return Ok(());
    }
    // 8: another start, with the large send buffer.
    quit(run, "quit-7")?;
    started(run, SNDBUF_CONF)?;
    first_page(address)?;
    notes.push(format!("8: {}", quit_during_download(run, address)?));
    // 9.
    started(run, CONF)?;
    first_page(address)?;
    notes.push(format!("9: {}", quit_with_rest(run, address)?));
    // 10.
    notes.push(format!("10: {}", nobody(run)?));
    Ok(())
}

/// The last record of the file service's counters on the console: calls, reads, snapshots.
fn ramfs_record(run: &qemu::Run) -> Option<(u64, u64, u64, u64)> {
    let line = run
        .text()
        .into_iter()
        .rfind(|l| l.contains("ramfs: prof "))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words.iter().position(|w| *w == "prof")?;
    let number = |name: &str| -> Option<u64> {
        let i = words.iter().position(|w| *w == name)?;
        words.get(i + 1)?.parse().ok()
    };
    Some((
        words.get(at + 1)?.parse().ok()?,
        number("calls")?,
        number("reads")?,
        number("snaps")?,
    ))
}

/// The last record after the console has been read for `settle`: the record of the counters is
/// printed at most every 100 ms while calls come and at each notification of the service
/// after, so what the service has counted shows within a heartbeat. The console is read by
/// waiting for a line that never comes, which makes no call of the file service.
fn settled_record(run: &mut qemu::Run, settle: Duration) -> Result<(u64, u64, u64, u64), String> {
    let _ = run.expect_seen("calls: the line that never comes", settle);
    ramfs_record(run).ok_or_else(|| "the file service printed no record of its calls".to_owned())
}

/// Step 3, `calls`: 100 requests of a file the worker has served before make no read call
/// to the file service (the worker reads from the copy it holds), the counters of the service
/// being those of its profile records. Without the copy (`STAFETO_FILE_CACHE=0`) each answer
/// reads the file from the service.
fn calls(run: &mut qemu::Run, address: SocketAddr) -> Result<String, String> {
    // The first pages fill the copies and the cache of open files.
    pages(address, 50, 4)?;
    let before = settled_record(run, Duration::from_secs(2))?;
    pages(address, 100, 4)?;
    let after = settled_record(run, Duration::from_secs(2))?;
    let (calls, reads, snaps) = (after.1 - before.1, after.2 - before.2, after.3 - before.3);
    let note = format!(
        "100 requests made {calls} calls to the file service, {reads} of them reads and {snaps} snapshots"
    );
    if reads != 0 {
        return Err(format!(
            "{note}: the worker reads the file from the service"
        ));
    }
    Ok(note)
}

/// `fast-probe nginx crash`.
fn crash_scenario(
    run: &mut qemu::Run,
    address: SocketAddr,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    booted(run)?;
    started(run, CONF)?;
    first_page(address)?;
    let stop = Arc::new(AtomicBool::new(false));
    let begin = Instant::now();
    let served = Arc::new(AtomicUsize::new(0));
    let asking = {
        let (stop, served) = (stop.clone(), served.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if Connection::open(address, Duration::from_secs(2))
                    .and_then(|mut c| c.get("/index.html"))
                    .is_ok()
                {
                    served.fetch_add(1, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };
    let result = (|| {
        std::thread::sleep(Duration::from_millis(1000));
        let at = Instant::now();
        run.send("fast-echo 7 --crash")?;
        expect_or_break(
            run,
            &[
                "fast-echo: crash sent",
                "init: net ended: fault",
                "fast: the network service let the device go",
                "exited with fatal code 2 and cannot be respawned",
            ],
            START_WITHIN,
        )?;
        let took = at.elapsed();
        if took > FATAL_WITHIN {
            return Err(format!(
                "the master said the worker could not be respawned {} ms after CRASH, past {} ms",
                took.as_millis(),
                FATAL_WITHIN.as_millis()
            ));
        }
        notes.push(format!(
            "crash: the layer's line, the worker's end with code 2 and the master's \"cannot be respawned\" {} ms after CRASH",
            took.as_millis()
        ));
        // No new worker in the next two seconds.
        std::thread::sleep(FATAL_WITHIN);
        let workers = run
            .lines()
            .iter()
            .filter(|l| l.contains("start worker process "))
            .count();
        if workers != 1 {
            return Err(format!(
                "{workers} lines of a started worker, wanted the one"
            ));
        }
        Ok::<(), String>(())
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = asking.join();
    result?;
    notes.push(format!(
        "crash: {} requests were served in {} ms before the end",
        served.load(Ordering::Relaxed),
        begin.elapsed().as_millis()
    ));
    run.send("echo probe-end")?;
    run.expect("probe-end", DIALOG_STEP)?;
    Ok(())
}

// ---- Apple VZ ----

/// What `wrk` printed: the rate, and the counts of its errors.
#[derive(Debug, PartialEq)]
pub struct Wrk {
    pub requests_per_second: f64,
    pub connect: u64,
    pub read: u64,
    pub write: u64,
    pub timeout: u64,
    pub non_2xx: u64,
}

/// The numbers in the output of `wrk`: `Requests/sec:`, the line `Socket
/// errors: connect N, read N, write N, timeout N` (absent when there are
/// none) and `Non-2xx or 3xx responses: N`.
pub fn parse_wrk(text: &str) -> Option<Wrk> {
    let mut out = Wrk {
        requests_per_second: f64::NAN,
        connect: 0,
        read: 0,
        write: 0,
        timeout: 0,
        non_2xx: 0,
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Requests/sec:") {
            out.requests_per_second = rest.trim().parse().ok()?;
        } else if let Some(rest) = line.strip_prefix("Socket errors:") {
            for part in rest.split(',') {
                let mut words = part.split_whitespace();
                let (name, count) = (words.next()?, words.next()?.parse().ok()?);
                match name {
                    "connect" => out.connect = count,
                    "read" => out.read = count,
                    "write" => out.write = count,
                    "timeout" => out.timeout = count,
                    _ => return None,
                }
            }
        } else if let Some(rest) = line.strip_prefix("Non-2xx or 3xx responses:") {
            out.non_2xx = rest.trim().parse().ok()?;
        }
    }
    out.requests_per_second.is_finite().then_some(out)
}

/// The totals of the stack's counters in a line of the glue.
#[derive(Debug, PartialEq)]
pub struct Stats {
    pub ticks: u64,
    pub notifications: u64,
    pub passes: u64,
    pub rx: u64,
    pub tx: u64,
}

/// `fast: stats ticks=N notifications=N ... passes=N rx=N tx=N`.
pub fn parse_stats(line: &str) -> Option<Stats> {
    let rest = line.split("fast: stats ").nth(1)?;
    let field = |name: &str| -> Option<u64> {
        rest.split_whitespace()
            .find_map(|w| w.strip_prefix(name)?.strip_prefix('='))?
            .parse()
            .ok()
    };
    Some(Stats {
        ticks: field("ticks")?,
        notifications: field("notifications")?,
        passes: field("passes")?,
        rx: field("rx")?,
        tx: field("tx")?,
    })
}

/// The sleeps of the worker's loop by what woke them, from a line of the glue.
#[derive(Debug, PartialEq)]
pub struct Wakes {
    pub sleeps: u64,
    pub bell: u64,
    pub deadline: u64,
    pub other: u64,
    pub deadline_found: u64,
}

impl Wakes {
    /// What came between two lines (`self` the later one).
    pub fn since(&self, before: &Wakes) -> Wakes {
        Wakes {
            sleeps: self.sleeps.saturating_sub(before.sleeps),
            bell: self.bell.saturating_sub(before.bell),
            deadline: self.deadline.saturating_sub(before.deadline),
            other: self.other.saturating_sub(before.other),
            deadline_found: self.deadline_found.saturating_sub(before.deadline_found),
        }
    }
}

/// `fast: wakes sleeps=N bell=N deadline=N other=N deadline_found=N`.
pub fn parse_wakes(line: &str) -> Option<Wakes> {
    let rest = line.split("fast: wakes ").nth(1)?;
    let field = |name: &str| -> Option<u64> {
        rest.split_whitespace()
            .find_map(|w| w.strip_prefix(name)?.strip_prefix('='))?
            .parse()
            .ok()
    };
    Some(Wakes {
        sleeps: field("sleeps")?,
        bell: field("bell")?,
        deadline: field("deadline")?,
        other: field("other")?,
        deadline_found: field("deadline_found")?,
    })
}

/// What the worker did during the paused requests (the change of the counters
/// over step 5 alone). A sleep that ended by the deadline with a frame already
/// in the ring may be a lost wake-up or a notification still on its way (the
/// ring is looked at the instant the sleep ends), so the probe judges the
/// share of the wakes that had a frame: `deadline_found` of `bell + deadline_found`
/// stays at most a quarter (about 5 % on QEMU's TCG with the interrupt working,
/// half with it switched off in every second sleep) and at least
/// `WAKES_ALLOWED` of them pass whatever the count. The interrupt of the device
/// wakes the idle loop and the deadline is only the backstop; the counters rule
/// out a lost wake-up and say nothing of a slow one. The sleeps seen must reach
/// `WAKES_MIN`.
const WAKES_MIN: u64 = 30;
const WAKES_ALLOWED: u64 = 2;
pub fn check_wakes(w: &Wakes) -> Result<(), String> {
    if w.sleeps < WAKES_MIN {
        return Err(format!(
            "the worker slept {} times, wanted {WAKES_MIN}",
            w.sleeps
        ));
    }
    let with_frames = w.bell + w.deadline_found;
    if w.deadline_found > WAKES_ALLOWED && w.deadline_found * 4 > with_frames {
        return Err(format!(
            "{} of {with_frames} wakes with a frame in the ring ended by the deadline (at most a quarter): the interrupt did not wake the loop",
            w.deadline_found
        ));
    }
    Ok(())
}

/// The next line `fast: wakes` the worker says (every second).
fn wakes_line(run: &mut qemu::Run) -> Result<Wakes, String> {
    run.send("echo wakes-mark")?;
    run.expect("wakes-mark", DIALOG_STEP)?;
    let line = run.expect_line(
        "the counters of the sleeps",
        |l| l.contains("fast: wakes "),
        Duration::from_secs(8),
    )?;
    parse_wakes(&line).ok_or_else(|| format!("no counters in {line:?}"))
}

/// `wrk -t2 -c200 -d<seconds>s URL` run on the Mac.
fn wrk(url: &str, seconds: u64) -> Result<Wrk, String> {
    let output = std::process::Command::new("wrk")
        .args(["-t2", "-c200", &format!("-d{seconds}s"), url])
        .output()
        .map_err(|e| format!("wrk: {e} (brew install wrk)"))?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    println!("{}", text.trim_end());
    parse_wrk(&text).ok_or_else(|| format!("wrk printed no rate: {text}"))
}

/// `curl --http2` against the second address with the probe CA: the page is
/// whole and the version is 2.
fn https_page(
    address: std::net::Ipv4Addr,
    ca: &std::path::Path,
    dir: &std::path::Path,
) -> Result<(), String> {
    let out = dir.join("vz-index.html");
    let output = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "60", "--http2", "--cacert"])
        .arg(ca.join("ca.crt"))
        .arg("--resolve")
        .arg(format!("nginx.stafeto.test:443:{address}"))
        .args(["-w", "%{http_version}", "-o"])
        .arg(&out)
        .arg("https://nginx.stafeto.test/index.html")
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() || version != "2" {
        return Err(format!(
            "curl --http2 over TLS ended with {:?}, HTTP version {version:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let body = std::fs::read(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    same(
        "the page over HTTP/2 from the Mac",
        &body,
        rootfs::www_index(),
    )
}

/// The program part of `cargo xtask net-vz --fast --static1 --nginx`, after
/// the checks of both devices: nginx on the stack at the second address
/// `address`, started by the first request to the device (the lazy start,
/// the host's reset of the device inside it), the pages over HTTP and
/// HTTPS, `ping`, the load of `wrk -c200`, the worker killed and a new one,
/// the quit with the counters of the stack's steps.
pub fn vz_run(
    run: &mut qemu::Run,
    address: std::net::Ipv4Addr,
    ca: &std::path::Path,
    dir: &std::path::Path,
) -> Result<(), String> {
    let http: SocketAddr = (address, 80).into();
    let command_at = Instant::now();
    run.send(&format!("STAFETO_FAST_STATS=1 nginx-fast -c {CONF} & M=$!"))?;
    expect_start(
        run,
        &[
            "using the \"epoll\" event method",
            "start worker process ",
            "fast: the stack is up on ",
        ],
        START_WITHIN,
    )?;
    let lazy = command_at.elapsed();
    let first_at = Instant::now();
    first_page(http)?;
    println!(
        "net-vz: nginx-fast: the stack is up {} ms after the command (the lazy start: the claim, the host's reset of the device, the stack's init); the first page {} ms after that",
        lazy.as_millis(),
        first_at.elapsed().as_millis()
    );
    pages(http, REQUESTS, CONNECTIONS)?;
    files(http)?;
    println!(
        "net-vz: nginx-fast: {REQUESTS} requests over {CONNECTIONS} connections and the three files by SHA-256 ok"
    );
    https_page(address, ca, dir)?;
    println!("net-vz: nginx-fast: TLS 1.3 with HTTP/2 from the Mac, the page whole");
    for (count, size) in [(5u32, 56u32), (5, 1472)] {
        let result = crate::net_vz::ping(address, count, size, None)?;
        println!(
            "net-vz: ping -c {count} -s {size} of the second address: {} of {} answered",
            result.received, result.sent
        );
        if result.received != count {
            return Err(format!(
                "the second address answered {} of {count} echoes of {size} bytes",
                result.received
            ));
        }
    }
    // The worker killed: the device comes back, a new worker, a page.
    let (_, workers) = master_and_workers(run, "vz-kill", true)?;
    let at = Instant::now();
    let after_kill = run.lines().len();
    run.send(&format!("kill -9 {}", workers[0]))?;
    expect_all(
        run,
        &["net: device 1 back", "start worker process "],
        START_WITHIN,
    )?;
    first_page(http)?;
    println!(
        "net-vz: kill -9 of the worker: the device back, a new worker and a page {} ms later",
        at.elapsed().as_millis()
    );
    // The worker's memory is read while the load runs: the largest holding
    // sets the quota of the command (init's table).
    let (_, current) = master_and_workers(run, "vz-load", true)?;
    let worker = current[0];
    let mut largest = 0;
    let mut loaded = |url: String, seconds: u64| -> Result<Wrk, String> {
        let load = std::thread::spawn(move || wrk(&url, seconds));
        while !load.is_finished() {
            largest = largest.max(resident_kib(run, worker)?);
            std::thread::sleep(Duration::from_secs(2));
        }
        load.join()
            .map_err(|_| "the wrk thread panicked".to_owned())?
    };
    let tiny = loaded(format!("http://{address}/tiny.txt"), 30)?;
    let index = loaded(format!("http://{address}/10k.bin"), 10)?;
    println!(
        "net-vz: nginx-fast: the largest holding of the worker under the load was {largest} KiB ({} pages)",
        largest / 4
    );
    for (what, w) in [("/tiny.txt", &tiny), ("/10k.bin", &index)] {
        if w.connect != 0 || w.non_2xx != 0 {
            return Err(format!(
                "wrk of {what}: errors of connect or non-2xx answers: {w:?}"
            ));
        }
        println!(
            "net-vz: wrk -t2 -c200 of {what}: {:.0} requests a second, errors: connect {} read {} write {} timeout {}",
            w.requests_per_second, w.connect, w.read, w.write, w.timeout
        );
    }
    quit_send(run, "vz-quit")?;
    quit_end(run, "vz-quit")?;
    // The worker that took the load is the one started after the kill. Its
    // totals are said every 5 s of its clock; the first line inside the load
    // and the last one before the quit give the rate of the notifications and
    // of the steps.
    let stats: Vec<Stats> = run.lines()[after_kill..]
        .iter()
        .filter_map(|l| parse_stats(l))
        .collect();
    match (stats.first(), stats.last()) {
        (Some(a), Some(b)) if b.ticks > a.ticks => {
            let seconds = (b.ticks - a.ticks) as f64 / 100.0;
            println!(
                "net-vz: the stack of the worker over {seconds:.0} s of its clock (the load included): {:.0} notifications of the device a second, {:.0} steps a second, {:.0} frames in and {:.0} out a second",
                (b.notifications - a.notifications) as f64 / seconds,
                (b.passes - a.passes) as f64 / seconds,
                (b.rx - a.rx) as f64 / seconds,
                (b.tx - a.tx) as f64 / seconds,
            );
        }
        _ => {
            return Err(
                "the stack printed no counters of its steps (STAFETO_FAST_STATS)".to_owned(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wakes_bound_is_a_quarter_of_the_wakes_with_a_frame() {
        let line = "fast: wakes sleeps=1000 bell=980 deadline=15 other=5 deadline_found=10";
        let w = parse_wakes(line).unwrap();
        assert_eq!(
            w,
            Wakes {
                sleeps: 1000,
                bell: 980,
                deadline: 15,
                other: 5,
                deadline_found: 10
            }
        );
        assert!(check_wakes(&w).is_ok());
        // More than a quarter of the wakes that had a frame fails.
        let slow = Wakes {
            bell: 29,
            deadline_found: 10,
            ..w
        };
        assert!(check_wakes(&slow).is_err());
        assert!(check_wakes(&Wakes { bell: 30, ..slow }).is_ok());
        // A small number of sleeps tolerates the allowance and no more.
        let few = |found| Wakes {
            sleeps: 100,
            bell: 4,
            deadline: 0,
            other: 0,
            deadline_found: found,
        };
        assert!(check_wakes(&few(2)).is_ok());
        assert!(check_wakes(&few(3)).is_err());
        assert!(
            check_wakes(&Wakes {
                sleeps: 5,
                ..few(0)
            })
            .is_err()
        );
        assert_eq!(parse_wakes("fast: stats ticks=1"), None);
    }

    #[test]
    fn the_change_between_two_lines_is_what_the_bound_judges() {
        let a = parse_wakes("fast: wakes sleeps=500 bell=480 deadline=15 other=5 deadline_found=9")
            .unwrap();
        let b = parse_wakes("fast: wakes sleeps=560 bell=538 deadline=17 other=5 deadline_found=9")
            .unwrap();
        let d = b.since(&a);
        assert_eq!(
            (d.sleeps, d.bell, d.deadline, d.deadline_found),
            (60, 58, 2, 0)
        );
        assert!(check_wakes(&d).is_ok());
    }

    #[test]
    fn the_images_have_the_table_and_the_program() {
        for (kind, table) in [
            (Kind::Plain, "table-fast-nginx"),
            (Kind::Crash, "table-fast-nginx"),
            (Kind::Steps, "table-fast-nginx"),
            (Kind::Vz, "table-fast-nginx-vz"),
        ] {
            let list = programs(kind);
            assert_eq!(list[0].3, &[table], "{kind:?}");
            assert!(list.iter().any(|p| p.0 == "nginx-fast"), "{kind:?}");
        }
        let netd = |kind| programs(kind).iter().find(|p| p.0 == "netd").unwrap().3;
        assert_eq!(netd(Kind::Crash), &["probe"]);
        assert_eq!(netd(Kind::Steps), &["steps"]);
        assert!(netd(Kind::Plain).is_empty());
    }

    #[test]
    fn the_settings_are_those_the_scenarios_need() {
        let package = NGINX_FAST_CONF;
        assert!(package.contains("user nobody nobody;"));
        assert!(root_conf().contains("user root;"));
        assert!(switch_conf().contains("user nobody nobody;"));
        assert!(package.contains("worker_processes 1;"));
        assert!(package.contains("worker_shutdown_timeout 5s;"));
        assert!(package.contains("listen 80;"));
        assert!(!package.contains("listen 80 reuseport"));
        assert!(!package.contains("tls.conf"));
        assert!(probe_conf().contains("include /etc/nginx/tls.conf;"));
        assert!(nobody_conf().contains("user nobody nobody;"));
        assert!(!nobody_conf().contains("user root;"));
    }

    /// A line of the alerts the scenarios cause passes the verdict; any other
    /// alert does not.
    #[test]
    fn the_verdict_allows_the_alerts_of_the_scenarios_only() {
        let line = |text: &str| vec![text.to_owned()];
        assert!(verdict(&line("[alert] 1#0: worker process 5 exited on signal 9"), 0).is_ok());
        assert!(
            verdict(
                &line(
                    "[alert] 1#0: worker process 5 exited with fatal code 2 and cannot be respawned"
                ),
                0
            )
            .is_ok()
        );
        assert!(verdict(&line("[alert] 1#0: something else"), 0).is_err());
        assert!(verdict(&line("[emerg] bind() failed"), 0).is_err());
        assert!(verdict(&line("process fault: x"), 0).is_err());
        assert!(verdict(&line("process fault: x"), 1).is_ok());
    }

    #[test]
    fn the_output_of_wrk_is_read() {
        let clean = "Running 30s test @ http://x/\n  2 threads and 200 connections\nRequests/sec: 140467.53\nTransfer/sec:     40.46MB\n";
        let got = parse_wrk(clean).unwrap();
        assert_eq!(got.requests_per_second, 140467.53);
        assert_eq!(
            (got.connect, got.read, got.write, got.timeout, got.non_2xx),
            (0, 0, 0, 0, 0)
        );
        let errors = "  Socket errors: connect 3, read 4, write 5, timeout 6\n  Non-2xx or 3xx responses: 7\nRequests/sec: 12.5\n";
        let got = parse_wrk(errors).unwrap();
        assert_eq!(
            (got.connect, got.read, got.write, got.timeout, got.non_2xx),
            (3, 4, 5, 6, 7)
        );
        assert_eq!(parse_wrk("wrk: nothing"), None);
    }

    #[test]
    fn the_counters_of_the_stack_are_read() {
        let line = "/ # fast: stats ticks=500 notifications=14 kicks=34411 sleeps=0 found_work=0 passes=34692 rx=1092850 tx=546540";
        assert_eq!(
            parse_stats(line),
            Some(Stats {
                ticks: 500,
                notifications: 14,
                passes: 34692,
                rx: 1092850,
                tx: 546540
            })
        );
        assert_eq!(parse_stats("fast: the stack is up on 10.0.3.15/24"), None);
        let glue =
            std::fs::read_to_string(crate::root().join("ports/f-stack/ff_stafeto_glue.c")).unwrap();
        for field in ["ticks=", "notifications=", "passes=", "rx=", "tx="] {
            assert!(glue.contains(field), "{field}");
        }
    }

    #[test]
    fn the_lines_waited_for_are_those_of_the_programs() {
        let glue =
            std::fs::read_to_string(crate::root().join("ports/f-stack/ff_stafeto_glue.c")).unwrap();
        assert!(glue.contains("fast: the stack is up on"));
        let layer =
            std::fs::read_to_string(crate::root().join("lib/posix-abi/src/fastnet.rs")).unwrap();
        assert!(layer.contains("fast: the network service let the device go"));
    }
}
