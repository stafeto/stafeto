// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of nginx on the stack at 10 000 connections (`cargo xtask
//! fast-probe scale`, stage P6b-4b of subproject 6, spec 6, 8.9), on QEMU
//! with 1 GiB: the image of nginx on the stack with the grant of the process
//! service (`table-fast-scale`: the worker's quota is 128 MiB), the settings
//! of the stack and of nginx for many connections (`worker_connections
//! 16384`, `kern.ipc.maxsockets`, the hash of the connections), and the
//! lines of the glue `fast: start` (the limits the stack took) and `fast:
//! scale` (every 5 s: sockets, the zones of UMA, the quota and its use, the
//! heap of the layer). The client of the host holds connections through the
//! forward of port 80:
//!
//! 1. `fast: start` shows the limits of the settings;
//! 2. 100, 250 and 400 connections are open (the handshake only; the user
//!    network of QEMU gives the guest two connections a second on a machine
//!    of the check, and 100 000 are for Apple VZ). The nginx of the image
//!    holds a pool of 16 KiB per connection, so that these few fill the room
//!    of 32 MiB and the layer grows it. The worker's quota used at each
//!    stage gives the memory per connection (at most 7 KiB beyond the pool,
//!    stop point O3), and the places of the kernel's table the layer holds
//!    stay within 112 of 128 (stop point O2);
//! 3. after 30 s of holding every 20th connection takes the page;
//! 4. the worker is killed with `kill -9` three times, one more than the
//!    grant has places: each new worker has the quota of the grant, so the
//!    place came back with the zombie;
//! 5. the data limit of the shell is 31 MiB (`ulimit -S -d`): of 250
//!    connections that each ask for the page some are refused, the worker
//!    lives or ends by the bounded retry (status 1 and the line `fst malloc
//!    failed`), and once the connections close a new one gets its page.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::fast_nginx::{NGINX_FAST_CONF, TINY};
use crate::nginx_probe::replaced;
use crate::qemu::{self, Forward, Proto};
use crate::rootfs::{RootFile, Source};
use crate::{
    BOOT_PROFILE, Variant, build, build_boot_image, busybox_build, nano_build, net_probe, relibc,
};

/// When the probe began, for the budget of the whole run.
static BEGAN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Says a line at once (a run that hangs must show where) and fails when the
/// run has taken longer than its budget.
fn say(what: &str) -> Result<(), String> {
    let at = BEGAN.get_or_init(Instant::now).elapsed();
    println!("fast-scale [{} s]: {what}", at.as_secs());
    if at > RUN_WITHIN {
        return Err(format!(
            "the run took {} s, past {} s",
            at.as_secs(),
            RUN_WITHIN.as_secs()
        ));
    }
    Ok(())
}

pub const IMAGE: &str = "boot-fast-scale.img";

/// The grant's quota in the image (`SCALE_GRANTS` of init's table): 128 MiB.
const GRANT_BYTES: u64 = 32_768 * 4096;
/// The connections of the stages, the data limit of the degradation step in
/// KiB, and the places of the kernel's table the layer may hold.
const STAGES: [usize; 3] = [100, 250, 400];
const DEGRADE_KIB: u32 = 31_744;
const DEGRADE_CONNS: usize = 250;
const DEGRADE_WITHIN: Duration = Duration::from_secs(150);
const STAGE_WITHIN: Duration = Duration::from_secs(300);
/// Every this many connections of those held take the page after the hold.
const SAMPLE: usize = 20;
/// What a connection holds beyond the stack's and nginx's usual: its pool of
/// 16 KiB (`connection_pool_size`), which makes few connections fill the room
/// of 32 MiB (the user network of QEMU on a machine of the check gives the
/// guest two connections a second).
const POOL: u64 = 16 * 1024;
const PLACES_MAX: u64 = 112;
/// The memory per connection that stops the work (O3), in bytes.
const SLOPE_MAX: u64 = 7 * 1024;
const HOLD: Duration = Duration::from_secs(30);
const WAVE_WITHIN: Duration = Duration::from_secs(120);
const LINE_WITHIN: Duration = Duration::from_secs(90);
const RUN_WITHIN: Duration = Duration::from_secs(900);
const THREADS: usize = 50;
const CONF: &str = "/etc/nginx/nginx-fast.conf";
const REQUEST: &[u8] = b"GET /tiny.txt HTTP/1.1\r\nHost: scale\r\n\r\n";

/// The settings of the stack for many connections: the sockets, the files
/// and the hash of the connections of the settings in ports/f-stack with the
/// limits of 135 000 (in the range of the fast sockets), and the largest
/// buffers 1 MiB. The wheel of callouts keeps its size (the timers of TCP
/// are in the connection's own block).
fn ini() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        let text = include_str!("../../ports/f-stack/fstack.ini");
        let text = replaced(
            text,
            "memsz_MB=256\n",
            "memsz_MB=256\nkern.ipc.maxsockets=135000\nkern.maxfiles=140000\nnet.inet.tcp.tcbhashsize=65536\nnet.inet.tcp.syncache.hashsize=1024\nnet.inet.tcp.syncache.bucketlimit=30\nkern.ipc.nmbclusters=65536\nkern.ncallout=18508\n",
        );
        let text = replaced(&text, "maxfilesperproc=262144", "maxfilesperproc=135000");
        let text = replaced(&text, "sendbuf_max=16777216", "sendbuf_max=1048576");
        replaced(&text, "recvbuf_max=16777216", "recvbuf_max=1048576")
    })
}

/// The settings of nginx: one worker with 16 384 connections that keep alive
/// for an hour, and the variable of the glue's lines.
fn conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        let text = replaced(
            NGINX_FAST_CONF,
            "worker_shutdown_timeout 5s;\n",
            "worker_shutdown_timeout 5s;\nenv STAFETO_FAST_STATS;\n",
        );
        let text = replaced(&text, "worker_connections 1024", "worker_connections 16384");
        let text = replaced(
            &text,
            "keepalive_timeout 65;",
            "keepalive_timeout 3600;\n    client_header_timeout 3600s;\n    connection_pool_size 16k;\n    large_client_header_buffers 4 16k;",
        );
        let text = replaced(
            &text,
            "keepalive_requests 100000;",
            "keepalive_requests 1000000;",
        );
        replaced(&text, "listen 80;", "listen 80 backlog=4096;")
    })
}

/// The files of the image of scale: those of the image of nginx on the
/// stack with the settings of the stack and of nginx above in the place of
/// the packages'.
pub fn files(mut files: Vec<RootFile>) -> Vec<RootFile> {
    for (path, name, bytes) in [
        (CONF, "nginx-fast-scale.conf", conf()),
        ("/etc/fstack.ini", "fstack-scale.ini", ini()),
    ] {
        let file = files
            .iter_mut()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("{IMAGE}: no {path}"));
        file.source = Some(Source::Bytes(name, bytes.as_bytes()));
    }
    files
}

pub fn command(args: &[String]) -> Result<(), String> {
    match args {
        [] => probe(&qemu::VIRT_1G),
        _ => Err("usage: cargo xtask fast-probe scale".to_owned()),
    }
}

/// The number after ` key=` in a line of the glue.
fn field(line: &str, key: &str) -> Option<u64> {
    let rest = line.split(&format!(" {key}=")).nth(1)?;
    rest.split([' ', '/']).next()?.parse().ok()
}

/// The raising of the open files of this process and the children: QEMU
/// holds a socket for each connection of the client.
fn raise_files() {
    #[repr(C)]
    struct Limit {
        soft: u64,
        hard: u64,
    }
    unsafe extern "C" {
        fn getrlimit(resource: i32, limit: *mut Limit) -> i32;
        fn setrlimit(resource: i32, limit: *const Limit) -> i32;
    }
    let resource = if cfg!(target_os = "macos") { 8 } else { 7 };
    let mut limit = Limit { soft: 0, hard: 0 };
    // SAFETY: plain calls with a structure of the C library's layout.
    unsafe {
        if getrlimit(resource, &mut limit) == 0 {
            limit.soft = limit.hard.min(65_536);
            setrlimit(resource, &limit);
        }
    }
}

/// `more` new connections, one at a time: the forward of the machine listens
/// with a queue of one, and a connection that finds it full waits for the
/// next try of its SYN. The forward accepts a connection long before the
/// guest does (the user network of QEMU gives the guest about 30 a second).
fn open_more(address: SocketAddr, held: &mut Vec<TcpStream>, more: usize) -> Result<(), String> {
    for i in 0..more {
        if i % 200 == 0 {
            say(&format!("{} connections held", held.len()))?;
        }
        let s = TcpStream::connect_timeout(&address, Duration::from_secs(20))
            .map_err(|e| format!("{i} of {more} connections opened ({e})"))?;
        held.push(s);
    }
    Ok(())
}

/// One request on every `every`-th connection of `held`: how many of those
/// answered the page whole before `within`. A connection that did not is
/// dropped.
fn ask_some(held: &mut Vec<TcpStream>, every: usize, within: Duration) -> usize {
    let deadline = Instant::now() + within;
    let mut kept: Vec<bool> = vec![true; held.len()];
    let mut asked = held.len().div_ceil(every);
    let mut pairs: Vec<(&mut TcpStream, &mut bool)> = held
        .iter_mut()
        .zip(kept.iter_mut())
        .step_by(every)
        .collect();
    let per = pairs.len().div_ceil(THREADS).max(1);
    std::thread::scope(|scope| {
        for chunk in pairs.chunks_mut(per) {
            scope.spawn(move || ask(chunk, deadline));
        }
    });
    let mut at = 0;
    held.retain(|_| {
        at += 1;
        kept[at - 1]
    });
    asked -= kept.iter().step_by(every).filter(|k| !**k).count();
    asked
}

/// Sends the request on each stream and reads the answers until they are
/// whole or `deadline`; the flag of a stream that did not answer is false.
fn ask(pairs: &mut [(&mut TcpStream, &mut bool)], deadline: Instant) {
    let mut seen: Vec<Vec<u8>> = vec![Vec::new(); pairs.len()];
    let mut done = vec![false; pairs.len()];
    for (i, (s, kept)) in pairs.iter_mut().enumerate() {
        let sent = s.set_nonblocking(true).is_ok() && s.write_all(REQUEST).is_ok();
        done[i] = !sent;
        **kept = sent;
    }
    while Instant::now() < deadline && done.iter().any(|d| !d) {
        let mut buf = [0u8; 512];
        for (i, (s, kept)) in pairs.iter_mut().enumerate() {
            if done[i] {
                continue;
            }
            match s.read(&mut buf) {
                Ok(0) => (done[i], **kept) = (true, false),
                Ok(n) => {
                    seen[i].extend_from_slice(&buf[..n]);
                    if let Some(end) = seen[i].windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&seen[i][..end]).to_string();
                        if seen[i].len() >= end + 4 + TINY.len() {
                            done[i] = true;
                            **kept = head.starts_with("HTTP/1.1 200")
                                && seen[i][end + 4..] == *TINY
                                && head.contains(&format!("Content-Length: {}", TINY.len()));
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => (done[i], **kept) = (true, false),
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    for (i, (_, kept)) in pairs.iter_mut().enumerate() {
        **kept &= done[i];
    }
}

/// A line of `fast: scale` of the worker as it is after the marker `tag`
/// and with at least `sockets` open.
fn scale_line(run: &mut qemu::Run, tag: &str, sockets: u64) -> Result<String, String> {
    crate::nginx_probe::marker(run, tag, Duration::from_secs(30))?;
    let end = Instant::now() + STAGE_WITHIN;
    loop {
        say(&format!("waiting for {sockets} sockets ({tag})"))?;
        let line = run.expect_line(
            "fast: scale",
            |l| l.contains("fast: scale "),
            end.saturating_duration_since(Instant::now())
                .max(Duration::from_secs(1)),
        )?;
        if field(&line, "sockets").unwrap_or(0) >= sockets {
            return Ok(line);
        }
    }
}

fn start_nginx(run: &mut qemu::Run) -> Result<String, String> {
    crate::fast_nginx::started(run, CONF)?;
    run.expect_line("fast: start", |l| l.contains("fast: start "), LINE_WITHIN)
}

pub fn probe(machine: &'static qemu::Machine) -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    raise_files();
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        IMAGE,
        crate::fast_nginx::programs(crate::fast_nginx::Kind::Scale),
        BOOT_PROFILE,
    )?;
    let port = crate::net_curl::free_tcp_port()?;
    let address: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    cmd.args(qemu::net_two_with(&[Forward {
        proto: Proto::Tcp,
        host: port,
        guest: 80,
    }]));
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    BEGAN.get_or_init(Instant::now);
    let began = Instant::now();
    let mut notes: Vec<String> = Vec::new();
    let talked = scenario(&mut run, address, &mut notes);
    let output = run.stop();
    crate::symbolize::backtrace(&output.lines, &kernel.elf);
    for note in &notes {
        println!("fast-scale: {note}");
    }
    talked?;
    // The refused connections of the last step make nginx say so, in
    // `accept4` or when its own pool finds no memory.
    let lines: Vec<String> = (output.lines.iter())
        .filter(|l| {
            !l.contains("accept4() failed")
                && !l.contains("posix_memalign(")
                && !l.contains("malloc() failed")
        })
        .cloned()
        .collect();
    crate::fast_nginx::verdict(&lines, 0)?;
    net_probe::placing_fault(&output.lines)?;
    if began.elapsed() > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s",
            began.elapsed().as_secs_f64()
        ));
    }
    println!(
        "fast-scale passed in {:.0} s",
        began.elapsed().as_secs_f64()
    );
    Ok(())
}

fn scenario(
    run: &mut qemu::Run,
    address: SocketAddr,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    crate::fast_nginx::booted(run)?;
    run.send("export STAFETO_FAST_STATS=1")?;
    let start = start_nginx(run)?;
    for (key, want) in [
        ("kern.ipc.maxsockets", 135_000),
        ("kern.maxfiles", 140_000),
        ("kern.maxfilesperproc", 135_000),
        ("net.inet.tcp.tcbhashsize", 65_536),
        ("kern.ncallout", 18_508),
    ] {
        if field(&start, key) != Some(want) {
            return Err(format!("the stack took {key} other than {want}: {start}"));
        }
    }
    notes.push(start.split("fast: ").nth(1).unwrap_or("").to_owned());
    // 1 and 2: the connections open, each one handshake for the stack.
    let mut held: Vec<TcpStream> = Vec::new();
    let mut used = Vec::new();
    let mut taken = Vec::new();
    let mut taken_room = 0;
    for (i, target) in STAGES.iter().enumerate() {
        let more = target - held.len();
        let began = Instant::now();
        open_more(address, &mut held, more)?;
        let line = scale_line(run, &format!("stage{i}"), *target as u64 + 1)?;
        let places = field(&line, "places").unwrap_or(999) + field(&line, "hidden").unwrap_or(0);
        let quota = field(&line, "quota").unwrap_or(0);
        if places > PLACES_MAX || quota != GRANT_BYTES {
            return Err(format!(
                "{places} places of the table (at most {PLACES_MAX}), quota {quota}: {line}"
            ));
        }
        used.push(field(&line, "used").unwrap_or(0));
        taken.push(field(&line, "user").unwrap_or(0));
        taken_room = field(&line, "room").unwrap_or(0);
        notes.push(format!(
            "{target} connections after {} s: {}",
            began.elapsed().as_secs(),
            line.split("fast: ").nth(1).unwrap_or("")
        ));
    }
    let top = *used.last().unwrap_or(&0);
    // The pages taken from the heap's chunks, not the chunks (a chunk of
    // several MiB comes at once): 4 KiB for each page.
    let slope = (taken[2].saturating_sub(taken[0])) * 4096 / (STAGES[2] - STAGES[0]) as u64;
    notes.push(format!(
        "the quota used per connection: {slope} bytes, {} beyond the pool (at most {SLOPE_MAX}); {top} bytes used at the top, the room grew to {taken_room} pages", slope.saturating_sub(POOL)
    ));
    let room = taken_room;
    if slope < POOL || slope - POOL > SLOPE_MAX || room != 262_144 {
        return Err(format!(
            "{slope} bytes per connection (pool {POOL}), room {room} pages"
        ));
    }
    // 3: after the hold every 20th connection takes the page.
    std::thread::sleep(HOLD);
    let asked = held.len().div_ceil(SAMPLE);
    let answered = ask_some(&mut held, SAMPLE, WAVE_WITHIN);
    if answered != asked {
        return Err(format!(
            "{answered} of {asked} connections answered after the hold"
        ));
    }
    notes.push(format!(
        "{asked} of the {} connections took the page after {} s",
        STAGES[2],
        HOLD.as_secs()
    ));
    drop(held);
    // 4.
    for round in 0..3 {
        let (_, workers) = crate::fast_nginx::master_and_workers(run, &format!("k{round}"), true)?;
        run.send(&format!("kill -9 {}", workers[0]))?;
        crate::fast_probe::expect_all(
            run,
            &["net: device 1 back", "start worker process "],
            LINE_WITHIN,
        )?;
        let line = scale_line(run, &format!("kill{round}"), 1)?;
        if field(&line, "quota") != Some(GRANT_BYTES) {
            return Err(format!(
                "worker {} after the kill has no grant: {line}",
                round + 2
            ));
        }
    }
    notes.push("the worker killed 3 times: each new one has the quota of the grant".to_owned());
    // 5.
    crate::fast_nginx::quit(run, "quit")?;
    run.send(&format!("ulimit -S -d {DEGRADE_KIB} && echo limit-\"set\""))?;
    run.expect_line(
        "limit-set",
        |l| l.trim_end().ends_with("limit-set"),
        LINE_WITHIN,
    )?;
    start_nginx(run)?;
    let mut held: Vec<TcpStream> = Vec::new();
    open_more(address, &mut held, DEGRADE_CONNS)?;
    let ok = ask_some(&mut held, 1, DEGRADE_WITHIN);
    notes.push(format!(
        "5: {ok} of {DEGRADE_CONNS} connections answered under a data limit of {DEGRADE_KIB} KiB"
    ));
    if ok == 0 || ok >= DEGRADE_CONNS {
        return Err(format!(
            "{ok} connections answered under the limit: some must be refused"
        ));
    }
    // At the limit a request of the stack that may not fail (a malloc of 4 KiB)
    // is retried a bounded number of times and then ends the worker with
    // status 1 and a line, and the main process starts another: no hang.
    let ended = run.lines().iter().any(|l| l.contains("exited with code 1"));
    let said = run.lines().iter().any(|l| l.contains("fst malloc failed"));
    if ended != said {
        return Err(
            "a worker ended with code 1 without the line of the stack, or the reverse".to_owned(),
        );
    }
    notes.push(format!(
        "5: the worker {} at the limit",
        if ended {
            "ended with status 1 (bounded retry) and was started again"
        } else {
            "lived"
        }
    ));
    drop(held);
    std::thread::sleep(Duration::from_secs(10));
    crate::nginx_probe::first_page(address)?;
    notes.push("5: after the connections closed a new one got its page".to_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_numbers_of_a_line_of_the_glue_are_read() {
        let line = "fast: scale sockets=10007 socket=864/10003/190 quota=134217728 used=70000000 places=40 hidden=8";
        assert_eq!(field(line, "sockets"), Some(10_007));
        assert_eq!(field(line, "socket"), Some(864));
        assert_eq!(field(line, "quota"), Some(GRANT_BYTES));
        assert_eq!(field(line, "places"), Some(40));
        assert_eq!(field(line, "room"), None);
    }

    #[test]
    fn the_settings_of_the_image_carry_the_limits_the_probe_checks() {
        for line in [
            "kern.ipc.maxsockets=135000",
            "kern.maxfiles=140000",
            "kern.maxfilesperproc=135000",
            "net.inet.tcp.tcbhashsize=65536",
        ] {
            assert_eq!(ini().matches(line).count(), 1, "{line}");
        }
        assert!(!ini().contains("262144\nnet"));
        assert!(conf().contains("worker_connections 16384"));
        assert!(conf().contains("env STAFETO_FAST_STATS;"));
    }

    #[test]
    fn the_image_replaces_the_settings_of_the_packages_and_no_other_file() {
        let held = crate::rootfs::files_of(IMAGE);
        let plain = crate::rootfs::files_of("boot-fast-nginx.img");
        assert_eq!(held.len(), plain.len());
        let mut differ: Vec<&str> = held
            .iter()
            .zip(&plain)
            .filter(|(a, b)| a.source != b.source)
            .map(|(a, _)| a.path)
            .collect();
        differ.sort_unstable();
        assert_eq!(differ, ["/etc/fstack.ini", "/etc/nginx/nginx-fast.conf"]);
    }
}
