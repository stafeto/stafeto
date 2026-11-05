// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of nginx on the shared sockets of the network service
//! (`cargo xtask nginx-probe`, its own job of ci): the image of the shell with
//! the network service and nginx (`boot-nginx-probe.img`) on QEMU's user
//! network, a port of the host forwarded to the port 80 of the guest. xtask
//! drives `ash` over the serial port and talks to nginx as a client of the
//! host:
//!
//! 1. `nginx -c /etc/nginx/nginx.conf &`: the console shows `using the
//!    "epoll" event method` and four `start worker process` lines.
//! 2. Five processes `nginx`; the four workers have the user ID 65534
//!    (`nobody`) in `/proc/<pid>/status`, the master 0.
//! 3. 200 requests HTTP/1.1 `GET /index.html` over 16 connections that stay
//!    open (12 or 13 each), every body the page of the image.
//! 4. `posix-net stat` before and after five `GET /256k.bin`, each checked by
//!    its SHA-256: the network service's counter of the shared buffers grew
//!    by 5 x 256 KiB at least (the answers went through the buffer). Five
//!    `GET /10k.bin` by their SHA-256.
//! 5. `kill -HUP` of the master: `reconfiguring`; meanwhile a new connection
//!    every 50 ms asks for the page, and none fails; 5 s later five
//!    processes `nginx`, the four workers new, each holding a shared buffer
//!    (`posix-net stat`), and an answer of 256 KiB goes through them.
//! 6. `kill -QUIT` of the master: it ends within 10 s.
//! 7. `nginx -c /etc/nginx/exclusive.conf &` (one listening socket for the
//!    four workers, EPOLLEXCLUSIVE), 40 requests over 8 connections,
//!    `kill -QUIT`.
//!
//! No line `[alert]`, `[emerg]` or `[crit]` in the whole run: they would
//! show nginx's self-check of EPOLLRDHUP timing out or a worker not spawned.
//! The settings are those of the package with 256 connections a worker and
//! keep-alive of 10 s; `netd.conf` gives eight buffers.
//!
//! `cargo xtask nginx-probe steps` runs the same with the service counting its
//! steps (`netd` built with the feature `steps`, under -icount with the guest
//! sleeping in real time), and judges every step against 0.9 of term B.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::qemu::{Forward, Proto};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, ImageProgram, SERVICES_STARTED, Variant, build,
    build_boot_image, net, packages, qemu, rootfs, symbolize, target_dir,
};

/// The images of the probe and of its run with the counted steps.
pub const IMAGE: &str = "boot-nginx-probe.img";
pub const STEPS_IMAGE: &str = "boot-nginx-probe-steps.img";

/// nginx's settings of the package (tools/nginx/nginx.conf).
pub const NGINX_CONF: &str = include_str!("../../tools/nginx/nginx.conf");
/// `/etc/netd.conf` of the probe: DHCP, and eight sessions with a shared
/// buffer: in a reload the four new workers ask for theirs while the four
/// old ones still hold theirs, and a refused buffer stays refused until
/// `exec`.
pub const NETD_CONF: &[u8] = b"buffers 8\n";

/// nginx's licence and PCRE2's in an image, and the notes of their sources.
const NGINX_LICENSE: &str = "NGINX-LICENSE";
const NGINX_SOURCE: &str = "NGINX-SOURCE";
const PCRE2_LICENCE: &str = "PCRE2-LICENCE";
const PCRE2_SOURCE: &str = "PCRE2-SOURCE";

/// The lengths of the files the probe fetches besides the page.
pub const WWW_10K_LEN: usize = 10 * 1024;
pub const WWW_256K_LEN: usize = 256 * 1024;

/// The requests of step 3 and the connections they share; those of step 7.
const REQUESTS: usize = 200;
const CONNECTIONS: usize = 16;
const EXCLUSIVE_REQUESTS: usize = 40;
const EXCLUSIVE_CONNECTIONS: usize = 8;
/// The large and the small files fetched in step 4.
const LARGE_FETCHES: usize = 5;
const SMALL_FETCHES: usize = 5;
/// The workers of the settings.
const WORKERS: usize = 4;
/// How long a request may take to be answered whole.
const READ_WITHIN: Duration = Duration::from_secs(30);
/// How long the first request waits for nginx to listen.
const LISTEN_WITHIN: Duration = Duration::from_secs(30);
/// How long nginx may take to start its workers, and the master to end.
const START_WITHIN: Duration = Duration::from_secs(30);
const QUIT_WITHIN: Duration = Duration::from_secs(10);
/// The gap between the connections of the reload, and how long after
/// `reconfiguring` the probe keeps asking before it counts the processes.
const RELOAD_GAP: Duration = Duration::from_millis(50);
const RELOAD_FOR: Duration = Duration::from_secs(5);
/// The whole run on TCG without -icount.
const RUN_WITHIN: Duration = Duration::from_secs(240);
/// The kinds of the network service's steps (the methods of proto/net,
/// 65 its own work) that nginx's traffic must show: own work, ACCEPT, SEND,
/// RECV, CLONE (a fork), BUFFER, EPOLL_SET and EPOLL_WAIT.
const STEP_KINDS: [(usize, &str); 8] = [
    (65, "the own steps"),
    (6, "Accept"),
    (8, "Send"),
    (10, "Recv"),
    (19, "Clone"),
    (BUFFER_KIND, "Buffer"),
    (22, "EpollSet"),
    (33, "EpollWait"),
];
/// The method BUFFER of the network service (proto/net), as a kind of step.
const BUFFER_KIND: usize = 25;
/// CLONE and CLONE_MORE, which copy a session's sockets in portions.
const CLONE_KINDS: [usize; 2] = [19, 20];

/// The probe's settings: the package's with 256 connections a worker and
/// keep-alive of 10 s.
pub fn probe_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        replaced(
            &replaced(
                NGINX_CONF,
                "worker_connections 512;",
                "worker_connections 256;",
            ),
            "keepalive_timeout 65;",
            "keepalive_timeout 10;",
        )
    })
}

/// The probe's settings with one listening socket that the four workers
/// share: nginx sets EPOLLEXCLUSIVE on it.
pub fn exclusive_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| replaced(probe_conf(), "listen 80 reuseport;", "listen 80;"))
}

/// `text` with the one `from` made `to`.
fn replaced(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from} in nginx's settings");
    text.replace(from, to)
}

/// `len` bytes from a fixed generator seeded with `seed`: the host knows the
/// files without reading the image.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// The bytes of `/www/10k.bin` and `/www/256k.bin`.
pub fn www_10k() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| noise(0x6a09_e667_f3bc_c908, WWW_10K_LEN))
}

/// `/www/256k.bin` is the file of the images with the network that the probe
/// of TLS fetches too.
pub fn www_256k() -> &'static [u8] {
    crate::net_tls::big_file()
}

/// The directory of nginx's source as tools/build-nginx.py unpacked it.
fn nginx_source() -> Result<std::path::PathBuf, String> {
    let version = packages::value("nginx", "version")?;
    Ok(target_dir().join(format!("nginx/nginx-{version}")))
}

/// `conf/mime.types` of nginx's source, read once in a run of xtask. Where
/// the script has not run (the check of the descriptions needs the paths of
/// an image only) it is empty, and the build of an image with nginx refuses
/// it so (`terms_files`).
pub fn mime_types() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| {
        nginx_source()
            .and_then(|dir| std::fs::read(dir.join("conf/mime.types")).map_err(|e| e.to_string()))
            .unwrap_or_default()
    })
}

/// The files of the terms of nginx and PCRE2 for an image whose programs
/// include nginx: the names and the bytes, to go in the image's list.
pub fn terms_files() -> Result<[(&'static str, Vec<u8>); 4], String> {
    if mime_types().is_empty() {
        return Err("nginx's mime.types is missing: run tools/build-nginx.py".to_owned());
    }
    let nginx = packages::value("nginx", "version")?;
    let nginx_url = packages::value("nginx", "url")?;
    let nginx_sha256 = packages::value("nginx", "sha256")?;
    let pcre2 = packages::value("pcre2", "version")?;
    let pcre2_url = packages::value("pcre2", "url")?;
    let pcre2_sha256 = packages::value("pcre2", "sha256")?;
    let read = |path: std::path::PathBuf| {
        std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let nginx_licence = read(nginx_source()?.join("LICENSE"))?;
    let pcre2_licence = read(target_dir().join(format!("nginx/pcre2-{pcre2}/LICENCE.md")))?;
    let relibc = crate::script_value("tools/build-relibc.py", "COMMIT")?;
    let commit = crate::rtbench2::commit();
    let nginx_note = format!(
        "/bin/nginx is nginx {nginx}, Copyright (C) Igor Sysoev and Nginx, Inc.\n\
         Licensed under the BSD 2-clause licence (NGINX-LICENSE).\n\n\
         Its source: {nginx_url}\n\
         (SHA-256 {nginx_sha256}), built by tools/build-nginx.py of\n\
         https://github.com/stafeto/stafeto at commit {commit}: configure's\n\
         run-probes answered by tools/nginx/autotest-answer.py through\n\
         tools/nginx/cross-autotest.patch (auto/feature, auto/types/sizeof,\n\
         auto/endianness); no other file of nginx changed. /etc/nginx/mime.types\n\
         is the conf/mime.types of the source. Linked with PCRE2 {pcre2}\n\
         (PCRE2-SOURCE) and relibc https://github.com/stafeto/relibc at commit\n\
         {relibc} (THIRD-PARTY-NOTICES).\n"
    );
    let pcre2_note = format!(
        "/bin/nginx holds PCRE2 {pcre2}, the 8-bit library without JIT,\n\
         Copyright (c) University of Cambridge and the PCRE2 contributors.\n\
         Licensed under the BSD 3-clause licence with the PCRE2 exception\n\
         (PCRE2-LICENCE, the LICENCE.md of the release).\n\n\
         Its source: {pcre2_url}\n\
         (SHA-256 {pcre2_sha256}), built unchanged by nginx's Makefile\n\
         from tools/build-nginx.py.\n"
    );
    Ok([
        (NGINX_LICENSE, nginx_licence),
        (NGINX_SOURCE, nginx_note.into_bytes()),
        (PCRE2_LICENCE, pcre2_licence),
        (PCRE2_SOURCE, pcre2_note.into_bytes()),
    ])
}

/// The programs of the probe's image: those of the shell with the network
/// and nginx.
pub fn programs() -> &'static [ImageProgram] {
    net::programs()
}

/// The programs of the image of the run with the counted steps: the network
/// service prints its longest steps.
pub fn steps_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = programs().to_vec();
        for program in &mut programs {
            if program.0 == "netd" {
                program.3 = &["steps"];
            }
        }
        programs
    })
}

/// SHA-256 (FIPS 180-4) of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in message.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A connection that stays open for several requests of HTTP/1.1.
struct Connection {
    stream: TcpStream,
    /// Bytes read past the last answer.
    rest: Vec<u8>,
}

impl Connection {
    fn open(address: SocketAddr, within: Duration) -> Result<Connection, String> {
        let stream =
            TcpStream::connect_timeout(&address, within).map_err(|e| format!("connect: {e}"))?;
        stream
            .set_read_timeout(Some(within))
            .and_then(|()| stream.set_write_timeout(Some(within)))
            .and_then(|()| stream.set_nodelay(true))
            .map_err(|e| format!("socket options: {e}"))?;
        Ok(Connection {
            stream,
            rest: Vec::new(),
        })
    }

    /// One GET of `path`: the body of a 200 whose length the header gives.
    fn get(&mut self, path: &str) -> Result<Vec<u8>, String> {
        self.stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: nginx-probe\r\n\r\n"
                )
                .as_bytes(),
            )
            .map_err(|e| format!("request: {e}"))?;
        let end = loop {
            if let Some(at) = self.rest.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            self.fill()?;
        };
        let head = String::from_utf8_lossy(&self.rest[..end]).into_owned();
        let status = head.lines().next().unwrap_or("");
        if !status.starts_with("HTTP/1.1 200 ") {
            return Err(format!("status line {status:?}"));
        }
        let length = content_length(&head).ok_or_else(|| format!("no length in {head:?}"))?;
        self.rest.drain(..end + 4);
        while self.rest.len() < length {
            self.fill()?;
        }
        let body: Vec<u8> = self.rest.drain(..length).collect();
        Ok(body)
    }

    fn fill(&mut self) -> Result<(), String> {
        let mut chunk = [0u8; 16 * 1024];
        match self.stream.read(&mut chunk) {
            Ok(0) => Err(format!(
                "the connection closed with {} bytes pending",
                self.rest.len()
            )),
            Ok(n) => {
                self.rest.extend_from_slice(&chunk[..n]);
                Ok(())
            }
            Err(e) => Err(format!("read after {} bytes: {e}", self.rest.len())),
        }
    }
}

/// The value of `Content-Length` in the head of an answer.
fn content_length(head: &str) -> Option<usize> {
    head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })
}

/// Fails unless `body` is `want`, by SHA-256; names the first difference.
fn same(what: &str, body: &[u8], want: &[u8]) -> Result<(), String> {
    if sha256(body) == sha256(want) {
        return Ok(());
    }
    let first = body.iter().zip(want).position(|(a, b)| a != b);
    Err(format!(
        "{what}: {} bytes with SHA-256 {}, wanted {} bytes with {}; the first difference at {first:?}",
        body.len(),
        hex(&sha256(body)),
        want.len(),
        hex(&sha256(want))
    ))
}

/// `requests` GETs of the page over `connections` connections at once,
/// each connection open for its share; every body is the page. The
/// connections are made one after another: slirp listens on the forwarded
/// port of the host with a backlog of one, and macOS gives up a connection
/// whose SYN found that queue full after 7.8 s (sixteen connects at once to
/// a listener of backlog 1 that accepts every 0.5 s lose nine of them on
/// the host alone).
fn pages(address: SocketAddr, requests: usize, connections: usize) -> Result<(), String> {
    let mut open = Vec::new();
    for n in 0..connections {
        open.push(
            Connection::open(address, READ_WITHIN)
                .map_err(|e| format!("connection {} of {connections}: {e}", n + 1))?,
        );
    }
    let started = Instant::now();
    let threads: Vec<_> = open
        .into_iter()
        .enumerate()
        .map(|(n, mut connection)| {
            let share = requests / connections + usize::from(n < requests % connections);
            std::thread::spawn(move || -> Result<(), String> {
                for k in 0..share {
                    let body = connection
                        .get("/index.html")
                        .map_err(|e| format!("request {} of {share}: {e}", k + 1))?;
                    same("the page", &body, rootfs::www_index())?;
                }
                Ok(())
            })
        })
        .collect();
    // Every connection's end, so that a failure names all that failed and
    // when.
    let mut failed = Vec::new();
    for (n, thread) in threads.into_iter().enumerate() {
        let result = thread
            .join()
            .map_err(|_| "a request thread panicked".to_owned())?;
        if let Err(why) = result {
            failed.push(format!(
                "connection {} of {connections} ({} ms): {why}",
                n + 1,
                started.elapsed().as_millis()
            ));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// The first request, which waits for nginx to listen: a SYN that comes
/// before a worker listens is answered by a reset that slirp turns into a
/// closed connection.
fn first_page(address: SocketAddr) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let answer = Connection::open(address, Duration::from_secs(2))
            .and_then(|mut c| c.get("/index.html"));
        match answer {
            Ok(body) => return same("the first page", &body, rootfs::www_index()),
            Err(_) if started.elapsed() < LISTEN_WITHIN => {
                std::thread::sleep(Duration::from_millis(300))
            }
            Err(why) => return Err(format!("the first request: {why}")),
        }
    }
}

/// What a line of the console says after the probe's marker: the shell
/// prints `ngx-TAG-end` for `echo ngx-"TAG"-end`, which the echo of the
/// typed command does not hold.
fn marker(run: &mut qemu::Run, tag: &str, within: Duration) -> Result<(), String> {
    run.send(&format!("echo ngx-\"{tag}\"-end"))?;
    let want = format!("ngx-{tag}-end");
    run.expect_line(&want.clone(), |l| l.trim_end().ends_with(&want), within)?;
    Ok(())
}

/// The processes of the guest whose name holds `nginx`: (PID, user ID).
fn nginx_processes(run: &mut qemu::Run, tag: &str) -> Result<Vec<(u32, u32)>, String> {
    let from = run.lines().len();
    run.send("grep -E '^(Name|Uid):' /proc/[0-9]*/status")?;
    marker(run, tag, DIALOG_STEP)?;
    Ok(processes_of(&run.lines()[from..]))
}

/// The nginx processes in the lines `/proc/PID/status:Name:\tNAME` and
/// `/proc/PID/status:Uid:\tREAL ...` of `grep`.
fn processes_of(lines: &[String]) -> Vec<(u32, u32)> {
    let mut names: Vec<(u32, String)> = Vec::new();
    let mut users: Vec<(u32, u32)> = Vec::new();
    for line in lines {
        let Some(rest) = line.split("/proc/").nth(1) else {
            continue;
        };
        let Some((pid, rest)) = rest.split_once("/status:") else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        if let Some(name) = rest.strip_prefix("Name:") {
            names.push((pid, name.trim().to_owned()));
        } else if let Some(ids) = rest.strip_prefix("Uid:")
            && let Some(Ok(uid)) = ids.split_whitespace().next().map(str::parse::<u32>)
        {
            users.push((pid, uid));
        }
    }
    let mut out: Vec<(u32, u32)> = names
        .iter()
        .filter(|(_, name)| name.contains("nginx"))
        .filter_map(|(pid, _)| users.iter().find(|(p, _)| p == pid).copied())
        .collect();
    out.sort_unstable();
    out
}

/// The master (user 0) and the workers (user 65534) of `processes`, or why
/// they are not one master and four workers.
fn master_and_workers(processes: &[(u32, u32)]) -> Result<(u32, Vec<u32>), String> {
    let masters: Vec<u32> = processes.iter().filter(|p| p.1 == 0).map(|p| p.0).collect();
    let workers: Vec<u32> = processes
        .iter()
        .filter(|p| p.1 == 65534)
        .map(|p| p.0)
        .collect();
    if processes.len() != WORKERS + 1 || masters.len() != 1 || workers.len() != WORKERS {
        return Err(format!(
            "the nginx processes (PID, user ID) are {processes:?}: wanted a master of user 0 and {WORKERS} workers of user 65534"
        ));
    }
    Ok((masters[0], workers))
}

/// Waits for `count` more lines of nginx that hold `what`.
fn lines_of(run: &mut qemu::Run, what: &str, count: usize, within: Duration) -> Result<(), String> {
    for _ in 0..count {
        run.expect_line(what, |l| l.contains(what), within)?;
    }
    Ok(())
}

/// `nginx -c SETTINGS &`, with its PID in the shell's `M`: the event method
/// and the four workers on the console.
fn start(run: &mut qemu::Run, settings: &str) -> Result<(), String> {
    run.send(&format!("nginx -c {settings} & M=$!"))?;
    run.expect_line(
        "the event method",
        |l| l.contains("using the \"epoll\" event method"),
        START_WITHIN,
    )?;
    lines_of(run, "start worker process ", WORKERS, START_WITHIN)
}

/// `kill -QUIT` of the master and the wait for it: within `QUIT_WITHIN`.
fn quit(run: &mut qemu::Run, tag: &str) -> Result<(), String> {
    let started = Instant::now();
    run.send("kill -QUIT $M; wait $M")?;
    marker(run, tag, QUIT_WITHIN)?;
    let took = started.elapsed();
    if took > QUIT_WITHIN {
        return Err(format!("the master took {} ms to end", took.as_millis()));
    }
    println!(
        "nginx-probe: SIGQUIT ended nginx in {} ms",
        took.as_millis()
    );
    Ok(())
}

/// The counter of the shared buffers of the network service in KiB, from
/// `posix-net stat`: `posix-net: buffers N limit L buffered K KiB`.
fn buffered(run: &mut qemu::Run) -> Result<(u32, u64), String> {
    run.send("posix-net stat")?;
    let line = run.expect_line(
        "posix-net stat",
        |l| l.contains("posix-net: buffers ") && l.contains(" buffered "),
        DIALOG_STEP,
    )?;
    stat_numbers(&line).ok_or_else(|| format!("the line {line:?}"))
}

/// (sessions with a buffer, KiB through the buffers) of the line of
/// `posix-net stat`.
fn stat_numbers(line: &str) -> Option<(u32, u64)> {
    let rest = line.split("posix-net: buffers ").nth(1)?;
    let mut words = rest.split_whitespace();
    let sessions = words.next()?.parse().ok()?;
    let kib = rest
        .split(" buffered ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((sessions, kib))
}

/// Step 4: five answers of 256 KiB through the shared buffers, five of 10 KiB.
fn large_files(run: &mut qemu::Run, address: SocketAddr) -> Result<(), String> {
    let (_, before) = buffered(run)?;
    let mut fetched = Vec::new();
    for n in 0..LARGE_FETCHES {
        let mut connection = Connection::open(address, READ_WITHIN)
            .map_err(|e| format!("GET /256k.bin {}: {e}", n + 1))?;
        let at = Instant::now();
        let body = connection
            .get("/256k.bin")
            .map_err(|e| format!("GET /256k.bin {}: {e}", n + 1))?;
        fetched.push(at.elapsed());
        same(&format!("GET /256k.bin {}", n + 1), &body, www_256k())?;
    }
    let (sessions, after) = buffered(run)?;
    let answer = fetched.iter().sum::<Duration>() / LARGE_FETCHES as u32;
    let grown = after.wrapping_sub(before);
    let wanted = (LARGE_FETCHES * WWW_256K_LEN / 1024) as u64;
    if grown < wanted {
        return Err(format!(
            "the shared buffers carried {grown} KiB for {LARGE_FETCHES} answers of 256 KiB (wanted {wanted} at least): the answers did not go through them"
        ));
    }
    for n in 0..SMALL_FETCHES {
        let body = Connection::open(address, READ_WITHIN)
            .and_then(|mut c| c.get("/10k.bin"))
            .map_err(|e| format!("GET /10k.bin {}: {e}", n + 1))?;
        same(&format!("GET /10k.bin {}", n + 1), &body, www_10k())?;
    }
    println!(
        "nginx-probe: {LARGE_FETCHES} x 256 KiB and {SMALL_FETCHES} x 10 KiB by SHA-256; the shared buffers carried {grown} KiB, {sessions} sessions hold one"
    );
    // The cost of reading the file nginx sends: the file service answers
    // pread in messages of at most 1 016 bytes (proto_fs::MAX_READ).
    run.send(&format!("posix-net readfile /www/256k.bin {READ_ROUNDS}"))?;
    let line = run.expect_line(
        "posix-net readfile",
        |l| l.contains("posix-net: readfile "),
        DIALOG_STEP * 3,
    )?;
    let read = readfile_mean(&line).ok_or_else(|| format!("the line {line:?}"))?;
    println!(
        "nginx-probe: a pread of /www/256k.bin in 32 KiB pieces takes {read} us on the mean ({READ_ROUNDS} rounds, {} messages of the file service of at most {} bytes); a GET of it from the host {} us",
        WWW_256K_LEN.div_ceil(proto_fs_max_read()),
        proto_fs_max_read(),
        answer.as_micros()
    );
    Ok(())
}

/// The reads of the file in `posix-net readfile`.
const READ_ROUNDS: usize = 100;

/// The most bytes the file service answers a read with (proto_fs::MAX_READ:
/// MESSAGE_MAX less the reply's header).
fn proto_fs_max_read() -> usize {
    1016
}

/// The mean time of one read in microseconds of the line `posix-net:
/// readfile B bytes N rounds mean M us least L us most X us`.
fn readfile_mean(line: &str) -> Option<u64> {
    line.split(" mean ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Step 5: SIGHUP under a new connection every 50 ms; none fails, and new
/// workers stand in for the old ones.
fn reload(run: &mut qemu::Run, address: SocketAddr, old: &[u32]) -> Result<(), String> {
    let stop = Arc::new(AtomicBool::new(false));
    let asking = {
        let stop = stop.clone();
        std::thread::spawn(move || -> Result<usize, String> {
            let mut done = 0;
            while !stop.load(Ordering::Relaxed) {
                let body = Connection::open(address, READ_WITHIN)
                    .and_then(|mut c| c.get("/index.html"))
                    .map_err(|e| format!("request {} of the reload: {e}", done + 1))?;
                same("the page in the reload", &body, rootfs::www_index())?;
                done += 1;
                std::thread::sleep(RELOAD_GAP);
            }
            Ok(done)
        })
    };
    let asked = (|| {
        std::thread::sleep(Duration::from_millis(500));
        run.send("kill -HUP $M")?;
        run.expect_line(
            "reconfiguring",
            |l| l.contains("reconfiguring"),
            START_WITHIN,
        )?;
        lines_of(run, "start worker process ", WORKERS, START_WITHIN)?;
        std::thread::sleep(RELOAD_FOR);
        Ok::<(), String>(())
    })();
    stop.store(true, Ordering::Relaxed);
    let done = asking
        .join()
        .map_err(|_| "the thread of the reload panicked".to_owned())??;
    asked?;
    let (_, workers) = master_and_workers(&nginx_processes(run, "reload")?)?;
    if let Some(pid) = workers.iter().find(|w| old.contains(w)) {
        return Err(format!(
            "worker {pid} lived through the reload (old {old:?}, now {workers:?})"
        ));
    }
    println!(
        "nginx-probe: SIGHUP under {done} requests on new connections, none failed; workers {old:?} became {workers:?}"
    );
    // The new workers took their buffers while the old ones still held
    // theirs: the old ones gave them back, the new ones hold one each, and an
    // answer of 256 KiB goes through the buffers.
    let (_, before) = buffered(run)?;
    let body = Connection::open(address, READ_WITHIN)
        .and_then(|mut c| c.get("/256k.bin"))
        .map_err(|e| format!("GET /256k.bin after the reload: {e}"))?;
    same("GET /256k.bin after the reload", &body, www_256k())?;
    let (sessions, after) = buffered(run)?;
    let grown = after.wrapping_sub(before);
    if sessions as usize != WORKERS || grown < (WWW_256K_LEN / 1024) as u64 {
        return Err(format!(
            "after the reload {sessions} sessions hold a shared buffer (wanted {WORKERS}, one for each new worker) and an answer of 256 KiB carried {grown} KiB through them"
        ));
    }
    println!(
        "nginx-probe: after the reload {sessions} sessions hold a buffer, and 256 KiB went through them"
    );
    Ok(())
}

/// `cargo xtask nginx-probe [steps] [MACHINE]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let (steps, rest) = match args.first().map(String::as_str) {
        Some("steps") => (true, &args[1..]),
        _ => (false, args),
    };
    let machine = match rest {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask nginx-probe [steps] [tcg|hvf]".to_owned()),
    };
    if steps && machine.is_hvf() {
        return Err("nginx-probe steps runs under -icount, on TCG only".to_owned());
    }
    probe(machine, steps)
}

pub fn probe(machine: &'static qemu::Machine, steps: bool) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    crate::relibc()?;
    crate::busybox_build()?;
    crate::nano_build()?;
    crate::net_build()?;
    let kernel = build(Variant::Normal)?;
    let (name, programs) = if steps {
        (STEPS_IMAGE, steps_programs())
    } else {
        (IMAGE, programs())
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let port = crate::net_curl::free_tcp_port()?;
    let address: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[Forward {
        proto: Proto::Tcp,
        host: port,
        guest: 80,
    }]));
    if steps {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        // 1 and 2.
        start(&mut run, "/etc/nginx/nginx.conf")?;
        let (master, workers) = master_and_workers(&nginx_processes(&mut run, "start")?)?;
        println!("nginx-probe: master {master} (user 0), workers {workers:?} (user 65534)");
        // 3.
        first_page(address)?;
        let at = Instant::now();
        pages(address, REQUESTS, CONNECTIONS)?;
        println!(
            "nginx-probe: {REQUESTS} requests over {CONNECTIONS} connections in {} ms",
            at.elapsed().as_millis()
        );
        // 4, 5, 6.
        large_files(&mut run, address)?;
        reload(&mut run, address, &workers)?;
        quit(&mut run, "quit")?;
        // 7.
        start(&mut run, "/etc/nginx/exclusive.conf")?;
        first_page(address)?;
        pages(address, EXCLUSIVE_REQUESTS, EXCLUSIVE_CONNECTIONS)?;
        println!(
            "nginx-probe: one listening socket for {WORKERS} workers: {EXCLUSIVE_REQUESTS} requests over {EXCLUSIVE_CONNECTIONS} connections"
        );
        quit(&mut run, "exclusive")
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    verdict(&output.lines)?;
    if steps {
        let rows = steps_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        let buffer = rows.iter().find(|r| r.0 == BUFFER_KIND).copied();
        println!(
            "nginx-probe steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); BUFFER {buffer:?}; every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            crate::net_probe::STEP_MAX
        );
    }
    let elapsed = started.elapsed();
    if !steps && elapsed > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s, past {} s",
            elapsed.as_secs_f64(),
            RUN_WITHIN.as_secs()
        ));
    }
    println!(
        "nginx-probe passed in {:.0} s on {}",
        elapsed.as_secs_f64(),
        machine.name
    );
    Ok(())
}

/// The longest step of each kind of the network service in `lines`: every
/// kind of `STEP_KINDS` is there, none passes 0.9 of term B, and CLONE stays
/// within its portion (0.8 of term B).
fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = crate::net_probe::longest_over_starts(lines);
    for (kind, name) in STEP_KINDS {
        if !rows.iter().any(|(k, ..)| *k == kind) {
            return Err(format!("the network service: no step {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > crate::net_probe::STEP_MAX) {
        return Err(format!(
            "the network service: a step past 0.9 of term B ({}): {row:?}",
            crate::net_probe::STEP_MAX
        ));
    }
    if let Some(row) = rows
        .iter()
        .find(|r| CLONE_KINDS.contains(&r.0) && r.1 > crate::net_probe::PORTION_MAX)
    {
        return Err(format!(
            "the network service: CLONE past 0.8 of term B ({}): {row:?}",
            crate::net_probe::PORTION_MAX
        ));
    }
    Ok(rows)
}

/// Fails on a line of nginx at `crit` or above, or on a fault of the
/// image.
fn verdict(lines: &[String]) -> Result<(), String> {
    if let Some(line) = lines.iter().find(|l| {
        ["[alert]", "[emerg]", "[crit]"]
            .iter()
            .any(|w| l.contains(w))
    }) {
        return Err(format!("nginx: {line}"));
    }
    if let Some(line) = lines.iter().find(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
    }) {
        return Err(format!("the image faulted: {line}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_meets_the_vectors_of_fips_180() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// The probe's settings differ from the package's in the connections,
    /// the keep-alive and, for `exclusive`, the listening socket only.
    #[test]
    fn the_variants_of_the_settings() {
        assert!(NGINX_CONF.contains("user nobody nobody;"));
        assert!(NGINX_CONF.contains("listen 80 reuseport;"));
        assert!(NGINX_CONF.contains("accept_mutex off;"));
        assert!(NGINX_CONF.contains("error_log stderr notice;"));
        let probe = probe_conf();
        assert!(probe.contains("worker_connections 256;"));
        assert!(probe.contains("keepalive_timeout 10;"));
        assert_eq!(probe.lines().count(), NGINX_CONF.lines().count());
        let exclusive = exclusive_conf();
        assert!(exclusive.contains("listen 80;") && !exclusive.contains("reuseport"));
    }

    #[test]
    fn the_files_are_fixed_noise() {
        assert_eq!(www_10k().len(), WWW_10K_LEN);
        assert_eq!(www_256k().len(), WWW_256K_LEN);
        assert_ne!(&www_256k()[..WWW_10K_LEN], www_10k());
        assert_eq!(noise(1, 20), noise(1, 20));
    }

    #[test]
    fn the_length_comes_from_the_head() {
        assert_eq!(
            content_length("HTTP/1.1 200 OK\r\nServer: nginx\r\ncontent-length: 10240\r\n"),
            Some(10240)
        );
        assert_eq!(content_length("HTTP/1.1 200 OK\r\nServer: nginx"), None);
    }

    #[test]
    fn the_processes_come_from_the_status_files() {
        let lines: Vec<String> = [
            "# grep -E '^(Name|Uid):' /proc/[0-9]*/status",
            "/proc/1/status:Name:\tinit",
            "/proc/1/status:Uid:\t0\t0\t0\t0",
            "/proc/40/status:Name:\tnginx",
            "/proc/40/status:Uid:\t0\t0\t0\t0",
            "/proc/41/status:Name:\tnginx",
            "/proc/41/status:Uid:\t65534\t65534\t65534\t65534",
        ]
        .map(str::to_owned)
        .to_vec();
        assert_eq!(processes_of(&lines), [(40, 0), (41, 65534)]);
        assert!(master_and_workers(&processes_of(&lines)).is_err());
        let all = [(40, 0), (41, 65534), (42, 65534), (43, 65534), (44, 65534)];
        assert_eq!(
            master_and_workers(&all).unwrap(),
            (40, vec![41, 42, 43, 44])
        );
        assert!(
            master_and_workers(&[(40, 0), (41, 0), (42, 65534), (43, 65534), (44, 65534)]).is_err()
        );
    }

    #[test]
    fn the_counter_comes_from_posix_net_stat() {
        assert_eq!(
            stat_numbers("posix-net: buffers 3 limit 4 buffered 1290 KiB"),
            Some((3, 1290))
        );
        assert_eq!(stat_numbers("posix-net: 63 checks ok"), None);
    }

    #[test]
    fn the_steps_need_every_kind_of_nginx_and_stay_within_the_bound() {
        let line = |kind: usize, ticks: u64| {
            format!("service step: {} kind {kind} {ticks} ticks detail 0", "14")
        };
        let mut lines: Vec<String> = STEP_KINDS.iter().map(|(k, _)| line(*k, 5000)).collect();
        assert_eq!(steps_verdict(&lines).unwrap().len(), STEP_KINDS.len());
        lines.push(line(BUFFER_KIND, crate::net_probe::STEP_MAX + 1));
        assert!(steps_verdict(&lines).unwrap_err().contains("0.9 of term B"));
        lines.pop();
        lines.push(line(20, crate::net_probe::PORTION_MAX + 1));
        assert!(steps_verdict(&lines).unwrap_err().contains("CLONE"));
        lines.pop();
        lines.retain(|l| !l.contains(&format!("kind {BUFFER_KIND} ")));
        assert!(steps_verdict(&lines).unwrap_err().contains("Buffer"));
    }

    #[test]
    fn the_time_of_a_read_comes_from_posix_net_readfile() {
        assert_eq!(
            readfile_mean(
                "posix-net: readfile 262144 bytes 100 rounds mean 4210 us least 3900 us most 7000 us"
            ),
            Some(4210)
        );
        assert_eq!(readfile_mean("posix-net: readfile /x: No such file"), None);
        assert_eq!(proto_fs_max_read(), proto_fs::MAX_READ);
    }

    #[test]
    fn a_line_of_nginx_at_crit_or_above_fails_the_run() {
        let ok = ["2026/11/05 [notice] 40#0: start worker process 41".to_owned()];
        assert!(verdict(&ok).is_ok());
        for word in ["alert", "emerg", "crit"] {
            let bad = [format!("2026/11/05 [{word}] 41#0: epoll_wait() timed out")];
            assert!(verdict(&bad).is_err(), "{word}");
        }
    }

    /// The image of the probe holds nginx, its settings of the probe and
    /// the files it fetches; the image of the steps counts the service's
    /// steps.
    #[test]
    fn the_images_hold_nginx_and_the_files_of_the_probe() {
        let files = rootfs::files_of(IMAGE);
        let has = |path: &str| files.iter().find(|f| f.path == path);
        assert!(has("/bin/nginx").is_some());
        assert!(has("/www/256k.bin").is_some());
        assert_eq!(
            has("/etc/nginx/nginx.conf").and_then(|f| f.source),
            Some(rootfs::Source::Bytes(
                "nginx-probe.conf",
                probe_conf().as_bytes()
            ))
        );
        assert!(programs().iter().any(|p| p.0 == "nginx"));
        let netd = steps_programs().iter().find(|p| p.0 == "netd").unwrap();
        assert_eq!(netd.3, &["steps"]);
    }

    /// The job of the workflow runs the probe and the final job waits for
    /// it.
    #[test]
    fn the_workflow_has_a_job_of_the_probe() {
        let workflow =
            std::fs::read_to_string(crate::root().join(".github/workflows/ci.yml")).unwrap();
        assert!(workflow.contains("  nginx-probe:\n"));
        assert!(workflow.contains("run: cargo xtask nginx-probe\n"));
        assert!(workflow.contains("needs: [build, group, doom-probe, nginx-probe]"));
    }
}
