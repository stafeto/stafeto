// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the sockets of the network service from outside
//! (`cargo xtask net-curl`): the shell image with the network service on
//! QEMU's user network, a port of the host forwarded to the port 80 of the
//! guest and one of the UDP ports to its port 7. xtask drives `ash` over the
//! serial port, as `doom-headless` does, and talks to the guest as a client
//! of the host:
//!
//! 1. `httpd -f -p 80 -h /www &` in the guest (BusyBox's server: `accept`,
//!    `fork` for a connection, the connection on descriptors 0 and 1,
//!    `shutdown`, `_exit`). Twenty requests in a row and eight at once for
//!    `/index.html`, an HTTP/1.0 GET from `std::net::TcpStream` (what `curl
//!    -s http://127.0.0.1:PORT/index.html` sends); each body is the page of
//!    the image, byte for byte (its SHA-256 is that of `/www/index.html`).
//! 2. UDP with the host: `net-sock ADDRESS udp-echo 7` answers a datagram
//!    sent to the forwarded port, and `net-sock ADDRESS udp-send 10.0.2.2
//!    PORT TEXT` sends one that xtask receives.
//! 3. `net-sock ADDRESS`: every check of tests/posix-so/dyn/net-sock.c.
//! 4. `kill` of `httpd`, a new `httpd` on the same port (the connections of
//!    the first one are in TIME-WAIT; it sets SO_REUSEADDR) and one request.
//!
//! The ports of the host are free ports xtask took and gave back just
//! before QEMU starts. Only 127.0.0.1 of the host is forwarded. The run
//! needs no `-icount`: the host's network lives in real time.
//!
//! `cargo xtask net-curl steps` runs the same with the service counting its
//! steps (`netd` built with the feature `steps`, under -icount with the guest
//! sleeping in real time), and judges every step against 0.9 of term B: the
//! cost of a frame of the wire, with real traffic.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::qemu::{Forward, Proto};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net, qemu, relibc, rootfs, symbolize,
};

/// The checks of `net-sock`, in the order the program runs them.
pub const CHECKS: [&str; 31] = [
    "tcp-loop",
    "tcp-own",
    "udp-loop",
    "ephemeral",
    "in-use",
    "reuse",
    "privileged",
    "refused",
    "fork",
    "exec",
    "poll-mixed",
    "nonblock-connect",
    "accept-again",
    "connect-eintr",
    "recv-eintr",
    "epipe",
    "msgsize",
    "inet6",
    "close-flush",
    "names",
    "fstat",
    "nonblock-refused",
    "hangup",
    "spawn-socket",
    "cloexec-exec",
    "clofork",
    "epipe-unread",
    "peek-waitall",
    "exec-blocked",
    "write-whole",
    "udp-connect",
];

/// The requests one after the other and those at once.
const SEQUENTIAL: usize = 20;
const CONCURRENT: usize = 8;
/// How long a request may take to be answered whole.
const READ_WITHIN: Duration = Duration::from_secs(30);
/// How long the first request waits for `httpd` to listen.
const LISTEN_WITHIN: Duration = Duration::from_secs(30);
/// The whole run may take this long (the ci group allows 120 s).
const RUN_WITHIN: Duration = Duration::from_secs(110);
/// How long `net-sock` may take for all its checks (some wait seconds for
/// an alarm or a late byte).
const CHECKS_WITHIN: Duration = Duration::from_secs(90);

/// The port of the guest with no listener, which the host reaches through a
/// forward: the first connection of the run must end in a second.
const CLOSED_GUEST_PORT: u16 = 81;
/// The datagrams of 1 472 bytes sent to a UDP port with no socket, and the
/// connections to the port with no listener: each makes the stack answer
/// with a frame of its own (port unreachable, reset), the case the rule of
/// the step of receiving is for (netd::frames::answered).
const ANSWERED_UDP: usize = 64;
const ANSWERED_TCP: usize = 32;
/// The reset of the guest to the very first connection reaches the host
/// only when the service asked for its gateway's address before (the ARP
/// request of the gateway every 30 s); while this is true a closed first
/// connection that stays open is a warning.
pub const CLOSED_PORT_NEEDS_GATEWAY_REQUEST: bool = false;

/// The image of the run with the counted steps.
pub const STEPS_IMAGE: &str = "boot-net-curl-steps.img";

/// The programs of the image of the run with the counted steps: the
/// shell's image with `netd` that prints its longest steps.
pub fn steps_programs() -> &'static [crate::ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<crate::ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = net::programs().to_vec();
        for program in &mut programs {
            if program.0 == "netd" {
                program.3 = &["steps", "probe"];
            }
        }
        programs
    })
}

/// A free port of the host, taken and given back.
pub fn free_tcp_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("a free port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("a free port: {e}"))?
        .port();
    Ok(port)
}

fn free_udp_port() -> Result<u16, String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("a free UDP port: {e}"))?;
    let port = socket
        .local_addr()
        .map_err(|e| format!("a free UDP port: {e}"))?
        .port();
    Ok(port)
}

/// One HTTP/1.0 GET of `/index.html`: the body and the time it took, or why
/// not.
fn get(address: SocketAddr) -> Result<(Vec<u8>, Duration), String> {
    get_within(address, READ_WITHIN)
}

/// The forwarded port of the host as an address of the run.
fn local(port: u16) -> SocketAddr {
    ([127, 0, 0, 1], port).into()
}

/// The least time between two connects of this process to a forwarded port
/// of QEMU's user network. The host's end of a forward listens with a queue
/// of one connection; a connection that finds the queue full is dropped
/// silently by a Linux host (the client sends its SYN again a second later)
/// and reset by macOS (the client sees "Connection reset by peer" on its
/// first read or write, and `setsockopt` on it fails with EINVAL). The user
/// network takes a connection off the queue within a millisecond or two, so
/// a gap of this size keeps the queue from ever filling, on both hosts,
/// while the connections it opens stay open together.
pub(crate) const FORWARD_CONNECT_GAP: Duration = Duration::from_millis(4);

/// Waits until `FORWARD_CONNECT_GAP` has passed since the last connect to
/// `address` started (by any thread of the process; each address of a
/// forward has its own clock, so that boots running side by side in one
/// process do not delay each other). The wait is the only time a lock is
/// held: the connect that follows takes none.
pub(crate) fn pace_forward(address: &SocketAddr) {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    type Clock = Arc<Mutex<Option<Instant>>>;
    static CLOCKS: Mutex<Option<HashMap<SocketAddr, Clock>>> = Mutex::new(None);
    let clock = CLOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .entry(*address)
        .or_default()
        .clone();
    let mut last_start = clock.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(wait) =
        last_start.and_then(|t| (t + FORWARD_CONNECT_GAP).checked_duration_since(Instant::now()))
    {
        std::thread::sleep(wait);
    }
    *last_start = Some(Instant::now());
}

/// `TcpStream::connect_timeout` to a forwarded port after `pace_forward`.
pub(crate) fn connect_forwarded(
    address: &SocketAddr,
    within: Duration,
) -> std::io::Result<TcpStream> {
    pace_forward(address);
    TcpStream::connect_timeout(address, within)
}

/// `get`, giving up after `within` on each step.
pub fn get_within(address: SocketAddr, within: Duration) -> Result<(Vec<u8>, Duration), String> {
    pace_forward(&address);
    let started = Instant::now();
    let mut stream =
        TcpStream::connect_timeout(&address, within).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(within))
        .and_then(|()| stream.set_write_timeout(Some(within)))
        .map_err(|e| format!("timeouts: {e}"))?;
    stream
        .write_all(b"GET /index.html HTTP/1.0\r\nHost: localhost\r\nUser-Agent: net-curl\r\n\r\n")
        .map_err(|e| format!("request: {e}"))?;
    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .map_err(|e| format!("response after {} bytes: {e}", answer.len()))?;
    let elapsed = started.elapsed();
    let body = body_of(&answer)?;
    Ok((body, elapsed))
}

/// The body of a response: after the blank line; the status must be 200.
pub fn body_of(answer: &[u8]) -> Result<Vec<u8>, String> {
    let split = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("no end of headers in {} bytes", answer.len()))?;
    let head = String::from_utf8_lossy(&answer[..split]);
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200 ") {
        return Err(format!("status line {status:?}"));
    }
    Ok(answer[split + 4..].to_vec())
}

/// Whether the body is the page of the image.
pub fn check_body(body: &[u8]) -> Result<(), String> {
    let page = rootfs::www_index();
    if body == page {
        return Ok(());
    }
    let first = body.iter().zip(page).position(|(a, b)| a != b);
    Err(format!(
        "the body is {} bytes, the page {}; the first difference at {first:?}",
        body.len(),
        page.len()
    ))
}

/// Statistics of the times of the requests: the median and the largest, in
/// milliseconds.
fn summary(times: &mut [Duration]) -> (u128, u128) {
    times.sort();
    let median = times.get(times.len() / 2).map_or(0, Duration::as_millis);
    let largest = times.last().map_or(0, Duration::as_millis);
    (median, largest)
}

/// The size of the file `httpd` of the steps run sends from the stack's own
/// socket to the wire.
const BULK_KIB: usize = 2048;

/// A bulk transfer from the stack's own `httpd` (no consumer ring, no
/// offload under QEMU): a file of `BULK_KIB` KiB made in the guest and read
/// whole through the forwarded port.
fn bulk(run: &mut qemu::Run, tcp: u16) -> Result<(), String> {
    run.send("kill $H2; wait $H2")?;
    run.expect("# ", DIALOG_STEP)?;
    // The image has no /dev/zero: the file is the page, repeated.
    let repeats = BULK_KIB * 1024 / rootfs::WWW_INDEX_LEN;
    run.send(&format!(
        "mkdir -p /tmp/bulk && i=0 && while [ $i -lt {repeats} ]; do cat /www/index.html; i=$((i+1)); done > /tmp/bulk/big; echo bulk-made-$?"
    ))?;
    run.expect("bulk-made-0", Duration::from_secs(120))?;
    run.expect("# ", DIALOG_STEP)?;
    run.send("httpd -f -p 80 -h /tmp/bulk &")?;
    run.expect("# ", DIALOG_STEP)?;
    std::thread::sleep(Duration::from_millis(500));
    let within = Duration::from_secs(300);
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&local(tcp), within)
        .map_err(|e| format!("bulk connect: {e}"))?;
    stream
        .set_read_timeout(Some(within))
        .map_err(|e| format!("bulk timeout: {e}"))?;
    stream
        .write_all(b"GET /big HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .map_err(|e| format!("bulk request: {e}"))?;
    let mut answer = Vec::new();
    stream
        .read_to_end(&mut answer)
        .map_err(|e| format!("bulk response after {} bytes: {e}", answer.len()))?;
    let body = body_of(&answer)?;
    if body.len() != BULK_KIB * 1024 {
        return Err(format!(
            "the bulk body is {} bytes, not {}",
            body.len(),
            BULK_KIB * 1024
        ));
    }
    println!(
        "net-curl: bulk of {BULK_KIB} KiB from the stack's own httpd read in {} ms",
        started.elapsed().as_millis()
    );
    Ok(())
}

/// The requests of the run: twenty in a row, eight at once.
pub fn requests(address: SocketAddr, started: Instant) -> Result<(u128, u128), String> {
    // The first request waits for `httpd` to listen. A SYN that comes before
    // the server listens gets no RST that arrives (the stack's answer is
    // dropped while it asks for the gateway's address), and QEMU sends the
    // SYN again after seconds: the request starts again after two.
    let first = loop {
        match get_within(address, Duration::from_secs(2)) {
            Ok(answer) => break answer,
            Err(why) if started.elapsed() < LISTEN_WITHIN => {
                let _ = why;
                std::thread::sleep(Duration::from_millis(300));
            }
            Err(why) => return Err(format!("the first request: {why}")),
        }
    };
    check_body(&first.0).map_err(|e| format!("request 1: {e}"))?;
    let mut times = vec![first.1];
    for n in 2..=SEQUENTIAL {
        let (body, time) = get(address).map_err(|e| format!("request {n}: {e}"))?;
        check_body(&body).map_err(|e| format!("request {n}: {e}"))?;
        times.push(time);
    }
    let threads: Vec<_> = (0..CONCURRENT)
        .map(|_| std::thread::spawn(move || get(address)))
        .collect();
    for (n, thread) in threads.into_iter().enumerate() {
        let (body, time) = thread
            .join()
            .map_err(|_| "a request thread panicked".to_owned())?
            .map_err(|e| format!("concurrent request {}: {e}", n + 1))?;
        check_body(&body).map_err(|e| format!("concurrent request {}: {e}", n + 1))?;
        times.push(time);
    }
    let millis: Vec<_> = times.iter().map(|t| t.as_millis()).collect();
    println!("net-curl: times of the requests in ms: {millis:?}");
    Ok(summary(&mut times))
}

/// The page through the host's `curl -s`, the program the criterion of the
/// stage names; not run on a host without it.
fn curl(port: u16) -> Result<bool, String> {
    let output = match std::process::Command::new("curl")
        .args(["-s", "--max-time", "30"])
        .arg(format!("http://127.0.0.1:{port}/index.html"))
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("curl: {e}")),
    };
    if !output.status.success() {
        return Err(format!("curl ended with {}", output.status));
    }
    check_body(&output.stdout).map_err(|e| format!("curl: {e}"))?;
    Ok(true)
}

/// A connection to the guest's port with no listener through the forward:
/// slirp accepts it, asks the guest, and closes it when the guest resets;
/// without the reset (lost, as the first answer to the gateway is while the
/// service does not know its address) slirp sends the SYN again after
/// seconds. The connection must be closed within `within`.
fn closed_connection(port: u16, within: Duration) -> Result<Duration, String> {
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&local(port), within)
        .map_err(|e| format!("connect to the forward of the closed port: {e}"))?;
    stream
        .set_read_timeout(Some(within))
        .map_err(|e| format!("timeout: {e}"))?;
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => Ok(started.elapsed()),
        Ok(_) => Err("the closed port sent data".to_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(started.elapsed()),
        Err(e) => Err(format!(
            "the connection to the closed port stayed open for {} ms ({e}): the guest's reset did not arrive",
            started.elapsed().as_millis()
        )),
    }
}

/// The frames the stack answers: 64 datagrams of 1 472 bytes to a UDP port
/// no socket has, then 32 connections to the port with no listener. Each
/// connection is closed within a second.
fn answered_frames(udp_port: u16, closed_port: u16) -> Result<(), String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("udp socket: {e}"))?;
    let datagram = [0x55u8; 1472];
    for _ in 0..ANSWERED_UDP {
        socket
            .send_to(&datagram, local(udp_port))
            .map_err(|e| format!("udp send: {e}"))?;
    }
    for n in 0..ANSWERED_TCP {
        closed_connection(closed_port, Duration::from_secs(2))
            .map_err(|e| format!("connection {} of {ANSWERED_TCP}: {e}", n + 1))?;
    }
    println!(
        "net-curl: {ANSWERED_UDP} datagrams of 1472 bytes to a port with no socket and {ANSWERED_TCP} connections to a port with no listener answered"
    );
    Ok(())
}

/// The datagrams of the flood: more than the 256 buffers of the ring of
/// receiving, sent with no pause.
const FLOOD_UDP: usize = 1500;

/// A flood of `FLOOD_UDP` datagrams of 1 472 bytes to a UDP port no socket has
/// reaches the guest in a run longer than its ring of receiving (the device
/// that looks at the ring after a doorbell only must not starve for want of
/// one). Then a connection to the port with no listener is answered within
/// two seconds, which a ring that waits for a doorbell for ever would not.
fn flood(udp_port: u16, closed_port: u16) -> Result<(), String> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("udp socket: {e}"))?;
    let datagram = [0x55u8; 1472];
    let started = Instant::now();
    for _ in 0..FLOOD_UDP {
        socket
            .send_to(&datagram, local(udp_port))
            .map_err(|e| format!("udp send: {e}"))?;
    }
    let sent = started.elapsed();
    let answered = closed_connection(closed_port, Duration::from_secs(2))
        .map_err(|e| format!("after the flood: {e}"))?;
    println!(
        "net-curl: flood of {FLOOD_UDP} datagrams sent in {} ms, the next connection answered in {} ms",
        sent.as_millis(),
        answered.as_millis()
    );
    Ok(())
}

/// UDP with the guest: the echo through the forwarded port, and a datagram
/// the guest sends to the host (10.0.2.2 is the host for slirp).
fn udp(run: &mut qemu::Run, address: &str, forward: u16) -> Result<(), String> {
    run.send(&format!("net-sock {address} udp-echo 7 &"))?;
    run.expect("# ", DIALOG_STEP)?;
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("udp socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| format!("udp timeout: {e}"))?;
    let target: SocketAddr = ([127, 0, 0, 1], forward).into();
    let mut buf = [0u8; 64];
    let started = Instant::now();
    // The guest may not listen yet; the datagram it did not take is gone.
    let echoed = loop {
        socket
            .send_to(b"net-udp-echo", target)
            .map_err(|e| format!("udp send: {e}"))?;
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => break buf[..n].to_vec(),
            Err(_) if started.elapsed() < Duration::from_secs(20) => {}
            Err(e) => return Err(format!("no echo from the guest: {e}")),
        }
    };
    if echoed != b"net-udp-echo" {
        return Err(format!(
            "the echo is {:?}",
            String::from_utf8_lossy(&echoed)
        ));
    }
    run.expect("net-sock: udp echo ok", DIALOG_STEP)?;
    let listener = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("udp socket: {e}"))?;
    listener
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("udp timeout: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("udp address: {e}"))?
        .port();
    run.send(&format!(
        "net-sock {address} udp-send 10.0.2.2 {port} net-udp"
    ))?;
    let (n, _) = listener
        .recv_from(&mut buf)
        .map_err(|e| format!("no datagram from the guest: {e}"))?;
    if &buf[..n] != b"net-udp" {
        return Err(format!(
            "the datagram is {:?}",
            String::from_utf8_lossy(&buf[..n])
        ));
    }
    run.expect("net-sock: udp send ok", DIALOG_STEP)?;
    run.expect("# ", DIALOG_STEP)
}

/// What a line says after `net-sock: `; the first line may follow the
/// prompt on the same line.
fn net_sock_text(line: &str) -> Option<&str> {
    line.split_once("net-sock: ").map(|(_, text)| text)
}

/// `net-sock` for all its checks: a line for each, then the count.
fn checks(run: &mut qemu::Run, address: &str) -> Result<(), String> {
    run.send(&format!("net-sock {address}"))?;
    let deadline = Instant::now() + CHECKS_WITHIN;
    let mut seen = 0;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = run.expect_line(
            "a line of net-sock",
            |l| net_sock_text(l).is_some_and(|t| t != "udp echo ok" && t != "udp send ok"),
            left,
        )?;
        let line = net_sock_text(&line).unwrap_or_default().to_owned();
        if line.contains(" failed: ") {
            return Err(format!("net-sock: {line}"));
        }
        if let Some(count) = line.strip_suffix(" checks ok") {
            let count: usize = count.parse().map_err(|_| format!("{line:?}"))?;
            if count != CHECKS.len() || seen != count {
                return Err(format!(
                    "net-sock ran {count} checks, {seen} lines said ok, xtask knows {}",
                    CHECKS.len()
                ));
            }
            return Ok(());
        }
        let name = line
            .strip_suffix(" ok")
            .ok_or_else(|| format!("an unknown line of net-sock: {line:?}"))?;
        if CHECKS.get(seen) != Some(&name) {
            return Err(format!(
                "check {} is {name}, wanted {:?}",
                seen + 1,
                CHECKS.get(seen)
            ));
        }
        seen += 1;
    }
}

/// The guest's address from the line `net: lease A.B.C.D/N ...`.
pub fn lease_address(line: &str) -> Option<String> {
    let rest = line.split("net: lease ").nth(1)?;
    let address = rest.split('/').next()?;
    (address.split('.').count() == 4).then(|| address.to_owned())
}

/// `cargo xtask net-curl [steps] [MACHINE]`.
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
        _ => return Err("usage: cargo xtask net-curl [steps] [tcg|hvf]".to_owned()),
    };
    probe(machine, steps)
}

pub fn probe(machine: &'static qemu::Machine, steps: bool) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let (name, programs) = if steps {
        (STEPS_IMAGE, steps_programs())
    } else if machine.msi() {
        (net::ITS_IMAGE, net::its_programs())
    } else {
        (net::IMAGE, net::programs())
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let tcp = free_tcp_port()?;
    let udp_port = free_udp_port()?;
    let closed_port = free_tcp_port()?;
    let forwards = [
        Forward {
            proto: Proto::Tcp,
            host: tcp,
            guest: 80,
        },
        Forward {
            proto: Proto::Udp,
            host: udp_port,
            guest: 7,
        },
        Forward {
            proto: Proto::Tcp,
            host: closed_port,
            guest: CLOSED_GUEST_PORT,
        },
    ];
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net_on(machine, &forwards));
    if steps {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let mut reported = None;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        let lease = run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        let address = lease_address(&lease).ok_or(format!("the lease line {lease:?}"))?;
        // The first exchange after the lease: the guest's reset to a
        // connection to a port with no listener closes it within a second.
        match closed_connection(closed_port, Duration::from_secs(1)) {
            Ok(took) => println!(
                "net-curl: the first connection, to a closed port, was closed in {} ms",
                took.as_millis()
            ),
            Err(why) if CLOSED_PORT_NEEDS_GATEWAY_REQUEST => {
                println!("net-curl: WARNING the first connection, to a closed port: {why}")
            }
            Err(why) => return Err(why),
        }
        answered_frames(udp_port, closed_port)?;
        flood(udp_port, closed_port)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("httpd -f -p 80 -h /www & H=$!")?;
        run.expect("# ", DIALOG_STEP)?;
        let timing = requests(local(tcp), started)?;
        println!(
            "net-curl: {} requests in a row and {} at once ok, {} ms median, {} ms the longest",
            SEQUENTIAL, CONCURRENT, timing.0, timing.1
        );
        if curl(tcp)? {
            println!("net-curl: curl -s http://127.0.0.1:{tcp}/index.html gives the page");
        }
        udp(&mut run, &address, udp_port)?;
        checks(&mut run, &address)?;
        run.expect("# ", DIALOG_STEP)?;
        // A new server on the port the first one used, while the connection
        // of one more request is in TIME-WAIT on that port (the server's
        // child closed first, 10 s in the stack): the new bind needs
        // SO_REUSEADDR. One request makes the orphan just before.
        let (body, _) = get(local(tcp)).map_err(|e| format!("the request before the kill: {e}"))?;
        check_body(&body).map_err(|e| format!("before the kill: {e}"))?;
        run.send("kill $H; wait $H")?;
        run.expect("# ", DIALOG_STEP)?;
        // The old listener goes in steps of the service after the kill: a
        // start that finds the port in use ends, and starts again.
        let mut answered = None;
        for _ in 0..10 {
            run.send("httpd -f -p 80 -h /www & H2=$!")?;
            run.expect("# ", DIALOG_STEP)?;
            std::thread::sleep(Duration::from_millis(300));
            if let Ok(answer) = get_within(local(tcp), Duration::from_secs(2)) {
                answered = Some(answer);
                break;
            }
        }
        let (body, _) = answered.ok_or("the new httpd never answered on the port")?;
        check_body(&body).map_err(|e| format!("the new httpd: {e}"))?;
        println!("net-curl: a new httpd on the same port ok");
        if steps {
            bulk(&mut run, tcp)?;
        }
        reported = Some(timing);
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
    }) {
        return Err("the network image faulted".into());
    }
    if steps {
        // The flood of the run is a burst: a doorbell serves several frames.
        if crate::net_probe::bells_serve_frames(&output.lines)? == 0 {
            return Err("the service printed no line of bells for the flood".to_owned());
        }
        let rows = crate::net_probe::traffic_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "net-curl steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            crate::net_probe::STEP_MAX
        );
    }
    let elapsed = started.elapsed();
    if elapsed > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s, past the {} s of the group",
            elapsed.as_secs_f64(),
            RUN_WITHIN.as_secs()
        ));
    }
    let (median, largest) = reported.unwrap_or_default();
    println!(
        "net-curl passed in {:.0} s on {}: {} checks of net-sock, GET of {} bytes {median} ms median, {largest} ms the longest",
        elapsed.as_secs_f64(),
        machine.name,
        CHECKS.len(),
        rootfs::WWW_INDEX_LEN
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn listen(fd: i32, backlog: i32) -> i32;
    }

    /// A burst of connects to a listener with a queue of one connection
    /// (the host's end of a forward of QEMU's user network) that takes a
    /// connection off the queue every 2 ms, as the user network does: with
    /// the gap between connects every one is answered; without it macOS
    /// resets those that find the queue full (and a Linux host drops their
    /// SYN, which the client sends again a second later).
    #[test]
    fn a_burst_of_connects_to_a_forward_is_answered_whole() {
        use std::os::fd::AsRawFd;
        const BURST: usize = 24;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        // SAFETY: `listen` on the descriptor of a listening socket only
        // changes the length of its queue.
        assert_eq!(unsafe { listen(listener.as_raw_fd(), 1) }, 0);
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let acceptor = std::thread::spawn(move || {
            while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                };
                std::thread::sleep(Duration::from_millis(2));
                std::thread::spawn(move || {
                    let mut request = [0u8; 1];
                    stream.set_nonblocking(false).unwrap();
                    if stream.read_exact(&mut request).is_ok() {
                        let _ = stream.write_all(b"x");
                    }
                });
            }
        });
        let clients: Vec<_> = (0..BURST)
            .map(|_| {
                std::thread::spawn(move || -> Result<(), String> {
                    let mut stream = connect_forwarded(&address, Duration::from_millis(500))
                        .map_err(|e| format!("connect: {e}"))?;
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .map_err(|e| format!("socket options: {e}"))?;
                    stream.write_all(b"?").map_err(|e| format!("write: {e}"))?;
                    let mut answer = [0u8; 1];
                    stream
                        .read_exact(&mut answer)
                        .map_err(|e| format!("read: {e}"))
                })
            })
            .collect();
        let failed: Vec<String> = clients
            .into_iter()
            .filter_map(|c| c.join().unwrap().err())
            .collect();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        acceptor.join().unwrap();
        assert!(
            failed.is_empty(),
            "{} of {BURST} failed: {failed:?}",
            failed.len()
        );
    }

    /// Connects to two forwards do not delay each other, and those to one
    /// forward keep the gap whichever thread makes them.
    #[test]
    fn the_gap_is_kept_for_each_address_apart() {
        let a: SocketAddr = ([127, 0, 0, 1], 40001).into();
        let b: SocketAddr = ([127, 0, 0, 1], 40002).into();
        pace_forward(&a);
        let started = Instant::now();
        pace_forward(&b);
        assert!(started.elapsed() < FORWARD_CONNECT_GAP, "b waited for a");
        let started = Instant::now();
        pace_forward(&a);
        assert!(started.elapsed() >= FORWARD_CONNECT_GAP - Duration::from_millis(1));
    }

    /// The checks xtask expects are those the program runs, in its order.
    #[test]
    fn the_checks_are_those_of_the_program() {
        let source =
            std::fs::read_to_string(crate::root().join("tests/posix-so/dyn/net-sock.c")).unwrap();
        let table = source.split("CHECKS[] = {").nth(1).unwrap();
        let table = table.split("};").next().unwrap();
        let names: Vec<&str> = table
            .lines()
            .filter_map(|l| l.trim().strip_prefix("{ \""))
            .filter_map(|l| l.split('"').next())
            .collect();
        assert_eq!(names, CHECKS);
    }

    #[test]
    fn the_page_is_64_kib_of_lines() {
        let page = rootfs::www_index();
        assert_eq!(page.len(), rootfs::WWW_INDEX_LEN);
        assert_eq!(page.last(), Some(&b'\n'));
        assert!(
            page.iter()
                .all(|&b| b == b'\n' || b.is_ascii_graphic() || b == b' ')
        );
        assert_eq!(page, rootfs::www_index());
    }

    #[test]
    fn a_body_comes_after_the_headers_of_a_200() {
        let answer = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(body_of(answer).unwrap(), b"abc");
        assert!(body_of(b"HTTP/1.0 404 Not Found\r\n\r\nx").is_err());
        assert!(body_of(b"HTTP/1.0 200 OK\r\n").is_err());
    }

    #[test]
    fn the_address_comes_from_the_lease_line() {
        assert_eq!(
            lease_address("net: lease 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3").as_deref(),
            Some("10.0.2.15")
        );
        assert_eq!(lease_address("net: lease lost"), None);
    }

    #[test]
    fn the_run_forwards_tcp_to_80_and_udp_to_7() {
        let args = qemu::net(&[
            Forward {
                proto: Proto::Tcp,
                host: 1,
                guest: 80,
            },
            Forward {
                proto: Proto::Udp,
                host: 2,
                guest: 7,
            },
        ])
        .join(" ");
        assert!(args.contains("hostfwd=tcp:127.0.0.1:1-:80,hostfwd=udp:127.0.0.1:2-:7"));
    }

    #[test]
    fn the_steps_image_builds_the_service_with_the_counting_of_steps_and_the_probe() {
        let netd = steps_programs().iter().find(|p| p.0 == "netd").unwrap();
        assert_eq!(netd.3, &["steps", "probe"]);
        assert!(steps_programs().iter().any(|p| p.0 == "ash-launcher"));
    }
}
