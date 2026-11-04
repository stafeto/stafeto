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
pub const CHECKS: [&str; 21] = [
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
                program.3 = &["steps"];
            }
        }
        programs
    })
}

/// A free port of the host, taken and given back.
fn free_tcp_port() -> Result<u16, String> {
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
fn get(port: u16) -> Result<(Vec<u8>, Duration), String> {
    get_within(port, READ_WITHIN)
}

/// `get`, giving up after `within` on each step.
fn get_within(port: u16, within: Duration) -> Result<(Vec<u8>, Duration), String> {
    let started = Instant::now();
    let address: SocketAddr = ([127, 0, 0, 1], port).into();
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
fn body_of(answer: &[u8]) -> Result<Vec<u8>, String> {
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
fn check_body(body: &[u8]) -> Result<(), String> {
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

/// The requests of the run: twenty in a row, eight at once.
fn requests(port: u16, started: Instant) -> Result<(u128, u128), String> {
    // The first request waits for `httpd` to listen. A SYN that comes before
    // the server listens gets no RST that arrives (the stack's answer is
    // dropped while it asks for the gateway's address), and QEMU sends the
    // SYN again after seconds: the request starts again after two.
    let first = loop {
        match get_within(port, Duration::from_secs(2)) {
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
        let (body, time) = get(port).map_err(|e| format!("request {n}: {e}"))?;
        check_body(&body).map_err(|e| format!("request {n}: {e}"))?;
        times.push(time);
    }
    let threads: Vec<_> = (0..CONCURRENT)
        .map(|_| std::thread::spawn(move || get(port)))
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
fn lease_address(line: &str) -> Option<String> {
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
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let (name, programs) = if steps {
        (STEPS_IMAGE, steps_programs())
    } else {
        (net::IMAGE, net::programs())
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let tcp = free_tcp_port()?;
    let udp_port = free_udp_port()?;
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
    ];
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&forwards));
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
        run.expect("# ", DIALOG_STEP)?;
        run.send("httpd -f -p 80 -h /www & H=$!")?;
        run.expect("# ", DIALOG_STEP)?;
        let timing = requests(tcp, started)?;
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
        // A new server on the port the first one used.
        run.send("kill $H")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("httpd -f -p 80 -h /www &")?;
        run.expect("# ", DIALOG_STEP)?;
        let (body, _) = loop {
            match get(tcp) {
                Ok(answer) => break answer,
                Err(why) if started.elapsed() < RUN_WITHIN => {
                    let _ = why;
                    std::thread::sleep(Duration::from_millis(300));
                }
                Err(why) => return Err(format!("the request to the new httpd: {why}")),
            }
        };
        check_body(&body).map_err(|e| format!("the new httpd: {e}"))?;
        println!("net-curl: a new httpd on the same port ok");
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
    fn the_steps_image_builds_the_service_with_the_counting_of_steps() {
        let netd = steps_programs().iter().find(|p| p.0 == "netd").unwrap();
        assert_eq!(netd.3, &["steps"]);
        assert!(steps_programs().iter().any(|p| p.0 == "ash-launcher"));
    }
}
