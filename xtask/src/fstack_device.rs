// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of F-Stack on the second network device (`cargo xtask
//! fstack-probe device`, stage P6b-2 of subproject 6): the TCP/IP stack of
//! FreeBSD 15 in a process that claimed the device (tests/fstack-probe/
//! device.c, ports/f-stack/ff_stafeto_if.c over libvirtio_net.a), on the
//! image with both devices (`table-fstack-device`) and `/etc/netd.conf` with
//! `handover 1` and the static `address1 10.0.3.15/24`. The second device's
//! user network forwards UDP 7 and TCP 80 of the host to that address. xtask
//! drives the shell:
//!
//! 1. `fstack-probe device &`: the stack starts on the device; 300
//!    datagrams of the echo come back byte for byte (slirp asks ARP for the
//!    address first, and the stack answers); the page of 1 MiB comes three
//!    times in turn and four at once, byte for byte; the latency of a
//!    datagram after a pause (the interrupts on, the queue looked at again);
//!    the rate of the echo with 32 datagrams in flight; the layer's counters
//!    (`?stats`): the frames came in without a copy, an ARP reply went to the
//!    network service through the bypass ring; `?stop` ends the program and
//!    the device comes back;
//! 2. `fstack-probe device hold &`: 500 connections of TCP 80 each send
//!    twenty segments that nobody reads, so the stack keeps more than the pool
//!    holds above the threshold of the layer; the echo of UDP on another
//!    socket still answers, and some frames were copied.
//!
//! `cargo xtask fstack-probe device steps` runs the first part under
//! -icount with the network service counting its steps, the program first
//! putting 16 frames of DHCP in the bypass ring at once (`flood`), and judges
//! every step of the service against 0.9 of term B (CLAIM, CLAIM_MORE, KICK
//! and the service's own steps among them).

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::fast_probe::{echoes, expect_all, steps_verdict};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, INIT_STACK_SIZE, ImageProgram, SERVICES_STARTED,
    Variant, build, build_boot_image, busybox_build, nano_build, net, net_probe, qemu, relibc,
    symbolize,
};

/// The images: the probe, and the probe with the steps counted.
pub const IMAGE: &str = "boot-fstack-device.img";
pub const STEPS_IMAGE: &str = "boot-fstack-device-steps.img";
/// The image whose second device runs DHCP: the stack's address is a lease,
/// and the service's client renews it through the bypass ring.
pub const DHCP_IMAGE: &str = "boot-fstack-device-dhcp.img";

/// `/etc/netd.conf` of the image with DHCP on the second device.
pub const NETD_CONF_DHCP: &[u8] = b"handover 1\n";

/// `/etc/netd.conf` of the images: the second device may go to a program,
/// and its address is fixed.
pub const NETD_CONF: &[u8] = b"handover 1\naddress1 10.0.3.15/24\n";

const UDP_PORT: u16 = 7;
const TCP_PORT: u16 = 80;
pub(crate) const PAGE_BYTES: usize = 1 << 20;
const HOLD_CONNECTIONS: usize = 500;
const HOLD_SEGMENTS: usize = 20;
const HOLD_BYTES: usize = 200;
/// The buffers free once the held connections are closed: the pool of 8 192
/// less the two queues of 256 and a margin for frames the stack still holds.
const POOL_FREE_MIN: u64 = 8192 - 2 * 256 - 64;
/// The most the median of the echo after a pause may take: a tenth of the
/// stack's clock tick and a little over the times the probe sees (0.1 to
/// 1.1 ms on TCG and HVF).
const IDLE_MEDIAN_MAX_US: u64 = 3000;

/// How long a line may take on TCG, and under -icount.
const LINE_WITHIN: Duration = Duration::from_secs(60);
const LINE_WITHIN_STEPS: Duration = Duration::from_secs(240);

/// The programs of the image: the network image's with the table of both
/// devices and the larger quota of the shell's commands.
pub fn programs(steps: bool) -> &'static [ImageProgram] {
    static PLAIN: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    static STEPS: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    let list = if steps { &STEPS } else { &PLAIN };
    list.get_or_init(|| {
        let mut programs = net::programs().to_vec();
        programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-fstack-device"]);
        programs.push(("fstack-probe", "fstack-probe", 0, &["dynamic"]));
        if steps {
            for program in &mut programs {
                if program.0 == "netd" {
                    program.3 = &["steps"];
                }
            }
        }
        programs
    })
}

/// Byte `i` of the page (device.c: page_byte).
pub(crate) fn page_byte(i: usize) -> u8 {
    (i as u32)
        .wrapping_mul(7)
        .wrapping_add((i >> 8) as u32)
        .wrapping_add((i >> 16) as u32) as u8
}

/// One request for the page: the head and the first `want` bytes of the body,
/// each compared; the seconds it took.
pub(crate) fn fetch(port: u16, want: usize) -> Result<f64, String> {
    let started = Instant::now();
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| format!("timeout: {e}"))?;
    stream
        .write_all(b"GET /page HTTP/1.1\r\nHost: probe\r\n\r\n")
        .map_err(|e| format!("request: {e}"))?;
    let head =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {PAGE_BYTES}\r\nConnection: close\r\n\r\n");
    let mut got = vec![0u8; head.len() + want];
    stream
        .read_exact(&mut got)
        .map_err(|e| format!("the page ({} bytes wanted): {e}", got.len()))?;
    if got[..head.len()] != *head.as_bytes() {
        return Err(format!(
            "the head of the page is {:?}",
            String::from_utf8_lossy(&got[..head.len()])
        ));
    }
    for (i, byte) in got[head.len()..].iter().enumerate() {
        if *byte != page_byte(i) {
            return Err(format!(
                "byte {i} of the page is {byte}, wanted {}",
                page_byte(i)
            ));
        }
    }
    Ok(started.elapsed().as_secs_f64())
}

/// The counters of the layer: `key=value` words.
fn stats_of(socket: &UdpSocket) -> Result<Vec<(String, u64)>, String> {
    let mut got = vec![0u8; 2048];
    for _ in 0..5 {
        socket.send(b"?stats").map_err(|e| format!("?stats: {e}"))?;
        if let Ok(len) = socket.recv(&mut got) {
            let text = String::from_utf8_lossy(&got[..len]).into_owned();
            return Ok(text
                .split_whitespace()
                .filter_map(|w| w.split_once('='))
                .filter_map(|(k, v)| v.parse().ok().map(|v| (k.to_owned(), v)))
                .collect());
        }
    }
    Err("no answer to ?stats".to_owned())
}

fn stat(stats: &[(String, u64)], key: &str) -> u64 {
    stats.iter().find(|(k, _)| k == key).map_or(0, |(_, v)| *v)
}

/// The median and the 90th percentile of the round trips of single datagrams
/// sent after a pause of 60 ms each, in microseconds.
fn idle_latency(socket: &UdpSocket, count: usize) -> Result<(u64, u64), String> {
    let mut got = vec![0u8; 2048];
    let mut times = Vec::new();
    for n in 0..count {
        std::thread::sleep(Duration::from_millis(60));
        let sent = [n as u8; 32];
        let started = Instant::now();
        let mut answered = false;
        for _ in 0..3 {
            socket.send(&sent).map_err(|e| format!("latency: {e}"))?;
            if socket.recv(&mut got).is_ok() {
                answered = true;
                break;
            }
        }
        if !answered {
            return Err(format!("latency datagram {n}: no echo"));
        }
        times.push(started.elapsed().as_micros() as u64);
    }
    times.sort_unstable();
    Ok((times[times.len() / 2], times[times.len() * 9 / 10]))
}

/// Datagrams per second of the echo with `window` in flight.
fn echo_rate(socket: &UdpSocket, total: usize, window: usize) -> Result<f64, String> {
    let mut got = vec![0u8; 2048];
    let started = Instant::now();
    let mut done = 0;
    while done < total {
        let batch = window.min(total - done);
        for n in 0..batch {
            let sent = [(done + n) as u8; 64];
            socket.send(&sent).map_err(|e| format!("rate: {e}"))?;
        }
        let mut seen = 0;
        while seen < batch {
            match socket.recv(&mut got) {
                Ok(_) => seen += 1,
                // A datagram lost to a full queue: count it as seen, the rate
                // is of what came back.
                Err(_) => break,
            }
        }
        done += batch;
    }
    Ok(total as f64 / started.elapsed().as_secs_f64())
}

/// `cargo xtask fstack-probe device [steps|dhcp|static] [tcg|hvf]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let (only, steps, rest) = match args.first().map(String::as_str) {
        Some("steps") => (None, true, &args[1..]),
        Some("dhcp") => (Some(true), false, &args[1..]),
        Some("static") => (Some(false), false, &args[1..]),
        _ => (None, false, args),
    };
    let machine = match rest {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => {
            return Err(
                "usage: cargo xtask fstack-probe device [steps|dhcp|static] [tcg|hvf]".to_owned(),
            );
        }
    };
    match only {
        Some(dhcp) => session(machine, false, dhcp),
        None => probe(machine, steps),
    }
}

pub(crate) fn free_port(tcp: bool) -> Result<u16, String> {
    if tcp {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .map(|a| a.port())
            .map_err(|e| format!("a free TCP port: {e}"))
    } else {
        UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .map(|a| a.port())
            .map_err(|e| format!("a free UDP port: {e}"))
    }
}

/// The hold part: connections that send and are never read.
fn hold(udp: &UdpSocket, tcp_port: u16) -> Result<Vec<(String, u64)>, String> {
    let mut streams = Vec::new();
    for n in 0..HOLD_CONNECTIONS {
        let stream = TcpStream::connect(("127.0.0.1", tcp_port))
            .map_err(|e| format!("hold connect {n}: {e}"))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("nodelay: {e}"))?;
        streams.push(stream);
    }
    let chunk = [0x5a_u8; HOLD_BYTES];
    for round in 0..HOLD_SEGMENTS {
        for (n, stream) in streams.iter_mut().enumerate() {
            if let Err(e) = stream.write_all(&chunk) {
                return Err(format!(
                    "hold write {n} (port {:?}) of round {round}: {e}",
                    stream.local_addr().map(|a| a.port())
                ));
            }
        }
        // Let the stack and slirp take the round before the next.
        std::thread::sleep(Duration::from_millis(100));
    }
    // The stack keeps the segments. The echo on another socket still answers.
    let again = echoes(udp, 50, 64)?;
    let stats = stats_of(udp)?;
    drop(streams);
    println!("hold: the echo answered with {again} datagrams sent again");
    Ok(stats)
}

/// Both runs: the second device with its fixed address, then (not under
/// -icount) with a lease.
pub fn probe(machine: &'static qemu::Machine, steps: bool) -> Result<(), String> {
    session(machine, steps, false)?;
    if !steps {
        session(machine, false, true)?;
    }
    Ok(())
}

fn session(machine: &'static qemu::Machine, steps: bool, dhcp: bool) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let name = match (steps, dhcp) {
        (true, _) => STEPS_IMAGE,
        (false, false) => IMAGE,
        (false, true) => DHCP_IMAGE,
    };
    let image = build_boot_image(name, programs(steps), BOOT_PROFILE)?;
    let udp_host = free_port(false)?;
    let tcp_host = free_port(true)?;
    let udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("a UDP socket: {e}"))?;
    udp.connect(("127.0.0.1", udp_host))
        .map_err(|e| format!("connect: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_secs(if steps { 10 } else { 2 })))
        .map_err(|e| format!("timeout: {e}"))?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    cmd.args(qemu::net_two_with(&[
        qemu::Forward {
            proto: qemu::Proto::Udp,
            host: udp_host,
            guest: UDP_PORT,
        },
        qemu::Forward {
            proto: qemu::Proto::Tcp,
            host: tcp_host,
            guest: TCP_PORT,
        },
    ]));
    if steps {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let within = if steps {
        LINE_WITHIN_STEPS
    } else {
        LINE_WITHIN
    };
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let back = "net: device 1 back";
    let mut notes = Vec::new();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        let second = if dhcp {
            "net: lease1 10.0.3.15/24"
        } else {
            "net: static1 10.0.3.15/24"
        };
        expect_all(&mut run, &["net: lease 10.0.2.15/24", second], BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        let began = Instant::now();
        run.send(&format!(
            "fstack-probe device {}&",
            if steps { "flood " } else { "" }
        ))?;
        let mut first = vec![
            "fstack-probe: device up 10.0.3.15/24 mac ",
            "fstack-probe: device serving",
        ];
        if steps {
            first.push("fstack-probe: flood taken");
        }
        if dhcp {
            first.push("net: renew1 10.0.3.15/24");
        }
        expect_all(&mut run, &first, within)?;
        notes.push(format!(
            "claim, stack start and serving {} ms",
            began.elapsed().as_millis()
        ));
        if dhcp {
            // The service's client asks for its lease again through the
            // bypass ring, both ways, while the stack answers ARP and the
            // echo with the leased address.
            let again = echoes(&udp, 100, 64)?;
            let stats = stats_of(&udp)?;
            if stat(&stats, "bypass") < 2 || stat(&stats, "tx_bypass") < 2 {
                return Err(format!(
                    "the lease went through the ring {} times in and {} out: {stats:?}",
                    stat(&stats, "bypass"),
                    stat(&stats, "tx_bypass")
                ));
            }
            notes.push(format!(
                "lease again through the ring: {} frames to the service, {} from it; 100 echoes ({again} sent again)",
                stat(&stats, "bypass"),
                stat(&stats, "tx_bypass")
            ));
            udp.send(b"?stop").map_err(|e| format!("?stop: {e}"))?;
            expect_all(
                &mut run,
                &[
                    "fstack-probe: device ended",
                    back,
                    "net: lease1 10.0.3.15/24",
                ],
                within,
            )?;
            run.send("echo probe-end")?;
            run.expect("probe-end", DIALOG_STEP)?;
            return Ok(());
        }
        let again = echoes(&udp, if steps { 30 } else { 200 }, 64)?;
        let again = again + if steps { 0 } else { echoes(&udp, 100, 1400)? };
        notes.push(format!("echoes ({again} sent again)"));
        if steps {
            let took = fetch(tcp_host, 65536)?;
            notes.push(format!("64 KiB of the page in {took:.2} s"));
        } else {
            let mut total = 0.0;
            for _ in 0..3 {
                total += fetch(tcp_host, PAGE_BYTES)?;
            }
            notes.push(format!(
                "3 pages of 1 MiB in turn in {total:.2} s ({:.1} MiB/s)",
                3.0 / total
            ));
            let at_once: Vec<_> = (0..4)
                .map(|_| std::thread::spawn(move || fetch(tcp_host, PAGE_BYTES)))
                .collect();
            let mut slowest = 0.0f64;
            for handle in at_once {
                slowest = slowest.max(handle.join().map_err(|_| "a fetch panicked".to_owned())??);
            }
            notes.push(format!("4 pages at once, the slowest in {slowest:.2} s"));
            let (median, p90) = idle_latency(&udp, 40)?;
            notes.push(format!(
                "echo after a pause of 60 ms: median {median} us, 90th percentile {p90} us"
            ));
            // The interrupts on while idle wake the stack at once; without
            // them it looks at the queue at its next clock tick (10 ms).
            if median > IDLE_MEDIAN_MAX_US {
                return Err(format!(
                    "a datagram after a pause took {median} us at the median, over {IDLE_MEDIAN_MAX_US}: the idle stack does not wake on the device's interrupt"
                ));
            }
            let rate = echo_rate(&udp, 3000, 32)?;
            notes.push(format!("echo rate with 32 in flight {rate:.0} datagrams/s"));
        }
        let stats = stats_of(&udp)?;
        let get = |k: &str| stat(&stats, k);
        if get("bypass") < 1 {
            return Err(format!("no frame went to the bypass ring: {stats:?}"));
        }
        if get("zero_copy") == 0 || get("copied") != 0 {
            return Err(format!(
                "the frames came in with {} without a copy and {} copied: {stats:?}",
                get("zero_copy"),
                get("copied")
            ));
        }
        if get("tx_no_buffer") != 0 || get("tx_full") != 0 || get("no_mbuf") != 0 {
            return Err(format!("frames were dropped by the layer: {stats:?}"));
        }
        let freq = get("freq").max(1);
        // Nanoseconds a frame costs the layer, from the totals of the counter.
        let ns = |ticks: u64, frames: u64| ticks as f64 * 1e9 / freq as f64 / frames.max(1) as f64;
        notes.push(format!(
            "per frame: receive in the layer {:.0} ns, handing to the stack {:.0} ns ({} frames), send with the copy {:.0} ns ({} frames); counter {freq} Hz",
            ns(get("rx_layer_ticks"), get("rx")),
            ns(get("rx_input_ticks"), get("rx")),
            get("rx"),
            ns(get("tx_send_ticks"), get("tx")),
            get("tx")
        ));
        notes.push(format!(
            "frames to the service {}, from it {}, doorbells {}, sleeps {} ({} found work), notifications {}",
            get("bypass"),
            get("tx_bypass"),
            get("kicks"),
            get("sleeps"),
            get("found_work"),
            get("notifications")
        ));
        udp.send(b"?stop").map_err(|e| format!("?stop: {e}"))?;
        expect_all(&mut run, &["fstack-probe: device ended", back], within)?;
        if !steps {
            // Connections nobody reads: the threshold of the layer.
            run.send("fstack-probe device hold &")?;
            expect_all(&mut run, &["fstack-probe: device serving"], within)?;
            let held_at = Instant::now();
            let stats = hold(&udp, tcp_host)?;
            let get = |k: &str| stat(&stats, k);
            notes.push(format!(
                "hold: {} connections, {} segments in {:.1} s; frames in {}, without a copy {}, copied {}, fewest free buffers {} of 8 192",
                get("accepted"),
                HOLD_CONNECTIONS * HOLD_SEGMENTS,
                held_at.elapsed().as_secs_f64(),
                get("rx"),
                get("zero_copy"),
                get("copied"),
                get("free_low")
            ));
            if get("copied") == 0 {
                return Err(format!(
                    "no frame was copied below the threshold: {stats:?}"
                ));
            }
            if get("no_mbuf") != 0 {
                return Err(format!("frames lost to the stack's memory: {stats:?}"));
            }
            if get("accepted") != HOLD_CONNECTIONS as u64 {
                return Err(format!(
                    "{} connections were accepted, wanted {HOLD_CONNECTIONS}: {stats:?}",
                    get("accepted")
                ));
            }
            // The held connections close: their buffers all come back to the
            // pool, but for the two queues of the device.
            let mut got = vec![0u8; 64];
            // The closing of 500 connections may take longer than the read
            // timeout; the command is the same again.
            let mut released = false;
            for _ in 0..5 {
                udp.send(b"?release")
                    .map_err(|e| format!("?release: {e}"))?;
                if udp.recv(&mut got).is_ok() {
                    released = true;
                    break;
                }
            }
            if !released {
                return Err("no answer to ?release".to_owned());
            }
            std::thread::sleep(Duration::from_millis(500));
            let stats = stats_of(&udp)?;
            let free = stat(&stats, "free_now");
            if free < POOL_FREE_MIN {
                return Err(format!(
                    "after the held connections closed {free} buffers are free, wanted {POOL_FREE_MIN}: {stats:?}"
                ));
            }
            notes.push(format!(
                "after the release {free} of 8 192 buffers are free"
            ));
            udp.send(b"?stop").map_err(|e| format!("?stop: {e}"))?;
            expect_all(&mut run, &["fstack-probe: device ended", back], within)?;
        }
        run.send("echo probe-end")?;
        run.expect("probe-end", DIALOG_STEP)?;
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended")
            || line.contains("net: bypass broken")
            || line.contains("fstack-probe: check failed")
    }) {
        return Err("the image of the stack on the device faulted".into());
    }
    if steps {
        let rows = steps_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "fstack-probe device steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            net_probe::STEP_MAX
        );
    }
    println!(
        "fstack-probe device{} passed in {:.0} s on {}: {}",
        if dhcp { " dhcp" } else { "" },
        started.elapsed().as_secs_f64(),
        machine.name,
        notes.join("; ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The image has the table of both devices with the larger quotas, the
    /// probe, and the file that allows the claim and fixes the address.
    #[test]
    fn the_image_has_both_devices_and_the_stack() {
        assert_eq!(programs(false)[0].3, &["table-fstack-device"]);
        let netd = programs(true).iter().find(|p| p.0 == "netd").unwrap();
        assert_eq!(netd.3, &["steps"]);
        assert!(programs(false).iter().any(|p| p.0 == "fstack-probe"));
        assert_eq!(NETD_CONF, b"handover 1\naddress1 10.0.3.15/24\n");
        assert_eq!(NETD_CONF_DHCP, b"handover 1\n");
    }

    /// A burst of connections reaches a stack that has not yet learned its
    /// gateway: the answers wait for the ARP reply in the entry's hold queue,
    /// which keeps one packet unless the setting is wide.
    #[test]
    fn the_arp_hold_queue_fits_a_burst_of_answers() {
        let ini = include_str!("../../ports/f-stack/fstack.ini");
        let hold: usize = ini
            .lines()
            .find_map(|l| l.strip_prefix("net.link.ether.inet.maxhold="))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(hold >= HOLD_CONNECTIONS);
    }

    /// The page's pattern is the program's.
    #[test]
    fn the_page_is_the_programs() {
        let source =
            std::fs::read_to_string(crate::root().join("tests/fstack-probe/device.c")).unwrap();
        assert!(source.contains("return (unsigned char)(i * 7u + (i >> 8) + (i >> 16));"));
        assert_eq!(page_byte(0), 0);
        assert_eq!(page_byte(300), (300u32 * 7 + 1) as u8);
        assert_eq!(page_byte(70000), (70000u32 * 7 + 273 + 1) as u8);
    }

    /// The lines and counters xtask waits for are those the program prints.
    #[test]
    fn the_lines_are_those_of_the_program() {
        let source =
            std::fs::read_to_string(crate::root().join("tests/fstack-probe/device.c")).unwrap();
        for text in [
            "device up ",
            "device serving",
            "flood taken",
            "device ended",
            "zero_copy=",
            "copied=",
            "rx_layer_per_frame=",
            "rx_input_per_frame=",
            "tx_per_frame=",
            "free_low=",
            "bypass=",
            "accepted=",
        ] {
            assert!(source.contains(text), "{text}");
        }
    }

    #[test]
    fn counters_are_read_from_their_words() {
        let stats = vec![("rx".to_owned(), 5), ("tx".to_owned(), 7)];
        assert_eq!(stat(&stats, "tx"), 7);
        assert_eq!(stat(&stats, "none"), 0);
    }
}
