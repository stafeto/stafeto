// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the network service on Apple VZ (`cargo xtask net-vz [--net
//! 2] [--static1]`): the shell image with the network service on the NAT of
//! the Virtualization framework. The Mac stands on the bridge of the NAT
//! (192.168.64.1) and reaches the guest at the address of its lease, which
//! the probe reads from the line `net: lease A/N gw G dns D` of the
//! console. With one network device:
//!
//! 1. the line of the driver (`virtio-net: 1af4:1041 at ...`, the fixed MAC
//!    of `vz-run` with the suffix the run claimed), the lease within 20 s of
//!    the start of the services, the gateway in the network of the address, and the first interrupt;
//! 2. a connection to a port with no listener ends in a refusal within a
//!    second (the RST of the guest to the first SYN is not lost);
//! 3. `httpd -f -p 80 -h /www &`, twenty requests in a row and eight at
//!    once, each body the page of the image;
//! 4. the Mac's `ping` of the guest: 5 echoes of 56 bytes, 5 of 1 472 bytes,
//!    200 of 1 472 bytes 0.1 s apart, every one answered, and a request
//!    after them.
//!
//! With two devices the same for the first, and the second device leases an
//! address (`net: lease1`, or with `--static1` the static one of
//! `netd.conf`), prints its own lines, answers no echo (it serves only
//! DHCP), and the Mac's ARP cache holds its MAC address for it.
//!
//! With `--fast` (two devices, `--static1` too) the image is the one of
//! `cargo xtask fast-probe` on VZ (`handover 1` and `fast-echo`). The checks
//! above run, the second device being the service's until the claim; then
//! `fast-echo 7 &` claims it (`claimed`, and with a lease `net: renew1`: the
//! lease again through the bypass ring), and the Mac reaches the program at
//! the second address: 300 UDP datagrams of 64 and 1 400 bytes come back
//! byte for byte, the echo rate at both sizes, `ping` of the address
//! answered, and `arp -n` shows the MAC address of the device. `kill -9` of
//! the program gives the device back (`net: device 1 back`, then the lease
//! or the static address), and a second program claims it and echoes. HTTP to
//! the first address passes before, during and after.
//!
//! The Mac may refuse to connect to the guest ("No route to host") when the
//! terminal has no permission for the local network (System Settings,
//! Privacy and Security, Local Network).

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::fast_nginx;
use crate::fast_probe;
use crate::net_curl;
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net, net_probe, qemu, relibc, rootfs, vz,
};

/// The lease within this long after the services started.
const LEASE_WITHIN: Duration = Duration::from_secs(20);
/// The second device's lease within this long.
const LEASE1_WITHIN: Duration = Duration::from_secs(30);
/// The probe may take this long from the start of the machine.
const RUN_WITHIN: Duration = Duration::from_secs(60 * 4);
/// With nginx on the stack: the load of `wrk` takes 40 s of it.
const RUN_WITHIN_NGINX: Duration = Duration::from_secs(60 * 7);
/// The closed port must refuse within this long. The two seconds are for the
/// behaviour of XNU: a RST that answers an ECN-setup SYN from a local peer is
/// dropped, and the SYN is sent again without ECN after one second, whose
/// refusal comes at 1.0 s (the guest's RST is right: right MAC, right
/// acknowledgement).
const REFUSAL_WITHIN: Duration = Duration::from_secs(2);
/// The kind of the steps of the second device's return, and their bound on
/// VZ: 50 ms of the counter (24 MHz), for the two sub-steps that touch the
/// device first after the host reset it (details 1, the reset, and 2, the
/// open) and for an own step that gets there first after an owner's death;
/// the other sub-steps of the return keep 0.9 of term B.
const RETURN_KIND: usize = 65;
const RETURN_MAX: u64 = 1_200_000;
/// The same after nginx on the stack served `wrk -c200` and was told to quit:
/// the host's reset of a device that has just carried a load took 27 to 86 ms
/// (the runs of stage P6b-3), against 16 to 20 ms of an idle one. 100 ms of
/// the counter.
const RETURN_MAX_AFTER_LOAD: u64 = 2_400_000;
/// Whether a line of steps is one the host's reset of the device delays: a
/// step of kind 65 with detail 1 (the reset) or 2 (the open), or, after the
/// owner was killed, with detail 0 (whichever own step touches the device
/// first after the reset: the interrupt's, the owner's departure).
fn is_return_step(line: &str, after_kill: bool) -> bool {
    line.contains(&format!("kind {RETURN_KIND} "))
        && line.rsplit_once("detail ").is_some_and(|(_, d)| {
            d.trim()
                .parse::<u64>()
                .is_ok_and(|d| d == 1 || d == 2 || (d == 0 && after_kill))
        })
}

/// The leases file of the DHCP service of macOS.
const LEASES: &str = "/var/db/dhcpd_leases";

/// A MAC address with one or two digits a byte, as two digits.
fn normal_mac(text: &str) -> Option<String> {
    let bytes: Vec<u8> = text
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).ok())
        .collect::<Option<_>>()?;
    (bytes.len() == 6).then(|| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

/// The address the leases file `text` holds for `mac`: the first entry, the
/// newest, wins. Its entries are
/// blocks of `key=value` lines, the MAC address in `hw_address=1,2:73:...`
/// with one digit for a zero byte.
pub fn leased_to(text: &str, mac: &str) -> Option<Ipv4Addr> {
    for block in text.split('}') {
        let value = |key: &str| {
            block
                .lines()
                .find_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))
        };
        let hw = value("hw_address").and_then(|h| h.split_once(',').map(|(_, m)| m));
        if hw.and_then(normal_mac).as_deref() == Some(mac)
            && let Some(address) = value("ip_address").and_then(|a| a.trim().parse().ok())
        {
            return Some(address);
        }
    }
    None
}

/// Whether the DHCP service gave `mac` the address `lease` the console
/// shows: a foreign guest with the same MAC address would own the lease
/// instead. A leases file that cannot be read or has no entry yet is no
/// evidence; the line says so and the check goes on.
pub fn lease_is_ours(who: &str, mac: &str, lease: Ipv4Addr) -> Result<(), String> {
    let Ok(text) = std::fs::read_to_string(LEASES) else {
        println!("{who}: {LEASES} cannot be read; the lease of {mac} is not cross-checked");
        return Ok(());
    };
    match leased_to(&text, mac) {
        Some(address) if address == lease => {
            println!("{who}: {LEASES} gives {lease} to {mac}");
            Ok(())
        }
        Some(address) => Err(format!(
            "{LEASES} gives {address} to {mac}, the console shows {lease}"
        )),
        None => {
            println!("{who}: {LEASES} has no entry for {mac} yet");
            Ok(())
        }
    }
}

/// The ARP cache of the Mac must show `mac` for `address`.
fn arp_is(address: Ipv4Addr, mac: &str) -> Result<(), String> {
    let arp = Command::new("/usr/sbin/arp")
        .args(["-n", &address.to_string()])
        .output()
        .map_err(|e| format!("arp: {e}"))?;
    let text = String::from_utf8_lossy(&arp.stdout).into_owned();
    let got = arp_mac(&text).ok_or_else(|| format!("arp has no entry for {address}: {text}"))?;
    if got != mac {
        return Err(format!("arp gives {got} for {address}, wanted {mac}"));
    }
    println!("net-vz: arp -n {address} shows {got}");
    Ok(())
}
/// The static address of the second device in the image `--static1`.
const STATIC1: &str = "192.168.64.250";

/// What the guest's line of a lease or a static address says.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Address {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Option<Ipv4Addr>,
}

/// The settings in a line `net: TAG A/N [gw G] [dns D]`, for the tag
/// `lease`, `lease1` or `static1`.
pub fn parse_address(line: &str, tag: &str) -> Option<Address> {
    let rest = line.split(&format!("net: {tag} ")).nth(1)?;
    let mut words = rest.split_whitespace();
    let (address, prefix) = words.next()?.split_once('/')?;
    let mut found = Address {
        address: address.parse().ok()?,
        prefix: prefix.parse().ok()?,
        gateway: None,
        dns: None,
    };
    while let Some(key) = words.next() {
        let value = words.next()?.parse().ok();
        match key {
            "gw" => found.gateway = value,
            "dns" => found.dns = value,
            _ => return None,
        }
    }
    Some(found)
}

/// Whether `a` and `b` are in one network of `prefix` bits.
pub fn same_network(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix.min(32)))
        .unwrap_or(0);
    u32::from(a) & mask == u32::from(b) & mask
}

/// What `ping` printed: the packets sent and received, and the
/// round-trip line, if any.
#[derive(Debug, PartialEq)]
pub struct PingResult {
    pub sent: u32,
    pub received: u32,
    pub round_trip: Option<String>,
}

pub fn parse_ping(output: &str) -> Option<PingResult> {
    let line = output.lines().find(|l| l.contains("packets transmitted"))?;
    let number = |after: &str| -> Option<u32> {
        let (before, _) = line.split_once(after)?;
        before
            .rsplit([' ', ','])
            .find(|w| !w.is_empty())?
            .parse()
            .ok()
    };
    Some(PingResult {
        sent: number(" packets transmitted")?,
        received: number(" packets received")?,
        round_trip: output
            .lines()
            .find(|l| l.contains("round-trip"))
            .map(|l| l.trim().to_owned()),
    })
}

/// The MAC address in the output of `arp -n ADDRESS`, as two digits per
/// byte (macOS prints `2:73:74:66:0:2`).
pub fn arp_mac(output: &str) -> Option<String> {
    normal_mac(output.split(" at ").nth(1)?.split_whitespace().next()?)
}

/// The first line of the run that `wanted` takes: one that came already, or
/// the next that comes within `within`.
fn line_where(
    run: &mut qemu::Run,
    what: &str,
    wanted: impl Fn(&str) -> bool,
    within: Duration,
) -> Result<String, String> {
    if let Some(line) = run.lines().iter().find(|l| wanted(l)) {
        return Ok(line.clone());
    }
    run.expect_line(what, wanted, within)
}

struct Options {
    devices: usize,
    static1: bool,
    /// The service counts its steps (`netd` built with `steps`), and the
    /// longest of each kind is judged by 0.9 of term B.
    steps: bool,
    /// The second device goes to `fast-echo` (the image of the owner).
    fast: bool,
    /// The second device goes to nginx on the stack (`--fast --static1`
    /// with it): the image of `cargo xtask fast-probe nginx` on VZ.
    nginx: bool,
}

fn options(args: &[String]) -> Result<Options, String> {
    let usage = "usage: cargo xtask net-vz [--net 2] [--static1] [--steps] [--fast] [--nginx]";
    let mut found = Options {
        devices: 1,
        static1: false,
        steps: false,
        fast: false,
        nginx: false,
    };
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--net" if rest.next().map(String::as_str) == Some("2") => found.devices = 2,
            "--static1" => found.static1 = true,
            "--steps" => found.steps = true,
            "--fast" => {
                found.fast = true;
                found.devices = 2;
            }
            "--nginx" => {
                found.nginx = true;
                found.fast = true;
                found.devices = 2;
            }
            _ => return Err(usage.to_owned()),
        }
    }
    if found.nginx && !found.static1 {
        return Err("--nginx belongs to --static1 (the address of the page is fixed)".to_owned());
    }
    if found.static1 && found.devices != 2 {
        return Err("--static1 belongs to --net 2".to_owned());
    }
    Ok(found)
}

pub(crate) fn ping(
    address: Ipv4Addr,
    count: u32,
    size: u32,
    interval: Option<&str>,
) -> Result<PingResult, String> {
    let mut cmd = Command::new("/sbin/ping");
    cmd.args(["-c", &count.to_string(), "-s", &size.to_string()]);
    if let Some(interval) = interval {
        cmd.args(["-i", interval]);
    }
    cmd.arg(address.to_string());
    let output = cmd.output().map_err(|e| format!("ping: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    parse_ping(&text).ok_or_else(|| format!("ping of {address} printed no summary: {text}"))
}

fn http(address: Ipv4Addr) -> SocketAddr {
    (address, 80).into()
}

/// The check of the first device after its lease.
fn first_device(
    run: &mut qemu::Run,
    started: Instant,
    services_at: Duration,
    mac: &str,
) -> Result<Address, String> {
    let mac = format!("mac {mac}");
    let driver = line_where(
        run,
        "the driver's line",
        |l| l.starts_with("virtio-net: 1af4:1041 at "),
        BOOT_TIMEOUT,
    )?;
    let expected = format!("virtio-net: 1af4:1041 at 0x40008000, line 65, status 0x0, {mac}");
    if driver != expected {
        return Err(format!("the driver says {driver:?}, wanted {expected:?}"));
    }
    let lease_line = line_where(
        run,
        "the lease",
        |l| l.contains("net: lease "),
        BOOT_TIMEOUT,
    )?;
    let lease_at = started.elapsed();
    let lease = parse_address(&lease_line, "lease").ok_or(format!("the lease {lease_line:?}"))?;
    println!(
        "net-vz: {mac}, {} (lease {:.2} s after the start of the machine, {:.2} s after the services)",
        lease_line.trim(),
        lease_at.as_secs_f64(),
        lease_at.saturating_sub(services_at).as_secs_f64()
    );
    if lease_at.saturating_sub(services_at) > LEASE_WITHIN {
        return Err(format!(
            "the lease came {:?} after the services",
            lease_at - services_at
        ));
    }
    let gateway = lease.gateway.ok_or("the lease has no gateway")?;
    if !same_network(lease.address, gateway, lease.prefix) {
        return Err(format!(
            "{} and the gateway {gateway} are in different networks",
            lease.address
        ));
    }
    run.expect_seen("virtio-net: first interrupt", DIALOG_STEP)?;
    Ok(lease)
}

/// A connection to a port with no listener is refused within a second.
fn closed_port(address: Ipv4Addr) -> Result<(), String> {
    let started = Instant::now();
    let target: SocketAddr = (address, 81).into();
    match TcpStream::connect_timeout(&target, REFUSAL_WITHIN) {
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            println!(
                "net-vz: the closed port {address}:81 refused in {} ms",
                started.elapsed().as_millis()
            );
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(65) => Err(format!(
            "{target}: {e}: the Mac has no route to the guest; allow the terminal the Local Network permission"
        )),
        other => Err(format!("{target}: {other:?}, wanted a refusal within 2 s")),
    }
}

pub fn command(args: &[String]) -> Result<(), String> {
    let options = options(args)?;
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let (name, two) = match (options.devices, options.static1, options.steps) {
        (_, _, false) if options.nginx => (fast_nginx::VZ_IMAGE, true),
        (_, _, true) if options.nginx => (fast_nginx::VZ_STEPS_IMAGE, true),
        (_, false, false) if options.fast => (fast_probe::VZ_IMAGE, true),
        (_, true, false) if options.fast => (fast_probe::VZ_STATIC_IMAGE, true),
        (_, _, true) if options.fast => (fast_probe::VZ_STEPS_IMAGE, true),
        (1, _, false) => (net::VZ_IMAGE, false),
        (1, _, true) => (net::VZ_STEPS_IMAGE, false),
        (_, false, false) => (net::VZ2_IMAGE, true),
        (_, true, false) => (net::VZ2_STATIC_IMAGE, true),
        (_, _, true) => (net::VZ2_STEPS_IMAGE, true),
    };
    let programs = if options.nginx {
        fast_nginx::programs(if options.steps {
            fast_nginx::Kind::VzSteps
        } else {
            fast_nginx::Kind::Vz
        })
    } else if options.fast {
        fast_probe::vz_programs(options.steps)
    } else if options.steps {
        net::vz_steps_programs(two)
    } else {
        net::vz_programs(two)
    };
    // The probe CA of nginx's certificate (the images of nginx).
    let ca = if options.nginx {
        crate::probe_ca::ensure(false)?
    } else {
        std::path::PathBuf::new()
    };
    let ca_dir = crate::target_dir().join("fast-nginx");
    if options.nginx {
        std::fs::create_dir_all(&ca_dir).map_err(|e| format!("{}: {e}", ca_dir.display()))?;
    }
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let suffix = vz::claim_suffix()?;
    let macs = [vz::mac(suffix.value, 0), vz::mac(suffix.value, 1)];
    let machine = vz::Machine {
        net: options.devices,
        mac_suffix: suffix.value,
        // The pool of nginx's commands is large (init's table).
        memory_mib: options.nginx.then_some(2048),
        ..vz::Machine::default()
    };
    let started = Instant::now();
    let mut run = qemu::Run::start(
        vz::command_on(&kernel.image, &image, machine)?,
        qemu::Input::Pipe,
    )?;
    let result = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        let services_at = started.elapsed();
        let first = first_device(&mut run, started, services_at, &macs[0])?;
        let guest = first.address;
        if let Err(why) = closed_port(guest) {
            if net_curl::CLOSED_PORT_NEEDS_GATEWAY_REQUEST && !why.contains("Local Network") {
                println!(
                    "net-vz: WARNING closed port: {why} (needs the ARP request of the gateway)"
                );
            } else {
                return Err(why);
            }
        }
        run.expect("# ", DIALOG_STEP)?;
        // The shell of the image of nginx has the quota of one command for
        // each process it runs (init's table): `httpd` and its eight children
        // are the first device's checks of the other images, and nginx's
        // own are below.
        let timing = if options.nginx {
            ping(guest, 2, 56, None)?;
            None
        } else {
            run.send("httpd -f -p 80 -h /www & H=$!")?;
            run.expect("# ", DIALOG_STEP)?;
            Some(net_curl::requests(http(guest), Instant::now())?)
        };
        // The guest has talked to the Mac: its address must be ours by the
        // ARP cache and by the DHCP service's file.
        arp_is(guest, &macs[0])?;
        lease_is_ours("net-vz", &macs[0], guest)?;
        if let Some(timing) = timing {
            println!(
                "net-vz: 20 requests in a row and 8 at once ok, {} ms median, {} ms the longest",
                timing.0, timing.1
            );
        }
        for (count, size, interval) in [(5, 56, None), (5, 1472, None), (200, 1472, Some("0.1"))] {
            let result = ping(guest, count, size, interval)?;
            println!(
                "net-vz: ping -c {count} -s {size}: {} of {} answered; {}",
                result.received,
                result.sent,
                result.round_trip.as_deref().unwrap_or("no round-trip line")
            );
            if result.received != count || result.sent != count {
                return Err(format!(
                    "ping -s {size}: {} of {count} answered",
                    result.received
                ));
            }
        }
        if !options.nginx {
            let (body, _) = net_curl::get_within(http(guest), Duration::from_secs(10))
                .map_err(|e| format!("the request after the pings: {e}"))?;
            net_curl::check_body(&body).map_err(|e| format!("after the pings: {e}"))?;
            println!("net-vz: the service is alive after the pings");
        }
        if options.devices == 2 {
            let second = second_device(&mut run, started, guest, options.static1, &macs[1])?;
            if !options.nginx {
                let (body, _) = net_curl::get_within(http(guest), Duration::from_secs(10))
                    .map_err(|e| format!("the request with two devices: {e}"))?;
                net_curl::check_body(&body).map_err(|e| format!("with two devices: {e}"))?;
                println!("net-vz: HTTP to the first device passes with two devices");
            }
            if options.nginx {
                fast_nginx::vz_run(&mut run, second.address, &ca, &ca_dir)?;
            } else if options.fast {
                owner(&mut run, guest, second, options.static1, &macs[1])?;
            }
        }
        Ok::<(), String>(())
    })();
    let output = run.stop();
    vz::stop_hint(result).map_err(|e| format!("net on VZ: {e}"))?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
    }) {
        return Err("the network image faulted".into());
    }
    if started.elapsed()
        > if options.nginx {
            RUN_WITHIN_NGINX
        } else {
            RUN_WITHIN
        }
    {
        return Err(format!(
            "the run took {:.0} s",
            started.elapsed().as_secs_f64()
        ));
    }
    if options.steps {
        let rows = net_probe::longest_over_starts(&output.lines);
        if rows.is_empty() {
            return Err("the service printed no line of steps".into());
        }
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "net-vz steps: the longest step is kind {} with {} ticks (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            net_probe::STEP_MAX
        );
        // The device that comes back from its owner is reset by the host: the
        // first access after the reset stalls the one virtual processor, so
        // the whole guest, for about 20 ms; a thread inside the service
        // cannot lift that. The steps that touch the device first (kind 65,
        // details 1 and 2, and after the owner's death any own step, detail
        // 0) have a bound of their own on VZ, 50 ms of the counter. The
        // others, the queues and the fill among them, keep 0.9 of term B.
        let mut after_kill = false;
        let (mut back, mut rest) = (Vec::new(), Vec::new());
        for line in &output.lines {
            after_kill |= line.contains("Killed") || line.contains("Quit");
            if is_return_step(line, after_kill) {
                back.push(line.clone());
            } else {
                rest.push(line.clone());
            }
        }
        if let Some(row) = net_probe::longest_over_starts(&rest)
            .iter()
            .find(|r| r.1 > net_probe::STEP_MAX)
        {
            return Err(format!("a step past 0.9 of term B: {row:?}"));
        }
        // The longest step of the return by its detail (1 reset, 2 open,
        // 3 and 4 the queues, 5 on the fill).
        let bound = if options.nginx {
            RETURN_MAX_AFTER_LOAD
        } else {
            RETURN_MAX
        };
        let mut returns: std::collections::BTreeMap<u64, u64> = Default::default();
        for line in &back {
            let words: Vec<&str> = line.split_whitespace().collect();
            if let Some(i) = words.iter().position(|w| *w == "ticks")
                && let (Some(ticks), Some(detail)) = (
                    words.get(i - 1).and_then(|w| w.parse::<u64>().ok()),
                    words.last().and_then(|w| w.parse::<u64>().ok()),
                )
            {
                let longest = returns.entry(detail).or_default();
                *longest = (*longest).max(ticks);
            }
        }
        println!(
            "net-vz steps: the steps of the return by detail: {returns:?} (the bound on VZ is {bound})"
        );
        if let Some(row) = returns.iter().find(|r| *r.1 > bound) {
            return Err(format!("a step of the return past its bound: {row:?}"));
        }
    }
    println!(
        "net-vz passed in {:.0} s with {} network device(s); page of {} bytes",
        started.elapsed().as_secs_f64(),
        options.devices,
        rootfs::WWW_INDEX_LEN
    );
    Ok(())
}

/// The checks of the second device.
fn second_device(
    run: &mut qemu::Run,
    started: Instant,
    first: Ipv4Addr,
    static1: bool,
    mac: &str,
) -> Result<Address, String> {
    let driver = line_where(
        run,
        "the second driver's line",
        |l| l.starts_with("virtio-net1: 1af4:1041 at "),
        BOOT_TIMEOUT,
    )?;
    let expected = format!("virtio-net1: 1af4:1041 at 0x40010000, line 66, status 0x0, mac {mac}");
    if driver != expected {
        return Err(format!(
            "the second driver says {driver:?}, wanted {expected:?}"
        ));
    }
    let second = if static1 {
        let line = line_where(
            run,
            "the static address",
            |l| l.contains("net: static1 "),
            BOOT_TIMEOUT,
        )?;
        parse_address(&line, "static1").ok_or(format!("the line {line:?}"))?
    } else {
        let wait = LEASE1_WITHIN;
        let line = line_where(
            run,
            "the second lease",
            |l| l.contains("net: lease1 "),
            wait,
        )
        .map_err(|e| {
            format!("net-vz: the second device got no lease in 30 s ({e}); try --static1")
        })?;
        parse_address(&line, "lease1").ok_or(format!("the line {line:?}"))?
    };
    println!(
        "net-vz: the second device has {}/{} ({:.2} s after the start)",
        second.address,
        second.prefix,
        started.elapsed().as_secs_f64()
    );
    if second.address == first {
        return Err(format!("both devices have {first}"));
    }
    if static1 && second.address.to_string() != STATIC1 {
        return Err(format!("the static address is {}", second.address));
    }
    run.expect_seen("virtio-net1: first interrupt", DIALOG_STEP)?;
    let echo = ping_quiet(second.address)?;
    if echo.received != 0 {
        return Err(format!(
            "the second device answered {} echoes; it serves only DHCP",
            echo.received
        ));
    }
    // The echo requests are unicast to the second device alone: its own
    // line (INTID 66) carries the interrupt, and the first device's status
    // is empty in that notification.
    run.expect_seen("virtio-net1: own interrupt", DIALOG_STEP)
        .map_err(|e| format!("the line of the second device was not shown: {e}"))?;
    arp_is(second.address, mac)?;
    println!("net-vz: 0 of 2 echoes answered by the second device");
    Ok(second)
}

/// One request to the first address, answered with the page.
fn http_alive(guest: Ipv4Addr, when: &str) -> Result<(), String> {
    let (body, _) = net_curl::get_within(http(guest), Duration::from_secs(10))
        .map_err(|e| format!("the request {when}: {e}"))?;
    net_curl::check_body(&body).map_err(|e| format!("{when}: {e}"))?;
    println!("net-vz: HTTP to the first device passes {when}");
    Ok(())
}

/// The program that owns the second device, from its claim to its end and a
/// second claim.
fn owner(
    run: &mut qemu::Run,
    guest: Ipv4Addr,
    second: Address,
    static1: bool,
    mac: &str,
) -> Result<(), String> {
    const ECHO_PORT: u16 = 7;
    let within = LEASE1_WITHIN;
    let cidr = format!("{}/{}", second.address, second.prefix);
    let claimed = format!("fast-echo: claimed {cidr} mac {mac}");
    let renewed = format!("net: renew1 {cidr}");
    // The static address needs no lease and prints no line when the device
    // comes back: the second claim shows the address is kept.
    let again = (!static1).then(|| format!("net: lease1 {cidr}"));
    let back = |again: &Option<String>| -> Vec<String> {
        std::iter::once("net: device 1 back".to_owned())
            .chain(again.clone())
            .collect()
    };
    let mut socket_target = None;
    for round in 1..=2 {
        let claim_at = Instant::now();
        run.send(&format!("fast-echo {ECHO_PORT} &"))?;
        let mut wanted = vec![claimed.as_str()];
        if !static1 {
            wanted.push(renewed.as_str());
        }
        fast_probe::expect_all(run, &wanted, within)?;
        println!(
            "net-vz: claim {round}: claimed{} {} ms after the command",
            if static1 { "" } else { " and renew1" },
            claim_at.elapsed().as_millis()
        );
        let socket = socket_target.get_or_insert_with(|| {
            std::net::UdpSocket::bind("0.0.0.0:0").expect("a UDP socket of the Mac")
        });
        socket
            .connect((second.address, ECHO_PORT))
            .map_err(|e| format!("connect: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| format!("timeout: {e}"))?;
        // The first datagrams after a claim may be lost (about 20 ms with a
        // static address; the cause is not established). Send one every 10 ms
        // until the first comes back; its first byte counts the datagrams
        // sent, and `fast-echo` prints the first byte of the first datagram
        // it saw, which tells a loss before the program from a loss after it.
        let first_at = Instant::now();
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .map_err(|e| format!("timeout: {e}"))?;
        let mut lost_first = 0;
        let mut buffer = [0u8; 64];
        loop {
            socket
                .send(&[lost_first as u8; 32])
                .map_err(|e| format!("send: {e}"))?;
            if socket.recv(&mut buffer).is_ok() {
                break;
            }
            lost_first += 1;
            if first_at.elapsed() > Duration::from_secs(5) {
                return Err("the program echoed nothing in 5 s".into());
            }
        }
        println!(
            "net-vz: the first echo came {} ms after the first datagram ({lost_first} lost before it)",
            first_at.elapsed().as_millis()
        );
        // The other warm-up datagrams came back as well, or soon will.
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("timeout: {e}"))?;
        while socket.recv(&mut buffer).is_ok() {}
        match run.expect_line(
            "the first datagram the program saw",
            |l| l.contains("fast-echo: first datagram"),
            Duration::from_secs(3),
        ) {
            Ok(line) => println!(
                "net-vz: {} ({lost_first} lost before the first echo)",
                line.trim()
            ),
            Err(e) => println!("net-vz: no line of the first datagram: {e}"),
        }
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| format!("timeout: {e}"))?;
        let at = Instant::now();
        let mut sent_again = fast_probe::echoes(socket, 200, 64)?;
        sent_again += fast_probe::echoes(socket, 100, 1400)?;
        println!(
            "net-vz: 300 echoes of UDP in {} ms ({sent_again} sent again)",
            at.elapsed().as_millis()
        );
        http_alive(guest, &format!("with the owner running (claim {round})"))?;
        if round == 1 {
            for size in [64, 1400] {
                let (per_second, lost) = fast_probe::rate(socket, size, Duration::from_secs(3))?;
                println!(
                    "net-vz: echo rate of {size} bytes: {per_second} a second ({lost} unanswered)"
                );
            }
            for (count, size) in [(5, 56), (5, 1472)] {
                let result = ping(second.address, count, size, None)?;
                println!(
                    "net-vz: ping -c {count} -s {size} of the owner: {} of {} answered; {}",
                    result.received,
                    result.sent,
                    result.round_trip.as_deref().unwrap_or("no round-trip line")
                );
                if result.received != count {
                    return Err(format!(
                        "the owner answered {} of {count} echoes of {size} bytes",
                        result.received
                    ));
                }
            }
            arp_is(second.address, mac)?;
        }
        if static1 && round == 1 {
            // A static address has no lease to ask for again through the ring.
            let line = format!("net: renew1 {cidr}");
            if run.lines().iter().any(|l| l.contains(&line)) {
                return Err("a static address renewed through the ring".into());
            }
        }
        if round == 2 {
            run.send("kill -QUIT $!")?;
            let wanted = back(&again);
            let wanted: Vec<&str> = wanted.iter().map(String::as_str).collect();
            fast_probe::expect_all(run, &wanted, within)?;
            http_alive(guest, "after the second owner ended")?;
            break;
        }
        let killed_at = Instant::now();
        run.send("kill -9 $!")?;
        let wanted = back(&again);
        let wanted: Vec<&str> = wanted.iter().map(String::as_str).collect();
        fast_probe::expect_all(run, &wanted, within)?;
        println!(
            "net-vz: kill -9 to the lease or address again {} ms",
            killed_at.elapsed().as_millis()
        );
        http_alive(guest, "after the owner was killed")?;
    }
    Ok(())
}

fn ping_quiet(address: Ipv4Addr) -> Result<PingResult, String> {
    let output = Command::new("/sbin/ping")
        .args(["-c", "2", "-t", "2", &address.to_string()])
        .output()
        .map_err(|e| format!("ping: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    parse_ping(&text).ok_or_else(|| format!("ping of {address} printed no summary: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_comes_from_the_lease_or_static_line() {
        let lease = parse_address(
            "net: lease 192.168.64.3/24 gw 192.168.64.1 dns 192.168.64.1",
            "lease",
        )
        .unwrap();
        assert_eq!(lease.address, Ipv4Addr::new(192, 168, 64, 3));
        assert_eq!(lease.prefix, 24);
        assert_eq!(lease.gateway, Some(Ipv4Addr::new(192, 168, 64, 1)));
        let static1 = parse_address("net: static1 192.168.64.250/24", "static1").unwrap();
        assert_eq!((static1.gateway, static1.dns), (None, None));
        // `lease` does not take the line of the second device, nor `lost`.
        assert_eq!(parse_address("net: lease1 192.168.64.4/24", "lease"), None);
        assert_eq!(parse_address("net: lease lost", "lease"), None);
        assert!(parse_address("net: lease1 192.168.64.4/24 gw 192.168.64.1", "lease1").is_some());
    }

    #[test]
    fn two_addresses_are_in_one_network_by_the_prefix() {
        let a = Ipv4Addr::new(192, 168, 64, 3);
        assert!(same_network(a, Ipv4Addr::new(192, 168, 64, 1), 24));
        assert!(!same_network(a, Ipv4Addr::new(192, 168, 65, 1), 24));
        assert!(same_network(a, Ipv4Addr::new(192, 168, 65, 1), 16));
        assert!(same_network(a, Ipv4Addr::new(10, 0, 0, 1), 0));
    }

    #[test]
    fn the_summary_of_ping_is_read() {
        let output = "PING 192.168.64.3 (192.168.64.3): 56 data bytes\n64 bytes from 192.168.64.3: icmp_seq=0 ttl=64 time=0.5 ms\n\n--- 192.168.64.3 ping statistics ---\n5 packets transmitted, 4 packets received, 20.0% packet loss\nround-trip min/avg/max/stddev = 0.4/0.5/0.8/0.1 ms\n";
        let result = parse_ping(output).unwrap();
        assert_eq!((result.sent, result.received), (5, 4));
        assert!(result.round_trip.unwrap().contains("0.4/0.5/0.8"));
        assert_eq!(parse_ping("ping: cannot resolve"), None);
        let none = "2 packets transmitted, 0 packets received, 100.0% packet loss\n";
        assert_eq!(parse_ping(none).unwrap().received, 0);
    }

    #[test]
    fn the_lease_of_a_mac_is_read_from_the_leases_file() {
        let text = "{\n\tname=a\n\tip_address=192.168.64.3\n\thw_address=1,2:73:74:66:0:1\n\tlease=0x1\n}\n{\n\tname=b\n\tip_address=192.168.64.4\n\thw_address=1,2:73:74:66:1:1\n}\n";
        assert_eq!(
            leased_to(text, "02:73:74:66:00:01"),
            Some("192.168.64.3".parse().unwrap())
        );
        assert_eq!(
            leased_to(text, "02:73:74:66:01:01"),
            Some("192.168.64.4".parse().unwrap())
        );
        assert_eq!(leased_to(text, "02:73:74:66:02:01"), None);
        let twice = "{\n\tip_address=192.168.64.9\n\thw_address=1,2:73:74:66:0:1\n}\n{\n\tip_address=192.168.64.3\n\thw_address=1,2:73:74:66:0:1\n}\n";
        assert_eq!(
            leased_to(twice, "02:73:74:66:00:01"),
            Some("192.168.64.9".parse().unwrap())
        );
    }

    #[test]
    fn the_mac_of_arp_has_two_digits_a_byte() {
        let line = "? (192.168.64.4) at 2:73:74:66:0:2 on bridge100 ifscope [ethernet]\n";
        assert_eq!(arp_mac(line).as_deref(), Some("02:73:74:66:00:02"));
        assert_eq!(arp_mac("? (192.168.64.9) -- no entry"), None);
    }

    #[test]
    fn a_step_of_the_return_has_kind_65_and_a_detail() {
        let line = |kind: u32, detail: u32| {
            format!("service step: 14 kind {kind} 30000 ticks detail {detail}")
        };
        assert!(is_return_step(&line(65, 2), false));
        assert!(is_return_step(&line(65, 1), false));
        // An own step is delayed only after the owner was killed.
        assert!(!is_return_step(&line(65, 0), false));
        assert!(is_return_step(&line(65, 0), true));
        // The queues and the fill keep the common bound.
        for detail in [3, 4, 5, 6] {
            assert!(!is_return_step(&line(65, detail), true));
        }
        assert!(!is_return_step(&line(36, 1), true));
    }

    #[test]
    fn the_options_take_net_2_and_static1_with_it() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(options(&args(&[])).unwrap().devices, 1);
        let two = options(&args(&["--net", "2", "--static1"])).unwrap();
        assert!(two.devices == 2 && two.static1);
        assert!(options(&args(&["--static1"])).is_err());
        assert!(options(&args(&["--net", "3"])).is_err());
    }
}
