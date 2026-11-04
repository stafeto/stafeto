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
//!    of `vz-run`), the lease within 20 s of the start of the services, the
//!    gateway in the network of the address, and the first interrupt;
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
//! The Mac may refuse to connect to the guest ("No route to host") when the
//! terminal has no permission for the local network (System Settings,
//! Privacy and Security, Local Network).

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::net_curl;
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net, qemu, relibc, rootfs, vz,
};

/// The lease within this long after the services started.
const LEASE_WITHIN: Duration = Duration::from_secs(20);
/// The second device's lease within this long.
const LEASE1_WITHIN: Duration = Duration::from_secs(30);
/// The probe may take this long from the start of the machine.
const RUN_WITHIN: Duration = Duration::from_secs(60 * 4);
/// The closed port must refuse within this long.
const REFUSAL_WITHIN: Duration = Duration::from_secs(1);
/// The fixed MAC addresses of `vz-run`, by device.
const MACS: [&str; 2] = ["02:73:74:66:00:01", "02:73:74:66:00:02"];
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
    let word = output.split(" at ").nth(1)?.split_whitespace().next()?;
    let bytes: Vec<u8> = word
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
}

fn options(args: &[String]) -> Result<Options, String> {
    let usage = "usage: cargo xtask net-vz [--net 2] [--static1]";
    let mut found = Options {
        devices: 1,
        static1: false,
    };
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--net" if rest.next().map(String::as_str) == Some("2") => found.devices = 2,
            "--static1" => found.static1 = true,
            _ => return Err(usage.to_owned()),
        }
    }
    if found.static1 && found.devices != 2 {
        return Err("--static1 belongs to --net 2".to_owned());
    }
    Ok(found)
}

fn ping(
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
) -> Result<Address, String> {
    let mut mac = MACS[0].to_owned();
    mac.insert_str(0, "mac ");
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
        other => Err(format!("{target}: {other:?}, wanted a refusal within 1 s")),
    }
}

pub fn command(args: &[String]) -> Result<(), String> {
    let options = options(args)?;
    busybox_build()?;
    nano_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let (name, two) = match (options.devices, options.static1) {
        (1, _) => (net::VZ_IMAGE, false),
        (_, false) => (net::VZ2_IMAGE, true),
        (_, true) => (net::VZ2_STATIC_IMAGE, true),
    };
    let image = build_boot_image(name, net::vz_programs(two), BOOT_PROFILE)?;
    let machine = vz::Machine {
        net: options.devices,
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
        let first = first_device(&mut run, started, services_at)?;
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
        run.send("httpd -f -p 80 -h /www & H=$!")?;
        run.expect("# ", DIALOG_STEP)?;
        let timing = net_curl::requests(http(guest), Instant::now())?;
        println!(
            "net-vz: 20 requests in a row and 8 at once ok, {} ms median, {} ms the longest",
            timing.0, timing.1
        );
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
        let (body, _) = net_curl::get_within(http(guest), Duration::from_secs(10))
            .map_err(|e| format!("the request after the pings: {e}"))?;
        net_curl::check_body(&body).map_err(|e| format!("after the pings: {e}"))?;
        println!("net-vz: the service is alive after the pings");
        if options.devices == 2 {
            second_device(&mut run, started, guest, options.static1)?;
            let (body, _) = net_curl::get_within(http(guest), Duration::from_secs(10))
                .map_err(|e| format!("the request with two devices: {e}"))?;
            net_curl::check_body(&body).map_err(|e| format!("with two devices: {e}"))?;
            println!("net-vz: HTTP to the first device passes with two devices");
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
    if started.elapsed() > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s",
            started.elapsed().as_secs_f64()
        ));
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
) -> Result<(), String> {
    let driver = line_where(
        run,
        "the second driver's line",
        |l| l.starts_with("virtio-net1: 1af4:1041 at "),
        BOOT_TIMEOUT,
    )?;
    let expected = format!(
        "virtio-net1: 1af4:1041 at 0x40010000, line 66, status 0x0, mac {}",
        MACS[1]
    );
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
    let arp = Command::new("/usr/sbin/arp")
        .args(["-n", &second.address.to_string()])
        .output()
        .map_err(|e| format!("arp: {e}"))?;
    let text = String::from_utf8_lossy(&arp.stdout).into_owned();
    let mac =
        arp_mac(&text).ok_or_else(|| format!("arp has no entry for {}: {text}", second.address))?;
    if mac != MACS[1] {
        return Err(format!(
            "arp gives {mac} for {}, wanted {}",
            second.address, MACS[1]
        ));
    }
    println!(
        "net-vz: the Mac's ARP cache has {} for {}; 0 of 2 echoes answered",
        mac, second.address
    );
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
    fn the_mac_of_arp_has_two_digits_a_byte() {
        let line = "? (192.168.64.4) at 2:73:74:66:0:2 on bridge100 ifscope [ethernet]\n";
        assert_eq!(arp_mac(line).as_deref(), Some("02:73:74:66:00:02"));
        assert_eq!(arp_mac("? (192.168.64.9) -- no entry"), None);
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
