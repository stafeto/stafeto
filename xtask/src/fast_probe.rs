// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the second network device in the hands of a program (`cargo
//! xtask fast-probe`, stage P6a of subproject 6, spec 6, 3.9 and 8.8): the
//! shell's image with both network devices on QEMU (`table-net-two`),
//! `/etc/netd.conf` with `handover 1`, and `fast-echo`
//! (tests/posix-so/dyn/fast-echo.c), which claims the device and drives it
//! with libvirtio_net.a. The second device's user network forwards a UDP
//! port of the host to port 7 of the second address (10.0.3.15). xtask
//! drives the shell over the serial port:
//!
//! 1. both leases and the second device's first interrupt;
//! 2. `fast-echo 7 --rules`: fork and execve fail with EPERM, munmap and
//!    mprotect of the mappings with EINVAL; the program ends, and the device
//!    comes back (`net: device 1 back`, `net: lease1`);
//! 3. `fast-echo 7 &`: `claimed`, then `net: renew1` (the service's DHCP
//!    client asked for its lease again through the bypass ring, both ways);
//! 4. 200 datagrams of 64 bytes and 100 of 1 400 from the host come back
//!    byte for byte (slirp asks ARP for the second address first), more
//!    than the queue of receiving holds;
//! 5. `fast-echo 7 --as 1000`: EPERM (`refused ok`); `fast-echo 7 --once`
//!    while the first owns the device: EBUSY (`busy ok`);
//! 6. `fast-echo 7 --retry &` is refused and tries again; `kill -9` of the
//!    first owner: the device comes back and gets its lease, the second
//!    claims it (`retry ok`: no departure of a refused try reads as the
//!    service's end), renews, and echoes 100 datagrams;
//! 7. `kill -QUIT`: the device comes back again.
//!
//! `cargo xtask fast-probe steps` runs the same under -icount with the
//! service counting its steps (and the second owner pushing 16 frames into
//! the ring at once, `--flood`), and judges every step of the service
//! against 0.9 of term B: CLAIM (26), CLAIM_MORE (36), KICK (37), and the
//! service's own steps, the ring's and the return's among them.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, INIT_STACK_SIZE, ImageProgram, SERVICES_STARTED,
    Variant, build, build_boot_image, busybox_build, nano_build, net, net_probe, qemu, relibc,
    symbolize,
};

/// The images: the probe, and the probe with the steps counted.
pub const IMAGE: &str = "boot-fast-probe.img";
pub const STEPS_IMAGE: &str = "boot-fast-probe-steps.img";

/// `/etc/netd.conf` of the images: DHCP on both devices, and the second
/// device may go to a program.
pub const NETD_CONF: &[u8] = b"handover 1\n";

/// The second address on QEMU's second user network, and the device's MAC.
const SECOND: &str = "10.0.3.15/24";
const PORT: u16 = 7;

/// The kinds of the steps of CLAIM, CLAIM_MORE and KICK.
const CLAIM_KIND: usize = 26;
const CLAIM_MORE_KIND: usize = 36;
const KICK_KIND: usize = 37;

/// How long a line may take on TCG, and under -icount.
const LINE_WITHIN: Duration = Duration::from_secs(30);
const LINE_WITHIN_STEPS: Duration = Duration::from_secs(120);

/// The programs of the image: the shell's with the network service, the
/// table of both devices.
pub fn programs(steps: bool) -> &'static [ImageProgram] {
    static PLAIN: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    static STEPS: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    let list = if steps { &STEPS } else { &PLAIN };
    list.get_or_init(|| {
        let mut programs = net::programs().to_vec();
        programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-net-two"]);
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

/// Waits for a line with each of `wanted`, in any order (two programs
/// write to the one serial port).
pub(crate) fn expect_all(
    run: &mut qemu::Run,
    wanted: &[&str],
    within: Duration,
) -> Result<(), String> {
    let mut left: Vec<&str> = wanted.to_vec();
    let end = Instant::now() + within;
    while !left.is_empty() {
        let line = run.expect_line(
            &format!("{left:?}"),
            |l| {
                left.iter().any(|w| l.contains(w))
                    || (l.contains("fast-echo:") && l.contains("failed"))
                    || l.contains("fstack-probe: check failed")
            },
            end.saturating_duration_since(Instant::now()),
        )?;
        if line.contains("failed") {
            return Err(format!("a failure: {line:?}"));
        }
        left.retain(|w| !line.contains(w));
    }
    Ok(())
}

/// `count` datagrams of `size` bytes through the forwarded port, each
/// back byte for byte: the datagrams sent again after a timeout.
pub(crate) fn echoes(socket: &UdpSocket, count: usize, size: usize) -> Result<usize, String> {
    let mut again = 0;
    let mut got = vec![0u8; 2048];
    for n in 0..count {
        let sent: Vec<u8> = (0..size)
            .map(|i| (i as u8) ^ (n as u8).wrapping_mul(31))
            .collect();
        let mut tries = 0;
        loop {
            socket
                .send(&sent)
                .map_err(|e| format!("datagram {n}: {e}"))?;
            match socket.recv(&mut got) {
                Ok(len) if got[..len] == sent[..] => break,
                Ok(len) => {
                    return Err(format!(
                        "datagram {n} of {size} bytes came back as {len} other bytes"
                    ));
                }
                Err(e) if tries < 3 => {
                    tries += 1;
                    again += 1;
                    let _ = e;
                }
                Err(e) => return Err(format!("datagram {n} of {size} bytes: no echo ({e})")),
            }
        }
    }
    Ok(again)
}

/// `cargo xtask fast-probe [steps] [tcg|hvf]`.
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
        _ => return Err("usage: cargo xtask fast-probe [steps] [tcg|hvf]".to_owned()),
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
    let name = if steps { STEPS_IMAGE } else { IMAGE };
    let image = build_boot_image(name, programs(steps), BOOT_PROFILE)?;
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("a UDP socket: {e}"))?;
    // A free port of the host for the forward, taken and given back.
    let host = UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map_err(|e| format!("a free UDP port: {e}"))?
        .port();
    socket
        .connect(("127.0.0.1", host))
        .map_err(|e| format!("connect: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(if steps { 10 } else { 2 })))
        .map_err(|e| format!("timeout: {e}"))?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    cmd.args(qemu::net_two_with(&[qemu::Forward {
        proto: qemu::Proto::Udp,
        host,
        guest: PORT,
    }]));
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
    let claimed = format!("fast-echo: claimed {SECOND} mac {}", qemu::NET_MAC_TWO);
    let renewed = format!("net: renew1 {SECOND}");
    let back = "net: device 1 back";
    let lease1 = format!("net: lease1 {SECOND}");
    let mut notes = Vec::new();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        expect_all(
            &mut run,
            &[
                "net: lease 10.0.2.15/24",
                &lease1,
                "virtio-net1: first interrupt",
            ],
            BOOT_TIMEOUT,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        // The rules of a process that holds the device; its end gives the
        // device back.
        run.send(&format!("fast-echo {PORT} --rules"))?;
        expect_all(
            &mut run,
            &[
                "fast-echo: fast-fork ok",
                "fast-echo: fast-exec ok",
                "fast-echo: fast-unmap ok",
                back,
                &lease1,
            ],
            within,
        )?;
        // The owner: the claim, and the lease again through the ring.
        let claim_at = Instant::now();
        run.send(&format!(
            "fast-echo {PORT} {}&",
            if steps { "--flood " } else { "" }
        ))?;
        let mut first = vec![claimed.as_str(), renewed.as_str()];
        if steps {
            first.push("fast-echo: flood taken");
        }
        expect_all(&mut run, &first, within)?;
        notes.push(format!(
            "claim to renew1 {} ms",
            claim_at.elapsed().as_millis()
        ));
        let echo_at = Instant::now();
        // More than the 256 buffers of the queue of receiving: the queue is
        // filled again from the pool.
        let mut again = echoes(&socket, 200, 64)?;
        again += echoes(&socket, 100, 1400)?;
        notes.push(format!(
            "300 echoes in {} ms ({again} sent again)",
            echo_at.elapsed().as_millis()
        ));
        // A user other than the superuser, and a second owner.
        run.send(&format!("fast-echo {PORT} --as 1000"))?;
        expect_all(&mut run, &["fast-echo: refused ok"], within)?;
        run.send(&format!("fast-echo {PORT} --once"))?;
        expect_all(&mut run, &["fast-echo: busy ok"], within)?;
        // A second program waits for the device (its refused tries leave
        // their departures on its channel); the owner killed: the device
        // comes back, and goes to the one that waits.
        run.send(&format!("fast-echo {PORT} --retry &"))?;
        expect_all(&mut run, &["fast-echo: retry busy"], within)?;
        let killed_at = Instant::now();
        run.send("kill -9 %1")?;
        // The service's lines and the program's come in either order.
        expect_all(
            &mut run,
            &[
                back,
                &lease1,
                "fast-echo: retry ok",
                claimed.as_str(),
                renewed.as_str(),
            ],
            within,
        )?;
        notes.push(format!(
            "kill -9 to the new owner's renew1 {} ms",
            killed_at.elapsed().as_millis()
        ));
        let again = echoes(&socket, 100, 512)?;
        notes.push(format!(
            "100 echoes after the new claim ({again} sent again)"
        ));
        run.send("kill -QUIT $!")?;
        expect_all(&mut run, &[back], within)?;
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
    }) {
        return Err("the image of the fast path faulted".into());
    }
    if steps {
        let rows = steps_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "fast-probe steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            net_probe::STEP_MAX
        );
    }
    println!(
        "fast-probe passed in {:.0} s on {}: {}",
        started.elapsed().as_secs_f64(),
        machine.name,
        notes.join("; ")
    );
    Ok(())
}

/// The longest step of each kind, judged against the bound; the steps of
/// CLAIM, CLAIM_MORE and KICK must be among them.
pub(crate) fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    let rows = net_probe::longest_over_starts(lines);
    for (kind, name) in [
        (CLAIM_KIND, "CLAIM"),
        (CLAIM_MORE_KIND, "CLAIM_MORE"),
        (KICK_KIND, "KICK"),
    ] {
        if !rows.iter().any(|r| r.0 == kind) {
            return Err(format!("no step of {name}: {rows:?}"));
        }
    }
    if let Some(row) = rows.iter().find(|r| r.1 > net_probe::STEP_MAX) {
        return Err(format!(
            "the network service: a step past 0.9 of term B ({}): {row:?}",
            net_probe::STEP_MAX
        ));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The image has the table of both devices, the program and the file
    /// that allows the claim.
    #[test]
    fn the_image_has_both_devices_and_the_owner() {
        assert_eq!(programs(false)[0].3, &["table-net-two"]);
        let netd = programs(true).iter().find(|p| p.0 == "netd").unwrap();
        assert_eq!(netd.3, &["steps"]);
        assert!(crate::rootfs::shared_path("fast-echo").is_some());
        assert_eq!(NETD_CONF, b"handover 1\n");
        let args = qemu::net_two_with(&[qemu::Forward {
            proto: qemu::Proto::Udp,
            host: 4000,
            guest: PORT,
        }])
        .join(" ");
        assert!(args.contains("hostfwd=udp:127.0.0.1:4000-10.0.3.15:7"));
    }

    #[test]
    fn the_steps_of_the_claim_must_be_there_and_within_the_bound() {
        let line =
            |kind: u32, ticks: u32| format!("service step: 14 kind {kind} {ticks} ticks detail 0");
        let ok = vec![
            line(26, 9_000),
            line(36, 6_000),
            line(37, 12_000),
            line(65, 11_000),
        ];
        assert!(steps_verdict(&ok).is_ok());
        let slow = vec![line(26, 9_000), line(36, 6_000), line(37, 19_000)];
        assert!(steps_verdict(&slow).unwrap_err().contains("past 0.9"));
        let none = vec![line(26, 9_000), line(37, 12_000)];
        assert!(steps_verdict(&none).unwrap_err().contains("CLAIM_MORE"));
    }

    /// The lines xtask waits for are those the programs print.
    #[test]
    fn the_lines_are_those_of_the_programs() {
        let echo =
            std::fs::read_to_string(crate::root().join("tests/posix-so/dyn/fast-echo.c")).unwrap();
        for line in [
            "fast-fork ok",
            "fast-exec ok",
            "fast-unmap ok",
            "refused ok",
            "busy ok",
            "flood taken",
            "retry busy",
            "retry ok",
        ] {
            assert!(echo.contains(line), "{line}");
        }
        let netd =
            std::fs::read_to_string(crate::root().join("services/netd/src/main.rs")).unwrap();
        for line in ["net: renew1 ", "net: device 1 back", "net: lease1 "] {
            assert!(netd.contains(line), "{line}");
        }
    }
}
