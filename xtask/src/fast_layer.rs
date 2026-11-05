// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the layer's sockets over the stack in a process (`cargo
//! xtask fast-probe layer`, stage P6b-3 of subproject 6, spec 6, 3.9): the
//! image of the stack on the second device (`table-fstack-device`, `handover
//! 1`, a fixed second address) with `fast-layer` (tests/fstack-probe/
//! layer.c), a program that makes plain sockets and epoll and links the
//! stack, the device's driver and the glue that registers the table:
//!
//! 1. `fast-layer &`: the glue's line (the stack is up on the second
//!    address), then a line for each check of the calls on the stack's
//!    loopback and of the layer's refusals, then `serving`;
//! 2. 16 echoes through the forwarded port, one connection at a time, of
//!    sizes from 1 byte to 20 000, each back byte for byte (the first waits
//!    for the first SYN's retry at most); the time to the first answer;
//! 3. the page of 1 MiB three times in turn and four at once, every byte
//!    compared (writev, partial writes, the edge of writing);
//! 4. one connection that waits 60 ms before each of 40 requests: the median
//!    of the echo times is at most 3 ms, so the idle loop wakes on the
//!    device's interrupt and not on its own timer;
//! 5. the clock ticks and steps of the stack over two idle seconds (about
//!    100 ticks a second);
//! 6. `?stop`: the program ends and the device comes back.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::fast_probe::expect_all;
use crate::fstack_device::{PAGE_BYTES, fetch, free_port};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, INIT_STACK_SIZE, ImageProgram, SERVICES_STARTED,
    Variant, build, build_boot_image, busybox_build, nano_build, net, qemu, relibc, symbolize,
};

pub const IMAGE: &str = "boot-fast-layer.img";

const ECHO_PORT: u16 = 7;
const PAGE_PORT: u16 = 80;
/// The most the median of the echo after a pause of 60 ms may take.
const IDLE_MEDIAN_MAX_US: u64 = 3000;
const LINE_WITHIN: Duration = Duration::from_secs(60);

/// The checks of the program, in its order (`fast-layer: <name> ok`).
pub const CHECKS: &[&str] = &[
    "range",
    "flags",
    "names",
    "accept_empty",
    "data",
    "oneshot",
    "rdhup",
    "refusals",
    "refused_connect",
    "scm_rights",
    "datagram_unchanged",
    "close",
];

/// The programs of the image: the network image's with the table of both
/// devices and the larger quota of the shell's commands.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = net::programs().to_vec();
        programs[0] = ("init", "init", INIT_STACK_SIZE, &["table-fstack-device"]);
        programs.push(("fast-layer", "fast-layer", 0, &["dynamic"]));
        programs
    })
}

/// `cargo xtask fast-probe layer [tcg|hvf]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let machine = match args {
        [] => &qemu::VIRT,
        [name] if name == "hvf" => &qemu::HVF_V3,
        [name] if name == "tcg" => &qemu::VIRT,
        _ => return Err("usage: cargo xtask fast-probe layer [tcg|hvf]".to_owned()),
    };
    probe(machine)
}

fn connect(port: u16) -> Result<TcpStream, String> {
    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("timeout: {e}"))?;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("nodelay: {e}"))?;
    Ok(stream)
}

/// `payload` through a new connection and back; the seconds it took. The
/// first connection after the start may lose its SYN to the stack that is not
/// ready (a retry of 1 s), so a connection that gives no answer in 3 s is
/// made again, up to three times.
fn echo(port: u16, payload: &[u8], retries: usize) -> Result<f64, String> {
    let started = Instant::now();
    for attempt in 0..=retries {
        let mut stream = connect(port)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(if attempt < retries { 3 } else { 20 })))
            .map_err(|e| format!("timeout: {e}"))?;
        stream
            .write_all(payload)
            .map_err(|e| format!("echo write: {e}"))?;
        let mut got = vec![0u8; payload.len()];
        match stream.read_exact(&mut got) {
            Ok(()) if got == payload => return Ok(started.elapsed().as_secs_f64()),
            Ok(()) => return Err(format!("echo of {} bytes came back different", payload.len())),
            Err(_) if attempt < retries => {}
            Err(e) => return Err(format!("echo of {} bytes: {e}", payload.len())),
        }
    }
    Err("no echo".to_owned())
}

fn pattern(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// The median and the 90th percentile of the echo of 32 bytes on one
/// connection after pauses of 60 ms, in microseconds.
fn idle_latency(port: u16, count: usize) -> Result<(u64, u64), String> {
    let mut stream = connect(port)?;
    let message = [0x42u8; 32];
    let mut got = [0u8; 32];
    let mut times = Vec::new();
    for _ in 0..count {
        std::thread::sleep(Duration::from_millis(60));
        let started = Instant::now();
        stream
            .write_all(&message)
            .map_err(|e| format!("latency write: {e}"))?;
        stream
            .read_exact(&mut got)
            .map_err(|e| format!("latency read: {e}"))?;
        if got != message {
            return Err("the echo of the latency probe differs".to_owned());
        }
        times.push(started.elapsed().as_micros() as u64);
    }
    times.sort_unstable();
    Ok((times[times.len() / 2], times[times.len() * 9 / 10]))
}

/// `ticks=N passes=M` of the program, asked on a new connection.
fn stats(port: u16) -> Result<(u64, u64), String> {
    let mut stream = connect(port)?;
    stream
        .write_all(b"?stats")
        .map_err(|e| format!("?stats: {e}"))?;
    let mut got = [0u8; 128];
    let n = stream.read(&mut got).map_err(|e| format!("?stats: {e}"))?;
    let text = String::from_utf8_lossy(&got[..n]).into_owned();
    let field = |name: &str| -> Result<u64, String> {
        text.split_whitespace()
            .find_map(|w| w.strip_prefix(name))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("no {name} in {text:?}"))
    };
    Ok((field("ticks=")?, field("passes=")?))
}

pub fn probe(machine: &'static qemu::Machine) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    let echo_host = free_port(true)?;
    let page_host = free_port(true)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    cmd.args(qemu::net_two_with(&[
        qemu::Forward {
            proto: qemu::Proto::Tcp,
            host: echo_host,
            guest: ECHO_PORT,
        },
        qemu::Forward {
            proto: qemu::Proto::Tcp,
            host: page_host,
            guest: PAGE_PORT,
        },
    ]));
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let mut notes = Vec::new();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        expect_all(
            &mut run,
            &["net: lease 10.0.2.15/24", "net: static1 10.0.3.15/24"],
            BOOT_TIMEOUT,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        let began = Instant::now();
        run.send("fast-layer &")?;
        let mut lines = vec!["fast: the stack is up on 10.0.3.15/24".to_owned()];
        lines.extend(CHECKS.iter().map(|name| format!("fast-layer: {name} ok")));
        lines.push("fast-layer: serving".to_owned());
        let wanted: Vec<&str> = lines.iter().map(String::as_str).collect();
        expect_all(&mut run, &wanted, LINE_WITHIN)?;
        notes.push(format!(
            "the stack up, {} checks and serving in {} ms",
            CHECKS.len(),
            began.elapsed().as_millis()
        ));
        let first = echo(echo_host, b"first", 3)?;
        notes.push(format!("the first echo after the start {first:.2} s"));
        let mut again = 0;
        for n in 0..16u8 {
            let size = [1, 2, 100, 1400, 1500, 4000, 8000, 20000][n as usize % 8];
            let seconds = echo(echo_host, &pattern(size, n), 0)?;
            if seconds > 5.0 {
                again += 1;
            }
        }
        notes.push(format!("16 echoes of 1 to 20 000 bytes ({again} slow)"));
        let mut total = 0.0;
        for _ in 0..3 {
            total += fetch(page_host, PAGE_BYTES)?;
        }
        notes.push(format!(
            "3 pages of 1 MiB in turn in {total:.2} s ({:.1} MiB/s)",
            3.0 / total
        ));
        let at_once: Vec<_> = (0..4)
            .map(|_| std::thread::spawn(move || fetch(page_host, PAGE_BYTES)))
            .collect();
        let mut slowest = 0.0f64;
        for handle in at_once {
            slowest = slowest.max(handle.join().map_err(|_| "a fetch panicked".to_owned())??);
        }
        notes.push(format!("4 pages at once, the slowest in {slowest:.2} s"));
        let (median, p90) = idle_latency(echo_host, 40)?;
        notes.push(format!(
            "echo after a pause of 60 ms: median {median} us, 90th percentile {p90} us"
        ));
        if median > IDLE_MEDIAN_MAX_US {
            return Err(format!(
                "an echo after a pause took {median} us at the median, over {IDLE_MEDIAN_MAX_US}: the idle loop does not wake on the device's interrupt"
            ));
        }
        let before = stats(echo_host)?;
        let at = Instant::now();
        std::thread::sleep(Duration::from_secs(2));
        let after = stats(echo_host)?;
        let seconds = at.elapsed().as_secs_f64();
        let ticks = (after.0 - before.0) as f64 / seconds;
        let passes = (after.1 - before.1) as f64 / seconds;
        notes.push(format!(
            "idle: {ticks:.0} clock ticks and {passes:.0} steps of the stack a second"
        ));
        if !(70.0..=130.0).contains(&ticks) {
            return Err(format!("the stack's clock ran {ticks:.0} ticks a second, wanted 100"));
        }
        let mut stream = connect(echo_host)?;
        stream
            .write_all(b"?stop")
            .map_err(|e| format!("?stop: {e}"))?;
        expect_all(
            &mut run,
            &["fast-layer: ended", "net: device 1 back"],
            LINE_WITHIN,
        )?;
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
            || line.contains("fast-layer: check failed")
    }) {
        return Err("the image of the layer's sockets faulted".into());
    }
    println!(
        "fast-probe layer passed in {:.0} s on {}: {}",
        started.elapsed().as_secs_f64(),
        machine.name,
        notes.join("; ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The image has the table of both devices and the program.
    #[test]
    fn the_image_has_the_program() {
        assert_eq!(programs()[0].3, &["table-fstack-device"]);
        assert!(programs().iter().any(|p| p.0 == "fast-layer"));
    }

    /// The lines xtask waits for are those the program prints.
    #[test]
    fn the_lines_are_those_of_the_program() {
        let source =
            std::fs::read_to_string(crate::root().join("tests/fstack-probe/layer.c")).unwrap();
        for name in CHECKS {
            assert!(
                source.contains(&format!("ok(\"{name}\")")),
                "layer.c does not print {name}"
            );
        }
        for text in ["fast-layer: serving", "fast-layer: ended", "ticks=%llu passes=%llu"] {
            assert!(source.contains(text), "layer.c does not print {text}");
        }
        let glue = std::fs::read_to_string(crate::root().join("ports/f-stack/ff_stafeto_glue.c"))
            .unwrap();
        assert!(glue.contains("fast: the stack is up on"));
    }
}
