// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! TLS in the guest (`cargo xtask net-tls`): curl and `openssl s_client` of
//! the image against two `openssl s_server -WWW` of the host, each on a free
//! port of 127.0.0.1 that the guest reaches as 10.0.2.2. Server A has a
//! certificate of the probe CA (`probe_ca.rs`) for `host.stafeto.test` and
//! 10.0.2.2; server B a self-signed one. The image (`boot-net-tls.img`)
//! carries the root certificates of Mozilla with the probe CA added as its
//! CA file, and a file of 256 KiB that the host serves too. xtask drives
//! `ash` over the serial port, as `net-wget` does:
//!
//! 0. The guest's clock against the host's (the certificates are checked
//!    against it); `openssl version` (OpenSSL's start, which tries the
//!    extensions of the CPU under SIGILL, passed) and `curl -V`.
//! 1. curl of the page from A: the chain is checked, the body is the page.
//! 2. The same with `--tlsv1.3`: the handshake says TLSv1.3.
//! 3. A by the name of its certificate (`--connect-to`): exit 0.
//! 4. A by a name its certificate does not hold: exit 60.
//! 5. B: exit 60 (no CA knows it); with `-k`: exit 0 and the page.
//! 6. `openssl s_client` to A: `Verification: OK` and TLSv1.3; to B with
//!    `-verify_return_error`: a failure.
//! 7. The file of 256 KiB from A: full TLS records.
//! 8. curl to a port without a listener: exit 7 within the 5 s of `-m`.
//! 9. `openssl speed -evp aes-128-gcm -seconds 1 -bytes 16384`: a number.
//!
//! `cargo xtask net-tls steps` runs steps 1 and 7 with the network service
//! counting its steps under `-icount shift=4,sleep=on` and judges every step
//! against 0.9 of term B. `cargo xtask net-tls internet` (a manual run)
//! fetches `https://example.com/` with the root certificates of Mozilla of
//! the image with the network (`boot-net.img`).

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::net_wget::{step, steps_verdict};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net, net_curl, packages, probe_ca, qemu, relibc, rootfs, symbolize,
};

/// The image of the probe and that of its run with the counted steps.
pub const IMAGE: &str = "boot-net-tls.img";
pub const STEPS_IMAGE: &str = "boot-net-tls-steps.img";
/// The CA file of the images with the network (package ca-bundle), which
/// curl names at its build.
pub const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
/// The large file of the probe, which the host serves too.
pub const BIG: &str = "/www/256k.bin";
const BIG_LEN: usize = 256 * 1024;
/// The version the programs of the image print.
const OPENSSL_VERSION: &str = "OpenSSL 3.5.9";

/// The whole run may take this long (the ci group allows 120 s).
const RUN_WITHIN: Duration = Duration::from_secs(110);
/// The time one curl or s_client may take.
const FETCH_WITHIN: Duration = Duration::from_secs(30);
/// The run of `openssl speed`: one second of work and the start.
const SPEED_WITHIN: Duration = Duration::from_secs(30);
/// curl's limit for the port without a listener, and the time it may take.
const REFUSED_LIMIT_S: u64 = 5;

/// The names of the licence notes of the image.
const OPENSSL_LICENSE: &str = "OPENSSL-LICENSE";
const OPENSSL_SOURCE: &str = "OPENSSL-SOURCE";
const CURL_LICENSE: &str = "CURL-LICENSE";
const CURL_SOURCE: &str = "CURL-SOURCE";
const CA_BUNDLE_LICENSE: &str = "CA-BUNDLE-LICENSE";
const CA_BUNDLE_SOURCE: &str = "CA-BUNDLE-SOURCE";

/// How a run goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Steps,
    Internet,
}

/// The bytes of the root certificates as tools/build-ca-bundle.py left
/// them, read once in a run of xtask; empty where the script has not run
/// (the check of the descriptions needs the paths of an image only).
pub fn ca_bundle() -> &'static [u8] {
    static BUNDLE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BUNDLE.get_or_init(|| {
        std::fs::read(crate::target_dir().join("ca-bundle/ca-certificates.crt")).unwrap_or_default()
    })
}

/// The bytes of `/www/256k.bin`: 256 KiB from a generator with a fixed
/// seed, so that the host knows the file without reading the image.
pub fn big_file() -> &'static [u8] {
    static FILE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    FILE.get_or_init(|| {
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut out = Vec::with_capacity(BIG_LEN);
        while out.len() < BIG_LEN {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(BIG_LEN);
        out
    })
}

/// The licence texts and the notes of the sources of OpenSSL, curl and the
/// root certificates, for an image that holds them.
pub fn terms_files(
    openssl: bool,
    curl: bool,
    bundle: bool,
) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let read = |path: PathBuf| std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()));
    let relibc = crate::script_value("tools/build-relibc.py", "COMMIT")?;
    let commit = crate::rtbench2::commit();
    let mut files = Vec::new();
    if openssl {
        let version = packages::value("openssl", "version")?;
        let sha256 = packages::value("openssl", "sha256")?;
        let url = packages::value("openssl", "url")?;
        let line = std::fs::read_to_string(crate::target_dir().join("openssl/configure-line.txt"))
            .map_err(|e| format!("openssl/configure-line.txt: {e}: tools/build-openssl.py"))?;
        files.push((
            OPENSSL_LICENSE,
            read(crate::target_dir().join(format!("openssl/openssl-{version}/LICENSE.txt")))?,
        ));
        files.push((
            OPENSSL_SOURCE,
            format!(
                "OpenSSL {version}, Copyright (c) the OpenSSL Project Authors.\n\
                 Licensed under the Apache License 2.0 (OPENSSL-LICENSE).\n\
                 Linked statically into curl and openssl of this image.\n\n\
                 Its source: {url}\n\
                 (SHA-256 {sha256}), built unchanged by tools/build-openssl.py\n\
                 of https://github.com/stafeto/stafeto at commit {commit} with\n\
                 {}\
                 linked with relibc https://github.com/stafeto/relibc at commit {relibc}\n\
                 (THIRD-PARTY-NOTICES).\n",
                line
            )
            .into_bytes(),
        ));
    }
    if curl {
        let version = packages::value("curl", "version")?;
        let sha256 = packages::value("curl", "sha256")?;
        let url = packages::value("curl", "url")?;
        files.push((
            CURL_LICENSE,
            read(crate::target_dir().join(format!("curl/curl-{version}/COPYING")))?,
        ));
        files.push((
            CURL_SOURCE,
            format!(
                "curl {version}, Copyright (c) Daniel Stenberg and the contributors.\n\
                 Licensed under the curl licence (CURL-LICENSE).\n\n\
                 Its source: {url}\n\
                 (SHA-256 {sha256}), built unchanged by tools/build-curl.py\n\
                 of https://github.com/stafeto/stafeto at commit {commit}; linked\n\
                 with OpenSSL (OPENSSL-SOURCE) and relibc\n\
                 https://github.com/stafeto/relibc at commit {relibc}\n\
                 (THIRD-PARTY-NOTICES).\n"
            )
            .into_bytes(),
        ));
    }
    if bundle {
        let version = packages::value("ca-bundle", "version")?;
        let sha256 = packages::value("ca-bundle", "sha256")?;
        let url = packages::value("ca-bundle", "url")?;
        let data = ca_bundle();
        let count = data
            .split(|&b| b == b'\n')
            .filter(|l| l.starts_with(b"-----BEGIN CERTIFICATE-----"))
            .count();
        let header: Vec<u8> = data
            .split_inclusive(|&b| b == b'\n')
            .take_while(|l| l.starts_with(b"##"))
            .flatten()
            .copied()
            .collect();
        let mut licence = read(crate::root().join("tools/ca-bundle/MPL-2.0.txt"))?;
        licence.extend_from_slice(b"\n\nThe header of the file:\n\n");
        licence.extend_from_slice(&header);
        files.push((CA_BUNDLE_LICENSE, licence));
        files.push((
            CA_BUNDLE_SOURCE,
            format!(
                "{CA_BUNDLE} holds the root certificates of Mozilla of {version}\n\
                 ({count} certificates), made from Mozilla's certdata.txt, which is\n\
                 under the Mozilla Public License 2.0 (CA-BUNDLE-LICENSE).\n\n\
                 Its source: {url}\n\
                 (SHA-256 {sha256}), put in the image unchanged by\n\
                 tools/build-ca-bundle.py.\n"
            )
            .into_bytes(),
        ));
    }
    Ok(files)
}

/// `openssl s_server -WWW` on a free port of 127.0.0.1 with the certificate
/// `name` of the probe CA, serving the page and the large file from a
/// directory of its own.
struct Server {
    port: u16,
    child: Child,
    _stdin: std::process::ChildStdin,
}

impl Server {
    fn start(directory: &Path, ca: &Path, name: &str) -> Result<Server, String> {
        let port = free_port()?;
        let mut child = Command::new("openssl")
            .current_dir(directory)
            .args(["s_server", "-accept", &format!("127.0.0.1:{port}")])
            .args(["-WWW", "-quiet", "-cert"])
            .arg(ca.join(format!("{name}.crt")))
            .arg("-key")
            .arg(ca.join(format!("{name}.key")))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("openssl s_server: {e}"))?;
        let stdin = child.stdin.take().ok_or("openssl s_server: no stdin")?;
        let address: SocketAddr = ([127, 0, 0, 1], port).into();
        let started = Instant::now();
        while TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_err() {
            if started.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "openssl s_server {name} did not listen within 10 s"
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(Server {
            port,
            child,
            _stdin: stdin,
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A free port of the host, taken and given back.
fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("a free port: {e}"))?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| format!("a free port: {e}"))
}

/// Sends `command` between two marker lines and gives the lines between
/// them, waiting up to `within` for the end. The markers hold the shell
/// variable `S` (`ok`), so the echo of the typed line, wrapped at the width
/// of the terminal, never reads as a marker.
fn capture(
    run: &mut qemu::Run,
    command: &str,
    marker: &str,
    within: Duration,
) -> Result<Vec<String>, String> {
    let (begin, end) = (format!("begin-ok-{marker}"), format!("end-ok-{marker}"));
    run.send(&format!(
        "echo begin-$S-{marker}; {command}; echo end-$S-{marker}"
    ))?;
    run.expect_line(&end, |l| l.trim() == end, within)?;
    let text = run.text();
    let first = text
        .iter()
        .rposition(|l| l.trim() == begin)
        .ok_or_else(|| format!("no {begin} line"))?;
    let last = text
        .iter()
        .rposition(|l| l.trim() == end)
        .ok_or_else(|| format!("no {end} line"))?;
    // The lines of the counted steps of the service come at any time.
    Ok(text[first + 1..last]
        .iter()
        .filter(|l| !l.starts_with("service "))
        .cloned()
        .collect())
}

/// The exit code a command printed as `rc=N` at its end.
fn exit_code(lines: &[String]) -> Option<i32> {
    lines
        .iter()
        .rev()
        .find_map(|l| l.trim().strip_prefix("rc=")?.parse().ok())
}

/// Runs `command` and gives its exit code and output.
fn coded(
    run: &mut qemu::Run,
    command: &str,
    marker: &str,
    within: Duration,
) -> Result<(i32, Vec<String>), String> {
    let lines = capture(run, &format!("{command}; echo rc=$?"), marker, within)?;
    let code = exit_code(&lines).ok_or_else(|| format!("{marker}: no exit code in {lines:?}"))?;
    Ok((code, lines))
}

/// Runs `command`, which must end with exit code `wanted`.
fn expect_code(
    run: &mut qemu::Run,
    command: &str,
    marker: &str,
    wanted: i32,
) -> Result<Duration, String> {
    let began = Instant::now();
    let (code, lines) = coded(run, command, marker, FETCH_WITHIN)?;
    if code != wanted {
        return Err(format!(
            "{marker}: `{command}` ended with {code}, wanted {wanted}: {lines:?}"
        ));
    }
    Ok(began.elapsed())
}

/// Whether a line of `curl -v` or `openssl s_client` names TLS 1.3 as the
/// version of the connection made (the lines of the handshake name the
/// versions offered).
fn negotiated_tls13(line: &str) -> bool {
    let line = line.trim();
    (line.contains("SSL connection using TLSv1.3") || line.starts_with("Protocol"))
        && line.contains("TLSv1.3")
}

/// What `openssl speed` printed: the line of its table for AES-128-GCM.
fn speed_line(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .find(|l| l.trim_start().starts_with("AES-128-GCM") && l.contains('k'))
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Step 0: the clock, and the versions of the programs.
fn versions(run: &mut qemu::Run) -> Result<(), String> {
    let date = capture(run, "date +%s", "clock", DIALOG_STEP)?;
    let off = probe_ca::clock_verdict(&date)?;
    println!("net-tls: the guest's clock is {off} s from the host's");
    let version = capture(run, "openssl version", "ov", FETCH_WITHIN)?;
    if !version.iter().any(|l| l.contains(OPENSSL_VERSION)) {
        return Err(format!("openssl version: {version:?}"));
    }
    let curl = capture(run, "curl -V", "cv", FETCH_WITHIN)?;
    let all = curl.join("\n");
    if !all.contains("OpenSSL/3.5.9") || !all.contains("https") {
        return Err(format!("curl -V: {curl:?}"));
    }
    if all.contains("HTTP2") || all.contains("IPv6") {
        return Err(format!("curl -V names HTTP2 or IPv6: {curl:?}"));
    }
    println!("net-tls: {}", version.join(" ").trim());
    println!("net-tls: {}", curl.first().map_or("", |l| l.trim()));
    Ok(())
}

/// `cargo xtask net-tls [steps|internet] [MACHINE]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let (mode, rest) = match args.first().map(String::as_str) {
        Some("steps") => (Mode::Steps, &args[1..]),
        Some("internet") => (Mode::Internet, &args[1..]),
        _ => (Mode::Normal, args),
    };
    let machine = match rest {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask net-tls [steps|internet] [tcg|hvf]".to_owned()),
    };
    probe(machine, mode)
}

pub fn probe(machine: &'static qemu::Machine, mode: Mode) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let ca = probe_ca::ensure(false)?;
    let kernel = build(Variant::Normal)?;
    let (name, programs) = match mode {
        Mode::Normal => (IMAGE, net::programs()),
        Mode::Steps => (STEPS_IMAGE, net_curl::steps_programs()),
        Mode::Internet => (net::IMAGE, net::programs()),
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    image_has_tls_files(&image, name)?;
    let directory = crate::target_dir().join("net-tls");
    std::fs::create_dir_all(&directory).map_err(|e| format!("{directory:?}: {e}"))?;
    std::fs::write(directory.join("index.html"), rootfs::www_index())
        .map_err(|e| format!("the page: {e}"))?;
    std::fs::write(directory.join("256k.bin"), big_file())
        .map_err(|e| format!("the large file: {e}"))?;
    let servers = if mode == Mode::Internet {
        None
    } else {
        let host = Command::new("openssl")
            .arg("version")
            .output()
            .map_err(|e| format!("openssl is needed for the servers: {e}"))?;
        println!(
            "net-tls: host {}",
            String::from_utf8_lossy(&host.stdout).trim()
        );
        Some((
            Server::start(&directory, &ca, "host-a")?,
            Server::start(&directory, &ca, "host-b")?,
            free_port()?,
        ))
    };
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    if mode == Mode::Steps {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let mut times: Vec<(String, Duration)> = Vec::new();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect_line(
            "the lease",
            |l| l.contains("net: lease 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3"),
            BOOT_TIMEOUT,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("S=ok")?;
        run.expect("# ", DIALOG_STEP)?;
        versions(&mut run)?;
        if mode == Mode::Internet {
            let t = step(
                &mut run,
                "internet-curl",
                "curl -sS -m 30 https://example.com/ | grep '<title>Example Domain</title>'",
                Duration::from_secs(60),
            )?;
            times.push(("example.com over https".into(), t));
            return Ok(());
        }
        let (a, b, c) = servers
            .as_ref()
            .map(|(a, b, c)| (a.port, b.port, *c))
            .ok_or("no servers")?;
        let big = |run: &mut qemu::Run| {
            step(
                run,
                "big",
                &format!(
                    "curl -sS -o /tmp/big https://10.0.2.2:{a}/256k.bin && cmp /tmp/big {BIG}"
                ),
                FETCH_WITHIN,
            )
        };
        // 1. The chain of A against the CA file.
        let t = step(
            &mut run,
            "chain",
            &format!(
                "curl -sS -o /tmp/i https://10.0.2.2:{a}/index.html && cmp /tmp/i /www/index.html"
            ),
            FETCH_WITHIN,
        )?;
        times.push(("page of 64 KiB, chain checked".into(), t));
        if mode == Mode::Steps {
            let t = big(&mut run)?;
            times.push(("file of 256 KiB".into(), t));
            return Ok(());
        }
        // 2. TLS 1.3.
        let (code, shown) = coded(
            &mut run,
            &format!("curl -sSv --tlsv1.3 -o /dev/null https://10.0.2.2:{a}/index.html 2>&1"),
            "v13",
            FETCH_WITHIN,
        )?;
        if code != 0 || !shown.iter().any(|l| negotiated_tls13(l)) {
            return Err(format!(
                "curl --tlsv1.3 ended with {code} with no connection of TLSv1.3: {shown:?}"
            ));
        }
        // 3. The name of the certificate.
        let t = expect_code(
            &mut run,
            &format!(
                "curl -sS -o /dev/null --connect-to host.stafeto.test:{a}:10.0.2.2:{a} https://host.stafeto.test:{a}/index.html"
            ),
            "san",
            0,
        )?;
        times.push(("by name".into(), t));
        // 4. A name the certificate does not hold.
        expect_code(
            &mut run,
            &format!(
                "curl -sS -o /dev/null --connect-to wrong.test:{a}:10.0.2.2:{a} https://wrong.test:{a}/index.html"
            ),
            "wrong-name",
            60,
        )?;
        // 5. A CA nobody knows, and the same without the check.
        expect_code(
            &mut run,
            &format!("curl -sS -o /dev/null https://10.0.2.2:{b}/index.html"),
            "unknown-ca",
            60,
        )?;
        step(
            &mut run,
            "insecure",
            &format!(
                "curl -sSk -o /tmp/b https://10.0.2.2:{b}/index.html && cmp /tmp/b /www/index.html"
            ),
            FETCH_WITHIN,
        )?;
        // 6. openssl s_client.
        let (code, lines) = coded(
            &mut run,
            &format!(
                "openssl s_client -connect 10.0.2.2:{a} -servername host.stafeto.test -CAfile {CA_BUNDLE} -verify_return_error </dev/null 2>&1"
            ),
            "s-client-a",
            FETCH_WITHIN,
        )?;
        if code != 0
            || !lines.iter().any(|l| l.contains("Verification: OK"))
            || !lines.iter().any(|l| negotiated_tls13(l))
        {
            return Err(format!("s_client to A ended with {code}: {lines:?}"));
        }
        let (code, lines) = coded(
            &mut run,
            &format!(
                "openssl s_client -connect 10.0.2.2:{b} -CAfile {CA_BUNDLE} -verify_return_error </dev/null 2>&1"
            ),
            "s-client-b",
            FETCH_WITHIN,
        )?;
        if code == 0 {
            return Err(format!("s_client to B passed the check: {lines:?}"));
        }
        // 7. Full records.
        let t = big(&mut run)?;
        times.push(("file of 256 KiB".into(), t));
        // 8. No listener.
        let t = expect_code(
            &mut run,
            &format!("curl -sS -m {REFUSED_LIMIT_S} https://10.0.2.2:{c}/"),
            "refused",
            7,
        )?;
        if t > Duration::from_secs(REFUSED_LIMIT_S) {
            return Err(format!(
                "a refused connection took {:.1} s",
                t.as_secs_f64()
            ));
        }
        times.push(("refused".into(), t));
        // 9. The speed of AES-128-GCM, with the extensions the CPU has and
        // with none (OPENSSL_armcap=0 skips the tries under SIGILL): the
        // first is the faster only when the tries found AES and PMULL.
        for (armcap, marker) in [("", "speed"), ("OPENSSL_armcap=0 ", "speed-c")] {
            let lines = capture(
                &mut run,
                &format!("{armcap}openssl speed -evp aes-128-gcm -seconds 1 -bytes 16384 2>&1"),
                marker,
                SPEED_WITHIN,
            )?;
            let line = speed_line(&lines).ok_or_else(|| format!("openssl speed: {lines:?}"))?;
            println!("net-tls: {armcap}openssl speed: {line}");
        }
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    if talked.is_err() {
        let from = output.lines.len().saturating_sub(40);
        println!("net-tls: the last lines of the console:");
        for line in &output.lines[from..] {
            println!("  {line}");
        }
    }
    talked?;
    drop(servers);
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
    }) {
        return Err("the network image faulted".into());
    }
    if mode == Mode::Steps {
        let rows = steps_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "net-tls steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            crate::net_probe::STEP_MAX
        );
    }
    let elapsed = started.elapsed();
    for (what, time) in &times {
        println!("net-tls: {what}: {:.2} s", time.as_secs_f64());
    }
    if mode == Mode::Normal && elapsed > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s, past the {} s of the group",
            elapsed.as_secs_f64(),
            RUN_WITHIN.as_secs()
        ));
    }
    println!(
        "net-tls passed in {:.0} s on {}",
        elapsed.as_secs_f64(),
        machine.name
    );
    Ok(())
}

/// Fails unless the boot image at `path` carries the CA file it should
/// (with the probe CA in the images of the probe) and the licence notes of
/// OpenSSL, curl and the root certificates.
fn image_has_tls_files(path: &Path, name: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let wanted = if name == net::IMAGE {
        ca_bundle()
    } else {
        probe_ca::bundle_with_ca()
    };
    if wanted.is_empty() || !image.files().any(|f| f.data == wanted) {
        return Err(format!("{name} carries no whole CA file"));
    }
    for note in [
        OPENSSL_LICENSE,
        OPENSSL_SOURCE,
        CURL_LICENSE,
        CURL_SOURCE,
        CA_BUNDLE_LICENSE,
        CA_BUNDLE_SOURCE,
    ] {
        if !image.files().any(|f| f.name == note && !f.data.is_empty()) {
            return Err(format!("{name} carries no {note}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_tls_large_file_is_fixed() {
        assert_eq!(big_file().len(), BIG_LEN);
        assert_ne!(&big_file()[..8], &big_file()[8..16]);
    }

    #[test]
    fn net_tls_version_of_the_connection() {
        assert!(negotiated_tls13(
            "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ecPublicKey"
        ));
        assert!(negotiated_tls13("Protocol: TLSv1.3"));
        assert!(negotiated_tls13("    Protocol  : TLSv1.3"));
        assert!(!negotiated_tls13(
            "* TLSv1.3 (OUT), TLS handshake, Client hello (1):"
        ));
        assert!(!negotiated_tls13("Protocol: TLSv1.2"));
    }

    #[test]
    fn net_tls_exit_code_and_speed_lines() {
        let lines: Vec<String> = ["curl: (60) SSL certificate problem", "rc=60"]
            .map(String::from)
            .to_vec();
        assert_eq!(exit_code(&lines), Some(60));
        assert_eq!(exit_code(&[]), None);
        let speed: Vec<String> = [
            "Doing AES-128-GCM ops for 1s on 16384 size blocks: 52 AES-128-GCM ops in 1.00s",
            "type             16384 bytes",
            "AES-128-GCM       851968.00k",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            speed_line(&speed).as_deref(),
            Some("AES-128-GCM 851968.00k")
        );
    }

    /// The images of the probe swap the CA file of the package for the one
    /// with the probe CA and add the large file; the image of the network
    /// keeps the package's.
    #[test]
    fn net_tls_images_list_their_ca_file() {
        for name in [IMAGE, STEPS_IMAGE] {
            let files = rootfs::files_of(name);
            let bundle = files.iter().find(|f| f.path == CA_BUNDLE).unwrap();
            assert_eq!(
                bundle.source.map(|s| s.file_name()).as_deref(),
                Some("bundle-with-ca.crt")
            );
            assert!(files.iter().any(|f| f.path == BIG));
            assert!(files.iter().any(|f| f.path == "/bin/curl"));
            assert!(files.iter().any(|f| f.path == "/bin/openssl"));
        }
        let files = rootfs::files_of(net::IMAGE);
        let bundle = files.iter().find(|f| f.path == CA_BUNDLE).unwrap();
        assert_eq!(
            bundle.source.map(|s| s.file_name()).as_deref(),
            Some("ca-certificates.crt")
        );
        assert!(!files.iter().any(|f| f.path == BIG));
        let shell = rootfs::files_of("boot-ash-dialog.img");
        assert!(
            !shell
                .iter()
                .any(|f| f.path == "/bin/curl" || f.path == CA_BUNDLE)
        );
    }
}
