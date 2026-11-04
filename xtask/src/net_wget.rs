// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The way out of the network service (`cargo xtask net-wget`): BusyBox
//! `wget` over HTTP and HTTPS, the name lookups of the C library, and the
//! file `/etc/resolv.conf` the service writes. The shell image with the
//! network service runs on QEMU's user network; xtask drives `ash` over the
//! serial port, as `net-curl` does, and is the server on the host:
//!
//! * HTTP: a server of its own on `127.0.0.1` (a free port), the guest
//!   reaches it as 10.0.2.2.
//! * HTTPS: `openssl s_server -WWW` on `127.0.0.1` with a certificate made
//!   for the run (BusyBox checks no certificate, and speaks TLS 1.2 only).
//!
//! The steps of the guest, in order:
//!
//! 1. The lease, the line `net: resolv.conf 10.0.2.3`, and the file with
//!    exactly that line.
//! 2. `first-contact`: one datagram to the name server and, at once, a TCP
//!    connect to the gateway: under 500 ms only if the service asked for the
//!    hardware addresses of both ahead of the first use.
//! 3. `wget` of the page over HTTP, compared with `cmp` to the page of the
//!    image.
//! 4. The same over HTTPS.
//! 5. A name server in the guest (`dnsd`) and a name for the host's address:
//!    `nslookup` and `wget` by name.
//! 6. A file with an unanswering server first (192.0.2.1, TEST-NET-1) and
//!    `dnsd` second: the lookup takes 5 s of the first and then succeeds.
//! 7. `net-dns checks`: the resolver against a name server that answers
//!    wrongly (tests/posix-so/dyn/net-dns.c).
//! 8. The name server of the lease and a real name, when the runner's own
//!    resolver knows it; the step says when it is skipped.
//!
//! `cargo xtask net-wget steps` counts the steps of the service under the
//! same traffic (`-icount shift=4,sleep=on`) and judges them against 0.9 of
//! term B. `cargo xtask net-wget internet` (a manual run; the ci jobs leave it out) fetches
//! example.com over HTTP and HTTPS through the user network.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, Variant, build, build_boot_image,
    busybox_build, nano_build, net, net_curl, qemu, relibc, rootfs, symbolize,
};

/// The checks of `net-dns`, in the order the program runs them.
pub const CHECKS: [&str; 13] = [
    "answer", "id", "source", "question", "retry", "servfail", "nxdomain", "nodata", "timeout",
    "loop", "parse", "leak", "badname",
];

/// The whole run may take this long (the ci group allows 120 s).
const RUN_WITHIN: Duration = Duration::from_secs(110);
/// The time one `wget` of the page may take, by the step.
const HTTP_WITHIN: Duration = Duration::from_secs(20);
const HTTPS_WITHIN: Duration = Duration::from_secs(30);
const CHECKS_WITHIN: Duration = Duration::from_secs(45);
/// The time a lookup of a real name may take in step 8 (two rounds of five
/// seconds of the resolver, and the start of the program).
const REAL_NAME_WITHIN: Duration = Duration::from_secs(25);
/// The first connect of the guest must be quick: the hardware addresses of
/// the gateway and the name server were asked for ahead of it.
const FIRST_CONTACT_MAX_MS: u64 = 500;
/// A lookup whose first server is silent takes at least one deadline of the
/// resolver (5 s; the least allows for the clock of the guest) and, with a
/// good second server, at most the 11 s of the spec.
const SILENT_FIRST_MIN: Duration = Duration::from_secs(4);
const SILENT_FIRST_MAX: Duration = Duration::from_secs(11);

/// How a run goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Steps,
    Internet,
}

/// A server of the page over HTTP, on a thread: every `GET /index.html` gets
/// the page, other paths a 404; the connection closes after the answer.
struct Http {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Http {
    fn start() -> Result<Http, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("http: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("http: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("http: {e}"))?
            .port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        std::thread::spawn(move || {
                            let _ = serve(stream);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(Http {
            port,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One connection: the request line decides the answer.
fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 256];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&byte[..n]);
    }
    stream.write_all(&answer_to(&head))?;
    stream.flush()
}

/// The bytes the server sends for the request `head`.
fn answer_to(head: &[u8]) -> Vec<u8> {
    let line = head.split(|&b| b == b'\r').next().unwrap_or(&[]);
    let mut out = Vec::new();
    if line.starts_with(b"GET /index.html ") {
        let page = rootfs::www_index();
        out.extend_from_slice(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                page.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(page);
    } else {
        out.extend_from_slice(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    }
    out
}

/// `openssl s_server -WWW` on a free port of 127.0.0.1 with a certificate
/// made for the run, serving the page from a directory of its own.
struct Tls {
    port: u16,
    child: Child,
    _stdin: std::process::ChildStdin,
}

impl Tls {
    fn start() -> Result<Tls, String> {
        let directory = crate::root().join("target").join("net-wget");
        std::fs::create_dir_all(&directory).map_err(|e| format!("{directory:?}: {e}"))?;
        std::fs::write(directory.join("index.html"), rootfs::www_index())
            .map_err(|e| format!("the page: {e}"))?;
        let version = Command::new("openssl")
            .arg("version")
            .output()
            .map_err(|e| format!("openssl is needed for the HTTPS step and is not there: {e}"))?;
        println!(
            "net-wget: {}",
            String::from_utf8_lossy(&version.stdout).trim()
        );
        let made = Command::new("openssl")
            .current_dir(&directory)
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=10.0.2.2",
                "-keyout",
                "k.pem",
                "-out",
                "c.pem",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("openssl req: {e}"))?;
        if !made.success() {
            return Err(format!("openssl req ended with {made}"));
        }
        let port = {
            let listener =
                TcpListener::bind("127.0.0.1:0").map_err(|e| format!("a free port: {e}"))?;
            listener
                .local_addr()
                .map_err(|e| format!("a free port: {e}"))?
                .port()
        };
        let mut child = Command::new("openssl")
            .current_dir(&directory)
            .args([
                "s_server",
                "-accept",
                &format!("127.0.0.1:{port}"),
                "-WWW",
                "-quiet",
                "-tls1_2",
                "-cert",
                "c.pem",
                "-key",
                "k.pem",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("openssl s_server: {e}"))?;
        let stdin = child.stdin.take().ok_or("openssl s_server: no stdin")?;
        let address: SocketAddr = ([127, 0, 0, 1], port).into();
        let started = Instant::now();
        loop {
            if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
                break;
            }
            if started.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("openssl s_server did not listen within 10 s".to_owned());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(Tls {
            port,
            child,
            _stdin: stdin,
        })
    }
}

impl Drop for Tls {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The IPv4 addresses the host's resolver gives `name`, within 5 s; None when
/// it gives none.
fn host_resolves(name: &str) -> Option<Vec<[u8; 4]>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let name = format!("{name}:80");
    std::thread::spawn(move || {
        let found: Vec<[u8; 4]> = name
            .to_socket_addrs()
            .map(|it| {
                it.filter_map(|a| match a {
                    SocketAddr::V4(v4) => Some(v4.ip().octets()),
                    SocketAddr::V6(_) => None,
                })
                .collect()
            })
            .unwrap_or_default();
        let _ = sender.send(found);
    });
    receiver
        .recv_timeout(Duration::from_secs(5))
        .ok()
        .filter(|found| !found.is_empty())
}

/// Dotted IPv4 addresses in the `Address` lines of `nslookup` that follow its
/// `Name:` line (the lines before it name the server), and in the `resolved`
/// lines of `net-dns resolve`.
fn addresses_in(lines: &[String]) -> Vec<[u8; 4]> {
    let mut out = Vec::new();
    let mut named = false;
    for line in lines {
        let text = line.trim();
        let candidate = if let Some(rest) = text.strip_prefix("net-dns: resolved ") {
            Some(rest)
        } else if text.starts_with("Name:") {
            named = true;
            None
        } else if named && text.starts_with("Address") {
            text.split_once(':').map(|(_, rest)| rest.trim())
        } else {
            None
        };
        if let Some(address) = candidate
            && let Some(octets) = parse_ipv4(address.split_whitespace().next().unwrap_or(""))
            && !out.contains(&octets)
        {
            out.push(octets);
        }
    }
    out
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.split('.').collect();
    let [a, b, c, d] = parts.as_slice() else {
        return None;
    };
    Some([
        a.parse().ok()?,
        b.parse().ok()?,
        c.parse().ok()?,
        d.parse().ok()?,
    ])
}

/// Sends `command` between two marker lines and gives the lines between them
/// (the output of the command), waiting up to `within` for the end.
fn capture(
    run: &mut qemu::Run,
    command: &str,
    marker: &str,
    within: Duration,
) -> Result<Vec<String>, String> {
    let begin = format!("begin-{marker}");
    let end = format!("end-{marker}");
    run.send(&format!("echo {begin}; {command}; echo {end}"))?;
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
    Ok(text[first + 1..last].to_vec())
}

/// Runs a command that ends with `echo NAME-ok` on success and `echo
/// NAME-no` on failure (the shell variable `S` holds `ok`, so the typed
/// command does not hold the answer), and gives the time it took.
fn step(
    run: &mut qemu::Run,
    name: &str,
    command: &str,
    within: Duration,
) -> Result<Duration, String> {
    let started = Instant::now();
    run.send(&format!("({command} && echo {name}-$S) || echo {name}-no"))?;
    let good = format!("{name}-ok");
    let bad = format!("{name}-no");
    let line = run
        .expect_line(
            name,
            |l| {
                let l = l.trim();
                l == good || l == bad
            },
            within,
        )
        .map_err(|e| format!("{name}: {e}"))?;
    let elapsed = started.elapsed();
    if line.trim() == bad {
        let tail: Vec<String> = run.text().iter().rev().take(8).rev().cloned().collect();
        return Err(format!("{name} failed; last lines: {tail:?}"));
    }
    Ok(elapsed)
}

/// `net-dns checks`: a line for each, then the count.
fn checks(run: &mut qemu::Run) -> Result<(), String> {
    run.send("net-dns checks")?;
    let deadline = Instant::now() + CHECKS_WITHIN;
    let mut seen = 0;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = run.expect_line("a line of net-dns", |l| text_of(l).is_some(), left)?;
        let line = text_of(&line).unwrap_or_default().to_owned();
        if line.contains(" failed: ") {
            return Err(format!("net-dns: {line}"));
        }
        if let Some(count) = line.strip_suffix(" checks ok") {
            let count: usize = count.parse().map_err(|_| format!("{line:?}"))?;
            if count != CHECKS.len() || seen != count {
                return Err(format!(
                    "net-dns ran {count} checks, {seen} lines said ok, xtask knows {}",
                    CHECKS.len()
                ));
            }
            return Ok(());
        }
        let name = line
            .strip_suffix(" ok")
            .ok_or_else(|| format!("an unknown line of net-dns: {line:?}"))?;
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

/// What a line says after `net-dns: `, for the lines the checks print.
fn text_of(line: &str) -> Option<&str> {
    let (_, text) = line.split_once("net-dns: ")?;
    (text.ends_with(" ok") || text.contains(" failed: ")).then_some(text)
}

/// The time `net-dns first-contact` printed, in milliseconds.
fn first_contact_ms(lines: &[String]) -> Option<u64> {
    lines.iter().find_map(|l| {
        let rest = l.split_once("net-dns: first-contact connect ")?.1;
        rest.strip_suffix(" ms")?.trim().parse().ok()
    })
}

/// The steps of the service: the kinds that wget's traffic makes came (the
/// service's own, Send, Recv, Clone) and every row is under STEP_MAX, a
/// CLONE under PORTION_MAX.
fn steps_verdict(lines: &[String]) -> Result<Vec<(usize, u64, u64)>, String> {
    const KINDS: [(usize, &str); 4] = [
        (65, "the own steps"),
        (8, "Send"),
        (10, "Recv"),
        (19, "Clone"),
    ];
    let rows = crate::net_probe::longest_over_starts(lines);
    for (kind, name) in KINDS {
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
        .find(|r| r.0 == 19 && r.1 > crate::net_probe::PORTION_MAX)
    {
        return Err(format!(
            "the network service: CLONE past 0.8 of term B ({}): {row:?}",
            crate::net_probe::PORTION_MAX
        ));
    }
    Ok(rows)
}

/// `cargo xtask net-wget [steps|internet] [MACHINE]`.
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
        _ => return Err("usage: cargo xtask net-wget [steps|internet] [tcg|hvf]".to_owned()),
    };
    probe(machine, mode)
}

pub fn probe(machine: &'static qemu::Machine, mode: Mode) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    busybox_build()?;
    nano_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let steps = mode == Mode::Steps;
    let (name, programs) = if steps {
        (net_curl::STEPS_IMAGE, net_curl::steps_programs())
    } else {
        (net::IMAGE, net::programs())
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let http = Http::start()?;
    let tls = if mode == Mode::Internet {
        None
    } else {
        Some(Tls::start()?)
    };
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net(&[]));
    if steps {
        cmd.args(["-icount", "shift=4,sleep=on"]);
    }
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let mut times: Vec<(String, Duration)> = Vec::new();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        // 1. The lease and the file.
        run.expect_line(
            "the lease",
            |l| l.contains("net: lease 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3"),
            BOOT_TIMEOUT,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        // The line may have come before or after the prompt.
        run.expect_seen("net: resolv.conf 10.0.2.3", DIALOG_STEP)?;
        run.send("S=ok")?;
        run.expect("# ", DIALOG_STEP)?;
        let file = capture(&mut run, "cat /etc/resolv.conf", "r1", DIALOG_STEP)?;
        if file != ["nameserver 10.0.2.3"] {
            return Err(format!("/etc/resolv.conf is {file:?}"));
        }
        println!("net-wget: /etc/resolv.conf written by the service ok");
        let after = capture(
            &mut run,
            "cp /etc/resolv.conf /tmp/resolv.lease",
            "r2",
            DIALOG_STEP,
        )?;
        if !after.is_empty() {
            return Err(format!("cp /etc/resolv.conf: {after:?}"));
        }
        if mode == Mode::Internet {
            return internet(&mut run, &mut times);
        }
        let tls = tls.as_ref().ok_or("no TLS server")?;
        let (p, q) = (http.port, tls.port);

        // 2. The first contact.
        let first = capture(
            &mut run,
            &format!("net-dns first-contact 10.0.2.3 10.0.2.2 {p}"),
            "fc",
            DIALOG_STEP,
        )?;
        let ms = first_contact_ms(&first).ok_or_else(|| format!("first-contact: {first:?}"))?;
        println!("net-wget: first contact {ms} ms");
        if ms > FIRST_CONTACT_MAX_MS {
            return Err(format!(
                "the first connect to the gateway took {ms} ms, past {FIRST_CONTACT_MAX_MS} (no ARP ahead of it)"
            ));
        }

        // 3. HTTP.
        let t = step(
            &mut run,
            "wget-http",
            &format!(
                "wget -q -T 15 -O /tmp/w http://10.0.2.2:{p}/index.html && cmp /tmp/w /www/index.html"
            ),
            HTTP_WITHIN,
        )?;
        times.push(("http".into(), t));
        // 4. HTTPS.
        let t = step(
            &mut run,
            "wget-https",
            &format!(
                "wget -q -T 20 -O /tmp/s https://10.0.2.2:{q}/index.html && cmp /tmp/s /www/index.html"
            ),
            HTTPS_WITHIN,
        )?;
        times.push(("https".into(), t));

        // 5. A name server in the guest.
        run.send("printf 'name.test 10.0.2.2\\n' > /tmp/dnsd.conf")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("dnsd -c /tmp/dnsd.conf -i 127.0.0.1 -p 53 & D=$!")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("printf 'nameserver 127.0.0.1\\n' > /etc/resolv.conf")?;
        run.expect("# ", DIALOG_STEP)?;
        let found = capture(&mut run, "nslookup name.test", "ns", DIALOG_STEP)?;
        if !addresses_in(&found).contains(&[10, 0, 2, 2]) {
            return Err(format!("nslookup name.test gave {found:?}"));
        }
        let by_name = format!(
            "wget -q -T 15 -O /tmp/n http://name.test:{p}/index.html && cmp /tmp/n /www/index.html"
        );
        let t = step(&mut run, "wget-name", &by_name, HTTP_WITHIN)?;
        times.push(("name".into(), t));

        // 6. A silent first server.
        run.send("printf 'nameserver 192.0.2.1\\nnameserver 127.0.0.1\\n' > /etc/resolv.conf")?;
        run.expect("# ", DIALOG_STEP)?;
        let t = step(&mut run, "wget-silent", &by_name, HTTP_WITHIN)?;
        times.push(("silent first server".into(), t));
        if t < SILENT_FIRST_MIN || t > SILENT_FIRST_MAX {
            return Err(format!(
                "a lookup with a silent first server took {:.1} s, wanted {} to {} s",
                t.as_secs_f64(),
                SILENT_FIRST_MIN.as_secs(),
                SILENT_FIRST_MAX.as_secs()
            ));
        }

        // 7. The resolver against wrong answers (its own name server takes
        // the port of dnsd).
        run.send("kill $D; wait $D")?;
        run.expect("# ", DIALOG_STEP)?;
        let began = Instant::now();
        checks(&mut run)?;
        times.push(("net-dns checks".into(), began.elapsed()));
        run.expect("# ", DIALOG_STEP)?;

        // 8. A real name through the lease's server.
        run.send("cp /tmp/resolv.lease /etc/resolv.conf")?;
        run.expect("# ", DIALOG_STEP)?;
        real_name(&mut run)?;
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    if talked.is_err() {
        let from = output.lines.len().saturating_sub(40);
        println!("net-wget: the last lines of the console:");
        for line in &output.lines[from..] {
            println!("  {line}");
        }
    }
    talked?;
    drop(tls);
    drop(http);
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
            || line.contains("net: resolv.conf unwritable")
    }) {
        return Err("the network image faulted".into());
    }
    if steps {
        let rows = steps_verdict(&output.lines)?;
        let worst = rows.iter().max_by_key(|r| r.1).copied().unwrap_or_default();
        println!(
            "net-wget steps: the longest step is kind {} with {} ticks and detail {} (the bound is {}); every kind: {rows:?}",
            worst.0,
            worst.1,
            worst.2,
            crate::net_probe::STEP_MAX
        );
    }
    let elapsed = started.elapsed();
    for (what, time) in &times {
        println!("net-wget: {what}: {:.1} s", time.as_secs_f64());
    }
    if mode == Mode::Normal && elapsed > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s, past the {} s of the group",
            elapsed.as_secs_f64(),
            RUN_WITHIN.as_secs()
        ));
    }
    println!(
        "net-wget passed in {:.0} s on {}",
        elapsed.as_secs_f64(),
        machine.name
    );
    Ok(())
}

/// Step 8: `nslookup` and `net-dns resolve` for example.com against the
/// host's own answer. Skipped, with a line, when the host cannot resolve.
fn real_name(run: &mut qemu::Run) -> Result<(), String> {
    let Some(mut host) = host_resolves("example.com") else {
        println!("dns: host has no resolver, step skipped");
        return Ok(());
    };
    for round in 0..4 {
        // The runner's resolver may be slow: a lookup that does not end in
        // time counts as an empty answer, which the host's own lookup below
        // judges.
        let lookup = capture(
            run,
            "nslookup example.com",
            &format!("dn{round}"),
            REAL_NAME_WITHIN,
        )
        .unwrap_or_default();
        let resolve = capture(
            run,
            "net-dns resolve example.com",
            &format!("dr{round}"),
            REAL_NAME_WITHIN,
        )
        .unwrap_or_default();
        let (a, b) = (addresses_in(&lookup), addresses_in(&resolve));
        if a.is_empty() || b.is_empty() {
            match host_resolves("example.com") {
                Some(more) => {
                    return Err(format!(
                        "the guest got no address for example.com (nslookup {lookup:?}, resolve {resolve:?}) while the host has {more:?}"
                    ));
                }
                None => {
                    println!("dns: host resolver lost, step skipped");
                    return Ok(());
                }
            }
        }
        let meets = |guest: &[[u8; 4]]| guest.iter().any(|g| host.contains(g));
        if meets(&a) && meets(&b) {
            println!(
                "net-wget: example.com resolved by nslookup {a:?} and by getaddrinfo {b:?}, host {host:?}"
            );
            return Ok(());
        }
        // The addresses of a CDN go round: ask the host again and add them.
        if let Some(more) = host_resolves("example.com") {
            for address in more {
                if !host.contains(&address) {
                    host.push(address);
                }
            }
        }
    }
    Err(format!(
        "the addresses of example.com in the guest never met the host's {host:?}"
    ))
}

/// The manual run: example.com over HTTP and HTTPS and its lookup, with the
/// time of each.
fn internet(run: &mut qemu::Run, times: &mut Vec<(String, Duration)>) -> Result<(), String> {
    let t = step(
        run,
        "internet-http",
        "wget -q -T 30 -O - http://example.com/ | grep '<title>Example Domain</title>'",
        Duration::from_secs(60),
    )?;
    times.push(("example.com over http".into(), t));
    let t = step(
        run,
        "internet-https",
        "wget -q -T 30 -O - https://example.com/ | grep '<title>Example Domain</title>'",
        Duration::from_secs(60),
    )?;
    times.push(("example.com over https".into(), t));
    let began = Instant::now();
    let lookup = capture(run, "nslookup example.com", "inl", Duration::from_secs(30))?;
    times.push(("nslookup example.com".into(), began.elapsed()));
    println!("net-wget: nslookup example.com: {lookup:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checks xtask expects are those the program runs, in its order.
    #[test]
    fn the_checks_are_those_of_the_program() {
        let source =
            std::fs::read_to_string(crate::root().join("tests/posix-so/dyn/net-dns.c")).unwrap();
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
    fn the_server_answers_the_page_and_a_404() {
        let page = answer_to(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(page.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(page.ends_with(rootfs::www_index()));
        let none = answer_to(b"GET /other HTTP/1.1\r\n\r\n");
        assert!(none.starts_with(b"HTTP/1.1 404 "));
    }

    #[test]
    fn addresses_come_from_both_programs() {
        let lookup: Vec<String> = [
            "Server:\t\t10.0.2.3",
            "Address:\t10.0.2.3:53",
            "",
            "Name:\texample.com",
            "Address: 93.184.216.34",
            "Address: 2606:2800:220:1::1",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(addresses_in(&lookup), [[93, 184, 216, 34]]);
        let resolve: Vec<String> = ["net-dns: resolved 1.2.3.4", "net-dns: resolved 1.2.3.4"]
            .map(String::from)
            .to_vec();
        assert_eq!(addresses_in(&resolve), [[1, 2, 3, 4]]);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.256"), None);
    }

    #[test]
    fn the_first_contact_time_comes_from_its_line() {
        let lines = vec!["net-dns: first-contact connect 12 ms".to_owned()];
        assert_eq!(first_contact_ms(&lines), Some(12));
        assert_eq!(first_contact_ms(&[]), None);
    }

    #[test]
    fn the_lines_of_the_checks_are_told_from_the_rest() {
        assert_eq!(text_of("# net-dns: answer ok"), Some("answer ok"));
        assert_eq!(
            text_of("net-dns: id failed: x errno 1"),
            Some("id failed: x errno 1")
        );
        assert_eq!(text_of("net-dns: resolved 1.2.3.4"), None);
    }

    #[test]
    fn the_steps_need_the_kinds_the_traffic_makes() {
        assert!(steps_verdict(&[]).is_err());
    }
}
