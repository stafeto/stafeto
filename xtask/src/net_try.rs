// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The try-out image of EC2 on QEMU (`cargo xtask net-try`): `boot-aws-qemu.img`, the image of
//! the shell on EC2 (`boot-aws.img`: nginx on 80 and 443, nginx-fast on 8080 through the switch,
//! Dropbear, `pkg`, the page written at boot) with init's table `table-aws-qemu`, the services
//! of the AWS table over virtio-net and the PL011. QEMU's user network stands for the VPC: its
//! ports 22, 80, 443 and 8080 and every other port of the scan below are forwarded from the host.
//!
//! The image has no metadata service to ask for the key of the instance, so its `ec2-key` writes
//! a key the probe made (net-ec2-key is the probe of the real one), and its official repository is
//! the mirror of the probe (`tools/pkg-mirror.py`, the probe CA in the certificate file, the
//! development root in the keys), as in `pkg-probe`.
//!
//! The steps:
//!
//! 0. The image check (`check_files`, the plan's security floor) on both images: no file in
//!    `/etc/dropbear`, every entry of `/etc/shadow` locked with `!`, no private key anywhere
//!    (no file named as one, no PEM or OpenSSH private key in a file of text, none in any file of
//!    the built image), the boot script starts nothing but the five servers' scripts and none of
//!    them starts BusyBox `httpd` or `telnetd`, and the settings of nginx name no port besides
//!    80, 443 and 8080.
//! 1. The console says, once the boot script has run: the SSH host key line, the page written,
//!    the certificate, nginx on 80 and 443, nginx-fast on 8080.
//! 2. The page: the same bytes on 80, 443 (TLS 1.3, the certificate the instance made) and 8080
//!    and in `/www/index.html`, with what the plan says it must tell.
//! 3. A login with the probe key; the host key the client saw is the one the console named; the
//!    private key and certificate of nginx were made on the instance (the key is `-rw-------`).
//! 4. `pkg update` and `pkg search` against the mirror of the probe.
//! 5. The processes: dropbear, nginx and nginx-fast run, `httpd` and `telnetd` do not.
//! 6. The scan: of the ports of the host's forwards (1 to 1 024, 8 000 to 8 199 and a few usual
//!    ones) only 22, 80, 443 and 8080 keep a connection open.
//! 7. The console shows no fault.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::net_ssh::{Client, host_ssh, make_key, run_for};
use crate::qemu::{Forward, Proto};
use crate::rootfs::{RootFile, Source};
use crate::{
    BOOT_PROFILE, SERVICES_STARTED, Variant, build, busybox_build, keys, nano_build, pkg_probe,
    probe_ca, qemu, relibc, rootfs, symbolize,
};

/// The image of the run.
pub const IMAGE: &str = "boot-aws-qemu.img";
/// The image of EC2, which the image check covers as well.
pub const AWS_IMAGE: &str = "boot-aws.img";

/// The ports that answer on the instance.
const OPEN: [u16; 4] = [22, 80, 443, 8080];
/// The port of the mirror of the probe (the image names it, `pkg_probe::official_address`).
const MIRROR_PORT: u16 = 8443;

/// The boot scripts the list of `/etc/rc` may name: the five servers' and helpers' of the image.
const SCRIPTS: [&str; 5] = ["ec2-key", "dropbear", "landing", "web", "fast"];
/// Programs that listen on a port when started, which no boot script of the image runs.
const FORBIDDEN: [&str; 7] = [
    "httpd", "telnetd", "inetd", "ftpd", "tftpd", "dnsd", "udhcpd",
];

/// A console line wait: the boot script of the image runs after the services started and the
/// lease came, with the certificate made on an emulated CPU.
const BOOT_WITHIN: Duration = Duration::from_secs(300);
/// One login or one command through `ssh`.
const SSH_WITHIN: Duration = Duration::from_secs(240);
/// `pkg update` over TLS on an emulated CPU.
const PKG_WITHIN: Duration = Duration::from_secs(300);
/// The whole run.
const RUN_WITHIN: Duration = Duration::from_secs(1500);
/// How long a connection of the scan is watched: a closed port shuts it at once.
const SCAN_WINDOW: Duration = Duration::from_secs(5);
/// The second look at a port the first found open, at a slow guest.
const SCAN_RECHECK: Duration = Duration::from_secs(20);

// ---- the key of the probe ----------------------------------------------------------------

/// The public key line `ec2-key` of the image writes: the key of the run (`KEY`), or a fixed one
/// of the right form where nothing runs.
static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
const PLACEHOLDER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA placeholder";

/// The script that stands for `ec2-key` in the image of the run: it writes the key of the run as
/// the metadata of an instance would give it.
pub fn key_script() -> &'static [u8] {
    static SCRIPT: std::sync::OnceLock<&'static [u8]> = std::sync::OnceLock::new();
    SCRIPT.get_or_init(|| {
        let key = KEY.get().map_or(PLACEHOLDER_KEY, String::as_str);
        let text = format!(
            "umask 077\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\necho '{key}' > /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\necho 'ec2-key: the key of the probe is placed'\n"
        );
        Box::leak(text.into_bytes().into_boxed_slice())
    })
}

// ---- the image check ---------------------------------------------------------------------

/// The bytes of a file of text of the image.
fn bytes_of<'a>(files: &'a [RootFile], path: &str) -> Option<&'a [u8]> {
    files
        .iter()
        .find(|f| f.path == path)
        .and_then(|f| match f.source {
            Some(Source::Bytes(_, bytes)) => Some(bytes),
            _ => None,
        })
}

/// Whether `bytes` hold the head of a private key: a PEM block (`-----BEGIN ... PRIVATE KEY-----`)
/// or the magic of an OpenSSH key file.
pub fn holds_private_key(bytes: &[u8]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN ";
    if bytes.windows(15).any(|w| w == b"openssh-key-v1\0") {
        return true;
    }
    let mut from = 0;
    while let Some(at) = bytes[from..].windows(BEGIN.len()).position(|w| w == BEGIN) {
        let start = from + at + BEGIN.len();
        let head = &bytes[start..bytes.len().min(start + 40)];
        let label = head.split(|&b| b == b'-').next().unwrap_or(&[]);
        if label.ends_with(b"PRIVATE KEY") {
            return true;
        }
        from = start;
    }
    false
}

/// The ports a settings file of nginx listens on: the number after each `listen`.
fn listen_ports(text: &str) -> Vec<u16> {
    text.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next() == Some("listen")).then(|| words.next())?
        })
        .filter_map(|w| {
            w.trim_end_matches(';')
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
        })
        .collect()
}

/// The words of a script that are not in its comments.
fn code_words(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .flat_map(|l| l.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')))
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The image check of the plan (the security floor of the try-out), on the files of an image: it
/// gives one line for each rule that holds, and an error for the first that does not.
pub fn check_files(files: &[RootFile]) -> Result<Vec<String>, String> {
    let mut report = Vec::new();

    // No key of the host: the SSH server makes its own at boot.
    let held: Vec<&str> = files
        .iter()
        .map(|f| f.path)
        .filter(|p| p.starts_with("/etc/dropbear/"))
        .collect();
    if !held.is_empty() {
        return Err(format!("the image holds files of /etc/dropbear: {held:?}"));
    }
    report.push("no file in /etc/dropbear".to_owned());

    // Every account locked.
    let shadow = bytes_of(files, "/etc/shadow").ok_or("the image has no /etc/shadow")?;
    let shadow = String::from_utf8_lossy(shadow);
    let mut accounts = 0;
    for line in shadow.lines() {
        let field = line.split(':').nth(1).unwrap_or("");
        if !field.starts_with('!') {
            return Err(format!(
                "/etc/shadow: the entry of {} is not locked with !",
                line.split(':').next().unwrap_or("?")
            ));
        }
        accounts += 1;
    }
    if accounts == 0 {
        return Err("/etc/shadow has no entry".to_owned());
    }
    report.push(format!(
        "all {accounts} entries of /etc/shadow start with !"
    ));

    // No private key: by name and by content.
    for f in files {
        let path = f.path;
        let name = path.rsplit('/').next().unwrap_or(path);
        let named = path.ends_with(".key")
            || path.ends_with(".pem")
            || path.ends_with("_key")
            || name.starts_with("id_")
            || name.contains("host_key");
        if named {
            return Err(format!("{path} is named as a private key"));
        }
        if let Some(Source::Bytes(_, bytes)) = f.source
            && holds_private_key(bytes)
        {
            return Err(format!("{path} holds a private key"));
        }
    }
    report.push("no file named as a private key, none of text holds one".to_owned());

    // The boot script starts the servers of the image and nothing else.
    let rc = bytes_of(files, "/etc/rc").ok_or("the image has no /etc/rc")?;
    let rc = String::from_utf8_lossy(rc);
    let list = rc
        .lines()
        .find_map(|l| l.trim().strip_prefix("for name in "))
        .and_then(|l| l.split(';').next())
        .ok_or("/etc/rc has no list of scripts")?;
    for name in list.split_whitespace() {
        if !SCRIPTS.contains(&name) {
            return Err(format!(
                "/etc/rc runs {name}, which is no script of the image"
            ));
        }
    }
    for f in files.iter().filter(|f| f.path.starts_with("/etc/rc.d/")) {
        let Some(Source::Bytes(_, bytes)) = f.source else {
            continue;
        };
        for word in code_words(&String::from_utf8_lossy(bytes)) {
            if FORBIDDEN.contains(&word.as_str()) {
                return Err(format!("{} starts {word}", f.path));
            }
        }
    }
    for path in ["/etc/inetd.conf", "/etc/inittab", "/etc/rc.local"] {
        if files.iter().any(|f| f.path == path) {
            return Err(format!("the image has {path}"));
        }
    }
    report.push(format!(
        "/etc/rc runs {} and no script starts httpd, telnetd or another server of BusyBox",
        list.trim()
    ));

    // The ports: the settings of nginx and the options of the SSH server.
    let mut ports = std::collections::BTreeSet::new();
    for f in files
        .iter()
        .filter(|f| f.path.starts_with("/etc/nginx/") && f.path.ends_with(".conf"))
    {
        if let Some(Source::Bytes(_, bytes)) = f.source {
            for port in listen_ports(&String::from_utf8_lossy(bytes)) {
                if !OPEN.contains(&port) {
                    return Err(format!("{} listens on port {port}", f.path));
                }
                ports.insert(port);
            }
        }
    }
    for want in [80, 443, 8080] {
        if !ports.contains(&want) {
            return Err(format!("no settings of nginx listen on {want}"));
        }
    }
    let dropbear = bytes_of(files, "/etc/rc.d/dropbear").ok_or("the image has no rc.d/dropbear")?;
    let dropbear = String::from_utf8_lossy(dropbear);
    // The options of the server are the words of the line `args=...`.
    let args = dropbear
        .lines()
        .find(|l| l.starts_with("args="))
        .ok_or("/etc/rc.d/dropbear has no line of options")?;
    if code_words(args).iter().any(|w| w == "-p") {
        return Err("/etc/rc.d/dropbear gives the server a port (-p)".to_owned());
    }
    report.push("nginx listens on 80, 443 and 8080, the SSH server on its own port 22".to_owned());
    Ok(report)
}

/// The check on the files of the image `name` as the table lists them.
pub fn check_image(name: &str) -> Result<Vec<String>, String> {
    check_files(&rootfs::files_of(name)).map_err(|e| format!("{name}: {e}"))
}

/// The check of the built image: no file of its container holds a private key.
fn check_built(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut files = 0;
    for f in image.files() {
        if holds_private_key(f.data) {
            return Err(format!(
                "{}: the file {:?} of the image holds a private key",
                path.display(),
                f.name
            ));
        }
        files += 1;
    }
    println!(
        "net-try: none of the {files} files of the built image holds a private key ({} bytes)",
        bytes.len()
    );
    Ok(())
}

// ---- the clients -------------------------------------------------------------------------

/// `n` free ports of the host, taken together so that no two are the same.
fn free_ports(n: usize) -> Result<Vec<u16>, String> {
    let held: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").map_err(|e| format!("a free port: {e}")))
        .collect::<Result<_, _>>()?;
    held.iter()
        .map(|l| l.local_addr().map(|a| a.port()).map_err(|e| e.to_string()))
        .collect()
}

/// A GET of `/` over plain HTTP: the status line and the body.
fn http_get(port: u16) -> Result<(String, Vec<u8>), String> {
    let address: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(30))
        .map_err(|e| format!("port {port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
        .map_err(|e| format!("port {port}: {e}"))?;
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .map_err(|e| format!("port {port}: {e}"))?;
    let split = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("port {port}: no end of the head in {} bytes", reply.len()))?;
    let head = String::from_utf8_lossy(&reply[..split]).into_owned();
    let status = head.lines().next().unwrap_or("").to_owned();
    Ok((status, reply[split + 4..].to_vec()))
}

/// A GET of `/` over TLS 1.3 with the host's `curl`, which accepts the certificate of the
/// instance (it is self-signed): the body and the HTTP version curl negotiated.
fn https_get(port: u16) -> Result<(Vec<u8>, String), String> {
    let out = Command::new("curl")
        .args([
            "-sk",
            "--tlsv1.3",
            "--max-time",
            "120",
            "-w",
            "\n%{http_version}",
        ])
        .arg(format!("https://127.0.0.1:{port}/"))
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl of https://127.0.0.1:{port}/ ended with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let mut body = out.stdout;
    let cut = body
        .iter()
        .rposition(|&b| b == b'\n')
        .ok_or("curl gave no version")?;
    let version = String::from_utf8_lossy(&body[cut + 1..]).trim().to_owned();
    body.truncate(cut);
    Ok((body, version))
}

/// What the page must say (the plan's section 3, item 4, and section 1, item 6).
const PAGE_SAYS: [&str; 15] = [
    "experimental operating system",
    "microkernel written in Rust",
    "This is an experimental system",
    "Keep no secrets on it",
    "only to your own address",
    "ssh root@",
    "key pair you chose when you launched",
    "pkg update",
    "pkg search nginx",
    "pkg install htop",
    "A reboot or a stop of the instance removes them all",
    "changes each time the instance starts",
    ":8080/",
    "<td>8080</td>",
    "nginx-fast",
];

/// The body of the page the way the guest wrote it, checked for what it must tell.
fn check_page(body: &[u8], from: &str) -> Result<(), String> {
    let text = String::from_utf8_lossy(body);
    let mut lacking = Vec::new();
    for words in PAGE_SAYS {
        if !text.contains(words) {
            lacking.push(words);
        }
    }
    if !lacking.is_empty() {
        return Err(format!("the page of {from} does not say {lacking:?}"));
    }
    for hole in ["@ADDRESS@", "@TYPE@", "@VERSION@"] {
        if text.contains(hole) {
            return Err(format!("the page of {from} still holds {hole}"));
        }
    }
    Ok(())
}

/// The guest ports the scan forwards: 1 to 1 024, 8 000 to 8 199 and the usual ones, less
/// those that answer.
fn scan_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = (1..=1024).chain(8000..=8199).collect();
    ports.extend([
        2222, 3000, 3306, 5000, 5432, 6379, 8443, 9000, 9090, 9200, 27017,
    ]);
    ports.retain(|p| !OPEN.contains(p));
    ports
}

/// Whether a connection to the forwarded port stays open for `window`: QEMU takes the connection
/// at once and shuts it when the guest refuses, so a connection that lives is a port that listens.
fn stays_open(host: u16, window: Duration) -> bool {
    let address: SocketAddr = ([127, 0, 0, 1], host).into();
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(10)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(window));
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) => matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

/// The guest ports of `forwards` that listen.
fn scan(forwards: &[(u16, u16)]) -> Vec<u16> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let open = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..32 {
            scope.spawn(|| {
                loop {
                    let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(&(host, guest)) = forwards.get(at) else {
                        return;
                    };
                    if stays_open(host, SCAN_WINDOW) {
                        open.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push((host, guest));
                    }
                }
            });
        }
    });
    let mut found = open
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // A guest slow to refuse shows as open the first time: look again, one at a time.
    found.retain(|&(host, _)| stays_open(host, SCAN_RECHECK));
    let mut ports: Vec<u16> = found.into_iter().map(|(_, guest)| guest).collect();
    ports.sort_unstable();
    ports
}

/// Waits up to `within` until each of `wanted` (a name for the error and a text) is in a line of
/// the console, in whatever order they come (the scripts of the image run their servers in
/// subshells): the first line of each.
fn console_lines(
    run: &mut qemu::Run,
    wanted: &[(&str, &str)],
    within: Duration,
) -> Result<Vec<String>, String> {
    let deadline = Instant::now() + within;
    loop {
        let found: Vec<Option<String>> = wanted
            .iter()
            .map(|(_, text)| run.lines().iter().find(|l| l.contains(text)).cloned())
            .collect();
        if found.iter().all(Option::is_some) {
            return Ok(found.into_iter().flatten().collect());
        }
        if Instant::now() > deadline {
            let missing: Vec<&str> = wanted
                .iter()
                .zip(&found)
                .filter(|(_, f)| f.is_none())
                .map(|(w, _)| w.0)
                .collect();
            return Err(format!(
                "the console did not show {missing:?} within {} s; last lines: {:?}",
                within.as_secs(),
                run.lines().iter().rev().take(12).collect::<Vec<_>>()
            ));
        }
        // Takes in what the console printed since: the wait ends at its short deadline.
        let _ = run.expect_line("more output", |_| false, Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A page over plain HTTP, asked again until the server answers 200 (its worker may not have
/// bound the port yet when its line is on the console).
fn page_of(port: u16, within: Duration) -> Result<Vec<u8>, String> {
    let began = Instant::now();
    loop {
        match http_get(port) {
            Ok((status, body)) if status.contains("200") && !body.is_empty() => return Ok(body),
            other => {
                if began.elapsed() > within {
                    return Err(format!("the page on port {port} did not come: {other:?}"));
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// The command a line of `ssh` runs on the guest, its output and status checked by the caller.
fn guest(
    client: &Client,
    key: &Path,
    command: &str,
    within: Duration,
) -> Result<crate::net_ssh::Ended, String> {
    let mut ssh = client.command("root", Some(key), true);
    ssh.arg(command);
    run_for(ssh, b"", within)
}

/// `guest`, failed when the status is not 0.
fn guest_ok(
    client: &Client,
    key: &Path,
    command: &str,
    within: Duration,
) -> Result<String, String> {
    let said = guest(client, key, command, within)?;
    if said.code != Some(0) {
        return Err(format!(
            "{command:?} on the guest ended with {:?}: {} {}",
            said.code,
            said.text(),
            said.stderr
        ));
    }
    Ok(said.text())
}

// ---- the run -----------------------------------------------------------------------------

/// `cargo xtask net-try [MACHINE]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let machine = match args {
        [] => &qemu::VIRT_2G,
        [name] => match name.as_str() {
            "tcg" => &qemu::VIRT_2G,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask net-try [tcg]".to_owned()),
    };
    probe(machine)
}

pub fn probe(machine: &'static qemu::Machine) -> Result<(), String> {
    println!("net-try: host client {}", host_ssh()?);
    // Step 0 on the lists, before anything is built.
    for image in [AWS_IMAGE, IMAGE] {
        for line in check_image(image)? {
            println!("net-try: {image}: {line}");
        }
    }
    relibc()?;
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    let kernel = build(Variant::Normal)?;
    let dir = crate::target_dir().join("net-try");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (good, good_line) = make_key(&dir, "good")?;
    KEY.set(good_line)
        .map_err(|_| "the key of the run is set twice".to_owned())?;

    // The mirror of the probe: one small base package, signed by the development keys.
    let ca = probe_ca::ensure(false)?;
    keys::dev_keys(&crate::root())?;
    let www = dir.join("www");
    let series = crate::pkg::series();
    std::fs::create_dir_all(www.join(&series)).map_err(|e| e.to_string())?;
    let repository = pkg_probe::make_repository(&dir.join("repository"), &["ncompress"], 2)?;
    pkg_probe::point_at(&www.join(&series).join("aarch64"), &repository)?;
    let roots = pkg_probe::roots_path();
    let roots_text = roots.display().to_string();
    let image = crate::write_boot_image_files(
        IMAGE,
        crate::aws_qemu_programs(),
        BOOT_PROFILE,
        &[("STAFETO_PKG_ROOTS", &roots_text)],
        Vec::new(),
    )?;
    check_built(&image)?;
    for package in ["dropbear", "nginx", "nginx-fast", "openssl"] {
        crate::notices::image_has_package_notices(&image, IMAGE, package)?;
    }
    let mirror = pkg_probe::Mirror::start(
        &www,
        MIRROR_PORT,
        &ca.join("host-a.crt"),
        &ca.join("host-a.key"),
        None,
    )?;

    // The forwards: the four ports of the instance, and every port the scan looks at.
    let scanned = scan_ports();
    let host_ports = free_ports(OPEN.len() + scanned.len())?;
    let mut forwards: Vec<Forward> = Vec::new();
    for (host, guest) in host_ports.iter().zip(OPEN.iter().chain(scanned.iter())) {
        forwards.push(Forward {
            proto: Proto::Tcp,
            host: *host,
            guest: *guest,
        });
    }
    let port_of = |guest: u16| {
        forwards
            .iter()
            .find(|f| f.guest == guest)
            .map(|f| f.host)
            .expect("a forwarded port")
    };
    let (ssh_port, http, https, fast) = (port_of(22), port_of(80), port_of(443), port_of(8080));
    let client = Client {
        port: ssh_port,
        dir: dir.clone(),
    };

    let mut cmd = qemu::on_cpus(2, || qemu::command(machine, &kernel.image, Some(&image)));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net_on(machine, &forwards));
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    let started = Instant::now();
    let talked = (|| {
        // 1. The console after the boot script.
        let lines = console_lines(
            &mut run,
            &[
                ("the end of the start of the services", SERVICES_STARTED),
                ("the lease", "net: lease "),
                (
                    "the key of the probe",
                    "ec2-key: the key of the probe is placed",
                ),
                ("the SSH host key", "ssh: host key SHA256:"),
                ("the page", "landing: page written for "),
                ("the certificate", "web: certificate "),
                ("nginx", "web: nginx on 80 and 443"),
                ("nginx-fast", "fast: nginx-fast on 8080"),
            ],
            BOOT_WITHIN,
        )?;
        for line in &lines[2..] {
            println!("net-try: the console says {:?}", line.trim());
        }
        let fingerprint = format!(
            "SHA256:{}",
            lines[3].split_once("SHA256:").map_or("", |(_, f)| f).trim()
        );

        // 2. The page on the three ports.
        let page = page_of(http, BOOT_WITHIN)?;
        println!("net-try: port 80 answers 200 with {} bytes", page.len());
        check_page(&page, "port 80")?;
        let (tls, version) = https_get(https)?;
        if tls != page {
            return Err(format!(
                "the page on 443 ({} bytes) is not the page on 80 ({} bytes)",
                tls.len(),
                page.len()
            ));
        }
        println!(
            "net-try: port 443 (TLS 1.3, the certificate of the instance, HTTP version {version}) gives the same page"
        );
        let fast_page = page_of(fast, BOOT_WITHIN)?;
        if fast_page != page {
            return Err(format!(
                "port 8080 answered {} bytes, wanted the page of 80 ({} bytes)",
                fast_page.len(),
                page.len()
            ));
        }
        println!("net-try: port 8080 (nginx-fast through the switch) gives the same page");

        // 3. The login, the host key, the files of the instance.
        let said = guest(&client, &good, "echo ssh-ok-$((6*7)); id -u", SSH_WITHIN)?;
        if said.code != Some(0) || !said.text().contains("ssh-ok-42") {
            return Err(format!(
                "the login with the key gave {:?}: {:?} {:?}",
                said.code,
                said.text(),
                said.stderr
            ));
        }
        println!("net-try: the login with the probe key runs a command");
        let known = Command::new("ssh-keygen")
            .arg("-l")
            .arg("-f")
            .arg(dir.join("known_hosts"))
            .output()
            .map_err(|e| format!("ssh-keygen: {e}"))?;
        let known = String::from_utf8_lossy(&known.stdout).into_owned();
        if !known.contains(&fingerprint) {
            return Err(format!(
                "the client saw {known:?}, the console said {fingerprint}"
            ));
        }
        println!("net-try: the host key the client saw is the one the console named");
        let guest_page = guest(&client, &good, "cat /www/index.html", SSH_WITHIN)?;
        if guest_page.stdout != page {
            return Err("/www/index.html on the guest is not the page the ports gave".to_owned());
        }
        let listing = guest_ok(
            &client,
            &good,
            "ls -l /etc/nginx/server.key /etc/nginx/server.crt; ls /etc/dropbear; openssl x509 -in /etc/nginx/server.crt -noout -subject -enddate",
            SSH_WITHIN,
        )?;
        let key_line = listing
            .lines()
            .find(|l| l.ends_with("/etc/nginx/server.key"))
            .ok_or_else(|| format!("no server.key on the guest: {listing:?}"))?;
        if !key_line.starts_with("-rw-------") {
            return Err(format!(
                "the key of nginx is not private to root: {key_line:?}"
            ));
        }
        if !listing.contains("dropbear_ed25519_host_key") || !listing.contains("stafeto") {
            return Err(format!(
                "the host key or the certificate is missing: {listing:?}"
            ));
        }
        println!(
            "net-try: the key and the certificate of nginx and the host key of SSH were made on the instance, the key is -rw-------"
        );

        // 4. The package manager against the mirror of the probe.
        let updated = guest_ok(&client, &good, "pkg update 2>&1", PKG_WITHIN)?;
        if !updated.contains("serial 2") {
            return Err(format!("pkg update said {updated:?}, wanted serial 2"));
        }
        let found = guest_ok(&client, &good, "pkg search compress 2>&1", PKG_WITHIN)?;
        if !found.contains("ncompress") {
            return Err(format!("pkg search compress said {found:?}"));
        }
        println!("net-try: pkg update (serial 2) and pkg search compress find ncompress");

        // 5. The processes.
        let names = guest_ok(
            &client,
            &good,
            "for p in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $p/cmdline 2>/dev/null); echo \"proc $c\"; done",
            SSH_WITHIN,
        )?;
        let running = |name: &str| {
            names.lines().any(|l| {
                l.strip_prefix("proc ")
                    .and_then(|c| c.split_whitespace().next())
                    .is_some_and(|c| c.rsplit('/').next() == Some(name))
            })
        };
        for name in ["dropbear", "nginx", "nginx-fast"] {
            if !running(name) {
                return Err(format!("no process named {name}: {names:?}"));
            }
        }
        for name in FORBIDDEN {
            if running(name) {
                return Err(format!("a process named {name} runs"));
            }
        }
        println!(
            "net-try: dropbear, nginx and nginx-fast run; httpd, telnetd and the other servers of BusyBox do not"
        );

        // 6. The scan.
        let pairs: Vec<(u16, u16)> = forwards
            .iter()
            .filter(|f| !OPEN.contains(&f.guest))
            .map(|f| (f.host, f.guest))
            .collect();
        let began = Instant::now();
        let open = scan(&pairs);
        if !open.is_empty() {
            return Err(format!(
                "these ports of the guest keep a connection: {open:?}"
            ));
        }
        // The same look at the four that answer, so that a scan that sees nothing is no pass.
        for port in OPEN {
            if !stays_open(port_of(port), Duration::from_secs(3)) {
                return Err(format!("port {port} shuts the connection of the scan"));
            }
        }
        println!(
            "net-try: of {} ports scanned ({} s) none listens; 22, 80, 443 and 8080 do",
            pairs.len(),
            began.elapsed().as_secs()
        );
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    drop(mirror);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
    }) {
        return Err("the try-out image faulted".into());
    }
    let elapsed = started.elapsed();
    if elapsed > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s, past {} s",
            elapsed.as_secs_f64(),
            RUN_WITHIN.as_secs()
        ));
    }
    println!(
        "net-try passed in {:.0} s on {}",
        elapsed.as_secs_f64(),
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages;

    const fn text(path: &'static str, bytes: &'static [u8]) -> RootFile {
        RootFile {
            path,
            mode: 0o644,
            uid: 0,
            gid: 0,
            source: Some(Source::Bytes("test", bytes)),
        }
    }

    fn without(files: Vec<RootFile>, path: &str) -> Vec<RootFile> {
        files.into_iter().filter(|f| f.path != path).collect()
    }

    #[test]
    fn both_images_of_the_try_out_pass_the_image_check() {
        for image in [AWS_IMAGE, IMAGE] {
            let report = check_image(image).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(report.len(), 5, "{image}: {report:?}");
        }
    }

    #[test]
    fn the_images_hold_the_servers_and_the_files_of_the_try_out() {
        for image in [AWS_IMAGE, IMAGE] {
            let files = rootfs::files_of(image);
            for path in [
                "/bin/nginx",
                "/bin/nginx-fast",
                "/bin/dropbear",
                "/bin/dropbearkey",
                "/bin/openssl",
                "/bin/pkg",
                "/etc/rc",
                "/etc/rc.d/ec2-key",
                "/etc/rc.d/dropbear",
                "/etc/rc.d/landing",
                "/etc/rc.d/web",
                "/etc/rc.d/fast",
                "/etc/nginx/nginx-try.conf",
                "/etc/nginx/nginx-fast-try.conf",
                "/etc/nginx/tls.conf",
                "/etc/nginx/try-req.cnf",
                "/etc/netd.conf",
                "/www",
                "/etc/dropbear",
            ] {
                assert!(files.iter().any(|f| f.path == path), "{image}: {path}");
            }
            // The page is written at boot, and the certificate and its key are made at boot.
            for path in [
                "/www/index.html",
                "/etc/nginx/server.key",
                "/etc/nginx/server.crt",
            ] {
                assert!(files.iter().all(|f| f.path != path), "{image}: {path}");
            }
            let conf = bytes_of(&files, "/etc/netd.conf").unwrap();
            assert_eq!(conf, b"switch 8\nflows 16384\n");
            let packages = packages::of_image(image).unwrap();
            for name in [
                "nginx",
                "nginx-fast",
                "dropbear",
                "openssl",
                "curl",
                "ca-bundle",
            ] {
                assert!(packages.iter().any(|p| p.name == name), "{image}: {name}");
            }
        }
    }

    #[test]
    fn a_host_key_in_the_image_fails_the_check() {
        let mut files = rootfs::files_of(AWS_IMAGE);
        files.push(text("/etc/dropbear/dropbear_ed25519_host_key", b"x"));
        let error = check_files(&files).unwrap_err();
        assert!(error.contains("/etc/dropbear"), "{error}");
    }

    #[test]
    fn an_account_that_is_not_locked_fails_the_check() {
        for shadow in [
            &b"root::20000:0:99999:7:::\n"[..],
            b"root:*:20000:0:99999:7:::\n",
            b"root:$6$salt$hash:20000:0:99999:7:::\n",
            b"root:!:20000:0:99999:7:::\nuser::20000:0:99999:7:::\n",
        ] {
            let mut files = without(rootfs::files_of(AWS_IMAGE), "/etc/shadow");
            files.push(text("/etc/shadow", shadow));
            let error = check_files(&files).unwrap_err();
            assert!(error.contains("not locked"), "{error}");
        }
    }

    #[test]
    fn a_private_key_anywhere_fails_the_check() {
        let mut files = rootfs::files_of(AWS_IMAGE);
        files.push(text("/root/.ssh/id_ed25519", b"x"));
        assert!(check_files(&files).unwrap_err().contains("private key"));
        let mut files = rootfs::files_of(AWS_IMAGE);
        files.push(text("/etc/nginx/server.key", b"x"));
        assert!(check_files(&files).unwrap_err().contains("private key"));
        let mut files = rootfs::files_of(AWS_IMAGE);
        files.push(text(
            "/etc/notes",
            b"a\n-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----\n",
        ));
        assert!(
            check_files(&files)
                .unwrap_err()
                .contains("holds a private key")
        );
        let mut files = rootfs::files_of(AWS_IMAGE);
        files.push(text("/etc/notes", b"openssh-key-v1\0\0\0"));
        assert!(
            check_files(&files)
                .unwrap_err()
                .contains("holds a private key")
        );
    }

    #[test]
    fn a_certificate_is_no_private_key() {
        assert!(!holds_private_key(
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        ));
        assert!(!holds_private_key(b"-----BEGIN PUBLIC KEY-----\nMFkw\n"));
        assert!(holds_private_key(b"-----BEGIN PRIVATE KEY-----\n"));
        assert!(holds_private_key(b"-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(holds_private_key(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        // A format string of a library is no key.
        assert!(!holds_private_key(b"-----BEGIN %s-----\n"));
    }

    #[test]
    fn a_script_that_starts_httpd_or_telnetd_fails_the_check() {
        for body in [
            &b"httpd -p 8081 -h /www\n"[..],
            b"    telnetd -l /bin/ash\n",
            b"( /bin/busybox httpd -f ) &\n",
        ] {
            let mut files = without(rootfs::files_of(AWS_IMAGE), "/etc/rc.d/fast");
            files.push(text("/etc/rc.d/fast", body));
            let error = check_files(&files).unwrap_err();
            assert!(error.contains("/etc/rc.d/fast starts"), "{error}");
        }
        // The words in a comment start nothing.
        let mut files = without(rootfs::files_of(AWS_IMAGE), "/etc/rc.d/fast");
        files.push(text("/etc/rc.d/fast", b"# no httpd and no telnetd here\n"));
        assert!(check_files(&files).is_ok());
    }

    #[test]
    fn a_script_outside_the_list_or_an_inetd_fails_the_check() {
        let mut files = without(rootfs::files_of(AWS_IMAGE), "/etc/rc");
        files.push(text(
            "/etc/rc",
            b"for name in ec2-key backdoor; do\n:\ndone\n",
        ));
        assert!(check_files(&files).unwrap_err().contains("backdoor"));
        let mut files = rootfs::files_of(AWS_IMAGE);
        files.push(text(
            "/etc/inetd.conf",
            b"23 stream tcp nowait root telnetd\n",
        ));
        assert!(check_files(&files).unwrap_err().contains("/etc/inetd.conf"));
    }

    #[test]
    fn a_port_besides_the_four_fails_the_check() {
        let mut files = rootfs::files_of(AWS_IMAGE);
        files.push(text(
            "/etc/nginx/extra.conf",
            b"server {\n    listen 8081;\n}\n",
        ));
        assert!(check_files(&files).unwrap_err().contains("port 8081"));
        let mut files = without(rootfs::files_of(AWS_IMAGE), "/etc/rc.d/dropbear");
        files.push(text("/etc/rc.d/dropbear", b"args=\"-F -p 2222\"\n"));
        assert!(check_files(&files).unwrap_err().contains("-p"));
    }

    #[test]
    fn the_listen_lines_give_their_ports() {
        let ports = listen_ports(
            "    listen 80 reuseport;\n    listen 443 ssl reuseport;\n    listen 8080;\n    listen 127.0.0.1:9000;\n# listen 1;\n    server_name listen;\n",
        );
        assert_eq!(ports, [80, 443, 8080, 9000]);
    }

    #[test]
    fn the_scan_leaves_out_the_four_ports_and_holds_the_low_ones() {
        let ports = scan_ports();
        for open in OPEN {
            assert!(!ports.contains(&open));
        }
        for port in [1, 21, 23, 25, 53, 81, 111, 1024, 8000, 8081, 8199] {
            assert!(ports.contains(&port), "{port}");
        }
        let mut sorted = ports.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ports.len());
    }

    #[test]
    fn the_page_template_says_what_the_plan_asks_for() {
        let page = String::from_utf8(rootfs::landing_script().to_vec()).unwrap();
        // The page of the template with the holes the script fills in.
        let page = page
            .replace("@ADDRESS@", "203.0.113.7")
            .replace("@TYPE@", "t4g.small");
        let start = page.find("<!DOCTYPE html>").unwrap();
        let end = page.find("</html>").unwrap();
        check_page(&page.as_bytes()[start..end], "the template").unwrap();
        assert!(!page.contains("@VERSION@"));
        assert!(page.contains(env!("CARGO_PKG_VERSION")));
        // A page with a part cut out fails.
        let cut = page[start..end].replace("pkg search nginx", "pkg find nginx");
        assert!(check_page(cut.as_bytes(), "the cut").is_err());
    }

    #[test]
    fn the_boot_script_lists_the_scripts_in_the_order_of_their_needs() {
        let rc = include_str!("../../tools/rc/rc");
        let line = rc.lines().find(|l| l.starts_with("for name in ")).unwrap();
        assert_eq!(line, "for name in ec2-key dropbear landing web fast; do");
        let names: Vec<&str> = line["for name in ".len()..line.len() - 4]
            .split_whitespace()
            .collect();
        assert_eq!(names, SCRIPTS);
    }

    #[test]
    fn the_scripts_of_the_image_name_the_lines_the_check_script_expects() {
        let landing = include_str!("../../tools/rc/landing");
        assert!(landing.contains("landing: page written for"));
        let web = include_str!("../../tools/rc/web");
        assert!(web.contains("web: certificate"));
        assert!(web.contains("web: nginx on 80 and 443"));
        let fast = include_str!("../../tools/rc/fast");
        assert!(fast.contains("fast: nginx-fast on"));
        let dropbear = include_str!("../../tools/rc/dropbear");
        assert!(dropbear.contains("ssh: host key"));
        let check = include_str!("../../tools/aws/try-check.sh");
        for line in [
            "ssh: host key SHA256:",
            "landing: page written for",
            "web: certificate",
            "web: nginx on 80 and 443",
            "fast: nginx-fast on 8080",
        ] {
            assert!(check.contains(line), "try-check.sh lacks {line}");
        }
    }

    #[test]
    fn the_nginx_settings_of_the_image_have_two_workers_and_the_ports() {
        let conf = rootfs::try_nginx_conf();
        assert!(conf.contains("worker_processes 2;"));
        assert!(conf.contains("include /etc/nginx/tls.conf;"));
        assert!(listen_ports(conf).contains(&80));
        let fast = rootfs::try_fast_conf();
        assert!(fast.contains("worker_processes 2;"));
        assert_eq!(listen_ports(fast), [8080]);
        assert_eq!(listen_ports(crate::nginx_probe::TLS_CONF), [443]);
    }
}
