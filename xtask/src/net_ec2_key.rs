// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The boot script that fetches the key of an EC2 instance
//! (`cargo xtask net-ec2-key`): the shell image with the network service and
//! the launcher that runs `/etc/rc` (init's feature `net-rc`, as on EC2), on
//! QEMU's user network, with a fake of the instance metadata service on the
//! host.
//!
//! The fake answers where the real service lives, 169.254.169.254 port 80,
//! which is off the link of the guest, as on EC2: the guest has 169.254.169.5/28
//! and the gateway 169.254.169.2 (`NETD_CONF`), QEMU's network is
//! 169.254.169.0/24, and `guestfwd` hands each connection to 169.254.169.254:80
//! to `cargo xtask net-ec2-key-imds DIR`, which answers it on its stdin and
//! stdout. The fake needs the token header the way IMDSv2 does (401 without it)
//! and takes its mode from the file `DIR/mode` at each connection: `key` (the
//! instance has a key pair), `nokey` (it has none, 404) or `refuse` (the token
//! request gets 403). It appends a line to `DIR/log` for each request.
//!
//! The steps, in order:
//!
//! 1. The boot: the launcher runs `/etc/rc`, which runs `ec2-key`; the script
//!    prints the line with the key's type and comment, and the fake saw the
//!    token request and one request for the key with the token.
//! 2. `/home/user/.ssh` is `drwx------`, `authorized_keys` is `-rw-------` and holds the
//!    key, one line; the token and the key's text did not reach the console.
//! 3. An IMDSv1 request (no token header) gets 401 and no key.
//! 4. A stale file is replaced when the script runs again.
//! 5. No key: one line says SSH stays off, nothing is written.
//! 6. A refused token: one line, nothing is written, and the script sent no
//!    request without a token (the fake saw the one token request and no other).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::net_wget::{capture, step};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, ImageProgram, SERVICES_STARTED, Variant, build,
    build_boot_image, busybox_build, nano_build, net, qemu, relibc, symbolize,
};

/// The image of the probe.
pub const IMAGE: &str = "boot-net-rc.img";

/// `/etc/netd.conf` of the image: an address on a /28 of QEMU's network with the
/// gateway inside it, so that 169.254.169.254 is off the link and goes through the
/// gateway, as the metadata service does on EC2.
pub const NETD_CONF: &[u8] =
    b"address 169.254.169.5/28\ngateway 169.254.169.2\ndns 169.254.169.3\n";

/// The address and port the guest asks for the metadata.
const IMDS: &str = "169.254.169.254";

/// The key the fake gives: a made-up key in the form of a real one.
const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYAB fake-key@xtask";
/// The token the fake gives.
const TOKEN: &str = "AQAEAFAKETOKENxtask0123456789abcdefghijklmnopqrstuvwxyz==";

/// The whole run may take this long.
const RUN_WITHIN: Duration = Duration::from_secs(180);
/// The boot script and its first request, from the start of the guest.
const SCRIPT_WITHIN: Duration = Duration::from_secs(90);
/// One run of the script from the shell.
const RUN_SCRIPT: Duration = Duration::from_secs(30);

/// The programs of the image: those of the shell with the network, whose init
/// runs the launcher with `/etc/rc`.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = net::programs().to_vec();
        programs[0].3 = &["table-net", "net-rc"];
        programs
    })
}

// ---- the fake of the metadata service ------------------------------------------

/// What the fake does with the token request and the key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// The instance has a key pair.
    Key,
    /// It has none: the key path is 404.
    NoKey,
    /// The token request is refused (403).
    Refuse,
}

impl Mode {
    fn parse(text: &str) -> Option<Mode> {
        match text.trim() {
            "key" => Some(Mode::Key),
            "nokey" => Some(Mode::NoKey),
            "refuse" => Some(Mode::Refuse),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mode::Key => "key",
            Mode::NoKey => "nokey",
            Mode::Refuse => "refuse",
        }
    }
}

/// One request as the fake reads it: the method, the path and the header
/// lines (names in lower case).
#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn parse(head: &[u8]) -> Option<Request> {
        let text = std::str::from_utf8(head).ok()?;
        let mut lines = text.split("\r\n");
        let mut first = lines.next()?.split(' ');
        let method = first.next()?.to_owned();
        let path = first.next()?.to_owned();
        if !first.next()?.starts_with("HTTP/1.") {
            return None;
        }
        let headers = lines
            .take_while(|l| !l.is_empty())
            .filter_map(|l| {
                let (name, value) = l.split_once(':')?;
                Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect();
        Some(Request {
            method,
            path,
            headers,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The answer of the fake to `request` in `mode`, and the line of the log.
fn respond(request: &Option<Request>, mode: Mode) -> (Vec<u8>, String) {
    let reply = |code: u16, reason: &str, body: &str, extra: &str| {
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    };
    let Some(request) = request else {
        return (
            reply(400, "Bad Request", "", ""),
            "unparsed request -> 400".to_owned(),
        );
    };
    let (method, path) = (request.method.as_str(), request.path.as_str());
    if method == "PUT" && path == "/latest/api/token" {
        let ttl = request.header("x-aws-ec2-metadata-token-ttl-seconds");
        let valid = ttl
            .and_then(|t| t.parse::<u32>().ok())
            .is_some_and(|t| (1..=21600).contains(&t));
        let (code, answer) = if mode == Mode::Refuse {
            (403, reply(403, "Forbidden", "", ""))
        } else if valid {
            (
                200,
                reply(
                    200,
                    "OK",
                    TOKEN,
                    "X-aws-ec2-metadata-token-ttl-seconds: 300\r\n",
                ),
            )
        } else {
            (400, reply(400, "Bad Request", "", ""))
        };
        return (
            answer,
            format!("PUT {path} ttl={} -> {code}", ttl.unwrap_or("none")),
        );
    }
    if method != "GET" {
        return (
            reply(405, "Method Not Allowed", "", ""),
            format!("{method} {path} -> 405"),
        );
    }
    let token = match request.header("x-aws-ec2-metadata-token") {
        None => "none",
        Some(t) if t == TOKEN => "ok",
        Some(_) => "bad",
    };
    let (code, answer) = if token != "ok" {
        (401, reply(401, "Unauthorized", "", ""))
    } else if path == "/latest/meta-data/public-keys/0/openssh-key" && mode == Mode::Key {
        (200, reply(200, "OK", &format!("{KEY}\n"), ""))
    } else {
        (404, reply(404, "Not Found", "", ""))
    };
    (answer, format!("GET {path} token={token} -> {code}"))
}

/// Reads one request from `stream`, answers it and gives the line of the log.
fn serve(stream: &mut (impl Read + Write), mode: Mode) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 512];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
    }
    let (answer, line) = respond(&Request::parse(&head), mode);
    stream.write_all(&answer)?;
    stream.flush()?;
    Ok(line)
}

/// A stdin and stdout as one stream: the connection `guestfwd` hands over.
struct Stdio2;

impl Read for Stdio2 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::stdin().read(buf)
    }
}

impl Write for Stdio2 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// `cargo xtask net-ec2-key-imds DIR`: one connection of the guest on stdin and
/// stdout, in the mode `DIR/mode` names, with a line in `DIR/log`.
pub fn imds_command(args: &[String]) -> Result<(), String> {
    let [dir] = args else {
        return Err("usage: cargo xtask net-ec2-key-imds DIR".to_owned());
    };
    let dir = Path::new(dir);
    let mode = std::fs::read_to_string(dir.join("mode"))
        .ok()
        .and_then(|t| Mode::parse(&t))
        .unwrap_or(Mode::Key);
    let line = serve(&mut Stdio2, mode).map_err(|e| format!("net-ec2-key-imds: {e}"))?;
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("log"))
        .map_err(|e| format!("net-ec2-key-imds: log: {e}"))?;
    writeln!(log, "{line}").map_err(|e| format!("net-ec2-key-imds: log: {e}"))
}

// ---- the probe -----------------------------------------------------------------

/// The directory of the fake: `mode` and `log`.
struct Fake {
    dir: PathBuf,
}

impl Fake {
    fn new() -> Result<Fake, String> {
        let dir = crate::root().join("target").join("net-ec2-key");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let fake = Fake { dir };
        fake.mode(Mode::Key)?;
        std::fs::write(fake.dir.join("log"), "").map_err(|e| format!("log: {e}"))?;
        Ok(fake)
    }

    fn mode(&self, mode: Mode) -> Result<(), String> {
        std::fs::write(self.dir.join("mode"), mode.name()).map_err(|e| format!("mode: {e}"))
    }

    /// The lines of the log so far.
    fn log(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The `-netdev` text of the user network with the fake on `IMDS`:80.
    fn netdev(&self) -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|e| format!("the path of xtask: {e}"))?;
        let command = format!("{} net-ec2-key-imds {}", exe.display(), self.dir.display());
        // QEMU reads a comma in an option as the next option.
        if command.contains(',') {
            return Err(format!("a comma in the command of the fake: {command}"));
        }
        Ok(format!(
            "user,id=n0,net=169.254.169.0/24,guestfwd=tcp:{IMDS}:80-cmd:{command}"
        ))
    }
}

/// The lines of the log after the first `from`.
fn since(log: &[String], from: usize) -> Vec<String> {
    log.get(from..).unwrap_or_default().to_vec()
}

/// `cargo xtask net-ec2-key [MACHINE]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let machine = match args {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask net-ec2-key [tcg|hvf]".to_owned()),
    };
    probe(machine)
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
    let fake = Fake::new()?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut net_args = qemu::net(&[]);
    if net_args.get(1).is_none_or(|n| !n.starts_with("user,id=n0")) {
        return Err(format!(
            "the user network of the probe changed: {net_args:?}"
        ));
    }
    net_args[1] = fake.netdev()?;
    cmd.args(net_args);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let result = steps(&mut run, &fake);
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    if result.is_err() {
        let from = output.lines.len().saturating_sub(40);
        println!("net-ec2-key: the last lines of the console:");
        for line in &output.lines[from..] {
            println!("  {line}");
        }
        println!("net-ec2-key: the log of the fake: {:?}", fake.log());
    }
    result?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
            || line.contains("ash-launch: cannot start")
    }) {
        return Err("the image faulted".into());
    }
    if output.lines.iter().any(|l| l.contains(TOKEN)) {
        return Err("the token reached the console".into());
    }
    let elapsed = started.elapsed();
    if elapsed > RUN_WITHIN {
        return Err(format!(
            "the run took {:.0} s, past the {} s of the group",
            elapsed.as_secs_f64(),
            RUN_WITHIN.as_secs()
        ));
    }
    println!(
        "net-ec2-key passed in {:.0} s on {}",
        elapsed.as_secs_f64(),
        machine.name
    );
    Ok(())
}

/// The lines `ls -ld` shows for the two paths, with the mode and owner of each.
fn modes_of(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let mode = words.next()?.to_owned();
            let owner = words.nth(1)?.to_owned();
            let path = l.split_whitespace().last()?.to_owned();
            path.starts_with('/')
                .then_some((format!("{mode} {owner}"), path))
        })
        .collect()
}

fn steps(run: &mut qemu::Run, fake: &Fake) -> Result<(), String> {
    let at = |what: &str| println!("net-ec2-key: {what} ok");
    run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;

    // 1. The boot: the line of the script, which comes through the route to the
    // metadata service that netd keeps off the link.
    run.expect_seen("ec2-key: ssh-ed25519 fake-key@xtask", SCRIPT_WITHIN)?;
    let log = fake.log();
    if log.len() != 2
        || !log[0].starts_with("PUT /latest/api/token ttl=300 -> 200")
        || log[1] != "GET /latest/meta-data/public-keys/0/openssh-key token=ok -> 200"
    {
        return Err(format!("the requests of the boot script: {log:?}"));
    }
    at("the boot script fetched the key, one token request and one request with it");
    run.expect("# ", DIALOG_STEP)?;
    run.send("S=ok")?;
    run.expect("# ", DIALOG_STEP)?;

    // 2. The files.
    let file = capture(
        run,
        "cat /home/user/.ssh/authorized_keys",
        "k1",
        DIALOG_STEP,
    )?;
    if file != [KEY] {
        return Err(format!("authorized_keys is {file:?}"));
    }
    let listing = capture(
        run,
        "ls -ld /home/user/.ssh /home/user/.ssh/authorized_keys",
        "k2",
        DIALOG_STEP,
    )?;
    let modes = modes_of(&listing);
    if modes
        != [
            ("drwx------ user".to_owned(), "/home/user/.ssh".to_owned()),
            (
                "-rw------- user".to_owned(),
                "/home/user/.ssh/authorized_keys".to_owned(),
            ),
        ]
    {
        return Err(format!("the modes are {listing:?}"));
    }
    at("/home/user/.ssh is 700 and authorized_keys is 600 with the key, one line");

    // 3. IMDSv1: no token header, no key.
    let before = fake.log().len();
    step(
        run,
        "v1",
        &format!(
            "! wget -q -T 10 -O /tmp/v1 http://{IMDS}/latest/meta-data/public-keys/0/openssh-key && [ ! -s /tmp/v1 ]"
        ),
        RUN_SCRIPT,
    )?;
    let seen = since(&fake.log(), before);
    if seen != ["GET /latest/meta-data/public-keys/0/openssh-key token=none -> 401"] {
        return Err(format!("the request without a token: {seen:?}"));
    }
    at("a request without a token gets 401 and no key");

    // 4. A stale file is replaced, the modes are the same.
    run.send(
        "echo stale > /home/user/.ssh/authorized_keys; chmod 644 /home/user/.ssh/authorized_keys",
    )?;
    run.expect("# ", DIALOG_STEP)?;
    let again = capture(run, "ash /etc/rc.d/ec2-key", "k3", RUN_SCRIPT)?;
    if again != ["ec2-key: ssh-ed25519 fake-key@xtask"] {
        return Err(format!("the second run said {again:?}"));
    }
    let file = capture(
        run,
        "cat /home/user/.ssh/authorized_keys",
        "k4",
        DIALOG_STEP,
    )?;
    let listing = capture(
        run,
        "ls -l /home/user/.ssh/authorized_keys",
        "k5",
        DIALOG_STEP,
    )?;
    if file != [KEY]
        || !listing
            .first()
            .is_some_and(|l| l.starts_with("-rw------- "))
    {
        return Err(format!("after the second run: {file:?} {listing:?}"));
    }
    at("a second run replaces a stale file");

    // 5. No key.
    fake.mode(Mode::NoKey)?;
    run.send("rm -r /home/user/.ssh")?;
    run.expect("# ", DIALOG_STEP)?;
    let none = capture(run, "ash /etc/rc.d/ec2-key", "k6", RUN_SCRIPT)?;
    if none != ["ec2-key: the instance has no key pair, SSH stays off"] {
        return Err(format!("the run without a key said {none:?}"));
    }
    step(
        run,
        "nokey",
        "[ ! -e /home/user/.ssh ] && [ ! -e /home/user/.ssh/authorized_keys ]",
        DIALOG_STEP,
    )?;
    at("no key pair: one line, nothing written");

    // 6. A refused token: the script asks once, and never without a token.
    fake.mode(Mode::Refuse)?;
    let before = fake.log().len();
    let refused = capture(run, "ash /etc/rc.d/ec2-key", "k7", RUN_SCRIPT)?;
    if refused != ["ec2-key: the metadata service gave no token (HTTP 403), SSH stays off"] {
        return Err(format!("the run with a refused token said {refused:?}"));
    }
    step(run, "refused", "[ ! -e /home/user/.ssh ]", DIALOG_STEP)?;
    let seen = since(&fake.log(), before);
    if seen != ["PUT /latest/api/token ttl=300 -> 403"] {
        return Err(format!("the requests after a refused token: {seen:?}"));
    }
    at("a refused token: one line, nothing written, no request without a token");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::process::Command;

    fn ask(head: &str, mode: Mode) -> (String, String) {
        let (answer, line) = respond(&Request::parse(head.as_bytes()), mode);
        (String::from_utf8(answer).unwrap(), line)
    }

    const PUT: &str = "PUT /latest/api/token HTTP/1.1\r\nHost: x\r\nX-aws-ec2-metadata-token-ttl-seconds: 300\r\n\r\n";

    #[test]
    fn the_token_request_needs_its_header_and_gives_the_token() {
        let (answer, line) = ask(PUT, Mode::Key);
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(answer.ends_with(TOKEN));
        assert_eq!(line, "PUT /latest/api/token ttl=300 -> 200");
        let (answer, _) = ask(
            "PUT /latest/api/token HTTP/1.1\r\nHost: x\r\n\r\n",
            Mode::Key,
        );
        assert!(answer.starts_with("HTTP/1.1 400 "));
        let (answer, _) = ask(
            "PUT /latest/api/token HTTP/1.1\r\nX-aws-ec2-metadata-token-ttl-seconds: 99999\r\n\r\n",
            Mode::Key,
        );
        assert!(answer.starts_with("HTTP/1.1 400 "));
        let (answer, line) = ask(PUT, Mode::Refuse);
        assert!(answer.starts_with("HTTP/1.1 403 "));
        assert_eq!(line, "PUT /latest/api/token ttl=300 -> 403");
    }

    #[test]
    fn a_get_without_the_token_is_401_and_with_it_gives_the_key() {
        let path = "/latest/meta-data/public-keys/0/openssh-key";
        let (answer, line) = ask(
            &format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n"),
            Mode::Key,
        );
        assert!(answer.starts_with("HTTP/1.1 401 "));
        assert!(!answer.contains("ssh-ed25519"));
        assert_eq!(line, format!("GET {path} token=none -> 401"));
        let with = |token: &str, mode| {
            ask(
                &format!("GET {path} HTTP/1.1\r\nX-aws-ec2-metadata-token: {token}\r\n\r\n"),
                mode,
            )
        };
        let (answer, line) = with(TOKEN, Mode::Key);
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(answer.ends_with(&format!("{KEY}\n")));
        assert_eq!(line, format!("GET {path} token=ok -> 200"));
        assert!(with("wrong", Mode::Key).0.starts_with("HTTP/1.1 401 "));
        assert_eq!(
            with("wrong", Mode::Key).1,
            format!("GET {path} token=bad -> 401")
        );
        assert!(with(TOKEN, Mode::NoKey).0.starts_with("HTTP/1.1 404 "));
    }

    #[test]
    fn other_requests_are_refused() {
        assert!(
            ask("POST / HTTP/1.1\r\n\r\n", Mode::Key)
                .0
                .starts_with("HTTP/1.1 405 ")
        );
        assert!(
            respond(&Request::parse(b"junk"), Mode::Key)
                .1
                .ends_with("-> 400")
        );
    }

    #[test]
    fn the_modes_are_read_from_their_names() {
        for mode in [Mode::Key, Mode::NoKey, Mode::Refuse] {
            assert_eq!(Mode::parse(mode.name()), Some(mode));
        }
        assert_eq!(Mode::parse("key\n"), Some(Mode::Key));
        assert_eq!(Mode::parse("other"), None);
    }

    #[test]
    fn the_listing_lines_give_mode_owner_and_path() {
        let lines = [
            "drwx------    2 user     user             0 Nov 16 10:00 /home/user/.ssh".to_owned(),
            "-rw-------    1 user     user           100 Nov 16 10:00 /home/user/.ssh/authorized_keys"
                .to_owned(),
        ];
        assert_eq!(
            modes_of(&lines),
            [
                ("drwx------ user".to_owned(), "/home/user/.ssh".to_owned()),
                (
                    "-rw------- user".to_owned(),
                    "/home/user/.ssh/authorized_keys".to_owned()
                ),
            ]
        );
    }

    /// A passwd file with the account `user` whose home is a directory of `work` (made here), for
    /// the script on a host: the home, and the environment that makes the script use it.
    fn account(work: &Path, name: &str, uid: u32) -> (PathBuf, Vec<(&'static str, String)>) {
        let home = work.join(format!("home-{name}"));
        std::fs::create_dir_all(&home).unwrap();
        let passwd = work.join(format!("passwd-{name}"));
        std::fs::write(
            &passwd,
            format!("user:x:{uid}:100:user:{}:/bin/ash\n", home.display()),
        )
        .unwrap();
        (
            home,
            vec![
                ("PASSWD_FILE", passwd.display().to_string()),
                ("SSH_CHOWN", "true".to_owned()),
            ],
        )
    }

    /// The script against the fake on the host, with the host's `sh` and `nc`: the
    /// cases of the probe that need no guest.
    #[test]
    fn the_script_writes_the_key_and_the_modes_on_a_host() {
        let have = |tool: &str| {
            Command::new("sh")
                .args(["-c", &format!("command -v {tool}")])
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !have("nc") || !have("tr") {
            return;
        }
        let script = crate::root().join("tools/rc/ec2-key");
        let work = crate::target_dir().join("net-ec2-key-host");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        for (mode, said, written) in [
            (Mode::Key, "ec2-key: ssh-ed25519 fake-key@xtask", true),
            (
                Mode::NoKey,
                "ec2-key: the instance has no key pair, SSH stays off",
                false,
            ),
            (
                Mode::Refuse,
                "ec2-key: the metadata service gave no token (HTTP 403), SSH stays off",
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let mut lines = Vec::new();
                for stream in listener.incoming() {
                    let mut stream: TcpStream = stream.unwrap();
                    let line = serve(&mut stream, mode).unwrap();
                    let done =
                        line.starts_with("PUT") && mode == Mode::Refuse || line.starts_with("GET");
                    lines.push(line);
                    if done {
                        break;
                    }
                }
                lines
            });
            let (home, env) = account(&work, mode.name(), 1000);
            let ssh = home.join(".ssh");
            let out = Command::new("sh")
                .arg(&script)
                .env("IMDS_HOST", "127.0.0.1")
                .env("IMDS_PORT", port.to_string())
                .envs(env)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert_eq!(text.trim_end(), said, "{mode:?}: {out:?}");
            let lines = server.join().unwrap();
            assert!(!text.contains(TOKEN));
            assert_eq!(ssh.join("authorized_keys").exists(), written, "{mode:?}");
            if written {
                assert_eq!(
                    std::fs::read_to_string(ssh.join("authorized_keys")).unwrap(),
                    format!("{KEY}\n")
                );
                use std::os::unix::fs::PermissionsExt;
                let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode_of(&ssh), 0o700);
                assert_eq!(mode_of(&ssh.join("authorized_keys")), 0o600);
                assert_eq!(lines.len(), 2);
            } else if mode == Mode::Refuse {
                assert_eq!(lines.len(), 1, "no request without a token: {lines:?}");
            }
        }
    }

    /// What the script does with replies a hostile service could send: it writes nothing,
    /// says one line, and asks at most for the token and the key.
    #[test]
    fn the_script_refuses_hostile_replies_on_a_host() {
        let have = |tool: &str| {
            Command::new("sh")
                .args(["-c", &format!("command -v {tool}")])
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !have("nc") || !have("tr") || !have("head") {
            return;
        }
        let script = crate::root().join("tools/rc/ec2-key");
        let work = crate::target_dir().join("net-ec2-key-hostile");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let ok = |body: &[u8]| -> Vec<u8> {
            let mut r =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            r.extend_from_slice(body);
            r
        };
        let token = ok(TOKEN.as_bytes());
        let not_key = "the key is not one line of an OpenSSH public key, SSH stays off";
        let not_word = "the metadata service gave a token that is not one word, SSH stays off";
        let mut huge = b"ssh-ed25519 ".to_vec();
        huge.resize(1 << 20, b'a');
        let cases: Vec<(&str, Vec<Vec<u8>>, &str, usize)> = vec![
            (
                "control",
                vec![token.clone(), ok(b"ssh-ed25519 AAAA c\x1b[31mred\x07")],
                not_key,
                2,
            ),
            ("newline-token", vec![ok(b"tok\nX-Evil: 1")], not_word, 1),
            (
                "status",
                vec![b"HTTP/1.1 2*0 OK\r\n\r\nx".to_vec()],
                "the metadata service gave no token (HTTP 000), SSH stays off",
                1,
            ),
            ("huge", vec![token.clone(), ok(&huge)], not_key, 2),
            (
                "two-keys",
                vec![token.clone(), ok(format!("{KEY}\n{KEY}").as_bytes())],
                not_key,
                2,
            ),
            (
                "symlink",
                vec![token.clone(), ok(KEY.as_bytes())],
                "is a symbolic link, SSH stays off",
                2,
            ),
        ];
        for (name, replies, said, asked) in cases {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let mut heads = Vec::new();
                for (n, stream) in listener.incoming().enumerate() {
                    let mut stream: TcpStream = stream.unwrap();
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 512];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(k) => head.extend_from_slice(&chunk[..k]),
                        }
                    }
                    if head.is_empty() {
                        break;
                    }
                    heads.push(String::from_utf8_lossy(&head).into_owned());
                    if let Some(reply) = replies.get(n) {
                        let _ = stream.write_all(reply);
                    }
                }
                heads
            });
            let (home, env) = account(&work, name, 1000);
            let ssh = home.join(".ssh");
            if name == "symlink" {
                let target = work.join("target");
                std::fs::create_dir_all(&target).unwrap();
                std::os::unix::fs::symlink(&target, &ssh).unwrap();
            }
            let out = Command::new("sh")
                .arg(&script)
                .env("IMDS_HOST", "127.0.0.1")
                .env("IMDS_PORT", port.to_string())
                .envs(env)
                .output()
                .unwrap();
            // Unblocks the server's accept.
            drop(TcpStream::connect(("127.0.0.1", port)));
            let heads = server.join().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert_eq!(text.lines().count(), 1, "{name}: {out:?}");
            assert!(text.contains(said), "{name}: {out:?}");
            assert!(!text.contains('\x1b') && !text.contains("X-Evil"), "{name}");
            assert_eq!(heads.len(), asked, "{name}: {heads:?}");
            assert!(heads.iter().all(|h| !h.contains("X-Evil")), "{name}");
            let found: Vec<_> = std::fs::read_dir(&ssh)
                .map(|d| d.map(|e| e.unwrap().file_name()).collect())
                .unwrap_or_default();
            assert!(found.is_empty(), "{name}: wrote {found:?}");
        }
    }

    /// An account that is root's, or whose home is not an absolute path, never gets the key:
    /// the script ends before it asks the metadata service for anything.
    #[test]
    fn the_script_refuses_an_account_that_is_root_or_has_no_absolute_home() {
        let script = crate::root().join("tools/rc/ec2-key");
        let work = crate::target_dir().join("net-ec2-key-accounts");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        for (name, line, said) in [
            (
                "root",
                "user:x:0:0:user:/root:/bin/ash\n",
                "no account user with an identifier of 1000 or more",
            ),
            (
                "zeros",
                "user:x:0000:0:user:/root:/bin/ash\n",
                "no account user with an identifier of 1000 or more",
            ),
            (
                "long",
                "user:x:99999999999999999999:0:user:/root:/bin/ash\n",
                "no account user with an identifier of 1000 or more",
            ),
            (
                "low",
                "user:x:999:100:user:/home/user:/bin/ash\n",
                "no account user with an identifier of 1000 or more",
            ),
            (
                "relative",
                "user:x:1000:100:user:home/user:/bin/ash\n",
                "the home of user is not an absolute path",
            ),
            (
                "dots",
                "user:x:1000:100:user:/home/../root:/bin/ash\n",
                "the home of user holds a dot component",
            ),
            (
                "missing",
                "nobody:x:65534:65534:nobody:/:/bin/ash\n",
                "no account user",
            ),
        ] {
            let passwd = work.join(format!("passwd-{name}"));
            std::fs::write(&passwd, line).unwrap();
            let out = Command::new("sh")
                .arg(&script)
                .env("IMDS_HOST", "127.0.0.1")
                .env("IMDS_PORT", "1")
                .env("PASSWD_FILE", &passwd)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(text.contains(said), "{name}: {out:?}");
            assert!(!out.status.success(), "{name}");
        }
    }
}
