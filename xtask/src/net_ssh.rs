// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probe of the SSH server (`cargo xtask net-ssh`): the image of the
//! shell with the network service whose launcher also starts Dropbear
//! (`/bin/dropbear -F -R -s -j -k`, tests/ash-launcher with the feature
//! `dropbear`) on QEMU's user network, a port of the host forwarded to the
//! port 22 of the guest. xtask drives `ash` over the serial port, as
//! `net-curl` does, and is the client with the host's own `ssh`:
//!
//! 1. The image: `/etc/dropbear` holds no file (the host keys are made on
//!    the first start), `/etc/shadow` locks every account (the check of
//!    rootfs.rs), and the package carries its licence notice.
//! 2. The command line of the running server, read from
//!    `/proc/<pid>/cmdline`, is exactly `dropbear -F -R -s -j -k`: the
//!    password login is off, no port is forwarded, the host keys are made
//!    when first needed (the build has no syslog, so the log goes to the
//!    standard error).
//! 3. The key the probe made is in `/root/.ssh/authorized_keys` (the key a
//!    later part takes from the metadata of the instance): a login with it
//!    runs a command and gives its exit status, a bulk transfer of 64 KiB
//!    through the pipes of a session is whole, a session with a terminal
//!    (`ssh -tt`) runs a shell on a pseudo terminal and brings 2 000 lines
//!    back in order. The host key now exists in `/etc/dropbear`.
//! 4. A key the server does not know is refused.
//! 5. A password of 257 and one of 1 024 bytes is refused for the account
//!    `root` (the field `!` of `/etc/shadow`) and for an account with `*`.
//! 6. Pseudo terminals: sessions with a terminal are opened one after the
//!    other until one gets none (the pairs are eight, the console takes
//!    one), the count is printed, and after they all end a new session gets
//!    its terminal again.
//! 7. The server's log on the console says what happened (a public key
//!    accepted, no password accepted) and the guest did not fault.
//!
//! The host needs `ssh` and `ssh-keygen` of OpenSSH. The ports of the host
//! are free ports xtask took and gave back just before QEMU starts.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::qemu::{Forward, Proto};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, ImageProgram, SERVICES_STARTED, Variant, build,
    build_boot_image, busybox_build, nano_build, net, net_tls, qemu, relibc, rootfs, symbolize,
};

/// The image of the run.
pub const IMAGE: &str = "boot-ssh-probe.img";

/// The command line of the server the launcher starts.
const SERVER_LINE: [&str; 6] = ["dropbear", "-F", "-R", "-s", "-j", "-k"];

/// How long one login may take: the key exchange and the first command run
/// on an emulated CPU.
const LOGIN_WITHIN: Duration = Duration::from_secs(120);
/// The whole run may take this long.
const RUN_WITHIN: Duration = Duration::from_secs(600);
/// The sessions with a terminal the run opens at most: more than the pairs
/// the system has.
const SESSIONS_AT_MOST: usize = 10;
/// The pairs of pseudo terminals of the system (`docs/status.md`); the
/// console is next to them, so seven sessions is the least that must get one.
const PAIRS: usize = 8;
/// The lines a session with a terminal brings back.
const LINES: usize = 2_000;

/// The programs of the image: those of the shell image with the network
/// service, with the launcher that also starts the server.
pub fn programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = net::programs().to_vec();
        for program in &mut programs {
            if program.0 == "ash-launcher" {
                program.3 = &["interactive", "dropbear"];
            }
        }
        programs
    })
}

/// What a run of `ssh` came to.
struct Ended {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

impl Ended {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Runs `command` with `stdin` written to it, waiting up to `within`; the
/// process is killed when the time is up.
fn run_for(mut command: Command, stdin: &[u8], within: Duration) -> Result<Ended, String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("ssh: {e}"))?;
    // The input stays open until the session ends: an end of input that
    // comes before the shell has read its lines would cut them off.
    let mut input = child.stdin.take().ok_or("ssh: no stdin")?;
    input
        .write_all(stdin)
        .and_then(|()| input.flush())
        .map_err(|e| format!("ssh: {e}"))?;
    let mut out = child.stdout.take().ok_or("ssh: no stdout")?;
    let mut err = child.stderr.take().ok_or("ssh: no stderr")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = out.read_to_end(&mut bytes);
        bytes
    });
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = err.read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + within;
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let stdout = reader.join().unwrap_or_default();
                let stderr = errors.join().unwrap_or_default();
                return Err(format!(
                    "ssh did not end within {} s; it said {:?} and {:?}",
                    within.as_secs(),
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                ));
            }
            Err(e) => return Err(format!("ssh: {e}")),
        }
    };
    drop(input);
    Ok(Ended {
        code,
        stdout: reader.join().unwrap_or_default(),
        stderr: String::from_utf8_lossy(&errors.join().unwrap_or_default()).into_owned(),
    })
}

/// The host's `ssh` towards the forwarded port: no configuration file, no
/// agent, the key exchange and the host key that the server's own list
/// starts with (the curve25519 exchange is the quick one on an emulated CPU,
/// and Ed25519 is the host key made first), and a file of known hosts of the
/// run.
struct Client {
    port: u16,
    dir: PathBuf,
}

impl Client {
    fn command(&self, user: &str, key: Option<&Path>, batch: bool) -> Command {
        let mut command = Command::new("ssh");
        command
            .args(["-F", "/dev/null", "-p", &self.port.to_string()])
            .args(["-o", "StrictHostKeyChecking=no"])
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.dir.join("known_hosts").display()
            ))
            .args(["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"])
            .args(["-o", "HostKeyAlgorithms=ssh-ed25519"])
            .args(["-o", "KexAlgorithms=curve25519-sha256"])
            .args(["-o", "ConnectTimeout=60"])
            .args([
                "-o",
                &format!("BatchMode={}", if batch { "yes" } else { "no" }),
            ]);
        if let Some(key) = key {
            command.arg("-i").arg(key);
        }
        command.arg(format!("{user}@127.0.0.1"));
        command
    }
}

/// `ssh-keygen` makes the key `name` in `dir` without a passphrase: the
/// private file and the public line.
fn make_key(dir: &Path, name: &str) -> Result<(PathBuf, String), String> {
    let path = dir.join(name);
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&path)
        .status()
        .map_err(|e| format!("ssh-keygen: {e}"))?;
    if !made.success() {
        return Err(format!("ssh-keygen ended with {made}"));
    }
    let line = std::fs::read_to_string(path.with_extension("pub"))
        .or_else(|_| std::fs::read_to_string(format!("{}.pub", path.display())))
        .map_err(|e| format!("the public key: {e}"))?;
    Ok((path, line.trim().to_owned()))
}

/// The version line of `ssh`, which the run needs on the host.
fn host_ssh() -> Result<String, String> {
    let said = Command::new("ssh")
        .arg("-V")
        .output()
        .map_err(|e| format!("net-ssh needs the OpenSSH client `ssh` on the host: {e}"))?;
    let text = String::from_utf8_lossy(&said.stderr).trim().to_owned();
    Command::new("ssh-keygen")
        .arg("-?")
        .output()
        .map_err(|e| format!("net-ssh needs `ssh-keygen` on the host: {e}"))?;
    Ok(text)
}

/// The files the image holds under `/etc/dropbear`, and whether the image
/// lists the directory: the host keys are made on the first start, so the
/// directory is empty.
fn image_check() -> Result<(), String> {
    let files = rootfs::files_of(IMAGE);
    let held: Vec<&str> = files
        .iter()
        .map(|f| f.path)
        .filter(|p| p.starts_with("/etc/dropbear/"))
        .collect();
    if !held.is_empty() {
        return Err(format!("the image holds files of /etc/dropbear: {held:?}"));
    }
    let package = crate::packages::load()?
        .into_iter()
        .find(|p| p.name == "dropbear")
        .ok_or("no package dropbear")?;
    if !package.dirs.iter().any(|d| d == "/etc/dropbear") {
        return Err("the package dropbear lists no directory /etc/dropbear".to_owned());
    }
    if let Some(file) = package
        .files
        .iter()
        .find(|f| f.0.starts_with("/etc/dropbear/"))
    {
        return Err(format!("the package dropbear holds {}", file.0));
    }
    Ok(())
}

/// The lines between the markers of `command` in the guest.
fn guest(run: &mut qemu::Run, command: &str, marker: &str) -> Result<Vec<String>, String> {
    net_tls::capture(run, command, marker, DIALOG_STEP)
}

/// Step 2: the one running server and its command line.
fn command_line(run: &mut qemu::Run) -> Result<(), String> {
    let lines = guest(
        run,
        "for p in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $p/cmdline 2>/dev/null); case \"$c\" in dropbear*) echo \"cmd ${p#/proc/}: $c\";; esac; done",
        "cmdline",
    )?;
    let found: Vec<&String> = lines.iter().filter(|l| l.starts_with("cmd ")).collect();
    let [line] = found.as_slice() else {
        return Err(format!(
            "the guest runs {} servers named dropbear, wanted one: {lines:?}",
            found.len()
        ));
    };
    let words: Vec<&str> = line
        .split_once(": ")
        .map(|(_, c)| c.split_whitespace().collect())
        .unwrap_or_default();
    if words != SERVER_LINE {
        return Err(format!(
            "the server runs as {words:?} ({line}), wanted {SERVER_LINE:?}"
        ));
    }
    println!(
        "net-ssh: the server's command line is {}",
        SERVER_LINE.join(" ")
    );
    Ok(())
}

/// Step 6: sessions with a terminal until one gets none.
fn terminals(client: &Client, key: &Path) -> Result<usize, String> {
    use std::io::{BufRead, BufReader};
    let mut held: Vec<std::process::Child> = Vec::new();
    let mut got = 0;
    for n in 1..=SESSIONS_AT_MOST {
        let mut command = client.command("root", Some(key), true);
        command
            .arg("-tt")
            .arg("echo tty-$(tty); sleep 600")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|e| format!("ssh: {e}"))?;
        let out = child.stdout.take().ok_or("ssh: no stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if line.trim().starts_with("tty-") {
                    let _ = tx.send(line.trim().to_owned());
                    break;
                }
            }
        });
        let said = rx.recv_timeout(LOGIN_WITHIN);
        held.push(child);
        match said {
            Ok(line) if line.starts_with("tty-/dev/") => got = n,
            Ok(line) => {
                println!("net-ssh: session {n} got no terminal ({line})");
                break;
            }
            Err(_) => {
                for mut child in held {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return Err(format!(
                    "session {n} said nothing within {} s",
                    LOGIN_WITHIN.as_secs()
                ));
            }
        }
    }
    for mut child in held {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(got)
}

/// `cargo xtask net-ssh [MACHINE]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let machine = match args {
        [] => &qemu::VIRT,
        [name] => match name.as_str() {
            "hvf" => &qemu::HVF_V3,
            "tcg" => &qemu::VIRT,
            other => qemu::machine(Some(&other.to_owned()))?,
        },
        _ => return Err("usage: cargo xtask net-ssh [tcg|hvf]".to_owned()),
    };
    probe(machine)
}

pub fn probe(machine: &'static qemu::Machine) -> Result<(), String> {
    if machine.is_hvf() {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
    }
    println!("net-ssh: host client {}", host_ssh()?);
    busybox_build()?;
    nano_build()?;
    crate::net_build()?;
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(IMAGE, programs(), BOOT_PROFILE)?;
    image_check()?;
    crate::notices::image_has_package_notices(&image, IMAGE, "dropbear")?;
    let dir = crate::target_dir().join("net-ssh");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (good, good_line) = make_key(&dir, "good")?;
    let (bad, _) = make_key(&dir, "bad")?;
    let port = crate::net_curl::free_tcp_port()?;
    let client = Client {
        port,
        dir: dir.clone(),
    };
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::net_on(
        machine,
        &[Forward {
            proto: Proto::Tcp,
            host: port,
            guest: 22,
        }],
    ));
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let started = Instant::now();
    let mut terminal_sessions = 0;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("S=ok")?;
        run.expect("# ", DIALOG_STEP)?;
        // 1 (the guest's half) and 2.
        let held = guest(&mut run, "ls -A /etc/dropbear | wc -l", "keys0")?;
        if held.iter().map(|l| l.trim()).collect::<Vec<_>>() != ["0"] {
            return Err(format!("/etc/dropbear is not empty at the start: {held:?}"));
        }
        command_line(&mut run)?;
        // The key of the probe, and an account whose field is `*`.
        run.send(&format!(
            "mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '{good_line}' > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && echo 'star:x:1001:100:star:/tmp:/bin/ash' >> /etc/passwd && echo 'star:*:20000:0:99999:7:::' >> /etc/shadow && echo placed-$?"
        ))?;
        run.expect_line("the key placed", |l| l.trim() == "placed-0", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // 3.
        let mut ssh = client.command("root", Some(&good), true);
        ssh.arg("echo ssh-ok-$((6*7)); id -u");
        let said = run_for(ssh, b"", LOGIN_WITHIN)?;
        if said.code != Some(0) || !said.text().contains("ssh-ok-42") {
            return Err(format!(
                "the login with the key gave {:?}: {:?} {:?}",
                said.code,
                said.text(),
                said.stderr
            ));
        }
        println!("net-ssh: the login with the key runs a command");
        let keys = guest(&mut run, "ls /etc/dropbear", "keys1")?;
        if keys.iter().all(|l| l.trim().is_empty()) {
            return Err("the first login made no host key in /etc/dropbear".to_owned());
        }
        println!("net-ssh: host keys after the first login: {keys:?}");
        let mut ssh = client.command("root", Some(&good), true);
        ssh.arg("exit 7");
        let said = run_for(ssh, b"", LOGIN_WITHIN)?;
        if said.code != Some(7) {
            return Err(format!(
                "the exit status of the session is {:?}, wanted 7: {}",
                said.code, said.stderr
            ));
        }
        let mut ssh = client.command("root", Some(&good), true);
        ssh.arg("cat /www/index.html");
        let said = run_for(ssh, b"", LOGIN_WITHIN)?;
        if said.stdout != rootfs::www_index() {
            return Err(format!(
                "the page through a session is {} bytes (code {:?}), wanted {}: {}",
                said.stdout.len(),
                said.code,
                rootfs::WWW_INDEX_LEN,
                said.stderr
            ));
        }
        println!(
            "net-ssh: exit status 7 and a page of {} bytes through the pipes are whole",
            rootfs::WWW_INDEX_LEN
        );
        let mut ssh = client.command("root", Some(&good), true);
        ssh.arg("-tt");
        let script = format!(
            "tty\necho pty-$((6*7))\ni=0; while [ $i -lt {LINES} ]; do echo line-$i; i=$((i+1)); done\nexit 3\n"
        );
        let said = run_for(ssh, script.as_bytes(), LOGIN_WITHIN)?;
        let text = said.text();
        let lines: Vec<&str> = text
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .filter(|l| l.starts_with("line-") && !l.contains("$"))
            .collect();
        let in_order = lines.len() == LINES
            && lines
                .iter()
                .enumerate()
                .all(|(n, l)| *l == format!("line-{n}"));
        if said.code != Some(3) || !text.contains("pty-42") || !text.contains("/dev/") || !in_order
        {
            return Err(format!(
                "the session with a terminal: code {:?}, {} of {LINES} lines (in order {in_order}), stderr {:?}, the head {:?}",
                said.code,
                lines.len(),
                said.stderr,
                text.chars().take(300).collect::<String>()
            ));
        }
        println!(
            "net-ssh: a session with a terminal runs a shell, {LINES} lines come back in order and its exit status is 3"
        );
        // 4.
        let mut ssh = client.command("root", Some(&bad), true);
        ssh.arg("echo must-not-run");
        let said = run_for(ssh, b"", LOGIN_WITHIN)?;
        if said.code != Some(255)
            || said.text().contains("must-not-run")
            || !said.stderr.contains("Permission denied")
        {
            return Err(format!(
                "a key the server does not know gave {:?}: {:?} {:?}",
                said.code,
                said.text(),
                said.stderr
            ));
        }
        println!("net-ssh: a key the server does not know is refused");
        // 5.
        for length in [257usize, 1024] {
            let secret = dir.join("secret");
            std::fs::write(&secret, "a".repeat(length)).map_err(|e| format!("secret: {e}"))?;
            let askpass = dir.join("askpass.sh");
            std::fs::write(&askpass, format!("#!/bin/sh\ncat '{}'\n", secret.display()))
                .map_err(|e| format!("askpass: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("askpass: {e}"))?;
            }
            for user in ["root", "star"] {
                let mut ssh = client.command(user, None, false);
                ssh.args([
                    "-o",
                    "PreferredAuthentications=password,keyboard-interactive",
                ])
                .args(["-o", "PubkeyAuthentication=no"])
                .args(["-o", "NumberOfPasswordPrompts=1"])
                .arg("echo must-not-run")
                .env("SSH_ASKPASS", &askpass)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env_remove("DISPLAY");
                let said = run_for(ssh, b"", LOGIN_WITHIN)?;
                if said.code != Some(255)
                    || said.text().contains("must-not-run")
                    || !said.stderr.contains("Permission denied")
                {
                    return Err(format!(
                        "a password of {length} bytes for {user} gave {:?}: {:?} {:?}",
                        said.code,
                        said.text(),
                        said.stderr
                    ));
                }
            }
        }
        println!(
            "net-ssh: a password of 257 and one of 1024 bytes is refused for the account with ! and the one with *"
        );
        // 6.
        terminal_sessions = terminals(&client, &good)?;
        println!(
            "net-ssh: {terminal_sessions} sessions at once got a terminal of the {PAIRS} pairs"
        );
        if terminal_sessions < PAIRS - 1 {
            return Err(format!(
                "only {terminal_sessions} sessions got a terminal, wanted at least {}",
                PAIRS - 1
            ));
        }
        let mut ssh = client.command("root", Some(&good), true);
        ssh.args(["-tt", "tty"]);
        let said = run_for(ssh, b"", LOGIN_WITHIN)?;
        if said.code != Some(0) || !said.text().contains("/dev/") {
            return Err(format!(
                "after the sessions ended a new session got no terminal: {:?} {:?} {:?}",
                said.code,
                said.text(),
                said.stderr
            ));
        }
        println!("net-ssh: after they ended a new session got its terminal at once");
        // 7: the server is still the one process and still answers.
        command_line(&mut run)?;
        let mut ssh = client.command("root", Some(&good), true);
        ssh.arg("echo last-$((6*7))");
        let said = run_for(ssh, b"", LOGIN_WITHIN)?;
        if said.code != Some(0) || !said.text().contains("last-42") {
            return Err(format!("the last login: {:?} {:?}", said.code, said.stderr));
        }
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    let has = |what: &str| output.lines.iter().any(|l| l.contains(what));
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("init: net ended: fault")
    }) {
        return Err("the image with the SSH server faulted".into());
    }
    if !has("Pubkey auth succeeded") {
        return Err("the console shows no \"Pubkey auth succeeded\" of the server".to_owned());
    }
    if has("Password auth succeeded") {
        return Err("the console shows a \"Password auth succeeded\"".to_owned());
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
        "net-ssh passed in {:.0} s on {}: {terminal_sessions} terminals at once",
        elapsed.as_secs_f64(),
        machine.name
    );
    Ok(())
}
