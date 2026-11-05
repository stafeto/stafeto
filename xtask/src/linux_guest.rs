// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The Linux guest of the measurement of the network (stage P7, part 1) and
//! the check that it and stafeto's image of the measurement stand on equal
//! ground. `cargo xtask linux-guest build|run|check`:
//!
//! - `build` makes `target/linux-guest/{Image,initramfs.cpio.gz,MANIFEST}`
//!   with `tools/build-linux-guest.py` from the Alpine packages that
//!   `tools/linux-guest/alpine.lock` pins: nginx and OpenSSL of the same
//!   versions as stafeto's, the settings of nginx of `tools/nginx/` and the
//!   files under `/www` of stafeto's image, from the same sources here.
//! - `run` boots it on Apple VZ with the shell on the terminal.
//! - `check` boots the Linux guest and then stafeto's image of the
//!   measurement (`boot-net-bench.img`, the shell's processes on four CPUs)
//!   on VZ with four CPUs and 1 GiB each, reads on both the versions of
//!   nginx and OpenSSL, the fingerprint of `nginx -T` and the SHA-256 of
//!   the files under `/www`, fetches every file from the Mac, and refuses
//!   to go on where the guests differ. It is the check that P7-2 makes
//!   before a run. The guest of Linux is built on this Mac and never ships:
//!   it stays in `target/`, and `tools/dist.py` refuses a release that holds
//!   it.
//!
//! No ladder runs here: it proves that both guests boot, serve the same
//! files with the same settings, and answer the Mac.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::nginx_probe::{self, Connection};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, ImageProgram, SERVICES_STARTED, Variant, build,
    build_boot_image, net, net_vz, qemu, root, run_cmd, target_dir, vz,
};

/// The image of stafeto in the measurement: the network image of VZ with the
/// shell's processes on all four CPUs (`init::table::bench`).
pub const BENCH_IMAGE: &str = "boot-net-bench.img";
/// The machine of both guests (the provisional ruling B2 of the owner).
pub const CPUS: usize = 4;
pub const MEMORY_MIB: u64 = 1024;
/// How long the guest of Linux takes to give its prompt, and nginx to
/// answer, after the start of the machine.
const LINUX_WITHIN: Duration = Duration::from_secs(60);
const ANSWER_WITHIN: Duration = Duration::from_secs(30);

/// The programs of the image of the measurement: those of the network image
/// of VZ with init's table of the measurement (`table-bench-vz`).
pub fn bench_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = net::vz_programs(false).to_vec();
        for program in &mut programs {
            if program.0 == "init" {
                program.3 = &["table-bench-vz"];
            }
        }
        programs
    })
}

/// Builds the image of the measurement (a step of ci, which can run
/// neither HVF nor VZ).
pub fn build_image() -> Result<PathBuf, String> {
    build_boot_image(BENCH_IMAGE, bench_programs(), BOOT_PROFILE)
}

// What both guests carry -------------------------------------------------------

/// The files under `/www` both guests carry, by their paths in the guest in
/// the order a shell expands `/www/*.*`: the page of the images with the
/// network and the three files of the load. One source: stafeto's image takes
/// them from `rootfs`, the Linux guest from the overlay made here.
pub fn www_files() -> Vec<(&'static str, &'static [u8])> {
    let mut files: Vec<(&'static str, &'static [u8])> = vec![
        ("/www/index.html", crate::rootfs::www_index()),
        ("/www/1k.bin", crate::nginx_bench::www_1k()),
        ("/www/10k.bin", nginx_probe::www_10k()),
        ("/www/256k.bin", nginx_probe::www_256k()),
    ];
    files.sort_by(|a, b| a.0.cmp(b.0));
    files
}

/// The settings of nginx in both guests.
pub fn nginx_conf() -> &'static str {
    nginx_probe::NGINX_CONF
}

/// Writes the overlay of the Linux guest into the empty `dir`: the settings
/// of nginx and the files under `/www`.
pub fn write_overlay(dir: &Path) -> Result<(), String> {
    let put = |path: &str, bytes: &[u8]| -> Result<(), String> {
        let target = dir.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(target.parent().expect("a path has a parent"))
            .and_then(|()| std::fs::write(&target, bytes))
            .map_err(|e| format!("{}: {e}", target.display()))
    };
    put("/etc/nginx/nginx.conf", nginx_conf().as_bytes())?;
    for (path, bytes) in www_files() {
        put(path, bytes)?;
    }
    Ok(())
}

// The fingerprints --------------------------------------------------------------

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of `bytes` in hex.
fn sha256_hex(bytes: &[u8]) -> String {
    hex_of(&nginx_probe::sha256(bytes))
}

/// The directives of nginx that the two guests may set apart: a run of
/// four workers against one, the user, the size of a worker, and the
/// parameter `reuseport`. The fingerprint of the settings masks them; any
/// other difference stays. P7-1 sets none apart.
const ALLOWED: [&str; 4] = [
    "worker_processes",
    "user",
    "worker_connections",
    "worker_shutdown_timeout",
];

/// `line` with the value of every allowed directive replaced by a label,
/// and the parameter `reuseport` of `listen` taken out. A directive is the
/// name at the start of the line or after `{` or `;`.
fn mask_allowed(line: &str) -> String {
    let mut text = line.to_owned();
    for name in ALLOWED {
        let mut from = 0;
        while let Some(found) = text[from..].find(name) {
            let start = from + found;
            let before = text[..start].trim_end();
            let at_directive = before.is_empty() || before.ends_with('{') || before.ends_with(';');
            let after = &text[start + name.len()..];
            let spaced = after.starts_with([' ', '\t']);
            if at_directive
                && spaced
                && let Some(end) = after.find(';')
            {
                let label = format!("{name} <allowed>");
                text.replace_range(start..start + name.len() + end, &label);
                from = start + label.len();
            } else {
                from = start + name.len();
            }
        }
    }
    if text.trim_start().starts_with("listen ") {
        text = text.replace(" reuseport", "");
    }
    text
}

/// The output of `nginx -T`, normalised: the lines of nginx's own about the
/// syntax and the test (`nginx: ...`) out, the carriage returns of the
/// console out, the allowed directives masked, no empty line at the end.
pub fn normalise_config(output: &str) -> String {
    let mut lines: Vec<String> = output
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.starts_with("nginx: "))
        .map(mask_allowed)
        .collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

/// The fingerprint of the settings that `nginx -T` printed.
pub fn config_digest(output: &str) -> String {
    sha256_hex(normalise_config(output).as_bytes())
}

/// What `nginx -T` prints for the settings `conf` and the types `mime`: each
/// file after the line that names it.
pub fn expected_config_output(conf: &str, mime: &[u8]) -> String {
    format!(
        "# configuration file /etc/nginx/nginx.conf:\n{conf}\n# configuration file /etc/nginx/mime.types:\n{}\n",
        String::from_utf8_lossy(mime)
    )
}

/// The digest of the files under `/www`: SHA-256 of the lines `HASH  PATH`,
/// one per file in the order of the paths, which is the order a shell expands
/// `/www/*.*` in.
pub fn www_digest(files: &[(&str, &[u8])]) -> String {
    let hashes: Vec<(String, String)> = files
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), sha256_hex(bytes)))
        .collect();
    digest_of_hashes(hashes)
}

fn digest_of_hashes(mut hashes: Vec<(String, String)>) -> String {
    hashes.sort();
    let mut listing = String::new();
    for (path, hash) in hashes {
        listing.push_str(&format!("{hash}  {path}\n"));
    }
    sha256_hex(listing.as_bytes())
}

/// The digest of the files that `openssl dgst -sha256 FILES` listed, a line
/// `SHA2-256(PATH)= HASH` each (`SHA256(PATH)= HASH` in older versions).
pub fn www_digest_of_listing(lines: &[String]) -> Result<String, String> {
    let mut hashes = Vec::new();
    for line in lines {
        let Some((head, hash)) = line.trim().split_once(")= ") else {
            continue;
        };
        let path = head
            .split_once('(')
            .map(|(_, path)| path)
            .ok_or_else(|| format!("the line {line:?}"))?;
        hashes.push((path.to_owned(), hash.trim().to_owned()));
    }
    if hashes.is_empty() {
        return Err(format!("no digest in {lines:?}"));
    }
    Ok(digest_of_hashes(hashes))
}

/// The version nginx names in `nginx -V` (the line `nginx version:
/// nginx/X`) and the OpenSSL it was built with (the line `built with
/// OpenSSL X ...`).
pub fn versions_of(lines: &[String]) -> Result<(String, String), String> {
    let nginx = lines
        .iter()
        .find_map(|l| l.trim().strip_prefix("nginx version: nginx/"))
        .ok_or_else(|| format!("nginx -V has no version line: {lines:?}"))?;
    let openssl = lines
        .iter()
        .find_map(|l| l.trim().strip_prefix("built with OpenSSL "))
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| format!("nginx -V has no OpenSSL line: {lines:?}"))?;
    Ok((nginx.trim().to_owned(), openssl.to_owned()))
}

/// Refuses a guest whose nginx or OpenSSL is not the version of stafeto's
/// packages (a pin of Alpine 3.23 has nginx 1.28.3).
pub fn check_versions(
    lines: &[String],
    nginx: &str,
    openssl: &str,
) -> Result<(String, String), String> {
    let (n, o) = versions_of(lines)?;
    if n != nginx || o != openssl {
        return Err(format!(
            "the guest has nginx {n} with OpenSSL {o}; the packages of stafeto have {nginx} and {openssl}"
        ));
    }
    Ok((n, o))
}

// The two guests ------------------------------------------------------------------

/// What one guest showed.
#[derive(Debug, Default)]
struct Report {
    system: &'static str,
    address: Option<Ipv4Addr>,
    mac: String,
    /// From the start of `vz-run` to the prompt of the shell, to the first
    /// answer of nginx on the Mac.
    prompt: Duration,
    answer: Duration,
    cpus: String,
    nginx: String,
    openssl: String,
    nginx_v: Vec<String>,
    config_digest: String,
    www_digest: String,
    features: String,
    served: usize,
}

impl Report {
    fn table(&self) -> String {
        let at = |d: Duration| format!("{:.2} s", d.as_secs_f64());
        format!(
            "| {} | {} | {} | {} | {} | nginx {} / OpenSSL {} | {} | {} | {} |\n",
            self.system,
            self.address.map_or(String::new(), |a| a.to_string()),
            self.mac,
            at(self.prompt),
            at(self.answer),
            self.nginx,
            self.openssl,
            &self.config_digest[..16],
            &self.www_digest[..16],
            self.served,
        )
    }
}

/// The captured lines of `command` between the markers of the shell.
fn capture(
    run: &mut qemu::Run,
    command: &str,
    marker: &str,
    within: Duration,
) -> Result<Vec<String>, String> {
    crate::net_tls::capture(run, command, marker, within)
}

/// The digests and versions the console of a guest gives, once its shell
/// answers: `nginx -V`, `nginx -T`, `openssl dgst -sha256 /www/*.*` and the number
/// of CPUs, checked against what stafeto's sources say.
fn read_fingerprints(run: &mut qemu::Run, report: &mut Report) -> Result<(), String> {
    run.send("S=ok")?;
    run.expect("# ", DIALOG_STEP)?;
    report.cpus = capture(run, "nproc", "nproc", DIALOG_STEP)?
        .iter()
        .find(|l| l.trim().parse::<usize>().is_ok())
        .map(|l| l.trim().to_owned())
        .unwrap_or_default();
    if report.cpus != CPUS.to_string() {
        return Err(format!(
            "{}: nproc says {:?}, {CPUS} wanted",
            report.system, report.cpus
        ));
    }
    report.nginx_v = capture(run, "nginx -V 2>&1", "version", DIALOG_STEP)?;
    let (nginx, openssl) = check_versions(
        &report.nginx_v,
        &crate::packages::value("nginx", "version")?,
        &crate::packages::value("openssl", "version")?,
    )
    .map_err(|e| format!("{}: {e}", report.system))?;
    report.nginx = nginx;
    report.openssl = openssl;
    let dump = capture(run, "nginx -T 2>&1", "config", DIALOG_STEP)?.join("\n");
    report.config_digest = config_digest(&dump);
    let www = capture(run, "openssl dgst -sha256 /www/*.*", "www", DIALOG_STEP)?;
    report.www_digest = www_digest_of_listing(&www)
        .map_err(|e| format!("{}: the digest of /www: {e}", report.system))?;
    Ok(())
}

/// The fingerprints a guest must show, from stafeto's sources.
fn expected() -> Result<(String, String), String> {
    let mime = nginx_probe::mime_types();
    if mime.is_empty() {
        return Err("nginx's mime.types is missing: run tools/build-nginx.py".to_owned());
    }
    Ok((
        config_digest(&expected_config_output(nginx_conf(), mime)),
        www_digest(&www_files()),
    ))
}

/// Refuses a guest whose fingerprints are not the expected ones.
fn verify(report: &Report, config: &str, www: &str) -> Result<(), String> {
    if report.config_digest != config {
        return Err(format!(
            "{}: the fingerprint of `nginx -T` is {}, stafeto's sources give {config}",
            report.system, report.config_digest
        ));
    }
    if report.www_digest != www {
        return Err(format!(
            "{}: the digest of /www is {}, stafeto's sources give {www}",
            report.system, report.www_digest
        ));
    }
    Ok(())
}

/// Fetches every file of `/www` from the guest and compares the bytes with
/// the sources; waits up to `ANSWER_WITHIN` for the first answer. Gives the
/// time of the first answer and the number of files served.
fn fetch_all(address: SocketAddr, started: Instant) -> Result<(Duration, usize), String> {
    let first = loop {
        let answer = Connection::open(address, Duration::from_secs(2))
            .and_then(|mut c| c.get("/index.html"));
        match answer {
            Ok(_) => break started.elapsed(),
            Err(_) if started.elapsed() < ANSWER_WITHIN * 3 => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(why) => return Err(format!("the first request: {why}")),
        }
    };
    let mut served = 0;
    for (path, bytes) in www_files() {
        let url = path.trim_start_matches("/www");
        let body = Connection::open(address, Duration::from_secs(10))
            .and_then(|mut c| c.get(url))
            .map_err(|e| format!("GET {url}: {e}"))?;
        nginx_probe::same(&format!("GET {url}"), &body, bytes)?;
        served += 1;
    }
    Ok((first, served))
}

/// The machine of both guests, with the MAC suffix of the run.
fn machine(suffix: &vz::Suffix) -> vz::Machine {
    vz::Machine {
        cpus: Some(CPUS),
        memory_mib: Some(MEMORY_MIB),
        net: 1,
        mac_suffix: suffix.value,
    }
}

fn linux_dir() -> PathBuf {
    target_dir().join("linux-guest")
}

/// `cargo xtask linux-guest build`.
pub fn build_guest() -> Result<PathBuf, String> {
    let dir = linux_dir();
    let overlay = dir.join("overlay");
    let _ = std::fs::remove_dir_all(&overlay);
    std::fs::create_dir_all(&overlay).map_err(|e| format!("{}: {e}", overlay.display()))?;
    write_overlay(&overlay)?;
    run_cmd(
        Command::new("python3")
            .arg(root().join("tools/build-linux-guest.py"))
            .arg("--overlay")
            .arg(&overlay)
            .arg("--out")
            .arg(&dir),
    )?;
    Ok(dir)
}

/// The command that boots the guest of Linux built in `dir`.
fn linux_command(dir: &Path, suffix: &vz::Suffix) -> Result<Command, String> {
    vz::command_on(
        &dir.join("Image"),
        &dir.join("initramfs.cpio.gz"),
        machine(suffix),
    )
}

/// `cargo xtask linux-guest run`: the shell of the guest on the terminal.
fn run_guest() -> Result<(), String> {
    let dir = build_guest()?;
    let suffix = vz::claim_suffix()?;
    println!(
        "linux-guest: MAC suffix {}; the console is a shell (Ctrl-D does not end it: `poweroff -f`)",
        suffix.value
    );
    let status = linux_command(&dir, &suffix)?
        .stdin(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("vz-run: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("vz-run exited with {status}"))
    }
}

/// What a check of one guest left: its report as far as it got, its console
/// and the error that ended it, if any.
struct Guest {
    report: Report,
    lines: Vec<String>,
    error: Option<String>,
}

/// The guest of Linux booted, fingerprinted and fetched from.
fn check_linux(dir: &Path, expected: &(String, String)) -> Result<Guest, String> {
    let suffix = vz::claim_suffix()?;
    let mut report = Report {
        system: "Linux 6.18 (Alpine 3.24)",
        ..Report::default()
    };
    let command = linux_command(dir, &suffix)?;
    let started = Instant::now();
    let mut run = qemu::Run::start(command, qemu::Input::Pipe)?;
    let result = (|| {
        let address = run.expect_line(
            "the address",
            |l| l.starts_with("linux-guest: address "),
            LINUX_WITHIN,
        )?;
        let address: Ipv4Addr = address
            .trim_start_matches("linux-guest: address ")
            .trim()
            .parse()
            .map_err(|e| format!("the address {address:?}: {e}"))?;
        report.address = Some(address);
        let mac = run.expect_line(
            "the MAC",
            |l| l.starts_with("linux-guest: mac "),
            DIALOG_STEP,
        )?;
        report.mac = mac
            .trim_start_matches("linux-guest: mac ")
            .trim()
            .to_owned();
        let own = vz::mac(suffix.value, 0);
        if report.mac != own {
            return Err(format!(
                "the guest has the MAC {}, the run set {own}",
                report.mac
            ));
        }
        let features = run.expect_line(
            "the features",
            |l| l.starts_with("linux-guest: features "),
            DIALOG_STEP,
        )?;
        report.features = features
            .trim_start_matches("linux-guest: features ")
            .trim()
            .to_owned();
        run.expect_line("ready", |l| l == "linux-guest: ready", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        report.prompt = started.elapsed();
        let (first, served) = fetch_all((address, 80).into(), started)?;
        report.answer = first;
        report.served = served;
        read_fingerprints(&mut run, &mut report)?;
        verify(&report, &expected.0, &expected.1)
    })();
    let _ = run.send("poweroff -f");
    let lines = run.lines().to_vec();
    run.stop();
    Ok(Guest {
        report,
        lines,
        error: result.err(),
    })
}

/// The image of the measurement booted, fingerprinted and fetched from.
fn check_stafeto(expected: &(String, String)) -> Result<Guest, String> {
    crate::relibc()?;
    crate::busybox_build()?;
    crate::nano_build()?;
    crate::net_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_image()?;
    let suffix = vz::claim_suffix()?;
    let mut report = Report {
        system: "stafeto (boot-net-bench)",
        ..Report::default()
    };
    let command = vz::command_on(&kernel.image, &image, machine(&suffix))?;
    let started = Instant::now();
    let mut run = qemu::Run::start(command, qemu::Input::Pipe)?;
    let result = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        let lease = run.expect_line("the lease", |l| l.contains("net: lease "), BOOT_TIMEOUT)?;
        let lease = net_vz::parse_address(&lease, "lease").ok_or_else(|| format!("{lease:?}"))?;
        report.address = Some(lease.address);
        run.expect("# ", DIALOG_STEP)?;
        report.prompt = started.elapsed();
        // The line of the driver names the MAC address of the device.
        let driver = run
            .lines()
            .iter()
            .find(|l| l.starts_with("virtio-net: "))
            .cloned()
            .ok_or("no line of the driver of the network device")?;
        report.mac = driver
            .split("mac ")
            .nth(1)
            .map(|m| m.trim().to_owned())
            .ok_or_else(|| format!("the driver's line {driver:?} names no MAC"))?;
        let own = vz::mac(suffix.value, 0);
        if report.mac != own {
            return Err(format!(
                "the guest has the MAC {}, the run set {own}",
                report.mac
            ));
        }
        run.send("nginx -c /etc/nginx/nginx.conf & M=$!")?;
        run.expect_line(
            "the event method",
            |l| l.contains("using the \"epoll\" event method"),
            DIALOG_STEP,
        )?;
        nginx_probe::lines_of(&mut run, "start worker process ", 4, DIALOG_STEP)?;
        let (first, served) = fetch_all((lease.address, 80).into(), started)?;
        report.answer = first;
        report.served = served;
        read_fingerprints(&mut run, &mut report)?;
        verify(&report, &expected.0, &expected.1)
    })();
    let lines = run.lines().to_vec();
    run.stop();
    Ok(Guest {
        report,
        lines,
        error: result.err(),
    })
}

/// `cargo xtask linux-guest check`.
fn check() -> Result<(), String> {
    let dir = build_guest()?;
    let expected = {
        crate::relibc()?;
        crate::net_build()?;
        expected()?
    };
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let out = linux_dir().join(format!("check-{seconds}"));
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let save = |name: &str, lines: &[String]| {
        let _ = std::fs::write(out.join(name), lines.join("\n") + "\n");
    };
    let guests = [
        ("linux", check_linux(&dir, &expected)?),
        ("stafeto", check_stafeto(&expected)?),
    ];
    let mut table = String::from(
        "| system | address | MAC | to the prompt | to the first answer | versions | `nginx -T` | `/www` | files served |\n|---|---|---|---|---|---|---|---|---|\n",
    );
    let mut failures = Vec::new();
    for (name, guest) in guests {
        save(&format!("{name}-console.log"), &guest.lines);
        save(&format!("{name}-nginx-v.txt"), &guest.report.nginx_v);
        if !guest.report.features.is_empty() {
            save(
                &format!("{name}-features.txt"),
                std::slice::from_ref(&guest.report.features),
            );
        }
        match guest.error {
            None => table.push_str(&guest.report.table()),
            Some(why) => failures.push(format!("{name}: {why}")),
        }
    }
    std::fs::write(
        out.join("report.md"),
        format!(
            "{table}\nexpected: `nginx -T` {}, `/www` {}\n",
            expected.0, expected.1
        ),
    )
    .map_err(|e| format!("report.md: {e}"))?;
    print!("{table}");
    println!(
        "linux-guest: expected fingerprint of `nginx -T` {}, digest of /www {}",
        expected.0, expected.1
    );
    println!("linux-guest: the raw files are in {}", out.display());
    if failures.is_empty() {
        println!(
            "linux-guest check passed: both guests boot, serve the same files with the same settings, and answer the Mac"
        );
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

/// `cargo xtask linux-guest build|run|check`.
pub fn command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("build") if args.len() == 1 => {
            let dir = build_guest()?;
            println!("linux-guest: built in {}", dir.display());
            Ok(())
        }
        Some("run") if args.len() == 1 => run_guest(),
        Some("check") if args.len() == 1 => check(),
        _ => Err("usage: cargo xtask linux-guest build|run|check".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "user nobody nobody;\nworker_processes 4;\nevents { use epoll; worker_connections 512; }\nhttp {\n    keepalive_requests 100000;\n    server {\n        listen 80 reuseport;\n    }\n}\n";
    const MIME: &[u8] = b"\ntypes {\n    text/html html;\n}\n";

    fn dump(conf: &str) -> String {
        format!(
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n{}",
            expected_config_output(conf, MIME)
        )
    }

    #[test]
    fn the_same_settings_give_one_fingerprint_whatever_nginx_says_around_them() {
        let a = config_digest(&dump(CONF));
        let b = config_digest(&expected_config_output(CONF, MIME));
        assert_eq!(a, b);
        // The console's carriage returns do not matter.
        assert_eq!(a, config_digest(&dump(CONF).replace('\n', "\r\n")));
    }

    #[test]
    fn one_changed_directive_changes_the_fingerprint() {
        // Breakage 1: the settings of one side differ.
        let linux = CONF.replace("keepalive_requests 100000", "keepalive_requests 100");
        assert_ne!(config_digest(&dump(CONF)), config_digest(&dump(&linux)));
        let mime = expected_config_output(CONF, b"\ntypes {\n    text/plain html;\n}\n");
        assert_ne!(config_digest(&dump(CONF)), config_digest(&mime));
    }

    #[test]
    fn the_allowed_differences_are_masked_and_only_they() {
        let one = CONF
            .replace("worker_processes 4", "worker_processes 1")
            .replace("user nobody nobody", "user www www")
            .replace("worker_connections 512", "worker_connections 1024")
            .replace(" reuseport", "");
        assert_eq!(config_digest(&dump(CONF)), config_digest(&dump(&one)));
        // A directive that only holds the name is no directive.
        assert_ne!(
            config_digest(&dump(CONF)),
            config_digest(&dump(
                &CONF.replace("keepalive_requests", "keepalive_users")
            ))
        );
        assert_eq!(
            mask_allowed("events { use epoll; worker_connections 512; accept_mutex off; }"),
            "events { use epoll; worker_connections <allowed>; accept_mutex off; }"
        );
        assert_eq!(mask_allowed("    sendfile off;"), "    sendfile off;");
        assert_eq!(mask_allowed("    listen 80 reuseport;"), "    listen 80;");
    }

    #[test]
    fn one_file_that_differs_changes_the_digest_of_www() {
        // Breakage 2.
        let a: Vec<(&str, &[u8])> = vec![("/www/1k.bin", b"abc"), ("/www/index.html", b"page")];
        let b: Vec<(&str, &[u8])> = vec![("/www/1k.bin", b"abd"), ("/www/index.html", b"page")];
        assert_ne!(www_digest(&a), www_digest(&b));
        assert_eq!(www_digest(&a), www_digest(&a));
        // A missing file changes it too.
        assert_ne!(www_digest(&a), www_digest(&a[..1]));
    }

    #[test]
    fn the_listing_of_openssl_gives_the_digest_the_sources_give() {
        let files: Vec<(&str, &[u8])> = vec![("/www/a", b"abc"), ("/www/b", b"")];
        let listing = |first: &str| {
            vec![
                format!("SHA2-256(/www/b)= {}", sha256_hex(b"")),
                "noise the shell printed".to_owned(),
                format!("SHA2-256(/www/a)= {first}"),
            ]
        };
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_hex(b"abc"), abc);
        assert_eq!(
            www_digest_of_listing(&listing(abc)).unwrap(),
            www_digest(&files)
        );
        // A different hash for one file, or no listing at all.
        assert_ne!(
            www_digest_of_listing(&listing(&sha256_hex(b"abd"))).unwrap(),
            www_digest(&files)
        );
        assert!(www_digest_of_listing(&["openssl: not found".to_owned()]).is_err());
    }

    fn v(nginx: &str, openssl: &str) -> Vec<String> {
        vec![
            format!("nginx version: nginx/{nginx}"),
            format!("built with OpenSSL {openssl}  30 Sep 2025"),
            "TLS SNI support enabled".to_owned(),
        ]
    }

    #[test]
    fn a_guest_with_another_nginx_or_openssl_is_refused() {
        // Breakage 3: the pin of Alpine 3.23.
        assert!(check_versions(&v("1.30.6", "3.5.9"), "1.30.6", "3.5.9").is_ok());
        let old = check_versions(&v("1.28.3", "3.5.9"), "1.30.6", "3.5.9").unwrap_err();
        assert!(old.contains("1.28.3"), "{old}");
        assert!(check_versions(&v("1.30.6", "3.5.4"), "1.30.6", "3.5.9").is_err());
        assert!(check_versions(&["nothing".to_owned()], "1.30.6", "3.5.9").is_err());
    }

    #[test]
    fn the_sources_of_both_guests_are_one_set_of_files() {
        let files = www_files();
        let paths: Vec<&str> = files.iter().map(|f| f.0).collect();
        assert_eq!(
            paths,
            [
                "/www/10k.bin",
                "/www/1k.bin",
                "/www/256k.bin",
                "/www/index.html"
            ]
        );
        let directory =
            std::env::temp_dir().join(format!("linux-guest-overlay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        write_overlay(&directory).unwrap();
        for (path, bytes) in &files {
            let written = std::fs::read(directory.join(path.trim_start_matches('/'))).unwrap();
            assert_eq!(&written[..], *bytes, "{path}");
        }
        assert_eq!(
            std::fs::read_to_string(directory.join("etc/nginx/nginx.conf")).unwrap(),
            nginx_conf()
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_image_of_the_measurement_starts_init_with_its_own_table() {
        assert_eq!(bench_programs()[0].0, "init");
        assert_eq!(bench_programs()[0].3, &["table-bench-vz"]);
        assert_eq!(net::vz_programs(false)[0].3, &["table-net-vz"]);
        assert_eq!(bench_programs().len(), net::vz_programs(false).len());
    }

    #[test]
    fn the_usage_is_refused_for_anything_else() {
        assert!(command(&[]).is_err());
        assert!(command(&["build".to_owned(), "x".to_owned()]).is_err());
        assert!(command(&["boot".to_owned()]).is_err());
    }
}
