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
/// The variants of the image for the profile of the network service
/// (`netd` built with the feature `profile`: it prints its totals when
/// `posix-net stat` asks): the shell's processes on all four CPUs, on CPUs 1
/// to 3, and every program on CPU 0.
pub const PROFILE_IMAGE: &str = "boot-net-bench-profile.img";
pub const PINNED_IMAGE: &str = "boot-net-bench-pinned.img";
pub const CPU0_IMAGE: &str = "boot-net-bench-cpu0.img";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchImage {
    Profile,
    Pinned,
    Cpu0,
}

/// The image of the row F1: nginx on the stack in its own process on the
/// second network device, the same one change of the CPUs
/// (`init::table::bench::BENCH_FAST_VZ_TABLE`).
pub const BENCH_FAST_IMAGE: &str = "boot-net-bench-fast.img";
/// The image of F1s: nginx-fast on the switch of the one device.
pub const BENCH_SWITCH_IMAGE: &str = "boot-net-bench-switch.img";
/// The second device's address in the image of F1 (the static address of
/// `netd.conf`: the NAT of VZ has no lease for a device that the stack owns).
pub const FAST_ADDRESS: &str = "192.168.64.250";
/// The machine of both guests (the provisional ruling B2 of the owner).
pub const CPUS: usize = 4;
pub const MEMORY_MIB: u64 = 1024;

/// The CPUs the shell of a variant of the image may use, which is what
/// `nproc` says there: `BENCH_CPUS` has four, `BENCH_PINNED_CPUS` three and
/// the image `cpu0` one (`init::table::bench`). The machine has `CPUS`
/// in each.
pub const fn shell_cpus(variant: BenchImage) -> usize {
    match variant {
        BenchImage::Profile => CPUS,
        BenchImage::Pinned => CPUS - 1,
        BenchImage::Cpu0 => 1,
    }
}
/// How long the guest of Linux takes to give its prompt, and nginx to
/// answer, after the start of the machine.
const LINUX_WITHIN: Duration = Duration::from_secs(60);
const ANSWER_WITHIN: Duration = Duration::from_secs(30);
/// The hashes of the files under `/www` by the guest's `openssl`.
const WWW_WITHIN: Duration = Duration::from_secs(120);

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

/// The programs of a variant: those of the network image of VZ with init's
/// table `table` and the network service with the profile's counters.
fn variant_programs(table: &'static [&'static str]) -> Vec<ImageProgram> {
    let mut programs = net::vz_programs(false).to_vec();
    for program in &mut programs {
        match program.0 {
            "init" => program.3 = table,
            "netd" => program.3 = &["profile"],
            _ => {}
        }
    }
    programs
}

/// The programs of a variant.
pub fn variant_list(variant: BenchImage) -> &'static [ImageProgram] {
    static LISTS: [std::sync::OnceLock<Vec<ImageProgram>>; 3] = [
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
        std::sync::OnceLock::new(),
    ];
    let (at, table): (usize, &'static [&'static str]) = match variant {
        BenchImage::Profile => (0, &["table-bench-vz"]),
        BenchImage::Pinned => (1, &["table-bench-pinned-vz"]),
        BenchImage::Cpu0 => (2, &["table-bench-cpu0-vz"]),
    };
    LISTS[at].get_or_init(|| variant_programs(table))
}

/// Builds a variant of the image of the measurement (a step of ci).
pub fn build_variant(variant: BenchImage) -> Result<PathBuf, String> {
    match variant {
        BenchImage::Profile => build_boot_image(PROFILE_IMAGE, variant_list(variant), BOOT_PROFILE),
        BenchImage::Pinned => build_boot_image(PINNED_IMAGE, variant_list(variant), BOOT_PROFILE),
        BenchImage::Cpu0 => build_boot_image(CPU0_IMAGE, variant_list(variant), BOOT_PROFILE),
    }
}

/// The programs of the image of F1: those of the image of nginx on the stack
/// on VZ with init's table of the measurement (`table-bench-fast-vz`).
pub fn bench_fast_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = crate::fast_nginx::programs(crate::fast_nginx::Kind::Vz).to_vec();
        for program in &mut programs {
            if program.0 == "init" {
                program.3 = &["table-bench-fast-vz"];
            }
        }
        programs
    })
}

/// The programs of the image of F1s: the switch image on VZ with init's table of the
/// measurement (`table-bench-fast-switch-vz`).
pub fn bench_switch_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = crate::fast_nginx::programs(crate::fast_nginx::Kind::SwitchVz).to_vec();
        for program in &mut programs {
            if program.0 == "init" {
                program.3 = &["table-bench-fast-switch-vz"];
            }
        }
        programs
    })
}

/// Builds the image of the measurement (a step of ci, which can run
/// neither HVF nor VZ).
pub fn build_image() -> Result<PathBuf, String> {
    crate::probe_ca::ensure(false)?;
    build_boot_image(BENCH_IMAGE, bench_programs(), BOOT_PROFILE)
}

/// Builds the image of F1.
pub fn build_fast_image() -> Result<PathBuf, String> {
    crate::probe_ca::ensure(false)?;
    build_boot_image(BENCH_FAST_IMAGE, bench_fast_programs(), BOOT_PROFILE)
}

/// Builds the image of F1s.
pub fn build_switch_image() -> Result<PathBuf, String> {
    crate::probe_ca::ensure(false)?;
    build_boot_image(BENCH_SWITCH_IMAGE, bench_switch_programs(), BOOT_PROFILE)
}

/// The programs of the image of F1s with the counters of the network service (`netd` built
/// with the feature `profile`), written to the file of the image of F1s.
pub fn bench_switch_profile_programs() -> &'static [ImageProgram] {
    static LIST: std::sync::OnceLock<Vec<ImageProgram>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut programs = bench_switch_programs().to_vec();
        for program in &mut programs {
            if program.0 == "netd" {
                program.3 = &["profile"];
            }
        }
        programs
    })
}

/// Builds the image of F1s with the profile (the same file as `build_switch_image`).
pub fn build_switch_profile_image() -> Result<PathBuf, String> {
    crate::probe_ca::ensure(false)?;
    build_boot_image(
        BENCH_SWITCH_IMAGE,
        bench_switch_profile_programs(),
        BOOT_PROFILE,
    )
}

// What both guests carry -------------------------------------------------------

/// The files of the load of the measurement: W1, 900 files of 10 KiB under
/// `/www/s/` (a ladder asks for them in turn), and W2, 64 files of 256 KiB under
/// `/www/l/`. Their bytes come from fixed seeds, so both guests carry the same.
/// 900 files and 64 connections stay under the 1 024 descriptors a process has on both
/// systems, with the descriptors nginx keeps besides them (stafeto-design#578).
pub const W1_FILES: usize = 900;
pub const W1_LEN: usize = 10 * 1024;
pub const W2_FILES: usize = 64;
pub const W2_LEN: usize = 256 * 1024;

fn sets() -> &'static [(&'static str, Vec<u8>)] {
    static SETS: std::sync::OnceLock<Vec<(&'static str, Vec<u8>)>> = std::sync::OnceLock::new();
    SETS.get_or_init(|| {
        let mut files = Vec::new();
        let mut add = |path: String, seed: u64, len: usize| {
            let path: &'static str = Box::leak(path.into_boxed_str());
            files.push((path, nginx_probe::noise(seed, len)));
        };
        for n in 0..W1_FILES {
            add(
                format!("/www/s/{n:04}.bin"),
                0x3c6e_f372_fe94_f82b ^ n as u64,
                W1_LEN,
            );
        }
        for n in 0..W2_FILES {
            add(
                format!("/www/l/{n:02}.bin"),
                0xa54f_f53a_5f1d_36f1 ^ n as u64,
                W2_LEN,
            );
        }
        files
    })
}

/// The files under `/www` both guests carry, by their paths in the guest, in
/// the order of the paths: the page of the images with the network, the three
/// files of the first measurements and the sets W1 and W2. One source:
/// stafeto's image takes them from `rootfs`, the Linux guest from the overlay
/// made here.
pub fn www_files() -> Vec<(&'static str, &'static [u8])> {
    let mut files: Vec<(&'static str, &'static [u8])> = vec![
        ("/www/index.html", crate::rootfs::www_index()),
        ("/www/1k.bin", crate::nginx_bench::www_1k()),
        ("/www/10k.bin", nginx_probe::www_10k()),
        ("/www/256k.bin", nginx_probe::www_256k()),
    ];
    files.extend(sets().iter().map(|(path, bytes)| (*path, bytes.as_slice())));
    files.sort_by(|a, b| a.0.cmp(b.0));
    files
}

/// The files the Mac fetches over HTTP: every file under `/www`. nginx keeps each file it
/// served open (`open_file_cache max=1000`), and the RAM service lets a client hold 1 056
/// numbers (`services/ramfs`), so a worker that has served all of W1 holds 900 files and
/// answers the next request: the fetch is the check that none is refused with
/// "Too many open files". The guests also give the hashes of every file under `/www`
/// (`read_fingerprints`).
pub fn fetched_files() -> Vec<(&'static str, &'static [u8])> {
    www_files()
}

/// The settings of nginx in both guests.
pub fn nginx_conf() -> &'static str {
    nginx_probe::NGINX_CONF
}

/// The settings of nginx on the stack (F1): its own file, which differs from
/// `nginx_conf` in the directives of the allowed list, in the types written
/// in the file, and in the path of the pid file.
pub fn nginx_fast_conf() -> &'static str {
    crate::fast_nginx::root_conf()
}

/// The path of the settings with the server of TLS in the guests of Linux
/// and in S4, and in F1.
pub const TLS_CONF: &str = "/etc/nginx/nginx-tls.conf";
pub const FAST_TLS_CONF: &str = "/etc/nginx/nginx-fast-tls.conf";

/// `conf` with the server of TLS (`tls.conf`) included before its server of
/// HTTP, the one change W4 and W5 make: the same `http` block, the same
/// listener on port 80, and the listener of TLS 1.3 and HTTP/2 on 443.
pub fn with_tls(conf: &str) -> String {
    nginx_probe::replaced(
        conf,
        "    server {\n",
        &format!(
            "    include {};\n    server {{\n",
            nginx_probe::TLS_CONF_PATH
        ),
    )
}

/// The settings of nginx of the guests of Linux and S4 for W4 and W5.
pub fn nginx_tls_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| with_tls(nginx_conf()))
}

/// The settings of F1 for W4 and W5.
pub fn nginx_fast_tls_conf() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| with_tls(nginx_fast_conf()))
}

/// What `nginx -T -c PATH` prints: each file of `parts` (its path and its
/// bytes) after the line that names it, in the order nginx reads them.
pub fn expected_dump(parts: &[(&str, &str)]) -> String {
    parts
        .iter()
        .map(|(path, text)| format!("# configuration file {path}:\n{text}\n"))
        .collect()
}

/// The dump of the settings with TLS: for the rows with `nginx.conf` (the
/// types before the server of TLS) and for F1.
pub fn expected_tls_dump(fast: bool, mime: &[u8]) -> String {
    let (path, conf) = if fast {
        (FAST_TLS_CONF, nginx_fast_tls_conf())
    } else {
        (TLS_CONF, nginx_tls_conf())
    };
    let mime = String::from_utf8_lossy(mime);
    let mut parts = vec![(path, conf)];
    if !fast {
        parts.push(("/etc/nginx/mime.types", mime.as_ref()));
    }
    parts.push((nginx_probe::TLS_CONF_PATH, nginx_probe::TLS_CONF));
    expected_dump(&parts)
}

/// Writes the overlay of the Linux guest into the empty `dir`: the settings
/// of nginx, its `mime.types` (the file of the nginx source that stafeto's image
/// carries) and the files under `/www`.
pub fn write_overlay(dir: &Path, mime: &[u8]) -> Result<(), String> {
    let put = |path: &str, bytes: &[u8]| -> Result<(), String> {
        let target = dir.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(target.parent().expect("a path has a parent"))
            .and_then(|()| std::fs::write(&target, bytes))
            .map_err(|e| format!("{}: {e}", target.display()))
    };
    put("/etc/nginx/nginx.conf", nginx_conf().as_bytes())?;
    put("/etc/nginx/mime.types", mime)?;
    // W4 and W5: the same settings with the server of TLS, and the key and
    // the certificate of the probe CA.
    put(TLS_CONF, nginx_tls_conf().as_bytes())?;
    put(nginx_probe::TLS_CONF_PATH, nginx_probe::TLS_CONF.as_bytes())?;
    put(
        nginx_probe::SERVER_CRT,
        crate::probe_ca::nginx_certificate(),
    )?;
    put(nginx_probe::SERVER_KEY, crate::probe_ca::nginx_key())?;
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

/// What `nginx-fast -T` prints for the settings of F1: the one file.
pub fn expected_fast_config_output(conf: &str) -> String {
    format!("# configuration file /etc/nginx/nginx-fast.conf:\n{conf}\n")
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

/// The paths and hashes of the listing of `openssl dgst -sha256`.
fn listing_pairs(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|line| {
            let (head, hash) = line.trim().split_once(")= ")?;
            let (_, path) = head.split_once('(')?;
            Some((path.to_owned(), hash.trim().to_owned()))
        })
        .collect()
}

/// What differs between the files a guest listed and the files of the sources:
/// a file that is missing, a file that is extra, a file with other bytes.
pub fn www_difference(lines: &[String], files: &[(&str, &[u8])]) -> Vec<String> {
    let listed = listing_pairs(lines);
    let mut out = Vec::new();
    for (path, bytes) in files {
        match listed.iter().find(|(p, _)| p == path) {
            None => out.push(format!("missing {path}")),
            Some((_, hash)) if *hash != sha256_hex(bytes) => out.push(format!("changed {path}")),
            Some(_) => {}
        }
    }
    for (path, _) in &listed {
        if !files.iter().any(|(p, _)| p == path) {
            out.push(format!("extra {path}"));
        }
    }
    out
}

/// The tokens of the `configure arguments:` lines of two builds of nginx that
/// only one of them has: `- ` for the first, `+ ` for the second.
pub fn configure_difference(first: &[String], second: &[String]) -> Vec<String> {
    let words = |lines: &[String]| -> Vec<String> {
        lines
            .iter()
            .find_map(|l| l.trim().strip_prefix("configure arguments:"))
            .map(|rest| rest.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    };
    let (a, b) = (words(first), words(second));
    let mut out: Vec<String> = a
        .iter()
        .filter(|w| !b.contains(w))
        .map(|w| format!("- {w}"))
        .collect();
    out.extend(
        b.iter()
            .filter(|w| !a.contains(w))
            .map(|w| format!("+ {w}")),
    );
    out
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
    if lines.iter().any(|l| l.contains("running with OpenSSL")) {
        return Err(format!(
            "the library the guest's nginx runs with is not the one it was built with: {lines:?}"
        ));
    }
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
pub(crate) struct Report {
    pub(crate) system: &'static str,
    pub(crate) address: Option<Ipv4Addr>,
    pub(crate) mac: String,
    /// From the start of `vz-run` to the prompt of the shell; from the moment
    /// the four workers of nginx are on the console and the shell answers to
    /// the first answer of nginx on the Mac. The same on both guests, a check
    /// of liveness that is no part of the measurement.
    pub(crate) prompt: Duration,
    pub(crate) answer: Duration,
    /// Every attempt to get the first answer: when and how it ended.
    pub(crate) attempts: Vec<String>,
    /// The Mac's load average and the other machines of VZ and QEMU on it,
    /// before the guest starts and after its last answer: no quiet Mac is
    /// asked for, the conditions are recorded.
    pub(crate) conditions: Vec<String>,
    /// The kernel's settings (`sysctl -a`), where the guest is Linux.
    pub(crate) sysctl: Vec<String>,
    pub(crate) cpus: String,
    pub(crate) nginx: String,
    pub(crate) openssl: String,
    pub(crate) nginx_v: Vec<String>,
    pub(crate) config_digest: String,
    pub(crate) www_digest: String,
    pub(crate) features: String,
    pub(crate) served: usize,
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

/// Waits until the console shows the four workers of nginx.
pub(crate) fn workers_up(
    run: &mut qemu::Run,
    within: Duration,
    count: usize,
) -> Result<(), String> {
    let deadline = Instant::now() + within;
    loop {
        let seen = run
            .lines()
            .iter()
            .filter(|l| l.contains("start worker process "))
            .count();
        if seen >= count {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("{seen} of {count} workers of nginx on the console"));
        }
        // Takes in the console's output for a moment.
        let _ = run.expect_seen("\u{0}pump", Duration::from_millis(100));
    }
}

/// The digests and versions the console of a guest gives, once its shell
/// answers: `nginx -V`, `nginx -T`, the hashes of `find /www -type f` and the
/// number of CPUs, checked against what stafeto's sources say; on Linux the
/// kernel's settings too.
pub(crate) fn read_fingerprints(
    run: &mut qemu::Run,
    report: &mut Report,
    kernel_settings: bool,
    cpus: usize,
) -> Result<(), String> {
    read_fingerprints_of(run, report, kernel_settings, cpus, "nginx", "nginx -T")
}

/// The same for a program of nginx other than `nginx`: `program` for the
/// versions, `dump` the command that prints its settings (`nginx-fast -T -c
/// FILE` for F1, whose settings are its own file).
pub(crate) fn read_fingerprints_of(
    run: &mut qemu::Run,
    report: &mut Report,
    kernel_settings: bool,
    cpus: usize,
    program: &str,
    dump: &str,
) -> Result<(), String> {
    run.send("S=ok")?;
    run.expect("# ", DIALOG_STEP)?;
    report.cpus = capture(run, "nproc", "nproc", DIALOG_STEP)?
        .iter()
        .find(|l| l.trim().parse::<usize>().is_ok())
        .map(|l| l.trim().to_owned())
        .unwrap_or_default();
    if report.cpus != cpus.to_string() {
        return Err(format!(
            "{}: nproc says {:?}, {cpus} wanted",
            report.system, report.cpus
        ));
    }
    report.nginx_v = capture(run, &format!("{program} -V 2>&1"), "version", DIALOG_STEP)?;
    let (nginx, openssl) = check_versions(
        &report.nginx_v,
        &crate::packages::value("nginx", "version")?,
        &crate::packages::value("openssl", "version")?,
    )
    .map_err(|e| format!("{}: {e}", report.system))?;
    report.nginx = nginx;
    report.openssl = openssl;
    let dump = capture(run, &format!("{dump} 2>&1"), "config", DIALOG_STEP)?.join("\n");
    report.config_digest = config_digest(&dump);
    let www = capture(
        run,
        "openssl dgst -sha256 $(find /www -type f)",
        "www",
        WWW_WITHIN,
    )?;
    let different = www_difference(&www, &www_files());
    if !different.is_empty() {
        return Err(format!(
            "{}: the files under /www differ from the sources: {}{}",
            report.system,
            different
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            if different.len() > 5 { ", ..." } else { "" }
        ));
    }
    report.www_digest = www_digest_of_listing(&www)
        .map_err(|e| format!("{}: the digest of /www: {e}", report.system))?;
    if kernel_settings {
        report.sysctl = capture(run, "sysctl -a 2>/dev/null", "sysctl", WWW_WITHIN)?;
    }
    Ok(())
}

/// The fingerprints a guest must show, from stafeto's sources.
pub(crate) fn expected() -> Result<(String, String), String> {
    let mime = nginx_probe::mime_types();
    if mime.is_empty() {
        return Err("nginx's mime.types is missing: run tools/build-nginx.py".to_owned());
    }
    Ok((
        config_digest(&expected_config_output(nginx_conf(), mime)),
        www_digest(&www_files()),
    ))
}

/// The fingerprints of the settings with TLS: for the rows with `nginx.conf`
/// and for F1.
pub(crate) fn expected_tls() -> Result<(String, String), String> {
    let mime = nginx_probe::mime_types();
    if mime.is_empty() {
        return Err("nginx's mime.types is missing: run tools/build-nginx.py".to_owned());
    }
    Ok((
        config_digest(&expected_tls_dump(false, mime)),
        config_digest(&expected_tls_dump(true, mime)),
    ))
}

/// The fingerprints of F1: the settings are its own file (`nginx-fast.conf`),
/// the files under `/www` are those of the other rows.
pub(crate) fn expected_fast() -> (String, String) {
    (
        config_digest(&expected_fast_config_output(nginx_fast_conf())),
        www_digest(&www_files()),
    )
}

/// The fingerprint of the settings of F1s (the package's file, the worker as nobody).
pub(crate) fn expected_switch() -> String {
    config_digest(&expected_fast_config_output(
        crate::fast_nginx::NGINX_FAST_CONF,
    ))
}

/// Refuses a guest whose fingerprints are not the expected ones.
pub(crate) fn verify(report: &Report, config: &str, www: &str) -> Result<(), String> {
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
/// the sources. The first answer is waited for up to `ANSWER_WITHIN` from
/// `from` (the moment the workers of nginx and the shell are up); each attempt
/// is noted with its time and the kind of its end. Gives the time of the first
/// answer, the attempts and the number of files served.
fn fetch_all(address: SocketAddr, from: Instant) -> Result<(Duration, Vec<String>, usize), String> {
    let mut attempts = Vec::new();
    let first = loop {
        let at = from.elapsed();
        let answer = Connection::open(address, Duration::from_secs(2))
            .and_then(|mut c| c.get("/index.html"));
        match answer {
            Ok(_) => {
                attempts.push(format!("{} ms: answered", at.as_millis()));
                break from.elapsed();
            }
            Err(why) if from.elapsed() < ANSWER_WITHIN => {
                let kind = if why.contains("timed out") {
                    "timeout"
                } else {
                    "failure"
                };
                attempts.push(format!("{} ms: {kind}: {why}", at.as_millis()));
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(why) => return Err(format!("the first request: {why}")),
        }
    };
    let mut served = 0;
    for (path, bytes) in fetched_files() {
        let url = path.trim_start_matches("/www");
        let body = Connection::open(address, Duration::from_secs(10))
            .and_then(|mut c| c.get(url))
            .map_err(|e| format!("GET {url}: {e}"))?;
        nginx_probe::same(&format!("GET {url}"), &body, bytes)?;
        served += 1;
    }
    Ok((first, attempts, served))
}

/// The machine of both guests, with the MAC suffix of the run.
pub(crate) fn machine(suffix: &vz::Suffix) -> vz::Machine {
    machine_with(suffix, 1)
}

/// The same with `net` network devices (two for F1).
pub(crate) fn machine_with(suffix: &vz::Suffix, net: usize) -> vz::Machine {
    vz::Machine {
        cpus: Some(CPUS),
        memory_mib: Some(MEMORY_MIB),
        net,
        mac_suffix: suffix.value,
    }
}

pub(crate) fn linux_dir() -> PathBuf {
    target_dir().join("linux-guest")
}

/// `cargo xtask linux-guest build`.
pub fn build_guest() -> Result<PathBuf, String> {
    // The overlay carries the key and the certificate of the probe CA (W4, W5).
    crate::probe_ca::ensure(false)?;
    // The overlay takes `mime.types` of the nginx source, which the build of
    // the network packages unpacks.
    crate::relibc()?;
    crate::net_build()?;
    let dir = linux_dir();
    let overlay = dir.join("overlay");
    let _ = std::fs::remove_dir_all(&overlay);
    std::fs::create_dir_all(&overlay).map_err(|e| format!("{}: {e}", overlay.display()))?;
    let mime = nginx_probe::mime_types();
    if mime.is_empty() {
        return Err("nginx's mime.types is missing: run tools/build-nginx.py".to_owned());
    }
    write_overlay(&overlay, mime)?;
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
pub(crate) fn linux_command(dir: &Path, suffix: &vz::Suffix) -> Result<Command, String> {
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

/// `cargo xtask linux-guest run stafeto`: the shell of stafeto's image of the
/// measurement on the terminal (nginx is started by hand, as `check` does).
fn run_stafeto() -> Result<(), String> {
    crate::relibc()?;
    crate::busybox_build()?;
    crate::nano_build()?;
    crate::net_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_image()?;
    let suffix = vz::claim_suffix()?;
    println!("linux-guest: MAC suffix {}", suffix.value);
    let status = vz::command_on(&kernel.image, &image, machine(&suffix))?
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
    report.conditions.push(format!(
        "before the start: {}",
        crate::nginx_bench::other_guests(0)
    ));
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
        workers_up(&mut run, DIALOG_STEP, 4)?;
        let (first, attempts, served) = fetch_all((address, 80).into(), Instant::now())?;
        report.answer = first;
        report.attempts = attempts;
        report.served = served;
        net_vz::lease_is_ours("linux-guest", &own, address)?;
        read_fingerprints(&mut run, &mut report, true, CPUS)?;
        report.conditions.push(format!(
            "at the end: {}",
            crate::nginx_bench::other_guests(1)
        ));
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
    report.conditions.push(format!(
        "before the start: {}",
        crate::nginx_bench::other_guests(0)
    ));
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
        workers_up(&mut run, DIALOG_STEP, 4)?;
        let (first, attempts, served) = fetch_all((lease.address, 80).into(), Instant::now())?;
        report.answer = first;
        report.attempts = attempts;
        report.served = served;
        net_vz::lease_is_ours("stafeto", &own, lease.address)?;
        read_fingerprints(&mut run, &mut report, false, CPUS)?;
        report.conditions.push(format!(
            "at the end: {}",
            crate::nginx_bench::other_guests(1)
        ));
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
        "| system | address | MAC | spawn to prompt | workers up to first answer (liveness, no part of the measurement) | versions | `nginx -T` | `/www` | files served |\n|---|---|---|---|---|---|---|---|---|\n",
    );
    let mut failures = Vec::new();
    let configure = configure_difference(&guests[0].1.report.nginx_v, &guests[1].1.report.nginx_v);
    let mut raw = Vec::new();
    for (name, guest) in &guests {
        raw.extend(
            guest
                .report
                .nginx_v
                .iter()
                .filter(|l| l.trim().starts_with("configure arguments:"))
                .map(|l| format!("{name}: {}", l.trim())),
        );
    }
    raw.push("difference (- linux, + stafeto):".to_owned());
    raw.extend(configure);
    save("configure-arguments.txt", &raw);
    for (name, guest) in guests {
        save(&format!("{name}-console.log"), &guest.lines);
        save(&format!("{name}-nginx-v.txt"), &guest.report.nginx_v);
        save(&format!("{name}-first-answer.txt"), &guest.report.attempts);
        save(&format!("{name}-conditions.txt"), &guest.report.conditions);
        if !guest.report.sysctl.is_empty() {
            save(&format!("{name}-sysctl.txt"), &guest.report.sysctl);
        }
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
        Some("run") if args.len() == 2 && args[1] == "stafeto" => run_stafeto(),
        Some("check") if args.len() == 1 => check(),
        _ => Err("usage: cargo xtask linux-guest build|run [stafeto]|check".to_owned()),
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
        assert_eq!(paths.len(), 4 + W1_FILES + W2_FILES);
        // The check takes every file by HTTP: the files fetched are all the files carried.
        assert_eq!(fetched_files().len(), paths.len());
        assert_eq!(fetched_files().len(), 4 + 900 + 64);
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
        assert!(paths.contains(&"/www/index.html"));
        assert!(paths.contains(&"/www/s/0899.bin") && paths.contains(&"/www/l/63.bin"));
        assert!(!paths.contains(&"/www/s/0900.bin"));
        let length = |path: &str| files.iter().find(|f| f.0 == path).unwrap().1.len();
        assert_eq!(length("/www/s/0000.bin"), W1_LEN);
        assert_eq!(length("/www/l/00.bin"), W2_LEN);
        assert_ne!(
            files.iter().find(|f| f.0 == "/www/s/0000.bin").unwrap().1,
            files.iter().find(|f| f.0 == "/www/s/0001.bin").unwrap().1
        );
        let directory =
            std::env::temp_dir().join(format!("linux-guest-overlay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        write_overlay(&directory, b"types {}\n").unwrap();
        for (path, bytes) in &files {
            let written = std::fs::read(directory.join(path.trim_start_matches('/'))).unwrap();
            assert_eq!(&written[..], *bytes, "{path}");
        }
        assert_eq!(
            std::fs::read_to_string(directory.join("etc/nginx/nginx.conf")).unwrap(),
            nginx_conf()
        );
        assert_eq!(
            std::fs::read(directory.join("etc/nginx/mime.types")).unwrap(),
            b"types {}\n"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_library_the_guest_runs_with_is_refused() {
        // Breakage 3, the second half: built with the right OpenSSL and run
        // with another.
        let mut lines = v("1.30.6", "3.5.9");
        assert!(check_versions(&lines, "1.30.6", "3.5.9").is_ok());
        lines.push(
            "running with OpenSSL 3.5.4  30 Sep 2025 (running with OpenSSL 3.5.4)".to_owned(),
        );
        let refused = check_versions(&lines, "1.30.6", "3.5.9").unwrap_err();
        assert!(refused.contains("runs with"), "{refused}");
    }

    #[test]
    fn a_file_of_the_listing_that_is_missing_extra_or_changed_is_named() {
        let files: Vec<(&str, &[u8])> = vec![("/www/a", b"abc"), ("/www/s/1", b"")];
        let line = |p: &str, b: &[u8]| format!("SHA2-256({p})= {}", sha256_hex(b));
        let good = vec![line("/www/s/1", b""), line("/www/a", b"abc")];
        assert!(www_difference(&good, &files).is_empty());
        let missing = vec![line("/www/a", b"abc")];
        assert_eq!(www_difference(&missing, &files), ["missing /www/s/1"]);
        let extra = vec![good[0].clone(), good[1].clone(), line("/www/no-dot", b"x")];
        assert_eq!(www_difference(&extra, &files), ["extra /www/no-dot"]);
        let changed = vec![good[0].clone(), line("/www/a", b"abd")];
        assert_eq!(www_difference(&changed, &files), ["changed /www/a"]);
    }

    #[test]
    fn the_difference_of_the_configure_arguments_names_what_one_side_has() {
        let linux = vec![
            "configure arguments: --with-threads --with-http_ssl_module --with-compat".to_owned(),
        ];
        let stafeto = vec![
            "configure arguments: --with-http_ssl_module --without-http_gzip_module".to_owned(),
        ];
        assert_eq!(
            configure_difference(&linux, &stafeto),
            [
                "- --with-threads",
                "- --with-compat",
                "+ --without-http_gzip_module"
            ]
        );
        assert!(configure_difference(&linux, &linux).is_empty());
    }

    #[test]
    fn the_image_of_f1_starts_init_with_its_own_table_and_holds_nginx_fast() {
        let programs = bench_fast_programs();
        assert_eq!(programs[0].0, "init");
        assert_eq!(programs[0].3, &["table-bench-fast-vz"]);
        assert!(programs.iter().any(|p| p.0 == "nginx-fast"));
        assert_eq!(
            programs.len(),
            crate::fast_nginx::programs(crate::fast_nginx::Kind::Vz).len()
        );
        // The row F1 is the only image of the measurement with two devices,
        // and its address is the static one of its `netd.conf`.
        assert!(
            crate::fast_probe::NETD_CONF_VZ_STATIC
                .windows(FAST_ADDRESS.len())
                .any(|w| w == FAST_ADDRESS.as_bytes())
        );
    }

    /// Everything of the settings of F1 that the other rows do not have is
    /// listed: the directives of the allowed list, the types written in the
    /// file, the path of the pid file and the one port. The `http` block of
    /// the two files is otherwise the same line for line (breakage 1 of the note).
    #[test]
    fn the_settings_of_f1_differ_from_the_others_in_the_listed_lines_alone() {
        let lines = |text: &str| -> Vec<String> {
            text.lines()
                .map(|l| mask_allowed(l.trim()))
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        };
        let (fast, plain) = (lines(nginx_fast_conf()), lines(nginx_conf()));
        let only_fast: Vec<_> = fast.iter().filter(|l| !plain.contains(l)).collect();
        let only_plain: Vec<_> = plain.iter().filter(|l| !fast.contains(l)).collect();
        assert_eq!(
            only_fast,
            [
                "pid /var/run/nginx-fast.pid;",
                "worker_shutdown_timeout <allowed>;",
                "types { text/html html htm; text/plain txt; application/octet-stream bin; }",
            ],
            "{only_fast:?}"
        );
        assert_eq!(
            only_plain,
            ["pid /var/run/nginx.pid;", "include /etc/nginx/mime.types;"],
            "{only_plain:?}"
        );
    }

    #[test]
    fn the_fingerprint_of_f1_is_that_of_its_own_file() {
        let (config, www) = expected_fast();
        assert_ne!(config, expected().map(|e| e.0).unwrap_or_default());
        assert_eq!(www, www_digest(&www_files()));
        // A change in a directive of the http block changes it.
        let changed =
            nginx_fast_conf().replace("keepalive_requests 100000", "keepalive_requests 100");
        assert_ne!(
            config_digest(&expected_fast_config_output(&changed)),
            config
        );
        // The allowed directives do not.
        let workers =
            nginx_fast_conf().replace("worker_connections 1024", "worker_connections 512");
        assert_eq!(
            config_digest(&expected_fast_config_output(&workers)),
            config
        );
    }

    /// W4 and W5 change one thing in the settings of the rows: the server
    /// of TLS, included before the server of HTTP. Every line of the plain
    /// settings is still there, in its place.
    #[test]
    fn the_settings_with_tls_add_the_include_and_change_nothing_else() {
        for (plain, tls) in [
            (nginx_conf(), nginx_tls_conf()),
            (nginx_fast_conf(), nginx_fast_tls_conf()),
        ] {
            let added: Vec<&str> = tls
                .lines()
                .filter(|l| !plain.lines().any(|p| p == *l))
                .collect();
            assert_eq!(added, ["    include /etc/nginx/tls.conf;"]);
            assert_eq!(tls.lines().count(), plain.lines().count() + 1);
            assert!(tls.contains("    include /etc/nginx/tls.conf;\n    server {\n"));
        }
        assert!(nginx_probe::TLS_CONF.contains("listen 443 ssl"));
        assert!(nginx_probe::TLS_CONF.contains("ssl_protocols TLSv1.3;"));
    }

    #[test]
    fn the_dump_with_tls_names_the_files_in_the_order_nginx_reads_them() {
        let plain = expected_tls_dump(false, b"types {}\n");
        let paths: Vec<&str> = plain
            .lines()
            .filter(|l| l.starts_with("# configuration file "))
            .collect();
        assert_eq!(
            paths,
            [
                "# configuration file /etc/nginx/nginx-tls.conf:",
                "# configuration file /etc/nginx/mime.types:",
                "# configuration file /etc/nginx/tls.conf:"
            ]
        );
        let fast = expected_tls_dump(true, b"types {}\n");
        assert!(fast.starts_with("# configuration file /etc/nginx/nginx-fast-tls.conf:"));
        assert!(!fast.contains("mime.types"));
        // A guest whose server of TLS differs from the file of the sources
        // has another fingerprint.
        let changed = fast.replace("ssl_protocols TLSv1.3;", "ssl_protocols TLSv1.2 TLSv1.3;");
        assert_ne!(config_digest(&changed), config_digest(&fast));
    }

    #[test]
    fn the_image_of_the_measurement_starts_init_with_its_own_table() {
        assert_eq!(bench_programs()[0].0, "init");
        assert_eq!(bench_programs()[0].3, &["table-bench-vz"]);
        assert_eq!(net::vz_programs(false)[0].3, &["table-net-vz"]);
        assert_eq!(bench_programs().len(), net::vz_programs(false).len());
    }

    #[test]
    fn the_variants_of_the_image_differ_in_the_table_and_the_profile_alone() {
        let plain = net::vz_programs(false);
        for (programs, table) in [
            (variant_list(BenchImage::Profile), "table-bench-vz"),
            (variant_list(BenchImage::Pinned), "table-bench-pinned-vz"),
            (variant_list(BenchImage::Cpu0), "table-bench-cpu0-vz"),
        ] {
            assert_eq!(programs.len(), plain.len());
            for (variant, base) in programs.iter().zip(plain) {
                match variant.0 {
                    "init" => assert_eq!(variant.3, &[table]),
                    "netd" => assert_eq!(variant.3, &["profile"]),
                    _ => assert_eq!(variant, base),
                }
            }
        }
        assert!(!bench_programs().iter().any(|p| p.3.contains(&"profile")));
    }

    /// `nproc` in the shell of a variant counts the CPUs of the launcher's
    /// mask in the table of the image.
    #[test]
    fn the_cpus_nproc_wants_are_those_of_the_shells_mask_in_the_table() {
        use init::table::{bench, net};
        let of = |table: &[init::table::Record]| {
            let launcher = table.iter().find(|r| r.name == net::NET_LAUNCHER.name);
            let mask = launcher.unwrap().cpus & ((1u8 << CPUS) - 1);
            mask.count_ones() as usize
        };
        assert_eq!(shell_cpus(BenchImage::Profile), of(bench::BENCH_VZ_TABLE));
        assert_eq!(
            shell_cpus(BenchImage::Pinned),
            of(bench::BENCH_PINNED_VZ_TABLE)
        );
        assert_eq!(shell_cpus(BenchImage::Cpu0), of(bench::BENCH_CPU0_VZ_TABLE));
    }

    #[test]
    fn the_usage_is_refused_for_anything_else() {
        assert!(command(&[]).is_err());
        assert!(command(&["build".to_owned(), "x".to_owned()]).is_err());
        assert!(command(&["boot".to_owned()]).is_err());
    }
}
