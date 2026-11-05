// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask pkg-probe [install] [--hvf]`: the package tool in the guest (sub-project 5, part 4a;
//! pk4-design R16, R17). The image (`boot-pkg-probe.img`) is the base image with the certificate
//! file of the probe CA and the mirror of the probe as its official repository,
//! `https://10.0.2.2:8443/<series>/aarch64`, trusting the roots of the development keys. xtask
//! starts the mirror (`tools/pkg-mirror.py`, a Python `http.server` with TLS and the certificate
//! `host-a` of the probe CA) for the length of the run and ends it with the run: no process
//! outlives the command. The disk of the guest is new for each run.
//!
//! The mirror serves `www/<series>/aarch64`, a link to the directory of a state of the repository
//! (`target/pkg-probe/states/<name>`), which xtask changes between steps. This part has one state,
//! `good` (serial 2: Doom and its WAD), and the steps that need it:
//!
//! 1. `pkg check`: the roots the build trusts (those of `pkgd: roots`), no package on the disk,
//!    the packages of the image.
//! 2. `pkg list` lists the image alone, and its lines go through a pipe (`| wc -l`).
//! 3. `pkg install doom`: the lines of the note, exit 0, no `curl` left (no zombie).
//! 4. `pkg list`: Doom and its WAD, the WAD as a dependency.
//! 5. The demo `timed N gametics`, exit 255 (spec 5, acceptance 2).
//! 6. `pkg info doom` and `pkg search doom`.
//! 7. `pkg update`: `serial 2, was 2`.
//! 8. `pkg install doom` again: "is installed", and no package was downloaded (the log of the mirror).

use crate::net_tls::{capture, coded};
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, STORE_BYTES, Variant, base_image,
    build, keys, packages, pkg, probe_ca, qemu, repo, root, symbolize, target_dir,
};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const IMAGE: &str = "boot-pkg-probe.img";
/// The port of the mirror, in `/etc/pkg/official` of the image.
const PORT: u16 = 8443;
/// The whole run of the probe may take this long on TCG (spec 5, section 9).
const WITHIN: Duration = Duration::from_secs(300);
/// One command of the dialog, the installation of Doom with its download.
const INSTALL_WITHIN: Duration = Duration::from_secs(240);
const DEMO_WITHIN: Duration = Duration::from_secs(300);
/// The files of Doom's packages that the demo needs.
const WAD: &str = "/games/freedoom1.wad";
/// The names of the packages of Doom.
const DOOM: [&str; 2] = ["doomgeneric", "freedoom"];
/// The serial of the state `good`.
const GOOD_SERIAL: u64 = 2;

/// `https://10.0.2.2:8443/<series>/aarch64`: the host as the guest of QEMU's user network sees it.
pub fn official_address() -> String {
    format!("https://10.0.2.2:{PORT}/{}/aarch64", pkg::series())
}

/// The bytes of `/etc/pkg/keys/stafeto.pub` of the image: the roots `pkg` and `pkgd` of the image
/// trust, the development root (`STAFETO_PKG_ROOTS` names the same file for their build).
pub fn roots_file() -> Vec<u8> {
    std::fs::read(roots_path()).unwrap_or_default()
}

fn roots_path() -> PathBuf {
    root().join("target/keys/stafeto-dev-root.pub")
}

/// A line of the log of the mirror with the time it came.
type Log = Arc<Mutex<Vec<(Instant, String)>>>;

/// The mirror: a child process whose output is read by a thread into the log. It ends with the value.
struct Mirror {
    child: Child,
    log: Log,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Mirror {
    fn start(
        directory: &Path,
        port: u16,
        certificate: &Path,
        key: &Path,
    ) -> Result<Mirror, String> {
        // A port that is taken stops the probe with a line that names it: the port is in the image.
        drop(
            TcpListener::bind(("127.0.0.1", port))
                .map_err(|_| format!("pkg-probe: port {port} is taken"))?,
        );
        let mut child = Command::new("python3")
            .arg(root().join("tools/pkg-mirror.py"))
            .arg("--dir")
            .arg(directory)
            .args(["--port", &port.to_string()])
            .arg("--cert")
            .arg(certificate)
            .arg("--key")
            .arg(key)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("python3 (tools/pkg-mirror.py): {e}"))?;
        let out = child.stdout.take().ok_or("the mirror has no output")?;
        let log: Log = Arc::default();
        let kept = Arc::clone(&log);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                kept.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((Instant::now(), line));
            }
        });
        let mirror = Mirror {
            child,
            log,
            reader: Some(reader),
        };
        let started = Instant::now();
        let listening = format!("pkg-mirror: listening {port}");
        while !mirror.lines().contains(&listening) {
            if started.elapsed() > Duration::from_secs(30) {
                return Err(format!(
                    "the mirror did not say \"{listening}\" within 30 s"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(mirror)
    }

    fn lines(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(_, l)| l.clone())
            .collect()
    }

    /// The requests from line `from` of the log on, with the time of each.
    fn requests(&self, from: usize) -> Vec<(Instant, String)> {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .skip(from)
            .filter(|(_, l)| l.starts_with("pkg-mirror: GET "))
            .cloned()
            .collect()
    }

    fn mark(&self) -> usize {
        self.lines().len()
    }
}

impl Drop for Mirror {
    fn drop(&mut self) {
        // The mirror ends with the run: killed, waited for, its reader joined.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// The path of a request of a package file in the log, for the packages of Doom.
fn gets_of_packages(requests: &[(Instant, String)]) -> usize {
    requests
        .iter()
        .filter(|(_, l)| l.contains(".stpkg "))
        .count()
}

/// The state `good`: Doom and its WAD, signed by the development release key, serial
/// `GOOD_SERIAL`, in `states/good`. The package files are those of `target/pkg`.
fn make_good(states: &Path) -> Result<PathBuf, String> {
    let built = pkg::build(&pkg::Options {
        names: DOOM.iter().map(|s| (*s).to_owned()).collect(),
        key: None,
        cert: None,
        time: None,
        out: None,
        recipe: false,
        replace: Vec::new(),
    })?;
    let all = packages::load()?;
    repo::make(
        &built,
        &all,
        &repo::Options {
            serial: GOOD_SERIAL,
            expires_days: 30,
            sources: false,
            key: None,
            cert: None,
            root: None,
            check: false,
            dir: Some(states.join("good")),
        },
    )
}

/// The link `www/<series>/aarch64` to the directory of the state, replaced in one step.
fn point(www: &Path, state: &Path) -> Result<(), String> {
    let link = www.join(pkg::series()).join("aarch64");
    let temp = link.with_extension("new");
    let _ = std::fs::remove_file(&temp);
    std::os::unix::fs::symlink(state, &temp).map_err(|e| format!("{}: {e}", temp.display()))?;
    std::fs::rename(&temp, &link).map_err(|e| format!("{}: {e}", link.display()))
}

/// What a step of the dialog gives: the lines and the exit code of a command.
fn run_command(
    run: &mut qemu::Run,
    command: &str,
    marker: &str,
    within: Duration,
) -> Result<(i32, Vec<String>), String> {
    let (code, lines) = coded(run, &format!("{command} 2>&1"), marker, within)?;
    Ok((
        code,
        lines
            .into_iter()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.starts_with("rc=") && !l.is_empty())
            .collect(),
    ))
}

fn expect_code(
    run: &mut qemu::Run,
    command: &str,
    marker: &str,
    wanted: i32,
    within: Duration,
) -> Result<Vec<String>, String> {
    let (code, lines) = run_command(run, command, marker, within)?;
    if code != wanted {
        return Err(format!(
            "{marker}: `{command}` ended with {code}, wanted {wanted}: {lines:?}"
        ));
    }
    Ok(lines)
}

fn has(lines: &[String], text: &str) -> bool {
    lines.iter().any(|l| l.contains(text))
}

fn need(lines: &[String], text: &str, step: &str) -> Result<(), String> {
    if has(lines, text) {
        Ok(())
    } else {
        Err(format!("{step}: no line with {text:?} in {lines:?}"))
    }
}

/// The packages of the base image that hold files (the image's count of `pkg check`).
fn base_packages() -> Result<usize, String> {
    Ok(packages::of_image(base_image::BASE_IMAGE)?
        .iter()
        .filter(|p| !(p.files.is_empty() && p.dirs.is_empty()))
        .count())
}

/// The count after `prefix` in a line: `packages 0 on the disk, 10 in the image`.
fn count_in(lines: &[String], before: &str, after: &str) -> Option<usize> {
    lines.iter().find_map(|l| {
        let rest = l.split(before).nth(1)?;
        rest.split(after).next()?.trim().parse().ok()
    })
}

/// The mean speed of a download in MB/s of 10^6 bytes: `bytes` in `took`.
fn megabytes_per_second(bytes: u64, took: Duration) -> f64 {
    bytes as f64 / 1e6 / took.as_secs_f64().max(1e-3)
}

/// Steps 1 to 8 on the machine `machine`.
fn install(machine: &'static qemu::Machine) -> Result<(), String> {
    let started = Instant::now();
    base_image::prepare()?;
    let ca = probe_ca::ensure(false)?;
    let dev = keys::dev_keys(&root())?;
    let _ = dev;
    let kernel = build(Variant::Normal)?;
    // The repository: the state and the link the mirror serves.
    let dir = target_dir().join("pkg-probe");
    let states = dir.join("states");
    let www = dir.join("www");
    std::fs::create_dir_all(www.join(pkg::series())).map_err(|e| e.to_string())?;
    let good = make_good(&states)?;
    point(&www, &good)?;
    let roots = roots_path();
    let roots_text = roots.display().to_string();
    let image = crate::write_boot_image_with(
        IMAGE,
        base_image::programs(base_image::BASE_IMAGE),
        BOOT_PROFILE,
        &[("STAFETO_PKG_ROOTS", &roots_text)],
    )?;
    let prepared = started.elapsed();
    let mirror = Mirror::start(&www, PORT, &ca.join("host-a.crt"), &ca.join("host-a.key"))?;
    // The disk of the guest: new for each run.
    let store = image.with_file_name("store-pkg-probe.img");
    qemu::store_file(&store, STORE_BYTES, true)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(base_image::machine_args(&store));
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let began = Instant::now();
    let mut report: Vec<String> = Vec::new();
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT * 4)?;
        run.expect("# ", DIALOG_STEP)?;
        // The network service came up before init said its services started.
        if !run
            .lines()
            .iter()
            .any(|l| l.contains("net: lease 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3"))
        {
            return Err("the network service took no lease".into());
        }
        run.send("S=ok")?;
        run.expect("# ", DIALOG_STEP)?;
        // The guest's clock against the host's: the certificates and the index are checked by it.
        let date = capture(&mut run, "date +%s", "clock", DIALOG_STEP)?;
        let off = probe_ca::clock_verdict(&date)?;
        report.push(format!("the guest's clock is {off} s from the host's"));

        // Step 1.
        let lines = expect_code(&mut run, "pkg check", "check1", 0, DIALOG_STEP)?;
        need(&lines, "roots stafeto-dev-root", "step 1")?;
        let image_count = base_packages()?;
        if count_in(&lines, "packages ", " on the disk") != Some(0)
            || count_in(&lines, "disk, ", " in the image") != Some(image_count)
        {
            return Err(format!(
                "step 1: pkg check should count 0 on the disk and {image_count} in the image: {lines:?}"
            ));
        }
        if !run
            .lines()
            .iter()
            .any(|l| l.trim() == "pkgd: roots stafeto-dev-root")
        {
            return Err("step 1: pkgd did not say \"pkgd: roots stafeto-dev-root\"".into());
        }
        report.push(format!(
            "pkg check: roots stafeto-dev-root, 0 on the disk, {image_count} in the image"
        ));

        // Step 2.
        let lines = expect_code(&mut run, "pkg list", "list1", 0, DIALOG_STEP)?;
        if lines.len() != image_count || !lines.iter().all(|l| l.ends_with("[image]")) {
            return Err(format!(
                "step 2: pkg list should list {image_count} lines of the image: {lines:?}"
            ));
        }
        let counted = expect_code(&mut run, "pkg list | wc -l", "list2", 0, DIALOG_STEP)?;
        if counted.last().map(String::as_str) != Some(&image_count.to_string()) {
            return Err(format!(
                "step 2: pkg list | wc -l gave {counted:?}, wanted {image_count}"
            ));
        }
        report.push(format!(
            "pkg list: {image_count} lines, all [image], {image_count} through a pipe"
        ));

        // Step 3.
        let mark = mirror.mark();
        let began_install = Instant::now();
        let lines = expect_code(&mut run, "pkg install doom", "install", 0, INSTALL_WITHIN)?;
        let took = began_install.elapsed();
        let fetching = format!(
            "fetching {}/INDEX ... ok (serial {GOOD_SERIAL}, signed by stafeto-dev-release)",
            official_address()
        );
        need(&lines, &fetching, "step 3")?;
        need(&lines, "installing freedoom ", "step 3")?;
        need(&lines, "doomgeneric needs display input", "step 3")?;
        need(&lines, "freedoom ", "step 3")?;
        need(&lines, " ... ok", "step 3")?;
        need(&lines, "(doom), freedoom 0.13.0-1 (dependency)", "step 3")?;
        let ps = capture(&mut run, "ps", "ps", DIALOG_STEP)?;
        if has(&ps, "curl") {
            return Err(format!(
                "step 3: ps shows curl after the installation: {ps:?}"
            ));
        }
        let requests = mirror.requests(mark);
        let packages_got = gets_of_packages(&requests);
        if packages_got != 2 {
            return Err(format!(
                "step 3: the mirror served {packages_got} package files, wanted 2: {requests:?}"
            ));
        }
        // The time by parts, from the times the requests came: the index (the first request, up
        // to the first package), the WAD (to the second package), the rest (to the end).
        let at = |what: &str| {
            requests
                .iter()
                .find(|(_, l)| l.contains(what))
                .map(|(t, _)| *t)
        };
        let (index, wad, engine) = (at("/INDEX "), at("freedoom-"), at("doomgeneric-"));
        if let (Some(index), Some(wad), Some(engine)) = (index, wad, engine) {
            let wad_bytes = 28_827_648u64;
            let wad_took = engine.saturating_duration_since(wad);
            report.push(format!(
                "pkg install doom: {:.1} s in all; to the first package {:.1} s (the lists, the index, the checks); the WAD ({} bytes) from its request to the next {:.1} s = {:.2} MB/s through curl, the pipe, FEED and the hash; the engine and the end {:.1} s",
                took.as_secs_f64(),
                wad.saturating_duration_since(index).as_secs_f64(),
                wad_bytes,
                wad_took.as_secs_f64(),
                megabytes_per_second(wad_bytes, wad_took),
                (began_install + took).saturating_duration_since(engine).as_secs_f64(),
            ));
            if megabytes_per_second(wad_bytes, wad_took) < 1.0 {
                return Err(format!(
                    "pkg-probe: the WAD came at {:.2} MB/s, under the 1 MB/s of the stop point of the note: stop and measure by parts (network, pipe, FEED, check)",
                    megabytes_per_second(wad_bytes, wad_took)
                ));
            }
        }

        // Step 4.
        let lines = expect_code(&mut run, "pkg list", "list3", 0, DIALOG_STEP)?;
        need(&lines, "doomgeneric e257a095-1 stafeto", "step 4")?;
        need(&lines, "freedoom 0.13.0-1 stafeto [dependency]", "step 4")?;
        if lines.len() != image_count + 2 {
            return Err(format!(
                "step 4: pkg list gave {} lines, wanted {}: {lines:?}",
                lines.len(),
                image_count + 2
            ));
        }

        // Step 5.
        let demo = format!("doom -iwad {WAD} -timedemo demo1 -nodraw");
        let (code, lines) = run_command(&mut run, &demo, "demo", DEMO_WITHIN)?;
        let timed = lines
            .iter()
            .find_map(|l| crate::doom::report_numbers(l))
            .ok_or_else(|| format!("step 5: no `timed N gametics` line: {lines:?}"))?;
        if code != 255 || timed.0 == 0 {
            return Err(format!(
                "step 5: the demo ended with {code} after {} gametics, wanted 255 and some",
                timed.0
            ));
        }
        report.push(format!(
            "the demo of Doom: {} gametics in {} realtics, exit 255",
            timed.0, timed.1
        ));

        // Step 6.
        let lines = expect_code(&mut run, "pkg info doom", "info", 0, DIALOG_STEP)?;
        need(&lines, "provides    doom", "step 6")?;
        need(&lines, "license     GPL-2.0-or-later", "step 6")?;
        need(&lines, "/usr/share/licenses/doomgeneric/LICENSE", "step 6")?;
        need(&lines, "/usr/share/licenses/doomgeneric/SOURCE", "step 6")?;
        need(&lines, "state       installed (by request)", "step 6")?;
        let lines = expect_code(&mut run, "pkg search doom", "search", 0, DIALOG_STEP)?;
        need(
            &lines,
            "doomgeneric e257a095-1 stafeto Doom engine",
            "step 6",
        )?;
        need(&lines, "[installed]", "step 6")?;

        // Step 7.
        let mark = mirror.mark();
        let lines = expect_code(&mut run, "pkg update", "update", 0, INSTALL_WITHIN)?;
        need(
            &lines,
            &format!("stafeto: serial {GOOD_SERIAL}, was {GOOD_SERIAL}, "),
            "step 7",
        )?;
        if gets_of_packages(&mirror.requests(mark)) != 0 {
            return Err("step 7: pkg update downloaded a package".into());
        }

        // Step 8.
        let mark = mirror.mark();
        let lines = expect_code(&mut run, "pkg install doom", "again", 0, INSTALL_WITHIN)?;
        need(
            &lines,
            "doom: doomgeneric e257a095-1 is installed",
            "step 8",
        )?;
        let requests = mirror.requests(mark);
        if gets_of_packages(&requests) != 0 {
            return Err(format!(
                "step 8: the second install downloaded a package: {requests:?}"
            ));
        }
        report.push(
            "the second pkg install doom downloads no package (the log of the mirror)".into(),
        );

        // The refusal of a process that is not the superuser is the next part's (runas).
        let free = run.lines().iter().find_map(|l| {
            l.trim()
                .strip_prefix("init: free pages ")?
                .split(' ')
                .next()?
                .parse::<u64>()
                .ok()
        });
        if let Some(free) = free {
            report.push(format!(
                "init has {free} free pages after the services started"
            ));
        }
        Ok::<(), String>(())
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    let log = mirror.lines();
    drop(mirror);
    talked.map_err(|e| format!("{e}\nthe log of the mirror: {log:?}"))?;
    if let Some(line) = output.lines.iter().find(|l| {
        l.contains("process fault:") || l.contains("KERNEL PANIC") || l.contains("out of memory")
    }) {
        return Err(format!("the guest faulted: {line}"));
    }
    let total = started.elapsed();
    for line in &report {
        println!("pkg-probe: {line}");
    }
    println!(
        "pkg-probe install on {}: steps 1 to 8 passed in {:.0} s (the build and the repository {:.0} s, the guest {:.0} s)",
        machine.name,
        total.as_secs_f64(),
        prepared.as_secs_f64(),
        began.elapsed().as_secs_f64()
    );
    if !machine.is_hvf() && began.elapsed() > WITHIN {
        return Err(format!(
            "pkg-probe: the guest took {:.0} s on TCG, over the {} s of the plan: stop and measure",
            began.elapsed().as_secs_f64(),
            WITHIN.as_secs()
        ));
    }
    Ok(())
}

/// `cargo xtask pkg-probe [install] [--hvf]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let mut hvf = false;
    for a in args {
        match a.as_str() {
            "install" => {}
            "--hvf" => hvf = true,
            other => {
                return Err(format!(
                    "usage: cargo xtask pkg-probe [install] [--hvf]: {other}"
                ));
            }
        }
    }
    let machine = if hvf {
        crate::hvf_host().map_err(|why| format!("hvf needs macOS on Apple Silicon: {why}"))?;
        &qemu::HVF_V3
    } else {
        base_image::machine(base_image::BASE_IMAGE)
    };
    install(machine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_of_the_mirror_is_the_host_of_the_guest_on_the_port_of_the_image() {
        assert_eq!(
            official_address(),
            format!("https://10.0.2.2:8443/{}/aarch64", pkg::series())
        );
    }

    #[test]
    fn counts_are_read_from_the_lines_of_check() {
        let lines = vec![
            "store generation 7, 131072 blocks, 123905 free (507.5 MB)".to_owned(),
            "packages 0 on the disk, 10 in the image, 0 revoked".to_owned(),
        ];
        assert_eq!(count_in(&lines, "packages ", " on the disk"), Some(0));
        assert_eq!(count_in(&lines, "disk, ", " in the image"), Some(10));
        assert_eq!(count_in(&lines, "nothing ", " here"), None);
    }

    #[test]
    fn a_download_is_counted_in_megabytes_a_second() {
        let speed = megabytes_per_second(28_827_648, Duration::from_secs(10));
        assert!((speed - 2.88).abs() < 0.01, "{speed}");
    }

    #[test]
    fn only_package_files_count_as_packages_in_the_log() {
        let now = Instant::now();
        let requests = vec![
            (now, "pkg-mirror: GET /0.3/aarch64/INDEX 200 100".to_owned()),
            (
                now,
                "pkg-mirror: GET /0.3/aarch64/hello-1.0-1.stpkg 200 100".to_owned(),
            ),
            (
                now,
                "pkg-mirror: GET /0.3/aarch64/INDEX.sig 200 456".to_owned(),
            ),
        ];
        assert_eq!(gets_of_packages(&requests), 1);
    }
}
