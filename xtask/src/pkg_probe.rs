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
//! 9. The codes of exit: 2 for a command line that is none, 1 with a line of its own for a name no
//!    repository has, and no package downloaded for it.

use crate::net_tls::{capture, coded};
use crate::pkg_states;
use crate::rootfs;
use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, DIALOG_STEP, SERVICES_STARTED, STORE_BYTES, Variant, base_image,
    build, keys, packages, pkg, probe_ca, qemu, repo, root, symbolize, target_dir,
};
use std::ffi::OsStr;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const IMAGE: &str = "boot-pkg-probe.img";
/// The port of the mirror, in `/etc/pkg/official` of the image.
const PORT: u16 = 8443;
/// The port of the mirror whose certificate no one trusts (`host-b` of the probe CA, self-signed).
const OTHER_PORT: u16 = 8444;
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
        redirects: Option<&Path>,
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
            .args(
                redirects
                    .iter()
                    .flat_map(|r| [OsStr::new("--redirects"), r.as_os_str()]),
            )
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

/// The requests of the mirror a command made, with the time of each.
type Requests = Vec<(Instant, String)>;

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
        previous: None,
        perturb: Vec::new(),
    })?;
    let all = packages::load()?;
    repo::make(
        &built,
        &all,
        &repo::Options {
            serial: GOOD_SERIAL,
            sources: false,
            dir: Some(states.join("doom")),
            ..repo::Options::default()
        },
    )
}

/// The link `link` to the directory of a state, replaced in one step; its directory is made.
fn point_at(link: &Path, state: &Path) -> Result<(), String> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let temp = link.with_extension("new");
    let _ = std::fs::remove_file(&temp);
    let state = std::fs::canonicalize(state).map_err(|e| format!("{}: {e}", state.display()))?;
    std::os::unix::fs::symlink(&state, &temp).map_err(|e| format!("{}: {e}", temp.display()))?;
    std::fs::rename(&temp, link).map_err(|e| format!("{}: {e}", link.display()))
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
            // The service writes lines of its own to the console at any time (`pkgd: memory ...`).
            .filter(|l| !l.starts_with("rc=") && !l.is_empty() && !l.starts_with("pkgd: "))
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

/// The files of the image of the probe besides the base: the program `runas` and the key files
/// the owner "brought" (`/test/games.pub`, `/test/bad.pub`).
fn test_files() -> Result<Vec<rootfs::RootFile>, String> {
    let mut cmd = crate::cargo();
    cmd.arg("build").args(BOOT_PROFILE.args());
    cmd.args(["--target", crate::PROGRAM_TARGET, "--package", "runas"]);
    crate::run_cmd(&mut cmd)?;
    let path = crate::cargo_output(&target_dir(), crate::PROGRAM_TARGET, BOOT_PROFILE, "runas");
    // The file the linker wrote carries its debug information (6.7 MB); the image holds it stripped.
    let stripped = target_dir().join("pkg-probe").join("runas");
    std::fs::create_dir_all(stripped.parent().ok_or("no directory")?).map_err(|e| e.to_string())?;
    std::fs::copy(&path, &stripped).map_err(|e| format!("{}: {e}", path.display()))?;
    crate::strip_elf(&stripped, &crate::llvm_tool("llvm-objcopy")?)?;
    let runas = std::fs::read(&stripped).map_err(|e| format!("{}: {e}", stripped.display()))?;
    let leak = |b: Vec<u8>| -> &'static [u8] { Box::leak(b.into_boxed_slice()) };
    let file =
        |path: &'static str, mode: u32, tag: &'static str, bytes: Vec<u8>| rootfs::RootFile {
            path,
            mode,
            uid: 0,
            gid: 0,
            source: Some(rootfs::Source::Bytes(tag, leak(bytes))),
        };
    Ok(vec![
        rootfs::RootFile {
            path: "/test",
            mode: 0o755,
            uid: 0,
            gid: 0,
            source: None,
        },
        file("/test/runas", 0o555, "test-runas", runas),
        file(
            "/test/games.pub",
            0o444,
            "test-games-key",
            pkg_states::key_file(pkg_states::GAMES_KEY, pkg_states::GAMES_SEED)?.into_bytes(),
        ),
        file(
            "/test/bad.pub",
            0o444,
            "test-bad-key",
            pkg_states::key_file(pkg_states::BAD_KEY, pkg_states::BAD_SEED)?.into_bytes(),
        ),
    ])
}

/// What the runs of the machine share.
struct Ctx<'a> {
    machine: &'static qemu::Machine,
    kernel: &'a crate::Artifacts,
    image: PathBuf,
    store: PathBuf,
    mirror: &'a Mirror,
    www: PathBuf,
    states: &'a pkg_states::States,
    report: Vec<String>,
    image_count: usize,
}

impl Ctx<'_> {
    fn state(&self, dir: &Path) -> Result<(), String> {
        point_at(&self.www.join(pkg::series()).join("aarch64"), dir)
    }
}

/// The path of a repository of the owner, as `repo add` names it.
fn games_address() -> String {
    format!("https://10.0.2.2:{PORT}/games/{}/aarch64", pkg::series())
}

fn bad_address() -> String {
    format!(
        "https://10.0.2.2:{OTHER_PORT}/games/{}/aarch64",
        pkg::series()
    )
}

/// One run of the machine on the disk of the probe: it boots, `body` talks to it, it stops; a fault
/// of the guest fails the run. The log of the mirror is added to a failure.
fn guest(
    ctx: &mut Ctx<'_>,
    body: impl FnOnce(&mut qemu::Run, &mut Ctx<'_>) -> Result<(), String>,
) -> Result<(), String> {
    let mut cmd = qemu::command(ctx.machine, &ctx.kernel.image, Some(&ctx.image));
    cmd.args(qemu::HEADLESS);
    cmd.args(base_image::machine_args(&ctx.store));
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = boot(&mut run, ctx).and_then(|()| body(&mut run, ctx));
    let output = run.stop();
    symbolize::backtrace(&output.lines, &ctx.kernel.elf);
    let log = ctx.mirror.lines();
    talked.map_err(|e| format!("{e}\nthe log of the mirror: {log:?}"))?;
    if let Some(line) = output.lines.iter().find(|l| {
        l.contains("process fault:") || l.contains("KERNEL PANIC") || l.contains("out of memory")
    }) {
        return Err(format!("the guest faulted: {line}"));
    }
    if let Some(line) = output
        .lines
        .iter()
        .find(|l| l.contains("pkgd: ") && l.contains("skipped"))
    {
        return Err(format!(
            "the package service skipped a package at the start: {line}"
        ));
    }
    Ok(())
}

/// The boot: the services, the lease of the network, the clock against the host's.
fn boot(run: &mut qemu::Run, ctx: &mut Ctx<'_>) -> Result<(), String> {
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
    let date = capture(run, "date +%s", "clock", DIALOG_STEP)?;
    let off = probe_ca::clock_verdict(&date)?;
    ctx.report
        .push(format!("the guest's clock is {off} s from the host's"));
    Ok(())
}

/// The lines of `command` without a refusal of its exit code, as `expect_code` has it, and the
/// requests of the mirror it made.
fn with_log(
    run: &mut qemu::Run,
    ctx: &Ctx<'_>,
    command: &str,
    marker: &str,
    wanted: i32,
) -> Result<(Vec<String>, Requests), String> {
    let mark = ctx.mirror.mark();
    let lines = expect_code(run, command, marker, wanted, INSTALL_WITHIN)?;
    Ok((lines, ctx.mirror.requests(mark)))
}

fn no_gets(requests: &[(Instant, String)], step: &str, what: &str) -> Result<(), String> {
    if requests.is_empty() {
        Ok(())
    } else {
        Err(format!("{step}: {what} asked the mirror: {requests:?}"))
    }
}

fn got(requests: &[(Instant, String)], what: &str) -> bool {
    requests.iter().any(|(_, l)| l.contains(what))
}

/// The store as `pkg check` and `pkg list` say it, to be sure a refusal changed nothing.
fn store_of(run: &mut qemu::Run, marker: &str) -> Result<(Vec<String>, Vec<String>), String> {
    // The generation moves with a list of revocations that is taken again; the packages and the
    // free space do not.
    let mut check = expect_code(run, "pkg check", &format!("{marker}c"), 0, DIALOG_STEP)?;
    check.retain(|l| !l.starts_with("store generation"));
    let list = expect_code(run, "pkg list", &format!("{marker}l"), 0, DIALOG_STEP)?;
    Ok((check, list))
}

/// Steps 1 to 9 (`install`), and with `full` the rest of the scenario on three boots of the machine.
fn scenario(machine: &'static qemu::Machine, full: bool) -> Result<(), String> {
    let started = Instant::now();
    base_image::prepare()?;
    let ca = probe_ca::ensure(false)?;
    keys::dev_keys(&root())?;
    let kernel = build(Variant::Normal)?;
    // The repositories: the states and the links the mirrors serve.
    let dir = target_dir().join("pkg-probe");
    let states_dir = dir.join("states");
    let www = dir.join("www");
    let www_b = dir.join("www-b");
    std::fs::create_dir_all(www.join(pkg::series())).map_err(|e| e.to_string())?;
    let doom = make_good(&states_dir)?;
    let states = pkg_states::make(&states_dir, &doom, &format!("https://10.0.2.2:{PORT}"))?;
    point_at(&www.join("store"), &states.store)?;
    let redirects = dir.join("redirects");
    std::fs::write(&redirects, &states.redirects)
        .map_err(|e| format!("{}: {e}", redirects.display()))?;
    point_at(&www.join(pkg::series()).join("aarch64"), &states.good)?;
    let games_link = www.join("games").join(pkg::series()).join("aarch64");
    point_at(&games_link, &states.games)?;
    point_at(
        &www_b.join("games").join(pkg::series()).join("aarch64"),
        &states.games,
    )?;
    let roots = roots_path();
    let roots_text = roots.display().to_string();
    let image = crate::write_boot_image_files(
        IMAGE,
        base_image::programs(base_image::BASE_IMAGE),
        BOOT_PROFILE,
        &[("STAFETO_PKG_ROOTS", &roots_text)],
        test_files()?,
    )?;
    let prepared = started.elapsed();
    let mirror = Mirror::start(
        &www,
        PORT,
        &ca.join("host-a.crt"),
        &ca.join("host-a.key"),
        Some(&redirects),
    )?;
    let other = Mirror::start(
        &www_b,
        OTHER_PORT,
        &ca.join("host-b.crt"),
        &ca.join("host-b.key"),
        None,
    )?;
    // The disk of the guest: new for the run, the same for its boots.
    let store = image.with_file_name("store-pkg-probe.img");
    qemu::store_file(&store, STORE_BYTES, true)?;
    let mut ctx = Ctx {
        machine,
        kernel: &kernel,
        image,
        store,
        mirror: &mirror,
        www,
        states: &states,
        report: Vec::new(),
        image_count: base_packages()?,
    };
    let began = Instant::now();
    guest(&mut ctx, |run, ctx| first_boot(run, ctx, full))?;
    if full {
        ctx.state(&states.next)?;
        guest(&mut ctx, second_boot)?;
        guest(&mut ctx, third_boot)?;
    }
    let report = ctx.report.clone();
    drop(ctx);
    drop(mirror);
    drop(other);
    let total = started.elapsed();
    for line in &report {
        println!("pkg-probe: {line}");
    }
    println!(
        "pkg-probe{} on {}: passed in {:.0} s (the build and the repositories {:.0} s, the guest {:.0} s)",
        if full { "" } else { " install" },
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

/// Steps 1 to 9 and, with `full`, 10 to 18 on the first boot.
fn first_boot(run: &mut qemu::Run, ctx: &mut Ctx<'_>, full: bool) -> Result<(), String> {
    let mirror = ctx.mirror;
    let image_count = ctx.image_count;
    // Step 1.
    let lines = expect_code(run, "pkg check", "check1", 0, DIALOG_STEP)?;
    need(&lines, "roots stafeto-dev-root", "step 1")?;
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
    ctx.report.push(format!(
        "pkg check: roots stafeto-dev-root, 0 on the disk, {image_count} in the image"
    ));

    // Step 2.
    let lines = expect_code(run, "pkg list", "list1", 0, DIALOG_STEP)?;
    if lines.len() != image_count || !lines.iter().all(|l| l.ends_with("[image]")) {
        return Err(format!(
            "step 2: pkg list should list {image_count} lines of the image: {lines:?}"
        ));
    }
    let counted = expect_code(run, "pkg list | wc -l", "list2", 0, DIALOG_STEP)?;
    if counted.last().map(String::as_str) != Some(&image_count.to_string()) {
        return Err(format!(
            "step 2: pkg list | wc -l gave {counted:?}, wanted {image_count}"
        ));
    }
    ctx.report.push(format!(
        "pkg list: {image_count} lines, all [image], {image_count} through a pipe"
    ));

    // Step 3.
    let mark = mirror.mark();
    let began_install = Instant::now();
    let lines = expect_code(run, "pkg install doom", "install", 0, INSTALL_WITHIN)?;
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
    let ps = capture(run, "ps", "ps", DIALOG_STEP)?;
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
    speed_report(&requests, took, began_install, &mut ctx.report)?;

    // Step 4.
    let lines = expect_code(run, "pkg list", "list3", 0, DIALOG_STEP)?;
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
    let timed = demo_run(run, &demo, "demo")?;
    ctx.report.push(format!(
        "the demo of Doom: {} gametics in {} realtics, exit 255",
        timed.0, timed.1
    ));

    // Step 6.
    let lines = expect_code(run, "pkg info doom", "info", 0, DIALOG_STEP)?;
    need(&lines, "provides    doom", "step 6")?;
    need(&lines, "license     GPL-2.0-or-later", "step 6")?;
    need(&lines, "/usr/share/licenses/doomgeneric/LICENSE", "step 6")?;
    need(&lines, "/usr/share/licenses/doomgeneric/SOURCE", "step 6")?;
    need(&lines, "state       installed (by request)", "step 6")?;
    let lines = expect_code(run, "pkg search doom", "search", 0, DIALOG_STEP)?;
    need(
        &lines,
        "doomgeneric e257a095-1 stafeto Doom engine",
        "step 6",
    )?;
    need(&lines, "[installed]", "step 6")?;

    // Step 7.
    let mark = mirror.mark();
    let lines = expect_code(run, "pkg update", "update", 0, INSTALL_WITHIN)?;
    need(
        &lines,
        &format!("stafeto: serial {GOOD_SERIAL}, was {GOOD_SERIAL}, "),
        "step 7",
    )?;
    if gets_of_packages(&mirror.requests(mark)) != 0 {
        return Err("step 7: pkg update downloaded a package".into());
    }

    // Step 8.
    let (lines, requests) = with_log(run, ctx, "pkg install doom", "again", 0)?;
    need(
        &lines,
        "doom: doomgeneric e257a095-1 is installed",
        "step 8",
    )?;
    if gets_of_packages(&requests) != 0 {
        return Err(format!(
            "step 8: the second install downloaded a package: {requests:?}"
        ));
    }
    ctx.report
        .push("the second pkg install doom downloads no package (the log of the mirror)".into());

    // Step 9: the codes of exit. A command line that is none is 2 with the usage line; a name no
    // repository has is 1 with its own line, and nothing is downloaded for it.
    let lines = expect_code(run, "pkg", "usage", 2, DIALOG_STEP)?;
    need(
        &lines,
        "usage: pkg install|remove|upgrade|update|list|info|search|repo|check",
        "step 9",
    )?;
    expect_code(run, "pkg install", "usage2", 2, DIALOG_STEP)?;
    let (lines, requests) = with_log(run, ctx, "pkg install nosuch", "nosuch", 1)?;
    need(&lines, "pkg: nosuch: no repository has it", "step 9")?;
    if gets_of_packages(&requests) != 0 {
        return Err(format!(
            "step 9: a name no repository has downloaded a package: {requests:?}"
        ));
    }
    ctx.report.push(
        "exit codes: 2 for a bad command line, 1 and a line of its own for a name no repository has"
            .into(),
    );
    if !full {
        report_free(run, &mut ctx.report);
        return Ok(());
    }
    refusals(run, ctx)?;
    manage(run, ctx)?;
    report_free(run, &mut ctx.report);
    Ok(())
}

fn report_free(run: &qemu::Run, report: &mut Vec<String>) {
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
}

/// The time of the first installation by parts, from the times the requests came: the index (the
/// first request, up to the first package), the WAD (to the second package), the rest.
fn speed_report(
    requests: &[(Instant, String)],
    took: Duration,
    began: Instant,
    report: &mut Vec<String>,
) -> Result<(), String> {
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
            (began + took).saturating_duration_since(engine).as_secs_f64(),
        ));
        if megabytes_per_second(wad_bytes, wad_took) < 1.0 {
            return Err(format!(
                "pkg-probe: the WAD came at {:.2} MB/s, under the 1 MB/s of the stop point of the note: stop and measure by parts (network, pipe, FEED, check)",
                megabytes_per_second(wad_bytes, wad_took)
            ));
        }
    }
    Ok(())
}

/// The demo of Doom: `timed N gametics`, exit 255.
fn demo_run(run: &mut qemu::Run, demo: &str, marker: &str) -> Result<(u64, u64), String> {
    let (code, lines) = run_command(run, demo, marker, DEMO_WITHIN)?;
    let timed = lines
        .iter()
        .find_map(|l| crate::doom::report_numbers(l))
        .ok_or_else(|| format!("the demo: no `timed N gametics` line: {lines:?}"))?;
    if code != 255 || timed.0 == 0 {
        return Err(format!(
            "the demo ended with {code} after {} gametics, wanted 255 and some",
            timed.0
        ));
    }
    Ok(timed)
}

/// Steps 10 to 14: each refusal with its own line, and what stays as it was.
fn refusals(run: &mut qemu::Run, ctx: &mut Ctx<'_>) -> Result<(), String> {
    let untouched = store_of(run, "s9")?;
    // Step 10: a process that is not the superuser. The tool refuses before it asks the network.
    let (lines, requests) = with_log(
        run,
        ctx,
        "/test/runas 1000 /bin/pkg install hello",
        "nonroot",
        1,
    )?;
    need(&lines, "pkg: permission denied", "step 10")?;
    no_gets(&requests, "step 10", "a process that is not the superuser")?;
    ctx.report
        .push("not UID 0: pkg: permission denied, the mirror was not asked".into());

    let before = store_of(run, "s10")?;
    if before != untouched {
        return Err("step 10: the store changed after a process that is not the superuser".into());
    }
    // Step 11: a byte of the file changed, and a file longer than the index says.
    ctx.state(&ctx.states.tampered)?;
    let (lines, _) = with_log(run, ctx, "pkg install hello", "tampered", 1)?;
    need(
        &lines,
        "pkg: hello: the file is not the one the index names",
        "step 11",
    )?;
    if store_of(run, "s11a")? != before {
        return Err("step 11: the store changed after a tampered file".into());
    }
    ctx.state(&ctx.states.long)?;
    let (lines, _) = with_log(run, ctx, "pkg install hello", "long", 1)?;
    if !has(&lines, "larger than the index says") && !has(&lines, "the server sent more than") {
        return Err(format!(
            "step 11: no line about a file longer than the index says: {lines:?}"
        ));
    }
    if store_of(run, "s11b")? != before {
        return Err("step 11: the store changed after a long file".into());
    }
    ctx.report
        .push("a changed byte and a longer file: refused, the store as it was".into());

    // Step 12: an older serial, and an index past its term.
    ctx.state(&ctx.states.old)?;
    let lines = expect_code(run, "pkg update", "old", 1, INSTALL_WITHIN)?;
    need(
        &lines,
        "pkg: stafeto: index serial 1 is older than serial 2 already accepted (rollback)",
        "step 12",
    )?;
    ctx.state(&ctx.states.expired)?;
    let lines = expect_code(run, "pkg update", "expired", 1, INSTALL_WITHIN)?;
    need(&lines, "pkg: stafeto: index expired at ", "step 12")?;
    if store_of(run, "s12")? != before {
        return Err("step 12: the store changed after a refused index".into());
    }
    ctx.report
        .push("serial 1 after 2 and an expired index: refused, each with its line".into());

    // Step 13: a key the repository does not trust, then a package that is good.
    ctx.state(&ctx.states.foreign)?;
    let lines = expect_code(run, "pkg install alien", "alien", 1, INSTALL_WITHIN)?;
    need(
        &lines,
        "pkg: alien: signed by a key the repository stafeto does not trust",
        "step 13",
    )?;
    if store_of(run, "s13")? != before {
        return Err("step 13: the store changed after a package of a foreign key".into());
    }
    let lines = expect_code(run, "pkg install hello", "hello1", 0, INSTALL_WITHIN)?;
    need(&lines, "installed hello 1.0-1", "step 13")?;
    expect_code(run, "/opt/hello/bin/hello", "run-hello", 42, DIALOG_STEP)?;
    ctx.report
        .push("a package of a foreign key: refused; hello 1.0 installed and run (exit 42)".into());

    // Step 14: a dependency, the flag of the world, the removal that keeps what is needed.
    expect_code(run, "pkg install app", "app", 0, INSTALL_WITHIN)?;
    let lines = expect_code(run, "pkg list", "list-app", 0, DIALOG_STEP)?;
    need(&lines, "app 1.0-1 stafeto", "step 14")?;
    need(&lines, "lib 1.0-1 stafeto [dependency]", "step 14")?;
    let (lines, requests) = with_log(run, ctx, "pkg install lib", "lib", 0)?;
    need(&lines, "lib 1.0-1: now installed by request", "step 14")?;
    if got(&requests, "lib-") {
        return Err(format!("step 14: lib was downloaded again: {requests:?}"));
    }
    let lines = expect_code(run, "pkg remove lib", "rm-lib", 1, INSTALL_WITHIN)?;
    need(&lines, "pkg: lib: needed by app", "step 14")?;
    let lines = expect_code(run, "pkg remove app", "rm-app", 0, INSTALL_WITHIN)?;
    need(&lines, "removed app 1.0-1", "step 14")?;
    let lines = expect_code(run, "pkg list", "list-lib", 0, DIALOG_STEP)?;
    need(&lines, "lib 1.0-1 stafeto", "step 14")?;
    if lines
        .iter()
        .any(|l| l.starts_with("lib ") && l.contains("[dependency]"))
        || lines.iter().any(|l| l.starts_with("app "))
    {
        return Err(format!(
            "step 14: lib should stay as a package of the world: {lines:?}"
        ));
    }
    expect_code(run, "pkg remove lib", "rm-lib2", 0, INSTALL_WITHIN)?;
    ctx.report.push("app and lib: WORLD_SET without a download, remove names what needs a package and keeps the world".into());
    Ok(())
}

/// Steps 15 to 18: the second repository, the upgrade, and an index signed by a key that is not the
/// repository's.
fn manage(run: &mut qemu::Run, ctx: &mut Ctx<'_>) -> Result<(), String> {
    // Step 15: an address that is not https, and a server the guest does not trust.
    let lines = expect_code(
        run,
        "pkg repo add plain http://10.0.2.2:8080/x /test/games.pub",
        "plain",
        1,
        DIALOG_STEP,
    )?;
    need(&lines, "not https", "step 15")?;
    let add = format!("pkg repo add bad {} /test/bad.pub", bad_address());
    let lines = expect_code(run, &add, "bad", 0, DIALOG_STEP)?;
    need(&lines, "bad: key bad-1 SHA256:", "step 15")?;
    need(&lines, ", trusted for bad only", "step 15")?;
    let lines = expect_code(run, "pkg update", "update-bad", 1, INSTALL_WITHIN)?;
    need(&lines, "the certificate is not trusted", "step 15")?;
    need(&lines, "stafeto: serial 4, was 4", "step 15")?;
    expect_code(run, "pkg repo remove bad", "rm-bad", 0, DIALOG_STEP)?;
    ctx.report.push(
        "a self-signed server: the certificate line for bad, the official repository passes".into(),
    );

    // Step 16: the second repository, its own key for it alone.
    let add = format!("pkg repo add games {} /test/games.pub", games_address());
    let lines = expect_code(run, &add, "games", 0, DIALOG_STEP)?;
    need(&lines, "games: key games-1 SHA256:", "step 16")?;
    need(&lines, ", trusted for games only", "step 16")?;
    let lines = expect_code(run, "pkg install hello-games", "hg", 0, INSTALL_WITHIN)?;
    need(&lines, "installed hello-games 1.0-1", "step 16")?;
    expect_code(
        run,
        "/opt/hello-games/bin/hello-games",
        "run-hg",
        42,
        DIALOG_STEP,
    )?;
    let lines = expect_code(run, "pkg install sneaky", "sneaky", 1, INSTALL_WITHIN)?;
    need(
        &lines,
        "pkg: sneaky: signed by a key the repository games does not trust",
        "step 16",
    )?;
    let lines = expect_code(run, "pkg list", "list-games", 0, DIALOG_STEP)?;
    need(&lines, "hello-games 1.0-1 games", "step 16")?;
    // The key is not changed and the repository is not removed while its package stands.
    let change = format!("pkg repo add games {} /test/bad.pub", games_address());
    let lines = expect_code(run, &change, "change", 1, DIALOG_STEP)?;
    need(
        &lines,
        "pkg: games: hello-games is installed from it; pkg remove it first",
        "step 16",
    )?;
    let lines = expect_code(run, "pkg repo remove games", "rm-games", 1, DIALOG_STEP)?;
    need(
        &lines,
        "pkg: games: hello-games is installed from it; pkg remove it first",
        "step 16",
    )?;
    let lines = expect_code(run, "pkg repo list", "repo-list", 0, DIALOG_STEP)?;
    need(&lines, "stafeto https://10.0.2.2:8443/", "step 16")?;
    need(&lines, "games https://10.0.2.2:8443/games/", "step 16")?;
    need(&lines, "key games-1 SHA256:", "step 16")?;
    let lines = expect_code(run, "cat /etc/pkg/repositories", "repos", 0, DIALOG_STEP)?;
    need(&lines, &format!("games {}", games_address()), "step 16")?;
    ctx.report.push("games: its key trusts it alone (sneaky is refused), the key and the repository stay while hello-games stands".into());

    // Step 17: the upgrade replaces what the index of the repository has another build of.
    ctx.state(&ctx.states.next)?;
    let (lines, requests) = with_log(run, ctx, "pkg upgrade", "upgrade", 0)?;
    need(&lines, "upgrading hello 1.0-1 -> 2.0-1", "step 17")?;
    if !got(&requests, "hello-2.0-1.stpkg")
        || got(&requests, "doomgeneric-")
        || got(&requests, "freedoom-")
        || got(&requests, "hello-games-")
    {
        return Err(format!(
            "step 17: the upgrade fetched the wrong files: {requests:?}"
        ));
    }
    let lines = expect_code(run, "pkg list", "list-next", 0, DIALOG_STEP)?;
    need(&lines, "hello 2.0-1 stafeto", "step 17")?;
    if has(&lines, "hello 2.0-1 stafeto [dependency]") {
        return Err(format!(
            "step 17: hello lost the flag of the world: {lines:?}"
        ));
    }
    let (lines, requests) = with_log(run, ctx, "pkg upgrade", "upgrade2", 0)?;
    need(&lines, "nothing to upgrade", "step 17")?;
    if gets_of_packages(&requests) != 0 {
        return Err(format!(
            "step 17: nothing to upgrade, and a package was fetched: {requests:?}"
        ));
    }
    expect_code(run, "/opt/hello/bin/hello", "run-hello2", 42, DIALOG_STEP)?;
    ctx.report.push("pkg upgrade: hello 1.0 -> 2.0, no package of Doom fetched, the flag of the world kept, then nothing to upgrade".into());

    // Step 18: an index of the official repository signed by the key of another repository.
    let before = store_of(run, "s18")?;
    ctx.state(&ctx.states.stolen)?;
    let lines = expect_code(run, "pkg update", "stolen", 1, INSTALL_WITHIN)?;
    need(
        &lines,
        "signed by games-1, a key this repository does not trust",
        "step 18",
    )?;
    let lines = expect_code(run, "pkg upgrade", "stolen-up", 1, INSTALL_WITHIN)?;
    need(
        &lines,
        "signed by games-1, a key this repository does not trust",
        "step 18",
    )?;
    if store_of(run, "s18b")? != before {
        return Err("step 18: the store changed".into());
    }
    ctx.state(&ctx.states.next)?;
    ctx.report.push("an index signed by the key of games: refused for stafeto; install and upgrade refuse as a whole".into());
    Ok(())
}

/// The second boot, on the same disk: what was installed is there; Doom goes with its notices.
fn second_boot(run: &mut qemu::Run, ctx: &mut Ctx<'_>) -> Result<(), String> {
    let lines = expect_code(run, "pkg list", "b2-list", 0, DIALOG_STEP)?;
    need(&lines, "doomgeneric e257a095-1 stafeto", "boot 2")?;
    need(&lines, "freedoom 0.13.0-1 stafeto [dependency]", "boot 2")?;
    need(&lines, "hello 2.0-1 stafeto", "boot 2")?;
    need(&lines, "hello-games 1.0-1 games", "boot 2")?;
    let lines = expect_code(run, "cat /etc/pkg/repositories", "b2-repos", 0, DIALOG_STEP)?;
    need(&lines, &format!("games {}", games_address()), "boot 2")?;
    let timed = demo_run(
        run,
        &format!("doom -iwad {WAD} -timedemo demo1 -nodraw"),
        "b2-demo",
    )?;
    ctx.report.push(format!(
        "after the restart on the same disk: the packages and the settings are there, the demo of Doom {} gametics, exit 255",
        timed.0
    ));
    let lines = expect_code(run, "pkg update", "b2-update", 0, INSTALL_WITHIN)?;
    need(&lines, "stafeto: serial 5, was 5, ", "boot 2")?;
    need(&lines, "games: serial 1, was 1, ", "boot 2")?;
    let lines = expect_code(run, "pkg remove doom", "b2-rm", 0, INSTALL_WITHIN)?;
    need(
        &lines,
        "removed doomgeneric e257a095-1, freedoom 0.13.0-1 (no longer needed)",
        "boot 2",
    )?;
    let (code, lines) = run_command(
        run,
        "ls /bin/doom /games/freedoom1.wad /usr/share/licenses/doomgeneric /usr/share/licenses/freedoom",
        "b2-ls",
        DIALOG_STEP,
    )?;
    let missing = lines.iter().filter(|l| l.contains("No such file")).count();
    if code == 0 || missing != 4 {
        return Err(format!(
            "boot 2: the files and the notices of Doom should be gone (4 missing, exit not 0): exit {code}, {lines:?}"
        ));
    }
    ctx.report
        .push("pkg remove doom: both packages and their notices are gone".into());
    // The settings layer is read-only, so the files cannot be edited here (the host tests hold the
    // check of /etc/pkg); `repo save` of the files as they are keeps what the service holds.
    let lines = expect_code(run, "pkg repo save", "b2-save", 0, DIALOG_STEP)?;
    need(&lines, "saved 1 repositories", "boot 2")?;
    let lines = expect_code(run, "pkg check", "b2-check", 0, DIALOG_STEP)?;
    need(&lines, "settings saved", "boot 2")?;
    let lines = expect_code(run, "pkg repo remove games", "b2-rm-games", 1, DIALOG_STEP)?;
    need(
        &lines,
        "pkg: games: hello-games is installed from it; pkg remove it first",
        "boot 2",
    )?;
    let lines = expect_code(run, "pkg remove hello-games", "b2-rm-hg", 0, INSTALL_WITHIN)?;
    need(&lines, "removed hello-games 1.0-1", "boot 2")?;
    expect_code(run, "pkg repo remove games", "b2-rm-games2", 0, DIALOG_STEP)?;
    Ok(())
}

/// The third boot: the removals are the disk's, and the settings are gone with the repository.
fn third_boot(run: &mut qemu::Run, ctx: &mut Ctx<'_>) -> Result<(), String> {
    let lines = expect_code(run, "pkg list", "b3-list", 0, DIALOG_STEP)?;
    need(&lines, "hello 2.0-1 stafeto", "boot 3")?;
    if lines.len() != ctx.image_count + 1 {
        return Err(format!(
            "boot 3: pkg list should have the image and hello: {lines:?}"
        ));
    }
    let (code, lines) = run_command(
        run,
        "ls /bin/doom /games/freedoom1.wad /etc/pkg/repositories /opt/hello-games",
        "b3-ls",
        DIALOG_STEP,
    )?;
    if code == 0 || lines.iter().filter(|l| l.contains("No such file")).count() != 4 {
        return Err(format!(
            "boot 3: Doom, the settings and hello-games should be gone: {lines:?}"
        ));
    }
    let lines = expect_code(run, "pkg check", "b3-check", 0, DIALOG_STEP)?;
    need(&lines, "settings saved", "boot 3")?;
    ctx.report.push("a third boot: only hello and the image, no path of Doom, no /etc/pkg/repositories, pkg check 0".into());
    absolute(run, ctx)
}

/// Step 19: an index with full addresses in `file`, a second directory of the mirror, and a
/// redirect from one address to another: `pkg install doom` puts Doom in again.
fn absolute(run: &mut qemu::Run, ctx: &mut Ctx<'_>) -> Result<(), String> {
    ctx.state(&ctx.states.absolute)?;
    let (lines, requests) = with_log(run, ctx, "pkg install doom", "abs-install", 0)?;
    need(
        &lines,
        &format!(
            "fetching {}/INDEX ... ok (serial 7, signed by stafeto-dev-release)",
            official_address()
        ),
        "step 19",
    )?;
    need(&lines, "(doom), freedoom 0.13.0-1 (dependency)", "step 19")?;
    let storage = pkg_states::STORAGE;
    for wanted in [
        format!("/store/{storage}/doomgeneric-e257a095-1.stpkg 302 0"),
        "/store/moved/doomgeneric-e257a095-1.stpkg 200".to_string(),
        format!("/store/{storage}/freedoom-0.13.0-1.stpkg 200"),
    ] {
        if !got(&requests, &wanted) {
            return Err(format!(
                "step 19: the mirror did not log {wanted}: {requests:?}"
            ));
        }
    }
    expect_code(
        run,
        "ls /bin/doom /games/freedoom1.wad",
        "abs-ls",
        0,
        DIALOG_STEP,
    )?;
    ctx.report.push("an index with full addresses: pkg install doom follows a 302 from one address to another and puts Doom in".into());
    Ok(())
}

/// `cargo xtask pkg-probe [install] [--hvf]`: `install` is steps 1 to 9, the plain command the
/// whole scenario.
pub fn command(args: &[String]) -> Result<(), String> {
    let (mut hvf, mut full) = (false, true);
    for a in args {
        match a.as_str() {
            "install" => full = false,
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
    scenario(machine, full)
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

    /// `runas` gives up the superuser and is for the probe alone: no image of a release holds it.
    #[test]
    fn runas_is_in_no_image_of_the_tree() {
        for image in rootfs::IMAGES {
            let files = rootfs::files_of(image);
            assert!(
                files.iter().all(|f| !f.path.starts_with("/test")),
                "{image} holds a file of the probes"
            );
        }
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
