// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask store-probe [steps]`: the package service (services/pkgd) on QEMU's `virt`
//! with a disk file, the disk service and the file service (tests/store-probe, pk3-design R17).
//!
//! 1. The disk is written here, on the host, by the service's own writer (`pkgd::host`): a
//!    store with `hello` (a program that exits with 42), `broken` (a copy of it with a byte
//!    changed after the signing), `revoked` (signed by a second release key the list of
//!    revocations names), the owner's settings with the repository `games` and its key, and
//!    the list. The service must attach `hello` and the settings, skip the other two with a
//!    line each, and the probe must see all of it.
//! 2. A disk of zeros: the service formats it, and nothing is listed.
//!
//! 3. The full scenario on a disk of zeros: the probe installs `hello` (signed by the
//!    development key), refuses a package for each reason the service has, is refused as a
//!    process that is not the superuser, installs a group (`big` of 16 MiB and `wide` of 1,000
//!    files), changes the settings, the serial and the list of revocations, removes `wide`;
//!    then the machine starts again on the same disk file and the probe finds what stayed.
//!
//! `steps` runs the disk of the first run and then the full scenario with the services under
//! -icount with their step statistics, the reads of the probe going on while the worker receives
//! and checks: every kind of the steps of the package service and of the disk service stays
//! under 0.9 of term B (18,369 ticks).
//!
//! `store-crash` (see `crash`) kills the machine at each crash point of the service and starts it
//! again on the same disk.

use super::*;
use pkgd::host::{self, Contents, FileDevice, Item};
use pkgfmt::cert::PURPOSE_PACKAGES;
use pkgfmt::container::write::{Content, Item as Part, container, sign};
use pkgfmt::meta::Meta;
use pkgfmt::{Certificate, Key, Kind, Revocation, keyfile, sig};
use std::path::{Path, PathBuf};

pub const PKGD_STACK_SIZE: u32 = 32 * 1024;
const DISK_BYTES: u64 = 512 << 20;
/// The tags of the services' lines of steps: the file service 2, the disk 15, the package service 16.
const RAM_TAG: &str = "2";
const PKGD_TAG: &str = "16";
/// The kinds of the package service's steps that must come: all of its methods, the heartbeat,
/// a notification and the departure of a session.
const PKGD_STEP_KINDS: [(usize, &str); 19] = [
    (1, "List"),
    (2, "Info"),
    (3, "InstallBegin"),
    (4, "Feed"),
    (5, "InstallCommit"),
    (6, "InstallCancel"),
    (7, "Remove"),
    (8, "SettingsGet"),
    (9, "SettingsSet"),
    (10, "Serial"),
    (11, "SerialSet"),
    (12, "Clone"),
    (13, "RevokedSet"),
    (14, "Take"),
    (15, "Buffer"),
    (16, "Status"),
    (64, "the heartbeat"),
    (65, "a notification"),
    (66, "the departure of a session"),
];
const BLK_STEP_KINDS: [(usize, &str); 4] = [(1, "Info"), (2, "Read"), (5, "Buffer"), (6, "Take")];
const ENDED: &str = "init: store-probe ended: exit code 0, not restarted";

/// The programs of the image: the services with the features of the run (`steps` for the
/// measurement, `crash` for the crash points).
const fn programs(steps: bool, crash: bool) -> [ImageProgram; 10] {
    let more: &'static [&'static str] = if steps { &["steps"] } else { &[] };
    let pkgd: &'static [&'static str] = if crash { &["crash"] } else { more };
    [
        ("init", "init", INIT_STACK_SIZE, &["table-store-probe"]),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        ("ramfs", "ramfs", RAMFS_STACK_SIZE, more),
        ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
        (
            "posix-process-service",
            "posix-process-service",
            64 * 1024,
            &[],
        ),
        ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
        ("virtio-blk", "virtio-blk", blk_probe::BLK_STACK_SIZE, more),
        ("pkgd", "pkgd", PKGD_STACK_SIZE, pkgd),
        ("store-probe", "store-probe", 4 * POSIX_STACK_SIZE, &[]),
        ("loader", "loader", 0, &[]),
    ]
}
pub const PROGRAMS: [ImageProgram; 10] = programs(false, false);
const PROGRAMS_STEPS: [ImageProgram; 10] = programs(true, false);
const PROGRAMS_CRASH: [ImageProgram; 10] = programs(false, true);

pub fn command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => disk()
            .and_then(|()| empty())
            .and_then(|()| full(false))
            .and_then(|()| deaf())
            .and_then(|()| no_store()),
        Some("steps") => steps(),
        Some("full") => full(false),
        Some("deaf") => deaf(),
        Some("no-store") => no_store(),
        Some("full-steps") => full(true),
        Some("doom") => match args.get(1).map(String::as_str) {
            None => doom(&qemu::VIRT),
            Some("--hvf") => {
                crate::hvf_host()?;
                doom(&qemu::HVF_V2)
            }
            Some(other) => Err(format!("store-probe doom: unknown argument {other}")),
        },
        Some(other) => Err(format!("store-probe: unknown argument {other}")),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The development keys: the root and release key of `keys::dev_keys`, and a second release
/// key with a certificate of the same root, which the list of revocations names.
struct Keys {
    dev: keys::DevKeys,
    second_seed: [u8; 32],
    second: Key,
    second_certificate: [u8; pkgfmt::cert::SIZE],
}

fn dev_keys() -> Result<Keys, String> {
    let tree = root();
    let dev = keys::dev_keys(&tree)?;
    let dir = tree.join("target").join("keys");
    let (second_seed, second) =
        keys::load_or_generate(keys::Role::Release, "stafeto-dev-release-2", &dir, &tree)?;
    let from = now() / 86_400 * 86_400;
    let second_certificate = Certificate::issue(
        &dev.root_seed,
        dev.root.name,
        second.name,
        second.public,
        PURPOSE_PACKAGES,
        from,
        from + 30 * 86_400,
    )
    .to_bytes();
    Ok(Keys {
        dev,
        second_seed,
        second,
        second_certificate,
    })
}

/// The program of a package that is never started: a few bytes after the mark of an executable.
/// Only `hello` runs, and its program is the probe's own file.
const TINY: &[u8] = b"\x7fELF a program that is never run, with room for the manifest to name it";

/// Who signs a package: a key, and the certificate of a root for it (none for a key nobody vouches for).
#[derive(Clone, Copy)]
struct Signer<'a> {
    seed: &'a [u8; 32],
    key: &'a Key,
    certificate: Option<[u8; pkgfmt::cert::SIZE]>,
}

/// What differs between the packages of the probe.
#[derive(Default)]
struct Options {
    /// A series other than the system's.
    series: Option<String>,
    version: Option<String>,
    /// A byte of the program changed before the signing: the manifest names another file.
    bad_manifest: bool,
    /// A file `/etc/passwd`, which the base has.
    passwd: bool,
    /// A byte of the signature changed after the signing.
    bad_signature: bool,
}

/// A package file: a program `/opt/<name>/bin/<name>` of `program`, a hard link to it, and
/// `extra` files of their own.
fn package(
    name: &str,
    program: &[u8],
    signer: Signer<'_>,
    extra: &[(String, Vec<u8>)],
    options: &Options,
) -> Result<Vec<u8>, String> {
    let (dir, bin) = (format!("/opt/{name}"), format!("/opt/{name}/bin"));
    let (path, link) = (
        format!("/opt/{name}/bin/{name}"),
        format!("/opt/{name}/bin/{name}-link"),
    );
    let mut parts = vec![
        Part {
            path: "/opt",
            mode: 0o040_755,
            content: Content::Directory,
        },
        Part {
            path: &dir,
            mode: 0o040_755,
            content: Content::Directory,
        },
        Part {
            path: &bin,
            mode: 0o040_755,
            content: Content::Directory,
        },
        Part {
            path: &path,
            mode: 0o100_755,
            content: Content::Data(program),
        },
        Part {
            path: &link,
            mode: 0o100_755,
            content: Content::Same(&path),
        },
    ];
    let mut extra = extra.to_vec();
    if options.passwd {
        extra.push(("/etc/passwd".into(), b"other\n".to_vec()));
    }
    // A layer lists the directory above each of its entries.
    let mut parents: Vec<&str> = extra
        .iter()
        .filter_map(|(p, _)| p.rsplit_once('/').map(|(d, _)| d))
        .collect();
    parents.dedup();
    for d in parents {
        parts.push(Part {
            path: d,
            mode: 0o040_755,
            content: Content::Directory,
        });
    }
    for (p, bytes) in &extra {
        parts.push(Part {
            path: p,
            mode: 0o100_644,
            content: Content::Data(bytes),
        });
    }
    let series = options.series.clone().unwrap_or_else(pkg::series);
    let version = options.version.as_deref().unwrap_or("1.0");
    let meta = Meta {
        name,
        version,
        release: "1",
        arch: "aarch64",
        series: &series,
        license: "MIT",
        depends: "-",
        provides: "-",
        needs: "-",
        summary: "A package of the store probe",
        url: "https://example.org/store-probe.tar.gz",
        sha256: &"0".repeat(64),
        recipe: &"1".repeat(64),
        commit: &"2".repeat(40),
        relibc: "-",
        size: 0,
    };
    let mut covered =
        container(&meta, &parts, 1_700_000_000).map_err(|e| format!("{name}: {e}"))?;
    if options.bad_manifest {
        let at = covered
            .windows(4)
            .position(|w| w == b"\x7fELF")
            .ok_or("no program in the package")?;
        covered[at + 24] ^= 1;
    }
    let mut bytes = sign(
        covered,
        signer.seed,
        signer.key.name,
        signer.certificate,
        now(),
    )
    .map_err(|e| format!("{name}: {e}"))?;
    if options.bad_signature {
        let at = bytes.len() - 4096 + 130;
        bytes[at] ^= 1;
    }
    Ok(bytes)
}

/// The list of revocations of `serial` that names `revoked`, signed by the root.
fn revoked_list(keys: &Keys, serial: u64, revoked: &[Key]) -> Result<Vec<u8>, String> {
    let entries: Vec<Revocation> = revoked
        .iter()
        .map(|k| Revocation {
            name: k.name,
            since: 0,
        })
        .collect();
    let list = pkgfmt::revoked::write(serial, &entries).map_err(|e| e.to_string())?;
    let digest = pkgfmt::sha::sha256(list.as_bytes());
    let block = pkgfmt::Block::sign(
        &keys.dev.root_seed,
        Kind::Revoked,
        list.len() as u64,
        digest,
        now(),
        keys.dev.root.name,
        None,
    );
    let mut file = list.into_bytes();
    file.extend_from_slice(&block.to_bytes());
    Ok(file)
}

/// The key file line of the owner's repository whose key has the seed `seed`.
fn repository_key(name: &str, seed: u8) -> Result<String, String> {
    Ok(keyfile::public_line(&Key {
        name: pkgfmt::Name::new(name).map_err(|e| e.to_string())?,
        public: sig::public_key(&[seed; 32]),
    }))
}

/// The settings blob of the owner with one repository.
fn settings_blob(name: &str, seed: u8, padding: usize) -> Result<Vec<u8>, String> {
    let key = repository_key(name, seed)?;
    let mut repositories = format!("{name} https://example.org/{name}\n");
    for i in 0..padding {
        repositories.push_str(&format!("disable r{i:04}\n"));
    }
    Ok(proto_pkg::blob::write(&[
        ("repositories", repositories.as_bytes()),
        (&format!("keys/{name}.pub"), key.as_bytes()),
    ]))
}

/// The files of the store: what the probe expects to find, with the packages of the
/// measurement when `steps`.
fn contents(hello: &[u8], steps: bool) -> Result<Contents, String> {
    let keys = dev_keys()?;
    let signer = Signer {
        seed: &keys.dev.release_seed,
        key: &keys.dev.release,
        certificate: Some(keys.dev.certificate),
    };
    let item = |bytes: Vec<u8>| Item {
        bytes,
        repository: "stafeto".into(),
        flags: pkgd::store::WORLD,
        installed: 1,
    };
    let plain = Options::default();
    let good = package("hello", hello, signer, &[], &plain)?;
    let mut broken = package("broken", hello, signer, &[], &plain)?;
    let at = broken
        .windows(4)
        .position(|w| w == b"\x7fELF")
        .ok_or("no program in the package")?;
    broken[at + 24] ^= 1;
    let second_key = Signer {
        seed: &keys.second_seed,
        key: &keys.second,
        certificate: Some(keys.second_certificate),
    };
    let revoked = package("revoked", hello, second_key, &[], &plain)?;
    let mut packages = vec![item(good), item(broken), item(revoked)];
    if steps {
        packages.push(item(package(
            "big",
            hello,
            signer,
            &[("/big/data".into(), big_data())],
            &plain,
        )?));
        packages.push(item(package("wide", hello, signer, &wide_files(), &plain)?));
    }
    let settings = settings_blob("games", 9, 0)?;
    let file = revoked_list(&keys, 2, &[keys.second])?;
    Ok(Contents {
        packages,
        settings: Some(settings),
        revoked: Some((file, 2)),
        repositories: vec![("games".into(), 4)],
    })
}

/// 16 MiB of a pattern in one file.
fn big_data() -> Vec<u8> {
    (0..16usize << 20)
        .map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8)
        .collect()
}

/// 1,000 files of one byte in one directory.
fn wide_files() -> Vec<(String, Vec<u8>)> {
    (0..1000)
        .map(|i| (format!("/wide/f{i:04}"), vec![b'w']))
        .collect()
}

/// The ELF file of `store-probe`, which is the program the package `hello` holds.
fn hello_elf() -> Result<Vec<u8>, String> {
    let mut cmd = cargo();
    cmd.arg("build").args(BOOT_PROFILE.args());
    cmd.args(["--target", PROGRAM_TARGET, "--package", "store-probe"]);
    run_cmd(&mut cmd)?;
    let path = cargo_output(&target_dir(), PROGRAM_TARGET, BOOT_PROFILE, "store-probe");
    std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The image of the probe, trusting the root of the development keys.
fn image(steps: bool) -> Result<PathBuf, String> {
    let name = if steps {
        "boot-store-probe-steps.img"
    } else {
        "boot-store-probe.img"
    };
    let programs: &'static [ImageProgram] = if steps { &PROGRAMS_STEPS } else { &PROGRAMS };
    image_with(name, programs, Vec::new(), None)
}

/// An image whose tree has the files `files` under `/test/`, with the service built to stop at
/// crash point `crash_at` when there is one.
pub fn image_with(
    name: &str,
    programs: &'static [ImageProgram],
    files: Vec<(String, Vec<u8>)>,
    crash_at: Option<u8>,
) -> Result<PathBuf, String> {
    let roots = root().join("target/keys/stafeto-dev-root.pub");
    keys::dev_keys(&root())?;
    let roots = roots.display().to_string();
    let point = crash_at.map(|n| n.to_string());
    let mut env = vec![("STAFETO_PKG_ROOTS", roots.as_str())];
    if let Some(point) = &point {
        env.push(("STAFETO_PKGD_CRASH_AT", point));
    }
    // The directories above the files come first: the tree lists each one.
    let mut dirs: Vec<&'static str> = vec!["/test"];
    if files.iter().any(|(p, _)| p.starts_with("packages/")) {
        dirs.push("/test/packages");
    }
    let mut extra: Vec<rootfs::RootFile> = dirs
        .into_iter()
        .map(|path| rootfs::RootFile {
            path,
            mode: 0o755,
            uid: 0,
            gid: 0,
            source: None,
        })
        .collect();
    extra.extend(files.into_iter().enumerate().map(|(n, (path, bytes))| {
        // The name of a file of the image is 32 bytes at most.
        let file: &'static str = Box::leak(format!("test-{n}").into_boxed_str());
        let path: &'static str = Box::leak(format!("/test/{path}").into_boxed_str());
        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        rootfs::RootFile {
            path,
            mode: 0o444,
            uid: 0,
            gid: 0,
            source: Some(rootfs::Source::Bytes(file, bytes)),
        }
    }));
    write_boot_image_files(name, programs, BOOT_PROFILE, &env, extra)
}

/// The file of a disk run: named by the process, removed at the end.
pub struct Disk(pub PathBuf);

impl Disk {
    pub fn new(what: &str) -> Disk {
        Disk(std::env::temp_dir().join(format!("stafeto-store-{}-{what}.img", std::process::id())))
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn write_disk(
    disk: &Disk,
    contents: Option<&Contents>,
) -> Result<Option<host::Layout>, String> {
    qemu::store_file(&disk.0, DISK_BYTES, true)?;
    let Some(contents) = contents else {
        return Ok(None);
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&disk.0)
        .map_err(|e| format!("{}: {e}", disk.0.display()))?;
    let mut device = FileDevice {
        file,
        blocks: DISK_BYTES / 4096,
    };
    host::write_store(&mut device, contents).map(Some)
}

/// Runs the machine until the probe ends: the lines of its output.
fn run(image: &Path, disk: &Path, steps: bool) -> Result<Vec<String>, String> {
    run_on(&qemu::VIRT, image, disk, steps)
}

/// `run` on `machine`.
fn run_on(
    machine: &qemu::Machine,
    image: &Path,
    disk: &Path,
    steps: bool,
) -> Result<Vec<String>, String> {
    let kernel = build(Variant::Normal)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(image));
    cmd.args(qemu::HEADLESS).args(qemu::store(disk, None));
    if steps {
        cmd.args(qemu::ICOUNT);
    }
    let output = run_until(
        cmd,
        if steps {
            BOOT_TIMEOUT * 40
        } else {
            BOOT_TIMEOUT * 12
        },
        Some("init: store-probe ended: "),
        &kernel.elf,
    )?;
    if let Some(failed) = output
        .lines
        .iter()
        .find(|l| l.starts_with("store-probe: failed"))
    {
        return Err(failed.clone());
    }
    qemu::expect_stopped_on(&output, ENDED)?;
    Ok(output.lines)
}

fn expect(lines: &[String], wanted: &[String]) -> Result<(), String> {
    for line in wanted {
        if !lines.iter().any(|l| l == line) {
            let said: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with("pkgd") || l.starts_with("store-probe"))
                .collect();
            return Err(format!(
                "no line {line:?}; pkgd and the probe said {said:?}"
            ));
        }
    }
    Ok(())
}

/// The lines a run on the store of `hello`, `broken` and `revoked` shows.
fn disk_lines(layout: &host::Layout) -> Vec<String> {
    let mut lines: Vec<String> = [
        "pkgd: roots stafeto-dev-root",
        "pkgd: broken: bad signature, skipped",
        "pkgd: revoked: key revoked, skipped",
        "store-probe: pkgd answers",
        "store-probe: list: hello 1.0 stafeto flags=1",
        "store-probe: serial games=4 stafeto=0 nobody=0",
        "store-probe: settings layer: /etc/pkg/repositories and /etc/pkg/keys/games.pub with mode 0644",
        "store-probe: broken and revoked are not in the tree",
        "store-probe: hello runs from its layer, exit code 42",
        "store-probe: clone, a second buffer and an unknown key are refused as they should be",
        "store-probe: buffers: two places for any session, a third is BUSY, the superuser's session still has one",
        "store-probe: ok",
    ]
    .map(String::from)
    .to_vec();
    lines.push(format!(
        "store-probe: status generation={} blocks={} free={} disk=1 image=0 flags=0",
        layout.generation, layout.blocks, layout.free
    ));
    lines
}

fn disk() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let contents = contents(&hello_elf()?, false)?;
    let file = Disk::new("disk");
    let layout = write_disk(&file, Some(&contents))?.ok_or("no layout")?;
    let lines = run(&image(false)?, &file.0, false)?;
    let mut wanted = disk_lines(&layout);
    wanted.push(format!(
        "pkgd: ready, 1 packages from the disk, 0 from the image, {} blocks free",
        layout.free
    ));
    expect(&lines, &wanted)?;
    println!(
        "store-probe: hello and the settings attached from the disk, broken and revoked skipped, the program of hello run, {} blocks free of {}: ok",
        layout.free, layout.blocks
    );
    Ok(())
}

fn empty() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    hello_elf()?;
    let file = Disk::new("empty");
    write_disk(&file, None)?;
    let lines = run(&image(false)?, &file.0, false)?;
    let blocks = DISK_BYTES / 4096;
    let wanted = [
        format!("pkgd: store formatted, {} blocks", blocks - 2),
        format!(
            "pkgd: ready, 0 packages from the disk, 0 from the image, {} blocks free",
            blocks - 2 - 5
        ),
        "store-probe: empty store: nothing listed, nothing attached".to_string(),
        format!(
            "store-probe: status generation=1 blocks={blocks} free={} disk=0 image=0 flags=0",
            blocks - 2 - 5
        ),
    ];
    expect(&lines, &wanted)?;
    println!("store-probe: a disk of zeros is formatted and lists nothing: ok");
    Ok(())
}

/// The steps of a kind in `rows` against the kinds that must come and the bound.
fn judge(who: &str, rows: &[(usize, u64, u64)], kinds: &[(usize, &str)]) -> Result<(), String> {
    for (kind, name) in kinds {
        if !rows.iter().any(|(k, ..)| k == kind) {
            return Err(format!("{who}: no step {name}: {rows:?}"));
        }
    }
    match rows.iter().find(|r| r.1 > blk_probe::STEP_MAX) {
        Some(row) => Err(format!(
            "{who}: a step past 0.9 of term B ({}): {row:?}",
            blk_probe::STEP_MAX
        )),
        None => Ok(()),
    }
}

/// The longest of each kind in two runs.
fn merge(a: Vec<(usize, u64, u64)>, b: Vec<(usize, u64, u64)>) -> Vec<(usize, u64, u64)> {
    let mut out = a;
    for row in b {
        match out.iter_mut().find(|r| r.0 == row.0) {
            Some(have) if have.1 >= row.1 => {}
            Some(have) => *have = row,
            None => out.push(row),
        }
    }
    out
}

fn steps() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let contents = contents(&hello_elf()?, true)?;
    let file = Disk::new("steps");
    let layout = write_disk(&file, Some(&contents))?.ok_or("no layout")?;
    let lines = run(&image(true)?, &file.0, true)?;
    expect(&lines, &disk_lines(&layout)[..4])?;
    // The full scenario under the same measurement: every method of the service comes.
    let full = full_run(true)?;
    let both = |tag: &str| merge(longest_steps(&lines, tag), longest_steps(&full, tag));
    let pkgd = both(PKGD_TAG);
    let blk = both(blk_probe::BLK_TAG);
    let ram = both(RAM_TAG);
    judge("pkgd", &pkgd, &PKGD_STEP_KINDS)?;
    judge("the disk service", &blk, &BLK_STEP_KINDS)?;
    // The file service: the layer calls the worker makes while the main thread answers.
    let ram: Vec<_> = ram
        .into_iter()
        .filter(|r| matches!(r.0, 51 | 53 | 64 | 65))
        .collect();
    judge("the file service", &ram, &[])?;
    check_waits(
        &lines,
        &[PKGD_TAG, blk_probe::BLK_TAG, RAM_TAG],
        "store-probe",
    )?;
    check_waits(
        &full,
        &[PKGD_TAG, blk_probe::BLK_TAG, RAM_TAG],
        "store-probe full",
    )?;
    let text = |rows: &[(usize, u64, u64)]| {
        rows.iter()
            .map(|(k, t, _)| format!("kind {k} {t}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!("store-probe steps: pkgd {}", text(&pkgd));
    println!("store-probe steps: the disk service {}", text(&blk));
    println!("store-probe steps: the file service {}", text(&ram));
    for line in lines.iter().chain(&full).filter(|l| {
        l.starts_with("pkgd: work") || l.starts_with("pkgd: memory") || l.starts_with("pkgd: ready")
    }) {
        println!("{line}");
    }
    println!(
        "store-probe steps: every step of the package service under 0.9 of term B ({}): ok",
        blk_probe::STEP_MAX
    );
    Ok(())
}

/// The packages and the blobs of the scenarios, as the files of the image (with the index the
/// probe reads) and the number of blocks each package takes.
struct World {
    files: Vec<(String, Vec<u8>)>,
    blocks: std::collections::BTreeMap<String, u64>,
    /// The bytes of the blob of settings the crash scenario installs.
    settings1: usize,
    /// The bytes of the second blob, which comes in more than one part.
    settings2: usize,
}

impl World {
    fn blocks(&self, name: &str) -> u64 {
        self.blocks.get(name).copied().unwrap_or(0)
    }
}

/// What the scenarios need: the files of `/test/packages/` and the mode file.
fn make_world(hello: &[u8], steps: bool, mode: &str) -> Result<World, String> {
    let keys = dev_keys()?;
    let official = Signer {
        seed: &keys.dev.release_seed,
        key: &keys.dev.release,
        certificate: Some(keys.dev.certificate),
    };
    let second_key = Signer {
        seed: &keys.second_seed,
        key: &keys.second,
        certificate: Some(keys.second_certificate),
    };
    let unknown_seed = [77u8; 32];
    let unknown = Key {
        name: pkgfmt::Name::new("other-key").map_err(|e| e.to_string())?,
        public: sig::public_key(&unknown_seed),
    };
    let nobody = Signer {
        seed: &unknown_seed,
        key: &unknown,
        certificate: None,
    };
    let plain = Options::default();
    let tiny = TINY;
    let wide = wide_files();
    let big = [("/big/data".to_string(), big_data())];
    let mut packages: Vec<(String, Vec<u8>)> = vec![
        (
            "hello".into(),
            package("hello", hello, official, &[], &plain)?,
        ),
        (
            "second".into(),
            package("second", tiny, official, &[], &plain)?,
        ),
        ("big".into(), package("big", tiny, official, &big, &plain)?),
        (
            "wide".into(),
            package("wide", tiny, official, &wide, &plain)?,
        ),
        (
            "keyb".into(),
            package("keyb", tiny, second_key, &[], &plain)?,
        ),
        (
            "bad-sig".into(),
            package(
                "bad-sig",
                tiny,
                official,
                &[],
                &Options {
                    bad_signature: true,
                    ..Options::default()
                },
            )?,
        ),
        (
            "other-key".into(),
            package("other-key", tiny, nobody, &[], &plain)?,
        ),
        (
            "old-series".into(),
            package(
                "old-series",
                tiny,
                official,
                &[],
                &Options {
                    series: Some("0.0".into()),
                    ..Options::default()
                },
            )?,
        ),
        (
            "bad-manifest".into(),
            package(
                "bad-manifest",
                tiny,
                official,
                &[],
                &Options {
                    bad_manifest: true,
                    ..Options::default()
                },
            )?,
        ),
        (
            "conflict".into(),
            package(
                "conflict",
                tiny,
                official,
                &[],
                &Options {
                    passwd: true,
                    ..Options::default()
                },
            )?,
        ),
    ];
    // A new version of `hello`, one that conflicts, and the owner's repository: its key is the
    // one the settings blob of `games2` holds, and the release key is not.
    let own_seed = [10u8; 32];
    let own_key = Key {
        name: pkgfmt::Name::new("games2").map_err(|e| e.to_string())?,
        public: sig::public_key(&own_seed),
    };
    let owner = Signer {
        seed: &own_seed,
        key: &own_key,
        certificate: None,
    };
    packages.push((
        "hello-2".into(),
        package(
            "hello",
            hello,
            official,
            &[],
            &Options {
                version: Some("2.0".into()),
                ..Options::default()
            },
        )?,
    ));
    packages.push((
        "hello-conflict".into(),
        package(
            "hello",
            tiny,
            official,
            &[],
            &Options {
                version: Some("3.0".into()),
                passwd: true,
                ..Options::default()
            },
        )?,
    ));
    packages.push(("own".into(), package("own", tiny, owner, &[], &plain)?));
    packages.push((
        "own-bad".into(),
        package("own-bad", tiny, official, &[], &plain)?,
    ));
    if steps {
        // Names and versions as long as they may be: the worst LIST.
        for n in 1..=5 {
            let name = format!("long-name-package-{}{n}", "a".repeat(44));
            let version = format!("1.{}", "0".repeat(60) + &n.to_string());
            let version = version[..63].to_string();
            let options = Options {
                version: Some(version),
                ..Options::default()
            };
            packages.push((name.clone(), package(&name, tiny, official, &[], &options)?));
        }
    }
    let mut files = Vec::new();
    let mut blocks = std::collections::BTreeMap::new();
    let mut index = String::new();
    for (stem, bytes) in &packages {
        // The name and the version are the package's own; the file is `<stem>.pkg`.
        let (name, meta_version) = pkgfmt::Package::parse(bytes)
            .map(|p| (p.meta.name.to_string(), p.meta.version.to_string()))
            .unwrap_or_else(|_| (stem.clone(), "1.0".to_string()));
        index.push_str(&format!(
            "{name} {meta_version} {} {} {stem}\n",
            bytes.len(),
            hex_of(&pkgfmt::sha::sha256(bytes))
        ));
        blocks.insert(stem.clone(), bytes.len() as u64 / 4096);
        files.push((format!("packages/{stem}.pkg"), bytes.clone()));
    }
    files.push(("packages/index".into(), index.into_bytes()));
    let settings1 = settings_blob("games", 9, 0)?;
    let settings2 = settings_blob("games2", 10, 1500)?;
    // A blob that breaks the rules: the key of the official repository is not the owner's.
    let key = repository_key("stafeto", 3)?;
    let bad = proto_pkg::blob::write(&[("keys/stafeto.pub", key.as_bytes())]);
    let (len1, len2) = (settings1.len(), settings2.len());
    files.push(("packages/settings1.blob".into(), settings1));
    files.push(("packages/settings2.blob".into(), settings2));
    files.push(("packages/settings-bad.blob".into(), bad));
    files.push((
        "packages/revoked-2.list".into(),
        revoked_list(&keys, 2, &[keys.second])?,
    ));
    files.push((
        "packages/revoked-1.list".into(),
        revoked_list(&keys, 1, &[])?,
    ));
    files.push(("mode".into(), format!("{mode}\n").into_bytes()));
    Ok(World {
        files,
        blocks,
        settings1: len1,
        settings2: len2,
    })
}

fn hex_of(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The lines of the full scenario's first run.
fn full_lines(world: &World, steps: bool) -> Vec<String> {
    let mut lines: Vec<String> = [
        "pkgd: roots stafeto-dev-root",
        "store-probe: pkgd answers",
        "store-probe: hello installed: the path is there, the program runs, the space is the package's",
        "store-probe: refused BAD_SIGNATURE, nothing changed",
        "store-probe: refused UNTRUSTED_KEY, nothing changed",
        "store-probe: refused WRONG_SERIES, nothing changed",
        "store-probe: refused BAD_MANIFEST, nothing changed",
        "store-probe: refused CONFLICT, nothing changed",
        "store-probe: refused BAD_HASH, nothing changed",
        "store-probe: refused TOO_LONG, the receipt is gone, nothing changed",
        "store-probe: INSTALL_CANCEL: the receipt is gone, the state is as it was",
        "store-probe: refused NO_MEMORY, nothing changed",
        "store-probe: refused NO_SPACE, nothing changed",
        "store-probe: refused INVALID for a repository the store does not know, nothing changed",
        "store-probe: not allowed without UID 0, or without an identity session: begin, remove, serial, settings, revoked",
        "store-probe: a session that goes at once, or with a receipt open, leaves the store free",
        "store-probe: another session cannot feed, commit or cancel a receipt it does not hold",
        "store-probe: group of big and wide: nothing before its end, both after, one generation",
        "store-probe: hello replaced by version 2.0: the new program runs, a replacement that conflicts is refused and the old one runs",
        "store-probe: own repository: a package signed by the key of games2 is installed, one signed by the release key is UNTRUSTED_KEY",
        "store-probe: settings: a blob that breaks the rules is INVALID, the old one stays",
        "store-probe: serial: 2 is set, 1 is ROLLBACK, 2 again changes nothing",
        "store-probe: revoked: keyb is detached and flagged, an older list is ROLLBACK, a bad signature is BAD_SIGNATURE, the key is REVOKED",
        "pkgd: keyb: key revoked, detached",
        "store-probe: removed wide: the names are gone, its space is back, a second REMOVE is NOT_FOUND",
        "store-probe: full scenario done",
        "store-probe: ok",
    ]
    .map(String::from)
    .to_vec();
    let parts = world.settings2.div_ceil(16_384);
    lines.push(format!(
        "store-probe: settings: games then games2, the layer follows, the blob reads back whole in {parts} parts"
    ));
    if steps {
        lines.push("store-probe: five packages of the longest names are listed".into());
    }
    lines
}

/// The numbers of the line `store-probe: <what> generation=G free=F disk=D`.
fn status_numbers(lines: &[String], what: &str) -> Result<(u64, u64, u64), String> {
    let line = lines
        .iter()
        .find_map(|l| l.strip_prefix(&format!("store-probe: {what} generation=")))
        .ok_or_else(|| format!("no line `{what}`"))?;
    let words: Vec<&str> = line.split([' ', '=']).collect();
    let number = |i: usize| -> Result<u64, String> {
        words
            .get(i)
            .and_then(|w| w.parse().ok())
            .ok_or_else(|| format!("the line `{what}`: {line}"))
    };
    Ok((number(0)?, number(2)?, number(4)?))
}

/// The full scenario on a disk of zeros, then the machine again on the same disk.
fn full(steps: bool) -> Result<(), String> {
    full_run(steps).map(drop)
}

/// The same, and the lines of the first run.
fn full_run(steps: bool) -> Result<Vec<String>, String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let mode = if steps { "full-steps" } else { "full" };
    let world = make_world(&hello_elf()?, steps, mode)?;
    let name = if steps {
        "boot-store-full-steps.img"
    } else {
        "boot-store-full.img"
    };
    let programs: &'static [ImageProgram] = if steps { &PROGRAMS_STEPS } else { &PROGRAMS };
    let blocks_hello = world.blocks("hello");
    let image = image_with(name, programs, world.files.clone(), None)?;
    let file = Disk::new(mode);
    write_disk(&file, None)?;
    let first = run(&image, &file.0, steps)?;
    expect(&first, &full_lines(&world, steps))?;
    let (generation, free, disk) = status_numbers(&first, "final status")?;
    // The second run: the same machine on the same disk file.
    let second = run(&image, &file.0, steps)?;
    let wanted = [
        "pkgd: roots stafeto-dev-root".to_string(),
        "pkgd: keyb: key revoked, skipped".to_string(),
        "store-probe: restart: hello runs, big, the settings and the serial are in place, wide and keyb are not".to_string(),
        "store-probe: ok".to_string(),
        format!("store-probe: status generation={generation} free={free} disk={}", disk - 1),
    ];
    expect(&second, &wanted)?;
    println!(
        "store-probe: full: hello installed (signed by the development key, {blocks_hello} blocks), every refusal, NOT_ALLOWED without UID 0, a group of big and wide, the settings, the serial and the list of revocations, REMOVE; after the restart the packages, the settings and the serial are in place (generation {generation}, {free} blocks free): ok"
    );
    Ok(first)
}

/// The disk service built to stop answering at the first write of a package's data
/// (`deaf`), the package service with a wait of 3 s for it (`short-deadline`): the
/// installation of `big` is refused IO within the wait, the store is as it was and free, the
/// next installation is refused at once.
fn deaf() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let world = make_world(&hello_elf()?, false, "deaf")?;
    let mut list = PROGRAMS.to_vec();
    for program in &mut list {
        match program.0 {
            "virtio-blk" => program.3 = &["deaf"],
            "pkgd" => program.3 = &["short-deadline"],
            _ => {}
        }
    }
    let programs: &'static [ImageProgram] = Box::leak(list.into_boxed_slice());
    let image = image_with("boot-store-deaf.img", programs, world.files.clone(), None)?;
    let file = Disk::new("deaf");
    write_disk(&file, None)?;
    let lines = run(&image, &file.0, false)?;
    expect(
        &lines,
        &[
            "pkgd: the disk service did not answer in time".to_string(),
            "store-probe: ok".to_string(),
        ],
    )?;
    let said = lines
        .iter()
        .find(|l| l.starts_with("store-probe: the disk stopped answering"))
        .ok_or("the probe did not say how the disk's silence ended")?;
    println!(
        "store-probe deaf: {}",
        said.trim_start_matches("store-probe: ")
    );
    Ok(())
}

/// The disk service deaf from its first read: the start of the package service fails on the
/// disk, and the service still says READY, shows the failure in STATUS and refuses a change.
fn no_store() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let world = make_world(&hello_elf()?, false, "no-store")?;
    let mut list = PROGRAMS.to_vec();
    for program in &mut list {
        match program.0 {
            "virtio-blk" => program.3 = &["deaf-start"],
            "pkgd" => program.3 = &["short-deadline"],
            _ => {}
        }
    }
    let programs: &'static [ImageProgram] = Box::leak(list.into_boxed_slice());
    let image = image_with(
        "boot-store-no-store.img",
        programs,
        world.files.clone(),
        None,
    )?;
    let file = Disk::new("no-store");
    write_disk(&file, None)?;
    let lines = run(&image, &file.0, false)?;
    expect(
        &lines,
        &[
            "pkgd: the disk service did not answer in time".to_string(),
            "store-probe: ok".to_string(),
        ],
    )?;
    let said = lines
        .iter()
        .find(|l| l.starts_with("store-probe: the start failed on the disk"))
        .ok_or("the probe did not say how the failed start ended")?;
    println!(
        "store-probe no-store: {}",
        said.trim_start_matches("store-probe: ")
    );
    Ok(())
}

/// The crash points of the note, each with what its scenario starts and what the machine finds
/// after it is killed there and started again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    /// The state before the change.
    Old,
    /// The state before or the state after, whole.
    Either,
    /// The state after.
    New,
    /// A store formatted again.
    Formatted,
}

/// The scenario of a point: the mode of the probe, the packages on the disk before, the
/// state after.
struct Case {
    mode: &'static str,
    /// The names on the disk the host writes before the run.
    before: &'static [&'static str],
    after: After,
}

fn case(point: u8) -> Case {
    match point {
        1..=9 => Case {
            mode: "crash-install",
            before: &["hello"],
            after: match point {
                8 => After::Either,
                9 => After::New,
                _ => After::Old,
            },
        },
        10 | 11 => Case {
            mode: "crash-remove",
            before: &["hello", "second"],
            after: if point == 10 { After::Old } else { After::New },
        },
        12 => Case {
            mode: "crash-settings",
            before: &["hello"],
            after: After::Old,
        },
        _ => Case {
            mode: "crash-format",
            before: &[],
            after: After::Formatted,
        },
    }
}

/// The names the machine lists, and the numbers of its status line, in `lines`.
fn state_of(lines: &[String]) -> Result<(u64, u64, u64, Vec<String>, u64), String> {
    let (generation, free, disk) = {
        let line = lines
            .iter()
            .find_map(|l| l.strip_prefix("store-probe: state generation="))
            .ok_or("no line `state`")?;
        let words: Vec<&str> = line.split([' ', '=']).collect();
        let n = |i: usize| words.get(i).and_then(|w| w.parse::<u64>().ok());
        (
            n(0).ok_or("the generation")?,
            n(2).ok_or("the free blocks")?,
            n(4).ok_or("the packages")?,
        )
    };
    let mut names: Vec<String> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("store-probe: state package "))
        .map(|l| l.split(' ').next().unwrap_or("").to_string())
        .collect();
    names.sort();
    let settings = lines
        .iter()
        .find_map(|l| l.strip_prefix("store-probe: state settings bytes="))
        .and_then(|l| l.split(' ').next()?.parse().ok())
        .ok_or("the settings line")?;
    Ok((generation, free, disk, names, settings))
}

/// `cargo xtask store-crash [N]`: the service built to stop at crash point N (and all 13 when no
/// N is given), the machine killed on its line, then started again on the same disk file; the
/// store it finds is the whole old state, the whole new one (point 8 may be either) or a new
/// format (point 13), and the free space is the disk less what the packages of the state take.
pub fn crash(args: &[String]) -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let points: Vec<u8> = match args.first() {
        None => (1..=13).collect(),
        Some(n) => vec![
            n.parse()
                .ok()
                .filter(|n| (1..=13).contains(n))
                .ok_or_else(|| format!("store-crash: {n} is not a crash point"))?,
        ],
    };
    let hello = hello_elf()?;
    for point in points {
        crash_point(point, &hello)?;
    }
    Ok(())
}

fn crash_point(point: u8, hello: &[u8]) -> Result<(), String> {
    let c = case(point);
    let name = pkgd::commit::Point::ALL[usize::from(point) - 1].name();
    let world = make_world(hello, false, c.mode)?;
    let file = Disk::new(&format!("crash-{point}"));
    // The disk before: the packages the host wrote, or zeros.
    let keys = dev_keys()?;
    let official = Signer {
        seed: &keys.dev.release_seed,
        key: &keys.dev.release,
        certificate: Some(keys.dev.certificate),
    };
    let item = |name: &str| -> Result<Item, String> {
        Ok(Item {
            bytes: package(
                name,
                if name == "hello" { hello } else { TINY },
                official,
                &[],
                &Options::default(),
            )?,
            repository: "stafeto".into(),
            flags: pkgd::store::WORLD,
            installed: 1,
        })
    };
    let layout = if c.before.is_empty() {
        write_disk(&file, None)?;
        None
    } else {
        let contents = Contents {
            packages: c.before.iter().map(|n| item(n)).collect::<Result<_, _>>()?,
            ..Contents::default()
        };
        write_disk(&file, Some(&contents))?
    };
    // The machine that stops at the point.
    let crash_image = image_with(
        &format!("boot-store-crash-{point}.img"),
        &PROGRAMS_CRASH,
        world.files.clone(),
        Some(point),
    )?;
    let kernel = build(Variant::Normal)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&crash_image));
    cmd.args(qemu::HEADLESS).args(qemu::store(&file.0, None));
    let marker = format!("pkgd: crash point {point} {name}");
    let output = run_until(cmd, BOOT_TIMEOUT * 6, Some(&marker), &kernel.elf)?;
    if !output.stopped_on_marker {
        let said: Vec<_> = output
            .lines
            .iter()
            .filter(|l| l.starts_with("pkgd") || l.starts_with("store-probe"))
            .collect();
        return Err(format!(
            "store-crash {point} {name}: the service never said {marker:?}: {said:?}"
        ));
    }
    // The same disk, the ordinary service, a probe that says what it finds.
    let verify = make_world(hello, false, "verify")?;
    let verify_image = image_with("boot-store-crash-verify.img", &PROGRAMS, verify.files, None)?;
    let lines = run(&verify_image, &file.0, false)?;
    let (generation, free, disk, names, settings) = state_of(&lines)?;
    let blocks = DISK_BYTES / 4096;
    let (old_generation, old_free) = layout
        .as_ref()
        .map_or((1, blocks - 2 - 5), |l| (l.generation, l.free));
    let mut old_names: Vec<String> = c.before.iter().map(|s| s.to_string()).collect();
    old_names.sort();
    let (new_generation, new_free, new_names, new_settings) = match point {
        1..=9 => {
            let mut n = old_names.clone();
            n.push("second".into());
            n.sort();
            (old_generation + 1, old_free - world.blocks("second"), n, 0)
        }
        10 | 11 => (
            old_generation + 1,
            old_free + world.blocks("second"),
            vec!["hello".to_string()],
            0,
        ),
        12 => (
            old_generation + 1,
            old_free - (world.settings1 as u64).div_ceil(4096),
            old_names.clone(),
            world.settings1 as u64,
        ),
        _ => (1, blocks - 2 - 5, Vec::new(), 0),
    };
    let found = (generation, free, names.clone(), settings);
    let old = (old_generation, old_free, old_names.clone(), 0);
    let new = (new_generation, new_free, new_names, new_settings);
    let ok = match c.after {
        After::Old => found == old,
        After::New | After::Formatted => found == new,
        After::Either => found == old || found == new,
    };
    if !ok {
        return Err(format!(
            "store-crash {point} {name}: found generation {generation}, {free} blocks free, {disk} packages {names:?}, settings {settings} bytes; the old state is {old:?}, the new one {new:?}"
        ));
    }
    if c.after == After::Formatted
        && !lines
            .iter()
            .any(|l| l.starts_with("pkgd: store formatted, "))
    {
        return Err(format!(
            "store-crash {point} {name}: the disk was not formatted again"
        ));
    }
    // The tree follows the state: the program of `second` is there when the state has it.
    let has_second = found.2.iter().any(|n| n == "second");
    let tree = format!(
        "store-probe: state tree /opt/second/bin/second {}",
        if has_second { "yes" } else { "no" }
    );
    expect(&lines, &[tree])?;
    println!(
        "store-crash {point} {name}: killed there, found {} (generation {generation}, {free} blocks free, {} packages): ok",
        match (found == old, found == new) {
            _ if c.after == After::Formatted => "a store formatted again",
            (true, false) => "the old state",
            (false, true) => "the new state",
            _ => "the old state, which is also the new",
        },
        disk
    );
    Ok(())
}

/// `cargo xtask store-probe doom`: Doom from the packages `freedoom` and `doomgeneric` of
/// `target/pkg` (`cargo xtask pkg-build freedoom doomgeneric`) installed as a group on a disk of
/// zeros, the memory the service holds after it, and the machine started again on the same disk.
fn doom(machine: &qemu::Machine) -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let dir = root().join("target/pkg");
    let find = |prefix: &str| -> Result<(String, Vec<u8>), String> {
        let found = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(Result::ok)
            .find(|f| f.file_name().to_string_lossy().starts_with(prefix));
        let path = found
            .ok_or_else(|| {
                format!("no {prefix}* in target/pkg: cargo xtask pkg-build freedoom doomgeneric")
            })?
            .path();
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok((prefix.trim_end_matches('-').to_string(), bytes))
    };
    let packages = [find("freedoom-")?, find("doomgeneric-")?];
    let mut files = Vec::new();
    let mut index = String::new();
    let mut pages = 0;
    for (name, bytes) in &packages {
        let package = pkgfmt::Package::parse(bytes).map_err(|e| format!("{name}: {e}"))?;
        index.push_str(&format!(
            "{name} {} {} {}\n",
            package.meta.version,
            bytes.len(),
            hex_of(&pkgfmt::sha::sha256(bytes))
        ));
        pages += bytes.len() / 4096;
        files.push((format!("packages/{name}.pkg"), bytes.clone()));
    }
    files.push(("packages/index".into(), index.into_bytes()));
    files.push(("mode".into(), b"doom\n".to_vec()));
    let image = image_with("boot-store-doom.img", &PROGRAMS, files, None)?;
    hello_elf()?;
    let file = Disk::new("doom");
    write_disk(&file, None)?;
    let first = run_on(machine, &image, &file.0, false)?;
    expect(
        &first,
        &["store-probe: Doom installed: freedoom and doomgeneric as a group, the program and the WAD are in the tree".to_string()],
    )?;
    let second = run_on(machine, &image, &file.0, false)?;
    expect(
        &second,
        &["store-probe: restart: Doom is in place, listed and in the tree".to_string()],
    )?;
    println!("store-probe doom: the packages take {pages} pages of the disk");
    for line in first.iter().chain(&second).filter(|l| {
        l.starts_with("pkgd: memory")
            || l.starts_with("store-probe: Doom installed in")
            || l.starts_with("store-probe: pkgd ready after")
            || l.starts_with("pkgd: ready")
            || l.starts_with("pkgd: start took")
    }) {
        println!("{line}");
    }
    println!(
        "store-probe doom on {}: Doom installed as a group, in place after the restart: ok",
        machine.name
    );
    Ok(())
}
