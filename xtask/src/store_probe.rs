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
/// The longest a run of the machine with the NVMe disk may take on TCG, edk2 and the loader included.
const WITHIN: Duration = Duration::from_secs(480);
/// The kinds of the package service's steps that must come: all of its methods, the heartbeat,
/// a notification and the departure of a session.
const PKGD_STEP_KINDS: [(usize, &str); 20] = [
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
    (17, "WorldSet"),
    (64, "the heartbeat"),
    (65, "a notification"),
    (66, "the departure of a session"),
];
const BLK_STEP_KINDS: [(usize, &str); 4] = [(1, "Info"), (2, "Read"), (5, "Buffer"), (6, "Take")];
const ENDED: &str = "init: store-probe ended: exit code 0, not restarted";

/// The programs of the image: the services with the features of the run (`steps` for the
/// measurement, `crash` for the crash points).
const fn programs(steps: bool, crash: bool) -> [ImageProgram; 12] {
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
        (
            "virtio-rng",
            "virtio-rng",
            crate::entropy::RNG_STACK_SIZE,
            &[],
        ),
        (
            "entropy",
            "entropy",
            crate::entropy::ENTROPY_STACK_SIZE,
            &[],
        ),
    ]
}
pub const PROGRAMS: [ImageProgram; 12] = programs(false, false);
const PROGRAMS_STEPS: [ImageProgram; 12] = programs(true, false);
const PROGRAMS_CRASH: [ImageProgram; 12] = programs(false, true);

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
pub(crate) struct Keys {
    pub(crate) dev: keys::DevKeys,
    second_seed: [u8; 32],
    second: Key,
    second_certificate: [u8; pkgfmt::cert::SIZE],
}

pub(crate) fn dev_keys() -> Result<Keys, String> {
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
pub(crate) const TINY: &[u8] =
    b"\x7fELF a program that is never run, with room for the manifest to name it";

/// Who signs a package: a key, and the certificate of a root for it (none for a key nobody vouches for).
#[derive(Clone, Copy)]
pub(crate) struct Signer<'a> {
    pub(crate) seed: &'a [u8; 32],
    pub(crate) key: &'a Key,
    pub(crate) certificate: Option<[u8; pkgfmt::cert::SIZE]>,
}

/// What differs between the packages of the probe.
#[derive(Default)]
pub(crate) struct Options {
    /// A series other than the system's.
    pub(crate) series: Option<String>,
    pub(crate) version: Option<String>,
    /// The `depends` line of `meta`, `-` when none.
    pub(crate) depends: Option<String>,
    /// A byte of the program changed before the signing: the manifest names another file.
    pub(crate) bad_manifest: bool,
    /// A file `/etc/passwd`, which the base has.
    pub(crate) passwd: bool,
    /// A byte of the signature changed after the signing.
    pub(crate) bad_signature: bool,
}

/// A package file: a program `/opt/<name>/bin/<name>` of `program`, a hard link to it, and
/// `extra` files of their own.
pub(crate) fn package(
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
        depends: options.depends.as_deref().unwrap_or("-"),
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
pub(crate) fn repository_key(name: &str, seed: u8) -> Result<String, String> {
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
pub(crate) fn hello_elf() -> Result<Vec<u8>, String> {
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
    Ok(apart(&output.lines))
}

/// The lines of the package service that the probes look for, as they begin.
const WHOLE_STARTS: [&str; 4] = [
    "pkgd: roots ",
    "pkgd: broken: ",
    "pkgd: revoked: ",
    "pkgd: keyb: ",
];

/// `lines` with a line of the package service that another writer's text came in front of set
/// apart. The console takes a line of another service in several writes (the audit and the
/// timing lines print their parts one after the other), and a line of pkgd that lands between
/// them begins in the middle of the line it fell in: `xxxpkgd: roots stafeto-dev-root`. The
/// text in front and the line are two lines again; only the exact starts of `WHOLE_STARTS`
/// count, so a text that merely names them stays.
fn apart(lines: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        let cut = WHOLE_STARTS
            .iter()
            .filter_map(|start| line.find(start))
            .min()
            .filter(|&at| at > 0 && !line.starts_with("store-probe: "));
        match cut {
            Some(at) => {
                out.push(line[..at].to_owned());
                out.push(line[at..].to_owned());
            }
            None => out.push(line.clone()),
        }
    }
    out
}

/// The lines of the full scenario a measured run must show: those of the probe. The first lines of the
/// package service come while every service starts and print at once, and the console drops some of
/// them under -icount.
fn steady_lines(world: &World) -> Vec<String> {
    measured(true, full_lines(world, true))
}

/// The lines `wanted` of a run, less those of the package service when the run is measured
/// (`steps`): the service prints them while every service starts, the kernel log holds a bounded
/// number of records and says `[kernel log: N records lost]` when a burst overruns it, so a short
/// line of the start (one record) may be among the lost. The lines of the probe come after the
/// start and stay.
fn measured(steps: bool, wanted: Vec<String>) -> Vec<String> {
    if steps {
        wanted
            .into_iter()
            .filter(|l| !l.starts_with("pkgd: "))
            .collect()
    } else {
        wanted
    }
}

/// `expect` for a run under -icount on the machine of the firmware, where the lines of the services come
/// glued to each other: each wanted line is part of some line.
fn expect_within(lines: &[String], wanted: &[String]) -> Result<(), String> {
    for line in wanted {
        if !lines.iter().any(|l| l.contains(line.as_str())) {
            let said: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("pkgd") || l.contains("store-probe"))
                .collect();
            return Err(format!(
                "no line {line:?}; pkgd and the probe said {said:?}"
            ));
        }
    }
    Ok(())
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

/// The records the kernel log lost in a run: the numbers of its `[kernel log: N records lost]`
/// lines. The burst at the start of the NVMe service's clients overruns the bounded log, and the
/// step lines of the first calls (Info, Buffer) are among the records it loses, so a missing
/// kind is reported with these numbers (stafeto/stafeto#455).
fn lost_records(lines: &[String]) -> Vec<u64> {
    lines
        .iter()
        .filter_map(|l| {
            let at = l.find("[kernel log: ")?;
            l[at + "[kernel log: ".len()..]
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .collect()
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
    expect(&lines, &measured(true, disk_lines(&layout)[..4].to_vec()))?;
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
    if steps {
        expect_within(&first, &steady_lines(&world))?;
    } else {
        expect(&first, &full_lines(&world, steps))?;
    }
    let (generation, free, disk) = status_numbers(&first, "final status")?;
    // The second run: the same machine on the same disk file.
    let second = run(&image, &file.0, steps)?;
    let wanted = measured(
        steps,
        vec![
        "pkgd: roots stafeto-dev-root".to_string(),
        "pkgd: keyb: key revoked, skipped".to_string(),
        "store-probe: restart: hello runs, big, the settings and the serial are in place, wide and keyb are not".to_string(),
        "store-probe: ok".to_string(),
        format!("store-probe: status generation={generation} free={free} disk={}", disk - 1),
        ],
    );
    expect(&second, &wanted)?;
    println!(
        "store-probe: full: hello installed (signed by the development key, {blocks_hello} blocks), every refusal, NOT_ALLOWED without UID 0, a group of big and wide, the settings, the serial and the list of revocations, REMOVE; after the restart the packages, the settings and the serial are in place (generation {generation}, {free} blocks free): ok"
    );
    Ok(first)
}

/// `cargo xtask nvme-persist [breaks|lba4096|mdts1|steps|key [nodisk|wrongdisk [breaks]|foreign|image [grown]]|blk-probe]`: the package service on an NVMe disk that outlives the machine.
/// The machine is `EFI` (edk2, ITS, ACPI: the boot disk is the first NVMe controller, with the loader, the
/// kernel and the boot image of the store probe), with a second NVMe controller over a file of zeros that
/// is the store: init walks the bus, finds that controller by its PCI id and index, and the service
/// `nvme-blk` (MSI-X on the ITS, the polling of the queue behind it) is the `blk` of the package
/// service. The first run is the whole scenario of `store-probe full` (the format of the store, the
/// installation of `hello`, every refusal, a group of packages, the settings, REMOVE), after which QEMU
/// is killed once the probe has ended and nothing is in flight (the data are the ones the service
/// and the controller took; the survival of the store format over a cut at each point of a write is
/// the evidence of `store-crash`, 13 crash points, on Virtio); the second run starts the machine on the same file and the probe
/// finds `hello` installed and running, the settings and the serial in place. With `breaks` the service
/// writes one sector past where it is asked (`break-nvme-write-offset`), and the probe must not pass; `lba4096`
/// gives the disk blocks of 4 KiB and `mdts1` a transfer limit of 8 KiB; `steps` runs the first scenario
/// under -icount with the steps of the services counted and holds the NVMe service's to 0.9 of term B.
pub fn nvme_persist(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("key") => {
            let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();
            let (case, breaks) = match rest.as_slice() {
                [] => (KeyCase::Normal, false),
                ["nodisk"] => (KeyCase::NoDisk, false),
                ["wrongdisk"] => (KeyCase::WrongDisk, false),
                ["wrongdisk", "breaks"] => (KeyCase::WrongDisk, true),
                ["wrongdisk", "blank"] => (KeyCase::WrongBlank, false),
                ["wrongdisk", "blank", "breaks"] => (KeyCase::WrongBlank, true),
                ["foreign"] => (KeyCase::Foreign, false),
                ["image"] => (KeyCase::Image, false),
                ["image", "grown"] => (KeyCase::ImageGrown, false),
                other => {
                    return Err(format!(
                        "usage: nvme-persist key [nodisk|wrongdisk [blank] [breaks]|foreign|image [grown]]: {other:?}"
                    ));
                }
            };
            return nvme_persist_key(case, breaks);
        }
        Some("blk-probe") if args.len() == 1 => return nvme_blk_probe(),
        Some("shutdown") if args.len() == 1 => return nvme_shutdown(),
        Some("stop-handlers") if args.len() == 1 => return nvme_stop_handlers(false),
        Some("stop-handlers") if args.len() == 2 && args[1] == "breaks" => {
            return nvme_stop_handlers(true);
        }
        _ => {}
    }
    let (breaks, shape, steps) = match args.first().map(String::as_str) {
        None => (false, Shape::Plain, false),
        Some("breaks") => (true, Shape::Plain, false),
        Some("lba4096") => (false, Shape::Lba4096, false),
        Some("mdts1") => (false, Shape::Mdts1, false),
        Some("steps") => (false, Shape::Plain, true),
        Some(other) => {
            return Err(format!(
                "usage: nvme-persist [breaks|lba4096|mdts1|steps|key|blk-probe|shutdown|stop-handlers]: {other}"
            ));
        }
    };
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let world = make_world(
        &hello_elf()?,
        steps,
        if steps { "full-steps" } else { "full" },
    )?;
    let broken: &'static [&'static str] = if breaks {
        &["break-nvme-write-offset"]
    } else if steps {
        &["steps"]
    } else {
        &[]
    };
    let mut list = if steps {
        PROGRAMS_STEPS.to_vec()
    } else {
        PROGRAMS.to_vec()
    };
    for program in &mut list {
        match program.0 {
            "init" => program.3 = &["table-store-probe", "nvme-store"],
            "virtio-blk" => {
                *program = ("nvme-blk", "nvme-blk", blk_probe::BLK_STACK_SIZE, broken);
            }
            _ => {}
        }
    }
    let programs: &'static [ImageProgram] = Box::leak(list.into_boxed_slice());
    // The jobs of the ci run side by side in one tree: each variant has the files of its own.
    let tag = match (breaks, steps, shape) {
        (true, ..) => "-break",
        (_, true, _) => "-steps",
        (_, _, Shape::Plain) => "",
        (_, _, Shape::Lba4096) => "-4096",
        (_, _, Shape::Mdts1) => "-mdts1",
        (_, _, Shape::Absent | Shape::Wrong) => "-key",
    };
    let name: &str = &format!("boot-nvme-persist{tag}.img");
    let esp_name = format!("efi-disk-nvme-persist{tag}.raw");
    let image = image_with(name, programs, world.files.clone(), None)?;
    let kernel = build(Variant::Normal)?;
    let firmware = efi::firmware()?;
    let loader = efi::build_loader(&[])?;
    let esp = target_dir().join(&esp_name);
    let artifacts = Artifacts {
        boot_image: image,
        ..kernel.clone()
    };
    efi::make_disk(&loader, &artifacts, &esp)?;
    // The ci runs the variants as threads of one process: the data disk is named after the variant.
    let file = Disk::new(&format!("nvme{tag}"));
    write_disk(&file, None)?;
    if breaks {
        // The first run keeps what it wrote in memory, so it may pass; the machine that starts again
        // on the file reads what the service wrote, and must not find the store whole.
        let caught = |why: String| {
            println!("nvme-persist breaks: break-nvme-write-offset is caught: {why}");
            Ok(())
        };
        if let Err(why) = nvme_run(&firmware, &esp, &file.0, &kernel.elf, shape, steps, WITHIN) {
            return caught(format!("the first run failed: {why}"));
        }
        return match nvme_run(
            &firmware,
            &esp,
            &file.0,
            &kernel.elf,
            shape,
            false,
            BOOT_TIMEOUT * 6,
        ) {
            Err(why) => caught(format!("the run after the kill failed: {why}")),
            Ok(lines) if !lines.iter().any(|l| l == "store-probe: ok") => {
                caught("the probe did not say ok after the kill".into())
            }
            Ok(_) => Err("break-nvme-write-offset passed the probe".into()),
        };
    }
    let blocks_hello = world.blocks("hello");
    let first = nvme_run(
        &firmware,
        &esp,
        &file.0,
        &kernel.elf,
        shape,
        steps,
        if steps { BOOT_TIMEOUT * 40 } else { WITHIN },
    )?;
    if steps {
        expect_within(&first, &steady_lines(&world))?;
    } else {
        expect(&first, &full_lines(&world, steps))?;
    }
    // The controller the service found, the interrupts that came, and nothing of the Virtio disk.
    // Under -icount the lines of the services come glued to the lines of a step, and a long one may
    // be cut: the text is read from its start, and the line of the controller is required whole
    // only when the run is not measured.
    let nvme_line = first.iter().find_map(|l| {
        let at = l.find("nvme: ")?;
        l.contains(" blocks of ").then(|| l[at..].to_string())
    });
    let nvme_line = match nvme_line {
        Some(line) => {
            if !line.contains(shape.said()) {
                return Err(format!(
                    "the controller is not the one asked for ({}): {line}",
                    shape.said()
                ));
            }
            if !line.contains("msi yes") {
                return Err(format!("the NVMe service ran without MSI-X: {line}"));
            }
            line
        }
        None if steps => "the line of the controller was cut by the steps".to_string(),
        None => return Err("the NVMe service said nothing of its controller".into()),
    };
    // The measured run may lose a line of the console; the interrupt is required of the others.
    if !steps
        && !first
            .iter()
            .any(|l| l.contains("nvme: first interrupt of vector 1"))
    {
        return Err("no interrupt of vector 1 came: the completions were found by polling".into());
    }
    if first
        .iter()
        .any(|l| l.contains("virtio-blk: ") || l.contains("nvme: reset"))
    {
        return Err("the Virtio disk ran, or the controller was reset in place".into());
    }
    if steps {
        // Every method of the service came, and no step of it, the heartbeat's and the
        // interrupt's included, is past 0.9 of term B.
        let mut blk = longest_steps(&first, blk_probe::BLK_TAG);
        // A line of a step is told only when it is a new longest of its kind, and with the lines
        // of the services glued together under -icount one may be lost: a kind that did not come
        // is looked for in a run on a fresh disk, two more at most, and the longest of each kind
        // is kept.
        let mut runs = 1;
        let mut lost = vec![lost_records(&first)];
        while runs < 3
            && BLK_STEP_KINDS
                .iter()
                .any(|(kind, _)| !blk.iter().any(|row| row.0 == *kind))
        {
            write_disk(&file, None)?;
            let again = nvme_run(
                &firmware,
                &esp,
                &file.0,
                &kernel.elf,
                shape,
                true,
                BOOT_TIMEOUT * 40,
            )?;
            expect_within(&again, &steady_lines(&world))?;
            blk = merge(blk, longest_steps(&again, blk_probe::BLK_TAG));
            lost.push(lost_records(&again));
            runs += 1;
        }
        judge("the NVMe service", &blk, &BLK_STEP_KINDS).map_err(|e| {
            format!("{e}; records the kernel log lost in each of {runs} runs: {lost:?}")
        })?;
        check_waits(
            &first,
            &[PKGD_TAG, blk_probe::BLK_TAG, RAM_TAG],
            "nvme-persist",
        )?;
        let text = blk
            .iter()
            .map(|(k, t, _)| format!("kind {k} {t}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("nvme-persist steps: the NVMe service {text}");
        println!(
            "nvme-persist steps: every step of the NVMe service under 0.9 of term B ({}): ok; {nvme_line}",
            blk_probe::STEP_MAX
        );
        return Ok(());
    }
    let (generation, free, disk) = status_numbers(&first, "final status")?;
    // QEMU was killed with the probe's last line: the second run is on what the file holds.
    let second = nvme_run(
        &firmware,
        &esp,
        &file.0,
        &kernel.elf,
        shape,
        steps,
        if steps { BOOT_TIMEOUT * 40 } else { WITHIN },
    )?;
    let wanted = measured(
        steps,
        vec![
        "pkgd: roots stafeto-dev-root".to_string(),
        "pkgd: keyb: key revoked, skipped".to_string(),
        "store-probe: restart: hello runs, big, the settings and the serial are in place, wide and keyb are not".to_string(),
        "store-probe: ok".to_string(),
        format!("store-probe: status generation={generation} free={free} disk={}", disk - 1),
        ],
    );
    expect(&second, &wanted)?;
    println!(
        "nvme-persist: on QEMU's NVMe disk the full scenario of the store probe passed (hello, {blocks_hello} blocks, every refusal, a group of big and wide, the settings, the serial, REMOVE), QEMU was killed, and the machine started again on the same file found hello installed and running, the settings and the serial in place (generation {generation}, {free} blocks free): ok; {nvme_line}"
    );
    Ok(())
}

/// The programs of the image of the host key probe: the services of the data volume on the NVMe disk,
/// the host key service and the probe that stands in for the boot script of Dropbear.
const PROGRAMS_KEY: [ImageProgram; 7] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-datakey-probe", "nvme-store"],
    ),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("nvme-blk", "nvme-blk", blk_probe::BLK_STACK_SIZE, &[]),
    ("datafsd", "datafsd", 32 * 1024, &[]),
    ("datakey", "datakey", 128 * 1024, &[]),
    ("datakey-probe", "datakey-probe", 128 * 1024, &[]),
];

/// The line of the fingerprint the probe prints, in the form of the boot script's line.
const KEY_LINE: &str = "ssh: host key FNV:";

/// The fingerprint line of a run.
fn key_fingerprint(lines: &[String]) -> Result<String, String> {
    let found: Vec<String> = lines
        .iter()
        .filter_map(|l| {
            let at = l.find(KEY_LINE)?;
            Some(l[at + KEY_LINE.len()..].trim().to_owned())
        })
        .collect();
    match found.as_slice() {
        [one] if one.len() == 16 => Ok(one.clone()),
        other => Err(format!(
            "one fingerprint line wanted, the run printed {other:?}"
        )),
    }
}

fn said(lines: &[String], text: &str) -> bool {
    lines.iter().any(|l| l.contains(text))
}

/// What the machine of `nvme-persist key` has as its data disk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyCase {
    /// A blank disk with the serial the record wants: the key outlives the boot.
    Normal,
    /// No second controller: the record `datadisk` is left out, the service of the data files
    /// answers "not mounted", the key is new on each boot.
    NoDisk,
    /// A controller whose serial number is another one, over a file that stands for an ESP: the
    /// service of the disk leaves it alone.
    WrongDisk,
    /// The same, with the first MiB of the file zeroed: `datafs` would take it for a blank disk and
    /// partition it, so only the check of the identity protects it.
    WrongBlank,
    /// The serial the record wants over a file shaped like a fresh volume of EC2 (the first and the
    /// last 4 KiB zero, bytes that are not zero between): the identity matches, and `datafs` itself
    /// says the disk holds something else and leaves it alone.
    Foreign,
    /// The data image of the AMI (`cargo xtask data-image`): `datafs` mounts it on the first boot.
    Image,
    /// The same image with the file 1 GiB longer, as an enlarged volume is: the backup copy of the
    /// table is moved to the new end and the volume mounts.
    ImageGrown,
}

/// The size of the file that stands for an ESP in the case `WrongDisk`.
const STAND_IN_BYTES: usize = 16 << 20;
/// The serial of the controller over that file: the boot disk's, which the record never names.
const WRONG_SERIAL: &str = "stafeto-esp";
/// The line of the service of the disk that leaves a volume alone.
const LEFT_ALONE: &str = "nvme: datadisk is not the data volume, left alone";

/// The SHA-256 of a file as text.
fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = [0u8; 64];
    Ok(pkgfmt::sha::hex(&pkgfmt::sha::sha256(&bytes), &mut buf).to_string())
}

/// A file of non-zero bytes that stands for an ESP: a service that wrote to it or formatted it
/// would change its digest.
fn write_stand_in(path: &Path, blank_start: bool) -> Result<(), String> {
    let mut bytes = vec![0u8; STAND_IN_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3] | 1;
    }
    if blank_start {
        // The first MiB is zero: the test of `datafs` for a blank disk.
        bytes[..1 << 20].fill(0);
    }
    std::fs::write(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn no_restart_loop(lines: &[String], what: &str) -> Result<(), String> {
    match lines.iter().find(|l| l.contains("; restarts in ")) {
        Some(line) => Err(format!("{what}: a service restarts: {line}")),
        None => Ok(()),
    }
}

/// `cargo xtask nvme-persist key [nodisk|wrongdisk [breaks]]`: the host key service on the NVMe
/// data disk, two machines on one file. The first finds a blank volume: the service reports no key,
/// the probe (the boot script
/// of Dropbear's stand-in) makes one, and the service keeps it on the volume. The second starts on
/// the same file: the service puts the key it finds into the file service, the probe keeps it, and
/// the fingerprint is the same.
///
/// `nodisk`: the machine has no data controller. The record `datadisk` is left out of the table, the
/// data file service serves nothing, the probe (the shell's stand-in) comes up and ends, nothing
/// restarts, and the key is new on each of two boots. `wrongdisk`: the controller the record
/// names has another serial number, over a file that stands for the ESP. The disk service
/// registers, says it left the volume alone, and refuses every operation: the file's SHA-256 is
/// the same after the boot, the data file service says not mounted, and the key is new. With
/// `breaks` the check of the identity always passes (`break-nvme-identity`), and the case must
/// then fail.
fn nvme_persist_key(case: KeyCase, breaks: bool) -> Result<(), String> {
    let tag = match (case, breaks) {
        (KeyCase::Normal, _) => "",
        (KeyCase::NoDisk, _) => "-nodisk",
        (KeyCase::WrongDisk, false) => "-wrongdisk",
        (KeyCase::WrongDisk, true) => "-wrongdisk-break",
        (KeyCase::WrongBlank, false) => "-wrongblank",
        (KeyCase::WrongBlank, true) => "-wrongblank-break",
        (KeyCase::Foreign, _) => "-foreign",
        (KeyCase::Image, _) => "-image",
        (KeyCase::ImageGrown, _) => "-image-grown",
    };
    let mut list = PROGRAMS_KEY.to_vec();
    if breaks {
        for program in &mut list {
            if program.0 == "nvme-blk" {
                program.3 = &["break-nvme-identity"];
            }
        }
    }
    let programs: &'static [ImageProgram] = Box::leak(list.into_boxed_slice());
    let dirs = ["/etc/dropbear"].map(|path| rootfs::RootFile {
        path,
        mode: 0o755,
        uid: 0,
        gid: 0,
        source: None,
    });
    let image_name: &'static str = Box::leak(format!("boot-nvme-persist-key{tag}.img").into());
    let image = write_boot_image_files(image_name, programs, BOOT_PROFILE, &[], dirs.into())?;
    let kernel = build(Variant::Normal)?;
    let firmware = efi::firmware()?;
    let loader = efi::build_loader(&[])?;
    let esp = target_dir().join(format!("efi-disk-nvme-persist-key{tag}.raw"));
    let artifacts = Artifacts {
        boot_image: image,
        ..kernel.clone()
    };
    efi::make_disk(&loader, &artifacts, &esp)?;
    let file = Disk::new(&format!("nvme-key{tag}"));
    let shape = match case {
        KeyCase::Normal | KeyCase::Foreign | KeyCase::Image | KeyCase::ImageGrown => Shape::Plain,
        KeyCase::NoDisk => Shape::Absent,
        KeyCase::WrongDisk | KeyCase::WrongBlank => Shape::Wrong,
    };
    if case == KeyCase::Foreign {
        write_ec2_noise(&file.0)?;
    } else if case == KeyCase::Image || case == KeyCase::ImageGrown {
        data_image::make(&file.0, DISK_BYTES)?;
        if case == KeyCase::ImageGrown {
            let grown = std::fs::OpenOptions::new()
                .write(true)
                .open(&file.0)
                .map_err(|e| format!("{}: {e}", file.0.display()))?;
            grown
                .set_len(DISK_BYTES + (1 << 30))
                .map_err(|e| format!("{}: {e}", file.0.display()))?;
        }
    } else if case != KeyCase::Normal && case != KeyCase::NoDisk {
        write_stand_in(&file.0, case == KeyCase::WrongBlank)?;
    } else {
        write_disk(&file, None)?;
    }
    let run = || {
        nvme_run_of(
            &firmware,
            &esp,
            &file.0,
            &kernel.elf,
            shape,
            false,
            WITHIN,
            "datakey-probe",
        )
    };
    if case == KeyCase::Foreign {
        return nvme_key_foreign(&file.0, &run);
    }
    if case == KeyCase::Image || case == KeyCase::ImageGrown {
        return nvme_key_image(case, &run);
    }
    if case != KeyCase::Normal {
        return nvme_key_without_volume(case, breaks, &file.0, &run);
    }
    let first = run()?;
    if !said(&first, "datakey: no host key on /data")
        || !said(&first, "datakey: host key saved to /data")
    {
        return Err(format!(
            "the first boot did not find a blank volume and keep the key: {:?}",
            first
                .iter()
                .filter(|l| l.contains("datakey"))
                .collect::<Vec<_>>()
        ));
    }
    let before = key_fingerprint(&first)?;
    no_foreign_report(&first, "nvme-persist key, first boot")?;
    let second = run()?;
    no_foreign_report(&second, "nvme-persist key, second boot")?;
    if !said(&second, "datakey: host key restored from /data")
        || said(&second, "datakey: no host key")
    {
        return Err(format!(
            "the second boot did not restore the key: {:?}",
            second
                .iter()
                .filter(|l| l.contains("datakey"))
                .collect::<Vec<_>>()
        ));
    }
    let after = key_fingerprint(&second)?;
    if before != after {
        return Err(format!(
            "the fingerprint of the host key changed between two boots of one volume: {before} then {after}"
        ));
    }
    println!(
        "nvme-persist key: the host key made on the first boot of a blank NVMe data volume was kept by datakey, and the second boot of the same volume restored it (fingerprint FNV:{before} on both): ok"
    );
    Ok(())
}

/// A blank volume and a valid one never print the lines of a foreign disk.
fn no_foreign_report(lines: &[String], what: &str) -> Result<(), String> {
    match lines
        .iter()
        .find(|l| l.contains("datafs: foreign at") || l.contains("datafs: lba1 "))
    {
        Some(line) => Err(format!("{what}: a line of a foreign disk: {line}")),
        None => Ok(()),
    }
}

/// A file shaped like a fresh volume of EC2: the first 4 KiB and the last 4 KiB zero, bytes that
/// are never zero in between.
fn write_ec2_noise(path: &Path) -> Result<(), String> {
    let mut bytes = vec![0u8; STAND_IN_BYTES];
    let end = bytes.len() - 4096;
    for (i, b) in bytes[4096..end].iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3] | 1;
    }
    std::fs::write(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// `nvme-persist key foreign`: the record's serial over a file shaped like a fresh volume of EC2.
/// The service of the disk takes it, and `datafs` classifies it as foreign (the first byte that is
/// not zero is at sector 8, offset 0; sector 1 and the last sector are zero), prints no byte of the
/// disk, and leaves it alone: the file has the same SHA-256 after two boots, and the key of the
/// host is new on each boot.
fn nvme_key_foreign(
    file: &Path,
    run: &dyn Fn() -> Result<Vec<String>, String>,
) -> Result<(), String> {
    let name = "nvme-persist key foreign";
    let before = file_sha256(file)?;
    let mut keys = Vec::new();
    for boot in ["first", "second"] {
        let lines = run()?;
        no_restart_loop(&lines, name)?;
        let count = |text: &str| lines.iter().filter(|l| l.contains(text)).count();
        for text in [
            "datafs: foreign at sector 8 offset 0",
            "datafs: lba1 zero lba-last zero",
            "datafs: the disk holds something else, left alone and unused in this release",
        ] {
            if count(text) != 1 {
                return Err(format!(
                    "{name}, {boot} boot: {} lines with {text:?}, one expected: {:?}",
                    count(text),
                    lines
                        .iter()
                        .filter(|l| l.contains("datafs") || l.contains("nvme"))
                        .collect::<Vec<_>>()
                ));
            }
        }
        if count("nvme: dma queues 0x") != 1 {
            return Err(format!(
                "{name}, {boot} boot: the line of the DMA addresses is missing"
            ));
        }
        if said(&lines, "datafs: no disk: ") || said(&lines, "datafs: data volume") {
            return Err(format!(
                "{name}, {boot} boot: the volume was not left alone"
            ));
        }
        if said(&lines, "datakey: host key saved") || said(&lines, "datakey: host key restored") {
            return Err(format!("{name}, {boot} boot: a key was kept or restored"));
        }
        keys.push(key_fingerprint(&lines)?);
    }
    if keys[0] == keys[1] {
        return Err(format!(
            "{name}: the key is the same on two boots of a volume that is left alone: FNV:{}",
            keys[0]
        ));
    }
    let after = file_sha256(file)?;
    if before != after {
        return Err(format!(
            "{name}: the file changed: SHA-256 {before} before the boots, {after} after"
        ));
    }
    println!(
        "{name}: datafs said where the first byte that is not zero is (sector 8 offset 0), printed no byte of the disk, left it alone (the file has the same SHA-256, {after}, after two boots), and the key is new on each boot (FNV:{} then FNV:{}): ok",
        keys[0], keys[1]
    );
    Ok(())
}

/// `nvme-persist key image [grown]`: the data image of the AMI as the data disk. The first boot
/// mounts it with no line of partitioning or formatting (with `grown`, one line that the backup
/// of the table moved to the end, then the mount), the key made by the stand-in of the boot script
/// is saved, and the second boot mounts again with no such line and restores the same key.
fn nvme_key_image(
    case: KeyCase,
    run: &dyn Fn() -> Result<Vec<String>, String>,
) -> Result<(), String> {
    let grown = case == KeyCase::ImageGrown;
    let name = if grown {
        "nvme-persist key image grown"
    } else {
        "nvme-persist key image"
    };
    let moved = "datafs: backup partition table moved to the end of the disk, data volume mounted";
    let first = run()?;
    let second = run()?;
    for (lines, boot) in [(&first, "first"), (&second, "second")] {
        no_restart_loop(lines, name)?;
        no_foreign_report(lines, &format!("{name}, {boot} boot"))?;
        let mounted = lines
            .iter()
            .filter(|l| l.contains("datafs: "))
            .collect::<Vec<_>>();
        let relocated = lines.iter().filter(|l| l.contains(moved)).count();
        let plain = lines
            .iter()
            .filter(|l| l.contains("datafs: data volume mounted,"))
            .count();
        let wanted_relocated = usize::from(grown && boot == "first");
        if relocated != wanted_relocated || relocated + plain != 1 {
            return Err(format!(
                "{name}, {boot} boot: {relocated} lines of a moved table and {plain} plain mounts, {wanted_relocated} and {} expected: {mounted:?}",
                1 - wanted_relocated
            ));
        }
        if said(lines, "datafs: data volume formatted")
            || said(lines, "datafs: partition table written")
        {
            return Err(format!(
                "{name}, {boot} boot: datafs formatted the volume: {mounted:?}"
            ));
        }
    }
    let datakey = |lines: &[String]| {
        lines
            .iter()
            .filter(|l| l.contains("datakey"))
            .cloned()
            .collect::<Vec<_>>()
    };
    if !said(&first, "datakey: no host key on /data")
        || !said(&first, "datakey: host key saved to /data")
    {
        return Err(format!(
            "{name}: the first boot did not keep the key: {:?}",
            datakey(&first)
        ));
    }
    if !said(&second, "datakey: host key restored from /data")
        || said(&second, "datakey: no host key")
    {
        return Err(format!(
            "{name}: the second boot did not restore the key: {:?}",
            datakey(&second)
        ));
    }
    let (before, after) = (key_fingerprint(&first)?, key_fingerprint(&second)?);
    if before != after {
        return Err(format!(
            "{name}: the fingerprint changed between two boots: {before} then {after}"
        ));
    }
    println!(
        "{name}: the data image {}mounted on the first boot with no formatting, the key was saved and the second boot restored it (FNV:{before} on both): ok",
        if grown {
            "of a volume 1 GiB larger had its backup table moved to the end and "
        } else {
            ""
        }
    );
    Ok(())
}

/// The cases of `nvme-persist key` without a usable data volume, two boots each.
fn nvme_key_without_volume(
    case: KeyCase,
    breaks: bool,
    file: &Path,
    run: &dyn Fn() -> Result<Vec<String>, String>,
) -> Result<(), String> {
    let name = match case {
        KeyCase::NoDisk => "nvme-persist key nodisk",
        KeyCase::WrongBlank => "nvme-persist key wrongdisk blank",
        _ => "nvme-persist key wrongdisk",
    };
    let blank = case == KeyCase::WrongBlank;
    let judge = |lines: &[String], boot: &str| -> Result<String, String> {
        no_restart_loop(lines, &format!("{name}, {boot} boot"))?;
        if blank && breaks {
            // The break must be caught by the file's digest alone: the lines are not looked at.
            return Ok(String::new());
        }
        // The data file service says it has no volume, whatever the reason.
        if !said(lines, "datafs: no disk: ") {
            return Err(format!(
                "{name}, {boot} boot: the data file service did not say it has no disk: {:?}",
                lines
                    .iter()
                    .filter(|l| l.contains("datafs"))
                    .collect::<Vec<_>>()
            ));
        }
        if said(lines, "datakey: host key saved") || said(lines, "datakey: host key restored") {
            return Err(format!("{name}, {boot} boot: a key was kept or restored"));
        }
        let left = lines.iter().filter(|l| l.contains(LEFT_ALONE)).count();
        match case {
            KeyCase::NoDisk if left != 0 || said(lines, "nvme: ") => Err(format!(
                "{name}, {boot} boot: the disk service ran with no data controller"
            )),
            KeyCase::NoDisk if !said(lines, "init: left out: ") => Err(format!(
                "{name}, {boot} boot: init did not say it left the record out"
            )),
            KeyCase::WrongDisk | KeyCase::WrongBlank if left != 1 => Err(format!(
                "{name}, {boot} boot: {left} lines {LEFT_ALONE:?}, one expected"
            )),
            _ => key_fingerprint(lines),
        }
    };
    let before = if case != KeyCase::NoDisk {
        Some(file_sha256(file)?)
    } else {
        None
    };
    let boots = if case == KeyCase::NoDisk { 2 } else { 1 };
    let mut keys = Vec::new();
    for boot in ["first", "second"].into_iter().take(boots) {
        let outcome = run().and_then(|lines| judge(&lines, boot));
        match outcome {
            Ok(key) => keys.push(key),
            Err(why) if breaks && !blank => {
                println!("{name} breaks: break-nvme-identity is caught: {why}");
                return Ok(());
            }
            Err(why) => return Err(why),
        }
    }
    if let Some(before) = before {
        let after = file_sha256(file)?;
        if before != after {
            let why = format!(
                "the file of the wrong disk changed: SHA-256 {before} before the boot, {after} after"
            );
            if breaks {
                println!(
                    "{name} breaks: break-nvme-identity is caught because the SHA-256 of the file changed: {why}"
                );
                return Ok(());
            }
            return Err(why);
        }
        if blank && breaks {
            return Err(
                "break-nvme-identity passed: the SHA-256 of the blank-start file is unchanged"
                    .into(),
            );
        }
    }
    if breaks {
        return Err("break-nvme-identity passed the probe".into());
    }
    if keys.len() == 2 && keys[0] == keys[1] {
        return Err(format!(
            "{name}: the key is the same on two boots with no volume: FNV:{}",
            keys[0]
        ));
    }
    match case {
        KeyCase::NoDisk => println!(
            "nvme-persist key nodisk: no data controller, the record datadisk is left out, the data file service says it has no disk, nothing restarts, and the key is new on each boot (FNV:{} then FNV:{}): ok",
            keys[0], keys[1]
        ),
        _ => println!(
            "nvme-persist key wrongdisk: the controller with another serial number is left alone, the file that stands for the ESP has the same SHA-256 after the boot ({}), nothing restarts, and the data file service has no disk: ok",
            file_sha256(file)?
        ),
    }
    Ok(())
}

/// `cargo xtask nvme-persist blk-probe`: the probe of the disk service (tests/blk-probe, the
/// runs 1 and 2 of `cargo xtask blk-probe`) over the NVMe disk service on QEMU's machine with edk2:
/// the refusals, a pattern written and flushed, CANCEL; then the machine again on the same file, the
/// pattern read back, a CRASH of the disk service, and the restarted service read again. The
/// record is `blk`, the name the probe connects to; init stops the controller before it starts the
/// service again.
fn nvme_blk_probe() -> Result<(), String> {
    let programs: &'static [ImageProgram] = &[
        (
            "init",
            "init",
            INIT_STACK_SIZE,
            &["table-blk-probe-nvme", "nvme-store"],
        ),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        (
            "nvme-blk",
            "nvme-blk",
            blk_probe::BLK_STACK_SIZE,
            &["crash"],
        ),
        ("blk-probe", "blk-probe", CHILD_STACK_SIZE, &[]),
    ];
    let image = build_boot_image("boot-nvme-persist-blk-probe.img", programs, BOOT_PROFILE)?;
    let kernel = build(Variant::Normal)?;
    let firmware = efi::firmware()?;
    let loader = efi::build_loader(&[])?;
    let esp = target_dir().join("efi-disk-nvme-persist-blk-probe.raw");
    let artifacts = Artifacts {
        boot_image: image,
        ..kernel.clone()
    };
    efi::make_disk(&loader, &artifacts, &esp)?;
    let file = Disk::new("nvme-blk-probe");
    qemu::store_file(&file.0, blk_probe::DISK_BYTES, true)?;
    let run = || {
        nvme_run_of(
            &firmware,
            &esp,
            &file.0,
            &kernel.elf,
            Shape::Plain,
            false,
            WITHIN,
            "blk-probe",
        )
    };
    let verdict = |lines: &[String], starts: usize, wanted: &[&str]| -> Result<(), String> {
        let seen = lines
            .iter()
            .filter(|l| l.starts_with("nvme: ") && l.contains(" sn stafeto-data,"))
            .count();
        if seen != starts {
            return Err(format!(
                "{seen} starts of the disk service, {starts} expected: {:?}",
                lines
                    .iter()
                    .filter(|l| l.contains("nvme: "))
                    .collect::<Vec<_>>()
            ));
        }
        for marker in [blk_probe::NO_BUFFER, blk_probe::INFO].iter().chain(wanted) {
            let n = lines.iter().filter(|l| l.contains(*marker)).count();
            if n != 1 {
                return Err(format!(
                    "{n} lines {marker:?}, one expected; the probe said {:?}",
                    lines
                        .iter()
                        .filter(|l| l.contains("blk-probe: "))
                        .collect::<Vec<_>>()
                ));
            }
        }
        Ok(())
    };
    let first = run()?;
    verdict(&first, 1, &blk_probe::WRITE_LINES)
        .map_err(|e| format!("nvme-persist blk-probe (writing): {e}"))?;
    let second = run()?;
    verdict(&second, 2, &blk_probe::CHECK_LINES)
        .map_err(|e| format!("nvme-persist blk-probe (checking): {e}"))?;
    println!(
        "nvme-persist blk-probe: refusals, a pattern of 4 MiB and the disk's tail written and flushed over NVMe, CANCEL, the same read after a new start of QEMU, a CRASH and a restart of the disk service: ok"
    );
    Ok(())
}

/// `cargo xtask nvme-persist shutdown`: init stops the system (proto_init SHUTDOWN) on QEMU's
/// machine with edk2 and the NVMe disk service. The table is `table-shutdown`: `power` (a stand-in for
/// the button's service, tests/svc role `p`) asks once its neighbours registered, `echo` ends at the
/// stop notice, `quiet` ignores it and is killed at its deadline, `blk` is the NVMe service whose
/// controller init stops (CC.SHN, then CC = 0) after its end, and the PL011's driver goes last. The
/// run needs the lines of the stop in order, the stop of the disk service confirmed, the line
/// `stafeto: system off`, no panic and QEMU's status 0.
fn nvme_shutdown() -> Result<(), String> {
    let programs: &'static [ImageProgram] = &[
        (
            "init",
            "init",
            INIT_STACK_SIZE,
            &["table-shutdown", "nvme-store"],
        ),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        ("nvme-blk", "nvme-blk", blk_probe::BLK_STACK_SIZE, &[]),
        ("svc", "test-svc", SVC_STACK_SIZE, &[]),
    ];
    let image = build_boot_image("boot-nvme-shutdown.img", programs, BOOT_PROFILE)?;
    let kernel = build(Variant::Normal)?;
    let firmware = efi::firmware()?;
    let loader = efi::build_loader(&[])?;
    let esp = target_dir().join("efi-disk-nvme-shutdown.raw");
    let artifacts = Artifacts {
        boot_image: image,
        ..kernel.clone()
    };
    efi::make_disk(&loader, &artifacts, &esp)?;
    let file = Disk::new("nvme-shutdown");
    qemu::store_file(&file.0, blk_probe::DISK_BYTES, true)?;
    let mut cmd = efi::command(&efi::EFI, &firmware, &esp, true, "efi-disk-nvme-shutdown")?;
    cmd.arg("-drive").arg(format!(
        "file={},if=none,format=raw,id=data,cache=writeback,werror=report,rerror=report",
        file.0.display()
    ));
    cmd.args(["-device", &Shape::Plain.device()]);
    let output = run_until(cmd, WITHIN, None, &kernel.elf)?;
    qemu::expect_system_off(&output)?;
    let lines = &output.lines;
    qemu::expect_in_order(
        lines,
        &[
            "init: stopping the system (off)",
            "init: stopping power",
            "init: power stopped: ",
            "init: stopping blk",
            "init: stopping echo",
            "init: stopping quiet",
            "init: quiet did not stop in 500 ms, killed",
            "init: stopping uart",
            "init: stopped in ",
            qemu::SYSTEM_OFF_LINE,
        ],
    )
    .map_err(|e| format!("nvme-persist shutdown: {e}"))?;
    // The disk service ended in the wave of the killed service and its controller stopped
    // before the console's wave began.
    qemu::expect_in_order(
        lines,
        &[
            "init: stopping blk",
            "init: blk device stopped and confirmed",
            "init: stopping uart",
        ],
    )
    .map_err(|e| format!("nvme-persist shutdown: {e}"))?;
    for wanted in ["power: button", "init: echo stopped: exit code 0"] {
        if !lines.iter().any(|l| l.contains(wanted)) {
            return Err(format!("nvme-persist shutdown: no line {wanted:?}"));
        }
    }
    for unwanted in [
        "init: power did not stop",
        "init: echo did not stop",
        "init: blk did not stop",
        "its DMA memory stays kept",
        "did not stop within the whole stop",
    ] {
        if let Some(line) = lines.iter().find(|l| l.contains(unwanted)) {
            return Err(format!("nvme-persist shutdown: unexpected line {line:?}"));
        }
    }
    println!(
        "nvme-persist shutdown: the waves in order, the quiet service killed at its deadline, the NVMe controller stopped and confirmed, one line off, no panic, powered off"
    );
    Ok(())
}

/// The programs of the image of `nvme-persist stop-handlers`: the services of a POSIX image on
/// the machine with edk2 (the entropy service has no driver there), the NVMe data disk with the
/// file service, two POSIX programs of tests/relibc-stop and the test services (`power`).
const PROGRAMS_STOP: [ImageProgram; 10] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-stop-handlers", "nvme-store"],
    ),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("relibc-stop", "relibc-stop", POSIX_STACK_SIZE, &[]),
    ("nvme-blk", "nvme-blk", blk_probe::BLK_STACK_SIZE, &[]),
    ("datafsd", "datafsd", 32 * 1024, &[]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
    ("entropy", "entropy", entropy::ENTROPY_STACK_SIZE, &[]),
];

/// `cargo xtask nvme-persist stop-handlers`: the stop handlers of `datafs` and of the process
/// service, on QEMU's machine with edk2 and the NVMe data disk, two boots of one disk file. The
/// first boot: `power` writes `/stop/f` (20 000 bytes) through its session with `datafs`, with no
/// sync and no close, and asks init to stop the system. The stop must show, in order: the process
/// service signals its two POSIX programs (the one with a handler for SIGTERM ends by itself, the
/// one that ignores it is killed), `datafs` finishes its queue, closes the file and unmounts (its line
/// comes before the disk's `stopped and confirmed`), and the machine powers off with no panic. The
/// second boot mounts the volume and `stop-writer` reads `/stop/f` back whole.
///
/// `stop-writer` (the last tier of the stop) keeps its session and the open file until `datafs` has
/// stopped, so the file is closed by the stop handler of `datafs` (`close_all`); the cleanup of a
/// session that went never gets to close it. With `breaks` the stop handler of `datafs` exits at once
/// (`break-datafs-stop`) and the run must fail: the file is short or missing after the next boot.
fn nvme_stop_handlers(breaks: bool) -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let mut list = PROGRAMS_STOP.to_vec();
    if breaks {
        for program in &mut list {
            if program.0 == "datafsd" {
                program.3 = &["break-datafs-stop"];
            }
        }
    }
    let programs: &'static [ImageProgram] = Box::leak(list.into_boxed_slice());
    let tag = if breaks { "-break" } else { "" };
    let image_name: &'static str = Box::leak(format!("boot-nvme-stop-handlers{tag}.img").into());
    let image = build_boot_image(image_name, programs, BOOT_PROFILE)?;
    let kernel = build(Variant::Normal)?;
    let firmware = efi::firmware()?;
    let loader = efi::build_loader(&[])?;
    let esp = target_dir().join(format!("efi-disk-nvme-stop-handlers{tag}.raw"));
    let artifacts = Artifacts {
        boot_image: image,
        ..kernel.clone()
    };
    efi::make_disk(&loader, &artifacts, &esp)?;
    let file = Disk::new(&format!("nvme-stop-handlers{tag}"));
    qemu::store_file(&file.0, blk_probe::DISK_BYTES, true)?;
    let boot = |which: &str| -> Result<Vec<String>, String> {
        let mut cmd = efi::command(
            &efi::EFI,
            &firmware,
            &esp,
            true,
            "efi-disk-nvme-stop-handlers",
        )?;
        cmd.arg("-drive").arg(format!(
            "file={},if=none,format=raw,id=data,cache=writeback,werror=report,rerror=report",
            file.0.display()
        ));
        cmd.args(["-device", &Shape::Plain.device()]);
        let output = run_until(cmd, WITHIN, None, &kernel.elf)?;
        qemu::expect_system_off(&output).map_err(|e| format!("{which}: {e}"))?;
        Ok(output.lines)
    };
    let stop_order: &[&str] = &[
        "init: stopping the system (off)",
        "init: stopping datafs",
        "datafs: stopped, ",
        "init: stopping datadisk",
        "init: datadisk device stopped and confirmed",
        "init: stopping uart",
        "init: stopped in ",
        qemu::SYSTEM_OFF_LINE,
    ];
    let check = |lines: &[String], which: &str| -> Result<(), String> {
        qemu::expect_in_order(lines, stop_order).map_err(|e| format!("{which}: {e}"))?;
        // The process service signals its two programs: the one with a handler for SIGTERM ends
        // by itself (SIGTERM was posted to it alone, the ignorer's action drops it) and the
        // ignorer is killed after the wait. The writer holds its session with `datafs` open
        // until the last wave, so `datafs` has an open file at its stop notice.
        qemu::expect_in_order(
            lines,
            &[
                "init: stopping the system (off)",
                "relibc-stop: handler got SIGTERM and exits",
                "posix: stopped, 1 signalled, 1 ended after SIGTERM, 1 killed",
            ],
        )
        .map_err(|e| format!("{which}: {e}"))?;
        // The writer and the console's driver are in the last wave, in the order of the table:
        // the writer stops after `datafs` whichever line comes first.
        qemu::expect_in_order(lines, &["datafs: stopped, ", "init: stopping stop-writer"])
            .map_err(|e| format!("{which}: {e}"))?;
        for wanted in [
            "relibc-stop: handler ready",
            "relibc-stop: ignorer ready",
            "init: stopping power",
            "init: stopping posix",
        ] {
            if !lines.iter().any(|l| l.contains(wanted)) {
                return Err(format!("{which}: no line {wanted:?}"));
            }
        }
        // Both programs were up before the stop began.
        let began = lines
            .iter()
            .position(|l| l.contains("init: stopping the system"))
            .ok_or_else(|| format!("{which}: no line of the stop"))?;
        for ready in ["relibc-stop: handler ready", "relibc-stop: ignorer ready"] {
            if !lines[..began].iter().any(|l| l.contains(ready)) {
                return Err(format!("{which}: {ready:?} came after the stop began"));
            }
        }
        // The ignorer never says it got the signal, and no service of the table overran its deadline.
        for unwanted in [
            "relibc-stop: ignorer got",
            "init: power did not stop",
            "init: posix did not stop",
            "init: datafs did not stop",
            "init: datadisk did not stop",
            "datafs: unmount failed",
            "datafs: flush failed",
            "its DMA memory stays kept",
            "did not stop within the whole stop",
            "stop-writer: file failed",
            "stop-writer: no session",
            "files did not close",
            "power: stop-writer did not answer",
            "power: SHUTDOWN refused",
        ] {
            if let Some(line) = lines.iter().find(|l| l.contains(unwanted)) {
                return Err(format!("{which}: unexpected line {line:?}"));
            }
        }
        Ok(())
    };
    let first = boot("first boot")?;
    if breaks {
        let second = boot("second boot")?;
        // The writer must have spoken: a silent console would let any run pass.
        if !second.iter().any(|l| l.contains("stop-writer: ")) {
            return Err(
                "nvme-persist stop-handlers breaks: no line of stop-writer on the second boot, the probe saw nothing"
                    .into(),
            );
        }
        if second
            .iter()
            .any(|l| l.contains("stop-writer: /stop/f whole, 20000 bytes"))
        {
            return Err(
                "nvme-persist stop-handlers breaks: a datafs that exits at once at the stop left the file whole, the probe does not prove the stop handler"
                    .into(),
            );
        }
        println!(
            "nvme-persist stop-handlers breaks: a datafs that exits at once at the stop notice is caught: the file written just before the stop did not read back whole"
        );
        return Ok(());
    }
    check(&first, "first boot")?;
    for wanted in [
        "datafs: partition table written, data volume formatted",
        "stop-writer: wrote /stop/f, 20000 bytes, no sync and no close",
    ] {
        if !first.iter().any(|l| l.contains(wanted)) {
            return Err(format!("first boot: no line {wanted:?}"));
        }
    }
    let second = boot("second boot")?;
    check(&second, "second boot")?;
    if !second
        .iter()
        .any(|l| l.contains("datafs: data volume mounted"))
    {
        return Err("second boot: the volume was not mounted from the first boot".into());
    }
    if !second
        .iter()
        .any(|l| l.contains("stop-writer: /stop/f whole, 20000 bytes"))
    {
        return Err(format!(
            "second boot: the file written just before the stop did not read back whole: {:?}",
            second
                .iter()
                .filter(|l| l.contains("stop-writer:") || l.contains("datafs:"))
                .collect::<Vec<_>>()
        ));
    }
    println!(
        "nvme-persist stop-handlers: the process service ended the program with a handler by SIGTERM and killed the one that ignores it, datafs stopped before the disk's confirmed stop, the machine powered off, and the file written just before the stop read back whole after the next boot"
    );
    Ok(())
}

/// How the data disk's controller is made: as QEMU makes it by default, with a namespace of 4 KiB
/// blocks (`nvme-ns`), or with a transfer limit of two pages (`mdts=1`: the library cuts each cell of
/// 16 KiB into two commands).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Plain,
    Lba4096,
    Mdts1,
    /// No data controller at all (`key nodisk`).
    Absent,
    /// A controller with the serial of the boot disk, over a file that stands for an ESP
    /// (`key wrongdisk`).
    Wrong,
}

impl Shape {
    fn device(self) -> String {
        let base = "nvme,serial=stafeto-data,bus=pcie.0,addr=0x4";
        match self {
            Shape::Plain => format!("{base},drive=data"),
            Shape::Lba4096 => format!("{base},id=data-controller"),
            Shape::Mdts1 => format!("{base},drive=data,mdts=1"),
            Shape::Absent => String::new(),
            Shape::Wrong => format!("nvme,serial={WRONG_SERIAL},bus=pcie.0,addr=0x4,drive=data"),
        }
    }

    /// What the line of the service says of the controller.
    fn said(self) -> &'static str {
        match self {
            Shape::Plain => " blocks of 512 bytes ",
            Shape::Lba4096 => " blocks of 4096 bytes ",
            Shape::Mdts1 => "mdts 1 (8192 bytes)",
            Shape::Absent | Shape::Wrong => "",
        }
    }
}

/// One run of the machine `EFI` on the boot disk `esp` with the data disk `data` as a second NVMe
/// controller (the function at 00:04.0; the boot disk's is at 00:01.0), until the probe ends: the lines
/// of its output. QEMU is killed when the line comes, or after `within`.
fn nvme_run(
    firmware: &efi::Firmware,
    esp: &Path,
    data: &Path,
    elf: &Path,
    shape: Shape,
    icount: bool,
    within: Duration,
) -> Result<Vec<String>, String> {
    nvme_run_of(
        firmware,
        esp,
        data,
        elf,
        shape,
        icount,
        within,
        "store-probe",
    )
}

/// `nvme_run` for the probe called `probe`: its line of failure starts with `<probe>: failed`, and
/// the machine stops when init says the probe ended.
#[allow(clippy::too_many_arguments)]
fn nvme_run_of(
    firmware: &efi::Firmware,
    esp: &Path,
    data: &Path,
    elf: &Path,
    shape: Shape,
    icount: bool,
    within: Duration,
    probe: &str,
) -> Result<Vec<String>, String> {
    // The variables of the firmware are copied to a file named after the disk of the run.
    let vars = esp
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("nvme-persist");
    let mut cmd = efi::command(&efi::EFI, firmware, esp, true, vars)?;
    if shape != Shape::Absent {
        cmd.arg("-drive").arg(format!(
            "file={},if=none,format=raw,id=data,cache=writeback,werror=report,rerror=report",
            data.display()
        ));
        cmd.args(["-device", &shape.device()]);
    }
    if shape == Shape::Lba4096 {
        cmd.args([
            "-device",
            "nvme-ns,drive=data,bus=data-controller,logical_block_size=4096,physical_block_size=4096",
        ]);
    }
    if icount {
        // One CPU, as the steps of the other services are measured: with two, the virtual time of
        // the idle one runs the services past the deadlines of their heartbeats.
        cmd.args(qemu::ICOUNT).args(["-smp", "1"]);
    }
    let ends = format!("init: {probe} ended: ");
    let output = run_until(cmd, within, Some(&ends), elf)?;
    let failed_start = format!("{probe}: failed");
    if let Some(failed) = output.lines.iter().find(|l| l.starts_with(&failed_start)) {
        return Err(failed.clone());
    }
    qemu::expect_stopped_on(&output, &format!("{ends}exit code 0, not restarted"))?;
    Ok(apart(&output.lines))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The console of run 44340066432 (guests-1, `nvme-persist steps`), from the line of the
    /// first step to the line that follows the loss: the records of the first calls are gone.
    const LOST_START: [&str; 9] = [
        "nvme: serve runs under its budget",
        "service step: 15 kind 66 779 ticks detail 0",
        "service gap: 15 kind 66 8513 ticks of 9292",
        "nvme: first interrupt of vector 0",
        "[kernel log: 16 records lost]",
        "pkgd: roots stafeto-dev-root",
        "service step: 15 kind 2 3500 ticks detail 0",
        "service step: 15 kind 65 2734 ticks detail 0",
        "service step: 15 kind 6 5064 ticks detail 0",
    ];

    fn console(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| (*l).to_owned()).collect()
    }

    #[test]
    fn the_records_lost_are_counted_and_a_missing_kind_is_named() {
        let mut lines = console(&LOST_START);
        lines.push("[kernel log: 23 records lost]".to_owned());
        assert_eq!(lost_records(&lines), [16, 23]);
        let rows = longest_steps(&lines, blk_probe::BLK_TAG);
        let kinds = [(1, "Info"), (2, "Read"), (5, "Buffer"), (6, "Take")];
        let why = judge("the NVMe service", &rows, &kinds).unwrap_err();
        assert!(why.contains("no step Info"), "{why}");
    }

    #[test]
    fn a_run_with_the_first_calls_passes_the_judge() {
        let mut lines = console(&LOST_START);
        lines.push("service step: 15 kind 5 8058 ticks detail 0".to_owned());
        lines.push("service step: 15 kind 1 2192 ticks detail 0".to_owned());
        let rows = longest_steps(&lines, blk_probe::BLK_TAG);
        let kinds = [(1, "Info"), (2, "Read"), (5, "Buffer"), (6, "Take")];
        assert_eq!(judge("the NVMe service", &rows, &kinds), Ok(()));
    }

    use super::apart;

    #[test]
    fn a_line_of_pkgd_that_another_writers_text_came_before_is_set_apart() {
        let lines: Vec<String> = [
            "ramfs: audit round 4pkgd: roots stafeto-dev-root",
            "pkgd: ready, 0 packages",
            "store-probe: says pkgd: roots stafeto-dev-root in a text",
            "a text that names pkgd: store formatted stays",
        ]
        .iter()
        .map(|l| (*l).to_owned())
        .collect();
        assert_eq!(
            apart(&lines),
            [
                "ramfs: audit round 4",
                "pkgd: roots stafeto-dev-root",
                "pkgd: ready, 0 packages",
                "store-probe: says pkgd: roots stafeto-dev-root in a text",
                "a text that names pkgd: store formatted stays",
            ]
        );
    }
}
