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
//! `steps` runs the first with the services under -icount with their step statistics and a
//! store that also holds `big` (16 MiB) and `wide` (1,000 files in a directory), so the main thread of the
//! service answers while its worker creates, maps, hashes and attaches them: every kind of its
//! steps and of the disk service's stays under 0.9 of term B (18,369 ticks).

use super::*;
use pkgd::host::{self, Contents, FileDevice, Item};
use pkgfmt::cert::PURPOSE_PACKAGES;
use pkgfmt::container::write::{Content, Item as Part, container, sign};
use pkgfmt::meta::Meta;
use pkgfmt::{Certificate, Key, Kind, Revocation, keyfile, sig};
use std::path::{Path, PathBuf};

const PKGD_STACK_SIZE: u32 = 32 * 1024;
const DISK_BYTES: u64 = 512 << 20;
/// The tags of the services' lines of steps: the file service 2, the disk 15, the package service 16.
const RAM_TAG: &str = "2";
const PKGD_TAG: &str = "16";
/// The kinds of the package service's steps that must come: the methods LIST, INFO,
/// SETTINGS_GET, SERIAL, CLONE, TAKE, BUFFER and STATUS, the heartbeat, a notification and
/// the departure of a session.
const PKGD_STEP_KINDS: [(usize, &str); 11] = [
    (1, "List"),
    (2, "Info"),
    (8, "SettingsGet"),
    (10, "Serial"),
    (12, "Clone"),
    (14, "Take"),
    (15, "Buffer"),
    (16, "Status"),
    (64, "the heartbeat"),
    (65, "a notification"),
    (66, "the departure of a session"),
];
const BLK_STEP_KINDS: [(usize, &str); 4] = [(1, "Info"), (2, "Read"), (5, "Buffer"), (6, "Take")];
const ENDED: &str = "init: store-probe ended: exit code 0, not restarted";

const fn programs(steps: bool) -> [ImageProgram; 10] {
    let more: &'static [&'static str] = if steps { &["steps"] } else { &[] };
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
        ("pkgd", "pkgd", PKGD_STACK_SIZE, more),
        ("store-probe", "store-probe", POSIX_STACK_SIZE, &[]),
        ("loader", "loader", 0, &[]),
    ]
}
const PROGRAMS: [ImageProgram; 10] = programs(false);
const PROGRAMS_STEPS: [ImageProgram; 10] = programs(true);

pub fn command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => disk().and_then(|()| empty()),
        Some("steps") => steps(),
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

/// A package file: a program `/<dir>/bin/<name>` of `program`, a hard link to it, and
/// `padding` bytes of a pattern in a file of their own.
fn package(
    name: &str,
    program: &[u8],
    seed: &[u8; 32],
    key: &Key,
    certificate: [u8; pkgfmt::cert::SIZE],
    extra: &[(String, Vec<u8>)],
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
    for (p, bytes) in extra {
        parts.push(Part {
            path: p,
            mode: 0o100_644,
            content: Content::Data(bytes),
        });
    }
    let series = pkg::series();
    let meta = Meta {
        name,
        version: "1.0",
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
    let covered = container(&meta, &parts, 1_700_000_000).map_err(|e| format!("{name}: {e}"))?;
    sign(covered, seed, key.name, Some(certificate), now()).map_err(|e| format!("{name}: {e}"))
}

/// The files of the store: what the probe expects to find, with the packages of the
/// measurement when `steps`.
fn contents(hello: &[u8], steps: bool) -> Result<Contents, String> {
    let keys = dev_keys()?;
    let (seed, key, certificate) = (
        &keys.dev.release_seed,
        &keys.dev.release,
        keys.dev.certificate,
    );
    let item = |bytes: Vec<u8>| Item {
        bytes,
        repository: "stafeto".into(),
        flags: pkgd::store::WORLD,
        installed: 1,
    };
    let good = package("hello", hello, seed, key, certificate, &[])?;
    let mut broken = package("broken", hello, seed, key, certificate, &[])?;
    let at = broken
        .windows(4)
        .position(|w| w == b"\x7fELF")
        .ok_or("no program in the package")?;
    broken[at + 24] ^= 1;
    let revoked = package(
        "revoked",
        hello,
        &keys.second_seed,
        &keys.second,
        keys.second_certificate,
        &[],
    )?;
    let mut packages = vec![item(good), item(broken), item(revoked)];
    if steps {
        // 16 MiB of a pattern in one file, and 1,000 files of one byte.
        let big: Vec<u8> = (0..16usize << 20)
            .map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8)
            .collect();
        packages.push(item(package(
            "big",
            hello,
            seed,
            key,
            certificate,
            &[("/big/data".into(), big)],
        )?));
        let wide: Vec<(String, Vec<u8>)> = (0..1000)
            .map(|i| (format!("/wide/f{i:04}"), vec![b'w']))
            .collect();
        packages.push(item(package("wide", hello, seed, key, certificate, &wide)?));
    }
    let games = keyfile::public_line(&Key {
        name: pkgfmt::Name::new("games").map_err(|e| e.to_string())?,
        public: sig::public_key(&[9; 32]),
    });
    let settings = proto_pkg::blob::write(&[
        ("repositories", b"games https://example.org/games\n"),
        ("keys/games.pub", games.as_bytes()),
    ]);
    let list = pkgfmt::revoked::write(
        2,
        &[Revocation {
            name: keys.second.name,
            since: 0,
        }],
    )
    .map_err(|e| e.to_string())?;
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
    let contents = Contents {
        packages,
        settings: Some(settings),
        revoked: Some((file, 2)),
        repositories: vec![("games".into(), 4)],
    };
    Ok(contents)
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
    let roots = root().join("target/keys/stafeto-dev-root.pub");
    keys::dev_keys(&root())?;
    let roots = roots.display().to_string();
    let name = if steps {
        "boot-store-probe-steps.img"
    } else {
        "boot-store-probe.img"
    };
    let programs: &'static [ImageProgram] = if steps { &PROGRAMS_STEPS } else { &PROGRAMS };
    write_boot_image_files(
        name,
        programs,
        BOOT_PROFILE,
        &[("STAFETO_PKG_ROOTS", &roots)],
        Vec::new(),
    )
}

/// The file of a disk run: named by the process, removed at the end.
struct Disk(PathBuf);

impl Disk {
    fn new(what: &str) -> Disk {
        Disk(std::env::temp_dir().join(format!("stafeto-store-{}-{what}.img", std::process::id())))
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_disk(disk: &Disk, contents: Option<&Contents>) -> Result<Option<host::Layout>, String> {
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
    let kernel = build(Variant::Normal)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(image));
    cmd.args(qemu::HEADLESS).args(qemu::store(disk, None));
    if steps {
        cmd.args(qemu::ICOUNT);
    }
    let output = run_until(
        cmd,
        BOOT_TIMEOUT * 8,
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

fn steps() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let contents = contents(&hello_elf()?, true)?;
    let file = Disk::new("steps");
    let layout = write_disk(&file, Some(&contents))?.ok_or("no layout")?;
    let lines = run(&image(true)?, &file.0, true)?;
    expect(&lines, &disk_lines(&layout)[..4])?;
    let pkgd = longest_steps(&lines, PKGD_TAG);
    let blk = longest_steps(&lines, blk_probe::BLK_TAG);
    let ram = longest_steps(&lines, RAM_TAG);
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
    let text = |rows: &[(usize, u64, u64)]| {
        rows.iter()
            .map(|(k, t, _)| format!("kind {k} {t}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!("store-probe steps: pkgd {}", text(&pkgd));
    println!("store-probe steps: the disk service {}", text(&blk));
    println!("store-probe steps: the file service {}", text(&ram));
    for line in lines
        .iter()
        .filter(|l| l.starts_with("pkgd: work") || l.starts_with("pkgd: memory"))
    {
        println!("{line}");
    }
    println!(
        "store-probe steps: every step of the package service under 0.9 of term B ({}): ok",
        blk_probe::STEP_MAX
    );
    Ok(())
}
