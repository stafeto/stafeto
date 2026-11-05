// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask layer-probe [steps]`: the layers of the RAM file service in QEMU
//! (tests/layer-probe, tests/layer-user). The layers of the test are built here as package
//! files and put in the image as files of `/test/layers`; the leader of the probe reads them
//! and attaches them through its layer session. `steps` runs the service with its step
//! statistics under -icount and checks the steps of the layer methods and of the maintenance
//! against the limits of the design (0.9 B for every step, 0.8 B for the largest of the
//! step method).

use crate::{
    BOOT_PROFILE, BOOT_TIMEOUT, INIT_STACK_SIZE, ImageProgram, POSIX_STACK_SIZE, PROGRAM_TARGET,
    RAMFS_STACK_SIZE, TERM_B, Variant, build, cargo, cargo_output, longest_steps, qemu, relibc,
    rootfs, run_cmd, run_until, target_dir, write_boot_image_files,
};
use std::path::PathBuf;

/// The largest step of a service at 0.9 B, in ticks (design pk1-design R5).
const STEP_MAX: u64 = TERM_B * 9 / 10;
/// The largest step of the layer step method at 0.8 B.
const PORTION_MAX: u64 = TERM_B * 8 / 10;

const PROGRAMS: [ImageProgram; 7] = [
    ("init", "init", INIT_STACK_SIZE, &["table-layer-probe"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &["layer-probe"]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("layer-probe", "layer-probe", POSIX_STACK_SIZE, &[]),
    ("layer-user", "layer-user", POSIX_STACK_SIZE, &[]),
    ("loader", "loader", 0, &["small-pieces"]),
];
const PROGRAMS_STEPS: [ImageProgram; 7] = {
    let mut programs = PROGRAMS;
    programs[1].3 = &["layer-probe", "steps"];
    programs
};

pub fn dispatch(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => run(false).map(drop),
        Some("steps") => steps(),
        Some(other) => Err(format!("layer-probe: unknown argument {other}")),
    }
}

/// The pattern of the file `/layer/data/big` of the layer `good`: tests/layer-user/user.c.
fn pattern(i: usize) -> u8 {
    ((i ^ (i >> 8) ^ (i >> 16)) & 0xff) as u8
}

/// The names of the layers of the test.
pub struct Layer {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
struct Item {
    path: String,
    mode: u32,
    file: Option<usize>,
}

/// A layer under construction: entries in the order given (the raw table writer does not sort
/// or check, so the layers that break a rule can be written) and the content files.
#[derive(Default)]
struct Spec {
    items: Vec<Item>,
    contents: Vec<Vec<u8>>,
}

const DIRECTORY: u32 = 0o040_000;
const REGULAR: u32 = 0o100_000;
const SYMLINK: u32 = 0o120_000;

impl Spec {
    fn dir(&mut self, path: &str) {
        self.items.push(Item {
            path: path.into(),
            mode: DIRECTORY | 0o755,
            file: None,
        });
    }
    fn file(&mut self, path: &str, mode: u32, bytes: Vec<u8>) {
        self.contents.push(bytes);
        self.items.push(Item {
            path: path.into(),
            mode: REGULAR | mode,
            file: Some(self.contents.len() - 1),
        });
    }
    fn link(&mut self, path: &str, of: &str) {
        let item = self
            .items
            .iter()
            .find(|i| i.path == of)
            .expect("the file")
            .clone();
        self.items.push(Item {
            path: path.into(),
            ..item
        });
    }
    fn symlink(&mut self, path: &str, target: &str) {
        self.contents.push(target.as_bytes().to_vec());
        self.items.push(Item {
            path: path.into(),
            mode: SYMLINK | 0o777,
            file: Some(self.contents.len() - 1),
        });
    }

    /// The package file: the container `STAFPKG1` (meta, rootfs, manifest, then the contents
    /// at 4 KiB boundaries) and a trailer page, which the service does not read.
    fn build(&self) -> Vec<u8> {
        let mut table = Vec::new();
        table.extend_from_slice(b"STAFROOT");
        table.extend_from_slice(&2u32.to_le_bytes());
        table.extend_from_slice(&(self.items.len() as u32).to_le_bytes());
        table.extend_from_slice(&5_000u64.to_le_bytes());
        let mut offset = 24 + 24 * self.items.len();
        for item in &self.items {
            table.extend_from_slice(&(offset as u32).to_le_bytes());
            table.extend_from_slice(&(item.path.len() as u16).to_le_bytes());
            table.extend_from_slice(&[0, 0]);
            table.extend_from_slice(&item.mode.to_le_bytes());
            table.extend_from_slice(&0u32.to_le_bytes());
            table.extend_from_slice(&0u32.to_le_bytes());
            table.extend_from_slice(&item.file.map_or(0, |f| 3 + f as u32).to_le_bytes());
            offset += item.path.len();
        }
        for item in &self.items {
            table.extend_from_slice(item.path.as_bytes());
        }
        let mut files: Vec<(String, &[u8])> = vec![
            ("meta".into(), b"meta"),
            ("rootfs".into(), &table),
            ("manifest".into(), b"manifest"),
        ];
        for (n, content) in self.contents.iter().enumerate() {
            files.push((format!("{}", n + 3), content));
        }
        let mut out = vec![0u8; 16 + 48 * files.len()];
        out[..8].copy_from_slice(b"STAFPKG1");
        out[8..12].copy_from_slice(&1u32.to_le_bytes());
        out[12..16].copy_from_slice(&(files.len() as u32).to_le_bytes());
        let mut cursor = out.len().next_multiple_of(4096);
        for (n, (name, bytes)) in files.iter().enumerate() {
            let at = 16 + 48 * n;
            out[at..at + name.len()].copy_from_slice(name.as_bytes());
            out[at + 32..at + 40].copy_from_slice(&(cursor as u64).to_le_bytes());
            out[at + 40..at + 48].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            if !bytes.is_empty() {
                out.resize(cursor, 0);
                out.extend_from_slice(bytes);
                cursor = out.len().next_multiple_of(4096);
            }
        }
        out.resize(cursor.max(out.len()).next_multiple_of(4096) + 4096, 0);
        out
    }
}

fn good(hello: &[u8]) -> Spec {
    let mut spec = Spec::default();
    spec.dir("/layer");
    spec.dir("/layer/bin");
    spec.file("/layer/bin/hello", 0o755, hello.to_vec());
    spec.link("/layer/bin/hi", "/layer/bin/hello");
    spec.symlink("/layer/bin/world", "hello");
    spec.dir("/layer/data");
    spec.file(
        "/layer/data/big",
        0o644,
        (0..256 * 1024).map(pattern).collect(),
    );
    spec.dir("/usr");
    spec.dir("/usr/share");
    spec.dir("/usr/share/licenses");
    spec.dir("/usr/share/licenses/layer-test");
    spec.file(
        "/usr/share/licenses/layer-test/LICENSE",
        0o644,
        b"layer test license\n".to_vec(),
    );
    spec
}

/// The bucket of a name in a directory (services/ramfs/src/storage.rs, `name_bucket`).
fn bucket(parent_slot: u32, name: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5 ^ parent_slot;
    for &byte in name {
        hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
    }
    (hash ^ (hash >> 15)) & 2047
}

/// A layer of 1 024 entries with paths of 511 bytes and names of 255: the directories `/w`
/// and `/w/aaa...` and 1 022 empty files. With `one_bucket` all the names of the files hash to
/// one bucket of the service when the directory `/w/aaa...` is the second directory a layer
/// created in a service that had none (its node is the place 6 150 of the nodes).
fn wide(one_bucket: bool) -> Spec {
    const DIR_SLOT: u32 = 6150;
    let a = "a".repeat(255);
    let mut spec = Spec::default();
    spec.dir("/w");
    spec.dir(&format!("/w/{a}"));
    let prefix = vec![b'x'; 252 - 6];
    let suffix = |mut n: u32| -> [u8; 6] {
        let mut out = [b'a'; 6];
        for byte in out.iter_mut().rev() {
            *byte = b'a' + (n % 26) as u8;
            n /= 26;
        }
        out
    };
    let target = bucket(DIR_SLOT, &[prefix.as_slice(), &suffix(0)].concat());
    let mut names: Vec<String> = Vec::new();
    let mut counter = 0u32;
    while names.len() < 1022 {
        let name = [prefix.as_slice(), &suffix(counter)].concat();
        counter += 1;
        if !one_bucket || bucket(DIR_SLOT, &name) == target {
            names.push(String::from_utf8(name).expect("ASCII"));
        }
    }
    names.sort();
    for name in names {
        spec.file(&format!("/w/{a}/{name}"), 0o644, Vec::new());
    }
    spec
}

/// The layers of the probe. `steps` adds the wide ones.
fn layers(hello: &[u8], steps: bool) -> Vec<Layer> {
    let mut out = vec![Layer {
        name: "good",
        bytes: good(hello).build(),
    }];
    let mut conflict = Spec::default();
    conflict.dir("/etc");
    conflict.file("/etc/passwd", 0o644, b"other\n".to_vec());
    out.push(Layer {
        name: "conflict",
        bytes: conflict.build(),
    });
    let mut setid = Spec::default();
    setid.dir("/s");
    setid.file("/s/x", 0o4755, b"x".to_vec());
    out.push(Layer {
        name: "setid",
        bytes: setid.build(),
    });
    let mut bad = Spec::default();
    bad.file("/b", 0o644, b"b".to_vec());
    bad.file("/a", 0o644, b"a".to_vec());
    out.push(Layer {
        name: "bad",
        bytes: bad.build(),
    });
    if steps {
        // 1 023 entries with short names: the cost of an entry that is not in its bytes.
        let mut many = Spec::default();
        many.dir("/m");
        for n in 0..1023 {
            many.file(&format!("/m/f{n:04}"), 0o644, Vec::new());
        }
        out.push(Layer {
            name: "many",
            bytes: many.build(),
        });
        out.push(Layer {
            name: "wide",
            bytes: wide(false).build(),
        });
        out.push(Layer {
            name: "wideb",
            bytes: wide(true).build(),
        });
    }
    out
}

/// The ELF file of `layer-user`, which is the program the layer `good` holds.
fn hello_elf() -> Result<Vec<u8>, String> {
    let mut cmd = cargo();
    cmd.arg("build").args(BOOT_PROFILE.args());
    cmd.args(["--target", PROGRAM_TARGET, "--package", "layer-user"]);
    run_cmd(&mut cmd)?;
    let path = cargo_output(&target_dir(), PROGRAM_TARGET, BOOT_PROFILE, "layer-user");
    std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
}

fn extra_files(layers: Vec<Layer>) -> Vec<rootfs::RootFile> {
    layers
        .into_iter()
        .map(|layer| {
            let name: &'static str = Box::leak(format!("{}.layer", layer.name).into_boxed_str());
            let path: &'static str =
                Box::leak(format!("/test/layers/{}.layer", layer.name).into_boxed_str());
            let bytes: &'static [u8] = Box::leak(layer.bytes.into_boxed_slice());
            rootfs::RootFile {
                path,
                mode: 0o444,
                uid: 0,
                gid: 0,
                source: Some(rootfs::Source::Bytes(name, bytes)),
            }
        })
        .collect()
}

fn image(steps: bool) -> Result<(PathBuf, qemu::Machine), String> {
    let hello = hello_elf()?;
    let name = if steps {
        "boot-layer-probe-steps.img"
    } else {
        "boot-layer-probe.img"
    };
    let programs: &'static [ImageProgram] = if steps { &PROGRAMS_STEPS } else { &PROGRAMS };
    let image = write_boot_image_files(
        name,
        programs,
        BOOT_PROFILE,
        &[],
        extra_files(layers(&hello, steps)),
    )?;
    Ok((image, qemu::VIRT))
}

/// Runs the probe: the lines of its output.
fn run(steps: bool) -> Result<Vec<String>, String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let kernel = build(Variant::Normal)?;
    let (image, machine) = image(steps)?;
    let mut cmd = qemu::command(&machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    if steps {
        cmd.args(qemu::ICOUNT);
    }
    let output = run_until(
        cmd,
        BOOT_TIMEOUT * 3,
        Some("init: layer-probe ended: "),
        &kernel.elf,
    )?;
    for marker in [
        "layer-probe: 1 good attached and looked at ok",
        "layer-probe: 2 conflict, set-ID and table refusals ok",
        "layer-probe: 3 detach, open file, release and unmap ok",
        "layer-probe: 4 big three times beside a reader ok",
        "layer-probe: 5 a refused unmap keeps the record ok",
        "layer-user: good looked at ok",
        "layer-user: open file and program after the detach ok",
        "layer-user: ok",
        "layer-probe: ok",
    ] {
        qemu::expect_marker(&output, marker)?;
    }
    qemu::expect_stopped_on(
        &output,
        "init: layer-probe ended: exit code 0, not restarted",
    )?;
    if output.lines.iter().any(|l| l.contains("not attached")) {
        return Err("a layer of the image was not attached".into());
    }
    for line in output
        .lines
        .iter()
        .filter(|l| l.contains("mappings before the layers") || l.contains("layers bytes="))
    {
        println!("{line}");
    }
    Ok(output.lines)
}

/// The steps of the layer methods under -icount (tag 2 is the RAM file service).
fn steps() -> Result<(), String> {
    let lines = run(true)?;
    let rows = longest_steps(&lines, "2");
    let mut worst = 0;
    for &(kind, ticks, detail) in &rows {
        let name = crate::RAM_STEP_KINDS
            .iter()
            .find(|(k, _)| *k == kind)
            .map_or("other", |(_, name)| name);
        println!("ramfs step {kind} {name}: {ticks} ticks, detail {detail}");
        // The steps of the layer calls, of ReadInto beside the mapping of the big layer and
        // of the maintenance and notifications are the ones this probe bounds; the others
        // belong to the probes of their own, and kind 63 is the whole start of the service,
        // which the first line of the counter takes in.
        if matches!(kind, 17 | 51 | 53 | 64 | 65) {
            worst = worst.max(ticks);
            if ticks > STEP_MAX {
                return Err(format!(
                    "ramfs step {kind} {name}: {ticks} ticks, over 0.9 B = {STEP_MAX}"
                ));
            }
        }
    }
    for kind in [51, 53, 65] {
        if !rows.iter().any(|r| r.0 == kind) {
            return Err(format!("no step of kind {kind} was measured: {rows:?}"));
        }
    }
    let portion = rows.iter().find(|r| r.0 == 53).map_or(0, |r| r.1);
    if portion > PORTION_MAX {
        return Err(format!(
            "the layer step: {portion} ticks, over 0.8 B = {PORTION_MAX}"
        ));
    }
    println!(
        "layer-probe steps: the worst step {worst} of 0.9 B {STEP_MAX}; layer step {portion} of 0.8 B {PORTION_MAX}"
    );
    Ok(())
}
