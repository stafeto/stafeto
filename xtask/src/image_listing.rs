// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask image-listing [--out DIR] [name...]`: builds the boot images
//! named (the images that hold packages, all of them without a name) and
//! writes for each the listing of the tree its file service shows: the path,
//! the mode, the owner and the SHA-256 of the content of every entry of the
//! table `rootfs` and of every package file (`.stpkg`) the container holds,
//! merged. The listing of an image before and after a change of how its
//! packages go in is the proof that the image shows the same tree.

use crate::*;
use bootimg::BootImage;
use bootimg::rootfs::Rootfs;
use pkgfmt::Package as PackageFile;
use std::collections::BTreeMap;

fn digest(bytes: &[u8]) -> String {
    let mut buf = [0u8; 64];
    pkgfmt::sha::hex(&pkgfmt::sha::sha256(bytes), &mut buf).to_string()
}

fn line(e: &bootimg::rootfs::Entry<'_>, content: &[u8]) -> String {
    let kind = match e.mode & bootimg::rootfs::FORMAT {
        bootimg::rootfs::DIRECTORY => "dir",
        bootimg::rootfs::SYMLINK => "link",
        _ => "file",
    };
    let sum = if e.is_directory() {
        "-".to_string()
    } else if e.is_symlink() {
        String::from_utf8_lossy(content).into_owned()
    } else {
        digest(content)
    };
    format!("{kind} {:04o} {}:{} {sum}", e.mode & 0o7777, e.uid, e.gid)
}

/// The listing of the boot image `bytes`: lines `<path> <kind> <mode>
/// <uid>:<gid> <content>`, sorted by path, the names of the table and of the
/// packages merged as the file service merges them. A path two sources name
/// differently is listed once per source, after a `!`.
pub fn listing(bytes: &[u8]) -> Result<Vec<String>, String> {
    let image = BootImage::parse(bytes).map_err(|e| e.to_string())?;
    let mut tree: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut add = |path: &str, text: String| {
        let at = tree.entry(path.to_string()).or_default();
        if !at.contains(&text) {
            at.push(text);
        }
    };
    if let Some(table) = image.files().find(|f| f.name == "rootfs") {
        let rootfs = Rootfs::parse(table.data, image.count()).map_err(|e| e.to_string())?;
        for n in 0..rootfs.len() as u32 {
            let e = rootfs.entry(n);
            let content = if e.is_directory() {
                &[][..]
            } else {
                image.file_at(e.file).map_or(&[][..], |f| f.data)
            };
            add(e.path, line(&e, content));
        }
    }
    for file in image.files().filter(|f| f.name.ends_with(".stpkg")) {
        let package = PackageFile::parse(file.data).map_err(|e| format!("{}: {e}", file.name))?;
        for n in 0..package.rootfs.len() as u32 {
            let e = package.rootfs.entry(n);
            add(e.path, line(&e, package.content(n)));
        }
    }
    let mut out = Vec::new();
    for (path, texts) in tree {
        if let [one] = texts.as_slice() {
            out.push(format!("{path} {one}"));
        } else {
            out.extend(texts.iter().map(|t| format!("! {path} {t}")));
        }
    }
    Ok(out)
}

/// The files of the container of `bytes` that are no program of the table:
/// `<name> <length> <sha256>`, for the part of a report that names the
/// notice files and the packages of an image.
pub fn container(bytes: &[u8]) -> Result<Vec<String>, String> {
    let image = BootImage::parse(bytes).map_err(|e| e.to_string())?;
    Ok(image
        .files()
        .map(|f| format!("{} {} {}", f.name, f.data.len(), digest(f.data)))
        .collect())
}

/// Builds the image `name` the way its own probe does.
fn build_named(name: &'static str) -> Result<PathBuf, String> {
    let programs: &'static [ImageProgram] = match name {
        "boot-ash-dialog.img" => shell_programs(),
        "boot-doom.img" => doom::programs(),
        "boot-doom-steps.img" => doom::steps_programs(),
        "boot-net.img" | "boot-net-tls.img" => net::programs(),
        "boot-net-curl-steps.img" | "boot-net-tls-steps.img" => net_curl::steps_programs(),
        "boot-nginx-probe.img" => nginx_probe::programs(),
        "boot-nginx-probe-steps.img" => nginx_probe::steps_programs(),
        "boot-nginx-bench.img" => nginx_bench::programs(false),
        "boot-fast-nginx.img" => fast_nginx::programs(fast_nginx::Kind::Plain),
        "boot-fstack-probe.img" => fstack_probe::programs(),
        "boot-fast-layer.img" => fast_layer::programs(),
        "boot-fstack-device.img" => fstack_device::programs(false),
        "boot-fast-probe.img" => fast_probe::programs(false),
        other => return Err(format!("{other}: no builder for the listing")),
    };
    build_boot_image(name, programs, BOOT_PROFILE)
}

const NAMES: [&str; 15] = [
    "boot-ash-dialog.img",
    "boot-doom.img",
    "boot-doom-steps.img",
    "boot-net.img",
    "boot-net-tls.img",
    "boot-nginx-probe.img",
    "boot-nginx-bench.img",
    "boot-fast-nginx.img",
    "boot-fstack-probe.img",
    "boot-fast-layer.img",
    "boot-fstack-device.img",
    "boot-fast-probe.img",
    "boot-net-curl-steps.img",
    "boot-net-tls-steps.img",
    "boot-nginx-probe-steps.img",
];

/// `cargo xtask image-listing [--out DIR] [name...]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let mut out = target_dir().join("listing");
    let mut names: Vec<&'static str> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--out" {
            out = it.next().ok_or("--out wants a directory")?.into();
        } else {
            names.push(
                NAMES
                    .iter()
                    .find(|n| **n == a)
                    .ok_or_else(|| format!("{a}: no builder for the listing"))?,
            );
        }
    }
    if names.is_empty() {
        names = NAMES.to_vec();
    }
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    busybox_build()?;
    nano_build()?;
    net_build()?;
    doom::build_games()?;
    for name in &names {
        let path = build_named(name)?;
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let lines = listing(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let text = lines.join("\n") + "\n";
        let file = out.join(format!("{}.txt", name.trim_end_matches(".img")));
        std::fs::write(&file, text).map_err(|e| format!("{}: {e}", file.display()))?;
        let files = out.join(format!("{}.container.txt", name.trim_end_matches(".img")));
        std::fs::write(&files, container(&bytes)?.join("\n") + "\n")
            .map_err(|e| format!("{}: {e}", files.display()))?;
        println!("image-listing: {name}: {} entries", lines.len());
    }
    Ok(())
}
