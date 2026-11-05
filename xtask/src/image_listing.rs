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

/// One entry of a source (the table or a package file) before it is merged.
struct Item {
    path: String,
    kind: &'static str,
    mode: u32,
    owner: (u32, u32),
    /// The content: its SHA-256, or the target of a link.
    content: String,
    /// The number of the file of its source, for the entries that name one.
    file: Option<u32>,
}

fn item(e: &bootimg::rootfs::Entry<'_>, content: &[u8]) -> Item {
    let kind = match e.mode & bootimg::rootfs::FORMAT {
        bootimg::rootfs::DIRECTORY => "dir",
        bootimg::rootfs::SYMLINK => "link",
        _ => "file",
    };
    let content = if e.is_directory() {
        "-".to_string()
    } else if e.is_symlink() {
        String::from_utf8_lossy(content).into_owned()
    } else {
        digest(content)
    };
    Item {
        path: e.path.to_string(),
        kind,
        mode: e.mode & 0o7777,
        owner: (e.uid, e.gid),
        content,
        file: (!e.is_directory()).then_some(e.file),
    }
}

/// The lines of one source: the regular files that name one file of the
/// source are hard links (the link count is their number, and `node=` names
/// the first of them, the node they share); a symbolic link is a node of
/// its own with one link, as the file service makes it from a table and
/// from a package file alike.
fn lines_of(items: &[Item]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|i| {
            let (links, node) = match (i.kind, i.file) {
                ("dir", _) | (_, None) => ("-".to_string(), "-".to_string()),
                ("link", _) => ("1".to_string(), i.path.clone()),
                (_, Some(file)) => {
                    let same: Vec<_> = items
                        .iter()
                        .filter(|j| j.kind == "file" && j.file == Some(file))
                        .collect();
                    (same.len().to_string(), same[0].path.clone())
                }
            };
            (
                i.path.clone(),
                format!(
                    "{} {:04o} {}:{} links={links} node={node} {}",
                    i.kind, i.mode, i.owner.0, i.owner.1, i.content
                ),
            )
        })
        .collect()
}

/// The listing of the boot image `bytes`: lines `<path> <kind> <mode>
/// <uid>:<gid> links=<n> node=<path> <content>`, sorted by path, the names
/// of the table and of the packages merged as the file service merges them.
/// A path two sources name is one line per source after a `!`, equal bytes
/// or not, because the file service refuses such a layer; a directory that
/// both name merges.
pub fn listing(bytes: &[u8]) -> Result<Vec<String>, String> {
    let image = BootImage::parse(bytes).map_err(|e| e.to_string())?;
    let mut tree: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut add = |source: &str, items: &[Item]| {
        for (path, text) in lines_of(items) {
            tree.entry(path)
                .or_default()
                .push((source.to_string(), text));
        }
    };
    if let Some(table) = image.files().find(|f| f.name == "rootfs") {
        let rootfs = Rootfs::parse(table.data, image.count()).map_err(|e| e.to_string())?;
        let items: Vec<Item> = (0..rootfs.len() as u32)
            .map(|n| {
                let e = rootfs.entry(n);
                let content = if e.is_directory() {
                    &[][..]
                } else {
                    image.file_at(e.file).map_or(&[][..], |f| f.data)
                };
                item(&e, content)
            })
            .collect();
        add("table", &items);
    }
    for file in image.files().filter(|f| f.name.ends_with(".stpkg")) {
        let package = PackageFile::parse(file.data).map_err(|e| format!("{}: {e}", file.name))?;
        let items: Vec<Item> = (0..package.rootfs.len() as u32)
            .map(|n| item(&package.rootfs.entry(n), package.content(n)))
            .collect();
        add(file.name, &items);
    }
    let mut out = Vec::new();
    for (path, texts) in tree {
        let directories = texts.iter().all(|(_, t)| t.starts_with("dir "));
        let same = texts.iter().all(|(_, t)| *t == texts[0].1);
        if texts.len() == 1 || (directories && same) {
            out.push(format!("{path} {}", texts[0].1));
        } else {
            out.extend(
                texts
                    .iter()
                    .map(|(source, t)| format!("! {path} {t} in {source}")),
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, mode: u32, file: u32) -> Item {
        Item {
            path: path.into(),
            kind: match mode & bootimg::rootfs::FORMAT {
                bootimg::rootfs::DIRECTORY => "dir",
                bootimg::rootfs::SYMLINK => "link",
                _ => "file",
            },
            mode: mode & 0o7777,
            owner: (0, 0),
            content: "x".into(),
            file: (mode & bootimg::rootfs::FORMAT != bootimg::rootfs::DIRECTORY).then_some(file),
        }
    }

    /// The applets of BusyBox are symbolic links that name one file of the
    /// package: the listing shows one link and a node each, and two names of
    /// the program two links and one node. A file service that counted the
    /// links of a file number without telling the kinds apart (87 links on
    /// `/bin/busybox`, one node for all the applets) would differ from this
    /// in every line of the applets.
    #[test]
    fn links_and_nodes_are_listed_as_the_service_shows_them() {
        use bootimg::rootfs::{REGULAR, SYMLINK};
        let items = [
            entry("/bin/ash", SYMLINK | 0o777, 3),
            entry("/bin/busybox", REGULAR | 0o755, 4),
            entry("/bin/cat", SYMLINK | 0o777, 3),
            entry("/libexec/login", REGULAR | 0o755, 4),
        ];
        let lines: Vec<String> = lines_of(&items).into_iter().map(|(_, l)| l).collect();
        assert!(lines[0].contains("links=1 node=/bin/ash"), "{}", lines[0]);
        assert!(lines[2].contains("links=1 node=/bin/cat"), "{}", lines[2]);
        assert!(
            lines[1].contains("links=2 node=/bin/busybox"),
            "{}",
            lines[1]
        );
        assert!(
            lines[3].contains("links=2 node=/bin/busybox"),
            "{}",
            lines[3]
        );
    }
}
