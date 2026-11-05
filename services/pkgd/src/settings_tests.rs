// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::settings::{CONTAINER_MAX, Invalid, Settings, container};
use bootimg::rootfs::Rootfs;
use bootimg::{BootImage, PACKAGE};
use pkgfmt::{Key, keyfile};
use proto_pkg::blob;

fn key_line(name: &str) -> String {
    keyfile::public_line(&Key {
        name: crate::testkit::name(name),
        public: [5; 32],
    })
}

fn valid() -> Vec<u8> {
    let key = key_line("games");
    blob::write(&[
        (
            "repositories",
            b"games https://example.org/games\ndisable stafeto\n",
        ),
        ("keys/games.pub", key.as_bytes()),
    ])
}

fn games_with(key_name: &str, byte: u8, lines: &str) -> Vec<u8> {
    let key = keyfile::public_line(&Key {
        name: crate::testkit::name(key_name),
        public: [byte; 32],
    });
    blob::write(&[
        ("repositories", lines.as_bytes()),
        ("keys/games.pub", key.as_bytes()),
    ])
}

#[test]
fn settings_keep_the_line_and_the_key_of_a_repository_a_package_came_from() {
    let old = games_with("games", 5, "games https://example.org/games\n");
    let same = games_with("games", 5, "games https://example.org/other\n");
    let other_key = games_with("games", 6, "games https://example.org/games\n");
    let disabled = games_with("games", 5, "disable games\n");
    let none = blob::write(&[]);
    let keeps =
        |new: &[u8], old: &[u8], held: &[&str]| Settings::parse(new).unwrap().keeps(old, held);
    // Nothing held: any blob. The address may change; the key and the line may not.
    assert!(keeps(&none, &old, &[]));
    assert!(keeps(&same, &old, &["games"]));
    assert!(!keeps(&other_key, &old, &["games"]));
    assert!(!keeps(&none, &old, &["games"]));
    assert!(!keeps(&disabled, &old, &["games"]));
    let added_and_disabled = games_with("games", 5, "games https://example.org/g\ndisable games\n");
    assert!(!keeps(&added_and_disabled, &old, &["games"]));
    // A repository the new blob lacks, whatever the old one held.
    assert!(!keeps(&same, &old, &["games", "tools"]));
    // With no blob held before, a key and a line are enough.
    assert!(keeps(&same, b"", &["games"]));
}

#[test]
fn a_blob_of_the_rules_passes() {
    let bytes = valid();
    let s = Settings::parse(&bytes).unwrap();
    assert_eq!(s.count(), 2);
    assert_eq!(s.key_of("games").unwrap().name.as_str(), "games");
    assert!(s.key_of("other").is_none());
    // No repositories file is fine too: keys alone.
    let key = key_line("k");
    assert!(Settings::parse(&blob::write(&[("keys/k.pub", key.as_bytes())])).is_ok());
    assert!(Settings::parse(&blob::write(&[])).is_ok());
}

fn refused(files: &[(&str, &[u8])]) -> bool {
    Settings::parse(&blob::write(files)).err() == Some(Invalid)
}

#[test]
fn every_rule_of_the_names_and_the_files_is_checked() {
    let key = key_line("games");
    let key = key.as_bytes();
    let repos: &[u8] = b"games https://example.org/g\n";
    // Names: only `repositories` and `keys/<name>.pub`.
    assert!(refused(&[("etc", b"x")]));
    assert!(refused(&[("keys/Games.pub", key)]));
    assert!(refused(&[("keys/games.txt", key)]));
    assert!(refused(&[("keys/.pub", key)]));
    assert!(refused(&[("keys/a/b.pub", key)]));
    assert!(refused(&[("keys/stafeto.pub", key)]));
    assert!(refused(&[
        ("repositories", repos),
        ("repositories", repos),
        ("keys/games.pub", key)
    ]));
    // A key that is no key.
    assert!(refused(&[("keys/games.pub", b"ed25519 !!!! games\n")]));
    assert!(refused(&[("keys/games.pub", b"ed25519 AAAA games\n")]));
    assert!(refused(&[("keys/games.pub", &[0xff, 0xfe])]));
    // The repositories: a repository without its key, the official name, a plain address.
    assert!(refused(&[("repositories", repos)]));
    assert!(refused(&[
        ("repositories", b"stafeto https://example.org/s\n"),
        ("keys/games.pub", key)
    ]));
    assert!(refused(&[
        ("repositories", b"games http://example.org/g\n"),
        ("keys/games.pub", key)
    ]));
    assert!(refused(&[
        ("repositories", b"games\n"),
        ("keys/games.pub", key)
    ]));
    assert!(refused(&[
        ("repositories", b"games https://x y\n"),
        ("keys/games.pub", key)
    ]));
    assert!(refused(&[("repositories", b"disable\n")]));
    assert!(refused(&[("repositories", b"disable Bad\n")]));
    assert!(refused(&[("repositories", &[0xff])]));
    // The blob's own limits: 33 files and one byte over 64 KiB.
    let names: Vec<String> = (0..33).map(|i| format!("keys/k{i}.pub")).collect();
    let keys: Vec<String> = (0..33).map(|i| key_line(&format!("k{i}"))).collect();
    let files: Vec<(&str, &[u8])> = names
        .iter()
        .zip(&keys)
        .map(|(n, k)| (n.as_str(), k.as_bytes()))
        .collect();
    assert!(Settings::parse(&blob::write(&files[..32])).is_ok());
    assert!(refused(&files));
    let big = vec![b'#'; blob::BYTES_MAX - 16 - 2 - 12 - 4];
    assert!(Settings::parse(&blob::write(&[("repositories", &big)])).is_err());
    assert!(refused(&[("repositories", &vec![b'a'; blob::BYTES_MAX])]));
}

fn build(bytes: &[u8]) -> Vec<u8> {
    let s = Settings::parse(bytes).unwrap();
    let mut out = vec![0u8; CONTAINER_MAX];
    let len = container(&s, &mut out).unwrap();
    out.truncate(len);
    out
}

#[test]
fn the_container_is_a_layer_the_file_service_reads() {
    let out = build(&valid());
    assert_eq!(out.len() % 4096, 0);
    let view = BootImage::view_as(&out, &PACKAGE).unwrap();
    assert_eq!(view.count(), 5);
    let names: Vec<&str> = (0..5).map(|n| view.file(n).unwrap().name).collect();
    assert_eq!(names, ["meta", "rootfs", "manifest", "3", "4"]);
    assert_eq!(view.file(0).unwrap().data, b"name settings\n");
    assert_eq!(view.file(2).unwrap().data.len(), 0);
    // The whole container passes the strict reader too.
    BootImage::parse_as(&out[..out.len() - 4096], &PACKAGE).unwrap();
    let table = view.file(1).unwrap().data;
    let rootfs = Rootfs::open(table, view.count()).unwrap();
    assert_eq!(rootfs.len(), 5);
    let mut seen = Vec::new();
    for n in 0..rootfs.len() {
        let e = rootfs.entry(n as u32);
        seen.push((e.path.to_string(), e.mode, e.uid, e.gid));
    }
    assert_eq!(
        seen,
        [
            ("/etc".to_string(), 0o040_755, 0, 0),
            ("/etc/pkg".to_string(), 0o040_755, 0, 0),
            ("/etc/pkg/keys".to_string(), 0o040_755, 0, 0),
            ("/etc/pkg/keys/games.pub".to_string(), 0o100_644, 0, 0),
            ("/etc/pkg/repositories".to_string(), 0o100_644, 0, 0),
        ]
    );
    // The file service's checks of an entry hold for each, and the files hold the blob's bytes.
    for n in 0..rootfs.len() {
        rootfs.check_entry(n as u32, view.count()).unwrap();
    }
    let key = view.file(rootfs.entry(3).file).unwrap().data;
    assert!(key.starts_with(b"ed25519 "));
    let repos = view.file(rootfs.entry(4).file).unwrap().data;
    assert!(repos.starts_with(b"games https://"));
}

#[test]
fn the_container_of_the_largest_blob_fits_its_buffer() {
    let names: Vec<String> = (0..32).map(|i| format!("keys/{:0>59}.pub", i)).collect();
    let keys: Vec<String> = (0..32).map(|i| key_line(&format!("k{i}"))).collect();
    let files: Vec<(&str, &[u8])> = names
        .iter()
        .zip(&keys)
        .map(|(n, k)| (n.as_str(), k.as_bytes()))
        .collect();
    let bytes = blob::write(&files);
    let s = Settings::parse(&bytes).unwrap();
    let mut out = vec![0u8; CONTAINER_MAX];
    let len = container(&s, &mut out).unwrap();
    assert!(len <= CONTAINER_MAX);
    let view = BootImage::view_as(&out[..len], &PACKAGE).unwrap();
    let rootfs = Rootfs::open(view.file(1).unwrap().data, view.count()).unwrap();
    assert_eq!(rootfs.len(), 35);
    for n in 0..rootfs.len() {
        rootfs.check_entry(n as u32, view.count()).unwrap();
    }
    // A buffer that is too small is refused.
    assert!(container(&s, &mut out[..len - 1]).is_none());
}
