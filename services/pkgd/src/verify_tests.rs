// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use crate::commit::{self, Start};
use crate::host::{Contents, Item, write_store};
use crate::packages::{Entry, find, needed_by};
use crate::store::{BLOCK, Table};
use crate::store::{DEPENDENCY, Record, WORLD, to_field};
use crate::testkit::*;
use crate::verify::{Fault, check, select};
use pkgfmt::sha::{Stream, sha256};
use pkgfmt::{Revocation, Trust};

/// The record the store would hold of `bytes`.
fn record_of(bytes: &[u8], name: &str, version: &str) -> Record {
    Record {
        kind: crate::store::PACKAGE,
        flags: WORLD,
        repo: 0,
        first: 10,
        blocks: (bytes.len() / BLOCK) as u32,
        length: bytes.len() as u64,
        number: 0,
        installed: 0,
        sha256: sha256(bytes),
        name: to_field(name.as_bytes()).unwrap(),
        version: to_field(version.as_bytes()).unwrap(),
    }
}

/// The two hashes the reading gives: of the covered part and of the file.
fn hashes(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut s = Stream::new();
    s.update(&bytes[..bytes.len() - BLOCK]);
    let covered = s.clone().finish();
    s.update(&bytes[bytes.len() - BLOCK..]);
    (covered, s.finish())
}

fn run(bytes: &[u8], record: &Record, trust: &Trust, revoked: &[Revocation]) -> Result<(), Fault> {
    let (covered, whole) = hashes(bytes);
    check(
        bytes,
        &covered,
        &whole,
        record,
        crate::SERIES,
        trust,
        revoked,
    )
    .map(drop)
}

fn official() -> [pkgfmt::Key; 1] {
    [root()]
}

#[test]
fn a_package_of_the_official_repository_passes_and_keeps_its_meta() {
    let bytes = package(&Spec::default());
    let record = record_of(&bytes, "hello", "1.0");
    let roots = official();
    let trust = select(true, &roots, &[]);
    let (covered, whole) = hashes(&bytes);
    let checked = check(
        &bytes,
        &covered,
        &whole,
        &record,
        crate::SERIES,
        &trust,
        &[],
    )
    .unwrap();
    assert!(checked.meta.starts_with(b"name hello\n"));
    assert_eq!(checked.trailer.len(), pkgfmt::sig::BLOCK_SIZE);
    assert_eq!(&checked.trailer[..8], b"STAFSIG1");
}

#[test]
fn each_fault_has_its_code_and_its_words() {
    let roots = official();
    let trust = select(true, &roots, &[]);
    let good = package(&Spec::default());
    let record = record_of(&good, "hello", "1.0");
    // The file is not the one the table names.
    let mut wrong = record;
    wrong.sha256[0] ^= 1;
    assert_eq!(run(&good, &wrong, &trust, &[]), Err(Fault::BadHash));
    // A byte of the content changed after the signing; the table was made of the changed file.
    let mut changed = good.clone();
    let at = changed.windows(4).position(|w| w == b"\x7fELF").unwrap();
    changed[at + 5] ^= 1;
    let r = record_of(&changed, "hello", "1.0");
    assert_eq!(run(&changed, &r, &trust, &[]), Err(Fault::Covered));
    assert_eq!(Fault::Covered.code(), proto_pkg::BAD_HASH);
    assert_eq!(Fault::Covered.words(), "bad signature");
    // A byte of the signature changed, the hash of the file made again.
    let mut signed = good.clone();
    let n = signed.len();
    signed[n - BLOCK + 140] ^= 1;
    let r = record_of(&signed, "hello", "1.0");
    assert_eq!(run(&signed, &r, &trust, &[]), Err(Fault::BadSignature));
    // Not a package at all, and a name or version that is not the record's.
    let junk = vec![0u8; 3 * BLOCK];
    let r = record_of(&junk, "hello", "1.0");
    assert_eq!(run(&junk, &r, &trust, &[]), Err(Fault::BadPackage));
    let r = record_of(&good, "other", "1.0");
    assert_eq!(run(&good, &r, &trust, &[]), Err(Fault::BadPackage));
    let r = record_of(&good, "hello", "2.0");
    assert_eq!(run(&good, &r, &trust, &[]), Err(Fault::BadPackage));
    // The series of another system.
    let old = package(&Spec {
        series: "0.1",
        ..Spec::default()
    });
    let r = record_of(&old, "hello", "1.0");
    assert_eq!(run(&old, &r, &trust, &[]), Err(Fault::WrongSeries));
    // A key no root vouched for.
    let stranger = package(&Spec {
        seed: OTHER_SEED,
        key: "stranger",
        certified: false,
        ..Spec::default()
    });
    let r = record_of(&stranger, "hello", "1.0");
    assert_eq!(run(&stranger, &r, &trust, &[]), Err(Fault::UntrustedKey));
    // A key the list names, from before the signing.
    let revoked = [Revocation {
        name: name("test-release"),
        since: 0,
    }];
    let r = record_of(&good, "hello", "1.0");
    assert_eq!(run(&good, &r, &trust, &revoked), Err(Fault::Revoked));
    let later = [Revocation {
        name: name("test-release"),
        since: 1_800_000_001,
    }];
    assert_eq!(run(&good, &r, &trust, &later), Ok(()));
    for (fault, code) in [
        (Fault::BadSignature, 1202),
        (Fault::UntrustedKey, 1205),
        (Fault::Revoked, 1214),
        (Fault::WrongSeries, 1213),
        (Fault::BadPackage, 1215),
        (Fault::BadHash, 1203),
    ] {
        assert_eq!(fault.code(), code);
    }
}

#[test]
fn the_trust_of_an_own_repository_is_its_key_alone() {
    // A package of the owner's repository `games`, signed by a key the owner
    // gave directly.
    let own = package(&Spec {
        seed: OTHER_SEED,
        key: "games-key",
        certified: false,
        ..Spec::default()
    });
    let key = pkgfmt::Key {
        name: name("games-key"),
        public: pkgfmt::sig::public_key(&OTHER_SEED),
    };
    let roots = official();
    let r = record_of(&own, "hello", "1.0");
    assert_eq!(run(&own, &r, &select(false, &roots, &[key]), &[]), Ok(()));
    // The roots are not the trust of such a repository: a package that a root
    // vouches for is refused there, and the owner's key does not serve the
    // official one.
    let vouched = package(&Spec::default());
    let r = record_of(&vouched, "hello", "1.0");
    assert_eq!(
        run(&vouched, &r, &select(false, &roots, &[key]), &[]),
        Err(Fault::UntrustedKey)
    );
    assert_eq!(
        run(
            &own,
            &record_of(&own, "hello", "1.0"),
            &select(true, &roots, &[key]),
            &[]
        ),
        Err(Fault::UntrustedKey)
    );
}

fn entry(spec: &Spec<'_>) -> Option<Entry> {
    let bytes = package(spec);
    let record = record_of(&bytes, spec.name, spec.version);
    let roots = official();
    let (covered, whole) = hashes(&bytes);
    let checked = check(
        &bytes,
        &covered,
        &whole,
        &record,
        crate::SERIES,
        &select(true, &roots, &[]),
        &[],
    )
    .unwrap();
    let mut e = Entry {
        record,
        image: false,
        layer: 0,
        meta_len: 0,
        meta: [0; 4096],
        trailer: [0; 456],
    };
    assert!(e.keep(checked.meta, checked.trailer));
    Some(e)
}

#[test]
fn removing_a_package_another_one_needs_is_refused_by_name() {
    let set = [
        entry(&Spec {
            name: "freedoom",
            provides: "wad",
            ..Spec::default()
        }),
        entry(&Spec {
            name: "doomgeneric",
            depends: "wad",
            ..Spec::default()
        }),
        entry(&Spec {
            name: "plain",
            ..Spec::default()
        }),
        None,
    ];
    assert_eq!(needed_by(&set, &[b"freedoom"]), Some(&b"doomgeneric"[..]));
    assert_eq!(needed_by(&set, &[b"plain"]), None);
    assert_eq!(needed_by(&set, &[b"freedoom", b"doomgeneric"]), None);
    assert_eq!(needed_by(&set, &[]), None);
    let direct = [
        entry(&Spec {
            name: "a",
            ..Spec::default()
        }),
        entry(&Spec {
            name: "b",
            depends: "a",
            ..Spec::default()
        }),
    ];
    assert_eq!(needed_by(&direct, &[b"a"]), Some(&b"b"[..]));
    assert_eq!(find(&direct, b"b").map(|(i, _)| i), Some(1));
    assert!(find(&direct, b"c").is_none());
    // A dependency nothing gives is not the removal's doing.
    let open = [entry(&Spec {
        name: "x",
        depends: "missing",
        ..Spec::default()
    })];
    assert_eq!(needed_by(&open, &[b"y"]), None);
    let flags = open[0].as_ref().unwrap();
    assert_eq!(flags.flags(), proto_pkg::ENTRY_WORLD);
    let mut dep = *flags;
    dep.record.flags = WORLD | DEPENDENCY;
    assert_eq!(
        dep.flags(),
        proto_pkg::ENTRY_WORLD | proto_pkg::ENTRY_DEPENDENCY
    );
    dep.image = true;
    assert_eq!(dep.flags() & proto_pkg::ENTRY_IMAGE, proto_pkg::ENTRY_IMAGE);
}

#[test]
fn the_writer_of_the_host_makes_a_store_the_service_starts_from() {
    let hello = package(&Spec::default());
    let wide = package(&Spec {
        name: "wide",
        padding: 5 * BLOCK,
        ..Spec::default()
    });
    let contents = Contents {
        packages: vec![
            Item {
                bytes: hello.clone(),
                repository: "stafeto".into(),
                flags: WORLD,
                installed: 5,
            },
            Item {
                bytes: wide.clone(),
                repository: "games".into(),
                flags: 0,
                installed: 6,
            },
        ],
        settings: Some(proto_pkg::blob::write(&[(
            "repositories",
            b"games https://example.org/g\n",
        )])),
        revoked: Some((vec![9; 5000], 2)),
        repositories: vec![("games".into(), 4)],
    };
    let mut disk = ModelDisk::new(131_072);
    let layout = write_store(&mut disk, &contents).unwrap();
    assert_eq!(layout.generation, 2);
    let mut table = Table::zeroed();
    let Start::Store(opened) = commit::open(&mut disk, &mut table).unwrap() else {
        panic!("store");
    };
    assert_eq!(opened.superblock.generation, 2);
    assert_eq!(table.repo(1), Some((&b"games"[..], 4)));
    assert_eq!(table.record(0).name_bytes(), b"hello");
    assert_eq!(table.record(1).repo, 1);
    assert_eq!(table.record(crate::store::REVOKED_SLOT).number, 2);
    assert_eq!(commit::free_of(&table, &opened), layout.free);
    // The bytes of the first package are where its record says.
    let r = table.record(0);
    let mut block = [0u8; BLOCK];
    disk.read_block(r.first, &mut block);
    assert_eq!(&block[..], &hello[..BLOCK]);
    assert_eq!(disk.pending(), 0);
}
