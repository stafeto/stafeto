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
    let text = pkgfmt::revoked::write(1, revoked).unwrap();
    let list = pkgfmt::revoked::Revoked::parse(&text).unwrap();
    let (covered, whole) = hashes(bytes);
    check(
        bytes,
        &covered,
        &whole,
        record,
        crate::SERIES,
        trust,
        Some(&list),
        false,
        &mut |_| {},
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
        None,
        false,
        &mut |_| {},
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
        None,
        false,
        &mut |_| {},
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

#[test]
fn a_long_list_of_revocations_is_applied_to_the_last_name_as_to_the_first() {
    let bytes = package(&Spec::default());
    let record = record_of(&bytes, "hello", "1.0");
    let roots = official();
    let trust = select(true, &roots, &[]);
    // 600 names, the key that signed after all the others, as a list of 16 KiB holds.
    let mut entries: Vec<Revocation> = (0..599)
        .map(|i| Revocation {
            name: name(&format!("a-key-{i:04}")),
            since: 0,
        })
        .collect();
    assert_eq!(run(&bytes, &record, &trust, &entries), Ok(()));
    entries.push(Revocation {
        name: name("test-release"),
        since: 0,
    });
    assert_eq!(run(&bytes, &record, &trust, &entries), Err(Fault::Revoked));
}

#[test]
fn the_packages_of_the_boot_image_are_read_and_a_disk_package_of_the_same_name_is_left_out() {
    use crate::packages::{in_image, read_image};
    let hello = package(&Spec::default());
    let other = package(&Spec {
        name: "other",
        ..Spec::default()
    });
    let ugly = bootimg::write::image_as(
        &pkgfmt::PACKAGE,
        &[("meta", b"junk"), ("rootfs", b"x"), ("manifest", b"")],
    )
    .unwrap();
    let image = bootimg::write::image(&[
        ("init", b"program"),
        ("hello.stpkg", &hello),
        ("not.stpkg", b"not a package at all"),
        ("ugly.stpkg", &ugly),
        ("other.stpkg", &other),
        ("data.bin", b"no suffix"),
    ])
    .unwrap();
    let mut said = Vec::new();
    let mut out = [None, None, None];
    let n = read_image(&image, &mut out, |file, why| {
        said.push(format!("{file}: {why}"))
    });
    assert_eq!(n, 2);
    assert_eq!(
        said,
        ["not.stpkg: not a package", "ugly.stpkg: meta is not good"]
    );
    let e = out[0].as_ref().unwrap();
    assert!(e.image && e.name() == b"hello" && e.record.version_bytes() == b"1.0");
    assert!(e.meta().starts_with(b"name hello\n") && e.layer == 0);
    assert_eq!(e.flags(), proto_pkg::ENTRY_IMAGE);
    assert_eq!(out[1].as_ref().unwrap().name(), b"other");
    assert!(out[2].is_none());
    assert!(in_image(&out, b"hello") && !in_image(&out, b"world"));
    // More packages than places: the rest are reported, not dropped silently.
    let mut few = [None];
    let mut said = Vec::new();
    assert_eq!(
        read_image(&image, &mut few, |f, w| said.push(format!("{f}: {w}"))),
        1
    );
    assert!(said.contains(&"other.stpkg: too many packages".to_string()));
    assert_eq!(read_image(b"not an image", &mut few, |_, _| {}), 0);
}

/// A table with the entries' records in the places 0, 1, ... and the official repository.
fn table_of(entries: &[Option<Entry>]) -> Table {
    let mut t = Table::zeroed();
    t.init(4);
    t.set_repo(0, b"stafeto", 0);
    for (i, e) in entries.iter().flatten().enumerate() {
        let mut r = e.record;
        r.first = 10 + 100 * i as u64;
        t.set_record(i, &r);
    }
    t
}

#[test]
fn a_removal_names_what_goes_and_refuses_the_image_the_unknown_and_the_needed() {
    use crate::plans::{REMOVE_MAX, remove};
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
    ];
    let table = table_of(&set);
    let mut image = [const { None }; 4];
    image[0] = entry(&Spec {
        name: "base",
        ..Spec::default()
    })
    .map(|mut e| {
        e.image = true;
        e
    });
    let mut out = Table::zeroed();
    let mut slots = [0; REMOVE_MAX];
    let mut go =
        |names: &[&[u8]], out: &mut Table| remove(&table, out, &set, &image, names, &mut slots);
    assert_eq!(go(&[b"base"], &mut out), Err(proto_pkg::IN_IMAGE));
    assert_eq!(go(&[b"nobody"], &mut out), Err(proto_pkg::NOT_FOUND));
    assert_eq!(
        go(&[b"plain", b"nobody"], &mut out),
        Err(proto_pkg::NOT_FOUND)
    );
    assert_eq!(go(&[b"freedoom"], &mut out), Err(proto_pkg::NEEDED_BY));
    // Both at once is no breakage; a name twice counts once.
    assert_eq!(
        go(&[b"freedoom", b"doomgeneric", b"freedoom"], &mut out),
        Ok(2)
    );
    assert_eq!(out.generation(), 5);
    assert_eq!(out.record(0), Record::EMPTY);
    assert_eq!(out.record(1), Record::EMPTY);
    assert_eq!(out.record(2), table.record(2));
    assert_eq!(table.generation(), 4);
    assert_eq!(out.check(5, 131_072, 2), Ok(()));
}

#[test]
fn a_serial_never_goes_back_and_a_new_repository_takes_a_free_place() {
    use crate::plans::serial;
    let mut t = Table::zeroed();
    t.init(4);
    t.set_repo(0, b"stafeto", 0);
    let mut out = Table::zeroed();
    // Zero for an unknown repository is what is held: nothing is written.
    assert_eq!(serial(&t, &mut out, b"games", 0), Ok(false));
    assert_eq!(serial(&t, &mut out, b"games", 3), Ok(true));
    assert_eq!(out.generation(), 5);
    assert_eq!(
        out.repo(out.find_repo(b"games").unwrap()),
        Some((&b"games"[..], 3))
    );
    assert_eq!(serial(&out, &mut Table::zeroed(), b"games", 3), Ok(false));
    assert_eq!(
        serial(&out, &mut Table::zeroed(), b"games", 2),
        Err(proto_pkg::ROLLBACK)
    );
    assert_eq!(serial(&out, &mut Table::zeroed(), b"stafeto", 1), Ok(true));
    for bad in [&b""[..], b"Games", b"a b", &[b'a'; 32]] {
        assert_eq!(
            serial(&t, &mut out, bad, 1),
            Err(proto_pkg::INVALID),
            "{bad:?}"
        );
    }
    // Sixteen repositories: the stafeto and fifteen others.
    for i in 1..16 {
        t.set_repo(i, format!("r{i}").as_bytes(), 1);
    }
    assert_eq!(serial(&t, &mut out, b"more", 1), Err(proto_pkg::NO_SPACE));
    assert_eq!(serial(&t, &mut out, b"r3", 2), Ok(true));
}

#[test]
fn the_flag_world_changes_that_record_alone_and_refuses_the_image_and_the_unknown() {
    use crate::plans::world;
    use crate::store::{DEPENDENCY, WORLD};
    let set = [
        entry(&Spec {
            name: "lib",
            ..Spec::default()
        }),
        entry(&Spec {
            name: "app",
            depends: "lib",
            ..Spec::default()
        }),
    ];
    let mut table = table_of(&set);
    let mut r = table.record(0);
    r.flags = DEPENDENCY;
    table.set_record(0, &r);
    let mut image = [const { None }; 4];
    image[0] = entry(&Spec {
        name: "base",
        ..Spec::default()
    })
    .map(|mut e| {
        e.image = true;
        e
    });
    let mut out = Table::zeroed();
    assert_eq!(
        world(&table, &mut out, &image, b"base", true),
        Err(proto_pkg::IN_IMAGE)
    );
    assert_eq!(
        world(&table, &mut out, &image, b"none", true),
        Err(proto_pkg::NOT_FOUND)
    );
    // The flag it has already: nothing is written.
    assert_eq!(world(&table, &mut out, &image, b"lib", false), Ok(None));
    assert_eq!(world(&table, &mut out, &image, b"app", true), Ok(None));
    assert_eq!(world(&table, &mut out, &image, b"lib", true), Ok(Some(0)));
    assert_eq!(out.generation(), table.generation() + 1);
    assert_eq!(out.record(0).flags, WORLD);
    assert_eq!(out.record(1), table.record(1));
    let back = table_of(&set);
    let mut again = Table::zeroed();
    assert_eq!(world(&out, &mut again, &image, b"lib", false), Ok(Some(0)));
    assert_eq!(again.record(0).flags, DEPENDENCY);
    assert_eq!(back.record(0).flags, WORLD);
}

#[test]
fn the_list_of_revocations_never_goes_back_and_marks_the_packages_it_names() {
    use crate::plans::{revoked, settings};
    use crate::store::{Extent, REVOKED, REVOKED_SLOT, SETTINGS_SLOT};
    let set = [
        entry(&Spec {
            name: "a",
            ..Spec::default()
        }),
        entry(&Spec {
            name: "b",
            ..Spec::default()
        }),
    ];
    let t = table_of(&set);
    let list = Extent {
        first: 900,
        blocks: 2,
    };
    let mut flags = [false; 64];
    flags[1] = true;
    let mut out = Table::zeroed();
    assert_eq!(
        revoked(&t, &mut out, list, 5000, [7; 32], 2, &flags),
        Ok(())
    );
    assert_eq!(out.record(1).flags, WORLD | REVOKED);
    assert_eq!(out.record(0).flags, WORLD);
    let held = out.record(REVOKED_SLOT);
    assert_eq!((held.number, held.length, held.blocks), (2, 5000, 2));
    assert_eq!(out.check(5, 131_072, 2), Ok(()));
    // An older list, the same one again, and a list that frees a package.
    let mut again = Table::zeroed();
    assert_eq!(
        revoked(&out, &mut again, list, 5000, [7; 32], 1, &flags),
        Err(proto_pkg::ROLLBACK)
    );
    assert_eq!(
        revoked(&out, &mut again, list, 5000, [7; 32], 2, &[false; 64]),
        Ok(())
    );
    assert_eq!(again.record(1).flags, WORLD);
    // The settings record.
    settings(&t, &mut out, list, 70, [8; 32]);
    let s = out.record(SETTINGS_SLOT);
    assert_eq!(
        (s.first, s.blocks, s.length, s.sha256),
        (900, 1, 70, [8; 32])
    );
    assert_eq!(out.check(5, 131_072, 2), Ok(()));
}

#[test]
fn the_manifest_is_checked_for_an_installation_and_not_for_a_start_from_the_disk() {
    let spec = Spec {
        padding: 10_000,
        ..Spec::default()
    };
    let good = package(&spec);
    // A byte of the program changed before the signing: the signature is good, the
    // manifest names another file.
    let bad = package_with(&spec, |covered| {
        let at = covered
            .windows(4)
            .position(|w| w == b"\x7fELF")
            .expect("the program");
        covered[at + 30] ^= 1;
    });
    let roots = official();
    let trust = select(true, &roots, &[]);
    for (bytes, manifest, wanted) in [
        (&good, true, Ok(())),
        (&bad, false, Ok(())),
        (&bad, true, Err(Fault::BadManifest)),
    ] {
        let record = record_of(bytes, "hello", "1.0");
        let (covered, whole) = hashes(bytes);
        let mut portions = 0;
        let got = check(
            bytes,
            &covered,
            &whole,
            &record,
            crate::SERIES,
            &trust,
            None,
            manifest,
            &mut |phase| portions += usize::from(phase == crate::verify::Phase::Portion),
        )
        .map(drop);
        assert_eq!(got, wanted, "{manifest}");
        assert_eq!(portions > 0, manifest);
    }
    assert_eq!(Fault::BadManifest.code(), proto_pkg::BAD_MANIFEST);
}

#[test]
fn a_list_names_the_packages_its_keys_signed_at_or_after_the_time() {
    use crate::verify::revoked_by;
    let bytes = package(&Spec::default());
    let record = record_of(&bytes, "hello", "1.0");
    let roots = official();
    let (covered, whole) = hashes(&bytes);
    let checked = check(
        &bytes,
        &covered,
        &whole,
        &record,
        crate::SERIES,
        &select(true, &roots, &[]),
        None,
        false,
        &mut |_| {},
    )
    .unwrap();
    let signed = 1_800_000_000;
    for (since, wanted) in [(0, true), (signed, true), (signed + 1, false)] {
        let text = pkgfmt::revoked::write(
            1,
            &[Revocation {
                name: name("test-release"),
                since,
            }],
        )
        .unwrap();
        let list = pkgfmt::revoked::Revoked::parse(&text).unwrap();
        assert_eq!(revoked_by(checked.trailer, &list), wanted, "{since}");
    }
    let other = pkgfmt::revoked::write(
        1,
        &[Revocation {
            name: name("other-key"),
            since: 0,
        }],
    )
    .unwrap();
    let list = pkgfmt::revoked::Revoked::parse(&other).unwrap();
    assert!(!revoked_by(checked.trailer, &list));
    assert!(!revoked_by(&[0; 10], &list));
}
