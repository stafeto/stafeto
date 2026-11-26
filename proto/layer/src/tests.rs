// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use proto_wire::long;

fn bytes(write: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
    let mut w = Writer::new();
    write(&mut w).unwrap();
    w.as_bytes().to_vec()
}

fn reply(write: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
    bytes(|w| {
        w.u32(0)?;
        write(w)
    })
}

/// Every cut of `wire` after `from` bytes and a byte too many are refused by `read`.
fn refuses_cuts(wire: &[u8], from: usize, is_err: impl Fn(&[u8]) -> bool) {
    for cut in from..wire.len() {
        assert!(is_err(&wire[..cut]), "cut at {cut}");
    }
    let mut extra = wire.to_vec();
    extra.push(0);
    assert!(is_err(&extra), "a byte too many");
}

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn method_numbers_are_fixed() {
    assert_eq!(
        Method::ALL.map(Method::number),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    );
    for m in Method::ALL {
        assert_eq!(Method::from_number(m.number()), Some(m));
        assert_eq!(m.header(), Header::new(m.number(), VERSION));
    }
    assert_eq!(Method::from_number(0), None);
    assert_eq!(Method::from_number(14), None);
    assert_eq!(VERSION, 1);
}

#[test]
fn codes_clear_of_the_wire_and_of_the_services_below() {
    for (i, a) in CODES.iter().enumerate() {
        assert!((1301..=1318).contains(a), "{a} is outside the series");
        assert!(!CODES[i + 1..].contains(a));
    }
    assert_eq!(CODES.len(), 18);
    for other in proto_blk_codes()
        .into_iter()
        .chain(proto_pkg::CODES)
        .chain([256, 257, 258])
    {
        assert!(!CODES.contains(&other), "{other}");
    }
    // The codes of the data service are the constants 1201 to 1224.
    for data in [
        proto_data::NO_ENTRY,
        proto_data::EXISTS,
        proto_data::IS_DIRECTORY,
    ] {
        assert!(!CODES.contains(&data));
    }
    assert_eq!(code(INVALID), Status::Unknown(1314));
    assert_eq!(Status::from_code(NOT_ALLOWED), Status::Unknown(1301));
}

fn proto_blk_codes() -> Vec<u32> {
    (1101..=1108).collect()
}

#[test]
fn the_limits_agree_with_the_neighbours() {
    assert_eq!(PATH_MAX, proto_fs::MAX_PATH);
    assert_eq!(NOTE_MAX, proto_pkg::NAME_MAX);
}

#[test]
fn text_and_path_limits() {
    let long = [b'a'; 64];
    let mut w = Writer::new();
    assert_eq!(put_text(&mut w, &long, NOTE_MAX), Err(Status::BadSize));
    assert!(put_text(&mut w, &long[..63], NOTE_MAX).is_ok());
    let mut wire = vec![64u8];
    wire.extend_from_slice(&long);
    assert_eq!(
        get_text(&mut Reader::new(&wire), NOTE_MAX),
        Err(Status::BadSize)
    );
    assert_eq!(
        get_text(&mut Reader::new(&[5, 1, 2]), NOTE_MAX),
        Err(Status::BadSize)
    );
    let mut w = Writer::new();
    assert_eq!(put_path(&mut w, b""), Err(code(INVALID)));
    assert_eq!(put_path(&mut w, b"/a\0b"), Err(code(INVALID)));
    assert_eq!(put_path(&mut w, &[b'a'; 512]), Err(code(INVALID)));
    assert!(put_path(&mut w, &[b'a'; 511]).is_ok());
    // Read side: a length of 512 and one of 0 are refused, a cut path is BAD_SIZE.
    let mut wire = 512u16.to_le_bytes().to_vec();
    wire.extend_from_slice(&[b'a'; 512]);
    assert_eq!(get_path(&mut Reader::new(&wire)), Err(code(INVALID)));
    assert_eq!(get_path(&mut Reader::new(&[0, 0])), Err(code(INVALID)));
    assert_eq!(
        get_path(&mut Reader::new(&[3, 0, b'a'])),
        Err(Status::BadSize)
    );
}

#[test]
fn a_selector_round_trips_in_every_form() {
    let forms = [
        (Selector::Live, 4),
        (Selector::Number(0), 8),
        (Selector::Number(99), 8),
        (Selector::Chain(id(7)), 36),
        (Selector::All, 4),
    ];
    for (selector, len) in forms {
        let wire = bytes(|w| selector.write(w, 15));
        assert_eq!(wire.len(), len);
        let mut r = Reader::new(&wire);
        assert_eq!(Selector::read(&mut r, 15), Ok(selector));
        assert_eq!(r.finish(), Ok(()));
        for cut in 0..wire.len() {
            assert!(Selector::read(&mut Reader::new(&wire[..cut]), 15).is_err());
        }
    }
}

#[test]
fn a_selector_form_a_method_does_not_allow_is_refused() {
    let cases = [
        (Selector::Live, ALLOW_STACK),
        (Selector::All, ALLOW_STACK),
        (Selector::Number(1), ALLOW_LIVE | ALLOW_CHAIN),
        (Selector::Chain(id(1)), ALLOW_NUMBER),
    ];
    for (selector, allow) in cases {
        assert_eq!(
            selector.write(&mut Writer::new(), allow),
            Err(code(INVALID))
        );
        let wire = bytes(|w| selector.write(w, 15));
        assert_eq!(
            Selector::read(&mut Reader::new(&wire), allow),
            Err(code(INVALID))
        );
    }
    // A number over 99 and an unknown tag.
    assert_eq!(
        Selector::Number(100).write(&mut Writer::new(), 15),
        Err(code(INVALID))
    );
    for wire in [[1u32, 100], [1, u32::MAX], [4, 0], [u32::MAX, 0]] {
        let b: Vec<u8> = wire.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(Selector::read(&mut Reader::new(&b), 15), Err(code(INVALID)));
    }
}

fn entry<'a>(kind: u32, number: u32, flags: u32, note: &'a [u8]) -> Entry<'a> {
    let sealed = flags & ENTRY_SEALED != 0;
    Entry {
        number,
        kind,
        flags,
        root: if sealed { id(1) } else { [0; 32] },
        chain: if sealed { id(2) } else { [0; 32] },
        bytes: 1 << 33,
        time: 1_795_000_000,
        note,
    }
}

#[test]
fn a_list_reply_round_trips() {
    let entries = [
        entry(KIND_PACKAGES, NO_NUMBER, ENTRY_SEALED, b"busybox"),
        entry(KIND_FROZEN, 1, ENTRY_SEALED, b"before the upgrade"),
        entry(KIND_FROZEN, 2, 0, b""),
        entry(
            KIND_FROZEN,
            3,
            ENTRY_SEALED | ENTRY_DEFERRED | ENTRY_DAMAGED,
            b"x",
        ),
        entry(KIND_LIVE, 4, 0, &[b'n'; 63]),
    ];
    let wire = reply(|w| {
        write_list_head(5, 9, w)?;
        for e in &entries {
            e.write(w)?;
        }
        Ok(())
    });
    let mut out = [None; LIST_MAX as usize];
    assert_eq!(read_list(&wire, &mut out), Ok((5, 9)));
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(out[i], Some(*e));
    }
    assert_eq!(out[5], None);
    refuses_cuts(&wire, 0, |b| {
        read_list(b, &mut [None; LIST_MAX as usize]).is_err()
    });
    let seven = reply(|w| write_list_head(7, 0, w));
    assert_eq!(
        read_list(&seven, &mut [None; LIST_MAX as usize]),
        Err(Status::BadSize)
    );
    assert_eq!(
        read_list(&1303u32.to_le_bytes(), &mut [None; LIST_MAX as usize]),
        Err(Status::Unknown(NOT_FOUND))
    );
}

#[test]
fn six_longest_entries_fit_one_message() {
    let e = entry(KIND_FROZEN, 99, ENTRY_SEALED, &[b'n'; 63]);
    let wire = reply(|w| {
        write_list_head(LIST_MAX, 0, w)?;
        for _ in 0..LIST_MAX {
            e.write(w)?;
        }
        Ok(())
    });
    assert!(wire.len() <= abi::MESSAGE_MAX, "{}", wire.len());
    assert_eq!(
        read_list(&wire, &mut [None; LIST_MAX as usize]).map(|r| r.0),
        Ok(6)
    );
}

#[test]
fn an_entry_that_does_not_make_sense_is_refused_both_ways() {
    let bad = [
        entry(0, 1, 0, b""),
        entry(4, 1, 0, b""),
        entry(KIND_FROZEN, 100, 0, b""),
        entry(KIND_PACKAGES, 1, ENTRY_SEALED, b""),
        entry(KIND_FROZEN, NO_NUMBER, 0, b""),
        entry(KIND_FROZEN, 1, 8, b""),
        entry(KIND_LIVE, 1, ENTRY_SEALED, b""),
        Entry {
            root: id(1),
            ..entry(KIND_FROZEN, 1, 0, b"")
        },
        entry(KIND_FROZEN, 1, 0, &[b'n'; 64]),
    ];
    for e in bad {
        assert!(e.write(&mut Writer::new()).is_err(), "{e:?}");
    }
    // The same on the read side: take a good entry and break its fields in the bytes.
    let good = entry(KIND_FROZEN, 1, ENTRY_SEALED, b"a");
    let wire = reply(|w| {
        write_list_head(1, 0, w)?;
        good.write(w)
    });
    for (offset, value) in [(12, 100u8), (16, 9), (20, 8), (20, 0)] {
        let mut broken = wire.clone();
        broken[offset] = value;
        assert!(
            read_list(&broken, &mut [None; LIST_MAX as usize]).is_err(),
            "{offset}"
        );
    }
}

#[test]
fn diff_and_its_changes_round_trip() {
    for layer in [Selector::Live, Selector::Number(3), Selector::Chain(id(5))] {
        let wire = bytes(|w| write_diff(&layer, 40, w));
        assert_eq!(&wire[..8], &Method::Diff.header().bytes());
        assert_eq!(read_diff(Reader::new(&wire[8..])), Ok((layer, 40)));
        refuses_cuts(&wire[8..], 0, |b| read_diff(Reader::new(b)).is_err());
    }
    assert_eq!(
        write_diff(&Selector::All, 0, &mut Writer::new()),
        Err(code(INVALID))
    );
    let changes = [
        Change {
            kind: CHANGE_ADDED,
            path: b"/etc/new",
        },
        Change {
            kind: CHANGE_CHANGED,
            path: b"/etc/passwd",
        },
        Change {
            kind: CHANGE_DELETED,
            path: &[b'/'; 511],
        },
    ];
    let wire = reply(|w| {
        write_list_head(3, 77, w)?;
        for c in &changes {
            c.write(w)?;
        }
        Ok(())
    });
    let mut seen = Vec::new();
    assert_eq!(read_changes(&wire, |c| seen.push(c)), Ok((3, 77)));
    assert_eq!(seen, changes);
    refuses_cuts(&wire, 0, |b| read_changes(b, |_| {}).is_err());
}

#[test]
fn a_change_with_a_bad_kind_or_path_is_refused() {
    for (kind, path) in [
        (0, &b"/a"[..]),
        (4, b"/a"),
        (CHANGE_ADDED, b"a"),
        (CHANGE_ADDED, b""),
        (CHANGE_ADDED, b"/a\0"),
    ] {
        assert!(Change { kind, path }.write(&mut Writer::new()).is_err());
    }
    for (kind, path) in [(9u32, &b"/a"[..]), (1, b"a")] {
        let mut wire = 0u32.to_le_bytes().to_vec();
        wire.extend_from_slice(&1u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&kind.to_le_bytes());
        wire.extend_from_slice(&(path.len() as u16).to_le_bytes());
        wire.extend_from_slice(path);
        assert_eq!(read_changes(&wire, |_| {}), Err(code(INVALID)));
    }
    let many = reply(|w| write_list_head(DIFF_MAX + 1, 0, w));
    assert_eq!(read_changes(&many, |_| {}), Err(Status::BadSize));
}

#[test]
fn compose_round_trips_and_has_its_limits() {
    let layers = [
        Selector::Number(1),
        Selector::Chain(id(9)),
        Selector::Number(7),
    ];
    let wire = bytes(|w| write_compose(&layers, w));
    let mut out = [Selector::Live; LAYERS_MAX];
    assert_eq!(read_compose(Reader::new(&wire[8..]), &mut out), Ok(3));
    assert_eq!(&out[..3], &layers);
    refuses_cuts(&wire[8..], 0, |b| {
        { read_compose(Reader::new(b), &mut [Selector::Live; LAYERS_MAX]) }.is_err()
    });
    let none = bytes(|w| write_compose(&[], w));
    assert_eq!(
        read_compose(Reader::new(&none[8..]), &mut [Selector::Live; LAYERS_MAX]),
        Ok(0)
    );
    let full = [Selector::Number(1); LAYERS_MAX];
    assert!(write_compose(&full, &mut Writer::new()).is_ok());
    assert_eq!(
        write_compose(&[Selector::Number(1); 17], &mut Writer::new()),
        Err(Status::BadSize)
    );
    assert_eq!(
        write_compose(&[Selector::Live], &mut Writer::new()),
        Err(code(INVALID))
    );
    let seventeen = 17u32.to_le_bytes();
    assert_eq!(
        read_compose(Reader::new(&seventeen), &mut [Selector::Live; LAYERS_MAX]),
        Err(Status::BadSize)
    );
    // Sixteen chain ids are the longest body and still fit a message.
    let chains = [Selector::Chain(id(3)); LAYERS_MAX];
    assert!(bytes(|w| write_compose(&chains, w)).len() <= abi::MESSAGE_MAX);
}

#[test]
fn composed_round_trips() {
    let c = Composed {
        composition: 2,
        live: 5,
    };
    let wire = reply(|w| c.write(w));
    assert_eq!(Composed::read(&wire), Ok(c));
    refuses_cuts(&wire, 0, |b| Composed::read(b).is_err());
    for bad in [
        Composed {
            composition: 0,
            live: 5,
        },
        Composed {
            composition: 1,
            live: 100,
        },
    ] {
        assert_eq!(Composed::read(&reply(|w| bad.write(w))), Err(code(INVALID)));
    }
}

#[test]
fn freeze_round_trips_and_takes_only_its_flag() {
    for (flags, note) in [
        (0, &b""[..]),
        (FREEZE_FORCE, b"before the upgrade"),
        (0, &[b'n'; 63][..]),
    ] {
        let wire = bytes(|w| write_freeze(flags, note, w));
        assert_eq!(read_freeze(Reader::new(&wire[8..])), Ok((flags, note)));
        refuses_cuts(&wire[8..], 0, |b| read_freeze(Reader::new(b)).is_err());
    }
    assert_eq!(write_freeze(2, b"", &mut Writer::new()), Err(code(INVALID)));
    assert_eq!(
        write_freeze(0, &[b'n'; 64], &mut Writer::new()),
        Err(Status::BadSize)
    );
    let mut wire = 2u32.to_le_bytes().to_vec();
    wire.push(0);
    assert_eq!(read_freeze(Reader::new(&wire)), Err(code(INVALID)));
}

#[test]
fn select_squash_export_and_remove_round_trip() {
    for (method, layer, allow) in [
        (Method::Rollback, Selector::Number(2), ALLOW_STACK),
        (Method::Remove, Selector::Chain(id(4)), ALLOW_STACK),
        (Method::Check, Selector::All, ALLOW_STACK | ALLOW_ALL),
        (Method::Check, Selector::Number(0), ALLOW_STACK | ALLOW_ALL),
    ] {
        let wire = bytes(|w| write_select(method, &layer, allow, w));
        assert_eq!(&wire[..8], &method.header().bytes());
        assert_eq!(read_select(Reader::new(&wire[8..]), allow), Ok(layer));
        refuses_cuts(&wire[8..], 0, |b| {
            read_select(Reader::new(b), allow).is_err()
        });
    }
    assert_eq!(
        write_select(
            Method::Rollback,
            &Selector::Live,
            ALLOW_STACK,
            &mut Writer::new()
        ),
        Err(code(INVALID))
    );
    let wire = bytes(|w| write_squash(&Selector::Number(1), &Selector::Chain(id(8)), w));
    assert_eq!(
        read_squash(Reader::new(&wire[8..])),
        Ok((Selector::Number(1), Selector::Chain(id(8))))
    );
    refuses_cuts(&wire[8..], 0, |b| read_squash(Reader::new(b)).is_err());
    assert_eq!(
        write_squash(&Selector::All, &Selector::Number(1), &mut Writer::new()),
        Err(code(INVALID))
    );
    let wire = bytes(|w| write_export(&Selector::Number(3), b"/out/layer.tar", w));
    assert_eq!(
        read_export(Reader::new(&wire[8..])),
        Ok((Selector::Number(3), &b"/out/layer.tar"[..]))
    );
    refuses_cuts(&wire[8..], 0, |b| read_export(Reader::new(b)).is_err());
    assert_eq!(
        write_export(&Selector::Number(3), b"", &mut Writer::new()),
        Err(code(INVALID))
    );
}

#[test]
fn import_round_trips_with_and_without_a_digest() {
    for diff_id in [None, Some(id(6))] {
        let import = Import {
            diff_id,
            note: b"from a registry",
            path: b"/in/a.tar",
        };
        let wire = bytes(|w| import.write(w));
        assert_eq!(read_import(Reader::new(&wire[8..])), Ok(import));
        refuses_cuts(&wire[8..], 0, |b| read_import(Reader::new(b)).is_err());
    }
    // The digest flag with no digest, and a flag that is not one.
    let mut wire = IMPORT_DIGEST.to_le_bytes().to_vec();
    wire.extend_from_slice(&[0, 2, 0, b'/', b'a']);
    assert!(read_import(Reader::new(&wire)).is_err());
    let wire = 2u32.to_le_bytes();
    assert_eq!(read_import(Reader::new(&wire)), Err(code(INVALID)));
    let long_note = Import {
        diff_id: None,
        note: &[b'n'; 64],
        path: b"/a",
    };
    assert_eq!(long_note.write(&mut Writer::new()), Err(Status::BadSize));
}

#[test]
fn keys_words_and_empty_requests() {
    for method in [Method::Take, Method::Cancel] {
        let wire = bytes(|w| write_key(method, u64::MAX, w));
        assert_eq!(read_key(Reader::new(&wire[8..])), Ok(u64::MAX));
        assert_eq!(
            write_key(method, 0, &mut Writer::new()),
            Err(Status::BadSize)
        );
        refuses_cuts(&wire[8..], 0, |b| read_key(Reader::new(b)).is_err());
    }
    assert_eq!(read_key(Reader::new(&[0; 8])), Err(Status::BadSize));
    let wire = bytes(|w| write_word(Method::List, 5, w));
    assert_eq!(read_word(Reader::new(&wire[8..])), Ok(5));
    assert_eq!(read_word(Reader::new(&wire[8..11])), Err(Status::BadSize));
    assert_eq!(
        bytes(|w| write_empty(Method::Status, w)),
        Method::Status.header().bytes()
    );
}

#[test]
fn the_results_of_the_jobs_round_trip() {
    let sealed = Sealed {
        number: 4,
        root: id(1),
        chain: id(2),
    };
    let wire = bytes(|w| sealed.write(w));
    assert_eq!(Sealed::read(&wire), Ok(sealed));
    refuses_cuts(&wire, 0, |b| Sealed::read(b).is_err());
    assert_eq!(
        Sealed::read(&bytes(|w| {
            w.u32(100)?;
            w.bytes(&id(1))?;
            w.bytes(&id(2))
        })),
        Err(code(INVALID))
    );
    let frozen = Frozen { sealed, live: 5 };
    let wire = bytes(|w| frozen.write(w));
    assert_eq!(Frozen::read(&wire), Ok(frozen));
    refuses_cuts(&wire, 0, |b| Frozen::read(b).is_err());
    assert_eq!(
        Frozen { sealed, live: 100 }.write(&mut Writer::new()),
        Err(code(INVALID))
    );
    let imported = Imported {
        sealed,
        diff_id: id(3),
    };
    let wire = bytes(|w| imported.write(w));
    assert_eq!(Imported::read(&wire), Ok(imported));
    refuses_cuts(&wire, 0, |b| Imported::read(b).is_err());
    let exported = Exported {
        root: id(1),
        diff_id: id(9),
        size: 5 << 30,
    };
    let wire = bytes(|w| exported.write(w));
    assert_eq!(Exported::read(&wire), Ok(exported));
    refuses_cuts(&wire, 0, |b| Exported::read(b).is_err());
}

#[test]
fn a_check_result_carries_the_first_difference() {
    let clean = Checked {
        layers: 3,
        files: 1000,
        first_bad: None,
    };
    let wire = bytes(|w| clean.write(w));
    assert_eq!(Checked::read(&wire), Ok(clean));
    refuses_cuts(&wire, 0, |b| Checked::read(b).is_err());
    let bad = Checked {
        layers: 1,
        files: 12,
        first_bad: Some((2, &[b'/'; 511])),
    };
    let wire = bytes(|w| bad.write(w));
    assert_eq!(Checked::read(&wire), Ok(bad));
    refuses_cuts(&wire, 0, |b| Checked::read(b).is_err());
    assert!(wire.len() + 8 <= abi::MESSAGE_MAX);
    // The marker is 0 or 1, the layer a number, the path a path.
    let mut broken = wire.clone();
    broken[12] = 2;
    assert_eq!(Checked::read(&broken), Err(code(INVALID)));
    let no_path = Checked {
        layers: 1,
        files: 1,
        first_bad: Some((100, b"/a")),
    };
    assert_eq!(no_path.write(&mut Writer::new()), Err(code(INVALID)));
    let empty = Checked {
        layers: 1,
        files: 1,
        first_bad: Some((1, b"")),
    };
    assert_eq!(empty.write(&mut Writer::new()), Err(code(INVALID)));
}

#[test]
fn a_job_result_rides_the_long_reply() {
    let frozen = Frozen {
        sealed: Sealed {
            number: 1,
            root: id(1),
            chain: id(2),
        },
        live: 2,
    };
    let body = bytes(|w| frozen.write(w));
    let wire = bytes(|w| long::Reply::Ready(&body).write(w));
    assert!(wire.len() <= abi::MESSAGE_MAX);
    match long::Reply::read(&wire) {
        Ok(long::Reply::Ready(b)) => assert_eq!(Frozen::read(b), Ok(frozen)),
        other => panic!("{other:?}"),
    }
    let wait = bytes(|w| long::Reply::Wait(9).write(w));
    assert_eq!(long::Reply::read(&wait), Ok(long::Reply::Wait(9)));
}

#[test]
fn status_round_trips_and_refuses_unknown_values() {
    let stat = Stat {
        live: 3,
        frozen: 2,
        deferred: 1,
        flags: STATUS_UNSEALED | STATUS_DEGRADED,
        generation: 1 << 40,
        added: 5,
        changed: 6,
        deleted: 7,
        names: 8_000,
        bytes: 3 << 30,
        job: JOB_SEAL,
        done: 10,
        total: 20,
    };
    let wire = reply(|w| stat.write(w));
    assert_eq!(Stat::read(&wire), Ok(stat));
    refuses_cuts(&wire, 0, |b| Stat::read(b).is_err());
    for bad in [
        Stat { live: 100, ..stat },
        Stat { frozen: 17, ..stat },
        Stat {
            deferred: 17,
            ..stat
        },
        Stat { flags: 16, ..stat },
        Stat { job: 7, ..stat },
    ] {
        assert_eq!(bad.write(&mut Writer::new()), Err(code(INVALID)));
        let mut w = Writer::new();
        w.u32(0).unwrap();
        // Write the broken record without the check, to try the reader.
        for word in [bad.live, bad.frozen, bad.deferred, bad.flags] {
            w.u32(word).unwrap();
        }
        w.u64(bad.generation).unwrap();
        for word in [bad.added, bad.changed, bad.deleted, bad.names] {
            w.u32(word).unwrap();
        }
        w.u64(bad.bytes).unwrap();
        w.u32(bad.job).unwrap();
        w.u64(bad.done).unwrap();
        w.u64(bad.total).unwrap();
        assert_eq!(Stat::read(w.as_bytes()), Err(code(INVALID)));
    }
    assert_eq!(
        Stat::read(&1309u32.to_le_bytes()),
        Err(Status::Unknown(NO_STORE))
    );
}

#[test]
fn rollback_reply_round_trips() {
    let wire = reply(|w| write_live(6, w));
    assert_eq!(read_live(&wire), Ok(6));
    refuses_cuts(&wire, 0, |b| read_live(b).is_err());
    assert_eq!(write_live(100, &mut Writer::new()), Err(code(INVALID)));
    assert_eq!(read_live(&reply(|w| w.u32(100))), Err(code(INVALID)));
    assert_eq!(
        read_live(&1303u32.to_le_bytes()),
        Err(Status::Unknown(NOT_FOUND))
    );
}
