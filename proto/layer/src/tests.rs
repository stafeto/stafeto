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
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18
        ]
    );
    for m in Method::ALL {
        assert_eq!(Method::from_number(m.number()), Some(m));
        assert_eq!(m.header(), Header::new(m.number(), VERSION));
    }
    assert_eq!(Method::from_number(0), None);
    assert_eq!(Method::from_number(19), None);
    assert_eq!(VERSION, 1);
    assert_eq!(ROOT, 1 << 63 | 1 << 60);
}

#[test]
fn codes_clear_of_the_wire_and_of_the_services_below() {
    for (i, a) in CODES.iter().enumerate() {
        assert!((1301..=1319).contains(a), "{a} is outside the series");
        assert!(!CODES[i + 1..].contains(a));
    }
    assert_eq!(CODES.len(), 19);
    for other in (1101..=1108).chain(proto_pkg::CODES).chain([256, 257, 258]) {
        assert!(!CODES.contains(&other), "{other}");
    }
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

#[test]
fn the_limits_agree_with_the_neighbours() {
    assert_eq!(PATH_MAX, proto_fs::MAX_PATH);
    assert_eq!(NOTE_MAX, proto_pkg::NAME_MAX);
    assert_eq!(CELLS, proto_pkg::CELLS);
    assert_eq!(CELL_BYTES, proto_pkg::CELL_BYTES);
    assert_eq!(BUFFER_SIZE, proto_pkg::BUFFER_SIZE);
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

const NONE: u32 = NO_NUMBER;

fn packages() -> Entry<'static> {
    Entry {
        number: NONE,
        kind: KIND_PACKAGES,
        flags: ENTRY_SEALED,
        parent: NONE,
        composition: 0,
        root: id(3),
        chain: [0; 32],
        lower: [0; 32],
        bytes: 0,
        time: 0,
        note: b"",
    }
}

fn frozen(number: u32, parent: u32, flags: u32, note: &[u8]) -> Entry<'_> {
    let sealed = flags & ENTRY_SEALED != 0;
    Entry {
        number,
        kind: KIND_FROZEN,
        flags,
        parent,
        composition: 0,
        root: if sealed { id(1) } else { [0; 32] },
        chain: if sealed { id(2) } else { [0; 32] },
        lower: if sealed { id(3) } else { [0; 32] },
        bytes: 1 << 33,
        time: 1_795_000_000,
        note,
    }
}

fn live(number: u32, parent: u32, composition: u32) -> Entry<'static> {
    Entry {
        kind: KIND_LIVE,
        number,
        flags: 0,
        parent,
        composition,
        root: [0; 32],
        chain: [0; 32],
        lower: [0; 32],
        bytes: 5,
        time: 6,
        note: b"",
    }
}

#[test]
fn a_list_reply_round_trips() {
    let entries = [
        packages(),
        frozen(1, NONE, ENTRY_SEALED, b"before the upgrade"),
        frozen(2, 1, 0, b""),
        frozen(3, 2, ENTRY_SEALED | ENTRY_DEFERRED | ENTRY_DAMAGED, b"x"),
        live(4, 1, 7),
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
    refuses_cuts(&wire, 0, |b| {
        read_list(b, &mut [None; LIST_MAX as usize]).is_err()
    });
    let six = reply(|w| write_list_head(6, 0, w));
    assert_eq!(
        read_list(&six, &mut [None; LIST_MAX as usize]),
        Err(Status::BadSize)
    );
    assert_eq!(
        read_list(&1303u32.to_le_bytes(), &mut [None; LIST_MAX as usize]),
        Err(Status::Unknown(NOT_FOUND))
    );
}

#[test]
fn a_page_with_no_entry_does_not_point_on() {
    assert_eq!(
        write_list_head(0, 4, &mut Writer::new()),
        Err(code(INVALID))
    );
    assert!(write_list_head(0, 0, &mut Writer::new()).is_ok());
    let mut wire = 0u32.to_le_bytes().to_vec();
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire.extend_from_slice(&4u32.to_le_bytes());
    assert_eq!(
        read_list(&wire, &mut [None; LIST_MAX as usize]),
        Err(code(INVALID))
    );
    assert_eq!(read_changes(&wire, |_| {}), Err(code(INVALID)));
}

#[test]
fn five_longest_entries_fit_one_message() {
    let e = frozen(99, 98, ENTRY_SEALED, &[b'n'; 63]);
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
        Ok(5)
    );
}

#[test]
fn an_entry_that_does_not_make_sense_is_refused_both_ways() {
    let bad = [
        Entry {
            kind: 0,
            ..live(1, NONE, 0)
        },
        Entry {
            kind: 4,
            ..live(1, NONE, 0)
        },
        frozen(100, NONE, 0, b""),
        frozen(NONE, NONE, 0, b""),
        frozen(1, 100, 0, b""),
        frozen(1, 1, 0, b""),
        frozen(1, NONE, 8, b""),
        Entry {
            composition: 1,
            ..frozen(1, NONE, 0, b"")
        },
        Entry {
            root: id(1),
            ..frozen(1, NONE, 0, b"")
        },
        Entry {
            chain: [0; 32],
            ..frozen(1, NONE, ENTRY_SEALED, b"")
        },
        Entry {
            lower: id(1),
            ..frozen(1, NONE, 0, b"")
        },
        frozen(1, NONE, 0, &[b'n'; 64]),
        // The lower set: unsealed, numbered, deferred, damaged, with a chain id or a parent.
        Entry {
            flags: 0,
            ..packages()
        },
        Entry {
            number: 1,
            ..packages()
        },
        Entry {
            flags: ENTRY_SEALED | ENTRY_DEFERRED,
            ..packages()
        },
        Entry {
            flags: ENTRY_SEALED | ENTRY_DAMAGED,
            ..packages()
        },
        Entry {
            chain: id(1),
            ..packages()
        },
        Entry {
            parent: 1,
            ..packages()
        },
        Entry {
            lower: id(1),
            ..packages()
        },
        Entry {
            composition: 1,
            ..packages()
        },
        // The live layer: sealed, deferred, damaged, with a root, a chain id or a lower digest.
        Entry {
            flags: ENTRY_SEALED,
            ..live(1, NONE, 0)
        },
        Entry {
            flags: ENTRY_DEFERRED,
            ..live(1, NONE, 0)
        },
        Entry {
            flags: ENTRY_DAMAGED,
            ..live(1, NONE, 0)
        },
        Entry {
            root: id(1),
            ..live(1, NONE, 0)
        },
        Entry {
            chain: id(1),
            ..live(1, NONE, 0)
        },
        Entry {
            lower: id(1),
            ..live(1, NONE, 0)
        },
        live(1, 1, 0),
    ];
    for e in bad {
        assert!(e.write(&mut Writer::new()).is_err(), "{e:?}");
    }
    // The same on the read side: break the fields of a good entry in the bytes (after the
    // status, the count and `next`: number at 12, kind 16, flags 20, parent 24, composition 28).
    let good = frozen(1, NONE, ENTRY_SEALED, b"a");
    let wire = reply(|w| {
        write_list_head(1, 0, w)?;
        good.write(w)
    });
    for (offset, value) in [(12, 100u8), (16, 9), (20, 8), (20, 0), (24, 100), (28, 1)] {
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
    let many = reply(|w| w.u32(DIFF_MAX + 1).and_then(|_| w.u32(0)));
    assert_eq!(read_changes(&many, |_| {}), Err(Status::BadSize));
}

#[test]
fn compose_round_trips_and_has_its_limits() {
    let layers = [
        Selector::Number(1),
        Selector::Chain(id(9)),
        Selector::Number(7),
    ];
    for flags in [0, COMPOSE_KEEP] {
        let wire = bytes(|w| write_compose(flags, &layers, w));
        let mut out = [Selector::Live; LAYERS_MAX];
        assert_eq!(
            read_compose(Reader::new(&wire[8..]), &mut out),
            Ok((flags, 3))
        );
        assert_eq!(&out[..3], &layers);
        refuses_cuts(&wire[8..], 0, |b| {
            read_compose(Reader::new(b), &mut [Selector::Live; LAYERS_MAX]).is_err()
        });
    }
    let none = bytes(|w| write_compose(0, &[], w));
    assert_eq!(
        read_compose(Reader::new(&none[8..]), &mut [Selector::Live; LAYERS_MAX]),
        Ok((0, 0))
    );
    let numbers: Vec<Selector> = (0..16).map(Selector::Number).collect();
    assert!(write_compose(0, &numbers, &mut Writer::new()).is_ok());
    let seventeen: Vec<Selector> = (0..17).map(Selector::Number).collect();
    assert_eq!(
        write_compose(0, &seventeen, &mut Writer::new()),
        Err(Status::BadSize)
    );
    assert_eq!(
        write_compose(0, &[Selector::Live], &mut Writer::new()),
        Err(code(INVALID))
    );
    assert_eq!(
        write_compose(2, &[], &mut Writer::new()),
        Err(code(INVALID))
    );
    // The same layer twice, either way.
    let twice = [Selector::Number(1), Selector::Number(1)];
    assert_eq!(
        write_compose(0, &twice, &mut Writer::new()),
        Err(code(INVALID))
    );
    let mut wire = 0u32.to_le_bytes().to_vec();
    wire.extend_from_slice(&2u32.to_le_bytes());
    for _ in 0..2 {
        wire.extend_from_slice(&1u32.to_le_bytes());
        wire.extend_from_slice(&1u32.to_le_bytes());
    }
    assert_eq!(
        read_compose(Reader::new(&wire), &mut [Selector::Live; LAYERS_MAX]),
        Err(code(INVALID))
    );
    let mut wire = 0u32.to_le_bytes().to_vec();
    wire.extend_from_slice(&17u32.to_le_bytes());
    assert_eq!(
        read_compose(Reader::new(&wire), &mut [Selector::Live; LAYERS_MAX]),
        Err(Status::BadSize)
    );
    // Sixteen chain ids are the longest body and still fit a message.
    let chains: Vec<Selector> = (0..16u8).map(|i| Selector::Chain(id(i))).collect();
    assert!(bytes(|w| write_compose(0, &chains, w)).len() <= abi::MESSAGE_MAX);
}

#[test]
fn composed_round_trips() {
    let c = Composed {
        composition: 2,
        live: 5,
    };
    let wire = bytes(|w| c.write(w));
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
        assert_eq!(bad.write(&mut Writer::new()), Err(code(INVALID)));
    }
}

#[test]
fn freeze_round_trips_with_a_note_alone() {
    for note in [&b""[..], b"before the upgrade", &[b'n'; 63][..]] {
        let wire = bytes(|w| write_freeze(note, w));
        assert_eq!(read_freeze(Reader::new(&wire[8..])), Ok(note));
        refuses_cuts(&wire[8..], 0, |b| read_freeze(Reader::new(b)).is_err());
    }
    assert_eq!(
        write_freeze(&[b'n'; 64], &mut Writer::new()),
        Err(Status::BadSize)
    );
}

#[test]
fn select_squash_and_remove_round_trip() {
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
}

#[test]
fn the_buffer_is_four_cells() {
    assert_eq!(BUFFER_SIZE, 65_536);
    let wire = bytes(|w| write_buffer(BUFFER_SIZE, w));
    assert_eq!(read_buffer(Reader::new(&wire[8..])), Ok(BUFFER_SIZE));
    assert_eq!(write_buffer(4096, &mut Writer::new()), Err(code(INVALID)));
    assert_eq!(
        read_buffer(Reader::new(&4096u32.to_le_bytes())),
        Err(code(INVALID))
    );
    refuses_cuts(&wire[8..], 0, |b| read_buffer(Reader::new(b)).is_err());
}

#[test]
fn export_and_its_parts_round_trip() {
    let wire = bytes(|w| write_export(&Selector::Number(3), 65_536, w));
    assert_eq!(
        read_export(Reader::new(&wire[8..])),
        Ok((Selector::Number(3), 65_536))
    );
    refuses_cuts(&wire[8..], 0, |b| read_export(Reader::new(b)).is_err());
    assert_eq!(
        write_export(&Selector::Number(3), 100, &mut Writer::new()),
        Err(code(INVALID))
    );
    assert_eq!(
        write_export(&Selector::Live, 0, &mut Writer::new()),
        Err(code(INVALID))
    );
    let mut odd = bytes(|w| write_export(&Selector::Number(3), 0, w))[8..].to_vec();
    let n = odd.len();
    odd[n - 8] = 1;
    assert_eq!(read_export(Reader::new(&odd)), Err(code(INVALID)));

    let part = ExportPart {
        root: id(1),
        total: 3 << 30,
        copied: BUFFER_SIZE,
        diff_id: [0; 32],
    };
    let wire = bytes(|w| part.write(w));
    assert_eq!(ExportPart::read(&wire), Ok(part));
    refuses_cuts(&wire, 0, |b| ExportPart::read(b).is_err());
    let last = ExportPart {
        copied: 1024,
        diff_id: id(2),
        ..part
    };
    assert_eq!(ExportPart::read(&bytes(|w| last.write(w))), Ok(last));
    for bad in [
        ExportPart { total: 0, ..part },
        ExportPart { total: 512, ..part },
        ExportPart {
            total: 1000,
            ..part
        },
        ExportPart {
            copied: BUFFER_SIZE + 1,
            ..part
        },
    ] {
        assert_eq!(bad.write(&mut Writer::new()), Err(code(INVALID)));
    }
}

#[test]
fn import_begin_feed_commit_and_cancel_round_trip() {
    for (diff_id, root) in [
        (None, None),
        (Some(id(6)), None),
        (None, Some(id(7))),
        (Some(id(6)), Some(id(7))),
    ] {
        let begin = ImportBegin {
            size: 4096,
            diff_id,
            root,
            note: b"from a registry",
        };
        let wire = bytes(|w| begin.write(w));
        assert_eq!(&wire[..8], &Method::ImportBegin.header().bytes());
        assert_eq!(read_import_begin(Reader::new(&wire[8..])), Ok(begin));
        refuses_cuts(&wire[8..], 0, |b| {
            read_import_begin(Reader::new(b)).is_err()
        });
    }
    for size in [0, 512, 1000, 1025] {
        let begin = ImportBegin {
            size,
            diff_id: None,
            root: None,
            note: b"",
        };
        assert_eq!(begin.write(&mut Writer::new()), Err(code(INVALID)));
    }
    let long_note = ImportBegin {
        size: 1024,
        diff_id: None,
        root: None,
        note: &[b'n'; 64],
    };
    assert_eq!(long_note.write(&mut Writer::new()), Err(Status::BadSize));
    // A flag with no digest behind it, an unknown flag, a size that is no archive's.
    let mut wire = 4096u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&IMPORT_DIGEST.to_le_bytes());
    wire.extend_from_slice(&[0]);
    assert!(read_import_begin(Reader::new(&wire)).is_err());
    let mut wire = 4096u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&4u32.to_le_bytes());
    wire.extend_from_slice(&[0]);
    assert_eq!(read_import_begin(Reader::new(&wire)), Err(code(INVALID)));
    let mut wire = 100u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire.extend_from_slice(&[0]);
    assert_eq!(read_import_begin(Reader::new(&wire)), Err(code(INVALID)));

    let feed = Feed {
        receipt: 3,
        cell: 3,
        len: CELL_BYTES,
    };
    let wire = bytes(|w| feed.write(w));
    assert_eq!(Feed::read(Reader::new(&wire[8..])), Ok(feed));
    for (cell, len) in [(4, 1), (0, 16_385), (0, 0), (u32::MAX, 1)] {
        let bad = Feed {
            receipt: 1,
            cell,
            len,
        };
        assert_eq!(bad.write(&mut Writer::new()), Err(code(INVALID)));
        let mut body = Vec::new();
        for word in [1u32, cell, len] {
            body.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(Feed::read(Reader::new(&body)), Err(code(INVALID)));
    }
    refuses_cuts(&wire[8..], 0, |b| Feed::read(Reader::new(b)).is_err());

    for method in [Method::ImportCommit, Method::ImportCancel] {
        let wire = bytes(|w| write_receipt(method, 9, w));
        assert_eq!(&wire[..8], &method.header().bytes());
        assert_eq!(read_receipt(Reader::new(&wire[8..])), Ok(9));
        assert_eq!(
            write_receipt(method, 0, &mut Writer::new()),
            Err(Status::BadSize)
        );
    }
    assert_eq!(read_receipt(Reader::new(&[0; 4])), Err(Status::BadSize));
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
    for method in [Method::Status, Method::Session] {
        assert_eq!(bytes(|w| write_empty(method, w)), method.header().bytes());
    }
}

fn sealed(number: u32) -> Sealed {
    Sealed {
        number,
        root: id(1),
        chain: id(2),
    }
}

#[test]
fn the_results_of_the_jobs_round_trip() {
    let done = sealed(4);
    let wire = bytes(|w| done.write(w));
    assert_eq!(Sealed::read(&wire), Ok(done));
    assert!(done.is_sealed());
    refuses_cuts(&wire, 0, |b| Sealed::read(b).is_err());
    // A layer whose sealing is not done has root and chain id both zero, never one of them.
    let open = Sealed {
        number: 4,
        root: [0; 32],
        chain: [0; 32],
    };
    assert_eq!(Sealed::read(&bytes(|w| open.write(w))), Ok(open));
    assert!(!open.is_sealed());
    for bad in [
        Sealed {
            number: 100,
            ..done
        },
        Sealed {
            root: [0; 32],
            ..done
        },
        Sealed {
            chain: [0; 32],
            ..done
        },
    ] {
        assert_eq!(bad.write(&mut Writer::new()), Err(code(INVALID)));
    }
    let frozen = Frozen {
        sealed: done,
        live: 5,
    };
    let wire = bytes(|w| frozen.write(w));
    assert_eq!(Frozen::read(&wire), Ok(frozen));
    refuses_cuts(&wire, 0, |b| Frozen::read(b).is_err());
    let unsealed = Frozen {
        sealed: open,
        live: 5,
    };
    assert_eq!(Frozen::read(&bytes(|w| unsealed.write(w))), Ok(unsealed));
    for bad in [
        Frozen {
            sealed: done,
            live: 100,
        },
        Frozen {
            sealed: done,
            live: 4,
        },
    ] {
        assert_eq!(bad.write(&mut Writer::new()), Err(code(INVALID)));
    }
    let mut broken = wire.clone();
    broken[wire.len() - 4] = 4;
    assert_eq!(Frozen::read(&broken), Err(code(INVALID)));
    let imported = Imported {
        frozen,
        diff_id: id(3),
    };
    let wire = bytes(|w| imported.write(w));
    assert_eq!(Imported::read(&wire), Ok(imported));
    refuses_cuts(&wire, 0, |b| Imported::read(b).is_err());
    assert_eq!(
        Imported {
            frozen: Frozen {
                sealed: done,
                live: 4
            },
            diff_id: id(3)
        }
        .write(&mut Writer::new()),
        Err(code(INVALID))
    );
}

#[test]
fn live_and_removed_results_round_trip() {
    let wire = bytes(|w| write_live(6, w));
    assert_eq!(read_live(&wire), Ok(6));
    refuses_cuts(&wire, 0, |b| read_live(b).is_err());
    assert_eq!(write_live(100, &mut Writer::new()), Err(code(INVALID)));
    assert_eq!(read_live(&100u32.to_le_bytes()), Err(code(INVALID)));
    let wire = bytes(|w| write_removed(3, w));
    assert_eq!(read_removed(&wire), Ok(3));
    refuses_cuts(&wire, 0, |b| read_removed(b).is_err());
    for bad in [0, 17] {
        assert_eq!(write_removed(bad, &mut Writer::new()), Err(code(INVALID)));
        assert_eq!(read_removed(&bad.to_le_bytes()), Err(code(INVALID)));
    }
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
    let mut broken = wire.clone();
    broken[12] = 2;
    assert_eq!(Checked::read(&broken), Err(code(INVALID)));
    let no_layer = Checked {
        layers: 1,
        files: 1,
        first_bad: Some((100, b"/a")),
    };
    assert_eq!(no_layer.write(&mut Writer::new()), Err(code(INVALID)));
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
        sealed: sealed(1),
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
    let cancelled = bytes(|w| long::Reply::Cancelled.write(w));
    assert_eq!(long::Reply::read(&cancelled), Ok(long::Reply::Cancelled));
}

fn stat() -> Stat {
    Stat {
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
        queued: 2,
        done: 10,
        total: 20,
    }
}

#[test]
fn status_round_trips_and_refuses_what_makes_no_sense() {
    let stat = stat();
    let wire = reply(|w| stat.write(w));
    assert_eq!(Stat::read(&wire), Ok(stat));
    refuses_cuts(&wire, 0, |b| Stat::read(b).is_err());
    let idle = Stat {
        job: JOB_NONE,
        queued: 0,
        done: 0,
        total: 0,
        ..stat
    };
    assert_eq!(Stat::read(&reply(|w| idle.write(w))), Ok(idle));
    let full = Stat {
        frozen: 14,
        deferred: 1,
        ..stat
    };
    assert_eq!(Stat::read(&reply(|w| full.write(w))), Ok(full));
    for bad in [
        Stat { live: 100, ..stat },
        Stat {
            frozen: 15,
            deferred: 1,
            ..stat
        },
        Stat {
            frozen: 16,
            deferred: 0,
            ..stat
        },
        Stat { flags: 16, ..stat },
        Stat { job: 8, ..stat },
        Stat {
            queued: JOBS_MAX + 1,
            ..stat
        },
        Stat { done: 21, ..stat },
        Stat {
            job: JOB_NONE,
            ..stat
        },
        Stat {
            job: JOB_NONE,
            queued: 1,
            done: 0,
            total: 0,
            ..stat
        },
        Stat {
            job: JOB_NONE,
            queued: 0,
            done: 1,
            total: 1,
            ..stat
        },
    ] {
        assert_eq!(bad.write(&mut Writer::new()), Err(code(INVALID)), "{bad:?}");
    }
    // The reader checks too: break the job in the bytes (it is at 4 + 16 + 8 + 16 + 8 = 52).
    let mut broken = wire.clone();
    broken[52] = 8;
    assert_eq!(Stat::read(&broken), Err(code(INVALID)));
    assert_eq!(
        Stat::read(&1309u32.to_le_bytes()),
        Err(Status::Unknown(NO_STORE))
    );
}
