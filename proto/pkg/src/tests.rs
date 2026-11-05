// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;

fn bytes(write: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
    let mut w = Writer::new();
    write(&mut w).unwrap();
    w.as_bytes().to_vec()
}

#[test]
fn method_numbers_are_fixed() {
    assert_eq!(
        Method::ALL.map(Method::number),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
    );
    for m in Method::ALL {
        assert_eq!(Method::from_number(m.number()), Some(m));
        assert_eq!(m.header(), Header::new(m.number(), VERSION));
    }
    assert_eq!(Method::from_number(0), None);
    assert_eq!(Method::from_number(18), None);
}

#[test]
fn codes_clear_of_the_wire_and_of_the_disk_service() {
    for (i, a) in CODES.iter().enumerate() {
        assert!((1201..=1222).contains(a), "{a} is outside the series");
        assert!(!CODES[i + 1..].contains(a));
    }
    assert_eq!(CODES.len(), 22);
    for blk in proto_blk::CODES {
        assert!(!CODES.contains(&blk));
    }
    for wire in [256u32, 257, 258] {
        assert!(!CODES.contains(&wire));
    }
    assert_eq!(code(INVALID), Status::Unknown(1222));
    assert_eq!(Status::from_code(NOT_ALLOWED), Status::Unknown(1201));
}

#[test]
fn the_buffer_is_four_cells() {
    assert_eq!(BUFFER_SIZE, 65_536);
    assert_eq!(CELLS * CELL_BYTES, BUFFER_SIZE);
}

#[test]
fn a_list_reply_round_trips() {
    let entries = [
        Entry {
            name: b"hello",
            version: b"1.0",
            sha256: [7; 32],
            flags: ENTRY_WORLD | ENTRY_DEPENDENCY,
            repository: b"stafeto",
        },
        Entry {
            name: b"x",
            version: b"",
            sha256: [0; 32],
            flags: ENTRY_IMAGE,
            repository: b"",
        },
    ];
    let wire = bytes(|w| {
        w.u32(0)?;
        write_list_head(2, 5, w)?;
        for e in &entries {
            e.write(w)?;
        }
        Ok(())
    });
    let mut out = [None; 4];
    assert_eq!(read_list(&wire, &mut out), Ok((2, 5)));
    assert_eq!(out[0], Some(entries[0]));
    assert_eq!(out[1], Some(entries[1]));
    assert_eq!(out[2], None);
    // Every cut and an extra byte are refused.
    for cut in 8..wire.len() {
        assert!(read_list(&wire[..cut], &mut [None; 4]).is_err(), "{cut}");
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(read_list(&extra, &mut [None; 4]).is_err());
    // Five entries are more than a reply holds.
    let five = bytes(|w| {
        w.u32(0)?;
        write_list_head(5, 0, w)
    });
    assert_eq!(read_list(&five, &mut [None; 4]), Err(Status::BadSize));
    assert_eq!(
        read_list(&1216u32.to_le_bytes(), &mut [None; 4]),
        Err(Status::Unknown(1216))
    );
}

#[test]
fn strings_over_their_limit_are_refused() {
    let long = [b'a'; 64];
    let mut w = Writer::new();
    assert_eq!(put_text(&mut w, &long, NAME_MAX), Err(Status::BadSize));
    assert!(put_text(&mut w, &long[..63], NAME_MAX).is_ok());
    let mut wire = vec![64u8];
    wire.extend_from_slice(&long);
    assert_eq!(
        get_text(&mut Reader::new(&wire), NAME_MAX),
        Err(Status::BadSize)
    );
    assert_eq!(
        get_text(&mut Reader::new(&[5, 1, 2]), NAME_MAX),
        Err(Status::BadSize)
    );
}

#[test]
fn info_begin_feed_and_commit_round_trip() {
    let wire = bytes(|w| write_info(b"hello", 960, w));
    assert_eq!(&wire[..8], &Method::Info.header().bytes());
    assert_eq!(read_info(Reader::new(&wire[8..])), Ok((&b"hello"[..], 960)));
    assert_eq!(
        read_info(Reader::new(&wire[8..wire.len() - 1])),
        Err(Status::BadSize)
    );
    let begin = Begin {
        name: b"hello",
        version: b"1.0-1",
        size: 3 << 20,
        sha256: [9; 32],
        repository: b"games",
        flags: BEGIN_WORLD,
    };
    let wire = bytes(|w| begin.write(w));
    assert_eq!(read_begin(Reader::new(&wire[8..])), Ok(begin));
    for cut in 0..wire.len() - 8 {
        assert!(read_begin(Reader::new(&wire[8..8 + cut])).is_err());
    }
    let feed = Feed {
        receipt: 3,
        cell: 3,
        len: CELL_BYTES,
    };
    let wire = bytes(|w| feed.write(w));
    assert_eq!(Feed::read(Reader::new(&wire[8..])), Ok(feed));
    let wire = bytes(|w| write_commit(4, COMMIT_END, w));
    assert_eq!(read_commit(Reader::new(&wire[8..])), Ok((4, COMMIT_END)));
}

#[test]
fn feed_refuses_cell_4_and_length_16385() {
    for (cell, len) in [(4, 1), (0, 16_385), (0, 0), (u32::MAX, 1)] {
        let feed = Feed {
            receipt: 1,
            cell,
            len,
        };
        assert_eq!(feed.write(&mut Writer::new()), Err(code(INVALID)));
        let mut body = Vec::new();
        for word in [1u32, cell, len] {
            body.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(Feed::read(Reader::new(&body)), Err(code(INVALID)));
    }
    let mut body = Vec::new();
    for word in [1u32, 0, 1] {
        body.extend_from_slice(&word.to_le_bytes());
    }
    body.push(0);
    assert_eq!(Feed::read(Reader::new(&body)), Err(Status::BadSize));
    assert_eq!(Feed::read(Reader::new(&body[..11])), Err(Status::BadSize));
}

#[test]
fn remove_serial_take_and_word_round_trip() {
    let wire = bytes(|w| write_remove(&[b"a", b"bb"], w));
    let mut out = [&b""[..]; 8];
    assert_eq!(read_remove(Reader::new(&wire[8..]), &mut out), Ok(2));
    assert_eq!(&out[..2], &[&b"a"[..], &b"bb"[..]]);
    assert_eq!(write_remove(&[], &mut Writer::new()), Err(Status::BadSize));
    assert_eq!(
        write_remove(&[&b"a"[..]; 9], &mut Writer::new()),
        Err(Status::BadSize)
    );
    let mut zero = vec![0u8; 4];
    assert_eq!(
        read_remove(Reader::new(&zero), &mut [&b""[..]; 8]),
        Err(Status::BadSize)
    );
    zero[0] = 9;
    assert_eq!(
        read_remove(Reader::new(&zero), &mut [&b""[..]; 8]),
        Err(Status::BadSize)
    );
    let wire = bytes(|w| write_serial(b"games", None, w));
    assert_eq!(wire[0], 10);
    assert_eq!(
        read_serial(Reader::new(&wire[8..]), false),
        Ok((&b"games"[..], 0))
    );
    let wire = bytes(|w| write_serial(b"games", Some(77), w));
    assert_eq!(wire[0], 11);
    assert_eq!(
        read_serial(Reader::new(&wire[8..]), true),
        Ok((&b"games"[..], 77))
    );
    assert!(read_serial(Reader::new(&wire[8..]), false).is_err());
    let wire = bytes(|w| write_world(b"lib", true, w));
    assert_eq!(wire[0], 17);
    assert_eq!(read_world(Reader::new(&wire[8..])), Ok((&b"lib"[..], true)));
    let wire = bytes(|w| write_world(b"lib", false, w));
    assert_eq!(
        read_world(Reader::new(&wire[8..])),
        Ok((&b"lib"[..], false))
    );
    assert!(read_world(Reader::new(&wire[8..wire.len() - 1])).is_err());
    let mut wire = wire;
    let last = wire.len() - 4;
    wire[last] = 2;
    assert_eq!(read_world(Reader::new(&wire[8..])), Err(Status::BadSize));
    let wire = bytes(|w| write_take(9, w));
    assert_eq!(read_take(Reader::new(&wire[8..])), Ok(9));
    assert_eq!(write_take(0, &mut Writer::new()), Err(Status::BadSize));
    assert_eq!(read_take(Reader::new(&[0; 8])), Err(Status::BadSize));
    let wire = bytes(|w| write_word(Method::List, 12, w));
    assert_eq!(read_word(Reader::new(&wire[8..])), Ok(12));
    assert_eq!(read_word(Reader::new(&wire[8..11])), Err(Status::BadSize));
}

#[test]
fn status_round_trips() {
    let stat = Stat {
        generation: 3,
        blocks: 131_072,
        free: 131_065,
        disk: 2,
        image: 1,
        flags: STATUS_READ_ONLY,
    };
    let wire = bytes(|w| {
        w.u32(0)?;
        stat.write(w)
    });
    assert_eq!(Stat::read(&wire), Ok(stat));
    assert_eq!(Stat::read(&wire[..wire.len() - 1]), Err(Status::BadSize));
    assert_eq!(
        Stat::read(&1221u32.to_le_bytes()),
        Err(Status::Unknown(1221))
    );
}

#[test]
fn the_blob_round_trips_and_every_cut_is_refused() {
    let wire = blob::write(&[
        ("repositories", b"games https://example.org/games\n"),
        ("keys/games.pub", b"ed25519 AAAA games\n"),
    ]);
    let parsed = blob::Blob::parse(&wire).unwrap();
    assert_eq!(parsed.count, 2);
    let files: Vec<_> = parsed.files().collect();
    assert_eq!(files[0].name, b"repositories");
    assert_eq!(files[1].data, b"ed25519 AAAA games\n");
    for cut in 0..wire.len() {
        assert!(blob::Blob::parse(&wire[..cut]).is_err(), "{cut}");
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(blob::Blob::parse(&extra).is_err());
    let mut other = wire.clone();
    other[7] = b'2';
    assert!(blob::Blob::parse(&other).is_err());
    let mut version = wire.clone();
    version[8] = 2;
    assert!(blob::Blob::parse(&version).is_err());
}

#[test]
fn the_blob_limits_are_exact() {
    let many: Vec<(String, &[u8])> = (0..33).map(|i| (format!("f{i}"), &b""[..])).collect();
    let refs: Vec<(&str, &[u8])> = many.iter().map(|(n, d)| (n.as_str(), *d)).collect();
    assert!(blob::Blob::parse(&blob::write(&refs[..32])).is_ok());
    assert!(blob::Blob::parse(&blob::write(&refs)).is_err());
    let fits = vec![0u8; blob::BYTES_MAX - 16 - 2 - 1 - 4];
    assert_eq!(blob::write(&[("a", &fits)]).len(), blob::BYTES_MAX);
    assert!(blob::Blob::parse(&blob::write(&[("a", &fits)])).is_ok());
    let over = vec![0u8; fits.len() + 1];
    assert!(blob::Blob::parse(&blob::write(&[("a", &over)])).is_err());
    assert!(blob::Blob::parse(&blob::write(&[("", b"x")])).is_err());
}

#[test]
fn a_settings_reply_round_trips_with_its_generation() {
    let reply = Settings {
        total: 70_000,
        copied: 16_384,
        generation: 9,
    };
    let mut w = Writer::new();
    w.u32(0).unwrap();
    reply.write(&mut w).unwrap();
    assert_eq!(Settings::read(w.as_bytes()), Ok(reply));
    // Cut, with a byte too many, and a refusal.
    assert!(Settings::read(&w.as_bytes()[..w.as_bytes().len() - 1]).is_err());
    let mut longer = w.as_bytes().to_vec();
    longer.push(0);
    assert!(Settings::read(&longer).is_err());
    assert_eq!(
        Settings::read(&Status::Unknown(BUSY).code().to_le_bytes()),
        Err(code(BUSY))
    );
}
