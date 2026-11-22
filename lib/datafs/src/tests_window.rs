// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The parts of version 4 on the server over the device in memory: READ_INTO, PREAD_INTO,
//! WRITE_FROM and PWRITE_FROM through the cells of a window (a vector of the test stands for the
//! memory the worker maps) and `INLINE`, OPEN_NUMBERED, and the answers of a session with no window.

use crate::server::Cell;
use crate::tests_perm::{OTHER, OWNER, ROOT, Rig, user};
use proto_data as p;
use proto_data::Method;
use proto_wire::{Reader, Status, Writer};
use std::vec;
use std::vec::Vec;

/// The bytes of the files of these tests, a function of the position.
fn byte(pos: usize) -> u8 {
    (pos.wrapping_mul(2_654_435_761) >> 11) as u8
}

fn pattern(from: usize, len: usize) -> Vec<u8> {
    (from..from + len).map(byte).collect()
}

fn head(handle: u32, count: usize, offset: u64, cell: u32, flags: u32) -> p::Part {
    p::Part {
        handle,
        count: count as u32,
        offset,
        cell,
        flags,
        lease: 0,
    }
}

/// The reply to a part: the three words, and the bytes of an `INLINE` read.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    count: u32,
    flags: u32,
    lease: u32,
    bytes: Vec<u8>,
}

impl Rig {
    /// The window of the session: it has one from here on (the worker holds the handle).
    fn window(&mut self, who: u64) {
        self.server.set_window(who, true).unwrap();
    }

    /// One part: `data` are the bytes of a write (from the cell or the message), `cell` the cell
    /// memory of the test; the reply or the status.
    fn part(
        &mut self,
        who: u64,
        method: Method,
        part: p::Part,
        data: &[u8],
        cells: &mut [Vec<u8>; 2],
    ) -> Result<Reply, Status> {
        let write = matches!(method, Method::WriteFrom | Method::PwriteFrom);
        let inline = part.cell == p::INLINE;
        let mut w = Writer::new();
        match method {
            Method::ReadInto => p::read_into(&part, &mut w),
            Method::PreadInto => p::pread_into(&part, &mut w),
            Method::WriteFrom => p::write_from(&part, if inline { data } else { &[] }, &mut w),
            _ => p::pwrite_from(&part, if inline { data } else { &[] }, &mut w),
        }
        .unwrap();
        let count = part.count as usize;
        let cell = match (inline, part.cell) {
            (true, _) | (_, 2..) => Cell::Absent,
            (false, c) if write => {
                cells[c as usize][..count].copy_from_slice(&data[..count]);
                Cell::Source(&cells[c as usize][..count])
            }
            (false, c) => Cell::Sink(&mut cells[c as usize][..count]),
        };
        let reply = self
            .server
            .handle_with(&mut self.fs, who, 0, w.as_bytes(), cell);
        let r = p::reply(reply.as_bytes())?;
        let got = p::read_part_reply(r, inline && !write).unwrap();
        Ok(Reply {
            count: got.count,
            flags: got.flags,
            lease: got.lease,
            bytes: got.bytes.to_vec(),
        })
    }
}

/// A volume with `/d`, open to everyone.
fn volume() -> Rig {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig
}

fn cells() -> [Vec<u8>; 2] {
    [vec![0u8; p::CELL_BYTES], vec![0u8; p::CELL_BYTES]]
}

#[test]
fn a_file_written_in_parts_through_the_cells_reads_back_the_same_through_the_cells_and_the_old_read()
 {
    let mut rig = volume();
    rig.window(OWNER);
    let mut c = cells();
    let h = rig
        .open(OWNER, b"/d/f", p::READ | p::WRITE | p::CREATE, 0o644)
        .unwrap();
    // 200,000 bytes in parts of a cell and a rest, alternating the two cells.
    let total = 200_000usize;
    let all = pattern(0, total);
    let mut at = 0;
    let mut which = 0;
    while at < total {
        let n = (total - at).min(p::CELL_BYTES);
        let more = if at + n < total { p::MORE } else { 0 };
        let r = rig
            .part(
                OWNER,
                Method::WriteFrom,
                head(h, n, 0, which, more),
                &all[at..at + n],
                &mut c,
            )
            .unwrap();
        assert_eq!((r.count as usize, r.lease), (n, 0));
        // No lease is given yet: a part that asks for one is told so.
        assert_eq!(r.flags, if more != 0 { p::UNLEASED } else { 0 });
        at += n;
        which ^= 1;
    }
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().size, total as u64);
    // The old READ sees it, from the start (the position moved with the parts: seek back).
    rig.ok(OWNER, |w| p::seek(h, 0, p::SEEK_SET, w));
    let mut old = Vec::new();
    loop {
        let chunk = rig.read(OWNER, h, 1000).unwrap();
        if chunk.is_empty() {
            break;
        }
        old.extend_from_slice(&chunk);
    }
    assert!(old == all, "the old READ differs");
    // READ_INTO in parts of a cell reads it back, and the position moves as READ's does.
    rig.ok(OWNER, |w| p::seek(h, 0, p::SEEK_SET, w));
    let mut got = Vec::new();
    loop {
        let r = rig
            .part(
                OWNER,
                Method::ReadInto,
                head(
                    h,
                    p::CELL_BYTES,
                    0,
                    (got.len() / p::CELL_BYTES % 2) as u32,
                    0,
                ),
                &[],
                &mut c,
            )
            .unwrap();
        if r.count == 0 {
            break;
        }
        let cell = got.len() / p::CELL_BYTES % 2;
        got.extend_from_slice(&c[cell][..r.count as usize]);
    }
    assert!(got == all, "READ_INTO differs");
    let seek = rig.ok(OWNER, |w| p::seek(h, 0, p::SEEK_CUR, w));
    assert_eq!(
        u64::from_le_bytes(seek[..8].try_into().unwrap()),
        total as u64
    );
}

#[test]
fn pread_into_and_pwrite_from_take_their_offset_and_leave_the_position() {
    let mut rig = volume();
    rig.window(OWNER);
    let mut c = cells();
    let h = rig
        .open(OWNER, b"/d/f", p::READ | p::WRITE | p::CREATE, 0o644)
        .unwrap();
    for chunk in pattern(0, 10_000).chunks(1000) {
        rig.write(OWNER, h, chunk).unwrap();
    }
    // Overwrite 5,000 bytes at 3,000 through a cell; the position stays at 10,000.
    let new = vec![0xEEu8; 5000];
    let r = rig
        .part(
            OWNER,
            Method::PwriteFrom,
            head(h, 5000, 3000, 1, 0),
            &new,
            &mut c,
        )
        .unwrap();
    assert_eq!(r.count, 5000);
    let mut want = pattern(0, 10_000);
    want[3000..8000].copy_from_slice(&new);
    let r = rig
        .part(
            OWNER,
            Method::PreadInto,
            head(h, 10_000, 0, 0, 0),
            &[],
            &mut c,
        )
        .unwrap();
    assert_eq!(r.count, 10_000);
    assert!(c[0][..10_000] == want[..]);
    let seek = rig.ok(OWNER, |w| p::seek(h, 0, p::SEEK_CUR, w));
    assert_eq!(u64::from_le_bytes(seek[..8].try_into().unwrap()), 10_000);
    // A read past the end is short, at the end it is 0.
    let r = rig
        .part(
            OWNER,
            Method::PreadInto,
            head(h, 4000, 8000, 0, 0),
            &[],
            &mut c,
        )
        .unwrap();
    assert_eq!(r.count, 2000);
    let r = rig
        .part(
            OWNER,
            Method::PreadInto,
            head(h, 4000, 10_000, 0, 0),
            &[],
            &mut c,
        )
        .unwrap();
    assert_eq!(r.count, 0);
    // An offset past FILE_MAX is TOO_BIG.
    assert_eq!(
        rig.part(
            OWNER,
            Method::PreadInto,
            head(h, 1, p::FILE_MAX + 1, 0, 0),
            &[],
            &mut c
        ),
        Err(p::code(p::TOO_BIG))
    );
}

#[test]
fn a_part_of_an_append_description_goes_to_the_end_and_a_pwrite_from_ignores_the_flag() {
    let mut rig = volume();
    rig.window(OWNER);
    let mut c = cells();
    rig.put(OWNER, b"/d/f", 0o644, &[1u8; 100]);
    let h = rig
        .open(OWNER, b"/d/f", p::READ | p::WRITE | p::APPEND, 0)
        .unwrap();
    rig.part(
        OWNER,
        Method::WriteFrom,
        head(h, 50, 0, 0, 0),
        &[2u8; 50],
        &mut c,
    )
    .unwrap();
    // POSIX.1-2024 pwrite(): the offset is used and O_APPEND does not matter.
    rig.part(
        OWNER,
        Method::PwriteFrom,
        head(h, 10, 0, 1, 0),
        &[3u8; 10],
        &mut c,
    )
    .unwrap();
    let r = rig
        .part(OWNER, Method::PreadInto, head(h, 200, 0, 0, 0), &[], &mut c)
        .unwrap();
    assert_eq!(r.count, 150);
    let mut want = vec![1u8; 100];
    want.extend_from_slice(&[2u8; 50]);
    want[..10].copy_from_slice(&[3u8; 10]);
    assert!(c[0][..150] == want[..]);
}

#[test]
fn inline_parts_do_what_read_pread_write_and_pwrite_do() {
    let mut rig = volume();
    let mut c = cells();
    // No window at all: INLINE needs none.
    let h = rig
        .open(OWNER, b"/d/f", p::READ | p::WRITE | p::CREATE, 0o644)
        .unwrap();
    let data = pattern(7, p::INLINE_WRITE);
    let r = rig
        .part(
            OWNER,
            Method::WriteFrom,
            head(h, data.len(), 0, p::INLINE, 0),
            &data,
            &mut c,
        )
        .unwrap();
    assert_eq!(r.count as usize, p::INLINE_WRITE);
    let more = pattern(9000, p::INLINE_PWRITE);
    rig.part(
        OWNER,
        Method::PwriteFrom,
        head(h, more.len(), 5000, p::INLINE, 0),
        &more,
        &mut c,
    )
    .unwrap();
    let mut want = data.clone();
    want.resize(5000 + p::INLINE_PWRITE, 0);
    want[5000..].copy_from_slice(&more);
    rig.ok(OWNER, |w| p::seek(h, 0, p::SEEK_SET, w));
    let mut got = Vec::new();
    loop {
        let r = rig
            .part(
                OWNER,
                Method::ReadInto,
                head(h, p::INLINE_READ, 0, p::INLINE, 0),
                &[],
                &mut c,
            )
            .unwrap();
        if r.count == 0 {
            break;
        }
        assert_eq!(r.count as usize, r.bytes.len());
        got.extend_from_slice(&r.bytes);
    }
    assert!(got == want);
    let r = rig
        .part(
            OWNER,
            Method::PreadInto,
            head(h, 100, 4950, p::INLINE, 0),
            &[],
            &mut c,
        )
        .unwrap();
    assert_eq!(r.bytes, want[4950..5050]);
}

#[test]
fn a_part_with_a_cell_in_a_session_with_no_window_is_no_window_and_touches_nothing() {
    let mut rig = volume();
    let mut c = cells();
    rig.put(OWNER, b"/d/f", 0o644, &[5u8; 1000]);
    let h = rig.open(OWNER, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    let no_window = Err(p::code(p::NO_WINDOW));
    for method in [
        Method::ReadInto,
        Method::PreadInto,
        Method::WriteFrom,
        Method::PwriteFrom,
    ] {
        assert_eq!(
            rig.part(OWNER, method, head(h, 10, 0, 0, 0), &[9u8; 10], &mut c),
            no_window,
            "{method:?}"
        );
    }
    // Neither the file nor the position moved.
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().size, 1000);
    assert_eq!(rig.read(OWNER, h, 1000).unwrap(), vec![5u8; 1000]);
    // The window comes, the part goes through; the session ends and the window is gone with it.
    rig.window(OWNER);
    assert!(rig.server.has_window(OWNER));
    rig.ok(OWNER, |w| p::seek(h, 0, p::SEEK_SET, w));
    assert_eq!(
        rig.part(OWNER, Method::PreadInto, head(h, 10, 0, 0, 0), &[], &mut c)
            .unwrap()
            .count,
        10
    );
    // UNBIND (a loader's VERIFY_SESSION) lets the window go; a new one is given again.
    rig.server.unbind(OWNER);
    assert!(!rig.server.has_window(OWNER));
    assert_eq!(
        rig.part(OWNER, Method::PreadInto, head(h, 10, 0, 0, 0), &[], &mut c),
        no_window
    );
    rig.window(OWNER);
    rig.server.gone(&mut rig.fs, OWNER);
    assert!(!rig.server.has_window(OWNER));
    // A window of a new instance: the server has none until the session gives one (a restart).
    let mut fresh = volume();
    assert!(!fresh.server.has_window(OWNER));
    fresh.window(OTHER);
    assert!(fresh.server.has_window(OTHER) && !fresh.server.has_window(OWNER));
}

#[test]
fn the_access_bits_and_the_binding_of_a_description_hold_for_the_new_methods() {
    let mut rig = volume();
    let mut c = cells();
    rig.window(OWNER);
    rig.put(OWNER, b"/d/f", 0o644, &[5u8; 100]);
    let read_only = rig.open(OWNER, b"/d/f", p::READ, 0).unwrap();
    let write_only = rig.open(OWNER, b"/d/f", p::WRITE, 0).unwrap();
    let bad = Err(p::code(p::BAD_HANDLE));
    assert_eq!(
        rig.part(
            OWNER,
            Method::WriteFrom,
            head(read_only, 1, 0, 0, 0),
            &[1],
            &mut c
        ),
        bad
    );
    assert_eq!(
        rig.part(
            OWNER,
            Method::PwriteFrom,
            head(read_only, 1, 0, 0, 0),
            &[1],
            &mut c
        ),
        bad
    );
    assert_eq!(
        rig.part(
            OWNER,
            Method::ReadInto,
            head(write_only, 1, 0, 0, 0),
            &[],
            &mut c
        ),
        bad
    );
    assert_eq!(
        rig.part(
            OWNER,
            Method::PreadInto,
            head(write_only, 1, 0, 0, 0),
            &[],
            &mut c
        ),
        bad
    );
    // A handle of another session is BAD_HANDLE, a handle of another epoch STALE.
    rig.bind(41, user(1000, 100, &[]));
    rig.server.set_window(41, true).unwrap();
    assert_eq!(
        rig.part(
            41,
            Method::ReadInto,
            head(read_only, 1, 0, 0, 0),
            &[],
            &mut c
        ),
        bad
    );
    assert_eq!(
        rig.part(
            OWNER,
            Method::ReadInto,
            head(read_only ^ 0x0001_0000 | 0x0002_0000, 1, 0, 0, 0),
            &[],
            &mut c
        )
        .map(drop),
        Err(p::code(p::STALE))
    );
    // A session of a clone has no binding: it may read through a part but not write.
    rig.clone_session(OWNER, 0x8000_0000_0000_0001, &[read_only])
        .unwrap();
    let child = 0x8000_0000_0000_0001;
    rig.server.set_window(child, true).unwrap();
    assert_eq!(
        rig.part(
            child,
            Method::ReadInto,
            head(read_only, 10, 0, 0, 0),
            &[],
            &mut c
        )
        .unwrap()
        .count,
        10
    );
    assert_eq!(
        rig.part(
            child,
            Method::WriteFrom,
            head(read_only, 1, 0, 0, 0),
            &[1],
            &mut c
        ),
        Err(p::code(p::NOT_BOUND))
    );
    // The root channel answers IS_ROOT to every new method.
    for method in [Method::ReadInto, Method::WriteFrom] {
        assert_eq!(
            rig.part(p::ROOT, method, head(read_only, 1, 0, 0, 0), &[1], &mut c),
            Err(p::code(p::IS_ROOT))
        );
    }
}

#[test]
fn a_bound_client_stops_short_at_its_file_size_limit_in_a_part() {
    let mut rig = volume();
    let mut limited = user(1000, 100, &[]);
    limited.fsize_limit = 1000;
    rig.bind(41, limited);
    rig.server.set_window(41, true).unwrap();
    let mut c = cells();
    let h = rig.open(41, b"/d/f", p::WRITE | p::CREATE, 0o644).unwrap();
    let r = rig
        .part(
            41,
            Method::WriteFrom,
            head(h, 5000, 0, 0, 0),
            &vec![1u8; 5000],
            &mut c,
        )
        .unwrap();
    assert_eq!(r.count, 1000);
    assert_eq!(
        rig.part(
            41,
            Method::WriteFrom,
            head(h, 10, 0, 0, 0),
            &[1u8; 10],
            &mut c
        ),
        Err(p::code(p::FILE_SIZE_LIMIT))
    );
}

#[test]
fn leases_do_not_exist_yet_and_the_shape_of_a_part_is_checked() {
    let mut rig = volume();
    rig.window(OWNER);
    let mut c = cells();
    let h = rig
        .open(OWNER, b"/d/f", p::READ | p::WRITE | p::CREATE, 0o644)
        .unwrap();
    // A lease number is one the service never gave.
    let mut leased = head(h, 1, 0, 0, 0);
    leased.lease = 9;
    assert_eq!(
        rig.part(OWNER, Method::WriteFrom, leased, &[1], &mut c),
        Err(p::code(p::BAD_HANDLE))
    );
    let r = rig.call(OWNER, |w| p::release(9, w));
    assert_eq!(r, Err(p::code(p::BAD_HANDLE)));
    // A count past the cell, a cell that is neither, a flag that is none: INVALID, whatever the window.
    for bad in [
        head(h, p::CELL_BYTES + 1, 0, 0, 0),
        head(h, 1, 0, 2, 0),
        head(h, 1, 0, 0, 2),
    ] {
        let mut w = Writer::new();
        p::read_into(&bad, &mut w).unwrap();
        let reply = rig.server.handle(&mut rig.fs, OWNER, 0, w.as_bytes());
        assert_eq!(
            p::reply(reply.as_bytes()).map(drop),
            Err(p::code(p::INVALID))
        );
    }
    // A cell the worker could not map, or one of the wrong length, is IO and touches nothing.
    let mut w = Writer::new();
    p::write_from(&head(h, 10, 0, 0, 0), &[], &mut w).unwrap();
    let reply = rig.server.handle(&mut rig.fs, OWNER, 0, w.as_bytes());
    assert_eq!(p::reply(reply.as_bytes()).map(drop), Err(p::code(p::IO)));
    assert_eq!(rig.stat(OWNER, b"/d/f").unwrap().size, 0);
}

#[test]
fn open_numbered_gives_a_new_file_the_number_the_native_client_names() {
    let mut rig = volume();
    let ino = p::INO_NUMBERED | 77;
    let flags = p::WRITE | p::CREATE | p::EXCLUSIVE;
    let open = |rig: &mut Rig, who: u64, flags: u32, ino: u64, path: &[u8]| {
        rig.call(who, |w| p::open_numbered(path, flags, 0o644, ino, w))
    };
    // A POSIX client is refused, whatever the number.
    assert_eq!(
        open(&mut rig, OWNER, flags, ino, b"/n"),
        Err(p::code(p::PERMISSION))
    );
    // The native client makes the file, and stat says the number; the reply is that of OPEN.
    let reply = open(&mut rig, ROOT, flags, ino, b"/n").unwrap();
    assert_eq!(reply.len(), 8);
    assert_eq!(rig.stat(ROOT, b"/n").unwrap().ino, ino);
    // The same name again is EXISTS; an existing file is not opened by number; bad numbers and
    // flags are INVALID.
    assert_eq!(
        open(&mut rig, ROOT, flags, ino, b"/n"),
        Err(p::code(p::EXISTS))
    );
    for (flags, ino) in [
        (p::READ, ino),
        (p::WRITE | p::CREATE, ino),
        (flags, 77),
        (flags, p::INO_NUMBERED | p::INO_PATH | 5),
    ] {
        assert_eq!(
            open(&mut rig, ROOT, flags, ino, b"/m"),
            Err(p::code(p::INVALID)),
            "{flags} {ino:#x}"
        );
    }
    assert!(rig.stat(ROOT, b"/m").is_err());
    // The counter of the volume is untouched by a named number: the next file gets the next of it.
    let a = rig.open(ROOT, b"/a", p::WRITE | p::CREATE, 0o644).unwrap();
    rig.close(ROOT, a);
    assert!(rig.stat(ROOT, b"/a").unwrap().ino < p::INO_NUMBERED);
}

#[test]
fn the_requests_that_need_blocks_include_the_parts_that_write_and_open_numbered() {
    use crate::server::needs_blocks;
    let mut w = Writer::new();
    p::write_from(&head(1, 0, 0, 0, 0), &[], &mut w).unwrap();
    assert!(needs_blocks(w.as_bytes()));
    let mut w = Writer::new();
    p::pwrite_from(&head(1, 0, 0, 0, 0), &[], &mut w).unwrap();
    assert!(needs_blocks(w.as_bytes()));
    let mut w = Writer::new();
    p::open_numbered(
        b"/x",
        p::WRITE | p::CREATE | p::EXCLUSIVE,
        0,
        p::INO_NUMBERED,
        &mut w,
    )
    .unwrap();
    assert!(needs_blocks(w.as_bytes()));
    let mut w = Writer::new();
    p::read_into(&head(1, 0, 0, 0, 0), &mut w).unwrap();
    assert!(!needs_blocks(w.as_bytes()));
    let _ = Reader::new(&[]);
}

#[test]
fn part_of_tells_the_worker_the_cell_and_the_count() {
    use crate::server::part_of;
    let mut w = Writer::new();
    p::pread_into(&head(3, 4096, 7, 1, 0), &mut w).unwrap();
    assert_eq!(part_of(w.as_bytes()), Some((Method::PreadInto, 1, 4096)));
    let mut w = Writer::new();
    p::write_from(&head(3, 2, 0, p::INLINE, 0), b"ab", &mut w).unwrap();
    assert_eq!(
        part_of(w.as_bytes()),
        Some((Method::WriteFrom, p::INLINE, 2))
    );
    // A part of a wrong shape, and any other request, are none.
    let mut w = Writer::new();
    p::read_into(&head(3, p::CELL_BYTES + 1, 0, 0, 0), &mut w).unwrap();
    assert_eq!(part_of(w.as_bytes()), None);
    let mut w = Writer::new();
    p::read(3, 4, &mut w).unwrap();
    assert_eq!(part_of(w.as_bytes()), None);
}
