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

pub(crate) fn pattern(from: usize, len: usize) -> Vec<u8> {
    (from..from + len).map(byte).collect()
}

pub(crate) fn head(handle: u32, count: usize, offset: u64, cell: u32, flags: u32) -> p::Part {
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
pub(crate) struct Reply {
    pub count: u32,
    pub flags: u32,
    pub lease: u32,
    pub bytes: Vec<u8>,
}

impl Rig {
    /// The window of the session: it has one from here on (the worker holds the handle).
    pub(crate) fn window(&mut self, who: u64) {
        self.server.set_window(who, true).unwrap();
    }

    /// One part: `data` are the bytes of a write (from the cell or the message), `cell` the cell
    /// memory of the test; the reply or the status.
    pub(crate) fn part(
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
pub(crate) fn volume() -> Rig {
    let mut rig = Rig::new();
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig
}

pub(crate) fn cells() -> [Vec<u8>; 2] {
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
    let mut lease = 0;
    while at < total {
        let n = (total - at).min(p::CELL_BYTES);
        let more = if at + n < total { p::MORE } else { 0 };
        let mut part = head(h, n, 0, which, more);
        part.lease = lease;
        let r = rig
            .part(OWNER, Method::WriteFrom, part, &all[at..at + n], &mut c)
            .unwrap();
        // The first part takes a lease, the next ones carry it, the last one ends it.
        assert_eq!((r.count as usize, r.flags), (n, 0));
        assert_eq!(r.lease != 0, more != 0);
        lease = r.lease;
        at += n;
        which ^= 1;
    }
    assert_eq!(rig.server.lease_count(), 0);
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
fn a_lease_number_never_given_is_bad_handle_and_the_shape_of_a_part_is_checked() {
    let mut rig = volume();
    rig.window(OWNER);
    let mut c = cells();
    let h = rig
        .open(OWNER, b"/d/f", p::READ | p::WRITE | p::CREATE, 0o644)
        .unwrap();
    // A lease number the service never gave.
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
        (flags, 0),
        (flags, p::INO_NUMBERED | p::INO_PATH | 5),
        (flags, p::INO_PATH | 5),
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
fn open_numbered_and_mkdir_numbered_take_the_number_of_a_lower_file() {
    let mut rig = volume();
    let flags = p::WRITE | p::CREATE | p::EXCLUSIVE;
    // The numbers of the RAM file service (bits 62 and 63 clear): a place plus one, a generation.
    let lower_file = (3u64 << 32) | 17;
    let lower_dir = (1u64 << 32) | 4;
    rig.call(ROOT, |w| {
        p::open_numbered(b"/nf", flags, 0o600, lower_file, w)
    })
    .unwrap();
    assert_eq!(rig.stat(ROOT, b"/nf").unwrap().ino, lower_file);
    // A directory takes a number the same way, and `.` of its listing says it.
    rig.call(ROOT, |w| p::mkdir_numbered(b"/nd", 0o755, lower_dir, w))
        .unwrap();
    let stat = rig.stat(ROOT, b"/nd").unwrap();
    assert_eq!((stat.ino, stat.kind), (lower_dir, p::KIND_DIRECTORY));
    // Numbers are stored and never compared: two files may carry one number, and the lease and
    // the tail of each go by its node and its path.
    rig.call(ROOT, |w| {
        p::open_numbered(b"/ng", flags, 0o600, lower_file, w)
    })
    .unwrap();
    rig.call(ROOT, |w| p::mkdir_numbered(b"/ne", 0o755, lower_file, w))
        .unwrap();
    assert_eq!(rig.stat(ROOT, b"/ng").unwrap().ino, lower_file);
    assert_eq!(rig.stat(ROOT, b"/ne").unwrap().ino, lower_file);
    // The counter of layerd (bit 62) is still taken, and a POSIX client is refused.
    rig.call(ROOT, |w| {
        p::mkdir_numbered(b"/nc", 0o755, p::INO_NUMBERED | 9, w)
    })
    .unwrap();
    assert_eq!(rig.stat(ROOT, b"/nc").unwrap().ino, p::INO_NUMBERED | 9);
    assert_eq!(
        rig.call(OWNER, |w| p::mkdir_numbered(b"/nx", 0o755, lower_dir, w)),
        Err(p::code(p::PERMISSION))
    );
    assert!(rig.stat(ROOT, b"/nx").is_err());
    // Bad numbers and modes are INVALID, and the name is EXISTS the second time.
    for (mode, ino) in [(0o755, 0), (0o755, p::INO_PATH | 5), (0o10000, 5)] {
        assert_eq!(
            rig.call(ROOT, |w| p::mkdir_numbered(b"/ny", mode, ino, w)),
            Err(p::code(p::INVALID)),
            "{mode:o} {ino:#x}"
        );
    }
    assert_eq!(
        rig.call(ROOT, |w| p::mkdir_numbered(b"/nd", 0o755, 5, w)),
        Err(p::code(p::EXISTS))
    );
    // The counter of the volume is untouched by named numbers.
    let a = rig.open(ROOT, b"/na", p::WRITE | p::CREATE, 0o644).unwrap();
    rig.close(ROOT, a);
    assert!(rig.stat(ROOT, b"/na").unwrap().ino < p::INO_NUMBERED);
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
    p::mkdir_numbered(b"/x", 0o755, p::INO_NUMBERED, &mut w).unwrap();
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

/// The entries of a directory description as READDIR_ATTR gives them, batch after batch: (name,
/// kind, ino, mode, uid, gid).
type Listed = Vec<(Vec<u8>, u32, u64, u32, u32, u32)>;

fn listed_with_attributes(rig: &mut Rig, dir: u32) -> Listed {
    let mut out = Vec::new();
    loop {
        let reply = rig
            .call(ROOT, |w| p::handle_call(Method::ReaddirAttr, dir, w))
            .unwrap();
        let more = u32::from_le_bytes(reply[..4].try_into().unwrap());
        let body = &reply[4..];
        let mut at = 0;
        while let Some((e, next)) = p::dir_attr_entry(body, at) {
            out.push((e.name.to_vec(), e.kind, e.ino, e.mode, e.uid, e.gid));
            at = next;
        }
        assert_eq!(at, body.len(), "every byte of the batch is an entry");
        if more == 0 {
            return out;
        }
        assert!(!body.is_empty(), "a batch with more carries an entry");
    }
}

#[test]
fn readdir_attr_gives_each_entry_what_stat_gives_without_the_dots_and_to_a_native_client_only() {
    let mut rig = volume();
    // More entries than a batch holds, files and directories, owners and modes of every kind.
    let mut names = Vec::new();
    for i in 0..120 {
        let name = std::format!("/d/entry-{i:03}-{}", "n".repeat(60));
        if i % 7 == 0 {
            rig.mkdir(ROOT, name.as_bytes(), 0o750).unwrap();
        } else {
            let h = rig
                .open(ROOT, name.as_bytes(), p::WRITE | p::CREATE, 0o640)
                .unwrap();
            rig.close(ROOT, h);
        }
        if i % 3 == 0 {
            rig.chown(ROOT, name.as_bytes(), 1000 + i, 100 + i).unwrap();
        }
        if i % 5 == 0 {
            rig.chmod(ROOT, name.as_bytes(), 0o4755).unwrap();
        }
        names.push(name);
    }
    let dir = rig.open(ROOT, b"/d", p::DIRECTORY | p::READ, 0).unwrap();
    let got = listed_with_attributes(&mut rig, dir);
    assert_eq!(got.len(), names.len(), "no `.` and `..`");
    for (name, kind, ino, mode, uid, gid) in &got {
        assert!(name != b"." && name != b"..");
        let stat = rig.stat(ROOT, &[b"/d/".as_slice(), name].concat()).unwrap();
        assert_eq!(
            (*kind, *ino, *mode, *uid, *gid),
            (stat.kind, stat.ino, stat.mode, stat.uid, stat.gid),
            "{}",
            String::from_utf8_lossy(name)
        );
    }
    // The same names as READDIR gives after the two dots.
    rig.call(ROOT, |w| p::handle_call(Method::Rewind, dir, w))
        .unwrap();
    let mut plain = Vec::new();
    loop {
        let reply = rig
            .call(ROOT, |w| p::handle_call(Method::Readdir, dir, w))
            .unwrap();
        let mut entries = p::read_dir_reply(Reader::new(&reply)).unwrap();
        while let Some(e) = entries.next_entry().unwrap() {
            if e.name != b"." && e.name != b".." {
                plain.push(e.name.to_vec());
            }
        }
        if !entries.more {
            break;
        }
    }
    assert_eq!(
        got.iter().map(|e| e.0.clone()).collect::<Vec<_>>(),
        plain,
        "the order of the directory"
    );
    // The two methods go on from one another on one description.
    rig.call(ROOT, |w| p::handle_call(Method::Rewind, dir, w))
        .unwrap();
    let first = rig
        .call(ROOT, |w| p::handle_call(Method::Readdir, dir, w))
        .unwrap();
    let mut entries = p::read_dir_reply(Reader::new(&first)).unwrap();
    let mut taken = 0;
    while entries.next_entry().unwrap().is_some() {
        taken += 1;
    }
    assert!(entries.more && taken > 2);
    let rest = listed_with_attributes(&mut rig, dir);
    assert_eq!(
        rest.len(),
        names.len() + 2 - taken,
        "`.` and `..` were in the first batch"
    );
    rig.close(ROOT, dir);
    // A session of a program is refused, and a file description is not a directory.
    let dir = rig.open(OWNER, b"/d", p::DIRECTORY | p::READ, 0).unwrap();
    assert_eq!(
        rig.call(OWNER, |w| p::handle_call(Method::ReaddirAttr, dir, w)),
        Err(p::code(p::PERMISSION))
    );
    let file = rig
        .open(ROOT, &names[1].clone().into_bytes(), p::READ, 0)
        .unwrap();
    assert_eq!(
        rig.call(ROOT, |w| p::handle_call(Method::ReaddirAttr, file, w)),
        Err(p::code(p::BAD_HANDLE))
    );
}
