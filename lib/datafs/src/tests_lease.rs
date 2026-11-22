// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The leases of version 4 on the server over the device in memory: what a lease holds back, the
//! order in which `Server::pick` serves the jobs, the lapse, RELEASE, the numbers, the limits, the
//! end of a call (`SYNC`, a limit, a failure), and the end of the session.

use crate::server::{Candidate, LEASE_GAP_NS};
use crate::tests_perm::{ROOT, Rig, user};
use crate::tests_window::{Reply, cells, head, pattern, volume};
use proto_data as p;
use proto_data::Method;
use proto_wire::{Status, Writer};
use std::vec::Vec;

const A: u64 = 11;
const B: u64 = 12;
const C: u64 = 13;

/// A volume with `/d/f` of 300,000 bytes and the sessions A, B, C (each with a window and its own
/// user), and a handle of A, B and C on it (read and write).
struct Fx {
    rig: Rig,
    c: [Vec<u8>; 2],
    ha: u32,
    hb: u32,
    hc: u32,
}

fn fx() -> Fx {
    let mut rig = volume();
    // The sessions of the rig are bound already: OWNER, GROUP and OTHER.
    for label in [A, B, C] {
        rig.window(label);
    }
    let mut c = cells();
    let h = rig
        .open(A, b"/d/f", p::READ | p::WRITE | p::CREATE, 0o666)
        .unwrap();
    let mut at = 0;
    let all = pattern(0, 300_000);
    let mut lease = 0;
    while at < all.len() {
        let n = (all.len() - at).min(p::CELL_BYTES);
        let more = if at + n < all.len() { p::MORE } else { 0 };
        let mut part = head(h, n, 0, 0, more);
        part.lease = lease;
        lease = rig
            .part(A, Method::WriteFrom, part, &all[at..at + n], &mut c)
            .unwrap()
            .lease;
        at += n;
    }
    let ha = h;
    let hb = rig.open(B, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    let hc = rig.open(C, b"/d/f", p::READ | p::WRITE, 0).unwrap();
    rig.mkdir(ROOT, b"/e", 0o777).unwrap();
    Fx { rig, c, ha, hb, hc }
}

impl Fx {
    /// A part of `who` on handle `h`: `lease` and `more` as the call carries them.
    fn part(
        &mut self,
        who: u64,
        method: Method,
        h: u32,
        count: usize,
        lease: u32,
        more: bool,
    ) -> Result<Reply, Status> {
        let mut part = head(h, count, 0, 0, if more { p::MORE } else { 0 });
        part.lease = lease;
        let data = vec![7u8; count];
        self.rig.part(who, method, part, &data, &mut self.c)
    }

    /// The first part of a write call that goes on: the lease number.
    fn write_lease(&mut self, who: u64, h: u32) -> u32 {
        let r = self.part(who, Method::PwriteFrom, h, 100, 0, true).unwrap();
        assert!(r.lease != 0 && r.flags == 0, "{r:?}");
        r.lease
    }

    fn read_lease(&mut self, who: u64, h: u32) -> u32 {
        let r = self.part(who, Method::PreadInto, h, 100, 0, true).unwrap();
        assert!(r.lease != 0 && r.flags == 0, "{r:?}");
        r.lease
    }
}

/// The bytes of a request.
fn req(build: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
    let mut w = Writer::new();
    build(&mut w).unwrap();
    w.as_bytes().to_vec()
}

/// The job picked among `(owner, request)` queued in this order (tickets 1, 2, ...): its index.
fn pick(rig: &Rig, jobs: &[(u64, Vec<u8>)]) -> Option<usize> {
    let cands: Vec<Candidate<'_>> = jobs
        .iter()
        .enumerate()
        .map(|(i, (owner, request))| Candidate {
            id: i,
            ticket: i as u64 + 1,
            owner: *owner,
            request,
        })
        .collect();
    rig.server.pick(&cands)
}

fn read_job(h: u32) -> Vec<u8> {
    req(|w| p::read(h, 10, w))
}
fn pread_job(h: u32) -> Vec<u8> {
    req(|w| p::pread(h, 10, 0, w))
}
fn write_job(h: u32) -> Vec<u8> {
    req(|w| p::write(h, b"x", w))
}
fn pwrite_job(h: u32) -> Vec<u8> {
    req(|w| p::pwrite(h, 0, b"x", w))
}
fn truncate_job(h: u32) -> Vec<u8> {
    req(|w| p::truncate(h, 10, w))
}
fn fstat_job(h: u32) -> Vec<u8> {
    req(|w| p::handle_call(Method::Fstat, h, w))
}
fn stat_job() -> Vec<u8> {
    req(|w| p::path_call(Method::Stat, b"/d/f", w))
}
fn open_trunc_job() -> Vec<u8> {
    req(|w| p::open(b"/d/f", p::WRITE | p::TRUNCATE, 0, w))
}
fn part_job(method: Method, h: u32, lease: u32, more: bool) -> Vec<u8> {
    let mut part = head(h, 100, 0, 0, if more { p::MORE } else { 0 });
    part.lease = lease;
    req(|w| match method {
        Method::ReadInto => p::read_into(&part, w),
        Method::PreadInto => p::pread_into(&part, w),
        Method::WriteFrom => p::write_from(&part, &[], w),
        _ => p::pwrite_from(&part, &[], w),
    })
}

#[test]
fn a_call_in_parts_takes_a_lease_on_its_first_part_and_ends_it_with_its_last() {
    let mut fx = fx();
    assert_eq!(fx.rig.server.lease_count(), 0);
    let lease = fx.write_lease(A, fx.ha);
    assert_eq!(fx.rig.server.lease_count(), 1);
    let r = fx
        .part(A, Method::PwriteFrom, fx.ha, 50, lease, true)
        .unwrap();
    assert_eq!(
        (r.lease, r.flags),
        (lease, 0),
        "a part that goes on keeps the number"
    );
    let r = fx
        .part(A, Method::PwriteFrom, fx.ha, 50, lease, false)
        .unwrap();
    assert_eq!(
        (r.lease, r.flags, r.count),
        (0, 0, 50),
        "the last part ends it"
    );
    assert_eq!(fx.rig.server.lease_count(), 0);
    // A call of one part (no MORE, lease 0) takes none.
    let r = fx.part(A, Method::PwriteFrom, fx.ha, 50, 0, false).unwrap();
    assert_eq!((r.lease, r.flags), (0, 0));
    assert_eq!(fx.rig.server.lease_count(), 0);
}

#[test]
fn a_write_lease_holds_back_every_other_call_on_the_file_and_nothing_else() {
    let mut fx = fx();
    let lease = fx.write_lease(A, fx.ha);
    for (name, job) in [
        ("read", read_job(fx.hb)),
        ("pread", pread_job(fx.hb)),
        ("write", write_job(fx.hb)),
        ("pwrite", pwrite_job(fx.hb)),
        ("truncate", truncate_job(fx.hb)),
        ("fstat", fstat_job(fx.hb)),
        ("stat by path", stat_job()),
        ("open with truncation", open_trunc_job()),
        ("read part", part_job(Method::ReadInto, fx.hb, 0, false)),
        ("write part", part_job(Method::WriteFrom, fx.hb, 0, false)),
        ("lease taker", part_job(Method::PreadInto, fx.hb, 0, true)),
    ] {
        assert_eq!(
            pick(&fx.rig, &[(B, job)]),
            None,
            "{name} of another session"
        );
    }
    // Another call of the same session waits as well: the lease belongs to one call.
    let own = part_job(Method::PreadInto, fx.ha, 0, false);
    assert_eq!(pick(&fx.rig, &[(A, own)]), None);
    // The holder's part runs, and so do jobs on other files and jobs that name no file.
    let mine = part_job(Method::PwriteFrom, fx.ha, lease, true);
    assert_eq!(pick(&fx.rig, &[(A, mine)]), Some(0));
    let other = req(|w| p::path_call(Method::Stat, b"/e", w));
    assert_eq!(pick(&fx.rig, &[(B, other)]), Some(0));
    let statfs = req(p::statfs);
    assert_eq!(pick(&fx.rig, &[(B, statfs)]), Some(0));
    // The job on the other file is served though the jobs on this one came first.
    let jobs = [
        (B, read_job(fx.hb)),
        (C, write_job(fx.hc)),
        (B, req(|w| p::path_call(Method::Stat, b"/e", w))),
    ];
    assert_eq!(pick(&fx.rig, &jobs), Some(2));
    // The call ends, and the oldest job that waited goes first.
    fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, false)
        .unwrap();
    assert_eq!(pick(&fx.rig, &jobs), Some(0));
}

#[test]
fn a_read_lease_holds_back_writes_and_truncations_and_lets_reads_go() {
    let mut fx = fx();
    let lease = fx.read_lease(A, fx.ha);
    for (name, job) in [
        ("write", write_job(fx.hb)),
        ("pwrite", pwrite_job(fx.hb)),
        ("truncate", truncate_job(fx.hb)),
        ("open with truncation", open_trunc_job()),
        ("write part", part_job(Method::WriteFrom, fx.hb, 0, false)),
        (
            "write lease taker",
            part_job(Method::PwriteFrom, fx.hb, 0, true),
        ),
    ] {
        assert_eq!(pick(&fx.rig, &[(B, job)]), None, "{name}");
    }
    for (name, job) in [
        ("read", read_job(fx.hb)),
        ("pread", pread_job(fx.hb)),
        ("fstat", fstat_job(fx.hb)),
        ("stat", stat_job()),
        ("read part", part_job(Method::ReadInto, fx.hb, 0, false)),
        (
            "read lease taker",
            part_job(Method::PreadInto, fx.hb, 0, true),
        ),
    ] {
        assert_eq!(pick(&fx.rig, &[(B, job)]), Some(0), "{name}");
    }
    // Two readers hold leases together, and a write waits for both.
    let second = fx.read_lease(B, fx.hb);
    assert_eq!(fx.rig.server.lease_count(), 2);
    let job = [(C, write_job(fx.hc))];
    assert_eq!(pick(&fx.rig, &job), None);
    fx.part(A, Method::PreadInto, fx.ha, 10, lease, false)
        .unwrap();
    assert_eq!(pick(&fx.rig, &job), None, "one read lease is left");
    fx.part(B, Method::PreadInto, fx.hb, 10, second, false)
        .unwrap();
    assert_eq!(pick(&fx.rig, &job), Some(0));
}

#[test]
fn the_part_of_a_holder_takes_the_place_of_the_oldest_job_that_waits_for_the_file() {
    let mut fx = fx();
    let lease = fx.write_lease(A, fx.ha);
    // Queue: a read of the file waits (ticket 1), a job on another file (2), the holder's next part (3).
    let jobs = [
        (B, read_job(fx.hb)),
        (C, req(|w| p::path_call(Method::Stat, b"/e", w))),
        (A, part_job(Method::PwriteFrom, fx.ha, lease, true)),
    ];
    // Without the place of the waiting job the other file's job (2) would go first; the holder goes at
    // the place of the waiting one (1), so the call does not queue behind those who wait for it.
    assert_eq!(pick(&fx.rig, &jobs), Some(2));
    // With no job waiting for the file the holder keeps its own place.
    let jobs = [
        (C, req(|w| p::path_call(Method::Stat, b"/e", w))),
        (A, part_job(Method::PwriteFrom, fx.ha, lease, true)),
    ];
    assert_eq!(pick(&fx.rig, &jobs), Some(0));
}

#[test]
fn a_new_read_lease_waits_behind_a_writer_that_waits() {
    let mut fx = fx();
    let lease = fx.read_lease(A, fx.ha);
    // B's write waits for A's read lease (ticket 1); C asks for a new read lease (2), and a plain read
    // of C (3) goes on, as do reads of other calls.
    let jobs = [
        (B, write_job(fx.hb)),
        (C, part_job(Method::ReadInto, fx.hc, 0, true)),
        (C, read_job(fx.hc)),
    ];
    assert_eq!(
        pick(&fx.rig, &jobs),
        Some(2),
        "the new read lease waits, the plain read goes"
    );
    assert_eq!(pick(&fx.rig, &jobs[..2]), None);
    // The writer is served when the lease ends, then the reader.
    fx.part(A, Method::PreadInto, fx.ha, 10, lease, false)
        .unwrap();
    assert_eq!(pick(&fx.rig, &jobs), Some(0));
    // A reader that came before the writer is not held behind it.
    let early = [
        (C, part_job(Method::ReadInto, fx.hc, 0, true)),
        (B, write_job(fx.hb)),
    ];
    assert_eq!(pick(&fx.rig, &early), Some(0));
}

#[test]
fn a_lease_lapses_after_a_gap_and_a_late_part_runs_alone_with_lapsed() {
    let mut fx = fx();
    fx.rig.server.set_mono(1_000);
    let lease = fx.write_lease(A, fx.ha);
    let expires = fx.rig.server.next_lease_expiry().unwrap();
    assert_eq!(expires, 1_000 + LEASE_GAP_NS);
    // A part renews it for another gap.
    fx.rig.server.set_mono(500_000_000);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
        .unwrap();
    assert_eq!(
        fx.rig.server.next_lease_expiry(),
        Some(500_000_000 + LEASE_GAP_NS)
    );
    // B's read waits until the gap is over, and goes when the lease has lapsed.
    let job = [(B, read_job(fx.hb))];
    fx.rig.server.set_mono(500_000_000 + LEASE_GAP_NS - 1);
    fx.rig.server.leases_sweep(&mut fx.rig.fs);
    assert_eq!(pick(&fx.rig, &job), None);
    fx.rig.server.set_mono(500_000_000 + LEASE_GAP_NS);
    fx.rig.server.leases_sweep(&mut fx.rig.fs);
    assert_eq!(fx.rig.server.lease_count(), 0);
    assert_eq!(pick(&fx.rig, &job), Some(0));
    // The late part runs as a call of its own: it is written, the answer says LAPSED and has no lease.
    let before = fx.rig.stat(A, b"/d/f").unwrap().size;
    let r = fx
        .part(A, Method::PwriteFrom, fx.ha, 20, lease, true)
        .unwrap();
    assert_eq!((r.count, r.flags, r.lease), (20, p::LAPSED, 0));
    assert_eq!(fx.rig.stat(A, b"/d/f").unwrap().size, before);
    assert_eq!(fx.rig.server.lease_count(), 0);
    // It takes no lease and holds nothing back, whatever MORE says.
    assert_eq!(pick(&fx.rig, &job), Some(0));
}

#[test]
fn a_part_that_runs_alone_after_a_lapse_with_append_takes_the_end_again() {
    let mut fx = fx();
    let ha = fx
        .rig
        .open(A, b"/d/f", p::READ | p::WRITE | p::APPEND, 0)
        .unwrap();
    fx.rig.server.set_mono(0);
    let first = fx.part(A, Method::WriteFrom, ha, 100, 0, true).unwrap();
    let lease = first.lease;
    assert!(lease != 0);
    // Another writer appends after the lapse; the late part goes after it and over nothing.
    fx.rig.server.set_mono(LEASE_GAP_NS);
    fx.rig.server.leases_sweep(&mut fx.rig.fs);
    let hb = fx.rig.open(B, b"/d/f", p::WRITE | p::APPEND, 0).unwrap();
    let size = fx.rig.stat(A, b"/d/f").unwrap().size;
    fx.part(B, Method::WriteFrom, hb, 30, 0, false).unwrap();
    let r = fx.part(A, Method::WriteFrom, ha, 50, lease, false).unwrap();
    assert_eq!(r.flags, p::LAPSED);
    assert_eq!(fx.rig.stat(A, b"/d/f").unwrap().size, size + 80);
}

#[test]
fn release_ends_a_lease_and_answers_for_a_number_that_is_over_or_never_was() {
    let mut fx = fx();
    let lease = fx.write_lease(A, fx.ha);
    // Another session cannot release it.
    assert_eq!(
        fx.rig.call(B, |w| p::release(lease, w)),
        Err(p::code(p::BAD_HANDLE))
    );
    assert_eq!(fx.rig.server.lease_count(), 1);
    fx.rig.ok(A, |w| p::release(lease, w));
    assert_eq!(fx.rig.server.lease_count(), 0);
    // Again: the lease is over, and nothing changes.
    fx.rig.ok(A, |w| p::release(lease, w));
    // A number never given (this instance's epoch, a slot and a generation that did not exist).
    let never = (lease & 0xFFFF_0000) | 0x0500 | 40;
    assert_eq!(
        fx.rig.call(A, |w| p::release(never, w)),
        Err(p::code(p::BAD_HANDLE))
    );
    assert_eq!(
        fx.rig.call(A, |w| p::release(5, w)),
        Err(p::code(p::BAD_HANDLE)),
        "no epoch"
    );
    // A number of an earlier instance.
    let other_epoch = ((lease >> 16) + 1) << 16 | (lease & 0xFFFF);
    assert_eq!(
        fx.rig.call(A, |w| p::release(other_epoch, w)),
        Err(p::code(p::STALE))
    );
    // A part with such numbers: BAD_HANDLE and STALE, and no lease is touched.
    let r = fx.part(A, Method::PwriteFrom, fx.ha, 10, never, true);
    assert_eq!(r.map(drop), Err(p::code(p::BAD_HANDLE)));
    let r = fx.part(A, Method::PwriteFrom, fx.ha, 10, other_epoch, true);
    assert_eq!(r.map(drop), Err(p::code(p::STALE)));
}

#[test]
fn a_number_that_ended_is_not_taken_for_the_next_lease_of_its_slot() {
    let mut fx = fx();
    let one = fx.write_lease(A, fx.ha);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, one, false)
        .unwrap();
    let two = fx.write_lease(A, fx.ha);
    assert_ne!(one, two, "the generation moved");
    assert_eq!(one & 0xFF, two & 0xFF, "the slot is the same");
    // The old number names an ended lease: LAPSED, and the new lease is not touched.
    let r = fx
        .part(A, Method::PwriteFrom, fx.ha, 10, one, false)
        .unwrap();
    assert_eq!((r.flags, r.lease), (p::LAPSED, 0));
    assert_eq!(fx.rig.server.lease_count(), 1);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, two, false)
        .unwrap();
    assert_eq!(fx.rig.server.lease_count(), 0);
}

#[test]
fn a_session_has_four_leases_and_the_service_sixty_four_and_the_rest_run_unleased() {
    let mut fx = fx();
    // Four read leases of A, on four calls of one description; the fifth call is UNLEASED.
    let mut leases = Vec::new();
    for _ in 0..p::LEASES_PER_SESSION {
        leases.push(fx.read_lease(A, fx.ha));
    }
    let r = fx.part(A, Method::PreadInto, fx.ha, 10, 0, true).unwrap();
    assert_eq!((r.flags, r.lease), (p::UNLEASED, 0));
    assert_eq!(fx.rig.server.lease_count(), 4);
    // It took no lease and holds nothing back: a write still waits for the four, a read goes.
    assert_eq!(pick(&fx.rig, &[(B, read_job(fx.hb))]), Some(0));
    for l in leases {
        fx.part(A, Method::PreadInto, fx.ha, 10, l, false).unwrap();
    }
    assert_eq!(fx.rig.server.lease_count(), 0);
    // Sixteen sessions with four each fill the service's 64; the next one is UNLEASED.
    let mut sessions = Vec::new();
    for i in 0..16u64 {
        let label = 100 + i;
        fx.rig.bind(label, user(3000 + i as u32, 100, &[]));
        fx.rig.window(label);
        let h = fx.rig.open(label, b"/d/f", p::READ, 0).unwrap();
        for _ in 0..p::LEASES_PER_SESSION {
            let r = fx.part(label, Method::PreadInto, h, 10, 0, true).unwrap();
            assert!(r.lease != 0, "session {i}");
        }
        sessions.push((label, h));
    }
    assert_eq!(fx.rig.server.lease_count(), p::LEASES);
    let r = fx.part(B, Method::PreadInto, fx.hb, 10, 0, true).unwrap();
    assert_eq!((r.flags, r.lease), (p::UNLEASED, 0));
    // A session that goes gives its leases back.
    fx.rig.server.gone(&mut fx.rig.fs, sessions[0].0);
    assert_eq!(fx.rig.server.lease_count(), p::LEASES - 4);
    let r = fx.part(B, Method::PreadInto, fx.hb, 10, 0, true).unwrap();
    assert!(r.lease != 0);
}

#[test]
fn a_close_in_the_middle_of_a_call_does_not_end_it() {
    let mut fx = fx();
    let before = fx.rig.server.open_count();
    let lease = fx.write_lease(A, fx.ha);
    fx.rig.close(A, fx.ha);
    // The description stays while the lease holds a reference to it, and the call goes on.
    assert_eq!(fx.rig.server.open_count(), before);
    let r = fx
        .part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
        .unwrap();
    assert_eq!(r.lease, lease);
    let r = fx
        .part(A, Method::PwriteFrom, fx.ha, 10, lease, false)
        .unwrap();
    assert_eq!(r.lease, 0);
    // It goes with the end of the call.
    assert_eq!(fx.rig.server.open_count(), before - 1);
    // A new call on the closed description is refused.
    assert!(fx.part(A, Method::PwriteFrom, fx.ha, 10, 0, false).is_err());
}

#[test]
fn a_call_ends_at_a_limit_at_the_end_of_the_file_and_at_a_failure() {
    let mut fx = fx();
    // A read part that the end of the file stopped short ends the call.
    let ha = fx.rig.open(A, b"/d/f", p::READ, 0).unwrap();
    let mut part = head(ha, 1000, 299_500, 0, p::MORE);
    part.lease = 0;
    let r = fx
        .rig
        .part(A, Method::PreadInto, part, &[], &mut fx.c)
        .unwrap();
    assert_eq!((r.count, r.lease), (500, 0));
    assert_eq!(fx.rig.server.lease_count(), 0);
    // A write that a file size limit stopped short ends it too.
    let mut limited = user(1500, 100, &[]);
    limited.fsize_limit = 300_100;
    fx.rig.bind(50, limited);
    fx.rig.window(50);
    let h = fx.rig.open(50, b"/d/f", p::WRITE | p::APPEND, 0);
    // The file is 0666 in /d (0777): the limited user may write it.
    let h = h.unwrap();
    let r = fx.part(50, Method::WriteFrom, h, 1000, 0, true).unwrap();
    assert_eq!((r.count, r.lease), (100, 0));
    assert_eq!(fx.rig.server.lease_count(), 0);
    // A part that fails (a cell of the wrong length) ends the lease it ran under.
    let lease = fx.write_lease(B, fx.hb);
    let mut bad = head(fx.hb, 10, 0, 0, p::MORE);
    bad.lease = lease;
    let mut w = Writer::new();
    p::pwrite_from(&bad, &[], &mut w).unwrap();
    let reply = fx.rig.server.handle(&mut fx.rig.fs, B, 0, w.as_bytes());
    assert_eq!(p::reply(reply.as_bytes()).map(drop), Err(p::code(p::IO)));
    assert_eq!(fx.rig.server.lease_count(), 0);
}

#[test]
fn a_description_with_sync_is_made_durable_after_the_part_that_ends_the_call() {
    let mut fx = fx();
    let h = fx.rig.open(B, b"/d/f", p::WRITE | p::SYNC, 0).unwrap();
    let flushes = |fx: &mut Fx| fx.rig.fs.device().flushes;
    let before = flushes(&mut fx);
    let lease = fx
        .part(B, Method::PwriteFrom, h, 5000, 0, true)
        .unwrap()
        .lease;
    let r = fx
        .part(B, Method::PwriteFrom, h, 5000, lease, true)
        .unwrap();
    assert_eq!(
        flushes(&mut fx),
        before,
        "a part that goes on is not synced"
    );
    assert_eq!(r.lease, lease);
    fx.part(B, Method::PwriteFrom, h, 5000, lease, false)
        .unwrap();
    assert!(flushes(&mut fx) > before, "the last part is");
    // A call of one part is synced as a write is.
    let again = flushes(&mut fx);
    fx.part(B, Method::PwriteFrom, h, 100, 0, false).unwrap();
    assert!(flushes(&mut fx) > again);
}

#[test]
fn two_append_calls_do_not_mix() {
    let mut fx = fx();
    let ha = fx.rig.open(A, b"/d/f", p::WRITE | p::APPEND, 0).unwrap();
    let hb = fx.rig.open(B, b"/d/f", p::WRITE | p::APPEND, 0).unwrap();
    let start = fx.rig.stat(A, b"/d/f").unwrap().size;
    let mut ca = cells();
    let mut part = head(ha, 1000, 0, 0, p::MORE);
    let first = fx
        .rig
        .part(A, Method::WriteFrom, part, &[b'a'; 1000], &mut ca)
        .unwrap();
    // B's append waits (the picker holds it back) and A's next part runs.
    let job = [(B, part_job(Method::WriteFrom, hb, 0, false))];
    assert_eq!(pick(&fx.rig, &job), None);
    part = head(ha, 1000, 0, 0, 0);
    part.lease = first.lease;
    fx.rig
        .part(A, Method::WriteFrom, part, &[b'a'; 1000], &mut ca)
        .unwrap();
    assert_eq!(pick(&fx.rig, &job), Some(0));
    fx.rig
        .part(
            B,
            Method::WriteFrom,
            head(hb, 500, 0, 0, 0),
            &[b'b'; 500],
            &mut ca,
        )
        .unwrap();
    // The file ends with A's 2,000 bytes whole and then B's 500.
    let mut out = cells();
    let h = fx.rig.open(C, b"/d/f", p::READ, 0).unwrap();
    let mut read = head(h, 2500, start, 0, 0);
    read.offset = start;
    let r = fx
        .rig
        .part(C, Method::PreadInto, read, &[], &mut out)
        .unwrap();
    assert_eq!(r.count, 2500);
    assert!(out[0][..2000].iter().all(|&b| b == b'a'));
    assert!(out[0][2000..2500].iter().all(|&b| b == b'b'));
}

#[test]
fn the_end_of_a_session_and_the_stop_end_its_leases() {
    let mut fx = fx();
    let before = fx.rig.server.open_count();
    let _ = fx.write_lease(B, fx.hb);
    let _ = fx.read_lease(C, fx.hc);
    assert_eq!(fx.rig.server.lease_count(), 2);
    // B goes: its lease ends and so does the reference it held.
    fx.rig.server.gone(&mut fx.rig.fs, B);
    assert_eq!(fx.rig.server.lease_count(), 1);
    assert_eq!(fx.rig.server.open_count(), before - 1);
    // The stop ends the rest, so that the jobs that wait run and the volume is put away.
    fx.rig.server.leases_end_all(&mut fx.rig.fs);
    assert_eq!(fx.rig.server.lease_count(), 0);
    assert_eq!(fx.rig.server.next_lease_expiry(), None);
}

#[test]
fn jobs_on_other_files_wait_for_no_lease_however_many_are_held() {
    let mut fx = fx();
    // Every lease the service can give, on the one file; the jobs on /e and the statfs go at once, in
    // the order they came.
    let mut held = Vec::new();
    for i in 0..16u64 {
        let label = 200 + i;
        fx.rig.bind(label, user(4000 + i as u32, 100, &[]));
        fx.rig.window(label);
        let h = fx.rig.open(label, b"/d/f", p::WRITE, 0).unwrap();
        held.push((label, h));
    }
    let lease = fx.write_lease(A, fx.ha);
    assert!(lease != 0);
    let mut jobs: Vec<(u64, Vec<u8>)> = held
        .iter()
        .map(|&(label, h)| (label, write_job(h)))
        .collect();
    jobs.push((B, req(|w| p::path_call(Method::Stat, b"/e", w))));
    jobs.push((B, req(p::statfs)));
    let idx = jobs.len() - 2;
    assert_eq!(pick(&fx.rig, &jobs), Some(idx));
    jobs.remove(idx);
    assert_eq!(pick(&fx.rig, &jobs), Some(jobs.len() - 1));
}
