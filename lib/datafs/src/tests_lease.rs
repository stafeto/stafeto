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
    /// The clock of the worker, in nanoseconds: every part arrives, runs and is answered at it, and the
    /// lease is stamped after it, as the worker does.
    now: u64,
    c: [Vec<u8>; 2],
    ha: u32,
    hb: u32,
    hc: u32,
}

fn fixture() -> Fx {
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
    Fx {
        rig,
        now: 0,
        c,
        ha,
        hb,
        hc,
    }
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
        self.rig.server.set_mono(self.now);
        self.rig.server.set_job_queued(self.now);
        let r = self.rig.part(who, method, part, &data, &mut self.c);
        self.rig.server.leases_stamp(self.now);
        r
    }

    /// The clock moves to `ns`.
    fn at(&mut self, ns: u64) {
        self.now = ns;
        self.rig.server.set_mono(ns);
    }

    /// The leases that lapse by `ns` end, with the jobs `queued` waiting.
    fn sweep(&mut self, ns: u64, queued: &[Candidate<'_>]) {
        self.at(ns);
        self.rig.server.leases_sweep(&mut self.rig.fs, queued);
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
            queued_at: 0,
            request,
        })
        .collect();
    rig.server.pick(&cands).run
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
fn a_lease_lapses_after_a_gap_and_a_late_part_is_not_run() {
    let mut fx = fixture();
    fx.at(1_000);
    let lease = fx.write_lease(A, fx.ha);
    assert_eq!(
        fx.rig.server.next_lease_expiry(),
        Some(1_000 + LEASE_GAP_NS)
    );
    // The gap counts from the answer to the part: a part at 0.5 s renews it for another gap.
    fx.at(500_000_000);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
        .unwrap();
    let expiry = fx.rig.server.next_lease_expiry().unwrap();
    assert!(expiry > 500_000_000 && expiry <= 500_000_000 + LEASE_GAP_NS);
    let job = [(B, read_job(fx.hb))];
    fx.sweep(500_000_000 + LEASE_GAP_NS - 1, &[]);
    assert_eq!(pick(&fx.rig, &job), None);
    fx.sweep(500_000_000 + LEASE_GAP_NS, &[]);
    assert_eq!(fx.rig.server.lease_count(), 0);
    assert_eq!(pick(&fx.rig, &job), Some(0));
    // The late part is not run: nothing is written, the answer says LAPSED and 0 bytes, with MORE
    // or without.
    let size = fx.rig.stat(A, b"/d/f").unwrap().size;
    for more in [true, false] {
        let r = fx
            .part(A, Method::PwriteFrom, fx.ha, 20, lease, more)
            .unwrap();
        assert_eq!((r.count, r.flags, r.lease), (0, p::LAPSED, 0), "{more}");
    }
    let r = fx.part(A, Method::PreadInto, fx.ha, 20, lease, false);
    assert_eq!(
        r.map(|r| (r.count, r.flags)),
        Ok((0, p::LAPSED)),
        "a read part of an ended lease"
    );
    assert_eq!(fx.rig.stat(A, b"/d/f").unwrap().size, size);
    assert_eq!(fx.rig.server.lease_count(), 0);
}

#[test]
fn the_gap_counts_from_the_answer_and_not_from_the_pick() {
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    // A part arrives at 0.8 s and is picked and answered at 0.9 s: the gap after it counts from 0.9 s.
    fx.at(900_000_000);
    fx.rig.server.set_job_queued(800_000_000);
    let mut part = head(fx.ha, 10, 0, 0, p::MORE);
    part.lease = lease;
    fx.rig
        .part(A, Method::PwriteFrom, part, &[7u8; 10], &mut fx.c)
        .unwrap();
    fx.rig.server.leases_stamp(900_000_000);
    // At 1.5 s (0.6 s after the answer) the lease lives; a clock that counted from the pick or from
    // the take would have lapsed it.
    fx.sweep(1_500_000_000, &[]);
    assert_eq!(fx.rig.server.lease_count(), 1);
    fx.sweep(1_900_000_000, &[]);
    assert_eq!(fx.rig.server.lease_count(), 0);
}

#[test]
fn a_lease_whose_next_part_is_queued_in_time_does_not_lapse() {
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    let mine = part_job(Method::PwriteFrom, fx.ha, lease, true);
    let queued = |at: u64| {
        [Candidate {
            id: 0,
            ticket: 1,
            owner: A,
            queued_at: at,
            request: &mine,
        }]
    };
    // The part arrived at 0.9 s and waits behind other files' jobs until 3 s: no lapse.
    fx.sweep(3_000_000_000, &queued(900_000_000));
    assert_eq!(fx.rig.server.lease_count(), 1);
    // A part that arrived at 1.2 s came late: the lease lapsed.
    fx.sweep(3_000_000_000, &queued(1_200_000_000));
    assert_eq!(fx.rig.server.lease_count(), 0);
}

#[test]
fn the_client_time_of_a_lease_is_bounded_while_jobs_wait_for_the_file() {
    let mut fx = fixture();
    // Gaps of 0.3 s between parts, five of them: no job waits, the lease lives on by the gap alone.
    let lease = fx.write_lease(A, fx.ha);
    let mut t = 0;
    for _ in 0..5 {
        t += 300_000_000;
        fx.rig.server.set_mono(t);
        fx.rig.server.set_job_queued(t);
        fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
            .unwrap();
        fx.rig.server.leases_stamp(t);
        fx.sweep(t, &[]);
        assert_eq!(fx.rig.server.lease_count(), 1, "no waiter, no bound");
    }
    // A reader of the file waits now. The client time so far is 1.5 s (five gaps of 0.3 s) with
    // the first part's, so the bound has fired already for the part that follows.
    let waiter = read_job(fx.hb);
    let queued = [Candidate {
        id: 0,
        ticket: 1,
        owner: B,
        queued_at: t,
        request: &waiter,
    }];
    fx.sweep(t + 1, &queued);
    assert_eq!(
        fx.rig.server.lease_count(),
        0,
        "the bound fired with a waiter"
    );
    assert_eq!(pick(&fx.rig, &[(B, read_job(fx.hb))]), Some(0));
}

#[test]
fn the_client_time_adds_up_over_many_short_gaps() {
    let mut fx = fixture();
    let waiter = read_job(fx.hb);
    let queued = |at: u64| {
        [Candidate {
            id: 0,
            ticket: 1,
            owner: B,
            queued_at: at,
            request: &waiter,
        }]
    };
    let lease = fx.write_lease(A, fx.ha);
    // Nine gaps of 0.1 s with a reader waiting: 0.9 s of client time, under the bound.
    let mut t = 0;
    for _ in 0..9 {
        t += 100_000_000;
        fx.sweep(t, &queued(t));
        assert_eq!(fx.rig.server.lease_count(), 1, "at {t}");
        fx.rig.server.set_job_queued(t);
        fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
            .unwrap();
    }
    // The tenth gap takes it over 1 s in all: the lease lapses though no single gap was long.
    t += 200_000_000;
    fx.sweep(t, &queued(t));
    assert_eq!(fx.rig.server.lease_count(), 0);
}

#[test]
fn a_call_that_lapses_by_the_bound_returns_what_was_done_and_syncs_with_sync() {
    let mut fx = fixture();
    let h = fx.rig.open(B, b"/d/f", p::WRITE | p::SYNC, 0).unwrap();
    let lease = fx
        .part(B, Method::PwriteFrom, h, 4000, 0, true)
        .unwrap()
        .lease;
    fx.part(B, Method::PwriteFrom, h, 4000, lease, true)
        .unwrap();
    let flushes = fx.rig.fs.device().flushes;
    // A waiter, and a client that takes 1.2 s: the bound lapses the lease, syncing the node first.
    let waiter = read_job(fx.hc);
    let queued = [Candidate {
        id: 0,
        ticket: 1,
        owner: C,
        queued_at: 1_200_000_000,
        request: &waiter,
    }];
    fx.sweep(1_200_000_000, &queued);
    assert_eq!(fx.rig.server.lease_count(), 0);
    assert!(
        fx.rig.fs.device().flushes > flushes,
        "the node was synced at the lapse"
    );
    // The late part is not run: 0 bytes, LAPSED; the layer returns the 8,000 bytes done.
    let r = fx
        .part(B, Method::PwriteFrom, h, 4000, lease, false)
        .unwrap();
    assert_eq!((r.count, r.flags), (0, p::LAPSED));
    // Without a waiter no bound applies: the same client time (1.2 s in two gaps) is fine.
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    fx.at(600_000_000);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
        .unwrap();
    fx.at(1_200_000_000);
    fx.sweep(1_200_000_000, &[]);
    assert_eq!(
        fx.rig.server.lease_count(),
        1,
        "no waiter: the gap rule alone"
    );
}

#[test]
fn release_ends_a_lease_and_answers_for_a_number_that_is_over_or_never_was() {
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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
    let mut fx = fixture();
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

#[test]
fn a_seek_waits_for_a_lease_and_the_call_goes_on_from_where_it_was() {
    let mut fx = fixture();
    // A call in parts on a description that has a position: the parts follow each other.
    let at = fx.rig.ok(A, |w| p::seek(fx.ha, 0, p::SEEK_CUR, w));
    let at = u64::from_le_bytes(at[..8].try_into().unwrap());
    let first = fx.part(A, Method::WriteFrom, fx.ha, 100, 0, true).unwrap();
    let lease = first.lease;
    // A seek of the same description by another thread, or of another description by another
    // process (SEEK_END reads the size the call is changing), waits for the lease.
    let seek = |h: u32, whence: u32| req(|w| p::seek(h, 0, whence, w));
    assert_eq!(pick(&fx.rig, &[(A, seek(fx.ha, p::SEEK_SET))]), None);
    assert_eq!(pick(&fx.rig, &[(B, seek(fx.hb, p::SEEK_END))]), None);
    // Under a read lease a seek waits too: the call reads from the position of its description.
    fx.part(A, Method::WriteFrom, fx.ha, 100, lease, false)
        .unwrap();
    let rl = fx.read_lease(A, fx.ha);
    assert_eq!(pick(&fx.rig, &[(A, seek(fx.ha, p::SEEK_SET))]), None);
    fx.part(A, Method::PreadInto, fx.ha, 100, rl, false)
        .unwrap();
    assert_eq!(pick(&fx.rig, &[(A, seek(fx.ha, p::SEEK_SET))]), Some(0));
    // The two parts of the write went one after the other (200 bytes from the start of the position).
    let pos = fx.rig.ok(A, |w| p::seek(fx.ha, 0, p::SEEK_CUR, w));
    assert_eq!(u64::from_le_bytes(pos[..8].try_into().unwrap()), at + 200);
}

#[test]
fn a_call_keeps_the_append_and_sync_its_description_had_at_its_first_part() {
    let mut fx = fixture();
    let h = fx.rig.open(B, b"/d/f", p::WRITE, 0).unwrap();
    let flushes = |fx: &mut Fx| fx.rig.fs.device().flushes;
    let size = fx.rig.stat(B, b"/d/f").unwrap().size;
    let lease = fx
        .part(B, Method::WriteFrom, h, 100, 0, true)
        .unwrap()
        .lease;
    // Another thread sets APPEND and SYNC in the middle of the call: the call is not changed by it.
    fx.rig.ok(B, |w| p::set_flags(h, p::APPEND | p::SYNC, w));
    let before = flushes(&mut fx);
    fx.part(B, Method::WriteFrom, h, 100, lease, true).unwrap();
    assert_eq!(
        flushes(&mut fx),
        before,
        "SYNC set in the middle does not apply to the call"
    );
    fx.part(B, Method::WriteFrom, h, 100, lease, false).unwrap();
    assert_eq!(flushes(&mut fx), before, "nor to its last part");
    // Written where the description was, over the start of the file and nowhere near the end.
    assert_eq!(fx.rig.stat(B, b"/d/f").unwrap().size, size);
    // The next call takes the flags the description has now.
    let r = fx.part(B, Method::WriteFrom, h, 100, 0, false).unwrap();
    assert_eq!(r.count, 100);
    assert_eq!(fx.rig.stat(B, b"/d/f").unwrap().size, size + 100);
    assert!(flushes(&mut fx) > before);
}

#[test]
fn with_sync_a_failed_part_makes_the_parts_before_it_durable_and_so_does_every_part_without_a_lease()
 {
    let mut fx = fixture();
    let mut limited = user(1500, 100, &[]);
    limited.fsize_limit = 300_000 + 5000;
    fx.rig.bind(60, limited);
    fx.rig.window(60);
    let h = fx
        .rig
        .open(60, b"/d/f", p::WRITE | p::SYNC | p::APPEND, 0)
        .unwrap();
    let flushes = |fx: &mut Fx| fx.rig.fs.device().flushes;
    // Part 1 goes (4,000 of the 5,000 the limit leaves); part 2 would pass the limit by 3,000: it is
    // written short (1,000) and stops the call. A part 3 after it finds the limit and fails with 0.
    let lease = fx
        .part(60, Method::WriteFrom, h, 4000, 0, true)
        .unwrap()
        .lease;
    let before = flushes(&mut fx);
    let r = fx
        .part(60, Method::WriteFrom, h, 4000, lease, true)
        .unwrap();
    assert_eq!(
        (r.count, r.lease),
        (1000, 0),
        "a part a limit stopped ends the call"
    );
    assert!(
        flushes(&mut fx) > before,
        "the call is synced when a limit stops it"
    );
    // Now a call whose second part fails with nothing written.
    let lease = fx.part(60, Method::WriteFrom, h, 100, 0, true);
    assert_eq!(lease.map(drop), Err(p::code(p::FILE_SIZE_LIMIT)));
    assert_eq!(fx.rig.server.lease_count(), 0);
    // A fresh limited user: part 1 fits exactly, part 2 fails with FILE_SIZE_LIMIT; the lease ends
    // and the node is synced.
    let mut tight = user(1600, 100, &[]);
    tight.fsize_limit = 305_000 + 4000;
    fx.rig.bind(61, tight);
    fx.rig.window(61);
    let h2 = fx
        .rig
        .open(61, b"/d/f", p::WRITE | p::SYNC | p::APPEND, 0)
        .unwrap();
    let lease = fx
        .part(61, Method::WriteFrom, h2, 4000, 0, true)
        .unwrap()
        .lease;
    assert!(lease != 0);
    let before = flushes(&mut fx);
    let r = fx.part(61, Method::WriteFrom, h2, 100, lease, true);
    assert_eq!(r.map(drop), Err(p::code(p::FILE_SIZE_LIMIT)));
    assert_eq!(fx.rig.server.lease_count(), 0);
    assert!(
        flushes(&mut fx) > before,
        "the failed part synced what the earlier parts wrote"
    );
}

#[test]
fn a_part_that_found_no_lease_to_take_is_synced_like_a_write() {
    let mut fx = fixture();
    let h = fx.rig.open(B, b"/d/f", p::WRITE | p::SYNC, 0).unwrap();
    // The session has its four leases (on reads of another description): the fifth part is unleased.
    let hr = fx.rig.open(B, b"/d/f", p::READ, 0).unwrap();
    for _ in 0..p::LEASES_PER_SESSION {
        fx.read_lease(B, hr);
    }
    let flushes = fx.rig.fs.device().flushes;
    let before = fx.rig.server.unleased();
    let r = fx.part(B, Method::PwriteFrom, h, 100, 0, true).unwrap();
    assert_eq!((r.flags, r.lease), (p::UNLEASED, 0));
    assert!(
        fx.rig.fs.device().flushes > flushes,
        "an unleased part with MORE is synced"
    );
    assert_eq!(fx.rig.server.unleased(), before + 1);
}

#[test]
fn a_part_that_would_take_a_lease_beyond_the_limits_waits_for_one_to_end() {
    let mut fx = fixture();
    let mut leases = Vec::new();
    for _ in 0..p::LEASES_PER_SESSION {
        leases.push(fx.read_lease(A, fx.ha));
    }
    let taker = part_job(Method::PreadInto, fx.ha, 0, true);
    let others = [(A, taker.clone()), (A, read_job(fx.ha))];
    let cands: Vec<Candidate<'_>> = others
        .iter()
        .enumerate()
        .map(|(i, (o, r))| Candidate {
            id: i,
            ticket: i as u64 + 1,
            owner: *o,
            queued_at: 0,
            request: r,
        })
        .collect();
    let choice = fx.rig.server.pick(&cands);
    assert_eq!(
        choice.run,
        Some(1),
        "the plain read goes, the fifth lease waits"
    );
    assert_eq!(choice.parked, 0b01);
    fx.part(A, Method::PreadInto, fx.ha, 10, leases[0], false)
        .unwrap();
    let choice = fx.rig.server.pick(&cands);
    assert_eq!(choice.run, Some(0), "it goes when a lease has ended");
    assert_eq!(choice.parked, 0);
}

#[test]
fn the_parts_of_one_lease_run_one_at_a_time_in_the_order_they_came() {
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    let jobs = [
        (A, part_job(Method::PwriteFrom, fx.ha, lease, true)),
        (A, part_job(Method::PwriteFrom, fx.ha, lease, true)),
    ];
    let cands: Vec<Candidate<'_>> = jobs
        .iter()
        .enumerate()
        .map(|(i, (o, r))| Candidate {
            id: i,
            ticket: i as u64 + 1,
            owner: *o,
            queued_at: 0,
            request: r,
        })
        .collect();
    let choice = fx.rig.server.pick(&cands);
    assert_eq!((choice.run, choice.parked), (Some(0), 0b10));
}

#[test]
fn stat_and_open_with_truncation_wait_for_a_lease_whoever_asks() {
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    // A session the server has not seen holds no descriptions, and a path names the file all the same.
    assert_eq!(pick(&fx.rig, &[(999, stat_job())]), None);
    assert_eq!(pick(&fx.rig, &[(999, open_trunc_job())]), None);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, false)
        .unwrap();
    assert_eq!(pick(&fx.rig, &[(999, stat_job())]), Some(0));
}

#[test]
fn a_session_that_ran_a_new_image_loses_its_leases_and_its_window() {
    let mut fx = fixture();
    let before = fx.rig.server.open_count();
    let _ = fx.write_lease(B, fx.hb);
    fx.rig.close(B, fx.hb);
    assert_eq!(
        fx.rig.server.open_count(),
        before,
        "the lease holds the description"
    );
    // The worker ends the leases of the session and then unbinds it (UNBIND of VERIFY_SESSION).
    fx.rig.server.leases_end_of(&mut fx.rig.fs, B);
    fx.rig.server.unbind(B);
    assert_eq!(fx.rig.server.lease_count(), 0);
    assert!(!fx.rig.server.has_window(B));
    assert_eq!(fx.rig.server.open_count(), before - 1);
}

#[test]
fn the_wake_up_of_the_worker_is_never_in_the_past_when_no_job_waits_for_the_file() {
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    // Six gaps of 0.3 s: the client time of the lease is 1.8 s, over the bound, with nobody waiting.
    let mut t = 0;
    for _ in 0..6 {
        t += 300_000_000;
        fx.at(t);
        fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
            .unwrap();
        fx.sweep(t, &[]);
        assert_eq!(fx.rig.server.lease_count(), 1);
        // The wake-up is the gap after the answer, ahead of now: no timer that fires at once.
        assert_eq!(fx.rig.server.next_lease_expiry(), Some(t + LEASE_GAP_NS));
    }
    // A sweep a little later, still with nobody waiting: the same instant, and in the future.
    fx.sweep(t + 100, &[]);
    let at = fx.rig.server.next_lease_expiry().unwrap();
    assert_eq!(at, t + LEASE_GAP_NS);
    assert!(at > t + 100);
    // A job that waits for the file brings the wake-up forward to the bound, which is still ahead
    // of now at that sweep, and the lease lapses when the bound is passed.
    let waiter = read_job(fx.hb);
    let queued = [Candidate {
        id: 0,
        ticket: 1,
        owner: B,
        queued_at: t,
        request: &waiter,
    }];
    fx.sweep(t + 100, &queued);
    assert_eq!(
        fx.rig.server.lease_count(),
        0,
        "over the bound with a waiter"
    );
}

#[test]
fn with_a_waiter_the_wake_up_is_when_the_client_time_reaches_the_bound() {
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    fx.at(400_000_000);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
        .unwrap();
    let waiter = read_job(fx.hb);
    let queued = [Candidate {
        id: 0,
        ticket: 1,
        owner: B,
        queued_at: 400_000_000,
        request: &waiter,
    }];
    fx.sweep(400_000_000, &queued);
    // 0.4 s of client time so far: 0.6 s left, sooner than the gap of 1 s.
    let at = fx.rig.server.next_lease_expiry().unwrap();
    assert_eq!(at, 400_000_000 + 600_000_000 + 1);
    assert!(at < 400_000_000 + LEASE_GAP_NS + 1);
}

#[test]
fn the_lapse_with_a_waiter_keeps_the_facts_the_probe_judges() {
    let mut fx = fixture();
    let lease = fx.write_lease(A, fx.ha);
    assert_eq!(fx.rig.server.lapse().count, 0);
    // The last part is answered at 0.2 s; a reader of the file is queued at 0.5 s.
    fx.at(200_000_000);
    fx.rig.server.set_job_queued(200_000_000);
    fx.part(A, Method::PwriteFrom, fx.ha, 10, lease, true)
        .unwrap();
    fx.rig.server.leases_stamp(200_000_000);
    let waiter = read_job(fx.hb);
    let queued = [Candidate {
        id: 0,
        ticket: 1,
        owner: B,
        queued_at: 500_000_000,
        request: &waiter,
    }];
    // Before the gap is over nothing lapses and nothing is kept.
    fx.sweep(900_000_000, &queued);
    assert_eq!(fx.rig.server.lease_count(), 1);
    assert_eq!(fx.rig.server.lapse().count, 0);
    // The sweep at 1.25 s ends the lease: 50 ms past the gap.
    fx.sweep(1_250_000_000, &queued);
    assert_eq!(fx.rig.server.lease_count(), 0);
    let l = fx.rig.server.lapse();
    assert_eq!(
        (l.count, l.answered, l.queued, l.at, l.ran),
        (1, 200_000_000, 500_000_000, 1_250_000_000, 0)
    );
    // Another job's pick is not the waiter; the waiter's is, once.
    assert!(!fx.rig.server.lapse_waiter_ran(1, 1_260_000_000));
    assert!(fx.rig.server.lapse_waiter_ran(500_000_000, 1_260_000_000));
    assert_eq!(fx.rig.server.lapse().ran, 1_260_000_000);
    assert!(!fx.rig.server.lapse_waiter_ran(500_000_000, 1_300_000_000));
    assert_eq!(fx.rig.server.lapse().ran, 1_260_000_000);
    // The record is told once, to the waiter's own job, and carries the instant the timer was set for.
    assert_eq!(fx.rig.server.lapse_told(1), None);
    let told = fx.rig.server.lapse_told(500_000_000).unwrap();
    // (the sweep at 0.9 s set it: the client time of 0.2 s reaches its bound at 1 s)
    assert_eq!(told.expiry, 1_000_000_001);
    assert_eq!(fx.rig.server.lapse_told(500_000_000), None);
}

#[test]
fn a_lapse_nobody_waited_for_leaves_no_facts() {
    let mut fx = fixture();
    fx.write_lease(A, fx.ha);
    fx.sweep(2 * LEASE_GAP_NS, &[]);
    assert_eq!(fx.rig.server.lease_count(), 0);
    assert_eq!(fx.rig.server.lapse().count, 0);
}
