// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tail of a rewrite copied in steps (issue #626): a write in the middle of a file, then the
//! jobs of the worker in the order `next_job` of the service serves them (`tails_start`, `pick`, the
//! job, one step of the copy), with the disk reads of every job counted on the device in memory;
//! and a cut of the power between the steps.

use crate::fs::{Fs, Storage};
use crate::mem::{MemDevice, Survive};
use crate::server::{Candidate, TAIL_SLICE_BLOCKS};
use crate::tests_perm::{OTHER, OWNER, ROOT, Rig};
use crate::tests_window::pattern;
use crate::{BLOCK, Device};
use proto_data as p;
use proto_wire::{Status, Writer};
use std::boxed::Box;
use std::string::{String, ToString};
use std::vec::Vec;

const MIB: usize = 1 << 20;

fn big() -> Rig {
    let mut rig = Rig::on(MemDevice::new(16_384));
    rig.mkdir(ROOT, b"/d", 0o777).unwrap();
    rig
}

fn req(build: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
    let mut w = Writer::new();
    build(&mut w).unwrap();
    w.as_bytes().to_vec()
}

/// A file of `data` at `path`, synced, the handle of `who` open on it.
fn make(rig: &mut Rig, who: u64, path: &[u8], data: &[u8]) -> u32 {
    let h = rig
        .open(who, path, p::READ | p::WRITE | p::CREATE, 0o666)
        .unwrap();
    for chunk in data.chunks(900) {
        rig.write(who, h, chunk).unwrap();
    }
    rig.ok(who, |w| p::handle_call(p::Method::Fsync, h, w));
    h
}

struct Job {
    who: u64,
    name: &'static str,
    request: Vec<u8>,
}

/// One thing the loop did: a job (its name, the reads of the device, the answer) or a step of a copy.
#[derive(Debug)]
struct Done {
    name: String,
    reads: u64,
    answer: Result<Vec<u8>, Status>,
}

/// The loop of the worker over `queue` (the jobs came in this order): `tails_start`, `pick`, the
/// job, one step of a copy; a step alone when no job can run. Ends when the queue is empty.
fn serve(rig: &mut Rig, mut queue: Vec<Job>) -> Vec<Done> {
    let mut log = Vec::new();
    while !queue.is_empty() {
        let run = {
            let cands: Vec<Candidate<'_>> = queue
                .iter()
                .enumerate()
                .map(|(i, j)| Candidate {
                    id: i,
                    ticket: i as u64 + 1,
                    owner: j.who,
                    queued_at: 0,
                    request: &j.request,
                })
                .collect();
            rig.server.tails_start(&mut rig.fs, &cands);
            rig.server.pick(&cands).run
        };
        let reads = rig.fs.device().reads;
        if let Some(i) = run {
            {
                let job = queue.remove(i);
                let reply = rig.server.handle(&mut rig.fs, job.who, 0, &job.request);
                let answer =
                    p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec());
                log.push(Done {
                    name: job.name.to_string(),
                    reads: rig.fs.device().reads - reads,
                    answer,
                });
            }
        }
        let reads = rig.fs.device().reads;
        if rig.server.tail_step(&mut rig.fs) {
            log.push(Done {
                name: "step".to_string(),
                reads: rig.fs.device().reads - reads,
                answer: Ok(Vec::new()),
            });
        } else {
            assert!(run.is_some(), "the loop is stuck with {} jobs", queue.len());
        }
    }
    log
}

fn pread(h: u32, count: u32, at: u64) -> Vec<u8> {
    req(|w| p::pread(h, count, at, w))
}

#[test]
fn a_read_of_another_file_runs_between_the_steps_of_a_tail_and_the_same_file_waits_for_it() {
    let mut rig = big();
    let old = pattern(0, MIB);
    let hf = make(&mut rig, OWNER, b"/d/f", &old);
    let hf2 = rig.open(OTHER, b"/d/f", p::READ, 0).unwrap();
    let small = pattern(5, 3000);
    let hg = make(&mut rig, OWNER, b"/d/g", &small);
    // One byte at offset 0 of the file of 1 MiB: everything after it is the tail.
    rig.ok(OWNER, |w| p::pwrite(hf, 0, b"Z", w));
    assert_eq!(rig.server.tail_steps, 0, "a write copies nothing");
    let log = serve(
        &mut rig,
        std::vec![
            Job {
                who: OTHER,
                name: "read f",
                request: pread(hf2, 64, 500_000)
            },
            Job {
                who: OWNER,
                name: "read g",
                request: pread(hg, 64, 100)
            },
            Job {
                who: OWNER,
                name: "read g again",
                request: pread(hg, 64, 200)
            },
        ],
    );
    let names: Vec<&str> = log.iter().map(|d| d.name.as_str()).collect();
    let first = names.iter().position(|n| *n == "read g").unwrap();
    let again = names.iter().position(|n| *n == "read g again").unwrap();
    let f = names.iter().position(|n| *n == "read f").unwrap();
    assert!(
        first < f && again < f,
        "the jobs of the other file run first: {names:?}"
    );
    assert_eq!(
        names[..first].iter().filter(|n| **n == "step").count(),
        0,
        "{names:?}"
    );
    // The jobs of the other file ran between steps: a step lies between the two of them.
    assert!(names[first..again].contains(&"step"), "{names:?}");
    let steps = names.iter().filter(|n| **n == "step").count();
    let blocks = MIB / (BLOCK - 8);
    assert!(
        steps >= blocks / TAIL_SLICE_BLOCKS as usize,
        "{steps} steps for {blocks} blocks"
    );
    assert!(
        names[f - 1] == "step",
        "the waiter runs after the last step: {names:?}"
    );
    assert!(names[f + 1..].iter().all(|n| *n != "step"), "{names:?}");
    // The waiter reads the bytes the file has.
    let reply = log[f].answer.clone().unwrap();
    assert_eq!(reply[4..], old[500_000..500_064]);
    // No job but the steps reads much; no step reads more than a few times its blocks.
    let widest = log.iter().map(|d| d.reads).max().unwrap();
    let total: u64 = log.iter().map(|d| d.reads).sum();
    std::println!("tail: {steps} steps, widest job {widest} reads, {total} reads in all");
    assert!(widest * 8 < total, "widest {widest} of {total}");
    // The whole file: the byte written and the old bytes after it.
    let got = rig.read(OWNER, hf, 1).ok();
    let _ = got;
    let mut all = Vec::new();
    for at in (0..MIB).step_by(900) {
        let r = rig
            .call(OWNER, |w| p::pread(hf, 900, at as u64, w))
            .unwrap();
        all.extend_from_slice(&r[4..]);
    }
    let mut want = old.clone();
    want[0] = b'Z';
    assert!(all == want, "the file after the copy");
}

#[test]
fn a_write_that_goes_on_where_the_last_one_stopped_copies_no_tail() {
    let mut rig = big();
    let old = pattern(0, 200_000);
    let h = make(&mut rig, OWNER, b"/d/f", &old);
    let mut want = old.clone();
    // Sequential rewrite in small calls: positional and plain, from offset 1000.
    rig.ok(OWNER, |w| p::pwrite(h, 1000, b"abcd", w));
    want[1000..1004].copy_from_slice(b"abcd");
    let mut at = 1004u64;
    for i in 0..40u8 {
        let chunk = [i; 50];
        let queue = std::vec![Job {
            who: OWNER,
            name: "pwrite",
            request: req(|w| p::pwrite(h, at, &chunk, w))
        }];
        let log = serve(&mut rig, queue);
        assert_eq!(log.len(), 1, "no step: {log:?}");
        want[at as usize..at as usize + 50].copy_from_slice(&chunk);
        at += 50;
    }
    assert_eq!(rig.server.tail_steps, 0);
    // A read of the file begins the copy, and the file is as written.
    let log = serve(
        &mut rig,
        std::vec![Job {
            who: OWNER,
            name: "read",
            request: pread(h, 100, 5)
        }],
    );
    assert!(rig.server.tail_steps > 0, "{log:?}");
    let mut all = Vec::new();
    for at in (0..want.len()).step_by(900) {
        let r = rig.call(OWNER, |w| p::pread(h, 900, at as u64, w)).unwrap();
        all.extend_from_slice(&r[4..]);
    }
    assert!(all == want);
}

#[test]
fn a_write_at_another_place_and_a_close_wait_for_the_copy_too() {
    let mut rig = big();
    let old = pattern(0, 300_000);
    let h = make(&mut rig, OWNER, b"/d/f", &old);
    rig.ok(OWNER, |w| p::pwrite(h, 10, b"x", w));
    let log = serve(
        &mut rig,
        std::vec![
            Job {
                who: OWNER,
                name: "pwrite far",
                request: req(|w| p::pwrite(h, 250_000, b"y", w))
            },
            Job {
                who: OWNER,
                name: "close",
                request: req(|w| p::handle_call(p::Method::Close, h, w))
            },
        ],
    );
    let names: Vec<&str> = log.iter().map(|d| d.name.as_str()).collect();
    let far = names.iter().position(|n| *n == "pwrite far").unwrap();
    assert_eq!(names[far - 1], "step", "{names:?}");
    assert!(log[far].answer.is_ok());
    let mut want = old.clone();
    want[10] = b'x';
    want[250_000] = b'y';
    let h2 = rig.open(OWNER, b"/d/f", p::READ, 0).unwrap();
    let mut all = Vec::new();
    for at in (0..want.len()).step_by(900) {
        let r = rig
            .call(OWNER, |w| p::pread(h2, 900, at as u64, w))
            .unwrap();
        all.extend_from_slice(&r[4..]);
    }
    assert!(all == want);
}

/// Random calls over two files with a step of a copy between them at random: every answer and the
/// file at the end are those of a model in memory, on a volume small enough for the allocator to
/// wrap (blocks of the copy and of the other file's writes compete).
#[test]
fn random_calls_with_steps_between_them_read_what_a_model_says() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move |n: usize| -> usize {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((state >> 33) as usize) % n
    };
    for round in 0..6 {
        let mut rig = Rig::on(MemDevice::new(1_280));
        rig.mkdir(ROOT, b"/d", 0o777).unwrap();
        let mut model: [Vec<u8>; 2] = [pattern(round, 150_000), pattern(round + 7, 60_000)];
        let hs = [
            make(&mut rig, OWNER, b"/d/a", &model[0]),
            make(&mut rig, OWNER, b"/d/b", &model[1]),
        ];
        for _ in 0..300 {
            let k = next(2);
            match next(6) {
                0 | 1 => {
                    let at = next(model[k].len());
                    let len = 1 + next(300);
                    let data = pattern(next(1000), len);
                    let queue = std::vec![Job {
                        who: OWNER,
                        name: "w",
                        request: req(|w| p::pwrite(hs[k], at as u64, &data, w))
                    }];
                    serve(&mut rig, queue);
                    let end = at + len;
                    if end > model[k].len() {
                        model[k].resize(end, 0);
                    }
                    model[k][at..end].copy_from_slice(&data);
                }
                2 => {
                    let at = next(model[k].len());
                    let queue = std::vec![Job {
                        who: OWNER,
                        name: "r",
                        request: pread(hs[k], 200, at as u64)
                    }];
                    let log = serve(&mut rig, queue);
                    let got = log
                        .iter()
                        .find(|d| d.name == "r")
                        .unwrap()
                        .answer
                        .clone()
                        .unwrap();
                    let end = (at + 200).min(model[k].len());
                    assert!(
                        got[4..] == model[k][at..end],
                        "round {round}: read of {k} at {at}"
                    );
                }
                3 => {
                    // A job that flushes the file begins the copy; some steps run, and the next
                    // calls come while the copy is half done.
                    let probe = pread(hs[k], 1, 0);
                    {
                        let cands = [Candidate {
                            id: 0,
                            ticket: 1,
                            owner: OWNER,
                            queued_at: 0,
                            request: &probe,
                        }];
                        rig.server.tails_start(&mut rig.fs, &cands);
                    }
                    for _ in 0..next(4) {
                        rig.server.tail_step(&mut rig.fs);
                    }
                }
                4 => {
                    let queue = std::vec![Job {
                        who: OWNER,
                        name: "sync",
                        request: req(|w| p::handle_call(p::Method::Fsync, hs[k], w))
                    }];
                    serve(&mut rig, queue);
                }
                _ => {
                    // A job on the other file while a copy of this one may be half done.
                    let o = 1 - k;
                    let at = next(model[o].len());
                    let data = pattern(next(1000), 100);
                    rig.ok(OWNER, |w| p::pwrite(hs[o], at as u64, &data, w));
                    let end = at + 100;
                    if end > model[o].len() {
                        model[o].resize(end, 0);
                    }
                    model[o][at..end].copy_from_slice(&data);
                    rig.ok(OWNER, |w| p::handle_call(p::Method::Fsync, hs[o], w));
                }
            }
        }
        assert!(
            rig.server.tail_steps > 5,
            "round {round}: {} steps",
            rig.server.tail_steps
        );
        for k in 0..2 {
            let queue = std::vec![Job {
                who: OWNER,
                name: "sync",
                request: req(|w| p::handle_call(p::Method::Fsync, hs[k], w))
            }];
            serve(&mut rig, queue);
            let mut all = Vec::new();
            for at in (0..model[k].len()).step_by(900) {
                let r = rig
                    .call(OWNER, |w| p::pread(hs[k], 900, at as u64, w))
                    .unwrap();
                all.extend_from_slice(&r[4..]);
            }
            assert!(all == model[k], "round {round}: file {k} at the end");
        }
    }
}

/// A cut of the power at every sector of a sequence: a rewrite from the middle, steps of its copy,
/// a sync of another file between them (a commit while the copy is half done), the rest of the
/// copy and the sync of the file. After the start the file is the old one or the new one, whole,
/// and the other file is whole.
#[test]
fn a_cut_between_the_steps_of_a_copy_leaves_the_old_file_or_the_new() {
    let old = pattern(0, 400_000);
    let other_old = pattern(3, 5_000);
    let other_new = pattern(4, 6_000);
    let mut new = old.clone();
    new[100..104].copy_from_slice(b"WXYZ");
    let sequence = |cut: Option<u64>, survive: Survive| -> (Vec<u8>, Vec<u8>, u64) {
        let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
        let mut rig = Rig {
            server: crate::server::Server::with_epoch(1),
            fs: Fs::new(MemDevice::new(4_096), state).unwrap(),
        };
        rig.fs.format().unwrap();
        rig.fs.mount().unwrap();
        crate::server::ensure_orphans(&mut rig.fs).unwrap();
        rig.server.set_now(1_000);
        let call = |rig: &mut Rig, build: &dyn Fn(&mut Writer) -> Result<(), Status>| {
            let mut w = Writer::new();
            build(&mut w).unwrap();
            let reply = rig.server.handle(&mut rig.fs, 1, 0, w.as_bytes());
            p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
        };
        // Without the setup of a session: the service treats a session it has not bound as native.
        let open = |rig: &mut Rig, path: &[u8]| -> u32 {
            let mut w = Writer::new();
            p::open(path, p::READ | p::WRITE | p::CREATE, 0o666, &mut w).unwrap();
            let reply = rig.server.handle(&mut rig.fs, 1, 0, w.as_bytes());
            let mut r = p::reply(reply.as_bytes()).unwrap();
            let body = r.bytes(r.left()).unwrap();
            u32::from_le_bytes(body[..4].try_into().unwrap())
        };
        let hf = open(&mut rig, b"/f");
        let hg = open(&mut rig, b"/g");
        for chunk in old.chunks(900) {
            call(&mut rig, &|w| p::write(hf, chunk, w)).unwrap();
        }
        for chunk in other_old.chunks(900) {
            call(&mut rig, &|w| p::write(hg, chunk, w)).unwrap();
        }
        call(&mut rig, &|w| p::handle_call(p::Method::Fsync, hf, w)).unwrap();
        call(&mut rig, &|w| p::handle_call(p::Method::Fsync, hg, w)).unwrap();
        rig.fs.device().flush().unwrap();
        let before = rig.fs.device().written;
        rig.fs.device().cut_after(cut);
        let _ = call(&mut rig, &|w| p::pwrite(hf, 100, b"WXYZ", w));
        // The copy begins with a job that flushes; two steps, a commit of the other file, the
        // rest of the steps, the sync of the file.
        let probe = req(|w| p::pread(hf, 1, 0, w));
        {
            let cands = [Candidate {
                id: 0,
                ticket: 1,
                owner: 1,
                queued_at: 0,
                request: &probe,
            }];
            rig.server.tails_start(&mut rig.fs, &cands);
        }
        for _ in 0..2 {
            rig.server.tail_step(&mut rig.fs);
        }
        for (i, chunk) in other_new.chunks(900).enumerate() {
            let _ = call(&mut rig, &|w| p::pwrite(hg, (i * 900) as u64, chunk, w));
        }
        let _ = call(&mut rig, &|w| p::handle_call(p::Method::Fsync, hg, w));
        while rig.server.tail_step(&mut rig.fs) {}
        let _ = call(&mut rig, &|w| p::handle_call(p::Method::Fsync, hf, w));
        let written = rig.fs.device().written - before;
        let mut device = rig.fs.into_device();
        device.power_cycle(survive);
        let mut state = Box::new(Storage::new());
        let mut fs = Fs::new(device, &mut state).unwrap();
        fs.mount().expect("the volume mounts after the cut");
        let mut read = |path: &[u8]| -> Vec<u8> {
            let f = fs.open(path, crate::fs::Open::READ).unwrap();
            let mut out = std::vec![0u8; 500_000];
            let n = fs.read(f, &mut out).unwrap();
            out.truncate(n);
            fs.close(f).unwrap();
            out
        };
        (read(b"/f"), read(b"/g"), written)
    };
    let (f, g, total) = sequence(None, Survive::All);
    assert!(f == new && g == other_new, "the run without a cut");
    assert!(total > 100, "{total} sectors");
    let mut olds = 0;
    for cut in (0..total).step_by(3) {
        for survive in [Survive::None, Survive::All, Survive::Random(cut * 2 + 1)] {
            let (f, g, _) = sequence(Some(cut), survive);
            assert!(
                f == old || f == new,
                "cut {cut} {survive:?}: the file is neither the old nor the new ({} bytes)",
                f.len()
            );
            assert!(
                g == other_old || g == other_new,
                "cut {cut} {survive:?}: the other file ({} bytes)",
                g.len()
            );
            olds += usize::from(f == old);
        }
    }
    assert!(olds > 0, "no cut ever left the old file");
}

/// A call that runs while a copy is half done (the unlink or the rename of an open file is not
/// known to flush, so `pick` lets it run) finishes the copy in its own job and sees the right bytes.
#[test]
fn a_call_that_meets_a_half_done_copy_finishes_it_and_sees_the_right_bytes() {
    for call in 0..3 {
        let mut rig = big();
        let old = pattern(0, 300_000);
        let h = make(&mut rig, OWNER, b"/d/f", &old);
        rig.ok(OWNER, |w| p::pwrite(h, 7, b"Q", w));
        let probe = pread(h, 1, 0);
        {
            let cands = [Candidate {
                id: 0,
                ticket: 1,
                owner: OWNER,
                queued_at: 0,
                request: &probe,
            }];
            rig.server.tails_start(&mut rig.fs, &cands);
        }
        assert!(rig.server.tail_step(&mut rig.fs), "the copy is running");
        assert!(rig.server.tail_running(), "and half done");
        let mut want = old.clone();
        want[7] = b'Q';
        match call {
            0 => {
                let r = rig.call(OWNER, |w| p::pread(h, 900, 100_000, w)).unwrap();
                assert!(r[4..] == want[100_000..100_900]);
            }
            1 => {
                rig.ok(OWNER, |w| p::pwrite(h, 10, b"R", w));
                want[10] = b'R';
            }
            _ => drop(rig.ok(OWNER, |w| p::handle_call(p::Method::Close, h, w))),
        }
        while rig.server.tail_step(&mut rig.fs) {}
        let h2 = rig.open(OWNER, b"/d/f", p::READ, 0).unwrap();
        let mut all = Vec::new();
        for at in (0..want.len()).step_by(900) {
            let r = rig
                .call(OWNER, |w| p::pread(h2, 900, at as u64, w))
                .unwrap();
            all.extend_from_slice(&r[4..]);
        }
        assert!(all == want, "call {call}");
    }
}
