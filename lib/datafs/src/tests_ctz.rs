// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The reads of the device that a sequential read of a large file costs, counted on the host.
//!
//! littlefs finds the block of a position of a file by walking the skip list of the file back from
//! its last block (`lfs_ctz_find`): about log2(n) reads of a pointer for the n-th block. The table
//! of the run prints the reads for each block of data for several sizes of file and of call.
//!
//! ```text
//! CARGO_PROFILE_DEV_OPT_LEVEL=3 cargo test -p datafs --lib tests_ctz -- --ignored --nocapture --test-threads=1
//! ```

use crate::fs::{Fs, Open, Storage, Whence};
use crate::mem::MemDevice;
use crate::{BLOCK_SECTORS, Device};
use std::boxed::Box;
use std::vec;
use std::vec::Vec;

type Vol = Fs<'static, MemDevice>;

/// The bytes of data a block of a file holds on average, for the table: a block of 4096 bytes less
/// the pointers (the exact figure depends on the index of the block).
const BLOCK_DATA: u64 = 4096 - 8;

fn attach(device: MemDevice) -> Vol {
    let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
    Fs::new(device, state).unwrap()
}

/// The bytes of a file of the tests: a function of the position, so that a read of the wrong block
/// shows at once.
fn byte(pos: u64) -> u8 {
    (pos.wrapping_mul(2_654_435_761) >> 13) as u8
}

fn pattern(from: u64, len: usize) -> Vec<u8> {
    (0..len as u64).map(|i| byte(from + i)).collect()
}

/// A volume of `blocks` blocks with the file `/f` of `bytes` bytes written in calls of 64 KiB,
/// closed, unmounted and settled; mounted again over the same medium with the counters at zero.
fn volume_with_file(blocks: u64, bytes: u64, hints: u32) -> Vol {
    let mut fs = attach(MemDevice::new(blocks * BLOCK_SECTORS));
    fs.format().unwrap();
    fs.mount().unwrap();
    let f = fs.open(b"/f", Open::WRITE.with(Open::CREATE)).unwrap();
    let mut at = 0;
    while at < bytes {
        let n = (bytes - at).min(65536) as usize;
        assert_eq!(fs.write(f, &pattern(at, n)).unwrap(), n);
        at += n as u64;
    }
    fs.close(f).unwrap();
    fs.unmount().unwrap();
    let mut device = fs.into_device();
    device.flush().unwrap();
    let mut fs = attach(device);
    fs.set_ctz_hints(hints);
    fs.mount().unwrap();
    fs
}

/// The reads of the device since `at`.
fn reads_since(fs: &mut Vol, at: u64) -> u64 {
    fs.device().reads - at
}

/// Reads the whole file in calls of `call` bytes, checking the bytes; the reads of the device.
fn read_all(fs: &mut Vol, bytes: u64, call: usize) -> u64 {
    let f = fs.open(b"/f", Open::READ).unwrap();
    let at = fs.device().reads;
    let mut buf = vec![0u8; call];
    let mut pos = 0;
    while pos < bytes {
        let n = fs.read(f, &mut buf).unwrap();
        assert!(n > 0);
        assert_eq!(buf[..n], pattern(pos, n)[..], "wrong bytes at {pos}");
        pos += n as u64;
    }
    let reads = reads_since(fs, at);
    fs.close(f).unwrap();
    reads
}

fn table(hints: u32) {
    std::println!("| file | blocks | call | reads | reads per block |");
    std::println!("|---:|---:|---:|---:|---:|");
    for mib in [1u64, 4, 16, 64] {
        let bytes = mib << 20;
        let blocks = bytes / BLOCK_DATA + 1;
        let device_blocks = blocks + blocks / 8 + 64;
        for call in [4096usize, 65536] {
            let mut fs = volume_with_file(device_blocks, bytes, hints);
            let reads = read_all(&mut fs, bytes, call);
            std::println!(
                "| {mib} MiB | {blocks} | {} KiB | {reads} | {:.2} |",
                call / 1024,
                reads as f64 / blocks as f64
            );
        }
    }
}

#[test]
#[ignore = "slow: a file of 64 MiB; run by name, see the module text"]
fn scale_ctz_read() {
    std::println!("\n## Reads of the device for each block of a sequential read\n");
    for hints in [0, 4, 8, 16] {
        std::println!("wayposts: {hints}\n");
        table(hints);
    }
}

/// A small xorshift generator: the same operations for every volume of a comparison.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn a_read_in_order_costs_at_most_three_reads_for_each_block() {
    let bytes = 4u64 << 20;
    let blocks = bytes / BLOCK_DATA + 1;
    let mut with = volume_with_file(2048, bytes, 16);
    let mut without = volume_with_file(2048, bytes, 0);
    let a = read_all(&mut with, bytes, 65536);
    let b = read_all(&mut without, bytes, 65536);
    assert!(a <= 3 * blocks, "{a} reads for {blocks} blocks");
    assert!(b > 5 * blocks, "the walk of the release: {b} reads");
}

/// What a read of `len` bytes at `pos` gives from the bytes of the model.
fn model_read(model: &[u8], pos: u64, len: usize) -> Vec<u8> {
    let start = (pos as usize).min(model.len());
    model[start..(start + len).min(model.len())].to_vec()
}

/// One volume of a comparison: the operations run on it, and its answers are noted.
struct Side {
    fs: Vol,
    file: crate::File,
}

impl Side {
    fn new(hints: u32) -> Self {
        let mut fs = attach(MemDevice::new(1024 * BLOCK_SECTORS));
        fs.set_ctz_hints(hints);
        fs.format().unwrap();
        fs.mount().unwrap();
        let file = fs.open(b"/f", Open::READ_WRITE.with(Open::CREATE)).unwrap();
        Self { fs, file }
    }
}

/// Runs `ops` random operations on a file over volumes with the numbers of wayposts of `hints`,
/// and on a model of the file in memory: every answer must be the model's and the same on every
/// volume, and the media must be the same byte for byte at the end.
fn same_answers(seed: u64, ops: usize, hints: &[u32]) {
    let mut rng = Rng(seed | 1);
    let mut sides: Vec<Side> = hints.iter().map(|&h| Side::new(h)).collect();
    let mut model: Vec<u8> = Vec::new();
    let mut pos = 0u64;
    for step in 0..ops {
        let kind = rng.below(100);
        // Sizes of a few blocks mostly, and now and then one of several hundred.
        let len = if rng.below(10) == 0 {
            rng.below(300_000)
        } else {
            rng.below(10_000)
        } as usize;
        let at = rng.below(model.len() as u64 + 20_000);
        match kind {
            // A read from where the file is, in order.
            0..=34 => {
                let want = model_read(&model, pos, len);
                for (i, s) in sides.iter_mut().enumerate() {
                    let mut buf = vec![0u8; len];
                    let n = s.fs.read(s.file, &mut buf).unwrap();
                    assert_eq!(
                        buf[..n],
                        want[..],
                        "step {step}: a read of {len} at {pos}, wayposts {}, side {i}",
                        hints[i]
                    );
                }
                pos += want.len() as u64;
            }
            // A seek, forward or backward, and the read after it.
            35..=59 => {
                pos = at.min(model.len() as u64 + 3000);
                let want = model_read(&model, pos, len);
                for s in sides.iter_mut() {
                    assert_eq!(s.fs.seek(s.file, pos as i32, Whence::Set).unwrap(), pos);
                    let mut buf = vec![0u8; len];
                    let n = s.fs.read(s.file, &mut buf).unwrap();
                    assert_eq!(buf[..n], want[..], "step {step}: a read of {len} at {pos}");
                }
                pos += want.len() as u64;
            }
            // A write at a position, over the old bytes, past the end or at it.
            60..=77 => {
                let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                let start = at.min(model.len() as u64 + 2000);
                if model.len() < start as usize + len {
                    model.resize(start as usize + len, 0);
                }
                model[start as usize..start as usize + len].copy_from_slice(&data);
                for s in sides.iter_mut() {
                    s.fs.seek(s.file, start as i32, Whence::Set).unwrap();
                    assert_eq!(s.fs.write(s.file, &data).unwrap(), len);
                }
                pos = start + len as u64;
            }
            // A truncation, shorter or longer.
            78..=85 => {
                let size = if rng.below(4) == 0 {
                    model.len() + len / 4
                } else {
                    at.min(model.len() as u64) as usize
                };
                model.resize(size, 0);
                for s in sides.iter_mut() {
                    s.fs.truncate(s.file, size as u32).unwrap();
                    s.fs.seek(s.file, 0, Whence::Set).unwrap();
                }
                pos = 0;
            }
            // A sync.
            86..=89 => {
                for s in sides.iter_mut() {
                    s.fs.sync(s.file).unwrap();
                }
            }
            // The file closed and opened again, and the volume mounted again now and then.
            90..=94 => {
                let remount = rng.below(4) == 0;
                for s in sides.iter_mut() {
                    s.fs.close(s.file).unwrap();
                    if remount {
                        s.fs.unmount().unwrap();
                        s.fs.device().flush().unwrap();
                        s.fs.mount().unwrap();
                    }
                    s.file = s.fs.open(b"/f", Open::READ_WRITE).unwrap();
                }
                pos = 0;
            }
            // A read of the whole file from the start, in calls of a size drawn at random.
            _ => {
                let call = 1 + rng.below(20_000) as usize;
                for s in sides.iter_mut() {
                    s.fs.seek(s.file, 0, Whence::Set).unwrap();
                    let mut got = Vec::new();
                    let mut buf = vec![0u8; call];
                    loop {
                        let n = s.fs.read(s.file, &mut buf).unwrap();
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                    }
                    assert!(
                        got == model,
                        "step {step}: the whole file in calls of {call}"
                    );
                }
                pos = model.len() as u64;
            }
        }
        for s in sides.iter_mut() {
            assert_eq!(
                s.fs.size(s.file).unwrap(),
                model.len() as u64,
                "step {step}"
            );
        }
    }
    let mut media = Vec::new();
    for mut s in sides {
        s.fs.close(s.file).unwrap();
        s.fs.unmount().unwrap();
        let mut dev = s.fs.into_device();
        dev.flush().unwrap();
        media.push(dev);
    }
    for m in &media[1..] {
        assert!(
            m.medium() == media[0].medium(),
            "the disk with wayposts is not the disk without"
        );
    }
}

#[test]
fn random_operations_read_the_same_bytes_with_and_without_wayposts() {
    for seed in 1..=6u64 {
        same_answers(seed * 7919, 400, &[0, 1, 3, 16]);
    }
}

#[test]
fn reads_after_a_truncation_and_a_rewrite_in_place() {
    let mut fs = volume_with_file(1024, 600_000, 16);
    let f = fs.open(b"/f", Open::READ_WRITE).unwrap();
    let mut model = pattern(0, 600_000);
    let check = |fs: &mut Vol, model: &[u8]| {
        for start in [
            0usize,
            1,
            4087,
            4088,
            100_000,
            model.len().saturating_sub(5000),
        ] {
            fs.seek(f, start as i32, Whence::Set).unwrap();
            let mut got = Vec::new();
            let mut buf = vec![0u8; 3000];
            loop {
                let n = fs.read(f, &mut buf).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert!(got == model[start.min(model.len())..], "from {start}");
        }
    };
    check(&mut fs, &model);
    // Truncated to the middle of a block, then to a block boundary, read each time.
    for size in [300_001usize, 250_000, 12_345, 4088, 1] {
        fs.truncate(f, size as u32).unwrap();
        model.truncate(size);
        check(&mut fs, &model);
    }
    // Longer again with zeros, and rewritten in place from the start, in the middle and at the end.
    for (at, len) in [
        (0usize, 700_000usize),
        (350_000, 3),
        (699_999, 1),
        (123_456, 9000),
    ] {
        let data = pattern(at as u64 + 99, len.min(100_000));
        if model.len() < at + data.len() {
            model.resize(at + data.len(), 0);
        }
        model[at..at + data.len()].copy_from_slice(&data);
        fs.seek(f, at as i32, Whence::Set).unwrap();
        fs.write(f, &data).unwrap();
        check(&mut fs, &model);
    }
}

/// The bytes of the file `/f` read in calls of `call` bytes after jumping to the places of `jumps`
/// (a failure is part of the answer).
fn what_a_reader_sees(
    device: &MemDevice,
    hints: u32,
    call: usize,
) -> Vec<Result<Vec<u8>, crate::Error>> {
    let mut fs = attach(device.clone());
    fs.set_ctz_hints(hints);
    fs.mount().unwrap();
    let mut answers = Vec::new();
    let f = match fs.open(b"/f", Open::READ) {
        Ok(f) => f,
        Err(e) => return vec![Err(e)],
    };
    let mut buf = vec![0u8; call];
    let mut all = Vec::new();
    loop {
        match fs.read(f, &mut buf) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(e) => {
                answers.push(Err(e));
                break;
            }
        }
    }
    answers.push(Ok(all));
    for jump in [200_000i32, 5, 399_000, 123_456, 0] {
        let _ = fs.seek(f, jump, Whence::Set);
        answers.push(fs.read(f, &mut buf).map(|n| buf[..n].to_vec()));
    }
    answers
}

#[test]
fn a_cut_at_every_sector_of_a_large_write_reads_the_same_with_and_without_wayposts() {
    // The file is 150 KiB; one write overwrites its middle and runs past its end, 300 KiB in all,
    // and is synced. A cut at every sector of it, with the cache sectors that reach the disk drawn
    // in three ways.
    let mut fs = volume_with_file(512, 150_000, 16);
    let base = {
        fs.unmount().unwrap();
        let mut d = fs.into_device();
        d.flush().unwrap();
        d
    };
    let op = |fs: &mut Vol| {
        if let Ok(f) = fs.open(b"/f", Open::READ_WRITE) {
            let _ = fs.seek(f, 40_000, Whence::Set);
            let _ = fs.write(f, &pattern(7, 300_000));
            let _ = fs.sync(f);
        }
    };
    let mut probe = attach(base.clone());
    probe.mount().unwrap();
    let before = probe.device().written;
    op(&mut probe);
    let sectors = probe.device().written - before;
    assert!(sectors > 500, "{sectors} sectors");
    for cut in 0..=sectors {
        for survive in [
            crate::mem::Survive::None,
            crate::mem::Survive::All,
            crate::mem::Survive::Random(cut + 3),
        ] {
            let mut fs = attach(base.clone());
            fs.mount().unwrap();
            fs.device().cut_after(Some(cut));
            op(&mut fs);
            let mut dev = fs.into_device();
            dev.power_cycle(survive);
            let a = what_a_reader_sees(&dev, 0, 6000);
            let b = what_a_reader_sees(&dev, 16, 6000);
            assert!(a == b, "cut {cut} {survive:?}: the reads differ");
        }
    }
}

#[test]
fn a_head_given_out_again_at_the_same_size_does_not_match_old_wayposts() {
    // The head of an old list is freed once the new one is synced, and the allocator can hand it out
    // again at the same size with other blocks inside: the pair (head, size) alone is no proof.
    // Only the drop at a write tells the lists apart. A small volume and a second file of varying
    // length make the allocator reuse blocks in many orders; the reads with the wayposts of an old
    // list in the handle must give the bytes of the new one.
    let size = 40_000usize;
    let mut fs = volume_with_file(48, size as u64, 16);
    let f = fs.open(b"/f", Open::READ_WRITE).unwrap();
    let mut model = pattern(0, size);
    let mut era = 1u64;
    for k in 1..=120usize {
        fs.seek(f, 0, Whence::Set).unwrap();
        let mut one = [0u8; 1];
        fs.read(f, &mut one).unwrap();
        for _ in 0..k {
            era += 1;
            model = pattern(era * 1_000_003, size);
            fs.seek(f, 0, Whence::Set).unwrap();
            let g = fs
                .open(b"/g", Open::WRITE.with(Open::CREATE).with(Open::TRUNCATE))
                .unwrap();
            let half = size / 2;
            fs.write(f, &model[..half]).unwrap();
            fs.write(g, &pattern(era, 4096 * (1 + (era as usize * 7) % 5)))
                .unwrap();
            fs.sync(g).unwrap();
            fs.write(f, &model[half..]).unwrap();
            fs.sync(f).unwrap();
            fs.close(g).unwrap();
        }
        for start in [0usize, 5000, 20_000, 39_000] {
            fs.seek(f, start as i32, Whence::Set).unwrap();
            let mut buf = vec![0u8; size - start];
            let n = fs.read(f, &mut buf).unwrap();
            assert!(buf[..n] == model[start..], "k {k} start {start}");
        }
    }
}

#[test]
fn a_reader_keeps_the_old_snapshot_while_another_handle_rewrites_the_file() {
    // B reads (and leaves wayposts), A rewrites the file and syncs, other files make the allocator
    // hand out blocks: B goes on reading the snapshot it opened, the same with and without wayposts
    // (littlefs marks B dusty and its walk keeps the blocks of B's list).
    for hints in [0u32, 16] {
        let size = 120_000usize;
        let mut fs = volume_with_file(160, size as u64, hints);
        let old = pattern(0, size);
        let b = fs.open(b"/f", Open::READ).unwrap();
        let mut buf = vec![0u8; 5000];
        for at in [100_000i32, 60_000, 0] {
            fs.seek(b, at, Whence::Set).unwrap();
            fs.read(b, &mut buf).unwrap();
        }
        for round in 1..=4u64 {
            let a = fs.open(b"/f", Open::READ_WRITE).unwrap();
            fs.write(a, &pattern(round * 77, size)).unwrap();
            fs.sync(a).unwrap();
            fs.close(a).unwrap();
            for n in 0..6 {
                let name = std::format!("/x{n}");
                let x = fs
                    .open(
                        name.as_bytes(),
                        Open::WRITE.with(Open::CREATE).with(Open::TRUNCATE),
                    )
                    .unwrap();
                fs.write(x, &pattern(round * 10 + n, 30_000)).unwrap();
                fs.close(x).unwrap();
            }
            for start in [0usize, 4088, 30_000, 99_999, 119_000] {
                fs.seek(b, start as i32, Whence::Set).unwrap();
                let mut got = vec![0u8; size - start];
                let n = fs.read(b, &mut got).unwrap();
                assert!(
                    got[..n] == old[start..start + n] && n == size - start,
                    "wayposts {hints}, round {round}, from {start}"
                );
            }
        }
    }
}
