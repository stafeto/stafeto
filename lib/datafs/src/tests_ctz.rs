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
fn volume_with_file(blocks: u64, bytes: u64) -> Vol {
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

fn table(hints: bool) {
    let _ = hints;
    std::println!("| file | blocks | call | reads | reads per block |");
    std::println!("|---:|---:|---:|---:|---:|");
    for mib in [1u64, 4, 16, 64] {
        let bytes = mib << 20;
        let blocks = bytes / BLOCK_DATA + 1;
        let device_blocks = blocks + blocks / 8 + 64;
        for call in [4096usize, 65536] {
            let mut fs = volume_with_file(device_blocks, bytes);
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
    table(true);
}

#[test]
fn a_small_file_reads_back() {
    let mut fs = volume_with_file(512, 300_000);
    read_all(&mut fs, 300_000, 4096);
    let f = fs.open(b"/f", Open::READ).unwrap();
    fs.seek(f, 0, Whence::Set).unwrap();
}
