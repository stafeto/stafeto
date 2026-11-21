// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the jobs of the file service cost in calls to the block device, counted on the host.
//!
//! littlefs runs over a `MemDevice` that counts its reads, programs and flushes (the erases are
//! counted on the C side). Every table row is a count; the time column is derived from those counts
//! with ASSUMED device costs (`READ_US`, `PROGRAM_US`, `FLUSH_US`), which come from the plan's
//! rate of 10,000 reads a second and are not measured on any real disk. The counts are exact, the
//! time is only as good as the assumption.
//!
//! The fast tests run with the normal `cargo test` and guard the properties the file service
//! relies on at a small scale. The slow ones (volumes of 256 MiB and more) are `#[ignore]` and run by
//! name, in an optimised build, which prints the tables:
//!
//! ```text
//! CARGO_PROFILE_DEV_OPT_LEVEL=3 cargo test -p datafs --lib tests_scale -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The allocator's window is one bit for each block of the volume, which is what the service has; a
//! window of 128 bytes (the first release's) is a test-only switch (`Fs::set_lookahead`, `Win::Narrow`)
//! kept for the comparison.

use crate::fs::{Fs, Open, Storage, Whence};
use crate::mem::{MemDevice, Survive};
use crate::server::recover_orphans;
use crate::{BLOCK, BLOCK_SECTORS, Device, Error};
use std::boxed::Box;
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

/// The assumed cost of one read call of the device, in microseconds: the plan's 10,000 reads a
/// second.
const READ_US: f64 = 100.0;
/// The assumed cost of one program call (a write of up to 4 KiB). An assumption.
const PROGRAM_US: f64 = 100.0;
/// The assumed cost of one flush of the device. An assumption.
const FLUSH_US: f64 = 1000.0;
/// A block device in the file service has no erase: the C side counts the calls littlefs makes,
/// and the time of an erase is taken as zero.
const ERASE_US: f64 = 0.0;

type Vol = Fs<'static, MemDevice>;
type Res<T> = Result<T, Error>;

/// The size of the allocator's window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Win {
    /// The 128 bytes release 0.5.1 had: 1024 blocks (set by the test-only switch).
    Narrow,
    /// One bit for every block of the volume: the service's window now.
    Whole,
}

impl Win {
    fn name(self) -> &'static str {
        match self {
            Win::Narrow => "128 B",
            Win::Whole => "whole",
        }
    }
}

/// The calls the device and the volume have seen so far.
#[derive(Clone, Copy, Debug, Default)]
struct Cost {
    reads: u64,
    sectors: u64,
    programs: u64,
    erases: u64,
    flushes: u64,
}

impl Cost {
    fn since(self, then: Cost) -> Cost {
        Cost {
            reads: self.reads - then.reads,
            sectors: self.sectors - then.sectors,
            programs: self.programs - then.programs,
            erases: self.erases - then.erases,
            flushes: self.flushes - then.flushes,
        }
    }

    fn ms(self) -> f64 {
        (self.reads as f64 * READ_US
            + self.programs as f64 * PROGRAM_US
            + self.erases as f64 * ERASE_US
            + self.flushes as f64 * FLUSH_US)
            / 1000.0
    }
}

fn now(fs: &mut Vol) -> Cost {
    let erases = fs.erases();
    let d = fs.device();
    Cost {
        reads: d.reads,
        sectors: d.read_sectors,
        programs: d.programs,
        erases,
        flushes: d.flushes,
    }
}

/// Counts a job, and the longest single call inside it (a job of many calls is a run of
/// jobs of the service: each call of the service is one job of its worker).
struct Meter {
    last: Cost,
    worst: Cost,
}

impl Meter {
    fn new(fs: &mut Vol) -> Self {
        Self {
            last: now(fs),
            worst: Cost::default(),
        }
    }

    /// Closes the call that just ran.
    fn lap(&mut self, fs: &mut Vol) {
        let at = now(fs);
        let call = at.since(self.last);
        if call.ms() > self.worst.ms() {
            self.worst = call;
        }
        self.last = at;
    }
}

fn attach(device: MemDevice, win: Win) -> Vol {
    let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
    let mut fs = Fs::new(device, state).unwrap();
    if win == Win::Narrow {
        // The window the first release had; the service's own is one bit for every block.
        fs.set_lookahead(Box::leak(vec![0u8; 128].into_boxed_slice()));
    }
    fs
}

/// A new volume of `blocks` blocks, formatted and mounted.
fn fresh(blocks: u64, win: Win) -> Vol {
    let mut fs = attach(MemDevice::new(blocks * BLOCK_SECTORS), win);
    fs.format().unwrap();
    fs.mount().unwrap();
    fs
}

/// A copy of `device` mounted with the window `win`: the state of a service that has just started.
fn mounted(device: &MemDevice, win: Win) -> Vol {
    let mut fs = attach(device.clone(), win);
    fs.mount().unwrap();
    fs
}

fn settle(mut fs: Vol) -> MemDevice {
    fs.unmount().unwrap();
    let mut device = fs.into_device();
    device.flush().unwrap();
    device
}

/// Writes `total` bytes to the open file in calls of `call` bytes, closing each call as a lap.
fn write_calls(
    fs: &mut Vol,
    meter: &mut Meter,
    f: crate::File,
    total: usize,
    call: usize,
) -> Res<()> {
    let data = vec![0xA5u8; call];
    let mut left = total;
    while left > 0 {
        let n = left.min(call);
        fs.write(f, &data[..n])?;
        meter.lap(fs);
        left -= n;
    }
    Ok(())
}

/// A file made, written in calls of 1 KiB, synced and closed.
fn put(fs: &mut Vol, meter: &mut Meter, path: &str, bytes: usize) -> Res<()> {
    let f = fs.open(path.as_bytes(), Open::WRITE.with(Open::CREATE))?;
    meter.lap(fs);
    write_calls(fs, meter, f, bytes, 1024)?;
    fs.sync(f)?;
    meter.lap(fs);
    fs.close(f)?;
    meter.lap(fs);
    Ok(())
}

#[derive(Clone, Copy)]
struct Layout {
    name: &'static str,
    file_bytes: usize,
    dirs: usize,
}

const BIG_FILES: Layout = Layout {
    name: "1 MiB files",
    file_bytes: 1 << 20,
    dirs: 4,
};
const SMALL_FILES: Layout = Layout {
    name: "16 KiB files",
    file_bytes: 16 << 10,
    dirs: 64,
};

/// Fills the volume with files of the layout, up to `percent` of its blocks (100 goes on until the
/// volume says it is full). Written in calls of 64 KiB.
fn fill(fs: &mut Vol, layout: Layout, percent: u64) {
    if percent == 0 {
        return;
    }
    for d in 0..layout.dirs {
        fs.mkdir(format!("/d{d}").as_bytes()).unwrap();
    }
    let target = if percent >= 100 {
        u64::MAX
    } else {
        fs.blocks() * BLOCK as u64 * percent / 100
    };
    let data = vec![0x5Au8; 64 << 10];
    let (mut written, mut i) = (0u64, 0usize);
    'files: loop {
        if written >= target {
            break;
        }
        let path = format!("/d{}/n{i}", i % layout.dirs);
        i += 1;
        let Ok(f) = fs.open(path.as_bytes(), Open::WRITE.with(Open::CREATE)) else {
            break;
        };
        let mut left = layout.file_bytes;
        while left > 0 {
            let n = left.min(data.len());
            match fs.write(f, &data[..n]) {
                Ok(done) if done == n => {}
                _ => {
                    let _ = fs.close(f);
                    break 'files;
                }
            }
            written += n as u64;
            left -= n;
        }
        if fs.close(f).is_err() {
            break;
        }
    }
}

/// A volume in a given state: the device, settled.
fn image(blocks: u64, layout: Layout, percent: u64) -> MemDevice {
    let mut fs = fresh(blocks, Win::Whole);
    fill(&mut fs, layout, percent);
    settle(fs)
}

fn gib(blocks: u64) -> f64 {
    (blocks * BLOCK as u64) as f64 / (1u64 << 30) as f64
}

const COLS: &str = "| job | state | window | reads | read sectors | programs | erases | flushes | worst call ms | derived ms |";

fn header(title: &str) {
    std::println!("\n### {title}\n");
    std::println!("{COLS}");
    std::println!("|---|---|---|---:|---:|---:|---:|---:|---:|---:|");
}

fn row(job: &str, state: &str, win: &str, c: Cost, worst: Cost) {
    std::println!(
        "| {job} | {state} | {win} | {} | {} | {} | {} | {} | {:.1} | {:.1} |",
        c.reads,
        c.sectors,
        c.programs,
        c.erases,
        c.flushes,
        worst.ms(),
        c.ms()
    );
}

// ---------------------------------------------------------------------------------------------
// The walk of the volume: lfs_fs_size, which is what STATFS does today.
// ---------------------------------------------------------------------------------------------

/// The reads of one `used_blocks` on a freshly mounted volume.
fn traverse_cost(device: &MemDevice) -> (Cost, u64) {
    let mut fs = mounted(device, Win::Whole);
    let at = now(&mut fs);
    let used = fs.used_blocks().unwrap();
    let cost = now(&mut fs).since(at);
    (cost, used)
}

#[test]
fn the_walk_reads_about_a_block_per_block_of_data() {
    // A volume of 16 MiB, half full of 64 KiB files: the walk reads every data block of every file.
    let blocks = 4096;
    let small = Layout {
        name: "64 KiB files",
        file_bytes: 64 << 10,
        dirs: 2,
    };
    let empty = image(blocks, small, 0);
    let half = image(blocks, small, 50);
    let (e, _) = traverse_cost(&empty);
    let (h, used) = traverse_cost(&half);
    assert!(
        e.reads <= 8,
        "an empty volume is walked in {} reads",
        e.reads
    );
    assert!(
        used >= blocks / 2 && h.reads >= used / 2,
        "a half full volume of {used} blocks is walked in {} reads",
        h.reads
    );
    assert!(h.reads <= used * 2, "{} reads for {used} blocks", h.reads);
}

#[test]
#[ignore = "slow: volumes of 256 MiB; run by name, see the module text"]
fn scale_traverse() {
    std::println!("\n## Walk of the volume (lfs_fs_size, today's STATFS), volume of 256 MiB\n");
    std::println!(
        "| layout | filled | blocks in use | reads | read sectors | reads per GiB of volume | reads per used block | derived s (volume) | derived s per GiB |"
    );
    std::println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
    let blocks = 65536u64;
    for layout in [BIG_FILES, SMALL_FILES] {
        for percent in [0, 25, 50, 100] {
            let img = image(blocks, layout, percent);
            let (c, used) = traverse_cost(&img);
            std::println!(
                "| {} | {percent} % | {used} | {} | {} | {:.0} | {:.2} | {:.2} | {:.2} |",
                layout.name,
                c.reads,
                c.sectors,
                c.reads as f64 / gib(blocks),
                c.reads as f64 / used.max(1) as f64,
                c.ms() / 1000.0,
                c.ms() / 1000.0 / gib(blocks)
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The allocator: how often it walks the volume.
// ---------------------------------------------------------------------------------------------

#[derive(Default, Debug)]
struct Run {
    scans: u64,
    calls_that_walked: u64,
    walk_reads: u64,
    most_walks_in_a_call: u64,
    cost: Cost,
    worst: Cost,
}

/// How many times the allocator refilled its window during one call. The allocator's cursor
/// (the window's start plus its next block) moves forward by one for every block it passes. After
/// the refills of a call the cursor stands `next` blocks into the last window, and each refill
/// moved the window's start by one whole window.
fn walks_in_call(blocks: u64, before: (u32, u32, u32), after: (u32, u32, u32)) -> u64 {
    let pos = |w: (u32, u32, u32)| (u64::from(w.0) + u64::from(w.1)) % blocks;
    let advance = (pos(after) + blocks - pos(before)) % blocks;
    let size = u64::from(after.2).max(1);
    let first = u64::from(before.2 == 0 && after.2 != 0);
    let passed = u64::from(before.1) + advance;
    first + passed.saturating_sub(u64::from(after.1)) / size
}

/// Writes `total` bytes in files of `file_bytes` (calls of 1 KiB, a sync and a close for each file)
/// and counts the walks of the volume the allocator made, found from its window (`walks_in_call`).
/// `walk_reads` holds the reads of the calls that walked, and `calls_that_walked` their number.
fn write_and_count(fs: &mut Vol, total: usize, file_bytes: usize, prefix: &str) -> Run {
    let blocks = fs.blocks();
    let start = now(fs);
    let mut run = Run::default();
    let data = vec![0xC3u8; 1024];
    let files = total / file_bytes;
    let mut worst = Cost::default();
    for n in 0..files {
        let path = format!("/{prefix}{n}");
        let f = fs
            .open(path.as_bytes(), Open::WRITE.with(Open::CREATE))
            .unwrap();
        for _ in 0..file_bytes / 1024 {
            let before = now(fs);
            let w0 = fs.window_state();
            fs.write(f, &data).unwrap();
            let after = now(fs);
            let w1 = fs.window_state();
            let call = after.since(before);
            let walks = walks_in_call(blocks, w0, w1);
            if walks > 0 {
                run.scans += walks;
                run.calls_that_walked += 1;
                run.walk_reads += call.reads;
                run.most_walks_in_a_call = run.most_walks_in_a_call.max(walks);
            }
            if call.ms() > worst.ms() {
                worst = call;
            }
        }
        let before = now(fs);
        fs.sync(f).unwrap();
        fs.close(f).unwrap();
        let call = now(fs).since(before);
        if call.ms() > worst.ms() {
            worst = call;
        }
    }
    run.cost = now(fs).since(start);
    run.worst = worst;
    run
}

#[test]
fn the_wide_window_walks_the_volume_once_where_the_service_window_walks_it_often() {
    // 64 MiB volume, 16 MiB written: the 128 byte window covers 4 MiB, so the walk repeats every
    // 4 MiB of new blocks; a window for the whole volume walks once.
    let blocks = 16384u64;
    let img = image(blocks, BIG_FILES, 0);
    let mut narrow = mounted(&img, Win::Narrow);
    let a = write_and_count(&mut narrow, 16 << 20, 1 << 20, "w");
    let mut wide = mounted(&img, Win::Whole);
    let b = write_and_count(&mut wide, 16 << 20, 1 << 20, "w");
    assert!(
        a.scans >= 4,
        "the window of 128 bytes walked {} times for 16 MiB",
        a.scans
    );
    assert_eq!(b.scans, 1, "the whole window walks once for 16 MiB");
}

#[test]
fn a_small_window_crawls_through_a_used_region_in_one_call_and_a_wide_one_does_not() {
    // A volume of 64 MiB, half full: the first write after a mount starts looking at a block the
    // mount chose, and with a window of 1024 blocks it walks the volume once for every 1024 used
    // blocks it passes, all inside one call of the service.
    // Where the window starts depends on the volume (the mount takes the start from a checksum),
    // so the volumes of four fill levels are tried and the worst of them counts.
    let (mut crawl, mut narrow_reads, mut wide_reads) = (0, 0, 0);
    for percent in [40, 50, 60, 70] {
        let img = image(16384, BIG_FILES, percent);
        let mut narrow = mounted(&img, Win::Narrow);
        let a = write_and_count(&mut narrow, 4 << 20, 1 << 20, "w");
        let mut wide = mounted(&img, Win::Whole);
        let b = write_and_count(&mut wide, 4 << 20, 1 << 20, "w");
        assert_eq!(
            b.most_walks_in_a_call, 1,
            "the whole window walks once in a call"
        );
        if a.most_walks_in_a_call > crawl {
            (crawl, narrow_reads, wide_reads) =
                (a.most_walks_in_a_call, a.worst.reads, b.worst.reads);
        }
    }
    assert!(
        crawl >= 3,
        "the window of 128 bytes walked {crawl} times in one call at most"
    );
    assert!(
        narrow_reads >= 2 * wide_reads,
        "{narrow_reads} reads in a call against {wide_reads}"
    );
}

#[test]
#[ignore = "slow: volumes of 256 MiB; run by name, see the module text"]
fn scale_allocator() {
    std::println!(
        "\n## Walks of the volume by the allocator: 64 MiB written in 1 MiB files by calls of 1 KiB, volume of 256 MiB\n"
    );
    std::println!(
        "| layout | filled | window | walks | most walks in one call | reads in all | reads per walk (mean, over the calls that walked) | reads of the longest call | programs | erases | flushes | derived s in all | longest call ms |"
    );
    std::println!("|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    let blocks = 65536u64;
    for layout in [BIG_FILES, SMALL_FILES] {
        // The 16 KiB files take more blocks than their bytes (the blocks in use are in the table
        // of the walk), so the last step is left out for them: 64 MiB more would not fit.
        let steps: &[u64] = if layout.file_bytes < 1 << 20 {
            &[0, 25, 50]
        } else {
            &[0, 25, 50, 70]
        };
        for &percent in steps {
            let img = image(blocks, layout, percent);
            for win in [Win::Whole, Win::Narrow] {
                let mut fs = mounted(&img, win);
                let run = write_and_count(&mut fs, 64 << 20, 1 << 20, "w");
                let mean = if run.scans == 0 {
                    0.0
                } else {
                    run.walk_reads as f64 / run.scans as f64
                };
                std::println!(
                    "| {} | {percent} % | {} | {} | {} | {} | {:.0} | {} | {} | {} | {} | {:.2} | {:.1} |",
                    layout.name,
                    win.name(),
                    run.scans,
                    run.most_walks_in_a_call,
                    run.cost.reads,
                    mean,
                    run.worst.reads,
                    run.cost.programs,
                    run.cost.erases,
                    run.cost.flushes,
                    run.cost.ms() / 1000.0,
                    run.worst.ms()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// STATFS: the walk against the count of free blocks from the window's bits.
// ---------------------------------------------------------------------------------------------

#[test]
fn free_blocks_from_the_window_agree_with_the_walk_and_read_nothing() {
    let blocks = 4096u64;
    let mut fs = fresh(blocks, Win::Whole);
    let mut m = Meter::new(&mut fs);
    put(&mut fs, &mut m, "/a", 300 << 10).unwrap();
    put(&mut fs, &mut m, "/b", 1 << 20).unwrap();
    fs.mkdir(b"/dir").unwrap();
    put(&mut fs, &mut m, "/dir/c", 5000).unwrap();
    // The window was filled by the first allocation: the count reads no block.
    let at = now(&mut fs);
    let free = fs.free_blocks().unwrap();
    assert_eq!(
        now(&mut fs).since(at).reads,
        0,
        "counting the bits reads no block"
    );
    let used = fs.used_blocks().unwrap();
    assert_eq!(
        free,
        blocks - used,
        "the window counts what the walk counts"
    );
    // After a mount the window is empty: the first count makes the walk, the next ones read nothing.
    let mut fs = mounted(&settle(fs), Win::Whole);
    let at = now(&mut fs);
    let first = fs.free_blocks().unwrap();
    let walk = now(&mut fs).since(at);
    assert!(walk.reads > 0 && walk.programs == 0 && walk.erases == 0);
    let at = now(&mut fs);
    assert_eq!(fs.free_blocks().unwrap(), first);
    assert_eq!(now(&mut fs).since(at).reads, 0);
    assert_eq!(first, blocks - fs.used_blocks().unwrap());
    // Blocks freed after the last walk are not seen: fewer free than there are, never more.
    fs.remove(b"/b").unwrap();
    let truth = blocks - fs.used_blocks().unwrap();
    let seen = fs.free_blocks().unwrap();
    assert!(seen <= truth, "{seen} free seen, {truth} free");
    assert!(seen < truth, "the freed blocks wait for the next walk");
    // The estimate of what was freed is the callers' (the server knows the size it removes).
    fs.note_freed_file(1 << 20);
    assert_eq!(fs.freed_estimate(), 256);
    // A walk sees them and starts the estimate again.
    fs.walk().unwrap();
    assert_eq!(fs.freed_estimate(), 0);
    assert_eq!(fs.free_blocks().unwrap(), truth);
    // The window of 128 bytes sees at most its 1024 blocks: it cannot answer for a larger volume.
    let mut narrow = fresh(blocks, Win::Narrow);
    let mut m = Meter::new(&mut narrow);
    put(&mut narrow, &mut m, "/a", 4096).unwrap();
    assert!(narrow.window_free() <= 1024);
}

#[test]
fn statfs_through_the_server_reads_nothing_after_the_first_walk() {
    let mut fs = fresh(4096, Win::Whole);
    let mut m = Meter::new(&mut fs);
    put(&mut fs, &mut m, "/a", 200 << 10).unwrap();
    let mut fs = mounted(&settle(fs), Win::Whole);
    let mut server = crate::server::Server::with_epoch(1);
    let mut statfs = |fs: &mut Vol| {
        let mut w = proto_wire::Writer::new();
        proto_data::statfs(&mut w).unwrap();
        let reply = server.handle(fs, 1, 0, w.as_bytes());
        let mut r = proto_data::reply(reply.as_bytes()).unwrap();
        let (blocks, free, avail) = (r.u64().unwrap(), r.u64().unwrap(), r.u64().unwrap());
        assert!(avail <= free && free <= blocks);
        (blocks, blocks - free, r.u32().unwrap())
    };
    let (blocks, used, unit) = statfs(&mut fs);
    assert_eq!((blocks, unit), (4096, 4096));
    assert_eq!(used, 4096 - fs.free_blocks().unwrap());
    let at = now(&mut fs);
    for _ in 0..5 {
        assert_eq!(statfs(&mut fs), (blocks, used, unit));
    }
    assert_eq!(now(&mut fs).since(at).reads, 0, "STATFS reads no block");
    assert_eq!(used, fs.used_blocks().unwrap());
}

#[test]
fn a_walk_only_reads_and_a_failed_one_leaves_a_volume_that_mounts() {
    // The walk marks blocks in memory and reads the device; it never writes, so a cut of the power
    // during a walk leaves the medium as it was. The medium is the same bytes after a walk, and a
    // walk that fails on a dead device leaves nothing to repair.
    let mut fs = fresh(1024, Win::Whole);
    let mut m = Meter::new(&mut fs);
    fs.mkdir(b"/d").unwrap();
    put(&mut fs, &mut m, "/d/f", 100 << 10).unwrap();
    let mut device = settle(fs);
    let before = device.medium().to_vec();
    let mut fs = mounted(&device, Win::Whole);
    let at = now(&mut fs);
    fs.walk().unwrap();
    let c = now(&mut fs).since(at);
    assert!(c.reads > 0);
    assert_eq!(
        (c.programs, c.erases, c.flushes),
        (0, 0, 0),
        "a walk writes nothing"
    );
    let mut after = fs.into_device();
    after.flush().unwrap();
    assert_eq!(after.medium(), &before[..], "the medium is as it was");

    // The device dies (a write after a cut at 0 sectors), then the walk: it fails.
    let mut fs = mounted(&device, Win::Whole);
    fs.device().cut_after(Some(0));
    assert!(fs.mkdir(b"/x").is_err());
    assert!(fs.walk().is_err(), "a walk on a dead device fails");
    let mut dead = fs.into_device();
    dead.power_cycle(Survive::None);
    let mut fs = attach(dead, Win::Whole);
    fs.mount().unwrap();
    assert_eq!(fs.stat(b"/d/f").unwrap().size, 100 << 10);
    assert_eq!(fs.stat(b"/x"), Err(Error::NoEntry));
    fs.walk().unwrap();
    device.power_cycle(Survive::All);
}

fn served(
    server: &mut crate::server::Server,
    fs: &mut Vol,
    build: &dyn Fn(&mut proto_wire::Writer),
) -> Result<Vec<u8>, proto_wire::Status> {
    let mut w = proto_wire::Writer::new();
    build(&mut w);
    let reply = server.handle(fs, 1, 0, w.as_bytes());
    proto_data::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
}

/// A file made through the protocol, written in calls of 900 bytes and synced; closed unless
/// `keep_open`, and the handle.
fn made(
    server: &mut crate::server::Server,
    fs: &mut Vol,
    path: &[u8],
    len: usize,
    keep_open: bool,
) -> u32 {
    use proto_data as p;
    let h = served(server, fs, &|w| {
        p::open(path, p::READ | p::WRITE | p::CREATE, 0o644, w).unwrap()
    })
    .unwrap();
    let h = u32::from_le_bytes(h[..4].try_into().unwrap());
    let data = vec![7u8; 900];
    let mut left = len;
    while left > 0 {
        let n = left.min(900);
        served(server, fs, &|w| p::write(h, &data[..n], w).unwrap()).unwrap();
        left -= n;
    }
    served(server, fs, &|w| {
        p::handle_call(p::Method::Fsync, h, w).unwrap()
    })
    .unwrap();
    if !keep_open {
        served(server, fs, &|w| {
            p::handle_call(p::Method::Close, h, w).unwrap()
        })
        .unwrap();
    }
    h
}

#[test]
fn freed_blocks_are_counted_by_what_the_server_knows() {
    use crate::server::Server;
    use proto_data as p;
    let mut fs = fresh(1024, Win::Whole);
    let mut server = Server::with_epoch(1);
    made(&mut server, &mut fs, b"/big", 40 << 10, false);
    made(&mut server, &mut fs, b"/tiny", 100, false);
    made(&mut server, &mut fs, b"/over", 20 << 10, false);
    made(&mut server, &mut fs, b"/with", 1000, false);
    assert_eq!(fs.freed_estimate(), 0);
    // A file of 40 KiB is 10 blocks; an inline file owns none.
    served(&mut server, &mut fs, &|w| {
        p::path_call(p::Method::Unlink, b"/big", w).unwrap()
    })
    .unwrap();
    assert_eq!(fs.freed_estimate(), 10);
    served(&mut server, &mut fs, &|w| {
        p::path_call(p::Method::Unlink, b"/tiny", w).unwrap()
    })
    .unwrap();
    assert_eq!(fs.freed_estimate(), 10, "an inline file owns no block");
    // A rename over a file gives the replaced file's blocks back (20 KiB: 5 blocks).
    served(&mut server, &mut fs, &|w| {
        p::rename(b"/with", b"/over", w).unwrap()
    })
    .unwrap();
    assert_eq!(fs.freed_estimate(), 15);
    // An open file that is unlinked gives its blocks back at the last close.
    let h = made(&mut server, &mut fs, b"/open", 8192, true);
    served(&mut server, &mut fs, &|w| {
        p::path_call(p::Method::Unlink, b"/open", w).unwrap()
    })
    .unwrap();
    assert_eq!(fs.freed_estimate(), 15);
    served(&mut server, &mut fs, &|w| {
        p::handle_call(p::Method::Close, h, w).unwrap()
    })
    .unwrap();
    assert_eq!(fs.freed_estimate(), 17);
    // A directory's pair, and a failed remove counts nothing.
    served(&mut server, &mut fs, &|w| {
        p::mkdir(b"/d", 0o755, w).unwrap()
    })
    .unwrap();
    served(&mut server, &mut fs, &|w| {
        p::path_call(p::Method::Rmdir, b"/d", w).unwrap()
    })
    .unwrap();
    assert_eq!(fs.freed_estimate(), 19);
    assert!(
        served(&mut server, &mut fs, &|w| p::path_call(
            p::Method::Unlink,
            b"/missing",
            w
        )
        .unwrap())
        .is_err()
    );
    assert_eq!(fs.freed_estimate(), 19);
    // A truncation counts the blocks it cuts; a walk starts the estimate again.
    made(&mut server, &mut fs, b"/t", 20 << 10, false);
    let f = fs.open(b"/t", Open::READ_WRITE).unwrap();
    fs.truncate(f, 4096).unwrap();
    assert_eq!(fs.freed_estimate(), 19 + 4);
    fs.close(f).unwrap();
    fs.walk().unwrap();
    assert_eq!(fs.freed_estimate(), 0);
}

#[test]
#[ignore = "slow: volumes of 256 MiB; run by name, see the module text"]
fn scale_statfs() {
    header("STATFS: the walk (today) against the free count from the window (volume of 256 MiB)");
    let blocks = 65536u64;
    for percent in [0, 50, 100] {
        let img = image(blocks, BIG_FILES, percent);
        let state = format!("{percent} % of 1 MiB files");
        let mut fs = mounted(&img, Win::Whole);
        let at = now(&mut fs);
        let used = fs.used_blocks().unwrap();
        let walk = now(&mut fs).since(at);
        row("STATFS today: lfs_fs_size", &state, "any", walk, walk);
        // The first allocation after a mount fills the window; the count is read after it.
        let mut m = Meter::new(&mut fs);
        let _ = put(&mut fs, &mut m, "/warm", 4096);
        let at = now(&mut fs);
        let free = fs.window_free();
        let bits = now(&mut fs).since(at);
        row(
            "STATFS from the window's bits (whole)",
            &state,
            "whole",
            bits,
            bits,
        );
        let used2 = fs.used_blocks().unwrap();
        std::println!(
            "| (check: bits say {free} free, the walk says {} free) | | | | | | | | | |",
            blocks - used2
        );
        let _ = used;
    }
}

// ---------------------------------------------------------------------------------------------
// The jobs.
// ---------------------------------------------------------------------------------------------

/// The working area every job finds: small files, a 1 MiB and a 16 MiB file, two large
/// directories, a deep path, and a file with a 48-byte attribute.
fn populate(fs: &mut Vol, full: bool) {
    let mut m = Meter::new(fs);
    fs.mkdir(b"/.orphans").unwrap();
    fs.mkdir(b"/w").unwrap();
    fs.mkdir(b"/w/s").unwrap();
    fs.mkdir(b"/w/t").unwrap();
    put(fs, &mut m, "/w/f0", 1024).unwrap();
    put(fs, &mut m, "/w/f1", 1024).unwrap();
    put(fs, &mut m, "/w/f2", 1024).unwrap();
    put(fs, &mut m, "/w/f3", 1024).unwrap();
    put(fs, &mut m, "/w/m1", 1 << 20).unwrap();
    put(fs, &mut m, "/w/m16", if full { 16 << 20 } else { 2 << 20 }).unwrap();
    put(fs, &mut m, "/w/s/x", 1024).unwrap();
    fs.setattr(b"/w/f0", 0x70, &[7u8; 48]).unwrap();
    let mut path = String::from("/w");
    for d in ["a", "b", "c", "d", "e", "f"] {
        path.push('/');
        path.push_str(d);
        fs.mkdir(path.as_bytes()).unwrap();
    }
    put(fs, &mut m, "/w/a/b/c/d/e/f/x", 1024).unwrap();
    fs.setattr(b"/w/a/b/c/d/e/f/x", 0x70, &[7u8; 48]).unwrap();
    let sizes = if full { (1000, 10000) } else { (100, 1000) };
    for big in [("big", sizes.0), ("huge", sizes.1)] {
        fs.mkdir(format!("/w/{}", big.0).as_bytes()).unwrap();
        for i in 0..big.1 {
            let f = fs
                .open(
                    format!("/w/{}/e{i:05}", big.0).as_bytes(),
                    Open::WRITE.with(Open::CREATE),
                )
                .unwrap();
            fs.close(f).unwrap();
        }
    }
}

/// A job a cut of the power interrupts.
type Script = fn(&mut Vol);

struct Job {
    name: &'static str,
    /// The job may take blocks from the allocator, so the state of its window changes the cost.
    allocs: bool,
    run: fn(&mut Vol, &mut Meter),
}

fn open_rw(fs: &mut Vol, path: &str) -> crate::File {
    fs.open(path.as_bytes(), Open::READ_WRITE).unwrap()
}

fn jobs() -> Vec<Job> {
    fn j(name: &'static str, allocs: bool, run: fn(&mut Vol, &mut Meter)) -> Job {
        Job { name, allocs, run }
    }
    vec![
        j("stat, depth 2 (/w/f0)", false, |fs, m| {
            fs.stat(b"/w/f0").unwrap();
            m.lap(fs);
        }),
        j("stat, depth 8", false, |fs, m| {
            fs.stat(b"/w/a/b/c/d/e/f/x").unwrap();
            m.lap(fs);
        }),
        j("getattr 48 B, depth 2", false, |fs, m| {
            let mut b = [0u8; 48];
            assert_eq!(fs.getattr(b"/w/f0", 0x70, &mut b).unwrap(), 48);
            m.lap(fs);
        }),
        j("getattr 48 B, depth 8", false, |fs, m| {
            let mut b = [0u8; 48];
            assert_eq!(fs.getattr(b"/w/a/b/c/d/e/f/x", 0x70, &mut b).unwrap(), 48);
            m.lap(fs);
        }),
        j("getattr 48 B, none set", false, |fs, m| {
            let mut b = [0u8; 48];
            assert_eq!(fs.getattr(b"/w/f1", 0x70, &mut b), Err(Error::NoAttr));
            m.lap(fs);
        }),
        j(
            "stat + getattr 48 B, depth 2 (a stat with permissions)",
            false,
            |fs, m| {
                let mut b = [0u8; 48];
                fs.stat(b"/w/f0").unwrap();
                fs.getattr(b"/w/f0", 0x70, &mut b).unwrap();
                m.lap(fs);
            },
        ),
        j(
            "stat + getattr 48 B, last entry of a 10000 entry directory",
            false,
            |fs, m| {
                let mut b = [0u8; 48];
                fs.stat(b"/w/huge/e09999").unwrap();
                let _ = fs.getattr(b"/w/huge/e09999", 0x70, &mut b);
                m.lap(fs);
            },
        ),
        j("setattr 48 B over an attribute (chmod)", false, |fs, m| {
            fs.setattr(b"/w/f0", 0x70, &[9u8; 48]).unwrap();
            m.lap(fs);
        }),
        j("setattr 48 B, first one on an entry", false, |fs, m| {
            fs.setattr(b"/w/f1", 0x70, &[9u8; 48]).unwrap();
            m.lap(fs);
        }),
        j("create empty file (open, close)", false, |fs, m| {
            let f = fs.open(b"/w/n1", Open::WRITE.with(Open::CREATE)).unwrap();
            fs.close(f).unwrap();
            m.lap(fs);
        }),
        j("create + setattr 48 B (two commits)", false, |fs, m| {
            let f = fs.open(b"/w/n1", Open::WRITE.with(Open::CREATE)).unwrap();
            fs.close(f).unwrap();
            fs.setattr(b"/w/n1", 0x70, &[9u8; 48]).unwrap();
            m.lap(fs);
        }),
        j(
            "create with the attribute in the file configuration, then close",
            false,
            |fs, m| {
                let f = fs
                    .open_with_attr(b"/w/n1", Open::WRITE.with(Open::CREATE), 0x70, &[9u8; 48])
                    .unwrap();
                fs.close(f).unwrap();
                m.lap(fs);
            },
        ),
        j("mkdir", true, |fs, m| {
            fs.mkdir(b"/w/n1").unwrap();
            m.lap(fs);
        }),
        j("mkdir + setattr 48 B", true, |fs, m| {
            fs.mkdir(b"/w/n1").unwrap();
            fs.setattr(b"/w/n1", 0x70, &[9u8; 48]).unwrap();
            m.lap(fs);
        }),
        j("rmdir (empty)", false, |fs, m| {
            fs.remove(b"/w/t").unwrap();
            m.lap(fs);
        }),
        j("rename in the same directory", false, |fs, m| {
            fs.rename(b"/w/f1", b"/w/g1").unwrap();
            m.lap(fs);
        }),
        j("rename into another directory", false, |fs, m| {
            fs.rename(b"/w/f1", b"/w/s/g1").unwrap();
            m.lap(fs);
        }),
        j("rename over an existing file", false, |fs, m| {
            fs.rename(b"/w/f1", b"/w/f2").unwrap();
            m.lap(fs);
        }),
        j("unlink 1 KiB file", false, |fs, m| {
            fs.remove(b"/w/f1").unwrap();
            m.lap(fs);
        }),
        j("unlink 1 MiB file", false, |fs, m| {
            fs.remove(b"/w/m1").unwrap();
            m.lap(fs);
        }),
        j("unlink 16 MiB file", false, |fs, m| {
            fs.remove(b"/w/m16").unwrap();
            m.lap(fs);
        }),
        j("write 1 KiB to an open file, no sync", true, |fs, m| {
            let f = open_rw(fs, "/w/f1");
            m.lap(fs);
            fs.seek(f, 0, Whence::End).unwrap();
            fs.write(f, &[1u8; 1024]).unwrap();
            m.lap(fs);
            // A close writes the file, which is the job of the next call of the service.
            fs.close(f).unwrap();
            m.lap(fs);
        }),
        j("create + write 1 KiB + sync + close", true, |fs, m| {
            put(fs, m, "/w/n1", 1024).unwrap();
        }),
        j(
            "create + write 4 KiB (calls of 1 KiB) + sync + close",
            true,
            |fs, m| {
                put(fs, m, "/w/n1", 4096).unwrap();
            },
        ),
        j(
            "create + write 64 KiB (calls of 1 KiB) + sync + close",
            true,
            |fs, m| {
                put(fs, m, "/w/n1", 64 << 10).unwrap();
            },
        ),
        j(
            "create + write 1 MiB (calls of 1 KiB) + sync + close",
            true,
            |fs, m| {
                put(fs, m, "/w/n1", 1 << 20).unwrap();
            },
        ),
        j(
            "create + write 16 MiB (calls of 1 KiB) + sync + close",
            true,
            |fs, m| {
                put(fs, m, "/w/n1", 16 << 20).unwrap();
            },
        ),
        j(
            "fsync after 1 KiB appended (file of 1 MiB)",
            true,
            |fs, m| {
                let f = open_rw(fs, "/w/m1");
                fs.seek(f, 0, Whence::End).unwrap();
                m.lap(fs);
                fs.write(f, &[1u8; 1024]).unwrap();
                m.lap(fs);
                fs.sync(f).unwrap();
                m.lap(fs);
                fs.close(f).unwrap();
            },
        ),
        j(
            "read 1 KiB at the start of a 16 MiB file (open, read, close)",
            false,
            |fs, m| {
                let f = fs.open(b"/w/m16", Open::READ).unwrap();
                let mut b = [0u8; 1024];
                fs.read(f, &mut b).unwrap();
                fs.close(f).unwrap();
                m.lap(fs);
            },
        ),
        j(
            "read 1 KiB in the middle of a 16 MiB file",
            false,
            |fs, m| {
                let f = fs.open(b"/w/m16", Open::READ).unwrap();
                fs.seek(f, 8 << 20, Whence::Set).unwrap();
                let mut b = [0u8; 1024];
                fs.read(f, &mut b).unwrap();
                fs.close(f).unwrap();
                m.lap(fs);
            },
        ),
        j("read 1 KiB at the end of a 16 MiB file", false, |fs, m| {
            let f = fs.open(b"/w/m16", Open::READ).unwrap();
            fs.seek(f, (16 << 20) - 1024, Whence::Set).unwrap();
            let mut b = [0u8; 1024];
            fs.read(f, &mut b).unwrap();
            fs.close(f).unwrap();
            m.lap(fs);
        }),
        j(
            "read 1 MiB in calls of 1 KiB, from the start",
            false,
            |fs, m| {
                let f = fs.open(b"/w/m16", Open::READ).unwrap();
                let mut b = [0u8; 1024];
                for _ in 0..1024 {
                    fs.read(f, &mut b).unwrap();
                    m.lap(fs);
                }
                fs.close(f).unwrap();
            },
        ),
        j(
            "read all of the 16 MiB file in calls of 1 KiB, from the start",
            false,
            |fs, m| {
                let f = fs.open(b"/w/m16", Open::READ).unwrap();
                let mut b = [0u8; 1024];
                loop {
                    if fs.read(f, &mut b).unwrap() == 0 {
                        break;
                    }
                    m.lap(fs);
                }
                fs.close(f).unwrap();
            },
        ),
        j("readdir of 1000 entries", false, |fs, m| {
            let d = fs.opendir(b"/w/big").unwrap();
            while fs.readdir(d).unwrap().is_some() {}
            fs.closedir(d).unwrap();
            m.lap(fs);
        }),
        j("readdir of 10000 entries", false, |fs, m| {
            let d = fs.opendir(b"/w/huge").unwrap();
            while fs.readdir(d).unwrap().is_some() {}
            fs.closedir(d).unwrap();
            m.lap(fs);
        }),
        j(
            "readdir of 1000 entries + getattr of each (an ino for each)",
            false,
            |fs, m| {
                let d = fs.opendir(b"/w/big").unwrap();
                let mut b = [0u8; 48];
                while let Some(e) = fs.readdir(d).unwrap() {
                    if e.name() == b"." || e.name() == b".." {
                        continue;
                    }
                    let mut path = b"/w/big/".to_vec();
                    path.extend_from_slice(e.name());
                    let _ = fs.getattr(&path, 0x70, &mut b);
                }
                fs.closedir(d).unwrap();
                m.lap(fs);
            },
        ),
        j(
            "readdir of 10000 entries + getattr of each",
            false,
            |fs, m| {
                let d = fs.opendir(b"/w/huge").unwrap();
                let mut b = [0u8; 48];
                while let Some(e) = fs.readdir(d).unwrap() {
                    if e.name() == b"." || e.name() == b".." {
                        continue;
                    }
                    let mut path = b"/w/huge/".to_vec();
                    path.extend_from_slice(e.name());
                    let _ = fs.getattr(&path, 0x70, &mut b);
                }
                fs.closedir(d).unwrap();
                m.lap(fs);
            },
        ),
        j("lfs_fs_size (STATFS today)", false, |fs, m| {
            fs.used_blocks().unwrap();
            m.lap(fs);
        }),
    ]
}

/// Runs a job on a copy of the device mounted with `win`. `warm` first makes the allocator fill its
/// window (a file of 4 KiB made and removed), so the job does not pay for a walk.
fn run_job(device: &MemDevice, win: Win, warm: bool, job: &Job) -> (Cost, Cost) {
    let mut fs = mounted(device, win);
    if warm {
        let mut m = Meter::new(&mut fs);
        put(&mut fs, &mut m, "/warm", 4096).unwrap();
        fs.remove(b"/warm").unwrap();
    }
    let mut meter = Meter::new(&mut fs);
    let start = now(&mut fs);
    (job.run)(&mut fs, &mut meter);
    meter.lap(&mut fs);
    (now(&mut fs).since(start), meter.worst)
}

fn with_working_area(blocks: u64, layout: Layout, percent: u64, full: bool) -> MemDevice {
    let mut fs = fresh(blocks, Win::Whole);
    fill(&mut fs, layout, percent);
    populate(&mut fs, full);
    settle(fs)
}

#[test]
fn a_stat_with_permissions_costs_a_few_reads() {
    // The guard of the plan's `stat` budget: a path lookup of depth 8 and the attribute read stay
    // within a handful of device reads, on a volume that holds a few hundred files.
    let device = with_working_area(8192, BIG_FILES, 0, false);
    let stat = jobs()
        .into_iter()
        .find(|j| j.name.starts_with("stat, depth 8"))
        .unwrap();
    let both = jobs()
        .into_iter()
        .find(|j| j.name.starts_with("stat + getattr 48 B, depth 2"))
        .unwrap();
    let (c, _) = run_job(&device, Win::Whole, false, &stat);
    assert!(c.reads <= 24, "a stat of depth 8 reads {} times", c.reads);
    assert_eq!(c.programs, 0);
    let (c, _) = run_job(&device, Win::Whole, false, &both);
    assert!(
        c.reads <= 24,
        "a stat with its attribute reads {} times",
        c.reads
    );
    assert_eq!(c.programs, 0);
    assert_eq!(c.erases, 0);
}

#[test]
fn an_attribute_costs_one_commit() {
    let device = with_working_area(8192, BIG_FILES, 0, false);
    let set = jobs()
        .into_iter()
        .find(|j| j.name.starts_with("setattr 48 B over"))
        .unwrap();
    let (c, _) = run_job(&device, Win::Whole, false, &set);
    assert!(c.programs <= 3, "a setattr programs {} times", c.programs);
    assert!(c.flushes <= 2, "a setattr flushes {} times", c.flushes);
}

#[test]
#[ignore = "slow: volumes of 256 MiB; run by name, see the module text"]
fn scale_jobs() {
    let blocks = 65536u64;
    let states: [(&str, Layout, u64); 2] = [
        ("working area only (about 19 MiB)", BIG_FILES, 0),
        ("working area + 50 % of 1 MiB files", BIG_FILES, 50),
    ];
    std::println!("\n## Cost of the jobs of the service, volume of 256 MiB\n");
    std::println!(
        "Assumed device costs: read {READ_US} us, program {PROGRAM_US} us, flush {FLUSH_US} us, erase {ERASE_US} us (assumptions; no real disk is measured here)."
    );
    for (state, layout, percent) in states {
        let device = with_working_area(blocks, layout, percent, true);
        header(&format!("Jobs on a volume {state}"));
        for job in jobs() {
            if job.allocs {
                for (win, warm) in [
                    (Win::Whole, false),
                    (Win::Whole, true),
                    (Win::Narrow, false),
                ] {
                    let (c, w) = run_job(&device, win, warm, &job);
                    let label = format!(
                        "{} ({})",
                        job.name,
                        if warm {
                            "warm window"
                        } else {
                            "window empty after the mount"
                        }
                    );
                    row(&label, state, win.name(), c, w);
                }
            } else {
                let (c, w) = run_job(&device, Win::Whole, false, &job);
                row(job.name, state, "any", c, w);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Attributes at the creation of a file.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_attribute_given_at_the_creation_appears_only_after_the_sync() {
    let mut fs = fresh(512, Win::Whole);
    let f = fs
        .open_with_attr(b"/a", Open::WRITE.with(Open::CREATE), 0x70, &[5u8; 48])
        .unwrap();
    // The name is committed at the creation; the attribute of the configuration is not.
    let mut buf = [0u8; 48];
    assert_eq!(fs.stat(b"/a").unwrap().size, 0);
    assert_eq!(fs.getattr(b"/a", 0x70, &mut buf), Err(Error::NoAttr));
    fs.write(f, b"data").unwrap();
    assert_eq!(fs.getattr(b"/a", 0x70, &mut buf), Err(Error::NoAttr));
    fs.sync(f).unwrap();
    assert_eq!(fs.getattr(b"/a", 0x70, &mut buf).unwrap(), 48);
    assert_eq!(buf, [5u8; 48]);
    fs.close(f).unwrap();

    // A cut of the power before the sync leaves the file with no attribute.
    let mut fs = fresh(512, Win::Whole);
    let f = fs
        .open_with_attr(b"/b", Open::WRITE.with(Open::CREATE), 0x70, &[6u8; 48])
        .unwrap();
    fs.write(f, b"data").unwrap();
    let mut device = fs.into_device();
    device.power_cycle(Survive::None);
    let mut fs = attach(device, Win::Whole);
    fs.mount().unwrap();
    assert_eq!(fs.getattr(b"/b", 0x70, &mut buf), Err(Error::NoAttr));
    assert_eq!(fs.stat(b"/b").unwrap().size, 0);
}

// ---------------------------------------------------------------------------------------------
// A full volume.
// ---------------------------------------------------------------------------------------------

/// A tiny generator for the sizes and the order.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

/// Fills a volume until the allocator reports no space, with files of random sizes in a few
/// directories (names of `name_len` bytes), and returns the paths of the files made.
fn fill_to_the_end(fs: &mut Vol, seed: u64, name_len: usize, max_file: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    for d in 0..4 {
        fs.mkdir(format!("/d{d}").as_bytes()).unwrap();
    }
    let mut paths = Vec::new();
    let data = vec![0x77u8; 8192];
    let mut i = 0u64;
    loop {
        let pad = "x".repeat(name_len.saturating_sub(12));
        let path = format!("/d{}/{pad}{i:08}", i % 4);
        i += 1;
        let Ok(f) = fs.open(path.as_bytes(), Open::WRITE.with(Open::CREATE)) else {
            break;
        };
        paths.push(path);
        let mut left = (rng.next() as usize % max_file).max(1);
        let mut full = false;
        while left > 0 {
            let n = left.min(data.len());
            match fs.write(f, &data[..n]) {
                Ok(done) if done == n => left -= n,
                _ => {
                    full = true;
                    break;
                }
            }
        }
        let closed = fs.close(f);
        if full || closed.is_err() {
            break;
        }
    }
    paths
}

/// What happened to the calls of a kind on a full volume.
#[derive(Default, Debug)]
struct Tally {
    ok: u32,
    no_space: u32,
    other: Vec<i32>,
}

impl Tally {
    fn add(&mut self, r: Res<()>) {
        match r {
            Ok(()) => self.ok += 1,
            Err(Error::NoSpace) => self.no_space += 1,
            Err(e) => self.other.push(e.code()),
        }
    }

    fn others(&self) -> String {
        let mut codes = self.other.clone();
        codes.sort_unstable();
        codes.dedup();
        format!("{} {codes:?}", self.other.len())
    }
}

#[test]
fn lfs_remove_succeeds_on_a_volume_with_no_free_block() {
    // 4 MiB volume, filled until the allocator says no space; names of two lengths, so that one
    // run has directories of many short entries and the other directories near the size of a block.
    for (seed, name_len, max_file) in [(1u64, 12usize, 20_000usize), (2, 200, 9000), (3, 12, 2000)]
    {
        let mut fs = fresh(1024, Win::Whole);
        let mut paths = fill_to_the_end(&mut fs, seed, name_len, max_file);
        // The removes run in a service that has just started, with the window of 128 bytes.
        let mut fs = mounted(&settle(fs), Win::Whole);
        let free = fs.blocks() - fs.used_blocks().unwrap();
        assert!(free <= 2, "seed {seed}: {free} blocks free after the fill");
        // Every entry goes, in an order a generator picks. Not one remove asks for a block.
        let mut rng = Rng(seed + 100);
        let mut failures = 0;
        while !paths.is_empty() {
            let at = rng.next() as usize % paths.len();
            let path = paths.swap_remove(at);
            if fs.remove(path.as_bytes()).is_err() {
                failures += 1;
            }
        }
        assert_eq!(
            failures, 0,
            "seed {seed}: lfs_remove failed on a full volume"
        );
        for d in 0..4 {
            fs.remove(format!("/d{d}").as_bytes()).unwrap();
        }
        assert!(fs.used_blocks().unwrap() <= 2, "everything given back");
    }
}

/// What the calls do on a full volume: the table of the plan's question about the reserve. The
/// volume is filled once and each kind of call runs on its own copy, over every entry (at most
/// 2000), so that one kind does not change what the next finds.
fn full_volume_table(
    blocks: u64,
    name_len: usize,
    max_file: usize,
    seed: u64,
) -> Vec<(&'static str, Tally)> {
    let mut fs = fresh(blocks, Win::Whole);
    let paths = fill_to_the_end(&mut fs, seed, name_len, max_file);
    let free = fs.blocks() - fs.used_blocks().unwrap();
    std::println!(
        "filled: {} files, {free} blocks free of {blocks}",
        paths.len()
    );
    let device = settle(fs);
    let sample: Vec<String> = paths.iter().take(2000).cloned().collect();
    let mut table = Vec::new();

    let mut run = |name: &'static str, body: &dyn Fn(&mut Vol, &[String], &mut Tally)| {
        let mut fs = mounted(&device, Win::Whole);
        let mut t = Tally::default();
        body(&mut fs, &sample, &mut t);
        table.push((name, t));
    };
    run("remove (file)", &|fs, ps, t| {
        for p in ps {
            t.add(fs.remove(p.as_bytes()));
        }
    });
    run("setattr 48 B, first on every entry", &|fs, ps, t| {
        for p in ps {
            t.add(fs.setattr(p.as_bytes(), 0x70, &[1u8; 48]));
        }
    });
    run(
        "setattr 48 B over an attribute (second round)",
        &|fs, ps, t| {
            let mut done = Vec::new();
            for p in ps {
                if fs.setattr(p.as_bytes(), 0x70, &[1u8; 48]).is_ok() {
                    done.push(p);
                }
            }
            for p in done {
                t.add(fs.setattr(p.as_bytes(), 0x70, &[2u8; 48]));
            }
        },
    );
    run(
        "rename in the same directory (same name length)",
        &|fs, ps, t| {
            for p in ps {
                let (dir, name) = p.rsplit_once('/').unwrap();
                t.add(fs.rename(p.as_bytes(), format!("{dir}/r{}", &name[1..]).as_bytes()));
            }
        },
    );
    run("rename into another directory", &|fs, ps, t| {
        for (i, p) in ps.iter().enumerate() {
            let name = p.rsplit_once('/').unwrap().1;
            t.add(fs.rename(p.as_bytes(), format!("/d{}/{name}", (i + 1) % 4).as_bytes()));
        }
    });
    run("create empty file", &|fs, _, t| {
        for i in 0..300 {
            t.add(
                fs.open(
                    format!("/d{}/new{i}", i % 4).as_bytes(),
                    Open::WRITE.with(Open::CREATE),
                )
                .and_then(|f| fs.close(f)),
            );
        }
    });
    run("mkdir", &|fs, _, t| {
        for i in 0..300 {
            t.add(fs.mkdir(format!("/d{}/dir{i}", i % 4).as_bytes()));
        }
    });
    run(
        "create + 1 byte + sync, attribute in the file configuration",
        &|fs, _, t| {
            for i in 0..100 {
                t.add(
                    fs.open_with_attr(
                        format!("/d{}/s{i}", i % 4).as_bytes(),
                        Open::WRITE.with(Open::CREATE),
                        0x70,
                        &[3u8; 48],
                    )
                    .and_then(|f| {
                        let r = fs.write(f, b"x").and_then(|_| fs.sync(f));
                        let c = fs.close(f);
                        r.and(c)
                    }),
                );
            }
        },
    );
    run("append 1 byte to an existing file + sync", &|fs, ps, t| {
        for p in ps.iter().take(300) {
            t.add(
                fs.open(p.as_bytes(), Open::WRITE.with(Open::APPEND))
                    .and_then(|f| {
                        let r = fs.write(f, b"x").map(drop).and_then(|_| fs.sync(f));
                        let c = fs.close(f);
                        r.and(c)
                    }),
            );
        }
    });
    table
}

#[test]
#[ignore = "slow: volumes of 16 MiB filled three times; run by name, see the module text"]
fn scale_full() {
    std::println!(
        "\n## Calls on a volume with no free block (16 MiB, filled until the allocator reports no space)\n"
    );
    std::println!(
        "Each call kind runs on its own copy of the full volume, over up to 2000 entries (300 for creates, 100 for the create with an attribute).\n"
    );
    std::println!("| fill | call | succeeded | NOSPC | other errors (count, codes) |");
    std::println!("|---|---|---:|---:|---|");
    for (label, name_len, max_file) in [
        ("short names, files up to 20 KiB", 12usize, 20_000usize),
        ("names of 200 bytes, files up to 9 KiB", 200, 9000),
        ("short names, files up to 2 KiB", 12, 2000),
    ] {
        for (call, t) in full_volume_table(4096, name_len, max_file, 5) {
            std::println!(
                "| {label} | {call} | {} | {} | {} |",
                t.ok,
                t.no_space,
                t.others()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// A rename between directories and a cut of the power at every sector.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_rename_between_directories_survives_a_cut_at_every_sector() {
    let content: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let mut base = fresh(512, Win::Whole);
    base.mkdir(b"/a").unwrap();
    base.mkdir(b"/b").unwrap();
    let mut m = Meter::new(&mut base);
    put(&mut base, &mut m, "/a/y", 100).unwrap();
    let f = base.open(b"/a/x", Open::WRITE.with(Open::CREATE)).unwrap();
    base.write(f, &content).unwrap();
    base.sync(f).unwrap();
    base.close(f).unwrap();
    base.unmount().unwrap();
    let mut medium = base.into_device();
    medium.flush().unwrap();

    // How many sectors the rename writes when nothing stops it.
    let mut probe = mounted(&medium, Win::Whole);
    let before = probe.device().written;
    probe.rename(b"/a/x", b"/b/x").unwrap();
    let sectors = probe.device().written - before;
    assert!(sectors >= 2);

    let mut cuts = 0;
    for cut in 0..=sectors {
        for survive in [
            Survive::None,
            Survive::All,
            Survive::Prefix(1),
            Survive::Random(cut + 1),
        ] {
            let mut fs = mounted(&medium, Win::Whole);
            fs.device().cut_after(Some(cut));
            let _ = fs.rename(b"/a/x", b"/b/x");
            let mut device = fs.into_device();
            device.power_cycle(survive);
            let mut fs = attach(device, Win::Whole);
            fs.mount().unwrap();
            let old = fs.stat(b"/a/x");
            let new = fs.stat(b"/b/x");
            assert!(
                old.is_ok() != new.is_ok(),
                "cut {cut} {survive:?}: the file is under both names or neither: {old:?} {new:?}"
            );
            let path: &[u8] = if old.is_ok() { b"/a/x" } else { b"/b/x" };
            let f = fs.open(path, Open::READ).unwrap();
            let mut got = vec![0u8; content.len() + 10];
            assert_eq!(fs.read(f, &mut got).unwrap(), content.len());
            assert_eq!(&got[..content.len()], &content[..], "cut {cut} {survive:?}");
            fs.close(f).unwrap();
            // The listings agree with the stats: a pending move leaves no entry doubled or lost.
            for (dir, want) in [(b"/a" as &[u8], old.is_ok()), (b"/b", new.is_ok())] {
                let d = fs.opendir(dir).unwrap();
                let mut names = Vec::new();
                while let Some(e) = fs.readdir(d).unwrap() {
                    names.push(e.name().to_vec());
                }
                fs.closedir(d).unwrap();
                assert_eq!(
                    names.contains(&b"x".to_vec()),
                    want,
                    "cut {cut} {survive:?} listing of {dir:?}"
                );
                if dir == b"/a" {
                    assert!(
                        names.contains(&b"y".to_vec()),
                        "cut {cut} {survive:?}: y lost"
                    );
                }
            }
            cuts += 1;
        }
    }
    assert!(cuts >= 8);
}

// ---------------------------------------------------------------------------------------------
// The mount, clean and after a cut.
// ---------------------------------------------------------------------------------------------

/// What the service does between the start and the first request: the mount, which finishes a
/// half-done move, and the recovery of the orphans.
fn service_mount(device: MemDevice, win: Win) -> (Cost, Vol) {
    let mut fs = attach(device, win);
    let at = now(&mut fs);
    fs.mount().unwrap();
    recover_orphans(&mut fs).unwrap();
    let cost = now(&mut fs).since(at);
    (cost, fs)
}

#[test]
fn the_mount_after_a_cut_costs_a_bounded_number_of_calls() {
    let device = with_working_area(8192, BIG_FILES, 0, false);
    let (clean, _) = service_mount(device.clone(), Win::Whole);
    assert!(
        clean.reads <= 200,
        "a clean mount reads {} times",
        clean.reads
    );
    // A cut at every sector of a rename between directories: the mount repairs the move.
    let mut fs = mounted(&device, Win::Whole);
    let before = fs.device().written;
    fs.rename(b"/w/f1", b"/w/s/g1").unwrap();
    let sectors = fs.device().written - before;
    let mut worst = 0;
    for cut in 0..=sectors {
        let mut fs = mounted(&device, Win::Whole);
        fs.device().cut_after(Some(cut));
        let _ = fs.rename(b"/w/f1", b"/w/s/g1");
        let mut d = fs.into_device();
        d.power_cycle(Survive::Random(cut + 3));
        let (c, _) = service_mount(d, Win::Whole);
        worst = worst.max(c.reads);
    }
    assert!(
        worst <= clean.reads + 200,
        "after a cut a mount reads {worst} times, a clean one {}",
        clean.reads
    );
}

#[test]
#[ignore = "slow: volumes of 256 MiB; run by name, see the module text"]
fn scale_mount() {
    let blocks = 65536u64;
    header(
        "Mount and recovery of the orphans (what the service does before READY), volume of 256 MiB",
    );
    let states: [(&str, Layout, u64); 3] = [
        ("working area only (about 19 MiB)", BIG_FILES, 0),
        ("working area + 50 % of 1 MiB files", BIG_FILES, 50),
        ("working area + 50 % of 16 KiB files", SMALL_FILES, 50),
    ];
    for (state, layout, percent) in states {
        let device = with_working_area(blocks, layout, percent, true);
        for win in [Win::Whole, Win::Narrow] {
            let (c, _) = service_mount(device.clone(), win);
            row("mount + recover_orphans, clean", state, win.name(), c, c);
        }
        // A cut at every sector of three jobs; the mount after each, with a random subset of the
        // cache surviving. The row says the cheapest and the dearest mount over the cuts.
        let scripts: [(&str, Script); 3] = [
            ("rename between directories", |fs| {
                let _ = fs.rename(b"/w/f1", b"/w/s/g1");
            }),
            ("mkdir", |fs| {
                let _ = fs.mkdir(b"/w/newdir");
            }),
            ("1 MiB written with no sync", |fs| {
                if let Ok(f) = fs.open(b"/w/n1", Open::WRITE.with(Open::CREATE)) {
                    let data = vec![1u8; 4096];
                    for _ in 0..256 {
                        if fs.write(f, &data).is_err() {
                            break;
                        }
                    }
                }
            }),
        ];
        for (name, script) in scripts {
            let mut fs = mounted(&device, Win::Whole);
            let before = fs.device().written;
            script(&mut fs);
            let sectors = (fs.device().written - before).min(40);
            let step = if sectors > 12 { sectors / 12 } else { 1 };
            let (mut low, mut high): (Option<Cost>, Option<Cost>) = (None, None);
            let mut cut = 0;
            while cut <= sectors {
                let mut fs = mounted(&device, Win::Whole);
                fs.device().cut_after(Some(cut));
                script(&mut fs);
                let mut d = fs.into_device();
                d.power_cycle(Survive::Random(cut + 11));
                let (c, _) = service_mount(d, Win::Whole);
                if low.is_none_or(|l| c.ms() < l.ms()) {
                    low = Some(c);
                }
                if high.is_none_or(|h| c.ms() > h.ms()) {
                    high = Some(c);
                }
                cut += step;
            }
            let (low, high) = (low.unwrap(), high.unwrap());
            row(
                &format!("mount after a cut in: {name} (cheapest)"),
                state,
                "whole",
                low,
                low,
            );
            row(
                &format!("mount after a cut in: {name} (dearest)"),
                state,
                "whole",
                high,
                high,
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The whole volume of 2 GiB, as the plan's estimate of 52 seconds.
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore = "slow and large: a volume of 2 GiB in memory; run by name, see the module text"]
fn scale_2gib() {
    let blocks = 524_288u64;
    std::println!("\n## Volume of 2 GiB (524288 blocks): the walk\n");
    std::println!(
        "| layout | filled | blocks in use | walk reads | reads per used block | derived s at 10,000 reads/s |"
    );
    std::println!("|---|---:|---:|---:|---:|---:|");
    for (layout, percent) in [
        (BIG_FILES, 50),
        (BIG_FILES, 100),
        (SMALL_FILES, 50),
        (SMALL_FILES, 100),
    ] {
        let img = image(blocks, layout, percent);
        let (c, used) = traverse_cost(&img);
        std::println!(
            "| {} | {percent} % | {used} | {} | {:.2} | {:.1} |",
            layout.name,
            c.reads,
            c.reads as f64 / used as f64,
            c.ms() / 1000.0
        );
    }
    std::println!(
        "\n## Volume of 2 GiB: 64 MiB written in 1 MiB files by calls of 1 KiB, after a mount\n"
    );
    std::println!(
        "| layout | filled | window | walks | most walks in one call | reads in all | reads of the longest call | derived s of the longest call |"
    );
    std::println!("|---|---:|---|---:|---:|---:|---:|---:|");
    for (layout, percent) in [(BIG_FILES, 0), (BIG_FILES, 25), (BIG_FILES, 50)] {
        let img = image(blocks, layout, percent);
        for win in [Win::Whole, Win::Narrow] {
            let mut fs = mounted(&img, win);
            let run = write_and_count(&mut fs, 64 << 20, 1 << 20, "w");
            std::println!(
                "| {} | {percent} % | {} | {} | {} | {} | {} | {:.1} |",
                layout.name,
                win.name(),
                run.scans,
                run.most_walks_in_a_call,
                run.cost.reads,
                run.worst.reads,
                run.worst.ms() / 1000.0
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// A read that fails, at every point.
// ---------------------------------------------------------------------------------------------

/// The files a volume for the failed-read tests holds: a name, the length, and a byte pattern.
const KEPT: [(&str, usize, u8); 5] = [
    ("/a/small", 100, 1),
    ("/a/mid", 5000, 2),
    ("/a/b/big", 40_000, 3),
    ("/top", 12_345, 4),
    ("/a/b/c/deep", 9000, 5),
];

fn kept_device() -> MemDevice {
    let mut fs = fresh(1024, Win::Whole);
    for d in ["/a", "/a/b", "/a/b/c"] {
        fs.mkdir(d.as_bytes()).unwrap();
    }
    for (path, len, salt) in KEPT {
        let f = fs
            .open(path.as_bytes(), Open::WRITE.with(Open::CREATE))
            .unwrap();
        let data: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(salt).wrapping_add(salt))
            .collect();
        assert_eq!(fs.write(f, &data).unwrap(), len);
        fs.close(f).unwrap();
    }
    settle(fs)
}

/// Reads every kept file whole and checks its bytes, and lists the directories.
fn read_everything(fs: &mut Vol) -> Res<()> {
    for (path, len, salt) in KEPT {
        let f = fs.open(path.as_bytes(), Open::READ)?;
        let mut got = vec![0u8; len + 8];
        let mut at = 0;
        loop {
            let n = fs.read(f, &mut got[at..]).inspect_err(|_| {
                let _ = fs.close(f);
            })?;
            if n == 0 {
                break;
            }
            at += n;
        }
        fs.close(f)?;
        assert_eq!(at, len, "{path}");
        for (i, b) in got[..len].iter().enumerate() {
            assert_eq!(
                *b,
                (i as u8).wrapping_mul(salt).wrapping_add(salt),
                "{path} byte {i}"
            );
        }
    }
    for d in ["/", "/a", "/a/b", "/a/b/c"] {
        let dir = fs.opendir(d.as_bytes())?;
        let mut names = 0;
        while let Some(e) = fs.readdir(dir).inspect_err(|_| {
            let _ = fs.closedir(dir);
        })? {
            if e.name() != b"." && e.name() != b".." {
                names += 1;
            }
        }
        fs.closedir(dir)?;
        assert!(names >= 1, "{d}");
    }
    Ok(())
}

#[test]
fn a_walk_stopped_at_every_read_leaves_a_volume_that_works() {
    let device = kept_device();
    let mut probe = mounted(&device, Win::Whole);
    let at = now(&mut probe);
    probe.walk().unwrap();
    let reads = now(&mut probe).since(at).reads;
    assert!(reads >= 10, "a walk of {reads} reads is too short to test");
    for point in 0..reads {
        let mut fs = mounted(&device, Win::Whole);
        // Warm the read cache with the root, as a service that has served requests would have it.
        fs.stat(b"/top").unwrap();
        fs.device().fail_read_after(Some(point));
        let stopped = fs.walk();
        assert_eq!(stopped, Err(Error::Io), "point {point}");
        // The volume is used on: every file reads back whole, a file is written, the walk works.
        read_everything(&mut fs).unwrap_or_else(|e| panic!("point {point}: {e:?}"));
        let mut m = Meter::new(&mut fs);
        put(&mut fs, &mut m, "/new", 20_000).unwrap();
        let f = fs.open(b"/new", Open::READ).unwrap();
        let mut got = vec![0u8; 20_000];
        assert_eq!(fs.read(f, &mut got).unwrap(), 20_000);
        fs.close(f).unwrap();
        assert_eq!(fs.stat(b"/new").unwrap().size, 20_000, "point {point}");
        read_everything(&mut fs).unwrap();
        fs.walk()
            .unwrap_or_else(|e| panic!("point {point}: the next walk failed: {e:?}"));
        assert_eq!(
            fs.free_blocks().unwrap(),
            1024 - fs.used_blocks().unwrap(),
            "point {point}"
        );
    }
}

#[test]
fn a_failed_read_at_every_point_of_ordinary_reads_leaves_a_volume_that_works() {
    let device = kept_device();
    let mut probe = mounted(&device, Win::Whole);
    let at = now(&mut probe);
    read_everything(&mut probe).unwrap();
    let reads = now(&mut probe).since(at).reads;
    for point in 0..reads {
        let mut fs = mounted(&device, Win::Whole);
        fs.device().fail_read_after(Some(point));
        // One of the reads fails somewhere in the reads, the opens or the listings.
        let first = read_everything(&mut fs);
        assert!(first.is_err(), "point {point}: no read failed");
        read_everything(&mut fs)
            .unwrap_or_else(|e| panic!("point {point}: after the failure {e:?}"));
        let mut m = Meter::new(&mut fs);
        put(&mut fs, &mut m, "/new", 3000).unwrap();
        read_everything(&mut fs).unwrap();
    }
}

#[test]
fn free_blocks_make_no_walk_for_a_window_the_checkpoint_cut_short() {
    // A wrap of the allocator inside a request fills the window as long as the checkpoint allowed:
    // shorter than the volume and still holding bits. STATFS counts its bits and walks only when the
    // window is empty; `window_short` tells the worker a walk in the idle would fill it whole.
    let mut fs = fresh(1024, Win::Whole);
    let mut m = Meter::new(&mut fs);
    put(&mut fs, &mut m, "/a", 100 << 10).unwrap();
    assert!(!fs.window_short());
    // Go round the volume: 3 MiB written and removed, then 3 MiB again, so that the cursor wraps
    // inside a request. (littlefs usually refills the window whole after the wrap; if the
    // checkpoint cuts it short, the branch below holds.)
    for round in 0..3 {
        for n in 0..3 {
            put(&mut fs, &mut m, &format!("/r{round}-{n}"), 1 << 20).unwrap();
        }
        for n in 0..3 {
            fs.remove(format!("/r{round}-{n}").as_bytes()).unwrap();
        }
    }
    let (_, _, size) = fs.window_state();
    assert!(size != 0, "the window is filled");
    if fs.window_short() {
        // Its bits give a count that is low, and a STATFS reads nothing for it.
        let at = now(&mut fs);
        let seen = fs.free_blocks().unwrap();
        assert_eq!(now(&mut fs).since(at).reads, 0);
        assert!(seen <= 1024 - fs.used_blocks().unwrap());
        fs.walk().unwrap();
    }
    assert!(!fs.window_short(), "a walk fills the window whole");
    assert_eq!(fs.window_state().2 as u64, fs.blocks());
}

#[test]
fn counts_agree_on_volumes_that_are_not_a_multiple_of_64_blocks() {
    for blocks in [1000u64, 1025, 4097] {
        let mut fs = fresh(blocks, Win::Whole);
        let mut m = Meter::new(&mut fs);
        put(&mut fs, &mut m, "/a", 150 << 10).unwrap();
        fs.mkdir(b"/d").unwrap();
        let mut fs = mounted(&settle(fs), Win::Whole);
        assert_eq!(fs.window_state().2, 0);
        let free = fs.free_blocks().unwrap();
        assert_eq!(
            fs.window_state().2 as u64,
            blocks,
            "{blocks}: the window holds the volume"
        );
        assert_eq!(free, blocks - fs.used_blocks().unwrap(), "{blocks} blocks");
    }
}

#[test]
fn a_volume_larger_than_the_window_counts_by_the_walk() {
    // The fallback for a volume the window cannot cover (the service refuses such a volume; the
    // volume layer keeps the count right all the same): a window of 128 bytes on 4096 blocks.
    let mut fs = fresh(4096, Win::Narrow);
    let mut m = Meter::new(&mut fs);
    put(&mut fs, &mut m, "/a", 300 << 10).unwrap();
    let at = now(&mut fs);
    let free = fs.free_blocks().unwrap();
    assert!(now(&mut fs).since(at).reads > 0, "the count walks the tree");
    assert_eq!(free, 4096 - fs.used_blocks().unwrap());
}

#[test]
fn a_disk_with_a_data_partition_over_4_gib_is_refused_and_not_written() {
    use crate::volume::{self, Refusal};
    use crate::{DeviceError, SECTOR};
    // A disk of 6 GiB that reads as zeros and panics on a write.
    struct Huge;
    impl Device for Huge {
        fn sectors(&self) -> u64 {
            (6u64 << 30) / SECTOR as u64
        }
        fn read(&mut self, _: u64, out: &mut [u8]) -> Result<(), DeviceError> {
            out.fill(0);
            Ok(())
        }
        fn write(&mut self, sector: u64, _: &[u8]) -> Result<(), DeviceError> {
            panic!("a write at sector {sector}")
        }
        fn flush(&mut self) -> Result<(), DeviceError> {
            Ok(())
        }
    }
    let mut state = Box::new(Storage::new());
    let refused = volume::open(Huge, &mut state, 1).err();
    assert_eq!(refused, Some(Refusal::TooLarge));
    assert!(Refusal::TooLarge.text().contains("4 GiB"));
}

// ---------------------------------------------------------------------------------------------
// A walk that gives way to a queued job.
// ---------------------------------------------------------------------------------------------

/// The device as the worker's disk is to a walk: a read fails when a job is queued and the walk may
/// give way to one (`Disk::read` in services/datafs).
struct Yielding {
    inner: MemDevice,
    /// A job is queued: set by the test when its job "arrives".
    queued: std::rc::Rc<std::cell::Cell<bool>>,
    may_yield: std::rc::Rc<std::cell::Cell<bool>>,
    /// The reads of the walk and of the jobs served meanwhile.
    stopped: std::rc::Rc<std::cell::Cell<u32>>,
}

impl Device for Yielding {
    fn sectors(&self) -> u64 {
        self.inner.sectors()
    }

    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), crate::DeviceError> {
        if self.may_yield.get() && self.queued.get() {
            self.stopped.set(self.stopped.get() + 1);
            return Err(crate::DeviceError);
        }
        self.inner.read(sector, out)
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), crate::DeviceError> {
        self.inner.write(sector, data)
    }

    fn flush(&mut self) -> Result<(), crate::DeviceError> {
        self.inner.flush()
    }
}

#[test]
fn a_job_during_a_walk_stops_it_is_served_in_a_few_reads_and_the_walk_completes_later() {
    use std::cell::Cell;
    use std::rc::Rc;
    let queued = Rc::new(Cell::new(false));
    let may_yield = Rc::new(Cell::new(false));
    let stopped = Rc::new(Cell::new(0));
    let device = kept_device();
    let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
    let gate = Yielding {
        inner: device,
        queued: queued.clone(),
        may_yield: may_yield.clone(),
        stopped: stopped.clone(),
    };
    let mut fs = Fs::new(gate, state).unwrap();
    fs.mount().unwrap();
    // The walk alone: how many reads it takes.
    let before = fs.device().inner.reads;
    fs.walk().unwrap();
    let whole = fs.device().inner.reads - before;
    assert!(whole >= 10);
    // A walk that a job stops at its first read (the job was queued as the walk began).
    may_yield.set(true);
    queued.set(true);
    assert_eq!(fs.walk(), Err(Error::Io));
    assert_eq!(stopped.get(), 1);
    // The job is served at once: the walk gave the device back at one read. The volume is whole.
    queued.set(false);
    may_yield.set(false);
    let at = fs.device().inner.reads;
    let mut buf = [0u8; 100];
    let f = fs.open(b"/a/small", Open::READ).unwrap();
    assert_eq!(fs.read(f, &mut buf).unwrap(), 100);
    fs.close(f).unwrap();
    let served = fs.device().inner.reads - at;
    assert!(
        served < whole && served <= 40,
        "a read job took {served} reads, a walk {whole}"
    );
    // The walk is tried again when the queue is empty, and completes.
    fs.walk().unwrap();
    assert_eq!(fs.free_blocks().unwrap(), 1024 - fs.used_blocks().unwrap());
}

#[test]
fn after_the_allowed_tries_a_walk_runs_to_its_end_though_jobs_keep_coming() {
    use crate::idle::{MAX_YIELDS, may_yield};
    use std::cell::Cell;
    use std::rc::Rc;
    let queued = Rc::new(Cell::new(true));
    let allowed = Rc::new(Cell::new(false));
    let stopped = Rc::new(Cell::new(0));
    let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
    let mut fs = Fs::new(
        Yielding {
            inner: kept_device(),
            queued: queued.clone(),
            may_yield: allowed.clone(),
            stopped: stopped.clone(),
        },
        state,
    )
    .unwrap();
    fs.mount().unwrap();
    // A job is queued all the time: each try is stopped until the rule says the next one is not to
    // be, and that one completes.
    let mut tries = 0;
    loop {
        allowed.set(may_yield(tries));
        match fs.walk() {
            Ok(()) => break,
            Err(Error::Io) => tries += 1,
            Err(e) => panic!("{e:?}"),
        }
        assert!(tries <= MAX_YIELDS, "the walk never completes");
    }
    assert_eq!(tries, MAX_YIELDS);
    assert_eq!(stopped.get(), MAX_YIELDS);
    assert_eq!(fs.window_state().2 as u64, fs.blocks());
}

#[test]
fn a_request_that_takes_blocks_is_named_for_the_stop_status() {
    use crate::server::needs_blocks;
    use proto_data as p;
    let build = |f: &dyn Fn(&mut proto_wire::Writer)| {
        let mut w = proto_wire::Writer::new();
        f(&mut w);
        w.as_bytes().to_vec()
    };
    assert!(needs_blocks(&build(&|w| p::write(1, b"x", w).unwrap())));
    assert!(needs_blocks(&build(&|w| p::path_call(
        p::Method::Mkdir,
        b"/d",
        w
    )
    .unwrap())));
    assert!(needs_blocks(&build(
        &|w| p::rename(b"/a", b"/b", w).unwrap()
    )));
    assert!(needs_blocks(&build(&|w| p::open(
        b"/n",
        p::WRITE | p::CREATE,
        0o644,
        w
    )
    .unwrap())));
    assert!(!needs_blocks(&build(
        &|w| p::open(b"/n", p::READ, 0, w).unwrap()
    )));
    assert!(!needs_blocks(&build(&|w| p::pread(1, 10, 0, w).unwrap())));
    assert!(!needs_blocks(&build(&|w| p::statfs(w).unwrap())));
    assert!(!needs_blocks(&build(&|w| p::path_call(
        p::Method::Stat,
        b"/a",
        w
    )
    .unwrap())));
    assert!(!needs_blocks(&build(&|w| p::path_call(
        p::Method::Unlink,
        b"/a",
        w
    )
    .unwrap())));
    assert!(!needs_blocks(&[]));
}

#[test]
fn the_mount_work_of_a_volume_that_exists_leaves_the_window_empty() {
    // The verifying boot of data-probe sleeps before its first request so that the service's first
    // walk starts after the quiet time: that holds only if the mount work (the directory of the
    // orphans, the recovery, the epoch) takes no block from the allocator on a volume a series of
    // writes left behind. On a new volume the directory of the orphans is made at mount and fills
    // the window ("made at mount").
    use crate::server::{bump_epoch, ensure_orphans, recover_orphans};
    let device = kept_device();
    let mut fs = mounted(&device, Win::Whole);
    ensure_orphans(&mut fs).unwrap();
    // The first start made the directory; a later start finds it.
    let mut fs = mounted(&settle(fs), Win::Whole);
    assert_eq!(fs.window_state().2, 0);
    ensure_orphans(&mut fs).unwrap();
    recover_orphans(&mut fs).unwrap();
    bump_epoch(&mut fs).unwrap();
    assert_eq!(fs.window_state().2, 0, "the mount work walked the volume");
    // The first walk after the quiet time is then a real one.
    let at = now(&mut fs);
    fs.walk().unwrap();
    assert!(now(&mut fs).since(at).reads > 0);
}

// ---------------------------------------------------------------------------------------------
// The repair of the orphans after a cut, on volumes with many directories and many pairs.
// ---------------------------------------------------------------------------------------------

/// A volume of `dirs` directories and about `pairs` metadata pairs (the rest of the pairs are made
/// by files of 500 bytes in one directory). Returns the settled device and the exact counts.
fn many_pairs(dirs: usize, pairs: usize) -> (MemDevice, u64, u64) {
    // /z is made first and /w after it, so the list runs root, /w, the pairs of its files, /z, the
    // directories of /z: the parent of every directory is as far from the head as the files put it.
    let mut fs = fresh(65536, Win::Whole);
    let mut meter = Meter::new(&mut fs);
    fs.mkdir(b"/z").unwrap();
    fs.mkdir(b"/w").unwrap();
    for i in 0..dirs.saturating_sub(4) {
        fs.mkdir(format!("/z/d{i}").as_bytes()).unwrap();
    }
    let mut n = 0;
    loop {
        if n % 32 == 0 && fs.metadata_pairs().unwrap().0 >= pairs as u64 {
            break;
        }
        let sub = n / 900;
        if n % 900 == 0 {
            fs.mkdir(format!("/w/s{sub}").as_bytes()).unwrap();
        }
        put(&mut fs, &mut meter, &format!("/w/s{sub}/f{n}"), 500).unwrap();
        n += 1;
    }
    let (p, d) = fs.metadata_pairs().unwrap();
    (settle(fs), p, d)
}

#[test]
#[ignore = "slow: volumes with thousands of pairs; run by name, see the module text"]
fn scale_orphan_mount() {
    std::println!("\n## Mount after a cut inside MKDIR, RMDIR and RENAME over a directory\n");
    std::println!(
        "| dirs | pairs | op | clean mount reads | cheapest | dearest | dearest s at 10,000/s | dearest s at 3,000/s |"
    );
    std::println!("|---:|---:|---|---:|---:|---:|---:|---:|");
    type Op = fn(&mut Vol);
    let ops: [(&str, Op); 3] = [
        ("mkdir", |fs| {
            let _ = fs.mkdir(b"/z/newdir");
        }),
        ("rmdir", |fs| {
            let _ = fs.remove(b"/z/d1");
        }),
        ("rename over a directory", |fs| {
            let _ = fs.rename(b"/z/d2", b"/z/d3");
        }),
    ];
    let scales: Vec<(usize, usize)> = std::env::var("ORPHAN_SCALES")
        .unwrap_or_else(|_| "128:256,256:512,512:1024,1024:2048".into())
        .split(',')
        .map(|s| {
            let (d, p) = s.split_once(':').unwrap();
            (d.parse().unwrap(), p.parse().unwrap())
        })
        .collect();
    for (dirs, pairs) in scales {
        let (device, p, d) = many_pairs(dirs, pairs);
        let (clean, _) = service_mount(device.clone(), Win::Whole);
        for (name, op) in ops {
            let mut fs = mounted(&device, Win::Whole);
            let before = fs.device().written;
            op(&mut fs);
            let sectors = fs.device().written - before;
            let (mut low, mut high) = (u64::MAX, 0u64);
            for cut in 0..=sectors {
                let mut fs = mounted(&device, Win::Whole);
                fs.device().cut_after(Some(cut));
                op(&mut fs);
                let mut dev = fs.into_device();
                dev.power_cycle(Survive::Random(cut + 5));
                let (c, _) = service_mount(dev, Win::Whole);
                low = low.min(c.reads);
                high = high.max(c.reads);
            }
            std::println!(
                "| {d} | {p} | {name} | {} | {low} | {high} | {:.1} | {:.1} |",
                clean.reads,
                high as f64 / 10_000.0,
                high as f64 / 3_000.0
            );
        }
    }
}
