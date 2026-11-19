// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The two reads of littlefs that give the user attribute of an entry with the entry
//! (`lfs_dir_read_attr`, `lfs_stat_attr`: third-party/littlefs/STAFETO-CHANGES.md), counted in
//! reads of the device and compared with `lfs_getattr` by path.

use crate::fs::{Fs, Open, Storage};
use crate::mem::MemDevice;
use crate::{BLOCK_SECTORS, Error};
use std::boxed::Box;
use std::format;
use std::println;
use std::string::{String, ToString};
use std::vec::Vec;

type Vol = Fs<'static, MemDevice>;

const ATTR: u8 = 0x70;
const ENTRIES: usize = 1000;

fn attach(device: MemDevice) -> Vol {
    let state: &'static mut Storage = Box::leak(Box::new(Storage::new()));
    Fs::new(device, state).unwrap()
}

/// A formatted volume of 4096 blocks, mounted.
fn fresh() -> Vol {
    let mut fs = attach(MemDevice::new(4096 * BLOCK_SECTORS));
    fs.format().unwrap();
    fs.mount().unwrap();
    fs
}

/// The volume as a service that has just started sees it: written out, mounted again, no cache.
fn restarted(mut fs: Vol) -> Vol {
    fs.unmount().unwrap();
    let device = fs.into_device();
    let mut fs = attach(device);
    fs.mount().unwrap();
    fs
}

fn reads(fs: &mut Vol) -> u64 {
    fs.device().reads
}

/// The attribute an entry of the working directory should have: none for every seventh entry, a
/// short one for every eleventh, 48 bytes for the others. The first two bytes are the index and
/// the others depend on it, so no two entries have the same bytes.
fn attribute_of(i: usize) -> Option<Vec<u8>> {
    if i.is_multiple_of(7) {
        return None;
    }
    let len = if i.is_multiple_of(11) { 8 } else { 48 };
    let mut bytes = std::vec![0u8; len];
    bytes[..2].copy_from_slice(&(i as u16).to_le_bytes());
    for (k, byte) in bytes.iter_mut().enumerate().skip(2) {
        *byte = (k as u8) ^ (i as u8);
    }
    Some(bytes)
}

fn name_of(i: usize) -> String {
    format!("e{i:05}")
}

/// `/w` with `count` empty files from index `first`, each with its attribute.
fn make_entries(fs: &mut Vol, first: usize, count: usize) {
    for i in first..first + count {
        let path = format!("/w/{}", name_of(i));
        let f = fs
            .open(path.as_bytes(), Open::WRITE.with(Open::CREATE))
            .unwrap();
        fs.close(f).unwrap();
        if let Some(a) = attribute_of(i) {
            fs.setattr(path.as_bytes(), ATTR, &a).unwrap();
        }
    }
}

/// The attribute of `path` by littlefs's own `lfs_getattr`: its size and bytes, or None.
fn by_path(fs: &mut Vol, path: &str) -> Option<(usize, [u8; 48])> {
    let mut b = [0u8; 48];
    match fs.getattr(path.as_bytes(), ATTR, &mut b) {
        Ok(n) => Some((n, b)),
        Err(Error::NoAttr) => None,
        Err(e) => panic!("getattr {path}: {e}"),
    }
}

/// Walks `dir_path` with `readdir_attr` and checks each entry against `getattr` by path. Returns
/// the number of entries other than `.` and `..`.
fn check_directory(fs: &mut Vol, dir_path: &str) -> usize {
    let d = fs.opendir(dir_path.as_bytes()).unwrap();
    let mut seen = 0;
    let mut dots = 0;
    loop {
        let mut b = [0u8; 48];
        let Some((entry, size)) = fs.readdir_attr(d, ATTR, &mut b).unwrap() else {
            break;
        };
        if entry.name() == b"." || entry.name() == b".." {
            assert_eq!(size, None, "{:?} has no attribute", entry.name());
            dots += 1;
            continue;
        }
        let path = format!(
            "{}/{}",
            dir_path.trim_end_matches('/'),
            core::str::from_utf8(entry.name()).unwrap()
        );
        let wanted = by_path(fs, &path);
        match (size, wanted) {
            (None, None) => {}
            (Some(n), Some((m, bytes))) => {
                assert_eq!(n, m, "{path}: the size");
                // The bytes littlefs gives are the stored ones, padded with zeros.
                assert_eq!(&b[..n.min(48)], &bytes[..n.min(48)], "{path}: the bytes");
            }
            (got, want) => panic!("{path}: readdir_attr {got:?}, getattr {want:?}"),
        }
        seen += 1;
    }
    fs.closedir(d).unwrap();
    assert_eq!(dots, 2);
    seen
}

#[test]
fn the_attribute_of_each_entry_equals_getattr_by_path_across_several_pairs() {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    make_entries(&mut fs, 0, ENTRIES);
    // Removals compact the pairs, and new entries split them again.
    for i in (0..ENTRIES).step_by(3) {
        fs.remove(format!("/w/{}", name_of(i)).as_bytes()).unwrap();
    }
    make_entries(&mut fs, ENTRIES, 400);
    let remaining = ENTRIES - ENTRIES.div_ceil(3) + 400;
    assert_eq!(check_directory(&mut fs, "/w"), remaining);
    // The same after a restart, with every pair read from the device.
    let mut fs = restarted(fs);
    assert_eq!(check_directory(&mut fs, "/w"), remaining);
}

#[test]
fn entries_without_the_attribute_and_the_root_report_none() {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    make_entries(&mut fs, 0, 30);
    fs.mkdir(b"/w/sub").unwrap();
    // The root keeps an attribute of its own, like the counter of file numbers.
    fs.setattr(b"/", ATTR, &[9u8; 48]).unwrap();
    assert_eq!(check_directory(&mut fs, "/"), 1);
    assert_eq!(check_directory(&mut fs, "/w"), 31);
    let mut b = [0u8; 48];
    let (info, size) = fs.stat_attr(b"/", ATTR, &mut b).unwrap();
    assert_eq!(
        (info.kind, size, b),
        (crate::Kind::Directory, Some(48), [9u8; 48])
    );
    let (info, size) = fs.stat_attr(b"/w/sub", ATTR, &mut b).unwrap();
    assert_eq!((info.kind, size), (crate::Kind::Directory, None));
    let (info, size) = fs.stat_attr(b"/w/e00001", ATTR, &mut b).unwrap();
    assert_eq!(
        (info.kind, info.size, size),
        (crate::Kind::File, 0, Some(48))
    );
    assert_eq!(
        fs.stat_attr(b"/w/e00000", ATTR, &mut b).unwrap().1,
        None,
        "every seventh entry has none"
    );
    assert_eq!(
        fs.stat_attr(b"/w/missing", ATTR, &mut b),
        Err(Error::NoEntry)
    );
    // A type that no entry has.
    let (_, size) = fs.stat_attr(b"/w/e00001", 0x7e, &mut b).unwrap();
    assert_eq!(size, None);
}

/// The reads of the walk of `/w` by `readdir` alone, by `readdir_attr` and by `readdir` with a
/// `getattr` of each path, each on a volume just mounted.
fn directory_costs(fs: Vol) -> (u64, u64, u64) {
    let mut cold = restarted(fs);
    let at = reads(&mut cold);
    let d = cold.opendir(b"/w").unwrap();
    while cold.readdir(d).unwrap().is_some() {}
    cold.closedir(d).unwrap();
    let plain = reads(&mut cold) - at;

    let mut cold = restarted(cold);
    let at = reads(&mut cold);
    let d = cold.opendir(b"/w").unwrap();
    let mut b = [0u8; 48];
    let mut n = 0;
    while cold.readdir_attr(d, ATTR, &mut b).unwrap().is_some() {
        n += 1;
    }
    cold.closedir(d).unwrap();
    let attributed = reads(&mut cold) - at;
    assert_eq!(n, ENTRIES + 2);

    let mut cold = restarted(cold);
    let at = reads(&mut cold);
    let d = cold.opendir(b"/w").unwrap();
    while let Some(e) = cold.readdir(d).unwrap() {
        if e.name() == b"." || e.name() == b".." {
            continue;
        }
        let path = format!("/w/{}", core::str::from_utf8(e.name()).unwrap());
        let _ = by_path(&mut cold, &path);
    }
    cold.closedir(d).unwrap();
    (plain, attributed, reads(&mut cold) - at)
}

/// The directory of the plan's measurement (tests_scale: 1,000 empty files, no attribute): the
/// listing costs 45 reads, and the attributes from the iterator add at most 2 for each entry.
#[test]
fn a_directory_of_entries_with_no_attribute_is_read_with_its_attributes_for_about_the_read_alone() {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    for i in 0..ENTRIES {
        let f = fs
            .open(
                format!("/w/{}", name_of(i)).as_bytes(),
                Open::WRITE.with(Open::CREATE),
            )
            .unwrap();
        fs.close(f).unwrap();
    }
    let (plain, attributed, by_paths) = directory_costs(fs);
    println!(
        "1,000 entries, no attribute: readdir {plain} reads; readdir_attr {attributed}; \
         readdir and getattr of each path {by_paths}"
    );
    assert!(attributed <= 45 + 2 * ENTRIES as u64, "{attributed} reads");
    assert!(attributed <= plain + 2 * ENTRIES as u64);
}

/// The directory as the service keeps it, every entry with its 48-byte attribute: the listing with
/// the attributes costs the reads of the listing alone (no more than half a read for each entry),
/// and a `getattr` of each path adds more than fifty times that.
#[test]
fn a_directory_of_entries_with_attributes_is_listed_with_them_for_the_reads_of_the_listing() {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    make_entries(&mut fs, 0, ENTRIES);
    let (plain, attributed, by_paths) = directory_costs(fs);
    println!(
        "1,000 entries with attributes: readdir {plain} reads; readdir_attr {attributed}; \
         readdir and getattr of each path {by_paths}"
    );
    assert!(attributed <= ENTRIES as u64 / 2, "{attributed} reads");
    assert!(
        attributed <= plain + 100,
        "{attributed} reads against {plain}"
    );
    assert!(
        by_paths > 50 * attributed,
        "{by_paths} against {attributed}"
    );
}

/// The same after every attribute was rewritten three times, as updates of the times and `chmod`
/// do: the log of each pair is longer, and the listing with the attributes still costs half a
/// read for each entry at most.
#[test]
fn a_directory_whose_attributes_were_rewritten_three_times_is_listed_for_half_a_read_an_entry() {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    make_entries(&mut fs, 0, ENTRIES);
    for round in 1..=3u8 {
        for i in 0..ENTRIES {
            let path = format!("/w/{}", name_of(i));
            fs.setattr(path.as_bytes(), ATTR, &[round ^ i as u8; 48])
                .unwrap();
        }
    }
    let (plain, attributed, _) = directory_costs(fs);
    println!(
        "1,000 entries rewritten three times: readdir {plain} reads; readdir_attr {attributed}"
    );
    assert!(attributed <= ENTRIES as u64 / 2, "{attributed} reads");
    assert!(
        attributed <= plain + 100,
        "{attributed} reads against {plain}"
    );
}

#[test]
fn a_stat_with_its_attribute_at_depth_two_costs_no_more_than_the_stat() {
    let mut fs = fresh();
    fs.mkdir(b"/a").unwrap();
    fs.mkdir(b"/a/b").unwrap();
    let f = fs.open(b"/a/b/f", Open::WRITE.with(Open::CREATE)).unwrap();
    fs.close(f).unwrap();
    fs.setattr(b"/a/b/f", ATTR, &[5u8; 48]).unwrap();
    let mut cold = restarted(fs);
    let mut b = [0u8; 48];
    let at = reads(&mut cold);
    let (info, size) = cold.stat_attr(b"/a/b/f", ATTR, &mut b).unwrap();
    let one = reads(&mut cold) - at;
    assert_eq!(
        (info.kind, size, b),
        (crate::Kind::File, Some(48), [5u8; 48])
    );
    let mut cold = restarted(cold);
    let at = reads(&mut cold);
    cold.stat(b"/a/b/f").unwrap();
    let mut c = [0u8; 48];
    let _ = cold.getattr(b"/a/b/f", ATTR, &mut c).unwrap();
    let two = reads(&mut cold) - at;
    let mut cold = restarted(cold);
    let at = reads(&mut cold);
    cold.stat(b"/a/b/f").unwrap();
    let plain = reads(&mut cold) - at;
    println!(
        "stat with its attribute at depth 2: {one} reads; stat alone {plain}; stat and getattr {two}"
    );
    // The attribute is in the pair the stat has just read: it costs nothing more, where a getattr
    // by path repeats the whole lookup.
    assert!(one <= plain, "{one} reads against {plain}");
    // An absolute bound: a path of depth 2 costs 9 reads, a few more for each level.
    assert!(one <= 12, "{one} reads");
    assert!(one * 3 <= two * 2, "{one} reads against {two}");
}

#[test]
fn a_stat_with_its_attribute_at_depth_eight_costs_no_more_than_thirty_two_reads() {
    let mut fs = fresh();
    let mut path = String::new();
    for d in 0..8 {
        path.push_str(&format!("/d{d}"));
        fs.mkdir(path.as_bytes()).unwrap();
    }
    path.push_str("/f");
    let f = fs
        .open(path.as_bytes(), Open::WRITE.with(Open::CREATE))
        .unwrap();
    fs.close(f).unwrap();
    fs.setattr(path.as_bytes(), ATTR, &[5u8; 48]).unwrap();
    let mut cold = restarted(fs);
    let mut b = [0u8; 48];
    let at = reads(&mut cold);
    let (_, size) = cold.stat_attr(path.as_bytes(), ATTR, &mut b).unwrap();
    let one = reads(&mut cold) - at;
    assert_eq!(size, Some(48));
    println!("stat with its attribute at depth 8: {one} reads");
    assert!(one <= 32, "{one} reads");
}

/// The size of a directory is 0: littlefs's stat leaves the field of `info` as it was, and the
/// wrappers start from a cleared one.
#[test]
fn the_size_of_a_directory_and_of_the_root_is_zero() {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    let mut b = [0u8; 48];
    for path in [&b"/"[..], b"/w"] {
        assert_eq!(fs.stat(path).unwrap().size, 0);
        let (info, size) = fs.stat_attr(path, ATTR, &mut b).unwrap();
        assert_eq!(
            (info.kind, info.size, size),
            (crate::Kind::Directory, 0, None)
        );
    }
}

#[test]
fn removing_entries_while_iterating_keeps_each_attribute_with_its_entry() {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    make_entries(&mut fs, 0, 300);
    let d = fs.opendir(b"/w").unwrap();
    let mut seen = 0;
    loop {
        let mut b = [0u8; 48];
        let Some((entry, size)) = fs.readdir_attr(d, ATTR, &mut b).unwrap() else {
            break;
        };
        if entry.name() == b"." || entry.name() == b".." {
            continue;
        }
        let name = core::str::from_utf8(entry.name()).unwrap().to_string();
        let i: usize = name[1..].parse().unwrap();
        assert_eq!(
            size.map(|n| n.min(48)),
            attribute_of(i).map(|a| a.len()),
            "{name}"
        );
        if let Some(a) = attribute_of(i) {
            assert_eq!(&b[..a.len()], &a[..], "{name}: the bytes");
        }
        seen += 1;
        // Remove this entry and the one two ahead of it, as a job that cleans a directory does.
        fs.remove(format!("/w/{name}").as_bytes()).unwrap();
        let _ = fs.remove(format!("/w/{}", name_of(i + 2)).as_bytes());
    }
    fs.closedir(d).unwrap();
    assert!(seen >= 100, "{seen} entries seen");
}

fn lap(fs: &mut Vol, at: &mut u64) -> u64 {
    let now = reads(fs);
    let d = now - *at;
    *at = now;
    d
}

/// The reads of the main jobs of the service on a volume just mounted, for the directory of `n`
/// entries after `rewrites` rewrites of every attribute (what updates of the times and `chmod`
/// do). Printed as a table row by `scale_the_read_size`.
fn costs(n: usize, rewrites: usize) -> [u64; 8] {
    let mut fs = fresh();
    fs.mkdir(b"/w").unwrap();
    make_entries(&mut fs, 0, n);
    for round in 1..=rewrites {
        for i in 0..n {
            let path = format!("/w/{}", name_of(i));
            fs.setattr(path.as_bytes(), ATTR, &[round as u8 ^ i as u8; 48])
                .unwrap();
        }
    }
    let mut deep = String::new();
    for d in 0..8 {
        deep.push_str(&format!("/d{d}"));
        fs.mkdir(deep.as_bytes()).unwrap();
    }
    for path in ["/d0/d1/f", "/d0/d1/d2/d3/d4/d5/d6/d7/f"] {
        let f = fs
            .open(path.as_bytes(), Open::WRITE.with(Open::CREATE))
            .unwrap();
        fs.close(f).unwrap();
        fs.setattr(path.as_bytes(), ATTR, &[3u8; 48]).unwrap();
    }
    let mut out = [0u64; 8];
    let mut b = [0u8; 48];
    // The reads of the mount: the device counts from its creation, and a restart keeps the count
    // of the device it was given, so the mount is what `restarted` adds.
    let before = reads(&mut fs);
    let mut cold = restarted(fs);
    out[0] = reads(&mut cold) - before;
    let mut at = reads(&mut cold);
    cold.used_blocks().unwrap();
    out[1] = lap(&mut cold, &mut at);
    let mut cold = restarted(cold);
    at = reads(&mut cold);
    cold.stat_attr(b"/d0/d1/f", ATTR, &mut b).unwrap();
    out[2] = lap(&mut cold, &mut at);
    let mut cold = restarted(cold);
    at = reads(&mut cold);
    cold.stat_attr(b"/d0/d1/d2/d3/d4/d5/d6/d7/f", ATTR, &mut b)
        .unwrap();
    out[3] = lap(&mut cold, &mut at);
    let mut cold = restarted(cold);
    at = reads(&mut cold);
    let f = cold
        .open(b"/w/new", Open::WRITE.with(Open::CREATE))
        .unwrap();
    cold.close(f).unwrap();
    cold.setattr(b"/w/new", ATTR, &[1u8; 48]).unwrap();
    out[4] = lap(&mut cold, &mut at);
    let mut cold = restarted(cold);
    at = reads(&mut cold);
    let d = cold.opendir(b"/w").unwrap();
    while cold.readdir(d).unwrap().is_some() {}
    out[5] = lap(&mut cold, &mut at);
    cold.closedir(d).unwrap();
    let mut cold = restarted(cold);
    at = reads(&mut cold);
    let d = cold.opendir(b"/w").unwrap();
    while cold.readdir_attr(d, ATTR, &mut b).unwrap().is_some() {}
    out[6] = lap(&mut cold, &mut at);
    cold.closedir(d).unwrap();
    out[7] = cold.device().read_sectors;
    out
}

/// Prints the table of the plan for the read size of the volume: run by name,
/// `cargo test -p datafs --lib scale_the_read_size -- --ignored --nocapture`.
#[test]
#[ignore]
fn scale_the_read_size() {
    println!(
        "| entries | rewrites | mount | first walk | stat_attr depth 2 | stat_attr depth 8 | create | readdir | readdir_attr |"
    );
    for (n, rewrites) in [(100, 0), (1000, 0), (100, 3), (1000, 3)] {
        let c = costs(n, rewrites);
        println!(
            "| {n} | {rewrites} | {} | {} | {} | {} | {} | {} | {} |",
            c[0], c[1], c[2], c[3], c[4], c[5], c[6]
        );
    }
}
