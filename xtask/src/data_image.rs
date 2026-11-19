// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data volume of the image of EC2, made offline: `cargo xtask data-image <path> [--size 2G]`.
//!
//! A fresh EBS volume does not read as zeros past its first 4 KiB, so on EC2 `datafs` never takes a
//! volume for blank and never formats one. The image carries the volume made: a sparse file with
//! the table of `datafs` (the partitions `store` and `data`) and an empty littlefs with the
//! attribute FORMATTED on the data partition, which `aws image` uploads as the second snapshot of
//! the AMI. The file is made by `datafs::volume::open` on a file-backed device, the code that runs
//! on the first boot of a blank disk, so no second formatter exists.
//!
//! The output is the same on every run: the GUIDs of the disk and of the partitions come from a
//! fixed seed (`SEED`), and neither the table nor littlefs holds a time.

use datafs::fs::Storage;
use datafs::volume::{self, Did};
use datafs::{Device, DeviceError, SECTOR};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// The size of the data volume of the image, in bytes (2 GiB: `DATA_VOLUME_GIB` of `aws.rs`).
pub const DEFAULT_SIZE: u64 = 2 << 30;

/// The seed of the GUIDs of the disk and of its partitions. Every image has the same ones.
const SEED: u64 = 0x5374_6166_6574_6f21;

/// A file as the sectors of a disk.
pub struct FileDevice {
    file: File,
    sectors: u64,
}

impl FileDevice {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let len = file
            .metadata()
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        Ok(Self {
            file,
            sectors: len / SECTOR as u64,
        })
    }
}

impl Device for FileDevice {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        let end = sector + (out.len() / SECTOR) as u64;
        if end > self.sectors {
            return Err(DeviceError);
        }
        self.file
            .read_exact_at(out, sector * SECTOR as u64)
            .map_err(|_| DeviceError)
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), DeviceError> {
        let end = sector + (data.len() / SECTOR) as u64;
        if end > self.sectors {
            return Err(DeviceError);
        }
        self.file
            .write_all_at(data, sector * SECTOR as u64)
            .map_err(|_| DeviceError)
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        self.file.sync_data().map_err(|_| DeviceError)
    }
}

/// The size in bytes of `4096`, `64M` or `2G` (M and G are MiB and GiB).
pub fn parse_size(text: &str) -> Result<u64, String> {
    let (digits, unit) = match text.char_indices().last() {
        Some((at, 'M')) => (&text[..at], 1u64 << 20),
        Some((at, 'G')) => (&text[..at], 1u64 << 30),
        _ => (text, 1),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(unit))
        .filter(|n| *n >= 16 << 20 && n % SECTOR as u64 == 0)
        .ok_or_else(|| format!("--size {text:?}: a size of at least 16M, such as 64M or 2G"))
}

/// Makes the file at `path` (replacing it): `size` bytes, sparse, with the table and the
/// file system. Returns what `datafs` did, which is `Did::Partitioned`.
pub fn make(path: &Path, size: u64) -> Result<Did, String> {
    let file = File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.set_len(size)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    drop(file);
    let mut state = Box::new(Storage::new());
    let device = FileDevice::open(path)?;
    let (mut fs, did, _) = volume::open(device, &mut state, SEED)
        .map_err(|r| format!("{}: datafs refused the file: {}", path.display(), r.text()))?;
    fs.unmount()
        .map_err(|e| format!("{}: unmount: {e:?}", path.display()))?;
    fs.into_device()
        .device
        .flush()
        .map_err(|_| format!("{}: flush failed", path.display()))?;
    Ok(did)
}

/// The time every entry of the volume of the POSIX probe carries, in nanoseconds: 2023-11-14
/// 22:13:20 UTC. The C probe compares `st_mtime` with `1700000000`.
pub const POSIX_VOLUME_TIME_NS: i64 = 1_700_000_000_000_000_000;
/// The entries of the directory `/many` of the POSIX volume: several batches of a listing.
pub const POSIX_VOLUME_MANY: u32 = 300;

/// One entry of the POSIX volume: the path, the kind (None for a directory, the size and the salt of
/// the bytes for a file), the owner and the mode.
struct Entry {
    path: String,
    file: Option<(usize, u8)>,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// The tree of the volume of the POSIX probe (tests/posix-data/data.c knows it by heart): the entries
/// in the order they are made. A file has `((i % 251) + salt) as u8` at byte `i`.
fn posix_volume_entries() -> Vec<Entry> {
    let e = |path: &str, file: Option<(usize, u8)>, (uid, gid): (u32, u32), mode: u32| Entry {
        path: path.to_owned(),
        file,
        uid,
        gid,
        mode,
    };
    let mut v = vec![
        e("/pub", Some((5000, 1)), (0, 0), 0o644),
        e("/secret", Some((100, 2)), (0, 0), 0o600),
        e("/mine", Some((64, 3)), (1000, 100), 0o640),
        e("/dir", None, (0, 0), 0o755),
        e("/dir/a", Some((10, 4)), (0, 0), 0o644),
        e("/dir/b", Some((11, 5)), (0, 0), 0o644),
        e("/dir/c", Some((12, 6)), (0, 0), 0o644),
        e("/hidden", None, (2000, 200), 0o700),
        e("/hidden/inside", Some((8, 9)), (2000, 200), 0o644),
        e("/many", None, (0, 0), 0o755),
    ];
    for n in 0..POSIX_VOLUME_MANY {
        v.push(e(&format!("/many/f{n:03}"), Some((0, 0)), (0, 0), 0o644));
    }
    v
}

/// The data volume of the POSIX probe, made offline: a version 3 volume (every entry has its record,
/// the root has the format mark and the counter of file numbers), so the service converts nothing
/// and the owners, the modes and the numbers are those the C probe knows. The record is written with
/// the format of `datafs::attr`, the one the service reads: the attribute 0x70 on every entry, the
/// mark 0x66 and the counter 0x69 on the root. A file number is the place of the entry in the order
/// of `posix_volume_entries` plus 2 (the root has 1); the counter starts above all of them.
pub fn make_posix_volume(path: &Path, size: u64) -> Result<(), String> {
    use datafs::attr::{ATTR_COUNTER_TYPE, ATTR_FORMAT_TYPE, ATTR_TYPE, Attr, VOLUME_FORMAT};
    make(path, size)?;
    let mut state = Box::new(Storage::new());
    let (mut fs, _, _) = volume::open(FileDevice::open(path)?, &mut state, SEED)
        .map_err(|r| format!("{}: datafs refused the file: {}", path.display(), r.text()))?;
    let record = |mode: u32, uid: u32, gid: u32, ino: u64| {
        Attr {
            uid,
            gid,
            mode,
            ino,
            atime: POSIX_VOLUME_TIME_NS,
            mtime: POSIX_VOLUME_TIME_NS,
            ctime: POSIX_VOLUME_TIME_NS,
        }
        .to_bytes()
    };
    let entries = posix_volume_entries();
    for (i, entry) in entries.iter().enumerate() {
        let ino = i as u64 + 2;
        let name = entry.path.as_bytes();
        match entry.file {
            None => fs
                .mkdir(name)
                .map_err(|e| format!("{}: mkdir {e:?}", entry.path))?,
            Some((bytes, salt)) => {
                let flags = datafs::Open::WRITE.with(datafs::Open::CREATE);
                let file = fs
                    .open(name, flags)
                    .map_err(|e| format!("{}: open {e:?}", entry.path))?;
                let data: Vec<u8> = (0..bytes)
                    .map(|k| ((k % 251) as u8).wrapping_add(salt))
                    .collect();
                if !data.is_empty() {
                    fs.write(file, &data)
                        .map_err(|e| format!("{}: write {e:?}", entry.path))?;
                }
                fs.close(file)
                    .map_err(|e| format!("{}: close {e:?}", entry.path))?;
            }
        }
        fs.setattr(
            name,
            ATTR_TYPE,
            &record(entry.mode, entry.uid, entry.gid, ino),
        )
        .map_err(|e| format!("{}: setattr {e:?}", entry.path))?;
    }
    fs.setattr(b"/", ATTR_TYPE, &record(0o755, 0, 0, 1))
        .map_err(|e| format!("/: setattr {e:?}"))?;
    fs.setattr(b"/", ATTR_FORMAT_TYPE, &VOLUME_FORMAT.to_le_bytes())
        .map_err(|e| format!("/: format mark {e:?}"))?;
    let counter = entries.len() as u64 + 100;
    fs.setattr(b"/", ATTR_COUNTER_TYPE, &counter.to_le_bytes())
        .map_err(|e| format!("/: counter {e:?}"))?;
    fs.unmount()
        .map_err(|e| format!("{}: unmount: {e:?}", path.display()))?;
    fs.into_device()
        .device
        .flush()
        .map_err(|_| format!("{}: flush failed", path.display()))
}

/// `cargo xtask data-image <path> [--size 2G]`.
pub fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: xtask data-image <path> [--size 2G]";
    let path = args.first().filter(|a| !a.starts_with("--")).ok_or(usage)?;
    let size = match args.get(1).map(String::as_str) {
        None => DEFAULT_SIZE,
        Some("--size") => parse_size(args.get(2).ok_or(usage)?)?,
        Some(_) => return Err(usage.to_string()),
    };
    if args.len() > 3 {
        return Err(usage.to_string());
    }
    let did = make(Path::new(path), size)?;
    println!("data-image: {path}, {size} bytes: {did:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("stafeto-data-image-{}-{name}", std::process::id()))
    }

    #[test]
    fn sizes_are_parsed() {
        assert_eq!(parse_size("2G"), Ok(2 << 30));
        assert_eq!(parse_size("64M"), Ok(64 << 20));
        assert_eq!(parse_size("33554432"), Ok(32 << 20));
        assert!(parse_size("1M").is_err());
        assert!(parse_size("x").is_err());
        assert!(parse_size("20000001").is_err());
    }

    #[test]
    fn the_image_mounts_without_being_formatted_again_and_is_the_same_every_time() {
        let (a, b) = (temp("a"), temp("b"));
        assert_eq!(make(&a, 64 << 20), Ok(Did::Partitioned));
        assert_eq!(make(&b, 64 << 20), Ok(Did::Partitioned));
        assert!(
            std::fs::read(&a).unwrap() == std::fs::read(&b).unwrap(),
            "two runs differ"
        );
        // The first boot on EC2 runs `volume::open` on this file: it mounts, and nothing is formatted
        // or partitioned.
        let mut state = Box::new(Storage::new());
        let (mut fs, did, part) =
            volume::open(FileDevice::open(&a).unwrap(), &mut state, 1).unwrap();
        assert_eq!(did, Did::Mounted);
        assert_eq!(part.kind, datafs::gpt::TYPE_DATA);
        assert!(part.attributes & datafs::gpt::FORMATTED != 0);
        // A file written and kept, as the key of the host is.
        let f = fs
            .open(b"/key", datafs::Open::WRITE.with(datafs::Open::CREATE))
            .unwrap();
        fs.write(f, b"kept").unwrap();
        fs.sync(f).unwrap();
        fs.close(f).unwrap();
        fs.unmount().unwrap();
        drop(fs);
        let mut state = Box::new(Storage::new());
        let (mut fs, did, _) = volume::open(FileDevice::open(&a).unwrap(), &mut state, 2).unwrap();
        assert_eq!(did, Did::Mounted);
        assert_eq!(fs.stat(b"/key").unwrap().size, 4);
        fs.unmount().unwrap();
        drop(fs);
        let _ = (std::fs::remove_file(&a), std::fs::remove_file(&b));
    }

    #[test]
    fn the_posix_volume_carries_the_records_the_c_probe_expects() {
        use datafs::attr::{ATTR_COUNTER_TYPE, ATTR_FORMAT_TYPE, ATTR_TYPE, Attr, VOLUME_FORMAT};
        let path = temp("posix");
        make_posix_volume(&path, 64 << 20).unwrap();
        let mut state = Box::new(Storage::new());
        let (mut fs, did, _) =
            volume::open(FileDevice::open(&path).unwrap(), &mut state, 1).unwrap();
        assert_eq!(did, Did::Mounted);
        let record = |fs: &mut datafs::Fs<'_, datafs::Window<FileDevice>>, p: &[u8]| {
            let mut out = [0u8; 64];
            let n = fs.getattr(p, ATTR_TYPE, &mut out).unwrap();
            Attr::from_bytes(&out[..n]).unwrap()
        };
        let root = record(&mut fs, b"/");
        assert_eq!((root.mode, root.uid, root.ino), (0o755, 0, 1));
        let mut mark = [0u8; 4];
        assert_eq!(fs.getattr(b"/", ATTR_FORMAT_TYPE, &mut mark).unwrap(), 4);
        assert_eq!(u32::from_le_bytes(mark), VOLUME_FORMAT);
        let mut counter = [0u8; 8];
        assert_eq!(
            fs.getattr(b"/", ATTR_COUNTER_TYPE, &mut counter).unwrap(),
            8
        );
        let mine = record(&mut fs, b"/mine");
        assert_eq!((mine.uid, mine.gid, mine.mode), (1000, 100, 0o640));
        assert_eq!(record(&mut fs, b"/hidden").mode, 0o700);
        assert_eq!(record(&mut fs, b"/hidden/inside").uid, 2000);
        assert_eq!(fs.stat(b"/pub").unwrap().size, 5000);
        // The numbers are distinct and under the counter, every entry has one.
        let mut seen = std::collections::BTreeSet::new();
        for entry in posix_volume_entries() {
            let ino = record(&mut fs, entry.path.as_bytes()).ino;
            assert!(
                ino >= 2 && ino < u64::from_le_bytes(counter),
                "{}",
                entry.path
            );
            assert!(seen.insert(ino), "{} repeats {ino}", entry.path);
        }
        // The bytes are the pattern the C probe computes.
        let file = fs.open(b"/dir/b", datafs::Open::READ).unwrap();
        let mut got = [0u8; 16];
        assert_eq!(fs.read(file, &mut got).unwrap(), 11);
        assert_eq!(got[3], 3 + 5);
        fs.close(file).unwrap();
        fs.unmount().unwrap();
        drop(fs);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_file_that_grew_is_relocated_by_the_same_code() {
        let a = temp("grown");
        make(&a, 64 << 20).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
        file.set_len(128 << 20).unwrap();
        drop(file);
        let mut state = Box::new(Storage::new());
        let (mut fs, did, _) = volume::open(FileDevice::open(&a).unwrap(), &mut state, 1).unwrap();
        assert_eq!(did, Did::Relocated);
        fs.unmount().unwrap();
        drop(fs);
        let mut state = Box::new(Storage::new());
        let (_, did, _) = volume::open(FileDevice::open(&a).unwrap(), &mut state, 1).unwrap();
        assert_eq!(did, Did::Mounted);
        let _ = std::fs::remove_file(&a);
    }
}
