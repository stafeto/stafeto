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
