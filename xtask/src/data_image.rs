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

/// A file as a disk whose flush does nothing: the fill writes hundreds of MiB and syncs the file once
/// at the end, since a crash of the host during the fill leaves a file that is made again.
struct Quick(FileDevice);

impl Device for Quick {
    fn sectors(&self) -> u64 {
        self.0.sectors()
    }

    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        self.0.read(sector, out)
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), DeviceError> {
        self.0.write(sector, data)
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        Ok(())
    }
}

/// What the fill puts on the volume, the way an older release leaves a volume (no attribute on any
/// entry): `small_dirs` directories of `small_per` files of `small_bytes`, `big` files of
/// `big_bytes`, a directory `/rd` of `listed` empty files and a directory `/rm` of `empty` empty
/// directories (the probe removes one and lists the other).
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub small_dirs: u32,
    pub small_per: u32,
    pub small_bytes: usize,
    pub big: u32,
    pub big_bytes: usize,
    pub listed: u32,
    pub empty: u32,
}

impl Profile {
    /// The bytes of file data the profile writes.
    #[cfg(test)]
    pub const fn data_bytes(&self) -> u64 {
        self.small_dirs as u64 * self.small_per as u64 * self.small_bytes as u64
            + self.big as u64 * self.big_bytes as u64
    }
}

/// The size of the disk file that holds a data partition of about 1 GiB: the layout gives `store`
/// 1 GiB or half the disk, whichever is less, so a disk of 1 GiB would hold a data partition of 511
/// MiB (the first fill ran out of space at the sixteenth large file). 2 GiB give `data` 1,023 MiB.
pub const FILL_DISK: u64 = 2 << 30;

/// The profile of the probe volume (a data partition of 1,023 MiB on a disk of `FILL_DISK`): 256 MiB of 2,000 files of 128 KiB, 512 MiB of 32 files of
/// 16 MiB, 1,000 files in one directory and 200 empty directories: 3,260 entries, under the 8,192 a
/// run of the conversion at mount writes, so that the first boot converts the volume whole.
pub const FILL_1G: Profile = Profile {
    small_dirs: 20,
    small_per: 100,
    small_bytes: 128 << 10,
    big: 32,
    big_bytes: 16 << 20,
    listed: 1000,
    empty: 200,
};

/// The bytes the fill writes: a pattern that is not zero, so that a block is never taken for blank.
fn pattern(out: &mut [u8], salt: u32) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(31).wrapping_add(salt) as u8 | 1;
    }
}

fn put<D: Device>(
    fs: &mut datafs::Fs<'_, datafs::Window<D>>,
    path: &str,
    bytes: usize,
    salt: u32,
) -> Result<(), String> {
    let flags = datafs::Open::WRITE.with(datafs::Open::CREATE);
    let file = fs
        .open(path.as_bytes(), flags)
        .map_err(|e| format!("{path}: open {e:?}"))?;
    let mut chunk = vec![0u8; 64 << 10];
    let mut done = 0;
    while done < bytes {
        let n = (bytes - done).min(chunk.len());
        pattern(&mut chunk[..n], salt.wrapping_add(done as u32));
        let wrote = fs
            .write(file, &chunk[..n])
            .map_err(|e| format!("{path}: write {e:?}"))?;
        if wrote != n {
            return Err(format!("{path}: a short write"));
        }
        done += n;
    }
    fs.close(file).map_err(|e| format!("{path}: close {e:?}"))
}

/// Makes the file at `path` as `make` does and puts `profile` on it. The names: `/small/d<N>/f<M>`,
/// `/big/b<N>`, `/rd/r<N>`, `/rm/e<N>`.
pub fn make_filled(path: &Path, size: u64, profile: Profile) -> Result<(), String> {
    make(path, size)?;
    let mut state = Box::new(Storage::new());
    let device = Quick(FileDevice::open(path)?);
    let (mut fs, _, _) = volume::open(device, &mut state, SEED)
        .map_err(|r| format!("{}: datafs refused the file: {}", path.display(), r.text()))?;
    let dir = |fs: &mut datafs::Fs<'_, datafs::Window<Quick>>, p: &str| {
        fs.mkdir(p.as_bytes())
            .map_err(|e| format!("{p}: mkdir {e:?}"))
    };
    // The empty directories come first: the oldest pairs are at the far end of the list of pairs of
    // the volume, where RMDIR looks up the pair before the one it removes (its worst case, which the
    // probe measures on `/rm/e0`).
    dir(&mut fs, "/rm")?;
    for e in 0..profile.empty {
        dir(&mut fs, &format!("/rm/e{e}"))?;
    }
    for top in ["/small", "/big", "/rd"] {
        dir(&mut fs, top)?;
    }
    for d in 0..profile.small_dirs {
        dir(&mut fs, &format!("/small/d{d}"))?;
        for f in 0..profile.small_per {
            put(
                &mut fs,
                &format!("/small/d{d}/f{f}"),
                profile.small_bytes,
                d * 977 + f,
            )?;
        }
    }
    for b in 0..profile.big {
        put(&mut fs, &format!("/big/b{b}"), profile.big_bytes, b)?;
    }
    for r in 0..profile.listed {
        put(&mut fs, &format!("/rd/r{r}"), 0, 0)?;
    }
    fs.unmount()
        .map_err(|e| format!("{}: unmount: {e:?}", path.display()))?;
    fs.into_device()
        .device
        .0
        .flush()
        .map_err(|_| format!("{}: flush failed", path.display()))
}

/// The path and the bytes of the key the service of the host key keeps on the volume (datakey).
pub const KEY_PATH: &str = "/ssh/dropbear_ed25519_host_key";

/// A data volume as the 0.5.1 image's service left it after the host key was saved: the table and
/// the file system of `make`, a directory `/ssh` and the key file in it, made with the plain calls
/// of the file system and no attribute on any entry (the service of that release wrote none: its
/// root, directories and files read as the defaults of the first mount of version 3). A host test
/// shows no attribute of the version-3 service anywhere on it.
pub fn make_v051(path: &Path, size: u64, key: &[u8]) -> Result<(), String> {
    make(path, size)?;
    let mut state = Box::new(Storage::new());
    let (mut fs, _, _) = volume::open(FileDevice::open(path)?, &mut state, SEED)
        .map_err(|r| format!("{}: datafs refused the file: {}", path.display(), r.text()))?;
    fs.mkdir(b"/ssh")
        .map_err(|e| format!("/ssh: mkdir {e:?}"))?;
    let flags = datafs::Open::WRITE.with(datafs::Open::CREATE);
    let file = fs
        .open(KEY_PATH.as_bytes(), flags)
        .map_err(|e| format!("{KEY_PATH}: open {e:?}"))?;
    fs.write(file, key)
        .map_err(|e| format!("{KEY_PATH}: write {e:?}"))?;
    fs.sync(file)
        .map_err(|e| format!("{KEY_PATH}: sync {e:?}"))?;
    fs.close(file)
        .map_err(|e| format!("{KEY_PATH}: close {e:?}"))?;
    fs.unmount()
        .map_err(|e| format!("{}: unmount: {e:?}", path.display()))?;
    fs.into_device()
        .device
        .flush()
        .map_err(|_| format!("{}: flush failed", path.display()))
}

/// `cargo xtask data-image <path> [--size 2G] [--fill]`: with `--fill` the volume also holds the
/// files of `FILL_1G` (about 770 MiB: for a volume of 1 GiB or more), the layout an older release
/// leaves, for the measurement of a walk and of the first mount on a device (the first boot of this
/// release converts it).
pub fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: xtask data-image <path> [--size 2G] [--fill]";
    let path = args.first().filter(|a| !a.starts_with("--")).ok_or(usage)?;
    let mut size = DEFAULT_SIZE;
    let mut fill = false;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--size" => size = parse_size(rest.next().ok_or(usage)?)?,
            "--fill" => fill = true,
            _ => return Err(usage.to_string()),
        }
    }
    if fill {
        if size < FILL_DISK {
            return Err(
                "--fill needs --size 2G or more (the data partition is about 1 GiB)".to_string(),
            );
        }
        make_filled(Path::new(path), size, FILL_1G)?;
        println!("data-image: {path}, {size} bytes, filled: Partitioned");
        return Ok(());
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
    fn a_filled_volume_has_what_the_profile_says_and_no_attribute_on_any_entry() {
        let path = temp("fill");
        let profile = Profile {
            small_dirs: 2,
            small_per: 3,
            small_bytes: 5000,
            big: 2,
            big_bytes: 200_000,
            listed: 7,
            empty: 4,
        };
        make_filled(&path, 64 << 20, profile).unwrap();
        let mut state = Box::new(Storage::new());
        let (mut fs, did, _) =
            volume::open(FileDevice::open(&path).unwrap(), &mut state, 1).unwrap();
        assert_eq!(did, Did::Mounted);
        assert_eq!(fs.stat(b"/small/d1/f2").unwrap().size, 5000);
        assert_eq!(fs.stat(b"/big/b1").unwrap().size, 200_000);
        assert_eq!(fs.stat(b"/rd/r6").unwrap().size, 0);
        assert!(fs.stat(b"/rm/e3").is_ok());
        assert!(fs.stat(b"/rm/e4").is_err());
        // The layout of an older release: no attribute of the version-3 service (the record 0x70, the
        // format mark 0x66, the counter 0x69) on the root or on an entry.
        for path in [&b"/"[..], b"/small", b"/small/d0/f0", b"/big/b0", b"/rm/e0"] {
            for kind in [0x70u8, 0x66, 0x69] {
                let mut out = [0u8; 64];
                assert!(
                    fs.getattr(path, kind, &mut out).is_err(),
                    "{path:?} has attribute {kind:#x}"
                );
            }
        }
        fs.unmount().unwrap();
        drop(fs);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_volume_of_the_old_release_has_the_key_and_no_attribute_anywhere() {
        let path = temp("v051");
        let key = [0x42u8; 120];
        make_v051(&path, 64 << 20, &key).unwrap();
        let mut state = Box::new(Storage::new());
        let (mut fs, did, _) =
            volume::open(FileDevice::open(&path).unwrap(), &mut state, 1).unwrap();
        assert_eq!(did, Did::Mounted);
        assert_eq!(fs.stat(KEY_PATH.as_bytes()).unwrap().size, 120);
        let file = fs.open(KEY_PATH.as_bytes(), datafs::Open::READ).unwrap();
        let mut back = [0u8; 200];
        assert_eq!(fs.read(file, &mut back).unwrap(), 120);
        assert_eq!(back[..120], key);
        fs.close(file).unwrap();
        for entry in [&b"/"[..], b"/ssh", KEY_PATH.as_bytes()] {
            for kind in [0x70u8, 0x66, 0x69] {
                let mut out = [0u8; 64];
                assert!(fs.getattr(entry, kind, &mut out).is_err());
            }
        }
        fs.unmount().unwrap();
        drop(fs);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_fill_profile_fits_the_data_partition_of_its_disk_with_a_margin() {
        // The partition the layout makes on the disk of the fill, in bytes.
        let layout = datafs::gpt::default_layout(FILL_DISK / SECTOR as u64).unwrap();
        let data = (layout[1].last - layout[1].first + 1) * SECTOR as u64;
        assert!(data > 1000 << 20, "the data partition is {data} bytes");
        // File data takes at most 80 % of the partition: the rest is the pairs of metadata, the
        // skip pointers of large files, the reserve of 64 blocks and the room the probe's own
        // writes (8 MiB) and removals need.
        let fill = FILL_1G.data_bytes();
        assert!(fill * 100 <= data * 80, "{fill} bytes of {data}");
        // And the probe's removals (24 files of 16 MiB) are over a sixteenth of the partition.
        assert!(24 * (16 << 20) > data / 16);
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
