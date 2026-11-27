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

/// The data volume of the POSIX probe, made offline: a volume with the mark 4 (every entry has its record, no file inline,
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

/// The bit of the number of a file the layer service creates (`proto_fs::names::UPPER_INO_TAG`).
const UPPER_INO_TAG: u64 = 1 << 62;

/// What the volume of `cargo xtask layer-names-probe` holds: the layer directory with the composition
/// and the live layer 00 of the probe (the lower set is the boot image of the probe: its files
/// `/lower/*`, `/lowdir/*` and `/etc/layer-*` are in `rootfs.rs`).
///
/// Under `/.layers/00`: `etc/.wh.layer-hidden` (a mark of deletion of a lower file), `etc/layer-note`
/// (a name the lower set does not have), `etc/layer-own` (0640, owner 1000:1000, the number
/// `UPPER_INO_TAG | 5`), `etc/layer-secret` (0600, owner 0), `lower/shadowed` (shadows the lower file of the same name) with
/// `lower/.wh.hidden`, `lowdir` (the marker `.wh..wh..opq` over a lower directory, and its own
/// `u1`) and `private` (0700, owner 0, with `f`).
pub const LAYER_VOLUME_ENTRIES: &[LayerEntry] = &[
    LayerEntry::dir("/.layers", 0o700, 0, 0),
    LayerEntry::dir("/.layers/00", 0o755, 0, 0),
    LayerEntry::dir("/.layers/work", 0o700, 0, 0),
    LayerEntry::file(
        "/.layers/COMPOSITION",
        0o600,
        0,
        0,
        b"STAFLAYR 1\nnext 01\nino 8\nlower -\nlayer 00 live unsealed - -\n",
    ),
    LayerEntry::dir("/.layers/00/etc", 0o755, 0, 0),
    LayerEntry::file("/.layers/00/etc/.wh.layer-hidden", 0o644, 0, 0, b""),
    LayerEntry::file("/.layers/00/etc/layer-note", 0o644, 0, 0, b"layer note\n"),
    LayerEntry::file(
        "/.layers/00/etc/layer-own",
        0o640,
        1000,
        1000,
        LAYER_OWN_BYTES,
    )
    .numbered(UPPER_INO_TAG | 5),
    LayerEntry::file("/.layers/00/etc/layer-secret", 0o600, 0, 0, b"secret\n"),
    LayerEntry::dir("/.layers/00/lower", 0o755, 0, 0),
    LayerEntry::file("/.layers/00/lower/.wh.hidden", 0o644, 0, 0, b""),
    LayerEntry::file(
        "/.layers/00/lower/shadowed",
        0o644,
        0,
        0,
        LAYER_SHADOW_BYTES,
    ),
    LayerEntry::dir("/.layers/00/lowdir", 0o755, 0, 0),
    LayerEntry::file("/.layers/00/lowdir/.wh..wh..opq", 0o644, 0, 0, b""),
    LayerEntry::file("/.layers/00/lowdir/u1", 0o644, 0, 0, b"u1\n"),
    LayerEntry::dir("/.layers/00/private", 0o700, 0, 0),
    LayerEntry::file("/.layers/00/private/f", 0o644, 0, 0, b"private\n"),
];

/// The bytes of `/etc/layer-own` of the layer and of `/lower/shadowed`, which the probe reads.
pub const LAYER_OWN_BYTES: &[u8] = b"owned bytes of the layer\n";
pub const LAYER_SHADOW_BYTES: &[u8] = b"upper shadow\n";

/// One entry of the volume of the layer probe.
#[derive(Clone, Copy, Debug)]
pub struct LayerEntry {
    pub path: &'static str,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// None for a directory.
    pub bytes: Option<&'static [u8]>,
    /// The number of the entry, or 0 for the next one of the order of the list.
    pub ino: u64,
}

impl LayerEntry {
    pub const fn dir(path: &'static str, mode: u32, uid: u32, gid: u32) -> LayerEntry {
        LayerEntry {
            path,
            mode,
            uid,
            gid,
            bytes: None,
            ino: 0,
        }
    }

    pub const fn file(
        path: &'static str,
        mode: u32,
        uid: u32,
        gid: u32,
        bytes: &'static [u8],
    ) -> LayerEntry {
        LayerEntry {
            path,
            mode,
            uid,
            gid,
            bytes: Some(bytes),
            ino: 0,
        }
    }

    pub const fn numbered(mut self, ino: u64) -> LayerEntry {
        self.ino = ino;
        self
    }
}

/// The volume of the layer probe (`LAYER_VOLUME_ENTRIES`), with the format mark 4 so that the data
/// service converts nothing. The numbers of the entries are their places in the list plus 2, but the
/// ones the list names, and the counter starts above all of them.
pub fn make_layer_volume(path: &Path, size: u64) -> Result<(), String> {
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
    for (i, entry) in LAYER_VOLUME_ENTRIES.iter().enumerate() {
        let ino = if entry.ino != 0 {
            entry.ino
        } else {
            i as u64 + 2
        };
        let name = entry.path.as_bytes();
        match entry.bytes {
            None => fs
                .mkdir(name)
                .map_err(|e| format!("{}: mkdir {e:?}", entry.path))?,
            Some(bytes) => {
                let flags = datafs::Open::WRITE.with(datafs::Open::CREATE);
                let file = fs
                    .open(name, flags)
                    .map_err(|e| format!("{}: open {e:?}", entry.path))?;
                if !bytes.is_empty() {
                    fs.write(file, bytes)
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
    let counter = LAYER_VOLUME_ENTRIES.len() as u64 + 100;
    fs.setattr(b"/", ATTR_COUNTER_TYPE, &counter.to_le_bytes())
        .map_err(|e| format!("/: counter {e:?}"))?;
    fs.unmount()
        .map_err(|e| format!("{}: unmount: {e:?}", path.display()))?;
    fs.into_device()
        .device
        .flush()
        .map_err(|_| format!("{}: flush failed", path.display()))
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
    // The 0.5.1 service had littlefs's default: a small file lives inside the pair of its directory,
    // as the host key does on a volume that release made.
    fs.unmount()
        .map_err(|e| format!("{}: unmount: {e:?}", path.display()))?;
    fs.set_inline_max(0);
    fs.mount()
        .map_err(|e| format!("{}: mount: {e:?}", path.display()))?;
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
        // The key is inline (inside the pair of /ssh), as the 0.5.1 service left it: the move-out of
        // the mount work has to find it.
        assert_eq!(fs.outline(KEY_PATH.as_bytes(), true), Ok(true));
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
