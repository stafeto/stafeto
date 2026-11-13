// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The disk of the EFI loader: a raw file of 1 GiB (the smallest gp3 volume)
//! with a GPT, one ESP partition of FAT32 and the loader, the kernel and
//! the boot image on it (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section 6). The GPT is written here
//! (protective MBR, header and entries with CRC32, the copy at the end); the
//! FAT32 comes from `fatfs`, with the clock of the host left out. The GUIDs
//! come from a hash of the files and every time stamp is constant, so the
//! same files give the same disk.

use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use fscommon::{BufStream, StreamSlice};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const SECTOR: u64 = 512;
/// The smallest volume of EBS gp3 (stafeto-design tasks/2026-11-12-aws-efi-loader.md, section 6).
pub const DISK_BYTES: u64 = 1 << 30;
const SECTORS: u64 = DISK_BYTES / SECTOR;
const ENTRIES: u64 = 128;
const ENTRY_SIZE: u64 = 128;
const ENTRY_SECTORS: u64 = ENTRIES * ENTRY_SIZE / SECTOR;
/// 1 MiB: the first partition's LBA.
const FIRST_LBA: u64 = 2048;
/// GUID of an EFI system partition, as written on disk (mixed endian):
/// C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// 128 bits of FNV-1a over `parts`, with the version and variant bits of a
/// random GUID set: names a disk or a partition by its content.
fn guid_of(parts: &[&[u8]], salt: u8) -> [u8; 16] {
    const BASIS: u128 = 0x6c62272e07bb014262b821756295c58d;
    const PRIME: u128 = 0x0000000001000000000000000000013B;
    let mut h = BASIS ^ u128::from(salt);
    for p in parts {
        for &b in *p {
            h = (h ^ u128::from(b)).wrapping_mul(PRIME);
        }
    }
    let mut g = h.to_le_bytes();
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

/// Where the ESP lies: the first and the last LBA, the last being the end of
/// the last whole MiB before the copy of the entries.
pub fn esp_range() -> (u64, u64) {
    let last_usable = SECTORS - 1 - ENTRY_SECTORS - 1;
    let end = (last_usable + 1) / FIRST_LBA * FIRST_LBA - 1;
    (FIRST_LBA, end)
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// The header of a GPT at `this_lba` with its copy at `other_lba`, entries at
/// `entries_lba`.
fn header(
    disk: [u8; 16],
    this_lba: u64,
    other_lba: u64,
    entries_lba: u64,
    entries_crc: u32,
) -> [u8; 92] {
    let mut h = [0u8; 92];
    h[..8].copy_from_slice(b"EFI PART");
    put32(&mut h, 8, 0x0001_0000);
    put32(&mut h, 12, 92);
    put64(&mut h, 24, this_lba);
    put64(&mut h, 32, other_lba);
    put64(&mut h, 40, 2 + ENTRY_SECTORS);
    put64(&mut h, 48, SECTORS - 2 - ENTRY_SECTORS);
    h[56..72].copy_from_slice(&disk);
    put64(&mut h, 72, entries_lba);
    put32(&mut h, 80, ENTRIES as u32);
    put32(&mut h, 84, ENTRY_SIZE as u32);
    put32(&mut h, 88, entries_crc);
    let crc = crc32(&h);
    put32(&mut h, 16, crc);
    h
}

/// The sectors of the disk before the partition and after it: LBA 0 to
/// `FIRST_LBA - 1` and the copy at the end.
fn gpt(disk: [u8; 16], part: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
    let (first, last) = esp_range();
    let mut entries = vec![0u8; (ENTRIES * ENTRY_SIZE) as usize];
    entries[..16].copy_from_slice(&ESP_TYPE);
    entries[16..32].copy_from_slice(&part);
    put64(&mut entries, 32, first);
    put64(&mut entries, 40, last);
    for (i, c) in "EFI system partition".encode_utf16().enumerate() {
        entries[56 + 2 * i..58 + 2 * i].copy_from_slice(&c.to_le_bytes());
    }
    let ecrc = crc32(&entries);
    let mut front = vec![0u8; (FIRST_LBA * SECTOR) as usize];
    // The protective MBR: one partition of type 0xEE over the rest of the disk.
    front[446 + 4] = 0xEE;
    front[446 + 2] = 2;
    // End CHS of a disk too big for it: 0xFFFFFF.
    front[446 + 5..446 + 8].fill(0xFF);
    put32(&mut front, 446 + 8, 1);
    put32(&mut front, 446 + 12, (SECTORS - 1).min(0xFFFF_FFFF) as u32);
    front[510] = 0x55;
    front[511] = 0xAA;
    let primary = header(disk, 1, SECTORS - 1, 2, ecrc);
    front[SECTOR as usize..SECTOR as usize + 92].copy_from_slice(&primary);
    front[2 * SECTOR as usize..2 * SECTOR as usize + entries.len()].copy_from_slice(&entries);
    // The copy: the entries, then the header in the last sector.
    let mut back = entries;
    let mut sector = vec![0u8; SECTOR as usize];
    sector[..92].copy_from_slice(&header(
        disk,
        SECTORS - 1,
        1,
        SECTORS - 1 - ENTRY_SECTORS,
        ecrc,
    ));
    back.extend(sector);
    (front, back)
}

/// A file on the ESP: its path with `/` between the names, and its bytes.
pub struct EspFile<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

/// Writes the disk to `path`: a sparse file of `DISK_BYTES`.
pub fn build(path: &Path, files: &[EspFile<'_>]) -> Result<(), String> {
    let err = |what: &str, e: &dyn std::fmt::Display| format!("{}: {what}: {e}", path.display());
    let contents: Vec<&[u8]> = files
        .iter()
        .flat_map(|f| [f.path.as_bytes(), f.bytes])
        .collect();
    let disk = guid_of(&contents, 1);
    let part = guid_of(&contents, 2);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| err("create", &e))?;
    file.set_len(DISK_BYTES).map_err(|e| err("size", &e))?;
    let (front, back) = gpt(disk, part);
    file.write_all(&front).map_err(|e| err("write GPT", &e))?;
    file.seek(SeekFrom::Start((SECTORS - ENTRY_SECTORS - 1) * SECTOR))
        .map_err(|e| err("seek", &e))?;
    file.write_all(&back)
        .map_err(|e| err("write the GPT copy", &e))?;

    let (first, last) = esp_range();
    let slice = StreamSlice::new(file, first * SECTOR, (last + 1) * SECTOR)
        .map_err(|e| err("partition", &e))?;
    let mut volume = BufStream::new(slice);
    // 4 KiB clusters: about 261 000 of them, over the 65 525 FAT32 needs.
    let options = FormatVolumeOptions::new()
        .fat_type(FatType::Fat32)
        .bytes_per_cluster(4096)
        .volume_label(*b"STAFETO    ")
        .volume_id(crc32(&disk));
    fatfs::format_volume(&mut volume, options).map_err(|e| err("format", &e))?;
    let fs = FileSystem::new(volume, FsOptions::new()).map_err(|e| err("mount", &e))?;
    {
        let root = fs.root_dir();
        for f in files {
            let (dirs, name) = f.path.rsplit_once('/').unwrap_or(("", f.path));
            let mut dir = root.clone();
            for d in dirs.split('/').filter(|d| !d.is_empty()) {
                dir = dir.create_dir(d).map_err(|e| err(d, &e))?;
            }
            let mut out = dir.create_file(name).map_err(|e| err(f.path, &e))?;
            out.truncate().map_err(|e| err(f.path, &e))?;
            out.write_all(f.bytes).map_err(|e| err(f.path, &e))?;
            out.flush().map_err(|e| err(f.path, &e))?;
        }
    }
    fs.unmount().map_err(|e| err("unmount", &e))?;
    // The disk is read back with the reader's checks before anyone boots it.
    let mut again = std::fs::File::open(path).map_err(|e| err("reopen", &e))?;
    let parts = read_partitions(&mut again).map_err(|e| err("check", &e))?;
    if parts.len() != 1 || parts[0].0 != ESP_TYPE {
        return Err(err("check", &"not one ESP"));
    }
    Ok(())
}

/// The files of directory `dir` (names with `/` between) of the ESP of the
/// disk at `path`, as (name, bytes): what the loader's `dump` wrote.
pub fn read_dir(path: &Path, dir: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let err = |what: &str, e: &dyn std::fmt::Display| format!("{}: {what}: {e}", path.display());
    let mut file = std::fs::File::open(path).map_err(|e| err("open", &e))?;
    let parts = read_partitions(&mut file)?;
    let (first, last) = (parts[0].1, parts[0].2);
    let slice = StreamSlice::new(file, first * SECTOR, (last + 1) * SECTOR)
        .map_err(|e| err("partition", &e))?;
    let fs =
        FileSystem::new(BufStream::new(slice), FsOptions::new()).map_err(|e| err("mount", &e))?;
    let folder = fs.root_dir().open_dir(dir).map_err(|e| err(dir, &e))?;
    let mut out = Vec::new();
    for entry in folder.iter() {
        let entry = entry.map_err(|e| err(dir, &e))?;
        if entry.is_dir() {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .to_file()
            .read_to_end(&mut bytes)
            .map_err(|e| err(&entry.file_name(), &e))?;
        out.push((entry.file_name(), bytes));
    }
    out.sort();
    Ok(out)
}

/// What a reader found: the partitions of the GPT, as (type GUID bytes, first
/// LBA, last LBA), after the checks of both headers.
pub fn read_partitions<R: Read + Seek>(disk: &mut R) -> Result<Vec<([u8; 16], u64, u64)>, String> {
    let mut sector = |lba: u64| -> Result<[u8; 512], String> {
        let mut b = [0u8; 512];
        disk.seek(SeekFrom::Start(lba * SECTOR))
            .map_err(|e| e.to_string())?;
        disk.read_exact(&mut b).map_err(|e| e.to_string())?;
        Ok(b)
    };
    let mbr = sector(0)?;
    if mbr[510..] != [0x55, 0xAA] || mbr[446 + 4] != 0xEE {
        return Err("no protective MBR".into());
    }
    let u32_at = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let u64_at = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let check = |h: &[u8; 512]| -> Result<(), String> {
        if &h[..8] != b"EFI PART" {
            return Err("no GPT signature".into());
        }
        let mut copy = h[..92].to_vec();
        copy[16..20].fill(0);
        if crc32(&copy) != u32_at(h, 16) {
            return Err("GPT header CRC".into());
        }
        Ok(())
    };
    let primary = sector(1)?;
    check(&primary)?;
    let backup_lba = u64_at(&primary, 32);
    let backup = sector(backup_lba)?;
    check(&backup)?;
    if u64_at(&backup, 24) != backup_lba || u64_at(&backup, 32) != 1 {
        return Err("the copy of the header does not point back".into());
    }
    let mut read_entries = |h: &[u8; 512]| -> Result<Vec<u8>, String> {
        let n = u32_at(h, 80) as usize * u32_at(h, 84) as usize;
        let mut buf = vec![0u8; n];
        disk.seek(SeekFrom::Start(u64_at(h, 72) * SECTOR))
            .map_err(|e| e.to_string())?;
        disk.read_exact(&mut buf).map_err(|e| e.to_string())?;
        if crc32(&buf) != u32_at(h, 88) {
            return Err("GPT entries CRC".into());
        }
        Ok(buf)
    };
    let entries = read_entries(&primary)?;
    if read_entries(&backup)? != entries {
        return Err("the copy of the entries differs".into());
    }
    Ok(entries
        .chunks(ENTRY_SIZE as usize)
        .filter(|e| e[..16] != [0; 16])
        .map(|e| (e[..16].try_into().unwrap(), u64_at(e, 32), u64_at(e, 40)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn crc32_is_the_standard_one() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn the_gpt_has_one_esp_and_the_copy_at_the_end_agrees() {
        let (front, back) = gpt(guid_of(&[b"a"], 1), guid_of(&[b"a"], 2));
        // The copy is read from the end of the real size: a sparse file.
        let path = std::env::temp_dir().join(format!("stafeto-gpt-{}.raw", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(DISK_BYTES).unwrap();
        f.write_all(&front).unwrap();
        f.seek(SeekFrom::Start((SECTORS - ENTRY_SECTORS - 1) * SECTOR))
            .unwrap();
        f.write_all(&back).unwrap();
        drop(f);
        let mut f = std::fs::File::open(&path).unwrap();
        let parts = read_partitions(&mut f).unwrap();
        std::fs::remove_file(&path).unwrap();
        let (first, last) = esp_range();
        assert_eq!(parts, [(ESP_TYPE, first, last)]);
        assert_eq!(first, 2048);
        assert_eq!((last + 1) % 2048, 0, "ends on a MiB");
        assert!(last + 1 + ENTRY_SECTORS < SECTORS, "leaves the copy");
    }

    #[test]
    fn a_damaged_header_entries_or_copy_is_refused() {
        let (front, back) = gpt(guid_of(&[b"a"], 1), guid_of(&[b"a"], 2));
        let make = |front: &[u8], back: &[u8]| {
            let mut d = vec![0u8; (SECTORS * SECTOR) as usize];
            d[..front.len()].copy_from_slice(front);
            let at = ((SECTORS - ENTRY_SECTORS - 1) * SECTOR) as usize;
            d[at..at + back.len()].copy_from_slice(back);
            d
        };
        let ok = make(&front, &back);
        assert!(read_partitions(&mut Cursor::new(&ok)).is_ok());
        let mut bad = front.clone();
        bad[SECTOR as usize + 20] ^= 1;
        assert!(read_partitions(&mut Cursor::new(make(&bad, &back))).is_err());
        let mut bad = front.clone();
        bad[2 * SECTOR as usize + 40] ^= 1;
        assert!(read_partitions(&mut Cursor::new(make(&bad, &back))).is_err());
        let mut bad = back.clone();
        let n = bad.len();
        bad[n - 512 + 40] ^= 1;
        assert!(read_partitions(&mut Cursor::new(make(&front, &bad))).is_err());
    }

    #[test]
    fn the_disk_is_one_gib_reads_back_and_is_the_same_every_time() {
        let dir = std::env::temp_dir();
        let a = dir.join(format!("stafeto-esp-a-{}.raw", std::process::id()));
        let b = dir.join(format!("stafeto-esp-b-{}.raw", std::process::id()));
        let files = [
            EspFile {
                path: "EFI/BOOT/BOOTAA64.EFI",
                bytes: b"MZ-loader",
            },
            EspFile {
                path: "stafeto/Image",
                bytes: &[7u8; 5000],
            },
            EspFile {
                path: "stafeto/boot.img",
                bytes: &[9u8; 8192],
            },
        ];
        build(&a, &files).unwrap();
        build(&b, &files).unwrap();
        assert_eq!(std::fs::metadata(&a).unwrap().len(), DISK_BYTES);
        let (xa, xb) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert!(xa == xb, "two builds differ");
        let mut f = std::fs::File::open(&a).unwrap();
        let parts = read_partitions(&mut f).unwrap();
        assert_eq!(parts.len(), 1);
        let (first, last) = (parts[0].1, parts[0].2);
        let slice = StreamSlice::new(f, first * SECTOR, (last + 1) * SECTOR).unwrap();
        let fs = FileSystem::new(BufStream::new(slice), FsOptions::new()).unwrap();
        assert_eq!(fs.fat_type(), FatType::Fat32);
        assert_eq!(fs.volume_label(), "STAFETO");
        let clusters = fs.stats().unwrap().total_clusters();
        assert!(clusters > 250_000 && clusters < 270_000, "{clusters}");
        let mut got = Vec::new();
        fs.root_dir()
            .open_file("stafeto/Image")
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, [7u8; 5000]);
        let mut got = Vec::new();
        fs.root_dir()
            .open_file("EFI/BOOT/BOOTAA64.EFI")
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, b"MZ-loader");
        std::fs::remove_file(&a).unwrap();
        std::fs::remove_file(&b).unwrap();
    }
}
