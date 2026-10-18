// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time the clock service starts at. QEMU `virt` has a PL031, whose
//! data register counts seconds since the epoch from the host's clock;
//! Apple VZ has none, so `tools/vz-run.swift` writes the host's time into
//! the file `boot-time` of the boot image (`SEED_FILE`) before it starts the
//! guest. The service reads one of them and starts CLOCK_REALTIME there; a
//! time before `FLOOR` is no time (a reading of zero, a file nobody wrote)
//! and the service keeps its own start.

#![cfg_attr(not(test), no_std)]

/// Where the PL031 of QEMU `virt` lies.
pub const PL031_BASE: u64 = 0x0901_0000;
/// The data register of the PL031: seconds since the epoch, read-only.
pub const PL031_DR: usize = 0x000;

/// The least time that counts: 2026-01-01 00:00:00 UTC, the start of the
/// clock service without a source.
pub const FLOOR: u64 = 1_767_225_600;

/// The name of the file of the boot image with the time of a VZ start.
pub const SEED_FILE: &str = "boot-time";
/// The signature of the file, then the seconds as u64, little endian: 16
/// bytes. The runner writes the seconds where it finds the signature in
/// the file of that name.
pub const SEED_MAGIC: [u8; 8] = *b"STAFTIME";
pub const SEED_SIZE: usize = 16;

/// The seconds a reading of the PL031 gives, or `None` when they are
/// before `FLOOR`.
pub fn from_pl031(reading: u32) -> Option<u64> {
    let seconds = u64::from(reading);
    (seconds >= FLOOR).then_some(seconds)
}

/// The file `boot-time` with `seconds` in it (0 for none).
pub fn seed_file(seconds: u64) -> [u8; SEED_SIZE] {
    let mut file = [0; SEED_SIZE];
    file[..8].copy_from_slice(&SEED_MAGIC);
    file[8..].copy_from_slice(&seconds.to_le_bytes());
    file
}

/// The seconds the contents of the file `boot-time` hold, or `None` for a
/// file that is no seed or holds a time before `FLOOR`.
pub fn from_seed_file(file: &[u8]) -> Option<u64> {
    if file.len() < SEED_SIZE || file[..8] != SEED_MAGIC {
        return None;
    }
    let mut seconds = [0; 8];
    seconds.copy_from_slice(&file[8..16]);
    let seconds = u64::from_le_bytes(seconds);
    (seconds >= FLOOR).then_some(seconds)
}

/// The seconds the file `boot-time` of the boot image `image` holds.
pub fn from_image(image: &[u8]) -> Option<u64> {
    let image = bootimg::BootImage::parse(image).ok()?;
    let seed = image.files().find(|file| file.name == SEED_FILE)?;
    from_seed_file(seed.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reading_below_the_floor_is_no_time() {
        assert_eq!(from_pl031(0), None);
        assert_eq!(from_pl031(FLOOR as u32 - 1), None);
        assert_eq!(from_pl031(FLOOR as u32), Some(FLOOR));
        assert_eq!(from_pl031(u32::MAX), Some(u64::from(u32::MAX)));
    }

    #[test]
    fn the_seed_file_reads_back_and_the_unwritten_one_is_none() {
        let now = FLOOR + 123_456;
        assert_eq!(from_seed_file(&seed_file(now)), Some(now));
        assert_eq!(from_seed_file(&seed_file(0)), None);
        assert_eq!(from_seed_file(&seed_file(FLOOR - 1)), None);
        let mut other = seed_file(now);
        other[0] = b'X';
        assert_eq!(from_seed_file(&other), None);
        assert_eq!(from_seed_file(&seed_file(now)[..15]), None);
        // The file is padded to the page in the image.
        let mut padded = seed_file(now).to_vec();
        padded.resize(4096, 0);
        assert_eq!(from_seed_file(&padded), Some(now));
    }

    #[test]
    fn the_seed_is_found_by_name_in_a_boot_image() {
        let now = FLOOR + 99;
        let image = bootimg::write::image(&[
            ("init", b"init"),
            (SEED_FILE, &seed_file(now)),
            ("other", &seed_file(FLOOR + 1)),
        ])
        .unwrap();
        assert_eq!(from_image(&image), Some(now));
        let without = bootimg::write::image(&[("init", b"init")]).unwrap();
        assert_eq!(from_image(&without), None);
        assert_eq!(from_image(b"not an image"), None);
    }
}
