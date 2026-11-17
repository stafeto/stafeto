// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time the clock service starts at. QEMU `virt` has a PL031, whose
//! data register counts seconds since the epoch from the host's clock;
//! Apple VZ has none, so `tools/vz-run.swift` writes the host's time into
//! the file `boot-time` of the boot image (`SEED_FILE`) before it starts the
//! guest. The EFI loader does the same for the machines it boots (EC2): it
//! reads the firmware's time (UEFI GetTime) while the boot services run and
//! writes it into that file (`from_efi`, `stamp`). The service reads one of
//! them and starts CLOCK_REALTIME there; a time before `FLOOR` is no time (a
//! reading of zero, a file nobody wrote) and the service keeps its own start.

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

/// The seconds since the epoch of the UEFI time with these fields, or `None`
/// for a field out of range, a time before `FLOOR` or a year from 2100 on.
/// `tz_minutes` is the field `TimeZone` of the firmware's time: UTC is the
/// local time plus that many minutes; 0x7FF (unspecified) leaves the time as
/// it is, as UTC.
pub fn from_efi(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    tz_minutes: i16,
) -> Option<u64> {
    const UNSPECIFIED: i16 = 0x7FF;
    if !(1970..2100).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || hour > 23
        || minute > 59
        || second > 59
        || (tz_minutes != UNSPECIFIED && !(-1440..=1440).contains(&tz_minutes))
    {
        return None;
    }
    let leap = year.is_multiple_of(4); // 1970 to 2099
    let length = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day > length {
        return None;
    }
    // Days from 1970-01-01 to the date (the years are before 2100, so the
    // leap years between are those divisible by four).
    let y = i64::from(year) - 1970;
    let mut days = y * 365 + (y + 1) / 4;
    const BEFORE: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += BEFORE[usize::from(month) - 1] + i64::from(day) - 1;
    if leap && month > 2 {
        days += 1;
    }
    let mut seconds =
        days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    if tz_minutes != UNSPECIFIED {
        seconds += i64::from(tz_minutes) * 60;
    }
    u64::try_from(seconds).ok().filter(|s| *s >= FLOOR)
}

/// Writes `seconds` into the file `boot-time` of the boot image `image`, in
/// memory. False when the image has no such file or the file has no
/// signature in it; the image stays as it was.
pub fn stamp(image: &mut [u8], seconds: u64) -> bool {
    let offset = {
        let Ok(parsed) = bootimg::BootImage::parse(image) else {
            return false;
        };
        let Some(seed) = parsed.files().find(|file| file.name == SEED_FILE) else {
            return false;
        };
        if seed.data.len() < SEED_SIZE || seed.data[..8] != SEED_MAGIC {
            return false;
        }
        seed.offset as usize
    };
    let Some(file) = image.get_mut(offset..offset + SEED_SIZE) else {
        return false;
    };
    if file[..8] != SEED_MAGIC {
        return false;
    }
    file[8..].copy_from_slice(&seconds.to_le_bytes());
    true
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

    #[test]
    fn the_firmware_time_becomes_epoch_seconds() {
        const U: i16 = 0x7FF;
        // Known values: 2026-01-01 is the floor, 2026-11-17 12:34:56.
        assert_eq!(from_efi(2026, 1, 1, 0, 0, 0, 0), Some(FLOOR));
        assert_eq!(from_efi(2026, 11, 17, 12, 34, 56, 0), Some(1_794_918_896));
        // Leap years: 2028 has a 29th of February, 2100 is out, 2026 has none.
        assert_eq!(
            from_efi(2028, 3, 1, 0, 0, 0, 0).unwrap() - from_efi(2028, 2, 29, 0, 0, 0, 0).unwrap(),
            86_400
        );
        assert_eq!(
            from_efi(2028, 2, 29, 0, 0, 0, 0).unwrap() - from_efi(2028, 2, 28, 0, 0, 0, 0).unwrap(),
            86_400
        );
        assert_eq!(from_efi(2026, 2, 29, 0, 0, 0, 0), None);
        assert_eq!(from_efi(2028, 2, 30, 0, 0, 0, 0), None);
        assert_eq!(from_efi(2027, 3, 1, 0, 0, 0, 0), Some(FLOOR + 424 * 86_400));
        assert!(from_efi(2099, 12, 31, 23, 59, 59, 0).is_some());
        assert_eq!(from_efi(2100, 1, 1, 0, 0, 0, 0), None);
        // The offset has both signs: UTC is local plus the field.
        let utc = from_efi(2026, 11, 17, 12, 0, 0, 0).unwrap();
        assert_eq!(from_efi(2026, 11, 17, 12, 0, 0, -120), Some(utc - 7200));
        assert_eq!(from_efi(2026, 11, 17, 12, 0, 0, 90), Some(utc + 5400));
        assert_eq!(from_efi(2026, 11, 17, 12, 0, 0, U), Some(utc));
        // The offset moves the date across the end of a year.
        assert_eq!(
            from_efi(2026, 12, 31, 23, 0, 0, 120),
            from_efi(2027, 1, 1, 1, 0, 0, 0)
        );
        // Rejections: before the floor, fields out of range, a bad offset.
        assert_eq!(from_efi(2025, 12, 31, 23, 59, 59, 0), None);
        assert_eq!(from_efi(2026, 1, 1, 0, 0, 0, -1), None);
        assert_eq!(from_efi(1970, 1, 1, 0, 0, 0, 0), None);
        assert_eq!(from_efi(2026, 0, 1, 0, 0, 0, 0), None);
        assert_eq!(from_efi(2026, 13, 1, 0, 0, 0, 0), None);
        assert_eq!(from_efi(2026, 1, 0, 0, 0, 0, 0), None);
        assert_eq!(from_efi(2026, 4, 31, 0, 0, 0, 0), None);
        assert_eq!(from_efi(2026, 1, 1, 24, 0, 0, 0), None);
        assert_eq!(from_efi(2026, 1, 1, 0, 60, 0, 0), None);
        assert_eq!(from_efi(2026, 1, 1, 0, 0, 60, 0), None);
        assert_eq!(from_efi(2026, 6, 1, 0, 0, 0, 1441), None);
        assert_eq!(from_efi(2026, 6, 1, 0, 0, 0, -1441), None);
    }

    #[test]
    fn a_stamp_reads_back_through_the_reader() {
        let mut image = bootimg::write::image(&[
            ("init", b"init"),
            (SEED_FILE, &seed_file(0)),
            ("other", &seed_file(0)),
        ])
        .unwrap();
        assert_eq!(from_image(&image), None);
        let before = image.clone();
        let now = 1_794_918_896;
        assert!(stamp(&mut image, now));
        assert_eq!(from_image(&image), Some(now));
        // Only the seed file changed: 8 bytes.
        let changed = image.iter().zip(&before).filter(|(a, b)| a != b).count();
        assert!(changed <= 8 && changed > 0);
        assert!(stamp(&mut image, now + 1));
        assert_eq!(from_image(&image), Some(now + 1));
    }

    #[test]
    fn an_image_without_the_file_or_with_a_foreign_one_is_left_alone() {
        let mut without = bootimg::write::image(&[("init", b"init")]).unwrap();
        let before = without.clone();
        assert!(!stamp(&mut without, FLOOR + 5));
        assert_eq!(without, before);
        let mut foreign = bootimg::write::image(&[(SEED_FILE, b"not a seed file at all")]).unwrap();
        let before = foreign.clone();
        assert!(!stamp(&mut foreign, FLOOR + 5));
        assert_eq!(foreign, before);
        assert!(!stamp(&mut [0u8; 64], FLOOR + 5));
    }
}
