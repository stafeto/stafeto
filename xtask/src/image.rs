// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Checks on the kernel image produced by objcopy.

/// Offsets and values of the arm64 Image header (Linux booting.rst).
pub const IMAGE_SIZE_OFFSET: usize = 0x10;
pub const FLAGS_OFFSET: usize = 0x18;
pub const MAGIC_OFFSET: usize = 0x38;
pub const MAGIC: u32 = 0x644d_5241;
/// Little endian, 4 KiB pages, may be placed anywhere in RAM.
pub const FLAGS: u64 = 0xa;

pub fn check_header(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 64 {
        return Err(format!("kernel image is {} bytes, shorter than the 64-byte arm64 header", bytes.len()));
    }
    let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    if u32_at(MAGIC_OFFSET) != MAGIC {
        return Err("kernel image has no arm64 Image magic at offset 0x38".into());
    }
    if u64_at(IMAGE_SIZE_OFFSET) < bytes.len() as u64 {
        return Err("image_size in the header is smaller than the file".into());
    }
    if u64_at(FLAGS_OFFSET) != FLAGS {
        return Err(format!("unexpected Image flags {:#x}, want {FLAGS:#x}", u64_at(FLAGS_OFFSET)));
    }
    Ok(())
}

pub fn check_size(len: u64, limit: u64) -> Result<(), String> {
    if len <= limit {
        Ok(())
    } else {
        Err(format!("kernel image is {len} bytes, over the {limit}-byte limit"))
    }
}

/// Stand-in boot image until the real format arrives in milestone 4: the
/// signature the kernel tests look for, padded to one page.
pub fn placeholder_boot_image() -> Vec<u8> {
    let mut v = b"STAFBOOT".to_vec();
    v.resize(4096, 0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(magic: u32, image_size: u64, flags: u64, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&magic.to_le_bytes());
        b[IMAGE_SIZE_OFFSET..IMAGE_SIZE_OFFSET + 8].copy_from_slice(&image_size.to_le_bytes());
        b[FLAGS_OFFSET..FLAGS_OFFSET + 8].copy_from_slice(&flags.to_le_bytes());
        b
    }

    #[test]
    fn accepts_a_valid_header() {
        assert!(check_header(&image(MAGIC, 8192, FLAGS, 4096)).is_ok());
    }

    #[test]
    fn rejects_missing_magic() {
        assert!(check_header(&image(0, 8192, FLAGS, 4096)).is_err());
    }

    #[test]
    fn rejects_a_file_shorter_than_the_header() {
        assert!(check_header(&[0; 10]).is_err());
    }

    #[test]
    fn rejects_image_size_smaller_than_the_file() {
        assert!(check_header(&image(MAGIC, 100, FLAGS, 4096)).is_err());
    }

    #[test]
    fn rejects_unexpected_flags() {
        assert!(check_header(&image(MAGIC, 8192, 0x2, 4096)).is_err());
    }

    #[test]
    fn size_limit_is_inclusive() {
        assert!(check_size(204_800, 204_800).is_ok());
        assert!(check_size(204_801, 204_800).is_err());
    }

    #[test]
    fn placeholder_boot_image_is_one_page_with_signature() {
        let p = placeholder_boot_image();
        assert_eq!(&p[..8], b"STAFBOOT");
        assert_eq!(p.len(), 4096);
    }
}
