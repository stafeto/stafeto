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
        return Err(format!(
            "kernel image is {} bytes, shorter than the 64-byte arm64 header",
            bytes.len()
        ));
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
        return Err(format!(
            "unexpected Image flags {:#x}, want {FLAGS:#x}",
            u64_at(FLAGS_OFFSET)
        ));
    }
    Ok(())
}

/// Growth over the recorded size that fails the build: 4 KiB, one page.
pub const GROWTH_LIMIT: u64 = 4096;

/// The recorded sizes of `kernel/size.txt`: a stem and its size in bytes on
/// each line, blank lines and lines that start with `#` skipped.
pub fn parse_record(text: &str) -> Result<Vec<(String, u64)>, String> {
    let mut sizes = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(stem), Some(size), None) = (words.next(), words.next(), words.next()) else {
            return Err(format!("kernel/size.txt line {}: want `stem bytes`", n + 1));
        };
        let size = size
            .parse()
            .map_err(|e| format!("kernel/size.txt line {}: {e}", n + 1))?;
        sizes.push((stem.to_string(), size));
    }
    if sizes.is_empty() {
        return Err("kernel/size.txt records no size".into());
    }
    Ok(sizes)
}

/// The line that compares the image of `stem`, `len` bytes, with the record,
/// and the error that fails the build when the image is more than
/// `GROWTH_LIMIT` bytes over it. None when the record has no line for `stem`.
pub fn compare(
    record: &[(String, u64)],
    stem: &str,
    len: u64,
) -> Option<(String, Result<(), String>)> {
    let (_, was) = record.iter().find(|(s, _)| s == stem)?;
    let delta = len as i64 - *was as i64;
    let line = format!("kernel size {stem}: {len} bytes, recorded {was}, difference {delta:+}");
    let verdict = if len > was + GROWTH_LIMIT {
        Err(format!(
            "the {stem} kernel grew by {delta} bytes, more than the {GROWTH_LIMIT} bytes that \
             kernel/size.txt allows. Find what grew it (`llvm-size -A` and `llvm-nm --size-sort` \
             on target/{stem}.elf), and when the growth is intended set the `{stem}` line of \
             kernel/size.txt to {len}"
        ))
    } else {
        Ok(())
    };
    Some((line, verdict))
}

/// Prints the comparison with the record of `kernel/size.txt`, if it has a
/// line for `stem`, and fails when the kernel grew beyond the limit.
pub fn report(stem: &str, len: u64) -> Result<(), String> {
    let path = crate::root().join("kernel/size.txt");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let record = parse_record(&text)?;
    match compare(&record, stem, len) {
        Some((line, verdict)) => {
            println!("{line}");
            verdict
        }
        None => Ok(()),
    }
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

    /// Fails only when `kernel/size.txt` is missing or malformed. The
    /// comparison is printed (run with `--nocapture`); `cargo xtask build`
    /// fails on growth.
    #[test]
    fn kernel_size_record() {
        let text = std::fs::read_to_string(crate::root().join("kernel/size.txt"))
            .expect("kernel/size.txt is the record of the kernel sizes");
        let record = parse_record(&text).unwrap();
        for (stem, _) in &record {
            let image = crate::target_dir().join(format!("{stem}.img"));
            match std::fs::metadata(&image) {
                Ok(meta) => println!("{}", compare(&record, stem, meta.len()).unwrap().0),
                Err(_) => println!("kernel size {stem}: no image built, nothing to compare"),
            }
        }
    }

    #[test]
    fn record_format() {
        assert!(parse_record("# c\nstafeto 100\n").is_ok());
        assert!(parse_record("").is_err());
        assert!(parse_record("stafeto\n").is_err());
        assert!(parse_record("stafeto x\n").is_err());
    }

    #[test]
    fn growth_over_4_kib_fails() {
        let record = vec![("k".to_string(), 1000)];
        let (line, verdict) = compare(&record, "k", 1000 + 4096).unwrap();
        assert!(line.contains("difference +4096"));
        assert!(verdict.is_ok());
        let (_, verdict) = compare(&record, "k", 1000 + 4097).unwrap();
        let message = verdict.unwrap_err();
        assert!(message.contains("kernel/size.txt"));
        assert!(message.contains("to 5097"));
        assert!(compare(&record, "other", 1).is_none());
    }

    #[test]
    fn shrinking_passes() {
        let record = vec![("k".to_string(), 1000)];
        let (line, verdict) = compare(&record, "k", 10).unwrap();
        assert!(line.contains("difference -990"));
        assert!(verdict.is_ok());
    }
}
