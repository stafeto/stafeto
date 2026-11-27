// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Checks on the kernel image produced by objcopy.

use std::path::Path;

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

/// How far the image may differ from the record, up or down, before the build
/// fails: 4 KiB, one page. A smaller image fails as well, so that the record
/// follows the kernel down and the next growth is measured from the real size.
pub const SIZE_MARGIN: u64 = 4096;

/// The largest `.data` of the kernel ELF: the flat image keeps `.data` and
/// leaves `.bss` out, so a table with one non-zero word in its initializer
/// costs its whole size in every boot image (#629).
pub const DATA_LIMIT: u64 = 4096;

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
/// `SIZE_MARGIN` bytes over or under it. A difference of any size says what to
/// write into the record, a pass included. None when the record has no line
/// for `stem`.
pub fn compare(
    record: &[(String, u64)],
    stem: &str,
    len: u64,
) -> Option<(String, Result<(), String>)> {
    let (_, was) = record.iter().find(|(s, _)| s == stem)?;
    let delta = len as i64 - *was as i64;
    let mut line = format!("kernel size {stem}: {len} bytes, recorded {was}, difference {delta:+}");
    if delta != 0 {
        line.push_str(&format!(": update kernel/size.txt to {len}"));
    }
    let verdict = if len > was + SIZE_MARGIN {
        Err(format!(
            "the {stem} kernel grew by {delta} bytes, more than the {SIZE_MARGIN} bytes that \
             kernel/size.txt allows. Find what grew it (`llvm-size -A` and `llvm-nm --size-sort` \
             on target/{stem}.elf), and when the growth is intended set the `{stem}` line of \
             kernel/size.txt to {len}"
        ))
    } else if len + SIZE_MARGIN < *was {
        Err(format!(
            "the {stem} kernel is {} bytes under the record of kernel/size.txt, more than the \
             {SIZE_MARGIN} bytes it allows: the record is stale. Set the `{stem}` line of \
             kernel/size.txt to {len}",
            -delta
        ))
    } else {
        Ok(())
    };
    Some((line, verdict))
}

/// The size of the section `.data` in a 64-bit little endian ELF file, read
/// from its section headers; 0 when it has none, None when the file is not
/// such an ELF file.
pub fn data_size(elf: &[u8]) -> Option<u64> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(elf.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(elf.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(elf.get(o..o + 8)?.try_into().ok()?));
    if elf.get(..6)? != [0x7f, b'E', b'L', b'F', 2, 1] {
        return None;
    }
    let shoff = usize::try_from(u64_at(0x28)?).ok()?;
    let shentsize = usize::from(u16_at(0x3a)?);
    let shnum = usize::from(u16_at(0x3c)?);
    let shstrndx = usize::from(u16_at(0x3e)?);
    let header = |i: usize| shoff.checked_add(i.checked_mul(shentsize)?);
    let strtab = usize::try_from(u64_at(header(shstrndx)? + 24)?).ok()?;
    for i in 0..shnum {
        let h = header(i)?;
        let name = strtab.checked_add(u32_at(h)? as usize)?;
        let end = elf.get(name..)?.iter().position(|&b| b == 0)?;
        if &elf[name..name + end] == b".data" {
            return u64_at(h + 32);
        }
    }
    Some(0)
}

/// The error that fails the build when `.data` of the kernel is `size` bytes,
/// over `DATA_LIMIT`; `nm` is the output of `llvm-nm -S --size-sort` of the
/// ELF file, whose lines `address size type name` of data symbols it names.
pub fn check_data(size: u64, nm: &str) -> Result<(), String> {
    if size <= DATA_LIMIT {
        return Ok(());
    }
    let mut data: Vec<&str> = nm
        .lines()
        .filter(|l| matches!(l.split_whitespace().nth(2), Some("d" | "D")))
        .collect();
    data.reverse();
    data.truncate(5);
    Err(format!(
        "the kernel has {size} bytes of .data, more than the {DATA_LIMIT} that it may have: a \
         static with a non-zero initializer moved a large table out of .bss, and the flat \
         image holds .data. Make the initializer all zero bytes. The largest data symbols \
         (address size type name):\n{}",
        data.join("\n")
    ))
}

/// Compares the kernel image of `stem`, `len` bytes, built from `elf`, with
/// the record of `kernel/size.txt` and checks the `.data` of the ELF file.
/// Fails when the image is more than `SIZE_MARGIN` away from the record or
/// `.data` is over `DATA_LIMIT`; with `enforce` false (a build with a trace
/// feature, whose size the record does not describe) it prints the same
/// messages as warnings. A missing or malformed `kernel/size.txt` fails the
/// build on purpose: without the record nothing would hold the size.
pub fn report(stem: &str, len: u64, elf: &Path, enforce: bool) -> Result<(), String> {
    let path = crate::root().join("kernel/size.txt");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let record = parse_record(&text)?;
    let mut verdicts = Vec::new();
    if let Some((line, verdict)) = compare(&record, stem, len) {
        println!("{line}");
        verdicts.push(verdict);
    }
    let bytes = std::fs::read(elf).map_err(|e| format!("{}: {e}", elf.display()))?;
    let data =
        data_size(&bytes).ok_or_else(|| format!("{}: not a 64-bit ELF file", elf.display()))?;
    verdicts.push(if data > DATA_LIMIT {
        let nm = crate::stdout_of(
            std::process::Command::new(crate::llvm_tool("llvm-nm")?)
                .args(["-S", "--size-sort"])
                .arg(elf),
        )?;
        check_data(data, &nm)
    } else {
        Ok(())
    });
    for verdict in verdicts {
        match verdict {
            Err(e) if enforce => return Err(e),
            Err(e) => println!("warning (trace build, not enforced): {e}"),
            Ok(()) => {}
        }
    }
    Ok(())
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
                Ok(meta) => {
                    println!("{}", compare(&record, stem, meta.len()).unwrap().0);
                    let elf = crate::target_dir().join(format!("{stem}.elf"));
                    if let Some(size) = std::fs::read(elf).ok().as_deref().and_then(data_size) {
                        println!("kernel {stem}: .data {size} bytes, limit {DATA_LIMIT}");
                    }
                }
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
        assert!(line.contains("update kernel/size.txt to 5096"));
        assert!(verdict.is_ok());
        let (_, verdict) = compare(&record, "k", 1000 + 4097).unwrap();
        let message = verdict.unwrap_err();
        assert!(message.contains("kernel/size.txt"));
        assert!(message.contains("to 5097"));
        assert!(compare(&record, "other", 1).is_none());
    }

    #[test]
    fn a_small_shrink_passes_and_says_to_update() {
        let record = vec![("k".to_string(), 10_000)];
        let (line, verdict) = compare(&record, "k", 10_000 - 4096).unwrap();
        assert!(line.contains("difference -4096"));
        assert!(line.contains("update kernel/size.txt to 5904"));
        assert!(verdict.is_ok());
    }

    #[test]
    fn a_shrink_over_4_kib_fails() {
        let record = vec![("k".to_string(), 10_000)];
        let (_, verdict) = compare(&record, "k", 10_000 - 4097).unwrap();
        let message = verdict.unwrap_err();
        assert!(message.contains("stale"));
        assert!(message.contains("to 5903"));
    }

    #[test]
    fn a_size_equal_to_the_record_prints_no_update() {
        let record = vec![("k".to_string(), 1000)];
        let (line, verdict) = compare(&record, "k", 1000).unwrap();
        assert!(!line.contains("update"));
        assert!(verdict.is_ok());
    }

    /// A 64-bit little endian ELF file with the sections `.shstrtab` and the
    /// ones in `sections` (name, size).
    fn elf(sections: &[(&str, u64)]) -> Vec<u8> {
        let mut names = vec![0u8];
        let mut offsets = Vec::new();
        for n in sections.iter().map(|s| s.0).chain([".shstrtab"]) {
            offsets.push(names.len() as u32);
            names.extend_from_slice(n.as_bytes());
            names.push(0);
        }
        let shnum = sections.len() + 2;
        let mut b = vec![0u8; 64];
        b[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        let shoff = 64 + names.len();
        b[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        b[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        b[0x3c..0x3e].copy_from_slice(&(shnum as u16).to_le_bytes());
        b[0x3e..0x40].copy_from_slice(&((shnum - 1) as u16).to_le_bytes());
        b.extend_from_slice(&names);
        b.extend_from_slice(&[0u8; 64]);
        for (i, (_, size)) in sections.iter().enumerate() {
            let mut h = [0u8; 64];
            h[..4].copy_from_slice(&offsets[i].to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            b.extend_from_slice(&h);
        }
        let mut h = [0u8; 64];
        h[..4].copy_from_slice(&offsets[sections.len()].to_le_bytes());
        h[24..32].copy_from_slice(&64u64.to_le_bytes());
        b.extend_from_slice(&h);
        b
    }

    #[test]
    fn the_data_size_is_read_from_the_section_headers() {
        assert_eq!(
            data_size(&elf(&[(".text", 900), (".data", 94272)])),
            Some(94272)
        );
        assert_eq!(data_size(&elf(&[(".text", 900), (".bss", 7)])), Some(0));
        assert_eq!(
            data_size(b"not an elf file at all, but long enough......"),
            None
        );
        assert_eq!(data_size(&[]), None);
    }

    #[test]
    fn data_over_4_kib_fails_and_names_the_largest_symbols() {
        let nm = "ffff0000 0000000000000010 d small\n\
                  ffff1000 0000000000017000 d kernel::arch::cpu::CPUS\n\
                  ffff0100 0000000000002000 b ZEROED\n";
        assert!(check_data(DATA_LIMIT, nm).is_ok());
        let message = check_data(DATA_LIMIT + 1, nm).unwrap_err();
        assert!(message.contains("kernel::arch::cpu::CPUS"));
        assert!(message.contains("non-zero initializer"));
        assert!(!message.contains("ZEROED"));
    }
}
