// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The names the probe builds without an allocator: a number in decimal and the paths of the
//! directories and files of the fill volume. Plain code, so that the host tests of xtask can include
//! this file and check every name the probe asks for (`xtask/src/data_probe.rs`).

/// `j` in decimal into `out` (up to four digits): the count of digits.
pub fn decimal(j: u32, out: &mut [u8; 4]) -> usize {
    let mut digits = 1;
    let mut probe = j;
    while probe >= 10 && digits < 4 {
        probe /= 10;
        digits += 1;
    }
    let mut v = j;
    for i in (0..digits).rev() {
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    digits
}

/// `prefix` and the number `n` in decimal into `out`: the count of bytes.
pub fn numbered(prefix: &[u8], n: u32, out: &mut [u8; 16]) -> usize {
    out[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 4];
    let d = decimal(n, &mut digits);
    out[prefix.len()..prefix.len() + d].copy_from_slice(&digits[..d]);
    prefix.len() + d
}

/// The path `/rm/e<n>` of an empty directory of the fill volume.
pub fn rm_name(n: u32, out: &mut [u8; 16]) -> usize {
    numbered(b"/rm/e", n, out)
}

/// The path `/big/b<n>` of a large file of the fill volume.
pub fn big_name(n: u32, out: &mut [u8; 16]) -> usize {
    numbered(b"/big/b", n, out)
}
