// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Base64 of RFC 4648 section 4: the standard alphabet with `=` padding and
//! a strict reader (no stray characters, no spare bits, no missing padding).

use crate::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The length of the text for `n` bytes.
pub const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Writes the text of `input` into `out`, which holds `encoded_len` bytes,
/// and returns it.
pub fn encode<'a>(input: &[u8], out: &'a mut [u8]) -> &'a str {
    let n = encoded_len(input.len());
    for (i, chunk) in input.chunks(3).enumerate() {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for j in 0..4 {
            out[4 * i + j] = ALPHABET[(v >> (18 - 6 * j) & 63) as usize];
        }
        if chunk.len() < 3 {
            out[4 * i + 3] = b'=';
        }
        if chunk.len() < 2 {
            out[4 * i + 2] = b'=';
        }
    }
    core::str::from_utf8(&out[..n]).expect("the alphabet is ASCII")
}

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

/// Decodes `text` into `out` and returns the number of bytes; `out` must be
/// large enough for `text.len() / 4 * 3` bytes.
pub fn decode(text: &str, out: &mut [u8]) -> Result<usize, Error> {
    let t = text.as_bytes();
    if !t.len().is_multiple_of(4) || out.len() < t.len() / 4 * 3 {
        return Err(Error::BadBase64);
    }
    let mut n = 0;
    for (i, q) in t.chunks(4).enumerate() {
        let last = (i + 1) * 4 == t.len();
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err(Error::BadBase64);
        }
        let mut v = 0u32;
        for (j, &c) in q.iter().enumerate() {
            let d = if j >= 4 - pad {
                0
            } else {
                value(c).ok_or(Error::BadBase64)?
            };
            v = v << 6 | d;
        }
        let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
        let take = 3 - pad;
        // The bits that the padding drops must be zero.
        if bytes[take..].iter().any(|&b| b != 0) {
            return Err(Error::BadBase64);
        }
        out[n..n + take].copy_from_slice(&bytes[..take]);
        n += take;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc_4648_section_10() {
        for (plain, text) in VECTORS {
            let mut buf = [0u8; 16];
            assert_eq!(encode(plain.as_bytes(), &mut buf), text);
            let mut out = [0u8; 12];
            let n = decode(text, &mut out).unwrap();
            assert_eq!(&out[..n], plain.as_bytes());
        }
    }

    #[test]
    fn the_reader_is_strict() {
        let mut out = [0u8; 12];
        for bad in [
            "Zg=", "Zg", "Zh==", "Zm9=", "Zg=A", "Z===", "=g==", "Zm9v\n", "Zm 9", "Zm9-",
            "Zg==Zg==",
        ] {
            assert_eq!(decode(bad, &mut out), Err(Error::BadBase64), "{bad}");
        }
    }
}
