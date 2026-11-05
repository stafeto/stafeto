// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! SHA-256 behind a small wrapper, so that replacing the implementation does
//! not touch the users.

use sha2::{Digest, Sha256};

/// SHA-256 over data that arrives in pieces.
pub struct Stream(Sha256);

impl Stream {
    pub fn new() -> Stream {
        Stream(Sha256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// The SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Stream::new();
    s.update(data);
    s.finish()
}

/// Lower-case hexadecimal of 32 bytes.
pub fn hex<'a>(digest: &[u8; 32], out: &'a mut [u8; 64]) -> &'a str {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in digest.iter().enumerate() {
        out[2 * i] = DIGITS[(b >> 4) as usize];
        out[2 * i + 1] = DIGITS[(b & 15) as usize];
    }
    core::str::from_utf8(out).expect("hex digits are ASCII")
}

/// The 32 bytes of 64 lower-case hexadecimal digits.
pub fn unhex(text: &str) -> Option<[u8; 32]> {
    let b = text.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = digit(b[2 * i])? << 4 | digit(b[2 * i + 1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(d: [u8; 32]) -> alloc::string::String {
        let mut buf = [0u8; 64];
        hex(&d, &mut buf).into()
    }

    #[test]
    fn fips_180_4_vectors() {
        assert_eq!(
            hexs(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hexs(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hexs(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let mut s = Stream::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            s.update(&chunk);
        }
        assert_eq!(
            hexs(s.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn hex_round_trips_and_is_strict() {
        let d = sha256(b"x");
        let mut buf = [0u8; 64];
        assert_eq!(unhex(hex(&d, &mut buf)), Some(d));
        assert_eq!(unhex(&hexs(d).to_uppercase()), None);
        assert_eq!(unhex("ab"), None);
    }
}
