// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The ChaCha20 block function of RFC 8439, section 2.3, and a generator
//! of random bytes on it with fast key erasure (D. J. Bernstein, "Fast-key-
//! erasure random-number generators", 2017), as Linux 5.17 and later and
//! OpenBSD's arc4random have it: the generator fills its buffer with N
//! blocks under its key and at once takes the first 32 bytes of them as
//! its next key; every byte it gives out is erased from the buffer as it
//! goes. Its state then never tells what it gave before. The entropy
//! service (services/entropy) runs one with a block of buffer and gives a
//! process 32 bytes, a key; the POSIX layer runs one per process on that
//! key. No dependency, no allocation, no `unsafe` but the erasing writes.

#![cfg_attr(not(test), no_std)]

/// The bytes of a key and of a block.
pub const KEY: usize = 32;
pub const BLOCK: usize = 64;

/// "expand 32-byte k" (RFC 8439, 2.3).
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The quarter round on the words a, b, c, d of the state (RFC 8439, 2.2).
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Writes zeros over `bytes` with volatile stores, which the compiler
/// keeps although nothing reads the bytes after them.
pub fn erase(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

fn erase_words(words: &mut [u32]) {
    for w in words.iter_mut() {
        // SAFETY: as in `erase`.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
}

/// The ChaCha20 block of `key`, `counter` and `nonce` into `out` (RFC
/// 8439, 2.3): the state of the constants, the key, the counter and the
/// nonce, each a little-endian word, through 20 rounds, added to itself
/// and written out little-endian.
pub fn block(key: &[u8; KEY], counter: u32, nonce: &[u8; 12], out: &mut [u8; BLOCK]) {
    let mut start = [0u32; 16];
    start[..4].copy_from_slice(&CONSTANTS);
    for (i, word) in key.as_chunks::<4>().0.iter().enumerate() {
        start[4 + i] = u32::from_le_bytes(*word);
    }
    start[12] = counter;
    for (i, word) in nonce.as_chunks::<4>().0.iter().enumerate() {
        start[13 + i] = u32::from_le_bytes(*word);
    }
    let mut s = start;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    for (i, bytes) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *bytes = s[i].wrapping_add(start[i]).to_le_bytes();
    }
    erase_words(&mut s);
    erase_words(&mut start);
}

/// A generator with fast key erasure and a buffer of N blocks: up to
/// N * 64 - 32 bytes come out of one turn of the key. Unseeded until
/// `seed`; `fill` then gives any number of bytes.
pub struct Generator<const N: usize> {
    key: [u8; KEY],
    buffer: [[u8; BLOCK]; N],
    /// The next byte of the buffer to give; N * 64 when it is used up.
    at: usize,
    seeded: bool,
}

impl<const N: usize> Default for Generator<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Generator<N> {
    const END: usize = N * BLOCK;

    /// An unseeded generator.
    pub const fn new() -> Self {
        assert!(N >= 1, "a block at least");
        Generator {
            key: [0; KEY],
            buffer: [[0; BLOCK]; N],
            at: N * BLOCK,
            seeded: false,
        }
    }

    pub fn seeded(&self) -> bool {
        self.seeded
    }

    /// Takes `seed` as the key; what the buffer held goes.
    pub fn seed(&mut self, seed: &[u8; KEY]) {
        self.key = *seed;
        self.drop_buffer();
        self.seeded = true;
    }

    /// Mixes `extra`, new bytes of a source, into the key: the new key is
    /// the first 32 bytes of the block of the old key XOR `extra`, so it
    /// is no weaker than either; what the buffer held goes.
    pub fn reseed(&mut self, extra: &[u8; KEY]) {
        let mut b = [0; BLOCK];
        block(&self.key, 0, &[0; 12], &mut b);
        for (k, (x, e)) in self.key.iter_mut().zip(b.iter().zip(extra)) {
            *k = x ^ e;
        }
        erase(&mut b);
        self.drop_buffer();
        self.seeded = true;
    }

    /// Forgets the key and the buffer: unseeded again (a child after
    /// fork, which must not give its parent's bytes).
    pub fn forget(&mut self) {
        erase(&mut self.key);
        self.drop_buffer();
        self.seeded = false;
    }

    fn drop_buffer(&mut self) {
        for b in self.buffer.iter_mut() {
            erase(b);
        }
        self.at = Self::END;
    }

    /// A new turn of the key: N blocks of the key, of counters 0 to N - 1
    /// and nonce 0; their first 32 bytes are the next key, erased from the
    /// buffer at once.
    fn turn(&mut self) {
        for (i, b) in self.buffer.iter_mut().enumerate() {
            block(&self.key, i as u32, &[0; 12], b);
        }
        self.key.copy_from_slice(&self.buffer[0][..KEY]);
        erase(&mut self.buffer[0][..KEY]);
        self.at = KEY;
    }

    /// Fills `out` with bytes of the generator, each erased from the
    /// buffer as it goes; false, with `out` untouched, while unseeded.
    pub fn fill(&mut self, out: &mut [u8]) -> bool {
        if !self.seeded {
            return false;
        }
        let mut done = 0;
        while done < out.len() {
            if self.at == Self::END {
                self.turn();
            }
            let n = (out.len() - done).min(Self::END - self.at);
            let (block_at, from) = (self.at / BLOCK, self.at % BLOCK);
            let n = n.min(BLOCK - from);
            let source = &mut self.buffer[block_at][from..from + n];
            out[done..done + n].copy_from_slice(source);
            erase(source);
            self.at += n;
            done += n;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn block_of(key: &str, counter: u32, nonce: &str) -> Vec<u8> {
        let mut out = [0; BLOCK];
        block(
            &hex(key).try_into().unwrap(),
            counter,
            &hex(nonce).try_into().unwrap(),
            &mut out,
        );
        out.to_vec()
    }

    /// RFC 8439, 2.3.2, "Test Vector for the ChaCha20 Block Function".
    #[test]
    fn the_block_of_section_2_3_2() {
        let key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:\
                   10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        let nonce = "00:00:00:09:00:00:00:4a:00:00:00:00";
        let want = hex("10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
             c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
             d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
             b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e");
        assert_eq!(block_of(key, 1, nonce), want);
    }

    /// RFC 8439, appendix A.1, "ChaCha20 Block Functions", test vectors
    /// 1 to 5.
    #[test]
    fn the_blocks_of_appendix_a_1() {
        let zero = "00".repeat(32);
        let one = format!("{}01", "00".repeat(31));
        let ff = format!("00ff{}", "00".repeat(30));
        let cases = [
            (
                &zero,
                0,
                "000000000000000000000000",
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
                 da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            ),
            (
                &zero,
                1,
                "000000000000000000000000",
                "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
                 29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
            ),
            (
                &one,
                1,
                "000000000000000000000000",
                "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
                 8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0",
            ),
            (
                &ff,
                2,
                "000000000000000000000000",
                "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca\
                 13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096",
            ),
            (
                &zero,
                0,
                "000000000000000000000002",
                "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7\
                 8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d",
            ),
        ];
        for (i, (key, counter, nonce, want)) in cases.into_iter().enumerate() {
            assert_eq!(block_of(key, counter, nonce), hex(want), "vector {}", i + 1);
        }
    }

    #[test]
    fn erase_writes_zeros() {
        let mut bytes = [0xee; 40];
        erase(&mut bytes[3..]);
        assert_eq!(bytes[..3], [0xee; 3]);
        assert_eq!(bytes[3..], [0; 37]);
    }

    #[test]
    fn an_unseeded_generator_gives_nothing() {
        let mut g = Generator::<1>::new();
        let mut out = [7; 8];
        assert!(!g.fill(&mut out));
        assert_eq!(out, [7; 8]);
    }

    /// Fast key erasure: a turn gives the bytes 32..64 of the block of the
    /// key, takes its first 32 as the next key, and erases each byte it
    /// gives; the next turn runs on the new key.
    #[test]
    fn the_key_turns_and_given_bytes_are_erased() {
        let seed = [3; KEY];
        let mut g = Generator::<1>::new();
        g.seed(&seed);
        let mut first = [0; BLOCK];
        block(&seed, 0, &[0; 12], &mut first);
        let mut out = [0; 32];
        assert!(g.fill(&mut out));
        assert_eq!(out[..], first[KEY..]);
        assert_eq!(g.key[..], first[..KEY]);
        assert_ne!(g.key, seed);
        assert!(g.buffer.iter().all(|b| b.iter().all(|&x| x == 0)));
        let mut second = [0; BLOCK];
        block(&first[..KEY].try_into().unwrap(), 0, &[0; 12], &mut second);
        assert!(g.fill(&mut out));
        assert_eq!(out[..], second[KEY..]);
        // A part of a turn: the rest stays until given, then goes.
        let mut g = Generator::<2>::new();
        g.seed(&seed);
        let mut part = [0; 40];
        assert!(g.fill(&mut part));
        assert_eq!(part[..32], first[KEY..]);
        assert!(g.buffer[0].iter().all(|&x| x == 0));
        assert!(g.buffer[1][..8].iter().all(|&x| x == 0));
        assert!(g.buffer[1][8..].iter().any(|&x| x != 0));
    }

    #[test]
    fn a_long_fill_crosses_turns_and_repeats_nothing() {
        let mut g = Generator::<8>::new();
        g.seed(&[9; KEY]);
        let mut a = vec![0; 3008];
        assert!(g.fill(&mut a));
        let mut b = vec![0; 3008];
        assert!(g.fill(&mut b));
        assert_ne!(a, b);
        let blocks: std::collections::HashSet<_> = a.chunks(16).chain(b.chunks(16)).collect();
        assert_eq!(blocks.len(), 2 * 3008 / 16);
    }

    #[test]
    fn a_reseed_mixes_into_the_key_and_drops_the_buffer() {
        let mut g = Generator::<2>::new();
        g.seed(&[1; KEY]);
        let mut out = [0; 8];
        assert!(g.fill(&mut out));
        let before = g.key;
        let mut b = [0; BLOCK];
        block(&before, 0, &[0; 12], &mut b);
        g.reseed(&[0x5a; KEY]);
        let want: Vec<u8> = b[..KEY].iter().map(|x| x ^ 0x5a).collect();
        assert_eq!(g.key[..], want[..]);
        assert!(g.buffer.iter().all(|b| b.iter().all(|&x| x == 0)));
        assert_eq!(g.at, 2 * BLOCK);
        // A generator that forgot gives nothing until seeded again.
        g.forget();
        assert!(!g.fill(&mut out));
        assert_eq!(g.key, [0; KEY]);
    }
}
