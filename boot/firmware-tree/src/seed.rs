// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The boot seed of `/chosen/rng-seed` (stafeto-design
//! tasks/2026-11-13-entropy-trust.md): what the loader found in the
//! firmware's sources of random bytes, mixed into 64 bytes. The sources are
//! read by the loader (it holds the protocols and the registers); this
//! crate mixes them on slices, so the rule is tested on the host.

use posix_random::{Generator, KEY};

/// The bytes of the seed in the tree: two keys' worth, as the entropy
/// service takes its first bytes (`entropy::FIRST_BYTES`).
pub const SEED_BYTES: usize = 2 * KEY;

/// The least bytes a source must give to count: 128 bits.
pub const MIN_SOURCE: usize = 16;

/// Whether a source's bytes look constant: all alike, or the two halves the
/// same. A source that gives such bytes (an unprogrammed device) adds
/// nothing and is left out.
fn constant(bytes: &[u8]) -> bool {
    let Some(&first) = bytes.first() else {
        return true;
    };
    let (a, b) = bytes.split_at(bytes.len() / 2);
    bytes.iter().all(|&x| x == first) || (!a.is_empty() && a == b)
}

/// The sources that count: at least MIN_SOURCE bytes and not constant.
pub fn counts(bytes: &[u8]) -> bool {
    bytes.len() >= MIN_SOURCE && !constant(bytes)
}

/// The seed of `sources`, each a run of bytes from one source: every source
/// that counts mixes into one generator (the key becomes the first 32 bytes
/// of the old key's block XOR the new bytes, so the result is no weaker
/// than any one of them), and the seed is 64 bytes of it. None when no
/// source counts.
pub fn mix(sources: &[&[u8]]) -> Option<[u8; SEED_BYTES]> {
    let mut generator = Generator::<1>::new();
    let mut any = false;
    for source in sources.iter().copied().filter(|s| counts(s)) {
        for chunk in source.chunks(KEY) {
            // A last piece of fewer than 32 bytes is padded with zeros.
            let mut block = [0u8; KEY];
            block[..chunk.len()].copy_from_slice(chunk);
            if any {
                generator.reseed(&block);
            } else {
                generator.seed(&block);
                any = true;
            }
        }
    }
    any.then(|| {
        let mut out = [0u8; SEED_BYTES];
        let filled = generator.fill(&mut out);
        debug_assert!(filled);
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(n: usize, from: u8) -> Vec<u8> {
        (0..n)
            .map(|i| from.wrapping_add((i as u8).wrapping_mul(7)))
            .collect()
    }

    #[test]
    fn no_source_gives_no_seed() {
        assert_eq!(mix(&[]), None);
        assert_eq!(mix(&[&[]]), None);
        // Constant, short: left out.
        assert_eq!(mix(&[&[0; 64], &[0xa5; 32], &bytes(15, 1)]), None);
    }

    #[test]
    fn one_source_gives_64_bytes_that_follow_every_byte_of_it() {
        let a = bytes(64, 1);
        let seed = mix(&[&a]).unwrap();
        assert_eq!(seed.len(), SEED_BYTES);
        assert_ne!(&seed[..KEY], &seed[KEY..]);
        assert_eq!(mix(&[&a]), Some(seed));
        for i in [0, 31, 32, 63] {
            let mut b = a.clone();
            b[i] ^= 1;
            assert_ne!(mix(&[&b]), Some(seed), "byte {i}");
        }
    }

    #[test]
    fn every_source_counts_and_a_constant_one_does_not() {
        let (a, b, c) = (bytes(64, 1), bytes(24, 90), bytes(32, 200));
        let all = mix(&[&a, &b, &c]).unwrap();
        for without in [mix(&[&a, &b]), mix(&[&a, &c]), mix(&[&b, &c])] {
            assert_ne!(without, Some(all));
        }
        // The second and third differ in what they give: each source decides.
        let mut b2 = b.clone();
        b2[23] ^= 1;
        assert_ne!(mix(&[&a, &b2, &c]), Some(all));
        // A source that is constant, or too short, changes nothing.
        assert_eq!(mix(&[&a, &[0; 32], &bytes(8, 3)]), mix(&[&a]));
    }

    #[test]
    fn one_good_source_among_known_ones_keeps_the_seed_secret() {
        // The first source known to an attacker, the second not: the seeds
        // for two different second sources differ, so the known one does not
        // fix the seed.
        let known = bytes(64, 5);
        let s1 = mix(&[&known, &bytes(32, 11)]);
        let s2 = mix(&[&known, &bytes(32, 12)]);
        assert_ne!(s1, s2);
    }
}
