// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the entropy service decides (proto_entropy, SEED), apart from the
//! calls it makes: its generator with fast key erasure (posix_random), fed
//! by the device's driver at the start and every RESEED_NS, and its answer
//! to a SEED. A client gets 32 bytes of the generator, its key; the
//! service keeps nothing of a client but the count of its seeds that wait
//! for the first bytes of the device. Everything here builds for the host
//! too, where `cargo test -p entropy` exercises it.

#![cfg_attr(not(test), no_std)]

use posix_random::{Generator, KEY};
use proto_entropy::{NONBLOCK, SEED_LEN};

/// The bytes of the device at the start: two keys' worth, mixed into one.
pub const FIRST_BYTES: usize = 2 * KEY;
/// The bytes of each reseed, and its period.
pub const RESEED_BYTES: usize = KEY;
pub const RESEED_NS: u64 = 60_000_000_000;

const _: () = assert!(SEED_LEN == KEY);

/// What a SEED gets.
#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    /// The key, at once.
    Ready([u8; SEED_LEN]),
    /// The device gave nothing yet: the seed waits (WAIT k).
    Wait,
    /// The device gave nothing yet, and the client asked not to wait.
    NotReady,
}

/// The service's generator and whether the device fed it yet.
pub struct Source {
    generator: Generator<1>,
    reseeds: u64,
}

impl Default for Source {
    fn default() -> Self {
        Self::new()
    }
}

impl Source {
    pub const fn new() -> Source {
        Source {
            generator: Generator::new(),
            reseeds: 0,
        }
    }

    pub fn ready(&self) -> bool {
        self.generator.seeded()
    }

    /// The reseeds after the first seed.
    pub fn reseeds(&self) -> u64 {
        self.reseeds
    }

    /// How many bytes the service asks the device for next.
    pub fn wanted(&self) -> usize {
        if self.ready() {
            RESEED_BYTES
        } else {
            FIRST_BYTES
        }
    }

    /// Bytes of the device: the first FIRST_BYTES seed the generator, the
    /// first half as the key and the second mixed in; later RESEED_BYTES
    /// mix into the key. Fewer bytes than wanted change nothing. Gives
    /// whether the generator just became ready.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() < self.wanted() {
            return false;
        }
        let first = !self.ready();
        let mut half = [0; KEY];
        if first {
            half.copy_from_slice(&bytes[..KEY]);
            self.generator.seed(&half);
            half.copy_from_slice(&bytes[KEY..2 * KEY]);
        } else {
            half.copy_from_slice(&bytes[..KEY]);
            self.reseeds += 1;
        }
        self.generator.reseed(&half);
        posix_random::erase(&mut half);
        first
    }

    /// A key of the generator once it is ready.
    pub fn take(&mut self) -> Option<[u8; SEED_LEN]> {
        let mut key = [0; SEED_LEN];
        self.generator.fill(&mut key).then_some(key)
    }

    /// SEED with `flags`, which the protocol checked: the key at once once
    /// the device fed the generator; before, WAIT, or NOT_READY with
    /// NONBLOCK.
    pub fn start(&mut self, flags: u32) -> Start {
        match self.take() {
            Some(key) => Start::Ready(key),
            None if flags & NONBLOCK != 0 => Start::NotReady,
            None => Start::Wait,
        }
    }
}

/// Whether bytes of the device look constant: all alike, or the two
/// halves the same. Such bytes seed nothing.
pub fn looks_constant(bytes: &[u8]) -> bool {
    let Some(&first) = bytes.first() else {
        return true;
    };
    let (a, b) = bytes.split_at(bytes.len() / 2);
    bytes.iter().all(|&x| x == first) || (!a.is_empty() && a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(n: usize, fill: u8) -> Vec<u8> {
        (0..n).map(|i| fill.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn a_seed_before_the_device_waits_or_is_refused_with_nonblock() {
        let mut s = Source::new();
        assert!(!s.ready());
        assert_eq!(s.start(0), Start::Wait);
        assert_eq!(s.start(NONBLOCK), Start::NotReady);
        assert_eq!(s.take(), None);
        assert_eq!(s.wanted(), FIRST_BYTES);
        // Too few bytes seed nothing.
        assert!(!s.feed(&device(KEY, 1)));
        assert!(!s.ready());
        assert!(s.feed(&device(FIRST_BYTES, 1)));
        assert!(s.ready());
        assert_eq!(s.wanted(), RESEED_BYTES);
        assert!(matches!(s.start(NONBLOCK), Start::Ready(_)));
        assert!(matches!(s.start(0), Start::Ready(_)));
    }

    #[test]
    fn keys_differ_for_every_seed_and_every_reseed() {
        let mut s = Source::new();
        assert!(s.feed(&device(FIRST_BYTES, 7)));
        let mut keys = std::collections::HashSet::new();
        for _ in 0..1000 {
            let Start::Ready(key) = s.start(NONBLOCK) else {
                panic!("a ready source refused a seed");
            };
            assert!(keys.insert(key));
        }
        assert!(!s.feed(&device(RESEED_BYTES, 9)));
        assert_eq!(s.reseeds(), 1);
        let Start::Ready(key) = s.start(0) else {
            panic!("refused after a reseed");
        };
        assert!(keys.insert(key));
    }

    #[test]
    fn the_same_device_bytes_give_the_same_keys_and_others_others() {
        let keys = |fill: u8| {
            let mut s = Source::new();
            s.feed(&device(FIRST_BYTES, fill));
            [s.take().unwrap(), s.take().unwrap()]
        };
        assert_eq!(keys(3), keys(3));
        assert_ne!(keys(3), keys(4));
        // Each half of the first bytes counts.
        let mut a = Source::new();
        let mut bytes = device(FIRST_BYTES, 3);
        a.feed(&bytes);
        bytes[FIRST_BYTES - 1] ^= 1;
        let mut b = Source::new();
        b.feed(&bytes);
        assert_ne!(a.take(), b.take());
    }

    #[test]
    fn constant_device_bytes_are_seen() {
        assert!(looks_constant(&[0; 64]));
        assert!(looks_constant(&[0xa5; 32]));
        let mut halves = device(32, 5);
        halves.extend(device(32, 5));
        assert!(looks_constant(&halves));
        assert!(looks_constant(&[]));
        assert!(!looks_constant(&device(64, 5)));
        assert!(!looks_constant(&device(32, 9)));
    }

    #[test]
    fn the_period_is_a_minute() {
        assert_eq!(RESEED_NS, 60 * 1_000_000_000);
        assert_eq!((FIRST_BYTES, RESEED_BYTES), (64, 32));
    }
}
