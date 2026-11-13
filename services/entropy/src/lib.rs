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

pub mod verify;

use posix_random::{Generator, KEY};
use proto_entropy::{NONBLOCK, SEED_LEN};

/// The bytes of the device at the start: two keys' worth, mixed into one.
pub const FIRST_BYTES: usize = 2 * KEY;
/// The bytes of each reseed, and its period.
pub const RESEED_BYTES: usize = KEY;
pub const RESEED_NS: u64 = 60_000_000_000;

const _: () = assert!(SEED_LEN == KEY);

/// The least bytes of a boot seed that count: 128 bits.
pub const MIN_SEED: usize = 16;
/// The most bytes of a boot seed, the room of the page's seed (abi::INIT_SEED_MAX).
pub const SEED_MAX: usize = FIRST_BYTES;

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
        let mut rest = bytes;
        if first {
            half.copy_from_slice(&bytes[..KEY]);
            self.generator.seed(&half);
            rest = &bytes[KEY..];
        } else {
            self.reseeds += 1;
        }
        for chunk in rest.chunks_exact(KEY) {
            half.copy_from_slice(chunk);
            self.generator.reseed(&half);
        }
        posix_random::erase(&mut half);
        first
    }

    /// The seed of the boot (the device tree's `rng-seed`, or the key the
    /// service before this one left): MIN_SEED to SEED_MAX bytes, taken
    /// as FIRST_BYTES, the end of a short one zero. A seed that is too short
    /// or looks constant changes nothing. Gives whether the generator
    /// just became ready.
    pub fn seed_from(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() < MIN_SEED || bytes.len() > SEED_MAX {
            return false;
        }
        #[cfg(not(feature = "break-seed-constant"))]
        if looks_constant(bytes) {
            return false;
        }
        let mut block = [0; FIRST_BYTES];
        block[..bytes.len()].copy_from_slice(bytes);
        let first = self.feed(&block);
        posix_random::erase(&mut block);
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

/// The page of the boot seed (abi::INIT_SEED), which init gives every
/// instance of the service: a u32 length in little endian, then that many
/// bytes. The first instance finds the kernel's seed there; each takes
/// what is there, leaves zeros, and keeps a key for the next instance in
/// its place (`keep`), so that a restart does not lose the seed. Nothing
/// of the boot seed itself ever goes back.
pub struct Page<'a>(&'a mut [u8]);

impl<'a> Page<'a> {
    /// The page over `bytes`, which have room for the length and SEED_MAX
    /// bytes.
    pub fn new(bytes: &'a mut [u8]) -> Option<Page<'a>> {
        (bytes.len() >= 4 + SEED_MAX).then_some(Page(bytes))
    }

    /// Moves the bytes out of the page into `out` and leaves zeros in it;
    /// gives their number, at most SEED_MAX (a length past it counts as
    /// SEED_MAX).
    pub fn take(&mut self, out: &mut [u8; SEED_MAX]) -> usize {
        let len = u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as usize;
        let n = len.min(SEED_MAX);
        out[..n].copy_from_slice(&self.0[4..4 + n]);
        #[cfg(not(feature = "break-page-wipe"))]
        posix_random::erase(&mut self.0[..4 + SEED_MAX]);
        n
    }

    /// Puts `key` in the page for the next instance, in the place of what
    /// was there.
    pub fn keep(&mut self, key: &[u8; KEY]) {
        posix_random::erase(&mut self.0[..4 + SEED_MAX]);
        #[cfg(not(feature = "break-page-keep"))]
        {
            self.0[4..4 + KEY].copy_from_slice(key);
            self.0[..4].copy_from_slice(&(KEY as u32).to_le_bytes());
        }
        #[cfg(feature = "break-page-keep")]
        let _ = key;
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

    fn seeded(fill: u8) -> Source {
        let mut s = Source::new();
        assert!(s.seed_from(&device(32, fill)));
        s
    }

    #[test]
    fn a_boot_seed_seeds_before_the_device() {
        let mut s = Source::new();
        assert!(!s.ready());
        assert!(s.seed_from(&device(32, 1)));
        assert!(s.ready());
        assert!(matches!(s.start(NONBLOCK), Start::Ready(_)));
        // The device's first bytes then mix in as a reseed, whole.
        assert!(!s.feed(&device(FIRST_BYTES, 9)));
        assert_eq!(s.reseeds(), 1);
    }

    #[test]
    fn a_boot_seed_that_is_short_long_or_constant_seeds_nothing() {
        for bytes in [
            device(MIN_SEED - 1, 1),
            device(SEED_MAX + 1, 1),
            vec![0; 32],
            vec![0x5a; 64],
            vec![],
        ] {
            let mut s = Source::new();
            assert!(!s.seed_from(&bytes));
            assert!(!s.ready());
        }
        assert!(Source::new().seed_from(&device(MIN_SEED, 1)));
        assert!(Source::new().seed_from(&device(SEED_MAX, 1)));
    }

    #[test]
    fn keys_follow_the_boot_seed_and_every_byte_of_it_counts() {
        let key = |bytes: &[u8]| {
            let mut s = Source::new();
            assert!(s.seed_from(bytes));
            s.take().unwrap()
        };
        let base = device(32, 4);
        assert_eq!(key(&base), key(&base));
        for i in [0, 15, 16, 31] {
            let mut other = base.clone();
            other[i] ^= 1;
            assert_ne!(key(&base), key(&other), "byte {i}");
        }
        assert_ne!(key(&device(32, 4)), key(&device(48, 4)));
    }

    #[test]
    fn the_page_gives_the_seed_once_and_keeps_a_key_for_the_next_instance() {
        let mut memory = vec![0u8; 4096];
        let seed = device(32, 7);
        memory[..4].copy_from_slice(&32u32.to_le_bytes());
        memory[4..36].copy_from_slice(&seed);
        // The first instance: the kernel's seed, which leaves no trace.
        let mut first = Source::new();
        let mut out = [0; SEED_MAX];
        let n = Page::new(&mut memory).unwrap().take(&mut out);
        assert_eq!(&out[..n], &seed[..]);
        assert!(memory.iter().all(|&b| b == 0), "the page keeps the seed");
        assert!(first.seed_from(&out[..n]));
        let key = first.take().unwrap();
        Page::new(&mut memory).unwrap().keep(&key);
        assert!(!memory.windows(32).any(|w| w == &seed[..]));
        // The next instance seeds from the key and leaves its own.
        let mut second = Source::new();
        let mut page = Page::new(&mut memory).unwrap();
        let n = page.take(&mut out);
        assert_eq!(&out[..n], &key[..]);
        assert!(second.seed_from(&out[..n]));
        assert!(memory.iter().all(|&b| b == 0));
        let (a, b) = (first.take().unwrap(), second.take().unwrap());
        assert_ne!(a, b);
        assert_ne!(b, key);
    }

    #[test]
    fn an_empty_page_gives_nothing_and_a_long_length_is_cut() {
        let mut memory = vec![0u8; 4096];
        let mut out = [0; SEED_MAX];
        assert_eq!(Page::new(&mut memory).unwrap().take(&mut out), 0);
        memory[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        memory[4..4 + SEED_MAX].fill(3);
        assert_eq!(Page::new(&mut memory).unwrap().take(&mut out), SEED_MAX);
        assert!(Page::new(&mut memory[..64]).is_none());
    }

    #[test]
    fn the_period_is_a_minute() {
        assert_eq!(RESEED_NS, 60 * 1_000_000_000);
        assert_eq!((FIRST_BYTES, RESEED_BYTES), (64, 32));
    }
}
