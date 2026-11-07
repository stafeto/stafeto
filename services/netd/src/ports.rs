// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The registry of the ports, one for the loopback and the interface's
//! address: which bind conflicts with which socket, and how an ephemeral
//! port is chosen. The rule of the conflict is that of Linux, which a
//! server restarted on its old port relies on; the choice of the port is
//! RFC 6056, algorithm 3 (a hash of the connection's ends and a secret
//! plus a counter).

use core::hash::Hasher;
#[allow(deprecated)] // SipHasher is in core and has no replacement there.
use core::hash::SipHasher;

/// The protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp = 6,
    Udp = 17,
}

/// What a socket holds of a port: where the registry looks for a conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub proto: Proto,
    pub address: [u8; 4],
    pub port: u16,
    pub listening: bool,
    pub connected: bool,
    pub reuse: bool,
    /// SO_REUSEPORT was set before BIND, and the effective user that held the
    /// socket: two such bindings of one user may share a port, whatever the
    /// addresses (as Linux's `inet_csk_bind_conflict`).
    pub share_uid: Option<u32>,
}

/// Whether two addresses can both receive a packet: 0.0.0.0 meets every
/// address.
pub fn overlap(a: [u8; 4], b: [u8; 4]) -> bool {
    a == [0; 4] || b == [0; 4] || a == b
}

/// Whether `new` may not bind next to `held`, the bindings the registry has:
/// on the same protocol and port with an address that meets the new one's,
/// when the old one listens or is not connected, or is connected (a
/// connection in TIME-WAIT included) and the new socket has no REUSEADDR.
pub fn conflicts(new: &Binding, held: impl IntoIterator<Item = Binding>) -> bool {
    held.into_iter().any(|old| {
        old.proto == new.proto
            && old.port == new.port
            && overlap(old.address, new.address)
            && (old.listening || !old.connected || !new.reuse)
            && !(old.share_uid.is_some() && old.share_uid == new.share_uid)
    })
}

/// The first port of the range of the ephemeral ports (RFC 6335) and how
/// many it holds.
pub const EPHEMERAL_FIRST: u16 = 49152;
pub const EPHEMERAL_COUNT: u32 = 16384;
/// How many candidates one choice tries.
pub const TRIES: u32 = 64;

/// The candidate `i` of the choice for a connection: `offset` is the hash
/// of its ends, `counter` grows by one for each choice.
fn candidate(offset: u32, counter: u32, i: u32) -> u16 {
    let n = offset.wrapping_add(counter).wrapping_add(i) % EPHEMERAL_COUNT;
    EPHEMERAL_FIRST + n as u16
}

/// The hash of RFC 6056, algorithm 3, over the ends of the connection and
/// the secret `key`.
#[allow(deprecated)]
pub fn offset(
    key: &[u8; 16],
    proto: Proto,
    local: [u8; 4],
    remote: [u8; 4],
    remote_port: u16,
) -> u32 {
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(key[8..].try_into().expect("8 bytes"));
    let mut hash = SipHasher::new_with_keys(k0, k1);
    hash.write(&local);
    hash.write(&remote);
    hash.write(&remote_port.to_le_bytes());
    hash.write(&[proto as u8]);
    (hash.finish() % u64::from(EPHEMERAL_COUNT)) as u32
}

/// The port of the choice for a connection: the first free of the TRIES
/// candidates (RFC 6056, algorithm 3), and then the first free port after the
/// last candidate, found a word of the bitmap at a time (at most 256 words,
/// whatever the number of sockets). None only when the whole range is held.
pub fn ephemeral(offset: u32, counter: u32, map: &PortMap) -> Option<u16> {
    for i in 0..TRIES {
        let port = candidate(offset, counter, i);
        if !map.held(port) {
            return Some(port);
        }
    }
    let after = offset.wrapping_add(counter).wrapping_add(TRIES) % EPHEMERAL_COUNT;
    map.first_free_from(after)
        .map(|n| EPHEMERAL_FIRST + n as u16)
}

/// How many sockets hold each port of one protocol. With a count, a socket
/// that lets go of a port subtracts one, where a bit would need a walk over
/// the table (which would put the number of sockets into a step). The ports
/// of the ephemeral range are also a bit each, set while the count is not
/// zero, for the search of a free one.
pub struct PortMap {
    held: [u16; 65536],
    used: [u64; EPHEMERAL_WORDS],
    /// Blocks of the ephemeral range that consumers of the switch hold (a run aligned on
    /// words): a bit each, apart from the counts, so that holding or letting go of a block
    /// of 512 ports costs 8 words.
    reserved: [u64; EPHEMERAL_WORDS],
}

const EPHEMERAL_WORDS: usize = EPHEMERAL_COUNT as usize / 64;

impl PortMap {
    pub const fn new() -> PortMap {
        PortMap {
            held: [0; 65536],
            used: [0; EPHEMERAL_WORDS],
            reserved: [0; EPHEMERAL_WORDS],
        }
    }

    pub fn held(&self, port: u16) -> bool {
        self.held[usize::from(port)] > 0 || self.is_reserved(port)
    }

    pub fn is_reserved(&self, port: u16) -> bool {
        if port >= EPHEMERAL_FIRST && u32::from(port - EPHEMERAL_FIRST) < EPHEMERAL_COUNT {
            let n = usize::from(port - EPHEMERAL_FIRST);
            return self.reserved[n / 64] >> (n % 64) & 1 != 0;
        }
        false
    }

    /// Whether none of the `count` ports from `first` is held: a word of the bitmap of the
    /// ephemeral range for each 64 of them when the run is aligned in it (the blocks of the
    /// switch are), else port by port.
    pub fn free_run(&self, first: u16, count: u16) -> bool {
        if Self::aligned(first, count) {
            let word = usize::from(first - EPHEMERAL_FIRST) / 64;
            let words = word..word + usize::from(count) / 64;
            return self.used[words.clone()]
                .iter()
                .zip(&self.reserved[words])
                .all(|(u, r)| *u | *r == 0);
        }
        (0..count).all(|i| !self.held(first + i))
    }

    /// Whether a run is aligned in the ephemeral range on words of the bitmap.
    fn aligned(first: u16, count: u16) -> bool {
        first >= EPHEMERAL_FIRST
            && u32::from(first - EPHEMERAL_FIRST) + u32::from(count) <= EPHEMERAL_COUNT
            && (first - EPHEMERAL_FIRST).is_multiple_of(64)
            && count.is_multiple_of(64)
    }

    /// `hold` for each of `count` ports from `first`. An aligned run of the ephemeral range
    /// (the blocks of the switch hold 512 ports at once) is a few bits of `reserved`: the run
    /// must have been free (`free_run`).
    pub fn hold_run(&mut self, first: u16, count: u16) {
        if count == 0 {
            return;
        }
        if Self::aligned(first, count) {
            let word = usize::from(first - EPHEMERAL_FIRST) / 64;
            self.reserved[word..word + usize::from(count) / 64].fill(!0);
            return;
        }
        for p in first..=first + (count - 1) {
            self.hold(p);
        }
    }

    /// `release` for each of `count` ports from `first` (a run `hold_run` took).
    pub fn release_run(&mut self, first: u16, count: u16) {
        if count == 0 {
            return;
        }
        if Self::aligned(first, count) {
            let word = usize::from(first - EPHEMERAL_FIRST) / 64;
            self.reserved[word..word + usize::from(count) / 64].fill(0);
            return;
        }
        for p in first..=first + (count - 1) {
            self.release(p);
        }
    }

    fn mark(&mut self, port: u16, on: bool) {
        if port >= EPHEMERAL_FIRST && u32::from(port - EPHEMERAL_FIRST) < EPHEMERAL_COUNT {
            let n = usize::from(port - EPHEMERAL_FIRST);
            if on {
                self.used[n / 64] |= 1 << (n % 64);
            } else {
                self.used[n / 64] &= !(1 << (n % 64));
            }
        }
    }

    pub fn hold(&mut self, port: u16) {
        let n = &mut self.held[usize::from(port)];
        let first = *n == 0;
        *n = n.saturating_add(1);
        if first {
            self.mark(port, true);
        }
    }

    pub fn release(&mut self, port: u16) {
        let n = &mut self.held[usize::from(port)];
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.mark(port, false);
        }
    }

    /// The index in the ephemeral range of the first port that is free at or
    /// after `from`, going round the end of the range.
    pub fn first_free_from(&self, from: u32) -> Option<u32> {
        let start = (from % EPHEMERAL_COUNT) as usize;
        for step in 0..=EPHEMERAL_WORDS {
            let word = (start / 64 + step) % EPHEMERAL_WORDS;
            let mut free = !(self.used[word] | self.reserved[word]);
            if step == 0 {
                free &= !0u64 << (start % 64);
            } else if step == EPHEMERAL_WORDS {
                free &= !(!0u64 << (start % 64));
            }
            if free != 0 {
                return Some((word * 64) as u32 + free.trailing_zeros());
            }
        }
        None
    }
}

impl Default for PortMap {
    fn default() -> PortMap {
        PortMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(address: [u8; 4], port: u16) -> Binding {
        Binding {
            proto: Proto::Tcp,
            address,
            port,
            listening: false,
            connected: false,
            reuse: false,
            share_uid: None,
        }
    }

    #[test]
    fn a_second_bind_of_a_port_conflicts() {
        let held = [binding([10, 0, 2, 15], 80)];
        assert!(conflicts(&binding([10, 0, 2, 15], 80), held));
        assert!(!conflicts(&binding([10, 0, 2, 15], 81), held));
        let mut udp = binding([10, 0, 2, 15], 80);
        udp.proto = Proto::Udp;
        assert!(!conflicts(&udp, held), "another protocol");
    }

    #[test]
    fn the_wildcard_meets_every_address_and_the_loopback_meets_it() {
        let wild = [binding([0; 4], 80)];
        assert!(conflicts(&binding([127, 0, 0, 1], 80), wild));
        let local = [binding([127, 0, 0, 1], 80)];
        assert!(conflicts(&binding([0; 4], 80), local));
        assert!(!conflicts(&binding([10, 0, 2, 15], 80), local));
        assert!(conflicts(&binding([127, 0, 0, 1], 80), local));
    }

    #[test]
    fn a_connection_conflicts_unless_the_new_socket_reuses_the_address() {
        let mut waiting = binding([10, 0, 2, 15], 80);
        waiting.connected = true;
        let new = binding([10, 0, 2, 15], 80);
        assert!(conflicts(&new, [waiting]), "a restart without REUSEADDR");
        let mut again = new;
        again.reuse = true;
        assert!(!conflicts(&again, [waiting]), "a restart with it");
    }

    #[test]
    fn two_bindings_that_asked_for_a_shared_port_do_not_conflict() {
        let mut old = binding([0; 4], 80);
        old.listening = true;
        old.share_uid = Some(7);
        let mut new = binding([0; 4], 80);
        assert!(conflicts(&new, [old]));
        new.share_uid = Some(7);
        assert!(!conflicts(&new, [old]));
        // Another user, or an address that only overlaps: the same rule.
        new.share_uid = Some(8);
        assert!(conflicts(&new, [old]));
        new.share_uid = Some(7);
        new.address = [10, 0, 2, 15];
        assert!(!conflicts(&new, [old]));
        new.share_uid = Some(8);
        assert!(
            conflicts(&new, [old]),
            "another user at an overlapping address"
        );
        // Another port or protocol is none of its business.
        new.port = 81;
        assert!(!conflicts(&new, [old]));
    }

    #[test]
    fn a_listener_and_an_unconnected_socket_conflict_even_with_reuse() {
        let mut listening = binding([0; 4], 80);
        listening.listening = true;
        let mut reusing = binding([0; 4], 80);
        reusing.reuse = true;
        assert!(conflicts(&reusing, [listening]));
        assert!(conflicts(&reusing, [binding([0; 4], 80)]));
    }

    #[test]
    fn the_offset_follows_the_ends_and_the_key() {
        let key = [7; 16];
        let a = offset(&key, Proto::Tcp, [10, 0, 2, 15], [10, 0, 2, 2], 80);
        assert_eq!(
            a,
            offset(&key, Proto::Tcp, [10, 0, 2, 15], [10, 0, 2, 2], 80)
        );
        assert_ne!(
            a,
            offset(&key, Proto::Tcp, [10, 0, 2, 15], [10, 0, 2, 2], 81)
        );
        assert_ne!(
            a,
            offset(&[8; 16], Proto::Tcp, [10, 0, 2, 15], [10, 0, 2, 2], 80)
        );
        assert_ne!(
            a,
            offset(&key, Proto::Udp, [10, 0, 2, 15], [10, 0, 2, 2], 80)
        );
        assert!(a < EPHEMERAL_COUNT);
    }

    fn held_map(ports: impl IntoIterator<Item = u16>) -> PortMap {
        let mut map = PortMap::new();
        for p in ports {
            map.hold(p);
        }
        map
    }

    #[test]
    fn ports_come_from_the_ephemeral_range_and_skip_the_held_ones() {
        let map = PortMap::new();
        let first = ephemeral(100, 0, &map).unwrap();
        assert_eq!(first, EPHEMERAL_FIRST + 100);
        // The counter moves the choice by one.
        assert_eq!(ephemeral(100, 1, &map), Some(first + 1));
        // A held candidate is skipped.
        assert_eq!(ephemeral(100, 0, &held_map([first])), Some(first + 1));
        // The range wraps.
        let last = ephemeral(EPHEMERAL_COUNT - 1, 0, &map).unwrap();
        assert_eq!(last, 65535);
        assert_eq!(ephemeral(EPHEMERAL_COUNT - 1, 1, &map), Some(49152));
    }

    #[test]
    fn a_block_of_held_ports_longer_than_the_candidates_is_passed() {
        // 500 ports in a row held, the choice starts inside the block.
        let block = held_map(EPHEMERAL_FIRST + 10..EPHEMERAL_FIRST + 510);
        assert_eq!(
            ephemeral(20, 0, &block),
            Some(EPHEMERAL_FIRST + 510),
            "the first free port after the candidates"
        );
        // A block that ends the range goes round to its start.
        let end = held_map(EPHEMERAL_FIRST + 16000..=65535);
        assert_eq!(ephemeral(16100, 0, &end), Some(EPHEMERAL_FIRST));
        // Released ports are free again.
        let mut map = held_map(EPHEMERAL_FIRST..EPHEMERAL_FIRST + 200);
        map.release(EPHEMERAL_FIRST + 150);
        assert_eq!(ephemeral(0, 0, &map), Some(EPHEMERAL_FIRST + 150));
        // Only the whole range held refuses.
        let all = held_map(EPHEMERAL_FIRST..=65535);
        assert_eq!(ephemeral(7, 0, &all), None);
    }

    #[test]
    fn the_map_counts_the_holders_of_a_port() {
        let mut map = PortMap::new();
        for port in [0u16, 1, 63, 64, 49152, 65535] {
            assert!(!map.held(port));
            map.hold(port);
            assert!(map.held(port));
        }
        map.release(64);
        assert!(!map.held(64));
        assert!(map.held(63));
        assert!(map.held(65535));
        // Two holders: the port is free after both let go.
        map.hold(80);
        map.hold(80);
        map.release(80);
        assert!(map.held(80));
        map.release(80);
        assert!(!map.held(80));
        map.release(80);
        assert!(!map.held(80), "a count does not go below zero");
    }
}
