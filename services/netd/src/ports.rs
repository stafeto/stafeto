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
use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};

/// The protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp = 6,
    Udp = 17,
}

/// The ports the stack instances of the service hold, for all of them: one byte for each port
/// of each protocol, 0 for a port no instance holds and the instance's number plus one for the
/// instance that does. An instance takes a port here the first time one of its sockets holds
/// it and lets it go with the last (`PortMap`), so that the instances share one port space
/// without a lock: a bind or a choice of an ephemeral port that finds the port taken by
/// another instance is refused or tries the next. The switch reads the same bytes to steer a
/// frame to the instance that holds its port (`switchlogic::tables::Tables::port`), and an
/// instance reads them to tell a frame for another instance from one for itself.
pub struct Claims {
    ports: [AtomicU8; 2 * 65536],
    /// For each word of 64 ports of the ephemeral range, of each protocol: how many of its ports
    /// have a claim of their own, and the owner (plus one) of a run that holds the whole word
    /// (the blocks of the consumers, which take 8 words at a time instead of 512 claims, so
    /// that the step of an ATTACH stays short).
    counts: [AtomicU16; 2 * EPHEMERAL_WORDS],
    runs: [AtomicU8; 2 * EPHEMERAL_WORDS],
}

impl Claims {
    pub const fn new() -> Claims {
        Claims {
            ports: [const { AtomicU8::new(0) }; 2 * 65536],
            counts: [const { AtomicU16::new(0) }; 2 * EPHEMERAL_WORDS],
            runs: [const { AtomicU8::new(0) }; 2 * EPHEMERAL_WORDS],
        }
    }

    fn at(proto: Proto, port: u16) -> usize {
        usize::from(proto == Proto::Udp) * 65536 + usize::from(port)
    }

    /// The word of the ephemeral range `port` is in (with the protocol's half), if it is in it.
    fn word(proto: Proto, port: u16) -> Option<usize> {
        (port >= EPHEMERAL_FIRST && u32::from(port - EPHEMERAL_FIRST) < EPHEMERAL_COUNT).then(
            || {
                usize::from(proto == Proto::Udp) * EPHEMERAL_WORDS
                    + usize::from(port - EPHEMERAL_FIRST) / 64
            },
        )
    }

    /// Takes `port` for instance `who`; true when it is the instance's already.
    pub fn claim(&self, proto: Proto, port: u16, who: u8) -> bool {
        let me = who + 1;
        match self.ports[Self::at(proto, port)].compare_exchange(
            0,
            me,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                if let Some(w) = Self::word(proto, port) {
                    self.counts[w].fetch_add(1, Ordering::SeqCst);
                    let run = self.runs[w].load(Ordering::SeqCst);
                    if run != 0 && run != me {
                        // A run holds the word: the port is not free.
                        self.counts[w].fetch_sub(1, Ordering::SeqCst);
                        self.ports[Self::at(proto, port)].store(0, Ordering::SeqCst);
                        return false;
                    }
                }
                true
            }
            Err(held) => held == me,
        }
    }

    /// Lets go of `port`, if it is `who`'s.
    pub fn release(&self, proto: Proto, port: u16, who: u8) {
        if self.ports[Self::at(proto, port)]
            .compare_exchange(who + 1, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
            && let Some(w) = Self::word(proto, port)
        {
            self.counts[w].fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// The instance that holds `port`.
    pub fn owner(&self, proto: Proto, port: u16) -> Option<u8> {
        let own = self.ports[Self::at(proto, port)]
            .load(Ordering::Acquire)
            .checked_sub(1);
        own.or_else(|| {
            Self::word(proto, port)
                .and_then(|w| self.runs[w].load(Ordering::Acquire).checked_sub(1))
        })
    }

    /// The owner of the run that holds the word of `port`.
    pub fn run_owner(&self, proto: Proto, port: u16) -> Option<u8> {
        Self::word(proto, port).and_then(|w| self.runs[w].load(Ordering::Acquire).checked_sub(1))
    }

    /// Whether no port of the run of words (`first` and `count` aligned on 64 in the ephemeral
    /// range) has a claim, its own or a run's.
    pub fn run_free(&self, proto: Proto, first: u16, count: u16) -> bool {
        let Some(w) = Self::word(proto, first) else {
            return false;
        };
        (w..w + usize::from(count) / 64).all(|w| {
            self.runs[w].load(Ordering::Acquire) == 0 && self.counts[w].load(Ordering::Acquire) == 0
        })
    }

    /// Takes the run of words for `who`; false, and nothing taken, when one has a claim.
    pub fn claim_run(&self, proto: Proto, first: u16, count: u16, who: u8) -> bool {
        let Some(from) = Self::word(proto, first) else {
            return false;
        };
        let words = from..from + usize::from(count) / 64;
        for w in words.clone() {
            let taken = self.runs[w]
                .compare_exchange(0, who + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();
            // A port claimed in the word before the run took it stands in the count.
            if !taken || self.counts[w].load(Ordering::SeqCst) != 0 {
                for u in from..=w {
                    if u < w || taken {
                        let _ = self.runs[u].compare_exchange(
                            who + 1,
                            0,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        );
                    }
                }
                return false;
            }
        }
        true
    }

    pub fn release_run(&self, proto: Proto, first: u16, count: u16, who: u8) {
        if let Some(from) = Self::word(proto, first) {
            for w in from..from + usize::from(count) / 64 {
                let _ =
                    self.runs[w].compare_exchange(who + 1, 0, Ordering::SeqCst, Ordering::SeqCst);
            }
        }
    }
}

impl Default for Claims {
    fn default() -> Claims {
        Claims::new()
    }
}

/// The claims of all the instances: the one port space of the service.
pub static CLAIMS: Claims = Claims::new();

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
    ephemeral_steps(offset, counter, map).0
}

/// `ephemeral`, and how many ports it looked at.
fn ephemeral_steps(offset: u32, counter: u32, map: &PortMap) -> (Option<u16>, u32) {
    let mut steps = 0;
    for i in 0..TRIES {
        let port = candidate(offset, counter, i);
        steps += 1;
        if !map.held(port) {
            return (Some(port), steps);
        }
    }
    // The bitmap is this instance's: a port another instance holds is skipped here, a port at
    // a time, and the words that a run holds (a block of a consumer) whole, for at most one
    // round of the range.
    let mut from = offset.wrapping_add(counter).wrapping_add(TRIES) % EPHEMERAL_COUNT;
    for _ in 0..EPHEMERAL_COUNT {
        let Some(n) = map.first_free_from(from) else {
            return (None, steps);
        };
        steps += 1;
        let port = EPHEMERAL_FIRST + n as u16;
        if !map.held_elsewhere(port) {
            return (Some(port), steps);
        }
        from = if map.in_foreign_run(port) {
            (n / 64 + 1) * 64
        } else {
            n + 1
        };
    }
    (None, steps)
}

/// How many sockets hold each port of one protocol. With a count, a socket
/// that lets go of a port subtracts one, where a bit would need a walk over
/// the table (which would put the number of sockets into a step). The ports
/// of the ephemeral range are also a bit each, set while the count is not
/// zero, for the search of a free one.
pub struct PortMap {
    /// The claims of all instances and this map's instance with the protocol it counts; none
    /// for a map that has the ports to itself.
    shared: Option<Shared>,
    held: [u16; 65536],
    used: [u64; EPHEMERAL_WORDS],
    /// Blocks of the ephemeral range that consumers of the switch hold (a run aligned on
    /// words): a bit each, apart from the counts, so that holding or letting go of a block
    /// of 512 ports costs 8 words.
    reserved: [u64; EPHEMERAL_WORDS],
}

#[derive(Clone, Copy)]
struct Shared {
    claims: &'static Claims,
    who: u8,
    proto: Proto,
}

const EPHEMERAL_WORDS: usize = EPHEMERAL_COUNT as usize / 64;

impl PortMap {
    pub const fn new() -> PortMap {
        PortMap {
            shared: None,
            held: [0; 65536],
            used: [0; EPHEMERAL_WORDS],
            reserved: [0; EPHEMERAL_WORDS],
        }
    }

    /// The map counts the ports of `proto` for instance `who`, and takes them from `claims`
    /// (and gives them back) as the instance's first socket holds a port and its last lets go.
    pub fn share(&mut self, claims: &'static Claims, who: u8, proto: Proto) {
        self.shared = Some(Shared { claims, who, proto });
    }

    /// Whether another instance holds `port`.
    pub fn held_elsewhere(&self, port: u16) -> bool {
        self.shared
            .is_some_and(|s| s.claims.owner(s.proto, port).is_some_and(|o| o != s.who))
    }

    pub fn held(&self, port: u16) -> bool {
        self.held[usize::from(port)] > 0 || self.is_reserved(port) || self.held_elsewhere(port)
    }

    /// Whether a run of another instance (a block of a consumer) holds the word of `port`.
    pub fn in_foreign_run(&self, port: u16) -> bool {
        self.shared.is_some_and(|s| {
            s.claims
                .run_owner(s.proto, port)
                .is_some_and(|o| o != s.who)
        })
    }

    /// `hold`, refused (false) when another instance holds `port`. Kept for the callers that
    /// name the refusal; `hold` itself refuses the same way.
    pub fn try_hold(&mut self, port: u16) -> bool {
        self.hold(port)
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
            // The claims are the one port space of all instances: a port another instance
            // holds (or a block of a consumer that instance 0 made, which the claims carry)
            // is not free, though this map's bitmap says so.
            return self.used[words.clone()]
                .iter()
                .zip(&self.reserved[words])
                .all(|(u, r)| *u | *r == 0)
                && self
                    .shared
                    .is_none_or(|s| s.claims.run_free(s.proto, first, count));
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

    /// `hold` for each of `count` ports from `first`; false, and nothing held, when one of the
    /// ports is held by another instance. An aligned run of the ephemeral range (the blocks of
    /// the switch hold 512 ports at once) is a few bits of `reserved` and a claim for each
    /// port, so that every instance sees the block as taken: the run must have been free
    /// (`free_run`).
    pub fn hold_run(&mut self, first: u16, count: u16) -> bool {
        if count == 0 {
            return true;
        }
        let last = first + (count - 1);
        if Self::aligned(first, count) {
            if let Some(s) = self.shared
                && !s.claims.claim_run(s.proto, first, count, s.who)
            {
                return false;
            }
            let word = usize::from(first - EPHEMERAL_FIRST) / 64;
            self.reserved[word..word + usize::from(count) / 64].fill(!0);
            return true;
        }
        for p in first..=last {
            if !self.hold(p) {
                (first..p).for_each(|q| self.release(q));
                return false;
            }
        }
        true
    }

    /// `release` for each of `count` ports from `first` (a run `hold_run` took).
    pub fn release_run(&mut self, first: u16, count: u16) {
        if count == 0 {
            return;
        }
        let last = first + (count - 1);
        if Self::aligned(first, count) {
            let word = usize::from(first - EPHEMERAL_FIRST) / 64;
            self.reserved[word..word + usize::from(count) / 64].fill(0);
            if let Some(s) = self.shared {
                s.claims.release_run(s.proto, first, count, s.who);
            }
            return;
        }
        for p in first..=last {
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

    /// One more socket holds `port`. False, and nothing counted, when another instance holds
    /// it: the claim is the instance's right to the port.
    pub fn hold(&mut self, port: u16) -> bool {
        let n = self.held[usize::from(port)];
        if n == 0 {
            if let Some(s) = self.shared
                && !s.claims.claim(s.proto, port, s.who)
            {
                return false;
            }
            self.mark(port, true);
        }
        self.held[usize::from(port)] = n.saturating_add(1);
        true
    }

    pub fn release(&mut self, port: u16) {
        let n = &mut self.held[usize::from(port)];
        let was = *n;
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.mark(port, false);
            if was > 0
                && let Some(s) = self.shared
            {
                s.claims.release(s.proto, port, s.who);
            }
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

    fn shared_maps() -> (PortMap, PortMap) {
        let claims: &'static Claims = Box::leak(Box::new(Claims::new()));
        let (mut a, mut b) = (PortMap::new(), PortMap::new());
        a.share(claims, 0, Proto::Tcp);
        b.share(claims, 1, Proto::Tcp);
        (a, b)
    }

    #[test]
    fn a_port_one_instance_holds_is_refused_to_another_until_the_last_socket_lets_go() {
        let (mut a, mut b) = shared_maps();
        assert!(a.try_hold(80));
        assert!(a.try_hold(80), "the holder takes it again");
        assert!(!b.try_hold(80));
        assert!(b.held(80) && b.held_elsewhere(80) && !a.held_elsewhere(80));
        a.release(80);
        assert!(!b.try_hold(80), "one holder is left");
        a.release(80);
        assert!(b.try_hold(80), "the last let go");
        assert!(a.held_elsewhere(80));
    }

    #[test]
    fn the_ports_of_another_protocol_are_another_space() {
        let claims: &'static Claims = Box::leak(Box::new(Claims::new()));
        let (mut tcp, mut udp) = (PortMap::new(), PortMap::new());
        tcp.share(claims, 0, Proto::Tcp);
        udp.share(claims, 1, Proto::Udp);
        assert!(tcp.try_hold(53));
        assert!(udp.try_hold(53));
        assert_eq!(claims.owner(Proto::Tcp, 53), Some(0));
        assert_eq!(claims.owner(Proto::Udp, 53), Some(1));
    }

    #[test]
    fn an_ephemeral_choice_skips_the_ports_of_another_instance() {
        let (mut a, b) = shared_maps();
        let first = ephemeral(100, 0, &a).unwrap();
        assert!(a.try_hold(first));
        assert_eq!(ephemeral(100, 0, &b), Some(first + 1));
    }

    /// The 512-port block `n` of the ephemeral range.
    fn block(n: u16) -> u16 {
        EPHEMERAL_FIRST + n * 512
    }

    #[test]
    fn a_consumer_block_is_taken_for_every_instance() {
        let (mut a, mut b) = shared_maps();
        assert!(a.free_run(block(3), 512) && b.free_run(block(3), 512));
        assert!(a.hold_run(block(3), 512));
        // Instance 1 sees every port of the block as held and cannot take one.
        for port in [block(3), block(3) + 100, block(3) + 511] {
            assert!(b.held(port) && b.held_elsewhere(port));
            assert!(!b.try_hold(port) && !b.hold(port));
        }
        assert!(!b.free_run(block(3), 512));
        assert!(
            !b.free_run(block(3) - 64, 128),
            "a run that half meets the block"
        );
        assert!(b.hold(block(3) + 512) && b.hold(block(3) - 1));
        b.release(block(3) + 512);
        b.release(block(3) - 1);
        // The choice of an ephemeral port never lands in the block, from any start: with
        // every other block held by instance 0 it is the one free block that is chosen.
        for n in (0..32).filter(|n| *n != 3 && *n != 9) {
            assert!(a.hold_run(block(n), 512));
        }
        assert!(a.free_run(block(9), 512) && !a.free_run(block(3), 512));
        for offset in [0, 1, 700, 3 * 512, 9 * 512 - 1, 16383] {
            for counter in [0, 5, 64, 1000] {
                let port = ephemeral(offset, counter, &b).expect("a free block is left");
                assert!(
                    (block(9)..block(9) + 512).contains(&port),
                    "port {port} is outside the free block"
                );
            }
        }
        // The block lets go: instance 1 may take its ports.
        for n in (0..32).filter(|n| *n != 9) {
            a.release_run(block(n), 512);
        }
        assert!(!b.held(block(3) + 7) && b.try_hold(block(3) + 7));
        assert!(b.free_run(block(4), 512));
    }

    #[test]
    fn a_block_is_not_made_over_the_ports_of_another_instance() {
        let (mut a, mut b) = shared_maps();
        // Instance 1 holds a port in block 5 only: instance 0's bitmap does not show it.
        assert!(b.hold(block(5) + 300));
        assert!(!a.is_reserved(block(5) + 300) && a.held[usize::from(block(5) + 300)] == 0);
        assert!(!a.free_run(block(5), 512));
        assert!(a.free_run(block(6), 512));
        // A hold that races the check is refused whole and leaves nothing of the run.
        assert!(!a.hold_run(block(5), 512));
        assert!(!a.is_reserved(block(5)) && !a.is_reserved(block(5) + 511));
        assert_eq!(b_owner(&b, block(5)), None);
        assert_eq!(b_owner(&b, block(5) + 300), Some(1));
        b.release(block(5) + 300);
        assert!(a.free_run(block(5), 512) && a.hold_run(block(5), 512));
    }

    fn b_owner(map: &PortMap, port: u16) -> Option<u8> {
        let s = map.shared.expect("a shared map");
        s.claims.owner(s.proto, port)
    }

    #[test]
    fn a_hold_of_a_port_another_instance_holds_counts_nothing() {
        let (mut a, mut b) = shared_maps();
        assert!(a.hold(8080));
        assert!(!b.hold(8080));
        assert!(b.held[8080] == 0 && b_owner(&b, 8080) == Some(0));
        // The holder's own second hold counts.
        assert!(a.hold(8080));
        a.release(8080);
        assert!(b_owner(&a, 8080) == Some(0));
        // A run holds nothing when one of its ports is another's.
        assert!(!b.hold_run(8079, 3));
        assert!(b.held[8079] == 0 && b.held[8081] == 0);
        assert!(a.hold(8079) && a.hold(8081));
    }

    #[test]
    fn the_search_passes_the_blocks_of_a_consumer_a_word_at_a_time() {
        let (mut a, b) = shared_maps();
        // Every block but the last is a consumer's (instance 0's): 31 blocks of 512 ports.
        for n in 0..31 {
            assert!(a.hold_run(block(n), 512));
        }
        let (port, steps) = ephemeral_steps(0, 0, &b);
        assert_eq!(port.map(|p| p >= block(31)), Some(true));
        // A port at a time it would be 15 872 looks; a word at a time under 400 (the 64 candidates
        // that are tried first, then one look at each of 248 words).
        assert!(steps < 400, "{steps} ports looked at");
    }
}
