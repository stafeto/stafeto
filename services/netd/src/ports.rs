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

/// The first free port of the candidates, None after TRIES.
pub fn ephemeral(offset: u32, counter: u32, free: impl Fn(u16) -> bool) -> Option<u16> {
    (0..TRIES)
        .map(|i| candidate(offset, counter, i))
        .find(|&port| free(port))
}

/// A bit for each port of one protocol: set while a socket holds the port.
pub struct PortMap {
    bits: [u64; 1024],
}

impl PortMap {
    pub const fn new() -> PortMap {
        PortMap { bits: [0; 1024] }
    }

    pub fn held(&self, port: u16) -> bool {
        self.bits[usize::from(port) / 64] >> (port % 64) & 1 != 0
    }

    pub fn hold(&mut self, port: u16) {
        self.bits[usize::from(port) / 64] |= 1 << (port % 64);
    }

    pub fn release(&mut self, port: u16) {
        self.bits[usize::from(port) / 64] &= !(1 << (port % 64));
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

    #[test]
    fn ports_come_from_the_ephemeral_range_and_skip_the_held_ones() {
        let first = ephemeral(100, 0, |_| true).unwrap();
        assert_eq!(first, EPHEMERAL_FIRST + 100);
        // The counter moves the choice by one.
        assert_eq!(ephemeral(100, 1, |_| true), Some(first + 1));
        // A held candidate is skipped.
        assert_eq!(ephemeral(100, 0, |p| p != first), Some(first + 1));
        // The range wraps.
        let last = ephemeral(EPHEMERAL_COUNT - 1, 0, |_| true).unwrap();
        assert_eq!(last, 65535);
        assert_eq!(ephemeral(EPHEMERAL_COUNT - 1, 1, |_| true), Some(49152));
        // 64 held candidates in a row end the choice.
        assert_eq!(ephemeral(5, 0, |p| p >= EPHEMERAL_FIRST + 69), None);
        assert!(ephemeral(5, 0, |p| p >= EPHEMERAL_FIRST + 68).is_some());
    }

    #[test]
    fn the_map_holds_and_releases_ports() {
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
    }
}
