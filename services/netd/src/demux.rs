// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table that steers a received frame to the place of the socket it is
//! for, so that the stack looks at the group of that socket alone (smoltcp
//! walks every socket of a set for each frame). A TCP socket with a
//! connection is found by its four, a listening description and a UDP socket
//! by its address and port; the address 0.0.0.0 stands for all.  Open
//! addressing with linear probing over DEMUX_SLOTS places, at most half of
//! them filled. The hash is SipHash-2-4 under a secret of the service, so
//! that a peer cannot choose the four of its connections to meet in one
//! chain. A removal shifts the chain back, leaving no tombstone.

use core::hash::Hasher;
#[allow(deprecated)] // SipHasher is in core and has no replacement there.
use core::hash::SipHasher;

/// The places of the table: six times the 1 280 sockets it must hold (one
/// sixth full), so that the chains of linear probing stay short (at most 8
/// in the probe's runs: with 4 096 places a chain of 9 came up).
pub const DEMUX_SLOTS: usize = 8192;
/// The longest chain a probe is allowed to find (acceptance).
pub const PROBE_LIMIT: usize = 8;

/// What a socket is found by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A stream with a connection: its own address and port, and the peer's.
    Conn {
        local: [u8; 4],
        local_port: u16,
        remote: [u8; 4],
        remote_port: u16,
    },
    /// A listening description or a datagram socket: the address (0.0.0.0 for
    /// all) and the port.
    Bound {
        tcp: bool,
        address: [u8; 4],
        port: u16,
    },
}

impl Key {
    fn bytes(&self) -> ([u8; 14], usize) {
        let mut b = [0u8; 14];
        match *self {
            Key::Conn {
                local,
                local_port,
                remote,
                remote_port,
            } => {
                b[0] = 1;
                b[1..5].copy_from_slice(&local);
                b[5..7].copy_from_slice(&local_port.to_le_bytes());
                b[7..11].copy_from_slice(&remote);
                b[11..13].copy_from_slice(&remote_port.to_le_bytes());
                (b, 13)
            }
            Key::Bound { tcp, address, port } => {
                b[0] = if tcp { 2 } else { 3 };
                b[1..5].copy_from_slice(&address);
                b[5..7].copy_from_slice(&port.to_le_bytes());
                (b, 7)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Entry {
    key: Key,
    place: u16,
}

/// The table.
pub struct Demux {
    entries: [Option<Entry>; DEMUX_SLOTS],
    keys: (u64, u64),
    used: usize,
    /// The longest chain any lookup or insert walked.
    pub probe_max: usize,
}

impl Demux {
    /// A table under the secret `key`.
    pub fn new(key: &[u8; 16]) -> Demux {
        let k0 = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(key[8..].try_into().expect("8 bytes"));
        Demux {
            entries: [None; DEMUX_SLOTS],
            keys: (k0, k1),
            used: 0,
            probe_max: 0,
        }
    }

    /// The table in place in zeroed memory.
    ///
    /// # Safety
    /// `at` is valid for writes, exclusive and zeroed.
    pub unsafe fn initialize_at(at: *mut Demux, key: &[u8; 16]) {
        use core::ptr::addr_of_mut;
        let k0 = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(key[8..].try_into().expect("8 bytes"));
        // SAFETY: each field is in bounds and written once.
        unsafe {
            rt_fill_none(addr_of_mut!((*at).entries));
            addr_of_mut!((*at).keys).write((k0, k1));
            addr_of_mut!((*at).used).write(0);
            addr_of_mut!((*at).probe_max).write(0);
        }
    }

    /// The hash of `key` under the secret of the service: the slot is its
    /// remainder, and a group of SO_REUSEPORT picks its member by it.
    #[allow(deprecated)]
    pub fn hash_of(&self, key: &Key) -> u64 {
        let (bytes, len) = key.bytes();
        let mut hash = SipHasher::new_with_keys(self.keys.0, self.keys.1);
        hash.write(&bytes[..len]);
        hash.finish()
    }

    fn home(&self, key: &Key) -> usize {
        (self.hash_of(key) % DEMUX_SLOTS as u64) as usize
    }

    /// Puts `key` in the table for `place`; false when it is there already
    /// or the table is full to its half.
    pub fn insert(&mut self, key: Key, place: usize) -> bool {
        if self.used >= DEMUX_SLOTS / 2 {
            return false;
        }
        let mut i = self.home(&key);
        let mut walked = 1;
        while let Some(e) = &self.entries[i] {
            if e.key == key {
                return false;
            }
            i = (i + 1) % DEMUX_SLOTS;
            walked += 1;
        }
        self.entries[i] = Some(Entry {
            key,
            place: place as u16,
        });
        self.used += 1;
        self.probe_max = self.probe_max.max(walked);
        true
    }

    /// The place `key` is for.
    pub fn find(&mut self, key: &Key) -> Option<usize> {
        let mut i = self.home(key);
        let mut walked = 1;
        let found = loop {
            match &self.entries[i] {
                None => break None,
                Some(e) if e.key == *key => break Some(usize::from(e.place)),
                Some(_) => {
                    i = (i + 1) % DEMUX_SLOTS;
                    walked += 1;
                }
            }
        };
        self.probe_max = self.probe_max.max(walked);
        found
    }

    /// Takes `key` out, shifting back the entries of its chain that a hole
    /// would hide.
    pub fn remove(&mut self, key: &Key) -> bool {
        let mut i = self.home(key);
        loop {
            match &self.entries[i] {
                None => return false,
                Some(e) if e.key == *key => break,
                Some(_) => i = (i + 1) % DEMUX_SLOTS,
            }
        }
        self.entries[i] = None;
        self.used -= 1;
        let mut hole = i;
        let mut j = i;
        loop {
            j = (j + 1) % DEMUX_SLOTS;
            let Some(e) = self.entries[j] else { break };
            let home = self.home(&e.key);
            // The entry may move into the hole when its home is not between
            // the hole (exclusive) and its place (inclusive), going forward.
            let between = if hole <= j {
                hole < home && home <= j
            } else {
                hole < home || home <= j
            };
            if !between {
                self.entries[hole] = Some(e);
                self.entries[j] = None;
                hole = j;
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }
}

/// Writes `None` into each element of the array (the bss helper of rt is not
/// in the host build of the library).
///
/// # Safety
/// `array` is valid for writes.
unsafe fn rt_fill_none<T, const N: usize>(array: *mut [Option<T>; N]) {
    let first = array.cast::<Option<T>>();
    for i in 0..N {
        // SAFETY: the element `i` of the array is in bounds.
        unsafe { first.add(i).write(None) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(i: u32) -> Key {
        Key::Conn {
            local: [127, 0, 0, 1],
            local_port: 80,
            remote: [127, 0, (i >> 16) as u8, 1],
            remote_port: 49152u16.wrapping_add(i as u16),
        }
    }

    #[test]
    fn a_key_is_found_until_it_is_removed() {
        let mut t = Demux::new(&[7; 16]);
        assert!(t.insert(conn(1), 5));
        assert!(!t.insert(conn(1), 6), "a key twice");
        assert_eq!(t.find(&conn(1)), Some(5));
        assert_eq!(t.find(&conn(2)), None);
        assert!(t.remove(&conn(1)));
        assert!(!t.remove(&conn(1)));
        assert_eq!(t.find(&conn(1)), None);
        assert!(t.is_empty());
    }

    #[test]
    fn the_exact_address_and_the_wildcard_are_two_keys() {
        let mut t = Demux::new(&[1; 16]);
        let exact = Key::Bound {
            tcp: true,
            address: [10, 0, 2, 15],
            port: 80,
        };
        let any = Key::Bound {
            tcp: true,
            address: [0; 4],
            port: 80,
        };
        let udp = Key::Bound {
            tcp: false,
            address: [0; 4],
            port: 80,
        };
        assert!(t.insert(any, 1));
        assert!(t.insert(exact, 2));
        assert!(t.insert(udp, 3));
        assert_eq!(t.find(&exact), Some(2));
        assert_eq!(t.find(&any), Some(1));
        assert_eq!(t.find(&udp), Some(3));
    }

    #[test]
    fn the_keys_of_all_the_sockets_are_found() {
        let mut t = Demux::new(&[9; 16]);
        // 1 280 sockets with a key each: less than a third of the table.
        for i in 0..1280 {
            assert!(t.insert(conn(i), i as usize), "{i}");
        }
        for i in 0..1280 {
            assert_eq!(t.find(&conn(i)), Some(i as usize));
        }
        assert!(t.probe_max <= PROBE_LIMIT, "chain {}", t.probe_max);
        // The table takes keys up to its half and refuses past it.
        for i in 1280..DEMUX_SLOTS as u32 / 2 {
            assert!(t.insert(conn(i), i as usize), "{i}");
        }
        assert!(!t.insert(conn(5000), 0), "the table is full to its half");
    }

    #[test]
    fn a_removal_keeps_the_rest_of_the_chain_reachable() {
        let mut t = Demux::new(&[3; 16]);
        for i in 0..200 {
            t.insert(conn(i), i as usize);
        }
        // Remove every other key, then find the rest and refill.
        for i in (0..200).step_by(2) {
            assert!(t.remove(&conn(i)));
        }
        for i in (1..200).step_by(2) {
            assert_eq!(t.find(&conn(i)), Some(i as usize), "{i}");
        }
        for i in (0..200).step_by(2) {
            assert!(t.insert(conn(i), 300 + i as usize));
        }
        for i in 0..200 {
            assert!(t.find(&conn(i)).is_some());
        }
        assert_eq!(t.len(), 200);
    }

    /// With a constant secret an attacker can choose fours that meet in one
    /// chain; a secret of the service makes the same fours spread. The test
    /// finds 64 fours that collide under the key of zeros and checks that
    /// another key does not chain them.
    #[test]
    fn a_secret_key_spreads_fours_chosen_for_another_key() {
        let zero = Demux::new(&[0; 16]);
        let mut chosen = Vec::new();
        let target = zero.home(&conn(0));
        let mut i = 0;
        while chosen.len() < 64 {
            if zero.home(&conn(i)) == target {
                chosen.push(i);
            }
            i += 1;
        }
        let mut weak = Demux::new(&[0; 16]);
        for &c in &chosen {
            weak.insert(conn(c), 0);
        }
        assert!(weak.probe_max > PROBE_LIMIT, "the zero key chains them");
        let mut strong = Demux::new(&[0xA5; 16]);
        for &c in &chosen {
            strong.insert(conn(c), 0);
        }
        assert!(
            strong.probe_max <= PROBE_LIMIT,
            "chain {}",
            strong.probe_max
        );
    }

    #[test]
    fn the_chain_through_the_end_of_the_array_is_kept() {
        // Fill the table with keys whose homes are near the end.
        let mut t = Demux::new(&[5; 16]);
        let mut near_end = Vec::new();
        let mut i = 0;
        while near_end.len() < 12 {
            if t.home(&conn(i)) >= DEMUX_SLOTS - 3 {
                near_end.push(i);
            }
            i += 1;
        }
        for &c in &near_end {
            t.insert(conn(c), c as usize);
        }
        t.remove(&conn(near_end[0]));
        for &c in &near_end[1..] {
            assert_eq!(t.find(&conn(c)), Some(c as usize));
        }
    }
}
