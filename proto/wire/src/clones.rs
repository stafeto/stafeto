// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sessions a service gave its clients' children with Clone (spec 2,
//! 3.7; 5c), counted: each takes a slot of the service's channel and room
//! in its table of sessions, so a client has PER_CLIENT of them alive at
//! most and the service N. A clone counts until the end of its last copy
//! (CLIENT_GONE of its label).

/// The live clones of each client at most.
pub const PER_CLIENT: usize = 48;

/// Why a Clone is refused: the client or the service has its most.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// No place: the end of a chain and of a free list.
const NONE: u16 = u16::MAX;

/// The bucket of `key` among `n`: a mix of its bits, so that labels that
/// count up (a service gives its clones' labels one after another) spread.
fn bucket(key: u64, n: usize) -> usize {
    let mut x = key.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    ((u128::from(x) * n as u128) >> 64) as usize
}

/// The live clones of a service: each one's label and its client's.
///
/// No operation walks the table, so the cost of a Clone does not grow with
/// the clones alive: the clones live in places with a free list, a table of
/// N chained buckets finds a clone by its label, and a second one finds the
/// record of a client, which holds the count of its clones. A chain holds 1
/// entry on average (as many buckets as places stand) and the mix of
/// `bucket` spreads the labels a service gives one after another; the
/// longest chain a table of N places can have is N, as long as the walk
/// of the table it replaces.
///
/// A place and a record take 12 bytes each, in arrays of their own without
/// padding: a table of 320 takes 9 KB, where a list of pairs took 7.7 KB.
pub struct Clones<const N: usize> {
    /// For each place of a clone: its label, the place of its client's
    /// record, and the next place of its chain, or of the free list.
    label: [u64; N],
    owner: [u16; N],
    next: [u16; N],
    /// The first place of the chain of each bucket of labels.
    labels: [u16; N],
    /// For each record of a client: its label, its count, and the next
    /// record of its chain, or of the free list.
    client: [u64; N],
    count: [u16; N],
    after: [u16; N],
    /// The first record of the chain of each bucket of clients.
    owners: [u16; N],
    free_clone: u16,
    free_client: u16,
}

impl<const N: usize> Default for Clones<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Clones<N> {
    pub const fn new() -> Self {
        assert!(N > 0 && N < NONE as usize, "places are 16 bits");
        let mut next = [NONE; N];
        let mut after = [NONE; N];
        let mut i = 0;
        while i + 1 < N {
            next[i] = (i + 1) as u16;
            after[i] = (i + 1) as u16;
            i += 1;
        }
        Self {
            label: [0; N],
            owner: [NONE; N],
            next,
            labels: [NONE; N],
            client: [0; N],
            count: [0; N],
            after,
            owners: [NONE; N],
            free_clone: 0,
            free_client: 0,
        }
    }

    /// The place of the record of `client`, if it has clones alive.
    fn record(&self, client: u64) -> Option<usize> {
        let mut at = self.owners[bucket(client, N)];
        while at != NONE {
            let i = usize::from(at);
            if self.client[i] == client {
                return Some(i);
            }
            at = self.after[i];
        }
        None
    }

    /// The clones `client` has alive.
    fn own(&self, client: u64) -> usize {
        self.record(client)
            .map_or(0, |i| usize::from(self.count[i]))
    }

    /// Whether `client` may have one clone more.
    pub fn room(&self, client: u64) -> Result<(), Full> {
        self.room_within(client, PER_CLIENT)
    }

    /// Whether `client` may have one clone more with `most` of its own at
    /// most, for a service that counts its clients otherwise (the pipe
    /// service counts the clones of a whole tree of processes).
    pub fn room_within(&self, client: u64, most: usize) -> Result<(), Full> {
        if self.own(client) >= most || self.free_clone == NONE {
            return Err(Full);
        }
        Ok(())
    }

    /// The clone `label` of `client` is alive; Full past the limits.
    pub fn add(&mut self, label: u64, client: u64) -> Result<(), Full> {
        self.add_within(label, client, PER_CLIENT)
    }

    /// `add` with `most` clones of `client` at most (`room_within`).
    pub fn add_within(&mut self, label: u64, client: u64, most: usize) -> Result<(), Full> {
        self.room_within(client, most)?;
        // A place is free, so fewer than N clones live, so fewer than N
        // clients have records: a record is free too.
        let record = match self.record(client) {
            Some(i) => i,
            None => {
                let i = usize::from(self.free_client);
                self.free_client = self.after[i];
                let b = bucket(client, N);
                self.client[i] = client;
                self.count[i] = 0;
                self.after[i] = self.owners[b];
                self.owners[b] = i as u16;
                i
            }
        };
        self.count[record] += 1;
        let place = usize::from(self.free_clone);
        self.free_clone = self.next[place];
        let b = bucket(label, N);
        self.label[place] = label;
        self.owner[place] = record as u16;
        self.next[place] = self.labels[b];
        self.labels[b] = place as u16;
        Ok(())
    }

    /// The place of the live clone `label`.
    fn place(&self, label: u64) -> Option<usize> {
        let mut at = self.labels[bucket(label, N)];
        while at != NONE {
            let i = usize::from(at);
            if self.label[i] == label {
                return Some(i);
            }
            at = self.next[i];
        }
        None
    }

    /// The client the live clone `label` was made for, if it is one.
    pub fn client_of(&self, label: u64) -> Option<u64> {
        self.place(label)
            .map(|i| self.client[usize::from(self.owner[i])])
    }

    /// The last copy of the clone `label` went.
    pub fn gone(&mut self, label: u64) {
        let b = bucket(label, N);
        let mut before = NONE;
        let mut at = self.labels[b];
        while at != NONE {
            let i = usize::from(at);
            if self.label[i] == label {
                if before == NONE {
                    self.labels[b] = self.next[i];
                } else {
                    self.next[usize::from(before)] = self.next[i];
                }
                let record = usize::from(self.owner[i]);
                self.next[i] = self.free_clone;
                self.free_clone = at;
                self.count[record] -= 1;
                if self.count[record] == 0 {
                    self.drop_record(record);
                }
                return;
            }
            before = at;
            at = self.next[i];
        }
    }

    /// The record `record`, which counts no clone, goes to the free list.
    fn drop_record(&mut self, record: usize) {
        let b = bucket(self.client[record], N);
        let mut before = NONE;
        let mut at = self.owners[b];
        while at != NONE {
            let i = usize::from(at);
            if i == record {
                if before == NONE {
                    self.owners[b] = self.after[i];
                } else {
                    self.after[usize::from(before)] = self.after[i];
                }
                self.after[i] = self.free_client;
                self.free_client = at;
                return;
            }
            before = at;
            at = self.after[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client has PER_CLIENT live clones: the next is refused until one
    /// goes; the service's N bound all clients.
    #[test]
    fn clones_are_bounded_per_client_and_in_all() {
        let mut c = Clones::<64>::new();
        for i in 0..PER_CLIENT as u64 {
            assert_eq!(c.add(100 + i, 7), Ok(()));
        }
        assert_eq!(c.add(999, 7), Err(Full), "one more of client 7");
        assert_eq!(c.add(999, 8), Ok(()), "another client's");
        c.gone(100);
        assert_eq!(c.add(1000, 7), Ok(()));
        for i in 0..15 {
            assert_eq!(c.add(2000 + i, 9), Ok(()));
        }
        assert_eq!(c.add(3000, 10), Err(Full), "the service's 64");
        assert_eq!(c.client_of(1000), Some(7));
        assert_eq!(c.client_of(100), None, "gone");
    }

    /// The longest walk a lookup of `label` makes along its chain.
    fn walk<const N: usize>(c: &Clones<N>, label: u64) -> usize {
        let mut steps = 0;
        let mut at = c.labels[bucket(label, N)];
        while at != NONE {
            steps += 1;
            if c.label[usize::from(at)] == label {
                break;
            }
            at = c.next[usize::from(at)];
        }
        steps
    }

    /// The same for the record of `client`.
    fn walk_client<const N: usize>(c: &Clones<N>, client: u64) -> usize {
        let mut steps = 0;
        let mut at = c.owners[bucket(client, N)];
        while at != NONE {
            steps += 1;
            if c.client[usize::from(at)] == client {
                break;
            }
            at = c.after[usize::from(at)];
        }
        steps
    }

    /// A full table of 320 clones, labels as the services give them (a
    /// tag in the high bits and a count) of clients 1..=7 with roots as
    /// the pipe service has them: no lookup walks more than a few places,
    /// where the table it replaces walked all 320.
    #[test]
    fn lookups_stay_short_with_a_full_table() {
        let mut c = Clones::<320>::new();
        let tag = 1u64 << 63;
        for i in 0..320u64 {
            assert_eq!(c.add_within(tag | (i + 1), (i % 7) + 1, 320), Ok(()));
        }
        assert_eq!(c.add_within(tag | 999, 1, 320), Err(Full));
        let longest = (0..320u64).map(|i| walk(&c, tag | (i + 1))).max().unwrap();
        let clients = (1..=7u64).map(|k| walk_client(&c, k)).max().unwrap();
        assert!(longest <= 8, "a label's chain is {longest} long");
        assert!(clients <= 3, "a client's chain is {clients} long");
        // Labels that count in the low bits and clients that are labels.
        let mut c = Clones::<320>::new();
        for i in 0..320u64 {
            assert_eq!(c.add_within(i + 1, tag | (i * 4096), 320), Ok(()));
        }
        let longest = (0..320u64).map(|i| walk(&c, i + 1)).max().unwrap();
        let clients = (0..320u64)
            .map(|i| walk_client(&c, tag | (i * 4096)))
            .max()
            .unwrap();
        assert!(longest <= 8, "a label's chain is {longest} long");
        assert!(clients <= 8, "a client's chain is {clients} long");
    }

    /// A long run of random Clone and end steps against a plain list: every
    /// answer is the list's, the places and records all come back at the
    /// end.
    #[test]
    fn follows_a_plain_list_of_clones() {
        const N: usize = 40;
        let mut c = Clones::<N>::new();
        let mut list: Vec<(u64, u64)> = Vec::new();
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut given = 0u64;
        for _ in 0..20_000 {
            let client = next() % 6;
            match next() % 3 {
                0 | 1 => {
                    given += 1;
                    let most = 1 + (next() % 9) as usize;
                    let own = list.iter().filter(|(_, k)| *k == client).count();
                    let expect = if own >= most || list.len() >= N {
                        Err(Full)
                    } else {
                        Ok(())
                    };
                    assert_eq!(c.room_within(client, most), expect);
                    assert_eq!(c.add_within(given, client, most), expect);
                    if expect.is_ok() {
                        list.push((given, client));
                    }
                }
                _ if !list.is_empty() => {
                    let (label, _) = list.swap_remove(next() as usize % list.len());
                    c.gone(label);
                    c.gone(label);
                }
                _ => {}
            }
            let probe = given.saturating_sub(next() % 50);
            let want = list.iter().find(|(l, _)| *l == probe).map(|(_, k)| *k);
            assert_eq!(c.client_of(probe), want);
        }
        for (label, _) in list.drain(..) {
            c.gone(label);
        }
        for k in 0..6 {
            assert_eq!(c.own(k), 0);
        }
        for i in 0..N as u64 {
            assert_eq!(c.add_within(1_000_000 + i, i, 1), Ok(()), "a record each");
        }
        assert_eq!(c.add_within(2_000_000, 99, 1), Err(Full));
    }
}
