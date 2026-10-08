// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sessions a service gave its clients' children with Clone (spec 2,
//! 3.7; 5c), counted: each takes a slot of the service's channel and room
//! in its table of sessions, so a client has PER_CLIENT of them alive at
//! most and the service N. A clone counts until the end of its last copy
//! (CLIENT_GONE of its label).

/// The live clones of each client at most.
pub const PER_CLIENT: usize = 48;

/// The clients that are not clones themselves (a root: a session that init
/// or the service gave out itself) that count clones at once, at most.
/// Trusted parties choose their labels, so the small table that holds them
/// is walked whole.
pub const ROOTS: usize = 32;

/// Why a Clone is refused: the client or the service has its most, or the
/// table of roots is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// The largest table: places are 16 bits, and the free list holds a place
/// plus one, so that zero ends it and an empty table is all zeros (in
/// `.bss`).
const MAX_PLACES: usize = u16::MAX as usize;

/// The count a new clone adds to: a place of the table (the client is a
/// clone) or an entry of the table of roots.
#[derive(Clone, Copy)]
enum Account {
    Place(usize),
    Root(usize),
}

/// The live clones of a service: each one's label and its client's.
///
/// A clone lives in a place of the table, and the place is in its label
/// (`tag | generation << BITS | place`; the service names the tag, `give`
/// counts the generation, so that a label is never given twice). A lookup
/// reads the place of the label and compares the label there: it never
/// walks the table, and a label that a client makes up finds nothing. The
/// count of the clones a clone made sits in its own place; a client that is
/// no clone of this table (a root) has its count in a table of ROOTS
/// entries, whose labels the trusted parties choose. Every operation takes
/// a bounded number of steps, whatever the clients do.
///
/// A place takes 20 bytes: a table of 320 takes 6.4 KB.
pub struct Clones<const N: usize, const BITS: u32 = 16> {
    /// For each place: the label of its clone (0 for a free place), its
    /// client's label, the clones it made as a client, and the place after
    /// it in the list of the places that went (plus one; 0 ends it).
    label: [u64; N],
    client: [u64; N],
    made: [u16; N],
    next: [u16; N],
    /// The first place of that list (plus one; 0 for none), and how many
    /// places were never used: they come after the list. A new table is
    /// all zeros.
    free: u16,
    fresh: u16,
    /// The labels `give` gave so far.
    given: u64,
    /// For each root: its label and the clones it has alive (0 for a free
    /// entry).
    root: [u64; ROOTS],
    root_made: [u16; ROOTS],
    /// How the table is filled: 1 once `give` was used, 2 once `adopt` was.
    #[cfg(debug_assertions)]
    mode: u8,
    /// The entries of the table of roots a test counted.
    #[cfg(test)]
    probes: core::cell::Cell<usize>,
}

impl<const N: usize, const BITS: u32> Default for Clones<N, BITS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const BITS: u32> Clones<N, BITS> {
    const MASK: u64 = (1 << BITS) - 1;

    pub const fn new() -> Self {
        assert!(N > 0 && N < MAX_PLACES, "places are 16 bits");
        assert!(N as u64 <= Self::MASK + 1, "a place fits the label");
        Self {
            label: [0; N],
            client: [0; N],
            made: [0; N],
            next: [0; N],
            free: 0,
            fresh: 0,
            given: 0,
            root: [0; ROOTS],
            root_made: [0; ROOTS],
            #[cfg(debug_assertions)]
            mode: 0,
            #[cfg(test)]
            probes: core::cell::Cell::new(0),
        }
    }

    /// The place of the live clone `label`: the place its bits name, if the
    /// label is the one there.
    pub fn place_of(&self, label: u64) -> Option<usize> {
        let place = (label & Self::MASK) as usize;
        (label != 0 && place < N && self.label[place] == label).then_some(place)
    }

    /// The entry of the table of roots that counts `client`, in one walk
    /// of the table.
    fn root_of(&self, client: u64) -> Option<usize> {
        (0..ROOTS).find(|&i| {
            #[cfg(test)]
            self.probes.set(self.probes.get() + 1);
            self.root_made[i] != 0 && self.root[i] == client
        })
    }

    /// Where `client` counts its clones, if it may have one more with
    /// `most` of its own at most: the one walk of the table of roots that
    /// a Clone makes.
    fn account(&self, client: u64, most: usize) -> Result<Account, Full> {
        if let Some(place) = self.place_of(client) {
            return if usize::from(self.made[place]) < most {
                Ok(Account::Place(place))
            } else {
                Err(Full)
            };
        }
        let mut free = None;
        for i in 0..ROOTS {
            #[cfg(test)]
            self.probes.set(self.probes.get() + 1);
            if self.root_made[i] == 0 {
                free = free.or(Some(i));
            } else if self.root[i] == client {
                return if usize::from(self.root_made[i]) < most {
                    Ok(Account::Root(i))
                } else {
                    Err(Full)
                };
            }
        }
        free.map(Account::Root).ok_or(Full)
    }

    /// Whether `client` may have one clone more.
    pub fn room(&self, client: u64) -> Result<(), Full> {
        self.room_within(client, PER_CLIENT)
    }

    /// Whether `client` may have one clone more with `most` of its own at
    /// most, for a service that counts its clients otherwise (the pipe
    /// service counts the clones of a whole tree of processes).
    pub fn room_within(&self, client: u64, most: usize) -> Result<(), Full> {
        self.account(client, most).map(|_| ())
    }

    /// A new clone of `client` with a label of its own: `tag` (bits the
    /// service keeps for itself, above the generation), the generation and
    /// the place. Full past the limits. A service that cannot finish the
    /// clone calls `gone` with the label.
    pub fn give(&mut self, tag: u64, client: u64) -> Result<u64, Full> {
        self.give_within(tag, client, PER_CLIENT)
    }

    /// `give` with `most` clones of `client` at most (`room_within`).
    pub fn give_within(&mut self, tag: u64, client: u64, most: usize) -> Result<u64, Full> {
        #[cfg(debug_assertions)]
        {
            assert!(self.mode & 2 == 0, "a table uses give or adopt, not both");
            self.mode |= 1;
        }
        let account = self.account(client, most)?;
        let given = self.given + 1;
        if given >= 1 << (62 - BITS) {
            return Err(Full);
        }
        // A place that went comes first; else the next never used.
        let place = if self.free != 0 {
            let place = usize::from(self.free) - 1;
            self.free = self.next[place];
            place
        } else if usize::from(self.fresh) < N {
            self.fresh += 1;
            usize::from(self.fresh) - 1
        } else {
            return Err(Full);
        };
        self.given = given;
        let label = tag | given << BITS | place as u64;
        self.insert(place, label, client, account);
        Ok(label)
    }

    /// The clone `label` of `client` is alive, with a label some other
    /// table made, whose low BITS bits name a place no other clone has.
    /// A table is filled by `give` or by `adopt`, never both: `adopt` does
    /// not take its place from the free list that `give` draws on, so a
    /// mixed table would hand out a place twice (debug builds check it).
    pub fn adopt(&mut self, label: u64, client: u64) -> Result<(), Full> {
        self.adopt_within(label, client, PER_CLIENT)
    }

    /// `adopt` with `most` clones of `client` at most.
    pub fn adopt_within(&mut self, label: u64, client: u64, most: usize) -> Result<(), Full> {
        #[cfg(debug_assertions)]
        {
            assert!(self.mode & 1 == 0, "a table uses give or adopt, not both");
            self.mode |= 2;
        }
        let account = self.account(client, most)?;
        let place = (label & Self::MASK) as usize;
        if label == 0 || place >= N || self.label[place] != 0 {
            return Err(Full);
        }
        self.insert(place, label, client, account);
        Ok(())
    }

    /// The clone `label` of `client` takes `place`.
    fn insert(&mut self, place: usize, label: u64, client: u64, account: Account) {
        match account {
            Account::Place(owner) => self.made[owner] += 1,
            Account::Root(at) => {
                self.root[at] = client;
                self.root_made[at] += 1;
            }
        }
        self.label[place] = label;
        self.client[place] = client;
        self.made[place] = 0;
    }

    /// The clones `client` has alive.
    #[cfg(test)]
    fn own(&self, client: u64) -> usize {
        if let Some(place) = self.place_of(client) {
            usize::from(self.made[place])
        } else {
            self.root_of(client)
                .map_or(0, |i| usize::from(self.root_made[i]))
        }
    }

    /// The client the live clone `label` was made for, if it is one.
    pub fn client_of(&self, label: u64) -> Option<u64> {
        self.place_of(label).map(|place| self.client[place])
    }

    /// The last copy of the clone `label` went.
    pub fn gone(&mut self, label: u64) {
        let Some(place) = self.place_of(label) else {
            return;
        };
        // A client that went before its clone counts nothing any more.
        let client = self.client[place];
        if let Some(owner) = self.place_of(client) {
            self.made[owner] = self.made[owner].saturating_sub(1);
        } else if let Some(at) = self.root_of(client) {
            self.root_made[at] = self.root_made[at].saturating_sub(1);
        }
        self.label[place] = 0;
        self.next[place] = self.free;
        self.free = place as u16 + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: u64 = 1 << 63;

    /// A client has PER_CLIENT live clones: the next is refused until one
    /// goes; the service's N bound all clients.
    /// An empty table is all zeros, so that a static one lies in `.bss`
    /// with none of its bytes in the program's file.
    #[test]
    fn an_empty_table_is_all_zeros() {
        // SAFETY: integers, and a Cell of one in tests.
        let zeros: Clones<8> = unsafe { core::mem::zeroed() };
        let new = Clones::<8>::new();
        assert_eq!(new.label, zeros.label);
        assert_eq!(new.client, zeros.client);
        assert_eq!(new.made, zeros.made);
        assert_eq!(new.next, zeros.next);
        assert_eq!((new.free, new.fresh, new.given), (0, 0, 0));
        assert_eq!(new.root, zeros.root);
        assert_eq!(new.root_made, zeros.root_made);
    }

    /// Places come in order while none went, a place that went comes
    /// first, and the table is full after N places.
    #[test]
    fn places_come_fresh_then_gone_ones_first() {
        let mut c = Clones::<4>::new();
        let root = TAG | 1 << 40;
        let a: Vec<u64> = (0..4).map(|_| c.give(TAG, root).unwrap()).collect();
        assert_eq!(
            a.iter().map(|l| l & 0xffff).collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert!(c.give(TAG, root).is_err());
        c.gone(a[2]);
        c.gone(a[1]);
        assert_eq!(c.give(TAG, root).unwrap() & 0xffff, 1);
        assert_eq!(c.give(TAG, root).unwrap() & 0xffff, 2);
        assert!(c.give(TAG, root).is_err());
    }

    #[test]
    fn clones_are_bounded_per_client_and_in_all() {
        let mut c = Clones::<64>::new();
        let mut mine = Vec::new();
        for _ in 0..PER_CLIENT {
            mine.push(c.give(TAG, 7).unwrap());
        }
        assert_eq!(c.give(TAG, 7), Err(Full), "one more of client 7");
        assert!(c.give(TAG, 8).is_ok(), "another client's");
        c.gone(mine[0]);
        let again = c.give(TAG, 7).unwrap();
        for _ in 0..15 {
            assert!(c.give(TAG, 9).is_ok());
        }
        assert_eq!(c.give(TAG, 10), Err(Full), "the service's 64");
        assert_eq!(c.client_of(again), Some(7));
        assert_eq!(c.client_of(mine[0]), None, "gone");
    }

    /// A label names its place and never repeats: a label of a clone that
    /// went finds nothing, though a new clone took its place; a label made
    /// up finds nothing.
    #[test]
    fn a_label_is_found_only_by_its_clone() {
        let mut c = Clones::<8>::new();
        let old = c.give(TAG, 1).unwrap();
        c.gone(old);
        let new = c.give(TAG, 1).unwrap();
        assert_eq!(new & 0xffff, old & 0xffff, "the place came back");
        assert_ne!(new, old);
        assert_eq!(c.client_of(old), None);
        c.gone(old);
        assert_eq!(c.client_of(new), Some(1), "the old label did not end it");
        for made_up in [0, 1, TAG, TAG | 5, new ^ (1 << 20), new + 1] {
            assert_eq!(c.client_of(made_up), None);
        }
        assert_eq!(c.give_within(TAG, 1, 1), Err(Full));
    }

    /// The clones a clone made count for the clone that made them; they go on
    /// after it went, and nothing is counted twice.
    #[test]
    fn a_clone_counts_the_clones_it_made() {
        let mut c = Clones::<16>::new();
        let a = c.give(TAG, 1).unwrap();
        let b1 = c.give_within(TAG, a, 2).unwrap();
        let b2 = c.give_within(TAG, a, 2).unwrap();
        assert_eq!(c.give_within(TAG, a, 2), Err(Full));
        assert_eq!(c.client_of(b2), Some(a));
        c.gone(b1);
        let b3 = c.give_within(TAG, a, 2).unwrap();
        // The client a goes before its clones: they end without a count.
        c.gone(a);
        c.gone(b2);
        c.gone(b3);
        assert_eq!(c.own(1), 0);
        // Its place is taken again; the old clients' labels count nothing.
        let d = c.give(TAG, 1).unwrap();
        assert_eq!(c.own(d), 0);
        assert_eq!(c.own(1), 1);
    }

    /// The attack on the table it replaces: clients and copies chosen so
    /// that a hashed chain would grow. A lookup reads one place and the
    /// table of roots is walked whole, so no chosen clients lengthen a step
    /// past ROOTS entries, and clients past ROOTS roots are refused.
    #[test]
    fn chosen_clients_do_not_lengthen_a_step() {
        let mut c = Clones::<320>::new();
        let mut labels = Vec::new();
        let mut most = 0;
        let mut step = |c: &Clones<320>, before: usize| {
            most = most.max(c.probes.get() - before);
        };
        // Clients that are labels apart by 4096, a pattern that fills one
        // bucket of a hash: ROOTS of them are admitted, the rest refused.
        for i in 0..400u64 {
            let client = TAG | 1 << 61 | (i * 4096);
            let before = c.probes.get();
            match c.give_within(TAG, client, 320) {
                Ok(label) => labels.push(label),
                Err(Full) => assert!(i as usize >= ROOTS),
            }
            step(&c, before);
        }
        assert_eq!(labels.len(), ROOTS);
        // Clones of one root, made as clients of their own, down to the
        // table's end.
        let mut from = labels[0];
        while let Ok(label) = c.give_within(TAG, from, 1) {
            labels.push(label);
            from = label;
        }
        assert!(c.give_within(TAG, from, 1).is_err());
        for label in labels.iter().copied() {
            let before = c.probes.get();
            let _ = c.client_of(label);
            c.gone(label);
            step(&c, before);
        }
        assert!(c.give(TAG, labels[0]).is_ok());
        assert!(
            most <= ROOTS,
            "a step walked {most} entries of the table of roots"
        );
    }

    /// A long run of random Clone and end steps against a plain list: every
    /// answer is the list's, the places all come back at the end.
    #[test]
    fn follows_a_plain_list_of_clones() {
        const N: usize = 40;
        let mut c = Clones::<N>::new();
        // (label, client)
        let mut list: Vec<(u64, u64)> = Vec::new();
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            // A client is a root (1..=6) or a live clone.
            let client = if list.is_empty() || next() % 3 == 0 {
                1 + next() % 6
            } else {
                list[next() as usize % list.len()].0
            };
            match next() % 3 {
                0 | 1 => {
                    let most = 1 + (next() % 9) as usize;
                    let own = list.iter().filter(|(_, k)| *k == client).count();
                    let expect_full = own >= most || list.len() >= N;
                    let got = c.give_within(TAG, client, most);
                    assert_eq!(got.is_err(), expect_full);
                    if let Ok(label) = got {
                        assert!(!list.iter().any(|(l, _)| *l == label));
                        list.push((label, client));
                    }
                }
                _ if !list.is_empty() => {
                    let (label, _) = list.swap_remove(next() as usize % list.len());
                    c.gone(label);
                    c.gone(label);
                }
                _ => {}
            }
            for &(label, k) in &list {
                assert_eq!(c.client_of(label), Some(k));
            }
            let probe = list.first().map_or(7, |(l, _)| l ^ 1);
            assert_eq!(c.client_of(probe), None);
        }
        for (label, _) in list.drain(..) {
            c.gone(label);
        }
        for k in 1..=6 {
            assert_eq!(c.own(k), 0);
        }
        for i in 0..N as u64 {
            assert!(c.give_within(TAG, 1_000_000 + i, 1).is_ok() || i as usize >= ROOTS);
        }
    }

    /// `adopt` takes the label of another table, whose low bits name the
    /// place: a place taken twice or out of the table is refused.
    #[test]
    fn adopt_takes_the_place_a_label_names() {
        let mut c = Clones::<8, 9>::new();
        let label = TAG | (3 << 9) | 5;
        assert_eq!(c.adopt(label, 1), Ok(()));
        assert_eq!(
            c.adopt(TAG | (4 << 9) | 5, 1),
            Err(Full),
            "place 5 is taken"
        );
        assert_eq!(c.adopt(TAG | 8, 1), Err(Full), "place 8 is out");
        assert_eq!(c.client_of(label), Some(1));
        assert_eq!(c.place_of(label), Some(5));
        c.gone(label);
        assert_eq!(c.adopt(TAG | (4 << 9) | 5, 1), Ok(()));
    }

    /// Mixing the two ways to fill a table is a mistake that debug builds
    /// stop.
    #[test]
    #[should_panic(expected = "give or adopt")]
    fn give_and_adopt_do_not_mix() {
        let mut c = Clones::<8, 9>::new();
        assert_eq!(c.adopt(TAG | 3, 1), Ok(()));
        let _ = c.give(TAG, 1);
    }
}
