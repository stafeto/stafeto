// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The system table of thread numbers and the tokens of replies (spec 6.1,
//! 7.8). A thread takes a number, an entry of the table, when it is made,
//! and gives it back when it goes. The entry names the thread and counts
//! the requests of the threads on its number that a service accepted; the
//! count stays in the entry when the thread goes, and the next thread on
//! the number goes on from it. A token names one accepted request: the
//! number in bits 0-15 and the count in bits 16-63, as a handle carries its
//! generation (spec 5.1). So a token is given out at most once in the life
//! of the system, and since the first count is 1, no token is 0. A thread
//! that ends while it waits for a reply marks its entry: the token of that
//! request gets PEER_CLOSED from then on, until the number goes to another
//! thread (spec 6.8). An entry whose count reached MAX_COUNT retires when
//! its thread goes. Numbers never handed out come first, in order, then
//! those given back, in the order they came back. Every operation takes
//! constant time, nothing allocates, and a new table is all zeros (spec
//! 7.8).

use abi::Error;
use core::ptr::NonNull;

/// Bits of a token for the number; the count takes the rest (spec 6.1).
pub const INDEX_BITS: u32 = 16;
/// The last count of an entry: the thread on it gets BAD_STATE from send,
/// and the entry retires when the thread goes.
pub const MAX_COUNT: u64 = (1 << (u64::BITS - INDEX_BITS)) - 1;

/// The bit of an entry's word that says it names a thread.
const TAKEN: u64 = 1 << 63;
/// The bit of an entry's word that says its thread ended while it waited
/// for the reply to its last accepted request.
const DEAD: u64 = 1 << 62;
/// The end of the list of numbers given back, which names number i as
/// i + 1.
const NONE: usize = 0;

/// What an entry holds besides its word: the thread while the number is
/// taken, the next number given back while it is free (as i + 1, NONE at
/// the end); the word's TAKEN bit says which.
union Holder<T> {
    thread: NonNull<T>,
    next: usize,
}

impl<T> Clone for Holder<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Holder<T> {}

/// An entry of the table, 16 bytes: its holder, and a word with the count
/// in bits 0-47, DEAD and TAKEN.
struct Entry<T> {
    holder: Holder<T>,
    word: u64,
}

/// The table of `N` thread numbers, at most 2^16 (spec 7.8), each naming
/// a thread `T` while it is taken.
pub struct Table<T, const N: usize> {
    entries: [Entry<T>; N],
    /// Numbers handed out at least once: those below it.
    used: usize,
    /// Numbers given back, from the first to come back to the last, as
    /// i + 1, linked through their holders.
    first_free: usize,
    last_free: usize,
    /// Numbers taken now, and numbers retired.
    taken: usize,
    retired: usize,
    /// The count of numbers never handed out, for tests that start near
    /// the end; the kernel's start at 0.
    #[cfg(test)]
    first_count: u64,
}

// SAFETY: the table holds pointers to threads the kernel hands it, and
// moving it moves them along, as moving the threads would.
unsafe impl<T: Send, const N: usize> Send for Table<T, N> {}

impl<T, const N: usize> Table<T, N> {
    /// A table with every number free and every count at 0.
    pub const fn new() -> Self {
        const { assert!(N <= 1 << INDEX_BITS, "a number takes 16 bits") };
        Table {
            entries: [const {
                Entry {
                    holder: Holder { next: NONE },
                    word: 0,
                }
            }; N],
            used: 0,
            first_free: NONE,
            last_free: NONE,
            taken: 0,
            retired: 0,
            #[cfg(test)]
            first_count: 0,
        }
    }

    /// A table whose numbers never handed out start at `count`, so tests
    /// reach the end of a count in a few steps.
    #[cfg(test)]
    fn with_first_count(count: u64) -> Self {
        let mut t = Self::new();
        t.first_count = count;
        t
    }

    /// Numbers free now: those never handed out and those given back, but
    /// not the retired ones.
    pub fn available(&self) -> usize {
        N - self.taken - self.retired
    }

    /// A number for `thread` (thread_create, spec 8, 11): the lowest never
    /// handed out, or else the number given back first, whose mark of a
    /// dead thread goes. LIMIT_REACHED when no number is free.
    pub fn alloc(&mut self, thread: NonNull<T>) -> Result<u16, Error> {
        let index = if self.used < N {
            self.used += 1;
            #[cfg(test)]
            {
                self.entries[self.used - 1].word = self.first_count;
            }
            self.used - 1
        } else if self.first_free != NONE {
            let i = self.first_free;
            // SAFETY: a number given back holds the next one.
            self.first_free = unsafe { self.entries[i - 1].holder.next };
            if self.first_free == NONE {
                self.last_free = NONE;
            }
            i - 1
        } else {
            return Err(Error::LimitReached);
        };
        let e = &mut self.entries[index];
        e.holder = Holder { thread };
        e.word = e.word & MAX_COUNT | TAKEN;
        self.taken += 1;
        Ok(index as u16)
    }

    /// The taken entry `index`.
    fn taken(&self, index: u16) -> &Entry<T> {
        let e = &self.entries[usize::from(index)];
        assert!(e.word & TAKEN != 0, "a free thread number is used");
        e
    }

    /// Number `index` comes back as its thread goes (spec 7.7), with its
    /// count and its mark of a dead thread: at the end of the list of
    /// numbers given back, or, with the count at MAX_COUNT, retired for good.
    pub fn free(&mut self, index: u16) {
        self.taken(index);
        let i = usize::from(index);
        let e = &mut self.entries[i];
        e.word &= !TAKEN;
        e.holder = Holder { next: NONE };
        self.taken -= 1;
        if e.word & MAX_COUNT == MAX_COUNT {
            self.retired += 1;
            return;
        }
        match self.last_free {
            NONE => self.first_free = i + 1,
            last => self.entries[last - 1].holder = Holder { next: i + 1 },
        }
        self.last_free = i + 1;
    }

    /// BAD_STATE when the thread on `index` has no count left for another
    /// request (send, spec 6.1): nothing of the call happens then.
    pub fn check_count(&self, index: u16) -> Result<(), Error> {
        if self.taken(index).word & MAX_COUNT == MAX_COUNT {
            Err(Error::BadState)
        } else {
            Ok(())
        }
    }

    /// A service accepts a request of the thread on `index` (spec 6.1):
    /// the count grows by 1, and the token of the request carries it.
    /// `check_count` let the request in.
    pub fn accept(&mut self, index: u16) -> u64 {
        self.check_count(index)
            .expect("a thread with no count left sent a request");
        let e = &mut self.entries[usize::from(index)];
        e.word += 1;
        (e.word & MAX_COUNT) << INDEX_BITS | u64::from(index)
    }

    /// The thread on `index` ended while it waited for the reply to its
    /// last accepted request (sched::exit, spec 6.8): the entry keeps a
    /// mark until `alloc` hands the number out again.
    pub fn mark_dead(&mut self, index: u16) {
        self.taken(index);
        self.entries[usize::from(index)].word |= DEAD;
    }

    /// The thread whose accepted request `token` names (reply, spec 6.1):
    /// BAD_STATE for a number outside the table, for count 0, and for a
    /// count other than the last its entry gave; PEER_CLOSED for the last
    /// count of an entry whose thread ended while it waited for this reply
    /// (`mark_dead`), however often it is asked; BAD_STATE for a free
    /// number otherwise.
    pub fn check(&self, token: u64) -> Result<NonNull<T>, Error> {
        let index = (token & ((1 << INDEX_BITS) - 1)) as usize;
        let count = token >> INDEX_BITS;
        let e = self.entries.get(index).ok_or(Error::BadState)?;
        if count == 0 || e.word & MAX_COUNT != count {
            return Err(Error::BadState);
        }
        if e.word & DEAD != 0 {
            return Err(Error::PeerClosed);
        }
        if e.word & TAKEN == 0 {
            return Err(Error::BadState);
        }
        // SAFETY: a taken entry holds its thread.
        Ok(unsafe { e.holder.thread })
    }

    /// Moves the count of the taken number `index` forward to `count`, at
    /// most MAX_COUNT, so that the kernel's tests reach the end of a count
    /// (spec 15.2); a token is still given out once.
    pub fn skip_to(&mut self, index: u16, count: u64) {
        let word = self.taken(index).word;
        assert!(
            (word & MAX_COUNT..=MAX_COUNT).contains(&count),
            "a count goes back or past its end"
        );
        self.entries[usize::from(index)].word = TAKEN | count;
    }
}

impl<T, const N: usize> Default for Table<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Threads as the table sees them: addresses it never reads.
    fn thread(n: usize) -> NonNull<u8> {
        NonNull::new((n + 1) as *mut u8).expect("not null")
    }

    #[test]
    fn entries_are_16_bytes() {
        assert_eq!(core::mem::size_of::<Entry<u8>>(), 16);
        assert_eq!(MAX_COUNT, (1 << 48) - 1);
        // A new table is all zeros.
        let t: Table<u8, 4> = Table::new();
        // SAFETY: the table is words and a union, every byte of them set.
        let bytes: [u8; core::mem::size_of::<Table<u8, 4>>()] = unsafe { core::mem::transmute(t) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    /// The first request a thread's number carries is count 1, so the
    /// token of number 0 is 1 << 16, and 0 is never a token (spec 6.1).
    #[test]
    fn token_zero_is_never_issued() {
        let mut t: Table<u8, 4> = Table::new();
        assert_eq!(t.alloc(thread(0)), Ok(0));
        assert_eq!(t.check(0), Err(Error::BadState));
        let token = t.accept(0);
        assert_eq!(token, 1 << INDEX_BITS);
        assert_eq!(t.check(token), Ok(thread(0)));
        assert_eq!(t.check(0), Err(Error::BadState));
    }

    /// A number given back keeps its count: the next thread on it goes on
    /// from there, and the tokens of the thread before stay bad.
    #[test]
    fn freed_index_keeps_its_counter() {
        let mut t: Table<u8, 1> = Table::new();
        assert_eq!(t.alloc(thread(0)), Ok(0));
        let old: Vec<u64> = (0..3).map(|_| t.accept(0)).collect();
        t.free(0);
        assert_eq!(t.check(old[2]), Err(Error::BadState));
        assert_eq!(t.alloc(thread(1)), Ok(0));
        let token = t.accept(0);
        assert_eq!(token >> INDEX_BITS, 4);
        assert_eq!(t.check(token), Ok(thread(1)));
        assert!(old.iter().all(|&o| t.check(o) == Err(Error::BadState)));
    }

    /// A thread that ends while it waits for its reply marks its number
    /// (spec 6.8): the token of that request gets PEER_CLOSED, however often
    /// it is tried, before and after the number comes back, and older
    /// tokens stay BAD_STATE. The next thread on the number clears the
    /// mark: until its first accepted request the token names it, a thread
    /// that waits for no reply, and then it is BAD_STATE.
    #[test]
    fn dead_mark_holds_until_the_index_is_reused() {
        let mut t: Table<u8, 1> = Table::new();
        assert_eq!(t.alloc(thread(0)), Ok(0));
        let old = t.accept(0);
        let last = t.accept(0);
        t.mark_dead(0);
        for _ in 0..2 {
            assert_eq!(t.check(last), Err(Error::PeerClosed));
        }
        assert_eq!(t.check(old), Err(Error::BadState));
        t.free(0);
        assert_eq!(t.check(last), Err(Error::PeerClosed));
        assert_eq!(t.check(old), Err(Error::BadState));
        assert_eq!(t.alloc(thread(1)), Ok(0));
        assert_eq!(t.check(last), Ok(thread(1)));
        let next = t.accept(0);
        assert_eq!(t.check(last), Err(Error::BadState));
        assert_eq!(t.check(next), Ok(thread(1)));
    }

    /// At MAX_COUNT the thread gets BAD_STATE for another request, its last
    /// token still works, and the number retires when the thread goes:
    /// never handed out again.
    #[test]
    fn index_retires_at_the_last_count() {
        let mut t: Table<u8, 2> = Table::with_first_count(MAX_COUNT - 2);
        assert_eq!(t.alloc(thread(0)), Ok(0));
        assert_eq!(t.check_count(0), Ok(()));
        t.accept(0);
        let last = t.accept(0);
        assert_eq!(last >> INDEX_BITS, MAX_COUNT);
        assert_eq!(t.check_count(0), Err(Error::BadState));
        assert_eq!(t.check(last), Ok(thread(0)));
        assert_eq!(t.available(), 1);
        t.free(0);
        assert_eq!(t.available(), 1);
        assert_eq!(t.alloc(thread(1)), Ok(1));
        assert_eq!(t.alloc(thread(2)), Err(Error::LimitReached));
        t.free(1);
        assert_eq!(t.alloc(thread(3)), Ok(1));
        assert_eq!(t.check(last), Err(Error::BadState));
        // The kernel's tests move a count to its end at once.
        t.skip_to(1, MAX_COUNT);
        assert_eq!(t.check_count(1), Err(Error::BadState));
    }

    /// Numbers never handed out come first, in order, then those given
    /// back in the order they came back; with none free, LIMIT_REACHED.
    #[test]
    fn index_limit_is_limit_reached() {
        let mut t: Table<u8, 4> = Table::new();
        assert_eq!(t.alloc(thread(0)), Ok(0));
        assert_eq!(t.alloc(thread(1)), Ok(1));
        t.free(1);
        t.free(0);
        assert_eq!(t.available(), 4);
        let order: Vec<_> = (0..5).map(|i| t.alloc(thread(i))).collect();
        assert_eq!(
            order,
            [Ok(2), Ok(3), Ok(1), Ok(0), Err(Error::LimitReached)]
        );
        assert_eq!(t.available(), 0);
        t.free(3);
        assert_eq!(t.alloc(thread(9)), Ok(3));
    }

    /// reply takes only the last token of a taken number (spec 6.1): a
    /// number outside the table or never handed out, a free one, count 0, a
    /// count before or after the last one are all BAD_STATE.
    #[test]
    fn stale_or_foreign_token_is_bad_state() {
        let mut t: Table<u8, 4> = Table::new();
        assert_eq!(t.alloc(thread(0)), Ok(0));
        assert_eq!(t.alloc(thread(1)), Ok(1));
        let first = t.accept(0);
        let second = t.accept(0);
        let other = t.accept(1);
        t.free(1);
        let bad = [
            first,
            second + (1 << INDEX_BITS),
            0,
            other,
            1 << INDEX_BITS | 2,
            1 << INDEX_BITS | 5,
            u64::MAX,
        ];
        for token in bad {
            assert_eq!(t.check(token), Err(Error::BadState), "{token:#x}");
        }
        assert_eq!(t.check(second), Ok(thread(0)));
    }

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// 100 000 random steps against a model on a table of 8 numbers:
    /// threads come and go and have requests accepted. Every token is new,
    /// and the last token of each live thread names it. An older token is
    /// bad, or it names the next thread on its number before that thread's
    /// first accepted request, which is waiting for no reply (spec 6.1).
    #[test]
    fn tokens_never_repeat() {
        let mut t: Table<u8, 8> = Table::new();
        let mut rng = Rng(0x7043_0000_5EED_0011);
        // The number and the last token of each live thread.
        let mut live: Vec<(usize, u16, Option<u64>)> = Vec::new();
        let mut seen = HashSet::new();
        let mut old = Vec::new();
        for step in 0..100_000 {
            match rng.below(3) {
                0 => match t.alloc(thread(step)) {
                    Ok(index) => live.push((step, index, None)),
                    Err(e) => assert_eq!((e, live.len()), (Error::LimitReached, 8)),
                },
                1 if !live.is_empty() => {
                    let (_, index, token) = live.swap_remove(rng.below(live.len() as u64) as usize);
                    old.extend(token);
                    t.free(index);
                }
                _ if !live.is_empty() => {
                    let k = rng.below(live.len() as u64) as usize;
                    let (_, index, token) = &mut live[k];
                    if t.check_count(*index).is_ok() {
                        old.extend(token.take());
                        let new = t.accept(*index);
                        assert!(seen.insert(new), "step {step}: token {new:#x} again");
                        *token = Some(new);
                    }
                }
                _ => {}
            }
            for &(n, _, token) in &live {
                if let Some(token) = token {
                    assert_eq!(t.check(token), Ok(thread(n)), "step {step}");
                }
            }
        }
        for token in old {
            if let Ok(p) = t.check(token) {
                let index = token & ((1 << INDEX_BITS) - 1);
                assert!(
                    live.iter().any(|&(n, i, last)| thread(n) == p
                        && u64::from(i) == index
                        && last.is_none()),
                    "an old token {token:#x} names a thread that had a request since"
                );
            }
        }
        assert!(seen.len() > 20_000);
    }
}
