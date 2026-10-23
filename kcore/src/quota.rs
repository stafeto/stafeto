// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The memory quota of a process (spec 7.5): the limit its parent gave it,
//! the bytes of kernel memory charged to it, and the bytes that went back
//! to the parent. A charge that does not fit is NO_MEMORY; everything is
//! O(1). The quota goes back in two parts: what is free when the process
//! has given back all it can (`return_free`), and the rest when its shell,
//! the last thing charged to it, goes (`return_rest`). Together they make
//! the limit, and neither comes before the memory is free.

use abi::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    limit: u64,
    used: u64,
    returned: u64,
    /// The free part went back: nothing is charged from then on.
    closed: bool,
}

impl Account {
    /// A quota of `limit` bytes with nothing charged.
    pub const fn new(limit: u64) -> Account {
        Account {
            limit,
            used: 0,
            returned: 0,
            closed: false,
        }
    }

    /// The quota the parent gave.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes charged and not refunded.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Bytes that went back to the parent.
    pub fn returned(&self) -> u64 {
        self.returned
    }

    /// Charges `bytes`: NO_MEMORY when they do not fit in what is left of
    /// the quota, or once the free part went back.
    pub fn charge(&mut self, bytes: u64) -> Result<(), Error> {
        match self.used.checked_add(bytes) {
            Some(used) if !self.closed && used <= self.limit - self.returned => {
                self.used = used;
                Ok(())
            }
            _ => Err(Error::NoMemory),
        }
    }

    /// Gives back `bytes` that a charge took.
    pub fn refund(&mut self, bytes: u64) {
        self.used = self
            .used
            .checked_sub(bytes)
            .expect("a refund of more than the quota holds");
    }

    /// The first part back to the parent: everything not charged now. The
    /// quota takes no charge afterwards; what is charged comes back with
    /// `return_rest`. Every later call returns 0, refunds or not: the
    /// refunds belong to the rest.
    pub fn return_free(&mut self) -> u64 {
        if self.closed {
            return 0;
        }
        let free = self.limit - self.returned - self.used;
        self.returned += free;
        self.closed = true;
        free
    }

    /// The rest back to the parent, when the last charge was refunded: the
    /// two parts add up to the limit.
    pub fn return_rest(&mut self) -> u64 {
        assert!(
            self.used == 0,
            "the rest of a quota goes back while {} bytes are charged",
            self.used
        );
        let rest = self.limit - self.returned;
        self.returned = self.limit;
        self.closed = true;
        rest
    }
}

/// A share of a process (spec 7.5): a count of thread numbers or of timer
/// places its creator gave it, what is charged to it, and what went back to
/// the creator, in two parts as `Account` has them. A charge that does not
/// fit is LIMIT_REACHED. The counts are kept in 16 bits, so that two shares
/// fit what a process shell has left of its page; the limit may be up to
/// `Share::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    limit: u16,
    used: u16,
    returned: u16,
    closed: bool,
}

impl Share {
    /// The largest count a share holds.
    pub const MAX: u32 = u16::MAX as u32;

    /// A share of `limit`, at most `MAX`, with nothing charged.
    pub const fn new(limit: u32) -> Share {
        assert!(limit <= Self::MAX, "a share above what 16 bits hold");
        Share {
            limit: limit as u16,
            used: 0,
            returned: 0,
            closed: false,
        }
    }

    /// The count the creator gave.
    pub fn limit(&self) -> u32 {
        self.limit.into()
    }

    /// The count charged and not refunded.
    pub fn used(&self) -> u32 {
        self.used.into()
    }

    /// The count that went back to the creator.
    pub fn returned(&self) -> u32 {
        self.returned.into()
    }

    /// Charges `n`: LIMIT_REACHED when they do not fit in what is left of
    /// the share, or once the free part went back.
    pub fn charge(&mut self, n: u32) -> Result<(), Error> {
        let used = u32::from(self.used) + n.min(Self::MAX + 1);
        if !self.closed && used <= u32::from(self.limit - self.returned) {
            self.used = used as u16;
            Ok(())
        } else {
            Err(Error::LimitReached)
        }
    }

    /// Gives back `n` that a charge took.
    pub fn refund(&mut self, n: u32) {
        self.used = u32::from(self.used)
            .checked_sub(n)
            .expect("a refund of more than the share holds") as u16;
    }

    /// The first part back to the creator, as `Account::return_free`.
    pub fn return_free(&mut self) -> u32 {
        if self.closed {
            return 0;
        }
        let free = self.limit - self.returned - self.used;
        self.returned += free;
        self.closed = true;
        free.into()
    }

    /// The rest back to the creator, as `Account::return_rest`: stops
    /// while a number or a place is still charged.
    pub fn return_rest(&mut self) -> u32 {
        assert!(
            self.used == 0,
            "the rest of a share goes back while {} are charged",
            self.used
        );
        let rest = self.limit - self.returned;
        self.returned = self.limit;
        self.closed = true;
        rest.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;

    #[test]
    fn charge_over_the_limit_is_no_memory() {
        let mut a = Account::new(64 * KIB);
        assert_eq!(a.charge(60 * KIB), Ok(()));
        assert_eq!(a.charge(4 * KIB + 1), Err(Error::NoMemory));
        assert_eq!(a.used(), 60 * KIB);
        assert_eq!(a.charge(4 * KIB), Ok(()));
        assert_eq!(a.charge(1), Err(Error::NoMemory));
        assert_eq!(a.charge(u64::MAX), Err(Error::NoMemory));
        a.refund(8 * KIB);
        assert_eq!((a.limit(), a.used(), a.returned()), (64 * KIB, 56 * KIB, 0));
        assert_eq!(a.charge(8 * KIB), Ok(()));
    }

    #[test]
    fn quota_comes_back_in_two_parts_and_adds_up() {
        let mut a = Account::new(64 * KIB);
        a.charge(12 * KIB).unwrap();
        a.charge(512).unwrap();
        // The quota stage: everything free goes back at once.
        let first = a.return_free();
        assert_eq!(first, 64 * KIB - 12 * KIB - 512);
        assert_eq!(a.returned(), first);
        assert_eq!(a.return_free(), 0);
        // The shells go one by one; the last one brings the rest.
        a.refund(512);
        a.refund(12 * KIB);
        let rest = a.return_rest();
        assert_eq!(rest, 12 * KIB + 512);
        assert_eq!(first + rest, 64 * KIB);
        assert_eq!((a.used(), a.returned()), (0, 64 * KIB));
    }

    #[test]
    fn rest_comes_back_only_with_the_shell() {
        let mut a = Account::new(16 * KIB);
        a.charge(4 * KIB).unwrap();
        a.charge(512).unwrap();
        // The free part only: what is charged stays charged.
        assert_eq!(a.return_free(), 16 * KIB - 4 * KIB - 512);
        assert_eq!((a.used(), a.returned()), (4 * KIB + 512, 12 * KIB - 512));
        a.refund(4 * KIB);
        a.refund(512);
        assert_eq!(a.return_rest(), 4 * KIB + 512);
    }

    #[test]
    #[should_panic(expected = "while 512 bytes are charged")]
    fn rest_before_the_last_refund_stops() {
        let mut a = Account::new(16 * KIB);
        a.charge(4 * KIB).unwrap();
        a.charge(512).unwrap();
        a.return_free();
        a.refund(4 * KIB);
        // The shell's 512 bytes are still charged.
        a.return_rest();
    }

    #[test]
    fn nothing_is_charged_after_the_free_part_went_back() {
        let mut a = Account::new(16 * KIB);
        a.charge(8 * KIB).unwrap();
        a.return_free();
        a.refund(4 * KIB);
        assert_eq!(a.charge(1), Err(Error::NoMemory));
        assert_eq!(a.used(), 4 * KIB);
        // The refund does not reopen the first part: it comes with the rest.
        assert_eq!(a.return_free(), 0);
        a.refund(4 * KIB);
        assert_eq!(a.return_rest(), 8 * KIB);
    }

    #[test]
    #[should_panic(expected = "a refund of more than the quota holds")]
    fn refund_of_more_than_was_charged_stops() {
        let mut a = Account::new(16 * KIB);
        a.charge(4 * KIB).unwrap();
        a.refund(4 * KIB + 1);
    }

    #[test]
    fn share_charges_to_its_limit_with_limit_reached() {
        let mut s = Share::new(4);
        for _ in 0..4 {
            assert_eq!(s.charge(1), Ok(()));
        }
        assert_eq!(s.charge(1), Err(Error::LimitReached));
        assert_eq!(s.charge(u32::MAX), Err(Error::LimitReached));
        s.refund(1);
        assert_eq!(s.charge(1), Ok(()));
        assert_eq!((s.limit(), s.used(), s.returned()), (4, 4, 0));
    }

    #[test]
    fn share_comes_back_in_two_parts_and_adds_up() {
        let mut s = Share::new(8);
        s.charge(3).unwrap();
        let first = s.return_free();
        assert_eq!(first, 5);
        assert_eq!(s.return_free(), 0);
        assert_eq!(s.charge(1), Err(Error::LimitReached));
        s.refund(3);
        let rest = s.return_rest();
        assert_eq!(rest, 3);
        assert_eq!((s.used(), s.returned()), (0, 8));
    }

    #[test]
    #[should_panic(expected = "while 1 are charged")]
    fn share_rest_before_the_last_refund_stops() {
        let mut s = Share::new(2);
        s.charge(1).unwrap();
        s.return_free();
        s.return_rest();
    }

    #[test]
    #[should_panic(expected = "a refund of more than the share holds")]
    fn share_refund_of_more_than_was_charged_stops() {
        let mut s = Share::new(2);
        s.charge(1).unwrap();
        s.refund(2);
    }
}
