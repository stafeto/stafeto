// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The buffers of receiving the stack reads in place when the device merges the segments it
//! receives. The ring of the device is then 64 chains (`virtio_net::books::TAILS`), each with a
//! tail of 64 KiB, and a chain the stack held would shorten the ring the device sees. The switch
//! copies a frame for the stack out of the chain into a buffer of this pool, gives the chain back
//! to the device at once, and the stack returns the pool's buffer through `rx_back`. The pool is
//! the buffers of 2 KiB of the object `net` that no chain uses: `TAILS` to `RX_BUFFERS` - 1.

use crate::ring::RX_BUFFERS;

/// The free buffers of the pool, and which ones the stack holds.
pub struct Pool {
    free: [u16; RX_BUFFERS],
    len: usize,
    /// The lane (plus one) of the instance that holds each buffer, 0 for none: a buffer comes
    /// back only from the lane that was given it.
    held: [u8; RX_BUFFERS],
    from: usize,
    to: usize,
}

impl Pool {
    /// A pool with no buffers.
    pub const fn empty() -> Pool {
        Pool {
            free: [0; RX_BUFFERS],
            len: 0,
            held: [0; RX_BUFFERS],
            from: 0,
            to: 0,
        }
    }

    /// The pool of the buffers `from` to `to` - 1, all free.
    pub fn filled(from: usize, to: usize) -> Pool {
        let mut pool = Pool::empty();
        let to = to.min(RX_BUFFERS);
        pool.from = from.min(to);
        pool.to = to;
        for n in pool.from..to {
            pool.free[pool.len] = n as u16;
            pool.len += 1;
        }
        pool
    }

    /// The free buffers.
    pub fn free(&self) -> usize {
        self.len
    }

    /// A free buffer, now the stack's of lane `lane`; None when the stack holds them all.
    pub fn take(&mut self, lane: usize) -> Option<u16> {
        self.len = self.len.checked_sub(1)?;
        let n = self.free[self.len];
        self.held[usize::from(n)] = lane as u8 + 1;
        Some(n)
    }

    /// Lane `lane` gave buffer `n` back. False, and nothing changes, for a number that is no
    /// buffer of the pool or one that lane does not hold.
    pub fn put(&mut self, n: u16, lane: usize) -> bool {
        let at = usize::from(n);
        if !(self.from..self.to).contains(&at) || self.held[at] != lane as u8 + 1 {
            return false;
        }
        self.held[at] = 0;
        self.free[self.len] = n;
        self.len += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pool_holds_the_buffers_no_chain_uses() {
        let mut pool = Pool::filled(64, RX_BUFFERS);
        assert_eq!(pool.free(), RX_BUFFERS - 64);
        let mut seen = [false; RX_BUFFERS];
        while let Some(n) = pool.take(0) {
            assert!((64..RX_BUFFERS).contains(&usize::from(n)));
            assert!(!seen[usize::from(n)], "{n} twice");
            seen[usize::from(n)] = true;
        }
        assert_eq!(pool.free(), 0);
        assert_eq!(pool.take(0), None);
    }

    #[test]
    fn a_buffer_comes_back_once_and_only_from_the_pool() {
        let mut pool = Pool::filled(64, RX_BUFFERS);
        let n = pool.take(0).unwrap();
        let other = if n == 64 { 65 } else { 64 };
        assert!(!pool.put(other, 0), "a buffer the stack does not hold");
        let free = pool.free();
        assert!(pool.put(n, 0));
        assert_eq!(pool.free(), free + 1);
        assert!(!pool.put(n, 0), "twice");
        // A chain's head, a number past the object, and a buffer of sending.
        for bad in [0, 63, RX_BUFFERS as u16, RX_BUFFERS as u16 + 5] {
            assert!(!pool.put(bad, 0), "{bad}");
        }
        assert_eq!(pool.free(), RX_BUFFERS - 64);
    }

    #[test]
    fn a_buffer_comes_back_only_from_the_lane_that_was_given_it() {
        let mut pool = Pool::filled(64, RX_BUFFERS);
        let n = pool.take(2).unwrap();
        assert!(!pool.put(n, 0), "another lane's buffer");
        assert!(!pool.put(n, 3));
        assert!(pool.put(n, 2));
    }

    #[test]
    fn a_taken_buffer_is_taken_again_after_its_return() {
        let mut pool = Pool::filled(64, 66);
        let (a, b) = (pool.take(0).unwrap(), pool.take(0).unwrap());
        assert_ne!(a, b);
        assert_eq!(pool.take(0), None);
        assert!(pool.put(a, 0));
        assert_eq!(pool.take(0), Some(a));
    }
}
