// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The account of a window's buffers. The service never says a buffer is
//! free in a reply: it sends a bit of the window's channel (bit k for
//! buffer k). A buffer is free from the window's making; a POST takes it
//! out of the free ones, and only the bit brings it back, whether the frame
//! that showed its successor came or a later POST replaced it before a
//! frame took it. The library learns of a release in no other way, so a
//! POST of a buffer the account does not call free is refused here, before
//! the service is asked.
//!
//! A POST takes its buffer out of the free ones before the service is asked
//! (`take`), and gives it back if the service refused (`give_back`): the
//! bit of a later POST that replaced this one can then come at any moment
//! after the request goes, and never meets a buffer still counted free. The
//! whole account fits a `u32` (`raw`, `from_raw`) so that the layer keeps
//! it in one atomic word and updates it with a compare-and-swap.

use crate::errno::{EBUSY, EINVAL};
use crate::layout::{BITS, BUFFERS_MAX};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buffers {
    count: u32,
    free: u32,
    /// The bits that came and no `take_pending` reported yet.
    pending: u32,
}

impl Buffers {
    /// The account of a window of `count` buffers (1 to 3), all free.
    pub const fn new(count: usize) -> Buffers {
        assert!(count >= 1 && count <= BUFFERS_MAX);
        Buffers {
            count: count as u32,
            free: (1 << count) - 1,
            pending: 0,
        }
    }

    /// The free buffers as a mask, bit k for buffer k.
    pub const fn free(&self) -> u32 {
        self.free
    }

    /// Whether POST of `buffer` may go to the service: EINVAL for a number
    /// the window has not, EBUSY for a buffer that is not free.
    pub const fn check(&self, buffer: u32) -> Result<(), i32> {
        if buffer >= self.count {
            Err(EINVAL)
        } else if self.free & (1 << buffer) == 0 {
            Err(EBUSY)
        } else {
            Ok(())
        }
    }

    /// `buffer` goes to the service: it is not free until its bit comes.
    /// The errors are `check`'s, and nothing changes with one.
    pub fn take(&mut self, buffer: u32) -> Result<(), i32> {
        self.check(buffer)?;
        self.free &= !(1 << buffer);
        Ok(())
    }

    /// The service refused the POST of `buffer`: it is free again.
    pub fn give_back(&mut self, buffer: u32) {
        if buffer < self.count {
            self.free |= 1 << buffer;
        }
    }

    /// The account in one word: the count, the free buffers, the bits that
    /// wait to be taken.
    pub const fn raw(&self) -> u32 {
        self.count | self.free << 4 | self.pending << 8
    }

    /// The account of a word `raw` gave; None for any other word.
    pub const fn from_raw(word: u32) -> Option<Buffers> {
        let count = word & 0xf;
        let free = word >> 4 & 0xf;
        let pending = word >> 8 & 0xf;
        if word >> 12 != 0 || count < 1 || count > BUFFERS_MAX as u32 || free >> count != 0 {
            return None;
        }
        Some(Buffers {
            count,
            free,
            pending,
        })
    }

    /// Bits of the channel came: the buffers they name are free, and the
    /// bits wait for `take_pending`. Bits outside the window's buffers and
    /// the events bit are dropped.
    pub fn bits(&mut self, bits: u64) {
        let bits = (bits & u64::from(BITS)) as u32;
        self.free |= bits & ((1 << self.count) - 1);
        self.pending |= bits;
    }

    /// The bits that came since the last call, once.
    pub fn take_pending(&mut self) -> u32 {
        core::mem::take(&mut self.pending)
    }

    /// Whether `take_pending` would give something.
    pub const fn has_pending(&self) -> bool {
        self.pending != 0
    }
}

/// Whether `mask` is a wait for buffers of a window of `count` buffers: not
/// empty, and no bit past the buffers (the events bit among them).
pub const fn mask_ok(mask: u32, count: u32) -> bool {
    mask != 0 && count <= BUFFERS_MAX as u32 && mask & !((1u32 << count) - 1) == 0
}

/// Whether a drain of the window's channel (by `post`, outside the wait)
/// sends the wake: it took `taken` notifications of any kind (the service's
/// bits, the timer's expiry, an earlier wake) and a thread waits. The waiter
/// may have set its timer or be about to block on exactly what was taken, so
/// anything taken wakes it once; it looks again at the account and at its
/// time.
pub const fn should_wake(taken: usize, waiting: bool) -> bool {
    taken > 0 && waiting
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::EVENTS;

    #[test]
    fn a_mask_names_buffers_of_the_window_only() {
        assert!(mask_ok(0b1, 1) && mask_ok(0b101, 3) && mask_ok(0b11, 2));
        assert!(!mask_ok(0, 2));
        assert!(!mask_ok(0b100, 2));
        assert!(!mask_ok(crate::layout::EVENTS, 3));
        assert!(!mask_ok(0b1, 4));
    }

    #[test]
    fn all_buffers_are_free_at_the_start() {
        assert_eq!(Buffers::new(1).free(), 0b1);
        assert_eq!(Buffers::new(2).free(), 0b11);
        assert_eq!(Buffers::new(3).free(), 0b111);
    }

    #[test]
    fn bit_k_frees_only_buffer_k() {
        for k in 0..3u32 {
            let mut b = Buffers::new(3);
            for n in 0..3 {
                b.take(n).unwrap();
            }
            assert_eq!(b.free(), 0);
            b.bits(1 << k);
            assert_eq!(b.free(), 1 << k, "bit {k}");
            for n in 0..3u32 {
                assert_eq!(b.check(n), if n == k { Ok(()) } else { Err(EBUSY) });
            }
        }
    }

    #[test]
    fn a_post_of_a_posted_buffer_is_busy_without_a_call() {
        let mut b = Buffers::new(2);
        assert_eq!(b.check(0), Ok(()));
        b.take(0).unwrap();
        assert_eq!(b.check(0), Err(EBUSY));
        assert_eq!(b.check(1), Ok(()));
        assert_eq!(b.check(2), Err(EINVAL));
    }

    /// POST 0, then POST 1 before a frame took 0: the service frees 0 at
    /// once and says so by its bit. Until the bit the account keeps 0 out.
    #[test]
    fn the_replaced_buffer_is_free_by_its_bit_alone() {
        let mut b = Buffers::new(2);
        b.take(0).unwrap();
        b.take(1).unwrap();
        assert_eq!(b.free(), 0);
        assert_eq!(b.check(0), Err(EBUSY));
        b.bits(1);
        assert_eq!(b.free(), 1);
        assert_eq!(b.check(0), Ok(()));
        assert_eq!(b.check(1), Err(EBUSY));
    }

    #[test]
    fn the_events_bit_frees_nothing_and_waits_to_be_taken() {
        let mut b = Buffers::new(2);
        b.take(0).unwrap();
        b.bits(u64::from(EVENTS));
        assert_eq!(b.free(), 0b10);
        assert!(b.has_pending());
        assert_eq!(b.take_pending(), EVENTS);
        assert_eq!(b.take_pending(), 0);
    }

    #[test]
    fn bits_of_buffers_the_window_lacks_are_dropped() {
        let mut b = Buffers::new(1);
        b.bits(0b110);
        assert_eq!(b.free(), 0b1);
        b.bits(0xffff_0000);
        assert_eq!(b.take_pending(), 0b110);
    }

    #[test]
    fn pending_bits_accumulate() {
        let mut b = Buffers::new(3);
        b.take(0).unwrap();
        b.bits(1);
        b.bits(u64::from(EVENTS));
        assert_eq!(b.take_pending(), 1 | EVENTS);
    }

    #[test]
    fn a_refused_post_gives_the_buffer_back_and_a_taken_one_is_busy() {
        let mut b = Buffers::new(2);
        assert_eq!(b.take(1), Ok(()));
        assert_eq!(b.take(1), Err(EBUSY));
        assert_eq!(b.take(2), Err(EINVAL));
        assert_eq!(b.free(), 0b01);
        b.give_back(1);
        assert_eq!(b.free(), 0b11);
        // A bit that comes between the request and the give-back cannot be
        // lost: the buffer was out of the free ones when it came.
        b.take(0).unwrap();
        b.bits(1);
        assert_eq!(b.free(), 0b11);
    }

    #[test]
    fn the_account_round_trips_through_its_word() {
        let mut b = Buffers::new(3);
        b.take(2).unwrap();
        b.bits(u64::from(EVENTS));
        let word = b.raw();
        assert_eq!(Buffers::from_raw(word), Some(b));
        assert_eq!(Buffers::from_raw(0), None);
        assert_eq!(Buffers::from_raw(4), None);
        assert_eq!(Buffers::from_raw(1 | 0b10 << 4), None);
        assert_eq!(Buffers::from_raw(1 | 1 << 12), None);
    }

    /// `post` takes the bits that wait on the channel before and after its
    /// request and keeps them: the next `wait` returns them at once, and
    /// each is returned once.
    #[test]
    fn the_bit_a_post_drained_is_returned_by_the_next_wait_once() {
        let mut b = Buffers::new(2);
        b.take(0).unwrap();
        b.take(1).unwrap();
        // The service freed buffer 0 (replaced by the post of 1) before it
        // replied: the account has it free when the post returns.
        b.bits(1);
        assert_eq!(b.free(), 0b01);
        assert!(b.has_pending());
        // The wait returns the bit now, without a receive, and only once.
        assert_eq!(b.take_pending(), 1);
        assert_eq!(b.take_pending(), 0);
        assert_eq!(b.free(), 0b01);
    }

    #[test]
    fn the_events_bit_a_post_drained_is_returned_by_the_next_wait() {
        let mut b = Buffers::new(2);
        b.take(0).unwrap();
        b.bits(u64::from(EVENTS));
        assert_eq!(b.free(), 0b10);
        assert_eq!(b.take_pending(), EVENTS);
        // The library's own wake bit and the kernel's are no service bits.
        b.bits(1 << 32);
        b.bits(1 << 63);
        assert_eq!(b.take_pending(), 0);
        assert!(!b.has_pending());
    }

    #[test]
    fn a_bit_is_returned_once_even_when_it_came_twice_before_the_wait() {
        let mut b = Buffers::new(2);
        b.take(0).unwrap();
        b.bits(1);
        b.bits(1);
        assert_eq!(b.take_pending(), 1);
        assert_eq!(b.take_pending(), 0);
    }

    #[test]
    fn a_drain_that_took_anything_wakes_a_waiter() {
        // Scenario A: the poster took the timer's expiry (no service bit),
        // and the waiter is about to block with no timer.
        assert!(should_wake(1, true));
        // Scenario B: the second poster took the first one's wake.
        assert!(should_wake(1, true));
        // Service bits, with several notifications.
        assert!(should_wake(3, true));
        // Nothing taken, or nobody waits: no wake.
        assert!(!should_wake(0, true));
        assert!(!should_wake(2, false));
        assert!(!should_wake(0, false));
    }

    /// The sequence the probe met: the frame of a post ended before the post
    /// returned, so the post's drain took the bit. The mask says the buffer
    /// is free at once, and the bit still waits for the next wait: a program
    /// that looks at the mask alone leaves it uncollected, and one that waits
    /// first gets it.
    #[test]
    fn a_bit_taken_by_a_post_makes_the_mask_free_and_still_waits_for_a_wait() {
        let mut b = Buffers::new(2);
        b.take(0).unwrap();
        b.take(1).unwrap();
        b.bits(1);
        assert_eq!(b.free() & 1, 1);
        assert!(b.has_pending());
        assert_eq!(b.take_pending() & 1, 1);
        assert!(!b.has_pending());
        assert_eq!(b.free() & 1, 1);
    }

    /// Two buffers through the probe's whole sequence: the buffer on the
    /// screen stays out of the free ones until a later post replaces it, so
    /// the mask is never "both" after the first post.
    #[test]
    fn the_buffer_on_the_screen_stays_out_of_the_free_mask() {
        let mut b = Buffers::new(2);
        b.take(0).unwrap();
        assert_eq!(b.free(), 0b10);
        b.take(1).unwrap();
        b.bits(0b01); // the frame of buffer 1 ended: buffer 0 is free
        assert_eq!(b.free(), 0b01);
        b.take(0).unwrap();
        b.bits(0b10); // the frame of buffer 0 ended: buffer 1 is free
        assert_eq!(b.free(), 0b10);
        // Signals and forks change nothing of the account: the same mask.
        assert_eq!(b.take_pending(), 0b11);
        assert_eq!(b.free(), 0b10);
    }
}
