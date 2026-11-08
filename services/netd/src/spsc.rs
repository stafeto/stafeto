// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rings between the switch thread and the stack thread of the service
//! (`switch.rs`): a ring of `u32` words with one writing thread and one
//! reading thread, no lock and no copy of frames. A word is the number of a
//! buffer of the device, with a length in its upper half when the ring
//! carries frames (`pack`, `unpack`). The indexes grow without wrapping to
//! the size, the ring holds `N` words, and a writer that finds it full is
//! told so (the rings of the service hold as many words as there are
//! buffers, so a push never fails there).

use core::sync::atomic::{AtomicU32, Ordering};

/// A ring of `N` words (a power of two): `push` from one thread, `pop`
/// from one other.
pub struct Spsc<const N: usize> {
    /// Words taken so far (written by the reader).
    head: AtomicU32,
    /// Words put so far (written by the writer).
    tail: AtomicU32,
    slots: [AtomicU32; N],
}

impl<const N: usize> Spsc<N> {
    pub const fn new() -> Spsc<N> {
        const { assert!(N.is_power_of_two() && N <= 1 << 16) };
        Spsc {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: [const { AtomicU32::new(0) }; N],
        }
    }

    /// Puts `word` in; false when the ring is full.
    pub fn push(&self, word: u32) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) as usize >= N {
            return false;
        }
        self.slots[tail as usize % N].store(word, Ordering::Relaxed);
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Takes the oldest word out.
    pub fn pop(&self) -> Option<u32> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let word = self.slots[head as usize % N].load(Ordering::Relaxed);
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(word)
    }

    /// How many words wait. Exact for the reader (the writer only adds),
    /// and for the writer a bound from above.
    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail.wrapping_sub(head) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<const N: usize> Default for Spsc<N> {
    fn default() -> Spsc<N> {
        Spsc::new()
    }
}

/// A buffer number and the length of its frame (or of what the ring
/// carries) in one word.
pub const fn pack(buffer: u16, length: u16) -> u32 {
    buffer as u32 | (length as u32) << 16
}

/// The buffer number and the length of a word `pack` made.
pub const fn unpack(word: u32) -> (u16, u16) {
    (word as u16, (word >> 16) as u16)
}

/// The bit of the length of a frame (a frame is at most 1514 bytes) that says
/// the sum of its TCP segment is good (received: the device checked it, or
/// the frame never left the service's memory) or partial (sent: the switch
/// completes it).
pub const SUM_BIT: u16 = 1 << 15;

/// `pack` for a frame, with `sum` in the bit above its length.
pub const fn pack_frame(buffer: u16, length: u16, sum: bool) -> u32 {
    pack(buffer, length | if sum { SUM_BIT } else { 0 })
}

/// The buffer number, the length and the sum bit of a word `pack_frame` made.
pub const fn unpack_frame(word: u32) -> (u16, u16, bool) {
    let (buffer, length) = unpack(word);
    (buffer, length & !SUM_BIT, length & SUM_BIT != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_come_out_in_the_order_they_went_in() {
        let ring = Spsc::<4>::new();
        assert!(ring.is_empty());
        for w in 1..=3 {
            assert!(ring.push(w));
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn a_full_ring_refuses_and_keeps_its_words() {
        let ring = Spsc::<4>::new();
        for w in 0..4 {
            assert!(ring.push(w));
        }
        assert!(!ring.push(9));
        assert_eq!(ring.pop(), Some(0));
        assert!(ring.push(9));
        let rest: Vec<u32> = core::iter::from_fn(|| ring.pop()).collect();
        assert_eq!(rest, [1, 2, 3, 9]);
    }

    #[test]
    fn the_indexes_wrap_past_the_size_and_past_u32() {
        let ring = Spsc::<4>::new();
        ring.head.store(u32::MAX - 1, Ordering::Relaxed);
        ring.tail.store(u32::MAX - 1, Ordering::Relaxed);
        for round in 0..10u32 {
            assert!(ring.push(round));
            assert!(ring.push(round + 100));
            assert_eq!(ring.len(), 2);
            assert_eq!(ring.pop(), Some(round));
            assert_eq!(ring.pop(), Some(round + 100));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn a_word_carries_a_buffer_and_a_length() {
        assert_eq!(unpack(pack(511, 1514)), (511, 1514));
        assert_eq!(unpack(pack(0, 0)), (0, 0));
    }

    #[test]
    fn a_frame_word_carries_the_sum_bit_apart_from_the_length() {
        for sum in [false, true] {
            for len in [0u16, 1, 60, 1514, 0x7FFF] {
                assert_eq!(unpack_frame(pack_frame(511, len, sum)), (511, len, sum));
            }
        }
        assert_eq!(pack_frame(5, 60, false), pack(5, 60));
        assert_eq!(unpack_frame(pack(5, 60)), (5, 60, false));
        assert_eq!(unpack(pack_frame(5, 60, true)).1, 60 | SUM_BIT);
    }

    #[test]
    fn one_writer_and_one_reader_lose_nothing() {
        use std::sync::Arc;
        let ring = Arc::new(Spsc::<64>::new());
        let writer = {
            let ring = ring.clone();
            std::thread::spawn(move || {
                for w in 0..20_000u32 {
                    while !ring.push(w) {
                        std::hint::spin_loop();
                    }
                }
            })
        };
        let mut next = 0;
        while next < 20_000 {
            if let Some(w) = ring.pop() {
                assert_eq!(w, next);
                next += 1;
            }
        }
        writer.join().unwrap();
    }
}
