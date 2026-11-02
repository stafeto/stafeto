// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the input service decides (spec 3, 3.6), apart from the device and
//! the calls it makes: who holds the focus (`focus`), the ring of the
//! focus's events (`ring`), and where its DMA object holds the queue and
//! the event buffers (`dma`). Everything here builds for the host too,
//! where `cargo test -p virtio-input` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod focus;
pub mod ring;

/// The service's DMA object (`dma`, 4 pages, contiguous and uncached): the
/// event queue takes the first QUEUE_PAGES, and the 64 buffers of 8 bytes
/// the device writes its events into lie in the page after them, at
/// `BUFFER_AT`. Uncached: no cache maintenance, only the barriers of the
/// queue.
pub mod dma {
    pub const PAGES: usize = 4;
    pub const PAGE: usize = virtio_mmio::PAGE;
    /// A queue of 64 entries with one descriptor each takes two pages: the
    /// descriptors (1,024 bytes) and the driver's ring (134) in one, the
    /// device's ring (518) in the other.
    pub const QUEUE_PAGES: usize = 2;
    /// The entries of the event queue (`eventq`); the device may have
    /// fewer in use, never more.
    pub const QUEUE_SIZE: usize = proto_input::RING;
    /// The page of the buffers.
    pub const BUFFER_PAGE: usize = QUEUE_PAGES;
    /// The bytes of one buffer: a `virtio_input_event`.
    pub const EVENT: usize = proto_input::EVENT_LEN;

    /// The offset in the page of the buffers of buffer `slot`.
    pub const fn buffer_at(slot: usize) -> usize {
        slot * EVENT
    }

    const _: () = assert!(QUEUE_SIZE.is_power_of_two());
    const _: () = assert!(QUEUE_SIZE * EVENT <= PAGE);
    const _: () = assert!(BUFFER_PAGE < PAGES);
    // The descriptors and the driver's ring, then the device's ring.
    const _: () = assert!(16 * QUEUE_SIZE + 2 * (3 + QUEUE_SIZE) <= PAGE);
    const _: () = assert!(2 * 3 + 8 * QUEUE_SIZE <= PAGE);
}

/// The Linux names of the config select of an input device (Virtio 1.2,
/// 5.8.5): the name string, and the bitmap of the event codes of a type.
pub mod config {
    pub const ID_NAME: u8 = 0x01;
    pub const EV_BITS: u8 = 0x11;
    /// Where the select, the sub-select and the size lie in the config
    /// space, and where the data of 128 bytes begins.
    pub const SELECT: usize = 0;
    pub const SUBSEL: usize = 1;
    pub const SIZE: usize = 2;
    pub const DATA: usize = 8;
    pub const DATA_MAX: usize = 128;

    /// How many keys a bitmap of key codes holds, and its first 64 codes
    /// as a word (bit i is code i), for the log.
    pub fn key_summary(bitmap: &[u8]) -> (u32, u64) {
        let count = bitmap.iter().map(|b| b.count_ones()).sum();
        let mut first = [0u8; 8];
        let n = bitmap.len().min(8);
        first[..n].copy_from_slice(&bitmap[..n]);
        (count, u64::from_le_bytes(first))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_summary_counts_keys_and_shows_the_first_codes() {
            // KEY_ESC (1) and KEY_A (30), and KEY_LEFT (105) beyond the word.
            let mut map = [0u8; 16];
            map[0] |= 1 << 1;
            map[3] |= 1 << 6;
            map[13] |= 1 << 1;
            assert_eq!(key_summary(&map), (3, (1 << 1) | (1 << 30)));
            assert_eq!(key_summary(&[]), (0, 0));
            assert_eq!(key_summary(&[0xFF; 3]), (24, 0xFF_FFFF));
        }
    }
}
