// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The shared buffers of the sessions (BUFFER, proto_net): a client's memory
//! object of `proto_net::BUFFER_SIZE` bytes that the service maps for the
//! session's life. Entry `i` of the table is mapped at its own address
//! (`dma::buffer_at` in the program); a session names the entry by its
//! index. An entry whose session went is retired: it stays taken until the
//! step that unmaps it lets it go, one unmap a step, and its generation
//! grows then.
//!
//! The service reads nothing that steers it from the buffer: the offset and
//! the length of a cell come in the request (`proto_net::cell_fits`), and
//! the bytes go through a raw pointer, a portion of `ring::BUFFER_PORTION`
//! at most in one request (`copy_portion`).

/// The entries of the table: sessions with a shared buffer at once.
pub const BUFFER_SESSIONS: usize = 64;

/// One entry: the session's label and the generation of the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    label: u64,
    generation: u32,
}

/// Why an entry is not given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The table is full, or the limit of `netd.conf` is reached.
    Full,
}

/// The table of the shared buffers.
pub struct Buffers {
    entries: [Entry; BUFFER_SESSIONS],
    /// The entries taken (mapped, or retired and not yet unmapped), a bit each.
    used: u64,
    /// The entries whose session went and that wait to be unmapped.
    retired: u64,
    /// The limit of `netd.conf` (`buffers N`).
    limit: u16,
}

impl Default for Buffers {
    fn default() -> Self {
        Buffers::new(BUFFER_SESSIONS as u16)
    }
}

impl Buffers {
    pub const fn new(limit: u16) -> Buffers {
        Buffers {
            entries: [Entry {
                label: 0,
                generation: 0,
            }; BUFFER_SESSIONS],
            used: 0,
            retired: 0,
            limit: if limit as usize > BUFFER_SESSIONS {
                BUFFER_SESSIONS as u16
            } else {
                limit
            },
        }
    }

    /// The entries taken now, retired ones among them.
    pub fn count(&self) -> u16 {
        self.used.count_ones() as u16
    }

    pub fn limit(&self) -> u16 {
        self.limit
    }

    /// A free entry for the session `label`, within the limit.
    pub fn give(&mut self, label: u64) -> Result<usize, Refusal> {
        if self.count() >= self.limit {
            return Err(Refusal::Full);
        }
        let free = !self.used;
        if free == 0 {
            return Err(Refusal::Full);
        }
        let i = free.trailing_zeros() as usize;
        self.used |= 1 << i;
        self.entries[i].label = label;
        Ok(i)
    }

    /// The entry `i` is free again at once (its map failed, or the service
    /// unmapped it in the step that called this): its generation grows.
    pub fn free(&mut self, i: usize) {
        if i >= BUFFER_SESSIONS || self.used & (1 << i) == 0 {
            return;
        }
        self.used &= !(1 << i);
        self.retired &= !(1 << i);
        let e = &mut self.entries[i];
        e.label = 0;
        e.generation = e.generation.wrapping_add(1);
    }

    /// The session of entry `i` went: the entry waits for a step to unmap it.
    pub fn retire(&mut self, i: usize) {
        if i < BUFFER_SESSIONS && self.used & (1 << i) != 0 {
            self.retired |= 1 << i;
        }
    }

    /// The first retired entry, which a step unmaps and frees.
    pub fn next_retired(&self) -> Option<usize> {
        (self.retired != 0).then(|| self.retired.trailing_zeros() as usize)
    }

    /// Whether the entry `i` belongs to the session `label` and is not retired.
    pub fn owned_by(&self, i: usize, label: u64) -> bool {
        i < BUFFER_SESSIONS
            && self.used & (1 << i) != 0
            && self.retired & (1 << i) == 0
            && self.entries[i].label == label
    }

    pub fn generation(&self, i: usize) -> u32 {
        self.entries[i % BUFFER_SESSIONS].generation
    }
}

/// Copies up to `portion` of `len` bytes through `window`, which moves bytes
/// from the source at offset `done` (up to `want` of them) and says how
/// many; it gives 0 when it has no room or no bytes. A ring has its free
/// space or its bytes in two windows at most, so the copy asks until the
/// portion is done or a window gives nothing. The bytes moved.
pub fn copy_portion(
    len: usize,
    portion: usize,
    mut window: impl FnMut(usize, usize) -> usize,
) -> usize {
    let most = len.min(portion);
    let mut done = 0;
    while done < most {
        let moved = window(done, most - done).min(most - done);
        if moved == 0 {
            break;
        }
        done += moved;
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_gives_up_to_its_limit_and_takes_back() {
        let mut b = Buffers::new(64);
        for k in 0..64 {
            assert_eq!(b.give(100 + k), Ok(k as usize));
        }
        assert_eq!(b.give(999), Err(Refusal::Full));
        assert_eq!(b.count(), 64);
        b.retire(5);
        // A retired entry is taken until it is unmapped.
        assert_eq!(b.give(999), Err(Refusal::Full));
        assert!(!b.owned_by(5, 105));
        assert_eq!(b.next_retired(), Some(5));
        let generation = b.generation(5);
        b.free(5);
        assert_eq!(b.next_retired(), None);
        assert_eq!(b.generation(5), generation + 1);
        assert_eq!(b.give(999), Ok(5));
        assert!(b.owned_by(5, 999));
        assert!(!b.owned_by(5, 105));
    }

    #[test]
    fn the_limit_of_the_file_holds_and_zero_gives_none() {
        let mut b = Buffers::new(4);
        for _ in 0..4 {
            b.give(1).unwrap();
        }
        assert_eq!(b.give(1), Err(Refusal::Full));
        assert_eq!(Buffers::new(0).give(1), Err(Refusal::Full));
        assert_eq!(Buffers::new(200).limit(), 64);
    }

    #[test]
    fn freeing_an_entry_twice_or_out_of_range_changes_nothing() {
        let mut b = Buffers::new(64);
        let i = b.give(7).unwrap();
        b.free(i);
        let g = b.generation(i);
        b.free(i);
        b.free(99);
        b.retire(99);
        assert_eq!(b.generation(i), g);
        assert_eq!(b.count(), 0);
    }

    /// A ring of `size` bytes with `used` of them taken from `head`: the
    /// free space in two windows, as smoltcp's ring gives it.
    fn ring_windows(size: usize, head: usize, used: usize) -> impl FnMut(usize, usize) -> usize {
        let mut tail = (head + used) % size;
        let mut free = size - used;
        move |_done, want| {
            let contiguous = (size - tail).min(free);
            let k = contiguous.min(want);
            tail = (tail + k) % size;
            free -= k;
            k
        }
    }

    #[test]
    fn a_copy_never_exceeds_the_portion() {
        for portion in [4096, 8192, 16_384] {
            for (head, used) in [(0, 0), (10_000, 0), (16_000, 100), (5, 16_000), (0, 16_384)] {
                let moved = copy_portion(16_384, portion, ring_windows(16_384, head, used));
                assert!(moved <= portion, "{portion} {head} {used}: {moved}");
                assert_eq!(moved, portion.min(16_384 - used), "{portion} {head} {used}");
            }
        }
        // Less asked than the portion: what was asked.
        assert_eq!(
            copy_portion(100, 16_384, ring_windows(16_384, 16_300, 0)),
            100
        );
        // A window that offers more than it is asked for is held to the rest.
        assert_eq!(copy_portion(1000, 512, |_, _| 4096), 512);
    }
}
