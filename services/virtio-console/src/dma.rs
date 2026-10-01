// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver's DMA object (spec 7.3, spec 2 section 4): DMA_PAGES pages,
//! contiguous and uncached, which init makes and gives it with its
//! physical address. The first QUEUE_PAGES go to the device's queues, a
//! page at a time and for good (`Queues`); the rest are bounce pages: a
//! buffer the device reads or writes goes through one while the device
//! has it, copied in before and out after (`Bounce`), since the driver's
//! own memory has no address the device knows. Uncached: no cache
//! maintenance, only the barriers of the queues.

/// The pages of the object, 64 KiB.
pub const DMA_PAGES: usize = 16;
pub const PAGE: usize = 4096;
/// Pages for the queues: two queues of two entries take four.
pub const QUEUE_PAGES: usize = 8;
/// Bounce pages: a buffer of the device is a page at most.
pub const BOUNCE_PAGES: usize = DMA_PAGES - QUEUE_PAGES;

/// The pages of the queues, handed out in order and never back: the
/// queues are made once per instance of the driver.
#[derive(Debug, Default)]
pub struct Queues {
    next: usize,
}

impl Queues {
    pub const fn new() -> Queues {
        Queues { next: 0 }
    }

    /// The first of `pages` pages from the start of the object; None when
    /// the queues' pages ran out.
    pub fn take(&mut self, pages: usize) -> Option<usize> {
        let first = self.next;
        let end = first.checked_add(pages).filter(|&e| e <= QUEUE_PAGES)?;
        self.next = end;
        Some(first)
    }
}

/// The bounce pages, each free or lent to one buffer of the device.
#[derive(Debug, Default)]
pub struct Bounce {
    lent: u32,
}

impl Bounce {
    pub const fn new() -> Bounce {
        Bounce { lent: 0 }
    }

    /// A free bounce page for a buffer of `len` bytes, by its page in the
    /// object; None for a buffer longer than a page, or when all are lent.
    pub fn lend(&mut self, len: usize) -> Option<usize> {
        if len > PAGE {
            return None;
        }
        let i = (0..BOUNCE_PAGES).find(|&i| self.lent & (1 << i) == 0)?;
        self.lent |= 1 << i;
        Some(QUEUE_PAGES + i)
    }

    /// The bounce page at `page` of the object comes back; false for a
    /// page that is no bounce page or was not lent.
    pub fn give_back(&mut self, page: usize) -> bool {
        let Some(i) = page.checked_sub(QUEUE_PAGES).filter(|&i| i < BOUNCE_PAGES) else {
            return false;
        };
        let was = self.lent & (1 << i) != 0;
        self.lent &= !(1 << i);
        was
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queues_take_pages_in_order_up_to_their_share() {
        let mut q = Queues::new();
        assert_eq!(q.take(2), Some(0));
        assert_eq!(q.take(1), Some(2));
        assert_eq!(q.take(5), Some(3));
        assert_eq!(q.take(1), None);
    }

    #[test]
    fn bounce_pages_go_once_and_come_back() {
        let mut b = Bounce::new();
        let pages: Vec<_> = (0..BOUNCE_PAGES).map(|_| b.lend(PAGE).unwrap()).collect();
        assert_eq!(pages, (QUEUE_PAGES..DMA_PAGES).collect::<Vec<_>>());
        assert_eq!(b.lend(1), None);
        assert!(b.give_back(QUEUE_PAGES + 3));
        assert!(!b.give_back(QUEUE_PAGES + 3));
        assert!(!b.give_back(0));
        assert!(!b.give_back(DMA_PAGES));
        assert_eq!(b.lend(PAGE + 1), None);
        assert_eq!(b.lend(10), Some(QUEUE_PAGES + 3));
    }
}
