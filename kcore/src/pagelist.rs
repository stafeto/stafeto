// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The frames of a memory object (spec 7.3, 7.7): a tree of nodes, each a
//! frame of ENTRIES words, whose depth follows the size. One page needs no
//! node: the root is the page's frame. Up to ENTRIES pages take one node
//! of their frames; more take a node of nodes and a node for each ENTRIES
//! pages, up to MAX_PAGES. `nodes` counts the nodes before the first frame
//! is taken, so that the creator pays for all of them at once. The list
//! fills a few pages at a time, in the order of their indices, and goes
//! back at most RELEASE_STEP frames at a time, pages first and nodes
//! behind them, with how far it came kept in the list. Finding page i
//! reads at most two words.

use crate::PAGE_SIZE;
use crate::frames::PhysMem;

/// Words of a node: the frames of its pages, or the nodes below it.
pub const ENTRIES: usize = PAGE_SIZE as usize / 8;
/// Pages a list holds at most: two levels of nodes, 1 GiB.
pub const MAX_PAGES: usize = ENTRIES * ENTRIES;
/// Frames, pages or nodes, one step of a release gives back at most; each
/// may merge up to crate::frames::MAX_ORDER times in the frame allocator,
/// two units of work of a portion (spec 7.7).
pub const RELEASE_STEP: usize = 32;

/// Frames for the pages and nodes of a list, whose words the list reads
/// and writes through PhysMem. Reading a page's frame needs PhysMem alone
/// (`PageList::frame`).
///
/// # Safety
/// `alloc_frame` returns the physical address of a zeroed 4 KiB frame,
/// aligned to 4 KiB, that belongs to the list from then on and that
/// nothing else uses; `free_frame` takes back only such a frame, once the
/// list no longer refers to it. The kernel's frames come from a budget the
/// creator paid for whole (spec 7.5), so `alloc_frame` does not fail.
pub unsafe trait ListMemory: PhysMem {
    fn alloc_frame(&mut self) -> u64;
    fn free_frame(&mut self, pa: u64);
}

/// Levels of nodes a list of `pages` pages has: 0 for one page, 1 up to
/// ENTRIES, 2 above.
pub const fn depth(pages: usize) -> u32 {
    if pages <= 1 {
        0
    } else if pages <= ENTRIES {
        1
    } else {
        2
    }
}

/// Nodes a list of `pages` pages takes (spec 7.3): none for one page, one
/// up to ENTRIES, and above that a node of nodes and one node for each
/// ENTRIES pages.
pub const fn nodes(pages: usize) -> usize {
    match depth(pages) {
        0 => 0,
        1 => 1,
        _ => 1 + pages.div_ceil(ENTRIES),
    }
}

/// The frames of a memory object of a fixed number of pages. It is
/// neither Clone nor Copy: one object owns its frames. A list dropped with
/// frames left stops the kernel: they go back only through `release_step`.
#[derive(Debug)]
pub struct PageList {
    /// The frame of the only page at depth 0, the top node otherwise; 0
    /// while the list holds no frame.
    root: u64,
    pages: usize,
    /// Pages filled: the frames of pages 0 to filled - 1 are taken.
    filled: usize,
    /// Nodes below the root at depth 2.
    leaves: usize,
    /// The release began: nothing fills or reads the list any more.
    going: bool,
}

impl PageList {
    /// A list of `pages` pages, 1 to MAX_PAGES, that holds no frame yet.
    pub const fn new(pages: usize) -> PageList {
        assert!(
            pages > 0 && pages <= MAX_PAGES,
            "a page list of no page or past its bound"
        );
        PageList {
            root: 0,
            pages,
            filled: 0,
            leaves: 0,
            going: false,
        }
    }

    /// The pages of the list.
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// The pages whose frames the list holds.
    pub fn filled(&self) -> usize {
        self.filled
    }

    /// Takes the frames of up to `n` more pages, in the order of their
    /// indices, and the nodes they need, at most two more frames; true once
    /// every page has its frame.
    pub fn fill(&mut self, mem: &mut impl ListMemory, n: usize) -> bool {
        assert!(!self.going, "a page list fills after its release began");
        let end = self.pages.min(self.filled + n);
        while self.filled < end {
            let i = self.filled;
            match depth(self.pages) {
                0 => self.root = mem.alloc_frame(),
                1 => {
                    if i == 0 {
                        self.root = mem.alloc_frame();
                    }
                    let page = mem.alloc_frame();
                    mem.write(self.root + 8 * i as u64, page);
                }
                _ => {
                    if i == 0 {
                        self.root = mem.alloc_frame();
                    }
                    let slot = self.root + 8 * (i / ENTRIES) as u64;
                    if i.is_multiple_of(ENTRIES) {
                        let leaf = mem.alloc_frame();
                        mem.write(slot, leaf);
                        self.leaves += 1;
                    }
                    let page = mem.alloc_frame();
                    let leaf = mem.read(slot);
                    mem.write(leaf + 8 * (i % ENTRIES) as u64, page);
                }
            }
            self.filled += 1;
        }
        self.filled == self.pages
    }

    /// The frame of page `i`, which the list holds: at most two reads.
    pub fn frame(&self, mem: &impl PhysMem, i: usize) -> u64 {
        assert!(!self.going, "a page list is read after its release began");
        assert!(i < self.filled, "a page the list does not hold");
        self.find(mem, i)
    }

    fn find(&self, mem: &impl PhysMem, i: usize) -> u64 {
        match depth(self.pages) {
            0 => self.root,
            1 => mem.read(self.root + 8 * i as u64),
            _ => {
                let leaf = mem.read(self.root + 8 * (i / ENTRIES) as u64);
                mem.read(leaf + 8 * (i % ENTRIES) as u64)
            }
        }
    }

    /// One step of the release (spec 7.7): up to RELEASE_STEP frames go
    /// back, the last page first; a node goes once its pages went, and the
    /// root last. A list that filled only in part goes the same way. True
    /// once the list holds no frame; every later step frees nothing.
    pub fn release_step(&mut self, mem: &mut impl ListMemory) -> bool {
        self.going = true;
        for _ in 0..RELEASE_STEP {
            if self.leaves > self.filled.div_ceil(ENTRIES) {
                self.leaves -= 1;
                let leaf = mem.read(self.root + 8 * self.leaves as u64);
                mem.free_frame(leaf);
            } else if self.filled > 0 {
                let page = self.find(mem, self.filled - 1);
                mem.free_frame(page);
                self.filled -= 1;
                if depth(self.pages) == 0 {
                    self.root = 0;
                }
            } else if self.root != 0 {
                mem.free_frame(self.root);
                self.root = 0;
            } else {
                break;
            }
        }
        self.root == 0
    }
}

impl Drop for PageList {
    fn drop(&mut self) {
        // Only a check, as for PageLog: the frames go back through
        // `release_step`. A host test that failed midway reports its own
        // panic instead.
        #[cfg(test)]
        if std::thread::panicking() {
            return;
        }
        assert!(self.root == 0, "a page list dropped with its frames");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x4000_0000;

    /// Frames handed out in order from BASE; a node's words live in a box
    /// of its own, and a frame nobody writes to is a page.
    struct Mem {
        nodes: Vec<Option<Box<[u64; ENTRIES]>>>,
        taken: Vec<bool>,
        allocated: Vec<u64>,
        freed: Vec<u64>,
    }

    impl Mem {
        fn new() -> Mem {
            Mem {
                nodes: Vec::new(),
                taken: Vec::new(),
                allocated: Vec::new(),
                freed: Vec::new(),
            }
        }

        fn index(pa: u64) -> usize {
            ((pa - BASE) / PAGE_SIZE) as usize
        }

        fn is_node(&self, pa: u64) -> bool {
            self.nodes[Mem::index(pa)].is_some()
        }

        /// The frames of pages, in the order they were taken.
        fn pages(&self) -> Vec<u64> {
            let pages = self.allocated.iter().copied();
            pages.filter(|&pa| !self.is_node(pa)).collect()
        }
    }

    // SAFETY: frames are distinct and owned by the test.
    unsafe impl ListMemory for Mem {
        fn alloc_frame(&mut self) -> u64 {
            let pa = BASE + self.taken.len() as u64 * PAGE_SIZE;
            self.nodes.push(None);
            self.taken.push(true);
            self.allocated.push(pa);
            pa
        }
        fn free_frame(&mut self, pa: u64) {
            let taken = &mut self.taken[Mem::index(pa)];
            assert!(*taken, "frame {pa:#x} freed twice or never taken");
            *taken = false;
            self.freed.push(pa);
        }
    }

    // SAFETY: absent words read as 0; `read` returns the last `write`, and
    // the words of a frame that went are never touched.
    unsafe impl PhysMem for Mem {
        fn read(&self, pa: u64) -> u64 {
            let i = Mem::index(pa);
            assert!(self.taken[i], "a read of a frame that went");
            self.nodes[i]
                .as_ref()
                .map_or(0, |n| n[(pa % PAGE_SIZE) as usize / 8])
        }
        fn write(&mut self, pa: u64, value: u64) {
            let i = Mem::index(pa);
            assert!(self.taken[i], "a write to a frame that went");
            let node = self.nodes[i].get_or_insert_with(|| Box::new([0; ENTRIES]));
            node[(pa % PAGE_SIZE) as usize / 8] = value;
        }
    }

    /// Releases `list` to the end; returns the steps it took.
    fn release(list: &mut PageList, mem: &mut Mem) -> usize {
        let mut steps = 1;
        while !list.release_step(mem) {
            steps += 1;
        }
        steps
    }

    #[test]
    fn depth_follows_the_size() {
        for (pages, d) in [
            (1, 0),
            (2, 1),
            (ENTRIES, 1),
            (ENTRIES + 1, 2),
            (2 * ENTRIES, 2),
            (MAX_PAGES, 2),
        ] {
            assert_eq!(depth(pages), d, "{pages} pages");
        }
        // One page: its frame is the root, and no node is written.
        let mut m = Mem::new();
        let mut one = PageList::new(1);
        assert!(one.fill(&mut m, 8));
        assert_eq!((m.allocated.len(), one.frame(&m, 0)), (1, m.allocated[0]));
        assert!(!m.is_node(m.allocated[0]));
        release(&mut one, &mut m);
        // 513 pages: a node of two nodes, the second with one page.
        let mut m = Mem::new();
        let mut list = PageList::new(ENTRIES + 1);
        assert!(list.fill(&mut m, ENTRIES + 1));
        let root = m.allocated[0];
        let leaves = [m.read(root), m.read(root + 8), m.read(root + 16)];
        assert!(m.is_node(leaves[0]) && m.is_node(leaves[1]));
        assert_eq!(leaves[2], 0, "a third node below the root");
        assert_eq!(m.read(leaves[1]), list.frame(&m, ENTRIES));
        release(&mut list, &mut m);
    }

    #[test]
    fn nodes_are_counted_up_front() {
        for (pages, n) in [
            (1, 0),
            (2, 1),
            (ENTRIES, 1),
            (ENTRIES + 1, 3),
            (2 * ENTRIES, 3),
            (2 * ENTRIES + 1, 4),
            (MAX_PAGES, 1 + ENTRIES),
        ] {
            assert_eq!(nodes(pages), n, "{pages} pages");
            // A full list takes exactly its pages and its nodes.
            let mut m = Mem::new();
            let mut list = PageList::new(pages);
            assert!(list.fill(&mut m, pages));
            let written = m.allocated.iter().filter(|&&pa| m.is_node(pa)).count();
            assert_eq!(
                (m.allocated.len(), written),
                (pages + n, n),
                "{pages} pages"
            );
            release(&mut list, &mut m);
        }
    }

    #[test]
    fn fill_in_steps_takes_every_page_once() {
        let sizes = [1, 2, 7, 8, 9, 511, 512, 513, 1023, 1024, 1025, 2000];
        for pages in sizes {
            for step in [1, 3, 8] {
                let mut m = Mem::new();
                let mut list = PageList::new(pages);
                let mut steps = 0;
                loop {
                    let before = m.allocated.len();
                    let full = list.fill(&mut m, step);
                    steps += 1;
                    assert!(
                        m.allocated.len() - before <= step + 2,
                        "a step of {step} took more"
                    );
                    assert_eq!(list.filled(), pages.min(steps * step));
                    if full {
                        break;
                    }
                }
                assert_eq!(steps, pages.div_ceil(step), "{pages} pages by {step}");
                assert!(list.fill(&mut m, step), "a full list fills again");
                let frames: Vec<u64> = (0..pages).map(|i| list.frame(&m, i)).collect();
                assert_eq!(frames, m.pages(), "{pages} pages by {step}");
                assert_eq!(m.allocated.len(), pages + nodes(pages));
                release(&mut list, &mut m);
            }
        }
    }

    /// 100 lists of random sizes up to MAX_PAGES, with a fixed seed, fill
    /// in random steps; after each step a random page the list holds so
    /// far, and once it is full 100 random pages, 10 000 in all, match a
    /// model: the frames of pages in the order the list took them.
    #[test]
    fn lookup_matches_a_model() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..100 {
            // Sizes spread over the three depths.
            let bits = next() % 19;
            let pages = 1 + (next() % (1 << bits)) as usize;
            let mut m = Mem::new();
            let mut list = PageList::new(pages);
            let mut model = Vec::new();
            let mut full = false;
            while !full {
                let seen = m.allocated.len();
                full = list.fill(&mut m, 1 + (next() % 64) as usize);
                let new = m.allocated[seen..].iter().copied();
                model.extend(new.filter(|&pa| !m.is_node(pa)));
                let i = (next() % list.filled() as u64) as usize;
                assert_eq!(list.frame(&m, i), model[i], "page {i} of {pages}");
            }
            for _ in 0..100 {
                let i = (next() % pages as u64) as usize;
                assert_eq!(list.frame(&m, i), model[i], "page {i} of {pages}");
            }
            release(&mut list, &mut m);
        }
    }

    #[test]
    fn release_in_steps_frees_every_page_and_node_once() {
        for (pages, filled) in [
            (1, 0),
            (1, 1),
            (2, 1),
            (ENTRIES, ENTRIES),
            (ENTRIES + 1, 1),
            (ENTRIES + 1, ENTRIES),
            (ENTRIES + 1, ENTRIES + 1),
            (2 * ENTRIES + 1, 700),
            (3000, 3000),
        ] {
            let mut m = Mem::new();
            let mut list = PageList::new(pages);
            list.fill(&mut m, filled);
            let taken = m.allocated.len();
            let steps = release(&mut list, &mut m);
            assert_eq!(
                steps,
                taken.div_ceil(RELEASE_STEP).max(1),
                "{pages}, {filled}"
            );
            let mut freed = m.freed.clone();
            if filled > 0 && pages > 1 {
                assert_eq!(freed.last(), Some(&m.allocated[0]), "the root goes last");
            }
            // A node goes after every page below it.
            for (i, &pa) in m.freed.iter().enumerate() {
                if m.is_node(pa) {
                    let below = m.nodes[Mem::index(pa)].as_ref().expect("a node");
                    let later = |page: &u64| m.freed[i..].contains(page);
                    assert!(!below.iter().any(later), "a node went before its pages");
                }
            }
            freed.sort();
            assert_eq!(freed, m.allocated, "{pages}, {filled}: each frame once");
            assert!(list.release_step(&mut m));
            assert_eq!(m.freed.len(), taken, "a step after the end freed a frame");
        }
    }

    #[test]
    fn a_release_step_frees_at_most_its_step() {
        let mut m = Mem::new();
        let mut list = PageList::new(5000);
        assert!(list.fill(&mut m, 5000));
        let mut counts = Vec::new();
        loop {
            let before = m.freed.len();
            let done = list.release_step(&mut m);
            counts.push(m.freed.len() - before);
            if done {
                break;
            }
        }
        let (last, full) = counts.split_last().expect("a step");
        assert!(
            full.iter().all(|&n| n == RELEASE_STEP),
            "a step freed other than RELEASE_STEP"
        );
        assert!(*last > 0 && *last <= RELEASE_STEP);
        assert_eq!(m.freed.len(), 5000 + nodes(5000));
    }
}
