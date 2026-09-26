// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The timers of programs (spec 10): a binary heap for each level of 1-63,
//! the priority of a timer's slot, the nodes inside the timer objects:
//! arming a timer never allocates. The earliest deadline is at the root,
//! found in O(1); a timer goes in or out, wherever it stands, in
//! O(log n). Positions count from 1 at the root, the children of k at 2k
//! and 2k + 1; the path to position k follows the bits of k below its
//! highest one, 0 to the left and 1 to the right. The last node is at
//! position n, the place for a new one at n + 1. `Levels` keeps the heaps
//! with the nearest deadline of the levels whose firing is not queued
//! yet, and `Firing` takes one portion of a level's expired timers.

use core::ptr::NonNull;

/// Where a timer stands in the heap: its parent and children, and its
/// deadline in counter ticks. Only the heap changes it; the deadline stays
/// after the timer leaves.
pub struct HeapLink<T> {
    deadline: u64,
    linked: bool,
    parent: Option<NonNull<T>>,
    left: Option<NonNull<T>>,
    right: Option<NonNull<T>>,
}

impl<T> HeapLink<T> {
    /// A timer in no heap.
    pub const fn new() -> HeapLink<T> {
        HeapLink {
            deadline: 0,
            linked: false,
            parent: None,
            left: None,
            right: None,
        }
    }

    /// The deadline the timer was put in the heap for last.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Whether the timer stands in the heap.
    pub fn is_linked(&self) -> bool {
        self.linked
    }
}

impl<T> Default for HeapLink<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// An object a `Heap` can hold.
///
/// # Safety
/// `heap_link` returns a pointer to a `HeapLink` inside the object `this`
/// points at, valid as long as that object lives.
pub unsafe trait HeapNode: Sized {
    fn heap_link(this: NonNull<Self>) -> NonNull<HeapLink<Self>>;
}

/// The link of `t`.
///
/// # Safety
/// `t` is alive, and nothing else refers to its link meanwhile.
unsafe fn link<'a, T: HeapNode>(t: NonNull<T>) -> &'a mut HeapLink<T> {
    // SAFETY: the caller's promise and HeapNode's contract.
    unsafe { T::heap_link(t).as_mut() }
}

/// A binary min-heap of timers by deadline, its links in the timers.
///
/// Every timer handed to `insert` stays alive and in place until it leaves
/// the heap; the heap keeps pointers to it meanwhile.
pub struct Heap<T> {
    root: Option<NonNull<T>>,
    len: usize,
    /// Comparisons of deadlines, for the test of the steps.
    #[cfg(test)]
    compared: u32,
}

// SAFETY: the heap holds pointers to timers that the kernel hands it, and
// moving it moves them along, as moving the timers would.
unsafe impl<T: Send> Send for Heap<T> {}

impl<T: HeapNode> Heap<T> {
    pub const fn new() -> Self {
        Heap {
            root: None,
            len: 0,
            #[cfg(test)]
            compared: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The earliest deadline, in O(1): what the timer of the kernel needs
    /// (sched::Scheduler::deadline).
    pub fn first(&self) -> Option<u64> {
        // SAFETY: a timer in the heap is alive (`insert`).
        self.root.map(|r| unsafe { link(r) }.deadline)
    }

    /// Whether `a` fires before `b`: the one place deadlines are compared.
    fn earlier(&mut self, a: NonNull<T>, b: NonNull<T>) -> bool {
        #[cfg(test)]
        {
            self.compared += 1;
        }
        // SAFETY: both are in the heap, so alive (`insert`); each borrow
        // ends with its read.
        unsafe { link(a).deadline < link(b).deadline }
    }

    /// The timer at `position` (1 is the root): from the root, the bits of
    /// `position` below its highest one lead left for 0 and right for 1.
    fn at(&self, position: usize) -> Option<NonNull<T>> {
        if position == 0 || position > self.len {
            return None;
        }
        let mut t = self.root?;
        for bit in (0..position.ilog2()).rev() {
            // SAFETY: a timer in the heap is alive (`insert`).
            let l = unsafe { link(t) };
            let next = if position >> bit & 1 == 0 {
                l.left
            } else {
                l.right
            };
            t = next.expect("a timer where the count puts one");
        }
        Some(t)
    }

    /// Puts `t` in for `deadline`, at the place after the last node, and
    /// lets it climb: O(log n).
    ///
    /// # Safety
    /// `t` is alive and in no heap, and stays alive and in place until it
    /// leaves this one.
    pub unsafe fn insert(&mut self, t: NonNull<T>, deadline: u64) {
        // SAFETY: the caller's promise; the timers in the heap are alive.
        unsafe {
            let l = link(t);
            assert!(!l.linked, "a timer goes into a heap twice");
            *l = HeapLink {
                deadline,
                linked: true,
                ..HeapLink::new()
            };
            let position = self.len + 1;
            if position == 1 {
                self.root = Some(t);
            } else {
                let parent = self.at(position / 2).expect("the parent's place");
                link(t).parent = Some(parent);
                let p = link(parent);
                if position.is_multiple_of(2) {
                    p.left = Some(t);
                } else {
                    p.right = Some(t);
                }
            }
            self.len = position;
            self.sift_up(t);
        }
    }

    /// Takes `t` out wherever it stands: the last node takes its place and
    /// climbs or sinks from there. O(log n).
    ///
    /// # Safety
    /// `t` is in this heap.
    pub unsafe fn remove(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the timers in the heap are alive,
        // and every borrow of a link ends before another of the same link.
        unsafe {
            assert!(link(t).linked, "a timer leaves a heap it is not in");
            let last = self.at(self.len).expect("the last node");
            match link(last).parent {
                None => self.root = None,
                Some(p) => {
                    let p = link(p);
                    if p.right == Some(last) {
                        p.right = None;
                    } else {
                        p.left = None;
                    }
                }
            }
            self.len -= 1;
            if last != t {
                let (parent, left, right) = {
                    let l = link(t);
                    (l.parent, l.left, l.right)
                };
                self.replace_child(parent, t, last);
                {
                    let l = link(last);
                    l.parent = parent;
                    l.left = left;
                    l.right = right;
                }
                for child in [left, right].into_iter().flatten() {
                    link(child).parent = Some(last);
                }
                if parent.is_some_and(|p| self.earlier(last, p)) {
                    self.swap_with_parent(last);
                    self.sift_up(last);
                } else {
                    self.sift_down(last);
                }
            }
            let l = link(t);
            l.linked = false;
            l.parent = None;
            l.left = None;
            l.right = None;
        }
    }

    /// The timer at the root when its deadline is not after `now`, out of
    /// the heap; None when nothing expired.
    pub fn pop_expired(&mut self, now: u64) -> Option<NonNull<T>> {
        let root = self.root?;
        // SAFETY: a timer in the heap is alive (`insert`).
        if unsafe { link(root) }.deadline > now {
            return None;
        }
        // SAFETY: the root is in this heap.
        unsafe { self.remove(root) };
        Some(root)
    }

    /// Where `parent` (the root for None) points at `old`, it points at
    /// `new` instead.
    ///
    /// # Safety
    /// `parent` is in the heap, and `old` is its child or the root.
    unsafe fn replace_child(
        &mut self,
        parent: Option<NonNull<T>>,
        old: NonNull<T>,
        new: NonNull<T>,
    ) {
        match parent {
            None => self.root = Some(new),
            Some(p) => {
                // SAFETY: the caller's promise.
                let p = unsafe { link(p) };
                if p.left == Some(old) {
                    p.left = Some(new);
                } else {
                    p.right = Some(new);
                }
            }
        }
    }

    /// `t` and its parent change places.
    ///
    /// # Safety
    /// `t` is in the heap and has a parent.
    unsafe fn swap_with_parent(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; the timers in the heap are alive,
        // and every borrow of a link ends before another of the same link.
        unsafe {
            let (parent, left, right) = {
                let l = link(t);
                (l.parent.expect("a parent"), l.left, l.right)
            };
            let (grandparent, p_left, p_right) = {
                let l = link(parent);
                (l.parent, l.left, l.right)
            };
            self.replace_child(grandparent, parent, t);
            // The parent goes where `t` was, its other child stays beside.
            let (new_left, new_right, sibling) = if p_left == Some(t) {
                (Some(parent), p_right, p_right)
            } else {
                (p_left, Some(parent), p_left)
            };
            {
                let l = link(t);
                l.parent = grandparent;
                l.left = new_left;
                l.right = new_right;
            }
            if let Some(s) = sibling {
                link(s).parent = Some(t);
            }
            {
                let l = link(parent);
                l.parent = Some(t);
                l.left = left;
                l.right = right;
            }
            for child in [left, right].into_iter().flatten() {
                link(child).parent = Some(parent);
            }
        }
    }

    /// `t` climbs while it fires before its parent.
    ///
    /// # Safety
    /// `t` is in the heap.
    unsafe fn sift_up(&mut self, t: NonNull<T>) {
        // SAFETY: the caller's promise; a timer in the heap is alive.
        while let Some(p) = unsafe { link(t) }.parent
            && self.earlier(t, p)
        {
            // SAFETY: `t` has a parent.
            unsafe { self.swap_with_parent(t) };
        }
    }

    /// `t` sinks while a child fires before it, the earlier child first:
    /// two comparisons a level.
    ///
    /// # Safety
    /// `t` is in the heap.
    unsafe fn sift_down(&mut self, t: NonNull<T>) {
        loop {
            // SAFETY: the caller's promise; a timer in the heap is alive.
            let (left, right) = {
                let l = unsafe { link(t) };
                (l.left, l.right)
            };
            let child = match (left, right) {
                (Some(l), Some(r)) if self.earlier(r, l) => r,
                (Some(l), _) => l,
                (None, _) => return,
            };
            if !self.earlier(child, t) {
                return;
            }
            // SAFETY: the child is in the heap, below `t`.
            unsafe { self.swap_with_parent(child) };
        }
    }
}

impl<T: HeapNode> Default for Heap<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The levels of timers: the priorities of their slots, 1-63 (spec 10).
pub const LEVELS: usize = 63;

/// Expired timers of one level a portion takes, at most (spec 7.7, 10).
pub const FIRE_PORTION: usize = 16;

/// The bit of `level` in the masks of `Levels`.
fn bit(level: u8) -> u64 {
    assert!(
        (1..=LEVELS as u8).contains(&level),
        "a timer's level is out of 1-63"
    );
    1 << level
}

/// The timers of programs by level (spec 10): a heap for each level, the
/// levels that have timers, the levels whose firing stands in the kernel's
/// cleanup queue (pending), and the nearest deadline of the levels that
/// have timers and are not pending, kept ready. It changes only when the
/// top of a heap or the mask of pending levels does, by a walk of up to 63
/// levels.
pub struct Levels<T> {
    heaps: [Heap<T>; LEVELS],
    nonempty: u64,
    pending: u64,
    nearest: Option<u64>,
}

impl<T: HeapNode> Levels<T> {
    pub const fn new() -> Self {
        Levels {
            heaps: [const { Heap::new() }; LEVELS],
            nonempty: 0,
            pending: 0,
            nearest: None,
        }
    }

    fn heap(&mut self, level: u8) -> &mut Heap<T> {
        let _ = bit(level);
        &mut self.heaps[usize::from(level) - 1]
    }

    /// The nearest deadline of the levels that are not pending, in O(1):
    /// what the kernel's timer needs (spec 8, 10).
    pub fn nearest(&self) -> Option<u64> {
        self.nearest
    }

    /// Whether the firing of `level` is queued: from `expired` until
    /// `settle`.
    #[cfg(test)]
    pub fn is_pending(&self, level: u8) -> bool {
        self.pending & bit(level) != 0
    }

    /// Timers armed at `level`.
    #[cfg(test)]
    pub fn len(&self, level: u8) -> usize {
        let _ = bit(level);
        self.heaps[usize::from(level) - 1].len()
    }

    /// Walks the levels that have timers and are not pending for the
    /// nearest deadline: up to 63 comparisons.
    fn renew(&mut self) {
        let mut levels = self.nonempty & !self.pending;
        let mut nearest: Option<u64> = None;
        while levels != 0 {
            let level = levels.trailing_zeros() as usize;
            levels &= levels - 1;
            let first = self.heaps[level - 1].first();
            nearest = match (nearest, first) {
                (Some(n), Some(f)) => Some(n.min(f)),
                (n, f) => n.or(f),
            };
        }
        self.nearest = nearest;
    }

    /// Puts `t` in at `level` for `deadline`: O(log n), and the nearest
    /// deadline follows unless the level is pending.
    ///
    /// # Safety
    /// As for Heap::insert.
    pub unsafe fn insert(&mut self, level: u8, t: NonNull<T>, deadline: u64) {
        // SAFETY: the caller's promise.
        unsafe { self.heap(level).insert(t, deadline) };
        self.nonempty |= bit(level);
        if self.pending & bit(level) == 0 {
            self.nearest = Some(self.nearest.map_or(deadline, |n| n.min(deadline)));
        }
    }

    /// Takes `t` out of `level` wherever it stands: O(log n), and the walk
    /// of the levels when the top of a level that is not pending changed.
    ///
    /// # Safety
    /// `t` is in the heap of `level`.
    pub unsafe fn remove(&mut self, level: u8, t: NonNull<T>) {
        let heap = self.heap(level);
        let top = heap.first();
        // SAFETY: the caller's promise.
        unsafe { heap.remove(t) };
        let after = heap.first();
        self.left(level, top != after);
    }

    /// After a timer left `level`: its bit goes with its last timer, and
    /// the nearest deadline is walked again when its top `moved`.
    fn left(&mut self, level: u8, moved: bool) {
        if self.heap(level).is_empty() {
            self.nonempty &= !bit(level);
        }
        if moved && self.pending & bit(level) == 0 {
            self.renew();
        }
    }

    /// The timer interrupt at `now`: the levels that are not pending and
    /// whose top the counter reached become pending, and come back as a
    /// mask, a bit for each; the nearest deadline leaves them out, in the
    /// same walk. Nothing leaves a heap. Up to 63 levels.
    pub fn expired(&mut self, now: u64) -> u64 {
        let mut levels = self.nonempty & !self.pending;
        let mut due = 0;
        let mut nearest: Option<u64> = None;
        while levels != 0 {
            let level = levels.trailing_zeros() as usize;
            levels &= levels - 1;
            match self.heaps[level - 1].first() {
                Some(d) if d <= now => due |= 1 << level,
                Some(d) => nearest = Some(nearest.map_or(d, |n| n.min(d))),
                None => {}
            }
        }
        if due != 0 {
            self.pending |= due;
            self.nearest = nearest;
        }
        due
    }

    /// Whether the top of `level` expired by `now`.
    pub fn has_expired(&self, level: u8, now: u64) -> bool {
        let _ = bit(level);
        self.heaps[usize::from(level) - 1]
            .first()
            .is_some_and(|d| d <= now)
    }

    /// The top of `level` when its deadline is not after `now`, out of the
    /// heap: O(log n).
    pub fn pop_expired(&mut self, level: u8, now: u64) -> Option<NonNull<T>> {
        let t = self.heap(level).pop_expired(now)?;
        self.left(level, true);
        Some(t)
    }

    /// The firing of `level` is over: the level is not pending any more,
    /// and its top counts toward the nearest deadline again.
    pub fn settle(&mut self, level: u8) {
        self.pending &= !bit(level);
        self.renew();
    }
}

impl<T: HeapNode> Default for Levels<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// One portion of the firing of a level (spec 7.7, 10): up to FIRE_PORTION
/// expired timers, one `next` at a time, so that the caller lets the lock
/// of the levels go before it posts each; then `finish`.
pub struct Firing {
    level: u8,
    left: usize,
}

impl Firing {
    pub fn new(level: u8) -> Firing {
        let _ = bit(level);
        Firing {
            level,
            left: FIRE_PORTION,
        }
    }

    /// The next expired timer of the level by `now`, out of its heap; None
    /// once the portion took FIRE_PORTION of them or nothing more expired.
    pub fn next<T: HeapNode>(&mut self, levels: &mut Levels<T>, now: u64) -> Option<NonNull<T>> {
        if self.left == 0 {
            return None;
        }
        let t = levels.pop_expired(self.level, now)?;
        self.left -= 1;
        Some(t)
    }

    /// The end of the portion at `now`: true when the level has expired
    /// timers left, and its firing goes on in the next portion; otherwise
    /// the level settles.
    pub fn finish<T: HeapNode>(self, levels: &mut Levels<T>, now: u64) -> bool {
        if levels.has_expired(self.level, now) {
            return true;
        }
        levels.settle(self.level);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Timer {
        link: HeapLink<Timer>,
        id: usize,
    }

    // SAFETY: the link is a field of the timer.
    unsafe impl HeapNode for Timer {
        fn heap_link(this: NonNull<Timer>) -> NonNull<HeapLink<Timer>> {
            // SAFETY: `this` points at a live timer.
            unsafe { NonNull::new_unchecked(&raw mut (*this.as_ptr()).link) }
        }
    }

    /// `n` timers that stay in place while the test runs, and their
    /// pointers.
    fn timers(n: usize) -> (Box<[Timer]>, Vec<NonNull<Timer>>) {
        let mut ts: Box<[Timer]> = (0..n)
            .map(|id| Timer {
                link: HeapLink::new(),
                id,
            })
            .collect();
        let ps = ts.iter_mut().map(NonNull::from).collect();
        (ts, ps)
    }

    fn link(t: NonNull<Timer>) -> &'static HeapLink<Timer> {
        // SAFETY: the tests keep their timers alive and only read here.
        unsafe { Timer::heap_link(t).as_ref() }
    }

    /// The whole tree against the rules: each child names its parent and
    /// fires no earlier, the node at each position is where the bits of
    /// the position lead, and the count is right.
    fn check(h: &Heap<Timer>) {
        let mut seen = 0;
        let mut stack: Vec<(NonNull<Timer>, usize)> = h.root.map(|r| (r, 1)).into_iter().collect();
        if let Some(r) = h.root {
            assert_eq!(link(r).parent, None, "the root has a parent");
        }
        while let Some((t, position)) = stack.pop() {
            seen += 1;
            let l = link(t);
            assert!(l.linked, "a node of the heap is not marked");
            assert_eq!(h.at(position), Some(t), "position {position}");
            for (child, at) in [(l.left, 2 * position), (l.right, 2 * position + 1)] {
                if let Some(c) = child {
                    assert_eq!(link(c).parent, Some(t), "position {at}");
                    assert!(
                        link(c).deadline >= l.deadline,
                        "position {at} fires before its parent"
                    );
                    stack.push((c, at));
                }
            }
        }
        assert_eq!(seen, h.len());
    }

    /// Xorshift: the same numbers on every run.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    #[test]
    fn heap_matches_a_sorted_model() {
        let (_ts, ps) = timers(64);
        let mut h = Heap::new();
        // (deadline, id) of each timer in the heap, sorted.
        let mut model: Vec<(u64, usize)> = Vec::new();
        let mut rng = Rng(0x5eed_0000_1357_9bdf);
        for step in 0..100_000 {
            let id = rng.below(64) as usize;
            let armed = model.iter().position(|&(_, i)| i == id);
            match (rng.below(3), armed) {
                // Armed, or set again: out, then in at the new deadline.
                (0, _) => {
                    if let Some(k) = armed {
                        // SAFETY: the timer is in the heap.
                        unsafe { h.remove(ps[id]) };
                        model.remove(k);
                    }
                    let d = rng.below(1000);
                    // SAFETY: the timer is alive and out of the heap.
                    unsafe { h.insert(ps[id], d) };
                    let at = model.partition_point(|&e| e < (d, id));
                    model.insert(at, (d, id));
                }
                // Cancelled.
                (1, Some(k)) => {
                    // SAFETY: the timer is in the heap.
                    unsafe { h.remove(ps[id]) };
                    model.remove(k);
                }
                // The counter passes a random time: what expired fires,
                // earliest first.
                _ => {
                    let now = rng.below(1000);
                    while let Some(t) = h.pop_expired(now) {
                        let d = link(t).deadline;
                        assert!(!link(t).linked);
                        assert_eq!(Some(d), model.first().map(|e| e.0), "step {step}");
                        assert!(d <= now, "step {step}: a timer fired early");
                        // SAFETY: the timer is alive.
                        let id = unsafe { t.as_ref() }.id;
                        model.retain(|&(_, i)| i != id);
                    }
                    assert!(model.first().is_none_or(|&(d, _)| d > now));
                }
            }
            assert_eq!(h.first(), model.first().map(|e| e.0), "step {step}");
            assert_eq!(h.len(), model.len(), "step {step}");
            check(&h);
        }
    }

    #[test]
    fn heap_removes_any_node() {
        // Deadlines by position; no node moves on the way in. The last node
        // (4) taking the place of position 4 or 5 must climb past 50.
        const DEADLINES: [u64; 7] = [1, 50, 2, 51, 52, 3, 4];
        for gone in 0..DEADLINES.len() {
            let (_ts, ps) = timers(DEADLINES.len());
            let mut h = Heap::new();
            for (&t, d) in ps.iter().zip(DEADLINES) {
                // SAFETY: the timers are alive and out of the heap.
                unsafe { h.insert(t, d) };
            }
            check(&h);
            // SAFETY: the timer is in the heap.
            unsafe { h.remove(ps[gone]) };
            assert!(!link(ps[gone]).linked);
            check(&h);
            let mut rest = DEADLINES.to_vec();
            rest.remove(gone);
            rest.sort();
            let mut fired = Vec::new();
            while let Some(t) = h.pop_expired(u64::MAX) {
                fired.push(link(t).deadline);
                check(&h);
            }
            assert_eq!(fired, rest, "without position {}", gone + 1);
        }
    }

    /// 2⌈log2(n + 1)⌉: the most comparisons an operation on a heap of n
    /// timers may make.
    fn bound(n: usize) -> u32 {
        2 * (usize::BITS - n.leading_zeros())
    }

    #[test]
    fn heap_steps_are_logarithmic() {
        let (_ts, ps) = timers(64);
        let mut h = Heap::new();
        // Later deadlines first: every new timer climbs to the root.
        for (k, &t) in ps.iter().enumerate() {
            h.compared = 0;
            // SAFETY: the timers are alive and out of the heap.
            unsafe { h.insert(t, 1000 - k as u64) };
            assert!(h.compared <= bound(h.len()), "insert {k}: {}", h.compared);
            assert_eq!(h.root, Some(t));
        }
        // Out of the middle, then the root each time: the last node sinks.
        let mut rng = Rng(7);
        for _ in 0..32 {
            let n = h.len();
            let t = h.at(2 + rng.below(n as u64 - 1) as usize).expect("a node");
            h.compared = 0;
            // SAFETY: the timer is in the heap.
            unsafe { h.remove(t) };
            assert!(h.compared <= bound(n), "remove from {n}: {}", h.compared);
        }
        while !h.is_empty() {
            let n = h.len();
            h.compared = 0;
            h.pop_expired(u64::MAX);
            assert!(h.compared <= bound(n), "pop from {n}: {}", h.compared);
        }
    }

    #[test]
    fn last_node_path_follows_the_bits() {
        let (_ts, ps) = timers(13);
        let mut h = Heap::new();
        // Rising deadlines: the k-th timer stays at position k.
        for (k, &t) in ps[..12].iter().enumerate() {
            // SAFETY: the timers are alive and out of the heap.
            unsafe { h.insert(t, k as u64) };
        }
        for k in 1..=12 {
            assert_eq!(h.at(k), Some(ps[k - 1]), "position {k}");
        }
        assert_eq!((h.at(0), h.at(13)), (None, None));
        // 12 is 0b1100: right from the root, then left and left.
        let right = link(h.root.expect("a root")).right.expect("position 3");
        let left = link(right).left.expect("position 6");
        assert_eq!((left, link(left).left), (ps[5], Some(ps[11])));
        // The last node leaves its place, and the next timer takes it.
        // SAFETY: the timer is in the heap.
        unsafe { h.remove(ps[11]) };
        assert_eq!((h.at(12), link(ps[5]).left), (None, None));
        // SAFETY: the timer is alive and out of the heap.
        unsafe { h.insert(ps[12], 100) };
        assert_eq!((h.at(12), link(ps[5]).left), (Some(ps[12]), Some(ps[12])));
        check(&h);
    }

    /// The deadline of `t`, a timer of the tests.
    fn deadline_of(t: NonNull<Timer>) -> u64 {
        link(t).deadline
    }

    /// The level of timer `id` in the tests of `Levels`: all 63 in turn.
    fn level_of(id: usize) -> u8 {
        (id % LEVELS) as u8 + 1
    }

    #[test]
    fn levels_match_a_model() {
        const TIMERS: usize = 200;
        let (_ts, ps) = timers(TIMERS);
        let mut l = Levels::new();
        // Each level's (deadline, id), sorted, and the pending levels.
        let mut model: Vec<Vec<(u64, usize)>> = vec![Vec::new(); LEVELS + 1];
        let mut pending = [false; LEVELS + 1];
        let mut rng = Rng(0x1e7e_15c0_ffee_0042);
        for step in 0..100_000 {
            let id = rng.below(TIMERS as u64) as usize;
            let level = level_of(id);
            let lv = usize::from(level);
            let armed = model[lv].iter().position(|&(_, i)| i == id);
            match rng.below(5) {
                // Armed, or set again.
                0 | 1 => {
                    if let Some(k) = armed {
                        // SAFETY: the timer is in the heap of its level.
                        unsafe { l.remove(level, ps[id]) };
                        model[lv].remove(k);
                    }
                    let d = rng.below(1000);
                    // SAFETY: the timer is alive and out of the heaps.
                    unsafe { l.insert(level, ps[id], d) };
                    let at = model[lv].partition_point(|&e| e < (d, id));
                    model[lv].insert(at, (d, id));
                }
                // Cancelled.
                2 => {
                    if let Some(k) = armed {
                        // SAFETY: the timer is in the heap of its level.
                        unsafe { l.remove(level, ps[id]) };
                        model[lv].remove(k);
                    }
                }
                // The interrupt at a random time: the levels whose top
                // expired and that were not pending come, once.
                3 => {
                    let now = rng.below(1000);
                    let due = l.expired(now);
                    for k in 1..=LEVELS {
                        let top = model[k].first().map(|e| e.0);
                        let expect = !pending[k] && top.is_some_and(|d| d <= now);
                        assert_eq!(due & 1 << k != 0, expect, "step {step}, level {k}");
                        pending[k] |= expect;
                    }
                }
                // A portion of a pending level, the first from a random
                // one on, at a random time.
                _ => {
                    let from = rng.below(LEVELS as u64) as usize;
                    let mut levels = (0..LEVELS).map(|j| (from + j) % LEVELS + 1);
                    let Some(k) = levels.find(|&k| pending[k]) else {
                        continue;
                    };
                    let now = rng.below(1000);
                    let mut firing = Firing::new(k as u8);
                    while let Some(t) = firing.next(&mut l, now) {
                        let d = deadline_of(t);
                        assert_eq!(Some(d), model[k].first().map(|e| e.0), "step {step}");
                        assert!(d <= now, "step {step}: a timer fired early");
                        model[k].remove(0);
                    }
                    let more = firing.finish(&mut l, now);
                    assert_eq!(more, model[k].first().is_some_and(|e| e.0 <= now));
                    pending[k] = more;
                }
            }
            let nearest = (1..=LEVELS)
                .filter(|&k| !pending[k])
                .filter_map(|k| model[k].first().map(|e| e.0))
                .min();
            assert_eq!(l.nearest(), nearest, "step {step}");
            for k in 1..=LEVELS {
                assert_eq!(l.len(k as u8), model[k].len(), "step {step}");
                assert_eq!(l.is_pending(k as u8), pending[k], "step {step}");
            }
        }
    }

    #[test]
    fn each_level_pops_only_its_own() {
        let (_ts, ps) = timers(6);
        let mut l = Levels::new();
        // Level 5 holds the earliest deadlines, level 40 the rest.
        for (i, &t) in ps.iter().enumerate() {
            let level = if i < 3 { 5 } else { 40 };
            // SAFETY: the timers are alive and out of the heaps.
            unsafe { l.insert(level, t, 10 + i as u64) };
        }
        assert_eq!(l.expired(100), 1 << 5 | 1 << 40);
        let mut high = Vec::new();
        while let Some(t) = l.pop_expired(40, 100) {
            high.push(deadline_of(t));
        }
        assert_eq!(high, [13, 14, 15], "level 40 gave another level's timers");
        assert_eq!((l.len(5), l.len(40)), (3, 0));
    }

    #[test]
    fn nearest_skips_pending_levels() {
        let (_ts, ps) = timers(4);
        let mut l = Levels::new();
        // SAFETY: the timers are alive and out of the heaps.
        unsafe {
            l.insert(10, ps[0], 100);
            l.insert(10, ps[1], 300);
            l.insert(20, ps[2], 200);
        }
        assert_eq!(l.nearest(), Some(100));
        assert_eq!(l.expired(150), 1 << 10);
        assert_eq!(l.nearest(), Some(200), "a pending level still counts");
        // SAFETY: the timer is alive and out of the heaps.
        unsafe { l.insert(10, ps[3], 50) };
        assert_eq!(l.nearest(), Some(200), "a timer of a pending level counts");
    }

    #[test]
    fn expired_levels_come_once_until_settled() {
        let (_ts, ps) = timers(2);
        let mut l = Levels::new();
        // SAFETY: the timers are alive and out of the heaps.
        unsafe {
            l.insert(63, ps[0], 5);
            l.insert(1, ps[1], 7);
        }
        assert_eq!(l.expired(4), 0, "a level came before its deadline");
        assert_eq!(l.expired(10), 1 << 63 | 1 << 1);
        assert_eq!(l.expired(20), 0, "a pending level came again");
        assert_eq!(l.len(63), 1, "the interrupt took a timer off");
        l.settle(63);
        assert_eq!(l.expired(20), 1 << 63, "a settled level did not come again");
    }

    #[test]
    fn settle_brings_a_later_top_back() {
        let (_ts, ps) = timers(2);
        let mut l = Levels::new();
        // SAFETY: the timers are alive and out of the heaps.
        unsafe {
            l.insert(30, ps[0], 10);
            l.insert(30, ps[1], 500);
        }
        assert_eq!(l.expired(20), 1 << 30);
        assert_eq!(l.nearest(), None);
        let mut firing = Firing::new(30);
        assert_eq!(firing.next(&mut l, 20), Some(ps[0]));
        assert_eq!(firing.next(&mut l, 20), None);
        assert!(!firing.finish(&mut l, 20), "the level has nothing expired");
        assert!(!l.is_pending(30));
        assert_eq!(l.nearest(), Some(500), "the later top did not come back");
    }

    #[test]
    fn a_firing_step_takes_at_most_its_portion() {
        const EXPIRED: usize = 2 * FIRE_PORTION + 3;
        let (_ts, ps) = timers(EXPIRED);
        let mut l = Levels::new();
        for (i, &t) in ps.iter().enumerate() {
            // SAFETY: the timers are alive and out of the heaps.
            unsafe { l.insert(7, t, i as u64) };
        }
        assert_eq!(l.expired(1000), 1 << 7);
        let mut taken = Vec::new();
        loop {
            let mut firing = Firing::new(7);
            let mut n = 0;
            while firing.next(&mut l, 1000).is_some() {
                n += 1;
            }
            taken.push(n);
            if !firing.finish(&mut l, 1000) {
                break;
            }
            assert!(l.is_pending(7), "a level with work left settled");
        }
        assert_eq!(taken, [FIRE_PORTION, FIRE_PORTION, 3]);
        assert!(!l.is_pending(7) && l.len(7) == 0);
    }
}
