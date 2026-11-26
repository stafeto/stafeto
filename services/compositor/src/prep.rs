// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The prepared images of the elements that turn, reflect or stretch a window
//! (the design is "Work for a window at the window's level" of
//! `docs/compositor.md`).
//!
//! The transform of such an element is made by a worker thread of the service,
//! at the level of the client that posted the window's buffer, into an image of
//! the element's target size. The bands of a frame at the service's level copy
//! that image like a plain element. An element has two images (a front the
//! frames read and a back the worker draws in) in a pool of memory the service
//! reserves at the scene's commit.
//!
//! Everything the two threads share is an atomic here, and no thread waits for
//! the other: the service defers the free of what the worker reads (a buffer of a
//! window, the pages of a slot) until the worker says it let go, and the worker
//! never draws in an image a frame holds. The slots, the pool and the windows
//! the worker reads are told by the service alone (`&self` methods with atomics
//! or cells the other side reads only under the claim `busy`).

#![allow(clippy::needless_range_loop)]

use crate::{Format, MAX_WINDOWS, Rect};
use core::cell::UnsafeCell;
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicU64,
    Ordering::{AcqRel, Acquire, Relaxed, Release, SeqCst},
};
use proto_comp::{Element, MAX_ELEMENTS, TRANSPARENCY_SOURCE};

/// The bytes of the pool of prepared images.
pub const POOL_BYTES: usize = 2 << 20;
pub const PAGE: usize = 4096;
pub const POOL_PAGES: usize = POOL_BYTES / PAGE;
/// The slots: a prepared element each, for the working scene, the pending one
/// and the one a commit is making.
pub const SLOTS: usize = 3 * MAX_ELEMENTS;
/// The slot of an element that has none.
pub const NO_SLOT: u8 = u8::MAX;
/// The points of the target one piece of the worker draws (whole lines of the
/// rectangle, at least one): the work between two looks of the worker at the jobs of
/// the levels above, and the longest a post waits for a pass of a lower level.
pub const PIECE_POINTS: u32 = 4096;

/// The lines of a piece over a rectangle `w` points wide.
pub const fn piece_rows(w: u32) -> u32 {
    let rows = PIECE_POINTS / if w == 0 { 1 } else { w };
    if rows == 0 { 1 } else { rows }
}
/// The highest level the worker takes: the service's own is above it.
pub const LEVEL_MAX: u8 = 31;
/// The least target side and the greatest the pool allows an element.
const SIDE_MAX: u32 = 4096;

/// The slots of the elements of a scene, in the order of its elements.
pub type Map = [u8; MAX_ELEMENTS];
pub const NO_MAP: Map = [NO_SLOT; MAX_ELEMENTS];

/// What makes two elements the same image: the window, the rectangle of it, the
/// turn and reflection, the target's size, the filter, and whether the points
/// keep their alpha. The place of the target on the screen is no part of it, so
/// an element that moves keeps its image.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Key {
    pub source: u32,
    pub src: [i32; 4],
    pub size: [i32; 2],
    pub orient: u32,
    pub filter: u32,
    pub argb: bool,
}

/// Whether an element is made as an image of its own: it is not a plain copy of
/// the window's points.
pub fn needs(e: &Element) -> bool {
    !crate::elements::is_plain(e)
}

/// The key of element `e` of a window of `format`, None for an element that needs
/// no image.
pub fn key_of(e: &Element, format: Format) -> Option<Key> {
    needs(e).then_some(Key {
        source: e.source,
        src: [e.sx, e.sy, e.sw, e.sh],
        size: [e.dw, e.dh],
        orient: e.orient,
        filter: e.filter,
        argb: format == Format::Argb && e.transparency & TRANSPARENCY_SOURCE != 0,
    })
}

/// The element as the bands draw it from its prepared image: the image's points
/// as they are at the target (no turn, no stretch), with the element's alpha and
/// mask as before.
pub fn view(e: &Element) -> Element {
    Element {
        sx: 0,
        sy: 0,
        sw: e.dw << 16,
        sh: e.dh << 16,
        orient: 0,
        filter: 0,
        ..*e
    }
}

/// The element as the worker draws it: at the origin, with no transparency, the
/// map of its target's points (from the origin) to the window's.
pub fn local(e: &Element) -> Element {
    Element {
        dx: 0,
        dy: 0,
        transparency: 0,
        alpha: 255,
        mask: proto_comp::NO_WINDOW,
        ..*e
    }
}

/// What a slot holds: the key, the target's size and the pages of its two
/// images (the second follows the first), and the place of the window.
#[derive(Clone, Copy, Debug, Default)]
pub struct Geometry {
    pub key: Key,
    pub w: u32,
    pub h: u32,
    pub page: u16,
    /// The pages of one image.
    pub pages: u16,
    pub place: u8,
}

impl Geometry {
    pub const fn stride(&self) -> u32 {
        self.w * 4
    }

    pub const fn bytes(&self) -> usize {
        self.w as usize * self.h as usize * 4
    }
}

/// Why a reservation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refuse {
    /// The images do not fit the pool, even with nothing else in it.
    Full,
    /// They fit once the pages of the slots the worker still holds are free.
    Wait,
}

// The words a slot's state packs: the front image (bit 0), the image a frame
// holds (bits 1 and 2: 0 none, 1 or 2 the image plus one), the image the worker
// draws in (bits 3 and 4, the same), and whether an image was ever published
// (bit 5).
const FRONT: u32 = 1;
const HELD: u32 = 0b110;
const DRAWING: u32 = 0b11000;
const READY: u32 = 1 << 5;

const fn held_of(s: u32) -> u32 {
    (s & HELD) >> 1
}

/// The pages of one image of `key` (at least one), None for a target that is empty
/// or has a side past `SIDE_MAX`.
fn pages_of(key: &Key) -> Option<usize> {
    let (w, h) = (key.size[0], key.size[1]);
    if w <= 0 || h <= 0 || w as u32 > SIDE_MAX || h as u32 > SIDE_MAX {
        return None;
    }
    Some((w as usize * h as usize * 4).div_ceil(PAGE))
}

/// The bits `n` from `bit` in a word.
const fn word_mask(bit: usize, n: usize) -> u64 {
    if n == 64 {
        u64::MAX
    } else {
        ((1u64 << n) - 1) << bit
    }
}

/// The pages `first` and the `n` after it of a bitmap in use (`on`) or free.
fn set_in(words: &mut [u64; POOL_PAGES / 64], first: usize, n: usize, on: bool) {
    let mut p = first;
    let end = first + n;
    while p < end {
        let bit = p % 64;
        let take = (64 - bit).min(end - p);
        if on {
            words[p / 64] |= word_mask(bit, take);
        } else {
            words[p / 64] &= !word_mask(bit, take);
        }
        p += take;
    }
}

/// The first run of `n` free pages of a bitmap, found a word at a time.
fn find_in(words: &[u64; POOL_PAGES / 64], n: usize) -> Option<usize> {
    let (mut p, mut start, mut run) = (0, 0, 0);
    while p < POOL_PAGES {
        let word = words[p / 64] >> (p % 64);
        let left = 64 - p % 64;
        if word & 1 != 0 {
            // Used pages: the run so far ends.
            p += (word.trailing_ones() as usize).min(left);
            run = 0;
            continue;
        }
        if run == 0 {
            start = p;
        }
        let zeros = if word == 0 {
            left
        } else {
            word.trailing_zeros() as usize
        };
        run += zeros;
        p += zeros;
        if run >= n {
            return (start + n <= POOL_PAGES).then_some(start);
        }
    }
    None
}

/// The packed rectangle: x0, y0, x1, y1 in 16 bits each; 0 is empty.
const EMPTY: u64 = 0;

fn pack(r: Rect) -> u64 {
    let (x1, y1) = (r.x + r.w, r.y + r.h);
    u64::from(r.x) | u64::from(r.y) << 16 | u64::from(x1) << 32 | u64::from(y1) << 48
}

fn unpack(v: u64) -> Option<Rect> {
    let (x0, y0) = ((v & 0xFFFF) as u32, ((v >> 16) & 0xFFFF) as u32);
    let (x1, y1) = (((v >> 32) & 0xFFFF) as u32, ((v >> 48) & 0xFFFF) as u32);
    (x1 > x0 && y1 > y0).then_some(Rect {
        x: x0,
        y: y0,
        w: x1 - x0,
        h: y1 - y0,
    })
}

/// `cell` takes the union of itself and `r`.
fn add(cell: &AtomicU64, r: Rect) {
    let mut cur = cell.load(Acquire);
    loop {
        let sum = match unpack(cur) {
            Some(c) => pack(proto_comp::union(Some(c), r)),
            None => pack(r),
        };
        match cell.compare_exchange_weak(cur, sum, AcqRel, Acquire) {
            Ok(_) => return,
            Err(now) => cur = now,
        }
    }
}

/// The whole of a target of `w` by `h`.
fn whole(w: u32, h: u32) -> Rect {
    Rect { x: 0, y: 0, w, h }
}

struct Slot {
    used: AtomicBool,
    /// The worker held it when it was let go: its pages are free when the worker
    /// lets go (`Table::reap`).
    zombie: AtomicBool,
    geometry: UnsafeCell<Geometry>,
    state: AtomicU32,
    /// What each image still lacks: the damage since it was drawn.
    dirty: [AtomicU64; 2],
    /// What the worker drew since the service last asked, to be damage.
    drawn: AtomicU64,
    level: AtomicU8,
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            used: AtomicBool::new(false),
            zombie: AtomicBool::new(false),
            geometry: UnsafeCell::new(Geometry {
                key: Key {
                    source: 0,
                    src: [0; 4],
                    size: [0; 2],
                    orient: 0,
                    filter: 0,
                    argb: false,
                },
                w: 0,
                h: 0,
                page: 0,
                pages: 0,
                place: 0,
            }),
            state: AtomicU32::new(0),
            dirty: [AtomicU64::new(EMPTY), AtomicU64::new(EMPTY)],
            drawn: AtomicU64::new(EMPTY),
            level: AtomicU8::new(1),
        }
    }
}

/// What the worker reads of a window: its id, its stride, size and whether it
/// is of ARGB (a place the service made no window in has the id 0).
struct WindowInfo {
    id: AtomicU32,
    stride: AtomicU32,
    size: AtomicU32,
    argb: AtomicBool,
    /// The buffer that holds what the window shows now (the latest posted, or
    /// the current), 0xFF for none.
    latest: AtomicU8,
}

impl WindowInfo {
    const fn new() -> WindowInfo {
        WindowInfo {
            id: AtomicU32::new(0),
            stride: AtomicU32::new(0),
            size: AtomicU32::new(0),
            argb: AtomicBool::new(false),
            latest: AtomicU8::new(NO_BUFFER),
        }
    }
}

const NO_BUFFER: u8 = 0xFF;

/// The pool of the images, the slots and what the two threads tell each other.
pub struct Table {
    pool: AtomicPtr<u8>,
    slots: [Slot; SLOTS],
    /// The pages of the pool in use, a bit each.
    pages: [AtomicU64; POOL_PAGES / 64],
    windows: [WindowInfo; MAX_WINDOWS],
    /// The slots with work for the worker.
    want: AtomicU64,
    /// What the worker holds, as `claim` packs it; 0 for nothing.
    busy: AtomicU32,
    /// The service has put a free or an unmapping off until the worker lets go.
    waiting: AtomicBool,
    /// The slots let go that the worker still held.
    zombies: AtomicU32,
    /// The slots the worker could not draw in (the other image is a frame's).
    blocked: AtomicU64,
    /// The slots that have something drawn the service has not told.
    published: AtomicU64,
    /// The level the service last set the worker to (the service alone sets it).
    level: AtomicU8,
    /// The worker's claim moved to another buffer of the window while the service
    /// waited (`take_moved`): a free that waited for the old buffer can go.
    moved: AtomicBool,
}

// SAFETY: the one non-atomic field, the geometry of a slot, is written by the
// service alone while the slot is not used and the worker does not hold it
// (`reserve`), and read by the worker only while `busy` names the slot and the
// slot is used.
unsafe impl Sync for Table {}

impl Default for Table {
    fn default() -> Table {
        Table::new()
    }
}

/// What the worker holds: the slot (low byte, plus one), and when it is reading
/// a window the place and the buffer (the next bytes, plus one; 0 for none).
const fn claim(slot: usize, place: usize, buffer: u8) -> u32 {
    (slot as u32 + 1) | (place as u32 + 1) << 8 | (buffer as u32 + 1) << 16
}

const fn claim_slot(slot: usize) -> u32 {
    slot as u32 + 1
}

impl Table {
    pub const fn new() -> Table {
        Table {
            pool: AtomicPtr::new(core::ptr::null_mut()),
            slots: [const { Slot::new() }; SLOTS],
            pages: [const { AtomicU64::new(0) }; POOL_PAGES / 64],
            windows: [const { WindowInfo::new() }; MAX_WINDOWS],
            want: AtomicU64::new(0),
            busy: AtomicU32::new(0),
            waiting: AtomicBool::new(false),
            zombies: AtomicU32::new(0),
            blocked: AtomicU64::new(0),
            published: AtomicU64::new(0),
            level: AtomicU8::new(1),
            moved: AtomicBool::new(false),
        }
    }

    /// The pool's memory: `POOL_BYTES` bytes, writable, aligned to a page, that
    /// nothing else uses.
    pub fn set_pool(&self, base: *mut u8) {
        self.pool.store(base, Release);
    }

    // ------------------------------------------------------------ the service

    /// What the service tells of window `place` when it is ready to be read:
    /// its id, stride, size and whether the worker may read it.
    pub fn set_window(&self, place: usize, id: u32, format: Format, stride: u32, w: u32, h: u32) {
        let info = &self.windows[place];
        info.latest.store(NO_BUFFER, SeqCst);
        info.argb.store(format == Format::Argb, Relaxed);
        info.stride.store(stride, Relaxed);
        info.size.store(w << 16 | h, Relaxed);
        info.id.store(id, SeqCst);
    }

    /// The window of `place` is gone: the worker reads it no more once it lets go.
    pub fn clear_window(&self, place: usize) {
        let info = &self.windows[place];
        info.id.store(0, SeqCst);
        info.latest.store(NO_BUFFER, SeqCst);
    }

    /// Buffer `buffer` of window `place` is what the window shows now (a post):
    /// the worker reads it from the next piece.
    pub fn set_latest(&self, place: usize, buffer: u8) {
        self.windows[place].latest.store(buffer, SeqCst);
    }

    /// Whether the worker may be reading buffer `buffer` of window `place` (any
    /// buffer for None). The service asks before it frees a buffer or unmaps a
    /// window and puts the free off when the answer is yes; the question sets
    /// `waiting`, so that the worker tells the service when it lets go or moves to
    /// another buffer.
    pub fn reads(&self, place: usize, buffer: Option<u8>) -> bool {
        self.waiting.store(true, SeqCst);
        let b = self.busy.load(SeqCst);
        ((b >> 8) & 0xFF) as usize == place + 1
            && buffer.is_none_or(|k| ((b >> 16) & 0xFF) == u32::from(k) + 1)
    }

    /// Whether the worker holds slot `slot` (its pages are not free).
    fn holds(&self, slot: usize) -> bool {
        self.busy.load(SeqCst) & 0xFF == slot as u32 + 1
    }

    /// The geometry of slot `slot`, which must be used.
    pub fn geometry(&self, slot: usize) -> Geometry {
        *self.geometry_ref(slot)
    }

    fn geometry_ref(&self, slot: usize) -> &Geometry {
        // SAFETY: the service writes it only while the slot is not used.
        unsafe { &*self.slots[slot].geometry.get() }
    }

    pub fn used(&self, slot: usize) -> bool {
        self.slots[slot].used.load(Acquire)
    }

    /// The pages in use (a count).
    pub fn pages_used(&self) -> u32 {
        self.pages
            .iter()
            .map(|w| w.load(Relaxed).count_ones())
            .sum()
    }

    /// The pages `first` and the `n` after it are in use (`on`) or free, a word of
    /// the bitmap at a time.
    fn pages_set(&self, first: usize, n: usize, on: bool) {
        let mut p = first;
        let end = first + n;
        while p < end {
            let bit = p % 64;
            let take = (64 - bit).min(end - p);
            let mask = word_mask(bit, take);
            if on {
                self.pages[p / 64].fetch_or(mask, Relaxed);
            } else {
                self.pages[p / 64].fetch_and(!mask, Relaxed);
            }
            p += take;
        }
    }

    /// The bitmap as a plan sees it: a copy the plan changes and the table does not.
    fn page_words(&self) -> [u64; POOL_PAGES / 64] {
        let mut words = [0u64; POOL_PAGES / 64];
        for (w, a) in words.iter_mut().zip(self.pages.iter()) {
            *w = a.load(Relaxed);
        }
        words
    }

    /// The first run of `n` free pages of the table.
    #[cfg(test)]
    fn find_pages(&self, n: usize) -> Option<usize> {
        find_in(&self.page_words(), n)
    }

    /// Reserves the images of the elements of a scene in two phases. The plan reads
    /// the table and changes nothing: it finds the slots of the scenes that stay
    /// (`keep`) that an element shares by its key, the slots nothing holds any more
    /// (let go once the plan fits), and for the elements that need a new slot a slot
    /// and a run of pages in a copy of the bitmap with the pages of the slots to go
    /// free. The apply phase lets go of the slots and makes the new ones as planned.
    /// A refused reservation (Full: it does not fit the pool whatever the worker
    /// holds; Wait: it fits once the worker lets go of the slots it holds) leaves
    /// the table as it was. `wants[k]` is the key of element `k` that needs an image
    /// (with the place of its window), None for the others. A new slot is drawn whole
    /// at `level`.
    pub fn reserve(
        &self,
        wants: &[Option<(Key, usize)>],
        keep: &[&Map],
        level: u8,
    ) -> Result<Map, Refuse> {
        let made = self.reserve_planned(wants, keep, level);
        if made == Err(Refuse::Wait) {
            // The worker is to tell when it lets go of what the plan waits for.
            self.waiting.store(true, SeqCst);
        }
        made
    }

    fn reserve_planned(
        &self,
        wants: &[Option<(Key, usize)>],
        keep: &[&Map],
        level: u8,
    ) -> Result<Map, Refuse> {
        self.reap();
        let mut kept = [false; SLOTS];
        for m in keep {
            for &s in m.iter() {
                if s != NO_SLOT {
                    kept[s as usize] = true;
                }
            }
        }
        // The slots this scene shares: of the slots the scenes still hold, the one
        // with the element's key.
        let mut held = [0u8; SLOTS];
        let mut n = 0;
        for s in 0..SLOTS {
            if kept[s] && self.used(s) {
                held[n] = s as u8;
                n += 1;
            }
        }
        let mut map = NO_MAP;
        for (k, want) in wants.iter().enumerate().take(MAX_ELEMENTS) {
            let Some((key, place)) = want else {
                continue;
            };
            for &s in &held[..n] {
                let g = self.geometry_ref(usize::from(s));
                if g.key == *key && usize::from(g.place) == *place {
                    map[k] = s;
                    break;
                }
            }
        }
        let mut shared = kept;
        for &s in map.iter() {
            if s != NO_SLOT {
                shared[s as usize] = true;
            }
        }
        // The plan's view of the table: what is free after the slots to go are let
        // go. A slot the worker holds keeps its pages until the worker lets go.
        let mut words = self.page_words();
        let mut free = [false; SLOTS];
        let mut zombies = 0;
        for s in 0..SLOTS {
            if self.used(s) && !shared[s] {
                if self.holds(s) {
                    zombies += 1;
                } else {
                    let g = self.geometry_ref(s);
                    set_in(
                        &mut words,
                        usize::from(g.page),
                        2 * usize::from(g.pages),
                        false,
                    );
                    free[s] = true;
                }
            } else if !self.used(s) {
                if self.slots[s].zombie.load(SeqCst) {
                    zombies += 1;
                } else {
                    free[s] = true;
                }
            }
        }
        let short = |zombies: usize| {
            if zombies > 0 {
                Refuse::Wait
            } else {
                Refuse::Full
            }
        };
        // Where each new slot goes: (element, slot, first page).
        let mut placed: [Option<(usize, usize)>; MAX_ELEMENTS] = [None; MAX_ELEMENTS];
        for (k, want) in wants.iter().enumerate().take(MAX_ELEMENTS) {
            let Some((key, place)) = want else {
                continue;
            };
            if map[k] != NO_SLOT {
                continue;
            }
            // An element of the scene whose twin (the same key) is planned shares
            // the twin's slot.
            let twin = (0..k).find(|&j| {
                matches!(wants[j], Some((other, p)) if other == *key && p == *place)
                    && (map[j] != NO_SLOT || placed[j].is_some())
            });
            if let Some(j) = twin {
                map[k] = map[j];
                placed[k] = placed[j];
                continue;
            }
            let pages = pages_of(key).ok_or(Refuse::Full)?;
            if 2 * pages > POOL_PAGES {
                return Err(Refuse::Full);
            }
            let slot = (0..SLOTS)
                .find(|&s| free[s])
                .ok_or_else(|| short(zombies))?;
            let first = find_in(&words, 2 * pages).ok_or_else(|| short(zombies))?;
            free[slot] = false;
            set_in(&mut words, first, 2 * pages, true);
            map[k] = slot as u8;
            placed[k] = Some((slot, first));
        }
        // The apply phase: nothing refuses from here.
        for s in 0..SLOTS {
            if self.used(s) && !shared[s] {
                self.release(s);
            }
        }
        for (k, want) in wants.iter().enumerate().take(MAX_ELEMENTS) {
            let (Some((key, place)), Some((slot, first))) = (want, placed[k]) else {
                continue;
            };
            // A twin is made once, at the element that planned it first.
            if !self.slots[slot].used.load(Relaxed) {
                self.make_at(*key, *place, level, slot, first);
            }
        }
        Ok(map)
    }

    /// A slot and its two images for `key` at the planned place, drawn whole before
    /// it shows.
    fn make_at(&self, key: Key, place: usize, level: u8, s: usize, first: usize) {
        let (w, h) = (key.size[0] as u32, key.size[1] as u32);
        let pages = pages_of(&key).unwrap_or(0);
        self.pages_set(first, 2 * pages, true);
        let slot = &self.slots[s];
        // SAFETY: the slot is not used and no zombie: nothing reads it.
        unsafe {
            *slot.geometry.get() = Geometry {
                key,
                w,
                h,
                page: first as u16,
                pages: pages as u16,
                place: place as u8,
            };
        }
        slot.state.store(0, SeqCst);
        let all = pack(whole(w, h));
        slot.dirty[0].store(all, SeqCst);
        slot.dirty[1].store(all, SeqCst);
        slot.drawn.store(EMPTY, SeqCst);
        slot.level.store(level.clamp(1, LEVEL_MAX), SeqCst);
        slot.used.store(true, SeqCst);
        self.want.fetch_or(1 << s, SeqCst);
    }

    /// Slot `s` is let go: its pages are free now, or when the worker lets go of
    /// it.
    fn release(&self, s: usize) {
        let slot = &self.slots[s];
        slot.used.store(false, SeqCst);
        self.want.fetch_and(!(1 << s), SeqCst);
        self.blocked.fetch_and(!(1 << s), SeqCst);
        self.published.fetch_and(!(1 << s), SeqCst);
        if self.holds(s) {
            slot.zombie.store(true, SeqCst);
            self.zombies.fetch_add(1, SeqCst);
            self.waiting.store(true, SeqCst);
            // The worker may have let go between the look and the store.
            if !self.holds(s) {
                self.reap();
            }
        } else {
            self.free_pages(s);
        }
    }

    fn free_pages(&self, s: usize) {
        let g = self.geometry(s);
        self.pages_set(usize::from(g.page), 2 * usize::from(g.pages), false);
        if self.slots[s].zombie.swap(false, SeqCst) {
            self.zombies.fetch_sub(1, SeqCst);
        }
    }

    /// The pages of the slots the worker held when they were let go, free now
    /// that it lets go. The number of slots still held.
    pub fn reap(&self) -> usize {
        if self.zombies.load(SeqCst) == 0 {
            return 0;
        }
        let mut held = 0;
        for s in 0..SLOTS {
            if self.slots[s].zombie.load(SeqCst) {
                if self.holds(s) {
                    held += 1;
                } else {
                    self.free_pages(s);
                }
            }
        }
        held
    }

    /// Whether something the service put off waits for the worker to let go.
    pub fn deferred(&self) -> bool {
        self.waiting.load(SeqCst)
    }

    /// The service has seen the worker let go: nothing waits now.
    pub fn undefer(&self) {
        self.waiting.store(false, SeqCst);
    }

    /// Window `place` changed in `rect` of its own points at post: every slot of
    /// the window has its images behind by what the element carries of it
    /// (`local` is the rectangle of the target the service computed per slot).
    pub fn damage(&self, slot: usize, local: Rect, level: u8) {
        let s = &self.slots[slot];
        add(&s.dirty[0], local);
        add(&s.dirty[1], local);
        s.level.store(level.clamp(1, LEVEL_MAX), SeqCst);
        self.want.fetch_or(1 << slot, SeqCst);
    }

    /// The whole of slot `slot` is to be drawn again.
    pub fn damage_all(&self, slot: usize, level: u8) {
        let g = self.geometry(slot);
        self.damage(slot, whole(g.w, g.h), level);
    }

    /// The level the slot's work has.
    pub fn level_of(&self, slot: usize) -> u8 {
        self.slots[slot].level.load(Relaxed)
    }

    /// Whether the slots have work the worker can do: some slot wants it.
    pub fn work_waits(&self) -> bool {
        self.want.load(SeqCst) != 0
    }

    /// The highest level of the slots that want the worker, None when none does.
    pub fn top_level(&self) -> Option<u8> {
        let want = self.want.load(SeqCst);
        // The slot the worker holds is work in hand: its level counts too.
        let busy = (self.busy.load(SeqCst) & 0xFF) as usize;
        let held = busy.checked_sub(1).filter(|&s| s < SLOTS && self.used(s));
        (0..SLOTS)
            .filter(|&s| (want & (1 << s) != 0 && self.used(s)) || held == Some(s))
            .map(|s| self.level_of(s))
            .max()
    }

    /// The worker's claim moved since the last call.
    pub fn take_moved(&self) -> bool {
        self.moved.swap(false, SeqCst)
    }

    /// The image of `slot` that shows now (its front), None before the first.
    pub fn front_of(&self, slot: usize) -> Option<u8> {
        let st = self.slots[slot].state.load(Acquire);
        (st & READY != 0).then_some((st & FRONT) as u8)
    }

    /// The level the service last set the worker to.
    pub fn worker_level(&self) -> u8 {
        self.level.load(Relaxed)
    }

    pub fn set_worker_level(&self, level: u8) {
        self.level.store(level, Relaxed);
    }

    /// The frame takes the front image of `slot`: held until `frame_release`.
    /// None when no image was published yet.
    pub fn frame_take(&self, slot: usize) -> Option<u8> {
        let st = &self.slots[slot].state;
        let mut cur = st.load(Acquire);
        loop {
            if cur & READY == 0 {
                return None;
            }
            let front = cur & FRONT;
            let next = (cur & !HELD) | (front + 1) << 1;
            match st.compare_exchange_weak(cur, next, AcqRel, Acquire) {
                Ok(_) => return Some(front as u8),
                Err(now) => cur = now,
            }
        }
    }

    /// The frame is over: it holds no image of `slot`. The worker is told when it
    /// could not draw for the hold.
    pub fn frame_release(&self, slot: usize) {
        self.slots[slot].state.fetch_and(!HELD, AcqRel);
    }

    /// The slots the worker could not draw in because a frame held the image, to
    /// be drawn again now (returned and cleared).
    pub fn unblock(&self) -> bool {
        let b = self.blocked.swap(0, SeqCst);
        if b != 0 {
            self.want.fetch_or(b, SeqCst);
        }
        b != 0
    }

    /// The bytes of image `image` of slot `slot`.
    pub fn image(&self, slot: usize, image: u8) -> &[u8] {
        let g = self.geometry(slot);
        let at = (usize::from(g.page) + usize::from(image) * usize::from(g.pages)) * PAGE;
        let base = self.pool.load(Acquire);
        if base.is_null() {
            return &[];
        }
        // SAFETY: the pool is `POOL_BYTES` long and the slot's pages lie in it;
        // a frame reads the image it holds, which the worker does not write.
        unsafe { core::slice::from_raw_parts(base.add(at), g.bytes()) }
    }

    /// The target rectangle the worker drew of the first slot that has one since the
    /// last call: one slot a call, so that the service's step over an image stays
    /// short (`drawn_waits` says more are left).
    pub fn take_drawn(&self) -> Option<(usize, Rect)> {
        loop {
            let mask = self.published.load(SeqCst);
            if mask == 0 {
                return None;
            }
            let s = mask.trailing_zeros() as usize;
            self.published.fetch_and(!(1 << s), SeqCst);
            if let Some(r) = unpack(self.slots[s].drawn.swap(EMPTY, SeqCst)) {
                return Some((s, r));
            }
        }
    }

    /// Whether some slot has a rectangle drawn that `take_drawn` has not given.
    pub fn drawn_waits(&self) -> bool {
        self.published.load(SeqCst) != 0
    }

    // ------------------------------------------------------------ the worker

    /// The slot with work of the highest level, and its level.
    pub fn pick(&self) -> Option<(usize, u8)> {
        let want = self.want.load(SeqCst);
        let mut best: Option<(usize, u8)> = None;
        for s in 0..SLOTS {
            if want & (1 << s) != 0 && self.used(s) {
                let l = self.level_of(s);
                if best.is_none_or(|(_, b)| l > b) {
                    best = Some((s, l));
                }
            }
        }
        best
    }

    /// The slot the worker works on next: the pass in work (`job`) goes on unless a
    /// slot of a higher level wants the worker, and when no pass is in work the slot
    /// of the highest level that wants it. With its level.
    pub fn next(&self, job: &Job) -> Option<(usize, u8)> {
        let top = self.pick();
        let live = job.slot().map(|s| (s, self.level_of(s)));
        match (live, top) {
            (Some(l), Some(t)) if t.1 > l.1 => Some(t),
            (Some(l), _) => Some(l),
            (None, t) => t,
        }
    }

    /// The worker lets go of what it holds; true when the service waits for it
    /// (it is to be told).
    pub fn let_go(&self) -> bool {
        self.busy.store(0, SeqCst);
        self.waiting.load(SeqCst)
    }

    /// The worker reads the window of `slot` (which it holds): the buffer that
    /// window shows now, claimed. None when the slot is gone, or the window is not
    /// the slot's or has nothing to read; the claim is then the slot's alone.
    fn hold(&self, slot: usize) -> Option<(Geometry, Surface)> {
        self.hold_with(slot, &mut || {})
    }

    /// `hold` with a step the tests inject between the claim and the look that
    /// confirms it, where the service may move the window's buffer.
    fn hold_with(&self, slot: usize, between: &mut dyn FnMut()) -> Option<(Geometry, Surface)> {
        loop {
            if !self.used(slot) {
                return None;
            }
            let g = self.geometry(slot);
            let info = &self.windows[usize::from(g.place)];
            if info.id.load(SeqCst) != g.key.source {
                return None;
            }
            let b = info.latest.load(SeqCst);
            if b == NO_BUFFER {
                return None;
            }
            let now = claim(slot, usize::from(g.place), b);
            let before = self.busy.swap(now, SeqCst);
            // A claim that moves from a buffer to another is told to a service that
            // waits for the first.
            if before != now && before >> 8 != 0 && before >> 8 != now >> 8 {
                self.moved.store(true, SeqCst);
            }
            between();
            // The service may have changed what the window shows meanwhile.
            if self.used(slot)
                && info.id.load(SeqCst) == g.key.source
                && info.latest.load(SeqCst) == b
            {
                let size = info.size.load(Relaxed);
                return Some((
                    g,
                    Surface {
                        place: usize::from(g.place),
                        buffer: b,
                        stride: info.stride.load(Relaxed),
                        size: (size >> 16, size & 0xFFFF),
                        format: if info.argb.load(Relaxed) {
                            Format::Argb
                        } else {
                            Format::Xrgb
                        },
                    },
                ));
            }
            // The claim stays until the next look replaces it (or the pass lets
            // go): a free that waited for the old buffer is told when it moves.
        }
    }
}

/// The window the worker reads: its place, the buffer, the stride, the size and
/// the format.
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    pub place: usize,
    pub buffer: u8,
    pub stride: u32,
    pub size: (u32, u32),
    pub format: Format,
}

/// Where the windows' buffers are, for the worker: the bytes of buffer
/// `buffer` of window `place`, `len` of them.
pub trait Reads {
    fn read(&self, place: usize, buffer: u8, len: usize) -> &[u8];
}

/// What draws the images: the transform of a rectangle of a window into an
/// image of the target's size. The program's is pixman's (`px::Pixman`), the
/// tests' their own.
pub trait Maker {
    /// The points of `area` of the target (from its origin) of `element` (the
    /// element `local` makes) are drawn into `dst` (`stride` bytes a line, `size`
    /// points, ARGB8888 when `argb` and XRGB8888 when not) from `src`.
    #[allow(clippy::too_many_arguments)]
    fn make(
        &mut self,
        dst: &mut [u8],
        stride: u32,
        argb: bool,
        size: (u32, u32),
        element: &Element,
        src: &Surface2<'_>,
        area: Rect,
    );
}

/// The window the worker reads, as the maker sees it.
pub struct Surface2<'a> {
    pub bytes: &'a [u8],
    pub stride: u32,
    pub format: Format,
    pub size: (u32, u32),
    /// The number the raster's table of images knows the buffer by.
    pub image: usize,
}

/// How a piece of the worker's pass went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    /// Nothing to draw for the slot (or the slot or its window is gone).
    Idle,
    /// A frame holds the image the worker would draw in: the slot waits for the
    /// end of the frame (`Table::unblock`).
    Blocked,
    /// A piece was drawn and more is left.
    More,
    /// The image was drawn and shows now.
    Published,
}

/// The state of a pass between its pieces.
#[derive(Clone, Copy, Debug)]
pub struct Job {
    slot: usize,
    target: u8,
    /// The rectangle taken, and the next line of it to draw.
    rect: Option<Rect>,
    row: u32,
    /// What was drawn of the image so far.
    done: Option<Rect>,
    /// The damage that came during the pass was taken once already: what comes
    /// after waits for the next pass.
    extended: bool,
    live: bool,
}

impl Job {
    pub const NONE: Job = Job {
        slot: 0,
        target: 0,
        rect: None,
        row: 0,
        done: None,
        extended: false,
        live: false,
    };

    /// The slot the pass is at.
    pub fn slot(&self) -> Option<usize> {
        self.live.then_some(self.slot)
    }
}

impl Table {
    /// One piece of the worker's pass at `slot`, which `job` carries from piece
    /// to piece. The first piece holds the slot, takes the image to draw in (not
    /// the front, nor the one a frame holds) and the damage it lacks; a piece
    /// draws `PIECE_ROWS` lines of it; the piece that finds nothing left
    /// publishes the image. The pass holds the slot (`busy`) until the caller
    /// lets go (`let_go`) after a piece that is not `More`, or when it leaves the
    /// pass (`abandon`).
    pub fn piece<M: Maker>(
        &self,
        job: &mut Job,
        slot: usize,
        maker: &mut M,
        reads: &impl Reads,
    ) -> Pass {
        let s = &self.slots[slot];
        if !job.live || job.slot != slot {
            if job.live {
                self.abandon(job);
            }
            self.busy.store(claim_slot(slot), SeqCst);
            // Every Idle or Blocked return leaves the slot's bit clear (the
            // service sets it again with a notice), or the worker would be given
            // the same slot for ever.
            if !self.used(slot) {
                self.want.fetch_and(!(1 << slot), SeqCst);
                return Pass::Idle;
            }
            // The image the worker draws in: the one that is not the front, nor a
            // frame's.
            let mut cur = s.state.load(Acquire);
            let target = loop {
                let t = (cur & FRONT) ^ 1;
                if held_of(cur) == t + 1 {
                    self.blocked.fetch_or(1 << slot, SeqCst);
                    self.want.fetch_and(!(1 << slot), SeqCst);
                    // The frame may have ended after the look: the slot is drawn
                    // again.
                    if held_of(s.state.load(SeqCst)) != t + 1 {
                        self.unblock();
                        cur = s.state.load(Acquire);
                        continue;
                    }
                    return Pass::Blocked;
                }
                let next = (cur & !DRAWING) | (t + 1) << 3;
                match s.state.compare_exchange_weak(cur, next, AcqRel, Acquire) {
                    Ok(_) => break t as u8,
                    Err(now) => cur = now,
                }
            };
            self.want.fetch_and(!(1 << slot), SeqCst);
            let Some(rect) = unpack(s.dirty[usize::from(target)].swap(EMPTY, SeqCst)) else {
                s.state.fetch_and(!DRAWING, AcqRel);
                return Pass::Idle;
            };
            *job = Job {
                slot,
                target,
                rect: Some(rect),
                row: rect.y,
                done: None,
                extended: false,
                live: true,
            };
        }
        let Some((g, win)) = self.hold(slot) else {
            // The window has nothing to read (it has not posted, or it is gone): the
            // damage stays with the slot, and the slot wants the worker again when a
            // post comes (`damage`), never before, or the worker would spin on it.
            self.give_back(job, false);
            self.want.fetch_and(!(1 << slot), SeqCst);
            return Pass::Idle;
        };
        let Some(rect) = job.rect else {
            self.give_back(job, false);
            self.want.fetch_and(!(1 << slot), SeqCst);
            return Pass::Idle;
        };
        let end = (rect.y + rect.h).min(g.h);
        let rows = piece_rows(rect.w).min(end.saturating_sub(job.row));
        if rows > 0 {
            let area = Rect {
                x: rect.x,
                y: job.row,
                w: rect.w.min(g.w.saturating_sub(rect.x)),
                h: rows,
            };
            let at = (usize::from(g.page) + usize::from(job.target) * usize::from(g.pages)) * PAGE;
            let base = self.pool.load(Acquire);
            // SAFETY: the slot's pages are in the pool, and nothing reads or writes
            // the image the worker took (`DRAWING`).
            let dst = unsafe { core::slice::from_raw_parts_mut(base.add(at), g.bytes()) };
            let element = Element {
                source: g.key.source,
                sx: g.key.src[0],
                sy: g.key.src[1],
                sw: g.key.src[2],
                sh: g.key.src[3],
                dw: g.key.size[0],
                dh: g.key.size[1],
                orient: g.key.orient,
                filter: g.key.filter,
                ..Element::NONE
            };
            maker.make(
                dst,
                g.stride(),
                g.key.argb,
                (g.w, g.h),
                &local(&element),
                &Surface2 {
                    bytes: reads.read(
                        win.place,
                        win.buffer,
                        win.size.1 as usize * win.stride as usize,
                    ),
                    stride: win.stride,
                    format: win.format,
                    size: win.size,
                    image: crate::image_of(win.place, win.buffer),
                },
                area,
            );
            job.done = Some(proto_comp::union(job.done, area));
            job.row += rows;
            if job.row < end {
                return Pass::More;
            }
        }
        // The rectangle is drawn: the damage that came meanwhile is drawn too, once;
        // what comes after that waits for the next pass.
        if !job.extended
            && let Some(more) = unpack(s.dirty[usize::from(job.target)].swap(EMPTY, SeqCst))
        {
            job.extended = true;
            job.rect = Some(more);
            job.row = more.y;
            return Pass::More;
        }
        let mut cur = s.state.load(Acquire);
        loop {
            let next = ((cur & !(FRONT | DRAWING)) | u32::from(job.target)) | READY;
            match s.state.compare_exchange_weak(cur, next, AcqRel, Acquire) {
                Ok(_) => break,
                Err(now) => cur = now,
            }
        }
        // Damage that came after the last look is the next pass's: the image that
        // shows lacks it.
        if s.dirty[usize::from(job.target)].load(SeqCst) != EMPTY {
            self.want.fetch_or(1 << slot, SeqCst);
        }
        // What shows now is damage of the screen: the union of what the pass drew.
        if let Some(r) = job.done.take() {
            add(&s.drawn, r);
            self.published.fetch_or(1 << slot, SeqCst);
        }
        *job = Job::NONE;
        Pass::Published
    }

    /// The pass leaves its image undrawn because a job of a higher level goes first:
    /// what it took of the damage is given back, the image is free for the next pass,
    /// and the slot wants the worker again.
    pub fn abandon(&self, job: &mut Job) {
        self.give_back(job, true);
    }

    fn give_back(&self, job: &mut Job, rewant: bool) {
        if job.live {
            let s = &self.slots[job.slot];
            if let Some(rect) = job.rect {
                // The lines not yet drawn go back, with what the pass drew.
                let left = Rect {
                    x: rect.x,
                    y: job.row.min(rect.y + rect.h),
                    w: rect.w,
                    h: (rect.y + rect.h).saturating_sub(job.row),
                };
                if left.h > 0 && left.w > 0 {
                    add(&s.dirty[usize::from(job.target)], left);
                }
                if let Some(done) = job.done.take() {
                    add(&s.dirty[usize::from(job.target)], done);
                }
                if rewant {
                    self.want.fetch_or(1 << job.slot, SeqCst);
                }
            }
            s.state.fetch_and(!DRAWING, AcqRel);
        }
        *job = Job::NONE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rectangle_packs_and_unpacks_and_unions() {
        let r = Rect {
            x: 3,
            y: 4,
            w: 5,
            h: 6,
        };
        assert_eq!(unpack(pack(r)), Some(r));
        assert_eq!(unpack(EMPTY), None);
        let cell = AtomicU64::new(EMPTY);
        add(&cell, r);
        add(
            &cell,
            Rect {
                x: 10,
                y: 0,
                w: 2,
                h: 2,
            },
        );
        assert_eq!(
            unpack(cell.load(Relaxed)),
            Some(Rect {
                x: 3,
                y: 0,
                w: 9,
                h: 10
            })
        );
    }

    fn table() -> Table {
        let t = Table::new();
        let pool: &'static mut [u8] = Box::leak(vec![0u8; POOL_BYTES].into_boxed_slice());
        t.set_pool(pool.as_mut_ptr());
        t
    }

    fn key(source: u32, w: i32, h: i32) -> Key {
        Key {
            source,
            src: [0, 0, 64 << 16, 40 << 16],
            size: [w, h],
            orient: 1,
            filter: 0,
            argb: false,
        }
    }

    #[test]
    fn an_element_of_the_same_key_keeps_its_slot_and_one_that_goes_is_let_go() {
        let t = table();
        let a = t.reserve(&[Some((key(8, 64, 40), 0))], &[], 28).unwrap();
        assert_ne!(a[0], NO_SLOT);
        assert_eq!(t.pages_used(), 2 * 3);
        // The same key in the next scene shares the slot, with the scene still held.
        let b = t.reserve(&[Some((key(8, 64, 40), 0))], &[&a], 28).unwrap();
        assert_eq!(a[0], b[0]);
        assert_eq!(t.pages_used(), 2 * 3);
        // Another size is another slot; the old one stays while a scene holds it.
        let c = t.reserve(&[Some((key(8, 32, 20), 0))], &[&b], 28).unwrap();
        assert_ne!(c[0], b[0]);
        assert!(t.used(usize::from(b[0])));
        // The scenes that held the first are gone: it is let go.
        let d = t.reserve(&[Some((key(8, 32, 20), 0))], &[&c], 28).unwrap();
        assert_eq!(d[0], c[0]);
        assert!(!t.used(usize::from(b[0])));
        assert_eq!(t.pages_used(), 2);
    }

    #[test]
    fn a_reservation_that_fails_leaves_nothing_behind() {
        let t = table();
        let ok = t.reserve(&[Some((key(8, 64, 40), 0))], &[], 28).unwrap();
        let used = t.pages_used();
        // Too big for the pool at all.
        assert_eq!(
            t.reserve(&[None, Some((key(8, 1500, 700), 0))], &[&ok], 28),
            Err(Refuse::Full)
        );
        assert_eq!(t.pages_used(), used);
        assert!(t.used(usize::from(ok[0])));
    }

    #[test]
    fn the_pages_of_a_slot_the_worker_holds_are_free_when_it_lets_go() {
        let t = table();
        let big = key(8, 700, 350);
        let a = t.reserve(&[Some((big, 0))], &[], 28).unwrap();
        // The worker holds the slot while it goes: its pages wait.
        t.busy.store(claim_slot(usize::from(a[0])), SeqCst);
        let other = key(9, 700, 350);
        assert_eq!(t.reserve(&[Some((other, 0))], &[], 28), Err(Refuse::Wait));
        assert!(t.deferred());
        assert!(t.pages_used() > 0);
        assert!(t.let_go());
        t.undefer();
        assert_eq!(t.reap(), 0);
        let b = t.reserve(&[Some((other, 0))], &[], 28).unwrap();
        assert_ne!(b[0], NO_SLOT);
    }

    #[test]
    fn a_pass_given_up_gives_back_what_it_took_and_the_slot_wants_the_worker_again() {
        let t = table();
        let a = t.reserve(&[Some((key(8, 128, 64), 0))], &[], 28).unwrap();
        let slot = usize::from(a[0]);
        t.set_window(0, 8, Format::Xrgb, 512, 128, 64);
        t.set_latest(0, 0);
        struct Nothing;
        impl Maker for Nothing {
            fn make(
                &mut self,
                _: &mut [u8],
                _: u32,
                _: bool,
                _: (u32, u32),
                _: &Element,
                _: &Surface2<'_>,
                _: Rect,
            ) {
            }
        }
        struct Window(Vec<u8>);
        impl Reads for Window {
            fn read(&self, _: usize, _: u8, _: usize) -> &[u8] {
                &self.0
            }
        }
        let win = Window(vec![0; 512 * 64]);
        let mut job = Job::NONE;
        assert_eq!(t.piece(&mut job, slot, &mut Nothing, &win), Pass::More);
        assert!(!t.work_waits());
        t.abandon(&mut job);
        assert!(t.work_waits());
        // The same pass again draws what is left, the whole image, and shows it.
        let mut job = Job::NONE;
        let mut passes = 0;
        loop {
            passes += 1;
            match t.piece(&mut job, slot, &mut Nothing, &win) {
                Pass::More => {}
                Pass::Published => break,
                other => panic!("{other:?}"),
            }
        }
        // 64 lines in pieces of 32 lines (4096 points over 128): two pieces, the last
        // publishes.
        assert_eq!(passes, 2);
        assert_eq!(t.front_of(slot), Some(1));
    }

    #[test]
    fn runs_of_pages_are_found_and_set_across_the_words_of_the_bitmap() {
        let t = table();
        assert_eq!(t.find_pages(POOL_PAGES), Some(0));
        assert_eq!(t.find_pages(POOL_PAGES + 1), None);
        t.pages_set(3, 70, true);
        assert_eq!(t.pages_used(), 70);
        // The first run that fits is before the used pages when it is short, after
        // them when it is long.
        assert_eq!(t.find_pages(3), Some(0));
        assert_eq!(t.find_pages(4), Some(73));
        assert_eq!(t.find_pages(POOL_PAGES - 73), Some(73));
        assert_eq!(t.find_pages(POOL_PAGES - 72), None);
        t.pages_set(3, 70, false);
        assert_eq!(t.pages_used(), 0);
        t.pages_set(0, POOL_PAGES, true);
        assert_eq!(t.pages_used() as usize, POOL_PAGES);
        assert_eq!(t.find_pages(1), None);
        t.pages_set(127, 2, false);
        assert_eq!(t.find_pages(2), Some(127));
        assert_eq!(t.find_pages(3), None);
    }

    #[test]
    fn a_slot_whose_window_has_posted_nothing_does_not_keep_the_worker_busy() {
        let t = table();
        let a = t.reserve(&[Some((key(8, 64, 40), 0))], &[], 28).unwrap();
        let slot = usize::from(a[0]);
        struct Nothing;
        impl Maker for Nothing {
            fn make(
                &mut self,
                _: &mut [u8],
                _: u32,
                _: bool,
                _: (u32, u32),
                _: &Element,
                _: &Surface2<'_>,
                _: Rect,
            ) {
            }
        }
        struct Window(Vec<u8>);
        impl Reads for Window {
            fn read(&self, _: usize, _: u8, _: usize) -> &[u8] {
                &self.0
            }
        }
        let win = Window(vec![0; 256 * 40]);
        let mut job = Job::NONE;
        // The window was not told to the table: the pass ends and the slot waits.
        assert_eq!(t.piece(&mut job, slot, &mut Nothing, &win), Pass::Idle);
        t.let_go();
        assert_eq!(t.next(&job), None);
        assert!(!t.work_waits());
        // The post comes: the slot has its whole image to draw.
        t.set_window(0, 8, Format::Xrgb, 256, 64, 40);
        t.set_latest(0, 0);
        t.damage(
            slot,
            Rect {
                x: 0,
                y: 0,
                w: 4,
                h: 4,
            },
            28,
        );
        let mut passes = 0;
        while let Some((s, _)) = t.next(&job) {
            passes += 1;
            assert!(passes < 10);
            if t.piece(&mut job, s, &mut Nothing, &win) != Pass::More {
                t.let_go();
            }
        }
        assert_eq!(t.front_of(slot), Some(1));
        let drawn = t.take_drawn().unwrap();
        assert_eq!(
            drawn,
            (
                slot,
                Rect {
                    x: 0,
                    y: 0,
                    w: 64,
                    h: 40
                }
            )
        );
    }

    struct NoMaker;

    impl Maker for NoMaker {
        fn make(
            &mut self,
            _: &mut [u8],
            _: u32,
            _: bool,
            _: (u32, u32),
            _: &Element,
            _: &Surface2<'_>,
            _: Rect,
        ) {
        }
    }

    struct Flat(Vec<u8>);

    impl Reads for Flat {
        fn read(&self, _: usize, _: u8, _: usize) -> &[u8] {
            &self.0
        }
    }

    /// The worker's loop as the service runs it: pieces while a slot is next, every
    /// pass that ends lets go. The slots a pass ended on.
    fn run(t: &Table, job: &mut Job, win: &Flat) -> Vec<(usize, Pass)> {
        let mut ended = Vec::new();
        let mut guard = 0;
        while let Some((slot, _)) = t.next(job) {
            guard += 1;
            assert!(guard < 1000, "the worker spins");
            let pass = t.piece(job, slot, &mut NoMaker, win);
            match pass {
                Pass::More => {}
                Pass::Published => {
                    t.let_go();
                    ended.push((slot, pass));
                }
                Pass::Idle | Pass::Blocked => {
                    // Every Idle or Blocked return has cleared the slot's bit.
                    assert_eq!(t.want.load(SeqCst) & (1 << slot), 0, "slot {slot} {pass:?}");
                    t.let_go();
                    ended.push((slot, pass));
                }
            }
        }
        ended
    }

    #[test]
    fn slots_of_windows_not_posted_yet_do_not_starve_a_later_slot_of_a_posted_window() {
        let t = table();
        // Three elements: two show windows that have posted nothing, the last a
        // posted static window.
        let wants = [
            Some((key(8, 64, 40), 0)),
            Some((key(9, 64, 40), 1)),
            Some((key(10, 64, 40), 2)),
        ];
        let map = t.reserve(&wants, &[], 28).unwrap();
        t.set_window(2, 10, Format::Xrgb, 256, 64, 40);
        t.set_latest(2, 0);
        let win = Flat(vec![0; 256 * 40]);
        let mut job = Job::NONE;
        let ended = run(&t, &mut job, &win);
        assert!(ended.contains(&(usize::from(map[2]), Pass::Published)));
        assert!(ended.contains(&(usize::from(map[0]), Pass::Idle)));
        assert!(ended.contains(&(usize::from(map[1]), Pass::Idle)));
        assert_eq!(t.front_of(usize::from(map[2])), Some(1));
        assert_eq!(t.front_of(usize::from(map[0])), None);
        // Nothing wants the worker now, and a later post wakes a slot again.
        assert!(!t.work_waits());
        t.set_window(0, 8, Format::Xrgb, 256, 64, 40);
        t.set_latest(0, 0);
        t.damage(
            usize::from(map[0]),
            Rect {
                x: 0,
                y: 0,
                w: 2,
                h: 2,
            },
            28,
        );
        let ended = run(&t, &mut job, &win);
        assert_eq!(ended, vec![(usize::from(map[0]), Pass::Published)]);
    }

    #[test]
    fn a_slot_a_frame_holds_blocks_until_the_frame_ends_and_clears_its_bit() {
        let t = table();
        let map = t.reserve(&[Some((key(8, 64, 40), 0))], &[], 28).unwrap();
        let slot = usize::from(map[0]);
        t.set_window(0, 8, Format::Xrgb, 256, 64, 40);
        t.set_latest(0, 0);
        let win = Flat(vec![0; 256 * 40]);
        let mut job = Job::NONE;
        run(&t, &mut job, &win);
        let held = t.frame_take(slot).unwrap();
        t.damage(
            slot,
            Rect {
                x: 0,
                y: 0,
                w: 4,
                h: 4,
            },
            28,
        );
        run(&t, &mut job, &win);
        // The front is now the other image; the next post finds the held one.
        assert_ne!(t.front_of(slot), Some(held));
        t.damage(
            slot,
            Rect {
                x: 0,
                y: 0,
                w: 4,
                h: 4,
            },
            28,
        );
        let ended = run(&t, &mut job, &win);
        assert_eq!(ended, vec![(slot, Pass::Blocked)]);
        assert!(!t.work_waits());
        t.frame_release(slot);
        assert!(t.unblock());
        let ended = run(&t, &mut job, &win);
        assert_eq!(ended, vec![(slot, Pass::Published)]);
    }

    #[test]
    fn a_refused_reservation_leaves_the_slots_the_pages_and_the_bits_as_they_were() {
        let t = table();
        let old = t
            .reserve(
                &[Some((key(8, 64, 40), 0)), Some((key(8, 32, 20), 0))],
                &[],
                28,
            )
            .unwrap();
        let before = (t.pages_used(), t.want.load(SeqCst));
        let used: Vec<bool> = (0..SLOTS).map(|s| t.used(s)).collect();
        // Sixteen new keys, the first fifteen small and the last too big for what
        // is left: the old slots are dead (no scene keeps them) and stay.
        let mut wants = Vec::new();
        for k in 0..15 {
            wants.push(Some((key(20 + k, 100, 100), 1)));
        }
        wants.push(Some((key(99, 700, 350), 1)));
        assert_eq!(t.reserve(&wants, &[], 28), Err(Refuse::Full));
        assert_eq!(before, (t.pages_used(), t.want.load(SeqCst)));
        let after: Vec<bool> = (0..SLOTS).map(|s| t.used(s)).collect();
        assert_eq!(used, after);
        assert!(t.used(usize::from(old[0])));
        // The same wants without the last element go through, and the dead slots go.
        let ok = t.reserve(&wants[..15], &[], 28).unwrap();
        assert!(ok[..15].iter().all(|&s| s != NO_SLOT));
        // The old slots' pages went: only the fifteen new slots hold pages.
        assert_eq!(t.pages_used(), 15 * 2 * 10);
    }

    #[test]
    fn a_reservation_that_waits_for_the_worker_changes_nothing_and_asks_to_be_told() {
        let t = table();
        let a = t.reserve(&[Some((key(8, 700, 350), 0))], &[], 28).unwrap();
        t.busy.store(claim_slot(usize::from(a[0])), SeqCst);
        let used = t.pages_used();
        assert_eq!(
            t.reserve(&[Some((key(9, 700, 350), 0))], &[], 28),
            Err(Refuse::Wait)
        );
        assert!(t.deferred());
        // The slot to go is still there, not yet a zombie.
        assert!(t.used(usize::from(a[0])));
        assert_eq!(t.pages_used(), used);
    }

    #[test]
    fn the_claim_moves_with_the_window_and_a_buffer_the_worker_left_can_be_freed() {
        let t = table();
        let a = t.reserve(&[Some((key(8, 64, 40), 0))], &[], 28).unwrap();
        let slot = usize::from(a[0]);
        t.set_window(0, 8, Format::Xrgb, 256, 64, 40);
        t.set_latest(0, 0);
        // The service moves the window to buffer 1 between the worker's claim of
        // buffer 0 and the look that confirms it.
        let mut once = true;
        let (_, win) = t
            .hold_with(slot, &mut || {
                if once {
                    once = false;
                    t.set_latest(0, 1);
                    // The service frees buffer 0 of the window now: the worker may
                    // be reading it.
                    assert!(t.reads(0, Some(0)));
                }
            })
            .expect("a window to read");
        assert_eq!(win.buffer, 1);
        assert!(t.take_moved());
        // The claim is buffer 1 now: buffer 0 can go, buffer 1 waits.
        assert!(!t.reads(0, Some(0)));
        assert!(t.reads(0, Some(1)));
        assert!(t.let_go());
        assert!(!t.reads(0, Some(1)));
    }

    #[test]
    fn damage_that_comes_during_a_pass_is_drawn_once_and_the_rest_is_the_next_passes() {
        let t = table();
        let a = t.reserve(&[Some((key(8, 128, 64), 0))], &[], 28).unwrap();
        let slot = usize::from(a[0]);
        t.set_window(0, 8, Format::Xrgb, 512, 128, 64);
        t.set_latest(0, 0);
        let win = Flat(vec![0; 512 * 64]);
        let mut job = Job::NONE;
        // The first piece takes the whole damage; two posts come meanwhile.
        assert_eq!(t.piece(&mut job, slot, &mut NoMaker, &win), Pass::More);
        t.damage(
            slot,
            Rect {
                x: 0,
                y: 0,
                w: 8,
                h: 8,
            },
            28,
        );
        loop {
            match t.piece(&mut job, slot, &mut NoMaker, &win) {
                Pass::More => {
                    // A second post in the extension is the next pass's.
                    t.damage(
                        slot,
                        Rect {
                            x: 8,
                            y: 0,
                            w: 8,
                            h: 8,
                        },
                        28,
                    );
                }
                Pass::Published => break,
                other => panic!("{other:?}"),
            }
        }
        t.let_go();
        // The image shows, and the slot wants the worker for what came last.
        assert_eq!(t.front_of(slot), Some(1));
        assert!(t.work_waits());
    }

    #[test]
    fn the_level_of_the_worker_is_that_of_the_work_it_holds_as_well_as_the_work_that_waits() {
        let t = table();
        let a = t.reserve(&[Some((key(8, 64, 40), 0))], &[], 28).unwrap();
        let slot = usize::from(a[0]);
        assert_eq!(t.top_level(), Some(28));
        // The worker took the slot's bit and holds the slot: its level still counts.
        t.want.fetch_and(!(1 << slot), SeqCst);
        t.busy.store(claim_slot(slot), SeqCst);
        assert_eq!(t.top_level(), Some(28));
        t.let_go();
        assert_eq!(t.top_level(), None);
    }
}
