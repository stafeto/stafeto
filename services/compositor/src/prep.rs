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
/// The lines of the target one piece of the worker draws: the points between two
/// looks of the worker at the jobs of the levels above.
pub const PIECE_ROWS: u32 = 16;
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
    /// The slots the worker could not draw in (the other image is a frame's).
    blocked: AtomicU64,
    /// The slots that have something drawn the service has not told.
    published: AtomicU64,
    /// The level the worker runs at now.
    level: AtomicU8,
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
            blocked: AtomicU64::new(0),
            published: AtomicU64::new(0),
            level: AtomicU8::new(1),
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

    /// Whether the worker may be reading buffer `buffer` of window `place`
    /// (`any` buffer for None); the service puts the free of such a buffer off
    /// (`waiting`).
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
        // SAFETY: the service writes it only while the slot is not used.
        unsafe { *self.slots[slot].geometry.get() }
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

    fn pages_range_free(&self, first: usize, n: usize) -> bool {
        (first..first + n).all(|p| self.pages[p / 64].load(Relaxed) & (1 << (p % 64)) == 0)
    }

    fn pages_set(&self, first: usize, n: usize, on: bool) {
        for p in first..first + n {
            let bit = 1u64 << (p % 64);
            if on {
                self.pages[p / 64].fetch_or(bit, Relaxed);
            } else {
                self.pages[p / 64].fetch_and(!bit, Relaxed);
            }
        }
    }

    fn find_pages(&self, n: usize) -> Option<usize> {
        let mut first = 0;
        while first + n <= POOL_PAGES {
            // The next used page at or after `first` bounds the try.
            match (first..first + n).find(|&p| !self.pages_range_free(p, 1)) {
                None => return Some(first),
                Some(used) => first = used + 1,
            }
        }
        None
    }

    /// Reserves the images of the elements of a scene. `wants[k]` is the key of
    /// element `k` that needs an image (with the place of its window), None for
    /// the others; the slots `keep` hold (the scenes still in use) stay as they
    /// are and an element of a key they hold shares its slot. The slots no map of
    /// `keep` has are let go first. On success the map of the new scene;
    /// nothing a failure allocated stays. A new slot is to be drawn whole: its
    /// level is `level`.
    pub fn reserve(
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
        // The slots this scene shares.
        let mut map = NO_MAP;
        for (k, want) in wants.iter().enumerate().take(MAX_ELEMENTS) {
            let Some((key, place)) = want else {
                continue;
            };
            for s in 0..SLOTS {
                if kept[s] && self.used(s) && self.slots[s].used.load(Relaxed) {
                    let g = self.geometry(s);
                    if g.key == *key && usize::from(g.place) == *place {
                        map[k] = s as u8;
                        break;
                    }
                }
            }
        }
        let mut shared = kept;
        for &s in map.iter() {
            if s != NO_SLOT {
                shared[s as usize] = true;
            }
        }
        // What nothing holds any more is let go.
        for s in 0..SLOTS {
            if self.used(s) && !shared[s] {
                self.release(s);
            }
        }
        // The new ones, in the order of the elements; a failure lets them go.
        let mut made = [false; SLOTS];
        let mut result = Ok(());
        for (k, want) in wants.iter().enumerate().take(MAX_ELEMENTS) {
            let Some((key, place)) = want else {
                continue;
            };
            if map[k] != NO_SLOT {
                continue;
            }
            // An element of the scene that the new slots of it already made for
            // the same key shares that slot.
            let twin = (0..k).find(|&j| {
                matches!(wants[j], Some((other, p)) if other == *key && p == *place)
                    && map[j] != NO_SLOT
            });
            if let Some(j) = twin {
                map[k] = map[j];
                continue;
            }
            match self.make(*key, *place, level) {
                Ok(s) => {
                    map[k] = s as u8;
                    made[s] = true;
                }
                Err(why) => {
                    result = Err(why);
                    break;
                }
            }
        }
        if let Err(why) = result {
            for s in 0..SLOTS {
                if made[s] {
                    self.release(s);
                }
            }
            return Err(why);
        }
        Ok(map)
    }

    /// A slot and its two images for `key`, drawn whole before it shows.
    fn make(&self, key: Key, place: usize, level: u8) -> Result<usize, Refuse> {
        let (w, h) = (key.size[0], key.size[1]);
        if w <= 0 || h <= 0 || w as u32 > SIDE_MAX || h as u32 > SIDE_MAX {
            return Err(Refuse::Full);
        }
        let (w, h) = (w as u32, h as u32);
        let pages = (w as usize * h as usize * 4).div_ceil(PAGE);
        if 2 * pages > POOL_PAGES {
            return Err(Refuse::Full);
        }
        let Some(s) = (0..SLOTS)
            .find(|&s| !self.slots[s].used.load(Relaxed) && !self.slots[s].zombie.load(Relaxed))
        else {
            return Err(Refuse::Wait);
        };
        let Some(first) = self.find_pages(2 * pages) else {
            // Whether the pool would have room with the zombies' pages free.
            let held = (0..SLOTS)
                .filter(|&z| self.slots[z].zombie.load(Relaxed))
                .count();
            return Err(if held > 0 { Refuse::Wait } else { Refuse::Full });
        };
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
        Ok(s)
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
        self.slots[s].zombie.store(false, SeqCst);
    }

    /// The pages of the slots the worker held when they were let go, free now
    /// that it lets go. The number of slots still held.
    pub fn reap(&self) -> usize {
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
        (0..SLOTS)
            .filter(|&s| want & (1 << s) != 0 && self.used(s))
            .map(|s| self.level_of(s))
            .max()
    }

    /// The image of `slot` that shows now (its front), None before the first.
    pub fn front_of(&self, slot: usize) -> Option<u8> {
        let st = self.slots[slot].state.load(Acquire);
        (st & READY != 0).then_some((st & FRONT) as u8)
    }

    /// The level the worker runs at, as the service last set it.
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

    /// The target rectangles the worker drew since the last call, per slot.
    pub fn take_drawn(&self, out: &mut [(usize, Rect); SLOTS]) -> usize {
        let mut n = 0;
        let mask = self.published.swap(0, SeqCst);
        for s in 0..SLOTS {
            if mask & (1 << s) != 0
                && let Some(r) = unpack(self.slots[s].drawn.swap(EMPTY, SeqCst))
            {
                out[n] = (s, r);
                n += 1;
            }
        }
        n
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
            self.busy
                .store(claim(slot, usize::from(g.place), b), SeqCst);
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
            self.busy.store(claim_slot(slot), SeqCst);
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
    live: bool,
}

impl Job {
    pub const NONE: Job = Job {
        slot: 0,
        target: 0,
        rect: None,
        row: 0,
        done: None,
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
            if !self.used(slot) {
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
                live: true,
            };
        }
        let Some((g, win)) = self.hold(slot) else {
            self.abandon(job);
            return Pass::Idle;
        };
        let Some(rect) = job.rect else {
            self.abandon(job);
            return Pass::Idle;
        };
        let end = (rect.y + rect.h).min(g.h);
        let rows = PIECE_ROWS.min(end.saturating_sub(job.row));
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
        // The rectangle is drawn: damage that came meanwhile is drawn too, and
        // then the image shows.
        if let Some(more) = unpack(s.dirty[usize::from(job.target)].swap(EMPTY, SeqCst)) {
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
        // What shows now is damage of the screen: the union of what the pass drew.
        if let Some(r) = job.done.take() {
            add(&s.drawn, r);
            self.published.fetch_or(1 << slot, SeqCst);
        }
        *job = Job::NONE;
        Pass::Published
    }

    /// The pass leaves its image undrawn (a job of a higher level goes first, or
    /// the slot is gone): what it took of the damage is given back, the image is
    /// free for the next pass.
    pub fn abandon(&self, job: &mut Job) {
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
                self.want.fetch_or(1 << job.slot, SeqCst);
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
        let a = t.reserve(&[Some((key(8, 64, 40), 0))], &[], 28).unwrap();
        let slot = usize::from(a[0]);
        t.set_window(0, 8, Format::Xrgb, 256, 64, 40);
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
        let win = Window(vec![0; 256 * 40]);
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
        // 40 lines in pieces of 16 lines: three pieces, the last publishes.
        assert_eq!(passes, 3);
        assert_eq!(t.front_of(slot), Some(1));
    }
}
