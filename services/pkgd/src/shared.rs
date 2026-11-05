// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the two threads share. The worker thread fills the table of the
//! store, the packages of the disk and the blobs while `STARTING` is set and
//! publishes each package with a flag (`PUBLISHED`, release and acquire);
//! once `STARTING` clears the main thread owns them all.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use pkgd::packages::Entry;
use pkgd::store::{PACKAGES, Table};
use pkgfmt::Key;
use rt::Handle;
use rt::handle::Memory;

/// A static the threads share by the rules above.
pub struct Shared<T>(UnsafeCell<T>);
// SAFETY: the rules above give each access one thread at a time.
unsafe impl<T> Sync for Shared<T> {}

impl<T> Shared<T> {
    pub const fn new(value: T) -> Shared<T> {
        Shared(UnsafeCell::new(value))
    }

    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// The most packages of the boot image the service lists.
pub const IMAGE_MAX: usize = 16;
/// The most entries of the revocation list that count.
pub const REVOKED_MAX: usize = 128;
/// The most bytes of the revocation list file: the text and its block.
pub const REVOKED_FILE_MAX: usize = 16 * 1024 + 456;

pub static TABLE: Shared<Table> = Shared::new(Table::zeroed());
pub static SETTINGS: Shared<[u8; 64 * 1024]> = Shared::new([0; 64 * 1024]);
pub static CONTAINER: Shared<[u8; pkgd::settings::CONTAINER_MAX]> =
    Shared::new([0; pkgd::settings::CONTAINER_MAX]);
pub static REVOKED_FILE: Shared<[u8; REVOKED_FILE_MAX]> = Shared::new([0; REVOKED_FILE_MAX]);
pub static DISK_ENTRIES: Shared<[Option<Entry>; PACKAGES]> =
    Shared::new([const { None }; PACKAGES]);
pub static IMAGE_ENTRIES: Shared<[Option<Entry>; IMAGE_MAX]> =
    Shared::new([const { None }; IMAGE_MAX]);
/// The objects of the packages, and of the settings layer in the place after them.
pub static OBJECTS: Shared<[Option<Handle<Memory>>; PACKAGES + 1]> =
    Shared::new([const { None }; PACKAGES + 1]);
pub static KEY: Shared<Option<Key>> = Shared::new(None);
pub static PUBLISHED: [AtomicBool; PACKAGES] = [const { AtomicBool::new(false) }; PACKAGES];

pub static STARTING: AtomicBool = AtomicBool::new(true);
pub static DAMAGED: AtomicBool = AtomicBool::new(false);
pub static READ_ONLY: AtomicBool = AtomicBool::new(false);
pub static GENERATION: AtomicU64 = AtomicU64::new(0);
pub static FREE: AtomicU64 = AtomicU64::new(0);
pub static BLOCKS: AtomicU64 = AtomicU64::new(0);
pub static DISK_PACKAGES: AtomicU32 = AtomicU32::new(0);
pub static IMAGE_PACKAGES: AtomicU32 = AtomicU32::new(0);
pub static SETTINGS_LEN: AtomicUsize = AtomicUsize::new(0);
pub static LAYER: AtomicU32 = AtomicU32::new(0);
pub static HASH_TICKS: AtomicU64 = AtomicU64::new(0);
pub static CHECK_TICKS: AtomicU64 = AtomicU64::new(0);

/// The label of the notification of a layer released (plus the number of
/// the layer), and of the worker's that it is done.
pub const LABEL_LAYER: u64 = 0x504b_0000;
pub const LABEL_DONE: u64 = 0x504b_0fff;
/// The level of the main thread, the one the notifications carry.
pub const MAIN_LEVEL: u8 = 32;

/// Where the worker maps the object of package `slot` (the settings layer
/// has the slot after the last package).
pub const fn window(slot: usize) -> usize {
    0x20_0000_0000 + slot * (1 << 30)
}

/// A reading of the counter, for the longest of a kind of work.
pub struct Stopwatch(u64);

impl Stopwatch {
    pub fn new() -> Stopwatch {
        Stopwatch(rt::time::now())
    }

    pub fn keep(self, longest: &AtomicU64) {
        longest.fetch_max(rt::time::now().wrapping_sub(self.0), Ordering::Relaxed);
    }
}
