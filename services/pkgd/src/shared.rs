// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the two threads share. The worker thread fills the table of the
//! store, the packages of the disk and the blobs while `STARTING` is set and
//! publishes each package with a flag (`PUBLISHED`, release and acquire);
//! once `STARTING` clears the main thread owns them all.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use pkgd::commit::Opened;
use pkgd::packages::Entry;
use pkgd::receipts::{GROUP_MAX, Group, GroupTable};
use pkgd::store::{PACKAGES, RECORDS, Table};
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

pub use pkgd::packages::IMAGE_MAX;
/// The most bytes of the revocation list file: the text and its block.
pub const REVOKED_FILE_MAX: usize = 16 * 1024 + 456;

pub static TABLE: Shared<Table> = Shared::new(Table::zeroed());
/// A blob of 64 KiB on a page: the copy of 16 KiB the main thread makes from it runs a word at a
/// time only when the bytes are aligned (a copy from a byte-aligned place costs four times the ticks).
#[repr(C, align(4096))]
pub struct Blob(pub [u8; 64 * 1024]);

impl core::ops::Deref for Blob {
    type Target = [u8; 64 * 1024];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for Blob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub static SETTINGS: Shared<Blob> = Shared::new(Blob([0; 64 * 1024]));
/// The blob and the list of a change in the making: copied from the buffer of the
/// client, checked, then written; the live ones above are replaced when the change is the state.
pub static NEW_BLOB: Shared<Blob> = Shared::new(Blob([0; 64 * 1024]));
pub static NEW_LIST: Shared<[u8; 5 * 4096]> = Shared::new([0; 5 * 4096]);
/// The table of the next state (the worker's) and the layers its change touches.
pub static NEXT: Shared<GroupTable> = Shared::new(GroupTable::new());
/// What the worker holds of the store: the state `TABLE` is the table of.
pub static OPENED: Shared<Option<Opened>> = Shared::new(None);
/// The open group and the entries of the packages it has checked, in the order it stages them.
pub static GROUP: Shared<Group> = Shared::new(Group::new());
pub static STAGED: Shared<[Option<Entry>; GROUP_MAX]> = Shared::new([const { None }; GROUP_MAX]);
/// The layer number of each place of the table while its layer is attached, 0 when none.
pub static LAYER_OF: Shared<[u32; RECORDS + 1]> = Shared::new([0; RECORDS + 1]);
pub static CONTAINER: Shared<[u8; pkgd::settings::CONTAINER_MAX]> =
    Shared::new([0; pkgd::settings::CONTAINER_MAX]);
pub static REVOKED_FILE: Shared<[u8; REVOKED_FILE_MAX]> = Shared::new([0; REVOKED_FILE_MAX]);
pub static DISK_ENTRIES: Shared<[Option<Entry>; PACKAGES]> =
    Shared::new([const { None }; PACKAGES]);
pub static IMAGE_ENTRIES: Shared<[Option<Entry>; IMAGE_MAX]> =
    Shared::new([const { None }; IMAGE_MAX]);
/// The objects of the packages by place of the table, the settings layer's in the place
/// 64, and the new settings layer's in `SETTINGS_NEW` while its change is under way.
pub static OBJECTS: Shared<[Option<Handle<Memory>>; RECORDS + 1]> =
    Shared::new([const { None }; RECORDS + 1]);
pub static KEY: Shared<Option<Key>> = Shared::new(None);
pub static PUBLISHED: [AtomicBool; PACKAGES] = [const { AtomicBool::new(false) }; PACKAGES];

pub static STARTING: AtomicBool = AtomicBool::new(true);
/// The counter when the process began, for the line of the time its start took.
pub static BEGAN: AtomicU64 = AtomicU64::new(0);
/// The store is not served: the start of the worker failed, or the disk service stopped
/// answering. A change is refused with IO at its gate, and STATUS says so.
pub static NO_STORE: AtomicBool = AtomicBool::new(false);
pub static DAMAGED: AtomicBool = AtomicBool::new(false);
pub static READ_ONLY: AtomicBool = AtomicBool::new(false);
pub static GENERATION: AtomicU64 = AtomicU64::new(0);
pub static FREE: AtomicU64 = AtomicU64::new(0);
pub static BLOCKS: AtomicU64 = AtomicU64::new(0);
pub static DISK_PACKAGES: AtomicU32 = AtomicU32::new(0);
pub static IMAGE_PACKAGES: AtomicU32 = AtomicU32::new(0);
pub static SETTINGS_LEN: AtomicUsize = AtomicUsize::new(0);
pub static LAYER: AtomicU32 = AtomicU32::new(0);
/// The count of changes of the state: odd while `TABLE`, the entries and the blobs change.
pub static SEQ: pkgd::seq::Seq = pkgd::seq::Seq::new();
/// The longest of each kind of work, in ticks, for the line of the report.
pub static SHA_TICKS: AtomicU64 = AtomicU64::new(0);
pub static PARSE_TICKS: AtomicU64 = AtomicU64::new(0);
pub static SIGN_TICKS: AtomicU64 = AtomicU64::new(0);
pub static MANIFEST_TICKS: AtomicU64 = AtomicU64::new(0);

/// The session that holds the store with a group, 0 when none; the worker sets it.
pub static GROUP_OWNER: AtomicU64 = AtomicU64::new(0);
/// The bytes of the open receipt that came, the main thread's count.
pub static FED: AtomicU64 = AtomicU64::new(0);
/// The main thread asks the worker to drop the group (a cancel, a session that went).
pub static CANCEL: AtomicBool = AtomicBool::new(false);

/// The job the main thread gives the worker, one at a time: the main thread fills `JOB`
/// and sets `JOB_STATE` to PENDING (release); the worker runs it, leaves its code and
/// value, and sets DONE (release), and tells the main thread.
pub static JOB: Shared<JobArgs> = Shared::new(JobArgs::EMPTY);
pub static JOB_STATE: AtomicU8 = AtomicU8::new(IDLE);
pub static JOB_CODE: AtomicU32 = AtomicU32::new(0);
pub static JOB_VALUE: AtomicU32 = AtomicU32::new(0);
/// The table place of the package that INSTALL_BEGIN made room for.
pub static JOB_SLOT: AtomicU32 = AtomicU32::new(0);
pub const IDLE: u8 = 0;
pub const PENDING: u8 = 1;
pub const RUNNING: u8 = 2;
pub const DONE: u8 = 3;

/// The kinds of job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    Begin,
    Commit,
    Remove,
    SettingsSet,
    SerialSet,
    RevokedSet,
}

/// What a job needs, as the main thread read it from the request. Names are
/// the fields of the table (`store::to_field`).
pub struct JobArgs {
    pub kind: JobKind,
    /// The label of the session that asked.
    pub owner: u64,
    pub number: u32,
    pub end: bool,
    pub world: bool,
    pub size: u64,
    pub serial: u64,
    /// The bytes of the blob or the list, in the buffer at `buffer`.
    pub len: usize,
    pub buffer: usize,
    pub sha256: [u8; 32],
    pub name: [u8; 64],
    pub version: [u8; 64],
    pub repo: [u8; 64],
    pub names: [[u8; 64]; 8],
    pub count: usize,
}

impl JobArgs {
    pub const EMPTY: JobArgs = JobArgs {
        kind: JobKind::Begin,
        owner: 0,
        number: 0,
        end: false,
        world: false,
        size: 0,
        serial: 0,
        len: 0,
        buffer: 0,
        sha256: [0; 32],
        name: [0; 64],
        version: [0; 64],
        repo: [0; 64],
        names: [[0; 64]; 8],
        count: 0,
    };
}

/// The label of the notification of a layer released (plus the number of
/// the layer, 0x7FFF at most), and of the worker's that it is done.
pub const LABEL_LAYER: u64 = 0x504b_0000;
pub const LABEL_DONE: u64 = 0x504b_8000;
/// The label of the kick the main thread gives the worker.
pub const LABEL_KICK: u64 = 1;

/// Where the main thread maps the buffers of its clients: 64 KiB for each place.
pub const BUFFERS_AT: usize = 0x58_0000_0000;
/// The buffers at once, one for each session that gave one.
pub const BUFFERS: usize = 4;
/// The places the superuser's sessions alone may take (the first ones): a session that is not
/// the superuser's has the rest, so that four programs that ask for a buffer and keep it cannot
/// leave `pkg install` and the changes of the settings without one.
pub const RESERVED: usize = 2;

pub const fn buffer_at(place: usize) -> usize {
    BUFFERS_AT + place * proto_pkg::BUFFER_SIZE as usize
}
/// The level of the main thread, the one the notifications carry.
pub const MAIN_LEVEL: u8 = 32;

/// Where the worker maps the object of the table place `slot` (the settings
/// layers have the places after the last package).
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
