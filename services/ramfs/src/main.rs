// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Single-threaded RAM file service. Each client session has its own fds.
//! The service opens a program's file for a loader (OPEN_EXEC, spec 2,
//! 3.2; 5c) through the session of the loaders alone, with the process
//! service vouching for the loader's identity through the service's
//! notary session, and gives a client a session for its child (CLONE).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use proto_fs::{MAX_READ, MAX_WRITE, Method, VERSION};
use proto_init::ServiceArgs;
use proto_wire::Status;
use proto_wire::clones::Clones;
use ramfs::authority::{
    Admission, AuditStep, Binding, BindingPurpose, CleanupAudit, Identity, NotaryReply,
    RetainedSourcePhase, retained_source_phase,
};
use ramfs::job::{JobOperation, PathJob, ResolveJob, Seconds};
use ramfs::locks::dispatch::{Dispatch as LockDispatch, Work as LockWork};
use ramfs::locks::jobs::Queue as LockQueue;
use ramfs::locks::service::LockService;
use ramfs::locks::wait_events::Events as WaitEvents;
use ramfs::locks::wait_notifications::Notifications as WaitNotifications;
use ramfs::locks::wait_proof::Proof as WaitProof;
use ramfs::locks::wait_receipts::Queue as WaitQueue;
use ramfs::locks::wait_select::{Decision as WaitDecision, Selector as WaitSelector};
use ramfs::locks::waiters::Pool as WaitPool;
use ramfs::open::{Journal as OpenJournal, Phase as OpenPhase};
use ramfs::resolve::{Intent, Progress, Resolve};
use ramfs::storage::{NONE, Root, Token};
use ramfs::tree::{self, Index};
use ramfs::{Exec, SET_GID, SET_UID};
use ramfs::{Fds, Ram};
use rt::abi::{Access, Rights};
use rt::handle::{Channel, Handle, Memory, Outgoing, Resource, Timer};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;

mod clock_page;
mod lifetime_page;

rt::entry!(main);

#[cfg(not(feature = "auth-probe"))]
const BASE_METHODS: &[u16] = proto_fs::METHODS;
#[cfg(feature = "auth-probe")]
const BASE_METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 0xfff7, 0xfff8, 0xfff9, 0xfffa, 0xfffb, 0xfffc, 0xfffd, 0xfffe,
];
#[cfg(not(any(
    feature = "steps",
    feature = "lifetime-probe",
    all(feature = "signal-probe", not(feature = "steps"))
)))]
const METHODS: &[u16] = BASE_METHODS;
#[cfg(any(
    feature = "steps",
    feature = "lifetime-probe",
    all(feature = "signal-probe", not(feature = "steps"))
))]
const METHODS: &[u16] = &{
    let mut methods = [0; BASE_METHODS.len()
        + cfg!(feature = "steps") as usize
        + cfg!(feature = "lifetime-probe") as usize
        + cfg!(all(feature = "signal-probe", not(feature = "steps"))) as usize];
    let mut i = 0;
    while i < BASE_METHODS.len() {
        methods[i] = BASE_METHODS[i];
        i += 1;
    }
    if cfg!(feature = "steps") {
        methods[i] = 0xfff5;
        i += 1;
    }
    if cfg!(all(feature = "signal-probe", not(feature = "steps"))) {
        methods[i] = 0xfff4;
        i += 1;
    }
    if cfg!(feature = "lifetime-probe") {
        methods[i] = 0xfff3;
    }
    methods
};
/// Genuine ordinary and image sessions each retain one exact place.
/// The fixed table covers process records and transient loader bindings.
const SESSIONS: usize = ramfs::places::COUNT;
/// Where the service maps the boot image, read-only, for as long as it
/// lives: the files of its table are read from there.
const IMAGE: usize = 0x50_0000_0000;
/// Where the service maps the object of a READ_INTO while it fills it.
const INTO: usize = 0x58_0000_0000;

/// The index of the table of the boot image, in the service's `.bss`.
struct Table(UnsafeCell<Index>);
// SAFETY: only the main thread reaches it, once (`image_tree`).
unsafe impl Sync for Table {}
static TABLE: Table = Table(UnsafeCell::new(Index::new()));
struct StorageBss(UnsafeCell<core::mem::MaybeUninit<ramfs::storage::State>>);
// SAFETY: only the service thread accesses the storage tables.
unsafe impl Sync for StorageBss {}
static STORAGE: StorageBss = StorageBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct LocksBss(UnsafeCell<core::mem::MaybeUninit<LockService>>);
// SAFETY: the sole service thread initializes and owns all lock tables.
unsafe impl Sync for LocksBss {}
static LOCKS: LocksBss = LocksBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct LockJobsBss(UnsafeCell<core::mem::MaybeUninit<LockQueue>>);
// SAFETY: the sole service thread initializes and owns prepaid request custody.
unsafe impl Sync for LockJobsBss {}
static LOCK_JOBS: LockJobsBss = LockJobsBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct WaitJobsBss(UnsafeCell<core::mem::MaybeUninit<WaitQueue>>);
// SAFETY: the sole service thread initializes and owns independent WAIT custody.
unsafe impl Sync for WaitJobsBss {}
static WAIT_JOBS: WaitJobsBss = WaitJobsBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct WaitPoolBss(UnsafeCell<core::mem::MaybeUninit<WaitPool>>);
// SAFETY: the sole service thread initializes and owns sleeping registrations.
unsafe impl Sync for WaitPoolBss {}
static WAIT_POOL: WaitPoolBss = WaitPoolBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct WaitNotifyBss(UnsafeCell<core::mem::MaybeUninit<WaitNotifications<Handle<Channel>>>>);
// SAFETY: the sole service thread initializes and owns all Notify copies.
unsafe impl Sync for WaitNotifyBss {}
static WAIT_NOTIFY: WaitNotifyBss =
    WaitNotifyBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct WaitEventsBss(UnsafeCell<core::mem::MaybeUninit<WaitEvents>>);
// SAFETY: the sole service thread owns all direct inode wake masks.
unsafe impl Sync for WaitEventsBss {}
static WAIT_EVENTS: WaitEventsBss =
    WaitEventsBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct WaitSelectorBss(UnsafeCell<core::mem::MaybeUninit<WaitSelector>>);
// SAFETY: the sole service thread owns read-only FIFO selection scratch.
unsafe impl Sync for WaitSelectorBss {}
static WAIT_SELECTOR: WaitSelectorBss =
    WaitSelectorBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
struct WaitProofBss(UnsafeCell<core::mem::MaybeUninit<WaitProof>>);
// SAFETY: the sole service thread owns paid read-only proof scratch.
unsafe impl Sync for WaitProofBss {}
static WAIT_PROOF: WaitProofBss = WaitProofBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
// The service loop reserves label zero for its heartbeat timer.
const WAIT_TIMER_LABEL: u64 = 0x5741_4954;
const WAIT_TIMER_PERIOD_NS: u64 = 250_000_000;
struct RamBss(UnsafeCell<core::mem::MaybeUninit<Ram<'static>>>);
// SAFETY: the sole service thread initializes and owns the RAM descriptors.
unsafe impl Sync for RamBss {}
static RAM: RamBss = RamBss(UnsafeCell::new(core::mem::MaybeUninit::uninit()));

/// The files of the boot image's table: the image is mapped from the
/// start data (`bootimage`, given to this record by init), and the table is
/// read. An image with no table, or no image, leaves the fixed tree alone.
fn image_tree(start: &mut rt::startup::Startup) -> Option<tree::Tree<'static>> {
    let image = start.take::<Memory>("bootimage").ok()?;
    let size = sys::memory_info(&image).ok()?.size;
    sys::mem_map(&start.process, &image, 0, size, IMAGE, Access::Read).ok()?;
    // SAFETY: the image stays mapped, read-only, for the life of the process.
    let bytes = unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size as usize) };
    // SAFETY: only the main thread reaches TABLE, here once.
    let index = unsafe { &mut *TABLE.0.get() };
    match tree::load(bytes, index) {
        Ok(tree) => Some(tree),
        Err(tree::Error::Missing) => None,
        Err(error) => {
            rt::println!("ramfs: the table of the boot image is refused: {error:?}");
            None
        }
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    // Legacy diagnostic timestamp source; clocked profiles replace this at startup.
    let Ok(args) = ServiceArgs::read(start.args()) else {
        return 7;
    };
    let period_ns = args.period_ns;
    let Ok(mode) = ramfs::time_source::Mode::parse(args.own) else {
        return 7;
    };
    let Ok(time_source) = clock_page::TimeSource::attach(mode, &start.parent, &start.process)
    else {
        return 8;
    };
    let Ok(now) = time_source.initial() else {
        return 9;
    };
    let tree = image_tree(&mut start);
    let Ok(backing) = sys::mem_create((ramfs::storage::PAGES * ramfs::storage::PAGE) as u64) else {
        return 5;
    };
    const DATA: usize = 0x54_0000_0000;
    let size = (ramfs::storage::PAGES * ramfs::storage::PAGE) as u64;
    if sys::mem_map(&start.process, &backing, 0, size, DATA, Access::ReadWrite).is_err() {
        return 6;
    }
    // SAFETY: the sole service thread owns this fixed data mapping and STORAGE.
    let data = unsafe { core::slice::from_raw_parts_mut(DATA as *mut u8, size as usize) };
    // SAFETY: the sole service thread initializes STORAGE before creating references.
    let state = unsafe {
        let pointer = (*STORAGE.0.get()).as_mut_ptr();
        // State's integer, boolean and Option<Account> fields admit zero values.
        pointer.write_bytes(0, 1);
        &mut *pointer
    };
    state.initialize();
    // SAFETY: initialization writes directly into exclusive aligned permanent storage.
    let locks = unsafe {
        let pointer = (*LOCKS.0.get()).as_mut_ptr();
        LockService::initialize_at(pointer);
        &mut *pointer
    };
    // SAFETY: initialization writes each field directly into exclusive permanent storage.
    let lock_jobs = unsafe {
        let pointer = (*LOCK_JOBS.0.get()).as_mut_ptr();
        LockQueue::initialize_at(pointer);
        &mut *pointer
    };
    // SAFETY: independent exclusive permanent allocations are initialized in place.
    let (wait_jobs, wait_pool, wait_notify, wait_events) = unsafe {
        let jobs = (*WAIT_JOBS.0.get()).as_mut_ptr();
        let pool = (*WAIT_POOL.0.get()).as_mut_ptr();
        let notify = (*WAIT_NOTIFY.0.get()).as_mut_ptr();
        let events = (*WAIT_EVENTS.0.get()).as_mut_ptr();
        WaitQueue::initialize_at(jobs);
        WaitPool::initialize_at(pool);
        WaitNotifications::initialize_at(notify);
        WaitEvents::initialize_at(events);
        (&mut *jobs, &mut *pool, &mut *notify, &mut *events)
    };
    // SAFETY: selection scratch is an exclusive permanent aligned allocation.
    let wait_selector = unsafe {
        let selector = (*WAIT_SELECTOR.0.get()).as_mut_ptr();
        WaitSelector::initialize_at(selector);
        &mut *selector
    };
    // SAFETY: RAM is exclusive permanent storage; every field is written first.
    let ram = unsafe {
        let pointer = (*RAM.0.get()).as_mut_ptr();
        Ram::initialize_at(pointer, now, state, data, tree);
        &mut *pointer
    };
    // SAFETY: exclusive permanent scratch, initialized field by field.
    let wait_proof = unsafe {
        let proof = (*WAIT_PROOF.0.get()).as_mut_ptr();
        WaitProof::initialize_at(proof);
        &mut *proof
    };
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let Ok(wait_view) = sys::handle_label(&channel, Rights::RECEIVE, WAIT_TIMER_LABEL, level)
    else {
        return 3;
    };
    let Ok(wait_timer) = sys::timer_create(&wait_view, level) else {
        return 3;
    };
    let heartbeat = Heartbeat {
        to: &start.parent,
        period_ns,
        priority: level,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    rt::println!(
        "ramfs: storage pages={} tables={} bytes",
        ramfs::storage::PAGES,
        core::mem::size_of::<ramfs::storage::State>()
            + core::mem::size_of::<Tables>()
            + core::mem::size_of::<Index>()
            + core::mem::size_of::<LockService>()
            + core::mem::size_of::<LockQueue>()
            + core::mem::size_of::<WaitQueue>()
            + core::mem::size_of::<WaitPool>()
            + core::mem::size_of::<WaitNotifications<Handle<Channel>>>()
            + core::mem::size_of::<WaitEvents>()
            + core::mem::size_of::<WaitProof>()
            + core::mem::size_of::<WaitSelector>()
            + core::mem::size_of::<Ram<'static>>()
    );
    rt::println!("ramfs: ready");
    // SAFETY: only the main thread reaches TABLES, here once.
    let tables = unsafe { &mut *TABLES.0.get() };
    let mut fs = Fs {
        ram,
        locks,
        lock_jobs,
        wait_jobs,
        wait_pool,
        wait_notify,
        wait_events,
        wait_selector,
        wait_selection: None,
        wait_proof,
        wait_proof_scan: None,
        wait_proof_scan_remaining: 0,
        wait_proof_choice: None,
        wait_proof_active: false,
        wait_proof_next: 0,
        wait_proof_serial: 0,
        wait_proof_disabled: false,
        wait_proof_turn: false,
        wait_timer,
        _wait_view: wait_view,
        wait_timer_armed: false,
        wait_request_turn: false,
        wait_ready_scan: None,
        wait_ready_scanned: false,
        lock_dispatch: LockDispatch::default(),
        lifetimes: None,
        legacy_pending: true,
        time_source,
        #[cfg(feature = "image-info-probe")]
        image_info_backing: Handle::borrowed(backing.raw()),
        #[cfg(feature = "image-info-probe")]
        image_info_fault: None,
        process: Handle::borrowed(start.process.raw()),
        channel: Handle::borrowed(channel.raw()),
        parent: Handle::borrowed(start.parent.raw()),
        notary: None,
        given: 0,
        level,
        births: &mut tables.births,
        clones: &mut tables.clones,
        places: &tables.places,
        identities: &mut tables.identities,
        jobs: &mut tables.jobs,
        job_generations: &mut tables.job_generations,
        seconds: &mut tables.seconds,
        generations: None,
        maintenance: ramfs::maintenance::Cursor::default(),
        maintenance_burst: ramfs::maintenance::Burst::default(),
        next_audit_ns: 0,
        maintenance_jobs: false,
        departure_turn: false,
        departures: ramfs::maintenance::Departures::new(SESSIONS + BIRTHS),
        data_gc_turn: false,
        #[cfg(feature = "steps")]
        steps_reclaim_owner: None,
        orphan_cursor: 0,
        orphan_count: 0,
        cancel_reported: 0,
    };
    // Prepare the authentic notary page after publishing the RAM endpoint.
    // Standalone boot profiles may have no Process service.
    let _ = fs.notary_register();
    let _ = fs.register_lifetimes();
    #[cfg(feature = "steps")]
    rt::service::report_steps(2);
    let _ = rt::service::run_in(&channel, &mut fs, config, &mut tables.sessions);
    4
}

struct Fs {
    ram: &'static mut Ram<'static>,
    locks: &'static mut LockService,
    lock_jobs: &'static mut LockQueue,
    wait_jobs: &'static mut WaitQueue,
    wait_pool: &'static mut WaitPool,
    wait_notify: &'static mut WaitNotifications<Handle<Channel>>,
    wait_events: &'static mut WaitEvents,
    wait_selector: &'static mut WaitSelector,
    wait_selection: Option<ramfs::locks::jobs::Id>,
    wait_proof: &'static mut WaitProof,
    wait_proof_scan: Option<ramfs::locks::waiters::Cursor>,
    wait_proof_scan_remaining: u8,
    wait_proof_choice: Option<(
        u8,
        ramfs::locks::waiters::RegistrationToken,
        ramfs::locks::request::Captured,
    )>,
    wait_proof_active: bool,
    wait_proof_next: u8,
    wait_proof_serial: u64,
    wait_proof_disabled: bool,
    wait_proof_turn: bool,
    wait_timer: Handle<Timer>,
    _wait_view: Handle<Channel>,
    wait_timer_armed: bool,
    wait_request_turn: bool,
    wait_ready_scan: Option<ramfs::locks::waiters::Cursor>,
    wait_ready_scanned: bool,
    lock_dispatch: LockDispatch,
    lifetimes: Option<lifetime_page::Lifetimes>,
    legacy_pending: bool,
    time_source: clock_page::TimeSource,
    // The startup-owned backing outlives this service loop and every outgoing copy.
    #[cfg(feature = "image-info-probe")]
    image_info_backing: ManuallyDrop<Handle<Memory>>,
    #[cfg(feature = "image-info-probe")]
    image_info_fault: Option<(u32, u32, u64, u32)>,
    /// The service's own process, to map the object of a READ_INTO in.
    process: ManuallyDrop<Handle<rt::handle::Process>>,
    /// The service's channel, which its own sessions are copies of, and
    /// its connection to init, which gives the notary session.
    channel: ManuallyDrop<Handle<Channel>>,
    parent: ManuallyDrop<Handle<Channel>>,
    /// The notary session with the process service (init's VOUCHERS),
    /// asked for at the first OPEN_EXEC.
    notary: Option<Handle<Channel>>,
    /// The sessions the service gave itself so far.
    given: u64,
    level: u8,
    /// The descriptors of the sessions Clone made that sent nothing yet,
    /// by their labels: the session's first request takes them, and the
    /// end of its last copy closes them.
    births: &'static mut [Option<(u64, Fds)>; BIRTHS],
    /// The clones alive, bounded for each client and in all.
    clones: &'static mut Clones<CLONES, { ramfs::places::SLOT_BITS }>,
    places: &'static ramfs::places::Places,
    identities: &'static mut Identities,
    jobs: &'static mut [Option<ResolveJob>; ramfs::storage::PREPARATIONS],
    job_generations: &'static mut [u64; ramfs::storage::PREPARATIONS],
    seconds: &'static mut Seconds,
    generations: Option<Handle<Memory>>,
    maintenance: ramfs::maintenance::Cursor,
    maintenance_burst:
        ramfs::maintenance::Burst<{ 4 * ramfs::storage::PREPARATIONS + 2 * (SESSIONS + BIRTHS) }>,
    next_audit_ns: u64,
    maintenance_jobs: bool,
    departure_turn: bool,
    departures: ramfs::maintenance::Departures<{ (SESSIONS + BIRTHS).div_ceil(64) }>,
    data_gc_turn: bool,
    /// The steps fixture retains queued nodes until the measured commit.
    #[cfg(feature = "steps")]
    steps_reclaim_owner: Option<u64>,
    orphan_cursor: u8,
    orphan_count: u16,
    /// The refused steps of a cancel the service has printed so far.
    cancel_reported: u32,
}

/// The clones the service keeps alive at most: one for each record of the
/// process service and room beside them.
const CLONES: usize = 320;

/// Clones whose sessions sent nothing yet, at most: past them, Clone is
/// LIMIT_REACHED. A child that never touches a file keeps its birth, so
/// there is room for every record and its transient binding preparation.
const BIRTHS: usize = CLONES;

/// The identity channels of the sessions, by index, with a list of the
/// free indexes: taking one costs the same with any number alive.
struct Identities {
    slots: [Option<IdentityChannel>; SESSIONS],
    next: [u16; SESSIONS],
    free: u16,
}
impl Identities {
    const fn new() -> Self {
        let mut next = [u16::MAX; SESSIONS];
        let mut i = 0;
        while i + 1 < SESSIONS {
            next[i] = (i + 1) as u16;
            i += 1;
        }
        Self {
            slots: [const { None }; SESSIONS],
            next,
            free: 0,
        }
    }
    /// The first free index, which the caller fills at once.
    fn take_free(&mut self) -> Option<usize> {
        let i = usize::from(self.free);
        if self.free == u16::MAX {
            return None;
        }
        self.free = self.next[i];
        Some(i)
    }
    /// The identity at `i` goes; its index is free again.
    fn release(&mut self, i: usize) {
        if self.slots[i].take().is_some() {
            self.next[i] = self.free;
            self.free = i as u16;
        }
    }
}
impl core::ops::Deref for Identities {
    type Target = [Option<IdentityChannel>; SESSIONS];
    fn deref(&self) -> &Self::Target {
        &self.slots
    }
}
impl core::ops::DerefMut for Identities {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.slots
    }
}

/// The tables of the sessions and of the births, in `.bss`: too big for
/// the service's stack.
struct ImageContext {
    token: Token,
    private: Option<Handle<Channel>>,
    transfer: Option<Handle<Channel>>,
}
struct IdentityChannel {
    label: u64,
    channel: Handle<Channel>,
    offered: Option<Handle<Channel>>,
    previous: Option<Handle<Channel>>,
    admission: Admission,
    pending: bool,
    require: bool,
    purpose: BindingPurpose,
    original: Binding,
    original_root: Root,
    audit: CleanupAudit,
    image: Option<ImageContext>,
}
struct Tables {
    places: ramfs::places::Places,
    clones: Clones<CLONES, { ramfs::places::SLOT_BITS }>,
    sessions: [Option<Session<Fds, 0>>; SESSIONS],
    births: [Option<(u64, Fds)>; BIRTHS],
    identities: Identities,
    jobs: [Option<ResolveJob>; ramfs::storage::PREPARATIONS],
    job_generations: [u64; ramfs::storage::PREPARATIONS],
    seconds: Seconds,
}
struct Bss(UnsafeCell<Tables>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(Tables {
    places: ramfs::places::Places::new(),
    clones: Clones::new(),
    sessions: [const { None }; SESSIONS],
    births: [None; BIRTHS],
    identities: Identities::new(),
    jobs: [const { None }; ramfs::storage::PREPARATIONS],
    job_generations: [0; ramfs::storage::PREPARATIONS],
    seconds: Seconds::new(),
}));

impl Fs {
    /// The index of the birth of the session `label`: its slot.
    fn birth_index(label: u64) -> usize {
        (label & ((1 << ramfs::places::SLOT_BITS) - 1)) as usize
    }

    /// The index of the identity channel of the image `outcome` names: the
    /// index it was prepared with, if the channel there still has its label.
    fn image_identity(&self, outcome: &ramfs::image::ImageOutcome) -> Option<usize> {
        let i = usize::from(outcome.identity);
        self.identities
            .get(i)?
            .as_ref()
            .is_some_and(|identity| identity.label == outcome.label)
            .then_some(i)
    }

    fn lock_custody_empty(
        queue: &LockQueue,
        wait_queue: &WaitQueue,
        places: &ramfs::places::Places,
        fds: &Fds,
        label: u64,
    ) -> bool {
        ramfs::locks::server::custody_empty(queue, fds, places.place(label), label)
            && fds.wait_departure == 16
            && !wait_queue.retains(places.place(label), label)
    }

    /// The index of the birth of `label`, if it holds one.
    fn birth_slot(&self, label: u64) -> Option<usize> {
        let i = Self::birth_index(label);
        self.births
            .get(i)?
            .as_ref()
            .is_some_and(|(l, _)| *l == label)
            .then_some(i)
    }

    /// A dead or superseded authority releases one retained reference per pass.
    fn cleanup_step(&mut self, fds: &mut Fds, label: u64) -> bool {
        if ramfs::locks::server::depart(
            self.lock_jobs,
            self.locks,
            fds,
            self.places.place(label),
            label,
        ) {
            return true;
        }
        if fds.departed && fds.wait_departure < 16 {
            let progress = ramfs::locks::wait_departure::part(
                self.wait_jobs,
                (self.wait_pool, self.wait_events),
                self.wait_notify,
                self.ram,
                (self.places.place(label), label),
                usize::from(fds.wait_departure),
                |handle| {
                    let _ = sys::notify(handle, 1);
                },
            )
            .expect("exact retained departed WAIT label");
            if progress.cancel_actor {
                self.locks.cancel();
            }
            fds.wait_departure += 8;
            self.refresh_wait_timer();
            return true;
        }
        if fds.departed && self.wait_jobs.retains(self.places.place(label), label) {
            // The sole active attempt may finish after the initial marking pass.
            fds.wait_departure = 0;
            return true;
        }
        if fds
            .binding
            .snapshot_ref()
            .is_some_and(|who| generation(who.index as usize) & proto_process::GENERATION_DEAD != 0)
        {
            let unfinished = fds.binding_preparation.is_some();
            self.drop_identity(fds);
            fds.binding = Binding::Cleanup;
            if unfinished || fds.binding_outcome.is_none() {
                fds.binding_outcome = Some(proto_fs::PERMISSION);
            }
            return true;
        }
        #[cfg(feature = "auth-probe")]
        if fds.auth_probe_hold
            && fds.binding_preparation.is_some()
            && fds
                .binding
                .snapshot_ref()
                .is_some_and(|who| generation(who.index as usize) == who.generation)
        {
            return false;
        }
        if fds.binding_preparation.is_some() {
            let mut progress = true;
            let _ = self.binding_phase(fds, label, &mut progress);
            return progress;
        }
        if self
            .identities
            .get(fds.authority_index as usize)
            .and_then(Option::as_ref)
            .is_some_and(|identity| {
                identity.purpose == BindingPurpose::Audit
                    && !identity.audit.cached(
                        fds.binding
                            .snapshot_ref()
                            .map_or(0, |who| generation(who.index as usize)),
                    )
            })
        {
            return self.audit_step(fds, label);
        }
        if fds.binding.snapshot_ref().is_some() {
            let result = self.authenticate(fds, label);
            if fds.binding_preparation.is_some() {
                return true;
            }
            if result == Err(proto_fs::TOO_MANY_OPEN_FILES) {
                let Some(who) = fds.binding.snapshot_ref() else {
                    return false;
                };
                let current = generation(who.index as usize);
                let Some(identity) = self
                    .identities
                    .get_mut(fds.authority_index as usize)
                    .and_then(Option::as_mut)
                else {
                    fds.binding = Binding::Cleanup;
                    return true;
                };
                if identity.audit.cached(current) && identity.original == fds.binding {
                    return false;
                }
                identity.audit.start(&mut identity.admission, current);
                identity.original = fds.binding;
                identity.original_root = fds.root;
                identity.purpose = BindingPurpose::Audit;
                return true;
            }
        }
        if !matches!(fds.binding, Binding::Cleanup) {
            return false;
        }
        if fds.image_outcome.is_some() {
            self.clear_image_outcome(fds);
            return true;
        }
        if let Some(id) = fds.resolvers.iter().copied().find(|&id| id != 0) {
            if fds.departed
                && self
                    .job_slot(id, label)
                    .is_ok_and(|i| self.jobs[i].as_ref().is_some_and(|job| !job.abandoned))
            {
                self.abandon_job(id, label, fds);
                return true;
            }
            let before = (fds.resolvers, self.ram.storage.available().pages);
            self.cancel_job(id, label, Some(fds));
            return fds.resolvers != before.0 || self.ram.storage.available().pages > before.1;
        }
        #[cfg(feature = "auth-probe")]
        if fds.auth_probe_gc.take().is_some() {
            let _ = self
                .ram
                .storage
                .unlink(ramfs::storage::ROOT, b"auth-probe-gc", fds.root);
            return true;
        }
        if self.ram.release_step(fds) {
            return true;
        }
        self.drop_identity(fds);
        false
    }
    fn notary(&mut self) -> Option<&Handle<Channel>> {
        if self.notary.is_none() {
            self.notary = rt::service::connect(&self.parent, "posix").ok();
        }
        self.notary.as_ref()
    }

    /// A session of the service's own with `label` for a client.
    fn session(&mut self, label: u64) -> Result<Handle<Channel>, rt::abi::Error> {
        self.session_rights(label, Rights::SEND | Rights::TRANSFER)
    }
    fn session_rights(
        &mut self,
        label: u64,
        rights: Rights,
    ) -> Result<Handle<Channel>, rt::abi::Error> {
        let Some(next) = self.given.checked_add(1).filter(|n| *n < 1 << 46) else {
            self.places.release(label);
            return Err(abi::Error::LimitReached);
        };
        self.given = next;
        let made = sys::handle_label(&self.channel, rights, label, self.level);
        if made.is_err() {
            self.places.release(label);
        }
        made
    }

    /// Prepayment retains one exact loading image before the SetId effect.
    fn prepare_image(
        &mut self,
        fds: &mut Fds,
        job: u64,
        token: Token,
        entry: u16,
    ) -> Result<(), u32> {
        let identity = self
            .identities
            .get(fds.authority_index as usize)
            .and_then(Option::as_ref)
            .ok_or(proto_fs::PERMISSION)?;
        let copy = sys::handle_duplicate(
            &identity.channel,
            Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
        )
        .map_err(|_| proto_fs::TOO_MANY_OPEN_FILES)?;
        let label = self
            .places
            .issue_image(self.given)
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
        let mut child = Fds::default();
        child.binding = fds.binding;
        child.root = fds.root;
        let admitted = (|| {
            self.ram.hold_image(&mut child, token, entry)?;
            self.install_identity(&mut child, label, copy, false)?;
            let private = self
                .session_rights(label, Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER)
                .map_err(|_| proto_fs::TOO_MANY_OPEN_FILES)?;
            let transfer = sys::handle_duplicate(&private, Rights::SEND | Rights::TRANSFER)
                .map_err(|_| proto_fs::TOO_MANY_OPEN_FILES)?;
            self.identities[child.authority_index as usize]
                .as_mut()
                .unwrap()
                .image = Some(ImageContext {
                token,
                private: Some(private),
                transfer: Some(transfer),
            });
            Ok(())
        })();
        if let Err(code) = admitted {
            self.drop_identity(&mut child);
            self.ram.release(&mut child);
            self.places.release(label);
            return Err(code);
        }
        let identity = child.authority_index;
        self.births[Self::birth_index(label)] = Some((label, child));
        fds.image_outcome = Some(ramfs::image::ImageOutcome {
            job,
            label,
            identity,
            token,
            phase: ramfs::image::ImagePhase::Prepared,
        });
        Ok(())
    }
    /// Source cleanup retires its private recovery copy while external copies retain the image.
    fn clear_image_outcome(&mut self, fds: &mut Fds) {
        let Some(outcome) = fds.image_outcome.take() else {
            return;
        };
        if outcome.phase == ramfs::image::ImagePhase::Prepared {
            // A prepared image can hold all 32 inherited descriptions too.
            self.closed(outcome.label);
        } else if let Some(i) = self.image_identity(&outcome)
            && let Some(image) = self.identities[i].as_mut().and_then(|i| i.image.as_mut())
        {
            image.private = None;
        }
    }
    fn finish_image_job(&mut self, fds: &mut Fds, id: u64, owner: u64) {
        let i = self.path_slot(id, owner).expect("exact executable job");
        let j = self.jobs[i].take().unwrap();
        let JobOperation::Path(path) = j.operation else {
            unreachable!()
        };
        path.resolver.release(&mut self.ram.storage);
        if let Some(second) = path.second {
            second.release(&mut self.ram.storage);
        }
        if j.root != NONE {
            self.ram.storage.release_preparation(j.root);
        }
        *fds.resolvers.iter_mut().find(|r| **r == id).unwrap() = 0;
    }
    fn open_exec(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        if let Some(outcome) = fds.image_outcome {
            if outcome.phase == ramfs::image::ImagePhase::Retired {
                return status(proto_fs::OPEN_RETIRED);
            }
            if outcome.job != job {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            }
            if outcome.phase == ramfs::image::ImagePhase::AbortRequired {
                return status(proto_fs::IMAGE_ABORT_REQUIRED);
            }
            if outcome.phase == ramfs::image::ImagePhase::Ready {
                if let Err(code) = self.authorize_loading(fds, r.label()) {
                    return status(code);
                }
                let copy = self
                    .image_identity(&outcome)
                    .and_then(|i| self.identities[i].as_ref())
                    .and_then(|identity| identity.image.as_ref())
                    .filter(|image| image.token == outcome.token)
                    .and_then(|image| image.private.as_ref())
                    .and_then(|private| {
                        sys::handle_duplicate(private, Rights::SEND | Rights::TRANSFER).ok()
                    });
                return match copy {
                    Some(copy) if r.reply().u32(0).is_ok() => Answer::Reply([copy.erase()].into()),
                    _ => {
                        self.clear_image_outcome(fds);
                        fds.image_outcome = Some(ramfs::image::ImageOutcome {
                            phase: ramfs::image::ImagePhase::AbortRequired,
                            ..outcome
                        });
                        status(proto_fs::IMAGE_ABORT_REQUIRED)
                    }
                };
            }
        }
        if !matches!(fds.binding, Binding::Pending(_)) {
            return status(proto_fs::PERMISSION);
        }
        if let Err(code) = self.authenticate(fds, r.label()) {
            return status(code);
        }
        if self.path_slot(job, r.label()).is_err() {
            return status(proto_fs::OPEN_RETIRED);
        }
        let token = match self.proof(job, r.label(), Some(fds)) {
            Ok((token, None)) => token,
            Ok(_) => return status(proto_fs::PERMISSION),
            Err(code) => {
                self.clear_image_outcome(fds);
                return status(code);
            }
        };
        let who = fds.binding.snapshot().expect("authenticated pending image");
        let Some(loader) = who.loader else {
            return status(proto_fs::PERMISSION);
        };
        let exec = match self
            .ram
            .exec_token(token, Identity::of(who.credentials, who.groups, false))
        {
            Ok(exec) => exec,
            Err(code) => {
                self.clear_image_outcome(fds);
                return status(code);
            }
        };
        if fds.image_outcome.is_none() {
            return match self.prepare_image(fds, job, token, exec.entry) {
                Ok(()) => status(proto_fs::RESOLVING),
                Err(code) => status(code),
            };
        }
        let outcome = fds.image_outcome.unwrap();
        let expected = self
            .image_identity(&outcome)
            .and_then(|i| self.identities[i].as_ref())
            .is_some_and(|identity| {
                identity.original == fds.binding
                    && identity
                        .image
                        .as_ref()
                        .is_some_and(|image| image.token == token)
            });
        if !expected || r.reply().u32(0).is_err() {
            self.clear_image_outcome(fds);
            return status(proto_fs::STALE_PROOF);
        }
        if !self.tell_set_id(&exec, who.pid, loader) {
            self.clear_image_outcome(fds);
            fds.image_outcome = Some(ramfs::image::ImageOutcome {
                phase: ramfs::image::ImagePhase::AbortRequired,
                ..outcome
            });
            return status(proto_fs::IMAGE_ABORT_REQUIRED);
        }
        // Every resource and reply field was prepaid before the first SetId attempt.
        self.finish_image_job(fds, job, r.label());
        fds.image_outcome.as_mut().unwrap().phase = ramfs::image::ImagePhase::Ready;
        let at = self.image_identity(&outcome).unwrap();
        let image = self.identities[at]
            .as_mut()
            .unwrap()
            .image
            .as_mut()
            .unwrap();
        Answer::Reply([image.transfer.take().unwrap().erase()].into())
    }
    fn image_authorize(&mut self, fds: &mut Fds, label: u64) -> Result<(), u32> {
        if fds.image_hold.is_none() {
            return Err(proto_fs::BAD_FD);
        }
        self.authorize_loading(fds, label)
    }
    fn authorize_loading(&mut self, fds: &mut Fds, label: u64) -> Result<(), u32> {
        match self.authenticate(fds, label) {
            Ok(()) if matches!(fds.binding, Binding::Pending(_)) => Ok(()),
            Err(proto_fs::PERMISSION)
                if matches!(fds.binding, Binding::Handoff(_))
                    && fds
                        .binding
                        .snapshot_ref()
                        .is_some_and(|who| generation(who.index as usize) == who.generation)
                    && self
                        .identities
                        .get(fds.authority_index as usize)
                        .and_then(Option::as_ref)
                        .is_some_and(|identity| identity.label == label) =>
            {
                Ok(())
            }
            Err(code) => Err(code),
            _ => Err(proto_fs::PERMISSION),
        }
    }

    /// SetId for a file with a set-ID bit, through the notary session:
    /// whether the process service kept it, or the file has none.
    fn tell_set_id(&mut self, exec: &Exec, pid: u32, loader: proto_process::LoaderOf) -> bool {
        if exec.mode & (SET_UID | SET_GID) == 0 {
            return true;
        }
        let pick = |bit, id| {
            if exec.mode & bit != 0 {
                id
            } else {
                proto_process::NO_ID
            }
        };
        let set = proto_process::SetId {
            ticket: loader.ticket,
            pid,
            image: loader.image,
            uid: pick(SET_UID, exec.uid),
            gid: pick(SET_GID, exec.gid),
        };
        let mut w = proto_wire::Writer::new();
        if proto_process::Method::SetId.header().write(&mut w).is_err()
            || set.write(&mut w).is_err()
        {
            return false;
        }
        let Some(notary) = self.notary() else {
            return false;
        };
        sys::send(notary, w.as_bytes()).is_ok_and(|reply| {
            reply.len == proto_wire::HEADER_LEN && reply.words[0] == 0 && reply.handles.is_empty()
        })
    }

    /// READ_AT, READ_INTO and INFO_FD use the image session's retained inode at fd0.
    fn image(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if r.method() != Method::ReadInto as u16 && !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::ReadInto) => {
                let (Ok(fd), Ok(offset), Ok(count), Ok(at)) =
                    (body.u32(), body.u64(), body.u32(), body.u64())
                else {
                    return Answer::Status(Status::BadSize);
                };
                let rights = Rights::MAP_READ | Rights::MAP_WRITE;
                let writable = matches!(r.handles.info(0), Some((rt::abi::ObjectKind::Memory, got)) if got.contains(rights));
                let handles = r.handles.len();
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Ok(memory) = r.handles.take::<Memory>(0) else {
                    return Answer::Status(Status::BadSize);
                };
                let size = sys::memory_info(&memory).map_or(0, |i| i.size);
                if !ramfs::read_into_valid(fd, count as usize, at, handles, writable, size) {
                    return Answer::Status(Status::BadSize);
                }
                match self.read_into(fds, offset, count as usize, &memory, at) {
                    Ok(n) => value(r, n as u32),
                    Err(answer) => answer,
                }
            }
            Some(Method::ReadAt) => {
                let (Ok(fd), Ok(offset), Ok(count)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || fd != 0 || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self
                    .ram
                    .held_image_read(fds, offset, &mut bytes[..count as usize])
                {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::InfoFd) => {
                if body.u32() != Ok(0) || body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.held_image_information(fds) {
                    Ok(info) => {
                        #[cfg(feature = "image-info-probe")]
                        if self
                            .image_info_fault
                            .is_some_and(|(pid, image, ticket, _)| {
                                fds.binding.snapshot_ref().is_some_and(|who| {
                                    who.pid == pid
                                        && who.image == image
                                        && who.loader.is_some_and(|loader| loader.ticket == ticket)
                                })
                            })
                        {
                            let fault = self.image_info_fault.take().expect("armed exact loader").3;
                            let mut body = proto_wire::Writer::new();
                            if body.u32(0).and_then(|()| info.write(&mut body)).is_err() {
                                return Answer::Status(Status::BadSize);
                            }
                            let length = body.as_bytes().len() - usize::from(fault == 2);
                            if r.reply().bytes(&body.as_bytes()[..length]).is_err()
                                || (fault == 1 && r.reply().u32(0).is_err())
                            {
                                return Answer::Status(Status::BadSize);
                            }
                            if fault == 3 {
                                return match sys::handle_duplicate(
                                    &self.image_info_backing,
                                    Rights::MAP_READ | Rights::TRANSFER,
                                ) {
                                    Ok(copy) => Answer::Reply([copy.erase()].into()),
                                    Err(error) => Answer::Status(Status::Kernel(error)),
                                };
                            }
                            return Answer::Reply(Outgoing::new());
                        }
                        let w = r.reply();
                        if w.u32(0).and_then(|()| info.write(w)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            _ => status(proto_fs::PERMISSION),
        }
    }
}

impl Fs {
    /// READ_INTO: `count` bytes of the retained inode from `offset` into
    /// `memory` from `at`, through the window INTO of the service's own
    /// space, mapped for the copy alone: the count copied.
    fn read_into(
        &mut self,
        fds: &Fds,
        offset: u64,
        count: usize,
        memory: &Handle<Memory>,
        at: u64,
    ) -> Result<usize, Answer> {
        if count == 0 {
            return Ok(0);
        }
        let len = (count as u64).next_multiple_of(4096);
        sys::mem_map(&self.process, memory, at, len, INTO, Access::ReadWrite)
            .map_err(|e| Answer::Status(Status::Kernel(e)))?;
        // SAFETY: the window maps `len` bytes of the object, which only this
        // step touches until the unmap below.
        let out = unsafe { core::slice::from_raw_parts_mut(INTO as *mut u8, count) };
        let read = self.ram.held_image_read(fds, offset, out);
        // SAFETY: the mapping made above, which nothing uses now.
        let _ = unsafe { sys::mem_unmap(&self.process, INTO, len) };
        read.map_err(status)
    }
}

fn status(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}

fn value(r: &mut Request<'_>, number: u32) -> Answer {
    let w = r.reply();
    if w.u32(0).and_then(|()| w.u32(number)).is_err() {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}

impl Fs {
    /// CLONE with a list of descriptors of the session `fds` (count u32,
    /// then each u32): a session of the service's own label whose
    /// descriptors of the same numbers share their open descriptions;
    /// BAD_FD for a number of none, LIMIT_REACHED with BIRTHS clones that
    /// sent nothing yet.
    fn clone_session(&mut self, fds: &Fds, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let mut list = [0u32; 32];
        let Ok(count) = ramfs::clone_count(&mut body, r.handles.len()) else {
            return Answer::Status(Status::BadSize);
        };
        for fd in &mut list[..count] {
            let Ok(n) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if r.method() == Method::CloneExact as u16 {
                let Ok(generation) = body.u64() else {
                    return Answer::Status(Status::BadSize);
                };
                if n & !(proto_fs::OPEN_FD_MASK | proto_fs::OPEN_DESCRIPTION_MASK) != 0
                    || !(3..35).contains(&(n & proto_fs::OPEN_FD_MASK))
                    || generation == 0
                {
                    return Answer::Status(Status::BadSize);
                }
                *fd = n & proto_fs::OPEN_FD_MASK;
                let expected = ramfs::storage::Token {
                    slot: ((n & proto_fs::OPEN_DESCRIPTION_MASK)
                        >> proto_fs::OPEN_DESCRIPTION_SHIFT) as u16,
                    generation,
                };
                if self.ram.description_token(fds, *fd) != Ok(expected) {
                    return status(proto_fs::STALE_PROOF);
                }
            } else {
                *fd = n;
            }
        }
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if self.clones.room(r.label()).is_err() {
            return Answer::Status(Status::Kernel(rt::abi::Error::LimitReached));
        }
        let mut child = Fds::default();
        if let Err(code) = self.ram.clone_fds_into(fds, &list[..count], &mut child) {
            return status(code);
        }
        if matches!(fds.binding, Binding::Boot) {
            child.binding = Binding::Boot;
        }
        let Some(label) = self.places.issue(self.given) else {
            self.ram.release(&mut child);
            return status(proto_fs::TOO_MANY_OPEN_FILES);
        };
        if let Some(who) = fds.binding.snapshot() {
            child.binding = Binding::Inherited(who);
            let identity = self.identities[fds.authority_index as usize]
                .as_ref()
                .and_then(|i| {
                    sys::handle_duplicate(
                        &i.channel,
                        Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
                    )
                    .ok()
                });
            let result = identity
                .ok_or(proto_fs::PERMISSION)
                .and_then(|identity| self.install_identity(&mut child, label, identity, false));
            if let Err(code) = result {
                self.places.release(label);
                self.ram.release(&mut child);
                return status(code);
            }
        }
        match self.session(label) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    self.drop_identity(&mut child);
                    self.ram.release(&mut child);
                    return Answer::Status(Status::BadSize);
                }
                self.births[Self::birth_index(label)] = Some((label, child));
                let adopted = self.clones.adopt(label, r.label());
                debug_assert!(adopted.is_ok(), "the place of a new label is free");
                Answer::Reply([session.erase()].into())
            }
            Err(e) => {
                self.drop_identity(&mut child);
                self.ram.release(&mut child);
                Answer::Status(Status::Kernel(e))
            }
        }
    }
}

impl Service<0> for Fs {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    const PLACED: usize = SESSIONS;
    type Data = Fds;

    /// Logical FD death precedes bounded physical reclamation.
    fn gone(&mut self, s: &mut Session<Fds, 0>) {
        self.maintenance_burst.restart();
        self.legacy_pending = true;
        Self::depart_fields(self.ram, self.locks, self.identities, &mut s.data);
        self.wait_events.poll();
        if !Self::lock_custody_empty(
            self.lock_jobs,
            self.wait_jobs,
            self.places,
            &s.data,
            s.label(),
        ) {
            self.departures.admit(self.places.place(s.label()));
        }
    }

    fn keep_departed(&self, s: &Session<Fds, 0>) -> bool {
        s.data.departed
            && !Self::lock_custody_empty(
                self.lock_jobs,
                self.wait_jobs,
                self.places,
                &s.data,
                s.label(),
            )
    }

    /// A never-used clone retains its paid birth until cleanup finishes.
    fn closed(&mut self, label: u64) {
        self.maintenance_burst.restart();
        self.legacy_pending = true;
        #[cfg(feature = "steps")]
        if self.steps_reclaim_owner == Some(label) {
            self.steps_reclaim_owner = None;
            let _ = sys::notify(&self.channel, 1);
        }
        if self.departures.contains(self.places.place(label)) {
            return;
        }
        if let Some(i) = self.birth_slot(label) {
            let (_, fds) = self.births[i].as_mut().expect("exact retained birth");
            Self::depart_fields(self.ram, self.locks, self.identities, fds);
            self.wait_events.poll();
            if !Self::lock_custody_empty(self.lock_jobs, self.wait_jobs, self.places, fds, label) {
                self.departures.admit(SESSIONS + i);
                return;
            }
            self.births[i] = None;
        }
        self.places.release(label);
        self.clones.gone(label);
    }

    fn maintenance(
        &mut self,
        sessions: &mut [Option<Session<Fds, 0>>],
        notice: rt::service::Notice,
    ) {
        if notice.source == rt::abi::Source::Timer && notice.label == WAIT_TIMER_LABEL {
            self.wait_timer_armed = false;
            if self.wait_pool.count() != 0 {
                self.wait_events.poll();
                self.schedule_wait_proof();
                self.maintenance_burst.restart();
                self.legacy_pending = true;
                self.refresh_wait_timer();
                let _ = sys::notify(&self.channel, 1);
            }
            return;
        }
        if notice.source != rt::abi::Source::Unlabeled || notice.label != 0 {
            self.maintenance_burst.restart();
            self.legacy_pending = true;
            let _ = sys::notify(&self.channel, 1);
            return;
        }
        rt::service::step_own();
        if self.ram.cancel_refusals != self.cancel_reported {
            self.cancel_reported = self.ram.cancel_refusals;
            rt::println!(
                "ramfs: {} steps of a cancel were refused",
                self.cancel_reported
            );
        }
        let now = rt::time::ticks_to_ns(rt::time::now());
        match self.lock_dispatch.next_with_requests(
            now,
            self.locks.busy(),
            self.lock_jobs.has_work()
                || self.wait_jobs.has_work()
                || self.wait_events.pending()
                || self.wait_proof_pending(),
            self.lifetimes.is_some(),
        ) {
            LockWork::Actor => {
                let page = self.lifetimes.as_ref();
                let (storage, descriptions) = self.ram.lock_parts();
                let progress = self.locks.step_with_owners(
                    storage,
                    |pid| page.is_some_and(|page| page.live(pid)),
                    |token| descriptions.live(token),
                );
                if let Some(result) = progress.completed {
                    if let Some(id) = self.wait_jobs.active() {
                        if result == Ok(ramfs::locks::actor::Response::Changed) {
                            let captured =
                                self.wait_jobs.snapshot(id).expect("exact WAIT capture").0;
                            self.wait_events.changed(captured.request.inode);
                        }
                        let place = usize::from(id.slot()) / ramfs::locks::wait_receipts::SHARE;
                        let source = sessions
                            .get(place)
                            .and_then(Option::as_ref)
                            .filter(|session| session.label() == id.owner() && session.data.claimed)
                            .map(|session| &session.data)
                            .or_else(|| {
                                self.births
                                    .get(Self::birth_index(id.owner()))
                                    .and_then(Option::as_ref)
                                    .filter(|(label, _)| *label == id.owner())
                                    .map(|(_, fds)| fds)
                            });
                        let finished = ramfs::locks::wait_server::finish(
                            self.wait_jobs,
                            self.wait_pool,
                            self.ram,
                            result,
                            source,
                            |pid| page.is_some_and(|page| page.live(pid)),
                        )
                        .expect("exact sole WAIT Actor completion");
                        if let ramfs::locks::wait_server::Finish::Complete(id) = finished {
                            self.publish_wait(id);
                        } else if let ramfs::locks::wait_server::Finish::Sleeping(registration) =
                            finished
                        {
                            self.wait_events
                                .attach(self.wait_pool, registration)
                                .expect("paid genuine WAIT inode wake mask");
                            self.schedule_wait_proof();
                        }
                        self.refresh_wait_timer();
                        self.notify_maintenance();
                        return;
                    }
                    let id = self.lock_jobs.active().expect("completed active request");
                    if result == Ok(ramfs::locks::actor::Response::Changed) {
                        let captured = self
                            .lock_jobs
                            .snapshot(id)
                            .expect("exact Control capture")
                            .0;
                        self.wait_events.changed(captured.request.inode);
                    }
                    let place = usize::from(id.slot()) / ramfs::locks::jobs::SHARE;
                    let source = sessions
                        .get(place)
                        .and_then(Option::as_ref)
                        .filter(|session| session.label() == id.owner() && session.data.claimed)
                        .map(|session| &session.data)
                        .or_else(|| {
                            self.births
                                .get(Self::birth_index(id.owner()))
                                .and_then(Option::as_ref)
                                .filter(|(label, _)| *label == id.owner())
                                .map(|(_, fds)| fds)
                        });
                    if ramfs::locks::server::finish_with_source(
                        self.lock_jobs,
                        self.ram,
                        result,
                        source,
                        |pid| page.is_some_and(|page| page.live(pid)),
                    ) {
                        self.maintenance_burst.restart();
                        self.legacy_pending = true;
                    }
                }
                self.notify_maintenance();
                return;
            }
            LockWork::Request { cleanup } => {
                if cleanup && self.wait_proof_pending() {
                    self.wait_proof_turn = !self.wait_proof_turn;
                }
                if self.wait_events.pending() {
                    self.wait_events
                        .part(self.wait_jobs, self.wait_pool)
                        .expect("exact bounded WAIT wake masks");
                    self.wait_ready_scan = None;
                    self.wait_ready_scanned = false;
                } else if cleanup && self.wait_proof_pending() && self.wait_proof_turn {
                    self.tick_wait_proof(sessions);
                } else if cleanup {
                    if self.lock_jobs.cleanup_released(&mut self.ram.storage) != 0 {
                        self.maintenance_burst.restart();
                        self.legacy_pending = true;
                    }
                } else if !self.locks.busy()
                    && self.wait_jobs.has_work()
                    && (self.wait_request_turn || !self.lock_jobs.has_work())
                {
                    self.wait_request_turn = false;
                    if let Some(id) = self.next_wait_ready() {
                        let place = usize::from(id.slot()) / ramfs::locks::wait_receipts::SHARE;
                        let source = sessions
                            .get(place)
                            .and_then(Option::as_ref)
                            .filter(|session| session.label() == id.owner() && session.data.claimed)
                            .map(|session| &session.data)
                            .or_else(|| {
                                self.births
                                    .get(Self::birth_index(id.owner()))
                                    .and_then(Option::as_ref)
                                    .filter(|(label, _)| *label == id.owner())
                                    .map(|(_, fds)| fds)
                            });
                        ramfs::locks::wait_server::begin(
                            self.wait_jobs,
                            self.locks,
                            self.ram,
                            id,
                            source,
                        )
                        .expect("exact queued WAIT attempt");
                        if self
                            .wait_jobs
                            .query(id)
                            .is_ok_and(|reply| reply.phase == proto_fs::WaitPhase::Complete)
                        {
                            self.publish_wait(id);
                        }
                    }
                } else if !self.locks.busy() {
                    self.wait_request_turn = true;
                    self.select_control(sessions);
                }
                self.notify_maintenance();
                return;
            }
            LockWork::Audit { first, end } => {
                let page = self.lifetimes.as_ref();
                let (_, descriptions) = self.ram.lock_parts();
                for index in first..end {
                    if index < proto_process::RECORDS {
                        self.locks
                            .audit_pid(index, |pid| page.is_some_and(|page| page.live(pid)))
                            .expect("bounded genuine PID place");
                    } else {
                        self.locks
                            .audit_description(index - proto_process::RECORDS, |token| {
                                descriptions.live(token)
                            })
                            .expect("bounded actual OFD place");
                    }
                }
                if end == proto_process::RECORDS + ramfs::DESCRIPTIONS {
                    self.wait_events.poll();
                }
                self.notify_maintenance();
                return;
            }
            LockWork::Legacy => {}
        }
        if now >= self.next_audit_ns && self.maintenance.remaining == 0 {
            self.next_audit_ns = now.saturating_add(250_000_000);
            self.maintenance.remaining = SESSIONS + BIRTHS - 1;
        }
        let mut work = false;
        self.maintenance_jobs = !self.maintenance_jobs;
        if self.maintenance_jobs {
            self.data_gc_turn = !self.data_gc_turn;
            if self.data_gc_turn && self.orphan_count != 0 {
                let slot = self.orphan_cursor as usize;
                self.orphan_cursor = ((slot + 1) % ramfs::storage::PREPARATIONS) as u8;
                if let Some(job) = self.jobs[slot].as_ref().filter(|job| job.abandoned) {
                    let (id, owner) = (job.id, job.owner);
                    let before = (self.orphan_count, self.ram.storage.available().pages);
                    self.cancel_job(id, owner, None);
                    let after = (self.orphan_count, self.ram.storage.available().pages);
                    work = ramfs::maintenance::orphan_progress(before, after);
                }
            } else {
                #[cfg(feature = "steps")]
                let retained = self.steps_reclaim_owner.is_some();
                #[cfg(not(feature = "steps"))]
                let retained = false;
                if !retained {
                    work = self.ram.storage.reclaim_step();
                }
            }
            self.legacy_pending = self.maintenance_burst.again(
                work,
                work || self.departures.pending()
                    || self.maintenance.remaining != 0
                    || self.orphan_count != 0,
            );
            self.notify_maintenance();
            return;
        }
        self.departure_turn = !self.departure_turn;
        if self.departure_turn
            && let Some(i) = self.departures.next_place()
        {
            let (label, complete) = if i < SESSIONS {
                let s = sessions[i].as_mut().expect("retained departed session");
                let label = s.label();
                work = self.cleanup_step(&mut s.data, label);
                (
                    label,
                    Self::lock_custody_empty(
                        self.lock_jobs,
                        self.wait_jobs,
                        self.places,
                        &s.data,
                        label,
                    ),
                )
            } else {
                let birth = &mut self.births[i - SESSIONS];
                let (label, mut fds) = birth.take().expect("retained departed birth");
                work = self.cleanup_step(&mut fds, label);
                let complete = Self::lock_custody_empty(
                    self.lock_jobs,
                    self.wait_jobs,
                    self.places,
                    &fds,
                    label,
                );
                self.births[i - SESSIONS] = Some((label, fds));
                (label, complete)
            };
            if complete {
                if i < SESSIONS {
                    sessions[i] = None;
                } else {
                    self.births[i - SESSIONS] = None;
                }
                self.departures.release(i);
                self.places.release(label);
                self.clones.gone(label);
                work = true;
            }
            self.legacy_pending = self.maintenance_burst.again(
                work,
                work || self.departures.pending()
                    || self.maintenance.remaining != 0
                    || self.orphan_count != 0,
            );
            self.notify_maintenance();
            return;
        }
        let mut client_work = false;
        let i = self.maintenance.position;
        if self.departures.contains(i) {
            // Queued cells receive separate fair bounded cleanup turns.
        } else if i < SESSIONS {
            if let Some(s) = sessions.get_mut(i).and_then(Option::as_mut) {
                let label = s.label();
                client_work = self.cleanup_step(&mut s.data, label);
            }
        } else if let Some((label, mut fds)) = self.births[i - SESSIONS].take() {
            client_work = self.cleanup_step(&mut fds, label);
            self.births[i - SESSIONS] = Some((label, fds));
        }
        work |= client_work;
        self.maintenance.complete(client_work, SESSIONS + BIRTHS);
        // A maintenance notification makes reclamation progress with no client request.
        self.legacy_pending = self.maintenance_burst.again(
            work,
            work || self.departures.pending()
                || self.maintenance.remaining != 0
                || self.orphan_count != 0,
        );
        self.notify_maintenance();
    }

    fn between_notifications(&mut self, notice: rt::service::Notice) {
        if notice.source == rt::abi::Source::Unlabeled && notice.label == 0 {
            // The one cursor dispatch and its statistics have ended. An own
            // queued notice must not monopolize equal-priority FIFO services.
            let _ = sys::yield_now();
        }
    }

    /// Genuine ordinary and image labels each name their exact retained slot.
    fn place(&self, label: u64) -> Option<usize> {
        Some(self.places.place(label))
    }

    fn request(&mut self, s: &mut Session<Fds, 0>, r: &mut Request<'_>) -> Answer {
        self.maintenance_burst.restart();
        self.legacy_pending = true;
        let first = !s.data.claimed;
        if !s.data.claimed {
            // The first request of a session Clone made takes its
            // descriptors.
            let label = r.label();
            if let Some(birth) = self.birth_slot(label).map(|i| &mut self.births[i]) {
                // RT creates unclaimed sessions from Fds::default, with no held references.
                let claimed = s.data.claim_retained_birth(birth, label);
                debug_assert!(claimed);
            } else if r.label() & proto_fs::OWN != 0 && self.clones.client_of(r.label()).is_some() {
                // A Loader consumed this birth into a distinct label; surviving old copies
                // have cleanup authority only, regardless of a creator's retained handle.
                s.data.binding = Binding::Cleanup;
            }
            s.data.claimed = true;
            // Admission into the session table is one bounded phase of its own.
            // It cannot share a receive with the Process Vouch round trip.
            if s.data.binding_preparation.is_some() && r.method() == Method::FinishBinding as u16 {
                return status(proto_fs::RESOLVING);
            }
        }
        #[cfg(feature = "image-info-probe")]
        if r.method() == 0xfff7 {
            let mut body = r.body();
            let Ok(fault) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if body.finish().is_err() || !r.handles.is_empty() || !(1..=3).contains(&fault) {
                return Answer::Status(Status::BadSize);
            }
            let Some(who) = s.data.binding.snapshot_ref() else {
                return status(proto_fs::PERMISSION);
            };
            let Some(loader) = who.loader else {
                return status(proto_fs::PERMISSION);
            };
            if self.image_info_fault.is_some() {
                return status(proto_fs::PERMISSION);
            }
            self.image_info_fault = Some((who.pid, who.image, loader.ticket, fault));
            return Answer::Status(Status::Ok);
        }
        if first && proto_fs::is_loaders(r.label()) && r.method() == Method::BindPending as u16 {
            return self.pending_admission(r);
        }
        if proto_fs::is_image(r.label()) {
            #[cfg(feature = "auth-probe")]
            if r.method() == 0xfffa {
                if !r.handles.is_empty() || r.body().finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let held = s.data.image_hold;
                let pins = held
                    .and_then(|held| self.ram.storage.node(held.token).ok())
                    .map_or(0, |node| {
                        u32::from(node.pins[ramfs::storage::Pin::Image as usize])
                    });
                let usage = self.ram.storage.usage(s.data.root);
                let output = r.reply();
                if output
                    .u32(0)
                    .and_then(|()| output.u32(u32::from(held.is_some())))
                    .and_then(|()| output.u32(u32::from(s.data.authority_index != NONE)))
                    .and_then(|()| output.u32(u32::from(usage.descriptions)))
                    .and_then(|()| output.u32(pins))
                    .is_err()
                {
                    return Answer::Status(Status::BadSize);
                }
                return Answer::Reply(Outgoing::new());
            }
            #[cfg(feature = "image-gates")]
            if r.method() == 0xfff9 {
                if !r.handles.is_empty() || r.body().finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                if let Err(code) = self.image_authorize(&mut s.data, r.label()) {
                    return status(code);
                }
                let Some(who) = s.data.binding.snapshot_ref() else {
                    return status(proto_fs::PERMISSION);
                };
                let Some(held) = s.data.image_hold else {
                    return status(proto_fs::BAD_FD);
                };
                let Some(loader) = who.loader else {
                    return status(proto_fs::PERMISSION);
                };
                let label = r.label();
                let w = r.reply();
                let result = (|| {
                    w.u32(0)?;
                    w.u32(0)?;
                    w.u32(who.pid)?;
                    w.u32(who.index)?;
                    w.u32(who.image)?;
                    w.u32(u32::from(matches!(s.data.binding, Binding::Handoff(_))))?;
                    w.u64(who.generation)?;
                    w.u64(loader.ticket)?;
                    w.u64(label)?;
                    w.u64(held.root.id)?;
                    w.u64(held.root.generation)?;
                    w.u32(u32::from(held.token.slot))?;
                    w.u32(0)?;
                    w.u64(held.token.generation)
                })();
                if result.is_err() {
                    return Answer::Status(Status::BadSize);
                }
                return Answer::Reply(Outgoing::new());
            }
            if r.method() == Method::FinishBinding as u16 {
                return self.finish_binding(&mut s.data, r);
            }
            if r.method() == Method::Close as u16 {
                let mut body = r.body();
                if !r.handles.is_empty() || body.u32() != Ok(0) || body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                self.drop_identity(&mut s.data);
                self.ram.release_image(&mut s.data);
                s.data.binding = Binding::Cleanup;
                return Answer::Status(Status::Ok);
            }
            if let Err(code) = self.image_authorize(&mut s.data, r.label()) {
                return status(code);
            }
            return self.image(&mut s.data, r);
        }
        #[cfg(feature = "auth-probe")]
        if r.method() == 0xfffd {
            if !r.handles.is_empty()
                || r.body().finish().is_err()
                || !s
                    .data
                    .binding
                    .snapshot_ref()
                    .is_some_and(|who| generation(who.index as usize) == who.generation)
            {
                return status(proto_fs::PERMISSION);
            }
            s.data.auth_probe_hold = true;
            return Answer::Status(Status::Ok);
        }
        #[cfg(feature = "auth-probe")]
        if r.method() == 0xfffb {
            if !r.handles.is_empty() || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let (audit, target, audited) = self
                .identities
                .get(s.data.authority_index as usize)
                .and_then(Option::as_ref)
                .map_or((false, 0, 0), |identity| {
                    let (target, audited) = identity.audit.generations();
                    (identity.purpose == BindingPurpose::Audit, target, audited)
                });
            let retained = s
                .data
                .binding
                .snapshot_ref()
                .map_or(0, |who| who.generation);
            let output = r.reply();
            let written = output
                .u32(0)
                .and_then(|()| output.u32(u32::from(audit)))
                .and_then(|()| output.u64(target))
                .and_then(|()| output.u64(audited))
                .and_then(|()| output.u64(retained));
            return if written.is_ok() {
                Answer::Reply(Outgoing::new())
            } else {
                Answer::Status(Status::BadSize)
            };
        }
        #[cfg(feature = "auth-probe")]
        if r.method() == 0xfffc {
            return self.auth_probe_gc(&mut s.data, r);
        }
        #[cfg(feature = "auth-probe")]
        if r.method() == 0xfff8 {
            if !r.handles.is_empty() || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let counts = [
                s.data.preparation_count() as u32,
                self.ram.storage.preparations_used() as u32,
                self.ram.storage.preparations_for_root(s.data.root) as u32,
                self.ram.open_descriptions() as u32,
            ];
            let w = r.reply();
            return if w
                .u32(0)
                .and_then(|()| counts.into_iter().try_for_each(|n| w.u32(n)))
                .is_ok()
            {
                Answer::Reply(Outgoing::new())
            } else {
                Answer::Status(Status::BadSize)
            };
        }
        #[cfg(feature = "auth-probe")]
        if r.method() == 0xfffe {
            if !r.handles.is_empty() || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            let counts = s.data.retained_counts();
            let phase = self
                .identities
                .get(s.data.authority_index as usize)
                .and_then(Option::as_ref)
                .map_or(0, |identity| match identity.admission {
                    Admission::Unvouched => 1,
                    Admission::Wire(_) | Admission::RetainedWire(_) => 2,
                    Admission::Vouched(_) | Admission::RetainedVouched(_) => 3,
                    Admission::Validated(_) | Admission::RetainedValidated(_) => 4,
                });
            let output = r.reply();
            let result = output
                .u32(0)
                .and_then(|()| counts.into_iter().try_for_each(|count| output.u32(count)))
                .and_then(|()| output.u32(self.ram.open_descriptions() as u32))
                .and_then(|()| output.u32(self.ram.storage.preparations_used() as u32))
                .and_then(|()| output.u32(phase));
            return if result.is_ok() {
                Answer::Reply(Outgoing::new())
            } else {
                Answer::Status(Status::BadSize)
            };
        }
        if r.method() == Method::FinishBinding as u16 {
            return self.finish_binding(&mut s.data, r);
        }
        if s.data.binding_preparation.is_some()
            && !(r.method() == Method::Bind as u16 && self.can_replace_refresh(&s.data))
            && !matches!(
                Method::from_number(r.method()),
                Some(
                    Method::Close
                        | Method::CloseExact
                        | Method::CloseEvent
                        | Method::ResolveCancel
                        | Method::OpenCancel
                        | Method::DataCancel
                        | Method::DataAck
                        | Method::ChangeRelease
                        | Method::LockStart
                        | Method::LockQuery
                        | Method::LockCancel
                        | Method::LockRelease
                        | Method::WaitStart
                        | Method::WaitQuery
                        | Method::WaitArm
                        | Method::WaitCancel
                        | Method::WaitRelease
                        | Method::VerifySession
                )
            )
        {
            return status(proto_fs::AUTHENTICATING);
        }
        if r.method() == Method::Bind as u16 {
            return self.bind(&mut s.data, r);
        }
        if r.method() == Method::BindPending as u16 {
            return self.bind_pending(r);
        }
        if matches!(
            Method::from_number(r.method()),
            Some(Method::LockStart | Method::LockQuery | Method::LockRelease | Method::LockCancel)
        ) {
            return self.lock_request(&mut s.data, r);
        }
        if matches!(
            Method::from_number(r.method()),
            Some(
                Method::WaitStart
                    | Method::WaitQuery
                    | Method::WaitCancel
                    | Method::WaitRelease
                    | Method::WaitArm
            )
        ) {
            return self.wait_request(&mut s.data, r);
        }
        // Keyed common operations preserve the native lock family's custody.
        if matches!(
            Method::from_number(r.method()),
            Some(
                Method::DataStart
                    | Method::DataQuery
                    | Method::DataCancel
                    | Method::DataAck
                    | Method::DataReadResult
                    | Method::ChangeStart
                    | Method::ChangeSecond
                    | Method::ChangeStep
                    | Method::ChangeQuery
                    | Method::ChangeRelease
                    | Method::OpenStart
                    | Method::OpenCancel
                    | Method::OpenQuery
                    | Method::OpenFinish
            )
        ) {
            let mut body = r.body();
            if let (Ok(slot), Ok(generation)) = (body.u32(), body.u64())
                && (32..48).contains(&slot)
                && generation != 0
            {
                let place = self.places.place(r.label());
                match self.lock_jobs.occupied(place, r.label(), slot) {
                    Ok(None) => {}
                    Ok(Some(_)) | Err(_) => return status(proto_fs::PERMISSION),
                }
            }
        }
        if matches!(
            Method::from_number(r.method()),
            Some(
                Method::DataStart
                    | Method::DataFeed
                    | Method::DataStep
                    | Method::DataCommit
                    | Method::DataQuery
                    | Method::DataCancel
                    | Method::DataAck
                    | Method::DataReadResult
            )
        ) {
            return self.data_request(&mut s.data, r);
        }
        if matches!(
            Method::from_number(r.method()),
            Some(
                Method::ChangeStart
                    | Method::ChangeSecond
                    | Method::ChangeStep
                    | Method::ChangeQuery
                    | Method::ChangeRelease
            )
        ) {
            return self.change_request(&mut s.data, r);
        }
        if matches!(
            Method::from_number(r.method()),
            Some(
                Method::ResolveStart
                    | Method::ResolveStep
                    | Method::ResolveCancel
                    | Method::ResolveSecond
                    | Method::OpenStart
                    | Method::OpenPrepare
                    | Method::OpenCommit
                    | Method::OpenFinish
                    | Method::OpenCancel
                    | Method::OpenQuery
            )
        ) {
            return self.resolve_request(&mut s.data, r);
        }
        if r.method() == Method::OpenExec as u16 {
            return self.open_exec(&mut s.data, r);
        }
        if r.method() == Method::VerifySession as u16 {
            return self.verify_clone(&mut s.data, r);
        }
        // Raw LoaderRoot requests must first obtain their own Pending session.
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let cleanup = matches!(
            Method::from_number(r.method()),
            Some(Method::Close | Method::CloseExact | Method::CloseEvent | Method::ResolveCancel)
        );
        if !cleanup && let Err(code) = self.authenticate(&mut s.data, r.label()) {
            return status(code);
        }
        #[cfg(feature = "lifetime-probe")]
        if r.method() == 0xfff3 {
            if !r.handles.is_empty() || s.data.binding.snapshot_ref().is_none() {
                return Answer::Status(Status::BadSize);
            }
            let mut body = r.body();
            let Ok(pid) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if body.finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            if !self.register_lifetimes() {
                return status(proto_fs::PERMISSION);
            }
            if !self.lock_dispatch.audited() {
                return status(proto_fs::RESOLVING);
            }
            let live = self.lifetimes.as_ref().expect("registered page").live(pid);
            let counts = self.locks.counts();
            if self.locks.busy() || counts != ramfs::locks::budget::Counts::default() {
                return status(proto_fs::PERMISSION);
            }
            let Ok(memory) = sys::process_memory(&self.process) else {
                return status(proto_fs::PERMISSION);
            };
            let free = memory.quota.saturating_sub(memory.used) / 4096;
            if free < 128 {
                return status(proto_fs::NO_SPACE);
            }
            let reply = r.reply();
            if reply
                .u32(0)
                .and_then(|()| reply.u32(u32::from(live)))
                .and_then(|()| reply.u64(memory.quota))
                .and_then(|()| reply.u64(memory.used))
                .and_then(|()| reply.u32(self.lock_jobs.retained() as u32))
                .and_then(|()| reply.u32(self.places.used() as u32))
                .is_err()
            {
                return Answer::Status(Status::BadSize);
            }
            return Answer::Reply(Outgoing::new());
        }
        #[cfg(all(feature = "signal-probe", not(feature = "steps")))]
        if r.method() == 0xfff4 {
            if !r.handles.is_empty() || r.body().finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            if s.data.binding.snapshot_ref().is_none() {
                return status(proto_fs::PERMISSION);
            }
            // A private timer wakes this fixture while ordinary requests stay queued.
            let channel = match sys::channel_create(1) {
                Ok(channel) => channel,
                Err(error) => return Answer::Status(Status::Kernel(error)),
            };
            let timer = match sys::timer_create(&channel, self.level) {
                Ok(timer) => timer,
                Err(error) => return Answer::Status(Status::Kernel(error)),
            };
            let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(20_000_000);
            if let Err(error) = sys::timer_set(&timer, deadline) {
                return Answer::Status(Status::Kernel(error));
            }
            if let Some(pending) = r.defer()
                && pending
                    .answer(&proto_wire::reply(Status::Ok), Outgoing::new())
                    .is_ok()
            {
                let _ = sys::receive(&channel);
            }
            return Answer::Deferred;
        }
        #[cfg(feature = "steps")]
        if r.method() == 0xfff5 {
            if !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
            let mut body = r.body();
            let Ok(command) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if body.finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            match command {
                0 if self.steps_reclaim_owner.is_none() => {
                    self.steps_reclaim_owner = Some(r.label());
                }
                1 if self.steps_reclaim_owner == Some(r.label()) => {}
                3 if self.steps_reclaim_owner == Some(r.label()) => {
                    return value(r, u32::from(self.ram.storage.usage(s.data.root).pages));
                }
                2 if self.steps_reclaim_owner == Some(r.label()) => {
                    self.steps_reclaim_owner = None;
                    let _ = sys::notify(&self.channel, 1);
                }
                _ => return status(proto_fs::INVALID_ARGUMENT),
            }
            return value(r, self.ram.storage.reclaim_backlog() as u32);
        }
        let mut body = r.body();
        match Method::from_number(r.method()) {
            Some(Method::Clone | Method::CloneExact) => self.clone_session(&s.data, r),
            Some(
                Method::OpenExec
                | Method::ReadInto
                | Method::VerifySession
                | Method::Bind
                | Method::BindPending
                | Method::ResolveStart
                | Method::ResolveStep
                | Method::ResolveCancel
                | Method::ResolveSecond
                | Method::FinishBinding
                | Method::OpenStart
                | Method::OpenPrepare
                | Method::OpenCommit
                | Method::OpenFinish
                | Method::OpenCancel
                | Method::OpenQuery,
            ) => status(proto_fs::PERMISSION),
            Some(Method::Open) => {
                let Ok(flags) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let token = match self.proof(job, r.label(), Some(&s.data)) {
                    Ok((t, _)) => t,
                    Err(code) => return status(code),
                };
                let identity = s
                    .data
                    .binding
                    .identity(false)
                    .expect("authenticated session");
                let opened = self.ram.open_token(&mut s.data, token, flags, identity);
                self.cancel_job(job, r.label(), Some(&mut s.data));
                match opened {
                    Ok(fd) if self.ram.is_random(&s.data, fd) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(fd))
                            .and_then(|()| w.u32(proto_fs::RANDOM_DEVICE))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Ok(fd) => value(r, fd),
                    Err(code) => status(code),
                }
            }
            Some(Method::Read) => {
                let (Ok(fd), Ok(count)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self.ram.read_at(
                    &mut s.data,
                    fd,
                    &mut bytes[..count as usize],
                    self.time_source.now(),
                ) {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadAt) => {
                let (Ok(fd), Ok(offset), Ok(count)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || count as usize > MAX_READ {
                    return Answer::Status(Status::BadSize);
                }
                let mut bytes = [0; MAX_READ];
                match self.ram.pread(
                    &s.data,
                    fd,
                    offset,
                    &mut bytes[..count as usize],
                    self.time_source.now(),
                ) {
                    Ok(n) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(n as u32))
                            .and_then(|()| w.bytes(&bytes[..n]))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Write) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(bytes) = body.bytes(body.left()) else {
                    return Answer::Status(Status::BadSize);
                };
                if bytes.len() > MAX_WRITE {
                    return Answer::Status(Status::BadSize);
                }
                match self
                    .ram
                    .write_at(&mut s.data, fd, bytes, self.time_source.now())
                {
                    Ok(n) => value(r, n as u32),
                    Err(code) => status(code),
                }
            }
            Some(Method::WriteAt) => {
                let (Ok(fd), Ok(offset)) = (body.u32(), body.u64()) else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(bytes) = body.bytes(body.left()) else {
                    return Answer::Status(Status::BadSize);
                };
                match self
                    .ram
                    .pwrite(&mut s.data, fd, offset, bytes, self.time_source.now())
                {
                    Ok(n) => value(r, n as u32),
                    Err(code) => status(code),
                }
            }
            Some(Method::Seek) => {
                let (Ok(fd), Ok(offset)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.seek(&mut s.data, fd, offset) {
                    Ok(offset) => value(r, offset),
                    Err(code) => status(code),
                }
            }
            Some(Method::SeekFrom) => {
                let (Ok(fd), Ok(offset), Ok(origin)) = (body.u32(), body.u64(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let Some(origin) = proto_fs::SeekFrom::from_number(origin) else {
                    return status(proto_fs::INVALID_ARGUMENT);
                };
                match self.ram.seek_from(&mut s.data, fd, offset as i64, origin) {
                    Ok(offset) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| w.u64(offset as u64)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Stat) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.size(&s.data, fd) {
                    Ok(size) => value(r, size),
                    Err(code) => status(code),
                }
            }
            Some(Method::CaptureDescription) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() || !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                let (held, flags) = match self.ram.capture_description(&s.data, fd) {
                    Ok(captured) => captured,
                    Err(code) => return status(code),
                };
                let packed = match self.ram.marked_open(&s.data, held) {
                    Ok(word) => word,
                    Err(code) => return status(code),
                };
                if r.reply()
                    .u32(0)
                    .and_then(|()| r.reply().u32(packed))
                    .and_then(|()| r.reply().u64(held.description.generation))
                    .and_then(|()| r.reply().u32(flags))
                    .is_err()
                {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(Outgoing::new())
            }
            Some(Method::CloseEvent) => {
                if !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                let event = match proto_fs::CloseEvent::read(body) {
                    Ok(event) => event,
                    Err(error) => return Answer::Status(error),
                };
                match self.ram.close_event(&mut s.data, self.locks, event) {
                    Ok(()) => {
                        self.wait_events.poll();
                        self.notify_maintenance();
                        Answer::Status(Status::Ok)
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::CloseExact) => {
                let (Ok(packed), Ok(generation)) = (body.u32(), body.u64()) else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err()
                    || !r.handles.is_empty()
                    || packed & !(proto_fs::OPEN_FD_MASK | proto_fs::OPEN_DESCRIPTION_MASK) != 0
                    || !(3..35).contains(&(packed & proto_fs::OPEN_FD_MASK))
                    || generation == 0
                {
                    return Answer::Status(Status::BadSize);
                }
                let held = ramfs::TentativeOpen {
                    fd: packed & proto_fs::OPEN_FD_MASK,
                    description: ramfs::storage::Token {
                        slot: ((packed & proto_fs::OPEN_DESCRIPTION_MASK)
                            >> proto_fs::OPEN_DESCRIPTION_SHIFT)
                            as u16,
                        generation,
                    },
                };
                match self.ram.close_exact_description(&mut s.data, held) {
                    Ok(closed) => value(r, u32::from(!closed)),
                    Err(code) => status(code),
                }
            }
            Some(Method::Close) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self.ram.close(&mut s.data, fd) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadDir) => {
                let Ok(index) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let token = match self.proof(job, r.label(), Some(&s.data)) {
                    Ok((t, _)) => t,
                    Err(code) => return status(code),
                };
                let identity = s
                    .data
                    .binding
                    .identity(false)
                    .expect("authenticated session");
                let found =
                    self.ram
                        .directory_read_token(token, index, identity, self.time_source.now());
                self.cancel_job(job, r.label(), Some(&mut s.data));
                match found {
                    Ok(entry) => {
                        let (name, kind) = entry
                            .as_ref()
                            .map_or((&b""[..], 0), |entry| (entry.name(), entry.kind));
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(kind))
                            .and_then(|()| w.bytes(name))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::ReadDirFd) => {
                let Ok(fd) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                if body.finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                match self
                    .ram
                    .directory_read(&mut s.data, fd, self.time_source.now())
                {
                    Ok(entry) => {
                        let entry = entry.as_ref().map(|entry| proto_fs::DirectoryEntry {
                            name: entry.name(),
                            kind: entry.kind,
                            inode: entry.inode,
                        });
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| proto_fs::DirectoryEntry::write(entry, w))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::InfoFd | Method::InfoPath) => {
                let info = if r.method() == Method::InfoFd as u16 {
                    let Ok(fd) = body.u32() else {
                        return Answer::Status(Status::BadSize);
                    };
                    if body.finish().is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    self.ram.descriptor_information(&s.data, fd)
                } else {
                    let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                        return Answer::Status(Status::BadSize);
                    };
                    let token = match self.proof(job, r.label(), Some(&s.data)) {
                        Ok((t, _)) => t,
                        Err(code) => return status(code),
                    };
                    let info = self.ram.token_information(token);
                    self.cancel_job(job, r.label(), Some(&mut s.data));
                    info
                };
                match info {
                    Ok(info) => {
                        let w = r.reply();
                        if w.u32(0).and_then(|()| info.write(w)).is_err() {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(Method::Lookup) => {
                let (Ok(job), Ok(())) = (body.u64(), body.finish()) else {
                    return Answer::Status(Status::BadSize);
                };
                let token = match self.proof(job, r.label(), Some(&s.data)) {
                    Ok((t, _)) => t,
                    Err(code) => return status(code),
                };
                let found = self
                    .ram
                    .token_information(token)
                    .map(|i| proto_fs::Metadata {
                        kind: i.kind,
                        size: i.size as u32,
                    });
                self.cancel_job(job, r.label(), Some(&mut s.data));
                match found {
                    Ok(meta) => {
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(meta.kind))
                            .and_then(|()| w.u32(meta.size))
                            .is_err()
                        {
                            return Answer::Status(Status::BadSize);
                        }
                        Answer::Reply(Outgoing::new())
                    }
                    Err(code) => status(code),
                }
            }
            Some(
                Method::DataStart
                | Method::DataFeed
                | Method::DataStep
                | Method::DataCommit
                | Method::DataQuery
                | Method::DataCancel
                | Method::DataAck
                | Method::DataReadResult
                | Method::ChangeStart
                | Method::ChangeSecond
                | Method::ChangeStep
                | Method::ChangeQuery
                | Method::ChangeRelease
                | Method::LockStart
                | Method::LockQuery
                | Method::LockCancel
                | Method::LockRelease
                | Method::WaitStart
                | Method::WaitQuery
                | Method::WaitCancel
                | Method::WaitRelease
                | Method::WaitArm,
            )
            | None => Answer::Status(Status::UnknownMethod),
        }
    }
}

const GENERATIONS: usize = 0x51_0000_0000;
fn generation(index: usize) -> u64 {
    if index >= proto_process::RECORDS {
        return proto_process::GENERATION_DEAD;
    }
    // SAFETY: notary_register maps the page read-only for the service's life.
    unsafe {
        (&*((GENERATIONS + index * 8) as *const core::sync::atomic::AtomicU64))
            .load(core::sync::atomic::Ordering::Acquire)
    }
}
impl Fs {
    /// FIFO ready selection and prepaid receipt scanning each have their own turn.
    fn next_wait_ready(&mut self) -> Option<ramfs::locks::wait_receipts::Id> {
        if self.wait_pool.count() == 0 || self.wait_ready_scanned {
            self.wait_ready_scanned = false;
            let id = self.wait_jobs.next_ready()?;
            if let Some(registration) = self.wait_pool.find(id)
                && self.wait_pool.snapshot(registration).ok()?.1
                    == ramfs::locks::waiters::Phase::Ready
            {
                self.wait_pool.run(registration).expect("exact ready WAIT");
            }
            return Some(id);
        }
        let cursor = self
            .wait_ready_scan
            .get_or_insert_with(|| self.wait_pool.cursor());
        let mut chosen = None;
        let scanned = self.wait_pool.scan(cursor, |token, _, phase| {
            if chosen.is_none() && phase == ramfs::locks::waiters::Phase::Ready {
                chosen = Some(token);
            }
        });
        if scanned.is_err() {
            self.wait_ready_scan = None;
            return None;
        }
        if let Some(registration) = chosen {
            self.wait_ready_scan = None;
            self.wait_pool
                .run(registration)
                .expect("exact FIFO WAIT attempt");
            Some(registration.receipt())
        } else {
            if cursor.done() {
                self.wait_ready_scan = None;
                self.wait_ready_scanned = true;
            }
            None
        }
    }
    fn refresh_wait_timer(&mut self) {
        let pending = self.wait_pool.count() != 0;
        if pending && !self.wait_timer_armed {
            let deadline =
                rt::time::ticks_to_ns(rt::time::now()).saturating_add(WAIT_TIMER_PERIOD_NS);
            self.wait_timer_armed = sys::timer_set(&self.wait_timer, deadline).is_ok();
        } else if !pending && self.wait_timer_armed {
            let _ = sys::timer_cancel(&self.wait_timer);
            self.wait_timer_armed = false;
        }
    }
    fn publish_wait(&mut self, id: ramfs::locks::wait_receipts::Id) {
        if let Some(registration) = self.wait_pool.find(id) {
            self.wait_events
                .detach(registration)
                .expect("exact terminal WAIT wake retirement");
        }
        self.wait_notify
            .complete(self.wait_jobs, self.wait_pool, id, |handle| {
                let _ = sys::notify(handle, 1);
            })
            .expect("canonical WAIT before Notify retirement");
        self.refresh_wait_timer();
    }
    fn wait_request(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let method = Method::from_number(r.method()).expect("native WAIT method");
        let arm = method == Method::WaitArm;
        if (arm && r.handles.len() != 1) || (!arm && !r.handles.is_empty()) {
            return Answer::Status(Status::BadSize);
        }
        let owner = r.label();
        let place = self.places.place(owner);
        let result = if method == Method::WaitStart {
            let wire = match proto_fs::WaitStart::read(r.body()) {
                Ok(wire) => wire,
                Err(error) => return Answer::Status(error),
            };
            match ramfs::locks::wait_server::replay(self.wait_jobs, place, owner, wire) {
                Ok(Some(reply)) => Ok(reply),
                Err(code) => Err(code),
                Ok(None) => {
                    if let Err(code) = self.authenticate(fds, owner) {
                        return status(code);
                    }
                    if wire.mode == proto_fs::WaitMode::Pid && !self.register_lifetimes() {
                        return status(proto_fs::NO_LOCKS);
                    }
                    ramfs::locks::wait_server::start(
                        self.wait_jobs,
                        self.ram,
                        fds,
                        place,
                        owner,
                        wire,
                    )
                }
            }
        } else {
            let key = match proto_fs::read_wait_key(r.body()) {
                Ok(key) => key,
                Err(error) => return Answer::Status(error),
            };
            if method == Method::WaitRelease {
                if let Ok(Some(id)) = self.wait_jobs.occupied(place, owner, key.slot)
                    && id.key() == key
                    && self
                        .wait_jobs
                        .query(id)
                        .is_ok_and(|reply| reply.phase == proto_fs::WaitPhase::Complete)
                {
                    self.publish_wait(id);
                }
                let result =
                    ramfs::locks::wait_server::release(self.wait_jobs, self.ram, place, owner, key);
                self.notify_maintenance();
                return match result {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                };
            }
            if arm {
                if !matches!(r.handles.info(0), Some((rt::abi::ObjectKind::Channel, rights))
                    if rights == (Rights::NOTIFY | Rights::TRANSFER))
                {
                    return Answer::Status(Status::BadSize);
                }
                let handle = match r.handles.take::<Channel>(0) {
                    Ok(handle) => handle,
                    Err(error) => return Answer::Status(Status::Kernel(error)),
                };
                match self.wait_jobs.occupied(place, owner, key.slot) {
                    Ok(Some(id)) if id.key() == key => {
                        self.wait_notify
                            .arm(self.wait_jobs, self.wait_pool, id, handle)
                    }
                    Ok(Some(id)) => Err(if key.generation <= id.key().generation {
                        proto_fs::OPEN_RETIRED
                    } else {
                        proto_fs::JOBS_FULL
                    }),
                    Ok(None) => Err(
                        if self.wait_jobs.is_retired(place, owner, key).unwrap_or(true) {
                            proto_fs::OPEN_RETIRED
                        } else {
                            proto_fs::NO_ENTRY
                        },
                    ),
                    Err(code) => Err(code),
                }
            } else if method == Method::WaitCancel {
                match ramfs::locks::wait_server::cancel(self.wait_jobs, place, owner, key) {
                    Ok((reply, active)) => {
                        if active {
                            self.locks.cancel();
                        }
                        if reply.phase == proto_fs::WaitPhase::Complete
                            && let Ok(Some(id)) = self.wait_jobs.occupied(place, owner, key.slot)
                        {
                            self.publish_wait(id);
                        }
                        Ok(reply)
                    }
                    Err(code) => Err(code),
                }
            } else {
                ramfs::locks::wait_server::query(self.wait_jobs, place, owner, key)
            }
        };
        self.notify_maintenance();
        match result {
            Ok(reply) => match reply.write(r.reply()) {
                Ok(()) => Answer::Reply(Outgoing::new()),
                Err(error) => Answer::Status(error),
            },
            Err(code) => status(code),
        }
    }
    /// Retain only the full paid Control key while the finite read-only selector
    /// runs; its credit survives internal cancellation and another queue turn.
    fn select_control(&mut self, sessions: &[Option<Session<Fds, 0>>]) {
        let id = if let Some(id) = self.wait_selection {
            id
        } else {
            let Some(id) = self.lock_jobs.next_ready() else {
                return;
            };
            let Ok((captured, phase, cancelling)) = self.lock_jobs.snapshot(id) else {
                return;
            };
            if phase != ramfs::locks::jobs::Phase::Queued || cancelling {
                return;
            }
            if self
                .wait_selector
                .begin(id, captured, self.wait_pool, self.lock_jobs)
                .is_err()
            {
                return;
            }
            self.wait_selection = Some(id);
            id
        };
        if !self
            .lock_jobs
            .snapshot(id)
            .is_ok_and(|(_, phase, cancelling)| {
                phase == ramfs::locks::jobs::Phase::Queued && !cancelling
            })
        {
            self.wait_selection = None;
            return;
        }
        let page = self.lifetimes.as_ref();
        let locks = &*self.locks;
        let (_, descriptions) = self.ram.lock_parts();
        let progress = locks.select_part(
            self.wait_selector,
            self.wait_pool,
            self.wait_jobs,
            self.lock_jobs,
            |pid| page.is_some_and(|page| page.live(pid)) && locks.pid_visible(pid),
            |ofd| descriptions.live(ofd),
        );
        let Some(decision) = progress.decision else {
            return;
        };
        self.wait_selection = None;
        if let WaitDecision::Wait(candidate) = decision {
            let receipt = candidate.registration.receipt();
            // Final full custody/capture gate; actual fd authority is checked by begin.
            if self
                .wait_pool
                .snapshot(candidate.registration)
                .is_ok_and(|(_, phase)| {
                    matches!(
                        phase,
                        ramfs::locks::waiters::Phase::Ready
                            | ramfs::locks::waiters::Phase::Sleeping
                    )
                })
                && self
                    .wait_jobs
                    .snapshot(receipt)
                    .is_ok_and(|(captured, phase, cancelling)| {
                        captured == candidate.captured
                            && !cancelling
                            && matches!(
                                phase,
                                ramfs::locks::wait_receipts::Phase::Ready
                                    | ramfs::locks::wait_receipts::Phase::Sleeping
                            )
                    })
            {
                if self.wait_jobs.snapshot(receipt).is_ok_and(|(_, phase, _)| {
                    phase == ramfs::locks::wait_receipts::Phase::Sleeping
                }) {
                    self.wait_jobs
                        .ready(receipt)
                        .expect("exact eligible sleeping receipt");
                }
                self.wait_pool
                    .ready(candidate.registration)
                    .expect("exact eligible registration");
                self.wait_pool
                    .run(candidate.registration)
                    .expect("eligible registration ready");
                self.begin_wait(receipt, sessions);
                return;
            }
        }
        let place = usize::from(id.slot()) / ramfs::locks::jobs::SHARE;
        let source = sessions
            .get(place)
            .and_then(Option::as_ref)
            .filter(|session| session.label() == id.owner() && session.data.claimed)
            .map(|session| &session.data)
            .or_else(|| {
                self.births
                    .get(Self::birth_index(id.owner()))
                    .and_then(Option::as_ref)
                    .filter(|(label, _)| *label == id.owner())
                    .map(|(_, fds)| fds)
            });
        ramfs::locks::server::begin(self.lock_jobs, self.locks, self.ram, id, source);
    }
    fn begin_wait(
        &mut self,
        id: ramfs::locks::wait_receipts::Id,
        sessions: &[Option<Session<Fds, 0>>],
    ) {
        let place = usize::from(id.slot()) / ramfs::locks::wait_receipts::SHARE;
        let source = sessions
            .get(place)
            .and_then(Option::as_ref)
            .filter(|session| session.label() == id.owner() && session.data.claimed)
            .map(|session| &session.data)
            .or_else(|| {
                self.births
                    .get(Self::birth_index(id.owner()))
                    .and_then(Option::as_ref)
                    .filter(|(label, _)| *label == id.owner())
                    .map(|(_, fds)| fds)
            });
        ramfs::locks::wait_server::begin(self.wait_jobs, self.locks, self.ram, id, source)
            .expect("exact queued WAIT attempt");
        if self
            .wait_jobs
            .query(id)
            .is_ok_and(|reply| reply.phase == proto_fs::WaitPhase::Complete)
        {
            self.publish_wait(id);
        }
    }
    /// Schedule one finite optional episode. Events coalesce; completion itself
    /// never schedules another episode or self-notifies.
    fn schedule_wait_proof(&mut self) {
        if self.wait_proof_disabled
            || self.wait_proof_active
            || self.wait_proof_scan.is_some()
            || self.wait_proof_choice.is_some()
            || self.wait_pool.count() == 0
        {
            return;
        }
        self.wait_proof_scan = Some(self.wait_pool.cursor());
        self.wait_proof_scan_remaining = ramfs::locks::waiters::CAPACITY as u8;
    }
    fn wait_proof_pending(&self) -> bool {
        self.wait_proof_active || self.wait_proof_scan.is_some() || self.wait_proof_choice.is_some()
    }
    /// Caller gives this helper its own maintenance turn; never follow an
    /// eight-object Actor/Reader/Selector portion in the same turn.
    fn tick_wait_proof(&mut self, sessions: &[Option<Session<Fds, 0>>]) {
        if self.wait_proof_active {
            let page = self.lifetimes.as_ref();
            let (storage, descriptions) = self.ram.lock_parts();
            let locks = &*self.locks;
            let progress = self.wait_proof.step(
                self.wait_jobs,
                self.wait_pool,
                self.locks,
                storage,
                |pid| page.is_some_and(|page| page.live(pid)) && locks.pid_visible(pid),
                |ofd| descriptions.live(ofd),
            );
            let Some(outcome) = progress.outcome else {
                return;
            };
            self.wait_proof_active = false;
            if outcome.verdict == ramfs::locks::deadlock::Verdict::Deadlock
                && self.wait_proof_source_live(sessions, outcome)
            {
                self.wait_jobs
                    .complete(
                        outcome.candidate,
                        proto_fs::WaitReply {
                            phase: proto_fs::WaitPhase::Complete,
                            result: proto_fs::LOCK_DEADLOCK,
                        },
                    )
                    .expect("exact pending proof candidate canonical completion");
                self.publish_wait(outcome.candidate);
            }
            return;
        }
        if let Some(cursor) = &mut self.wait_proof_scan {
            let queue = &*self.wait_jobs;
            let next = self.wait_proof_next;
            let choice = &mut self.wait_proof_choice;
            let scanned = self.wait_pool.scan(cursor, |token, _, phase| {
                if phase != ramfs::locks::waiters::Phase::Sleeping {
                    return;
                }
                let Ok((captured, phase, cancelling)) = queue.snapshot(token.receipt()) else {
                    return;
                };
                if phase != ramfs::locks::wait_receipts::Phase::Sleeping
                    || cancelling
                    || !matches!(captured.request.owner, ramfs::locks::Owner::Process(_))
                {
                    return;
                }
                let rank = ((token.slot() + ramfs::locks::waiters::CAPACITY - usize::from(next))
                    % ramfs::locks::waiters::CAPACITY) as u8;
                if choice.as_ref().is_none_or(|old| rank < old.0) {
                    *choice = Some((rank, token, captured));
                }
            });
            match scanned {
                Err(_) => {
                    self.wait_proof_scan = None;
                    self.wait_proof_choice = None;
                }
                Ok(visited) => {
                    self.wait_proof_scan_remaining =
                        self.wait_proof_scan_remaining.saturating_sub(visited as u8);
                    if cursor.done() || self.wait_proof_scan_remaining == 0 {
                        self.wait_proof_scan = None;
                    }
                }
            }
            return;
        }
        let Some((_, token, captured)) = self.wait_proof_choice.take() else {
            return;
        };
        self.wait_proof_next = ((token.slot() + 1) % ramfs::locks::waiters::CAPACITY) as u8;
        let Some(serial) = self.wait_proof_serial.checked_add(1) else {
            self.wait_proof_disabled = true;
            return;
        };
        self.wait_proof_serial = serial;
        let receipt = token.receipt();
        self.wait_proof_active = self.wait_proof.start(
            self.wait_jobs,
            self.wait_pool,
            token,
            captured,
            ramfs::locks::deadlock::Scope {
                owner: receipt.owner(),
                key: receipt.key(),
                scan: serial,
            },
        );
    }
    /// A proof spans service turns; recheck exact local and genuine RAM source
    /// authority immediately before publishing an optional terminal error.
    fn wait_proof_source_live(
        &self,
        sessions: &[Option<Session<Fds, 0>>],
        outcome: ramfs::locks::wait_proof::Outcome,
    ) -> bool {
        let id = outcome.candidate;
        let Some(registration) = self.wait_pool.find(id) else {
            return false;
        };
        if !self
            .wait_pool
            .snapshot(registration)
            .is_ok_and(|(input, phase)| {
                phase == ramfs::locks::waiters::Phase::Sleeping
                    && input.root == outcome.captured.root
                    && input.inode == outcome.captured.request.inode
                    && input.range == outcome.captured.request.range
                    && outcome.captured.request.command
                        == ramfs::locks::actor::Command::Set(Some(input.kind))
            })
            || !self
                .wait_jobs
                .snapshot(id)
                .is_ok_and(|(captured, phase, cancelling)| {
                    captured == outcome.captured
                        && phase == ramfs::locks::wait_receipts::Phase::Sleeping
                        && !cancelling
                })
        {
            return false;
        }
        let ramfs::locks::Owner::Process(pid) = outcome.captured.request.owner else {
            return false;
        };
        if !self.lifetimes.as_ref().is_some_and(|page| page.live(pid))
            || !self.locks.pid_visible(pid)
        {
            return false;
        }
        let place = usize::from(id.slot()) / ramfs::locks::wait_receipts::SHARE;
        let source = sessions
            .get(place)
            .and_then(Option::as_ref)
            .filter(|session| session.label() == id.owner() && session.data.claimed)
            .map(|session| &session.data)
            .or_else(|| {
                self.births
                    .get(Self::birth_index(id.owner()))
                    .and_then(Option::as_ref)
                    .filter(|(label, _)| *label == id.owner())
                    .map(|(_, fds)| fds)
            });
        source
            .filter(|fds| !fds.departed)
            .and_then(|fds| self.ram.live_description(fds, outcome.captured.source).ok())
            .is_some_and(|(inode, _)| inode == outcome.captured.request.inode)
    }
    fn notify_maintenance(&self) {
        if self.legacy_pending
            || self.wait_events.pending()
            || self.wait_proof_pending()
            || self.lock_dispatch.pending(
                self.locks.busy() || self.lock_jobs.has_work() || self.wait_jobs.has_work(),
            )
        {
            let _ = sys::notify(&self.channel, 1);
        }
    }
    fn register_lifetimes(&mut self) -> bool {
        if self.lifetimes.is_some() {
            return true;
        }
        let Some(notary) = self.notary() else {
            return false;
        };
        let Some(page) = lifetime_page::Lifetimes::receive(notary) else {
            return false;
        };
        let Some(page) = lifetime_page::Lifetimes::map(page, &self.process) else {
            return false;
        };
        self.lifetimes = Some(page);
        let _ = sys::notify(&self.channel, 1);
        true
    }
    fn notary_register(&mut self) -> bool {
        if self.generations.is_some() {
            return true;
        }
        let Some(notary) = self.notary() else {
            return false;
        };
        let request = proto_process::Method::Register.header().bytes();
        let Ok(mut reply) = sys::send(notary, &request) else {
            return false;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
            return false;
        }
        let Ok(page) = reply.handles.take::<Memory>(0) else {
            return false;
        };
        if sys::mem_map(&self.process, &page, 0, 4096, GENERATIONS, Access::Read).is_err() {
            return false;
        }
        self.generations = Some(page);
        true
    }
    /// Only transport happens in this phase. Decoding the genuine Process reply
    /// is another receive, before any identity or inode effect is committed.
    fn vouch_wire(&mut self, identity: &Handle<Channel>) -> NotaryReply<252> {
        let Ok(copy) = sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER) else {
            return NotaryReply::Retry;
        };
        let request = proto_process::Method::Vouch.header().bytes();
        let Some(notary) = self.notary.as_ref() else {
            return NotaryReply::Retry;
        };
        let Ok(reply) = sys::send_handles(notary, &request, [copy.erase()]) else {
            return NotaryReply::Retry;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        NotaryReply::read(reply.bytes(&mut buffer), reply.handles.is_empty())
    }
    fn retained_wire(&mut self, identity: &Handle<Channel>, original: Binding) -> NotaryReply<260> {
        let Some(who) = original.snapshot_ref() else {
            return NotaryReply::Denied;
        };
        let Some(loader) = who.loader else {
            return NotaryReply::Denied;
        };
        let expected = proto_process::RetainedLoader {
            pid: who.pid,
            index: who.index,
            image: who.image,
            ticket: loader.ticket,
            root: who.root,
        };
        let Ok(copy) = sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER) else {
            return NotaryReply::Retry;
        };
        let mut request = proto_wire::Writer::new();
        if proto_process::Method::RetainedLoader
            .header()
            .write(&mut request)
            .and_then(|()| expected.write(&mut request))
            .is_err()
        {
            return NotaryReply::Retry;
        }
        let Some(notary) = self.notary.as_ref() else {
            return NotaryReply::Retry;
        };
        let Ok(reply) = sys::send_handles(notary, request.as_bytes(), [copy.erase()]) else {
            // A lost transport response proves no loader abort. The next paid
            // phase retries this read with a fresh copy of the retained identity.
            return NotaryReply::Retry;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        NotaryReply::read(reply.bytes(&mut buffer), reply.handles.is_empty())
    }
    fn install_identity(
        &mut self,
        fds: &mut Fds,
        label: u64,
        identity: Handle<Channel>,
        retain_previous: bool,
    ) -> Result<(), u32> {
        let i = if fds.authority_index == NONE {
            self.identities
                .take_free()
                .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?
        } else {
            fds.authority_index as usize
        };
        let previous = self.identities[i].take().and_then(|old| {
            if retain_previous {
                Some(old.channel)
            } else {
                None
            }
        });
        self.identities[i] = Some(IdentityChannel {
            label,
            channel: identity,
            offered: None,
            previous,
            admission: Admission::Unvouched,
            pending: false,
            require: false,
            purpose: BindingPurpose::Candidate,
            original: fds.binding,
            original_root: fds.root,
            audit: CleanupAudit::default(),
            image: None,
        });
        fds.authority_index = i as u16;
        if let Some(root) = fds.binding.root() {
            fds.root = root;
        }
        Ok(())
    }
    fn depart_fields(
        ram: &mut Ram<'_>,
        locks: &mut LockService,
        identities: &mut Identities,
        fds: &mut Fds,
    ) {
        if fds.departed {
            return;
        }
        ram.detach_session_descriptions(fds, locks);
        Self::drop_identity_fields(ram, identities, fds);
        fds.binding = Binding::Cleanup;
        fds.departed = true;
        fds.lock_departure = 0;
        fds.wait_departure = 0;
    }

    fn drop_identity(&mut self, fds: &mut Fds) {
        Self::drop_identity_fields(self.ram, self.identities, fds);
    }
    fn drop_identity_fields(ram: &mut Ram<'_>, identities: &mut Identities, fds: &mut Fds) {
        if let Some(root) = fds.binding_preparation.take() {
            ram.storage.release_preparation(root);
        }
        fds.binding_source = None;
        if fds.authority_index != NONE {
            identities.release(fds.authority_index as usize);
            fds.authority_index = NONE;
        }
    }
    /// A rejected candidate restores the actual old capability and its binding.
    fn reject_binding(&mut self, fds: &mut Fds) -> u32 {
        self.fail_binding(fds, proto_fs::PERMISSION)
    }
    fn fail_binding(&mut self, fds: &mut Fds, code: u32) -> u32 {
        let i = fds.authority_index as usize;
        let original = self
            .identities
            .get(i)
            .and_then(Option::as_ref)
            .map(|identity| (identity.original, identity.original_root));
        let previous = self
            .identities
            .get_mut(i)
            .and_then(Option::as_mut)
            .and_then(|identity| identity.previous.take());
        if let Some(previous) = previous {
            let identity = self.identities[i].as_mut().unwrap();
            (fds.binding, fds.root) = original.unwrap();
            identity.channel = previous;
            identity.admission = Admission::Unvouched;
            identity.offered = None;
            identity.pending = false;
            identity.require = false;
            self.ram.complete_binding(fds, code);
        } else {
            self.drop_identity(fds);
            fds.binding = Binding::Cleanup;
        }
        fds.binding_outcome = Some(code);
        code
    }
    /// Test setup queues real storage reclamation before releasing a live
    /// prepared binding to the unchanged alternating maintenance cursor.
    #[cfg(feature = "auth-probe")]
    fn auth_probe_gc(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        let Ok(phase) = body.u32() else {
            return Answer::Status(Status::BadSize);
        };
        if phase == 3 {
            return if body.finish().is_ok() {
                value(r, u32::from(self.ram.storage.usage(fds.root).pages))
            } else {
                Answer::Status(Status::BadSize)
            };
        }
        let result = match phase {
            0 if body.left() == 0 => self.ram.auth_probe_gc_reserve(fds),
            4 if body.left() == 0 => self.ram.auth_probe_gc_commit(fds),
            1 => {
                let offset = body.u32();
                let bytes = body.bytes(body.left());
                match (offset, bytes, fds.auth_probe_gc) {
                    (Ok(offset), Ok(bytes), Some(token)) if bytes.len() <= proto_fs::MAX_WRITE => {
                        self.ram
                            .storage
                            .write(token, fds.root, offset as usize, bytes)
                            .map(|_| ())
                    }
                    _ => Err(proto_fs::INVALID_ARGUMENT),
                }
            }
            2 if body.left() == 0 && fds.auth_probe_gc.is_some() => self
                .ram
                .storage
                .unlink(ramfs::storage::ROOT, b"auth-probe-gc", fds.root)
                .map(|_| {
                    fds.auth_probe_gc = None;
                    fds.auth_probe_hold = false;
                }),
            _ => Err(proto_fs::INVALID_ARGUMENT),
        };
        match result {
            Ok(()) => Answer::Status(Status::Ok),
            Err(code) => status(code),
        }
    }
    fn bind_refusal(&mut self, fds: &mut Fds, code: u32) -> Answer {
        if fds.binding_preparation.is_none() {
            fds.binding_outcome = Some(code);
        }
        status(code)
    }
    fn bind(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err()
            || r.handles.len() != 1
            || proto_fs::is_loaders(r.label())
            || (fds.binding_preparation.is_some() && !self.can_replace_refresh(fds))
            || matches!(fds.binding, Binding::Cleanup)
        {
            return self.bind_refusal(fds, proto_fs::PERMISSION);
        }
        if !fds.preparation_available() && fds.binding_preparation.is_none() {
            return self.bind_refusal(fds, proto_fs::TOO_MANY_OPEN_FILES);
        }
        let rights = r.handles.info(0).map(|(_, rights)| rights);
        if !rights
            .is_some_and(|r| r.contains(Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER))
        {
            return self.bind_refusal(fds, proto_fs::PERMISSION);
        }
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return self.bind_refusal(fds, proto_fs::PERMISSION);
        };
        if fds.binding_preparation.is_some() {
            // A real target identity supersedes only the retained loader refresh.
            // The original identity and captured descriptions remain for rollback.
            self.ram.complete_binding(fds, proto_fs::PERMISSION);
        }
        if let Err(code) = self.ram.begin_binding(fds) {
            return self.bind_refusal(fds, code);
        }
        match self.install_identity(fds, r.label(), identity, true) {
            Ok(()) => status(proto_fs::RESOLVING),
            Err(code) => {
                self.drop_identity(fds);
                self.bind_refusal(fds, code)
            }
        }
    }

    fn can_replace_refresh(&self, fds: &Fds) -> bool {
        matches!(fds.binding, Binding::Pending(_) | Binding::Handoff(_))
            && self
                .identities
                .get(fds.authority_index as usize)
                .and_then(Option::as_ref)
                .is_some_and(|identity| identity.purpose == BindingPurpose::Refresh)
    }

    fn authenticate(&mut self, fds: &mut Fds, label: u64) -> Result<(), u32> {
        Self::authenticate_fields(self.ram, self.identities, fds, label)
    }
    fn authenticate_fields(
        ram: &mut Ram<'_>,
        identities: &mut Identities,
        fds: &mut Fds,
        label: u64,
    ) -> Result<(), u32> {
        if matches!(fds.binding, Binding::Unbound) && proto_fs::is_boot_profile(label) {
            fds.binding = Binding::Boot;
            fds.root = Root {
                id: label,
                generation: 1,
            };
        }
        if matches!(fds.binding, Binding::Boot) {
            return Ok(());
        }
        if fds.binding_preparation.is_some() {
            return Err(proto_fs::AUTHENTICATING);
        }
        let who = fds.binding.snapshot_ref().ok_or(proto_fs::PERMISSION)?;
        let current = generation(who.index as usize);
        if current == who.generation {
            return if matches!(fds.binding, Binding::Inherited(_) | Binding::Handoff(_)) {
                Err(proto_fs::PERMISSION)
            } else {
                Ok(())
            };
        }
        if current & proto_process::GENERATION_DEAD != 0 {
            fds.binding = Binding::Cleanup;
            return Err(proto_fs::PERMISSION);
        }
        if !fds.preparation_available() {
            return Err(proto_fs::TOO_MANY_OPEN_FILES);
        }
        let i = fds.authority_index as usize;
        let identity = identities
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(proto_fs::PERMISSION)?;
        if identity.label != label {
            return Err(proto_fs::PERMISSION);
        }
        ram.begin_binding(fds)?;
        identity.admission = Admission::Unvouched;
        identity.audit.reset();
        identity.purpose = BindingPurpose::Refresh;
        identity.original = fds.binding;
        identity.original_root = fds.root;
        identity.pending = matches!(fds.binding, Binding::Pending(_));
        Err(proto_fs::AUTHENTICATING)
    }
    /// Compatibility verification only admits this authenticated caller's true clone.
    fn verify_clone(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let mut body = r.body();
        if !matches!(body.u32(), Ok(0 | 1)) || body.finish().is_err() || r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        if !r.handles.info(0).is_some_and(|(kind, rights)| {
            kind == rt::abi::ObjectKind::Channel && rights.contains(Rights::SEND | Rights::TRANSFER)
        }) {
            return status(proto_fs::PERMISSION);
        }
        if let Err(code) = self.authenticate(fds, r.label()) {
            if code == proto_fs::AUTHENTICATING && r.handles.len() == 1 {
                let Ok(offered) = r.handles.take::<Channel>(0) else {
                    return status(proto_fs::PERMISSION);
                };
                let _ = r.reply().u32(code);
                return Answer::Reply([offered.erase()].into());
            }
            return status(code);
        }
        let Ok(offered) = r.handles.take::<Channel>(0) else {
            return status(proto_fs::PERMISSION);
        };
        let Ok(label) = sys::copy_label(&self.channel, &offered) else {
            return status(proto_fs::PERMISSION);
        };
        if self.clones.client_of(label) != Some(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        let Some(i) = self.birth_slot(label) else {
            return status(proto_fs::PERMISSION);
        };
        let (_, mut child) = self.births[i].take().expect("own clone");
        // Verification retains creator capture; only a genuine Bind grants
        // effects to the eventual holder of this unclaimed child capability.
        let installed = if fds.authority_index == NONE {
            Ok(())
        } else {
            let identity = self.identities[fds.authority_index as usize]
                .as_ref()
                .and_then(|identity| {
                    sys::handle_duplicate(
                        &identity.channel,
                        Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
                    )
                    .ok()
                });
            identity
                .ok_or(proto_fs::PERMISSION)
                .and_then(|identity| self.install_identity(&mut child, label, identity, false))
        };
        self.births[i] = Some((label, child));
        if let Err(code) = installed {
            return status(code);
        }
        if r.reply().u32(0).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([offered.erase()].into())
    }
    fn pending_input(r: &Request<'_>) -> Result<(bool, Option<usize>, usize), u32> {
        let mut body = r.body();
        let require = body.u32();
        if !proto_fs::is_loaders(r.label())
            || !matches!(require, Ok(0 | 1))
            || body.finish().is_err()
            || !(r.handles.len() == 2 || (require == Ok(0) && r.handles.len() == 1))
        {
            return Err(proto_fs::PERMISSION);
        }
        let offered_index = (r.handles.len() == 2).then_some(0);
        let identity_index = usize::from(offered_index.is_some());
        if offered_index.is_some_and(|i| {
            !r.handles.info(i).is_some_and(|(kind, rights)| {
                kind == rt::abi::ObjectKind::Channel
                    && rights.contains(Rights::SEND | Rights::TRANSFER)
            })
        }) || !r
            .handles
            .info(identity_index)
            .is_some_and(|(kind, rights)| {
                kind == rt::abi::ObjectKind::Channel
                    && rights.contains(Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER)
            })
        {
            return Err(proto_fs::PERMISSION);
        }
        Ok((require == Ok(1), offered_index, identity_index))
    }
    /// Cold root admission returns every accepted object before paid child preparation.
    #[inline(never)]
    fn pending_admission(&mut self, r: &mut Request<'_>) -> Answer {
        if let Err(code) = Self::pending_input(r) {
            return status(code);
        }
        if r.reply()
            .u32(proto_fs::AUTHENTICATING)
            .and_then(|()| r.reply().u32(0))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        let mut returned = Outgoing::new();
        for i in 0..r.handles.len() {
            let Ok(channel) = r.handles.take::<Channel>(i) else {
                return status(proto_fs::PERMISSION);
            };
            returned
                .push(channel.erase())
                .expect("at most two pending admission channels");
        }
        Answer::Reply(returned)
    }
    #[inline(never)]
    fn bind_pending(&mut self, r: &mut Request<'_>) -> Answer {
        let (require, offered_index, identity_index) = match Self::pending_input(r) {
            Ok(input) => input,
            Err(code) => return status(code),
        };
        let offered = match offered_index {
            Some(i) => match r.handles.take::<Channel>(i) {
                Ok(offered) => Some(offered),
                Err(_) => return status(proto_fs::PERMISSION),
            },
            None => None,
        };
        let Ok(identity) = r.handles.take::<Channel>(identity_index) else {
            return status(proto_fs::PERMISSION);
        };
        if self.clones.room_within(r.label(), CLONES).is_err() {
            return status(proto_fs::TOO_MANY_OPEN_FILES);
        }
        // Identity admission itself holds a finite preparation. Its exact root
        // replaces the boot admission account after the separate genuine Vouch.
        let mut child = Fds::default();
        if let Err(code) = self.ram.begin_binding(&mut child) {
            return status(code);
        }
        let Some(label) = self.places.issue(self.given) else {
            self.drop_identity(&mut child);
            return status(proto_fs::TOO_MANY_OPEN_FILES);
        };
        let session = match self.session(label) {
            Ok(session) => session,
            Err(error) => {
                self.drop_identity(&mut child);
                return Answer::Status(Status::Kernel(error));
            }
        };
        if let Err(code) = self.install_identity(&mut child, label, identity, false) {
            self.drop_identity(&mut child);
            return status(code);
        }
        let binding = self.identities[child.authority_index as usize]
            .as_mut()
            .unwrap();
        binding.offered = offered;
        binding.pending = true;
        binding.require = require;
        self.births[Self::birth_index(label)] = Some((label, child));
        let adopted = self.clones.adopt_within(label, r.label(), CLONES);
        debug_assert!(adopted.is_ok(), "the place of a new label is free");
        if r.reply().u32(0).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([session.erase()].into())
    }
    /// Each genuine prepared capability advances at most one authentication phase.
    fn finish_binding(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() || r.body().finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if fds.binding_preparation.is_none() {
            return status(fds.binding_outcome.unwrap_or(proto_fs::PERMISSION));
        }
        status(self.binding_step(fds, r.label()))
    }
    /// Existing identity storage bounds cleanup even when every preparation is used.
    fn audit_step(&mut self, fds: &mut Fds, label: u64) -> bool {
        let Some(who) = fds.binding.snapshot_ref() else {
            return false;
        };
        let current = generation(who.index as usize);
        let i = fds.authority_index as usize;
        let Some(identity) = self.identities.get_mut(i).and_then(Option::as_mut) else {
            fds.binding = Binding::Cleanup;
            return true;
        };
        if identity.label != label || identity.original != fds.binding {
            self.reject_binding(fds);
            return true;
        }
        match identity.audit.synchronize(&mut identity.admission, current) {
            AuditStep::Denied => {
                self.reject_binding(fds);
                return true;
            }
            AuditStep::Retry => return false,
            _ => {}
        }
        let step = if matches!(identity.admission, Admission::Unvouched) {
            let channel = Handle::borrowed(identity.channel.raw());
            let original = identity.original;
            if self.generations.is_none() {
                let _ = self.notary_register();
                return false;
            }
            let wire = if matches!(original, Binding::Pending(_) | Binding::Handoff(_)) {
                match self.retained_wire(&channel, original) {
                    NotaryReply::Wire(wire) => Some(Admission::RetainedWire(wire)),
                    NotaryReply::Denied => {
                        self.reject_binding(fds);
                        return true;
                    }
                    NotaryReply::Retry => None,
                }
            } else {
                match self.vouch_wire(&channel) {
                    NotaryReply::Wire(wire) => Some(Admission::Wire(wire)),
                    NotaryReply::Denied => {
                        self.reject_binding(fds);
                        return true;
                    }
                    NotaryReply::Retry => None,
                }
            };
            let Some(wire) = wire else {
                return false;
            };
            self.identities[i].as_mut().unwrap().admission = wire;
            AuditStep::Advance
        } else {
            identity
                .audit
                .step(identity.original, &mut identity.admission, current)
        };
        match step {
            AuditStep::Denied => {
                self.reject_binding(fds);
                true
            }
            AuditStep::Retry => false,
            AuditStep::Advance | AuditStep::Alive => true,
        }
    }
    fn binding_step(&mut self, fds: &mut Fds, label: u64) -> u32 {
        self.binding_phase(fds, label, &mut true)
    }
    fn binding_phase(&mut self, fds: &mut Fds, label: u64, progress: &mut bool) -> u32 {
        *progress = true;
        let i = fds.authority_index as usize;
        let Some(binding) = self.identities.get(i).and_then(Option::as_ref) else {
            return self.reject_binding(fds);
        };
        if binding.label != label {
            return self.reject_binding(fds);
        }
        if matches!(binding.admission, Admission::Unvouched) {
            if self.generations.is_none() {
                return if self.notary_register() {
                    proto_fs::RESOLVING
                } else {
                    self.reject_binding(fds)
                };
            }
            let identity = Handle::borrowed(binding.channel.raw());
            if binding.purpose == BindingPurpose::Refresh
                && matches!(binding.original, Binding::Pending(_) | Binding::Handoff(_))
            {
                let original = binding.original;
                let wire = self.retained_wire(&identity, original);
                return match wire.admit(
                    &mut self.identities[i].as_mut().unwrap().admission,
                    Admission::RetainedWire,
                ) {
                    Ok(advanced) => {
                        *progress = advanced;
                        proto_fs::RESOLVING
                    }
                    Err(code) => self.fail_binding(fds, code),
                };
            }
            let wire = self.vouch_wire(&identity);
            return match wire.admit(
                &mut self.identities[i].as_mut().unwrap().admission,
                Admission::Wire,
            ) {
                Ok(advanced) => {
                    *progress = advanced;
                    proto_fs::RESOLVING
                }
                Err(code) => self.fail_binding(fds, code),
            };
        }
        if matches!(
            binding.admission,
            Admission::Wire(_) | Admission::RetainedWire(_)
        ) {
            return match self.identities[i].as_mut().unwrap().admission.decode() {
                Ok(()) => {
                    *progress = !matches!(
                        self.identities[i].as_ref().unwrap().admission,
                        Admission::Unvouched
                    );
                    proto_fs::RESOLVING
                }
                Err(code) => self.fail_binding(fds, code),
            };
        }
        if let Admission::RetainedVouched(retained) = binding.admission {
            let original = binding.original;
            return match self.identities[i]
                .as_mut()
                .unwrap()
                .admission
                .validate_retained(original, generation(retained.who.index as usize))
            {
                Ok(()) => {
                    *progress = !matches!(
                        self.identities[i].as_ref().unwrap().admission,
                        Admission::Unvouched
                    );
                    proto_fs::RESOLVING
                }
                Err(code) => self.fail_binding(fds, code),
            };
        }
        if let Admission::RetainedValidated(retained) = binding.admission {
            if generation(retained.who.index as usize) != retained.who.generation {
                self.identities[i].as_mut().unwrap().admission = Admission::Unvouched;
                *progress = false;
                return proto_fs::RESOLVING;
            }
            return match binding.original.retained_refresh(&retained) {
                Ok(refreshed) => {
                    fds.binding = refreshed;
                    self.ram.complete_binding(fds, 0);
                    0
                }
                Err(code) => self.fail_binding(fds, code),
            };
        }
        if let Admission::Vouched(who) = binding.admission {
            let (original, purpose, pending) = (binding.original, binding.purpose, binding.pending);
            return match self.identities[i].as_mut().unwrap().admission.validate(
                original,
                purpose,
                pending,
                generation(who.index as usize),
            ) {
                Ok(()) => {
                    *progress = !matches!(
                        self.identities[i].as_ref().unwrap().admission,
                        Admission::Unvouched
                    );
                    proto_fs::RESOLVING
                }
                Err(code) => self.fail_binding(fds, code),
            };
        }
        let Admission::Validated(who) = binding.admission else {
            unreachable!()
        };
        if generation(who.index as usize) != who.generation {
            self.identities[i].as_mut().unwrap().admission = Admission::Unvouched;
            *progress = false;
            return proto_fs::RESOLVING;
        }
        let pending = binding.pending;
        if binding.purpose == BindingPurpose::Refresh {
            let refreshed = binding.original.refreshed(&who);
            match refreshed {
                Ok(refreshed) => fds.binding = refreshed,
                Err(_) => return self.reject_binding(fds),
            }
            self.ram.complete_binding(fds, 0);
            return 0;
        }
        if !pending || !matches!(fds.binding, Binding::Pending(_)) {
            let mut bound = fds.binding;
            if bound.bind_ref(Some(&who), pending).is_err() {
                return self.reject_binding(fds);
            }
            let root = bound.root().unwrap();
            if pending {
                let binding = self.identities[i].as_ref().unwrap();
                let offered_label = binding
                    .offered
                    .as_ref()
                    .and_then(|offered| sys::copy_label(&self.channel, offered).ok());
                let original = offered_label.and_then(|label| self.birth_slot(label));
                if binding.require && original.is_none() {
                    return self.reject_binding(fds);
                }
                if let Some(slot) = original {
                    let source = &self.births[slot].as_ref().unwrap().1;
                    let mut inherited = source.binding;
                    if (source.binding_preparation.is_some()
                        && self
                            .identities
                            .get(source.authority_index as usize)
                            .and_then(Option::as_ref)
                            .is_none_or(|identity| identity.purpose != BindingPurpose::Refresh))
                        || inherited.bind_ref(Some(&who), true).is_err()
                        || (source.root.id != 0 && source.root != root)
                    {
                        return self.reject_binding(fds);
                    }
                    fds.binding_source = Some((slot as u16, offered_label.unwrap()));
                }
            }
            let charge = match self
                .ram
                .storage
                .reassign_preparation(fds.binding_preparation.unwrap(), root)
            {
                Ok(charge) => charge,
                Err(code) => return self.fail_binding(fds, code),
            };
            fds.binding_preparation = Some(charge);
            fds.root = root;
            fds.binding = bound;
            if pending {
                return proto_fs::RESOLVING;
            }
        }
        if let Some((slot, label)) = fds.binding_source {
            let Some((old_label, source)) = self.births[slot as usize].as_ref() else {
                return self.reject_binding(fds);
            };
            if *old_label != label {
                return self.reject_binding(fds);
            }
            let Some(creator) = source.binding.snapshot_ref() else {
                return self.reject_binding(fds);
            };
            let purpose = self
                .identities
                .get(source.authority_index as usize)
                .and_then(Option::as_ref)
                .filter(|identity| identity.label == label)
                .map(|identity| identity.purpose);
            let source_phase = match retained_source_phase(
                label,
                *old_label,
                source.binding_preparation.is_some(),
                purpose,
                generation(creator.index as usize),
                creator.generation,
            ) {
                Err(_) => return self.reject_binding(fds),
                Ok(phase) => phase,
            };
            *progress = source_phase.progresses();
            match source_phase {
                RetainedSourcePhase::WaitRefresh => {
                    // The retained birth advances from its own maintenance visit.
                    return proto_fs::RESOLVING;
                }
                RetainedSourcePhase::Authenticate => {
                    let source = &mut self.births[slot as usize].as_mut().unwrap().1;
                    let result =
                        Self::authenticate_fields(self.ram, self.identities, source, label);
                    let valid = !matches!(source.binding, Binding::Cleanup);
                    return if !valid {
                        self.reject_binding(fds)
                    } else {
                        match result {
                            Ok(()) | Err(proto_fs::AUTHENTICATING) => proto_fs::RESOLVING,
                            Err(code) => self.fail_binding(fds, code),
                        }
                    };
                }
                RetainedSourcePhase::Ready => {}
            }
            let mut bound = source.binding;
            if bound.bind_ref(Some(&who), true).is_err() || source.root != fds.root {
                return self.reject_binding(fds);
            }
            let source = &mut self.births[slot as usize].as_mut().unwrap().1;
            Self::drop_identity_fields(self.ram, self.identities, source);
            source.binding = bound;
            source.authority_index = fds.authority_index;
            source.claimed = true;
            self.ram.complete_binding(fds, 0);
            core::mem::swap(fds, source);
            self.births[slot as usize] = None;
        } else {
            self.ram.complete_binding(fds, 0);
        }
        let binding = self.identities[fds.authority_index as usize]
            .as_mut()
            .unwrap();
        binding.admission = Admission::Unvouched;
        binding.offered = None;
        binding.previous = None;
        fds.binding_outcome = Some(0);
        0
    }
    fn data_request(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let method = Method::from_number(r.method()).expect("data method");
        if method == Method::DataStart {
            let args = match proto_fs::DataStart::read(r.body()) {
                Ok(args) => args,
                Err(error) => return Answer::Status(error),
            };
            if let Err(code) = self.authenticate(fds, r.label()) {
                return status(code);
            }
            if let Some(job) = self
                .jobs
                .iter()
                .flatten()
                .find(|job| job.owner == r.label() && job.open_key == Some(args.key))
            {
                let JobOperation::Data(data) = &job.operation else {
                    return status(proto_fs::PERMISSION);
                };
                if job.abandoned {
                    return status(proto_fs::OPEN_RETIRED);
                }
                if data.args != args {
                    return status(proto_fs::PERMISSION);
                }
                if !fds.resolvers.contains(&job.id)
                    || job.authority.map(|stamp| stamp.image)
                        != fds.binding.stamp().map(|stamp| stamp.image)
                {
                    return status(proto_fs::OPEN_RETIRED);
                }
                if r.reply()
                    .u32(0)
                    .and_then(|()| r.reply().u32(data.phase as u32))
                    .and_then(|()| r.reply().u64(job.id))
                    .is_err()
                {
                    return Answer::Status(Status::BadSize);
                }
                return Answer::Reply(Outgoing::new());
            }
            if self.jobs.iter().flatten().any(|job| {
                job.owner == r.label() && job.open_key.is_some_and(|key| key.slot == args.key.slot)
            }) {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            }
            if args.key.generation <= fds.open_watermarks[args.key.slot as usize] {
                return status(proto_fs::OPEN_RETIRED);
            }
            if !fds.preparation_available() {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            }
            let Some(local) = fds.resolvers.iter().position(|&id| id == 0) else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            // The full side table and the full share of the root keep the key
            // free and make no effect: JOBS_FULL, as in Change, and the client
            // sleeps and asks again. TOO_MANY_OPEN_FILES stays for what the
            // client counts itself and for a key taken by another generation.
            let Some(slot) = self.jobs.iter().position(Option::is_none) else {
                return status(proto_fs::JOBS_FULL);
            };
            let Some(generation) = self.job_generations[slot]
                .checked_add(1)
                .filter(|&generation| generation < 1 << 56)
            else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let charge = match self.ram.storage.charge_preparation(fds.root) {
                Ok(charge) => charge,
                Err(code) => {
                    return status(if code == proto_fs::TOO_MANY_OPEN_FILES {
                        proto_fs::JOBS_FULL
                    } else {
                        code
                    });
                }
            };
            let data = match ramfs::data::Journal::capture(self.ram, fds, args) {
                Ok(data) => data,
                Err(code) => {
                    self.ram.storage.release_preparation(charge);
                    return status(code);
                }
            };
            let phase = data.phase;
            let id = generation << 8 | slot as u64;
            self.jobs[slot] = Some(ResolveJob {
                id,
                owner: r.label(),
                root: charge,
                real: false,
                authority: fds.binding.stamp(),
                operation: JobOperation::Data(data),
                open_key: Some(args.key),
                raw_base: (0, 0),
                abandoned: false,
            });
            self.job_generations[slot] = generation;
            fds.resolvers[local] = id;
            fds.open_watermarks[args.key.slot as usize] = args.key.generation;
            if r.reply()
                .u32(0)
                .and_then(|()| r.reply().u32(phase as u32))
                .and_then(|()| r.reply().u64(id))
                .is_err()
            {
                self.cancel_job(id, r.label(), Some(fds));
                return Answer::Status(Status::BadSize);
            }
            return Answer::Reply(Outgoing::new());
        }
        let mut body = r.body();
        let keyed = matches!(
            method,
            Method::DataQuery | Method::DataCancel | Method::DataAck | Method::DataReadResult
        );
        let slot = if keyed {
            let mut key_body = r.body();
            let (Ok(slot), Ok(generation), Ok(())) =
                (key_body.u32(), key_body.u64(), key_body.finish())
            else {
                return Answer::Status(Status::BadSize);
            };
            let key = proto_fs::OpenKey { slot, generation };
            if let Err(code) = key.validate() {
                return status(code);
            }
            let found = self.jobs.iter().position(|job| {
                job.as_ref()
                    .is_some_and(|job| job.owner == r.label() && job.open_key == Some(key))
            });
            let Some(slot) = found else {
                if method == Method::DataCancel {
                    let watermark = &mut fds.open_watermarks[key.slot as usize];
                    *watermark = (*watermark).max(key.generation);
                    return Answer::Status(Status::Ok);
                }
                return status(
                    if key.generation <= fds.open_watermarks[key.slot as usize] {
                        proto_fs::OPEN_RETIRED
                    } else {
                        proto_fs::NO_ENTRY
                    },
                );
            };
            slot
        } else {
            let Ok(id) = body.u64() else {
                return Answer::Status(Status::BadSize);
            };
            if method != Method::DataFeed && body.left() != 0 {
                return Answer::Status(Status::BadSize);
            }
            match self.job_slot(id, r.label()) {
                Ok(slot) => slot,
                Err(code) => return status(code),
            }
        };
        let job = self.jobs[slot].as_ref().expect("exact data job");
        let id = job.id;
        let JobOperation::Data(data) = &job.operation else {
            return status(proto_fs::PERMISSION);
        };
        if !fds.resolvers.contains(&id) {
            return status(proto_fs::PERMISSION);
        }
        if matches!(method, Method::DataAck | Method::DataCancel) {
            if method == Method::DataAck && !data.ack_allowed() {
                return status(proto_fs::INVALID_ARGUMENT);
            }
            let retire = method == Method::DataAck || !data.ack_allowed();
            return if self.cancel_job_mode(id, r.label(), Some(fds), retire) {
                Answer::Status(Status::Ok)
            } else {
                status(proto_fs::RESOLVING)
            };
        }
        if job.abandoned {
            return status(proto_fs::OPEN_RETIRED);
        }
        if let Err(code) = self.authenticate(fds, r.label()) {
            return status(code);
        }
        let job = self.jobs[slot].as_mut().expect("owned data job");
        if job.authority.map(|stamp| stamp.image) != fds.binding.stamp().map(|stamp| stamp.image) {
            return status(proto_fs::OPEN_RETIRED);
        }
        let JobOperation::Data(data) = &mut job.operation else {
            unreachable!()
        };
        match method {
            Method::DataFeed => {
                let Ok(offset) = body.u32() else {
                    return Answer::Status(Status::BadSize);
                };
                let Ok(bytes) = body.bytes(body.left()) else {
                    return Answer::Status(Status::BadSize);
                };
                match data.feed(offset as usize, bytes) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                }
            }
            Method::DataStep => match data.step(self.ram) {
                Ok(true) => Answer::Status(Status::Ok),
                Ok(false) => status(proto_fs::RESOLVING),
                Err(code) => status(code),
            },
            Method::DataCommit => {
                // The fixed envelope is prepaid before Clock or file effects.
                if r.reply().bytes(&[0; 32]).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                *r.reply() = proto_wire::Writer::new();
                let now = if data.needs_time() {
                    match self.time_source.read_once() {
                        Ok(now) => now,
                        Err(error) => return Answer::Status(error),
                    }
                } else {
                    None
                };
                if let Err(code) = data.commit(self.ram, now) {
                    return status(code);
                }
                data.outcome(id)
                    .write(r.reply())
                    .expect("prepaid fixed data response");
                Answer::Reply(Outgoing::new())
            }
            Method::DataQuery => match data.outcome(id).write(r.reply()) {
                Ok(()) => Answer::Reply(Outgoing::new()),
                Err(error) => Answer::Status(error),
            },
            Method::DataReadResult => {
                let bytes = match data.read_result() {
                    Ok(bytes) => bytes,
                    Err(code) => return status(code),
                };
                match r
                    .reply()
                    .u32(0)
                    .and_then(|()| r.reply().u32(bytes.len() as u32))
                    .and_then(|()| r.reply().bytes(bytes))
                {
                    Ok(()) => Answer::Reply(Outgoing::new()),
                    Err(error) => Answer::Status(error),
                }
            }
            _ => unreachable!(),
        }
    }
    fn common_control_busy(&self, fds: &Fds, owner: u64, slot: u32) -> bool {
        fds.resolvers
            .iter()
            .copied()
            .filter(|&id| id != 0)
            .any(|id| {
                self.jobs
                    .get((id & 255) as usize)
                    .and_then(Option::as_ref)
                    .is_some_and(|job| {
                        job.id == id
                            && job.owner == owner
                            && job.open_key.is_some_and(|key| key.slot == slot)
                    })
            })
    }

    fn lock_request(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let owner = r.label();
        let place = self.places.place(owner);
        let method = Method::from_number(r.method()).expect("native lock method");
        let result = if method == Method::LockStart {
            let wire = match proto_fs::LockStart::read(r.body()) {
                Ok(wire) => wire,
                Err(error) => return Answer::Status(error),
            };
            match ramfs::locks::server::replay(self.lock_jobs, place, owner, wire) {
                Ok(Some(result)) => Ok(result),
                Err(code) => Err(code),
                Ok(None) => {
                    if let Err(code) = self.authenticate(fds, owner) {
                        return status(code);
                    }
                    if !wire.command.ofd() && !self.register_lifetimes() {
                        return status(proto_fs::NO_LOCKS);
                    }
                    if self.common_control_busy(fds, owner, wire.key.slot) {
                        return status(proto_fs::JOBS_FULL);
                    }
                    ramfs::locks::server::start(self.lock_jobs, self.ram, fds, place, owner, wire)
                }
            }
        } else {
            let key = match proto_fs::read_lock_key(r.body()) {
                Ok(key) => key,
                Err(error) => return Answer::Status(error),
            };
            if self.common_control_busy(fds, owner, key.slot) {
                return status(proto_fs::PERMISSION);
            }
            if method == Method::LockRelease {
                let result =
                    ramfs::locks::server::release(self.lock_jobs, self.ram, fds, place, owner, key);
                let answer = match result {
                    Ok(true) => {
                        self.locks.cancel();
                        status(proto_fs::RESOLVING)
                    }
                    Ok(false) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                };
                self.notify_maintenance();
                return answer;
            }
            if method == Method::LockCancel {
                match ramfs::locks::server::cancel(self.lock_jobs, fds, place, owner, key) {
                    Ok((result, active)) => {
                        if active {
                            self.locks.cancel();
                        }
                        Ok(result)
                    }
                    Err(code) => Err(code),
                }
            } else {
                ramfs::locks::server::query(self.lock_jobs, fds, place, owner, key)
            }
        };
        self.notify_maintenance();
        match result {
            Ok(result) => match result.write(r.reply()) {
                Ok(()) => Answer::Reply(Outgoing::new()),
                Err(error) => Answer::Status(error),
            },
            Err(code) => status(code),
        }
    }

    /// The five methods of the Change family (44 to 48).
    fn change_request(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let method = Method::from_number(r.method()).expect("change method");
        let owner = r.label();
        if method == Method::ChangeRelease
            && let Ok(key) = proto_fs::read_key_body(r.body())
        {
            // The key of a Data job (a truncate) ends with the same Release:
            // the cleanup of its journal, step by step, and the job forgotten.
            let data = self.jobs.iter().flatten().find(|job| {
                job.owner == owner
                    && job.open_key == Some(key)
                    && matches!(job.operation, JobOperation::Data(_))
            });
            if let Some(id) = data.map(|job| job.id) {
                return if self.cancel_job_mode(id, owner, Some(fds), true) {
                    Answer::Status(Status::Ok)
                } else {
                    status(proto_fs::RESOLVING)
                };
            }
        }
        // Release is cleanup: it needs no live authority.
        if method != Method::ChangeRelease
            && let Err(code) = self.authenticate(fds, owner)
        {
            return status(code);
        }
        let mut out = proto_wire::Writer::new();
        let mut ctx = ramfs::change::Ctx {
            ram: self.ram,
            jobs: &mut *self.jobs,
            generations: &mut *self.job_generations,
            seconds: &mut *self.seconds,
        };
        let result = match method {
            Method::ChangeStart => match proto_fs::ChangeStart::read(r.body()) {
                Ok(req) => ramfs::change::start(&mut ctx, fds, owner, &req, &mut out),
                Err(error) => Err(error.code()),
            },
            Method::ChangeSecond => match proto_fs::ChangeSecond::read(r.body()) {
                Ok(req) => ramfs::change::second(&mut ctx, fds, owner, &req),
                Err(error) => Err(error.code()),
            },
            Method::ChangeStep | Method::ChangeQuery => match proto_fs::read_key_body(r.body()) {
                Ok(key) => ramfs::change::step(
                    &mut ctx,
                    fds,
                    owner,
                    key,
                    if method == Method::ChangeStep {
                        ramfs::change::Advance::Step
                    } else {
                        ramfs::change::Advance::Query
                    },
                    &self.time_source,
                    &mut out,
                ),
                Err(error) => Err(error.code()),
            },
            _ => match proto_fs::read_key_body(r.body()) {
                Ok(key) => ramfs::change::release(&mut ctx, fds, owner, key),
                Err(error) => Err(error.code()),
            },
        };
        match result {
            Ok(()) => {
                if method == Method::ChangeSecond || method == Method::ChangeRelease {
                    return Answer::Status(Status::Ok);
                }
                *r.reply() = out;
                Answer::Reply(Outgoing::new())
            }
            Err(code) => status(code),
        }
    }
    fn job_slot(&self, id: u64, owner: u64) -> Result<usize, u32> {
        let i = (id & 255) as usize;
        if !self
            .jobs
            .get(i)
            .is_some_and(|j| j.as_ref().is_some_and(|j| j.id == id && j.owner == owner))
        {
            return Err(proto_fs::STALE_PROOF);
        }
        Ok(i)
    }
    fn path_slot(&self, id: u64, owner: u64) -> Result<usize, u32> {
        let slot = self.job_slot(id, owner)?;
        if !matches!(
            self.jobs[slot].as_ref().expect("exact job").operation,
            JobOperation::Path(_)
        ) {
            return Err(proto_fs::PERMISSION);
        }
        Ok(slot)
    }
    fn abandon_job(&mut self, id: u64, owner: u64, fds: &mut Fds) {
        let Ok(slot) = self.job_slot(id, owner) else {
            return;
        };
        let job = self.jobs[slot].as_mut().expect("exact disappearing job");
        if matches!(
            job.operation,
            JobOperation::Data(_) | JobOperation::Change(_)
        ) {
            if !job.abandoned {
                if let JobOperation::Data(data) = &mut job.operation {
                    data.abandon();
                }
                job.abandoned = true;
                self.orphan_count = self.orphan_count.checked_add(1).expect("bounded paid jobs");
                assert!(self.orphan_count as usize <= ramfs::storage::PREPARATIONS);
            }
            let _ = sys::notify(&self.channel, 1);
        } else {
            self.cancel_job(id, owner, Some(fds));
        }
    }
    fn cancel_job(&mut self, id: u64, owner: u64, fds: Option<&mut Fds>) {
        self.cancel_job_mode(id, owner, fds, true);
    }
    /// Completed Data Cancel retains the paid result until exact ACK or abandonment.
    fn cancel_job_mode(
        &mut self,
        id: u64,
        owner: u64,
        mut fds: Option<&mut Fds>,
        retire: bool,
    ) -> bool {
        if let Some(fds) = fds.as_deref_mut()
            && fds.image_outcome.is_some_and(|outcome| outcome.job == id)
        {
            let outcome = fds.image_outcome.unwrap();
            self.clear_image_outcome(fds);
            if outcome.phase != ramfs::image::ImagePhase::Prepared {
                fds.image_outcome = Some(ramfs::image::ImageOutcome {
                    phase: if outcome.phase == ramfs::image::ImagePhase::AbortRequired {
                        ramfs::image::ImagePhase::AbortRequired
                    } else {
                        ramfs::image::ImagePhase::Retired
                    },
                    ..outcome
                });
            }
        }
        if let Ok(i) = self.job_slot(id, owner) {
            if matches!(
                self.jobs[i].as_ref().map(|job| &job.operation),
                Some(JobOperation::Change(_))
            ) {
                let mut ctx = ramfs::change::Ctx {
                    ram: self.ram,
                    jobs: &mut *self.jobs,
                    generations: &mut *self.job_generations,
                    seconds: &mut *self.seconds,
                };
                if ramfs::change::cancel_slot(&mut ctx, fds.as_deref_mut(), i) {
                    self.orphan_count = self
                        .orphan_count
                        .checked_sub(1)
                        .expect("owned abandoned count");
                }
                return true;
            }
            if let Some(ResolveJob {
                operation: JobOperation::Data(data),
                ..
            }) = self.jobs[i].as_mut()
                && !data.cancel_step(self.ram).expect("exact data job cleanup")
            {
                return false;
            }
            if !retire {
                return true;
            }
            let mut j = self.jobs[i].take().expect("owned canceled job");
            if let JobOperation::Path(mut path) = j.operation {
                if let Some(open) = path.open.as_mut() {
                    let fds = fds
                        .as_deref_mut()
                        .expect("open job retains its owning session");
                    open.cancel(self.ram, fds, &mut j.root)
                        .expect("exact open job cleanup");
                }
                path.resolver.release(&mut self.ram.storage);
                if let Some(second) = path.second {
                    second.release(&mut self.ram.storage);
                }
            }
            if j.root != NONE {
                self.ram.storage.release_preparation(j.root);
            }
            if j.abandoned {
                self.orphan_count = self
                    .orphan_count
                    .checked_sub(1)
                    .expect("owned abandoned count");
            }
        }
        if let Some(fds) = fds
            && let Some(place) = fds.resolvers.iter_mut().find(|r| **r == id)
        {
            *place = 0;
        }
        true
    }
    fn resolve_request(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if proto_fs::is_loaders(r.label()) {
            return status(proto_fs::PERMISSION);
        }
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if matches!(
            Method::from_number(r.method()),
            Some(Method::OpenCancel | Method::OpenQuery | Method::OpenFinish)
        ) {
            let mut body = r.body();
            let (Ok(slot), Ok(generation), Ok(())) = (body.u32(), body.u64(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            let key = proto_fs::OpenKey { slot, generation };
            if let Err(code) = key.validate() {
                return status(code);
            }
            let found = self.jobs.iter().position(|j| {
                j.as_ref()
                    .is_some_and(|j| j.owner == r.label() && j.open_key == Some(key))
            });
            let Some(i) = found else {
                if r.method() == Method::OpenCancel as u16 {
                    let watermark = &mut fds.open_watermarks[key.slot as usize];
                    *watermark = (*watermark).max(key.generation);
                    return match self.ram.cancel_finished_open(fds, key) {
                        Ok(()) => Answer::Status(Status::Ok),
                        Err(code) => status(code),
                    };
                }
                if let Err(code) = self.authenticate(fds, r.label()) {
                    return status(code);
                }
                return match self.ram.finished_open(fds, key) {
                    Ok(held) => {
                        self.finished_reply(fds, r, held, r.method() == Method::OpenQuery as u16)
                    }
                    Err(code) => status(code),
                };
            };
            let j = self.jobs[i].as_ref().expect("exact client key");
            if !matches!(j.operation, JobOperation::Path(_)) {
                return status(proto_fs::PERMISSION);
            }
            let id = j.id;
            if r.method() == Method::OpenCancel as u16 {
                self.cancel_job(id, r.label(), Some(fds));
                return Answer::Status(Status::Ok);
            }
            if let Err(code) = self.authenticate(fds, r.label()) {
                return status(code);
            }
            let j = self.jobs[i].as_ref().expect("retained query job");
            if !fds.resolvers.contains(&id)
                || j.real
                || j.path().second.is_some()
                || j.authority.map(|stamp| stamp.image)
                    != fds.binding.stamp().map(|stamp| stamp.image)
            {
                return status(proto_fs::OPEN_RETIRED);
            }
            if r.method() == Method::OpenFinish as u16 {
                let j = self.jobs[i].as_mut().expect("retained finalization job");
                let JobOperation::Path(path) = &mut j.operation else {
                    unreachable!()
                };
                let open = path.open.as_mut().expect("keyed Open");
                let first = matches!(open.phase, OpenPhase::Prepared { .. });
                let held = match open.phase {
                    OpenPhase::Prepared { held, .. } | OpenPhase::Committed { held, .. } => held,
                    _ => return status(proto_fs::RESOLVING),
                };
                if first && j.authority != fds.binding.stamp() {
                    return status(proto_fs::STALE_PROOF);
                }
                let publication = match self.ram.preflight_finish_open(fds, key, held) {
                    Ok(proof) => proof,
                    Err(code) => return status(code),
                };
                let marked_fd = match self.ram.marked_open(fds, held) {
                    Ok(fd) => fd,
                    Err(code) => return status(code),
                };
                // Reply and receipt are paid before Clock or file effects.
                if r.reply()
                    .u32(0)
                    .and_then(|()| r.reply().u32(marked_fd))
                    .and_then(|()| r.reply().u64(held.description.generation))
                    .is_err()
                {
                    return Answer::Status(Status::BadSize);
                }
                if first {
                    let identity = match fds.binding.identity(false) {
                        Ok(identity) => identity,
                        Err(code) => return status(code),
                    };
                    let proof = match path.resolver.result_proof(
                        &self.ram.storage,
                        identity,
                        Intent::Open { flags: open.flags },
                    ) {
                        Ok(proof) => proof,
                        Err(code) => return status(code),
                    };
                    let now = match open.needs_time(self.ram, fds) {
                        Ok(false) => proto_fs::Timestamp::ZERO,
                        Ok(true) => match self.time_source.read_once() {
                            Ok(Some(now)) => now,
                            Ok(None) => return status(proto_fs::TIME_DEFERRED),
                            Err(error) => return Answer::Status(error),
                        },
                        Err(code) => return status(code),
                    };
                    if let Err(code) =
                        open.commit(self.ram, fds, Some(proof), identity, &mut j.root, now)
                    {
                        return status(code);
                    }
                }
                // Commit does not alter the prepaid descriptor/receipt mappings.
                let published = self.ram.finish_preflighted(fds, publication);
                debug_assert_eq!(published, held);
                let completed = self.jobs[i].take().expect("finished paid Open");
                let JobOperation::Path(path) = completed.operation else {
                    unreachable!()
                };
                path.resolver.release(&mut self.ram.storage);
                if completed.root != NONE {
                    self.ram.storage.release_preparation(completed.root);
                }
                *fds.resolvers
                    .iter_mut()
                    .find(|slot| **slot == id)
                    .expect("owned finished slot") = 0;
                return Answer::Reply(Outgoing::new());
            }
            let phase = match j.path().open.as_ref().expect("keyed Open").phase {
                OpenPhase::Resolving => 0,
                OpenPhase::Reserved(_) => 1,
                OpenPhase::Prepared { .. } => 2,
                OpenPhase::Committed { .. } => 3,
                OpenPhase::Canceled { .. } => 4,
            };
            let w = r.reply();
            if w.u32(0)
                .and_then(|()| w.u32(phase))
                .and_then(|()| w.u64(id))
                .is_err()
            {
                return Answer::Status(Status::BadSize);
            }
            return Answer::Reply(Outgoing::new());
        }
        if r.method() == Method::ResolveCancel as u16 {
            let mut body = r.body();
            let (Ok(id), Ok(())) = (body.u64(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            if let Ok(slot) = self.job_slot(id, r.label())
                && matches!(
                    self.jobs[slot]
                        .as_ref()
                        .expect("exact canceled job")
                        .operation,
                    JobOperation::Data(_) | JobOperation::Change(_)
                )
            {
                return status(proto_fs::PERMISSION);
            }
            self.cancel_job(id, r.label(), Some(fds));
            return Answer::Status(Status::Ok);
        }
        if let Err(code) = self.authenticate(fds, r.label()) {
            return status(code);
        }
        if matches!(
            Method::from_number(r.method()),
            Some(Method::OpenPrepare | Method::OpenCommit)
        ) {
            return self.open_stage(fds, r);
        }
        let mut body = r.body();
        if matches!(
            Method::from_number(r.method()),
            Some(Method::ResolveStart | Method::OpenStart)
        ) {
            let open_key = if r.method() == Method::OpenStart as u16 {
                let (Ok(slot), Ok(generation)) = (body.u32(), body.u64()) else {
                    return Answer::Status(Status::BadSize);
                };
                let key = proto_fs::OpenKey { slot, generation };
                if let Err(code) = key.validate() {
                    return status(code);
                }
                Some(key)
            } else {
                None
            };
            let (Ok(slot), Ok(generation)) = (body.u32(), body.u64()) else {
                return Answer::Status(Status::BadSize);
            };
            let (real, intent, open) = if r.method() == Method::OpenStart as u16 {
                let (Ok(flags), Ok(mode), Ok(umask)) = (body.u32(), body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                let open = match OpenJournal::new(flags, mode, umask) {
                    Ok(open) => open,
                    Err(code) => return status(code),
                };
                (0, Intent::Open { flags }, Some(open))
            } else {
                let (Ok(real), Ok(follow)) = (body.u32(), body.u32()) else {
                    return Answer::Status(Status::BadSize);
                };
                if !matches!(real, 0 | 1) || !matches!(follow, 0 | 1) {
                    return Answer::Status(Status::BadSize);
                }
                (
                    real,
                    Intent::Lookup {
                        follow: follow != 0,
                    },
                    None,
                )
            };
            let Ok(path) = body.bytes(body.left()) else {
                return Answer::Status(Status::BadSize);
            };
            let raw_base = (slot, generation);
            if let Some(key) = open_key {
                if let Some(j) = self
                    .jobs
                    .iter()
                    .flatten()
                    .find(|j| j.owner == r.label() && j.open_key == Some(key))
                {
                    if !matches!(j.operation, JobOperation::Path(_)) {
                        return status(proto_fs::PERMISSION);
                    }
                    let old = j.path().open.as_ref().expect("keyed Open");
                    let current = open.as_ref().expect("parsed Open");
                    if j.raw_base != raw_base
                        || old.flags != current.flags
                        || old.mode != current.mode
                        || old.umask != current.umask
                        || j.path().resolver.original_path() != path
                    {
                        return status(proto_fs::PERMISSION);
                    }
                    let id = j.id;
                    if r.reply().u32(0).and_then(|()| r.reply().u64(id)).is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    return Answer::Reply(Outgoing::new());
                }
                if self.jobs.iter().flatten().any(|j| {
                    j.owner == r.label() && j.open_key.is_some_and(|old| old.slot == key.slot)
                }) {
                    return status(proto_fs::TOO_MANY_OPEN_FILES);
                }
                if key.generation <= fds.open_watermarks[key.slot as usize] {
                    return status(proto_fs::OPEN_RETIRED);
                }
            }
            let identity = fds.binding.identity(real != 0).expect("authenticated");
            let root = fds.root;
            for id in &mut fds.resolvers {
                if *id != 0
                    && !self.jobs[(*id & 255) as usize]
                        .as_ref()
                        .is_some_and(|j| j.id == *id && j.owner == r.label())
                {
                    *id = 0;
                }
            }
            if !fds.preparation_available() {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            }
            let Some(place) = fds.resolvers.iter().position(|&id| id == 0) else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let Some(i) = self.jobs.iter().position(Option::is_none) else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let Some(next) = self.job_generations[i]
                .checked_add(1)
                .filter(|&n| n < 1 << 56)
            else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let charge = match self.ram.storage.charge_preparation(root) {
                Ok(c) => c,
                Err(code) => return status(code),
            };
            let base =
                match self
                    .ram
                    .request_base(fds, slot, generation, path.first() != Some(&b'/'))
                {
                    Ok(base) => base,
                    Err(code) => {
                        self.ram.storage.release_preparation(charge);
                        return status(code);
                    }
                };
            let resolver =
                match Resolve::with_intent(&mut self.ram.storage, path, base, identity, intent) {
                    Ok(r) => r,
                    Err(code) => {
                        self.ram.storage.release_preparation(charge);
                        return status(code);
                    }
                };
            let id = next << 8 | i as u64;
            self.job_generations[i] = next;
            self.jobs[i] = Some(ResolveJob {
                id,
                owner: r.label(),
                root: charge,
                real: real != 0,
                authority: fds.binding.stamp(),
                operation: JobOperation::Path(PathJob {
                    resolver,
                    second: None,
                    open,
                }),
                open_key,
                raw_base,
                abandoned: false,
            });
            fds.resolvers[place] = id;
            if let Some(key) = open_key {
                fds.open_watermarks[key.slot as usize] = key.generation;
            }
            if r.reply().u32(0).and_then(|()| r.reply().u64(id)).is_err() {
                self.cancel_job(id, r.label(), Some(fds));
                return Answer::Status(Status::BadSize);
            }
            return Answer::Reply(Outgoing::new());
        }
        if r.method() == Method::ResolveSecond as u16 {
            if !r.handles.is_empty() {
                return status(proto_fs::PERMISSION);
            }
            let (Ok(id), Ok(slot), Ok(generation), Ok(follow)) =
                (body.u64(), body.u32(), body.u64(), body.u32())
            else {
                return Answer::Status(Status::BadSize);
            };
            if !matches!(follow, 0 | 1) {
                return Answer::Status(Status::BadSize);
            }
            let path = match body.bytes(body.left()) {
                Ok(p) => p,
                Err(_) => return Answer::Status(Status::BadSize),
            };
            let i = match self.path_slot(id, r.label()) {
                Ok(i) => i,
                Err(code) => return status(code),
            };
            let j = self.jobs[i].as_mut().expect("owned job");
            if j.path().second.is_some() || j.real || j.path().open.is_some() {
                return status(proto_fs::PERMISSION);
            }
            let base =
                match self
                    .ram
                    .request_base(fds, slot, generation, path.first() != Some(&b'/'))
                {
                    Ok(base) => base,
                    Err(code) => return status(code),
                };
            let identity = fds.binding.identity(false).expect("authenticated");
            match Resolve::new(&mut self.ram.storage, path, base, identity, follow != 0) {
                Ok(second) => {
                    j.path_mut().second = Some(second);
                    return Answer::Status(Status::Ok);
                }
                Err(code) => return status(code),
            }
        }
        let (Ok(id), Ok(())) = (body.u64(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        let i = match self.path_slot(id, r.label()) {
            Ok(i) => i,
            Err(code) => return status(code),
        };
        let j = self.jobs[i].as_ref().expect("resolve job");
        let identity = fds.binding.identity(j.real).expect("authenticated");
        let j = self.jobs[i].as_mut().expect("resolve job");
        let JobOperation::Path(path) = &mut j.operation else {
            return status(proto_fs::PERMISSION);
        };
        if let Some(open) = path.open.as_mut() {
            if matches!(
                open.phase,
                OpenPhase::Committed { .. } | OpenPhase::Canceled { .. }
            ) {
                return if j.authority == fds.binding.stamp() {
                    Answer::Status(Status::Ok)
                } else {
                    status(proto_fs::OPEN_RETIRED)
                };
            }
            if !matches!(open.phase, OpenPhase::Resolving)
                && let Err(code) = open.reset_unpublished(self.ram, fds, &mut j.root)
            {
                return status(code);
            }
        }
        if j.authority != fds.binding.stamp() {
            j.authority = fds.binding.stamp();
            path.resolver.invalidate();
            if let Some(second) = path.second.as_mut() {
                second.invalidate();
            }
        }
        let mut result = path.resolver.step(&mut self.ram.storage, identity);
        if matches!(result, Ok(Progress::Found(_) | Progress::Missing(_)))
            && let Some(second) = path.second.as_mut()
        {
            result = second.step(&mut self.ram.storage, identity);
        }
        match result {
            Ok(Progress::More) => status(proto_fs::RESOLVING),
            Ok(Progress::Found(_) | Progress::Missing(_)) => Answer::Status(Status::Ok),
            Err(code) => {
                self.cancel_job(id, r.label(), Some(fds));
                status(code)
            }
        }
    }
    /// Every effect and cached result is gated by the exact job and current binding stamp.
    fn finished_reply(
        &self,
        fds: &Fds,
        r: &mut Request<'_>,
        held: ramfs::TentativeOpen,
        query: bool,
    ) -> Answer {
        let marked_fd = match self.ram.marked_open(fds, held) {
            Ok(fd) => fd,
            Err(code) => return status(code),
        };
        let w = r.reply();
        let result = if query {
            w.u32(0)
                .and_then(|()| w.u32(5))
                .and_then(|()| w.u64(0))
                .and_then(|()| w.u32(marked_fd))
                .and_then(|()| w.u32(0))
                .and_then(|()| w.u64(held.description.generation))
        } else {
            w.u32(0)
                .and_then(|()| w.u32(marked_fd))
                .and_then(|()| w.u64(held.description.generation))
        };
        if result.is_err() {
            Answer::Status(Status::BadSize)
        } else {
            Answer::Reply(Outgoing::new())
        }
    }
    fn open_stage(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(id), Ok(())) = (body.u64(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        let i = match self.path_slot(id, r.label()) {
            Ok(i) => i,
            Err(code) => return status(code),
        };
        let j = self.jobs[i].as_mut().expect("owned open job");
        if !fds.resolvers.contains(&id) || j.real || j.path().second.is_some() {
            return status(proto_fs::PERMISSION);
        }
        if j.authority != fds.binding.stamp() {
            return status(
                if j.path().open.as_ref().is_some_and(|open| {
                    matches!(
                        open.phase,
                        OpenPhase::Committed { .. } | OpenPhase::Canceled { .. }
                    )
                }) {
                    proto_fs::OPEN_RETIRED
                } else {
                    proto_fs::STALE_PROOF
                },
            );
        }
        let identity = match fds.binding.identity(false) {
            Ok(identity) => identity,
            Err(code) => return status(code),
        };
        let JobOperation::Path(path) = &mut j.operation else {
            return status(proto_fs::PERMISSION);
        };
        let Some(open) = path.open.as_mut() else {
            return status(proto_fs::PERMISSION);
        };
        let cached = matches!(open.phase, OpenPhase::Committed { .. });
        let proof = if cached {
            None
        } else {
            match path.resolver.result_proof(
                &self.ram.storage,
                identity,
                Intent::Open { flags: open.flags },
            ) {
                Ok(proof) => Some(proof),
                Err(code) => return status(code),
            }
        };
        if r.method() == Method::OpenPrepare as u16 {
            if let OpenPhase::Committed { held, .. } = open.phase {
                return match self.ram.validate_tentative(fds, held) {
                    Ok(_) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                };
            }
            return match open.prepare(
                self.ram,
                fds,
                proof.expect("uncommitted path proof"),
                identity,
                &mut j.root,
            ) {
                Ok(true) => Answer::Status(Status::Ok),
                Ok(false) => status(proto_fs::RESOLVING),
                Err(code) => status(code),
            };
        }
        let held = match open.phase {
            OpenPhase::Prepared { held, .. } | OpenPhase::Committed { held, .. } => held,
            _ => return status(proto_fs::RESOLVING),
        };
        let marked_fd = match self.ram.marked_open(fds, held) {
            Ok(fd) => fd,
            Err(code) => return status(code),
        };
        // The exact type and fixed response are captured before namespace effects.
        let w = r.reply();
        if w.u32(0)
            .and_then(|()| w.u32(marked_fd))
            .and_then(|()| w.u64(held.description.generation))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        let now = self.time_source.now();
        match open.commit(self.ram, fds, proof, identity, &mut j.root, now) {
            Ok(committed) => {
                debug_assert_eq!(committed, held);
                Answer::Reply(Outgoing::new())
            }
            Err(code) => status(code),
        }
    }
    fn proof(
        &mut self,
        id: u64,
        owner: u64,
        fds: Option<&Fds>,
    ) -> Result<(Token, Option<proto_process::WhoReply>), u32> {
        let i = self.path_slot(id, owner)?;
        let j = self.jobs[i].as_ref().expect("job");
        if j.real || j.path().second.is_some() || j.path().open.is_some() {
            return Err(proto_fs::PERMISSION);
        }
        let fds = fds.ok_or(proto_fs::PERMISSION)?;
        if !fds.resolvers.contains(&id) {
            return Err(proto_fs::PERMISSION);
        }
        if j.authority != fds.binding.stamp() {
            return Err(proto_fs::STALE_PROOF);
        }
        let identity = fds.binding.identity(j.real)?;
        Ok((j.path().resolver.proof(&self.ram.storage, identity)?, None))
    }
}
