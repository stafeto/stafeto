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
    AdmissionState, AuditStep, Binding, BindingPurpose, CleanupAudit, Identity, NotaryReply,
    RetainedSourcePhase,
};
use ramfs::open::{Journal as OpenJournal, Phase as OpenPhase};
use ramfs::resolve::{Intent, Progress, Resolve};
use ramfs::storage::{NONE, Root, Token};
use ramfs::tree::{self, Index};
use ramfs::{Exec, SET_GID, SET_UID};
use ramfs::{Fds, Ram};
use rt::abi::{Access, Rights};
use rt::compact::Compact;
use rt::handle::{Any, Channel, Handle, Incoming, Memory, Outgoing, Resource};
use rt::service::{Answer, Config, Heartbeat, Request, Service, Session};
use rt::sys;

mod clock_page;

rt::entry!(main);

#[cfg(not(feature = "auth-probe"))]
const METHODS: &[u16] = proto_fs::METHODS;
#[cfg(feature = "auth-probe")]
const METHODS: &[u16] = &[
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    0xfff6,
    0xfff7,
    0xfff8,
    0xfff9,
    0xfffa,
    0xfffb,
    0xfffc,
    0xfffd,
    0xfffe,
    #[cfg(feature = "full-capacity-probe")]
    0xfff0,
    #[cfg(feature = "full-capacity-probe")]
    0xfff1,
    #[cfg(feature = "full-capacity-probe")]
    0xfff2,
];
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
    // Startup retains this exact owner handle throughout the loop. take changes
    // only Named. Reverse local drop order removes the observer before Startup.
    #[cfg(feature = "full-capacity-probe")]
    let registered_process = Handle::borrowed(start.process.raw());
    #[cfg(feature = "full-capacity-probe")]
    let Ok(_resource_guard) = rt::resource_meter::Guard::install(&registered_process) else {
        return 10;
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
    let state = unsafe {
        let pointer = (*STORAGE.0.get()).as_mut_ptr();
        // State's integer, boolean and Option<Account> fields admit zero values.
        pointer.write_bytes(0, 1);
        &mut *pointer
    };
    state.initialize();
    let ram = Ram::with_storage(now, state, data, tree);
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
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
    );
    rt::println!("ramfs: ready");
    // SAFETY: only the main thread reaches TABLES, here once.
    let tables = unsafe { &mut *TABLES.0.get() };
    let mut fs = Fs {
        ram,
        time_source,
        #[cfg(feature = "open-finalize-clock-probe")]
        clock_gate: None,
        #[cfg(feature = "image-info-probe")]
        image_info_backing: Handle::borrowed(backing.raw()),
        #[cfg(feature = "image-info-probe")]
        image_info_fault: None,
        #[cfg(feature = "full-capacity-probe")]
        capacity_backing: Handle::borrowed(backing.raw()),
        #[cfg(feature = "full-capacity-probe")]
        capacity_checkpoints: ramfs::capacity::Checkpoints::default(),
        #[cfg(feature = "full-capacity-probe")]
        capacity_retired_gate: None,
        into_window: None,
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
        generations: None,
        maintenance: ramfs::maintenance::Cursor::default(),
        next_audit_ns: 0,
        maintenance_jobs: false,
        data_gc_turn: false,
        orphan_cursor: 0,
        orphan_count: 0,
        clone_wake: false,
    };
    // Prepare the authentic notary page after publishing the RAM endpoint.
    // Standalone boot profiles may have no Process service.
    let _ = fs.notary_register();
    #[cfg(feature = "steps")]
    rt::service::report_steps(2);
    let _ = rt::service::run_in(&channel, &mut fs, config, &mut tables.sessions);
    4
}

type Admission = AdmissionState<NotaryTransport>;

type NotaryTransport = ramfs::notary_transport::Transport<NotaryEffects>;
type NotaryState = ramfs::notary_transport::State<NotaryEffects>;

struct NotaryEffects;
impl ramfs::notary_transport::Owners for NotaryEffects {
    type Copy = Compact<Channel>;
    type Back = Outgoing;
    type Reply = Incoming;
    type Held = Handle<Any>;
    fn copy_live(owner: &Self::Copy) -> bool {
        owner.is_some()
    }
    fn close_copy(owner: &mut Self::Copy) {
        let _ = owner.close_retained();
    }
    fn pop_back(owners: &mut Self::Back) -> Option<Self::Held> {
        owners.pop()
    }
    fn reply_len(owners: &Self::Reply) -> usize {
        owners.len()
    }
    fn take_reply(owners: &mut Self::Reply, index: usize) -> Option<Self::Held> {
        owners.take_any(index).ok()
    }
    fn close_held(owner: &mut Option<Self::Held>) {
        let _ = Handle::close_retained(owner);
    }
}
struct NotaryCall<'a> {
    identity: &'a Handle<Channel>,
    notary: &'a Handle<Channel>,
    original: &'a Binding,
    retained: bool,
}
impl ramfs::notary_transport::Effects<NotaryEffects> for NotaryCall<'_> {
    fn duplicate(&mut self) -> Option<Compact<Channel>> {
        sys::handle_duplicate(self.identity, Rights::NOTIFY | Rights::TRANSFER)
            .ok()
            .map(|copy| Compact::from_owner(Some(copy)))
    }
    fn send(
        &mut self,
        owner: &mut Compact<Channel>,
    ) -> ramfs::notary_transport::Send<Outgoing, Incoming> {
        use ramfs::notary_transport::Send;
        let mut request = proto_wire::Writer::new();
        if self.retained {
            let Some(who) = self.original.snapshot_ref() else {
                return Send::Denied;
            };
            let Some(loader) = who.loader else {
                return Send::Denied;
            };
            let expected = proto_process::RetainedLoader {
                pid: who.pid,
                index: who.index,
                image: who.image,
                ticket: loader.ticket,
                root: who.root,
            };
            proto_process::Method::RetainedLoader
                .header()
                .write(&mut request)
                .and_then(|()| expected.write(&mut request))
                .expect("fixed retained request");
        } else {
            proto_process::Method::Vouch
                .header()
                .write(&mut request)
                .expect("fixed vouch request");
        }
        let Some(copy) = owner.take() else {
            return Send::Retry;
        };
        match sys::send_handles(self.notary, request.as_bytes(), [copy.erase()]) {
            Ok(reply) => {
                let mut bytes = [0; rt::abi::MESSAGE_MAX];
                let body = reply.bytes(&mut bytes);
                if !reply.handles.is_empty() {
                    return Send::Reply(reply.handles);
                }
                if self.retained {
                    match NotaryReply::<260>::read(body, true) {
                        NotaryReply::Wire(wire) => Send::RetainedWire(wire),
                        NotaryReply::Denied => Send::Denied,
                        NotaryReply::Retry => Send::Retry,
                    }
                } else {
                    match NotaryReply::<252>::read(body, true) {
                        NotaryReply::Wire(wire) => Send::Wire(wire),
                        NotaryReply::Denied => Send::Denied,
                        NotaryReply::Retry => Send::Retry,
                    }
                }
            }
            Err(refused) => {
                assert!(refused.token.is_none(), "Send retains no reply token");
                match refused.back {
                    Some(owners) => Send::Back(owners),
                    None => Send::Retry,
                }
            }
        }
    }
}
const _: () = assert!(core::mem::size_of::<NotaryTransport>() == 104);
const _: () = assert!(core::mem::size_of::<Admission>() == 280);

type IntoWindow = rt::retention::Window<Handle<Memory>>;
const _: () = assert!(core::mem::size_of::<IntoWindow>() == 40);

struct Fs {
    /// The unique INTO resource keeps its paid mapping owner through failed unmap.
    into_window: Option<IntoWindow>,
    ram: Ram<'static>,
    time_source: clock_page::TimeSource,
    #[cfg(feature = "open-finalize-clock-probe")]
    clock_gate: Option<clock_page::ClockGate>,
    // The startup-owned backing outlives this service loop and every outgoing copy.
    #[cfg(feature = "image-info-probe")]
    image_info_backing: ManuallyDrop<Handle<Memory>>,
    #[cfg(feature = "image-info-probe")]
    image_info_fault: Option<(u32, u32, u64, u32)>,
    #[cfg(feature = "full-capacity-probe")]
    capacity_backing: ManuallyDrop<Handle<Memory>>,
    #[cfg(feature = "full-capacity-probe")]
    capacity_checkpoints: ramfs::capacity::Checkpoints,
    #[cfg(feature = "full-capacity-probe")]
    capacity_retired_gate: Option<ramfs::capacity::RetiredGate>,
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
    births: &'static mut [Option<(u64, BirthData)>; BIRTHS],
    /// The clones alive, bounded for each client and in all.
    clones: &'static mut Clones<CLONES>,
    places: &'static ramfs::places::Places,
    identities: &'static mut [Option<IdentityChannel>; SESSIONS],
    jobs: &'static mut [Option<ResolveJob>; ramfs::storage::PREPARATIONS],
    job_generations: &'static mut [u64; ramfs::storage::PREPARATIONS],
    generations: Option<Handle<Memory>>,
    maintenance: ramfs::maintenance::Cursor,
    next_audit_ns: u64,
    maintenance_jobs: bool,
    data_gc_turn: bool,
    orphan_cursor: u8,
    orphan_count: u16,
    clone_wake: bool,
}

/// The clones the service keeps alive at most: one for each record of the
/// process service and room beside them.
const CLONES: usize = 320;

/// Clones whose sessions sent nothing yet, at most: past them, Clone is
/// LIMIT_REACHED. A child that never touches a file keeps its birth, so
/// there is room for every record and its transient binding preparation.
const BIRTHS: usize = CLONES;

/// The tables of the sessions and of the births, in `.bss`: too big for
/// the service's stack.
// The paid resident Fds variant supplies the exact existing storage for both owners.
#[allow(clippy::large_enum_variant)]
enum BirthData {
    Ready(Fds),
    Cloning(CloneBirth),
}
impl BirthData {
    fn into_ready(self) -> Fds {
        match self {
            Self::Ready(fds) => fds,
            Self::Cloning(_) => panic!("published ready birth"),
        }
    }
}
impl core::ops::Deref for BirthData {
    type Target = Fds;
    fn deref(&self) -> &Fds {
        match self {
            Self::Ready(fds) => fds,
            Self::Cloning(_) => panic!("ready birth access"),
        }
    }
}
impl core::ops::DerefMut for BirthData {
    fn deref_mut(&mut self) -> &mut Fds {
        match self {
            Self::Ready(fds) => fds,
            Self::Cloning(_) => panic!("ready birth access"),
        }
    }
}
type CloneBirth = ramfs::clone::Journal<Handle<Channel>, sys::Token>;
use ramfs::clone::Phase as ClonePhase;
const _: () = assert!(core::mem::size_of::<Option<(u64, BirthData)>>() <= 2632);

struct ImageContext {
    token: Token,
    private: Option<Handle<Channel>>,
    transfer: Option<Handle<Channel>>,
}
struct IdentityChannel {
    label: u64,
    closing: bool,
    channel: Handle<Channel>,
    offered: Compact<Channel>,
    previous: Compact<Channel>,
    admission: Admission,
    pending: bool,
    require: bool,
    purpose: BindingPurpose,
    original: Binding,
    original_root: Root,
    audit: CleanupAudit,
    image: Option<ImageContext>,
}
struct ResolveJob {
    id: u64,
    owner: u64,
    root: u16,
    real: bool,
    authority: Option<ramfs::authority::Stamp>,
    operation: JobOperation,
    open_key: Option<proto_fs::OpenKey>,
    raw_base: (u32, u64),
    abandoned: bool,
    /// A paid cancellation continues through the ordinary owner cursor.
    retiring: bool,
}
struct PathJob {
    resolver: Resolve,
    second: Option<Resolve>,
    open: Option<OpenJournal>,
}
#[allow(clippy::large_enum_variant)]
enum JobOperation {
    Path(PathJob),
    Data(ramfs::data::Journal),
}
impl ResolveJob {
    fn path(&self) -> &PathJob {
        match &self.operation {
            JobOperation::Path(path) => path,
            JobOperation::Data(_) => panic!("validated path job"),
        }
    }
    fn path_mut(&mut self) -> &mut PathJob {
        match &mut self.operation {
            JobOperation::Path(path) => path,
            JobOperation::Data(_) => panic!("validated path job"),
        }
    }
}
struct Tables {
    places: ramfs::places::Places,
    clones: Clones<CLONES>,
    sessions: [Option<Session<Fds, 0>>; SESSIONS],
    births: [Option<(u64, BirthData)>; BIRTHS],
    identities: [Option<IdentityChannel>; SESSIONS],
    jobs: [Option<ResolveJob>; ramfs::storage::PREPARATIONS],
    job_generations: [u64; ramfs::storage::PREPARATIONS],
}
struct Bss(UnsafeCell<Tables>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(Tables {
    places: ramfs::places::Places::new(),
    clones: Clones::new(),
    sessions: [const { None }; SESSIONS],
    births: [const { None }; BIRTHS],
    identities: [const { None }; SESSIONS],
    jobs: [const { None }; ramfs::storage::PREPARATIONS],
    job_generations: [0; ramfs::storage::PREPARATIONS],
}));

impl Fs {
    fn window_cleanup_step(&mut self) {
        let Some(window) = self.into_window.as_mut() else {
            return;
        };
        let done = window.step(
            |length| {
                // SAFETY: this journal owns the unique exact INTO mapping.
                unsafe { sys::mem_unmap(&self.process, INTO, length) }
            },
            Handle::close_retained,
        );
        if done == Ok(true) {
            self.into_window = None;
        }
    }

    fn closed_terminal(&self, fds: &Fds, label: u64) -> bool {
        !self
            .births
            .iter()
            .flatten()
            .any(|(held, data)| *held == label && matches!(data, BirthData::Cloning(_)))
            && Ram::released(fds)
            && self.jobs.iter().flatten().all(|job| job.owner != label)
            && self
                .into_window
                .as_ref()
                .is_none_or(|window| window.owner != label)
    }

    /// Closing dispatch reaches only retained settlement phases.
    fn closed_cleanup_step(&mut self, fds: &mut Fds, label: u64) -> bool {
        #[cfg(feature = "open-finalize-clock-probe")]
        if let Some(gate) = self.clock_gate.as_mut().filter(|gate| gate.owner == label) {
            gate.closing = true;
            if Handle::close_retained(&mut gate.channel).is_ok() {
                self.clock_gate = None;
            }
            return true;
        }
        if fds.image_outcome.is_some() {
            self.clear_image_outcome_step(fds);
            return true;
        }
        if let Some(id) = self
            .jobs
            .iter()
            .flatten()
            .find(|job| job.owner == label)
            .map(|job| job.id)
        {
            self.cancel_job_mode(id, label, Some(fds), true);
            return true;
        }
        #[cfg(feature = "auth-probe")]
        if fds.auth_probe_gc.take().is_some() {
            let _ = self
                .ram
                .storage
                .unlink(ramfs::storage::ROOT, b"auth-probe-gc", fds.root);
            return true;
        }
        if ramfs::maintenance::retained_release_step(
            &mut self.ram,
            fds,
            label,
            self.into_window.as_ref().map(|window| window.owner),
        ) {
            return true;
        }
        if !Ram::references_released(fds) {
            return true;
        }
        self.identity_close_step(fds)
    }

    fn identity_close_step(&mut self, fds: &mut Fds) -> bool {
        Self::identity_close_fields(self.identities, fds)
    }

    fn identity_close_fields(
        identities: &mut [Option<IdentityChannel>; SESSIONS],
        fds: &mut Fds,
    ) -> bool {
        let Some(identity) = identities
            .get_mut(fds.authority_index as usize)
            .and_then(Option::as_mut)
        else {
            fds.authority_index = NONE;
            return false;
        };
        if Self::transport_drain_identity(identity).is_some() {
            return true;
        }
        if let Admission::Transport(transport) = &mut identity.admission {
            match &mut transport.state {
                NotaryState::Rollback { rejected, .. } if rejected.is_some() => {
                    let _ = rejected.close_retained();
                    return true;
                }
                NotaryState::Rollback { .. } | NotaryState::Commit => {
                    identity.admission = Admission::Unvouched
                }
                _ => unreachable!("settled transport disposal"),
            }
        }
        if identity.offered.is_some() {
            let _ = identity.offered.close_retained();
            return true;
        }
        if identity.previous.is_some() {
            let _ = identity.previous.close_retained();
            return true;
        }
        if let Some(image) = identity.image.as_mut() {
            if image.private.is_some() {
                let _ = Handle::close_retained(&mut image.private);
                return true;
            }
            if image.transfer.is_some() {
                let _ = Handle::close_retained(&mut image.transfer);
                return true;
            }
        }
        // All four optional owners are absent before the mandatory channel call.
        if Handle::close_retained_owner(
            &mut identities[fds.authority_index as usize],
            |identity| &identity.channel,
            |identity| {
                let _ = identity.channel.into_raw();
            },
        )
        .is_ok()
        {
            fds.authority_index = NONE;
        }
        true
    }
}

impl Fs {
    /// A dead or superseded authority releases one retained reference per pass.
    fn cleanup_step(&mut self, fds: &mut Fds, label: u64, protected: Option<u64>) -> bool {
        if fds.closing
            || self
                .identities
                .get(fds.authority_index as usize)
                .and_then(Option::as_ref)
                .is_some_and(|identity| identity.closing)
        {
            fds.closing = true;
            fds.binding = Binding::Cleanup;
            return self.closed_cleanup_step(fds, label);
        }
        if self.binding_finish_step(fds).is_some() {
            return true;
        }
        if self
            .identities
            .get(fds.authority_index as usize)
            .and_then(Option::as_ref)
            .is_some_and(|identity| {
                matches!(
                    identity.admission,
                    Admission::Transport(NotaryTransport {
                        state: NotaryState::Back { .. }
                            | NotaryState::Reply { .. }
                            | NotaryState::Copy { outcome: 1.., .. },
                        ..
                    })
                )
            })
        {
            self.transport_drain_step(fds);
            return true;
        }
        if fds.image_outcome.is_some_and(|outcome| {
            outcome.phase == ramfs::image::ImagePhase::Prepared
                && self
                    .births
                    .iter()
                    .flatten()
                    .find(|(label, _)| *label == outcome.label)
                    .is_none_or(|(_, child)| child.closing)
        }) {
            self.clear_image_outcome_step(fds);
            return true;
        }
        if let Some(id) = fds.resolvers.iter().copied().find(|id| {
            *id != 0
                && self
                    .job_slot(*id, label)
                    .is_ok_and(|slot| self.jobs[slot].as_ref().is_some_and(|job| job.retiring))
        }) {
            self.cancel_job_mode(id, label, Some(fds), true);
            return true;
        }
        #[cfg(feature = "full-capacity-probe")]
        if fds
            .binding
            .snapshot_ref()
            .is_none_or(|who| generation(who.index as usize) != who.generation)
        {
            self.capacity_clear_owner(label);
        }
        match fds.binding.custody_phase(fds.binding_preparation.is_some()) {
            ramfs::authority::CustodyPhase::Hold => return false,
            ramfs::authority::CustodyPhase::Candidate => {
                let _ = self.binding_phase(fds, label, &mut true, protected);
                return true;
            }
            ramfs::authority::CustodyPhase::Ordinary => {}
        }
        if fds
            .binding
            .snapshot_ref()
            .is_some_and(|who| generation(who.index as usize) & proto_process::GENERATION_DEAD != 0)
        {
            self.revoke_clone_owner(label);
            let unfinished = fds.binding_preparation.is_some();
            fds.closing = true;
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
            let _ = self.binding_phase(fds, label, &mut progress, protected);
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
                if matches!(identity.admission, Admission::Transport(_)) {
                    self.transport_drain_step(fds);
                    return true;
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
        fds.closing = true;
        self.closed_cleanup_step(fds, label)
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
        let free = self
            .births
            .iter()
            .position(Option::is_none)
            .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?;
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
        self.births[free] = Some((label, BirthData::Ready(child)));
        fds.image_outcome = Some(ramfs::image::ImageOutcome {
            job,
            label,
            token,
            phase: ramfs::image::ImagePhase::Prepared,
        });
        Ok(())
    }
    /// Source cleanup retires its private recovery copy while external copies retain the image.
    fn clear_image_outcome(&mut self, fds: &mut Fds) {
        self.clear_image_outcome_step(fds);
        self.clone_wake = true;
        self.maintenance.remaining = SESSIONS + BIRTHS;
    }
    /// Cancellation keeps the exact child until its existing cursor settles all owners.
    fn clear_image_outcome_step(&mut self, fds: &mut Fds) -> bool {
        let Some(outcome) = fds.image_outcome else {
            return true;
        };
        if outcome.phase == ramfs::image::ImagePhase::Prepared {
            if let Some((_, child)) = self
                .births
                .iter_mut()
                .flatten()
                .find(|(label, _)| *label == outcome.label)
            {
                child.closing = true;
                child.binding = Binding::Cleanup;
                self.clone_wake = true;
                self.maintenance.remaining = SESSIONS + BIRTHS;
                return false;
            }
            if self
                .identities
                .iter()
                .flatten()
                .any(|identity| identity.label == outcome.label)
            {
                return false;
            }
        } else if let Some(image) = self
            .identities
            .iter_mut()
            .flatten()
            .find(|identity| identity.label == outcome.label)
            .and_then(|identity| identity.image.as_mut())
            && image.private.is_some()
        {
            let _ = Handle::close_retained(&mut image.private);
            return false;
        }
        fds.image_outcome = None;
        true
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
        if self
            .job_slot(job, r.label())
            .is_ok_and(|slot| self.jobs[slot].as_ref().is_some_and(|job| job.retiring))
        {
            return status(proto_fs::OPEN_RETIRED);
        }
        if fds.image_outcome.is_some_and(|outcome| {
            outcome.phase == ramfs::image::ImagePhase::Prepared
                && self
                    .births
                    .iter()
                    .flatten()
                    .find(|(label, _)| *label == outcome.label)
                    .is_none_or(|(_, child)| child.closing)
        }) {
            self.clear_image_outcome_step(fds);
            return status(proto_fs::RESOLVING);
        }
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
                    .identities
                    .iter()
                    .filter_map(Option::as_ref)
                    .find(|identity| identity.label == outcome.label)
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
            .identities
            .iter()
            .filter_map(Option::as_ref)
            .find(|identity| identity.label == outcome.label)
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
        let image = self
            .identities
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|identity| identity.label == outcome.label)
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
                if body.finish().is_err()
                    || count as usize > proto_fs::READ_INTO_MAX
                    || r.handles.len() != 1
                    || !matches!(r.handles.info(0), Some((abi::ObjectKind::Memory, got)) if got.contains(rights))
                {
                    return Answer::Status(Status::BadSize);
                }
                let Some(image) = fds.image_hold else {
                    return status(proto_fs::BAD_FD);
                };
                let Some(words) = r.loan() else {
                    return Answer::Status(Status::Kernel(abi::Error::BadState));
                };
                assert!(
                    self.notary.is_some() && self.generations.is_some(),
                    "registered image loan"
                );
                ramfs::read_into::Loan::new(words).begin(fd, count, offset, at, image);
                Answer::Reply(Outgoing::new())
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
        let snapshot = match ramfs::clone::Snapshot::preflight(&self.ram, fds, &list[..count]) {
            Ok(snapshot) => snapshot,
            Err(code) => return status(code),
        };
        let source = if fds.binding.snapshot_ref().is_some() {
            let Some(identity) = self
                .identities
                .get(fds.authority_index as usize)
                .and_then(Option::as_ref)
                .filter(|identity| identity.label == r.label() && !identity.closing)
            else {
                return status(proto_fs::PERMISSION);
            };
            Some(identity.channel.raw())
        } else {
            None
        };
        let authority_index = if source.is_some() {
            let Some(index) = self.identities.iter().position(Option::is_none) else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            index as u16
        } else {
            NONE
        };
        let (free, label) = match ramfs::clone::reserve(
            self.births,
            &mut self.given,
            self.places,
            self.clones,
            r.label(),
        ) {
            Ok(reserved) => reserved,
            Err(code) => return status(code),
        };
        snapshot.retain(&mut self.ram);
        let binding = fds
            .binding
            .snapshot()
            .map_or(fds.binding, Binding::Inherited);
        self.births[free] = Some((
            label,
            BirthData::Cloning(CloneBirth {
                owner: r.label(),
                snapshot: Some(snapshot),
                binding,
                authority_index,
                session: None,
                token: r.token(),
                phase: ClonePhase::Session,
                code: 0,
            }),
        ));
        if let Some(raw) = source {
            let identity = Handle::<Channel>::borrowed(raw);
            match sys::handle_duplicate(
                &identity,
                Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER,
            ) {
                Ok(copy) => {
                    self.identities[authority_index as usize] = Some(IdentityChannel {
                        label,
                        closing: false,
                        channel: copy,
                        offered: Compact::empty(),
                        previous: Compact::empty(),
                        admission: Admission::Unvouched,
                        pending: false,
                        require: false,
                        purpose: BindingPurpose::Candidate,
                        original: binding,
                        original_root: fds.root,
                        audit: CleanupAudit::default(),
                        image: None,
                    });
                }
                Err(_) => {
                    let BirthData::Cloning(child) = &mut self.births[free].as_mut().unwrap().1
                    else {
                        unreachable!()
                    };
                    child.authority_index = NONE;
                    child.code = proto_fs::PERMISSION;
                    child.phase = ClonePhase::ErrorReply;
                }
            }
        }
        self.clone_wake = true;
        Answer::Deferred
    }
}

impl Fs {
    fn revoke_clone_owner(&mut self, owner: u64) {
        for (_, data) in self.births.iter_mut().flatten() {
            if let BirthData::Cloning(child) = data
                && child.owner == owner
            {
                child.code = Status::Kernel(abi::Error::PeerClosed).code();
                child.phase = if child.token.is_some() {
                    ClonePhase::ErrorReply
                } else {
                    ClonePhase::Rollback
                };
                self.clone_wake = true;
            }
        }
    }

    /// Dispatch the same resident ownership engine exercised by host fixtures.
    fn clone_birth_step(&mut self, slot: usize) {
        let (label, data) = self.births[slot].as_mut().expect("paid clone birth");
        let BirthData::Cloning(child) = data else {
            return;
        };
        let mut effects = CloneEffects {
            channel: &self.channel,
            identities: self.identities,
            level: self.level,
        };
        match child.step(&mut self.ram, *label, &mut effects) {
            ramfs::clone::Outcome::Pending => {}
            ramfs::clone::Outcome::Ready => *data = BirthData::Ready(child.materialize()),
            ramfs::clone::Outcome::Terminal => {
                let label = *label;
                self.places.release(label);
                self.clones.gone(label);
                self.births[slot] = None;
            }
        }
    }
}

struct CloneEffects<'a> {
    channel: &'a Handle<Channel>,
    identities: &'a mut [Option<IdentityChannel>; SESSIONS],
    level: u8,
}
impl ramfs::clone::Effects<Handle<Channel>, sys::Token> for CloneEffects<'_> {
    fn label(&mut self, label: u64) -> Result<Handle<Channel>, abi::Error> {
        sys::handle_label(
            self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        )
    }
    fn reply(
        &mut self,
        token: sys::Token,
        session: Option<Handle<Channel>>,
        code: u32,
    ) -> Result<(), ramfs::clone::Refusal<Handle<Channel>, sys::Token>> {
        let mut outgoing = Outgoing::new();
        if let Some(session) = session {
            outgoing.push(session.erase()).expect("one clone transfer");
        }
        token
            .reply_handles(&proto_wire::reply(Status::from_code(code)), outgoing)
            .map_err(|mut refusal| {
                let back = refusal
                    .back
                    .as_mut()
                    .and_then(Outgoing::pop)
                    .map(|handle| Handle::from_raw(handle.into_raw()));
                assert!(refusal.back.as_ref().is_none_or(Outgoing::is_empty));
                ramfs::clone::Refusal {
                    error: refusal.error,
                    back,
                    token: refusal.token,
                }
            })
    }
    fn close(&mut self, session: &mut Option<Handle<Channel>>) -> Result<(), abi::Error> {
        Handle::close_retained(session)
    }
    fn close_identity(&mut self, index: u16, label: u64) -> Result<(), abi::Error> {
        let identity = self.identities[index as usize]
            .as_ref()
            .expect("retained child identity");
        assert_eq!(identity.label, label, "exact clone identity");
        assert!(
            !identity.offered.is_some() && !identity.previous.is_some() && identity.image.is_none(),
            "unpublished clone identity optionals"
        );
        Handle::close_retained_owner(
            &mut self.identities[index as usize],
            |identity| &identity.channel,
            |identity| {
                let _ = identity.channel.into_raw();
            },
        )
    }
}

impl Service<0> for Fs {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    const PLACED: usize = SESSIONS;
    const RETAIN_CLOSED: bool = true;
    const BOUNDED_INGRESS: bool = true;

    fn closing(&self, s: &Session<Fds, 0>) -> bool {
        s.data.closing
    }

    fn closed_method(&self, method: u16) -> bool {
        ramfs::maintenance::closed_method(method)
    }

    type Data = Fds;

    /// The client of `s` went: its descriptors close.
    fn gone(&mut self, s: &mut Session<Fds, 0>) {
        #[cfg(feature = "full-capacity-probe")]
        self.capacity_revoke_owner(s.label());
        #[cfg(feature = "open-finalize-clock-probe")]
        if self
            .clock_gate
            .as_ref()
            .is_some_and(|gate| gate.owner == s.label())
        {
            self.clock_gate
                .as_mut()
                .expect("exact revoked gate")
                .closing = true;
        }
        if !s.data.claimed {
            let label = s.label();
            if let Some(birth) = self.births.iter_mut().find(|b| {
                b.as_ref()
                    .is_some_and(|(l, data)| *l == label && matches!(data, BirthData::Ready(_)))
            }) {
                s.data = birth
                    .take()
                    .expect("exact disappearing birth")
                    .1
                    .into_ready();
            }
            s.data.claimed = true;
        }
        self.revoke_clone_owner(s.label());
        s.data.closing = true;
        s.data.binding = Binding::Cleanup;
        #[cfg(feature = "auth-probe")]
        {
            s.data.auth_probe_hold = false;
        }
    }

    /// The last copy of a session Clone made went before it sent anything:
    /// the descriptors it was born with close.
    fn closed(&mut self, label: u64) {
        #[cfg(feature = "full-capacity-probe")]
        self.capacity_revoke_owner(label);
        #[cfg(feature = "open-finalize-clock-probe")]
        if self
            .clock_gate
            .as_ref()
            .is_some_and(|gate| gate.owner == label)
        {
            self.clock_gate
                .as_mut()
                .expect("exact revoked gate")
                .closing = true;
        }
        if let Some((_, BirthData::Cloning(child))) =
            self.births.iter_mut().flatten().find(|(l, _)| *l == label)
        {
            child.phase = if child.token.is_some() {
                ClonePhase::ErrorReply
            } else {
                ClonePhase::Rollback
            };
            child.code = Status::Kernel(abi::Error::PeerClosed).code();
            self.clone_wake = true;
            return;
        }
        if let Some((_, fds)) = self.births.iter_mut().flatten().find(|(l, _)| *l == label) {
            fds.closing = true;
            fds.binding = Binding::Cleanup;
            #[cfg(feature = "auth-probe")]
            {
                fds.auth_probe_hold = false;
            }
        }
    }

    fn maintenance(
        &mut self,
        sessions: &mut [Option<Session<Fds, 0>>],
        notice: rt::service::Notice,
    ) {
        self.cursor_maintenance(sessions, notice, None);
    }

    fn request_maintenance(&mut self, sessions: &mut [Option<Session<Fds, 0>>], protected: u64) {
        self.cursor_maintenance(
            sessions,
            rt::service::Notice {
                source: abi::Source::Unlabeled,
                label: 0,
                bits: 1,
                count: 1,
            },
            Some(protected),
        );
    }

    fn request_tail(&mut self, request: &mut Request<'_>) -> rt::service::TailProgress {
        self.read_into_step(request)
    }

    fn continuation_step(&mut self) -> bool {
        if !self.clone_wake {
            return false;
        }
        if sys::notify(&self.channel, 1).is_ok() {
            self.clone_wake = false;
        }
        self.clone_wake
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
        if self.closing(s) && !s.data.claimed {
            let label = s.label();
            if let Some(birth) = self.births.iter_mut().find(|b| {
                b.as_ref()
                    .is_some_and(|(l, data)| *l == label && matches!(data, BirthData::Ready(_)))
            }) {
                s.data = birth.take().expect("exact retained birth").1.into_ready();
            }
            s.data.claimed = true;
            s.data.closing = true;
            s.data.binding = Binding::Cleanup;
        }
        if s.data.closing && !self.closed_method(r.method()) {
            return status(proto_fs::PERMISSION);
        }
        let first = !s.data.claimed;
        if !s.data.claimed {
            // The first request of a session Clone made takes its
            // descriptors.
            let label = r.label();
            if let Some(birth) = self.births.iter_mut().find(|b| {
                b.as_ref()
                    .is_some_and(|(l, data)| *l == label && matches!(data, BirthData::Ready(_)))
            }) {
                s.data
                    .claim_birth(birth.take().expect("a birth").1.into_ready());
            } else if r.label() & proto_fs::OWN != 0 && self.clones.client_of(r.label()).is_some() {
                // A Loader consumed this birth into a distinct label; surviving old copies
                // have cleanup authority only, regardless of a creator's retained handle.
                s.data.binding = Binding::Cleanup;
            }
            s.data.claimed = true;
            if s.data.closing && !s.data.permits_method(r.method()) {
                return status(proto_fs::PERMISSION);
            }
            // Admission into the session table is one bounded phase of its own.
            // It cannot share a receive with the Process Vouch round trip.
            if s.data.binding_preparation.is_some() && r.method() == Method::FinishBinding as u16 {
                return status(proto_fs::RESOLVING);
            }
        }
        #[cfg(feature = "full-capacity-probe")]
        if matches!(r.method(), 0xfff0..=0xfff2) {
            return self.capacity_request(&mut s.data, r);
        }
        #[cfg(feature = "open-finalize-clock-probe")]
        if r.method() == 0xfff6 {
            let mut body = r.body();
            let (Ok(action), Ok(slot), Ok(generation), Ok(job), Ok(())) = (
                body.u32(),
                body.u32(),
                body.u64(),
                body.u64(),
                body.finish(),
            ) else {
                return Answer::Status(Status::BadSize);
            };
            let key = proto_fs::OpenKey { slot, generation };
            if action > 1 || key.validate().is_err() || job == 0 {
                return Answer::Status(Status::BadSize);
            }
            if let Err(code) = self.authenticate(&mut s.data, r.label()) {
                return status(code);
            }
            let Some(stamp) = s.data.binding.stamp() else {
                return status(proto_fs::PERMISSION);
            };
            let matches = self.clock_gate.as_ref().is_some_and(|gate| {
                gate.owner == r.label() && gate.key == key && gate.job == job && gate.stamp == stamp
            });
            if action == 0 {
                if !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                if matches {
                    self.clock_gate = None;
                } else if self.clock_gate.is_some() {
                    return status(proto_fs::PERMISSION);
                }
                return Answer::Status(Status::Ok);
            }
            if matches && r.handles.is_empty() {
                return Answer::Status(Status::Ok);
            }
            if self.clock_gate.is_some() {
                return status(proto_fs::PERMISSION);
            }
            if r.handles.len() != 1
                || r.handles.info(0)
                    != Some((
                        rt::abi::ObjectKind::Channel,
                        Rights::SEND | Rights::TRANSFER,
                    ))
            {
                return Answer::Status(Status::BadSize);
            }
            let Ok(index) = self.path_slot(job, r.label()) else {
                return status(proto_fs::PERMISSION);
            };
            let paid = self.jobs[index].as_ref().expect("exact gated job");
            if paid.open_key != Some(key)
                || paid.authority != Some(stamp)
                || !s.data.resolvers.contains(&job)
                || paid.real
                || !paid.path().open.as_ref().is_some_and(|open| {
                    matches!(open.phase, OpenPhase::Prepared { .. })
                        && open.needs_time(&self.ram, &s.data) == Ok(true)
                })
            {
                return status(proto_fs::PERMISSION);
            }
            let Ok(channel) = r.handles.take::<Channel>(0) else {
                return Answer::Status(Status::BadSize);
            };
            self.clock_gate = Some(clock_page::ClockGate {
                closing: false,
                owner: r.label(),
                key,
                job,
                stamp,
                channel: Some(channel),
            });
            return Answer::Status(Status::Ok);
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
                s.data.closing = true;
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
                    Admission::Unvouched | Admission::Transport(_) => 1,
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
                        | Method::ResolveCancel
                        | Method::OpenCancel
                        | Method::DataCancel
                        | Method::DataAck
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
            Some(Method::Close | Method::CloseExact | Method::ResolveCancel)
        );
        if !cleanup && let Err(code) = self.authenticate(&mut s.data, r.label()) {
            return status(code);
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
                    proto_fs::Timestamp::legacy_ns(rt::time::ticks_to_ns(rt::time::now())),
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
                    proto_fs::Timestamp::legacy_ns(rt::time::ticks_to_ns(rt::time::now())),
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
                match self.ram.write_at(
                    &mut s.data,
                    fd,
                    bytes,
                    proto_fs::Timestamp::legacy_ns(rt::time::ticks_to_ns(rt::time::now())),
                ) {
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
                match self.ram.pwrite(
                    &mut s.data,
                    fd,
                    offset,
                    bytes,
                    proto_fs::Timestamp::legacy_ns(rt::time::ticks_to_ns(rt::time::now())),
                ) {
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
                let found = self.ram.directory_read_token(
                    token,
                    index,
                    identity,
                    proto_fs::Timestamp::legacy_ns(rt::time::ticks_to_ns(rt::time::now())),
                );
                self.cancel_job(job, r.label(), Some(&mut s.data));
                match found {
                    Ok(entry) => {
                        let (name, kind) = entry.map_or(("", 0), |entry| (entry.name, entry.kind));
                        let w = r.reply();
                        if w.u32(0)
                            .and_then(|()| w.u32(kind))
                            .and_then(|()| w.bytes(name.as_bytes()))
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
                match self.ram.directory_read(
                    &mut s.data,
                    fd,
                    proto_fs::Timestamp::legacy_ns(rt::time::ticks_to_ns(rt::time::now())),
                ) {
                    Ok(entry) => {
                        let entry = entry.map(|entry| proto_fs::DirectoryEntry {
                            name: entry.name.as_bytes(),
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
                | Method::DataReadResult,
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
    /// One retained transport owner settles before any admission reset.
    fn transport_drain_step(&mut self, fds: &mut Fds) -> bool {
        let Some(identity) = self
            .identities
            .get_mut(fds.authority_index as usize)
            .and_then(Option::as_mut)
        else {
            return false;
        };
        let Some(settled) = Self::transport_drain_identity(identity) else {
            return false;
        };
        if let Some(outcome) = settled
            && outcome != 0
        {
            self.begin_binding_failure(fds, outcome);
        }
        true
    }

    fn transport_drain_identity(identity: &mut IdentityChannel) -> Option<Option<u32>> {
        let Admission::Transport(transport) = &mut identity.admission else {
            return None;
        };
        let settled = transport.drain()?;
        let Some(outcome) = settled else {
            return Some(None);
        };
        identity.admission = Admission::Unvouched;
        Some(Some(outcome))
    }

    /// Duplicate and Send have distinct paid visits and distinct exact owners.
    fn notary_transport_step(&mut self, fds: &mut Fds, retained: bool) -> Result<bool, u32> {
        let Some(notary) = self.notary.as_ref() else {
            return Ok(false);
        };
        let identity = self.identities[fds.authority_index as usize]
            .as_mut()
            .expect("retained identity");
        let current = identity
            .original
            .snapshot_ref()
            .map_or(0, |who| generation(who.index as usize));
        let mut effects = NotaryCall {
            identity: &identity.channel,
            notary,
            original: &identity.original,
            retained,
        };
        ramfs::notary_transport::advance(&mut identity.admission, current, &mut effects)
    }

    /// Failure records CPU state; subsequent visits settle every rejected owner.
    fn begin_binding_failure(&mut self, fds: &mut Fds, code: u32) {
        let i = fds.authority_index as usize;
        let Some(identity) = self.identities.get_mut(i).and_then(Option::as_mut) else {
            fds.binding = Binding::Cleanup;
            fds.binding_outcome = Some(code);
            return;
        };
        if let Some(previous) = identity.previous.take() {
            let rejected = core::mem::replace(&mut identity.channel, previous);
            identity.admission = Admission::Transport(NotaryTransport {
                epoch: 0,
                state: NotaryState::Rollback {
                    rejected: Compact::from_owner(Some(rejected)),
                    outcome: code,
                },
            });
        } else {
            identity.closing = true;
            fds.closing = true;
            fds.binding = Binding::Cleanup;
            fds.binding_outcome = Some(code);
        }
    }

    fn binding_finish_step(&mut self, fds: &mut Fds) -> Option<u32> {
        let identity = self
            .identities
            .get_mut(fds.authority_index as usize)?
            .as_mut()?;
        let Admission::Transport(transport) = &mut identity.admission else {
            return None;
        };
        match ramfs::notary_transport::finish(
            transport,
            &mut identity.offered,
            &mut identity.previous,
        )? {
            ramfs::notary_transport::Finish::Pending => Some(proto_fs::RESOLVING),
            ramfs::notary_transport::Finish::Rollback(outcome) => {
                (fds.binding, fds.root) = (identity.original, identity.original_root);
                identity.pending = false;
                identity.require = false;
                identity.admission = Admission::Unvouched;
                self.ram.complete_binding(fds, outcome);
                Some(outcome)
            }
            ramfs::notary_transport::Finish::Commit => {
                identity.admission = Admission::Unvouched;
                self.ram.complete_binding(fds, 0);
                Some(0)
            }
        }
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
                .iter()
                .position(Option::is_none)
                .ok_or(proto_fs::TOO_MANY_OPEN_FILES)?
        } else {
            fds.authority_index as usize
        };
        assert!(
            self.identities[i]
                .as_ref()
                .is_none_or(|old| !matches!(old.admission, Admission::Transport(_))),
            "settled identity replacement"
        );
        assert!(
            self.identities[i]
                .as_ref()
                .is_none_or(|old| !old.offered.is_some()
                    && !old.previous.is_some()
                    && old.image.is_none()),
            "settled secondary identity owners"
        );
        let previous = self.identities[i].take().and_then(|old| {
            if retain_previous {
                Some(old.channel)
            } else {
                None
            }
        });
        self.identities[i] = Some(IdentityChannel {
            label,
            closing: false,
            channel: identity,
            offered: Compact::empty(),
            previous: Compact::from_owner(previous),
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
    fn drop_identity(&mut self, fds: &mut Fds) {
        Self::drop_identity_fields(&mut self.ram, self.identities, fds);
    }
    /// Disjoint fields allow a retained birth to release its authority in place.
    fn drop_identity_fields(
        ram: &mut Ram<'_>,
        identities: &mut [Option<IdentityChannel>; SESSIONS],
        fds: &mut Fds,
    ) {
        assert!(
            identities
                .get(fds.authority_index as usize)
                .and_then(Option::as_ref)
                .is_none_or(|identity| !matches!(identity.admission, Admission::Transport(_))),
            "settled identity disposal"
        );
        if let Some(root) = fds.binding_preparation.take() {
            ram.storage.release_preparation(root);
        }
        fds.binding_source = None;
        if fds.authority_index != NONE {
            identities[fds.authority_index as usize] = None;
            fds.authority_index = NONE;
        }
    }
    /// A rejected candidate restores the actual old capability and its binding.
    fn reject_binding(&mut self, fds: &mut Fds) -> u32 {
        self.fail_binding(fds, proto_fs::PERMISSION)
    }
    fn fail_binding(&mut self, fds: &mut Fds, code: u32) -> u32 {
        if let Some(identity) = self
            .identities
            .get_mut(fds.authority_index as usize)
            .and_then(Option::as_mut)
            && let Admission::Transport(transport) = &mut identity.admission
        {
            match &mut transport.state {
                NotaryState::Copy { outcome, .. }
                | NotaryState::Back { outcome, .. }
                | NotaryState::Reply { outcome, .. } => {
                    *outcome = code;
                    return code;
                }
                NotaryState::Rollback { outcome, .. } => return *outcome,
                NotaryState::Commit => return code,
            }
        }
        self.begin_binding_failure(fds, code);
        code
    }
    /// Test setup queues real storage reclamation before releasing a live
    /// prepared binding to the unchanged alternating maintenance cursor.
    #[cfg(feature = "auth-probe")]
    #[inline(always)]
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
        if self
            .identities
            .get(fds.authority_index as usize)
            .and_then(Option::as_ref)
            .is_some_and(|identity| matches!(identity.admission, Admission::Transport(_)))
        {
            if self.binding_finish_step(fds).is_none() {
                self.transport_drain_step(fds);
            }
            self.clone_wake = true;
            self.maintenance.remaining = SESSIONS + BIRTHS;
            return status(proto_fs::AUTHENTICATING);
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

    #[cfg(feature = "full-capacity-probe")]
    fn capacity_info<T>(&self, result: Result<T, abi::Error>) -> Result<T, abi::Error> {
        result.inspect_err(|&error| {
            let _ = rt::resource_meter::invalidate_for(&self.process, error);
        })
    }

    #[cfg(feature = "full-capacity-probe")]
    fn capacity_revoke_owner(&mut self, label: u64) {
        if self
            .capacity_retired_gate
            .is_some_and(|gate| gate.owner(label))
        {
            self.capacity_retired_gate = None;
        }
    }

    #[cfg(feature = "full-capacity-probe")]
    fn capacity_clear_owner(&mut self, label: u64) {
        if self
            .capacity_retired_gate
            .is_some_and(|gate| gate.owner(label))
        {
            self.capacity_retired_gate = None;
            self.clone_wake = true;
        }
    }
    #[inline(never)]
    #[cfg(feature = "full-capacity-probe")]
    fn capacity_request(&mut self, fds: &mut Fds, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() {
            if r.method() == 0xfff0 {
                self.capacity_clear_owner(r.label());
            }
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        let retired = if r.method() == 0xfff2 {
            let (Ok(action), Ok(slot), Ok(generation), Ok(job)) =
                (body.u32(), body.u32(), body.u64(), body.u64())
            else {
                return Answer::Status(Status::BadSize);
            };
            Some((action, proto_fs::OpenKey { slot, generation }, job))
        } else {
            None
        };
        let control = if r.method() == 0xfff1 {
            let (Ok(action), Ok(phase)) = (body.u32(), body.u32()) else {
                return Answer::Status(Status::BadSize);
            };
            Some((action, phase))
        } else {
            None
        };
        if body.finish().is_err() {
            if r.method() == 0xfff0 {
                self.capacity_clear_owner(r.label());
            }
            return Answer::Status(Status::BadSize);
        }
        if let Err(code) = self.authenticate(fds, r.label()) {
            self.capacity_clear_owner(r.label());
            return status(code);
        }
        let Binding::Active(who) = &fds.binding else {
            self.capacity_clear_owner(r.label());
            return status(proto_fs::PERMISSION);
        };
        let root = Root {
            id: u64::from(who.root.pid),
            generation: u64::from(who.root.generation),
        };
        if root != fds.root {
            self.capacity_clear_owner(r.label());
            return status(proto_fs::PERMISSION);
        }
        let (pid, image) = (who.pid, who.image);
        if let Some((action, key, job)) = retired {
            if action == 1 {
                if !self
                    .capacity_retired_gate
                    .is_some_and(|gate| gate.exact(r.label(), pid, image, root, key, job))
                {
                    return status(proto_fs::PERMISSION);
                }
                self.capacity_clear_owner(r.label());
                return Answer::Status(Status::Ok);
            }
            if action != 0 {
                return status(proto_fs::INVALID_ARGUMENT);
            }
            if let Some(gate) = self.capacity_retired_gate {
                return if gate.exact(r.label(), pid, image, root, key, job) {
                    Answer::Status(Status::Ok)
                } else {
                    status(proto_fs::INVALID_ARGUMENT)
                };
            }
            if !self
                .capacity_checkpoints
                .0
                .iter()
                .any(|c| c.root == root && c.pid == pid && c.image == image && c.phase == 4)
            {
                return status(proto_fs::PERMISSION);
            }
            let valid=self.jobs.iter().flatten().any(|record| {
                record.id==job && record.owner==r.label() && record.open_key==Some(key) && !record.abandoned
                    && fds.resolvers.contains(&job) && record.authority==fds.binding.stamp()
                    && matches!(&record.operation, JobOperation::Data(data) if data.args.kind==proto_fs::DataKind::Truncate
                        && data.outcome(job).phase==proto_fs::DataPhase::Ready && data.outcome(job).result==proto_fs::DataResult::None)
            });
            if !valid {
                return status(proto_fs::PERMISSION);
            }
            let gate =
                match ramfs::capacity::RetiredGate::new(r.label(), pid, image, root, key, job) {
                    Ok(gate) => gate,
                    Err(code) => return status(code),
                };
            self.capacity_retired_gate = Some(gate);
            return Answer::Status(Status::Ok);
        }
        if let Some((action, phase)) = control {
            if action == 1 && phase == 0 {
                let own =
                    self.capacity_checkpoints.0.iter().any(|c| {
                        c.root == root && c.pid == pid && c.image == image && c.phase == 1
                    });
                if !own
                    || !self.capacity_checkpoints.both(1)
                    || self.jobs.iter().any(Option::is_some)
                    || self.ram.storage.preparations_used() != 0
                    || self.ram.storage.available().pages as usize != ramfs::storage::PAGES
                    || self.ram.storage.reclamation_pending()
                    || !ramfs::capacity::warm_metadata_idle(
                        self.births.iter().all(Option::is_none),
                        self.places.has_issued(),
                        self.clones.is_empty(),
                        self.identities.iter().flatten().all(|identity| {
                            ramfs::capacity::warm_identity_idle(
                                identity.label,
                                identity.pending,
                                identity.offered.is_some(),
                                identity.previous.is_some(),
                                identity.image.is_some(),
                            )
                        }),
                        self.orphan_count,
                    )
                {
                    return status(proto_fs::INVALID_ARGUMENT);
                }
                return match rt::resource_meter::warm_for(&self.process) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(error) => Answer::Status(Status::Kernel(error)),
                };
            }
            if action != 0 {
                return status(proto_fs::INVALID_ARGUMENT);
            }
            // An invalid observation refuses the phase before either card changes.
            let snapshot = match rt::resource_meter::snapshot_for(&self.process) {
                Ok(snapshot) => snapshot,
                Err(error) => return Answer::Status(Status::Kernel(error)),
            };
            let handles = match self.capacity_info(sys::process_handles(&self.process)) {
                Ok(handles) => handles,
                Err(error) => return Answer::Status(Status::Kernel(error)),
            };
            let changed = match self.capacity_checkpoints.advance(root, pid, image, phase) {
                Ok(changed) => changed,
                Err(code) => return status(code),
            };
            if changed && self.capacity_checkpoints.both(5) {
                let [a, b] = self.capacity_checkpoints.0;
                rt::println!(
                    "ramfs-capacity: final roots={}:{} pid={} image={} phase={} / {}:{} pid={} image={} phase={} startup={} warm={} memory_peak={} handles_peak={} handles_limit={} attempts={} failures={}",
                    a.root.id,
                    a.root.generation,
                    a.pid,
                    a.image,
                    a.phase,
                    b.root.id,
                    b.root.generation,
                    b.pid,
                    b.image,
                    b.phase,
                    snapshot.startup,
                    snapshot.warm,
                    snapshot.peak,
                    snapshot.handle_peak,
                    handles.limit,
                    snapshot.attempts,
                    snapshot.failures
                );
            }
            return Answer::Status(Status::Ok);
        }
        let meter = match rt::resource_meter::snapshot_for(&self.process) {
            Ok(meter) => meter,
            Err(error) => {
                self.capacity_clear_owner(r.label());
                return Answer::Status(Status::Kernel(error));
            }
        };
        let memory = match self.capacity_info(sys::process_memory(&self.process)) {
            Ok(memory) => memory,
            Err(error) => {
                self.capacity_clear_owner(r.label());
                return Answer::Status(Status::Kernel(error));
            }
        };
        let handles = match self.capacity_info(sys::process_handles(&self.process)) {
            Ok(handles) => handles,
            Err(error) => {
                self.capacity_clear_owner(r.label());
                return Answer::Status(Status::Kernel(error));
            }
        };
        let backing = match self.capacity_info(sys::memory_info(&self.capacity_backing)) {
            Ok(backing) => backing,
            Err(error) => {
                self.capacity_clear_owner(r.label());
                return Answer::Status(Status::Kernel(error));
            }
        };
        let available = self.ram.storage.available();
        let usage = self.ram.storage.usage(root);
        let jobs = self.jobs.iter().filter(|job| job.is_some()).count() as u32;
        let output = r.reply();
        let result = (|| -> Result<(), Status> {
            for word in [0, 3, pid, image] {
                output.u32(word)?;
            }
            for word in [root.id, root.generation] {
                output.u64(word)?;
            }
            for word in memory.to_words() {
                output.u64(word)?;
            }
            for word in [
                meter.startup,
                meter.warm,
                meter.peak,
                meter.attempts,
                meter.failures,
            ] {
                output.u64(word)?;
            }
            for word in handles.to_words() {
                output.u64(word)?;
            }
            for word in backing.to_words() {
                output.u64(word)?;
            }
            for word in [
                available.inodes as u32,
                available.dentries as u32,
                available.pages as u32,
                u32::from(self.ram.storage.reclamation_pending()),
                usage.inodes as u32,
                usage.dentries as u32,
                usage.pages as u32,
                usage.descriptions as u32,
                jobs,
                self.ram.storage.preparations_used() as u32,
                self.ram.storage.preparations_for_root(root) as u32,
                self.capacity_checkpoints.phase_pack(root),
            ] {
                output.u32(word)?;
            }
            if output.as_bytes().len() != 192 {
                return Err(Status::BadSize);
            }
            Ok(())
        })();
        if self
            .capacity_retired_gate
            .is_some_and(|gate| gate.observed(r.label(), pid, image, root))
        {
            // Capture actual charge/free counters before resuming the real GC.
            self.capacity_clear_owner(r.label());
        } else if result.is_err() {
            self.capacity_clear_owner(r.label());
        }
        match result {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(error) => Answer::Status(error),
        }
    }

    fn authenticate(&mut self, fds: &mut Fds, label: u64) -> Result<(), u32> {
        Self::authenticate_fields(&mut self.ram, self.identities, fds, label)
    }
    fn authenticate_fields(
        ram: &mut Ram<'_>,
        identities: &mut [Option<IdentityChannel>; SESSIONS],
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
        if fds.binding.awaits_child_identity() {
            return Err(proto_fs::PERMISSION);
        }
        let who = fds.binding.snapshot_ref().ok_or(proto_fs::PERMISSION)?;
        let current = generation(who.index as usize);
        if fds.binding.authenticate_epoch(current)? {
            return Ok(());
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
        if matches!(identity.admission, Admission::Transport(_)) {
            return Err(proto_fs::AUTHENTICATING);
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
        let Some(i) = self
            .births
            .iter()
            .position(|b| b.as_ref().is_some_and(|(l, _)| *l == label))
        else {
            return status(proto_fs::PERMISSION);
        };
        let (_, child) = self.births[i].take().expect("own clone");
        let mut child = child.into_ready();
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
        self.births[i] = Some((label, BirthData::Ready(child)));
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
        let Some(slot) = self.births.iter().position(Option::is_none) else {
            return status(proto_fs::TOO_MANY_OPEN_FILES);
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
        binding.offered = Compact::from_owner(offered);
        binding.pending = true;
        binding.require = require;
        self.births[slot] = Some((label, BirthData::Ready(child)));
        let _ = self.clones.add_within(label, r.label(), CLONES);
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
    #[inline(always)]
    fn audit_step(&mut self, fds: &mut Fds, label: u64) -> bool {
        if fds.binding.awaits_child_identity() {
            return false;
        }
        let Some(who) = fds.binding.snapshot_ref() else {
            return false;
        };
        let current = generation(who.index as usize);
        let i = fds.authority_index as usize;
        if let Some(result) = self.binding_finish_step(fds) {
            let _ = result;
            return true;
        }
        if let Some(identity) = self.identities.get(i).and_then(Option::as_ref)
            && let Admission::Transport(transport) = &identity.admission
        {
            if transport.epoch != current || current & proto_process::GENERATION_DEAD != 0 {
                self.transport_drain_step(fds);
                return true;
            }
            let retained = matches!(identity.original, Binding::Pending(_) | Binding::Handoff(_));
            return match self.notary_transport_step(fds, retained) {
                Ok(advanced) => advanced,
                Err(code) => {
                    self.fail_binding(fds, code);
                    true
                }
            };
        }
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
        let step = if matches!(
            identity.admission,
            Admission::Unvouched | Admission::Transport(_)
        ) {
            let retained = matches!(identity.original, Binding::Pending(_) | Binding::Handoff(_));
            if self.generations.is_none() {
                let _ = self.notary_register();
                return false;
            }
            match self.notary_transport_step(fds, retained) {
                Ok(true) => AuditStep::Advance,
                Ok(false) => AuditStep::Retry,
                Err(code) => {
                    self.fail_binding(fds, code);
                    return true;
                }
            }
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
        self.binding_phase(fds, label, &mut true, None)
    }
    fn binding_phase(
        &mut self,
        fds: &mut Fds,
        label: u64,
        progress: &mut bool,
        protected: Option<u64>,
    ) -> u32 {
        *progress = true;
        if let Some(result) = self.binding_finish_step(fds) {
            return result;
        }
        let i = fds.authority_index as usize;
        let Some(binding) = self.identities.get(i).and_then(Option::as_ref) else {
            return self.reject_binding(fds);
        };
        if binding.label != label {
            return self.reject_binding(fds);
        }
        if matches!(
            binding.admission,
            Admission::Unvouched | Admission::Transport(_)
        ) {
            if self.generations.is_none() {
                return if self.notary_register() {
                    proto_fs::RESOLVING
                } else {
                    self.reject_binding(fds)
                };
            }
            let retained = binding.purpose == BindingPurpose::Refresh
                && matches!(binding.original, Binding::Pending(_) | Binding::Handoff(_));
            return match self.notary_transport_step(fds, retained) {
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
                    .with_view(|offered| sys::copy_label(&self.channel, offered).ok())
                    .flatten();
                let original = offered_label.and_then(|label| {
                    self.births
                        .iter()
                        .position(|b| b.as_ref().is_some_and(|(l, _)| *l == label))
                });
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
            if ramfs::maintenance::source_protected(
                label,
                protected,
                self.into_window.as_ref().map(|window| window.owner),
            ) {
                *progress = false;
                return proto_fs::RESOLVING;
            }
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
            let source_phase = match ramfs::authority::inherited_source_phase(
                source.binding,
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
                        Self::authenticate_fields(&mut self.ram, self.identities, source, label);
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
            if Self::identity_close_fields(self.identities, source) {
                return proto_fs::RESOLVING;
            }
            if let Some(root) = source.binding_preparation.take() {
                self.ram.storage.release_preparation(root);
            }
            source.binding_source = None;
            source.binding = bound;
            source.authority_index = fds.authority_index;
            source.claimed = true;
            source.binding_preparation = fds.binding_preparation.take();
            source.binding_source = None;
            core::mem::swap(fds, &mut **source);
            self.births[slot as usize] = None;
        }
        let binding = self.identities[fds.authority_index as usize]
            .as_mut()
            .unwrap();
        binding.admission = Admission::Transport(NotaryTransport {
            epoch: 0,
            state: NotaryState::Commit,
        });
        fds.binding_outcome = None;
        proto_fs::RESOLVING
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
            let Some(slot) = self.jobs.iter().position(Option::is_none) else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let Some(generation) = self.job_generations[slot]
                .checked_add(1)
                .filter(|&generation| generation < 1 << 56)
            else {
                return status(proto_fs::TOO_MANY_OPEN_FILES);
            };
            let charge = match self.ram.storage.charge_preparation(fds.root) {
                Ok(charge) => charge,
                Err(code) => return status(code),
            };
            let data = match ramfs::data::Journal::capture(&mut self.ram, fds, args) {
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
                retiring: false,
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
        if job.retiring
            && !matches!(
                method,
                Method::DataQuery | Method::DataAck | Method::DataCancel
            )
        {
            return status(proto_fs::OPEN_RETIRED);
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
        if !fds.closing
            && let Err(code) = self.authenticate(fds, r.label())
        {
            return status(code);
        }
        let job = self.jobs[slot].as_mut().expect("owned data job");
        if !fds.closing
            && job.authority.map(|stamp| stamp.image)
                != fds.binding.stamp().map(|stamp| stamp.image)
        {
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
            Method::DataStep => match data.step(&mut self.ram) {
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
                #[cfg(feature = "full-capacity-probe")]
                let before = data.outcome(id);
                if let Err(code) = data.commit(&mut self.ram, now) {
                    return status(code);
                }
                #[cfg(feature = "full-capacity-probe")]
                if let (Some(gate), Some(key)) = (&mut self.capacity_retired_gate, job.open_key) {
                    gate.committed(r.label(), key, before, data.outcome(id));
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
        if self.jobs[slot].as_ref().is_some_and(|job| job.retiring) {
            return Err(proto_fs::OPEN_RETIRED);
        }
        if !matches!(
            self.jobs[slot].as_ref().expect("exact job").operation,
            JobOperation::Path(_)
        ) {
            return Err(proto_fs::PERMISSION);
        }
        Ok(slot)
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
        #[cfg(feature = "full-capacity-probe")]
        if self
            .capacity_retired_gate
            .is_some_and(|gate| gate.canceled_armed(owner, id))
        {
            self.capacity_clear_owner(owner);
        }
        if retire && let Ok(i) = self.job_slot(id, owner) {
            let job = self.jobs[i].as_mut().expect("exact retiring job");
            if !job.retiring {
                job.retiring = true;
                self.maintenance.remaining = SESSIONS + BIRTHS;
                self.clone_wake = true;
            }
        }
        if let Some(fds) = fds.as_deref_mut()
            && !fds.closing
            && fds.image_outcome.is_some_and(|outcome| outcome.job == id)
        {
            let outcome = fds.image_outcome.unwrap();
            if outcome.phase == ramfs::image::ImagePhase::Ready {
                fds.image_outcome = Some(ramfs::image::ImageOutcome {
                    phase: ramfs::image::ImagePhase::Retired,
                    ..outcome
                });
            }
            if !self.clear_image_outcome_step(fds) {
                return false;
            }
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
            if let Some(ResolveJob {
                operation: JobOperation::Data(data),
                ..
            }) = self.jobs[i].as_mut()
                && !data.cleanup_done()
            {
                data.cancel_step(&mut self.ram)
                    .expect("exact data job cleanup");
                return false;
            }
            if !retire {
                return true;
            }
            let j = self.jobs[i].as_mut().expect("owned canceled job");
            if let JobOperation::Path(path) = &mut j.operation {
                if let Some(open) = path.open.as_mut()
                    && !matches!(open.phase, OpenPhase::Canceled { .. })
                {
                    let fds = fds
                        .as_deref_mut()
                        .expect("open job retains its owning session");
                    if !open
                        .cancel_step(&mut self.ram, fds, &mut j.root)
                        .expect("exact open cleanup")
                    {
                        return false;
                    }
                    return false;
                }
                if !path.resolver.release_step(&mut self.ram.storage) {
                    return false;
                }
                if let Some(second) = path.second.as_mut() {
                    if !second.release_step(&mut self.ram.storage) {
                        return false;
                    }
                    path.second = None;
                    return false;
                }
            }
            if j.root != NONE {
                self.ram.storage.release_preparation(j.root);
                j.root = NONE;
                return false;
            }
            let j = self.jobs[i].take().expect("settled canceled job");
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
                if !fds.closing
                    && let Err(code) = self.authenticate(fds, r.label())
                {
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
            if !fds.closing
                && let Err(code) = self.authenticate(fds, r.label())
            {
                return status(code);
            }
            let j = self.jobs[i].as_ref().expect("retained query job");
            if !fds.resolvers.contains(&id)
                || j.real
                || j.path().second.is_some()
                || (!fds.closing
                    && j.authority.map(|stamp| stamp.image)
                        != fds.binding.stamp().map(|stamp| stamp.image))
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
                    let now = match open.needs_time(&self.ram, fds) {
                        Ok(false) => proto_fs::Timestamp::ZERO,
                        Ok(true) => {
                            #[cfg(feature = "open-finalize-clock-probe")]
                            let sample = {
                                let gate = if self.clock_gate.as_ref().is_some_and(|gate| {
                                    gate.owner == r.label()
                                        && gate.key == key
                                        && gate.job == id
                                        && Some(gate.stamp) == fds.binding.stamp()
                                }) {
                                    self.clock_gate.take()
                                } else {
                                    None
                                };
                                self.time_source.read_gated(gate)
                            };
                            #[cfg(not(feature = "open-finalize-clock-probe"))]
                            let sample = self.time_source.read_once();
                            match sample {
                                Ok(Some(now)) => now,
                                Ok(None) => return status(proto_fs::TIME_DEFERRED),
                                Err(error) => return Answer::Status(error),
                            }
                        }
                        Err(code) => return status(code),
                    };
                    if let Err(code) =
                        open.commit(&mut self.ram, fds, Some(proof), identity, &mut j.root, now)
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
                    JobOperation::Data(_)
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
            let base = Token {
                slot: match u16::try_from(slot) {
                    Ok(s) => s,
                    Err(_) => NONE,
                },
                generation,
            };
            if path.first() != Some(&b'/') && !self.ram.owns_directory_base(fds, base) {
                self.ram.storage.release_preparation(charge);
                return status(proto_fs::BAD_FD);
            }
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
                retiring: false,
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
            let base = Token {
                slot: u16::try_from(slot).unwrap_or(NONE),
                generation,
            };
            if path.first() != Some(&b'/') && !self.ram.owns_directory_base(fds, base) {
                return status(proto_fs::BAD_FD);
            }
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
                && let Err(code) = open.reset_unpublished(&mut self.ram, fds, &mut j.root)
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
                &mut self.ram,
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
        let now = rt::time::ticks_to_ns(rt::time::now());
        match open.commit(
            &mut self.ram,
            fds,
            proof,
            identity,
            &mut j.root,
            proto_fs::Timestamp::legacy_ns(now),
        ) {
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

impl Fs {
    fn cursor_maintenance(
        &mut self,
        sessions: &mut [Option<Session<Fds, 0>>],
        notice: rt::service::Notice,
        protected: Option<u64>,
    ) {
        if notice.source != rt::abi::Source::Unlabeled || notice.label != 0 {
            self.clone_wake = true;
            return;
        }
        rt::service::step_own();
        let now = rt::time::ticks_to_ns(rt::time::now());
        if now >= self.next_audit_ns && self.maintenance.remaining == 0 {
            self.next_audit_ns = now.saturating_add(250_000_000);
            self.maintenance.remaining = SESSIONS + BIRTHS - 1;
        }
        let mut work = false;
        self.maintenance_jobs = !self.maintenance_jobs;
        if self.maintenance_jobs {
            self.data_gc_turn = !self.data_gc_turn;
            if self.data_gc_turn && (self.orphan_count != 0 || self.into_window.is_some()) {
                let slot = ramfs::maintenance::debt_turn(
                    &mut self.orphan_cursor,
                    ramfs::storage::PREPARATIONS,
                );
                if slot == ramfs::storage::PREPARATIONS {
                    if self
                        .into_window
                        .as_ref()
                        .is_some_and(|window| Some(window.owner) != protected)
                    {
                        self.window_cleanup_step();
                    }
                    work = true;
                } else if let Some(job) = self.jobs[slot].as_ref().filter(|job| job.abandoned) {
                    let (id, owner) = (job.id, job.owner);
                    self.cancel_job(id, owner, None);
                    work = true;
                }
            } else {
                #[cfg(feature = "full-capacity-probe")]
                let paused = self.capacity_retired_gate.is_some_and(|gate| gate.paused());
                #[cfg(not(feature = "full-capacity-probe"))]
                let paused = false;
                if !paused {
                    work = self.ram.storage.reclaim_step();
                }
            }
            if work
                || self.maintenance.remaining != 0
                || self.orphan_count != 0
                || self.into_window.is_some()
            {
                self.clone_wake = true;
            }
            return;
        }
        let mut client_work = false;
        let mut closing_visit = false;
        let i = self.maintenance.position;
        if i < SESSIONS {
            if let Some(s) = sessions.get_mut(i).and_then(Option::as_mut)
                && Some(s.label()) != protected
            {
                let label = s.label();
                client_work = self.cleanup_step(&mut s.data, label, protected);
                closing_visit = s.data.closing;
                if s.data.closing && self.closed_terminal(&s.data, label) {
                    self.places.release(label);
                    self.clones.gone(label);
                    sessions[i] = None;
                }
            }
        } else if self.births[i - SESSIONS]
            .as_ref()
            .is_some_and(|(_, data)| matches!(data, BirthData::Cloning(_)))
        {
            self.clone_birth_step(i - SESSIONS);
            self.maintenance.complete_clone(SESSIONS + BIRTHS);
            self.clone_wake = true;
            return;
        } else if self.births[i - SESSIONS]
            .as_ref()
            .is_some_and(|(label, _)| Some(*label) == protected)
        {
            // Preserve only this exact current image context.
        } else if let Some((label, data)) = self.births[i - SESSIONS].take() {
            let mut fds = data.into_ready();
            client_work = self.cleanup_step(&mut fds, label, protected);
            closing_visit = fds.closing;
            if fds.closing && self.closed_terminal(&fds, label) {
                self.places.release(label);
                self.clones.gone(label);
            } else {
                self.births[i - SESSIONS] = Some((label, BirthData::Ready(fds)));
            }
        }
        work |= client_work;
        self.maintenance
            .complete_client(client_work, closing_visit, SESSIONS + BIRTHS);
        // A maintenance notification makes reclamation progress with no client request.
        if work
            || self.maintenance.remaining != 0
            || self.orphan_count != 0
            || self.into_window.is_some()
        {
            self.clone_wake = true;
        }
    }
}

impl Fs {
    fn read_into_step(&mut self, request: &mut Request<'_>) -> rt::service::TailProgress {
        request
            .with_loan(|request, words| self.read_into_loan(request, words))
            .unwrap_or(rt::service::TailProgress::Idle)
    }

    fn read_into_loan(
        &mut self,
        request: &mut Request<'_>,
        words: &mut [u64; 11],
    ) -> rt::service::TailProgress {
        use ramfs::read_into::{Loan, Progress};
        let mut loan = Loan::new(words);
        rt::service::step_detail(16 + loan.phase() as u64);
        let mut effects = IntoEffects { fs: self, request };
        match loan.step(&mut effects) {
            Progress::Idle => rt::service::TailProgress::Idle,
            Progress::Continue => rt::service::TailProgress::Continue,
            Progress::Finish { code, count } => {
                let writer = effects.request.reply();
                writer
                    .u32(code)
                    .and_then(|()| writer.u32(count))
                    .expect("bounded reply bytes");
                rt::service::TailProgress::Idle
            }
        }
    }
}

struct IntoEffects<'a, 'b> {
    fs: &'a mut Fs,
    request: &'a mut Request<'b>,
}
impl ramfs::read_into::Effects for IntoEffects<'_, '_> {
    fn info(&mut self) -> u64 {
        self.request
            .handles
            .with_view::<Memory, _>(0, sys::memory_info)
            .ok()
            .and_then(Result::ok)
            .map_or(0, |info| info.size)
    }
    fn incoming(&self) -> usize {
        self.request.handles.len()
    }
    fn busy(&self) -> bool {
        self.fs.into_window.is_some()
    }
    fn admit(&mut self, count: usize) {
        let memory = self
            .request
            .handles
            .take::<Memory>(0)
            .expect("checked incoming memory");
        self.fs.into_window = Some(IntoWindow {
            owner: self.request.label(),
            memory: Some(memory),
            length: (count as u64).next_multiple_of(4096),
            mapped: false,
        });
    }
    fn map(&mut self, at: u64) -> Result<(), (u32, bool)> {
        let window = self.fs.into_window.as_mut().expect("current window owner");
        assert_eq!(window.owner, self.request.label());
        match sys::mem_map(
            &self.fs.process,
            window.memory.as_ref().expect("owned memory"),
            at,
            window.length,
            INTO,
            Access::ReadWrite,
        ) {
            Ok(()) => {
                window.mapped = true;
                Ok(())
            }
            Err(error) => {
                window.mapped = matches!(error, abi::Error::Unknown(_));
                Err((Status::Kernel(error).code(), window.mapped))
            }
        }
    }
    fn copy(
        &mut self,
        image: ramfs::image::ImageHold,
        offset: u64,
        copied: usize,
        remaining: usize,
    ) -> Result<(usize, usize), u32> {
        let count = self
            .fs
            .ram
            .storage
            .read_chunk(image.token, offset, remaining)?;
        // SAFETY: only the current loan accesses its exact mapped INTO window.
        // count is bounded by remaining and source physical and logical pages.
        let out = unsafe { core::slice::from_raw_parts_mut((INTO as *mut u8).add(copied), count) };
        self.fs
            .ram
            .storage
            .read(image.token, offset, out)
            .map(|n| (n, count))
    }
    fn unmap(&mut self) -> Result<(), u32> {
        let window = self.fs.into_window.as_mut().expect("current mapped owner");
        // SAFETY: the exact singleton mapping stays owned until this call succeeds.
        unsafe { sys::mem_unmap(&self.fs.process, INTO, window.length) }
            .map(|()| window.mapped = false)
            .map_err(|error| Status::Kernel(error).code())
    }
    fn close(&mut self) -> bool {
        let window = self.fs.into_window.as_mut().expect("current memory owner");
        if Handle::close_retained(&mut window.memory).is_err() {
            return false;
        }
        assert!(!window.mapped);
        self.fs.into_window = None;
        true
    }
    fn wake_due(&mut self) {
        self.fs.clone_wake = true;
    }
}
