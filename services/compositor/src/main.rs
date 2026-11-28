// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The composition service of stafeto (spec 3 and the design of graphics,
//! stage 1): the one client of the display driver (services/virtio-gpu) and
//! the display service its own clients see. A client makes windows,
//! draws in buffers of its own memory and posts them (proto_comp); the
//! service puts the windows into the screen's buffer, which only it maps,
//! and tells the driver to show the changed rectangle (COMMIT of proto_gpu's
//! second revision, which answers at once; the end comes as a bit). A
//! program of the first revision, which knows only OPEN and FLUSH, gets a
//! window of the whole screen whose buffer is the driver's pool source
//! (proto_gpu revision 3), so that Doom runs here as it runs on the driver.
//! While that window covers the whole screen with nothing above it, and the
//! pointer is not in the frame, the service puts nothing together: it binds
//! the pool to the primary pipeline (LAYERS) and the display shows the
//! window's buffer as it is (the direct frame, `Scene::plan`).
//!
//! The service never waits for a client or for the device inside a step.
//! A frame is taken at its start (the posted buffer of every window), made
//! in bands of a few lines, a step each, which the service's own bit
//! starts one after another (the requests of the clients pass between
//! them), committed to the driver, and finished by the driver's bit; the
//! replies a FLUSH waits for and the notices that a buffer is free go out
//! then. A window goes when its session or its context's session closes:
//! the end of a process frees its windows, and their places on the screen
//! are painted over in the next frame.
//!
//! The service is the driver's client by init's table (`connects` has
//! `display`) and the input services': the keyboard's (`input`) and the
//! pointer's (`pointer`, a virtio-tablet), whose focus it holds for itself
//! (GRANT with a channel of its own, so that a bit tells it when events
//! wait) and routes to the windows (stage G2: the window with the focus
//! gets the keys, the one under the pointer the pointer, a click moves the
//! focus). The keyboard's focus stays the compositor's: the program that
//! holds the window of the first revision reads its keys from a session of
//! focus the compositor itself serves (READ of proto_input), which holds the
//! keys of the window's ring, so they reach it while the window has the focus
//! and no other time. A manager (a program the
//! table gives a session marked MANAGER_MARK) moves, raises and hides the
//! windows and gives one the focus; a session marked INPUT_MARK injects
//! events as a device would. The pointer's picture is the display's cursor
//! when the driver has a cursor pipeline (proto_gpu revision 3): the service
//! draws the arrow into the cursor source once at the opening of the screen
//! and sends one LAYERS per step of input that moved the pointer, never
//! inside a frame. It ends with a code of its own when the driver
//! goes (every session it gave is dead then); init starts it again.

#![no_std]
#![no_main]

use abi::{Access, Error, MESSAGE_MAX, Rights, Source};
use compositor::frame::{self, Fire, Pacer, Wake};
use compositor::mapping::{self, CHUNK, Pick, Wait};
use compositor::prep::{self, Pass, Reads, Table};
use compositor::{
    Band, Format, FrameKind, MAX_WINDOWS, Refusal, SCREEN, Scene, ScreenAsk, ScreenPhase,
    Source as PixelSource, compose_planned,
};
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::slice;
use core::sync::atomic::{AtomicU64, Ordering};
use proto_comp::{
    Attach, BUFFER_MAX, COMMITTED_BIT, COMPOSED_BIT, Create, Description, EVENTS_BIT, Event,
    FOCUSED, INPUT_MARK, MANAGER_MARK, MAX_EVENTS, Method as Comp, NO_WINDOW, Post, RESET, Rect,
    SCENE_MARK, SHOWN, STATS_WINDOWS, SetBody, SetText, Size, StatsReply, WindowRecord,
    WindowStats, manage, read_scene_compose, read_stats_request,
};
use proto_gpu::{
    BUFFER_BYTES, BUSY, CLEARING, FORMATS_ARGB8888, FORMATS_XRGB8888, FRAME_FAILED, FRAME_SHOWN,
    HEIGHT, IO, KIND_CURSOR, KIND_PRIMARY, LayerRow, Layers, Method as Gpu, NO_DEVICE, NO_INPUT,
    NOT_ALLOWED, PIPELINE_FULL_SCREEN, Pipeline, Pipelines, SCREEN_BYTES, SOURCE_KIND_CURSOR,
    SOURCE_KIND_POOL, SOURCE_POOL, SOURCE_TARGET, Screen, SourceInfo, VERSION, WIDTH, code,
};
use proto_init::ServiceArgs;
use proto_input::{ABS_MAX, ABS_X, ABS_Y, EV_ABS, EV_KEY, Method as InputMethod};
use proto_wire::clones::Clones;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Memory, Outgoing, Process, Thread, Timer};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::wait::Waiter;
use rt::{Handle, sys};

mod px;

rt::entry!(main);

/// Where the service maps the screen's buffer, and the buffers of the
/// windows (each place of a window has three spans of BUFFER_MAX).
const FB_AT: usize = 0x10_0100_0000;
const BUF_AT: usize = 0x11_0000_0000;
/// Where the service maps the pool (source 2 of the driver), the buffer of
/// the window of the first revision, for reading and writing, for its whole
/// life. The mapping covers the 250 pages the source describes (POOL_LEN) of
/// the object's 256, so it ends at 0x12_000F_A000 and the
/// six pages up to CURSOR_AT stay unmapped: a guard gap between the two
/// objects. Both lie in the 2 MiB span 0x12_0000_0000 to 0x12_0020_0000, one
/// page table, the one the service's own buffer of the first revision used
/// to need, so the gap and the cursor's four pages cost no page-table page.
const POOL_AT: usize = 0x12_0000_0000;
// The buffers of every window (48 MiB at 16 windows) end before the pool.
// STATS and LIST have a record for every window.
const _: () = assert!(proto_comp::STATS_WINDOWS >= MAX_WINDOWS);
const _: () = assert!(BUF_AT + MAX_WINDOWS * proto_comp::BUFFERS * BUFFER_MAX as usize <= POOL_AT);
/// Where the service maps the cursor's picture (source 3 of the driver),
/// past the pool inside the same 2 MiB span.
const CURSOR_AT: usize = 0x12_0010_0000;
// The pool's mapping ends before the cursor's with a gap of at least a page.
const _: () = assert!(POOL_AT + POOL_LEN + PAGE <= CURSOR_AT);
const PAGE: usize = 4096;
/// The pages of the driver's frame buffer.
const BUFFER_PAGES: usize = BUFFER_BYTES as usize / PAGE;
/// The tries and the pause of the first OPEN of the driver.
const OPEN_TRIES: u32 = 150;
const OPEN_PAUSE_NS: u64 = 5_000_000;
/// The bytes of the pool the service maps: the screen's, 250 pages.
const POOL_LEN: usize = SCREEN_BYTES as usize;
/// The bytes of it one step clears.
const CLEARED: usize = 16 * 1024;
/// The sessions of the service's channel: the contexts, the windows, and
/// the clones' places, with room.
const SESSIONS: usize = 96;
/// The clones the service keeps alive at most, for all its clients.
const CLONES: usize = 64;
/// The marks of labels: a clone's (bit 63, as the driver has them), a
/// window's (bit 62), and the label of the handle the driver notifies
/// through (bit 61).
const OWN: u64 = 1 << 63;
const WINDOW: u64 = 1 << 62;
const DRIVER: u64 = 1 << 61;
/// Init's marks (proto_comp: MANAGER_MARK is bit 60, INPUT_MARK bit 59) and
/// the labels of the handles the input services notify through (bits 58
/// and 57). Init's labels are counts, far under these bits.
const KEYS: u64 = 1 << 58;
const POINTER: u64 = 1 << 57;
/// The mark of the session of keyboard focus of a window of the first
/// revision: the label of the window and this bit. The service serves its
/// READ (proto_input) from the window's ring, so the keys follow the focus.
const WINDOW_KEYS: u64 = 1 << 56;
/// The label of the handle the frame's timer is made through: no session has it
/// (its marks are bits 56 to 63, the devices' labels bits 57 and 58).
const TIMER_LABEL: u64 = 1 << 55;
/// The low bits of a device's label: the generation of the grant.
const GENERATION: u64 = 0xFFFF;
/// The service's own bits: the next band of the frame is due, a chunk of
/// mapping, unmapping or clearing is, and more events wait at an input
/// service.
const BAND: u64 = 1;
const WORK: u64 = 2;
const INPUT: u64 = 4;
/// The timer is to be armed for the start the bands put off by the cap wait
/// for: a step of its own, so that the kernel call is not in the step of the
/// band that reached the cap.
const ARM: u64 = 8;
/// The worker has let go of what it held, or drew something: the free of buffers
/// that waited for it, the unmapping of windows, the images it published.
const PREP: u64 = 16;
/// The mapper thread did its order (`rt::mapper`).
const MAPPED: u64 = 32;
/// The events one READ of an input service asks for.
const READ_MAX: u32 = 32;
/// The codes of a start that failed, and of the driver's end.
const NO_START_DATA: u64 = 1;
const NOT_REGISTERED: u64 = 2;
const STOPPED: u64 = 3;
const DRIVER_GONE: u64 = 4;

/// The address of buffer `b` of window `i`.
const fn buf_at(i: usize, b: usize) -> usize {
    BUF_AT + (i * proto_comp::BUFFERS + b) * BUFFER_MAX as usize
}

fn is_window(label: u64) -> bool {
    label & WINDOW != 0 && label & (OWN | WINDOW_KEYS) == 0
}

/// A window's session of keyboard focus (a window of the first revision).
fn is_window_keys(label: u64) -> bool {
    label & WINDOW != 0 && label & WINDOW_KEYS != 0 && label & OWN == 0
}

/// A session of the manager or of the input: a label init marked. The
/// service's own labels never have these marks.
fn is_manager(label: u64) -> bool {
    label & MANAGER_MARK != 0 && label & (OWN | WINDOW | DRIVER) == 0
}

fn is_input(label: u64) -> bool {
    label & INPUT_MARK != 0 && label & (OWN | WINDOW | DRIVER | MANAGER_MARK) == 0
}

/// A session of a holder of a scene: a context that is also a manager, and
/// commits scenes. A clone of it (a child's) has OWN and is none of this.
fn is_scene(label: u64) -> bool {
    label & SCENE_MARK != 0 && label & (OWN | WINDOW | DRIVER | MANAGER_MARK | INPUT_MARK) == 0
}

/// What a window holds besides what the scene decides: the objects of its
/// buffers with the pages of each that are mapped (for reading, from the
/// start, one call for a buffer), the channel the client is told on, the FLUSH
/// that waits for the frame in progress and the one that waits for the next.
/// A window that went keeps its place, `dying`, until its buffers are unmapped
/// and no order of the mapper thread is for it.
struct Extra {
    notify: Option<Handle<Channel>>,
    memory: [Option<Handle<Memory>>; proto_comp::BUFFERS],
    /// The pages each buffer has, and the pages of them mapped: 0 or all.
    pages: [usize; proto_comp::BUFFERS],
    mapped: [usize; proto_comp::BUFFERS],
    /// The level of the client that attached: the mapper thread works at it for the
    /// window's mappings and unmappings.
    level: u8,
    dying: bool,
    wait: Option<Pending>,
    queued: Option<Pending>,
}

impl Extra {
    const fn new() -> Extra {
        Extra {
            notify: None,
            memory: [const { None }; proto_comp::BUFFERS],
            pages: [0; proto_comp::BUFFERS],
            mapped: [0; proto_comp::BUFFERS],
            level: 1,
            dying: false,
            wait: None,
            queued: None,
        }
    }
}

/// An ATTACH whose buffers are being mapped: window `slot` gets `count`
/// buffers of `stride`, the reply waits for the last chunk.
struct Attaching {
    slot: usize,
    count: u8,
    stride: u32,
    /// The bytes the smallest of the buffers holds: the window's capacity.
    bytes: u64,
    buffer: usize,
    pending: Pending,
}

/// The order the mapper thread has: the buffer of a window it maps or unmaps.
#[derive(Clone, Copy)]
struct Ordered {
    slot: usize,
    buffer: usize,
    unmap: bool,
    /// The pages the order maps or unmaps: the whole buffer.
    pages: usize,
}

/// The pages one order maps of the `left` a buffer has to map. A buffer is one order; the break
/// maps the pieces of 32 pages the step thread used to, one entry each.
fn order_pages(left: usize) -> usize {
    if cfg!(feature = "break-compositor-chunk-map") {
        left.min(CHUNK)
    } else {
        left
    }
}

/// The first page of the order that unmaps the last of `mapped` pages of a buffer.
fn order_first(mapped: usize) -> usize {
    if cfg!(feature = "break-compositor-chunk-map") {
        (mapped - 1) / CHUNK * CHUNK
    } else {
        0
    }
}

/// The pixels of the windows' buffers, as the mappings hold them.
struct Pixels<'a>(&'a Scene);

/// The detail of the longest step of the service's own work tells which
/// work it is: the thousands (1 a band, to which the images it made are added,
/// 2 the take of a frame, 3 the commit after the last band, 4 the end of a
/// frame, 5 a step of the service's housekeeping, 6 the arming of the timer
/// after a band reached the cap).
const STEP_BAND: u64 = 1000;
const STEP_TAKE: u64 = 2000;
const STEP_COMMIT: u64 = 3000;
const STEP_END: u64 = 4000;
const STEP_WORK: u64 = 5000;
/// The same for a step that maps a portion of the frame buffer, and for the
/// step that finishes the opening of the screen (the probe of the late
/// opening reads both).
const STEP_SCREEN: u64 = 5001;
const STEP_SCREEN_SUBSCRIBE: u64 = 5002;
const STEP_SCREEN_PLANES: u64 = 5003;
const STEP_SCREEN_CURSOR: u64 = 5004;
const STEP_SCREEN_POOL: u64 = 5005;
const STEP_ARM: u64 = 6000;

/// The windows' buffers, as the mappings hold them.
fn window_bytes(scene: &Scene, window: usize, buffer: u8) -> &[u8] {
    {
        let len = scene.window(window).map_or(0, |w| {
            w.stride as usize * scene.buffer_lines(window) as usize
        });
        let at = if scene.window(window).is_some_and(|w| w.legacy) {
            POOL_AT
        } else {
            buf_at(window, buffer as usize)
        };
        // SAFETY: a buffer is taken only once it is attached, and the
        // reply of ATTACH comes after the mapper thread's last order is done
        // (the buffer is mapped read-only at this address in one call, for at
        // least `stride` times `h` bytes); the legacy buffer is mapped from
        // the start. The mapping stays until the window has gone and the
        // mapper thread unmaps it by an order a step gave after the worker
        // let go of the window, never in the middle of a band (one thread).
        unsafe { slice::from_raw_parts(at as *const u8, len) }
    }
}

/// The prepared images (`compositor::prep`): the table the service and the worker
/// share, the pool of their pages, and what the worker thread needs to start.
static TABLE: Table = Table::new();

/// The pool of the images, `prep::POOL_BYTES` of memory the table reads and the
/// worker writes.
#[repr(align(4096))]
struct ImagePool(UnsafeCell<[u8; prep::POOL_BYTES]>);

// SAFETY: the table decides who touches which image (a frame reads the one it
// holds, the worker writes the other).
unsafe impl Sync for ImagePool {}

static IMAGES: ImagePool = ImagePool(UnsafeCell::new([0; prep::POOL_BYTES]));
static WORKER_STACK: rt::Stack<{ 64 * 1024 }> = rt::Stack::new();
/// The page after the main thread's message buffer is the worker's.
const WORKER_BUFFER: usize = rt::abi::INIT_MSGBUF as usize + 4096;
/// The mapper thread's message buffer, the page after the worker's.
const MAPPER_BUFFER: usize = rt::abi::INIT_MSGBUF as usize + 2 * 4096;
/// The wait channel the worker receives on, the channel it tells the service's
/// bit through, as raw handle numbers (the handles live in the service).
static WORKER_WAIT: AtomicU64 = AtomicU64::new(0);
static WORKER_TELL: AtomicU64 = AtomicU64::new(0);

impl PixelSource for Pixels<'_> {
    fn pixels(&self, window: usize, buffer: u8) -> &[u8] {
        window_bytes(self.0, window, buffer)
    }

    fn prepared(&self, slot: u8, image: u8) -> (&[u8], u32, (u32, u32), bool) {
        let g = TABLE.geometry(usize::from(slot));
        (
            TABLE.image(usize::from(slot), image),
            g.stride(),
            (g.w, g.h),
            g.key.argb,
        )
    }
}

/// The link to an input service, as the display driver has one.
enum Link {
    Absent,
    Linked(Handle<Channel>),
    Lost,
}

/// An input service and the focus the compositor holds at it.
struct Device {
    name: &'static str,
    /// The bit's label of the handle the service notifies through, with the
    /// generation of the grant in its low 16 bits (a label a driver that
    /// ended left is told from the one of the grant that followed).
    mark: u64,
    generation: u64,
    link: Link,
    /// The session of focus the service made for the compositor.
    own: Option<Handle<Channel>>,
}

impl Device {
    const fn new(name: &'static str, mark: u64) -> Device {
        Device {
            name,
            mark,
            generation: 0,
            link: Link::Absent,
            own: None,
        }
    }
}

/// The place the absolute pointer last said, a number of the device's axes
/// (0 to ABS_MAX) each.
#[derive(Default)]
struct Axes {
    x: Option<i32>,
    y: Option<i32>,
}

/// The frame being made: the rectangle and the next line.
struct Job {
    /// The bounds of the frame's damage: what the driver is told to show.
    damage: Rect,
    /// The rectangles the bands walk, one after the other (`Scene::frame_damage`),
    /// and the one the bands are in now.
    rects: [Rect; compositor::damage::MAX_DAMAGE],
    count: usize,
    index: usize,
    at: Band,
    /// The groups of the layers of the place, made once when it began.
    passes: Option<compositor::Passes>,
}

/// The pool: the buffer of the window of the first revision, the driver's
/// source 2, mapped at POOL_AT for the service's life (to read the window's
/// pixels when a frame is put together, and to clear them). The handle has
/// DUPLICATE (the driver gives it to the owner so), and each window gets a
/// copy without it; `refs` is the number of references the object had right
/// after the mapping (init's, the driver's two and the service's two): more
/// of them mean a program kept a copy of an earlier window's buffer. `dirty`
/// says a program may have written into the pool since the last clearing
/// that ended with no copy out (`compositor::pool_open`).
struct Pool {
    handle: Handle<Memory>,
    refs: u64,
    dirty: bool,
}

/// What the driver gave at OPEN and the service has not finished with: the
/// buffer to map by steps, the owner session, the screen's size.
struct Opening {
    buffer: Handle<Memory>,
    owner: Handle<Channel>,
    width: u32,
    height: u32,
    stride: u32,
    /// The driver's pipelines, once asked (the phase `Planes`).
    list: Option<Pipelines>,
}

/// Where the pool is.
enum PoolState {
    /// The service has none and asks no more: the driver has no primary
    /// pipeline that suits, or its source does not.
    None,
    /// SOURCE was BUSY (a program kept a copy of the pool of an earlier
    /// screen, as after the service ended while Doom ran): it is asked again
    /// at OPEN.
    Retry,
    /// The object is being mapped, a chunk of pages a step of the work
    /// (`done` pages so far): OPEN says CLEARING meanwhile.
    Mapping {
        handle: Handle<Memory>,
        done: usize,
    },
    Ready(Pool),
}

struct Compositor {
    channel: ManuallyDrop<Handle<Channel>>,
    /// A copy of the channel with NOTIFY: the bands start themselves
    /// through it.
    notify: Handle<Channel>,
    parent: ManuallyDrop<Handle<Channel>>,
    process: ManuallyDrop<Handle<Process>>,
    level: u8,
    /// The driver's owner session, once the screen is open.
    screen: Option<Handle<Channel>>,
    /// Where the opening from a request is (`compositor::ScreenPhase`); the
    /// frame clock and every request that needs the screen look at
    /// `screen`, which is `Some` only in the phase `Open`.
    phase: ScreenPhase,
    /// The driver's buffer and session while they are being mapped and
    /// subscribed.
    opening: Option<Opening>,
    scene: Scene,
    extra: [Extra; MAX_WINDOWS],
    clones: Clones<CLONES>,
    serial: u64,
    job: Option<Job>,
    /// A COMMIT is with the driver: its bit is awaited.
    committed: bool,
    /// The windows of the first revision that went since the last frame
    /// shown: each is a line "gpu: screen released" once its place is.
    released: u32,
    raster: px::Pixman,
    keys: Device,
    pointer: Device,
    axes: Axes,
    /// The channel the manager is told of events through, once it said.
    manager: Option<Handle<Channel>>,
    /// The label of the session that subscribed: only its end clears it.
    manager_label: u64,
    /// Whether that session is the scene's (it holds the manager's ring too).
    manager_scene: bool,
    /// The scene session that committed a scene (0: none): its end ends the
    /// scene.
    scene_label: u64,
    /// The buffer of the window of the first revision, None when the driver
    /// gave none (OPEN is BUSY then). It is cleared a step at a time once its
    /// window has gone and the display does not show it (`cleared`: the
    /// bytes done, None when it is clean).
    pool: PoolState,
    /// The driver's primary pipeline, when it can show the pool.
    primary: Option<Pipeline>,
    cleared: Option<usize>,
    attaching: Option<Attaching>,
    /// The thread that maps and unmaps the windows' buffers, and the order it has.
    mapper: Option<rt::mapper::Mapper>,
    ordered: Option<Ordered>,
    /// The context of a manager that went: its windows are destroyed one a step
    /// (`reap_one`), so that eight windows do not make one long step.
    reaping: Option<u64>,
    /// The clock of the frame: when a frame is taken, the periods, the counters.
    pacer: Pacer,
    /// The timer of the frame, made through a copy of the channel with a label
    /// of its own; the copy lives as long as the timer.
    timer: Handle<Timer>,
    _timer_view: Handle<Channel>,
    /// The worker that makes the prepared images (started at the first job): its
    /// thread, the wait channel it receives on and the copy of it the service
    /// wakes it through (NOTIFY alone: no request can queue there).
    worker: Option<Worker>,
    /// The worker was tried once at the start.
    worker_tried: bool,
    /// The level a commit refused with BUSY lent the worker, until the pages it waits
    /// for are free.
    busy_boost: u8,
}

struct Worker {
    thread: Handle<Thread>,
    _wait: Handle<Channel>,
    wake: Handle<Channel>,
}

/// The worker's view of the windows' buffers.
struct WorkerReads;

impl Reads for WorkerReads {
    fn read(&self, place: usize, buffer: u8, len: usize) -> &[u8] {
        let len = len.min(BUFFER_MAX as usize);
        // SAFETY: the worker reads a buffer only while it holds the window
        // (`Table::hold`): the service unmaps a window's pages only after the worker
        // lets go, and a window's buffers are mapped when its first POST came.
        unsafe { slice::from_raw_parts(buf_at(place, usize::from(buffer)) as *const u8, len) }
    }
}

/// The worker thread: makes the prepared images, the slot of the highest level
/// first. It waits on a wait channel for the service to say there is work, and tells
/// the service (PREP) when it let go of something the service put off, moved to
/// another buffer while the service waited, published an image, or went idle. It
/// never sets its own level: the service owns it (`Compositor::steer_worker`),
/// raises it on the request path and lowers it when told the worker is idle.
///
/// The loop has one shape: pieces while a slot is next, then let go and wait. Every
/// pass that returns Idle or Blocked has cleared its slot's bit, and every setter of
/// a bit outside the worker (a post, a commit, the end of a frame) is followed by a
/// notice, so a slot that wants the worker is never left waiting and the worker
/// never has the same slot for ever.
extern "C" fn worker_main(_: u64) -> ! {
    let wait = Handle::<Channel>::borrowed(rt::abi::Handle(WORKER_WAIT.load(Ordering::Acquire)));
    let tell = Handle::<Channel>::borrowed(rt::abi::Handle(WORKER_TELL.load(Ordering::Acquire)));
    let mut maker = px::Worker::new();
    let mut job = prep::Job::NONE;
    // The level the service was told is too high for the work in hand.
    let mut told_level = 0;
    loop {
        while let Some((slot, at)) = TABLE.next(&job) {
            // A slot of a level below the worker's: the service is told, to lower the
            // worker, once for a level, so that the pass does not run above its level.
            let now = TABLE.worker_level();
            if at < now && told_level != now {
                told_level = now;
                let _ = sys::notify(&tell, PREP);
            } else if at >= now {
                told_level = 0;
            }
            match TABLE.piece(&mut job, slot, &mut maker, &WorkerReads) {
                Pass::More => {}
                Pass::Published => {
                    TABLE.let_go();
                    let _ = sys::notify(&tell, PREP);
                }
                Pass::Idle | Pass::Blocked => {
                    if TABLE.let_go() {
                        let _ = sys::notify(&tell, PREP);
                    }
                }
            }
            // The claim moved to another buffer of a window while the service waited
            // for the first: its free can go.
            if TABLE.take_moved() && TABLE.deferred() {
                let _ = sys::notify(&tell, PREP);
            }
        }
        // Idle: what the service waits for is let go, and a worker above its lowest
        // level says so, for the service to lower it.
        if TABLE.let_go() || TABLE.worker_level() > 1 {
            let _ = sys::notify(&tell, PREP);
        }
        let _ = sys::receive(&wait);
    }
}

/// The time on the scale of the counter, in nanoseconds.
fn now_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

fn main(_: u64) -> u64 {
    #[cfg(feature = "steps")]
    px::stack::paint();
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return NOT_REGISTERED;
    };
    if rt::service::register(&s.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    let Ok(notify) = sys::handle_duplicate(&channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    let Ok(timer_view) = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&timer_view, level) else {
        return NOT_REGISTERED;
    };
    let (period, cap_ppm, bad) = frame::parse_args(args.map_or(&[], |a| a.own));
    if bad {
        rt::println!(
            "compositor: the arguments of the record are no period and cap, the defaults stand"
        );
    }
    let cap = frame::band_cap(period, cap_ppm);
    let mut service = Compositor {
        channel: Handle::borrowed(channel.raw()),
        notify,
        parent: Handle::borrowed(s.parent.raw()),
        process: Handle::borrowed(s.process.raw()),
        level,
        screen: None,
        phase: ScreenPhase::Closed,
        opening: None,
        scene: Scene::new(),
        extra: [const { Extra::new() }; MAX_WINDOWS],
        clones: Clones::new(),
        serial: 0,
        job: None,
        committed: false,
        released: 0,
        raster: px::Pixman::warm(),
        keys: Device::new("input", KEYS),
        pointer: Device::new("pointer", POINTER),
        axes: Axes::default(),
        manager: None,
        manager_label: 0,
        manager_scene: false,
        scene_label: 0,
        pool: PoolState::None,
        primary: None,
        cleared: None,
        attaching: None,
        mapper: None,
        ordered: None,
        reaping: None,
        pacer: Pacer::new(now_ns(), period, cap),
        timer,
        _timer_view: timer_view,
        worker: None,
        worker_tried: false,
        busy_boost: 0,
    };
    TABLE.set_pool(IMAGES.0.get().cast());
    service.scene.set_prep(&TABLE);
    // The worker starts here, before the first request: a thread is made at no
    // step of the service.
    service.start_worker();
    // The mapper thread of the windows' buffers starts here, too.
    service.mapper =
        rt::mapper::Mapper::start(&service.process, &service.notify, MAPPED, MAPPER_BUFFER).ok();
    if service.mapper.is_none() {
        rt::println!("compositor: no thread for the windows' buffers, ATTACH is refused");
    }
    // The image of the pointer's picture is made here, before the first band
    // the pointer is in.
    service.raster.prepare(
        compositor::pointer_picture(),
        compositor::CURSOR_W * 4,
        Format::Argb,
        (compositor::CURSOR_W, compositor::CURSOR_H),
        compositor::POINTER_IMAGE,
    );
    service.keys.link = connect_device(&service.parent, service.keys.name);
    service.pointer.link = connect_device(&service.parent, service.pointer.name);
    // The screen is opened here, outside any step (its buffer is 256 pages
    // to map): the driver says CLEARING while it sets the device up, and
    // the service asks again on a timer of its own channel. A driver that
    // does not answer is asked again at a request.
    // A probe build of the late opening leaves the tries out: the first
    // request opens the screen, by the steps of the work.
    if !cfg!(feature = "late-open") {
        service.open_screen_waiting(level);
    }
    // The prices of the bands measured on shapes of their own, in the screen's
    // buffer, before the first request (the probes that read the lines, feature
    // `calibrate`: it takes a second of the CPU at the service's level, in which
    // the services below it, the process service among them, do not start).
    #[cfg(feature = "calibrate")]
    if service.screen.is_some() {
        // SAFETY: the buffer is this service's mapping of the screen's object,
        // read and write, SCREEN_BYTES of its 256 pages; nothing else holds it.
        let fb = unsafe { slice::from_raw_parts_mut(FB_AT as *mut u8, SCREEN_BYTES as usize) };
        service.raster.calibrate(fb);
        service.raster.calibrate_layers(fb);
        service.raster.calibrate_lookup(fb);
    }
    // The periods start when the screen is open (and measured).
    service.pacer = Pacer::new(now_ns(), period, cap);
    // The devices' focus is the compositor's, once the screen is.
    service.take_own(Which::Keys);
    service.take_own(Which::Pointer);
    #[cfg(feature = "steps")]
    {
        rt::service::report_steps(17);
        rt::service::table_steps_from(16);
        rt::service::step_after(px::cost::tell);
    }
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &s.parent,
            period_ns: args.map_or(0, |a| a.period_ns),
            priority: level,
        }),
    };
    let _ = rt::service::run::<Compositor, SESSIONS, 1>(&channel, &mut service, config);
    // A stop in the middle of the opening: the pages mapped so far go.
    service.release_opening();
    STOPPED
}

/// The format a number of the protocol names.
fn format_of(number: u32) -> Option<Format> {
    match number {
        proto_comp::FORMAT_XRGB8888 => Some(Format::Xrgb),
        proto_comp::FORMAT_ARGB8888 => Some(Format::Argb),
        proto_comp::FORMAT_A8 => Some(Format::A8),
        _ => None,
    }
}

/// The two input services of the compositor.
#[derive(Clone, Copy)]
enum Which {
    Keys,
    Pointer,
}

/// The session init gives the compositor with the input service `name`
/// (`connects` of its record): Absent when the table gives none.
fn connect_device(parent: &Handle<Channel>, name: &str) -> Link {
    match rt::service::connect(parent, name) {
        Ok(session) => Link::Linked(session),
        Err(Status::Kernel(Error::AccessDenied)) => Link::Absent,
        Err(_) => Link::Lost,
    }
}

/// The status at the head of a reply.
fn status_of(bytes: &[u8]) -> Option<Status> {
    bytes
        .get(..4)
        .map(|b| Status::from_code(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
}

impl Compositor {
    // ------------------------------------------------------------ the driver

    /// Opens the screen of the driver, once: OPEN of the session init gave
    /// (`display`), its buffer mapped for writing, SUBSCRIBE with the
    /// channel the driver says the end of a COMMIT through. The refusal
    /// is the status a client of ours gets: CLEARING while the driver is
    /// setting up or the last owner's buffer is cleared, NO_DEVICE
    /// without the driver.
    fn open_screen(&mut self, late: bool) -> Result<(), Status> {
        match self.phase.ask() {
            ScreenAsk::Ready => return Ok(()),
            ScreenAsk::Clearing => return Err(code(CLEARING)),
            ScreenAsk::Ask => {}
        }
        let session = match rt::service::connect(&self.parent, "display") {
            Ok(session) => session,
            Err(Status::Kernel(Error::AccessDenied)) => return Err(code(NO_DEVICE)),
            Err(_) => return Err(code(CLEARING)),
        };
        let mut reply =
            sys::send(&session, &Gpu::Open.header().bytes()).map_err(|_| code(CLEARING))?;
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        match status_of(bytes) {
            Some(Status::Ok) => {}
            Some(status) if status == code(NO_INPUT) => {}
            Some(status) => return Err(status),
            None => return Err(code(IO)),
        }
        let screen = match Screen::read(bytes) {
            Ok((_, screen)) if screen == Screen::FIXED => screen,
            _ => return Err(code(IO)),
        };
        let (Ok(fb), Ok(owner)) = (
            reply.handles.take::<Memory>(0),
            reply.handles.take::<Channel>(1),
        ) else {
            return Err(code(IO));
        };
        self.opening = Some(Opening {
            buffer: fb,
            owner,
            width: screen.width,
            height: screen.height,
            stride: screen.stride,
            list: None,
        });
        self.phase = self.phase.begin();
        if late {
            // From a request: the buffer's 256 pages are mapped by the steps
            // of the work, and the requests meanwhile are told CLEARING.
            let _ = sys::notify(&self.notify, WORK);
            return Err(code(CLEARING));
        }
        // At the start, outside any step: all at once.
        let opening = self.opening.as_ref().ok_or(code(IO))?;
        if sys::mem_map(
            &self.process,
            &opening.buffer,
            0,
            u64::from(BUFFER_BYTES),
            FB_AT,
            Access::ReadWrite,
        )
        .is_err()
        {
            self.abort_opening();
            return Err(code(IO));
        }
        self.phase = self.phase.mapped(BUFFER_PAGES, BUFFER_PAGES);
        while self.phase.has_work() {
            self.advance_opening()?;
        }
        Ok(())
    }

    /// A step of the finishing of the opening: SUBSCRIBE (with the frame
    /// bit's handle), then the pipelines and the cursor's picture, then the
    /// pool's source, and the screen is open. A refusal of SUBSCRIBE
    /// releases the mapping; the planes' refusals leave the old ways
    /// (`take_planes`).
    fn advance_opening(&mut self) -> Result<(), Status> {
        let Some(mut opening) = self.opening.take() else {
            self.phase = ScreenPhase::Closed;
            return Err(code(IO));
        };
        match self.phase {
            ScreenPhase::Subscribing => {
                if let Err(status) = self.subscribe(&opening.owner) {
                    self.release_mapping();
                    return Err(status);
                }
            }
            ScreenPhase::Planes => opening.list = self.ask_pipelines(&opening.owner),
            ScreenPhase::Cursor => {
                if let Some(list) = &opening.list {
                    self.take_cursor(&opening.owner, list);
                }
            }
            ScreenPhase::Pool => {
                if let Some(list) = &opening.list
                    && let Err(why) = self.pool_source(&opening.owner, list)
                {
                    rt::println!("compositor: no pool for the window of the first revision: {why}");
                }
            }
            _ => {}
        }
        self.phase = self.phase.advanced();
        if self.phase != ScreenPhase::Open {
            self.opening = Some(opening);
            return Ok(());
        }
        // The mapping keeps the object; the handle is not needed.
        let Opening {
            buffer,
            owner,
            width,
            height,
            stride,
            ..
        } = opening;
        drop(buffer);
        self.screen = Some(owner);
        rt::println!("compositor: screen ready, {width}x{height}, stride {stride}");
        Ok(())
    }

    /// SUBSCRIBE: the frame bit comes through a handle of this channel with
    /// a label of its own; the driver holds it for the screen's time. A
    /// driver that went in the middle ends the service (init starts it
    /// again), the mapping released first.
    fn subscribe(&mut self, owner: &Handle<Channel>) -> Result<(), Status> {
        let frame = sys::handle_label(
            &self.channel,
            Rights::NOTIFY | Rights::TRANSFER,
            DRIVER,
            self.level,
        )
        .map_err(|_| code(IO))?;
        let mut request = Writer::new();
        Gpu::Subscribe.header().write(&mut request)?;
        let reply = match sys::send_handles(owner, request.as_bytes(), [frame.erase()]) {
            Ok(reply) => reply,
            Err(refused) => {
                if refused.error == Error::PeerClosed {
                    self.release_mapping();
                    self.driver_gone();
                }
                return Err(Status::Kernel(refused.error));
            }
        };
        let mut buffer = [0; MESSAGE_MAX];
        if status_of(reply.bytes(&mut buffer)) == Some(Status::Ok) {
            Ok(())
        } else {
            Err(code(IO))
        }
    }

    /// One step of the opening from a request: a portion of the buffer's
    /// pages mapped, or, after the last one, the finishing.
    fn open_step(&mut self) {
        rt::service::step_detail(match self.phase {
            ScreenPhase::Subscribing => STEP_SCREEN_SUBSCRIBE,
            ScreenPhase::Planes => STEP_SCREEN_PLANES,
            ScreenPhase::Cursor => STEP_SCREEN_CURSOR,
            ScreenPhase::Pool => STEP_SCREEN_POOL,
            _ => STEP_SCREEN,
        });
        match self.phase {
            ScreenPhase::Mapping { done } => {
                let pages = self.phase.portion(BUFFER_PAGES, CHUNK);
                let Some(opening) = &self.opening else {
                    self.phase = ScreenPhase::Closed;
                    return;
                };
                let mapped = sys::mem_map(
                    &self.process,
                    &opening.buffer,
                    (done * PAGE) as u64,
                    (pages * PAGE) as u64,
                    FB_AT + done * PAGE,
                    Access::ReadWrite,
                );
                if mapped.is_err() {
                    rt::println!("compositor: the frame buffer cannot be mapped");
                    self.abort_opening();
                    return;
                }
                self.phase = self.phase.mapped(pages, BUFFER_PAGES);
            }
            ScreenPhase::Subscribing
            | ScreenPhase::Planes
            | ScreenPhase::Cursor
            | ScreenPhase::Pool => {
                let _ = self.advance_opening();
            }
            ScreenPhase::Closed | ScreenPhase::Open => {}
        }
    }

    /// Unmaps the pages of the frame buffer mapped so far and goes back to
    /// the phase `Closed`; the session of the driver goes with the handle
    /// (the driver takes the screen back and a request asks it again).
    fn release_mapping(&mut self) {
        let (phase, pages) = self.phase.release(BUFFER_PAGES);
        if pages != 0 {
            // SAFETY: the pages from FB_AT for `pages` were mapped by the
            // steps of the opening, and nothing reads the buffer before the
            // screen is open.
            let _ = unsafe { sys::mem_unmap(&self.process, FB_AT, (pages * PAGE) as u64) };
        }
        self.phase = phase;
    }

    /// A refusal of the opening: the mapping and the session are released.
    fn abort_opening(&mut self) {
        self.release_mapping();
        self.opening = None;
    }

    /// The stop of the service: whatever the opening mapped is released.
    fn release_opening(&mut self) {
        if self.phase.has_work() {
            self.abort_opening();
        }
    }

    /// What the driver's pipelines let the service do, once the screen is
    /// subscribed: the pipelines are asked (`ask_pipelines`), the pointer
    /// goes onto the cursor pipeline (`take_cursor`), and the pool becomes the buffer of the window of the
    /// first revision (the next step, `pool_source`). Both are calls to the
    /// driver and mappings, so they belong to the opening of the screen,
    /// which no frame is waiting for, each in a step of its own. Any
    /// refusal leaves the old way: the pointer drawn into the frame, no
    /// direct frame, and OPEN BUSY (the pool is the only buffer of a window
    /// of the first revision).
    fn ask_pipelines(&mut self, owner: &Handle<Channel>) -> Option<Pipelines> {
        let list = {
            let mut buffer = [0; MESSAGE_MAX];
            let mut request = Writer::new();
            Pipelines::write_request(&mut request)
                .map_err(|_| "PIPELINES")
                .and_then(|()| sys::send(owner, request.as_bytes()).map_err(|_| "PIPELINES failed"))
                .and_then(|reply| {
                    Pipelines::read(reply.bytes(&mut buffer)).map_err(|_| "no PIPELINES")
                })
        };
        let list = match list {
            Ok(list) => list,
            Err(why) => {
                rt::println!("compositor: the pointer is drawn in the frame: {why}");
                rt::println!("compositor: no pool for the window of the first revision: {why}");
                return None;
            }
        };
        Some(list)
    }

    /// The cursor's pipeline and picture.
    fn take_cursor(&mut self, owner: &Handle<Channel>, list: &Pipelines) {
        match self.cursor_picture(owner, list) {
            Ok(plane) => {
                self.scene.set_cursor_plane(Some(plane));
                rt::println!("compositor: the pointer is on the cursor pipeline");
            }
            Err(why) => rt::println!("compositor: the pointer is drawn in the frame: {why}"),
        }
    }

    /// The pool: SOURCE of kind pool. The object is mapped by the steps of
    /// the work (`map_pool_chunk`), a chunk of pages each, since 250 pages
    /// in one step would pass the bound; OPEN says CLEARING until that is
    /// done. The primary pipeline must take the screen's whole size.
    fn pool_source(
        &mut self,
        owner: &Handle<Channel>,
        list: &Pipelines,
    ) -> Result<(), &'static str> {
        let primary = *list
            .as_slice()
            .iter()
            .find(|p| {
                p.kind == KIND_PRIMARY
                    && p.has(PIPELINE_FULL_SCREEN)
                    && p.formats & FORMATS_XRGB8888 != 0
            })
            .ok_or("no primary pipeline that takes the whole screen")?;
        self.primary = Some(primary);
        self.ask_pool(owner)
    }

    /// SOURCE of kind pool: the object goes to the mapping steps. A BUSY
    /// from the driver is remembered (`PoolState::Retry`): the driver marks a
    /// source as given only when it gives it, so OPEN may ask again once the
    /// program that holds the old copy is gone.
    fn ask_pool(&mut self, owner: &Handle<Channel>) -> Result<(), &'static str> {
        let primary = self.primary.ok_or("no primary pipeline")?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut request = Writer::new();
        SourceInfo::write_request(SOURCE_KIND_POOL, &mut request).map_err(|_| "SOURCE")?;
        let mut reply = sys::send(owner, request.as_bytes()).map_err(|_| "SOURCE failed")?;
        let bytes = reply.bytes(&mut buffer);
        if status_of(bytes) == Some(code(BUSY)) {
            self.pool = PoolState::Retry;
            return Err("the pool is held by a program of an earlier screen");
        }
        let source = SourceInfo::read(bytes).map_err(|_| "SOURCE refused")?;
        let object = reply.handles.take::<Memory>(0).map_err(|_| "no object")?;
        if source.id != SOURCE_POOL
            || !source.suits(&primary)
            || u64::from(source.stride) * u64::from(source.height) != POOL_LEN as u64
        {
            self.pool = PoolState::None;
            return Err("the pool source does not suit");
        }
        self.pool = PoolState::Mapping {
            handle: object,
            done: 0,
        };
        let _ = sys::notify(&self.notify, WORK);
        Ok(())
    }

    /// A chunk of the pool mapped at POOL_AT; the last one records the
    /// references and the pool is ready (dirty: its first OPEN clears it).
    fn map_pool_chunk(&mut self) {
        let PoolState::Mapping { handle, done } = &mut self.pool else {
            return;
        };
        let pages = CHUNK.min(POOL_LEN / PAGE - *done);
        let mapped = sys::mem_map(
            &self.process,
            handle,
            (*done * PAGE) as u64,
            (pages * PAGE) as u64,
            POOL_AT + *done * PAGE,
            Access::ReadWrite,
        );
        if mapped.is_err() {
            rt::println!("compositor: the pool cannot be mapped");
            let first = *done;
            if first != 0 {
                // SAFETY: the pages from POOL_AT to `first` were mapped by
                // this function in earlier steps and nothing reads them yet.
                let _ = unsafe { sys::mem_unmap(&self.process, POOL_AT, (first * PAGE) as u64) };
            }
            self.pool = PoolState::None;
            return;
        }
        *done += pages;
        if *done * PAGE < POOL_LEN {
            return;
        }
        let refs = sys::memory_info(handle).map_or(0, |info| info.refs);
        let PoolState::Mapping { handle, .. } = core::mem::replace(&mut self.pool, PoolState::None)
        else {
            return;
        };
        self.pool = PoolState::Ready(Pool {
            handle,
            refs,
            dirty: true,
        });
        self.scene.set_direct(true);
        rt::println!("compositor: the pool is the buffer of the first revision");
    }

    /// The pipeline and the source of the cursor, with the picture in place.
    fn cursor_picture(
        &mut self,
        owner: &Handle<Channel>,
        list: &Pipelines,
    ) -> Result<(u32, u32), &'static str> {
        let mut buffer = [0; MESSAGE_MAX];
        let pipeline = *list
            .as_slice()
            .iter()
            .find(|p| p.kind == KIND_CURSOR && p.formats & FORMATS_ARGB8888 != 0)
            .ok_or("no cursor pipeline")?;
        let mut request = Writer::new();
        SourceInfo::write_request(SOURCE_KIND_CURSOR, &mut request).map_err(|_| "SOURCE")?;
        let mut reply = sys::send(owner, request.as_bytes()).map_err(|_| "SOURCE failed")?;
        let source = SourceInfo::read(reply.bytes(&mut buffer)).map_err(|_| "SOURCE refused")?;
        let object = reply.handles.take::<Memory>(0).map_err(|_| "no object")?;
        let bytes = u64::from(source.stride) * u64::from(source.height);
        if !source.suits(&pipeline)
            || source.width < compositor::CURSOR_W
            || source.height < compositor::CURSOR_H
            || bytes > (4 * PAGE) as u64
        {
            return Err("the cursor source does not suit");
        }
        sys::mem_map(
            &self.process,
            &object,
            0,
            bytes,
            CURSOR_AT,
            Access::ReadWrite,
        )
        .map_err(|_| "the picture cannot be mapped")?;
        // SAFETY: the object was mapped for reading and writing at CURSOR_AT
        // for `bytes` bytes just above, and nothing else in this thread
        // holds the range.
        let picture = unsafe { slice::from_raw_parts_mut(CURSOR_AT as *mut u8, bytes as usize) };
        let line = (compositor::CURSOR_W * 4) as usize;
        for (y, row) in compositor::CURSOR.chunks(line).enumerate() {
            let at = y * source.stride as usize;
            picture[at..at + line].copy_from_slice(row);
        }
        // The mapping keeps the object.
        drop(object);
        Ok((pipeline.id, source.id))
    }

    /// The cursor to the pointer: one LAYERS of the cursor pipeline alone
    /// when the pointer's place or visibility changed since the last one
    /// the driver took, however many moves the step's events made. The
    /// driver takes it at once (it queues the move for the device) and
    /// merges moves itself, so the step never waits for the device. A
    /// refusal is final: the pointer goes back into the frame
    /// (`Scene::cursor_refused`), after one row that hides the cursor if
    /// the device may be showing it, whose answer is not looked at, and a
    /// line says so once.
    fn move_cursor(&mut self) {
        let Some(row) = self.scene.cursor_row() else {
            return;
        };
        let Some(owner) = &self.screen else {
            return;
        };
        let mut request = Writer::new();
        let wrote = Layers::new(&[row])
            .and_then(|layers| layers.write(&mut request))
            .map_err(|_| Error::InvalidArgs);
        let sent = wrote.and_then(|()| sys::send(owner, request.as_bytes()));
        match sent {
            Ok(reply) => {
                let mut buffer = [0; MESSAGE_MAX];
                if status_of(reply.bytes(&mut buffer)) == Some(Status::Ok) {
                    self.scene.cursor_shown(&row);
                } else {
                    self.give_up_cursor();
                }
            }
            Err(Error::PeerClosed) => self.driver_gone(),
            Err(_) => self.give_up_cursor(),
        }
    }

    /// The driver will not take the cursor's rows: hide what it may show,
    /// draw the pointer in the frame from now on, say so once.
    fn give_up_cursor(&mut self) {
        if let Some(off) = self.scene.cursor_refused()
            && let Some(owner) = &self.screen
        {
            let mut request = Writer::new();
            if Layers::new(&[off])
                .and_then(|layers| layers.write(&mut request))
                .is_ok()
            {
                let _ = sys::send(owner, request.as_bytes());
            }
        }
        rt::println!(
            "compositor: the cursor LAYERS was refused, the pointer is drawn in the frame"
        );
    }

    /// `open_screen`, again every few milliseconds while the driver says it
    /// is not ready, for a second at most.
    fn open_screen_waiting(&mut self, level: u8) {
        let Ok(quiet) = sys::channel_create(level) else {
            let _ = self.open_screen(false);
            return;
        };
        let Ok(waiter) = Waiter::new(&quiet, 0, level) else {
            let _ = self.open_screen(false);
            return;
        };
        for _ in 0..OPEN_TRIES {
            if self.open_screen(false) != Err(code(CLEARING)) {
                return;
            }
            let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(OPEN_PAUSE_NS);
            let _ = waiter.receive_until(&quiet, deadline);
        }
    }

    /// The driver is gone or broke: every window this instance gave leads
    /// nowhere, so the service ends and init starts it again.
    fn driver_gone(&self) -> ! {
        rt::println!("compositor: the display driver went");
        sys::process_exit(DRIVER_GONE)
    }

    // ------------------------------------------------------------ the input

    fn device(&mut self, which: Which) -> &mut Device {
        match which {
            Which::Keys => &mut self.keys,
            Which::Pointer => &mut self.pointer,
        }
    }

    /// The device a label of a grant names, if it is one: neither the
    /// service's own marks nor init's are set, and one of the two device
    /// bits is.
    fn device_label(label: u64) -> Option<Which> {
        if label & (OWN | WINDOW | DRIVER | MANAGER_MARK | INPUT_MARK | SCENE_MARK | WINDOW_KEYS)
            != 0
        {
            return None;
        }
        match label & !GENERATION {
            KEYS => Some(Which::Keys),
            POINTER => Some(Which::Pointer),
            _ => None,
        }
    }

    /// The focus of each input device the compositor does not hold, though
    /// the image has the device, is taken again (the driver ended and was
    /// started again by init). A connection to a service that is starting
    /// again waits for it.
    fn regrant(&mut self) {
        for which in [Which::Keys, Which::Pointer] {
            let device = self.device(which);
            let present = !matches!(device.link, Link::Absent);
            if compositor::wants_focus(present, device.own.is_some()) {
                self.take_own(which);
            }
        }
    }

    /// GRANT with a channel of the compositor's own: the focus of the
    /// device is its, and the device says by a bit when events wait.
    fn take_own(&mut self, which: Which) {
        let level = self.level;
        let channel = &self.channel;
        let device = match which {
            Which::Keys => &mut self.keys,
            Which::Pointer => &mut self.pointer,
        };
        for _ in 0..2 {
            if matches!(device.link, Link::Lost) {
                device.link = connect_device(&self.parent, device.name);
            }
            let Link::Linked(session) = &device.link else {
                return;
            };
            let rights = Rights::NOTIFY | Rights::TRANSFER;
            device.generation = (device.generation + 1) & GENERATION;
            let label = device.mark | device.generation;
            let Ok(wake) = sys::handle_label(channel, rights, label, level) else {
                return;
            };
            match sys::send_handles(
                session,
                &InputMethod::Grant.header().bytes(),
                [wake.erase()],
            ) {
                Ok(mut reply) => {
                    let mut buffer = [0; MESSAGE_MAX];
                    let status = status_of(reply.bytes(&mut buffer));
                    if status == Some(Status::Ok) && reply.handles.len() == 1 {
                        device.own = reply.handles.take::<Channel>(0).ok();
                    } else {
                        rt::println!("compositor: GRANT of {} refused: {status:?}", device.name);
                    }
                    return;
                }
                Err(refused) if refused.error == Error::PeerClosed => device.link = Link::Lost,
                Err(_) => return,
            }
        }
    }

    /// READ of a device's events (up to READ_MAX, without waiting) into the
    /// scene; when it filled the request the next ones wait for the
    /// service's own bit.
    fn read_device(&mut self, which: Which) {
        rt::service::step_own();
        let mut request = Writer::new();
        if proto_input::write_read(READ_MAX, &mut request).is_err() {
            return;
        }
        let device = self.device(which);
        let Some(own) = &device.own else {
            return;
        };
        let reply = match sys::send(own, request.as_bytes()) {
            Ok(reply) => reply,
            Err(Error::PeerClosed) => {
                device.own = None;
                device.link = Link::Lost;
                let _ = sys::notify(&self.notify, WORK);
                return;
            }
            Err(_) => return,
        };
        let mut buffer = [0; MESSAGE_MAX];
        let mut batch = [proto_input::Event::default(); READ_MAX as usize];
        let mut n = 0;
        let read = proto_input::read_events(reply.bytes(&mut buffer), |e| {
            if n < batch.len() {
                batch[n] = e;
                n += 1;
            }
        });
        if read.is_err() {
            return;
        }
        for e in &batch[..n] {
            self.route(which, *e);
        }
        self.pointer_to_axes();
        self.move_cursor();
        if n == READ_MAX as usize {
            let _ = sys::notify(&self.notify, INPUT);
        }
        self.kick();
    }

    /// An event of a device into the scene.
    fn route(&mut self, which: Which, e: proto_input::Event) {
        match (which, e.kind) {
            (Which::Keys, EV_KEY) => self.scene.key(e.code, e.value == proto_input::PRESS),
            (Which::Pointer, EV_KEY) => {
                // The place first, then the button that was pressed there.
                self.pointer_to_axes();
                self.scene.button(e.code, e.value == proto_input::PRESS);
            }
            (Which::Pointer, EV_ABS) if e.code == ABS_X => self.axes.x = Some(e.value),
            (Which::Pointer, EV_ABS) if e.code == ABS_Y => self.axes.y = Some(e.value),
            _ => {}
        }
    }

    /// The pointer goes where the axes say, once something moved them.
    fn pointer_to_axes(&mut self) {
        let (x, y) = (self.axes.x.take(), self.axes.y.take());
        if x.is_none() && y.is_none() {
            return;
        }
        let (px, py) = self.scene.pointer().unwrap_or((0, 0));
        let scale = |v: i32, size: u32| {
            (i64::from(v.clamp(0, ABS_MAX)) * i64::from(size) / (i64::from(ABS_MAX) + 1)) as i32
        };
        let x = x.map_or(px, |v| scale(v, proto_gpu::WIDTH));
        let y = y.map_or(py, |v| scale(v, proto_gpu::HEIGHT));
        self.scene.pointer_to(x, y);
    }

    /// Tells the windows and the manager whose rings got events since the
    /// last time.
    fn deliver(&mut self) {
        let d = self.scene.delivered();
        for i in 0..MAX_WINDOWS {
            if d.windows & (1 << i) != 0
                && let Some(notify) = &self.extra[i].notify
            {
                let _ = sys::notify(notify, EVENTS_BIT);
            }
        }
        let scene = self.scene.scene_bits();
        let bits = if d.manager { EVENTS_BIT } else { 0 }
            | if scene.committed { COMMITTED_BIT } else { 0 }
            | if scene.composed { COMPOSED_BIT } else { 0 };
        if bits != 0
            && let Some(manager) = &self.manager
        {
            let _ = sys::notify(manager, bits);
        }
    }

    /// What a taking gave back of the windows no element of the scene shows:
    /// the bit of each buffer that is free again, and the answer of a FLUSH of
    /// the first revision that has nothing to wait for.
    fn release_given(&mut self) {
        let given = self.scene.given_back();
        for i in 0..MAX_WINDOWS {
            if let Some(b) = given.freed[i]
                && let Some(notify) = &self.extra[i].notify
            {
                let _ = sys::notify(notify, 1 << b);
            }
            if given.answered & (1 << i) != 0
                && let Some(pending) = self.extra[i].queued.take()
            {
                let _ = pending.answer(&proto_wire::reply(Status::Ok), Outgoing::new());
            }
        }
    }

    // ------------------------------------------------------------ the frame

    /// A change may have come: the free run starts a frame at once when none is
    /// in progress and damage waits; with a period the change waits for the next
    /// start of a period (the timer is armed for it), where the windows' posted
    /// buffers are taken, the FLUSHes that wait move to that frame, and the first
    /// band is due.
    fn kick(&mut self) {
        if self.pacer.is_free() {
            self.start_free();
        } else {
            self.want_frame();
        }
        self.deliver();
    }

    /// A change waits for a frame: the pacer arms the timer for the start of
    /// the period it is taken at, when no frame is in work.
    fn want_frame(&mut self) {
        if self.screen.is_none() || !self.scene.damaged() {
            return;
        }
        let wake = self.pacer.change(now_ns(), None);
        self.arm(wake);
    }

    /// The step after a band reached the cap: the timer is armed for the start
    /// the bands wait for (`Pacer::take_arm`).
    fn arm_after_cap(&mut self) {
        rt::service::step_own();
        rt::service::step_detail(STEP_ARM);
        if let Some(at) = self.pacer.take_arm() {
            let _ = sys::timer_set(&self.timer, at);
        }
    }

    /// What the pacer says of the timer.
    fn arm(&mut self, wake: Wake) {
        match wake {
            Wake::At(at) => {
                let _ = sys::timer_set(&self.timer, at);
            }
            Wake::Now => self.start_free(),
            Wake::None => {}
        }
    }

    /// The free run: a frame as soon as the screen, the device and damage allow.
    fn start_free(&mut self) {
        if self.begin_frame(None) {
            self.pacer.take_now(now_ns());
        }
    }

    /// The timer fired at the start of a period (or the bands put off by the cap
    /// are due): take the frame, or go on with its bands.
    fn timer_fired(&mut self) {
        // The step that takes a frame is judged as a band is (under the band's
        // limit), with the steps of the service's own work.
        rt::service::step_own();
        rt::service::step_detail(STEP_TAKE);
        let now = now_ns();
        match self.pacer.fire(now) {
            Fire::Take(k) => {
                if self.begin_frame(Some(k)) {
                    // The windows the frame did not take are owed their start.
                    if let Some(e) = self.scene.held_until() {
                        self.pacer.hold(e);
                    }
                    self.deliver();
                } else {
                    // Nothing was taken (damage that has gone, or only windows
                    // held for their intervals): they are owed their start.
                    if let Some(e) = self.scene.held_until() {
                        self.pacer.hold(e);
                    }
                    let wake = self.pacer.nothing_taken(now);
                    self.arm(wake);
                    self.deliver();
                }
            }
            Fire::Continue => {
                #[cfg(feature = "irq-trace")]
                px::cost::trace::mark_expiry();
                let _ = sys::notify(&self.notify, BAND);
            }
            Fire::Idle | Fire::Early => {}
        }
    }

    /// Begins a frame (of period `k`, or of the free run) when none is in
    /// progress and the screen is open and damage waits: whether one began.
    fn begin_frame(&mut self, k: Option<u64>) -> bool {
        if self.screen.is_none() || self.job.is_some() || self.committed {
            return false;
        }
        let began = self.scene.begin_at(k.unwrap_or(u64::MAX));
        self.release_given();
        let Some(damage) = began else {
            return false;
        };
        for i in 0..MAX_WINDOWS {
            if self.scene.window(i).is_some_and(|w| w.in_frame) && self.extra[i].queued.is_some() {
                self.extra[i].wait = self.extra[i].queued.take();
            }
        }
        // A direct frame has no band: its one step is the end of the frame.
        let row = if self.scene.frame_kind() == FrameKind::Bypass {
            damage.y + damage.h
        } else {
            damage.y
        };
        let mut rects = [damage; compositor::damage::MAX_DAMAGE];
        let list = self.scene.frame_damage();
        let count = list.len().clamp(1, rects.len());
        rects[..count].copy_from_slice(&list[..count]);
        let row = if count == 1 { row } else { rects[0].y };
        let passes = if self.scene.frame_kind() == FrameKind::Bypass {
            None
        } else {
            compositor::plan(&self.scene, rects[0])
        };
        self.job = Some(Job {
            damage,
            rects,
            count,
            index: 0,
            passes,
            at: Band {
                row,
                col: 0,
                pass: 0,
            },
        });
        #[cfg(feature = "irq-trace")]
        px::cost::trace::mark_first_of_frame();
        let _ = sys::notify(&self.notify, BAND);
        true
    }

    /// One band of the frame; the step after the last band commits it
    /// (the driver's answer is a wait of its own, which does not belong in
    /// the step of a band).
    fn band(&mut self) {
        rt::service::step_own();
        // The bands are put off by the cap until the expiry of the timer says to go on
        // (which notifies the next band): a notice of a band before that does nothing.
        if self.pacer.deferred() {
            return;
        }
        rt::service::step_detail(STEP_BAND);
        #[cfg(feature = "steps")]
        let band_began = rt::time::now();
        let Some(job) = self.job.as_mut() else {
            return;
        };
        if job.at.row >= job.rects[job.index].y + job.rects[job.index].h {
            let damage = job.damage;
            self.job = None;
            #[cfg(feature = "steps")]
            px::cost::frame_done();
            rt::service::step_detail(STEP_COMMIT);
            self.commit(damage);
            return;
        }
        // SAFETY: the buffer is this service's mapping of the screen's
        // object, read and write, SCREEN_BYTES of its 256 pages; nothing
        // else in this thread holds it.
        let fb = unsafe { slice::from_raw_parts_mut(FB_AT as *mut u8, SCREEN_BYTES as usize) };
        let began = now_ns();
        let made = self.raster.made();
        #[cfg(feature = "steps")]
        px::cost::band_begin();
        #[cfg(feature = "irq-trace")]
        let (times_began, scan_began) = (px::cost::trace::times(), self.raster.scanned());
        #[cfg(feature = "steps")]
        let compose_began = rt::time::now();
        job.at = compose_planned(
            &self.scene,
            job.rects[job.index],
            job.at,
            job.passes.as_ref(),
            fb,
            &Pixels(&self.scene),
            &mut self.raster,
        );
        #[cfg(feature = "steps")]
        let (compose_ticks, band_ticks) = (
            rt::time::now() - compose_began,
            rt::time::now() - band_began,
        );
        #[cfg(feature = "irq-trace")]
        {
            let times = px::cost::trace::times();
            px::cost::trace::band(
                times.0.saturating_sub(times_began.0),
                times.1.saturating_sub(times_began.1),
                self.raster.scanned().wrapping_sub(scan_began),
            );
        }
        #[cfg(feature = "steps")]
        px::cost::band_end(compose_ticks, band_ticks);
        // The images this band made (surfaces first used in it) go in the
        // detail with the band's number, so that a long band is told from a
        // band of images made.
        rt::service::step_detail(STEP_BAND + u64::from(self.raster.made().wrapping_sub(made)));
        self.scene.band_done();
        // The last band of a rectangle goes on to the next one at once, in the
        // same step: the groups of its layers are made for it, and its first band
        // is the next step.
        if job.at.row >= job.rects[job.index].y + job.rects[job.index].h
            && job.index + 1 < job.count
        {
            job.index += 1;
            let next = job.rects[job.index];
            job.passes = compositor::plan(&self.scene, next);
            job.at = Band {
                row: next.y,
                col: 0,
                pass: 0,
            };
        }
        let more = job.at.row < job.rects[job.index].y + job.rects[job.index].h;
        let now = now_ns();
        match self.pacer.band_done(now, now.saturating_sub(began), more) {
            frame::Band::Go => {
                let _ = sys::notify(&self.notify, BAND);
            }
            // The cap of the period is reached: the next band waits for the
            // start of the next one, and the timer is armed by a step of its
            // own (ARM), so that the kernel call is not in the longest band.
            frame::Band::Defer(_) => {
                #[cfg(feature = "irq-trace")]
                px::cost::trace::mark_before_cap();
                let _ = sys::notify(&self.notify, ARM);
            }
        }
    }

    /// The frame goes to the driver, which answers at once and says the end
    /// by a bit: COMMIT of the rectangle for a frame composed in the
    /// target the screen shows; LAYERS with a row of the primary pipeline
    /// bound to the target, after bands over the whole screen, when the
    /// screen shows the pool; LAYERS bound to the pool, with the changed
    /// area, for a direct frame. It is the step after the last band (the
    /// first step of a direct frame) and no band is in it.
    fn commit(&mut self, damage: Rect) {
        let Some(owner) = &self.screen else {
            return;
        };
        let kind = self.scene.frame_kind();
        let mut request = Writer::new();
        let wrote = match kind {
            FrameKind::Compose => damage.write_as(Gpu::Commit, &mut request),
            FrameKind::Rebind => Layers::new(&[LayerRow::primary(
                self.primary.map_or(0, |p| p.id),
                SOURCE_TARGET,
                Some(SCREEN),
            )])
            .and_then(|layers| layers.write(&mut request)),
            FrameKind::Bypass => Layers::new(&[LayerRow::primary(
                self.primary.map_or(0, |p| p.id),
                SOURCE_POOL,
                Some(damage),
            )])
            .and_then(|layers| layers.write(&mut request)),
        };
        let sent = wrote
            .map_err(|_| Error::InvalidArgs)
            .and_then(|()| sys::send(owner, request.as_bytes()));
        match sent {
            Ok(reply) => {
                let mut buffer = [0; MESSAGE_MAX];
                if status_of(reply.bytes(&mut buffer)) == Some(Status::Ok) {
                    self.committed = true;
                    self.pacer.committed(now_ns());
                } else {
                    rt::println!("compositor: COMMIT refused");
                    // A driver that refuses the pool is asked no more: the
                    // frames are put together from now on.
                    if kind == FrameKind::Bypass {
                        self.scene.set_direct(false);
                    }
                    self.finish(false);
                }
            }
            Err(Error::PeerClosed) => self.driver_gone(),
            Err(_) => self.finish(false),
        }
    }

    /// The frame is shown (or the device refused it): the FLUSHes that
    /// waited are answered, the buffers it freed are told to their
    /// clients, the windows that went are lines of the log.
    fn finish(&mut self, shown: bool) {
        let shown_at = now_ns();
        rt::service::step_own();
        rt::service::step_detail(STEP_END);
        self.committed = false;
        let direct = self.scene.frame_kind() == FrameKind::Bypass;
        let ended = self.scene.end(shown);
        if self.scene.take_wake() {
            self.wake_worker();
        }
        // The time of the frame is counted at the beginning of the step in
        // which the service learned the device was done; a failed frame asks for
        // the timer again when a change waits.
        let wake = self.pacer.shown(shown_at, shown, direct);
        if !self.pacer.is_free() {
            self.arm(wake);
        }
        for (i, e) in ended.iter().enumerate() {
            if let Some(b) = e.freed
                && let Some(notify) = &self.extra[i].notify
            {
                let _ = sys::notify(notify, 1 << b);
            }
            if e.in_frame
                && let Some(pending) = self.extra[i].wait.take()
            {
                let status = if shown { Status::Ok } else { code(IO) };
                let _ = pending.answer(&proto_wire::reply(status), Outgoing::new());
            }
        }
        if shown {
            for _ in 0..core::mem::take(&mut self.released) {
                rt::println!("gpu: screen released");
            }
        }
        // The pool is cleared once the frame that unbound it is shown.
        self.start_clearing();
        self.kick();
    }

    // ------------------------------------------------------------ the windows

    /// The window at place `i` goes: what it waited for is refused
    /// (PEER_CLOSED), its buffers are unmapped by the mapper thread (the place is
    /// `dying` until the last one is done), its buffer, if it is of the first revision, is
    /// cleared a step at a time (its session of keyboard focus answers
    /// REVOKED from now on), and the place on the screen is shown again.
    fn destroy(&mut self, i: usize) {
        let Some(w) = self.scene.destroy(i) else {
            return;
        };
        if self.attaching.as_ref().is_some_and(|a| a.slot == i) {
            self.attaching = None;
        }
        let extra = &mut self.extra[i];
        extra.notify = None;
        extra.wait = None;
        extra.queued = None;
        // An order in flight for the window maps a buffer the window has not recorded yet.
        let in_flight = self.ordered.is_some_and(|o| o.slot == i);
        if in_flight || extra.mapped.iter().any(|&m| m != 0) {
            extra.dying = true;
        } else {
            *extra = Extra::new();
        }
        self.steer_mapper();
        if w.legacy {
            self.released += 1;
        }
        self.start_clearing();
        let _ = sys::notify(&self.notify, WORK);
        self.kick();
    }

    /// The clearing of the pool starts when the window of the first
    /// revision has gone and the display does not show the pool (the scene
    /// says so: after the frame that returned the screen to the target is
    /// shown, never before).
    fn start_clearing(&mut self) {
        if self.scene.take_pool_clear() {
            self.cleared = Some(0);
            let _ = sys::notify(&self.notify, WORK);
        }
    }

    /// The places that cannot take a new window: those whose pages are
    /// still being unmapped.
    fn taken(&self) -> u16 {
        let mut mask = 0;
        for (i, e) in self.extra.iter().enumerate() {
            if e.dying {
                mask |= 1 << i;
            }
        }
        mask
    }

    /// Whether a step of the work is due: clearing, unmapping, mapping.
    fn has_work(&self) -> bool {
        self.phase.has_work()
            || self.cleared.is_some()
            || matches!(self.pool, PoolState::Mapping { .. })
            || self.reaping.is_some()
            || self.next_order().is_some()
    }

    /// The jobs that wait for the mapper thread: the dying windows with buffers to unmap
    /// (the worker is not reading them) and the ATTACH in progress, each at the level of
    /// its client.
    fn mapper_waits(&self, waits: &mut [Wait; MAX_WINDOWS + 1]) -> usize {
        let mut n = 0;
        for i in 0..MAX_WINDOWS {
            let e = &self.extra[i];
            let in_flight = self.ordered.is_some_and(|o| o.slot == i);
            if e.dying
                && !in_flight
                && e.mapped.iter().any(|&m| m != 0)
                && !self.scene.worker_reads(i)
            {
                waits[n] = Wait {
                    slot: i,
                    level: e.level,
                    dying: true,
                };
                n += 1;
            }
        }
        if let Some(job) = &self.attaching {
            waits[n] = Wait {
                slot: job.slot,
                level: self.extra[job.slot].level,
                dying: false,
            };
            n += 1;
        }
        n
    }

    /// The order the mapper thread gets now, if it has none and a job waits.
    fn next_order(&self) -> Option<Pick> {
        let mapper = self.mapper.as_ref()?;
        let mut waits = [Wait {
            slot: 0,
            level: 1,
            dying: false,
        }; MAX_WINDOWS + 1];
        let n = self.mapper_waits(&mut waits);
        mapping::pick(!mapper.idle(), &waits[..n])
    }

    /// While the thread works on an order, the jobs that wait for it lend their level: it
    /// is raised to the highest of them.
    fn steer_mapper(&self) {
        let Some(mapper) = self.mapper.as_ref().filter(|m| !m.idle()) else {
            return;
        };
        let mut waits = [Wait {
            slot: 0,
            level: 1,
            dying: false,
        }; MAX_WINDOWS + 1];
        let n = self.mapper_waits(&mut waits);
        if let Some(level) = mapping::waiting_level(&waits[..n]) {
            mapper.raise(level);
        }
    }

    /// One step of the work: a piece of the legacy buffer cleared, else the next
    /// order of the mapper thread given (a dying window's buffer to unmap, else the
    /// buffer an ATTACH waits for). The thread's end of an order comes by its own
    /// bit (`mapped`), so a step that waits for it is not asked for again.
    fn work(&mut self) {
        rt::service::step_own();
        rt::service::step_detail(STEP_WORK);
        self.regrant();
        if self.phase.has_work() {
            self.open_step();
        } else if self.reaping.is_some() {
            self.reap_one();
        } else if let Some(done) = self.cleared {
            let len = CLEARED.min(POOL_LEN - done);
            // SAFETY: the service's own read and write mapping of the
            // legacy buffer, POOL_LEN long, of which `len` bytes from
            // `done` are in it; no window uses it while it is being
            // cleared (OPEN says CLEARING).
            unsafe { core::ptr::write_bytes((POOL_AT + done) as *mut u8, 0, len) };
            let done = done + len;
            self.cleared = (done < POOL_LEN).then_some(done);
            if self.cleared.is_none()
                && let PoolState::Ready(pool) = &mut self.pool
            {
                // A copy that is out can write after the clearing passed.
                let refs = sys::memory_info(&pool.handle).map_or(u64::MAX, |info| info.refs);
                pool.dirty = compositor::dirty_after_clearing(refs, pool.refs);
            }
        } else if matches!(self.pool, PoolState::Mapping { .. }) {
            self.map_pool_chunk();
        } else if let Some(pick) = self.next_order() {
            self.give_order(pick);
        }
        if self.has_work() {
            let _ = sys::notify(&self.notify, WORK);
        }
    }

    /// One window of the manager that went is destroyed; the last one ends the
    /// reaping.
    fn reap_one(&mut self) {
        let Some(label) = self.reaping else {
            return;
        };
        match (0..MAX_WINDOWS).find(|&i| self.scene.window(i).is_some_and(|w| w.ctx == label)) {
            Some(i) => self.destroy(i),
            None => self.reaping = None,
        }
    }

    /// Gives the mapper thread the order `pick` chose.
    fn give_order(&mut self, pick: Pick) {
        let Some(mapper) = self.mapper.as_ref() else {
            return;
        };
        match pick {
            Pick::Unmap(i) => {
                let extra = &mut self.extra[i];
                let Some(b) = (0..proto_comp::BUFFERS).find(|&b| extra.mapped[b] != 0) else {
                    return;
                };
                let first = order_first(extra.mapped[b]);
                let pages = extra.mapped[b] - first;
                match mapper.unmap(
                    extra.level,
                    (pages * PAGE) as u64,
                    buf_at(i, b) + first * PAGE,
                ) {
                    Ok(()) => {
                        self.ordered = Some(Ordered {
                            slot: i,
                            buffer: b,
                            unmap: true,
                            pages,
                        });
                        // The break gives the place back at the first order.
                        #[cfg(feature = "break-compositor-unmap-early")]
                        {
                            *extra = Extra::new();
                        }
                    }
                    Err(error) => {
                        // The mapping stays in its place, which no window takes any more
                        // than its own; the place is given back.
                        rt::println!("compositor: a buffer cannot be given back: {error:?}");
                        extra.mapped[b] = 0;
                        if extra.mapped.iter().all(|&m| m == 0) {
                            *extra = Extra::new();
                        }
                    }
                }
            }
            Pick::Attach => {
                let Some(job) = &self.attaching else {
                    return;
                };
                let (i, b) = (job.slot, job.buffer);
                let extra = &self.extra[i];
                let done = extra.mapped[b];
                let pages = order_pages(extra.pages[b] - done);
                let (offset, size) = ((done * PAGE) as u64, (pages * PAGE) as u64);
                let at = buf_at(i, b) + done * PAGE;
                // The break maps in the step, as a buffer of 256 pages that no order is.
                #[cfg(feature = "break-compositor-map-on-step")]
                {
                    let outcome = match &extra.memory[b] {
                        Some(memory) => {
                            sys::mem_map(&self.process, memory, offset, size, at, Access::Read)
                        }
                        None => Err(Error::BadState),
                    };
                    self.ordered = Some(Ordered {
                        slot: i,
                        buffer: b,
                        unmap: false,
                        pages,
                    });
                    self.order_done(outcome);
                }
                #[cfg(not(feature = "break-compositor-map-on-step"))]
                {
                    let ordered = match &extra.memory[b] {
                        Some(memory) => {
                            mapper.map(extra.level, memory, offset, size, at, Access::Read)
                        }
                        None => Err(Error::BadState),
                    };
                    match ordered {
                        Ok(()) => {
                            self.ordered = Some(Ordered {
                                slot: i,
                                buffer: b,
                                unmap: false,
                                pages,
                            })
                        }
                        Err(error) => self.attach_failed(i, error),
                    }
                }
            }
        }
    }

    /// The ATTACH of window `i` ends with the status of `error`, and the window goes.
    fn attach_failed(&mut self, i: usize, error: Error) {
        rt::println!("compositor: a buffer could not be mapped: {error:?}");
        if let Some(job) = self.attaching.take() {
            let _ = job.pending.answer(
                &proto_wire::reply(mapping::attach_status(error)),
                Outgoing::new(),
            );
        }
        self.destroy(i);
    }

    /// The mapper thread did its order: a buffer is mapped or unmapped. The last buffer of
    /// the ATTACH in progress ends it; the last unmapping of a window that went gives its
    /// place back.
    fn mapped(&mut self) {
        let Some(outcome) = self.mapper.as_ref().and_then(rt::mapper::Mapper::take) else {
            return;
        };
        self.order_done(outcome);
    }

    /// The order the thread had ended with `outcome`.
    fn order_done(&mut self, outcome: Result<(), Error>) {
        let Some(done) = self.ordered.take() else {
            return;
        };
        let (i, b) = (done.slot, done.buffer);
        let extra = &mut self.extra[i];
        if done.unmap {
            if let Err(error) = outcome {
                rt::println!("compositor: a buffer was not unmapped: {error:?}");
            }
            extra.mapped[b] -= done.pages.min(extra.mapped[b]);
        } else if let Err(error) = outcome {
            if extra.dying {
                // The window went while its buffer was being mapped.
                if extra.mapped.iter().all(|&m| m == 0) {
                    *extra = Extra::new();
                }
            } else {
                self.attach_failed(i, error);
            }
        } else {
            extra.mapped[b] += done.pages;
            if !extra.dying && extra.mapped[b] == extra.pages[b] {
                self.attach_next();
            }
        }
        let extra = &mut self.extra[i];
        if extra.dying && extra.mapped.iter().all(|&m| m == 0) {
            *extra = Extra::new();
        }
        if self.has_work() {
            let _ = sys::notify(&self.notify, WORK);
        }
    }

    /// A buffer of the ATTACH in progress is mapped: the next one is ordered by the next step,
    /// the last one ends the ATTACH with its reply.
    fn attach_next(&mut self) {
        let Some(job) = self.attaching.as_mut() else {
            return;
        };
        job.buffer += 1;
        if job.buffer < job.count as usize {
            return;
        }
        let Some(job) = self.attaching.take() else {
            return;
        };
        let status = match self
            .scene
            .attach_sized(job.slot, job.count, job.stride, job.bytes)
        {
            Ok(()) => Status::Ok,
            Err(refusal) => Compositor::refusal(refusal),
        };
        let _ = job
            .pending
            .answer(&proto_wire::reply(status), Outgoing::new());
    }

    /// The window a request's session names, and the reason it has none.
    fn window_of(&self, label: u64) -> Result<usize, Answer> {
        self.scene
            .find(label)
            .ok_or(Answer::Status(proto_comp::code(proto_comp::REVOKED)))
    }

    /// The refusal of a method the session is not for, in the code of the
    /// method's own protocol.
    fn not_allowed(comp: bool) -> Answer {
        Answer::Status(if comp {
            proto_comp::code(proto_comp::NOT_ALLOWED)
        } else {
            code(NOT_ALLOWED)
        })
    }

    fn refusal(r: Refusal) -> Status {
        match r {
            Refusal::Limit => proto_gpu::LIMIT,
            Refusal::Invalid => proto_comp::code(proto_comp::INVALID),
            Refusal::Busy => proto_comp::code(proto_comp::BUSY),
            Refusal::NotAllowed => proto_comp::code(proto_comp::NOT_ALLOWED),
            Refusal::Unsupported => proto_comp::code(proto_comp::UNSUPPORTED),
        }
    }

    /// A new session for a window: its label and the handle.
    fn window_session(&mut self) -> Result<(u64, Handle<Channel>), Error> {
        self.serial += 1;
        let label = WINDOW | self.serial;
        let rights = Rights::SEND | Rights::TRANSFER;
        let session = sys::handle_label(&self.channel, rights, label, self.level)?;
        Ok((label, session))
    }

    /// The session of keyboard focus of the window of the first revision
    /// with label `window`.
    fn keys_session(&mut self, window: u64) -> Result<Handle<Channel>, Error> {
        let rights = Rights::SEND | Rights::TRANSFER;
        sys::handle_label(&self.channel, rights, window | WINDOW_KEYS, self.level)
    }

    // ------------------------------------------------------------ the methods

    /// OPEN of a `Display` session (proto_gpu): a window of the whole
    /// screen, the buffer the service made, the window's session and the
    /// focus.
    fn open(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if let Err(status) = self.open_screen(true) {
            return Answer::Status(status);
        }
        if self.scene.has_legacy() {
            return Answer::Status(code(BUSY));
        }
        // The pool is the window's buffer. A client that closed its window and
        // kept its handle, mapped or not, or sent a copy on, still reaches
        // it: the service holds the only references it may have, its handle
        // and its mapping, and a program that kept its mapping can write
        // after the clearing passed, so the pool is cleared again once the
        // copy is gone (`compositor::pool_open`).
        if matches!(self.pool, PoolState::Retry) {
            // The driver said BUSY at the opening of the screen: ask again.
            let asked = match self.screen.take() {
                Some(owner) => {
                    let asked = self.ask_pool(&owner);
                    self.screen = Some(owner);
                    asked
                }
                None => Err("no screen"),
            };
            return Answer::Status(if asked.is_ok() {
                code(CLEARING)
            } else {
                code(BUSY)
            });
        }
        let decision = match &self.pool {
            PoolState::Ready(pool) => {
                let refs = sys::memory_info(&pool.handle).map_or(pool.refs, |info| info.refs);
                compositor::pool_open(
                    refs,
                    pool.refs,
                    pool.dirty,
                    self.cleared.is_some(),
                    self.scene.pool_release_pending(),
                )
            }
            PoolState::Mapping { .. } => compositor::PoolOpen::Clearing,
            PoolState::None | PoolState::Retry => compositor::PoolOpen::Busy,
        };
        match decision {
            compositor::PoolOpen::Busy => return Answer::Status(code(BUSY)),
            compositor::PoolOpen::Clearing => return Answer::Status(code(CLEARING)),
            compositor::PoolOpen::StartClearing => {
                self.cleared = Some(0);
                let _ = sys::notify(&self.notify, WORK);
                return Answer::Status(code(CLEARING));
            }
            compositor::PoolOpen::Go => {}
        }
        let Ok((label, session)) = self.window_session() else {
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let taken = self.taken();
        let i = match self.scene.create(label, r.label(), SCREEN, true, taken) {
            Ok(i) => i,
            Err(refusal) => return Answer::Status(Compositor::refusal(refusal)),
        };
        // The keyboard's focus is the compositor's always; the program reads
        // the keys of its window from a session of the compositor's own, so
        // they go to it while the window has the focus. An image without a
        // keyboard has none to give.
        if self.keys.own.is_none() {
            self.take_own(Which::Keys);
        }
        let focus = if self.keys.own.is_some() {
            self.keys_session(label).ok()
        } else {
            None
        };
        let status = if focus.is_some() {
            Status::Ok
        } else {
            code(NO_INPUT)
        };
        if Screen::FIXED.write(status, r.reply()).is_err() {
            self.destroy(i);
            return Answer::Status(Status::BadSize);
        }
        let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
        let client = match &mut self.pool {
            PoolState::Ready(pool) => {
                let copy = sys::handle_duplicate(&pool.handle, rights).ok();
                // A copy is out: the program may write into the pool.
                pool.dirty |= copy.is_some();
                copy
            }
            _ => None,
        };
        let Some(client) = client else {
            self.destroy(i);
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let mut handles: Outgoing = [client.erase(), session.erase()].into();
        if let Some(focus) = focus {
            let _ = handles.push(focus.erase());
        }
        Answer::Reply(handles)
    }

    /// FLUSH of a window of the first revision: the rectangle is posted and
    /// the reply waits for the frame that shows it.
    fn flush(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        let rect = match Rect::read(r.body()) {
            Ok(rect) => rect,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if self.extra[i].queued.is_some() {
            return Answer::Status(proto_gpu::LIMIT);
        }
        if let Err(refusal) = self.scene.flush(i, rect) {
            return Answer::Status(Compositor::refusal(refusal));
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        self.extra[i].queued = Some(pending);
        self.kick();
        Answer::Deferred
    }

    /// CLOSE of a window of the first revision.
    fn close(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        self.destroy(i);
        Answer::Status(Status::Ok)
    }

    /// CLONE: a new `Display` session for a child of the client.
    fn clone_session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Ok(label) = self.clones.give(OWN, r.label()) else {
            return Answer::Status(proto_gpu::LIMIT);
        };
        let rights = Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER;
        match sys::handle_label(&self.channel, rights, label, self.level) {
            Ok(session) => {
                if r.reply().u32(Status::Ok.code()).is_err() {
                    self.clones.gone(label);
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(error) => {
                self.clones.gone(label);
                Answer::Status(Status::Kernel(error))
            }
        }
    }

    /// DESCRIBE.
    fn describe(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if let Err(status) = self.open_screen(true) {
            return Answer::Status(status);
        }
        let d = Description {
            width: WIDTH,
            height: HEIGHT,
            format: proto_comp::FORMAT_XRGB8888,
            flags: (u32::from(self.scene.has_manager()) * proto_comp::HAS_MANAGER)
                | (u32::from(self.scene.cursor_plane()) * proto_comp::CURSOR_PLANE)
                | (u32::from(!self.scene.prepared()) * proto_comp::NO_IMAGE_WORKER),
            open: self.scene.open(),
            created: self.scene.created(),
            frames: self.scene.frames(),
            busy: u32::from(self.scene.busy()),
            bypassed: self.scene.bypassed(),
            bands: self.scene.bands(),
        };
        match d.write(r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// WINDOW_CREATE: a window of the context `r.label()`, its session and
    /// number.
    fn window_create(&mut self, r: &mut Request<'_>) -> Answer {
        let create = match Create::read(r.body()) {
            Ok(create) => create,
            Err(status) => return Answer::Status(status),
        };
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Some(format) = format_of(create.format) else {
            return Answer::Status(proto_comp::code(proto_comp::UNSUPPORTED));
        };
        if create.flags != 0 {
            return Answer::Status(proto_comp::code(proto_comp::UNSUPPORTED));
        }
        if !create.fits(WIDTH, HEIGHT) {
            return Answer::Status(proto_comp::code(proto_comp::INVALID));
        }
        let Ok(notify) = r.handles.take::<Channel>(0) else {
            return Answer::Status(proto_comp::code(proto_comp::INVALID));
        };
        if let Err(status) = self.open_screen(true) {
            return Answer::Status(status);
        }
        let Ok((label, session)) = self.window_session() else {
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let rect = Rect {
            x: create.x,
            y: create.y,
            w: create.w,
            h: create.h,
        };
        let taken = self.taken();
        let manager = is_manager(r.label());
        let i = match self
            .scene
            .create_as(label, r.label(), rect, false, taken, manager)
        {
            Ok(i) => i,
            Err(refusal) => return Answer::Status(Compositor::refusal(refusal)),
        };
        self.scene.set_format(i, format);
        self.extra[i].notify = Some(notify);
        // The manager hears of the new window.
        self.deliver();
        let wrote = r
            .reply()
            .u32(Status::Ok.code())
            .and_then(|()| r.reply().u32(self.scene.window(i).map_or(0, |w| w.id)));
        if wrote.is_err() {
            self.destroy(i);
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply([session.erase()].into())
    }

    /// ATTACH: the buffers of window `i`, once.
    fn attach(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        let attach = match Attach::read(r.body()) {
            Ok(attach) => attach,
            Err(status) => return Answer::Status(status),
        };
        if r.handles.len() != attach.count as usize {
            return Answer::Status(Status::BadSize);
        }
        let Some(w) = self.scene.window(i).copied() else {
            return Answer::Status(proto_comp::code(proto_comp::REVOKED));
        };
        // The buffers are of the window's format.
        if format_of(attach.format) != Some(w.format) {
            return Answer::Status(proto_comp::code(proto_comp::UNSUPPORTED));
        }
        if w.attached != 0 {
            return Answer::Status(proto_comp::code(proto_comp::BUSY));
        }
        if u64::from(attach.stride) < w.format.line(w.rect.w)
            || (w.format == Format::A8 && !attach.stride.is_multiple_of(4))
            || attach.bytes(w.rect.h) > BUFFER_MAX
        {
            return Answer::Status(proto_comp::code(proto_comp::INVALID));
        }
        if self.attaching.is_some() {
            return Answer::Status(proto_comp::code(proto_comp::BUSY));
        }
        if self.mapper.is_none() {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let need = attach.bytes(w.rect.h);
        // The objects are looked at here, in this step; they are mapped a
        // buffer at a time by the mapper thread, and the reply waits for the
        // last. All of an object is mapped: what it holds beyond the window's lines is the
        // capacity the window can be resized to.
        let mut memory: [Option<Handle<Memory>>; proto_comp::BUFFERS] = [const { None }; 3];
        let mut pages = [0; proto_comp::BUFFERS];
        let mut held = u64::MAX;
        for b in 0..attach.count as usize {
            let Ok(object) = r.handles.take::<Memory>(b) else {
                return Answer::Status(proto_comp::code(proto_comp::INVALID));
            };
            let size = match sys::memory_info(&object) {
                Ok(info) if info.size >= need && info.size <= BUFFER_MAX => info.size,
                _ => return Answer::Status(proto_comp::code(proto_comp::INVALID)),
            };
            held = held.min(size);
            pages[b] = (size as usize).div_ceil(PAGE);
            memory[b] = Some(object);
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let extra = &mut self.extra[i];
        extra.memory = memory;
        extra.pages = pages;
        extra.level = r.level().clamp(1, prep::LEVEL_MAX);
        self.attaching = Some(Attaching {
            slot: i,
            count: attach.count as u8,
            stride: attach.stride,
            bytes: held,
            buffer: 0,
            pending,
        });
        self.steer_mapper();
        let _ = sys::notify(&self.notify, WORK);
        Answer::Deferred
    }

    /// POST: a buffer of window `i` is the window's next.
    fn post(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        let post = match Post::read(r.body()) {
            Ok(post) => post,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Ok(buffer) = u8::try_from(post.buffer) else {
            return Answer::Status(proto_comp::code(proto_comp::INVALID));
        };
        let rects = &post.rects[..post.count as usize];
        let now = now_ns();
        let posted = if self.pacer.is_free() {
            self.scene.post(i, buffer, rects).map(|r| (r, None))
        } else {
            self.scene
                .post_paced(i, buffer, rects, self.pacer.clock(), now)
        };
        match posted {
            Ok((replaced, due)) => {
                if let Some(b) = replaced
                    && let Some(notify) = &self.extra[i].notify
                {
                    let _ = sys::notify(notify, 1 << b);
                }
                // The posted buffer's image is made here: the first band that
                // reads the buffer would pay for it (a few hundred ticks a
                // layer, and a band of eight windows has eight).
                if let Some(w) = self.scene.window(i).copied() {
                    let pixels = Pixels(&self.scene);
                    let src = pixels.pixels(i, buffer);
                    // The size the buffer will have when a frame takes it.
                    self.raster.prepare(
                        src,
                        w.stride,
                        w.format,
                        self.scene.posted_size(i),
                        compositor::image_of(i, buffer),
                    );
                }
                // The images of the elements that turn or stretch the window are
                // behind now: the worker makes them at the poster's level, and the
                // frame shows them when they are ready.
                if self
                    .scene
                    .note_post(i, buffer, rects, r.level().min(prep::LEVEL_MAX))
                {
                    self.wake_worker();
                }
                // A window with an interval is due at its start, whatever else
                // is waiting for a frame.
                if let Some(e) = due {
                    let wake = self.pacer.change(now, Some(e));
                    self.arm(wake);
                }
                self.kick();
                Answer::Status(Status::Ok)
            }
            Err(refusal) => Answer::Status(Compositor::refusal(refusal)),
        }
    }

    /// SET of window `i`: the interval it promises between its posts.
    fn set(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        let set = match SetBody::read(r.body()) {
            Ok(set) => set,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        // The window of the first revision has no interval.
        if self.scene.window(i).is_none_or(|w| w.legacy) {
            return Answer::Status(proto_comp::code(proto_comp::NOT_ALLOWED));
        }
        let set_ok = self
            .scene
            .pace_mut(i)
            .is_some_and(|pace| pace.set_interval(set.value));
        if set_ok {
            Answer::Status(Status::Ok)
        } else {
            Answer::Status(proto_comp::code(proto_comp::INVALID))
        }
    }

    /// SET_TEXT of window `i`: its title or the kind of its application.
    fn set_text(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        let text = match SetText::read(r.body()) {
            Ok(text) => text,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let told = self.scene.set_text(i, text.which, text.text());
        self.deliver();
        match told {
            Ok(()) => Answer::Status(Status::Ok),
            Err(refusal) => Answer::Status(Compositor::refusal(refusal)),
        }
    }

    /// SIZE of window `i`: the size of its next POST.
    fn size(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        let size = match Size::read(r.body()) {
            Ok(size) => size,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        match self.scene.set_size(i, size.w, size.h, size.serial) {
            Ok(()) => Answer::Status(Status::Ok),
            Err(refusal) => Answer::Status(Compositor::refusal(refusal)),
        }
    }

    /// The worker thread, made once when the service starts. False when it cannot be
    /// made (it is tried once, and the service says so on the console): the images
    /// are not made then and the elements that need them show nothing.
    fn start_worker(&mut self) -> bool {
        if self.worker.is_some() {
            return true;
        }
        if core::mem::replace(&mut self.worker_tried, true) {
            return false;
        }
        if !self.make_worker() {
            // Without a worker the elements are drawn by the bands, as before.
            self.scene.clear_prep();
            return false;
        }
        true
    }

    fn make_worker(&mut self) -> bool {
        let Ok(wait) = sys::channel_create_wait(1) else {
            rt::println!("compositor: no channel for the prepared images");
            return false;
        };
        let Ok(wake) = sys::handle_label(&wait, Rights::NOTIFY, 1, 1) else {
            rt::println!("compositor: no handle for the prepared images");
            return false;
        };
        WORKER_WAIT.store(wait.raw().0, Ordering::Release);
        WORKER_TELL.store(self.notify.raw().0, Ordering::Release);
        // SAFETY: WORKER_STACK is the worker's alone, and the page after the main
        // thread's message buffer is free.
        let thread = unsafe {
            sys::thread_create(
                &self.process,
                worker_main,
                WORKER_STACK.top(),
                0,
                1,
                rt::abi::Policy::Fifo,
                WORKER_BUFFER,
            )
        };
        let Ok(thread) = thread else {
            rt::println!("compositor: no thread for the prepared images");
            return false;
        };
        if sys::thread_start(&thread).is_err() {
            rt::println!("compositor: the thread for the prepared images did not start");
            return false;
        }
        self.worker = Some(Worker {
            thread,
            _wait: wait,
            wake,
        });
        true
    }

    /// The worker's level is the service's to set, and the service sets it here only:
    /// the level of the highest slot that wants the worker or that it holds (the level
    /// of the client that posted, capped at 31), or `at_least` (a commit the service
    /// refused with BUSY), or 1 when there is no work. Called on the request path
    /// when work comes and when the worker says it let go or went idle, so that the
    /// worker is never lowered under work it has.
    fn steer_worker(&mut self, at_least: u8) {
        let Some(worker) = &self.worker else {
            return;
        };
        let level = TABLE
            .top_level()
            .unwrap_or(1)
            .max(at_least)
            .max(self.busy_boost)
            .min(prep::LEVEL_MAX);
        if level != TABLE.worker_level()
            && sys::thread_set_priority(&worker.thread, level, rt::abi::Policy::Fifo).is_ok()
        {
            TABLE.set_worker_level(level);
        }
    }

    /// The worker is raised to the level of the work that waits, and told.
    fn wake_worker(&mut self) {
        if !self.start_worker() {
            return;
        }
        self.steer_worker(0);
        if let Some(worker) = &self.worker {
            let _ = sys::notify(&worker.wake, 1);
        }
    }

    /// The worker let go of something or drew an image (PREP): the buffers whose free
    /// waited for it are free and told to their clients, the pages of the slots it
    /// held are free, the images it published are known to the raster and the screen
    /// is damaged where an element shows them, and the windows whose unmapping waited
    /// go on.
    fn prep_done(&mut self) {
        TABLE.undefer();
        let freed = self.scene.release_owed();
        for (i, bits) in freed.into_iter().enumerate() {
            if bits != 0
                && let Some(notify) = &self.extra[i].notify
            {
                let _ = sys::notify(notify, u64::from(bits));
            }
        }
        TABLE.reap();
        // One image a step: the raster wraps it now, so that no band does, and
        // the screen is damaged where an element shows it. The rest wait for the
        // service's own bit.
        if let Some((slot, local)) = TABLE.take_drawn() {
            if let Some(image) = TABLE.front_of(slot) {
                let g = TABLE.geometry(slot);
                self.raster.prepare(
                    TABLE.image(slot, image),
                    g.stride(),
                    if g.key.argb {
                        Format::Argb
                    } else {
                        Format::Xrgb
                    },
                    (g.w, g.h),
                    usize::MAX,
                );
            }
            self.scene.images_drawn(&[(slot, local)]);
            // A scene that waited for its images is taken now.
            self.kick();
        }
        if TABLE.drawn_waits() {
            let _ = sys::notify(&self.notify, PREP);
        }
        // The raise for a commit refused with BUSY ends when the pages are free.
        if TABLE.zombies_left() == 0 {
            self.busy_boost = 0;
        }
        // The worker lets go or goes idle: its level follows the work that is left.
        self.steer_worker(0);
        if self.extra.iter().any(|e| e.dying) {
            let _ = sys::notify(&self.notify, WORK);
        }
    }

    /// STATS: the counters of the frame clock and the records of the windows
    /// the session may see (its own window, the windows of its context, or all
    /// for the manager and the input). RESET is for the last two alone.
    fn stats(&mut self, r: &mut Request<'_>, scope: Scope) -> Answer {
        let flags = match read_stats_request(r.body()) {
            Ok(flags) => flags,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let reset = flags & RESET != 0;
        if reset && !matches!(scope, Scope::All) {
            return Answer::Status(proto_comp::code(proto_comp::NOT_ALLOWED));
        }
        let now = now_ns();
        // The phases of the first late frame of the count not told yet, one a
        // step (a line costs about 7 000 ticks, and the step stays under its
        // gate), for the report of the probe. A RESET starts a count and tells
        // nothing.
        if !reset && let Some(late) = self.pacer.next_late() {
            rt::println!(
                "compositor: late frame period {} take {} us compose {} us device {} us frame {} us (the longest: {})",
                late.k,
                late.take_ns / 1_000,
                late.compose_ns / 1_000,
                late.device_ns / 1_000,
                late.frame_ns() / 1_000,
                late.cause()
            );
        }
        let mut records = [WindowStats::default(); STATS_WINDOWS];
        let mut count = 0;
        for i in 0..MAX_WINDOWS {
            let visible = self.scene.window(i).is_some_and(|w| match scope {
                Scope::Window(only) => only == i,
                Scope::Context(label) => w.ctx == label,
                Scope::All => true,
            });
            // A window that was awaited and passed its start is a miss, whoever
            // asks.
            if !self.pacer.is_free()
                && let Some(pace) = self.scene.pace_mut(i)
            {
                pace.settle(self.pacer.clock(), now);
            }
            if visible && let Some(pace) = self.scene.pace(i) {
                records[count] = pace.record(self.scene.window(i).map_or(i as u32, |w| w.id));
                count += 1;
            }
        }
        let reply = StatsReply::new(self.pacer.stats(now), &records[..count])
            .and_then(|reply| reply.write(r.reply()));
        if let Err(status) = reply {
            return Answer::Status(status);
        }
        if reset {
            self.pacer.counters.reset(now);
            for i in 0..MAX_WINDOWS {
                if let Some(pace) = self.scene.pace_mut(i) {
                    pace.reset_counts();
                }
            }
        }
        Answer::Reply(Outgoing::new())
    }

    /// EVENTS of window `i`.
    fn events_of_window(&mut self, i: usize, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut out = [Event::default(); MAX_EVENTS];
        let (n, lost) = self.scene.take_events(i, &mut out);
        match proto_comp::write_events(&out[..n], lost, r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// READ of a window's session of keyboard focus (proto_input): the keys
    /// in the window's ring, none when it has not the focus, REVOKED once
    /// the window is gone.
    fn read_keys(&mut self, label: u64, method: u16, r: &mut Request<'_>) -> Answer {
        if method != InputMethod::Read.number() {
            return Answer::Status(proto_input::code(proto_input::NOT_ALLOWED));
        }
        let max = match proto_input::read_max(r.body()) {
            Ok(max) if r.handles.is_empty() => max as usize,
            Ok(_) => return Answer::Status(Status::BadSize),
            Err(status) => return Answer::Status(status),
        };
        let Some(i) = self.scene.find(label & !WINDOW_KEYS) else {
            return Answer::Status(proto_input::code(proto_input::REVOKED));
        };
        let mut keys = [Event::default(); proto_comp::RING];
        let n = max.min(keys.len());
        let (n, lost) = self.scene.take_keys(i, &mut keys[..n]);
        let mut out = [proto_input::Event::default(); proto_comp::RING];
        for (to, from) in out.iter_mut().zip(&keys[..n]) {
            *to = proto_input::Event::key(from.code, from.value != 0);
        }
        match proto_input::write_events(&out[..n], lost, r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// The requests of the manager's session: EVENTS of its ring and MANAGE.
    fn manager_request(&mut self, method: u16, r: &mut Request<'_>) -> Answer {
        match Comp::from_number(method) {
            Some(Comp::Events) => {
                if r.body().finish().is_err() || !r.handles.is_empty() {
                    return Answer::Status(Status::BadSize);
                }
                let mut out = [Event::default(); MAX_EVENTS];
                let (n, lost) = self.scene.take_manager_events(&mut out);
                match proto_comp::write_events(&out[..n], lost, r.reply()) {
                    Ok(()) => Answer::Reply(Outgoing::new()),
                    Err(status) => Answer::Status(status),
                }
            }
            Some(Comp::Manage) => self.manage(r),
            Some(Comp::Describe) => self.describe(r),
            Some(Comp::Stats) => self.stats(r, Scope::All),
            // The session of the manager is a context too: its windows are its
            // panel and the frames of the windows it manages.
            Some(Comp::WindowCreate) => self.window_create(r),
            _ => Compositor::not_allowed(Comp::from_number(method).is_some()),
        }
    }

    /// MANAGE: the manager's operations on the windows.
    fn manage(&mut self, r: &mut Request<'_>) -> Answer {
        let [op, a, b, c] = match proto_comp::read_manage(r.body()) {
            Ok(n) => n,
            Err(status) => return Answer::Status(status),
        };
        if (op == manage::SUBSCRIBE) != (r.handles.len() == 1) || r.handles.len() > 1 {
            return Answer::Status(Status::BadSize);
        }
        let scene = is_scene(r.label());
        // The scene's holder is the one manager once it has subscribed or has
        // committed a scene.
        if !compositor::manage_allowed(self.holder(), self.scene_label != 0, scene) {
            return Answer::Status(proto_comp::code(proto_comp::NOT_ALLOWED));
        }
        // The window of an id: the live window that has it (a window that went
        // has no id any more, though its place may hold another window).
        let id = self.scene.place_of(a).unwrap_or(usize::MAX);
        let result = match op {
            manage::SUBSCRIBE => {
                let same = self.manager.is_some() && self.manager_label == r.label();
                if !compositor::subscribe_allowed(self.holder(), scene, same) {
                    return Answer::Status(proto_comp::code(proto_comp::BUSY));
                }
                let Ok(notify) = r.handles.take::<Channel>(0) else {
                    return Answer::Status(proto_comp::code(proto_comp::INVALID));
                };
                self.manager = Some(notify);
                self.manager_label = r.label();
                self.manager_scene = scene;
                self.scene.set_manager(true);
                Ok(())
            }
            manage::LIST => return self.list(r),
            manage::INFO => return self.info(id, r),
            manage::MOVE => self.scene.move_to(id, b, c),
            manage::RAISE => self.scene.raise(id),
            manage::FOCUS => self.scene.focus_on(id),
            manage::CONFIGURE => {
                let (w, h) = manage::unsize(b);
                self.scene.configure(id, w, h, c)
            }
            manage::CLOSE => self.scene.close_request(id),
            manage::LINK if b == NO_WINDOW => self.scene.link(id, None),
            manage::LINK => match self.scene.place_of(b) {
                Some(follower) => self.scene.link(id, Some(follower)),
                None => Err(Refusal::Invalid),
            },
            _ => self.scene.set_visible(id, b != 0),
        };
        // `kick` tells the rings that got CONFIGURE or CLOSE_REQUEST.
        self.kick();
        match result {
            Ok(()) => Answer::Status(Status::Ok),
            Err(refusal) => Answer::Status(Compositor::refusal(refusal)),
        }
    }

    /// INFO: the flags, the capacity and the texts of the window at place `id`
    /// (`usize::MAX` for an id that names none).
    fn info(&mut self, id: usize, r: &mut Request<'_>) -> Answer {
        let Some(info) = self.scene.info(id) else {
            return Answer::Status(proto_comp::code(proto_comp::INVALID));
        };
        match info.write(r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// LIST: the windows, each with its place, its flags and its depth.
    fn list(&mut self, r: &mut Request<'_>) -> Answer {
        let (order, n) = self.scene.by_depth();
        let mut records = [WindowRecord::default(); MAX_WINDOWS];
        for (depth, &k) in order[..n].iter().enumerate() {
            let Some(w) = self.scene.window(k as usize) else {
                continue;
            };
            let mut flags = 0;
            if w.visible && w.current.is_some() {
                flags |= SHOWN;
            }
            if self.scene.focus() == Some(k as usize) {
                flags |= FOCUSED;
            }
            records[depth] = WindowRecord {
                id: w.id,
                x: w.rect.x,
                y: w.rect.y,
                w: w.rect.w,
                h: w.rect.h,
                flags,
                depth: depth as u32,
            };
        }
        match proto_comp::write_list(&records[..n], r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// Who holds the subscription to the manager's ring.
    fn holder(&self) -> compositor::Holder {
        match (self.manager.is_some(), self.manager_scene) {
            (false, _) => compositor::Holder::Unsubscribed,
            (true, false) => compositor::Holder::Manager,
            (true, true) => compositor::Holder::Scene,
        }
    }

    /// SCENE_COMMIT: the scene of the session's windows (proto_comp).
    fn scene_commit(&mut self, r: &mut Request<'_>) -> Answer {
        // The scene is parsed into the place the scenes keep for it, with no
        // copy of a whole scene (a copy is a loop of bytes on this target).
        let flags = match self.scene.commit_slot().parse(r.body()) {
            Ok(flags) => flags,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if !compositor::scene_allowed(self.holder())
            || (self.scene_label != 0 && self.scene_label != r.label())
        {
            return Answer::Status(proto_comp::code(proto_comp::BUSY));
        }
        self.scene.set_period(if self.pacer.is_free() {
            u64::MAX
        } else {
            self.pacer.clock().index(now_ns())
        });
        if let Err(refusal) = self.scene.commit_done_at(
            flags & proto_comp::ASK_COMMITTED != 0,
            r.level().min(prep::LEVEL_MAX),
        ) {
            // BUSY: the images fit once the worker lets go of the slots it holds; it
            // runs at the commit's level until it does.
            if refusal == Refusal::Busy {
                // The raise stays until the pages are free (`prep_done`), so that a
                // lowering for other work does not undo it early.
                self.busy_boost = self.busy_boost.max(r.level().min(prep::LEVEL_MAX));
                self.steer_worker(0);
            }
            return Answer::Status(Compositor::refusal(refusal));
        }
        self.scene_label = r.label();
        if TABLE.work_waits() {
            self.wake_worker();
        }
        self.kick();
        Answer::Status(Status::Ok)
    }

    /// SCENE_COMPOSE: the frame of a scene that is composed on request.
    fn scene_compose(&mut self, r: &mut Request<'_>) -> Answer {
        let flags = match read_scene_compose(r.body()) {
            Ok(flags) => flags,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if !compositor::scene_allowed(self.holder())
            || (self.scene_label != 0 && self.scene_label != r.label())
        {
            return Answer::Status(proto_comp::code(proto_comp::BUSY));
        }
        if let Err(refusal) = self
            .scene
            .scene_compose(flags & proto_comp::ASK_COMPOSED != 0)
        {
            return Answer::Status(Compositor::refusal(refusal));
        }
        self.scene_label = r.label();
        self.kick();
        Answer::Status(Status::Ok)
    }

    /// INJECT: an event as a device would have made it.
    fn inject(&mut self, r: &mut Request<'_>) -> Answer {
        let event = match Event::read_inject(r.body()) {
            Ok(event) => event,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        self.scene.inject(event);
        self.move_cursor();
        self.kick();
        Answer::Status(Status::Ok)
    }
}

/// The methods of the service: proto_gpu's first revision (OPEN, FLUSH,
/// CLOSE, CLONE) and proto_comp's.
const METHODS: &[u16] = &[
    Gpu::Open.number(),
    Gpu::Flush.number(),
    Gpu::Close.number(),
    Gpu::Clone.number(),
    Comp::Describe.number(),
    Comp::WindowCreate.number(),
    Comp::Attach.number(),
    Comp::Post.number(),
    Comp::Events.number(),
    Comp::Manage.number(),
    Comp::Inject.number(),
    Comp::Set.number(),
    Comp::Stats.number(),
    Comp::SceneCommit.number(),
    Comp::SceneCompose.number(),
    Comp::SetText.number(),
    Comp::Size.number(),
];

/// Which windows a STATS shows its session.
enum Scope {
    Window(usize),
    Context(u64),
    All,
}

impl Service<1> for Compositor {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        let label = r.label();
        let method = r.method();
        let gpu = Gpu::from_number(method);
        let comp = Comp::from_number(method);
        if is_manager(label) {
            // A manager that is a process of POSIX (`desk`) starts programs: each
            // gets a clone of the session (CLONE, which `posix_spawn` asks), an
            // ordinary context's session with no mark of the manager's.
            if gpu == Some(Gpu::Clone) {
                return self.clone_session(r);
            }
            return self.manager_request(method, r);
        }
        if is_scene(label) {
            // The holder of a scene: its own methods and the manager's, and
            // then what any context may.
            match comp {
                Some(Comp::SceneCommit) => return self.scene_commit(r),
                Some(Comp::SceneCompose) => return self.scene_compose(r),
                Some(Comp::Events | Comp::Manage) => return self.manager_request(method, r),
                _ => {}
            }
        }
        if is_input(label) {
            return match comp {
                Some(Comp::Inject) => self.inject(r),
                Some(Comp::Describe) => self.describe(r),
                Some(Comp::Stats) => self.stats(r, Scope::All),
                _ => Compositor::not_allowed(comp.is_some()),
            };
        }
        if is_window_keys(label) {
            return self.read_keys(label, method, r);
        }
        if is_window(label) {
            // A window's session: ATTACH and POST of a window with buffers
            // of its own, FLUSH and CLOSE of the window of the first
            // revision.
            let i = match self.window_of(label) {
                Ok(i) => i,
                Err(answer) => return answer,
            };
            return match (gpu, comp) {
                (Some(Gpu::Flush), _) => self.flush(i, r),
                (Some(Gpu::Close), _) => self.close(i, r),
                (_, Some(Comp::Attach)) => self.attach(i, r),
                (_, Some(Comp::Post)) => self.post(i, r),
                (_, Some(Comp::Events)) => self.events_of_window(i, r),
                (_, Some(Comp::Set)) => self.set(i, r),
                (_, Some(Comp::SetText)) => self.set_text(i, r),
                (_, Some(Comp::Size)) => self.size(i, r),
                (_, Some(Comp::Stats)) => self.stats(r, Scope::Window(i)),
                _ => Compositor::not_allowed(comp.is_some()),
            };
        }
        match (gpu, comp) {
            (Some(Gpu::Open), _) => self.open(r),
            (Some(Gpu::Clone), _) => self.clone_session(r),
            (_, Some(Comp::Describe)) => self.describe(r),
            (_, Some(Comp::WindowCreate)) => self.window_create(r),
            (_, Some(Comp::Stats)) => self.stats(r, Scope::Context(label)),
            _ => Compositor::not_allowed(comp.is_some()),
        }
    }

    /// The last copy of a session went. A window's takes the window; a
    /// context's (the process ended, or `exec` closed it) takes all its
    /// windows, and a clone's frees its place.
    fn closed(&mut self, label: u64) {
        if label == DRIVER {
            return;
        }
        if let Some(which) = Compositor::device_label(label) {
            // The driver of an input device ended with the grant it held:
            // the focus is to be taken again, from its next instance.
            let device = self.device(which);
            if label & GENERATION == device.generation {
                device.own = None;
                device.link = Link::Lost;
                let _ = sys::notify(&self.notify, WORK);
            }
            return;
        }
        if is_manager(label) || is_scene(label) {
            if label == self.manager_label {
                self.manager = None;
                self.manager_label = 0;
                self.manager_scene = false;
                self.scene.set_manager(false);
            }
            // The windows of the manager's session go with it (a scene's go
            // below): the windows they framed stay where they are.
            if !is_scene(label) {
                // A manager that went before the last one's windows were all
                // destroyed finishes them now (rare); the new one goes a step
                // a window.
                if let Some(old) = self.reaping.replace(label) {
                    for i in 0..MAX_WINDOWS {
                        if self.scene.window(i).is_some_and(|w| w.ctx == old) {
                            self.destroy(i);
                        }
                    }
                }
                let _ = sys::notify(&self.notify, WORK);
                return;
            }
            // The holder of the scene went: the windows show as they did
            // without one from the next frame, and its own windows go with it.
            if label == self.scene_label {
                self.scene_label = 0;
                self.scene.scene_end();
                self.kick();
            }
        }
        if is_input(label) {
            return;
        }
        if is_window_keys(label) {
            return;
        }
        if is_window(label) {
            if let Some(i) = self.scene.find(label) {
                self.destroy(i);
            }
            return;
        }
        for i in 0..MAX_WINDOWS {
            if self.scene.window(i).is_some_and(|w| w.ctx == label) {
                self.destroy(i);
            }
        }
        self.clones.gone(label);
    }

    fn notification(&mut self, n: Notice) {
        if matches!(n.source, Source::Unlabeled) && n.bits & INPUT != 0 {
            self.read_device(Which::Keys);
            self.read_device(Which::Pointer);
        }
        if matches!(n.source, Source::Unlabeled) && n.bits & PREP != 0 {
            self.prep_done();
        }
        if matches!(n.source, Source::Unlabeled) && n.bits & MAPPED != 0 {
            self.mapped();
        }
        match n.source {
            Source::Session if n.label & !GENERATION == KEYS => self.read_device(Which::Keys),
            Source::Session if n.label & !GENERATION == POINTER => self.read_device(Which::Pointer),
            // One piece of work to a step: when both bits came, the work's
            // goes again by the service's own bit.
            Source::Unlabeled if n.bits & ARM != 0 => {
                self.arm_after_cap();
                let rest = n.bits & (BAND | WORK);
                if rest != 0 {
                    let _ = sys::notify(&self.notify, rest);
                }
            }
            Source::Unlabeled if n.bits & BAND != 0 => {
                self.band();
                if n.bits & WORK != 0 {
                    let _ = sys::notify(&self.notify, WORK);
                }
            }
            Source::Unlabeled if n.bits & WORK != 0 => self.work(),
            Source::Timer if n.label == TIMER_LABEL => self.timer_fired(),
            Source::Session if n.label == DRIVER => {
                if n.bits & FRAME_SHOWN != 0 {
                    self.finish(true);
                } else if n.bits & FRAME_FAILED != 0 {
                    self.finish(false);
                }
            }
            _ => {}
        }
    }
}
