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
use compositor::{
    BAND_TICKS, Band, Format, FrameKind, MAX_WINDOWS, Refusal, SCREEN, Scene,
    Source as PixelSource, compose,
};
use core::mem::ManuallyDrop;
use core::slice;
use proto_comp::{
    Attach, BUFFER_MAX, Create, Description, EVENTS_BIT, Event, FOCUSED, INPUT_MARK, MANAGER_MARK,
    MAX_EVENTS, Method as Comp, Post, RESET, Rect, SHOWN, STATS_WINDOWS, SetBody, StatsReply,
    WindowRecord, WindowStats, manage, read_stats_request,
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
use rt::handle::{Channel, Memory, Outgoing, Process, Timer};
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
/// Where the service maps the cursor's picture (source 3 of the driver),
/// past the pool inside the same 2 MiB span.
const CURSOR_AT: usize = 0x12_0010_0000;
// The pool's mapping ends before the cursor's with a gap of at least a page.
const _: () = assert!(POOL_AT + POOL_LEN + PAGE <= CURSOR_AT);
const PAGE: usize = 4096;
/// The pages one step of the service maps or unmaps at most: a page costs
/// the kernel about 200 ticks of a mapping and 80 of an unmapping, and a
/// step stays under 16 500 (xtask).
const CHUNK: usize = 32;
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

/// What a window holds besides what the scene decides: the objects of its
/// buffers with the pages of each that are mapped (for reading, from the
/// start, in chunks), the channel the client is told on, the FLUSH that
/// waits for the frame in progress and the one that waits for the next. A
/// window that went keeps its place, `dying`, until its pages are unmapped,
/// a chunk a step.
struct Extra {
    notify: Option<Handle<Channel>>,
    memory: [Option<Handle<Memory>>; proto_comp::BUFFERS],
    /// The pages each buffer has, and the pages of them mapped so far.
    pages: [usize; proto_comp::BUFFERS],
    mapped: [usize; proto_comp::BUFFERS],
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
    buffer: usize,
    pending: Pending,
}

/// The pixels of the windows' buffers, as the mappings hold them.
struct Pixels<'a>(&'a Scene);

/// The detail of the longest step of the service's own work tells which
/// work it is: the thousands (1 a band, to which the images it made are added,
/// 2 the take of a frame, 3 the commit after the last band, 4 the end of a
/// frame, 5 a step of the service's housekeeping).
const STEP_BAND: u64 = 1000;
const STEP_TAKE: u64 = 2000;
const STEP_COMMIT: u64 = 3000;
const STEP_END: u64 = 4000;
const STEP_WORK: u64 = 5000;

impl PixelSource for Pixels<'_> {
    fn pixels(&self, window: usize, buffer: u8) -> &[u8] {
        let len = self
            .0
            .window(window)
            .map_or(0, |w| w.stride as usize * w.rect.h as usize);
        let at = if self.0.window(window).is_some_and(|w| w.legacy) {
            POOL_AT
        } else {
            buf_at(window, buffer as usize)
        };
        // SAFETY: a buffer is taken only once it is attached, and the
        // reply of ATTACH comes after its last chunk is mapped read-only at
        // this address, for at least `stride` times `h` bytes; the legacy
        // buffer is mapped from the start. The mapping stays until the
        // window has gone and a later step unmaps it, never in the middle
        // of a band (one thread).
        unsafe { slice::from_raw_parts(at as *const u8, len) }
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
    damage: Rect,
    at: Band,
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
    /// The buffer of the window of the first revision, None when the driver
    /// gave none (OPEN is BUSY then). It is cleared a step at a time once its
    /// window has gone and the display does not show it (`cleared`: the
    /// bytes done, None when it is clean).
    pool: PoolState,
    /// The driver's primary pipeline, when it can show the pool.
    primary: Option<Pipeline>,
    cleared: Option<usize>,
    attaching: Option<Attaching>,
    /// The clock of the frame: when a frame is taken, the periods, the counters.
    pacer: Pacer,
    /// The timer of the frame, made through a copy of the channel with a label
    /// of its own; the copy lives as long as the timer.
    timer: Handle<Timer>,
    _timer_view: Handle<Channel>,
}

/// The time on the scale of the counter, in nanoseconds.
fn now_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

fn main(_: u64) -> u64 {
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
    let cap = frame::band_cap(period, cap_ppm, BAND_TICKS);
    let mut service = Compositor {
        channel: Handle::borrowed(channel.raw()),
        notify,
        parent: Handle::borrowed(s.parent.raw()),
        process: Handle::borrowed(s.process.raw()),
        level,
        screen: None,
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
        pool: PoolState::None,
        primary: None,
        cleared: None,
        attaching: None,
        pacer: Pacer::new(now_ns(), period, cap),
        timer,
        _timer_view: timer_view,
    };
    // The image of the pointer's picture is made here, before the first band
    // the pointer is in.
    service.raster.prepare(
        compositor::pointer_picture(),
        compositor::CURSOR_W * 4,
        Format::Argb,
        (compositor::CURSOR_W, compositor::CURSOR_H),
    );
    service.keys.link = connect_device(&service.parent, service.keys.name);
    service.pointer.link = connect_device(&service.parent, service.pointer.name);
    // The screen is opened here, outside any step (its buffer is 256 pages
    // to map): the driver says CLEARING while it sets the device up, and
    // the service asks again on a timer of its own channel. A driver that
    // does not answer is asked again at a request.
    service.open_screen_waiting(level);
    // The prices of the bands measured on shapes of their own, in the screen's
    // buffer, before the first request (the run under -icount, `steps` alone).
    #[cfg(feature = "steps")]
    if service.screen.is_some() {
        // SAFETY: the buffer is this service's mapping of the screen's object,
        // read and write, SCREEN_BYTES of its 256 pages; nothing else holds it.
        let fb = unsafe { slice::from_raw_parts_mut(FB_AT as *mut u8, SCREEN_BYTES as usize) };
        service.raster.calibrate(fb);
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
    STOPPED
}

/// The format a number of the protocol names.
fn format_of(number: u32) -> Option<Format> {
    match number {
        proto_comp::FORMAT_XRGB8888 => Some(Format::Xrgb),
        proto_comp::FORMAT_ARGB8888 => Some(Format::Argb),
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
    fn open_screen(&mut self) -> Result<(), Status> {
        if self.screen.is_some() {
            return Ok(());
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
        if sys::mem_map(
            &self.process,
            &fb,
            0,
            u64::from(BUFFER_BYTES),
            FB_AT,
            Access::ReadWrite,
        )
        .is_err()
        {
            return Err(code(IO));
        }
        // The frame bit comes through a handle of this channel with a label
        // of its own; the driver holds it for the screen's time.
        let frame = sys::handle_label(
            &self.channel,
            Rights::NOTIFY | Rights::TRANSFER,
            DRIVER,
            self.level,
        )
        .map_err(|_| code(IO))?;
        let mut request = Writer::new();
        Gpu::Subscribe.header().write(&mut request)?;
        let subscribed = sys::send_handles(&owner, request.as_bytes(), [frame.erase()])
            .map_err(|refused| Status::Kernel(refused.error))?;
        let mut buffer = [0; MESSAGE_MAX];
        if status_of(subscribed.bytes(&mut buffer)) != Some(Status::Ok) {
            return Err(code(IO));
        }
        // The mapping keeps the object; the handle is not needed.
        drop(fb);
        self.take_planes(&owner);
        self.screen = Some(owner);
        rt::println!(
            "compositor: screen ready, {}x{}, stride {}",
            screen.width,
            screen.height,
            screen.stride
        );
        Ok(())
    }

    /// What the driver's pipelines let the service do, once the screen is
    /// open: the pointer goes onto the cursor pipeline, and the pool
    /// becomes the buffer of the window of the first revision. Both are
    /// calls to the driver and mappings (a pool of 250 pages), so they
    /// belong to the opening of the screen, which no frame is waiting for.
    /// Any refusal leaves the old way: the pointer drawn into the frame,
    /// no direct frame, and OPEN BUSY (the pool is the only buffer of a
    /// window of the first revision).
    fn take_planes(&mut self, owner: &Handle<Channel>) {
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
                return;
            }
        };
        match self.cursor_picture(owner, &list) {
            Ok(plane) => {
                self.scene.set_cursor_plane(Some(plane));
                rt::println!("compositor: the pointer is on the cursor pipeline");
            }
            Err(why) => rt::println!("compositor: the pointer is drawn in the frame: {why}"),
        }
        match self.pool_source(owner, &list) {
            Ok(()) => {}
            Err(why) => {
                rt::println!("compositor: no pool for the window of the first revision: {why}");
            }
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
            let _ = self.open_screen();
            return;
        };
        let Ok(waiter) = Waiter::new(&quiet, 0, level) else {
            let _ = self.open_screen();
            return;
        };
        for _ in 0..OPEN_TRIES {
            if self.open_screen() != Err(code(CLEARING)) {
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
        if label & (OWN | WINDOW | DRIVER | MANAGER_MARK | INPUT_MARK | WINDOW_KEYS) != 0 {
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
        if d.manager
            && let Some(manager) = &self.manager
        {
            let _ = sys::notify(manager, EVENTS_BIT);
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
                }
            }
            Fire::Continue => {
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
        let Some(damage) = self.scene.begin_at(k.unwrap_or(u64::MAX)) else {
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
        self.job = Some(Job {
            damage,
            at: Band { row, col: 0 },
        });
        let _ = sys::notify(&self.notify, BAND);
        true
    }

    /// One band of the frame; the step after the last band commits it
    /// (the driver's answer is a wait of its own, which does not belong in
    /// the step of a band).
    fn band(&mut self) {
        rt::service::step_own();
        rt::service::step_detail(STEP_BAND);
        let Some(job) = self.job.as_mut() else {
            return;
        };
        if job.at.row >= job.damage.y + job.damage.h {
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
        job.at = compose(
            &self.scene,
            job.damage,
            job.at,
            fb,
            &Pixels(&self.scene),
            &mut self.raster,
        );
        // The images this band made (surfaces first used in it) go in the
        // detail with the band's number, so that a long band is told from a
        // band of images made.
        rt::service::step_detail(STEP_BAND + u64::from(self.raster.made().wrapping_sub(made)));
        self.scene.band_done();
        let more = job.at.row < job.damage.y + job.damage.h;
        let now = now_ns();
        match self.pacer.band_done(now, now.saturating_sub(began), more) {
            frame::Band::Go => {
                let _ = sys::notify(&self.notify, BAND);
            }
            // The cap of the period is reached: the next band waits for the
            // start of the next one.
            frame::Band::Defer(at) => {
                let _ = sys::timer_set(&self.timer, at);
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
    /// (PEER_CLOSED), its buffers are unmapped a chunk a step (the place is
    /// `dying` until then), its buffer, if it is of the first revision, is
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
        if extra.mapped.iter().any(|&m| m != 0) {
            extra.dying = true;
        } else {
            *extra = Extra::new();
        }
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
    fn taken(&self) -> u8 {
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
        self.cleared.is_some()
            || matches!(self.pool, PoolState::Mapping { .. })
            || self.attaching.is_some()
            || self.extra.iter().any(|e| e.dying)
    }

    /// One step of the work: a piece of the legacy buffer cleared, else a
    /// chunk of a dying window's pages unmapped, else a chunk of the
    /// buffers an ATTACH waits for mapped. The next is due by the service's
    /// own bit.
    fn work(&mut self) {
        rt::service::step_own();
        rt::service::step_detail(STEP_WORK);
        self.regrant();
        if let Some(done) = self.cleared {
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
        } else if let Some(i) = self.extra.iter().position(|e| e.dying) {
            self.unmap_chunk(i);
        } else if self.attaching.is_some() {
            self.map_chunk();
        }
        if self.has_work() {
            let _ = sys::notify(&self.notify, WORK);
        }
    }

    /// The last chunk of the pages mapped of a dying window `i`.
    fn unmap_chunk(&mut self, i: usize) {
        let extra = &mut self.extra[i];
        if let Some(b) = (0..proto_comp::BUFFERS).find(|&b| extra.mapped[b] != 0) {
            let first = (extra.mapped[b] - 1) / CHUNK * CHUNK;
            let pages = extra.mapped[b] - first;
            // SAFETY: the chunk is one mapping this service made at this
            // address, of these pages; no band reads a dying window.
            let _ = unsafe {
                sys::mem_unmap(
                    &self.process,
                    buf_at(i, b) + first * PAGE,
                    (pages * PAGE) as u64,
                )
            };
            extra.mapped[b] = first;
        }
        if extra.mapped.iter().all(|&m| m == 0) {
            *extra = Extra::new();
        }
    }

    /// A chunk of the buffer the ATTACH in progress is at; the last chunk
    /// of the last buffer ends it.
    fn map_chunk(&mut self) {
        let Some(job) = &self.attaching else {
            return;
        };
        let (i, b) = (job.slot, job.buffer);
        let extra = &mut self.extra[i];
        let done = extra.mapped[b];
        let pages = CHUNK.min(extra.pages[b] - done);
        let mapped = match &extra.memory[b] {
            Some(memory) => sys::mem_map(
                &self.process,
                memory,
                (done * PAGE) as u64,
                (pages * PAGE) as u64,
                buf_at(i, b) + done * PAGE,
                Access::Read,
            ),
            None => Err(Error::BadState),
        };
        if let Err(error) = mapped {
            rt::println!("compositor: a buffer could not be mapped: {error:?}");
            if let Some(job) = self.attaching.take() {
                let _ = job.pending.answer(
                    &proto_wire::reply(proto_comp::code(proto_comp::INVALID)),
                    Outgoing::new(),
                );
            }
            self.destroy(i);
            return;
        }
        extra.mapped[b] = done + pages;
        if extra.mapped[b] < extra.pages[b] {
            return;
        }
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
        let status = match self.scene.attach(job.slot, job.count, job.stride) {
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
        if let Err(status) = self.open_screen() {
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
        if let Err(status) = self.open_screen() {
            return Answer::Status(status);
        }
        let d = Description {
            width: WIDTH,
            height: HEIGHT,
            format: proto_comp::FORMAT_XRGB8888,
            flags: (u32::from(self.scene.has_manager()) * proto_comp::HAS_MANAGER)
                | (u32::from(self.scene.cursor_plane()) * proto_comp::CURSOR_PLANE),
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
        if let Err(status) = self.open_screen() {
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
        let i = match self.scene.create(label, r.label(), rect, false, taken) {
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
            .and_then(|()| r.reply().u32(i as u32));
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
        if u64::from(attach.stride) < u64::from(w.rect.w) * 4 || attach.bytes(w.rect.h) > BUFFER_MAX
        {
            return Answer::Status(proto_comp::code(proto_comp::INVALID));
        }
        if self.attaching.is_some() {
            return Answer::Status(proto_comp::code(proto_comp::BUSY));
        }
        let need = attach.bytes(w.rect.h);
        // The objects are looked at here, in this step; they are mapped a
        // chunk of pages a step, and the reply waits for the last.
        let mut memory: [Option<Handle<Memory>>; proto_comp::BUFFERS] = [const { None }; 3];
        let mut pages = [0; proto_comp::BUFFERS];
        for b in 0..attach.count as usize {
            let Ok(object) = r.handles.take::<Memory>(b) else {
                return Answer::Status(proto_comp::code(proto_comp::INVALID));
            };
            match sys::memory_info(&object) {
                Ok(info) if info.size >= need && info.size <= BUFFER_MAX => {}
                _ => return Answer::Status(proto_comp::code(proto_comp::INVALID)),
            }
            pages[b] = (need as usize).div_ceil(PAGE);
            memory[b] = Some(object);
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let extra = &mut self.extra[i];
        extra.memory = memory;
        extra.pages = pages;
        self.attaching = Some(Attaching {
            slot: i,
            count: attach.count as u8,
            stride: attach.stride,
            buffer: 0,
            pending,
        });
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
                    self.raster
                        .prepare(src, w.stride, w.format, (w.rect.w, w.rect.h));
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
                records[count] = pace.record(i as u32);
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
        let id = a as usize;
        let result = match op {
            manage::SUBSCRIBE => {
                let Ok(notify) = r.handles.take::<Channel>(0) else {
                    return Answer::Status(proto_comp::code(proto_comp::INVALID));
                };
                self.manager = Some(notify);
                self.manager_label = r.label();
                self.scene.set_manager(true);
                Ok(())
            }
            manage::LIST => return self.list(r),
            manage::MOVE => self.scene.move_to(id, b, c),
            manage::RAISE => self.scene.raise(id),
            manage::FOCUS => self.scene.focus_on(id),
            _ => self.scene.set_visible(id, b != 0),
        };
        self.kick();
        match result {
            Ok(()) => Answer::Status(Status::Ok),
            Err(refusal) => Answer::Status(Compositor::refusal(refusal)),
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
                id: u32::from(k),
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
            return self.manager_request(method, r);
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
        if is_manager(label) {
            if label == self.manager_label {
                self.manager = None;
                self.manager_label = 0;
                self.scene.set_manager(false);
            }
            return;
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
        match n.source {
            Source::Session if n.label & !GENERATION == KEYS => self.read_device(Which::Keys),
            Source::Session if n.label & !GENERATION == POINTER => self.read_device(Which::Pointer),
            // One piece of work to a step: when both bits came, the work's
            // goes again by the service's own bit.
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
