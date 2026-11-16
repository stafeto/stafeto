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
//! window of the whole screen with a buffer the service makes, so that
//! Doom runs here as it runs on the driver.
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
//! `display`) and the input service's (`input`), whose focus it passes on
//! to the program that holds the window of the first revision. It ends
//! with a code of its own when the driver goes (every session it gave is
//! dead then); init starts it again.

#![no_std]
#![no_main]

use abi::{Access, Error, MESSAGE_MAX, Rights, Source};
use compositor::{MAX_WINDOWS, Refusal, SCREEN, Scene, Source as PixelSource, compose};
use core::mem::ManuallyDrop;
use core::slice;
use proto_comp::{Attach, BUFFER_MAX, Create, Description, Method as Comp, Post, Rect};
use proto_gpu::{
    BUFFER_BYTES, BUSY, CLEARING, FRAME_FAILED, FRAME_SHOWN, HEIGHT, IO, Method as Gpu, NO_DEVICE,
    NO_INPUT, NOT_ALLOWED, SCREEN_BYTES, Screen, VERSION, WIDTH, code,
};
use proto_init::ServiceArgs;
use proto_input::Method as InputMethod;
use proto_wire::clones::Clones;
use proto_wire::{Status, Writer};
use rt::handle::{Any, Channel, Memory, Outgoing, Process};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::wait::Waiter;
use rt::{Handle, sys};

rt::entry!(main);

/// Where the service maps the screen's buffer, and the buffers of the
/// windows (each place of a window has three spans of BUFFER_MAX).
const FB_AT: usize = 0x10_0100_0000;
const BUF_AT: usize = 0x11_0000_0000;
/// Where the service maps the buffer it made for the window of the first
/// revision, for reading and writing, for its whole life.
const LEGACY_AT: usize = 0x12_0000_0000;
const PAGE: usize = 4096;
/// The pages one step of the service maps or unmaps at most: a page costs
/// the kernel about 200 ticks of a mapping and 80 of an unmapping, and a
/// step stays under 16 500 (xtask).
const CHUNK: usize = 32;
/// The tries and the pause of the first OPEN of the driver.
const OPEN_TRIES: u32 = 150;
const OPEN_PAUSE_NS: u64 = 5_000_000;
/// The bytes of the buffer of the first revision: the screen's, 250 pages.
const LEGACY_LEN: usize = SCREEN_BYTES as usize;
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
/// The service's own bits: the next band of the frame is due, and a chunk of
/// mapping, unmapping or clearing is.
const BAND: u64 = 1;
const WORK: u64 = 2;
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
    label & WINDOW != 0 && label & OWN == 0
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

impl PixelSource for Pixels<'_> {
    fn pixels(&self, window: usize, buffer: u8) -> &[u8] {
        let len = self
            .0
            .window(window)
            .map_or(0, |w| w.stride as usize * w.rect.h as usize);
        let at = if self.0.window(window).is_some_and(|w| w.legacy) {
            LEGACY_AT
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

/// The link to the input service, as the display driver has one.
enum Link {
    Absent,
    Linked(Handle<Channel>),
    Lost,
}

/// The frame being made: the rectangle and the next line.
struct Job {
    damage: Rect,
    row: u32,
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
    input: Link,
    focus_on: bool,
    /// The buffer of the window of the first revision: the service's own
    /// object, mapped at LEGACY_AT for good, cleared a step at a time when
    /// its window goes (`cleared`: the bytes done, None when it is clean).
    legacy: Handle<Memory>,
    cleared: Option<usize>,
    attaching: Option<Attaching>,
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
    // The buffer of the window of the first revision, made here, outside
    // any step (the kernel clears its 250 pages in the call).
    let Ok(legacy) = sys::mem_create(LEGACY_LEN as u64) else {
        return NOT_REGISTERED;
    };
    let rw = Access::ReadWrite;
    if sys::mem_map(&s.process, &legacy, 0, LEGACY_LEN as u64, LEGACY_AT, rw).is_err() {
        return NOT_REGISTERED;
    }
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
        input: Link::Absent,
        focus_on: false,
        legacy,
        cleared: None,
        attaching: None,
    };
    service.input = service.connect_input();
    // The screen is opened here, outside any step (its buffer is 256 pages
    // to map): the driver says CLEARING while it sets the device up, and
    // the service asks again on a timer of its own channel. A driver that
    // does not answer is asked again at a request.
    service.open_screen_waiting(level);
    #[cfg(feature = "steps")]
    rt::service::report_steps(17);
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
        self.screen = Some(owner);
        rt::println!(
            "compositor: screen ready, {}x{}, stride {}",
            screen.width,
            screen.height,
            screen.stride
        );
        Ok(())
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

    fn connect_input(&self) -> Link {
        match rt::service::connect(&self.parent, "input") {
            Ok(session) => Link::Linked(session),
            Err(Status::Kernel(Error::AccessDenied)) => Link::Absent,
            Err(_) => Link::Lost,
        }
    }

    /// GRANT: the session of focus for the window of the first revision,
    /// or None (OPEN's status is NO_INPUT).
    fn grant_focus(&mut self) -> Option<Handle<Any>> {
        for _ in 0..2 {
            if matches!(self.input, Link::Lost) {
                self.input = self.connect_input();
            }
            let Link::Linked(session) = &self.input else {
                return None;
            };
            match sys::send(session, &InputMethod::Grant.header().bytes()) {
                Ok(mut reply) => {
                    let mut buffer = [0; MESSAGE_MAX];
                    let status = status_of(reply.bytes(&mut buffer));
                    if status != Some(Status::Ok) || reply.handles.len() != 1 {
                        rt::println!("compositor: GRANT refused: {status:?}");
                        return None;
                    }
                    let focus = reply.handles.take::<Any>(0).ok()?;
                    self.focus_on = true;
                    return Some(focus);
                }
                Err(Error::PeerClosed) => self.input = Link::Lost,
                Err(_) => return None,
            }
        }
        None
    }

    fn revoke_focus(&mut self) {
        if !core::mem::take(&mut self.focus_on) {
            return;
        }
        let Link::Linked(session) = &self.input else {
            return;
        };
        match sys::send(session, &InputMethod::Revoke.header().bytes()) {
            Ok(_) => {}
            Err(Error::PeerClosed) => self.input = Link::Lost,
            Err(error) => rt::println!("compositor: REVOKE failed: {error:?}"),
        }
    }

    // ------------------------------------------------------------ the frame

    /// Starts a frame when none is in progress and the screen is open and
    /// damage waits: the windows' posted buffers are taken, the FLUSHes
    /// that wait move to this frame, and the first band is due.
    fn kick(&mut self) {
        if self.screen.is_none() || self.job.is_some() || self.committed {
            return;
        }
        let Some(damage) = self.scene.begin() else {
            return;
        };
        for i in 0..MAX_WINDOWS {
            if self.scene.window(i).is_some_and(|w| w.in_frame) && self.extra[i].queued.is_some() {
                self.extra[i].wait = self.extra[i].queued.take();
            }
        }
        self.job = Some(Job {
            damage,
            row: damage.y,
        });
        let _ = sys::notify(&self.notify, BAND);
    }

    /// One band of the frame; the step after the last band commits it
    /// (the driver's answer is a wait of its own, which does not belong in
    /// the step of a band).
    fn band(&mut self) {
        rt::service::step_own();
        let Some(job) = self.job.as_mut() else {
            return;
        };
        if job.row >= job.damage.y + job.damage.h {
            let damage = job.damage;
            self.job = None;
            self.commit(damage);
            return;
        }
        // SAFETY: the buffer is this service's mapping of the screen's
        // object, read and write, SCREEN_BYTES of its 256 pages; nothing
        // else in this thread holds it.
        let fb = unsafe { slice::from_raw_parts_mut(FB_AT as *mut u8, SCREEN_BYTES as usize) };
        job.row = compose(&self.scene, job.damage, job.row, fb, &Pixels(&self.scene));
        let _ = sys::notify(&self.notify, BAND);
    }

    /// COMMIT of the frame's rectangle: the driver answers at once and says
    /// the end by a bit.
    fn commit(&mut self, damage: Rect) {
        let Some(owner) = &self.screen else {
            return;
        };
        let mut request = Writer::new();
        let wrote = damage.write_as(Gpu::Commit, &mut request);
        let sent = wrote
            .map_err(|_| Error::InvalidArgs)
            .and_then(|()| sys::send(owner, request.as_bytes()));
        match sent {
            Ok(reply) => {
                let mut buffer = [0; MESSAGE_MAX];
                if status_of(reply.bytes(&mut buffer)) == Some(Status::Ok) {
                    self.committed = true;
                } else {
                    rt::println!("compositor: COMMIT refused");
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
        rt::service::step_own();
        self.committed = false;
        let ended = self.scene.end(shown);
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
        self.kick();
    }

    // ------------------------------------------------------------ the windows

    /// The window at place `i` goes: what it waited for is refused
    /// (PEER_CLOSED), its buffers are unmapped a chunk a step (the place is
    /// `dying` until then), the focus of a window of the first revision
    /// ends and its buffer is cleared a step at a time, and the place on
    /// the screen is shown again.
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
            self.revoke_focus();
            self.released += 1;
            self.cleared = Some(0);
        }
        let _ = sys::notify(&self.notify, WORK);
        self.kick();
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
        self.cleared.is_some() || self.attaching.is_some() || self.extra.iter().any(|e| e.dying)
    }

    /// One step of the work: a piece of the legacy buffer cleared, else a
    /// chunk of a dying window's pages unmapped, else a chunk of the
    /// buffers an ATTACH waits for mapped. The next is due by the service's
    /// own bit.
    fn work(&mut self) {
        rt::service::step_own();
        if let Some(done) = self.cleared {
            let len = CLEARED.min(LEGACY_LEN - done);
            // SAFETY: the service's own read and write mapping of the
            // legacy buffer, LEGACY_LEN long, of which `len` bytes from
            // `done` are in it; no window uses it while it is being
            // cleared (OPEN says CLEARING).
            unsafe { core::ptr::write_bytes((LEGACY_AT + done) as *mut u8, 0, len) };
            let done = done + len;
            self.cleared = (done < LEGACY_LEN).then_some(done);
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
        // A client that closed its window and kept its mapping still reaches
        // the buffer: the service holds the only mapping it may have.
        if sys::memory_info(&self.legacy).is_ok_and(|info| info.mappings > 1) {
            return Answer::Status(code(BUSY));
        }
        // The last window's buffer is being cleared: ask again.
        if self.cleared.is_some() {
            return Answer::Status(code(CLEARING));
        }
        let Ok((label, session)) = self.window_session() else {
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let taken = self.taken();
        let i = match self.scene.create(label, r.label(), SCREEN, true, taken) {
            Ok(i) => i,
            Err(refusal) => return Answer::Status(Compositor::refusal(refusal)),
        };
        let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
        let Ok(client) = sys::handle_duplicate(&self.legacy, rights) else {
            self.destroy(i);
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let mut handles: Outgoing = [client.erase(), session.erase()].into();
        let focus = self.grant_focus();
        let status = if focus.is_some() {
            Status::Ok
        } else {
            code(NO_INPUT)
        };
        if let Some(focus) = focus {
            let _ = handles.push(focus);
        }
        if Screen::FIXED.write(status, r.reply()).is_err() {
            self.destroy(i);
            return Answer::Status(Status::BadSize);
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
            flags: 0,
            open: self.scene.open(),
            created: self.scene.created(),
            frames: self.scene.frames(),
            busy: u32::from(self.scene.busy()),
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
        if create.format != proto_comp::FORMAT_XRGB8888 || create.flags != 0 {
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
        self.extra[i].notify = Some(notify);
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
        if attach.format != proto_comp::FORMAT_XRGB8888 {
            return Answer::Status(proto_comp::code(proto_comp::UNSUPPORTED));
        }
        let Some(w) = self.scene.window(i).copied() else {
            return Answer::Status(proto_comp::code(proto_comp::REVOKED));
        };
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
        match self
            .scene
            .post(i, buffer, &post.rects[..post.count as usize])
        {
            Ok(replaced) => {
                if let Some(b) = replaced
                    && let Some(notify) = &self.extra[i].notify
                {
                    let _ = sys::notify(notify, 1 << b);
                }
                self.kick();
                Answer::Status(Status::Ok)
            }
            Err(refusal) => Answer::Status(Compositor::refusal(refusal)),
        }
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
];

impl Service<1> for Compositor {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), 1>, r: &mut Request<'_>) -> Answer {
        let label = r.label();
        let method = r.method();
        let gpu = Gpu::from_number(method);
        let comp = Comp::from_number(method);
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
                _ => Compositor::not_allowed(comp.is_some()),
            };
        }
        match (gpu, comp) {
            (Some(Gpu::Open), _) => self.open(r),
            (Some(Gpu::Clone), _) => self.clone_session(r),
            (_, Some(Comp::Describe)) => self.describe(r),
            (_, Some(Comp::WindowCreate)) => self.window_create(r),
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
        match n.source {
            // One piece of work to a step: when both bits came, the work's
            // goes again by the service's own bit.
            Source::Unlabeled if n.bits & BAND != 0 => {
                self.band();
                if n.bits & WORK != 0 {
                    let _ = sys::notify(&self.notify, WORK);
                }
            }
            Source::Unlabeled if n.bits & WORK != 0 => self.work(),
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
