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
    NO_INPUT, NOT_ALLOWED, SCREEN_BYTES, STRIDE, Screen, VERSION, WIDTH, code,
};
use proto_init::ServiceArgs;
use proto_input::Method as InputMethod;
use proto_wire::clones::Clones;
use proto_wire::{Status, Writer};
use rt::handle::{Any, Channel, Memory, Outgoing, Process};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, sys};

rt::entry!(main);

/// Where the service maps the screen's buffer, and the buffers of the
/// windows (each place of a window has three spans of BUFFER_MAX).
const FB_AT: usize = 0x10_0100_0000;
const BUF_AT: usize = 0x11_0000_0000;
const PAGE: usize = 4096;
/// The sessions of the service's channel: the contexts, the windows, and
/// the clones' places, with room.
const SESSIONS: usize = 64;
/// The clones the service keeps alive at most, for all its clients.
const CLONES: usize = 32;
/// The marks of labels: a clone's (bit 63, as the driver has them), a
/// window's (bit 62), and the label of the handle the driver notifies
/// through (bit 61).
const OWN: u64 = 1 << 63;
const WINDOW: u64 = 1 << 62;
const DRIVER: u64 = 1 << 61;
/// The service's own bit: the next band of the frame is due.
const BAND: u64 = 1;
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
/// buffers (mapped for reading), the channel the client is told on, the
/// FLUSH that waits for the frame in progress and the one that waits for
/// the next.
struct Extra {
    notify: Option<Handle<Channel>>,
    memory: [Option<Handle<Memory>>; proto_comp::BUFFERS],
    mapped: [usize; proto_comp::BUFFERS],
    wait: Option<Pending>,
    queued: Option<Pending>,
}

impl Extra {
    const fn new() -> Extra {
        Extra {
            notify: None,
            memory: [const { None }; proto_comp::BUFFERS],
            mapped: [0; proto_comp::BUFFERS],
            wait: None,
            queued: None,
        }
    }
}

/// The pixels of the windows' buffers, as the mappings hold them.
struct Pixels<'a>(&'a Scene);

impl PixelSource for Pixels<'_> {
    fn pixels(&self, window: usize, buffer: u8) -> &[u8] {
        let len = self
            .0
            .window(window)
            .map_or(0, |w| w.stride as usize * w.rect.h as usize);
        // SAFETY: a buffer is taken only once it is attached, and ATTACH
        // maps its object read-only at this address for at least `stride`
        // times `h` bytes; the mapping stays until the window goes, which
        // is never in the middle of a band (one thread).
        unsafe { slice::from_raw_parts(buf_at(window, buffer as usize) as *const u8, len) }
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
    };
    service.input = service.connect_input();
    // The first try, so that the first client finds the screen ready; a
    // driver that is still setting up is asked again at a request.
    let _ = service.open_screen();
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

    /// One band of the frame; the last one commits it.
    fn band(&mut self) {
        rt::service::step_own();
        let Some(job) = self.job.as_mut() else {
            return;
        };
        // SAFETY: the buffer is this service's mapping of the screen's
        // object, read and write, SCREEN_BYTES of its 256 pages; nothing
        // else in this thread holds it.
        let fb = unsafe { slice::from_raw_parts_mut(FB_AT as *mut u8, SCREEN_BYTES as usize) };
        job.row = compose(&self.scene, job.damage, job.row, fb, &Pixels(&self.scene));
        if job.row < job.damage.y + job.damage.h {
            let _ = sys::notify(&self.notify, BAND);
            return;
        }
        let damage = job.damage;
        self.job = None;
        self.commit(damage);
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

    /// The window at place `i` goes: its buffers unmap, what it waited for
    /// is refused (PEER_CLOSED), the focus of a window of the first
    /// revision ends, and the place is shown again.
    fn destroy(&mut self, i: usize) {
        let Some(w) = self.scene.destroy(i) else {
            return;
        };
        let extra = &mut self.extra[i];
        for b in 0..proto_comp::BUFFERS {
            if extra.mapped[b] != 0 {
                // SAFETY: the buffer's own mapping, made by this service
                // at this address; no band is in progress (one thread).
                let _ =
                    unsafe { sys::mem_unmap(&self.process, buf_at(i, b), extra.mapped[b] as u64) };
            }
        }
        *extra = Extra::new();
        if w.legacy {
            self.revoke_focus();
            self.released += 1;
        }
        self.kick();
    }

    /// Maps `memory` for reading at the place of buffer `b` of window `i`:
    /// the bytes it must hold are `need`.
    fn map_buffer(
        &mut self,
        i: usize,
        b: usize,
        memory: Handle<Memory>,
        need: u64,
    ) -> Result<(), Status> {
        let Ok(info) = sys::memory_info(&memory) else {
            return Err(proto_comp::code(proto_comp::INVALID));
        };
        if info.size < need || info.size > BUFFER_MAX {
            return Err(proto_comp::code(proto_comp::INVALID));
        }
        let len = need.div_ceil(PAGE as u64) * PAGE as u64;
        sys::mem_map(&self.process, &memory, 0, len, buf_at(i, b), Access::Read).map_err(|e| {
            rt::println!("compositor: a buffer could not be mapped: {e:?}");
            proto_comp::code(proto_comp::INVALID)
        })?;
        self.extra[i].mapped[b] = len as usize;
        self.extra[i].memory[b] = Some(memory);
        Ok(())
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
        let Ok((label, session)) = self.window_session() else {
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let i = match self.scene.create(label, r.label(), SCREEN, true) {
            Ok(i) => i,
            Err(refusal) => return Answer::Status(Compositor::refusal(refusal)),
        };
        let made = sys::mem_create(u64::from(BUFFER_BYTES)).and_then(|memory| {
            let client = sys::handle_duplicate(
                &memory,
                Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
            )?;
            Ok((memory, client))
        });
        let Ok((memory, client)) = made else {
            self.destroy(i);
            return Answer::Status(Status::Kernel(Error::NoMemory));
        };
        let need = u64::from(STRIDE) * u64::from(HEIGHT);
        if self.map_buffer(i, 0, memory, need).is_err() {
            self.destroy(i);
            return Answer::Status(code(IO));
        }
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
        let i = match self.scene.create(label, r.label(), rect, false) {
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
        let need = attach.bytes(w.rect.h);
        for b in 0..attach.count as usize {
            let Ok(memory) = r.handles.take::<Memory>(b) else {
                self.unmap_all(i);
                return Answer::Status(proto_comp::code(proto_comp::INVALID));
            };
            if let Err(status) = self.map_buffer(i, b, memory, need) {
                self.unmap_all(i);
                return Answer::Status(status);
            }
        }
        match self.scene.attach(i, attach.count as u8, attach.stride) {
            Ok(()) => Answer::Status(Status::Ok),
            Err(refusal) => {
                self.unmap_all(i);
                Answer::Status(Compositor::refusal(refusal))
            }
        }
    }

    /// Takes back the buffers a failed ATTACH mapped.
    fn unmap_all(&mut self, i: usize) {
        let extra = &mut self.extra[i];
        for b in 0..proto_comp::BUFFERS {
            if extra.mapped[b] != 0 {
                // SAFETY: the buffer's own mapping, made by this service.
                let _ =
                    unsafe { sys::mem_unmap(&self.process, buf_at(i, b), extra.mapped[b] as u64) };
                extra.mapped[b] = 0;
            }
            extra.memory[b] = None;
        }
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
            Source::Unlabeled if n.bits & BAND != 0 => self.band(),
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
