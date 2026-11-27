// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loads of the frame-time probe, one role to a program: the first word of
//! the record's own arguments names it. Every role is started by init at boot,
//! reads the phase schedule (`frame_load::phases`), sleeps until its first
//! phase, works while its phases last and ends with a line. How a role is
//! started: a record of `table::frame` with the role as its arguments; how it
//! stops: at the end of the last phase it wants (or at the end of the
//! schedule); how its intensity is set: by the phase table (which phases),
//! and for `draw` by its declared interval (one period).
//!
//! - `ctl`: the conductor. It holds the input session of the compositor (the
//!   record's mark), checks it started before the epoch, and at the start and
//!   the end of each phase reads the service's counters and prints the line of
//!   the phase. It ends with `frame-load: done`.
//! - `draw`: the paced client. A window of the scene of the phase (160 by 100,
//!   or the whole screen), two buffers, a stripe that moves each period; it
//!   posts at the start of each period of the compositor's clock, on the
//!   buffer the service gave back, and counts the periods in which it had none.
//! - `legacy`: the client of the first revision: OPEN, then FLUSH of the whole
//!   screen one after another (each answers once the frame is shown) while the
//!   scene is D, then CLOSE.
//! - `cpu`: a loop that counts its turns; the loops a second of each phase are
//!   a line, and the share of the CPU the levels below the service got is
//!   their ratio to the loops of the quiet phase.

#![no_std]
#![no_main]

use abi::{Access, MESSAGE_MAX, Rights, Source};
use core::cell::Cell;
use frame_load::paint::{self, STRIPE_ROWS};
use frame_load::phases::{ORDER, PERIOD_NS, Phase, Scene, Schedule};
use frame_load::report::{
    BandsLine, Counters, CpuLine, HistLine, PhaseLine, WindowCounters, WindowLine, loops_per_second,
};
use proto_comp::{
    Attach, Create, Description, FORMAT_ARGB8888, FORMAT_XRGB8888, INTERVAL, Method, Post, RESET,
    Rect, SetBody, StatsReply,
};
use proto_gpu::{HEIGHT, STRIDE, WIDTH};
use proto_init::ServiceArgs;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Memory, Outgoing, Resource};
use rt::sys::Received;
use rt::wait::{Waited, Waiter};
use rt::{Handle, sys, time};

rt::entry!(main);

/// Where `draw` maps its two buffers.
const MAP_AT: usize = 0x20_0000_0000;
const MAP_STEP: usize = 0x100_0000;
/// The retry period for a service that is being set up, and the longest wait.
const RETRY_NS: u64 = 5_000_000;
/// The lateness of a wake-up at a phase start that fails the run.
const WAKE_LATE_NS: u64 = 100_000_000;
/// The counters of a phase start this long after its start and are read this
/// long before its end.
const SETTLE_NS: u64 = 50_000_000;
const READ_BEFORE_END_NS: u64 = 5_000_000;
/// The size of the compositor's log of late frames (compositor::frame::LATE_LOG).
const LATE_LOG_SIZE: u64 = 4;
const WAIT_NS: u64 = 60_000_000_000;
/// How long after the last phase the conductor says `done`.
const DONE_AFTER_NS: u64 = 2_000_000_000;
/// The windows of the overload have two buffers each of 320 by 200 points.
const SMALL_OBJECTS: usize = 2 * paint::O_WINDOWS;
const SMALL_STRIDE: u32 = 320 * 4;
const SMALL_BYTES: usize = (SMALL_STRIDE * 200) as usize;
/// The bytes of a buffer (the whole screen: both scenes use the same objects).
const BUFFER_BYTES: u64 = (STRIDE * HEIGHT) as u64;

type Fail = &'static str;

fn say<E: core::fmt::Debug>(what: &'static str) -> impl Fn(E) -> &'static str {
    move |e| {
        rt::println!("frame-load: {what}: {e:?}");
        what
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let own = ServiceArgs::read(start.args()).map_or(&[][..], |a| a.own);
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return 1;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, level) else {
        return 1;
    };
    let env = Env {
        process: &start.process,
        parent: &start.parent,
        channel,
        waiter,
        bits: Cell::new(0),
        schedule: Schedule::DEFAULT,
    };
    let result = match own {
        b"ctl" => env.conduct(),
        b"draw" => env.draw(),
        b"legacy" => env.legacy(),
        b"cpu" => env.cpu(),
        _ => Err("an unknown role"),
    };
    match result {
        Ok(()) => 0,
        Err(reason) => {
            rt::println!("frame-load: failed: {reason}");
            2
        }
    }
}

struct Env<'a> {
    process: &'a Handle<rt::handle::Process>,
    parent: &'a Handle<Channel>,
    channel: Handle<Channel>,
    waiter: Waiter,
    /// The bits the compositor sent this channel and nobody read yet.
    bits: Cell<u64>,
    schedule: Schedule,
}

fn now() -> u64 {
    time::ticks_to_ns(time::now())
}

impl Env<'_> {
    fn keep(&self, got: &Received) {
        if let Received::Notification {
            source: Source::Unlabeled,
            bits,
            ..
        } = got
        {
            self.bits.set(self.bits.get() | bits);
        }
    }

    /// Waits until the clock reaches `deadline`, keeping the bits that come.
    fn sleep_until(&self, deadline: u64) {
        while now() < deadline {
            match self.waiter.receive_until(&self.channel, deadline) {
                Ok(Waited::Got(got)) => self.keep(&got),
                _ => break,
            }
        }
    }

    fn display(&self) -> Result<Handle<Channel>, Fail> {
        rt::service::connect(self.parent, "gpu").map_err(say("connect to gpu"))
    }

    fn describe(display: &Handle<Channel>) -> Result<Description, Status> {
        let reply =
            sys::send(display, &Method::Describe.header().bytes()).map_err(Status::Kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        Description::read(reply.bytes(&mut buffer))
    }

    /// STATS of the service, with its counters reset when `reset`.
    fn stats(display: &Handle<Channel>, reset: bool) -> Result<StatsReply, Fail> {
        let mut w = Writer::new();
        proto_comp::write_stats(if reset { RESET } else { 0 }, &mut w)
            .map_err(say("STATS's bytes"))?;
        let reply = sys::send(display, w.as_bytes()).map_err(say("STATS"))?;
        let mut buffer = [0; MESSAGE_MAX];
        StatsReply::read(reply.bytes(&mut buffer)).map_err(say("STATS's reply"))
    }

    /// DESCRIBE until the service has its screen.
    fn describe_when_ready(&self, display: &Handle<Channel>) -> Result<Description, Fail> {
        let end = now() + WAIT_NS;
        loop {
            match Self::describe(display) {
                Ok(d) => return Ok(d),
                Err(s) if s == proto_gpu::code(proto_gpu::CLEARING) => {}
                Err(_) => return Err("DESCRIBE"),
            }
            if now() > end {
                return Err("the service never had its screen");
            }
            self.sleep_until(now() + RETRY_NS);
        }
    }

    /// A program that starts after the epoch has missed phases: fail at once.
    fn on_time(&self, who: &str) -> Result<(), Fail> {
        if now() >= self.schedule.epoch_ns {
            rt::println!(
                "frame-load: {who} started at {} ms, after the epoch at {} ms",
                now() / 1_000_000,
                self.schedule.epoch_ns / 1_000_000
            );
            return Err("started after the epoch");
        }
        Ok(())
    }

    /// The program that keeps time has to wake at the start of a phase: a
    /// load that keeps it off the processor for longer than this has spoiled
    /// the phase, and the run fails with the lateness named.
    fn woke_in_time(&self, who: &str, phase: Phase) -> Result<(), Fail> {
        let late = now().saturating_sub(self.schedule.start_of(phase));
        if late > WAKE_LATE_NS {
            rt::println!(
                "frame-load: {who} woke {} ms late for the phase {}",
                late / 1_000_000,
                phase.name()
            );
            return Err("woke late for a phase");
        }
        Ok(())
    }

    // ---- ctl ----

    fn conduct(&self) -> Result<(), Fail> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        self.on_time("ctl")?;
        for phase in ORDER {
            self.sleep_until(self.schedule.start_of(phase));
            self.woke_in_time("ctl", phase)?;
            // The window of the scene of the phase is made in its first moments
            // (the one of the phase before goes at the boundary), so the counters
            // start after them and are read before the boundary.
            self.sleep_until(self.schedule.start_of(phase) + SETTLE_NS);
            Self::stats(&display, true)?;
            let before = Self::describe(&display).map_err(say("DESCRIBE"))?;
            self.sleep_until(self.schedule.end_of(phase) - READ_BEFORE_END_NS);
            let after = Self::describe(&display).map_err(say("DESCRIBE"))?;
            let reply = Self::stats(&display, false)?;
            let s = &reply.stats;
            let counters = Counters {
                releases: s.releases,
                frames: s.frames,
                direct: s.direct,
                late: s.late,
                skipped: s.skipped,
                failed: s.failed,
                capped: s.capped,
                wakeups: s.wakeups,
                take_max_us: s.take_max_us,
                compose_max_us: s.compose_max_us,
                device_max_us: s.device_max_us,
                frame_max_us: s.frame_max_us,
                band_max_us: s.band_max_us,
            };
            rt::println!("{}", PhaseLine(phase, &counters));
            rt::println!("{}", HistLine(phase, &s.hist));
            rt::println!(
                "{}",
                BandsLine(phase, after.bands.wrapping_sub(before.bands))
            );
            for w in reply.windows() {
                let w = WindowCounters {
                    id: w.id,
                    interval: w.interval,
                    posts: w.posts,
                    taken: w.taken,
                    replaced: w.replaced,
                    late: w.late,
                    missed: w.missed,
                    late_max_us: w.late_max_us,
                };
                rt::println!("{}", WindowLine(phase, &w));
            }
        }
        // The other loads print their last lines as their phases end; the
        // conductor says it is done a moment after them.
        self.sleep_until(self.schedule.finish() + DONE_AFTER_NS);
        rt::println!("frame-load: done");
        Ok(())
    }

    // ---- draw ----

    fn objects(&self) -> Result<([Handle<Memory>; 2], [usize; 2]), Fail> {
        let len = BUFFER_BYTES.div_ceil(4096) * 4096;
        let mut at = [0; 2];
        let mut made = [const { None }; 2];
        for b in 0..2 {
            let memory = sys::mem_create(len).map_err(say("mem_create"))?;
            at[b] = MAP_AT + b * MAP_STEP;
            sys::mem_map(self.process, &memory, 0, len, at[b], Access::ReadWrite)
                .map_err(say("map a buffer"))?;
            made[b] = Some(memory);
        }
        let [Some(a), Some(b)] = made else {
            return Err("buffers");
        };
        Ok(([a, b], at))
    }

    /// A window of `rect` over the two objects, XRGB8888 with the interval of
    /// one period; its session.
    fn window(
        &self,
        display: &Handle<Channel>,
        rect: paint::Rect,
        objects: &[Handle<Memory>; 2],
    ) -> Result<Handle<Channel>, Fail> {
        self.window_over(display, rect, FORMAT_XRGB8888, STRIDE, objects, true)
    }

    /// A window of `rect` and `format` over `objects` (one buffer each, of
    /// `stride` bytes a row); its session. `paced` sets the interval of one
    /// period.
    fn window_over(
        &self,
        display: &Handle<Channel>,
        rect: paint::Rect,
        format: u32,
        stride: u32,
        objects: &[Handle<Memory>],
        paced: bool,
    ) -> Result<Handle<Channel>, Fail> {
        let notify = sys::handle_duplicate(&self.channel, Rights::NOTIFY | Rights::TRANSFER)
            .map_err(say("duplicate the channel"))?;
        let mut w = Writer::new();
        Create {
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
            format,
            flags: 0,
        }
        .write(&mut w)
        .map_err(say("WINDOW_CREATE's bytes"))?;
        let mut sent = Outgoing::new();
        sent.push(notify.erase()).map_err(|_| "too many handles")?;
        let mut reply = sys::send_handles(display, w.as_bytes(), sent)
            .map_err(|r| say("WINDOW_CREATE")(r.error))?;
        let mut buffer = [0; MESSAGE_MAX];
        let status = reply
            .bytes(&mut buffer)
            .get(..4)
            .map(|b| Status::from_code(u32::from_le_bytes([b[0], b[1], b[2], b[3]])));
        if status != Some(Status::Ok) {
            rt::println!("frame-load: WINDOW_CREATE said {status:?}");
            return Err("WINDOW_CREATE was refused");
        }
        let session = reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| "WINDOW_CREATE's handle")?;
        let mut w = Writer::new();
        Attach {
            count: objects.len() as u32,
            stride,
            format,
        }
        .write(&mut w)
        .map_err(say("ATTACH's bytes"))?;
        let mut handles = Outgoing::new();
        for object in objects {
            let copy = sys::handle_duplicate(object, Rights::MAP_READ | Rights::TRANSFER)
                .map_err(say("duplicate a buffer"))?;
            handles.push(copy.erase()).map_err(|_| "too many handles")?;
        }
        let reply = sys::send_handles(&session, w.as_bytes(), handles)
            .map_err(|r| say("ATTACH")(r.error))?;
        let mut buffer = [0; MESSAGE_MAX];
        match reply.bytes(&mut buffer).get(..4) {
            Some(b) if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == 0 => {}
            _ => return Err("ATTACH was refused"),
        }
        if !paced {
            return Ok(session);
        }
        // One post a period: the service judges the window against its start.
        let mut w = Writer::new();
        SetBody {
            property: INTERVAL,
            value: 1,
        }
        .write(&mut w)
        .map_err(say("SET's bytes"))?;
        let reply = sys::send(&session, w.as_bytes()).map_err(say("SET"))?;
        match reply.bytes(&mut buffer).get(..4) {
            Some(b) if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == 0 => Ok(session),
            _ => Err("SET of the interval was refused"),
        }
    }

    fn post(window: &Handle<Channel>, buffer: u32, rect: paint::Rect) -> Result<(), Fail> {
        let rect = Rect {
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
        };
        let mut w = Writer::new();
        Post::new(buffer, &[rect])
            .and_then(|p| p.write(&mut w))
            .map_err(say("POST's bytes"))?;
        let reply = sys::send(window, w.as_bytes()).map_err(say("POST"))?;
        let mut buffer = [0; MESSAGE_MAX];
        match reply.bytes(&mut buffer).get(..4) {
            Some(b) if u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == 0 => Ok(()),
            _ => Err("POST was refused"),
        }
    }

    /// A POST of the whole of a window: whether the service took it (false when
    /// it said BUSY, the buffer being the one it shows or holds).
    fn try_post(window: &Handle<Channel>, buffer: u32, rect: paint::Rect) -> Result<bool, Fail> {
        let rect = Rect {
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
        };
        let mut w = Writer::new();
        Post::new(buffer, &[rect])
            .and_then(|p| p.write(&mut w))
            .map_err(say("POST's bytes"))?;
        let reply = sys::send(window, w.as_bytes()).map_err(say("POST"))?;
        let mut buffer = [0; MESSAGE_MAX];
        match reply
            .bytes(&mut buffer)
            .get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        {
            Some(0) => Ok(true),
            Some(code) if code == proto_comp::code(proto_comp::BUSY).code() => Ok(false),
            _ => Err("POST was refused"),
        }
    }

    /// The buffers of the overload: two objects for each of the windows, of 320
    /// by 200 points, painted once with a part of alpha and mapped for writing.
    fn small_objects(&self) -> Result<[Handle<Memory>; SMALL_OBJECTS], Fail> {
        let len = (SMALL_BYTES as u64).div_ceil(4096) * 4096;
        let mut made = [const { None }; SMALL_OBJECTS];
        for (i, slot) in made.iter_mut().enumerate() {
            let memory = sys::mem_create(len).map_err(say("mem_create"))?;
            let at = MAP_AT + (2 + i) * MAP_STEP;
            sys::mem_map(self.process, &memory, 0, len, at, Access::ReadWrite)
                .map_err(say("map a buffer"))?;
            // SAFETY: just mapped for reading and writing over `len` bytes.
            let points =
                unsafe { core::slice::from_raw_parts_mut(at as *mut u32, SMALL_BYTES / 4) };
            points.fill(0x8040_80C0 | (i as u32 & 0xF) << 8);
            *slot = Some(memory);
        }
        Ok(made.map(|m| m.expect("every buffer was made")))
    }

    /// The phase of the overload: eight windows in one place, each posted whole
    /// every period, one buffer or the other (a buffer the service shows or
    /// holds is BUSY, and the other goes), for the length of the phase; the
    /// windows go with the end of it.
    fn overload(
        &self,
        display: &Handle<Channel>,
        small: &[Handle<Memory>; SMALL_OBJECTS],
        phase: Phase,
    ) -> Result<(), Fail> {
        // The service lets one context (one session of the display) have four
        // windows, so the eight stand in two contexts of four.
        let second = self.display()?;
        let mut sessions: [Option<Handle<Channel>>; paint::O_WINDOWS] = [const { None }; 8];
        for (i, slot) in sessions.iter_mut().enumerate() {
            let context = if i < paint::O_WINDOWS / 2 {
                display
            } else {
                &second
            };
            let made = self.window_over(
                context,
                paint::O_RECT,
                FORMAT_ARGB8888,
                SMALL_STRIDE,
                &small[2 * i..2 * i + 2],
                false,
            );
            if made.is_err() {
                rt::println!("frame-load: window {i} of the overload was refused");
            }
            *slot = Some(made?);
        }
        let whole = paint::Rect {
            x: 0,
            y: 0,
            w: paint::O_RECT.w,
            h: paint::O_RECT.h,
        };
        let mut next = [0u32; paint::O_WINDOWS];
        // A window whose both buffers the service holds is left alone until it
        // gives one back (a bit on the channel says that some window's buffer
        // came back): asking again in the meantime is a request the service
        // serves between its bands for nothing.
        let mut held = [false; paint::O_WINDOWS];
        let (mut posts, mut busy, mut step) = (0u32, 0u32, 0u64);
        let (t0, end) = (self.schedule.start_of(phase), self.schedule.end_of(phase));
        loop {
            let due = paint::post_time(t0, PERIOD_NS, 1, step);
            if due >= end {
                break;
            }
            self.sleep_until(due);
            if self.bits.replace(0) & 0b11 != 0 {
                held = [false; paint::O_WINDOWS];
            }
            for (i, slot) in sessions.iter().enumerate() {
                let Some(session) = slot else {
                    continue;
                };
                if held[i] {
                    continue;
                }
                let mut taken = false;
                for _ in 0..2 {
                    if Self::try_post(session, next[i], whole)? {
                        taken = true;
                        next[i] ^= 1;
                        break;
                    }
                    busy += 1;
                    next[i] ^= 1;
                }
                held[i] = !taken;
                posts += u32::from(taken);
            }
            step += 1;
        }
        rt::println!(
            "frame-load: draw {} posts {posts} busy {busy}",
            phase.name()
        );
        Ok(())
    }

    fn draw(&self) -> Result<(), Fail> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        self.on_time("draw")?;
        let (objects, at) = self.objects()?;
        let small = self.small_objects()?;
        let mut open: Option<(Scene, Handle<Channel>)> = None;
        // The buffers the service has given back: both in a new window, and
        // kept from phase to phase while the window stays.
        let mut free: u64 = 0b11;
        for phase in ORDER {
            let scene = phase.scene();
            self.sleep_until(self.schedule.start_of(phase));
            self.woke_in_time("draw", phase)?;
            if scene == Scene::O {
                drop(open.take());
                self.overload(&display, &small, phase)?;
                continue;
            }
            let Some(rect) = paint::window_of(scene) else {
                // No window in this scene: the one of the phase before goes.
                open = None;
                continue;
            };
            if open.as_ref().map(|(s, _)| *s) != Some(scene) {
                // The window of the scene before closes first.
                drop(open.take());
                self.bits.set(0);
                free = 0b11;
                open = Some((scene, self.window(&display, rect, &objects)?));
            }
            let Some((_, session)) = &open else {
                continue;
            };
            let (mut posts, mut idle, mut step) = (0u32, 0u32, 0u64);
            let end = self.schedule.end_of(phase);
            let t0 = self.schedule.start_of(phase);
            loop {
                let due = paint::post_time(t0, PERIOD_NS, 1, step);
                if due >= end {
                    break;
                }
                self.sleep_until(due);
                // A buffer comes back once the frame that replaced it is shown,
                // some time into the period: the client waits for it up to the
                // end of the period and posts at once, as a client that paces
                // itself by the service's notices does.
                self.wait_free(&mut free, due + PERIOD_NS);
                let Some(buffer) = (0..2u32).find(|b| free & (1 << b) != 0) else {
                    idle += 1;
                    step += 1;
                    continue;
                };
                let Some(redraw) = paint::redraw(scene, step) else {
                    break;
                };
                // SAFETY: the buffer is mapped for reading and writing, the
                // service has given it back (its bit), and this is the only
                // thread.
                let points = unsafe {
                    core::slice::from_raw_parts_mut(
                        at[buffer as usize] as *mut u32,
                        (STRIDE / 4 * HEIGHT) as usize,
                    )
                };
                for y in redraw.y..redraw.y + redraw.h {
                    let from = (y * (STRIDE / 4)) as usize;
                    paint::fill(step, y, rect.h, &mut points[from..from + rect.w as usize]);
                }
                let Some(damage) = paint::damage(scene, step) else {
                    break;
                };
                free &= !(1 << buffer);
                Self::post(session, buffer, damage)?;
                posts += 1;
                step += 1;
            }
            rt::println!(
                "frame-load: draw {} posts {posts} no-free-buffer {idle}",
                phase.name()
            );
        }
        Ok(())
    }

    /// Collects the bits of the buffers the service gave back into `free`,
    /// waiting for the first one until `deadline` when there is none.
    fn wait_free(&self, free: &mut u64, deadline: u64) {
        *free |= self.bits.replace(0) & 0b11;
        while *free == 0 && now() < deadline {
            match self.waiter.receive_until(&self.channel, deadline) {
                Ok(Waited::Got(got)) => self.keep(&got),
                _ => break,
            }
            *free |= self.bits.replace(0) & 0b11;
        }
    }

    // ---- legacy ----

    fn legacy(&self) -> Result<(), Fail> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        self.on_time("legacy")?;
        for phase in ORDER {
            if phase.scene() != Scene::D {
                continue;
            }
            self.sleep_until(self.schedule.start_of(phase));
            self.woke_in_time("legacy", phase)?;
            let open = proto_gpu::Method::Open.header().bytes();
            let end = now() + WAIT_NS;
            let mut reply = loop {
                let reply = sys::send(&display, &open).map_err(say("OPEN"))?;
                let mut buffer = [0; MESSAGE_MAX];
                let word = reply
                    .bytes(&mut buffer)
                    .get(..4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .ok_or("a short reply")?;
                // NO_INPUT: the image has no keys for the window; the screen is its.
                if word == 0 || word == proto_gpu::code(proto_gpu::NO_INPUT).code() {
                    break reply;
                }
                if word != proto_gpu::code(proto_gpu::CLEARING).code() || now() > end {
                    rt::println!("frame-load: OPEN said {word}");
                    return Err("OPEN was refused");
                }
                self.sleep_until(now() + RETRY_NS);
            };
            let (Ok(memory), Ok(owner)) = (
                reply.handles.take::<Memory>(0),
                reply.handles.take::<Channel>(1),
            ) else {
                return Err("OPEN's handles");
            };
            sys::mem_map(
                self.process,
                &memory,
                0,
                u64::from(proto_gpu::SCREEN_BYTES),
                MAP_AT,
                Access::ReadWrite,
            )
            .map_err(say("map the buffer"))?;
            let mut flushes = 0u32;
            let finish = self.schedule.end_of(phase);
            let t0 = self.schedule.start_of(phase);
            while now() < finish {
                // One flush a period: a client of 60 Hz, which is the pace of the
                // service with a clock and the pace this loop keeps on a service
                // that shows a frame as soon as it can.
                self.sleep_until(t0 + u64::from(flushes) * PERIOD_NS);
                // SAFETY: mapped for reading and writing above; one thread.
                let points = unsafe {
                    core::slice::from_raw_parts_mut(
                        MAP_AT as *mut u32,
                        (STRIDE / 4 * HEIGHT) as usize,
                    )
                };
                let top = (flushes * 9) % (HEIGHT - STRIPE_ROWS);
                for y in top..top + STRIPE_ROWS {
                    for x in 0..WIDTH {
                        points[(y * WIDTH + x) as usize] = 0x00C0_4020 | (flushes & 0x3F) << 8;
                    }
                }
                let mut w = Writer::new();
                proto_gpu::Rect::SCREEN
                    .write(&mut w)
                    .map_err(say("FLUSH's bytes"))?;
                sys::send(&owner, w.as_bytes()).map_err(say("FLUSH"))?;
                flushes += 1;
            }
            let close = proto_gpu::Method::Close.header().bytes();
            sys::send(&owner, &close).map_err(say("CLOSE"))?;
            rt::println!("frame-load: legacy {} flushes {flushes}", phase.name());
        }
        Ok(())
    }

    // ---- cpu ----

    fn cpu(&self) -> Result<(), Fail> {
        self.on_time("cpu")?;
        for phase in ORDER {
            // The quiet phase is the loop alone: the figure the others are
            // compared with.
            let runs = phase == Phase::Quiet || phase.loads().cpu;
            if !runs {
                continue;
            }
            let start = self.schedule.start_of(phase);
            self.sleep_until(start);
            let end = if phase == Phase::Quiet {
                // One second is enough for the loop alone.
                start + 1_000_000_000
            } else {
                self.schedule.end_of(phase)
            };
            let began = now();
            let mut loops = 0u64;
            let mut x = 1u64;
            while now() < end {
                for _ in 0..1024 {
                    x = core::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
                }
                loops += 1024;
            }
            let elapsed = now() - began;
            rt::println!("{}", CpuLine(phase, loops_per_second(loops, elapsed)));
        }
        Ok(())
    }
}
