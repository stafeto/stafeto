// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `fork` by a full copy (spec 2, 3.2; 5d). The calling thread keeps its
//! registers of the AAPCS64 callee (x19 to x30, the stack pointer, d8 to
//! d15, FPCR, FPSR and TPIDR_EL0) in CONTEXT (`point`), and the process
//! service makes the child's record and process with the loader in it
//! (ForkStart, with the classes of the process's actions for the child's
//! page). The loader of the child takes the objects of the layer's memory
//! map (Fork, Regions), copies them into objects the child pays for at the
//! same addresses (Go), and once ForkCommit made the child live it writes
//! the child's handles into TRANSFER and jumps to `resume`, which takes
//! the registers back from the copy of CONTEXT and returns 0 from `point`
//! on the copy of the caller's stack. A program init started has no
//! segments in its map, and gets ENOSYS. No copy on write: the child pays
//! for every page it gets. `fork` stops the process's other threads first
//! (crate::signals::stop_others, as exec does): each parks outside every
//! critical section of the layer, so no lock of the layer is held in the
//! copy, and the child has the calling thread alone. relibc's lock of its
//! allocator is the calling thread's through its pthread_atfork handlers.
//! `fork` gives the child clones of the process's sessions too, and the
//! child binds every part of the layer to its own handles (`child`)
//! before it returns.

use crate::constants::*;
use crate::process::{ask, ask_loader, client, load_errno, request, start_errno};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use proto_loader::{Fork, Method, REGIONS_MAX, Region, TRANSFER_SIZE};
use proto_wire::{Status, Writer};
use rt::abi::{Access, Rights};
use rt::handle::{Channel, Handle, Memory, Outgoing};

/// The registers of the callee the calling thread had at `point`: x19 to
/// x30, the stack pointer, d8 to d15, FPCR, FPSR and TPIDR_EL0.
#[repr(C)]
struct Registers {
    x: [u64; 12],
    sp: u64,
    d: [u64; 8],
    fpcr: u64,
    fpsr: u64,
    tpidr: u64,
}

struct Context(UnsafeCell<Registers>);
// SAFETY: only `point` writes it, one fork at a time (FORKING), and only
// `resume` reads it, in the child, before anything else runs there.
unsafe impl Sync for Context {}
static CONTEXT: Context = Context(UnsafeCell::new(Registers {
    x: [0; 12],
    sp: 0,
    d: [0; 8],
    fpcr: 0,
    fpsr: 0,
    tpidr: 0,
}));
const _: () = {
    assert!(core::mem::offset_of!(Registers, sp) == 96);
    assert!(core::mem::offset_of!(Registers, d) == 104);
    assert!(core::mem::offset_of!(Registers, fpcr) == 168);
    assert!(core::mem::offset_of!(Registers, tpidr) == 184);
};

/// Where the child's loader writes its handles and map
/// (proto_loader::write_transfer), in the layer's data.
#[repr(C, align(8))]
struct Transfer(UnsafeCell<[u8; TRANSFER_SIZE]>);
// SAFETY: only the child's loader writes it, before the child runs, and
// the child alone reads it then.
unsafe impl Sync for Transfer {}
static TRANSFER: Transfer = Transfer(UnsafeCell::new([0; TRANSFER_SIZE]));

/// One fork of the process at a time: CONTEXT and TRANSFER are one.
static FORKING: AtomicBool = AtomicBool::new(false);

/// Keeps the registers of the callee in CONTEXT and tail-calls `work`
/// with `arg`: `work`'s value comes back to the caller of `point`. In the
/// child `resume` returns 0 from it.
///
/// # Safety
/// One call at a time (FORKING); `work` writes nothing of the caller's
/// frame that the child may not see as it was then.
#[unsafe(naked)]
unsafe extern "C" fn point(work: extern "C" fn(u64) -> i64, arg: u64) -> i64 {
    core::arch::naked_asm!(
        "adrp x9, {context}",
        "add x9, x9, :lo12:{context}",
        "stp x19, x20, [x9, #0]",
        "stp x21, x22, [x9, #16]",
        "stp x23, x24, [x9, #32]",
        "stp x25, x26, [x9, #48]",
        "stp x27, x28, [x9, #64]",
        "stp x29, x30, [x9, #80]",
        "mov x10, sp",
        "str x10, [x9, #96]",
        "stp d8, d9, [x9, #104]",
        "stp d10, d11, [x9, #120]",
        "stp d12, d13, [x9, #136]",
        "stp d14, d15, [x9, #152]",
        "mrs x10, fpcr",
        "str x10, [x9, #168]",
        "mrs x10, fpsr",
        "str x10, [x9, #176]",
        "mrs x10, tpidr_el0",
        "str x10, [x9, #184]",
        "mov x9, x0",
        "mov x0, x1",
        "br x9",
        context = sym CONTEXT,
    )
}

/// The child's first instruction, where its loader jumps: the registers
/// of CONTEXT back, TPIDR_EL0 among them (written at EL0), and 0 from
/// `point` to its caller.
#[unsafe(naked)]
unsafe extern "C" fn resume() -> ! {
    core::arch::naked_asm!(
        "adrp x9, {context}",
        "add x9, x9, :lo12:{context}",
        "ldp x19, x20, [x9, #0]",
        "ldp x21, x22, [x9, #16]",
        "ldp x23, x24, [x9, #32]",
        "ldp x25, x26, [x9, #48]",
        "ldp x27, x28, [x9, #64]",
        "ldp x29, x30, [x9, #80]",
        "ldr x10, [x9, #96]",
        "mov sp, x10",
        "ldp d8, d9, [x9, #104]",
        "ldp d10, d11, [x9, #120]",
        "ldp d12, d13, [x9, #136]",
        "ldp d14, d15, [x9, #152]",
        "ldr x10, [x9, #168]",
        "msr fpcr, x10",
        "ldr x10, [x9, #176]",
        "msr fpsr, x10",
        "ldr x10, [x9, #184]",
        "msr tpidr_el0, x10",
        "mov x0, #0",
        "ret",
        context = sym CONTEXT,
    )
}

/// Where a fork came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forked {
    /// In the parent, with the child's PID.
    Parent(i32),
    /// In the child: nothing of the layer is bound to it yet.
    Child,
}

/// What the parent's work came to, in the frame of `copy`'s caller.
/// The sessions for the child are raw values: a copy of them in the
/// child names nothing of its own, and nothing there may close them.
struct Work {
    window: Option<fn()>,
    sessions: Sessions,
    result: Result<i32, i32>,
}

/// The values of the sessions a fork gives the child's loader (Handles),
/// by proto_loader::Slot: Files, Clock, Uart, Pipes and Entropy; 0 for
/// none.
#[derive(Clone, Copy, Default)]
pub struct Sessions {
    pub files: u64,
    pub clock: u64,
    pub uart: u64,
    pub pipes: u64,
    pub entropy: u64,
}

impl Sessions {
    /// The parent's own sessions go: those of a fork that never came to
    /// its loader.
    fn close(self) {
        for raw in [self.files, self.clock, self.uart, self.pipes, self.entropy] {
            if raw != 0 {
                drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
            }
        }
    }
}

extern "C" fn work(arg: u64) -> i64 {
    // SAFETY: `copy` passes its own Work, which lives across `point`.
    let work = unsafe { &mut *(arg as *mut Work) };
    let sessions = core::mem::take(&mut work.sessions);
    work.result = parent(work.window, sessions);
    1
}

/// The copy of the calling process into a child (the module's text): in
/// the parent the child's PID once ForkCommit made it live, or the errno
/// of why none came (the child gone): ENOSYS for a program without
/// segments in its map, EAGAIN past the service's limits or while another
/// fork of the process goes on, ENOMEM past the pool or the child's quota.
/// `window` runs in the parent once the copy is ready, before ForkCommit
/// (the probes). The child's loader gets `sessions` (Handles), which the
/// parent has no more afterwards. In the child nothing of the layer is
/// bound to it: the caller binds it before it calls anything of the layer.
pub fn copy(window: Option<fn()>, sessions: Sessions) -> Result<Forked, i32> {
    if FORKING.swap(true, Ordering::AcqRel) {
        sessions.close();
        return Err(EAGAIN);
    }
    let mut w = Work {
        window,
        sessions,
        result: Err(EIO),
    };
    // SAFETY: one fork at a time (FORKING); `work` writes only `w`.
    let from = unsafe { point(work, (&raw mut w) as u64) };
    if from == 0 {
        // The child's own flag, which the copy took raised.
        FORKING.store(false, Ordering::Release);
        return Ok(Forked::Child);
    }
    FORKING.store(false, Ordering::Release);
    w.result.map(Forked::Parent)
}

/// Handles: the sessions for the child to its loader `c`, each that is
/// there; they move whatever comes of it. Four go in one message, the
/// entropy service's in a second.
fn give(c: &Handle<Channel>, sessions: Sessions) -> Result<(), i32> {
    use proto_loader::Slot;
    give_slots(
        c,
        &[
            (Slot::Files, sessions.files),
            (Slot::Clock, sessions.clock),
            (Slot::Uart, sessions.uart),
            (Slot::Pipes, sessions.pipes),
        ],
    )
    .and(give_slots(c, &[(Slot::Entropy, sessions.entropy)]))
}

/// One Handles of the sessions `slots` (four at most) that are there.
pub(crate) fn give_slots(
    c: &Handle<Channel>,
    slots: &[(proto_loader::Slot, u64)],
) -> Result<(), i32> {
    let mut w = Writer::new();
    Method::Handles.header().write(&mut w).map_err(|_| EIO)?;
    let mut handles = Outgoing::new();
    for &(slot, raw) in slots {
        if raw != 0 {
            let session = Handle::<Channel>::from_raw(rt::abi::Handle(raw));
            w.u32(slot as u32).map_err(|_| EIO)?;
            handles.push(session.erase()).map_err(|_| EIO)?;
        }
    }
    if handles.is_empty() {
        return Ok(());
    }
    match ask_loader(c, &w, Some(handles)) {
        0 => Ok(()),
        _ => Err(EIO),
    }
}

/// The regions of the memory map as the child's loader takes them, with
/// a copy of each handle (MAP_READ, TRANSFER) for it.
struct Regions {
    count: usize,
    regions: [Option<(Region, Handle<Memory>)>; REGIONS_MAX],
}

/// The map's regions, under the heap's lock; ENOSYS when no code region
/// holds `resume` (a program init started), ENOMEM when a copy of a handle
/// fails.
fn regions() -> Result<Regions, i32> {
    let mut out = Regions {
        count: 0,
        regions: [const { None }; REGIONS_MAX],
    };
    let at = resume as *const () as u64;
    // The values under the heap's lock, the copies of the handles out of
    // it: the map only grows, so each value stays its region's.
    let mut seen = [(
        Region {
            address: 0,
            pages: 0,
            access: Access::Read,
        },
        0u64,
    ); REGIONS_MAX];
    let count = crate::allocation::regions(|map| {
        let mut count = 0;
        for (place, region) in seen.iter_mut().zip(map.iter()) {
            *place = (
                Region {
                    address: region.address as u64,
                    pages: u32::try_from(region.pages).map_err(|_| ENOMEM)?,
                    access: region.access,
                },
                region.handle.raw().0,
            );
            count += 1;
        }
        Ok::<usize, i32>(count)
    })?;
    let mut code = false;
    for (region, raw) in &seen[..count] {
        code |= region.access == Access::ReadExec && region.holds(at);
        let held = Handle::<Memory>::borrowed(rt::abi::Handle(*raw));
        let copy = rt::sys::handle_duplicate(&*held, Rights::MAP_READ | Rights::TRANSFER)
            .map_err(|_| ENOMEM)?;
        out.regions[out.count] = Some((*region, copy));
        out.count += 1;
    }
    if code { Ok(out) } else { Err(ENOSYS) }
}

/// The parent's side of a fork: ForkStart, then Fork, Regions and Go
/// through the child's loader, the window and ForkCommit; ForkAbort when
/// anything fails after ForkStart.
fn parent(window: Option<fn()>, sessions: Sessions) -> Result<i32, i32> {
    let regions = match regions() {
        Ok(regions) => regions,
        Err(errno) => {
            sessions.close();
            return Err(errno);
        }
    };
    let level = crate::threads::own_block()
        .base_level
        .load(Ordering::Relaxed) as u8;
    let page = crate::process::page();
    let start = proto_process::ForkStart {
        level,
        ignored: page.ignored.load(Ordering::Acquire),
        caught: page.caught.load(Ordering::Acquire),
        flags: page.flags.load(Ordering::Acquire) & proto_process::PAGE_FLAGS,
    };
    let mut w = Writer::new();
    proto_process::Method::ForkStart
        .header()
        .write(&mut w)
        .map_err(|_| EIO)?;
    start.write(&mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut reply = loop {
        match rt::sys::send(client().session(), w.as_bytes()) {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => {
                sessions.close();
                return Err(EAGAIN);
            }
            Ok(reply) => break reply,
        }
    };
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    let status = Status::from_code(r.u32().unwrap_or(proto_wire::BAD_SIZE));
    let pid = r.u32().unwrap_or(0);
    let c = reply.handles.take::<Channel>(0);
    let c = match (status, c) {
        (Status::Ok, Ok(c)) => c,
        (status, _) => {
            sessions.close();
            return Err(if status == Status::Ok {
                EIO
            } else {
                start_errno(status)
            });
        }
    };
    let made = make(&c, regions, sessions, window);
    let method = match made {
        Ok(()) => proto_process::Method::ForkCommit,
        Err(_) => proto_process::Method::ForkAbort,
    };
    let told = ask(&request(method, &[pid])?);
    made.and(told).map(|_| pid as i32)
}

/// Fork, Regions, Handles with `sessions` and Go through the child's
/// loader `c`, then `window`.
fn make(
    c: &Handle<Channel>,
    regions: Regions,
    sessions: Sessions,
    window: Option<fn()>,
) -> Result<(), i32> {
    // SAFETY: only CONTEXT's address and its stack pointer, which `point`
    // wrote before this ran.
    let sp = unsafe { (*CONTEXT.0.get()).sp };
    let fork = Fork {
        pc: resume as *const () as u64,
        sp,
        transfer: TRANSFER.0.get() as u64,
        regions: regions.count as u32,
    };
    let mut w = Writer::new();
    Method::Fork.header().write(&mut w).map_err(|_| EIO)?;
    fork.write(&mut w).map_err(|_| EIO)?;
    if ask_loader(c, &w, None) != 0 {
        sessions.close();
        return Err(EIO);
    }
    give(c, sessions)?;
    let Regions { count, regions } = regions;
    let mut list = regions.into_iter().take(count).flatten().peekable();
    while list.peek().is_some() {
        let mut w = Writer::new();
        Method::Regions.header().write(&mut w).map_err(|_| EIO)?;
        let mut handles = Outgoing::new();
        for (region, handle) in list.by_ref().take(rt::abi::MESSAGE_HANDLES) {
            region.write(&mut w).map_err(|_| EIO)?;
            handles.push(handle.erase()).map_err(|_| EIO)?;
        }
        if ask_loader(c, &w, Some(handles)) != 0 {
            return Err(EIO);
        }
        let early = EARLY.swap(0, Ordering::AcqRel);
        if early != 0 {
            // SAFETY: only `probe_early_window` stores a value, a `fn()`.
            let early: fn() = unsafe { core::mem::transmute::<usize, fn()>(early) };
            early();
        }
    }
    let mut w = Writer::new();
    Method::Go.header().write(&mut w).map_err(|_| EIO)?;
    match ask_loader(c, &w, None) {
        0 => {}
        code => return Err(load_errno(code)),
    }
    if let Some(window) = window {
        window();
    }
    Ok(())
}

/// The probe of a bare fork (5d): every signal of the caller held across
/// the copy; in the child `child` runs on the copy with nothing of the
/// layer bound and the process exits with its value; in the parent the
/// mask comes back and the child's PID, or the errno.
pub fn probe_bare(child: impl FnOnce() -> i32, window: Option<fn()>) -> Result<i32, i32> {
    let block = crate::threads::own_block();
    let mask = block.mask.swap(!0, Ordering::SeqCst);
    match copy(window, Sessions::default()) {
        Ok(Forked::Child) => rt::sys::process_exit(child() as u64 & 0xFF),
        result => {
            block.mask.store(mask, Ordering::SeqCst);
            crate::signals::deliver_now();
            result.map(|forked| match forked {
                Forked::Parent(pid) => pid,
                Forked::Child => 0,
            })
        }
    }
}

/// The probe of a load of ForkStart that never gets its copy: SpawnCommit
/// of the child (ESRCH: no child of SpawnStart), ForkCommit (EIO: the
/// loader is not ready), then ForkAbort; the child's PID in `pid`, and 0
/// when the two were refused so, else the errno each gave in the bytes.
pub fn probe_abort(pid: &mut i32) -> i32 {
    use proto_process::Method::{ForkAbort, ForkCommit, ForkStart, SpawnCommit};
    let mut w = Writer::new();
    let start = proto_process::ForkStart {
        level: crate::threads::own_block()
            .base_level
            .load(Ordering::Relaxed) as u8,
        ignored: 0,
        caught: 0,
        flags: 0,
    };
    if ForkStart.header().write(&mut w).is_err() || start.write(&mut w).is_err() {
        return EIO;
    }
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let Ok(mut reply) = rt::sys::send(client().session(), w.as_bytes()) else {
        return EIO;
    };
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    let status = Status::from_code(r.u32().unwrap_or(proto_wire::BAD_SIZE));
    if status != Status::Ok {
        return start_errno(status);
    }
    let child = r.u32().unwrap_or(0);
    let _c = reply.handles.take::<Channel>(0);
    *pid = child as i32;
    let errno = |method| match request(method, &[child]).and_then(|w| ask(&w)) {
        Ok(_) => 0,
        Err(errno) => errno,
    };
    let spawn = errno(SpawnCommit);
    let early = errno(ForkCommit);
    let _ = errno(ForkAbort);
    if spawn == ESRCH && early == EIO {
        0
    } else {
        spawn | early << 8
    }
}

/// The most mappings an object of the memory map has, for the probe that
/// a child's loader leaves no mapping of the parent's objects behind.
pub fn probe_mappings() -> u64 {
    crate::allocation::regions(|map| {
        map.iter()
            .filter_map(|r| rt::sys::memory_info(&r.handle).ok())
            .map(|info| info.mappings)
            .max()
            .unwrap_or(0)
    })
}

/// fork ([P24-FORK]; spec 2, 3.2): the calling thread holds every signal
/// from here to its return, so a signal to the process waits on its page
/// and one to its group reaches the child's page too (ForkStart writes
/// the classes before the child's record is a target). The child gets
/// clones of the process's sessions with the RAM files (sharing the
/// descriptions of the descriptors without FD_CLOFORK, and so their
/// offsets), the clock and the console's input, and binds every part of
/// the layer to its own handles (`child`) before its return; its thread
/// keeps its mask and has no pending signal. The child's PID in the
/// parent, 0 in the child; EAGAIN, ENOMEM or ENOSYS as `copy` says, and
/// for a service out of clones.
pub fn fork(window: Option<fn()>) -> Result<i32, i32> {
    // A program init started has no code in its map: nothing to stop for.
    let at = resume as *const () as u64;
    let code = crate::allocation::regions(|map| {
        map.iter().any(|r| {
            r.access == Access::ReadExec
                && (r.address as u64..r.address as u64 + r.pages as u64 * 4096).contains(&at)
        })
    });
    if !code {
        return Err(ENOSYS);
    }
    let block = crate::threads::own_block();
    let mask = block.mask.swap(!0, Ordering::SeqCst);
    let result = crate::signals::stop_others()
        .and_then(|()| sessions())
        .and_then(|sessions| copy(window, sessions));
    if result == Ok(Forked::Child) {
        if let Err(why) = child() {
            rt::println!("posix-abi: a forked child could not bind {}", why);
            rt::sys::process_exit(127);
        }
    } else {
        crate::signals::resume_others();
    }
    block.mask.store(mask, Ordering::SeqCst);
    crate::signals::route();
    crate::signals::deliver_now();
    // fork's errors are EAGAIN and ENOMEM (and ENOSYS above): a refusal
    // of the loader or of a service is a limit of the moment.
    result
        .map(|forked| match forked {
            Forked::Parent(pid) => pid,
            Forked::Child => 0,
        })
        .map_err(|errno| match errno {
            ENOMEM | ENOSYS => errno,
            _ => EAGAIN,
        })
}

/// Clones of the process's sessions for a child (Clone): the RAM files'
/// with the descriptions of the descriptors without FD_CLOFORK, the
/// clock's, the console input's, the pipe service's with the ends of the
/// descriptors without FD_CLOFORK, and the entropy service's, each the
/// process has.
fn sessions() -> Result<Sessions, i32> {
    use crate::process::clone_errno;
    let mut out = Sessions::default();
    let made = (|| {
        if let Some(clock) = crate::clock::session() {
            let clone =
                rt::service::clone_session(clock, &proto_clock::Method::Clone.header().bytes())
                    .map_err(clone_errno)?;
            out.clock = clone.into_raw().0;
        }
        let mut kept = [0; posix_fs::OPEN_MAX];
        let count = crate::shared::kept_by_fork(&mut kept)?;
        let (files, uart) = crate::shared::with_files(|fs| {
            let (files, uart) = fs.sessions();
            Ok((files.raw(), uart.map(Handle::raw)))
        })?;
        let mut w = Writer::new();
        proto_fs::Method::Clone
            .header()
            .write(&mut w)
            .map_err(|_| EIO)?;
        w.u32(count as u32).map_err(|_| EIO)?;
        for n in &kept[..count] {
            w.u32(*n).map_err(|_| EIO)?;
        }
        // The sessions live as long as the process's files.
        let clone = rt::service::clone_session(&Handle::<Channel>::borrowed(files), w.as_bytes())
            .map_err(clone_errno)?;
        out.files = clone.into_raw().0;
        if let Some(uart) = uart {
            let clone = rt::service::clone_session(
                &Handle::<Channel>::borrowed(uart),
                &proto_uart::Method::Clone.header().bytes(),
            )
            .map_err(clone_errno)?;
            out.uart = clone.into_raw().0;
        }
        let mut ends = [0; posix_fs::OPEN_MAX];
        let count = crate::shared::pipes_kept_by_fork(&mut ends)?;
        if let Some(pipes) = crate::shared::with_files(|fs| Ok(fs.pipes().map(Handle::raw)))? {
            let clone = pipes_clone(pipes, &ends[..count])?;
            out.pipes = clone.into_raw().0;
        }
        if let Some(clone) = entropy_clone()? {
            out.entropy = clone.into_raw().0;
        }
        Ok(())
    })();
    match made {
        Ok(()) => Ok(out),
        Err(errno) => {
            out.close();
            Err(errno)
        }
    }
}

/// A clone of the process's session with the entropy service for a child
/// (proto_entropy CLONE), when it has one.
pub(crate) fn entropy_clone() -> Result<Option<Handle<Channel>>, i32> {
    use crate::process::clone_errno;
    let Some(entropy) = crate::random::session() else {
        return Ok(None);
    };
    rt::service::clone_session(
        &Handle::<Channel>::borrowed(entropy),
        &proto_entropy::Method::Clone.header().bytes(),
    )
    .map(Some)
    .map_err(clone_errno)
}

/// Clone of the session `pipes` with the pipe service for a child: a
/// session that holds the ends `ends` (proto_pipe CLONE).
pub(crate) fn pipes_clone(pipes: rt::abi::Handle, ends: &[u32]) -> Result<Handle<Channel>, i32> {
    use crate::process::clone_errno;
    let mut w = Writer::new();
    proto_pipe::Method::Clone
        .header()
        .write(&mut w)
        .and_then(|()| w.u32(ends.len() as u32))
        .map_err(|_| EIO)?;
    for end in ends {
        w.u32(*end).map_err(|_| EIO)?;
    }
    // The session lives as long as the process's files.
    rt::service::clone_session(&Handle::<Channel>::borrowed(pipes), w.as_bytes())
        .map_err(clone_errno)
}

/// The function the next fork runs in the parent once the loader took the
/// first message of Regions (a probe of a parent that dies there), 0 for
/// none.
static EARLY: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Sets the function the next fork runs after its first Regions.
pub fn probe_early_window(window: Option<fn()>) {
    EARLY.store(window.map_or(0, |f| f as usize), Ordering::Release);
}

/// What the child runs once at its start, set by the program's start
/// (posix-crt): its own state of the start goes.
static AT_CHILD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// `hook` runs in each forked child once the layer is bound to it.
pub fn at_child(hook: fn()) {
    AT_CHILD.store(hook as usize, Ordering::Release);
}

/// The child binds every part of the layer to the handles its loader
/// wrote into TRANSFER (spec 2, 3.2): its heap and map, its thread with a
/// new channel and timer and its place in the table, the table of waits
/// by address empty, its record and identity, its files, its clock and
/// its page of the anchor, the console, its entry of signals and its
/// router; then AT_CHILD. What fails is named.
fn child() -> Result<(), &'static str> {
    use proto_loader::Slot;
    // SAFETY: the loader wrote the transfer before it jumped to `resume`,
    // and nothing writes it in the child.
    let bytes = unsafe { &*TRANSFER.0.get() };
    let transfer = proto_loader::Transfer::read(bytes).ok_or("its transfer")?;
    let raw = |slot: Slot| transfer.handles[slot as usize];
    fn handle<K>(raw: u64) -> Option<Handle<K>> {
        (raw != 0).then(|| Handle::from_raw(rt::abi::Handle(raw)))
    }
    rt::console::forget();
    if let Some(console) = handle(raw(Slot::Console)) {
        rt::console::set(console);
    }
    let process = handle(raw(Slot::Process)).ok_or("its process")?;
    let thread = handle(raw(Slot::Thread)).ok_or("its thread")?;
    let posix = handle(raw(Slot::Posix)).ok_or("its record")?;
    let map = transfer.map().map(|entry| {
        (
            entry.address as usize,
            entry.pages as usize,
            entry.access,
            Handle::from_raw(rt::abi::Handle(entry.handle)),
        )
    });
    // SAFETY: the child's only thread, before anything else of the layer.
    unsafe {
        crate::allocation::after_fork(process, map).map_err(|_| "its memory map")?;
        crate::threads::after_fork(thread).map_err(|_| "its thread")?;
        posix_sync::after_fork();
        crate::process::after_fork(posix, handle(raw(Slot::PosixId))).map_err(|_| "its record")?;
        if let Some(files) = handle(raw(Slot::Files)) {
            crate::shared::after_fork(files, handle(raw(Slot::Uart)), handle(raw(Slot::Pipes)));
        }
        crate::clock::after_fork(handle(raw(Slot::Clock)), crate::allocation::process())
            .map_err(|_| "its clock")?;
        // The parent's key and buffer go: the child asks for a key of its
        // own at its first use.
        crate::random::after_fork(handle(raw(Slot::Entropy)));
        crate::signals::after_fork().map_err(|_| "its signals")?;
    }
    let id = crate::threads::thread_number();
    let (_, native) = crate::relibc::target(id).map_err(|_| "its place")?;
    crate::process::register_router(&native).map_err(|_| "its router")?;
    let hook = AT_CHILD.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `at_child` stores a value, a `fn()`.
        let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(hook) };
        hook();
    }
    Ok(())
}

/// Holds a lock of the layer for `ns` nanoseconds, spinning on the
/// counter inside its critical section: 0 the heap's, 1 the files', 2 the
/// bucket of the table of waits by address of `probe_hold`'s own word;
/// EINVAL for another. For the probes of a fork while other threads hold
/// the layer's locks: the fork waits for the end of each section.
pub fn probe_hold(which: u32, ns: u64) -> i32 {
    static WORD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let end = rt::time::ticks_to_ns(rt::time::now()) + ns;
    let spin = || while !rt::time::reached(end) {};
    match which {
        0 => crate::allocation::hold(spin),
        1 => crate::shared::hold(spin),
        2 => posix_sync::hold_bucket(WORD.as_ptr() as usize, spin),
        _ => return EINVAL,
    }
    0
}

/// How many places of the table of threads hold a thread.
pub fn probe_threads() -> usize {
    crate::relibc::occupied()
}
