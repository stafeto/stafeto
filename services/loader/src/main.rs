// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loader of POSIX programs from files (spec 2, 3.2; 5c). The process
//! service maps it into a new process, in the region from
//! proto_loader::LOADER_BASE, with its session to the service in entry 0,
//! and starts it at the parent's level, x0. The loader makes its start
//! channel C, gives the service its two copies (Boot) and takes from the
//! reply its process, its thread, the session of the loaders with the RAM
//! file service and its identity: the only handles it uses for its own
//! requests (condition O2). Through C the parent gives the block (Start), which the
//! loader copies before it reads it, and says Go: the loader opens
//! the program through the session of the loaders with a copy of its
//! identity (OpenExec, condition O1), has the file service copy its ELF file into objects
//! of the new process, which pays for them, tells the service the image
//! is ready (Ready, before which no commit of its place is taken) and
//! answers "the image is ready" or why not. The parent gives the program's sessions (Handles);
//! once the service says through C that the record is ready (label 2, the
//! only notification the loader trusts), the loader takes the program's
//! sessions and credentials (Take), writes the start area, closes all that
//! was its own, the image session, the loaders' session and its identity
//! among them (condition O6), unmaps its data and stack and jumps to the program.
//!
//! For a `fork` (5d) the parent gives Fork in place of Start, then the
//! objects of its memory map (Regions), and Go makes the copy: each region
//! goes into an object of the new process at the parent's address with the
//! parent's access, the parent's bytes read through a window of the
//! loader's region (`copy`). Once the record is ready the loader writes the
//! child's handles and map into the layer's transfer and jumps to the
//! layer's point of return on the parent's stack (`finish_fork`).

#![no_std]
#![no_main]

use abi::{INIT_STACK_TOP, INLINE_MAX, MESSAGE_MAX, Rights, START_CHANNEL, Source};
use bootimg::Part;
use bootimg::elf::{self, Load};
use core::mem::MaybeUninit;
use proto_loader::{
    self as pl, AREA_MAX, BLOCK_MAX, Block, BlockError, Fork, LOADER_BASE, MAP_ENTRIES, MapEntry,
    Method, PROGRAM_ROOM, REGIONS_MAX, Region, SLOTS, STACK_SIZE, START_AREA, Slot, TRANSFER_SIZE,
};
use proto_wire::{Header, Reader, Status, Writer};
use rt::abi::{Access, Error};
use rt::handle::{Channel, Handle, Memory, Process, Resource, Thread};
use rt::sys::{self, Received, Token};
use rt::{loader, msgbuf};

rt::entry!(main);

const PAGE: u64 = 4096;
/// Where the loader keeps its copy of the block, in its own region.
const STAGING: u64 = LOADER_BASE + (4 << 20);
/// Where it maps the parent's block to copy it.
const BORROWED: u64 = LOADER_BASE + (6 << 20);
/// Where it maps a piece of an object of the parent's memory to copy it
/// (Fork), WINDOW bytes at most.
const WINDOW: u64 = LOADER_BASE + (8 << 20);
#[cfg(not(feature = "small-pieces"))]
const PIECE: u64 = 4 << 20;
#[cfg(feature = "small-pieces")]
const PIECE: u64 = 64 << 10;
/// The exit code of a loader that gave up: the parent hears why through C
/// first, or its wait reports 127 (posix_spawn's fallback, [MUSL-SPAWN]).
const GAVE_UP: u64 = 127;

/// The steps of a copy under `-icount` (feature `steps`, xtask
/// process-steps): each kernel call of `copy` and `fill` with its ticks,
/// the longest of each kind with its detail printed once the console the
/// service gave the program is there (`report`). Without the feature a
/// step is its closure.
#[cfg(feature = "steps")]
mod steps {
    use core::sync::atomic::{AtomicU64, Ordering};
    static LONGEST: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
    static DETAIL: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

    pub fn timed<T>(kind: usize, detail: u64, step: impl FnOnce() -> T) -> T {
        let began = rt::time::now();
        let out = step();
        let took = rt::time::now().saturating_sub(began);
        if took > LONGEST[kind].fetch_max(took, Ordering::Relaxed) {
            DETAIL[kind].store(detail, Ordering::Relaxed);
        }
        out
    }

    /// One line for each kind that ran, through a copy of `console`.
    pub fn report(console: &rt::handle::Handle<rt::handle::Resource>) {
        // The console is the program's: a borrowed name of it prints here.
        rt::console::set(core::mem::ManuallyDrop::into_inner(
            rt::handle::Handle::borrowed(console.raw()),
        ));
        for kind in 0..LONGEST.len() {
            let took = LONGEST[kind].load(Ordering::Relaxed);
            if took != 0 {
                let detail = DETAIL[kind].load(Ordering::Relaxed);
                rt::println!("loader step: kind {kind} {took} ticks detail {detail}");
            }
        }
    }
}

#[cfg(not(feature = "steps"))]
mod steps {
    pub fn timed<T>(_: usize, _: u64, step: impl FnOnce() -> T) -> T {
        step()
    }
}

/// The kinds of the steps of a copy.
mod kind {
    pub const MEM_CREATE: usize = 1;
    pub const MAP_NEW: usize = 2;
    pub const MAP_PIECE: usize = 3;
    pub const COPY_PIECE: usize = 4;
    pub const UNMAP_PIECE: usize = 5;
    pub const REMAP: usize = 6;
    pub const DUPLICATE: usize = 7;
    pub const REGIONS: usize = 8;
    pub const GO: usize = 9;
}

/// What Boot brought: the loader's own handles from the service.
struct Own {
    process: Handle<Process>,
    thread: Handle<Thread>,
    files: Handle<Channel>,
    clock: Handle<Channel>,
    identity: Handle<Channel>,
    /// The loader's data and stack, which it unmaps at its end.
    data: (u64, u64),
}

fn main(level: u64) -> u64 {
    let level = (level as u8).clamp(1, 63);
    // SAFETY: entry 0 is the loader's session with the service, which the
    // service put there (process_create x5) and nothing else holds.
    let session = Handle::<Channel>::from_raw(START_CHANNEL);
    let Ok(start) = sys::channel_create(level) else {
        return GAVE_UP;
    };
    let Ok(own) = boot(&session, &start, level) else {
        return GAVE_UP;
    };
    let Some(done) = serve(&session, &start, &own) else {
        return GAVE_UP;
    };
    let Ok(taken) = take(&session) else {
        return GAVE_UP;
    };
    #[cfg(feature = "steps")]
    if matches!(done, Done::Copied(_))
        && let Some(console) = taken.console.as_ref()
    {
        steps::report(console);
    }
    match done {
        Done::Loaded(loaded) => finish(session, start, own, loaded, taken),
        Done::Copied(copied) => finish_fork(session, start, own, copied, taken),
    }
}

/// Boot: the copies of C for the parent (SEND, label 1) and for the
/// service (NOTIFY, label 2) go to the service, which answers with the
/// loader's own handles.
fn boot(session: &Handle<Channel>, start: &Handle<Channel>, level: u8) -> Result<Own, Error> {
    let parent = sys::handle_label(start, Rights::SEND | Rights::TRANSFER, pl::PARENT, level)?;
    let service = sys::handle_label(start, Rights::NOTIFY | Rights::TRANSFER, pl::SERVICE, level)?;
    let request = proto_process::Method::Boot.header().bytes();
    let mut reply = sys::send_handles(session, &request, [parent.erase(), service.erase()])
        .map_err(|refused| refused.error)?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    if r.u32() != Ok(0) {
        return Err(Error::BadState);
    }
    let data = (
        r.u64().map_err(|_| Error::BadState)?,
        r.u64().map_err(|_| Error::BadState)?,
    );
    Ok(Own {
        process: reply.handles.take(0)?,
        thread: reply.handles.take(1)?,
        files: reply.handles.take(2)?,
        identity: reply.handles.take(3)?,
        clock: loader_clock(session).map_err(|_| Error::BadState)?,
        data,
    })
}

/// What the parent's requests left: the copy of the block, the program's
/// entry, the image session, the memory map and the sessions Handles gave.
struct Loaded {
    block_len: usize,
    entry: u64,
    image: Handle<Channel>,
    maps: Maps,
    given: [Option<Handle<Channel>>; SLOTS],
}

/// One object `load` mapped, which the program's memory map keeps (spec 2,
/// 3.2): where it lies, how many pages, with what access, and a handle
/// narrowed to MAP_READ, DUPLICATE and TRANSFER, with MAP_WRITE for a
/// writable part. The handle never carries MAP_EXEC, so the layer cannot
/// map the code writable or the data executable through it.
struct Kept {
    address: u64,
    pages: u32,
    access: Access,
    handle: Handle<Memory>,
}

/// The program's segments, stack and start area, in the order `load`
/// mapped them.
type Maps = [Option<Kept>; MAP_ENTRIES];

/// Keeps a narrowed handle of `m`, which `load` mapped as `len` bytes at
/// `address` with `access`, for the program's memory map: the rights of
/// `Kept`. The program's start area has room for MAP_ENTRIES entries, the
/// three segments, the stack and itself.
fn keep_region(
    maps: &mut Maps,
    m: &Handle<Memory>,
    address: u64,
    len: u64,
    access: Access,
) -> Result<(), u32> {
    let mut rights = Rights::MAP_READ | Rights::DUPLICATE | Rights::TRANSFER;
    if access == Access::ReadWrite {
        rights = rights | Rights::MAP_WRITE;
    }
    let place = maps.iter_mut().find(|place| place.is_none());
    let (Some(place), Ok(pages)) = (place, u32::try_from(len / PAGE)) else {
        return Err(pl::TOO_BIG);
    };
    let handle = sys::handle_duplicate(m, rights).map_err(code)?;
    *place = Some(Kept {
        address,
        pages,
        access,
        handle,
    });
    Ok(())
}

/// The bytes of the copy of the block.
fn staged(len: usize) -> &'static [u8] {
    // SAFETY: the copy lies at STAGING, mapped read and write for the
    // loader's life (`stage`), and nothing writes it after Start.
    unsafe { core::slice::from_raw_parts(STAGING as *const u8, len) }
}

/// What the parent's requests came to: a program loaded from its file
/// (Start), or a copy of the parent's memory (Fork).
enum Done {
    Loaded(Loaded),
    Copied(Copied),
}

/// The copy a Fork made: Fork's body, the scratch with the objects of the
/// child's map, and the sessions Handles gave.
struct Copied {
    fork: Fork,
    scratch: &'static mut Scratch,
    given: [Option<Handle<Channel>>; SLOTS],
}

/// The loader's notes of a copy, in an object of its own at STAGING (too
/// big for its stack): the regions Regions brought and the parent's
/// handle of each, then the objects of the child's map.
struct Scratch {
    count: usize,
    regions: [MaybeUninit<Region>; REGIONS_MAX],
    parents: [u64; REGIONS_MAX],
    kept: usize,
    map: [MaybeUninit<MapEntry>; REGIONS_MAX],
}

impl Scratch {
    /// The regions that came.
    fn regions(&self) -> &[Region] {
        // SAFETY: Regions wrote the first `count` regions.
        unsafe { core::slice::from_raw_parts(self.regions.as_ptr().cast(), self.count) }
    }

    /// The entries of the child's map.
    fn map(&self) -> &[MapEntry] {
        // SAFETY: `copy` wrote the first `kept` entries.
        unsafe { core::slice::from_raw_parts(self.map.as_ptr().cast(), self.kept) }
    }
}

/// The pages of the scratch.
const SCRATCH_LEN: u64 = (core::mem::size_of::<Scratch>() as u64).next_multiple_of(PAGE);

/// The scratch of a copy: a new object mapped at STAGING, which the new
/// process pays for, all zeros.
fn scratch(own: &Own) -> Result<&'static mut Scratch, Status> {
    let m = sys::mem_create(SCRATCH_LEN).map_err(Status::Kernel)?;
    sys::mem_map(
        &own.process,
        &m,
        0,
        SCRATCH_LEN,
        STAGING as usize,
        Access::ReadWrite,
    )
    .map_err(Status::Kernel)?;
    // SAFETY: the object is mapped at STAGING for the loader's life, its
    // zeros are a Scratch with no region (MaybeUninit and integers), and
    // nothing else reaches it.
    Ok(unsafe { &mut *(STAGING as *mut Scratch) })
}

/// The requests of the parent through C and the service's word that the
/// record is ready: the load once Start and Go came, or the copy once
/// Fork, the regions and Go came, and the end once the image or the copy
/// is ready and the record too. None when the loader gives up.
fn serve(session: &Handle<Channel>, start: &Handle<Channel>, own: &Own) -> Option<Done> {
    let mut block_len = None;
    let mut loaded: Option<(u64, Handle<Channel>, Maps)> = None;
    let mut fork: Option<(Fork, &'static mut Scratch)> = None;
    let mut copied = false;
    // The sessions the block's descriptors need (Block::needs).
    let mut needed = [false; SLOTS];
    let mut given: [Option<Handle<Channel>>; SLOTS] = Default::default();
    let mut ready = false;
    let mut early_given = false;
    let mut completed = false;
    let mut terminal_actions = false;
    let mut trusted_terminal = None;
    let mut buffer = [0; MESSAGE_MAX];
    loop {
        if ready && (!completed || (0..SLOTS).any(|i| needed[i] && given[i].is_none())) {
            return None;
        }
        if ready && let Some((entry, image, maps)) = loaded.take() {
            return Some(Done::Loaded(Loaded {
                block_len: block_len?,
                entry,
                image,
                maps,
                given,
            }));
        }
        if ready && copied {
            let (fork, scratch) = fork?;
            return Some(Done::Copied(Copied {
                fork,
                scratch,
                given,
            }));
        }
        match sys::receive(start).ok()? {
            Received::Notification {
                source,
                label,
                bits,
                ..
            } => {
                // The service's word through its copy, label 2, bit 1: a
                // parent's copy carries no NOTIFY, and the end of the
                // service's copy (CLIENT_GONE) says nothing. The parent's
                // end (CLIENT_GONE of label 1) changes nothing either: its
                // death ends the child.
                if source == Source::Session && label == pl::SERVICE && bits & 1 != 0 {
                    ready = true;
                }
            }
            Received::Message {
                label,
                len,
                mut handles,
                token,
                words,
            } => {
                let bytes = &mut buffer[..len.min(MESSAGE_MAX)];
                if len <= INLINE_MAX {
                    bytes.copy_from_slice(&abi::inline_bytes(&words)[..len]);
                } else {
                    msgbuf::read(0, bytes);
                }
                let mut r = Reader::new(bytes);
                let method = match Header::read(&mut r) {
                    Ok(h) if label == pl::PARENT && h.version == pl::VERSION => {
                        Method::from_number(h.method)
                    }
                    _ => None,
                };
                let first = block_len.is_none() && fork.is_none();
                let status = match method {
                    Some(Method::Start) if first => {
                        let memory = handles.take::<Memory>(0).ok();
                        match (r.u32(), memory, r.finish()) {
                            (Ok(len), Some(memory), Ok(())) => {
                                match stage(own, &memory, len as usize) {
                                    Ok(len) => {
                                        block_len = Some(len);
                                        0
                                    }
                                    Err(status) => status.code(),
                                }
                            }
                            _ => Status::BadSize.code(),
                        }
                    }
                    Some(Method::Fork) if first => match Fork::read(r) {
                        Ok(body) if handles.is_empty() => match scratch(own) {
                            Ok(scratch) => {
                                fork = Some((body, scratch));
                                0
                            }
                            Err(status) => status.code(),
                        },
                        _ => Status::BadSize.code(),
                    },
                    Some(Method::Regions) if !copied => match fork.as_mut() {
                        Some((_, scratch)) => {
                            match steps::timed(kind::REGIONS, handles.len() as u64, || {
                                take_regions(r, &mut handles, scratch)
                            }) {
                                Ok(()) => 0,
                                Err(status) => status.code(),
                            }
                        }
                        None => Status::Kernel(Error::BadState).code(),
                    },
                    Some(Method::Go) if !copied && fork.is_some() => {
                        if trusted_terminal.is_none() {
                            trusted_terminal = match loader_terminal(session) {
                                Ok(terminal) => terminal,
                                Err(code) => {
                                    reply(token, code);
                                    return None;
                                }
                            };
                        }
                        let (body, scratch) = fork.as_mut()?;
                        let regions = scratch.count as u64;
                        match steps::timed(kind::GO, regions, || copy(own, body, scratch)).and_then(
                            |()| {
                                if completed {
                                    tell_ready(session)
                                } else {
                                    Ok(())
                                }
                            },
                        ) {
                            Ok(()) => {
                                copied = true;
                                0
                            }
                            Err(code) => {
                                let _ = token.reply(&proto_wire::reply(Status::from_code(code)));
                                return None;
                            }
                        }
                    }
                    Some(Method::Go) if block_len.is_some() && loaded.is_none() => {
                        if trusted_terminal.is_none() {
                            trusted_terminal = match loader_terminal(session) {
                                Ok(terminal) => terminal,
                                Err(code) => {
                                    reply(token, code);
                                    return None;
                                }
                            };
                        }
                        let Ok(block) = Block::read(staged(block_len?)) else {
                            reply(token, Status::BadSize.code());
                            return None;
                        };
                        let needs = Slot::GIVEN.map(|slot| (slot, block.needs(slot)));
                        if early_given && !completed {
                            reply(token, Status::Kernel(Error::BadState).code());
                            return None;
                        }
                        if completed
                            && needs
                                .iter()
                                .any(|(slot, needs)| *needs && given[*slot as usize].is_none())
                        {
                            reply(token, Status::BadSize.code());
                            return None;
                        }
                        match load(own, &block).and_then(|done| {
                            if completed {
                                tell_ready(session)?;
                            }
                            Ok(done)
                        }) {
                            Ok(done) => {
                                loaded = Some(done);
                                for (slot, needs) in needs {
                                    needed[slot as usize] = needs;
                                }
                                0
                            }
                            Err(code) => {
                                // The parent hears why, and the loader
                                // ends: the service reaps the child.
                                let _ = token.reply(&proto_wire::reply(Status::from_code(code)));
                                return None;
                            }
                        }
                    }
                    Some(Method::TerminalActions)
                        if block_len.is_some() && loaded.is_none() && !terminal_actions =>
                    {
                        terminal_actions = true;
                        if trusted_terminal.is_none() {
                            trusted_terminal = match loader_terminal(session) {
                                Ok(terminal) => terminal,
                                Err(code) => {
                                    reply(token, code);
                                    return None;
                                }
                            };
                        }
                        match open_terminals(own, trusted_terminal.as_ref(), r) {
                            Ok(()) => 0,
                            Err(code) => {
                                reply(token, code);
                                return None;
                            }
                        }
                    }
                    Some(Method::HandlesDone)
                        if !completed && (block_len.is_some() || fork.is_some()) =>
                    {
                        if r.finish().is_err() || !handles.is_empty() {
                            Status::BadSize.code()
                        } else {
                            if let Some(len) = block_len {
                                let Ok(block) = Block::read(staged(len)) else {
                                    reply(token, Status::BadSize.code());
                                    return None;
                                };
                                for slot in Slot::GIVEN {
                                    needed[slot as usize] = block.needs(slot);
                                }
                            }
                            if (0..SLOTS).any(|i| needed[i] && given[i].is_none()) {
                                reply(token, Status::BadSize.code());
                                return None;
                            }
                            if (loaded.is_some() || copied)
                                && let Err(code) = tell_ready(session)
                            {
                                reply(token, code);
                                return None;
                            }
                            completed = true;
                            0
                        }
                    }
                    Some(Method::Handles)
                        if !completed && (block_len.is_some() || fork.is_some()) =>
                    {
                        early_given |= loaded.is_none() && block_len.is_some();
                        match take_given(r, &mut handles, &mut given) {
                            Ok(()) => {
                                for slot in [Slot::Files, Slot::Clock] {
                                    if let Some(offered) = given[slot as usize].take() {
                                        // Fork descriptors live in the copied layer memory.
                                        let require_fds = fork.is_some()
                                            || block_len
                                                .and_then(|len| Block::read(staged(len)).ok())
                                                .is_some_and(|block| block.needs(Slot::Files));
                                        match verify_session(own, slot, offered, require_fds) {
                                            Ok(channel) => given[slot as usize] = Some(channel),
                                            Err(code) => {
                                                reply(token, code);
                                                return None;
                                            }
                                        }
                                    }
                                }
                                if let Some(offered) = given[Slot::Terminal as usize].take() {
                                    if trusted_terminal.is_none() {
                                        trusted_terminal = match loader_terminal(session) {
                                            Ok(terminal) => terminal,
                                            Err(code) => {
                                                reply(token, code);
                                                return None;
                                            }
                                        };
                                    }
                                    match verify_terminal(trusted_terminal.as_ref(), offered) {
                                        Ok(terminal) => {
                                            given[Slot::Terminal as usize] = Some(terminal)
                                        }
                                        Err(code) => {
                                            reply(token, code);
                                            return None;
                                        }
                                    }
                                }
                                0
                            }
                            Err(status) => status.code(),
                        }
                    }
                    Some(_) => Status::Kernel(Error::BadState).code(),
                    None => Status::UnknownMethod.code(),
                };
                reply(token, status);
            }
        }
    }
}

/// Every request carries the current LoaderOf identity from Boot. No
/// authenticated child identity or credential is returned to the parent.
fn open_terminals(own: &Own, tty: Option<&Handle<Channel>>, mut r: Reader<'_>) -> Result<(), u32> {
    let count = r.u32().map_err(|s| s.code())? as usize;
    if count == 0 || count > pl::TERMINAL_ACTIONS {
        return Err(Status::BadSize.code());
    }
    let mut actions = [pl::TerminalOpen::default(); pl::TERMINAL_ACTIONS];
    for action in &mut actions[..count] {
        *action = pl::TerminalOpen::read(&mut r).map_err(|s| s.code())?;
    }
    r.finish().map_err(|s| s.code())?;
    // The parent supplied Slot::Terminal, so it must never receive our
    // identity. The active loader gets this endpoint from the process
    // service, which received it from tty's authenticated Register.
    let tty = tty.ok_or(pl::IO)?;
    for action in &actions[..count] {
        if !action.controlling && action.no_ctty {
            continue;
        }
        let method = if action.controlling {
            proto_tty::Method::Controlling
        } else {
            proto_tty::Method::Acquire
        };
        let mut w = Writer::new();
        method.header().write(&mut w).map_err(|s| s.code())?;
        w.u32(action.terminal).map_err(|s| s.code())?;
        let identity = sys::handle_duplicate(&own.identity, Rights::NOTIFY | Rights::TRANSFER)
            .map_err(code)?;
        let reply = sys::send_handles(tty, w.as_bytes(), [identity.erase()])
            .map_err(|refused| code(refused.error))?;
        let mut buffer = [0; MESSAGE_MAX];
        let status = Reader::new(reply.bytes(&mut buffer))
            .u32()
            .map_err(|_| pl::IO)?;
        if action.controlling && status != 0 {
            return Err(if status == proto_tty::NOT_CONTROLLING {
                pl::NO_CONTROLLING
            } else {
                pl::PERMISSION
            });
        }
        // Like open(), failure to acquire a busy terminal does not fail
        // an ordinary terminal open. A later /dev/tty still verifies it.
    }
    Ok(())
}

fn loader_clock(session: &Handle<Channel>) -> Result<Handle<Channel>, u32> {
    let request = proto_process::Method::LoaderClock.header().bytes();
    let mut reply = sys::send(session, &request).map_err(code)?;
    let mut buffer = [0; MESSAGE_MAX];
    if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
        return Err(pl::IO);
    }
    reply.handles.take::<Channel>(0).map_err(code)
}

fn verify_session(
    own: &Own,
    slot: Slot,
    offered: Handle<Channel>,
    require_fds: bool,
) -> Result<Handle<Channel>, u32> {
    let (root, header) = match slot {
        Slot::Files => (&own.files, proto_fs::Method::VerifySession.header()),
        Slot::Clock => (&own.clock, proto_clock::Method::VerifySession.header()),
        _ => return Err(pl::IO),
    };
    let mut w = Writer::new();
    header.write(&mut w).map_err(|s| s.code())?;
    if slot == Slot::Files {
        w.u32(u32::from(require_fds)).map_err(|s| s.code())?;
    }
    let mut reply = sys::send_handles(root, w.as_bytes(), [offered.erase()])
        .map_err(|refused| code(refused.error))?;
    let mut buffer = [0; MESSAGE_MAX];
    if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
        return Err(pl::IO);
    }
    reply.handles.take::<Channel>(0).map_err(code)
}

fn loader_terminal(session: &Handle<Channel>) -> Result<Option<Handle<Channel>>, u32> {
    let request = proto_process::Method::LoaderTerminal.header().bytes();
    let mut reply = sys::send(session, &request).map_err(code)?;
    let mut buffer = [0; MESSAGE_MAX];
    match Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => reply.handles.take::<Channel>(0).map(Some).map_err(code),
        Ok(proto_process::UNREGISTERED) => Ok(None),
        _ => Err(pl::IO),
    }
}

/// Verify before a parent can commit SetId. True tty descriptions and
/// their clone root move unchanged; a counterfeit is replaced without a
/// single request or identity sent through it.
fn verify_terminal(
    tty: Option<&Handle<Channel>>,
    offered: Handle<Channel>,
) -> Result<Handle<Channel>, u32> {
    let tty = tty.ok_or(pl::IO)?;
    let request = proto_tty::Method::VerifySession.header().bytes();
    let mut reply = sys::send_handles(tty, &request, [offered.erase()])
        .map_err(|refused| code(refused.error))?;
    let mut buffer = [0; MESSAGE_MAX];
    if Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
        return Err(pl::IO);
    }
    reply.handles.take::<Channel>(0).map_err(code)
}

/// Regions: an entry for each handle, a memory object of the parent's
/// map with MAP_READ at least the entry's pages long, each taken where
/// `admit` lets it; BAD_SIZE for anything else, and none of the message
/// is taken then.
fn take_regions(
    mut r: Reader<'_>,
    handles: &mut rt::handle::Incoming,
    scratch: &mut Scratch,
) -> Result<(), Status> {
    let count = handles.len();
    if count == 0 {
        return Err(Status::BadSize);
    }
    let mut regions = [None; abi::MESSAGE_HANDLES];
    for (i, region) in regions.iter_mut().enumerate().take(count) {
        let read = Region::read(&mut r)?;
        let reads = handles
            .info(i)
            .is_some_and(|(kind, rights)| pl::region_object(kind, rights));
        if !reads {
            return Err(Status::BadSize);
        }
        *region = Some(read);
    }
    r.finish()?;
    let held = scratch.count;
    for (i, region) in regions.iter().enumerate().take(count) {
        let region = region.ok_or(Status::BadSize)?;
        let memory = handles.take::<Memory>(i).map_err(Status::Kernel)?;
        let long =
            sys::memory_info(&memory).is_ok_and(|info| info.size >= u64::from(region.pages) * PAGE);
        let admitted = long && pl::admit(scratch.regions(), &region).is_ok();
        if !admitted {
            // The regions of this message go again.
            for parent in &mut scratch.parents[held..scratch.count] {
                drop(Handle::<Memory>::from_raw(abi::Handle(core::mem::take(
                    parent,
                ))));
            }
            scratch.count = held;
            return Err(Status::BadSize);
        }
        let at = scratch.count;
        scratch.regions[at].write(region);
        scratch.parents[at] = memory.into_raw().0;
        scratch.count += 1;
    }
    Ok(())
}

/// Go of a Fork: once every region came and `check_fork` holds, each
/// object of the child (`pl::groups` of the regions sorted by address)
/// is made, the new process paying, mapped at its address and filled
/// from the parent's objects through WINDOW; the code and the read-only
/// data are mapped again with their access once filled (the kernel
/// cleans the caches for code it maps). Each parent's handle closes once
/// its region is copied, and a narrowed handle of each new object goes to
/// the child's map. NO_MEMORY past the child's quota, BAD_SIZE for a copy
/// that may not go.
fn copy(own: &Own, fork: &Fork, scratch: &mut Scratch) -> Result<(), u32> {
    pl::check_fork(fork, scratch.regions()).map_err(|s| s.code())?;
    // By address: insertion sort, REGIONS_MAX at most.
    let n = scratch.count;
    for i in 1..n {
        let mut j = i;
        while j > 0 && scratch.regions()[j - 1].address > scratch.regions()[j].address {
            scratch.regions.swap(j - 1, j);
            scratch.parents.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut next = 0;
    loop {
        let Some(first) = pl::groups(&scratch.regions()[next..]).next() else {
            break;
        };
        let group = next + first.start..next + first.end;
        next = group.end;
        let (first, last) = (
            scratch.regions()[group.start],
            scratch.regions()[group.end - 1],
        );
        let len = last.end() - first.address;
        let at = first.address as usize;
        let m = steps::timed(kind::MEM_CREATE, len, || sys::mem_create(len)).map_err(code)?;
        steps::timed(kind::MAP_NEW, len, || {
            loader::map_narrowed(&own.process, &m, 0, len, at, Access::ReadWrite)
        })
        .map_err(code)?;
        for i in group.clone() {
            let region = scratch.regions()[i];
            let parent =
                Handle::<Memory>::from_raw(abi::Handle(core::mem::take(&mut scratch.parents[i])));
            let bytes = u64::from(region.pages) * PAGE;
            fill(own, &parent, bytes, region.address)?;
        }
        if first.access != Access::ReadWrite {
            steps::timed(kind::REMAP, len, || {
                // SAFETY: the new object's mapping, which nothing uses now.
                unsafe { sys::mem_unmap(&own.process, at, len) }.map_err(code)?;
                loader::map_narrowed(&own.process, &m, 0, len, at, first.access).map_err(code)
            })?;
        }
        let mut rights = Rights::MAP_READ | Rights::DUPLICATE | Rights::TRANSFER;
        if first.access == Access::ReadWrite {
            rights = rights | Rights::MAP_WRITE;
        }
        let kept = steps::timed(kind::DUPLICATE, len, || sys::handle_duplicate(&m, rights))
            .map_err(code)?;
        let pages = u32::try_from(len / PAGE).map_err(|_| pl::TOO_BIG)?;
        scratch.map[scratch.kept].write(MapEntry {
            address: first.address,
            pages,
            access: first.access,
            handle: kept.into_raw().0,
        });
        scratch.kept += 1;
    }
    Ok(())
}

/// `bytes` of the parent's object `parent` into the new process at `at`,
/// mapped writable there: PIECE bytes at a time through WINDOW, each
/// piece unmapped once copied.
fn fill(own: &Own, parent: &Handle<Memory>, bytes: u64, at: u64) -> Result<(), u32> {
    let mut offset = 0;
    while offset < bytes {
        let piece = (bytes - offset).min(PIECE);
        steps::timed(kind::MAP_PIECE, piece, || {
            sys::mem_map(
                &own.process,
                parent,
                offset,
                piece,
                WINDOW as usize,
                Access::Read,
            )
        })
        .map_err(code)?;
        // SAFETY: WINDOW maps `piece` bytes of the parent's object, read
        // only, and the new object is mapped writable at `at` for `bytes`
        // bytes; the two never meet (`admit` keeps every region off the
        // loader's region). The parent waits for Go's reply meanwhile.
        steps::timed(kind::COPY_PIECE, piece, || unsafe {
            core::ptr::copy_nonoverlapping(
                WINDOW as *const u8,
                (at + offset) as *mut u8,
                piece as usize,
            );
        });
        // SAFETY: the window's mapping, which nothing uses now.
        steps::timed(kind::UNMAP_PIECE, piece, || unsafe {
            sys::mem_unmap(&own.process, WINDOW as usize, piece)
        })
        .map_err(code)?;
        offset += piece;
    }
    Ok(())
}

/// Ready: the service hears the image is loaded before the parent does,
/// and takes a commit of the place only from then on.
fn tell_ready(session: &Handle<Channel>) -> Result<(), u32> {
    let request = proto_process::Method::Ready.header().bytes();
    let mut buffer = [0; MESSAGE_MAX];
    match sys::send(session, &request) {
        Ok(reply) if Reader::new(reply.bytes(&mut buffer)).u32() == Ok(0) => Ok(()),
        _ => Err(pl::IO),
    }
}

fn reply(token: Token, code: u32) {
    let _ = token.reply(&proto_wire::reply(Status::from_code(code)));
}

/// Start: the parent's block, `len` bytes of `memory`, copied into an
/// object of the loader's own at STAGING before anything reads it; the
/// parent's object goes. BAD_SIZE for a length past BLOCK_MAX or past the
/// object, or a copy out of the layout (`Block::read`).
fn stage(own: &Own, memory: &Handle<Memory>, len: usize) -> Result<usize, Status> {
    let size = sys::memory_info(memory).map_err(Status::Kernel)?.size;
    if len > BLOCK_MAX || len as u64 > size || len == 0 {
        return Err(Status::BadSize);
    }
    let pages = (len as u64).next_multiple_of(PAGE);
    sys::mem_map(
        &own.process,
        memory,
        0,
        pages,
        BORROWED as usize,
        Access::Read,
    )
    .map_err(Status::Kernel)?;
    let copy = sys::mem_create(pages).map_err(Status::Kernel)?;
    let mapped = sys::mem_map(
        &own.process,
        &copy,
        0,
        pages,
        STAGING as usize,
        Access::ReadWrite,
    );
    let checked = mapped.map_err(Status::Kernel).and_then(|()| {
        // SAFETY: the copy is mapped at STAGING for `pages` bytes, the
        // loader's alone.
        let into = unsafe { core::slice::from_raw_parts_mut(STAGING as *mut u8, len) };
        // Each byte of the parent's object, mapped read-only at BORROWED,
        // is read once; the checks run on the copy alone.
        // An atomic load each: the parent may write its object meanwhile.
        // SAFETY: BORROWED maps `pages` bytes, and `i` stays below `len`.
        let source = |i: usize| unsafe {
            core::sync::atomic::AtomicU8::from_ptr((BORROWED as *mut u8).add(i))
                .load(core::sync::atomic::Ordering::Relaxed)
        };
        pl::copy_block(source, len, into)
            .map(drop)
            .map_err(|_| Status::BadSize)
    });
    // SAFETY: the mapping of the parent's object, which nothing uses now.
    let _ = unsafe { sys::mem_unmap(&own.process, BORROWED as usize, pages) };
    // The mapping holds the copy until the loader's end.
    drop(copy);
    checked.map(|()| len)
}

/// Handles: the sessions the parent gives the program, each with its slot
/// and SEND.
fn take_given(
    r: Reader<'_>,
    handles: &mut rt::handle::Incoming,
    given: &mut [Option<Handle<Channel>>; SLOTS],
) -> Result<(), Status> {
    let slots = pl::handle_slots(r, handles.len())?;
    for (i, slot) in slots.iter().enumerate() {
        let Some(slot) = slot else { break };
        let sends = matches!(handles.info(i), Some((abi::ObjectKind::Channel, rights)) if rights.contains(Rights::SEND));
        if !sends || given[*slot as usize].is_some() {
            return Err(Status::BadSize);
        }
    }
    for (i, slot) in slots.iter().enumerate() {
        let Some(slot) = slot else { break };
        given[*slot as usize] = Some(handles.take(i).map_err(Status::Kernel)?);
    }
    Ok(())
}

/// The code of an error of the kernel for the parent.
fn code(e: Error) -> u32 {
    match e {
        Error::NoMemory => pl::NO_MEMORY,
        _ => pl::IO,
    }
}

/// Go: OpenExec of the block's path through the session of the loaders
/// with a copy of the loader's identity, then the program's segments,
/// each in a new object filled from the file and mapped with its access,
/// its stack and its start area: the program's entry, the image session
/// and the memory map (a narrowed handle of each object it mapped), or the
/// code of why not.
fn load(own: &Own, block: &Block<'_>) -> Result<(u64, Handle<Channel>, Maps), u32> {
    let mut path = [0; pl::PATH_MAX];
    let path = block.full_path(&mut path).map_err(|e| match e {
        BlockError::NameTooLong => pl::NAME_TOO_LONG,
        _ => pl::NO_ENTRY,
    })?;
    let image = open(own, path)?;
    let size = file_size(&image)?;
    let mut head = [0; PAGE as usize];
    let read = read_at(&image, 0, &mut head[..size.min(PAGE) as usize])?;
    let layout =
        elf::layout(&head[..read], size, PROGRAM_ROOM.clone()).map_err(|_| pl::NOT_EXEC)?;
    let mut maps = Maps::default();
    for part in Part::ALL {
        let load = &layout.segments[part as usize];
        if !load.is_empty() {
            segment(own, &image, load, part, &mut maps)?;
        }
    }
    let stack = sys::mem_create(STACK_SIZE).map_err(code)?;
    let stack_at = INIT_STACK_TOP - STACK_SIZE;
    loader::map_narrowed(
        &own.process,
        &stack,
        0,
        STACK_SIZE,
        stack_at as usize,
        Access::ReadWrite,
    )
    .map_err(code)?;
    keep_region(&mut maps, &stack, stack_at, STACK_SIZE, Access::ReadWrite)?;
    let area = (pl::area_len(block) as u64).next_multiple_of(PAGE);
    if area > AREA_MAX {
        return Err(pl::TOO_BIG);
    }
    let start = sys::mem_create(area).map_err(code)?;
    loader::map_narrowed(
        &own.process,
        &start,
        0,
        area,
        START_AREA as usize,
        Access::ReadWrite,
    )
    .map_err(code)?;
    keep_region(&mut maps, &start, START_AREA, area, Access::ReadWrite)?;
    Ok((layout.entry, image, maps))
}

/// OpenExec of `path`: the image session, or the code of the refusal.
fn open(own: &Own, path: &[u8]) -> Result<Handle<Channel>, u32> {
    let copy =
        sys::handle_duplicate(&own.identity, Rights::NOTIFY | Rights::TRANSFER).map_err(code)?;
    let mut w = Writer::new();
    proto_fs::Method::OpenExec
        .header()
        .write(&mut w)
        .and_then(|()| w.bytes(path))
        .map_err(|_| pl::NAME_TOO_LONG)?;
    let mut reply = sys::send_handles(&own.files, w.as_bytes(), [copy.erase()])
        .map_err(|refused| code(refused.error))?;
    let mut buffer = [0; MESSAGE_MAX];
    let status = Reader::new(reply.bytes(&mut buffer))
        .u32()
        .map_err(|_| pl::IO)?;
    match status {
        0 => reply.handles.take(0).map_err(|_| pl::IO),
        proto_fs::NO_ENTRY => Err(pl::NO_ENTRY),
        proto_fs::ACCESS_DENIED => Err(pl::ACCESS),
        proto_fs::NOT_DIRECTORY => Err(pl::NOT_DIRECTORY),
        proto_fs::PERMISSION => Err(pl::PERMISSION),
        _ => Err(pl::IO),
    }
}

/// The size of the file of the image session.
fn file_size(image: &Handle<Channel>) -> Result<u64, u32> {
    let mut w = Writer::new();
    proto_fs::Method::InfoFd
        .header()
        .write(&mut w)
        .and_then(|()| w.u32(0))
        .map_err(|_| pl::IO)?;
    let reply = sys::send(image, w.as_bytes()).map_err(code)?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    if r.u32() != Ok(0) {
        return Err(pl::IO);
    }
    let info = proto_fs::NodeInfo::read(&mut r).map_err(|_| pl::IO)?;
    Ok(info.size)
}

/// ReadAt of the image session into `out` from `offset`, as many requests
/// as it takes; the count read, short at the end of the file.
fn read_at(image: &Handle<Channel>, offset: u64, out: &mut [u8]) -> Result<usize, u32> {
    let mut done = 0;
    let mut buffer = [0; MESSAGE_MAX];
    while done < out.len() {
        let count = (out.len() - done).min(proto_fs::MAX_READ);
        let mut w = Writer::new();
        proto_fs::Method::ReadAt
            .header()
            .write(&mut w)
            .and_then(|()| w.u32(0))
            .and_then(|()| w.u64(offset + done as u64))
            .and_then(|()| w.u32(count as u32))
            .map_err(|_| pl::IO)?;
        let reply = sys::send(image, w.as_bytes()).map_err(code)?;
        let mut r = Reader::new(reply.bytes(&mut buffer));
        if r.u32() != Ok(0) {
            return Err(pl::IO);
        }
        let n = r.u32().map_err(|_| pl::IO)? as usize;
        let bytes = r.bytes(n).map_err(|_| pl::IO)?;
        if n == 0 || n > count {
            break;
        }
        out[done..done + n].copy_from_slice(bytes);
        done += n;
    }
    Ok(done)
}

/// The access a part is mapped with: code RX, read-only data R, data RW.
const fn access(part: Part) -> Access {
    match part {
        Part::Code => Access::ReadExec,
        Part::Rodata => Access::Read,
        Part::Data => Access::ReadWrite,
    }
}

/// A segment of the program: a new object of its pages, which the new
/// process pays for, filled by the file service READ_INTO_MAX bytes a
/// request (READ_INTO) and mapped at its address with its access; its
/// narrowed handle goes into `maps`.
fn segment(
    own: &Own,
    image: &Handle<Channel>,
    load: &Load,
    part: Part,
    maps: &mut Maps,
) -> Result<(), u32> {
    let pages = load.pages();
    let len = pages.end - pages.start;
    let m = sys::mem_create(len).map_err(code)?;
    let mut at = 0;
    while at < load.file_size {
        let piece = (load.file_size - at).min(proto_fs::READ_INTO_MAX as u64);
        if read_into(image, &m, load.offset + at, piece, at)? != piece {
            return Err(pl::NOT_EXEC);
        }
        at += piece;
    }
    loader::map_narrowed(&own.process, &m, 0, len, pages.start as usize, access(part))
        .map_err(code)?;
    keep_region(maps, &m, pages.start, len, access(part))
}

/// READ_INTO of the image session: `count` bytes of the file from
/// `offset` into `m` from `at`, a whole page, through a copy of `m` the
/// service maps for the copy; the count read.
fn read_into(
    image: &Handle<Channel>,
    m: &Handle<Memory>,
    offset: u64,
    count: u64,
    at: u64,
) -> Result<u64, u32> {
    let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
    let copy = sys::handle_duplicate(m, rights).map_err(code)?;
    let mut w = Writer::new();
    proto_fs::Method::ReadInto
        .header()
        .write(&mut w)
        .and_then(|()| w.u32(0))
        .and_then(|()| w.u64(offset))
        .and_then(|()| w.u32(count as u32))
        .and_then(|()| w.u64(at))
        .map_err(|_| pl::IO)?;
    let reply = sys::send_handles(image, w.as_bytes(), [copy.erase()])
        .map_err(|refused| code(refused.error))?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    match (r.u32(), r.u32()) {
        (Ok(0), Ok(n)) => Ok(n.into()),
        _ => Err(pl::IO),
    }
}

/// What Take brought: the credentials and the program's sessions.
struct Taken {
    credentials: proto_process::Credentials,
    posix: Handle<Channel>,
    identity: Handle<Channel>,
    console: Option<Handle<Resource>>,
}

/// Take, once the record is ready.
fn take(session: &Handle<Channel>) -> Result<Taken, Error> {
    let request = proto_process::Method::Take.header().bytes();
    let mut reply = sys::send(session, &request)?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut r = Reader::new(reply.bytes(&mut buffer));
    if r.u32() != Ok(0) {
        return Err(Error::BadState);
    }
    let mut words = [0; 6];
    for w in &mut words {
        *w = r.u32().map_err(|_| Error::BadState)?;
    }
    Ok(Taken {
        credentials: proto_process::Credentials::from_words(words),
        posix: reply.handles.take(0)?,
        identity: reply.handles.take(1)?,
        console: reply.handles.take(2).ok(),
    })
}

/// The value of `h` for the program: it stays open.
fn keep<K>(h: Handle<K>) -> u64 {
    h.into_raw().0
}

/// The end: the start area, then every handle of the loader's own closes
/// (C, the session with the service, the session of the loaders, its
/// identity, the image session), and the jump.
fn finish(
    session: Handle<Channel>,
    start: Handle<Channel>,
    own: Own,
    loaded: Loaded,
    taken: Taken,
) -> u64 {
    let Loaded {
        block_len,
        entry,
        image,
        mut maps,
        mut given,
    } = loaded;
    let Ok(block) = Block::read(staged(block_len)) else {
        return GAVE_UP;
    };
    let c = taken.credentials;
    // A set-ID program starts in the secure mode (AT_SECURE).
    let flags = if c.uid != c.euid || c.gid != c.egid {
        pl::SECURE
    } else {
        0
    };
    let process = own.process.raw().0;
    let mut handles = [0; SLOTS];
    handles[Slot::Process as usize] = keep(own.process);
    handles[Slot::Thread as usize] = keep(own.thread);
    handles[Slot::Posix as usize] = keep(taken.posix);
    handles[Slot::PosixId as usize] = keep(taken.identity);
    handles[Slot::Console as usize] = taken.console.map_or(0, keep);
    for slot in Slot::GIVEN {
        handles[slot as usize] = given[slot as usize].take().map_or(0, keep);
    }
    let mut entries = [MapEntry {
        address: 0,
        pages: 0,
        access: Access::Read,
        handle: 0,
    }; MAP_ENTRIES];
    let mut count = 0;
    for kept in maps.iter_mut().filter_map(Option::take) {
        entries[count] = MapEntry {
            address: kept.address,
            pages: kept.pages,
            access: kept.access,
            handle: keep(kept.handle),
        };
        count += 1;
    }
    let len = pl::area_len(&block);
    // SAFETY: the start area lies at START_AREA, mapped read and write for
    // `len` bytes and more (`load`), and only the loader writes it now.
    let area = unsafe { core::slice::from_raw_parts_mut(START_AREA as *mut u8, len) };
    if pl::write_area(area, START_AREA, &block, flags, handles, &entries[..count]).is_err() {
        return GAVE_UP;
    }
    let staging = (block_len as u64).next_multiple_of(PAGE);
    drop((image, own.files, own.clock, own.identity, start, session));
    // SAFETY: the copy of the block is read no more.
    let _ = unsafe {
        sys::mem_unmap(
            &Handle::<Process>::borrowed(abi::Handle(process)),
            STAGING as usize,
            staging,
        )
    };
    let (data, data_len) = own.data;
    // SAFETY: the loader's last step: its data and stack go, and the jump
    // runs on registers alone.
    unsafe { leap(process, data, data_len, entry, INIT_STACK_TOP, START_AREA) }
}

/// The end of a copy: the child's handles (its process, its thread, its
/// sessions with the services from Take, those Handles gave) and its map
/// go into the transfer at Fork's address, every handle of the loader's
/// own closes, and the jump to Fork's `pc` on its `sp` with x0 = 0, where
/// the layer's point of return takes the parent's registers back.
fn finish_fork(
    session: Handle<Channel>,
    start: Handle<Channel>,
    own: Own,
    copied: Copied,
    taken: Taken,
) -> u64 {
    let Copied {
        fork,
        scratch,
        mut given,
    } = copied;
    let process = own.process.raw().0;
    let mut handles = [0; SLOTS];
    handles[Slot::Process as usize] = keep(own.process);
    handles[Slot::Thread as usize] = keep(own.thread);
    handles[Slot::Posix as usize] = keep(taken.posix);
    handles[Slot::PosixId as usize] = keep(taken.identity);
    handles[Slot::Console as usize] = taken.console.map_or(0, keep);
    for slot in Slot::GIVEN {
        handles[slot as usize] = given[slot as usize].take().map_or(0, keep);
    }
    // SAFETY: `check_fork` put the transfer whole in a writable region,
    // which `copy` mapped read and write at the parent's address; the
    // child's thread does not run yet.
    let out = unsafe { core::slice::from_raw_parts_mut(fork.transfer as *mut u8, TRANSFER_SIZE) };
    if pl::write_transfer(out, handles, scratch.map()).is_err() {
        return GAVE_UP;
    }
    drop((own.files, own.clock, own.identity, start, session));
    // SAFETY: the scratch is read no more.
    let _ = unsafe {
        sys::mem_unmap(
            &Handle::<Process>::borrowed(abi::Handle(process)),
            STAGING as usize,
            SCRATCH_LEN,
        )
    };
    let (data, data_len) = own.data;
    // SAFETY: the loader's last step, as for a program from a file.
    unsafe { leap(process, data, data_len, fork.pc, fork.sp, 0) }
}

/// Unmaps the loader's data and stack (`mem_unmap` of `len` bytes at
/// `base` of `process`), sets the program's stack pointer `sp` and jumps
/// to `entry` with `arg` in x0, all on registers.
///
/// # Safety
/// The stack the caller runs on lies in the range that goes; nothing
/// after the call uses it.
#[unsafe(naked)]
unsafe extern "C" fn leap(process: u64, base: u64, len: u64, entry: u64, sp: u64, arg: u64) -> ! {
    core::arch::naked_asm!(
        "mov x19, x3",
        "mov x20, x4",
        "mov x21, x5",
        "svc #{unmap}",
        "mov sp, x20",
        "mov x0, x21",
        "mov x29, xzr",
        "mov x30, xzr",
        "br x19",
        unmap = const abi::Call::MemUnmap.number(),
    )
}
