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
//! loader copies before it reads it (sp3.M6), and says Go: the loader opens
//! the program through the session of the loaders with a copy of its
//! identity (OpenExec, condition O1), reads its ELF file piece by piece into objects
//! of the new process, which pays for them, and answers "the image is
//! ready" or why not. The parent gives the program's sessions (Handles);
//! once the service says through C that the record is ready (label 2, the
//! only notification the loader trusts), the loader takes the program's
//! sessions and credentials (Take), writes the start area, closes all that
//! was its own, the image session, the loaders' session and its identity
//! among them (condition O6), unmaps its data and stack and jumps to the program.

#![no_std]
#![no_main]

use abi::{INIT_STACK_TOP, INLINE_MAX, MESSAGE_MAX, Rights, START_CHANNEL, Source};
use bootimg::Part;
use bootimg::elf::{self, Load};
use proto_loader::{
    self as pl, AREA_MAX, BLOCK_MAX, Block, BlockError, LOADER_BASE, Method, PROGRAM_ROOM, SLOTS,
    STACK_SIZE, START_AREA, Slot,
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
/// Where it maps a piece of a segment to fill it from the file.
const WINDOW: u64 = pl::LOADER_WINDOW;
const WINDOW_LEN: u64 = 1 << 20;
/// The exit code of a loader that gave up: the parent hears why through C
/// first, or its wait reports 127 (posix_spawn's fallback, [MUSL-SPAWN]).
const GAVE_UP: u64 = 127;

/// What Boot brought: the loader's own handles from the service.
struct Own {
    process: Handle<Process>,
    thread: Handle<Thread>,
    files: Handle<Channel>,
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
    let Some(loaded) = serve(&start, &own) else {
        return GAVE_UP;
    };
    let Ok(taken) = take(&session) else {
        return GAVE_UP;
    };
    finish(session, start, own, loaded, taken)
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
        data,
    })
}

/// What the parent's requests left: the copy of the block, the program's
/// entry, the image session and the sessions Handles gave.
struct Loaded {
    block_len: usize,
    entry: u64,
    image: Handle<Channel>,
    given: [Option<Handle<Channel>>; SLOTS],
}

/// The bytes of the copy of the block.
fn staged(len: usize) -> &'static [u8] {
    // SAFETY: the copy lies at STAGING, mapped read and write for the
    // loader's life (`stage`), and nothing writes it after Start.
    unsafe { core::slice::from_raw_parts(STAGING as *const u8, len) }
}

/// The requests of the parent through C and the service's word that the
/// record is ready: the load once Start and Go came, and the end once the
/// image is ready and the record too. None when the loader gives up.
fn serve(start: &Handle<Channel>, own: &Own) -> Option<Loaded> {
    let mut block_len = None;
    let mut loaded: Option<(u64, Handle<Channel>)> = None;
    let mut given: [Option<Handle<Channel>>; SLOTS] = Default::default();
    let mut ready = false;
    let mut buffer = [0; MESSAGE_MAX];
    loop {
        if ready && let Some((entry, image)) = loaded.take() {
            return Some(Loaded {
                block_len: block_len?,
                entry,
                image,
                given,
            });
        }
        match sys::receive(start).ok()? {
            Received::Notification { source, label, .. } => {
                // The service's word through its copy, label 2: a parent's
                // copy carries no NOTIFY. The parent's end (CLIENT_GONE of
                // label 1) changes nothing: its death ends the child.
                if source == Source::Session && label == pl::SERVICE {
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
                let status = match method {
                    Some(Method::Start) if block_len.is_none() => {
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
                    Some(Method::Go) if block_len.is_some() && loaded.is_none() => {
                        let block = Block::read(staged(block_len?)).ok()?;
                        match load(own, &block) {
                            Ok(done) => {
                                loaded = Some(done);
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
                    Some(Method::Handles) if loaded.is_some() => {
                        match take_given(r, &mut handles, &mut given) {
                            Ok(()) => 0,
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
        // is read once; the checks run on the copy alone (sp3.M6).
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
/// its stack and its start area: the program's entry and the image
/// session, or the code of why not.
fn load(own: &Own, block: &Block<'_>) -> Result<(u64, Handle<Channel>), u32> {
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
    for part in Part::ALL {
        let load = &layout.segments[part as usize];
        if !load.is_empty() {
            segment(own, &image, load, part)?;
        }
    }
    let stack = sys::mem_create(STACK_SIZE).map_err(code)?;
    loader::map_narrowed(
        &own.process,
        &stack,
        0,
        STACK_SIZE,
        (INIT_STACK_TOP - STACK_SIZE) as usize,
        Access::ReadWrite,
    )
    .map_err(code)?;
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
    Ok((layout.entry, image))
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
/// process pays for, filled from the file a window at a time and mapped
/// at its address with its access.
fn segment(own: &Own, image: &Handle<Channel>, load: &Load, part: Part) -> Result<(), u32> {
    let pages = load.pages();
    let len = pages.end - pages.start;
    let m = sys::mem_create(len).map_err(code)?;
    let mut at = 0;
    while at < load.file_size {
        let piece = (load.file_size - at).min(WINDOW_LEN);
        let mapped = piece.next_multiple_of(PAGE);
        sys::mem_map(
            &own.process,
            &m,
            at,
            mapped,
            WINDOW as usize,
            Access::ReadWrite,
        )
        .map_err(code)?;
        // SAFETY: the window maps `mapped` bytes of the new object, which
        // only the loader uses.
        let out = unsafe { core::slice::from_raw_parts_mut(WINDOW as *mut u8, piece as usize) };
        let read = read_at(image, load.offset + at, out);
        // SAFETY: the mapping made above, which nothing uses now.
        let _ = unsafe { sys::mem_unmap(&own.process, WINDOW as usize, mapped) };
        if read? != piece as usize {
            return Err(pl::NOT_EXEC);
        }
        at += piece;
    }
    loader::map_narrowed(&own.process, &m, 0, len, pages.start as usize, access(part)).map_err(code)
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
    for slot in [Slot::Files, Slot::Clock, Slot::Uart] {
        handles[slot as usize] = given[slot as usize].take().map_or(0, keep);
    }
    let len = pl::area_len(&block);
    // SAFETY: the start area lies at START_AREA, mapped read and write for
    // `len` bytes and more (`load`), and only the loader writes it now.
    let area = unsafe { core::slice::from_raw_parts_mut(START_AREA as *mut u8, len) };
    if pl::write_area(area, START_AREA, &block, flags, handles).is_err() {
        return GAVE_UP;
    }
    let staging = (block_len as u64).next_multiple_of(PAGE);
    drop((image, own.files, own.identity, start, session));
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
