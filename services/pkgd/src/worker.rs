// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The worker thread (pk3-design R1, R4, R12): everything that takes long.
//! It reads the store from the disk through the disk service, creates and
//! maps the object of each package, hashes it as the bytes arrive, checks
//! its signature, and attaches it to the file service as a layer, all in
//! straight lines that wait in calls; the main thread of the service never
//! waits for any of it and keeps answering. The thread owns the table of
//! the store and the packages of the disk until it tells the main thread
//! it is done (`shared::STARTING` clears), and the main thread reads what the
//! thread published, entry by entry, meanwhile.

use crate::shared::*;
use abi::{Access, MESSAGE_MAX, Rights, Source};
use core::sync::atomic::Ordering::{Acquire, Release};
use pkgd::commit::{self, Device, Failed, Start};
use pkgd::packages::Entry;
use pkgd::settings::{self, Settings};
use pkgd::store::{self, BLOCK, PACKAGES, Record, Table};
use pkgd::verify::{self, Fault};
use pkgfmt::sha::{Stream, sha256};
use pkgfmt::{Key, Revocation, Trust, keyfile};
use proto_blk::{CELL_BYTES, CELLS, Info, Key as BlkKey, Method as Blk, SECTOR};
use proto_fs::{LayerOp, LayerReply, LayerStart, LayerStep};
use proto_wire::{Status, Writer, long};
use rt::handle::{Any, Channel, Memory, Process};
use rt::sys::{self, Received};
use rt::{Handle, Stack};

const STACK_SIZE: usize = 64 * 1024;
static STACK: Stack<STACK_SIZE> = Stack::new();
/// The thread's message buffer: the page after the main thread's.
const MSGBUF: usize = abi::INIT_MSGBUF as usize + 4096;
/// The blocks of a cell and the sectors of a block.
const CELL_BLOCKS: u64 = CELL_BYTES as u64 / BLOCK as u64;
const BLOCK_SECTORS: u32 = (BLOCK / SECTOR) as u32;

/// The raw handles of the main thread's, kept for this thread.
pub const HANDLES: usize = 5;
pub static RAW: [core::sync::atomic::AtomicU64; HANDLES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; HANDLES];
pub const PROCESS: usize = 0;
pub const BLK_SESSION: usize = 1;
pub const LAYERS_SESSION: usize = 2;
pub const MAIN_CHANNEL: usize = 3;
pub const WAKE: usize = 4;

fn view<K>(i: usize) -> core::mem::ManuallyDrop<Handle<K>> {
    Handle::borrowed(abi::Handle(RAW[i].load(Acquire)))
}

/// Starts the thread; it begins with the work of the start.
pub fn start(process: &Handle<Process>) -> Result<Handle<rt::handle::Thread>, abi::Error> {
    // SAFETY: STACK is the thread's alone.
    let thread = unsafe {
        sys::thread_create(
            process,
            work,
            STACK.top(),
            0,
            LEVEL,
            abi::Policy::RoundRobin,
            MSGBUF,
        )
    }?;
    sys::thread_start(&thread)?;
    Ok(thread)
}

/// The level of the thread: the clients' of the service, the ones that
/// the layer calls it makes name (`LayerStart::level`).
pub const LEVEL: u8 = 30;

extern "C" fn work(_: u64) -> ! {
    let outcome = run();
    if let Err(why) = outcome {
        rt::println!("pkgd: the start failed: {why}");
    }
    STARTING.store(false, Release);
    let tell = view::<Channel>(WAKE);
    // The thread has nothing more to do in this part: it waits for the end of the process.
    let _ = sys::notify(&tell, 1);
    loop {
        let _ = sys::receive(&tell);
    }
}

type Fail = &'static str;

/// The disk service as a `Device`: one block at a time, with its own channel
/// for the notifications of the operations.
struct Disk {
    session: core::mem::ManuallyDrop<Handle<Channel>>,
    own: Handle<Channel>,
    /// A copy of `own` with NOTIFY for each cell, labelled by the cell plus one.
    notify: [Handle<Channel>; CELLS as usize],
    sectors: u64,
    flush: bool,
}

/// Where the thread maps the disk service's buffer.
const BUFFER_AT: usize = 0x58_1000_0000;

enum Got {
    Ready,
    Wait(u64),
    Armed,
}

impl Disk {
    fn call(&self, request: &[u8], handle: Option<Handle<Any>>) -> Result<Got, Status> {
        let reply = match handle {
            None => sys::send(&self.session, request)?,
            Some(h) => sys::send_handles(&self.session, request, [h]).map_err(|r| r.error)?,
        };
        let mut buffer = [0; MESSAGE_MAX];
        match long::Reply::read(reply.bytes(&mut buffer))? {
            long::Reply::Ready(_) => Ok(Got::Ready),
            long::Reply::Wait(key) => Ok(Got::Wait(key)),
            long::Reply::Armed => Ok(Got::Armed),
            long::Reply::Cancelled => Err(Status::BadSize),
        }
    }

    fn io(&self, method: Blk, cell: u32, count: u32, sector: u64) -> Result<u64, Status> {
        let mut w = Writer::new();
        method.header().write(&mut w)?;
        w.u32(cell)?;
        w.u32(count)?;
        w.u64(sector)?;
        match self.call(w.as_bytes(), None)? {
            Got::Wait(key) => Ok(key),
            _ => Err(Status::BadSize),
        }
    }

    /// TAKE of `key` until it is READY: the first time with a handle that
    /// notifies this thread's channel.
    fn finish(&self, key: u64, cell: usize) -> Result<(), Status> {
        let mut w = Writer::new();
        BlkKey { key }.write(Blk::Take, &mut w)?;
        let mut notify = Some(
            sys::handle_duplicate(&self.notify[cell], Rights::NOTIFY | Rights::TRANSFER)?.erase(),
        );
        loop {
            match self.call(w.as_bytes(), notify.take())? {
                Got::Ready => return Ok(()),
                Got::Armed => {}
                Got::Wait(_) => return Err(Status::BadSize),
            }
            loop {
                if let Received::Notification {
                    source: Source::Session,
                    label,
                    bits,
                    ..
                } = sys::receive(&self.own)?
                    && label == cell as u64 + 1
                    && bits & 1 != 0
                {
                    break;
                }
            }
        }
    }

    fn cell(cell: usize) -> *mut u8 {
        (BUFFER_AT + cell * CELL_BYTES as usize) as *mut u8
    }

    /// Reads `blocks` blocks from `first` into `to(chunk_start_block, bytes)`,
    /// four cells in flight; `done` sees each chunk as it lands.
    fn read_run(
        &self,
        first: u64,
        blocks: u64,
        mut sink: impl FnMut(u64, &[u8]),
    ) -> Result<(), Failed> {
        let mut issued = 0;
        let mut taken = 0;
        let mut keys = [0u64; CELLS as usize];
        let total = blocks.div_ceil(CELL_BLOCKS);
        while taken < total {
            while issued < total && issued - taken < u64::from(CELLS) {
                let at = issued * CELL_BLOCKS;
                let count = (blocks - at).min(CELL_BLOCKS) as u32 * BLOCK_SECTORS;
                let cell = (issued % u64::from(CELLS)) as u32;
                keys[cell as usize] = self
                    .io(
                        Blk::Read,
                        cell,
                        count,
                        (first + at) * u64::from(BLOCK_SECTORS),
                    )
                    .map_err(|_| Failed)?;
                issued += 1;
            }
            let cell = (taken % u64::from(CELLS)) as usize;
            self.finish(keys[cell], cell).map_err(|_| Failed)?;
            let at = taken * CELL_BLOCKS;
            let len = (blocks - at).min(CELL_BLOCKS) as usize * BLOCK;
            // SAFETY: the cell lies in the mapped buffer, READY: the service wrote it and
            // no request of this cell is in flight.
            sink(at, unsafe {
                core::slice::from_raw_parts(Self::cell(cell), len)
            });
            taken += 1;
        }
        Ok(())
    }
}

impl Device for Disk {
    fn blocks(&self) -> u64 {
        self.sectors / u64::from(BLOCK_SECTORS)
    }

    fn read(&mut self, block: u64, out: &mut [u8; BLOCK]) -> Result<(), Failed> {
        self.read_run(block, 1, |_, bytes| out.copy_from_slice(bytes))
    }

    fn write(&mut self, block: u64, data: &[u8; BLOCK]) -> Result<(), Failed> {
        // SAFETY: cell 0 of the mapped buffer; no request of it is in flight.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), Self::cell(0), BLOCK) };
        let key = self
            .io(
                Blk::Write,
                0,
                BLOCK_SECTORS,
                block * u64::from(BLOCK_SECTORS),
            )
            .map_err(|_| Failed)?;
        self.finish(key, 0).map_err(|_| Failed)
    }

    fn flush(&mut self) -> Result<(), Failed> {
        match self.call(&Blk::Flush.header().bytes(), None) {
            Ok(Got::Wait(key)) => self.finish(key, 0).map_err(|_| Failed),
            _ => Err(Failed),
        }
    }
}

/// The disk service: the buffer of four cells and its INFO.
fn connect_disk(process: &Handle<Process>) -> Result<Disk, Fail> {
    let session = view::<Channel>(BLK_SESSION);
    let object = sys::mem_create(u64::from(proto_blk::BUFFER_SIZE)).map_err(|_| "no memory")?;
    sys::mem_map(
        process,
        &object,
        0,
        u64::from(proto_blk::BUFFER_SIZE),
        BUFFER_AT,
        Access::ReadWrite,
    )
    .map_err(|_| "the buffer is not mapped")?;
    let copy = sys::handle_duplicate(
        &object,
        Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
    )
    .map_err(|_| "no copy")?;
    let mut w = Writer::new();
    proto_blk::write_buffer(proto_blk::BUFFER_SIZE, &mut w).map_err(|_| "request")?;
    let reply = sys::send_handles(&session, w.as_bytes(), [copy.erase()]).map_err(|_| "BUFFER")?;
    let mut buffer = [0; MESSAGE_MAX];
    if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
        return Err("the disk service refused the buffer");
    }
    let reply = sys::send(&session, &Blk::Info.header().bytes()).map_err(|_| "INFO")?;
    let info = Info::read(reply.bytes(&mut buffer)).map_err(|_| "INFO reply")?;
    let own = sys::channel_create(LEVEL).map_err(|_| "no channel")?;
    let label = |cell: u64| {
        sys::handle_label(
            &own,
            Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
            cell + 1,
            LEVEL,
        )
        .map_err(|_| "no notification")
    };
    let notify = [label(0)?, label(1)?, label(2)?, label(3)?];
    Ok(Disk {
        session,
        notify,
        own,
        sectors: info.sectors,
        flush: info.flush(),
    })
}

/// A number for the next layer, from 1 on and round after 256.
fn next_layer() -> u32 {
    LAYER.fetch_add(1, core::sync::atomic::Ordering::Relaxed) % 256 + 1
}

/// Attaches `memory` as a layer: LayerStart with the object and the
/// notification, then LayerStep until the answer. The code of the refusal.
fn attach(memory: &Handle<Memory>, layer: u32) -> Result<(), u32> {
    let session = view::<Channel>(LAYERS_SESSION);
    let main = view::<Channel>(MAIN_CHANNEL);
    for _ in 0..1000 {
        let copy = sys::handle_duplicate(memory, Rights::MAP_READ | Rights::TRANSFER)
            .map_err(|_| proto_pkg::NO_MEMORY)?;
        let tell = sys::handle_label(
            &main,
            Rights::NOTIFY | Rights::TRANSFER,
            LABEL_LAYER + u64::from(layer),
            MAIN_LEVEL,
        )
        .map_err(|_| proto_pkg::NO_MEMORY)?;
        let mut w = Writer::new();
        let start = LayerStart {
            op: LayerOp::Attach,
            layer,
            level: u32::from(LEVEL),
        };
        start.write(&mut w).map_err(|_| proto_pkg::INVALID)?;
        let reply = sys::send_handles(&session, w.as_bytes(), [copy.erase(), tell.erase()])
            .map_err(|_| proto_pkg::IO)?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut answer = LayerReply::read(proto_wire::Reader::new(reply.bytes(&mut buffer)))
            .map_err(|_| proto_pkg::IO)?;
        loop {
            match answer {
                LayerReply::Resolving => {
                    let mut w = Writer::new();
                    LayerStep { layer }
                        .write(&mut w)
                        .map_err(|_| proto_pkg::INVALID)?;
                    let reply = sys::send(&session, w.as_bytes()).map_err(|_| proto_pkg::IO)?;
                    answer = LayerReply::read(proto_wire::Reader::new(reply.bytes(&mut buffer)))
                        .map_err(|_| proto_pkg::IO)?;
                }
                LayerReply::Done { .. } => return Ok(()),
                LayerReply::Entry { status, entry } => {
                    rt::println!("pkgd: layer {layer}: status {status} at entry {entry}");
                    return Err(match status {
                        proto_fs::CONFLICT => proto_pkg::CONFLICT,
                        _ => proto_pkg::BAD_PACKAGE,
                    });
                }
                LayerReply::Refused { status } if status == proto_fs::BUSY => break,
                LayerReply::Refused { status } if status == proto_fs::NO_SPACE => {
                    return Err(proto_pkg::NO_SPACE);
                }
                LayerReply::Refused { .. } => return Err(proto_pkg::IO),
            }
        }
        // The mapping thread of the file service is busy with the last layer.
        let _ = sys::yield_now();
    }
    Err(proto_pkg::BUSY)
}

/// What the start of the disk is and does. The lines it prints are the
/// service's account of what it found (pk3-design R12).
fn run() -> Result<(), Fail> {
    let process = view::<Process>(PROCESS);
    let mut disk = connect_disk(&process)?;
    let roots = roots();
    rt::print!("pkgd: roots");
    for key in &roots.0[..roots.1] {
        rt::print!(" {}", key.name.as_str());
    }
    rt::println!();
    // SAFETY: the thread owns the table until `STARTING` clears.
    let table = unsafe { &mut *TABLE.get() };
    let opened = match commit::open(&mut disk, table).map_err(|_| "the disk failed")? {
        Start::Store(opened) => opened,
        Start::Blank if disk.flush => {
            let opened = commit::format(&mut disk, table).map_err(|_| "the format failed")?;
            rt::println!(
                "pkgd: store formatted, {} blocks",
                disk.blocks() - store::SUPERS
            );
            READ_ONLY.store(false, Release);
            GENERATION.store(opened.superblock.generation, Release);
            finish_counts(&opened, table, &disk);
            return Ok(());
        }
        Start::Blank => {
            rt::println!("pkgd: device has no flush, store read-only");
            READ_ONLY.store(true, Release);
            return Ok(());
        }
        Start::Damaged => {
            rt::println!("pkgd: store damaged, no package from the disk");
            DAMAGED.store(true, Release);
            return Ok(());
        }
    };
    if !disk.flush {
        rt::println!("pkgd: device has no flush, store read-only");
        READ_ONLY.store(true, Release);
    }
    GENERATION.store(opened.superblock.generation, Release);
    let settings_len = read_settings(&mut disk, table, &process);
    let revoked = read_revoked(&mut disk, table, &roots);
    let mut disk_count = 0;
    for (slot, published) in PUBLISHED.iter().enumerate() {
        let record = table.record(slot);
        if record.kind != store::PACKAGE {
            continue;
        }
        match load(
            &mut disk,
            &process,
            table,
            &record,
            slot,
            &roots,
            settings_len,
            &revoked,
        ) {
            Ok(entry) => {
                // SAFETY: the slot is published below, after the entry is whole.
                unsafe { (*DISK_ENTRIES.get())[slot] = Some(entry) };
                published.store(true, Release);
                disk_count += 1;
            }
            Err(why) => rt::println!(
                "pkgd: {}: {why}, skipped",
                core::str::from_utf8(record.name_bytes()).unwrap_or("?")
            ),
        }
    }
    DISK_PACKAGES.store(disk_count, Release);
    finish_counts(&opened, table, &disk);
    Ok(())
}

fn finish_counts(opened: &commit::Opened, table: &Table, disk: &Disk) {
    let free = commit::free_of(table, opened);
    FREE.store(free, Release);
    BLOCKS.store(disk.blocks(), Release);
    GENERATION.store(opened.superblock.generation, Release);
    rt::println!(
        "pkgd: ready, {} packages from the disk, {} from the image, {free} blocks free",
        DISK_PACKAGES.load(Acquire),
        IMAGE_PACKAGES.load(Acquire),
    );
}

/// The roots of the trust of the official repository.
fn roots() -> ([Key; 4], usize) {
    let mut keys = [Key {
        name: pkgfmt::Name::new("none").expect("a name"),
        public: [0; 32],
    }; 4];
    let mut n = 0;
    for line in pkgd::ROOTS {
        if let Ok(key) = keyfile::parse_public(line)
            && n < keys.len()
        {
            keys[n] = key;
            n += 1;
        }
    }
    (keys, n)
}

/// The blob of settings from its extent, checked, made into the container of
/// a layer and attached. The length of the blob, 0 for none.
fn read_settings(disk: &mut Disk, table: &Table, process: &Handle<Process>) -> usize {
    let record = table.record(store::SETTINGS_SLOT);
    if record.kind != store::SETTINGS {
        return 0;
    }
    // SAFETY: the thread owns the blob until `STARTING` clears.
    let blob = unsafe { &mut *SETTINGS.get() };
    if record.length as usize > blob.len() || disk_read(disk, &record, blob).is_err() {
        rt::println!("pkgd: settings damaged, no settings layer");
        return 0;
    }
    let bytes = &blob[..record.length as usize];
    let Ok(parsed) = Settings::parse(bytes)
        .map_err(|_| ())
        .and_then(|s| (sha256(bytes) == record.sha256).then_some(s).ok_or(()))
    else {
        rt::println!("pkgd: settings damaged, no settings layer");
        return 0;
    };
    // SAFETY: as above.
    let out = unsafe { &mut *CONTAINER.get() };
    let Some(len) = settings::container(&parsed, out) else {
        return 0;
    };
    let layer = next_layer();
    let attached = sys::mem_create(len as u64)
        .map_err(|_| proto_pkg::NO_MEMORY)
        .and_then(|memory| {
            sys::mem_map(
                process,
                &memory,
                0,
                len as u64,
                window(PACKAGES),
                Access::ReadWrite,
            )
            .map_err(|_| proto_pkg::NO_MEMORY)?;
            // SAFETY: the window is the thread's and mapped for `len` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(out.as_ptr(), window(PACKAGES) as *mut u8, len)
            };
            // SAFETY: nothing reads the window any more.
            let _ = unsafe { sys::mem_unmap(process, window(PACKAGES), len as u64) };
            attach(&memory, layer).map(|()| memory)
        });
    match attached {
        Ok(memory) => {
            // SAFETY: the thread owns the handles of the start.
            unsafe { (*OBJECTS.get())[PACKAGES] = Some(memory) };
            SETTINGS_LEN.store(bytes.len(), Release);
        }
        Err(code) => rt::println!("pkgd: settings layer: code {code}, not attached"),
    }
    bytes.len()
}

/// The extent of `record` into `out`.
fn disk_read(disk: &mut Disk, record: &Record, out: &mut [u8]) -> Result<(), Failed> {
    disk.read_run(record.first, u64::from(record.blocks), |at, bytes| {
        let from = at as usize * BLOCK;
        let n = bytes.len().min(out.len().saturating_sub(from));
        out[from..from + n].copy_from_slice(&bytes[..n]);
    })
}

/// The list of revocations from its extent: the text, then the block of the
/// signature of a root. The entries that count; none when the list is bad.
fn read_revoked(
    disk: &mut Disk,
    table: &Table,
    roots: &([Key; 4], usize),
) -> ([Option<Revocation>; REVOKED_MAX], usize) {
    let none = ([None; REVOKED_MAX], 0);
    let record = table.record(store::REVOKED_SLOT);
    if record.kind != store::REVOKED_LIST {
        return none;
    }
    // SAFETY: the thread owns the buffer until `STARTING` clears.
    let buffer = unsafe { &mut *REVOKED_FILE.get() };
    let bad = |why: &str| {
        rt::println!("pkgd: revocation list damaged ({why}), using the empty list");
        none
    };
    if record.length as usize > buffer.len()
        || record.length as usize <= pkgfmt::sig::BLOCK_SIZE
        || disk_read(disk, &record, buffer).is_err()
    {
        return bad("read");
    }
    let bytes = &buffer[..record.length as usize];
    if sha256(bytes) != record.sha256 {
        return bad("hash");
    }
    let (text, block) = bytes.split_at(bytes.len() - pkgfmt::sig::BLOCK_SIZE);
    let trust = Trust {
        roots: &roots.0[..roots.1],
        direct: &[],
    };
    let parsed = core::str::from_utf8(text)
        .ok()
        .and_then(|t| pkgfmt::revoked::Revoked::parse(t).ok());
    let signed = pkgfmt::Block::parse(block).ok().and_then(|b| {
        pkgfmt::trust::verify(
            &b,
            pkgfmt::Kind::Revoked,
            &sha256(text),
            text.len() as u64,
            &trust,
            &[],
        )
        .ok()
    });
    let (Some(list), Some(_)) = (parsed, signed) else {
        return bad("signature");
    };
    if list.serial != record.number {
        return bad("serial");
    }
    let mut out = none;
    for r in list.entries().take(REVOKED_MAX) {
        out.0[out.1] = Some(r);
        out.1 += 1;
    }
    out
}

/// One package of the disk: its object created and filled while the hashes
/// run, the checks of `pkgd::verify`, the attach. The words of what refused it.
#[allow(clippy::too_many_arguments)]
fn load(
    disk: &mut Disk,
    process: &Handle<Process>,
    table: &Table,
    record: &Record,
    slot: usize,
    roots: &([Key; 4], usize),
    settings_len: usize,
    revoked: &([Option<Revocation>; REVOKED_MAX], usize),
) -> Result<Entry, &'static str> {
    // A package of the image of the same name is the one that is used.
    // SAFETY: the main thread filled the image entries before this thread began.
    let images = unsafe { &*IMAGE_ENTRIES.get() };
    if images
        .iter()
        .flatten()
        .any(|e| e.name() == record.name_bytes())
    {
        return Err("in the image");
    }
    let len = record.length;
    let memory = sys::mem_create(len).map_err(|_| "no memory")?;
    let at = window(slot);
    sys::mem_map(process, &memory, 0, len, at, Access::ReadWrite).map_err(|_| "not mapped")?;
    let blocks = u64::from(record.blocks);
    let mut stream = Stream::new();
    let mut covered = [0u8; 32];
    let hashed = Stopwatch::new();
    let read = disk.read_run(record.first, blocks, |first, bytes| {
        // SAFETY: the window holds `len` bytes and this is the thread's alone.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (at + first as usize * BLOCK) as *mut u8,
                bytes.len(),
            )
        };
        let last = first + (bytes.len() / BLOCK) as u64 == blocks;
        let body = if last {
            bytes.len() - BLOCK
        } else {
            bytes.len()
        };
        stream.update(&bytes[..body]);
        if last {
            covered = stream.clone().finish();
            stream.update(&bytes[body..]);
        }
    });
    hashed.keep(&HASH_TICKS);
    // SAFETY: the unmap below is the last use of the window.
    let unmap = || {
        let _ = unsafe { sys::mem_unmap(process, at, len) };
    };
    if read.is_err() {
        unmap();
        return Err("read failed");
    }
    let whole = stream.finish();
    // SAFETY: the window holds the whole file, no one writes it now.
    let bytes = unsafe { core::slice::from_raw_parts(at as *const u8, len as usize) };
    let repo = table.repo(usize::from(record.repo)).map(|(name, _)| name);
    let own = match repo {
        Some(b"stafeto") | None => None,
        Some(name) => settings_key(settings_len, name),
    };
    let official = matches!(repo, Some(b"stafeto"));
    let own_keys = own.map_or([].as_slice(), |k| core::slice::from_ref(k));
    let trust = verify::select(official, &roots.0[..roots.1], own_keys);
    let list: [Revocation; REVOKED_MAX] = core::array::from_fn(|i| {
        revoked.0[i].unwrap_or(Revocation {
            name: pkgfmt::Name::new("none").expect("a name"),
            since: u64::MAX,
        })
    });
    let checking = Stopwatch::new();
    let checked = verify::check(
        bytes,
        &covered,
        &whole,
        record,
        pkgd::SERIES,
        &trust,
        &list[..revoked.1],
    );
    checking.keep(&CHECK_TICKS);
    let entry = match checked {
        Ok(checked) => {
            let mut entry = Entry {
                record: *record,
                image: false,
                layer: 0,
                meta_len: 0,
                meta: [0; pkgd::packages::META_MAX],
                trailer: [0; pkgd::packages::TRAILER],
            };
            if entry.keep(checked.meta, checked.trailer) {
                Ok(entry)
            } else {
                Err(Fault::BadPackage)
            }
        }
        Err(fault) => Err(fault),
    };
    unmap();
    let mut entry = entry.map_err(Fault::words)?;
    entry.layer = next_layer();
    attach(&memory, entry.layer).map_err(|code| match code {
        proto_pkg::CONFLICT => "conflict",
        proto_pkg::NO_SPACE => "no space for a layer",
        _ => "not attached",
    })?;
    // SAFETY: the thread owns the handles until it is done.
    unsafe { (*OBJECTS.get())[slot] = Some(memory) };
    Ok(entry)
}

/// The key of the owner's repository `name` out of the settings blob, which
/// the thread read (`read_settings`), parsed again.
fn settings_key(len: usize, name: &[u8]) -> Option<&'static Key> {
    if len == 0 {
        return None;
    }
    // SAFETY: the blob is the thread's until it is done and unchanged by now.
    let blob = unsafe { core::slice::from_raw_parts((*SETTINGS.get()).as_ptr(), len) };
    let key = Settings::parse(blob)
        .ok()?
        .key_of(core::str::from_utf8(name).ok()?)?;
    // SAFETY: one key of the repository being loaded at a time.
    unsafe { *KEY.get() = Some(key) };
    unsafe { (*KEY.get()).as_ref() }
}
