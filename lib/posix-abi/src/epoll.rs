// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! epoll (spec 6, 3.4). An instance is a descriptor of `Target::Epoll` and
//! an entry of a small table of the process; it holds the interest records
//! of its descriptors. The sockets of the network service (`Target::Net`) live
//! in a set of that service, which answers readiness with the labels this
//! layer gave (the index and the generation of the record); the user's data
//! word, and the records of the other descriptors (pipes, FIFOs, terminals),
//! live here. A record names its descriptor by the number and the
//! generation of the number (`posix_fd`), so a descriptor closed and opened
//! again is a stranger and its record goes.
//!
//! One lock, `EPOLL_LOCK`, guards the table and the pages of records. It is
//! never held with the lock of the files, and no call of a service runs
//! under it. Every stretch under it is bounded: 16 words of a bitmap, one
//! record, or at most 64 records of a batch.

use crate::constants::*;
use crate::{shared, wait};
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use posix_fs::Target;
use posix_sync::LayerLock;
use proto_net::sockets::{self as wire, EpollList, EpollReady, EpollRecord, epoll as bits};

/// The instances of a process.
pub const INSTANCES: usize = 8;
/// The records of an instance: one for each descriptor number.
pub const ENTRIES: usize = posix_fs::OPEN_MAX;
/// The records of descriptors that are not sockets of the network service.
pub const NON_NET_MAX: usize = 64;
const PAGE_ENTRIES: usize = 128;
const PAGES: usize = ENTRIES / PAGE_ENTRIES;
const WORDS: usize = ENTRIES / 64;
/// The descriptions of closed descriptors waiting to be taken out of the
/// interest set of the service.
const PENDING: usize = wire::EPOLL_BATCH;
/// The flag of `epoll_create1`.
pub const EPOLL_CLOEXEC: i32 = 0x8_0000;
const EPOLL_WAKEUP: u32 = 1 << 29;

const CTL_ADD: i32 = 1;
const CTL_DEL: i32 = 2;
const CTL_MOD: i32 = 3;

/// The event word of Linux: the events and the user's data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

// The flags of a record.
const USED: u8 = 1;
const NET: u8 = 2;
const STREAM: u8 = 4;
/// A oneshot record that reported: off until MOD.
const DISABLED: u8 = 8;
/// A record the service has not answered for yet.
const PENDING_ADD: u8 = 16;

/// A record: 32 bytes.
#[derive(Clone, Copy)]
struct Entry {
    fd: u16,
    /// The generation of the record's slot, which grows each time the slot is given.
    egen: u16,
    events: u32,
    /// The description (a socket) or the events reported last (the others,
    /// for the records by edge).
    aux: u32,
    flags: u8,
    data: u64,
    /// The generation of the descriptor number when the record was made.
    fd_generation: u64,
}
const _: () = assert!(core::mem::size_of::<Entry>() == 32);
const _: () = assert!(PAGE_ENTRIES * 32 == 4096);

struct Instance {
    used: bool,
    after_fork: bool,
    generation: u32,
    /// The set of the network service, 0 before the first socket.
    set: u32,
    count: u16,
    others: u16,
    taken: [u64; WORDS],
    /// The records of descriptors that are not sockets of the service.
    other_bits: [u64; WORDS],
    pages: [*mut Entry; PAGES],
    /// The record of each descriptor number, plus one (0 for none).
    by_fd: *mut [u16; ENTRIES],
    pending: [u32; PENDING],
    pending_len: u8,
}

impl Instance {
    const EMPTY: Instance = Instance {
        used: false,
        after_fork: false,
        generation: 0,
        set: 0,
        count: 0,
        others: 0,
        taken: [0; WORDS],
        other_bits: [0; WORDS],
        pages: [core::ptr::null_mut(); PAGES],
        by_fd: core::ptr::null_mut(),
        pending: [0; PENDING],
        pending_len: 0,
    };
}

struct Table(UnsafeCell<[Instance; INSTANCES]>);
// SAFETY: every access is under `EPOLL_LOCK`.
unsafe impl Sync for Table {}
static TABLE: Table = Table(UnsafeCell::new([Instance::EMPTY; INSTANCES]));
static EPOLL_LOCK: LayerLock = LayerLock::raising();
/// The descriptor numbers that have a record by edge of a pipe, a FIFO or a
/// terminal: a read or a write that finds nothing to do looks here first, so
/// that only a process with such records takes the lock of epoll.
/// How many instances are in use: a process that never made one pays one load
/// at each close (the close of a descriptor is a path of a few hundred
/// instructions, `rtbench` S4).
static LIVE: AtomicU32 = AtomicU32::new(0);
static EDGE_FDS: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
/// The descriptor numbers that have any record: a close looks here first.
static WATCHED: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];

fn locked<R>(f: impl FnOnce(&mut [Instance; INSTANCES]) -> R) -> R {
    let _guard = EPOLL_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    f(unsafe { &mut *TABLE.0.get() })
}

fn mark(map: &[AtomicU64; WORDS], fd: usize, on: bool) {
    let bit = 1u64 << (fd % 64);
    if on {
        map[fd / 64].fetch_or(bit, Ordering::Relaxed);
    } else {
        map[fd / 64].fetch_and(!bit, Ordering::Relaxed);
    }
}

fn marked(map: &[AtomicU64; WORDS], fd: usize) -> bool {
    fd < ENTRIES && map[fd / 64].load(Ordering::Relaxed) >> (fd % 64) & 1 != 0
}

/// What a step under the lock needs before it can go on: a page for the
/// records or for the map of numbers (mapped outside the lock), a flush of
/// the descriptions waiting to be taken out of the service's set, or an
/// errno.
enum Need {
    Page(usize),
    ByFd,
    Flush,
    Errno(i32),
}

impl From<i32> for Need {
    fn from(errno: i32) -> Self {
        Need::Errno(errno)
    }
}

fn is_taken(inst: &Instance, idx: usize) -> bool {
    inst.taken[idx / 64] >> (idx % 64) & 1 != 0
}

fn entry(inst: &mut Instance, idx: usize) -> Option<&mut Entry> {
    if !is_taken(inst, idx) {
        return None;
    }
    let page = inst.pages[idx / PAGE_ENTRIES];
    if page.is_null() {
        return None;
    }
    // SAFETY: the page holds PAGE_ENTRIES records, zeroed when mapped.
    Some(unsafe { &mut *page.add(idx % PAGE_ENTRIES) })
}

/// The record of descriptor number `fd`, when it has one.
fn by_fd(inst: &Instance, fd: usize) -> Option<usize> {
    if inst.by_fd.is_null() {
        return None;
    }
    // SAFETY: the page holds ENTRIES words, zeroed when mapped.
    let at = unsafe { (*inst.by_fd)[fd] };
    (at != 0).then_some(usize::from(at) - 1)
}

fn set_by_fd(inst: &mut Instance, fd: usize, idx: Option<usize>) {
    if !inst.by_fd.is_null() {
        // SAFETY: as above.
        unsafe { (*inst.by_fd)[fd] = idx.map_or(0, |i| i as u16 + 1) };
    }
}

/// The record a label of the service names, if it is that record's.
fn by_label(inst: &mut Instance, label: u32) -> Option<&mut Entry> {
    let idx = (label & 0xffff) as usize;
    let egen = (label >> 16) as u16;
    entry(inst, idx).filter(|e| e.egen == egen && e.flags & PENDING_ADD == 0)
}

fn label_of(idx: usize, egen: u16) -> u32 {
    idx as u32 | u32::from(egen) << 16
}

/// Frees the record `idx`. With `queue` the description of a socket of the
/// service goes to the descriptions to take out of its set (the caller of a
/// record that goes on its own); true when that list is full and the caller
/// flushes it.
fn free_entry(inst: &mut Instance, idx: usize, queue: bool) -> bool {
    let Some(e) = entry(inst, idx).map(|e| *e) else {
        return false;
    };
    inst.taken[idx / 64] &= !(1 << (idx % 64));
    inst.count -= 1;
    if e.flags & NET == 0 {
        inst.others -= 1;
        inst.other_bits[idx / 64] &= !(1 << (idx % 64));
    }
    let fd = usize::from(e.fd);
    if by_fd(inst, fd) == Some(idx) {
        set_by_fd(inst, fd, None);
    }
    if queue && e.flags & NET != 0 && e.flags & PENDING_ADD == 0 && inst.set != 0 {
        if usize::from(inst.pending_len) < PENDING {
            inst.pending[usize::from(inst.pending_len)] = e.aux;
            inst.pending_len += 1;
        } else {
            return true;
        }
    }
    false
}

fn free_index(inst: &Instance) -> Option<usize> {
    for (w, word) in inst.taken.iter().enumerate() {
        if *word != !0 {
            return Some(w * 64 + word.trailing_ones() as usize);
        }
    }
    None
}

/// The instance of the descriptor `id` of `Target::Epoll`.
fn instance(table: &mut [Instance; INSTANCES], id: u32) -> Result<&mut Instance, i32> {
    let inst = table.get_mut((id & 0xff) as usize).ok_or(EBADF)?;
    if inst.used && inst.generation == id >> 8 {
        Ok(inst)
    } else {
        Err(EBADF)
    }
}

/// Maps a page and gives it to the instance `id` as `need` asks; a page that
/// is not needed any more (another thread gave it first) is unmapped.
fn provide(id: u32, need: &Need) -> Result<(), i32> {
    let page = crate::allocation::map_pages(4096).map_err(|_| ENOMEM)?;
    let taken = locked(|table| {
        let Ok(inst) = instance(table, id) else {
            return false;
        };
        match need {
            Need::Page(k) if inst.pages[*k].is_null() => {
                inst.pages[*k] = page.as_ptr().cast();
                true
            }
            Need::ByFd if inst.by_fd.is_null() => {
                inst.by_fd = page.as_ptr().cast();
                true
            }
            _ => false,
        }
    });
    if !taken {
        // SAFETY: the page came from `map_pages` and nothing uses it.
        unsafe { crate::allocation::unmap_pages(page, 4096) };
    }
    Ok(())
}

/// Runs `f` on the instance `id` under the lock, giving it pages and
/// flushing as it asks, until it answers.
fn with_instance<R>(
    id: u32,
    mut f: impl FnMut(&mut Instance) -> Result<R, Need>,
) -> Result<R, i32> {
    loop {
        let step = locked(|table| match instance(table, id) {
            Ok(inst) if inst.after_fork => Err(Need::Errno(EBADF)),
            Ok(inst) => f(inst),
            Err(errno) => Err(Need::Errno(errno)),
        });
        match step {
            Ok(value) => return Ok(value),
            Err(Need::Errno(errno)) => return Err(errno),
            Err(Need::Flush) => flush(id)?,
            Err(need) => provide(id, &need)?,
        }
    }
}

/// Takes the descriptions waiting out of the interest set of the service.
fn flush(id: u32) -> Result<(), i32> {
    let (set, list, len) = locked(|table| {
        let Ok(inst) = instance(table, id) else {
            return (0, [0; PENDING], 0);
        };
        let taken = (inst.set, inst.pending, usize::from(inst.pending_len));
        inst.pending_len = 0;
        taken
    });
    if set == 0 || len == 0 {
        return Ok(());
    }
    let mut records = [EpollRecord::default(); PENDING];
    for (record, &description) in records.iter_mut().zip(&list[..len]) {
        *record = EpollRecord {
            action: wire::EPOLL_DEL,
            description,
            events: 0,
            label: 0,
        };
    }
    let Some(list) = EpollList::new(&records[..len]) else {
        return Ok(());
    };
    let mut statuses = [0u32; wire::EPOLL_BATCH];
    // The descriptions that closed meanwhile (BAD_FD) or were taken out
    // already (NO_ENTRY) are of no concern; a set that went is none.
    match crate::net::epoll_set(set, list, &mut statuses) {
        Ok(_) | Err(EBADF) => Ok(()),
        Err(errno) => Err(errno),
    }
}

// ------------------------------------------------------------------ the calls

/// epoll_create1: a new instance and its descriptor.
pub fn create(flags: i32) -> Result<i32, i32> {
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(EINVAL);
    }
    let id = locked(|table| {
        let (k, inst) = table.iter_mut().enumerate().find(|(_, i)| !i.used)?;
        let generation = match (inst.generation + 1) & 0xff_ffff {
            0 => 1,
            g => g,
        };
        *inst = Instance::EMPTY;
        inst.used = true;
        inst.generation = generation;
        LIVE.fetch_add(1, Ordering::Relaxed);
        Some(k as u32 | generation << 8)
    })
    .ok_or(EMFILE)?;
    let flags = posix_fs::DescriptorFlags {
        close_on_exec: flags & EPOLL_CLOEXEC != 0,
        close_on_fork: false,
    };
    let inserted = shared::growing(|files| {
        files
            .insert(Target::Epoll(id), flags)
            .map(|fd| fd as i32)
            .map_err(shared::page_error)
    });
    if inserted.is_err() {
        release(id);
    }
    inserted
}

/// The instance a descriptor names: EBADF for none, EINVAL for a
/// descriptor that is not an epoll.
fn epoll_of(fd: i32) -> Result<u32, i32> {
    if fd < 0 {
        return Err(EBADF);
    }
    let target = shared::with_descriptors(&[fd as u32], |files| {
        files.target(fd as u32).map_err(crate::error)
    })?;
    match target {
        Target::Epoll(id) => Ok(id),
        _ => Err(EINVAL),
    }
}

/// How a descriptor is watched.
enum Kind {
    Net { description: u32, stream: bool },
    Other,
}

fn classify(target: Target) -> Result<Kind, i32> {
    Ok(match target {
        Target::Net(n) => Kind::Net {
            description: n.description,
            stream: n.stream,
        },
        Target::Pipe(_) | Target::Fifo(_) | Target::Tty(_) => Kind::Other,
        // The console is the terminal's descriptors of the process.
        Target::Input | Target::Output | Target::Error => Kind::Other,
        Target::Epoll(_) => return Err(EINVAL),
        // Files of the file service, of `/proc` and the random devices have
        // no waiting.
        Target::Ram(_) | Target::Random(_) | Target::Proc(_) => return Err(EPERM),
    })
}

/// The errno of a record's refusal by the service.
fn record_errno(status: u32) -> i32 {
    match status {
        proto_net::BAD_FD => EBADF,
        proto_net::EXISTS => EEXIST,
        proto_net::NO_ENTRY => ENOENT,
        proto_net::NO_SPACE => ENOSPC,
        proto_net::INVALID => EINVAL,
        _ => EIO,
    }
}

/// epoll_ctl: ADD, MOD and DEL of the record of `fd` in the instance `epfd`.
pub fn ctl(epfd: i32, op: i32, fd: i32, event: Option<EpollEvent>) -> Result<(), i32> {
    if epfd < 0 || fd < 0 {
        return Err(EBADF);
    }
    let (target, fd_generation, epoll_target) =
        shared::with_descriptors(&[epfd as u32, fd as u32], |files| {
            let epoll_target = files.target(epfd as u32).map_err(crate::error)?;
            let target = files.target(fd as u32).map_err(crate::error)?;
            let generation = files.entry_generation(fd as u32).map_err(crate::error)?;
            Ok((target, generation, epoll_target))
        })?;
    let Target::Epoll(id) = epoll_target else {
        return Err(EINVAL);
    };
    if fd == epfd {
        return Err(EINVAL);
    }
    let kind = classify(target)?;
    let event = match op {
        CTL_ADD | CTL_MOD => {
            let event = event.ok_or(EFAULT)?;
            if event.events & bits::EXCLUSIVE != 0 {
                return Err(EINVAL);
            }
            Some(EpollEvent {
                events: event.events & !EPOLL_WAKEUP,
                data: event.data,
            })
        }
        CTL_DEL => None,
        _ => return Err(EINVAL),
    };
    let number = fd as usize;
    if number >= ENTRIES {
        return Err(EBADF);
    }
    match (op, event) {
        (CTL_ADD, Some(event)) => add(id, number, fd_generation, kind, event),
        (CTL_MOD, Some(event)) => modify(id, number, fd_generation, kind, event),
        _ => delete(id, number, fd_generation),
    }
}

/// The record of descriptor number `fd` of generation `generation` in the
/// instance: its index when it names this descriptor, and a record of an
/// earlier descriptor of that number is freed on the way.
fn live_entry(inst: &mut Instance, fd: usize, generation: u64) -> Result<Option<usize>, Need> {
    let Some(idx) = by_fd(inst, fd) else {
        return Ok(None);
    };
    let Some(e) = entry(inst, idx).map(|e| *e) else {
        set_by_fd(inst, fd, None);
        return Ok(None);
    };
    if e.fd_generation == generation {
        return Ok(Some(idx));
    }
    if free_entry(inst, idx, true) {
        return Err(Need::Flush);
    }
    Ok(None)
}

/// The set of the instance in the service, made at the first socket.
fn ensure_set(id: u32) -> Result<u32, i32> {
    let set = with_instance(id, |inst| Ok(inst.set))?;
    if set != 0 {
        return Ok(set);
    }
    let list = EpollList::new(&[]).ok_or(EIO)?;
    let mut statuses = [0u32; wire::EPOLL_BATCH];
    let made = crate::net::epoll_set(0, list, &mut statuses)?;
    let kept = with_instance(id, |inst| {
        if inst.set == 0 {
            inst.set = made;
        }
        Ok(inst.set)
    })?;
    if kept != made {
        // Another thread made one first: the empty one goes.
        crate::net::epoll_drop(made);
    }
    Ok(kept)
}

fn add(id: u32, fd: usize, generation: u64, kind: Kind, event: EpollEvent) -> Result<(), i32> {
    flush(id)?;
    let set = match kind {
        Kind::Net { .. } => ensure_set(id)?,
        Kind::Other => 0,
    };
    let (idx, label) = with_instance(id, |inst| {
        if live_entry(inst, fd, generation)?.is_some() {
            return Err(Need::Errno(EEXIST));
        }
        let net = matches!(kind, Kind::Net { .. });
        if usize::from(inst.count) >= ENTRIES || (!net && usize::from(inst.others) >= NON_NET_MAX) {
            return Err(Need::Errno(ENOSPC));
        }
        if inst.by_fd.is_null() {
            return Err(Need::ByFd);
        }
        let idx = free_index(inst).ok_or(Need::Errno(ENOSPC))?;
        if inst.pages[idx / PAGE_ENTRIES].is_null() {
            return Err(Need::Page(idx / PAGE_ENTRIES));
        }
        let page = inst.pages[idx / PAGE_ENTRIES];
        // SAFETY: the page holds PAGE_ENTRIES records.
        let slot = unsafe { &mut *page.add(idx % PAGE_ENTRIES) };
        let egen = slot.egen.wrapping_add(1);
        let (flags, aux) = match kind {
            Kind::Net {
                description,
                stream,
            } => (
                USED | NET | PENDING_ADD | if stream { STREAM } else { 0 },
                description,
            ),
            Kind::Other => (USED, 0),
        };
        *slot = Entry {
            fd: fd as u16,
            egen,
            events: event.events,
            aux,
            flags,
            data: event.data,
            fd_generation: generation,
        };
        inst.taken[idx / 64] |= 1 << (idx % 64);
        inst.count += 1;
        if !net {
            inst.others += 1;
            inst.other_bits[idx / 64] |= 1 << (idx % 64);
        }
        set_by_fd(inst, fd, Some(idx));
        Ok((idx, label_of(idx, egen)))
    })?;
    mark(&WATCHED, fd, true);
    let Kind::Net { description, .. } = kind else {
        if event.events & bits::ET != 0 {
            mark(&EDGE_FDS, fd, true);
        }
        return Ok(());
    };
    let result = net_record(
        set,
        EpollRecord {
            action: wire::EPOLL_ADD,
            description,
            events: event.events,
            label,
        },
    );
    // The service has answered: the record lives, or goes.
    let _ = with_instance(id, |inst| {
        match result {
            Ok(()) => {
                if let Some(e) = entry(inst, idx) {
                    e.flags &= !PENDING_ADD;
                }
            }
            Err(_) => {
                free_entry(inst, idx, false);
            }
        }
        Ok(())
    });
    result
}

/// One record to the set: 0 or the errno of the service's refusal.
fn net_record(set: u32, record: EpollRecord) -> Result<(), i32> {
    let list = EpollList::new(&[record]).ok_or(EIO)?;
    let mut statuses = [0u32; wire::EPOLL_BATCH];
    crate::net::epoll_set(set, list, &mut statuses)?;
    match statuses[0] {
        0 => Ok(()),
        status => Err(record_errno(status)),
    }
}

fn modify(id: u32, fd: usize, generation: u64, kind: Kind, event: EpollEvent) -> Result<(), i32> {
    flush(id)?;
    let (label, set) = with_instance(id, |inst| {
        let idx = live_entry(inst, fd, generation)?.ok_or(Need::Errno(ENOENT))?;
        let e = entry(inst, idx).ok_or(Need::Errno(ENOENT))?;
        if e.flags & PENDING_ADD != 0 {
            return Err(Need::Errno(ENOENT));
        }
        e.events = event.events;
        e.data = event.data;
        e.flags &= !DISABLED;
        if e.flags & NET == 0 {
            e.aux = 0;
        }
        let label = label_of(idx, e.egen);
        Ok((label, inst.set))
    })?;
    let edge = event.events & bits::ET != 0;
    match kind {
        Kind::Net { description, .. } => net_record(
            set,
            EpollRecord {
                action: wire::EPOLL_MOD,
                description,
                events: event.events,
                label,
            },
        ),
        Kind::Other => {
            mark(&EDGE_FDS, fd, edge);
            Ok(())
        }
    }
}

fn delete(id: u32, fd: usize, generation: u64) -> Result<(), i32> {
    flush(id)?;
    let (description, set) = with_instance(id, |inst| {
        let idx = live_entry(inst, fd, generation)?.ok_or(Need::Errno(ENOENT))?;
        let e = entry(inst, idx).map(|e| *e).ok_or(Need::Errno(ENOENT))?;
        free_entry(inst, idx, false);
        Ok(((e.flags & NET != 0).then_some(e.aux), inst.set))
    })?;
    mark(&EDGE_FDS, fd, false);
    if let Some(description) = description
        && set != 0
    {
        // A description that closed (BAD_FD) or was out already is no error.
        let _ = net_record(
            set,
            EpollRecord {
                action: wire::EPOLL_DEL,
                description,
                events: 0,
                label: 0,
            },
        );
    }
    Ok(())
}

// ------------------------------------------------------------------ waiting

/// epoll_pwait: up to `out.len()` events; `timeout` is relative nanoseconds
/// (None without end); `mask` replaces the signal mask while it waits. A
/// signal ends the wait with EINTR whatever its handler's SA_RESTART.
pub fn pwait(
    epfd: i32,
    out: &mut [EpollEvent],
    timeout: Option<u64>,
    mask: Option<u64>,
) -> Result<usize, i32> {
    if out.is_empty() {
        return Err(EINVAL);
    }
    let id = epoll_of(epfd)?;
    // The pairs the service gave, which the records must not lose when the
    // wait ends with an error after taking them.
    let mut consumed = EpollReady::EMPTY;
    let result = wait::boundary(timeout, mask, |until, handled| {
        round(id, out, until, handled, &mut consumed)
    });
    if result.is_err() && consumed.len != 0 {
        restore(id, &consumed);
    }
    result
}

/// What a round collects under the lock: the records of the other
/// descriptors, as the entries of a poll.
struct Gathered {
    items: [posix_types::PollFd; NON_NET_MAX],
    index: [u16; NON_NET_MAX],
    egen: [u16; NON_NET_MAX],
    len: usize,
    set: u32,
    nets: bool,
}

fn gather(id: u32) -> Result<Gathered, i32> {
    with_instance(id, |inst| {
        let mut g = Gathered {
            items: [posix_types::PollFd::default(); NON_NET_MAX],
            index: [0; NON_NET_MAX],
            egen: [0; NON_NET_MAX],
            len: 0,
            set: inst.set,
            nets: false,
        };
        g.nets = inst.count > inst.others;
        for word in 0..WORDS {
            let mut bits_left = inst.other_bits[word];
            while bits_left != 0 {
                let at = word * 64 + bits_left.trailing_zeros() as usize;
                bits_left &= bits_left - 1;
                let Some(e) = entry(inst, at).map(|e| *e) else {
                    continue;
                };
                if e.flags & DISABLED != 0 {
                    continue;
                }
                let edge = e.events & bits::ET != 0;
                if edge && e.aux & (bits::ERR | bits::HUP) != 0 {
                    // It reported the end of its descriptor once; no more.
                    continue;
                }
                // By edge, what was reported last is not asked for again.
                let asked = if edge { e.events & !e.aux } else { e.events } & bits::EVENTS;
                g.items[g.len] = posix_types::PollFd {
                    fd: i32::from(e.fd),
                    events: asked as i16,
                    revents: 0,
                };
                g.index[g.len] = at as u16;
                g.egen[g.len] = e.egen;
                g.len += 1;
            }
        }
        Ok(g)
    })
}

/// One round of the wait: the records gathered, one wait on them and the
/// service's set together, the events that came as the user sees them. Goes
/// again when nothing of what came is for a live record.
fn round(
    id: u32,
    out: &mut [EpollEvent],
    until: Option<u64>,
    handled: u64,
    consumed: &mut EpollReady,
) -> Result<usize, i32> {
    loop {
        flush(id)?;
        let mut g = gather(id)?;
        // The service gives pairs it takes off its lists for good: it is
        // asked for no more than fit, and a place is kept for the other
        // descriptors when there are any, so that sockets never crowd them out.
        let reserve = usize::from(g.len > 0 && out.len() > 1);
        let most = (out.len() - reserve).min(wire::EPOLL_MOST);
        let mut net = (g.nets && g.set != 0).then(|| wait::NetWait::new(g.set, most as u32));
        let len = g.len;
        let ran = wait::run_net(&mut g.items[..len], net.as_mut(), until, handled);
        // What the service gave is kept for the error exits, which put it back.
        if let Some(net) = &net {
            *consumed = net.ready;
        }
        ran?;
        let mut filled = 0;
        if let Some(net) = &net {
            filled = deliver_net(id, &net.ready, out)?;
        }
        filled += deliver_others(id, &g, &mut out[filled..])?;
        if filled > 0 {
            return Ok(filled);
        }
        if until.is_some_and(|deadline| wait::now() >= deadline) {
            return Ok(0);
        }
    }
}

/// The events of the service's pairs that are for live records, into `out`;
/// how many. A record whose descriptor number was closed or given again goes.
fn deliver_net(id: u32, ready: &EpollReady, out: &mut [EpollEvent]) -> Result<usize, i32> {
    let mut found = [(0u16, 0u64, 0u64, 0u32, 0u32); wire::EPOLL_MOST];
    let mut len = 0;
    with_instance(id, |inst| {
        len = 0;
        for &(label, events) in ready.as_slice() {
            if let Some(e) = by_label(inst, label) {
                found[len] = (e.fd, e.fd_generation, e.data, events, label);
                len += 1;
            }
        }
        Ok(())
    })?;
    // One capture of the files' lock for the whole batch.
    let mut live = [false; wire::EPOLL_MOST];
    shared::with_files(|files| {
        for (k, f) in found[..len].iter().enumerate() {
            live[k] = files
                .entry_generation(u32::from(f.0))
                .is_ok_and(|g| g == f.1);
        }
        Ok(())
    })?;
    let mut filled = 0;
    let mut dead = false;
    for (k, f) in found[..len].iter().enumerate() {
        if live[k] && filled < out.len() {
            out[filled] = EpollEvent {
                events: f.3,
                data: f.2,
            };
            filled += 1;
        } else if !live[k] {
            dead = true;
        }
    }
    if dead {
        with_instance(id, |inst| {
            for (k, f) in found[..len].iter().enumerate() {
                if !live[k] {
                    let idx = (f.4 & 0xffff) as usize;
                    if by_label(inst, f.4).is_some() && free_entry(inst, idx, true) {
                        return Err(Need::Flush);
                    }
                }
            }
            Ok(())
        })?;
    }
    Ok(filled)
}

/// The events of the other descriptors the wait found, into `out`.
fn deliver_others(id: u32, g: &Gathered, out: &mut [EpollEvent]) -> Result<usize, i32> {
    let mut batch = [(0u16, 0u32); NON_NET_MAX];
    let mut len = 0;
    for k in 0..g.len {
        let revents = g.items[k].revents as u16 as u32;
        if revents != 0 {
            batch[len] = (k as u16, revents);
            len += 1;
        }
    }
    if len == 0 {
        return Ok(0);
    }
    // The descriptor numbers must still name the descriptors they did.
    let mut live = [false; NON_NET_MAX];
    let generations = with_instance(id, |inst| {
        let mut generations = [0u64; NON_NET_MAX];
        for (n, &(k, _)) in batch[..len].iter().enumerate() {
            let k = usize::from(k);
            if let Some(e) = entry(inst, usize::from(g.index[k]))
                && e.egen == g.egen[k]
            {
                generations[n] = e.fd_generation;
            }
        }
        Ok(generations)
    })?;
    shared::with_files(|files| {
        for (n, &(k, _)) in batch[..len].iter().enumerate() {
            let fd = g.items[usize::from(k)].fd as u32;
            live[n] = generations[n] != 0
                && files
                    .entry_generation(fd)
                    .is_ok_and(|generation| generation == generations[n]);
        }
        Ok(())
    })?;
    let mut filled = 0;
    with_instance(id, |inst| {
        filled = 0;
        for (n, &(k, revents)) in batch[..len].iter().enumerate() {
            let k = usize::from(k);
            let idx = usize::from(g.index[k]);
            let alive = live[n];
            let Some(e) = entry(inst, idx) else { continue };
            if e.egen != g.egen[k] {
                continue;
            }
            if !alive || revents & proto_wire::watch::NVAL != 0 {
                if free_entry(inst, idx, true) {
                    return Err(Need::Flush);
                }
                continue;
            }
            let edge = e.events & bits::ET != 0;
            let mask = (e.events & bits::EVENTS) | bits::ERR | bits::HUP;
            let mut deliver = revents & mask;
            if edge {
                deliver &= !e.aux;
                // What the snapshot lacks is not "last" any more.
                e.aux &= revents;
            }
            if deliver == 0 || filled >= out.len() {
                continue;
            }
            if edge {
                e.aux |= deliver;
            }
            if e.events & bits::ONESHOT != 0 {
                e.flags |= DISABLED;
            }
            out[filled] = EpollEvent {
                events: deliver,
                data: e.data,
            };
            filled += 1;
        }
        Ok(())
    })?;
    Ok(filled)
}

/// The pairs taken from the service that did not reach the user (the wait
/// ended with an error): the records ask the service again, which lists a
/// record that is still ready.
fn restore(id: u32, consumed: &EpollReady) {
    let mut records = [EpollRecord::default(); wire::EPOLL_BATCH];
    for chunk in consumed.as_slice().chunks(wire::EPOLL_BATCH) {
        let mut len = 0;
        let mut set = 0;
        let _ = with_instance(id, |inst| {
            len = 0;
            set = inst.set;
            for &(label, _) in chunk {
                if let Some(e) = by_label(inst, label)
                    && e.flags & NET != 0
                {
                    records[len] = EpollRecord {
                        action: wire::EPOLL_MOD,
                        description: e.aux,
                        events: e.events,
                        label,
                    };
                    len += 1;
                }
            }
            Ok(())
        });
        if let Some(list) = EpollList::new(&records[..len])
            && len != 0
            && set != 0
        {
            let mut statuses = [0u32; wire::EPOLL_BATCH];
            let _ = crate::net::epoll_set(set, list, &mut statuses);
        }
    }
}

// ------------------------------------------------------------------ the hooks

/// The last descriptor of the instance closed: its set goes in the service
/// and its pages go back.
pub fn release(id: u32) {
    let taken = locked(|table| {
        let Ok(inst) = instance(table, id) else {
            return None;
        };
        let taken = (inst.set, inst.after_fork, inst.pages, inst.by_fd);
        let generation = inst.generation;
        *inst = Instance::EMPTY;
        inst.generation = generation;
        LIVE.fetch_sub(1, Ordering::Relaxed);
        Some(taken)
    });
    let Some((set, after_fork, pages, by_fd)) = taken else {
        return;
    };
    // The instance of the parent is not the child's: its set is the
    // parent's session's, which the child has no right to drop.
    if set != 0 && !after_fork {
        crate::net::epoll_drop(set);
    }
    for page in pages.into_iter().chain([by_fd.cast()]) {
        if let Some(page) = NonNull::new(page.cast::<u8>()) {
            // SAFETY: the pages came from `map_pages` and nothing uses them.
            unsafe { crate::allocation::unmap_pages(page, 4096) };
        }
    }
}

/// The child of a fork: its instances are the parent's, whose set the
/// session of the parent holds; every call on them is EBADF, and a close of
/// them touches no service.
pub fn after_fork() {
    locked(|table| {
        for inst in table.iter_mut().filter(|i| i.used) {
            inst.after_fork = true;
        }
    });
}

/// A read, a write, a receive, a send or an accept on `fd` found nothing to
/// do (EAGAIN): a record by edge of a pipe, a FIFO or a terminal asks for
/// that event again (the contract of epoll by edge: wait after EAGAIN).
pub fn would_block(fd: i32, write: bool) {
    if fd < 0 || !marked(&EDGE_FDS, fd as usize) {
        return;
    }
    let gone = if write {
        bits::OUT | bits::WRNORM
    } else {
        bits::IN | bits::RDNORM
    };
    locked(|table| {
        for inst in table.iter_mut().filter(|i| i.used && !i.after_fork) {
            if let Some(idx) = by_fd(inst, fd as usize)
                && let Some(e) = entry(inst, idx)
                && e.flags & NET == 0
            {
                e.aux &= !gone;
            }
        }
    });
}

/// The descriptor number `fd` closed (or was given another descriptor by
/// `dup2`): its records of pipes, FIFOs and terminals go from every instance.
/// A record of a socket of the service stays until the number is looked at
/// again: its generation says it is dead (`live_entry`, and the pairs of the
/// service for it are dropped), so it costs one record of the instance for the
/// number, and the description it names is taken out of the service's set then.
#[inline(always)]
pub fn closed(fd: u32) {
    if LIVE.load(Ordering::Relaxed) != 0 {
        closed_of_instances(fd);
    }
}

#[inline(never)]
fn closed_of_instances(fd: u32) {
    let fd = fd as usize;
    if !marked(&WATCHED, fd) {
        return;
    }
    let kept = locked(|table| {
        let mut kept = false;
        for inst in table.iter_mut().filter(|i| i.used && !i.after_fork) {
            if let Some(idx) = by_fd(inst, fd) {
                if entry(inst, idx).is_some_and(|e| e.flags & NET != 0) {
                    kept = true;
                } else {
                    free_entry(inst, idx, false);
                }
            }
        }
        kept
    });
    if !kept {
        mark(&WATCHED, fd, false);
    }
    mark(&EDGE_FDS, fd, false);
}
