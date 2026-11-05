// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The second network device in the hands of the process (spec 6, 3.9;
//! `<stafeto/fast.h>`, the protocol `proto_net::fast`). `claim` makes the
//! bypass ring (17 pages of the process's quota) and sends CLAIM to the
//! network service with a copy of the identity session (the service has
//! the process service vouch for the superuser), a copy of the calling
//! thread's channel with a label of `FAST_LABEL`, new for each try (the
//! service notifies it)
//! and a copy of the ring; CLAIM_MORE brings the last two objects. The
//! window, the five objects and the ring become pieces of the memory map of
//! their own kind (`posix_map::Kind::Fast`): `munmap`, `mprotect` and
//! `mremap` refuse them, `fork` and `exec` fail with EPERM while the
//! process has them, and the end of the process gives them back with the
//! device. The device's driver is the static library `libvirtio_net.a`;
//! the layer makes every call of the kernel.
//!
//! `wait` waits on the claiming thread's channel for the service's
//! notifications; the kernel adds the bits of the notifications that came
//! meanwhile into one. Another wait of the same thread on its channel (a
//! `poll`) takes such a notification away: the program looks at its queues
//! after every wait in any case (the device's queue is checked once more
//! after its interrupts are turned on).

use crate::constants::{EBADF, EBUSY, EINTR, EINVAL, EIO, ENODEV, ENOMEM, EPERM, ETIMEDOUT};
use crate::threads;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use proto_net::fast::{self as wire, Claimed, RING_PAGES};
use proto_wire::{Reader, Status, Writer};
use rt::abi::{CLIENT_GONE, Error, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle, Memory, Timer};
use rt::sys::{self, Received};

/// The label of the service's notifications and of the wait's timer on
/// the thread's channel: apart from the labels of `wait` (bit 63) and of
/// the long operations (small numbers).
///
/// Each try of CLAIM labels its copy of the channel anew (`FAST_LABEL`
/// with the number of the try in the low 32 bits): the service closes the
/// copy of a refused try, the kernel puts its CLIENT_GONE on the channel
/// with that label, and `wait` takes only the label of the claim that holds
/// the device, so the departure of a refused try never reads as the end of
/// the service.
pub const FAST_LABEL: u64 = 1 << 62 | 0xfa57 << 32;
const TIMER_LABEL: u64 = 1 << 62 | 0xfa58 << 32;
/// The label of the try that got the device (0 before).
static ACTIVE: AtomicU64 = AtomicU64::new(0);
/// The number of the next try.
static TRY: AtomicU64 = AtomicU64::new(1);
/// EPROTO: KICK on a ring the service found broken.
const EPROTO: i32 = 71;
/// How long `claim` waits for the second address and for the device.
const ADDRESS_WAIT_NS: u64 = 20_000_000_000;
const BUSY_WAIT_NS: u64 = 30_000_000_000;
const RETRY_NS: u64 = 100_000_000;
const PAGE: usize = 4096;
const ENETDOWN: i32 = 100;
/// The bit `wait` gives when the service let go of its notifications: it
/// ended, or it took the device back.
pub const GONE: u32 = 16;

/// The bits of a notification of the service as `wait` gives them.
fn bits_of(bits: u64) -> u32 {
    let own = (bits & 0xf) as u32;
    if bits & CLIENT_GONE != 0 {
        own | GONE
    } else {
        own
    }
}

/// `struct stafeto_fast_object`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FastObject {
    pub va: u64,
    pub pa: u64,
    pub pages: u32,
    pub uncached: u32,
}

/// `struct stafeto_fast_config`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FastConfig {
    pub address: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub mac: [u8; 6],
    pub prefix: u8,
    pub pad: u8,
}

/// `struct stafeto_fast_claim`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FastClaim {
    pub kind: u32,
    pub pad: u32,
    pub window: u64,
    pub window_len: u64,
    pub objects: [FastObject; wire::OBJECTS],
    pub ring: u64,
    pub bar_sizes: [u64; 6],
    pub snapshot: [u32; wire::SNAPSHOT_WORDS],
    pub config: FastConfig,
}

const _: () = {
    // The layout of `<stafeto/fast.h>` (and of `vnet.h`'s library).
    assert!(core::mem::size_of::<FastObject>() == 24);
    assert!(core::mem::size_of::<FastConfig>() == 20);
    assert!(core::mem::offset_of!(FastClaim, objects) == 24);
    assert!(core::mem::offset_of!(FastClaim, ring) == 144);
    assert!(core::mem::offset_of!(FastClaim, snapshot) == 200);
    assert!(core::mem::offset_of!(FastClaim, config) == 456);
    assert!(core::mem::size_of::<FastClaim>() == 480);
};

/// The flag of `claim`: EBUSY at once while the device has an owner.
pub const ONCE: u32 = 1;

/// The process holds the device.
static CLAIMED: AtomicBool = AtomicBool::new(false);
/// The claiming thread's channel, and the timer of its waits (raw handles).
static CHANNEL: AtomicU64 = AtomicU64::new(0);
static TIMER: AtomicU64 = AtomicU64::new(0);

/// Whether the process claimed the device: `fork` and `exec` refuse then.
pub fn claimed() -> bool {
    CLAIMED.load(Ordering::Acquire)
}

fn config_of(c: &proto_net::Config) -> FastConfig {
    FastConfig {
        address: c.address,
        gateway: c.gateway.unwrap_or([0; 4]),
        dns: c.dns.unwrap_or([0; 4]),
        mac: c.mac,
        prefix: c.prefix as u8,
        pad: 0,
    }
}

fn service() -> Result<core::mem::ManuallyDrop<Handle<Channel>>, i32> {
    crate::net::session().map(Handle::borrowed).ok_or(ENODEV)
}

/// The errno of a refusal of CLAIM.
fn refusal(status: Status) -> i32 {
    match status.code() {
        proto_net::NOT_ALLOWED => EPERM,
        proto_net::BUSY => EBUSY,
        proto_net::NET_DOWN => ENETDOWN,
        proto_net::INVALID => ENODEV,
        _ => match status {
            Status::Kernel(Error::NoMemory | Error::LimitReached) => ENOMEM,
            _ => EIO,
        },
    }
}

/// Sends `request` with `handles` until a signal no longer interrupts it.
fn call(
    service: &Handle<Channel>,
    request: &[u8],
    handles: rt::handle::Outgoing,
) -> Result<sys::Reply, i32> {
    let mut handles = Some(handles);
    loop {
        let Some(sending) = handles.take() else {
            return Err(EIO);
        };
        match sys::send_handles(service, request, sending) {
            Ok(reply) => return Ok(reply),
            Err(refused) if refused.error == Error::Interrupted => handles = refused.back,
            Err(refused) => {
                return Err(match refused.error {
                    Error::PeerClosed | Error::BadHandle => ENODEV,
                    _ => EIO,
                });
            }
        }
    }
}

/// Sleeps on the thread's channel until `until` (nanoseconds of the
/// counter): the claim's pause between two tries.
fn pause(until: u64) -> Result<(), i32> {
    let timer = timer()?;
    loop {
        if crate::wait::now() >= until {
            return Ok(());
        }
        sys::timer_set(&timer, until).map_err(|_| EIO)?;
        match sys::receive(&channel()) {
            Ok(_) => {}
            Err(Error::Interrupted) => {
                crate::signals::deliver_now();
                return Err(EINTR);
            }
            Err(_) => return Err(EIO),
        }
    }
}

fn channel() -> core::mem::ManuallyDrop<Handle<Channel>> {
    let block = threads::own_block();
    Handle::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)))
}

fn level() -> u8 {
    (threads::own_block().base_level.load(Ordering::Relaxed) as u8).max(1)
}

/// The timer of the waits, labelled on the claiming thread's channel; made
/// at the first use.
fn timer() -> Result<core::mem::ManuallyDrop<Handle<Timer>>, i32> {
    let raw = TIMER.load(Ordering::Acquire);
    if raw != 0 {
        return Ok(Handle::borrowed(rt::abi::Handle(raw)));
    }
    let labelled =
        sys::handle_label(&channel(), Rights::RECEIVE, TIMER_LABEL, level()).map_err(|_| EIO)?;
    let timer = sys::timer_create(&labelled, level()).map_err(|_| EIO)?;
    // The view lives as long as the timer: both are the process's to the end.
    core::mem::forget(labelled);
    let raw = timer.raw().0;
    core::mem::forget(timer);
    TIMER.store(raw, Ordering::Release);
    Ok(Handle::borrowed(rt::abi::Handle(raw)))
}

/// One CLAIM: the reply, or the errno with the status of a refusal.
fn ask(
    service: &Handle<Channel>,
    ring: &Handle<Memory>,
    label: u64,
) -> Result<(Claimed, sys::Reply), (i32, Option<Status>)> {
    let identity = crate::process::identity()
        .and_then(|i| sys::handle_duplicate(i, Rights::NOTIFY | Rights::TRANSFER).ok())
        .ok_or((EPERM, None))?;
    let notify = sys::handle_label(
        &channel(),
        Rights::NOTIFY | Rights::TRANSFER,
        label,
        level(),
    )
    .map_err(|_| (EIO, None))?;
    let copy = sys::handle_duplicate(
        ring,
        Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
    )
    .map_err(|_| (ENOMEM, None))?;
    let mut handles = rt::handle::Outgoing::new();
    for h in [identity.erase(), notify.erase(), copy.erase()] {
        handles.push(h).map_err(|_| (EIO, None))?;
    }
    let mut w = Writer::new();
    wire::write_claim(RING_PAGES, &mut w).map_err(|_| (EIO, None))?;
    let reply = call(service, w.as_bytes(), handles).map_err(|e| (e, None))?;
    let mut buffer = [0u8; MESSAGE_MAX];
    match Claimed::read(reply.bytes(&mut buffer)) {
        Ok(claimed) => Ok((claimed, reply)),
        Err(status) => Err((refusal(status), Some(status))),
    }
}

/// `stafeto_fast_claim`.
pub fn claim(out: &mut FastClaim, flags: u32) -> Result<(), i32> {
    if claimed() {
        return Err(EBUSY);
    }
    let service = service()?;
    CHANNEL.store(
        threads::own_block().channel.load(Ordering::Relaxed),
        Ordering::Release,
    );
    let size = RING_PAGES as usize * PAGE;
    let ring = sys::mem_create(size as u64).map_err(|_| ENOMEM)?;
    let started = crate::wait::now();
    let (claimed, mut reply) = loop {
        let label = FAST_LABEL | (TRY.fetch_add(1, Ordering::Relaxed) & 0xffff_ffff);
        match ask(&service, &ring, label) {
            Ok(got) => {
                ACTIVE.store(label, Ordering::Release);
                break got;
            }
            Err((ENETDOWN, _)) if crate::wait::now() < started + ADDRESS_WAIT_NS => {}
            Err((EBUSY, Some(_)))
                if flags & ONCE == 0 && crate::wait::now() < started + BUSY_WAIT_NS => {}
            Err((errno, _)) => return Err(errno),
        }
        pause(crate::wait::now() + RETRY_NS)?;
    };
    CLAIMED.store(true, Ordering::Release);
    let mut objects: [Option<Handle<Memory>>; 6] = Default::default();
    for (i, slot) in objects.iter_mut().take(4).enumerate() {
        *slot = reply.handles.take::<Memory>(i).ok();
    }
    let mut w = Writer::new();
    wire::write_claim_more(&mut w).map_err(|_| EIO)?;
    let more = call(&service, w.as_bytes(), rt::handle::Outgoing::new())?;
    let mut buffer = [0u8; MESSAGE_MAX];
    let status = Reader::new(more.bytes(&mut buffer))
        .u32()
        .map_or(Status::BadSize, Status::from_code);
    if status != Status::Ok {
        return Err(refusal(status));
    }
    let mut more = more;
    for (i, slot) in objects.iter_mut().skip(4).enumerate() {
        *slot = more.handles.take::<Memory>(i).ok();
    }
    let [window, rest @ ..] = objects;
    let window = window.ok_or(EIO)?;
    *out = FastClaim {
        kind: claimed.kind,
        pad: 0,
        window: 0,
        window_len: 0,
        objects: [FastObject::default(); wire::OBJECTS],
        ring: 0,
        bar_sizes: claimed.bar_sizes,
        snapshot: claimed.snapshot,
        config: config_of(&claimed.config),
    };
    crate::allocation::heap(|state| -> Result<(), i32> {
        // The window: the transport's page (virtio-mmio), or the function's
        // BAR 0 alone in a window that may hold another's (PCI).
        if claimed.kind == wire::PCI {
            let len = claimed.bar_sizes[0] as usize;
            if len == 0
                || !len.is_multiple_of(PAGE)
                || !(claimed.transport as usize).is_multiple_of(PAGE)
            {
                return Err(EIO);
            }
            let at = state.map_fast(window, len / PAGE, claimed.transport as usize / PAGE)?;
            out.window = at as u64;
            out.window_len = len as u64;
        } else {
            let at = state.map_fast(window, 1, 0)?;
            out.window = (at + (claimed.transport as usize % PAGE)) as u64;
            out.window_len = PAGE as u64;
        }
        for (i, handle) in rest.into_iter().enumerate() {
            let o = claimed.objects[i];
            let handle = handle.ok_or(EIO)?;
            let at = state.map_fast(handle, o.pages as usize, 0)?;
            out.objects[i] = FastObject {
                va: at as u64,
                pa: o.pa,
                pages: o.pages,
                uncached: u32::from(o.uncached),
            };
        }
        out.ring = state.map_fast(ring, RING_PAGES as usize, 0)? as u64;
        Ok(())
    })
}

/// `stafeto_fast_wait`: the bits of the service's notifications that came,
/// waiting up to `timeout_ns` (0 only looks).
pub fn wait(timeout_ns: u64) -> Result<u32, i32> {
    if !claimed() {
        return Err(EBADF);
    }
    let own = channel();
    if own.raw().0 != CHANNEL.load(Ordering::Acquire) {
        return Err(EBADF);
    }
    let until = crate::wait::now().saturating_add(timeout_ns);
    let block = threads::own_block();
    // The notifications of other labels (a refused try's CLIENT_GONE, a
    // timer that fired late) are taken off the channel and dropped.
    let active = ACTIVE.load(Ordering::Acquire);
    loop {
        // Whatever waits on the channel first, without blocking.
        loop {
            match sys::try_receive(&own) {
                Ok(Received::Notification { label, bits, .. }) if label == active => {
                    return Ok(bits_of(bits));
                }
                Ok(_) => {}
                Err(Error::WouldBlock) => break,
                Err(Error::Interrupted) => {
                    crate::signals::deliver_now();
                    return Err(EINTR);
                }
                Err(_) => return Err(EIO),
            }
        }
        if crate::wait::now() >= until {
            return Err(ETIMEDOUT);
        }
        let handled = block.handled.load(Ordering::SeqCst);
        if crate::signals::pending_unblocked() {
            crate::signals::deliver_now();
            return Err(EINTR);
        }
        let timer = timer()?;
        sys::timer_set(&timer, until).map_err(|_| EIO)?;
        let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
        if block.handled.load(Ordering::SeqCst) != handled || crate::signals::pending_unblocked() {
            drop(guard);
            crate::signals::deliver_now();
            return Err(EINTR);
        }
        let got = sys::receive(&own);
        drop(guard);
        match got {
            Ok(Received::Notification { label, bits, .. }) if label == active => {
                let _ = sys::timer_cancel(&timer);
                return Ok(bits_of(bits));
            }
            Ok(_) => {}
            Err(Error::Interrupted) => {
                let _ = sys::timer_cancel(&timer);
                crate::signals::deliver_now();
                return Err(EINTR);
            }
            Err(_) => return Err(EIO),
        }
    }
}

/// `stafeto_fast_kick`: the frames the service took in its step.
pub fn kick(count: u32) -> Result<u32, i32> {
    if !claimed() {
        return Err(EBADF);
    }
    if !(1..=wire::RING_SLOTS).contains(&count) {
        return Err(EINVAL);
    }
    let service = service()?;
    let mut w = Writer::new();
    wire::write_kick(count, &mut w).map_err(|_| EIO)?;
    let reply = call(&service, w.as_bytes(), rt::handle::Outgoing::new())?;
    let mut buffer = [0u8; MESSAGE_MAX];
    wire::read_kick_reply(reply.bytes(&mut buffer)).map_err(|status| {
        if status.code() == proto_net::INVALID {
            EPROTO
        } else {
            refusal(status)
        }
    })
}

/// `stafeto_fast_config`: the second address now.
pub fn config() -> Result<FastConfig, i32> {
    let service = service()?;
    let mut w = Writer::new();
    wire::write_config(1, &mut w).map_err(|_| EIO)?;
    let reply = call(&service, w.as_bytes(), rt::handle::Outgoing::new())?;
    let mut buffer = [0u8; MESSAGE_MAX];
    proto_net::Config::read(reply.bytes(&mut buffer))
        .map(|c| config_of(&c))
        .map_err(refusal)
}

/// The network service built for its probe faults on CRASH (method 63); the
/// service of the shell answers an unknown method. The probe of the owner
/// uses it to end the service while the device is claimed.
pub fn probe_crash() -> Result<(), i32> {
    let service = service()?;
    let mut w = Writer::new();
    proto_net::Method::Crash
        .header()
        .write(&mut w)
        .map_err(|_| EIO)?;
    call(&service, w.as_bytes(), rt::handle::Outgoing::new()).map(|_| ())
}
