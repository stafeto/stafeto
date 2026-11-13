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
//! meanwhile into one. Every receive of the layer on the thread's channel
//! goes through `receive` and `try_receive` here: a notification of the
//! active try that another wait (a `poll`, a lock, a sleep) takes off the
//! channel lands in a bank, and `wait` takes the bank first. CLIENT_GONE
//! also sets the sticky `lost`. A process that never claimed has no
//! notification with the label of the fast path, so the cost of the wrappers
//! is one comparison.

use crate::constants::{EBADF, EBUSY, EINTR, EINVAL, EIO, ENODEV, ENOMEM, EPERM, ETIMEDOUT};
use crate::threads;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use posix_sync::fast_bank::CLIENT_GONE;
pub use posix_sync::fast_bank::{FAST_LABEL, FAST_MASK, GONE};
use proto_net::fast::{self as wire, Claimed, RING_PAGES};
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle, Memory, Timer};
use rt::sys;

/// The label of the wait's timer on the thread's channel: next to
/// `FAST_LABEL` and outside `FAST_MASK`.
const TIMER_LABEL: u64 = 1 << 62 | 0xfa58 << 32;
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
const _: () = assert!(CLIENT_GONE == rt::abi::CLIENT_GONE);
const _: () = assert!(TIMER_LABEL & FAST_MASK != FAST_LABEL);

pub use posix_sync::receiver::{lost, receive, take_pending, try_receive};

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
/// counter): the claim's pause between two tries. A signal ends it with
/// EINTR, or with `steady` runs its handler and sleeps on until `until`.
fn pause(until: u64, steady: bool) -> Result<(), i32> {
    let timer = timer()?;
    loop {
        if crate::wait::now() >= until {
            return Ok(());
        }
        sys::timer_set(&timer, until).map_err(|_| EIO)?;
        match receive(&channel()) {
            Ok(_) => {}
            Err(Error::Interrupted) => {
                crate::signals::deliver_now();
                if !steady {
                    return Err(EINTR);
                }
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
    claim_with(out, flags, false)
}

/// The claim of the stack that starts by itself at the first call of a
/// fast socket: its pause between tries is not ended by a signal (the
/// handler runs, the wait goes on), since the calls it stands in for
/// (`epoll_ctl`, `accept`, `connect`) have no EINTR to give.
pub fn claim_steady(out: &mut FastClaim, flags: u32) -> Result<(), i32> {
    claim_with(out, flags, true)
}

fn claim_with(out: &mut FastClaim, flags: u32, steady: bool) -> Result<(), i32> {
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
                posix_sync::receiver::activate(label);
                break got;
            }
            // No address yet, or no consumer number free yet (a worker that left gives its number
            // back after the sweep has gone over the flows twice): wait and ask again.
            Err((ENETDOWN | EBUSY, _)) if crate::wait::now() < started + ADDRESS_WAIT_NS => {}
            Err((EBUSY, Some(_)))
                if flags & ONCE == 0 && crate::wait::now() < started + BUSY_WAIT_NS => {}
            Err((errno, _)) => return Err(errno),
        }
        pause(crate::wait::now() + RETRY_NS, steady)?;
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

/// `stafeto_fast_attach` kind of the claim it describes.
pub const KIND_PORT: u32 = 3;
/// The switch thread's channel (a copy with NOTIFY alone), raw; 0 before an attach.
static SWITCH: AtomicU64 = AtomicU64::new(0);
/// EAGAIN of `attach`: the service has no switch.
pub const NO_SWITCH: i32 = crate::constants::EAGAIN;

/// The reply of an ATTACH and the switch's channel, or the errno with the status of a refusal.
type Attach = Result<(proto_net::switch::Attached, Option<Handle<Channel>>), (i32, Option<Status>)>;

/// One ATTACH.
fn ask_attach(service: &Handle<Channel>, ring: &Handle<Memory>, label: u64) -> Attach {
    use proto_net::switch as sw;
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
    for h in [copy.erase(), notify.erase()] {
        handles.push(h).map_err(|_| (EIO, None))?;
    }
    let mut w = Writer::new();
    sw::write_attach(sw::Layout::DEFAULT, &mut w).map_err(|_| (EIO, None))?;
    let mut reply = call(service, w.as_bytes(), handles).map_err(|e| {
        dbg(format_args!("fast: ATTACH call failed errno {e}\n"));
        (e, None)
    })?;
    let mut buffer = [0u8; MESSAGE_MAX];
    match sw::Attached::read(reply.bytes(&mut buffer)) {
        Ok(attached) => Ok((attached, reply.handles.take::<Channel>(0).ok())),
        Err(status) => {
            dbg(format_args!("fast: ATTACH refused: {status:?}\n"));
            Err((attach_refusal(status), Some(status)))
        }
    }
}

/// The errno of a refusal of ATTACH.
fn attach_refusal(status: Status) -> i32 {
    match status {
        // A service without the method, or with `switch 0`.
        Status::UnknownMethod => NO_SWITCH,
        Status::Kernel(Error::LimitReached) => EBUSY,
        _ => match status.code() {
            proto_net::INVALID => NO_SWITCH,
            proto_net::NET_DOWN => ENETDOWN,
            _ => refusal(status),
        },
    }
}

/// `stafeto_fast_attach`: the consumer of the service's switch (spec Sh4).
/// The ring object is the process's own (`Layout::DEFAULT`, about 5 MiB of
/// its quota), mapped as a piece of kind `Fast` like the claim's. The
/// channel the service notifies is the thread's, labelled as for a claim,
/// so `wait`, the bank and `lost` serve both. Nothing but the switch's
/// channel (for `poke`) is kept besides.
pub fn attach(out: &mut FastClaim) -> Result<(), i32> {
    use proto_net::switch as sw;
    if claimed() {
        return Err(EBUSY);
    }
    let service = service()?;
    CHANNEL.store(
        threads::own_block().channel.load(Ordering::Relaxed),
        Ordering::Release,
    );
    let layout = sw::Layout::DEFAULT;
    let pages = layout.total() / PAGE;
    let ring = sys::mem_create(layout.total() as u64).map_err(|_| ENOMEM)?;
    let started = crate::wait::now();
    let (attached, switch) = loop {
        let label = FAST_LABEL | (TRY.fetch_add(1, Ordering::Relaxed) & 0xffff_ffff);
        match ask_attach(&service, &ring, label) {
            Ok(got) => {
                posix_sync::receiver::activate(label);
                break got;
            }
            Err((ENETDOWN, _)) if crate::wait::now() < started + ADDRESS_WAIT_NS => {}
            Err((errno, _)) => return Err(errno),
        }
        pause(crate::wait::now() + RETRY_NS, true)?;
    };
    CLAIMED.store(true, Ordering::Release);
    OWN.set_block(
        attached.block_first.min(0xffff) as u16,
        attached.block_count.min(0xffff) as u16,
    );
    SWITCH.store(switch.map_or(0, |h| h.into_raw().0), Ordering::Release);
    *out = FastClaim {
        kind: KIND_PORT,
        pad: 0,
        window: 0,
        window_len: layout.total() as u64,
        objects: [FastObject::default(); wire::OBJECTS],
        ring: 0,
        bar_sizes: [0; 6],
        snapshot: [0; wire::SNAPSHOT_WORDS],
        config: config_of(&attached.config),
    };
    out.snapshot[..7].copy_from_slice(&[
        attached.consumer,
        attached.generation,
        layout.rx_slots,
        layout.tx_slots,
        attached.block_first,
        attached.block_count,
        // Bit 0: the device completes the sums of TCP; bit 1: it cuts frames of TCP (`TX_TSO`).
        u32::from(attached.offload) | u32::from(attached.tso) << 1,
    ]);
    crate::allocation::heap(|state| -> Result<(), i32> {
        out.window = state.map_fast(ring, pages, 0)? as u64;
        Ok(())
    })
}

/// PORT_HOLD of a TCP port for the probes of the switch (`stafeto_fast_port_hold`): the
/// descriptor of the hold; ENOSYS when the service has no switch.
pub fn port_hold(port: u16, reuseport: bool) -> Result<i32, i32> {
    crate::net::port_hold(port, reuseport, 0)?.ok_or(crate::constants::ENOSYS)
}

/// JOIN with the port description `fd` (`stafeto_fast_port_join`).
pub fn port_join(fd: i32) -> Result<(), i32> {
    crate::net::port_join(fd)
}

/// The ports this process's stack owns, which the glue of the stack asks for
/// (`stafeto_fast_own_port`) to tell a packet of the loopback network for its own sockets from one
/// for another stack (`proto_net::switch::OwnPorts`). A forked worker has the words as the master
/// left them (the master holds the ports before it forks).
static OWN: proto_net::switch::OwnPorts = proto_net::switch::OwnPorts::new();

/// Remembers that the description `description` holds `port` for this process's stack.
pub fn note_own_port(port: u16, description: u32) {
    OWN.note(port, description);
}

/// The last close of `description` in this process: the ports it held are no longer own.
pub fn forget_own_ports(description: u32) {
    OWN.forget(description);
}

/// Whether `port` belongs to the stack of this process: a held port, or in its block.
pub fn own_port(port: u16) -> bool {
    OWN.owns(port)
}

/// Whether the process is a consumer of the switch (not an owner of a device).
pub fn port_mode() -> bool {
    SWITCH.load(Ordering::Acquire) != 0
}

/// `stafeto_fast_poke`: tells the switch's thread that frames wait in TX
/// (bit 1 of its channel).
pub fn poke() -> Result<(), i32> {
    match SWITCH.load(Ordering::Acquire) {
        0 => Err(EBADF),
        raw => {
            let channel = Handle::<Channel>::borrowed(rt::abi::Handle(raw));
            sys::notify(&channel, 1).map_err(|_| EIO)
        }
    }
}

/// `stafeto_fast_wait`: the bits of the service's notifications that came,
/// waiting up to `timeout_ns` (0 only looks). The bits a wait of another
/// owner banked come first.
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
    // timer that fired late) are taken off the channel and dropped; those
    // of the active try land in the bank.
    loop {
        // Whatever waits on the channel first, without blocking.
        loop {
            let bits = take_pending();
            if bits != 0 {
                return Ok(bits);
            }
            match try_receive(&own) {
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
        // With the entries deferred no handler can bank a bit from here to
        // `receive`; one that came since the loop above (a handler that
        // waited on this channel) is in the bank and would otherwise sleep
        // until the deadline.
        let bits = take_pending();
        if bits != 0 {
            drop(guard);
            let _ = sys::timer_cancel(&timer);
            return Ok(bits);
        }
        let got = receive(&own);
        drop(guard);
        match got {
            Ok(_) => {
                let bits = take_pending();
                if bits != 0 {
                    let _ = sys::timer_cancel(&timer);
                    return Ok(bits);
                }
            }
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

/// A line on standard error (a diagnostic of the start of the stack).
pub(crate) fn dbg(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;
    struct Line([u8; 120], usize);
    impl Write for Line {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.0.len() - self.1);
            self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
            self.1 += n;
            Ok(())
        }
    }
    let mut line = Line([0; 120], 0);
    let _ = line.write_fmt(args);
    let _ = crate::write(2, &line.0[..line.1]);
}
