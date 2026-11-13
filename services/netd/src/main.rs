// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The network service of stafeto (spec 6): its own driver of the Virtio
//! network device on a virtio-mmio transport (Virtio 1.2, 5.1) and the
//! smoltcp stack over it, with DHCP (or the static address of
//! `/etc/netd.conf`), ARP and the answer to ICMP echo. CONFIG tells the
//! interface's address; the sockets' methods of proto_net serve TCP and UDP
//! over IPv4, with a loopback inside the one interface (`net.rs`,
//! `calls.rs`); a build with the feature `probe` adds PING (an echo request
//! to an address, for the network probe) and CRASH.
//!
//! The device is `net` of init's table: two DMA objects (`dma`, the pages
//! of the two queues, and `net`, 512 buffers of 2 KiB for the frames), the
//! window `mmio` and the binding `irq`. The service is in the trusted base:
//! the device writes where the queues tell it (spec 9, no SMMU). Init
//! stops the device (Status 0) before it lets the objects of an instance
//! go.
//!
//! The service has three threads (`switch.rs`, `instance.rs`). The first one builds the
//! service and then waits. The switch thread, one level above the stack on the CPU of the
//! line, owns the device's transport, queues, doorbells and binding; the thread of the stack
//! instance, described below, is its internal consumer, and they pass the numbers of the
//! device's buffers in rings, with no copy. The text below tells the steps of the stack as they were
//! before the split, with the queue of the device replaced by those rings.
//!
//! The service never waits for the device. An interrupt (or the service's
//! own notification STEP, or its timer) starts a step: the used buffers of
//! sending come back, the stack takes the frames of the loopback and then of
//! the wire (`ring::STEP_RX` at most) and sends in one pass over its
//! sockets (`ring::STEP_TX` frames at most), the operations that wait are
//! told, the buffers of receiving go back to the queue, and the timer is set
//! for the stack's next deadline. A step that left frames behind notifies
//! the service again and keeps the line closed, and asks the device for no
//! interrupt meanwhile; otherwise the line opens again (irq_ack) with the
//! source cleared. The doorbells ring once for a run of steps, when it ends
//! (`doorbells`): a ring is an exit from the guest. A
//! call of a socket never runs the stack: it changes the buffers of one
//! socket and asks for a step.
//!
//! The key of the stack comes from the entropy service and the address
//! settings from the file service, both before the service registers with
//! init, so that a wait for either is not counted against the heartbeat.
//! The program ends with a code of its own when its start fails, and init
//! starts it again.

#![no_std]
#![no_main]

mod calls;
mod cells;
mod consumers;
mod device;
mod dma;
mod ena_service;
mod ena_switch;
mod fast;
mod files;
mod instance;
#[cfg(feature = "trace")]
mod kdump;
mod msix;
mod net;
mod owner;
mod second;
mod seed;
mod split;
mod stack;
mod switch;

use abi::{Access, Rights, Source};
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use device::{DEVICE, NetDevice, RxRing, TxRing};
use instance::Instance;
use net::{Client, Net, SESSIONS, now_ns};
use netd::config::Settings;
use netd::home::BUILT;
use netd::lines::Mac;
use netd::profile::{self, Counter};
use netd::published;
use netd::switchlogic::tables::MAX_INSTANCES;

/// The points of the packet path (lib/trace, the feature `trace`): without the feature `netd`
/// does not link the crate and every call below is empty, so the normal image has no trace.
#[cfg(feature = "trace")]
pub(crate) use ::trace;
#[cfg(not(feature = "trace"))]
#[allow(dead_code)]
pub(crate) mod trace {
    macro_rules! points {
        ($($n:ident),*) => {$(pub const $n: u8 = 0;)*};
    }
    points!(
        P_N_BELL,
        P_N_BELL_SKIP,
        P_N_CSKIP,
        P_N_CWAKE,
        P_N_RX,
        P_N_STEP,
        P_N_STK_TX,
        P_N_TO_CONSUMER,
        P_N_TO_STACK,
        P_N_TX_SEEN,
        P_N_TX_SUBMIT,
        P_N_WAKE,
        P_N_WAKE_STACK,
        P_N_REQ_BEGIN,
        P_N_REQ_END,
        P_N_IRQ1,
        P_N_STK_BEGIN,
        P_N_STK_END
    );
    #[inline(always)]
    pub fn point(_: u8, _: u32) {}
    #[inline(always)]
    pub fn frame(_: u8, _: &[u8], _: bool) {}
}
use crate::trace::{P_N_IRQ1, P_N_REQ_BEGIN, P_N_REQ_END, P_N_STK_BEGIN, P_N_STK_END};
use netd::resolv::{Text, Written};
use netd::ring::{Budget, NET_PAGES, QUEUE_SIZE};
use proto_init::ServiceArgs;
use proto_net::sockets;
use proto_net::{Method, VERSION, code};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Process, Resource, Timer};
use rt::service::{
    Answer, Config, Heartbeat, LongSession, Notice, Pending, Request, Service, Session,
};
use rt::{Handle, sys};
use second::Second;
use smoltcp::iface::SocketStorage;
use stack::{Event, PingEnd, Stack, Storage};
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::SomeTransport;
use virtio_mmio::PAGE;
use virtio_net::open::{MAC, MTU, OFFLOAD, STATUS, TSO};
use virtio_net::transport::{self, Function, OpenError};
use virtio_net::{OpenFailure, Opened};
use virtio_pci::qemu;

rt::entry!(main);

/// The bits of the service's notification to itself, each a step of its own:
/// receiving, sending (also asked by a request), the departure of a session,
/// the waking of operations, the sweep of the streams that close, and the
/// write of `/etc/resolv.conf`.
const RX: u64 = 16;
const TX: u64 = 1;
const CLEANUP: u64 = 2;
const WAKE: u64 = 4;
const SWEEP: u64 = 8;
const RESOLV: u64 = 32;
/// The second device's step of receiving (second.rs).
const RX1: u64 = 64;
/// A step of the second device's return from its owner (owner.rs).
const RETURN: u64 = 128;
/// The switch thread has answers for the stack (`switch::COMMANDS`).
pub(crate) const BACK: u64 = 256;
/// The map of a shared buffer a BUFFER waits for (`Net::map_waiting`).
const MAP: u64 = 512;
const STEP_BITS: u64 = RX | RX1 | TX | CLEANUP | WAKE | SWEEP | RESOLV | RETURN | BACK | MAP;
/// The label of the service's timer.
const TIMER_LABEL: u64 = 1;
/// The label of the sweep's timer on the switch thread's channel.
const SWEEP_LABEL: u64 = 2;
/// The objects of the second device in the start data of a record of two
/// devices, after `dma` and `net`: the pages of its queues and four objects
/// of 4 MiB of buffers.
const SECOND_OBJECTS: [&str; 5] = ["dma1", "net1a", "net1b", "net1c", "net1d"];
/// The device's queues: `receiveq` and `transmitq` (Virtio 1.2, 5.1.2).
pub(crate) const RECEIVEQ: u16 = 0;
pub(crate) const TRANSMITQ: u16 = 1;
/// The features the service asks for (`virtio_net::open`):
/// `VIRTIO_F_VERSION_1`, `VIRTIO_NET_F_MTU`, `VIRTIO_NET_F_MAC` and
/// `VIRTIO_NET_F_STATUS`. The checksum offload is added by `start_device` when
/// the device takes it (`virtio_net::open_offload`), the segmentation offload
/// when the service has the 64 KiB tails of the receiving chains it needs; no
/// merged buffers, no control queue (Virtio 1.2, 5.1.3). Apple's device
/// clears `FEATURES_OK` for any set without MTU.
const WANTED: u64 = MTU | MAC | STATUS;
/// The least MTU the service starts on: the IP packet of a full frame.
const MTU_MIN: u16 = 1500;

/// The codes of a start that failed: the start data or an object; the
/// entropy service; REGISTER, the window or the binding; a map; no network
/// device at the transport; the device refused the driver; the file
/// `netd.conf`.
const NO_START_DATA: u64 = 1;
const NO_ENTROPY: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;
const NO_DEVICE: u64 = 6;
const NOT_STARTED: u64 = 7;
const NO_CONFIG: u64 = 9;
/// The common configuration of a PCI device lies elsewhere than at the
/// start of BAR 0.
const CONFIG_ELSEWHERE: u64 = 10;

/// The tables of the service in `.bss`, too big for the stack: the sockets
/// with their buffers (`net`), the storage of the smoltcp sockets, the table
/// of sessions and the frames of the loopback. They are filled in place at
/// the start (`Net::initialize_at`); nothing in them is touched before a
/// socket needs it.
struct Tables {
    /// The tables of each stack instance the build has room for (`netd::home::BUILT`).
    nets: [Net; BUILT],
    storages: [Storage<'static>; BUILT],
    sessions: [[Option<Session<Client, 0>>; SESSIONS]; BUILT],
    /// The second device, once `Second::start_at` built it, and its one
    /// socket's storage.
    second: core::mem::MaybeUninit<Second>,
    second_storage: second::Storage,
}
struct Bss(UnsafeCell<core::mem::MaybeUninit<Tables>>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(core::mem::MaybeUninit::zeroed()));

/// The heap the device's crate may ask for: none (the queues have no
/// indirect entries, the only thing of the crate that allocates).
struct NoHeap;

#[global_allocator]
static ALLOCATOR: NoHeap = NoHeap;

// SAFETY: every allocation fails with a null pointer, which the contract
// allows; nothing is ever handed out to come back.
unsafe impl GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

/// The first 8 bytes of `own` from `at`, little-endian; 0 without them.
fn word(own: &[u8], at: usize) -> u64 {
    own.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// 16 bytes for the table of destinations from the key of the ports and 8
/// bytes more of the entropy service's key: two SipHash-2-4 values of them.
#[allow(deprecated)] // SipHasher is in core and has no replacement there.
fn demux_secret(ports_key: &[u8; 16], tail: &[u8]) -> [u8; 16] {
    use core::hash::{Hasher, SipHasher};
    let k0 = u64::from_le_bytes(ports_key[..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(ports_key[8..].try_into().expect("8 bytes"));
    let mut out = [0u8; 16];
    for (n, half) in out.chunks_mut(8).enumerate() {
        let mut hash = SipHasher::new_with_keys(k0, k1);
        hash.write(b"demux");
        hash.write(&[n as u8]);
        hash.write(tail);
        half.copy_from_slice(&hash.finish().to_le_bytes());
    }
    out
}

fn main(_: u64) -> u64 {
    #[cfg(feature = "trace")]
    ::trace::set_frequency(rt::time::frequency());
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    // A record with an ENA device holds the object `ena` and runs the driver
    // of the second kind of device (ena_service.rs).
    if let Ok(object) = s.take::<Memory>("ena") {
        return ena_service::run(s, object);
    }
    #[cfg(feature = "trace")]
    let kernel_stamps = s.take::<Resource>("trace").ok();
    let (Ok(dma_object), Ok(net_object)) = (s.take::<Memory>("dma"), s.take::<Memory>("net"))
    else {
        return NO_START_DATA;
    };
    // The tails of the chains of receiving (4 MiB), for a device that merges the segments it
    // receives: only the record `NETD_VZ_TSO` has them (the image that says `tso 1`); a service
    // without them keeps the pair of sums whatever netd.conf says.
    let tails_object = s.take::<Memory>("tails").ok();
    // The record of two devices gives the second device objects of its own
    // (init's table): the service drives it on `dma1` and the first
    // megabyte of `net1a`, and keeps the others.
    let second_objects = SECOND_OBJECTS.map(|name| s.take::<Memory>(name).ok());
    let objects = if second_objects.iter().all(Option::is_some) {
        2 + SECOND_OBJECTS.len()
    } else {
        2 + usize::from(tails_object.is_some())
    };
    let args = ServiceArgs::read(s.args()).ok();
    // The own arguments: the physical addresses of the objects, which init
    // puts first in their order, then the record's, where the transports
    // are: the second device's transport or function is 0 without one.
    let own = args.map_or(&[][..], |a| a.own);
    let (dma_pa, net_pa) = (word(own, 0), word(own, 8));
    let (dma1_pa, net1_pa) = (word(own, 16), word(own, 24));
    let tails_pa = if tails_object.is_some() && objects == 3 {
        word(own, 16)
    } else {
        0
    };
    let second_pas: [u64; 5] = core::array::from_fn(|i| word(own, 16 + 8 * i));
    // The size of each object as the kernel has it: the owner maps what is
    // there, whatever init's table says.
    let second_pages: [u32; 5] = core::array::from_fn(|i| {
        second_objects[i]
            .as_ref()
            .and_then(|o| sys::memory_info(o).ok())
            .map_or(0, |info| (info.size / PAGE as u64) as u32)
    });
    let (at, at1) = (word(own, 8 * objects), word(own, 8 * objects + 8));
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return NOT_REGISTERED;
    };

    // The timer of the service, made before anything is waited for: it ends
    // the wait for the key, and after REGISTER it serves the deadlines of the
    // stack.
    let Ok(notify) = sys::handle_duplicate(&channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    let Ok(view) = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };
    // The switch thread's channel, one level above the stack's: the line's
    // interrupts come to it (init binds the first line through it) and the
    // stack's notifications. The stack's copy with NOTIFY is for the
    // stack to wake it.
    let Ok(switch_channel) = sys::channel_create(level + 1) else {
        return NOT_REGISTERED;
    };
    let Ok(wake_switch) = sys::handle_duplicate(&switch_channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };

    // The key of the stack: its first 8 bytes seed the stack, the next 16
    // are the secret of the choice of ports (RFC 6056), and the rest is
    // erased.
    let Ok(entropy) = rt::service::connect(&s.parent, "entropy") else {
        return NO_ENTROPY;
    };
    let mut key = match seed::take(&entropy, &channel, level, (&timer, TIMER_LABEL)) {
        Ok(key) => key,
        Err(failure) => {
            match failure {
                seed::Failure::Gone => {
                    rt::println!("net: no key from the entropy service (gone)")
                }
                seed::Failure::Timeout => {
                    rt::println!("net: no key from the entropy service (timeout)")
                }
                seed::Failure::Refused(status) => {
                    rt::println!("net: no key from the entropy service ({status:?})")
                }
            }
            return NO_ENTROPY;
        }
    };
    let mut first = [0; 8];
    first.copy_from_slice(&key[..8]);
    let random_seed = u64::from_le_bytes(first);
    let mut ports_key = [0; 16];
    ports_key.copy_from_slice(&key[8..24]);
    // The secret of the table of destinations: a hash of the key of the ports
    // and the rest of the key.
    let demux_key = demux_secret(&ports_key, &key[24..32]);
    // The secret of the switch's table of flows, apart from the first.
    let flows_key = demux_secret(&ports_key, b"switch-flows");
    posix_random::erase(&mut key);
    drop(entropy);

    let settings = match files::read(&s.parent) {
        Ok(settings) => settings,
        Err(files::Failure::Refused(error)) => {
            rt::println!(
                "net: netd.conf line {}: {}",
                error.line,
                error.reason.text()
            );
            return NO_CONFIG;
        }
        Err(files::Failure::Unreadable(error)) => {
            rt::println!("net: netd.conf unreadable: {error:?}");
            return NO_CONFIG;
        }
    };

    let Ok(mut got) = rt::service::register_with(&s.parent, &channel, Some(&switch_channel)) else {
        return NOT_REGISTERED;
    };
    let Ok(irq) = got.take::<Interrupt>("irq") else {
        return NOT_REGISTERED;
    };
    // The record of two devices has a second binding; the record of QEMU's
    // machine with an ITS has one binding a queue, `irq` for receiving and
    // `irqtx` for sending, each an event of the function's MSI device
    // (init's table, `NETD_ITS`).
    let irq1 = got.take::<Interrupt>("irq1").ok();
    let irq_tx = got.take::<Interrupt>("irqtx").ok();
    let msi = irq_tx.is_some();
    let devices = 1 + usize::from(irq1.is_some());

    // One stack instance for each CPU of the service's mask, up to the file's limit: the
    // instance k runs on the k-th CPU (`netd::home`). The instances after the first have a
    // channel and a timer of their own; sessions reach them through HOME.
    // Where the service has the switch or a second device, every session stays on the first
    // instance (the methods of both are its alone, `home`), so one instance starts. A stopgap:
    // the forwarding of ATTACH, CLAIM, PORT_HOLD and JOIN to the first instance, which lets the
    // others serve sockets in such images, belongs to P3 (deferred to the ENA work).
    let (cpus, instances, mut extra) = match plan_instances(&settings, devices > 1, level) {
        Ok(plan) => plan,
        Err(code) => return code,
    };

    let rw = Access::ReadWrite;
    let page = PAGE as u64;
    // QEMU's transports, or VZ's functions and their Virtio structures.
    let mut windows: [Option<Handle<Memory>>; 3] = [None, None, None];
    let pci = if let Ok(window) = got.take::<Memory>("mmio") {
        if sys::mem_map(&s.process, &window, 0, page, dma::mmio_at(DEVICE), rw).is_err() {
            return NOT_MAPPED;
        }
        windows[0] = Some(window);
        if devices == 2 {
            let Ok(window) = got.take::<Memory>("mmio1") else {
                return NOT_REGISTERED;
            };
            if sys::mem_map(&s.process, &window, 0, page, dma::mmio_at(1), rw).is_err() {
                return NOT_MAPPED;
            }
            windows[2] = Some(window);
        }
        false
    } else {
        let (Ok(ecam), Ok(bar)) = (got.take::<Memory>("ecam"), got.take::<Memory>("bar")) else {
            return NOT_REGISTERED;
        };
        let (ecam_len, bar_len) = if msi {
            (page, qemu::NET.len + qemu::NET_MSIX_LEN)
        } else {
            (
                netd::pci::ecam_window(devices).1,
                netd::pci::bar_window(devices).1,
            )
        };
        if sys::mem_map(&s.process, &ecam, 0, ecam_len, dma::ecam_at(), rw).is_err()
            || sys::mem_map(&s.process, &bar, 0, bar_len, dma::bar_at(), rw).is_err()
        {
            return NOT_MAPPED;
        }
        windows[0] = Some(ecam);
        windows[1] = Some(bar);
        true
    };
    // Each device has its pages of the queues (`dma`, `dma1`) and its 512
    // buffers (`net`, the first megabyte of `net1a`).
    let dma_len = dma::DMA_PAGES as u64 * page;
    let net_len = NET_PAGES as u64 * page;
    let [dma1_object, net1_object, ..] = &second_objects;
    let maps = [
        (Some(&dma_object), dma_pa, Some(&net_object), net_pa),
        (dma1_object.as_ref(), dma1_pa, net1_object.as_ref(), net1_pa),
    ];
    for (d, &(dma_object, dma_pa, net_object, net_pa)) in maps.iter().enumerate().take(devices) {
        let (Some(dma_object), Some(net_object)) = (dma_object, net_object) else {
            return NOT_MAPPED;
        };
        if dma_pa == 0
            || net_pa == 0
            || sys::mem_map(&s.process, dma_object, 0, dma_len, dma::dma_at(d), rw).is_err()
            || sys::mem_map(&s.process, net_object, 0, net_len, dma::net_at(d), rw).is_err()
            || !dma::attach(d, dma_pa, net_pa)
        {
            return NOT_MAPPED;
        }
    }
    let (mut transport, status) = match open_device(pci, msi, DEVICE, at) {
        Ok(found) => found,
        Err(code) => return code,
    };
    let opened = match start_device(
        &mut transport,
        "virtio-net",
        true,
        tails_pa != 0 && settings.tso(),
    ) {
        Ok(opened) => opened,
        Err(code) => return code,
    };
    let (mac, link) = (opened.mac, opened.link);
    let offload = opened.features & OFFLOAD == OFFLOAD;
    // The device that took the four bits of segmentation merges segments into frames of up to
    // 64 KiB: its ring of receiving is chains of a head and a tail.
    let tso = opened.features & TSO == TSO;
    let tails_mapped = !tso
        || tails_object.as_ref().is_some_and(|object| {
            sys::mem_map(
                &s.process,
                object,
                0,
                netd::ring::TAIL_PAGES as u64 * page,
                dma::TAILS_AT,
                rw,
            )
            .is_ok()
                && dma::attach_tails(DEVICE, dma_pa, net_pa, tails_pa)
        });
    if !tails_mapped {
        return NOT_MAPPED;
    }
    rt::println!(
        "net-offload: features {:#x}, checksum offload {}, segmentation offload {}",
        opened.features,
        if offload { "on" } else { "off" },
        if tso { "on" } else { "off" }
    );
    type Q = VirtQueue<dma::Host<DEVICE>, QUEUE_SIZE>;
    let Ok(rx_queue) = Q::new(&mut transport, RECEIVEQ, false, false) else {
        return NOT_STARTED;
    };
    let Ok(tx_queue) = Q::new(&mut transport, TRANSMITQ, false, false) else {
        return NOT_STARTED;
    };
    if let Some(irq_tx) = &irq_tx
        && let Err(why) = msix::set_up([&irq, irq_tx])
    {
        rt::println!("virtio-net: MSI-X: {why}");
        return NOT_STARTED;
    }
    // SAFETY: only this thread reaches TABLES, here once; the pointer is to
    // zeroed memory of the static.
    let tables = unsafe {
        let pointer = (*TABLES.0.get()).as_mut_ptr();
        let mut channels: [&Handle<Channel>; MAX_INSTANCES] = [&channel; MAX_INSTANCES];
        for (k, slot) in extra.iter().enumerate().take(instances).skip(1) {
            channels[k] = &slot.as_ref().expect("made above").channel;
        }
        Tables::initialize_at(
            pointer,
            ports_key,
            demux_key,
            (&s.parent, &channels[..instances], &s.process),
            level,
            settings.buffers(),
            cpus,
        );
        &mut *pointer
    };
    posix_random::erase(&mut ports_key);
    let Tables {
        nets,
        storages,
        sessions,
        second,
        second_storage,
    } = tables;
    let lane = &switch::INNER.lanes[netd::switchlogic::route::DEFAULT_INSTANCE];
    let mut device = NetDevice::new(RxRing::inner(lane), TxRing::inner(lane), mac);
    let line = sys::irq_info(&irq).map_or(0, |info| info.line);
    // The switch's tables and the timer of their sweep, when the file asks for consumers.
    let (switch_tables, sweep_timer) = match make_switch_tables(
        &s.process,
        &switch_channel,
        mac,
        flows_key,
        &settings,
        level + 1,
        instances,
    ) {
        Ok(made) => made,
        Err(code) => return code,
    };
    let gate = (settings.consumers() > 0)
        .then(|| {
            sys::handle_duplicate(
                &switch_channel,
                Rights(Rights::NOTIFY.0 | Rights::DUPLICATE.0 | Rights::TRANSFER.0),
            )
            .ok()
        })
        .flatten();
    let mut switch = switch::Switch::new(
        transport,
        rx_queue,
        tx_queue,
        irq,
        switch_channel,
        link,
        (offload, tso),
        (switch_tables, sweep_timer.0, sweep_timer.1),
        instances,
    );
    if let Some(irq_tx) = irq_tx {
        switch.vectors(irq_tx);
        rt::println!(
            "virtio-net: 1af4:1041 at {at:#x}, msi-x 2 vectors, status {status:#x}, mac {}",
            Mac(mac)
        );
    } else if pci {
        rt::println!(
            "virtio-net: 1af4:1041 at {at:#x}, line {line}, status {status:#x}, mac {}",
            Mac(mac)
        );
    } else {
        rt::println!(
            "virtio-net: virtio-mmio at {at:#x}, line {line}, status {status:#x}, mac {}",
            Mac(mac)
        );
    }
    if !link {
        rt::println!("virtio-net: link down");
    }
    if !mtu_fits(&opened, "virtio-net") {
        return NOT_STARTED;
    }
    // The second device, if the record has one.
    let second = match irq1 {
        Some(irq1) => {
            let started = start_second(
                pci,
                at1,
                irq1,
                second,
                second_storage,
                &settings,
                random_seed,
                (dma1_pa, net1_pa),
            );
            match started {
                Ok(second) => Some(second),
                Err(code) => return code,
            }
        }
        None => None,
    };

    let now = now_ns();
    let mut storages = storages.iter_mut();
    let mut nets = nets.iter_mut();
    let mut session_tables = sessions.iter_mut();
    let (storage0, net0) = (
        storages.next().expect("one instance"),
        nets.next().expect("one instance"),
    );
    let mut stack = Stack::new(
        storage0,
        &mut device,
        mac,
        random_seed,
        now,
        settings.address.is_none(),
    );
    announce_static(&mut stack, &settings);
    net0.external = stack.lease.map(|lease| lease.address);
    let (own, own_count) = stack.addresses();
    device.set_addresses(&own[..own_count]);
    device.seed_neighbours();
    // The address of the first instance is the service's: the others take it from here.
    published::ADDRESS.publish(stack::record_of(stack.lease).as_ref());
    // The lanes know the channels of their instances before the switch starts: it wakes
    // them through these.
    switch::INNER.lanes[0].set_stack_channel(notify.raw().0);
    for (k, slot) in extra.iter().enumerate().take(instances).skip(1) {
        switch::INNER.lanes[k].set_stack_channel(slot.as_ref().expect("made").notify.raw().0);
    }
    // The switch thread starts now: the stack and its tables are built, and
    // from here the device is the switch's.
    let Ok(switch_thread) = switch::start(switch, &s.process, level + 1, &wake_switch) else {
        return NOT_STARTED;
    };
    let mut driver0 = Driver::new(
        Instance::new(lane, device, stack, net0),
        0,
        notify,
        timer,
        view,
        mac,
        netd::books::AddressSync::new(),
        consumers::Side::new(settings.consumers(), gate, consumers::GATE_PRIORITY),
        #[cfg(feature = "trace")]
        kdump::KernelDump::new(kernel_stamps),
    );
    driver0.pause = make_pause(level);
    driver0.cpus = cpus;
    driver0.instances = instances;
    driver0.routed = settings.consumers() > 0 || instances > 1;
    driver0.second = second;
    driver0.claimable = owner::Claimable {
        handover: settings.handover == Some(true),
        pci,
        at: at1,
        objects: second_pas,
        pages: second_pages,
    };
    driver0.switch = Some((switch_thread, wake_switch));
    driver0.maps = Some(Maps {
        _dma: dma_object,
        _net: net_object,
        _tails: tails_object,
        windows,
        second: second_objects,
    });
    // The handles with which the first instance asks the others for sessions (HOME).
    for (k, slot) in extra.iter_mut().enumerate().take(instances).skip(1) {
        driver0.homes[k] = slot.as_mut().and_then(|e| e.home.take());
    }
    let mut free_slots = DRIVERS.fill().iter_mut();
    let mut placed: [Option<&'static mut Driver<'static>>; MAX_INSTANCES] =
        [const { None }; MAX_INSTANCES];
    placed[0] = Some(free_slots.next().expect("a slot").write(driver0));
    // The channels of the instances after the first, which their loops serve for the life of
    // the service.
    let mut held_channels: [Option<Handle<Channel>>; MAX_INSTANCES] =
        [const { None }; MAX_INSTANCES];
    for (k, slot) in extra.iter_mut().enumerate().take(instances).skip(1) {
        let made = slot.take().expect("made");
        held_channels[k] = Some(made.channel);
        let lane = &switch::INNER.lanes[k];
        let mut device = NetDevice::new(RxRing::inner(lane), TxRing::inner(lane), mac);
        let stack = Stack::new(
            storages.next().expect("an instance has storage"),
            &mut device,
            mac,
            random_seed.wrapping_add(k as u64),
            now,
            false,
        );
        let net = nets.next().expect("an instance has tables");
        let mut driver = Driver::new(
            Instance::new(lane, device, stack, net),
            k,
            made.notify,
            made.timer,
            made.view,
            mac,
            netd::books::AddressSync::new(),
            consumers::Side::new(0, None, consumers::GATE_PRIORITY),
            #[cfg(feature = "trace")]
            kdump::KernelDump::new(None),
        );
        driver.pause = make_pause(level);
        driver.cpus = cpus;
        driver.instances = instances;
        driver.routed = true;
        placed[k] = Some(
            free_slots
                .next()
                .expect("a slot for an instance")
                .write(driver),
        );
    }
    let mut launches: [Option<instance::Launch<'_, Driver<'static>>>; MAX_INSTANCES] =
        [const { None }; MAX_INSTANCES];
    for (k, (launch, driver)) in launches
        .iter_mut()
        .zip(placed.iter_mut())
        .enumerate()
        .take(instances)
    {
        let driver = driver.take().expect("made");
        let sessions = session_tables.next().expect("an instance has its sessions");
        // Each instance serves its own channel; the first is the one init knows, and the
        // only one that tells init it lives.
        let channel_k = if k == 0 {
            &channel
        } else {
            held_channels[k].as_ref().expect("made")
        };
        *launch = Some(instance::Launch {
            driver,
            channel: channel_k,
            config: Some(Config {
                issued: 0,
                heartbeat: (k == 0).then(|| Heartbeat {
                    to: &s.parent,
                    period_ns: args.map_or(0, |a| a.period_ns),
                    priority: level,
                }),
            }),
            sessions,
            entry: instance_entry,
        });
    }
    // The loops of the instances run in threads of their own, each on its CPU (the first on
    // the CPU of this thread); this thread has nothing more to do.
    for (k, launch) in launches.iter_mut().enumerate().take(instances) {
        let cpu = (k > 0).then(|| netd::home::cpu_of(cpus, k)).flatten();
        let launch = launch.as_mut().expect("made");
        if instance::start(launch, &s.process, level, k, cpu).is_err() {
            return NOT_STARTED;
        }
    }
    instance::wait_forever(level)
}

/// The places of the instances' drivers, in `.bss`: each is about 33 KB, too much for the first
/// thread's stack four times over, and they live as long as the service.
struct DriverSlots(UnsafeCell<[core::mem::MaybeUninit<Driver<'static>>; MAX_INSTANCES]>);
// SAFETY: filled by the first thread before the threads of the instances start, then each
// driver is its instance's thread's alone.
unsafe impl Sync for DriverSlots {}
static DRIVERS: DriverSlots = DriverSlots(UnsafeCell::new(
    [const { core::mem::MaybeUninit::uninit() }; MAX_INSTANCES],
));

impl DriverSlots {
    /// The slots, once, by the first thread.
    #[allow(clippy::mut_from_ref)]
    fn fill(
        &'static self,
    ) -> &'static mut [core::mem::MaybeUninit<Driver<'static>>; MAX_INSTANCES] {
        // SAFETY: called once, before any thread of an instance exists.
        unsafe { &mut *self.0.get() }
    }
}

/// The first steps of the instance and its loop, on its thread (`instance::start`).
fn instance_entry(launch: &mut instance::Launch<'_, Driver<'_>>) -> u64 {
    let driver = &mut *launch.driver;
    #[cfg(any(feature = "probe", feature = "profile"))]
    {
        driver.own = sys::self_thread().ok();
    }
    if driver.switch_address() {
        driver.tell(BACK);
    }
    // The static address names its servers at once; a lease does in its event.
    if driver.index == 0 && driver.inst.stack.lease.is_some() {
        driver.tell(RESOLV);
    }
    // The first step starts the DHCP client.
    driver.rx_step();
    driver.tx_step(false);
    driver.rx1_step(false);
    #[cfg(feature = "steps")]
    rt::service::report_steps(14);
    let config = launch.config.take().expect("the loop starts once");
    let _ = rt::service::run_in(launch.channel, driver, config, &mut *launch.sessions);
    STOPPED
}

/// The memory of the port table, 2 x 65 536 bytes of `.bss` the switch thread writes.
struct PortBytes(UnsafeCell<[u8; 2 * 65536]>);
// SAFETY: written by the switch thread alone after the start; the stack thread reads single
// bytes (`switch::turn_wanted`).
unsafe impl Sync for PortBytes {}
static PORT_BYTES: PortBytes = PortBytes(UnsafeCell::new([0; 2 * 65536]));

struct ParkBytes(
    UnsafeCell<[netd::switchlogic::tables::ParkSlot; netd::switchlogic::tables::PARK_SLOTS]>,
);
// SAFETY: written by the switch thread alone after the start.
unsafe impl Sync for ParkBytes {}
static PARKED_SYNS: ParkBytes = ParkBytes(UnsafeCell::new(
    [netd::switchlogic::tables::ParkSlot::EMPTY; netd::switchlogic::tables::PARK_SLOTS],
));

/// The tables of the switch (the port table, and the flow table in an object of its own
/// that the service's quota pays for) and the timer of the sweep on the switch thread's
/// channel; none without `switch N`.
type SweepTimer = (Handle<Timer>, Handle<Channel>);
fn make_switch_tables(
    process: &Handle<Process>,
    channel: &Handle<Channel>,
    mac: [u8; 6],
    secret: [u8; 16],
    settings: &Settings,
    level: u8,
    instances: usize,
) -> Result<
    (
        Option<netd::switchlogic::tables::Tables<'static>>,
        SweepTimer,
    ),
    u64,
> {
    use netd::switchlogic::tables::{Flow, Flows, Own, Tables};
    let Ok(view) = sys::handle_label(channel, Rights::RECEIVE, SWEEP_LABEL, level) else {
        return Err(NOT_REGISTERED);
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return Err(NOT_REGISTERED);
    };
    // One instance and no consumers: the stack sees every frame, and no table is needed.
    if settings.consumers() == 0 && instances == 1 {
        return Ok((None, (timer, view)));
    }
    // Instances alone make no flows (they hold ports, and the ports tell whose a frame is): a
    // small table serves the day a group of ports gives them some.
    let flows = if settings.consumers() == 0 {
        netd::config::FLOWS_RANGE.0
    } else {
        settings.flows()
    };
    let places = flows as usize * 2;
    let bytes = (places * core::mem::size_of::<Flow>()).div_ceil(PAGE) * PAGE;
    let Ok(object) = sys::mem_create(bytes as u64) else {
        return Err(NOT_MAPPED);
    };
    if sys::mem_map(
        process,
        &object,
        0,
        bytes as u64,
        dma::FLOWS_AT,
        Access::ReadWrite,
    )
    .is_err()
    {
        return Err(NOT_MAPPED);
    }
    // The mapping keeps the object.
    drop(object);
    // SAFETY: the object is mapped read and write at FLOWS_AT for `places` flows, zeroed, and
    // belongs to the tables from here; the port bytes are the table's alone (the stack
    // thread reads single bytes of them).
    let (slots, ports) = unsafe {
        (
            core::slice::from_raw_parts_mut(dma::FLOWS_AT as *mut Flow, places),
            &mut *PORT_BYTES.0.get(),
        )
    };
    let own = Own {
        ip: [0; 4],
        mac,
        prefix: 0,
    };
    let mut tables = Tables::new(own, ports, Flows::new(slots, &secret), switch::tag);
    // SAFETY: the park belongs to the tables from here.
    tables.set_park(unsafe { &mut *PARKED_SYNS.0.get() });
    // The stack instances are consumers of the switch too, from its first step: they take the
    // frames the tables name for them through their lanes. They send from the whole ephemeral
    // range and hold their ports in the claims all of them share, which the tables read.
    tables.set_claims(&netd::ports::CLAIMS);
    for k in 0..instances {
        assert!(
            tables.attach_instance(k, None).is_some(),
            "an instance has its place"
        );
    }
    Ok((Some(tables), (timer, view)))
}

/// The device on `transport` reset, its features negotiated (WANTED), its MAC
/// address and link status read (`virtio_net::open`); says why on failure
/// and gives the code the service ends with.
///
/// With `offload` the checksum offload is asked for and kept when the device takes it
/// (`virtio_net::open_offload`), with `tso` the segmentation offload too (the driver has the
/// tails of the chains of receiving it needs); the second device and its owner's frames keep
/// their sums in software.
fn start_device(
    transport: &mut SomeTransport<'static>,
    tag: &str,
    offload: bool,
    tso: bool,
) -> Result<Opened, u64> {
    let started = if offload {
        virtio_net::open_offload(transport, WANTED, tso)
    } else {
        virtio_net::open(transport, WANTED)
    };
    match started {
        Ok(opened) => Ok(opened),
        Err(OpenFailure::Reset | OpenFailure::Config) => Err(NOT_STARTED),
        Err(OpenFailure::Features { offered }) => {
            rt::println!("{tag}: features refused, offered {offered:#x}");
            Err(NOT_STARTED)
        }
        Err(OpenFailure::NoMac) => {
            rt::println!("{tag}: the device offers no MAC address");
            Err(NO_DEVICE)
        }
    }
}

/// Whether the device's MTU, if it was negotiated, takes the frames the
/// service builds (MTU_MIN): a driver sends no frame longer than the MTU
/// (Virtio 1.2, 5.1.4.1), and the service's interface is made for 1 500. Says
/// the value on the way.
fn mtu_fits(opened: &Opened, tag: &str) -> bool {
    let Some(mtu) = opened.mtu else {
        return true;
    };
    if mtu < MTU_MIN {
        rt::println!("{tag}: mtu {mtu} below {MTU_MIN}");
        return false;
    }
    rt::println!("{tag}: mtu {mtu}");
    true
}

/// The transport of the network device `device` (0 or 1) at `at`, with the
/// status it had before the service's reset; says why on failure and gives
/// the code the service ends with.
fn open_device(
    pci: bool,
    msi: bool,
    device: usize,
    at: u64,
) -> Result<(SomeTransport<'static>, u32), u64> {
    let tag = if device == DEVICE {
        "virtio-net"
    } else {
        "virtio-net1"
    };
    if pci {
        let opened = match device {
            DEVICE => pci_transport::<DEVICE>(msi),
            _ => pci_transport::<1>(false),
        };
        return match opened {
            Ok((transport, status)) => Ok((transport.into(), status)),
            Err(None) => Err(CONFIG_ELSEWHERE),
            Err(Some(transport::Failure::NotReset)) => Err(NOT_STARTED),
            Err(Some(transport::Failure::BarElsewhere)) => {
                rt::println!("{tag}: BAR 0 of the function lies elsewhere than its window");
                Err(NO_DEVICE)
            }
            Err(Some(transport::Failure::NoDevice)) => {
                rt::println!("{tag}: no network device at {at:#x}");
                Err(NO_DEVICE)
            }
        };
    }
    let base = dma::mmio_at(device) + (at as usize & (PAGE - 1));
    // SAFETY: the window maps the transport's page at mmio_at as device
    // memory, read and write; `base` is the transport within it, and only
    // the transport and the reads of the configuration space reach the
    // registers from here on.
    match unsafe { transport::mmio_transport(base) } {
        Ok((transport, status)) => Ok((transport.into(), status)),
        Err(OpenError::Rejected(why)) => {
            rt::println!("{tag}: no network device at {at:#x}: {why:?}");
            Err(NO_DEVICE)
        }
        Err(OpenError::Unusable) => {
            rt::println!("{tag}: no usable transport at {at:#x}");
            Err(NO_DEVICE)
        }
    }
}

/// The Virtio PCI function of device `D` of the record, whose page the
/// window `ecam` maps at `ecam_at() + ecam_offset(D)`, set up as the other
/// drivers of VZ set theirs up (virtio_pci): the ID of the function checked,
/// the common configuration looked up in its capability list (init stops
/// the device through `device_status` at the start of BAR 0; None when it
/// lies elsewhere), the BARs written with decoding off and then on, the
/// device reset (`virtio_net::transport::pci_transport`), and bus mastering
/// on only then (Virtio 1.2, 2.4.1, 3.1.1). Every access to the
/// configuration space is 32 bits wide, as VZ stops the machine at a byte
/// write there. With `msi` the function is QEMU's (`virtio_pci::qemu::NET`):
/// the structures in BAR 4, and BAR 1 of the MSI-X table placed after it.
fn pci_transport<const D: usize>(
    msi: bool,
) -> Result<(virtio_drivers::transport::pci::PciTransport, u32), Option<transport::Failure>> {
    let place = &netd::pci::PLACES[D];
    let page = dma::ecam_at() + netd::pci::ecam_offset(D) as usize;
    let read = |offset: usize| {
        // SAFETY: the page is mapped as device memory, read and write; the
        // offset is a register of virtio_pci.
        unsafe { virtio_net::mmio::read32(page + offset) }
    };
    let write = |offset: usize, value: u32| {
        // SAFETY: as for `read`.
        unsafe { virtio_net::mmio::write32(page + offset, value) }
    };
    // The record names the function of the network device; one that holds
    // something else ends the service before it writes there.
    let found = read(virtio_pci::COMMAND) & 0xFFFF;
    let (id, index, writes, bar) = if msi {
        let msix = (virtio_pci::BAR0 + 4, qemu::NET_MSIX as u32);
        let writes = qemu::NET.set_up_with(found, msix);
        (qemu::NET.id, qemu::NET.index as u8, writes, dma::qemu_bar())
    } else {
        (place.id, 0, place.set_up(found), dma::bar(D))
    };
    if read(virtio_pci::ID) != id {
        return Err(Some(transport::Failure::NoDevice));
    }
    if virtio_pci::common_config(read) != Some((index, 0)) {
        return Err(None);
    }
    for (offset, value) in writes {
        write(offset, value);
    }
    let opened = transport::pci_transport_in::<D, _>(Function(page), index, bar).map_err(Some)?;
    write(
        virtio_pci::COMMAND,
        virtio_pci::bus_master(read(virtio_pci::COMMAND)),
    );
    Ok(opened)
}

/// Starts the second device in `slot`.
#[allow(clippy::too_many_arguments)]
fn start_second<'a>(
    pci: bool,
    at1: u64,
    irq1: Handle<Interrupt>,
    slot: &'a mut core::mem::MaybeUninit<Second>,
    storage: &'static mut second::Storage,
    settings: &Settings,
    seed: u64,
    objects: (u64, u64),
) -> Result<&'a mut Second, u64> {
    let (transport, status) = open_device(pci, false, 1, at1)?;
    // SAFETY: the slot is exclusive and empty, the storage is the one
    // socket's and used nowhere else; the device is up when `start_at`
    // returns Ok.
    unsafe {
        Second::start_at(
            slot.as_mut_ptr(),
            storage,
            transport,
            irq1,
            (pci, at1, status),
            seed.wrapping_add(1),
            now_ns(),
            settings.address1,
            objects,
        )?;
        Ok(slot.assume_init_mut())
    }
}

/// The static address of the file, when it names one.
fn announce_static(stack: &mut Stack<'_>, settings: &Settings) {
    if let Some(address) = settings.address {
        stack.set_static(address, settings.gateway, settings.dns);
        if let Some(lease) = stack.lease {
            rt::println!("net: static {}", lease.summary());
        }
    }
}

impl Tables {
    /// The tables as they start, in place: those of the `channels.len()` instances.
    ///
    /// # Safety
    /// `tables` is valid for writes, exclusive and zeroed.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn initialize_at(
        tables: *mut Tables,
        key: [u8; 16],
        demux_key: [u8; 16],
        (parent, channels, process): (&Handle<Channel>, &[&Handle<Channel>], &Handle<Process>),
        level: u8,
        buffers: u16,
        cpus: u32,
    ) {
        use core::ptr::addr_of_mut;
        let count = channels.len();
        for (k, channel) in channels.iter().enumerate() {
            // SAFETY: each field is in bounds and written once.
            unsafe {
                Net::initialize_at(
                    addr_of_mut!((*tables).nets[k]),
                    key,
                    demux_key,
                    parent,
                    channel,
                    level,
                    process,
                    netd::buffers::Buffers::of_instance(buffers, k, count),
                    (&netd::ports::CLAIMS, k as u8),
                    netd::home::cpu_of(cpus, k).unwrap_or(0) as u8,
                );
                Storage::initialize_at(addr_of_mut!((*tables).storages[k]));
                rt::bss::fill_none(addr_of_mut!((*tables).sessions[k]));
            }
        }
        // SAFETY: as above.
        unsafe {
            addr_of_mut!((*tables).second_storage).write([SocketStorage::EMPTY]);
        }
    }
}

/// The objects and the windows the service holds for its life: the
/// mappings and the copies it hands to the owner of the second device
/// (owner.rs) need them. The windows: `mmio` or `ecam`, `bar`, `mmio1`.
struct Maps {
    _dma: Handle<Memory>,
    _net: Handle<Memory>,
    _tails: Option<Handle<Memory>>,
    windows: [Option<Handle<Memory>>; 3],
    second: [Option<Handle<Memory>>; SECOND_OBJECTS.len()],
}

/// What an instance after the first needs besides its tables: the channel its loop serves, a
/// copy of it with NOTIFY (the loop tells itself steps, and the switch tells it frames), the
/// timer of its deadlines, and the handle with which the first instance asks it for the sessions
/// of the processes whose home it is (HOME).
/// The CPUs of the instances, how many there are, and the channels and timers of those after
/// the first (apart from `main`, whose frame is on the thread's small stack).
#[inline(never)]
fn plan_instances(
    settings: &netd::config::Settings,
    second_device: bool,
    level: u8,
) -> Result<(u32, usize, [Option<Extra>; MAX_INSTANCES]), u64> {
    let limit = if settings.consumers() > 0 || second_device {
        1
    } else {
        settings.instances().min(BUILT)
    };
    let allowed = sys::cpu_info(0).map_or(1, |info| info.allowed as u32);
    let cpus = match netd::home::instance_cpus(allowed, limit) {
        0 => 1,
        cpus => cpus,
    };
    let instances = netd::home::count(cpus);
    rt::println!("net: {instances} stack instances, CPUs {cpus:#b} of {allowed:#b}");
    let mut extra: [Option<Extra>; MAX_INSTANCES] = [const { None }; MAX_INSTANCES];
    for slot in extra.iter_mut().take(instances).skip(1) {
        *slot = Some(Extra::new(level)?);
    }
    Ok((cpus, instances, extra))
}

/// The channel and timer of an instance's pauses: a wait channel, so that the pause lends no
/// priority.
#[inline(never)]
fn make_pause(level: u8) -> Option<(Handle<Channel>, Handle<Timer>)> {
    sys::channel_create_wait(level)
        .and_then(|channel| sys::timer_create(&channel, level).map(|timer| (channel, timer)))
        .ok()
}

struct Extra {
    channel: Handle<Channel>,
    notify: Handle<Channel>,
    view: Handle<Channel>,
    timer: Handle<Timer>,
    home: Option<Handle<Channel>>,
}

impl Extra {
    fn new(level: u8) -> Result<Extra, u64> {
        let channel = sys::channel_create(level).map_err(|_| NOT_REGISTERED)?;
        let notify = sys::handle_duplicate(&channel, Rights::NOTIFY).map_err(|_| NOT_REGISTERED)?;
        let view = sys::handle_label(&channel, Rights::RECEIVE, TIMER_LABEL, level)
            .map_err(|_| NOT_REGISTERED)?;
        let timer = sys::timer_create(&view, level).map_err(|_| NOT_REGISTERED)?;
        let home = sys::handle_label(&channel, Rights::SEND, calls::HOME_LABEL, level)
            .map_err(|_| NOT_REGISTERED)?;
        Ok(Extra {
            channel,
            notify,
            view,
            timer,
            home: Some(home),
        })
    }
}

/// The service: the device and the stack, the binding of its line, the
/// timer, the sockets, and the PING that waits for its reply.
struct Driver<'a> {
    /// Which instance this is, the CPUs the instances stand on (a mask), and how many there are.
    index: usize,
    cpus: u32,
    instances: usize,
    /// The switch has tables: it needs the address, and the instances' ports steer frames.
    routed: bool,
    /// The generation of the shared address (`netd::published`) this instance has applied.
    address_seen: u32,
    /// The handles with which this instance (the first) asks another for a session of a process
    /// that is homed there (HOME_MAKE).
    homes: [Option<Handle<Channel>>; MAX_INSTANCES],
    /// The dump of the time stamps of the kernel (kdump.rs).
    #[cfg(feature = "trace")]
    kernel_stamps: kdump::KernelDump,
    /// The address the switch was last told (a renewal of the lease that changes nothing is
    /// not told: consumers end their processes on a new address).
    switch_ip: netd::books::AddressSync,
    /// The stack instance this loop runs: its device (a lane of the switch's rings), its
    /// smoltcp interface and its tables of sockets.
    inst: Instance<'a>,
    /// A copy of the service's channel with NOTIFY: the service tells
    /// itself a step is due, and the switch tells the stack of frames.
    notify: Handle<Channel>,
    /// The switch thread (`switch.rs`) and the copy of its channel with
    /// NOTIFY the stack wakes it with: the service holds them for its life.
    switch: Option<(Handle<rt::handle::Thread>, Handle<Channel>)>,
    timer: Handle<Timer>,
    _view: Handle<Channel>,
    ping: Option<Pending>,
    mac: [u8; 6],
    /// The second device, if the record has one.
    second: Option<&'a mut Second>,
    /// The second device said its own interrupt (see `rx1_step`).
    own_said: bool,
    /// The bits of the notifications to itself that are on their way.
    told: u64,
    /// The doorbell held for the work queued behind a step.
    bell: netd::ring::Hold,
    /// The queue was looked at in the event that is on.
    bell_checked: bool,
    /// A step of departure is due that no notification told.
    cleanup_due: bool,
    /// CONFIG asked for the probe's report of counters: it is said after the step, outside it
    /// (a line costs the console path of the kernel, about 70 ticks a character, and the report
    /// is no work of the service).
    #[cfg(feature = "probe")]
    report_due: bool,
    /// The deadline the timer is set for.
    armed: Option<u64>,
    /// The step that ran last among those asked for together.
    last_step: usize,
    /// When the neighbour entries of the own addresses are renewed.
    neighbours_at: u64,
    /// The run of the thread and the channel and timer of its pauses.
    guard: netd::ring::RunGuard,
    pause: Option<(Handle<Channel>, Handle<Timer>)>,
    counters_pause_failed: u32,
    /// When the instance next leaves its counters for the profile record.
    #[cfg(feature = "profile")]
    snapshot_at: u64,
    /// The gateway and the name servers are to be asked for their hardware
    /// addresses (a lease came, or the renewal is due).
    ask_due: bool,
    /// How many of the targets of the round the requests went out for.
    asked: usize,
    /// When the requests left go on, after a step that found the queue full.
    ask_at: Option<u64>,
    /// The text of `/etc/resolv.conf` as the service wrote it last.
    resolv: Written,
    /// The consumers of the switch (`consumers.rs`).
    side: consumers::Side,
    /// The program that owns the second device, and what a claim needs.
    owner: Option<owner::Owner>,
    claimable: owner::Claimable,
    /// The probe holds the steps of the stack (HOLD), and an interrupt came
    /// meanwhile.
    #[cfg(feature = "probe")]
    hold: bool,
    /// A step of each kind was asked for while the steps were held.
    #[cfg(feature = "probe")]
    held_rx: bool,
    #[cfg(feature = "probe")]
    held_tx: bool,
    /// The count of merged frames at which the stack says the line of the cut next.
    merged_next: u32,
    /// The count of frames of the segmentation offload at which the next line is said.
    tso_next: u32,
    /// The longest step of waking and of departure so far (the probe's lines
    /// `net: step wake` and `net: step cleanup`, which the measurement of the
    /// interest sets reads: the own steps of the service are one kind).
    #[cfg(feature = "probe")]
    longest: [u64; 2],
    /// The service's own thread (its handle of the start data), whose time
    /// of its own (thread_ran) the two steps are measured in: a thread of a
    /// higher level that runs in the middle of a step does not lengthen it,
    /// as in rt's count of steps. No handle of its own: the operations of
    /// role `w` take the service's handles up to its limit.
    #[cfg(any(feature = "probe", feature = "profile"))]
    own: Option<Handle<rt::handle::Thread>>,
    maps: Option<Maps>,
}

impl<'a> Driver<'a> {
    /// An instance with nothing of the first instance's own (no second device, no owner of it,
    /// no consumers): `main` fills in what the first has.
    #[allow(clippy::too_many_arguments)]
    fn new(
        inst: Instance<'a>,
        index: usize,
        notify: Handle<Channel>,
        timer: Handle<Timer>,
        view: Handle<Channel>,
        mac: [u8; 6],
        switch_ip: netd::books::AddressSync,
        side: consumers::Side,
        #[cfg(feature = "trace")] kernel_stamps: kdump::KernelDump,
    ) -> Driver<'a> {
        Driver {
            index,
            cpus: 1,
            instances: 1,
            routed: false,
            address_seen: 0,
            homes: [const { None }; MAX_INSTANCES],
            #[cfg(feature = "trace")]
            kernel_stamps,
            switch_ip,
            inst,
            notify,
            switch: None,
            timer,
            _view: view,
            ping: None,
            mac,
            second: None,
            own_said: false,
            told: 0,
            bell: netd::ring::Hold::new(),
            bell_checked: false,
            cleanup_due: false,
            #[cfg(feature = "probe")]
            report_due: false,
            armed: None,
            last_step: 0,
            neighbours_at: 0,
            guard: netd::ring::RunGuard::new(),
            pause: None,
            counters_pause_failed: 0,
            #[cfg(feature = "profile")]
            snapshot_at: 0,
            ask_due: false,
            asked: 0,
            ask_at: None,
            resolv: Written::default(),
            side,
            owner: None,
            claimable: owner::Claimable {
                handover: false,
                pci: false,
                at: 0,
                objects: [0; 5],
                pages: [0; 5],
            },
            #[cfg(feature = "probe")]
            hold: false,
            #[cfg(feature = "probe")]
            held_rx: false,
            #[cfg(feature = "probe")]
            held_tx: false,
            merged_next: 1,
            tso_next: 1,
            #[cfg(feature = "probe")]
            longest: [0; 2],
            #[cfg(any(feature = "probe", feature = "profile"))]
            own: None,
            maps: None,
        }
    }
}

/// What each instance leaves for the profile record (`profile_snapshot`).
#[cfg(feature = "profile")]
struct Snapshot {
    ran: core::sync::atomic::AtomicU64,
    calls: core::sync::atomic::AtomicU64,
    members: [core::sync::atomic::AtomicU64; 8],
}

#[cfg(feature = "profile")]
static SNAPSHOT: [Snapshot; MAX_INSTANCES] = [const {
    Snapshot {
        ran: core::sync::atomic::AtomicU64::new(0),
        calls: core::sync::atomic::AtomicU64::new(0),
        members: [const { core::sync::atomic::AtomicU64::new(0) }; 8],
    }
}; MAX_INSTANCES];

impl Driver<'_> {
    /// The profile's totals as records of the console (builds with the
    /// feature `profile`): the service's own time first, then the maxima
    /// start anew for the next snapshot.
    #[cfg(feature = "profile")]
    fn leave_snapshot(&self) {
        // The groups and the thread's time belong to the instance: each one leaves its own in
        // `SNAPSHOT` (the steps do it every 50 ms) and the record carries the sums.
        let own = &SNAPSHOT[self.index];
        own.ran
            .store(self.ran(), core::sync::atomic::Ordering::Relaxed);
        own.calls.store(
            self.inst.net.counters.calls,
            core::sync::atomic::Ordering::Relaxed,
        );
        let served = self.inst.net.groups.served_by_position();
        for (cell, n) in own.members.iter().zip(served) {
            cell.store(n, core::sync::atomic::Ordering::Relaxed);
        }
    }

    /// The profile's totals as records of the console (builds with the feature `profile`).
    #[cfg(feature = "profile")]
    fn profile_snapshot(&self) {
        let own = &SNAPSHOT[self.index];
        self.leave_snapshot();
        let load =
            |cell: &core::sync::atomic::AtomicU64| cell.load(core::sync::atomic::Ordering::Relaxed);
        profile::store(Counter::Ran, SNAPSHOT.iter().map(|i| load(&i.ran)).sum());
        // How the load is shared: the SYNs of each member of a group, the frames of each
        // consumer of the switch.
        for at in 0..own.members.len() {
            let sum: u64 = SNAPSHOT.iter().map(|i| load(&i.members[at])).sum();
            profile::store_at(Counter::Member0, at, sum);
        }
        // What each instance answered and ran: which instance serves which calls.
        for (k, i) in SNAPSHOT.iter().enumerate().take(self.instances) {
            let mut members = [0u64; 8];
            for (m, cell) in members.iter_mut().zip(&i.members) {
                *m = load(cell);
            }
            rt::println!(
                "net: instance {k} calls {} ran {} members {members:?}",
                load(&i.calls),
                load(&i.ran)
            );
        }
        for (at, n) in switch::INNER.stats.rx_by.iter().enumerate() {
            profile::store_at(
                Counter::Cons0,
                at,
                u64::from(n.load(core::sync::atomic::Ordering::Relaxed)),
            );
        }
        let id = profile::next_id();
        profile::records(id, &profile::snapshot(), |record| rt::println!("{record}"));
        profile::take_maxima();
        split::report();
    }

    /// The ticks the service's thread has run (builds with the feature
    /// `probe` or `profile`).
    #[cfg(any(feature = "probe", feature = "profile"))]
    fn ran(&self) -> u64 {
        self.own
            .as_ref()
            .map_or(0, |t| sys::thread_ran(t).unwrap_or(0))
    }

    /// A step of waking (`which` 0) or of departure (1) ran until now from
    /// `began` (`ran`): a line when it is the longest of its kind (builds
    /// with the feature `probe`).
    #[cfg(feature = "probe")]
    fn measured(&mut self, which: usize, began: u64) {
        let ticks = self.ran().saturating_sub(began);
        if ticks > self.longest[which] {
            self.longest[which] = ticks;
            let name = ["wake", "cleanup"][which];
            rt::println!("net: step {name} {ticks} ticks");
        }
    }

    /// Tells the loop `bit` unless it is told already; false when the
    /// notification was refused and nothing is on its way.
    fn tell(&mut self, bit: u64) -> bool {
        if self.told & bit != 0 {
            return true;
        }
        if sys::notify(&self.notify, bit).is_ok() {
            profile::count(Counter::Told);
            self.told |= bit;
            return true;
        }
        profile::count(Counter::Refused);
        false
    }

    /// Asks the loop for a step of the stack.
    fn want_step(&mut self) -> bool {
        self.tell(TX)
    }

    /// The requests made while a step or a departure was wanted: the loop
    /// is told, once.
    fn after_request(&mut self) {
        if core::mem::take(&mut self.inst.net.step_due) {
            self.want_step();
        }
        if core::mem::take(&mut self.inst.net.cleanup_wanted) {
            self.cleanup();
        }
        if core::mem::take(&mut self.inst.net.wake_wanted) {
            self.tell(WAKE);
        }
        if core::mem::take(&mut self.inst.net.buffer_wanted) {
            self.tell(MAP);
        }
        if self.side.max > 0 {
            self.drain_releases();
        }
        if self.cleanup_due && self.tell(CLEANUP) {
            self.cleanup_due = false;
        }
        // An operation with a time limit was made: the timer may be set
        // earlier for it.
        if core::mem::take(&mut self.inst.net.deadline_new) {
            self.arm(now_ns());
        }
        self.bell_release();
    }

    /// A departure is due.
    fn cleanup(&mut self) {
        if !self.tell(CLEANUP) {
            self.cleanup_due = true;
        }
    }

    /// The step of receiving: from the switch's notification or the
    /// service's own. It takes up to STEP_RX frames the switch passed
    /// (loopback first), with the stack's answers to them, and asks for the
    /// steps that follow.
    /// The line of the cut of merged frames at each power of two of their count, said here (the
    /// stack's step) and never in a step of the switch.
    fn say_merged(&mut self) {
        if !switch::INNER.merged() {
            return;
        }
        let st = &switch::INNER.stats;
        let tso = st.tso.load(core::sync::atomic::Ordering::Relaxed);
        if tso >= self.tso_next {
            self.tso_next = (tso + 1).next_power_of_two();
            rt::println!(
                "net: tso {tso} frames in {} chunks, {} waited for buffers",
                st.tso_chunks.load(core::sync::atomic::Ordering::Relaxed),
                st.tso_waits.load(core::sync::atomic::Ordering::Relaxed)
            );
        }
        let count = st.merged.load(core::sync::atomic::Ordering::Relaxed);
        if count >= self.merged_next {
            self.merged_next = (count + 1).next_power_of_two();
            let get =
                |c: &core::sync::atomic::AtomicU32| c.load(core::sync::atomic::Ordering::Relaxed);
            rt::println!(
                "net: merged {count} frames, the longest of {} bytes, cut into {} segments, {} dropped, pool empty {}",
                get(&st.merged_max),
                get(&st.cut),
                get(&st.merged_dropped),
                get(&st.pool_empty)
            );
        }
    }

    fn rx_step(&mut self) {
        rt::service::step_own();
        profile::count(Counter::StepRx);
        self.follow_address();
        // Seen before the ring is looked at: frames the switch passes after
        // this tell the stack again.
        self.inst.lane.stack_awake();
        self.say_merged();
        #[cfg(feature = "probe")]
        if self.hold {
            self.held_rx = true;
            self.inst.lane.kick(false);
            return;
        }
        let began = split::now();
        split::begin_step();
        let now = now_ns();
        self.inst.device.rx.begin_step(Budget::receiving());
        self.inst.device.tx.begin_step(Budget::receiving());
        stack::ingress(
            &mut self.inst.stack,
            &mut self.inst.device,
            self.inst.net,
            now,
        );
        self.events(now);
        self.finish_step(now);
        rt::service::step_detail(self.inst.device.step_frames() as u64);
        // Frames the share of the step left in the switch's ring or in the
        // loop: another step of receiving.
        let kernel = split::now();
        let more = !self.inst.lane.rx_ready.is_empty()
            || self.inst.device.looped.waiting() > 0
            || self.inst.device.has_deferred();
        let continued = more && self.tell(RX);
        let sending = self.next_steps(now, continued);
        self.kick_switch(continued || sending);
        let end = split::now();
        split::record(split::KERNEL, end - kernel);
        let counted = split::get(&split::RX_TURNS) + split::get(&split::PASSES);
        split::record(split::FIXED_RX, (end - began).saturating_sub(counted));
    }

    /// The step of sending: the service's set when it has work and up to
    /// EGRESS_GROUPS groups of those that have, at most STEP_TX frames. From
    /// the timer (`deadline`) or the service's own notification.
    fn tx_step(&mut self, deadline: bool) {
        rt::service::step_own();
        profile::count(Counter::StepTx);
        self.follow_address();
        #[cfg(feature = "probe")]
        if self.hold {
            self.held_tx = true;
            self.inst.lane.kick(false);
            return;
        }
        let began = split::now();
        split::begin_step();
        let now = now_ns();
        self.inst.device.rx.begin_step(Budget::sending());
        self.inst.device.tx.begin_step(Budget::sending());
        self.inst.stack.egress(
            now,
            &mut self.inst.device,
            &mut self.inst.net.due,
            &mut self.inst.net.touched,
            &mut self.inst.net.passed,
        );
        self.events(now);
        if now >= self.neighbours_at {
            self.addresses();
        }
        #[cfg(feature = "profile")]
        if now >= self.snapshot_at {
            self.snapshot_at = now + 50_000_000;
            self.leave_snapshot();
        }
        if self.ask_due {
            self.ask_at = None;
            self.ask_neighbours();
        }
        if deadline && self.inst.net.orphans_wait() {
            self.tell(SWEEP);
        }
        if deadline && self.inst.net.rst_waiting() {
            self.inst.net.cleanup_wanted = true;
        }
        self.finish_step(now);
        rt::service::step_detail(self.inst.device.step_frames() as u64);
        let kernel = split::now();
        let continued = self.inst.device.looped.waiting() > 0 && self.tell(RX);
        let sending = self.next_steps(now, continued);
        self.kick_switch(continued || sending);
        let end = split::now();
        split::record(split::KERNEL, end - kernel);
        let counted = split::get(&split::RX_TURNS) + split::get(&split::PASSES);
        split::record(split::FIXED_TX, (end - began).saturating_sub(counted));
    }

    /// What every step ends with: the operations that wait are looked at by a
    /// step of their own.
    fn finish_step(&mut self, _now: u64) {
        self.inst.net.schedule_wake();
        if self.inst.net.wake_pending() {
            self.tell(WAKE);
        }
    }

    /// Groups with work left want a step of sending; when no step follows,
    /// the timer is set for the next deadline. True when a step of sending
    /// follows.
    fn next_steps(&mut self, now: u64, receiving: bool) -> bool {
        // The DHCP client's set has a message to send after a frame of the
        // server (a request after an offer) that only a pass of sending
        // makes; without this step it would wait for the client's retry.
        let sending = (self.inst.net.due.any() || self.inst.stack.service_due) && self.tell(TX);
        if !receiving && !sending {
            self.arm(now);
        }
        sending
    }

    /// The second device's step (second.rs): its status if an interrupt
    /// brought the step, the frames of DHCP and ARP, the client's pass; it
    /// asks for another step while frames are left, and opens its line when
    /// the queue is empty. While a program owns the device, the frames come
    /// from the bypass ring, and an interrupt only tells the owner. The
    /// frames taken from the ring.
    fn rx1_step(&mut self, interrupt: bool) -> u32 {
        rt::service::step_own();
        profile::count(Counter::StepRx1);
        self.rx1_work(interrupt)
    }

    /// The work of `rx1_step`, which KICK does in its own step.
    fn rx1_work(&mut self, interrupt: bool) -> u32 {
        let Some(second) = self.second.as_deref_mut() else {
            return 0;
        };
        let now = now_ns();
        let outcome = second.step(now, interrupt);
        match outcome.event {
            Some(Event::Leased(lease)) => rt::println!("net: lease1 {}", lease.summary()),
            Some(Event::Lost) => rt::println!("net: lease1 lost"),
            None => {}
        }
        match outcome.renewed {
            Some((lease, false)) => rt::println!("net: renew1 {}", lease.summary()),
            Some((lease, true)) => rt::println!("net: renew1 {} changed", lease.summary()),
            None => {}
        }
        if outcome.first_interrupt {
            rt::println!("virtio-net1: first interrupt");
        }
        if outcome.ring_broken {
            rt::println!("net: bypass broken");
        }
        // The notification came from the second device's own line (its
        // label), and its status was not empty.
        if interrupt && outcome.isr_seen && !self.own_said {
            self.own_said = true;
            rt::println!("virtio-net1: own interrupt");
        }
        self.tell_owner(outcome.owner_bits);
        // Frames left in the queue or the ring: another step, with the line
        // closed. The owner's device opens it at once: its status was read.
        let continued = outcome.more && self.tell(RX1);
        if (!continued || outcome.owner_bits & proto_net::fast::FAST_INTERRUPT != 0)
            && let Some(second) = self.second.as_deref_mut()
            && second.mode != second::Mode::Dead
            && core::mem::take(&mut second.line_closed)
        {
            virtio_mmio::reopen(&second.irq);
        }
        if !continued {
            self.arm(now);
        }
        outcome.taken
    }

    /// A step of the second device's return from its owner.
    fn return_step(&mut self) {
        let Some(second) = self.second.as_deref_mut() else {
            return;
        };
        rt::service::step_own();
        profile::count(Counter::StepReturn);
        // The line of the longest step says which step of the return it was.
        rt::service::step_detail(second.back_detail());
        match second.back_step() {
            second::Returned::More => {
                self.tell(RETURN);
            }
            second::Returned::Done => {
                rt::println!("net: device 1 back");
                self.tell(RX1);
            }
            // The first device and its sockets go on; the second stays dead.
            second::Returned::Failed => {
                rt::println!("virtio-net1: the device did not come back");
            }
        }
    }

    /// What the DHCP client and the PING made of the step.
    fn events(&mut self, now: u64) {
        let dhcp = if self.inst.stack.take_service_ran() {
            self.inst.stack.dhcp_event()
        } else {
            None
        };
        match dhcp {
            Some(Event::Leased(lease)) => {
                self.inst.net.external = Some(lease.address);
                self.addresses();
                self.inst.net.touch_all();
                self.publish_address();
                self.tell(RESOLV);
                rt::println!("net: lease {}", lease.summary())
            }
            Some(Event::Lost) => {
                self.inst.net.external = None;
                self.addresses();
                self.inst.net.touch_all();
                self.publish_address();
                rt::println!("net: lease lost")
            }
            None => {}
        }
        if self.ping.is_some()
            && let Some(end) = self.inst.stack.ping_end(now)
        {
            self.finish_ping(end);
        }
    }

    /// The first instance holds the DHCP client: the address it has goes to the others, which
    /// are told a step is due (their steps look at the shared record's generation first).
    fn publish_address(&mut self) {
        if self.index != 0 {
            return;
        }
        let record = stack::record_of(self.inst.stack.lease);
        let before = published::ADDRESS.read().1;
        if before != record {
            published::ADDRESS.publish(record.as_ref());
            for k in 1..self.instances {
                switch::INNER.lanes[k].poke(TX);
            }
        }
    }

    /// An instance after the first takes the address the first published, when it changed: the
    /// interface, the loop's own addresses, the neighbours (the gateway and the servers are
    /// asked for), and every socket that waited for the address.
    fn follow_address(&mut self) {
        if self.index == 0 {
            return;
        }
        let generation = published::ADDRESS.generation();
        if generation == self.address_seen {
            return;
        }
        let (generation, record) = published::ADDRESS.read();
        self.address_seen = generation;
        self.inst.stack.follow(record.as_ref());
        self.inst.net.external = record.map(|r| r.address);
        self.addresses();
        self.inst.net.touch_all();
    }

    /// The frames to the addresses of the interface stay in the loop.
    fn addresses(&mut self) {
        let (own, count) = self.inst.stack.addresses();
        self.inst.device.set_addresses(&own[..count]);
        self.inst.device.seed_neighbours();
        self.neighbours_at = now_ns() + NEIGHBOURS_NS;
        self.ask_due = true;
        self.asked = 0;
        self.inst.net.step_due = true;
        if self.switch_address() {
            self.tell(BACK);
        }
    }

    /// The switch and its consumers learn the address (the lease, or none). True when the
    /// switch's ring of commands was full: the address stays due, and the step of the answers
    /// tries again.
    fn switch_address(&mut self) -> bool {
        if self.index != 0 || !self.routed {
            return false;
        }
        let (ip, prefix) = self
            .inst
            .stack
            .lease
            .map_or(([0; 4], 0), |lease| (lease.address, lease.prefix.min(32)));
        if !self.switch_ip.due((ip, prefix)) {
            return false;
        }
        if !switch::command(netd::switchlogic::commands::Command::Address { ip, prefix }) {
            return true;
        }
        self.switch_ip.done((ip, prefix));
        self.tell_consumers(proto_net::switch::WAKE_ADDRESS);
        false
    }

    /// Asks the gateway and the name servers on the link for their hardware
    /// addresses, so that the first datagram or SYN to them finds the entry
    /// in the neighbour cache: smoltcp sends one request a second for the
    /// whole interface (`SILENT_TIME` of its neighbour cache), and a lookup
    /// of a name followed at once by a connection to the gateway would wait
    /// for the second.
    fn ask_neighbours(&mut self) {
        let Some(lease) = self.inst.stack.lease else {
            self.ask_due = false;
            return;
        };
        let (targets, count) =
            netd::resolv::neighbours(lease.address, lease.prefix, lease.gateway, &lease.servers);
        let sent = self
            .inst
            .device
            .ask_neighbours(lease.address, &targets[self.asked.min(count)..count]);
        let (asked, round) = netd::resolv::round(self.asked.min(count), sent, count);
        self.asked = asked;
        match round {
            netd::resolv::Round::Done => self.ask_due = false,
            // The next request goes out in the next step, which the service
            // orders itself.
            netd::resolv::Round::Continue => {
                self.tell(TX);
            }
            // The queue is full: a step after a millisecond, as for a group
            // with nothing to send, so that the service does not spin on it.
            netd::resolv::Round::Wait => self.ask_at = Some(now_ns() + ASK_RETRY_NS),
        }
    }

    /// The step of RESOLV: `/etc/resolv.conf` gets the lease's name servers
    /// when they differ from what the service wrote last. A lease without
    /// servers leaves the file as it is.
    fn resolv_step(&mut self) {
        rt::service::step_own();
        let Some(lease) = self.inst.stack.lease else {
            return;
        };
        let text = Text::new(&lease.servers);
        if text.is_empty() {
            rt::println!("net: resolv.conf no server");
            return;
        }
        if !self.resolv.needs(&text) {
            return;
        }
        match files::write_resolv(text.as_bytes()) {
            Ok(()) => {
                self.resolv.record(text);
                let mut line = [0u8; netd::resolv::TEXT_MAX];
                rt::println!("net: resolv.conf {}", servers_line(&text, &mut line));
            }
            Err(error) => rt::println!("net: resolv.conf unwritable: {error:?}"),
        }
    }

    fn finish_ping(&mut self, end: PingEnd) {
        let Some(pending) = self.ping.take() else {
            return;
        };
        let mut w = Writer::new();
        let answered = match end {
            PingEnd::Reply(nanos) => proto_net::write_ping_reply(nanos, &mut w)
                .map(|()| pending.answer(w.as_bytes(), Outgoing::new())),
            PingEnd::TimedOut => Ok(pending.answer(
                &proto_wire::reply(code(proto_net::TIMEOUT)),
                Outgoing::new(),
            )),
        };
        if answered.is_err() {
            rt::println!("net: a reply of PING could not be written");
        }
    }

    /// The end of a step: the switch is told when the run of steps is over
    /// (`more` false) and buffers, frames or a held doorbell wait for it
    /// (`switch::Inner::kick`). A doorbell is an exit from the guest, so the
    /// switch rings once for the run, and takes the buffers of receiving back
    /// then.
    fn kick_switch(&mut self, more: bool) {
        let held = !more && self.bell_waits();
        self.inst.lane.kick(more || held);
    }

    /// Frames of the stack wait for the switch's doorbell and a call of a
    /// program stands queued behind this event: the bell waits for it
    /// (`ring::Hold`), so that the frames of the answers of calls that queue up
    /// behind one another go out with one bell. A step goes ahead of the calls
    /// behind it, so without this each call's frame rings a bell of its own.
    /// A step told to the service itself holds nothing.
    fn bell_waits(&mut self) -> bool {
        let own = self.told & STEP_BITS != 0;
        let notify = &self.notify;
        let verdict = self.bell.decide(
            self.inst.lane.tx_sub.len(),
            own,
            || sys::channel_info(notify).is_ok_and(|info| info.queued > 0),
            now_ns(),
        );
        self.bell_checked = true;
        if let Some(at) = verdict.arm {
            self.arm_bell(at, now_ns());
        }
        verdict.held
    }

    /// The timer fires at `at` for a held bell, below the floor of `arm`.
    fn arm_bell(&mut self, at: u64, now: u64) {
        if self.armed.is_none_or(|armed| at < armed || armed <= now) {
            if sys::timer_set(&self.timer, at).is_err() {
                self.bell.timer_gone();
                return;
            }
            self.armed = Some(at);
        }
    }

    /// The end of an event: a held bell rings once the queue behind it is
    /// empty or its time is up. The event's own step has looked at the queue
    /// already (`bell_checked`).
    fn bell_release(&mut self) {
        if self.bell.on() && !self.bell_checked && !self.bell_waits() {
            self.inst.lane.kick(false);
        }
    }

    /// Sets the timer for the stack's next work (`next`), the PING's
    /// deadline or the sweep of the streams that close, never in the past.
    fn arm(&mut self, now: u64) {
        let sweep =
            (self.inst.net.orphans_wait() || self.inst.net.rst_waiting()).then(|| now + SWEEP_NS);
        let at = [
            self.inst.stack.next_deadline(),
            self.inst.stack.ping.as_ref().map(|p| p.deadline_ns),
            sweep,
            self.inst.net.next_deadline(),
            Some(self.neighbours_at),
            self.ask_at,
            self.second.as_deref().and_then(|s| s.next_at),
        ]
        .into_iter()
        .flatten()
        .min();
        if let Some(at) = at {
            let at = at.max(now + 1_000_000);
            // The timer is set when there is none or the new deadline is
            // earlier: a later one finds the timer firing early and a step
            // that sets it again.
            if self.armed.is_none_or(|armed| at < armed || armed <= now) {
                let _ = sys::timer_set(&self.timer, at);
                self.armed = Some(at);
            }
        }
    }

    /// HOME: the process's session gets its home, once (`netd::home`). The reply says the CPU of
    /// the instance that holds the session after the call, and carries a session on another
    /// instance's channel when the home is not this one. A session that has descriptions or was
    /// homed before, and any session of an instance after the first (it is at its home), stays.
    fn home(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let (cpu, allowed) = match proto_net::read_home(r.body()) {
            Ok(asked) if r.handles.is_empty() => asked,
            Ok(_) => return Answer::Status(Status::BadSize),
            Err(status) => return Answer::Status(status),
        };
        let here = u32::from(self.inst.net.cpu);
        // The methods of the switch (ATTACH, PORT_HOLD, JOIN) and of the second device (CLAIM)
        // are the first instance's alone: where the service has either, no session moves away
        // from it, so that a program that attaches or claims later finds them. A stopgap: the
        // forwarding of those methods to the first instance belongs to P3.
        let owner_methods = self.side.max > 0 || self.second.is_some();
        if self.index != 0 || s.data.homed || s.data.held.count() > 0 || owner_methods {
            return stays(s, r, here);
        }
        let home = netd::home::choose(self.cpus, cpu, allowed);
        let Some(link) = self
            .homes
            .get(home)
            .and_then(Option::as_ref)
            .filter(|_| home != 0)
        else {
            return stays(s, r, here);
        };
        let mut w = Writer::new();
        if proto_net::write_home_make(s.data.root, &mut w).is_err() {
            return Answer::Status(Status::BadSize);
        }
        // The home answers at once (it makes a label and a handle); the first instance waits
        // for it, and the home never calls the first, so the two cannot wait for each other.
        match rt::service::clone_session(link, w.as_bytes()) {
            Ok(session) => {
                s.data.homed = true;
                let there = netd::home::cpu_of(self.cpus, home).unwrap_or(0);
                match sockets::write_word(r.reply(), there) {
                    Ok(()) => Answer::Reply([session.erase()].into()),
                    Err(status) => Answer::Status(status),
                }
            }
            // No session at the home: the process stays here, and its calls cross CPUs.
            Err(_) => stays(s, r, here),
        }
    }

    /// CONFIG: the address of the interface of the device the request
    /// names (the first without one), or NET_DOWN while it has none. The
    /// second device's gateway and name server are what its lease said; the
    /// service routes nothing through them.
    fn config(&mut self, r: &mut Request<'_>) -> Answer {
        let device = match proto_net::fast::read_config(r.body()) {
            Ok(device) => device,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        #[cfg(feature = "probe")]
        {
            self.report_due = true;
        }
        let (lease, mac) = if device == 0 {
            (self.inst.stack.lease, self.mac)
        } else {
            match self.second.as_deref() {
                Some(second) if second.mode != second::Mode::Dead => {
                    (second.lease, second.device.mac)
                }
                _ => return Answer::Status(code(proto_net::INVALID)),
            }
        };
        let Some(lease) = lease else {
            return Answer::Status(code(proto_net::NET_DOWN));
        };
        let config = proto_net::Config {
            address: lease.address,
            prefix: u32::from(lease.prefix),
            gateway: lease.gateway,
            dns: lease.dns,
            mac,
        };
        if config.write(r.reply()).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// The counters of the probe's line.
    #[cfg(feature = "probe")]
    fn report_frames(&self) {
        let (rx, rx_dropped, rx_martian) = self.inst.device.rx.counters();
        let tx = self.inst.device.tx.counters();
        rt::println!(
            "net: frames rx {} tx {} dhcp {} dropped {} martian {} listen_short {} syn_dropped {} set_barred {} syn_stray {} orphan_reused {} bad_sum {} demux_probe {}",
            rx,
            tx.tx,
            tx.dhcp,
            rx_dropped + tx.dropped + self.inst.device.looped.dropped(),
            rx_martian + tx.martian,
            self.inst.net.counters.listen_short,
            self.inst.net.counters.syn_dropped,
            self.inst.net.counters.set_barred,
            self.inst.net.counters.syn_stray,
            self.inst.net.counters.orphan_reused,
            self.inst.device.bad_sum,
            self.inst.net.demux.probe_max
        );
        rt::println!(
            "net: bells tx {} frames {}",
            switch::INNER.bells_tx(),
            tx.tx
        );
        if switch::INNER.merged() {
            let st = &switch::INNER.stats;
            let get =
                |c: &core::sync::atomic::AtomicU32| c.load(core::sync::atomic::Ordering::Relaxed);
            rt::println!(
                "net: merged {} cut {} merged_dropped {} merged_max {} pool_empty {}",
                get(&st.merged),
                get(&st.cut),
                get(&st.merged_dropped),
                get(&st.merged_max),
                get(&st.pool_empty)
            );
        }
        if self.side.max > 0 {
            self.report_switch();
        }
        let [first, all] = self.inst.net.counters.buffers_used;
        if all != 0 {
            rt::println!("net: buffers 1 used {first} pages, 64 used {all} pages");
        }
        if self.inst.net.counters.largest_copy != 0 {
            rt::println!(
                "net: buffer portion {} largest copy {}",
                netd::ring::BUFFER_PORTION,
                self.inst.net.counters.largest_copy
            );
        }
        if let Some((refused, lost, broken)) =
            self.second.as_deref().and_then(|s| s.ring_counters())
        {
            rt::println!("net: bypass refused {refused} lost {lost} broken {broken}");
        }
        split::report();
    }

    /// The switch's counters, one line (`posix-net stat`): consumers and flows, what the
    /// rings dropped and refused, the frames turned back at the shared address (and the frames
    /// to the device with that destination, which must stay 0).
    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    fn report_switch(&self) {
        use core::sync::atomic::Ordering::Relaxed;
        let st = &switch::INNER.stats;
        let get = |a: &core::sync::atomic::AtomicU32| a.load(Relaxed);
        rt::println!(
            "net: switch consumers {} flows {} unconfirmed {} evicted {} expired {} rx_full {} tx_refused {} hairpin {} own_to_device {} rx_consumer {} tx_consumer {} park_given {} left {} looped {} pauses {} pause_failed {} run_max_us {} budget_waits {} sum_tx {} sum_rx {} sum_soft {}",
            get(&st.consumers),
            get(&st.flows),
            get(&st.unconfirmed),
            get(&st.evicted),
            get(&st.expired),
            get(&st.rx_full),
            get(&st.tx_refused),
            get(&st.hairpin),
            get(&st.own_to_device),
            get(&st.rx_consumer),
            get(&st.tx_consumer),
            get(&st.park_given),
            get(&st.left),
            get(&st.looped),
            get(&st.pauses),
            get(&st.pause_failed),
            get(&st.run_max_us),
            get(&st.budget_waits),
            get(&st.sum_tx),
            get(&st.sum_rx),
            get(&st.sum_soft)
        );
        let drops: [u32; 7] = core::array::from_fn(|i| get(&st.drops[i]));
        let refused: [u32; netd::switchlogic::route::Reason::COUNT] =
            core::array::from_fn(|i| get(&st.refused_by[i]));
        rt::println!("net: switch dropped {drops:?} refused_by {refused:?}");
        let by: [u32; 8] = core::array::from_fn(|i| get(&st.rx_by[i]));
        rt::println!("net: switch rx_by {by:?}");
    }

    /// HOLD: the steps of the stack wait (1), go on (0), or every group of
    /// sockets is marked as having work (2).
    #[cfg(feature = "probe")]
    fn hold(&mut self, r: &mut Request<'_>) -> Answer {
        let value = match proto_net::read_hold(r.body()) {
            Ok(value) => value,
            Err(status) => return Answer::Status(status),
        };
        match value {
            proto_net::HOLD_ON => self.hold = true,
            proto_net::HOLD_OFF => {
                self.hold = false;
                self.held_rx = false;
                self.held_tx = false;
                self.inst.net.step_due = true;
                self.tell(RX);
            }
            proto_net::HOLD_DROP => self.inst.device.tx.drop_loop = 1,
            _ => {
                self.inst.net.touch_all();
                self.inst.net.step_due = true;
            }
        }
        Answer::Status(Status::Ok)
    }

    /// PING: an echo request to the address; the reply comes from the step
    /// that sees the answer, or TIMEOUT after a second.
    #[cfg(feature = "probe")]
    fn ping(&mut self, r: &mut Request<'_>, length: usize) -> Answer {
        let target = match proto_net::read_ping(r.body()) {
            Ok(address) => address.ipv4(),
            Err(status) => return Answer::Status(status),
        };
        let Some(target) = target else {
            return Answer::Status(Status::BadSize);
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if self.ping.is_some() {
            return Answer::Status(proto_net::LIMIT);
        }
        if self.inst.stack.lease.is_none() {
            return Answer::Status(code(proto_net::NET_DOWN));
        }
        let Some(pending) = r.defer() else {
            return Answer::Status(Status::Kernel(abi::Error::BadState));
        };
        if !self.inst.stack.ping_start(target, now_ns(), length) {
            let status = code(proto_net::NO_BUFFERS);
            let _ = pending.answer(&proto_wire::reply(status), Outgoing::new());
            return Answer::Deferred;
        }
        self.ping = Some(pending);
        self.want_step();
        Answer::Deferred
    }
}

/// The answer of HOME that leaves the session where it is, at the instance on CPU `here`.
fn stays(s: &mut Session<Client, 0>, r: &mut Request<'_>, here: u32) -> Answer {
    s.data.homed = true;
    match sockets::write_word(r.reply(), here) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

/// How often the stack is told again that its own addresses are at its own
/// MAC: half the life of an entry of the neighbour cache (60 s).
const NEIGHBOURS_NS: u64 = 30_000_000_000;

/// The servers of `text` on one line, separated by spaces: the words after
/// each `nameserver` (the text is the service's own, made by `Text::new`).
fn servers_line<'a>(text: &Text, out: &'a mut [u8; netd::resolv::TEXT_MAX]) -> &'a str {
    let mut len = 0;
    for line in text
        .as_bytes()
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
    {
        let server = &line[b"nameserver ".len()..];
        if len > 0 {
            out[len] = b' ';
            len += 1;
        }
        out[len..len + server.len()].copy_from_slice(server);
        len += server.len();
    }
    core::str::from_utf8(&out[..len]).unwrap_or("")
}

/// How long the requests of ARP wait when the queue of sending is full.
const ASK_RETRY_NS: u64 = 1_000_000;

/// How long after a step the streams that close are looked at again.
const SWEEP_NS: u64 = 1_000_000_000;

/// The methods of the service: PING and CRASH only with the feature
/// `probe`.
#[cfg(feature = "probe")]
const METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 62, 63,
];
#[cfg(not(feature = "probe"))]
const METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
];

impl Driver<'_> {
    /// An item of work (a request or a notification) begins: the run of the thread goes on
    /// through items that follow one another, and once it has lasted `SWITCH_RUN_NS` the thread
    /// pauses `SWITCH_PAUSE_NS` on a wait channel, as the switch does, so that a flood of SYNs
    /// or datagrams for this instance cannot hold its CPU from the processes below its level
    /// (the worker that stands on the same CPU).
    fn begin_item(&mut self) {
        if self.guard.begin(now_ns()) {
            self.pause();
            self.guard.paused(now_ns());
        }
    }

    fn end_item(&mut self) {
        self.guard.end(now_ns());
    }

    fn pause(&mut self) {
        let waited = match &self.pause {
            Some((channel, timer)) => {
                sys::timer_set(timer, now_ns() + netd::ring::SWITCH_PAUSE_NS).is_ok()
                    && sys::receive(channel).is_ok()
            }
            None => false,
        };
        if !waited {
            self.counters_pause_failed += 1;
        }
    }

    fn handle_request(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let began = profile::now();
        let method = r.method();
        trace::point(P_N_REQ_BEGIN, u32::from(method));
        self.inst.net.claim(s, r.label());
        self.inst.net.counters.calls += 1;
        let answer = match Method::from_number(r.method()) {
            Some(Method::Home) => self.home(s, r),
            Some(Method::HomeMake) => self.inst.net.home_make(s, r),
            Some(Method::Config) => self.config(r),
            #[cfg(feature = "probe")]
            Some(Method::Ping) => self.ping(r, stack::ECHO_DATA),
            #[cfg(feature = "probe")]
            Some(Method::PingWire) => self.ping(r, proto_net::PING_WIRE_DATA),
            #[cfg(feature = "probe")]
            Some(Method::Crash) => crash(r),
            #[cfg(feature = "probe")]
            Some(Method::Hold) => self.hold(r),
            Some(Method::Buffer) => self.inst.net.buffer(s, r),
            Some(Method::Claim) => self.claim(s, r),
            Some(Method::ClaimMore) => self.claim_more(s, r),
            Some(Method::Kick) => self.kick(s, r),
            Some(Method::PortHold) => self.port_hold(s, r),
            Some(Method::Attach) => self.attach(s, r),
            Some(Method::Join) => self.join(s, r),
            Some(method) => match sockets::Request::parse(method, r.body()) {
                Some(Ok(call)) => self.inst.net.call(&mut self.inst.stack, s, r, call),
                Some(Err(status)) => Answer::Status(status),
                None => Answer::Status(Status::UnknownMethod),
            },
            None => Answer::Status(Status::UnknownMethod),
        };
        self.after_request();
        trace::point(P_N_REQ_END, u32::from(method));
        profile::call(method, began);
        answer
    }

    fn handle_notification(&mut self, n: Notice) {
        match n.source {
            // Init labels the bindings of a record of two devices
            // (`proto_init::binding_label`): the line says whose interrupt it
            // is, and the step reads that device's status alone.
            Source::Interrupt if n.label == proto_init::binding_label(1) => {
                profile::count(Counter::Irq);
                trace::point(P_N_IRQ1, 0);
                self.rx1_step(true);
            }
            // The first line's interrupts come to the switch thread.
            Source::Interrupt => {}
            Source::Unlabeled if n.bits & STEP_BITS != 0 => {
                // One step at a time: the first bit in this order, and the
                // others are told again, so that a request waits for the
                // step that is on.
                let order = [RX, RX1, TX, WAKE, CLEANUP, SWEEP, RESOLV, RETURN, BACK, MAP];
                let at =
                    netd::ring::next_bit(&order, n.bits & STEP_BITS, self.last_step).unwrap_or(0);
                self.last_step = at;
                let bit = order[at];
                let rest = n.bits & STEP_BITS & !bit;
                self.told &= !bit;
                if rest != 0 && sys::notify(&self.notify, rest).is_err() {
                    self.told &= !rest;
                    self.cleanup_due |= rest & CLEANUP != 0;
                }
                let began = profile::now();
                trace::point(P_N_STK_BEGIN, bit as u32);
                match bit {
                    RX => self.rx_step(),
                    RX1 => {
                        self.rx1_step(false);
                    }
                    RETURN => self.return_step(),
                    BACK => self.back_step(),
                    MAP => {
                        rt::service::step_own();
                        if self.inst.net.map_waiting() {
                            self.tell(MAP);
                        }
                    }
                    TX => self.tx_step(false),
                    WAKE => {
                        rt::service::step_own();
                        profile::count(Counter::StepWake);
                        #[cfg(feature = "probe")]
                        let began = self.ran();
                        let left = self.inst.net.wake(&mut self.inst.stack, now_ns());
                        #[cfg(feature = "probe")]
                        self.measured(0, began);
                        if left {
                            self.tell(WAKE);
                        }
                    }
                    CLEANUP => {
                        rt::service::step_own();
                        profile::count(Counter::StepCleanup);
                        #[cfg(feature = "probe")]
                        let began = self.ran();
                        let more = self.inst.net.depart_step(&mut self.inst.stack);
                        #[cfg(feature = "probe")]
                        self.measured(1, began);
                        if more {
                            self.cleanup();
                        }
                    }
                    RESOLV => {
                        profile::count(Counter::StepResolv);
                        self.resolv_step()
                    }
                    _ => {
                        rt::service::step_own();
                        profile::count(Counter::StepSweep);
                        if self.inst.net.sweep(&mut self.inst.stack, now_ns()) {
                            self.tell(SWEEP);
                        }
                    }
                }
                let kind = match bit {
                    RX => Counter::StepRxTicks,
                    TX => Counter::StepTxTicks,
                    _ => Counter::StepOtherTicks,
                };
                profile::add(kind, profile::now().saturating_sub(began));
                trace::point(P_N_STK_END, bit as u32);
                self.after_request();
            }
            Source::Timer if n.label == TIMER_LABEL => {
                profile::count(Counter::StepTimer);
                self.armed = None;
                self.bell.timer_gone();
                let now = now_ns();
                self.inst.net.expire(now);
                if self
                    .second
                    .as_deref()
                    .is_some_and(|s| s.next_at.is_some_and(|at| at <= now))
                {
                    self.tell(RX1);
                }
                let began = profile::now();
                self.tx_step(true);
                profile::add(Counter::StepTxTicks, profile::now().saturating_sub(began));
                self.after_request();
            }
            _ => {}
        }
    }
}

impl Service<0> for Driver<'_> {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = Client;

    fn request(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        self.begin_item();
        let answer = self.handle_request(s, r);
        self.end_item();
        answer
    }

    /// The client of `s` went: its operations go, and its descriptions are
    /// let go of in steps.
    fn gone(&mut self, s: &mut Session<Client, 0>) {
        rt::service::step_own();
        // The owner of the second device went: the device comes back.
        self.owner_gone(s);
        self.consumer_gone(s);
        let held = core::mem::take(&mut s.data.held);
        let long = core::mem::take(&mut s.data.long);
        // The shared buffer is unmapped by a step of departure.
        if self.inst.net.retire_buffer(s) {
            self.cleanup();
        }
        // The interest sets of the session go with it, their records in steps.
        if self.inst.net.interest.sets_of(s.label()) != 0 {
            self.inst.net.interest.drop_sets_of(s.label());
            self.cleanup();
        }
        if self.inst.net.depart(&mut self.inst.stack, held, long) {
            self.cleanup();
        }
        self.inst.net.step_due = true;
        self.after_request();
    }

    /// The last copy of a session Clone made went before it sent anything.
    fn closed(&mut self, label: u64) {
        rt::service::step_own();
        // The last copy of a pass: its reference of the place goes.
        if netd::passes::Passes::is_pass(label) {
            self.inst.net.pass_gone(&mut self.inst.stack, label);
            self.after_request();
            return;
        }
        if let Some(held) = self.inst.net.unborn(label)
            && self
                .inst
                .net
                .depart(&mut self.inst.stack, held, LongSession::default())
        {
            self.cleanup();
        }
        self.after_request();
    }

    fn between_notifications(&mut self, _: Notice) {
        self.bell_release();
        self.bell_checked = false;
    }

    fn between_requests(&mut self) {
        self.bell_release();
        self.bell_checked = false;
        // The totals a request asked for (`GETOPT BUFFERED`): said after its step ended and its
        // answer went, so that the lines of the console do not count in the step.
        #[cfg(any(feature = "profile", feature = "probe", feature = "trace"))]
        if core::mem::take(&mut self.inst.net.profile_due) {
            #[cfg(feature = "probe")]
            self.report_frames();
            #[cfg(feature = "profile")]
            self.profile_snapshot();
            #[cfg(feature = "trace")]
            trace_dump(&mut self.kernel_stamps);
        }
        // The report CONFIG asked for, likewise.
        #[cfg(feature = "probe")]
        if core::mem::take(&mut self.report_due) {
            self.report_frames();
            // The probe image with the profile prints the totals here, so that
            // a boot of it checks that the records come whole.
            #[cfg(feature = "profile")]
            self.profile_snapshot();
        }
    }

    fn notification(&mut self, n: Notice) {
        self.begin_item();
        self.handle_notification(n);
        self.end_item();
    }
}

/// CRASH: a load from page 0 ends the service with a fault while the
/// device still has its queues; init stops the device before it lets the
/// DMA objects go, and starts the service again.
#[cfg(feature = "probe")]
fn crash(r: &Request<'_>) -> Answer {
    if r.body().finish().is_err() {
        return Answer::Status(Status::BadSize);
    }
    // SAFETY: the load is the fault the method exists for; the thread
    // never runs after it.
    unsafe {
        core::arch::asm!(
            "ldr {t}, [{a}]",
            t = out(reg) _,
            a = in(reg) 0_usize,
            options(nostack, readonly),
        )
    };
    Answer::Status(Status::Kernel(abi::Error::BadState))
}

/// A part of the ring of time stamps to the console (each `posix-net stat` gives the next part,
/// and the line `tr n done` ends the dump), as `tr n ...` lines packed into records of the kernel's
/// log (64 bytes each). The console's service takes 64 records of the log every 50 ms and loses the
/// rest, so the dump writes 60 records, then waits 52 ms (it runs after the load: the wait costs
/// only its time; the wait yields, the service may stand on this CPU). A part is at most 1 500
/// lines, about half a second: init kills a service that stays silent for longer. The first part
/// freezes the rings of the kernel, and once the ring of the service has gone the parts that
/// follow give those of the kernel (kdump.rs; `tr k done` ends them).
#[cfg(feature = "trace")]
fn trace_dump(kernel: &mut kdump::KernelDump) {
    // The first part stops the rings of the service and of the kernel: the long dump that follows
    // would otherwise read records of the idle loop in the places of the load's.
    trace::freeze();
    kernel.freeze();
    let (mut buf, mut len, mut records) = ([0u8; 64], 0, 0u32);
    // The kernel's part goes slower still: a record lost on the console breaks a chain of the
    // analysis, and a part of 800 lines at this pace stays under the silence init allows.
    let (per, lines) = if kernel.is_open() && NET_DONE.load(core::sync::atomic::Ordering::Relaxed) {
        (40, 800)
    } else {
        (60, 1_500)
    };
    let mut write = |bytes: &[u8]| {
        let _ = rt::console::write(bytes);
        records += 1;
        if records % per == 0 {
            let began = rt::time::now();
            while rt::time::now().wrapping_sub(began) < 52 * rt::time::frequency() / 1000 {
                let _ = rt::sys::yield_now();
            }
        }
    };
    let mut emit = |line: &str| {
        if len + line.len() + 1 > buf.len() {
            write(&buf[..len]);
            len = 0;
        }
        buf[len..len + line.len()].copy_from_slice(line.as_bytes());
        buf[len + line.len()] = b'\n';
        len += line.len() + 1;
    };
    if kernel.is_open() && NET_DONE.load(core::sync::atomic::Ordering::Relaxed) {
        kernel.part(lines, &mut emit);
        write(&buf[..len]);
        return;
    }
    let done = trace::dump_part("n", lines, trace::RECORDS, &mut emit);
    write(&buf[..len]);
    if done {
        NET_DONE.store(true, core::sync::atomic::Ordering::Relaxed);
        rt::println!("tr n done");
    }
}

/// The ring of the service has gone: the parts that follow are the kernel's.
#[cfg(feature = "trace")]
static NET_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
