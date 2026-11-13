// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The network service with an ENA device (the start data holds the objects
//! `ena` and `net`): the second kind of device after Virtio, with the whole
//! of the service over it, one stack instance and one queue pair.
//!
//! Three threads. The first one is the admin thread: it owns the driver's admin
//! side (`ena::Ena`: reset, the admin queue, the features, the queues, the
//! MSI-X table, the keep-alive and the watchdog, the reset in place), runs it
//! on a timer and on the notifications of vector 0, and never touches a ring of
//! data. The switch thread (`ena_switch.rs`, one level above the stack) owns the
//! pair's rings, the doorbells and vector 1. The stack instance is the one of
//! the Virtio kinds. The admin side tells the switch thread that the pair is
//! up or down by an epoch (`IO_EPOCH`, odd while down) and the registers of its
//! doorbells (`io_info`).
//!
//! The device is brought up before the stack is built, since the stack takes
//! the device's MAC: the first thread runs the admin side to `Up` with a
//! heartbeat to init on the way. The key of the stack has no entropy service on
//! EC2 (the t4g has no device of random bytes): `local_key` mixes the counters
//! of the machine, and the PR of this step says it is weak.

use crate::device::{NetDevice, RxRing, TxRing};
use crate::dma::net_at;
use crate::ena_switch::{self, EnaSwitch};
use crate::instance::{self, Instance};
use crate::{
    DRIVERS, Driver, NO_CONFIG, NO_DEVICE, NO_START_DATA, NOT_MAPPED, NOT_REGISTERED, NOT_STARTED,
    TABLES, Tables, announce_static, demux_secret, instance_entry, make_pause, plan_instances,
    word,
};
use abi::{Access, Rights, Source};
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use ena::io::{Buffers, Info};
use ena::mmio::Bar;
use ena::{Ena, Event, Platform, Region};
use netd::enawire::Wire;
use netd::ring::NET_PAGES;
use proto_init::ServiceArgs;
use rt::handle::{Channel, Interrupt, Memory, Timer};
use rt::service::{Config, Heartbeat};
use rt::{Handle, sys, time};

/// Where the service maps what init gives it (`dma.rs` keeps the rest free).
const ENA_AT: usize = 0x10_0000_0000;
const BAR_AT: usize = 0x10_1000_0000;
const ECAM_AT: usize = 0x10_2000_0000;
const PAGE: u64 = 4096;
const TIMER_LABEL: u64 = 1;
/// The step of the admin side once the device runs: half the watchdog's 100 ms. The tick
/// while it comes up: a read through memory takes a step each.
const TICK_NS: u64 = 50_000_000;
const BRINGUP_TICK_NS: u64 = 500_000;
/// The steps one notification takes at most. A step never waits (`ena::Ena::poll`) and makes
/// at most `REG_ACCESSES_PER_STEP` access to a register and reads at most `EVENTS_PER_STEP`
/// event entries (`LOADS_PER_ENTRY` loads of the device's memory each) and a few admin
/// entries (`LOADS_PER_ADMIN`). Two steps store besides: the one after a reset zeroes the
/// admin structures with `RESET_ZERO_STORES` 64-bit stores, and the one that gives the host
/// info writes `HOST_STORES` stores; the steps that zero the queues store `IO_STORES / 4`
/// each, below the first. A notification of 8 steps is bounded by every step reading and
/// every storing step, 1 us an access at most, under a quarter of the step bound of the
/// service (`netd::choose::BOUND`). The admin side is this thread's alone, and the switch of
/// the service does not call it.
const STEPS: u32 = 8;
const LOADS_PER_ENTRY: u32 = 16;
const LOADS_PER_ADMIN: u32 = 16;
const _: () = assert!(
    STEPS
        * (ena::device::REG_ACCESSES_PER_STEP
            + ena::device::EVENTS_PER_STEP * LOADS_PER_ENTRY
            + LOADS_PER_ADMIN)
        + ena::device::RESET_ZERO_STORES
        + ena::device::HOST_STORES
        <= (netd::choose::BOUND / 4) as u32
);
const _: () = assert!(ena::io::IO_STORES / 4 <= ena::device::RESET_ZERO_STORES);
/// How long the mapping of an event may take before the table is programmed anyway.
const MAPPED_LIMIT_NS: u64 = 2_000_000_000;
/// The longest the bring-up may take before the service gives up.
const BRINGUP_LIMIT_NS: u64 = 20_000_000_000;
/// The keep-alives (one a second) after which a device with vectors and no interrupt is
/// rebuilt.
const SILENCE_KEEPALIVES: u64 = 6;
/// The code the service ends with when the device cannot be recovered (three failed resets
/// in a minute); init stops the device and starts the service again.
const FAILED: u64 = 8;
/// The MSI-X table lies at this offset of BAR 0 on the ENA (`iomem` and the capability of
/// the t4g.small).
const MSIX_TABLE_OFFSET: u32 = 0x2000;
/// The vectors the service uses: the admin one and the pair's.
const VECTORS: u16 = 2;
/// The notification bit that wakes the admin thread.
const ADMIN_BIT: u64 = 1;

// What the admin thread tells the switch thread, and the other way round.
/// The pair's epoch: odd while the queues are not usable, even and new for each pair.
pub static IO_EPOCH: AtomicU32 = AtomicU32::new(1);
static INFO: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];
static RESET_ASK: AtomicBool = AtomicBool::new(false);
/// No interrupt came although the device has vectors, even after a rebuild: the switch thread
/// looks at the queue every 500 us where it looked every 100 ms (the data path works, by polling).
pub static POLL_FALLBACK: AtomicBool = AtomicBool::new(false);
pub static SWITCH_RAW: AtomicU64 = AtomicU64::new(0);
static ADMIN_RAW: AtomicU64 = AtomicU64::new(0);

/// The counters the switch thread keeps and the admin thread says.
pub struct Stats {
    pub irq: [AtomicU64; 2],
    pub rx_irq: AtomicU64,
    pub rx_timer: AtomicU64,
    pub rx_other: AtomicU64,
}
pub static STATS: Stats = Stats {
    irq: [const { AtomicU64::new(0) }; 2],
    rx_irq: AtomicU64::new(0),
    rx_timer: AtomicU64::new(0),
    rx_other: AtomicU64::new(0),
};

/// What the admin side found of the pair, once it is up.
pub fn io_info() -> Info {
    Info {
        tx_db: INFO[0].load(Ordering::Relaxed),
        rx_db: INFO[1].load(Ordering::Relaxed),
        tx_cq_head_db: INFO[2].load(Ordering::Relaxed),
        rx_cq_head_db: INFO[3].load(Ordering::Relaxed),
        rx_unmask: INFO[4].load(Ordering::Relaxed),
    }
}

/// The switch thread found the pair out of step: the admin side resets the device.
pub fn ask_reset() {
    RESET_ASK.store(true, Ordering::Release);
    wake_admin();
}

pub fn wake_admin() {
    let raw = ADMIN_RAW.load(Ordering::Acquire);
    if raw != 0 {
        let channel = Handle::<Channel>::borrowed(rt::abi::Handle(raw));
        let _ = sys::notify(&channel, ADMIN_BIT);
    }
}

fn wake_switch() {
    let raw = SWITCH_RAW.load(Ordering::Acquire);
    if raw != 0 {
        let channel = Handle::<Channel>::borrowed(rt::abi::Handle(raw));
        let _ = sys::notify(&channel, ena_switch::EPOCH_BIT);
    }
}

/// The platform of both sides: BAR 0, the clock, the barriers, the vectors' messages (from
/// the bindings, read once) and the place of the MSI-X capability in the function's page.
#[derive(Clone, Copy)]
pub struct Hw {
    bar: Bar,
    msi: [Option<(u64, u32)>; 2],
    msix_at: Option<usize>,
    /// The pending bit array of the vectors: its offset in BAR 0.
    pba: Option<u32>,
}

impl Platform for Hw {
    fn read32(&self, offset: u32) -> u32 {
        self.bar.read32(offset)
    }

    fn write32(&self, offset: u32, value: u32) {
        self.bar.write32(offset, value);
    }

    fn now_ns(&self) -> u64 {
        time::ticks_to_ns(time::now())
    }

    fn wmb(&self) {
        rt::dma::wmb();
    }

    fn rmb(&self) {
        rt::dma::rmb();
    }

    fn log(&self, line: fmt::Arguments<'_>) {
        rt::println!("{line}");
    }

    fn msi(&self, vector: u16) -> Option<(u64, u32)> {
        self.msi.get(usize::from(vector)).copied().flatten()
    }

    fn msix_control(&self, enable: bool, function_mask: bool) {
        let Some(at) = self.msix_at else {
            return;
        };
        // SAFETY: the page of the function is mapped at ECAM_AT, read and write, as device
        // memory (`run`); `at` is the first word of its MSI-X capability, which `pci::msix`
        // found. Memory decoding and bus mastering were turned on by init; INTx stays off.
        unsafe {
            let mut word = rt::mmio::read32(ECAM_AT + at);
            word &= !(::pci::MSIX_ENABLE | ::pci::MSIX_FUNCTION_MASK);
            if enable {
                word |= ::pci::MSIX_ENABLE;
            }
            if function_mask {
                word |= ::pci::MSIX_FUNCTION_MASK;
            }
            rt::mmio::write32(ECAM_AT + at, word);
        }
    }

    fn io_state(&self, up: Option<&Info>) {
        let epoch = IO_EPOCH.load(Ordering::Relaxed);
        match up {
            Some(info) => {
                for (cell, value) in INFO.iter().zip([
                    info.tx_db,
                    info.rx_db,
                    info.tx_cq_head_db,
                    info.rx_cq_head_db,
                    info.rx_unmask,
                ]) {
                    cell.store(value, Ordering::Relaxed);
                }
                // Odd to even: a new pair.
                if epoch % 2 == 1 {
                    IO_EPOCH.store(epoch + 1, Ordering::Release);
                }
            }
            None => {
                if epoch.is_multiple_of(2) {
                    IO_EPOCH.store(epoch + 1, Ordering::Release);
                }
            }
        }
        wake_switch();
    }
}

/// The key of the stack from the counters of the machine and the MAC: the t4g has no device
/// of random bytes and the image has no entropy service. Weak: the sequence numbers and the
/// ports it seeds are guessable by an attacker who knows the boot time.
fn local_key(mac: [u8; 6]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut sample = [0u8; 16];
    for (n, chunk) in out.chunks_mut(16).enumerate() {
        // The counter read a few times, each after some work of the thread.
        let mut a = time::now();
        for _ in 0..64 {
            a = a.rotate_left(7) ^ time::now();
        }
        sample[..8].copy_from_slice(&a.to_le_bytes());
        sample[8..14].copy_from_slice(&mac);
        sample[14] = n as u8;
        sample[15] = (core::ptr::addr_of!(sample) as usize >> 4) as u8;
        chunk.copy_from_slice(&demux_secret(&sample, b"ena-local-key"));
    }
    out
}

fn heartbeat(parent: &Handle<Channel>) {
    let _ = sys::send(parent, &proto_init::Method::Heartbeat.header().bytes());
}

/// The messages of the vectors, the place of the capability in the page of the function and
/// the offset of the pending bit array.
type MsiPlan = ([Option<(u64, u32)>; 2], Option<usize>, Option<u32>);

/// The messages of the vectors from the bindings, and whether the table can be used: the
/// capability must be where the driver writes (BAR 0, offset 0x2000) and hold both vectors.
fn msi_plan(irq: &[Option<Handle<Interrupt>>; 2]) -> MsiPlan {
    let none = ([None, None], None, None);
    // SAFETY: the page of the function is mapped at ECAM_AT as device memory; the offsets the
    // capability list gives are inside it (`pci::msix` stops at 48 capabilities).
    let found = ::pci::msix(|offset| unsafe { rt::mmio::read32(ECAM_AT + offset) });
    let Some(msix) = found else {
        rt::println!("ena: no MSI-X capability: polling");
        return none;
    };
    if let Err(why) = netd::enawire::msix_table(&msix, MSIX_TABLE_OFFSET, VECTORS) {
        rt::println!("ena: the MSI-X table is not where the driver writes: {why}: polling");
        return none;
    }
    let mut messages = [None, None];
    for (v, binding) in irq.iter().enumerate() {
        let Some(binding) = binding else {
            rt::println!("ena: no binding for vector {v}: polling");
            return none;
        };
        match sys::irq_info(binding) {
            Ok(info) if info.lpi => messages[v] = Some((info.msi_address, info.msi_data as u32)),
            _ => {
                rt::println!("ena: the binding of vector {v} is no LPI: polling");
                return none;
            }
        }
    }
    (
        messages,
        Some(msix.at),
        (msix.pba_bar == 0).then_some(msix.pba_offset),
    )
}

/// Waits (at most `MAPPED_LIMIT_NS`, with a heartbeat on the way) until the ITS has run the
/// commands of each binding's event: `irq_ack` says `WOULD_BLOCK` until it has. A message the
/// device writes before that is lost, so the table is programmed once it is done.
fn wait_mapped(
    irq: &[Option<Handle<Interrupt>>; 2],
    parent: &Handle<Channel>,
    channel: &Handle<Channel>,
    timer: &Handle<Timer>,
) {
    let began = time::ticks_to_ns(time::now());
    for (v, binding) in irq.iter().enumerate() {
        let Some(binding) = binding else {
            continue;
        };
        let mut waits = 0u32;
        while let Err(abi::Error::WouldBlock) = sys::irq_ack(binding) {
            let now = time::ticks_to_ns(time::now());
            if now - began > MAPPED_LIMIT_NS {
                rt::println!("ena: the mapping of vector {v} is not done after 2 s");
                return;
            }
            waits += 1;
            heartbeat(parent);
            let _ = sys::timer_set(timer, now + BRINGUP_TICK_NS);
            let _ = sys::receive(channel);
        }
        if waits > 0 {
            rt::println!("ena: vector {v} mapped after {waits} waits");
        }
    }
}

/// What the function and the bindings say of the vectors once the device is up, for the
/// console: the capability's first word, the table entries and the bindings' LPIs.
fn say_msix(hw: &Hw, irq: &[Option<Handle<Interrupt>>; 2]) {
    let Some(at) = hw.msix_at else {
        return;
    };
    // SAFETY: the page of the function is mapped at ECAM_AT as device memory (`run`); `at` is
    // the MSI-X capability the walk found.
    let head = unsafe { rt::mmio::read32(ECAM_AT + at) };
    // SAFETY: as above; offset 4 is the command word of the function.
    let command = unsafe { rt::mmio::read32(ECAM_AT + 4) };
    rt::println!("ena: msix cap {head:#x} command {command:#x}");
    for v in 0..2u32 {
        let base = MSIX_TABLE_OFFSET + 16 * v;
        let words = [0, 4, 8, 12].map(|o| hw.bar.read32(base + o));
        let lpi = irq[v as usize]
            .as_ref()
            .and_then(|b| sys::irq_info(b).ok())
            .map_or((0, 0), |i| (i.lpi_number, i.cpu));
        rt::println!(
            "ena: msix vector {v} {:#x} {:#x} {:#x} {:#x}; lpi {} cpu {}",
            words[0],
            words[1],
            words[2],
            words[3],
            lpi.0,
            lpi.1
        );
    }
}

/// Runs the admin side until the device is up; false when it failed or took too long.
fn bring_up(
    ena: &mut Ena<Hw>,
    parent: &Handle<Channel>,
    channel: &Handle<Channel>,
    timer: &Handle<Timer>,
) -> bool {
    let began = time::ticks_to_ns(time::now());
    let mut beat = began;
    loop {
        let now = time::ticks_to_ns(time::now());
        if now - began > BRINGUP_LIMIT_NS {
            rt::println!("ena: the bring-up took too long");
            return false;
        }
        if now - beat > 200_000_000 {
            beat = now;
            heartbeat(parent);
        }
        match ena.poll() {
            Event::Up => return true,
            Event::Failed(_) => return false,
            Event::Idle => {
                let _ = sys::timer_set(timer, now + BRINGUP_TICK_NS);
                let _ = sys::receive(channel);
            }
            _ => {}
        }
    }
}

struct Admin {
    ena: Ena<Hw>,
    channel: Handle<Channel>,
    timer: Handle<Timer>,
    deadline: u64,
    stats_at: u64,
    stats_count: u32,
    /// The device has vectors, and a rebuild for silence was tried (once).
    msi: bool,
    silent_tried: bool,
    /// The probe's deliberate break: after the first start the head of the event queue is
    /// not written back, until the reset it causes.
    #[cfg(feature = "ena-break-aenq")]
    broken: bool,
    /// The probe of a restart (`ena-break-exit`): the uptime at which this instance began.
    #[cfg(feature = "ena-break-exit")]
    born_ns: u64,
}

/// The probe of a restart (`ena-break-exit`): the instance that began before this uptime
/// exits with FAILED once the device is up and the uptime reaches it, so init stops the device
/// and starts the service again; the next instance begins after it and runs on.
#[cfg(feature = "ena-break-exit")]
const BREAK_EXIT_NS: u64 = 40_000_000_000;

impl Admin {
    fn arm(&mut self) {
        let now = time::ticks_to_ns(time::now());
        let tick = if self.ena.is_up() {
            TICK_NS
        } else {
            BRINGUP_TICK_NS
        };
        self.deadline = now + tick;
        let _ = sys::timer_set(&self.timer, self.deadline);
    }

    fn step(&mut self) {
        if RESET_ASK.swap(false, Ordering::AcqRel) {
            rt::println!("ena: the switch asks for a reset");
            self.ena
                .request_reset(ena::regs::RESET_DRIVER_INVALID_STATE);
        }
        for _ in 0..STEPS {
            match self.ena.poll() {
                Event::Idle => break,
                Event::Failed(_) => sys::process_exit(FAILED),
                #[cfg(feature = "ena-break-aenq")]
                Event::Up if !self.broken => {
                    self.broken = true;
                    self.ena.hold_event_head(true);
                    rt::println!("ena: break: the event head is held");
                }
                #[cfg(feature = "ena-break-aenq")]
                Event::Resetting(_) => self.ena.hold_event_head(false),
                _ => {}
            }
        }
        #[cfg(feature = "ena-break-exit")]
        {
            let now = time::ticks_to_ns(time::now());
            if self.ena.is_up() && self.born_ns < BREAK_EXIT_NS && now >= BREAK_EXIT_NS {
                rt::println!(
                    "ena: break: the service exits, uptime {} s",
                    now / 1_000_000_000
                );
                sys::process_exit(FAILED);
            }
        }
        self.check_silence();
        self.say_stats();
    }

    /// The device has vectors, has said keep-alives for a while and no interrupt came: the
    /// table is written again once with the sequence of the first fill (masked, rewritten,
    /// unmasked), which makes the hypervisor install the route of the messages again.
    fn check_silence(&mut self) {
        if !self.msi || !self.ena.is_up() {
            return;
        }
        let heard = STATS.irq[0].load(Ordering::Relaxed) + STATS.irq[1].load(Ordering::Relaxed);
        if self.silent_tried {
            // Still silent after the toggle: poll quickly from now on.
            if heard == 0
                && self.ena.keep_alive().count >= 2 * SILENCE_KEEPALIVES
                && !POLL_FALLBACK.swap(true, Ordering::AcqRel)
            {
                rt::println!("ena: still no interrupt: the queue is polled every 500 us");
            }
            return;
        }
        if heard == 0 && self.ena.keep_alive().count >= SILENCE_KEEPALIVES {
            self.silent_tried = true;
            rt::println!(
                "ena: no interrupt after {SILENCE_KEEPALIVES} keep-alives: the table is toggled"
            );
            self.ena.request_msix_toggle();
        }
    }

    /// The counters of the data path, every 10 s for three minutes and then every minute.
    fn say_stats(&mut self) {
        let now = time::ticks_to_ns(time::now());
        let every = if self.stats_count < 18 {
            10_000_000_000
        } else {
            60_000_000_000
        };
        if now < self.stats_at + every || !self.ena.is_up() {
            return;
        }
        self.stats_at = now;
        self.stats_count += 1;
        let ka = self.ena.keep_alive();
        // The pending bits of the vectors: set while an interrupt is held back by a mask.
        if let Some(pba) = self.ena.platform().pba {
            let bar = self.ena.platform().bar;
            rt::println!("ena: pba {:#x} {:#x}", bar.read32(pba), bar.read32(pba + 4));
        }
        rt::println!(
            "ena: stats irq0 {} irq1 {} rx by irq {} timer {} other {} keepalive {} resets {}",
            STATS.irq[0].load(Ordering::Relaxed),
            STATS.irq[1].load(Ordering::Relaxed),
            STATS.rx_irq.load(Ordering::Relaxed),
            STATS.rx_timer.load(Ordering::Relaxed),
            STATS.rx_other.load(Ordering::Relaxed),
            ka.count,
            self.ena.resets().count,
        );
    }

    /// The admin thread's loop: a step on the timer or on a notification, for the life of
    /// the service.
    fn run(mut self) -> ! {
        self.arm();
        loop {
            match sys::receive(&self.channel) {
                Ok(sys::Received::Notification { source, label, .. }) => {
                    let timer = source == Source::Timer && label == TIMER_LABEL;
                    if timer && !time::reached(self.deadline) {
                        continue;
                    }
                    self.step();
                    if timer || !self.ena.is_up() {
                        self.arm();
                    }
                }
                Ok(_) => {}
                Err(_) => sys::process_exit(NO_DEVICE),
            }
        }
    }
}

/// Runs the service for the device whose objects the start data holds: the objects `ena` (the
/// admin structures and the queues) and `net` (the buffers), their physical addresses the
/// first two words of the record's own arguments, the windows `bar` (BAR 0) and `ecam` (the
/// page of the function, whose revision byte picks the way registers are read) and the
/// bindings `irq0` and `irq1` of the two vectors.
pub fn run(mut s: rt::startup::Startup, object: Handle<Memory>) -> u64 {
    let Ok(net_object) = s.take::<Memory>("net") else {
        return NO_START_DATA;
    };
    let args = ServiceArgs::read(s.args()).ok();
    let own = args.map_or(&[][..], |a| a.own);
    let (ena_pa, net_pa) = (word(own, 0), word(own, 8));
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    // The admin thread's own channel and timer: a step on the timer and on the notifications
    // of the switch.
    let Ok(admin_channel) = sys::channel_create(level) else {
        return NOT_REGISTERED;
    };
    let Ok(admin_notify) = sys::handle_duplicate(&admin_channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    ADMIN_RAW.store(admin_notify.raw().0, Ordering::Release);
    let Ok(admin_view) = sys::handle_label(&admin_channel, Rights::RECEIVE, TIMER_LABEL, level)
    else {
        return NOT_REGISTERED;
    };
    let Ok(admin_timer) = sys::timer_create(&admin_view, level) else {
        return NOT_REGISTERED;
    };
    // The service's own channel (the instance's loop serves it) with its timer, and the switch
    // thread's, one level above.
    let Ok(channel) = sys::channel_create(level) else {
        return NOT_REGISTERED;
    };
    let Ok(notify) = sys::handle_duplicate(&channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    let Ok(view) = sys::handle_label(&channel, Rights::RECEIVE, crate::TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };
    let Ok(switch_channel) = sys::channel_create(level + 1) else {
        return NOT_REGISTERED;
    };
    let Ok(wake_switch) = sys::handle_duplicate(&switch_channel, Rights::NOTIFY) else {
        return NOT_REGISTERED;
    };
    let settings = match crate::files::read(&s.parent) {
        Ok(settings) => settings,
        Err(crate::files::Failure::Refused(error)) => {
            rt::println!(
                "net: netd.conf line {}: {}",
                error.line,
                error.reason.text()
            );
            return NO_CONFIG;
        }
        Err(crate::files::Failure::Unreadable(error)) => {
            rt::println!("net: netd.conf unreadable: {error:?}");
            return NO_CONFIG;
        }
    };
    if settings.consumers() > 0 {
        rt::println!("net: the ENA kind has no consumers of the switch yet");
        return NO_CONFIG;
    }
    let Ok(mut got) = rt::service::register_with(&s.parent, &channel, Some(&switch_channel)) else {
        return NOT_REGISTERED;
    };
    let (Ok(bar), Ok(ecam)) = (got.take::<Memory>("bar"), got.take::<Memory>("ecam")) else {
        return NO_DEVICE;
    };
    let irq = [
        got.take::<Interrupt>("irq0").ok(),
        got.take::<Interrupt>("irq1").ok(),
    ];
    let ena_len = sys::memory_info(&object).map_or(0, |info| info.size);
    let net_len = NET_PAGES as u64 * PAGE;
    let rw = Access::ReadWrite;
    if ena_pa == 0
        || net_pa == 0
        || sys::mem_map(&s.process, &object, 0, ena_len, ENA_AT, rw).is_err()
        || sys::mem_map(&s.process, &net_object, 0, net_len, net_at(0), rw).is_err()
        || sys::mem_map(&s.process, &bar, 0, 4 * PAGE, BAR_AT, rw).is_err()
        || sys::mem_map(&s.process, &ecam, 0, PAGE, ECAM_AT, rw).is_err()
    {
        return NOT_MAPPED;
    }
    // SAFETY: the page of the function is mapped at ECAM_AT as device memory; offset 8 is its
    // revision and class word. Memory decoding and bus mastering were turned on by init when
    // it started this instance.
    let revision = unsafe { rt::mmio::read32(ECAM_AT + 8) } as u8;
    let (messages, msix_at, pba) = msi_plan(&irq);
    let msi = msix_at.is_some();
    if msix_at.is_some() {
        wait_mapped(&irq, &s.parent, &admin_channel, &admin_timer);
    }
    let hw = Hw {
        bar: {
            // SAFETY: BAR 0 is mapped at BAR_AT for 4 pages (the window of init's table).
            unsafe { Bar::new(BAR_AT, 4 * PAGE as usize) }
        },
        msi: messages,
        msix_at,
        pba,
    };
    let region = Region {
        va: ENA_AT,
        pa: ena_pa,
        len: ena_len as usize,
    };
    // SAFETY: the object is mapped at ENA_AT for `ena_len` bytes, uncached, and the admin and
    // the switch threads alone use it; the device addresses it at `ena_pa`, as init's reply to
    // the creation of the object says.
    let opened = unsafe { Ena::open(hw, region, revision) };
    let Ok(mut ena) = opened else {
        rt::println!("ena: the object does not fit the driver");
        return NO_DEVICE;
    };
    let bufs = Buffers {
        va: net_at(0),
        pa: net_pa,
        count: (net_len / ena::io::BUFFER_LEN as u64) as u16,
    };
    let table = msix_at.map(|_| MSIX_TABLE_OFFSET);
    if ena.set_data_path(bufs, table).is_err() {
        rt::println!("ena: the object of the queues is too small");
        return NO_DEVICE;
    }
    // The host info names the CPUs of the service; the function's bus, device and function
    // number are not known here (init finds the function), so 0.
    ena.set_host(0, 2);
    rt::println!(
        "ena: pci revision {revision:#x}, objects {ena_pa:#x}+{ena_len:#x} {net_pa:#x}+{net_len:#x}, msi {}",
        if msix_at.is_some() { "yes" } else { "no" }
    );
    if !bring_up(&mut ena, &s.parent, &admin_channel, &admin_timer) {
        return NO_DEVICE;
    }
    #[cfg(feature = "ena-break-aenq")]
    {
        ena.hold_event_head(true);
        rt::println!("ena: break: the event head is held");
    }
    let mac = ena.info().mac;
    if msix_at.is_some() {
        say_msix(&hw, &irq);
    }
    rt::println!(
        "net: ena mac {}, link {}",
        netd::lines::Mac(mac),
        ena.link()
            .map_or("unknown", |up| if up { "up" } else { "down" })
    );

    // One stack instance (the lane of the one queue pair).
    let (cpus, instances, extra) = match plan_instances(&settings, true, level) {
        Ok(plan) => plan,
        Err(code) => return code,
    };
    debug_assert!(instances == 1 && extra.iter().all(Option::is_none));
    let key = local_key(mac);
    let mut first = [0; 8];
    first.copy_from_slice(&key[..8]);
    let random_seed = u64::from_le_bytes(first);
    let mut ports_key = [0; 16];
    ports_key.copy_from_slice(&key[8..24]);
    let demux_key = demux_secret(&ports_key, &key[24..32]);
    // SAFETY: only this thread reaches TABLES, here once; the pointer is to zeroed memory of
    // the static.
    let tables = unsafe {
        let pointer = (*TABLES.0.get()).as_mut_ptr();
        let channels: [&Handle<Channel>; netd::switchlogic::tables::MAX_INSTANCES] =
            [&channel; netd::switchlogic::tables::MAX_INSTANCES];
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
        ..
    } = tables;
    let lane = &crate::switch::INNER.lanes[netd::switchlogic::route::DEFAULT_INSTANCE];
    let mut device = NetDevice::new(RxRing::inner(lane), TxRing::inner(lane), mac);
    let (Some(storage0), Some(net0), Some(sessions0)) = (
        storages.iter_mut().next(),
        nets.iter_mut().next(),
        sessions.iter_mut().next(),
    ) else {
        return NOT_STARTED;
    };
    let now = crate::now_ns();
    let mut stack = crate::Stack::new(
        storage0,
        &mut device,
        mac,
        random_seed,
        now,
        settings.address.is_none(),
    );
    announce_static(&mut stack, &settings);
    net0.external = stack.lease.map(|lease| lease.address);
    let (own_addresses, own_count) = stack.addresses();
    device.set_addresses(&own_addresses[..own_count]);
    device.seed_neighbours();
    netd::published::ADDRESS.publish(crate::stack::record_of(stack.lease).as_ref());
    crate::switch::INNER.lanes[0].set_stack_channel(notify.raw().0);

    // The switch thread: the wire over the pair, whose first epoch is odd (down) until the
    // admin side's `Up` of this bring-up has been seen (it was: the epoch is even already).
    let wire = Wire::new(hw, region, bufs);
    let Some(switch) = EnaSwitch::new(wire, switch_channel, irq, msi, level + 1) else {
        return NOT_STARTED;
    };
    let Ok(switch_thread) = ena_switch::start(switch, &s.process, level + 1, &wake_switch) else {
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
        crate::consumers::Side::new(0, None, crate::consumers::GATE_PRIORITY),
        #[cfg(feature = "trace")]
        crate::kdump::KernelDump::new(None),
    );
    driver0.pause = make_pause(level);
    driver0.cpus = cpus;
    driver0.instances = instances;
    driver0.routed = false;
    driver0.switch = Some((switch_thread, wake_switch));
    let mut free_slots = DRIVERS.fill().iter_mut();
    let driver = free_slots.next().expect("a slot").write(driver0);
    let mut launch = Some(instance::Launch {
        driver,
        channel: &channel,
        config: Some(Config {
            issued: 0,
            heartbeat: Some(Heartbeat {
                to: &s.parent,
                period_ns: args.map_or(0, |a| a.period_ns),
                priority: level,
            }),
        }),
        sessions: sessions0,
        entry: instance_entry,
    });
    let launch = launch.as_mut().expect("made");
    if instance::start(launch, &s.process, level, 0, None).is_err() {
        return NOT_STARTED;
    }
    // The root for the loaders goes to the process service from a thread of its own.
    crate::roots::start(&s.process, &s.parent, &channel, level);
    // The first thread is the admin thread from here on.
    let admin = Admin {
        ena,
        msi,
        silent_tried: false,
        channel: admin_channel,
        timer: admin_timer,
        deadline: 0,
        stats_at: time::ticks_to_ns(time::now()),
        stats_count: 0,
        #[cfg(feature = "ena-break-aenq")]
        broken: true,
        #[cfg(feature = "ena-break-exit")]
        born_ns: time::ticks_to_ns(time::now()),
    };
    // The memory the threads use lives as long as this one, which never returns.
    let _keep = (object, net_object, bar, ecam, admin_view, admin_notify);
    admin.run()
}
