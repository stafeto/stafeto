// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The device: reset, identification, the admin queue by polling, the
//! asynchronous event queue, the watchdog and the reset in place, as one
//! state machine that `Ena::poll` advances one step at a time. A step reads
//! or writes a few registers or entries and returns; every wait is a
//! deadline against `Platform::now_ns` checked by the next step, so a caller
//! that must stay short (the switch of `netd`) never stands in a wait.
//!
//! The order of the bring-up is the one the note `2026-11-13-aws-ena.md`
//! gives: the read mode, `DEV_STS.READY`, the reset with its two waits,
//! the version and capabilities, the queues, the features, the event
//! groups, the MTU. A reset in place runs the same path again on the
//! same memory, from `Stage::Begin` with the cause the watchdog found.

use crate::admin::{self as adm};
use crate::regs;
use core::fmt;

/// What the device and the platform give the driver: the 32-bit registers
/// of BAR 0 (each a single `ldr` or `str`, no writeback [G34]), a clock,
/// the barriers that order stores to the rings against a register write and
/// a register read against loads from the rings, and the console line.
pub trait Platform {
    fn read32(&self, offset: u32) -> u32;
    fn write32(&self, offset: u32, value: u32);
    fn now_ns(&self) -> u64;
    /// `dmb oshst`: the stores to the rings come before the write that follows.
    fn wmb(&self) {}
    /// `dmb oshld`: the loads after this see what the device stored before the
    /// register read that gave the phase.
    fn rmb(&self) {}
    fn log(&self, line: fmt::Arguments<'_>);
}

/// A piece of memory the device reads and writes: `len` bytes at `va` in
/// the driver's space that the device addresses as `pa`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub va: usize,
    pub pa: u64,
    pub len: usize,
}

/// The placement of the admin structures in the first region: the admin
/// queue, its completions, the event queue and the 8-byte answer of a read
/// through memory.
pub const AQ_AT: usize = 0;
pub const ACQ_AT: usize = 0x800;
pub const AENQ_AT: usize = 0x1000;
pub const READLESS_AT: usize = 0x1400;
/// The page of the host info (`ena_admin_host_info`, 4 KiB).
pub const HOST_AT: usize = 0x2000;
/// The bytes the admin structures and the host info take.
pub const ADMIN_BYTES: usize = 0x3000;
/// The OS type the host info carries: the device refuses 0 (status 5) and takes 4.
const HOST_OS_TYPE: u32 = 4;

const NS_PER_MS: u64 = 1_000_000;
/// How long a read through memory waits for its answer, and the most
/// reads it makes while it does (a device that answers needs a few).
const READLESS_NS: u64 = 20 * NS_PER_MS;
/// Consecutive reads without an answer in one mode before the other is tried.
const READ_RETRIES: u8 = 3;
/// The step of the watchdog, and of the read of `DEV_STS` inside it.
const WATCH_NS: u64 = 100 * NS_PER_MS;
const STATUS_NS: u64 = 1_000 * NS_PER_MS;
/// The event entries one step reads, and the register accesses it makes at most.
pub const EVENTS_PER_STEP: u32 = 4;
pub const REG_ACCESSES_PER_STEP: u32 = 1;
/// The 64-bit stores of the step that zeroes the admin structures once the
/// reset is over (`released`): the queues and the answer of a read, `READLESS_AT`
/// bytes.
pub const RESET_ZERO_STORES: u32 = (READLESS_AT / 8) as u32;
/// The stores of the step that gives the host info (`host`): its page zeroed by
/// 64-bit stores, then the bytes of its fields (4 of the OS type, 7 of the
/// distribution name, 5 of the kernel version, 4 of the driver version, 2 of the
/// spec version, 2 of the function, 2 of the CPU count).
pub const HOST_STORES: u32 = 4096 / 8 + 4 + 7 + 5 + 4 + 2 + 2 + 2;
/// The most memory stores any one step makes; no step makes a register access
/// and more than a few of these besides.
pub const MEM_STORES_PER_STEP: u32 = RESET_ZERO_STORES;
const _: () = assert!(HOST_STORES <= MEM_STORES_PER_STEP);
/// How often the statistics of the device are read, and the keep-alive
/// lines that follow the first three.
const STATS_NS: u64 = 60_000 * NS_PER_MS;
const KEEPALIVE_EVERY: u64 = 60;
/// The wait for the first link event, and the reset timeout that stands in
/// for a device that gives none (`CAPS.RESET_TIMEOUT` of 0).
const LINK_WAIT_NS: u64 = 2_000 * NS_PER_MS;
const DEFAULT_RESET_NS: u64 = 3_000 * NS_PER_MS;
/// Three failures in a row inside this window end the in-place recovery.
const FAILURES: usize = 3;
const FAILURE_WINDOW_NS: u64 = 60_000 * NS_PER_MS;
/// The MTU the device is given (the stack runs at 1 500).
pub const MTU: u32 = 1500;

/// How a register is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    /// A load from BAR 0.
    Direct,
    /// A write of the offset and a request number to `MMIO_REG_READ`, the
    /// answer in memory.
    Readless,
}

/// Why the device is down for good, or why a bring-up stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The region is too small or not page-aligned.
    Region,
    /// `DEV_STS.READY` never came.
    NotReady,
    /// A register read got no answer in either mode.
    ReadTimeout,
    /// `RESET_IN_PROGRESS` did not rise or did not fall in the reset timeout.
    ResetTimeout,
    /// A region lies above the address width of the device.
    DmaWidth { width: u32 },
    /// An admin command got a status other than success, or no answer.
    Admin { opcode: u8, status: u8 },
    /// Three failures in a row inside a minute.
    TooManyResets,
}

/// What one step of `poll` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Nothing is due.
    Idle,
    /// A step of the bring-up or the reset ran.
    Progress,
    /// The device is up (the first time, or after a reset in place).
    Up,
    /// The watchdog or the device started a reset with this cause.
    Resetting(u32),
    /// The device is down for good.
    Failed(Failure),
}

/// What the attributes and capabilities say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub version: u32,
    pub controller: u32,
    pub caps: u32,
    pub dma_width: u32,
    pub impl_id: u32,
    pub supported: u32,
    pub capabilities: u32,
    pub mac: [u8; 6],
    pub max_mtu: u32,
    pub reset_to_ms: u64,
    pub admin_to_ms: u64,
    pub tx_sq: u32,
    pub tx_cq: u32,
    pub rx_sq: u32,
    pub rx_cq: u32,
    pub tx_depth: u32,
    pub rx_depth: u32,
    pub llq: bool,
    pub offload_tx: u32,
    pub offload_rx: u32,
    pub hint_watchdog_ms: u32,
    pub hint_mmio_ms: u32,
    pub hint_missing_tx_ms: u32,
    pub aenq_supported: u32,
    pub aenq_enabled: u32,
    pub speed_mbps: u32,
}

/// What the keep-alive events counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeepAlive {
    pub count: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
    pub rx_overruns: u64,
}

/// Counters of the device from `GET_STATS` of the ENI kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EniStats {
    pub bw_in: u64,
    pub bw_out: u64,
    pub pps: u64,
    pub conntrack: u64,
    pub linklocal: u64,
}

/// The resets of this run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resets {
    pub count: u32,
    pub last_reason: u32,
    /// By cause: the index is the reason, up to 19.
    pub by_reason: [u32; 20],
}

/// What a read of a register gave.
enum Reg {
    Value(u32),
    Wait,
    Failed,
}

/// A read through memory in flight.
#[derive(Clone, Copy, Debug)]
struct Rd {
    offset: u32,
    id: u16,
    deadline: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Mode, answer address, the first read; `reason` is the cause of a
    /// reset, 0 for the first start.
    Begin,
    /// The status and capabilities before the reset, read one a step.
    Probe,
    /// Waiting for `DEV_STS.READY`.
    Ready {
        since: u64,
    },
    /// The reset bit written, waiting for the device to show it.
    Asserted {
        since: u64,
    },
    /// The reset bit cleared, waiting for the device to finish.
    Released {
        since: u64,
    },
    /// The version and capability registers, read one a step.
    Identify,
    /// The host info: given to the device before the features.
    Host,
    /// The feature `FEATURES[at]`, asked or being answered.
    Features {
        at: usize,
    },
    /// The two sets: the event groups, then the MTU.
    Configure {
        at: usize,
    },
    /// Up; waiting for the first link event for a while.
    Running,
    Failed(Failure),
}

/// The features read at bring-up, in order: the id and the bit of
/// `supported_features` that must be set for the device to know it (0 for
/// the attributes themselves).
const FEATURES: [(u8, bool); 7] = [
    (adm::DEVICE_ATTRIBUTES, true),
    (adm::MAX_QUEUES_EXT, false),
    (adm::AENQ_CONFIG, true),
    (adm::STATELESS_OFFLOAD_CONFIG, false),
    (adm::HW_HINTS, false),
    (adm::LLQ, false),
    (adm::LINK_CONFIG, false),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Feature { id: u8 },
    Set { id: u8 },
    Stats,
    Host,
}

#[derive(Clone, Copy, Debug)]
struct Command {
    pending: Pending,
    id: u16,
    sent_ns: u64,
}

/// The driver of one device.
pub struct Ena<P: Platform> {
    p: P,
    region: Region,
    revision: u8,
    stage: Stage,
    reason: u32,
    mode: ReadMode,
    /// The other mode was tried once after reads timed out.
    tried_other: bool,
    /// A read through memory in flight, reads without an answer in a row, and
    /// the registers of a gather read so far.
    rd: Option<Rd>,
    rd_fail: u8,
    gather: [u32; 3],
    gathered: u8,
    /// The reads of the status register in the watchdog that got no answer in a row.
    status_fail: u8,
    /// The watchdog wants the status register read (one access, in a later step).
    status_due: bool,
    req_id: u16,
    // The queues.
    aq_tail: u16,
    aq_phase: u8,
    acq_head: u16,
    acq_phase: u8,
    aenq_head: u16,
    aenq_phase: u8,
    command: Option<Command>,
    info: Info,
    keep: KeepAlive,
    keep_ns: u64,
    keep_watch: bool,
    /// Keep-alives since the last bring-up: the first three of each are printed.
    keep_run: u64,
    link: Option<bool>,
    up_ns: u64,
    watch_ns: u64,
    status_ns: u64,
    stats_ns: u64,
    eni: EniStats,
    eni_reads: u32,
    resets: Resets,
    failures: [u64; FAILURES],
    began_ns: u64,
    reset_began_ns: u64,
    reset_ns_limit: u64,
    up_once: bool,
    /// A reset the caller or the device asked for, taken at the next step.
    asked: Option<u32>,
    /// The head of the event queue is not written back (a deliberate break).
    hold_head: bool,
    /// The function's bus, device and function in 16 bits, and the CPUs: the host info.
    bdf: u16,
    cpus: u16,
}

impl<P: Platform> Ena<P> {
    /// A driver for the device behind `p`, whose admin structures live in
    /// `region` (`ADMIN_BYTES` at least, a page-aligned physical address,
    /// zeroed memory that nothing else uses), on a function of PCI revision
    /// `revision`: bit 0 of it set means the device answers a plain read of
    /// its registers, clear means a read through memory (the rule is checked on
    /// the device: a t4g.small has revision 0 and answers reads through memory).
    ///
    /// # Safety
    ///
    /// `region.va` is valid, writable memory of `region.len` bytes for as long
    /// as the driver lives, which the device reads and writes at `region.pa`
    /// and nothing else touches.
    pub unsafe fn open(p: P, region: Region, revision: u8) -> Result<Ena<P>, Failure> {
        if region.len < ADMIN_BYTES
            || !region.pa.is_multiple_of(4096)
            || !region.va.is_multiple_of(8)
        {
            return Err(Failure::Region);
        }
        Ok(Ena {
            p,
            region,
            revision,
            stage: Stage::Begin,
            reason: regs::RESET_NORMAL,
            mode: if revision & 1 == 1 {
                ReadMode::Direct
            } else {
                ReadMode::Readless
            },
            tried_other: false,
            rd: None,
            rd_fail: 0,
            gather: [0; 3],
            gathered: 0,
            status_fail: 0,
            status_due: false,
            req_id: 0,
            aq_tail: 0,
            aq_phase: 1,
            acq_head: 0,
            acq_phase: 1,
            aenq_head: 0,
            aenq_phase: 1,
            command: None,
            info: Info::default(),
            keep: KeepAlive::default(),
            keep_ns: 0,
            keep_watch: false,
            keep_run: 0,
            link: None,
            up_ns: 0,
            watch_ns: 0,
            status_ns: 0,
            stats_ns: 0,
            eni: EniStats::default(),
            eni_reads: 0,
            resets: Resets::default(),
            failures: [0; FAILURES],
            began_ns: 0,
            reset_began_ns: 0,
            reset_ns_limit: DEFAULT_RESET_NS,
            up_once: false,
            asked: None,
            hold_head: cfg!(feature = "break-aenq-head"),
            bdf: 0,
            cpus: 1,
        })
    }

    pub fn platform(&self) -> &P {
        &self.p
    }
    pub fn info(&self) -> &Info {
        &self.info
    }
    pub fn keep_alive(&self) -> KeepAlive {
        self.keep
    }
    pub fn link(&self) -> Option<bool> {
        self.link
    }
    pub fn resets(&self) -> Resets {
        self.resets
    }
    pub fn eni_stats(&self) -> Option<EniStats> {
        (self.eni_reads > 0).then_some(self.eni)
    }
    pub fn mode(&self) -> ReadMode {
        self.mode
    }
    pub fn is_up(&self) -> bool {
        self.stage == Stage::Running
    }
    pub fn failure(&self) -> Option<Failure> {
        match self.stage {
            Stage::Failed(f) => Some(f),
            _ => None,
        }
    }

    /// Stops writing the head of the event queue back (or starts again): the
    /// device then stops sending events after one queue's worth, which the
    /// watchdog turns into a reset. The deliberate break of the probe on the
    /// device (`ena-break-aenq`).
    pub fn hold_event_head(&mut self, hold: bool) {
        self.hold_head = hold;
    }

    /// What the host info says of the function and the host: `bdf` is
    /// `Address::rid` of the function, `cpus` the CPUs the service runs on.
    pub fn set_host(&mut self, bdf: u16, cpus: u16) {
        self.bdf = bdf;
        self.cpus = cpus;
    }

    /// Whether the driver has already tried the other read mode since it was last up.
    #[cfg(test)]
    pub(crate) fn tried_other(&self) -> bool {
        self.tried_other
    }

    /// Asks for a reset with `reason`: the next step starts it.
    pub fn request_reset(&mut self, reason: u32) {
        self.asked = Some(reason);
    }

    // The memory of the admin structures.

    fn mem(&self, at: usize) -> *mut u8 {
        (self.region.va + at) as *mut u8
    }

    fn read_u8(&self, at: usize) -> u8 {
        // SAFETY: `at` is within the region (the callers' offsets are below
        // `ADMIN_BYTES`, which `open` checked); the device writes it, so the
        // read is volatile.
        unsafe { core::ptr::read_volatile(self.mem(at)) }
    }

    fn read_u16(&self, at: usize) -> u16 {
        u16::from(self.read_u8(at)) | u16::from(self.read_u8(at + 1)) << 8
    }

    fn read_u32(&self, at: usize) -> u32 {
        u32::from(self.read_u16(at)) | u32::from(self.read_u16(at + 2)) << 16
    }

    fn read_u64(&self, at: usize) -> u64 {
        u64::from(self.read_u32(at)) | u64::from(self.read_u32(at + 4)) << 32
    }

    fn write_u8(&self, at: usize, value: u8) {
        // SAFETY: as for `read_u8`.
        unsafe { core::ptr::write_volatile(self.mem(at), value) }
    }

    /// Zeroes `len` bytes at `at` with 64-bit stores, `len / 8` of them: the
    /// region starts on a word (`open` checks) and the callers' offsets and
    /// lengths are multiples of 8.
    fn zero(&self, at: usize, len: usize) {
        assert!(at.is_multiple_of(8) && len.is_multiple_of(8));
        for i in (0..len).step_by(8) {
            // SAFETY: `at + i` is a word within the region (the callers' offsets are
            // below `ADMIN_BYTES`, which `open` checked, and the region is word
            // aligned); the device reads and writes it, so the store is volatile.
            unsafe { core::ptr::write_volatile(self.mem(at + i).cast::<u64>(), 0) }
        }
    }

    // The registers.

    /// The timeout of a read through memory: the device's own hint (`mmio_read_timeout`,
    /// in ms) when it gave one, else 20 ms.
    fn readless_ns(&self) -> u64 {
        match self.info.hint_mmio_ms {
            _ if cfg!(feature = "break-read-hint") => READLESS_NS,
            0 => READLESS_NS,
            ms => u64::from(ms) * NS_PER_MS,
        }
    }

    /// One register, at most one device access a call and no wait: a plain
    /// read answers at once; a read through memory writes its request on the
    /// first call and looks for the answer on the next ones, `Wait` until it
    /// comes or the timeout passes (`Failed`).
    fn reg(&mut self, offset: u32) -> Reg {
        match self.mode {
            ReadMode::Direct => Reg::Value(self.p.read32(offset)),
            ReadMode::Readless => {
                let now = self.p.now_ns();
                match self.rd {
                    Some(rd) if rd.offset == offset => {
                        self.p.rmb();
                        if self.read_u16(READLESS_AT + adm::READLESS_REQ_ID) == rd.id
                            && u32::from(self.read_u16(READLESS_AT + adm::READLESS_REG_OFF))
                                == offset
                        {
                            self.rd = None;
                            return Reg::Value(self.read_u32(READLESS_AT + adm::READLESS_REG_VAL));
                        }
                        if now > rd.deadline {
                            self.rd = None;
                            return Reg::Failed;
                        }
                        Reg::Wait
                    }
                    _ => {
                        self.req_id = self.req_id.wrapping_add(1);
                        let id = self.req_id;
                        // An answer that is not this request's: id 0, no value.
                        self.zero(READLESS_AT, adm::READLESS_LEN);
                        self.p.wmb();
                        let word = (offset << regs::MMIO_REG_READ_REG_OFF_SHIFT
                            & regs::MMIO_REG_READ_REG_OFF_MASK)
                            | u32::from(id) & regs::MMIO_REG_READ_REQ_ID_MASK;
                        self.p.write32(regs::MMIO_REG_READ, word);
                        self.rd = Some(Rd {
                            offset,
                            id,
                            deadline: now + self.readless_ns(),
                        });
                        Reg::Wait
                    }
                }
            }
        }
    }

    /// Reads `offsets` in order, one a call, into `self.gather`: Some(values) once all are in.
    /// A call that reads nothing new (`Wait`) or fails gives `Err` with the event to return.
    fn gather<const N: usize>(&mut self, offsets: [u32; N]) -> Result<[u32; N], Event> {
        let at = usize::from(self.gathered);
        match self.reg(offsets[at]) {
            Reg::Value(v) => {
                self.rd_fail = 0;
                self.gather[at] = v;
                self.gathered += 1;
                if usize::from(self.gathered) == N {
                    self.gathered = 0;
                    return Ok(core::array::from_fn(|i| self.gather[i]));
                }
                Err(Event::Progress)
            }
            Reg::Wait => Err(Event::Idle),
            Reg::Failed => Err(self.read_failed()),
        }
    }

    fn write_reg(&self, offset: u32, value: u32) {
        self.p.write32(offset, value);
    }

    fn write_pair(&self, lo: u32, hi: u32, pa: u64) {
        self.write_reg(lo, pa as u32);
        self.write_reg(hi, (pa >> 32) as u32);
    }

    // The steps.

    /// One step: at most one register access, `EVENTS_PER_STEP` event entries
    /// and a few admin entries, never a wait. The caller calls it when it has
    /// time (on a timer) and again at once after `Progress`.
    pub fn poll(&mut self) -> Event {
        let now = self.p.now_ns();
        // A reset asked for while the device comes up waits for it to be up.
        if cfg!(feature = "break-ask-lost") {
            if let Some(reason) = self.asked.take()
                && matches!(self.stage, Stage::Running)
            {
                return self.start_reset(reason, now);
            }
        } else if matches!(self.stage, Stage::Running)
            && let Some(reason) = self.asked.take()
        {
            return self.start_reset(reason, now);
        }
        match self.stage {
            Stage::Begin => self.begin(now),
            Stage::Probe => self.probe(now),
            Stage::Ready { since } => self.ready(now, since),
            Stage::Asserted { since } => self.asserted(now, since),
            Stage::Released { since } => self.released(now, since),
            Stage::Identify => self.identify(now),
            Stage::Host => self.host(now),
            Stage::Features { at } => self.features(now, at),
            Stage::Configure { at } => self.configure(now, at),
            Stage::Running => self.running(now),
            Stage::Failed(f) => Event::Failed(f),
        }
    }

    fn fail(&mut self, failure: Failure) -> Event {
        self.p.log(format_args!("ena: failed {failure:?}"));
        self.stage = Stage::Failed(failure);
        Event::Failed(failure)
    }

    /// A failure of the bring-up the device may get over: counts as an attempt of
    /// the three a minute and starts the reset again, until the third ends the
    /// recovery (`Failed`, and the owner of the driver restarts its service).
    fn recover(&mut self, failure: Failure, now: u64) -> Event {
        self.p.log(format_args!("ena: bring-up failed {failure:?}"));
        match self.start_reset(regs::RESET_INIT_ERR, now) {
            Event::Failed(_) => self.fail(failure),
            e => e,
        }
    }

    /// The device asked to go down: counts it, and gives up after the
    /// third inside a minute.
    fn start_reset(&mut self, reason: u32, now: u64) -> Event {
        self.p.log(format_args!(
            "ena: reset reason {reason} after {} s",
            now.saturating_sub(self.up_ns) / (1000 * NS_PER_MS)
        ));
        if reason == regs::RESET_KEEP_ALIVE_TO {
            // The first entry of the event queue: all zero when the device posted nothing.
            let words = [0, 4, 8, 12].map(|i| self.read_u32(AENQ_AT + i));
            self.p.log(format_args!(
                "ena: no keep-alive; head {} entry0 {:#x} {:#x} {:#x} {:#x}",
                self.aenq_head, words[0], words[1], words[2], words[3]
            ));
        }
        self.resets.count += 1;
        self.resets.last_reason = reason;
        if let Some(n) = self.resets.by_reason.get_mut(reason as usize) {
            *n += 1;
        }
        self.failures.rotate_left(1);
        self.failures[FAILURES - 1] = now;
        if self.failures[0] != 0 && now - self.failures[0] < FAILURE_WINDOW_NS {
            return self.fail(Failure::TooManyResets);
        }
        // A request for a reset waits for the device to be up (`poll`); a reset that
        // starts on its own answers it, so one fault takes one attempt of the three.
        if !cfg!(feature = "break-ask-kept") {
            self.asked = None;
        }
        self.reason = reason;
        self.reset_began_ns = now;
        self.stage = Stage::Begin;
        self.command = None;
        self.rd = None;
        self.gathered = 0;
        Event::Resetting(reason)
    }

    fn begin(&mut self, now: u64) -> Event {
        self.began_ns = now;
        // Fresh books for the queues. The memory is zeroed once the reset is
        // over (`released`): an old device may still post into it until then.
        self.aq_tail = 0;
        self.aq_phase = 1;
        self.acq_head = 0;
        self.acq_phase = 1;
        self.aenq_head = 0;
        self.aenq_phase = 1;
        self.command = None;
        self.keep_watch = false;
        self.keep_run = 0;
        self.link = None;
        self.rd = None;
        self.gathered = 0;
        if cfg!(feature = "break-zero-early") {
            self.zero(0, READLESS_AT);
        }
        if self.mode == ReadMode::Readless {
            self.write_pair(
                regs::MMIO_RESP_LO,
                regs::MMIO_RESP_HI,
                self.region.pa + READLESS_AT as u64,
            );
        }
        self.stage = Stage::Probe;
        Event::Progress
    }

    /// The status and capability registers before the reset: the reset timeout.
    fn probe(&mut self, now: u64) -> Event {
        let [sts, caps] = match self.gather([regs::DEV_STS, regs::CAPS]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        self.p.log(format_args!(
            "ena: {:?} read; dev_sts {sts:#x} caps {caps:#x}",
            self.mode
        ));
        let timeout =
            u64::from((caps & regs::CAPS_RESET_TIMEOUT_MASK) >> regs::CAPS_RESET_TIMEOUT_SHIFT)
                * 100
                * NS_PER_MS;
        self.reset_ns_limit = if timeout == 0 {
            DEFAULT_RESET_NS
        } else {
            timeout
        };
        self.stage = Stage::Ready { since: now };
        Event::Progress
    }

    /// A register read got no answer: tries again in the same mode, and after
    /// `READ_RETRIES` in a row the other mode once, then gives up (a recovery).
    fn read_failed(&mut self) -> Event {
        self.rd_fail += 1;
        if self.rd_fail < READ_RETRIES && !cfg!(feature = "break-read-retry") {
            return Event::Idle;
        }
        self.rd_fail = 0;
        let now = self.p.now_ns();
        if self.tried_other {
            return self.recover(Failure::ReadTimeout, now);
        }
        self.tried_other = true;
        self.mode = match self.mode {
            ReadMode::Direct => ReadMode::Readless,
            ReadMode::Readless => ReadMode::Direct,
        };
        self.p.log(format_args!(
            "ena: no answer to a read of a register, trying {:?} (revision {:#x})",
            self.mode, self.revision
        ));
        self.stage = Stage::Begin;
        Event::Progress
    }

    /// The status register, one read a step: its value, or the event to return.
    fn status(&mut self) -> Result<u32, Event> {
        match self.reg(regs::DEV_STS) {
            Reg::Value(v) => {
                self.rd_fail = 0;
                Ok(v)
            }
            Reg::Wait => Err(Event::Idle),
            Reg::Failed => Err(self.read_failed()),
        }
    }

    fn ready(&mut self, now: u64, since: u64) -> Event {
        let sts = match self.status() {
            Ok(v) => v,
            Err(e) => return e,
        };
        if sts & regs::DEV_STS_READY_MASK == 0 {
            if now - since > self.reset_ns_limit {
                self.p.log(format_args!("ena: reset failed sts {sts:#x}"));
                return self.recover(Failure::NotReady, now);
            }
            return Event::Idle;
        }
        let extended = self.info.capabilities & (1 << adm::CAP_EXTENDED_RESET_REASONS) != 0;
        self.write_reg(regs::DEV_CTL, regs::reset_word(self.reason, extended));
        // The reset clears the address of the answers of a read through memory:
        // the polls that follow need it again.
        if self.mode == ReadMode::Readless && !cfg!(feature = "break-resp-rewrite") {
            self.write_pair(
                regs::MMIO_RESP_LO,
                regs::MMIO_RESP_HI,
                self.region.pa + READLESS_AT as u64,
            );
        }
        self.rd = None;
        self.stage = Stage::Asserted { since: now };
        Event::Progress
    }

    fn asserted(&mut self, now: u64, since: u64) -> Event {
        let sts = match self.status() {
            Ok(v) => v,
            Err(e) => return e,
        };
        if sts & regs::DEV_STS_RESET_IN_PROGRESS_MASK != 0 {
            self.write_reg(regs::DEV_CTL, 0);
            self.stage = Stage::Released { since: now };
            return Event::Progress;
        }
        if now - since > self.reset_ns_limit {
            self.p.log(format_args!("ena: reset failed sts {sts:#x}"));
            return self.recover(Failure::ResetTimeout, now);
        }
        Event::Idle
    }

    fn released(&mut self, now: u64, since: u64) -> Event {
        // The wait for the device to finish; `break-reset-wait` goes on at once,
        // while it still resets.
        let sts = match self.status() {
            Ok(v) => v,
            Err(e) => return e,
        };
        let finished = sts & regs::DEV_STS_RESET_IN_PROGRESS_MASK == 0;
        if finished || cfg!(feature = "break-reset-wait") {
            // The old device is silent now: whatever it posted into the rings
            // while it still ran goes, and the rings are fresh.
            if !cfg!(feature = "break-zero-early") {
                self.zero(0, READLESS_AT);
            }
            let ms = (now - self.began_ns) / NS_PER_MS;
            self.p.log(format_args!("ena: reset ok {ms} ms"));
            self.stage = Stage::Identify;
            return Event::Progress;
        }
        if now - since > self.reset_ns_limit {
            self.p.log(format_args!("ena: reset failed sts {sts:#x}"));
            return self.recover(Failure::ResetTimeout, now);
        }
        Event::Idle
    }

    fn identify(&mut self, now: u64) -> Event {
        let [version, controller, caps] =
            match self.gather([regs::VERSION, regs::CONTROLLER_VERSION, regs::CAPS]) {
                Ok(v) => v,
                Err(e) => return e,
            };
        let width = (caps & regs::CAPS_DMA_ADDR_WIDTH_MASK) >> regs::CAPS_DMA_ADDR_WIDTH_SHIFT;
        let admin =
            u64::from((caps & regs::CAPS_ADMIN_CMD_TO_MASK) >> regs::CAPS_ADMIN_CMD_TO_SHIFT) * 100;
        let reset =
            u64::from((caps & regs::CAPS_RESET_TIMEOUT_MASK) >> regs::CAPS_RESET_TIMEOUT_SHIFT)
                * 100;
        self.info.version = version;
        self.info.controller = controller;
        self.info.caps = caps;
        self.info.dma_width = width;
        self.info.reset_to_ms = reset;
        self.info.admin_to_ms = admin;
        self.p.log(format_args!(
            "ena: version {}.{} controller {}.{}.{} impl {} caps {caps:#x} dma_width {width} reset_to {reset} admin_to {admin}",
            (version & regs::VERSION_MAJOR_MASK) >> regs::VERSION_MAJOR_SHIFT,
            version & regs::VERSION_MINOR_MASK,
            (controller & regs::CONTROLLER_VERSION_MAJOR_MASK) >> regs::CONTROLLER_VERSION_MAJOR_SHIFT,
            (controller & regs::CONTROLLER_VERSION_MINOR_MASK) >> regs::CONTROLLER_VERSION_MINOR_SHIFT,
            controller & regs::CONTROLLER_VERSION_SUBMINOR_MASK,
            (controller & regs::CONTROLLER_VERSION_IMPL_ID_MASK) >> regs::CONTROLLER_VERSION_IMPL_ID_SHIFT,
        ));
        // Every address the device is given must fit its width.
        let top = self.region.pa + self.region.len as u64 - 1;
        let fits = width == 0 || width >= 64 || top >> width == 0;
        if !fits && !cfg!(feature = "break-dma-width") {
            return self.fail(Failure::DmaWidth { width });
        }
        // The queues.
        let depth = u32::from(adm::ADMIN_DEPTH);
        let size = (adm::ENTRY as u32) << regs::QUEUE_CAPS_ENTRY_SIZE_SHIFT;
        self.write_pair(
            regs::AQ_BASE_LO,
            regs::AQ_BASE_HI,
            self.region.pa + AQ_AT as u64,
        );
        self.write_reg(regs::AQ_CAPS, depth | size);
        self.write_pair(
            regs::ACQ_BASE_LO,
            regs::ACQ_BASE_HI,
            self.region.pa + ACQ_AT as u64,
        );
        self.write_reg(regs::ACQ_CAPS, depth | size);
        self.write_pair(
            regs::AENQ_BASE_LO,
            regs::AENQ_BASE_HI,
            self.region.pa + AENQ_AT as u64,
        );
        self.write_reg(regs::AENQ_CAPS, u32::from(adm::EVENT_DEPTH) | size);
        // The event queue's head starts at its depth: the device owns all
        // entries. The doorbell that tells it so is written last, in `up`: the
        // device sends no event before it (seen on the device: written earlier,
        // no event came in three launches). The admin
        // interrupt stays masked, the driver polls.
        self.aenq_head = adm::EVENT_DEPTH;
        self.aenq_phase = 1;
        self.write_reg(regs::INTR_MASK, regs::ADMIN_INTR_MASK);
        self.stage = Stage::Host;
        let _ = now;
        Event::Progress
    }

    // The admin queue.

    /// Puts a command in the queue: `fill` writes its fields into the 64
    /// bytes (zeroed, with the opcode, the id and the phase already set).
    fn submit(&mut self, opcode: u8, pending: Pending, now: u64, fill: impl FnOnce(&mut [u8; 64])) {
        let slot = usize::from(self.aq_tail & (adm::ADMIN_DEPTH - 1));
        let id = self.aq_tail & adm::AQ_COMMAND_ID_MASK;
        let mut entry = [0u8; adm::ENTRY];
        entry[0..2].copy_from_slice(&id.to_le_bytes());
        entry[adm::AQ_OPCODE] = opcode;
        entry[adm::AQ_FLAGS] = self.aq_phase;
        fill(&mut entry);
        let at = AQ_AT + slot * adm::ENTRY;
        for (i, b) in entry.iter().enumerate() {
            self.write_u8(at + i, *b);
        }
        self.aq_tail = self.aq_tail.wrapping_add(1);
        if self.aq_tail & (adm::ADMIN_DEPTH - 1) == 0 {
            self.aq_phase ^= 1;
        }
        self.command = Some(Command {
            pending,
            id,
            sent_ns: now,
        });
        self.p.wmb();
        self.write_reg(regs::AQ_DB, u32::from(self.aq_tail));
    }

    /// The completion of the command in flight, if it came: the status and
    /// the offset in the region of the entry's body.
    fn complete(&mut self) -> Option<(Command, u8, usize)> {
        let command = self.command?;
        let slot = usize::from(self.acq_head & (adm::ADMIN_DEPTH - 1));
        let at = ACQ_AT + slot * adm::ENTRY;
        self.p.rmb();
        let flags = self.read_u8(at + adm::ACQ_FLAGS);
        if flags & adm::ACQ_FLAG_PHASE != self.acq_phase {
            return None;
        }
        self.p.rmb();
        let id = self.read_u16(at + adm::ACQ_COMMAND) & adm::AQ_COMMAND_ID_MASK;
        let status = self.read_u8(at + adm::ACQ_STATUS);
        self.acq_head = self.acq_head.wrapping_add(1);
        // `break-acq-phase`: the phase does not turn at the wrap of the queue.
        if self.acq_head & (adm::ADMIN_DEPTH - 1) == 0 && !cfg!(feature = "break-acq-phase") {
            self.acq_phase ^= 1;
        }
        self.command = None;
        if id != command.id {
            // A completion that is not the command's: the queue is out of step.
            return Some((command, adm::UNKNOWN_ERROR, usize::MAX));
        }
        Some((command, status, at + adm::ACQ_DATA))
    }

    /// The deadline of a command: the device's own, 3 s without one.
    fn admin_limit_ns(&self) -> u64 {
        let ms = self.info.admin_to_ms;
        if ms == 0 {
            adm::ADMIN_CMD_TIMEOUT_US * 1000
        } else {
            ms * NS_PER_MS
        }
    }

    /// The host info: written into its page, then given to the device with
    /// SET_FEATURE `HOST_ATTR_CONFIG`, before the features. A refusal is logged and
    /// the bring-up goes on (the device took it with OS type 4 and refused 0 with
    /// status 5 on a t4g.small).
    fn host(&mut self, now: u64) -> Event {
        let Some(command) = self.command else {
            let at = HOST_AT;
            self.zero(at, 4096);
            let put = |s: &Self, off: usize, bytes: &[u8]| {
                for (i, b) in bytes.iter().enumerate() {
                    s.write_u8(at + off + i, *b);
                }
            };
            put(self, adm::HOST_INFO_OS_TYPE, &HOST_OS_TYPE.to_le_bytes());
            put(self, adm::HOST_INFO_OS_DIST_STR, b"stafeto");
            put(self, adm::HOST_INFO_KERNEL_VER_STR, b"0.2.0");
            put(self, adm::HOST_INFO_DRIVER_VERSION, &1u32.to_le_bytes());
            let spec = adm::SPEC_VERSION_MAJOR << 8 | adm::SPEC_VERSION_MINOR;
            put(self, adm::HOST_INFO_SPEC_VERSION, &spec.to_le_bytes());
            put(self, adm::HOST_INFO_BDF, &self.bdf.to_le_bytes());
            put(self, adm::HOST_INFO_NUM_CPUS, &self.cpus.to_le_bytes());
            let pa = self.region.pa + HOST_AT as u64;
            self.p.wmb();
            self.submit(adm::SET_FEATURE, Pending::Host, now, |e| {
                e[adm::FEAT_ID] = adm::HOST_ATTR_CONFIG;
                e[adm::FEAT_DATA + adm::HOST_OS_INFO_BA..][..4]
                    .copy_from_slice(&(pa as u32).to_le_bytes());
                e[adm::FEAT_DATA + adm::HOST_OS_INFO_BA + 4..][..2]
                    .copy_from_slice(&((pa >> 32) as u16).to_le_bytes());
            });
            return Event::Progress;
        };
        let Some((_, status, _)) = self.complete() else {
            if now - command.sent_ns > self.admin_limit_ns() {
                return self.recover(
                    Failure::Admin {
                        opcode: adm::SET_FEATURE,
                        status: 0xFF,
                    },
                    now,
                );
            }
            return Event::Idle;
        };
        if status != adm::SUCCESS {
            self.p
                .log(format_args!("ena: host info refused, status {status}"));
        }
        self.stage = Stage::Features { at: 0 };
        Event::Progress
    }

    // The features.

    fn features(&mut self, now: u64, at: usize) -> Event {
        let Some(command) = self.command else {
            return self.ask_feature(now, at);
        };
        let Some((_, status, body)) = self.complete() else {
            if now - command.sent_ns > self.admin_limit_ns() {
                return self.recover(
                    Failure::Admin {
                        opcode: adm::GET_FEATURE,
                        status: 0xFF,
                    },
                    now,
                );
            }
            return Event::Idle;
        };
        let Pending::Feature { id } = command.pending else {
            return self.recover(
                Failure::Admin {
                    opcode: adm::GET_FEATURE,
                    status,
                },
                now,
            );
        };
        if status != adm::SUCCESS {
            // The attributes and the event groups are needed; the rest is advice.
            if FEATURES[at].1 {
                return self.recover(
                    Failure::Admin {
                        opcode: adm::GET_FEATURE,
                        status,
                    },
                    now,
                );
            }
            self.p
                .log(format_args!("ena: feature {id} refused, status {status}"));
        } else {
            self.take_feature(id, body);
        }
        if at + 1 < FEATURES.len() {
            self.stage = Stage::Features { at: at + 1 };
        } else {
            self.report_attributes();
            self.stage = Stage::Configure { at: 0 };
        }
        Event::Progress
    }

    fn ask_feature(&mut self, now: u64, at: usize) -> Event {
        let (id, _) = FEATURES[at];
        // Features other than the attributes are asked only when the device
        // lists them (`supported_features` bit `id`), with the legacy queue
        // limits when the extended are missing.
        let listed = id == adm::DEVICE_ATTRIBUTES || self.info.supported & (1 << id) != 0;
        if !listed {
            if id == adm::MAX_QUEUES_EXT && self.info.supported & (1 << adm::MAX_QUEUES_NUM) != 0 {
                self.submit_get(adm::MAX_QUEUES_NUM, now);
                return Event::Progress;
            }
            self.stage = if at + 1 < FEATURES.len() {
                Stage::Features { at: at + 1 }
            } else {
                self.report_attributes();
                Stage::Configure { at: 0 }
            };
            return Event::Progress;
        }
        self.submit_get(id, now);
        Event::Progress
    }

    fn submit_get(&mut self, id: u8, now: u64) {
        self.submit(adm::GET_FEATURE, Pending::Feature { id }, now, |e| {
            // `FEAT_FLAGS` stays 0, which the device takes (seen on the device);
            // the version is the newest the driver reads of the two features that
            // have a second one.
            e[adm::FEAT_ID] = id;
            e[adm::FEAT_VERSION] = match id {
                adm::MAX_QUEUES_EXT | adm::LLQ => 1,
                _ => 0,
            };
        });
    }

    fn take_feature(&mut self, id: u8, body: usize) {
        let u32_at = |s: &Self, off: usize| s.read_u32(body + off);
        match id {
            adm::DEVICE_ATTRIBUTES => {
                self.info.impl_id = u32_at(self, adm::ATTR_IMPL_ID);
                self.info.supported = u32_at(self, adm::ATTR_SUPPORTED);
                self.info.capabilities = u32_at(self, adm::ATTR_CAPABILITIES);
                self.info.max_mtu = u32_at(self, adm::ATTR_MAX_MTU);
                for i in 0..6 {
                    self.info.mac[i] = self.read_u8(body + adm::ATTR_MAC + i);
                }
            }
            adm::MAX_QUEUES_EXT => {
                self.info.tx_sq = u32_at(self, adm::QEXT_TX_SQ_NUM);
                self.info.tx_cq = u32_at(self, adm::QEXT_TX_CQ_NUM);
                self.info.rx_sq = u32_at(self, adm::QEXT_RX_SQ_NUM);
                self.info.rx_cq = u32_at(self, adm::QEXT_RX_CQ_NUM);
                self.info.tx_depth = u32_at(self, adm::QEXT_TX_SQ_DEPTH);
                self.info.rx_depth = u32_at(self, adm::QEXT_RX_SQ_DEPTH);
            }
            adm::MAX_QUEUES_NUM => {
                self.info.tx_sq = u32_at(self, adm::QUEUE_SQ_NUM);
                self.info.rx_sq = self.info.tx_sq;
                self.info.tx_cq = u32_at(self, adm::QUEUE_CQ_NUM);
                self.info.rx_cq = self.info.tx_cq;
                self.info.tx_depth = u32_at(self, adm::QUEUE_SQ_DEPTH);
                self.info.rx_depth = self.info.tx_depth;
            }
            adm::AENQ_CONFIG => {
                self.info.aenq_supported = u32_at(self, adm::AENQ_SUPPORTED);
                self.info.aenq_enabled = u32_at(self, adm::AENQ_ENABLED);
            }
            adm::STATELESS_OFFLOAD_CONFIG => {
                self.info.offload_tx = u32_at(self, adm::OFFLOAD_TX);
                self.info.offload_rx = u32_at(self, adm::OFFLOAD_RX_SUPPORTED);
            }
            adm::HW_HINTS => {
                let hint = |s: &Self, off: usize| match s.read_u16(body + off) {
                    adm::HINT_NO_TIMEOUT => 0,
                    ms => u32::from(ms),
                };
                self.info.hint_watchdog_ms = hint(self, adm::HINT_WATCHDOG);
                self.info.hint_mmio_ms = hint(self, adm::HINT_MMIO_READ);
                self.info.hint_missing_tx_ms = hint(self, adm::HINT_MISSING_TX);
            }
            adm::LLQ => {
                self.info.llq = u32_at(self, adm::LLQ_MAX_NUM) != 0;
            }
            adm::LINK_CONFIG => {
                self.info.speed_mbps = u32_at(self, adm::LINK_SPEED);
            }
            _ => {}
        }
    }

    fn report_attributes(&mut self) {
        let i = self.info;
        self.p.log(format_args!(
            "ena: aq ok; mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} max_mtu {} features {:#x} queues sq {}/{} cq {}/{} depth {}/{} llq {}; offload tx {:#x} rx {:#x}; hints watchdog {} missing_tx {} mmio {}; link {} Mb/s",
            i.mac[0], i.mac[1], i.mac[2], i.mac[3], i.mac[4], i.mac[5],
            i.max_mtu, i.supported, i.tx_sq, i.rx_sq, i.tx_cq, i.rx_cq, i.tx_depth, i.rx_depth,
            if i.llq { "yes" } else { "no" },
            i.offload_tx, i.offload_rx, i.hint_watchdog_ms, i.hint_missing_tx_ms, i.hint_mmio_ms, i.speed_mbps,
        ));
    }

    fn configure(&mut self, now: u64, at: usize) -> Event {
        let Some(command) = self.command else {
            if at == 0 {
                // The groups the driver handles, within what the device reports.
                let wanted = (1u32 << adm::AENQ_LINK_CHANGE)
                    | 1 << adm::AENQ_FATAL_ERROR
                    | 1 << adm::AENQ_WARNING
                    | 1 << adm::AENQ_NOTIFICATION
                    | 1 << adm::AENQ_KEEP_ALIVE
                    | 1 << adm::AENQ_DEVICE_REQUEST_RESET;
                let groups = wanted & self.info.aenq_supported;
                self.info.aenq_enabled = groups;
                self.submit(
                    adm::SET_FEATURE,
                    Pending::Set {
                        id: adm::AENQ_CONFIG,
                    },
                    now,
                    |e| {
                        e[adm::FEAT_ID] = adm::AENQ_CONFIG;
                        e[adm::FEAT_DATA + adm::AENQ_ENABLED..][..4]
                            .copy_from_slice(&groups.to_le_bytes());
                    },
                );
            } else {
                self.submit(adm::SET_FEATURE, Pending::Set { id: adm::MTU }, now, |e| {
                    e[adm::FEAT_ID] = adm::MTU;
                    e[adm::FEAT_DATA + adm::MTU_VALUE..][..4].copy_from_slice(&MTU.to_le_bytes());
                });
            }
            return Event::Progress;
        };
        let Some((_, status, _)) = self.complete() else {
            if now - command.sent_ns > self.admin_limit_ns() {
                return self.recover(
                    Failure::Admin {
                        opcode: adm::SET_FEATURE,
                        status: 0xFF,
                    },
                    now,
                );
            }
            return Event::Idle;
        };
        if status != adm::SUCCESS {
            if at == 0 {
                return self.recover(
                    Failure::Admin {
                        opcode: adm::SET_FEATURE,
                        status,
                    },
                    now,
                );
            }
            self.p
                .log(format_args!("ena: mtu {MTU} refused, status {status}"));
        }
        if at == 0 {
            self.p.log(format_args!(
                "ena: aenq groups {:#x}",
                self.info.aenq_enabled
            ));
            self.keep_watch = self.info.aenq_enabled & (1 << adm::AENQ_KEEP_ALIVE) != 0;
            self.stage = Stage::Configure { at: 1 };
            return Event::Progress;
        }
        self.up(now)
    }

    fn up(&mut self, now: u64) -> Event {
        // All entries of the event queue are the device's: it may post.
        self.p.wmb();
        self.write_reg(regs::AENQ_HEAD_DB, u32::from(self.aenq_head));
        // Once up, the next trouble with the reads starts with the first mode again.
        if !cfg!(feature = "break-tried-kept") {
            self.tried_other = false;
        }
        self.stage = Stage::Running;
        self.up_ns = now;
        self.keep_ns = now;
        self.watch_ns = now;
        self.status_ns = now;
        self.stats_ns = now;
        if self.up_once {
            let ms = (now - self.reset_began_ns) / NS_PER_MS;
            self.p.log(format_args!("ena: rebuilt in {ms} ms"));
        }
        self.up_once = true;
        Event::Up
    }

    // Running.

    fn running(&mut self, now: u64) -> Event {
        if let Some(command) = self.command {
            if let Some((c, status, body)) = self.complete() {
                self.stats_done(c, status, body);
                return Event::Progress;
            }
            if now - command.sent_ns > self.admin_limit_ns() {
                return self.start_reset(regs::RESET_ADMIN_TO, now);
            }
        }
        if let Some(reason) = self.events(now) {
            return self.start_reset(reason, now);
        }
        if now - self.watch_ns >= WATCH_NS {
            self.watch_ns = now;
            if let Some(reason) = self.watchdog(now) {
                return self.start_reset(reason, now);
            }
        }
        if self.status_due {
            match self.reg(regs::DEV_STS) {
                Reg::Value(sts) => {
                    self.status_due = false;
                    self.status_fail = 0;
                    if sts & regs::DEV_STS_FATAL_ERROR_MASK != 0 {
                        return self.start_reset(regs::RESET_GENERIC, now);
                    }
                }
                Reg::Wait => return Event::Idle,
                Reg::Failed => {
                    self.status_fail += 1;
                    if self.status_fail >= READ_RETRIES {
                        self.status_fail = 0;
                        self.status_due = false;
                        return self.start_reset(regs::RESET_DRIVER_INVALID_STATE, now);
                    }
                }
            }
            return Event::Progress;
        }
        let eni = self.info.capabilities & (1 << adm::CAP_ENI_STATS) != 0
            || cfg!(feature = "break-eni-gate");
        if eni && self.command.is_none() && (now - self.stats_ns >= STATS_NS || self.eni_reads == 0)
        {
            self.stats_ns = now;
            self.submit(adm::GET_STATS, Pending::Stats, now, |e| {
                e[adm::STATS_TYPE] = adm::STATS_TYPE_ENI;
                e[adm::STATS_SCOPE] = adm::STATS_SCOPE_ETH_TRAFFIC;
                e[adm::STATS_DEVICE..][..2].copy_from_slice(&adm::DEVICE_ME.to_le_bytes());
            });
            return Event::Progress;
        }
        if self.link.is_none() && now - self.up_ns > LINK_WAIT_NS {
            self.p
                .log(format_args!("ena: link unknown (no event), taken as up"));
            self.link = Some(true);
        }
        Event::Idle
    }

    fn stats_done(&mut self, command: Command, status: u8, body: usize) {
        if command.pending != Pending::Stats {
            return;
        }
        if status != adm::SUCCESS {
            self.p
                .log(format_args!("ena: stats refused, status {status}"));
            // Count it so that the request is not repeated at once.
            self.eni_reads += 1;
            return;
        }
        self.eni = EniStats {
            bw_in: self.read_u64(body),
            bw_out: self.read_u64(body + 8),
            pps: self.read_u64(body + 16),
            conntrack: self.read_u64(body + 24),
            linklocal: self.read_u64(body + 32),
        };
        self.eni_reads += 1;
        self.p.log(format_args!(
            "ena: eni bw_in {} bw_out {} pps {} conntrack {} linklocal {}",
            self.eni.bw_in, self.eni.bw_out, self.eni.pps, self.eni.conntrack, self.eni.linklocal
        ));
    }

    /// Reads at most `EVENTS_PER_STEP` entries of the event queue; the
    /// reset cause when one asks for it.
    fn events(&mut self, now: u64) -> Option<u32> {
        let mut taken = 0;
        let mut reset = None;
        while taken < EVENTS_PER_STEP {
            let slot = usize::from(self.aenq_head & (adm::EVENT_DEPTH - 1));
            let at = AENQ_AT + slot * adm::ENTRY;
            self.p.rmb();
            if self.read_u8(at + adm::AENQ_FLAGS) & adm::AENQ_FLAG_PHASE != self.aenq_phase {
                break;
            }
            self.p.rmb();
            let group = self.read_u16(at + adm::AENQ_GROUP);
            match group {
                adm::AENQ_KEEP_ALIVE => self.keep_alive_event(at, now),
                adm::AENQ_LINK_CHANGE => {
                    let up = self.read_u32(at + adm::AENQ_DATA) & adm::LINK_STATUS_MASK != 0;
                    if self.link != Some(up) {
                        self.p
                            .log(format_args!("ena: link {}", if up { "up" } else { "down" }));
                    }
                    self.link = Some(up);
                }
                adm::AENQ_FATAL_ERROR => reset = reset.or(Some(regs::RESET_GENERIC)),
                adm::AENQ_DEVICE_REQUEST_RESET => {
                    reset = reset.or(Some(regs::RESET_DEVICE_REQUEST))
                }
                adm::AENQ_NOTIFICATION
                    if self.read_u16(at + adm::AENQ_SYNDROME) == adm::AENQ_UPDATE_HINTS =>
                {
                    // The hints are read again at the next bring-up.
                }
                _ => {}
            }
            self.aenq_head = self.aenq_head.wrapping_add(1);
            if self.aenq_head & (adm::EVENT_DEPTH - 1) == 0 {
                self.aenq_phase ^= 1;
            }
            taken += 1;
        }
        if taken > 0 && !self.hold_head {
            self.p.wmb();
            self.write_reg(regs::AENQ_HEAD_DB, u32::from(self.aenq_head));
        }
        reset
    }

    fn keep_alive_event(&mut self, at: usize, now: u64) {
        self.keep.count += 1;
        self.keep_run += 1;
        self.keep.rx_drops = self.read_u64(at + adm::AENQ_DATA + adm::KA_RX_DROPS);
        self.keep.tx_drops = self.read_u64(at + adm::AENQ_DATA + adm::KA_TX_DROPS);
        self.keep.rx_overruns = self.read_u64(at + adm::AENQ_DATA + adm::KA_RX_OVERRUNS);
        self.keep_ns = now;
        if self.keep_run <= 3 || self.keep.count.is_multiple_of(KEEPALIVE_EVERY) {
            self.p.log(format_args!(
                "ena: keepalive {} rx_drops {} tx_drops {}",
                self.keep.count, self.keep.rx_drops, self.keep.tx_drops
            ));
        }
    }

    /// The checks of the watchdog, every 100 ms: the cause of a reset.
    fn watchdog(&mut self, now: u64) -> Option<u32> {
        let limit = match self.info.hint_watchdog_ms {
            0 => adm::KEEP_ALIVE_TIMEOUT_MS,
            ms => u64::from(ms),
        };
        if self.keep_watch && now - self.keep_ns > limit * NS_PER_MS {
            return Some(regs::RESET_KEEP_ALIVE_TO);
        }
        if now - self.status_ns >= STATUS_NS {
            self.status_ns = now;
            self.status_due = true;
        }
        None
    }
}
