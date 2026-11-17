// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The controller as one state machine that `Nvme::poll` advances one step at
//! a time. A step reads or writes one register at most and a bounded number of
//! words of memory, and returns; every wait is a deadline against
//! `Platform::now_ns` checked by the next step, so a caller that must stay
//! short never stands in a wait.
//!
//! The order of the bring-up is the one of the specification (section
//! "Initialization"): read CAP, clear CC.EN and wait for CSTS.RDY = 0, set
//! AQA, ASQ and ACQ, set CC (the I/O command set, the page size, the entry
//! sizes) with EN = 1, wait for CSTS.RDY = 1, then the admin commands one at a
//! time: Set Features (number of queues), Identify controller, Identify
//! namespace, Create I/O CQ, Create I/O SQ. A reset in place runs the same
//! path again on the same memory.

use crate::cmd::{self, Cqe, Sqe};
use crate::regs::{self, Cap};
use core::fmt;

/// What the controller and the platform give the driver: the 32-bit registers
/// of BAR 0 (each a single `ldr` or `str`, no writeback [G34]), a clock, the
/// barriers that order stores to the queues against a doorbell write and a
/// load of a completion against the phase read before it, and the console.
pub trait Platform {
    fn read32(&self, offset: u32) -> u32;
    fn write32(&self, offset: u32, value: u32);
    fn now_ns(&self) -> u64;
    /// `dmb oshst`: the stores to the queues come before the doorbell write
    /// that follows.
    fn wmb(&self);
    /// `dmb oshld`: the loads of a completion after this see what the
    /// controller stored before the phase bit that was read.
    fn rmb(&self);
    fn log(&self, line: fmt::Arguments<'_>);
}

/// A piece of memory the controller reads and writes: `len` bytes at `va` in
/// the driver's space that the controller addresses as `pa`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub va: usize,
    pub pa: u64,
    pub len: usize,
}

/// The cells: four of 16 KiB, in one region, each four pages.
pub const CELL: usize = 16 * 1024;
pub const CELLS: usize = 4;
pub const CELLS_BYTES: usize = CELL * CELLS;
/// The slots of requests: one a cell and one for Flush.
pub const TAGS: usize = CELLS + 1;
pub const FLUSH_TAG: u8 = CELLS as u8;

/// The queues: the admin pair at most 16 deep, the I/O pair 32 deep.
pub const ADMIN_DEPTH: u16 = 16;
pub const IO_DEPTH: u16 = 32;
const QID_IO: u16 = 1;

/// The placement in the first region (32 KiB, eight pages, each structure on
/// a page of its own).
pub const ASQ_AT: usize = 0;
pub const ACQ_AT: usize = 0x1000;
pub const IOSQ_AT: usize = 0x2000;
pub const IOCQ_AT: usize = 0x3000;
pub const IDENT_AT: usize = 0x4000;
/// The page of the PRP lists, one of `LIST_STRIDE` bytes for each cell.
pub const LISTS_AT: usize = 0x5000;
pub const LIST_STRIDE: usize = 32;
pub const MEM_BYTES: usize = 0x8000;
const _: () = assert!(ADMIN_DEPTH as usize * cmd::SQE_BYTES <= cmd::PAGE);
const _: () = assert!(IO_DEPTH as usize * cmd::SQE_BYTES <= cmd::PAGE);
const _: () = assert!(CELLS * LIST_STRIDE <= cmd::PAGE);
const _: () = assert!((CELL / cmd::PAGE - 1) * 8 <= LIST_STRIDE);

/// The register accesses a step or a call of the submission makes at most.
pub const REG_ACCESSES_PER_STEP: u32 = 1;
/// The 64-bit stores of the step that zeroes one queue (the largest is the
/// I/O submission queue), and the 32-bit stores of the step that writes one
/// entry (a submission entry).
pub const ZERO_STORES_PER_STEP: u32 = (IO_DEPTH as usize * cmd::SQE_BYTES / 8) as u32;
pub const ENTRY_STORES_PER_STEP: u32 = 16;
/// The submission entries one call of `read`, `write` or `flush` puts in the
/// queue (the parts a controller's MDTS cuts a cell into), and the completion
/// entries one step takes.
pub const MAX_PARTS: usize = 2;
pub const CQES_PER_STEP: u32 = 1;
/// How long a command of the I/O queue waits before the console says so; it
/// is never cut off (a volume under repair may delay answers a long time).
pub const SLOW_IO_NS: u64 = 30_000_000_000;
/// The step of the watchdog: one read of CSTS.
const WATCH_NS: u64 = 100_000_000;
/// How long the controller has to finish a normal shutdown.
const SHUTDOWN_NS: u64 = 5_000_000_000;
/// Three resets inside this window (or three times CAP.TO, if longer) end the recovery in place.
const RESETS: usize = 3;
const RESET_WINDOW_NS: u64 = 60_000_000_000;

/// The choices of the owner.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The depth of the admin queues, 2 to `ADMIN_DEPTH`.
    pub admin_depth: u16,
    /// The vector of the I/O completion queue's interrupt, None to run on
    /// polling (IEN = 0).
    pub vector: Option<u16>,
    /// The namespace to use.
    pub nsid: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            admin_depth: ADMIN_DEPTH,
            vector: None,
            nsid: 1,
        }
    }
}

/// What Identify told the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub version: u32,
    pub cap: Cap,
    pub serial: [u8; 20],
    pub model: [u8; 40],
    pub firmware: [u8; 8],
    /// The vendor specific bytes 3072..3104 of Identify controller: the name of the block device
    /// on EBS ("sdf" or "/dev/sdf"), zeros elsewhere.
    pub vendor_name: [u8; 32],
    /// The namespaces the controller reports.
    pub nn: u32,
    /// Whether the controller has a volatile write cache (Identify
    /// controller VWC bit 0): then only Flush makes completed writes durable.
    pub vwc: bool,
    /// MDTS as Identify gave it (0: no limit), and the bytes one command may
    /// move, at most one cell.
    pub mdts: u8,
    pub max_transfer: usize,
    pub nsid: u32,
    /// The blocks of the namespace and the log2 of the bytes of a block.
    pub blocks: u64,
    pub block_shift: u8,
}

/// Why the controller is down for good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A region is too small, not page-aligned, or `Config` is out of range.
    Region,
    /// CAP does not allow what the driver needs.
    Unsupported(Unsupported),
    /// CSTS reads as all ones: the function is gone.
    Gone,
    /// An admin command got a status other than success.
    Admin { opcode: u8, sct: u8, sc: u8 },
    /// No namespace, or one with a format the driver does not run.
    Namespace,
    /// The controller did not finish the shutdown.
    Shutdown,
    /// Three resets inside a minute.
    TooManyResets,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// The NVM command set is not in CAP.CSS.
    CommandSet,
    /// 4 KiB is not a memory page size the controller takes.
    PageSize,
    /// The I/O queue would be deeper than CAP.MQES.
    QueueSize,
}

/// Why a reset in place began.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// CSTS.CFS = 1.
    Fatal,
    /// CSTS read as all ones while the controller was running.
    Gone,
    /// An admin command did not complete within CAP.TO.
    AdminTimeout,
    /// CSTS.RDY did not rise within CAP.TO.
    NotReady,
    /// CSTS.RDY did not fall within CAP.TO.
    NotCleared,
}

/// How a request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// The controller answered with this status (SCT and SC of the entry).
    Error {
        sct: u8,
        sc: u8,
        dnr: bool,
    },
    /// A reset took the command; it may or may not have run.
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The cell of a Read or Write, `FLUSH_TAG` for a Flush.
    pub tag: u8,
    pub outcome: Outcome,
}

/// What a step did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Nothing to do until a doorbell is answered or the clock moves.
    Idle,
    /// A step of work was done; call again.
    Working,
    /// The queues are made; requests are taken.
    Up,
    /// A request ended.
    Done(Completion),
    /// A reset in place began; the requests in work end as `Aborted`.
    Reset(Cause),
    /// The controller is down for good.
    Failed(Failure),
    /// The shutdown finished.
    Stopped,
}

/// Why a request was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The queues are not up.
    NotUp,
    /// The cell (or Flush) has a request in work, or the queue is full.
    Busy,
    /// A cell out of range, no blocks, or more than a cell.
    Invalid,
    /// The blocks lie outside the window.
    Range,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmd {
    SetQueues,
    IdentController,
    IdentNamespace,
    CreateCq,
    CreateSq,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    Restart,
    Fail(Failure),
    Stop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    CapLo,
    CapHi,
    ReadCc,
    WriteCcOff,
    WaitNotReady,
    Zero(u8),
    Aqa,
    AsqLo,
    AsqHi,
    AcqLo,
    AcqHi,
    CcOn,
    WaitReady,
    AdminSubmit(Cmd),
    AdminWait(Cmd, u16),
    AdminAck(Cmd, Cqe),
    Up,
    Abort {
        cause: Cause,
        next: Next,
        announced: bool,
    },
    /// CC.EN = 0 written; wait for CSTS.RDY = 0, after which the controller
    /// does no more DMA and the requests in work can be handed back.
    QuiesceWrite(Next),
    QuiesceWait(Next),
    Drain(Next),
    /// CC.EN = 1 and RDY = 0 at the start: firmware is enabling the controller.
    WaitEnabled,
    ShutWrite,
    ShutWait,
    ShutOff,
    ShutWaitOff,
    Stopped,
    Failed,
}

/// One queue pair's position: the tail of the submission queue the driver
/// writes, the head of it as the controller reported it, the head of the
/// completion queue the driver reads and the phase it expects there.
#[derive(Clone, Copy, Debug, Default)]
struct Ring {
    depth: u16,
    sq_tail: u16,
    sq_head: u16,
    cq_head: u16,
    phase: bool,
}

impl Ring {
    fn new(depth: u16) -> Ring {
        Ring {
            depth,
            sq_tail: 0,
            sq_head: 0,
            cq_head: 0,
            phase: true,
        }
    }

    /// Entries free in the submission queue (one stays empty).
    fn free(&self) -> u16 {
        self.depth - 1 - (self.sq_tail + self.depth - self.sq_head) % self.depth
    }

    fn push(&mut self) -> u16 {
        let at = self.sq_tail;
        self.sq_tail = (self.sq_tail + 1) % self.depth;
        at
    }

    fn pop(&mut self) {
        self.cq_head += 1;
        if self.cq_head == self.depth {
            self.cq_head = 0;
            if !cfg!(feature = "break-nvme-cq-phase") {
                self.phase = !self.phase;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Idle,
    /// A Flush waits for the writes in `mask` (bit per cell) to complete.
    FlushWait {
        mask: u8,
    },
    Busy(Busy),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Busy {
    /// None for a Flush.
    op: Option<Op>,
    parts: u8,
    done: u8,
    /// The first error of the parts.
    error: Option<(u8, u8, bool)>,
    since_ns: u64,
    warned: bool,
}

/// The driver.
pub struct Nvme<P: Platform> {
    p: P,
    mem: Region,
    cells: Region,
    cfg: Config,
    stage: Stage,
    cap: Cap,
    deadline: u64,
    next_watch: u64,
    info: Option<Info>,
    admin: Ring,
    io: Ring,
    slots: [Slot; TAGS],
    /// The window of the namespace the owner gets: first block and blocks.
    window: (u64, u64),
    window_set: bool,
    cid: u16,
    resets: [u64; RESETS],
    reset_count: u64,
    stray: u64,
}

impl<P: Platform> Nvme<P> {
    /// Takes the memory.
    ///
    /// # Safety
    ///
    /// `mem` and `cells` are memory the process maps read and write, as
    /// `va`, `len` bytes each, that the controller addresses at `pa` and
    /// nothing else uses, for as long as the value lives. The queues are
    /// `mem`, which is `MEM_BYTES` or more; the cells are `CELLS_BYTES` or
    /// more; both start on a page.
    ///
    /// The driver assumes DMA is coherent and does no cache maintenance: the
    /// controller and the CPU see the same bytes once the barriers have run.
    /// That holds on t4g (no SMMU node in IORT, and the Nitro PCIe is
    /// I/O-coherent) and under QEMU TCG. It is unverified under HVF or KVM,
    /// where a non-cacheable guest mapping against a cacheable host access can
    /// lose coherence.
    pub unsafe fn open(p: P, mem: Region, cells: Region, cfg: Config) -> Result<Nvme<P>, Failure> {
        let aligned =
            |r: &Region| r.va.is_multiple_of(cmd::PAGE) && r.pa.is_multiple_of(cmd::PAGE as u64);
        if mem.len < MEM_BYTES
            || cells.len < CELLS_BYTES
            || !aligned(&mem)
            || !aligned(&cells)
            || cfg.admin_depth < 2
            || cfg.admin_depth > ADMIN_DEPTH
        {
            return Err(Failure::Region);
        }
        let n = Nvme {
            p,
            mem,
            cells,
            cfg,
            stage: Stage::CapLo,
            cap: Cap::decode(0, 0),
            deadline: 0,
            next_watch: 0,
            info: None,
            admin: Ring::new(cfg.admin_depth),
            io: Ring::new(IO_DEPTH),
            slots: [Slot::Idle; TAGS],
            window: (0, 0),
            window_set: false,
            cid: 0,
            resets: [0; RESETS],
            reset_count: 0,
            stray: 0,
        };
        // The PRP lists never change: the list of a cell holds its pages 1 to
        // 3, so that a part of four pages is PRP1 and a pointer to the list.
        for cell in 0..CELLS {
            for j in 0..(CELL / cmd::PAGE - 1) {
                let pa = cells.pa + (cell * CELL + (j + 1) * cmd::PAGE) as u64;
                n.put64(LISTS_AT + cell * LIST_STRIDE + j * 8, pa);
            }
        }
        Ok(n)
    }

    pub fn info(&self) -> Option<&Info> {
        self.info.as_ref()
    }

    pub fn is_up(&self) -> bool {
        self.stage == Stage::Up
    }

    /// The resets in place so far.
    pub fn resets(&self) -> u64 {
        self.reset_count
    }

    /// The completions the driver could not match to a request.
    pub fn stray(&self) -> u64 {
        self.stray
    }

    pub fn platform(&self) -> &P {
        &self.p
    }

    /// The virtual address of the cell, for the owner to fill and read.
    pub fn cell_va(&self, cell: u8) -> usize {
        self.cells.va + cell as usize * CELL
    }

    /// The blocks of the window and the log2 of the bytes of a block, once up.
    pub fn blocks(&self) -> u64 {
        self.window.1
    }

    /// Narrows the window the requests address to `len` blocks from `first`
    /// (block 0 of a request is `first`). False when it is not inside the
    /// namespace or the controller is not up.
    pub fn set_window(&mut self, first: u64, len: u64) -> bool {
        let Some(info) = self.info else { return false };
        if first.checked_add(len).is_none_or(|e| e > info.blocks) {
            return false;
        }
        self.window = (first, len);
        self.window_set = true;
        true
    }

    // ----- memory -----

    fn put32(&self, at: usize, v: u32) {
        // SAFETY: `at` lies in `mem` (the layout above and `open`'s promise).
        unsafe { core::ptr::write_volatile((self.mem.va + at) as *mut u32, v) }
    }

    fn put64(&self, at: usize, v: u64) {
        // SAFETY: as for `put32`.
        unsafe { core::ptr::write_volatile((self.mem.va + at) as *mut u64, v) }
    }

    fn get32(&self, at: usize) -> u32 {
        // SAFETY: as for `put32`.
        unsafe { core::ptr::read_volatile((self.mem.va + at) as *const u32) }
    }

    fn get8(&self, at: usize) -> u8 {
        // SAFETY: as for `put32`.
        unsafe { core::ptr::read_volatile((self.mem.va + at) as *const u8) }
    }

    fn put_sqe(&self, base: usize, slot: u16, e: &Sqe) {
        for (i, w) in e.iter().enumerate() {
            self.put32(base + slot as usize * cmd::SQE_BYTES + i * 4, *w);
        }
    }

    /// The doorbell: the stores to the queue come first.
    fn ring_sq(&self, qid: u16, tail: u16) {
        if !cfg!(feature = "break-nvme-wmb") {
            self.p.wmb();
        }
        self.p
            .write32(regs::sq_tail_db(qid, self.cap.dstrd), tail as u32);
    }

    fn ring_cq(&self, qid: u16, head: u16) {
        if !cfg!(feature = "break-nvme-cq-head") {
            self.p
                .write32(regs::cq_head_db(qid, self.cap.dstrd), head as u32);
        }
    }

    /// The completion at the head of the ring whose queue is at `base`, when
    /// the phase says the controller wrote it.
    fn take_cqe(&self, base: usize, ring: &Ring) -> Option<Cqe> {
        let at = base + ring.cq_head as usize * cmd::CQE_BYTES;
        let dw3 = self.get32(at + 12);
        if cmd::phase_of(dw3) != ring.phase {
            return None;
        }
        // The other dwords are read after the phase.
        self.p.rmb();
        Some(Cqe::decode([
            self.get32(at),
            self.get32(at + 4),
            self.get32(at + 8),
            dw3,
        ]))
    }

    fn mem_pa(&self, at: usize) -> u64 {
        self.mem.pa + at as u64
    }

    // ----- the steps -----

    /// One step.
    pub fn poll(&mut self) -> Event {
        match self.stage {
            Stage::CapLo => {
                let lo = self.p.read32(regs::CAP_LO);
                if lo == regs::GONE {
                    return self.fail(Failure::Gone);
                }
                self.cap = Cap::decode(lo, 0);
                self.stage = Stage::CapHi;
                Event::Working
            }
            Stage::CapHi => {
                let hi = self.p.read32(regs::CAP_HI);
                let high = Cap::decode(0, hi);
                self.cap = Cap {
                    dstrd: high.dstrd,
                    css: high.css,
                    mpsmin: high.mpsmin,
                    mpsmax: high.mpsmax,
                    ..self.cap
                };
                if self.cap.css & 1 == 0 {
                    return self.fail(Failure::Unsupported(Unsupported::CommandSet));
                }
                if self.cap.mpsmin != 0 {
                    return self.fail(Failure::Unsupported(Unsupported::PageSize));
                }
                if self.cap.mqes < IO_DEPTH - 1 {
                    return self.fail(Failure::Unsupported(Unsupported::QueueSize));
                }
                self.stage = Stage::ReadCc;
                Event::Working
            }
            Stage::ReadCc => {
                let cc = self.p.read32(regs::CC);
                if cc == regs::GONE {
                    return self.fail(Failure::Gone);
                }
                self.stage = if cc & regs::CC_EN != 0 {
                    // Enabled: let a controller that is still becoming ready
                    // get there before CC.EN is cleared (NVMe 1.3, section
                    // 3.1.5, "likely" by the review that named it; the clause
                    // is not checked against the text).
                    self.deadline = self.p.now_ns() + self.cap.timeout_ns();
                    Stage::WaitEnabled
                } else {
                    self.wait_clear()
                };
                Event::Working
            }
            Stage::WaitEnabled => {
                let sts = self.p.read32(regs::CSTS);
                if sts == regs::GONE {
                    return self.fail(Failure::Gone);
                }
                if sts & regs::CSTS_RDY != 0 || self.p.now_ns() > self.deadline {
                    self.stage = Stage::WriteCcOff;
                    Event::Working
                } else {
                    Event::Idle
                }
            }
            Stage::WriteCcOff => {
                self.p.write32(regs::CC, 0);
                self.stage = self.wait_clear();
                Event::Working
            }
            Stage::WaitNotReady => self.step_wait_not_ready(),
            Stage::Zero(area) => self.step_zero(area),
            Stage::Aqa => {
                let d = self.cfg.admin_depth as u32 - 1;
                self.p.write32(regs::AQA, d | d << 16);
                self.stage = Stage::AsqLo;
                Event::Working
            }
            Stage::AsqLo => {
                self.p.write32(regs::ASQ_LO, self.mem_pa(ASQ_AT) as u32);
                self.stage = Stage::AsqHi;
                Event::Working
            }
            Stage::AsqHi => {
                self.p
                    .write32(regs::ASQ_HI, (self.mem_pa(ASQ_AT) >> 32) as u32);
                self.stage = Stage::AcqLo;
                Event::Working
            }
            Stage::AcqLo => {
                self.p.write32(regs::ACQ_LO, self.mem_pa(ACQ_AT) as u32);
                self.stage = Stage::AcqHi;
                Event::Working
            }
            Stage::AcqHi => {
                self.p
                    .write32(regs::ACQ_HI, (self.mem_pa(ACQ_AT) >> 32) as u32);
                self.stage = Stage::CcOn;
                Event::Working
            }
            Stage::CcOn => {
                self.p.write32(regs::CC, regs::cc_enable());
                self.deadline = self.p.now_ns() + self.cap.timeout_ns();
                self.stage = Stage::WaitReady;
                Event::Working
            }
            Stage::WaitReady => self.step_wait_ready(),
            Stage::AdminSubmit(c) => self.step_admin_submit(c),
            Stage::AdminWait(c, cid) => self.step_admin_wait(c, cid),
            Stage::AdminAck(c, cqe) => self.step_admin_ack(c, cqe),
            Stage::Up => self.step_up(),
            Stage::Abort {
                cause,
                next,
                announced,
            } => self.step_abort(cause, next, announced),
            Stage::QuiesceWrite(next) => {
                self.p.write32(regs::CC, 0);
                self.deadline = self.p.now_ns() + self.cap.timeout_ns();
                self.stage = Stage::QuiesceWait(next);
                Event::Working
            }
            Stage::QuiesceWait(next) => {
                let sts = self.p.read32(regs::CSTS);
                let early = cfg!(feature = "break-nvme-abort-early");
                if early || sts == regs::GONE || sts & regs::CSTS_RDY == 0 {
                    self.stage = Stage::Drain(next);
                    Event::Working
                } else if self.p.now_ns() > self.deadline {
                    self.p.log(format_args!("nvme: RDY did not fall"));
                    self.stage = Stage::Drain(next);
                    Event::Working
                } else {
                    Event::Idle
                }
            }
            Stage::Drain(next) => self.step_drain(next),
            Stage::ShutWrite => {
                self.p
                    .write32(regs::CC, regs::cc_enable() | regs::CC_SHN_NORMAL);
                self.deadline = self.p.now_ns() + SHUTDOWN_NS;
                self.stage = Stage::ShutWait;
                Event::Working
            }
            Stage::ShutWait => {
                let sts = self.p.read32(regs::CSTS);
                if (sts & regs::CSTS_SHST_MASK) >> regs::CSTS_SHST_SHIFT == regs::CSTS_SHST_COMPLETE
                {
                    self.stage = Stage::ShutOff;
                    Event::Working
                } else if self.p.now_ns() > self.deadline {
                    self.fail(Failure::Shutdown)
                } else {
                    Event::Idle
                }
            }
            Stage::ShutOff => {
                self.p.write32(regs::CC, 0);
                self.deadline = self.p.now_ns() + self.cap.timeout_ns();
                self.stage = Stage::ShutWaitOff;
                Event::Working
            }
            Stage::ShutWaitOff => {
                let sts = self.p.read32(regs::CSTS);
                if sts & regs::CSTS_RDY == 0 {
                    self.stage = Stage::Drain(Next::Stop);
                    Event::Working
                } else if self.p.now_ns() > self.deadline {
                    self.fail(Failure::Shutdown)
                } else {
                    Event::Idle
                }
            }
            Stage::Stopped | Stage::Failed => Event::Idle,
        }
    }

    /// Begins a normal shutdown (CC.SHN = 1, wait for CSTS.SHST = 2, then
    /// CC = 0): the requests in work end as `Aborted`, then `Stopped` comes.
    pub fn shutdown(&mut self) {
        match self.stage {
            Stage::Stopped | Stage::Failed => {}
            // Up: the notification needs the admin queues; the requests in
            // work are handed back after RDY = 0.
            Stage::Up => self.stage = Stage::ShutWrite,
            Stage::ShutWrite | Stage::ShutWait | Stage::ShutOff | Stage::ShutWaitOff => {}
            // A reset or a failure is under way: it ends in `Stopped` unless it
            // is a failure.
            Stage::Abort {
                cause,
                next,
                announced,
            } => {
                self.stage = Stage::Abort {
                    cause,
                    next: Self::stop(next),
                    announced,
                };
            }
            Stage::QuiesceWrite(n) => self.stage = Stage::QuiesceWrite(Self::stop(n)),
            Stage::QuiesceWait(n) => self.stage = Stage::QuiesceWait(Self::stop(n)),
            Stage::Drain(n) => self.stage = Stage::Drain(Self::stop(n)),
            // Not up yet: there are no admin queues for a notification, so
            // CC = 0 and the wait for RDY = 0 (the controller is never enabled
            // to be shut down).
            _ => {
                self.stage = Stage::Abort {
                    cause: Cause::Fatal,
                    next: Next::Stop,
                    announced: true,
                }
            }
        }
    }

    fn stop(next: Next) -> Next {
        match next {
            Next::Fail(f) => Next::Fail(f),
            _ => Next::Stop,
        }
    }

    fn fail(&mut self, f: Failure) -> Event {
        self.stage = Stage::Abort {
            cause: Cause::Fatal,
            next: Next::Fail(f),
            announced: true,
        };
        Event::Working
    }

    /// A reset in place begins: the requests in work end first.
    fn reset(&mut self, cause: Cause) -> Event {
        self.p.log(format_args!("nvme: reset ({cause:?})"));
        self.stage = Stage::Abort {
            cause,
            next: Next::Restart,
            announced: false,
        };
        Event::Working
    }

    fn wait_clear(&mut self) -> Stage {
        if cfg!(feature = "break-nvme-reset-wait") {
            return Stage::Zero(0);
        }
        self.deadline = self.p.now_ns() + self.cap.timeout_ns();
        Stage::WaitNotReady
    }

    fn step_wait_not_ready(&mut self) -> Event {
        let sts = self.p.read32(regs::CSTS);
        if sts == regs::GONE {
            return self.fail(Failure::Gone);
        }
        if sts & regs::CSTS_RDY == 0 {
            self.stage = Stage::Zero(0);
            Event::Working
        } else if self.p.now_ns() > self.deadline {
            self.reset(Cause::NotCleared)
        } else {
            Event::Idle
        }
    }

    fn step_wait_ready(&mut self) -> Event {
        let sts = self.p.read32(regs::CSTS);
        if sts == regs::GONE {
            return self.fail(Failure::Gone);
        }
        if sts & regs::CSTS_CFS != 0 {
            return self.reset(Cause::Fatal);
        }
        if sts & regs::CSTS_RDY != 0 {
            self.admin = Ring::new(self.cfg.admin_depth);
            self.io = Ring::new(IO_DEPTH);
            self.stage = Stage::AdminSubmit(Cmd::SetQueues);
            Event::Working
        } else if self.p.now_ns() > self.deadline {
            self.reset(Cause::NotReady)
        } else {
            Event::Idle
        }
    }

    /// Zeroes one queue a step: the completion queues must read phase 0 and
    /// the submission queues hold nothing.
    fn step_zero(&mut self, area: u8) -> Event {
        let (at, bytes) = match area {
            0 => (ASQ_AT, self.cfg.admin_depth as usize * cmd::SQE_BYTES),
            1 => (ACQ_AT, self.cfg.admin_depth as usize * cmd::CQE_BYTES),
            2 => (IOSQ_AT, IO_DEPTH as usize * cmd::SQE_BYTES),
            _ => (IOCQ_AT, IO_DEPTH as usize * cmd::CQE_BYTES),
        };
        for i in 0..bytes / 8 {
            self.put64(at + i * 8, 0);
        }
        self.stage = if area == 3 {
            Stage::Aqa
        } else {
            Stage::Zero(area + 1)
        };
        Event::Working
    }

    // ----- the admin queue -----

    fn admin_sqe(&mut self, c: Cmd) -> (Sqe, u16) {
        self.cid = self.cid.wrapping_add(1) & 0x7fff;
        let cid = self.cid;
        let nsid = self.cfg.nsid;
        let e = match c {
            Cmd::SetQueues => {
                let mut e = cmd::sqe(cmd::ADMIN_SET_FEATURES, cid, 0);
                e[10] = cmd::FID_NUMBER_OF_QUEUES;
                // One queue pair, 0-based.
                e[11] = 0;
                e
            }
            Cmd::IdentController | Cmd::IdentNamespace => {
                let ctrl = c == Cmd::IdentController;
                let mut e = cmd::sqe(cmd::ADMIN_IDENTIFY, cid, if ctrl { 0 } else { nsid });
                cmd::set_prp(&mut e, self.mem_pa(IDENT_AT), 0);
                e[10] = if ctrl {
                    cmd::CNS_CONTROLLER
                } else {
                    cmd::CNS_NAMESPACE
                };
                e
            }
            Cmd::CreateCq => {
                let mut e = cmd::sqe(cmd::ADMIN_CREATE_CQ, cid, 0);
                cmd::set_prp(&mut e, self.mem_pa(IOCQ_AT), 0);
                e[10] = QID_IO as u32 | (IO_DEPTH as u32 - 1) << 16;
                // Physically contiguous, interrupts on when there is a vector.
                e[11] = 1 | match self.cfg.vector {
                    Some(v) => 2 | (v as u32) << 16,
                    None => 0,
                };
                e
            }
            Cmd::CreateSq => {
                let mut e = cmd::sqe(cmd::ADMIN_CREATE_SQ, cid, 0);
                cmd::set_prp(&mut e, self.mem_pa(IOSQ_AT), 0);
                e[10] = QID_IO as u32 | (IO_DEPTH as u32 - 1) << 16;
                // Physically contiguous, medium priority irrelevant, CQ 1.
                e[11] = 1 | (QID_IO as u32) << 16;
                e
            }
        };
        (e, cid)
    }

    fn step_admin_submit(&mut self, c: Cmd) -> Event {
        let (e, cid) = self.admin_sqe(c);
        let slot = self.admin.push();
        self.put_sqe(ASQ_AT, slot, &e);
        self.ring_sq(0, self.admin.sq_tail);
        self.deadline = self.p.now_ns() + self.cap.timeout_ns();
        self.stage = Stage::AdminWait(c, cid);
        Event::Working
    }

    fn step_admin_wait(&mut self, c: Cmd, cid: u16) -> Event {
        if let Some(cqe) = self.take_cqe(ACQ_AT, &self.admin) {
            self.admin.pop();
            if cqe.cid != cid {
                self.stray += 1;
                // A completion of nothing we sent: acknowledge and wait on.
                self.ring_cq(0, self.admin.cq_head);
                return Event::Working;
            }
            self.admin.sq_head = cqe.sq_head;
            self.stage = Stage::AdminAck(c, cqe);
            return Event::Working;
        }
        if self.p.now_ns() > self.deadline {
            return self.reset(Cause::AdminTimeout);
        }
        match self.watch() {
            Some(cause) => self.reset(cause),
            None => Event::Idle,
        }
    }

    fn step_admin_ack(&mut self, c: Cmd, cqe: Cqe) -> Event {
        self.ring_cq(0, self.admin.cq_head);
        if !cqe.ok() {
            let opcode = match c {
                Cmd::SetQueues => cmd::ADMIN_SET_FEATURES,
                Cmd::IdentController | Cmd::IdentNamespace => cmd::ADMIN_IDENTIFY,
                Cmd::CreateCq => cmd::ADMIN_CREATE_CQ,
                Cmd::CreateSq => cmd::ADMIN_CREATE_SQ,
            };
            return self.fail(Failure::Admin {
                opcode,
                sct: cqe.sct,
                sc: cqe.sc,
            });
        }
        let next = match c {
            Cmd::SetQueues => Cmd::IdentController,
            Cmd::IdentController => {
                self.parse_controller();
                Cmd::IdentNamespace
            }
            Cmd::IdentNamespace => {
                if !self.parse_namespace() {
                    return self.fail(Failure::Namespace);
                }
                Cmd::CreateCq
            }
            Cmd::CreateCq => Cmd::CreateSq,
            Cmd::CreateSq => {
                self.next_watch = self.p.now_ns() + WATCH_NS;
                self.stage = Stage::Up;
                return Event::Up;
            }
        };
        self.stage = Stage::AdminSubmit(next);
        Event::Working
    }

    fn bytes<const N: usize>(&self, at: usize) -> [u8; N] {
        let mut b = [0u8; N];
        for (i, x) in b.iter_mut().enumerate() {
            *x = self.get8(IDENT_AT + at + i);
        }
        b
    }

    fn parse_controller(&mut self) {
        let mdts = self.get8(IDENT_AT + cmd::IDC_MDTS);
        let max_transfer = if mdts == 0 || mdts >= 8 {
            CELL
        } else {
            CELL.min(cmd::PAGE << mdts)
        };
        self.info = Some(Info {
            version: self.get32(IDENT_AT + cmd::IDC_VER),
            cap: self.cap,
            serial: self.bytes(cmd::IDC_SN),
            model: self.bytes(cmd::IDC_MN),
            firmware: self.bytes(cmd::IDC_FR),
            vendor_name: self.bytes(cmd::IDC_VENDOR_NAME),
            nn: self.get32(IDENT_AT + cmd::IDC_NN),
            vwc: self.get8(IDENT_AT + cmd::IDC_VWC) & 1 != 0,
            mdts,
            max_transfer,
            nsid: self.cfg.nsid,
            blocks: 0,
            block_shift: 0,
        });
    }

    /// The size and the format of the namespace. False for an inactive
    /// namespace and for a format with metadata or a block size other than 512
    /// and 4096 bytes.
    fn parse_namespace(&mut self) -> bool {
        let nsze = u64::from(self.get32(IDENT_AT + cmd::IDN_NSZE))
            | u64::from(self.get32(IDENT_AT + cmd::IDN_NSZE + 4)) << 32;
        let flbas = self.get8(IDENT_AT + cmd::IDN_FLBAS);
        let nlbaf = self.get8(IDENT_AT + cmd::IDN_NLBAF);
        let index = (flbas & 0xf) | (flbas >> 5 & 3) << 4;
        if index > nlbaf || nsze == 0 {
            return false;
        }
        let lbaf = self.get32(IDENT_AT + cmd::IDN_LBAF + index as usize * 4);
        let (ms, lbads) = (lbaf & 0xffff, (lbaf >> 16 & 0xff) as u8);
        if ms != 0 || !(lbads == 9 || lbads == 12) {
            return false;
        }
        let Some(info) = self.info.as_mut() else {
            return false;
        };
        info.blocks = nsze;
        info.block_shift = lbads;
        // The owner's window survives a reset in place if it still fits.
        if !(self.window_set && self.window.0 + self.window.1 <= nsze) {
            self.window = (0, nsze);
            self.window_set = false;
        }
        true
    }

    // ----- the watchdog -----

    /// Reads CSTS once in `WATCH_NS`: a fatal status or a function that is
    /// gone is a cause to reset.
    fn watch(&mut self) -> Option<Cause> {
        let now = self.p.now_ns();
        if now < self.next_watch {
            return None;
        }
        self.next_watch = now + WATCH_NS;
        let sts = self.p.read32(regs::CSTS);
        if sts == regs::GONE {
            Some(Cause::Gone)
        } else if sts & regs::CSTS_CFS != 0 {
            Some(Cause::Fatal)
        } else {
            None
        }
    }

    // ----- the reset -----

    fn step_abort(&mut self, cause: Cause, next: Next, announced: bool) -> Event {
        if !announced {
            self.stage = Stage::Abort {
                cause,
                next,
                announced: true,
            };
            return Event::Reset(cause);
        }
        // The controller is stopped before any request is handed back: a
        // command in work may still move data into its cell until RDY = 0.
        self.stage = Stage::QuiesceWrite(next);
        Event::Working
    }

    fn step_drain(&mut self, next: Next) -> Event {
        // Up to the requests in work, one a step.
        for tag in 0..TAGS {
            if self.slots[tag] != Slot::Idle {
                self.slots[tag] = Slot::Idle;
                return Event::Done(Completion {
                    tag: tag as u8,
                    outcome: Outcome::Aborted,
                });
            }
        }
        match next {
            Next::Restart => {
                let now = self.p.now_ns();
                self.reset_count += 1;
                self.resets.rotate_left(1);
                self.resets[RESETS - 1] = now;
                // The oldest of the last three, when there are three.
                let oldest = self.resets[0];
                if oldest != 0 && now - oldest < RESET_WINDOW_NS.max(3 * self.cap.timeout_ns()) {
                    self.p.log(format_args!("nvme: too many resets"));
                    self.stage = Stage::Failed;
                    return Event::Failed(Failure::TooManyResets);
                }
                self.stage = Stage::CapLo;
                Event::Working
            }
            Next::Fail(f) => {
                self.p.log(format_args!("nvme: failed ({f:?})"));
                self.stage = Stage::Failed;
                Event::Failed(f)
            }
            Next::Stop => {
                self.stage = Stage::Stopped;
                Event::Stopped
            }
        }
    }

    // ----- requests -----

    /// Reads `blocks` blocks from `lba` of the window into the cell.
    pub fn read(&mut self, cell: u8, lba: u64, blocks: u32) -> Result<(), Reject> {
        self.start(Some(Op::Read), cell, lba, blocks)
    }

    /// Writes `blocks` blocks from the cell to `lba` of the window.
    pub fn write(&mut self, cell: u8, lba: u64, blocks: u32) -> Result<(), Reject> {
        self.start(Some(Op::Write), cell, lba, blocks)
    }

    /// Makes the writes taken before it durable. It waits for the writes in
    /// work to complete; then, when the controller has a volatile write cache,
    /// sends Flush, and otherwise (a write is durable when it completes)
    /// completes at once.
    pub fn flush(&mut self) -> Result<(), Reject> {
        if self.stage != Stage::Up {
            return Err(Reject::NotUp);
        }
        let tag = FLUSH_TAG as usize;
        if self.slots[tag] != Slot::Idle {
            return Err(Reject::Busy);
        }
        let mut mask = 0u8;
        if !cfg!(feature = "break-nvme-flush-early") {
            for (cell, s) in self.slots[..CELLS].iter().enumerate() {
                if matches!(s, Slot::Busy(b) if b.op == Some(Op::Write)) {
                    mask |= 1 << cell;
                }
            }
        }
        self.slots[tag] = Slot::FlushWait { mask };
        Ok(())
    }

    fn start(&mut self, op: Option<Op>, cell: u8, lba: u64, blocks: u32) -> Result<(), Reject> {
        let Some(info) = self.info.filter(|_| self.stage == Stage::Up) else {
            return Err(Reject::NotUp);
        };
        let tag = cell as usize;
        let bytes = (blocks as usize) << info.block_shift;
        if tag >= CELLS || blocks == 0 || bytes > CELL {
            return Err(Reject::Invalid);
        }
        if self.slots[tag] != Slot::Idle {
            return Err(Reject::Busy);
        }
        let limit = if cfg!(feature = "break-nvme-partition") {
            info.blocks
        } else {
            self.window.1
        };
        if lba.checked_add(blocks as u64).is_none_or(|e| e > limit) {
            return Err(Reject::Range);
        }
        let part = info.max_transfer;
        let parts = bytes.div_ceil(part);
        debug_assert!(parts <= MAX_PARTS);
        if self.io.free() < parts as u16 {
            return Err(Reject::Busy);
        }
        let opcode = if op == Some(Op::Read) {
            cmd::NVM_READ
        } else {
            cmd::NVM_WRITE
        };
        let first = self.window.0 + lba;
        let per_part = (part >> info.block_shift) as u32;
        for i in 0..parts {
            let off = i * part;
            let len = part.min(bytes - off);
            let nblocks = (len as u32).div_ceil(1 << info.block_shift);
            let cid = (tag as u16) << 2 | i as u16;
            let mut e = cmd::sqe(opcode, cid, info.nsid);
            let first_pa = self.cells.pa + (tag * CELL + off) as u64;
            let list = self.mem_pa(LISTS_AT + tag * LIST_STRIDE);
            let (p1, p2) = cmd::prps(first_pa, len, list);
            cmd::set_prp(&mut e, p1, p2);
            cmd::set_rw(&mut e, first + (i as u64) * per_part as u64, nblocks);
            let slot = self.io.push();
            self.put_sqe(IOSQ_AT, slot, &e);
        }
        self.ring_sq(QID_IO, self.io.sq_tail);
        self.slots[tag] = Slot::Busy(Busy {
            op,
            parts: parts as u8,
            done: 0,
            error: None,
            since_ns: self.p.now_ns(),
            warned: false,
        });
        Ok(())
    }

    /// Sends the Flush command of a request whose writes have completed.
    fn issue_flush(&mut self) -> bool {
        let Some(info) = self.info else { return false };
        if self.io.free() < 1 {
            return false;
        }
        let cid = (FLUSH_TAG as u16) << 2;
        let e = cmd::sqe(cmd::NVM_FLUSH, cid, info.nsid);
        let slot = self.io.push();
        self.put_sqe(IOSQ_AT, slot, &e);
        self.ring_sq(QID_IO, self.io.sq_tail);
        self.slots[FLUSH_TAG as usize] = Slot::Busy(Busy {
            op: None,
            parts: 1,
            done: 0,
            error: None,
            since_ns: self.p.now_ns(),
            warned: false,
        });
        true
    }

    fn step_up(&mut self) -> Event {
        if let Some(cqe) = self.take_cqe(IOCQ_AT, &self.io) {
            return self.complete(cqe);
        }
        // A Flush whose writes are done.
        if let Slot::FlushWait { mask: 0 } = self.slots[FLUSH_TAG as usize] {
            let vwc = self.info.is_some_and(|i| i.vwc);
            if !vwc {
                self.slots[FLUSH_TAG as usize] = Slot::Idle;
                return Event::Done(Completion {
                    tag: FLUSH_TAG,
                    outcome: Outcome::Ok,
                });
            }
            if self.issue_flush() {
                return Event::Working;
            }
        }
        if let Some(cause) = self.watch() {
            return self.reset(cause);
        }
        self.check_slow();
        Event::Idle
    }

    /// Takes one completion: the head moves, the doorbell is written, and the
    /// request ends when its last part did.
    fn complete(&mut self, cqe: Cqe) -> Event {
        self.io.pop();
        if !cfg!(feature = "break-nvme-sq-head") {
            self.io.sq_head = cqe.sq_head % IO_DEPTH;
        }
        self.ring_cq(QID_IO, self.io.cq_head);
        let tag = (cqe.cid >> 2) as usize;
        let part = (cqe.cid & 3) as u8;
        let Some(Slot::Busy(mut b)) = self.slots.get(tag).copied() else {
            self.stray += 1;
            return Event::Working;
        };
        if part >= b.parts || b.done & (1 << part) != 0 {
            self.stray += 1;
            return Event::Working;
        }
        b.done |= 1 << part;
        if !cqe.ok() && b.error.is_none() {
            b.error = Some((cqe.sct, cqe.sc, cqe.dnr));
        }
        if b.done.count_ones() < b.parts as u32 {
            self.slots[tag] = Slot::Busy(b);
            return Event::Working;
        }
        self.slots[tag] = Slot::Idle;
        if b.op == Some(Op::Write)
            && let Slot::FlushWait { mask } = &mut self.slots[FLUSH_TAG as usize]
        {
            *mask &= !(1 << tag);
        }
        let outcome = match b.error {
            None => Outcome::Ok,
            Some((sct, sc, dnr)) => Outcome::Error { sct, sc, dnr },
        };
        Event::Done(Completion {
            tag: tag as u8,
            outcome,
        })
    }

    /// Says on the console, once, that a command has waited `SLOW_IO_NS`.
    fn check_slow(&mut self) {
        let now = self.p.now_ns();
        for tag in 0..TAGS {
            if let Slot::Busy(b) = &mut self.slots[tag]
                && !b.warned
                && now - b.since_ns >= SLOW_IO_NS
            {
                b.warned = true;
                self.p.log(format_args!(
                    "nvme: a command of cell {tag} waits for over {} s",
                    SLOW_IO_NS / 1_000_000_000
                ));
            }
        }
    }
}
