// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A model of the controller on the host, for the tests of the driver and of
//! a service: the register file of BAR 0 with its readiness delays, the
//! queue protocol in memory (the doorbells, the submission entries, the
//! completion entries with their phase bits and the head pointers), the admin
//! commands the driver uses, Read, Write and Flush over a disk with an
//! optional volatile write cache, PRP entries and lists resolved the way the
//! specification says, the fatal status, the function that goes away, the
//! shutdown. It shares the driver's memory (`Region`) the way a controller
//! does, through the physical addresses the driver wrote, and it notes each
//! thing a real controller would refuse or not survive (`violations`).
//!
//! The model runs on the clock of the test (`advance`), which the driver reads
//! through `Platform::now_ns`. It checks the logic of the driver (phases,
//! wraps, order of the bring-up, the barrier before a doorbell, the pages of a
//! transfer). It cannot catch an error the driver and the model make alike,
//! nor what a real volume does (its timing, the fields it fills): the host
//! tests are the first line and the device is the second.

extern crate std;

use crate::cmd;
use crate::device::{Platform, Region};
use crate::regs;
use core::fmt;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::string::{String, ToString};
use std::vec::Vec;

const MS: u64 = 1_000_000;

/// What the model is and what it does that a healthy controller does not.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub mqes: u16,
    pub to: u8,
    pub dstrd: u8,
    pub mpsmin: u8,
    pub css: u8,
    pub mdts: u8,
    pub vwc: bool,
    pub blocks: u64,
    /// log2 of the bytes of a block, 9 or 12.
    pub lba_shift: u8,
    /// The namespace's format carries 8 bytes of metadata.
    pub metadata: bool,
    /// The namespace's format has this log2 block size.
    pub odd_shift: Option<u8>,
    /// Identify namespace answers all zeros (no such namespace).
    pub no_namespace: bool,
    /// CC.EN is 1 and CSTS.RDY is 1 when the driver comes.
    pub initially_enabled: bool,
    /// RDY rises this long after CC.EN = 1, and falls this long after
    /// CC.EN = 0.
    pub rdy_delay_ns: u64,
    pub clear_delay_ns: u64,
    pub never_ready: bool,
    pub never_clear: bool,
    /// Admin commands complete this long after the doorbell; or never.
    pub admin_delay_ns: u64,
    pub admin_dead: bool,
    /// I/O commands complete this long after the doorbell.
    pub io_delay_ns: u64,
    /// SHST reaches 2 this long after CC.SHN = 1; or never.
    pub shutdown_delay_ns: u64,
    pub shutdown_never: bool,
    /// Every admin command with this opcode answers with this (SCT, SC).
    pub admin_error: Option<(u8, u8, u8)>,
    /// Every I/O command with this opcode answers with this (SCT, SC).
    pub io_error: Option<(u8, u8, u8)>,
}

impl Default for Scenario {
    fn default() -> Scenario {
        Scenario {
            mqes: 1023,
            to: 2,
            dstrd: 0,
            mpsmin: 0,
            css: 1,
            mdts: 0,
            vwc: false,
            blocks: 8192,
            lba_shift: 9,
            metadata: false,
            odd_shift: None,
            no_namespace: false,
            initially_enabled: false,
            rdy_delay_ns: 0,
            clear_delay_ns: 0,
            never_ready: false,
            never_clear: false,
            admin_delay_ns: 0,
            admin_dead: false,
            io_delay_ns: 0,
            shutdown_delay_ns: 0,
            shutdown_never: false,
            admin_error: None,
            io_error: None,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Queue {
    sq_base: u64,
    sq_depth: u16,
    sq_made: bool,
    sq_head: u16,
    sq_tail: u16,
    cq_base: u64,
    cq_depth: u16,
    cq_made: bool,
    cq_tail: u16,
    cq_head: u16,
    phase: bool,
    ien: bool,
    iv: u16,
}

enum Effect {
    None,
    Read { lba: u64, segs: Vec<(u64, usize)> },
    Write { lba: u64, segs: Vec<(u64, usize)> },
    Flush,
}

struct Pend {
    due: u64,
    qid: u16,
    cid: u16,
    sqhd: u16,
    status: (u8, u8),
    result: u32,
    effect: Effect,
    write: bool,
}

pub struct Inner {
    pub scenario: Scenario,
    regions: Vec<Region>,
    now: u64,
    cc: u32,
    rdy: bool,
    rdy_at: Option<u64>,
    clear_at: Option<u64>,
    shst: u32,
    shst_at: Option<u64>,
    cfs: bool,
    gone: bool,
    aqa: u32,
    asq: u64,
    acq: u64,
    q: [Queue; 2],
    pending: Vec<Pend>,
    media: Vec<u8>,
    cache: BTreeMap<u64, Vec<u8>>,
    delays: VecDeque<u64>,
    barrier: bool,
    /// What the model saw that a healthy driver never does.
    pub violations: Vec<String>,
    pub log: Vec<String>,
    /// The commands in the order they were taken: (queue id, opcode).
    pub commands: Vec<(u16, u8)>,
    /// The register writes in order: (offset, value).
    pub reg_log: Vec<(u32, u32)>,
    /// The register accesses (reads and writes) so far.
    pub reg_accesses: u64,
    /// The times CC.EN fell.
    pub controller_resets: u32,
    pub flush_commands: u32,
    /// The queues the driver created: (queue id, depth, interrupt on, vector).
    pub created: Vec<(u16, u16, bool, u16)>,
    /// The interrupts the controller would have raised (a CQE of a queue with
    /// IEN set): (queue id, vector).
    pub interrupts: Vec<(u16, u16)>,
}

/// The model, shared by the test and the platform the driver holds.
#[derive(Clone)]
pub struct Model(pub Rc<RefCell<Inner>>);

impl Model {
    /// A model whose memory is `mem` (the queues) and `cells`.
    pub fn new(mem: Region, cells: Region, scenario: Scenario) -> Model {
        let bytes = (scenario.blocks as usize) << scenario.lba_shift;
        let enabled = scenario.initially_enabled;
        Model(Rc::new(RefCell::new(Inner {
            regions: std::vec![mem, cells],
            now: 1_000 * MS,
            cc: if enabled { regs::CC_EN } else { 0 },
            rdy: enabled,
            rdy_at: None,
            clear_at: None,
            shst: 0,
            shst_at: None,
            cfs: false,
            gone: false,
            aqa: 0,
            asq: 0,
            acq: 0,
            q: [Queue::default(); 2],
            pending: Vec::new(),
            media: std::vec![0u8; bytes],
            cache: BTreeMap::new(),
            delays: VecDeque::new(),
            barrier: false,
            violations: Vec::new(),
            log: Vec::new(),
            commands: Vec::new(),
            reg_log: Vec::new(),
            reg_accesses: 0,
            controller_resets: 0,
            flush_commands: 0,
            created: Vec::new(),
            interrupts: Vec::new(),
            scenario,
        })))
    }

    pub fn platform(&self) -> Model {
        self.clone()
    }

    pub fn now(&self) -> u64 {
        self.0.borrow().now
    }

    /// Moves the clock by `ns`, in steps of a millisecond at most so that the
    /// completions come in their order.
    pub fn advance(&self, ns: u64) {
        let mut left = ns;
        while left > 0 {
            let step = left.min(MS);
            {
                let mut m = self.0.borrow_mut();
                m.now += step;
                m.tick();
            }
            left -= step;
        }
    }

    pub fn set<R>(&self, f: impl FnOnce(&mut Scenario) -> R) -> R {
        f(&mut self.0.borrow_mut().scenario)
    }

    /// The delays of the next I/O commands, one each, in the order they are
    /// taken (then `io_delay_ns` again).
    pub fn push_delays(&self, d: &[u64]) {
        self.0.borrow_mut().delays.extend(d.iter().copied());
    }

    pub fn violations(&self) -> Vec<String> {
        self.0.borrow().violations.clone()
    }

    pub fn log_lines(&self) -> Vec<String> {
        self.0.borrow().log.clone()
    }

    pub fn commands(&self) -> Vec<(u16, u8)> {
        self.0.borrow().commands.clone()
    }

    pub fn count_commands(&self, qid: u16, opcode: u8) -> usize {
        self.0
            .borrow()
            .commands
            .iter()
            .filter(|c| **c == (qid, opcode))
            .count()
    }

    pub fn reg_log(&self) -> Vec<(u32, u32)> {
        self.0.borrow().reg_log.clone()
    }

    pub fn reg_accesses(&self) -> u64 {
        self.0.borrow().reg_accesses
    }

    pub fn controller_resets(&self) -> u32 {
        self.0.borrow().controller_resets
    }

    pub fn flush_commands(&self) -> u32 {
        self.0.borrow().flush_commands
    }

    pub fn created(&self) -> Vec<(u16, u16, bool, u16)> {
        self.0.borrow().created.clone()
    }

    pub fn interrupts(&self) -> Vec<(u16, u16)> {
        self.0.borrow().interrupts.clone()
    }

    /// Sets CSTS.CFS (cleared by the next controller reset).
    pub fn inject_fatal(&self) {
        self.0.borrow_mut().cfs = true;
    }

    /// The function goes away (every register reads all ones) or comes back.
    pub fn set_gone(&self, gone: bool) {
        self.0.borrow_mut().gone = gone;
    }

    /// The bytes of the blocks `lba..lba + blocks` as a reader of the media
    /// (not of the cache) sees them: what survives a power loss.
    pub fn media(&self, lba: u64, blocks: u64) -> Vec<u8> {
        let m = self.0.borrow();
        let bs = 1usize << m.scenario.lba_shift;
        m.media[lba as usize * bs..(lba + blocks) as usize * bs].to_vec()
    }

    /// The bytes as the host reads them back (cache first).
    pub fn view(&self, lba: u64, blocks: u64) -> Vec<u8> {
        let m = self.0.borrow();
        (lba..lba + blocks).flat_map(|l| m.block(l)).collect()
    }

    /// Writes straight to the media.
    pub fn fill_media(&self, lba: u64, data: &[u8]) {
        let mut m = self.0.borrow_mut();
        let bs = 1usize << m.scenario.lba_shift;
        let at = lba as usize * bs;
        m.media[at..at + data.len()].copy_from_slice(data);
    }

    /// The power goes: what was only in the volatile cache is lost.
    pub fn power_loss(&self) {
        self.0.borrow_mut().cache.clear();
    }

    pub fn cache_blocks(&self) -> usize {
        self.0.borrow().cache.len()
    }
}

impl Inner {
    fn violation(&mut self, text: &str) {
        self.violations.push(text.to_string());
    }

    fn bs(&self) -> usize {
        1 << self.scenario.lba_shift
    }

    fn va(&self, pa: u64, len: usize) -> Option<usize> {
        self.regions
            .iter()
            .find(|r| pa >= r.pa && pa + len as u64 <= r.pa + r.len as u64)
            .map(|r| r.va + (pa - r.pa) as usize)
    }

    fn mem_get(&mut self, pa: u64, len: usize) -> Option<Vec<u8>> {
        let Some(va) = self.va(pa, len) else {
            self.violation(&std::format!("DMA read outside the regions at {pa:#x}"));
            return None;
        };
        // SAFETY: `va` lies in a region of the driver, which stays valid.
        Some(
            (0..len)
                .map(|i| unsafe { core::ptr::read_volatile((va + i) as *const u8) })
                .collect(),
        )
    }

    fn mem_put(&mut self, pa: u64, bytes: &[u8]) -> bool {
        let Some(va) = self.va(pa, bytes.len()) else {
            self.violation(&std::format!("DMA write outside the regions at {pa:#x}"));
            return false;
        };
        for (i, b) in bytes.iter().enumerate() {
            // SAFETY: as for `mem_get`.
            unsafe { core::ptr::write_volatile((va + i) as *mut u8, *b) }
        }
        true
    }

    fn word(&mut self, pa: u64) -> u32 {
        self.mem_get(pa, 4)
            .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn block(&self, lba: u64) -> Vec<u8> {
        let bs = self.bs();
        self.cache
            .get(&lba)
            .cloned()
            .unwrap_or_else(|| self.media[lba as usize * bs..(lba as usize + 1) * bs].to_vec())
    }

    fn store(&mut self, lba: u64, data: &[u8]) {
        let bs = self.bs();
        for (i, chunk) in data.chunks(bs).enumerate() {
            let l = lba + i as u64;
            if self.scenario.vwc {
                self.cache.insert(l, chunk.to_vec());
            } else {
                let at = l as usize * bs;
                self.media[at..at + bs].copy_from_slice(chunk);
            }
        }
    }

    // ----- time -----

    fn tick(&mut self) {
        if self.rdy_at.is_some_and(|t| self.now >= t) {
            self.rdy_at = None;
            self.rdy = true;
        }
        if self.clear_at.is_some_and(|t| self.now >= t) {
            self.clear_at = None;
            self.rdy = false;
        }
        if self.shst_at.is_some_and(|t| self.now >= t) {
            self.shst_at = None;
            self.shst = regs::CSTS_SHST_COMPLETE;
        }
        // The due completions, earliest first, the older first among equals.
        loop {
            let pick = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, p)| p.due <= self.now)
                .min_by_key(|(_, p)| p.due)
                .map(|(i, _)| i);
            let Some(i) = pick else { break };
            if !self.post(i) {
                break;
            }
        }
    }

    /// Runs the effect of the pending command `i` and posts its completion.
    /// False when the completion queue is full (the entry waits).
    fn post(&mut self, i: usize) -> bool {
        let qid = self.pending[i].qid as usize;
        let q = self.q[qid];
        if !q.cq_made || (q.cq_tail + 1) % q.cq_depth == q.cq_head {
            return false;
        }
        let p = self.pending.remove(i);
        let mut status = p.status;
        if status == (0, 0) {
            match &p.effect {
                Effect::None => {}
                Effect::Flush => {
                    let cached: Vec<(u64, Vec<u8>)> =
                        core::mem::take(&mut self.cache).into_iter().collect();
                    let bs = self.bs();
                    for (l, d) in cached {
                        let at = l as usize * bs;
                        self.media[at..at + bs].copy_from_slice(&d);
                    }
                }
                Effect::Write { lba, segs } => {
                    let mut data = Vec::new();
                    for (pa, len) in segs {
                        match self.mem_get(*pa, *len) {
                            Some(b) => data.extend(b),
                            None => status = (0, cmd::SC_INVALID_FIELD),
                        }
                    }
                    if status == (0, 0) {
                        self.store(*lba, &data);
                    }
                }
                Effect::Read { lba, segs } => {
                    let total: usize = segs.iter().map(|s| s.1).sum();
                    let blocks = total / self.bs();
                    let data: Vec<u8> = (*lba..*lba + blocks as u64)
                        .flat_map(|l| self.block(l))
                        .collect();
                    let mut at = 0;
                    for (pa, len) in segs {
                        if !self.mem_put(*pa, &data[at..at + len]) {
                            status = (0, cmd::SC_INVALID_FIELD);
                        }
                        at += len;
                    }
                }
            }
        }
        let q = &mut self.q[qid];
        let at = q.cq_base + q.cq_tail as u64 * cmd::CQE_BYTES as u64;
        let dw2 = p.sqhd as u32 | (qid as u32) << 16;
        let dw3 = p.cid as u32
            | (q.phase as u32) << 16
            | (status.1 as u32) << 17
            | (status.0 as u32) << 25;
        let (ien, iv) = (q.ien, q.iv);
        q.cq_tail += 1;
        if q.cq_tail == q.cq_depth {
            q.cq_tail = 0;
            q.phase = !q.phase;
        }
        // The phase dword goes last.
        self.mem_put(at, &p.result.to_le_bytes());
        self.mem_put(at + 4, &0u32.to_le_bytes());
        self.mem_put(at + 8, &dw2.to_le_bytes());
        self.mem_put(at + 12, &dw3.to_le_bytes());
        if ien || qid == 0 {
            self.interrupts.push((qid as u16, iv));
        }
        true
    }

    // ----- registers -----

    fn read_reg(&mut self, offset: u32) -> u32 {
        if self.gone {
            return regs::GONE;
        }
        let s = &self.scenario;
        match offset {
            regs::CAP_LO => s.mqes as u32 | 1 << 16 | (s.to as u32) << 24,
            regs::CAP_HI => {
                s.dstrd as u32 | (s.css as u32) << 5 | (s.mpsmin as u32) << 16 | 4 << 20
            }
            regs::VS => 0x0002_0000,
            regs::CC => self.cc,
            regs::CSTS => {
                self.rdy as u32 | (self.cfs as u32) << 1 | self.shst << regs::CSTS_SHST_SHIFT
            }
            _ => {
                self.violation(&std::format!("read of {offset:#x}"));
                0
            }
        }
    }

    fn write_reg(&mut self, offset: u32, value: u32) {
        let barrier = core::mem::take(&mut self.barrier);
        self.reg_log.push((offset, value));
        if self.gone {
            return;
        }
        if offset >= regs::DB_BASE {
            return self.doorbell(offset, value, barrier);
        }
        let enabled = self.cc & regs::CC_EN != 0;
        match offset {
            regs::CC => self.write_cc(value),
            regs::AQA | regs::ASQ_LO | regs::ASQ_HI | regs::ACQ_LO | regs::ACQ_HI => {
                if enabled || self.rdy {
                    self.violation(
                        "an admin queue register written while the controller is enabled",
                    );
                }
                match offset {
                    regs::AQA => self.aqa = value,
                    regs::ASQ_LO => self.asq = self.asq & !0xffff_ffff | value as u64,
                    regs::ASQ_HI => self.asq = self.asq & 0xffff_ffff | (value as u64) << 32,
                    regs::ACQ_LO => self.acq = self.acq & !0xffff_ffff | value as u64,
                    _ => self.acq = self.acq & 0xffff_ffff | (value as u64) << 32,
                }
            }
            _ => self.violation(&std::format!("write of {offset:#x}")),
        }
    }

    fn write_cc(&mut self, v: u32) {
        let (old_en, new_en) = (self.cc & regs::CC_EN != 0, v & regs::CC_EN != 0);
        if new_en && !old_en {
            if self.rdy || self.clear_at.is_some() {
                self.violation("enabled before CSTS.RDY was clear");
            }
            let (sqes, cqes) = (
                v >> regs::CC_IOSQES_SHIFT & 0xf,
                v >> regs::CC_IOCQES_SHIFT & 0xf,
            );
            if sqes != 6 || cqes != 4 || v >> regs::CC_MPS_SHIFT & 0xf != 0 || v >> 4 & 7 != 0 {
                self.violation(
                    "CC does not select the NVM command set, 4 KiB pages and the entry sizes",
                );
            }
            if self.asq == 0 || self.acq == 0 || self.aqa == 0 {
                self.violation("enabled without the admin queues");
            }
            self.q = [Queue::default(); 2];
            self.q[0] = Queue {
                sq_base: self.asq,
                sq_depth: (self.aqa & 0xfff) as u16 + 1,
                sq_made: true,
                cq_base: self.acq,
                cq_depth: (self.aqa >> 16 & 0xfff) as u16 + 1,
                cq_made: true,
                phase: true,
                ..Queue::default()
            };
            self.shst = 0;
            if !self.scenario.never_ready {
                if self.scenario.rdy_delay_ns == 0 {
                    self.rdy = true;
                } else {
                    self.rdy_at = Some(self.now + self.scenario.rdy_delay_ns);
                }
            }
        } else if !new_en && old_en {
            self.controller_resets += 1;
            self.q = [Queue::default(); 2];
            self.pending.clear();
            self.cfs = false;
            self.shst = 0;
            self.rdy_at = None;
            if !self.scenario.never_clear {
                if self.scenario.clear_delay_ns == 0 {
                    self.rdy = false;
                } else {
                    self.clear_at = Some(self.now + self.scenario.clear_delay_ns);
                }
            }
        }
        let shn = v & regs::CC_SHN_MASK;
        if shn == regs::CC_SHN_NORMAL
            && self.cc & regs::CC_SHN_MASK == 0
            && !self.scenario.shutdown_never
        {
            if self.scenario.shutdown_delay_ns == 0 {
                self.shst = regs::CSTS_SHST_COMPLETE;
            } else {
                self.shst_at = Some(self.now + self.scenario.shutdown_delay_ns);
            }
        }
        self.cc = v;
    }

    fn doorbell(&mut self, offset: u32, value: u32, barrier: bool) {
        let stride = 4u32 << self.scenario.dstrd;
        let rel = offset - regs::DB_BASE;
        if !rel.is_multiple_of(stride) {
            self.violation(&std::format!(
                "doorbell at {offset:#x} is not on the stride of {stride}"
            ));
            return;
        }
        let (qid, is_cq) = ((rel / stride / 2) as usize, (rel / stride) % 2 == 1);
        if qid > 1 || (is_cq && !self.q[qid].cq_made) || (!is_cq && !self.q[qid].sq_made) {
            self.violation(&std::format!(
                "doorbell of a queue that does not exist ({offset:#x})"
            ));
            return;
        }
        if is_cq {
            if value >= self.q[qid].cq_depth as u32 {
                self.violation("a completion head beyond the queue");
                return;
            }
            self.q[qid].cq_head = value as u16;
            self.tick();
            return;
        }
        if !barrier {
            self.violation("a submission doorbell without the barrier before it");
        }
        if value >= self.q[qid].sq_depth as u32 {
            self.violation("a submission tail beyond the queue");
            return;
        }
        self.q[qid].sq_tail = value as u16;
        while self.q[qid].sq_head != self.q[qid].sq_tail {
            let q = self.q[qid];
            let at = q.sq_base + q.sq_head as u64 * cmd::SQE_BYTES as u64;
            let mut e = [0u32; 16];
            for (i, w) in e.iter_mut().enumerate() {
                *w = self.word(at + i as u64 * 4);
            }
            self.q[qid].sq_head = (q.sq_head + 1) % q.sq_depth;
            self.execute(qid as u16, &e);
        }
    }

    // ----- commands -----

    fn queue_command(
        &mut self,
        qid: u16,
        e: &cmd::Sqe,
        status: (u8, u8),
        result: u32,
        effect: Effect,
        delay: u64,
    ) {
        let write = matches!(effect, Effect::Write { .. });
        let sqhd = self.q[qid as usize].sq_head;
        self.pending.push(Pend {
            due: self.now + delay,
            qid,
            cid: (e[0] >> 16) as u16,
            sqhd,
            status,
            result,
            effect,
            write,
        });
    }

    fn execute(&mut self, qid: u16, e: &cmd::Sqe) {
        let opcode = (e[0] & 0xff) as u8;
        self.commands.push((qid, opcode));
        if qid == 0 {
            if self.scenario.admin_dead {
                return;
            }
            let (status, result) = self.admin(opcode, e);
            let delay = self.scenario.admin_delay_ns;
            self.queue_command(0, e, status, result, Effect::None, delay);
        } else {
            let delay = self.scenario.io_delay_ns;
            let delay = self.delays.pop_front().unwrap_or(delay);
            let (status, effect) = self.io(opcode, e);
            self.queue_command(qid, e, status, 0, effect, delay);
        }
    }

    fn admin(&mut self, opcode: u8, e: &cmd::Sqe) -> ((u8, u8), u32) {
        if let Some((o, sct, sc)) = self.scenario.admin_error
            && o == opcode
        {
            return ((sct, sc), 0);
        }
        let prp1 = e[6] as u64 | (e[7] as u64) << 32;
        match opcode {
            cmd::ADMIN_SET_FEATURES => ((0, 0), 0),
            cmd::ADMIN_IDENTIFY => {
                let data = if e[10] & 0xff == cmd::CNS_CONTROLLER {
                    self.identify_controller()
                } else if e[1] == 1 && !self.scenario.no_namespace {
                    self.identify_namespace()
                } else {
                    std::vec![0u8; 4096]
                };
                if !prp1.is_multiple_of(4096) {
                    self.violation("Identify into an unaligned buffer");
                }
                if self.mem_put(prp1, &data) {
                    ((0, 0), 0)
                } else {
                    ((0, 4), 0)
                }
            }
            cmd::ADMIN_CREATE_CQ => {
                let (qid, size) = ((e[10] & 0xffff) as u16, (e[10] >> 16) as u16 + 1);
                let (pc, ien, iv) = (e[11] & 1 != 0, e[11] & 2 != 0, (e[11] >> 16) as u16);
                if qid != 1
                    || size > self.scenario.mqes + 1
                    || !pc
                    || !prp1.is_multiple_of(4096)
                    || self.q[1].cq_made
                {
                    return ((1, 0x02), 0);
                }
                self.q[1].cq_base = prp1;
                self.q[1].cq_depth = size;
                self.q[1].cq_made = true;
                self.q[1].phase = true;
                self.q[1].ien = ien;
                self.q[1].iv = iv;
                self.created.push((1, size, ien, iv));
                ((0, 0), 0)
            }
            cmd::ADMIN_CREATE_SQ => {
                let (qid, size) = ((e[10] & 0xffff) as u16, (e[10] >> 16) as u16 + 1);
                let (pc, cqid) = (e[11] & 1 != 0, (e[11] >> 16) as u16);
                if cqid != 1 || !self.q[1].cq_made {
                    return ((1, 0x00), 0);
                }
                if qid != 1
                    || size > self.scenario.mqes + 1
                    || !pc
                    || !prp1.is_multiple_of(4096)
                    || self.q[1].sq_made
                {
                    return ((1, 0x02), 0);
                }
                self.q[1].sq_base = prp1;
                self.q[1].sq_depth = size;
                self.q[1].sq_made = true;
                ((0, 0), 0)
            }
            _ => ((0, cmd::SC_INVALID_OPCODE), 0),
        }
    }

    fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn identify_controller(&self) -> Vec<u8> {
        let mut b = std::vec![0u8; 4096];
        let pad = |s: &str, n: usize| {
            let mut v = std::vec![b' '; n];
            v[..s.len()].copy_from_slice(s.as_bytes());
            v
        };
        Self::put(&mut b, cmd::IDC_SN, &pad("MODEL-SERIAL-0001", 20));
        Self::put(&mut b, cmd::IDC_MN, &pad("stafeto model controller", 40));
        Self::put(&mut b, cmd::IDC_FR, &pad("1.0", 8));
        b[cmd::IDC_MDTS] = self.scenario.mdts;
        Self::put(&mut b, cmd::IDC_VER, &0x0002_0000u32.to_le_bytes());
        Self::put(&mut b, cmd::IDC_NN, &1u32.to_le_bytes());
        b[cmd::IDC_VWC] = self.scenario.vwc as u8;
        b
    }

    fn identify_namespace(&self) -> Vec<u8> {
        let s = &self.scenario;
        let mut b = std::vec![0u8; 4096];
        Self::put(&mut b, cmd::IDN_NSZE, &s.blocks.to_le_bytes());
        b[cmd::IDN_NLBAF] = 3;
        // Formats: 0 is 512 bytes, 1 is 4096, 2 has 8 bytes of metadata, 3 is odd.
        let lbaf = |ms: u32, shift: u8| ms | (shift as u32) << 16;
        Self::put(&mut b, cmd::IDN_LBAF, &lbaf(0, 9).to_le_bytes());
        Self::put(&mut b, cmd::IDN_LBAF + 4, &lbaf(0, 12).to_le_bytes());
        Self::put(&mut b, cmd::IDN_LBAF + 8, &lbaf(8, 9).to_le_bytes());
        Self::put(
            &mut b,
            cmd::IDN_LBAF + 12,
            &lbaf(0, s.odd_shift.unwrap_or(10)).to_le_bytes(),
        );
        b[cmd::IDN_FLBAS] = if s.metadata {
            2
        } else if s.odd_shift.is_some() {
            3
        } else if s.lba_shift == 12 {
            1
        } else {
            0
        };
        b
    }

    /// The pages of a transfer of `bytes` bytes as the specification says
    /// PRP1 and PRP2 give them.
    fn segments(&mut self, prp1: u64, prp2: u64, bytes: usize) -> Option<Vec<(u64, usize)>> {
        let first = bytes.min(cmd::PAGE - (prp1 % cmd::PAGE as u64) as usize);
        let mut segs = std::vec![(prp1, first)];
        let rest = bytes - first;
        if rest == 0 {
            if prp2 != 0 {
                self.violation("PRP2 set for a transfer inside one page");
            }
            return Some(segs);
        }
        let pages = rest.div_ceil(cmd::PAGE);
        if pages == 1 {
            if !prp2.is_multiple_of(cmd::PAGE as u64) {
                self.violation("PRP2 of a second page is not page-aligned");
                return None;
            }
            segs.push((prp2, rest));
            return Some(segs);
        }
        if !prp2.is_multiple_of(8) || (prp2 % cmd::PAGE as u64) as usize + pages * 8 > cmd::PAGE {
            self.violation("a PRP list pointer that is unaligned or needs a chain");
            return None;
        }
        let mut left = rest;
        for j in 0..pages {
            let lo = self.word(prp2 + j as u64 * 8) as u64;
            let hi = self.word(prp2 + j as u64 * 8 + 4) as u64;
            let entry = lo | hi << 32;
            if entry == 0 || !entry.is_multiple_of(cmd::PAGE as u64) {
                self.violation("a PRP list entry that is not the address of a page");
                return None;
            }
            let n = left.min(cmd::PAGE);
            segs.push((entry, n));
            left -= n;
        }
        Some(segs)
    }

    fn io(&mut self, opcode: u8, e: &cmd::Sqe) -> ((u8, u8), Effect) {
        if let Some((o, sct, sc)) = self.scenario.io_error
            && o == opcode
        {
            return ((sct, sc), Effect::None);
        }
        if e[1] != 1 {
            return ((0, 0x0b), Effect::None);
        }
        match opcode {
            cmd::NVM_FLUSH => {
                self.flush_commands += 1;
                if self.pending.iter().any(|p| p.write) {
                    self.violation("Flush taken while a write is in work");
                }
                ((0, 0), Effect::Flush)
            }
            cmd::NVM_READ | cmd::NVM_WRITE => {
                let slba = e[10] as u64 | (e[11] as u64) << 32;
                let nlb = (e[12] & 0xffff) as u64 + 1;
                let bytes = nlb as usize * self.bs();
                if slba + nlb > self.scenario.blocks {
                    return ((0, cmd::SC_LBA_RANGE), Effect::None);
                }
                let max = if self.scenario.mdts == 0 {
                    usize::MAX
                } else {
                    cmd::PAGE << self.scenario.mdts
                };
                if bytes > max {
                    return ((0, cmd::SC_INVALID_FIELD), Effect::None);
                }
                let prp1 = e[6] as u64 | (e[7] as u64) << 32;
                let prp2 = e[8] as u64 | (e[9] as u64) << 32;
                let Some(segs) = self.segments(prp1, prp2, bytes) else {
                    return ((0, 4), Effect::None);
                };
                let effect = if opcode == cmd::NVM_READ {
                    Effect::Read { lba: slba, segs }
                } else {
                    Effect::Write { lba: slba, segs }
                };
                ((0, 0), effect)
            }
            _ => ((0, cmd::SC_INVALID_OPCODE), Effect::None),
        }
    }
}

impl Platform for Model {
    fn read32(&self, offset: u32) -> u32 {
        let mut m = self.0.borrow_mut();
        m.tick();
        m.reg_accesses += 1;
        m.read_reg(offset)
    }

    fn write32(&self, offset: u32, value: u32) {
        let mut m = self.0.borrow_mut();
        m.tick();
        m.reg_accesses += 1;
        m.write_reg(offset, value);
        m.tick();
    }

    fn now_ns(&self) -> u64 {
        self.0.borrow().now
    }

    fn wmb(&self) {
        self.0.borrow_mut().barrier = true;
    }

    fn log(&self, line: fmt::Arguments<'_>) {
        self.0.borrow_mut().log.push(line.to_string());
    }
}

/// A zeroed region of `len` bytes on the host's heap, page-aligned, whose
/// "physical" address is `pa`, for the model and the driver to share.
pub fn region(len: usize, pa: u64) -> Region {
    let layout = std::alloc::Layout::from_size_align(len, 4096).unwrap();
    // SAFETY: a nonzero layout; the block is leaked on purpose and lives on.
    let va = unsafe { std::alloc::alloc_zeroed(layout) } as usize;
    Region { va, pa, len }
}
