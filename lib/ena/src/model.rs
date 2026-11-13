// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A model of the device on the host, for the tests of the driver: the
//! register file of BAR 0, the admin queue with its phases, the answers to
//! GET_FEATURE, SET_FEATURE and GET_STATS, the event queue with keep-alive
//! once a second of the model's clock, the reset and the read of a register
//! through memory. It shares the driver's memory (`Region`) the way a device
//! does, through the physical addresses the driver wrote, and it notes each
//! thing a real device would refuse or not survive (`violations`).
//!
//! The model runs on the clock of the test (`advance`), which the driver reads
//! through `Platform::now_ns`. It checks the logic of the driver (phases,
//! wraps, order of the reset, deadlines). It cannot catch an error the driver
//! and the model make alike, nor what Nitro does (which features it insists
//! on, the time of a command): the host tests are the first line and the
//! device is the second.

extern crate std;

use crate::admin as adm;
use crate::device::{Platform, Region};
use crate::regs;
use core::fmt;
use std::cell::RefCell;
use std::rc::Rc;
use std::string::{String, ToString};
use std::vec::Vec;

const MS: u64 = 1_000_000;

/// What the model does that a healthy device does not.
#[derive(Clone, Debug)]
pub struct Scenario {
    /// Every admin command with this opcode answers with this status.
    pub error_status: Option<(u8, u8)>,
    /// Admin answers come this long after the doorbell.
    pub answer_delay_ns: u64,
    /// No keep-alive events.
    pub no_keep_alive: bool,
    /// The reset never finishes.
    pub reset_never_ends: bool,
    /// A read through memory is never answered.
    pub readless_dead: bool,
    /// The width of the DMA addresses the device can use.
    pub dma_width: u32,
    /// `DEV_STS.FATAL_ERROR` rises at this time.
    pub fatal_at_ns: Option<u64>,
    /// The device posts a fatal-error event at this time.
    pub fatal_event_at_ns: Option<u64>,
    /// How long a reset takes.
    pub reset_ns: u64,
    /// The admin completion carries another command's id.
    pub wrong_command_id: bool,
    /// The next reset ends the delay of the answers.
    pub delay_ends_at_reset: bool,
    /// The device posts a link-change event (up) once the groups are set.
    pub link_event: bool,
    /// The device says it needs no hint-less commands: LLQ is listed.
    pub llq: bool,
}

impl Default for Scenario {
    fn default() -> Scenario {
        Scenario {
            error_status: None,
            answer_delay_ns: 0,
            no_keep_alive: false,
            reset_never_ends: false,
            readless_dead: false,
            dma_width: 48,
            fatal_at_ns: None,
            fatal_event_at_ns: None,
            reset_ns: 5 * MS,
            wrong_command_id: false,
            delay_ends_at_reset: false,
            link_event: true,
            llq: false,
        }
    }
}

struct Answer {
    due_ns: u64,
    entry: [u8; adm::ENTRY],
}

pub struct Inner {
    pub scenario: Scenario,
    region: Region,
    now: u64,
    // The register file.
    aq_base: u64,
    acq_base: u64,
    aenq_base: u64,
    aq_caps: u32,
    acq_caps: u32,
    aenq_caps: u32,
    aenq_head_db: u32,
    resp_lo: u32,
    resp_hi: u32,
    dev_ctl: u32,
    intr_mask: u32,
    reset_until: Option<u64>,
    // The admin queue.
    aq_head: u16,
    aq_phase: u8,
    acq_tail: u16,
    acq_phase: u8,
    answers: Vec<Answer>,
    // The event queue.
    aenq_tail: u16,
    aenq_phase: u8,
    next_keep_ns: u64,
    enabled_groups: u32,
    keep_sent: u64,
    // What the driver set.
    pub mtu: u32,
    // What the model saw.
    pub violations: Vec<String>,
    pub log: Vec<String>,
    pub commands: Vec<u8>,
    pub resets: Vec<u32>,
    pub read_requests: u32,
    pub reset_sequence: Vec<&'static str>,
    revision: u8,
}

/// The model, shared by the test and the platform the driver holds.
#[derive(Clone)]
pub struct Model(pub Rc<RefCell<Inner>>);

impl Model {
    /// A model whose driver's memory is `region`.
    pub fn new(region: Region, revision: u8, scenario: Scenario) -> Model {
        Model(Rc::new(RefCell::new(Inner {
            scenario,
            region,
            now: 1_000 * MS,
            aq_base: 0,
            acq_base: 0,
            aenq_base: 0,
            aq_caps: 0,
            acq_caps: 0,
            aenq_caps: 0,
            aenq_head_db: 0,
            resp_lo: 0,
            resp_hi: 0,
            dev_ctl: 0,
            intr_mask: 0,
            reset_until: None,
            aq_head: 0,
            aq_phase: 1,
            acq_tail: 0,
            acq_phase: 1,
            answers: Vec::new(),
            aenq_tail: 0,
            aenq_phase: 1,
            next_keep_ns: 0,
            enabled_groups: 0,
            keep_sent: 0,
            mtu: 0,
            violations: Vec::new(),
            log: Vec::new(),
            commands: Vec::new(),
            resets: Vec::new(),
            read_requests: 0,
            reset_sequence: Vec::new(),
            revision,
        })))
    }

    /// The platform for the driver: the same model.
    pub fn platform(&self) -> Model {
        self.clone()
    }

    pub fn now(&self) -> u64 {
        self.0.borrow().now
    }

    /// Moves the clock by `ns`, in steps of a millisecond so that the events
    /// and answers come in their order.
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

    pub fn violations(&self) -> Vec<String> {
        self.0.borrow().violations.clone()
    }

    pub fn log_lines(&self) -> Vec<String> {
        self.0.borrow().log.clone()
    }

    pub fn commands(&self) -> Vec<u8> {
        self.0.borrow().commands.clone()
    }

    pub fn resets(&self) -> Vec<u32> {
        self.0.borrow().resets.clone()
    }

    pub fn set<R>(&self, f: impl FnOnce(&mut Scenario) -> R) -> R {
        f(&mut self.0.borrow_mut().scenario)
    }

    pub fn keep_alives_sent(&self) -> u64 {
        self.0.borrow().keep_sent
    }

    pub fn mtu(&self) -> u32 {
        self.0.borrow().mtu
    }
}

impl Platform for Model {
    fn read32(&self, offset: u32) -> u32 {
        let mut m = self.0.borrow_mut();
        m.tick();
        m.read_reg(offset)
    }

    fn write32(&self, offset: u32, value: u32) {
        let mut m = self.0.borrow_mut();
        m.tick();
        m.write_reg(offset, value);
    }

    fn now_ns(&self) -> u64 {
        self.0.borrow().now
    }

    fn log(&self, line: fmt::Arguments<'_>) {
        self.0.borrow_mut().log.push(line.to_string());
    }
}

impl Inner {
    fn va(&self, pa: u64) -> usize {
        let top = self.region.pa + self.region.len as u64;
        if pa < self.region.pa || pa >= top {
            self.violations_push("DMA outside the driver's region");
            return self.region.va;
        }
        self.region.va + (pa - self.region.pa) as usize
    }

    fn violations_push(&self, what: &str) {
        // `violations` is behind `&self` in the helpers that only look: use a
        // raw cell through the pointer; the model is single-threaded.
        let this = self as *const Inner as *mut Inner;
        // SAFETY: the model is used from one thread and no reference into
        // `violations` is alive across this call.
        unsafe { (*this).violations.push(what.to_string()) }
    }

    fn mem_get(&self, va: usize, len: usize) -> Vec<u8> {
        (0..len)
            // SAFETY: `va` lies in the driver's region, which stays valid (the
            // promise of `Ena::open`).
            .map(|i| unsafe { core::ptr::read_volatile((va + i) as *const u8) })
            .collect()
    }

    fn mem_put(&self, va: usize, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            // SAFETY: as for `mem_get`.
            unsafe { core::ptr::write_volatile((va + i) as *mut u8, *b) }
        }
    }

    fn check_pa(&self, pa: u64, what: &str) {
        let width = self.scenario.dma_width;
        if width < 64 && (pa + 63) >> width != 0 {
            self.violations_push(&std::format!("{what} above the DMA width of {width} bits"));
        }
    }

    fn in_reset(&self) -> bool {
        self.reset_until.is_some()
    }

    fn status(&self) -> u32 {
        let mut sts = regs::DEV_STS_READY_MASK;
        if self.in_reset() {
            sts |= regs::DEV_STS_RESET_IN_PROGRESS_MASK;
        }
        if self.scenario.fatal_at_ns.is_some_and(|t| self.now >= t) {
            sts |= regs::DEV_STS_FATAL_ERROR_MASK;
        }
        sts
    }

    fn read_reg(&mut self, offset: u32) -> u32 {
        match offset {
            regs::VERSION => 0x0000_0201,
            regs::CONTROLLER_VERSION => 0x0100_0001,
            regs::CAPS => {
                // Reset timeout 3 (300 ms), DMA width, admin command timeout 3 (300 ms).
                3 << regs::CAPS_RESET_TIMEOUT_SHIFT & regs::CAPS_RESET_TIMEOUT_MASK
                    | self.scenario.dma_width << regs::CAPS_DMA_ADDR_WIDTH_SHIFT
                    | 3 << regs::CAPS_ADMIN_CMD_TO_SHIFT
            }
            regs::DEV_STS => self.status(),
            regs::DEV_CTL => self.dev_ctl,
            _ => 0,
        }
    }

    fn write_reg(&mut self, offset: u32, value: u32) {
        let configuring = matches!(
            offset,
            regs::AQ_BASE_LO
                | regs::AQ_BASE_HI
                | regs::AQ_CAPS
                | regs::ACQ_BASE_LO
                | regs::ACQ_BASE_HI
                | regs::ACQ_CAPS
                | regs::AENQ_BASE_LO
                | regs::AENQ_BASE_HI
                | regs::AENQ_CAPS
                | regs::AENQ_HEAD_DB
                | regs::AQ_DB
        );
        if configuring && self.in_reset() {
            self.violations_push("a queue register written while the reset is in progress");
        }
        match offset {
            regs::DEV_CTL => {
                let was = self.dev_ctl;
                self.dev_ctl = value;
                if value & regs::DEV_CTL_DEV_RESET_MASK != 0 {
                    let reason = (value & regs::DEV_CTL_RESET_REASON_MASK)
                        >> regs::DEV_CTL_RESET_REASON_SHIFT
                        | (value & regs::DEV_CTL_RESET_REASON_EXT_MASK)
                            >> regs::DEV_CTL_RESET_REASON_EXT_SHIFT
                            << 4;
                    self.resets.push(reason);
                    self.reset_sequence.push("asserted");
                    self.start_reset();
                } else if was & regs::DEV_CTL_DEV_RESET_MASK != 0 {
                    self.reset_sequence.push("released");
                }
            }
            regs::AQ_BASE_LO => self.aq_base = self.aq_base & !0xFFFF_FFFF | u64::from(value),
            regs::AQ_BASE_HI => self.aq_base = self.aq_base & 0xFFFF_FFFF | u64::from(value) << 32,
            regs::ACQ_BASE_LO => self.acq_base = self.acq_base & !0xFFFF_FFFF | u64::from(value),
            regs::ACQ_BASE_HI => {
                self.acq_base = self.acq_base & 0xFFFF_FFFF | u64::from(value) << 32
            }
            regs::AENQ_BASE_LO => self.aenq_base = self.aenq_base & !0xFFFF_FFFF | u64::from(value),
            regs::AENQ_BASE_HI => {
                self.aenq_base = self.aenq_base & 0xFFFF_FFFF | u64::from(value) << 32
            }
            regs::AQ_CAPS => self.aq_caps = value,
            regs::ACQ_CAPS => self.acq_caps = value,
            regs::AENQ_CAPS => self.aenq_caps = value,
            regs::AENQ_HEAD_DB => self.aenq_head_db = value,
            regs::INTR_MASK => self.intr_mask = value,
            regs::MMIO_RESP_LO => self.resp_lo = value,
            regs::MMIO_RESP_HI => self.resp_hi = value,
            regs::MMIO_REG_READ => self.readless(value),
            regs::AQ_DB => self.doorbell(value as u16),
            _ => {}
        }
    }

    fn start_reset(&mut self) {
        if self.scenario.delay_ends_at_reset {
            self.scenario.answer_delay_ns = 0;
        }
        self.reset_until = Some(self.now + self.scenario.reset_ns);
        self.resp_lo = 0;
        self.resp_hi = 0;
        self.aq_base = 0;
        self.acq_base = 0;
        self.aenq_base = 0;
        self.aq_head = 0;
        self.aq_phase = 1;
        self.acq_tail = 0;
        self.acq_phase = 1;
        self.aenq_tail = 0;
        self.aenq_phase = 1;
        self.aenq_head_db = 0;
        self.enabled_groups = 0;
        self.answers.clear();
    }

    fn readless(&mut self, value: u32) {
        self.read_requests += 1;
        if self.scenario.readless_dead {
            return;
        }
        let offset =
            (value & regs::MMIO_REG_READ_REG_OFF_MASK) >> regs::MMIO_REG_READ_REG_OFF_SHIFT;
        let id = value & regs::MMIO_REG_READ_REQ_ID_MASK;
        let pa = u64::from(self.resp_hi) << 32 | u64::from(self.resp_lo);
        if pa == 0 {
            self.violations_push("a read through memory before the answer address was set");
            return;
        }
        let v = self.read_reg(offset);
        let mut resp = [0u8; adm::READLESS_LEN];
        resp[adm::READLESS_REQ_ID..][..2].copy_from_slice(&(id as u16).to_le_bytes());
        resp[adm::READLESS_REG_OFF..][..2].copy_from_slice(&(offset as u16).to_le_bytes());
        resp[adm::READLESS_REG_VAL..][..4].copy_from_slice(&v.to_le_bytes());
        let va = self.va(pa);
        self.mem_put(va, &resp);
    }

    fn doorbell(&mut self, tail: u16) {
        if self.aq_base == 0 {
            self.violations_push("the admin doorbell rang without a queue");
            return;
        }
        self.check_pa(self.aq_base, "the admin queue");
        self.check_pa(self.acq_base, "the admin completion queue");
        while self.aq_head != tail {
            let slot = usize::from(self.aq_head & (adm::ADMIN_DEPTH - 1));
            let va = self.va(self.aq_base) + slot * adm::ENTRY;
            let entry = self.mem_get(va, adm::ENTRY);
            if entry[adm::AQ_FLAGS] & adm::AQ_FLAG_PHASE != self.aq_phase {
                self.violations_push("an admin command with the wrong phase");
                return;
            }
            self.aq_head = self.aq_head.wrapping_add(1);
            if self.aq_head & (adm::ADMIN_DEPTH - 1) == 0 {
                self.aq_phase ^= 1;
            }
            let entry: [u8; adm::ENTRY] = entry.try_into().unwrap();
            let answer = self.execute(&entry);
            self.answers.push(Answer {
                due_ns: self.now + self.scenario.answer_delay_ns,
                entry: answer,
            });
        }
        self.deliver();
    }

    fn execute(&mut self, cmd: &[u8; adm::ENTRY]) -> [u8; adm::ENTRY] {
        let opcode = cmd[adm::AQ_OPCODE];
        self.commands.push(opcode);
        let id = u16::from_le_bytes([cmd[0], cmd[1]]) & adm::AQ_COMMAND_ID_MASK;
        let mut out = [0u8; adm::ENTRY];
        let shown = if self.scenario.wrong_command_id {
            id ^ 0x55
        } else {
            id
        };
        out[adm::ACQ_COMMAND..][..2].copy_from_slice(&shown.to_le_bytes());
        let mut status = adm::SUCCESS;
        if let Some((op, st)) = self.scenario.error_status
            && op == opcode
        {
            status = st;
        } else {
            match opcode {
                adm::GET_FEATURE => {
                    if cmd[adm::FEAT_ID] == adm::MAX_QUEUES_EXT && cmd[adm::FEAT_VERSION] != 1 {
                        self.violations_push("the extended queue limits asked in version 0");
                    }
                    status = self.get_feature(cmd[adm::FEAT_ID], &mut out)
                }
                adm::SET_FEATURE => status = self.set_feature(cmd),
                adm::GET_STATS => {
                    if cmd[adm::STATS_TYPE] == adm::STATS_TYPE_ENI {
                        for (i, n) in [11u64, 22, 33, 44, 55].iter().enumerate() {
                            out[adm::ACQ_DATA + 8 * i..][..8].copy_from_slice(&n.to_le_bytes());
                        }
                    }
                }
                _ => status = adm::UNSUPPORTED_OPCODE,
            }
        }
        out[adm::ACQ_STATUS] = status;
        out
    }

    fn get_feature(&mut self, id: u8, out: &mut [u8; adm::ENTRY]) -> u8 {
        let body = &mut out[adm::ACQ_DATA..];
        let put32 =
            |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        match id {
            adm::DEVICE_ATTRIBUTES => {
                let mut features = 0u32;
                for f in [
                    adm::DEVICE_ATTRIBUTES,
                    adm::MAX_QUEUES_EXT,
                    adm::HW_HINTS,
                    adm::STATELESS_OFFLOAD_CONFIG,
                    adm::MTU,
                    adm::AENQ_CONFIG,
                    adm::LINK_CONFIG,
                ] {
                    features |= 1 << f;
                }
                if self.scenario.llq {
                    features |= 1 << adm::LLQ;
                }
                put32(body, adm::ATTR_IMPL_ID, 3);
                put32(body, adm::ATTR_VERSION, 0x0001_0000);
                put32(body, adm::ATTR_SUPPORTED, features);
                put32(body, adm::ATTR_CAPABILITIES, 1 << adm::CAP_ENI_STATS);
                put32(body, adm::ATTR_PHYS_WIDTH, self.scenario.dma_width);
                body[adm::ATTR_MAC..adm::ATTR_MAC + 6]
                    .copy_from_slice(&[0x06, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]);
                put32(body, adm::ATTR_MAX_MTU, 9001);
            }
            adm::MAX_QUEUES_EXT => {
                for (at, v) in [
                    (adm::QEXT_TX_SQ_NUM, 2u32),
                    (adm::QEXT_TX_CQ_NUM, 2),
                    (adm::QEXT_RX_SQ_NUM, 2),
                    (adm::QEXT_RX_CQ_NUM, 2),
                    (adm::QEXT_TX_SQ_DEPTH, 1024),
                    (adm::QEXT_TX_CQ_DEPTH, 1024),
                    (adm::QEXT_RX_SQ_DEPTH, 1024),
                    (adm::QEXT_RX_CQ_DEPTH, 1024),
                ] {
                    put32(body, at, v);
                }
            }
            adm::AENQ_CONFIG => {
                let all = 1u32 << adm::AENQ_LINK_CHANGE
                    | 1 << adm::AENQ_FATAL_ERROR
                    | 1 << adm::AENQ_WARNING
                    | 1 << adm::AENQ_NOTIFICATION
                    | 1 << adm::AENQ_KEEP_ALIVE
                    | 1 << adm::AENQ_DEVICE_REQUEST_RESET;
                put32(body, adm::AENQ_SUPPORTED, all);
                put32(body, adm::AENQ_ENABLED, 0);
            }
            adm::STATELESS_OFFLOAD_CONFIG => {
                put32(body, adm::OFFLOAD_TX, 0x3);
                put32(body, adm::OFFLOAD_RX_SUPPORTED, 0x7);
            }
            adm::HW_HINTS => {
                body[adm::HINT_WATCHDOG..][..2].copy_from_slice(&6_000u16.to_le_bytes());
                body[adm::HINT_MISSING_TX..][..2].copy_from_slice(&5_000u16.to_le_bytes());
            }
            adm::LLQ => put32(body, adm::LLQ_MAX_NUM, 4),
            _ => return adm::UNSUPPORTED_OPCODE,
        }
        adm::SUCCESS
    }

    fn set_feature(&mut self, cmd: &[u8; adm::ENTRY]) -> u8 {
        let word = |at: usize| u32::from_le_bytes(cmd[at..at + 4].try_into().unwrap());
        match cmd[adm::FEAT_ID] {
            adm::AENQ_CONFIG => {
                self.enabled_groups = word(adm::FEAT_DATA + adm::AENQ_ENABLED);
                if self.scenario.link_event && self.enabled_groups & 1 << adm::AENQ_LINK_CHANGE != 0
                {
                    self.post_event(adm::AENQ_LINK_CHANGE, &1u32.to_le_bytes());
                }
                self.next_keep_ns = self.now + 1_000 * MS;
            }
            adm::MTU => self.mtu = word(adm::FEAT_DATA + adm::MTU_VALUE),
            _ => return adm::UNSUPPORTED_OPCODE,
        }
        adm::SUCCESS
    }

    /// Puts the due answers in the completion queue, with the phase.
    fn deliver(&mut self) {
        while self.answers.first().is_some_and(|a| a.due_ns <= self.now) {
            let mut a = self.answers.remove(0);
            let slot = usize::from(self.acq_tail & (adm::ADMIN_DEPTH - 1));
            a.entry[adm::ACQ_FLAGS] = self.acq_phase;
            let va = self.va(self.acq_base) + slot * adm::ENTRY;
            self.mem_put(va, &a.entry);
            self.acq_tail = self.acq_tail.wrapping_add(1);
            if self.acq_tail & (adm::ADMIN_DEPTH - 1) == 0 {
                self.acq_phase ^= 1;
            }
        }
    }

    /// Posts an event when the driver has left room: the entries the driver
    /// gave back are `aenq_head_db - depth` in all.
    fn post_event(&mut self, group: u16, data: &[u8]) -> bool {
        if self.aenq_base == 0 {
            return false;
        }
        let depth = u32::from(adm::EVENT_DEPTH);
        let given_back = self.aenq_head_db.wrapping_sub(depth) & 0xFFFF;
        let posted = u32::from(self.aenq_tail);
        if posted.wrapping_sub(given_back) & 0xFFFF >= depth {
            return false;
        }
        let slot = usize::from(self.aenq_tail & (adm::EVENT_DEPTH - 1));
        let mut entry = [0u8; adm::ENTRY];
        entry[adm::AENQ_GROUP..][..2].copy_from_slice(&group.to_le_bytes());
        entry[adm::AENQ_FLAGS] = self.aenq_phase;
        entry[adm::AENQ_DATA..][..data.len()].copy_from_slice(data);
        let va = self.va(self.aenq_base) + slot * adm::ENTRY;
        self.mem_put(va, &entry);
        self.aenq_tail = self.aenq_tail.wrapping_add(1);
        if self.aenq_tail & (adm::EVENT_DEPTH - 1) == 0 {
            self.aenq_phase ^= 1;
        }
        true
    }

    fn tick(&mut self) {
        if let Some(until) = self.reset_until
            && self.now >= until
            && !self.scenario.reset_never_ends
        {
            self.reset_until = None;
        }
        if self.in_reset() {
            return;
        }
        self.deliver();
        let groups = self.enabled_groups;
        if groups & 1 << adm::AENQ_KEEP_ALIVE != 0
            && !self.scenario.no_keep_alive
            && self.now >= self.next_keep_ns
        {
            let mut data = [0u8; 24];
            data[0..8].copy_from_slice(&(self.keep_sent * 2).to_le_bytes());
            data[8..16].copy_from_slice(&self.keep_sent.to_le_bytes());
            if self.post_event(adm::AENQ_KEEP_ALIVE, &data) {
                self.keep_sent += 1;
            }
            self.next_keep_ns += 1_000 * MS;
        }
        if let Some(t) = self.scenario.fatal_event_at_ns
            && self.now >= t
        {
            self.scenario.fatal_event_at_ns = None;
            self.post_event(adm::AENQ_FATAL_ERROR, &[]);
        }
        let _ = (
            self.aq_caps,
            self.acq_caps,
            self.aenq_caps,
            self.intr_mask,
            self.revision,
        );
    }
}

/// A zeroed region of `len` bytes on the host's heap, whose "physical"
/// address is `pa`, for the model and the driver to share.
pub fn region(len: usize, pa: u64) -> Region {
    let words = std::vec![0u64; len / 8].leak();
    Region {
        va: words.as_mut_ptr() as usize,
        pa,
        len,
    }
}
