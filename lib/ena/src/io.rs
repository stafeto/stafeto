// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data path of one queue pair: the submission and completion queues of
//! sending and of receiving in the host's memory (no LLQ), the descriptors
//! and the doorbells. The numbers are definitions of `ena_eth_io_defs.h`
//! (FreeBSD `sys/contrib/ena-com/ena_defs/`, DPDK
//! `drivers/net/ena/base/ena_defs/`, BSD-3-Clause, see `NOTICE`): the sizes
//! of the four descriptors, the bits of their words and the offsets of their
//! fields (sums of the header's field sizes). The logic is this library's own.
//!
//! The owner of the pair (the switch thread of `netd`) holds an `Io`. The
//! admin side (`Ena`) makes the queues and hands over what the device told
//! it (`Info`); the owner touches the rings and the doorbells alone and never
//! waits: every call makes at most one register access.

use crate::device::{Platform, Region};

/// The entries of each queue: all four are this deep, so a queue never holds
/// more than the buffers its pair owns.
pub const DEPTH: u16 = 256;
/// The bytes of a descriptor of sending and of receiving, of a completion of
/// sending and of a completion of receiving (`ena_eth_io_tx_desc`,
/// `ena_eth_io_rx_desc`, `ena_eth_io_tx_cdesc`, `ena_eth_io_rx_cdesc_base`).
pub const TX_DESC: usize = 16;
pub const RX_DESC: usize = 16;
pub const TX_CDESC: usize = 8;
pub const RX_CDESC: usize = 16;
/// The size of a completion of each kind in 32-bit words, which CREATE_CQ takes.
pub const TX_CDESC_WORDS: u8 = (TX_CDESC / 4) as u8;
pub const RX_CDESC_WORDS: u8 = (RX_CDESC / 4) as u8;

/// Where the queues lie in the driver's region: after the admin structures
/// (`device::ADMIN_BYTES`), 16 KiB in all.
pub const IO_AT: usize = 0x4000;
pub const TX_SQ_AT: usize = IO_AT;
pub const TX_CQ_AT: usize = TX_SQ_AT + DEPTH as usize * TX_DESC;
pub const RX_SQ_AT: usize = IO_AT + 0x2000;
pub const RX_CQ_AT: usize = RX_SQ_AT + DEPTH as usize * RX_DESC;
pub const IO_END: usize = RX_CQ_AT + DEPTH as usize * RX_CDESC;
const _: () = assert!(TX_CQ_AT + DEPTH as usize * TX_CDESC <= RX_SQ_AT);
const _: () = assert!(IO_END == IO_AT + 0x4000);
const _: () = assert!(IO_AT >= crate::device::ADMIN_BYTES);
/// The bytes of the rings, and the 64-bit stores that zero them.
pub const IO_BYTES: usize = IO_END - IO_AT;
pub const IO_STORES: u32 = (IO_BYTES / 8) as u32;

// ena_eth_io_tx_desc: `len_ctrl` at 0, `meta_ctrl` at 4, `buff_addr_lo` at 8,
// `buff_addr_hi_hdr_sz` at 12.
pub const TX_LEN_MASK: u32 = 0xFFFF;
pub const TX_REQ_ID_HI_SHIFT: u32 = 16;
pub const TX_REQ_ID_HI_MASK: u32 = 0x3F << 16;
pub const TX_META_DESC: u32 = 1 << 23;
pub const TX_PHASE_SHIFT: u32 = 24;
pub const TX_FIRST: u32 = 1 << 26;
pub const TX_LAST: u32 = 1 << 27;
pub const TX_COMP_REQ: u32 = 1 << 28;
pub const TX_REQ_ID_LO_SHIFT: u32 = 22;
pub const TX_REQ_ID_LO_MASK: u32 = 0x3FF << 22;
pub const TX_ADDR_HI_MASK: u32 = 0xFFFF;
pub const TX_HEADER_LENGTH_SHIFT: u32 = 24;

// ena_eth_io_tx_cdesc: `req_id` (16 bits) at 0, `status` at 2, `flags` at 3
// (the phase in bit 0), `sub_qid` at 4, `sq_head_idx` at 6.
pub const TX_CDESC_REQ_ID: usize = 0;
pub const TX_CDESC_STATUS: usize = 2;
pub const TX_CDESC_FLAGS: usize = 3;
pub const TX_CDESC_PHASE: u8 = 1;

// ena_eth_io_rx_desc: `length` (16 bits) at 0, `ctrl` at 3, `req_id` (16
// bits) at 4, `buff_addr_lo` at 8, `buff_addr_hi` (16 bits) at 12.
pub const RX_DESC_LENGTH: usize = 0;
pub const RX_DESC_CTRL: usize = 3;
pub const RX_DESC_REQ_ID: usize = 4;
pub const RX_DESC_ADDR_LO: usize = 8;
pub const RX_DESC_ADDR_HI: usize = 12;
pub const RX_CTRL_PHASE: u8 = 1;
pub const RX_CTRL_FIRST: u8 = 1 << 2;
pub const RX_CTRL_LAST: u8 = 1 << 3;
pub const RX_CTRL_COMP_REQ: u8 = 1 << 4;

// ena_eth_io_rx_cdesc_base: `status` (32 bits) at 0, `length` (16 bits) at 4,
// `req_id` (16 bits) at 6, `hash` at 8, `sub_qid` at 12, `offset` at 14.
pub const RX_CDESC_STATUS: usize = 0;
pub const RX_CDESC_LENGTH: usize = 4;
pub const RX_CDESC_REQ_ID: usize = 6;
pub const RX_CDESC_HASH: usize = 8;
pub const RX_CDESC_OFFSET: usize = 14;
pub const RX_STATUS_L3_CSUM_ERR: u32 = 1 << 13;
pub const RX_STATUS_L4_CSUM_ERR: u32 = 1 << 14;
pub const RX_STATUS_IPV4_FRAG: u32 = 1 << 15;
pub const RX_STATUS_L4_CSUM_CHECKED: u32 = 1 << 16;
pub const RX_STATUS_PHASE: u32 = 1 << 24;
pub const RX_STATUS_FIRST: u32 = 1 << 26;
pub const RX_STATUS_LAST: u32 = 1 << 27;

// ena_eth_io_intr_reg, the word a CQ's unmask register takes.
pub const INTR_UNMASK: u32 = 1 << 30;
pub const INTR_NO_MODERATION_UPDATE: u32 = 1 << 31;

/// What the device told the admin side about the pair: the doorbells and the
/// registers of the completion queues, as offsets in BAR 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub tx_db: u32,
    pub rx_db: u32,
    pub tx_cq_head_db: u32,
    pub rx_cq_head_db: u32,
    pub rx_unmask: u32,
}

/// The buffers: `net` object of 512 buffers of `BUFFER_LEN` bytes, mapped at
/// `va` and addressed by the device at `pa`. A frame lies `HDR_LEN` bytes
/// into its buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buffers {
    pub va: usize,
    pub pa: u64,
    pub count: u16,
}

/// The bytes of one buffer, and the bytes before a frame in it.
pub const BUFFER_LEN: usize = 2048;
pub const HDR_LEN: usize = 12;

impl Buffers {
    /// The device's address of the frame area of buffer `n`.
    pub fn frame_pa(&self, n: u16) -> u64 {
        self.pa + n as u64 * BUFFER_LEN as u64 + HDR_LEN as u64
    }

    pub fn top(&self) -> u64 {
        self.pa + self.count as u64 * BUFFER_LEN as u64
    }
}

/// A received frame: the buffer, the bytes of the frame in it (after
/// `HDR_LEN`), whether the device checked the sum of the segment and found it
/// good, and whether the frame took more than one descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rx {
    pub n: u16,
    pub len: u16,
    pub sum_ok: bool,
    pub whole: bool,
}

/// How a queue of the pair and the device disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// A completion names a request the pair does not hold.
    Unknown,
}

/// The queues of the pair as the owner sees them: the tails and the phases
/// the driver writes with, the heads and the phases it reads with.
pub struct Io<P: Platform> {
    p: P,
    mem: Region,
    bufs: Buffers,
    info: Info,
    tx_tail: u16,
    tx_phase: u8,
    tx_head: u16,
    tx_head_phase: u8,
    rx_tail: u16,
    rx_phase: u8,
    rx_head: u16,
    rx_head_phase: u8,
    /// The tail last written to each doorbell.
    tx_rung: u16,
    rx_rung: u16,
    /// The completions taken since the head was last written to the device.
    tx_unreported: u16,
    rx_unreported: u16,
    /// The descriptors of each queue the device has not completed.
    tx_out: u16,
    rx_out: u16,
}

/// The heads of the completion queues are told to the device after this many
/// completions (half a queue), so that it knows the room it has.
const HEAD_EVERY: u16 = DEPTH / 2;

impl<P: Platform> Io<P> {
    /// The pair over `mem` (its queues zeroed, from `IO_AT`) and `bufs`, as the
    /// device `info` says.
    ///
    /// # Safety
    ///
    /// `mem.va` and `bufs.va` are valid, writable memory for the lengths they
    /// say for as long as the value lives; the device reads and writes `mem`
    /// at `mem.pa` and the buffers at `bufs.pa`, and nothing else touches the
    /// queues.
    pub unsafe fn new(p: P, mem: Region, bufs: Buffers, info: Info) -> Io<P> {
        Io {
            p,
            mem,
            bufs,
            info,
            tx_tail: 0,
            tx_phase: 1,
            tx_head: 0,
            tx_head_phase: 1,
            rx_tail: 0,
            rx_phase: 1,
            rx_head: 0,
            rx_head_phase: 1,
            tx_rung: 0,
            rx_rung: 0,
            tx_unreported: 0,
            rx_unreported: 0,
            tx_out: 0,
            rx_out: 0,
        }
    }

    pub fn platform(&self) -> &P {
        &self.p
    }

    fn at(&self, offset: usize) -> *mut u8 {
        (self.mem.va + offset) as *mut u8
    }

    fn put32(&self, offset: usize, value: u32) {
        // SAFETY: the offsets are inside the rings (`IO_END` is within the
        // region the caller promised) and word aligned; the device reads the
        // queues, so the store is volatile.
        unsafe { core::ptr::write_volatile(self.at(offset).cast::<u32>(), value) }
    }

    fn put16(&self, offset: usize, value: u16) {
        // SAFETY: as for `put32`.
        unsafe { core::ptr::write_volatile(self.at(offset).cast::<u16>(), value) }
    }

    fn put8(&self, offset: usize, value: u8) {
        // SAFETY: as for `put32`.
        unsafe { core::ptr::write_volatile(self.at(offset), value) }
    }

    fn get8(&self, offset: usize) -> u8 {
        // SAFETY: as for `put32`; the device writes the completions.
        unsafe { core::ptr::read_volatile(self.at(offset)) }
    }

    fn get16(&self, offset: usize) -> u16 {
        // SAFETY: as for `get8`, and the offsets are even.
        unsafe { core::ptr::read_volatile(self.at(offset).cast::<u16>()) }
    }

    fn get32(&self, offset: usize) -> u32 {
        // SAFETY: as for `get8`, and the offsets are multiples of 4.
        unsafe { core::ptr::read_volatile(self.at(offset).cast::<u32>()) }
    }

    /// Descriptors of receiving the device holds.
    pub fn rx_held(&self) -> u16 {
        self.rx_out
    }

    /// Descriptors of sending the device holds (submitted, not yet completed).
    pub fn tx_held(&self) -> u16 {
        self.tx_out
    }

    /// Puts buffer `n` in the queue of receiving, for a frame of up to
    /// `BUFFER_LEN - HDR_LEN` bytes. False when the queue holds `DEPTH` of them
    /// already or `n` is no buffer.
    pub fn rx_give(&mut self, n: u16) -> bool {
        if self.rx_out >= DEPTH || n >= self.bufs.count {
            return false;
        }
        let slot = usize::from(self.rx_tail % DEPTH);
        let at = RX_SQ_AT + slot * RX_DESC;
        let pa = self.bufs.frame_pa(n);
        self.put16(at + RX_DESC_LENGTH, (BUFFER_LEN - HDR_LEN) as u16);
        self.put16(at + RX_DESC_REQ_ID, n);
        self.put32(at + RX_DESC_ADDR_LO, pa as u32);
        self.put16(at + RX_DESC_ADDR_HI, (pa >> 32) as u16);
        // The control byte, with the phase, last: the device owns the entry
        // once the phase it waits for is there.
        let ctrl = if cfg!(feature = "break-rx-phase") {
            RX_CTRL_FIRST | RX_CTRL_LAST | RX_CTRL_COMP_REQ
        } else {
            self.rx_phase | RX_CTRL_FIRST | RX_CTRL_LAST | RX_CTRL_COMP_REQ
        };
        self.put8(at + RX_DESC_CTRL, ctrl);
        self.rx_tail = self.rx_tail.wrapping_add(1);
        if self.rx_tail.is_multiple_of(DEPTH) {
            self.rx_phase ^= 1;
        }
        self.rx_out += 1;
        true
    }

    /// Whether the doorbell of receiving is behind the tail.
    pub fn rx_bell_due(&self) -> bool {
        self.rx_rung != self.rx_tail
    }

    /// Tells the device the tail of receiving, once: after the descriptors are
    /// in memory. One register access, or none when the device knows it.
    pub fn rx_bell(&mut self) -> bool {
        if !self.rx_bell_due() {
            return false;
        }
        self.p.wmb();
        self.p.write32(self.info.rx_db, u32::from(self.rx_tail));
        self.rx_rung = self.rx_tail;
        true
    }

    /// Puts the frame of `len` bytes in buffer `n` (after `HDR_LEN`) in the
    /// queue of sending. False for a full queue, a length the descriptor does
    /// not hold, or a buffer that is none.
    pub fn tx_submit(&mut self, n: u16, len: u16) -> bool {
        if self.tx_out >= DEPTH
            || n >= self.bufs.count
            || len == 0
            || usize::from(len) + HDR_LEN > BUFFER_LEN
        {
            return false;
        }
        let slot = usize::from(self.tx_tail % DEPTH);
        let at = TX_SQ_AT + slot * TX_DESC;
        let pa = self.bufs.frame_pa(n);
        let req = u32::from(n);
        let phase = if cfg!(feature = "break-tx-phase") {
            0
        } else {
            u32::from(self.tx_phase)
        };
        let len_ctrl = u32::from(len) & TX_LEN_MASK
            | (req >> 10) << TX_REQ_ID_HI_SHIFT & TX_REQ_ID_HI_MASK
            | phase << TX_PHASE_SHIFT
            | TX_FIRST
            | TX_LAST
            | TX_COMP_REQ;
        self.put32(at + 4, (req << TX_REQ_ID_LO_SHIFT) & TX_REQ_ID_LO_MASK);
        self.put32(at + 8, pa as u32);
        self.put32(at + 12, (pa >> 32) as u32 & TX_ADDR_HI_MASK);
        // The word with the phase last.
        self.put32(at, len_ctrl);
        self.tx_tail = self.tx_tail.wrapping_add(1);
        if self.tx_tail.is_multiple_of(DEPTH) {
            self.tx_phase ^= 1;
        }
        self.tx_out += 1;
        true
    }

    pub fn tx_bell_due(&self) -> bool {
        self.tx_rung != self.tx_tail
    }

    /// Tells the device the tail of sending, once.
    pub fn tx_bell(&mut self) -> bool {
        if !self.tx_bell_due() {
            return false;
        }
        self.p.wmb();
        self.p.write32(self.info.tx_db, u32::from(self.tx_tail));
        self.tx_rung = self.tx_tail;
        true
    }

    /// Whether a completion of receiving is waiting.
    pub fn rx_ready(&self) -> bool {
        let at = RX_CQ_AT + usize::from(self.rx_head % DEPTH) * RX_CDESC;
        self.p.rmb();
        u8::from(self.get32(at + RX_CDESC_STATUS) & RX_STATUS_PHASE != 0) == self.rx_head_phase
    }

    /// The next completion of receiving, if one is there: `whole` is false for
    /// a frame that took more than one descriptor, which the owner drops
    /// (every descriptor of it comes out as one `Rx`, its buffer to be given
    /// back).
    pub fn rx_pop(&mut self) -> Result<Option<Rx>, Bad> {
        let at = RX_CQ_AT + usize::from(self.rx_head % DEPTH) * RX_CDESC;
        self.p.rmb();
        let status = self.get32(at + RX_CDESC_STATUS);
        if u8::from(status & RX_STATUS_PHASE != 0) != self.rx_head_phase {
            return Ok(None);
        }
        self.p.rmb();
        let len = self.get16(at + RX_CDESC_LENGTH);
        let n = self.get16(at + RX_CDESC_REQ_ID);
        if n >= self.bufs.count || self.rx_out == 0 {
            return Err(Bad::Unknown);
        }
        self.rx_head = self.rx_head.wrapping_add(1);
        if self.rx_head.is_multiple_of(DEPTH) && !cfg!(feature = "break-cq-phase") {
            self.rx_head_phase ^= 1;
        }
        self.rx_out -= 1;
        self.rx_unreported += 1;
        if self.rx_unreported >= HEAD_EVERY && !cfg!(feature = "break-cq-head") {
            self.rx_unreported = 0;
            self.p
                .write32(self.info.rx_cq_head_db, u32::from(self.rx_head));
        }
        let whole = status & RX_STATUS_FIRST != 0 && status & RX_STATUS_LAST != 0;
        let sum_ok = status & RX_STATUS_L4_CSUM_CHECKED != 0
            && status & (RX_STATUS_L3_CSUM_ERR | RX_STATUS_L4_CSUM_ERR) == 0;
        Ok(Some(Rx {
            n,
            len,
            sum_ok,
            whole,
        }))
    }

    /// Takes up to `limit` completions of sending, each handed to `done` with
    /// the buffer it names. The number taken, or a request the pair does not
    /// hold. One register access at most (the head, after half a queue).
    pub fn tx_reclaim(&mut self, limit: usize, mut done: impl FnMut(u16)) -> Result<usize, Bad> {
        let mut taken = 0;
        while taken < limit {
            let at = TX_CQ_AT + usize::from(self.tx_head % DEPTH) * TX_CDESC;
            self.p.rmb();
            if self.get8(at + TX_CDESC_FLAGS) & TX_CDESC_PHASE != self.tx_head_phase {
                break;
            }
            self.p.rmb();
            let n = self.get16(at + TX_CDESC_REQ_ID);
            if n >= self.bufs.count || self.tx_out == 0 {
                return Err(Bad::Unknown);
            }
            self.tx_head = self.tx_head.wrapping_add(1);
            if self.tx_head.is_multiple_of(DEPTH) {
                self.tx_head_phase ^= 1;
            }
            self.tx_out -= 1;
            self.tx_unreported += 1;
            done(n);
            taken += 1;
        }
        if self.tx_unreported >= HEAD_EVERY && !cfg!(feature = "break-cq-head") {
            self.tx_unreported = 0;
            self.p
                .write32(self.info.tx_cq_head_db, u32::from(self.tx_head));
        }
        Ok(taken)
    }

    /// Whether a completion of sending is waiting.
    pub fn tx_ready(&self) -> bool {
        let at = TX_CQ_AT + usize::from(self.tx_head % DEPTH) * TX_CDESC;
        self.p.rmb();
        self.get8(at + TX_CDESC_FLAGS) & TX_CDESC_PHASE == self.tx_head_phase
    }

    /// Lets the device interrupt for the next completion of receiving: the
    /// vector is masked after each interrupt until this write.
    pub fn unmask_rx(&mut self) {
        if !cfg!(feature = "break-no-unmask") {
            self.p
                .write32(self.info.rx_unmask, INTR_UNMASK | INTR_NO_MODERATION_UPDATE);
        }
    }

    /// Whether the device has completions of receiving to give or room for the
    /// queue to be looked at once more (`rx_pop` is the check).
    pub fn rx_pending(&self) -> bool {
        self.rx_ready()
    }
}
