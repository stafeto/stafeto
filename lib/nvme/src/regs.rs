// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The registers of the controller in BAR 0 and the bit fields of CAP, CC and
//! CSTS, as the NVM Express Base Specification defines them (the controller
//! properties, the doorbell stride). The 64-bit registers are read and written
//! as two 32-bit accesses, the low half first.

pub const CAP_LO: u32 = 0x00;
pub const CAP_HI: u32 = 0x04;
pub const VS: u32 = 0x08;
pub const CC: u32 = 0x14;
pub const CSTS: u32 = 0x1c;
pub const AQA: u32 = 0x24;
pub const ASQ_LO: u32 = 0x28;
pub const ASQ_HI: u32 = 0x2c;
pub const ACQ_LO: u32 = 0x30;
pub const ACQ_HI: u32 = 0x34;
/// The first doorbell.
pub const DB_BASE: u32 = 0x1000;

// CC: enable, I/O command set, memory page size (4 KiB << MPS), arbitration,
// shutdown notification, and the entry sizes of the I/O queues as log2 bytes.
pub const CC_EN: u32 = 1;
pub const CC_CSS_SHIFT: u32 = 4;
pub const CC_MPS_SHIFT: u32 = 7;
pub const CC_AMS_SHIFT: u32 = 11;
pub const CC_SHN_SHIFT: u32 = 14;
pub const CC_SHN_MASK: u32 = 3 << CC_SHN_SHIFT;
pub const CC_SHN_NORMAL: u32 = 1 << CC_SHN_SHIFT;
pub const CC_IOSQES_SHIFT: u32 = 16;
pub const CC_IOCQES_SHIFT: u32 = 20;
/// The entry sizes the driver uses: 64-byte submission and 16-byte completion
/// entries, as log2.
pub const SQES_LOG2: u32 = 6;
pub const CQES_LOG2: u32 = 4;

// CSTS.
pub const CSTS_RDY: u32 = 1;
pub const CSTS_CFS: u32 = 1 << 1;
pub const CSTS_SHST_SHIFT: u32 = 2;
pub const CSTS_SHST_MASK: u32 = 3 << CSTS_SHST_SHIFT;
pub const CSTS_SHST_COMPLETE: u32 = 2;
/// What a read of a function that is gone returns.
pub const GONE: u32 = 0xffff_ffff;

/// The `CC` the driver programs when it enables the controller: the NVM
/// command set, 4 KiB pages, round robin, the entry sizes of the driver.
pub const fn cc_enable() -> u32 {
    CC_EN | (SQES_LOG2 << CC_IOSQES_SHIFT) | (CQES_LOG2 << CC_IOCQES_SHIFT)
}

/// The fields of CAP the driver uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    /// Maximum queue entries supported, 0-based.
    pub mqes: u16,
    /// Worst-case wait for CSTS.RDY, in units of 500 ms.
    pub to: u8,
    /// Doorbell stride: 4 << dstrd bytes.
    pub dstrd: u8,
    /// Command sets supported (bit 0: the NVM command set).
    pub css: u8,
    /// Minimum and maximum memory page size, 4 KiB << n.
    pub mpsmin: u8,
    pub mpsmax: u8,
}

impl Cap {
    pub const fn decode(lo: u32, hi: u32) -> Cap {
        Cap {
            mqes: (lo & 0xffff) as u16,
            to: (lo >> 24) as u8,
            dstrd: (hi & 0xf) as u8,
            css: ((hi >> 5) & 0xff) as u8,
            mpsmin: ((hi >> 16) & 0xf) as u8,
            mpsmax: ((hi >> 20) & 0xf) as u8,
        }
    }

    /// The longest wait for readiness, in ns (at least one unit of 500 ms).
    pub const fn timeout_ns(&self) -> u64 {
        let units = if self.to == 0 { 1 } else { self.to as u64 };
        units * 500_000_000
    }
}

/// The offset of the submission queue `qid` tail doorbell.
pub const fn sq_tail_db(qid: u16, dstrd: u8) -> u32 {
    DB_BASE + (2 * qid as u32) * stride(dstrd)
}

/// The offset of the completion queue `qid` head doorbell.
pub const fn cq_head_db(qid: u16, dstrd: u8) -> u32 {
    DB_BASE + (2 * qid as u32 + 1) * stride(dstrd)
}

const fn stride(dstrd: u8) -> u32 {
    if cfg!(feature = "break-nvme-dstrd") {
        4
    } else {
        4 << dstrd
    }
}
