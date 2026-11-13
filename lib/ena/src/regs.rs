// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The registers of BAR 0. Every number below is a definition of
//! `ena_regs_defs.h` (FreeBSD `sys/contrib/ena-com/ena_defs/` and DPDK
//! `drivers/net/ena/base/ena_defs/`, BSD-3-Clause, see `NOTICE`); the line
//! before each group names the register or the enum the numbers come from,
//! and each constant's name is the header's with the prefix `ENA_REGS_`
//! dropped. The two trees agree on all of them; DPDK adds reset reason 20.

// ena_registers offsets (`ENA_REGS_*_OFF`).
pub const VERSION: u32 = 0x0;
pub const CONTROLLER_VERSION: u32 = 0x4;
pub const CAPS: u32 = 0x8;
pub const AQ_BASE_LO: u32 = 0x10;
pub const AQ_BASE_HI: u32 = 0x14;
pub const AQ_CAPS: u32 = 0x18;
pub const ACQ_BASE_LO: u32 = 0x20;
pub const ACQ_BASE_HI: u32 = 0x24;
pub const ACQ_CAPS: u32 = 0x28;
pub const AQ_DB: u32 = 0x2c;
pub const ACQ_TAIL: u32 = 0x30;
pub const AENQ_CAPS: u32 = 0x34;
pub const AENQ_BASE_LO: u32 = 0x38;
pub const AENQ_BASE_HI: u32 = 0x3c;
pub const AENQ_HEAD_DB: u32 = 0x40;
pub const AENQ_TAIL: u32 = 0x44;
pub const INTR_MASK: u32 = 0x4c;
pub const DEV_CTL: u32 = 0x54;
pub const DEV_STS: u32 = 0x58;
pub const MMIO_REG_READ: u32 = 0x5c;
pub const MMIO_RESP_LO: u32 = 0x60;
pub const MMIO_RESP_HI: u32 = 0x64;

// version register.
pub const VERSION_MINOR_MASK: u32 = 0xff;
pub const VERSION_MAJOR_SHIFT: u32 = 8;
pub const VERSION_MAJOR_MASK: u32 = 0xff00;

// controller_version register.
pub const CONTROLLER_VERSION_SUBMINOR_MASK: u32 = 0xff;
pub const CONTROLLER_VERSION_MINOR_SHIFT: u32 = 8;
pub const CONTROLLER_VERSION_MINOR_MASK: u32 = 0xff00;
pub const CONTROLLER_VERSION_MAJOR_SHIFT: u32 = 16;
pub const CONTROLLER_VERSION_MAJOR_MASK: u32 = 0xff0000;
pub const CONTROLLER_VERSION_IMPL_ID_SHIFT: u32 = 24;
pub const CONTROLLER_VERSION_IMPL_ID_MASK: u32 = 0xff00_0000;

// caps register.
pub const CAPS_CONTIGUOUS_QUEUE_REQUIRED_MASK: u32 = 0x1;
pub const CAPS_RESET_TIMEOUT_SHIFT: u32 = 1;
pub const CAPS_RESET_TIMEOUT_MASK: u32 = 0x3e;
pub const CAPS_DMA_ADDR_WIDTH_SHIFT: u32 = 8;
pub const CAPS_DMA_ADDR_WIDTH_MASK: u32 = 0xff00;
pub const CAPS_ADMIN_CMD_TO_SHIFT: u32 = 16;
pub const CAPS_ADMIN_CMD_TO_MASK: u32 = 0xf0000;

// aq_caps, acq_caps and aenq_caps registers: the depth in the low half, the
// entry size in bytes in the high half.
pub const QUEUE_CAPS_DEPTH_MASK: u32 = 0xffff;
pub const QUEUE_CAPS_ENTRY_SIZE_SHIFT: u32 = 16;
pub const QUEUE_CAPS_ENTRY_SIZE_MASK: u32 = 0xffff_0000;

// dev_ctl register.
pub const DEV_CTL_DEV_RESET_MASK: u32 = 0x1;
pub const DEV_CTL_RESET_REASON_EXT_SHIFT: u32 = 24;
pub const DEV_CTL_RESET_REASON_EXT_MASK: u32 = 0xf00_0000;
pub const DEV_CTL_RESET_REASON_SHIFT: u32 = 28;
pub const DEV_CTL_RESET_REASON_MASK: u32 = 0xf000_0000;

// dev_sts register.
pub const DEV_STS_READY_MASK: u32 = 0x1;
pub const DEV_STS_RESET_IN_PROGRESS_MASK: u32 = 0x8;
pub const DEV_STS_RESET_FINISHED_MASK: u32 = 0x10;
pub const DEV_STS_FATAL_ERROR_MASK: u32 = 0x20;

// mmio_reg_read register.
pub const MMIO_REG_READ_REQ_ID_MASK: u32 = 0xffff;
pub const MMIO_REG_READ_REG_OFF_SHIFT: u32 = 16;
pub const MMIO_REG_READ_REG_OFF_MASK: u32 = 0xffff_0000;

// The value this driver writes to INTR_MASK so that the admin interrupt stays
// masked while it polls (the driver's own choice; the headers give no number for it).
pub const ADMIN_INTR_MASK: u32 = 1;

// enum ena_regs_reset_reason_types.
pub const RESET_NORMAL: u32 = 0;
pub const RESET_KEEP_ALIVE_TO: u32 = 1;
pub const RESET_ADMIN_TO: u32 = 2;
pub const RESET_MISS_TX_CMPL: u32 = 3;
pub const RESET_INV_RX_REQ_ID: u32 = 4;
pub const RESET_INV_TX_REQ_ID: u32 = 5;
pub const RESET_TOO_MANY_RX_DESCS: u32 = 6;
pub const RESET_INIT_ERR: u32 = 7;
pub const RESET_DRIVER_INVALID_STATE: u32 = 8;
pub const RESET_OS_TRIGGER: u32 = 9;
pub const RESET_OS_NETDEV_WD: u32 = 10;
pub const RESET_SHUTDOWN: u32 = 11;
pub const RESET_USER_TRIGGER: u32 = 12;
pub const RESET_GENERIC: u32 = 13;
pub const RESET_MISS_INTERRUPT: u32 = 14;
pub const RESET_SUSPECTED_POLL_STARVATION: u32 = 15;
pub const RESET_RX_DESCRIPTOR_MALFORMED: u32 = 16;
pub const RESET_TX_DESCRIPTOR_MALFORMED: u32 = 17;
pub const RESET_MISSING_ADMIN_INTERRUPT: u32 = 18;
pub const RESET_DEVICE_REQUEST: u32 = 19;

/// The `DEV_CTL` word that resets the device for `reason`: the reset bit, the
/// low four bits of the reason in bits 31:28, and, when the device advertises
/// extended reset reasons (`extended`), the next four in bits 27:24. A reason above
/// 15 that the device cannot take goes as `RESET_GENERIC`.
pub const fn reset_word(reason: u32, extended: bool) -> u32 {
    let reason = if reason > 15 && !extended && !cfg!(feature = "break-reset-reason") {
        RESET_GENERIC
    } else {
        reason
    };
    DEV_CTL_DEV_RESET_MASK
        | (reason << DEV_CTL_RESET_REASON_SHIFT) & DEV_CTL_RESET_REASON_MASK
        | ((reason >> 4) << DEV_CTL_RESET_REASON_EXT_SHIFT) & DEV_CTL_RESET_REASON_EXT_MASK
}
