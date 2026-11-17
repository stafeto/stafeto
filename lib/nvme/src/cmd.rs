// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The commands: the 64-byte submission entry, the 16-byte completion entry
//! with its phase bit, the opcodes, and the PRP entries of a transfer. The
//! numbers are those of the NVM Express Base Specification and the NVM
//! Command Set Specification.

/// The bytes of a submission and of a completion entry.
pub const SQE_BYTES: usize = 64;
pub const CQE_BYTES: usize = 16;
/// The memory page the controller is told to use (CC.MPS = 0).
pub const PAGE: usize = 4096;

// Admin opcodes.
pub const ADMIN_CREATE_SQ: u8 = 0x01;
pub const ADMIN_CREATE_CQ: u8 = 0x05;
pub const ADMIN_IDENTIFY: u8 = 0x06;
pub const ADMIN_SET_FEATURES: u8 = 0x09;
// NVM opcodes.
pub const NVM_FLUSH: u8 = 0x00;
pub const NVM_WRITE: u8 = 0x01;
pub const NVM_READ: u8 = 0x02;

pub const FID_NUMBER_OF_QUEUES: u32 = 0x07;
pub const CNS_NAMESPACE: u32 = 0;
pub const CNS_CONTROLLER: u32 = 1;

// Offsets in Identify Controller (bytes).
pub const IDC_SN: usize = 4;
pub const IDC_MN: usize = 24;
pub const IDC_FR: usize = 64;
pub const IDC_MDTS: usize = 77;
pub const IDC_VER: usize = 80;
pub const IDC_NN: usize = 516;
pub const IDC_VWC: usize = 525;
/// The vendor specific area: EBS puts the name of the block device here.
pub const IDC_VENDOR_NAME: usize = 3072;
// Offsets in Identify Namespace (bytes).
pub const IDN_NSZE: usize = 0;
pub const IDN_NLBAF: usize = 25;
pub const IDN_FLBAS: usize = 26;
pub const IDN_LBAF: usize = 128;

// Generic command status: SCT 0.
pub const SC_SUCCESS: u8 = 0x00;
pub const SC_INVALID_OPCODE: u8 = 0x01;
pub const SC_INVALID_FIELD: u8 = 0x02;
pub const SC_LBA_RANGE: u8 = 0x80;

/// A submission entry as its sixteen dwords.
pub type Sqe = [u32; 16];

/// An entry with the opcode, the command identifier and the namespace set.
pub fn sqe(opcode: u8, cid: u16, nsid: u32) -> Sqe {
    let mut e = [0u32; 16];
    e[0] = opcode as u32 | (cid as u32) << 16;
    e[1] = nsid;
    e
}

/// Sets PRP1 and PRP2 (dwords 6 to 9).
pub fn set_prp(e: &mut Sqe, prp1: u64, prp2: u64) {
    e[6] = prp1 as u32;
    e[7] = (prp1 >> 32) as u32;
    e[8] = prp2 as u32;
    e[9] = (prp2 >> 32) as u32;
}

/// The command dwords 10, 11 and 12 of a Read or Write: the starting LBA and
/// the number of blocks, 0-based.
pub fn set_rw(e: &mut Sqe, slba: u64, blocks: u32) {
    e[10] = slba as u32;
    e[11] = (slba >> 32) as u32;
    e[12] = (blocks - 1) & 0xffff;
}

/// A completion entry decoded from its four dwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cqe {
    pub result: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub cid: u16,
    pub phase: bool,
    pub sc: u8,
    pub sct: u8,
    /// Do Not Retry.
    pub dnr: bool,
}

impl Cqe {
    pub const fn decode(w: [u32; 4]) -> Cqe {
        Cqe {
            result: w[0],
            sq_head: (w[2] & 0xffff) as u16,
            sq_id: (w[2] >> 16) as u16,
            cid: (w[3] & 0xffff) as u16,
            phase: w[3] >> 16 & 1 != 0,
            sc: (w[3] >> 17) as u8,
            sct: (w[3] >> 25 & 7) as u8,
            dnr: w[3] >> 31 != 0,
        }
    }

    pub const fn ok(&self) -> bool {
        self.sc == 0 && self.sct == 0
    }
}

/// The phase bit of dword 3.
pub const fn phase_of(dw3: u32) -> bool {
    dw3 >> 16 & 1 != 0
}

/// PRP1 and PRP2 of a part of a transfer: `len` bytes from the page-aligned
/// address `first`, `list` the address of a prepared list of the following
/// pages. One page needs PRP1 alone, two put the second page in PRP2, more
/// point PRP2 at a list that starts with the second page.
pub fn prps(first: u64, len: usize, list: u64) -> (u64, u64) {
    let pages = len.div_ceil(PAGE);
    match pages {
        0 | 1 => (first, 0),
        2 => (first, first + PAGE as u64),
        _ if cfg!(feature = "break-nvme-prp2") => (first, first + PAGE as u64),
        _ => (first, list),
    }
}
