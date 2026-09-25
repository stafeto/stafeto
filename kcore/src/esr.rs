// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Decoding of ESR_EL1, the exception syndrome register.

pub const EC_UNKNOWN: u8 = 0x00;
pub const EC_SVC64: u8 = 0x15;
pub const EC_IABT_LOWER: u8 = 0x20;
pub const EC_IABT_SAME: u8 = 0x21;
pub const EC_DABT_LOWER: u8 = 0x24;
pub const EC_DABT_SAME: u8 = 0x25;
pub const EC_BRK64: u8 = 0x3C;

/// Immediate of the BRK that kernel tests use to prove the exception return path.
pub const TEST_BRK: u16 = 0x51;

/// Exception class, ESR bits [31:26]. Newer cores use bits above 31, so they are masked off.
pub fn ec(esr: u64) -> u8 {
    ((esr >> 26) & 0x3F) as u8
}

/// The BRK immediate, ISS[15:0], when the exception is a BRK.
pub fn brk_immediate(esr: u64) -> Option<u16> {
    (ec(esr) == EC_BRK64).then_some((esr & 0xFFFF) as u16)
}

/// The system call number (spec 11), the immediate of `svc #number` in
/// ISS[15:0], when the exception is an SVC from AArch64.
pub fn svc_immediate(esr: u64) -> Option<u16> {
    (ec(esr) == EC_SVC64).then_some((esr & 0xFFFF) as u16)
}

pub fn class_name(ec: u8) -> &'static str {
    match ec {
        0x00 => "unknown or undefined instruction",
        0x01 => "WFI or WFE trapped",
        0x07 => "FP/SIMD access trapped",
        0x0E => "illegal execution state",
        0x15 => "SVC from AArch64",
        0x16 => "HVC from AArch64",
        0x17 => "SMC from AArch64",
        0x18 => "MSR or MRS trapped",
        0x20 => "instruction abort from EL0",
        0x21 => "instruction abort in the kernel",
        0x22 => "PC misaligned",
        0x24 => "data abort from EL0",
        0x25 => "data abort in the kernel",
        0x26 => "SP misaligned",
        0x2F => "SError",
        0x3C => "BRK",
        _ => "other",
    }
}

/// The fault status of an abort, ISS[5:0] (DFSC or IFSC).
pub fn fault_status_name(esr: u64) -> &'static str {
    match esr & 0x3F {
        0x00..=0x03 => "address size fault",
        0x04..=0x07 => "translation fault",
        0x08..=0x0B => "access flag fault",
        0x0C..=0x0F => "permission fault",
        0x10 => "synchronous external abort",
        0x21 => "alignment fault",
        _ => "other fault",
    }
}

/// Translation table level of an address size, translation, access flag or
/// permission fault (ISS[1:0], DFSC/IFSC 0x00..=0x0F); other fault statuses
/// carry no level.
pub fn fault_level(esr: u64) -> Option<u8> {
    matches!(esr & 0x3F, 0x00..=0x0F).then(|| (esr & 0b11) as u8)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrkAction {
    Skip,
    Panic,
}

/// A BRK in kernel code is a deliberate trap (Rust lowers aborts and
/// unreachable code to BRK) and stops the kernel; only the test marker in a
/// test build is skipped.
pub fn kernel_brk_action(imm: u16, test_build: bool) -> BrkAction {
    if test_build && imm == TEST_BRK {
        BrkAction::Skip
    } else {
        BrkAction::Panic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IL: u64 = 1 << 25;

    #[test]
    fn ec_ignores_bits_above_31() {
        assert_eq!(ec((1 << 32) | (0x25 << 26) | IL), 0x25);
    }

    #[test]
    fn brk_immediate_reads_iss_of_a_brk_only() {
        assert_eq!(brk_immediate((0x3C << 26) | IL | 0x51), Some(0x51));
        assert_eq!(brk_immediate((0x25 << 26) | IL | 0x51), None);
    }

    #[test]
    fn svc_immediate_reads_iss_of_an_svc_only() {
        assert_eq!(svc_immediate((0x15 << 26) | IL | 0xFF01), Some(0xFF01));
        assert_eq!(svc_immediate((1 << 32) | (0x15 << 26) | IL | 7), Some(7));
        assert_eq!(svc_immediate((0x3C << 26) | IL | 0xFF01), None);
    }

    #[test]
    fn fault_status_names_cover_the_abort_codes() {
        assert_eq!(fault_status_name(0x02), "address size fault");
        assert_eq!(fault_status_name(0x07), "translation fault");
        assert_eq!(fault_status_name(0x0B), "access flag fault");
        assert_eq!(fault_status_name(0x0F), "permission fault");
        assert_eq!(fault_status_name(0x10), "synchronous external abort");
        assert_eq!(fault_status_name(0x21), "alignment fault");
        assert_eq!(fault_status_name(0x3F), "other fault");
    }

    #[test]
    fn fault_level_is_the_low_two_bits() {
        assert_eq!(fault_level(0x06), Some(2));
        assert_eq!(fault_level(0x0F), Some(3));
        assert_eq!(fault_level(0x10), None);
        assert_eq!(fault_level(0x21), None);
    }

    #[test]
    fn test_build_skips_only_the_test_marker() {
        assert_eq!(kernel_brk_action(TEST_BRK, true), BrkAction::Skip);
        assert_eq!(kernel_brk_action(1, true), BrkAction::Panic);
    }

    #[test]
    fn normal_build_never_skips_brk() {
        assert_eq!(kernel_brk_action(TEST_BRK, false), BrkAction::Panic);
        assert_eq!(kernel_brk_action(1, false), BrkAction::Panic);
    }

    #[test]
    fn class_names_describe_common_classes() {
        assert_eq!(class_name(0x00), "unknown or undefined instruction");
        assert_eq!(class_name(0x15), "SVC from AArch64");
        assert_eq!(class_name(0x25), "data abort in the kernel");
        assert_eq!(class_name(0x3C), "BRK");
        assert_eq!(class_name(0x3E), "other");
    }
}
