// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System register values that decide what programs at EL0 may do (spec
//! 7.2, 8, 10). Bit positions are those of SCTLR_EL1, CPACR_EL1,
//! CNTKCTL_EL1, MDSCR_EL1, ID_AA64DFR0_EL1 and SPSR_EL1 in the Arm ARM.

/// SCTLR_EL1 bits that ARMv8.0 defines as RES1: 29, 28, 23, 22, 20, 11.
pub const SCTLR_RES1: u64 = 0x30D0_0800;
pub const SCTLR_M: u64 = 1 << 0;
pub const SCTLR_A: u64 = 1 << 1;
pub const SCTLR_C: u64 = 1 << 2;
pub const SCTLR_SA: u64 = 1 << 3;
pub const SCTLR_SA0: u64 = 1 << 4;
pub const SCTLR_UMA: u64 = 1 << 9;
pub const SCTLR_I: u64 = 1 << 12;
pub const SCTLR_DZE: u64 = 1 << 14;
pub const SCTLR_UCT: u64 = 1 << 15;
pub const SCTLR_NTWI: u64 = 1 << 16;
pub const SCTLR_NTWE: u64 = 1 << 18;
pub const SCTLR_WXN: u64 = 1 << 19;
pub const SCTLR_E0E: u64 = 1 << 24;
pub const SCTLR_UCI: u64 = 1 << 26;

/// What head.S writes when it turns the MMU on (SCTLR_MMU_ON): the RES1
/// bits, the MMU, both caches, and SP alignment checks at EL1 and EL0.
pub const SCTLR_EL1_BOOT: u64 = SCTLR_RES1 | SCTLR_M | SCTLR_C | SCTLR_SA | SCTLR_SA0 | SCTLR_I;

/// SCTLR_EL1 from the moment the kernel tables replace the boot tables,
/// whose image blocks are writable and executable at once:
/// - WXN: no page is both writable and executable, at any level;
/// - UCT and UCI: EL0 reads the cache line sizes (CTR_EL0) and cleans
///   caches by address, for code a program writes and runs at the same
///   address; code bound for another process is synchronized by the
///   kernel when it maps the page executable;
/// - DZE: EL0 zeroes cache lines with DC ZVA;
/// - nTWE: WFE at EL0, a spin-wait hint, does not trap.
///
/// nTWI stays clear, so WFI at EL0 traps: only the kernel puts the
/// processor to sleep. UMA stays clear: EL0 cannot mask interrupts.
/// Alignment checks (A) stay off, and EL0 data stays little-endian (E0E).
pub const SCTLR_EL1: u64 =
    SCTLR_EL1_BOOT | SCTLR_WXN | SCTLR_UCT | SCTLR_UCI | SCTLR_DZE | SCTLR_NTWE;

/// CPACR_EL1.FPEN = 0b11: FP and SIMD instructions do not trap at EL0 or
/// EL1. The kernel is built without FP; only the thread switch touches
/// these registers, in assembly.
pub const CPACR_EL1: u64 = 0b11 << 20;

/// CNTKCTL_EL1.EL0VCTEN: EL0 reads CNTVCT_EL0 and CNTFRQ_EL0 (spec 10).
/// EL0PCTEN (bit 0), EL0VTEN (bit 8) and EL0PTEN (bit 9) stay clear: no
/// physical counter and no timer registers for programs.
pub const CNTKCTL_EL1: u64 = 1 << 1;

/// MDSCR_EL1: TDCC traps EL0 access to the debug communication channel;
/// MDE, KDE and SS stay clear: no breakpoints, watchpoints or
/// single-stepping. Its fields are UNKNOWN after reset, so the kernel
/// writes it whole.
pub const MDSCR_EL1: u64 = 1 << 12;

/// Whether PMUSERENR_EL0 exists: ID_AA64DFR0_EL1.PMUVer, bits [11:8], is
/// neither 0 (no PMU) nor 0xF (an IMPLEMENTATION DEFINED one). Its fields
/// are UNKNOWN after reset; the kernel clears them, so programs reach no
/// PMU register.
pub fn has_pmu(dfr0: u64) -> bool {
    !matches!((dfr0 >> 8) & 0xF, 0 | 0xF)
}

/// SPSR_EL1 for a thread's first return to EL0: EL0t in AArch64, flags
/// clear, no exception masked.
pub const SPSR_EL0T: u64 = 0;

/// The condition flags in SPSR_EL1, bits [31:28].
pub const SPSR_NZCV: u64 = 0xF << 28;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_value_is_the_one_head_s_writes() {
        assert_eq!(SCTLR_EL1_BOOT, 0x30D0_181D);
    }

    #[test]
    fn running_value_keeps_the_boot_bits_and_opens_el0() {
        assert_eq!(SCTLR_EL1 & SCTLR_EL1_BOOT, SCTLR_EL1_BOOT);
        for bit in [SCTLR_WXN, SCTLR_UCT, SCTLR_UCI, SCTLR_DZE, SCTLR_NTWE] {
            assert_ne!(SCTLR_EL1 & bit, 0);
        }
        for bit in [SCTLR_NTWI, SCTLR_A, SCTLR_E0E, SCTLR_UMA] {
            assert_eq!(SCTLR_EL1 & bit, 0);
        }
        assert_eq!(SCTLR_EL1, 0x34DC_D81D);
    }

    #[test]
    fn el0_gets_fp_and_the_virtual_counter_only() {
        assert_eq!(CPACR_EL1, 0x30_0000);
        assert_eq!(CNTKCTL_EL1, 0b10);
        assert_eq!(MDSCR_EL1, 0x1000);
    }

    #[test]
    fn a_pmu_is_one_of_the_architected_versions() {
        // PMUVer 1 is PMUv3, as on the Cortex-A53 and A72; later versions
        // count up from there.
        assert!(has_pmu(0x0100));
        assert!(has_pmu(0x0600));
        assert!(!has_pmu(0x0000));
        assert!(!has_pmu(0xF00));
        assert!(!has_pmu(0xFFFF_FFFF_FFFF_F0FF));
    }
}
