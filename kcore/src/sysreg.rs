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
pub const SCTLR_ITD: u64 = 1 << 7;
pub const SCTLR_SED: u64 = 1 << 8;
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
/// - nTWE: WFE at EL0, a spin-wait hint, does not trap;
/// - ITD and SED: the AArch32 IT and SETEND instructions at EL0 are
///   disabled. The kernel runs no AArch32 program; a processor without
///   AArch32 at EL0, such as Apple's under HVF, holds the bits at 1, and
///   the value then reads back the same on every machine.
///
/// nTWI stays clear, so WFI at EL0 traps: only the kernel puts the
/// processor to sleep. UMA stays clear: EL0 cannot mask interrupts.
/// Alignment checks (A) stay off, and EL0 data stays little-endian (E0E).
pub const SCTLR_EL1: u64 = SCTLR_EL1_BOOT
    | SCTLR_WXN
    | SCTLR_UCT
    | SCTLR_UCI
    | SCTLR_DZE
    | SCTLR_NTWE
    | SCTLR_ITD
    | SCTLR_SED;

/// CPACR_EL1.FPEN = 0b11: FP and SIMD instructions do not trap at EL0 or
/// EL1. The kernel is built without FP; only the thread switch touches
/// these registers, in assembly.
pub const CPACR_EL1: u64 = 0b11 << 20;

/// CNTKCTL_EL1.EL0VCTEN: EL0 reads CNTVCT_EL0 and CNTFRQ_EL0 (spec 10).
/// EL0PCTEN (bit 0), EL0VTEN (bit 8) and EL0PTEN (bit 9) stay clear: no
/// physical counter and no timer registers for programs.
///
/// EVNTEN with EVNTDIR 0 is the event stream: bit EVNTI of the virtual
/// counter rising sends an event every 2^(EVNTI+1) ticks. It bounds the sleep
/// of a `wfe` that waits for the lock OBJ (`sync::Ticket`) if its wake-up got
/// lost. `cntkctl_el1` takes EVNTI from the counter's frequency.
pub const CNTKCTL_EL1: u64 = (1 << 1) | CNTKCTL_EVNTEN;
const CNTKCTL_EVNTEN: u64 = 1 << 2;

/// The period of the event stream, about: 20 us.
const EVENT_PERIOD_HZ: u64 = 50_000;

/// CNTKCTL_EL1 for a counter of `frequency` Hz: EVNTI the largest bit whose
/// rise comes at most every 2^(EVNTI+1) ticks, 20 to 40 us, so that a lost
/// wake-up costs the same time on any board (EVNTI 8 at the 24 MHz of the
/// A64, 21 us; 10 at the 62.5 MHz of QEMU, 33 us).
pub const fn cntkctl_el1(frequency: u64) -> u64 {
    let ticks = frequency / EVENT_PERIOD_HZ;
    let evnti = if ticks < 2 { 0 } else { ticks.ilog2() as u64 };
    let evnti = if evnti > 15 { 15 } else { evnti };
    CNTKCTL_EL1 | evnti << 4
}

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
        assert_eq!(SCTLR_EL1, 0x34DC_D99D);
    }

    #[test]
    fn sctlr_keeps_aarch32_el0_instructions_off() {
        assert_eq!((SCTLR_ITD, SCTLR_SED), (0x80, 0x100));
        assert_eq!(SCTLR_EL1 & (SCTLR_ITD | SCTLR_SED), SCTLR_ITD | SCTLR_SED);
    }

    #[test]
    fn el0_gets_fp_and_the_virtual_counter_only() {
        assert_eq!(CPACR_EL1, 0x30_0000);
        assert_eq!(cntkctl_el1(24_000_000), 0b1000_0110);
        assert_eq!(MDSCR_EL1, 0x1000);
    }

    /// The event stream comes every 20 to 40 us whatever the frequency.
    #[test]
    fn the_event_stream_period_follows_the_counter() {
        for (hz, evnti) in [
            (24_000_000, 8),
            (62_500_000, 10),
            (1_000_000_000, 14),
            (19_200_000, 8),
        ] {
            assert_eq!(cntkctl_el1(hz) >> 4 & 0xf, evnti, "{hz} Hz");
            let period_ns = (2u64 << evnti) * 1_000_000_000 / hz;
            assert!(
                (20_000..40_000).contains(&period_ns),
                "{hz} Hz: {period_ns} ns"
            );
        }
        assert_eq!(cntkctl_el1(0) >> 4 & 0xf, 0);
        assert_eq!(cntkctl_el1(u64::MAX) >> 4 & 0xf, 15);
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
