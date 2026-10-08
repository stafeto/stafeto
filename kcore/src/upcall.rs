// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Coalesced user entry requests; signal queues and dispositions live at EL0.
use abi::{Error, UpcallControl};

/// AArch64 EL0 flags: NZCV, TCO, DIT, SSBS and BTYPE. Mode and IRQ masks stay zero.
/// Field positions follow Arm Trusted Firmware include/arch/aarch64/arch.h.
pub const USER_PSTATE: u64 = NZCV | TCO | DIT | SSBS | BRANCH_TYPE;
pub const NZCV: u64 = 0xf000_0000;
pub const TCO: u64 = 1 << 25;
pub const DIT: u64 = 1 << 24;
pub const SSBS: u64 = 1 << 12;
pub const BRANCH_TYPE: u64 = 0xc00;

/// The EL0 flags this processor implements, from ID_AA64PFR0_EL1 and
/// ID_AA64PFR1_EL1: NZCV always; DIT with PFR0.DIT [51:48], TCO with
/// PFR1.MTE [11:8], SSBS with PFR1.SSBS [7:4] and BTYPE with PFR1.BT
/// [3:0] not zero. On an ARMv8.0 core such as the Cortex-A53 the other
/// four are RES0 in SPSR_EL1, so a restored context may not set them.
pub const fn user_pstate(pfr0: u64, pfr1: u64) -> u64 {
    const fn has(register: u64, shift: u32) -> bool {
        (register >> shift) & 0xf != 0
    }
    let mut flags = NZCV;
    if has(pfr0, 48) {
        flags |= DIT;
    }
    if has(pfr1, 8) {
        flags |= TCO;
    }
    if has(pfr1, 4) {
        flags |= SSBS;
    }
    if has(pfr1, 0) {
        flags |= BRANCH_TYPE;
    }
    flags
}

/// A restored context can select only user execution with the flags the
/// processor implements (`allowed`, from `user_pstate`) and retain its
/// kernel buffer.
pub fn validate_context(
    pc: u64,
    sp: u64,
    flags: u64,
    allowed: u64,
    buffer: u64,
    expected: u64,
) -> Result<(), Error> {
    crate::args::check_start(pc, sp, 1)?;
    if flags & !(allowed & USER_PSTATE) != 0 || buffer != expected {
        return Err(Error::InvalidArgs);
    }
    Ok(())
}

/// The state of the one entry of a thread. Everything above this single
/// lane lives at EL0 (`rt`, relibc): the order of several handlers, nesting
/// and the reset after a long jump (design note "what cannot move out").
#[derive(Debug)]
pub struct State {
    entry: u64,
    pc: u64,
    flags: u64,
    depth: u32,
    deferred: u32,
    masked: bool,
    pending: bool,
    entering: bool,
}
const _: () = assert!(core::mem::size_of::<State>() <= 40);
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub const fn new() -> Self {
        Self {
            entry: 0,
            pc: 0,
            flags: 0,
            depth: 0,
            deferred: 0,
            masked: true,
            pending: false,
            entering: false,
        }
    }
    /// Replace the entry: masked, nothing pending. Refused inside a handler
    /// (`entering` implies a depth above 0) and after one was left by a long
    /// jump (the depth stays above 0; `rt` binds once per thread). The
    /// deferral count belongs to the thread's own sections and survives.
    pub fn bind(&mut self, entry: u64) -> Result<(), Error> {
        if self.depth != 0 {
            return Err(Error::BadState);
        }
        crate::args::check_start(entry, 0, 1)?;
        self.entry = entry;
        self.masked = true;
        self.pending = false;
        Ok(())
    }
    /// Return whether an existing IPC wait should be interrupted now.
    pub fn request(&mut self) -> Result<bool, Error> {
        if self.entry == 0 {
            return Err(Error::BadState);
        }
        self.pending = true;
        Ok(!self.masked)
    }
    /// `thread_upcall_control` with the parsed operation of x0.
    pub fn control(&mut self, operation: UpcallControl) -> Result<(u64, u64, u64), Error> {
        let was = u64::from(self.masked);
        match operation {
            UpcallControl::Mask => {
                self.masked = true;
                Ok((was, 0, 0))
            }
            UpcallControl::Enable if !self.entering => {
                self.masked = false;
                Ok((was, 0, 0))
            }
            UpcallControl::Take if self.entering => {
                self.entering = false;
                Ok((was, self.pc, self.flags))
            }
            UpcallControl::Defer => {
                self.deferred = self.deferred.checked_add(1).ok_or(Error::NoMemory)?;
                Ok((was, 0, 0))
            }
            UpcallControl::Resume => {
                self.deferred = self.deferred.checked_sub(1).ok_or(Error::BadState)?;
                Ok((was, 0, 0))
            }
            UpcallControl::Enable | UpcallControl::Take => Err(Error::BadState),
        }
    }
    pub fn prepare(&mut self, pc: u64, flags: u64, long_call: bool) -> Option<u64> {
        if self.entry == 0 || self.masked || self.deferred != 0 || !self.pending || long_call {
            return None;
        }
        self.masked = true;
        self.pending = false;
        self.entering = true;
        self.pc = pc;
        self.flags = flags;
        // A handler that leaves its entry by a long jump never returns it:
        // the count stays at its top then, and entries go on (`can_return`
        // and `bind` only ask whether it is 0).
        self.depth = self.depth.saturating_add(1);
        Some(self.entry)
    }
    /// A request deferred by an internal borrow must not strand a new wait.
    pub fn interrupt_wait(&self) -> bool {
        self.deferred != 0 && self.pending && !self.masked
    }
    pub fn can_return(&self) -> bool {
        self.depth != 0 && self.deferred == 0 && self.masked && !self.entering
    }
    pub fn returned(&mut self) -> Result<(), Error> {
        if !self.can_return() {
            return Err(Error::BadState);
        }
        self.depth -= 1;
        self.masked = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MASK: UpcallControl = UpcallControl::Mask;
    const ENABLE: UpcallControl = UpcallControl::Enable;
    const TAKE: UpcallControl = UpcallControl::Take;
    const DEFER: UpcallControl = UpcallControl::Defer;
    const RESUME: UpcallControl = UpcallControl::Resume;
    #[test]
    fn restoration_rejects_privilege_interrupt_masks_and_foreign_buffer() {
        let check =
            |pc, sp, flags, buffer| validate_context(pc, sp, flags, USER_PSTATE, buffer, 0x3000);
        assert_eq!(check(0x1000, 0x2000, 0xa000_0000, 0x3000), Ok(()));
        assert_eq!(check(0x1000, 0x2000, USER_PSTATE, 0x3000), Ok(()));
        for flags in [5, 0x80, 0x200, 0x2000, 1 << 23, 1 << 63] {
            assert_eq!(
                check(0x1000, 0x2000, flags, 0x3000),
                Err(Error::InvalidArgs)
            );
        }
        for (pc, sp) in [(0x1002, 0x2000), (1 << 63, 0x2000), (0x1000, 0x2008)] {
            assert_eq!(check(pc, sp, 0, 0x3000), Err(Error::InvalidArgs));
        }
        assert_eq!(check(0x1000, 0x2000, 0, 0x4000), Err(Error::InvalidArgs));
    }
    #[test]
    fn restoration_keeps_unimplemented_flags_zero() {
        // QEMU's cortex-a53 and cortex-a72: ARMv8.0, PFR0 0x2222, PFR1 0.
        let a53 = user_pstate(0x2222, 0);
        assert_eq!(a53, NZCV);
        for flag in [TCO, DIT, SSBS, 1 << 10, 1 << 11] {
            assert_eq!(
                validate_context(0x1000, 0x2000, flag, a53, 0x3000, 0x3000),
                Err(Error::InvalidArgs),
                "{flag:#x}"
            );
        }
        assert_eq!(
            validate_context(0x1000, 0x2000, NZCV, a53, 0x3000, 0x3000),
            Ok(())
        );
        // Each feature field enables its flags alone.
        assert_eq!(user_pstate(1 << 48, 0), NZCV | DIT);
        assert_eq!(user_pstate(0, 1 << 8), NZCV | TCO);
        assert_eq!(user_pstate(0, 2 << 4), NZCV | SSBS);
        assert_eq!(user_pstate(0, 1), NZCV | BRANCH_TYPE);
        assert_eq!(user_pstate(u64::MAX, u64::MAX), USER_PSTATE);
    }
    /// 2^32 entries left by long jumps (half an hour of them on HVF) do
    /// not shut the entry: the depth stops at its top.
    #[test]
    fn entries_left_by_long_jumps_do_not_shut_the_entry() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.depth = u32::MAX - 1;
        for _ in 0..3 {
            state.control(ENABLE).unwrap();
            assert_eq!(state.request(), Ok(true));
            assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
            assert_eq!(state.control(TAKE), Ok((1, 0x2000, 0)));
            // The handler jumps out: the thread unmasks with no return.
        }
        assert_eq!(state.depth, u32::MAX);
        assert!(state.can_return());
        state.returned().unwrap();
        assert_eq!(state.depth, u32::MAX - 1);
    }
    #[test]
    fn requests_wait_for_registration_enable_and_long_call_completion() {
        let mut state = State::new();
        assert_eq!(state.request(), Err(Error::BadState));
        state.bind(0x1000).unwrap();
        assert_eq!(state.request(), Ok(false));
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(ENABLE).unwrap();
        assert_eq!(state.prepare(0x2000, 0, true), None);
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
        assert_eq!(state.control(ENABLE), Err(Error::BadState));
        assert_eq!(state.control(TAKE), Ok((1, 0x2000, 0)));
        state.returned().unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
    }
    #[test]
    fn nested_requests_keep_each_original_pc_and_coalesce_pending() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE).unwrap();
        state.request().unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0xa100_1000, false), Some(0x1000));
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        assert_eq!(state.returned(), Err(Error::BadState));
        assert_eq!(state.control(TAKE), Ok((1, 0x2000, 0xa100_1000)));
        state.request().unwrap();
        state.request().unwrap();
        state.control(ENABLE).unwrap();
        assert_eq!(state.prepare(0x4000, 0x6300_0400, false), Some(0x1000));
        assert_eq!(state.control(TAKE), Ok((1, 0x4000, 0x6300_0400)));
        state.returned().unwrap();
        state.control(MASK).unwrap();
        state.returned().unwrap();
        assert_eq!(state.prepare(0x5000, 0, false), None);
        state.bind(0).unwrap();
        assert_eq!(state.request(), Err(Error::BadState));
    }
    #[test]
    fn deferral_interrupts_waits_and_delivers_only_after_last_level() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE).unwrap();
        state.control(DEFER).unwrap();
        state.control(DEFER).unwrap();
        assert_eq!(state.request(), Ok(true));
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(RESUME).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(RESUME).unwrap();
        assert!(!state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
        state.control(TAKE).unwrap();
        state.control(DEFER).unwrap();
        assert!(!state.can_return());
        assert_eq!(state.returned(), Err(Error::BadState));
        state.control(RESUME).unwrap();
        state.returned().unwrap();
    }
    #[test]
    fn deferral_respects_mask_changes_and_rejects_unbalanced_control() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        assert_eq!(state.control(RESUME), Err(Error::BadState));
        state.control(DEFER).unwrap();
        assert_eq!(state.request(), Ok(false));
        assert!(!state.interrupt_wait());
        state.control(RESUME).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(DEFER).unwrap();
        state.control(ENABLE).unwrap();
        assert!(state.interrupt_wait());
        state.control(MASK).unwrap();
        state.control(RESUME).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(ENABLE).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
    }
    #[test]
    fn deferral_overflow_preserves_state_and_pending_request() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE).unwrap();
        state.request().unwrap();
        state.deferred = u32::MAX;
        assert_eq!(state.control(DEFER), Err(Error::NoMemory));
        assert_eq!(state.deferred, u32::MAX);
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.deferred = 1;
        state.control(RESUME).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
    }
    #[test]
    fn malformed_control_and_address_do_not_change_pending_state() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.request().unwrap();
        assert_eq!(state.bind(0x1002), Err(Error::InvalidArgs));
        assert_eq!(state.control(TAKE), Err(Error::BadState));
        state.control(ENABLE).unwrap();
        assert_eq!(state.prepare(0, 0, false), Some(0x1000));
        assert_eq!(state.control(TAKE), Ok((1, 0, 0)));
        state.returned().unwrap();
    }
    /// The binding replaces the entry and nothing else: the deferral count
    /// of the thread's own sections stays (the rt used to lift it around the
    /// call), and the entry opens only after the last `Resume`.
    #[test]
    fn binding_under_deferral_keeps_the_count() {
        let mut state = State::new();
        state.control(DEFER).unwrap();
        state.control(DEFER).unwrap();
        state.bind(0x1000).unwrap();
        assert_eq!(state.control(MASK), Ok((1, 0, 0)));
        state.control(ENABLE).unwrap();
        assert_eq!(state.request(), Ok(true));
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(RESUME).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(RESUME).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
        assert_eq!(state.control(RESUME), Err(Error::BadState));
        // A second binding drops the entry and the pending request, not the debt.
        state.control(TAKE).unwrap();
        state.returned().unwrap();
        state.control(DEFER).unwrap();
        state.bind(0x3000).unwrap();
        assert_eq!(state.control(RESUME), Ok((1, 0, 0)));
        assert_eq!(state.control(RESUME), Err(Error::BadState));
    }
    /// Inside a handler, between its entry and its return, the entry cannot
    /// be replaced; after a long jump out of it (depth stays above 0) it
    /// cannot either, for the rest of the thread.
    #[test]
    fn binding_inside_a_handler_and_after_a_jump_is_refused() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE).unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
        // Entered, not yet taken.
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        state.control(TAKE).unwrap();
        // Taken, the handler runs.
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        assert_eq!(state.bind(0), Err(Error::BadState));
        // The handler leaves by a long jump: the thread unmasks, no return.
        state.control(ENABLE).unwrap();
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        // A later entry works, and the binding stays refused.
        state.request().unwrap();
        assert_eq!(state.prepare(0x4000, 0, false), Some(0x1000));
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        // Returned from both levels the entry can be replaced again.
        state.control(TAKE).unwrap();
        state.returned().unwrap();
        state.control(MASK).unwrap();
        state.returned().unwrap();
        state.bind(0x3000).unwrap();
    }
}
