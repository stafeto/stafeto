// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Coalesced user entry requests; signal queues and dispositions live at EL0.
use crate::layout::USER_END;
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
/// Besides the entry it keeps what only EL1 can give: the fault that
/// entered (ESR and FAR), the alternate stack the entry runs on, and the
/// stack pointer the entry interrupted.
#[derive(Debug)]
pub struct State {
    entry: u64,
    pc: u64,
    flags: u64,
    /// The stack pointer of the interrupted code, given back by `Take`.
    sp: u64,
    /// The alternate stack: `stack_size` bytes from `stack_base`, 0 for none.
    stack_base: u64,
    stack_size: u64,
    esr: u64,
    far: u64,
    depth: u32,
    deferred: u32,
    masked: bool,
    pending: bool,
    entering: bool,
    /// Whether a fault of the thread enters instead of ending its process.
    faults: bool,
    /// The entry that waits for `Take` is the fault of the code (the thread
    /// runs no code between the fault and the entry, so no other entry can
    /// come first).
    faulted: bool,
}
const _: () = assert!(core::mem::size_of::<State>() <= 80);

/// The values `thread_upcall_control` returns in x1 and up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    values: [u64; 5],
    len: usize,
}
impl Reply {
    /// The values `values` (at most five), the rest zero.
    #[inline(always)]
    pub const fn new<const N: usize>(values: [u64; N]) -> Self {
        const { assert!(N <= 5) };
        let mut all = [0; 5];
        let mut i = 0;
        while i < N {
            all[i] = values[i];
            i += 1;
        }
        Self {
            values: all,
            len: N,
        }
    }
    pub fn values(&self) -> &[u64] {
        &self.values[..self.len]
    }
    /// All five words, those past `len` zero.
    #[inline(always)]
    pub const fn words(&self) -> [u64; 5] {
        self.values
    }
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Bit 1 of the first value of `Take`: the entry is the fault of the
/// interrupted code, whose ESR and FAR `Query` gives.
pub const TAKE_FAULT: u64 = 2;

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
            sp: 0,
            stack_base: 0,
            stack_size: 0,
            esr: 0,
            far: 0,
            depth: 0,
            deferred: 0,
            masked: true,
            pending: false,
            entering: false,
            faults: false,
            faulted: false,
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
        self.faulted = false;
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
    /// `thread_upcall_control` with the parsed operation of x0 and the
    /// arguments x1 and x2.
    pub fn control(&mut self, operation: UpcallControl, x1: u64, x2: u64) -> Result<Reply, Error> {
        match operation {
            UpcallControl::Faults
            | UpcallControl::Stack
            | UpcallControl::Adopt
            | UpcallControl::Query => self.control_more(operation, x1, x2),
            _ => self.control_basic(operation),
        }
    }
    /// The five operations that need no argument: the entry of every signal
    /// makes some of them (S5 counts the instructions of that path).
    #[inline(always)]
    pub fn control_basic(&mut self, operation: UpcallControl) -> Result<Reply, Error> {
        let was = u64::from(self.masked);
        let plain = Reply::new([was, 0, 0]);
        match operation {
            UpcallControl::Mask => {
                self.masked = true;
                Ok(plain)
            }
            UpcallControl::Enable if !self.entering => {
                self.masked = false;
                Ok(plain)
            }
            UpcallControl::Take => self.take().map(Reply::new),
            UpcallControl::Defer => {
                self.deferred = self.deferred.checked_add(1).ok_or(Error::NoMemory)?;
                Ok(plain)
            }
            UpcallControl::Resume => {
                self.deferred = self.deferred.checked_sub(1).ok_or(Error::BadState)?;
                Ok(plain)
            }
            UpcallControl::Enable => Err(Error::BadState),
            _ => Err(Error::InvalidArgs),
        }
    }
    /// `Take`: the previous mask with `TAKE_FAULT` when a fault made the
    /// entry, the PC, the PSTATE and the SP the entry interrupted; BAD_STATE
    /// when no entry waits.
    #[inline(always)]
    pub fn take(&mut self) -> Result<[u64; 4], Error> {
        if !self.entering {
            return Err(Error::BadState);
        }
        self.entering = false;
        let fault = u64::from(self.faulted) * TAKE_FAULT;
        self.faulted = false;
        Ok([u64::from(self.masked) | fault, self.pc, self.flags, self.sp])
    }
    /// The operations 13 to 16, off the path of the five that a signal's
    /// entry makes (S5 counts its instructions).
    #[inline(never)]
    pub fn control_more(
        &mut self,
        operation: UpcallControl,
        x1: u64,
        x2: u64,
    ) -> Result<Reply, Error> {
        let was = u64::from(self.masked);
        let plain = Reply::new([was, 0, 0]);
        match operation {
            UpcallControl::Faults if x1 <= 1 => {
                self.faults = x1 == 1;
                Ok(plain)
            }
            UpcallControl::Stack => {
                self.set_stack(x1, x2)?;
                Ok(plain)
            }
            UpcallControl::Adopt => {
                self.adopt(x1, x2)?;
                Ok(plain)
            }
            UpcallControl::Query => Ok(Reply::new([
                was,
                self.esr,
                self.far,
                u64::from(self.depth),
                u64::from(self.deferred),
            ])),
            _ => Err(Error::InvalidArgs),
        }
    }
    /// The alternate stack of `size` bytes from `base`; size 0 removes it.
    /// Both are multiples of 16 and the stack lies in user space. Nothing
    /// maps it; whether the thread runs on it now is for the layer to see.
    fn set_stack(&mut self, base: u64, size: u64) -> Result<(), Error> {
        if size == 0 {
            self.stack_base = 0;
            self.stack_size = 0;
            return Ok(());
        }
        let end = base.checked_add(size).ok_or(Error::InvalidArgs)?;
        if !base.is_multiple_of(16) || !size.is_multiple_of(16) || end > USER_END as u64 {
            return Err(Error::InvalidArgs);
        }
        self.stack_base = base;
        self.stack_size = size;
        Ok(())
    }
    /// Takes over the nesting of the thread this one is a copy of (a child
    /// of `fork` made inside a handler): its depth and deferral count, as
    /// `Query` gave them. Only a thread that never entered, with its entry
    /// bound, takes them; the entry stays shut. The child's return from the
    /// handler then leaves the levels one by one.
    fn adopt(&mut self, depth: u64, deferred: u64) -> Result<(), Error> {
        if self.depth != 0 || self.entering || self.entry == 0 {
            return Err(Error::BadState);
        }
        let (Ok(depth), Ok(deferred)) = (u32::try_from(depth), u32::try_from(deferred)) else {
            return Err(Error::InvalidArgs);
        };
        self.depth = depth;
        self.deferred = deferred;
        self.masked = true;
        self.faulted = false;
        Ok(())
    }
    /// A fault of the code at EL0: whether it enters instead of ending the
    /// process. It does when the thread asked for faults, its entry is bound
    /// and open and no deferral holds it; ESR and FAR (0 where the fault
    /// sets none) wait for `Query`. A fault under a closed entry ends the
    /// process as before: the dispatcher itself faulted, and entering again
    /// would loop. So does a fault while a long call goes on: `prepare`
    /// refuses an entry then, the call returns to its own `svc`, and the
    /// thread would fault there for ever.
    pub fn fault(&mut self, esr: u64, far: u64, long_call: bool) -> bool {
        if !self.faults || self.entry == 0 || self.masked || self.deferred != 0 || long_call {
            return false;
        }
        self.esr = esr;
        self.far = far;
        self.pending = true;
        self.faulted = true;
        true
    }
    pub fn prepare(&mut self, pc: u64, flags: u64, sp: u64, long_call: bool) -> Option<u64> {
        if self.entry == 0 || self.masked || self.deferred != 0 || !self.pending || long_call {
            return None;
        }
        self.masked = true;
        self.pending = false;
        self.entering = true;
        self.pc = pc;
        self.flags = flags;
        self.sp = sp;
        // A handler that leaves its entry by a long jump never returns it:
        // the count stays at its top then, and entries go on (`can_return`
        // and `bind` only ask whether it is 0).
        self.depth = self.depth.saturating_add(1);
        Some(self.entry)
    }
    /// The top of the alternate stack when the entry just prepared must
    /// start there: the code it interrupts has its stack pointer outside
    /// the stack. Inside (bounds included) the entry goes on below the
    /// interrupted pointer, as a nested one does; without an alternate stack
    /// the pointer stays.
    #[inline(always)]
    pub fn alternate_sp(&self) -> Option<u64> {
        if self.stack_size != 0 && self.sp.wrapping_sub(self.stack_base) > self.stack_size {
            Some(self.stack_base + self.stack_size)
        } else {
            None
        }
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
    const FAULTS: UpcallControl = UpcallControl::Faults;
    const STACK: UpcallControl = UpcallControl::Stack;
    const ADOPT: UpcallControl = UpcallControl::Adopt;
    const QUERY: UpcallControl = UpcallControl::Query;
    const ESR_DABT: u64 = 0x9200_0004;
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
            state.control(ENABLE, 0, 0).unwrap();
            assert_eq!(state.request(), Ok(true));
            assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
            assert_eq!(state.control(TAKE, 0, 0), Ok(Reply::new([1, 0x2000, 0, 0])));
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
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.control(ENABLE, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, true), None);
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
        assert_eq!(state.control(ENABLE, 0, 0), Err(Error::BadState));
        assert_eq!(state.control(TAKE, 0, 0), Ok(Reply::new([1, 0x2000, 0, 0])));
        state.returned().unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
    }
    #[test]
    fn nested_requests_keep_each_original_pc_and_coalesce_pending() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.request().unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0xa100_1000, 0, false), Some(0x1000));
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        assert_eq!(state.returned(), Err(Error::BadState));
        assert_eq!(
            state.control(TAKE, 0, 0),
            Ok(Reply::new([1, 0x2000, 0xa100_1000, 0]))
        );
        state.request().unwrap();
        state.request().unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        assert_eq!(state.prepare(0x4000, 0x6300_0400, 0, false), Some(0x1000));
        assert_eq!(
            state.control(TAKE, 0, 0),
            Ok(Reply::new([1, 0x4000, 0x6300_0400, 0]))
        );
        state.returned().unwrap();
        state.control(MASK, 0, 0).unwrap();
        state.returned().unwrap();
        assert_eq!(state.prepare(0x5000, 0, 0, false), None);
        state.bind(0).unwrap();
        assert_eq!(state.request(), Err(Error::BadState));
    }
    #[test]
    fn deferral_interrupts_waits_and_delivers_only_after_last_level() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.control(DEFER, 0, 0).unwrap();
        state.control(DEFER, 0, 0).unwrap();
        assert_eq!(state.request(), Ok(true));
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.control(RESUME, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.control(RESUME, 0, 0).unwrap();
        assert!(!state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
        state.control(TAKE, 0, 0).unwrap();
        state.control(DEFER, 0, 0).unwrap();
        assert!(!state.can_return());
        assert_eq!(state.returned(), Err(Error::BadState));
        state.control(RESUME, 0, 0).unwrap();
        state.returned().unwrap();
    }
    #[test]
    fn deferral_respects_mask_changes_and_rejects_unbalanced_control() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        assert_eq!(state.control(RESUME, 0, 0), Err(Error::BadState));
        state.control(DEFER, 0, 0).unwrap();
        assert_eq!(state.request(), Ok(false));
        assert!(!state.interrupt_wait());
        state.control(RESUME, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.control(DEFER, 0, 0).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        assert!(state.interrupt_wait());
        state.control(MASK, 0, 0).unwrap();
        state.control(RESUME, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.control(ENABLE, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
    }
    #[test]
    fn deferral_overflow_preserves_state_and_pending_request() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.request().unwrap();
        state.deferred = u32::MAX;
        assert_eq!(state.control(DEFER, 0, 0), Err(Error::NoMemory));
        assert_eq!(state.deferred, u32::MAX);
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.deferred = 1;
        state.control(RESUME, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
    }
    #[test]
    fn malformed_control_and_address_do_not_change_pending_state() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.request().unwrap();
        assert_eq!(state.bind(0x1002), Err(Error::InvalidArgs));
        assert_eq!(state.control(TAKE, 0, 0), Err(Error::BadState));
        state.control(ENABLE, 0, 0).unwrap();
        assert_eq!(state.prepare(0, 0, 0, false), Some(0x1000));
        assert_eq!(state.control(TAKE, 0, 0), Ok(Reply::new([1, 0, 0, 0])));
        state.returned().unwrap();
    }
    /// The binding replaces the entry and nothing else: the deferral count
    /// of the thread's own sections stays (the rt used to lift it around the
    /// call), and the entry opens only after the last `Resume`.
    #[test]
    fn binding_under_deferral_keeps_the_count() {
        let mut state = State::new();
        state.control(DEFER, 0, 0).unwrap();
        state.control(DEFER, 0, 0).unwrap();
        state.bind(0x1000).unwrap();
        assert_eq!(state.control(MASK, 0, 0), Ok(Reply::new([1, 0, 0])));
        state.control(ENABLE, 0, 0).unwrap();
        assert_eq!(state.request(), Ok(true));
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.control(RESUME, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.control(RESUME, 0, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
        assert_eq!(state.control(RESUME, 0, 0), Err(Error::BadState));
        // A second binding drops the entry and the pending request; the debt stays.
        state.control(TAKE, 0, 0).unwrap();
        state.returned().unwrap();
        state.control(DEFER, 0, 0).unwrap();
        state.bind(0x3000).unwrap();
        assert_eq!(state.control(RESUME, 0, 0), Ok(Reply::new([1, 0, 0])));
        assert_eq!(state.control(RESUME, 0, 0), Err(Error::BadState));
    }
    /// Inside a handler, between its entry and its return, the entry cannot
    /// be replaced; after a long jump out of it (depth stays above 0) it
    /// cannot either, for the rest of the thread.
    #[test]
    fn binding_inside_a_handler_and_after_a_jump_is_refused() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
        // Entered, not yet taken.
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        state.control(TAKE, 0, 0).unwrap();
        // Taken, the handler runs.
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        assert_eq!(state.bind(0), Err(Error::BadState));
        // The handler leaves by a long jump: the thread unmasks, no return.
        state.control(ENABLE, 0, 0).unwrap();
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        // A later entry works, and the binding stays refused.
        state.request().unwrap();
        assert_eq!(state.prepare(0x4000, 0, 0, false), Some(0x1000));
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        // Returned from both levels the entry can be replaced again.
        state.control(TAKE, 0, 0).unwrap();
        state.returned().unwrap();
        state.control(MASK, 0, 0).unwrap();
        state.returned().unwrap();
        state.bind(0x3000).unwrap();
    }
    /// `Adopt` is for a thread that never entered and has its entry bound:
    /// a depth above 0 (an entry was made, even one left by a long jump)
    /// and a missing entry refuse it, and a refusal changes nothing.
    #[test]
    fn adopt_is_refused_at_a_depth_above_0_and_without_an_entry() {
        let mut state = State::new();
        assert_eq!(state.control(ADOPT, 1, 0), Err(Error::BadState));
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
        // Entered, not taken: the entry waits for Take.
        assert_eq!(state.control(ADOPT, 1, 0), Err(Error::BadState));
        state.control(TAKE, 0, 0).unwrap();
        assert_eq!(state.control(ADOPT, 1, 0), Err(Error::BadState));
        assert_eq!(state.depth, 1);
        assert_eq!(state.deferred, 0);
        // Left by a long jump: the depth stays above 0 and so does the refusal.
        state.control(ENABLE, 0, 0).unwrap();
        assert_eq!(state.control(ADOPT, 0, 0), Err(Error::BadState));
    }
    /// The child of a `fork` inside a handler takes the nesting of the
    /// parent: it returns once per level, and its entry is shut until then.
    #[test]
    fn adopt_takes_the_parents_nesting_and_leaves_the_entry_shut() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.request().unwrap();
        assert_eq!(
            state.control(ADOPT, 1 << 32, 0),
            Err(Error::InvalidArgs),
            "a depth past 32 bits"
        );
        assert_eq!(state.control(ADOPT, 0, 1 << 32), Err(Error::InvalidArgs));
        assert_eq!(state.control(ADOPT, 2, 1), Ok(Reply::new([0, 0, 0])));
        assert_eq!(state.control(QUERY, 0, 0), Ok(Reply::new([1, 0, 0, 2, 1])));
        // Shut, nothing pending: no entry comes, and the deferral holds the return.
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        assert_eq!(state.returned(), Err(Error::BadState));
        state.control(RESUME, 0, 0).unwrap();
        state.returned().unwrap();
        state.control(MASK, 0, 0).unwrap();
        state.returned().unwrap();
        // Out of the last level the thread binds again.
        assert_eq!(state.returned(), Err(Error::BadState));
        state.bind(0x3000).unwrap();
    }
    /// A fault enters only when the thread asked for it and its entry is
    /// bound, open and not deferred; any other fault ends the process.
    #[test]
    fn a_fault_enters_only_an_open_entry_that_asked_for_faults() {
        let mut state = State::new();
        // Faults is off at the start.
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        assert!(!state.fault(ESR_DABT, 0x10, false));
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        assert_eq!(state.control(FAULTS, 2, 0), Err(Error::InvalidArgs));
        assert_eq!(state.control(FAULTS, 1, 0), Ok(Reply::new([0, 0, 0])));
        // Masked: the dispatcher faulted.
        state.control(MASK, 0, 0).unwrap();
        assert!(!state.fault(ESR_DABT, 0x10, false));
        state.control(ENABLE, 0, 0).unwrap();
        state.control(DEFER, 0, 0).unwrap();
        assert!(!state.fault(ESR_DABT, 0x10, false));
        state.control(RESUME, 0, 0).unwrap();
        // Open: the entry comes with no request.
        assert!(state.fault(ESR_DABT, 0x10, false));
        assert_eq!(
            state.prepare(0x2000, 0xa000_0000, 0x7000, false),
            Some(0x1000)
        );
        assert_eq!(
            state.control(TAKE, 0, 0),
            Ok(Reply::new([1 | TAKE_FAULT, 0x2000, 0xa000_0000, 0x7000]))
        );
        assert_eq!(
            state.control(QUERY, 0, 0),
            Ok(Reply::new([1, ESR_DABT, 0x10, 1, 0]))
        );
        // A request after it is no fault, and the last fault stays in Query.
        state.control(MASK, 0, 0).unwrap();
        state.returned().unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
        assert_eq!(state.control(TAKE, 0, 0), Ok(Reply::new([1, 0x2000, 0, 0])));
        assert_eq!(state.control(QUERY, 0, 0).unwrap().values()[1], ESR_DABT);
        // Turned off again, and with no entry at all.
        state.control(MASK, 0, 0).unwrap();
        state.returned().unwrap();
        state.control(FAULTS, 0, 0).unwrap();
        assert!(!state.fault(ESR_DABT, 0, false));
        let mut bare = State::new();
        bare.control(FAULTS, 1, 0).unwrap();
        bare.control(ENABLE, 0, 0).unwrap();
        assert!(!bare.fault(ESR_DABT, 0, false));
    }
    /// A new binding forgets a fault no entry has taken.
    #[test]
    fn binding_drops_a_fault_that_waits() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(FAULTS, 1, 0).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        assert!(state.fault(ESR_DABT, 0, false));
        state.bind(0x3000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x3000));
        assert_eq!(state.control(TAKE, 0, 0).unwrap().values()[0], 1);
    }
    #[test]
    fn the_alternate_stack_is_checked_and_removed_by_size_0() {
        let mut state = State::new();
        let top = USER_END as u64;
        for (base, size) in [
            (0x1008, 0x1000),
            (0x1000, 0x1008),
            (top - 0x1000, 0x2000),
            (u64::MAX - 15, 32),
            (top, 16),
        ] {
            assert_eq!(
                state.control(STACK, base, size),
                Err(Error::InvalidArgs),
                "{base:#x} {size:#x}"
            );
        }
        assert_eq!(state.stack_size, 0);
        assert_eq!(
            state.control(STACK, top - 0x1000, 0x1000),
            Ok(Reply::new([1, 0, 0]))
        );
        assert_eq!(state.stack_size, 0x1000);
        state.control(STACK, 0x9990, 0).unwrap();
        assert_eq!((state.stack_base, state.stack_size), (0, 0));
    }
    /// An entry starts at the top of the alternate stack unless the code it
    /// interrupts runs on it; `Take` gives the interrupted pointer either way.
    #[test]
    fn an_entry_runs_on_the_alternate_stack_unless_it_interrupts_it() {
        let (base, size) = (0x10_0000, 0x4000);
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        // No stack: the interrupted pointer stays.
        state.request().unwrap();
        state.prepare(0x2000, 0, 0x7fff0, false).unwrap();
        assert_eq!(state.alternate_sp(), None);
        state.control(TAKE, 0, 0).unwrap();
        state.control(STACK, base, size).unwrap();
        for (sp, want) in [
            (0x7fff0, base + size),
            (base - 16, base + size),
            (base + size + 16, base + size),
            (0, base + size),
            // On the stack, bounds included: the entry goes on below.
            (base, base),
            (base + 0x2230, base + 0x2230),
            (base + size, base + size),
        ] {
            state.control(ENABLE, 0, 0).unwrap();
            state.request().unwrap();
            state.prepare(0x2000, 0, sp, false).unwrap();
            assert_eq!(state.alternate_sp().unwrap_or(sp), want, "sp {sp:#x}");
            assert_eq!(state.control(TAKE, 0, 0).unwrap().values()[3], sp);
            state.control(MASK, 0, 0).unwrap();
            state.returned().unwrap();
        }
    }
    /// Space for the state of the entry in a thread: 80 bytes since the fault
    /// and the stack.
    #[test]
    fn the_state_takes_80_bytes() {
        assert_eq!(core::mem::size_of::<State>(), 80);
    }
    /// A request that came between the binding and `Adopt` stays: the entry
    /// is shut, and the first return opens it for the request.
    #[test]
    fn adopt_keeps_a_request_that_came_before() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        state.request().unwrap();
        state.control(ADOPT, 1, 0).unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        state.returned().unwrap();
        assert_eq!(state.prepare(0x2000, 0, 0, false), Some(0x1000));
    }
    /// A fault during a long call ends the process: the call returns to its
    /// own `svc`, no entry can come, and the thread would fault there for ever.
    #[test]
    fn a_fault_during_a_long_call_does_not_enter() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(FAULTS, 1, 0).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        assert!(!state.fault(ESR_DABT, 0x10, true));
        assert_eq!(state.prepare(0x2000, 0, 0, false), None);
        assert!(state.fault(ESR_DABT, 0x10, false));
    }
    /// A fault inside the handler of a fault, once the handler opened its
    /// entry, enters at depth 2 and gives its own ESR and FAR to `Query`.
    #[test]
    fn a_nested_fault_gives_its_own_cause() {
        const ESR_UDF: u64 = 0x0200_0000;
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(FAULTS, 1, 0).unwrap();
        state.control(ENABLE, 0, 0).unwrap();
        assert!(state.fault(ESR_DABT, 0x10, false));
        assert_eq!(state.prepare(0x2000, 0, 0x7000, false), Some(0x1000));
        assert_eq!(
            state.control(TAKE, 0, 0).unwrap().values()[0],
            1 | TAKE_FAULT
        );
        state.control(ENABLE, 0, 0).unwrap();
        assert!(state.fault(ESR_UDF, 0, false));
        assert_eq!(state.prepare(0x3000, 0, 0x6000, false), Some(0x1000));
        assert_eq!(
            state.control(TAKE, 0, 0),
            Ok(Reply::new([1 | TAKE_FAULT, 0x3000, 0, 0x6000]))
        );
        assert_eq!(
            state.control(QUERY, 0, 0),
            Ok(Reply::new([1, ESR_UDF, 0, 2, 0]))
        );
        state.control(MASK, 0, 0).unwrap();
        state.returned().unwrap();
        assert_eq!(state.control(QUERY, 0, 0).unwrap().values()[3], 1);
    }
}
