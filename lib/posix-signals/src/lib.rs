// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Ordinary process dispositions and per-thread signal masks/pending sets.
//! A single runtime owner serializes mutation; no user callback runs here.
#![no_std]
pub use posix_types::{SigAction, SigSet, constants::*};
pub const DEFAULT: u64 = 0;
pub const IGNORE: u64 = 1;
/// The signals 1 to 64: the ordinary ones, and the real-time signals from 32.
pub const VALID: SigSet = u64::MAX;
/// The highest signal number.
pub const SIGNAL_MAX: i32 = 64;
pub const UNBLOCKABLE: SigSet = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));
pub const FLAGS: i32 =
    SA_NODEFER | SA_RESETHAND | SA_SIGINFO | SA_RESTART | SA_NOCLDSTOP | SA_NOCLDWAIT | SA_ONSTACK;
pub const INITIAL: SigAction = SigAction {
    handler: DEFAULT,
    mask: 0,
    flags: 0,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    Signal,
    Flags,
    Mask,
    Handler,
}
pub fn bit(signal: i32) -> Result<SigSet, Invalid> {
    if !(1..=SIGNAL_MAX).contains(&signal) {
        return Err(Invalid::Signal);
    }
    Ok(1 << (signal - 1))
}
pub fn mask(set: SigSet) -> Result<SigSet, Invalid> {
    // Every bit of a set is a signal (1 to 64); SIGKILL and SIGSTOP cannot be held.
    Ok(set & VALID & !UNBLOCKABLE)
}
pub fn action_words(action: SigAction) -> [u64; 3] {
    [action.handler, action.mask, action.flags as u32 as u64]
}
pub fn action_from_words(words: [u64; 3]) -> SigAction {
    SigAction {
        handler: words[0],
        mask: words[1],
        flags: words[2] as u32 as i32,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    Ignore,
    Terminate,
    Stop,
    Continue,
}
pub fn default_action(signal: i32) -> DefaultAction {
    match signal {
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Continue,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        _ => DefaultAction::Terminate,
    }
}
pub struct Actions {
    values: [SigAction; 64],
}
impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}
impl Actions {
    pub const fn new() -> Self {
        Self {
            values: [INITIAL; 64],
        }
    }
    pub fn get(&self, signal: i32) -> Result<SigAction, Invalid> {
        bit(signal)?;
        Ok(self.values[signal as usize - 1])
    }
    pub fn replace(&mut self, signal: i32, action: SigAction) -> Result<SigAction, Invalid> {
        bit(signal)?;
        if signal == SIGKILL || signal == SIGSTOP {
            return Err(Invalid::Signal);
        }
        if action.flags & !FLAGS != 0 {
            return Err(Invalid::Flags);
        }
        if action.handler == u64::MAX {
            return Err(Invalid::Handler);
        }
        let action = SigAction {
            mask: mask(action.mask)?,
            ..action
        };
        let old = self.values[signal as usize - 1];
        self.values[signal as usize - 1] = action;
        Ok(old)
    }
    pub fn ignored(&self, signal: i32) -> bool {
        let action = self.values[signal as usize - 1];
        action.handler == IGNORE
            || (action.handler == DEFAULT && default_action(signal) == DefaultAction::Ignore)
    }
}
/// The signal a synchronous exception at EL0 stands for (XSH 2.4.3 and the
/// causes of `siginfo_t`): its number, `si_code` and `si_addr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub signal: i32,
    pub code: i32,
    pub address: u64,
}

/// The ISS bit of a trapped floating-point exception that says its cause
/// bits are valid (TFV).
const TFV: u64 = 1 << 23;

/// The signal of the exception with syndrome `esr`, the faulting address
/// `far` (0 where the exception sets none, spec 7.9), the interrupted PC
/// `pc` and the interrupted stack pointer `sp` (the address of a SIGBUS for a
/// misaligned stack pointer, whose exception sets no FAR). Aborts become SIGSEGV (a translation or address size fault
/// SEGV_MAPERR, an access flag or permission fault SEGV_ACCERR) or SIGBUS
/// (alignment, external abort); an undefined instruction and the rest of
/// the exceptions SIGILL; BRK, breakpoints and single steps SIGTRAP; a
/// trapped floating-point exception SIGFPE with the cause its ISS names, or
/// FPE_FLTINV when the ISS has no valid cause (TFV, bit 23, is clear: the
/// other bits are UNKNOWN then).
pub fn fault(esr: u64, far: u64, pc: u64, sp: u64) -> Fault {
    let class = (esr >> 26) & 0x3f;
    let status = esr & 0x3f;
    let (signal, code, address) = match class {
        0x20 | 0x24 => match status {
            0x00..=0x07 => (SIGSEGV, SEGV_MAPERR, far),
            0x09..=0x0b | 0x0d..=0x0f => (SIGSEGV, SEGV_ACCERR, far),
            0x21 => (SIGBUS, BUS_ADRALN, far),
            0x10 | 0x14..=0x17 | 0x18 | 0x1c..=0x1f => (SIGBUS, BUS_OBJERR, far),
            _ => (SIGSEGV, SEGV_MAPERR, far),
        },
        0x22 => (SIGBUS, BUS_ADRALN, far),
        0x26 => (SIGBUS, BUS_ADRALN, sp),
        0x2c => {
            let code = if esr & TFV == 0 {
                FPE_FLTINV
            } else if esr & 2 != 0 {
                FPE_FLTDIV
            } else if esr & 4 != 0 {
                FPE_FLTOVF
            } else if esr & 8 != 0 {
                FPE_FLTUND
            } else if esr & 16 != 0 {
                FPE_FLTRES
            } else {
                FPE_FLTINV
            };
            (SIGFPE, code, pc)
        }
        0x30 | 0x31 | 0x3c => (SIGTRAP, TRAP_BRKPT, pc),
        0x32 | 0x33 => (SIGTRAP, TRAP_TRACE, pc),
        0x34 | 0x35 => (SIGTRAP, TRAP_HWBKPT, far),
        0x07 => (SIGILL, ILL_COPROC, pc),
        _ => (SIGILL, ILL_ILLOPC, pc),
    };
    Fault {
        signal,
        code,
        address,
    }
}

#[derive(Clone, Copy)]
pub struct Thread {
    pub mask: SigSet,
    pending: SigSet,
    pub ready: bool,
}
impl Thread {
    pub const fn new(mask: SigSet) -> Self {
        Self {
            mask,
            pending: 0,
            ready: false,
        }
    }
    pub fn change_mask(&mut self, how: i32, set: Option<SigSet>) -> Result<SigSet, Invalid> {
        let old = self.mask;
        if let Some(set) = set {
            let set = mask(set)?;
            self.mask = match how {
                SIG_BLOCK => old | set,
                SIG_UNBLOCK => old & !set,
                SIG_SETMASK => set,
                _ => return Err(Invalid::Mask),
            };
        }
        Ok(old)
    }
    pub fn generate(&mut self, signal: i32, actions: &Actions) -> Result<(), Invalid> {
        let bit = bit(signal)?;
        if !actions.ignored(signal) {
            self.pending |= bit;
        }
        Ok(())
    }
    pub fn discard(&mut self, signal: i32) {
        self.pending &= !bit(signal).expect("validated signal");
    }
    pub fn pending(&self) -> SigSet {
        self.pending & self.mask
    }
    pub fn deliverable(&self) -> bool {
        self.ready && self.pending & !self.mask != 0
    }
    /// Atomically accept one pending signal without executing its disposition.
    /// The caller has blocked the requested set; acceptance preserves that mask.
    pub fn accept(&mut self, set: SigSet) -> Result<Option<i32>, Invalid> {
        let eligible = self.pending & mask(set)?;
        if eligible == 0 {
            return Ok(None);
        }
        let signal = eligible.trailing_zeros() as i32 + 1;
        self.discard(signal);
        Ok(Some(signal))
    }
    /// Copy the action and install its effective mask before executing user code.
    /// The dispatcher owns the saved old mask and restores it after the handler.
    pub fn take(&mut self, actions: &mut Actions) -> Option<(i32, SigAction)> {
        if !self.ready {
            return None;
        }
        loop {
            let eligible = self.pending & !self.mask;
            if eligible == 0 {
                return None;
            }
            let signal = eligible.trailing_zeros() as i32 + 1;
            self.discard(signal);
            if actions.ignored(signal) {
                continue;
            }
            let action = actions.get(signal).expect("pending signal");
            self.mask |= action.mask;
            if action.flags & SA_NODEFER == 0 {
                self.mask |= bit(signal).unwrap() & !UNBLOCKABLE;
            }
            if action.flags & SA_RESETHAND != 0 && signal != SIGILL && signal != SIGTRAP {
                actions.values[signal as usize - 1] = INITIAL;
            }
            return Some((signal, action));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn action_transport_preserves_upper_mask_bits_independently_of_flags() {
        // Transport supports future real-time bits; public policy still rejects
        // those numbers until queued delivery is implemented.
        let action = SigAction {
            handler: 0xffff_ffff_0000_1234,
            mask: 0x8000_0001_0000_0010,
            flags: SA_NODEFER | SA_RESETHAND,
        };
        assert_eq!(action_words(action), [action.handler, action.mask, 3]);
        assert_eq!(action_from_words(action_words(action)), action);
    }
    fn caught(flags: i32, mask: SigSet) -> SigAction {
        SigAction {
            handler: 0x1000,
            mask,
            flags,
        }
    }
    #[test]
    fn every_signal_bit_and_invalid_boundaries() {
        for signal in 1..=64 {
            assert_eq!(bit(signal), Ok(1 << (signal - 1)));
        }
        for signal in [i32::MIN, -1, 0, 65, i32::MAX] {
            assert_eq!(bit(signal), Err(Invalid::Signal));
        }
        assert_eq!(mask(VALID), Ok(VALID & !UNBLOCKABLE));
    }
    #[test]
    fn invalid_action_is_atomic_and_uncatchable_queries_work() {
        let mut actions = Actions::new();
        assert_eq!(actions.get(SIGKILL), Ok(INITIAL));
        for signal in [SIGKILL, SIGSTOP] {
            assert!(actions.replace(signal, caught(0, 0)).is_err());
        }
        for action in [
            caught(128, 0),
            SigAction {
                handler: u64::MAX,
                ..INITIAL
            },
        ] {
            assert!(actions.replace(SIGUSR1, action).is_err());
            assert_eq!(actions.get(SIGUSR1), Ok(INITIAL));
        }
        actions.replace(SIGUSR1, caught(0, UNBLOCKABLE)).unwrap();
        assert_eq!(actions.get(SIGUSR1).unwrap().mask, 0);
        assert_eq!(
            action_from_words(action_words(caught(FLAGS, VALID & !UNBLOCKABLE))),
            caught(FLAGS, VALID & !UNBLOCKABLE)
        );
    }
    #[test]
    fn masks_query_ignore_how_and_failed_updates_preserve_state() {
        let mut thread = Thread::new(0);
        let first = bit(SIGUSR1).unwrap();
        let second = bit(SIGUSR2).unwrap();
        assert_eq!(thread.change_mask(SIG_BLOCK, Some(first)), Ok(0));
        assert_eq!(thread.change_mask(-99, None), Ok(first));
        assert_eq!(thread.change_mask(-99, Some(second)), Err(Invalid::Mask));
        assert_eq!(thread.mask, first);
        assert_eq!(
            thread.change_mask(SIG_BLOCK, Some(second | UNBLOCKABLE)),
            Ok(first)
        );
        assert_eq!(thread.mask, first | second);
        thread.change_mask(SIG_UNBLOCK, Some(first)).unwrap();
        assert_eq!(thread.mask, second);
        thread.change_mask(SIG_SETMASK, Some(VALID)).unwrap();
        assert_eq!(thread.mask, VALID & !UNBLOCKABLE);
    }
    #[test]
    fn ordinary_duplicates_coalesce_and_inherited_mask_has_no_pending() {
        let mut actions = Actions::new();
        actions.replace(SIGUSR1, caught(0, 0)).unwrap();
        let mut parent = Thread::new(bit(SIGUSR1).unwrap());
        parent.ready = true;
        parent.generate(SIGUSR1, &actions).unwrap();
        parent.generate(SIGUSR1, &actions).unwrap();
        assert_eq!(parent.pending(), bit(SIGUSR1).unwrap());
        assert!(!parent.deliverable());
        let child = Thread::new(parent.mask);
        assert_eq!(child.pending(), 0);
        parent
            .change_mask(SIG_UNBLOCK, Some(bit(SIGUSR1).unwrap()))
            .unwrap();
        assert!(parent.deliverable());
        assert_eq!(parent.take(&mut actions), Some((SIGUSR1, caught(0, 0))));
        parent.mask = 0;
        assert_eq!(parent.take(&mut actions), None);
    }
    #[test]
    fn ignore_discards_pending_and_default_ignored_never_generates() {
        let mut actions = Actions::new();
        let mut thread = Thread::new(VALID & !UNBLOCKABLE);
        thread.ready = true;
        thread.generate(SIGUSR1, &actions).unwrap();
        actions
            .replace(
                SIGUSR1,
                SigAction {
                    handler: IGNORE,
                    ..INITIAL
                },
            )
            .unwrap();
        thread.discard(SIGUSR1);
        for signal in [SIGUSR1, SIGCHLD, SIGURG, SIGWINCH] {
            thread.generate(signal, &actions).unwrap();
        }
        assert_eq!(thread.pending(), 0);
    }
    #[test]
    fn nested_handler_mask_and_nodefer_are_distinct() {
        let mut actions = Actions::new();
        let mut thread = Thread::new(bit(SIGPIPE).unwrap());
        thread.ready = true;
        let action = caught(0, bit(SIGUSR2).unwrap());
        actions.replace(SIGUSR1, action).unwrap();
        thread.generate(SIGUSR1, &actions).unwrap();
        assert_eq!(thread.take(&mut actions), Some((SIGUSR1, action)));
        assert_eq!(
            thread.mask,
            bit(SIGPIPE).unwrap() | bit(SIGUSR1).unwrap() | bit(SIGUSR2).unwrap()
        );
        thread.generate(SIGUSR1, &actions).unwrap();
        assert_eq!(thread.take(&mut actions), None);
        thread.mask = 0;
        actions.replace(SIGUSR1, caught(SA_NODEFER, 0)).unwrap();
        thread.take(&mut actions).unwrap();
        assert_eq!(thread.mask, 0);
        thread.generate(SIGUSR1, &actions).unwrap();
        assert!(thread.take(&mut actions).is_some());
    }
    #[test]
    fn reset_is_visible_before_handler_and_ill_trap_keep_their_action() {
        let mut actions = Actions::new();
        let mut thread = Thread::new(0);
        thread.ready = true;
        for signal in [SIGUSR1, SIGILL, SIGTRAP] {
            actions
                .replace(signal, caught(SA_RESETHAND | SA_SIGINFO, 0))
                .unwrap();
            thread.mask = 0;
            thread.generate(signal, &actions).unwrap();
            thread.take(&mut actions).unwrap();
            assert_eq!(
                actions.get(signal).unwrap(),
                if signal == SIGUSR1 {
                    INITIAL
                } else {
                    caught(SA_RESETHAND | SA_SIGINFO, 0)
                }
            );
        }
    }
    #[test]
    fn ready_publication_does_not_lose_earlier_generation() {
        let mut actions = Actions::new();
        let mut thread = Thread::new(0);
        thread.generate(SIGUSR1, &actions).unwrap();
        assert_eq!(thread.take(&mut actions), None);
        thread.ready = true;
        assert!(thread.deliverable());
        assert!(thread.take(&mut actions).is_some());
        assert_eq!(default_action(SIGSTOP), DefaultAction::Stop);
        assert_eq!(default_action(SIGCONT), DefaultAction::Continue);
        assert_eq!(default_action(SIGTERM), DefaultAction::Terminate);
    }
}

#[cfg(test)]
mod accept_tests {
    use super::*;
    #[test]
    fn acceptance_preserves_masks_actions_and_other_pending_signals() {
        let mut actions = Actions::new();
        let action = SigAction {
            handler: 0x1000,
            flags: SA_RESETHAND,
            ..INITIAL
        };
        actions.replace(SIGUSR1, action).unwrap();
        let first = bit(SIGUSR1).unwrap();
        let second = bit(SIGUSR2).unwrap();
        let mut thread = Thread::new(first | second);
        // Synchronous acceptance does not depend on native readiness.
        thread.generate(SIGUSR1, &actions).unwrap();
        thread.generate(SIGUSR1, &actions).unwrap();
        thread.generate(SIGUSR2, &actions).unwrap();
        assert_eq!(thread.accept(first), Ok(Some(SIGUSR1)));
        assert_eq!(thread.mask, first | second);
        assert_eq!(thread.pending(), second);
        assert_eq!(actions.get(SIGUSR1), Ok(action));
        assert_eq!(thread.accept(first), Ok(None));
        assert_eq!(thread.accept(first | second), Ok(Some(SIGUSR2)));
        assert_eq!(thread.pending(), 0);
    }
    #[test]
    fn invalid_set_is_atomic_and_lowest_pending_bit_wins() {
        let actions = Actions::new();
        let set = bit(SIGUSR1).unwrap() | bit(SIGUSR2).unwrap();
        let mut thread = Thread::new(set);
        thread.generate(SIGUSR2, &actions).unwrap();
        thread.generate(SIGUSR1, &actions).unwrap();
        assert_eq!(thread.pending(), set);
        assert_eq!(thread.accept(0), Ok(None));
        assert_eq!(thread.accept(set | UNBLOCKABLE), Ok(Some(SIGUSR1)));
        assert_eq!(thread.accept(set), Ok(Some(SIGUSR2)));
        assert_eq!(thread.accept(set), Ok(None));
        assert_eq!(thread.mask, set);
    }
}

#[cfg(test)]
mod fault_tests {
    use super::*;
    const fn syndrome(class: u64, iss: u64) -> u64 {
        class << 26 | 1 << 25 | iss
    }
    #[test]
    fn aborts_become_segv_and_bus_with_the_address() {
        // Data abort from EL0 (0x24) with a translation fault at level 3,
        // a permission fault at level 3 and an alignment fault.
        let f = |class, status| fault(syndrome(class, status), 0x1234, 0x400, 0x7fff0);
        let expect = |signal, code| Fault {
            signal,
            code,
            address: 0x1234,
        };
        assert_eq!(f(0x24, 0x07), expect(SIGSEGV, SEGV_MAPERR));
        assert_eq!(f(0x20, 0x05), expect(SIGSEGV, SEGV_MAPERR));
        assert_eq!(f(0x24, 0x0f), expect(SIGSEGV, SEGV_ACCERR));
        assert_eq!(f(0x20, 0x0d), expect(SIGSEGV, SEGV_ACCERR));
        assert_eq!(f(0x24, 0x09), expect(SIGSEGV, SEGV_ACCERR));
        assert_eq!(f(0x24, 0x21), expect(SIGBUS, BUS_ADRALN));
        assert_eq!(f(0x24, 0x10), expect(SIGBUS, BUS_OBJERR));
        assert_eq!(f(0x22, 0), expect(SIGBUS, BUS_ADRALN));
        assert_eq!(
            fault(syndrome(0x26, 0), 0x77, 0x400, 0x7fff0),
            Fault {
                signal: SIGBUS,
                code: BUS_ADRALN,
                address: 0x7fff0
            }
        );
    }
    #[test]
    fn undefined_instruction_and_traps_name_their_pc() {
        let at_pc = |signal, code| Fault {
            signal,
            code,
            address: 0x400,
        };
        for class in [0x00, 0x01, 0x0e, 0x18] {
            assert_eq!(
                fault(syndrome(class, 0), 0x99, 0x400, 0x7fff0),
                at_pc(SIGILL, ILL_ILLOPC),
                "{class:#x}"
            );
        }
        assert_eq!(
            fault(syndrome(0x07, 0), 0, 0x400, 0x7fff0),
            at_pc(SIGILL, ILL_COPROC)
        );
        // BRK #5 and a software step.
        assert_eq!(
            fault(syndrome(0x3c, 5), 0, 0x400, 0x7fff0),
            at_pc(SIGTRAP, TRAP_BRKPT)
        );
        assert_eq!(
            fault(syndrome(0x32, 0), 0, 0x400, 0x7fff0),
            at_pc(SIGTRAP, TRAP_TRACE)
        );
    }
    #[test]
    fn a_trapped_float_exception_names_its_cause() {
        let f = |iss| fault(syndrome(0x2c, 1u64 << 23 | iss), 0, 0x400, 0x7fff0);
        assert_eq!((f(2).signal, f(2).code), (SIGFPE, FPE_FLTDIV));
        assert_eq!(f(4).code, FPE_FLTOVF);
        assert_eq!(f(8).code, FPE_FLTUND);
        assert_eq!(f(16).code, FPE_FLTRES);
        assert_eq!(f(1).code, FPE_FLTINV);
        // Division first when several bits are set.
        assert_eq!(f(2 | 4 | 16).code, FPE_FLTDIV);
    }
    #[test]
    fn a_float_trap_with_no_valid_cause_is_an_invalid_operation() {
        // TFV clear: the cause bits are UNKNOWN, whatever they hold.
        for iss in [0, 2, 4, 8, 16, 0x1f, 0x7f_ffff] {
            let fault = fault(syndrome(0x2c, iss), 0, 0x400, 0x7fff0);
            assert_eq!((fault.signal, fault.code), (SIGFPE, FPE_FLTINV), "{iss:#x}");
            assert_eq!(fault.address, 0x400);
        }
    }
}
