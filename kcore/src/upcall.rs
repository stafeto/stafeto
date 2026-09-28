// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Coalesced user entry requests; signal queues and dispositions live at EL0.
use abi::Error;

/// AArch64 EL0 flags: NZCV, TCO, DIT, SSBS and BTYPE. Mode and IRQ masks stay zero.
/// Field positions follow Arm Trusted Firmware include/arch/aarch64/arch.h.
pub const USER_PSTATE: u64 = 0xf300_1c00;
pub const BRANCH_TYPE: u64 = 0xc00;

/// A restored context can select only user execution and retain its kernel buffer.
pub fn validate_context(
    pc: u64,
    sp: u64,
    flags: u64,
    buffer: u64,
    expected: u64,
) -> Result<(), Error> {
    crate::args::check_start(pc, sp, 1)?;
    if flags & !USER_PSTATE != 0 || buffer != expected {
        return Err(Error::InvalidArgs);
    }
    Ok(())
}

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
    pub fn bind(&mut self, entry: u64) -> Result<(), Error> {
        if self.depth != 0 || self.deferred != 0 {
            return Err(Error::BadState);
        }
        crate::args::check_start(entry, 0, 1)?;
        *self = Self {
            entry,
            ..Self::new()
        };
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
    pub fn control(&mut self, operation: u64) -> Result<(u64, u64, u64), Error> {
        let was = u64::from(self.masked);
        match operation {
            0 => {
                self.masked = true;
                Ok((was, 0, 0))
            }
            1 if !self.entering => {
                self.masked = false;
                Ok((was, 0, 0))
            }
            2 if self.entering => {
                self.entering = false;
                Ok((was, self.pc, self.flags))
            }
            3 => {
                self.deferred = self.deferred.checked_add(1).ok_or(Error::NoMemory)?;
                Ok((was, 0, 0))
            }
            4 => {
                self.deferred = self.deferred.checked_sub(1).ok_or(Error::BadState)?;
                Ok((was, 0, 0))
            }
            1..=2 => Err(Error::BadState),
            _ => Err(Error::InvalidArgs),
        }
    }
    pub fn prepare(&mut self, pc: u64, flags: u64, long_call: bool) -> Option<u64> {
        if self.entry == 0
            || self.masked
            || self.deferred != 0
            || !self.pending
            || long_call
            || self.depth == u32::MAX
        {
            return None;
        }
        self.masked = true;
        self.pending = false;
        self.entering = true;
        self.pc = pc;
        self.flags = flags;
        self.depth += 1;
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
    #[test]
    fn restoration_rejects_privilege_interrupt_masks_and_foreign_buffer() {
        assert_eq!(
            validate_context(0x1000, 0x2000, 0xa000_0000, 0x3000, 0x3000),
            Ok(())
        );
        assert_eq!(
            validate_context(0x1000, 0x2000, USER_PSTATE, 0x3000, 0x3000),
            Ok(())
        );
        for flags in [5, 0x80, 0x200, 0x2000, 1 << 23, 1 << 63] {
            assert_eq!(
                validate_context(0x1000, 0x2000, flags, 0x3000, 0x3000),
                Err(Error::InvalidArgs)
            );
        }
        for (pc, sp) in [(0x1002, 0x2000), (1 << 63, 0x2000), (0x1000, 0x2008)] {
            assert_eq!(
                validate_context(pc, sp, 0, 0x3000, 0x3000),
                Err(Error::InvalidArgs)
            );
        }
        assert_eq!(
            validate_context(0x1000, 0x2000, 0, 0x4000, 0x3000),
            Err(Error::InvalidArgs)
        );
    }
    #[test]
    fn requests_wait_for_registration_enable_and_long_call_completion() {
        let mut state = State::new();
        assert_eq!(state.request(), Err(Error::BadState));
        state.bind(0x1000).unwrap();
        assert_eq!(state.request(), Ok(false));
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(1).unwrap();
        assert_eq!(state.prepare(0x2000, 0, true), None);
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
        assert_eq!(state.control(1), Err(Error::BadState));
        assert_eq!(state.control(2), Ok((1, 0x2000, 0)));
        state.returned().unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
    }
    #[test]
    fn nested_requests_keep_each_original_pc_and_coalesce_pending() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(1).unwrap();
        state.request().unwrap();
        state.request().unwrap();
        assert_eq!(state.prepare(0x2000, 0xa100_1000, false), Some(0x1000));
        assert_eq!(state.bind(0x3000), Err(Error::BadState));
        assert_eq!(state.returned(), Err(Error::BadState));
        assert_eq!(state.control(2), Ok((1, 0x2000, 0xa100_1000)));
        state.request().unwrap();
        state.request().unwrap();
        state.control(1).unwrap();
        assert_eq!(state.prepare(0x4000, 0x6300_0400, false), Some(0x1000));
        assert_eq!(state.control(2), Ok((1, 0x4000, 0x6300_0400)));
        state.returned().unwrap();
        state.control(0).unwrap();
        state.returned().unwrap();
        assert_eq!(state.prepare(0x5000, 0, false), None);
        state.bind(0).unwrap();
        assert_eq!(state.request(), Err(Error::BadState));
    }
    #[test]
    fn deferral_interrupts_waits_and_delivers_only_after_last_level() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(1).unwrap();
        state.control(3).unwrap();
        state.control(3).unwrap();
        assert_eq!(state.request(), Ok(true));
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, false), None);
        assert_eq!(state.bind(0), Err(Error::BadState));
        state.control(4).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(4).unwrap();
        assert!(!state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
        state.control(2).unwrap();
        state.control(3).unwrap();
        assert!(!state.can_return());
        assert_eq!(state.returned(), Err(Error::BadState));
        state.control(4).unwrap();
        state.returned().unwrap();
    }
    #[test]
    fn deferral_respects_mask_changes_and_rejects_unbalanced_control() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        assert_eq!(state.control(4), Err(Error::BadState));
        state.control(3).unwrap();
        assert_eq!(state.request(), Ok(false));
        assert!(!state.interrupt_wait());
        state.control(4).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(3).unwrap();
        state.control(1).unwrap();
        assert!(state.interrupt_wait());
        state.control(0).unwrap();
        state.control(4).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.control(1).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
    }
    #[test]
    fn deferral_overflow_preserves_state_and_pending_request() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.control(1).unwrap();
        state.request().unwrap();
        state.deferred = u32::MAX;
        assert_eq!(state.control(3), Err(Error::NoMemory));
        assert_eq!(state.deferred, u32::MAX);
        assert!(state.interrupt_wait());
        assert_eq!(state.prepare(0x2000, 0, false), None);
        state.deferred = 1;
        state.control(4).unwrap();
        assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
    }
    #[test]
    fn malformed_control_and_address_do_not_change_pending_state() {
        let mut state = State::new();
        state.bind(0x1000).unwrap();
        state.request().unwrap();
        assert_eq!(state.bind(0x1002), Err(Error::InvalidArgs));
        assert_eq!(state.control(5), Err(Error::InvalidArgs));
        assert_eq!(state.control(2), Err(Error::BadState));
        state.control(1).unwrap();
        assert_eq!(state.prepare(0, 0, false), Some(0x1000));
        assert_eq!(state.control(2), Ok((1, 0, 0)));
        state.returned().unwrap();
    }
}
