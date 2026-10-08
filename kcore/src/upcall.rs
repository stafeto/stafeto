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

#[derive(Debug, Clone, Copy)]
struct Lane {
    entry: u64,
    depth: u32,
    masked: bool,
    pending: bool,
    entering: bool,
}
impl Lane {
    const fn new(entry: u64) -> Self {
        Self {
            entry,
            depth: 0,
            masked: true,
            pending: false,
            entering: false,
        }
    }
}

/// One selected entry; an observer installs its resident TLS for dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub pc: u64,
    pub tls: Option<u64>,
}

#[derive(Debug)]
pub struct State {
    primary: Lane,
    observer: Lane,
    pc: u64,
    flags: u64,
    observer_tls: u64,
    interrupted_tls: u64,
    deferred: u32,
    next_observer: bool,
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub const fn new() -> Self {
        Self {
            primary: Lane::new(0),
            observer: Lane::new(0),
            pc: 0,
            flags: 0,
            observer_tls: 0,
            interrupted_tls: 0,
            deferred: 0,
            next_observer: false,
        }
    }
    pub fn bind(&mut self, entry: u64) -> Result<(), Error> {
        if self.primary.depth != 0 || self.deferred != 0 {
            return Err(Error::BadState);
        }
        crate::args::check_start(entry, 0, 1)?;
        self.primary = Lane::new(entry);
        Ok(())
    }
    /// Install the current thread's observer while both entries are deferred.
    pub fn bind_observer(&mut self, entry: u64, tls: u64) -> Result<(), Error> {
        if self.observer.depth != 0 || self.observer.entering {
            return Err(Error::BadState);
        }
        if (entry == 0) != (tls == 0) {
            return Err(Error::InvalidArgs);
        }
        crate::args::check_start(entry, tls, 1)?;
        self.observer = Lane::new(entry);
        self.observer_tls = tls;
        Ok(())
    }
    fn request_lane(&mut self, observer: bool) -> Result<bool, Error> {
        let available = observer || self.observer.depth == 0;
        let lane = if observer {
            &mut self.observer
        } else {
            &mut self.primary
        };
        if lane.entry == 0 {
            return Err(Error::BadState);
        }
        lane.pending = true;
        Ok(!lane.masked && available)
    }
    /// Preserve the native request and its coalesced pending state.
    pub fn request(&mut self) -> Result<bool, Error> {
        self.request_lane(false)
    }
    /// Prefer the resident observer; a thread without one uses its native entry.
    pub fn request_layer(&mut self) -> Result<bool, Error> {
        self.request_lane(self.observer.entry != 0)
    }
    fn active_observer(&self) -> bool {
        self.observer.depth != 0
    }
    pub fn interrupted_tls(&self) -> u64 {
        self.interrupted_tls
    }
    /// Old operations keep their native result span and share entry deferral.
    pub fn control(&mut self, operation: u64) -> Result<(u64, u64, u64), Error> {
        let op = UpcallControl::from_raw(operation).ok_or(Error::InvalidArgs)?;
        let observer = matches!(
            op,
            UpcallControl::ObserverMask
                | UpcallControl::ObserverEnable
                | UpcallControl::ObserverTake
        );
        let was = u64::from(if observer {
            self.observer.masked
        } else {
            self.primary.masked
        });
        match op {
            UpcallControl::Defer => {
                self.deferred = self.deferred.checked_add(1).ok_or(Error::NoMemory)?;
                return Ok((was, 0, 0));
            }
            UpcallControl::Resume => {
                self.deferred = self.deferred.checked_sub(1).ok_or(Error::BadState)?;
                return Ok((was, 0, 0));
            }
            UpcallControl::ObserverBind | UpcallControl::LayerRequest => {
                return Err(Error::InvalidArgs);
            }
            _ => {}
        }
        let active = self.active_observer();
        let lane = if observer {
            &mut self.observer
        } else {
            &mut self.primary
        };
        match op {
            UpcallControl::Mask | UpcallControl::ObserverMask => lane.masked = true,
            UpcallControl::Enable | UpcallControl::ObserverEnable if !lane.entering => {
                lane.masked = false
            }
            UpcallControl::Take | UpcallControl::ObserverTake
                if lane.entering && observer == active =>
            {
                lane.entering = false;
                return Ok((was, self.pc, self.flags));
            }
            _ => return Err(Error::BadState),
        }
        Ok((was, 0, 0))
    }
    /// Native compatibility helper; real delivery also captures interrupted TLS.
    pub fn prepare(&mut self, pc: u64, flags: u64, long_call: bool) -> Option<u64> {
        self.prepare_with_tls(pc, flags, 0, long_call)
            .map(|entry| entry.pc)
    }
    pub fn prepare_with_tls(
        &mut self,
        pc: u64,
        flags: u64,
        tls: u64,
        long_call: bool,
    ) -> Option<Entry> {
        if self.deferred != 0 || long_call || self.primary.entering || self.observer.entering {
            return None;
        }
        let primary = self.primary.entry != 0
            && !self.primary.masked
            && self.primary.pending
            && self.observer.depth == 0;
        let observer = self.observer.entry != 0 && !self.observer.masked && self.observer.pending;
        if !primary && !observer {
            return None;
        }
        let selected = observer && (!primary || self.next_observer);
        self.next_observer = !selected;
        let lane = if selected {
            &mut self.observer
        } else {
            &mut self.primary
        };
        lane.masked = true;
        lane.pending = false;
        lane.entering = true;
        lane.depth = lane.depth.saturating_add(1);
        self.pc = pc;
        self.flags = flags;
        self.interrupted_tls = tls;
        Some(Entry {
            pc: lane.entry,
            tls: selected.then_some(self.observer_tls),
        })
    }
    /// Deferred eligible requests keep an enabled IPC wait interruptible.
    pub fn interrupt_wait(&self) -> bool {
        self.deferred != 0
            && ((self.primary.pending && !self.primary.masked && self.observer.depth == 0)
                || (self.observer.pending && !self.observer.masked))
    }
    pub fn can_return(&self) -> bool {
        let lane = if self.active_observer() {
            &self.observer
        } else {
            &self.primary
        };
        lane.depth != 0 && self.deferred == 0 && lane.masked && !lane.entering
    }
    /// The observer nesting restriction identifies the innermost active entry.
    pub fn returned(&mut self) -> Result<(), Error> {
        if !self.can_return() {
            return Err(Error::BadState);
        }
        let lane = if self.active_observer() {
            &mut self.observer
        } else {
            &mut self.primary
        };
        lane.depth -= 1;
        lane.masked = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MASK: u64 = UpcallControl::Mask.raw();
    const ENABLE: u64 = UpcallControl::Enable.raw();
    const TAKE: u64 = UpcallControl::Take.raw();
    const DEFER: u64 = UpcallControl::Defer.raw();
    const RESUME: u64 = UpcallControl::Resume.raw();
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
        state.primary.depth = u32::MAX - 1;
        for _ in 0..3 {
            state.control(ENABLE).unwrap();
            assert_eq!(state.request(), Ok(true));
            assert_eq!(state.prepare(0x2000, 0, false), Some(0x1000));
            assert_eq!(state.control(TAKE), Ok((1, 0x2000, 0)));
            // The handler jumps out: the thread unmasks with no return.
        }
        assert_eq!(state.primary.depth, u32::MAX);
        assert!(state.can_return());
        state.returned().unwrap();
        assert_eq!(state.primary.depth, u32::MAX - 1);
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
        assert_eq!(state.bind(0), Err(Error::BadState));
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
        assert_eq!(state.control(10), Err(Error::InvalidArgs));
        assert_eq!(state.control(TAKE), Err(Error::BadState));
        state.control(ENABLE).unwrap();
        assert_eq!(state.prepare(0, 0, false), Some(0x1000));
        assert_eq!(state.control(TAKE), Ok((1, 0, 0)));
        state.returned().unwrap();
    }
    #[test]
    fn observer_install_preserves_active_native_entry_and_both_pending_masks() {
        let mut s = State::new();
        s.bind(0x1000).unwrap();
        s.control(ENABLE).unwrap();
        s.request().unwrap();
        assert_eq!(s.prepare(0x2000, NZCV, false), Some(0x1000));
        s.control(TAKE).unwrap();
        s.request().unwrap();
        let primary = (
            s.primary.entry,
            s.primary.depth,
            s.primary.masked,
            s.primary.pending,
        );
        s.control(DEFER).unwrap();
        s.bind_observer(0x3000, 0x4000).unwrap();
        s.control(UpcallControl::ObserverEnable.raw()).unwrap();
        s.request_layer().unwrap();
        assert_eq!(
            (
                s.primary.entry,
                s.primary.depth,
                s.primary.masked,
                s.primary.pending
            ),
            primary
        );
        assert!(s.interrupt_wait());
        assert_eq!(s.prepare_with_tls(0x2100, 0, 0, false), None);
        s.control(RESUME).unwrap();
        assert_eq!(
            s.prepare_with_tls(0x2100, NZCV, 0, false),
            Some(Entry {
                pc: 0x3000,
                tls: Some(0x4000)
            })
        );
        assert_eq!(s.control(TAKE), Err(Error::BadState));
        assert_eq!(
            s.control(UpcallControl::ObserverTake.raw()),
            Ok((1, 0x2100, NZCV))
        );
        assert_eq!(s.interrupted_tls(), 0);
        s.returned().unwrap();
        assert_eq!(s.primary.depth, 1);
        assert!(s.primary.pending);
        s.control(MASK).unwrap();
        s.returned().unwrap();
        assert_eq!(s.primary.depth, 0);
    }
    #[test]
    fn observer_nesting_restores_innermost_and_delays_primary_until_outer_return() {
        let mut s = State::new();
        s.bind(0x1000).unwrap();
        s.bind_observer(0x3000, 0x4000).unwrap();
        s.control(ENABLE).unwrap();
        s.control(UpcallControl::ObserverEnable.raw()).unwrap();
        s.request_layer().unwrap();
        s.prepare_with_tls(0x2000, NZCV, 0, false).unwrap();
        s.control(UpcallControl::ObserverTake.raw()).unwrap();
        assert_eq!(s.request(), Ok(false));
        s.control(UpcallControl::ObserverEnable.raw()).unwrap();
        assert_eq!(s.prepare(0x5000, 0, false), None);
        s.request_layer().unwrap();
        s.prepare_with_tls(0x5000, NZCV, 0x4000, false).unwrap();
        assert_eq!(
            s.control(UpcallControl::ObserverTake.raw()),
            Ok((1, 0x5000, NZCV))
        );
        assert_eq!(s.interrupted_tls(), 0x4000);
        assert_eq!(s.bind_observer(0, 0), Err(Error::BadState));
        s.returned().unwrap();
        assert_eq!(s.observer.depth, 1);
        assert_eq!(s.prepare(0x5000, 0, false), None);
        s.control(UpcallControl::ObserverMask.raw()).unwrap();
        s.returned().unwrap();
        assert_eq!(s.observer.depth, 0);
        assert_eq!(s.prepare(0x2000, 0, false), Some(0x1000));
    }
    #[test]
    fn eligible_pending_lanes_are_fair_and_layer_falls_back() {
        let mut s = State::new();
        s.bind(0x1000).unwrap();
        s.control(ENABLE).unwrap();
        s.request_layer().unwrap();
        assert_eq!(s.prepare(0x2000, 0, false), Some(0x1000));
        s.control(TAKE).unwrap();
        s.returned().unwrap();
        s.bind_observer(0x3000, 0x4000).unwrap();
        s.control(UpcallControl::ObserverEnable.raw()).unwrap();
        let mut entered = [0; 4];
        for entry in &mut entered {
            s.request().unwrap();
            s.request_layer().unwrap();
            *entry = s.prepare(0x2000, 0, false).unwrap();
            s.control(if *entry == 0x1000 {
                TAKE
            } else {
                UpcallControl::ObserverTake.raw()
            })
            .unwrap();
            s.returned().unwrap();
        }
        assert!(entered.windows(2).all(|w| w[0] != w[1]));
    }
    #[test]
    fn failed_observer_bind_and_shared_deferral_preserve_resident_debt() {
        let mut s = State::new();
        s.bind(0x1000).unwrap();
        s.bind_observer(0x3000, 0x4000).unwrap();
        s.control(UpcallControl::ObserverEnable.raw()).unwrap();
        s.request_layer().unwrap();
        for (entry, tls) in [(0x3002, 0x4000), (0x3000, 0x4008), (0, 0x4000), (0x3000, 0)] {
            assert_eq!(s.bind_observer(entry, tls), Err(Error::InvalidArgs));
        }
        s.control(DEFER).unwrap();
        assert_eq!(s.bind(0), Err(Error::BadState));
        assert!(s.interrupt_wait());
        assert_eq!(s.prepare(0x2000, 0, false), None);
        s.control(RESUME).unwrap();
        assert_eq!(
            s.prepare_with_tls(0x2000, 0, 0x9000, false),
            Some(Entry {
                pc: 0x3000,
                tls: Some(0x4000)
            })
        );
        assert_eq!(s.interrupted_tls(), 0x9000);
        assert_eq!(s.returned(), Err(Error::BadState));
    }
}
