// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Ordinary process dispositions and per-thread signal masks/pending sets.
//! A single runtime owner serializes mutation; no user callback runs here.
#![no_std]
pub use posix_types::{SigAction, SigSet, constants::*};
pub const DEFAULT: u64 = 0;
pub const IGNORE: u64 = 1;
pub const VALID: SigSet = (1 << 31) - 1;
pub const UNBLOCKABLE: SigSet = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));
pub const FLAGS: i32 = SA_NODEFER | SA_RESETHAND;
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
    if !(1..=31).contains(&signal) {
        return Err(Invalid::Signal);
    }
    Ok(1 << (signal - 1))
}
pub fn mask(set: SigSet) -> Result<SigSet, Invalid> {
    if set & !VALID != 0 {
        return Err(Invalid::Mask);
    }
    Ok(set & !UNBLOCKABLE)
}
pub fn packed(action: SigAction) -> u64 {
    action.mask | ((action.flags as u64) << 32)
}
pub fn unpacked(handler: u64, value: u64) -> SigAction {
    SigAction {
        handler,
        mask: value & 0xffff_ffff,
        flags: (value >> 32) as i32,
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
    values: [SigAction; 31],
}
impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}
impl Actions {
    pub const fn new() -> Self {
        Self {
            values: [INITIAL; 31],
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
    fn caught(flags: i32, mask: SigSet) -> SigAction {
        SigAction {
            handler: 0x1000,
            mask,
            flags,
        }
    }
    #[test]
    fn every_signal_bit_and_invalid_boundaries() {
        for signal in 1..=31 {
            assert_eq!(bit(signal), Ok(1 << (signal - 1)));
        }
        for signal in [i32::MIN, -1, 0, 32, i32::MAX] {
            assert_eq!(bit(signal), Err(Invalid::Signal));
        }
        assert_eq!(mask(VALID), Ok(VALID & !UNBLOCKABLE));
        assert_eq!(mask(1 << 63), Err(Invalid::Mask));
    }
    #[test]
    fn invalid_action_is_atomic_and_uncatchable_queries_work() {
        let mut actions = Actions::new();
        assert_eq!(actions.get(SIGKILL), Ok(INITIAL));
        for signal in [SIGKILL, SIGSTOP] {
            assert!(actions.replace(signal, caught(0, 0)).is_err());
        }
        for action in [
            caught(4, 0),
            caught(0, 1 << 63),
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
            unpacked(0x1000, packed(caught(FLAGS, VALID & !UNBLOCKABLE))),
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
        assert_eq!(
            thread.change_mask(SIG_BLOCK, Some(1 << 63)),
            Err(Invalid::Mask)
        );
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
            actions.replace(signal, caught(SA_RESETHAND, 0)).unwrap();
            thread.mask = 0;
            thread.generate(signal, &actions).unwrap();
            thread.take(&mut actions).unwrap();
            assert_eq!(
                actions.get(signal).unwrap(),
                if signal == SIGUSR1 {
                    INITIAL
                } else {
                    caught(SA_RESETHAND, 0)
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
