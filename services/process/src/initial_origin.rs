// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Persistent initial provenance. Values alone grant no executable authority.

pub const MAPS_PUBLISHED: u32 = 1;
pub const MAPS_ACKED: u32 = 2;
pub const STAGE_COMMITTED: u32 = 4;
pub const BOOTSTRAP_RELEASED: u32 = 8;
pub const USER_RELEASED: u32 = 16;
pub const INIT_ACKED: u32 = 32;
const FLAGS: u32 = 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialOrigin {
    pub artifact: u32,
    pub flags: u32,
}
impl InitialOrigin {
    pub fn new(artifact: u32, flags: u32) -> Option<Self> {
        (flags & !FLAGS == 0).then_some(Self { artifact, flags })
    }
    pub const fn raw(self) -> u64 {
        self.artifact as u64 | ((self.flags as u64) << 32)
    }
    pub fn from_raw(raw: u64) -> Option<Self> {
        Self::new(raw as u32, (raw >> 32) as u32)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct SourceOrigin(u64);
impl SourceOrigin {
    pub const UNKNOWN: Self = Self(0);
    pub const SUSPENDED: u64 = 1 << 40;
    pub const WAS_RUNNABLE: u64 = 1 << 41;
    const RECOVERY: u64 = Self::SUSPENDED | Self::WAS_RUNNABLE;

    pub fn boot(artifact: u32, none: bool) -> Option<Self> {
        let artifact = artifact.checked_add(1)?;
        Some(Self(
            u64::from(artifact) | ((if none { 2 } else { 1 }) << 32),
        ))
    }
    pub fn from_wire(raw: u64) -> Option<Self> {
        if raw == 0 {
            return Some(Self::UNKNOWN);
        }
        ((raw >> 32 == 1 || raw >> 32 == 2) && raw as u32 != 0).then_some(Self(raw))
    }
    pub const fn wire(self) -> u64 {
        self.0 & !Self::RECOVERY
    }
    pub fn artifact(self) -> Option<u32> {
        (self.wire() != 0).then(|| (self.0 as u32) - 1)
    }
    pub fn none(self) -> bool {
        self.wire() >> 32 == 2
    }
    pub fn capture_suspend(&mut self, runnable: bool) {
        if self.0 & Self::SUSPENDED == 0 {
            self.0 |= Self::SUSPENDED;
            if runnable {
                self.0 |= Self::WAS_RUNNABLE;
            }
        }
    }
    pub fn recovery_suspended(self) -> bool {
        self.0 & Self::SUSPENDED != 0
    }
    pub fn recovery_was_runnable(self) -> bool {
        self.0 & Self::WAS_RUNNABLE != 0
    }
    pub fn finish_suspend(&mut self) {
        self.0 &= !Self::RECOVERY;
    }
    pub fn inherited(self) -> Self {
        Self(self.wire())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_flags_reject_unknown_and_retain_terminal_ack() {
        assert_eq!(
            InitialOrigin::new(7, INIT_ACKED).unwrap().raw(),
            7 | (32 << 32)
        );
        assert!(InitialOrigin::from_raw(64 << 32).is_none());
    }
    #[test]
    fn recovery_flags_stay_private_and_child_keeps_only_source() {
        let mut source = SourceOrigin::boot(8, true).unwrap();
        let wire = source.wire();
        source.capture_suspend(true);
        source.capture_suspend(false);
        assert!(source.recovery_was_runnable());
        assert_eq!(source.wire(), wire);
        assert_eq!(source.inherited(), SourceOrigin::from_wire(wire).unwrap());
        assert!(!source.inherited().recovery_suspended());
        assert!(SourceOrigin::from_wire(source.0).is_none());
        source.finish_suspend();
        assert_eq!(source.artifact(), Some(8));
        assert!(source.none());
    }
    #[test]
    fn maximum_source_never_wraps_and_unknown_stays_unknown() {
        assert!(SourceOrigin::boot(u32::MAX, false).is_none());
        assert_eq!(
            SourceOrigin::boot(u32::MAX - 1, false).unwrap().artifact(),
            Some(u32::MAX - 1)
        );
        let mut unknown = SourceOrigin::UNKNOWN;
        unknown.capture_suspend(false);
        assert_eq!(unknown.wire(), 0);
        assert_eq!(unknown.artifact(), None);
        assert!(!unknown.recovery_was_runnable());
    }
}
