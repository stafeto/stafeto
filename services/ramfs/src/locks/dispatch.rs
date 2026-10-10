// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Separate bounded lock portions preserve turns for existing RAM maintenance.

const PID_PLACES: usize = proto_process::RECORDS;
const DESCRIPTION_PLACES: usize = crate::DESCRIPTIONS;
const OWNER_PLACES: usize = PID_PLACES + DESCRIPTION_PLACES;
const AUDIT_PORTION: usize = 8;
const AUDIT_PERIOD_NS: u64 = 250_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    Legacy,
    Actor,
    Audit { first: usize, end: usize },
}
#[derive(Default)]
pub struct Dispatch {
    turn: u8,
    next_audit_ns: u64,
    audit_position: usize,
    audit_remaining: usize,
    audited: bool,
    full_round: bool,
}
impl Dispatch {
    /// Each finite round audits actual OFDs and authenticated PID lifetimes.
    pub fn next(&mut self, now_ns: u64, actor_pending: bool, mapped: bool) -> Work {
        if self.audit_remaining == 0 && (now_ns >= self.next_audit_ns || mapped && !self.audited) {
            self.next_audit_ns = now_ns.saturating_add(AUDIT_PERIOD_NS);
            self.audit_position = if mapped { 0 } else { PID_PLACES };
            self.audit_remaining = OWNER_PLACES - self.audit_position;
            self.full_round = mapped;
        }
        self.turn = (self.turn + 1) % 3;
        match self.turn {
            1 if actor_pending => Work::Actor,
            2 if self.audit_remaining != 0 => {
                let first = self.audit_position;
                let count = self.audit_remaining.min(AUDIT_PORTION);
                self.audit_position += count;
                self.audit_remaining -= count;
                if self.audit_remaining == 0 {
                    if self.full_round {
                        self.audited = true;
                    } else if mapped && !self.audited {
                        self.audit_position = 0;
                        self.audit_remaining = OWNER_PLACES;
                        self.full_round = true;
                    }
                }
                Work::Audit {
                    first,
                    end: first + count,
                }
            }
            _ => Work::Legacy,
        }
    }
    pub fn pending(&self, actor_pending: bool) -> bool {
        actor_pending || self.audit_remaining != 0
    }
    pub fn audited(&self) -> bool {
        self.audited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuous_actor_work_preserves_legacy_turns_and_one_exact_owner_round() {
        let mut dispatch = Dispatch::default();
        let mut seen = [0; OWNER_PLACES];
        let (mut legacy, mut actor, mut audits) = (0, 0, 0);
        for _ in 0..3 * OWNER_PLACES / AUDIT_PORTION {
            match dispatch.next(0, true, true) {
                Work::Legacy => legacy += 1,
                Work::Actor => actor += 1,
                Work::Audit { first, end } => {
                    assert!(end - first <= 8);
                    for visits in &mut seen[first..end] {
                        *visits += 1;
                    }
                    audits += 1;
                }
            }
            assert_eq!(dispatch.audited(), audits == 48);
        }
        assert_eq!((legacy, actor, audits), (48, 48, 48));
        assert!(seen.into_iter().all(|visits| visits == 1));
        assert!(!dispatch.pending(false));
        assert!(dispatch.audited());
        for _ in 0..9 {
            assert_eq!(
                dispatch.next(AUDIT_PERIOD_NS - 1, false, true),
                Work::Legacy
            );
        }
        assert_eq!(dispatch.next(AUDIT_PERIOD_NS, false, true), Work::Legacy);
        assert_eq!(
            dispatch.next(AUDIT_PERIOD_NS, false, true),
            Work::Audit { first: 0, end: 8 }
        );
    }
    #[test]
    fn standalone_without_process_progresses_only_real_ofds_and_preserves_legacy_turns() {
        let mut dispatch = Dispatch::default();
        let mut seen = [0; DESCRIPTION_PLACES];
        let (mut legacy, mut actor, mut audits) = (0, 0, 0);
        for _ in 0..48 {
            match dispatch.next(0, true, false) {
                Work::Legacy => legacy += 1,
                Work::Actor => actor += 1,
                Work::Audit { first, end } => {
                    assert!(first >= PID_PLACES && end <= OWNER_PLACES);
                    assert!(end - first <= 8);
                    for visits in &mut seen[first - PID_PLACES..end - PID_PLACES] {
                        *visits += 1;
                    }
                    audits += 1;
                }
            }
            assert!(!dispatch.audited());
        }
        assert_eq!((legacy, actor, audits), (16, 16, 16));
        assert!(seen.into_iter().all(|n| n == 1));
        assert!(!dispatch.pending(false));
    }
    #[test]
    fn mapping_during_ofd_round_preserves_its_cursor_then_finishes_one_full_round() {
        let mut dispatch = Dispatch::default();
        let mut seen = [0; OWNER_PLACES];
        let mut completed = 0;
        for tick in 0..240 {
            if let Work::Audit { first, end } = dispatch.next(0, false, tick >= 6) {
                assert!(end - first <= 8);
                for n in &mut seen[first..end] {
                    *n += 1;
                }
                completed += 1;
            }
            if dispatch.audited() {
                break;
            }
            assert!(dispatch.pending(false));
        }
        assert!(dispatch.audited());
        assert!(!dispatch.pending(false));
        assert_eq!(completed, 64);
        assert!(seen[..PID_PLACES].iter().all(|&n| n == 1));
        assert!(seen[PID_PLACES..].iter().all(|&n| n == 2));
    }
    #[test]
    fn audit_completes_when_its_period_expires_mid_round() {
        let mut dispatch = Dispatch::default();
        let mut next = 0;
        let mut portions = 0;
        for step in 0..144 {
            if let Work::Audit { first, end } = dispatch.next(step * AUDIT_PERIOD_NS, false, true) {
                assert_eq!(first, next);
                next = end;
                portions += 1;
            }
        }
        assert_eq!((next, portions), (384, 48));
    }
}
