// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Separate bounded lock portions preserve turns for existing RAM maintenance.

const PID_PLACES: usize = proto_process::RECORDS;
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
}
impl Dispatch {
    /// An authenticated lifetime mapping enables exactly one finite audit round.
    pub fn next(&mut self, now_ns: u64, actor_pending: bool, mapped: bool) -> Work {
        if !mapped {
            return Work::Legacy;
        }
        if now_ns >= self.next_audit_ns && self.audit_remaining == 0 {
            self.next_audit_ns = now_ns.saturating_add(AUDIT_PERIOD_NS);
            self.audit_position = 0;
            self.audit_remaining = PID_PLACES;
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
                    self.audited = true;
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
    fn continuous_actor_work_preserves_legacy_turns_and_one_exact_pid_round() {
        let mut dispatch = Dispatch::default();
        let mut seen = [0; PID_PLACES];
        let (mut legacy, mut actor, mut audits) = (0, 0, 0);
        for _ in 0..3 * PID_PLACES / AUDIT_PORTION {
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
            assert_eq!(dispatch.audited(), audits == 32);
        }
        assert_eq!((legacy, actor, audits), (32, 32, 32));
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
    fn standalone_without_process_never_fabricates_life_or_schedules_actor() {
        let mut dispatch = Dispatch::default();
        for _ in 0..1000 {
            assert_eq!(dispatch.next(u64::MAX, true, false), Work::Legacy);
            assert!(!dispatch.pending(false));
            assert!(!dispatch.audited());
        }
        assert_eq!(dispatch.next(0, false, true), Work::Legacy);
        assert!(dispatch.pending(false));
        assert_eq!(
            dispatch.next(0, false, true),
            Work::Audit { first: 0, end: 8 }
        );
    }
    #[test]
    fn audit_completes_when_its_period_expires_mid_round() {
        let mut dispatch = Dispatch::default();
        let mut next = 0;
        let mut portions = 0;
        for step in 0..96 {
            if let Work::Audit { first, end } = dispatch.next(step * AUDIT_PERIOD_NS, false, true) {
                assert_eq!(first, next);
                next = end;
                portions += 1;
            }
        }
        assert_eq!((next, portions), (256, 32));
    }
}
