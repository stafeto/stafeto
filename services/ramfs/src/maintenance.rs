// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fixed maintenance traversal keeps blocked transports from retaining the cursor.

pub struct Cursor {
    pub position: usize,
    pub remaining: usize,
}
impl Default for Cursor {
    fn default() -> Self {
        Self {
            position: 1,
            remaining: 0,
        }
    }
}
impl Cursor {
    /// Every Cloning visit, including a failed retained close, releases the cursor.
    pub fn complete_clone(&mut self, slots: usize) {
        self.complete_client(true, true, slots);
    }

    /// Retained cleanup rotates after every visit and keeps retrying the finite table.
    pub fn complete_client(&mut self, worked: bool, closing: bool, slots: usize) {
        if worked && closing {
            self.remaining = self.remaining.max(slots - 1);
        }
        self.complete(worked && !closing, slots);
    }

    pub fn complete(&mut self, worked: bool, slots: usize) {
        if !worked {
            self.position = 1 + self.position % (slots - 1);
            self.remaining = self.remaining.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_retained_close_rotates_and_retries_while_another_owner_progresses() {
        let mut cursor = Cursor {
            position: 1,
            remaining: 0,
        };
        let mut stalled_visits = 0;
        let mut other_steps = 0;
        for _ in 0..18 {
            match cursor.position {
                1 => {
                    stalled_visits += 1;
                    cursor.complete_client(true, true, 4);
                }
                2 => {
                    other_steps += 1;
                    cursor.complete_client(true, true, 4);
                }
                _ => cursor.complete_client(false, false, 4),
            }
            assert!(cursor.remaining > 0);
        }
        assert_eq!(stalled_visits, 6);
        assert_eq!(other_steps, 6);
        assert_eq!(cursor.position, 1);
    }

    #[test]
    fn waiting_destination_gives_the_retained_source_a_turn() {
        let mut cursor = Cursor {
            position: 1,
            remaining: 3,
        };
        // Destination waits; the next retained birth performs three refresh phases.
        let waiting = crate::authority::retained_source_phase(
            19,
            19,
            true,
            Some(crate::authority::BindingPurpose::Refresh),
            8,
            7,
        )
        .unwrap();
        cursor.complete(waiting.progresses(), 3);
        assert_eq!(cursor.position, 2);
        for _ in 0..3 {
            cursor.complete(true, 3);
            assert_eq!(cursor.position, 2);
            assert_eq!(cursor.remaining, 2);
        }
        // A completed source lets the destination observe the refreshed authority.
        cursor.complete(false, 3);
        assert_eq!(cursor.position, 1);
        assert_eq!(cursor.remaining, 1);
    }
}

/// Closed sessions may only inspect or settle exact existing operations.
pub fn closed_method(method: u16) -> bool {
    use proto_fs::Method;
    matches!(
        Method::from_number(method),
        Some(
            Method::Close
                | Method::CloseExact
                | Method::ResolveCancel
                | Method::OpenCancel
                | Method::OpenQuery
                | Method::DataQuery
                | Method::DataCancel
                | Method::DataAck
        )
    )
}

#[cfg(test)]
mod retained_tests {
    use super::*;
    use proto_fs::Method;
    #[test]
    fn retained_dispatch_accepts_settlement_and_rejects_every_new_effect() {
        for method in [
            Method::Close,
            Method::CloseExact,
            Method::ResolveCancel,
            Method::OpenCancel,
            Method::OpenQuery,
            Method::DataQuery,
            Method::DataCancel,
            Method::DataAck,
        ] {
            assert!(closed_method(method as u16));
        }
        for method in [
            Method::Open,
            Method::Clone,
            Method::CloneExact,
            Method::Bind,
            Method::FinishBinding,
            Method::ReadInto,
            Method::OpenStart,
            Method::OpenPrepare,
            Method::OpenCommit,
            Method::OpenFinish,
            Method::ResolveStart,
            Method::ResolveStep,
            Method::DataStart,
            Method::DataFeed,
            Method::DataStep,
            Method::DataCommit,
        ] {
            assert!(!closed_method(method as u16));
        }
        assert!(!closed_method(u16::MAX));
    }
}

/// The existing cursor visits every paid job and the unique INTO resource.
pub fn debt_turn(cursor: &mut u8, jobs: usize) -> usize {
    let slot = *cursor as usize;
    *cursor = ((slot + 1) % (jobs + 1)) as u8;
    slot
}

#[cfg(test)]
mod debt_tests {
    use super::*;
    #[test]
    fn failed_window_retry_preserves_fair_visits_to_all_128_jobs() {
        let mut cursor = 0;
        let mut visits = [0; 129];
        for _ in 0..129 * 4 {
            let slot = debt_turn(&mut cursor, 128);
            visits[slot] += 1;
        }
        assert_eq!(visits, [4; 129]);
        assert_eq!(cursor, 0);
    }
}
