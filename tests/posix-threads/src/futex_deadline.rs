// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#[derive(Clone, Copy)]
pub enum Outcome {
    Timeout,
    Woken,
    Other,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Retry,
    Done,
    Fail,
}

pub fn select(outcome: Outcome, reached: bool, word: u32, waiters: u32) -> Decision {
    if word != 0 || waiters != 0 {
        return Decision::Fail;
    }
    match outcome {
        Outcome::Woken => Decision::Retry,
        Outcome::Timeout if reached => Decision::Done,
        _ => Decision::Fail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spurious_returns_require_a_real_timeout() {
        for reached in [false, true] {
            assert_eq!(select(Outcome::Woken, reached, 0, 0), Decision::Retry);
        }
        let sequence = [Outcome::Woken, Outcome::Woken, Outcome::Timeout];
        let decisions = sequence.map(|outcome| select(outcome, true, 0, 0));
        assert_eq!(
            decisions,
            [Decision::Retry, Decision::Retry, Decision::Done]
        );
    }

    #[test]
    fn early_timeout_entry_and_other_errors_fail() {
        assert_eq!(select(Outcome::Timeout, false, 0, 0), Decision::Fail);
        // Entry and every errno other than ETIMEDOUT map to Other.
        for reached in [false, true] {
            assert_eq!(select(Outcome::Other, reached, 0, 0), Decision::Fail);
        }
    }

    #[test]
    fn every_return_requires_unchanged_word_and_empty_bucket() {
        for outcome in [Outcome::Woken, Outcome::Timeout, Outcome::Other] {
            for reached in [false, true] {
                assert_eq!(select(outcome, reached, 1, 0), Decision::Fail);
                assert_eq!(select(outcome, reached, 0, 1), Decision::Fail);
            }
        }
    }
}
