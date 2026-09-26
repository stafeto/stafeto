// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The labels init gives (spec 13.4): the label of each spawn, of each
//! session CONNECT makes and of its worker thread, from one 64-bit count.

/// A count of labels from 1 that never gives one twice: 0 is no label,
/// and once u64::MAX went the count stops.
#[derive(Debug)]
pub struct Labels {
    given: u64,
}

impl Labels {
    pub const fn new() -> Labels {
        Labels { given: 0 }
    }

    /// The labels given so far (STATS).
    pub fn given(&self) -> u64 {
        self.given
    }
}

impl Iterator for Labels {
    type Item = u64;

    /// The next label; None once every label went: init stops then, since
    /// a label given twice would let a CLIENT_GONE of an old session end
    /// a new one.
    fn next(&mut self) -> Option<u64> {
        let label = self.given.checked_add(1)?;
        self.given = label;
        Some(label)
    }
}

impl Default for Labels {
    fn default() -> Labels {
        Labels::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_start_at_1_and_never_repeat() {
        let mut labels = Labels::new();
        assert_eq!(labels.given(), 0);
        let taken: Vec<u64> = (0..1000).map(|_| labels.next().unwrap()).collect();
        assert_eq!(taken[0], 1);
        assert!(taken.windows(2).all(|w| w[1] == w[0] + 1));
        assert_eq!(labels.given(), 1000);
    }

    #[test]
    fn labels_stop_before_they_wrap() {
        let mut labels = Labels {
            given: u64::MAX - 2,
        };
        assert_eq!(labels.next(), Some(u64::MAX - 1));
        assert_eq!(labels.next(), Some(u64::MAX));
        for _ in 0..3 {
            assert_eq!(labels.next(), None, "no label past u64::MAX, and no 0");
        }
        assert_eq!(labels.given(), u64::MAX);
    }
}
