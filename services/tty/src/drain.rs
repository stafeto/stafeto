// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sticky drain outcomes in the padding of the existing operation pin.

use crate::discipline::OUTPUT;

#[derive(Clone, Copy, Default)]
pub struct Prefix {
    pub reached: bool,
    pub ready: bool,
    pub failed: bool,
}

impl Prefix {
    /// Every live target is inside the fixed output ring. Call immediately
    /// after each bounded send/flush; completed prefixes are never compared
    /// after later traffic can move the modulo cursor farther away.
    pub fn advance(&mut self, sent: u64, target: u64) {
        if !self.reached && sent.wrapping_sub(target) <= OUTPUT as u64 {
            self.reached = true;
        }
    }

    pub fn complete(&mut self) {
        if self.reached && !self.failed {
            self.ready = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_crosses_wrap_and_completion_survives_later_traffic() {
        let mut prefix = Prefix::default();
        prefix.advance(u64::MAX, 1);
        assert!(!prefix.reached);
        prefix.complete();
        assert!(!prefix.ready);
        prefix.advance(2, 1);
        assert!(prefix.reached);
        prefix.complete();
        prefix.advance(u64::MAX / 2, 1);
        assert!(prefix.ready);
    }

    #[test]
    fn failed_physical_delivery_cannot_become_ready() {
        let mut prefix = Prefix {
            reached: true,
            failed: true,
            ..Prefix::default()
        };
        prefix.complete();
        assert!(!prefix.ready);
    }
}
