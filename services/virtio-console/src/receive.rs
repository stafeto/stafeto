// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The existing single receive buffer: device ownership, returned prefix and EOF.

pub const RX_BYTES: usize = 256;

#[derive(Default)]
pub struct Receive {
    pub token: Option<u16>,
    len: usize,
    at: usize,
    ended: bool,
}

impl Receive {
    /// Pop only the exact visible completion, at most once. Until then the
    /// buffer remains device-owned and its contents must not be inspected.
    pub fn finish(&mut self, used: Option<u16>, pop: impl FnOnce(u16) -> Option<usize>) {
        let Some(token) = self.token else { return };
        if used != Some(token) {
            return;
        }
        self.token = None;
        match pop(token) {
            Some(n) if n != 0 => {
                self.len = n.min(RX_BYTES);
                self.at = 0;
            }
            _ => self.ended = true,
        }
    }

    pub fn next_index(&mut self) -> Option<usize> {
        if self.at == self.len {
            return None;
        }
        let at = self.at;
        self.at += 1;
        Some(at)
    }

    pub fn discard(&mut self) {
        self.at = self.len;
    }

    pub fn should_post(&self) -> bool {
        self.token.is_none() && !self.ended && self.at == self.len
    }

    pub fn ended(&self) -> bool {
        self.ended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_discards_only_the_returned_prefix_and_keeps_device_ownership() {
        let mut rx = Receive {
            token: Some(7),
            ..Receive::default()
        };
        rx.finish(None, |_| panic!("unreturned buffer popped"));
        rx.discard();
        assert_eq!(rx.token, Some(7));
        assert!(!rx.should_post());
        let mut pops = 0;
        rx.finish(Some(7), |token| {
            assert_eq!(token, 7);
            pops += 1;
            Some(256)
        });
        assert_eq!(pops, 1);
        assert_eq!(rx.next_index(), Some(0));
        rx.discard();
        assert_eq!(rx.next_index(), None);
        assert!(rx.should_post());
        rx.finish(Some(7), |_| panic!("completion popped twice"));
        rx.token = Some(8);
        rx.finish(Some(7), |_| panic!("wrong generation popped"));
        rx.finish(Some(8), |_| Some(2));
        assert_eq!(rx.next_index(), Some(0));
        assert_eq!(rx.next_index(), Some(1));
        assert_eq!(rx.next_index(), None);
    }

    #[test]
    fn flush_preserves_eof_and_caps_returned_length() {
        let mut rx = Receive {
            token: Some(1),
            ..Receive::default()
        };
        rx.finish(Some(1), |_| Some(RX_BYTES + 1));
        assert_eq!(
            (0..RX_BYTES + 1).filter_map(|_| rx.next_index()).count(),
            RX_BYTES
        );
        rx.token = Some(2);
        rx.finish(Some(2), |_| Some(0));
        rx.discard();
        assert!(rx.ended());
        assert!(!rx.should_post());
    }
}
