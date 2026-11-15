// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! How often a request that the kernel took back from the queue of a channel is sent again.
//!
//! The kernel ends a send only while its request stands in the queue and no service has taken
//! it, so the service has changed nothing and the request can go again. A budgeted service
//! that is demoted keeps requests in the queue for up to T - C, and a signal that arrives then
//! ends the wait of a call that the POSIX rules do not let block. Such a call asks again, and
//! the handler of the signal has run on the way back from the interrupted send. A flood of
//! signals that comes faster than the queue time would interrupt every try; the count ends
//! the loop after MAX tries and the call gives its EINTR as before.

/// The most interruptions of one request that are answered with another send.
pub const MAX: u32 = 16;

/// Counts one more interruption in `tries` (0 at the first): whether the request goes again.
pub fn ask_again(tries: &mut u32) -> bool {
    if *tries >= MAX {
        return false;
    }
    *tries += 1;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loop of a caller: a send that a flood of signals interrupts every time ends after
    /// MAX more sends; one that is interrupted twice goes through on the third.
    fn sends(interrupted: u32) -> (u32, bool) {
        let (mut tries, mut sent) = (0, 0);
        loop {
            sent += 1;
            if sent > interrupted {
                return (sent, true);
            }
            if !ask_again(&mut tries) {
                return (sent, false);
            }
        }
    }

    #[test]
    fn a_request_taken_back_goes_again_a_bounded_number_of_times() {
        assert_eq!(sends(0), (1, true));
        assert_eq!(sends(2), (3, true));
        assert_eq!(sends(MAX), (MAX + 1, true));
        assert_eq!(sends(MAX + 1), (MAX + 1, false));
        assert_eq!(sends(u32::MAX), (MAX + 1, false));
    }
}
