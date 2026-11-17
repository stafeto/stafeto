// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the NVMe service decides apart from the controller and the calls: tested on the host.

#![no_std]

/// Whether the service keeps its timer armed: while a command is out, and while the controller
/// is not up (a reset in place runs the bring-up again, one register access a step, and the
/// steps need the timer when no interrupt and no request comes).
pub const fn timer_wanted(inflight: u32, up: bool) -> bool {
    inflight > 0 || !up
}

#[cfg(test)]
mod tests {
    use super::timer_wanted;

    #[test]
    fn the_timer_runs_while_a_command_is_out() {
        assert!(timer_wanted(1, true));
        assert!(timer_wanted(5, true));
    }

    #[test]
    fn the_timer_sleeps_when_the_controller_is_up_and_idle() {
        assert!(!timer_wanted(0, true));
    }

    #[test]
    fn after_a_reset_the_timer_runs_with_no_command_out() {
        // The reset ends every command in work, so none is out while the bring-up goes on.
        assert!(timer_wanted(0, false));
    }
}
