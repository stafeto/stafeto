// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! How a process lives and ends (spec 4, 7.9): the count of its threads
//! that started and have not ended, and the reason it ended, which the
//! first end records for good. The last started thread to exit ends the
//! process with code 0; threads that never started do not keep it alive,
//! and a process in which no thread ever started lives until its
//! references go. Also the checks on the values `process_create` takes.

use crate::PAGE_SIZE;
use crate::handles::MAX_HANDLES;
use abi::{Error, ProcessState};

pub struct Life {
    /// Threads that started and have not ended.
    live: u32,
    state: ProcessState,
}

impl Life {
    /// A new process: alive, no thread started.
    pub const fn new() -> Life {
        Life {
            live: 0,
            state: ProcessState::Alive,
        }
    }

    /// What `object_info` reports: alive, or why the process ended.
    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn is_alive(&self) -> bool {
        self.state == ProcessState::Alive
    }

    /// A thread of the process starts. BAD_STATE once the process ended:
    /// none of its threads runs again.
    pub fn start(&mut self) -> Result<(), Error> {
        if !self.is_alive() {
            return Err(Error::BadState);
        }
        self.live = self.live.checked_add(1).expect("started threads overflow");
        Ok(())
    }

    /// A started thread ends of itself (thread_exit). True when it was the
    /// last: the process ends then, as if it exited with code 0. A process
    /// that ended before stays as it is.
    pub fn exit(&mut self) -> bool {
        if !self.is_alive() {
            return false;
        }
        self.live = self.live.checked_sub(1).expect("an exit without a start");
        self.live == 0 && self.end(ProcessState::Exited { code: 0 })
    }

    /// The process ends with `reason`: process_exit, process_kill or a
    /// fault. False when it ended before: the first reason stays.
    pub fn end(&mut self, reason: ProcessState) -> bool {
        assert!(
            reason != ProcessState::Alive,
            "a process ends with a reason"
        );
        if !self.is_alive() {
            return false;
        }
        self.state = reason;
        self.live = 0;
        true
    }
}

impl Default for Life {
    fn default() -> Self {
        Self::new()
    }
}

/// The memory quota `process_create` takes, in bytes: whole pages, at
/// least one. INVALID_ARGS otherwise.
pub fn quota_arg(raw: u64) -> Result<u64, Error> {
    if raw > 0 && raw.is_multiple_of(PAGE_SIZE) {
        Ok(raw)
    } else {
        Err(Error::InvalidArgs)
    }
}

/// The handle limit `process_create` takes: 1 to MAX_HANDLES. INVALID_ARGS
/// otherwise.
pub fn handle_limit_arg(raw: u64) -> Result<u32, Error> {
    match u32::try_from(raw) {
        Ok(limit) if (1..=MAX_HANDLES).contains(&limit) => Ok(limit),
        _ => Err(Error::InvalidArgs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAULT: ProcessState = ProcessState::Fault {
        esr: 0x9200_004F,
        far: 0x1000,
        elr: 0x40_0000,
    };

    #[test]
    fn last_started_thread_ends_the_process() {
        let mut life = Life::new();
        // Nothing started: the process lives until its references go.
        assert!(life.is_alive());
        life.start().unwrap();
        life.start().unwrap();
        // A third thread was created and never started: it does not count.
        assert!(!life.exit());
        assert_eq!(life.state(), ProcessState::Alive);
        assert!(life.exit());
        assert_eq!(life.state(), ProcessState::Exited { code: 0 });
        assert_eq!(life.start(), Err(Error::BadState));
        assert!(!life.exit());
    }

    #[test]
    fn reason_is_recorded_once() {
        let mut life = Life::new();
        life.start().unwrap();
        assert!(life.end(ProcessState::Killed));
        assert!(!life.end(FAULT));
        assert!(!life.end(ProcessState::Exited { code: 3 }));
        // The killed thread never exits of itself; nothing changes if it does.
        assert!(!life.exit());
        assert_eq!(life.state(), ProcessState::Killed);
        assert_eq!(life.start(), Err(Error::BadState));

        let mut life = Life::new();
        assert!(life.end(ProcessState::Exited { code: u64::MAX }));
        assert!(!life.end(FAULT));
        assert_eq!(life.state(), ProcessState::Exited { code: u64::MAX });
    }

    #[test]
    fn process_create_values() {
        for quota in [PAGE_SIZE, 3 * PAGE_SIZE, 1 << 40] {
            assert_eq!(quota_arg(quota), Ok(quota));
        }
        for quota in [0, 1, PAGE_SIZE - 1, PAGE_SIZE + 8, u64::MAX] {
            assert_eq!(quota_arg(quota), Err(Error::InvalidArgs));
        }
        assert_eq!(handle_limit_arg(1), Ok(1));
        assert_eq!(handle_limit_arg(u64::from(MAX_HANDLES)), Ok(MAX_HANDLES));
        for limit in [0, u64::from(MAX_HANDLES) + 1, 1 << 32 | 16, u64::MAX] {
            assert_eq!(handle_limit_arg(limit), Err(Error::InvalidArgs));
        }
    }
}
