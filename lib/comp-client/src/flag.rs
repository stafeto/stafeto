// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A flag one thread holds for the length of a scope (the wait of a window,
//! the taking of its events): the holder's end of the scope clears it. A
//! thread that does not get the flag leaves it as it found it.

use core::sync::atomic::{AtomicBool, Ordering};

/// Clears a flag at the end of the scope.
pub struct Flag(&'static AtomicBool);

impl Flag {
    /// Takes the flag; None when another thread has it, and then the flag
    /// stays set for that thread.
    pub fn take(flag: &'static AtomicBool) -> Option<Flag> {
        // The guard is made only after the flag was got: `then_some` would make
        // it before, and its drop would clear the flag of the thread that holds it.
        (!flag.swap(true, Ordering::AcqRel)).then(|| Flag(flag))
    }
}

impl Drop for Flag {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_that_does_not_get_the_flag_leaves_it_set() {
        static FLAG: AtomicBool = AtomicBool::new(false);
        let held = Flag::take(&FLAG).expect("a free flag");
        assert!(FLAG.load(Ordering::Acquire));
        assert!(Flag::take(&FLAG).is_none());
        assert!(
            FLAG.load(Ordering::Acquire),
            "the failed take cleared the flag of the holder"
        );
        drop(held);
        assert!(!FLAG.load(Ordering::Acquire));
        assert!(Flag::take(&FLAG).is_some());
    }
}
