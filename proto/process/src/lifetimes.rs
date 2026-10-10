// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Read-only consumers compare complete PID lifetimes independently of credentials.

use crate::RECORDS;
use core::sync::atomic::{AtomicU64, Ordering};
pub const SIZE: usize = RECORDS * core::mem::size_of::<u64>();
pub const DEAD: u64 = 1 << 63;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Retired,
}

#[repr(C)]
pub struct Page {
    words: [AtomicU64; RECORDS],
}
impl Page {
    pub const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; RECORDS],
        }
    }
    fn index(pid: u32) -> Option<usize> {
        (pid / RECORDS as u32 != 0 && pid <= i32::MAX as u32)
            .then_some((pid % RECORDS as u32) as usize)
    }
    pub fn live(&self, pid: u32) -> bool {
        Self::index(pid)
            .is_some_and(|index| self.words[index].load(Ordering::Acquire) == u64::from(pid))
    }
    /// The process service serializes publishers; consumers only load.
    pub fn publish(&self, pid: u32) -> Result<(), Error> {
        let index = Self::index(pid).ok_or(Error::Invalid)?;
        let old = self.words[index].load(Ordering::Relaxed);
        if old & !DEAD > u64::from(pid) {
            return Err(Error::Invalid);
        }
        if old == u64::from(pid) | DEAD {
            return Err(Error::Retired);
        }
        self.words[index].store(u64::from(pid), Ordering::Release);
        Ok(())
    }
    /// An old image/record cannot retire the replacement in its reused place.
    pub fn retire(&self, pid: u32) -> bool {
        let Some(index) = Self::index(pid) else {
            return false;
        };
        self.words[index]
            .compare_exchange(
                u64::from(pid),
                u64::from(pid) | DEAD,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}
impl Default for Page {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn life_stays_live_across_credential_changes_and_ends_at_exact_retirement() {
        let page = Page::new();
        let credentials = AtomicU64::new(1);
        assert!(!page.live(256));
        page.publish(256).unwrap();
        assert!(page.live(256));
        for _ in 0..10 {
            credentials.fetch_add(1, Ordering::Release);
            assert!(page.live(256));
        }
        page.publish(256).unwrap();
        assert!(page.live(256));
        assert!(page.retire(256));
        assert!(!page.live(256));
        assert!(!page.retire(256));
        assert_eq!(page.publish(256), Err(Error::Retired));
        assert!(!page.live(256));
    }
    #[test]
    fn reused_pid_place_keeps_new_owner_safe_from_old_publish_and_death() {
        let page = Page::new();
        page.publish(256).unwrap();
        page.retire(256);
        page.publish(512).unwrap();
        assert!(page.live(512));
        assert!(!page.live(256));
        assert!(!page.retire(256));
        assert!(page.live(512));
        assert_eq!(page.publish(256), Err(Error::Invalid));
        assert!(page.live(512));
        assert!(page.retire(512));
        page.publish(768).unwrap();
        assert!(page.live(768));
    }
    #[test]
    fn page_size_and_pid_boundaries_preserve_other_places() {
        assert_eq!(core::mem::size_of::<Page>(), SIZE);
        assert_eq!(SIZE, 2048);
        let page = Page::new();
        for pid in [0, 1, 255, i32::MAX as u32 + 1, u32::MAX] {
            assert_eq!(page.publish(pid), Err(Error::Invalid));
            assert!(!page.live(pid));
            assert!(!page.retire(pid));
        }
        page.publish(256).unwrap();
        page.publish(i32::MAX as u32).unwrap();
        assert!(page.live(256));
        assert!(page.live(i32::MAX as u32));
        page.retire(i32::MAX as u32);
        assert!(page.live(256));
    }
}
