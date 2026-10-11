// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A sleep registration owns only Notify custody, never its receiver capability.

use super::{
    wait_receipts::{Id, Queue},
    waiters::{CAPACITY, Pool, RegistrationToken},
};
use proto_fs::{WaitPhase, WaitReply};

struct Notification<H> {
    registration: RegistrationToken,
    handle: H,
}
pub struct Notifications<H> {
    cells: [Option<Notification<H>>; CAPACITY],
}
impl<H> Default for Notifications<H> {
    fn default() -> Self {
        Self::new()
    }
}
impl<H> Notifications<H> {
    pub const fn new() -> Self {
        Self {
            cells: [const { None }; CAPACITY],
        }
    }
    /// # Safety
    /// Exclusive aligned writable uninitialized storage for Self.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: writes each empty cell without constructing an array on stack.
        unsafe {
            let cells =
                core::ptr::addr_of_mut!((*destination).cells).cast::<Option<Notification<H>>>();
            for i in 0..CAPACITY {
                cells.add(i).write(None);
            }
        }
    }
    /// The service has already validated the incoming handle's kind and rights.
    /// On every refusal or duplicate this function closes the incoming copy.
    pub fn arm(
        &mut self,
        queue: &mut Queue,
        sleepers: &Pool,
        id: Id,
        handle: H,
    ) -> Result<WaitReply, u32> {
        let result = queue.query(id)?;
        if result.phase == WaitPhase::Complete {
            return Ok(result);
        }
        let registration = sleepers.find(id).ok_or(proto_fs::INVALID_ARGUMENT)?;
        let cell = &mut self.cells[registration.slot()];
        if cell
            .as_ref()
            .is_some_and(|old| old.registration != registration)
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        queue.arm_registration(id)?;
        if cell.is_none() {
            *cell = Some(Notification {
                registration,
                handle,
            });
        }
        queue.query(id)
    }

    /// Canonical publication precedes notification and closing the last Notify.
    /// The canonical receipt remains payable until the client's explicit Release.
    pub fn complete(
        &mut self,
        queue: &Queue,
        sleepers: &mut Pool,
        id: Id,
        notify: impl FnMut(&H),
    ) -> Result<(), u32> {
        if queue.query(id)?.phase != WaitPhase::Complete {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let Some(registration) = sleepers.find(id) else {
            return Ok(());
        };
        self.complete_registration(queue, sleepers, registration, notify)
    }

    /// O(1) completion for an already validated full registration, without lookup.
    pub fn complete_registration(
        &mut self,
        queue: &Queue,
        sleepers: &mut Pool,
        registration: RegistrationToken,
        mut notify: impl FnMut(&H),
    ) -> Result<(), u32> {
        if queue.query(registration.receipt())?.phase != WaitPhase::Complete {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        sleepers.snapshot(registration)?;
        let cell = &mut self.cells[registration.slot()];
        if cell
            .as_ref()
            .is_some_and(|old| old.registration != registration)
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        if let Some(notification) = cell.take() {
            notify(&notification.handle);
            drop(notification);
        }
        sleepers.complete(registration)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "wait_notifications_tests.rs"]
mod tests;
