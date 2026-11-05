// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The one receiver of the thread's channel. Every receive of the POSIX
//! layer, of the platform and of the waits on an address goes through
//! `receive` and `try_receive`: a notification with the label of the fast
//! path (see `fast_bank`) is banked and still returned as it came. A process
//! that never claimed the second device has no such notification, so the
//! cost is one comparison of the label; messages and errors are not looked
//! at. A test of the sources (`xtask`, `fast_bank_tests`) fails on any raw
//! `sys::receive(` or `sys::try_receive(` outside the few files that
//! listen on another channel.

use crate::fast_bank::{Bank, FAST_LABEL, FAST_MASK};
use abi::Error;
use rt::handle::{Channel, Handle};
use rt::sys::{self, Received};

static BANK: Bank = Bank::new();

/// The try with this label holds the device: its notifications are banked.
pub fn activate(label: u64) {
    BANK.activate(label);
}

/// Takes the bits the receivers banked (each bit goes to one taker).
pub fn take_pending() -> u32 {
    BANK.take()
}

/// Whether the service let go of its notifications.
pub fn lost() -> bool {
    BANK.lost()
}

#[inline(always)]
fn bank(got: &Result<Received, Error>) {
    if let Ok(Received::Notification { label, bits, .. }) = got
        && label & FAST_MASK == FAST_LABEL
    {
        BANK.deposit(*label, *bits);
    }
}

/// `sys::receive` on the thread's channel with the banking.
pub fn receive(channel: &Handle<Channel>) -> Result<Received, Error> {
    let got = sys::receive(channel);
    bank(&got);
    got
}

/// `sys::try_receive` with the same banking.
pub fn try_receive(channel: &Handle<Channel>) -> Result<Received, Error> {
    let got = sys::try_receive(channel);
    bank(&got);
    got
}
