// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Typed handles (spec 5, 13.2). A handle carries the kind of its object in
//! its type, so that a channel does not go where a thread is due. It is
//! neither `Copy` nor `Clone`: `close` takes it, so a program cannot use
//! the value of a handle it closed (spec 5.4). A handle that goes out of
//! scope stays open until milestone 1.4 closes it on drop. `from_raw` and
//! `raw` are for tests that hand the kernel values it must refuse.

use core::fmt;
use core::marker::PhantomData;

/// A handle to an object of kind `K`: `Channel`, `Timer`, `Process`,
/// `Thread`, `Resource` or `Memory`.
#[repr(transparent)]
pub struct Handle<K> {
    raw: abi::Handle,
    kind: PhantomData<K>,
}

/// A channel (spec 6).
pub enum Channel {}
/// A timer (spec 10).
pub enum Timer {}
/// A process (spec 4).
pub enum Process {}
/// A thread (spec 8).
pub enum Thread {}
/// The system resource (spec 4).
pub enum Resource {}
/// A memory object (spec 7.3).
pub enum Memory {}

impl<K> Handle<K> {
    /// The handle with the value `raw`; the kernel checks the kind at each
    /// call (WRONG_TYPE).
    pub const fn from_raw(raw: abi::Handle) -> Handle<K> {
        Handle {
            raw,
            kind: PhantomData,
        }
    }

    /// The value the kernel knows the handle by.
    pub const fn raw(&self) -> abi::Handle {
        self.raw
    }
}

impl<K> PartialEq for Handle<K> {
    fn eq(&self, other: &Handle<K>) -> bool {
        self.raw == other.raw
    }
}

impl<K> Eq for Handle<K> {}

impl<K> fmt::Debug for Handle<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.fmt(f)
    }
}
