// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Optional ownership in one raw handle word. Used by retained identity debts.

use crate::{handle::Handle, sys};
use core::marker::PhantomData;

pub struct Compact<K> {
    raw: abi::Handle,
    kind: PhantomData<K>,
}

impl<K> Compact<K> {
    pub const fn empty() -> Self {
        Self {
            raw: abi::Handle::INVALID,
            kind: PhantomData,
        }
    }

    pub fn from_owner(owner: Option<Handle<K>>) -> Self {
        match owner {
            None => Self::empty(),
            Some(owner) => {
                assert!(owner.raw() != abi::Handle::INVALID, "invalid compact owner");
                Self {
                    raw: owner.into_raw(),
                    kind: PhantomData,
                }
            }
        }
    }

    pub fn is_some(&self) -> bool {
        self.raw != abi::Handle::INVALID
    }

    /// The borrowed handle cannot escape this operation or outlive the owner.
    pub fn with_view<R>(&self, operation: impl FnOnce(&Handle<K>) -> R) -> Option<R> {
        if !self.is_some() {
            return None;
        }
        let view = Handle::borrowed(self.raw);
        Some(operation(&view))
    }

    pub fn take(&mut self) -> Option<Handle<K>> {
        if !self.is_some() {
            return None;
        }
        let raw = core::mem::replace(&mut self.raw, abi::Handle::INVALID);
        Some(Handle::from_raw(raw))
    }

    pub fn close_retained(&mut self) -> Result<bool, abi::Error> {
        if !self.is_some() {
            return Ok(false);
        }
        sys::close_raw(self.raw)?;
        self.raw = abi::Handle::INVALID;
        Ok(true)
    }
}

impl<K> Drop for Compact<K> {
    fn drop(&mut self) {
        if self.is_some() {
            let _ = sys::close_raw(self.raw);
        }
    }
}
