// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process keys serialized by the pthread owner; callbacks run on the exiting
//! application thread after the owner clears each selected value.

use super::{LAUNCH, current_launch, request, request_pair};
use crate::constants::*;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicU64, Ordering},
};

pub(super) const COUNT: usize = PTHREAD_KEYS_MAX as usize;
pub(super) const CREATE: u64 = 9;
pub(super) const DELETE: u64 = 10;
pub(super) const GET: u64 = 11;
pub(super) const SET: u64 = 12;
pub(super) const TAKE: u64 = 13;
type Destructor = unsafe extern "C" fn(*mut c_void);

pub(super) struct Values([AtomicU64; COUNT]);
impl Values {
    pub(super) const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; COUNT])
    }
    pub(super) fn reset(&self) {
        for value in &self.0 {
            value.store(0, Ordering::Release);
        }
    }
}

#[derive(Clone, Copy)]
struct Key {
    id: u64,
    destructor: u64,
}
pub(super) struct Registry {
    keys: [Option<Key>; COUNT],
    generation: u64,
}
impl Registry {
    pub(super) const fn new() -> Self {
        Self {
            keys: [None; COUNT],
            generation: 1,
        }
    }
    fn slot(&self, id: u64) -> Result<usize, i32> {
        let slot = (id % COUNT as u64) as usize;
        self.keys[slot]
            .filter(|key| key.id == id)
            .map(|_| slot)
            .ok_or(EINVAL)
    }
    // Only the single pthread owner calls this method or resets launch values.
    pub(super) fn perform(&mut self, caller: usize, words: [u64; 8]) -> Result<(u64, u64), i32> {
        match words[0] {
            CREATE => {
                let slot = self.keys.iter().position(Option::is_none).ok_or(EAGAIN)?;
                let base = self.generation.checked_mul(COUNT as u64).ok_or(EAGAIN)?;
                let id = base.checked_add(slot as u64).ok_or(EAGAIN)?;
                let next = self.generation.checked_add(1).ok_or(EAGAIN)?;
                for launch in &LAUNCH {
                    launch.specific.0[slot].store(0, Ordering::Release);
                }
                self.keys[slot] = Some(Key {
                    id,
                    destructor: words[3],
                });
                self.generation = next;
                Ok((id, 0))
            }
            DELETE => {
                let slot = self.slot(words[3])?;
                self.keys[slot] = None;
                Ok((0, 0))
            }
            GET | SET => {
                let slot = self.slot(words[3])?;
                let value = &LAUNCH[caller].specific.0[slot];
                if words[0] == SET {
                    value.store(words[4], Ordering::Release);
                    Ok((0, 0))
                } else {
                    Ok((value.load(Ordering::Acquire), 0))
                }
            }
            TAKE => {
                let slot = usize::try_from(words[3]).map_err(|_| EINVAL)?;
                let key = self.keys.get(slot).ok_or(EINVAL)?;
                let Some(key) = key.filter(|key| key.destructor != 0) else {
                    return Ok((0, 0));
                };
                let value = LAUNCH[caller].specific.0[slot].swap(0, Ordering::AcqRel);
                Ok((value, key.destructor))
            }
            _ => Err(EINVAL),
        }
    }
}

/// # Safety
/// key points to writable storage. The optional destructor remains callable
/// while registered and while any already selected invocation is in flight.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_create(key: *mut u64, destructor: Option<Destructor>) -> i32 {
    if key.is_null() {
        return EINVAL;
    }
    match request(
        CREATE,
        [destructor.map_or(0, |f| f as usize as u64), 0, 0, 0, 0],
    ) {
        Ok(id) => {
            unsafe { key.write(id) };
            0
        }
        Err(error) => error,
    }
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_key_delete(key: u64) -> i32 {
    request(DELETE, [key, 0, 0, 0, 0]).map_or_else(|error| error, |_| 0)
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_getspecific(key: u64) -> *mut c_void {
    request(GET, [key, 0, 0, 0, 0]).unwrap_or(0) as *mut c_void
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_setspecific(key: u64, value: *const c_void) -> i32 {
    request(SET, [key, value as u64, 0, 0, 0]).map_or_else(|error| error, |_| 0)
}

/// # Safety
/// The calling managed thread is exiting with cancellation disabled. Registered
/// destructors and their non-null arguments satisfy their application contracts.
pub(super) unsafe fn exit_destructors() {
    let values = &current_launch()
        .expect("managed thread-specific values")
        .specific;
    for _ in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        let mut called = false;
        for slot in 0..COUNT {
            // An empty binding cannot require a destructor. Only the owner
            // writes values; this acquire observes acknowledged SET operations.
            if values.0[slot].load(Ordering::Acquire) == 0 {
                continue;
            }
            let (value, callback) = request_pair(TAKE, [slot as u64, 0, 0, 0, 0])
                .expect("managed thread-specific destruction");
            if value != 0 && callback != 0 {
                // SAFETY: the owner selected a registered C destructor and
                // cleared this value before returning the cached snapshot.
                let destructor: Destructor = unsafe { core::mem::transmute(callback as usize) };
                unsafe { destructor(value as *mut c_void) };
                called = true;
            }
        }
        if !called {
            break;
        }
    }
}

#[cfg(feature = "transport-probe")]
pub fn probe_interrupt_replies() {
    super::INTERRUPT_REPLIES.fetch_or(
        (1 << CREATE) | (1 << DELETE) | (1 << GET) | (1 << SET) | (1 << TAKE),
        Ordering::AcqRel,
    );
}
