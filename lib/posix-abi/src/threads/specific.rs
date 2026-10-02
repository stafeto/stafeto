// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process keys under the layer's lock; each thread's values in its slot of
//! the table of launches; destructors run on the exiting thread after its
//! value was cleared under the lock.

use super::{LAUNCH, current_launch};
use crate::constants::*;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicU64, Ordering},
};
use posix_sync::LayerLock;

pub(super) const COUNT: usize = PTHREAD_KEYS_MAX as usize;
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
struct Registry {
    keys: [Option<Key>; COUNT],
    generation: u64,
}
struct Keys(UnsafeCell<Registry>);
// SAFETY: only `keys` borrows it, under KEYS_LOCK.
unsafe impl Sync for Keys {}
static KEYS: Keys = Keys(UnsafeCell::new(Registry {
    keys: [None; COUNT],
    generation: 1,
}));
static KEYS_LOCK: LayerLock = LayerLock::new();

/// Runs `f` on the keys under the layer's lock.
fn keys<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    let _guard = KEYS_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    f(unsafe { &mut *KEYS.0.get() })
}

impl Registry {
    fn slot(&self, id: u64) -> Result<usize, i32> {
        let slot = (id % COUNT as u64) as usize;
        self.keys[slot]
            .filter(|key| key.id == id)
            .map(|_| slot)
            .ok_or(EINVAL)
    }
}

fn own_values() -> Result<&'static Values, i32> {
    current_launch()
        .map(|launch| &launch.specific)
        .ok_or(EINVAL)
}

/// # Safety
/// key points to writable storage. The optional destructor remains callable
/// while registered and while any already selected invocation is in flight.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_create(key: *mut u64, destructor: Option<Destructor>) -> i32 {
    if key.is_null() {
        return EINVAL;
    }
    let result = keys(|r| {
        let slot = r.keys.iter().position(Option::is_none).ok_or(EAGAIN)?;
        let base = r.generation.checked_mul(COUNT as u64).ok_or(EAGAIN)?;
        let id = base.checked_add(slot as u64).ok_or(EAGAIN)?;
        let next = r.generation.checked_add(1).ok_or(EAGAIN)?;
        for launch in &LAUNCH {
            launch.specific.0[slot].store(0, Ordering::Release);
        }
        r.keys[slot] = Some(Key {
            id,
            destructor: destructor.map_or(0, |f| f as usize as u64),
        });
        r.generation = next;
        Ok(id)
    });
    match result {
        Ok(id) => {
            unsafe { key.write(id) };
            0
        }
        Err(error) => error,
    }
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_key_delete(key: u64) -> i32 {
    keys(|r| {
        let slot = r.slot(key)?;
        r.keys[slot] = None;
        Ok(())
    })
    .map_or_else(|error| error, |()| 0)
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_getspecific(key: u64) -> *mut c_void {
    let Ok(values) = own_values() else {
        return core::ptr::null_mut();
    };
    keys(|r| r.slot(key)).map_or(0, |slot| values.0[slot].load(Ordering::Acquire)) as *mut c_void
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_setspecific(key: u64, value: *const c_void) -> i32 {
    let values = match own_values() {
        Ok(values) => values,
        Err(error) => return error,
    };
    keys(|r| {
        let slot = r.slot(key)?;
        values.0[slot].store(value as u64, Ordering::Release);
        Ok(())
    })
    .map_or_else(|error| error, |()| 0)
}

/// # Safety
/// The calling managed thread is exiting with cancellation disabled. Registered
/// destructors and their non-null arguments satisfy their application contracts.
pub(super) unsafe fn exit_destructors() {
    let Ok(values) = own_values() else {
        return;
    };
    for _ in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        let mut called = false;
        for slot in 0..COUNT {
            if values.0[slot].load(Ordering::Acquire) == 0 {
                continue;
            }
            // The key and its destructor under the lock; the value cleared
            // before the destructor runs outside it.
            let (value, callback) = keys(|r| match r.keys[slot] {
                Some(key) if key.destructor != 0 => {
                    (values.0[slot].swap(0, Ordering::AcqRel), key.destructor)
                }
                _ => (0, 0),
            });
            if value != 0 && callback != 0 {
                // SAFETY: a registered C destructor.
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
