// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Following a redirect of the RAM file service (`proto_fs::REDIRECT`).
//!
//! A walk of the service that meets the mount point of `/data` through a symbolic link ends with
//! the answer REDIRECT and the absolute path to continue with. The request layer (`rt::fs`) hands
//! that path to `store`, which keeps it for the calling thread, and the call fails. The call that
//! asked (`follow`) takes the path and runs the same operation once more against it: a path under
//! `/data` goes to the data service, any other path to the RAM file service again. A second
//! redirect in that second run is ELOOP: the layer follows one level.
//!
//! The paths wait in a small table keyed by the thread's block, so a failing call on one thread
//! never hands its path to another. A table with no free place drops the path, and the failing
//! call keeps its own errno (EXDEV).

use crate::constants::ELOOP;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

const PLACES: usize = 16;
const MAX: usize = proto_fs::MAX_PATH;

struct Place {
    /// The thread that keeps a path here, 0 when the place is free.
    key: AtomicUsize,
    length: AtomicUsize,
    bytes: UnsafeCell<[u8; MAX]>,
}

// SAFETY: the bytes and the length belong to the thread whose key the place holds, and to no other
// thread until that thread frees the place.
unsafe impl Sync for Place {}

static PLACES_TABLE: [Place; PLACES] = [const {
    Place {
        key: AtomicUsize::new(0),
        length: AtomicUsize::new(0),
        bytes: UnsafeCell::new([0; MAX]),
    }
}; PLACES];

/// The key of the calling thread: its block's place, 1 for a thread with none.
fn key() -> usize {
    let block = posix_thread::block() as usize;
    if block == 0 { 1 } else { block }
}

/// Keeps the path of a redirect for the calling thread (the sink of `rt::fs`).
fn store(path: &[u8]) {
    if path.is_empty() || path.len() > MAX {
        return;
    }
    let me = key();
    let place = PLACES_TABLE
        .iter()
        .find(|place| place.key.load(Ordering::Acquire) == me)
        .or_else(|| {
            PLACES_TABLE.iter().find(|place| {
                place
                    .key
                    .compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            })
        });
    let Some(place) = place else {
        return;
    };
    // SAFETY: the place holds this thread's key.
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr(), place.bytes.get().cast::<u8>(), path.len())
    };
    place.length.store(path.len(), Ordering::Release);
}

/// Takes the path the calling thread kept: its length, the bytes in `out`.
fn take(out: &mut [u8; MAX]) -> Option<usize> {
    let me = key();
    let place = PLACES_TABLE
        .iter()
        .find(|place| place.key.load(Ordering::Acquire) == me)?;
    let length = place.length.swap(0, Ordering::AcqRel).min(MAX);
    // SAFETY: as above; `length` is at most MAX.
    unsafe {
        core::ptr::copy_nonoverlapping(place.bytes.get().cast::<u8>(), out.as_mut_ptr(), length)
    };
    place.key.store(0, Ordering::Release);
    (length > 0).then_some(length)
}

/// Forgets the path the calling thread kept.
fn clear() {
    let mut scratch = [0; MAX];
    let _ = take(&mut scratch);
}

/// Runs `attempt` against the path of the call (`None`), and when the RAM file service answers it
/// with a redirect, once more against the path the redirect names (`Some(absolute path)`). A
/// redirect of that second run is ELOOP.
pub(crate) fn follow<T>(
    mut attempt: impl FnMut(Option<&[u8]>) -> Result<T, i32>,
) -> Result<T, i32> {
    rt::fs::set_redirect_sink(store);
    clear();
    let first = attempt(None);
    if first.is_ok() {
        return first;
    }
    let mut target = [0; MAX];
    let Some(length) = take(&mut target) else {
        return first;
    };
    // The dots go first, as for every path of the layer: a path that leaves /data by `..` is a
    // path of the RAM file service.
    let mut simple = [0; MAX + 1];
    let length = posix_path::simplify(&target[..length], &mut simple);
    let second = attempt(Some(&simple[..length]));
    if second.is_ok() {
        return second;
    }
    if take(&mut target).is_some() {
        return Err(ELOOP);
    }
    second
}
