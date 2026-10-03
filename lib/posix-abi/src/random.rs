// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's generator of random bytes (step 5e'): ChaCha20 with fast
//! key erasure (posix_random), keyed with 32 bytes of the entropy service
//! (proto_entropy, SEED) at its first use and again after REKEY_BYTES of
//! output. `getentropy`, `getrandom` and, through relibc, `arc4random` read
//! it with no request to a service in between. Its state lies under a lock
//! of the layer, taken for a piece of PIECE bytes at a time; the key is
//! asked for outside the lock, a long operation in two steps that waits
//! for the service's first bytes of the device. A forked child forgets the
//! key and the buffer (`after_fork`): its first call asks for a key of its
//! own, so it never gives its parent's bytes. A process without a session
//! with the service gets ENOSYS.

use crate::constants::*;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};
use posix_random::{Generator, KEY};
use posix_sync::LayerLock;
use proto_entropy::{Key, Method, NONBLOCK, NOT_READY, SEED_LEN, Seed};
use proto_wire::{Status, Writer};
use rt::abi::Error;
use rt::handle::{Channel, Handle};

/// {GETENTROPY_MAX}: the most one `getentropy` gives (POSIX.1-2024).
pub const GETENTROPY_MAX: usize = 256;
/// The flags of `getrandom` (Linux): GRND_RANDOM takes the same
/// generator, as Linux does since 5.6; GRND_INSECURE waits for the key as
/// well, since without one there is nothing to give.
pub const GRND_NONBLOCK: u32 = 1;
pub const GRND_RANDOM: u32 = 2;
pub const GRND_INSECURE: u32 = 4;
/// The output of one key, after which the next use asks for another.
pub const REKEY_BYTES: u64 = 1 << 20;
/// The bytes one hold of the lock gives at most.
const PIECE: usize = 512;
/// The generator's buffer: 8 blocks, 512 bytes.
const BLOCKS: usize = 8;

const _: () = assert!(SEED_LEN == KEY);

struct State {
    generator: Generator<BLOCKS>,
    /// The bytes given since the last key.
    given: u64,
}

struct Cell(UnsafeCell<State>);

// SAFETY: the state is borrowed under LOCK alone, or by a forked child's
// only thread before anything else runs (`after_fork`).
unsafe impl Sync for Cell {}

static STATE: Cell = Cell(UnsafeCell::new(State {
    generator: Generator::new(),
    given: 0,
}));
static LOCK: LayerLock = LayerLock::raising();
/// The session with the entropy service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// Runs `f` on the state under the lock.
fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let _guard = LOCK.lock();
    // SAFETY: LOCK is held, so this borrow is the only one.
    f(unsafe { &mut *STATE.0.get() })
}

/// The process's session with the entropy service, which the start gives
/// (init's CONNECT, or the loader's slot Entropy).
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// A forked child: the copy of the parent's key and buffer goes, and its
/// own session (`session`, a clone the parent made) takes the place of the
/// parent's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    // SAFETY: the caller's promise: no other borrow, and the lock word was
    // free in the copy (fork stopped the other threads outside it).
    let state = unsafe { &mut *STATE.0.get() };
    state.generator.forget();
    state.given = 0;
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
}

/// The session with the entropy service, for the clones a child gets.
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}

/// A key of the service: it waits for the service's first bytes unless
/// `nonblock` (EAGAIN then); EINTR when a signal handler without
/// SA_RESTART ran meanwhile; ENOSYS without a session.
fn key(nonblock: bool) -> Result<[u8; KEY], i32> {
    let service = Handle::<Channel>::borrowed(session().ok_or(ENOSYS)?);
    let mut start = Writer::new();
    let flags = if nonblock { NONBLOCK } else { 0 };
    Seed { flags }.write(&mut start).map_err(|_| EIO)?;
    let keyed = |cancel: bool, key: u64, w: &mut Writer| {
        let method = if cancel {
            Method::SeedCancel
        } else {
            Method::SeedTake
        };
        Key { key }.write(method, w)
    };
    let refusal = |status: Status| match status {
        s if s == NOT_READY => Some(EAGAIN),
        Status::Kernel(Error::InvalidArgs) => Some(EINVAL),
        _ => None,
    };
    let mut out = [0; KEY];
    let n = crate::long::run_with(&service, start.as_bytes(), keyed, &mut out, &refusal)?;
    if n != KEY {
        posix_random::erase(&mut out);
        return Err(EIO);
    }
    Ok(out)
}

/// Fills `out` from the generator, asking the service for a key first
/// when there is none or the last gave REKEY_BYTES; a key mixes into the
/// one before it (posix_random::Generator::reseed).
pub fn fill(out: &mut [u8], nonblock: bool) -> Result<(), i32> {
    let mut done = 0;
    while done < out.len() {
        let wants = with_state(|s| !s.generator.seeded() || s.given >= REKEY_BYTES);
        if wants {
            // EAGAIN of a wait that may wait: every place for a waiting
            // seed in the service is taken (the boot's first moments); it
            // comes again once the service answers. The yield lets the
            // service and its feeder, above every process, go on.
            let mut new = loop {
                match key(nonblock) {
                    Err(EAGAIN) if !nonblock => {
                        let _ = rt::sys::yield_now();
                    }
                    other => break other?,
                }
            };
            with_state(|s| {
                if !s.generator.seeded() {
                    s.generator.seed(&new);
                    s.given = 0;
                } else if s.given >= REKEY_BYTES {
                    s.generator.reseed(&new);
                    s.given = 0;
                }
            });
            posix_random::erase(&mut new);
        }
        let end = (done + PIECE).min(out.len());
        let filled = with_state(|s| {
            let filled = s.generator.fill(&mut out[done..end]);
            if filled {
                s.given += (end - done) as u64;
            }
            filled
        });
        // A generator that went unseeded meanwhile asks again.
        if filled {
            done = end;
        }
    }
    Ok(())
}

/// getentropy ([P24-GETENTROPY]): `buffer.len()` bytes, GETENTROPY_MAX at
/// most (EINVAL past it); it waits for the service's first bytes, again
/// after a signal handler (EINTR is no error of getentropy). ENOSYS
/// without the service.
pub fn getentropy(buffer: &mut [u8]) -> Result<(), i32> {
    if buffer.len() > GETENTROPY_MAX {
        return Err(EINVAL);
    }
    loop {
        match fill(buffer, false) {
            Err(EINTR) => continue,
            other => return other,
        }
    }
}

/// getrandom (Linux): every byte asked for once the generator has a key;
/// before, EAGAIN with GRND_NONBLOCK, else a wait that a signal handler
/// ends with EINTR. EINVAL for an unknown flag or GRND_RANDOM with
/// GRND_INSECURE.
pub fn getrandom(buffer: &mut [u8], flags: u32) -> Result<usize, i32> {
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || flags & (GRND_RANDOM | GRND_INSECURE) == GRND_RANDOM | GRND_INSECURE
    {
        return Err(EINVAL);
    }
    fill(buffer, flags & GRND_NONBLOCK != 0)?;
    Ok(buffer.len())
}
