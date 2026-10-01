// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! C sleep boundaries and value-only waits in the existing pthread owner.
use super::{Registry, cancel, request, respond};
use crate::{constants::*, fail};
use posix_time::{Observation, Sleep};
use posix_types::Timespec;
use rt::sys;

pub const TIMER_ABSTIME: i32 = 1;
pub(super) const BEGIN: u64 = 25;
pub(super) const ABANDON: u64 = 26;
pub(super) const QUERY: u64 = 27;
pub(super) struct Waiting {
    pub(super) deadline: Sleep,
    pub(super) nonce: u64,
    token: sys::Token,
}
impl Registry {
    /// Expire in the original clock and choose the next representable wake.
    /// Rechecking after every timer/clock notice rejects stale timer deliveries.
    pub(super) fn wait_deadlines(&mut self) -> Option<u64> {
        self.deadlines(false)
    }
    pub(super) fn deadlines(&mut self, force: bool) -> Option<u64> {
        let realtime = self.entries.iter().flatten().any(|e| {
            e.sleep_waiting
                .as_ref()
                .is_some_and(|w| w.deadline.calendar())
        });
        let observation = if realtime || force {
            crate::clock::observation().ok()
        } else {
            None
        };
        let now = now();
        self.sleep_deadlines(now, observation)
            .into_iter()
            .chain(self.signal_deadlines(now))
            .min()
    }
    pub(super) fn sleep_begin(&mut self, caller: usize, words: [u64; 8], token: sys::Token) {
        if let Some(wait) = self.entry_mut(caller).sleep_waiting.as_mut()
            && wait.nonce == words[2]
        {
            wait.token = token;
            return;
        }
        let deadline = Sleep::new(
            words[3] as u32,
            words[4] == TIMER_ABSTIME as u64,
            words[5] as i64,
            words[6] as i64,
            words[7],
        );
        let deadline = match deadline {
            Ok(deadline) if words[4] <= TIMER_ABSTIME as u64 => deadline,
            _ => {
                let answer = self.cache(caller, words[2], Err(EINVAL), BEGIN);
                respond(token, answer);
                return;
            }
        };
        if deadline.calendar() {
            self.deadlines(true);
        }
        self.entry_mut(caller).sleep_waiting = Some(Waiting {
            deadline,
            nonce: words[2],
            token,
        });
    }
    pub(super) fn sleep_deadlines(
        &mut self,
        now: u64,
        observation: Option<Observation>,
    ) -> Option<u64> {
        let mut next: Option<u64> = None;
        for index in 0..self.entries.len() {
            let Some(wait) = self.entries[index]
                .as_ref()
                .and_then(|e| e.sleep_waiting.as_ref())
            else {
                continue;
            };
            let result = match wait.deadline.expired(now, observation) {
                Ok(true) => Some(Ok(0)),
                Err(_) => Some(Err(EIO)),
                Ok(false) => {
                    if let Ok(when) = u64::try_from(
                        wait.deadline
                            .target(observation.map(|o| o.anchor))
                            .expect("validated sleep clock"),
                    ) {
                        next = Some(next.map_or(when, |v| v.min(when)));
                    }
                    None
                }
            };
            if let Some(result) = result {
                let wait = self
                    .entry_mut(index)
                    .sleep_waiting
                    .take()
                    .expect("finished sleep wait");
                let answer = self.cache(index, wait.nonce, result, BEGIN);
                respond(wait.token, answer);
            }
        }
        next
    }
}

fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
/// # Safety
/// The caller is managed. request supplies a readable aligned Timespec; remaining
/// is null or writable. They may name the same object. Absolute calls ignore remaining.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_nanosleep(
    clock: i32,
    flags: i32,
    requested: *const Timespec,
    remaining: *mut Timespec,
) -> i32 {
    let point = cancel::Point::begin();
    let result = (|| {
        if requested.is_null() {
            return Err(EFAULT);
        }
        if !matches!(flags, 0 | TIMER_ABSTIME) {
            return Err(EINVAL);
        }
        // SAFETY: caller supplies one Timespec; copy before touching a possible alias.
        let value = unsafe { requested.read() };
        let start = now();
        let deadline = Sleep::new(
            clock as u32,
            flags == TIMER_ABSTIME,
            value.tv_sec,
            value.tv_nsec,
            start,
        )
        .map_err(|_| EINVAL)?;
        let result = request(
            BEGIN,
            [
                clock as u64,
                flags as u64,
                value.tv_sec as u64,
                value.tv_nsec as u64,
                start,
            ],
        );
        if result == Err(EINTR) {
            // The interrupted request may have committed. Remove its wait before
            // returning or running cancellation cleanup; acknowledgement retries internally.
            request(ABANDON, [0; 5]).expect("interrupted sleep wait release");
            if !remaining.is_null()
                && let Some(time) = deadline.remaining(now()).map_err(|_| EOVERFLOW)?
            {
                // SAFETY: caller supplies writable storage, possibly aliasing the copied request.
                unsafe {
                    remaining.write(Timespec {
                        tv_sec: time.seconds,
                        tv_nsec: time.nanos,
                    })
                };
            }
        }
        result.map(|_| ())
    })();
    point.finish();
    result.map_or_else(|error| error, |()| 0)
}
/// # Safety
/// As for clock_nanosleep with CLOCK_REALTIME and a relative interval.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(requested: *const Timespec, remaining: *mut Timespec) -> i32 {
    let status = unsafe { clock_nanosleep(crate::clock::CLOCK_REALTIME, 0, requested, remaining) };
    if status == 0 { 0 } else { fail(status) as i32 }
}

#[cfg(feature = "transport-probe")]
pub fn probe_waiting(thread: u64) -> Result<bool, i32> {
    request(QUERY, [thread, 0, 0, 0, 0]).map(|value| value != 0)
}

#[cfg(feature = "transport-probe")]
pub fn probe_interrupt_abandon_reply() {
    super::INTERRUPT_REPLIES.fetch_or(1 << ABANDON, core::sync::atomic::Ordering::AcqRel);
}
