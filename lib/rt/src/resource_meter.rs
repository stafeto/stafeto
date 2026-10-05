// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private resource measurements around actual returning kernel calls.
//! The sole service thread installs a guard before its first resource operation.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::abi::{Call, Error, ProcessHandles, ProcessMemory};
use crate::handle::{Handle, Process};

struct Meter {
    process: AtomicU64,
    startup: AtomicU64,
    warm: AtomicU64,
    peak: AtomicU64,
    attempts: AtomicU64,
    failures: AtomicU64,
    handle_peak: AtomicU64,
    invalid: AtomicU64,
}

impl Meter {
    const fn new() -> Self {
        Self {
            process: AtomicU64::new(0),
            startup: AtomicU64::new(0),
            warm: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            attempts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            handle_peak: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
        }
    }

    fn record(&self, memory: Result<ProcessMemory, Error>, handles: Result<ProcessHandles, Error>) {
        match (memory, handles) {
            (Ok(memory), Ok(handles)) => {
                self.peak.fetch_max(memory.used, Ordering::Relaxed);
                self.handle_peak.fetch_max(handles.live, Ordering::Relaxed);
            }
            (Err(error), _) | (_, Err(error)) => {
                let _ = self.invalid.compare_exchange(
                    0,
                    error.code(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
        }
    }

    fn sample(&self) {
        let raw = self.process.load(Ordering::Relaxed);
        if raw == 0 {
            return;
        }
        // The guard borrows this exact process handle for the registration's lifetime.
        let process = Handle::<Process>::borrowed(crate::abi::Handle(raw));
        self.record(
            crate::sys::process_memory(&process),
            crate::sys::process_handles(&process),
        );
    }

    fn status(&self) -> Result<(), Error> {
        Error::from_code(self.invalid.load(Ordering::Relaxed)).map_or(Ok(()), Err)
    }

    fn attempt(&self, status: u64) {
        increment(&self.attempts);
        if status != 0 {
            increment(&self.failures);
        }
    }
}

static METER: Meter = Meter::new();
const _: () = assert!(core::mem::size_of::<Meter>() == 64);

fn increment(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

/// One process-local registration on a single service thread.
/// Its borrow keeps the process capability alive until the observer is removed.
pub struct Guard<'a> {
    process: &'a Handle<Process>,
    single_thread: PhantomData<*mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub startup: u64,
    pub warm: u64,
    pub peak: u64,
    pub attempts: u64,
    pub failures: u64,
    pub handle_peak: u64,
}

impl<'a> Guard<'a> {
    pub fn install(process: &'a Handle<Process>) -> Result<Self, Error> {
        if process.raw().0 == 0
            || METER
                .process
                .compare_exchange(0, process.raw().0, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return Err(Error::BadState);
        }
        for value in [
            &METER.startup,
            &METER.warm,
            &METER.peak,
            &METER.attempts,
            &METER.failures,
            &METER.handle_peak,
            &METER.invalid,
        ] {
            value.store(0, Ordering::Relaxed);
        }
        let guard = Self {
            process,
            single_thread: PhantomData,
        };
        let memory = crate::sys::process_memory(process);
        let handles = crate::sys::process_handles(process);
        METER.record(memory, handles);
        METER.status()?;
        METER.startup.store(memory?.used, Ordering::Relaxed);
        Ok(guard)
    }

    /// Establish exactly one separate baseline after the specified warm-up.
    pub fn warm(&mut self) -> Result<(), Error> {
        let memory = crate::sys::process_memory(self.process);
        let handles = crate::sys::process_handles(self.process);
        METER.record(memory, handles);
        METER.status()?;
        let used = memory?.used;
        if used == 0
            || METER
                .warm
                .compare_exchange(0, used, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return Err(Error::BadState);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        METER.sample();
        self.observed()
    }

    /// Inspect the recorded event without introducing another sampling syscall.
    /// Native probes can check an installed resource before its next operation.
    pub fn observed(&self) -> Result<Snapshot, Error> {
        METER.status()?;
        Ok(Snapshot {
            startup: METER.startup.load(Ordering::Relaxed),
            warm: METER.warm.load(Ordering::Relaxed),
            peak: METER.peak.load(Ordering::Relaxed),
            attempts: METER.attempts.load(Ordering::Relaxed),
            failures: METER.failures.load(Ordering::Relaxed),
            handle_peak: METER.handle_peak.load(Ordering::Relaxed),
        })
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        METER.process.store(0, Ordering::Relaxed);
    }
}

pub(crate) fn before<const N: u16>() {
    // ObjectInfo reads only registers and never allocates or consumes incoming caps.
    // Excluding it also terminates the sampler's own ObjectInfo calls.
    if N != Call::ObjectInfo.number() {
        METER.sample();
    }
}

pub(crate) fn after<const N: u16>(status: u64) {
    if N == Call::ObjectInfo.number() || METER.process.load(Ordering::Relaxed) == 0 {
        return;
    }
    if matches!(N, n if n == Call::HandleDuplicate.number()
        || n == Call::CreateChannel.number() || n == Call::MemCreate.number()
        || n == Call::MemMap.number() || n == Call::TimerCreate.number()
        || n == Call::ProcessCreate.number() || n == Call::ThreadCreate.number()
        || n == Call::DeviceWindowCreate.number() || n == Call::IrqBind.number())
    {
        METER.attempt(status);
    }
    METER.sample();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory(used: u64) -> Result<ProcessMemory, Error> {
        Ok(ProcessMemory {
            quota: 1000,
            used,
            returned: 0,
        })
    }
    fn handles(live: u64) -> Result<ProcessHandles, Error> {
        Ok(ProcessHandles {
            live,
            retired: 0,
            limit: 128,
        })
    }

    #[test]
    fn peaks_survive_temporary_resource_release_and_preserve_warm_baseline() {
        let meter = Meter::new();
        meter.warm.store(120, Ordering::Relaxed);
        meter.record(memory(120), handles(8));
        meter.record(memory(240), handles(13));
        meter.record(memory(120), handles(8));
        assert_eq!(meter.peak.load(Ordering::Relaxed), 240);
        assert_eq!(meter.handle_peak.load(Ordering::Relaxed), 13);
        assert_eq!(meter.warm.load(Ordering::Relaxed), 120);
        assert_eq!(core::mem::size_of::<Meter>(), 64);
    }

    #[test]
    fn observation_failure_stays_invalid_after_successful_queries() {
        let meter = Meter::new();
        meter.record(memory(120), Err(Error::BadHandle));
        meter.record(Err(Error::AccessDenied), handles(9));
        meter.record(memory(240), handles(13));
        assert_eq!(meter.status(), Err(Error::BadHandle));
    }

    #[test]
    fn actual_attempt_status_counts_failures_and_saturates() {
        let meter = Meter::new();
        meter.attempt(0);
        meter.attempt(Error::NoMemory.code());
        assert_eq!(meter.attempts.load(Ordering::Relaxed), 2);
        assert_eq!(meter.failures.load(Ordering::Relaxed), 1);
        meter.attempts.store(u64::MAX, Ordering::Relaxed);
        meter.attempt(Error::LimitReached.code());
        assert_eq!(meter.attempts.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(meter.failures.load(Ordering::Relaxed), 2);
    }
}
