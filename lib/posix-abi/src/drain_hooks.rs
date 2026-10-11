// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Register recovery before the first paid drain, without rooting its driver
//! from ordinary file operations that never start a drain.

use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use entries::Frame;
use posix_fd::OwnerToken;

pub(crate) struct Hooks {
    pub detach: fn(u64) -> bool,
    pub help: fn(),
    pub collect: fn(OwnerToken, Frame),
}

struct Registry(AtomicPtr<Hooks>);
const _: () = assert!(core::mem::size_of::<Registry>() == core::mem::size_of::<usize>());
impl Registry {
    const fn new() -> Self {
        Self(AtomicPtr::new(ptr::null_mut()))
    }
    fn register(&self, hooks: &'static Hooks) {
        // Every production caller installs the same immutable static table
        // before admitting a hold or record. It is never removed, including
        // in a forked child whose inherited records were already discarded.
        self.0
            .store(ptr::from_ref(hooks).cast_mut(), Ordering::Release);
    }
    fn hooks(&self) -> Option<&'static Hooks> {
        let hooks = self.0.load(Ordering::Acquire);
        // SAFETY: register stores only an immutable &'static Hooks. Readers
        // never mutate it, and the entire table precedes the Release store.
        unsafe { hooks.as_ref() }
    }
    fn detach(&self, owner: u64) -> bool {
        self.hooks().is_none_or(|hooks| (hooks.detach)(owner))
    }
    fn help(&self) {
        if let Some(hooks) = self.hooks() {
            (hooks.help)();
        }
    }
    fn collect(&self, owner: OwnerToken, frame: Frame) {
        if let Some(hooks) = self.hooks() {
            (hooks.collect)(owner, frame);
        }
    }
}

static REGISTRY: Registry = Registry::new();

pub(crate) fn register(hooks: &'static Hooks) {
    REGISTRY.register(hooks);
}
pub(crate) fn detach(owner: u64) -> bool {
    REGISTRY.detach(owner)
}
pub(crate) fn help() {
    REGISTRY.help();
}
pub(crate) fn collect(owner: OwnerToken, frame: Frame) {
    REGISTRY.collect(owner, frame);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU64;
    use std::sync::Mutex;

    static TEST: Mutex<()> = Mutex::new(());
    static DETACHED: AtomicU64 = AtomicU64::new(0);
    static HELPED: AtomicU64 = AtomicU64::new(0);
    static OWNER: AtomicU64 = AtomicU64::new(0);
    static SP: AtomicU64 = AtomicU64::new(0);
    static Z: AtomicU64 = AtomicU64::new(0);
    static HOOKS: Hooks = Hooks {
        detach: |owner| {
            DETACHED.store(owner, Ordering::Relaxed);
            owner != 0xfeed
        },
        help: || {
            HELPED.fetch_add(1, Ordering::Relaxed);
        },
        collect: |owner, frame| {
            OWNER.store(owner.value(), Ordering::Relaxed);
            SP.store(frame.sp, Ordering::Relaxed);
            Z.store(frame.z.into(), Ordering::Relaxed);
        },
    };

    #[test]
    fn absent_registration_has_no_debt_or_callback() {
        let _test = TEST.lock().unwrap();
        let registry = Registry::new();
        DETACHED.store(0, Ordering::Relaxed);
        HELPED.store(0, Ordering::Relaxed);
        OWNER.store(0, Ordering::Relaxed);
        assert!(registry.detach(0xfeed));
        registry.help();
        registry.collect(OwnerToken::new(91).unwrap(), Frame::main(700));
        assert_eq!(DETACHED.load(Ordering::Relaxed), 0);
        assert_eq!(HELPED.load(Ordering::Relaxed), 0);
        assert_eq!(OWNER.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn installed_callbacks_preserve_exact_owner_frame_and_refusal() {
        let _test = TEST.lock().unwrap();
        let registry = Registry::new();
        registry.register(&HOOKS);
        assert!(!registry.detach(0xfeed));
        assert_eq!(DETACHED.load(Ordering::Relaxed), 0xfeed);
        assert!(registry.detach(0x1_0000_0003));
        assert_eq!(DETACHED.load(Ordering::Relaxed), 0x1_0000_0003);
        HELPED.store(0, Ordering::Relaxed);
        registry.help();
        assert_eq!(HELPED.load(Ordering::Relaxed), 1);
        registry.collect(
            OwnerToken::new(0x2_0000_0009).unwrap(),
            Frame {
                z: 1,
                sp: 0x1_0000_4560,
            },
        );
        assert_eq!(OWNER.load(Ordering::Relaxed), 0x2_0000_0009);
        assert_eq!(SP.load(Ordering::Relaxed), 0x1_0000_4560);
        assert_eq!(Z.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn static_registration_survives_repeat_and_cross_thread_dispatch() {
        let _test = TEST.lock().unwrap();
        let registry = std::sync::Arc::new(Registry::new());
        registry.register(&HOOKS);
        HELPED.store(0, Ordering::Relaxed);
        let other = std::sync::Arc::clone(&registry);
        std::thread::spawn(move || {
            other.register(&HOOKS);
            other.collect(OwnerToken::new(0x3_0000_0001).unwrap(), Frame::main(999));
            other.help();
            assert!(!other.detach(0xfeed));
        })
        .join()
        .unwrap();
        assert_eq!(HELPED.load(Ordering::Relaxed), 1);
        assert_eq!(OWNER.load(Ordering::Relaxed), 0x3_0000_0001);
        assert_eq!(SP.load(Ordering::Relaxed), 999);
        assert_eq!(Z.load(Ordering::Relaxed), 0);
        assert!(!registry.detach(0xfeed));
    }

    #[test]
    fn production_dispatch_uses_the_registered_table() {
        let _test = TEST.lock().unwrap();
        register(&HOOKS);
        assert!(!detach(0xfeed));
        HELPED.store(0, Ordering::Relaxed);
        help();
        collect(OwnerToken::new(0x4_0000_0001).unwrap(), Frame::main(123));
        assert_eq!(HELPED.load(Ordering::Relaxed), 1);
        assert_eq!(OWNER.load(Ordering::Relaxed), 0x4_0000_0001);
        assert_eq!(SP.load(Ordering::Relaxed), 123);
    }
}
