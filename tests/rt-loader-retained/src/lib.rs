// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Host fault injection for the retained loader, with simulated kernel calls.

#![cfg(test)]
#![allow(dead_code)]
#[path = "../../../lib/rt/src/handle.rs"]
pub mod handle;
pub mod msgbuf {
    pub fn handle(_: usize) -> (abi::Handle, (abi::ObjectKind, abi::Rights)) {
        panic!("unused message buffer")
    }
}
pub mod sys {
    use super::handle::{Handle, Memory, Process};
    use abi::{Access, Error, Rights};
    use std::{cell::RefCell, collections::BTreeMap};
    #[derive(Default)]
    pub struct State {
        pub calls: usize,
        pub fail: usize,
        pub next: u64,
        pub handles: BTreeMap<u64, Rights>,
        pub window: bool,
        pub maps: Vec<(u64, Rights)>,
    }
    thread_local! {pub static STATE:RefCell<State>=RefCell::new(State::default());}
    pub fn call() -> Result<(), Error> {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.calls += 1;
            if s.calls == s.fail {
                Err(Error::NoMemory)
            } else {
                Ok(())
            }
        })
    }
    pub fn new<K>(rights: Rights) -> Handle<K> {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.next += 1;
            let n = s.next + 10;
            s.handles.insert(n, rights);
            Handle::from_raw(abi::Handle(n))
        })
    }
    pub fn close_raw(h: abi::Handle) -> Result<(), Error> {
        if h.0 <= 2 {
            return Ok(());
        }
        call()?;
        STATE.with(|s| {
            assert!(s.borrow_mut().handles.remove(&h.0).is_some());
        });
        Ok(())
    }
    pub fn mem_create(_: u64) -> Result<Handle<Memory>, Error> {
        call()?;
        Ok(new(Rights::ALL))
    }
    pub fn handle_duplicate<K>(h: &Handle<K>, rights: Rights) -> Result<Handle<K>, Error> {
        call()?;
        STATE.with(|s| assert!(s.borrow().handles[&h.raw().0].contains(rights)));
        Ok(new(rights))
    }
    pub fn mem_map(
        p: &Handle<Process>,
        m: &Handle<Memory>,
        _: u64,
        _: u64,
        _: usize,
        a: Access,
    ) -> Result<(), Error> {
        call()?;
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            let r = s.handles[&m.raw().0];
            assert!(r.contains(a.rights()));
            if p.raw().0 == 1 {
                assert!(!s.window);
                s.window = true;
            } else {
                s.maps.push((m.raw().0, r));
            }
        });
        Ok(())
    }
    /// # Safety
    /// The simulated window must be live and unused by the test.
    pub unsafe fn mem_unmap(_: &Handle<Process>, _: usize, _: u64) -> Result<(), Error> {
        call()?;
        STATE.with(|s| {
            assert!(s.borrow().window);
            s.borrow_mut().window = false;
        });
        Ok(())
    }
}
mod loader;
#[cfg(test)]
mod tests {
    use super::*;
    use abi::{Access, Policy, Rights};
    use bootimg::{Program, Segment};
    use loader::retained::*;
    #[allow(clippy::result_large_err)] // Exercise the exact fixed custody state.
    fn run(fail: usize) -> Result<RetainedImage, FillFailure> {
        sys::STATE.with(|s| {
            *s.borrow_mut() = sys::State {
                fail,
                ..Default::default()
            }
        });
        let own = handle::Handle::borrowed(abi::Handle(1));
        let target = handle::Handle::borrowed(abi::Handle(2));
        let p = Program {
            entry: 4096,
            stack_size: 4096,
            segments: [
                Segment {
                    vaddr: 4096,
                    mem_size: 4096,
                    bytes: &[1, 2, 3, 4],
                },
                Segment {
                    vaddr: 8192,
                    mem_size: 4096,
                    bytes: &[5],
                },
                Segment {
                    vaddr: 12288,
                    mem_size: 4096,
                    bytes: &[6],
                },
            ],
        };
        let mut window = vec![0; 8192];
        // Tests never use the window after this call. Fake mapping uses this live allocation.
        unsafe {
            fill_retained(
                &own,
                &target,
                &p,
                window.as_mut_ptr() as usize,
                1,
                Policy::Fifo,
            )
        }
    }
    fn cleanup(f: &mut FillFailure) {
        let own = handle::Handle::borrowed(abi::Handle(1));
        sys::STATE.with(|s| s.borrow_mut().fail = 0);
        for _ in 0..16 {
            if unsafe { f.cleanup_one(&own) }.unwrap() {
                return;
            }
        }
        panic!("cleanup failed to terminate")
    }
    #[test]
    fn successful_rights_and_four_objects() {
        let i = run(0).ok().unwrap();
        assert_eq!(i.segments.iter().flatten().count(), 4);
        for segment in i.segments.iter().flatten() {
            let r = sys::STATE.with(|s| s.borrow().handles[&segment.memory().unwrap().raw().0]);
            assert!(r.contains(Rights::MAP_READ | Rights::DUPLICATE | Rights::TRANSFER));
            assert!(!r.contains(Rights::MAP_EXEC));
            assert_eq!(
                r.contains(Rights::MAP_WRITE),
                segment.mapping.access == Access::ReadWrite
            );
        }
        sys::STATE.with(|s| {
            let s = s.borrow();
            assert!(!s.window);
            assert_eq!(s.maps.len(), 4);
            assert!(s.maps[0].1.contains(Rights::MAP_EXEC));
        });
        drop(i);
        sys::STATE.with(|s| assert!(s.borrow().handles.is_empty()));
    }
    #[test]
    fn every_syscall_failure_retains_all_local_custody() {
        let ok = run(0).ok().unwrap();
        let total = sys::STATE.with(|s| s.borrow().calls);
        drop(ok);
        assert!(total > 20);
        for fail in 1..=total {
            let mut f = run(fail).err().expect("injected failure");
            assert_eq!(
                sys::STATE.with(|s| s.borrow().calls),
                fail,
                "hidden cleanup after failure"
            );
            assert_eq!(
                f.window().is_some(),
                sys::STATE.with(|s| s.borrow().window),
                "call {fail}"
            );
            let mapped = f
                .segments()
                .iter()
                .flatten()
                .filter(|s| s.mapping.installed)
                .count()
                + usize::from(f.pending_mapping().is_some_and(|m| m.installed));
            assert_eq!(
                mapped,
                sys::STATE.with(|s| s.borrow().maps.len()),
                "call {fail}"
            );
            cleanup(&mut f);
            sys::STATE.with(|s| assert!(s.borrow().handles.is_empty(), "call {fail}"));
            let after = f
                .segments()
                .iter()
                .flatten()
                .filter(|s| s.mapping.installed)
                .count()
                + usize::from(f.pending_mapping().is_some_and(|m| m.installed));
            assert_eq!(after, mapped);
        }
    }
    #[test]
    fn cleanup_failure_preserves_handles_and_window() {
        let total = {
            let i = run(0).ok().unwrap();
            let t = sys::STATE.with(|s| s.borrow().calls);
            drop(i);
            t
        };
        for fail in 1..=total {
            let mut f = run(fail).err().unwrap();
            let before = sys::STATE.with(|s| s.borrow().handles.clone());
            let window = f.window();
            sys::STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.fail = s.calls + 1;
            });
            let own = handle::Handle::borrowed(abi::Handle(1));
            if !before.is_empty() || window.is_some() {
                assert!(unsafe { f.cleanup_one(&own) }.is_err());
                assert_eq!(before, sys::STATE.with(|s| s.borrow().handles.clone()));
                assert_eq!(window, f.window());
            }
            cleanup(&mut f);
        }
    }
    #[test]
    fn live_window_rejects_another_process() {
        let mut failure = run(3).err().expect("unmap failure");
        let window = failure.window().expect("retained own window");
        let calls = sys::STATE.with(|s| s.borrow().calls);
        let other = handle::Handle::borrowed(abi::Handle(2));
        // The simulated other process cannot identify the live own window.
        assert_eq!(
            unsafe { failure.cleanup_one(&other) },
            Err(abi::Error::InvalidArgs)
        );
        assert_eq!(failure.window(), Some(window));
        assert_eq!(sys::STATE.with(|s| s.borrow().calls), calls);
        cleanup(&mut failure);
    }

    #[test]
    fn failure_drop_keeps_caps() {
        let f = run(2).err().unwrap();
        let before = sys::STATE.with(|s| s.borrow().handles.clone());
        assert!(!before.is_empty());
        drop(f);
        assert_eq!(before, sys::STATE.with(|s| s.borrow().handles.clone()));
    }
}
