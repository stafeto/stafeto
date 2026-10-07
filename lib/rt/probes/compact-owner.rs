// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Host ownership probes using the shipping Handle and Compact implementations.
#![allow(dead_code)]

#[path = "../src/compact.rs"]
mod compact;
#[path = "../src/handle.rs"]
mod handle;
mod msgbuf {
    pub fn handle(_: usize) -> (abi::Handle, (abi::ObjectKind, abi::Rights)) {
        unreachable!()
    }
}
mod sys {
    use std::cell::RefCell;
    thread_local! {
        static STATE: RefCell<(Vec<abi::Handle>, bool)> = const { RefCell::new((Vec::new(), false)) };
    }
    pub fn close_raw(raw: abi::Handle) -> Result<(), abi::Error> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.0.push(raw);
            if state.1 {
                Err(abi::Error::BadHandle)
            } else {
                Ok(())
            }
        })
    }
    pub fn reset(fail: bool) {
        STATE.with(|state| *state.borrow_mut() = (Vec::new(), fail));
    }
    pub fn calls() -> Vec<abi::Handle> {
        STATE.with(|state| state.borrow().0.clone())
    }
}
use compact::Compact;
use handle::{Channel, Handle};
fn owner(raw: u64) -> Compact<Channel> {
    Compact::from_owner(Some(Handle::from_raw(abi::Handle(raw))))
}
#[test]
fn failed_close_preserves_exact_owner_until_retry() {
    sys::reset(true);
    let mut debt = owner(73);
    assert_eq!(debt.close_retained(), Err(abi::Error::BadHandle));
    assert_eq!(debt.with_view(Handle::raw), Some(abi::Handle(73)));
    assert_eq!(sys::calls(), vec![abi::Handle(73)]);
    sys::reset(false);
    assert_eq!(debt.close_retained(), Ok(true));
    drop(debt);
    assert_eq!(sys::calls(), vec![abi::Handle(73)]);
}
#[test]
fn take_disarms_before_owner_leaves() {
    sys::reset(false);
    let mut debt = owner(81);
    let taken = debt.take().unwrap();
    assert!(!debt.is_some());
    assert!(debt.take().is_none());
    drop(debt);
    assert!(sys::calls().is_empty());
    drop(taken);
    assert_eq!(sys::calls(), vec![abi::Handle(81)]);
}
#[test]
fn replacement_and_drop_close_each_nonempty_owner_once() {
    sys::reset(false);
    let mut debt = owner(91);
    assert!(debt.is_some());
    debt = owner(92);
    assert_eq!(sys::calls(), vec![abi::Handle(91)]);
    drop(debt);
    assert_eq!(sys::calls(), vec![abi::Handle(91), abi::Handle(92)]);
}
#[test]
fn empty_never_becomes_a_handle_or_calls_close() {
    sys::reset(false);
    let mut debt = Compact::<Channel>::empty();
    assert!(debt.with_view(Handle::raw).is_none());
    assert!(debt.take().is_none());
    assert_eq!(debt.close_retained(), Ok(false));
    drop(debt);
    assert!(sys::calls().is_empty());
}
#[test]
fn borrowed_operation_keeps_owner_and_has_no_close_effect() {
    sys::reset(false);
    let mut debt = owner(101);
    assert_eq!(debt.with_view(Handle::raw), Some(abi::Handle(101)));
    assert!(sys::calls().is_empty());
    let taken = debt.take().unwrap();
    assert_eq!(taken.raw(), abi::Handle(101));
    drop(taken);
    drop(debt);
    assert_eq!(sys::calls(), vec![abi::Handle(101)]);
}
