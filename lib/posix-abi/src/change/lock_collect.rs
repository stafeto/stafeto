// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One local selection and one remote cleanup turn, followed by local confirmation.

pub(crate) fn turn<T>(
    mut find: impl FnMut() -> Result<Option<T>, i32>,
    mut step: impl FnMut(T) -> Result<bool, i32>,
    mut wake: impl FnMut(),
) -> bool {
    let Ok(token) = find() else {
        return false;
    };
    let Some(token) = token else {
        wake();
        return false;
    };
    if step(token).unwrap_or(false) {
        let next = find();
        wake();
        return next.is_ok_and(|token| token.is_some());
    }
    true
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::turn;
    use std::cell::RefCell;
    use std::vec;

    #[test]
    fn lock_collection_one_turn_retains_unfinished_debt() {
        let events = RefCell::new(vec![]);
        assert!(turn(
            || {
                events.borrow_mut().push("find");
                Ok(Some(7))
            },
            |token| {
                assert_eq!(token, 7);
                events.borrow_mut().push("rpc");
                Ok(false)
            },
            || events.borrow_mut().push("wake"),
        ));
        assert_eq!(*events.borrow(), vec!["find", "rpc"]);
    }
    #[test]
    fn lock_collection_completed_turn_locally_confirms_then_reports_next_debt() {
        let events = RefCell::new(vec![]);
        let mut pass = 0;
        assert!(turn(
            || {
                pass += 1;
                events.borrow_mut().push("find");
                Ok(Some(pass))
            },
            |token| {
                assert_eq!(token, 1);
                events.borrow_mut().push("rpc");
                Ok(true)
            },
            || events.borrow_mut().push("wake"),
        ));
        assert_eq!(*events.borrow(), vec!["find", "rpc", "find", "wake"]);
        assert_eq!(pass, 2);
    }
    #[test]
    fn lock_collection_busy_defers_without_rpc_or_wake() {
        assert!(!turn::<u32>(
            || Err(16),
            |_| panic!("RPC while selection busy"),
            || panic!("wake while selection busy")
        ));
    }
    #[test]
    fn lock_collection_local_ack_wakes_without_rpc_and_failed_rpc_keeps_debt() {
        let mut woke = 0;
        assert!(!turn::<u32>(
            || Ok(None),
            |_| panic!("local acknowledgement needs no RPC"),
            || woke += 1
        ));
        assert_eq!(woke, 1);
        assert!(turn(
            || Ok(Some(9)),
            |_| Err(5),
            || panic!("failed RPC retains debt")
        ));
    }
}
