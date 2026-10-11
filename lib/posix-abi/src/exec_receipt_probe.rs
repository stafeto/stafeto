// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub fn on_accepted(receipt_ok: bool, hook: impl FnOnce() -> bool) -> bool {
    receipt_ok && hook()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_receipt_never_consumes_the_first_successful_discard() {
        let mut calls = 0;
        assert!(!on_accepted(false, || {
            calls += 1;
            true
        }));
        assert_eq!(calls, 0);
        assert!(on_accepted(true, || {
            calls += 1;
            true
        }));
        assert_eq!(calls, 1);
        assert!(!on_accepted(true, || {
            calls += 1;
            false
        }));
        assert_eq!(calls, 2);
    }
}
