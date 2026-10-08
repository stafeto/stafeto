// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Strict test observation of the genuine loader supervisor's PID.

#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub const ARGUMENT: &[u8] = b"native-scope-only";

pub fn parent_pid(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut pid = 0u32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        pid = pid.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    (pid != 0).then_some(pid)
}
