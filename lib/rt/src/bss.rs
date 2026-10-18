// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tables that live in `.bss`. A static whose first value has a non-zero
//! byte goes into `.data`, and the boot image then carries every zero of it;
//! the tables of the services are zero except for a tag or a list head in
//! each place. A service keeps such a table in a zeroed static
//! (`MaybeUninit::zeroed`) and writes those places at its start, in place,
//! with the helpers here.

/// Writes `value` into each element of the array at `array`.
///
/// # Safety
/// `array` is valid for writes, and nothing reads it before.
pub unsafe fn fill<T: Copy, const N: usize>(array: *mut [T; N], value: T) {
    let first = array.cast::<T>();
    for i in 0..N {
        // SAFETY: the element `i` of the array is in bounds.
        unsafe { first.add(i).write(value) };
    }
}

/// Writes `None` into each element of the array at `array`.
///
/// # Safety
/// `array` is valid for writes, and nothing reads it before.
pub unsafe fn fill_none<T, const N: usize>(array: *mut [Option<T>; N]) {
    let first = array.cast::<Option<T>>();
    for i in 0..N {
        // SAFETY: the element `i` of the array is in bounds.
        unsafe { first.add(i).write(None) };
    }
}
