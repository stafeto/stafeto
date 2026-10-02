// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! C array sorting with byte swaps and no allocation or temporary element.

use core::{
    ffi::{c_int, c_void},
    ptr,
};

pub type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
pub type CompareContext = unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;

unsafe fn sort(
    base: *mut u8,
    count: usize,
    width: usize,
    mut compare: impl FnMut(*const c_void, *const c_void) -> c_int,
) {
    if count < 2 || width == 0 {
        return;
    }
    // The C caller supplies one live array; an overflowing extent cannot be one.
    if count
        .checked_mul(width)
        .is_none_or(|size| size > isize::MAX as usize)
    {
        return;
    }
    posix_order::sort_by(
        count,
        |a, b| {
            // SAFETY: the array contract and checked extent cover both elements.
            let result = compare(unsafe { base.add(a * width).cast() }, unsafe {
                base.add(b * width).cast()
            });
            result.cmp(&0)
        },
        |a, b| {
            if a != b {
                for offset in 0..width {
                    // SAFETY: different elements are disjoint, including this byte.
                    unsafe {
                        ptr::swap(base.add(a * width + offset), base.add(b * width + offset))
                    };
                }
            }
        },
    );
}

/// # Safety
/// base supplies count initialized elements of width bytes; compare defines a
/// consistent total order and does not modify the elements or unwind.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn qsort(
    base: *mut c_void,
    count: usize,
    width: usize,
    compare: Option<Compare>,
) {
    if let Some(compare) = compare {
        unsafe { sort(base.cast(), count, width, |a, b| compare(a, b)) };
    }
}

/// # Safety
/// qsort's array and comparator contract holds; context remains valid for all
/// comparator calls and is passed unchanged as their last argument.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn qsort_r(
    base: *mut c_void,
    count: usize,
    width: usize,
    compare: Option<CompareContext>,
    context: *mut c_void,
) {
    if let Some(compare) = compare {
        unsafe { sort(base.cast(), count, width, |a, b| compare(a, b, context)) };
    }
}
