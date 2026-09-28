// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial C/POSIX locale. Unsupported locales fail without changing state.

use crate::constants::*;
use core::{
    ffi::{CStr, c_char, c_int},
    ptr,
};

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

unsafe fn environment(name: &[u8]) -> Option<&'static [u8]> {
    // SAFETY: C startup/caller supplies a live NULL-terminated environment;
    // callers synchronize environment changes with locale selection.
    let mut entry = unsafe { environ };
    if entry.is_null() {
        return None;
    }
    while !unsafe { *entry }.is_null() {
        let bytes = unsafe { CStr::from_ptr(*entry) }.to_bytes();
        if bytes.starts_with(name) && bytes.get(name.len()) == Some(&b'=') {
            let value = &bytes[name.len() + 1..];
            return (!value.is_empty()).then_some(value);
        }
        entry = unsafe { entry.add(1) };
    }
    None
}

fn supported(name: &[u8]) -> bool {
    name == b"C" || name == b"POSIX"
}

unsafe fn native(category: c_int) -> bool {
    let variable = match category {
        LC_COLLATE => b"LC_COLLATE".as_slice(),
        LC_CTYPE => b"LC_CTYPE".as_slice(),
        LC_MESSAGES => b"LC_MESSAGES".as_slice(),
        LC_MONETARY => b"LC_MONETARY".as_slice(),
        LC_NUMERIC => b"LC_NUMERIC".as_slice(),
        LC_TIME => b"LC_TIME".as_slice(),
        _ => return false,
    };
    let selected = unsafe { environment(b"LC_ALL") }
        .or_else(|| unsafe { environment(variable) })
        .or_else(|| unsafe { environment(b"LANG") })
        .unwrap_or(b"C");
    supported(selected)
}

/// # Safety
/// locale is NULL or a readable C string. Environment entries are valid and
/// no other thread changes environ during a request for the native locale.
/// The returned name is borrowed and must not be modified or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char {
    if !(LC_ALL..=LC_TIME).contains(&category) {
        return ptr::null_mut();
    }
    if !locale.is_null() {
        let name = unsafe { CStr::from_ptr(locale) }.to_bytes();
        let accepted = if name.is_empty() {
            if category == LC_ALL {
                (LC_COLLATE..=LC_TIME).all(|category| unsafe { native(category) })
            } else {
                unsafe { native(category) }
            }
        } else {
            supported(name)
        };
        if !accepted {
            return ptr::null_mut();
        }
    }
    c"C".as_ptr().cast_mut()
}

/// # Safety
/// Both arguments are readable NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(left: *const c_char, right: *const c_char) -> c_int {
    let left = unsafe { CStr::from_ptr(left) }.to_bytes();
    let right = unsafe { CStr::from_ptr(right) }.to_bytes();
    match posix_order::collate(left, right) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// # Safety
/// strcmp's string contract holds. The current implementation supports only
/// C/POSIX collation, which is unsigned byte ordering.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcoll(left: *const c_char, right: *const c_char) -> c_int {
    unsafe { strcmp(left, right) }
}

/// # Safety
/// source is a readable C string; destination supplies count writable bytes,
/// disjoint from source. destination may be NULL when count is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strxfrm(
    destination: *mut c_char,
    source: *const c_char,
    count: usize,
) -> usize {
    let source = unsafe { CStr::from_ptr(source) }.to_bytes();
    let copied = source.len().min(count);
    if copied != 0 {
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), destination.cast(), copied) };
    }
    if count > source.len() {
        unsafe { destination.add(source.len()).write(0) };
    }
    source.len()
}
