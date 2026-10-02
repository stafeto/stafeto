// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Directory selection with separately owned entries and all-or-nothing output.

use crate::{
    allocation::{free, malloc, reallocarray},
    constants::*,
    directory::{self, Stream},
    fail,
    locale::strcoll,
    ordering::qsort_r,
    tls,
};
use core::{
    ffi::{c_char, c_int, c_void},
    mem::size_of,
    ptr,
};
use posix_types::Dirent;

pub type Select = unsafe extern "C" fn(*const Dirent) -> c_int;
pub type Compare = unsafe extern "C" fn(*const *const Dirent, *const *const Dirent) -> c_int;

struct List {
    pointer: *mut *mut Dirent,
    count: usize,
    capacity: usize,
}

impl List {
    unsafe fn push(&mut self, entry: *const Dirent) -> Result<(), c_int> {
        if self.count == c_int::MAX as usize {
            return Err(EOVERFLOW);
        }
        if self.count == self.capacity {
            let capacity = self.capacity.max(4).checked_mul(2).ok_or(ENOMEM)?;
            let replacement: *mut *mut Dirent =
                unsafe { reallocarray(self.pointer.cast(), capacity, size_of::<*mut Dirent>()) }
                    .cast();
            if replacement.is_null() {
                return Err(ENOMEM);
            }
            self.pointer = replacement;
            self.capacity = capacity;
        }
        let copy = unsafe { malloc(size_of::<Dirent>()) }.cast::<Dirent>();
        if copy.is_null() {
            return Err(ENOMEM);
        }
        // SAFETY: readdir supplies a complete live entry; malloc provides disjoint
        // storage, and the checked list capacity covers its next pointer slot.
        unsafe {
            ptr::copy_nonoverlapping(entry, copy, 1);
            self.pointer.add(self.count).write(copy);
        }
        self.count += 1;
        Ok(())
    }
}

impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: only initialized entries are freed, each owned once by this list.
        unsafe {
            for index in 0..self.count {
                free((*self.pointer.add(index)).cast());
            }
            free(self.pointer.cast());
        }
    }
}

struct OpenStream(*mut Stream);
impl Drop for OpenStream {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this guard owns the stream; cleanup preserves the original error.
            unsafe {
                let saved = *tls::errno();
                directory::closedir(self.0);
                *tls::errno() = saved;
            }
        }
    }
}

unsafe extern "C" fn compare_entries(
    left: *const c_void,
    right: *const c_void,
    context: *mut c_void,
) -> c_int {
    // SAFETY: qsort_r passes real pointer-array elements and the live comparator.
    let compare = unsafe { *context.cast::<Compare>() };
    unsafe { compare(left.cast(), right.cast()) }
}

/// # Safety
/// path is a live C string; namelist is writable for one pointer. This thread
/// has file and heap initialization. Callbacks obey their C contracts and may
/// reenter unrelated ABI functions; they must not invalidate directory entries.
/// On success the caller frees each selected entry and then the pointer array.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn scandir(
    path: *const c_char,
    namelist: *mut *mut *mut Dirent,
    select: Option<Select>,
    compare: Option<Compare>,
) -> c_int {
    if namelist.is_null() {
        return fail(EFAULT) as c_int;
    }
    let saved = unsafe { *tls::errno() };
    let result = (|| {
        let pointer = unsafe { directory::opendir(path) };
        if pointer.is_null() {
            return Err(unsafe { *tls::errno() });
        }
        let mut stream = OpenStream(pointer);
        let mut list = List {
            pointer: ptr::null_mut(),
            count: 0,
            capacity: 0,
        };
        loop {
            // The internal result distinguishes EOF from an error without changing
            // errno or observing values written by selection callbacks.
            let entry = directory::read_entry(pointer)?;
            if entry.is_null() {
                break;
            }
            unsafe { *tls::errno() = saved };
            if select.is_none_or(|select| unsafe { select(entry) != 0 }) {
                unsafe { list.push(entry) }?;
            }
        }
        if unsafe { directory::closedir(pointer) } != 0 {
            return Err(unsafe { *tls::errno() });
        }
        stream.0 = ptr::null_mut();
        if list.pointer.is_null() {
            list.pointer = unsafe { malloc(0) }.cast();
            if list.pointer.is_null() {
                return Err(ENOMEM);
            }
        }
        if let Some(mut compare) = compare {
            unsafe {
                qsort_r(
                    list.pointer.cast(),
                    list.count,
                    size_of::<*mut Dirent>(),
                    Some(compare_entries),
                    ptr::addr_of_mut!(compare).cast(),
                )
            };
        }
        let count = list.count as c_int;
        unsafe { namelist.write(list.pointer) };
        // Transfer both the pointer array and every entry to the caller.
        list.pointer = ptr::null_mut();
        list.count = 0;
        Ok(count)
    })();
    match result {
        Ok(count) => {
            unsafe { *tls::errno() = saved };
            count
        }
        Err(code) => fail(code) as c_int,
    }
}

/// # Safety
/// Arguments point to readable pointers to live directory entries whose names
/// are NUL terminated. The currently supported C/POSIX locale is used.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort(
    left: *const *const Dirent,
    right: *const *const Dirent,
) -> c_int {
    unsafe {
        strcoll(
            (*left).as_ref().unwrap().d_name.as_ptr().cast(),
            (*right).as_ref().unwrap().d_name.as_ptr().cast(),
        )
    }
}
