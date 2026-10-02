// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C functions of relibc the Rust guest probes call, with relibc's
//! types and numbers (its headers for AArch64), and the link of relibc's
//! libc.a. A probe declares C `main` and starts through posix-crt; the
//! layer's internals it checks through the layer's Rust interface.

#![no_std]
#![allow(non_camel_case_types)]

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::sync::atomic::AtomicU32;

/// relibc's `pthread_t`, a pointer, as a number.
pub type pthread_t = u64;
/// relibc's `pthread_key_t`.
pub type pthread_key_t = u64;
/// A thread's start routine.
pub type Start = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

pub const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 0;
pub const PTHREAD_CANCEL_ENABLE: c_int = 1;
pub const PTHREAD_CANCEL_DEFERRED: c_int = 2;
pub const PTHREAD_CANCEL_DISABLE: c_int = 3;
pub const PTHREAD_CREATE_DETACHED: c_int = 0;
pub const PTHREAD_CREATE_JOINABLE: c_int = 1;
pub const PTHREAD_MUTEX_DEFAULT: c_int = 0;
pub const PTHREAD_MUTEX_ERRORCHECK: c_int = 1;
pub const PTHREAD_MUTEX_NORMAL: c_int = 2;
pub const PTHREAD_MUTEX_RECURSIVE: c_int = 3;
pub const PTHREAD_STACK_MIN: usize = 65536;
pub const O_RDONLY: c_int = 0;
pub const O_RDWR: c_int = 2;
pub const SEEK_SET: c_int = 0;
pub const SEEK_CUR: c_int = 1;
pub const PTHREAD_DESTRUCTOR_ITERATIONS: u32 = 4;
/// `pthread_join`'s value of a cancelled thread.
pub const CANCELED: *mut c_void = usize::MAX as *mut c_void;

/// `pthread_attr_t`: 32 bytes.
#[repr(C, align(8))]
pub struct Attr([u8; 32]);
impl Attr {
    pub const fn new() -> Self {
        Self([0; 32])
    }
}
impl Default for Attr {
    fn default() -> Self {
        Self::new()
    }
}

/// `pthread_mutex_t`: 12 bytes, `PTHREAD_MUTEX_INITIALIZER` all zero; the
/// first word is the lock word.
#[repr(C, align(4))]
pub struct Mutex(UnsafeCell<[u8; 12]>);
// SAFETY: relibc's mutex is made to be shared between threads.
unsafe impl Sync for Mutex {}
impl Mutex {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; 12]))
    }
    /// The lock word: 0 free, the owner's number, bit 31 a waiter.
    pub fn word(&self) -> &AtomicU32 {
        // SAFETY: the first four bytes are relibc's atomic lock word.
        unsafe { &*self.0.get().cast::<AtomicU32>() }
    }
    pub fn get(&self) -> *mut Mutex {
        core::ptr::from_ref(self).cast_mut()
    }
}
impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
}

/// `pthread_mutexattr_t`: 20 bytes.
#[repr(C, align(4))]
pub struct MutexAttr([u8; 20]);
impl MutexAttr {
    pub const fn new() -> Self {
        Self([0; 20])
    }
}
impl Default for MutexAttr {
    fn default() -> Self {
        Self::new()
    }
}

/// `pthread_once_t`: 4 bytes, `PTHREAD_ONCE_INIT` zero.
#[repr(C, align(4))]
pub struct Once(UnsafeCell<[u8; 4]>);
// SAFETY: relibc's once control is made to be shared between threads.
unsafe impl Sync for Once {}
impl Once {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; 4]))
    }
    pub fn get(&self) -> *mut Once {
        core::ptr::from_ref(self).cast_mut()
    }
}
impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

/// A node of `pthread_cleanup_push`, as relibc's macro lays it out.
#[repr(C)]
pub struct Cleanup {
    routine: Option<unsafe extern "C" fn(*mut c_void)>,
    argument: *mut c_void,
    previous: *mut c_void,
}
impl Cleanup {
    pub const fn new() -> Self {
        Self {
            routine: None,
            argument: core::ptr::null_mut(),
            previous: core::ptr::null_mut(),
        }
    }
}
impl Default for Cleanup {
    fn default() -> Self {
        Self::new()
    }
}

/// `pthread_cleanup_push(routine, argument)` with `node` for the macro's
/// local.
///
/// # Safety
/// `node` stays at its address until the matching `cleanup_pop` or the
/// thread's end; calls pair as the macros do.
pub unsafe fn cleanup_push(
    node: *mut Cleanup,
    routine: Option<unsafe extern "C" fn(*mut c_void)>,
    argument: *mut c_void,
) {
    // SAFETY: the caller's promise.
    unsafe {
        node.write(Cleanup {
            routine,
            argument,
            previous: core::ptr::null_mut(),
        });
        __relibc_internal_pthread_cleanup_push(node.cast());
    }
}

/// `pthread_cleanup_pop(execute)` of the node `cleanup_push` pushed last.
///
/// # Safety
/// `_node` is the thread's last pushed node.
pub unsafe fn cleanup_pop(_node: *mut Cleanup, execute: c_int) {
    // SAFETY: the caller's promise.
    unsafe { __relibc_internal_pthread_cleanup_pop(execute) }
}

unsafe extern "C" {
    pub fn pthread_create(
        thread: *mut pthread_t,
        attr: *const Attr,
        start: Option<Start>,
        argument: *mut c_void,
    ) -> c_int;
    pub fn pthread_join(thread: pthread_t, value: *mut *mut c_void) -> c_int;
    pub fn pthread_detach(thread: pthread_t) -> c_int;
    pub fn pthread_exit(value: *mut c_void) -> !;
    pub safe fn pthread_self() -> pthread_t;
    pub safe fn pthread_equal(a: pthread_t, b: pthread_t) -> c_int;
    pub safe fn pthread_cancel(thread: pthread_t) -> c_int;
    pub safe fn pthread_kill(thread: pthread_t, signal: c_int) -> c_int;
    pub fn pthread_setcancelstate(state: c_int, old: *mut c_int) -> c_int;
    pub fn pthread_setcanceltype(kind: c_int, old: *mut c_int) -> c_int;
    pub safe fn pthread_testcancel();
    pub fn pthread_attr_init(attr: *mut Attr) -> c_int;
    pub fn pthread_attr_destroy(attr: *mut Attr) -> c_int;
    pub fn pthread_attr_setstacksize(attr: *mut Attr, size: usize) -> c_int;
    pub fn pthread_attr_setdetachstate(attr: *mut Attr, state: c_int) -> c_int;
    pub fn pthread_mutex_init(mutex: *mut Mutex, attr: *const MutexAttr) -> c_int;
    pub fn pthread_mutex_destroy(mutex: *mut Mutex) -> c_int;
    pub fn pthread_mutex_lock(mutex: *mut Mutex) -> c_int;
    pub fn pthread_mutex_trylock(mutex: *mut Mutex) -> c_int;
    pub fn pthread_mutex_timedlock(mutex: *mut Mutex, deadline: *const Timespec) -> c_int;
    pub fn pthread_mutex_unlock(mutex: *mut Mutex) -> c_int;
    pub fn pthread_mutexattr_init(attr: *mut MutexAttr) -> c_int;
    pub fn pthread_mutexattr_destroy(attr: *mut MutexAttr) -> c_int;
    pub fn pthread_mutexattr_settype(attr: *mut MutexAttr, kind: c_int) -> c_int;
    pub fn pthread_mutexattr_gettype(attr: *const MutexAttr, kind: *mut c_int) -> c_int;
    pub fn pthread_once(control: *mut Once, routine: Option<unsafe extern "C" fn()>) -> c_int;
    pub fn pthread_key_create(
        key: *mut pthread_key_t,
        destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
    pub safe fn pthread_key_delete(key: pthread_key_t) -> c_int;
    pub safe fn pthread_getspecific(key: pthread_key_t) -> *mut c_void;
    pub safe fn pthread_setspecific(key: pthread_key_t, value: *const c_void) -> c_int;
    pub fn __errno_location() -> *mut c_int;
    pub fn open(path: *const core::ffi::c_char, flags: c_int, ...) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
    pub fn write(fd: c_int, buffer: *const u8, count: usize) -> isize;
    pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64;
    pub fn dup(fd: c_int) -> c_int;
    pub fn dup2(fd: c_int, target: c_int) -> c_int;
    pub fn getcwd(buffer: *mut core::ffi::c_char, size: usize) -> *mut core::ffi::c_char;
    pub fn chdir(path: *const core::ffi::c_char) -> c_int;
    pub fn stat(path: *const core::ffi::c_char, out: *mut Stat) -> c_int;
    pub fn fstat(fd: c_int, out: *mut Stat) -> c_int;
    pub fn malloc(size: usize) -> *mut u8;
    pub fn free(pointer: *mut u8);
    fn __relibc_internal_pthread_cleanup_push(node: *mut c_void);
    fn __relibc_internal_pthread_cleanup_pop(execute: c_int);
}

/// relibc's `struct stat` (Linux AArch64, 128 bytes), opaque but for its
/// size field.
#[repr(C, align(8))]
pub struct Stat([u8; 128]);
impl Stat {
    pub const fn new() -> Self {
        Self([0; 128])
    }
    /// `st_size`, 48 bytes on.
    pub fn size(&self) -> i64 {
        i64::from_le_bytes(self.0[48..56].try_into().expect("eight bytes"))
    }
}
impl Default for Stat {
    fn default() -> Self {
        Self::new()
    }
}

/// `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// relibc's errno of the calling thread.
pub fn errno() -> c_int {
    // SAFETY: relibc's errno of a thread relibc started.
    unsafe { *__errno_location() }
}

/// Sets relibc's errno of the calling thread.
pub fn set_errno(value: c_int) {
    // SAFETY: as in `errno`.
    unsafe { *__errno_location() = value }
}
