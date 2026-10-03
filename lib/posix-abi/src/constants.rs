// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Experimental ABI 1 constants; the sysroot generator reads these definitions.

pub const ABI_VERSION: u32 = 1;
pub const SYSROOT_VERSION: &str = "0.1.0";
pub const PTHREAD_CANCEL_ENABLE: i32 = 0;
pub const PTHREAD_CANCEL_DISABLE: i32 = 1;
pub const PTHREAD_CANCEL_DEFERRED: i32 = 0;
pub const PTHREAD_CANCEL_ASYNCHRONOUS: i32 = 1;
pub const ECANCELED: i32 = 125;
pub const ETIMEDOUT: i32 = 110;
pub const ESRCH: i32 = 3;
pub const ECHILD: i32 = 10;
pub const EAGAIN: i32 = 11;
pub const EDEADLK: i32 = 35;
pub const PTHREAD_CREATE_JOINABLE: i32 = 0;
pub const PTHREAD_CREATE_DETACHED: i32 = 1;
pub const PTHREAD_THREADS_MAX: u32 = 64;
pub const PTHREAD_KEYS_MAX: u32 = 128;
pub const PTHREAD_DESTRUCTOR_ITERATIONS: u32 = 4;
pub const PTHREAD_STACK_MIN: u32 = 16384;
pub const ENOENT: i32 = 2;
pub const E2BIG: i32 = 7;
pub const ENOEXEC: i32 = 8;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const EMFILE: i32 = 24;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const ERANGE: i32 = 34;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const EOVERFLOW: i32 = 75;
pub const EILSEQ: i32 = 84;
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_ACCMODE: i32 = 3;
pub const O_DIRECTORY: i32 = 65536;
pub const O_CLOEXEC: i32 = 524288;
pub const O_CLOFORK: i32 = 16777216;
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;
pub const SEEK_DATA: i32 = 3;
pub const SEEK_HOLE: i32 = 4;
pub const STDIN_FILENO: i32 = 0;
pub const STDOUT_FILENO: i32 = 1;
pub const STDERR_FILENO: i32 = 2;
pub const LC_ALL: i32 = 0;
pub const LC_COLLATE: i32 = 1;
pub const LC_CTYPE: i32 = 2;
pub const LC_MESSAGES: i32 = 3;
pub const LC_MONETARY: i32 = 4;
pub const LC_NUMERIC: i32 = 5;
pub const LC_TIME: i32 = 6;

pub use posix_types::constants::*;

pub const EPERM: i32 = 1;
pub const EBUSY: i32 = 16;
pub const PTHREAD_MUTEX_NORMAL: i32 = 0;
pub const PTHREAD_MUTEX_ERRORCHECK: i32 = 1;
pub const PTHREAD_MUTEX_RECURSIVE: i32 = 2;
pub const PTHREAD_MUTEX_DEFAULT: i32 = 3;
pub const ENFILE: i32 = 23;
pub const EPIPE: i32 = 32;
/// Linux's O_NONBLOCK on AArch64, relibc's.
pub const O_NONBLOCK: i32 = 0o4000;
